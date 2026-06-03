//! Active-write event signer wired against the SDK's unified
//! `EventProofBuilder` / `Ed25519DetachedJwsSigner` pipeline.
//!
//! T5.2 (Round 22, 2026-05-20) — T5.1 landed `Ed25519DetachedJwsSigner`,
//! `EventProofBuilder`, and `ProductionVerifier` in the SDK
//! (`cokret-rust-sdk/crates/signatures/src/proof.rs`). Before T5.2
//! yougen's [`crate::operation::EventEnvelope::sign_ed25519`] hand-rolled
//! the same canonical-bytes → JWS pipeline, which meant a bug fixed in
//! the SDK had to be ported a second time into yougen. This module
//! collapses both code paths through the SDK.
//!
//! ## What lives here
//!
//! * [`YougenEventSigner`] — opaque handle around an `EventSigner` trait object plus the metadata
//!   UI surfaces want (`signer_did`, `verification_method`, last-sign timestamp).
//! * [`build_ed25519_signer`] — bootstrap that takes a 32-byte Ed25519 seed (typically loaded via
//!   `secure_key_store::ensure_signing_seed`) and returns a `YougenEventSigner` ready to attach
//!   detached JWS proofs to event envelopes.
//! * [`install_active_signer`] / [`active_signer`] — a process-wide `OnceLock` that holds the
//!   active signer; the submit guard in [`crate::api::CokretApi::submit_event_envelope`] reaches
//!   into this to lazily sign envelopes that were built unsigned.
//! * [`signer_status`] — diagnostic snapshot for the settings panel.
//!
//! ## Canonical bytes alignment
//!
//! The SDK's `EventProofBuilder` operates over an opaque `T: Serialize`.
//! Yougen's [`crate::operation::EventEnvelope`] is **not** the same
//! struct as `contrix_core::Event` — yougen's wire shape evolved
//! independently before the SDK pipeline landed. To keep the SDK as the
//! single canonical-bytes source, this module re-serializes the
//! envelope into a `serde_json::Value` with `proofs` + `unsigned`
//! stripped (the same projection
//! [`crate::operation::EventEnvelope::sign_ed25519`] used) and feeds
//! that into `EventProofBuilder::canonical_bytes`.
//!
//! ## Wiring contract
//!
//! Boot (e.g. `app::init`) should call:
//!
//! ```ignore
//! let store = crate::secure_key_store::default_secure_key_store("yougen");
//! let material = crate::secure_key_store::ensure_signing_seed(&*store)?;
//! let signer = crate::event_signer::build_ed25519_signer(
//!     material.seed,
//!     material.device_did.clone(),
//! );
//! crate::event_signer::install_active_signer(std::sync::Arc::new(signer));
//! crate::operation::set_proof_mode(crate::operation::ProofMode::RealEd25519);
//! ```
//!
//! Hosts that prefer to hand in an external signer (HSM, WebAuthn,
//! `secret-service`-mediated PIN-protected key) skip the seed step and
//! call [`YougenEventSigner::from_dyn_signer`] directly. The submit
//! guard then routes through their backend instead of the in-process
//! seed.

use std::sync::{Arc, Mutex, OnceLock};

use chrono::{DateTime, Utc};
use contrix_sdk::signatures::proof::{EventProofBuilder, EventSigner as SdkEventSigner, ProofType};
use serde_json::Value;

use crate::operation::{EventEnvelope, EventProof, ProofMode, current_proof_mode};

/// Errors produced by the active-write signing pipeline.
#[derive(Debug)]
pub enum EventSignerError {
    /// The active runtime [`ProofMode`] expects a real signer but none
    /// has been installed via [`install_active_signer`]. The submit
    /// guard surfaces this so the UI can prompt the user.
    MissingSigner { mode: &'static str },
    /// The underlying SDK backend refused to sign.
    Backend(String),
    /// Canonical serialisation failed before reaching the signer.
    Encoding(String),
}

impl std::fmt::Display for EventSignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSigner { mode } => write!(
                f,
                "no event signer installed (active proof mode = {mode}). \
                Boot must call event_signer::install_active_signer or downgrade \
                to ProofMode::PlaceholderDev for dev fixtures."
            ),
            Self::Backend(msg) => write!(f, "event signer backend rejected payload: {msg}"),
            Self::Encoding(msg) => write!(f, "canonical encoding failed before signing: {msg}"),
        }
    }
}

impl std::error::Error for EventSignerError {}

/// Opaque handle wrapping an SDK [`SdkEventSigner`] trait object plus
/// the metadata yougen's UI / submit guard care about.
pub struct YougenEventSigner {
    inner: Arc<dyn SdkEventSigner + Send + Sync>,
    /// The DID the verifier should resolve to obtain the public key.
    /// For did:key-derived signers this matches the device DID; for
    /// HSM-backed signers it is whatever DID the host has bound the
    /// hardware key to.
    signer_did: String,
    /// Verification method id (`<did>#<fragment>`) the produced proofs
    /// reference. Defaults to `<signer_did>#device` when the backend
    /// does not override it.
    verification_method: String,
    /// Coarse mode tag used by the UI to colour the badge — `"ed25519"`
    /// for the in-process seed path and `"external"` for delegated
    /// backends.
    mode_tag: &'static str,
    /// Wall-clock timestamp of the most recent successful sign call.
    /// `None` until the first sign succeeds. Exposed for the UI
    /// freshness indicator.
    last_signed_at: Mutex<Option<DateTime<Utc>>>,
}

impl std::fmt::Debug for YougenEventSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YougenEventSigner")
            .field("signer_did", &self.signer_did)
            .field("verification_method", &self.verification_method)
            .field("mode_tag", &self.mode_tag)
            .field("algorithm", &self.inner.algorithm())
            .field("last_signed_at", &self.last_signed_at_snapshot())
            .finish()
    }
}

impl YougenEventSigner {
    /// Wrap an arbitrary SDK [`SdkEventSigner`] (HSM, WebAuthn,
    /// external host-bridge). `signer_did` is the DID receivers will
    /// resolve to fetch the verifying key. The verification method
    /// defaults to `<signer_did>#device` if the SDK signer returns an
    /// empty string.
    pub fn from_dyn_signer(
        inner: Arc<dyn SdkEventSigner + Send + Sync>,
        signer_did: impl Into<String>,
    ) -> Self {
        let signer_did = signer_did.into();
        let verification_method = {
            let vm = inner.verification_method().to_owned();
            if vm.is_empty() {
                format!("{signer_did}#device")
            } else {
                vm
            }
        };
        Self {
            inner,
            signer_did,
            verification_method,
            mode_tag: "external",
            last_signed_at: Mutex::new(None),
        }
    }

    /// Returns the DID receivers will resolve to verify proofs produced
    /// by this signer.
    pub fn signer_did(&self) -> &str {
        &self.signer_did
    }

    /// Verification method id embedded in each emitted proof.
    pub fn verification_method(&self) -> &str {
        &self.verification_method
    }

    /// JWS algorithm name (e.g. `"EdDSA"`).
    pub fn algorithm(&self) -> &str {
        self.inner.algorithm()
    }

    /// Produce a RAW detached signature over `bytes` (not a JWS) using the
    /// active backend — works for the in-process seed signer AND external / HSM
    /// signers alike (the SDK `EventSigner::sign` returns raw signature bytes;
    /// for EdDSA that is the 64-byte Ed25519 signature). Used for the
    /// `cx.schema.key_backup.v1` `auth_data.signature` (key-management.md
    /// §7.4.1), whose wire form is a single base64url token, not a dotted JWS.
    pub fn sign_raw(&self, bytes: &[u8]) -> Result<Vec<u8>, EventSignerError> {
        self.inner
            .sign(bytes)
            .map_err(|err| EventSignerError::Backend(err.to_string()))
    }

    /// `"ed25519"` for the in-process seed signer, `"external"` for
    /// SDK-trait delegated backends. Surfaced by the settings UI badge.
    pub fn mode_tag(&self) -> &'static str {
        self.mode_tag
    }

    /// Snapshot of the most recent successful sign timestamp. `None`
    /// until the first sign call lands.
    pub fn last_signed_at_snapshot(&self) -> Option<DateTime<Utc>> {
        self.last_signed_at
            .lock()
            .map(|guard| *guard)
            .unwrap_or(None)
    }

    /// Sign `event` in place: replaces `event.proofs` with a single
    /// detached-JWS proof produced by the SDK pipeline. The proof
    /// carries `ProofType::Production` (`detached_jws` / `EdDSA`) so a
    /// `ProductionVerifier`-wrapped receiver accepts it.
    ///
    /// Updates [`Self::last_signed_at_snapshot`] on success.
    pub fn sign_envelope(&self, event: &mut EventEnvelope) -> Result<(), EventSignerError> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        // Mirror EventEnvelope::sign_ed25519: strip proofs + unsigned
        // before canonicalising so the digest is stable across rounds.
        let mut canonical = serde_json::to_value(&*event)
            .map_err(|err| EventSignerError::Encoding(err.to_string()))?;
        if let Value::Object(object) = &mut canonical {
            object.remove("proofs");
            object.remove("unsigned");
        }

        let builder = EventProofBuilder::new();
        let canonical_bytes = builder
            .canonical_bytes(&canonical)
            .map_err(|err| EventSignerError::Encoding(err.to_string()))?;
        let event_digest = crate::canonical::sha256_digest(&canonical_bytes);

        let verification_method = self.verification_method_for_event(event);
        let created_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let proof_binding = serde_json::json!({
            "event_digest": event_digest.as_str(),
            "actor_id": event.actor_id.as_str(),
            "verification_method": verification_method.as_str(),
            "created_at": created_at.as_str(),
        });
        let proof_binding_bytes = builder
            .canonical_bytes(&proof_binding)
            .map_err(|err| EventSignerError::Encoding(err.to_string()))?;

        // Run the SDK signer — its `sign` already prepends the b64u
        // header + b64u payload and returns the raw signature bytes.
        let signature = self
            .inner
            .sign(&proof_binding_bytes)
            .map_err(|err| EventSignerError::Backend(err.to_string()))?;

        // Reassemble the detached JWS using the same header constant the
        // SDK's Ed25519DetachedJwsSigner uses (`{"alg":"EdDSA","typ":"JWT"}`).
        // Sourcing the algorithm name from the trait keeps non-Ed25519
        // backends honest: an ES256 signer would still surface
        // `alg=ES256` in the header.
        let header = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, self.algorithm());
        let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);
        let jws = format!("{header_b64}..{sig_b64}");

        event.proofs = vec![EventProof {
            kind: "detached_jws".to_owned(),
            alg: self.algorithm().to_owned(),
            verification_method,
            event_digest,
            jws,
            created_at,
        }];
        if event.actor_id.is_empty() {
            event.actor_id = self.signer_did.clone();
        }

        if let Ok(mut guard) = self.last_signed_at.lock() {
            *guard = Some(Utc::now());
        }
        let _proof_type = Self::proof_type_tag();
        Ok(())
    }

    fn verification_method_for_event(&self, event: &EventEnvelope) -> String {
        let actor_id = event.actor_id.trim();
        if actor_id.is_empty() {
            self.verification_method.clone()
        } else {
            format!("{actor_id}#device")
        }
    }

    /// The [`ProofType`] tag every proof emitted by this signer carries.
    /// Always `Production(detached_jws / <algorithm>)`. Exposed so
    /// receivers / tests can wrap a verifier with the matching tag
    /// without re-deriving it.
    pub fn proof_type_tag() -> ProofType {
        ProofType::production("detached_jws", "EdDSA")
    }
}

/// Build a [`YougenEventSigner`] backed by the SDK's
/// `Ed25519DetachedJwsSigner` over a raw 32-byte seed.
///
/// The signing seed should originate from
/// [`crate::secure_key_store::ensure_signing_seed`] (OS keychain /
/// SecureKeyStore-backed) — passing a hard-coded byte literal here is
/// only safe in tests.
///
/// `signer_did` is the did:key (or did:web, etc.) the produced proofs
/// will reference. The verification-method id becomes
/// `<signer_did>#device`.
pub fn build_ed25519_signer(seed: [u8; 32], signer_did: impl Into<String>) -> YougenEventSigner {
    use contrix_sdk::signatures::proof::Ed25519DetachedJwsSigner;
    let signer_did = signer_did.into();
    let verification_method = format!("{signer_did}#device");
    let sdk_signer = Ed25519DetachedJwsSigner::from_seed(seed, verification_method.clone());
    YougenEventSigner {
        inner: Arc::new(sdk_signer),
        signer_did,
        verification_method,
        mode_tag: "ed25519",
        last_signed_at: Mutex::new(None),
    }
}

// Process-wide active signer slot. `OnceLock` so callers don't have to
// hold a handle — the submit guard reads it lazily. We deliberately do
// not allow re-installation: once a signer is set the rest of the
// process is bound to it, which mirrors `key_store`'s "primary identity
// is sticky" contract.
//
// Wrapped in an `RwLock` rather than a plain `OnceLock<Arc<...>>` so
// the rare host that needs to swap signers mid-session (e.g. a
// hardware-key unlock that happens after first paint) can call
// [`replace_active_signer`]. Tests use the same swap path to reset
// between cases.
static ACTIVE_SIGNER: OnceLock<std::sync::RwLock<Option<Arc<YougenEventSigner>>>> = OnceLock::new();

fn active_slot() -> &'static std::sync::RwLock<Option<Arc<YougenEventSigner>>> {
    ACTIVE_SIGNER.get_or_init(|| std::sync::RwLock::new(None))
}

/// Install `signer` as the process-wide active signer. Returns `true`
/// on first install. Subsequent calls overwrite — see
/// [`replace_active_signer`] for the semantic mirror.
pub fn install_active_signer(signer: Arc<YougenEventSigner>) -> bool {
    let mut guard = match active_slot().write() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    let first = guard.is_none();
    *guard = Some(signer);
    first
}

/// Swap the active signer (for tests and for hosts that need to
/// rotate). Returns the previous signer when one was installed.
pub fn replace_active_signer(
    signer: Option<Arc<YougenEventSigner>>,
) -> Option<Arc<YougenEventSigner>> {
    let mut guard = match active_slot().write() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    std::mem::replace(&mut *guard, signer)
}

/// Returns the currently-installed active signer, if any.
pub fn active_signer() -> Option<Arc<YougenEventSigner>> {
    let guard = match active_slot().read() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    guard.clone()
}

/// True when an active signer is installed and the active proof mode
/// expects real signing. Used by the submit guard to decide whether to
/// auto-sign an envelope that was built unsigned.
pub fn should_auto_sign() -> bool {
    let mode = current_proof_mode();
    matches!(mode, ProofMode::RealEd25519 | ProofMode::ExternalSigner) && active_signer().is_some()
}

/// Sign `event` with the currently-installed active signer, returning
/// `MissingSigner` when none is installed. The submit guard calls this
/// just before sending to the wire so envelopes built with placeholder
/// dev proofs (or no proofs at all) get a real signature attached when
/// the proof mode expects one.
pub fn sign_with_active(event: &mut EventEnvelope) -> Result<(), EventSignerError> {
    let signer = active_signer().ok_or(EventSignerError::MissingSigner {
        mode: current_proof_mode().label_en(),
    })?;
    signer.sign_envelope(event)
}

/// UI-facing snapshot of the currently-installed signer. `None` when no
/// signer is installed; the settings panel surfaces "—" for each field
/// in that case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerStatus {
    pub signer_did: String,
    pub verification_method: String,
    pub algorithm: String,
    pub mode_tag: &'static str,
    /// RFC3339 timestamp of the last successful sign call, or `None` if
    /// the signer has not produced a proof yet in this session.
    pub last_signed_at: Option<String>,
}

/// Snapshot of the active signer for diagnostic UI. Returns `None`
/// when no signer is installed — the settings panel renders that as
/// "no signer (production)" when paired with [`ProofMode::Production`].
pub fn signer_status() -> Option<SignerStatus> {
    let signer = active_signer()?;
    let last = signer
        .last_signed_at_snapshot()
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    Some(SignerStatus {
        signer_did: signer.signer_did().to_owned(),
        verification_method: signer.verification_method().to_owned(),
        algorithm: signer.algorithm().to_owned(),
        mode_tag: signer.mode_tag(),
        last_signed_at: last,
    })
}

/// Bootstrap the OS-keychain backed signer:
///
/// 1. Pull the platform-default [`crate::secure_key_store::SecureKeyStore`]
///    (`KeyringSecureKeyStore` on desktop, `LocalStorageSecureKeyStore` on wasm32,
///    `HostBridgeSecureKeyStore` on mobile when a host bridge is installed).
/// 2. [`crate::secure_key_store::ensure_signing_seed`] — loads the seed or generates and persists a
///    fresh one.
/// 3. [`build_ed25519_signer`] from the seed + derived did:key.
/// 4. [`install_active_signer`] + [`crate::operation::set_proof_mode`] so the submit guard switches
///    to the real-signer path.
///
/// Returns the installed signer for the caller to thread into the UI.
/// On error the caller is expected to fall back to either
/// [`ProofMode::PlaceholderDev`] (dev only) or [`ProofMode::Production`]
/// (fail-closed) and surface the error to the user.
pub fn bootstrap_default_signer(
    service_name: &str,
) -> Result<Arc<YougenEventSigner>, anyhow::Error> {
    let store = crate::secure_key_store::default_secure_key_store(service_name);
    let material = crate::secure_key_store::ensure_signing_seed(&*store)
        .map_err(|err| anyhow::anyhow!("ensure_signing_seed failed: {err}"))?;
    let signer = Arc::new(build_ed25519_signer(material.seed, material.device_did));
    install_active_signer(signer.clone());
    crate::operation::set_proof_mode(crate::operation::ProofMode::RealEd25519);
    Ok(signer)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::canonical::canonical_json_bytes;
    use crate::operation::{OperationBuilder, set_proof_mode};

    /// Same per-process guard pattern operation.rs uses — proof-mode
    /// and active-signer state is global so concurrent tests would
    /// race.
    static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn reset() -> impl Drop {
        let guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let _ = replace_active_signer(None);
        // Hold the lock for the lifetime of the returned guard so
        // sibling tests cannot race the global signer slot. The lock
        // guard is kept inside the struct rather than dropped early.
        struct Reset(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);
        impl Drop for Reset {
            fn drop(&mut self) {
                let _ = replace_active_signer(None);
            }
        }
        Reset(guard)
    }

    #[test]
    fn build_ed25519_signer_sets_did_and_verification_method() {
        let _g = reset();
        let signer = build_ed25519_signer([7u8; 32], "did:web:alice.example");
        assert_eq!(signer.signer_did(), "did:web:alice.example");
        assert_eq!(signer.verification_method(), "did:web:alice.example#device");
        assert_eq!(signer.algorithm(), "EdDSA");
        assert_eq!(signer.mode_tag(), "ed25519");
        assert!(signer.last_signed_at_snapshot().is_none());
    }

    #[test]
    fn sign_envelope_attaches_real_jws_proof() {
        let _g = reset();
        let signer = build_ed25519_signer([3u8; 32], "did:web:bob.example");

        let prior_mode = current_proof_mode();
        set_proof_mode(ProofMode::RealEd25519);
        let mut event =
            OperationBuilder::new("ck:space:t", "did:web:bob.example", "cx.message.create")
                .body(json!({"body": "hi"}))
                .build("test_node");
        set_proof_mode(prior_mode);

        // RealEd25519 mode skips placeholder attach.
        assert!(event.proofs.is_empty());

        signer.sign_envelope(&mut event).expect("sign");

        let proof = event.proofs.first().expect("real proof attached");
        assert_eq!(proof.kind, "detached_jws");
        assert_eq!(proof.alg, "EdDSA");
        assert_eq!(proof.verification_method, "did:web:bob.example#device");
        assert!(proof.event_digest.starts_with("sha256:"));
        // Real detached JWS: header..signature, signature non-empty.
        let parts: Vec<&str> = proof.jws.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[1].is_empty()); // detached
        assert!(!parts[2].is_empty());

        assert!(signer.last_signed_at_snapshot().is_some());
    }

    #[test]
    fn sign_envelope_roots_proof_in_event_actor() {
        let _g = reset();
        let signer = build_ed25519_signer([9u8; 32], "did:key:zlocal");

        let prior_mode = current_proof_mode();
        set_proof_mode(ProofMode::RealEd25519);
        let mut event =
            OperationBuilder::new("ck:space:t", "did:web:alice.example", "cx.message.create")
                .body(json!({"body": "actor-rooted"}))
                .build("test_node");
        set_proof_mode(prior_mode);

        signer.sign_envelope(&mut event).expect("sign");

        let proof = event.proofs.first().expect("proof");
        assert_eq!(proof.verification_method, "did:web:alice.example#device");
        assert_eq!(event.actor_id, "did:web:alice.example");
    }

    #[test]
    fn sign_envelope_round_trips_through_sdk_verifier() {
        use contrix_sdk::signatures::proof::{
            Ed25519DetachedJwsSigner, Ed25519DetachedJwsVerifier, EventVerifier, PublicKeyMaterial,
        };
        let _g = reset();
        let seed = [5u8; 32];
        let signer = build_ed25519_signer(seed, "did:web:carol.example");

        // Compute the matching verifying key for the seed via the SDK.
        let sdk_signer = Ed25519DetachedJwsSigner::from_seed(seed, "did:web:carol.example#device");
        let public_key = PublicKeyMaterial::Ed25519Raw {
            bytes: sdk_signer.verifying_key().to_bytes().to_vec(),
        };

        let prior_mode = current_proof_mode();
        set_proof_mode(ProofMode::RealEd25519);
        let mut event =
            OperationBuilder::new("ck:space:t", "did:web:carol.example", "cx.message.create")
                .body(json!({"body": "verifiable"}))
                .build("test_node");
        set_proof_mode(prior_mode);

        signer.sign_envelope(&mut event).expect("sign");

        // Recompute the canonical event digest, then verify the JWS
        // over the spec proof-binding object. Event proofs sign
        // `{event_digest, actor_id, verification_method, created_at}`,
        // not the full event bytes directly.
        let mut canonical = serde_json::to_value(&event).unwrap();
        if let Value::Object(obj) = &mut canonical {
            obj.remove("proofs");
            obj.remove("unsigned");
        }
        let canonical_bytes = canonical_json_bytes(&canonical).unwrap();
        let proof = event.proofs.first().unwrap();
        assert_eq!(
            proof.event_digest,
            crate::canonical::sha256_digest(&canonical_bytes).as_str()
        );
        let proof_binding_bytes = canonical_json_bytes(&json!({
            "event_digest": proof.event_digest.as_str(),
            "actor_id": event.actor_id.as_str(),
            "verification_method": proof.verification_method.as_str(),
            "created_at": proof.created_at.as_str(),
        }))
        .unwrap();

        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let parts: Vec<&str> = proof.jws.split('.').collect();
        assert_eq!(parts.len(), 3);
        let sig = URL_SAFE_NO_PAD.decode(parts[2]).expect("sig b64");

        let verifier = Ed25519DetachedJwsVerifier::new();
        verifier
            .verify(&proof_binding_bytes, &sig, &public_key)
            .expect("SDK verifier accepts the proof");
    }

    #[test]
    fn install_and_replace_active_signer() {
        let _g = reset();
        assert!(active_signer().is_none());
        assert!(!should_auto_sign());

        let signer = Arc::new(build_ed25519_signer([1u8; 32], "did:web:x"));
        assert!(install_active_signer(signer.clone()));

        let prior_mode = current_proof_mode();
        set_proof_mode(ProofMode::RealEd25519);
        assert!(should_auto_sign());
        set_proof_mode(prior_mode);

        let prev = replace_active_signer(None);
        assert!(prev.is_some());
        assert!(active_signer().is_none());
    }

    #[test]
    fn sign_with_active_uses_installed_signer() {
        let _g = reset();
        let signer = Arc::new(build_ed25519_signer([2u8; 32], "did:web:dave.example"));
        install_active_signer(signer);

        let prior_mode = current_proof_mode();
        set_proof_mode(ProofMode::RealEd25519);
        let mut event =
            OperationBuilder::new("ck:space:t", "did:web:dave.example", "cx.message.create")
                .body(json!({"body": "auto"}))
                .build("test_node");
        sign_with_active(&mut event).expect("auto sign");
        set_proof_mode(prior_mode);

        let proof = event.proofs.first().expect("auto-attached proof");
        assert_eq!(proof.verification_method, "did:web:dave.example#device");
        // Submit guard accept-shape: header..signature, non-empty sig.
        assert!(proof.jws.contains(".."));
        let sig_segment = proof.jws.split("..").nth(1).unwrap();
        assert!(!sig_segment.is_empty());
    }

    #[test]
    fn sign_with_active_returns_missing_signer_when_none_installed() {
        let _g = reset();
        let mut event =
            OperationBuilder::new("ck:space:t", "did:web:eve.example", "cx.message.create")
                .body(json!({"body": "no"}))
                .build("test_node");
        let err = sign_with_active(&mut event).unwrap_err();
        assert!(matches!(err, EventSignerError::MissingSigner { .. }));
    }

    #[test]
    fn signer_status_reports_installed_signer_metadata() {
        let _g = reset();
        assert!(signer_status().is_none());

        let signer = Arc::new(build_ed25519_signer([4u8; 32], "did:web:frank.example"));
        install_active_signer(signer);

        let status = signer_status().expect("status");
        assert_eq!(status.signer_did, "did:web:frank.example");
        assert_eq!(status.verification_method, "did:web:frank.example#device");
        assert_eq!(status.algorithm, "EdDSA");
        assert_eq!(status.mode_tag, "ed25519");
        assert!(status.last_signed_at.is_none());
    }

    #[test]
    fn proof_type_tag_is_production() {
        let pt = YougenEventSigner::proof_type_tag();
        assert!(!pt.is_development());
    }
}
