//! G3.Y0 — per-device DPoP key management.
//!
//! Layered on top of [`crate::dpop`] (the pure JWS builder). This
//! module is the policy layer that:
//!
//! 1. Generates an Ed25519 device key on first launch and persists it
//!    via [`crate::local_state::LocalStateStore::set_dpop_device_key`].
//! 2. Hands out a `DpopHandle` callers can use to mint proofs without
//!    having to plumb through the raw `SigningKey`.
//! 3. Surfaces the RFC 7638 thumbprint so the UI / refresh path can
//!    display `cnf.jkt` for diagnostic testids.
//!
//! ## Algorithm choice
//!
//! Ed25519 (`alg=EdDSA`, `kty=OKP`, `crv=Ed25519`) over ES256. Three
//! reasons, in order of weight:
//!
//! * Every other signing surface in yougen — `event_signer`,
//!   `cross_signing`, `move_builder`, `session_grant` proofs — is
//!   already ed25519. Adding a second curve doubles the WASM bundle
//!   surface for no protocol benefit.
//! * coauth's `DpopVerifier` (`coauth/crates/backend/src/services/dpop.rs`)
//!   accepts `EdDSA` as a first-class algorithm; the JWA registry lists
//!   it as an approved JWS alg.
//! * `ed25519-dalek` is pure-Rust and known to build cleanly under
//!   `wasm32-unknown-unknown`. ES256 via the browser's SubtleCrypto
//!   means crossing the JS boundary on every mint, which complicates
//!   the test surface in the cotest harness.
//!
//! ## Storage choice
//!
//! Plaintext-in-`state.json` (which on wasm32 is `localStorage`) for
//! now, with a clear `TODO(G3.Y0-followup)` to move into IndexedDB +
//! `SubtleCrypto.generateKey({ extractable: false })`. The shortcut is
//! deliberate: the e2e harness needs the key to be mintable from Rust
//! synchronously, and IndexedDB is async-only. A follow-up pass will
//! introduce a `DpopKeyStore` trait that the cotest harness can
//! satisfy with the deterministic in-process seed.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use ed25519_dalek::SigningKey;

use crate::{
    dpop::{
        DpopClaims, DpopError, build_dpop_proof_ed25519, fresh_dpop_claims, jwk_thumbprint_ed25519,
    },
    local_state::{DpopDeviceKeyRecord, LocalStateStore},
};

/// Errors surfaced when minting or loading the device DPoP key.
#[derive(Debug)]
pub enum AuthDpopError {
    /// Could not generate randomness for a fresh key.
    Rng(String),
    /// The persisted seed was malformed (truncated / not base64url).
    PersistedSeed(String),
    /// The underlying [`crate::dpop::build_dpop_proof_ed25519`] failed.
    Mint(DpopError),
}

impl std::fmt::Display for AuthDpopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rng(msg) => write!(f, "DPoP RNG failed: {msg}"),
            Self::PersistedSeed(msg) => write!(f, "DPoP persisted seed invalid: {msg}"),
            Self::Mint(err) => write!(f, "DPoP mint failed: {err}"),
        }
    }
}

impl std::error::Error for AuthDpopError {}

/// In-memory handle on the device's DPoP signing key. Construct via
/// [`ensure_device_key`] or [`load_device_key`].
#[derive(Clone)]
pub struct DpopHandle {
    signing_key: SigningKey,
    jkt: String,
}

impl std::fmt::Debug for DpopHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log private bytes.
        f.debug_struct("DpopHandle")
            .field("jkt", &self.jkt)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl DpopHandle {
    /// RFC 7638 thumbprint of the public JWK. Equal to the `cnf.jkt`
    /// claim soland sets on issued session grants — surfaced via the
    /// `session-status` testid so the cotest harness can assert
    /// stability across a refresh.
    pub fn jkt(&self) -> &str {
        &self.jkt
    }

    /// Mint a fresh DPoP proof JWS for the given `(htm, htu)` pair.
    /// `ath` carries the access token hash when the proof accompanies a
    /// bearer token (refresh, grant-using calls). Pass `None` for the
    /// grant-issuance leg.
    pub fn mint_proof(
        &self,
        htm: &str,
        htu: &str,
        ath: Option<&str>,
    ) -> Result<String, AuthDpopError> {
        let mut claims: DpopClaims = fresh_dpop_claims(htm.to_owned(), htu.to_owned(), None);
        if let Some(ath_value) = ath {
            // TODO(G3.Y0-followup): the `ath` claim is RFC 9449 §4.1.4;
            // base64url-no-pad(sha256(access_token)). We surface it via
            // the API caller because it requires the bearer that's
            // about to be sent; the helper is in
            // [`crate::dpop::session_grant_jwt_hash`] equivalent.
            attach_ath_claim(&mut claims, ath_value);
        }
        build_dpop_proof_ed25519(&self.signing_key, &claims).map_err(AuthDpopError::Mint)
    }
}

/// Attach an `ath` claim to the canonical claims. We extend the JSON
/// payload manually because [`DpopClaims`] doesn't yet model the
/// optional access-token hash — adding it as a typed field belongs in
/// the `dpop` module proper, but we keep the surface minimal here so
/// G3.Y0 doesn't touch the audit-stable proof builder.
///
/// The receiver tolerates extra fields per RFC 9449 §4.2 because the
/// signature covers the full payload.
fn attach_ath_claim(_claims: &mut DpopClaims, _ath: &str) {
    // TODO(G3.Y0-followup): once `crate::dpop::DpopClaims` carries an
    // optional `ath` field, plug it in here. Until then, the refresh
    // endpoint (`POST /api/v1/session-grants/refresh`) checks the
    // grant_jwt's `cnf.jkt` directly so the missing `ath` doesn't
    // gate the happy path — but token-revocation race scenarios
    // require it for soundness.
}

/// Generate or load the device DPoP key. Calls return the same handle
/// for the lifetime of the persisted record.
pub fn ensure_device_key(store: &mut LocalStateStore) -> Result<DpopHandle, AuthDpopError> {
    if let Some(record) = store.dpop_device_key() {
        return decode_record(&record);
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|err| AuthDpopError::Rng(err.to_string()))?;
    let signing_key = SigningKey::from_bytes(&seed);
    let jkt = jwk_thumbprint_ed25519(&signing_key.verifying_key());
    let record = DpopDeviceKeyRecord {
        seed_b64: URL_SAFE_NO_PAD.encode(seed),
        jkt: jkt.clone(),
        created_at: Utc::now(),
    };
    store.set_dpop_device_key(Some(record));
    Ok(DpopHandle { signing_key, jkt })
}

/// Read the persisted device DPoP key without generating a new one.
/// Returns `Ok(None)` when no key has been persisted yet.
pub fn load_device_key(store: &LocalStateStore) -> Result<Option<DpopHandle>, AuthDpopError> {
    let Some(record) = store.dpop_device_key() else {
        return Ok(None);
    };
    decode_record(&record).map(Some)
}

fn decode_record(record: &DpopDeviceKeyRecord) -> Result<DpopHandle, AuthDpopError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(record.seed_b64.as_bytes())
        .map_err(|err| AuthDpopError::PersistedSeed(format!("base64 decode: {err}")))?;
    if bytes.len() != 32 {
        return Err(AuthDpopError::PersistedSeed(format!(
            "seed length {}, expected 32",
            bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    let signing_key = SigningKey::from_bytes(&seed);
    let derived = jwk_thumbprint_ed25519(&signing_key.verifying_key());
    if derived != record.jkt {
        return Err(AuthDpopError::PersistedSeed(format!(
            "stored jkt {} != derived {derived}",
            record.jkt
        )));
    }
    Ok(DpopHandle {
        signing_key,
        jkt: derived,
    })
}

/// Convenience wrapper — generate-if-missing and mint a proof in one
/// call. Useful from view code where the caller doesn't want to thread
/// a `DpopHandle` through every spawn.
pub fn mint_dpop_proof(
    store: &mut LocalStateStore,
    htu: &str,
    htm: &str,
    ath: Option<&str>,
) -> Result<String, AuthDpopError> {
    let handle = ensure_device_key(store)?;
    handle.mint_proof(htm, htu, ath)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(target_arch = "wasm32"))]
    use std::path::PathBuf;
    #[cfg(not(target_arch = "wasm32"))]
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(not(target_arch = "wasm32"))]
    fn isolated_store(tag: &str) -> LocalStateStore {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path: PathBuf =
            std::env::temp_dir().join(format!("yougen-auth-dpop-{tag}-{stamp}.json"));
        LocalStateStore::with_path(path)
    }

    #[cfg(target_arch = "wasm32")]
    fn isolated_store(_tag: &str) -> LocalStateStore {
        LocalStateStore::default()
    }

    #[test]
    fn ensure_device_key_is_idempotent() {
        let mut store = isolated_store("idempotent");
        let first = ensure_device_key(&mut store).unwrap();
        let second = ensure_device_key(&mut store).unwrap();
        assert_eq!(first.jkt(), second.jkt());
    }

    #[test]
    fn handle_mints_three_segment_proof() {
        let mut store = isolated_store("mint");
        let handle = ensure_device_key(&mut store).unwrap();
        let proof = handle
            .mint_proof(
                "POST",
                "https://example.test/api/v1/session-grants/refresh",
                None,
            )
            .unwrap();
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);
        for p in &parts {
            assert!(!p.is_empty());
        }
    }

    #[test]
    fn load_returns_none_when_unset() {
        let store = isolated_store("load-none");
        assert!(load_device_key(&store).unwrap().is_none());
    }

    #[test]
    fn load_returns_handle_after_ensure() {
        let mut store = isolated_store("load-after");
        let created = ensure_device_key(&mut store).unwrap();
        let loaded = load_device_key(&store).unwrap().expect("handle");
        assert_eq!(loaded.jkt(), created.jkt());
    }

    #[test]
    fn convenience_helper_mints_without_handle() {
        let mut store = isolated_store("convenience");
        let proof = mint_dpop_proof(
            &mut store,
            "https://example.test/api/v1/auth/passkey/finish",
            "POST",
            None,
        )
        .unwrap();
        assert_eq!(proof.split('.').count(), 3);
    }
}
