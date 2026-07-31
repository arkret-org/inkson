//! Active-write event signer wired against the SDK's unified
//! `EventProofBuilder` / `Ed25519DetachedJwsSigner` pipeline.
//!
//! T5.2 (Round 22, 2026-05-20) — T5.1 landed `Ed25519DetachedJwsSigner`,
//! `EventProofBuilder`, and `ProductionVerifier` in the SDK
//! (`arkret-rust-sdk/crates/signatures/src/proof.rs`). Before T5.2
//! inkson's previous Event signing helper hand-rolled
//! the same canonical-bytes → JWS pipeline, which meant a bug fixed in
//! the SDK had to be ported a second time into inkson. This module
//! collapses both code paths through the SDK.
//!
//! ## What lives here
//!
//! * [`InksonEventSigner`] — opaque handle around an `EventSigner` trait object plus the metadata
//!   UI surfaces want (`signer_did`, `verification_method`, last-sign timestamp).
//! * [`build_ed25519_signer`] — bootstrap that takes a 32-byte Ed25519 seed (typically loaded via
//!   `secure_key_store::ensure_signing_seed`) and returns a `InksonEventSigner` ready to attach
//!   detached JWS proofs to event envelopes.
//! * [`install_active_signer`] / [`active_signer`] — a process-wide `OnceLock` that holds the
//!   active signer; [`crate::transport::TransportClient::submit_sdk_event`] reaches into this to
//!   lazily sign SDK events that were built unsigned.
//! * [`signer_status`] — diagnostic snapshot for the settings panel.
//!
//! ## Canonical bytes alignment
//!
//! The SDK's `EventProofBuilder` operates over an opaque `T: Serialize`.
//! The builder now emits `arkret_sdk::Event` directly, so this module derives
//! `Event::event_digest()` from the SDK event in place.
//!
//! ## Wiring contract
//!
//! Boot (e.g. `app::init`) should call:
//!
//! ```ignore
//! let store = crate::secure_key_store::default_secure_key_store("inkson");
//! let material = crate::secure_key_store::ensure_signing_seed(&*store)?;
//! let signer = crate::event_signer::build_ed25519_signer(
//!     material.seed,
//!     material.local_signing_did.clone(),
//! );
//! crate::event_signer::install_active_signer(std::sync::Arc::new(signer));
//! crate::operation::set_proof_mode(crate::operation::ProofMode::RealEd25519);
//! ```
//!
//! Hosts that prefer to hand in an external signer (HSM, WebAuthn,
//! `secret-service`-mediated PIN-protected key) skip the seed step and
//! call [`InksonEventSigner::from_dyn_signer`] directly. The submit
//! guard then routes through their backend instead of the in-process
//! seed.

use std::sync::{Arc, Mutex, OnceLock};

use arkret_sdk::signatures::proof::{EventSigner as SdkEventSigner, ProofType};
use arkret_sdk::{Did, DidUrl, Hash, PayloadSigner, WireError};
use arkret_wire::PayloadSignature;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer as _, SigningKey};

use crate::operation::{Event, EventProofAudience, ProofMode, current_proof_mode};

/// Errors produced by the active-write signing pipeline.
#[derive(Debug, thiserror::Error)]
pub enum EventSignerError {
    /// The active runtime [`ProofMode`] expects a real signer but none
    /// has been installed via [`install_active_signer`]. The submit
    /// guard surfaces this so the UI can prompt the user.
    #[error(
        "no event signer installed (active proof mode = {mode}). \
        Boot must call event_signer::install_active_signer with a real \
        signer; ProofMode::Production stays fail-closed until it does."
    )]
    MissingSigner { mode: &'static str },
    /// The underlying SDK backend refused to sign.
    #[error("event signer backend rejected payload: {0}")]
    Backend(String),
    /// Canonical serialisation failed before reaching the signer.
    #[error("canonical encoding failed before signing: {0}")]
    Encoding(String),
    /// A caller needs a raw Ed25519 signature over canonical JSON bytes,
    /// but this signer only exposes the detached-JWS event-signing path.
    #[error("raw canonical-byte signing is not available for this signer")]
    RawSigningUnavailable,
}

/// Domain/audience binding carried by EventProof and included in the
/// canonical proof-binding bytes that the detached JWS signs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventProofContext {
    pub domain: Option<String>,
    pub audience: Option<EventProofAudience>,
}

impl EventProofContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    pub fn with_audience(mut self, audience: EventProofAudience) -> Self {
        self.audience = Some(audience);
        self
    }
}

/// Opaque handle wrapping an SDK [`SdkEventSigner`] trait object plus
/// the metadata inkson's UI / submit guard care about.
pub struct InksonEventSigner {
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
    /// Protocol device id for durable Event proofs. When present, ordinary
    /// event proofs use `<event actor/controller>#<device_id>`.
    device_id: Option<String>,
    /// Coarse mode tag used by the UI to colour the badge — `"ed25519"`
    /// for the in-process seed path and `"external"` for delegated
    /// backends.
    mode_tag: &'static str,
    /// Local seed-backed signers can also produce raw Ed25519 signatures
    /// over canonical JSON bytes. Event proofs still go through the SDK
    /// detached-JWS signer held in `inner`.
    raw_signing_key: Option<SigningKey>,
    /// Wall-clock timestamp of the most recent successful sign call.
    /// `None` until the first sign succeeds. Exposed for the UI
    /// freshness indicator.
    last_signed_at: Mutex<Option<DateTime<Utc>>>,
}

struct InksonPayloadSignerAdapter<'a> {
    owner: &'a InksonEventSigner,
    did: Did,
    /// Typed DID URL: `arkret_wire::PayloadSigner::verification_method_id`
    /// returns `&DidUrl`, so the adapter owns the validated form rather than
    /// re-parsing a `String` on every call.
    verification_method: DidUrl,
}

impl PayloadSigner for InksonPayloadSignerAdapter<'_> {
    fn signer_did(&self) -> &Did {
        &self.did
    }

    fn verification_method_id(&self) -> &DidUrl {
        &self.verification_method
    }

    fn sign_payload(&self, canonical_bytes: &[u8]) -> Result<PayloadSignature, WireError> {
        let signature = self
            .owner
            .inner
            .sign(canonical_bytes)
            .map_err(|error| WireError::Protocol(error.to_string()))?;
        let header = serde_json::to_vec(&serde_json::json!({
            "alg": self.owner.algorithm(),
        }))?;
        Ok(PayloadSignature {
            alg: self.owner.algorithm().to_owned(),
            verification_method: self.verification_method.clone(),
            payload_digest: Hash::new(arkret_sdk::canonical::sha256_digest(canonical_bytes))?,
            created_at: crate::clock::now_utc(),
            jws: format!(
                "{}..{}",
                URL_SAFE_NO_PAD.encode(header),
                URL_SAFE_NO_PAD.encode(signature)
            ),
            // `seal.schema.json#/$defs/signature` is `additionalProperties:
            // true`; inkson emits no extension members.
            extra: Default::default(),
        })
    }
}

impl std::fmt::Debug for InksonEventSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InksonEventSigner")
            .field("signer_did", &self.signer_did)
            .field("verification_method", &self.verification_method)
            .field("device_id", &self.device_id)
            .field("mode_tag", &self.mode_tag)
            .field("algorithm", &self.inner.algorithm())
            .field("raw_signing_available", &self.raw_signing_key.is_some())
            .field("last_signed_at", &self.last_signed_at_snapshot())
            .finish()
    }
}

impl InksonEventSigner {
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
            device_id: None,
            mode_tag: "external",
            raw_signing_key: None,
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

    /// Protocol `ak:device:*` id bound into ordinary Event proof fragments.
    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    /// Local seed-backed signer's Ed25519 public key in multibase form.
    pub fn public_key_multibase(&self) -> Option<String> {
        self.raw_signing_key.as_ref().map(|key| {
            crate::identity::did_key::encode_ed25519_did_key_multibase(&key.verifying_key())
        })
    }

    /// Local seed-backed signer's raw 32-byte Ed25519 public key as
    /// unpadded base64url. Device-pairing `PublicKey.key` uses this encoding,
    /// rather than the multibase encoding used by device directory records.
    pub fn public_key_base64url(&self) -> Option<String> {
        self.raw_signing_key
            .as_ref()
            .map(|key| URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()))
    }

    /// JWS algorithm name (e.g. `"EdDSA"`).
    pub fn algorithm(&self) -> &str {
        self.inner.algorithm()
    }

    /// Produce a raw Ed25519 signature over `bytes` (not a detached JWS).
    /// Used for protocol control-plane proofs such as key backup
    /// `auth_data.signature` and recovery proofs, whose wire form is a
    /// single base64url token over canonical JSON bytes.
    pub fn sign_raw(&self, bytes: &[u8]) -> Result<Vec<u8>, EventSignerError> {
        let Some(signing_key) = &self.raw_signing_key else {
            return Err(EventSignerError::RawSigningUnavailable);
        };
        let signature = signing_key.sign(bytes);
        if let Ok(mut guard) = self.last_signed_at.lock() {
            *guard = Some(crate::clock::now_utc());
        }
        Ok(signature.to_bytes().to_vec())
    }

    /// Adapt the session device key as an authenticated principal signer.
    ///
    /// The locally stored key can have a `did:key` identity while the server
    /// session binds that same key to `<principal>#<device_id>`. Protocol
    /// authoring that commits to the account principal must use the latter
    /// identity, not the local key DID.
    pub(crate) fn payload_signer_adapter_for_principal(
        &self,
        principal_id: &Did,
    ) -> Result<impl PayloadSigner + '_, EventSignerError> {
        let verification_method = self.verification_method_for_principal(principal_id)?;
        Ok(InksonPayloadSignerAdapter {
            owner: self,
            did: principal_id.clone(),
            verification_method,
        })
    }

    /// The principal-scoped verification method, as a validated
    /// [`DidUrl`]. Both shapes it can produce carry a `#fragment`, so the
    /// conversion only fails on genuinely malformed identifiers — which is a
    /// real error, not a case to paper over with a `String`.
    pub(crate) fn verification_method_for_principal(
        &self,
        principal_id: &Did,
    ) -> Result<DidUrl, EventSignerError> {
        let raw = match self.device_id.as_deref() {
            Some(device_id) => format!("{principal_id}#{device_id}"),
            None if self.signer_did == principal_id.as_str() => {
                self.verification_method.as_str().to_owned()
            }
            None => {
                return Err(EventSignerError::Encoding(format!(
                    "principal-bound signing for {principal_id} requires a bound device_id"
                )));
            }
        };
        DidUrl::new(raw).map_err(|error| EventSignerError::Encoding(error.to_string()))
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

    /// Sign `event` in place through the SDK proof pipeline. An existing proof
    /// for the same verification method is replaced idempotently; a proof from
    /// another verification method makes the signing attempt fail closed.
    ///
    /// Updates [`Self::last_signed_at_snapshot`] on success.
    pub fn sign_envelope(&self, event: &mut Event) -> Result<(), EventSignerError> {
        self.sign_envelope_with_context(event, EventProofContext::default())
    }

    /// Sign `event` with an explicit EventProof domain/audience binding.
    pub fn sign_envelope_with_context(
        &self,
        event: &mut Event,
        context: EventProofContext,
    ) -> Result<(), EventSignerError> {
        self.sign_sdk_event_with_context(event, context)
    }

    /// Sign a SDK-typed Event in place. This is the single event proof path for
    /// modules that build `arkret_sdk::Event` through the operation builder.
    pub fn sign_sdk_event_with_context(
        &self,
        event: &mut arkret_sdk::Event,
        context: EventProofContext,
    ) -> Result<(), EventSignerError> {
        let verification_method = self.verification_method_for_sdk_event(event)?;
        let proof_audience = context
            .audience
            .as_ref()
            .map(|audience| {
                serde_json::from_value::<arkret_sdk::Audience>(
                    serde_json::to_value(audience)
                        .map_err(|err| EventSignerError::Encoding(err.to_string()))?,
                )
                .map_err(|err| EventSignerError::Encoding(err.to_string()))
            })
            .transpose()?;
        let signer = InksonPayloadSignerAdapter {
            owner: self,
            did: Did::new(self.signer_did.clone())
                .map_err(|error| EventSignerError::Encoding(error.to_string()))?,
            verification_method: verification_method.clone(),
        };
        arkret_sdk::signatures::sign_event(
            event,
            &signer,
            &verification_method,
            arkret_sdk::signatures::SignEventOptions {
                domain: context.domain,
                audience: proof_audience,
                created_at: Some(crate::clock::now_utc()),
            },
        )
        .map_err(|error| EventSignerError::Backend(error.to_string()))?;

        if let Ok(mut guard) = self.last_signed_at.lock() {
            *guard = Some(crate::clock::now_utc());
        }
        let _proof_type = Self::proof_type_tag();
        Ok(())
    }

    /// Build the first B-model principal-control Seal with this device key.
    /// The signer identity is rebound to the principal and the verification
    /// method is the explicit `<principal>#<device_id>` session binding.
    pub fn sign_self_principal_bootstrap_seal(
        &self,
        create: &arkret_sdk::Event,
        authorize: &arkret_sdk::Event,
        hlc: arkret_sdk::Hlc,
    ) -> Result<arkret_sdk::Seal, EventSignerError> {
        let device_id = self.device_id.as_deref().ok_or_else(|| {
            EventSignerError::Encoding(
                "principal bootstrap Seal requires a bound device_id".to_owned(),
            )
        })?;
        let signer = InksonPayloadSignerAdapter {
            owner: self,
            did: create.actor_id.clone(),
            verification_method: DidUrl::new(format!("{}#{device_id}", create.actor_id))
                .map_err(|error| EventSignerError::Encoding(error.to_string()))?,
        };
        arkret_bootstrap::build_self_principal_bootstrap_seal(
            create,
            authorize,
            hlc,
            &signer,
            &crate::operation::cell_write_projector,
        )
        .map_err(|error| EventSignerError::Backend(error.to_string()))
    }

    /// Sign the first post-bootstrap self-PCR Seal. The predecessor view is
    /// the accepted two-Event bootstrap Seal; the first successor is the
    /// recovery-policy Event required before the first encrypted backup.
    pub fn sign_self_principal_first_successor_seal(
        &self,
        create: &arkret_sdk::Event,
        authorize: &arkret_sdk::Event,
        successor: &arkret_sdk::Event,
        predecessor: &arkret_sdk::RealmSealFrontierView,
        hlc: arkret_sdk::Hlc,
    ) -> Result<arkret_sdk::Seal, EventSignerError> {
        let device_id = self.device_id.as_deref().ok_or_else(|| {
            EventSignerError::Encoding(
                "principal successor Seal requires a bound device_id".to_owned(),
            )
        })?;
        let signer = InksonPayloadSignerAdapter {
            owner: self,
            did: create.actor_id.clone(),
            verification_method: DidUrl::new(format!("{}#{device_id}", create.actor_id))
                .map_err(|error| EventSignerError::Encoding(error.to_string()))?,
        };
        arkret_bootstrap::build_self_principal_first_successor_seal(
            create,
            authorize,
            successor,
            predecessor,
            hlc,
            &signer,
            &crate::operation::cell_write_projector,
        )
        .map_err(|error| EventSignerError::Backend(error.to_string()))
    }

    pub fn sign_self_principal_linear_successor_seal(
        &self,
        events: &[arkret_sdk::Event],
        predecessor: &arkret_sdk::RealmSealFrontierView,
        hlc: arkret_sdk::Hlc,
    ) -> Result<arkret_sdk::Seal, EventSignerError> {
        let principal = events.first().ok_or_else(|| {
            EventSignerError::Encoding(
                "principal successor Seal requires accepted Event history".to_owned(),
            )
        })?;
        let device_id = self.device_id.as_deref().ok_or_else(|| {
            EventSignerError::Encoding(
                "principal successor Seal requires a bound device_id".to_owned(),
            )
        })?;
        let signer = InksonPayloadSignerAdapter {
            owner: self,
            did: principal.actor_id.clone(),
            verification_method: DidUrl::new(format!("{}#{device_id}", principal.actor_id))
                .map_err(|error| EventSignerError::Encoding(error.to_string()))?,
        };
        arkret_bootstrap::build_self_principal_linear_successor_seal(
            events,
            predecessor,
            hlc,
            &signer,
            &crate::operation::cell_write_projector,
        )
        .map_err(|error| EventSignerError::Backend(error.to_string()))
    }

    /// Sign a managed Agent PCR Seal as the controller device named by the
    /// Agent DID's accepted delegation. The wire signer is rebound to the
    /// controller DID and the authenticated `<controller>#<device_id>` method.
    pub fn sign_managed_agent_pcr_event_seal(
        &self,
        controller_id: &arkret_sdk::Did,
        events: &[arkret_sdk::Event],
        predecessor: Option<&arkret_sdk::Seal>,
        hlc: arkret_sdk::Hlc,
    ) -> Result<arkret_sdk::Seal, EventSignerError> {
        let device_id = self.device_id.as_deref().ok_or_else(|| {
            EventSignerError::Encoding(
                "managed Agent PCR Seal requires a bound device_id".to_owned(),
            )
        })?;
        let signer = InksonPayloadSignerAdapter {
            owner: self,
            did: controller_id.clone(),
            verification_method: DidUrl::new(format!("{controller_id}#{device_id}"))
                .map_err(|error| EventSignerError::Encoding(error.to_string()))?,
        };
        arkret_bootstrap::build_managed_agent_pcr_event_seal(
            events,
            predecessor,
            hlc,
            &signer,
            &crate::operation::cell_write_projector,
        )
        .map_err(|error| EventSignerError::Backend(error.to_string()))
    }

    /// Produce a detached JWS (`<b64u header>..<b64u sig>`) over `bytes`
    /// using the active backend, matching the alg-only protected header
    /// shape [`Self::sign_envelope_with_context`] uses. Control-plane
    /// signatures that are NOT [`Event`] proofs — notably the
    /// `ak.call.signal` ephemeral envelope `proof` (spec
    /// `webrtc-signaling.md` §5: detached signature over canonical
    /// envelope bytes excluding `proof`) — go through this helper instead
    /// of re-deriving the JWS reassembly.
    pub fn detached_jws_over(&self, bytes: &[u8]) -> Result<String, EventSignerError> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let signature = self
            .inner
            .sign(bytes)
            .map_err(|err| EventSignerError::Backend(err.to_string()))?;
        let header = serde_json::json!({ "alg": self.algorithm() });
        let header = serde_json::to_vec(&header)
            .map_err(|err| EventSignerError::Encoding(err.to_string()))?;
        let header_b64 = URL_SAFE_NO_PAD.encode(&header);
        let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);
        if let Ok(mut guard) = self.last_signed_at.lock() {
            *guard = Some(crate::clock::now_utc());
        }
        Ok(format!("{header_b64}..{sig_b64}"))
    }

    /// Produce a detached compact JWS (`<b64u header>..<b64u sig>`) with a
    /// `kid` protected-header claim. Unlike [`Self::detached_jws_over`], this
    /// follows RFC 7515 signing input rules and signs
    /// `b64u(header) "." b64u(payload)`. The session-grant refresh endpoint
    /// verifies this shape against the Principal Server's authorized device
    /// key.
    pub fn detached_jws_over_payload_with_kid(
        &self,
        kid: &str,
        payload: &[u8],
    ) -> Result<String, EventSignerError> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let kid = kid.trim();
        if kid.is_empty() {
            return Err(EventSignerError::Encoding(
                "detached JWS kid must not be empty".to_owned(),
            ));
        }
        let header = serde_json::json!({
            "alg": self.algorithm(),
            "kid": kid,
        });
        let header = serde_json::to_vec(&header)
            .map_err(|err| EventSignerError::Encoding(err.to_string()))?;
        let header_b64 = URL_SAFE_NO_PAD.encode(&header);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let Some(signing_key) = &self.raw_signing_key else {
            return Err(EventSignerError::RawSigningUnavailable);
        };
        let signature = signing_key.sign(signing_input.as_bytes()).to_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature);
        if let Ok(mut guard) = self.last_signed_at.lock() {
            *guard = Some(crate::clock::now_utc());
        }
        Ok(format!("{header_b64}..{sig_b64}"))
    }

    pub(crate) fn verification_method_for_sdk_event(
        &self,
        event: &arkret_sdk::Event,
    ) -> Result<DidUrl, EventSignerError> {
        let controller = event
            .executed_by
            .as_ref()
            .map(|did| did.as_str())
            .unwrap_or_else(|| event.actor_id.as_str());
        let raw = if let Some(device_id) = self.device_id.as_deref() {
            format!("{controller}#{device_id}")
        } else {
            let stored_controller = verification_method_controller(&self.verification_method);
            if stored_controller == controller {
                self.verification_method.as_str().to_owned()
            } else {
                format!("{controller}#device")
            }
        };
        DidUrl::new(raw).map_err(|error| EventSignerError::Encoding(error.to_string()))
    }

    /// The [`ProofType`] tag every proof emitted by this signer carries.
    /// Always `Production(detached_jws / <algorithm>)`. Exposed so
    /// receivers / tests can wrap a verifier with the matching tag
    /// without re-deriving it.
    pub fn proof_type_tag() -> ProofType {
        ProofType::production("detached_jws", "EdDSA")
    }
}

/// Build a [`InksonEventSigner`] backed by the SDK's
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
pub fn build_ed25519_signer(seed: [u8; 32], signer_did: impl Into<String>) -> InksonEventSigner {
    let signer_did = signer_did.into();
    let verification_method = format!("{signer_did}#device");
    build_ed25519_signer_with_verification_method(seed, signer_did, verification_method)
}

/// Build a local Ed25519 signer for a concrete protocol device id. Event
/// proofs are emitted as `<event actor/controller>#<device_id>`.
pub fn build_ed25519_device_signer(
    seed: [u8; 32],
    signer_did: impl Into<String>,
    device_id: impl Into<String>,
) -> InksonEventSigner {
    let mut signer = build_ed25519_signer(seed, signer_did);
    signer.device_id = normalize_signer_device_id(Some(device_id.into()));
    signer
}

/// Install the active device signer from the exact signing material used for
/// this session device. Callers that just enrolled or rehydrated the device
/// identity should use this instead of hand-building a signer so enrollment,
/// KeyPackage uploads, Welcome claim envelopes, and event proofs stay bound to
/// the same Ed25519 key.
pub fn install_device_signer_from_material(
    material: &crate::secure_key_store::SigningSeedMaterial,
) -> Arc<InksonEventSigner> {
    let signer = Arc::new(build_ed25519_signer(
        material.seed,
        material.local_signing_did.clone(),
    ));
    install_device_signer(signer)
}

pub fn install_device_signer_from_material_for_device(
    material: &crate::secure_key_store::SigningSeedMaterial,
    device_id: &str,
) -> Arc<InksonEventSigner> {
    let signer = Arc::new(build_ed25519_device_signer(
        material.seed,
        material.local_signing_did.clone(),
        device_id,
    ));
    install_device_signer(signer)
}

fn install_device_signer(signer: Arc<InksonEventSigner>) -> Arc<InksonEventSigner> {
    let installed = install_active_signer(signer.clone());
    crate::operation::set_proof_mode(crate::operation::ProofMode::RealEd25519);
    if installed {
        signer
    } else {
        active_signer().unwrap_or(signer)
    }
}

/// Make `seed` the active session-device signer, replacing any stale signer.
///
/// Separated-lifecycle boot paths pass the durable device identity signing seed
/// used for events, device authorization, KeyPackage claims, and MLS Welcome
/// claim envelopes. Grant-binding (DPoP) seeds have a separate lifecycle and
/// are installed in the auth DPoP store instead.
pub fn activate_device_signer_from_seed(
    seed: [u8; 32],
    persist_store: Option<&dyn crate::secure_key_store::SecureKeyStore>,
) -> Result<Arc<InksonEventSigner>, anyhow::Error> {
    activate_device_signer_from_seed_for_device(seed, persist_store, None)
}

pub fn activate_device_signer_from_seed_for_device(
    seed: [u8; 32],
    persist_store: Option<&dyn crate::secure_key_store::SecureKeyStore>,
    device_id: Option<&str>,
) -> Result<Arc<InksonEventSigner>, anyhow::Error> {
    let material = match persist_store {
        Some(store) => crate::secure_key_store::store_signing_seed(store, &seed)
            .map_err(|err| anyhow::anyhow!("persist device signing seed failed: {err}"))?,
        None => {
            let verifying = SigningKey::from_bytes(&seed).verifying_key();
            crate::secure_key_store::SigningSeedMaterial {
                seed,
                local_signing_did: crate::identity::did_key::did_key_from_verifying_key(&verifying),
            }
        }
    };
    let signer = match device_id.and_then(|device_id| normalize_signer_device_id(Some(device_id))) {
        Some(device_id) => Arc::new(build_ed25519_device_signer(
            material.seed,
            material.local_signing_did.clone(),
            device_id,
        )),
        None => Arc::new(build_ed25519_signer(
            material.seed,
            material.local_signing_did.clone(),
        )),
    };
    let expected_public_key = signer.public_key_multibase();
    let active_matches = active_signer()
        .and_then(|active| active.public_key_multibase())
        .is_some_and(|active_public_key| Some(active_public_key) == expected_public_key);
    let active = if active_matches {
        let active = active_signer().unwrap_or_else(|| signer.clone());
        if signer.device_id.is_some() && active.device_id != signer.device_id {
            replace_active_signer(Some(signer.clone()));
            signer
        } else {
            active
        }
    } else {
        let _ = replace_active_signer(Some(signer.clone()));
        signer
    };
    crate::operation::set_proof_mode(crate::operation::ProofMode::RealEd25519);
    Ok(active)
}

/// Decode a base64url-no-pad Ed25519 seed, then install it as the active
/// session-device signer.
pub fn activate_device_signer_from_seed_b64url(
    seed_b64url: &str,
    persist_store: Option<&dyn crate::secure_key_store::SecureKeyStore>,
) -> Result<Arc<InksonEventSigner>, anyhow::Error> {
    activate_device_signer_from_seed_b64url_for_device(seed_b64url, persist_store, None)
}

pub fn activate_device_signer_from_seed_b64url_for_device(
    seed_b64url: &str,
    persist_store: Option<&dyn crate::secure_key_store::SecureKeyStore>,
    device_id: Option<&str>,
) -> Result<Arc<InksonEventSigner>, anyhow::Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(seed_b64url.as_bytes())
        .map_err(|err| anyhow::anyhow!("device signing seed base64url decode: {err}"))?;
    if bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "device signing seed length {}, expected 32",
            bytes.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    activate_device_signer_from_seed_for_device(seed, persist_store, device_id)
}

/// Build an Ed25519 signer with an explicit verification-method id.
///
/// This is used by control-plane proofs whose verification method is scoped
/// by the principal DID rather than by the local did:key identity.
pub fn build_ed25519_signer_with_verification_method(
    seed: [u8; 32],
    signer_did: impl Into<String>,
    verification_method: impl Into<String>,
) -> InksonEventSigner {
    use arkret_sdk::signatures::proof::Ed25519DetachedJwsSigner;
    let signer_did = signer_did.into();
    let verification_method = verification_method.into();
    let raw_signing_key = SigningKey::from_bytes(&seed);
    let sdk_signer = Ed25519DetachedJwsSigner::from_seed(seed, verification_method.clone());
    InksonEventSigner {
        inner: Arc::new(sdk_signer),
        signer_did,
        verification_method,
        device_id: None,
        mode_tag: "ed25519",
        raw_signing_key: Some(raw_signing_key),
        last_signed_at: Mutex::new(None),
    }
}

pub fn bind_active_signer_device_id(
    device_id: &str,
) -> Result<Option<Arc<InksonEventSigner>>, anyhow::Error> {
    let Some(active) = active_signer() else {
        return Ok(None);
    };
    let Some(device_id) = normalize_signer_device_id(Some(device_id)) else {
        return Err(anyhow::anyhow!(
            "device_id is required for device-bound event proofs"
        ));
    };
    arkret_sdk::DeviceId::new(device_id.clone())
        .map_err(|err| anyhow::anyhow!("invalid device_id for event signer: {err}"))?;
    if active.device_id.as_deref() == Some(device_id.as_str()) {
        return Ok(Some(active));
    }
    let rebound = Arc::new(InksonEventSigner {
        inner: active.inner.clone(),
        signer_did: active.signer_did.clone(),
        verification_method: active.verification_method.clone(),
        device_id: Some(device_id),
        mode_tag: active.mode_tag,
        raw_signing_key: active.raw_signing_key.clone(),
        last_signed_at: Mutex::new(active.last_signed_at_snapshot()),
    });
    let _ = replace_active_signer(Some(rebound.clone()));
    Ok(Some(rebound))
}

fn normalize_signer_device_id(device_id: Option<impl AsRef<str>>) -> Option<String> {
    device_id
        .as_ref()
        .map(|value| value.as_ref().trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn verification_method_controller(verification_method: &str) -> &str {
    let no_query = verification_method
        .split_once('?')
        .map(|(head, _)| head)
        .unwrap_or(verification_method);
    no_query
        .split_once('#')
        .map(|(head, _)| head)
        .unwrap_or(no_query)
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
static ACTIVE_SIGNER: OnceLock<std::sync::RwLock<Option<Arc<InksonEventSigner>>>> = OnceLock::new();

fn active_slot() -> &'static std::sync::RwLock<Option<Arc<InksonEventSigner>>> {
    ACTIVE_SIGNER.get_or_init(|| std::sync::RwLock::new(None))
}

/// Drop the process-local device Event signer after an accepted local-device
/// revoke/reset. The next enrollment must load freshly generated device
/// identity material instead of continuing to sign with the revoked key.
pub fn clear_active_device_signer() {
    *active_slot().write().unwrap_or_else(|err| err.into_inner()) = None;
}

/// Install `signer` as the process-wide active signer. Returns `true`
/// on first install. Subsequent calls leave the current signer in place;
/// callers that intentionally rotate the device signer must use
/// [`replace_active_signer`].
pub fn install_active_signer(signer: Arc<InksonEventSigner>) -> bool {
    let mut guard = match active_slot().write() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    let first = guard.is_none();
    if first {
        *guard = Some(signer);
    }
    first
}

/// Swap the active signer (for tests and for hosts that need to
/// rotate). Returns the previous signer when one was installed.
pub fn replace_active_signer(
    signer: Option<Arc<InksonEventSigner>>,
) -> Option<Arc<InksonEventSigner>> {
    let mut guard = match active_slot().write() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    std::mem::replace(&mut *guard, signer)
}

/// Returns the currently-installed active signer, if any.
pub fn active_signer() -> Option<Arc<InksonEventSigner>> {
    let guard = match active_slot().read() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    guard.clone()
}

#[cfg(test)]
static ACTIVE_SIGNER_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes unit tests that temporarily replace the process-wide signer.
/// Production code never takes this lock.
#[cfg(test)]
pub(crate) struct ActiveSignerTestGuard {
    previous: Option<Arc<InksonEventSigner>>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl ActiveSignerTestGuard {
    pub(crate) fn replace(signer: Option<Arc<InksonEventSigner>>) -> Self {
        let lock = ACTIVE_SIGNER_TEST_MUTEX
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let previous = replace_active_signer(signer);
        Self {
            previous,
            _lock: lock,
        }
    }
}

#[cfg(test)]
impl Drop for ActiveSignerTestGuard {
    fn drop(&mut self) {
        let _ = replace_active_signer(self.previous.take());
    }
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
pub fn sign_with_active(event: &mut Event) -> Result<(), EventSignerError> {
    let signer = active_signer().ok_or(EventSignerError::MissingSigner {
        mode: current_proof_mode().label_en(),
    })?;
    signer.sign_envelope(event)
}

/// Sign `event` with the active signer and explicit EventProof context.
pub fn sign_with_active_context(
    event: &mut Event,
    context: EventProofContext,
) -> Result<(), EventSignerError> {
    let signer = active_signer().ok_or(EventSignerError::MissingSigner {
        mode: current_proof_mode().label_en(),
    })?;
    signer.sign_envelope_with_context(event, context)
}

pub fn sign_sdk_event_with_active_context(
    event: &mut arkret_sdk::Event,
    context: EventProofContext,
) -> Result<(), EventSignerError> {
    let mode = current_proof_mode();
    if !should_auto_sign() {
        return Err(EventSignerError::MissingSigner {
            mode: mode.label_en(),
        });
    }
    let signer = active_signer().ok_or(EventSignerError::MissingSigner {
        mode: mode.label_en(),
    })?;
    signer.sign_sdk_event_with_context(event, context)
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
        .map(arkret_sdk::canonical::format_timestamp_canonical);
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
///    (`KeyringSecureKeyStore` on desktop, `IndexedDbSecureKeyStore` on wasm32 after async upgrade,
///    `HostBridgeSecureKeyStore` on mobile when a host bridge is installed).
/// 2. [`crate::secure_key_store::ensure_signing_seed`] — loads the seed or generates and persists a
///    fresh one.
/// 3. [`build_ed25519_signer`] from the seed + derived did:key.
/// 4. [`install_active_signer`] + [`crate::operation::set_proof_mode`] so the submit guard switches
///    to the real-signer path.
///
/// Returns the installed signer for the caller to thread into the UI.
/// On wasm32 this fails closed until the IndexedDB/SubtleCrypto
/// upgrade has installed the non-extractable wrapping tier; localStorage
/// signing seeds are refused. On error the caller is expected to stay in
/// [`ProofMode::Production`] and surface the error to the user.
pub fn bootstrap_default_signer(
    service_name: &str,
) -> Result<Arc<InksonEventSigner>, anyhow::Error> {
    let store = crate::secure_key_store::default_secure_key_store(service_name);
    let material = crate::secure_key_store::ensure_signing_seed(&*store)
        .map_err(|err| anyhow::anyhow!("ensure_signing_seed failed: {err}"))?;
    Ok(install_device_signer_from_material(&material))
}

/// Bootstrap the OS-keychain backed signer and bind it to the protocol
/// `ak:device:*` id for this account session.
///
/// Unlike [`bootstrap_default_signer`], this intentionally replaces any stale
/// active signer. Boot may have installed a grant-binding (DPoP) signer early
/// enough to unblock requests; once the account-scoped device id is known, the
/// durable device identity signer must win the active slot.
pub fn bootstrap_default_signer_for_device(
    service_name: &str,
    device_id: &str,
) -> Result<Arc<InksonEventSigner>, anyhow::Error> {
    let device_id = normalize_signer_device_id(Some(device_id))
        .ok_or_else(|| anyhow::anyhow!("device_id is required for device-bound event signer"))?;
    arkret_sdk::DeviceId::new(device_id.clone())
        .map_err(|err| anyhow::anyhow!("invalid device_id for event signer: {err}"))?;
    let store = crate::secure_key_store::default_secure_key_store(service_name);
    let material = crate::secure_key_store::ensure_signing_seed(&*store)
        .map_err(|err| anyhow::anyhow!("ensure_signing_seed failed: {err}"))?;
    activate_device_signer_from_seed_for_device(
        material.seed,
        Some(store.as_ref()),
        Some(&device_id),
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::canonical::canonical_json_bytes;
    use crate::operation::{EventProofAudience, OperationBuilder, set_proof_mode};

    const TEST_REALM_ID: &str = "ak:realm:01964137-0000-7000-8000-000000000001";
    const TEST_DEVICE_ID: &str = "ak:device:01964137-0000-7000-8000-000000000001";

    fn reset() -> impl Drop {
        ActiveSignerTestGuard::replace(None)
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
    fn build_ed25519_signer_with_verification_method_overrides_default_fragment() {
        let _g = reset();
        let signer = build_ed25519_signer_with_verification_method(
            [7u8; 32],
            "did:web:alice.example",
            "did:web:alice.example#did-key-1",
        );
        assert_eq!(signer.signer_did(), "did:web:alice.example");
        assert_eq!(
            signer.verification_method(),
            "did:web:alice.example#did-key-1"
        );
        assert_eq!(signer.algorithm(), "EdDSA");
        assert_eq!(signer.mode_tag(), "ed25519");
    }

    #[test]
    fn pairing_public_key_uses_raw_ed25519_base64url() {
        let _g = reset();
        let seed = [7u8; 32];
        let signer = build_ed25519_signer(seed, "did:web:alice.example");
        let expected =
            URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&seed).verifying_key().as_bytes());

        assert_eq!(
            signer.public_key_base64url().as_deref(),
            Some(expected.as_str())
        );
        assert_ne!(
            signer.public_key_base64url(),
            signer.public_key_multibase(),
            "pairing wire keys must not use device-directory multibase"
        );
    }

    #[test]
    fn principal_move_signer_uses_authenticated_account_did_not_local_key_did() {
        let _g = reset();
        let signer =
            build_ed25519_device_signer([19u8; 32], "did:key:zlocal-device-key", TEST_DEVICE_ID);
        let controller = Did::new("did:web:controller.example").unwrap();

        let adapter = signer
            .payload_signer_adapter_for_principal(&controller)
            .unwrap();

        assert_eq!(adapter.signer_did(), &controller);
        assert_eq!(
            adapter.verification_method_id().as_str(),
            format!("{controller}#{TEST_DEVICE_ID}")
        );
    }

    #[test]
    fn sign_raw_signs_canonical_bytes_not_detached_jws_input() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use ed25519_dalek::{Signature, SigningKey, Verifier as _};

        let _g = reset();
        let seed = [8u8; 32];
        let signer = build_ed25519_signer(seed, "did:web:raw.example");
        let bytes = canonical_json_bytes(&json!({
            "purpose": "key_backup_unlock_proof",
            "version": 1,
        }))
        .unwrap();

        let sig = signer.sign_raw(&bytes).expect("raw sign");
        let signature = Signature::from_slice(&sig).expect("64-byte signature");
        let verifying_key = SigningKey::from_bytes(&seed).verifying_key();

        verifying_key
            .verify(&bytes, &signature)
            .expect("raw signature verifies against canonical bytes");

        let jws_signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA"}"#),
            URL_SAFE_NO_PAD.encode(&bytes)
        );
        assert!(
            verifying_key
                .verify(jws_signing_input.as_bytes(), &signature)
                .is_err(),
            "raw control-plane signatures must not be detached-JWS signatures"
        );
    }

    #[test]
    fn detached_jws_over_payload_with_kid_signs_standard_jws_input() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use ed25519_dalek::{Signature, SigningKey, Verifier as _};

        let _g = reset();
        let seed = [10u8; 32];
        let signer = build_ed25519_signer(seed, "did:web:jws.example");
        let payload = canonical_json_bytes(&json!({
            "purpose": "session_grant_refresh",
            "challenge": "challenge-1",
        }))
        .unwrap();
        let kid = "did:web:jws.example#ak:device:01964137-0000-7000-8000-000000000001";

        let jws = signer
            .detached_jws_over_payload_with_kid(kid, &payload)
            .expect("detached jws");
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[1].is_empty());
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).expect("header b64"))
                .expect("header json");
        assert_eq!(header, json!({"alg": "EdDSA", "kid": kid}));

        let signing_input = format!("{}.{}", parts[0], URL_SAFE_NO_PAD.encode(&payload));
        let signature =
            Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).expect("signature b64"))
                .expect("signature");
        SigningKey::from_bytes(&seed)
            .verifying_key()
            .verify(signing_input.as_bytes(), &signature)
            .expect("signature verifies over JWS signing input");
    }

    #[test]
    fn sign_envelope_attaches_real_jws_proof() {
        let _g = reset();
        let signer = build_ed25519_device_signer([3u8; 32], "did:web:bob.example", TEST_DEVICE_ID);

        let prior_mode = current_proof_mode();
        set_proof_mode(ProofMode::RealEd25519);
        let mut event = OperationBuilder::new(
            TEST_REALM_ID,
            "did:web:bob.example",
            arkret_sdk::EventKind::MessageCreate,
        )
        .body(json!({
            "strand_id": "ak:strand:0196419b-0000-7000-8000-0000000000f1",
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "body": "hi"}
        }))
        .build("test_node");
        set_proof_mode(prior_mode);

        // RealEd25519 mode skips placeholder attach.
        assert!(event.proofs.is_empty());

        signer.sign_envelope(&mut event).expect("sign");

        let proof = event.proofs.first().expect("real proof attached");
        assert_eq!(proof.kind, "detached_jws");
        assert_eq!(proof.alg, "EdDSA");
        assert_eq!(
            proof.verification_method,
            format!("did:web:bob.example#{TEST_DEVICE_ID}")
        );
        assert!(proof.event_digest.as_str().starts_with("sha256:"));
        // Real detached JWS: header..signature, signature non-empty.
        let parts: Vec<&str> = proof.jws.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[1].is_empty()); // detached
        assert!(!parts[2].is_empty());
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = URL_SAFE_NO_PAD.decode(parts[0]).expect("header b64");
        let header: serde_json::Value = serde_json::from_slice(&header).expect("header json");
        assert_eq!(header, json!({"alg": "EdDSA"}));

        assert!(signer.last_signed_at_snapshot().is_some());
    }

    #[test]
    fn sign_envelope_roots_proof_in_event_actor() {
        let _g = reset();
        let signer = build_ed25519_device_signer([9u8; 32], "did:key:zlocal", TEST_DEVICE_ID);

        let prior_mode = current_proof_mode();
        set_proof_mode(ProofMode::RealEd25519);
        let mut event = OperationBuilder::new(
            TEST_REALM_ID,
            "did:web:alice.example",
            arkret_sdk::EventKind::MessageCreate,
        )
        .body(json!({
            "strand_id": "ak:strand:0196419b-0000-7000-8000-0000000000f1",
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "body": "actor-rooted"}
        }))
        .build("test_node");
        set_proof_mode(prior_mode);

        signer.sign_envelope(&mut event).expect("sign");

        let proof = event.proofs.first().expect("proof");
        assert_eq!(
            proof.verification_method,
            format!("did:web:alice.example#{TEST_DEVICE_ID}")
        );
        assert_eq!(event.actor_id.as_str(), "did:web:alice.example");
    }

    #[test]
    fn sign_envelope_round_trips_through_sdk_verifier() {
        use arkret_sdk::signatures::proof::{
            Ed25519DetachedJwsSigner, Ed25519DetachedJwsVerifier, EventVerifier, PublicKeyMaterial,
        };
        let _g = reset();
        let seed = [5u8; 32];
        let signer = build_ed25519_device_signer(seed, "did:web:carol.example", TEST_DEVICE_ID);

        // Compute the matching verifying key for the seed via the SDK.
        let sdk_signer = Ed25519DetachedJwsSigner::from_seed(
            seed,
            format!("did:web:carol.example#{TEST_DEVICE_ID}"),
        );
        let public_key = PublicKeyMaterial::Ed25519Raw {
            bytes: sdk_signer.verifying_key().to_bytes().to_vec(),
        };

        let prior_mode = current_proof_mode();
        set_proof_mode(ProofMode::RealEd25519);
        let mut event = OperationBuilder::new(
            TEST_REALM_ID,
            "did:web:carol.example",
            arkret_sdk::EventKind::MessageCreate,
        )
        .body(json!({
            "strand_id": "ak:strand:0196419b-0000-7000-8000-0000000000f1",
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "body": "verifiable"}
        }))
        .build("test_node");
        set_proof_mode(prior_mode);

        signer.sign_envelope(&mut event).expect("sign");

        // Recompute the canonical event digest, then verify the JWS
        // over the spec proof-binding object. Event proofs sign
        // `{event_digest, actor_id, verification_method, created_at}`,
        // not the full event bytes directly.
        let proof = event.proofs.first().unwrap();
        assert_eq!(
            proof.event_digest.as_str(),
            event.event_digest().unwrap().as_str()
        );
        // The binding transcript is the SDK's authoritative `canonical_binding_bytes`
        // (folds in the `context = "ak.event-proof-v1"` domain tag), matching the
        // production signer.
        let did = arkret_sdk::Did::new(event.actor_id.as_str().to_owned()).unwrap();
        let proof_binding_bytes = proof.canonical_binding_bytes(&did).unwrap();

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
    fn sign_envelope_with_context_binds_domain_and_audience() {
        use arkret_sdk::signatures::proof::{
            Ed25519DetachedJwsSigner, Ed25519DetachedJwsVerifier, EventVerifier, PublicKeyMaterial,
        };
        let _g = reset();
        let seed = [6u8; 32];
        let signer = build_ed25519_device_signer(seed, "did:web:carol.example", TEST_DEVICE_ID);
        let sdk_signer = Ed25519DetachedJwsSigner::from_seed(
            seed,
            format!("did:web:carol.example#{TEST_DEVICE_ID}"),
        );
        let public_key = PublicKeyMaterial::Ed25519Raw {
            bytes: sdk_signer.verifying_key().to_bytes().to_vec(),
        };

        let prior_mode = current_proof_mode();
        set_proof_mode(ProofMode::RealEd25519);
        let mut event = OperationBuilder::new(
            TEST_REALM_ID,
            "did:web:carol.example",
            arkret_sdk::EventKind::MessageCreate,
        )
        .body(json!({
            "strand_id": "ak:strand:0196419b-0000-7000-8000-0000000000f1",
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "body": "bound"}
        }))
        .build("test_node");
        set_proof_mode(prior_mode);

        let context = EventProofContext::new()
            .with_domain("ak:trust_domain:server.example")
            .with_audience(EventProofAudience::Single(
                "did:web:server.example".to_owned(),
            ));
        signer
            .sign_envelope_with_context(&mut event, context)
            .expect("sign");

        let proof = event.proofs.first().unwrap();
        assert_eq!(
            proof.domain.as_deref(),
            Some("ak:trust_domain:server.example")
        );
        assert_eq!(
            proof.audience,
            Some(EventProofAudience::Single(
                "did:web:server.example".to_owned()
            ))
        );

        assert_eq!(
            proof.event_digest.as_str(),
            event.event_digest().unwrap().as_str()
        );
        // Binding transcript via the SDK's authoritative `canonical_binding_bytes`
        // (context tag + domain + audience folded in), matching the production signer.
        let did = arkret_sdk::Did::new(event.actor_id.as_str().to_owned()).unwrap();
        let proof_binding_bytes = proof.canonical_binding_bytes(&did).unwrap();

        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let parts: Vec<&str> = proof.jws.split('.').collect();
        let sig = URL_SAFE_NO_PAD.decode(parts[2]).expect("sig b64");
        Ed25519DetachedJwsVerifier::new()
            .verify(&proof_binding_bytes, &sig, &public_key)
            .expect("SDK verifier accepts domain/audience-bound proof");
    }

    #[test]
    fn sign_sdk_event_with_context_attaches_typed_proof() {
        let _g = reset();
        let signer = build_ed25519_device_signer([10u8; 32], "did:web:sdk.example", TEST_DEVICE_ID);
        let mut event: arkret_sdk::Event = serde_json::from_value(json!({
            "event_id": "ak:event:01904100-0000-7000-8000-000000000001",
            "kind": "ak.message.create",
            "realm_id": TEST_REALM_ID,
            "scope_ref": {"kind": "realm", "realm_id": TEST_REALM_ID},
            "actor_id": "did:web:sdk.example",
            "actor_seq": 1,
            "created_at": "2026-05-19T00:00:00.000Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {"kind": "ak.content.text", "body": "typed"},
            "proofs": []
        }))
        .unwrap();
        let context = EventProofContext::new()
            .with_domain("did:web:server.example")
            .with_audience(EventProofAudience::Single(
                "did:web:server.example".to_owned(),
            ));

        signer
            .sign_sdk_event_with_context(&mut event, context)
            .expect("sign SDK event");

        let proof = event.proofs.first().expect("proof");
        assert_eq!(proof.kind, "detached_jws");
        assert_eq!(
            proof.verification_method,
            format!("did:web:sdk.example#{TEST_DEVICE_ID}")
        );
        assert_eq!(proof.domain.as_deref(), Some("did:web:server.example"));
        assert!(proof.audience.is_some());
        event
            .validate_proof_bindings()
            .expect("proof digest matches");
    }

    #[test]
    fn sign_sdk_event_is_idempotent_for_the_same_verification_method() {
        let _g = reset();
        let signer = build_ed25519_device_signer([12u8; 32], "did:web:sdk.example", TEST_DEVICE_ID);
        let mut event: arkret_sdk::Event = serde_json::from_value(json!({
            "event_id": "ak:event:01904100-0000-7000-8000-000000000011",
            "kind": "ak.message.create",
            "realm_id": TEST_REALM_ID,
            "scope_ref": {"kind": "realm", "realm_id": TEST_REALM_ID},
            "actor_id": "did:web:sdk.example",
            "actor_seq": 1,
            "created_at": "2026-05-19T00:00:00.000Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {"kind": "ak.content.text", "body": "typed"},
            "proofs": []
        }))
        .unwrap();

        signer
            .sign_sdk_event_with_context(&mut event, EventProofContext::default())
            .unwrap();
        signer
            .sign_sdk_event_with_context(&mut event, EventProofContext::default())
            .unwrap();

        assert_eq!(event.proofs.len(), 1);
    }

    #[test]
    fn sign_sdk_event_rejects_a_second_verification_method() {
        let _g = reset();
        let first = build_ed25519_device_signer(
            [13u8; 32],
            "did:web:sdk.example",
            "ak:device:01904100-0000-7000-8000-000000000013",
        );
        let second = build_ed25519_device_signer(
            [14u8; 32],
            "did:web:sdk.example",
            "ak:device:01904100-0000-7000-8000-000000000014",
        );
        let mut event: arkret_sdk::Event = serde_json::from_value(json!({
            "event_id": "ak:event:01904100-0000-7000-8000-000000000012",
            "kind": "ak.message.create",
            "realm_id": TEST_REALM_ID,
            "scope_ref": {"kind": "realm", "realm_id": TEST_REALM_ID},
            "actor_id": "did:web:sdk.example",
            "actor_seq": 1,
            "created_at": "2026-05-19T00:00:00.000Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {"kind": "ak.content.text", "body": "typed"},
            "proofs": []
        }))
        .unwrap();

        first
            .sign_sdk_event_with_context(&mut event, EventProofContext::default())
            .unwrap();
        let original = event.proofs.clone();
        let error = second
            .sign_sdk_event_with_context(&mut event, EventProofContext::default())
            .unwrap_err();

        assert!(!error.to_string().is_empty());
        assert_eq!(event.proofs, original);
    }

    #[test]
    fn install_and_replace_active_signer() {
        let _g = reset();
        assert!(active_signer().is_none());
        assert!(!should_auto_sign());

        let signer = Arc::new(build_ed25519_signer([1u8; 32], "did:web:x"));
        assert!(install_active_signer(signer.clone()));
        let replacement = Arc::new(build_ed25519_signer([8u8; 32], "did:web:y"));
        assert!(!install_active_signer(replacement));
        assert_eq!(
            active_signer()
                .expect("active signer")
                .verification_method(),
            signer.verification_method()
        );

        let prior_mode = current_proof_mode();
        set_proof_mode(ProofMode::RealEd25519);
        assert!(should_auto_sign());
        set_proof_mode(prior_mode);

        let prev = replace_active_signer(None);
        assert!(prev.is_some());
        assert!(active_signer().is_none());
    }

    #[test]
    fn install_device_signer_from_material_uses_material_did_key() {
        let _g = reset();
        let seed = [11u8; 32];
        let verifying = SigningKey::from_bytes(&seed).verifying_key();
        let did = crate::identity::did_key::did_key_from_verifying_key(&verifying);
        let material = crate::secure_key_store::SigningSeedMaterial {
            seed,
            local_signing_did: did.clone(),
        };

        let signer = install_device_signer_from_material(&material);

        assert_eq!(signer.signer_did(), did);
        assert_eq!(signer.verification_method(), format!("{did}#device"));
        assert_eq!(
            active_signer()
                .expect("active signer")
                .verification_method(),
            format!("{did}#device")
        );
        assert!(should_auto_sign());
    }

    #[test]
    fn activate_device_signer_from_seed_b64url_persists_and_replaces_stale_signer() {
        let _g = reset();
        let stale = Arc::new(build_ed25519_signer([8u8; 32], "did:web:stale.example"));
        assert!(install_active_signer(stale));

        let seed = [12u8; 32];
        let seed_b64url = URL_SAFE_NO_PAD.encode(seed);
        let verifying = SigningKey::from_bytes(&seed).verifying_key();
        let did = crate::identity::did_key::did_key_from_verifying_key(&verifying);
        let store = crate::secure_key_store::MemorySecureKeyStore::new();

        let signer = activate_device_signer_from_seed_b64url(&seed_b64url, Some(&store)).unwrap();

        assert_eq!(signer.signer_did(), did);
        assert_eq!(
            active_signer()
                .expect("active signer")
                .verification_method(),
            format!("{did}#device")
        );
        let persisted = crate::secure_key_store::load_signing_seed(&store)
            .unwrap()
            .expect("persisted seed");
        assert_eq!(persisted.seed, seed);
        assert!(should_auto_sign());
    }

    #[test]
    fn sign_with_active_uses_installed_signer() {
        let _g = reset();
        let signer = Arc::new(build_ed25519_device_signer(
            [2u8; 32],
            "did:web:dave.example",
            TEST_DEVICE_ID,
        ));
        install_active_signer(signer);

        let prior_mode = current_proof_mode();
        set_proof_mode(ProofMode::RealEd25519);
        let mut event = OperationBuilder::new(
            TEST_REALM_ID,
            "did:web:dave.example",
            arkret_sdk::EventKind::MessageCreate,
        )
        .body(json!({
            "strand_id": "ak:strand:0196419b-0000-7000-8000-0000000000f1",
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "body": "auto"}
        }))
        .build("test_node");
        sign_with_active(&mut event).expect("auto sign");
        set_proof_mode(prior_mode);

        let proof = event.proofs.first().expect("auto-attached proof");
        assert_eq!(
            proof.verification_method,
            format!("did:web:dave.example#{TEST_DEVICE_ID}")
        );
        // Submit guard accept-shape: header..signature, non-empty sig.
        assert!(proof.jws.contains(".."));
        let sig_segment = proof.jws.split("..").nth(1).unwrap();
        assert!(!sig_segment.is_empty());
    }

    #[test]
    fn sign_with_active_returns_missing_signer_when_none_installed() {
        let _g = reset();
        let mut event = OperationBuilder::new(
            TEST_REALM_ID,
            "did:web:eve.example",
            arkret_sdk::EventKind::MessageCreate,
        )
        .body(json!({
            "strand_id": "ak:strand:0196419b-0000-7000-8000-0000000000f1",
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "body": "no"}
        }))
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
    fn explicit_device_reset_drops_the_active_event_signer() {
        let _guard = reset();
        let signer = Arc::new(build_ed25519_signer([5_u8; 32], "did:web:alice.example"));
        install_active_signer(signer);
        assert!(signer_status().is_some());

        clear_active_device_signer();

        assert!(signer_status().is_none());
    }

    #[test]
    fn proof_type_tag_is_production() {
        let pt = InksonEventSigner::proof_type_tag();
        assert!(!pt.is_development());
    }
}
