//! G3.Y0 — per-device DPoP key management.
//!
//! Layered on top of [`crate::dpop`] (the pure JWS builder). This
//! module is the policy layer that:
//!
//! 1. Generates an Ed25519 device key on first launch and persists it via
//!    [`crate::local_state::LocalStateStore::set_dpop_device_key`].
//! 2. Hands out a `DpopHandle` callers can use to mint proofs without having to plumb through the
//!    raw `SigningKey`.
//! 3. Surfaces the RFC 7638 thumbprint so the UI / refresh path can display `cnf.jkt` for
//!    diagnostic testids.
//!
//! ## Algorithm choice
//!
//! Ed25519 (`alg=EdDSA`, `kty=OKP`, `crv=Ed25519`) over ES256. Three
//! reasons, in order of weight:
//!
//! * Every other signing surface in yougen — `event_signer`, `cross_signing`, `move_builder`,
//!   `session_grant` proofs — is already ed25519. Adding a second curve doubles the WASM bundle
//!   surface for no protocol benefit.
//! * coauth's `DpopVerifier` (`coauth/crates/backend/src/services/dpop.rs`) accepts `EdDSA` as a
//!   first-class algorithm; the JWA registry lists it as an approved JWS alg.
//! * `ed25519-dalek` is pure-Rust and known to build cleanly under `wasm32-unknown-unknown`. ES256
//!   via the browser's SubtleCrypto means crossing the JS boundary on every mint, which complicates
//!   the test surface in the cotest harness.
//!
//! ## Storage choice
//!
//! Production builds persist the seed through
//! [`crate::secure_key_store::SecureKeyStore`]. On wasm32 the default
//! boot path starts with the synchronous localStorage wrapper and
//! upgrades to the IndexedDB/SubtleCrypto tier via
//! `upgrade_wasm_secure_key_store_async`, so the DPoP seed follows the
//! same handoff as OIDC refresh tokens. Tests keep using plaintext
//! state records to remain deterministic and dependency-free.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use crate::dpop::{
    DpopClaims, DpopError, build_dpop_proof_ed25519, fresh_dpop_claims, jwk_thumbprint_ed25519,
};
use crate::local_state::{DpopDeviceKeyRecord, LocalStateStore};

/// Errors surfaced when minting or loading the device DPoP key.
#[derive(Debug, thiserror::Error)]
pub enum AuthDpopError {
    /// Could not generate randomness for a fresh key.
    #[error("DPoP RNG failed: {0}")]
    Rng(String),
    /// The secure-key-store backend could not read or write the seed.
    #[error("DPoP secure store failed: {0}")]
    SecureStore(String),
    /// The persisted seed was malformed (truncated / not base64url).
    #[error("DPoP persisted seed invalid: {0}")]
    PersistedSeed(String),
    /// The underlying [`crate::dpop::build_dpop_proof_ed25519`] failed.
    #[error("DPoP mint failed: {0}")]
    Mint(#[from] DpopError),
    /// The session-grant introspection proof could not be signed.
    #[error("session-grant introspection proof failed: {0}")]
    SessionGrantProof(String),
}

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

    /// Export the raw 32-byte ed25519 seed as base64url-no-pad.
    ///
    /// Used only by the durable hard-logout journal
    /// ([`crate::pending_logout`]): the logout wipes the live key, so a
    /// copy of the seed is stashed (alongside [`Self::jkt`]) purely so a
    /// later boot can rebuild this handle via
    /// [`device_handle_from_seed`] and mint the holder proof that revokes
    /// the *old* grant. This is the same secret already held in the secure
    /// key store; it is cleared as soon as the revoke succeeds.
    pub fn seed_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_key.to_bytes())
    }

    /// Export the device signing key as PKCS#8 PEM.
    ///
    /// Used after a DPoP-bound session-grant rotation: the rotated grant's
    /// `session_public_key` is this device key (the grant binds to the same key
    /// the rotation proof proved possession of), so the principal-server
    /// exchange proof must be signed with this key. Persisting it as the
    /// rotated grant's `session_private_key_pem` lets the existing exchange path
    /// (`session_grant_signing_key_from_pem`) sign with the right key, uniformly
    /// with the first-login flow.
    pub fn session_signing_key_pkcs8_pem(&self) -> Result<String, AuthDpopError> {
        use ed25519_dalek::pkcs8::EncodePrivateKey as _;
        self.signing_key
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .map(|pem| pem.to_string())
            .map_err(|err| AuthDpopError::SessionGrantProof(format!("device key pkcs8 pem: {err}")))
    }

    /// Mint a fresh DPoP proof JWS for the given `(htm, htu)` pair.
    /// `ath` carries the raw access token when the proof accompanies a
    /// bearer token (refresh, grant-using calls); this helper hashes it
    /// into the RFC 9449 `ath` claim. Pass `None` for grant issuance.
    pub fn mint_proof(
        &self,
        htm: &str,
        htu: &str,
        ath: Option<&str>,
    ) -> Result<String, AuthDpopError> {
        let mut claims: DpopClaims = fresh_dpop_claims(htm.to_owned(), htu.to_owned(), None);
        claims.ath = ath.map(dpop_access_token_hash);
        build_dpop_proof_ed25519(&self.signing_key, &claims).map_err(AuthDpopError::Mint)
    }

    /// Sign the one-shot proof that soland forwards to coauth when it
    /// introspects a session grant. It uses the same private key as the
    /// DPoP proof that coauth bound into the grant's `cnf.jkt`.
    pub fn mint_session_grant_introspection_proof(
        &self,
        grant_id: &str,
        grant_jwt: &str,
        audience: &str,
    ) -> Result<crate::api::SessionGrantIntrospectionProof, AuthDpopError> {
        crate::coauth::build_session_grant_introspection_proof_bundle(
            grant_id,
            grant_jwt,
            audience,
            &self.signing_key,
        )
        .map_err(|error| AuthDpopError::SessionGrantProof(error.to_string()))
    }
}

/// RFC 9449 access-token hash:
/// `base64url-no-pad(sha256(access_token))`.
pub fn dpop_access_token_hash(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()))
}

/// Generate or load the device DPoP key. Calls return the same handle
/// for the lifetime of the persisted record.
pub fn ensure_device_key(store: &mut LocalStateStore) -> Result<DpopHandle, AuthDpopError> {
    #[cfg(not(test))]
    {
        let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
        ensure_device_key_with_secure_store(store, secure_store.as_ref())
    }

    #[cfg(test)]
    {
        ensure_device_key_in_plaintext_state(store)
    }
}

/// Generate or load the DPoP key using the supplied secure-key backend.
/// The on-disk state keeps only public metadata; private seed bytes live
/// in the secure store.
pub fn ensure_device_key_with_secure_store(
    store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Result<DpopHandle, AuthDpopError> {
    if let Some(record) = store
        .load_dpop_device_key_with_secure_store(secure_store)
        .map_err(|err| AuthDpopError::SecureStore(err.to_string()))?
    {
        let handle = decode_record(&record)?;
        store
            .set_dpop_device_key_with_secure_store(Some(record), secure_store)
            .map_err(|err| AuthDpopError::SecureStore(err.to_string()))?;
        return Ok(handle);
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
    store
        .set_dpop_device_key_with_secure_store(Some(record), secure_store)
        .map_err(|err| AuthDpopError::SecureStore(err.to_string()))?;
    Ok(DpopHandle { signing_key, jkt })
}

#[cfg(test)]
fn ensure_device_key_in_plaintext_state(
    store: &mut LocalStateStore,
) -> Result<DpopHandle, AuthDpopError> {
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
    #[cfg(not(test))]
    {
        let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
        load_device_key_with_secure_store(store, secure_store.as_ref())
    }

    #[cfg(test)]
    {
        let Some(record) = store.dpop_device_key() else {
            return Ok(None);
        };
        decode_record(&record).map(Some)
    }
}

/// Read the persisted DPoP key from the supplied secure-key backend
/// without generating a new one.
pub fn load_device_key_with_secure_store(
    store: &LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Result<Option<DpopHandle>, AuthDpopError> {
    let Some(record) = store
        .load_dpop_device_key_with_secure_store(secure_store)
        .map_err(|err| AuthDpopError::SecureStore(err.to_string()))?
    else {
        return Ok(None);
    };
    decode_record(&record).map(Some)
}

/// Rebuild a [`DpopHandle`] from a persisted seed + thumbprint pair,
/// without touching the live key store.
///
/// Used by the durable hard-logout retry path
/// ([`crate::pending_logout`]): a logout wipes the active device key so
/// the next sign-in rotates `cnf.jkt`, but the pending-logout record
/// stashes a copy of the *old* seed purely so a later boot can still mint
/// the holder proof needed to revoke the *old* grant. The thumbprint is
/// re-derived and checked against `jkt` to reject a tampered record.
pub fn device_handle_from_seed(seed_b64: &str, jkt: &str) -> Result<DpopHandle, AuthDpopError> {
    decode_record(&DpopDeviceKeyRecord {
        seed_b64: seed_b64.to_owned(),
        jkt: jkt.to_owned(),
        created_at: Utc::now(),
    })
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

/// Reconstruct a [`DpopDeviceKeyRecord`] from a base64url-no-pad 32-byte
/// ed25519 seed, deriving the RFC 7638 thumbprint from the seed's public key.
///
/// The derived `jkt` is identical to the thumbprint the grant was bound to
/// (`cnf.jkt`) precisely because both sides start from the same seed. Returns an
/// error if the seed is not 32 base64url-no-pad bytes.
pub fn dpop_device_key_record_from_seed(
    seed_b64: &str,
) -> Result<DpopDeviceKeyRecord, AuthDpopError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(seed_b64.as_bytes())
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
    let jkt = jwk_thumbprint_ed25519(&signing_key.verifying_key());
    Ok(DpopDeviceKeyRecord {
        seed_b64: URL_SAFE_NO_PAD.encode(seed),
        jkt,
        created_at: Utc::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    // YOU-05-010: shared hermetic state-store fixture from `local_state`.
    use crate::local_state::isolated_store_for_tests as isolated_store;
    use crate::secure_key_store::MemorySecureKeyStore;

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
                "https://example.test/_cokret/gate/account/session-grants",
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
    fn handle_mints_session_grant_introspection_proof() {
        let mut store = isolated_store("session-grant-proof");
        let handle = ensure_device_key(&mut store).unwrap();
        let proof = handle
            .mint_session_grant_introspection_proof(
                "grant-1",
                "eyJ.mock.jwt",
                "did:web:soland.example",
            )
            .unwrap();

        assert!(!proof.challenge.is_empty());
        assert_eq!(proof.proof_jwt.split('.').count(), 3);
    }

    fn proof_payload(proof: &str) -> serde_json::Value {
        let payload_b64 = proof.split('.').nth(1).expect("payload segment");
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).expect("payload b64");
        serde_json::from_slice(&payload_bytes).expect("payload json")
    }

    #[test]
    fn access_token_hash_matches_rfc9449_ath_encoding() {
        assert_eq!(
            dpop_access_token_hash("access-token-1"),
            URL_SAFE_NO_PAD.encode(Sha256::digest(b"access-token-1"))
        );
    }

    #[test]
    fn handle_mints_ath_when_access_token_supplied() {
        let mut store = isolated_store("mint-ath");
        let handle = ensure_device_key(&mut store).unwrap();
        let proof = handle
            .mint_proof(
                "POST",
                "https://example.test/_cokret/gate/account/session-grants",
                Some("access-token-1"),
            )
            .unwrap();
        let payload = proof_payload(&proof);
        assert_eq!(payload["ath"], dpop_access_token_hash("access-token-1"));
    }

    #[test]
    fn handle_omits_ath_when_no_access_token_supplied() {
        let mut store = isolated_store("mint-no-ath");
        let handle = ensure_device_key(&mut store).unwrap();
        let proof = handle
            .mint_proof(
                "POST",
                "https://example.test/_cokret/gate/account/session-grants",
                None,
            )
            .unwrap();
        let payload = proof_payload(&proof);
        assert!(payload.get("ath").is_none());
    }

    #[test]
    fn seed_export_rebuilds_an_equivalent_handle() {
        // The durable hard-logout journal stashes seed_b64 + jkt and later
        // rebuilds the holder key via device_handle_from_seed. The rebuilt
        // handle must mint proofs under the same cnf.jkt as the original.
        let mut store = isolated_store("seed-roundtrip");
        let original = ensure_device_key(&mut store).unwrap();
        let rebuilt = device_handle_from_seed(&original.seed_b64(), original.jkt()).unwrap();
        assert_eq!(rebuilt.jkt(), original.jkt());
    }

    #[test]
    fn record_from_seed_derives_matching_thumbprint() {
        // The cotest joint-e2e injection rebuilds the DPoP key from the same
        // seed the grant was bound to; the derived jkt MUST equal what a handle
        // built from that seed reports, so it equals the grant's cnf.jkt.
        let mut store = isolated_store("record-from-seed");
        let original = ensure_device_key(&mut store).unwrap();
        let record = dpop_device_key_record_from_seed(&original.seed_b64()).unwrap();
        assert_eq!(record.jkt, original.jkt());
        assert_eq!(record.seed_b64, original.seed_b64());
        assert_eq!(decode_record(&record).unwrap().jkt(), original.jkt());
    }

    #[test]
    fn record_from_seed_rejects_wrong_length() {
        assert!(dpop_device_key_record_from_seed("AAAA").is_err());
    }

    #[test]
    fn seed_rebuild_rejects_mismatched_thumbprint() {
        let mut store = isolated_store("seed-tamper");
        let original = ensure_device_key(&mut store).unwrap();
        let result = device_handle_from_seed(&original.seed_b64(), "not-the-real-jkt");
        assert!(result.is_err());
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
            "https://example.test/_cokret/gate/account/session-grants",
            "POST",
            None,
        )
        .unwrap();
        assert_eq!(proof.split('.').count(), 3);
    }

    #[test]
    fn secure_store_seed_round_trips_without_plaintext_state_seed() {
        let mut store = isolated_store("secure");
        let secure = MemorySecureKeyStore::default();
        let first = ensure_device_key_with_secure_store(&mut store, &secure).unwrap();
        let public_record = store.dpop_device_key().expect("public record");
        assert_eq!(public_record.jkt, first.jkt());
        assert!(public_record.seed_b64.is_empty());

        let second = load_device_key_with_secure_store(&store, &secure)
            .unwrap()
            .expect("loaded");
        assert_eq!(second.jkt(), first.jkt());
    }
}
