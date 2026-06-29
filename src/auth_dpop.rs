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
//! same handoff as session credentials. Tests keep using plaintext
//! state records to remain deterministic and dependency-free.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::dpop::{
    DpopClaims, DpopError, build_dpop_proof_ed25519, fresh_dpop_claims, jwk_thumbprint_ed25519,
};
use crate::local_state::{DpopDeviceKeyRecord, LocalStateStore};

const SOFT_LOGOUT_RESTORE_OPERATION: &str = "resume_soft_logged_out_session";

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
    pub fn seed_b64(&self) -> Zeroizing<String> {
        Zeroizing::new(URL_SAFE_NO_PAD.encode(self.signing_key.to_bytes()))
    }

    /// Export the device signing key as PKCS#8 PEM.
    ///
    /// Used after a DPoP-bound session-grant rotation: the rotated grant's
    /// `session_public_key` is this device key (the grant binds to the same key
    /// the rotation proof proved possession of), so the principal-server
    /// introspection proof must be signed with this key. Persisting it as the
    /// rotated grant's `session_private_key_pem` lets the existing proof path
    /// (`session_grant_signing_key_from_pem`) sign with the right key, uniformly
    /// with the first-login flow.
    pub fn session_signing_key_pkcs8_pem(&self) -> Result<Zeroizing<String>, AuthDpopError> {
        use ed25519_dalek::pkcs8::EncodePrivateKey as _;
        self.signing_key
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .map(|pem| Zeroizing::new(pem.to_string()))
            .map_err(|err| AuthDpopError::SessionGrantProof(format!("device key pkcs8 pem: {err}")))
    }

    /// Mint a fresh DPoP proof JWS for the given `(htm, htu)` pair.
    /// `ath` carries the raw authorization credential when the proof
    /// accompanies a protected call; this helper hashes it into the
    /// RFC 9449 `ath` claim. Pass `None` for grant issuance.
    pub fn mint_proof(
        &self,
        htm: &str,
        htu: &str,
        ath: Option<&str>,
    ) -> Result<String, AuthDpopError> {
        let mut claims: DpopClaims = fresh_dpop_claims(htm.to_owned(), htu.to_owned(), None)?;
        claims.ath = ath.map(dpop_authorization_credential_hash);
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

    pub fn mint_session_grant_refresh_proof(
        &self,
        grant_jwt: &str,
        principal_id: &str,
        device_id: &str,
        audience: &str,
    ) -> Result<cokret_sdk::SessionGrantRefreshProof, AuthDpopError> {
        let verification_method = format!("{}#{}", principal_id.trim(), device_id.trim());
        let request_canonical_digest = soft_logout_restore_request_canonical_digest(
            grant_jwt,
            principal_id,
            device_id,
            audience,
            &verification_method,
        )?;
        let request_canonical_digest_hash = cokret_sdk::Hash::new(request_canonical_digest.clone())
            .map_err(|error| {
                AuthDpopError::SessionGrantProof(format!(
                    "soft logout restore request digest: {error}"
                ))
            })?;
        let challenge = soft_logout_refresh_challenge()?;
        let issued_at = Utc::now();
        let expires_at = issued_at + chrono::Duration::seconds(60);
        let claims = SoftLogoutDidProofClaims {
            principal_id,
            device_id,
            audience,
            challenge: &challenge,
            request_canonical_digest: &request_canonical_digest,
            issued_at,
            expires_at,
        };
        let payload = crate::canonical::canonical_json_bytes(&claims)
            .map_err(|error| AuthDpopError::SessionGrantProof(error.to_string()))?;
        let signature =
            sign_detached_jws_eddsa_with_kid(&self.signing_key, &verification_method, &payload)?;
        Ok(cokret_sdk::SessionGrantRefreshProof {
            proof_kind: Some(cokret_sdk::SessionGrantProofKind::DidBoundSignature),
            challenge: Some(challenge),
            request_canonical_digest: Some(request_canonical_digest_hash),
            audience: Some(audience.to_owned()),
            issued_at: Some(issued_at),
            expires_at: Some(expires_at),
            signature: Some(signature),
            verification_method: Some(verification_method),
        })
    }
}

#[derive(Debug, Serialize)]
struct SoftLogoutDidProofClaims<'a> {
    pub principal_id: &'a str,
    pub device_id: &'a str,
    pub audience: &'a str,
    pub challenge: &'a str,
    pub request_canonical_digest: &'a str,
    pub issued_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct SoftLogoutRestoreRequestDigest<'a> {
    pub operation: &'static str,
    pub grant_jwt_hash: String,
    pub principal_id: &'a str,
    pub device_id: &'a str,
    pub audience: &'a str,
    pub holder_key_id: &'a str,
}

fn soft_logout_restore_request_canonical_digest(
    grant_jwt: &str,
    principal_id: &str,
    device_id: &str,
    audience: &str,
    holder_key_id: &str,
) -> Result<String, AuthDpopError> {
    crate::canonical::canonical_sha256(&SoftLogoutRestoreRequestDigest {
        operation: SOFT_LOGOUT_RESTORE_OPERATION,
        grant_jwt_hash: crate::coauth::session_grant_jwt_hash(grant_jwt),
        principal_id,
        device_id,
        audience,
        holder_key_id,
    })
    .map_err(|error| AuthDpopError::SessionGrantProof(error.to_string()))
}

/// SEC-08: build the soft-logout refresh challenge from a pure 128-bit random
/// nonce + millisecond timestamp. The jkt is intentionally NOT mixed in: it adds
/// no entropy (it is predictable to the peer) and the holder-key binding is
/// already carried by the signed [`SoftLogoutDidProofClaims`] payload (which
/// embeds this challenge), so the challenge itself must stay opaque-random.
fn soft_logout_refresh_challenge() -> Result<String, AuthDpopError> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|err| AuthDpopError::Rng(err.to_string()))?;
    Ok(format!(
        "sg-refresh-{}-{}",
        Utc::now().timestamp_millis(),
        URL_SAFE_NO_PAD.encode(nonce)
    ))
}

fn sign_detached_jws_eddsa_with_kid(
    signing_key: &SigningKey,
    kid: &str,
    payload: &[u8],
) -> Result<String, AuthDpopError> {
    let header = serde_json::json!({
        "alg": "EdDSA",
        "kid": kid,
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header)
            .map_err(|error| AuthDpopError::SessionGrantProof(error.to_string()))?,
    );
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes()).to_bytes();
    Ok(format!(
        "{header_b64}..{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

/// RFC 9449 `ath` hash:
/// `base64url-no-pad(sha256(authorization_credential))`.
pub fn dpop_authorization_credential_hash(authorization_credential: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(authorization_credential.as_bytes()))
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
    let record = store
        .load_dpop_device_key_with_secure_store(secure_store)
        .map_err(|err| AuthDpopError::SecureStore(err.to_string()))?;
    let signing_seed = crate::secure_key_store::load_signing_seed(secure_store)
        .map_err(|err| AuthDpopError::SecureStore(format!("load device signing seed: {err}")))?;

    if let Some(material) = signing_seed {
        let (seed_handle, seed_record) = handle_and_record_from_seed(material.seed);
        let record_matches_seed = record
            .as_ref()
            .and_then(|record| decode_record(record).ok())
            .is_some_and(|handle| handle.jkt() == seed_handle.jkt());
        if !record_matches_seed {
            tracing::warn!(
                stored_jkt = record
                    .as_ref()
                    .map(|record| record.jkt.as_str())
                    .unwrap_or(""),
                seed_jkt = seed_handle.jkt(),
                "DPoP device-key record did not match active signing seed; repairing record from signing seed"
            );
            store
                .set_dpop_device_key_with_secure_store(Some(seed_record), secure_store)
                .map_err(|err| AuthDpopError::SecureStore(err.to_string()))?;
            #[cfg(not(test))]
            crate::event_signer::activate_device_signer_from_seed(
                material.seed,
                Some(secure_store),
            )
            .map_err(|err| AuthDpopError::SecureStore(format!("activate event signer: {err}")))?;
            return Ok(seed_handle);
        }
    }

    if let Some(record) = record {
        let handle = persist_loaded_record(store, secure_store, record)?;
        return Ok(handle);
    }

    let material = crate::secure_key_store::ensure_signing_seed(secure_store)
        .map_err(|err| AuthDpopError::SecureStore(format!("ensure device signing seed: {err}")))?;
    let (handle, record) = handle_and_record_from_seed(material.seed);
    store
        .set_dpop_device_key_with_secure_store(Some(record), secure_store)
        .map_err(|err| AuthDpopError::SecureStore(err.to_string()))?;
    #[cfg(not(test))]
    crate::event_signer::activate_device_signer_from_seed(material.seed, Some(secure_store))
        .map_err(|err| AuthDpopError::SecureStore(format!("activate event signer: {err}")))?;
    Ok(handle)
}

fn persist_loaded_record(
    store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    record: DpopDeviceKeyRecord,
) -> Result<DpopHandle, AuthDpopError> {
    let handle = decode_record(&record)?;
    #[cfg(not(test))]
    crate::event_signer::activate_device_signer_from_seed_b64url(
        &record.seed_b64,
        Some(secure_store),
    )
    .map_err(|err| AuthDpopError::SecureStore(format!("activate event signer: {err}")))?;
    store
        .set_dpop_device_key_with_secure_store(Some(record), secure_store)
        .map_err(|err| AuthDpopError::SecureStore(err.to_string()))?;
    Ok(handle)
}

fn handle_and_record_from_seed(seed: [u8; 32]) -> (DpopHandle, DpopDeviceKeyRecord) {
    let signing_key = SigningKey::from_bytes(&seed);
    let jkt = jwk_thumbprint_ed25519(&signing_key.verifying_key());
    let record = DpopDeviceKeyRecord {
        seed_b64: URL_SAFE_NO_PAD.encode(seed),
        jkt: jkt.clone(),
        created_at: Utc::now(),
    };
    (DpopHandle { signing_key, jkt }, record)
}

fn persist_recovered_seed_record(
    store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    seed: [u8; 32],
) -> Result<DpopHandle, AuthDpopError> {
    let (handle, record) = handle_and_record_from_seed(seed);
    store
        .set_dpop_device_key_with_secure_store(Some(record), secure_store)
        .map_err(|err| AuthDpopError::SecureStore(format!("recover DPoP record: {err}")))?;
    #[cfg(not(test))]
    crate::event_signer::activate_device_signer_from_seed(seed, Some(secure_store))
        .map_err(|err| AuthDpopError::SecureStore(format!("activate event signer: {err}")))?;
    Ok(handle)
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

/// Read the persisted DPoP key, or recover its record from the active
/// account-scoped signing seed when a prior boot/login wrote the seed but the
/// derived DPoP record was not durably re-homed yet. This never generates a new
/// key: if neither the record nor signing seed exists, the current session
/// grant cannot be sender-constrained and the caller should let auth recovery
/// fail closed.
#[cfg(not(test))]
pub fn load_or_recover_device_key(
    store: &mut LocalStateStore,
) -> Result<Option<DpopHandle>, AuthDpopError> {
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    load_or_recover_device_key_with_secure_store(store, secure_store.as_ref())
}

#[cfg(test)]
pub fn load_or_recover_device_key(
    store: &mut LocalStateStore,
) -> Result<Option<DpopHandle>, AuthDpopError> {
    load_device_key(store)
}

pub fn load_or_recover_device_key_with_secure_store(
    store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Result<Option<DpopHandle>, AuthDpopError> {
    let record = store
        .load_dpop_device_key_with_secure_store(secure_store)
        .map_err(|err| AuthDpopError::SecureStore(err.to_string()))?;
    let signing_seed = crate::secure_key_store::load_signing_seed(secure_store)
        .map_err(|err| AuthDpopError::SecureStore(format!("load signing seed: {err}")))?;

    if let Some(material) = signing_seed {
        let (seed_handle, _) = handle_and_record_from_seed(material.seed);
        let record_matches_seed = record
            .as_ref()
            .and_then(|record| decode_record(record).ok())
            .is_some_and(|handle| handle.jkt() == seed_handle.jkt());
        if !record_matches_seed {
            tracing::warn!(
                stored_jkt = record
                    .as_ref()
                    .map(|record| record.jkt.as_str())
                    .unwrap_or(""),
                seed_jkt = seed_handle.jkt(),
                "recovering DPoP device-key record from active signing seed"
            );
            return persist_recovered_seed_record(store, secure_store, material.seed).map(Some);
        }
    }

    match record {
        Some(record) => persist_loaded_record(store, secure_store, record).map(Some),
        None => Ok(None),
    }
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
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use super::*;
    // YOU-05-010: shared hermetic state-store fixture from `local_state`.
    use crate::local_state::isolated_store_for_tests as isolated_store;
    use crate::secure_key_store::MemorySecureKeyStore;

    fn seed_scope_test_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("seed scope test lock")
    }

    struct SeedScopeReset;

    impl Drop for SeedScopeReset {
        fn drop(&mut self) {
            crate::secure_key_store::set_active_device_seed_scope(None);
        }
    }

    fn set_seed_scope(scope: &str) -> SeedScopeReset {
        crate::secure_key_store::set_active_device_seed_scope(Some(scope));
        SeedScopeReset
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
    fn authorization_credential_hash_matches_rfc9449_ath_encoding() {
        assert_eq!(
            dpop_authorization_credential_hash("session-credential-1"),
            URL_SAFE_NO_PAD.encode(Sha256::digest(b"session-credential-1"))
        );
    }

    #[test]
    fn handle_mints_ath_when_authorization_credential_supplied() {
        let mut store = isolated_store("mint-ath");
        let handle = ensure_device_key(&mut store).unwrap();
        let proof = handle
            .mint_proof(
                "POST",
                "https://example.test/_cokret/gate/account/session-grants",
                Some("session-credential-1"),
            )
            .unwrap();
        let payload = proof_payload(&proof);
        assert_eq!(
            payload["ath"],
            dpop_authorization_credential_hash("session-credential-1")
        );
    }

    #[test]
    fn handle_omits_ath_when_no_authorization_credential_supplied() {
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
        assert_eq!(record.seed_b64, original.seed_b64().as_str());
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
        let _lock = seed_scope_test_lock();
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

    #[test]
    fn recovers_secure_store_dpop_record_from_account_scoped_signing_seed() {
        let _lock = seed_scope_test_lock();
        let mut store = isolated_store("recover-secure-dpop-record");
        let secure = MemorySecureKeyStore::default();
        let actor = "did:web:alice.example";
        let _scope = set_seed_scope(actor);
        let seed = [9_u8; 32];
        crate::secure_key_store::store_signing_seed_scoped(&secure, Some(actor), &seed).unwrap();

        let recovered = load_or_recover_device_key_with_secure_store(&mut store, &secure)
            .unwrap()
            .expect("recovered handle");
        assert_eq!(recovered.seed_b64().as_str(), URL_SAFE_NO_PAD.encode(seed));
        let public_record = store.dpop_device_key().expect("public dpop record");
        assert!(public_record.seed_b64.is_empty());
        assert_eq!(public_record.jkt, recovered.jkt());
        let loaded = load_device_key_with_secure_store(&store, &secure)
            .unwrap()
            .expect("loaded recovered handle");
        assert_eq!(loaded.jkt(), recovered.jkt());
    }

    #[test]
    fn load_or_recover_repairs_stale_account_dpop_record_from_signing_seed() {
        let _lock = seed_scope_test_lock();
        let mut store = isolated_store("repair-stale-dpop-record");
        let secure = MemorySecureKeyStore::default();
        let actor = "did:web:bob.example";
        let _scope = set_seed_scope(actor);
        let old_seed = [3_u8; 32];
        let new_seed = [7_u8; 32];
        let old_record =
            dpop_device_key_record_from_seed(&URL_SAFE_NO_PAD.encode(old_seed)).unwrap();
        store
            .set_dpop_device_key_with_secure_store(Some(old_record.clone()), &secure)
            .unwrap();
        crate::secure_key_store::store_signing_seed_scoped(&secure, Some(actor), &new_seed)
            .unwrap();

        let repaired = load_or_recover_device_key_with_secure_store(&mut store, &secure)
            .unwrap()
            .expect("repaired handle");

        assert_ne!(repaired.jkt(), old_record.jkt);
        assert_eq!(repaired.seed_b64().as_str(), URL_SAFE_NO_PAD.encode(new_seed));
        let loaded = load_device_key_with_secure_store(&store, &secure)
            .unwrap()
            .expect("loaded repaired handle");
        assert_eq!(loaded.jkt(), repaired.jkt());
    }

    #[test]
    fn ensure_repairs_stale_account_dpop_record_from_signing_seed() {
        let _lock = seed_scope_test_lock();
        let mut store = isolated_store("ensure-repairs-stale-dpop-record");
        let secure = MemorySecureKeyStore::default();
        let actor = "did:web:returning.example";
        let _scope = set_seed_scope(actor);
        let old_seed = [11_u8; 32];
        let new_seed = [13_u8; 32];
        let old_record =
            dpop_device_key_record_from_seed(&URL_SAFE_NO_PAD.encode(old_seed)).unwrap();
        store
            .set_dpop_device_key_with_secure_store(Some(old_record.clone()), &secure)
            .unwrap();
        crate::secure_key_store::store_signing_seed_scoped(&secure, Some(actor), &new_seed)
            .unwrap();

        let repaired = ensure_device_key_with_secure_store(&mut store, &secure).unwrap();

        assert_ne!(repaired.jkt(), old_record.jkt);
        assert_eq!(repaired.seed_b64().as_str(), URL_SAFE_NO_PAD.encode(new_seed));
    }
}
