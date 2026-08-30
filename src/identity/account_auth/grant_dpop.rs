//! G3.Y0 — per-device DPoP key management.
//!
//! This module is the inkson host policy layer around the shared SDK DPoP
//! helpers. It:
//!
//! 1. Generates an Ed25519 device key on first launch and persists it via
//!    [`crate::state::LocalStateStore::set_dpop_device_key`].
//! 2. Hands out a `DpopHandle` callers can use to mint SDK DPoP proofs without having to plumb
//!    through the raw `SigningKey`.
//! 3. Surfaces the RFC 7638 thumbprint so the UI / refresh path can display `cnf.jkt` for
//!    diagnostic testids.
//!
//! ## Algorithm choice
//!
//! Ed25519 (`alg=Ed25519`, `kty=OKP`, `crv=Ed25519`) over ES256. Three
//! reasons, in order of weight:
//!
//! * Every other signing surface in inkson — `event_signer`, `move_builder`, `session_grant` proofs
//!   — is already ed25519. Adding a second curve doubles the WASM bundle surface for no protocol
//!   benefit.
//! * coauth's `DpopVerifier` (`coauth/crates/backend/src/services/dpop.rs`) accepts `Ed25519` as a
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
//! `initialize_wasm_secure_key_store_async`, so the DPoP seed follows the
//! same handoff as session credentials. Tests keep using plaintext
//! state records to remain deterministic and dependency-free.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use ed25519_dalek::{Signer as _, SigningKey};
use zeroize::Zeroizing;

use crate::state::{DpopDeviceKeyRecord, LocalStateStore};

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
    /// The shared SDK DPoP proof builder failed.
    #[error("DPoP mint failed: {0}")]
    Mint(String),
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

    /// Canonical public JWK committed by the atomic identity-creation request.
    pub fn canonical_session_public_jwk(
        &self,
    ) -> Result<arkret_sdk::CanonicalSessionPublicJwk, AuthDpopError> {
        let jwk = arkret_sdk::signatures::JsonWebKey::from_ed25519_verifying_key(
            &self.signing_key.verifying_key(),
        );
        let bytes = arkret_sdk::canonical::canonical_json_bytes(&jwk)
            .map_err(|error| AuthDpopError::SessionGrantProof(error.to_string()))?;
        let json = String::from_utf8(bytes)
            .map_err(|error| AuthDpopError::SessionGrantProof(error.to_string()))?;
        arkret_sdk::CanonicalSessionPublicJwk::new(json)
            .map_err(|error| AuthDpopError::SessionGrantProof(error.to_string()))
    }

    /// Export the raw 32-byte ed25519 seed as base64url-no-pad.
    ///
    /// Used only by the durable hard-logout journal
    /// ([`crate::pending_logout`]): the logout wipes the live key, so a
    /// copy of the seed is stashed (alongside [`Self::jkt`]) purely so a
    /// later boot can rebuild this handle via
    /// [`device_handle_from_seed`] and mint the grant-binding DPoP proof that revokes
    /// the *old* grant. This is the same secret already held in the secure
    /// key store; it is cleared as soon as the revoke succeeds.
    pub fn seed_b64(&self) -> Zeroizing<String> {
        Zeroizing::new(URL_SAFE_NO_PAD.encode(self.signing_key.to_bytes()))
    }

    /// Export the device signing key as PKCS#8 PEM.
    ///
    /// Used after a DPoP-bound session-grant rotation: the rotated grant's
    /// `session_public_key` is this device key (the grant binds to the same key
    /// the rotation proof proved possession of), so the station
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

    /// Sign one `challenge_dpop_session_v1` proof for
    /// `ak.profile.binding.websocket.v1`.
    ///
    /// The transcript is the SDK's — the same holder key backs the HTTP DPoP
    /// proofs above, and it never leaves this handle. `zh/sync/websocket-binding.md`
    /// §3.1 is explicit that this is a distinct validator context from the HTTP
    /// one, which is why it is a separate method rather than a `mint_proof`
    /// call with a `wss` target.
    pub fn mint_websocket_auth_proof(
        &self,
        base_url: &str,
        session_grant: &str,
        nonce: &str,
        jti: &str,
        issued_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<String, AuthDpopError> {
        arkret_sdk::signatures::websocket_auth::build_websocket_auth_proof(
            &arkret_sdk::signatures::websocket_auth::WebSocketAuthProofRequest {
                base_url,
                session_grant,
                nonce,
                issued_at,
                jti,
            },
            &self.signing_key,
        )
        .map(|proof| proof.compact_jws)
        .map_err(|error| AuthDpopError::Mint(error.to_string()))
    }

    /// Build SDK http-client DPoP auth for requests protected by the
    /// current session grant.
    pub fn sdk_dpop_auth_for_access_token(
        &self,
        access_token: impl Into<String>,
    ) -> arkret_sdk::http_client::DpopAuth {
        garth::session::dpop::access_token_auth(access_token, self.signing_key.clone())
    }

    /// Build SDK http-client DPoP auth for proof-only requests.
    pub fn sdk_dpop_proof_only_auth(&self) -> arkret_sdk::http_client::DpopAuth {
        garth::session::dpop::proof_only_auth(self.signing_key.clone())
    }

    /// Build SDK authentication for the DPoP-scheme account handoff token.
    pub fn sdk_account_handoff_auth(
        &self,
        account_handoff_grant: impl Into<String>,
    ) -> arkret_sdk::http_client::DpopAuth {
        garth::session::dpop::account_handoff_auth(account_handoff_grant, self.signing_key.clone())
    }

    /// Holder-sign canonical protocol bytes with the same key published in
    /// the request DPoP JWK.
    pub fn sign_protocol_bytes(&self, bytes: &[u8]) -> arkret_sdk::Result<String> {
        Ok(URL_SAFE_NO_PAD.encode(self.signing_key.sign(bytes).to_bytes()))
    }
}

/// Generate or load the device DPoP key. Calls return the same handle
/// for the lifetime of the persisted record.
pub fn ensure_device_key(store: &mut LocalStateStore) -> Result<DpopHandle, AuthDpopError> {
    #[cfg(not(test))]
    {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        if let Some(device_id) = crate::secure_key_store::pending_login_device_id() {
            let pending_store = crate::secure_key_store::PendingLocalStore::new(device_id);
            ensure_pending_device_key_with_secure_store(
                store,
                secure_store.as_ref(),
                &pending_store,
            )
        } else {
            ensure_device_key_with_secure_store(store, secure_store.as_ref())
        }
    }

    #[cfg(test)]
    {
        ensure_device_key_in_plaintext_state(store)
    }
}

/// Generate or load the grant-binding DPoP key for a pre-principal login
/// transaction. This path never consults a user scope: the caller supplies the
/// validated pending-device store, which is promoted only after the authority
/// returns a principal DID.
pub fn ensure_pending_device_key_with_secure_store(
    store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    pending_store: &crate::secure_key_store::PendingLocalStore,
) -> Result<DpopHandle, AuthDpopError> {
    let material = pending_store
        .ensure_grant_binding_seed(secure_store)
        .map_err(|error| {
            AuthDpopError::SecureStore(format!("ensure pending grant-binding seed: {error}"))
        })?;
    let (handle, record) = handle_and_record_from_seed(material.seed)?;
    store
        .set_pending_dpop_device_key_with_secure_store(Some(record), secure_store, pending_store)
        .map_err(|error| AuthDpopError::SecureStore(error.to_string()))?;
    Ok(handle)
}

/// Durable prepare half for a pending grant-binding key. This deliberately
/// does not borrow [`LocalStateStore`] across `.await`: callers first wait for
/// the seed commit, then publish the returned public record synchronously.
/// That ordering prevents an OIDC/session exchange from depending on a key
/// that exists only in the browser backend's volatile write cache.
pub async fn prepare_pending_device_key_with_secure_store_durable(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    pending_store: &crate::secure_key_store::PendingLocalStore,
) -> Result<(DpopHandle, DpopDeviceKeyRecord), AuthDpopError> {
    let material = pending_store
        .ensure_grant_binding_seed_durable(secure_store)
        .await
        .map_err(|error| {
            AuthDpopError::SecureStore(format!(
                "durably ensure pending grant-binding seed: {error}"
            ))
        })?;
    handle_and_record_from_seed(material.seed)
}

/// Generate or load the DPoP key using the supplied secure-key backend.
/// The on-disk state keeps only public metadata; private seed bytes live
/// in the secure store.
pub fn ensure_device_key_with_secure_store(
    store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Result<DpopHandle, AuthDpopError> {
    // 0004 §4.2/§4.3: the DPoP / grant-binding key is a SESSION credential (its
    // RFC 7638 thumbprint is the grant's `cnf.jkt`), distinct from the per-account
    // device identity signing seed. It sources the dedicated grant-binding store
    // and MUST NOT activate the event signer — the device identity key that signs
    // events / KeyPackages / MLS stays on `signing_seed` and is activated
    // independently via `event_signer::bootstrap_default_signer`. Decoupling the
    // two lifecycles is what stops a fresh interactive login from rotating the
    // E2EE device identity (decision 0004).
    let material = crate::secure_key_store::ensure_grant_binding_seed(secure_store)
        .map_err(|err| AuthDpopError::SecureStore(format!("ensure grant-binding seed: {err}")))?;
    let (handle, record) = handle_and_record_from_seed(material.seed)?;
    store
        .set_dpop_device_key_with_secure_store(Some(record), secure_store)
        .map_err(|err| AuthDpopError::SecureStore(err.to_string()))?;
    Ok(handle)
}

fn persist_loaded_record(
    store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    record: DpopDeviceKeyRecord,
) -> Result<DpopHandle, AuthDpopError> {
    // 0004 §4.3: this persists the DPoP / grant-binding record only. It MUST NOT
    // activate the event signer — the device identity key that signs events stays
    // on the signing seed (activated via event_signer::bootstrap_default_signer).
    let handle = decode_record(&record)?;
    store
        .set_dpop_device_key_with_secure_store(Some(record), secure_store)
        .map_err(|err| AuthDpopError::SecureStore(err.to_string()))?;
    Ok(handle)
}

fn handle_and_record_from_seed(
    seed: [u8; 32],
) -> Result<(DpopHandle, DpopDeviceKeyRecord), AuthDpopError> {
    let signing_key = SigningKey::from_bytes(&seed);
    let jkt = jwk_thumbprint_ed25519(&signing_key.verifying_key())?;
    let record = DpopDeviceKeyRecord {
        seed_b64: URL_SAFE_NO_PAD.encode(seed),
        jkt: jkt.clone(),
        created_at: Utc::now(),
    };
    Ok((DpopHandle { signing_key, jkt }, record))
}

fn persist_recovered_seed_record(
    store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    seed: [u8; 32],
) -> Result<DpopHandle, AuthDpopError> {
    // 0004 §4.3: DPoP / grant-binding record only — never activate the event
    // signer here (the device identity key that signs events is decoupled).
    let (handle, record) = handle_and_record_from_seed(seed)?;
    store
        .set_dpop_device_key_with_secure_store(Some(record), secure_store)
        .map_err(|err| AuthDpopError::SecureStore(format!("recover DPoP record: {err}")))?;
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
    let jkt = jwk_thumbprint_ed25519(&signing_key.verifying_key())?;
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
#[cfg(test)]
pub fn load_device_key(store: &LocalStateStore) -> Result<Option<DpopHandle>, AuthDpopError> {
    #[cfg(not(test))]
    {
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
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
#[cfg(test)]
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
/// grant-binding seed when a prior boot/login wrote the seed but the derived
/// DPoP record was not durably re-homed yet. This never generates a new key: if
/// neither the record nor grant-binding seed exists, the current session
/// grant cannot be sender-constrained and the caller should let auth recovery
/// fail closed.
#[cfg(not(test))]
pub fn load_or_recover_device_key(
    store: &mut LocalStateStore,
) -> Result<Option<DpopHandle>, AuthDpopError> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
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
    // 0004 §4.2: the DPoP key is the browser-session grant-binding key, NOT the
    // per-account device identity signing seed. Prefer the persisted grant-binding
    // seed and recover the DPoP record from it when the stored record drifted;
    // never recover from (or fall back to) the signing seed — that is the device
    // identity key and must stay decoupled from the grant lifecycle. Never
    // generate here: a missing grant-binding key means the session cannot be
    // sender-constrained, so the caller fails closed.
    if let Some(material) = crate::secure_key_store::load_grant_binding_seed(secure_store)
        .map_err(|err| AuthDpopError::SecureStore(format!("load grant-binding seed: {err}")))?
    {
        let stored_jkt = store
            .load_dpop_device_key_with_secure_store(secure_store)
            .ok()
            .flatten()
            .map(|record| record.jkt);
        let (seed_handle, _) = handle_and_record_from_seed(material.seed)?;
        if stored_jkt.as_deref() != Some(seed_handle.jkt()) {
            tracing::warn!(
                stored_jkt = stored_jkt.as_deref().unwrap_or(""),
                seed_jkt = seed_handle.jkt(),
                "recovering DPoP device-key record from active grant-binding seed"
            );
        }
        return persist_recovered_seed_record(store, secure_store, material.seed).map(Some);
    }

    match store
        .load_dpop_device_key_with_secure_store(secure_store)
        .map_err(|err| AuthDpopError::SecureStore(err.to_string()))?
    {
        Some(record) => persist_loaded_record(store, secure_store, record).map(Some),
        None => Ok(None),
    }
}

/// Load the grant-binding key from one explicit accepted account scope without
/// consulting or changing the process-wide active scope.
pub(crate) fn load_user_device_key_with_secure_store(
    user_store: &crate::secure_key_store::UserLocalStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Result<Option<DpopHandle>, AuthDpopError> {
    let Some(material) = user_store
        .load_grant_binding_seed(secure_store)
        .map_err(|error| {
            AuthDpopError::SecureStore(format!("load account grant-binding seed: {error}"))
        })?
    else {
        return Ok(None);
    };
    handle_and_record_from_seed(material.seed).map(|(handle, _)| Some(handle))
}

/// Read the DPoP holder for one pre-principal authentication transaction.
///
/// The pending device id is the storage boundary until the authority returns
/// a principal core id. Consequently this path never reads or writes an active
/// [`crate::secure_key_store::UserLocalStore`]. It also never generates a new
/// holder key: losing the original key must fail the handoff closed.
pub fn load_or_recover_pending_device_key_with_secure_store(
    store: &mut LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    pending_store: &crate::secure_key_store::PendingLocalStore,
) -> Result<Option<DpopHandle>, AuthDpopError> {
    if let Some(material) = pending_store
        .load_grant_binding_seed(secure_store)
        .map_err(|error| {
            AuthDpopError::SecureStore(format!("load pending grant-binding seed: {error}"))
        })?
    {
        let stored_jkt = store
            .load_pending_dpop_device_key_with_secure_store(secure_store, pending_store)
            .ok()
            .flatten()
            .map(|record| record.jkt);
        let (handle, record) = handle_and_record_from_seed(material.seed)?;
        if stored_jkt.as_deref() != Some(handle.jkt()) {
            tracing::warn!(
                device_id = %pending_store.device_id(),
                stored_jkt = stored_jkt.as_deref().unwrap_or(""),
                seed_jkt = handle.jkt(),
                "recovering pending DPoP record from its grant-binding seed"
            );
        }
        store
            .set_pending_dpop_device_key_with_secure_store(
                Some(record),
                secure_store,
                pending_store,
            )
            .map_err(|error| {
                AuthDpopError::SecureStore(format!("recover pending DPoP record: {error}"))
            })?;
        return Ok(Some(handle));
    }

    let Some(record) = store
        .load_pending_dpop_device_key_with_secure_store(secure_store, pending_store)
        .map_err(|error| AuthDpopError::SecureStore(error.to_string()))?
    else {
        return Ok(None);
    };
    let handle = decode_record(&record)?;
    store
        .set_pending_dpop_device_key_with_secure_store(Some(record), secure_store, pending_store)
        .map_err(|error| AuthDpopError::SecureStore(error.to_string()))?;
    Ok(Some(handle))
}

/// Rebuild a [`DpopHandle`] from a persisted seed + thumbprint pair,
/// without touching the live key store.
///
/// Used by the durable hard-logout retry path
/// ([`crate::pending_logout`]): a logout wipes the active device key so
/// the next sign-in rotates `cnf.jkt`, but the pending-logout record
/// stashes a copy of the *old* seed purely so a later boot can still mint
/// the grant-binding DPoP proof needed to revoke the *old* grant. The thumbprint is
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
    let derived = jwk_thumbprint_ed25519(&signing_key.verifying_key())?;
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
    let jkt = jwk_thumbprint_ed25519(&signing_key.verifying_key())?;
    Ok(DpopDeviceKeyRecord {
        seed_b64: URL_SAFE_NO_PAD.encode(seed),
        jkt,
        created_at: Utc::now(),
    })
}

fn jwk_thumbprint_ed25519(
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<String, AuthDpopError> {
    let jwk = arkret_sdk::signatures::JsonWebKey::from_ed25519_verifying_key(verifying_key);
    arkret_sdk::dpop::dpop_jwk_thumbprint(&jwk)
        .map_err(|error| AuthDpopError::Mint(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_key_store::{DeviceSeedScopeTestGuard, MemorySecureKeyStore};
    // YOU-05-010: shared hermetic state-store fixture from `local_state`.
    use crate::state::isolated_store_for_tests as isolated_store;

    fn test_authority(actor: &str) -> arkret_sdk::AccountId {
        arkret_sdk::AccountId::new(
            crate::mls_api_helpers::principal_core_id(actor).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
        )
    }

    fn test_device_id() -> arkret_sdk::DeviceId {
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000099".to_owned())
            .unwrap()
    }

    #[test]
    fn ensure_device_key_is_idempotent() {
        let mut store = isolated_store("idempotent");
        let first = ensure_device_key(&mut store).unwrap();
        let second = ensure_device_key(&mut store).unwrap();
        assert_eq!(first.jkt(), second.jkt());
    }

    #[test]
    fn seed_export_rebuilds_an_equivalent_handle() {
        // The durable hard-logout journal stashes seed_b64 + jkt and later
        // rebuilds the grant-binding key via device_handle_from_seed. The rebuilt
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
    fn secure_store_seed_round_trips_without_plaintext_state_seed() {
        let authority = test_authority("ak:did_core:web:secure.example");
        let device_id = test_device_id();
        let _scope = DeviceSeedScopeTestGuard::replace(Some((&authority, &device_id)));
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
    fn pending_handoff_recovers_holder_without_an_active_user_scope() {
        let _scope = DeviceSeedScopeTestGuard::replace(None);
        let mut store = isolated_store("pending-handoff-holder");
        let secure = MemorySecureKeyStore::default();
        let pending_store = crate::secure_key_store::PendingLocalStore::new(
            arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000099".to_owned())
                .unwrap(),
        );
        let created =
            ensure_pending_device_key_with_secure_store(&mut store, &secure, &pending_store)
                .unwrap();

        let recovered = load_or_recover_pending_device_key_with_secure_store(
            &mut store,
            &secure,
            &pending_store,
        )
        .unwrap()
        .expect("pending holder");

        assert_eq!(recovered.jkt(), created.jkt());
        assert!(crate::secure_key_store::active_device_seed_scope().is_none());
    }

    #[tokio::test]
    async fn accepted_account_holder_load_does_not_depend_on_the_active_scope() {
        let authority = test_authority("ak:did_core:web:accepted.example");
        let device_id = test_device_id();
        let _scope = DeviceSeedScopeTestGuard::replace(None);
        let user_store =
            crate::secure_key_store::UserLocalStore::new(authority, device_id).unwrap();
        let secure = MemorySecureKeyStore::default();
        let seed = [31_u8; 32];
        user_store
            .save_grant_binding_seed_b64url_durable(&secure, &URL_SAFE_NO_PAD.encode(seed))
            .await
            .unwrap();

        let restored = load_user_device_key_with_secure_store(&user_store, &secure)
            .unwrap()
            .expect("accepted holder");

        assert_eq!(restored.seed_b64().as_str(), URL_SAFE_NO_PAD.encode(seed));
        assert!(crate::secure_key_store::active_device_seed_scope().is_none());
    }

    #[test]
    fn recovers_secure_store_dpop_record_from_grant_binding_seed() {
        // 0004 §4.2: the DPoP key is the browser-session grant-binding seed, not
        // the per-account device identity signing seed. `load_or_recover` recovers
        // the DPoP record from the grant-binding seed and ignores the signing seed.
        let actor = "ak:did_core:web:alice.example";
        let authority = test_authority(actor);
        let device_id = test_device_id();
        let _scope = DeviceSeedScopeTestGuard::replace(Some((&authority, &device_id)));
        let mut store = isolated_store("recover-secure-dpop-record");
        let secure = MemorySecureKeyStore::default();
        // A device identity seed exists for this account but MUST NOT drive DPoP.
        let identity_seed = [9_u8; 32];
        crate::secure_key_store::store_signing_seed(&secure, &identity_seed).unwrap();
        let grant_seed = [19_u8; 32];
        crate::secure_key_store::store_grant_binding_seed(&secure, &grant_seed).unwrap();

        let recovered = load_or_recover_device_key_with_secure_store(&mut store, &secure)
            .unwrap()
            .expect("recovered handle");
        assert_eq!(
            recovered.seed_b64().as_str(),
            URL_SAFE_NO_PAD.encode(grant_seed)
        );
        assert_ne!(
            recovered.seed_b64().as_str(),
            URL_SAFE_NO_PAD.encode(identity_seed)
        );
        let public_record = store.dpop_device_key().expect("public dpop record");
        assert!(public_record.seed_b64.is_empty());
        assert_eq!(public_record.jkt, recovered.jkt());
        let loaded = load_device_key_with_secure_store(&store, &secure)
            .unwrap()
            .expect("loaded recovered handle");
        assert_eq!(loaded.jkt(), recovered.jkt());
    }

    #[test]
    fn load_or_recover_repairs_stale_account_dpop_record_from_grant_binding_seed() {
        // 0004 §4.2: a stale stored DPoP record is repaired from the grant-binding
        // seed (the `cnf.jkt` credential), never from the device identity signing
        // seed. A present signing seed for the same account MUST be ignored.
        let actor = "ak:did_core:web:bob.example";
        let authority = test_authority(actor);
        let device_id = test_device_id();
        let _scope = DeviceSeedScopeTestGuard::replace(Some((&authority, &device_id)));
        let mut store = isolated_store("repair-stale-dpop-record");
        let secure = MemorySecureKeyStore::default();
        let old_seed = [3_u8; 32];
        let identity_seed = [7_u8; 32];
        let grant_seed = [23_u8; 32];
        let old_record =
            dpop_device_key_record_from_seed(&URL_SAFE_NO_PAD.encode(old_seed)).unwrap();
        store
            .set_dpop_device_key_with_secure_store(Some(old_record.clone()), &secure)
            .unwrap();
        crate::secure_key_store::store_signing_seed(&secure, &identity_seed).unwrap();
        crate::secure_key_store::store_grant_binding_seed(&secure, &grant_seed).unwrap();

        let repaired = load_or_recover_device_key_with_secure_store(&mut store, &secure)
            .unwrap()
            .expect("repaired handle");

        assert_ne!(repaired.jkt(), old_record.jkt);
        assert_eq!(
            repaired.seed_b64().as_str(),
            URL_SAFE_NO_PAD.encode(grant_seed)
        );
        assert_ne!(
            repaired.seed_b64().as_str(),
            URL_SAFE_NO_PAD.encode(identity_seed)
        );
        let loaded = load_device_key_with_secure_store(&store, &secure)
            .unwrap()
            .expect("loaded repaired handle");
        assert_eq!(loaded.jkt(), repaired.jkt());
    }

    #[test]
    fn ensure_device_key_sources_grant_binding_not_signing_seed() {
        // 0004 §4.2: `ensure_device_key` mints/loads the DPoP key from the
        // grant-binding store, decoupled from the device identity signing seed.
        let actor = "ak:did_core:web:returning.example";
        let authority = test_authority(actor);
        let device_id = test_device_id();
        let _scope = DeviceSeedScopeTestGuard::replace(Some((&authority, &device_id)));
        let mut store = isolated_store("ensure-sources-grant-binding");
        let secure = MemorySecureKeyStore::default();
        let identity_seed = [13_u8; 32];
        let grant_seed = [29_u8; 32];
        crate::secure_key_store::store_signing_seed(&secure, &identity_seed).unwrap();
        crate::secure_key_store::store_grant_binding_seed(&secure, &grant_seed).unwrap();

        let handle = ensure_device_key_with_secure_store(&mut store, &secure).unwrap();

        assert_eq!(
            handle.seed_b64().as_str(),
            URL_SAFE_NO_PAD.encode(grant_seed)
        );
        assert_ne!(
            handle.seed_b64().as_str(),
            URL_SAFE_NO_PAD.encode(identity_seed)
        );
    }
}
