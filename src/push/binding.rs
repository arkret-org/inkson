//! SecureKeyStore-backed push-token binding.
//!
//! ═══════════════════════════════════════════════════════════════════════════
//! The push token (`ChimePushRegisterDeviceRequest::push_key`) is a long-lived
//! platform identifier that we would otherwise persist plaintext in
//! `LocalStateStore` so a register/unregister retry can find it. By
//! routing the persistence through the [`SecureKeyStore`] tier and
//! AEAD-wrapping the token with a key derived from a per-installation
//! wrapping seed (itself stored in the secure-key tier), we get two
//! useful properties:
//!
//!   1. The on-disk form of the token is ChaCha20-Poly1305 ciphertext; a backup/disk-dump that
//!      doesn't include the secure-key tier cannot recover the plaintext token.
//!   2. Rotating the wrapping seed via [`PushTokenBinding::rotate`] invalidates every prior
//!      ciphertext — useful when device credentials change or when the user opts to wipe push state
//!      without re-registering.
//!
//! The binding is intentionally narrow: it owns *one* wrapping seed
//! per service_name and one entry slot per device_id. Multi-device
//! hosts construct one binding per device.
//! ═══════════════════════════════════════════════════════════════════════════
//!
//! Pure structural split out of `push::mod`; behaviour and visibility
//! are unchanged.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;

use crate::secure_key_store::{SecureKeyStore, SecureKeyStoreError, unwrap_secret, wrap_secret};

/// SecureKeyStore key under which the AEAD wrapping seed for push tokens
/// is held. Keyed by service_name, so a `inkson` install and a
/// `inkson.test` install have separate seeds (and so do their
/// ciphertext entries).
pub const PUSH_TOKEN_WRAP_SEED_KEY: &str = "push.token.wrap_seed.v1";

/// SecureKeyStore key prefix under which the per-device wrapped push
/// token ciphertext is held. Combined with the device id to form the
/// full entry name.
pub const PUSH_TOKEN_ENTRY_PREFIX: &str = "push.token.v1.";

pub(crate) fn push_token_entry_key(device_id: &str) -> String {
    format!("{PUSH_TOKEN_ENTRY_PREFIX}{device_id}")
}

/// Read (or generate + persist) the 32-byte AEAD wrapping seed under
/// [`PUSH_TOKEN_WRAP_SEED_KEY`]. Used by [`PushTokenBinding`] to
/// wrap/unwrap the persisted push token. A future call to
/// [`rotate_push_token_wrap_seed`] overwrites the seed; afterwards
/// any prior ciphertext fails to decrypt.
fn load_or_create_push_token_wrap_seed(
    store: &dyn SecureKeyStore,
) -> Result<[u8; 32], SecureKeyStoreError> {
    if let Some(existing) = store.get_secret(PUSH_TOKEN_WRAP_SEED_KEY)? {
        let bytes = STANDARD_NO_PAD
            .decode(existing.as_bytes())
            .map_err(|err| SecureKeyStoreError::Backend(format!("push wrap seed decode: {err}")))?;
        if bytes.len() != 32 {
            return Err(SecureKeyStoreError::Backend(format!(
                "push wrap seed length {}, expected 32",
                bytes.len()
            )));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        return Ok(buf);
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom wrap seed: {err}")))?;
    store.store_secret(PUSH_TOKEN_WRAP_SEED_KEY, &STANDARD_NO_PAD.encode(seed))?;
    Ok(seed)
}

/// Force-rotate the AEAD wrapping seed used to wrap persisted push
/// tokens. Returns the new seed bytes (the caller usually does not need
/// them — [`PushTokenBinding::rotate`] handles re-wrapping the live
/// token). After this call, every ciphertext stored under
/// [`PUSH_TOKEN_ENTRY_PREFIX`]`*` becomes undecryptable, so callers
/// should follow up with [`PushTokenBinding::store_token`] or
/// [`PushTokenBinding::rotate`] before the next register-device strand.
pub fn rotate_push_token_wrap_seed(
    store: &dyn SecureKeyStore,
) -> Result<[u8; 32], SecureKeyStoreError> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom wrap seed: {err}")))?;
    store.store_secret(PUSH_TOKEN_WRAP_SEED_KEY, &STANDARD_NO_PAD.encode(seed))?;
    Ok(seed)
}

/// Per-device wrapper that funnels push-token persistence through the
/// process-wide [`SecureKeyStore`]. Construct via
/// [`PushTokenBinding::new`] passing the same `service_name` that was
/// handed to [`crate::secure_key_store::default_secure_key_store`].
///
/// The binding does not own the SecureKeyStore — it holds an
/// `Arc<dyn SecureKeyStore>` so multiple bindings (one per device id)
/// share the same wrapping-seed slot.
#[derive(Clone)]
pub struct PushTokenBinding {
    store: Arc<dyn SecureKeyStore>,
    device_id: String,
}

impl PushTokenBinding {
    /// Construct a binding that persists tokens for `device_id` via
    /// `store`. The wrapping seed under
    /// [`PUSH_TOKEN_WRAP_SEED_KEY`] is created lazily on the first
    /// [`store_token`](Self::store_token) call (or eagerly via
    /// [`ensure_wrap_seed`](Self::ensure_wrap_seed)).
    pub fn new(store: Arc<dyn SecureKeyStore>, device_id: impl Into<String>) -> Self {
        Self {
            store,
            device_id: device_id.into(),
        }
    }

    /// Device id this binding writes / reads under.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Persist `push_key` under this binding's device id. Overwrites
    /// silently. The on-disk form is `wrap_secret(push_key, seed)` —
    /// a ChaCha20-Poly1305 ciphertext with a random nonce prefix.
    pub fn store_token(&self, push_key: &str) -> Result<(), SecureKeyStoreError> {
        let seed = load_or_create_push_token_wrap_seed(self.store.as_ref())?;
        let wrapped = wrap_secret(push_key, &seed)?;
        self.store
            .store_secret(&push_token_entry_key(&self.device_id), &wrapped)
    }

    /// Load the previously-persisted push token. Returns `Ok(None)`
    /// when no entry exists; also returns `Ok(None)` when the
    /// ciphertext fails to authenticate (matches
    /// [`unwrap_secret`]'s contract — typically because the wrapping
    /// seed has been rotated since the ciphertext was written).
    pub fn load_token(&self) -> Result<Option<String>, SecureKeyStoreError> {
        let Some(wrapped) = self
            .store
            .get_secret(&push_token_entry_key(&self.device_id))?
        else {
            return Ok(None);
        };
        let Some(seed_b64) = self.store.get_secret(PUSH_TOKEN_WRAP_SEED_KEY)? else {
            // Seed was rotated away without re-wrapping; the ciphertext
            // is unrecoverable.
            return Ok(None);
        };
        let seed_bytes = STANDARD_NO_PAD
            .decode(seed_b64.as_bytes())
            .map_err(|err| SecureKeyStoreError::Backend(format!("seed decode: {err}")))?;
        if seed_bytes.len() != 32 {
            return Ok(None);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        unwrap_secret(&wrapped, &seed)
    }

    /// Remove the persisted token for this device id. Idempotent —
    /// deleting an absent entry returns `Ok(())`.
    pub fn delete_token(&self) -> Result<(), SecureKeyStoreError> {
        self.store
            .delete_secret(&push_token_entry_key(&self.device_id))
    }

    /// Rotate the AEAD wrapping seed AND re-wrap the current token
    /// under the new seed. Returns the rotated token (read from the
    /// store before rotation) so the caller can immediately drive a
    /// fresh `register_device` call.
    ///
    /// If no token was persisted, the seed is rotated and `Ok(None)`
    /// is returned.
    ///
    /// After this method returns, any *other* ciphertext stored under
    /// a different device id with the old seed becomes unrecoverable —
    /// callers that share a wrapping seed across device ids should
    /// rotate at a higher layer.
    pub fn rotate(&self) -> Result<Option<String>, SecureKeyStoreError> {
        let token = self.load_token()?;
        let _ = rotate_push_token_wrap_seed(self.store.as_ref())?;
        if let Some(ref t) = token {
            self.store_token(t)?;
        } else {
            // Drop any stale ciphertext that was wrapped under the
            // pre-rotation seed.
            self.delete_token()?;
        }
        Ok(token)
    }
}

impl std::fmt::Debug for PushTokenBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushTokenBinding")
            .field("device_id", &self.device_id)
            .field("store", &self.store.backend_name())
            .finish()
    }
}
