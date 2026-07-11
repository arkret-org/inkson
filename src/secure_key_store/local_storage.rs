//! wasm32-only AEAD-wrapped `localStorage` [`SecureKeyStore`].

#![cfg(target_arch = "wasm32")]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use garth::{SecretBytes, SecureKeyStoreBackendInfo};

use super::{
    SecureKeyStore, SecureKeyStoreError, WASM_ED25519_SEED_INDEXEDDB_REQUIRED,
    WASM_SENSITIVE_SECRET_INDEXEDDB_REQUIRED, is_wasm_ed25519_seed_key,
    is_wasm_indexeddb_required_secret_key, unwrap_secret,
    wasm_localstorage_secret_downgrade_enabled, wrap_secret,
};

/// wasm32-only persistence-backed store
/// that wraps secrets with ChaCha20-Poly1305 before stashing them in
/// `localStorage`. The wrapping key is a per-installation random
/// 32-byte seed that itself lives in `localStorage` under a separate
/// key — this is the same trust posture as
/// `MemorySecureKeyStore` against a fully-compromised DOM, but it
/// keeps secrets out of plaintext if a backup / disk-dump only sees
/// the localStorage blob (an actual attack the spec calls out in
/// `crypto-media/secret-storage.md` §3 — the "lukewarm" tier).
///
/// This backend is only for non-sensitive first-paint secrets. Ed25519
/// signing seeds, local identity seeds, account MLS secrets, and session
/// credentials are refused so they cannot land in localStorage. The IndexedDB
/// + non-extractable SubtleCrypto tier uses the same
/// `inkson.secret.<service_name>.<key>` namespace after async upgrade.
pub struct LocalStorageSecureKeyStore {
    service_name: String,
    wrapping_key: [u8; 32],
}

impl LocalStorageSecureKeyStore {
    const WRAPPING_KEY_STORAGE_KEY_SUFFIX: &'static str = ".wrap_seed.v1";

    /// Initialise the store for the given service namespace. Boot
    /// reads the wrapping-key seed from `localStorage`, generating a
    /// fresh one via `getrandom` if none exists yet. The seed is
    /// base64-encoded so it round-trips through the JS string API.
    pub fn new(service_name: &str) -> Result<Self, SecureKeyStoreError> {
        let storage = Self::storage()?;
        let seed_key = Self::wrapping_seed_key(service_name);
        let wrapping_key = match storage
            .get_item(&seed_key)
            .map_err(|err| SecureKeyStoreError::Backend(format!("localStorage get: {err:?}")))?
        {
            Some(b64) => {
                let bytes = STANDARD_NO_PAD.decode(b64.as_bytes()).map_err(|err| {
                    SecureKeyStoreError::Backend(format!("wrap_seed base64: {err}"))
                })?;
                if bytes.len() != 32 {
                    return Err(SecureKeyStoreError::Backend(format!(
                        "wrap_seed length {}, expected 32",
                        bytes.len()
                    )));
                }
                let mut buf = [0u8; 32];
                buf.copy_from_slice(&bytes);
                buf
            }
            None => {
                let mut seed = [0u8; 32];
                getrandom::fill(&mut seed)
                    .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom: {err}")))?;
                storage
                    .set_item(&seed_key, &STANDARD_NO_PAD.encode(seed))
                    .map_err(|err| {
                        SecureKeyStoreError::Backend(format!("localStorage set seed: {err:?}"))
                    })?;
                seed
            }
        };
        Ok(Self {
            service_name: service_name.to_owned(),
            wrapping_key,
        })
    }

    fn storage() -> Result<web_sys::Storage, SecureKeyStoreError> {
        let window = web_sys::window().ok_or_else(|| {
            SecureKeyStoreError::Unsupported("web_sys::window unavailable (non-browser host)")
        })?;
        window
            .local_storage()
            .map_err(|err| SecureKeyStoreError::Backend(format!("localStorage: {err:?}")))?
            .ok_or_else(|| SecureKeyStoreError::Unsupported("window.localStorage not available"))
    }

    /// The wrap_seed key — `inkson.secret.<namespace>.wrap_seed.v1`. The
    /// namespace is GLOBAL (the bare `service_name`); see
    /// [`super::wrap_seed_namespace`] for why it must stay constant across a
    /// sign-in. Per-account device-key isolation is at the entry-key level, not
    /// the wrapping key.
    pub(super) fn wrapping_seed_key(service_name: &str) -> String {
        let namespace = super::wrap_seed_namespace(service_name);
        format!(
            "inkson.secret.{namespace}{}",
            Self::WRAPPING_KEY_STORAGE_KEY_SUFFIX
        )
    }

    fn entry_key(&self, key: &str) -> String {
        format!("inkson.secret.{}.{key}", self.service_name)
    }
}

impl std::fmt::Debug for LocalStorageSecureKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalStorageSecureKeyStore")
            .field("service_name", &self.service_name)
            .field("wrapping_key", &"<redacted>")
            .finish()
    }
}

impl SecureKeyStore for LocalStorageSecureKeyStore {
    fn store_secret_bytes(&self, key: &str, value: &[u8]) -> Result<(), SecureKeyStoreError> {
        if is_wasm_indexeddb_required_secret_key(key)
            && !wasm_localstorage_secret_downgrade_enabled()
        {
            return Err(SecureKeyStoreError::Unsupported(
                if is_wasm_ed25519_seed_key(key) {
                    WASM_ED25519_SEED_INDEXEDDB_REQUIRED
                } else {
                    WASM_SENSITIVE_SECRET_INDEXEDDB_REQUIRED
                },
            ));
        }
        // AEAD-wrap the value as-is (unchanged on-disk format). The backend only
        // ever holds UTF-8 (base64/JSON) values, and garth's default
        // `store_secret(&str)` routes here as valid UTF-8; reject non-UTF-8 rather
        // than silently altering the wrapped representation.
        let value = std::str::from_utf8(value).map_err(|err| {
            SecureKeyStoreError::Backend(format!("localStorage secret not utf8: {err}"))
        })?;
        let storage = Self::storage()?;
        let wrapped = wrap_secret(value, &self.wrapping_key)?;
        storage
            .set_item(&self.entry_key(key), &wrapped)
            .map_err(|err| SecureKeyStoreError::Backend(format!("localStorage set: {err:?}")))
    }

    fn get_secret_bytes(&self, key: &str) -> Result<Option<SecretBytes>, SecureKeyStoreError> {
        if is_wasm_indexeddb_required_secret_key(key)
            && !wasm_localstorage_secret_downgrade_enabled()
        {
            return Err(SecureKeyStoreError::Unsupported(
                if is_wasm_ed25519_seed_key(key) {
                    WASM_ED25519_SEED_INDEXEDDB_REQUIRED
                } else {
                    WASM_SENSITIVE_SECRET_INDEXEDDB_REQUIRED
                },
            ));
        }
        let storage = Self::storage()?;
        let Some(wrapped) = storage
            .get_item(&self.entry_key(key))
            .map_err(|err| SecureKeyStoreError::Backend(format!("localStorage get: {err:?}")))?
        else {
            return Ok(None);
        };
        Ok(unwrap_secret(&wrapped, &self.wrapping_key)?
            .map(|plain| SecretBytes::new(plain.into_bytes())))
    }

    fn delete_secret(&self, key: &str) -> Result<(), SecureKeyStoreError> {
        let storage = Self::storage()?;
        storage
            .remove_item(&self.entry_key(key))
            .map_err(|err| SecureKeyStoreError::Backend(format!("localStorage remove: {err:?}")))
    }

    fn list_secret_keys(&self, prefix: Option<&str>) -> Result<Vec<String>, SecureKeyStoreError> {
        let storage = Self::storage()?;
        let entry_prefix = format!("inkson.secret.{}.", self.service_name);
        let length = storage
            .length()
            .map_err(|err| SecureKeyStoreError::Backend(format!("localStorage length: {err:?}")))?;
        let mut out = Vec::new();
        for i in 0..length {
            let Ok(Some(full_key)) = storage.key(i) else {
                continue;
            };
            let Some(entry) = full_key.strip_prefix(&entry_prefix) else {
                continue;
            };
            if prefix.is_none_or(|prefix| entry.starts_with(prefix)) {
                out.push(entry.to_owned());
            }
        }
        Ok(out)
    }

    fn backend_info(&self) -> SecureKeyStoreBackendInfo {
        SecureKeyStoreBackendInfo {
            // Preserved verbatim (`FallbackSecureKeyStore` / diagnostics key off it).
            name: "local_storage_aead",
            // ChaCha20-Poly1305 wrap over a localStorage-resident random seed:
            // software-only and recoverable from a same-origin disk dump.
            hardware_backed: false,
            exportable: true,
        }
    }
}
