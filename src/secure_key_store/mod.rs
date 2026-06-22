//! Platform-secure secret storage.
//!
//! `crate::key_store` already abstracts the per-device *signing* identity
//! (ed25519 seed → did:key). This module covers the orthogonal axis:
//! arbitrary short-string secrets that should land in the OS keychain
//! rather than `state.json`. Today's callers:
//!
//! * coauth-issued session credential and session-grant holder material.
//! * Push provider auth bundles for FCM / APNs once the host adapters land.
//!
//! ## Backends
//!
//! | Target          | Default backend         | Notes |
//! |-----------------|-------------------------|-------|
//! | macOS / Linux / Windows | [`KeyringSecureKeyStore`] | Uses the `keyring` crate (Keychain / Secret Service / Credential Manager). |
//! | wasm32          | [`LocalStorageSecureKeyStore`] for low-value first-paint secrets, then [`IndexedDbSecureKeyStore`] after async upgrade | Ed25519 signing seeds, account MLS secrets, and session credentials require the IndexedDB + non-extractable SubtleCrypto tier and fail closed before upgrade. |
//! | iOS / Android   | [`HostBridgeSecureKeyStore`] when the host installs a bridge; otherwise [`MemorySecureKeyStore`] | Mobile artifacts are outside the local 1.0 milestone. |
//!
//! ## Why not reuse `crate::key_store::KeyStore`?
//!
//! `KeyStore` is typed for `LocalIdentityRecord` (seed bytes + did:key
//! cache). [`SecureKeyStore`] is a string KV — it deliberately has no
//! schema so callers don't have to extend a typed enum each time a new
//! secret category appears.

use std::sync::Arc;
#[cfg(target_arch = "wasm32")]
use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use chacha20poly1305::aead::{Aead, OsRng};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit, Nonce};

mod fallback;
mod host_bridge;
mod indexed_db;
mod keyring;
mod local_storage;
mod memory;
mod platform;
mod signing_seed;

#[cfg(test)]
mod tests;

#[cfg(target_arch = "wasm32")]
use fallback::FallbackSecureKeyStore;
pub use host_bridge::{
    HostBridgeSecureKeyStore, HostSecretBridge, host_secret_bridge_installed,
    install_host_secret_bridge,
};
#[cfg(target_arch = "wasm32")]
pub use indexed_db::{
    IndexedDbSecureKeyStore, migrate_localstorage_entries_to_indexeddb,
    upgrade_wasm_secure_key_store_async,
};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub use keyring::KeyringSecureKeyStore;
#[cfg(target_arch = "wasm32")]
pub use local_storage::LocalStorageSecureKeyStore;
pub use memory::MemorySecureKeyStore;
#[cfg(any(feature = "mobile-android", target_os = "android"))]
pub use platform::AndroidKeystoreSecureKeyStore;
#[cfg(any(feature = "mobile-ios", target_os = "ios"))]
pub use platform::IosKeychainSecureKeyStore;
pub use signing_seed::{
    SIGNING_SEED_KEY, SigningSeedMaterial, ensure_signing_seed, load_signing_seed,
    store_signing_seed,
};

#[cfg(target_arch = "wasm32")]
static WASM_UPGRADED_SECURE_KEY_STORE: OnceLock<Arc<dyn SecureKeyStore>> = OnceLock::new();

#[cfg(target_arch = "wasm32")]
pub(crate) const WASM_INDEXEDDB_SECURE_KEY_STORE_BACKEND: &str = "indexed_db_subtle_aes_gcm";

#[cfg(any(target_arch = "wasm32", test))]
const WASM_LOCAL_IDENTITY_SEED_KEY: &str = "identity.local.primary.v1";

/// Secure-store key for the durable hard-logout journal
/// ([`crate::pending_logout`]). The record embeds the device DPoP holder
/// seed, so it is classified as a seed-grade secret: IndexedDB-only on wasm
/// (no localStorage tier) and excluded from the unload-race localStorage
/// mirror, exactly like an Ed25519 signing seed.
pub(crate) const PENDING_LOGOUT_SECRET_KEY: &str = "cokret.pending_logout.v1";

#[cfg(target_arch = "wasm32")]
const WASM_ED25519_SEED_INDEXEDDB_REQUIRED: &str = "wasm Ed25519 signing seeds require IndexedDbSecureKeyStore with a non-extractable \
     SubtleCrypto AES-GCM wrapping key; portable WebCrypto Ed25519 signing is not used, so \
     localStorage seed read/write is disabled";

#[cfg(target_arch = "wasm32")]
const WASM_SENSITIVE_SECRET_INDEXEDDB_REQUIRED: &str = "wasm account secrets and session credentials require IndexedDbSecureKeyStore with a \
     non-extractable SubtleCrypto AES-GCM wrapping key; localStorage read/write is disabled";

/// localStorage flag that opts OUT of the wasm IndexedDB-only secure-secret
/// hardening, allowing seeds / account secrets / session credentials to live in the
/// AEAD-wrapped `localStorage` tier instead of requiring IndexedDB +
/// non-extractable SubtleCrypto.
///
/// Default OFF (hardening enforced). Intended ONLY for (a) e2e/test harnesses
/// that inject sessions into localStorage and (b) browsers without IndexedDB /
/// SubtleCrypto. SECURITY NOTE: when ON, an attacker who can read localStorage
/// (disk dump, same-origin XSS) recovers the AEAD wrapping seed alongside the
/// ciphertext — the exact disk-dump protection the IndexedDB tier adds is lost.
/// Production builds MUST leave this unset.
#[cfg(target_arch = "wasm32")]
pub(crate) const WASM_ALLOW_LOCALSTORAGE_SECRETS_FLAG: &str =
    "yougen.security.allow_localstorage_secrets";

/// `true` when [`WASM_ALLOW_LOCALSTORAGE_SECRETS_FLAG`] is set to a truthy value
/// (`1`/`true`) in `localStorage`. Reading the flag itself from localStorage is
/// safe (it carries no secret) and works even when IndexedDB/SubtleCrypto is
/// unavailable.
#[cfg(target_arch = "wasm32")]
pub(crate) fn wasm_allow_localstorage_secrets() -> bool {
    web_sys::window()
        .and_then(|window| window.local_storage().ok().flatten())
        .and_then(|storage| {
            storage
                .get_item(WASM_ALLOW_LOCALSTORAGE_SECRETS_FLAG)
                .ok()
                .flatten()
        })
        .map(|value| {
            let value = value.trim();
            value.eq_ignore_ascii_case("1") || value.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn is_wasm_ed25519_seed_key(key: &str) -> bool {
    key == SIGNING_SEED_KEY || key == WASM_LOCAL_IDENTITY_SEED_KEY
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn is_wasm_indexeddb_required_secret_key(key: &str) -> bool {
    is_wasm_ed25519_seed_key(key)
        || key == PENDING_LOGOUT_SECRET_KEY
        || key.starts_with("yougen.mls_snapshot.account_secret.")
        || key.starts_with("yougen_mls_account_secret")
        || key.starts_with("yougen.mls_key_package.identity_state.")
        || key.starts_with("coauth.session_credential.")
}

/// Keys that MUST NOT be mirrored to the transient localStorage unload-race
/// copy (see the IndexedDB store's `store_secret`): raw signing-seed material
/// that should live only in the strong IndexedDB tier. Unlike the broader
/// [`is_wasm_indexeddb_required_secret_key`] set — whose account/MLS secrets
/// are deliberately mirrored to close the YOU-02-009 unload race — these are
/// kept out of localStorage entirely.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn is_wasm_no_localstorage_mirror_key(key: &str) -> bool {
    is_wasm_ed25519_seed_key(key)
        || key == PENDING_LOGOUT_SECRET_KEY
        || key.starts_with("yougen.mls_key_package.identity_state.")
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn require_wasm_indexeddb_ed25519_seed_store(
    store: &dyn SecureKeyStore,
) -> Result<(), SecureKeyStoreError> {
    if store.backend_name() == WASM_INDEXEDDB_SECURE_KEY_STORE_BACKEND
        || wasm_allow_localstorage_secrets()
    {
        Ok(())
    } else {
        Err(SecureKeyStoreError::Unsupported(
            WASM_ED25519_SEED_INDEXEDDB_REQUIRED,
        ))
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn require_wasm_indexeddb_ed25519_seed_store(
    _store: &dyn SecureKeyStore,
) -> Result<(), SecureKeyStoreError> {
    Ok(())
}

/// AEAD-wrap a UTF-8 secret string with
/// ChaCha20-Poly1305 + a 32-byte wrapping key. Returns a base64
/// (no-pad) string with a 12-byte random nonce prefix so the same
/// secret encrypts to a different ciphertext each time. Use
/// [`unwrap_secret`] to round-trip. Both helpers are platform-
/// agnostic — they live here so the at-rest crypto used by the
/// wasm32 [`LocalStorageSecureKeyStore`] (and any future IndexedDB
/// store) is testable on native too.
pub fn wrap_secret(secret: &str, wrapping_key: &[u8; 32]) -> Result<String, SecureKeyStoreError> {
    let cipher = ChaCha20Poly1305::new(wrapping_key.into());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, secret.as_bytes())
        .map_err(|err| SecureKeyStoreError::Backend(format!("wrap_secret encrypt: {err}")))?;
    let mut packed = Vec::with_capacity(nonce.len() + ciphertext.len());
    packed.extend_from_slice(nonce.as_slice());
    packed.extend_from_slice(&ciphertext);
    Ok(STANDARD_NO_PAD.encode(&packed))
}

/// Inverse of [`wrap_secret`]. Returns
/// `Ok(None)` when the wrapped blob fails to decode / authenticate
/// (likely cause: the wrapping key has changed or the entry was
/// rolled in by a different installation).
pub fn unwrap_secret(
    wrapped_b64: &str,
    wrapping_key: &[u8; 32],
) -> Result<Option<String>, SecureKeyStoreError> {
    let packed = match STANDARD_NO_PAD.decode(wrapped_b64.as_bytes()) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    if packed.len() < 12 {
        return Ok(None);
    }
    let (nonce_bytes, ciphertext) = packed.split_at(12);
    let cipher = ChaCha20Poly1305::new(wrapping_key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    let plain = match cipher.decrypt(nonce, ciphertext) {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };
    Ok(String::from_utf8(plain).ok())
}

/// Errors a [`SecureKeyStore`] can surface.
#[derive(Debug, thiserror::Error)]
pub enum SecureKeyStoreError {
    /// The key was not present.
    #[error("secret not found")]
    NotFound,
    /// Backend reachable but refused (locked keychain, biometric
    /// cancelled, permission denied, etc.).
    #[error("secure key store backend error: {0}")]
    Backend(String),
    /// Backend not wired on this build target. Callers should fall back
    /// to a software default ([`MemorySecureKeyStore`]) and surface a
    /// "secrets stored in plaintext" warning to the user.
    #[error("secure key store backend `{0}` is not supported")]
    Unsupported(&'static str),
}

/// Pluggable string-keyed secret store. All methods take `&self` so a
/// store can be cheaply shared via `Arc<dyn SecureKeyStore>`.
///
/// Implementors MUST treat the values as opaque secrets — never log,
/// never hash with a non-cryptographic hash, never include in `Debug`
/// output. The trait is `Send + Sync` so a single store can be cloned
/// across UI surfaces.
pub trait SecureKeyStore: Send + Sync {
    /// Persist `value` under `key`. Overwrites silently when the key
    /// already exists.
    fn store_secret(&self, key: &str, value: &str) -> Result<(), SecureKeyStoreError>;

    /// Load the secret associated with `key`. Returns `Ok(None)` when
    /// the key is absent (vs `Err(NotFound)` — we collapse "not present"
    /// into the success path so callers don't have to discriminate).
    fn get_secret(&self, key: &str) -> Result<Option<String>, SecureKeyStoreError>;

    /// Remove the secret. Idempotent — deleting an absent key returns
    /// `Ok(())`.
    fn delete_secret(&self, key: &str) -> Result<(), SecureKeyStoreError>;

    /// Human-readable backend identifier (e.g. `"keyring"`,
    /// `"memory"`). Surfaced in diagnostic UI.
    fn backend_name(&self) -> &'static str;
}

/// Pick the most secure backend available at compile time.
///
/// | Target          | Backend |
/// |-----------------|---------|
/// | macOS / Linux / Windows | [`KeyringSecureKeyStore`] |
/// | Android         | [`AndroidKeystoreSecureKeyStore`] when a host bridge is installed; otherwise [`MemorySecureKeyStore`] |
/// | iOS             | [`IosKeychainSecureKeyStore`] when a host bridge is installed; otherwise [`MemorySecureKeyStore`] |
/// | wasm32          | [`LocalStorageSecureKeyStore`] for non-signing sync fallback; [`IndexedDbSecureKeyStore`] after async upgrade |
///
/// The returned trait object is `Arc`-shared so one selection can be
/// installed process-wide. **Mobile app artifacts are not shipped in
/// the local 1.0 milestone**; the Android/iOS branches remain for a
/// future host runtime and never panic when no bridge is installed.
/// They fall back to [`MemorySecureKeyStore`] with the usual "secrets
/// in plaintext heap" UX warning.
///
/// **wasm32 callers**: this returns the synchronous
/// [`LocalStorageSecureKeyStore`] fallback until async upgrade, but
/// that backend refuses Ed25519 signing seed keys. Call
/// [`upgrade_wasm_secure_key_store_async`] to promote the process
/// default to the IndexedDB + SubtleCrypto-non-extractable tier before
/// signer bootstrap.
pub fn default_secure_key_store(service_name: &str) -> Arc<dyn SecureKeyStore> {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(store) = WASM_UPGRADED_SECURE_KEY_STORE.get() {
            return match LocalStorageSecureKeyStore::new(service_name) {
                Ok(fallback) => Arc::new(FallbackSecureKeyStore::new(
                    store.clone(),
                    Arc::new(fallback),
                )),
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        "LocalStorageSecureKeyStore fallback init failed after IndexedDB upgrade"
                    );
                    store.clone()
                }
            };
        }
        // The wasm32 build persists AEAD-wrapped secrets to `localStorage`
        // rather than dropping them on a memory-only fallback. See
        // `LocalStorageSecureKeyStore` doc-comment for the wrapping-key
        // bootstrap details.
        //
        // The LocalStorage store remains the sync first-paint fallback;
        // the app upgrades to `IndexedDbSecureKeyStore` via
        // `upgrade_wasm_secure_key_store_async` once async init can run.
        // Both stores share the same `SecureKeyStore` interface. Ed25519
        // seed callers still require the IndexedDB tier explicitly.
        match LocalStorageSecureKeyStore::new(service_name) {
            Ok(store) => return Arc::new(store),
            Err(err) => {
                tracing::warn!(
                    ?err,
                    "LocalStorageSecureKeyStore init failed; falling back to in-memory store"
                );
                return Arc::new(MemorySecureKeyStore::new());
            }
        }
    }
    #[cfg(all(
        not(target_arch = "wasm32"),
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    {
        Arc::new(KeyringSecureKeyStore::new(service_name.to_owned()))
    }
    #[cfg(all(not(target_arch = "wasm32"), target_os = "android"))]
    {
        // If the host runtime has installed a HostSecretBridge, route
        // through it; otherwise fall back to MemorySecureKeyStore with the
        // documented "secrets in plaintext heap" caveat. The host typically
        // calls install_host_secret_bridge() from its JNI init before
        // mounting the Dioxus app.
        if let Some(store) = AndroidKeystoreSecureKeyStore::from_installed(service_name.to_owned())
        {
            return Arc::new(store);
        }
        tracing::warn!(
            "no HostSecretBridge registered on Android; falling back to MemorySecureKeyStore"
        );
        Arc::new(MemorySecureKeyStore::new())
    }
    #[cfg(all(not(target_arch = "wasm32"), target_os = "ios"))]
    {
        if let Some(store) = IosKeychainSecureKeyStore::from_installed(service_name.to_owned()) {
            return Arc::new(store);
        }
        tracing::warn!(
            "no HostSecretBridge registered on iOS; falling back to MemorySecureKeyStore"
        );
        Arc::new(MemorySecureKeyStore::new())
    }
    #[cfg(not(any(
        target_arch = "wasm32",
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "android",
        target_os = "ios",
    )))]
    {
        // Unknown targets land on the in-memory fallback. wasm32 is
        // handled above by `LocalStorageSecureKeyStore`.
        let _ = service_name;
        Arc::new(MemorySecureKeyStore::new())
    }
}
