//! Platform-secure secret storage.
//!
//! This module stores both per-device signing identities and arbitrary
//! short-string secrets in platform-protected storage rather than `state.json`.
//! Today's callers include:
//!
//! * coauth-issued session credential and session-grant grant-binding material.
//! * Push provider auth bundles for FCM / APNs once the host adapters land.
//!
//! ## Backends
//!
//! | Target          | Default backend         | Notes |
//! |-----------------|-------------------------|-------|
//! | macOS / Linux / Windows | [`KeyringSecureKeyStore`] | Uses the SDK-selected Keychain / Secret Service / Credential Manager backend. |
//! | wasm32          | [`LocalStorageSecureKeyStore`] for low-value first-paint secrets, then [`IndexedDbSecureKeyStore`] after async initialization | Ed25519 signing seeds, account MLS secrets, and session credentials require the IndexedDB + non-extractable SubtleCrypto tier and fail closed before initialization. |
//! | iOS / Android   | [`HostBridgeSecureKeyStore`] when the host installs a bridge; otherwise [`MemorySecureKeyStore`] | Mobile artifacts are outside the local 1.0 milestone. |
use std::sync::Arc;
#[cfg(target_arch = "wasm32")]
use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

/// The browser `localStorage` handle, mapped into the secure-store error
/// type. Every wasm fallback backend in this module funnels through the one
/// [`crate::browser_storage`] accessor so "storage unreachable" is reported
/// identically wherever it happens.
#[cfg(target_arch = "wasm32")]
fn browser_storage() -> Result<web_sys::Storage, SecureKeyStoreError> {
    crate::browser_storage::browser_storage().ok_or(SecureKeyStoreError::Unsupported(
        "window.localStorage unavailable",
    ))
}

mod fallback;
mod host_bridge;
mod identity_store;
mod indexed_db;
mod keyring;
mod local_storage;
mod platform;
mod signing_seed;

#[cfg(test)]
mod tests;

#[cfg(target_arch = "wasm32")]
use fallback::FallbackSecureKeyStore;
// F-11: the authoritative client `SecureKeyStore` trait, its error type, and the
// in-memory backend all live in garth now (the bytes-superset trait relaxed to
// `MaybeSendSync + 'static` so wasm `!Send` backends can implement it directly).
// inkson's `secure_key_store` module keeps the platform backends + seed
// governance below and surfaces the canonical garth trait through this path; the
// former parallel inkson trait / error / memory impl / `InksonSecureKeyStoreAdapter`
// are deleted.
pub use garth::{MemorySecureKeyStore, SecureKeyStore, SecureKeyStoreError};
pub use host_bridge::{
    HostBridgeSecureKeyStore, HostSecretBridge, host_secret_bridge_installed,
    install_host_secret_bridge,
};
pub use identity_store::{GlobalLocalStore, PendingLocalStore, UserLocalStore};
#[cfg(target_arch = "wasm32")]
pub(crate) use indexed_db::current_index_backend::Backend as CurrentIndexBackend;
#[cfg(target_arch = "wasm32")]
pub use indexed_db::{IndexedDbSecureKeyStore, initialize_wasm_secure_key_store_async};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub use keyring::KeyringSecureKeyStore;
#[cfg(target_arch = "wasm32")]
pub use local_storage::LocalStorageSecureKeyStore;
#[cfg(any(feature = "mobile-android", target_os = "android"))]
pub use platform::AndroidKeystoreSecureKeyStore;
#[cfg(any(feature = "mobile-ios", target_os = "ios"))]
pub use platform::IosKeychainSecureKeyStore;
#[cfg(test)]
pub(crate) use signing_seed::DeviceSeedScopeTestGuard;
pub use signing_seed::{
    ActiveDeviceSeedScope, GRANT_BINDING_SEED_KEY, SIGNING_SEED_KEY, SigningSeedMaterial,
    account_scoped_device_key, active_device_seed_scope, delete_grant_binding_seed,
    ensure_grant_binding_seed, ensure_signing_seed, load_device_id, load_grant_binding_seed,
    load_signing_seed, pending_login_device_id, reset_device_seed_scope_for_signin,
    rotate_grant_binding_seed, set_active_device_seed_scope, set_pending_login_device_id,
    store_device_id, store_grant_binding_seed, store_grant_binding_seed_b64url, store_signing_seed,
};

#[cfg(target_arch = "wasm32")]
// The garth `SecureKeyStore` trait object drops its `Send + Sync` supertrait on
// wasm (`MaybeSendSync`), but a `static OnceLock<T>` still requires `T: Sync`.
// The concrete backends we ever install here (IndexedDb via `IndexedDbSendBoundary`,
// LocalStorage over `String`/`[u8; 32]`, memory over `Arc<Mutex<…>>`) are all
// genuinely `Send + Sync`, so pin the process-global slot to the `+ Send + Sync`
// trait object; callers freely coerce it down to the bare `Arc<dyn SecureKeyStore>`.
static WASM_INDEXEDDB_SECURE_KEY_STORE: OnceLock<Arc<dyn SecureKeyStore + Send + Sync>> =
    OnceLock::new();

#[cfg(target_arch = "wasm32")]
pub(crate) const WASM_INDEXEDDB_SECURE_KEY_STORE_BACKEND: &str = "indexed_db_subtle_aes_gcm";

#[cfg(any(target_arch = "wasm32", test))]
const WASM_LOCAL_IDENTITY_SEED_KEY: &str = "identity.local.primary.v1";

/// Secure-store key for the durable hard-logout journal
/// ([`crate::pending_logout`]). The record embeds the grant-binding (DPoP)
/// seed, so it is classified as a seed-grade secret: IndexedDB-only on wasm
/// (no localStorage tier) and excluded from the unload-race localStorage
/// mirror, exactly like an Ed25519 signing seed.
pub(crate) const PENDING_LOGOUT_SECRET_KEY_PREFIX: &str = "arkret.pending_logout.v1.";

#[cfg(target_arch = "wasm32")]
const WASM_ED25519_SEED_INDEXEDDB_REQUIRED: &str = "wasm Ed25519 signing seeds require IndexedDbSecureKeyStore with a non-extractable \
     SubtleCrypto AES-GCM wrapping key; portable WebCrypto Ed25519 signing is not used, so \
     localStorage seed read/write is disabled";

#[cfg(target_arch = "wasm32")]
const WASM_SENSITIVE_SECRET_INDEXEDDB_REQUIRED: &str = "wasm account secrets and session credentials require IndexedDbSecureKeyStore with a \
     non-extractable SubtleCrypto AES-GCM wrapping key; localStorage read/write is disabled";

/// Compile-time test escape hatch for wasm fixtures that must inject the device
/// signing seed before the IndexedDB/SubtleCrypto tier is ready. Production
/// builds keep the feature disabled, and even test builds may only downgrade
/// keys accepted by [`is_wasm_test_downgrade_fixture_key`].
#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
pub(crate) const fn wasm_localstorage_secret_downgrade_enabled() -> bool {
    true
}

#[cfg(all(
    target_arch = "wasm32",
    not(feature = "wasm-localstorage-secrets-test")
))]
pub(crate) const fn wasm_localstorage_secret_downgrade_enabled() -> bool {
    false
}

/// The narrow set of IndexedDB-only keys that Cotest must inject during the
/// synchronous first-paint seam. E2EE caches, MLS account material, history
/// secrets, recovery keys, and session credentials remain IndexedDB-only even
/// when the test feature is enabled.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn is_wasm_test_downgrade_fixture_key(key: &str) -> bool {
    is_wasm_ed25519_seed_key(key)
}

/// Ensure wasm callers that need seed-grade material run on the initialized
/// IndexedDB/SubtleCrypto tier before touching signing seeds.
#[cfg(target_arch = "wasm32")]
pub async fn ensure_wasm_secure_key_store_ready(
    service_name: &str,
) -> Result<Arc<dyn SecureKeyStore>, SecureKeyStoreError> {
    if let Some(store) = WASM_INDEXEDDB_SECURE_KEY_STORE.get() {
        return Ok(store.clone());
    }
    // `Some(store)` is the `+ Send + Sync` trait object; `Ok(store)` coerces it
    // down to the bare `Arc<dyn SecureKeyStore>` return type at the argument site.
    match initialize_wasm_secure_key_store_async(service_name).await? {
        Some(store) => Ok(store),
        None => Err(SecureKeyStoreError::Unsupported(
            WASM_ED25519_SEED_INDEXEDDB_REQUIRED,
        )),
    }
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn is_wasm_ed25519_seed_key(key: &str) -> bool {
    // Typed browser stores prepend their identity namespace to the logical
    // key. Classification therefore accepts both the bare logical key used by
    // native/test backends and the scoped physical key used in the browser.
    key == SIGNING_SEED_KEY
        || key.ends_with(&format!(".{SIGNING_SEED_KEY}"))
        || key == WASM_LOCAL_IDENTITY_SEED_KEY
        || key == GRANT_BINDING_SEED_KEY
        || key.ends_with(&format!(".{GRANT_BINDING_SEED_KEY}"))
}

/// SecureKeyStore key prefix for one scope/group's device-local
/// `local_authoritative` history records. The value is the closed SDK record
/// map keyed by epoch; raw exporter material therefore remains coupled to its
/// exact durable local-state reference and winning transition tuple.
pub(crate) const MLS_HISTORY_SECRET_KEY_PREFIX: &str = "inkson.mls_history_secret.v1.";

/// Account-scoped cache for decrypted MLS application plaintext and the
/// author's private plaintext sidecar. On wasm this key is IndexedDB-only so
/// neither the plaintext nor a decryptable mirror can enter localStorage.
pub(crate) const E2EE_PLAINTEXT_CACHE_KEY_PREFIX: &str = "inkson.e2ee_plaintext_cache.v1.";

// Stable, opaque physical namespaces for an Account Authority pair and for a
// device coordinate below it. Both hash the SDK canonical form rather than
// concatenating DIDs, so a namespace cannot be ambiguous and no unbounded DID
// lands in a native filename or platform-keystore key. They belong with the
// `SecureKeyStore` port itself, which garth owns.
pub(crate) use garth::{account_id_storage_digest, device_storage_digest};

/// Per-account main `ClientLocalState` blob stored in the IndexedDB +
/// non-extractable SubtleCrypto encrypted entries store. The semantic key is
/// `inkson.local_state.v1.account.<authority_digest>`. Classifying the prefix
/// as IndexedDB-only makes the localStorage secure tier
/// refuse it — so it fails closed before the wrapping key is ready and is never
/// mirrored back to localStorage.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const ACCOUNT_LOCAL_STATE_KEY_PREFIX: &str = "inkson.local_state.v1.account.";

// The durable outbound send-queue prefix
// (`crate::outbound_store::OUTBOUND_QUEUE_KEY_PREFIX`) is classified
// IndexedDB-only for two reasons at once. A queue snapshot carries signed,
// not-yet-accepted Events, so a localStorage mirror would leave authored
// content at rest under the weaker tier; and one queue routinely exceeds the
// whole ~5 MB localStorage per-origin budget, so the mirror would also spend
// that budget against every other key on the origin.

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn is_wasm_indexeddb_required_secret_key(key: &str) -> bool {
    let scoped_prefix = |logical_prefix: &str| {
        key.starts_with(logical_prefix) || key.contains(&format!(".{logical_prefix}"))
    };
    is_wasm_ed25519_seed_key(key)
        || key.starts_with(PENDING_LOGOUT_SECRET_KEY_PREFIX)
        || key.contains(&format!(".{PENDING_LOGOUT_SECRET_KEY_PREFIX}"))
        || scoped_prefix(crate::identity::account_auth::ACCOUNT_HANDOFF_GRANT_SECRET_KEY_PREFIX)
        || scoped_prefix(crate::transport::CONTACT_PENDING_COMMIT_SECRET_KEY)
        || scoped_prefix(
            crate::identity::account_auth::PREPARED_IDENTITY_CREATION_REQUEST_SECRET_KEY_PREFIX,
        )
        || scoped_prefix(
            crate::identity::account_auth::PENDING_IDENTITY_CREATION_RECOVERY_KEY_PREFIX,
        )
        || key.starts_with("inkson.mls_snapshot.account_secret.")
        || key.starts_with("inkson_mls_account_secret")
        || key.starts_with("inkson.mls_key_package.identity_state.")
        || key.starts_with("inkson.mls_key_package.consume_request.")
        || key.starts_with("coauth.session_credential.")
        || key == "auth.dpop.device_key.v1"
        || key.ends_with(".auth.dpop.device_key.v1")
        || key == "auth.session_grant.v1"
        || key.ends_with(".auth.session_grant.v1")
        || key.starts_with("inkson.device_hpke_x25519.private.")
        || key.starts_with("inkson.history_request_hpke_x25519.private.")
        || key.starts_with(MLS_HISTORY_SECRET_KEY_PREFIX)
        || key.starts_with("arkret/history-candidate/v1/")
        || key.starts_with("arkret/history-response-capability/v1/")
        || key.starts_with("arkret/history-source-outbox/v1/")
        || key.starts_with(E2EE_PLAINTEXT_CACHE_KEY_PREFIX)
        || key.starts_with(ACCOUNT_LOCAL_STATE_KEY_PREFIX)
        || key.starts_with(crate::outbound_store::OUTBOUND_QUEUE_KEY_PREFIX)
}

pub(crate) fn e2ee_plaintext_cache_store_key(authority_namespace: &str) -> String {
    format!(
        "{E2EE_PLAINTEXT_CACHE_KEY_PREFIX}{}",
        STANDARD_NO_PAD.encode(authority_namespace.as_bytes())
    )
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn require_wasm_indexeddb_ed25519_seed_store(
    store: &dyn SecureKeyStore,
) -> Result<(), SecureKeyStoreError> {
    if store.backend_name() == WASM_INDEXEDDB_SECURE_KEY_STORE_BACKEND
        || wasm_localstorage_secret_downgrade_enabled()
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
    let mut nonce_bytes = [0_u8; 12];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|err| SecureKeyStoreError::Backend(format!("wrap_secret RNG: {err}")))?;
    let nonce = Nonce::from(nonce_bytes);
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
    // `split_at(12)` already fixed the prefix length, so a rejection here can
    // only mean the crate's nonce width changed; treat it as unreadable material
    // rather than panicking inside a decode path that is total by contract.
    let Ok(nonce) = Nonce::try_from(nonce_bytes) else {
        return Ok(None);
    };
    let plain = match cipher.decrypt(&nonce, ciphertext) {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };
    Ok(String::from_utf8(plain).ok())
}

/// Pick the most secure backend available at compile time.
///
/// | Target          | Backend |
/// |-----------------|---------|
/// | macOS / Linux / Windows | [`KeyringSecureKeyStore`] (SDK platform backend) |
/// | Android         | [`AndroidKeystoreSecureKeyStore`] when a host bridge is installed; otherwise [`MemorySecureKeyStore`] |
/// | iOS             | [`IosKeychainSecureKeyStore`] when a host bridge is installed; otherwise [`MemorySecureKeyStore`] |
/// | wasm32          | [`LocalStorageSecureKeyStore`] for non-signing sync fallback; [`IndexedDbSecureKeyStore`] after async initialization |
///
/// The returned trait object is `Arc`-shared so one selection can be
/// installed process-wide. **Mobile app artifacts are not shipped in
/// the local 1.0 milestone**; the Android/iOS branches remain for a
/// future host runtime and never panic when no bridge is installed.
/// They fall back to [`MemorySecureKeyStore`] with the usual "secrets
/// in plaintext heap" UX warning.
///
/// **wasm32 callers**: this returns the synchronous
/// [`LocalStorageSecureKeyStore`] fallback until async initialization, but
/// that backend refuses Ed25519 signing seed keys. Call
/// [`initialize_wasm_secure_key_store_async`] to initialize the process
/// default to the IndexedDB + SubtleCrypto-non-extractable tier before
/// signer bootstrap.
pub fn default_secure_key_store(service_name: &str) -> Arc<dyn SecureKeyStore + Send + Sync> {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(store) = WASM_INDEXEDDB_SECURE_KEY_STORE.get() {
            return match LocalStorageSecureKeyStore::new(service_name) {
                Ok(fallback) => Arc::new(FallbackSecureKeyStore::new(
                    store.clone(),
                    Arc::new(fallback),
                )),
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        "LocalStorageSecureKeyStore fallback init failed after IndexedDB initialization"
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
        // the app initializes `IndexedDbSecureKeyStore` via
        // `initialize_wasm_secure_key_store_async` once async init can run.
        // Both stores share the same `SecureKeyStore` interface. Ed25519
        // seed callers still require the IndexedDB tier explicitly.
        match LocalStorageSecureKeyStore::new(service_name) {
            Ok(store) => Arc::new(store),
            Err(err) => {
                tracing::warn!(
                    ?err,
                    "LocalStorageSecureKeyStore init failed; falling back to in-memory store"
                );
                Arc::new(MemorySecureKeyStore::new())
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
