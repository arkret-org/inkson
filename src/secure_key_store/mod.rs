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
use chacha20poly1305::aead::{Aead, OsRng};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit, Nonce};

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
pub(crate) use signing_seed::{
    DeviceSeedScopeTestGuard, account_scoped_device_key_for, load_signing_seed_scoped,
    store_signing_seed_scoped,
};
pub use signing_seed::{
    GRANT_BINDING_SEED_KEY, SIGNING_SEED_KEY, SigningSeedMaterial, account_scoped_device_key,
    active_device_seed_scope, delete_grant_binding_seed, ensure_grant_binding_seed,
    ensure_signing_seed, load_device_id, load_grant_binding_seed, load_signing_seed,
    pending_login_device_id, reset_device_seed_scope_for_signin, rotate_grant_binding_seed,
    set_active_device_seed_scope, set_pending_login_device_id, store_device_id,
    store_grant_binding_seed, store_grant_binding_seed_b64url, store_signing_seed,
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
pub(crate) const PENDING_LOGOUT_SECRET_KEY: &str = "arkret.pending_logout.v1";

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

/// SecureKeyStore key prefix for per-realm aggregated MLS `history_secret`s
/// (E2EE-at-rest hardening spec T1). The value is JSON
/// `{ "<epoch>": "<base64url(secret)>" }` and the full key is
/// `inkson.mls_history_secret.v1.<base64(realm_id)>`. This is raw exporter key
/// material — it MUST live only in the IndexedDB + non-extractable SubtleCrypto
/// tier (same protection level as the account MLS secret).
pub(crate) const MLS_HISTORY_SECRET_KEY_PREFIX: &str = "inkson.mls_history_secret.v1.";

/// Account-scoped cache for decrypted MLS application plaintext and the
/// author's private plaintext sidecar. On wasm this key is IndexedDB-only so
/// neither the plaintext nor a decryptable mirror can enter localStorage.
pub(crate) const E2EE_PLAINTEXT_CACHE_KEY_PREFIX: &str = "inkson.e2ee_plaintext_cache.v1.";

/// Per-account main `ClientLocalState` blob. Historically this lived in
/// near-plaintext `localStorage`; phase 2 of the E2EE-local-state work moved it
/// into the IndexedDB + non-extractable SubtleCrypto encrypted entries store.
/// The semantic key is `inkson.local_state.v1.account.<core_id>`; v1 data is
/// intentionally ignored rather than migrated or read through compatibility
/// fallbacks. Classifying the prefix as IndexedDB-only makes the localStorage secure tier
/// refuse it — so it fails closed before the wrapping key is ready and is never
/// mirrored back to localStorage.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const ACCOUNT_LOCAL_STATE_KEY_PREFIX: &str = "inkson.local_state.v1.account.";

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn is_wasm_indexeddb_required_secret_key(key: &str) -> bool {
    let scoped_prefix = |logical_prefix: &str| {
        key.starts_with(logical_prefix) || key.contains(&format!(".{logical_prefix}"))
    };
    is_wasm_ed25519_seed_key(key)
        || key == PENDING_LOGOUT_SECRET_KEY
        || key.ends_with(&format!(".{PENDING_LOGOUT_SECRET_KEY}"))
        || scoped_prefix(crate::identity::account_auth::ACCOUNT_HANDOFF_GRANT_SECRET_KEY_PREFIX)
        || scoped_prefix(
            crate::identity::account_auth::PREPARED_IDENTITY_CREATION_REQUEST_SECRET_KEY_PREFIX,
        )
        || scoped_prefix(
            crate::identity::account_auth::PENDING_IDENTITY_CREATION_RECOVERY_KEY_PREFIX,
        )
        || key.starts_with("inkson.mls_snapshot.account_secret.")
        || key.starts_with("inkson_mls_account_secret")
        || key.starts_with("inkson.mls_key_package.identity_state.")
        || key.starts_with("coauth.session_credential.")
        || key == "auth.dpop.device_key.v1"
        || key.ends_with(".auth.dpop.device_key.v1")
        || key == "auth.session_grant.v1"
        || key.ends_with(".auth.session_grant.v1")
        || key.starts_with("inkson.device_hpke_x25519.private.")
        || key.starts_with(MLS_HISTORY_SECRET_KEY_PREFIX)
        || key.starts_with("arkret/history-candidate/v1/")
        || key.starts_with("arkret/history-response-capability/v1/")
        || key.starts_with(E2EE_PLAINTEXT_CACHE_KEY_PREFIX)
        || key.starts_with(ACCOUNT_LOCAL_STATE_KEY_PREFIX)
}

pub(crate) fn e2ee_plaintext_cache_store_key(account_did: &str) -> String {
    format!(
        "{E2EE_PLAINTEXT_CACHE_KEY_PREFIX}{}",
        STANDARD_NO_PAD.encode(account_did.trim().as_bytes())
    )
}

/// E2EE-at-rest T1 — SecureKeyStore key for one exact scope/group's aggregated
/// MLS `history_secret`s. The canonical scope/group key is base64-encoded (no
/// pad) so it is a stable, character-safe suffix.
pub(crate) fn mls_history_secret_store_key(scope_group_key: &str) -> String {
    format!(
        "{MLS_HISTORY_SECRET_KEY_PREFIX}{}",
        STANDARD_NO_PAD.encode(scope_group_key.trim().as_bytes())
    )
}

/// E2EE-at-rest T1 — encode a per-realm `epoch -> secret` map to the stored
/// JSON shape `{ "<epoch>": "<base64url(secret)>" }`. `u64` epoch keys are
/// emitted as decimal strings so the map round-trips through `serde_json`
/// (which rejects non-string map keys).
pub(crate) fn encode_history_secrets_json(
    by_epoch: &std::collections::BTreeMap<u64, Vec<u8>>,
) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let map: std::collections::BTreeMap<String, String> = by_epoch
        .iter()
        .map(|(epoch, secret)| (epoch.to_string(), URL_SAFE_NO_PAD.encode(secret)))
        .collect();
    serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_owned())
}

/// E2EE-at-rest T1 — inverse of [`encode_history_secrets_json`]. Malformed
/// entries (unparseable epoch or base64) are dropped rather than failing the
/// whole decode, so a single bad entry cannot shadow the rest.
pub(crate) fn decode_history_secrets_json(json: &str) -> std::collections::BTreeMap<u64, Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let map: std::collections::BTreeMap<String, String> =
        serde_json::from_str(json).unwrap_or_default();
    map.into_iter()
        .filter_map(|(epoch, b64)| {
            let epoch = epoch.parse::<u64>().ok()?;
            let secret = URL_SAFE_NO_PAD.decode(b64.as_bytes()).ok()?;
            Some((epoch, secret))
        })
        .collect()
}

/// True once the wasm IndexedDB + SubtleCrypto tier has
/// completed. History-secret reads/writes fail closed before this so raw key
/// material never lands in the weaker localStorage tier.
#[cfg(target_arch = "wasm32")]
pub(crate) fn wasm_secure_store_ready() -> bool {
    WASM_INDEXEDDB_SECURE_KEY_STORE.get().is_some()
}

/// E2EE-at-rest T1 — load an exact scope/group's aggregated `history_secret`s from the
/// hardened SecureKeyStore. Returns `None` before IndexedDB initialization (fail
/// closed) so callers fall back to any transitional inline copy; returns
/// `Some(empty)` when upgraded but no secrets are stored for the realm.
pub(crate) fn load_history_secrets(
    scope_group_key: &str,
) -> Option<std::collections::BTreeMap<u64, Vec<u8>>> {
    #[cfg(target_arch = "wasm32")]
    if !wasm_secure_store_ready() {
        return None;
    }
    let store = default_secure_key_store("inkson");
    let key = mls_history_secret_store_key(scope_group_key);
    match store.get_secret(&key) {
        Ok(Some(json)) => Some(decode_history_secrets_json(&json)),
        Ok(None) => Some(std::collections::BTreeMap::new()),
        Err(error) => {
            tracing::warn!(?error, "history secret read from secure store failed");
            None
        }
    }
}

/// E2EE-at-rest T1 — durably persist an exact scope/group's aggregated
/// `history_secret`s to
/// the hardened SecureKeyStore tier. Callers must not publish dependent state
/// before this future succeeds.
pub(crate) async fn persist_history_secrets(
    store: &dyn SecureKeyStore,
    scope_group_key: &str,
    by_epoch: &std::collections::BTreeMap<u64, Vec<u8>>,
) -> Result<(), SecureKeyStoreError> {
    #[cfg(target_arch = "wasm32")]
    if !wasm_secure_store_ready() {
        return Err(SecureKeyStoreError::Unsupported(
            "history secrets require the initialized IndexedDB secure store",
        ));
    }
    let key = mls_history_secret_store_key(scope_group_key);
    store
        .store_secret_durable(&key, &encode_history_secrets_json(by_epoch))
        .await
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
