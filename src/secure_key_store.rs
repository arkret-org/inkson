//! Platform-secure secret storage.
//!
//! `crate::key_store` already abstracts the per-device *signing* identity
//! (ed25519 seed → did:key). This module covers the orthogonal axis:
//! arbitrary short-string secrets that should land in the OS keychain
//! rather than `state.json`. Today's callers:
//!
//! * OIDC `refresh_token` (currently persisted plaintext in
//!   [`crate::local_state::OidcTokenBundle`]).
//! * coauth-issued session grant (short-lived but useful between
//!   `register_device` retries).
//! * Push provider auth bundles for FCM / APNs once the host adapters
//!   land.
//!
//! ## Backends
//!
//! | Target          | Default backend         | Notes |
//! |-----------------|-------------------------|-------|
//! | macOS / Linux / Windows | [`KeyringSecureKeyStore`] | Uses the `keyring` crate (Keychain / Secret Service / Credential Manager). |
//! | wasm32          | [`MemorySecureKeyStore`] | Browser has no symmetric secret store yet — fall back to in-memory + TODO for IndexedDB-backed encryption. |
//! | iOS / Android   | [`MemorySecureKeyStore`] | Mobile FFI lands next round (planned: Android Keystore + iOS Keychain). |
//!
//! ## Why not reuse `crate::key_store::KeyStore`?
//!
//! `KeyStore` is typed for `LocalIdentityRecord` (seed bytes + did:key
//! cache). [`SecureKeyStore`] is a string KV — it deliberately has no
//! schema so callers don't have to extend a typed enum each time a new
//! secret category appears.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, OsRng},
};

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
#[derive(Debug)]
pub enum SecureKeyStoreError {
    /// The key was not present.
    NotFound,
    /// Backend reachable but refused (locked keychain, biometric
    /// cancelled, permission denied, etc.).
    Backend(String),
    /// Backend not wired on this build target. Callers should fall back
    /// to a software default ([`MemorySecureKeyStore`]) and surface a
    /// "secrets stored in plaintext" warning to the user.
    Unsupported(&'static str),
}

impl std::fmt::Display for SecureKeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "secret not found"),
            Self::Backend(msg) => write!(f, "secure key store backend error: {msg}"),
            Self::Unsupported(name) => {
                write!(f, "secure key store backend `{name}` is not supported")
            }
        }
    }
}

impl std::error::Error for SecureKeyStoreError {}

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

/// In-memory fallback store. Wraps an `Arc<Mutex<HashMap>>` so clones
/// share state. Used on wasm32 and as the mobile fallback until the
/// FFI keystores land. Also useful for tests that don't want to
/// touch the real OS keychain.
///
/// **WARNING**: this store keeps secrets in plaintext in the process
/// heap. Production callers should prefer [`KeyringSecureKeyStore`]
/// and only fall back to this when the platform backend is
/// [`SecureKeyStoreError::Unsupported`].
#[derive(Clone, Default)]
pub struct MemorySecureKeyStore {
    inner: Arc<Mutex<HashMap<String, String>>>,
}

impl MemorySecureKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Total entries currently held — only useful for diagnostics /
    /// tests. Production code should never iterate the store contents.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|guard| guard.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::fmt::Debug for MemorySecureKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEVER include the values themselves.
        f.debug_struct("MemorySecureKeyStore")
            .field("entries", &self.len())
            .finish()
    }
}

impl SecureKeyStore for MemorySecureKeyStore {
    fn store_secret(&self, key: &str, value: &str) -> Result<(), SecureKeyStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|err| SecureKeyStoreError::Backend(format!("lock poisoned: {err}")))?;
        guard.insert(key.to_owned(), value.to_owned());
        Ok(())
    }

    fn get_secret(&self, key: &str) -> Result<Option<String>, SecureKeyStoreError> {
        let guard = self
            .inner
            .lock()
            .map_err(|err| SecureKeyStoreError::Backend(format!("lock poisoned: {err}")))?;
        Ok(guard.get(key).cloned())
    }

    fn delete_secret(&self, key: &str) -> Result<(), SecureKeyStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|err| SecureKeyStoreError::Backend(format!("lock poisoned: {err}")))?;
        guard.remove(key);
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "memory"
    }
}

/// Desktop OS-keychain backend. Uses the `keyring` crate which routes
/// to:
///
/// * **macOS** — Security framework Keychain Services.
/// * **Linux** — freedesktop Secret Service (`libsecret` / GNOME
///   Keyring / KWallet).
/// * **Windows** — Windows Credential Manager (`wincred`).
///
/// The store is keyed by a constant `service_name` (typically
/// `"yougen"` or `"yougen.test"`) plus the per-secret `key` as the
/// "username" slot. That two-level naming matches `cmdkey /list`,
/// `Keychain Access.app`, and `seahorse` UX.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows",))]
#[derive(Clone, Debug)]
pub struct KeyringSecureKeyStore {
    service_name: String,
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows",))]
impl KeyringSecureKeyStore {
    /// Construct a store whose entries land under
    /// `service_name`. Conventional value: `"yougen"`.
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }

    /// Service name passed to the `keyring` crate. Returned for
    /// diagnostic UI / test introspection.
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    fn entry(&self, key: &str) -> Result<keyring::Entry, SecureKeyStoreError> {
        keyring::Entry::new(&self.service_name, key)
            .map_err(|err| SecureKeyStoreError::Backend(format!("entry init: {err}")))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows",))]
impl SecureKeyStore for KeyringSecureKeyStore {
    fn store_secret(&self, key: &str, value: &str) -> Result<(), SecureKeyStoreError> {
        let entry = self.entry(key)?;
        entry
            .set_password(value)
            .map_err(|err| SecureKeyStoreError::Backend(format!("set_password: {err}")))
    }

    fn get_secret(&self, key: &str) -> Result<Option<String>, SecureKeyStoreError> {
        let entry = self.entry(key)?;
        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(SecureKeyStoreError::Backend(format!("get_password: {err}"))),
        }
    }

    fn delete_secret(&self, key: &str) -> Result<(), SecureKeyStoreError> {
        let entry = self.entry(key)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(SecureKeyStoreError::Backend(format!(
                "delete_credential: {err}"
            ))),
        }
    }

    fn backend_name(&self) -> &'static str {
        "keyring"
    }
}

/// Mobile **host-bridge** delegation pattern for
/// Android Keystore + iOS Keychain access.
///
/// The mobile-platform FFI surface (JNI on Android,
/// `Security.framework` on iOS) cannot be cleanly initialised from
/// inside yougen alone — the Android Keystore path needs a `JNIEnv`
/// that's only valid on the current Java thread, and iOS Keychain
/// access against `kSecClassGenericPassword` needs Objective-C
/// runtime + an app-level entitlement. Both of those are owned by
/// the host runtime (Dioxus mobile + the platform-native shell that
/// embeds it).
///
/// We solve this by inverting the relationship: instead of yougen
/// linking against a mobile FFI crate, yougen exposes a
/// [`HostSecretBridge`] trait that the host implements and registers
/// via [`install_host_secret_bridge`]. When
/// [`default_secure_key_store`] runs on `target_os = "android"` or
/// `"ios"`, it constructs a [`HostBridgeSecureKeyStore`] that delegates
/// every store/get/delete through the installed bridge. The bridge
/// implementation lives in the host runtime where it has access to
/// `JNIEnv` / Security.framework.
///
/// Hosts that don't install a bridge get
/// [`MemorySecureKeyStore`] as the fallback (matches existing
/// "secrets in plaintext heap" caveat), so the API is forwards-
/// safe by default: a binary that never wires a bridge keeps working,
/// it just loses the OS-keychain tier.
///
/// The host implementation contract:
///
/// * **Android** — bridge methods call into a Java class
///   (`com.contrix.yougen.SecureKeyStoreBridge` or similar) via JNI.
///   That class proxies to `java.security.KeyStore` with provider
///   `"AndroidKeyStore"`, aliasing entries as
///   `"<service_name>:<key>"`. AES-256-GCM is the recommended
///   cipher; the platform Keystore can be configured to require
///   user authentication / biometrics before the key is unsealed.
/// * **iOS** — bridge methods call into Objective-C / Swift code
///   that invokes `SecItemAdd`, `SecItemCopyMatching`, and
///   `SecItemDelete` against `kSecClassGenericPassword` keychain
///   items. `kSecAttrService` is set to `service_name`,
///   `kSecAttrAccount` is set to the entry key. `kSecAttrAccessible`
///   defaults to `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
///   so secrets do NOT propagate through iCloud Keychain.
///
/// Both bridges MUST be safe to call from arbitrary threads
/// (the trait demands `Send + Sync`). On Android that means each
/// call attaches the current thread to the JavaVM before issuing
/// JNI calls; on iOS Keychain Services is already thread-safe.
pub trait HostSecretBridge: Send + Sync {
    /// Persist `value` under `(service_name, key)` in the platform
    /// secure store. Overwrites silently when the alias already
    /// exists.
    fn put(&self, service_name: &str, key: &str, value: &str) -> Result<(), SecureKeyStoreError>;

    /// Load the secret under `(service_name, key)`. Returns `Ok(None)`
    /// when the alias is absent.
    fn get(&self, service_name: &str, key: &str) -> Result<Option<String>, SecureKeyStoreError>;

    /// Remove the secret. Idempotent — deleting an absent alias
    /// returns `Ok(())`.
    fn delete(&self, service_name: &str, key: &str) -> Result<(), SecureKeyStoreError>;

    /// Optional human-readable label surfaced via
    /// [`SecureKeyStore::backend_name`]. Default is
    /// `"host-bridge"`; hosts override to e.g. `"android-keystore"`
    /// or `"ios-keychain"` so diagnostic UI can distinguish them.
    fn backend_label(&self) -> &'static str {
        "host-bridge"
    }
}

static HOST_SECRET_BRIDGE: std::sync::OnceLock<Arc<dyn HostSecretBridge>> =
    std::sync::OnceLock::new();

/// Register a [`HostSecretBridge`] implementation. Idempotent — the
/// first call wins; subsequent calls are no-ops and return `false`.
/// Hosts MUST call this **before** any secure-store consumer runs
/// (typically in the platform glue's `init()` hook before mounting
/// the Dioxus app).
///
/// Returns `true` on first install, `false` if a bridge was already
/// registered. The "first-write-wins" semantics match how the
/// Android `JavaVM` reference works: there is exactly one host
/// runtime per process, and re-registering would race against
/// in-flight secret reads.
pub fn install_host_secret_bridge(bridge: Arc<dyn HostSecretBridge>) -> bool {
    HOST_SECRET_BRIDGE.set(bridge).is_ok()
}

/// Test/diagnostic helper: did the host install a secret bridge?
pub fn host_secret_bridge_installed() -> bool {
    HOST_SECRET_BRIDGE.get().is_some()
}

/// [`SecureKeyStore`] implementation that delegates every operation
/// through the installed [`HostSecretBridge`]. Constructed by
/// [`default_secure_key_store`] on `target_os = "android"` and
/// `"ios"` when a bridge is registered; falls back to
/// [`MemorySecureKeyStore`] otherwise.
#[derive(Clone)]
pub struct HostBridgeSecureKeyStore {
    service_name: String,
    bridge: Arc<dyn HostSecretBridge>,
}

impl HostBridgeSecureKeyStore {
    /// Build a store that funnels calls through the supplied bridge.
    /// Use [`HostBridgeSecureKeyStore::from_installed`] when the
    /// bridge has been registered via
    /// [`install_host_secret_bridge`].
    pub fn new(service_name: impl Into<String>, bridge: Arc<dyn HostSecretBridge>) -> Self {
        Self {
            service_name: service_name.into(),
            bridge,
        }
    }

    /// Build a store backed by the currently-installed host bridge.
    /// Returns `None` when no bridge has been registered yet.
    pub fn from_installed(service_name: impl Into<String>) -> Option<Self> {
        let bridge = HOST_SECRET_BRIDGE.get()?.clone();
        Some(Self {
            service_name: service_name.into(),
            bridge,
        })
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }
}

impl std::fmt::Debug for HostBridgeSecureKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostBridgeSecureKeyStore")
            .field("service_name", &self.service_name)
            .field("bridge", &self.bridge.backend_label())
            .finish()
    }
}

impl SecureKeyStore for HostBridgeSecureKeyStore {
    fn store_secret(&self, key: &str, value: &str) -> Result<(), SecureKeyStoreError> {
        self.bridge.put(&self.service_name, key, value)
    }

    fn get_secret(&self, key: &str) -> Result<Option<String>, SecureKeyStoreError> {
        self.bridge.get(&self.service_name, key)
    }

    fn delete_secret(&self, key: &str) -> Result<(), SecureKeyStoreError> {
        self.bridge.delete(&self.service_name, key)
    }

    fn backend_name(&self) -> &'static str {
        self.bridge.backend_label()
    }
}

/// Android Keystore-backed secret store. On `target_os = "android"`
/// this is a thin wrapper around [`HostBridgeSecureKeyStore`] — the
/// real FFI work happens in the host runtime's
/// [`HostSecretBridge`] implementation (typically a JNI shim against
/// `java.security.KeyStore` with provider `"AndroidKeyStore"`).
///
/// See the [`HostSecretBridge`] doc-comment for the full contract.
#[cfg(target_os = "android")]
#[derive(Clone, Debug)]
pub struct AndroidKeystoreSecureKeyStore {
    inner: HostBridgeSecureKeyStore,
}

#[cfg(target_os = "android")]
impl AndroidKeystoreSecureKeyStore {
    /// Construct a store delegating to the installed
    /// [`HostSecretBridge`]. Returns `None` when no bridge has been
    /// registered; callers should fall back to
    /// [`MemorySecureKeyStore`] in that case.
    pub fn from_installed(service_name: impl Into<String>) -> Option<Self> {
        HostBridgeSecureKeyStore::from_installed(service_name).map(|inner| Self { inner })
    }

    /// Construct against an explicit bridge — used by tests and by
    /// hosts that prefer dependency injection over the global
    /// registry.
    pub fn new_with_bridge(
        service_name: impl Into<String>,
        bridge: Arc<dyn HostSecretBridge>,
    ) -> Self {
        Self {
            inner: HostBridgeSecureKeyStore::new(service_name, bridge),
        }
    }

    pub fn service_name(&self) -> &str {
        self.inner.service_name()
    }
}

#[cfg(target_os = "android")]
impl SecureKeyStore for AndroidKeystoreSecureKeyStore {
    fn store_secret(&self, key: &str, value: &str) -> Result<(), SecureKeyStoreError> {
        self.inner.store_secret(key, value)
    }
    fn get_secret(&self, key: &str) -> Result<Option<String>, SecureKeyStoreError> {
        self.inner.get_secret(key)
    }
    fn delete_secret(&self, key: &str) -> Result<(), SecureKeyStoreError> {
        self.inner.delete_secret(key)
    }
    fn backend_name(&self) -> &'static str {
        "android-keystore"
    }
}

/// iOS Keychain-backed secret store. On `target_os = "ios"` this is
/// a thin wrapper around [`HostBridgeSecureKeyStore`] — the real FFI
/// work happens in the host runtime's [`HostSecretBridge`]
/// implementation (typically an Objective-C / Swift shim against
/// `Security.framework` `SecItemAdd` / `SecItemCopyMatching` /
/// `SecItemDelete`).
///
/// See the [`HostSecretBridge`] doc-comment for the full contract.
#[cfg(target_os = "ios")]
#[derive(Clone, Debug)]
pub struct IosKeychainSecureKeyStore {
    inner: HostBridgeSecureKeyStore,
}

#[cfg(target_os = "ios")]
impl IosKeychainSecureKeyStore {
    pub fn from_installed(service_name: impl Into<String>) -> Option<Self> {
        HostBridgeSecureKeyStore::from_installed(service_name).map(|inner| Self { inner })
    }

    pub fn new_with_bridge(
        service_name: impl Into<String>,
        bridge: Arc<dyn HostSecretBridge>,
    ) -> Self {
        Self {
            inner: HostBridgeSecureKeyStore::new(service_name, bridge),
        }
    }

    pub fn service_name(&self) -> &str {
        self.inner.service_name()
    }
}

#[cfg(target_os = "ios")]
impl SecureKeyStore for IosKeychainSecureKeyStore {
    fn store_secret(&self, key: &str, value: &str) -> Result<(), SecureKeyStoreError> {
        self.inner.store_secret(key, value)
    }
    fn get_secret(&self, key: &str) -> Result<Option<String>, SecureKeyStoreError> {
        self.inner.get_secret(key)
    }
    fn delete_secret(&self, key: &str) -> Result<(), SecureKeyStoreError> {
        self.inner.delete_secret(key)
    }
    fn backend_name(&self) -> &'static str {
        "ios-keychain"
    }
}

/// Pick the most secure backend available at compile time.
///
/// | Target          | Backend |
/// |-----------------|---------|
/// | macOS / Linux / Windows | [`KeyringSecureKeyStore`] |
/// | Android         | [`AndroidKeystoreSecureKeyStore`] (C34.1 stub — calls panic until JNI lands) |
/// | iOS             | [`IosKeychainSecureKeyStore`] (C34.1 stub — calls panic until Security.framework lands) |
/// | wasm32          | [`MemorySecureKeyStore`] (no symmetric secret store available in the browser) |
///
/// The returned trait object is `Arc`-shared so one selection can be
/// installed process-wide. **Mobile callers** should treat the
/// returned store as compile-time-stable but runtime-unimplemented
/// until the FFI shim lands — either gate the call site behind a
/// runtime feature flag, or substitute [`MemorySecureKeyStore`]
/// explicitly with the usual "secrets in plaintext heap" UX warning.
///
/// **wasm32 callers**: this returns the synchronous fallback
/// [`LocalStorageSecureKeyStore`] for first-paint usability. Once the
/// app reaches an async-capable boot phase, call
/// [`upgrade_wasm_secure_key_store_async`] to promote the store to
/// the IndexedDB + SubtleCrypto-non-extractable tier (H6).
pub fn default_secure_key_store(service_name: &str) -> Arc<dyn SecureKeyStore> {
    #[cfg(target_arch = "wasm32")]
    {
        // The wasm32 build persists AEAD-wrapped secrets to `localStorage`
        // rather than dropping them on a memory-only fallback. See
        // `LocalStorageSecureKeyStore` doc-comment for the wrapping-key
        // bootstrap details.
        //
        // The LocalStorage store remains the sync first-paint fallback;
        // the app upgrades to `IndexedDbSecureKeyStore` via
        // `upgrade_wasm_secure_key_store_async` once async init can run.
        // Both stores share the same `SecureKeyStore` interface so callers
        // don't care which tier they got.
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
/// A future IndexedDB + `crypto.subtle.deriveKey` upgrade can swap
/// the wrapping-key bootstrap without changing the on-disk format
/// because the storage key namespace stays
/// `yougen.secret.<service_name>.<key>`. Until then this is the best
/// the browser tier can offer without an OS keychain.
#[cfg(target_arch = "wasm32")]
pub struct LocalStorageSecureKeyStore {
    service_name: String,
    wrapping_key: [u8; 32],
}

#[cfg(target_arch = "wasm32")]
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

    // Module-scope visibility so `migrate_localstorage_entries_to_indexeddb`
    // can reuse the same getter without re-implementing the window /
    // Storage probe.
    pub(super) fn storage() -> Result<web_sys::Storage, SecureKeyStoreError> {
        let window = web_sys::window().ok_or_else(|| {
            SecureKeyStoreError::Unsupported("web_sys::window unavailable (non-browser host)")
        })?;
        window
            .local_storage()
            .map_err(|err| SecureKeyStoreError::Backend(format!("localStorage: {err:?}")))?
            .ok_or_else(|| SecureKeyStoreError::Unsupported("window.localStorage not available"))
    }

    pub(super) fn wrapping_seed_key(service_name: &str) -> String {
        format!(
            "yougen.secret.{service_name}{}",
            Self::WRAPPING_KEY_STORAGE_KEY_SUFFIX
        )
    }

    fn entry_key(&self, key: &str) -> String {
        format!("yougen.secret.{}.{key}", self.service_name)
    }
}

#[cfg(target_arch = "wasm32")]
impl std::fmt::Debug for LocalStorageSecureKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalStorageSecureKeyStore")
            .field("service_name", &self.service_name)
            .field("wrapping_key", &"<redacted>")
            .finish()
    }
}

#[cfg(target_arch = "wasm32")]
impl SecureKeyStore for LocalStorageSecureKeyStore {
    fn store_secret(&self, key: &str, value: &str) -> Result<(), SecureKeyStoreError> {
        let storage = Self::storage()?;
        let wrapped = wrap_secret(value, &self.wrapping_key)?;
        storage
            .set_item(&self.entry_key(key), &wrapped)
            .map_err(|err| SecureKeyStoreError::Backend(format!("localStorage set: {err:?}")))
    }

    fn get_secret(&self, key: &str) -> Result<Option<String>, SecureKeyStoreError> {
        let storage = Self::storage()?;
        let Some(wrapped) = storage
            .get_item(&self.entry_key(key))
            .map_err(|err| SecureKeyStoreError::Backend(format!("localStorage get: {err:?}")))?
        else {
            return Ok(None);
        };
        unwrap_secret(&wrapped, &self.wrapping_key)
    }

    fn delete_secret(&self, key: &str) -> Result<(), SecureKeyStoreError> {
        let storage = Self::storage()?;
        storage
            .remove_item(&self.entry_key(key))
            .map_err(|err| SecureKeyStoreError::Backend(format!("localStorage remove: {err:?}")))
    }

    fn backend_name(&self) -> &'static str {
        "local_storage_aead"
    }
}

/// wasm32 IndexedDB-backed secret store that upgrades the wrapping-key
/// tier from the `localStorage` byte seed to a SubtleCrypto-derived
/// **non-extractable** AES-GCM key.
///
/// ## Threat model improvement over [`LocalStorageSecureKeyStore`]
///
/// LocalStorageSecureKeyStore (H2) keeps both the wrapping seed (32
/// random bytes) AND every wrapped secret in `localStorage` under the
/// same origin. An attacker who can read the localStorage blob — via
/// a backup dump, a misconfigured browser extension, a developer-tools
/// clipboard, or a same-origin XSS — gets the seed alongside the
/// ciphertext and decrypts everything offline.
///
/// IndexedDbSecureKeyStore (H6) splits the layers:
///
///   1. The wrapping key is derived once via `SubtleCrypto.deriveKey`
///      with `extractable: false`. The derived `CryptoKey` lives in
///      the browser's SubtleCrypto subsystem; even
///      `crypto.subtle.exportKey(...)` against it rejects.
///   2. The persisted form of the wrapping key — needed to recover
///      across page reloads — is the `CryptoKey` *object* itself,
///      stashed in IndexedDB via structured clone. IndexedDB preserves
///      the `extractable: false` attribute on round-trip.
///   3. Encrypted entries (AES-GCM ciphertext + 12-byte IV) live in a
///      separate IndexedDB object store, keyed by `service_name`/`key`.
///
/// A disk dump now yields ciphertext + an unusable key handle.
/// Recovering plaintext requires running JS in the same origin and
/// calling `crypto.subtle.decrypt(...)`. The
/// `LocalStorageSecureKeyStore` floor stays available as a fallback
/// for browsers / contexts where IndexedDB is denied (private-mode
/// Firefox, file:// URLs, etc.).
///
/// ## Sync trait surface against async storage
///
/// SubtleCrypto and IndexedDB are Promise-based; the
/// [`SecureKeyStore`] trait is sync. The store resolves this via a
/// two-phase model:
///
///   * [`IndexedDbSecureKeyStore::new_async`] (async, called once at
///     app startup) opens the database, derives or loads the wrapping
///     key, and decrypts every existing entry into an in-process
///     `HashMap`. This is the only async path.
///   * Sync trait methods read from / write to the cache directly.
///     Writes additionally spawn a `wasm_bindgen_futures::spawn_local`
///     task that re-encrypts and persists the change to IndexedDB.
///     Failures are logged but do not block the caller (mirrors the
///     `localStorage` failure mode, where a quota-exceeded `setItem`
///     also can't be reported through a sync trait).
///
/// Result: an in-flight write to IndexedDB that doesn't complete
/// before a page-unload is lost. Production callers tolerate this
/// because the data is re-derivable on next login (OIDC refresh
/// token, push registration grant, etc.).
#[cfg(target_arch = "wasm32")]
pub struct IndexedDbSecureKeyStore {
    service_name: String,
    db_name: String,
    cache: Arc<Mutex<HashMap<String, String>>>,
    /// Non-extractable AES-GCM CryptoKey, cloned cheaply via JsValue
    /// reference counting. Used by spawn_local persistence tasks. The
    /// `IndexedDbSendBoundary` wrapper attests Send+Sync on wasm32
    /// where there is exactly one thread — `JsValue` is `!Send` by
    /// default because wasm-bindgen has to accommodate the
    /// (currently theoretical) future where multiple wasm threads can
    /// share JS values.
    crypto_key: IndexedDbSendBoundary<wasm_bindgen::JsValue>,
    /// Cached `IdbDatabase` handle reused across every persistence
    /// write/delete. The connection is opened once at `new_async` time
    /// and shared for the lifetime of the store so each `spawn_local`
    /// callback inside `store_secret` / `delete_secret` does not have to
    /// reopen IndexedDB (and re-run `onupgradeneeded` checks) on every
    /// write.
    db: IndexedDbSendBoundary<web_sys::IdbDatabase>,
}

/// wasm32-only wrapper that asserts Send + Sync on a value that is
/// only ever touched from the single wasm thread. The
/// [`SecureKeyStore`] trait requires Send + Sync; wasm32 has no real
/// thread sharing, so this is sound.
#[cfg(target_arch = "wasm32")]
#[derive(Clone)]
struct IndexedDbSendBoundary<T>(std::sync::Arc<T>);

#[cfg(target_arch = "wasm32")]
unsafe impl<T> Send for IndexedDbSendBoundary<T> {}
#[cfg(target_arch = "wasm32")]
unsafe impl<T> Sync for IndexedDbSendBoundary<T> {}

#[cfg(target_arch = "wasm32")]
impl IndexedDbSecureKeyStore {
    /// IndexedDB database version. Bump when the object-store schema
    /// changes; the `onupgradeneeded` handler will fire.
    const DB_VERSION: u32 = 1;
    const OBJECT_STORE_ENTRIES: &'static str = "entries";
    const OBJECT_STORE_KEYS: &'static str = "wrapping_keys";
    const WRAPPING_KEY_PRIMARY: &'static str = "primary";
    /// Key-derivation parameters. PBKDF2 over a stable installation
    /// salt → AES-GCM 256-bit non-extractable key. Iterations are
    /// 100k to keep init cost bounded; in-origin attackers don't
    /// benefit from raising it.
    const PBKDF2_ITERATIONS: u32 = 100_000;
    const SALT_BYTES: usize = 16;

    /// Open / create the IndexedDB database, derive (or recover) the
    /// non-extractable AES-GCM wrapping key, then decrypt every
    /// existing entry into the in-process cache. Returns a fully
    /// initialised store ready for sync access via the
    /// [`SecureKeyStore`] trait.
    pub async fn new_async(service_name: &str) -> Result<Self, SecureKeyStoreError> {
        let db_name = format!("yougen.secret.{service_name}");
        let db = Self::open_db(&db_name).await?;
        let crypto_key = Self::load_or_derive_wrapping_key(&db, service_name).await?;
        let cache = Self::load_and_decrypt_cache(&db, &crypto_key).await?;
        Ok(Self {
            service_name: service_name.to_owned(),
            db_name,
            cache: Arc::new(Mutex::new(cache)),
            crypto_key: IndexedDbSendBoundary(Arc::new(crypto_key)),
            db: IndexedDbSendBoundary(Arc::new(db)),
        })
    }

    async fn open_db(db_name: &str) -> Result<web_sys::IdbDatabase, SecureKeyStoreError> {
        use wasm_bindgen::JsCast;
        use wasm_bindgen_futures::JsFuture;
        let window = web_sys::window().ok_or_else(|| {
            SecureKeyStoreError::Unsupported("web_sys::window unavailable (non-browser host)")
        })?;
        let factory = window
            .indexed_db()
            .map_err(|err| SecureKeyStoreError::Backend(format!("indexedDB: {err:?}")))?
            .ok_or_else(|| SecureKeyStoreError::Unsupported("window.indexedDB unavailable"))?;
        let open_req = factory
            .open_with_u32(db_name, Self::DB_VERSION)
            .map_err(|err| SecureKeyStoreError::Backend(format!("indexedDB.open: {err:?}")))?;
        // onupgradeneeded synchronously creates the two object stores
        // when version bumps (first install: version goes 0 → 1).
        let on_upgrade = wasm_bindgen::closure::Closure::<dyn FnMut(web_sys::Event)>::new(
            move |event: web_sys::Event| {
                let request: web_sys::IdbOpenDbRequest = match event
                    .target()
                    .and_then(|t| t.dyn_into::<web_sys::IdbOpenDbRequest>().ok())
                {
                    Some(r) => r,
                    None => return,
                };
                let db_value = match request.result() {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let db: web_sys::IdbDatabase = match db_value.dyn_into() {
                    Ok(d) => d,
                    Err(_) => return,
                };
                let _ = db.create_object_store(Self::OBJECT_STORE_ENTRIES);
                let _ = db.create_object_store(Self::OBJECT_STORE_KEYS);
            },
        );
        open_req.set_onupgradeneeded(Some(on_upgrade.as_ref().unchecked_ref()));
        let result = JsFuture::from(js_sys::Promise::new(&mut |resolve, reject| {
            let resolve_clone = resolve.clone();
            let reject_clone = reject.clone();
            let on_success =
                wasm_bindgen::closure::Closure::once_into_js(move |event: web_sys::Event| {
                    if let Some(request) = event
                        .target()
                        .and_then(|t| t.dyn_into::<web_sys::IdbOpenDbRequest>().ok())
                    {
                        match request.result() {
                            Ok(value) => {
                                let _ = resolve_clone.call1(&wasm_bindgen::JsValue::NULL, &value);
                            }
                            Err(err) => {
                                let _ = reject_clone.call1(&wasm_bindgen::JsValue::NULL, &err);
                            }
                        }
                    }
                });
            let on_error =
                wasm_bindgen::closure::Closure::once_into_js(move |event: web_sys::Event| {
                    let err = event
                        .target()
                        .and_then(|t| t.dyn_into::<web_sys::IdbOpenDbRequest>().ok())
                        .and_then(|r| r.error().ok())
                        .map(|opt| {
                            opt.map(wasm_bindgen::JsValue::from).unwrap_or(
                                wasm_bindgen::JsValue::from_str(
                                    "indexedDB open error (no DOMException)",
                                ),
                            )
                        })
                        .unwrap_or_else(|| {
                            wasm_bindgen::JsValue::from_str("indexedDB open error (no target)")
                        });
                    let _ = reject.call1(&wasm_bindgen::JsValue::NULL, &err);
                });
            open_req.set_onsuccess(Some(on_success.unchecked_ref()));
            open_req.set_onerror(Some(on_error.unchecked_ref()));
        }))
        .await
        .map_err(|err| SecureKeyStoreError::Backend(format!("indexedDB open awaited: {err:?}")))?;
        // Keep the closure alive past the await — `forget` here
        // intentionally leaks because the closure has the lifetime
        // of the request which is consumed once.
        on_upgrade.forget();
        let db: web_sys::IdbDatabase = result.dyn_into().map_err(|_| {
            SecureKeyStoreError::Backend("open did not return IdbDatabase".to_owned())
        })?;
        Ok(db)
    }

    async fn load_or_derive_wrapping_key(
        db: &web_sys::IdbDatabase,
        service_name: &str,
    ) -> Result<wasm_bindgen::JsValue, SecureKeyStoreError> {
        // Read the existing CryptoKey if present; else generate +
        // store. IndexedDB preserves the `extractable: false`
        // attribute on round-trip via structured clone.
        if let Some(existing) =
            Self::idb_get_value(db, Self::OBJECT_STORE_KEYS, Self::WRAPPING_KEY_PRIMARY).await?
        {
            return Ok(existing);
        }
        let key = Self::derive_fresh_wrapping_key(service_name).await?;
        Self::idb_put_value(
            db,
            Self::OBJECT_STORE_KEYS,
            Self::WRAPPING_KEY_PRIMARY,
            &key,
        )
        .await?;
        Ok(key)
    }

    async fn derive_fresh_wrapping_key(
        service_name: &str,
    ) -> Result<wasm_bindgen::JsValue, SecureKeyStoreError> {
        use js_sys::{Array, Object, Reflect, Uint8Array};
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;
        let window = web_sys::window()
            .ok_or_else(|| SecureKeyStoreError::Unsupported("web_sys::window unavailable"))?;
        let subtle = window
            .crypto()
            .map_err(|err| SecureKeyStoreError::Backend(format!("crypto: {err:?}")))?
            .subtle();
        // Step 1: import the service_name bytes as a PBKDF2 base key.
        let base_material = Uint8Array::new_with_length(service_name.len() as u32);
        base_material.copy_from(service_name.as_bytes());
        let pbkdf2_usages = Array::new();
        pbkdf2_usages.push(&JsValue::from_str("deriveKey"));
        let base_key_promise = subtle
            .import_key_with_str(
                "raw",
                base_material.as_ref(),
                "PBKDF2",
                false,
                &JsValue::from(pbkdf2_usages),
            )
            .map_err(|err| {
                SecureKeyStoreError::Backend(format!("subtle.importKey PBKDF2: {err:?}"))
            })?;
        let base_key = JsFuture::from(base_key_promise).await.map_err(|err| {
            SecureKeyStoreError::Backend(format!("subtle.importKey PBKDF2 awaited: {err:?}"))
        })?;
        // Step 2: deriveKey → AES-GCM 256, extractable=false.
        let mut salt = [0u8; Self::SALT_BYTES];
        getrandom::fill(&mut salt)
            .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom salt: {err}")))?;
        let salt_array = Uint8Array::new_with_length(Self::SALT_BYTES as u32);
        salt_array.copy_from(&salt);
        let derive_algo = Object::new();
        Reflect::set(
            &derive_algo,
            &JsValue::from_str("name"),
            &JsValue::from_str("PBKDF2"),
        )
        .map_err(|err| SecureKeyStoreError::Backend(format!("derive name set: {err:?}")))?;
        Reflect::set(&derive_algo, &JsValue::from_str("salt"), &salt_array)
            .map_err(|err| SecureKeyStoreError::Backend(format!("derive salt set: {err:?}")))?;
        Reflect::set(
            &derive_algo,
            &JsValue::from_str("iterations"),
            &JsValue::from_f64(Self::PBKDF2_ITERATIONS as f64),
        )
        .map_err(|err| SecureKeyStoreError::Backend(format!("derive iter set: {err:?}")))?;
        Reflect::set(
            &derive_algo,
            &JsValue::from_str("hash"),
            &JsValue::from_str("SHA-256"),
        )
        .map_err(|err| SecureKeyStoreError::Backend(format!("derive hash set: {err:?}")))?;
        let derived_algo = Object::new();
        Reflect::set(
            &derived_algo,
            &JsValue::from_str("name"),
            &JsValue::from_str("AES-GCM"),
        )
        .map_err(|err| SecureKeyStoreError::Backend(format!("derived name set: {err:?}")))?;
        Reflect::set(
            &derived_algo,
            &JsValue::from_str("length"),
            &JsValue::from_f64(256.0),
        )
        .map_err(|err| SecureKeyStoreError::Backend(format!("derived length set: {err:?}")))?;
        let aes_usages = Array::new();
        aes_usages.push(&JsValue::from_str("encrypt"));
        aes_usages.push(&JsValue::from_str("decrypt"));
        let base_key_typed: web_sys::CryptoKey = base_key.dyn_into().map_err(|_| {
            SecureKeyStoreError::Backend("PBKDF2 importKey did not yield CryptoKey".to_owned())
        })?;
        let derive_promise = subtle
            .derive_key_with_object_and_object(
                &derive_algo,
                &base_key_typed,
                &derived_algo,
                false,
                &JsValue::from(aes_usages),
            )
            .map_err(|err| SecureKeyStoreError::Backend(format!("subtle.deriveKey: {err:?}")))?;
        let derived = JsFuture::from(derive_promise)
            .await
            .map_err(|err| SecureKeyStoreError::Backend(format!("deriveKey awaited: {err:?}")))?;
        Ok(derived)
    }

    async fn load_and_decrypt_cache(
        db: &web_sys::IdbDatabase,
        crypto_key: &wasm_bindgen::JsValue,
    ) -> Result<HashMap<String, String>, SecureKeyStoreError> {
        let entries = Self::idb_all_entries(db, Self::OBJECT_STORE_ENTRIES).await?;
        let mut out = HashMap::with_capacity(entries.len());
        for (key_name, wrapped_bytes) in entries {
            match Self::subtle_decrypt(crypto_key, &wrapped_bytes).await {
                Ok(plain) => {
                    if let Ok(s) = String::from_utf8(plain) {
                        out.insert(key_name, s);
                    }
                }
                Err(err) => {
                    tracing::warn!(?err, key=%key_name, "indexedDB entry decrypt failed");
                }
            }
        }
        Ok(out)
    }

    async fn idb_get_value(
        db: &web_sys::IdbDatabase,
        store: &str,
        key: &str,
    ) -> Result<Option<wasm_bindgen::JsValue>, SecureKeyStoreError> {
        use wasm_bindgen::JsCast;
        use wasm_bindgen::JsValue;
        use wasm_bindgen_futures::JsFuture;
        let tx = db
            .transaction_with_str(store)
            .map_err(|err| SecureKeyStoreError::Backend(format!("tx open: {err:?}")))?;
        let obj_store = tx
            .object_store(store)
            .map_err(|err| SecureKeyStoreError::Backend(format!("objectStore: {err:?}")))?;
        let request = obj_store
            .get(&JsValue::from_str(key))
            .map_err(|err| SecureKeyStoreError::Backend(format!("get: {err:?}")))?;
        let promise = js_sys::Promise::new(&mut |resolve, reject| {
            let reject_for_error = reject.clone();
            let on_success =
                wasm_bindgen::closure::Closure::once_into_js(move |event: web_sys::Event| {
                    if let Some(req) = event
                        .target()
                        .and_then(|t| t.dyn_into::<web_sys::IdbRequest>().ok())
                    {
                        match req.result() {
                            Ok(v) => {
                                let _ = resolve.call1(&JsValue::NULL, &v);
                            }
                            Err(err) => {
                                let _ = reject.call1(&JsValue::NULL, &err);
                            }
                        }
                    }
                });
            let on_error =
                wasm_bindgen::closure::Closure::once_into_js(move |_event: web_sys::Event| {
                    let _ = reject_for_error
                        .call1(&JsValue::NULL, &JsValue::from_str("indexedDB get error"));
                });
            request.set_onsuccess(Some(on_success.unchecked_ref()));
            request.set_onerror(Some(on_error.unchecked_ref()));
        });
        let value = JsFuture::from(promise)
            .await
            .map_err(|err| SecureKeyStoreError::Backend(format!("get awaited: {err:?}")))?;
        if value.is_undefined() || value.is_null() {
            Ok(None)
        } else {
            Ok(Some(value))
        }
    }

    async fn idb_put_value(
        db: &web_sys::IdbDatabase,
        store: &str,
        key: &str,
        value: &wasm_bindgen::JsValue,
    ) -> Result<(), SecureKeyStoreError> {
        use wasm_bindgen::JsCast;
        use wasm_bindgen::JsValue;
        use wasm_bindgen_futures::JsFuture;
        let tx = db
            .transaction_with_str_and_mode(store, web_sys::IdbTransactionMode::Readwrite)
            .map_err(|err| SecureKeyStoreError::Backend(format!("tx open rw: {err:?}")))?;
        let obj_store = tx
            .object_store(store)
            .map_err(|err| SecureKeyStoreError::Backend(format!("objectStore: {err:?}")))?;
        let request = obj_store
            .put_with_key(value, &JsValue::from_str(key))
            .map_err(|err| SecureKeyStoreError::Backend(format!("put: {err:?}")))?;
        let promise = js_sys::Promise::new(&mut |resolve, reject| {
            let resolve = resolve.clone();
            let reject = reject.clone();
            let on_success =
                wasm_bindgen::closure::Closure::once_into_js(move |_event: web_sys::Event| {
                    let _ = resolve.call1(&JsValue::NULL, &JsValue::UNDEFINED);
                });
            let on_error =
                wasm_bindgen::closure::Closure::once_into_js(move |_event: web_sys::Event| {
                    let _ = reject.call1(&JsValue::NULL, &JsValue::from_str("indexedDB put error"));
                });
            request.set_onsuccess(Some(on_success.unchecked_ref()));
            request.set_onerror(Some(on_error.unchecked_ref()));
        });
        JsFuture::from(promise)
            .await
            .map_err(|err| SecureKeyStoreError::Backend(format!("put awaited: {err:?}")))?;
        Ok(())
    }

    async fn idb_delete_value(
        db: &web_sys::IdbDatabase,
        store: &str,
        key: &str,
    ) -> Result<(), SecureKeyStoreError> {
        use wasm_bindgen::JsCast;
        use wasm_bindgen::JsValue;
        use wasm_bindgen_futures::JsFuture;
        let tx = db
            .transaction_with_str_and_mode(store, web_sys::IdbTransactionMode::Readwrite)
            .map_err(|err| SecureKeyStoreError::Backend(format!("tx open rw: {err:?}")))?;
        let obj_store = tx
            .object_store(store)
            .map_err(|err| SecureKeyStoreError::Backend(format!("objectStore: {err:?}")))?;
        let request = obj_store
            .delete(&JsValue::from_str(key))
            .map_err(|err| SecureKeyStoreError::Backend(format!("delete: {err:?}")))?;
        let promise = js_sys::Promise::new(&mut |resolve, reject| {
            let resolve = resolve.clone();
            let reject = reject.clone();
            let on_success =
                wasm_bindgen::closure::Closure::once_into_js(move |_event: web_sys::Event| {
                    let _ = resolve.call1(&JsValue::NULL, &JsValue::UNDEFINED);
                });
            let on_error =
                wasm_bindgen::closure::Closure::once_into_js(move |_event: web_sys::Event| {
                    let _ =
                        reject.call1(&JsValue::NULL, &JsValue::from_str("indexedDB delete error"));
                });
            request.set_onsuccess(Some(on_success.unchecked_ref()));
            request.set_onerror(Some(on_error.unchecked_ref()));
        });
        JsFuture::from(promise)
            .await
            .map_err(|err| SecureKeyStoreError::Backend(format!("delete awaited: {err:?}")))?;
        Ok(())
    }

    /// Read every entry in `store` as `(key, value)`. The promise
    /// pattern is openCursor → onsuccess loops until cursor is None.
    async fn idb_all_entries(
        db: &web_sys::IdbDatabase,
        store: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, SecureKeyStoreError> {
        use js_sys::{Object, Reflect, Uint8Array};
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;
        let tx = db
            .transaction_with_str(store)
            .map_err(|err| SecureKeyStoreError::Backend(format!("tx open: {err:?}")))?;
        let obj_store = tx
            .object_store(store)
            .map_err(|err| SecureKeyStoreError::Backend(format!("objectStore: {err:?}")))?;
        // getAll + getAllKeys is the simplest cross-browser way to
        // enumerate without cursor-callback gymnastics.
        let values_req = obj_store
            .get_all()
            .map_err(|err| SecureKeyStoreError::Backend(format!("getAll: {err:?}")))?;
        let keys_req = obj_store
            .get_all_keys()
            .map_err(|err| SecureKeyStoreError::Backend(format!("getAllKeys: {err:?}")))?;
        let values_promise = js_sys::Promise::new(&mut |resolve, reject| {
            let reject_for_error = reject.clone();
            let on_success =
                wasm_bindgen::closure::Closure::once_into_js(move |event: web_sys::Event| {
                    if let Some(req) = event
                        .target()
                        .and_then(|t| t.dyn_into::<web_sys::IdbRequest>().ok())
                    {
                        match req.result() {
                            Ok(v) => {
                                let _ = resolve.call1(&JsValue::NULL, &v);
                            }
                            Err(err) => {
                                let _ = reject.call1(&JsValue::NULL, &err);
                            }
                        }
                    }
                });
            let on_error =
                wasm_bindgen::closure::Closure::once_into_js(move |_event: web_sys::Event| {
                    let _ = reject_for_error
                        .call1(&JsValue::NULL, &JsValue::from_str("indexedDB getAll error"));
                });
            values_req.set_onsuccess(Some(on_success.unchecked_ref()));
            values_req.set_onerror(Some(on_error.unchecked_ref()));
        });
        let keys_promise = js_sys::Promise::new(&mut |resolve, reject| {
            let reject_for_error = reject.clone();
            let on_success =
                wasm_bindgen::closure::Closure::once_into_js(move |event: web_sys::Event| {
                    if let Some(req) = event
                        .target()
                        .and_then(|t| t.dyn_into::<web_sys::IdbRequest>().ok())
                    {
                        match req.result() {
                            Ok(v) => {
                                let _ = resolve.call1(&JsValue::NULL, &v);
                            }
                            Err(err) => {
                                let _ = reject.call1(&JsValue::NULL, &err);
                            }
                        }
                    }
                });
            let on_error =
                wasm_bindgen::closure::Closure::once_into_js(move |_event: web_sys::Event| {
                    let _ = reject_for_error.call1(
                        &JsValue::NULL,
                        &JsValue::from_str("indexedDB getAllKeys error"),
                    );
                });
            keys_req.set_onsuccess(Some(on_success.unchecked_ref()));
            keys_req.set_onerror(Some(on_error.unchecked_ref()));
        });
        let values = JsFuture::from(values_promise)
            .await
            .map_err(|err| SecureKeyStoreError::Backend(format!("getAll awaited: {err:?}")))?;
        let keys = JsFuture::from(keys_promise)
            .await
            .map_err(|err| SecureKeyStoreError::Backend(format!("getAllKeys awaited: {err:?}")))?;
        let values_arr: js_sys::Array = values.into();
        let keys_arr: js_sys::Array = keys.into();
        let len = std::cmp::min(values_arr.length(), keys_arr.length()) as usize;
        let mut out = Vec::with_capacity(len);
        for i in 0..len as u32 {
            let key_value = keys_arr.get(i);
            let entry_value = values_arr.get(i);
            let Some(key_str) = key_value.as_string() else {
                continue;
            };
            // entry_value is an Object with { iv: Uint8Array, ct: Uint8Array }.
            let obj: Object = match entry_value.dyn_into() {
                Ok(o) => o,
                Err(_) => continue,
            };
            let iv = Reflect::get(&obj, &JsValue::from_str("iv"))
                .ok()
                .and_then(|v| v.dyn_into::<Uint8Array>().ok());
            let ct = Reflect::get(&obj, &JsValue::from_str("ct"))
                .ok()
                .and_then(|v| v.dyn_into::<Uint8Array>().ok());
            let (Some(iv), Some(ct)) = (iv, ct) else {
                continue;
            };
            let mut iv_bytes = vec![0u8; iv.length() as usize];
            iv.copy_to(&mut iv_bytes);
            let mut ct_bytes = vec![0u8; ct.length() as usize];
            ct.copy_to(&mut ct_bytes);
            let mut packed = Vec::with_capacity(iv_bytes.len() + ct_bytes.len());
            packed.extend_from_slice(&iv_bytes);
            packed.extend_from_slice(&ct_bytes);
            out.push((key_str, packed));
        }
        Ok(out)
    }

    /// Encrypt `plain` against the non-extractable CryptoKey via
    /// `SubtleCrypto.encrypt({ name: "AES-GCM", iv })`. Returns
    /// `[iv (12 bytes) || ciphertext]` so the on-disk record is
    /// self-contained.
    async fn subtle_encrypt(
        crypto_key: &wasm_bindgen::JsValue,
        plain: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), SecureKeyStoreError> {
        use js_sys::{Object, Reflect, Uint8Array};
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;
        let window = web_sys::window()
            .ok_or_else(|| SecureKeyStoreError::Unsupported("web_sys::window unavailable"))?;
        let subtle = window
            .crypto()
            .map_err(|err| SecureKeyStoreError::Backend(format!("crypto: {err:?}")))?
            .subtle();
        let mut iv = [0u8; 12];
        getrandom::fill(&mut iv)
            .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom iv: {err}")))?;
        let iv_array = Uint8Array::new_with_length(12);
        iv_array.copy_from(&iv);
        let algo = Object::new();
        Reflect::set(
            &algo,
            &JsValue::from_str("name"),
            &JsValue::from_str("AES-GCM"),
        )
        .map_err(|err| SecureKeyStoreError::Backend(format!("algo name: {err:?}")))?;
        Reflect::set(&algo, &JsValue::from_str("iv"), &iv_array)
            .map_err(|err| SecureKeyStoreError::Backend(format!("algo iv: {err:?}")))?;
        let plain_array = Uint8Array::new_with_length(plain.len() as u32);
        plain_array.copy_from(plain);
        let key_typed: web_sys::CryptoKey = crypto_key
            .clone()
            .dyn_into()
            .map_err(|_| SecureKeyStoreError::Backend("wrapping key not CryptoKey".to_owned()))?;
        let promise = subtle
            .encrypt_with_object_and_buffer_source(&algo, &key_typed, plain_array.as_ref())
            .map_err(|err| SecureKeyStoreError::Backend(format!("subtle.encrypt: {err:?}")))?;
        let result = JsFuture::from(promise)
            .await
            .map_err(|err| SecureKeyStoreError::Backend(format!("encrypt awaited: {err:?}")))?;
        let buf: js_sys::ArrayBuffer = result.dyn_into().map_err(|_| {
            SecureKeyStoreError::Backend("encrypt did not return ArrayBuffer".to_owned())
        })?;
        let view = Uint8Array::new(&buf);
        let mut ct = vec![0u8; view.length() as usize];
        view.copy_to(&mut ct);
        Ok((iv.to_vec(), ct))
    }

    async fn subtle_decrypt(
        crypto_key: &wasm_bindgen::JsValue,
        packed: &[u8],
    ) -> Result<Vec<u8>, SecureKeyStoreError> {
        use js_sys::{Object, Reflect, Uint8Array};
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;
        if packed.len() < 12 {
            return Err(SecureKeyStoreError::Backend(
                "subtle_decrypt: packed too short".to_owned(),
            ));
        }
        let (iv, ct) = packed.split_at(12);
        let window = web_sys::window()
            .ok_or_else(|| SecureKeyStoreError::Unsupported("web_sys::window unavailable"))?;
        let subtle = window
            .crypto()
            .map_err(|err| SecureKeyStoreError::Backend(format!("crypto: {err:?}")))?
            .subtle();
        let iv_array = Uint8Array::new_with_length(12);
        iv_array.copy_from(iv);
        let algo = Object::new();
        Reflect::set(
            &algo,
            &JsValue::from_str("name"),
            &JsValue::from_str("AES-GCM"),
        )
        .map_err(|err| SecureKeyStoreError::Backend(format!("algo name: {err:?}")))?;
        Reflect::set(&algo, &JsValue::from_str("iv"), &iv_array)
            .map_err(|err| SecureKeyStoreError::Backend(format!("algo iv: {err:?}")))?;
        let ct_array = Uint8Array::new_with_length(ct.len() as u32);
        ct_array.copy_from(ct);
        let key_typed: web_sys::CryptoKey = crypto_key
            .clone()
            .dyn_into()
            .map_err(|_| SecureKeyStoreError::Backend("wrapping key not CryptoKey".to_owned()))?;
        let promise = subtle
            .decrypt_with_object_and_buffer_source(&algo, &key_typed, ct_array.as_ref())
            .map_err(|err| SecureKeyStoreError::Backend(format!("subtle.decrypt: {err:?}")))?;
        let result = JsFuture::from(promise)
            .await
            .map_err(|err| SecureKeyStoreError::Backend(format!("decrypt awaited: {err:?}")))?;
        let buf: js_sys::ArrayBuffer = result.dyn_into().map_err(|_| {
            SecureKeyStoreError::Backend("decrypt did not return ArrayBuffer".to_owned())
        })?;
        let view = Uint8Array::new(&buf);
        let mut out = vec![0u8; view.length() as usize];
        view.copy_to(&mut out);
        Ok(out)
    }

    /// Persist `(iv, ct)` against `key` in the entries object store.
    /// Called from sync trait paths via `spawn_local`. Takes a borrowed
    /// `IdbDatabase` so the cached connection is reused instead of
    /// re-opening per write.
    async fn persist_entry_value(
        db: &web_sys::IdbDatabase,
        crypto_key: &wasm_bindgen::JsValue,
        key: &str,
        plain: &str,
    ) -> Result<(), SecureKeyStoreError> {
        use js_sys::{Object, Reflect, Uint8Array};
        use wasm_bindgen::JsValue;
        let (iv, ct) = Self::subtle_encrypt(crypto_key, plain.as_bytes()).await?;
        let entry = Object::new();
        let iv_array = Uint8Array::new_with_length(iv.len() as u32);
        iv_array.copy_from(&iv);
        let ct_array = Uint8Array::new_with_length(ct.len() as u32);
        ct_array.copy_from(&ct);
        Reflect::set(&entry, &JsValue::from_str("iv"), &iv_array)
            .map_err(|err| SecureKeyStoreError::Backend(format!("entry iv: {err:?}")))?;
        Reflect::set(&entry, &JsValue::from_str("ct"), &ct_array)
            .map_err(|err| SecureKeyStoreError::Backend(format!("entry ct: {err:?}")))?;
        Self::idb_put_value(db, Self::OBJECT_STORE_ENTRIES, key, entry.as_ref()).await
    }
}

#[cfg(target_arch = "wasm32")]
impl std::fmt::Debug for IndexedDbSecureKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexedDbSecureKeyStore")
            .field("service_name", &self.service_name)
            .field("db_name", &self.db_name)
            .field(
                "cache_entries",
                &self.cache.lock().map(|g| g.len()).unwrap_or(0),
            )
            .field("crypto_key", &"<non-extractable CryptoKey>")
            .finish()
    }
}

#[cfg(target_arch = "wasm32")]
impl SecureKeyStore for IndexedDbSecureKeyStore {
    fn store_secret(&self, key: &str, value: &str) -> Result<(), SecureKeyStoreError> {
        {
            let mut guard = self
                .cache
                .lock()
                .map_err(|err| SecureKeyStoreError::Backend(format!("cache lock: {err}")))?;
            guard.insert(key.to_owned(), value.to_owned());
        }
        // Fire-and-forget persistence. Failures are logged; the cache
        // already has the new value so subsequent reads succeed even
        // if the write loses out to a page-unload race.
        //
        // Reuse the cached `IdbDatabase` handle instead of opening a
        // fresh one per write.
        let key_for_async = key.to_owned();
        let value_for_async = value.to_owned();
        let crypto_key = self.crypto_key.clone();
        let db = self.db.clone();
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(err) =
                Self::persist_entry_value(&db.0, &crypto_key.0, &key_for_async, &value_for_async)
                    .await
            {
                tracing::warn!(?err, key=%key_for_async, "indexedDB persist failed");
            }
        });
        Ok(())
    }

    fn get_secret(&self, key: &str) -> Result<Option<String>, SecureKeyStoreError> {
        let guard = self
            .cache
            .lock()
            .map_err(|err| SecureKeyStoreError::Backend(format!("cache lock: {err}")))?;
        Ok(guard.get(key).cloned())
    }

    fn delete_secret(&self, key: &str) -> Result<(), SecureKeyStoreError> {
        {
            let mut guard = self
                .cache
                .lock()
                .map_err(|err| SecureKeyStoreError::Backend(format!("cache lock: {err}")))?;
            guard.remove(key);
        }
        // Reuse the cached `IdbDatabase` handle for the spawned delete.
        let key_for_async = key.to_owned();
        let db = self.db.clone();
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(err) =
                Self::idb_delete_value(&db.0, Self::OBJECT_STORE_ENTRIES, &key_for_async).await
            {
                tracing::warn!(?err, key=%key_for_async, "indexedDB delete failed");
            }
        });
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "indexed_db_subtle_aes_gcm"
    }
}

/// wasm32-only async upgrade path.
///
/// The boot sequence on wasm32 looks like:
///
///   1. App `main` calls [`default_secure_key_store`] synchronously
///      and receives a [`LocalStorageSecureKeyStore`]. This unblocks
///      first paint without waiting on IndexedDB/SubtleCrypto.
///   2. App `main` then `spawn_local`s an async task that calls
///      `upgrade_wasm_secure_key_store_async(service_name).await`,
///      which returns either:
///        * `Ok(Some(store))` — a fully-initialised
///          [`IndexedDbSecureKeyStore`] ready to replace the
///          LocalStorage store. The app should hot-swap the
///          `Arc<dyn SecureKeyStore>` in its app state.
///        * `Ok(None)` — IndexedDB or SubtleCrypto were
///          unavailable (private-mode Firefox, file:// origin,
///          Tor Browser hardened). Keep the LocalStorage store.
///        * `Err(...)` — backend failure during init. Caller should
///          log and keep the LocalStorage store.
///   3. The first time an entry is written through the IndexedDB
///      store, [`migrate_localstorage_entries_to_indexeddb`] (also
///      async) can be invoked to copy any pre-existing wrapped
///      secrets across, then drop the LocalStorage seed.
///
/// Returning `Option<Arc<...>>` rather than panicking on
/// "browser doesn't support this" mirrors the rest of the secure
/// key store contract (sync `default_secure_key_store` also falls
/// back to `MemorySecureKeyStore` rather than crashing).
#[cfg(target_arch = "wasm32")]
pub async fn upgrade_wasm_secure_key_store_async(
    service_name: &str,
) -> Result<Option<Arc<dyn SecureKeyStore>>, SecureKeyStoreError> {
    // Probe for SubtleCrypto first — older browsers / file:// origins
    // expose `crypto` but not `crypto.subtle`. We can't reasonably
    // recover from a missing SubtleCrypto, so return `Ok(None)` and
    // let the caller keep the LocalStorage fallback.
    if !indexeddb_and_subtle_available() {
        tracing::info!("IndexedDB or SubtleCrypto unavailable; keeping LocalStorage store");
        return Ok(None);
    }
    let store = IndexedDbSecureKeyStore::new_async(service_name).await?;
    // One-shot migration of any pre-existing LocalStorage entries
    // into the new IndexedDB store, then prune the LocalStorage side so a future
    // disk dump can't recover the seed alongside the ciphertext.
    let migrated = migrate_localstorage_entries_to_indexeddb(service_name, &store)
        .await
        .unwrap_or_else(|err| {
            tracing::warn!(?err, "H6 LocalStorage→IndexedDB migration failed");
            0
        });
    if migrated > 0 {
        tracing::info!("H6 migration: {migrated} entry(s) migrated from LocalStorage to IndexedDB");
    }
    Ok(Some(Arc::new(store)))
}

/// Walk `localStorage` looking for keys under the
/// `yougen.secret.<service_name>.*` prefix written by
/// [`LocalStorageSecureKeyStore`], decrypt each via the
/// existing AEAD wrapping seed, re-store under the IndexedDB tier
/// via [`IndexedDbSecureKeyStore::store_secret`], then `removeItem`
/// the original localStorage key plus the wrapping seed itself.
///
/// Returns the count of migrated entries. Silently skips entries
/// that fail to decrypt — they're either corrupted or written by a
/// different installation (different wrapping_seed). A
/// `Ok(_)` return means migration ran (possibly with skipped
/// entries); `Err` indicates an environmental failure like no
/// `window.localStorage` (private-mode Firefox, file:// origin).
///
/// Idempotent: a second run finds nothing to migrate and returns 0.
#[cfg(target_arch = "wasm32")]
pub async fn migrate_localstorage_entries_to_indexeddb(
    service_name: &str,
    indexed_store: &IndexedDbSecureKeyStore,
) -> Result<usize, SecureKeyStoreError> {
    let storage = match LocalStorageSecureKeyStore::storage() {
        Ok(s) => s,
        Err(_) => return Ok(0),
    };
    // Read the H2 wrapping seed (still bytes in localStorage — that
    // is the threat model H6 is moving away from). When absent
    // there's nothing to migrate.
    let seed_key = LocalStorageSecureKeyStore::wrapping_seed_key(service_name);
    let wrapping_seed_b64 = match storage.get_item(&seed_key) {
        Ok(Some(b)) => b,
        Ok(None) => return Ok(0),
        Err(err) => {
            return Err(SecureKeyStoreError::Backend(format!(
                "migrate read seed: {err:?}"
            )));
        }
    };
    let wrapping_seed_bytes = match STANDARD_NO_PAD.decode(wrapping_seed_b64.as_bytes()) {
        Ok(b) => b,
        Err(_) => return Ok(0),
    };
    if wrapping_seed_bytes.len() != 32 {
        return Ok(0);
    }
    let mut wrapping_key = [0u8; 32];
    wrapping_key.copy_from_slice(&wrapping_seed_bytes);

    // Enumerate localStorage entries whose key matches the H2
    // prefix `yougen.secret.<service_name>.*` (excluding the
    // wrap_seed key itself).
    let prefix = format!("yougen.secret.{service_name}.");
    let length = storage
        .length()
        .map_err(|err| SecureKeyStoreError::Backend(format!("ls length: {err:?}")))?;
    let mut candidates: Vec<String> = Vec::new();
    for i in 0..length {
        let key = match storage.key(i) {
            Ok(Some(k)) => k,
            _ => continue,
        };
        if key == seed_key {
            continue;
        }
        if !key.starts_with(&prefix) {
            continue;
        }
        candidates.push(key);
    }
    let mut migrated = 0usize;
    for full_key in &candidates {
        let entry_name = full_key
            .strip_prefix(&prefix)
            .unwrap_or(full_key.as_str())
            .to_owned();
        let wrapped = match storage.get_item(full_key) {
            Ok(Some(v)) => v,
            _ => continue,
        };
        let Ok(Some(plain)) = unwrap_secret(&wrapped, &wrapping_key) else {
            tracing::warn!(key=%entry_name, "H6 migrate: decrypt failed; skipping");
            continue;
        };
        if let Err(err) = indexed_store.store_secret(&entry_name, &plain) {
            tracing::warn!(?err, key=%entry_name, "H6 migrate: IDB write failed");
            continue;
        }
        // Remove the LocalStorage copy only after the IDB write
        // returns Ok. The IDB persistence task is fire-and-forget
        // (see `IndexedDbSecureKeyStore::store_secret` doc-comment),
        // so we accept a small window where both sides could exist
        // — the next migration run will reconcile.
        let _ = storage.remove_item(full_key);
        migrated += 1;
    }
    // Finally drop the wrapping seed too, so a future disk dump
    // only carries the IndexedDB's non-extractable CryptoKey.
    if migrated > 0 {
        let _ = storage.remove_item(&seed_key);
    }
    Ok(migrated)
}

#[cfg(target_arch = "wasm32")]
fn indexeddb_and_subtle_available() -> bool {
    let Some(window) = web_sys::window() else {
        return false;
    };
    let idb_present = window.indexed_db().ok().flatten().is_some();
    // `crypto.subtle()` on web_sys returns a `SubtleCrypto` directly
    // (no `Result` / `Option`), but the underlying property access
    // panics on browsers that don't expose it. Probe by catching the
    // JS-side `undefined` via a runtime check: convert the SubtleCrypto
    // reference into a JsValue and verify it's not undefined / null.
    let subtle_present = window
        .crypto()
        .map(|c| {
            let subtle: wasm_bindgen::JsValue = c.subtle().into();
            !subtle.is_undefined() && !subtle.is_null()
        })
        .unwrap_or(false);
    idb_present && subtle_present
}

// ── T5.2: signing-seed convenience layer ─────────────────────────────
//
// The `SecureKeyStore` trait above is a generic string → string KV
// (used by OIDC refresh tokens, push grants, etc.). T5.2 piggybacks on
// the same backend for the per-device Ed25519 signing seed so the seed
// lands in the OS keychain alongside the rest of the secrets instead of
// in `state.json` plaintext.

/// Canonical key name for the active-device Ed25519 signing seed in the
/// secure-key store. Scoped by `service_name` (`"yougen"` in production)
/// so dev and prod builds never collide.
pub const SIGNING_SEED_KEY: &str = "device.ed25519.signing_seed.v1";

/// Decoded signing seed (32 bytes) plus the `did:key` the seed encodes.
/// Returned by [`load_signing_seed`] / [`ensure_signing_seed`] so callers
/// can stand up an `Ed25519DetachedJwsSigner` without re-deriving the DID.
#[derive(Clone)]
pub struct SigningSeedMaterial {
    pub seed: [u8; 32],
    pub device_did: String,
}

impl std::fmt::Debug for SigningSeedMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningSeedMaterial")
            .field("seed", &"<redacted>")
            .field("device_did", &self.device_did)
            .finish()
    }
}

/// Read a previously-stashed signing seed from `store`. Returns `Ok(None)`
/// when the entry is absent (vs `Err(...)` for backend failures).
///
/// The seed is encoded as base64-no-pad. Any decode failure (corrupt
/// entry, length mismatch) is reported as `SecureKeyStoreError::Backend`
/// so the boot path can surface a clear "rotate device identity" warning
/// instead of silently regenerating.
pub fn load_signing_seed(
    store: &dyn SecureKeyStore,
) -> Result<Option<SigningSeedMaterial>, SecureKeyStoreError> {
    let Some(raw) = store.get_secret(SIGNING_SEED_KEY)? else {
        return Ok(None);
    };
    let bytes = STANDARD_NO_PAD.decode(raw.as_bytes()).map_err(|err| {
        SecureKeyStoreError::Backend(format!("signing seed base64 decode: {err}"))
    })?;
    if bytes.len() != 32 {
        return Err(SecureKeyStoreError::Backend(format!(
            "signing seed length {}, expected 32",
            bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    let did = ed25519_seed_to_did_key(&seed);
    Ok(Some(SigningSeedMaterial {
        seed,
        device_did: did,
    }))
}

/// Persist `seed` into the secure-key store under [`SIGNING_SEED_KEY`].
/// Overwrites silently. The DID is recomputed from the seed by the
/// loader, so it is not stored separately.
pub fn store_signing_seed(
    store: &dyn SecureKeyStore,
    seed: &[u8; 32],
) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
    let encoded = STANDARD_NO_PAD.encode(seed);
    store.store_secret(SIGNING_SEED_KEY, &encoded)?;
    Ok(SigningSeedMaterial {
        seed: *seed,
        device_did: ed25519_seed_to_did_key(seed),
    })
}

/// Load the existing signing seed, or generate + persist a fresh one if
/// none exists. The generated seed is a 32-byte `getrandom` draw.
pub fn ensure_signing_seed(
    store: &dyn SecureKeyStore,
) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
    if let Some(material) = load_signing_seed(store)? {
        return Ok(material);
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom signing seed: {err}")))?;
    store_signing_seed(store, &seed)
}

/// Encode an Ed25519 seed into a `did:key:z…` (multibase `0xed01 ||
/// pubkey32`). Kept in this module so callers don't have to depend on
/// `crate::local_state::encode_did_key` for the seed-only path.
fn ed25519_seed_to_did_key(seed: &[u8; 32]) -> String {
    let signing = ed25519_dalek::SigningKey::from_bytes(seed);
    let verifying = signing.verifying_key();
    let mut prefixed = Vec::with_capacity(34);
    prefixed.push(0xed);
    prefixed.push(0x01);
    prefixed.extend_from_slice(&verifying.to_bytes());
    format!("did:key:z{}", bs58::encode(prefixed).into_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T5.2 — store / load signing seed round-trips through a
    /// MemorySecureKeyStore. `load_signing_seed` returns None on a
    /// fresh store; `store_signing_seed` followed by
    /// `load_signing_seed` returns the same 32-byte material plus the
    /// derived did:key.
    #[test]
    fn signing_seed_round_trips_through_memory_store() {
        let store = MemorySecureKeyStore::new();
        assert!(load_signing_seed(&store).unwrap().is_none());

        let seed = [11u8; 32];
        let saved = store_signing_seed(&store, &seed).expect("store");
        assert_eq!(saved.seed, seed);
        assert!(saved.device_did.starts_with("did:key:z"));

        let loaded = load_signing_seed(&store)
            .expect("load")
            .expect("seed present");
        assert_eq!(loaded.seed, seed);
        assert_eq!(loaded.device_did, saved.device_did);
    }

    /// `ensure_signing_seed` generates a fresh seed when none exists
    /// and is idempotent on subsequent calls.
    #[test]
    fn ensure_signing_seed_generates_and_is_idempotent() {
        let store = MemorySecureKeyStore::new();
        let first = ensure_signing_seed(&store).expect("first");
        // Seed must be non-trivial.
        assert!(first.seed.iter().any(|b| *b != 0));
        let second = ensure_signing_seed(&store).expect("second");
        assert_eq!(first.seed, second.seed);
        assert_eq!(first.device_did, second.device_did);
    }

    /// Corrupt entry → backend error so the boot path surfaces a
    /// "rotate identity" warning instead of silently regenerating.
    #[test]
    fn load_signing_seed_rejects_short_entries() {
        let store = MemorySecureKeyStore::new();
        store
            .store_secret(SIGNING_SEED_KEY, &STANDARD_NO_PAD.encode([1u8; 16]))
            .unwrap();
        let err = load_signing_seed(&store).unwrap_err();
        assert!(matches!(err, SecureKeyStoreError::Backend(_)));
    }

    /// The AEAD wrap helper MUST be a real ChaCha20-Poly1305 wrap —
    /// round-trip recovers the
    /// plaintext, identical inputs produce different ciphertexts
    /// (random nonce), and decryption with the wrong key fails
    /// closed.
    #[test]
    fn wrap_secret_round_trips_and_is_nonce_unique() {
        let key = [0x42u8; 32];
        let secret = "rt-1234567890";

        let wrapped_a = wrap_secret(secret, &key).expect("wrap a");
        let wrapped_b = wrap_secret(secret, &key).expect("wrap b");
        // Random nonce → identical plaintexts encrypt to distinct
        // ciphertexts.
        assert_ne!(wrapped_a, wrapped_b);

        let recovered = unwrap_secret(&wrapped_a, &key).expect("unwrap a");
        assert_eq!(recovered.as_deref(), Some(secret));

        // Wrong key → MAC fails → None (we collapse decrypt errors
        // into None so callers see "secret missing or corrupt").
        let wrong_key = [0x21u8; 32];
        let recovered_wrong = unwrap_secret(&wrapped_a, &wrong_key).expect("unwrap call ok");
        assert!(recovered_wrong.is_none());

        // Tampered ciphertext → also None.
        let mut tampered = wrapped_a.into_bytes();
        let last_idx = tampered.len() - 1;
        // Flip a single base64 character — close to guaranteed to break
        // the MAC.
        tampered[last_idx] = if tampered[last_idx] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let tampered = String::from_utf8(tampered).unwrap();
        let recovered_tampered = unwrap_secret(&tampered, &key).expect("unwrap call ok");
        assert!(recovered_tampered.is_none());
    }

    /// Malformed input (non-base64, too short to carry a nonce, etc.)
    /// MUST not panic — the helper
    /// returns Ok(None) so callers treat it the same as "secret
    /// missing".
    #[test]
    fn unwrap_secret_tolerates_malformed_blobs() {
        let key = [0x10u8; 32];
        assert!(unwrap_secret("not-base64-@@!!", &key).unwrap().is_none());
        assert!(unwrap_secret("", &key).unwrap().is_none());
        // Valid base64 but shorter than 12 bytes (no nonce).
        assert!(
            unwrap_secret(&STANDARD_NO_PAD.encode([0u8; 8]), &key)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn memory_store_round_trips_a_secret() {
        let store = MemorySecureKeyStore::new();
        assert!(store.is_empty());

        store
            .store_secret("oidc.refresh_token", "rt-secret-value")
            .expect("store");
        assert_eq!(store.len(), 1);

        let loaded = store
            .get_secret("oidc.refresh_token")
            .expect("get")
            .expect("present");
        assert_eq!(loaded, "rt-secret-value");
    }

    #[test]
    fn memory_store_overwrites_existing_entry() {
        let store = MemorySecureKeyStore::new();
        store.store_secret("k", "v1").unwrap();
        store.store_secret("k", "v2").unwrap();
        assert_eq!(store.get_secret("k").unwrap().as_deref(), Some("v2"));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn memory_store_returns_none_for_missing_key() {
        let store = MemorySecureKeyStore::new();
        assert!(store.get_secret("absent").unwrap().is_none());
    }

    #[test]
    fn memory_store_delete_is_idempotent() {
        let store = MemorySecureKeyStore::new();
        store.delete_secret("never-stored").expect("idempotent");
        store.store_secret("k", "v").unwrap();
        store.delete_secret("k").expect("delete");
        assert!(store.get_secret("k").unwrap().is_none());
        store.delete_secret("k").expect("idempotent second delete");
    }

    #[test]
    fn memory_store_clones_share_state() {
        let a = MemorySecureKeyStore::new();
        let b = a.clone();
        a.store_secret("shared", "value").unwrap();
        assert_eq!(b.get_secret("shared").unwrap().as_deref(), Some("value"));
    }

    #[test]
    fn memory_store_debug_does_not_leak_secret_values() {
        let store = MemorySecureKeyStore::new();
        store
            .store_secret("oidc.refresh_token", "extremely-sensitive-token")
            .unwrap();
        let debug = format!("{store:?}");
        assert!(
            !debug.contains("extremely-sensitive-token"),
            "Debug must NEVER include secret values, got: {debug}"
        );
        assert!(
            !debug.contains("oidc.refresh_token"),
            "Debug should not leak key names either, got: {debug}"
        );
    }

    #[test]
    fn memory_store_advertises_correct_backend_name() {
        assert_eq!(MemorySecureKeyStore::new().backend_name(), "memory");
    }

    #[test]
    fn trait_object_dispatch_works_for_memory_backend() {
        // Sanity: the orchestrator stores `Arc<dyn SecureKeyStore>` —
        // confirm the memory impl is dyn-safe + threads through the
        // trait surface without specialisation.
        fn store_via_trait(store: &dyn SecureKeyStore, key: &str, value: &str) {
            store.store_secret(key, value).expect("store");
        }
        let store = MemorySecureKeyStore::new();
        store_via_trait(&store, "k", "v");
        assert_eq!(store.get_secret("k").unwrap().as_deref(), Some("v"));
    }

    #[test]
    fn default_secure_key_store_returns_a_usable_backend() {
        // We don't hit the OS keychain in unit tests — too easy to
        // pollute the developer's keychain with stale `yougen.test`
        // entries and to flake on locked sessions in CI. We only
        // assert that the constructor returns a value whose
        // `backend_name` matches the platform expectation.
        let store = default_secure_key_store("yougen.test.unit");
        let name = store.backend_name();
        if cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows",
        )) {
            assert_eq!(name, "keyring");
        } else if cfg!(target_os = "android") {
            assert_eq!(name, "android-keystore");
        } else if cfg!(target_os = "ios") {
            assert_eq!(name, "ios-keychain");
        } else {
            assert_eq!(name, "memory");
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows",))]
    #[test]
    fn keyring_store_exposes_service_name() {
        let store = KeyringSecureKeyStore::new("yougen.test.unit");
        assert_eq!(store.service_name(), "yougen.test.unit");
        assert_eq!(store.backend_name(), "keyring");
    }

    /// Android Keystore store constructed against an explicit in-memory
    /// bridge round-trips secrets through the bridge. store/get/delete
    /// work because the host-bridge pattern moves the FFI out of yougen
    /// and into a pluggable trait. A real Android build wires a
    /// JNI-backed bridge here;
    /// this test wires `MemorySecureKeyStore` behind a thin adapter
    /// so the surface compiles + functions on any target.
    #[cfg(target_os = "android")]
    #[test]
    fn android_keystore_via_bridge_round_trips_secrets() {
        let bridge: Arc<dyn HostSecretBridge> =
            Arc::new(TestHostSecretBridge::new("android-keystore"));
        let store = AndroidKeystoreSecureKeyStore::new_with_bridge("yougen.test.unit", bridge);
        assert_eq!(store.service_name(), "yougen.test.unit");
        assert_eq!(store.backend_name(), "android-keystore");
        store.store_secret("refresh_token", "rt-123").unwrap();
        assert_eq!(
            store.get_secret("refresh_token").unwrap().as_deref(),
            Some("rt-123")
        );
        store.delete_secret("refresh_token").unwrap();
        assert_eq!(store.get_secret("refresh_token").unwrap(), None);
    }

    /// Matching iOS test — same rationale as the Android case above.
    #[cfg(target_os = "ios")]
    #[test]
    fn ios_keychain_via_bridge_round_trips_secrets() {
        let bridge: Arc<dyn HostSecretBridge> = Arc::new(TestHostSecretBridge::new("ios-keychain"));
        let store = IosKeychainSecureKeyStore::new_with_bridge("yougen.test.unit", bridge);
        assert_eq!(store.service_name(), "yougen.test.unit");
        assert_eq!(store.backend_name(), "ios-keychain");
        store.store_secret("refresh_token", "rt-123").unwrap();
        assert_eq!(
            store.get_secret("refresh_token").unwrap().as_deref(),
            Some("rt-123")
        );
        store.delete_secret("refresh_token").unwrap();
        assert_eq!(store.get_secret("refresh_token").unwrap(), None);
    }

    /// HostBridgeSecureKeyStore wires the right service_name + key
    /// tuple through to the bridge.
    /// Exercised cross-target because the bridge contract MUST be
    /// callable from non-mobile builds too (it's the same trait
    /// surface).
    #[test]
    fn host_bridge_store_namespaces_by_service_name() {
        let bridge: Arc<dyn HostSecretBridge> = Arc::new(TestHostSecretBridge::new("test-bridge"));
        let store_a = HostBridgeSecureKeyStore::new("svc.a", bridge.clone());
        let store_b = HostBridgeSecureKeyStore::new("svc.b", bridge.clone());
        store_a.store_secret("k", "v-a").unwrap();
        store_b.store_secret("k", "v-b").unwrap();
        assert_eq!(store_a.get_secret("k").unwrap().as_deref(), Some("v-a"));
        assert_eq!(store_b.get_secret("k").unwrap().as_deref(), Some("v-b"));
        // Deleting from store_a must not affect store_b — service_name
        // is part of the bridge key tuple.
        store_a.delete_secret("k").unwrap();
        assert_eq!(store_a.get_secret("k").unwrap(), None);
        assert_eq!(store_b.get_secret("k").unwrap().as_deref(), Some("v-b"));
    }

    /// `backend_name` flows from the bridge's `backend_label` so
    /// diagnostic UI can distinguish
    /// Android Keystore vs iOS Keychain.
    #[test]
    fn host_bridge_store_surface_backend_label_from_bridge() {
        let bridge: Arc<dyn HostSecretBridge> = Arc::new(TestHostSecretBridge::new("custom-label"));
        let store = HostBridgeSecureKeyStore::new("svc", bridge);
        assert_eq!(store.backend_name(), "custom-label");
    }

    /// In-process [`HostSecretBridge`] used by mobile-platform unit
    /// tests so the round-trip can run on any target. Stores entries
    /// in a `(service_name, key) -> value` map. NOT a real Android /
    /// iOS implementation — production hosts wire JNI / Security.framework.
    struct TestHostSecretBridge {
        label: &'static str,
        inner: std::sync::Mutex<std::collections::HashMap<(String, String), String>>,
    }

    impl TestHostSecretBridge {
        fn new(label: &'static str) -> Self {
            Self {
                label,
                inner: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }
    }

    impl HostSecretBridge for TestHostSecretBridge {
        fn put(
            &self,
            service_name: &str,
            key: &str,
            value: &str,
        ) -> Result<(), SecureKeyStoreError> {
            let mut guard = self
                .inner
                .lock()
                .map_err(|err| SecureKeyStoreError::Backend(format!("lock: {err}")))?;
            guard.insert((service_name.to_owned(), key.to_owned()), value.to_owned());
            Ok(())
        }
        fn get(
            &self,
            service_name: &str,
            key: &str,
        ) -> Result<Option<String>, SecureKeyStoreError> {
            let guard = self
                .inner
                .lock()
                .map_err(|err| SecureKeyStoreError::Backend(format!("lock: {err}")))?;
            Ok(guard
                .get(&(service_name.to_owned(), key.to_owned()))
                .cloned())
        }
        fn delete(&self, service_name: &str, key: &str) -> Result<(), SecureKeyStoreError> {
            let mut guard = self
                .inner
                .lock()
                .map_err(|err| SecureKeyStoreError::Backend(format!("lock: {err}")))?;
            guard.remove(&(service_name.to_owned(), key.to_owned()));
            Ok(())
        }
        fn backend_label(&self) -> &'static str {
            self.label
        }
    }
}
