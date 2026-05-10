//! Round 33 (C33.2): platform-secure secret storage.
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
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
))]
#[derive(Clone, Debug)]
pub struct KeyringSecureKeyStore {
    service_name: String,
}

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
))]
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

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
))]
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

/// Android Keystore-backed secret store (C34.1 stub).
///
/// On `target_os = "android"` the production wiring will bridge into
/// the platform `java.security.KeyStore` (provider `"AndroidKeyStore"`)
/// through a JNI shim — typically dispatched by the Dioxus mobile
/// runtime which owns the `JNIEnv` for the calling thread. The stub
/// here pins the *Rust-side* trait surface so the rest of the crate
/// can hand callers an `Arc<dyn SecureKeyStore>` selected at compile
/// time, and so the FFI wire-up can happen in isolation without
/// re-touching every call site that holds a key store.
///
/// All methods currently `unimplemented!()` — the surface is interface
/// only. Hosts that want a working secret store on Android today
/// should explicitly construct [`MemorySecureKeyStore`] (with the
/// usual "secrets in plaintext heap" caveat) and revisit once the FFI
/// shim lands.
#[cfg(target_os = "android")]
#[derive(Clone, Debug)]
pub struct AndroidKeystoreSecureKeyStore {
    service_name: String,
}

#[cfg(target_os = "android")]
impl AndroidKeystoreSecureKeyStore {
    /// Construct a store whose entries land under `service_name`.
    /// Conventional value: `"yougen"`. The service name is currently
    /// only retained for diagnostic UI; the Android Keystore alias
    /// scheme will be `"<service_name>:<key>"` once the JNI shim is
    /// wired.
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }
}

#[cfg(target_os = "android")]
impl SecureKeyStore for AndroidKeystoreSecureKeyStore {
    fn store_secret(&self, _key: &str, _value: &str) -> Result<(), SecureKeyStoreError> {
        unimplemented!(
            "android keystore FFI pending wire-up: bridge to java.security.KeyStore \
             via the Dioxus mobile JNIEnv handle"
        )
    }

    fn get_secret(&self, _key: &str) -> Result<Option<String>, SecureKeyStoreError> {
        unimplemented!(
            "android keystore FFI pending wire-up: bridge to java.security.KeyStore \
             via the Dioxus mobile JNIEnv handle"
        )
    }

    fn delete_secret(&self, _key: &str) -> Result<(), SecureKeyStoreError> {
        unimplemented!(
            "android keystore FFI pending wire-up: bridge to java.security.KeyStore \
             via the Dioxus mobile JNIEnv handle"
        )
    }

    fn backend_name(&self) -> &'static str {
        "android-keystore"
    }
}

/// iOS Keychain-backed secret store (C34.1 stub).
///
/// On `target_os = "ios"` the production wiring will bridge into
/// `Security.framework` — `SecItemAdd` / `SecItemCopyMatching` /
/// `SecItemDelete` against the `kSecClassGenericPassword` class — via
/// an Objective-C / Swift shim exposed through `extern "C"` symbols.
/// The shim should set `kSecAttrAccessible` to
/// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` so secrets are
/// not synchronised through iCloud Keychain by default.
///
/// All methods currently `unimplemented!()` — the surface is interface
/// only. See [`AndroidKeystoreSecureKeyStore`] for the matching
/// rationale.
#[cfg(target_os = "ios")]
#[derive(Clone, Debug)]
pub struct IosKeychainSecureKeyStore {
    service_name: String,
}

#[cfg(target_os = "ios")]
impl IosKeychainSecureKeyStore {
    /// Construct a store whose entries land under `service_name`.
    /// Conventional value: `"yougen"`. Stamped onto the keychain item
    /// `kSecAttrService` attribute by the Security.framework shim.
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }
}

#[cfg(target_os = "ios")]
impl SecureKeyStore for IosKeychainSecureKeyStore {
    fn store_secret(&self, _key: &str, _value: &str) -> Result<(), SecureKeyStoreError> {
        unimplemented!(
            "ios keychain FFI pending wire-up: bridge to Security.framework \
             SecItemAdd/SecItemCopyMatching/SecItemDelete with \
             kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"
        )
    }

    fn get_secret(&self, _key: &str) -> Result<Option<String>, SecureKeyStoreError> {
        unimplemented!(
            "ios keychain FFI pending wire-up: bridge to Security.framework \
             SecItemAdd/SecItemCopyMatching/SecItemDelete with \
             kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"
        )
    }

    fn delete_secret(&self, _key: &str) -> Result<(), SecureKeyStoreError> {
        unimplemented!(
            "ios keychain FFI pending wire-up: bridge to Security.framework \
             SecItemAdd/SecItemCopyMatching/SecItemDelete with \
             kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"
        )
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
pub fn default_secure_key_store(service_name: &str) -> Arc<dyn SecureKeyStore> {
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
    ))]
    {
        Arc::new(KeyringSecureKeyStore::new(service_name.to_owned()))
    }
    #[cfg(target_os = "android")]
    {
        Arc::new(AndroidKeystoreSecureKeyStore::new(service_name.to_owned()))
    }
    #[cfg(target_os = "ios")]
    {
        Arc::new(IosKeychainSecureKeyStore::new(service_name.to_owned()))
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "android",
        target_os = "ios",
    )))]
    {
        // wasm32 stays on the in-memory fallback until we add an
        // IndexedDB+WebCrypto wrapper. Other unknown targets also land
        // here.
        let _ = service_name; // suppress unused warning on wasm
        Arc::new(MemorySecureKeyStore::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
    ))]
    #[test]
    fn keyring_store_exposes_service_name() {
        let store = KeyringSecureKeyStore::new("yougen.test.unit");
        assert_eq!(store.service_name(), "yougen.test.unit");
        assert_eq!(store.backend_name(), "keyring");
    }

    /// C34.1: ensure the Android stub trait surface compiles + the
    /// metadata accessors do not panic. The store/get/delete methods
    /// `unimplemented!()` until the JNI shim lands, so we deliberately
    /// avoid touching them from unit tests.
    #[cfg(target_os = "android")]
    #[test]
    fn android_keystore_stub_metadata_is_stable() {
        let store = AndroidKeystoreSecureKeyStore::new("yougen.test.unit");
        assert_eq!(store.service_name(), "yougen.test.unit");
        assert_eq!(store.backend_name(), "android-keystore");
        // Trait-object construction must succeed at compile time so the
        // dyn-dispatched call sites in `default_secure_key_store` stay
        // sound once the FFI lands.
        let _: Arc<dyn SecureKeyStore> = Arc::new(store);
    }

    /// C34.1: matching iOS stub metadata test — same rationale as the
    /// Android case above.
    #[cfg(target_os = "ios")]
    #[test]
    fn ios_keychain_stub_metadata_is_stable() {
        let store = IosKeychainSecureKeyStore::new("yougen.test.unit");
        assert_eq!(store.service_name(), "yougen.test.unit");
        assert_eq!(store.backend_name(), "ios-keychain");
        let _: Arc<dyn SecureKeyStore> = Arc::new(store);
    }
}
