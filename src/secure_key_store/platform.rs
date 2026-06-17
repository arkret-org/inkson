//! Mobile platform thin wrappers: Android Keystore + iOS Keychain
//! stores delegating to the host bridge.

#[cfg(any(
    feature = "mobile-android",
    target_os = "android",
    feature = "mobile-ios",
    target_os = "ios"
))]
use std::sync::Arc;

#[cfg(any(
    feature = "mobile-android",
    target_os = "android",
    feature = "mobile-ios",
    target_os = "ios"
))]
use super::{HostBridgeSecureKeyStore, HostSecretBridge, SecureKeyStore, SecureKeyStoreError};

/// Android Keystore-backed secret store. On `target_os = "android"`
/// this is a thin wrapper around [`HostBridgeSecureKeyStore`] — the
/// real FFI work happens in the host runtime's
/// [`HostSecretBridge`] implementation (typically a JNI shim against
/// `java.security.KeyStore` with provider `"AndroidKeyStore"`).
///
/// See the [`HostSecretBridge`] doc-comment for the full contract.
///
/// **Feature gating**: compiled when either the target is
/// `target_os = "android"` (native mobile build) OR the `mobile-android`
/// crate feature is enabled (e.g. desktop cross-compile-check). Desktop
/// / wasm builds without that feature do not see this type, so the
/// host-bridge stub code is dropped from those binaries.
#[cfg(any(feature = "mobile-android", target_os = "android"))]
#[derive(Clone, Debug)]
pub struct AndroidKeystoreSecureKeyStore {
    inner: HostBridgeSecureKeyStore,
}

#[cfg(any(feature = "mobile-android", target_os = "android"))]
impl AndroidKeystoreSecureKeyStore {
    /// Construct a store delegating to the installed
    /// [`HostSecretBridge`]. Returns `None` when no bridge has been
    /// registered; callers should fall back to
    /// [`super::MemorySecureKeyStore`] in that case.
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

#[cfg(any(feature = "mobile-android", target_os = "android"))]
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
///
/// **Feature gating**: compiled when either the target is
/// `target_os = "ios"` (native mobile build) OR the `mobile-ios` crate
/// feature is enabled (e.g. desktop cross-compile-check). Desktop / wasm
/// builds without that feature do not see this type, so the host-bridge
/// stub code is dropped from those binaries.
#[cfg(any(feature = "mobile-ios", target_os = "ios"))]
#[derive(Clone, Debug)]
pub struct IosKeychainSecureKeyStore {
    inner: HostBridgeSecureKeyStore,
}

#[cfg(any(feature = "mobile-ios", target_os = "ios"))]
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

#[cfg(any(feature = "mobile-ios", target_os = "ios"))]
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
