//! Desktop SDK platform-key-store adapter (macOS / Linux / Windows).

#![cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]

use std::fmt;

use arkret_sdk::{KeyBytes, KeyStore, KeyStoreError, durable_platform_keystore};
use garth::{SdkKeyStoreSecureAdapter, SecretBytes, SecureKeyStoreBackendInfo};

use super::{SecureKeyStore, SecureKeyStoreError};

/// Local newtype that lets garth's canonical adapter own the SDK trait object.
struct PlatformKeyStore(Box<dyn KeyStore>);

impl fmt::Debug for PlatformKeyStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PlatformKeyStore(..)")
    }
}

impl KeyStore for PlatformKeyStore {
    fn load(&self, id: &str) -> Result<KeyBytes, KeyStoreError> {
        self.0.load(id)
    }

    fn store(&self, id: &str, key: &[u8]) -> Result<(), KeyStoreError> {
        self.0.store(id, key)
    }

    fn list(&self) -> Result<Vec<String>, KeyStoreError> {
        self.0.list()
    }

    fn delete(&self, id: &str) -> Result<(), KeyStoreError> {
        self.0.delete(id)
    }
}

/// Desktop secure storage backed by the SDK's platform-selected durable store.
///
/// The SDK owns backend selection and service-name namespacing; Inkson only
/// adapts the canonical [`KeyStore`] contract to garth's [`SecureKeyStore`].
#[derive(Debug)]
pub struct KeyringSecureKeyStore {
    application_id: String,
    inner: Result<SdkKeyStoreSecureAdapter<PlatformKeyStore>, String>,
}

impl KeyringSecureKeyStore {
    pub fn new(application_id: impl Into<String>) -> Self {
        let application_id = application_id.into();
        let inner = durable_platform_keystore(&application_id)
            .map(PlatformKeyStore)
            .map(SdkKeyStoreSecureAdapter::new)
            .map_err(|error| error.to_string());
        Self {
            application_id,
            inner,
        }
    }

    /// Application id passed to the SDK platform backend.
    pub fn service_name(&self) -> &str {
        &self.application_id
    }

    fn inner(&self) -> Result<&SdkKeyStoreSecureAdapter<PlatformKeyStore>, SecureKeyStoreError> {
        self.inner
            .as_ref()
            .map_err(|error| SecureKeyStoreError::Backend(error.clone()))
    }
}

impl SecureKeyStore for KeyringSecureKeyStore {
    fn store_secret_bytes(&self, key: &str, value: &[u8]) -> Result<(), SecureKeyStoreError> {
        self.inner()?.store_secret_bytes(key, value)
    }

    fn get_secret_bytes(&self, key: &str) -> Result<Option<SecretBytes>, SecureKeyStoreError> {
        self.inner()?.get_secret_bytes(key)
    }

    fn delete_secret(&self, key: &str) -> Result<(), SecureKeyStoreError> {
        self.inner()?.delete_secret(key)
    }

    fn list_secret_keys(&self, prefix: Option<&str>) -> Result<Vec<String>, SecureKeyStoreError> {
        self.inner()?.list_secret_keys(prefix)
    }

    fn backend_info(&self) -> SecureKeyStoreBackendInfo {
        SecureKeyStoreBackendInfo {
            name: "sdk_platform_key_store",
            hardware_backed: false,
            exportable: true,
        }
    }
}
