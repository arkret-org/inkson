//! Desktop SDK platform-key-store adapter (macOS / Linux / Windows).

#![cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]

use std::fmt;

use arkret_sdk::{KeyBytes, KeyStore, KeyStoreError, durable_platform_keystore};
use garth::{SdkKeyStoreSecureAdapter, SecureKeyStoreBackendInfo};

use super::{SecureKeyStore, SecureKeyStoreError};

/// Local newtype that lets garth's canonical adapter own the SDK trait object.
struct PlatformKeyStore(Box<dyn KeyStore>);

// The Linux backend uses blocking zbus/SecretService APIs that enter their
// own Tokio runtime. Neither construction nor an operation may run inside
// Dioxus's UI runtime. Scoped threads preserve borrowed inputs and the
// synchronous KeyStore contract without swallowing a backend panic.
fn platform_backend_call<T: Send>(operation: impl FnOnce() -> T + Send) -> T {
    #[cfg(target_os = "linux")]
    {
        std::thread::scope(|scope| {
            scope
                .spawn(operation)
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        operation()
    }
}

impl fmt::Debug for PlatformKeyStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PlatformKeyStore(..)")
    }
}

impl KeyStore for PlatformKeyStore {
    fn load(&self, id: &str) -> Result<KeyBytes, KeyStoreError> {
        platform_backend_call(|| self.0.load(id))
    }

    fn store(&self, id: &str, key: &[u8]) -> Result<(), KeyStoreError> {
        platform_backend_call(|| self.0.store(id, key))
    }

    fn list(&self) -> Result<Vec<String>, KeyStoreError> {
        platform_backend_call(|| self.0.list())
    }

    fn delete(&self, id: &str) -> Result<(), KeyStoreError> {
        platform_backend_call(|| self.0.delete(id))
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
        Self::with_backend_factory(application_id.into(), durable_platform_keystore)
    }

    fn with_backend_factory(
        application_id: String,
        make_backend: impl FnOnce(&str) -> Result<Box<dyn KeyStore>, KeyStoreError> + Send,
    ) -> Self {
        let inner = platform_backend_call(|| make_backend(&application_id))
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

#[cfg(all(test, target_os = "linux"))]
mod linux_runtime_tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    struct RuntimeSensitiveBackend {
        value: Mutex<Option<Vec<u8>>>,
        visits: Arc<Mutex<Vec<&'static str>>>,
    }

    fn visit_without_ui_runtime(visits: &Mutex<Vec<&'static str>>, operation: &'static str) {
        assert!(tokio::runtime::Handle::try_current().is_err());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert_eq!(runtime.block_on(async { 7 }), 7);
        visits.lock().unwrap().push(operation);
    }

    impl KeyStore for RuntimeSensitiveBackend {
        fn load(&self, id: &str) -> Result<KeyBytes, KeyStoreError> {
            visit_without_ui_runtime(&self.visits, "load");
            if id == "panic" {
                std::panic::panic_any(19_u32);
            }
            if id == "error" {
                return Err(KeyStoreError::backend("original backend failure"));
            }
            self.value
                .lock()
                .unwrap()
                .clone()
                .map(KeyBytes::new)
                .ok_or_else(|| KeyStoreError::not_found(id))
        }

        fn store(&self, _id: &str, key: &[u8]) -> Result<(), KeyStoreError> {
            visit_without_ui_runtime(&self.visits, "store");
            *self.value.lock().unwrap() = Some(key.to_vec());
            Ok(())
        }

        fn list(&self) -> Result<Vec<String>, KeyStoreError> {
            visit_without_ui_runtime(&self.visits, "list");
            Ok(if self.value.lock().unwrap().is_some() {
                vec!["recovery-key.v1".to_owned()]
            } else {
                Vec::new()
            })
        }

        fn delete(&self, _id: &str) -> Result<(), KeyStoreError> {
            visit_without_ui_runtime(&self.visits, "delete");
            *self.value.lock().unwrap() = None;
            Ok(())
        }
    }

    fn runtime_sensitive_store(visits: Arc<Mutex<Vec<&'static str>>>) -> KeyringSecureKeyStore {
        KeyringSecureKeyStore::with_backend_factory("inkson".to_owned(), move |application| {
            assert_eq!(application, "inkson");
            visit_without_ui_runtime(&visits, "construct");
            Ok(Box::new(RuntimeSensitiveBackend {
                value: Mutex::new(None),
                visits,
            }))
        })
    }

    #[tokio::test]
    async fn mock_constructor_and_all_operations_leave_the_ui_tokio_runtime() {
        assert!(tokio::runtime::Handle::try_current().is_ok());
        let visits = Arc::new(Mutex::new(Vec::new()));
        let store = runtime_sensitive_store(visits.clone());
        assert!(store.get_secret_bytes("recovery-key.v1").unwrap().is_none());
        store
            .store_secret_bytes("recovery-key.v1", b"probe")
            .unwrap();
        assert_eq!(
            store
                .get_secret_bytes("recovery-key.v1")
                .unwrap()
                .unwrap()
                .as_slice(),
            b"probe"
        );
        assert_eq!(
            store.list_secret_keys(Some("recovery")).unwrap(),
            vec!["recovery-key.v1"]
        );
        store.delete_secret("recovery-key.v1").unwrap();
        assert!(store.get_secret_bytes("recovery-key.v1").unwrap().is_none());
        assert_eq!(
            *visits.lock().unwrap(),
            [
                "construct",
                "load",
                "store",
                "load",
                "list",
                "delete",
                "load"
            ]
        );
        assert!(tokio::runtime::Handle::try_current().is_ok());
    }

    #[tokio::test]
    async fn mock_backend_errors_and_original_panic_payload_reach_the_ui_caller() {
        let failed = KeyringSecureKeyStore::with_backend_factory("inkson".to_owned(), |_| {
            assert!(tokio::runtime::Handle::try_current().is_err());
            Err(KeyStoreError::backend("original constructor failure"))
        });
        assert!(
            matches!(failed.get_secret_bytes("recovery-key.v1"), Err(SecureKeyStoreError::Backend(error)) if error.contains("original constructor failure"))
        );
        let store = runtime_sensitive_store(Arc::new(Mutex::new(Vec::new())));
        assert!(
            matches!(store.get_secret_bytes("error"), Err(SecureKeyStoreError::Backend(error)) if error.contains("original backend failure"))
        );
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store.get_secret_bytes("panic")
        }))
        .unwrap_err();
        assert_eq!(panic.downcast_ref::<u32>(), Some(&19));
        let panic = std::panic::catch_unwind(|| {
            KeyringSecureKeyStore::with_backend_factory("inkson".to_owned(), |_| {
                std::panic::panic_any(11_u32)
            })
        })
        .unwrap_err();
        assert_eq!(panic.downcast_ref::<u32>(), Some(&11));
    }

    #[tokio::test]
    #[ignore = "requires the Packages runner's isolated live SecretService lease"]
    async fn secret_service_round_trip_from_the_ui_tokio_runtime() {
        assert_eq!(
            std::env::var("COTEST_LINUX_KEYSTORE_PROBE").as_deref(),
            Ok("1")
        );
        assert!(tokio::runtime::Handle::try_current().is_ok());
        let user = crate::secure_key_store::UserLocalStore::new(
            arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
            ),
            arkret_sdk::DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap(),
        )
        .unwrap();
        let key = user.secret_key("recovery-key.v1");
        let first = KeyringSecureKeyStore::new("inkson");
        assert!(first.get_secret_bytes(&key).unwrap().is_none());
        first.store_secret_bytes(&key, b"probe").unwrap();
        let reopened = KeyringSecureKeyStore::new("inkson");
        assert_eq!(
            reopened.get_secret_bytes(&key).unwrap().unwrap().as_slice(),
            b"probe"
        );
        assert_eq!(
            reopened.list_secret_keys(Some(&key)).unwrap(),
            vec![key.clone()]
        );
        reopened.store_secret_bytes(&key, b"rotated").unwrap();
        assert_eq!(
            first.get_secret_bytes(&key).unwrap().unwrap().as_slice(),
            b"rotated"
        );
        reopened.delete_secret(&key).unwrap();
        let cold = KeyringSecureKeyStore::new("inkson");
        assert!(cold.get_secret_bytes(&key).unwrap().is_none());
        assert!(cold.list_secret_keys(Some(&key)).unwrap().is_empty());
        assert!(tokio::runtime::Handle::try_current().is_ok());
    }
}

impl SecureKeyStore for KeyringSecureKeyStore {
    fn store_secret_bytes(&self, key: &str, value: &[u8]) -> Result<(), SecureKeyStoreError> {
        self.inner()?.store_secret_bytes(key, value)
    }

    fn get_secret_bytes(&self, key: &str) -> Result<Option<KeyBytes>, SecureKeyStoreError> {
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
