//! wasm32-only primary/fallback compositing [`SecureKeyStore`].

#![cfg(target_arch = "wasm32")]

use std::collections::BTreeSet;
use std::sync::Arc;

use garth::{SecretBytes, SecureKeyStoreBackendInfo};

use super::{SecureKeyStore, SecureKeyStoreError, WASM_INDEXEDDB_SECURE_KEY_STORE_BACKEND};

pub(super) struct FallbackSecureKeyStore {
    primary: Arc<dyn SecureKeyStore>,
    fallback: Arc<dyn SecureKeyStore>,
}

impl FallbackSecureKeyStore {
    pub(super) fn new(primary: Arc<dyn SecureKeyStore>, fallback: Arc<dyn SecureKeyStore>) -> Self {
        Self { primary, fallback }
    }
}

impl std::fmt::Debug for FallbackSecureKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FallbackSecureKeyStore")
            .field("primary", &self.primary.backend_name())
            .field("fallback", &self.fallback.backend_name())
            .finish()
    }
}

impl SecureKeyStore for FallbackSecureKeyStore {
    fn store_secret_bytes(&self, key: &str, value: &[u8]) -> Result<(), SecureKeyStoreError> {
        match self.primary.store_secret_bytes(key, value) {
            Ok(()) => {
                let _ = self.fallback.store_secret_bytes(key, value);
                Ok(())
            }
            Err(primary_err) => match self.fallback.store_secret_bytes(key, value) {
                Ok(()) => Ok(()),
                Err(fallback_err) => Err(SecureKeyStoreError::Backend(format!(
                    "primary secure store write failed: {primary_err}; fallback write failed: {fallback_err}"
                ))),
            },
        }
    }

    fn store_secret_bytes_durable<'a>(
        &'a self,
        key: &'a str,
        value: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SecureKeyStoreError>> + 'a>>
    {
        Box::pin(async move {
            // Await the primary (IndexedDB) durable write. Required-IndexedDB
            // keys (e.g. the MLS KeyPackage init key) only live in the primary;
            // the localStorage fallback refuses them, so a best-effort mirror is
            // all the fallback can offer for the rest.
            match self.primary.store_secret_bytes_durable(key, value).await {
                Ok(()) => {
                    let _ = self.fallback.store_secret_bytes(key, value);
                    Ok(())
                }
                Err(primary_err) => match self.fallback.store_secret_bytes(key, value) {
                    Ok(()) => Ok(()),
                    Err(fallback_err) => Err(SecureKeyStoreError::Backend(format!(
                        "primary durable secure store write failed: {primary_err}; fallback write failed: {fallback_err}"
                    ))),
                },
            }
        })
    }

    fn get_secret_bytes(&self, key: &str) -> Result<Option<SecretBytes>, SecureKeyStoreError> {
        match self.primary.get_secret_bytes(key) {
            Ok(Some(secret)) => Ok(Some(secret)),
            Ok(None) => match self.fallback.get_secret_bytes(key) {
                Ok(secret) => Ok(secret),
                Err(SecureKeyStoreError::Unsupported(_)) => Ok(None),
                Err(err) => Err(err),
            },
            Err(primary_err) => match self.fallback.get_secret_bytes(key) {
                Ok(Some(secret)) => Ok(Some(secret)),
                Ok(None) | Err(_) => Err(primary_err),
            },
        }
    }

    fn delete_secret(&self, key: &str) -> Result<(), SecureKeyStoreError> {
        let primary = self.primary.delete_secret(key);
        let _ = self.fallback.delete_secret(key);
        primary
    }

    fn list_secret_keys(&self, prefix: Option<&str>) -> Result<Vec<String>, SecureKeyStoreError> {
        // Union of both tiers' keys (a secret may live only in one). Ignore a
        // tier that cannot enumerate rather than failing the whole listing.
        let mut keys: BTreeSet<String> = BTreeSet::new();
        if let Ok(primary_keys) = self.primary.list_secret_keys(prefix) {
            keys.extend(primary_keys);
        }
        if let Ok(fallback_keys) = self.fallback.list_secret_keys(prefix) {
            keys.extend(fallback_keys);
        }
        Ok(keys.into_iter().collect())
    }

    fn backend_info(&self) -> SecureKeyStoreBackendInfo {
        SecureKeyStoreBackendInfo {
            // Preserved verbatim: reports the primary (IndexedDB) tier identity.
            name: WASM_INDEXEDDB_SECURE_KEY_STORE_BACKEND,
            hardware_backed: false,
            exportable: false,
        }
    }
}
