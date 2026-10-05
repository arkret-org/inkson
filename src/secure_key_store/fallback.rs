//! wasm32-only primary/fallback compositing [`SecureKeyStore`].
//!
//! This is **not** a migration bridge between an old and a new backend. Both
//! tiers are current, and the reason there are two is that the browser gives
//! inkson no synchronous path to its strong one:
//!
//! * `IndexedDbSecureKeyStore` (primary) needs `await` to open the database and to derive its
//!   non-extractable SubtleCrypto wrapping key, so it does not exist during the first synchronous
//!   paint.
//! * `LocalStorageSecureKeyStore` (fallback) is synchronous and therefore is the only store
//!   `default_secure_key_store` can hand out before `initialize_wasm_secure_key_store_async` has
//!   run.
//!
//! Only non-sensitive writes mirror into the fallback tier: the reader of that
//! mirror is the *next* page load's pre-initialization seam, which can see
//! nothing but `localStorage`. Dropping the mirror would make first-paint
//! reads miss values this session wrote.
//!
//! Durability is the only thing the mirror buys, never a weaker protection
//! level: `is_wasm_indexeddb_required_secret_key` makes the fallback tier
//! *refuse* signing seeds, identity seeds, account MLS material, session
//! credentials and the account state blob, so those keys stay IndexedDB-only.
//! Primary failures for those keys propagate without trying the weaker tier. Reads resolve
//! primary-first, so an entry present in both always answers from IndexedDB.

#![cfg(target_arch = "wasm32")]

use std::collections::BTreeSet;
use std::sync::Arc;

use arkret_sdk::KeyBytes;
use garth::SecureKeyStoreBackendInfo;

use super::{SecureKeyStore, SecureKeyStoreError, WASM_INDEXEDDB_SECURE_KEY_STORE_BACKEND};

pub(super) struct FallbackSecureKeyStore {
    primary: Arc<dyn SecureKeyStore + Send + Sync>,
    fallback: Arc<dyn SecureKeyStore + Send + Sync>,
}

impl FallbackSecureKeyStore {
    pub(super) fn new(
        primary: Arc<dyn SecureKeyStore + Send + Sync>,
        fallback: Arc<dyn SecureKeyStore + Send + Sync>,
    ) -> Self {
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
        if super::is_wasm_indexeddb_required_secret_key(key) {
            return self.primary.store_secret_bytes(key, value);
        }
        match self.primary.store_secret_bytes(key, value) {
            Ok(()) => {
                // Best-effort mirror for the next boot's synchronous seam (see
                // the module doc). IndexedDB-only keys are rejected by the
                // fallback tier by design, so the error is discarded rather
                // than failing a write the primary already committed.
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
            if super::is_wasm_indexeddb_required_secret_key(key) {
                return self.primary.store_secret_bytes_durable(key, value).await;
            }
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

    fn get_secret_bytes(&self, key: &str) -> Result<Option<KeyBytes>, SecureKeyStoreError> {
        if super::is_wasm_indexeddb_required_secret_key(key) {
            return self.primary.get_secret_bytes(key);
        }
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

    fn read_secret_bytes_durable<'a>(
        &'a self,
        key: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<KeyBytes>, SecureKeyStoreError>> + 'a>,
    > {
        // A cache or localStorage mirror cannot establish the committed value.
        self.primary.read_secret_bytes_durable(key)
    }

    fn compare_exchange_secret_bytes_durable<'a>(
        &'a self,
        key: &'a str,
        expected: Option<&'a [u8]>,
        replacement: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, SecureKeyStoreError>> + 'a>>
    {
        // Atomic authoring stays wholly in the primary backend. Never mirror
        // or fall back after a conflict or an unavailable transaction.
        self.primary
            .compare_exchange_secret_bytes_durable(key, expected, replacement)
    }

    fn delete_secret(&self, key: &str) -> Result<(), SecureKeyStoreError> {
        let primary = self.primary.delete_secret(key);
        let _ = self.fallback.delete_secret(key);
        primary
    }

    fn delete_secret_durable<'a>(
        &'a self,
        key: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SecureKeyStoreError>> + 'a>>
    {
        Box::pin(async move {
            self.primary.delete_secret_durable(key).await?;
            let _ = self.fallback.delete_secret(key);
            Ok(())
        })
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
