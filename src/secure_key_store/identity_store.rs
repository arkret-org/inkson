//! Typed local-persistence namespaces for identity-owned client data.
//!
//! The namespace is part of the store instance, not an optional argument at
//! each read/write call. Callers pass a bare logical key; the store always
//! expands it with the validated [`DidCoreId`] supplied at construction time.
//! Pre-principal transactions use [`PendingLocalStore`].

use arkret_sdk::{DeviceId, DidCoreId};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::signing_seed::{
    SigningSeedMaterial, ensure_signing_seed_at, load_signing_seed_at, store_signing_seed_at,
};
use super::{SecureKeyStore, SecureKeyStoreError};

const PENDING_NAMESPACE: &str = "pending";
const GLOBAL_NAMESPACE: &str = "global";
const DEVICE_ID_ENTRY: &str = "device_id.v1";
const SIGNING_SEED_ENTRY: &str = "device.ed25519.signing_seed.v1";
const GRANT_BINDING_SEED_ENTRY: &str = "device.ed25519.grant_binding.v1";

fn did_core_storage_scope(principal_id: &DidCoreId) -> &str {
    principal_id
        .as_str()
        .strip_prefix("ak:did_core:")
        .unwrap_or_else(|| principal_id.as_str())
}

fn pending_storage_scope(device_id: &DeviceId) -> &str {
    device_id
        .as_str()
        .strip_prefix("ak:device:")
        .unwrap_or_else(|| device_id.as_str())
}

#[cfg(target_arch = "wasm32")]
fn browser_storage() -> Result<web_sys::Storage, SecureKeyStoreError> {
    web_sys::window()
        .ok_or_else(|| SecureKeyStoreError::Unsupported("web_sys::window unavailable"))?
        .local_storage()
        .map_err(|error| {
            SecureKeyStoreError::Backend(format!("localStorage access failed: {error:?}"))
        })?
        .ok_or_else(|| SecureKeyStoreError::Unsupported("window.localStorage unavailable"))
}

fn load_device_id(
    store: &dyn SecureKeyStore,
    storage_key: &str,
) -> Result<Option<DeviceId>, SecureKeyStoreError> {
    #[cfg(target_arch = "wasm32")]
    let raw = {
        let _ = store;
        browser_storage()?.get_item(storage_key).map_err(|error| {
            SecureKeyStoreError::Backend(format!("localStorage device_id get: {error:?}"))
        })?
    };
    #[cfg(not(target_arch = "wasm32"))]
    let raw = store.get_secret(storage_key)?;

    raw.map(|value| {
        DeviceId::new(value.trim().to_owned()).map_err(|error| {
            SecureKeyStoreError::Backend(format!("stored device_id is invalid: {error}"))
        })
    })
    .transpose()
}

fn save_device_id(
    store: &dyn SecureKeyStore,
    storage_key: &str,
    device_id: &DeviceId,
) -> Result<(), SecureKeyStoreError> {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = store;
        browser_storage()?
            .set_item(storage_key, device_id.as_str())
            .map_err(|error| {
                SecureKeyStoreError::Backend(format!("localStorage device_id set: {error:?}"))
            })
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        store.store_secret(storage_key, device_id.as_str())
    }
}

fn delete_device_id(
    store: &dyn SecureKeyStore,
    storage_key: &str,
) -> Result<(), SecureKeyStoreError> {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = store;
        browser_storage()?
            .remove_item(storage_key)
            .map_err(|error| {
                SecureKeyStoreError::Backend(format!("localStorage device_id remove: {error:?}"))
            })
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        store.delete_secret(storage_key)
    }
}

fn decode_seed_b64url(value: &str) -> Result<[u8; 32], SecureKeyStoreError> {
    let bytes = URL_SAFE_NO_PAD.decode(value.as_bytes()).map_err(|error| {
        SecureKeyStoreError::Backend(format!("grant-binding seed base64url decode: {error}"))
    })?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        SecureKeyStoreError::Backend(format!(
            "grant-binding seed length {}, expected 32",
            bytes.len()
        ))
    })
}

/// Installation/origin-wide local data.  This type deliberately has no
/// user-data methods; it only names the very small set of genuinely global
/// entries such as the secure-store wrapping seed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalLocalStore {
    application: String,
}

impl GlobalLocalStore {
    #[must_use]
    pub fn new(application: impl Into<String>) -> Self {
        Self {
            application: application.into(),
        }
    }

    /// Expand a caller-supplied logical key into an installation-global key.
    #[must_use]
    pub(crate) fn key(&self, logical_key: &str) -> String {
        format!("{}.{GLOBAL_NAMESPACE}.{logical_key}", self.application)
    }
}

/// Local data belonging to one server-authored principal.
///
/// There is intentionally no default constructor and no string/optional
/// scope. Methods accept bare logical keys and every emitted storage key
/// contains the validated core id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserLocalStore {
    principal_id: DidCoreId,
    namespace: String,
}

impl UserLocalStore {
    #[must_use]
    pub fn new(principal_id: DidCoreId) -> Self {
        let namespace = format!("inkson.{}", did_core_storage_scope(&principal_id));
        Self {
            principal_id,
            namespace,
        }
    }

    #[must_use]
    pub fn principal_id(&self) -> &DidCoreId {
        &self.principal_id
    }

    /// Expand a caller-supplied logical key into
    /// `inkson.{did-core-without-ak:did_core:}.{logical-key}`.
    fn key(&self, logical_key: &str) -> String {
        format!("{}.{logical_key}", self.namespace)
    }

    pub(crate) fn secret_key(&self, entry: &str) -> String {
        self.key(entry)
    }

    pub(crate) fn delete_secret(
        &self,
        store: &dyn SecureKeyStore,
        logical_key: &str,
    ) -> Result<(), SecureKeyStoreError> {
        store.delete_secret(&self.key(logical_key))
    }

    pub(crate) fn load_secret(
        &self,
        store: &dyn SecureKeyStore,
        logical_key: &str,
    ) -> Result<Option<String>, SecureKeyStoreError> {
        store.get_secret(&self.key(logical_key))
    }

    pub(crate) fn save_secret(
        &self,
        store: &dyn SecureKeyStore,
        logical_key: &str,
        value: &str,
    ) -> Result<(), SecureKeyStoreError> {
        store.store_secret(&self.key(logical_key), value)
    }

    pub fn activate(&self) {
        super::set_pending_login_device_id(None);
        super::set_active_device_seed_scope(Some(self.principal_id.as_str()));
    }

    pub fn load_device_id(
        &self,
        store: &dyn SecureKeyStore,
    ) -> Result<Option<DeviceId>, SecureKeyStoreError> {
        load_device_id(store, &self.key(DEVICE_ID_ENTRY))
    }

    pub fn save_device_id(
        &self,
        store: &dyn SecureKeyStore,
        device_id: &DeviceId,
    ) -> Result<(), SecureKeyStoreError> {
        save_device_id(store, &self.key(DEVICE_ID_ENTRY), device_id)
    }

    pub fn load_signing_seed(
        &self,
        store: &dyn SecureKeyStore,
    ) -> Result<Option<SigningSeedMaterial>, SecureKeyStoreError> {
        load_signing_seed_at(store, &self.key(SIGNING_SEED_ENTRY))
    }

    pub fn ensure_signing_seed(
        &self,
        store: &dyn SecureKeyStore,
    ) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
        ensure_signing_seed_at(store, &self.key(SIGNING_SEED_ENTRY))
    }

    pub fn save_signing_seed(
        &self,
        store: &dyn SecureKeyStore,
        seed: &[u8; 32],
    ) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
        store_signing_seed_at(store, &self.key(SIGNING_SEED_ENTRY), seed)
    }

    pub fn save_grant_binding_seed_b64url(
        &self,
        store: &dyn SecureKeyStore,
        seed_b64url: &str,
    ) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
        let seed = decode_seed_b64url(seed_b64url)?;
        store_signing_seed_at(store, &self.key(GRANT_BINDING_SEED_ENTRY), &seed)
    }

    pub(crate) fn delete_grant_binding_seed(
        &self,
        store: &dyn SecureKeyStore,
    ) -> Result<(), SecureKeyStoreError> {
        store.delete_secret(&self.key(GRANT_BINDING_SEED_ENTRY))
    }

    pub fn delete_device_identity(
        &self,
        store: &dyn SecureKeyStore,
    ) -> Result<(), SecureKeyStoreError> {
        store.delete_secret(&self.key(SIGNING_SEED_ENTRY))?;
        store.delete_secret(&self.key(GRANT_BINDING_SEED_ENTRY))?;
        delete_device_id(store, &self.key(DEVICE_ID_ENTRY))
    }
}

/// Local data for one pre-principal authentication transaction.
///
/// Pending entries are fenced by the freshly generated protocol device id and
/// can only become user entries through [`Self::promote_to`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingLocalStore {
    device_id: DeviceId,
    namespace: String,
}

impl PendingLocalStore {
    #[must_use]
    pub fn new(device_id: DeviceId) -> Self {
        let namespace = format!(
            "inkson.{PENDING_NAMESPACE}.{}",
            pending_storage_scope(&device_id)
        );
        Self {
            device_id,
            namespace,
        }
    }

    #[must_use]
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// Expand a caller-supplied logical key into the pending transaction
    /// namespace. The logical key itself remains readable at the call site.
    fn key(&self, logical_key: &str) -> String {
        format!("{}.{logical_key}", self.namespace)
    }

    pub fn activate(&self) {
        super::set_active_device_seed_scope(None);
        super::set_pending_login_device_id(Some(self.device_id.as_str()));
    }

    pub fn save_device_id(&self, store: &dyn SecureKeyStore) -> Result<(), SecureKeyStoreError> {
        save_device_id(store, &self.key(DEVICE_ID_ENTRY), &self.device_id)
    }

    pub fn save_signing_seed(
        &self,
        store: &dyn SecureKeyStore,
        seed: &[u8; 32],
    ) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
        store_signing_seed_at(store, &self.key(SIGNING_SEED_ENTRY), seed)
    }

    pub fn ensure_signing_seed(
        &self,
        store: &dyn SecureKeyStore,
    ) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
        ensure_signing_seed_at(store, &self.key(SIGNING_SEED_ENTRY))
    }

    pub fn load_signing_seed(
        &self,
        store: &dyn SecureKeyStore,
    ) -> Result<Option<SigningSeedMaterial>, SecureKeyStoreError> {
        load_signing_seed_at(store, &self.key(SIGNING_SEED_ENTRY))
    }

    pub fn ensure_grant_binding_seed(
        &self,
        store: &dyn SecureKeyStore,
    ) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
        ensure_signing_seed_at(store, &self.key(GRANT_BINDING_SEED_ENTRY))
    }

    pub fn load_grant_binding_seed(
        &self,
        store: &dyn SecureKeyStore,
    ) -> Result<Option<SigningSeedMaterial>, SecureKeyStoreError> {
        load_signing_seed_at(store, &self.key(GRANT_BINDING_SEED_ENTRY))
    }

    pub(crate) fn load_secret(
        &self,
        store: &dyn SecureKeyStore,
        logical_key: &str,
    ) -> Result<Option<String>, SecureKeyStoreError> {
        store.get_secret(&self.key(logical_key))
    }

    pub(crate) fn save_secret(
        &self,
        store: &dyn SecureKeyStore,
        logical_key: &str,
        value: &str,
    ) -> Result<(), SecureKeyStoreError> {
        store.store_secret(&self.key(logical_key), value)
    }

    pub(crate) async fn save_secret_durable(
        &self,
        store: &dyn SecureKeyStore,
        logical_key: &str,
        value: &str,
    ) -> Result<(), SecureKeyStoreError> {
        store
            .store_secret_durable(&self.key(logical_key), value)
            .await
    }

    pub(crate) fn delete_secret(
        &self,
        store: &dyn SecureKeyStore,
        logical_key: &str,
    ) -> Result<(), SecureKeyStoreError> {
        store.delete_secret(&self.key(logical_key))
    }

    pub fn promote_to(
        &self,
        store: &dyn SecureKeyStore,
        user: &UserLocalStore,
    ) -> Result<(), SecureKeyStoreError> {
        if user.load_device_id(store)?.is_none() {
            user.save_device_id(store, &self.device_id)?;
        }
        if user.load_signing_seed(store)?.is_none()
            && let Some(material) = load_signing_seed_at(store, &self.key(SIGNING_SEED_ENTRY))?
        {
            store_signing_seed_at(store, &user.key(SIGNING_SEED_ENTRY), &material.seed)?;
        }
        if store
            .get_secret(&user.key(GRANT_BINDING_SEED_ENTRY))?
            .is_none()
            && let Some(seed) = store.get_secret(&self.key(GRANT_BINDING_SEED_ENTRY))?
        {
            store.store_secret(&user.key(GRANT_BINDING_SEED_ENTRY), &seed)?;
        }
        self.delete(store)?;
        user.activate();
        Ok(())
    }

    pub fn delete(&self, store: &dyn SecureKeyStore) -> Result<(), SecureKeyStoreError> {
        store.delete_secret(&self.key(SIGNING_SEED_ENTRY))?;
        store.delete_secret(&self.key(GRANT_BINDING_SEED_ENTRY))?;
        delete_device_id(store, &self.key(DEVICE_ID_ENTRY))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_key_store::MemorySecureKeyStore;

    fn device(suffix: &str) -> DeviceId {
        DeviceId::new(format!("ak:device:01964137-0000-7000-8000-{suffix}")).unwrap()
    }

    #[test]
    fn user_keys_always_include_the_validated_core_id() {
        let alice = UserLocalStore::new(
            DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
        );
        let bob =
            UserLocalStore::new(DidCoreId::new("ak:did_core:web:bob.example".to_owned()).unwrap());

        let alice_key = alice.key(DEVICE_ID_ENTRY);
        let bob_key = bob.key(DEVICE_ID_ENTRY);
        assert!(alice_key.starts_with("inkson.web:alice.example."));
        assert!(alice_key.ends_with(".device_id.v1"));
        assert_ne!(alice_key, bob_key);
        assert_ne!(alice_key, DEVICE_ID_ENTRY);
        assert!(!alice_key.contains("ak:did_core:"));
    }

    #[test]
    fn two_pending_transactions_cannot_share_a_device_entry() {
        let first = PendingLocalStore::new(device("000000000001"));
        let second = PendingLocalStore::new(device("000000000002"));
        assert_ne!(first.key(DEVICE_ID_ENTRY), second.key(DEVICE_ID_ENTRY));
        assert_eq!(
            first.key(DEVICE_ID_ENTRY),
            "inkson.pending.01964137-0000-7000-8000-000000000001.device_id.v1"
        );
        assert!(!first.key(DEVICE_ID_ENTRY).contains("inkson.secret"));
        assert!(!first.key(DEVICE_ID_ENTRY).contains("inkson.inkson"));
    }

    #[test]
    fn promotion_moves_only_the_selected_pending_identity() {
        let store = MemorySecureKeyStore::default();
        let pending = PendingLocalStore::new(device("000000000003"));
        pending.save_device_id(&store).unwrap();
        let user = UserLocalStore::new(
            DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
        );

        pending.promote_to(&store, &user).unwrap();

        assert_eq!(
            user.load_device_id(&store).unwrap(),
            Some(device("000000000003"))
        );
        assert!(
            load_device_id(&store, &pending.key(DEVICE_ID_ENTRY))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn global_namespace_is_explicit_and_separate() {
        let key = GlobalLocalStore::new("inkson").key("secure_store.wrap_seed.v1");
        assert_eq!(key, "inkson.global.secure_store.wrap_seed.v1");
    }

    #[test]
    fn scoped_key_helper_has_no_bare_key_case() {
        let user = UserLocalStore::new(
            DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
        );
        let key = user.key(DEVICE_ID_ENTRY);
        assert_ne!(key, DEVICE_ID_ENTRY);
        assert_eq!(key, "inkson.web:alice.example.device_id.v1");
    }
}
