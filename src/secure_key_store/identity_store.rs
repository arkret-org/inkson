//! Typed local-persistence namespaces for identity-owned client data.
//!
//! The namespace is part of the store instance, not an optional argument at
//! each read/write call. Callers pass a bare logical key; the store always
//! expands it with the validated authority/device supplied at construction time.
//! Pre-principal transactions use [`PendingLocalStore`].

use arkret_sdk::{DeviceId, PrincipalAuthorityKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::signing_seed::{
    SigningSeedMaterial, ensure_signing_seed_at, ensure_signing_seed_at_durable,
    load_signing_seed_at, store_signing_seed_at, store_signing_seed_at_durable,
};
use super::{SecureKeyStore, SecureKeyStoreError};

const PENDING_NAMESPACE: &str = "pending";
/// Only the wasm32 `localStorage` backend names an installation-global entry
/// (the secure-store wrapping seed), so the namespace carries that gate rather
/// than an allow that would also hide a real regression.
#[cfg(any(target_arch = "wasm32", test))]
const GLOBAL_NAMESPACE: &str = "global";
const DEVICE_ID_ENTRY: &str = "device_id.v1";
const SIGNING_SEED_ENTRY: &str = "device.ed25519.signing_seed.v1";
const GRANT_BINDING_SEED_ENTRY: &str = "device.ed25519.grant_binding.v1";

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

async fn save_device_id_durable(
    store: &dyn SecureKeyStore,
    storage_key: &str,
    device_id: &DeviceId,
) -> Result<(), SecureKeyStoreError> {
    #[cfg(target_arch = "wasm32")]
    {
        // Device ids are intentionally non-secret browser routing metadata and
        // live in localStorage, whose setItem contract completes synchronously.
        save_device_id(store, storage_key, device_id)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        store
            .store_secret_durable(storage_key, device_id.as_str())
            .await
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
    #[cfg(any(target_arch = "wasm32", test))]
    #[must_use]
    pub(crate) fn key(&self, logical_key: &str) -> String {
        format!("{}.{GLOBAL_NAMESPACE}.{logical_key}", self.application)
    }
}

/// Local secret data belonging to one account authority and one device.
///
/// There is intentionally no default constructor and no string/optional
/// scope. Methods accept bare logical keys and every emitted storage key
/// contains bounded digests of the typed authority and device coordinates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserLocalStore {
    authority: PrincipalAuthorityKey,
    device_id: DeviceId,
    namespace: String,
}

impl UserLocalStore {
    pub fn new(
        authority: PrincipalAuthorityKey,
        device_id: DeviceId,
    ) -> Result<Self, SecureKeyStoreError> {
        let authority_digest = super::principal_authority_storage_digest(&authority)?;
        let device_digest = super::device_storage_digest(&device_id);
        let namespace = format!("inkson.authority.{authority_digest}.device.{device_digest}");
        Ok(Self {
            authority,
            device_id,
            namespace,
        })
    }

    #[must_use]
    pub fn authority(&self) -> &PrincipalAuthorityKey {
        &self.authority
    }

    #[must_use]
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
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
        super::set_active_device_seed_scope(Some((&self.authority, &self.device_id)));
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

    /// Crash-durable device-id write used while preparing an identity
    /// transition. Ordinary metadata updates may continue using
    /// [`Self::save_device_id`].
    pub async fn save_device_id_durable(
        &self,
        store: &dyn SecureKeyStore,
        device_id: &DeviceId,
    ) -> Result<(), SecureKeyStoreError> {
        save_device_id_durable(store, &self.key(DEVICE_ID_ENTRY), device_id).await
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

    /// Load the account device signer or durably create it before a protocol
    /// transition starts depending on that key.
    pub async fn ensure_signing_seed_durable(
        &self,
        store: &dyn SecureKeyStore,
    ) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
        ensure_signing_seed_at_durable(store, &self.key(SIGNING_SEED_ENTRY)).await
    }

    pub fn save_signing_seed(
        &self,
        store: &dyn SecureKeyStore,
        seed: &[u8; 32],
    ) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
        store_signing_seed_at(store, &self.key(SIGNING_SEED_ENTRY), seed)
    }

    pub async fn save_signing_seed_durable(
        &self,
        store: &dyn SecureKeyStore,
        seed: &[u8; 32],
    ) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
        store_signing_seed_at_durable(store, &self.key(SIGNING_SEED_ENTRY), seed).await
    }

    /// Persist the post-authentication grant-binding key before the account
    /// scope is made visible to the rest of the application.
    pub async fn save_grant_binding_seed_b64url_durable(
        &self,
        store: &dyn SecureKeyStore,
        seed_b64url: &str,
    ) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
        let seed = decode_seed_b64url(seed_b64url)?;
        store_signing_seed_at_durable(store, &self.key(GRANT_BINDING_SEED_ENTRY), &seed).await
    }

    /// Logout-only; the sole caller sits under `cfg(not(test))`, so this carries
    /// the same gate instead of an allow.
    #[cfg(not(test))]
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
        super::set_pending_login_device_id(Some(&self.device_id));
    }

    pub fn save_device_id(&self, store: &dyn SecureKeyStore) -> Result<(), SecureKeyStoreError> {
        save_device_id(store, &self.key(DEVICE_ID_ENTRY), &self.device_id)
    }

    pub async fn save_device_id_durable(
        &self,
        store: &dyn SecureKeyStore,
    ) -> Result<(), SecureKeyStoreError> {
        save_device_id_durable(store, &self.key(DEVICE_ID_ENTRY), &self.device_id).await
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

    pub async fn ensure_signing_seed_durable(
        &self,
        store: &dyn SecureKeyStore,
    ) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
        ensure_signing_seed_at_durable(store, &self.key(SIGNING_SEED_ENTRY)).await
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

    pub async fn ensure_grant_binding_seed_durable(
        &self,
        store: &dyn SecureKeyStore,
    ) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
        ensure_signing_seed_at_durable(store, &self.key(GRANT_BINDING_SEED_ENTRY)).await
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
        self.copy_to(store, user)?;
        self.delete(store)?;
        user.activate();
        Ok(())
    }

    /// Copy pending identity material without consuming the pending namespace.
    /// Login completion uses this as a prepare phase: every fallible secure
    /// write finishes before the public root switches to the resolved account.
    /// The caller deletes the pending namespace only after the account state
    /// commit succeeds, so a failed prepare remains safely retryable.
    pub fn copy_to(
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
        Ok(())
    }

    /// Prepare pending identity material in its final account namespace and
    /// wait for every newly-created secret write to commit. The pending
    /// namespace remains intact, so callers can retry after any partial error
    /// and consume it only after the public account-state commit succeeds.
    pub async fn copy_to_durable(
        &self,
        store: &dyn SecureKeyStore,
        user: &UserLocalStore,
    ) -> Result<(), SecureKeyStoreError> {
        if user.load_device_id(store)?.is_none() {
            user.save_device_id_durable(store, &self.device_id).await?;
        }
        if user.load_signing_seed(store)?.is_none()
            && let Some(material) = load_signing_seed_at(store, &self.key(SIGNING_SEED_ENTRY))?
        {
            user.save_signing_seed_durable(store, &material.seed)
                .await?;
        }
        if store
            .get_secret(&user.key(GRANT_BINDING_SEED_ENTRY))?
            .is_none()
            && let Some(seed) = store.get_secret(&self.key(GRANT_BINDING_SEED_ENTRY))?
        {
            store
                .store_secret_durable(&user.key(GRANT_BINDING_SEED_ENTRY), &seed)
                .await?;
        }
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
    #[cfg(not(target_arch = "wasm32"))]
    use std::future::Future;
    #[cfg(not(target_arch = "wasm32"))]
    use std::pin::Pin;
    #[cfg(not(target_arch = "wasm32"))]
    use std::sync::Mutex;

    use super::*;
    use crate::secure_key_store::MemorySecureKeyStore;

    #[cfg(not(target_arch = "wasm32"))]
    #[derive(Debug, Default)]
    struct TrackingDurableStore {
        inner: MemorySecureKeyStore,
        durable_keys: Mutex<Vec<String>>,
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl SecureKeyStore for TrackingDurableStore {
        fn store_secret_bytes(&self, key: &str, value: &[u8]) -> Result<(), SecureKeyStoreError> {
            self.inner.store_secret_bytes(key, value)
        }

        fn store_secret_bytes_durable<'a>(
            &'a self,
            key: &'a str,
            value: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Result<(), SecureKeyStoreError>> + Send + 'a>> {
            Box::pin(async move {
                self.durable_keys.lock().unwrap().push(key.to_owned());
                self.inner.store_secret_bytes(key, value)
            })
        }

        fn get_secret_bytes(
            &self,
            key: &str,
        ) -> Result<Option<garth::SecretBytes>, SecureKeyStoreError> {
            self.inner.get_secret_bytes(key)
        }

        fn delete_secret(&self, key: &str) -> Result<(), SecureKeyStoreError> {
            self.inner.delete_secret(key)
        }

        fn list_secret_keys(
            &self,
            prefix: Option<&str>,
        ) -> Result<Vec<String>, SecureKeyStoreError> {
            self.inner.list_secret_keys(prefix)
        }

        fn backend_info(&self) -> garth::SecureKeyStoreBackendInfo {
            garth::SecureKeyStoreBackendInfo {
                name: "tracking-durable",
                hardware_backed: false,
                exportable: true,
            }
        }
    }

    fn device(suffix: &str) -> DeviceId {
        DeviceId::new(format!("ak:device:01964137-0000-7000-8000-{suffix}")).unwrap()
    }

    fn user(principal: &str, server: &str, device_id: DeviceId) -> UserLocalStore {
        UserLocalStore::new(
            PrincipalAuthorityKey::new(
                arkret_sdk::DidCoreId::new(principal.to_owned()).unwrap(),
                arkret_sdk::DidCoreId::new(server.to_owned()).unwrap(),
            ),
            device_id,
        )
        .unwrap()
    }

    #[test]
    fn user_keys_include_authority_and_device_digests() {
        let alice = user(
            "ak:did_core:web:alice.example",
            "ak:did_core:web:server.example",
            device("000000000001"),
        );
        let bob = user(
            "ak:did_core:web:bob.example",
            "ak:did_core:web:server.example",
            device("000000000002"),
        );

        let alice_key = alice.key(DEVICE_ID_ENTRY);
        let bob_key = bob.key(DEVICE_ID_ENTRY);
        assert!(alice_key.starts_with("inkson.authority."));
        assert!(alice_key.contains(".device."));
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
        assert!(first.key(DEVICE_ID_ENTRY).starts_with("inkson.pending."));
        assert!(first.key(DEVICE_ID_ENTRY).ends_with(".device_id.v1"));
        assert!(!first.key(DEVICE_ID_ENTRY).contains("inkson.secret"));
        assert!(!first.key(DEVICE_ID_ENTRY).contains("inkson.inkson"));
    }

    #[test]
    fn promotion_moves_only_the_selected_pending_identity() {
        // promote_to activates the user store, mutating the process-global
        // device-seed scope.
        let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
        let store = MemorySecureKeyStore::default();
        let pending = PendingLocalStore::new(device("000000000003"));
        pending.save_device_id(&store).unwrap();
        let user = user(
            "ak:did_core:web:alice.example",
            "ak:did_core:web:server.example",
            device("000000000003"),
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
        let user = user(
            "ak:did_core:web:alice.example",
            "ak:did_core:web:server.example",
            device("000000000003"),
        );
        let key = user.key(DEVICE_ID_ENTRY);
        assert_ne!(key, DEVICE_ID_ENTRY);
        assert!(key.ends_with(".device_id.v1"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn durable_prepare_commits_each_new_identity_binding() {
        let store = TrackingDurableStore::default();
        let pending = PendingLocalStore::new(device("000000000004"));
        pending.save_signing_seed(&store, &[5_u8; 32]).unwrap();
        pending
            .ensure_grant_binding_seed_durable(&store)
            .await
            .unwrap();
        let user = user(
            "ak:did_core:web:alice.example",
            "ak:did_core:web:server.example",
            device("000000000004"),
        );

        pending.copy_to_durable(&store, &user).await.unwrap();

        assert_eq!(
            user.load_device_id(&store).unwrap(),
            Some(device("000000000004"))
        );
        assert_eq!(
            user.load_signing_seed(&store).unwrap().unwrap().seed,
            [5_u8; 32]
        );
        assert!(
            store
                .get_secret(&user.key(GRANT_BINDING_SEED_ENTRY))
                .unwrap()
                .is_some()
        );
        let durable_keys = store.durable_keys.lock().unwrap();
        assert!(
            durable_keys
                .iter()
                .any(|key| key == &user.key(DEVICE_ID_ENTRY))
        );
        assert!(
            durable_keys
                .iter()
                .any(|key| key == &user.key(SIGNING_SEED_ENTRY))
        );
        assert!(
            durable_keys
                .iter()
                .any(|key| key == &user.key(GRANT_BINDING_SEED_ENTRY))
        );
    }
}
