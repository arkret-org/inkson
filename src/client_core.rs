//! Thin host-adapter entry points for the shared `cokret-client` runtime.
//!
//! The production path still uses the existing yougen engines until the E-wave
//! migration replaces them. This module gives that migration a typed,
//! target-aware construction point without pulling UI state into client-core.

use std::collections::{BTreeSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use cokret_client::{RealmEventsFrameSource, RealmEventsTransport};
#[cfg(not(target_arch = "wasm32"))]
use reqwest::header::CONTENT_TYPE;

use crate::sync_parse::{AccountSubscribeReconnectAfter, AccountSubscribeSnapshotResult};

#[derive(Clone, Debug)]
pub struct YougenLocalStateStoreAdapter {
    inner: Arc<Mutex<crate::local_state::LocalStateStore>>,
}

impl YougenLocalStateStoreAdapter {
    pub fn new(store: crate::local_state::LocalStateStore) -> Self {
        Self {
            inner: Arc::new(Mutex::new(store)),
        }
    }

    pub fn shared(store: Arc<Mutex<crate::local_state::LocalStateStore>>) -> Self {
        Self { inner: store }
    }

    fn lock(
        &self,
    ) -> cokret_sdk::Result<std::sync::MutexGuard<'_, crate::local_state::LocalStateStore>> {
        self.inner
            .lock()
            .map_err(|err| cokret_sdk::Error::Protocol(format!("local state lock poisoned: {err}")))
    }

    fn realm_id(scope: &cokret_client::CursorScope) -> Option<String> {
        match scope {
            cokret_client::CursorScope::RealmEvents { realm_id, .. } => {
                Some(realm_id.as_str().to_owned())
            }
            _ => None,
        }
    }
}

impl cokret_client::CursorStore for YougenLocalStateStoreAdapter {
    async fn load(
        &self,
        scope: cokret_client::CursorScope,
    ) -> cokret_sdk::Result<Option<cokret_client::OpaqueCursor>> {
        let store = self.lock()?;
        match scope {
            cokret_client::CursorScope::Account { .. } => Ok(store.sync_cursor()),
            cokret_client::CursorScope::RealmEvents { realm_id, .. } => {
                Ok(store.realm_events_cursor(realm_id.as_str()))
            }
            cokret_client::CursorScope::EventsQuery { .. } => Ok(None),
        }
    }

    async fn save(
        &self,
        scope: cokret_client::CursorScope,
        cursor: cokret_client::OpaqueCursor,
    ) -> cokret_sdk::Result<()> {
        let mut store = self.lock()?;
        match scope {
            cokret_client::CursorScope::Account { .. } => store.save_sync_cursor(cursor),
            cokret_client::CursorScope::RealmEvents { realm_id, .. } => {
                store.save_realm_events_cursor(realm_id.as_str(), Some(cursor));
            }
            cokret_client::CursorScope::EventsQuery { .. } => {}
        }
        Ok(())
    }

    async fn clear(&self, scope: cokret_client::CursorScope) -> cokret_sdk::Result<()> {
        let mut store = self.lock()?;
        match scope {
            cokret_client::CursorScope::Account { .. } => store.clear_sync_cursor(),
            cokret_client::CursorScope::RealmEvents { .. } => {
                if let Some(realm_id) = Self::realm_id(&scope) {
                    store.save_realm_events_cursor(&realm_id, None);
                }
            }
            cokret_client::CursorScope::EventsQuery { .. } => {}
        }
        Ok(())
    }
}

impl cokret_client::EventCacheStore for YougenLocalStateStoreAdapter {
    async fn seen(&self, event_id: cokret_sdk::EventId) -> cokret_sdk::Result<bool> {
        let store = self.lock()?;
        Ok(store.client_core_event_seen(event_id.as_str()))
    }

    async fn remember(&self, event_id: cokret_sdk::EventId) -> cokret_sdk::Result<()> {
        let mut store = self.lock()?;
        store.remember_client_core_event(event_id.as_str());
        Ok(())
    }
}

#[derive(Clone)]
pub struct YougenSecureKeyStoreAdapter {
    inner: Arc<dyn crate::secure_key_store::SecureKeyStore>,
    key_index: Arc<Mutex<BTreeSet<String>>>,
}

impl YougenSecureKeyStoreAdapter {
    pub fn new(inner: Arc<dyn crate::secure_key_store::SecureKeyStore>) -> Self {
        Self {
            inner,
            key_index: Arc::new(Mutex::new(BTreeSet::new())),
        }
    }

    fn map_error(
        error: crate::secure_key_store::SecureKeyStoreError,
    ) -> cokret_client::SecureKeyStoreError {
        match error {
            crate::secure_key_store::SecureKeyStoreError::NotFound => {
                cokret_client::SecureKeyStoreError::NotFound
            }
            crate::secure_key_store::SecureKeyStoreError::Backend(error) => {
                cokret_client::SecureKeyStoreError::Backend(error)
            }
            crate::secure_key_store::SecureKeyStoreError::Unsupported(backend) => {
                cokret_client::SecureKeyStoreError::Unsupported(backend)
            }
        }
    }

    fn remember_key(&self, key: &str) -> Result<(), cokret_client::SecureKeyStoreError> {
        self.key_index
            .lock()
            .map_err(|err| {
                cokret_client::SecureKeyStoreError::Backend(format!(
                    "secure key index lock poisoned: {err}"
                ))
            })?
            .insert(key.to_owned());
        Ok(())
    }
}

impl std::fmt::Debug for YougenSecureKeyStoreAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YougenSecureKeyStoreAdapter")
            .field("backend", &self.inner.backend_name())
            .finish_non_exhaustive()
    }
}

impl cokret_client::SecureKeyStore for YougenSecureKeyStoreAdapter {
    fn store_secret_bytes(
        &self,
        key: &str,
        value: &[u8],
    ) -> Result<(), cokret_client::SecureKeyStoreError> {
        let encoded = STANDARD_NO_PAD.encode(value);
        self.inner
            .store_secret(key, &encoded)
            .map_err(Self::map_error)?;
        self.remember_key(key)
    }

    fn store_secret_bytes_durable<'a>(
        &'a self,
        key: &'a str,
        value: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), cokret_client::SecureKeyStoreError>> + 'a>,
    > {
        let encoded = STANDARD_NO_PAD.encode(value);
        Box::pin(async move {
            self.inner
                .store_secret_durable(key, &encoded)
                .await
                .map_err(Self::map_error)?;
            self.remember_key(key)
        })
    }

    fn get_secret_bytes(
        &self,
        key: &str,
    ) -> Result<Option<cokret_client::SecretBytes>, cokret_client::SecureKeyStoreError> {
        let Some(encoded) = self.inner.get_secret(key).map_err(Self::map_error)? else {
            return Ok(None);
        };
        let bytes = STANDARD_NO_PAD.decode(encoded.as_bytes()).map_err(|err| {
            cokret_client::SecureKeyStoreError::Backend(format!("base64 secret decode: {err}"))
        })?;
        Ok(Some(zeroize::Zeroizing::new(bytes)))
    }

    fn delete_secret(&self, key: &str) -> Result<(), cokret_client::SecureKeyStoreError> {
        self.inner.delete_secret(key).map_err(Self::map_error)?;
        if let Ok(mut index) = self.key_index.lock() {
            index.remove(key);
        }
        Ok(())
    }

    fn list_secret_keys(
        &self,
        prefix: Option<&str>,
    ) -> Result<Vec<String>, cokret_client::SecureKeyStoreError> {
        let index = self.key_index.lock().map_err(|err| {
            cokret_client::SecureKeyStoreError::Backend(format!(
                "secure key index lock poisoned: {err}"
            ))
        })?;
        Ok(index
            .iter()
            .filter(|key| prefix.is_none_or(|prefix| key.starts_with(prefix)))
            .cloned()
            .collect())
    }

    fn backend_info(&self) -> cokret_client::SecureKeyStoreBackendInfo {
        cokret_client::SecureKeyStoreBackendInfo {
            name: self.inner.backend_name(),
            hardware_backed: matches!(
                self.inner.backend_name(),
                "keyring" | "host_bridge" | "android_keystore" | "ios_keychain"
            ),
            exportable: !matches!(
                self.inner.backend_name(),
                "keyring" | "host_bridge" | "android_keystore" | "ios_keychain"
            ),
        }
    }
}

pub type MemoryClientCore<E> = cokret_client::CokretClient<
    E,
    cokret_client::MemoryStore,
    cokret_client::MemoryStore,
    cokret_client::MemorySecureKeyStore,
>;

pub type YougenClientCore<E> = cokret_client::CokretClient<
    E,
    YougenLocalStateStoreAdapter,
    YougenLocalStateStoreAdapter,
    YougenSecureKeyStoreAdapter,
>;

pub struct BufferedRealmEventsFrameSource {
    frames: VecDeque<cokret_sdk::EventsSubscribeFrame>,
}

impl BufferedRealmEventsFrameSource {
    fn new(frames: Vec<cokret_sdk::EventsSubscribeFrame>) -> Self {
        Self {
            frames: VecDeque::from(frames),
        }
    }
}

impl RealmEventsFrameSource for BufferedRealmEventsFrameSource {
    fn next_frame<'a>(
        &'a mut self,
    ) -> Pin<
        Box<dyn Future<Output = cokret_sdk::Result<Option<cokret_sdk::EventsSubscribeFrame>>> + 'a>,
    > {
        let frame = self.frames.pop_front();
        Box::pin(async move { Ok(frame) })
    }
}

#[derive(Clone, Debug)]
pub struct YougenRealmEventsTransport {
    http: cokret_sdk::http_client::Client,
    max_duration_ms: Option<u64>,
    heartbeat_ms: Option<u64>,
}

impl YougenRealmEventsTransport {
    pub fn new(http: cokret_sdk::http_client::Client) -> Self {
        Self {
            http,
            max_duration_ms: None,
            heartbeat_ms: None,
        }
    }

    #[must_use]
    pub fn with_max_duration_ms(mut self, max_duration_ms: u64) -> Self {
        self.max_duration_ms = Some(max_duration_ms);
        self
    }

    #[must_use]
    pub fn with_heartbeat_ms(mut self, heartbeat_ms: u64) -> Self {
        self.heartbeat_ms = Some(heartbeat_ms);
        self
    }
}

impl RealmEventsTransport for YougenRealmEventsTransport {
    type Source = BufferedRealmEventsFrameSource;

    fn open_realm_events<'a>(
        &'a self,
        realm_id: &'a cokret_sdk::RealmId,
        after: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = cokret_sdk::Result<Self::Source>> + 'a>> {
        Box::pin(async move {
            let mut options = cokret_sdk::http_client::EventsSubscribeOptions::new()
                .realm(realm_id.as_str().to_owned())
                .include_history(after.is_none());
            if let Some(after) = after {
                options = options.after(after.to_owned());
            }
            if let Some(max_duration_ms) = self.max_duration_ms {
                options = options.max_duration_ms(max_duration_ms);
            }
            if let Some(heartbeat_ms) = self.heartbeat_ms {
                options = options.heartbeat_ms(heartbeat_ms);
            }
            let response = self
                .http
                .events_subscribe_stream_with_options(&options)
                .await?;
            let bytes = response
                .bytes()
                .await
                .map_err(|error| cokret_sdk::Error::Http(error.to_string()))?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|error| cokret_sdk::Error::Protocol(error.to_string()))?;
            let frames = crate::sync_parse::parse_events_subscribe_ndjson_text(text)
                .map_err(|error| cokret_sdk::Error::Protocol(error.to_string()))?;
            Ok(BufferedRealmEventsFrameSource::new(frames))
        })
    }
}

pub async fn account_subscribe_snapshot(
    http: &cokret_sdk::http_client::Client,
    after: Option<&str>,
) -> anyhow::Result<crate::models::ClientSyncOutcome> {
    match account_subscribe_snapshot_outcome(http, after).await? {
        AccountSubscribeSnapshotResult::Delta(response) => Ok(*response),
        AccountSubscribeSnapshotResult::ReconnectAfter {
            reconnect_after_ms,
            reason,
            reset_cursor,
        } => Err(AccountSubscribeReconnectAfter {
            reconnect_after_ms,
            reason,
            reset_cursor,
        }
        .into()),
    }
}

pub async fn account_subscribe_snapshot_outcome(
    http: &cokret_sdk::http_client::Client,
    after: Option<&str>,
) -> anyhow::Result<AccountSubscribeSnapshotResult> {
    account_subscribe_snapshot_outcome_with_options(
        http,
        after,
        &cokret_sdk::http_client::ClientRequestOptions::default(),
    )
    .await
}

pub async fn account_subscribe_snapshot_with_options(
    http: &cokret_sdk::http_client::Client,
    after: Option<&str>,
    options: &cokret_sdk::http_client::ClientRequestOptions,
) -> anyhow::Result<crate::models::ClientSyncOutcome> {
    match account_subscribe_snapshot_outcome_with_options(http, after, options).await? {
        AccountSubscribeSnapshotResult::Delta(response) => Ok(*response),
        AccountSubscribeSnapshotResult::ReconnectAfter {
            reconnect_after_ms,
            reason,
            reset_cursor,
        } => Err(AccountSubscribeReconnectAfter {
            reconnect_after_ms,
            reason,
            reset_cursor,
        }
        .into()),
    }
}

pub async fn account_subscribe_snapshot_outcome_with_options(
    http: &cokret_sdk::http_client::Client,
    after: Option<&str>,
    options: &cokret_sdk::http_client::ClientRequestOptions,
) -> anyhow::Result<AccountSubscribeSnapshotResult> {
    if let Some(cursor) = after {
        crate::api::validate_cursor(cursor)?;
    }

    let _subscribe_gate = crate::sync_parse::ACCOUNT_SUBSCRIBE_NETWORK_GATE
        .lock()
        .await;
    let request = cokret_sdk::SyncRequestBody {
        after: after.map(str::to_owned),
        catchup: Some(true),
        filter: None,
        subscriptions: None,
        wait_for: None,
    };
    let response = http
        .account_subscribe_with_options(&request, options)
        .await?;

    #[cfg(not(target_arch = "wasm32"))]
    let is_ndjson = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .contains("application/x-ndjson");
    #[cfg(not(target_arch = "wasm32"))]
    {
        if is_ndjson {
            crate::sync_parse::drain_account_subscribe_response(response).await
        } else {
            let bytes = response.bytes().await?;
            crate::sync_parse::parse_account_subscribe_snapshot_outcome(&bytes)
        }
    }
    #[cfg(target_arch = "wasm32")]
    {
        let bytes = response.bytes().await?;
        crate::sync_parse::parse_account_subscribe_snapshot_outcome(&bytes)
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub type DefaultClientCore = MemoryClientCore<cokret_client::NativeExecutor>;

#[cfg(target_arch = "wasm32")]
pub type DefaultClientCore = MemoryClientCore<cokret_client::WasmExecutor>;

#[cfg(not(target_arch = "wasm32"))]
pub fn build_memory_client_core(http: cokret_sdk::http_client::Client) -> DefaultClientCore {
    cokret_client::CokretClient::new(
        http,
        cokret_client::NativeExecutor,
        cokret_client::MemoryStore::new(),
        cokret_client::MemoryStore::new(),
        cokret_client::MemorySecureKeyStore::new(),
    )
}

#[cfg(not(target_arch = "wasm32"))]
pub fn build_client_core(
    http: cokret_sdk::http_client::Client,
    local_state: crate::local_state::LocalStateStore,
    secure_key_store: Arc<dyn crate::secure_key_store::SecureKeyStore>,
) -> YougenClientCore<cokret_client::NativeExecutor> {
    let local_state = YougenLocalStateStoreAdapter::new(local_state);
    cokret_client::CokretClient::new(
        http,
        cokret_client::NativeExecutor,
        local_state.clone(),
        local_state,
        YougenSecureKeyStoreAdapter::new(secure_key_store),
    )
}

#[cfg(target_arch = "wasm32")]
pub fn build_client_core(
    http: cokret_sdk::http_client::Client,
    local_state: crate::local_state::LocalStateStore,
    secure_key_store: Arc<dyn crate::secure_key_store::SecureKeyStore>,
) -> YougenClientCore<cokret_client::WasmExecutor> {
    let local_state = YougenLocalStateStoreAdapter::new(local_state);
    cokret_client::CokretClient::new(
        http,
        cokret_client::WasmExecutor,
        local_state.clone(),
        local_state,
        YougenSecureKeyStoreAdapter::new(secure_key_store),
    )
}

#[cfg(target_arch = "wasm32")]
pub fn build_memory_client_core(http: cokret_sdk::http_client::Client) -> DefaultClientCore {
    cokret_client::CokretClient::new(
        http,
        cokret_client::WasmExecutor,
        cokret_client::MemoryStore::new(),
        cokret_client::MemoryStore::new(),
        cokret_client::MemorySecureKeyStore::new(),
    )
}

#[cfg(test)]
mod tests {
    use cokret_client::{CursorStore, EventCacheStore, SecureKeyStore};

    #[test]
    fn memory_client_core_exposes_session_and_subscription_engines() {
        let http = cokret_sdk::http_client::Client::new("https://service.example".parse().unwrap())
            .unwrap();
        let client = super::build_memory_client_core(http);

        let _session = client.session_engine();
        let _subscription = client.subscription_engine();
    }

    #[tokio::test]
    async fn local_state_adapter_persists_client_core_cursors_and_event_cache() {
        let path = std::env::temp_dir().join(format!(
            "yougen-client-core-adapter-{}.json",
            crate::operation::uuid_v7()
        ));
        let adapter = super::YougenLocalStateStoreAdapter::new(
            crate::local_state::LocalStateStore::with_path(path),
        );
        let account_scope = cokret_client::CursorScope::Account {
            service_did: None,
            actor_id: cokret_sdk::Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            device_id: cokret_sdk::DeviceId::new("ck:device:01904100-0000-7000-8000-000000000001")
                .unwrap(),
        };
        let realm_scope = cokret_client::CursorScope::RealmEvents {
            service_did: None,
            realm_id: cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001")
                .unwrap(),
        };
        let event_id =
            cokret_sdk::EventId::new("ck:event:01904100-0000-7000-8000-000000000001").unwrap();

        adapter
            .save(account_scope.clone(), "ck:cursor:account".to_owned())
            .await
            .unwrap();
        adapter
            .save(realm_scope.clone(), "ck:cursor:realm".to_owned())
            .await
            .unwrap();
        adapter.remember(event_id.clone()).await.unwrap();

        assert_eq!(
            adapter
                .load(account_scope.clone())
                .await
                .unwrap()
                .as_deref(),
            Some("ck:cursor:account")
        );
        assert_eq!(
            adapter.load(realm_scope.clone()).await.unwrap().as_deref(),
            Some("ck:cursor:realm")
        );
        assert!(adapter.seen(event_id).await.unwrap());

        adapter.clear(account_scope).await.unwrap();
        adapter.clear(realm_scope).await.unwrap();
        assert!(
            adapter
                .load(cokret_client::CursorScope::Account {
                    service_did: None,
                    actor_id: cokret_sdk::Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
                    device_id: cokret_sdk::DeviceId::new(
                        "ck:device:01904100-0000-7000-8000-000000000001",
                    )
                    .unwrap(),
                })
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn secure_key_store_adapter_round_trips_binary_secrets() {
        let adapter = super::YougenSecureKeyStoreAdapter::new(std::sync::Arc::new(
            crate::secure_key_store::MemorySecureKeyStore::new(),
        ));

        adapter
            .store_secret_bytes_durable("client-core.secret", &[0, 1, 2, 255])
            .await
            .unwrap();

        assert_eq!(
            adapter
                .get_secret_bytes("client-core.secret")
                .unwrap()
                .as_ref()
                .map(|secret| secret.as_slice()),
            Some([0, 1, 2, 255].as_slice())
        );
        assert_eq!(
            adapter.list_secret_keys(Some("client-core")).unwrap(),
            vec!["client-core.secret".to_owned()]
        );
        adapter.delete_secret("client-core.secret").unwrap();
        assert!(
            adapter
                .get_secret_bytes("client-core.secret")
                .unwrap()
                .is_none()
        );
    }
}
