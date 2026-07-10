//! Thin host-adapter entry points for the shared `garth` client runtime.
//!
//! The production path still uses the existing inkson engines until the E-wave
//! migration replaces them. This module gives that migration a typed,
//! target-aware construction point without pulling UI state into client-core.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use dioxus::prelude::{ReadableExt, SyncSignal, WritableExt};

use garth::{RealmEventsFrameSource, RealmEventsTransport};
#[cfg(not(target_arch = "wasm32"))]
use reqwest::header::CONTENT_TYPE;

use crate::sync_parse::{AccountSubscribeReconnectAfter, AccountSubscribeSnapshotResult};

#[derive(Clone)]
pub struct InksonLocalStateStoreAdapter {
    inner: InksonLocalStateStoreHandle,
}

#[derive(Clone)]
enum InksonLocalStateStoreHandle {
    Owned(Arc<Mutex<crate::local_state::LocalStateStore>>),
    Signal(SyncSignal<crate::local_state::LocalStateStore>),
}

impl InksonLocalStateStoreAdapter {
    pub fn new(store: crate::local_state::LocalStateStore) -> Self {
        Self {
            inner: InksonLocalStateStoreHandle::Owned(Arc::new(Mutex::new(store))),
        }
    }

    pub fn from_signal(store: SyncSignal<crate::local_state::LocalStateStore>) -> Self {
        Self {
            inner: InksonLocalStateStoreHandle::Signal(store),
        }
    }

    fn with_store<R>(
        &self,
        f: impl FnOnce(&crate::local_state::LocalStateStore) -> R,
    ) -> arkret_sdk::Result<R> {
        match &self.inner {
            InksonLocalStateStoreHandle::Owned(store) => {
                let store = store.lock().map_err(|error| {
                    arkret_sdk::Error::Protocol(format!("local state lock poisoned: {error}"))
                })?;
                Ok(f(&store))
            }
            InksonLocalStateStoreHandle::Signal(store) => Ok(f(&store.read())),
        }
    }

    fn with_store_mut<R>(
        &self,
        f: impl FnOnce(&mut crate::local_state::LocalStateStore) -> R,
    ) -> arkret_sdk::Result<R> {
        match &self.inner {
            InksonLocalStateStoreHandle::Owned(store) => {
                let mut store = store.lock().map_err(|error| {
                    arkret_sdk::Error::Protocol(format!("local state lock poisoned: {error}"))
                })?;
                Ok(f(&mut store))
            }
            InksonLocalStateStoreHandle::Signal(store) => {
                let mut store = *store;
                Ok(f(&mut store.write()))
            }
        }
    }

    fn realm_id(scope: &garth::CursorScope) -> Option<String> {
        match scope {
            garth::CursorScope::RealmEvents { realm_id, .. } => Some(realm_id.as_str().to_owned()),
            _ => None,
        }
    }
}

impl garth::CursorStore for InksonLocalStateStoreAdapter {
    async fn load(
        &self,
        scope: garth::CursorScope,
    ) -> arkret_sdk::Result<Option<garth::OpaqueCursor>> {
        self.with_store(|store| match scope {
            garth::CursorScope::Account { .. } => store
                .sync_cursor()
                .filter(|cursor| !cursor.trim().is_empty()),
            garth::CursorScope::RealmEvents { realm_id, .. } => {
                store.realm_events_cursor(realm_id.as_str())
            }
        })
    }

    async fn save(
        &self,
        scope: garth::CursorScope,
        cursor: garth::OpaqueCursor,
    ) -> arkret_sdk::Result<()> {
        self.with_store_mut(|store| match scope {
            garth::CursorScope::Account { .. } => store.save_sync_cursor(cursor),
            garth::CursorScope::RealmEvents { realm_id, .. } => {
                store.save_realm_events_cursor(realm_id.as_str(), Some(cursor));
            }
        })
    }

    async fn clear(&self, scope: garth::CursorScope) -> arkret_sdk::Result<()> {
        self.with_store_mut(|store| match scope {
            garth::CursorScope::Account { .. } => store.clear_sync_cursor(),
            garth::CursorScope::RealmEvents { .. } => {
                if let Some(realm_id) = Self::realm_id(&scope) {
                    store.save_realm_events_cursor(&realm_id, None);
                }
            }
        })
    }
}

impl garth::EventCacheStore for InksonLocalStateStoreAdapter {
    async fn seen(&self, event_id: arkret_sdk::EventId) -> arkret_sdk::Result<bool> {
        self.with_store(|store| store.client_core_event_seen(event_id.as_str()))
    }

    async fn remember(&self, event_id: arkret_sdk::EventId) -> arkret_sdk::Result<()> {
        self.with_store_mut(|store| store.remember_client_core_event(event_id.as_str()))
    }
}

#[derive(Clone)]
pub struct ClientCoreState<E, C, D, S> {
    pub http: arkret_sdk::http_client::Client,
    pub secure_key_store: S,
    core: garth::ArkretClient<E, C, D>,
}

impl<E, C, D, S> ClientCoreState<E, C, D, S>
where
    E: garth::Executor,
    C: garth::CursorStore,
    D: garth::EventCacheStore,
{
    pub fn new(
        http: arkret_sdk::http_client::Client,
        secure_key_store: S,
        core: garth::ArkretClient<E, C, D>,
    ) -> Self {
        Self {
            http,
            secure_key_store,
            core,
        }
    }

    pub fn subscription_engine(&self) -> garth::SubscriptionEngine<E, C, D>
    where
        E: Clone,
    {
        self.core.subscription_engine()
    }
}

pub type MemoryClientCore<E> =
    ClientCoreState<E, garth::MemoryStore, garth::MemoryStore, garth::MemorySecureKeyStore>;

#[cfg(not(target_arch = "wasm32"))]
type InksonSubscriptionEngine = garth::SubscriptionEngine<
    garth::NativeExecutor,
    InksonLocalStateStoreAdapter,
    InksonLocalStateStoreAdapter,
>;

#[cfg(target_arch = "wasm32")]
type InksonSubscriptionEngine = garth::SubscriptionEngine<
    garth::WasmExecutor,
    InksonLocalStateStoreAdapter,
    InksonLocalStateStoreAdapter,
>;

#[derive(Clone)]
pub struct InksonClientRuntime {
    subscriptions: InksonSubscriptionEngine,
}

impl InksonClientRuntime {
    pub fn new(state_store: SyncSignal<crate::local_state::LocalStateStore>) -> Self {
        let adapter = InksonLocalStateStoreAdapter::from_signal(state_store);
        #[cfg(not(target_arch = "wasm32"))]
        let executor = garth::NativeExecutor;
        #[cfg(target_arch = "wasm32")]
        let executor = garth::WasmExecutor;
        Self {
            subscriptions: garth::SubscriptionEngine::new(executor, adapter.clone(), adapter),
        }
    }

    pub fn subscription_engine(&self) -> InksonSubscriptionEngine {
        self.subscriptions.clone()
    }
}

pub struct BufferedRealmEventsFrameSource {
    frames: VecDeque<arkret_sdk::EventsSubscribeFrame>,
}

impl BufferedRealmEventsFrameSource {
    fn new(frames: Vec<arkret_sdk::EventsSubscribeFrame>) -> Self {
        Self {
            frames: VecDeque::from(frames),
        }
    }
}

impl RealmEventsFrameSource for BufferedRealmEventsFrameSource {
    fn next_frame<'a>(
        &'a mut self,
    ) -> garth::subscribe::realm::BoxRealmStreamFuture<'a, Option<arkret_sdk::EventsSubscribeFrame>>
    {
        let frame = self.frames.pop_front();
        Box::pin(async move { Ok(frame) })
    }
}

#[derive(Clone, Debug)]
pub struct InksonRealmEventsTransport {
    http: arkret_sdk::http_client::Client,
    max_duration_ms: Option<u64>,
    heartbeat_ms: Option<u64>,
}

impl InksonRealmEventsTransport {
    pub fn new(http: arkret_sdk::http_client::Client) -> Self {
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

impl RealmEventsTransport for InksonRealmEventsTransport {
    type Source = BufferedRealmEventsFrameSource;

    fn open_realm_events<'a>(
        &'a self,
        realm_id: &'a arkret_sdk::RealmId,
        after: Option<&'a str>,
    ) -> garth::subscribe::realm::BoxRealmStreamFuture<'a, Self::Source> {
        Box::pin(async move {
            let mut options = arkret_sdk::http_client::EventsSubscribeOptions::new()
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
                .map_err(|error| arkret_sdk::Error::Http(error.to_string()))?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))?;
            let frames = crate::sync_parse::parse_events_subscribe_ndjson_text(text)
                .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))?;
            Ok(BufferedRealmEventsFrameSource::new(frames))
        })
    }
}

impl garth::EventsScanTransport for InksonRealmEventsTransport {
    fn scan_events<'a>(
        &'a self,
        request: garth::EventsScanRequest,
    ) -> garth::subscribe::scan::BoxScanFuture<'a, arkret_sdk::SyncBackfillOutcome> {
        garth::EventsScanTransport::scan_events(&self.http, request)
    }
}

pub async fn account_subscribe_snapshot(
    http: &arkret_sdk::http_client::Client,
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
    http: &arkret_sdk::http_client::Client,
    after: Option<&str>,
) -> anyhow::Result<AccountSubscribeSnapshotResult> {
    account_subscribe_snapshot_outcome_with_options(
        http,
        after,
        &arkret_sdk::http_client::ClientRequestOptions::default(),
    )
    .await
}

pub async fn account_subscribe_snapshot_with_options(
    http: &arkret_sdk::http_client::Client,
    after: Option<&str>,
    options: &arkret_sdk::http_client::ClientRequestOptions,
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
    http: &arkret_sdk::http_client::Client,
    after: Option<&str>,
    options: &arkret_sdk::http_client::ClientRequestOptions,
) -> anyhow::Result<AccountSubscribeSnapshotResult> {
    let after = after
        .map(crate::wire_helpers::validate_cursor)
        .transpose()?
        .map(|cursor| cursor.into_string());

    let _subscribe_gate = crate::sync_parse::ACCOUNT_SUBSCRIBE_NETWORK_GATE
        .lock()
        .await;
    let request = arkret_sdk::SyncRequestBody {
        after,
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
pub type DefaultClientCore = MemoryClientCore<garth::NativeExecutor>;

#[cfg(target_arch = "wasm32")]
pub type DefaultClientCore = MemoryClientCore<garth::WasmExecutor>;

#[cfg(not(target_arch = "wasm32"))]
pub fn build_memory_client_core(http: arkret_sdk::http_client::Client) -> DefaultClientCore {
    let secure_key_store = garth::MemorySecureKeyStore::new();
    ClientCoreState::new(
        http,
        secure_key_store,
        garth::ArkretClient::new(
            garth::NativeExecutor,
            garth::MemoryStore::new(),
            garth::MemoryStore::new(),
        ),
    )
}

#[cfg(target_arch = "wasm32")]
pub fn build_memory_client_core(http: arkret_sdk::http_client::Client) -> DefaultClientCore {
    let secure_key_store = garth::MemorySecureKeyStore::new();
    ClientCoreState::new(
        http,
        secure_key_store,
        garth::ArkretClient::new(
            garth::WasmExecutor,
            garth::MemoryStore::new(),
            garth::MemoryStore::new(),
        ),
    )
}

#[cfg(test)]
mod tests {
    use garth::{CursorStore, EventCacheStore, SecureKeyStore};

    #[test]
    fn memory_client_core_exposes_host_session_and_subscription_engines() {
        let http = arkret_sdk::http_client::Client::new("https://service.example".parse().unwrap())
            .unwrap();
        let client = super::build_memory_client_core(http.clone());

        let _session = garth::SessionEngine::new(http);
        let _subscription = client.subscription_engine();
    }

    #[tokio::test]
    async fn local_state_adapter_persists_client_core_cursors_and_event_cache() {
        let path = std::env::temp_dir().join(format!(
            "inkson-client-core-adapter-{}.json",
            crate::operation::uuid_v7()
        ));
        let adapter = super::InksonLocalStateStoreAdapter::new(
            crate::local_state::LocalStateStore::with_path(path),
        );
        let account_scope = garth::CursorScope::Account {
            service_did: None,
            actor_id: arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            device_id: arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001")
                .unwrap(),
        };
        let realm_scope = garth::CursorScope::RealmEvents {
            service_did: None,
            realm_id: arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001")
                .unwrap(),
        };
        let event_id =
            arkret_sdk::EventId::new("ak:event:01904100-0000-7000-8000-000000000001").unwrap();

        adapter
            .save(account_scope.clone(), "ak:cursor:account".to_owned())
            .await
            .unwrap();
        adapter
            .save(realm_scope.clone(), "ak:cursor:realm".to_owned())
            .await
            .unwrap();
        adapter.remember(event_id.clone()).await.unwrap();

        assert_eq!(
            adapter
                .load(account_scope.clone())
                .await
                .unwrap()
                .as_deref(),
            Some("ak:cursor:account")
        );
        assert_eq!(
            adapter.load(realm_scope.clone()).await.unwrap().as_deref(),
            Some("ak:cursor:realm")
        );
        assert!(adapter.seen(event_id).await.unwrap());

        adapter.clear(account_scope).await.unwrap();
        adapter.clear(realm_scope).await.unwrap();
        assert!(
            adapter
                .load(garth::CursorScope::Account {
                    service_did: None,
                    actor_id: arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
                    device_id: arkret_sdk::DeviceId::new(
                        "ak:device:01904100-0000-7000-8000-000000000001",
                    )
                    .unwrap(),
                })
                .await
                .unwrap()
                .is_none()
        );
    }

    /// F-11: the shared garth `MemorySecureKeyStore` round-trips binary secrets
    /// end-to-end through the bytes trait surface (no inkson-side adapter).
    #[tokio::test]
    async fn secure_key_store_round_trips_binary_secrets() {
        let store = garth::MemorySecureKeyStore::new();

        store
            .store_secret_bytes_durable("client-core.secret", &[0, 1, 2, 255])
            .await
            .unwrap();

        assert_eq!(
            store
                .get_secret_bytes("client-core.secret")
                .unwrap()
                .as_ref()
                .map(|secret| secret.as_slice()),
            Some([0, 1, 2, 255].as_slice())
        );
        assert_eq!(
            store.list_secret_keys(Some("client-core")).unwrap(),
            vec!["client-core.secret".to_owned()]
        );
        store.delete_secret("client-core.secret").unwrap();
        assert!(
            store
                .get_secret_bytes("client-core.secret")
                .unwrap()
                .is_none()
        );
    }
}
