//! Thin host-adapter entry points for the shared `garth` client runtime.
//!
//! The production path still uses the existing inkson engines until the E-wave
//! migration replaces them. This module gives that migration a typed,
//! target-aware construction point without pulling UI state into client-core.

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

#[derive(Clone, Debug)]
pub struct InksonRealmEventsTransport {
    http: arkret_sdk::http_client::Client,
    max_duration_ms: Option<u64>,
    heartbeat_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RealmEventsTraceContext {
    after: Option<String>,
    catchup: bool,
}

impl RealmEventsTraceContext {
    fn from_after(after: Option<&str>) -> Self {
        Self {
            after: after.map(str::to_owned),
            catchup: after.is_none(),
        }
    }
}

pub struct InksonRealmEventsFrameSource {
    inner: arkret_sdk::http_client::EventsSubscribeFrameStream,
    _trace_context: RealmEventsTraceContext,
}

impl RealmEventsFrameSource for InksonRealmEventsFrameSource {
    fn next_frame<'a>(
        &'a mut self,
    ) -> garth::subscribe::realm::BoxRealmStreamFuture<'a, Option<arkret_sdk::EventsSubscribeFrame>>
    {
        Box::pin(async move { self.inner.next_frame().await })
    }
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

    fn subscribe_request(
        &self,
        realm_id: &arkret_sdk::RealmId,
        after: Option<&str>,
    ) -> (
        arkret_sdk::http_client::EventsSubscribeOptions,
        RealmEventsTraceContext,
    ) {
        let trace_context = RealmEventsTraceContext::from_after(after);
        let mut options = arkret_sdk::http_client::EventsSubscribeOptions::new()
            .realm(realm_id.as_str().to_owned())
            .include_history(trace_context.catchup);
        if let Some(after) = trace_context.after.as_deref() {
            options = options.after(after.to_owned());
        }
        if let Some(max_duration_ms) = self.max_duration_ms {
            options = options.max_duration_ms(max_duration_ms);
        }
        if let Some(heartbeat_ms) = self.heartbeat_ms {
            options = options.heartbeat_ms(heartbeat_ms);
        }
        (options, trace_context)
    }
}

impl RealmEventsTransport for InksonRealmEventsTransport {
    type Source = InksonRealmEventsFrameSource;

    fn open_realm_events<'a>(
        &'a self,
        realm_id: &'a arkret_sdk::RealmId,
        after: Option<&'a str>,
    ) -> garth::subscribe::realm::BoxRealmStreamFuture<'a, Self::Source> {
        Box::pin(async move {
            let (options, trace_context) = self.subscribe_request(realm_id, after);
            let inner = self.http.events_subscribe_frames(&options).await?;
            Ok(InksonRealmEventsFrameSource {
                inner,
                _trace_context: trace_context,
            })
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
    use garth::{
        CursorStore, EventCacheStore, RealmEventsFrameSource, RealmEventsTransport, SecureKeyStore,
    };

    #[test]
    fn memory_client_core_exposes_host_session_and_subscription_engines() {
        let http = arkret_sdk::http_client::Client::new("https://service.example".parse().unwrap())
            .unwrap();
        let client = super::build_memory_client_core(http.clone());

        let _session = garth::SessionEngine::new(http);
        let _subscription = client.subscription_engine();
    }

    #[test]
    fn realm_events_request_retains_initial_and_resumed_trace_context() {
        let http = arkret_sdk::http_client::Client::new("https://service.example".parse().unwrap())
            .unwrap();
        let transport = super::InksonRealmEventsTransport::new(http)
            .with_max_duration_ms(30_000)
            .with_heartbeat_ms(5_000);
        let realm_id =
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();

        let (initial, initial_context) = transport.subscribe_request(&realm_id, None);
        assert_eq!(initial.realms, vec![realm_id.as_str().to_owned()]);
        assert_eq!(initial.after, None);
        assert_eq!(initial.include_history, Some(true));
        assert_eq!(initial.max_duration_ms, Some(30_000));
        assert_eq!(initial.heartbeat_ms, Some(5_000));
        assert_eq!(
            initial_context,
            super::RealmEventsTraceContext {
                after: None,
                catchup: true,
            }
        );

        let (resumed, resumed_context) =
            transport.subscribe_request(&realm_id, Some("ak:cursor:resume"));
        assert_eq!(resumed.after.as_deref(), Some("ak:cursor:resume"));
        assert_eq!(resumed.include_history, Some(false));
        assert_eq!(
            resumed_context,
            super::RealmEventsTraceContext {
                after: Some("ak:cursor:resume".to_owned()),
                catchup: false,
            }
        );
    }

    #[tokio::test]
    async fn realm_events_transport_yields_before_stream_response_closes() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let read = socket.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            request_tx
                .send(String::from_utf8(request).unwrap())
                .unwrap();

            let frame = b"{\"cursor\":\"ak:cursor:first\",\"kind\":\"frontier\"}\n";
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
                )
                .unwrap();
            write!(socket, "{:X}\r\n", frame.len()).unwrap();
            socket.write_all(frame).unwrap();
            socket.write_all(b"\r\n").unwrap();
            socket.flush().unwrap();

            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            socket.write_all(b"0\r\n\r\n").unwrap();
        });

        let http =
            arkret_sdk::http_client::Client::builder(format!("http://{address}/").parse().unwrap())
                .allow_insecure_localhost()
                .build()
                .unwrap();
        let transport = super::InksonRealmEventsTransport::new(http);
        let realm_id =
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
        let mut source = tokio::time::timeout(
            Duration::from_secs(2),
            transport.open_realm_events(&realm_id, None),
        )
        .await
        .expect("response headers should arrive")
        .unwrap();
        let frame = tokio::time::timeout(Duration::from_secs(2), source.next_frame())
            .await
            .expect("the first frame must not wait for response EOF")
            .unwrap()
            .unwrap();
        assert_eq!(frame.kind, arkret_sdk::EventsSubscribeFrameKind::Frontier);
        assert_eq!(
            frame.cursor.as_ref().map(|cursor| cursor.as_str()),
            Some("ak:cursor:first")
        );

        let request = request_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(request.starts_with("GET /_arkret/self/events/subscribe?"));
        assert!(request.contains("include_history=true"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("accept: application/x-ndjson")
        );
        release_tx.send(()).unwrap();
        server.join().unwrap();
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
