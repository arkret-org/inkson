//! Thin host-adapter entry points for the shared `garth` client runtime.
//!
//! This module provides typed, target-aware construction points for the shared
//! client runtime without pulling UI state into client-core.

use std::sync::{Arc, Mutex};

use garth::{RealmEventsFrameSource, RealmEventsTransport};

use crate::sync_parse::{AccountSubscribeReconnectAfter, AccountSubscribeSnapshotResult};

#[derive(Clone)]
pub struct InksonLocalStateStoreAdapter {
    inner: Arc<dyn LocalStateBackend>,
}

pub trait LocalStateBackend: Send + Sync {
    fn load_cursor(
        &self,
        scope: &garth::CursorScope,
    ) -> arkret_sdk::Result<Option<garth::OpaqueCursor>>;
    fn save_cursor(
        &self,
        scope: &garth::CursorScope,
        cursor: garth::OpaqueCursor,
    ) -> arkret_sdk::Result<()>;
    fn clear_cursor(&self, scope: &garth::CursorScope) -> arkret_sdk::Result<()>;
    fn event_seen(&self, event_id: &arkret_sdk::EventId) -> arkret_sdk::Result<bool>;
    fn remember_event(&self, event_id: &arkret_sdk::EventId) -> arkret_sdk::Result<()>;
}

pub(crate) fn device_message_cursor_key(
    service_id: Option<&arkret_sdk::Did>,
    actor_id: &arkret_sdk::Did,
    device_id: &arkret_sdk::DeviceId,
) -> arkret_sdk::Result<String> {
    serde_json::to_string(&serde_json::json!({
        "service_id": service_id.map(arkret_sdk::Did::as_str),
        "actor_id": actor_id.as_str(),
        "device_id": device_id.as_str(),
    }))
    .map_err(Into::into)
}

struct OwnedLocalStateBackend {
    store: Mutex<crate::state::LocalStateStore>,
}

impl OwnedLocalStateBackend {
    fn with_store<R>(
        &self,
        f: impl FnOnce(&crate::state::LocalStateStore) -> R,
    ) -> arkret_sdk::Result<R> {
        let store = self.store.lock().map_err(|error| {
            arkret_sdk::Error::Protocol(format!("local state lock poisoned: {error}"))
        })?;
        Ok(f(&store))
    }

    fn with_store_mut<R>(
        &self,
        f: impl FnOnce(&mut crate::state::LocalStateStore) -> R,
    ) -> arkret_sdk::Result<R> {
        let mut store = self.store.lock().map_err(|error| {
            arkret_sdk::Error::Protocol(format!("local state lock poisoned: {error}"))
        })?;
        Ok(f(&mut store))
    }
}

impl LocalStateBackend for OwnedLocalStateBackend {
    fn load_cursor(
        &self,
        scope: &garth::CursorScope,
    ) -> arkret_sdk::Result<Option<garth::OpaqueCursor>> {
        self.with_store(|store| store.load_client_cursor(scope))?
    }

    fn save_cursor(
        &self,
        scope: &garth::CursorScope,
        cursor: garth::OpaqueCursor,
    ) -> arkret_sdk::Result<()> {
        self.with_store_mut(|store| store.save_client_cursor(scope, cursor))?
    }

    fn clear_cursor(&self, scope: &garth::CursorScope) -> arkret_sdk::Result<()> {
        self.with_store_mut(|store| store.clear_client_cursor(scope))?
    }

    fn event_seen(&self, event_id: &arkret_sdk::EventId) -> arkret_sdk::Result<bool> {
        self.with_store(|store| store.client_core_event_seen(event_id.as_str()))
    }

    fn remember_event(&self, event_id: &arkret_sdk::EventId) -> arkret_sdk::Result<()> {
        self.with_store_mut(|store| store.remember_client_core_event(event_id.as_str()))
    }
}

impl InksonLocalStateStoreAdapter {
    pub fn new(store: crate::state::LocalStateStore) -> Self {
        Self::from_backend(OwnedLocalStateBackend {
            store: Mutex::new(store),
        })
    }

    pub fn from_backend(backend: impl LocalStateBackend + 'static) -> Self {
        Self {
            inner: Arc::new(backend),
        }
    }
}

impl garth::CursorStore for InksonLocalStateStoreAdapter {
    async fn load(
        &self,
        scope: garth::CursorScope,
    ) -> arkret_sdk::Result<Option<garth::OpaqueCursor>> {
        self.inner.load_cursor(&scope)
    }

    async fn save(
        &self,
        scope: garth::CursorScope,
        cursor: garth::OpaqueCursor,
    ) -> arkret_sdk::Result<()> {
        self.inner.save_cursor(&scope, cursor)
    }

    async fn clear(&self, scope: garth::CursorScope) -> arkret_sdk::Result<()> {
        self.inner.clear_cursor(&scope)
    }
}

impl garth::EventCacheStore for InksonLocalStateStoreAdapter {
    async fn seen(&self, event_id: arkret_sdk::EventId) -> arkret_sdk::Result<bool> {
        self.inner.event_seen(&event_id)
    }

    async fn remember(&self, event_id: arkret_sdk::EventId) -> arkret_sdk::Result<()> {
        self.inner.remember_event(&event_id)
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

#[cfg(not(target_arch = "wasm32"))]
type InksonArkretClient = garth::ArkretClient<
    garth::NativeExecutor,
    InksonLocalStateStoreAdapter,
    InksonLocalStateStoreAdapter,
>;

#[cfg(target_arch = "wasm32")]
type InksonArkretClient = garth::ArkretClient<
    garth::WasmExecutor,
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
    client: InksonArkretClient,
}

impl InksonClientRuntime {
    pub(crate) fn from_state_adapter(adapter: InksonLocalStateStoreAdapter) -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        let executor = garth::NativeExecutor;
        #[cfg(target_arch = "wasm32")]
        let executor = garth::WasmExecutor;
        Self {
            client: garth::ArkretClient::new(executor, adapter.clone(), adapter),
        }
    }

    pub fn subscription_engine(&self) -> InksonSubscriptionEngine {
        self.client.subscription_engine()
    }

    pub(crate) fn client(&self) -> InksonArkretClient {
        self.client.clone()
    }
}

#[derive(Clone, Debug)]
pub struct InksonRealmEventsTransport {
    http: arkret_sdk::http_client::Client,
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
            // Every bounded long-poll reconnect asks the server to replay the
            // gap after our durable cursor before switching back to live
            // delivery. `catchup=false` with an `after` cursor can lose an
            // event that lands between response close and the next receiver.
            catchup: true,
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
        Self { http }
    }

    /// Build the subscribe options with the request-aware trace context: a
    /// initial and resumed subscribes are catch-up requests: the latter closes
    /// the response-boundary gap after the durable cursor. The `catchup` flag
    /// seeds the SDK frame stream's internal `StreamTraceValidator`, so
    /// every frame this adapter yields has already passed the full §1.1 trace
    /// state machine — there is no shape-only parsing bypass.
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
            .catchup(trace_context.catchup);
        if let Some(after) = trace_context.after.as_deref() {
            options = options.after(after.to_owned());
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
            reconnect_cursor,
            reason,
            reset_cursor,
        } => Err(AccountSubscribeReconnectAfter {
            reconnect_after_ms,
            reconnect_cursor,
            reason,
            reset_cursor,
        }
        .into()),
    }
}

/// One validated account-subscribe snapshot through the SDK's request-aware
/// pipeline (SPI-INK-002). `account_subscribe_once` runs the full §1.1
/// StreamTraceValidator over every frame — inkson no longer parses NDJSON
/// shapes itself, so there is no trace-bypassing side path. Stream interrupts
/// (`dropped` / `resync_required` / `unauthorized`) fold back into the typed
/// [`AccountSubscribeSnapshotResult::ReconnectAfter`] the engine consumes.
pub async fn account_subscribe_snapshot_outcome(
    http: &arkret_sdk::http_client::Client,
    after: Option<&str>,
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
    match http.account_subscribe_once(&request).await {
        Ok(outcome) => Ok(AccountSubscribeSnapshotResult::Delta(Box::new(outcome))),
        Err(arkret_sdk::Error::AccountStreamInterrupt(interrupt)) => {
            Ok(reconnect_result_from_interrupt(interrupt))
        }
        Err(error) => Err(error.into()),
    }
}

fn reconnect_result_from_interrupt(
    interrupt: arkret_sdk::AccountStreamInterrupt,
) -> AccountSubscribeSnapshotResult {
    let clamp = |raw: Option<u64>| {
        raw.unwrap_or(arkret_sdk::DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS)
            .min(arkret_sdk::MAX_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS)
    };
    match interrupt {
        arkret_sdk::AccountStreamInterrupt::Dropped {
            cursor,
            reconnect_after_ms,
        } => AccountSubscribeSnapshotResult::ReconnectAfter {
            reconnect_after_ms: clamp(reconnect_after_ms),
            reconnect_cursor: Some(cursor),
            reason: None,
            reset_cursor: false,
        },
        arkret_sdk::AccountStreamInterrupt::ResyncRequired { reconnect_after_ms } => {
            AccountSubscribeSnapshotResult::ReconnectAfter {
                reconnect_after_ms: clamp(reconnect_after_ms),
                reconnect_cursor: None,
                reason: None,
                reset_cursor: true,
            }
        }
        arkret_sdk::AccountStreamInterrupt::Unauthorized => {
            AccountSubscribeSnapshotResult::ReconnectAfter {
                reconnect_after_ms: clamp(None),
                reconnect_cursor: None,
                reason: None,
                reset_cursor: false,
            }
        }
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
        let transport = super::InksonRealmEventsTransport::new(http);
        let realm_id =
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();

        let (initial, initial_context) = transport.subscribe_request(&realm_id, None);
        assert_eq!(initial.realms, vec![realm_id.as_str().to_owned()]);
        assert_eq!(initial.after, None);
        assert_eq!(initial.catchup, Some(true));
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
        assert_eq!(resumed.catchup, Some(true));
        assert_eq!(
            resumed_context,
            super::RealmEventsTraceContext {
                after: Some("ak:cursor:resume".to_owned()),
                catchup: true,
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
        assert!(request.contains("catchup=true"));
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
            crate::state::LocalStateStore::with_path(path),
        );
        let account_scope = garth::CursorScope::Account {
            service_id: None,
            actor_id: arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            device_id: arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001")
                .unwrap(),
        };
        let realm_scope = garth::CursorScope::RealmEvents {
            service_id: None,
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
                    service_id: None,
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

    #[tokio::test]
    async fn projector_failure_does_not_advance_inkson_cursor_or_dedupe() {
        use std::collections::VecDeque;
        use std::sync::{Arc, Mutex};

        use garth::{BoxRealmStreamFuture, ClientEvent, ClientProjector, RealmEventsDriver};

        struct Frames(VecDeque<arkret_sdk::Result<arkret_sdk::EventsSubscribeFrame>>);

        impl RealmEventsFrameSource for Frames {
            fn next_frame<'a>(
                &'a mut self,
            ) -> BoxRealmStreamFuture<'a, Option<arkret_sdk::EventsSubscribeFrame>> {
                let frame = self.0.pop_front();
                Box::pin(async move { frame.transpose() })
            }
        }

        struct Transport(Vec<arkret_sdk::EventsSubscribeFrame>);

        impl RealmEventsTransport for Transport {
            type Source = Frames;

            fn open_realm_events<'a>(
                &'a self,
                _realm_id: &'a arkret_sdk::RealmId,
                _after: Option<&'a str>,
            ) -> BoxRealmStreamFuture<'a, Self::Source> {
                let frames = self.0.clone().into_iter().map(Ok).collect();
                Box::pin(async move { Ok(Frames(frames)) })
            }
        }

        struct Projector {
            fail: bool,
            calls: Arc<Mutex<usize>>,
        }

        impl ClientProjector for Projector {
            async fn project(&self, _batch: Vec<ClientEvent>) -> arkret_sdk::Result<()> {
                *self.calls.lock().unwrap() += 1;
                if self.fail {
                    Err(arkret_sdk::Error::Protocol(
                        "injected Inkson projection failure".to_owned(),
                    ))
                } else {
                    Ok(())
                }
            }
        }

        let path = std::env::temp_dir().join(format!(
            "inkson-projector-failure-drill-{}.json",
            crate::operation::uuid_v7()
        ));
        let adapter = super::InksonLocalStateStoreAdapter::new(
            crate::state::LocalStateStore::with_path(path.clone()),
        );
        let realm_id =
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
        let event = arkret_sdk::Event::new(
            arkret_sdk::events::kinds::MESSAGE_CREATE,
            realm_id.clone(),
            arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            1,
            arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            serde_json::json!({
                "content": {"kind": "ak.content.text", "body": "hello"},
                "strand_id": "ak:strand:01904100-0000-7000-8000-000000000002",
                "track_name": "discussion"
            }),
        )
        .unwrap();
        let event_id = event.event_id.clone();
        let frames = vec![
            arkret_sdk::EventsSubscribeFrame {
                kind: arkret_sdk::EventsSubscribeFrameKind::Event,
                realm_id: Some(realm_id.clone()),
                cursor: Some(arkret_sdk::identifiers::Cursor::new("ak:cursor:projected").unwrap()),
                payload: serde_json::to_value(event).unwrap(),
                reconnect_after_ms: None,
            },
            arkret_sdk::EventsSubscribeFrame {
                kind: arkret_sdk::EventsSubscribeFrameKind::Unauthorized,
                realm_id: Some(realm_id.clone()),
                cursor: None,
                payload: serde_json::json!({"reason": "stop fixture"}),
                reconnect_after_ms: None,
            },
        ];
        let driver = RealmEventsDriver::new(adapter.clone(), adapter.clone());
        let calls = Arc::new(Mutex::new(0));

        assert!(
            driver
                .run_stream(
                    &Transport(frames.clone()),
                    realm_id.clone(),
                    &Projector {
                        fail: true,
                        calls: Arc::clone(&calls),
                    },
                )
                .await
                .is_err()
        );
        let scope = garth::CursorScope::RealmEvents {
            service_id: None,
            realm_id: realm_id.clone(),
        };
        assert!(adapter.load(scope.clone()).await.unwrap().is_none());
        assert!(!adapter.seen(event_id.clone()).await.unwrap());

        driver
            .run_stream(
                &Transport(frames),
                realm_id,
                &Projector {
                    fail: false,
                    calls: Arc::clone(&calls),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            adapter.load(scope).await.unwrap().as_deref(),
            Some("ak:cursor:projected")
        );
        assert!(adapter.seen(event_id).await.unwrap());
        assert_eq!(*calls.lock().unwrap(), 2);
        let _ = std::fs::remove_file(path);
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
