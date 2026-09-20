//! Thin host-adapter entry points for the shared `garth` client runtime.
//!
//! This module provides typed, target-aware construction points for the shared
//! client runtime without pulling UI state into client-core.

use std::sync::{Arc, Mutex};

/// Account transport adapter for the durable account-aggregate subscription.
///
/// v1 removed the plaintext presence bucket from account sync, so there is no
/// longer a set of sender devices to pre-resolve here: presence arrives as an
/// encrypted Signal on its own rail and its device proof is resolved there.
#[derive(Clone)]
pub(crate) struct InksonAccountTransport {
    http: arkret_sdk::http_client::Client,
}

impl InksonAccountTransport {
    pub(crate) fn new(http: arkret_sdk::http_client::Client) -> Self {
        Self { http }
    }

    pub(crate) fn http(&self) -> &arkret_sdk::http_client::Client {
        &self.http
    }
}

impl garth::AccountSubscribeTransport for InksonAccountTransport {
    /// One bounded delivery window of the account aggregate.
    ///
    /// `AccountSubscribeSnapshotResult` already folds the Station's control
    /// interrupts (drop with a resume cursor, resync-required, unauthorized)
    /// into the shape [`garth::AccountRunner`] resumes from, so nothing here
    /// re-derives reconnect policy.
    async fn subscribe(
        &self,
        request: &arkret_models_collaboration::sync_frames::account_subscribe::SyncRequestBody,
    ) -> garth::Result<
        arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeSnapshotResult,
    > {
        garth::AccountSubscribeTransport::subscribe(&self.http, request).await
    }
}

#[derive(Clone)]
pub struct InksonLocalStateStoreAdapter {
    inner: Arc<dyn LocalStateBackend>,
    inbox_serial: Arc<futures_util::lock::Mutex<()>>,
}

pub(crate) trait LocalStateBackend: Send + Sync {
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
    fn load_account_checkpoint(
        &self,
        scope: &garth::CursorScope,
    ) -> arkret_sdk::Result<Option<garth::AccountCursorCheckpoint>>;
    fn save_account_checkpoint(
        &self,
        scope: &garth::CursorScope,
        checkpoint: garth::AccountCursorCheckpoint,
    ) -> arkret_sdk::Result<()>;
    fn restore_account_checkpoint(
        &self,
        scope: &garth::CursorScope,
        checkpoint: Option<garth::AccountCursorCheckpoint>,
    ) -> arkret_sdk::Result<()>;
    fn event_seen(&self, event_id: &arkret_sdk::EventId) -> arkret_sdk::Result<bool>;
    fn remember_event(&self, event_id: &arkret_sdk::EventId) -> arkret_sdk::Result<()>;
    fn commit_delivery(
        &self,
        scope: garth::CursorScope,
        cursor: Option<garth::OpaqueCursor>,
        events: Vec<garth::ClientEvent>,
    ) -> arkret_sdk::Result<Option<garth::DeliveryId>>;
    fn pending_deliveries(
        &self,
        limit: usize,
    ) -> arkret_sdk::Result<Vec<garth::PendingDelivery<Vec<garth::ClientEvent>>>>;
    fn ack_delivery(&self, id: garth::DeliveryId) -> arkret_sdk::Result<bool>;
    fn retry_delivery(
        &self,
        id: garth::DeliveryId,
        next_attempt_at_ms: Option<i64>,
        error_class: garth::DeliveryErrorClass,
        error: String,
    ) -> arkret_sdk::Result<bool>;
    fn delivery_snapshot(
        &self,
        id: garth::DeliveryId,
    ) -> arkret_sdk::Result<Option<crate::state::StoredClientDelivery>>;
    fn restore_delivery(
        &self,
        delivery: crate::state::StoredClientDelivery,
    ) -> arkret_sdk::Result<()>;
    fn rollback_delivery_commit(
        &self,
        scope: &garth::CursorScope,
        previous_cursor: Option<garth::OpaqueCursor>,
        delivery_id: Option<garth::DeliveryId>,
    ) -> arkret_sdk::Result<()>;
    fn begin_durable_flush(&self) -> arkret_sdk::Result<crate::state::LocalStatePersistBarrier>;
}

pub(crate) fn device_message_cursor_key(
    service_id: Option<&arkret_sdk::DidCoreId>,
    actor_id: &arkret_sdk::ActorId,
    device_id: &arkret_sdk::DeviceId,
) -> arkret_sdk::Result<String> {
    serde_json::to_string(&serde_json::json!({
        "service_id": service_id.map(arkret_sdk::DidCoreId::as_str),
        "actor_id": actor_id,
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

    fn load_account_checkpoint(
        &self,
        scope: &garth::CursorScope,
    ) -> arkret_sdk::Result<Option<garth::AccountCursorCheckpoint>> {
        self.with_store(|store| store.load_account_checkpoint(scope))?
    }

    fn save_account_checkpoint(
        &self,
        scope: &garth::CursorScope,
        checkpoint: garth::AccountCursorCheckpoint,
    ) -> arkret_sdk::Result<()> {
        self.with_store_mut(|store| store.save_account_checkpoint(scope, checkpoint))?
    }

    fn restore_account_checkpoint(
        &self,
        scope: &garth::CursorScope,
        checkpoint: Option<garth::AccountCursorCheckpoint>,
    ) -> arkret_sdk::Result<()> {
        self.with_store_mut(|store| store.restore_account_checkpoint(scope, checkpoint))?
    }

    fn event_seen(&self, event_id: &arkret_sdk::EventId) -> arkret_sdk::Result<bool> {
        self.with_store(|store| store.client_core_event_seen(event_id.as_str()))
    }

    fn remember_event(&self, event_id: &arkret_sdk::EventId) -> arkret_sdk::Result<()> {
        self.with_store_mut(|store| store.remember_client_core_event(event_id.as_str()))
    }

    fn commit_delivery(
        &self,
        scope: garth::CursorScope,
        cursor: Option<garth::OpaqueCursor>,
        events: Vec<garth::ClientEvent>,
    ) -> arkret_sdk::Result<Option<garth::DeliveryId>> {
        self.with_store_mut(|store| store.commit_client_delivery(scope, cursor, events))?
    }

    fn pending_deliveries(
        &self,
        limit: usize,
    ) -> arkret_sdk::Result<Vec<garth::PendingDelivery<Vec<garth::ClientEvent>>>> {
        self.with_store(|store| store.pending_client_deliveries(limit))?
    }

    fn ack_delivery(&self, id: garth::DeliveryId) -> arkret_sdk::Result<bool> {
        self.with_store_mut(|store| store.ack_client_delivery(id))?
    }

    fn retry_delivery(
        &self,
        id: garth::DeliveryId,
        next_attempt_at_ms: Option<i64>,
        error_class: garth::DeliveryErrorClass,
        error: String,
    ) -> arkret_sdk::Result<bool> {
        self.with_store_mut(|store| {
            store.retry_client_delivery(id, next_attempt_at_ms, error_class, error)
        })?
    }

    fn delivery_snapshot(
        &self,
        id: garth::DeliveryId,
    ) -> arkret_sdk::Result<Option<crate::state::StoredClientDelivery>> {
        self.with_store(|store| store.client_delivery_snapshot(id))
    }

    fn restore_delivery(
        &self,
        delivery: crate::state::StoredClientDelivery,
    ) -> arkret_sdk::Result<()> {
        self.with_store_mut(|store| store.restore_client_delivery(delivery))?
    }

    fn rollback_delivery_commit(
        &self,
        scope: &garth::CursorScope,
        previous_cursor: Option<garth::OpaqueCursor>,
        delivery_id: Option<garth::DeliveryId>,
    ) -> arkret_sdk::Result<()> {
        self.with_store_mut(|store| {
            store.rollback_client_delivery_commit(scope, previous_cursor, delivery_id)
        })?
    }

    fn begin_durable_flush(&self) -> arkret_sdk::Result<crate::state::LocalStatePersistBarrier> {
        self.with_store(|store| store.begin_durable_flush())?
            .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))
    }
}

impl InksonLocalStateStoreAdapter {
    pub fn new(store: crate::state::LocalStateStore) -> Self {
        Self::from_backend(OwnedLocalStateBackend {
            store: Mutex::new(store),
        })
    }

    pub(crate) fn from_backend(backend: impl LocalStateBackend + 'static) -> Self {
        Self {
            inner: Arc::new(backend),
            inbox_serial: Arc::new(futures_util::lock::Mutex::new(())),
        }
    }

    async fn await_durable_flush(&self) -> garth::Result<()> {
        let barrier = self
            .inner
            .begin_durable_flush()
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        barrier
            .wait()
            .await
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    async fn persist_rollback<T>(&self, original: garth::Error) -> garth::Result<T> {
        self.await_durable_flush().await.map_err(|rollback| {
            garth::Error::Protocol(format!(
                "{original}; durable inbox rollback also failed: {rollback}"
            ))
        })?;
        Err(original)
    }
}

impl garth::CursorStore for InksonLocalStateStoreAdapter {
    async fn load(&self, scope: garth::CursorScope) -> garth::Result<Option<garth::OpaqueCursor>> {
        self.inner
            .load_cursor(&scope)
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    async fn save(
        &self,
        scope: garth::CursorScope,
        cursor: garth::OpaqueCursor,
    ) -> garth::Result<()> {
        self.inner
            .save_cursor(&scope, cursor)
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    async fn clear(&self, scope: garth::CursorScope) -> garth::Result<()> {
        self.inner
            .clear_cursor(&scope)
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    async fn load_account_checkpoint(
        &self,
        scope: garth::CursorScope,
    ) -> garth::Result<Option<garth::AccountCursorCheckpoint>> {
        self.inner
            .load_account_checkpoint(&scope)
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    async fn save_account_checkpoint(
        &self,
        scope: garth::CursorScope,
        checkpoint: garth::AccountCursorCheckpoint,
    ) -> garth::Result<()> {
        let previous = self
            .inner
            .load_account_checkpoint(&scope)
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        self.inner
            .save_account_checkpoint(&scope, checkpoint)
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        if let Err(error) = self.await_durable_flush().await {
            self.inner
                .restore_account_checkpoint(&scope, previous)
                .map_err(|rollback| {
                    garth::Error::Protocol(format!(
                        "{error}; in-memory account checkpoint rollback also failed: {rollback}"
                    ))
                })?;
            return self.persist_rollback(error).await;
        }
        Ok(())
    }
}

impl garth::EventCacheStore for InksonLocalStateStoreAdapter {
    async fn seen(&self, event_id: arkret_sdk::EventId) -> garth::Result<bool> {
        self.inner
            .event_seen(&event_id)
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    async fn remember(&self, event_id: arkret_sdk::EventId) -> garth::Result<()> {
        self.inner
            .remember_event(&event_id)
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }
}

impl garth::DurableInboxStore<Vec<garth::ClientEvent>> for InksonLocalStateStoreAdapter {
    async fn commit(
        &self,
        scope: garth::CursorScope,
        cursor: Option<garth::OpaqueCursor>,
        events: Vec<garth::ClientEvent>,
    ) -> garth::Result<garth::DeliveryId> {
        let _serial = self.inbox_serial.lock().await;
        let previous_cursor = self
            .inner
            .load_cursor(&scope)
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        let delivery_id = self
            .inner
            .commit_delivery(scope.clone(), cursor, events)
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        let durable = self.await_durable_flush().await;
        if let Err(error) = durable {
            self.inner
                .rollback_delivery_commit(&scope, previous_cursor, delivery_id)
                .map_err(|rollback| {
                    garth::Error::Protocol(format!(
                        "{error}; in-memory inbox rollback also failed: {rollback}"
                    ))
                })?;
            return self.persist_rollback(error).await;
        }
        delivery_id.ok_or_else(|| {
            garth::Error::Protocol("durable inbox commit produced no delivery".to_owned())
        })
    }

    async fn pending(
        &self,
        limit: usize,
    ) -> garth::Result<Vec<garth::PendingDelivery<Vec<garth::ClientEvent>>>> {
        let _serial = self.inbox_serial.lock().await;
        self.inner
            .pending_deliveries(limit)
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    async fn ack(&self, id: garth::DeliveryId) -> garth::Result<bool> {
        let _serial = self.inbox_serial.lock().await;
        let previous = self
            .inner
            .delivery_snapshot(id)
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        let removed = self
            .inner
            .ack_delivery(id)
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        if !removed {
            return Ok(false);
        }
        if let Err(error) = self.await_durable_flush().await {
            if let Some(previous) = previous {
                self.inner.restore_delivery(previous).map_err(|rollback| {
                    garth::Error::Protocol(format!(
                        "{error}; in-memory inbox acknowledgement rollback also failed: {rollback}"
                    ))
                })?;
            }
            return self.persist_rollback(error).await;
        }
        Ok(true)
    }

    async fn retry(
        &self,
        id: garth::DeliveryId,
        next_attempt_at_ms: Option<i64>,
        error_class: garth::DeliveryErrorClass,
        error: String,
    ) -> garth::Result<bool> {
        let _serial = self.inbox_serial.lock().await;
        let previous = self
            .inner
            .delivery_snapshot(id)
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        let updated = self
            .inner
            .retry_delivery(id, next_attempt_at_ms, error_class, error)
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        if !updated {
            return Ok(false);
        }
        if let Err(error) = self.await_durable_flush().await {
            if let Some(previous) = previous {
                self.inner.restore_delivery(previous).map_err(|rollback| {
                    garth::Error::Protocol(format!(
                        "{error}; in-memory inbox retry rollback also failed: {rollback}"
                    ))
                })?;
            }
            return self.persist_rollback(error).await;
        }
        Ok(true)
    }
}

/// Host-side client runtime: the durable local-state adapter plus the
/// target-appropriate executor.
///
/// It deliberately holds no transport. Under the authority-commit protocol a
/// transport is authenticated per connection attempt (see
/// [`crate::identity::session_refresh::provide_authenticated_sdk_client`]), and
/// the stream engines build [`garth::AuthorityClient`] /
/// [`garth::AccountRunner`] around the transport they just obtained.
#[derive(Clone)]
pub struct InksonClientRuntime {
    store: InksonLocalStateStoreAdapter,
}

impl InksonClientRuntime {
    pub(crate) fn from_state_adapter(adapter: InksonLocalStateStoreAdapter) -> Self {
        Self { store: adapter }
    }

    /// The durable cursor store the run loops checkpoint into.
    pub(crate) fn cursors(&self) -> InksonLocalStateStoreAdapter {
        self.store.clone()
    }

    /// The durable inbox the projectors drain.
    pub(crate) fn inbox_store(&self) -> InksonLocalStateStoreAdapter {
        self.store.clone()
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn executor(&self) -> garth::NativeExecutor {
        garth::NativeExecutor
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn executor(&self) -> garth::WasmExecutor {
        garth::WasmExecutor
    }

    /// An account run loop bound to this runtime's durable cursor store.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn account_runner(
        &self,
    ) -> garth::AccountRunner<garth::NativeExecutor, InksonLocalStateStoreAdapter> {
        garth::AccountRunner::new(self.executor(), self.cursors())
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn account_runner(
        &self,
    ) -> garth::AccountRunner<garth::WasmExecutor, InksonLocalStateStoreAdapter> {
        garth::AccountRunner::new(self.executor(), self.cursors())
    }
}

#[cfg(test)]
mod tests {
    use garth::{CursorStore, EventCacheStore, SecureKeyStore};

    const REALM_ID: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    #[tokio::test]
    async fn local_state_adapter_persists_client_core_cursors_and_event_cache() {
        let path = std::env::temp_dir().join(format!(
            "inkson-client-core-adapter-{}.json",
            crate::operation::uuid_v7()
        ));
        let adapter = super::InksonLocalStateStoreAdapter::new(
            crate::state::LocalStateStore::with_path(path.clone()),
        );
        let account_scope = garth::CursorScope::Account {
            service_id: None,
            actor_id: crate::mls_api_helpers::principal_core_id(
                "did:webvh:z6mkfixture:alice.example",
            )
            .unwrap(),
            device_id: arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001")
                .unwrap(),
        };
        // A commit-stream cursor is that one stream's own position. There is no
        // Realm-wide scope to store, which is what keeps a Realm-global order
        // unrepresentable in the durable layer.
        let realm_stream_scope = garth::CursorScope::CommitStream {
            service_id: None,
            stream_ref: garth::CommitStreamRef::Realm {
                realm_id: arkret_sdk::RealmId::new(REALM_ID).unwrap(),
            },
        };
        let event_id =
            arkret_sdk::EventId::new("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap();

        let account_checkpoint = garth::AccountCursorCheckpoint {
            cursor: "ak:cursor:account".to_owned(),
            station_cas: garth::StationCasProjection::default(),
        };
        adapter
            .save_account_checkpoint(account_scope.clone(), account_checkpoint.clone())
            .await
            .unwrap();
        adapter
            .save(realm_stream_scope.clone(), "42".to_owned())
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
            adapter
                .load_account_checkpoint(account_scope.clone())
                .await
                .unwrap(),
            Some(account_checkpoint)
        );
        assert_eq!(
            adapter
                .load(realm_stream_scope.clone())
                .await
                .unwrap()
                .as_deref(),
            Some("42")
        );
        assert!(adapter.seen(event_id).await.unwrap());

        adapter.clear(account_scope.clone()).await.unwrap();
        adapter.clear(realm_stream_scope.clone()).await.unwrap();
        assert!(adapter.load(account_scope).await.unwrap().is_none());
        assert!(adapter.load(realm_stream_scope).await.unwrap().is_none());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn two_streams_of_one_realm_never_share_a_durable_position() {
        let path = std::env::temp_dir().join(format!(
            "inkson-client-core-streams-{}.json",
            crate::operation::uuid_v7()
        ));
        let adapter = super::InksonLocalStateStoreAdapter::new(
            crate::state::LocalStateStore::with_path(path.clone()),
        );
        let realm_id = arkret_sdk::RealmId::new(REALM_ID).unwrap();
        let realm_scope = garth::CursorScope::CommitStream {
            service_id: None,
            stream_ref: garth::CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
        };
        let circle_scope = garth::CursorScope::CommitStream {
            service_id: None,
            stream_ref: garth::CommitStreamRef::Circle {
                realm_id,
                circle_id: arkret_sdk::CircleId::new(
                    "ak:circle:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
                )
                .unwrap(),
            },
        };
        adapter
            .save(realm_scope.clone(), "7".to_owned())
            .await
            .unwrap();
        adapter
            .save(circle_scope.clone(), "3".to_owned())
            .await
            .unwrap();
        assert_eq!(
            adapter.load(realm_scope).await.unwrap().as_deref(),
            Some("7")
        );
        assert_eq!(
            adapter.load(circle_scope).await.unwrap().as_deref(),
            Some("3")
        );
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
