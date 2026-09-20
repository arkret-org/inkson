use dioxus::prelude::{ReadableExt, Signal, SyncSignal, WritableExt};

use crate::client_core::LocalStateBackend;
use crate::state::LocalStateStore;

pub(super) fn value_reader<T: Clone + 'static>(
    signal: Signal<T>,
) -> crate::runtime::input::ValueReader<T> {
    crate::runtime::input::ValueReader::new(move || signal.read().clone())
}

pub(crate) fn value_cell<T: Clone + 'static>(
    signal: Signal<T>,
) -> crate::runtime::input::ValueCell<T> {
    crate::runtime::input::ValueCell::new(
        move || signal.read().clone(),
        move |value| {
            let mut signal = signal;
            signal.set(value);
        },
        move |update| {
            let mut signal = signal;
            update(&mut signal.write());
        },
    )
}

pub(crate) fn state_store_handle(
    store: SyncSignal<LocalStateStore>,
) -> crate::runtime::input::StateStoreHandle {
    crate::runtime::input::StateStoreHandle::new(
        move |read| read(&store.read()),
        move |write| {
            let mut store = store;
            write(&mut store.write());
        },
    )
}

pub(super) struct SignalLocalStateBackend {
    store: SyncSignal<LocalStateStore>,
}

impl SignalLocalStateBackend {
    pub(super) fn new(store: SyncSignal<LocalStateStore>) -> Self {
        Self { store }
    }
}

impl LocalStateBackend for SignalLocalStateBackend {
    fn load_cursor(
        &self,
        scope: &garth::CursorScope,
    ) -> arkret_sdk::Result<Option<garth::OpaqueCursor>> {
        self.store.read().load_client_cursor(scope)
    }

    fn save_cursor(
        &self,
        scope: &garth::CursorScope,
        cursor: garth::OpaqueCursor,
    ) -> arkret_sdk::Result<()> {
        let mut signal = self.store;
        signal.write().save_client_cursor(scope, cursor)
    }

    fn clear_cursor(&self, scope: &garth::CursorScope) -> arkret_sdk::Result<()> {
        let mut signal = self.store;
        signal.write().clear_client_cursor(scope)
    }

    fn load_account_checkpoint(
        &self,
        scope: &garth::CursorScope,
    ) -> arkret_sdk::Result<Option<garth::AccountCursorCheckpoint>> {
        self.store.read().load_account_checkpoint(scope)
    }

    fn save_account_checkpoint(
        &self,
        scope: &garth::CursorScope,
        checkpoint: garth::AccountCursorCheckpoint,
    ) -> arkret_sdk::Result<()> {
        let mut signal = self.store;
        signal.write().save_account_checkpoint(scope, checkpoint)
    }

    fn restore_account_checkpoint(
        &self,
        scope: &garth::CursorScope,
        checkpoint: Option<garth::AccountCursorCheckpoint>,
    ) -> arkret_sdk::Result<()> {
        let mut signal = self.store;
        signal.write().restore_account_checkpoint(scope, checkpoint)
    }

    fn event_seen(&self, event_id: &arkret_sdk::EventId) -> arkret_sdk::Result<bool> {
        Ok(self.store.read().client_core_event_seen(event_id.as_str()))
    }

    fn remember_event(&self, event_id: &arkret_sdk::EventId) -> arkret_sdk::Result<()> {
        let mut signal = self.store;
        signal.write().remember_client_core_event(event_id.as_str());
        Ok(())
    }

    fn commit_delivery(
        &self,
        scope: garth::CursorScope,
        cursor: Option<garth::OpaqueCursor>,
        events: Vec<garth::ClientEvent>,
    ) -> arkret_sdk::Result<Option<garth::DeliveryId>> {
        let mut signal = self.store;
        signal.write().commit_client_delivery(scope, cursor, events)
    }

    fn pending_deliveries(
        &self,
        limit: usize,
    ) -> arkret_sdk::Result<Vec<garth::PendingDelivery<Vec<garth::ClientEvent>>>> {
        self.store.read().pending_client_deliveries(limit)
    }

    fn ack_delivery(&self, id: garth::DeliveryId) -> arkret_sdk::Result<bool> {
        let mut signal = self.store;
        signal.write().ack_client_delivery(id)
    }

    fn retry_delivery(
        &self,
        id: garth::DeliveryId,
        next_attempt_at_ms: Option<i64>,
        error_class: garth::DeliveryErrorClass,
        error: String,
    ) -> arkret_sdk::Result<bool> {
        let mut signal = self.store;
        signal
            .write()
            .retry_client_delivery(id, next_attempt_at_ms, error_class, error)
    }

    fn delivery_snapshot(
        &self,
        id: garth::DeliveryId,
    ) -> arkret_sdk::Result<Option<crate::state::StoredClientDelivery>> {
        Ok(self.store.read().client_delivery_snapshot(id))
    }

    fn restore_delivery(
        &self,
        delivery: crate::state::StoredClientDelivery,
    ) -> arkret_sdk::Result<()> {
        let mut signal = self.store;
        signal.write().restore_client_delivery(delivery)
    }

    fn rollback_delivery_commit(
        &self,
        scope: &garth::CursorScope,
        previous_cursor: Option<garth::OpaqueCursor>,
        delivery_id: Option<garth::DeliveryId>,
    ) -> arkret_sdk::Result<()> {
        let mut signal = self.store;
        signal
            .write()
            .rollback_client_delivery_commit(scope, previous_cursor, delivery_id)
    }

    fn begin_durable_flush(&self) -> arkret_sdk::Result<crate::state::LocalStatePersistBarrier> {
        self.store
            .read()
            .begin_durable_flush()
            .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))
    }
}
