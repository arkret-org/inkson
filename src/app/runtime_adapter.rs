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

    fn event_seen(&self, event_id: &arkret_sdk::EventId) -> arkret_sdk::Result<bool> {
        Ok(self.store.read().client_core_event_seen(event_id.as_str()))
    }

    fn remember_event(&self, event_id: &arkret_sdk::EventId) -> arkret_sdk::Result<()> {
        let mut signal = self.store;
        signal.write().remember_client_core_event(event_id.as_str());
        Ok(())
    }
}
