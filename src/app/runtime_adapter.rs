use dioxus::prelude::{ReadableExt, SyncSignal, WritableExt};

use crate::client_core::LocalStateBackend;
use crate::local_state::LocalStateStore;

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
        let store = self.store.read();
        Ok(match scope {
            garth::CursorScope::Account { .. } => store
                .sync_cursor()
                .filter(|cursor| !cursor.trim().is_empty()),
            garth::CursorScope::RealmEvents { realm_id, .. } => {
                store.realm_events_cursor(realm_id.as_str())
            }
        })
    }

    fn save_cursor(
        &self,
        scope: &garth::CursorScope,
        cursor: garth::OpaqueCursor,
    ) -> arkret_sdk::Result<()> {
        let mut signal = self.store;
        let mut store = signal.write();
        match scope {
            garth::CursorScope::Account { .. } => store.save_sync_cursor(cursor),
            garth::CursorScope::RealmEvents { realm_id, .. } => {
                store.save_realm_events_cursor(realm_id.as_str(), Some(cursor));
            }
        }
        Ok(())
    }

    fn clear_cursor(&self, scope: &garth::CursorScope) -> arkret_sdk::Result<()> {
        let mut signal = self.store;
        let mut store = signal.write();
        match scope {
            garth::CursorScope::Account { .. } => store.clear_sync_cursor(),
            garth::CursorScope::RealmEvents { realm_id, .. } => {
                store.save_realm_events_cursor(realm_id.as_str(), None);
            }
        }
        Ok(())
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
