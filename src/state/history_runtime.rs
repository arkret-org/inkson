use std::future::Future;

use dioxus::prelude::{ReadableExt, SyncSignal, WritableExt};

use super::LocalStateStore;

#[derive(Clone, Copy)]
pub(crate) struct InksonHistoryRuntimeStore {
    state_store: SyncSignal<LocalStateStore>,
}

impl InksonHistoryRuntimeStore {
    pub(crate) fn new(state_store: SyncSignal<LocalStateStore>) -> Self {
        Self { state_store }
    }
}

impl garth::HistoryRuntimeStore for InksonHistoryRuntimeStore {
    fn load_history_runtime(&self) -> garth::Result<garth::VersionedHistoryRuntimeSnapshot> {
        Ok(self.state_store.read().load().history_runtime_state)
    }

    fn compare_and_swap_history_runtime<'a>(
        &'a self,
        expected_revision: u64,
        snapshot: &'a garth::HistoryRuntimeSnapshot,
    ) -> impl Future<Output = garth::Result<bool>> + garth::MaybeSend + 'a {
        async move {
            let mut state_store = self.state_store;
            let mut store = state_store.write();
            store.ensure_cached_loaded();
            if store.cached.history_runtime_state.revision != expected_revision {
                return Ok(false);
            }
            let revision = expected_revision.checked_add(1).ok_or_else(|| {
                garth::Error::Protocol("history runtime revision overflow".to_owned())
            })?;
            store.cached.history_runtime_state = garth::VersionedHistoryRuntimeSnapshot {
                revision,
                snapshot: snapshot.clone(),
            };
            store
                .flush()
                .map_err(|error| garth::Error::Protocol(error.to_string()))?;
            Ok(true)
        }
    }
}

pub(crate) fn history_runtime(
    state_store: SyncSignal<LocalStateStore>,
) -> garth::HistoryRuntime<InksonHistoryRuntimeStore> {
    garth::HistoryRuntime::new(InksonHistoryRuntimeStore::new(state_store))
}
