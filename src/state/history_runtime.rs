use crate::runtime::input::StateStoreHandle;

#[derive(Clone)]
pub(crate) struct InksonHistoryRuntimeStore {
    state_store: StateStoreHandle,
}

impl InksonHistoryRuntimeStore {
    pub(crate) fn new(state_store: StateStoreHandle) -> Self {
        Self { state_store }
    }
}

impl garth::HistoryRuntimeStore for InksonHistoryRuntimeStore {
    fn load_history_runtime(&self) -> garth::Result<garth::VersionedHistoryRuntimeSnapshot> {
        Ok(self
            .state_store
            .read(|store| store.load().history_runtime_state))
    }

    async fn compare_and_swap_history_runtime(
        &self,
        expected_revision: u64,
        snapshot: &garth::HistoryRuntimeSnapshot,
    ) -> garth::Result<bool> {
        let Some(barrier) = self.state_store.write(|store| {
            store.ensure_cached_loaded();
            if store.cached.history_runtime_state.revision != expected_revision {
                return Ok(None);
            }
            let revision = expected_revision.checked_add(1).ok_or_else(|| {
                garth::Error::Protocol("history runtime revision overflow".to_owned())
            })?;
            store.cached.history_runtime_state = garth::VersionedHistoryRuntimeSnapshot {
                revision,
                snapshot: snapshot.clone(),
            };
            store
                .begin_durable_flush()
                .map(Some)
                .map_err(|error| garth::Error::Protocol(error.to_string()))
        })?
        else {
            return Ok(false);
        };
        barrier
            .wait()
            .await
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        Ok(true)
    }
}

pub(crate) fn history_runtime(
    state_store: &StateStoreHandle,
) -> garth::HistoryRuntime<InksonHistoryRuntimeStore> {
    garth::HistoryRuntime::new(InksonHistoryRuntimeStore::new(state_store.clone()))
}
