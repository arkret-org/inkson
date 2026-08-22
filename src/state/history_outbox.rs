use std::future::Future;

use dioxus::prelude::{ReadableExt, SyncSignal, WritableExt};

use super::LocalStateStore;

#[derive(Clone, Copy)]
pub(crate) struct InksonHistorySourceOutboxStore {
    state_store: SyncSignal<LocalStateStore>,
}

impl InksonHistorySourceOutboxStore {
    pub(crate) fn new(state_store: SyncSignal<LocalStateStore>) -> Self {
        Self { state_store }
    }
}

impl garth::HistorySourceOutboxStore for InksonHistorySourceOutboxStore {
    fn load_history_source_outbox(
        &self,
    ) -> garth::Result<garth::VersionedHistorySourceOutboxSnapshot> {
        Ok(self.state_store.read().load().history_source_outbox_state)
    }

    fn compare_and_swap_history_source_outbox<'a>(
        &'a self,
        expected_revision: u64,
        snapshot: &'a garth::HistorySourceOutboxSnapshot,
    ) -> impl Future<Output = garth::Result<bool>> + garth::MaybeSend + 'a {
        async move {
            let barrier = {
                let mut state_store = self.state_store;
                let mut store = state_store.write();
                store.ensure_cached_loaded();
                if store.cached.history_source_outbox_state.revision != expected_revision {
                    return Ok(false);
                }
                let revision = expected_revision.checked_add(1).ok_or_else(|| {
                    garth::Error::Protocol("history source outbox revision overflow".to_owned())
                })?;
                store.cached.history_source_outbox_state =
                    garth::VersionedHistorySourceOutboxSnapshot {
                        revision,
                        snapshot: snapshot.clone(),
                    };
                store
                    .begin_durable_flush()
                    .map_err(|error| garth::Error::Protocol(error.to_string()))?
            };
            barrier
                .wait()
                .await
                .map_err(|error| garth::Error::Protocol(error.to_string()))?;
            Ok(true)
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct InksonHistorySourceBlobStore;

impl garth::HistorySourceBlobStore for InksonHistorySourceBlobStore {
    fn put_history_blob<'a>(
        &'a self,
        key: &'a str,
        bytes: &'a [u8],
    ) -> impl Future<Output = garth::Result<()>> + garth::MaybeSend + 'a {
        async move {
            let store = crate::secure_key_store::default_secure_key_store("inkson");
            if let Some(existing) = store
                .get_secret_bytes(key)
                .map_err(|error| garth::Error::Protocol(error.to_string()))?
            {
                return if existing.as_slice() == bytes {
                    Ok(())
                } else {
                    Err(garth::Error::IdempotencyConflict(key.to_owned()))
                };
            }
            store
                .store_secret_bytes_durable(key, bytes)
                .await
                .map_err(|error| garth::Error::Protocol(error.to_string()))
        }
    }

    fn get_history_blob(&self, key: &str) -> garth::Result<Option<Vec<u8>>> {
        crate::secure_key_store::default_secure_key_store("inkson")
            .get_secret_bytes(key)
            .map(|value| value.map(|bytes| bytes.to_vec()))
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    fn delete_history_blob(&self, key: &str) -> garth::Result<()> {
        crate::secure_key_store::default_secure_key_store("inkson")
            .delete_secret(key)
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    fn list_history_blob_keys(&self) -> garth::Result<Vec<String>> {
        crate::secure_key_store::default_secure_key_store("inkson")
            .list_secret_keys(Some(
                crate::secure_key_store::HISTORY_SOURCE_OUTBOX_BLOB_KEY_PREFIX,
            ))
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }
}

pub(crate) fn history_source_outbox(
    state_store: SyncSignal<LocalStateStore>,
) -> garth::HistorySourceOutbox<InksonHistorySourceOutboxStore> {
    garth::HistorySourceOutbox::new(InksonHistorySourceOutboxStore::new(state_store))
}
