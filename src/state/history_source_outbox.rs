use dioxus::prelude::{ReadableExt, SyncSignal, WritableExt};

use super::LocalStateStore;
use crate::secure_key_store::SecureKeyStore;

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

    async fn compare_and_swap_history_source_outbox(
        &self,
        expected_revision: u64,
        snapshot: &garth::HistorySourceOutboxSnapshot,
    ) -> garth::Result<bool> {
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

pub(crate) struct InksonHistorySourceBlobStore<'a> {
    secure_store: &'a dyn SecureKeyStore,
}

impl<'a> InksonHistorySourceBlobStore<'a> {
    pub(crate) fn new(secure_store: &'a dyn SecureKeyStore) -> Self {
        Self { secure_store }
    }
}

impl garth::HistorySourceBlobStore for InksonHistorySourceBlobStore<'_> {
    async fn put_history_blob(&self, key: &str, bytes: &[u8]) -> garth::Result<()> {
        if let Some(existing) = self
            .secure_store
            .get_secret_bytes(key)
            .map_err(|error| garth::Error::Protocol(error.to_string()))?
        {
            if existing.as_ref() != bytes {
                return Err(garth::Error::IdempotencyConflict(key.to_owned()));
            }
            return Ok(());
        }
        self.secure_store
            .put_secret(
                key,
                bytes,
                garth::PutSecretOptions {
                    durability: garth::SecretDurability::DurableBeforeReturn,
                    class: garth::SecretClass::MlsSecret,
                },
            )
            .await
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    fn get_history_blob(&self, key: &str) -> garth::Result<Option<Vec<u8>>> {
        self.secure_store
            .get_secret_bytes(key)
            .map(|bytes| bytes.map(|bytes| bytes.as_ref().to_vec()))
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    fn delete_history_blob(&self, key: &str) -> garth::Result<()> {
        self.secure_store
            .delete_secret(key)
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    fn list_history_blob_keys(&self) -> garth::Result<Vec<String>> {
        self.secure_store
            .list_secret_keys(Some("arkret/history-source-outbox/v1/"))
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }
}

pub(crate) fn history_source_outbox(
    state_store: SyncSignal<LocalStateStore>,
) -> garth::HistorySourceOutbox<InksonHistorySourceOutboxStore> {
    garth::HistorySourceOutbox::new(InksonHistorySourceOutboxStore::new(state_store))
}
