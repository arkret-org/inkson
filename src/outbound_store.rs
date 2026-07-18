//! Product storage adapter for Garth's durable outbound queue.
//!
//! Queue state is scoped by actor DID. Native clients use Garth's atomic
//! `FileStore`; web clients persist the same SDK `SendQueueSnapshot` shape in
//! origin storage until the IndexedDB contract adapter replaces this fallback.

use garth::OutboundQueueStore;
use garth::outbound::BoxOutboundFuture;

#[cfg(not(target_arch = "wasm32"))]
static NATIVE_OUTBOUND_STORES: std::sync::OnceLock<
    std::sync::Mutex<std::collections::BTreeMap<std::path::PathBuf, garth::FileStore>>,
> = std::sync::OnceLock::new();

#[derive(Clone)]
pub(crate) struct InksonOutboundStore {
    #[cfg(not(target_arch = "wasm32"))]
    inner: garth::FileStore,
    #[cfg(target_arch = "wasm32")]
    storage_key: String,
}

impl InksonOutboundStore {
    pub(crate) fn open(actor_id: &str) -> arkret_sdk::Result<Self> {
        let scope = crate::canonical::sha256_hex(actor_id.as_bytes());
        #[cfg(not(target_arch = "wasm32"))]
        {
            let path = crate::state::app_data_dir()
                .join("outbound")
                .join(format!("{scope}.json"));
            let stores = NATIVE_OUTBOUND_STORES
                .get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()));
            let mut stores = stores.lock().map_err(|error| {
                arkret_sdk::Error::Protocol(format!("native outbound store registry: {error}"))
            })?;
            let inner = match stores.get(&path) {
                Some(store) => store.clone(),
                None => {
                    let store = garth::FileStore::open(&path)?;
                    stores.insert(path, store.clone());
                    store
                }
            };
            Ok(Self { inner })
        }
        #[cfg(target_arch = "wasm32")]
        {
            Ok(Self {
                storage_key: format!("inkson.outbound.v1::{scope}"),
            })
        }
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    fn open_at(path: impl Into<std::path::PathBuf>) -> arkret_sdk::Result<Self> {
        Ok(Self {
            inner: garth::FileStore::open(path)?,
        })
    }
}

impl OutboundQueueStore for InksonOutboundStore {
    fn mutate_outbound<'a, R>(
        &'a self,
        mutation: impl FnOnce(&mut arkret_sdk::sync_client::SendQueue) -> arkret_sdk::Result<R>
        + garth::MaybeSend
        + 'a,
    ) -> BoxOutboundFuture<'a, R>
    where
        R: garth::MaybeSend + 'a,
    {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.inner.mutate_outbound(mutation)
        }
        #[cfg(target_arch = "wasm32")]
        {
            Box::pin(async move {
                let storage = crate::state::browser_storage().ok_or_else(|| {
                    arkret_sdk::Error::Protocol(
                        "browser storage unavailable for durable outbound queue".to_owned(),
                    )
                })?;
                let snapshot = match storage.get_item(&self.storage_key).map_err(|error| {
                    arkret_sdk::Error::Protocol(format!("read browser outbound queue: {error:?}"))
                })? {
                    Some(raw) => serde_json::from_str(&raw).map_err(|error| {
                        arkret_sdk::Error::Protocol(format!(
                            "decode browser outbound queue: {error}"
                        ))
                    })?,
                    None => arkret_sdk::sync_client::SendQueueSnapshot::default(),
                };
                let mut queue = arkret_sdk::sync_client::SendQueue::from_snapshot(snapshot)?;
                let result = mutation(&mut queue)?;
                let encoded = serde_json::to_string(&queue.snapshot()).map_err(|error| {
                    arkret_sdk::Error::Protocol(format!("encode browser outbound queue: {error}"))
                })?;
                storage
                    .set_item(&self.storage_key, &encoded)
                    .map_err(|error| {
                        arkret_sdk::Error::Protocol(format!(
                            "persist browser outbound queue: {error:?}"
                        ))
                    })?;
                Ok(result)
            })
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use chrono::Utc;
    use garth::{OutboundEngine, OutboundQueueStore};

    use super::*;

    #[tokio::test]
    async fn native_queue_survives_reopen() {
        let path = std::env::temp_dir().join(format!(
            "inkson-outbound-{}-{}.json",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let store = InksonOutboundStore::open_at(&path).unwrap();
        let engine = OutboundEngine::new(store);
        let realm =
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
        engine
            .enqueue(
                Some("ak:event:01904100-0000-7000-8000-000000000001".to_owned()),
                realm,
                arkret_sdk::sync_client::SendQueueItemKind::Custom {
                    kind: "ak.test.event".to_owned(),
                },
                serde_json::json!({"event_id": "stable"}),
                Vec::new(),
            )
            .await
            .unwrap();

        let reopened = InksonOutboundStore::open_at(&path).unwrap();
        let snapshot = reopened
            .mutate_outbound(|queue| Ok(queue.snapshot()))
            .await
            .unwrap();
        assert_eq!(snapshot.items.len(), 1);
        assert_eq!(
            snapshot.items[0].transaction_id,
            "ak:event:01904100-0000-7000-8000-000000000001"
        );
        let _ = std::fs::remove_file(path);
    }
}
