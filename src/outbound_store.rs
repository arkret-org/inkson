//! Product storage adapter for Garth's durable outbound queue.
//!
//! Each queue item carries the authoritative `(realm_id, actor_id)` authoring
//! partition. Actor-keyed files are storage containers used by account-level
//! drain; they do not provide or derive authoring sequence state. Native
//! clients use Garth's atomic `FileStore`; web clients persist the same SDK
//! `SendQueueSnapshot` shape in origin storage until the IndexedDB contract
//! adapter replaces this fallback.

use garth::OutboundQueueStore;
use garth::outbound::BoxOutboundFuture;

#[cfg(target_arch = "wasm32")]
const BROWSER_OUTBOUND_STORAGE_PREFIX: &str = "inkson.outbound.v1::";

/// Only the browser fallback store compacts in place; the host build keeps it
/// for the unit test that pins the pruning contract.
#[cfg(any(target_arch = "wasm32", test))]
fn compact_snapshot_json(
    raw: &str,
    cutoff: chrono::DateTime<chrono::Utc>,
) -> garth::Result<Option<(String, usize)>> {
    let snapshot = serde_json::from_str(raw).map_err(|error| {
        garth::Error::Protocol(format!("decode browser outbound queue: {error}"))
    })?;
    let mut queue = garth::SendQueue::from_snapshot(snapshot)?;
    let removed = queue.prune_terminal_before(cutoff);
    if removed == 0 {
        return Ok(None);
    }
    let encoded = serde_json::to_string(&queue.snapshot()).map_err(|error| {
        garth::Error::Protocol(format!("encode compacted browser outbound queue: {error}"))
    })?;
    Ok(Some((encoded, removed)))
}

#[cfg(target_arch = "wasm32")]
fn compact_sibling_browser_outbound_queues(
    storage: &web_sys::Storage,
    current_storage_key: &str,
) -> usize {
    let Ok(length) = storage.length() else {
        return 0;
    };
    let keys = (0..length)
        .filter_map(|index| storage.key(index).ok().flatten())
        .filter(|key| {
            key.starts_with(BROWSER_OUTBOUND_STORAGE_PREFIX) && key != current_storage_key
        })
        .collect::<Vec<_>>();
    let cutoff = chrono::Utc::now();
    let mut removed_total = 0;
    for key in keys {
        let Some(raw) = storage.get_item(&key).ok().flatten() else {
            continue;
        };
        let Ok(Some((encoded, removed))) = compact_snapshot_json(&raw, cutoff) else {
            continue;
        };
        if storage.set_item(&key, &encoded).is_ok() {
            removed_total += removed;
        }
    }
    removed_total
}

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
                    let store = garth::FileStore::open(&path)
                        .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))?;
                    stores.insert(path, store.clone());
                    store
                }
            };
            Ok(Self { inner })
        }
        #[cfg(target_arch = "wasm32")]
        {
            Ok(Self {
                storage_key: format!("{BROWSER_OUTBOUND_STORAGE_PREFIX}{scope}"),
            })
        }
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    fn open_at(path: impl Into<std::path::PathBuf>) -> arkret_sdk::Result<Self> {
        Ok(Self {
            inner: garth::FileStore::open(path)
                .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))?,
        })
    }
}

impl OutboundQueueStore for InksonOutboundStore {
    fn mutate_outbound<'a, R>(
        &'a self,
        mutation: impl FnOnce(&mut garth::SendQueue) -> garth::Result<R> + garth::MaybeSend + 'a,
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
                    garth::Error::Protocol(
                        "browser storage unavailable for durable outbound queue".to_owned(),
                    )
                })?;
                let snapshot = match storage.get_item(&self.storage_key).map_err(|error| {
                    garth::Error::Protocol(format!("read browser outbound queue: {error:?}"))
                })? {
                    Some(raw) => serde_json::from_str(&raw).map_err(|error| {
                        garth::Error::Protocol(format!("decode browser outbound queue: {error}"))
                    })?,
                    None => garth::SendQueueSnapshot::default(),
                };
                let mut queue = garth::SendQueue::from_snapshot(snapshot)?;
                let result = mutation(&mut queue)?;
                let mut encoded = serde_json::to_string(&queue.snapshot()).map_err(|error| {
                    garth::Error::Protocol(format!("encode browser outbound queue: {error}"))
                })?;
                if let Err(initial_error) = storage.set_item(&self.storage_key, &encoded) {
                    // Browser localStorage has a small per-origin quota. Preserve
                    // every pending/dependency item. First discard unreferenced
                    // terminal history in this actor queue, then compact sibling
                    // actor queues left by earlier Agent identities. A new actor
                    // otherwise cannot persist its first item when an old actor's
                    // terminal history consumes the shared origin quota.
                    let removed = queue.prune_terminal_before(chrono::Utc::now());
                    if removed > 0 {
                        encoded = serde_json::to_string(&queue.snapshot()).map_err(|error| {
                            garth::Error::Protocol(format!(
                                "encode compacted browser outbound queue: {error}"
                            ))
                        })?;
                    }
                    let sibling_removed =
                        compact_sibling_browser_outbound_queues(&storage, &self.storage_key);
                    storage
                        .set_item(&self.storage_key, &encoded)
                        .map_err(|error| {
                            garth::Error::Protocol(format!(
                                "persist compacted browser outbound queue after removing {removed} \
                             current and {sibling_removed} sibling terminal item(s): {error:?}; \
                             initial error: {initial_error:?}"
                            ))
                        })?;
                }
                Ok(result)
            })
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn legacy_kind_content_snapshot_is_rejected() {
        let legacy = serde_json::json!({
            "items": [],
            "next_sequence": 0
        });
        assert!(serde_json::from_value::<garth::SendQueueSnapshot>(legacy).is_err());
    }
}
