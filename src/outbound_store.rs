//! Product storage adapter for Garth's durable outbound queue.
//!
//! Each queue item carries the authoritative `(realm_id, actor_id)` authoring
//! partition. Physical queues are additionally partitioned by the exact
//! [`arkret_sdk::AccountId`] that owns the authenticated session; actor ids
//! never serve as account-storage coordinates.
//!
//! Native clients use Garth's atomic `FileStore`. Web clients persist the same
//! SDK `SendQueueSnapshot` shape in the IndexedDB + non-extractable
//! SubtleCrypto encrypted entries store — the tier the per-account main state
//! already uses — so a queue of signed, not-yet-accepted Events is ciphertext
//! at rest and is not charged against the ~5 MB localStorage per-origin quota
//! that a single queue can exhaust on its own. Queues written by builds that
//! predate this are drained out of localStorage on first use; see
//! [`migrate_legacy_localstorage_queues`].

use garth::OutboundQueueStore;
use garth::outbound::BoxOutboundFuture;

/// Storage-key prefix for one durable outbound queue:
/// `<prefix><authority digest>.<lane>`.
///
/// The same key addresses the same logical queue in both tiers — the IndexedDB
/// entries store writes it today, and the retired localStorage layout the
/// migration drains used it verbatim — so adopting a legacy queue needs no key
/// rewrite. `secure_key_store::is_wasm_indexeddb_required_secret_key`
/// classifies this prefix as IndexedDB-only, which is what stops the secure
/// localStorage tier from mirroring a multi-megabyte queue back onto the very
/// quota it was moved off.
pub(crate) const OUTBOUND_QUEUE_KEY_PREFIX: &str = "inkson.outbound.v1::";

/// The authority storage namespace an outbound queue key belongs to, or `None`
/// when the key is not an outbound queue.
///
/// The digest is base64url and so never contains `.`, while the lane suffix
/// (`standard`, `mls-durable-post-accept`, ...) contains `-`. The first dot
/// after the prefix is therefore the only correct split point.
#[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
fn outbound_key_namespace(storage_key: &str) -> Option<&str> {
    storage_key
        .strip_prefix(OUTBOUND_QUEUE_KEY_PREFIX)?
        .split_once('.')
        .map(|(namespace, _)| namespace)
}

/// What the one-shot legacy drain does with one localStorage queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
enum LegacyQueueAction {
    /// Copy into the secure store, then delete the legacy copy.
    Adopt,
    /// Delete without copying. The authority owning this queue has no account
    /// entry left, so nothing will ever sign or send its items — they are
    /// unreachable work, not pending work.
    Discard,
}

/// Classify one legacy key against the authorities this device still holds an
/// account entry for.
///
/// `live_namespaces` is `None` when the root index could not be read. That
/// means "unknown", never "no account is known", so every queue is adopted
/// rather than risk discarding a live authority's unsent Events.
#[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
fn legacy_queue_action(
    storage_key: &str,
    live_namespaces: Option<&std::collections::BTreeSet<String>>,
) -> Option<LegacyQueueAction> {
    let namespace = outbound_key_namespace(storage_key)?;
    match live_namespaces {
        Some(live) if !live.contains(namespace) => Some(LegacyQueueAction::Discard),
        _ => Some(LegacyQueueAction::Adopt),
    }
}

/// The hardened entries store, or a refusal.
///
/// Fail closed rather than degrade to localStorage: the queue holds signed
/// Events, and the Ed25519 seed that authored them already requires this same
/// tier, so any caller that reaches here with work to persist finds it ready.
#[cfg(target_arch = "wasm32")]
fn secure_outbound_store()
-> garth::Result<std::sync::Arc<dyn crate::secure_key_store::SecureKeyStore + Send + Sync>> {
    if !crate::secure_key_store::wasm_secure_store_ready() {
        return Err(garth::Error::Protocol(
            "durable outbound queue requires an initialised IndexedDB secure tier".to_owned(),
        ));
    }
    Ok(crate::secure_key_store::default_secure_key_store("inkson"))
}

/// Write gate, holding "the legacy drain has run" as its guarded state.
///
/// Persisting now spans `await`, so two concurrent `mutate_outbound` calls
/// could otherwise interleave read-modify-write into a lost update. One
/// process-wide gate rather than one per queue also makes the drain run
/// exactly once with no second lock to order against; outbound writes are not
/// a hot path.
#[cfg(target_arch = "wasm32")]
fn outbound_write_gate() -> &'static tokio::sync::Mutex<bool> {
    static GATE: std::sync::OnceLock<tokio::sync::Mutex<bool>> = std::sync::OnceLock::new();
    GATE.get_or_init(|| tokio::sync::Mutex::new(false))
}

/// Drain every queue the retired localStorage layout still holds.
///
/// An adopted queue is committed durably FIRST and only then removed from
/// localStorage, so a failure anywhere leaves the legacy copy in place for the
/// next attempt: no unsent item is dropped to let the drain finish. A queue
/// that will not decode is left untouched and reported, rather than copied as
/// bytes the queue engine would later refuse to load.
#[cfg(target_arch = "wasm32")]
async fn migrate_legacy_localstorage_queues(
    store: &dyn crate::secure_key_store::SecureKeyStore,
) -> garth::Result<()> {
    let Some(storage) = crate::browser_storage::browser_storage() else {
        return Ok(());
    };
    let Ok(length) = storage.length() else {
        return Ok(());
    };
    let legacy_keys = (0..length)
        .filter_map(|index| storage.key(index).ok().flatten())
        .filter(|key| outbound_key_namespace(key).is_some())
        .collect::<Vec<_>>();
    if legacy_keys.is_empty() {
        return Ok(());
    }
    let live_namespaces = crate::state::persisted_account_storage_namespaces();
    for key in legacy_keys {
        match legacy_queue_action(&key, live_namespaces.as_ref()) {
            Some(LegacyQueueAction::Discard) => {
                let _ = storage.remove_item(&key);
                continue;
            }
            None => continue,
            Some(LegacyQueueAction::Adopt) => {}
        }
        let Some(raw) = storage.get_item(&key).ok().flatten() else {
            continue;
        };
        if store.get_secret(&key).ok().flatten().is_none() {
            serde_json::from_str::<garth::SendQueueSnapshot>(&raw).map_err(|error| {
                garth::Error::Protocol(format!("decode legacy outbound queue {key}: {error}"))
            })?;
            store
                .store_secret_durable(&key, &raw)
                .await
                .map_err(|error| {
                    garth::Error::Protocol(format!(
                        "adopt legacy outbound queue {key} ({} bytes): {error}",
                        raw.len()
                    ))
                })?;
        }
        // The durable copy is committed — now, or by an earlier run whose
        // delete was lost — so dropping the legacy copy cannot lose an item.
        let _ = storage.remove_item(&key);
    }
    Ok(())
}

/// One read-modify-write of a queue against an explicit store.
///
/// Only the `SecureKeyStore` port is involved, so this compiles on every
/// target and the native unit tests drive it against in-memory and
/// deliberately-failing stores instead of a browser.
#[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
async fn mutate_queue_in_store<R>(
    store: &dyn crate::secure_key_store::SecureKeyStore,
    storage_key: &str,
    mutation: impl FnOnce(&mut garth::SendQueue) -> garth::Result<R>,
) -> garth::Result<R> {
    let stored = store
        .get_secret(storage_key)
        .map_err(|error| garth::Error::Protocol(format!("read outbound queue: {error}")))?;
    let snapshot = match stored {
        Some(raw) => serde_json::from_str(&raw)
            .map_err(|error| garth::Error::Protocol(format!("decode outbound queue: {error}")))?,
        None => garth::SendQueueSnapshot::default(),
    };
    let mut queue = garth::SendQueue::from_snapshot(snapshot)?;
    let result = mutation(&mut queue)?;
    let encoded = serde_json::to_string(&queue.snapshot())
        .map_err(|error| garth::Error::Protocol(format!("encode outbound queue: {error}")))?;
    store
        .store_secret_durable(storage_key, &encoded)
        .await
        .map_err(|error| {
            garth::Error::Protocol(format!(
                "persist outbound queue ({} item(s), {} encoded bytes): {error}",
                queue.len(),
                encoded.len(),
            ))
        })?;
    Ok(result)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutboundLane {
    Standard,
    MlsDurablePostAccept,
    MlsHostOnly,
}

impl OutboundLane {
    fn suffix(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::MlsDurablePostAccept => "mls-durable-post-accept",
            Self::MlsHostOnly => "mls-host-only",
        }
    }
}

fn outbound_storage_scope(
    authority: &arkret_sdk::AccountId,
    lane: OutboundLane,
) -> arkret_sdk::Result<String> {
    let authority_digest =
        crate::secure_key_store::account_id_storage_digest(authority).map_err(|error| {
            arkret_sdk::Error::Protocol(format!(
                "derive durable outbound authority namespace: {error}"
            ))
        })?;
    Ok(format!("{authority_digest}.{}", lane.suffix()))
}

impl InksonOutboundStore {
    pub(crate) fn open(
        authority: &arkret_sdk::AccountId,
        lane: OutboundLane,
    ) -> arkret_sdk::Result<Self> {
        let scope = outbound_storage_scope(authority, lane)?;
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
                storage_key: format!("{OUTBOUND_QUEUE_KEY_PREFIX}{scope}"),
            })
        }
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
                let store = secure_outbound_store()?;
                let mut legacy_drained = outbound_write_gate().lock().await;
                if !*legacy_drained {
                    migrate_legacy_localstorage_queues(store.as_ref()).await?;
                    *legacy_drained = true;
                }
                mutate_queue_in_store(store.as_ref(), &self.storage_key, mutation).await
            })
        }
    }
}

/// Browser-contract entry points for `tests/wasm_indexed_db_capacity.rs`.
///
/// The production path takes a process-global store and a process-global gate,
/// neither of which a browser test can substitute. These forward into the same
/// functions with the store passed in, so the contract exercises the real
/// adoption and read-modify-write code rather than a copy of it.
///
/// Target-gated, not feature-gated: CI runs the browser tests with no extra
/// features, and a contract that only compiles under an opt-in feature is a
/// contract that never runs. Nothing here weakens a production path — the
/// functions are unreachable from the app, and the wasm build drops them.
#[cfg(target_arch = "wasm32")]
#[doc(hidden)]
pub mod test_api {
    pub async fn mutate_outbound_queue<R>(
        store: &dyn crate::secure_key_store::SecureKeyStore,
        storage_key: &str,
        mutation: impl FnOnce(&mut garth::SendQueue) -> garth::Result<R>,
    ) -> garth::Result<R> {
        super::mutate_queue_in_store(store, storage_key, mutation).await
    }

    pub async fn drain_legacy_outbound_queues(
        store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> garth::Result<()> {
        super::migrate_legacy_localstorage_queues(store).await
    }

    /// Build a queue key exactly as [`super::InksonOutboundStore::open`] does,
    /// so a contract cannot drift from the production key layout.
    #[must_use]
    pub fn outbound_queue_key(namespace: &str, lane: &str) -> String {
        format!("{}{namespace}.{lane}", super::OUTBOUND_QUEUE_KEY_PREFIX)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use garth::SecureKeyStore as _;

    use super::*;
    use crate::test_support as fixture;

    #[test]
    fn same_principal_on_different_servers_has_distinct_outbound_scope() {
        let first = fixture::authority_at_station(
            "ak:did_core:webvh:zPrincipal",
            "ak:did_core:webvh:zServerA",
        );
        let second = fixture::authority_at_station(
            "ak:did_core:webvh:zPrincipal",
            "ak:did_core:webvh:zServerB",
        );
        assert_ne!(
            outbound_storage_scope(&first, OutboundLane::Standard).unwrap(),
            outbound_storage_scope(&second, OutboundLane::Standard).unwrap()
        );
    }

    #[test]
    fn every_lane_of_one_authority_shares_one_browser_namespace() {
        let authority = fixture::authority_at_station(
            "ak:did_core:webvh:zPrincipal",
            "ak:did_core:webvh:zServerA",
        );
        let standard = outbound_storage_scope(&authority, OutboundLane::Standard).unwrap();
        let mls = outbound_storage_scope(&authority, OutboundLane::MlsDurablePostAccept).unwrap();
        let standard_key = format!("{OUTBOUND_QUEUE_KEY_PREFIX}{standard}");
        let mls_key = format!("{OUTBOUND_QUEUE_KEY_PREFIX}{mls}");

        // Reclaiming abandoned queues keys off this namespace, and the lane
        // suffix itself contains `-`: splitting anywhere but the first `.`
        // would read one authority's MLS lane as a different account and
        // delete pending work the live session still owns.
        assert_eq!(
            outbound_key_namespace(&standard_key),
            outbound_key_namespace(&mls_key)
        );
        assert_eq!(
            outbound_key_namespace(&mls_key),
            Some(mls.split_once('.').unwrap().0)
        );
    }

    const FIXTURE_REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    /// One valid queued write. Kept deliberately ordinary: these tests are
    /// about the storage adapter, so the record only has to be something
    /// `SendQueue::from_snapshot` will accept back.
    fn fixture_record() -> garth::QueuedRecord {
        let actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
        ));
        let event: arkret_sdk::Event = serde_json::from_value(serde_json::json!({
            "event_id": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "kind": "ak.presence",
            "realm_id": FIXTURE_REALM,
            "scope_ref": {"kind": "realm", "realm_id": FIXTURE_REALM},
            "actor_id": actor_id,
            "actor_seq": 1,
            "created_at": "2026-05-19T00:00:00.000Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {"actor_id": actor_id, "state": "online"},
            "proofs": []
        }))
        .unwrap();
        garth::QueuedRecord::SdkEvent(Box::new(
            garth::QueuedSdkEvent::unauthored(
                garth::QueuedEventIntent::new(
                    arkret_event_draft::EventIntent::from_authored(&event),
                    arkret_sdk::DigestSuite::Sha256,
                ),
                "local-operation".to_owned(),
                "attempt".to_owned(),
                None,
                garth::AuthoringGeneration {
                    authority_model: garth::AuthoringAuthorityModel::AcceptedDevice,
                    authority_principal_id: arkret_sdk::DidCoreId::new(
                        "ak:did_core:web:alice.example".to_owned(),
                    )
                    .unwrap(),
                    generation_ref: "1-QmCurrent".to_owned(),
                },
                None,
            )
            .unwrap(),
        ))
    }

    fn enqueue_items(queue: &mut garth::SendQueue, count: usize) {
        let realm = fixture::realm_id(FIXTURE_REALM);
        let now = chrono::Utc::now();
        for index in 0..count {
            queue
                .enqueue(
                    Some(format!("txn-{index}")),
                    realm.clone(),
                    fixture_record(),
                    Vec::new(),
                    now,
                )
                .unwrap();
        }
    }

    /// A store whose durable write always fails, to prove the adapter reports
    /// the failure instead of returning `Ok` on a queue that was never stored.
    #[derive(Debug)]
    struct RefusingStore;

    impl garth::SecureKeyStore for RefusingStore {
        fn store_secret_bytes(
            &self,
            _key: &str,
            _value: &[u8],
        ) -> Result<(), garth::SecureKeyStoreError> {
            Err(garth::SecureKeyStoreError::Backend(
                "entries store unavailable".to_owned(),
            ))
        }

        fn get_secret_bytes(
            &self,
            _key: &str,
        ) -> Result<Option<arkret_sdk::KeyBytes>, garth::SecureKeyStoreError> {
            Ok(None)
        }

        fn delete_secret(&self, _key: &str) -> Result<(), garth::SecureKeyStoreError> {
            Ok(())
        }

        fn list_secret_keys(
            &self,
            _prefix: Option<&str>,
        ) -> Result<Vec<String>, garth::SecureKeyStoreError> {
            Ok(Vec::new())
        }

        fn backend_info(&self) -> garth::SecureKeyStoreBackendInfo {
            garth::SecureKeyStoreBackendInfo {
                name: "refusing_test_store",
                hardware_backed: false,
                exportable: false,
            }
        }
    }

    #[tokio::test]
    async fn a_queue_round_trips_through_the_secure_store() {
        let store = garth::MemorySecureKeyStore::default();
        let key = "inkson.outbound.v1::nsA.standard";

        let enqueued = mutate_queue_in_store(&store, key, |queue| {
            enqueue_items(queue, 3);
            Ok(queue.len())
        })
        .await
        .unwrap();
        assert_eq!(enqueued, 3);

        let reloaded = mutate_queue_in_store(&store, key, |queue| Ok(queue.len()))
            .await
            .unwrap();
        assert_eq!(reloaded, 3, "a persisted queue must reload with every item");
    }

    #[tokio::test]
    async fn a_queue_past_the_localstorage_quota_round_trips_intact() {
        // The move off localStorage exists for exactly this shape. Encoding and
        // reloading is verified here; that the browser tier actually accepts
        // this many bytes is the browser contract in
        // `tests/wasm_indexed_db_capacity.rs`.
        let store = garth::MemorySecureKeyStore::default();
        let key = "inkson.outbound.v1::nsA.standard";

        mutate_queue_in_store(&store, key, |queue| {
            enqueue_items(queue, 2048);
            Ok(())
        })
        .await
        .unwrap();

        let encoded_len = store.get_secret(key).unwrap().unwrap().len();
        assert!(
            encoded_len > 5 * 1024 * 1024,
            "fixture queue is only {encoded_len} bytes; it no longer exceeds the \
             localStorage quota this test exists to clear"
        );

        let (items, first, last) = mutate_queue_in_store(&store, key, |queue| {
            let items = queue.active_items();
            Ok((
                queue.len(),
                items.first().unwrap().transaction_id.clone(),
                items.last().unwrap().transaction_id.clone(),
            ))
        })
        .await
        .unwrap();
        assert_eq!(items, 2048);
        assert_eq!(first, "txn-0");
        assert_eq!(last, "txn-2047");
    }

    #[tokio::test]
    async fn a_refused_durable_write_is_reported_not_swallowed() {
        // Fail closed: the caller must learn its Event was not persisted, or it
        // will treat an unqueued write as queued.
        let error = mutate_queue_in_store(
            &RefusingStore,
            "inkson.outbound.v1::nsA.standard",
            |queue| {
                enqueue_items(queue, 1);
                Ok(())
            },
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("persist outbound queue"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn outbound_queue_keys_are_classified_indexeddb_only() {
        // The whole point of the move off localStorage: if this prefix were
        // not classified, the secure fallback tier would mirror every queue
        // back into localStorage and spend the same ~5 MB origin quota the
        // move was made to escape — and leave signed Events under the weaker
        // tier while doing it.
        let authority = fixture::authority_at_station(
            "ak:did_core:webvh:zPrincipal",
            "ak:did_core:webvh:zServerA",
        );
        let scope = outbound_storage_scope(&authority, OutboundLane::Standard).unwrap();
        assert!(
            crate::secure_key_store::is_wasm_indexeddb_required_secret_key(&format!(
                "{OUTBOUND_QUEUE_KEY_PREFIX}{scope}"
            ))
        );
    }

    fn namespaces(values: &[&str]) -> std::collections::BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn legacy_drain_adopts_a_queue_whose_authority_still_has_an_account() {
        let live = namespaces(&["nsA", "nsB"]);
        assert_eq!(
            legacy_queue_action("inkson.outbound.v1::nsA.standard", Some(&live)),
            Some(LegacyQueueAction::Adopt)
        );
    }

    #[test]
    fn legacy_drain_discards_a_queue_whose_authority_is_gone() {
        // These items are Pending forever — the session that would sign and
        // send them no longer exists — so carrying them into the new tier
        // would migrate work that can never drain.
        let live = namespaces(&["nsA"]);
        assert_eq!(
            legacy_queue_action("inkson.outbound.v1::nsGone.standard", Some(&live)),
            Some(LegacyQueueAction::Discard)
        );
    }

    #[test]
    fn legacy_drain_adopts_everything_when_the_account_index_is_unreadable() {
        // `None` is "unknown", not "no account is known". Reading it as the
        // latter would delete a live authority's unsent Events the first time
        // the root index fails to parse.
        assert_eq!(
            legacy_queue_action("inkson.outbound.v1::nsA.standard", None),
            Some(LegacyQueueAction::Adopt)
        );
    }

    #[test]
    fn legacy_drain_ignores_keys_that_are_not_outbound_queues() {
        let live = namespaces(&["nsA"]);
        assert_eq!(
            legacy_queue_action("inkson.local_state.v1", Some(&live)),
            None
        );
    }

    #[test]
    fn browser_namespace_is_none_for_keys_that_are_not_outbound_queues() {
        // `None` keeps the reclaimer fail-closed: a key it cannot parse is
        // never treated as an abandoned queue.
        assert_eq!(outbound_key_namespace("inkson.local_state.v1"), None);
        assert_eq!(
            outbound_key_namespace("inkson.outbound.v1::digest-without-a-lane"),
            None
        );
    }

    #[test]
    fn mls_and_standard_lanes_are_distinct_within_one_authority() {
        let authority = fixture::authority_at_station(
            "ak:did_core:webvh:zPrincipal",
            "ak:did_core:webvh:zServerA",
        );
        assert_ne!(
            outbound_storage_scope(&authority, OutboundLane::Standard).unwrap(),
            outbound_storage_scope(&authority, OutboundLane::MlsDurablePostAccept).unwrap()
        );
    }
}
