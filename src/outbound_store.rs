//! Product storage adapter for garth's durable outbound queue.
//!
//! One queue item is one `AuthoritySubmitRequest` frozen at authoring time plus
//! its retry ledger. Physical queues are partitioned by the exact
//! [`arkret_sdk::AccountId`] that owns the authenticated session and by lane;
//! actor ids never serve as account-storage coordinates.
//!
//! Native clients persist an atomically replaced JSON file under the app data
//! directory. Web clients persist the same `SendQueueSnapshot` shape in the
//! IndexedDB + non-extractable SubtleCrypto entries store — the tier the
//! per-account main state already uses — so a queue of signed, not-yet-committed
//! Events is ciphertext at rest and is not charged against the ~5 MB
//! localStorage per-origin quota that a single queue can exhaust on its own.

use garth::OutboundQueueStore;
use garth::outbound::BoxOutboundFuture;

/// Storage-key prefix for one durable outbound queue:
/// `<prefix><authority digest>.<lane>`.
///
/// `secure_key_store::is_wasm_indexeddb_required_secret_key` classifies this
/// prefix as IndexedDB-only, preventing plaintext localStorage persistence.
#[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
pub(crate) const OUTBOUND_QUEUE_KEY_PREFIX: &str = "inkson.outbound.v1::";

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

/// Serialize asynchronous read-modify-write operations to prevent lost updates.
fn outbound_write_gate() -> &'static tokio::sync::Mutex<()> {
    static GATE: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    GATE.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn decode_snapshot(raw: Option<&str>) -> garth::Result<garth::SendQueueSnapshot> {
    match raw {
        Some(raw) => serde_json::from_str(raw)
            .map_err(|error| garth::Error::Protocol(format!("decode outbound queue: {error}"))),
        None => Ok(garth::SendQueueSnapshot::default()),
    }
}

fn encode_snapshot(queue: &garth::SendQueue) -> garth::Result<String> {
    serde_json::to_string(&queue.snapshot())
        .map_err(|error| garth::Error::Protocol(format!("encode outbound queue: {error}")))
}

/// One read-modify-write of a queue against an explicit secure store.
///
/// Only the `SecureKeyStore` port is involved, so this compiles on every target
/// and the native unit tests drive it against in-memory and
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
    let mut queue = garth::SendQueue::from_snapshot(decode_snapshot(stored.as_deref())?);
    let result = mutation(&mut queue)?;
    let encoded = encode_snapshot(&queue)?;
    // `OutboundQueueStore` exposes reads through the same mutation closure as
    // writes. In particular, `OutboundEngine::snapshot()` lands here. Do not
    // turn an unchanged read into a full AES-GCM + IndexedDB commit while the
    // process-wide outbound gate is held: besides being unnecessary, that can
    // serialize an ordinary Event behind unrelated secure-store maintenance.
    if stored.as_deref() == Some(encoded.as_str()) || (stored.is_none() && queue.items().is_empty())
    {
        return Ok(result);
    }
    store
        .store_secret_durable(storage_key, &encoded)
        .await
        .map_err(|error| {
            garth::Error::Protocol(format!(
                "persist outbound queue ({} item(s), {} encoded bytes): {error}",
                queue.items().len(),
                encoded.len(),
            ))
        })?;
    Ok(result)
}

/// One read-modify-write of a queue held in a file that is replaced atomically.
///
/// garth's own `FileStore` covers cursors, the event cache and the signing-stamp
/// floor; the outbound queue is a host-owned durable surface, so its file layout
/// belongs here next to the browser tier it mirrors.
#[cfg(not(target_arch = "wasm32"))]
async fn mutate_queue_in_file<R>(
    path: &std::path::Path,
    mutation: impl FnOnce(&mut garth::SendQueue) -> garth::Result<R>,
) -> garth::Result<R> {
    let stored = match std::fs::read_to_string(path) {
        Ok(raw) => Some(raw),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(garth::Error::Protocol(format!(
                "read outbound queue {}: {error}",
                path.display()
            )));
        }
    };
    let mut queue = garth::SendQueue::from_snapshot(decode_snapshot(stored.as_deref())?);
    let result = mutation(&mut queue)?;
    let encoded = encode_snapshot(&queue)?;
    if stored.as_deref() == Some(encoded.as_str()) || (stored.is_none() && queue.items().is_empty())
    {
        return Ok(result);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            garth::Error::Protocol(format!(
                "create outbound queue directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, encoded.as_bytes()).map_err(|error| {
        garth::Error::Protocol(format!(
            "stage outbound queue {}: {error}",
            temporary.display()
        ))
    })?;
    std::fs::rename(&temporary, path).map_err(|error| {
        garth::Error::Protocol(format!("persist outbound queue {}: {error}", path.display()))
    })?;
    Ok(result)
}

#[derive(Clone)]
pub(crate) struct InksonOutboundStore {
    #[cfg(not(target_arch = "wasm32"))]
    path: std::path::PathBuf,
    #[cfg(target_arch = "wasm32")]
    storage_key: String,
}

/// Durable queues are split by what has to happen after the Station answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutboundLane {
    /// Ordinary producer Events. A commit ends the item's life.
    Standard,
    /// `ak.mls.commit` submissions. The commit Event and its Welcome
    /// deliveries are one atomic submission, and an accepted commit still owes
    /// the local install of the staged group state.
    MlsCommit,
}

impl OutboundLane {
    fn suffix(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::MlsCommit => "mls-commit",
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
            Ok(Self {
                path: crate::state::app_data_dir()
                    .join("outbound")
                    .join(format!("{scope}.json")),
            })
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
            Box::pin(async move {
                let _write_guard = outbound_write_gate().lock().await;
                mutate_queue_in_file(&self.path, mutation).await
            })
        }
        #[cfg(target_arch = "wasm32")]
        {
            Box::pin(async move {
                let store = secure_outbound_store()?;
                let _write_guard = outbound_write_gate().lock().await;
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
/// read-modify-write code rather than a copy of it.
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

    const FIXTURE_REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    /// One valid queued submission. Kept deliberately ordinary: these tests are
    /// about the storage adapter, so the submission only has to be something
    /// `SendQueue::enqueue` accepts and `from_snapshot` reads back.
    fn fixture_submission(nth: usize) -> garth::QueuedSubmission {
        let actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
        ));
        let payload = arkret_sdk::MessageCreatePayload::with_content(
            arkret_sdk::StrandId::new("ak:strand:AXA352XtBodUhnMN_nDxOloEHVn0_yAotxiYxbyU38Df")
                .unwrap(),
            "discussion",
            arkret_sdk::ContentBlock::text(format!("queued fixture {nth}")),
        );
        let event =
            arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::MessageCreate>::new(
                arkret_sdk::ScopeRef::Realm {
                    realm_id: fixture::realm_id(FIXTURE_REALM),
                },
                actor_id,
                payload,
            )
            .unwrap()
            .author_with_digest_suite(
                chrono::DateTime::from_timestamp_millis(
                    1_760_000_000_000 + i64::try_from(nth).unwrap_or(0),
                )
                .unwrap(),
                arkret_sdk::DigestSuite::Sha256,
            )
            .unwrap()
            .into_event();
        garth::QueuedSubmission::new(arkret_wire::AuthoritySubmitRequest::Event(
            arkret_wire::EventCommitSubmission { event },
        ))
        .expect("fixture submission is structurally valid")
    }

    fn enqueue_items(queue: &mut garth::SendQueue, count: usize) {
        let now = chrono::Utc::now();
        for index in 0..count {
            queue.enqueue(fixture_submission(index), now).unwrap();
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
            Ok(queue.items().len())
        })
        .await
        .unwrap();
        assert_eq!(enqueued, 3);

        let reloaded = mutate_queue_in_store(&store, key, |queue| Ok(queue.items().len()))
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
            let items = queue.items();
            Ok((
                items.len(),
                items.first().unwrap().event_id().clone(),
                items.last().unwrap().event_id().clone(),
            ))
        })
        .await
        .unwrap();
        assert_eq!(items, 2048);
        assert_ne!(first, last, "every queued item keeps its own Event identity");
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

    #[tokio::test]
    async fn an_empty_snapshot_is_a_true_read_and_does_not_write() {
        let item_count = mutate_queue_in_store(
            &RefusingStore,
            "inkson.outbound.v1::nsA.standard",
            |queue| Ok(queue.items().len()),
        )
        .await
        .expect("an unchanged empty queue must not attempt durable persistence");
        assert_eq!(item_count, 0);
    }

    #[tokio::test]
    async fn a_native_queue_file_is_replaced_atomically_and_reloads() {
        let directory = std::env::temp_dir().join(format!(
            "inkson-outbound-{}",
            arkret_sdk::identifiers::uuid_v7_at(crate::clock::now_unix_ms())
        ));
        let path = directory.join("standard.json");

        mutate_queue_in_file(&path, |queue| {
            enqueue_items(queue, 4);
            Ok(())
        })
        .await
        .unwrap();
        assert!(
            !path.with_extension("json.tmp").exists(),
            "the staged file must be renamed, not left behind"
        );

        let reloaded = mutate_queue_in_file(&path, |queue| Ok(queue.items().len()))
            .await
            .unwrap();
        assert_eq!(reloaded, 4);
        std::fs::remove_dir_all(&directory).ok();
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

    #[test]
    fn mls_and_standard_lanes_are_distinct_within_one_authority() {
        let authority = fixture::authority_at_station(
            "ak:did_core:webvh:zPrincipal",
            "ak:did_core:webvh:zServerA",
        );
        assert_ne!(
            outbound_storage_scope(&authority, OutboundLane::Standard).unwrap(),
            outbound_storage_scope(&authority, OutboundLane::MlsCommit).unwrap()
        );
    }
}
