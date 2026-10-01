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

pub(crate) mod creator_protection;

use arkret_models_collaboration::mls_creator_bootstrap::{
    MlsCreatorBootstrapIntent, MlsCreatorBootstrapRecord,
};
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

type ScheduledDispatches =
    std::collections::BTreeMap<arkret_identifiers::ScheduledSendId, arkret_sdk::EventId>;

/// Holder-private dispatch identities share the queue's single durable write.
/// This adds no protocol wire field or second storage key.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableOutboundState {
    items: Vec<garth::SendQueueItem>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    scheduled_dispatches: ScheduledDispatches,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    creator_bootstrap_records: Vec<MlsCreatorBootstrapRecord>,
}

impl DurableOutboundState {
    fn validate(&self) -> garth::Result<()> {
        for (index, record) in self.creator_bootstrap_records.iter().enumerate() {
            record.validate()?;
            let intent = record.intent();
            if self.creator_bootstrap_records[..index]
                .iter()
                .any(|other| other.intent().effective_scope() == intent.effective_scope())
            {
                return Err(garth::Error::Storage(
                    "duplicate creator bootstrap logical key in authoring vault".into(),
                ));
            }
            let item = self
                .items
                .iter()
                .find(|item| item.event_id() == intent.scope_create_event_id())
                .ok_or_else(|| {
                    garth::Error::Storage(
                        "creator intent lost its frozen scope-create queue item".into(),
                    )
                })?;
            if item.request() != intent.signed_scope_create_unit() {
                return Err(garth::Error::Storage(
                    "creator intent disagrees with its frozen scope-create queue item".into(),
                ));
            }
        }
        for record in &self.creator_bootstrap_records {
            if let Some(queued) = record.queued_genesis() {
                let item = self
                    .items
                    .iter()
                    .find(|item| item.event_id() == queued.outbound_queue_item_id())
                    .ok_or_else(|| {
                        garth::Error::Storage(
                            "creator transaction lost its original Genesis queue item".into(),
                        )
                    })?;
                let expected = crate::event_submit::event_submission(queued.signed_genesis())
                    .map_err(|error| garth::Error::Storage(error.to_string()))?;
                if item.request() != &expected.request {
                    return Err(garth::Error::Storage(
                        "creator transaction disagrees with its original Genesis queue bytes"
                            .into(),
                    ));
                }
            }
        }
        for event_id in self.scheduled_dispatches.values() {
            let item = self
                .items
                .iter()
                .find(|item| item.event_id() == event_id)
                .ok_or_else(|| {
                    garth::Error::Storage(
                        "scheduled dispatch lost its frozen queue item".to_owned(),
                    )
                })?;
            let arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
                event,
            ) = &item.submission.request
            else {
                return Err(garth::Error::Protocol(
                    "scheduled dispatch requires an ordinary message".to_owned(),
                ));
            };
            garth::FrozenMessageSubmission::from_signed_request(garth::MessageSubmitRequestBody {
                submission: event.clone(),
            })?;
        }
        Ok(())
    }

    /// First registry cut: retain the whole closed intent and the exact create
    /// queue item in the same durable unit. A second holder can only join it.
    fn freeze_creator_intent(
        &mut self,
        intent: MlsCreatorBootstrapIntent,
        submission: garth::QueuedSubmission,
    ) -> garth::Result<()> {
        intent.validate()?;
        if &submission.request != intent.signed_scope_create_unit() {
            return Err(garth::Error::Protocol(
                "creator intent does not name the exact frozen create submission".into(),
            ));
        }
        if let Some(existing) = self
            .creator_bootstrap_records
            .iter()
            .find(|existing| existing.intent().effective_scope() == intent.effective_scope())
        {
            if existing.intent() != &intent {
                return Err(garth::Error::Protocol(
                    "creator bootstrap already belongs to another immutable intent or holder"
                        .into(),
                ));
            }
        } else {
            self.creator_bootstrap_records
                .push(MlsCreatorBootstrapRecord::new(intent)?);
        }
        let mut queue = garth::SendQueue::from_snapshot(garth::SendQueueSnapshot {
            items: std::mem::take(&mut self.items),
        });
        if let Some(existing) = queue.get(&submission.event_id) {
            if existing.request() != &submission.request {
                return Err(garth::Error::Protocol(
                    "creator create identity has different frozen request bytes".into(),
                ));
            }
        } else {
            queue.enqueue(submission, crate::clock::now_utc())?;
        }
        self.items = queue.snapshot().items;
        Ok(())
    }
}

fn decode_snapshot(raw: Option<&str>) -> garth::Result<DurableOutboundState> {
    let state: DurableOutboundState = match raw {
        Some(raw) => serde_json::from_str(raw)
            .map_err(|error| garth::Error::Protocol(format!("decode outbound queue: {error}")))?,
        None => DurableOutboundState::default(),
    };
    state.validate()?;
    Ok(state)
}

fn encode_snapshot(state: &DurableOutboundState) -> garth::Result<String> {
    state.validate()?;
    serde_json::to_string(state)
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
    mutate_dispatches_in_store(store, storage_key, |queue, _| mutation(queue)).await
}

#[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
async fn mutate_dispatches_in_store<R>(
    store: &dyn crate::secure_key_store::SecureKeyStore,
    storage_key: &str,
    mutation: impl FnOnce(&mut garth::SendQueue, &mut ScheduledDispatches) -> garth::Result<R>,
) -> garth::Result<R> {
    mutate_state_in_store(store, storage_key, |state| {
        let mut queue = garth::SendQueue::from_snapshot(garth::SendQueueSnapshot {
            items: std::mem::take(&mut state.items),
        });
        let result = mutation(&mut queue, &mut state.scheduled_dispatches)?;
        state.items = queue.snapshot().items;
        Ok(result)
    })
    .await
}

#[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
async fn mutate_state_in_store<R>(
    store: &dyn crate::secure_key_store::SecureKeyStore,
    storage_key: &str,
    mutation: impl FnOnce(&mut DurableOutboundState) -> garth::Result<R>,
) -> garth::Result<R> {
    let stored_bytes = store
        .read_secret_bytes_durable(storage_key)
        .await
        .map_err(|error| {
            garth::Error::Storage(format!("read committed outbound queue: {error}"))
        })?;
    let stored = stored_bytes
        .as_ref()
        .map(|bytes| std::str::from_utf8(bytes.as_slice()))
        .transpose()
        .map_err(|error| garth::Error::Storage(format!("decode outbound queue bytes: {error}")))?;
    let mut state = decode_snapshot(stored)?;
    let result = mutation(&mut state)?;
    let encoded = encode_snapshot(&state)?;
    // `OutboundQueueStore` exposes reads through the same mutation closure as
    // writes. In particular, `OutboundEngine::snapshot()` lands here. Do not
    // turn an unchanged read into a full AES-GCM + IndexedDB commit while the
    // process-wide outbound gate is held: besides being unnecessary, that can
    // serialize an ordinary Event behind unrelated secure-store maintenance.
    if stored == Some(encoded.as_str())
        || (stored.is_none() && encoded == encode_snapshot(&DurableOutboundState::default())?)
    {
        return Ok(result);
    }
    let committed = store
        .compare_exchange_secret_bytes_durable(
            storage_key,
            stored_bytes.as_ref().map(arkret_sdk::KeyBytes::as_slice),
            encoded.as_bytes(),
        )
        .await
        .map_err(|error| {
            garth::Error::Protocol(format!(
                "persist outbound queue ({} item(s), {} encoded bytes): {error}",
                state.items.len(),
                encoded.len(),
            ))
        })?;
    if !committed {
        return Err(garth::Error::Storage(
            "outbound queue changed in another holder; retry from its committed snapshot".into(),
        ));
    }
    Ok(result)
}

/// One read-modify-write of a queue held in a file that is replaced atomically.
///
/// garth's own `FileStore` covers cursors, the event cache and the signing-stamp
/// floor; the outbound queue is a host-owned durable surface, so its file layout
/// belongs here next to the browser tier it mirrors.
#[cfg(all(test, not(target_arch = "wasm32")))]
async fn mutate_queue_in_file<R>(
    path: &std::path::Path,
    mutation: impl FnOnce(&mut garth::SendQueue) -> garth::Result<R>,
) -> garth::Result<R> {
    mutate_dispatches_in_file(path, |queue, _| mutation(queue)).await
}

#[cfg(all(test, not(target_arch = "wasm32")))]
async fn mutate_dispatches_in_file<R>(
    path: &std::path::Path,
    mutation: impl FnOnce(&mut garth::SendQueue, &mut ScheduledDispatches) -> garth::Result<R>,
) -> garth::Result<R> {
    mutate_state_in_file(path, None, |state| {
        let mut queue = garth::SendQueue::from_snapshot(garth::SendQueueSnapshot {
            items: std::mem::take(&mut state.items),
        });
        let result = mutation(&mut queue, &mut state.scheduled_dispatches)?;
        state.items = queue.snapshot().items;
        Ok(result)
    })
    .await
}

#[cfg(not(target_arch = "wasm32"))]
async fn mutate_state_in_file<R>(
    path: &std::path::Path,
    protection: Option<(
        &arkret_sdk::AccountId,
        &dyn crate::secure_key_store::SecureKeyStore,
    )>,
    mutation: impl FnOnce(&mut DurableOutboundState) -> garth::Result<R>,
) -> garth::Result<R> {
    // Reload and replace under one OS lock shared by independent processes.
    // Locking the data file itself would release protection after its rename.
    let mut lock_name = path.as_os_str().to_owned();
    lock_name.push(".lock");
    let lock_path = std::path::PathBuf::from(lock_name);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|error| {
            garth::Error::Storage(format!(
                "create outbound queue directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|error| {
            garth::Error::Storage(format!(
                "open outbound lock {}: {error}",
                lock_path.display()
            ))
        })?;
    lock.lock().map_err(|error| {
        garth::Error::Storage(format!("lock outbound queue {}: {error}", path.display()))
    })?;
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
    let plaintext = stored
        .as_deref()
        .map(|raw| match protection {
            Some((authority, store)) => creator_protection::open_records(raw, authority, store)
                .map_err(|error| garth::Error::Storage(error.to_string())),
            None => Ok(raw.to_owned()),
        })
        .transpose()?;
    let mut state = decode_snapshot(plaintext.as_deref())?;
    let result = mutation(&mut state)?;
    let encoded = encode_snapshot(&state)?;
    if plaintext.as_deref() == Some(encoded.as_str())
        || (plaintext.is_none() && encoded == encode_snapshot(&DurableOutboundState::default())?)
    {
        return Ok(result);
    }
    let encoded = match protection {
        Some((authority, store)) => creator_protection::protect_records(&encoded, authority, store)
            .map_err(|error| garth::Error::Storage(error.to_string()))?,
        None => encoded,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            garth::Error::Protocol(format!(
                "create outbound queue directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    let temporary = path.with_extension("json.tmp");
    let write_result = (|| -> std::io::Result<()> {
        use std::io::Write as _;
        let mut staged = std::fs::File::create(&temporary)?;
        staged.write_all(encoded.as_bytes())?;
        staged.sync_all()
    })();
    write_result.map_err(|error| {
        garth::Error::Protocol(format!(
            "stage outbound queue {}: {error}",
            temporary.display()
        ))
    })?;
    std::fs::rename(&temporary, path).map_err(|error| {
        garth::Error::Protocol(format!(
            "persist outbound queue {}: {error}",
            path.display()
        ))
    })?;
    Ok(result)
}

#[derive(Clone)]
pub(crate) struct InksonOutboundStore {
    #[cfg(not(target_arch = "wasm32"))]
    path: std::path::PathBuf,
    #[cfg(not(target_arch = "wasm32"))]
    protection: Option<(
        arkret_sdk::AccountId,
        std::sync::Arc<dyn crate::secure_key_store::SecureKeyStore + Send + Sync>,
    )>,
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
    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(crate) fn for_test_path(path: std::path::PathBuf) -> Self {
        Self {
            path,
            protection: None,
        }
    }

    pub(crate) fn open(
        authority: &arkret_sdk::AccountId,
        lane: OutboundLane,
    ) -> arkret_sdk::Result<Self> {
        let scope = outbound_storage_scope(authority, lane)?;
        #[cfg(not(target_arch = "wasm32"))]
        {
            Ok(Self {
                protection: Some((
                    authority.clone(),
                    crate::secure_key_store::default_secure_key_store("inkson"),
                )),
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

    async fn mutate_state<R>(
        &self,
        mutation: impl FnOnce(&mut DurableOutboundState) -> garth::Result<R>,
    ) -> garth::Result<R> {
        let _write_guard = outbound_write_gate().lock().await;
        #[cfg(not(target_arch = "wasm32"))]
        {
            mutate_state_in_file(
                &self.path,
                self.protection.as_ref().map(|(authority, store)| {
                    (
                        authority,
                        store.as_ref() as &dyn crate::secure_key_store::SecureKeyStore,
                    )
                }),
                mutation,
            )
            .await
        }
        #[cfg(target_arch = "wasm32")]
        {
            let store = secure_outbound_store()?;
            mutate_state_in_store(store.as_ref(), &self.storage_key, mutation).await
        }
    }

    pub(crate) async fn freeze_creator_intent(
        &self,
        intent: MlsCreatorBootstrapIntent,
        submission: garth::QueuedSubmission,
    ) -> garth::Result<()> {
        self.mutate_state(|state| state.freeze_creator_intent(intent, submission))
            .await
    }

    /// Holder-local encryption choice. This does not assert protocol MLS
    /// activation; it only prevents publishing plaintext during bootstrap.
    pub(crate) async fn has_creator_intent_for_scope(
        &self,
        scope: &arkret_sdk::ScopeRef,
    ) -> garth::Result<bool> {
        self.mutate_state(|state| {
            Ok(state
                .creator_bootstrap_records
                .iter()
                .any(|record| record.intent().effective_scope() == scope))
        })
        .await
    }

    pub(crate) async fn creator_intent(
        &self,
        owner: &arkret_sdk::ActorId,
        scope: &arkret_sdk::ScopeRef,
    ) -> garth::Result<Option<MlsCreatorBootstrapIntent>> {
        self.mutate_state(|state| {
            Ok(state
                .creator_bootstrap_records
                .iter()
                .map(MlsCreatorBootstrapRecord::intent)
                .find(|intent| {
                    intent.owner_actor_id() == owner && intent.effective_scope() == scope
                })
                .cloned())
        })
        .await
    }

    pub(crate) async fn creator_record(
        &self,
        owner: &arkret_sdk::ActorId,
        scope: &arkret_sdk::ScopeRef,
    ) -> garth::Result<Option<MlsCreatorBootstrapRecord>> {
        self.mutate_state(|state| {
            Ok(state
                .creator_bootstrap_records
                .iter()
                .find(|record| {
                    record.intent().owner_actor_id() == owner
                        && record.intent().effective_scope() == scope
                })
                .cloned())
        })
        .await
    }

    /// Compare the whole previously read record while holding the vault's
    /// native OS lock or IndexedDB CAS. The queue and record share one commit.
    pub(crate) async fn accept_creator_realm(
        &self,
        expected: MlsCreatorBootstrapRecord,
        accepted_create: arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAcceptedCreate,
        genesis_absence: arkret_wire::RealmStateSnapshot,
    ) -> garth::Result<()> {
        let mut next = expected.clone();
        next.accept_realm(accepted_create, genesis_absence)?;
        self.replace_creator_record(expected, next).await
    }

    pub(crate) async fn pin_creator_governance(
        &self,
        expected: MlsCreatorBootstrapRecord,
        evidence: arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapGovernanceEvidence,
    ) -> garth::Result<()> {
        let mut next = expected.clone();
        next.pin_governance(evidence)?;
        self.replace_creator_record(expected, next).await
    }

    pub(crate) async fn persist_creator_epoch_zero(
        &self,
        expected: MlsCreatorBootstrapRecord,
        unit: arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapEpochZero,
    ) -> garth::Result<()> {
        let mut next = expected.clone();
        next.persist_epoch_zero(unit)?;
        self.replace_creator_record(expected, next).await
    }

    /// Establish the signed original and its ledger item with one vault commit.
    pub(crate) async fn queue_creator_genesis(
        &self,
        expected: MlsCreatorBootstrapRecord,
        signed: arkret_sdk::AuthoredEvent,
    ) -> garth::Result<garth::QueuedSubmission> {
        let submission = crate::event_submit::event_submission(&signed)
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        let mut next = expected.clone();
        next.queue_genesis(signed)?;
        self.mutate_state(|state| {
            let record = state
                .creator_bootstrap_records
                .iter_mut()
                .find(|record| {
                    record.intent().effective_scope() == expected.intent().effective_scope()
                })
                .ok_or_else(|| {
                    garth::Error::Storage("creator queue lost its durable record".into())
                })?;
            if record != &next && record != &expected {
                return Err(garth::Error::Storage(
                    "creator queue changed in another holder; reread the frozen original".into(),
                ));
            }
            let mut queue = garth::SendQueue::from_snapshot(garth::SendQueueSnapshot {
                items: std::mem::take(&mut state.items),
            });
            if let Some(existing) = queue.get(&submission.event_id) {
                if existing.request() != &submission.request {
                    return Err(garth::Error::Storage(
                        "creator Genesis queue has different frozen bytes".into(),
                    ));
                }
            } else {
                queue.enqueue(submission.clone(), crate::clock::now_utc())?;
            }
            state.items = queue.snapshot().items;
            *record = next;
            Ok(submission)
        })
        .await
    }

    async fn replace_creator_record(
        &self,
        expected: MlsCreatorBootstrapRecord,
        next: MlsCreatorBootstrapRecord,
    ) -> garth::Result<()> {
        next.validate()?;
        self.mutate_state(|state| {
            let record = state
                .creator_bootstrap_records
                .iter_mut()
                .find(|record| {
                    record.intent().effective_scope() == expected.intent().effective_scope()
                })
                .ok_or_else(|| {
                    garth::Error::Storage("creator transaction lost its durable intent".into())
                })?;
            if record == &next {
                return Ok(());
            }
            if record != &expected {
                return Err(garth::Error::Storage(
                    "creator transaction changed in another holder; reread its committed state"
                        .into(),
                ));
            }
            *record = next;
            Ok(())
        })
        .await
    }

    async fn mutate_dispatches<R>(
        &self,
        mutation: impl FnOnce(&mut garth::SendQueue, &mut ScheduledDispatches) -> garth::Result<R>,
    ) -> garth::Result<R> {
        let _write_guard = outbound_write_gate().lock().await;
        #[cfg(not(target_arch = "wasm32"))]
        {
            mutate_state_in_file(
                &self.path,
                self.protection.as_ref().map(|(authority, store)| {
                    (
                        authority,
                        store.as_ref() as &dyn crate::secure_key_store::SecureKeyStore,
                    )
                }),
                |state| {
                    let mut queue = garth::SendQueue::from_snapshot(garth::SendQueueSnapshot {
                        items: std::mem::take(&mut state.items),
                    });
                    let result = mutation(&mut queue, &mut state.scheduled_dispatches)?;
                    state.items = queue.snapshot().items;
                    Ok(result)
                },
            )
            .await
        }
        #[cfg(target_arch = "wasm32")]
        {
            let store = secure_outbound_store()?;
            mutate_dispatches_in_store(store.as_ref(), &self.storage_key, mutation).await
        }
    }

    pub(crate) async fn scheduled_dispatch(
        &self,
        id: &arkret_identifiers::ScheduledSendId,
    ) -> garth::Result<Option<garth::SendQueueItem>> {
        self.mutate_dispatches(|queue, dispatches| {
            let Some(event_id) = dispatches.get(id) else {
                return Ok(None);
            };
            queue
                .items()
                .iter()
                .find(|item| item.event_id() == event_id)
                .cloned()
                .map(Some)
                .ok_or_else(|| {
                    garth::Error::Storage("scheduled dispatch lost its frozen Event".to_owned())
                })
        })
        .await
    }

    pub(crate) async fn resolve_scheduled_dispatch<F, Fut>(
        &self,
        id: arkret_identifiers::ScheduledSendId,
        author: F,
    ) -> garth::Result<garth::QueuedSubmission>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = garth::Result<garth::QueuedSubmission>>,
    {
        // Keep the first lookup, one-shot host authoring and the atomic bind
        // together across every scheduled producer in this holder runtime.
        static AUTHORING_GATE: std::sync::OnceLock<tokio::sync::Mutex<()>> =
            std::sync::OnceLock::new();
        let _authoring_guard = AUTHORING_GATE
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await;
        if let Some(existing) = self.scheduled_dispatch(&id).await? {
            return Ok(existing.submission);
        }
        self.freeze_scheduled_dispatch(id, author().await?).await
    }

    pub(crate) async fn freeze_scheduled_dispatch(
        &self,
        id: arkret_identifiers::ScheduledSendId,
        submission: garth::QueuedSubmission,
    ) -> garth::Result<garth::QueuedSubmission> {
        self.mutate_dispatches(|queue, dispatches| {
            if let Some(event_id) = dispatches.get(&id) {
                return queue
                    .items()
                    .iter()
                    .find(|item| item.event_id() == event_id)
                    .map(|item| item.submission.clone())
                    .ok_or_else(|| {
                        garth::Error::Storage("scheduled dispatch lost its frozen Event".to_owned())
                    });
            }
            let event_id = submission.event_id.clone();
            queue.enqueue(submission.clone(), crate::clock::now_utc())?;
            dispatches.insert(id, event_id);
            Ok(submission)
        })
        .await
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
            Box::pin(self.mutate_state(|state| {
                let mut queue = garth::SendQueue::from_snapshot(garth::SendQueueSnapshot {
                    items: std::mem::take(&mut state.items),
                });
                let result = mutation(&mut queue)?;
                state.items = queue.snapshot().items;
                Ok(result)
            }))
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
    pub async fn freeze_creator_intent(
        store: &dyn crate::secure_key_store::SecureKeyStore,
        storage_key: &str,
        intent: arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapIntent,
        submission: garth::QueuedSubmission,
    ) -> garth::Result<()> {
        super::mutate_state_in_store(store, storage_key, |state| {
            state.freeze_creator_intent(intent, submission)
        })
        .await
    }

    pub async fn creator_intents(
        store: &dyn crate::secure_key_store::SecureKeyStore,
        storage_key: &str,
    ) -> garth::Result<
        Vec<arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapIntent>,
    > {
        super::mutate_state_in_store(store, storage_key, |state| {
            Ok(state
                .creator_bootstrap_records
                .iter()
                .map(|record| record.intent().clone())
                .collect())
        })
        .await
    }
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
    use crate::operation::AuthoredEventExt as _;
    use crate::test_support as fixture;

    fn creator_fixture(device: &str) -> (MlsCreatorBootstrapIntent, garth::QueuedSubmission) {
        let mut events = crate::event_submit::author_event_unit_for_test(
            crate::event_builders::build_realm_bootstrap_steps_for_station(
                fixture::core_id(fixture::STATION_ID),
                arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                    .unwrap(),
                "did:web:alice.example",
                "did:web:principal.example",
                "https://principal.example",
                "Creator intent",
                None,
                "invite_only",
                "invite",
                "since_join",
                "standard",
                "closed",
                "sha256",
                "ak:trust_domain:did.web.example",
                &[],
                None,
            )
            .unwrap(),
        )
        .unwrap();
        for event in &mut events {
            event
                .sign_ed25519(
                    "did:web:alice.example",
                    &format!("did:web:alice.example#{device}"),
                    &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                )
                .unwrap();
        }
        let submission = garth::QueuedSubmission::realm_bootstrap(
            arkret_models_collaboration::authority_commit::OrdinaryRealmBootstrapUnitSubmission {
                unit_kind: arkret_models_collaboration::authority_commit::OrdinaryRealmBootstrapUnitKind::OrdinaryRealmBootstrap,
                idempotency_key: serde_json::from_value(serde_json::json!("01904100-0000-7000-8000-000000000001")).unwrap(),
                events: events.into_iter().map(|event| arkret_wire::EventAdmissionSubmission::new(event.into_event())).collect(),
            },
        ).unwrap();
        let intent = crate::event_submit::creator_intent_for_submission(
            &submission,
            fixture::device_id(device),
        )
        .unwrap();
        (intent, submission)
    }

    const CREATOR_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000001";

    fn creator_acceptance(
        intent: &MlsCreatorBootstrapIntent,
    ) -> (
        arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAcceptedCreate,
        arkret_wire::RealmStateSnapshot,
    ) {
        use arkret_wire::*;
        let arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(unit) = intent.signed_scope_create_unit() else { panic!("fixture is a Realm bootstrap") };
        let event = unit.events[0].event.clone();
        let time = event.created_at;
        // Shape-only acceptance for storage fault tests. Cryptographic source
        // authentication is covered by the host's Garth gate and live tests.
        let signature = |context| DetachedObjectSignature {
            context,
            signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
            verification_method: DidUrl::new("did:web:principal.example#key").unwrap(),
            signed_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            created_at: time,
            sig: Base64UrlString::new("AA").unwrap(),
        };
        let commit = RealmCommit {
            commit_id: RealmCommitId::from_digest([7; 32]),
            realm_id: event.realm_id.clone(),
            stream_ref: CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            },
            stream_position: 0,
            previous_commit_ref: None,
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone()),
            committed_at: time,
            signature: signature(DetachedSignatureContext::RealmCommit),
        };
        let head = CommitStreamHead {
            stream_ref: commit.stream_ref.clone(),
            stream_position: 0,
            commit_id: commit.commit_id.clone(),
        };
        let root = RealmAuthorityBundle {
            realm_id: event.realm_id.clone(),
            genesis_event: event.clone(),
            genesis_commit: commit.clone(),
            authority_transitions: vec![],
            current_generation: 0,
            current_service_id: fixture::core_id(fixture::STATION_ID),
            current_route_record: serde_json::json!({}),
            realm_stream_head: head.clone(),
            bundle_issued_at: time,
            current_assertion: RealmAuthorityCurrentAssertion {
                realm_id: event.realm_id.clone(),
                current_generation: 0,
                current_service_id: fixture::core_id(fixture::STATION_ID),
                last_handoff_ref: None,
                realm_stream_head: head.clone(),
                nonce: Base64UrlString::new("AAAAAAAAAAAAAAAAAAAAAA").unwrap(),
                expires_at: time + chrono::TimeDelta::minutes(5),
                signature: signature(DetachedSignatureContext::RealmAuthorityCurrentAssertion),
            },
        };
        let snapshot = RealmStateSnapshot {
            snapshot_id: RealmSnapshotId::from_digest([3; 32]),
            realm_id: event.realm_id.clone(),
            governance_generation: 0,
            visible_stream_heads: vec![head],
            current_state_entries: vec![],
            retention_and_history_floor: RetentionAndHistoryFloor {
                history_access: HistoryAccess::SinceJoin,
                stream_floors: vec![StreamHistoryFloor {
                    stream_ref: commit.stream_ref.clone(),
                    oldest_position: 0,
                }],
            },
            created_at: time,
            signature: signature(DetachedSignatureContext::RealmSnapshot),
        };
        (arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAcceptedCreate::new(intent, event, commit, arkret_sdk::DigestSuite::Sha256, root).unwrap(), snapshot)
    }

    #[tokio::test]
    async fn creator_acceptance_failure_keeps_intent_and_exact_queue_then_reopens() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("standard.json");
        let store = InksonOutboundStore::for_test_path(path.clone());
        let (intent, submission) = creator_fixture(CREATOR_DEVICE);
        store
            .freeze_creator_intent(intent.clone(), submission.clone())
            .await
            .unwrap();
        assert!(matches!(
            crate::mls::send_gate::check_creator_plaintext_slot(&store, intent.effective_scope())
                .await,
            Err(crate::mls::send_gate::MlsSendGateBlocked::GenesisPending)
        ));
        let expected = store
            .creator_record(intent.owner_actor_id(), intent.effective_scope())
            .await
            .unwrap()
            .unwrap();
        let (accepted, snapshot) = creator_acceptance(&intent);
        let before = std::fs::read(&path).unwrap();
        std::fs::create_dir(path.with_extension("json.tmp")).unwrap();
        assert!(
            store
                .accept_creator_realm(expected.clone(), accepted.clone(), snapshot.clone())
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let reopened = InksonOutboundStore::for_test_path(path.clone());
        assert_eq!(
            reopened
                .creator_record(intent.owner_actor_id(), intent.effective_scope())
                .await
                .unwrap(),
            Some(expected.clone())
        );
        std::fs::remove_dir(path.with_extension("json.tmp")).unwrap();
        reopened
            .accept_creator_realm(expected.clone(), accepted.clone(), snapshot.clone())
            .await
            .unwrap();
        let winner = reopened
            .creator_record(intent.owner_actor_id(), intent.effective_scope())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            winner.state(),
            arkret_wire::MlsCreatorBootstrapState::RealmAccepted
        );
        assert_eq!(winner.intent(), &intent);
        store
            .accept_creator_realm(expected.clone(), accepted.clone(), snapshot.clone())
            .await
            .unwrap();
        let mut changed = snapshot;
        changed.created_at += chrono::TimeDelta::seconds(1);
        assert!(
            store
                .accept_creator_realm(expected, accepted, changed)
                .await
                .is_err()
        );
        let state = decode_snapshot(Some(&std::fs::read_to_string(path).unwrap())).unwrap();
        assert_eq!(state.creator_bootstrap_records, vec![winner]);
        assert_eq!(state.items.len(), 1);
        assert_eq!(state.items[0].request(), &submission.request);
    }

    #[tokio::test]
    async fn creator_pin_failure_and_stale_holder_keep_the_single_durable_cut() {
        use arkret_models_collaboration::mls_creator_bootstrap::{
            MlsCreatorBootstrapDeviceAuthority, MlsCreatorBootstrapGovernanceEvidence,
        };
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("standard.json");
        let store = InksonOutboundStore::for_test_path(path.clone());
        let (intent, submission) = creator_fixture(CREATOR_DEVICE);
        store
            .freeze_creator_intent(intent.clone(), submission.clone())
            .await
            .unwrap();
        let initial = store
            .creator_record(intent.owner_actor_id(), intent.effective_scope())
            .await
            .unwrap()
            .unwrap();
        let (accepted, snapshot) = creator_acceptance(&intent);
        store
            .accept_creator_realm(initial, accepted.clone(), snapshot.clone())
            .await
            .unwrap();
        let expected = store
            .creator_record(intent.owner_actor_id(), intent.effective_scope())
            .await
            .unwrap()
            .unwrap();
        let now = accepted.authority_root().bundle_issued_at;
        // These fixtures check atomic storage, not authenticated source evidence.
        let outcome: arkret_models_crypto::KeysQueryOutcome = serde_json::from_value(serde_json::json!({
            "device_keys": [{"account_id": intent.owner_actor_id().as_account_id().unwrap(), "device_keys": {
                CREATOR_DEVICE: {"signer_evidence_ref": "ak:signer_evidence:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "algorithms": {}, "trust_algorithms": [], "device_projection": {
                        "device_signing_key_did": "did:key:z6MkhHrTbtosB4xyyJM217fS4ry35F7JhZ5oA9uVHErBJDL5",
                        "hpke_key": "hpke-test", "device_authorize_event_id": intent.scope_create_event_id(),
                        "authorized_generation_ref": 7, "device_status": "active",
                        "attested_at": arkret_sdk::canonical::format_timestamp_canonical(now), "expires_at": arkret_sdk::canonical::format_timestamp_canonical(now + chrono::TimeDelta::minutes(5)),
                        "authorization_window": {"not_before": arkret_sdk::canonical::format_timestamp_canonical(now), "expires_at": null}
                    }}
            }}], "device_generations": [{"account_id": intent.owner_actor_id().as_account_id().unwrap(),
                "generation_state": {"current_device_generation_ref": 7}}]
        })).unwrap();
        let device =
            MlsCreatorBootstrapDeviceAuthority::from_self_keys_query(&intent, &outcome, now)
                .unwrap();
        let evidence = MlsCreatorBootstrapGovernanceEvidence::new_device(
            &intent,
            accepted.clone(),
            snapshot.clone(),
            device,
        )
        .unwrap();
        let before = std::fs::read(&path).unwrap();
        std::fs::create_dir(path.with_extension("json.tmp")).unwrap();
        assert!(
            store
                .pin_creator_governance(expected.clone(), evidence.clone())
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let reopened = InksonOutboundStore::for_test_path(path.clone());
        assert_eq!(
            reopened
                .creator_record(intent.owner_actor_id(), intent.effective_scope())
                .await
                .unwrap(),
            Some(expected.clone())
        );
        std::fs::remove_dir(path.with_extension("json.tmp")).unwrap();
        reopened
            .pin_creator_governance(expected.clone(), evidence.clone())
            .await
            .unwrap();
        store
            .pin_creator_governance(expected.clone(), evidence)
            .await
            .unwrap();
        let later_device = MlsCreatorBootstrapDeviceAuthority::from_self_keys_query(
            &intent,
            &outcome,
            now + chrono::TimeDelta::milliseconds(1),
        )
        .unwrap();
        let later_evidence = MlsCreatorBootstrapGovernanceEvidence::new_device(
            &intent,
            accepted,
            snapshot,
            later_device,
        )
        .unwrap();
        assert!(
            store
                .pin_creator_governance(expected, later_evidence)
                .await
                .is_err()
        );
        let state = decode_snapshot(Some(&std::fs::read_to_string(&path).unwrap())).unwrap();
        assert_eq!(
            state.creator_bootstrap_records[0].state(),
            arkret_wire::MlsCreatorBootstrapState::GovernanceResultPinned
        );
        assert_eq!(state.items.len(), 1);
        assert_eq!(state.items[0].request(), &submission.request);
        let expected = state.creator_bootstrap_records[0].clone();
        let evidence = expected.governance_evidence().unwrap();
        let private_store = crate::secure_key_store::MemorySecureKeyStore::new();
        let authority = intent.owner_actor_id().as_account_id().unwrap();
        let _scope_guard = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(Some((
            authority,
            intent.creator_device_id(),
        )));
        crate::secure_key_store::store_signing_seed(&private_store, &[11; 32]).unwrap();
        let device_secret = creator_protection::checkpoint_secret(
            &private_store,
            authority,
            intent.creator_device_id(),
        )
        .unwrap();
        let (private, summary) = crate::mls::runtime::generate_creator_epoch_zero(
            intent.effective_scope(),
            authority,
            intent.creator_device_id(),
            evidence.governance_binding(),
            &device_secret,
            Some(
                &evidence
                    .creator_device_authority()
                    .projection()
                    .device_authorize_event_id,
            ),
        )
        .unwrap();
        let unsigned =
            crate::mls::runtime::freeze_creator_genesis_core(&intent, evidence, &summary).unwrap();
        assert_eq!(unsigned.actor_id, *intent.owner_actor_id());
        let unit =
            arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapEpochZero::new(
                &intent,
                evidence,
                serde_json::to_vec(&private).unwrap(),
                summary.group_info_bytes.clone(),
                summary.ratchet_tree_bytes.clone(),
                unsigned.clone(),
            )
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        std::fs::create_dir(path.with_extension("json.tmp")).unwrap();
        assert!(
            reopened
                .persist_creator_epoch_zero(expected.clone(), unit.clone())
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            reopened
                .creator_record(intent.owner_actor_id(), intent.effective_scope())
                .await
                .unwrap(),
            Some(expected.clone())
        );
        std::fs::remove_dir(path.with_extension("json.tmp")).unwrap();
        reopened
            .persist_creator_epoch_zero(expected.clone(), unit.clone())
            .await
            .unwrap();
        let epoch_record = reopened
            .creator_record(intent.owner_actor_id(), intent.effective_scope())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            epoch_record.state(),
            arkret_wire::MlsCreatorBootstrapState::Epoch0StatePersisted
        );
        let (_, restored_summary) = crate::mls::runtime::restore_creator_epoch_zero(
            epoch_record.epoch_zero().unwrap(),
            &intent,
            &device_secret,
        )
        .unwrap();
        assert_eq!(restored_summary.group_info_bytes, summary.group_info_bytes);
        assert_eq!(
            restored_summary.ratchet_tree_bytes,
            summary.ratchet_tree_bytes
        );
        assert!(
            crate::mls::runtime::restore_creator_epoch_zero(
                &unit,
                &intent,
                "foreign-device-secret"
            )
            .is_err()
        );
        store
            .persist_creator_epoch_zero(expected, unit)
            .await
            .unwrap();
        let signer = crate::event_signer::build_ed25519_signer_with_verification_method(
            [11; 32],
            "did:web:alice.example",
            intent.creator_signer_method().as_str(),
        );
        let mut signed = unsigned;
        signer
            .sign_envelope_with_context(
                &mut signed,
                crate::event_signer::ProducerProofContext::new()
                    .with_digest_suite(arkret_sdk::DigestSuite::Sha256),
            )
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        std::fs::create_dir(path.with_extension("json.tmp")).unwrap();
        assert!(
            reopened
                .queue_creator_genesis(epoch_record.clone(), signed.clone())
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            reopened
                .creator_record(intent.owner_actor_id(), intent.effective_scope())
                .await
                .unwrap(),
            Some(epoch_record.clone())
        );
        std::fs::remove_dir(path.with_extension("json.tmp")).unwrap();
        let queued = reopened
            .queue_creator_genesis(epoch_record.clone(), signed.clone())
            .await
            .unwrap();
        store
            .queue_creator_genesis(epoch_record.clone(), signed.clone())
            .await
            .unwrap();
        let winner = reopened
            .creator_record(intent.owner_actor_id(), intent.effective_scope())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            winner.state(),
            arkret_wire::MlsCreatorBootstrapState::GenesisQueued
        );
        let stored = decode_snapshot(Some(&std::fs::read_to_string(&path).unwrap())).unwrap();
        assert_eq!(stored.items.len(), 2);
        assert_eq!(
            stored
                .items
                .iter()
                .find(|item| item.event_id() == &queued.event_id)
                .unwrap()
                .request(),
            &queued.request
        );
        let mut changed = signed;
        let mut proof = changed.producer_proof.clone().unwrap();
        proof.created_at += chrono::TimeDelta::milliseconds(1);
        changed.attach_proof(proof);
        assert!(
            store
                .queue_creator_genesis(epoch_record, changed)
                .await
                .is_err()
        );
        assert_eq!(
            store
                .creator_record(intent.owner_actor_id(), intent.effective_scope())
                .await
                .unwrap(),
            Some(winner)
        );
    }

    #[tokio::test]
    async fn creator_native_record_requires_the_original_device_secret_without_plaintext_fallback()
    {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("standard.json");
        let (intent, submission) = creator_fixture(CREATOR_DEVICE);
        let authority = intent.owner_actor_id().as_account_id().unwrap();
        let secrets = std::sync::Arc::new(crate::secure_key_store::MemorySecureKeyStore::new());
        let _scope_guard = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(Some((
            authority,
            intent.creator_device_id(),
        )));
        let store = InksonOutboundStore {
            path: path.clone(),
            protection: Some((authority.clone(), secrets.clone())),
        };
        assert!(
            store
                .freeze_creator_intent(intent.clone(), submission.clone())
                .await
                .is_err()
        );
        assert!(!path.exists());
        crate::secure_key_store::store_signing_seed(secrets.as_ref(), &[13; 32]).unwrap();
        store
            .freeze_creator_intent(intent.clone(), submission.clone())
            .await
            .unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(
            value["creator_bootstrap_records"][0]
                .get("intent")
                .is_none()
        );
        assert!(
            value["creator_bootstrap_records"][0]
                .get("ciphertext")
                .is_some()
        );
        let frozen = store
            .creator_record(intent.owner_actor_id(), intent.effective_scope())
            .await
            .unwrap()
            .unwrap();
        // Generic queue reads and writes use the same protected-record codec.
        store
            .mutate_outbound(|queue| {
                assert_eq!(queue.items().len(), 1);
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), raw);
        crate::secure_key_store::store_signing_seed(secrets.as_ref(), &[14; 32]).unwrap();
        assert!(
            store
                .creator_record(intent.owner_actor_id(), intent.effective_scope())
                .await
                .is_err()
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), raw);
        crate::secure_key_store::store_signing_seed(secrets.as_ref(), &[13; 32]).unwrap();
        assert_eq!(
            store
                .creator_record(intent.owner_actor_id(), intent.effective_scope())
                .await
                .unwrap(),
            Some(frozen)
        );
        // Old development plaintext is rejected rather than silently adopted.
        let plaintext =
            creator_protection::open_records(&raw, authority, secrets.as_ref()).unwrap();
        std::fs::write(&path, plaintext).unwrap();
        assert!(
            store
                .creator_record(intent.owner_actor_id(), intent.effective_scope())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn creator_intent_and_create_queue_survive_reopen_together() {
        let directory = std::env::temp_dir().join(format!(
            "inkson-creator-intent-{}",
            arkret_sdk::identifiers::uuid_v7_at(crate::clock::now_unix_ms())
        ));
        let path = directory.join("standard.json");
        let (intent, submission) = creator_fixture(CREATOR_DEVICE);
        InksonOutboundStore::for_test_path(path.clone())
            .freeze_creator_intent(intent.clone(), submission.clone())
            .await
            .unwrap();
        let reopened = InksonOutboundStore::for_test_path(path.clone());
        assert_eq!(
            reopened
                .creator_intent(intent.owner_actor_id(), intent.effective_scope())
                .await
                .unwrap(),
            Some(intent.clone())
        );
        reopened
            .freeze_creator_intent(intent.clone(), submission.clone())
            .await
            .unwrap();
        // Generic queue writes must preserve the closed selector even when they
        // only know the retry ledger, and must not create a second create unit.
        reopened
            .mutate_outbound(|queue| {
                queue.enqueue(fixture_submission(0), crate::clock::now_utc())?;
                Ok(())
            })
            .await
            .unwrap();
        let snapshot = decode_snapshot(Some(&std::fs::read_to_string(&path).unwrap())).unwrap();
        assert_eq!(
            snapshot.creator_bootstrap_records,
            vec![MlsCreatorBootstrapRecord::new(intent).unwrap()]
        );
        assert_eq!(snapshot.items.len(), 2);
        assert_eq!(snapshot.items[0].request(), &submission.request);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn independent_native_creator_holders_keep_one_immutable_intent() {
        let directory = std::env::temp_dir().join(format!(
            "inkson-creator-race-{}",
            arkret_sdk::identifiers::uuid_v7_at(crate::clock::now_unix_ms())
        ));
        let path = directory.join("standard.json");
        let (left_intent, left_submission) = creator_fixture(CREATOR_DEVICE);
        let (right_intent, right_submission) =
            creator_fixture("ak:device:01904100-0000-7000-8000-000000000002");
        assert_eq!(
            left_intent.effective_scope(),
            right_intent.effective_scope()
        );
        let contenders = [
            (left_intent, left_submission),
            (right_intent, right_submission),
        ];
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let threads = contenders.clone().map(|(intent, submission)| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap()
                    .block_on(mutate_state_in_file(&path, None, |state| {
                        state.freeze_creator_intent(intent, submission)
                    }))
            })
        });
        let outcomes = threads.map(|thread| thread.join().unwrap());
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        let reopened = decode_snapshot(Some(&std::fs::read_to_string(&path).unwrap())).unwrap();
        assert_eq!(reopened.creator_bootstrap_records.len(), 1);
        assert_eq!(reopened.items.len(), 1);
        let winner = outcomes.iter().position(|result| result.is_ok()).unwrap();
        assert_eq!(
            *reopened.creator_bootstrap_records[0].intent(),
            contenders[winner].0
        );
        assert_eq!(reopened.items[0].request(), &contenders[winner].1.request);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn creator_intent_failure_never_publishes_half_a_create() {
        let (intent, submission) = creator_fixture(CREATOR_DEVICE);
        assert!(
            mutate_state_in_store(
                &RefusingStore,
                "inkson.outbound.v1::creator.standard",
                |state| state.freeze_creator_intent(intent.clone(), submission.clone())
            )
            .await
            .is_err()
        );
        let directory = std::env::temp_dir().join(format!(
            "inkson-creator-fault-{}",
            arkret_sdk::identifiers::uuid_v7_at(crate::clock::now_unix_ms())
        ));
        let path = directory.join("standard.json");
        mutate_queue_in_file(&path, |queue| {
            queue.enqueue(fixture_submission(0), crate::clock::now_utc())?;
            Ok(())
        })
        .await
        .unwrap();
        let committed = std::fs::read_to_string(&path).unwrap();
        std::fs::create_dir(path.with_extension("json.tmp")).unwrap();
        assert!(
            mutate_state_in_file(&path, None, |state| state
                .freeze_creator_intent(intent, submission))
            .await
            .is_err()
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), committed);
        let reopened = decode_snapshot(Some(&committed)).unwrap();
        assert!(reopened.creator_bootstrap_records.is_empty());
        assert_eq!(reopened.items.len(), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn creator_intent_rejects_substituted_queue_and_duplicate_key() {
        let (intent, submission) = creator_fixture(CREATOR_DEVICE);
        let mut snapshot = DurableOutboundState::default();
        assert!(
            snapshot
                .freeze_creator_intent(intent.clone(), fixture_submission(0))
                .is_err()
        );
        snapshot
            .freeze_creator_intent(intent.clone(), submission)
            .unwrap();
        snapshot
            .creator_bootstrap_records
            .push(MlsCreatorBootstrapRecord::new(intent).unwrap());
        assert!(encode_snapshot(&snapshot).is_err());
        snapshot.creator_bootstrap_records.pop();
        snapshot.items.clear();
        assert!(encode_snapshot(&snapshot).is_err());
    }

    #[cfg(not(target_arch = "wasm32"))]
    type StoreFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;
    #[cfg(target_arch = "wasm32")]
    type StoreFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + 'a>>;

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn independent_native_queue_handles_serialize_the_whole_durable_mutation() {
        use std::sync::mpsc;
        use std::time::Duration;

        let directory = std::env::temp_dir().join(format!(
            "inkson-outbound-lock-{}",
            arkret_sdk::identifiers::uuid_v7_at(crate::clock::now_unix_ms())
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("queue.json");
        let (first_entered, observe_first) = mpsc::channel();
        let (release_first, first_release) = mpsc::channel();
        let (second_started, observe_second_start) = mpsc::channel();
        let (second_entered, observe_second) = mpsc::channel();
        let first_path = path.clone();
        let first = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(mutate_queue_in_file(&first_path, |queue| {
                    first_entered.send(()).unwrap();
                    first_release.recv_timeout(Duration::from_secs(10)).unwrap();
                    queue.enqueue(fixture_submission(0), crate::clock::now_utc())?;
                    Ok(())
                }))
        });
        observe_first.recv_timeout(Duration::from_secs(10)).unwrap();
        let second_path = path.clone();
        let second = std::thread::spawn(move || {
            second_started.send(()).unwrap();
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(mutate_queue_in_file(&second_path, |queue| {
                    second_entered.send(()).unwrap();
                    queue.enqueue(fixture_submission(1), crate::clock::now_utc())?;
                    Ok(())
                }))
        });
        observe_second_start
            .recv_timeout(Duration::from_secs(10))
            .unwrap();
        let entered_before_first_commit = observe_second
            .recv_timeout(Duration::from_millis(500))
            .is_ok();
        release_first.send(()).unwrap();
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();
        let reloaded = decode_snapshot(Some(&std::fs::read_to_string(&path).unwrap())).unwrap();
        std::fs::remove_dir_all(&directory).unwrap();
        assert!(
            !entered_before_first_commit,
            "a second independent handle entered before the first durable commit"
        );
        assert_eq!(
            reloaded.items.len(),
            2,
            "both frozen Events survive reopening"
        );
    }

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
        let mut event = arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::MessageCreate>::new(
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
        .unwrap();
        event
            .sign_ed25519(
                "did:web:alice.example",
                "did:web:alice.example#key-1",
                &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            )
            .expect("fixture Event has a real producer proof");
        let event = event.into_event();
        garth::QueuedSubmission::new(arkret_wire::AuthoritySubmitRequest::Event(
            arkret_wire::EventAdmissionSubmission {
                event,
                approval_signatures: None,
            },
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

        fn read_secret_bytes_durable<'a>(
            &'a self,
            _key: &'a str,
        ) -> StoreFuture<'a, Result<Option<arkret_sdk::KeyBytes>, garth::SecureKeyStoreError>>
        {
            Box::pin(async { Ok(None) })
        }

        fn compare_exchange_secret_bytes_durable<'a>(
            &'a self,
            _key: &'a str,
            _expected: Option<&'a [u8]>,
            _replacement: &'a [u8],
        ) -> StoreFuture<'a, Result<bool, garth::SecureKeyStoreError>> {
            Box::pin(async {
                Err(garth::SecureKeyStoreError::Backend(
                    "entries store unavailable".into(),
                ))
            })
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
            enqueue_items(queue, 4608);
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
        assert_eq!(items, 4608);
        assert_ne!(
            first, last,
            "every queued item keeps its own Event identity"
        );
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
