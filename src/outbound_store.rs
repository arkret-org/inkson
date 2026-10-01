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
mod creator_quarantine;

use arkret_models_collaboration::mls_creator_bootstrap::{
    MlsCreatorBootstrapIntent, MlsCreatorBootstrapRecord, MlsCreatorBootstrapRejection,
    MlsCreatorBootstrapVerifiedAbsence,
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

fn committed_changes() -> &'static tokio::sync::watch::Sender<u64> {
    static CHANGES: std::sync::OnceLock<tokio::sync::watch::Sender<u64>> =
        std::sync::OnceLock::new();
    CHANGES.get_or_init(|| tokio::sync::watch::channel(0).0)
}

pub(crate) fn subscribe_committed_changes() -> tokio::sync::watch::Receiver<u64> {
    committed_changes().subscribe()
}

fn notify_committed_change() {
    committed_changes().send_modify(|revision| *revision = revision.wrapping_add(1));
}

type ScheduledDispatches =
    std::collections::BTreeMap<arkret_identifiers::ScheduledSendId, arkret_sdk::EventId>;

/// Holder-private dispatch identities share the queue's single durable write.
/// This adds no protocol wire field or second storage key.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableOutboundState {
    items: Vec<garth::SendQueueItem>,
    // Opaque diagnostics only; retired ingress records can never be replayed
    // or used as evidence of an authority commit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    retired_ingress_items: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retired_ingress_next_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retired_ingress_schema: Option<String>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    scheduled_dispatches: ScheduledDispatches,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    creator_bootstrap_records: Vec<MlsCreatorBootstrapRecord>,
    #[serde(default)]
    commit_position: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    creator_ready_index:
        Vec<arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapReadyReceipt>,
}

impl DurableOutboundState {
    fn settle_creator_rejections(
        &mut self,
        decision: &Option<(arkret_sdk::EventId, MlsCreatorBootstrapVerifiedAbsence)>,
    ) -> garth::Result<()> {
        for record in &mut self.creator_bootstrap_records {
            let Some(queued) = record.queued_genesis() else {
                continue;
            };
            let Some(item) = self
                .items
                .iter()
                .find(|item| item.event_id() == queued.signed_genesis().event_id())
            else {
                continue;
            };
            let terminal_problem = item.last_problem.as_deref().filter(|problem| {
                item.status == garth::SendQueueStatus::Failed
                    && MlsCreatorBootstrapRejection::terminal_problem_reason(problem).is_some()
            });
            let reason = match &item.submission.state {
                garth::SubmissionState::Rejected {
                    status: arkret_wire::AuthorityRejectionStatus::Rejected,
                    reason_code,
                } if item.status == garth::SendQueueStatus::Rejected => Some(reason_code),
                _ if terminal_problem.is_some() => None,
                _ => continue,
            };
            let Some((_, absence)) = decision.as_ref().filter(|(id, _)| id == item.event_id())
            else {
                return Err(garth::Error::Storage(
                    "creator rejection has no verified decision for this send attempt".into(),
                ));
            };
            let rejection = match terminal_problem {
                Some(problem) => MlsCreatorBootstrapRejection::from_problem(
                    record,
                    problem.clone(),
                    absence.clone(),
                )?,
                None => MlsCreatorBootstrapRejection::new(
                    record,
                    reason
                        .expect("typed authority rejection has its reason")
                        .clone(),
                    absence.clone(),
                )?,
            };
            record.reject(rejection)?;
        }
        Ok(())
    }

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
            if record.quarantine_diagnostic().is_some() {
                continue;
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
            if let Some(diagnostic) = record.quarantine_diagnostic() {
                for item in &self.items {
                    if creator_quarantine::belongs_to_attempt(
                        &serde_json::to_value(item)?,
                        record.intent(),
                        diagnostic.recovery_record(),
                    ) || diagnostic.related_recovery_records().iter().any(|raw| {
                        creator_quarantine::belongs_to_attempt(
                            &serde_json::to_value(item).expect("queue serialization"),
                            record.intent(),
                            raw,
                        )
                    }) {
                        if item.status.is_terminal() {
                            continue;
                        }
                        return Err(garth::Error::Storage(
                            "quarantined creator queue was reactivated".into(),
                        ));
                    }
                }
                continue;
            }
            if record.closed_attempts().iter().any(|closed| {
                self.items
                    .iter()
                    .any(|item| item.event_id() == closed.event_id())
            }) {
                return Err(garth::Error::Storage(
                    "closed creator attempt queue item was reintroduced".into(),
                ));
            }
            if let MlsCreatorBootstrapRecord::Rejected {
                rejection,
                rejected_record,
                ..
            } = record
            {
                let queued = rejected_record.queued_genesis().ok_or_else(|| {
                    garth::Error::Storage("rejected creator lost its signed diagnostic".into())
                })?;
                let expected = crate::event_submit::event_submission(queued.signed_genesis())
                    .map_err(|error| garth::Error::Storage(error.to_string()))?;
                let item = self
                    .items
                    .iter()
                    .find(|item| item.event_id() == rejection.event_id())
                    .ok_or_else(|| {
                        garth::Error::Storage("rejected creator lost its stopped queue item".into())
                    })?;
                if item.request() != &expected.request
                    || match rejection.authority_problem() {
                        Some(problem) => {
                            item.status != garth::SendQueueStatus::Failed
                                || item.last_problem.as_deref() != Some(problem)
                        }
                        None => {
                            item.status != garth::SendQueueStatus::Rejected
                                || item.rejection_reason_code() != Some(rejection.reason_code())
                        }
                    }
                    || item.settled_at.is_none()
                {
                    return Err(garth::Error::Storage(
                        "rejected creator disagrees with its original queue outcome".into(),
                    ));
                }
            }
            if let MlsCreatorBootstrapRecord::Superseded {
                loser_genesis: Some((id, _)),
                ..
            } = record
                && self.items.iter().any(|item| item.event_id() == id)
            {
                return Err(garth::Error::Storage(
                    "superseded creator loser queue item was reintroduced".into(),
                ));
            }
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
                if let Some(accepted) = record.accepted_genesis()
                    && (item.status != garth::SendQueueStatus::Committed
                        || item.commit() != Some(&accepted.accepted().commit)
                        || item.settled_at.is_none())
                {
                    return Err(garth::Error::Storage(
                        "accepted creator queue is not completed and retained".into(),
                    ));
                }
            }
        }
        for record in &self.creator_bootstrap_records {
            let entries: Vec<_> = self
                .creator_ready_index
                .iter()
                .filter(|receipt| receipt.effective_scope() == record.intent().effective_scope())
                .collect();
            match record.ready_receipt() {
                Some(receipt)
                    if entries.len() == 1
                        && entries[0] == receipt
                        && receipt.ready_commit_position() <= self.commit_position => {}
                None if entries.is_empty() => {}
                _ => {
                    return Err(garth::Error::Storage(
                        "creator ready record and send-gate index disagree".into(),
                    ));
                }
            }
        }
        if self.creator_ready_index.iter().any(|receipt| {
            !self
                .creator_bootstrap_records
                .iter()
                .any(|record| record.ready_receipt() == Some(receipt))
        }) {
            return Err(garth::Error::Storage(
                "orphan creator send-gate index".into(),
            ));
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
            if existing.quarantine_diagnostic().is_some() {
                return Err(garth::Error::Storage(
                    "quarantined creator cannot reopen its original authoring intent".into(),
                ));
            }
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
    mutate_authenticated_state_in_store(store, storage_key, None, mutation).await
}

async fn mutate_authenticated_state_in_store<R>(
    store: &dyn crate::secure_key_store::SecureKeyStore,
    storage_key: &str,
    authority: Option<&arkret_sdk::AccountId>,
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
    let (mut state, quarantined, retired) =
        creator_quarantine::decode_for_recovery(stored, authority)?;
    let before = encode_snapshot(&state)?;
    let result = if quarantined {
        Err(garth::Error::Storage(
            "creator inconsistency quarantined durably; requested queue mutation stopped".into(),
        ))
    } else {
        Ok(mutation(&mut state)?)
    };
    let changed =
        serde_json::to_string(&state).map_err(|error| garth::Error::Storage(error.to_string()))?;
    if !quarantined && !retired && changed == before {
        return result;
    }
    state.commit_position = state
        .commit_position
        .checked_add(1)
        .ok_or_else(|| garth::Error::Storage("outbound vault commit position exhausted".into()))?;
    let encoded = encode_snapshot(&state)?;
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
    notify_committed_change();
    result
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
    let (mut state, quarantined, retired) = creator_quarantine::decode_for_recovery(
        plaintext.as_deref(),
        protection.map(|(authority, _)| authority),
    )?;
    let before = encode_snapshot(&state)?;
    let result = if quarantined {
        Err(garth::Error::Storage(
            "creator inconsistency quarantined durably; requested queue mutation stopped".into(),
        ))
    } else {
        Ok(mutation(&mut state)?)
    };
    let changed =
        serde_json::to_string(&state).map_err(|error| garth::Error::Storage(error.to_string()))?;
    if !quarantined && !retired && changed == before {
        return result;
    }
    state.commit_position = state
        .commit_position
        .checked_add(1)
        .ok_or_else(|| garth::Error::Storage("outbound vault commit position exhausted".into()))?;
    let encoded = encode_snapshot(&state)?;
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
    #[cfg(unix)]
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                garth::Error::Storage(format!("sync outbound queue directory: {error}"))
            })?;
    }
    notify_committed_change();
    result
}

#[derive(Clone)]
pub(crate) struct InksonOutboundStore {
    creator_decision: std::sync::Arc<
        std::sync::Mutex<Option<(arkret_sdk::EventId, MlsCreatorBootstrapVerifiedAbsence)>>,
    >,
    #[cfg(not(target_arch = "wasm32"))]
    path: std::path::PathBuf,
    #[cfg(not(target_arch = "wasm32"))]
    protection: Option<(
        arkret_sdk::AccountId,
        std::sync::Arc<dyn crate::secure_key_store::SecureKeyStore + Send + Sync>,
    )>,
    #[cfg(target_arch = "wasm32")]
    authority: arkret_sdk::AccountId,
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
            creator_decision: Default::default(),
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
                creator_decision: Default::default(),
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
                creator_decision: Default::default(),
                authority: authority.clone(),
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
            mutate_authenticated_state_in_store(
                store.as_ref(),
                &self.storage_key,
                Some(&self.authority),
                mutation,
            )
            .await
        }
    }

    /// The verified gate decision is published with a terminal authority answer,
    /// never as a refreshed pin or an unregistered active-state amendment.
    pub(crate) fn remember_creator_absence(
        &self,
        decision: (arkret_sdk::EventId, MlsCreatorBootstrapVerifiedAbsence),
    ) -> garth::Result<()> {
        *self
            .creator_decision
            .lock()
            .map_err(|_| garth::Error::Storage("creator decision lock poisoned".into()))? =
            Some(decision);
        Ok(())
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

    /// Bind exact verified acceptance and stop its retained ledger atomically.
    pub(crate) async fn accept_creator_genesis(
        &self,
        expected: MlsCreatorBootstrapRecord,
        accepted: arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAcceptedGenesis,
    ) -> garth::Result<()> {
        let mut next = expected.clone();
        next.accept_genesis(accepted.clone())?;
        self.mutate_state(|state| {
            let record = state
                .creator_bootstrap_records
                .iter_mut()
                .find(|record| {
                    record.intent().effective_scope() == expected.intent().effective_scope()
                })
                .ok_or_else(|| {
                    garth::Error::Storage("creator acceptance lost its signed original".into())
                })?;
            if record != &next && record != &expected {
                return Err(garth::Error::Storage(
                    "creator acceptance changed in another holder".into(),
                ));
            }
            let item = state
                .items
                .iter_mut()
                .find(|item| item.event_id() == &accepted.accepted().event.event_id)
                .ok_or_else(|| {
                    garth::Error::Storage("creator acceptance lost its queue item".into())
                })?;
            if item
                .commit()
                .is_some_and(|commit| commit != &accepted.accepted().commit)
            {
                return Err(garth::Error::Storage(
                    "creator queue outcome disagrees with exact accepted Commit".into(),
                ));
            }
            item.submission.state = garth::SubmissionState::Committed {
                status: arkret_wire::AuthorityCommitStatus::Committed,
                commit: Box::new(accepted.accepted().commit.clone()),
            };
            item.status = garth::SendQueueStatus::Committed;
            item.settled_at = Some(accepted.accepted().commit.committed_at);
            item.last_error = None;
            *record = next;
            Ok(())
        })
        .await
    }

    /// Stop and remove the losing original in the same commit as its durable
    /// terminal diagnostics. The retained record cannot become write-ready.
    /// Preserve the original recovery unit before returning a private/accepted
    /// inconsistency to its caller. Every related queue and index stops in CAS.
    pub(crate) async fn quarantine_creator(
        &self,
        expected: MlsCreatorBootstrapRecord,
        invariant: arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapInvariant,
        detail: String,
        known: Option<
            arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapKnownGenesis,
        >,
    ) -> garth::Result<()> {
        self.mutate_state(|state| {
            let position = state
                .creator_bootstrap_records
                .iter()
                .position(|record| {
                    record.intent().effective_scope() == expected.intent().effective_scope()
                })
                .ok_or_else(|| {
                    garth::Error::Storage(
                        "creator quarantine lost the authenticated original".into(),
                    )
                })?;
            let record = &state.creator_bootstrap_records[position];
            if record.quarantine_diagnostic().is_some() {
                return Ok(());
            }
            if record != &expected {
                return Err(garth::Error::Storage(
                    "creator quarantine must reread the changed original".into(),
                ));
            }
            creator_quarantine::stop_creator(state, position, invariant, detail, known)
        })
        .await
    }

    pub(crate) async fn supersede_creator(
        &self,
        expected: MlsCreatorBootstrapRecord,
        winner: arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapWinner,
    ) -> garth::Result<()> {
        let mut next = expected.clone();
        next.supersede(winner)?;
        let loser = expected
            .queued_genesis()
            .map(|queued| queued.outbound_queue_item_id().clone())
            .or_else(|| {
                expected
                    .rejection()
                    .map(|rejection| rejection.event_id().clone())
            });
        self.mutate_state(|state| {
            let record = state
                .creator_bootstrap_records
                .iter_mut()
                .find(|record| {
                    record.intent().effective_scope() == expected.intent().effective_scope()
                })
                .ok_or_else(|| {
                    garth::Error::Storage("superseded creator lost its original record".into())
                })?;
            if record != &next && record != &expected {
                return Err(garth::Error::Storage(
                    "creator winner changed in another holder".into(),
                ));
            }
            if let Some(loser) = loser {
                state.items.retain(|item| item.event_id() != &loser);
            }
            *record = next;
            Ok(())
        })
        .await
    }

    pub(crate) async fn reopen_creator(
        &self,
        expected: MlsCreatorBootstrapRecord,
        absence: MlsCreatorBootstrapVerifiedAbsence,
    ) -> garth::Result<()> {
        let old_id = expected
            .rejection()
            .ok_or_else(|| {
                garth::Error::Storage("creator restart requires a rejected attempt".into())
            })?
            .event_id()
            .clone();
        let mut next = expected.clone();
        next.reopen_rejected(absence)?;
        self.mutate_state(|state| {
            let record = state
                .creator_bootstrap_records
                .iter_mut()
                .find(|record| {
                    record.intent().effective_scope() == expected.intent().effective_scope()
                })
                .ok_or_else(|| {
                    garth::Error::Storage("creator restart lost its terminal attempt".into())
                })?;
            if record != &expected && record != &next {
                return Err(garth::Error::Storage(
                    "creator restart changed in another holder".into(),
                ));
            }
            state.items.retain(|item| item.event_id() != &old_id);
            *record = next;
            Ok(())
        })
        .await
    }

    pub(crate) async fn ensure_creator_automatic_replay_allowed(
        &self,
        scope: &arkret_sdk::ScopeRef,
    ) -> garth::Result<()> {
        self.mutate_state(|state| {
            if state.creator_bootstrap_records.iter().any(|record| {
                record.intent().effective_scope() == scope
                    && record.quarantine_diagnostic().is_some()
            }) {
                return Err(garth::Error::Storage(
                    "creator recovery is quarantined; all automatic queue replay stops".into(),
                ));
            }
            Ok(())
        })
        .await
    }

    pub(crate) async fn check_creator_artifact_candidate(
        &self,
        event: &arkret_sdk::Event,
    ) -> garth::Result<()> {
        self.mutate_state(|state| {
            if let Some(record) = state
                .creator_bootstrap_records
                .iter()
                .find(|record| record.intent().effective_scope() == &event.scope_ref)
            {
                if record
                    .queued_genesis()
                    .is_none_or(|queued| queued.signed_genesis().event() != event)
                {
                    return Err(garth::Error::Storage(
                        "accepted artifact cannot adopt a losing creator private unit".into(),
                    ));
                }
            }
            Ok(())
        })
        .await
    }

    pub(crate) async fn converge_creator_artifacts(
        &self,
        expected: MlsCreatorBootstrapRecord,
        artifacts: arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapArtifacts,
    ) -> garth::Result<()> {
        let mut next = expected.clone();
        next.converge_artifacts(artifacts)?;
        self.replace_creator_record(expected, next).await
    }

    /// The record and the receipt consumed by every send gate share one CAS.
    pub(crate) async fn publish_creator_ready(
        &self,
        expected: MlsCreatorBootstrapRecord,
    ) -> garth::Result<()> {
        self.mutate_state(|state| {
            let record = state.creator_bootstrap_records.iter_mut().find(|record|
                record.intent().effective_scope() == expected.intent().effective_scope())
                .ok_or_else(|| garth::Error::Storage("creator ready publication lost its durable artifacts".into()))?;
            if record.ready_receipt().is_some() {
                if record != &expected { return Err(garth::Error::Storage("creator ready publication changed in another holder".into())); }
                return Ok(());
            }
            if record != &expected { return Err(garth::Error::Storage("creator artifacts changed before ready publication; reread".into())); }
            let position = state.commit_position.checked_add(1).ok_or_else(|| garth::Error::Storage("outbound vault commit position exhausted".into()))?;
            let receipt = arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapReadyReceipt::new(record, position)?;
            record.publish_ready(receipt.clone())?;
            state.creator_ready_index.push(receipt);
            Ok(())
        }).await
    }

    /// This reads the committed vault, validating record, artifact and index
    /// together. A cached emitted flag has no authority to open this slot.
    pub(crate) async fn check_creator_ready_slot(
        &self,
        scope: &arkret_sdk::ScopeRef,
        genesis: &arkret_sdk::EventId,
    ) -> garth::Result<Option<MlsCreatorBootstrapRecord>> {
        self.mutate_state(|state| {
            if let Some(record) = state
                .creator_bootstrap_records
                .iter()
                .find(|record| record.intent().effective_scope() == scope)
            {
                if let Some(winner) = record.superseded_winner() {
                    if &winner.accepted().event.event_id != genesis {
                        return Err(garth::Error::Storage(
                            "superseded creator names another winning Genesis".into(),
                        ));
                    }
                    return Ok(Some(record.clone()));
                }
                let receipt = record.ready_receipt().ok_or_else(|| {
                    garth::Error::Storage(
                        "creator artifacts and ready index are not durably published".into(),
                    )
                })?;
                if receipt.accepted_genesis_event_id() != genesis {
                    return Err(garth::Error::Storage(
                        "creator private artifact belongs to another accepted Genesis".into(),
                    ));
                }
                return Ok(Some(record.clone()));
            }
            Ok(None)
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
        self.mutate_state(|state| {
            let mut queue = garth::SendQueue::from_snapshot(garth::SendQueueSnapshot {
                items: std::mem::take(&mut state.items),
            });
            let result = mutation(&mut queue, &mut state.scheduled_dispatches)?;
            state.items = queue.snapshot().items;
            Ok(result)
        })
        .await
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
        Box::pin(async move {
            let decision = self
                .creator_decision
                .lock()
                .map_err(|_| garth::Error::Storage("creator decision lock poisoned".into()))?
                .clone();
            self.mutate_state(|state| {
                let mut queue = garth::SendQueue::from_snapshot(garth::SendQueueSnapshot {
                    items: std::mem::take(&mut state.items),
                });
                let result = mutation(&mut queue)?;
                state.items = queue.snapshot().items;
                state.settle_creator_rejections(&decision)?;
                Ok(result)
            })
            .await
        })
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

    async fn creator_rejection_fault_cut(
        directory: &std::path::Path,
        path: &std::path::Path,
        winner: &MlsCreatorBootstrapRecord,
        queued: &garth::QueuedSubmission,
    ) {
        let intent = winner.intent().clone();
        let create = winner.governance_evidence().unwrap().accepted_create();
        // Structural authority decision only: this branch verifies the
        // durable queue/diagnostic cut, not Station authentication.
        let rejected_path = directory.join("rejected.json");
        std::fs::copy(path, &rejected_path).unwrap();
        let rejected_vault = InksonOutboundStore::for_test_path(rejected_path.clone());
        let snapshot = match &winner {
            MlsCreatorBootstrapRecord::GenesisQueued {
                genesis_absence, ..
            } => (**genesis_absence).clone(),
            _ => panic!("expected queued creator"),
        };
        let absence =
            MlsCreatorBootstrapVerifiedAbsence::new(&intent, create.clone(), snapshot.clone())
                .unwrap();
        let reject_item = |queue: &mut garth::SendQueue| {
            let mut next = queue.snapshot();
            let item = next
                .items
                .iter_mut()
                .find(|item| item.event_id() == &queued.event_id)
                .unwrap();
            item.status = garth::SendQueueStatus::Failed;
            item.last_problem = Some(Box::new(arkret_wire::Problem::new(
                "capability_denied",
                403,
                "structural admission refusal",
            )));

            item.settled_at = Some(crate::clock::now_utc());
            *queue = garth::SendQueue::from_snapshot(next);
            Ok(())
        };
        let before = std::fs::read(&rejected_path).unwrap();
        assert!(rejected_vault.mutate_outbound(reject_item).await.is_err());
        assert_eq!(std::fs::read(&rejected_path).unwrap(), before);
        rejected_vault
            .remember_creator_absence((queued.event_id.clone(), absence))
            .unwrap();
        std::fs::create_dir(rejected_path.with_extension("json.tmp")).unwrap();
        assert!(rejected_vault.mutate_outbound(reject_item).await.is_err());
        assert_eq!(std::fs::read(&rejected_path).unwrap(), before);
        std::fs::remove_dir(rejected_path.with_extension("json.tmp")).unwrap();
        rejected_vault.mutate_outbound(reject_item).await.unwrap();
        let stopped = rejected_vault
            .creator_record(intent.owner_actor_id(), intent.effective_scope())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stopped.state(),
            arkret_wire::MlsCreatorBootstrapState::Rejected
        );
        assert_eq!(
            stopped.rejection().unwrap().reason_code(),
            "capability_denied"
        );
        let reopened = InksonOutboundStore::for_test_path(rejected_path.clone());
        assert_eq!(
            reopened
                .creator_record(intent.owner_actor_id(), intent.effective_scope())
                .await
                .unwrap(),
            Some(stopped.clone())
        );
        let mut root = create.authority_root().clone();
        root.current_assertion.nonce =
            arkret_wire::Base64UrlString::new("BBBBBBBBBBBBBBBBBBBBBB").unwrap();
        let fresh_create = arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAcceptedCreate::new(
            &intent, create.accepted_event().clone(), create.covering_commit().clone(), create.digest_suite(), root,
        ).unwrap();
        let fresh =
            MlsCreatorBootstrapVerifiedAbsence::new(&intent, fresh_create, snapshot).unwrap();
        let before = std::fs::read(&rejected_path).unwrap();
        std::fs::create_dir(rejected_path.with_extension("json.tmp")).unwrap();
        assert!(
            reopened
                .reopen_creator(stopped.clone(), fresh.clone())
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&rejected_path).unwrap(), before);
        std::fs::remove_dir(rejected_path.with_extension("json.tmp")).unwrap();
        reopened
            .reopen_creator(stopped.clone(), fresh.clone())
            .await
            .unwrap();
        let next = reopened
            .creator_record(intent.owner_actor_id(), intent.effective_scope())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            next.state(),
            arkret_wire::MlsCreatorBootstrapState::RealmAccepted
        );
        assert_eq!(next.intent(), &intent);
        assert_eq!(next.closed_attempts().len(), 1);
        assert_eq!(next.closed_attempts()[0].event_id(), &queued.event_id);
        assert!(next.epoch_zero().is_none());
        assert!(next.queued_genesis().is_none());
        let unit = winner.epoch_zero().unwrap();
        let mut old_cache: crate::mls::persistence::MlsLocalCheckpointEnvelope =
            serde_json::from_slice(unit.encrypted_private_state()).unwrap();
        let matches_cache = |cache: &crate::mls::persistence::MlsLocalCheckpointEnvelope,
                             emitted: bool,
                             public: &[u8]| {
            crate::event_submit::creator_cache_belongs_to_closed_attempt(
                &next,
                cache,
                emitted,
                public,
                unit.ratchet_tree_bytes(),
            )
            .unwrap()
        };
        assert!(matches_cache(&old_cache, false, unit.group_info_bytes()));
        assert!(!matches_cache(&old_cache, true, unit.group_info_bytes()));
        assert!(!matches_cache(
            &old_cache,
            false,
            b"unrelated public material"
        ));
        old_cache.epoch = 1;
        assert!(!matches_cache(&old_cache, false, unit.group_info_bytes()));
        old_cache.epoch = 0;
        old_cache.group_state_event_id = Some(queued.event_id.clone());
        assert!(!matches_cache(&old_cache, false, unit.group_info_bytes()));

        let state =
            decode_snapshot(Some(&std::fs::read_to_string(&rejected_path).unwrap())).unwrap();
        assert!(
            !state
                .items
                .iter()
                .any(|item| item.event_id() == &queued.event_id)
        );
        let before = std::fs::read(&rejected_path).unwrap();
        reopened.reopen_creator(stopped, fresh).await.unwrap();
        assert_eq!(std::fs::read(&rejected_path).unwrap(), before);
    }

    async fn creator_quarantine_fault_cuts(
        directory: &std::path::Path,
        source: &std::path::Path,
        ready: &MlsCreatorBootstrapRecord,
        queued: &garth::QueuedSubmission,
        secrets: &dyn crate::secure_key_store::SecureKeyStore,
    ) {
        use arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapInvariant;
        let original: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(source).unwrap()).unwrap();
        for cut in ["record", "queue", "index", "duplicate"] {
            let path = directory.join(format!("quarantine-{cut}.json"));
            let mut damaged = original.clone();
            match cut {
                "record" => {
                    damaged["creator_bootstrap_records"][0]["epoch_zero"]["encrypted_private_state"] =
                        serde_json::json!({"damaged": true})
                }
                "queue" => {
                    let items = damaged["items"].as_array_mut().unwrap();
                    let genesis = items
                        .iter_mut()
                        .find(|item| {
                            item["submission"]["event_id"]
                                == serde_json::to_value(&queued.event_id).unwrap()
                        })
                        .unwrap();
                    genesis["submission"]["request"]["event"]["created_at"] =
                        serde_json::json!("2026-01-01T00:00:00.000Z");
                }
                "index" => damaged["creator_ready_index"] = serde_json::json!([]),
                _ => damaged["creator_bootstrap_records"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::to_value(ready).unwrap()),
            }
            std::fs::write(&path, serde_json::to_vec(&damaged).unwrap()).unwrap();
            let raw = std::fs::read(&path).unwrap();
            let vault = InksonOutboundStore::for_test_path(path.clone());
            std::fs::create_dir(path.with_extension("json.tmp")).unwrap();
            let error = vault
                .creator_record(
                    ready.intent().owner_actor_id(),
                    ready.intent().effective_scope(),
                )
                .await
                .unwrap_err();
            assert!(!error.to_string().contains("quarantined durably"));
            assert_eq!(std::fs::read(&path).unwrap(), raw, "{cut}");
            std::fs::remove_dir(path.with_extension("json.tmp")).unwrap();
            assert!(
                vault
                    .creator_record(
                        ready.intent().owner_actor_id(),
                        ready.intent().effective_scope()
                    )
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("quarantined durably")
            );
            let reopened = InksonOutboundStore::for_test_path(path.clone());
            let stopped = reopened
                .creator_record(
                    ready.intent().owner_actor_id(),
                    ready.intent().effective_scope(),
                )
                .await
                .unwrap()
                .unwrap();
            let diagnostic = stopped.quarantine_diagnostic().unwrap();
            assert_eq!(
                diagnostic.last_state(),
                arkret_wire::MlsCreatorBootstrapState::Ready
            );
            assert_eq!(diagnostic.event_id(), Some(&queued.event_id));
            assert_eq!(
                diagnostic.recovery_record(),
                &damaged["creator_bootstrap_records"][0]
            );
            assert_eq!(
                diagnostic.related_recovery_records().len(),
                usize::from(cut == "duplicate")
            );
            assert!(
                diagnostic
                    .recovery_queue_items()
                    .iter()
                    .any(|item| item["submission"]["event_id"]
                        == serde_json::to_value(&queued.event_id).unwrap())
            );
            let state = decode_snapshot(Some(&std::fs::read_to_string(&path).unwrap())).unwrap();
            assert!(state.creator_ready_index.is_empty());
            assert!(state.items.iter().all(|item| item.status.is_terminal()));
            let frozen = std::fs::read(&path).unwrap();
            assert!(
                reopened
                    .ensure_creator_automatic_replay_allowed(ready.intent().effective_scope())
                    .await
                    .is_err()
            );
            let mut control = serde_json::to_value(&state.items[0]).unwrap();
            control["submission"]["event_id"] = serde_json::to_value(
                arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [99; 32]),
            )
            .unwrap();
            control["submission"]["request"] = serde_json::json!({"commit_event": {
                "scope_ref": ready.intent().effective_scope(), "actor_id": ready.intent().owner_actor_id()
            }});
            assert!(creator_quarantine::belongs_to_attempt(
                &control,
                ready.intent(),
                diagnostic.recovery_record()
            ));
            control["submission"]["request"] = serde_json::json!({"events": [{"event": {
                "scope_ref": ready.intent().effective_scope(), "actor_id": ready.intent().owner_actor_id()
            }}]});
            assert!(creator_quarantine::belongs_to_attempt(
                &control,
                ready.intent(),
                diagnostic.recovery_record()
            ));
            control["submission"]["request"]["events"][0]["event"]["actor_id"] =
                serde_json::json!(null);
            assert!(!creator_quarantine::belongs_to_attempt(
                &control,
                ready.intent(),
                diagnostic.recovery_record()
            ));
            assert!(
                reopened
                    .check_creator_ready_slot(ready.intent().effective_scope(), &queued.event_id)
                    .await
                    .is_err()
            );
            assert!(
                reopened
                    .freeze_creator_intent(
                        ready.intent().clone(),
                        state
                            .items
                            .iter()
                            .find(|item| item.event_id() == ready.intent().scope_create_event_id())
                            .unwrap()
                            .submission
                            .clone()
                    )
                    .await
                    .is_err()
            );
            assert!(reopened.publish_creator_ready(ready.clone()).await.is_err());
            assert!(
                reopened
                    .mutate_outbound(|queue| {
                        queue.enqueue(queued.clone(), crate::clock::now_utc())?;
                        Ok(())
                    })
                    .await
                    .is_err()
            );
            reopened
                .quarantine_creator(
                    stopped.clone(),
                    MlsCreatorBootstrapInvariant::SignedBytes,
                    "replacement diagnostic forbidden".into(),
                    None,
                )
                .await
                .unwrap();
            assert_eq!(
                std::fs::read(&path).unwrap(),
                frozen,
                "terminal diagnostic was amended at {cut}"
            );
            assert_eq!(
                reopened
                    .creator_record(
                        ready.intent().owner_actor_id(),
                        ready.intent().effective_scope()
                    )
                    .await
                    .unwrap(),
                Some(stopped)
            );
        }
        for private_cut in ["ciphertext", "state_record"] {
            let path = directory.join(format!("quarantine-actual-private-{private_cut}.json"));
            let mut damaged = original.clone();
            let raw = &mut damaged["creator_bootstrap_records"][0];
            let original_private: Vec<u8> =
                serde_json::from_value(raw["epoch_zero"]["encrypted_private_state"].clone())
                    .unwrap();
            let mut envelope: crate::mls::persistence::MlsLocalCheckpointEnvelope =
                serde_json::from_slice(&original_private).unwrap();
            let authority = ready.intent().owner_actor_id().as_account_id().unwrap();
            let secret =
                crate::event_submit::original_creator_checkpoint_secret(&ready, secrets, authority)
                    .unwrap();
            if private_cut == "ciphertext" {
                let first = if envelope.ciphertext_hex.starts_with('0') {
                    "1"
                } else {
                    "0"
                };
                envelope.ciphertext_hex.replace_range(..1, first);
                assert!(crate::mls::persistence::decrypt_envelope(&envelope, &secret).is_err());
            } else {
                envelope = crate::mls::persistence::encrypt_state(
                    &envelope.realm_id,
                    &envelope.group_id,
                    0,
                    b"invalid MLS private state",
                    &secret,
                    &[19; 32],
                );
                assert!(crate::mls::persistence::decrypt_envelope(&envelope, &secret).is_ok());
                assert!(crate::mls::persistence::restore_envelope(&envelope, &secret, 0).is_err());
            }
            let private = serde_json::to_vec(&envelope).unwrap();
            raw["epoch_zero"]["encrypted_private_state"] = serde_json::to_value(&private).unwrap();
            raw["artifacts"]["private_state_binding"] = serde_json::to_value(
                arkret_wire::Hash::new(arkret_sdk::canonical::digest(
                    ready
                        .queued_genesis()
                        .unwrap()
                        .signed_genesis()
                        .digest_suite(),
                    &private,
                ))
                .unwrap(),
            )
            .unwrap();
            let retained: MlsCreatorBootstrapRecord = serde_json::from_value(raw.clone()).unwrap();
            retained.validate().unwrap();
            std::fs::write(&path, serde_json::to_vec(&damaged).unwrap()).unwrap();
            let before = std::fs::read(&path).unwrap();
            let vault = InksonOutboundStore::for_test_path(path.clone());
            let http =
                arkret_sdk::http_client::Client::builder("http://127.0.0.1:9/".parse().unwrap())
                    .allow_insecure_localhost()
                    .build()
                    .unwrap();
            let submitter = crate::event_submit::EventSubmitter::new(http).with_authority(
                ready
                    .intent()
                    .owner_actor_id()
                    .as_account_id()
                    .unwrap()
                    .clone(),
            );
            let missing = crate::secure_key_store::MemorySecureKeyStore::new();
            assert!(
                submitter
                    .restore_creator_artifacts_or_quarantine(&vault, &retained, &missing)
                    .await
                    .is_err()
            );
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert!(
                vault
                    .creator_record(
                        ready.intent().owner_actor_id(),
                        ready.intent().effective_scope()
                    )
                    .await
                    .unwrap()
                    .unwrap()
                    .quarantine_diagnostic()
                    .is_none()
            );
            std::fs::create_dir(path.with_extension("json.tmp")).unwrap();
            assert!(
                submitter
                    .restore_creator_artifacts_or_quarantine(&vault, &retained, secrets)
                    .await
                    .is_err()
            );
            assert_eq!(std::fs::read(&path).unwrap(), before);
            std::fs::remove_dir(path.with_extension("json.tmp")).unwrap();
            assert!(
                submitter
                    .restore_creator_artifacts_or_quarantine(&vault, &retained, secrets)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("quarantined")
            );
            let stopped = vault
                .creator_record(
                    ready.intent().owner_actor_id(),
                    ready.intent().effective_scope(),
                )
                .await
                .unwrap()
                .unwrap();
            let diagnostic = stopped.quarantine_diagnostic().unwrap();
            assert_eq!(
                diagnostic.invariant(),
                MlsCreatorBootstrapInvariant::PrivateMaterial
            );
            assert_eq!(
                diagnostic.recovery_record(),
                &damaged["creator_bootstrap_records"][0]
            );
            assert!(diagnostic.accepted_winner().is_some());
            let frozen = std::fs::read(&path).unwrap();
            assert!(
                submitter
                    .restore_creator_artifacts_or_quarantine(&vault, &stopped, secrets)
                    .await
                    .is_err()
            );
            assert_eq!(std::fs::read(&path).unwrap(), frozen);
        }
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
                        "device_signing_key_did": format!("did:key:{}", arkret_sdk::ed25519_pubkey_to_did_key_multibase(ed25519_dalek::SigningKey::from_bytes(&[11; 32]).verifying_key().as_bytes())),
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
            Some(winner.clone())
        );
        let create = winner.governance_evidence().unwrap().accepted_create();
        // Structural acceptance fixture. Live authentication belongs to the
        // exact verified query, not this durable adapter fault test.
        let mut commit = create.covering_commit().clone();
        commit.stream_position += 1;
        commit.previous_commit_ref = Some(create.covering_commit().commit_id.clone());
        commit.event_ref = queued.event_id.clone();
        let accepted = arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapAcceptedGenesis::new(
            &intent, winner.queued_genesis().unwrap(),
            arkret_wire::CommittedEventFullView { commit: commit.clone(), event: winner.queued_genesis().unwrap().signed_genesis().event().clone() },
            create.authority_root().clone()).unwrap();
        crate::event_submit::verify_creator_genesis_producer(&winner, &accepted).unwrap();
        Box::pin(creator_rejection_fault_cut(
            directory.path(),
            &path,
            &winner,
            &queued,
        ))
        .await;
        {
            let rival_path = directory.path().join("rival.json");
            std::fs::copy(&path, &rival_path).unwrap();
            let rival_vault = InksonOutboundStore::for_test_path(rival_path.clone());
            let evidence = winner.governance_evidence().unwrap();
            let (rival_private, rival_summary) = crate::mls::runtime::generate_creator_epoch_zero(
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
            let mut rival_event =
                crate::mls::runtime::freeze_creator_genesis_core(&intent, evidence, &rival_summary)
                    .unwrap();
            signer
                .sign_envelope_with_context(
                    &mut rival_event,
                    crate::event_signer::ProducerProofContext::new()
                        .with_digest_suite(arkret_sdk::DigestSuite::Sha256),
                )
                .unwrap();
            assert_ne!(rival_event.event_id(), &queued.event_id);
            let mut rival_commit = commit.clone();
            rival_commit.event_ref = rival_event.event_id().clone();
            // Shape-only Commit; authority authentication is the query's job.
            let rival_winner =
                arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapWinner::new(
                    &winner,
                    arkret_wire::CommittedEventFullView {
                        event: rival_event.event().clone(),
                        commit: rival_commit,
                    },
                    create.authority_root().clone(),
                )
                .unwrap();
            let before = std::fs::read(&rival_path).unwrap();
            std::fs::create_dir(rival_path.with_extension("json.tmp")).unwrap();
            assert!(
                rival_vault
                    .supersede_creator(winner.clone(), rival_winner.clone())
                    .await
                    .is_err()
            );
            assert_eq!(std::fs::read(&rival_path).unwrap(), before);
            assert_eq!(
                rival_vault
                    .creator_record(intent.owner_actor_id(), intent.effective_scope())
                    .await
                    .unwrap(),
                Some(winner.clone())
            );
            std::fs::remove_dir(rival_path.with_extension("json.tmp")).unwrap();
            rival_vault
                .supersede_creator(winner.clone(), rival_winner.clone())
                .await
                .unwrap();
            let terminal = rival_vault
                .creator_record(intent.owner_actor_id(), intent.effective_scope())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                terminal.state(),
                arkret_wire::MlsCreatorBootstrapState::Superseded
            );
            assert_eq!(terminal.superseded_winner(), Some(&rival_winner));
            let state =
                decode_snapshot(Some(&std::fs::read_to_string(&rival_path).unwrap())).unwrap();
            assert_eq!(state.items.len(), 1);
            assert!(
                !state
                    .items
                    .iter()
                    .any(|item| item.event_id() == &queued.event_id)
            );
            assert!(state.creator_ready_index.is_empty());
            let before = std::fs::read(&rival_path).unwrap();
            rival_vault
                .supersede_creator(winner.clone(), rival_winner)
                .await
                .unwrap();
            assert_eq!(std::fs::read(&rival_path).unwrap(), before);
            assert!(
                rival_vault
                    .queue_creator_genesis(
                        winner.clone(),
                        winner.queued_genesis().unwrap().signed_genesis().clone()
                    )
                    .await
                    .is_err()
            );
            assert!(
                rival_vault
                    .check_creator_artifact_candidate(rival_event.event())
                    .await
                    .is_err()
            );
            assert!(
                rival_vault
                    .check_creator_artifact_candidate(
                        winner.queued_genesis().unwrap().signed_genesis().event()
                    )
                    .await
                    .is_err()
            );
            assert!(
                rival_vault
                    .mutate_outbound(|queue| queue.enqueue(queued.clone(), chrono::Utc::now()))
                    .await
                    .is_err()
            );
            assert_eq!(std::fs::read(&rival_path).unwrap(), before);
            let current = arkret_wire::MlsGroupCurrent {
                effective_scope: intent.effective_scope().clone(),
                genesis_event_ref: rival_event.event_id().clone(),
                current_mls_commit_event_ref: rival_event.event_id().clone(),
                epoch: 0,
                current_key_access_revision: 0,
                covered_key_access_revision: 0,
                public_tree_ref: arkret_sdk::BlobRef::new(format!(
                    "ak:blob:{}",
                    arkret_sdk::canonical::digest(
                        arkret_sdk::DigestSuite::Sha256,
                        &rival_summary.ratchet_tree_bytes
                    )
                ))
                .unwrap(),
            };
            let losing_group =
                crate::mls::persistence::restore_envelope(&private, &device_secret, 0).unwrap();
            assert!(
                crate::mls::send_gate::validate_superseded_private_group(
                    &terminal,
                    &losing_group,
                    &current
                )
                .is_err()
            );
            // Independently acquired winning private material can recover the
            // scope; it never changes the losing transaction to ready.
            let recovered_group =
                crate::mls::persistence::restore_envelope(&rival_private, &device_secret, 0)
                    .unwrap();
            crate::mls::send_gate::validate_superseded_private_group(
                &terminal,
                &recovered_group,
                &current,
            )
            .unwrap();
            assert_eq!(
                rival_vault
                    .check_creator_ready_slot(intent.effective_scope(), &current.genesis_event_ref)
                    .await
                    .unwrap(),
                Some(terminal)
            );
        }

        let before = std::fs::read(&path).unwrap();
        std::fs::create_dir(path.with_extension("json.tmp")).unwrap();
        assert!(
            store
                .accept_creator_genesis(winner.clone(), accepted.clone())
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            reopened
                .creator_record(intent.owner_actor_id(), intent.effective_scope())
                .await
                .unwrap(),
            Some(winner.clone())
        );
        std::fs::remove_dir(path.with_extension("json.tmp")).unwrap();
        store
            .accept_creator_genesis(winner.clone(), accepted.clone())
            .await
            .unwrap();
        reopened
            .accept_creator_genesis(winner, accepted)
            .await
            .unwrap();
        let final_state = decode_snapshot(Some(&std::fs::read_to_string(&path).unwrap())).unwrap();
        assert_eq!(
            final_state.creator_bootstrap_records[0].state(),
            arkret_wire::MlsCreatorBootstrapState::GenesisAccepted
        );
        assert_eq!(final_state.items.len(), 2);
        let item = final_state
            .items
            .iter()
            .find(|item| item.event_id() == &queued.event_id)
            .unwrap();
        assert_eq!(item.status, garth::SendQueueStatus::Committed);
        assert_eq!(item.commit(), Some(&commit));
        assert!(item.settled_at.is_some());
        // Generic queue compaction cannot delete a retained acceptance item.
        assert!(
            store
                .mutate_outbound(|queue| Ok(
                    queue.compact_terminal_before(chrono::Utc::now() + chrono::TimeDelta::days(1))
                ))
                .await
                .is_err()
        );
        assert_eq!(
            reopened
                .creator_record(intent.owner_actor_id(), intent.effective_scope())
                .await
                .unwrap()
                .unwrap(),
            final_state.creator_bootstrap_records[0]
        );
        let accepted_record = final_state.creator_bootstrap_records[0].clone();
        let artifacts = crate::event_submit::restored_creator_artifacts(
            &accepted_record,
            &private_store,
            authority,
        )
        .unwrap();
        assert!(
            store
                .check_creator_ready_slot(intent.effective_scope(), &queued.event_id)
                .await
                .is_err()
        );
        for ready_cut in [false, true] {
            let before_record = reopened
                .creator_record(intent.owner_actor_id(), intent.effective_scope())
                .await
                .unwrap()
                .unwrap();
            let before = std::fs::read(&path).unwrap();
            std::fs::create_dir(path.with_extension("json.tmp")).unwrap();
            let failed = if ready_cut {
                store.publish_creator_ready(before_record.clone()).await
            } else {
                store
                    .converge_creator_artifacts(before_record.clone(), artifacts.clone())
                    .await
            };
            assert!(failed.is_err());
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert_eq!(
                reopened
                    .creator_record(intent.owner_actor_id(), intent.effective_scope())
                    .await
                    .unwrap(),
                Some(before_record.clone())
            );
            assert!(
                reopened
                    .check_creator_ready_slot(intent.effective_scope(), &queued.event_id)
                    .await
                    .is_err()
            );
            std::fs::remove_dir(path.with_extension("json.tmp")).unwrap();
            if ready_cut {
                reopened.publish_creator_ready(before_record).await.unwrap();
            } else {
                reopened
                    .converge_creator_artifacts(before_record, artifacts.clone())
                    .await
                    .unwrap();
            }
        }
        let ready = reopened
            .creator_record(intent.owner_actor_id(), intent.effective_scope())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ready.state(), arkret_wire::MlsCreatorBootstrapState::Ready);
        assert_eq!(ready.epoch_zero(), accepted_record.epoch_zero());
        assert_eq!(ready.accepted_genesis(), accepted_record.accepted_genesis());
        assert_eq!(ready.artifacts(), Some(&artifacts));
        let before = std::fs::read(&path).unwrap();
        reopened.publish_creator_ready(ready.clone()).await.unwrap();
        reopened
            .check_creator_ready_slot(intent.effective_scope(), &queued.event_id)
            .await
            .unwrap();
        assert!(
            reopened
                .check_creator_ready_slot(intent.effective_scope(), intent.scope_create_event_id())
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let mut state = decode_snapshot(Some(&std::fs::read_to_string(&path).unwrap())).unwrap();
        assert_eq!(
            state.creator_ready_index,
            vec![ready.ready_receipt().unwrap().clone()]
        );
        assert_eq!(
            state.commit_position,
            ready.ready_receipt().unwrap().ready_commit_position()
        );
        Box::pin(creator_quarantine_fault_cuts(
            directory.path(),
            &path,
            &ready,
            &queued,
            &private_store,
        ))
        .await;
        state.creator_ready_index.clear();
        assert!(encode_snapshot(&state).is_err());
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
            creator_decision: Default::default(),
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
            Some(frozen.clone())
        );
        let (accepted, snapshot) = creator_acceptance(&intent);
        store
            .accept_creator_realm(frozen, accepted, snapshot)
            .await
            .unwrap();
        let protected = std::fs::read_to_string(&path).unwrap();
        let opened =
            creator_protection::open_records(&protected, authority, secrets.as_ref()).unwrap();
        let mut typed_damage: serde_json::Value = serde_json::from_str(&opened).unwrap();
        typed_damage["creator_bootstrap_records"][0]["genesis_absence"]["visible_stream_heads"] =
            serde_json::json!([]);
        let encoded_damage = creator_protection::protect_records(
            &serde_json::to_string(&typed_damage).unwrap(),
            authority,
            secrets.as_ref(),
        )
        .unwrap();
        std::fs::write(&path, &encoded_damage).unwrap();
        std::fs::create_dir(path.with_extension("json.tmp")).unwrap();
        assert!(
            store
                .creator_record(intent.owner_actor_id(), intent.effective_scope())
                .await
                .is_err()
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), encoded_damage);
        std::fs::remove_dir(path.with_extension("json.tmp")).unwrap();
        assert!(
            store
                .creator_record(intent.owner_actor_id(), intent.effective_scope())
                .await
                .is_err()
        );
        let quarantined = store
            .creator_record(intent.owner_actor_id(), intent.effective_scope())
            .await
            .unwrap()
            .unwrap();
        assert!(quarantined.quarantine_diagnostic().is_some());
        assert_eq!(
            quarantined
                .quarantine_diagnostic()
                .unwrap()
                .recovery_record(),
            &typed_damage["creator_bootstrap_records"][0]
        );
        let ciphertext = std::fs::read_to_string(&path).unwrap();
        assert!(!ciphertext.contains("genesis_absence"));
        crate::secure_key_store::store_signing_seed(secrets.as_ref(), &[14; 32]).unwrap();
        assert!(
            store
                .creator_record(intent.owner_actor_id(), intent.effective_scope())
                .await
                .is_err()
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), ciphertext);
        crate::secure_key_store::store_signing_seed(secrets.as_ref(), &[13; 32]).unwrap();
        // Old development plaintext is rejected rather than silently adopted.
        let plaintext =
            creator_protection::open_records(&ciphertext, authority, secrets.as_ref()).unwrap();
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

    fn retired_ingress_fixture() -> serde_json::Value {
        // Opaque removed wire material: it must never become a current submission.
        serde_json::json!({
            "transaction_id": "old-operation",
            "record": {"kind": "event", "payload": {"old": true}},
            "canonical_payload_bytes": [123, 125],
            "status": "sent"
        })
    }

    #[tokio::test]
    async fn retired_ingress_queue_is_preserved_and_new_work_survives_reopen() {
        let store = garth::MemorySecureKeyStore::default();
        let key = "inkson.outbound.v1::nsA.standard";
        let retired = retired_ingress_fixture();
        let raw = serde_json::json!({"schema": "org.arkret.garth.send_queue.v1", "items": [retired.clone()], "next_sequence": 17}).to_string();
        store.store_secret(key, &raw).unwrap();

        // A read-only snapshot must durably retire the incompatible entry too.
        assert_eq!(
            mutate_queue_in_store(&store, key, |q| Ok(q.items().len()))
                .await
                .unwrap(),
            0
        );
        let first = store.get_secret(key).unwrap().unwrap();
        let state = decode_snapshot(Some(&first)).unwrap();
        assert_eq!(state.retired_ingress_items, vec![retired.clone()]);
        assert_eq!(state.retired_ingress_next_sequence, Some(17));
        assert_eq!(
            state.retired_ingress_schema.as_deref(),
            Some("org.arkret.garth.send_queue.v1")
        );
        assert!(
            serde_json::from_str::<serde_json::Value>(&first)
                .unwrap()
                .get("next_sequence")
                .is_none()
        );
        assert_eq!(state.commit_position, 1);

        mutate_queue_in_store(&store, key, |queue| {
            queue.enqueue(fixture_submission(0), crate::clock::now_utc())?;
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(
            mutate_queue_in_store(&store, key, |q| Ok(q.items().len()))
                .await
                .unwrap(),
            1
        );
        let reopened = store.get_secret(key).unwrap().unwrap();
        let state = decode_snapshot(Some(&reopened)).unwrap();
        assert_eq!(state.retired_ingress_items, vec![retired]);
        assert_eq!(state.retired_ingress_next_sequence, Some(17));
        assert_eq!(state.items[0].status, garth::SendQueueStatus::Queued);
        assert!(state.items[0].commit().is_none());
    }

    #[tokio::test]
    async fn retired_ingress_cleanup_is_durable_in_native_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("standard.json");
        let retired = retired_ingress_fixture();
        std::fs::write(
            &path,
            serde_json::json!({"schema": "org.arkret.garth.send_queue.v1", "items": [retired.clone()], "next_sequence": 17}).to_string(),
        )
        .unwrap();
        mutate_queue_in_file(&path, |q| {
            assert!(q.items().is_empty());
            Ok(())
        })
        .await
        .unwrap();
        let first = std::fs::read_to_string(&path).unwrap();
        let state = decode_snapshot(Some(&first)).unwrap();
        assert_eq!(state.retired_ingress_items, vec![retired]);
        assert_eq!(state.retired_ingress_next_sequence, Some(17));
        assert_eq!(
            state.retired_ingress_schema.as_deref(),
            Some("org.arkret.garth.send_queue.v1")
        );
        assert_eq!(state.commit_position, 1);
        mutate_queue_in_file(&path, |_| Ok(())).await.unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), first);
    }

    #[tokio::test]
    async fn empty_retired_ingress_counter_is_durably_archived_once() {
        for counter in [0, u64::MAX] {
            let store = garth::MemorySecureKeyStore::default();
            let key = "inkson.outbound.v1::nsA.standard";
            let original = serde_json::json!({"items": [], "next_sequence": counter}).to_string();
            store.store_secret(key, &original).unwrap();
            mutate_queue_in_store(&store, key, |q| {
                assert!(q.items().is_empty());
                Ok(())
            })
            .await
            .unwrap();
            let first = store.get_secret(key).unwrap().unwrap();
            let state = decode_snapshot(Some(&first)).unwrap();
            assert_eq!(state.retired_ingress_next_sequence, Some(counter));
            assert_eq!(state.commit_position, 1);
            mutate_queue_in_store(&store, key, |_| Ok(()))
                .await
                .unwrap();
            assert_eq!(store.get_secret(key).unwrap().unwrap(), first);

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("standard.json");
            std::fs::write(&path, original).unwrap();
            mutate_queue_in_file(&path, |_| Ok(())).await.unwrap();
            let first = std::fs::read_to_string(&path).unwrap();
            let state = decode_snapshot(Some(&first)).unwrap();
            assert_eq!(state.retired_ingress_next_sequence, Some(counter));
            assert_eq!(state.commit_position, 1);
            mutate_queue_in_file(&path, |_| Ok(())).await.unwrap();
            assert_eq!(std::fs::read_to_string(&path).unwrap(), first);
        }
    }

    #[tokio::test]
    async fn invalid_legacy_counters_and_unknown_fields_do_not_rewrite_the_vault() {
        for damage in [
            serde_json::json!({"next_sequence": -1}),
            serde_json::json!({"next_sequence": "17"}),
            serde_json::json!({"next_sequence": null}),
            serde_json::json!({"next_sequence": 1.5}),
            serde_json::json!({"next_sequence": 17, "unexpected": true}),
            serde_json::json!({"next_sequence": 17, "retired_ingress_next_sequence": 18}),
            serde_json::json!({"next_sequence": 17, "schema": "unknown-format"}),
            serde_json::json!({"schema": "org.arkret.garth.send_queue.v1"}),
            serde_json::json!({"next_sequence": 17, "schema": "org.arkret.garth.send_queue.v1", "retired_ingress_schema": "unknown-format"}),
        ] {
            let store = garth::MemorySecureKeyStore::default();
            let key = "inkson.outbound.v1::nsA.standard";
            let mut raw = damage;
            raw["items"] = serde_json::json!([retired_ingress_fixture()]);
            let original = raw.to_string();
            store.store_secret(key, &original).unwrap();
            assert!(
                mutate_queue_in_store(&store, key, |_| Ok(()))
                    .await
                    .is_err()
            );
            assert_eq!(store.get_secret(key).unwrap().unwrap(), original);
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("standard.json");
            std::fs::write(&path, &original).unwrap();
            assert!(mutate_queue_in_file(&path, |_| Ok(())).await.is_err());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        }
    }

    #[tokio::test]
    async fn current_queue_damage_is_not_retired_as_ingress() {
        let store = garth::MemorySecureKeyStore::default();
        let key = "inkson.outbound.v1::nsA.standard";
        let mut queue = garth::SendQueue::default();
        enqueue_items(&mut queue, 1);
        let mut raw = serde_json::to_value(queue.snapshot()).unwrap();
        raw["items"][0]["status"] = serde_json::json!("sent");
        raw["next_sequence"] = serde_json::json!(17);
        raw["schema"] = serde_json::json!("org.arkret.garth.send_queue.v1");
        let original = raw.to_string();
        store.store_secret(key, &original).unwrap();
        assert!(
            mutate_queue_in_store(&store, key, |_| Ok(()))
                .await
                .is_err()
        );
        assert_eq!(store.get_secret(key).unwrap().unwrap(), original);
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
