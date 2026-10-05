//! `EventSubmitter` — the authenticated producer-submission engine.
//!
//! A user write is one producer Event or one registered atomic unit. Authoring finalizes each
//! content-bound `event_id` exactly once: there is no chain position, no
//! predecessor, no basis and no precondition to resolve, so nothing after the
//! authoring boundary can change the identity. The frozen
//! [`arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest`] is what the
//! durable queue stores, and the current governance Station's authority-signed
//! [`arkret_wire::RealmCommit`] is the only finality signal.
//!
//! Retry, backoff and terminal classification belong to
//! [`garth::OutboundEngine`]. This module owns the host-side concerns the
//! engine deliberately does not have: the replay generation fence, the
//! post-commit local actions, and the join back to the optimistic UI row.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock as SyncOnceLock, PoisonError};
use std::time::Duration;

use anyhow::Context;
use arkret_wire::{CapabilityActionId, event_kind_str};
use garth::{OutboundEngine, OutboundEngineOutcome, QueuedSubmission, SendQueueStatus};
use serde_json::Value;
use tokio::sync::OnceCell;

use crate::ephemeral::{ensure_authority_accepted, validate_outgoing_registered_event_payload};
use crate::identity::authoring_generation::{
    GenerationFenceDecision, ResolvedQueueGenerationFence,
};
use crate::models::{BackfillView, ServiceDescribe, SubmitEventResult};
use crate::operation::{EventIntent, LocalOperation, uuid_v7};
use crate::outbound_store::{InksonOutboundStore, OutboundLane};

mod authoring_unit;
mod authority;
mod message_authoring;
mod metadata;

#[cfg(test)]
pub(crate) use authoring_unit::author_event_unit_for_test;
use authoring_unit::{UnitAuthoringChain, validate_authored_unit_shape};
#[cfg(test)]
pub(crate) use authority::creator_cache_belongs_to_closed_attempt;
#[cfg(test)]
pub(crate) use authority::verify_creator_genesis_producer;
use authority::*;
pub(crate) use authority::{original_creator_checkpoint_secret, restored_creator_artifacts};
#[cfg(test)]
pub(crate) use message_authoring::retry_frozen_message;
pub(crate) use message_authoring::{MessageSendAttempt, drive_message_send};
#[cfg(test)]
pub(crate) use tests::queue_message_operation_for_test;

/// Largest page one stream scan asks for. The wire ceiling is 1000.
const STREAM_SCAN_PAGE: u16 = 500;

/// Host wall clock for the durable outbound engine.
///
/// The engine's retry ledger is persisted in milliseconds, so it has to read
/// the same clock the rest of the client does rather than `Utc::now` directly:
/// on wasm that reading goes through the platform-safe shim.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct InksonHostClock;

impl garth::HostClock for InksonHostClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        crate::clock::now_utc()
    }
}

type InksonOutboundEngine = OutboundEngine<InksonOutboundStore, InksonHostClock>;
type InksonAuthorityClient = garth::AuthorityClient<garth::own_station::OwnStationConsumer>;

/// The write is safely persisted and will be retried.
///
/// It is keyed by the holder-local operation id rather than by the Event id:
/// the user's operation is what the optimistic row and the interface are
/// talking about, and it stays put across every transport attempt.
#[derive(Debug, thiserror::Error)]
#[error(
    "operation {operation_id} is durably queued for retry{detail}",
    detail = reason
        .as_deref()
        .map(|reason| format!(": {reason}"))
        .unwrap_or_default()
)]
pub(crate) struct DurablyQueuedError {
    pub(crate) operation_id: String,
    pub(crate) reason: Option<String>,
}

pub(crate) fn is_durably_queued_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<DurablyQueuedError>().is_some()
}

/// Scan one independent commit stream from an authenticated HTTP client.
///
/// [`EventSubmitter::scan_stream`] is the ordinary entry point; this free form
/// exists for the identity and pairing paths that authenticate an Event before
/// a submitter (which needs a bound account authority) can be built.
///
/// There is deliberately no Realm-wide cursor: the Realm and every Circle and
/// Sidecar have their own stream, and the caller drives the tail of each one it
/// is entitled to read.
pub(crate) async fn scan_stream_with(
    http: &arkret_sdk::http_client::Client,
    stream_ref: &arkret_wire::CommitStreamRef,
    after_position: Option<u64>,
    limit: u16,
) -> anyhow::Result<BackfillView> {
    let request = arkret_wire::StreamScanRequest {
        realm_id: stream_ref.realm_id().clone(),
        stream_ref: stream_ref.clone(),
        direction: arkret_wire::StreamScanDirection::After(after_position),
        limit: limit.clamp(1, 1000),
    };
    Ok(BackfillView::from(
        garth::AuthorityClient::new(http.clone())
            .scan(&request)
            .await
            .map_err(anyhow::Error::from)?,
    ))
}

/// Confirm the current governance Station committed this exact Event, and
/// return the commit coordinate it was given.
///
/// This replaces the removed proposal/Seal readback: an authority-signed
/// `RealmCommit` in the Event's own stream is the only finality signal, and the
/// Event's scope names the one stream that can carry it. The content binding is
/// re-derived first, so a substituted envelope cannot borrow another Event's
/// commit.
pub(crate) async fn require_committed_event_with(
    http: &arkret_sdk::http_client::Client,
    event: &arkret_sdk::Event,
) -> anyhow::Result<arkret_wire::CommittedEventRef> {
    let digest_suite = event.event_id.digest_suite_code().digest_suite();
    event.verify_event_id_matches_content_with_digest_suite(digest_suite)?;
    let stream_ref =
        arkret_wire::CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
            .map_err(anyhow::Error::from)?;
    let mut after_position = None;
    loop {
        let page = scan_stream_with(http, &stream_ref, after_position, STREAM_SCAN_PAGE).await?;
        if let Some(committed) = page
            .committed_refs()
            .into_iter()
            .find(|reference| reference.event_id == event.event_id)
        {
            return Ok(committed);
        }
        match page.last_position() {
            Some(position) if page.truncated() => after_position = Some(position),
            _ => {
                anyhow::bail!(
                    "Event {} is not committed in its own stream yet",
                    event.event_id
                );
            }
        }
    }
}

/// Compare a producer-authored Event with its accepted projection.
///
/// Acceptance retains the exact producer envelope: the current governance
/// Station answers an Event with its own signed `RealmCommit` and never appends
/// an admission proof to, or rewrites any signed field of, the Event itself.
/// Callers that re-read an Event they authored use this to prove that.
pub(crate) fn accepted_event_preserves_authored_envelope(
    accepted: &arkret_sdk::Event,
    authored: &arkret_sdk::Event,
    digest_suite: arkret_sdk::DigestSuite,
) -> anyhow::Result<bool> {
    Ok(accepted.event_id == authored.event_id
        && arkret_sdk::Hash::new(accepted.event_digest_with_digest_suite(digest_suite)?)?
            == arkret_sdk::Hash::new(authored.event_digest_with_digest_suite(digest_suite)?)?
        && accepted == authored)
}

/// One stage of an atomic unit, built from the members already authored before
/// it. A stage may yield several intents when none of them names another.
/// See [`EventSubmitter::author_event_unit`].
pub(crate) type EventUnitStep =
    Box<dyn FnOnce(&[arkret_sdk::AuthoredEvent]) -> anyhow::Result<Vec<EventIntent>> + Send>;

/// What the host still owes after the Station returns an accepted commit.
///
/// garth's engine has no post-accept hook: a commit ends the queue item's
/// life, and anything else that has to happen is the host's, run here while
/// the accepted commit is in hand.
enum PostAccept {
    /// Nothing beyond the optimistic-row join every submission does.
    None,
    /// Install the MLS group state this device staged while authoring the
    /// commit. `authority_hints` carry the checked KeyPackage claim evidence
    /// for every leaf the commit newly occupies.
    InstallMlsCommit {
        authority: arkret_sdk::AccountId,
        device_id: arkret_sdk::DeviceId,
        authority_hints: Vec<crate::mls::governance_proof::MlsLeafAuthorityHint>,
        state_store: crate::runtime::input::StateStoreHandle,
    },
}

/// Everything one durable submission needs besides its frozen request.
struct QueuedWrite {
    lane: OutboundLane,
    submission: QueuedSubmission,
    local_operation_id: String,
    post_accept: PostAccept,
    retry_scope: InteractiveRetryScope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InteractiveRetryScope {
    Ordinary,
    RealmBootstrap,
}

pub(crate) struct CommittedRealmBootstrap {
    pub(crate) realm_id: arkret_sdk::RealmId,
    pub(crate) first_commit: arkret_wire::RealmCommit,
}

/// The closed local selector is derived before any scope-create write. It never
/// becomes a field of the Realm-create payload or an authority assertion.
pub(crate) fn creator_intent_for_submission(
    submission: &garth::QueuedSubmission,
    device_id: arkret_sdk::DeviceId,
) -> anyhow::Result<arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapIntent> {
    let create = submission.primary_event();
    let scope = match create.kind {
        arkret_sdk::EventKind::RealmCreate => arkret_sdk::ScopeRef::Realm {
            realm_id: create.realm_id.clone(),
        },
        arkret_sdk::EventKind::CircleCreate => arkret_sdk::ScopeRef::Circle {
            realm_id: create.realm_id.clone(),
            circle_id: arkret_sdk::CircleId::from_event_id(&create.event_id),
        },
        _ => anyhow::bail!("creator intent requires a Realm or Circle create"),
    };
    let proof = create
        .producer_proof
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("creator intent requires a signed scope-create unit"))?;
    Ok(
        arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapIntent::new(
            create.actor_id.clone(),
            scope.clone(),
            device_id,
            proof.verification_method.clone(),
            arkret_sdk::MlsGovernanceBindingPayload::new(scope, None, 0, 0, 0)?,
            submission.request.clone(),
        )?,
    )
}

/// A new encrypted Circle has a metadata-free discussion before activation.
/// Its identity is frozen with create/join, so recovery never invents another
/// application object and no plaintext user metadata enters an activated scope.
pub(crate) fn initial_circle_discussion_intent(
    scope: &arkret_sdk::ScopeRef,
    owner: &arkret_sdk::ActorId,
) -> anyhow::Result<EventIntent> {
    let arkret_sdk::ScopeRef::Circle {
        realm_id,
        circle_id,
    } = scope
    else {
        anyhow::bail!("initial Circle discussion requires its exact scope");
    };
    let object = arkret_sdk::StrandCreateObject::new(realm_id.clone(), owner.clone())
        .with_scope_circle_id(circle_id.clone())
        .with_track("discussion", arkret_sdk::StrandTrack::discussion_primary());
    let payload = crate::operation::ak_ops::strand_create_payload(object)?;
    let created_at = payload.object.created_at;
    Ok(
        arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::StrandCreate>::new(
            scope.clone(),
            owner.clone(),
            payload,
        )?
        .into_intent(created_at)?,
    )
}

/// A browser runtime has multiple outbound triggers: the foreground writer and
/// the account-sync drain. Engines opened on the same durable store do not
/// share an in-memory lease, so forwarding needs a runtime single-writer gate.
/// Durable enqueue uses the store's own mutation gate and must not wait for a
/// network attempt or its retry delay.
fn outbound_submit_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// How long an interactive caller should wait before looking at the durable
/// queue again, for failures the engine does not classify for us.
fn outbound_retry_delay(error: &anyhow::Error) -> Option<Duration> {
    let rendered = format!("{error:#}");
    if crate::api_error::is_auth_expired_error(error)
        || rendered.contains("no active signer configured")
    {
        return Some(Duration::from_secs(1));
    }
    // Browser fetch failures can cross the WASM/runtime-service boundary as a
    // string-only anyhow context, losing the concrete http-client Error in the
    // source chain. Its stable transport prefix still distinguishes a
    // retryable network failure from protocol and admission rejections.
    if rendered.contains("HTTP request failed:") {
        return Some(Duration::from_secs(1));
    }
    if let Some(retry_after_ms) = crate::api_error::rate_limited_retry_after(error) {
        return Some(Duration::from_millis(retry_after_ms.max(1_000)));
    }
    error.chain().find_map(|cause| {
        if let Some(error) = cause.downcast_ref::<arkret_sdk::http_client::Error>() {
            return match error {
                arkret_sdk::http_client::Error::Http(_) => Some(Duration::from_secs(1)),
                arkret_sdk::http_client::Error::Api { status, .. }
                    if *status == 408 || *status == 429 || *status >= 500 =>
                {
                    Some(Duration::from_secs(1))
                }
                _ => None,
            };
        }
        cause
            .downcast_ref::<arkret_sdk::Error>()
            .and_then(|error| match error {
                arkret_sdk::Error::Http(_) => Some(Duration::from_secs(1)),
                arkret_sdk::Error::Api { status, .. }
                    if *status == 408 || *status == 429 || *status >= 500 =>
                {
                    Some(Duration::from_secs(1))
                }
                _ => None,
            })
    })
}

fn verified_recovery_gate_cache() -> &'static Mutex<BTreeSet<String>> {
    static CACHE: SyncOnceLock<Mutex<BTreeSet<String>>> = SyncOnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeSet::new()))
}

pub(crate) fn remember_verified_recovery_gate(authority: &arkret_sdk::AccountId, device_id: &str) {
    let Some(key) = recovery_gate_account_cache_key(authority, device_id) else {
        return;
    };
    let mut cache = verified_recovery_gate_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    cache.insert(key);
}

fn recovery_gate_account_cache_key(
    authority: &arkret_sdk::AccountId,
    device_id: &str,
) -> Option<String> {
    let device = arkret_sdk::DeviceId::new(device_id.to_owned()).ok()?;
    Some(format!(
        "{}\u{1f}{}\u{1f}{device}",
        authority.principal_id, authority.station_id
    ))
}

fn recovery_gate_cache_key(
    authority: &arkret_sdk::AccountId,
    intent: &EventIntent,
) -> Option<String> {
    let authority_principal = intent
        .executed_by()
        .unwrap_or_else(|| intent.actor_id())
        .signing_principal_id()
        .as_str();
    let signer = crate::event_signer::active_signer()?;
    let device_id = signer.device_id()?;
    (authority.principal_id.as_str() == authority_principal)
        .then(|| recovery_gate_account_cache_key(authority, device_id))
        .flatten()
}

pub(crate) fn reset_verified_recovery_gates() {
    let mut cache = verified_recovery_gate_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    cache.clear();
}

/// The producer Event a queue item is carrying, whichever submission shape it
/// took.
fn queued_event(item: &garth::SendQueueItem) -> &arkret_sdk::Event {
    item.submission.primary_event()
}

/// An item that has not reached a terminal authority answer yet.
fn is_unsettled(status: SendQueueStatus) -> bool {
    matches!(
        status,
        SendQueueStatus::Queued | SendQueueStatus::Forwarding
    )
}

/// A frozen controller control remains the retry identity until the signed
/// history exposes its terminal result. Never seal a second close merely
/// because the response to the first submission was lost.
pub(crate) async fn retained_sidecar_control_request(
    authority: &arkret_sdk::AccountId,
    sidecar: &arkret_sdk::SidecarId,
    request: &arkret_sdk::EventId,
    store: &crate::runtime::input::StateStoreHandle,
) -> anyhow::Result<bool> {
    let outbound = OutboundEngine::new(
        InksonOutboundStore::open(authority, OutboundLane::Standard)?,
        InksonHostClock,
    );
    let snapshot = outbound.snapshot().await?;
    for item in &snapshot.items {
        if matches!(
            item.submission.state,
            garth::SubmissionState::Rejected { .. }
        ) {
            continue;
        }
        let event = queued_event(item);
        if event.kind != arkret_sdk::EventKind::AgentSidecarExchangeControl
            || !matches!(&event.scope_ref, arkret_sdk::ScopeRef::Sidecar { sidecar_id, .. } if sidecar_id == sidecar)
            || event.actor_id.as_account_id() != Some(authority)
        {
            continue;
        }
        let payload: arkret_sdk::AgentSidecarExchangeControlPayload =
            serde_json::from_value(serde_json::to_value(&event.payload)?)?;
        let digest = payload.encrypted_payload.payload_digest()?;
        let plaintext = store
            .read(|store| {
                store.mls_decrypted_plaintext_for(event.realm_id.as_str(), digest.as_str())
            })
            .ok_or_else(|| {
                anyhow::anyhow!("frozen Sidecar control awaits its retained authored plaintext")
            })?;
        let control: arkret_sdk::AgentSidecarExchangeControl = serde_json::from_slice(&plaintext)?;
        control.validate_shape()?;
        if &control.request_event_id == request {
            return Ok(true);
        }
    }
    Ok(false)
}

fn pending_chat_event_ids_from_snapshot(
    snapshot: &garth::SendQueueSnapshot,
    realm_id: &str,
    strand_id: &str,
) -> BTreeSet<String> {
    snapshot
        .items
        .iter()
        .filter(|item| is_unsettled(item.status))
        .map(|item| queued_event(item))
        .filter(|event| {
            event.kind == arkret_sdk::EventKind::MessageCreate
                && event.realm_id.as_str() == realm_id
                && event
                    .payload
                    .get("strand_id")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value == strand_id)
        })
        .map(|event| event.event_id.to_string())
        .collect()
}

/// Project the pending chat sends of one Strand directly from the durable
/// queue.
///
/// Each final content-bound Event id is joined back to its holder-local
/// operation when that identity record exists. A queued send is counted once,
/// even while the optimistic bubble still carries its local id.
pub(crate) async fn pending_chat_outbound_local_operation_ids(
    authority: &arkret_sdk::AccountId,
    realm_id: &str,
    strand_id: &str,
    state_store: &crate::runtime::input::StateStoreHandle,
) -> anyhow::Result<BTreeSet<String>> {
    let outbound = OutboundEngine::new(
        InksonOutboundStore::open(authority, OutboundLane::Standard)?,
        InksonHostClock,
    );
    let snapshot = outbound.snapshot().await?;
    // Enqueue may finish its holder-local identity join during the async read.
    // Project with that latest durable mapping, not a pre-await UI snapshot.
    Ok(state_store.read(|store| {
        pending_chat_local_operation_ids_from_snapshot(
            &snapshot,
            realm_id,
            strand_id,
            &store.load(),
        )
    }))
}

fn pending_chat_local_operation_ids_from_snapshot(
    snapshot: &garth::SendQueueSnapshot,
    realm_id: &str,
    strand_id: &str,
    state: &crate::state::ClientLocalState,
) -> BTreeSet<String> {
    pending_chat_event_ids_from_snapshot(snapshot, realm_id, strand_id)
        .into_iter()
        .map(|event_id| {
            arkret_sdk::EventId::new(event_id.clone())
                .ok()
                .and_then(|event_id| local_operation_for_event(state, &event_id))
                .unwrap_or(event_id)
        })
        .collect()
}

fn pending_mls_commit_for_realm_from_snapshot(
    snapshot: &garth::SendQueueSnapshot,
    realm_id: &str,
    installed: impl Fn(&arkret_sdk::Event) -> bool,
) -> bool {
    snapshot.items.iter().any(|item| {
        let event = queued_event(item);
        event.realm_id.as_str() == realm_id
            && (is_unsettled(item.status)
                || (item.status == SendQueueStatus::Committed && !installed(event)))
    })
}

fn durable_mls_genesis_for_realm_from_snapshot(
    snapshot: &garth::SendQueueSnapshot,
    realm_id: &str,
) -> bool {
    snapshot
        .items
        .iter()
        .filter(|item| is_unsettled(item.status) || item.status == SendQueueStatus::Committed)
        .any(|item| {
            let event = queued_event(item);
            event.kind == arkret_sdk::EventKind::MlsGenesis
                && matches!(&event.scope_ref, arkret_sdk::ScopeRef::Realm { realm_id: scope_realm } if scope_realm.as_str() == realm_id)
        })
}

/// Stamp the final Event identity onto the optimistic row that stands for this
/// write.
///
/// Authoring is one-shot, so this runs at enqueue time rather than after the
/// Station answers: from the moment the write is durable, the row already
/// carries the identity the committed Event will have, and a later backfill
/// keyed by that identity merges into the same row instead of appearing beside
/// it as a second create.
fn record_queued_operation_identity(
    state_store: &mut crate::state::LocalStateStore,
    local_operation_id: &str,
    event: &arkret_sdk::Event,
) -> bool {
    // Materialize earlier local projection commands before establishing the
    // durable queue-to-operation join. An ordinary chat bubble may exist only
    // in memory; its identity record must still survive queue replay.
    state_store.project_pending_local_commands();
    if state_store.update_raw_operation_write_state(
        local_operation_id,
        "queued",
        Some(event.event_id.to_string()),
        None,
    ) {
        return true;
    }
    if state_store
        .load()
        .raw_operations
        .iter()
        .any(|row| row.operation_id == local_operation_id)
    {
        return false;
    }
    if event.kind != arkret_sdk::EventKind::MessageCreate {
        return false;
    }
    // Ordinary chat can reach the durable queue before a holder projection
    // exists. Keep its signed bytes separate from local lifecycle metadata.
    state_store.upsert_raw_operation(
        local_operation_id,
        Some(event.realm_id.to_string()),
        serde_json::json!({
            "event": event,
            "event_id": event.event_id,
            "write_state": "queued",
        }),
    )
}

/// The holder-local operation whose optimistic row already names this Event.
///
/// The durable queue holds only the frozen submission, so after a restart the
/// join back to the user's operation is read from the row the enqueue stamped.
fn local_operation_for_event(
    state: &crate::state::ClientLocalState,
    event_id: &arkret_sdk::EventId,
) -> Option<String> {
    state
        .raw_operations
        .iter()
        .find(|record| {
            // A signed Event row names its own id but is not a holder-local
            // operation row.
            record.payload.get("producer_proof").is_none()
                && record.payload.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
        })
        .map(|record| record.operation_id.clone())
}

/// Join the durable queue's holder IDs to the frozen Event identities used
/// by the timeline fold. The queue count still counts holder operations once.
pub(crate) fn pending_chat_message_identities(
    local_ids: &BTreeSet<String>,
    state: &crate::state::ClientLocalState,
) -> BTreeSet<String> {
    let mut identities = local_ids.clone();
    for record in &state.raw_operations {
        if !local_ids.contains(&record.operation_id) {
            continue;
        }
        let Some(event) = record
            .payload
            .get("event")
            .and_then(|value| serde_json::from_value::<arkret_sdk::Event>(value.clone()).ok())
        else {
            continue;
        };
        if event.kind != arkret_sdk::EventKind::MessageCreate
            || record.payload.get("event_id").and_then(Value::as_str)
                != Some(event.event_id.as_str())
            || record.realm_id.as_deref() != Some(event.realm_id.as_str())
            || event
                .verify_event_id_matches_content_with_digest_suite(
                    event.event_id.digest_suite_code().digest_suite(),
                )
                .is_err()
        {
            continue;
        }
        identities.insert(event.event_id.to_string());
        identities.insert(arkret_sdk::MessageId::from_event_id(&event.event_id).to_string());
    }
    identities
}

/// Move the optimistic row to its terminal write state once the Station has
/// answered for the Event it names.
fn reconcile_settled_outbound_item(
    state_store: &mut crate::state::LocalStateStore,
    item: &garth::SendQueueItem,
) -> bool {
    let event_id = item.event_id().clone();
    let (write_state, error) = match item.status {
        SendQueueStatus::Committed
            if queued_event(item).kind == arkret_sdk::EventKind::MessageCreate =>
        {
            ("committed", None)
        }
        SendQueueStatus::Committed => ("accepted", None),
        SendQueueStatus::Rejected => (
            "rejected",
            Some(
                item.rejection_reason_code()
                    .unwrap_or("rejected")
                    .to_owned(),
            ),
        ),
        _ => return false,
    };
    let operation_id = local_operation_for_event(&state_store.load(), &event_id);
    let committed_message = item.status == SendQueueStatus::Committed
        && queued_event(item).kind == arkret_sdk::EventKind::MessageCreate;
    if committed_message {
        // Keep the exact signed Event separate from holder-local write metadata.
        // A committed sender must be able to project its own message before
        // account or Realm stream backfill echoes it. The queue's committed
        // transition already checked the covering Commit for these frozen bytes.
        let event = queued_event(item);
        return state_store.upsert_raw_operation(
            operation_id.unwrap_or_else(|| event_id.to_string()),
            Some(event.realm_id.to_string()),
            serde_json::json!({
                "event": event,
                "event_id": event_id,
                "write_state": write_state,
            }),
        );
    }
    let Some(operation_id) = operation_id else {
        return false;
    };
    if queued_event(item).kind == arkret_sdk::EventKind::StrandUpdate
        && let garth::SubmissionState::Committed { commit, .. } = &item.submission.state
    {
        state_store.record_card_display_commit(&operation_id, commit);
    }
    state_store.update_raw_operation_write_state(
        &operation_id,
        write_state,
        Some(event_id.to_string()),
        error,
    )
}

/// Turn one settled queue item into the caller-facing result, or into the
/// typed authority refusal.
fn settled_outbound_result(item: &garth::SendQueueItem) -> anyhow::Result<SubmitEventResult> {
    match &item.submission.state {
        garth::SubmissionState::Committed { status, commit } => {
            ensure_authority_accepted(arkret_wire::AuthoritySubmitOutcome::Accepted {
                status: *status,
                commit: (**commit).clone(),
            })
            .map(|commit| SubmitEventResult::committed(item.event_id().to_string(), commit))
        }
        garth::SubmissionState::UnitCommitted { .. } => Err(anyhow::anyhow!(
            "aggregate unit requires its complete Commit result"
        )),
        garth::SubmissionState::Rejected {
            status,
            reason_code,
        } => ensure_authority_accepted(arkret_wire::AuthoritySubmitOutcome::Rejected {
            status: *status,
            reason_code: reason_code.clone(),
        })
        .map(|commit| SubmitEventResult::committed(item.event_id().to_string(), commit)),
        garth::SubmissionState::Queued => Err(DurablyQueuedError {
            operation_id: item.event_id().to_string(),
            reason: item.last_error.clone(),
        }
        .into()),
    }
}

/// Authenticated producer-submission engine, constructed per authenticated
/// call from the shared SDK http-client (see
/// `crate::transport::auth::with_event_submitter`).
pub struct EventSubmitter {
    http: arkret_sdk::http_client::Client,
    /// Exact account authority captured when this submitter is constructed.
    /// Durable queue operations never re-read the process-global active scope.
    authority: Option<arkret_sdk::AccountId>,
    describe_cache: OnceCell<ServiceDescribe>,
    state_store: Option<crate::runtime::input::StateStoreHandle>,
    /// A freshly committed Realm has no complete local projection yet, but its
    /// setup flow must still append the deterministic default-Strand
    /// follow-ups. This only bypasses the local-detail freshness guard for
    /// that exact Realm; producer proofs and Station admission remain
    /// mandatory.
    founding_realm: Option<arkret_sdk::RealmId>,
}

/// Exact Relation state returned by the governing Station and validated
/// against the locally installed governance generation. Its fields stay
/// private so callers cannot manufacture a CAS basis from a projection.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedRelationCurrent {
    primary_conflict_domain: arkret_sdk::RelationPrimaryConflictDomain,
    revision: Option<arkret_wire::CurrentRevision>,
    value: Option<arkret_sdk::Relation>,
}

impl VerifiedRelationCurrent {
    #[cfg(test)]
    pub(crate) fn never_written_for_test(
        primary_conflict_domain: arkret_sdk::RelationPrimaryConflictDomain,
    ) -> Self {
        Self {
            primary_conflict_domain,
            revision: None,
            value: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn present_for_test(
        primary_conflict_domain: arkret_sdk::RelationPrimaryConflictDomain,
        revision: arkret_wire::CurrentRevision,
        value: arkret_sdk::Relation,
    ) -> Self {
        Self {
            primary_conflict_domain,
            revision: Some(revision),
            value: Some(value),
        }
    }

    pub(crate) fn expected_revision_for_create(
        &self,
        domain: &arkret_sdk::RelationPrimaryConflictDomain,
    ) -> anyhow::Result<Option<arkret_wire::CurrentRevision>> {
        anyhow::ensure!(
            &self.primary_conflict_domain == domain,
            "verified Relation current basis belongs to another primary conflict domain"
        );
        Ok(self.revision.clone())
    }

    pub(crate) fn present(
        &self,
        domain: &arkret_sdk::RelationPrimaryConflictDomain,
    ) -> anyhow::Result<(&arkret_wire::CurrentRevision, &arkret_sdk::Relation)> {
        anyhow::ensure!(
            &self.primary_conflict_domain == domain,
            "verified Relation current basis belongs to another primary conflict domain"
        );
        match (&self.revision, &self.value) {
            (Some(revision), Some(value)) => Ok((revision, value)),
            _ => anyhow::bail!(
                "Relation tombstone requires an exact present current result; never_written is valid only for create"
            ),
        }
    }
}

/// Exact moderation state returned by the governing Station and validated
/// against the locally installed governance generation.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedModerationCurrent {
    target_ref: arkret_models_collaboration::exact_current_results::ExactModerationTargetRef,
    revision: arkret_wire::CurrentRevision,
    assertions: Vec<arkret_models_collaboration::exact_current_results::ModerationDecisionEntry>,
}

impl VerifiedModerationCurrent {
    #[cfg(test)]
    pub(crate) fn for_test(
        target_ref: &str,
        revision: arkret_wire::CurrentRevision,
        assertions: Vec<
            arkret_models_collaboration::exact_current_results::ModerationDecisionEntry,
        >,
    ) -> Self {
        Self {
            target_ref:
                arkret_models_collaboration::exact_current_results::ExactModerationTargetRef::new(
                    target_ref.to_owned(),
                )
                .unwrap(),
            revision,
            assertions,
        }
    }

    pub(crate) fn revision_for_decision(
        &self,
        target_ref: &str,
        decision_ref: &arkret_sdk::EventId,
    ) -> anyhow::Result<arkret_wire::CurrentRevision> {
        anyhow::ensure!(
            self.target_ref.as_str() == target_ref,
            "verified moderation current basis belongs to another target"
        );
        let decision_is_current = self.assertions.iter().any(|assertion| {
            assertion.tag_id.event_id() == decision_ref
                && matches!(
                    &assertion.value,
                    arkret_models_collaboration::exact_current_results::ModerationAssertionValue::Decision(_)
                )
        });
        anyhow::ensure!(
            decision_is_current,
            "moderation decision is not present in the governing Station's exact current result"
        );
        Ok(self.revision.clone())
    }
}

impl EventSubmitter {
    pub fn new(http: arkret_sdk::http_client::Client) -> Self {
        Self {
            http,
            authority: crate::secure_key_store::active_device_seed_scope()
                .map(|scope| scope.authority),
            describe_cache: OnceCell::new(),
            state_store: None,
            founding_realm: None,
        }
    }

    pub(crate) fn with_state_store(
        mut self,
        state_store: crate::runtime::input::StateStoreHandle,
    ) -> Self {
        self.state_store = Some(state_store);
        self
    }

    pub(crate) fn with_authority(mut self, authority: arkret_sdk::AccountId) -> Self {
        self.authority = Some(authority);
        self
    }

    pub(crate) fn for_founding_realm(mut self, realm_id: arkret_sdk::RealmId) -> Self {
        self.founding_realm = Some(realm_id);
        self
    }

    pub(crate) fn from_current_session(http: arkret_sdk::http_client::Client) -> Self {
        match dioxus::prelude::try_consume_context::<crate::app::SessionContext>() {
            Some(context) => {
                // Accepted onboarding promotes the secure authoring scope and
                // account store before publishing the runtime account. The UI
                // may still retain the previous account until recovery is ready;
                // it must not replace the exact scope captured by `new`.
                Self::new(http).with_state_store(crate::app::runtime_adapter::state_store_handle(
                    context.state_store,
                ))
            }
            None => Self::new(http),
        }
    }

    pub(crate) fn authority(&self) -> anyhow::Result<&arkret_sdk::AccountId> {
        self.authority.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "durable Event submission requires an active AccountId captured when the submitter was created"
            )
        })
    }

    /// The shared SDK http-client backing this submitter.
    pub(crate) fn http(&self) -> &arkret_sdk::http_client::Client {
        &self.http
    }

    async fn exact_current_result(
        &self,
        request: &arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadRequestBody,
    ) -> anyhow::Result<
        arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadOutcome,
    > {
        let authority = self.authority()?.clone();
        let state_store = self.state_store.as_ref().ok_or_else(|| {
            anyhow::anyhow!("exact current read requires the active account state store")
        })?;
        let location = state_store.read(|store| store.current_index_location());
        let index = crate::state::CurrentIndex::open_committed(&authority, location, || {
            state_store.read(|store| {
                anyhow::ensure!(
                    store.active_authority().as_ref() == Some(&authority),
                    "exact current read account changed before authorization"
                );
                anyhow::ensure!(
                    !store.current_reset_required(),
                    "exact current read requires a fresh account current baseline"
                );
                Ok(store.current_generation())
            })
        })
        .await?;
        let progress = index.read_progress(request.realm_id.as_str()).await?;
        anyhow::ensure!(
            !progress.needs_refresh,
            "exact current read requires a refreshed Realm current baseline"
        );
        let baseline = progress.baseline.as_ref().ok_or_else(|| {
            anyhow::anyhow!("exact current read requires an installed Realm current baseline")
        })?;
        anyhow::ensure!(
            baseline.complete && baseline.coverage.complete_for_authorized_streams,
            "exact current read requires complete authorized-stream coverage"
        );
        anyhow::ensure!(
            baseline.coverage.realm_id == request.realm_id,
            "exact current read baseline belongs to another Realm"
        );
        let governance_generation = progress.governance_generation.ok_or_else(|| {
            anyhow::anyhow!("exact current read lacks a verified governance generation")
        })?;
        self.http
            .exact_current_result(request, governance_generation)
            .await
            .map_err(anyhow::Error::from)
    }

    pub(crate) async fn read_relation_current(
        &self,
        realm_id: arkret_sdk::RealmId,
        primary_conflict_domain: arkret_sdk::RelationPrimaryConflictDomain,
    ) -> anyhow::Result<VerifiedRelationCurrent> {
        use arkret_models_collaboration::exact_current_results::{
            ExactCurrentResultEntry, ExactCurrentResultSelector, ExactCurrentResultsReadOutcome,
            ExactCurrentResultsReadRequestBody, RelationExactCurrentSelector,
        };

        let selector = RelationExactCurrentSelector::new(primary_conflict_domain.clone())?;
        let request = ExactCurrentResultsReadRequestBody {
            realm_id,
            selector: ExactCurrentResultSelector::Relation(selector),
        };
        match self.exact_current_result(&request).await? {
            ExactCurrentResultsReadOutcome::NeverWritten { .. } => Ok(VerifiedRelationCurrent {
                primary_conflict_domain,
                revision: None,
                value: None,
            }),
            ExactCurrentResultsReadOutcome::Present {
                entry: ExactCurrentResultEntry::Relation(entry),
                ..
            } => Ok(VerifiedRelationCurrent {
                primary_conflict_domain,
                revision: Some(entry.revision),
                value: Some(entry.value),
            }),
            ExactCurrentResultsReadOutcome::Present { .. } => {
                anyhow::bail!("exact Relation current read returned another result family")
            }
        }
    }

    pub(crate) async fn read_moderation_current(
        &self,
        realm_id: arkret_sdk::RealmId,
        target_ref: &str,
    ) -> anyhow::Result<VerifiedModerationCurrent> {
        use arkret_models_collaboration::exact_current_results::{
            ExactCurrentResultEntry, ExactCurrentResultSelector, ExactCurrentResultsReadOutcome,
            ExactCurrentResultsReadRequestBody, ExactModerationTargetRef,
            ModerationStateExactCurrentSelector, ModerationStateExactCurrentSelectorKind,
        };

        let target_ref = ExactModerationTargetRef::new(target_ref.to_owned())?;
        let request = ExactCurrentResultsReadRequestBody {
            realm_id,
            selector: ExactCurrentResultSelector::ModerationState(
                ModerationStateExactCurrentSelector {
                    kind: ModerationStateExactCurrentSelectorKind::ModerationState,
                    target_ref: target_ref.clone(),
                },
            ),
        };
        match self.exact_current_result(&request).await? {
            ExactCurrentResultsReadOutcome::Present {
                entry: ExactCurrentResultEntry::ModerationState(entry),
                ..
            } => Ok(VerifiedModerationCurrent {
                target_ref,
                revision: entry.revision,
                assertions: entry.value.assertions,
            }),
            ExactCurrentResultsReadOutcome::Present { .. } => {
                anyhow::bail!("exact moderation current read returned another result family")
            }
            ExactCurrentResultsReadOutcome::NeverWritten { .. } => anyhow::bail!(
                "governing Station returned never_written for moderation current; that branch is Relation-only"
            ),
        }
    }

    async fn authority_client(&self) -> anyhow::Result<InksonAuthorityClient> {
        let binding = crate::station_connection::enrolled(self.http.base_url().as_str()).await?;
        let epoch = crate::identity::device_directory::session_cache_epoch();
        let consumer = garth::own_station::OwnStationConsumer::authenticate(
            self.http.clone(),
            &binding,
            self.authority()?.clone(),
            epoch,
        )
        .await?;
        anyhow::ensure!(
            epoch == crate::identity::device_directory::session_cache_epoch(),
            "submission Account epoch changed"
        );
        Ok(garth::AuthorityClient::new(consumer))
    }

    fn outbound(&self, lane: OutboundLane) -> anyhow::Result<InksonOutboundEngine> {
        Ok(OutboundEngine::new(
            InksonOutboundStore::open(self.authority()?, lane)?,
            InksonHostClock,
        ))
    }

    /// Lazily fetch + cache the service describe for this submitter.
    async fn describe_cached(&self) -> anyhow::Result<&ServiceDescribe> {
        crate::transport::describe_cache::cached_service_describe(&self.http, &self.describe_cache)
            .await
    }

    pub(crate) async fn service_did(&self) -> anyhow::Result<String> {
        Ok(self
            .describe_cached()
            .await?
            .service_resolution
            .did
            .to_string())
    }

    /// Current server metadata.
    pub async fn service_describe(&self) -> anyhow::Result<arkret_sdk::ServiceDescribe> {
        self.http
            .describe()
            .await
            .map_err(|error| anyhow::anyhow!("server describe: {error}"))
    }

    async fn ensure_realm_detail_current(&self, realm_id: &str) -> anyhow::Result<()> {
        // A fresh Realm selection or Account invalidation can temporarily
        // remove the verified current view. Keep the authoring gate closed
        // while the account subscription replaces that bounded baseline, then
        // submit the original intent without asking the user to retry it.
        for _ in 0..60 {
            let invalidated_without_projection = self
                .state_store
                .as_ref()
                .is_some_and(|store| store.read(|store| store.realm_detail_invalidated(realm_id)));
            if !local_detail_blocks_authoring(
                self.founding_realm.as_ref(),
                realm_id,
                invalidated_without_projection,
            ) {
                return Ok(());
            }
            crate::runtime_helpers::sleep_for(Duration::from_millis(250)).await;
        }
        Err(anyhow::Error::new(arkret_sdk::Error::Http(
            "Realm current state is refreshing after an account invalidation".to_owned(),
        )))
    }

    // ---------------------------------------------------------------- reads

    /// Scan one independent commit stream.
    ///
    /// There is deliberately no Realm-wide cursor: the Realm and every Circle
    /// and Sidecar have their own stream, and the caller drives the tail of
    /// each one it is entitled to read.
    pub async fn scan_stream(
        &self,
        stream_ref: &arkret_wire::CommitStreamRef,
        after_position: Option<u64>,
        limit: u16,
    ) -> anyhow::Result<BackfillView> {
        scan_stream_with(&self.http, stream_ref, after_position, limit).await
    }

    /// One page of the Realm's own commit stream, from its start.
    ///
    /// This is the Realm stream, not a Realm-wide ordering: Circle and Sidecar
    /// streams are scanned separately through [`Self::scan_stream`].
    pub async fn backfill(&self, realm_id: &str) -> anyhow::Result<BackfillView> {
        let stream_ref = arkret_wire::CommitStreamRef::Realm {
            realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())?,
        };
        self.scan_stream(&stream_ref, None, STREAM_SCAN_PAGE).await
    }

    /// Every Event committed to the Realm's own stream, following pagination
    /// to the tail.
    async fn realm_stream_events(&self, realm_id: &str) -> anyhow::Result<Vec<arkret_sdk::Event>> {
        let stream_ref = arkret_wire::CommitStreamRef::Realm {
            realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())?,
        };
        let mut events = Vec::new();
        let mut after_position = None;
        loop {
            let page = self
                .scan_stream(&stream_ref, after_position, STREAM_SCAN_PAGE)
                .await?;
            events.extend(page.events());
            match page.last_position() {
                Some(position) if page.truncated() => after_position = Some(position),
                _ => return Ok(events),
            }
        }
    }

    /// The `ak.mls.genesis` that activated encryption for the Realm scope.
    pub(crate) async fn find_mls_genesis_event_id(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<Option<arkret_sdk::EventId>> {
        let events = self.realm_stream_events(realm_id).await?;
        Ok(mls_genesis_event_id_from_events(&events, realm_id))
    }

    /// Confirm the current governance Station committed this exact Event, and
    /// return the commit coordinate it was given.
    ///
    /// The Event's own scope names the one stream that can carry it, so this
    /// walks that stream rather than asking a separate finality endpoint —
    /// `resolve_committed_events` answers only for refs a Directory announce
    /// already authorized.
    pub(crate) async fn require_committed_event(
        &self,
        event: &arkret_sdk::Event,
    ) -> anyhow::Result<arkret_wire::CommittedEventRef> {
        require_committed_event_with(&self.http, event).await
    }

    /// Read the immutable founding Event from position zero of the Realm's own
    /// stream.
    async fn realm_create_authority(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<Option<RealmCreateAuthority>> {
        if let Some(cached) = realm_create_authority_cache()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(realm_id)
        {
            return Ok(Some(cached.clone()));
        }
        // The nonce-bound, Station-signed authority bundle carries the exact
        // genesis Event of the Realm's verified chain. A readable-history scan
        // is not the source: its first row need not be position 0.
        let realm = arkret_sdk::RealmId::new(realm_id.to_owned())?;
        let originals =
            crate::realm_events_engine::own_realm_prefix(&self.http, self.authority()?, &realm, 1)
                .await?;
        let resolved =
            realm_create_authority_from_events(std::slice::from_ref(&originals[0].event), realm_id);
        if let Some(authority) = &resolved {
            realm_create_authority_cache()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(realm_id.to_owned(), authority.clone());
        }
        // A temporarily unavailable founding Event is not cached.
        Ok(resolved)
    }

    /// Whether this account authors the Realm's first `ak.mls.genesis`, and
    /// whether the Realm is a Direct Conversation. An ordinary Realm's genesis
    /// belongs to its root controller; a Direct Conversation's to its founder,
    /// whose one scope-derived Genesis both bootstrap phases require
    /// (`identity/contact-and-direct-conversation.md` 7.2 / 7.3).
    pub(crate) async fn accepted_scope_genesis_author(
        &self,
        realm_id: &str,
        authority: &arkret_sdk::AccountId,
    ) -> anyhow::Result<(bool, bool)> {
        let actor = arkret_sdk::ActorId::account(authority.clone());
        let founding = self
            .realm_create_authority(realm_id)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("committed Realm founding authority is not available")
            })?;
        Ok(match founding {
            RealmCreateAuthority::Root { controller } => (controller == actor, false),
            RealmCreateAuthority::DirectConversation { founder } => (founder == actor, true),
        })
    }

    // ------------------------------------------------------------ authoring

    /// The digest suite an Event authored into this scope must use.
    ///
    /// A Realm id is derived from its genesis Event id, whose token header
    /// carries the suite, so the value is a local fact about the scope rather
    /// than something negotiated with a Station. A Realm genesis itself is the
    /// SHA-256 bootstrap identity.
    fn digest_suite_for_intent(
        &self,
        intent: &EventIntent,
    ) -> anyhow::Result<arkret_sdk::DigestSuite> {
        if intent.kind() == &arkret_sdk::EventKind::RealmCreate {
            return Ok(arkret_sdk::DigestSuite::Sha256);
        }
        let realm_id = intent.realm_id_opt().ok_or_else(|| {
            anyhow::anyhow!(
                "{} carries no Realm scope to take its digest suite from",
                intent.kind().as_str()
            )
        })?;
        Ok(realm_id.digest_suite_code().digest_suite())
    }

    pub(crate) async fn event_proof_context(
        &self,
        digest_suite: arkret_sdk::DigestSuite,
    ) -> anyhow::Result<crate::event_signer::ProducerProofContext> {
        // Device-list refresh fences the retained cache before its async
        // query completes. Resolve this exact author's current evidence here
        // instead of turning that transient gap into a failed user action.
        let authority = self.authority()?;
        let signer = crate::event_signer::active_signer()
            .ok_or_else(|| anyhow::anyhow!("active device signer is unavailable"))?;
        let device = arkret_sdk::DeviceId::new(
            signer
                .device_id()
                .ok_or_else(|| anyhow::anyhow!("active signer has no device id"))?
                .to_owned(),
        )?;
        let session_epoch = crate::identity::device_directory::session_cache_epoch();
        for _ in 0..3 {
            self.ensure_device_authoring_fence(authority, &device, &signer, session_epoch)?;
            if let Ok(context) =
                crate::event_signer::cached_active_event_proof_context(digest_suite)
            {
                return Ok(context);
            }
            let epoch = crate::identity::device_directory::cache_epoch();
            let persisted =
                crate::identity::device_directory::authenticated_device_authoring_authority(
                    &self.http,
                    authority,
                    &device,
                    signer.as_ref(),
                )
                .await?;
            self.ensure_device_authoring_fence(authority, &device, &signer, session_epoch)?;
            // A notification invalidated this read, even if its reply was a
            // negative projection. Re-query in the same session; never install
            // that reply under the new directory epoch.
            if crate::identity::device_directory::cache_epoch() != epoch {
                continue;
            }
            let persisted = persisted.ok_or_else(|| {
                anyhow::anyhow!("active device has no matching verified authoring authority")
            })?;
            if !crate::identity::device_directory::restore_persisted_device_authoring_authority(
                epoch, authority, &device, &persisted,
            ) {
                self.ensure_device_authoring_fence(authority, &device, &signer, session_epoch)?;
                if crate::identity::device_directory::cache_epoch() != epoch {
                    continue;
                }
                anyhow::bail!("device authoring authority was superseded or revoked");
            }
            if let Some(store) = self.state_store.as_ref() {
                store.write(|state| state.set_device_authoring_authority(Some(persisted)));
            }
            return crate::event_signer::cached_active_event_proof_context(digest_suite)
                .map_err(|error| anyhow::anyhow!("{error}"));
        }
        anyhow::bail!("device authoring refresh did not settle in the current session")
    }

    fn ensure_device_authoring_fence(
        &self,
        authority: &arkret_sdk::AccountId,
        device: &arkret_sdk::DeviceId,
        signer: &std::sync::Arc<crate::event_signer::InksonEventSigner>,
        session_epoch: u64,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            crate::identity::device_directory::session_cache_epoch() == session_epoch
                && crate::secure_key_store::active_device_seed_scope().is_some_and(|scope| {
                    &scope.authority == authority && &scope.device_id == device
                })
                && crate::event_signer::active_signer()
                    .is_some_and(|active| std::sync::Arc::ptr_eq(&active, signer)),
            "device authoring refresh crossed its session or authority fence"
        );
        if let Some(store) = self.state_store.as_ref() {
            anyhow::ensure!(
                store
                    .read(crate::state::LocalStateStore::active_authority)
                    .as_ref()
                    == Some(authority),
                "device authoring refresh crossed its account fence"
            );
        }
        Ok(())
    }

    async fn verify_actor_authority(&self, intent: &EventIntent) -> anyhow::Result<()> {
        // The captured authority is the exact AccountId this submitter was
        // created for. Reject an account actor that substitutes another hosted
        // account while retaining the authenticated principal.
        if let (Some(authority), Some(actor_account)) =
            (self.authority.as_ref(), intent.actor_id().as_account_id())
            && actor_account.principal_id == authority.principal_id
            && actor_account.station_id != authority.station_id
        {
            anyhow::bail!(
                "Event actor names Station {} but the authenticated account is hosted at {}",
                actor_account.station_id,
                authority.station_id
            );
        }
        Ok(())
    }

    /// The single producer-authoring boundary.
    ///
    /// Everything the producer signs is complete on the [`EventIntent`] here;
    /// `event_id` is derived exactly once, at the end, from that finished
    /// content. Nothing before this point holds an Event identity, and nothing
    /// after it changes one: the signer only adds a proof.
    async fn author_intent(
        &self,
        intent: &EventIntent,
    ) -> anyhow::Result<arkret_sdk::AuthoredEvent> {
        if let Some(realm_id) = intent.realm_id_opt() {
            self.ensure_realm_detail_current(realm_id.as_str()).await?;
        }
        self.verify_actor_authority(intent).await?;
        validate_capability_grant_payload(intent)?;
        let intent = self.direct_participant_authoring_intent(intent).await?;
        let digest_suite = self.digest_suite_for_intent(&intent)?;
        let proof_context = self.event_proof_context(digest_suite).await?;
        let mut event = intent
            .clone()
            .author_with_digest_suite(digest_suite)
            .map_err(|error| anyhow::anyhow!("author Event: {error}"))?;
        self.sign_authored_event(&intent, &mut event, proof_context)?;
        Ok(event)
    }

    async fn direct_participant_authoring_intent(
        &self,
        intent: &EventIntent,
    ) -> anyhow::Result<EventIntent> {
        if !matches!(
            intent.kind(),
            arkret_sdk::EventKind::MlsCommit
                | arkret_sdk::EventKind::MessageCreate
                | arkret_sdk::EventKind::StrandWatchSet
        ) {
            return Ok(intent.clone());
        }
        let Some(realm) = intent.realm_id_opt() else {
            return Ok(intent.clone());
        };
        let Some(store) = self.state_store.as_ref() else {
            return Ok(intent.clone());
        };
        if store.read(|state| state.realm_collaboration_role(realm.as_str()))
            != Some(arkret_sdk::CollaborationRealmRole::DirectConversation)
        {
            return Ok(intent.clone());
        }
        if matches!(
            intent.kind(),
            arkret_sdk::EventKind::MessageCreate | arkret_sdk::EventKind::StrandWatchSet
        ) {
            let context = store
                .read(|state| state.direct_message_context(realm.as_str(), intent.actor_id()))
                .ok_or_else(|| {
                    anyhow::anyhow!("Direct message current authority is unavailable")
                })?;
            return crate::mls::direct_binding::participant_authoring_intent(
                intent,
                context.authority_source,
                &context.authority_event_ref,
            );
        }
        let peer = store
            .read(|state| state.direct_conversation_peer(realm.as_str()))
            .ok_or_else(|| anyhow::anyhow!("Direct MLS admission requires its exact peer"))?;
        let originals =
            crate::realm_events_engine::own_realm_prefix(&self.http, self.authority()?, realm, 1)
                .await?;
        let outcome = self
            .http
            .direct_conversation_resolve(
                &arkret_sdk::direct_conversation::DirectConversationResolveRequestBody { peer },
            )
            .await?;
        crate::mls::direct_binding::mls_authoring_intent(intent, &originals[0].event, &outcome)
    }

    fn sign_authored_event(
        &self,
        intent: &EventIntent,
        event: &mut arkret_sdk::AuthoredEvent,
        proof_context: crate::event_signer::ProducerProofContext,
    ) -> anyhow::Result<()> {
        if let Some(realm_id) = intent.realm_id_opt() {
            if self.state_store.as_ref().is_some_and(|store| {
                store.read(|state| {
                    state.realm_projection_has_retired_minimal_metadata_marker(realm_id.as_str())
                })
            }) {
                anyhow::bail!(
                    "retired minimal-metadata Realm marker requires verified current governance genesis and schema"
                );
            }
        }
        sign_event_through_message_seam(event, |unsigned| {
            crate::event_signer::sign_sdk_event_with_active_context(unsigned, proof_context)
                .map_err(|error| anyhow::anyhow!("sign SDK Event: {error}"))
        })
    }

    /// Author and sign one write for a protocol endpoint that carries the
    /// Event in its own request body rather than going through the durable
    /// submit queue (`account.update_profile`, `moderation.report`,
    /// `recovery-policy.publish`).
    pub(crate) async fn author_for_direct_submission(
        &self,
        operation: &LocalOperation,
    ) -> anyhow::Result<arkret_sdk::AuthoredEvent> {
        self.author_intent(operation.intent()).await
    }

    /// Author an atomic unit of writes in dependency order.
    ///
    /// A unit's later members name earlier members by their FINAL `event_id` —
    /// a Realm genesis follow-up is scoped to the Realm the create Event
    /// derives — so the unit arrives as a chain of steps rather than a
    /// finished list. Step `n` receives everything steps `0..n` authored.
    pub(crate) async fn author_event_unit(
        &self,
        steps: Vec<EventUnitStep>,
    ) -> anyhow::Result<Vec<arkret_sdk::AuthoredEvent>> {
        let mut authored: Vec<arkret_sdk::AuthoredEvent> = Vec::with_capacity(steps.len());
        let mut chain = UnitAuthoringChain::default();
        for step in steps {
            for intent in step(&authored)? {
                chain.observe(&intent, authored.is_empty());
                self.verify_actor_authority(&intent).await?;
                validate_capability_grant_payload(&intent)?;
                // Every member of a genesis unit is authored under the
                // bootstrap identity suite: the Realm id it is scoped to does
                // not exist until the create Event derives it.
                let digest_suite = if chain.is_genesis_unit() {
                    arkret_sdk::DigestSuite::Sha256
                } else {
                    self.digest_suite_for_intent(&intent)?
                };
                let proof_context = self.event_proof_context(digest_suite).await?;
                let mut event = intent
                    .clone()
                    .author_with_digest_suite(digest_suite)
                    .map_err(|error| anyhow::anyhow!("author unit Event: {error}"))?;
                self.sign_authored_event(&intent, &mut event, proof_context)?;
                authored.push(event);
            }
        }
        validate_authored_unit_shape(&authored)?;
        Ok(authored)
    }

    /// Author an independent batch: every member stands alone, so no member
    /// names another.
    pub(crate) async fn author_independent_events(
        &self,
        intents: Vec<EventIntent>,
    ) -> anyhow::Result<Vec<arkret_sdk::AuthoredEvent>> {
        self.author_event_unit(vec![Box::new(move |_| Ok(intents))])
            .await
    }

    /// Wrap authored Events as the submissions an endpoint body carries.
    ///
    /// Several protocol endpoints (`account.device-pair`, `applet.revoke`)
    /// take producer submissions inside their own request body rather than
    /// through the authority submit rail.
    pub(crate) async fn prepare_initial_submissions(
        &self,
        events: &[arkret_sdk::AuthoredEvent],
    ) -> anyhow::Result<Vec<arkret_wire::EventAdmissionSubmission>> {
        let mut submissions = Vec::with_capacity(events.len());
        for event in events {
            validate_signed_sdk_event_for_submit(event.event(), event.digest_suite())?;
            submissions.push(arkret_wire::EventAdmissionSubmission {
                event: event.event().clone(),
                approval_signatures: None,
            });
        }
        Ok(submissions)
    }

    /// The single submission used by an authority-authored human self-PCR
    /// aggregate operation (for example Agent provisioning).
    ///
    /// `accepted_create` is the verified durable bootstrap evidence for the
    /// PCR this Event belongs to; a PCR history scan is not an
    /// authority-discovery surface.
    pub(crate) fn prepare_authority_authored_self_principal_submission(
        &self,
        event: &arkret_sdk::AuthoredEvent,
        accepted_create: &arkret_sdk::Event,
    ) -> anyhow::Result<arkret_wire::EventAdmissionSubmission> {
        arkret_bootstrap::validate_self_principal_pcr_create(accepted_create, true)
            .map_err(|error| anyhow::anyhow!("accepted self-principal PCR create: {error}"))?;
        anyhow::ensure!(
            event.realm_id == accepted_create.realm_id,
            "authority-authored self-principal Event is scoped to another Realm"
        );
        validate_signed_sdk_event_for_submit(event.event(), event.digest_suite())?;
        Ok(arkret_wire::EventAdmissionSubmission {
            event: event.event().clone(),
            approval_signatures: None,
        })
    }

    // ------------------------------------------------------------ submitting

    /// Submit one user write.
    pub(crate) async fn submit_sdk_event(
        &self,
        operation: &LocalOperation,
    ) -> anyhow::Result<SubmitEventResult> {
        let result = self.submit_sdk_event_inner(operation).await;
        #[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
        if let Err(error) = &result {
            tracing::warn!(kind = %operation.intent().kind().as_str(), error = %error,
                "ordinary Event submission failed");
        }
        result
    }

    async fn submit_sdk_event_inner(
        &self,
        operation: &LocalOperation,
    ) -> anyhow::Result<SubmitEventResult> {
        let intent = operation.intent().clone();
        self.ensure_recovery_material_ready(&intent).await?;
        self.await_application_current(&intent).await?;
        let intent = self.prepare_metadata(intent).await?;
        self.ensure_application_send_gate(&intent).await?;
        self.refresh_direct_message_authority(&intent, None).await?;
        let local_operation_id = operation.local_operation_id().to_string();
        let _single_writer = outbound_submit_lock().lock().await;
        let event = self.author_intent(&intent).await?;
        tracing::debug!(
            local_operation_id = %local_operation_id,
            kind = %event.kind.as_str(),
            event_id = %event.event_id,
            "producer Event authored; enqueueing durable submission"
        );
        let submission = event_submission(&event)?;
        let item = self
            .enqueue_and_drive(QueuedWrite {
                lane: OutboundLane::Standard,
                submission,
                local_operation_id,
                post_accept: PostAccept::None,
                retry_scope: InteractiveRetryScope::Ordinary,
            })
            .await?;
        settled_outbound_result(&item)
    }

    /// Create an explicitly encrypted Circle. Freeze the signed creation
    /// Events and the closed creator selector in one vault CAS before sending.
    pub(crate) async fn submit_circle_creator_durable(
        &self,
        operation: &LocalOperation,
        device_id: &arkret_sdk::DeviceId,
    ) -> anyhow::Result<arkret_sdk::CircleId> {
        let intent = operation.intent();
        self.ensure_recovery_material_ready(intent).await?;
        let _single_writer = outbound_submit_lock().lock().await;
        let parent_revision = self
            .read_parent_membership_revision(
                intent
                    .realm_id_opt()
                    .ok_or_else(|| anyhow::anyhow!("Circle create has no parent Realm"))?,
                intent.actor_id(),
            )
            .await?;
        let create = self.author_intent(intent).await?;
        anyhow::ensure!(
            create.kind == arkret_sdk::EventKind::CircleCreate,
            "Circle creator requires a Circle create operation"
        );
        let circle_id = arkret_sdk::CircleId::from_event_id(create.event_id());
        let scope = arkret_sdk::ScopeRef::Circle {
            realm_id: create.realm_id.clone(),
            circle_id: circle_id.clone(),
        };
        let member = arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::CircleMemberState>::new(
            scope.clone(),
            create.actor_id.clone(),
            arkret_sdk::CircleMemberStatePayload {
                circle_id: circle_id.clone(),
                member_id: create.actor_id.clone(),
                membership: arkret_sdk::CircleMembership::Join,
                parent_membership_revision: Some(parent_revision),
                reason: None,
                effective_at: None,
                expected_membership: arkret_sdk::WirePresence::Missing,
            },
        )?
        .into_intent(arkret_sdk::canonical::normalize_timestamp_canonical(
            crate::clock::now_utc(),
        ))?;
        let member = self.author_intent(&member).await?;
        let discussion = self
            .author_intent(&initial_circle_discussion_intent(&scope, &create.actor_id)?)
            .await?;
        let create_submission = event_submission(&create)?;
        let member_submission = event_submission(&member)?;
        let discussion_submission = event_submission(&discussion)?;
        let creator = creator_intent_for_submission(&create_submission, device_id.clone())?;
        self.outbound(OutboundLane::Standard)?
            .store()
            .freeze_circle_creator_intent(
                creator,
                create_submission.clone(),
                member_submission.clone(),
                discussion_submission.clone(),
            )
            .await?;
        for submission in [create_submission, member_submission, discussion_submission] {
            let local_operation_id = submission.event_id.to_string();
            let item = self
                .enqueue_and_drive(QueuedWrite {
                    lane: OutboundLane::Standard,
                    submission,
                    local_operation_id,
                    post_accept: PostAccept::None,
                    retry_scope: InteractiveRetryScope::Ordinary,
                })
                .await?;
            settled_outbound_result(&item)?;
        }
        Ok(circle_id)
    }

    pub(crate) async fn creator_bootstrap_records(
        &self,
    ) -> anyhow::Result<
        Vec<arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapRecord>,
    > {
        Ok(self
            .outbound(OutboundLane::Standard)?
            .store()
            .creator_records(&arkret_sdk::ActorId::account(self.authority()?.clone()))
            .await?)
    }

    /// Submit already-signed Events one at a time, in order, to the same
    /// governance Station.
    ///
    /// There is no batch submission in the authority protocol: a founding unit
    /// is a sequence of ordinary Events, each answered by its own RealmCommit.
    /// The sequence stops at the first Event the Station refuses.
    pub(crate) async fn submit_signed_sdk_events_in_order(
        &self,
        sdk_events: &[arkret_sdk::AuthoredEvent],
    ) -> anyhow::Result<Vec<SubmitEventResult>> {
        let first = sdk_events
            .first()
            .ok_or_else(|| anyhow::anyhow!("an ordered submission must not be empty"))?;
        self.ensure_recovery_material_ready(&EventIntent::from_authored(first))
            .await?;
        for event in sdk_events {
            self.ensure_application_send_gate(&EventIntent::from_authored(event))
                .await?;
        }
        let _single_writer = outbound_submit_lock().lock().await;
        let mut results = Vec::with_capacity(sdk_events.len());
        for event in sdk_events {
            self.ensure_realm_detail_current(event.realm_id.as_str())
                .await?;
            let submission = event_submission(event)?;
            let item = self
                .enqueue_and_drive(QueuedWrite {
                    lane: OutboundLane::Standard,
                    submission,
                    local_operation_id: event.event_id().to_string(),
                    post_accept: PostAccept::None,
                    retry_scope: InteractiveRetryScope::Ordinary,
                })
                .await?;
            results.push(settled_outbound_result(&item)?);
        }
        Ok(results)
    }

    /// Author independent intents and submit them in order.
    pub(crate) async fn submit_sdk_events_in_order(
        &self,
        intents: Vec<EventIntent>,
    ) -> anyhow::Result<Vec<SubmitEventResult>> {
        let events = self.author_independent_events(intents).await?;
        self.submit_signed_sdk_events_in_order(&events).await
    }

    /// Author a Realm's complete genesis unit, then submit its members in
    /// order through the durable queue.
    ///
    /// The unit is authored before anything is enqueued because its members
    /// name each other by final identity: every follow-up is scoped to the
    /// Realm the create Event derives.
    pub(crate) async fn submit_realm_bootstrap_durable(
        &self,
        steps: Vec<EventUnitStep>,
        local_operation_id: String,
        mls_creator_device: Option<&arkret_sdk::DeviceId>,
    ) -> anyhow::Result<CommittedRealmBootstrap> {
        let _single_writer = outbound_submit_lock().lock().await;
        let events = self.author_event_unit(steps).await?;
        let realm_id = events
            .first()
            .ok_or_else(|| anyhow::anyhow!("Realm bootstrap unit is empty"))?
            .realm_id
            .clone();
        let unit = arkret_models_collaboration::authority_commit::OrdinaryRealmBootstrapUnitSubmission {
            unit_kind: arkret_models_collaboration::authority_commit::OrdinaryRealmBootstrapUnitKind::OrdinaryRealmBootstrap,
            idempotency_key: serde_json::from_value(serde_json::json!(local_operation_id.strip_prefix("ak:operation:").ok_or_else(|| anyhow::anyhow!("bootstrap operation must be a canonical OperationId"))?))?,
            events: self.prepare_initial_submissions(&events).await?,
        };
        let submission = QueuedSubmission::realm_bootstrap(unit)?;
        if let Some(device_id) = mls_creator_device {
            let intent = creator_intent_for_submission(&submission, device_id.clone())?;
            self.outbound(OutboundLane::Standard)?
                .store()
                .freeze_realm_creator_intent(intent, submission.clone())
                .await?;
        }
        let item = self
            .enqueue_and_drive(QueuedWrite {
                lane: OutboundLane::Standard,
                submission,
                local_operation_id,
                post_accept: PostAccept::None,
                retry_scope: InteractiveRetryScope::RealmBootstrap,
            })
            .await?;
        let garth::SubmissionState::UnitCommitted { outcome } = &item.submission.state else {
            settled_outbound_result(&item)?;
            anyhow::bail!("Realm bootstrap completed without its aggregate outcome");
        };
        let arkret_models_collaboration::authority_commit::SelfAuthoritySubmitOutcome::OrdinaryRealmBootstrap(outcome) = outcome.as_ref() else {
            anyhow::bail!("Realm bootstrap returned a different aggregate unit");
        };
        outcome.validate()?;
        Ok(CommittedRealmBootstrap {
            realm_id,
            first_commit: outcome.commits[0].clone(),
        })
    }

    /// Resume the two independent product Events before activating MLS. The
    /// vault CAS chooses each original signed submission across holder races.
    pub(crate) async fn ensure_creator_realm_default_discussion(
        &self,
        realm: &arkret_sdk::RealmId,
    ) -> anyhow::Result<arkret_sdk::StrandId> {
        use crate::outbound_store::CreatorDiscussionStep;
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        let intent = self
            .creator_bootstrap_intent(&scope)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("default discussion requires a durable Realm creator")
            })?;
        let store = self.outbound(OutboundLane::Standard)?.store().clone();
        if let Some(strand) = store.completed_creator_discussion(realm).await? {
            return Ok(strand);
        }
        let _single_writer = outbound_submit_lock().lock().await;
        // The foreground or another holder may have completed while waiting.
        if let Some(strand) = store.completed_creator_discussion(realm).await? {
            return Ok(strand);
        }
        let actor = intent.owner_actor_id().signing_principal_id().as_str();
        let mut strand_id: Option<String> = None;
        for step in [CreatorDiscussionStep::Create, CreatorDiscussionStep::Select] {
            let submission =
                if let Some(original) = store.creator_discussion_submission(realm, step).await? {
                    original
                } else {
                    let operation = match step {
                        CreatorDiscussionStep::Create => {
                            crate::operation::ak_ops::initial_default_discussion_strand_create(
                                realm.as_str(),
                                actor,
                            )?
                        }
                        CreatorDiscussionStep::Select => {
                            crate::operation::ak_ops::realm_set_default_strand(
                                realm.as_str(),
                                actor,
                                strand_id.as_ref().ok_or_else(|| {
                                    anyhow::anyhow!("default Strand has not committed")
                                })?,
                            )?
                        }
                    }
                    .build_sdk_event("inkson")?;
                    self.ensure_recovery_material_ready(operation.intent())
                        .await?;
                    self.ensure_application_send_gate(operation.intent())
                        .await?;
                    self.refresh_direct_message_authority(operation.intent(), None)
                        .await?;
                    let signed = self.author_intent(operation.intent()).await?;
                    store
                        .freeze_creator_discussion_step(realm, step, event_submission(&signed)?)
                        .await?
                };
            let id = submission.event_id.clone();
            let item = self
                .enqueue_and_drive(QueuedWrite {
                    lane: OutboundLane::Standard,
                    submission,
                    local_operation_id: id.to_string(),
                    post_accept: PostAccept::None,
                    retry_scope: InteractiveRetryScope::Ordinary,
                })
                .await?;
            settled_outbound_result(&item)?;
            if matches!(step, CreatorDiscussionStep::Create) {
                strand_id = Some(arkret_sdk::StrandId::from_event_id(&id).into_string());
            }
        }
        Ok(arkret_sdk::StrandId::new(strand_id.ok_or_else(|| {
            anyhow::anyhow!("default Strand missing")
        })?)?)
    }

    pub(crate) async fn creator_bootstrap_record(
        &self,
        scope: &arkret_sdk::ScopeRef,
    ) -> anyhow::Result<
        Option<arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapRecord>,
    > {
        Ok(self
            .outbound(OutboundLane::Standard)?
            .store()
            .creator_record(
                &arkret_sdk::ActorId::account(self.authority()?.clone()),
                scope,
            )
            .await?)
    }

    pub(crate) async fn creator_bootstrap_intent(
        &self,
        scope: &arkret_sdk::ScopeRef,
    ) -> anyhow::Result<
        Option<arkret_models_collaboration::mls_creator_bootstrap::MlsCreatorBootstrapIntent>,
    > {
        Ok(self
            .outbound(OutboundLane::Standard)?
            .store()
            .creator_intent(
                &arkret_sdk::ActorId::account(self.authority()?.clone()),
                scope,
            )
            .await?)
    }

    /// Submit the founding unit of a Direct Conversation.
    ///
    /// Freeze all four signed Events in one durable atomic submission. Its
    /// accepted result contains every original Commit in the submitted order.
    pub(crate) async fn submit_direct_conversation_founding_durable(
        &self,
        events: Vec<arkret_sdk::AuthoredEvent>,
    ) -> anyhow::Result<Vec<SubmitEventResult>> {
        let _single_writer = outbound_submit_lock().lock().await;
        let idempotency_key = arkret_wire::UuidV7::new(arkret_sdk::identifiers::uuid_v7_at(
            crate::clock::now_unix_ms(),
        ))?;
        let local_operation_id = format!("ak:operation:{}", idempotency_key.as_uuid());
        let unit = arkret_models_collaboration::authority_commit::DirectConversationFoundingUnitSubmission {
            unit_kind: arkret_models_collaboration::authority_commit::DirectConversationFoundingUnitKind::DirectConversationFounding,
            idempotency_key,
            events: self.prepare_initial_submissions(&events).await?.try_into()
                .map_err(|_| anyhow::anyhow!("Direct Conversation founding requires exactly four Events"))?,
        };
        let item = self
            .enqueue_and_drive(QueuedWrite {
                lane: OutboundLane::Standard,
                submission: QueuedSubmission::direct_conversation_founding(unit)?,
                local_operation_id,
                post_accept: PostAccept::None,
                retry_scope: InteractiveRetryScope::RealmBootstrap,
            })
            .await?;
        let garth::SubmissionState::UnitCommitted { outcome } = &item.submission.state else {
            settled_outbound_result(&item)?;
            anyhow::bail!("Direct Conversation founding completed without its aggregate outcome");
        };
        let arkret_models_collaboration::authority_commit::SelfAuthoritySubmitOutcome::DirectConversationFounding(outcome) = outcome.as_ref() else {
            anyhow::bail!("Direct Conversation founding returned a different aggregate unit");
        };
        Ok(events
            .iter()
            .zip(&outcome.commits)
            .map(|(event, commit)| {
                SubmitEventResult::committed(event.event_id().to_string(), commit.clone())
            })
            .collect())
    }

    /// Freeze and durably persist a fully signed scheduled message before any
    /// submission I/O. Resolving or editing the plan after this boundary is
    /// forbidden.
    pub(crate) async fn submit_scheduled_send_event(
        &self,
        scheduled_send_id: arkret_identifiers::ScheduledSendId,
        submission: QueuedSubmission,
    ) -> anyhow::Result<SubmitEventResult> {
        let _single_writer = outbound_submit_lock().lock().await;
        let submission = self
            .outbound(OutboundLane::Standard)?
            .store()
            .freeze_scheduled_dispatch(scheduled_send_id.clone(), submission)
            .await?;
        let item = self
            .enqueue_and_drive(QueuedWrite {
                lane: OutboundLane::Standard,
                submission,
                local_operation_id: scheduled_send_id.to_string(),
                post_accept: PostAccept::None,
                retry_scope: InteractiveRetryScope::Ordinary,
            })
            .await?;
        settled_outbound_result(&item)
    }

    /// Submit one `ak.mls.commit` together with its Welcome deliveries as a
    /// single atomic authority submission, then install the staged group state
    /// this device already holds.
    ///
    /// The Welcomes are producer-signed delivery objects, not Events: the
    /// Station either commits the Event and accepts every delivery, or neither.
    /// Installation happens as soon as the commit is authority-signed; the
    /// protocol has no recipient acknowledgement to wait for.
    pub(crate) async fn submit_mls_commit(
        &self,
        commit: arkret_sdk::AuthoredEvent,
        welcomes: Vec<arkret_wire::MlsWelcomeDelivery>,
        device_id: arkret_sdk::DeviceId,
        authority_hints: Vec<crate::mls::governance_proof::MlsLeafAuthorityHint>,
        state_store: &crate::runtime::input::StateStoreHandle,
        mut staged_checkpoint: crate::mls::persistence::MlsLocalCheckpointEnvelope,
    ) -> anyhow::Result<SubmitEventResult> {
        anyhow::ensure!(
            commit.kind == arkret_sdk::EventKind::MlsCommit,
            "the MLS commit lane carries only ak.mls.commit"
        );
        let authority = self.authority()?.clone();
        let _single_writer = outbound_submit_lock().lock().await;
        validate_signed_sdk_event_for_submit(commit.event(), commit.digest_suite())?;
        let mut welcomes = welcomes;
        welcomes.sort_by(|left, right| left.welcome_id.cmp(&right.welcome_id));
        let submission = QueuedSubmission::new(arkret_wire::AuthoritySubmitRequest::MlsCommit(
            arkret_wire::MlsCommitSubmission {
                commit_event: commit.event().clone(),
                welcomes,
                idempotency_key: arkret_wire::UuidV7::new(arkret_sdk::identifiers::uuid_v7_at(
                    crate::clock::now_unix_ms(),
                ))
                .map_err(anyhow::Error::from)?,
            },
        ))
        .map_err(anyhow::Error::from)?;
        let payload: arkret_sdk::MlsCommitPayload =
            serde_json::from_value(serde_json::to_value(&commit.event().payload)?)?;
        staged_checkpoint.group_state_event_id =
            payload.governance_binding().base_group_state_ref().cloned();
        if let Some(base) =
            state_store.read(|store| store.mls_checkpoint_for_scope(&commit.event().scope_ref))
        {
            staged_checkpoint.admission_epoch = base.admission_epoch;
            staged_checkpoint.epoch_started_at = base.epoch_started_at;
            staged_checkpoint.app_messages_observed = base.app_messages_observed;
        }
        let outbound = self.outbound(OutboundLane::MlsCommit)?;
        outbound
            .store()
            .freeze_mls_commit(submission.clone(), staged_checkpoint)
            .await?;
        self.prepare_frozen_mls_checkpoint(outbound.store(), commit.event(), state_store)
            .await?;
        let item = self
            .enqueue_and_drive(QueuedWrite {
                lane: OutboundLane::MlsCommit,
                submission,
                local_operation_id: commit.event_id().to_string(),
                post_accept: PostAccept::InstallMlsCommit {
                    authority,
                    device_id,
                    authority_hints,
                    state_store: state_store.clone(),
                },
                retry_scope: InteractiveRetryScope::Ordinary,
            })
            .await?;
        settled_outbound_result(&item)
    }

    async fn prepare_frozen_mls_checkpoint(
        &self,
        vault: &InksonOutboundStore,
        event: &arkret_sdk::Event,
        state: &crate::runtime::input::StateStoreHandle,
    ) -> anyhow::Result<()> {
        let Some(checkpoint) = vault.mls_commit_checkpoint(&event.event_id).await? else {
            return Ok(());
        };
        let payload: arkret_sdk::MlsCommitPayload =
            serde_json::from_value(serde_json::to_value(&event.payload)?)?;
        let binding = payload.governance_binding();
        let local = state
            .read(|store| store.mls_checkpoint_for_scope(binding.effective_scope()))
            .ok_or_else(|| anyhow::anyhow!("MLS retry has no installed private base"))?;
        if local.epoch >= binding.next_epoch() && local.group_state_event_id.is_some() {
            return Ok(());
        }
        anyhow::ensure!(
            local.epoch == binding.previous_epoch()
                && local.group_id == checkpoint.group_id
                && local.group_state_event_id.as_ref() == binding.base_group_state_ref(),
            "MLS retry private base differs from its original signed unit"
        );
        let endpoint = crate::secure_key_store::active_device_seed_scope()
            .ok_or_else(|| anyhow::anyhow!("MLS retry requires the original endpoint"))?;
        anyhow::ensure!(
            &endpoint.authority == self.authority()?,
            "MLS retry endpoint belongs to another Account"
        );
        let secure = crate::secure_key_store::default_secure_key_store("inkson");
        let secret = crate::mls::runtime::load_device_checkpoint_secret(
            secure.as_ref(),
            &endpoint.authority,
            &endpoint.device_id,
        )?;
        let group = crate::mls::persistence::restore_envelope(&local, &secret, local.epoch)?;
        let frozen: arkret_models_crypto::MlsGroupStateRecord = serde_json::from_slice(
            &crate::mls::persistence::decrypt_envelope(&checkpoint, &secret)?,
        )?;
        let resumed =
            group.resume_frozen_pending_commit(&frozen, &payload.commit_envelope()?, binding)?;
        let record = resumed.export_state_record()?;
        let mut salt = [0_u8; 16];
        getrandom::fill(&mut salt)?;
        let mut checkpoint = crate::mls::persistence::encrypt_state(
            &checkpoint.realm_id,
            &record.group_id,
            record.epoch,
            &serde_json::to_vec(&record)?,
            &secret,
            &salt,
        );
        checkpoint.group_state_event_id = local.group_state_event_id;
        checkpoint.admission_epoch = local.admission_epoch;
        checkpoint.epoch_started_at = local.epoch_started_at;
        checkpoint.app_messages_observed = local.app_messages_observed;
        let barrier = state.write(|store| {
            store
                .save_mls_checkpoint_for_scope(binding.effective_scope(), checkpoint)
                .map_err(anyhow::Error::msg)?;
            store.begin_durable_flush()
        })?;
        barrier.wait().await?;
        Ok(())
    }

    /// Whether this holder already owns an unfinished MLS commit submission
    /// for the Realm. A queued commit freezes one epoch transition and its
    /// Welcome deliveries as one atomic unit; authoring another membership
    /// change while it waits would consume a second one-time KeyPackage and
    /// race the predecessor epoch.
    pub(crate) async fn has_pending_mls_admission_for_realm(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<bool> {
        let snapshot = self.outbound(OutboundLane::MlsCommit)?.snapshot().await?;
        Ok(pending_mls_commit_for_realm_from_snapshot(
            &snapshot,
            realm_id,
            |event| {
                self.state_store.as_ref().is_some_and(|state| {
                    state.read(|store| {
                        let Ok(payload) = serde_json::from_value::<arkret_sdk::MlsCommitPayload>(
                            Value::Object(event.payload.clone().into_iter().collect()),
                        ) else {
                            return false;
                        };
                        let binding = payload.governance_binding();
                        let Ok(group_id) = binding.mls_group_id() else {
                            return false;
                        };
                        store
                            .mls_checkpoint_for_scope_and_group(
                                binding.effective_scope(),
                                group_id.as_str(),
                            )
                            .is_some_and(|checkpoint| {
                                checkpoint.epoch >= binding.next_epoch()
                                    && checkpoint.group_state_event_id.is_some()
                            })
                    })
                })
            },
        ))
    }

    /// Whether the standard lane already owns an `ak.mls.genesis` attempt for
    /// this Realm that is active or already committed. Treating the window
    /// between commit and local projection as absence would author a second
    /// activation.
    pub(crate) async fn has_durable_mls_genesis_for_realm(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<bool> {
        let snapshot = self.outbound(OutboundLane::Standard)?.snapshot().await?;
        Ok(durable_mls_genesis_for_realm_from_snapshot(
            &snapshot, realm_id,
        ))
    }

    // ----------------------------------------------------------- queue drive

    /// Resolve the replay fence for every unsettled item in one drain pass.
    ///
    /// garth's engine has no fence hook, so the host resolves the decisions
    /// itself and withdraws the quarantined items before anything is
    /// forwarded.
    async fn resolve_queue_generation_fence(
        &self,
        outbound: &InksonOutboundEngine,
    ) -> anyhow::Result<ResolvedQueueGenerationFence> {
        let mut decisions = BTreeMap::new();
        for item in outbound.snapshot().await?.items {
            if !is_unsettled(item.status) {
                continue;
            }
            decisions.insert(
                item.event_id().clone(),
                match item.request() {
                    arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(unit) => {
                        let mut decision = GenerationFenceDecision::Current;
                        for submission in &unit.events {
                            let candidate = queued_event_generation_decision(&submission.event)?;
                            if candidate != GenerationFenceDecision::Current {
                                decision = candidate;
                                break;
                            }
                        }
                        decision
                    }
                    arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::DirectConversationFounding(unit) => {
                        let mut decision = GenerationFenceDecision::Current;
                        for submission in &unit.events {
                            let candidate = queued_event_generation_decision(&submission.event)?;
                            if candidate != GenerationFenceDecision::Current {
                                decision = candidate;
                                break;
                            }
                        }
                        decision
                    }
                    _ => queued_event_generation_decision(queued_event(&item))?,
                },
            );
        }
        Ok(ResolvedQueueGenerationFence::new(decisions))
    }

    /// The creator record lives in the standard vault. MLS control items
    /// in the other lane must re-read that same terminal fence before retry.
    async fn cancel_quarantined_creator_items(
        &self,
        outbound: &InksonOutboundEngine,
    ) -> anyhow::Result<usize> {
        let standard = self.outbound(OutboundLane::Standard)?.store().clone();
        let owner = arkret_sdk::ActorId::account(self.authority()?.clone());
        let mut stopped = 0;
        for item in outbound.snapshot().await?.items {
            if item.status.is_terminal() {
                continue;
            }
            let event = queued_event(&item);
            if standard
                .creator_record(&owner, &event.scope_ref)
                .await?
                .is_some_and(|record| record.quarantine_diagnostic().is_some())
                && outbound.cancel(item.event_id().clone()).await?
            {
                stopped += 1;
            }
        }
        Ok(stopped)
    }

    async fn ensure_creator_quarantine_replay_fence(
        &self,
        request: &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest,
    ) -> anyhow::Result<()> {
        use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
        let events: Vec<&arkret_sdk::Event> = match request {
            SelfAuthoritySubmitRequest::Event(value) => vec![&value.event],
            SelfAuthoritySubmitRequest::MlsCommit(value) => vec![&value.commit_event],
            SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(value) => {
                value.events.iter().map(|event| &event.event).collect()
            }
            SelfAuthoritySubmitRequest::DirectConversationFounding(value) => {
                value.events.iter().map(|event| &event.event).collect()
            }
            SelfAuthoritySubmitRequest::MembershipCompensation(value) => {
                vec![&value.event_submission.event]
            }
        };
        let standard = self.outbound(OutboundLane::Standard)?.store().clone();
        for event in events {
            standard
                .ensure_creator_automatic_replay_allowed(&event.scope_ref)
                .await?;
        }
        Ok(())
    }

    /// Withdraw every quarantined item so the engine never forwards it.
    async fn quarantine_superseded_items(
        &self,
        outbound: &InksonOutboundEngine,
        fence: &ResolvedQueueGenerationFence,
    ) -> anyhow::Result<usize> {
        let mut quarantined = 0usize;
        for item in outbound.snapshot().await?.items {
            if item.status != SendQueueStatus::Queued {
                continue;
            }
            let GenerationFenceDecision::Quarantine { reason } = fence.evaluate(&item)? else {
                continue;
            };
            tracing::warn!(
                event_id = %item.event_id(),
                %reason,
                "durable outbound item quarantined by the authoring-generation fence"
            );
            if outbound.cancel(item.event_id().clone()).await? {
                quarantined = quarantined.saturating_add(1);
            }
        }
        Ok(quarantined)
    }

    /// Enqueue one frozen submission and drive the queue until this item has
    /// Persist frozen bytes and their holder-local identity without forwarding.
    async fn persist_queued_write(
        &self,
        write: &QueuedWrite,
        outbound: &InksonOutboundEngine,
    ) -> anyhow::Result<Option<garth::SendQueueItem>> {
        let event_id = &write.submission.event_id;
        let event = write.submission.primary_event();
        let existing = outbound
            .snapshot()
            .await?
            .items
            .into_iter()
            .find(|item| item.event_id() == event_id);
        if let Some(item) = &existing {
            ensure_exact_queued_request(&item.submission, &write.submission)?;
        }
        match existing {
            // The Station already answered for these exact bytes. Authoring is
            // one-shot, so a repeat call for the same operation is the same
            // Event, and its committed answer is the answer.
            Some(item) if item.status.is_terminal() => {
                if let Some(state_store) = self.state_store.as_ref() {
                    state_store.write(|store| {
                        reconcile_settled_outbound_item(store, &item);
                    });
                }
                return Ok(Some(item));
            }
            Some(_) => {}
            None => {
                outbound
                    .enqueue(write.submission.clone())
                    .await
                    .map_err(anyhow::Error::from)?;
            }
        }
        if let Some(state_store) = self.state_store.as_ref() {
            state_store.write(|store| {
                record_queued_operation_identity(store, &write.local_operation_id, event);
            });
        }

        // A concurrent drain may have settled the item between durable enqueue
        // and the holder-local identity join. Reconcile that answer as well.
        let settled = outbound
            .snapshot()
            .await?
            .items
            .into_iter()
            .find(|item| item.event_id() == event_id && item.status.is_terminal());
        if let (Some(state_store), Some(item)) = (self.state_store.as_ref(), settled.as_ref()) {
            state_store.write(|store| {
                reconcile_settled_outbound_item(store, item);
            });
        }
        Ok(settled)
    }

    async fn enqueue_and_drive(&self, write: QueuedWrite) -> anyhow::Result<garth::SendQueueItem> {
        let outbound = self.outbound(write.lane)?;
        if let Some(item) = self.persist_queued_write(&write, &outbound).await? {
            return Ok(item);
        }
        let QueuedWrite {
            submission,
            local_operation_id,
            post_accept,
            retry_scope,
            ..
        } = write;
        let event_id = submission.event_id;

        self.cancel_quarantined_creator_items(&outbound).await?;
        let authority_client = self.authority_client().await?;
        let options = arkret_sdk::http_client::ClientRequestOptions::new()
            .request_id(event_id.to_string())
            .idempotency_key(event_id.to_string());
        let mut interactive_retries = 0_u8;
        loop {
            let fence = self.resolve_queue_generation_fence(&outbound).await?;
            self.quarantine_superseded_items(&outbound, &fence).await?;
            let replay_store = outbound.store().clone();
            match outbound
                .submit_next_checked(&authority_client, &options, |request| async move {
                    self.ensure_creator_quarantine_replay_fence(&request)
                        .await
                        .map_err(|error| error.to_string())?;
                    if let Some(decision) = self
                        .ensure_creator_genesis_replay_gate(&request)
                        .await
                        .map_err(|error| error.to_string())?
                    {
                        replay_store
                            .remember_creator_absence(decision)
                            .map_err(|error| error.to_string())?;
                    }
                    self.ensure_queued_application_send_gate(&request)
                        .await
                        .map_err(|error| error.to_string())
                })
                .await
                .map_err(anyhow::Error::from)?
            {
                OutboundEngineOutcome::Committed { item, commit }
                    if item.event_id() == &event_id =>
                {
                    self.run_post_accept(&post_accept, &item, &commit).await?;
                    if let Some(state_store) = self.state_store.as_ref() {
                        state_store.write(|store| {
                            reconcile_settled_outbound_item(store, &item);
                        });
                    }
                    return Ok(*item);
                }
                OutboundEngineOutcome::Rejected { item, .. } if item.event_id() == &event_id => {
                    if let Some(state_store) = self.state_store.as_ref() {
                        state_store.write(|store| {
                            reconcile_settled_outbound_item(store, &item);
                        });
                    }
                    return Ok(*item);
                }
                OutboundEngineOutcome::Failed {
                    item,
                    error,
                    problem,
                } if item.event_id() == &event_id => {
                    let context = format!("durable submission of {event_id} failed");
                    return Err(match problem {
                        Some(problem) => anyhow::Error::new(arkret_sdk::http_client::Error::Api {
                            status: problem.status,
                            error: problem,
                        })
                        .context(context),
                        None => anyhow::anyhow!("{context}: {error}"),
                    });
                }
                OutboundEngineOutcome::Retry { item, delay } if item.event_id() == &event_id => {
                    if retry_scope == InteractiveRetryScope::RealmBootstrap
                        && !is_retryable_authority_item(&item)
                        && !crate::api_error::is_realm_bootstrap_temporarily_unavailable_detail(
                            item.last_error.as_deref(),
                        )
                    {
                        return Err(DurablyQueuedError {
                            operation_id: local_operation_id,
                            reason: item.last_error.clone(),
                        }
                        .into());
                    }
                    if interactive_retries >= 4 {
                        return Err(DurablyQueuedError {
                            operation_id: local_operation_id,
                            reason: item.last_error.clone(),
                        }
                        .into());
                    }
                    interactive_retries = interactive_retries.saturating_add(1);
                    crate::runtime_helpers::sleep_for(
                        delay.saturating_add(Duration::from_millis(25)),
                    )
                    .await;
                }
                OutboundEngineOutcome::Idle => {
                    // Either an earlier item is backing off, or this one was
                    // quarantined. Both leave the write durably queued.
                    return Err(DurablyQueuedError {
                        operation_id: local_operation_id,
                        reason: None,
                    }
                    .into());
                }
                // An older item in the same lane settled or backed off. Keep
                // draining until this write's turn comes.
                OutboundEngineOutcome::Committed { item, .. }
                | OutboundEngineOutcome::Rejected { item, .. }
                | OutboundEngineOutcome::Failed { item, .. } => {
                    self.settle_other_item(&item);
                }
                OutboundEngineOutcome::Retry { item, delay } => {
                    if retry_scope == InteractiveRetryScope::RealmBootstrap
                        && !is_retryable_authority_item(&item)
                        && !crate::api_error::is_realm_bootstrap_temporarily_unavailable_detail(
                            item.last_error.as_deref(),
                        )
                    {
                        return Err(DurablyQueuedError {
                            operation_id: local_operation_id,
                            reason: item.last_error.clone().map(|reason| {
                                format!(
                                    "blocked by earlier operation {}: {reason}",
                                    item.event_id()
                                )
                            }),
                        }
                        .into());
                    }
                    if interactive_retries >= 4 {
                        let blocking = item.event_id().to_string();
                        return Err(DurablyQueuedError {
                            operation_id: local_operation_id,
                            reason: item.last_error.clone().map(|reason| {
                                format!("blocked by earlier operation {blocking}: {reason}")
                            }),
                        }
                        .into());
                    }
                    interactive_retries = interactive_retries.saturating_add(1);
                    crate::runtime_helpers::sleep_for(
                        delay.saturating_add(Duration::from_millis(25)),
                    )
                    .await;
                }
            }
        }
    }

    fn settle_other_item(&self, item: &garth::SendQueueItem) {
        if let Some(state_store) = self.state_store.as_ref() {
            state_store.write(|store| {
                reconcile_settled_outbound_item(store, item);
            });
        }
    }

    async fn run_post_accept(
        &self,
        post_accept: &PostAccept,
        item: &garth::SendQueueItem,
        commit: &arkret_wire::RealmCommit,
    ) -> anyhow::Result<()> {
        match post_accept {
            PostAccept::None => Ok(()),
            PostAccept::InstallMlsCommit {
                authority,
                device_id,
                authority_hints,
                state_store,
            } => {
                let committed_event = arkret_wire::CommittedEventFullView {
                    commit: commit.clone(),
                    event: queued_event(item).clone(),
                };
                let installed = crate::mls::runtime::install_accepted_transition(
                    state_store,
                    authority,
                    device_id,
                    &committed_event,
                    authority_hints,
                )
                .await
                .map_err(|error| {
                    anyhow::anyhow!("install the committed MLS transition: {error}")
                })?;
                if installed != crate::mls::runtime::MlsInstallOutcome::BaseEpochMissing {
                    self.outbound(OutboundLane::MlsCommit)?
                        .store()
                        .retire_mls_commit_checkpoint(&item.submission.event_id)
                        .await?;
                }
                Ok(())
            }
        }
    }

    /// Resume queued writes for this account without a new user send.
    ///
    /// The account runner calls this after it has rebuilt an authenticated
    /// client, so process and browser restarts eventually drain pending work.
    pub(crate) async fn drain_outbound(&self) -> anyhow::Result<usize> {
        self.drain_lane(OutboundLane::Standard).await
    }

    /// Resume queued `ak.mls.commit` submissions.
    ///
    /// Once authority acceptance is durable, merge the exact staged own
    /// Commit and recover leaf attribution from the signed historical roster.
    pub(crate) async fn drain_mls_outbound(&self) -> anyhow::Result<usize> {
        let completed = self.drain_lane(OutboundLane::MlsCommit).await?;
        self.recover_committed_mls_outbound().await?;
        Ok(completed)
    }

    async fn recover_committed_mls_outbound(&self) -> anyhow::Result<()> {
        let Some(state) = self.state_store.as_ref() else {
            return Ok(());
        };
        let Some(endpoint) = crate::secure_key_store::active_device_seed_scope() else {
            return Ok(());
        };
        anyhow::ensure!(
            &endpoint.authority == self.authority()?,
            "MLS recovery endpoint belongs to another Account"
        );
        let api = crate::transport::TransportClient::from_http(
            self.http.clone(),
            crate::transport::RequestContext::new(""),
        );
        let snapshot = self.outbound(OutboundLane::MlsCommit)?.snapshot().await?;
        for item in snapshot.items {
            let garth::SubmissionState::Committed { commit, .. } = &item.submission.state else {
                continue;
            };
            let accepted = arkret_wire::CommittedEventFullView {
                commit: (**commit).clone(),
                event: queued_event(&item).clone(),
            };
            match crate::mls::runtime::install_recovered_outbound_commit(
                &api,
                state,
                &endpoint.authority,
                &endpoint.device_id,
                &accepted,
            )
            .await
            {
                Ok(
                    crate::mls::runtime::MlsInstallOutcome::Applied
                    | crate::mls::runtime::MlsInstallOutcome::AlreadyCurrent,
                ) => {
                    self.outbound(OutboundLane::MlsCommit)?
                        .store()
                        .retire_mls_commit_checkpoint(&accepted.event.event_id)
                        .await?;
                }
                Ok(crate::mls::runtime::MlsInstallOutcome::BaseEpochMissing) => {}
                Err(error) => {
                    tracing::warn!(event = %accepted.event.event_id, %error, "accepted outbound MLS Commit remains pending local installation")
                }
            }
        }
        Ok(())
    }

    async fn drain_lane(&self, lane: OutboundLane) -> anyhow::Result<usize> {
        let _single_writer = outbound_submit_lock().lock().await;
        let outbound = self.outbound(lane)?;
        if lane == OutboundLane::MlsCommit
            && let Some(state) = self.state_store.as_ref()
        {
            for item in outbound.snapshot().await?.items {
                if is_unsettled(item.status) || item.status == SendQueueStatus::Committed {
                    self.prepare_frozen_mls_checkpoint(
                        outbound.store(),
                        queued_event(&item),
                        state,
                    )
                    .await?;
                }
            }
        }
        // A previous task can be dropped after the queue durably records a
        // commit but before the caller updates its optimistic row. Replay that
        // join before draining active work.
        if let Some(state_store) = self.state_store.as_ref() {
            let snapshot = outbound.snapshot().await?;
            state_store.write(|store| {
                for item in &snapshot.items {
                    reconcile_settled_outbound_item(store, item);
                }
            });
        }
        let authority_client = self.authority_client().await?;
        let mut completed = 0usize;
        loop {
            completed =
                completed.saturating_add(self.cancel_quarantined_creator_items(&outbound).await?);
            let fence = self.resolve_queue_generation_fence(&outbound).await?;
            completed = completed
                .saturating_add(self.quarantine_superseded_items(&outbound, &fence).await?);
            let options = arkret_sdk::http_client::ClientRequestOptions::new();
            let replay_store = outbound.store().clone();
            match outbound
                .submit_next_checked(&authority_client, &options, |request| async move {
                    self.ensure_creator_quarantine_replay_fence(&request)
                        .await
                        .map_err(|error| error.to_string())?;
                    if let Some(decision) = self
                        .ensure_creator_genesis_replay_gate(&request)
                        .await
                        .map_err(|error| error.to_string())?
                    {
                        replay_store
                            .remember_creator_absence(decision)
                            .map_err(|error| error.to_string())?;
                    }
                    self.ensure_queued_application_send_gate(&request)
                        .await
                        .map_err(|error| error.to_string())
                })
                .await
                .map_err(anyhow::Error::from)?
            {
                OutboundEngineOutcome::Committed { item, .. }
                | OutboundEngineOutcome::Rejected { item, .. }
                | OutboundEngineOutcome::Failed { item, .. } => {
                    self.settle_other_item(&item);
                    completed = completed.saturating_add(1);
                }
                OutboundEngineOutcome::Idle | OutboundEngineOutcome::Retry { .. } => {
                    return Ok(completed);
                }
            }
        }
    }

    // ------------------------------------------------------------- authoring
    //                                                                 gates

    /// A newly selected Realm may hydrate after its composer mounts. Wait
    /// within the existing 15-second current-refresh window before sealing
    /// or authoring; an incomplete cut never means plaintext permission.
    async fn await_application_current(&self, intent: &EventIntent) -> anyhow::Result<()> {
        if !matches!(
            intent.scope_ref(),
            arkret_sdk::ScopeRef::Realm { .. } | arkret_sdk::ScopeRef::Circle { .. }
        ) || crate::mls::send_gate::ApplicationBody::of_event(intent.kind(), intent.payload())?
            .is_none()
        {
            return Ok(());
        }
        let Some(store) = self.state_store.as_ref() else {
            return Ok(());
        };
        let authority = self.authority()?;
        let realm = intent
            .realm_id_opt()
            .ok_or_else(|| anyhow::anyhow!("application scope has no Realm"))?;
        for _ in 0..60 {
            anyhow::ensure!(
                store.read(|state| state.active_authority().as_ref() == Some(authority)),
                "application current crossed its Account fence"
            );
            if store.read(crate::state::LocalStateStore::current_reset_required) {
                crate::runtime_helpers::sleep_for(Duration::from_millis(250)).await;
                continue;
            }
            let location = store.read(crate::state::LocalStateStore::current_index_location);
            let index = crate::state::CurrentIndex::open_committed(authority, location, || {
                store.read(|state| {
                    anyhow::ensure!(
                        state.active_authority().as_ref() == Some(authority),
                        "application current crossed its Account fence"
                    );
                    Ok(state.current_generation())
                })
            })
            .await?;
            if index.read_complete_cut(realm.as_str()).await?.is_some() {
                anyhow::ensure!(
                    store.read(|state| state.active_authority().as_ref() == Some(authority)),
                    "application current crossed its Account fence"
                );
                if store.read(crate::state::LocalStateStore::current_reset_required) {
                    continue;
                }
                return Ok(());
            }
            crate::runtime_helpers::sleep_for(Duration::from_millis(250)).await;
        }
        anyhow::bail!("application current is unavailable: Realm baseline is still incomplete")
    }

    /// Refuse to activate or enter end-to-end encryption before this account
    /// can recover its MLS material.
    ///
    /// Encryption is no longer a Realm-create choice: a scope becomes
    /// encrypted when its `ak.mls.genesis` commits. So the gate fires exactly
    /// on authoring that activation, and on joining a scope that already has
    /// one.
    async fn ensure_recovery_material_ready(&self, intent: &EventIntent) -> anyhow::Result<()> {
        if !self.event_enters_encrypted_scope(intent).await? {
            return Ok(());
        }
        let authority = self.authority()?;
        let cache_key = recovery_gate_cache_key(authority, intent);
        let active_endpoint = crate::secure_key_store::active_device_seed_scope();
        if cache_key.is_some() {
            anyhow::ensure!(
                active_endpoint.as_ref().is_some_and(|endpoint| {
                    endpoint.authority == *authority
                        && recovery_gate_account_cache_key(authority, endpoint.device_id.as_str())
                            == cache_key
                }) && self.state_store.as_ref().is_some_and(|store| {
                    store.read(|state| state.active_authority().as_ref() == Some(authority))
                }),
                "recovery-material gate requires the active Account and Device context"
            );
        }
        let mut accepted_principal_control = cache_key.as_ref().is_some_and(|key| {
            verified_recovery_gate_cache()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(key)
        });
        // Cold boot may reach authoring before the UI recovery effect has
        // verified the durable evidence. Resolve that same evidence here;
        // neither a local marker nor an active policy alone opens the gate.
        if !accepted_principal_control {
            let endpoint = crate::secure_key_store::active_device_seed_scope();
            let evidence = self.state_store.as_ref().and_then(|store| {
                store.read(|state| {
                    (state.active_authority().as_ref() == Some(authority))
                        .then(|| state.recovery_material_evidence())
                        .flatten()
                })
            });
            if let (Some(key), Some(endpoint), Some(evidence)) =
                (cache_key.as_ref(), endpoint.as_ref(), evidence.as_ref())
            {
                anyhow::ensure!(
                    endpoint.authority == *authority
                        && evidence.account_id == *authority
                        && evidence.device_id == endpoint.device_id,
                    "recovery-material evidence belongs to another Account or Device"
                );
                let api = crate::transport::TransportClient::from_http(
                    self.http.clone(),
                    crate::transport::RequestContext::new(""),
                );
                crate::recovery_flow::verify_recovery_material_evidence(&api, evidence).await?;
                anyhow::ensure!(
                    self.state_store
                        .as_ref()
                        .is_some_and(|store| store.read(|state| {
                            state.active_authority().as_ref() == Some(authority)
                                && state.recovery_material_evidence().as_ref() == Some(evidence)
                        }))
                        && crate::secure_key_store::active_device_seed_scope().as_ref()
                            == Some(endpoint),
                    "recovery-material context changed during verification"
                );
                verified_recovery_gate_cache()
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(key.clone());
                accepted_principal_control = true;
            }
        }
        let policy: arkret_models_crypto::RecoveryPolicyActiveOutcome = self
            .http
            .get("/_arkret/root/identity/recovery-policy")
            .await
            .map_err(anyhow::Error::from)?;
        if cache_key.is_some() {
            anyhow::ensure!(
                crate::secure_key_store::active_device_seed_scope() == active_endpoint
                    && self.state_store.as_ref().is_some_and(|store| {
                        store.read(|state| state.active_authority().as_ref() == Some(authority))
                    }),
                "recovery-material context changed during policy verification"
            );
        }
        match crate::recovery_flow::first_backup_gate_status(accepted_principal_control, &policy) {
            crate::recovery_flow::FirstBackupGateStatus::Satisfied => Ok(()),
            crate::recovery_flow::FirstBackupGateStatus::Blocked(reason) => {
                anyhow::bail!("recovery_material_pending blocks E2EE activation/join: {reason:?}")
            }
        }
    }

    async fn event_enters_encrypted_scope(&self, intent: &EventIntent) -> anyhow::Result<bool> {
        if intent.kind() == &arkret_sdk::EventKind::MlsGenesis {
            return Ok(true);
        }
        let is_join = intent.kind().as_str() == event_kind_str::INVITE_ACCEPT
            || (intent.kind().as_str() == event_kind_str::MEMBER_STATE
                && intent.payload().get("membership").and_then(Value::as_str) == Some("join"));
        if !is_join {
            return Ok(false);
        }
        // Only a complete verified cut without the scope's `mls_group` shows
        // the join targets a plaintext scope. Every other answer (activated,
        // not ready, no current index for a Realm not yet joined) keeps the
        // recovery gate armed.
        let Some(input) = self.mls_send_gate_input(intent.scope_ref()) else {
            return Ok(true);
        };
        Ok(!matches!(
            crate::mls::send_gate::resolve_mls_send_gate(&input, intent.scope_ref()).await,
            Ok(crate::mls::send_gate::MlsSendGate::Plaintext)
        ))
    }

    /// The durable send-gate input of `scope` from this submitter's account
    /// store, or `None` when the submitter has no store to read.
    fn mls_send_gate_input(
        &self,
        scope: &arkret_sdk::ScopeRef,
    ) -> Option<crate::mls::send_gate::MlsSendGateInput> {
        self.state_store
            .as_ref()
            .map(|store| crate::mls::send_gate::MlsSendGateInput::capture(store, scope))
    }

    /// Resolve the controller's join Event from its complete current revision,
    /// then read that exact accepted stream position. A cached roster or a
    /// principal-only identity cannot supply an Agent membership generation.
    pub(crate) async fn read_agent_controller_membership_binding(
        &self,
        realm: &arkret_sdk::RealmId,
    ) -> anyhow::Result<arkret_sdk::AgentControllerMembershipBinding> {
        let controller = self.authority()?.clone();
        let member = arkret_sdk::ActorId::account(controller.clone());
        let revision = self.read_parent_membership_revision(realm, &member).await?;
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let page = self
            .scan_stream(&stream, revision.stream_position.checked_sub(1), 1)
            .await?;
        let row = page
            .0
            .committed_events
            .first()
            .ok_or_else(|| anyhow::anyhow!("controller membership Event is unavailable"))?;
        anyhow::ensure!(
            row.commit().commit_id == revision.commit_id
                && row.commit().stream_position == revision.stream_position
                && row.commit().stream_ref == stream,
            "controller membership Event differs from the verified current revision"
        );
        let event = row
            .reducer_input()
            .ok_or_else(|| anyhow::anyhow!("controller membership Event is not disclosed"))?;
        anyhow::ensure!(
            event.realm_id == *realm,
            "controller membership belongs to another Realm"
        );
        match event.kind {
            arkret_sdk::EventKind::MemberState => {
                let payload: arkret_sdk::MembershipPayload =
                    serde_json::from_value(serde_json::to_value(&event.payload)?)?;
                anyhow::ensure!(
                    payload.member_id == member
                        && payload.membership == arkret_sdk::MembershipPayloadState::Join
                        && payload.strand_id.is_none()
                        && payload.agent_controller_binding.is_none(),
                    "controller is not in an accepted ordinary joined generation"
                );
            }
            arkret_sdk::EventKind::InviteAccept => {
                anyhow::ensure!(
                    event.actor_id == member,
                    "accepted Invite names another controller"
                );
            }
            _ => anyhow::bail!("controller membership revision does not cover a join Event"),
        }
        Ok(arkret_sdk::AgentControllerMembershipBinding {
            controller_account_id: controller,
            controller_membership_generation_ref: event.event_id.clone(),
            controller_terminal_event_ref: None,
        })
    }

    pub(crate) async fn read_parent_membership_revision(
        &self,
        realm: &arkret_sdk::RealmId,
        member: &arkret_sdk::ActorId,
    ) -> anyhow::Result<arkret_wire::CurrentRevision> {
        let authority = self.authority()?.clone();
        let store = self.state_store.as_ref().ok_or_else(|| {
            anyhow::anyhow!("membership authoring requires an account current index")
        })?;
        for _ in 0..60 {
            let location = store.read(|state| state.current_index_location());
            let index = crate::state::CurrentIndex::open_committed(&authority, location, || {
                store.read(|state| {
                    anyhow::ensure!(
                        state.active_authority().as_ref() == Some(&authority),
                        "the active account changed before the membership current read"
                    );
                    anyhow::ensure!(
                        !state.current_reset_required(),
                        "membership authoring awaits a fresh account baseline"
                    );
                    Ok(state.current_generation())
                })
            })
            .await?;
            if let Some(revision) = index
                .read_parent_membership_revision_at_complete_cut(realm, member)
                .await?
            {
                return Ok(revision);
            }
            crate::runtime_helpers::sleep_for(Duration::from_millis(250)).await;
        }
        anyhow::bail!("membership authoring requires a complete verified parent Realm cut")
    }

    async fn ensure_queued_application_send_gate(
        &self,
        request: &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest,
    ) -> anyhow::Result<()> {
        let arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
            submission,
        ) = request
        else {
            return Ok(());
        };
        let event = &submission.event;
        if !matches!(
            event.scope_ref,
            arkret_sdk::ScopeRef::Realm { .. } | arkret_sdk::ScopeRef::Circle { .. }
        ) {
            return Ok(());
        }
        if let Some(body) =
            crate::mls::send_gate::ApplicationBody::of_event(&event.kind, &event.payload)?
        {
            let input = self.mls_send_gate_input(&event.scope_ref).ok_or_else(|| {
                anyhow::anyhow!("outbound application send requires an account current index")
            })?;
            if matches!(event.scope_ref, arkret_sdk::ScopeRef::Circle { .. }) {
                crate::mls::send_gate::check_circle_send_membership(&input, &event.scope_ref)
                    .await?;
            }
            crate::mls::send_gate::check_application_body(&input, &event.scope_ref, body).await?;
        }
        Ok(())
    }

    /// Refuse an application body the durable accepted MLS current of its
    /// scope does not admit (encryption-and-audit §2.5.2).
    ///
    /// Every chat, Kanban and ordinary Event write reaches the authority
    /// through this submitter, so this is the one client-side gate between a
    /// built body and the network: plaintext needs a complete verified cut
    /// without the scope's `mls_group`, ciphertext needs the exact current
    /// epoch and group-state reference with a covered key-access revision.
    /// Sidecar scopes ride their own contract and are not gated here.
    async fn ensure_application_send_gate(&self, intent: &EventIntent) -> anyhow::Result<()> {
        if !matches!(
            intent.scope_ref(),
            arkret_sdk::ScopeRef::Realm { .. } | arkret_sdk::ScopeRef::Circle { .. }
        ) {
            return Ok(());
        }
        let Some(body) =
            crate::mls::send_gate::ApplicationBody::of_event(intent.kind(), intent.payload())?
        else {
            return Ok(());
        };
        let input = self
            .mls_send_gate_input(intent.scope_ref())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "MLS send gate is not ready: no account store to read the scope's current"
                )
            })?;
        crate::mls::send_gate::check_application_body(&input, intent.scope_ref(), body)
            .await
            .map_err(anyhow::Error::from)
    }

    /// Refresh before authoring. A service-observed binding closes bootstrap
    /// but never substitutes for the Realm's own committed founding unit.
    async fn refresh_direct_message_authority(
        &self,
        intent: &EventIntent,
        state_store: Option<&crate::runtime::input::StateStoreHandle>,
    ) -> anyhow::Result<()> {
        if intent.kind() != &arkret_sdk::EventKind::MessageCreate {
            return Ok(());
        }
        let Some(realm) = intent.realm_id_opt() else {
            return Ok(());
        };
        let store = state_store.or(self.state_store.as_ref()).ok_or_else(|| {
            anyhow::anyhow!("Direct Conversation requires an account state store")
        })?;
        if store.read(|state| state.realm_collaboration_role(realm.as_str()))
            != Some(arkret_sdk::CollaborationRealmRole::DirectConversation)
        {
            return Ok(());
        }
        let authority = self
            .authority
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Direct Conversation requires an account"))?;
        if store.read(|state| {
            state
                .direct_message_context(realm.as_str(), intent.actor_id())
                .is_some_and(|context| {
                    context.authority_source
                        == arkret_wire::AuthoritySourceId::DirectConversationParticipantV1
                })
        }) {
            return Ok(());
        }
        // Bootstrap authority exits when the first binding is accepted. Refresh
        // this transient source before signing; a settled participant context
        // remains usable while the peer or network is unavailable.
        let epoch = crate::identity::device_directory::session_cache_epoch();
        let peer = store
            .read(|state| state.direct_conversation_peer(realm.as_str()))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Open the Direct Conversation to refresh its exact peer coordinates"
                )
            })?;
        let query_sequence = crate::mls::direct_binding::begin_query(authority, &peer)?;
        let outcome = self
            .http
            .direct_conversation_resolve(
                &arkret_sdk::direct_conversation::DirectConversationResolveRequestBody {
                    peer: peer.clone(),
                },
            )
            .await?;
        anyhow::ensure!(
            outcome
                .coordinates()
                .is_some_and(|coordinates| coordinates.realm_id == *realm),
            "Direct Conversation resolver returned another Realm"
        );
        crate::mls::direct_binding::install_resolved_message_context(
            &self.http,
            store,
            authority,
            epoch,
            query_sequence,
            peer,
            &outcome,
        )
        .await?;
        anyhow::ensure!(
            store.read(|state| state
                .direct_message_context(realm.as_str(), intent.actor_id())
                .is_some()),
            "Direct Conversation authoring is not ready"
        );
        Ok(())
    }

    // --------------------------------------------------------------- signals

    /// The current head of the commit stream a Signal is scoped to.
    ///
    /// `signal.md` binds an envelope to the stream head its sender observed,
    /// read from the enrolled own Station's original current snapshot.
    pub(crate) async fn current_stream_head_for(
        &self,
        scope_ref: &arkret_sdk::ScopeRef,
    ) -> anyhow::Result<arkret_wire::RealmCommitId> {
        let realm_id = scope_ref
            .realm_id_opt()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("a Signal scope must name its Realm"))?;
        let stream_ref =
            arkret_wire::CommitStreamRef::from_scope(scope_ref, Some(realm_id.clone()))
                .map_err(anyhow::Error::from)?;
        let binding = crate::station_connection::enrolled(self.http.base_url().as_str()).await?;
        let epoch = crate::identity::device_directory::session_cache_epoch();
        let consumer = garth::own_station::OwnStationConsumer::authenticate(
            self.http.clone(),
            &binding,
            self.authority()?.clone(),
            epoch,
        )
        .await?;
        let snapshot = consumer.snapshot_head(&realm_id).await?;
        anyhow::ensure!(
            epoch == crate::identity::device_directory::session_cache_epoch(),
            "head read Account epoch changed"
        );
        snapshot
            .snapshot()
            .visible_stream_heads
            .iter()
            .find(|head| head.stream_ref == stream_ref)
            .map(|head| head.commit_id.clone())
            .ok_or_else(|| anyhow::anyhow!("own Station current omits the requested stream head"))
    }

    /// [`Self::send_signal`] with the scope header assembled from the current
    /// authenticated stream head.
    pub async fn send_scope_signal(
        &self,
        scope_ref: arkret_sdk::ScopeRef,
        authority: &arkret_sdk::AccountId,
        device_id: &arkret_sdk::DeviceId,
        material: &crate::signal::SignalKeyMaterial,
        payload: &crate::signal::SignalPayload,
        state_store: &crate::runtime::input::StateStoreHandle,
    ) -> anyhow::Result<arkret_sdk::SignalSubmitOutcome> {
        self.send_scope_signal_with_transport_observation(
            scope_ref,
            authority,
            device_id,
            material,
            payload,
            state_store,
        )
        .await
        .map(|(outcome, _observation)| outcome)
    }

    /// Identical producer path with metadata from the actual HTTP response.
    pub async fn send_scope_signal_with_transport_observation(
        &self,
        scope_ref: arkret_sdk::ScopeRef,
        authority: &arkret_sdk::AccountId,
        device_id: &arkret_sdk::DeviceId,
        material: &crate::signal::SignalKeyMaterial,
        payload: &crate::signal::SignalPayload,
        state_store: &crate::runtime::input::StateStoreHandle,
    ) -> anyhow::Result<(
        arkret_sdk::SignalSubmitOutcome,
        arkret_sdk::http_client::SignalSendTransportObservation,
    )> {
        state_store.read(|store| store.require_blocklist_signal_freshness(payload))?;
        let stream_head_ref = self.current_stream_head_for(&scope_ref).await?;
        let parent_realm_authority_commit_id =
            if matches!(&scope_ref, arkret_sdk::ScopeRef::Circle { .. }) {
                Some(
                    self.current_stream_head_for(&arkret_sdk::ScopeRef::Realm {
                        realm_id: scope_ref.realm_id().clone(),
                    })
                    .await?,
                )
            } else {
                None
            };
        let header = crate::signal::SignalHeader::new(
            scope_ref,
            arkret_sdk::ActorId::account(authority.clone()),
            device_id.clone(),
            stream_head_ref,
            parent_realm_authority_commit_id,
            payload.signal_class(),
            crate::clock::now_utc(),
        );
        self.send_signal_with_transport_observation(
            authority,
            header,
            material,
            payload,
            state_store,
        )
        .await
    }

    /// Seal and submit one Signal.
    ///
    /// `state_store` is not optional plumbing: the AEAD nonce counter lives in
    /// the persisted MLS snapshot and `encoding.md` §10.1 requires it to be
    /// durably burnt before the envelope leaves this device.
    pub async fn send_signal(
        &self,
        authority: &arkret_sdk::AccountId,
        header: crate::signal::SignalHeader,
        material: &crate::signal::SignalKeyMaterial,
        payload: &crate::signal::SignalPayload,
        state_store: &crate::runtime::input::StateStoreHandle,
    ) -> anyhow::Result<arkret_sdk::SignalSubmitOutcome> {
        self.send_signal_with_transport_observation(
            authority,
            header,
            material,
            payload,
            state_store,
        )
        .await
        .map(|(outcome, _observation)| outcome)
    }

    pub async fn send_signal_with_transport_observation(
        &self,
        authority: &arkret_sdk::AccountId,
        header: crate::signal::SignalHeader,
        material: &crate::signal::SignalKeyMaterial,
        payload: &crate::signal::SignalPayload,
        state_store: &crate::runtime::input::StateStoreHandle,
    ) -> anyhow::Result<(
        arkret_sdk::SignalSubmitOutcome,
        arkret_sdk::http_client::SignalSendTransportObservation,
    )> {
        state_store.read(|store| store.require_blocklist_signal_freshness(payload))?;
        if header.sender_actor_id.as_account_id() != Some(authority) {
            anyhow::bail!("Signal sender does not match the encryption authority");
        }
        // A Signal is sealed under the scope's accepted current group only;
        // the durable send gate decides, and the sealing material must name
        // exactly that current epoch and group-state reference.
        let input =
            crate::mls::send_gate::MlsSendGateInput::capture(state_store, &header.scope_ref);
        match crate::mls::send_gate::resolve_mls_send_gate(&input, &header.scope_ref).await? {
            crate::mls::send_gate::MlsSendGate::Encrypted(current) => anyhow::ensure!(
                current.epoch == material.epoch
                    && current.current_mls_commit_event_ref.as_str() == material.group_state_ref,
                "Signal material does not name the scope's accepted current MLS state"
            ),
            crate::mls::send_gate::MlsSendGate::Plaintext => {
                anyhow::bail!("the Signal scope has no accepted MLS Genesis")
            }
        }
        let sequence = crate::signal::next_signal_sequence(
            state_store,
            &header.sender_actor_id,
            &header.sender_device_id,
            &header.scope_ref,
        )
        .await?;
        let plaintext = payload.to_plaintext(&header.sender_actor_id, sequence)?;
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let encrypted_payload = state_store.write(|store| {
            store.signal_sequence_store_context(&header.sender_actor_id)?;
            crate::signal::encrypt_signal_payload_with_store(
                store,
                secure_store.as_ref(),
                authority,
                &header,
                material,
                &plaintext,
            )
        })?;
        let envelope = crate::signal::seal_signal_envelope(header, encrypted_payload)?;
        self.submit_signal_envelope_with_transport_observation(&envelope)
            .await
    }

    /// `POST /_arkret/self/signal` — `ak.self.signal.command.send.v1`.
    pub async fn submit_signal_envelope(
        &self,
        envelope: &arkret_wire::SignalEnvelope,
    ) -> anyhow::Result<arkret_sdk::SignalSubmitOutcome> {
        self.submit_signal_envelope_with_transport_observation(envelope)
            .await
            .map(|(outcome, _observation)| outcome)
    }

    pub async fn submit_signal_envelope_with_transport_observation(
        &self,
        envelope: &arkret_wire::SignalEnvelope,
    ) -> anyhow::Result<(
        arkret_sdk::SignalSubmitOutcome,
        arkret_sdk::http_client::SignalSendTransportObservation,
    )> {
        envelope
            .validate_structural()
            .map_err(|error| anyhow::anyhow!("signal submit rejected locally: {error}"))?;
        self.http
            .signal_send_with_transport_observation(envelope)
            .await
            .map_err(anyhow::Error::from)
    }

    /// `POST /_arkret/gate/account/agent-key-pair` —
    /// `ak.gate.account.command.pair_agent_key.v1`.
    pub(crate) async fn agent_key_pair(
        &self,
        body: &arkret_models_collaboration::agent_operations::AgentKeyPairRequestBody,
    ) -> anyhow::Result<arkret_models_collaboration::agent_operations::AgentKeyPairOutcome> {
        let station_url = self.http.base_url().as_str();
        let authority =
            crate::identity::account_auth::AuthorityResolver::discover(station_url).await?;
        let gate_account_base_url = url::Url::parse(&authority.gate_account_base_url)?;
        let authority_origin = gate_account_base_url.origin().ascii_serialization();
        let authority_http = account_authority_http_client(&authority_origin)?;
        authority_http
            .agent_key_pair(body)
            .await
            .map_err(anyhow::Error::from)
            .with_context(|| format!("pair Agent key at {authority_origin}"))
    }
}

/// What the replay fence decides about one queued Event.
///
/// A queued submission is frozen bytes, so the only authoring fact still
/// readable from it is its producer proof. The verification method in that
/// proof names the exact device key the write was signed under: replacing a
/// device generation replaces that key, so a queued Event whose proof no
/// longer names this device's current signing method is quarantined instead of
/// being forwarded under an authority the principal has withdrawn.
fn queued_event_generation_decision(
    event: &arkret_sdk::Event,
) -> anyhow::Result<GenerationFenceDecision> {
    let signer = crate::event_signer::active_signer().ok_or_else(|| {
        anyhow::anyhow!("no active signer configured for a generation-fenced replay")
    })?;
    let signer_principal = arkret_sdk::Did::new(signer.signer_did().to_owned())
        .ok()
        .and_then(|did| arkret_sdk::project_did_to_core_id(&did).ok())
        .ok_or_else(|| {
            anyhow::anyhow!("the active signer DID does not project to a principal id")
        })?;
    Ok(generation_decision_for_signer(
        &signer_principal,
        signer.verification_method(),
        event,
    ))
}

/// [`queued_event_generation_decision`] against an explicit signer identity.
///
/// A write authored by another principal (an Agent acting for its controller,
/// say) is left alone: this device has nothing to compare it against, and
/// guessing would cancel work it does not own.
fn generation_decision_for_signer(
    signer_principal: &arkret_sdk::DidCoreId,
    signer_verification_method: &str,
    event: &arkret_sdk::Event,
) -> GenerationFenceDecision {
    let authoring_principal = event
        .executed_by
        .as_ref()
        .unwrap_or(&event.actor_id)
        .signing_principal_id();
    if authoring_principal != signer_principal {
        return GenerationFenceDecision::Current;
    }
    let Some(proof) = event.producer_proof.as_ref() else {
        return GenerationFenceDecision::Quarantine {
            reason: "queued_event_has_no_producer_proof".to_owned(),
        };
    };
    if proof.verification_method.as_str() == signer_verification_method {
        GenerationFenceDecision::Current
    } else {
        GenerationFenceDecision::Quarantine {
            reason: "authoring_generation_superseded".to_owned(),
        }
    }
}

fn local_detail_blocks_authoring(
    founding_realm: Option<&arkret_sdk::RealmId>,
    realm_id: &str,
    invalidated_without_projection: bool,
) -> bool {
    !founding_realm.is_some_and(|founding| founding.as_str() == realm_id)
        && invalidated_without_projection
}

// The queue lifecycle is nonterminal even while retaining the authority's
// exact typed retryable outcome for diagnosis and interactive retry policy.
fn is_retryable_authority_item(item: &garth::SendQueueItem) -> bool {
    matches!(
        &item.submission.state,
        garth::SubmissionState::Rejected {
            status: arkret_wire::AuthorityRejectionStatus::RetryableUnavailable,
            ..
        }
    )
}

fn ensure_exact_queued_request(
    existing: &QueuedSubmission,
    attempted: &QueuedSubmission,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        arkret_sdk::canonical::canonical_json_bytes(&existing.request)?
            == arkret_sdk::canonical::canonical_json_bytes(&attempted.request)?,
        "local dispatch invariant: an existing Event identity has different signed submission bytes"
    );
    Ok(())
}

/// Every message producer, including poll, scheduled and confirmed Sidecar
/// writes, enters the same consuming proof-only session. Other Event kinds
/// retain their domain-specific signing path.
fn sign_event_through_message_seam(
    event: &mut arkret_sdk::AuthoredEvent,
    sign: impl FnOnce(&mut arkret_sdk::AuthoredEvent) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    if event.kind != arkret_sdk::EventKind::MessageCreate {
        return sign(event);
    }
    let frozen = garth::MessageAuthoringSession::from_authored_event(event.clone())?.sign_with(
        |unsigned| sign(unsigned).map_err(|error| garth::Error::Protocol(error.to_string())),
    )?;
    event.attach_proof(
        frozen
            .request()
            .submission
            .event
            .producer_proof
            .clone()
            .ok_or_else(|| anyhow::anyhow!("message signer produced no producer proof"))?,
    );
    Ok(())
}

/// Freeze one signed producer Event as an authority submission.
pub(crate) fn event_submission(
    event: &arkret_sdk::AuthoredEvent,
) -> anyhow::Result<QueuedSubmission> {
    validate_signed_sdk_event_for_submit(event.event(), event.digest_suite())?;
    let request = arkret_wire::EventAdmissionSubmission {
        event: event.event().clone(),
        approval_signatures: None,
    };
    if event.kind == arkret_sdk::EventKind::MessageCreate {
        return garth::FrozenMessageSubmission::from_signed_request(
            garth::MessageSubmitRequestBody {
                submission: request,
            },
        )
        .map(garth::FrozenMessageSubmission::into_queued_submission)
        .map_err(anyhow::Error::from);
    }
    QueuedSubmission::new(arkret_wire::AuthoritySubmitRequest::Event(request))
        .map_err(anyhow::Error::from)
}

fn account_authority_http_client(
    authority_origin: &str,
) -> anyhow::Result<arkret_sdk::http_client::Client> {
    let base_url = url::Url::parse(authority_origin)?;
    arkret_sdk::http_client::ClientBuilder::new(base_url)
        // Account enrollment and refresh already use the same exception. It is
        // restricted by the SDK to loopback hosts, so production HTTP origins
        // remain rejected while the joint local stack can complete the
        // controller-approved Agent runtime pairing flow.
        .allow_insecure_localhost()
        .build()
        .map_err(anyhow::Error::from)
}

/// Validate the inner capability artifact before the outer Event is signed.
///
/// The Event envelope proof is the sole durable issuer signature; nested grant
/// proofs are intentionally absent from the v1 wire shape, so this reduces to
/// proving the artifact names the Event's own actor as issuer.
pub(crate) fn validate_capability_grant_payload(intent: &EventIntent) -> anyhow::Result<()> {
    if intent.kind() != &arkret_sdk::EventKind::CapabilityGrant {
        return Ok(());
    }
    let payload: arkret_sdk::CapabilityGrantPayload = serde_json::from_value(
        serde_json::to_value(intent.payload())
            .map_err(|error| anyhow::anyhow!("encode capability grant payload: {error}"))?,
    )
    .map_err(|error| anyhow::anyhow!("decode capability grant payload: {error}"))?;
    if &payload.grant.issuer_id != intent.actor_id() {
        anyhow::bail!("capability grant issuer must equal the Event actor");
    }
    Ok(())
}

fn validate_signed_sdk_event_for_submit(
    event: &arkret_sdk::Event,
    digest_suite: arkret_sdk::DigestSuite,
) -> anyhow::Result<()> {
    let Some(_producer) = event.producer_proof.as_ref() else {
        anyhow::bail!(
            "submit requires exactly one producer proof (event_id={}, kind={})",
            event.event_id,
            event.kind.as_str()
        );
    };
    event
        .validate_proof_bindings_with_digest_suite(digest_suite)
        .map_err(|err| {
            anyhow::anyhow!("event proof binding invalid for {}: {err}", event.event_id)
        })?;
    validate_outgoing_registered_event_payload(event.kind.as_str(), &event.payload)
}

fn mls_genesis_event_id_from_events(
    events: &[arkret_sdk::Event],
    realm_id: &str,
) -> Option<arkret_sdk::EventId> {
    events
        .iter()
        .find(|event| {
            event.realm_id.as_str() == realm_id && event.kind == arkret_sdk::EventKind::MlsGenesis
        })
        .map(|event| event.event_id.clone())
}

#[cfg(test)]
#[path = "event_submit/tests.rs"]
mod tests;
