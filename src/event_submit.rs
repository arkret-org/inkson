//! `EventSubmitter` — the authenticated producer-submission engine.
//!
//! One user write is one producer-authored `Event`. Authoring finalizes its
//! content-bound `event_id` exactly once: there is no chain position, no
//! predecessor, no basis and no precondition to resolve, so nothing after the
//! authoring boundary can change the identity. The frozen
//! [`arkret_wire::AuthoritySubmitRequest`] is what the durable queue stores,
//! and the current governance Station's authority-signed
//! [`arkret_wire::RealmCommit`] is the only finality signal.
//!
//! Retry, backoff and terminal classification belong to
//! [`garth::OutboundEngine`]. This module owns the host-side concerns the
//! engine deliberately does not have: the replay generation fence, the
//! post-commit local actions, and the join back to the optimistic UI row.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock as SyncOnceLock, PoisonError};
use std::time::Duration;

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

#[cfg(test)]
pub(crate) use authoring_unit::author_event_unit_for_test;
use authoring_unit::{UnitAuthoringChain, validate_authored_unit_shape};
use authority::*;
pub(crate) use message_authoring::{MessageSendAttempt, drive_message_send};

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
type InksonAuthorityClient = garth::AuthorityClient<arkret_sdk::http_client::Client>;

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
        after_position,
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
}

/// A browser runtime has multiple outbound triggers: the foreground writer and
/// the account-sync drain. Engines opened on the same durable store do not
/// share an in-memory lease, so without a runtime single-writer gate both can
/// enqueue and forward concurrently against the same persisted queue file.
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

pub(crate) fn remember_verified_recovery_gate(authority_principal: &str, device_id: &str) {
    let Some(key) = normalized_recovery_gate_cache_key(authority_principal, device_id) else {
        return;
    };
    let mut cache = verified_recovery_gate_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    cache.insert(key);
}

fn normalized_recovery_gate_cache_key(
    authority_principal: &str,
    device_id: &str,
) -> Option<String> {
    let principal = arkret_sdk::DidCoreId::new(authority_principal.to_owned())
        .ok()
        .or_else(|| {
            let did = arkret_sdk::Did::new(authority_principal.to_owned()).ok()?;
            arkret_sdk::project_did_to_core_id(&did).ok()
        })?;
    let device = arkret_sdk::DeviceId::new(device_id.to_owned()).ok()?;
    Some(format!("{principal}\u{1f}{device}"))
}

fn recovery_gate_cache_key(intent: &EventIntent) -> Option<String> {
    let authority_principal = intent
        .executed_by()
        .unwrap_or_else(|| intent.actor_id())
        .signing_principal_id()
        .as_str();
    let signer = crate::event_signer::active_signer()?;
    let device_id = signer.device_id()?;
    normalized_recovery_gate_cache_key(authority_principal, device_id)
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
    match item.request() {
        arkret_wire::AuthoritySubmitRequest::Event(submission) => &submission.event,
        arkret_wire::AuthoritySubmitRequest::MlsCommit(submission) => &submission.commit_event,
    }
}

/// An item that has not reached a terminal authority answer yet.
fn is_unsettled(status: SendQueueStatus) -> bool {
    matches!(
        status,
        SendQueueStatus::Queued | SendQueueStatus::Forwarding
    )
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
/// The ids are the final content-bound Event ids: authoring derives them
/// before anything is enqueued, so a queued send already knows the identity it
/// will carry once committed, and the optimistic row is stamped with the same
/// value at enqueue time.
pub(crate) async fn pending_chat_outbound_local_operation_ids(
    authority: &arkret_sdk::AccountId,
    realm_id: &str,
    strand_id: &str,
) -> anyhow::Result<BTreeSet<String>> {
    let outbound = OutboundEngine::new(
        InksonOutboundStore::open(authority, OutboundLane::Standard)?,
        InksonHostClock,
    );
    let snapshot = outbound.snapshot().await?;
    Ok(pending_chat_event_ids_from_snapshot(
        &snapshot, realm_id, strand_id,
    ))
}

fn pending_mls_commit_for_realm_from_snapshot(
    snapshot: &garth::SendQueueSnapshot,
    realm_id: &str,
) -> bool {
    snapshot
        .items
        .iter()
        .any(|item| is_unsettled(item.status) && queued_event(item).realm_id.as_str() == realm_id)
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
            event.kind == arkret_sdk::EventKind::MlsGenesis && event.realm_id.as_str() == realm_id
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
    event_id: &arkret_sdk::EventId,
) -> bool {
    state_store.update_raw_operation_write_state(
        local_operation_id,
        "queued",
        Some(event_id.to_string()),
        None,
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
            record.payload.get("event_id").and_then(Value::as_str) == Some(event_id.as_str())
        })
        .map(|record| record.operation_id.clone())
}

/// Move the optimistic row to its terminal write state once the Station has
/// answered for the Event it names.
fn reconcile_settled_outbound_item(
    state_store: &mut crate::state::LocalStateStore,
    item: &garth::SendQueueItem,
) -> bool {
    let event_id = item.event_id().clone();
    let (write_state, error) = match item.status {
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
    let Some(operation_id) = local_operation_for_event(&state_store.load(), &event_id) else {
        return false;
    };
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
                use dioxus::prelude::ReadableExt as _;
                let authority = context
                    .active_account
                    .peek()
                    .as_ref()
                    .map(|account| account.authority.clone());
                let mut submitter = Self::new(http).with_state_store(
                    crate::app::runtime_adapter::state_store_handle(context.state_store),
                );
                if let Some(authority) = authority {
                    submitter = submitter.with_authority(authority);
                }
                submitter
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

    fn authority_client(&self) -> InksonAuthorityClient {
        garth::AuthorityClient::new(self.http.clone())
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

    fn ensure_realm_detail_current(&self, realm_id: &str) -> anyhow::Result<()> {
        let invalidated_without_projection = self
            .state_store
            .as_ref()
            .is_some_and(|store| store.read(|store| store.realm_detail_invalidated(realm_id)));
        if local_detail_blocks_authoring(
            self.founding_realm.as_ref(),
            realm_id,
            invalidated_without_projection,
        ) {
            return Err(anyhow::Error::new(arkret_sdk::Error::Http(
                "Realm current state is refreshing after an account invalidation".to_owned(),
            )));
        }
        Ok(())
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
        let stream_ref = arkret_wire::CommitStreamRef::Realm {
            realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())?,
        };
        let genesis = self.scan_stream(&stream_ref, None, 1).await?;
        let resolved = realm_create_authority_from_events(&genesis.events(), realm_id);
        if let Some(authority) = &resolved {
            realm_create_authority_cache()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(realm_id.to_owned(), authority.clone());
        }
        // A temporarily unavailable founding Event is not cached.
        Ok(resolved)
    }

    /// Confirm the immutable creator of an already-committed Realm.
    pub(crate) async fn accepted_realm_creator_matches_account(
        &self,
        realm_id: &str,
        authority: &arkret_sdk::AccountId,
    ) -> anyhow::Result<bool> {
        let actor = arkret_sdk::ActorId::account(authority.clone());
        let founding = self
            .realm_create_authority(realm_id)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("committed Realm founding authority is not available")
            })?;
        Ok(matches!(founding, RealmCreateAuthority::Root { controller } if controller == actor))
    }

    /// Whether the Realm scope has already activated standard RFC 9420
    /// encryption.
    ///
    /// Activation is a committed `ak.mls.genesis` for that scope and nothing
    /// else: the Realm create no longer carries an encryption choice, and the
    /// transition is irreversible once it lands.
    pub(crate) async fn accepted_realm_is_encrypted(&self, realm_id: &str) -> anyhow::Result<bool> {
        let events = self.realm_stream_events(realm_id).await?;
        let scope_ref = arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())?,
        };
        Ok(scope_has_accepted_mls_genesis(&events, &scope_ref))
    }

    /// Whether the typed Realm state snapshot already carries an MLS group for
    /// this scope. Same judgement as [`Self::accepted_realm_is_encrypted`],
    /// read from a snapshot the caller already holds.
    pub(crate) fn snapshot_scope_is_encrypted(
        snapshot: &arkret_wire::RealmStateSnapshot,
        scope_ref: &arkret_sdk::ScopeRef,
    ) -> bool {
        snapshot_scope_has_mls_group(snapshot, scope_ref)
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
        crate::event_signer::cached_active_event_proof_context(digest_suite)
            .map_err(|error| anyhow::anyhow!("{error}"))
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
            self.ensure_realm_detail_current(realm_id.as_str())?;
        }
        self.verify_actor_authority(intent).await?;
        validate_capability_grant_payload(intent)?;
        let digest_suite = self.digest_suite_for_intent(intent)?;
        let proof_context = self.event_proof_context(digest_suite).await?;
        let mut event = intent
            .clone()
            .author_with_digest_suite(digest_suite)
            .map_err(|error| anyhow::anyhow!("author Event: {error}"))?;
        self.sign_authored_event(intent, &mut event, proof_context)?;
        Ok(event)
    }

    fn sign_authored_event(
        &self,
        intent: &EventIntent,
        event: &mut arkret_sdk::AuthoredEvent,
        proof_context: crate::event_signer::ProducerProofContext,
    ) -> anyhow::Result<()> {
        let minimal_metadata = intent.realm_id_opt().is_some_and(|realm_id| {
            self.state_store.as_ref().is_some_and(|store| {
                store.read(|state| state.realm_projection_is_minimal_metadata(realm_id.as_str()))
            })
        });
        if !minimal_metadata {
            return crate::event_signer::sign_sdk_event_with_active_context(event, proof_context)
                .map_err(|error| anyhow::anyhow!("sign SDK Event: {error}"));
        }
        let realm_id = intent
            .realm_id_opt()
            .ok_or_else(|| anyhow::anyhow!("minimal-metadata Event has no Realm scope"))?;
        let authority = self.authority.as_ref().ok_or_else(|| {
            anyhow::anyhow!("minimal-metadata Event has no captured account authority")
        })?;
        let active = crate::event_signer::active_signer()
            .ok_or_else(|| anyhow::anyhow!("active endpoint signer is unavailable"))?;
        let device_id = arkret_sdk::DeviceId::new(
            active
                .device_id()
                .ok_or_else(|| anyhow::anyhow!("active endpoint signer has no device id"))?
                .to_owned(),
        )?;
        let material = crate::mls::pairwise_identity::derive_pairwise_signing_material(
            authority, &device_id, realm_id,
        )
        .map_err(anyhow::Error::msg)?;
        if intent.actor_id().signing_principal_id() != &material.actor_id {
            anyhow::bail!("minimal-metadata intent actor does not equal the Realm pairwise actor");
        }
        material
            .signer
            .sign_sdk_event_with_context(event, proof_context)
            .map_err(|error| anyhow::anyhow!("sign minimal-metadata SDK Event: {error}"))
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
    ) -> anyhow::Result<Vec<arkret_wire::EventCommitSubmission>> {
        let mut submissions = Vec::with_capacity(events.len());
        for event in events {
            validate_signed_sdk_event_for_submit(event.event(), event.digest_suite())?;
            submissions.push(arkret_wire::EventCommitSubmission {
                event: event.event().clone(),
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
    ) -> anyhow::Result<arkret_wire::EventCommitSubmission> {
        arkret_bootstrap::validate_self_principal_pcr_create(accepted_create, true)
            .map_err(|error| anyhow::anyhow!("accepted self-principal PCR create: {error}"))?;
        anyhow::ensure!(
            event.realm_id == accepted_create.realm_id,
            "authority-authored self-principal Event is scoped to another Realm"
        );
        validate_signed_sdk_event_for_submit(event.event(), event.digest_suite())?;
        Ok(arkret_wire::EventCommitSubmission {
            event: event.event().clone(),
        })
    }

    // ------------------------------------------------------------ submitting

    /// Submit one user write.
    pub(crate) async fn submit_sdk_event(
        &self,
        operation: &LocalOperation,
    ) -> anyhow::Result<SubmitEventResult> {
        let intent = operation.intent().clone();
        self.ensure_recovery_material_ready(&intent).await?;
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
            })
            .await?;
        settled_outbound_result(&item)
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
        let _single_writer = outbound_submit_lock().lock().await;
        let mut results = Vec::with_capacity(sdk_events.len());
        for event in sdk_events {
            self.ensure_realm_detail_current(event.realm_id.as_str())?;
            let submission = event_submission(event)?;
            let item = self
                .enqueue_and_drive(QueuedWrite {
                    lane: OutboundLane::Standard,
                    submission,
                    local_operation_id: event.event_id().to_string(),
                    post_accept: PostAccept::None,
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
    ) -> anyhow::Result<arkret_sdk::RealmId> {
        let _single_writer = outbound_submit_lock().lock().await;
        let events = self.author_event_unit(steps).await?;
        let realm_id = events
            .first()
            .ok_or_else(|| anyhow::anyhow!("Realm bootstrap unit is empty"))?
            .realm_id
            .clone();
        for (index, event) in events.iter().enumerate() {
            let submission = event_submission(event)?;
            let item = self
                .enqueue_and_drive(QueuedWrite {
                    lane: OutboundLane::Standard,
                    submission,
                    local_operation_id: if index == 0 {
                        local_operation_id.clone()
                    } else {
                        event.event_id().to_string()
                    },
                    post_accept: PostAccept::None,
                })
                .await?;
            settled_outbound_result(&item)?;
        }
        Ok(realm_id)
    }

    /// Submit the founding unit of a Direct Conversation.
    ///
    /// A Direct Conversation Realm is founded exactly like any other Realm:
    /// its members are ordinary Events committed in order by the governance
    /// Station named in the genesis payload.
    pub(crate) async fn submit_direct_conversation_founding_durable(
        &self,
        events: Vec<arkret_sdk::AuthoredEvent>,
    ) -> anyhow::Result<arkret_sdk::RealmId> {
        let realm_id = events
            .first()
            .ok_or_else(|| anyhow::anyhow!("Direct Conversation founding unit is empty"))?
            .realm_id
            .clone();
        let _single_writer = outbound_submit_lock().lock().await;
        for event in &events {
            let submission = event_submission(event)?;
            let item = self
                .enqueue_and_drive(QueuedWrite {
                    lane: OutboundLane::Standard,
                    submission,
                    local_operation_id: event.event_id().to_string(),
                    post_accept: PostAccept::None,
                })
                .await?;
            settled_outbound_result(&item)?;
        }
        Ok(realm_id)
    }

    /// Freeze and durably persist a fully signed scheduled message before any
    /// submission I/O. Resolving or editing the plan after this boundary is
    /// forbidden.
    pub(crate) async fn submit_scheduled_send_event(
        &self,
        scheduled_send_id: arkret_identifiers::ScheduledSendId,
        signed_event: arkret_sdk::AuthoredEvent,
    ) -> anyhow::Result<SubmitEventResult> {
        let _single_writer = outbound_submit_lock().lock().await;
        let submission = event_submission(&signed_event)?;
        let item = self
            .enqueue_and_drive(QueuedWrite {
                lane: OutboundLane::Standard,
                submission,
                local_operation_id: scheduled_send_id.to_string(),
                post_accept: PostAccept::None,
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
            })
            .await?;
        settled_outbound_result(&item)
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
            &snapshot, realm_id,
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
                queued_event_generation_decision(queued_event(&item))?,
            );
        }
        Ok(ResolvedQueueGenerationFence::new(decisions))
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
    /// an authority answer or is left durably queued.
    /// Enqueue one frozen submission and drive the queue until this item has
    /// a settled authority answer, or is left durably queued.
    ///
    /// A Station refusal is an answer, not an error: it comes back as the
    /// settled item so the caller can read its exact `reason_code`.
    async fn enqueue_and_drive(&self, write: QueuedWrite) -> anyhow::Result<garth::SendQueueItem> {
        let QueuedWrite {
            lane,
            submission,
            local_operation_id,
            post_accept,
        } = write;
        let event_id = submission.event_id.clone();
        let outbound = self.outbound(lane)?;
        let existing = outbound
            .snapshot()
            .await?
            .items
            .into_iter()
            .find(|item| item.event_id() == &event_id);
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
                return Ok(item);
            }
            Some(_) => {}
            None => {
                outbound
                    .enqueue(submission)
                    .await
                    .map_err(anyhow::Error::from)?;
            }
        }
        if let Some(state_store) = self.state_store.as_ref() {
            state_store.write(|store| {
                record_queued_operation_identity(store, &local_operation_id, &event_id);
            });
        }

        let authority_client = self.authority_client();
        let options = arkret_sdk::http_client::ClientRequestOptions::new()
            .request_id(event_id.to_string())
            .idempotency_key(event_id.to_string());
        let mut interactive_retries = 0_u8;
        loop {
            let fence = self.resolve_queue_generation_fence(&outbound).await?;
            self.quarantine_superseded_items(&outbound, &fence).await?;
            match outbound
                .submit_next(&authority_client, &options)
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
                OutboundEngineOutcome::Failed { item, error } if item.event_id() == &event_id => {
                    anyhow::bail!("durable submission of {event_id} failed: {error}");
                }
                OutboundEngineOutcome::Retry { item, delay } if item.event_id() == &event_id => {
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
                crate::mls::runtime::install_accepted_transition(
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
    /// A commit resumed here is installed by the scope's own stream installer
    /// rather than in this pass: the leaf attribution evidence a membership
    /// change needs is not part of the frozen submission.
    pub(crate) async fn drain_mls_outbound(&self) -> anyhow::Result<usize> {
        self.drain_lane(OutboundLane::MlsCommit).await
    }

    async fn drain_lane(&self, lane: OutboundLane) -> anyhow::Result<usize> {
        let _single_writer = outbound_submit_lock().lock().await;
        let outbound = self.outbound(lane)?;
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
        let authority_client = self.authority_client();
        let mut completed = 0usize;
        loop {
            let fence = self.resolve_queue_generation_fence(&outbound).await?;
            completed = completed
                .saturating_add(self.quarantine_superseded_items(&outbound, &fence).await?);
            let options = arkret_sdk::http_client::ClientRequestOptions::new();
            match outbound
                .submit_next(&authority_client, &options)
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
        let accepted_principal_control = recovery_gate_cache_key(intent).is_some_and(|key| {
            verified_recovery_gate_cache()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&key)
        });
        let policy: arkret_models_crypto::RecoveryPolicyActiveOutcome = self
            .http
            .get("/_arkret/root/identity/recovery-policy")
            .await
            .map_err(anyhow::Error::from)?;
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
        let Some(realm_id) = intent.realm_id_opt() else {
            return Ok(false);
        };
        let events = self.realm_stream_events(realm_id.as_str()).await?;
        Ok(scope_has_accepted_mls_genesis(&events, intent.scope_ref()))
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
                .is_some()
        }) {
            return Ok(());
        }
        let epoch = crate::identity::device_directory::cache_epoch();
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
    /// and the current governance Station's authority bundle is where that
    /// head is authenticated.
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
        if matches!(stream_ref, arkret_wire::CommitStreamRef::Realm { .. }) {
            // The Realm stream head travels inside the signed authority
            // bundle, so one authenticated read answers for it.
            let bundle = self
                .authority_client()
                .resolve_authority(&arkret_wire::AuthorityBundleRequest {
                    realm_id,
                    nonce: arkret_wire::Base64UrlString::new(uuid_v7().replace('-', ""))
                        .map_err(|error| anyhow::anyhow!("authority bundle nonce: {error}"))?,
                })
                .await
                .map_err(anyhow::Error::from)?;
            return Ok(bundle.realm_stream_head.commit_id);
        }
        // A Circle or Sidecar keeps its own independent stream and the bundle
        // does not carry its head, so the head is the tail of that one stream.
        let mut after_position = None;
        let mut head = None;
        loop {
            let page = self
                .scan_stream(&stream_ref, after_position, STREAM_SCAN_PAGE)
                .await?;
            if let Some(last) = page.committed_refs().pop() {
                head = Some(last.commit_id);
            }
            match page.last_position() {
                Some(position) if page.truncated() => after_position = Some(position),
                _ => {
                    return head.ok_or_else(|| {
                        anyhow::anyhow!(
                            "this scope's commit stream has no head to bind a Signal to"
                        )
                    });
                }
            }
        }
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
        let stream_head_ref = self.current_stream_head_for(&scope_ref).await?;
        let header = crate::signal::SignalHeader::new(
            scope_ref,
            arkret_sdk::ActorId::account(authority.clone()),
            device_id.clone(),
            stream_head_ref,
            payload.signal_class(),
            crate::clock::now_utc(),
        );
        self.send_signal(authority, header, material, payload, state_store)
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
        if header.sender_actor_id.as_account_id() != Some(authority) {
            anyhow::bail!("Signal sender does not match the encryption authority");
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
        self.submit_signal_envelope(&envelope).await
    }

    /// `POST /_arkret/self/signal` — `ak.self.signal.command.send.v1`.
    pub async fn submit_signal_envelope(
        &self,
        envelope: &arkret_wire::SignalEnvelope,
    ) -> anyhow::Result<arkret_sdk::SignalSubmitOutcome> {
        envelope
            .validate_structural()
            .map_err(|error| anyhow::anyhow!("signal submit rejected locally: {error}"))?;
        self.http
            .signal_send(envelope)
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

/// Freeze one signed producer Event as an authority submission.
fn event_submission(event: &arkret_sdk::AuthoredEvent) -> anyhow::Result<QueuedSubmission> {
    validate_signed_sdk_event_for_submit(event.event(), event.digest_suite())?;
    QueuedSubmission::new(arkret_wire::AuthoritySubmitRequest::Event(
        arkret_wire::EventCommitSubmission {
            event: event.event().clone(),
        },
    ))
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
