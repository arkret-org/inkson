//! `EventSubmitter` — the TransportClient-free durable/ephemeral event submission
//! engine. Holds the authenticated SDK http-client plus a lazily-populated,
//! per-instance service-describe cache. The cache lifetime matches the former
//! per-`TransportClient` `OnceCell`: the signing path (`event_proof_context`) fetches
//! `describe` at most once per submitter, and non-signing paths
//! (`submit_signed_*`, ephemeral, frontier, backfill) never fetch it.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock as SyncOnceLock, PoisonError};
use std::time::Duration;

#[cfg(test)]
use arkret_sdk::ErrorEnvelope;
use garth::outbound::BoxOutboundFuture;
use garth::{
    OutboundEngine, OutboundEngineOutcome, OutboundGenerationFenceDecision, OutboundPostAcceptHook,
    OutboundSubmitOutcome, OutboundSubmitter,
};
#[cfg(test)]
use reqwest::StatusCode;
use serde::Deserialize as _;
use serde_json::Value;
use tokio::sync::OnceCell;

#[cfg(test)]
use crate::api_error::TransportClientError;
use crate::ephemeral::{
    attach_broadcast_ephemeral_proof, build_presence_envelope, build_receipt_read_envelope,
    build_typing_envelope, ensure_events_submit_accepted,
    validate_outgoing_registered_event_payload,
};
use crate::models::{
    BackfillView, PresenceResult, ReceiptResult, ServiceDescribe, SubmitEventResult, TypingResult,
};
use crate::operation::uuid_v7;
#[cfg(test)]
use crate::service_parse::parse_server_description;
use crate::wire_helpers::query_component;

/// Authenticated durable/ephemeral event submission engine extracted from the
/// former `TransportClient` events surface. Constructed per authenticated call from
/// the shared SDK http-client (see `crate::transport::auth::with_event_submitter`).
pub struct EventSubmitter {
    http: arkret_sdk::http_client::Client,
    describe_cache: OnceCell<ServiceDescribe>,
}

#[derive(Debug, thiserror::Error)]
#[error("event {event_id} is durably queued for retry")]
pub(crate) struct DurablyQueuedError {
    pub(crate) event_id: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QueuedSdkEvent {
    pub(crate) event: arkret_sdk::Event,
    pub(crate) authoring_generation: crate::identity::authoring_generation::AuthoringGeneration,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub(crate) post_accept: Option<PostAcceptAction>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) enum PostAcceptAction {
    MlsSnapshot {
        realm_id: String,
        snapshot: crate::mls::persistence::MlsSnapshotEnvelope,
    },
}

fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn decode_queued_sdk_event(content: Value) -> arkret_sdk::Result<QueuedSdkEvent> {
    serde_json::from_value(content).map_err(|error| {
        arkret_sdk::Error::Protocol(format!("decode queued Inkson SDK event: {error}"))
    })
}

#[derive(Clone, Default)]
struct InksonPostAcceptHook {
    state_store: Option<crate::runtime::input::StateStoreHandle>,
}

impl OutboundPostAcceptHook for InksonPostAcceptHook {
    fn post_accept<'a>(
        &'a self,
        item: &'a garth::SendQueueItem,
        _event_id: &'a arkret_sdk::EventId,
        _duplicate: bool,
    ) -> BoxOutboundFuture<'a, ()> {
        Box::pin(async move {
            let queued = decode_queued_sdk_event(item.content.clone())
                .map_err(|error| garth::Error::Protocol(error.to_string()))?;
            let Some(action) = queued.post_accept else {
                return Ok(());
            };
            let store = self.state_store.as_ref().ok_or_else(|| {
                garth::Error::Protocol(
                    "queued post-accept action has no host state-store adapter".to_owned(),
                )
            })?;
            let barrier = match action {
                PostAcceptAction::MlsSnapshot { realm_id, snapshot } => store.write(|store| {
                    store.save_mls_snapshot(realm_id, snapshot);
                    store.begin_durable_flush().map_err(|error| {
                        garth::Error::Protocol(format!(
                            "begin durable MLS post-accept snapshot persist: {error}"
                        ))
                    })
                })?,
            };
            barrier.wait().await.map_err(|error| {
                garth::Error::Protocol(format!("persist MLS post-accept snapshot: {error}"))
            })
        })
    }
}

pub(crate) fn is_durably_queued_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<DurablyQueuedError>().is_some()
}

#[derive(Default)]
struct OutboundAttemptResults {
    accepted: Mutex<BTreeMap<String, SubmitEventResult>>,
    rejected: Mutex<BTreeMap<String, anyhow::Error>>,
}

struct EventOutboundSubmitter<'a> {
    owner: &'a EventSubmitter,
    results: &'a OutboundAttemptResults,
}

impl OutboundSubmitter for EventOutboundSubmitter<'_> {
    fn submit<'a>(
        &'a self,
        item: garth::SendQueueItem,
    ) -> BoxOutboundFuture<'a, OutboundSubmitOutcome> {
        Box::pin(async move {
            let event = decode_queued_sdk_event(item.content)
                .map_err(|error| garth::Error::Protocol(error.to_string()))?
                .event;
            match self.owner.submit_sdk_event_direct(&event).await {
                Ok(result) => {
                    let event_id =
                        arkret_sdk::EventId::new(result.event_id.clone()).map_err(|error| {
                            garth::Error::Protocol(format!(
                                "server returned invalid accepted event id: {error}"
                            ))
                        })?;
                    let duplicate = result.status == "duplicate";
                    self.results
                        .accepted
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .insert(item.transaction_id, result);
                    if duplicate {
                        Ok(OutboundSubmitOutcome::Duplicate { event_id })
                    } else {
                        Ok(OutboundSubmitOutcome::Accepted { event_id })
                    }
                }
                Err(error) => {
                    let reason = format!("{error:#}");
                    if let Some(delay) = outbound_retry_delay(&error) {
                        return Ok(OutboundSubmitOutcome::RetryAfter { delay, reason });
                    }
                    self.results
                        .rejected
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .insert(item.transaction_id, error);
                    Ok(OutboundSubmitOutcome::Rejected { reason })
                }
            }
        })
    }
}

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

fn verified_recovery_gate_cache() -> &'static Mutex<std::collections::BTreeSet<String>> {
    static CACHE: SyncOnceLock<Mutex<std::collections::BTreeSet<String>>> = SyncOnceLock::new();
    CACHE.get_or_init(|| Mutex::new(std::collections::BTreeSet::new()))
}

pub(crate) fn remember_verified_recovery_gate(authority_principal: &str, device_id: &str) {
    if authority_principal.trim().is_empty() || device_id.trim().is_empty() {
        return;
    }
    let mut cache = verified_recovery_gate_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    cache.insert(format!("{authority_principal}\u{1f}{device_id}"));
}

fn recovery_gate_cache_key(event: &arkret_sdk::Event) -> Option<String> {
    let authority_principal = event
        .executed_by
        .as_ref()
        .unwrap_or(&event.actor_id)
        .as_str();
    let signer = crate::event_signer::active_signer()?;
    let device_id = signer.device_id()?;
    Some(format!("{authority_principal}\u{1f}{device_id}"))
}

pub(crate) fn reset_verified_recovery_gates() {
    let mut cache = verified_recovery_gate_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    cache.clear();
}

fn actor_frontier_refresh_error(actor_id: &str, error: anyhow::Error) -> anyhow::Error {
    error.context(format!(
        "refresh actor frontier for {actor_id} before submit"
    ))
}

fn pending_chat_message_ids_from_snapshot(
    snapshot: &garth::SendQueueSnapshot,
) -> std::collections::BTreeSet<String> {
    use garth::SendQueueStatus;

    snapshot
        .items
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                SendQueueStatus::Queued | SendQueueStatus::Sending | SendQueueStatus::Failed
            )
        })
        .filter(|item| {
            matches!(
                &item.kind,
                garth::SendQueueItemKind::Custom { kind }
                    if kind == "ak.message.create"
            )
        })
        .filter_map(|item| decode_queued_sdk_event(item.content.clone()).ok())
        .filter_map(|queued| {
            queued
                .event
                .payload
                .get("message_id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|message_id| !message_id.is_empty())
                .map(ToOwned::to_owned)
        })
        .collect()
}

/// Project pending chat message ids directly from the one durable Garth queue.
/// The chat UI uses this snapshot instead of maintaining a second plaintext
/// outbox with separate replay semantics.
pub(crate) async fn pending_chat_outbound_message_ids(
    actor_id: &str,
) -> anyhow::Result<std::collections::BTreeSet<String>> {
    let outbound = OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open(actor_id)?);
    let snapshot = outbound.snapshot().await?;
    Ok(pending_chat_message_ids_from_snapshot(&snapshot))
}

fn completed_outbound_result(item: &garth::SendQueueItem) -> SubmitEventResult {
    SubmitEventResult {
        event_id: item
            .remote_event_id
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        status: "accepted".to_owned(),
        cursor: String::new(),
        receipt: Value::Null,
    }
}

fn outbound_store_scope(event: &arkret_sdk::Event, durable_post_accept: bool) -> String {
    let actor = event.actor_id.as_str();
    if durable_post_accept {
        format!("{actor}\u{1f}mls-durable-post-accept")
    } else if event.kind.as_str().starts_with("ak.mls.") {
        // Legacy MLS callers still persist their snapshot after this method
        // returns. Keep them host-only until they adopt the durable action.
        format!("{actor}\u{1f}mls-host-only")
    } else {
        actor.to_owned()
    }
}

fn durable_mls_store_scope(actor_id: &str) -> String {
    format!("{actor_id}\u{1f}mls-durable-post-accept")
}

/// A browser runtime has multiple outbound triggers: the foreground writer
/// and the account-sync drain. Garth engines opened on the same durable store
/// do not share an in-memory lease, so without a runtime single-writer gate
/// both triggers can prepare and sign the same Event against different actor
/// frontiers. The server then correctly accepts one canonical envelope and
/// rejects the other as `duplicate_conflict`.
fn outbound_submit_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

impl EventSubmitter {
    pub fn new(http: arkret_sdk::http_client::Client) -> Self {
        Self {
            http,
            describe_cache: OnceCell::new(),
        }
    }

    /// The shared SDK http-client backing this submitter. Event-authoring free
    /// functions that also need a plain transport call (for example the
    /// account-data actor-scope lookup preceding a `ak.account_data.set`) reach
    /// it through here instead of holding a second `Client`.
    pub(crate) fn http(&self) -> &arkret_sdk::http_client::Client {
        &self.http
    }

    async fn resolve_queue_generation_fence(
        &self,
        outbound: &OutboundEngine<crate::outbound_store::InksonOutboundStore>,
    ) -> anyhow::Result<crate::identity::authoring_generation::ResolvedQueueGenerationFence> {
        use garth::SendQueueStatus;

        use crate::identity::authoring_generation::CurrentEventAuthoringGeneration;

        let mut decisions = BTreeMap::new();
        for item in outbound.snapshot().await?.items {
            if !matches!(
                item.status,
                SendQueueStatus::Queued | SendQueueStatus::Sending | SendQueueStatus::Failed
            ) {
                continue;
            }
            let queued = decode_queued_sdk_event(item.content.clone())?;
            let decision = match crate::identity::authoring_generation::resolve_current_event_authoring_generation(
                &self.http,
                &queued.event,
            )
            .await?
            {
                CurrentEventAuthoringGeneration::Active(current)
                    if current == queued.authoring_generation =>
                {
                    OutboundGenerationFenceDecision::Current
                }
                CurrentEventAuthoringGeneration::Active(_) => {
                    OutboundGenerationFenceDecision::Quarantine {
                        reason: "authoring_generation_superseded".to_owned(),
                    }
                }
                CurrentEventAuthoringGeneration::Quarantine(reason) => {
                    OutboundGenerationFenceDecision::Quarantine { reason }
                }
            };
            decisions.insert(item.transaction_id, decision);
        }
        Ok(crate::identity::authoring_generation::ResolvedQueueGenerationFence::new(decisions))
    }

    /// Resume queued events for this actor without requiring a new user send.
    /// The account runner calls this after it has rebuilt an authenticated
    /// client, so process/browser restarts eventually drain pending work.
    pub(crate) async fn drain_outbound(&self, actor_id: &str) -> anyhow::Result<usize> {
        let _single_writer = outbound_submit_lock().lock().await;
        let outbound =
            OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open(actor_id)?);
        let results = OutboundAttemptResults::default();
        let submitter = EventOutboundSubmitter {
            owner: self,
            results: &results,
        };
        let mut completed = 0usize;
        loop {
            let fence = self.resolve_queue_generation_fence(&outbound).await?;
            match outbound
                .submit_next_with_fence(&submitter, &fence, chrono::Utc::now())
                .await?
            {
                OutboundEngineOutcome::Accepted(_) | OutboundEngineOutcome::Duplicate(_) => {
                    completed = completed.saturating_add(1);
                }
                OutboundEngineOutcome::Rejected { .. } | OutboundEngineOutcome::Terminal { .. } => {
                    completed = completed.saturating_add(1);
                }
                OutboundEngineOutcome::Quarantined { item, reason } => {
                    tracing::warn!(
                        transaction_id = %item.transaction_id,
                        %reason,
                        "durable outbound item quarantined by authoring-generation fence"
                    );
                    completed = completed.saturating_add(1);
                }
                OutboundEngineOutcome::Idle | OutboundEngineOutcome::RetryAt { .. } => {
                    return Ok(completed);
                }
            }
        }
    }

    /// Resume MLS commits that carry their encrypted post-accept snapshot.
    /// The hook commits the snapshot before Garth marks the item sent; hook
    /// failure leaves the event retryable, so a later duplicate response can
    /// finish the same idempotent action.
    pub(crate) async fn drain_mls_outbound(
        &self,
        actor_id: &str,
        state_store: crate::runtime::input::StateStoreHandle,
    ) -> anyhow::Result<usize> {
        let _single_writer = outbound_submit_lock().lock().await;
        let outbound = OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open(
            &durable_mls_store_scope(actor_id),
        )?);
        let results = OutboundAttemptResults::default();
        let submitter = EventOutboundSubmitter {
            owner: self,
            results: &results,
        };
        let hook = InksonPostAcceptHook {
            state_store: Some(state_store),
        };
        let mut completed = 0usize;
        loop {
            let fence = self.resolve_queue_generation_fence(&outbound).await?;
            match outbound
                .submit_next_with_fence_and_hook(&submitter, &fence, &hook, chrono::Utc::now())
                .await?
            {
                OutboundEngineOutcome::Accepted(_)
                | OutboundEngineOutcome::Duplicate(_)
                | OutboundEngineOutcome::Rejected { .. }
                | OutboundEngineOutcome::Terminal { .. } => {
                    completed = completed.saturating_add(1);
                }
                OutboundEngineOutcome::Quarantined { item, reason } => {
                    tracing::warn!(
                        transaction_id = %item.transaction_id,
                        %reason,
                        "durable MLS outbound item quarantined by authoring-generation fence"
                    );
                    completed = completed.saturating_add(1);
                }
                OutboundEngineOutcome::Idle | OutboundEngineOutcome::RetryAt { .. } => {
                    return Ok(completed);
                }
            }
        }
    }

    async fn describe(&self) -> anyhow::Result<ServiceDescribe> {
        self.http
            .describe()
            .await
            .map_err(|error| anyhow::anyhow!("server describe: {error}"))
    }

    async fn ensure_recovery_material_ready(
        &self,
        event: &arkret_sdk::Event,
    ) -> anyhow::Result<()> {
        let cache_key = recovery_gate_cache_key(event);
        let verification = async {
            let policy: arkret_sdk::RecoveryPolicyActiveOutcome = self
                .http
                .get("/_arkret/root/identity/recovery-policy")
                .await
                .map_err(anyhow::Error::from)?;
            let backups = self
                .http
                .list_key_backups(&arkret_sdk::KeyBackupsListQuery {
                    series_id: None,
                    backup_class: Some(arkret_sdk::BackupClass::DidRecovery),
                    cursor: None,
                    limit: None,
                })
                .await
                .map_err(anyhow::Error::from)?;
            match crate::recovery_strand::first_backup_gate_status_from_payloads(
                &serde_json::to_value(policy)?,
                &serde_json::to_value(backups)?,
            ) {
                crate::recovery_strand::FirstBackupGateStatus::Satisfied { .. } => Ok(()),
                crate::recovery_strand::FirstBackupGateStatus::Blocked(reason) => anyhow::bail!(
                    "recovery_material_pending blocks post-bootstrap persistent write: {reason:?}"
                ),
            }
        }
        .await;

        match verification {
            Ok(()) => {
                if let Some(cache_key) = cache_key {
                    verified_recovery_gate_cache()
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .insert(cache_key);
                }
                Ok(())
            }
            Err(error)
                if outbound_retry_delay(&error).is_some()
                    && cache_key.as_ref().is_some_and(|cache_key| {
                        verified_recovery_gate_cache()
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .contains(cache_key)
                    }) =>
            {
                Ok(())
            }
            Err(error) if outbound_retry_delay(&error).is_some() => Err(error.context(
                format!(
                    "retryable recovery-material verification failed without a verified cache entry (cache_key={}, entries={})",
                    cache_key.is_some(),
                    verified_recovery_gate_cache()
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .len(),
                ),
            )),
            Err(error) => Err(error),
        }
    }

    /// Lazily fetch + cache the service describe for this submitter. Only the
    /// signing path calls this, so a submitter that never signs never fetches.
    async fn describe_cached(&self) -> anyhow::Result<&ServiceDescribe> {
        self.describe_cache
            .get_or_try_init(|| async { self.describe().await })
            .await
    }

    pub(crate) async fn service_id(&self) -> anyhow::Result<String> {
        Ok(self.describe_cached().await?.service_id.to_string())
    }

    /// Mint a DataEvent `seal_ref` head from the membership-gated Realm Seal
    /// view. Only the CBA data-plane stamping path uses this.
    pub(crate) async fn current_seal_for(&self, realm_id: &str) -> anyhow::Result<String> {
        let view = self.events_frontier_realm_seal_view(realm_id).await?;
        Ok(view.seal_id.to_string())
    }
    /// Query durable events through the current `/_arkret/self/events` surface,
    /// following pagination to completion (COR-07).
    pub async fn backfill(&self, realm_id: &str) -> anyhow::Result<BackfillView> {
        let outcome = self
            .http
            .events_query_all_pages(realm_id)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(outcome.into())
    }

    pub(crate) async fn find_mls_genesis_event_id(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<Option<arkret_sdk::EventId>> {
        // COR-07: the MLS genesis event may sit past the first page; paginate so
        // it is never silently judged "absent" because of front-page noise.
        let outcome = self
            .http
            .events_query_all_pages(realm_id)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(mls_genesis_event_id_from_events(&outcome, realm_id))
    }

    /// Stream the canonical `/_arkret/self/events/subscribe` NDJSON response and
    /// invoke `on_frame` once per parsed frame.
    ///
    /// Round R2/R3 (T02) — typing notifications are wire-scope-ephemeral
    /// (`ak.typing`). They MUST strand through the canonical
    /// `ak.self.ephemeral.command.send` operation (`POST /_arkret/self/ephemeral`), never
    /// through `ak.self.events.command.submit` or a deployment-local typing shim.
    pub async fn send_typing(
        &self,
        realm_id: &str,
        actor: &str,
        device_id: &str,
        strand_id: &str,
        typing: bool,
    ) -> anyhow::Result<TypingResult> {
        let mut envelope = build_typing_envelope(realm_id, actor, device_id, strand_id, typing)?;
        attach_broadcast_ephemeral_proof(&mut envelope)?;
        let response = self.submit_ephemeral_envelope(&envelope).await?;
        Ok(TypingResult {
            ok: response.accepted,
        })
    }

    pub async fn send_presence(
        &self,
        realm_id: &str,
        actor: &str,
        device_id: &str,
        state: &str,
        status_message: Option<&str>,
        last_active_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<PresenceResult> {
        let mut envelope = build_presence_envelope(
            realm_id,
            actor,
            device_id,
            state,
            status_message,
            last_active_at,
        )?;
        attach_broadcast_ephemeral_proof(&mut envelope)?;
        let response = self.submit_ephemeral_envelope(&envelope).await?;
        Ok(PresenceResult {
            ok: response.accepted,
        })
    }

    /// Round R2/R3 (T02) — read receipts (`ak.receipt.read`) are wire-scope-
    /// ephemeral. They MUST strand through `ak.self.ephemeral.command.send`; the
    /// `ak.self.events.command.submit` durable path and deployment-local `/receipts`
    /// shims MUST NOT be used.
    pub async fn send_receipt(
        &self,
        realm_id: &str,
        actor: &str,
        device_id: &str,
        strand_id: &str,
        event_id: &str,
        receipt_type: &str,
    ) -> anyhow::Result<ReceiptResult> {
        // Only `ak.receipt.read` is an ephemeral receipt; other receipt
        // types (delivered/franking/etc.) stay on their own paths. Guard
        // the kind here so we don't accidentally widen the contract.
        if receipt_type != "ak.receipt.read" {
            anyhow::bail!("unsupported ephemeral receipt_type {receipt_type:?}");
        }
        let mut envelope =
            build_receipt_read_envelope(realm_id, actor, device_id, strand_id, event_id)?;
        attach_broadcast_ephemeral_proof(&mut envelope)?;
        let response = self.submit_ephemeral_envelope(&envelope).await?;
        Ok(ReceiptResult {
            ok: response.accepted,
        })
    }

    /// `GET /_arkret/self/events/frontier?realm_id=` — Realm Seal view
    /// `{realm_id, seal_id, control_event_set_root, state_root, hlc?}`.
    ///
    /// This is the spec-registered account-client sourcing for minting a
    /// single-leaf Control Move `seal_basis` (`view.seal_basis()`) and a
    /// DataEvent `seal_ref` (`view.seal_id`) — SPEC-SOL-003 resolution.
    /// Fails closed (never fabricates a basis) when the server cannot
    /// serve the view or answers for a different Realm.
    pub async fn events_frontier_realm_seal_view(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<arkret_sdk::RealmSealFrontierView> {
        let (view, _) = self.events_frontier_realm_state(realm_id).await?;
        Ok(view)
    }

    async fn events_frontier_realm_state(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<(
        arkret_sdk::RealmSealFrontierView,
        Vec<arkret_sdk::ManagedAgentPcrSealHeadReceipt>,
    )> {
        let realm_id_query = query_component(realm_id);
        let state: arkret_sdk::EventsFrontierAccountClientState = self
            .http
            .get(&format!(
                "/_arkret/self/events/frontier?realm_id={realm_id_query}"
            ))
            .await
            .map_err(anyhow::Error::from)?;
        let arkret_sdk::EventsFrontierView::RealmSealView(view) = state.frontier else {
            anyhow::bail!(
                "events/frontier for realm_id={realm_id} did not return a Realm Seal view — \
                 cannot mint seal_basis / seal_ref"
            );
        };
        if view.realm_id.as_str() != realm_id {
            anyhow::bail!(
                "events/frontier answered for realm {} instead of {realm_id}",
                view.realm_id
            );
        }
        Ok((view, state.receipts))
    }

    /// Return the accepted controller-signed head needed to author the next
    /// managed Agent PCR Seal. The head can intentionally lag accepted Events.
    pub async fn events_frontier_managed_agent_seal_head(
        &self,
        realm_id: &str,
        controller_id: &arkret_sdk::Did,
    ) -> anyhow::Result<(arkret_sdk::RealmSealFrontierView, arkret_sdk::Seal)> {
        let (view, receipts) = self.events_frontier_realm_state(realm_id).await?;
        let receipt = receipts.first().ok_or_else(|| {
            anyhow::anyhow!("events/frontier omitted the accepted managed Agent PCR Seal head")
        })?;
        let seal = receipt.seal.clone();
        crate::mls::governance_proof::prefetch_managed_agent_pcr_seal_head_device_key(
            &self.http,
            &seal,
            controller_id,
        )
        .await
        .map_err(|error| {
            anyhow::anyhow!("resolve managed Agent PCR Seal head device key: {error}")
        })?;
        crate::mls::governance_proof::verify_managed_agent_pcr_seal_head(&seal, controller_id)
            .map_err(|error| anyhow::anyhow!("invalid managed Agent PCR Seal head: {error}"))?;
        if seal.realm_id != view.realm_id
            || seal.id != view.seal_id
            || seal.control_event_set_root != view.control_event_set_root
            || seal.state_root != view.state_root
        {
            anyhow::bail!("managed Agent PCR Seal head differs from its frontier view");
        }
        Ok((view, seal))
    }

    /// `GET /_arkret/self/events/frontier?actor_id=` — actor frontier
    /// `{actor_id, actor_seq, event_id}` (highest accepted actor_seq
    /// visible to the caller).
    pub async fn events_frontier_actor(
        &self,
        actor_id: &str,
    ) -> anyhow::Result<arkret_sdk::ActorFrontierView> {
        let actor_id_query = query_component(actor_id);
        let state: arkret_sdk::EventsFrontierAccountClientState = self
            .http
            .get(&format!(
                "/_arkret/self/events/frontier?actor_id={actor_id_query}"
            ))
            .await
            .map_err(anyhow::Error::from)?;
        let arkret_sdk::EventsFrontierView::Actor(view) = state.frontier else {
            anyhow::bail!(
                "events/frontier for actor_id={actor_id} did not return an actor frontier"
            );
        };
        view.validate()
            .map_err(|error| anyhow::anyhow!("invalid actor frontier: {error}"))?;
        Ok(view)
    }

    /// `GET /_arkret/self/events/describe` — spec binds the response to the
    /// canonical `ServiceDescribe` shape (OpenAPI `ak.self.events.query.describe`).
    /// YOU-01-016: the former soland-private `SolandEventsDescribeResBody`
    /// mirror (with its non-spec `capabilities` blob) was removed.
    pub async fn events_describe(&self) -> anyhow::Result<arkret_sdk::ServiceDescribe> {
        self.http
            .events_describe()
            .await
            .map_err(|error| anyhow::anyhow!("events describe: {error}"))
    }

    pub(crate) async fn event_proof_context(
        &self,
    ) -> anyhow::Result<crate::event_signer::EventProofContext> {
        let describe = self.describe_cached().await?;
        Ok(event_proof_context_from_description(describe))
    }

    /// Wire-submit a fully-prepared, already-signed SDK [`arkret_sdk::Event`].
    /// This is the only single-event HTTP tail that serialises onto
    /// `POST /_arkret/self/events`.
    async fn post_signed_sdk_event(
        &self,
        signed: &arkret_sdk::Event,
        idempotency_key: String,
    ) -> anyhow::Result<SubmitEventResult> {
        validate_signed_sdk_event_for_submit(signed)?;
        let response: arkret_sdk::EventsSubmitOutcome = self
            .http
            .events_submit_with_options(
                signed,
                &arkret_sdk::http_client::ClientRequestOptions::new()
                    .request_id(idempotency_key.clone())
                    .idempotency_key(idempotency_key),
            )
            .await
            .map_err(anyhow::Error::from)?;
        ensure_events_submit_accepted(&response)?;
        Ok(SubmitEventResult::from(response))
    }

    /// Submit a fully-prepared, already-signed SDK [`arkret_sdk::Event`]
    /// without passing through the local builder path.
    ///
    /// This is for service-returned Events that are already the authoritative
    /// wire object, such as account-authority device enrollment. It does not
    /// stamp `seal_ref` or attach proofs because either change would mutate the
    /// signed transcript.
    pub(crate) async fn submit_signed_sdk_event(
        &self,
        signed: &arkret_sdk::Event,
    ) -> anyhow::Result<SubmitEventResult> {
        self.ensure_recovery_material_ready(signed).await?;
        self.post_signed_sdk_event(signed, uuid_v7()).await
    }

    /// Submit a SDK-typed Event, signing it with the active signer when needed.
    pub(crate) async fn submit_sdk_event(
        &self,
        event: &arkret_sdk::Event,
    ) -> anyhow::Result<SubmitEventResult> {
        self.submit_sdk_event_queued(event, None, None).await
    }

    pub(crate) async fn submit_mls_event_with_snapshot(
        &self,
        event: &arkret_sdk::Event,
        realm_id: String,
        snapshot: crate::mls::persistence::MlsSnapshotEnvelope,
        state_store: crate::runtime::input::StateStoreHandle,
    ) -> anyhow::Result<SubmitEventResult> {
        self.submit_sdk_event_queued(
            event,
            Some(PostAcceptAction::MlsSnapshot { realm_id, snapshot }),
            Some(state_store),
        )
        .await
    }

    async fn submit_sdk_event_queued(
        &self,
        event: &arkret_sdk::Event,
        post_accept: Option<PostAcceptAction>,
        state_store: Option<crate::runtime::input::StateStoreHandle>,
    ) -> anyhow::Result<SubmitEventResult> {
        let _single_writer = outbound_submit_lock().lock().await;
        self.ensure_recovery_material_ready(event).await?;
        let transaction_id = event.event_id.to_string();
        let durable_post_accept = post_accept.is_some();
        let outbound = OutboundEngine::new(crate::outbound_store::InksonOutboundStore::open(
            &outbound_store_scope(event, durable_post_accept),
        )?);
        let authoring_generation =
            match crate::identity::authoring_generation::resolve_event_authoring_generation(
                &self.http, event,
            )
            .await
            {
                Ok(generation) => generation,
                Err(error) if outbound_retry_delay(&error).is_some() => {
                    match crate::identity::authoring_generation::cached_event_authoring_generation(
                        event,
                    )? {
                        Some(generation) => generation,
                        None => {
                            return Err(error.context(
                                "retryable authoring-generation lookup failed without a verified cache entry",
                            ));
                        }
                    }
                }
                Err(error) => return Err(error),
            };
        outbound
            .enqueue(
                Some(transaction_id.clone()),
                event.realm_id.clone(),
                garth::SendQueueItemKind::Custom {
                    kind: event.kind.to_string(),
                },
                serde_json::to_value(QueuedSdkEvent {
                    event: event.clone(),
                    authoring_generation,
                    post_accept,
                })?,
                Vec::new(),
            )
            .await?;

        let results = OutboundAttemptResults::default();
        let submitter = EventOutboundSubmitter {
            owner: self,
            results: &results,
        };
        let hook = InksonPostAcceptHook { state_store };
        loop {
            let fence = match self.resolve_queue_generation_fence(&outbound).await {
                Ok(fence) => fence,
                Err(error) if outbound_retry_delay(&error).is_some() => {
                    return Err(DurablyQueuedError {
                        event_id: event.event_id.to_string(),
                    }
                    .into());
                }
                Err(error) => return Err(error),
            };
            match outbound
                .submit_next_with_fence_and_hook(&submitter, &fence, &hook, chrono::Utc::now())
                .await?
            {
                OutboundEngineOutcome::Accepted(item) | OutboundEngineOutcome::Duplicate(item)
                    if item.transaction_id == transaction_id =>
                {
                    if let Some(result) = results
                        .accepted
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&transaction_id)
                    {
                        return Ok(result);
                    }
                    return Ok(completed_outbound_result(&item));
                }
                OutboundEngineOutcome::Accepted(_) | OutboundEngineOutcome::Duplicate(_) => {}
                OutboundEngineOutcome::RetryAt { item, at }
                    if item.transaction_id == transaction_id =>
                {
                    tracing::debug!(event_id = %event.event_id, %at, "event remains in durable outbound queue");
                    return Err(DurablyQueuedError {
                        event_id: event.event_id.to_string(),
                    }
                    .into());
                }
                OutboundEngineOutcome::RetryAt { .. } => {}
                OutboundEngineOutcome::Rejected { item, .. }
                | OutboundEngineOutcome::Terminal { item, .. }
                    if item.transaction_id == transaction_id =>
                {
                    if let Some(error) = results
                        .rejected
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&transaction_id)
                    {
                        return Err(error);
                    }
                    anyhow::bail!("queued event {} reached a terminal state", event.event_id);
                }
                OutboundEngineOutcome::Rejected { .. } | OutboundEngineOutcome::Terminal { .. } => {
                }
                OutboundEngineOutcome::Quarantined { item, reason }
                    if item.transaction_id == transaction_id =>
                {
                    anyhow::bail!(
                        "queued event {} quarantined by authoring-generation fence: {}",
                        event.event_id,
                        reason
                    );
                }
                OutboundEngineOutcome::Quarantined { .. } => {}
                OutboundEngineOutcome::Idle => {
                    let snapshot = outbound.snapshot().await?;
                    if let Some(item) = snapshot
                        .items
                        .iter()
                        .find(|item| item.transaction_id == transaction_id)
                        && item.remote_event_id.is_some()
                    {
                        return Ok(completed_outbound_result(item));
                    }
                    return Err(DurablyQueuedError {
                        event_id: event.event_id.to_string(),
                    }
                    .into());
                }
            }
        }
    }

    async fn submit_sdk_event_direct(
        &self,
        event: &arkret_sdk::Event,
    ) -> anyhow::Result<SubmitEventResult> {
        let retry_actor_seq_cas = event.proofs.is_empty();
        let (signed, idempotency_key) = self.prepare_sdk_event_for_submit(event).await?;
        match self
            .post_signed_sdk_event(&signed, idempotency_key.clone())
            .await
        {
            Ok(result) => Ok(result),
            Err(error)
                if retry_actor_seq_cas
                    && crate::api_error::is_actor_seq_cas_conflict_error(&error) =>
            {
                tracing::warn!(
                    event_id = %event.event_id,
                    actor_id = %event.actor_id,
                    kind = %event.kind,
                    "actor frontier advanced during SDK Event submit; refreshing and retrying once"
                );
                let (signed, idempotency_key) = self.prepare_sdk_event_for_submit(event).await?;
                self.post_signed_sdk_event(&signed, idempotency_key).await
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn prepare_sdk_event_for_submit(
        &self,
        event: &arkret_sdk::Event,
    ) -> anyhow::Result<(arkret_sdk::Event, String)> {
        let mut signed = event.clone();
        self.refresh_unsigned_sdk_event_actor_frontier(&mut signed)
            .await?;
        self.stamp_cba_basis_for_sdk_event(&mut signed).await?;
        if signed.proofs.is_empty() {
            let proof_context = self.event_proof_context().await?;
            crate::event_signer::sign_sdk_event_with_active_context(&mut signed, proof_context)
                .map_err(|err| {
                    anyhow::anyhow!(
                        "no active signer configured \u{2014} cannot submit unsigned SDK Event: {err}"
                    )
                })?;
        }
        let idempotency_key = signed
            .unsigned
            .get("local_operation_idempotency_alias")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(uuid_v7);
        Ok((signed, idempotency_key))
    }

    pub(crate) async fn stamp_cba_basis_for_sdk_event(
        &self,
        event: &mut arkret_sdk::Event,
    ) -> anyhow::Result<()> {
        if event.seal_ref.is_some()
            || event.auth_context.is_some()
            || event.seal_basis.is_some()
            || event.effects.is_empty()
            || cba_exempt_reducer_kind(&event.kind)
        {
            return Ok(());
        }
        match cba_effect_plane_for_event(event)? {
            CbaEffectPlane::Control => {
                let seal_view = self
                    .events_frontier_realm_seal_view(event.realm_id.as_str())
                    .await?;
                event.seal_basis = Some(seal_view.seal_basis());
            }
            CbaEffectPlane::Data => {
                if !event.preconditions.is_empty() {
                    anyhow::bail!(
                        "DataEvent {} carries preconditions; CBA DataEvents must use effects + seal_ref + auth_context only",
                        event.event_id
                    );
                }
                let seal = self.current_seal_for(event.realm_id.as_str()).await?;
                event.seal_ref = Some(
                    arkret_sdk::SealId::new(seal)
                        .map_err(|err| anyhow::anyhow!("current seal id is invalid: {err}"))?,
                );
                event.auth_context = Some(data_event_auth_context(event)?);
            }
        }
        Ok(())
    }

    async fn refresh_unsigned_sdk_event_actor_frontier(
        &self,
        event: &mut arkret_sdk::Event,
    ) -> anyhow::Result<()> {
        if !event.proofs.is_empty() {
            return Ok(());
        }
        let actor_id = event.actor_id.as_str().to_owned();
        let observed_frontier = match self.events_frontier_actor(&actor_id).await {
            Ok(frontier) => {
                apply_actor_frontier_to_sdk_event(event, &frontier)?;
                Some(frontier.actor_seq)
            }
            Err(error) if crate::api_error::is_actor_frontier_absent_error(&error) => {
                event.actor_seq = 1;
                event.prev_refs.clear();
                tracing::debug!(
                    actor_id = %actor_id,
                    event_id = %event.event_id,
                    "no actor frontier visible; submitting actor-chain genesis event"
                );
                None
            }
            Err(error) => return Err(actor_frontier_refresh_error(&actor_id, error)),
        };
        let stamp = crate::signing_stamp::issue_event_stamp(event, observed_frontier).await?;
        event.actor_seq = stamp.actor_seq;
        event.hlc = stamp.hlc;
        Ok(())
    }

    /// `ak.self.events.command.submit` in batch form over typed envelopes. Spec binds
    /// events.submit to `POST /_arkret/self/events` and distinguishes the three
    /// accepted body shapes (single envelope,
    /// [`arkret_sdk::EventsSubmitBatchRequestBody`],
    /// [`arkret_sdk::EventsSubmitFederationRequestBody`]) by JSON shape, not
    /// by URL suffix. The federation shape is S2S only and inkson MUST
    /// NEVER serialise it.
    ///
    /// SDK Events MUST already be signed by the caller (typically via
    /// `event_signer::sign_sdk_event_with_active_context`) — the batch path
    /// does not auto-sign because callers commonly need an atomic seal_ref +
    /// sign sequence the per-event helper cannot replicate.
    pub(crate) async fn submit_signed_sdk_events_batch(
        &self,
        sdk_events: &[arkret_sdk::Event],
        idempotency_key: Option<&str>,
    ) -> anyhow::Result<arkret_sdk::EventsSubmitOutcome> {
        let first_event = sdk_events
            .first()
            .ok_or_else(|| anyhow::anyhow!("events.submit batch must not be empty"))?;
        self.ensure_recovery_material_ready(first_event).await?;
        // YOU-01-016: the former `capabilities.batch_submit` probe (a
        // non-spec soland capability field) was removed. The batch request
        // body is one of the three spec-defined `ak.self.events.command.submit`
        // shapes (distinguished by JSON shape), so it is sent
        // unconditionally — no capability negotiation exists in the spec.
        for sdk_event in sdk_events {
            validate_signed_sdk_event_for_submit(sdk_event)?;
        }
        let body = arkret_sdk::EventsSubmitBatchRequestBody {
            events: sdk_events.to_vec(),
            idempotency_key: idempotency_key.map(ToOwned::to_owned),
        };
        let idem = idempotency_key
            .map(ToOwned::to_owned)
            .unwrap_or_else(uuid_v7);
        let response: arkret_sdk::EventsSubmitOutcome = self
            .http
            .post_with_options(
                "/_arkret/self/events",
                &body,
                &arkret_sdk::http_client::ClientRequestOptions::new()
                    .request_id(idem.clone())
                    .idempotency_key(idem),
            )
            .await
            .map_err(anyhow::Error::from)?;
        ensure_events_submit_accepted(&response)?;
        Ok(response)
    }

    pub(crate) async fn submit_sdk_events_batch(
        &self,
        _realm_id: &str,
        events: Vec<arkret_sdk::Event>,
        idempotency_key: Option<&str>,
    ) -> anyhow::Result<arkret_sdk::EventsSubmitOutcome> {
        if events
            .first()
            .is_some_and(|event| event.kind.as_str() == arkret_sdk::events::EventKind::REALM_CREATE)
            && events.get(1).is_some_and(|event| {
                event.kind.as_str() == arkret_sdk::events::EventKind::CAPABILITY_GRANT
            })
        {
            crate::identity::authoring_generation::resolve_event_authoring_generation(
                &self.http, &events[0],
            )
            .await?;
        }
        let events = self.prepare_sdk_events_batch(events).await?;
        self.submit_signed_sdk_events_batch(&events, idempotency_key)
            .await
    }

    pub(crate) async fn prepare_sdk_events_batch(
        &self,
        mut events: Vec<arkret_sdk::Event>,
    ) -> anyhow::Result<Vec<arkret_sdk::Event>> {
        let first_is_realm_create = events.first().is_some_and(|event| {
            event.kind.as_str() == arkret_sdk::events::EventKind::REALM_CREATE
        });
        let is_identity_anchor_unit = first_is_realm_create
            && events.len() == 2
            && events.get(1).is_some_and(|event| {
                event.kind.as_str() == arkret_sdk::events::EventKind::DEVICE_AUTHORIZE
            });
        let is_ordinary_realm_bootstrap = if first_is_realm_create && !is_identity_anchor_unit {
            arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&events)
                .map_err(|error| anyhow::anyhow!(error.reason_code()))?;
            true
        } else {
            false
        };
        for event in &mut events {
            attach_capability_grant_payload_proof(event)?;
        }
        let mut batch_frontiers = BTreeMap::<String, (u64, arkret_sdk::EventId)>::new();
        for event in &mut events {
            let actor_id = event.actor_id.to_string();
            if event.proofs.is_empty() {
                if let Some((actor_seq, event_id)) = batch_frontiers.get(&actor_id) {
                    event.prev_refs = vec![event_id.clone()];
                    let stamp =
                        crate::signing_stamp::issue_event_stamp(event, Some(*actor_seq)).await?;
                    event.actor_seq = stamp.actor_seq;
                    event.hlc = stamp.hlc;
                } else {
                    self.refresh_unsigned_sdk_event_actor_frontier(event)
                        .await?;
                }
            }
            batch_frontiers.insert(actor_id, (event.actor_seq, event.event_id.clone()));
        }
        for event in &mut events {
            if !is_ordinary_realm_bootstrap && !is_identity_anchor_unit {
                self.stamp_cba_basis_for_sdk_event(event).await?;
            }
        }
        let proof_context = self.event_proof_context().await?;
        for event in &mut events {
            if event.proofs.is_empty() {
                crate::event_signer::sign_sdk_event_with_active_context(
                    event,
                    proof_context.clone(),
                )
                .map_err(|err| {
                    anyhow::anyhow!(
                        "no active signer configured \u{2014} cannot submit SDK Event batch: {err}"
                    )
                })?;
            }
        }
        Ok(events)
    }

    /// Round R2/R3 (T02) — POST a broadcast ephemeral signal to the
    /// canonical ephemeral channel (`POST /_arkret/self/ephemeral`) instead of the
    /// durable `/_arkret/self/events` endpoint. The envelope MUST validate against
    /// `ak.schema.ephemeral_envelope.v1` (kind in
    /// {`ak.call.signal`, `ak.presence`, `ak.typing`, `ak.receipt.read`}, and
    /// `expires_at - sent_at <= 300_000` ms). The four broadcast ephemeral
    /// signal kinds MUST NOT travel via `ak.self.events.command.submit`; this method is
    /// the single approved network path.
    pub async fn submit_ephemeral_envelope(
        &self,
        envelope: &arkret_sdk::EphemeralEnvelope,
    ) -> anyhow::Result<arkret_sdk::EphemeralSubmitOutcome> {
        // Defensive re-validation. The constructor already enforced this,
        // but a caller could mutate a raw envelope in place between build
        // and submit. Fail fast with the canonical error code rather than
        // shipping a non-conformant payload to the wire.
        if !arkret_sdk::events::is_ephemeral_kind(&envelope.kind) {
            anyhow::bail!(
                "ephemeral submit: kind {:?} is not in the broadcast ephemeral allowlist",
                envelope.kind
            );
        }
        let window_ms = envelope
            .expires_at
            .signed_duration_since(envelope.sent_at)
            .num_milliseconds();
        if window_ms <= 0
            || (window_ms as u64) > arkret_sdk::EPHEMERAL_ABSOLUTE_HARD_CEILING_MS as u64
        {
            anyhow::bail!(
                "ephemeral submit: expires_at - sent_at = {window_ms} ms violates 5-minute ceiling"
            );
        }
        self.http
            .post("/_arkret/self/ephemeral", envelope)
            .await
            .map_err(anyhow::Error::from)
    }

    /// `POST /_arkret/gate/account/agent-key-pair` —
    /// `ak.gate.account.command.pair_agent_key`. The runtime generated the
    /// key and PoP; the controller signs `authorize_event` locally before this
    /// method submits the pairing request.
    async fn agent_key_pair(
        &self,
        body: &arkret_sdk::models::AgentKeyPairRequestBody,
    ) -> anyhow::Result<arkret_sdk::models::AgentKeyPairOutcome> {
        let principal_server_url = self.http.base_url().as_str();
        let authority =
            crate::identity::account_auth::AuthorityResolver::discover(principal_server_url)
                .await?;
        let gate_account_base = url::Url::parse(&authority.gate_account_base)?;
        let authority_origin = gate_account_base.origin().ascii_serialization();
        let authority_http =
            arkret_sdk::http_client::Client::new(url::Url::parse(&authority_origin)?)?;
        authority_http
            .agent_key_pair(body)
            .await
            .map_err(anyhow::Error::from)
    }

    pub(crate) async fn agent_key_pair_with_authorize_event(
        &self,
        mut body: arkret_sdk::models::AgentKeyPairRequestBody,
        authorize_event: &arkret_sdk::Event,
    ) -> anyhow::Result<arkret_sdk::models::AgentKeyPairOutcome> {
        let (signed, _) = self.prepare_sdk_event_for_submit(authorize_event).await?;
        body.authorize_event = signed;
        self.agent_key_pair(&body).await
    }
}

/// Finalize the inner capability artifact before the outer Event is signed.
/// Capability grants have two distinct signatures: the issuer attestation over
/// the grant body, and the Event proof over the complete envelope.
pub(crate) fn attach_capability_grant_payload_proof(
    event: &mut arkret_sdk::Event,
) -> anyhow::Result<()> {
    if event.kind.as_str() != arkret_sdk::events::EventKind::CAPABILITY_GRANT {
        return Ok(());
    }
    let grant = event
        .payload
        .get_mut("grant")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow::anyhow!("capability grant payload requires grant object"))?;
    if grant
        .get("proofs")
        .and_then(Value::as_array)
        .is_some_and(|proofs| !proofs.is_empty())
    {
        return Ok(());
    }
    grant.insert("proofs".to_owned(), Value::Array(Vec::new()));
    let transcript = crate::canonical::canonical_json_bytes(grant)?;
    let signer = crate::event_signer::active_signer().ok_or_else(|| {
        anyhow::anyhow!("no active signer configured — cannot attest capability grant payload")
    })?;
    let proof = arkret_sdk::PayloadProof {
        kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
        alg: signer.algorithm().to_owned(),
        verification_method: signer.verification_method().to_owned(),
        payload_digest: arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(&transcript))
            .map_err(|error| anyhow::anyhow!("capability grant payload digest: {error}"))?,
        created_at: crate::clock::now_utc(),
        domain: None,
        audience: None,
        proof_purpose: Some(arkret_sdk::PayloadProofPurpose::IssuerAttestation),
        jws: signer.detached_jws_over(&transcript)?,
    };
    grant.insert(
        "proofs".to_owned(),
        serde_json::to_value(vec![proof])
            .map_err(|error| anyhow::anyhow!("capability grant proof encode: {error}"))?,
    );
    Ok(())
}

fn ensure_sdk_event_proofs_are_domain_bound(event: &arkret_sdk::Event) -> anyhow::Result<()> {
    for proof in &event.proofs {
        if proof
            .domain
            .as_deref()
            .is_none_or(|domain| domain.trim().is_empty())
        {
            anyhow::bail!(
                "event proof for {} is missing domain binding",
                event.event_id
            );
        }
        if proof.audience.is_none() {
            anyhow::bail!(
                "event proof for {} is missing audience binding",
                event.event_id
            );
        }
    }
    Ok(())
}

fn validate_signed_sdk_event_for_submit(event: &arkret_sdk::Event) -> anyhow::Result<()> {
    if event.proofs.is_empty() {
        anyhow::bail!(
            "submit refuses unsigned SDK Event (event_id={}, kind={})",
            event.event_id,
            event.kind.as_str()
        );
    }
    ensure_sdk_event_proofs_are_domain_bound(event)?;
    event.validate_proof_bindings().map_err(|err| {
        anyhow::anyhow!("event proof binding invalid for {}: {err}", event.event_id)
    })?;
    validate_outgoing_registered_event_payload(event.kind.as_str(), &event.payload)
}

fn apply_actor_frontier_to_sdk_event(
    event: &mut arkret_sdk::Event,
    frontier: &arkret_sdk::ActorFrontierView,
) -> anyhow::Result<()> {
    if frontier.actor_id.as_str() != event.actor_id.as_str() {
        anyhow::bail!(
            "actor frontier mismatch: event actor {} but frontier actor {}",
            event.actor_id,
            frontier.actor_id
        );
    }
    event.actor_seq = frontier.actor_seq.checked_add(1).ok_or_else(|| {
        anyhow::anyhow!("actor frontier sequence overflow for {}", event.actor_id)
    })?;
    event.prev_refs = frontier.event_id.iter().cloned().collect();
    Ok(())
}

fn mls_genesis_event_id_from_events(
    outcome: &arkret_sdk::EventsQueryOutcome,
    realm_id: &str,
) -> Option<arkret_sdk::EventId> {
    outcome
        .events
        .iter()
        .find(|event| {
            event.realm_id.as_str() == realm_id
                && event.kind.as_str() == arkret_sdk::events::EventKind::MLS_GENESIS
        })
        .map(|event| event.event_id.clone())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CbaEffectPlane {
    Data,
    Control,
}

const DATA_PLANE_CELL_FAMILIES: &[&str] = &[
    "ak.component.strand.discussion.timeline.v1",
    "ak.component.message.reactions.v1",
    "ak.component.pin.v1",
];

fn cba_exempt_reducer_kind(kind: &arkret_sdk::events::kinds::EventKind) -> bool {
    matches!(kind, arkret_sdk::events::kinds::EventKind::RealmCreate)
}

fn cba_effect_plane_for_event(event: &arkret_sdk::Event) -> anyhow::Result<CbaEffectPlane> {
    let mut observed = None;
    for effect in &event.effects {
        let plane = if DATA_PLANE_CELL_FAMILIES.contains(&cba_cell_family(effect.cell.as_str())?) {
            CbaEffectPlane::Data
        } else {
            CbaEffectPlane::Control
        };
        match observed {
            Some(existing) if existing != plane => {
                anyhow::bail!(
                    "event {} mixes data-plane and control-plane effects",
                    event.event_id
                );
            }
            Some(_) => {}
            None => observed = Some(plane),
        }
    }
    observed.ok_or_else(|| anyhow::anyhow!("event {} has no effects", event.event_id))
}

fn cba_cell_family(cell: &str) -> anyhow::Result<&str> {
    arkret_sdk::CellRef::new(cell.to_owned()).map_err(|_| {
        anyhow::anyhow!(
            "effects[].cell must use canonical ak:cell:ak.component.<facet-path>.v<n>:<subject> form"
        )
    })?;
    let rest = cell
        .strip_prefix("ak:cell:")
        .ok_or_else(|| anyhow::anyhow!("validated CellRef is missing the ak:cell: prefix"))?;
    let (family, subject) = rest
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("effects[].cell must include family and subject"))?;
    if family.trim().is_empty() || subject.trim().is_empty() {
        anyhow::bail!("effects[].cell must include non-empty family and subject");
    }
    Ok(family)
}

fn data_event_auth_context(event: &arkret_sdk::Event) -> anyhow::Result<arkret_sdk::AuthContext> {
    let Some(authorization_ref) = event.authorization_ref.as_deref() else {
        anyhow::bail!(
            "DataEvent {} requires authorization_ref so auth_context.capability_refs can be pinned",
            event.event_id
        );
    };
    if !authorization_ref.starts_with("ak:grant:") {
        anyhow::bail!(
            "DataEvent {} authorization_ref must be a ak:grant:* capability ref for auth_context",
            event.event_id
        );
    }
    let did = event
        .executed_by
        .clone()
        .unwrap_or_else(|| event.actor_id.clone());
    let key_id = data_event_key_id_for(event);
    Ok(arkret_sdk::AuthContext {
        did,
        key_id,
        key_epoch: 0,
        credential_epoch: None,
        capability_refs: vec![authorization_ref.to_owned()],
    })
}

fn data_event_key_id_for(event: &arkret_sdk::Event) -> String {
    let controller = event
        .executed_by
        .as_ref()
        .map(|did| did.as_str())
        .unwrap_or_else(|| event.actor_id.as_str());
    let Some(signer) = crate::event_signer::active_signer() else {
        return "device".to_owned();
    };
    if let Some(device_id) = signer.device_id() {
        return device_id.to_owned();
    }
    let method = signer.verification_method();
    let method_without_query = method
        .split_once('?')
        .map(|(head, _)| head)
        .unwrap_or(method);
    let Some((method_controller, fragment)) = method_without_query.split_once('#') else {
        return "device".to_owned();
    };
    if method_controller == controller && !fragment.is_empty() {
        fragment.to_owned()
    } else {
        "device".to_owned()
    }
}

fn event_proof_context_from_description(
    describe: &ServiceDescribe,
) -> crate::event_signer::EventProofContext {
    let service_id = describe.service_id.to_string();
    crate::event_signer::EventProofContext::new()
        .with_domain(service_id.clone())
        .with_audience(crate::operation::EventProofAudience::Single(
            service_id.to_owned(),
        ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn test_authoring_generation() -> crate::identity::authoring_generation::AuthoringGeneration {
        crate::identity::authoring_generation::AuthoringGeneration {
            authority_model:
                crate::identity::authoring_generation::AuthoringAuthorityModel::EnrollmentAuthority,
            authority_principal_id: "did:web:alice.example".to_owned(),
            generation_ref: "1-QmCurrent".to_owned(),
        }
    }

    #[test]
    fn queued_event_rejects_pre_generation_shape() {
        let event = sdk_event_without_proof("did:web:alice.example");
        let error = decode_queued_sdk_event(serde_json::json!({
            "event": event,
            "post_accept": null
        }))
        .unwrap_err();
        assert!(error.to_string().contains("authoring_generation"));
    }

    #[test]
    fn frontier_context_preserves_retryable_transport_error() {
        let error = actor_frontier_refresh_error(
            "did:web:alice.example",
            arkret_sdk::http_client::Error::Http("browser offline".to_owned()).into(),
        );

        assert_eq!(outbound_retry_delay(&error), Some(Duration::from_secs(1)));
        assert!(format!("{error:#}").contains("browser offline"));
    }

    #[test]
    fn wasm_string_only_transport_error_remains_retryable() {
        let error = anyhow::anyhow!(
            "resolve authoring generation: HTTP request failed: error sending request"
        );

        assert_eq!(outbound_retry_delay(&error), Some(Duration::from_secs(1)));
    }

    #[test]
    fn pending_chat_projection_ignores_sent_items() {
        let realm =
            arkret_sdk::RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001".to_owned())
                .unwrap();
        let actor = "did:web:alice.example";
        let mut queue = garth::SendQueue::new();
        let pending = sdk_event_with_kind(
            "ak:event:01904100-0000-7000-8000-000000000001",
            realm.as_str(),
            "ak.message.create",
            actor,
        );
        let mut pending = pending;
        pending.payload = serde_json::from_value(json!({
            "message_id": "ak:message:01904100-0000-7000-8000-000000000001"
        }))
        .unwrap();
        queue
            .enqueue(
                Some(pending.event_id.to_string()),
                realm.clone(),
                garth::SendQueueItemKind::Custom {
                    kind: "ak.message.create".to_owned(),
                },
                serde_json::to_value(QueuedSdkEvent {
                    event: pending,
                    authoring_generation: test_authoring_generation(),
                    post_accept: None,
                })
                .unwrap(),
                Vec::new(),
            )
            .unwrap();

        let sent = sdk_event_with_kind(
            "ak:event:01904100-0000-7000-8000-000000000002",
            realm.as_str(),
            "ak.message.create",
            actor,
        );
        let sent_transaction = sent.event_id.to_string();
        queue
            .enqueue(
                Some(sent_transaction.clone()),
                realm.clone(),
                garth::SendQueueItemKind::Custom {
                    kind: "ak.message.create".to_owned(),
                },
                serde_json::to_value(QueuedSdkEvent {
                    event: sent,
                    authoring_generation: test_authoring_generation(),
                    post_accept: None,
                })
                .unwrap(),
                Vec::new(),
            )
            .unwrap();
        queue
            .mark_sent(
                &sent_transaction,
                arkret_sdk::EventId::new(
                    "ak:event:01904100-0000-7000-8000-000000000099".to_owned(),
                )
                .unwrap(),
            )
            .unwrap();

        assert_eq!(
            pending_chat_message_ids_from_snapshot(&queue.snapshot()),
            std::collections::BTreeSet::from([
                "ak:message:01904100-0000-7000-8000-000000000001".to_owned()
            ])
        );
    }

    fn sdk_event_without_proof(actor_id: &str) -> arkret_sdk::Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:01904100-0000-7000-8000-000000000001",
            "kind": "ak.presence",
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
            "actor_id": actor_id,
            "actor_seq": 1,
            "created_at": "2026-05-19T00:00:00.000Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {
                "actor_id": actor_id,
                "state": "online"
            },
            "proofs": []
        }))
        .unwrap()
    }

    fn sdk_event_with_kind(
        event_id: &str,
        realm_id: &str,
        kind: &str,
        actor_id: &str,
    ) -> arkret_sdk::Event {
        serde_json::from_value(json!({
            "event_id": event_id,
            "kind": kind,
            "realm_id": realm_id,
            "actor_id": actor_id,
            "actor_seq": 1,
            "created_at": "2026-05-19T00:00:00.000Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {},
            "proofs": []
        }))
        .unwrap()
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn mls_post_accept_hook_persists_snapshot_idempotently() {
        use std::sync::{Arc, Mutex};

        use garth::OutboundPostAcceptHook;

        let path = std::env::temp_dir().join(format!(
            "inkson-mls-post-accept-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let store = Arc::new(Mutex::new(crate::state::LocalStateStore::with_path(&path)));
        let read_store = Arc::clone(&store);
        let write_store = Arc::clone(&store);
        let handle = crate::runtime::input::StateStoreHandle::new(
            move |read| read(&read_store.lock().unwrap()),
            move |write| write(&mut write_store.lock().unwrap()),
        );
        let hook = InksonPostAcceptHook {
            state_store: Some(handle),
        };
        let realm_id = "ak:realm:01904100-0000-7000-8000-000000000001";
        let event = sdk_event_with_kind(
            "ak:event:01904100-0000-7000-8000-000000000001",
            realm_id,
            "ak.mls.commit",
            "did:web:alice.example",
        );
        let snapshot = crate::mls::persistence::MlsSnapshotEnvelope {
            realm_id: realm_id.to_owned(),
            group_id: "010203".to_owned(),
            epoch: 7,
            salt_hex: "00".repeat(16),
            ciphertext_hex: "11".repeat(32),
            mac_hex: "22".repeat(12),
            recorded_at: chrono::Utc::now(),
            epoch_started_at: chrono::Utc::now(),
            app_messages_observed: 1,
            aead_version: crate::mls::persistence::AEAD_VERSION_CHACHA20_POLY1305,
        };
        let content = serde_json::to_value(QueuedSdkEvent {
            event,
            authoring_generation: test_authoring_generation(),
            post_accept: Some(PostAcceptAction::MlsSnapshot {
                realm_id: realm_id.to_owned(),
                snapshot,
            }),
        })
        .unwrap();
        let realm = arkret_sdk::RealmId::new(realm_id).unwrap();
        let mut queue = garth::SendQueue::new();
        let item = queue
            .enqueue(
                Some("txn-mls-hook".to_owned()),
                realm,
                garth::SendQueueItemKind::Custom {
                    kind: "ak.mls.commit".to_owned(),
                },
                content,
                Vec::new(),
            )
            .unwrap();
        let event_id =
            arkret_sdk::EventId::new("ak:event:01904100-0000-7000-8000-000000000001").unwrap();

        hook.post_accept(&item, &event_id, false).await.unwrap();
        hook.post_accept(&item, &event_id, true).await.unwrap();
        assert_eq!(
            store
                .lock()
                .unwrap()
                .mls_snapshot_for(realm_id)
                .unwrap()
                .epoch,
            7
        );
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn apply_actor_frontier_stamps_next_sequence_and_predecessor() {
        let mut event = sdk_event_without_proof("did:web:alice.example");
        let frontier = arkret_sdk::ActorFrontierView {
            actor_id: arkret_sdk::Did::new("did:web:alice.example").unwrap(),
            actor_seq: 7,
            event_id: Some(
                arkret_sdk::EventId::new("ak:event:01904100-0000-7000-8000-000000000002").unwrap(),
            ),
        };

        apply_actor_frontier_to_sdk_event(&mut event, &frontier).unwrap();

        assert_eq!(event.actor_seq, 8);
        assert_eq!(
            event.prev_refs,
            frontier.event_id.into_iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn apply_empty_actor_frontier_stamps_genesis_sequence_without_predecessor() {
        let mut event = sdk_event_without_proof("did:web:alice.example");
        let frontier = arkret_sdk::ActorFrontierView {
            actor_id: arkret_sdk::Did::new("did:web:alice.example").unwrap(),
            actor_seq: 0,
            event_id: None,
        };

        apply_actor_frontier_to_sdk_event(&mut event, &frontier).unwrap();

        assert_eq!(event.actor_seq, 1);
        assert!(event.prev_refs.is_empty());
    }

    #[test]
    fn apply_actor_frontier_rejects_wrong_actor() {
        let mut event = sdk_event_without_proof("did:web:alice.example");
        let frontier = arkret_sdk::ActorFrontierView {
            actor_id: arkret_sdk::Did::new("did:web:bob.example").unwrap(),
            actor_seq: 7,
            event_id: Some(
                arkret_sdk::EventId::new("ak:event:01904100-0000-7000-8000-000000000002").unwrap(),
            ),
        };

        let error = apply_actor_frontier_to_sdk_event(&mut event, &frontier)
            .unwrap_err()
            .to_string();

        assert!(error.contains("actor frontier mismatch"));
    }

    #[test]
    fn actor_seq_cas_conflict_classifier_is_narrow() {
        let cas: anyhow::Error = TransportClientError {
            status: StatusCode::CONFLICT,
            error: ErrorEnvelope::new(
                "cas_conflict",
                "actor_seq is older than the accepted actor frontier",
            ),
        }
        .into();
        assert!(crate::api_error::is_actor_seq_cas_conflict_error(&cas));

        let different_conflict: anyhow::Error = TransportClientError {
            status: StatusCode::CONFLICT,
            error: ErrorEnvelope::new("cas_conflict", "expected head mismatch"),
        }
        .into();
        assert!(!crate::api_error::is_actor_seq_cas_conflict_error(
            &different_conflict
        ));
    }

    #[test]
    fn mls_genesis_event_lookup_filters_kind_and_realm() {
        let realm = "ak:realm:01904100-0000-7000-8000-000000000001";
        let other_realm = "ak:realm:01904100-0000-7000-8000-000000000099";
        let expected =
            arkret_sdk::EventId::new("ak:event:01904100-0000-7000-8000-000000000003").unwrap();
        let outcome = arkret_sdk::EventsQueryOutcome {
            events: vec![
                sdk_event_with_kind(
                    "ak:event:01904100-0000-7000-8000-000000000001",
                    realm,
                    "ak.message.create",
                    "did:web:alice.example",
                ),
                sdk_event_with_kind(
                    "ak:event:01904100-0000-7000-8000-000000000002",
                    other_realm,
                    "ak.mls.genesis",
                    "did:web:alice.example",
                ),
                sdk_event_with_kind(
                    expected.as_str(),
                    realm,
                    "ak.mls.genesis",
                    "did:web:alice.example",
                ),
            ],
            snapshot_bootstrap: None,
            next_cursor: None,
            prev_cursor: None,
            has_more: false,
            range_completeness: None,
        };

        assert_eq!(
            mls_genesis_event_id_from_events(&outcome, realm),
            Some(expected)
        );
        assert_eq!(
            mls_genesis_event_id_from_events(
                &outcome,
                "ak:realm:01904100-0000-7000-8000-000000000123"
            ),
            None
        );
    }

    #[test]
    fn event_proof_context_binds_domain_and_audience_to_service_id() {
        let describe = parse_server_description(json!({
            "service_id": "did:web:local.host",
            "trust_domain": "ak:trust_domain:local.host",
            "service_type": "principal_server",
            "protocol_version": "1.0",
            "supported_profiles": [
                "ak.profile.core_event_store.v1",
                "ak.profile.principal_server_events_api.v1"
            ],
            "supported_operations": [
                "ak.self.events.query.describe",
                "ak.self.events.command.submit"
            ],
            "supported_bindings": [{"kind": "http_json", "base_url": "https://local.host"}],
            "supported_features": ["ak.feature.soland.events.describe"],
            "auth_metadata": {"mode": "development"},
            "limits": {},
            "plaintext_visibility": {"data_classes": [], "max_visibility": "none"},
            "implemented_features": ["ak.feature.soland.events.describe"],
            "claimed_profiles": [],
            "verified_profiles": [],
            "experimental_features": [],
            "compat_surfaces": [],
            "development_mode": true
        }))
        .unwrap();

        let context = event_proof_context_from_description(&describe);

        assert_eq!(context.domain.as_deref(), Some("did:web:local.host"));
        assert_eq!(
            context.audience,
            Some(crate::operation::EventProofAudience::Single(
                "did:web:local.host".to_owned()
            ))
        );
    }

    fn sdk_event_with_proof(domain: Option<&str>, audience: Option<&str>) -> arkret_sdk::Event {
        let mut proof = json!({
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": "did:web:alice.example#device-1",
            "event_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "created_at": "2026-05-19T00:00:00.000Z",
            "jws": "header.payload.signature"
        });
        if let Some(domain) = domain {
            proof["domain"] = json!(domain);
        }
        if let Some(audience) = audience {
            proof["audience"] = json!(audience);
        }
        serde_json::from_value(json!({
            "event_id": "ak:event:01904100-0000-7000-8000-000000000001",
            "kind": "ak.presence",
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
            "actor_id": "did:web:alice.example",
            "actor_seq": 1,
            "created_at": "2026-05-19T00:00:00.000Z",
            "hlc": "01970e589d21-0001-a13f9c2e",
            "prev_refs": [],
            "payload": {
                "actor_id": "did:web:alice.example",
                "state": "online"
            },
            "proofs": [proof]
        }))
        .unwrap()
    }

    #[test]
    fn sdk_event_proof_gate_requires_domain_and_audience() {
        let ok = sdk_event_with_proof(Some("did:web:local.host"), Some("did:web:local.host"));
        ensure_sdk_event_proofs_are_domain_bound(&ok).unwrap();

        let missing_domain = sdk_event_with_proof(None, Some("did:web:local.host"));
        assert!(ensure_sdk_event_proofs_are_domain_bound(&missing_domain).is_err());

        let missing_audience = sdk_event_with_proof(Some("did:web:local.host"), None);
        assert!(ensure_sdk_event_proofs_are_domain_bound(&missing_audience).is_err());
    }
}
