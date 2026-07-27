//! Ephemeral hosted-view state for an Agent Sidecar.
//!
//! This state deliberately stays in memory. It carries UI context from the
//! ensure action into the source Strand shell without inventing a wire type or
//! persisting message plaintext outside the existing composer lifecycle.

use dioxus::prelude::*;

const SIDECAR_VIEW_STATE_CACHE_PREFIX: &str = "sidecar.view_state.v1";

#[derive(Clone, Debug, PartialEq)]
pub struct HostedSidecarState {
    pub trace_id: String,
    pub controller_id: String,
    pub addressed_agent_ids: Vec<String>,
    pub addressed_agent_label: String,
    pub source_realm_id: String,
    pub source_strand_id: String,
    pub sidecar_id: arkret_sdk::SidecarId,
    /// Internal effective-scope binding used by the encrypted write path. It
    /// is never rendered, routed to, or used as Sidecar identity.
    pub backing_scope_circle_id: arkret_sdk::CircleId,
    pub private_strand_id: String,
    pub private_relation_id: String,
    pub access_readiness: arkret_sdk::AgentSidecarAccessReadiness,
    pub pending_access_reconciliations: Vec<arkret_sdk::PendingSidecarAccessReconciliationItem>,
    pub mls_context: arkret_sdk::AgentSidecarMlsContext,
    pub display_mode: arkret_sdk::AgentSidecarDisplayMode,
    pub migrated_draft: String,
    pub opened_at: chrono::DateTime<chrono::Utc>,
}

impl HostedSidecarState {
    pub fn matches_route(&self, realm_id: &str, strand_id: &str) -> bool {
        self.source_realm_id == realm_id && self.source_strand_id == strand_id
    }

    pub fn membership_ready(&self) -> bool {
        self.access_readiness == arkret_sdk::AgentSidecarAccessReadiness::Ready
            && self.pending_access_reconciliations.is_empty()
            && self.mls_context.current_controller_device_ready
    }

    pub fn mls_binding(&self) -> arkret_sdk::Result<arkret_sdk::SidecarMlsBinding> {
        let binding = arkret_sdk::SidecarMlsBinding {
            sidecar_id: self.sidecar_id.clone(),
            desired_access_digest: self.mls_context.desired_access_digest.clone(),
            control_frontier: self.mls_context.control_frontier.clone(),
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn pending_reconciliation_count(&self) -> usize {
        self.pending_access_reconciliations.len()
    }

    pub fn diagnostic_summary(
        &self,
        encryption_state: &str,
        message_submit_state: &str,
        notification_fanout_state: &str,
        agent_receipt_state: &str,
        last_updated: &str,
    ) -> String {
        format!(
            "Trace ID: {}\nEnsure: complete\nPrivate access: {}\nEncryption: {}\nMessage submit: {}\nNotification fanout: {}\nAgent receipt: {}\nLast updated: {}",
            self.trace_id,
            if self.membership_ready() {
                "complete".to_owned()
            } else {
                format!(
                    "reconciling ({} pending)",
                    self.pending_reconciliation_count()
                )
            },
            encryption_state,
            message_submit_state,
            notification_fanout_state,
            agent_receipt_state,
            last_updated,
        )
    }
}

fn sidecar_view_state_cache_key(controller_id: &str, realm_id: &str, strand_id: &str) -> String {
    format!("{SIDECAR_VIEW_STATE_CACHE_PREFIX}:{controller_id}:{realm_id}:{strand_id}")
}

fn cache_sidecar_view_state(
    store: &mut crate::state::LocalStateStore,
    account_did: &str,
    view_state: &arkret_sdk::AgentSidecarViewState,
) -> anyhow::Result<bool> {
    let key = sidecar_view_state_cache_key(
        view_state.controller_id.as_str(),
        view_state.context_ref.realm_id.as_str(),
        view_state.context_ref.strand_id.as_str(),
    );
    let should_replace = store
        .load_private_data(account_did, &key)
        .and_then(|raw| serde_json::from_str::<arkret_sdk::AgentSidecarViewState>(&raw).ok())
        .is_none_or(|current| {
            (
                view_state.updated_hlc.to_string(),
                view_state.origin_device_id.to_string(),
            ) > (
                current.updated_hlc.to_string(),
                current.origin_device_id.to_string(),
            )
        });
    if should_replace {
        store.save_private_data(account_did, key, serde_json::to_string(view_state)?);
    }
    Ok(should_replace)
}

pub fn ingest_sidecar_view_state_account_data(
    store: &mut crate::state::LocalStateStore,
    account_did: &str,
    account_data_key: &str,
    entry: &impl serde::Serialize,
) -> anyhow::Result<bool> {
    if !account_data_key.starts_with("ak.agent.sidecar_view_state.v1:") {
        return Ok(false);
    }
    let view_state: arkret_sdk::AgentSidecarViewState = serde_json::from_value(
        crate::account_data::decrypt_account_data_entry(account_did, account_data_key, entry)?,
    )?;
    view_state.validate_account_data_key(account_data_key)?;
    if view_state.controller_id.as_str() != account_did {
        anyhow::bail!("Sidecar view-state controller does not match the account holder");
    }
    cache_sidecar_view_state(store, account_did, &view_state)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Event-truth exchange model (`zh/models/sidecar.md` §7.2).
//
// The exchange projection is a disposable controller-device-LOCAL fold cache:
// it is never uploaded, never Account Data, never merged across devices via
// the account stream, and can always be rebuilt from the accepted Sidecar
// private-Strand Events. There is no LWW/updated_hlc arbitration — a refold
// replaces the cached value wholesale.
// ---------------------------------------------------------------------------

/// Client-local fold-cache key prefix (deliberately NOT an `ak.*` account-data
/// type name).
const SIDECAR_EXCHANGE_FOLD_CACHE_PREFIX: &str = "sidecar_exchange_fold";
/// Client-local pre-submission intent records (`zh/models/sidecar.md` §7.2.4:
/// a rejected request has no durable exchange; retries of the same intent
/// MUST reuse the same `exchange_id`).
const SIDECAR_PENDING_SUBMISSION_PREFIX: &str = "ak.local.sidecar_pending_submission.v1";
/// Durable local record of this device's own accepted `role=request` Events.
/// MLS forward secrecy prevents the authoring device from decrypting its own
/// `encrypted_metadata`, so the request fact must survive locally for later
/// refolds; other controller devices recover it by decrypting the Event.
const SIDECAR_EXCHANGE_REQUEST_FACT_PREFIX: &str = "sidecar_exchange_request_fact";

fn sidecar_exchange_fold_cache_key(
    controller_id: &str,
    private_strand_id: &str,
    exchange_id: &str,
) -> String {
    format!(
        "{SIDECAR_EXCHANGE_FOLD_CACHE_PREFIX}:{controller_id}:{private_strand_id}:{exchange_id}"
    )
}

/// Replace the local fold cache entry for one exchange. The fold output is
/// authoritative for the cache: no LWW, no `updated_hlc` arbitration. Writes
/// are skipped when the cached value is already identical so reactive callers
/// do not loop on their own writes. Returns whether the cache changed.
pub(crate) fn cache_sidecar_exchange_projection(
    store: &mut crate::state::LocalStateStore,
    account_did: &str,
    projection: &arkret_sdk::AgentSidecarExchangeProjection,
) -> anyhow::Result<bool> {
    projection.validate()?;
    if projection.controller_id.as_str() != account_did {
        anyhow::bail!("Sidecar exchange controller does not match the account holder");
    }
    let key = sidecar_exchange_fold_cache_key(
        projection.controller_id.as_str(),
        projection.private_strand_id.as_str(),
        projection.exchange_id.as_str(),
    );
    let current = store.load_private_data(account_did, &key).and_then(|raw| {
        serde_json::from_str::<arkret_sdk::AgentSidecarExchangeProjection>(&raw).ok()
    });
    if current.as_ref() == Some(projection) {
        return Ok(false);
    }
    store.save_private_data(account_did, key, serde_json::to_string(projection)?);
    Ok(true)
}

pub fn cached_sidecar_exchange_projections(
    store: &crate::state::LocalStateStore,
    account_did: &str,
    source_realm_id: &str,
) -> Vec<arkret_sdk::AgentSidecarExchangeProjection> {
    let prefix = format!("{SIDECAR_EXCHANGE_FOLD_CACHE_PREFIX}:{account_did}:");
    let mut projections = store
        .private_data_keys()
        .into_iter()
        .filter(|key| key.starts_with(&prefix))
        .filter_map(|key| store.load_private_data(account_did, &key))
        .filter_map(|raw| {
            serde_json::from_str::<arkret_sdk::AgentSidecarExchangeProjection>(&raw).ok()
        })
        .filter(|projection| {
            projection.validate().is_ok()
                && projection.controller_id.as_str() == account_did
                && projection.source_track_ref.realm_id.as_str() == source_realm_id
        })
        .collect::<Vec<_>>();
    projections.sort_by(|left, right| {
        (
            left.source_hlc.to_string(),
            left.exchange_id.as_str().to_owned(),
        )
            .cmp(&(
                right.source_hlc.to_string(),
                right.exchange_id.as_str().to_owned(),
            ))
    });
    projections
}

/// Client-local pre-submission state for one source-routed request intent.
/// Never a wire object: a rejected/failed submit keeps this record (so the
/// retry reuses the same `exchange_id`) and produces no durable exchange
/// state; server acceptance deletes it and seeds the local fold cache.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct PendingSidecarSubmission {
    pub controller_id: String,
    pub sidecar_id: arkret_sdk::SidecarId,
    pub private_strand_id: String,
    /// Backing Circle of this Sidecar context: the ONLY effective scope under
    /// which exchange Events of this private Strand are valid (§7.2.1).
    pub backing_circle_id: arkret_sdk::CircleId,
    pub exchange_id: arkret_sdk::AgentSidecarExchangeId,
    pub request_context: arkret_sdk::AgentSidecarExchangeRequestContext,
    /// Message id of the latest submit attempt (used to recognise the
    /// accepted request Event in the synced timeline after a crash).
    pub message_id: String,
    pub local_operation_id: String,
}

/// In-flight submission registry (F-7): one live submit per
/// `(controller, private Strand, intent)` so a double-click cannot author two
/// request Events under the same `exchange_id` (controller equivocation).
/// Process-local on purpose — a crash releases it, and the durable pending
/// record still guarantees exchange-id reuse on the next attempt.
static SIDECAR_SUBMISSIONS_IN_FLIGHT: std::sync::OnceLock<
    std::sync::Mutex<std::collections::BTreeSet<String>>,
> = std::sync::OnceLock::new();

fn sidecar_submissions_in_flight() -> &'static std::sync::Mutex<std::collections::BTreeSet<String>>
{
    SIDECAR_SUBMISSIONS_IN_FLIGHT.get_or_init(|| std::sync::Mutex::new(Default::default()))
}

/// RAII in-flight marker returned by [`try_begin_sidecar_submission`].
pub(crate) struct SidecarSubmissionGuard {
    key: String,
}

impl Drop for SidecarSubmissionGuard {
    fn drop(&mut self) {
        if let Ok(mut in_flight) = sidecar_submissions_in_flight().lock() {
            in_flight.remove(&self.key);
        }
    }
}

/// Reserve the submission slot for one intent. Returns `None` while an
/// earlier submit of the SAME intent is still in flight.
pub(crate) fn try_begin_sidecar_submission(
    controller_id: &str,
    private_strand_id: &str,
    intent_digest: &str,
) -> Option<SidecarSubmissionGuard> {
    let key = format!("{controller_id}\u{1f}{private_strand_id}\u{1f}{intent_digest}");
    let mut in_flight = sidecar_submissions_in_flight().lock().ok()?;
    in_flight
        .insert(key.clone())
        .then(|| SidecarSubmissionGuard { key })
}

/// Deterministic identity of one composer intent. Retrying the same body to
/// the same source Strand with the same addressed set reuses the stored
/// pending record — and therefore the same `exchange_id`.
pub(crate) fn sidecar_submission_intent_digest(
    source_strand_id: &str,
    body: &str,
    addressed_agent_ids: &[String],
) -> String {
    let mut transcript = String::new();
    transcript.push_str(source_strand_id);
    transcript.push('\u{1f}');
    transcript.push_str(body);
    for agent_id in addressed_agent_ids {
        transcript.push('\u{1f}');
        transcript.push_str(agent_id);
    }
    crate::canonical::sha256_hex(transcript.as_bytes())
}

fn pending_sidecar_submission_key(
    controller_id: &str,
    private_strand_id: &str,
    intent_digest: &str,
) -> String {
    format!(
        "{SIDECAR_PENDING_SUBMISSION_PREFIX}:{controller_id}:{private_strand_id}:{intent_digest}"
    )
}

pub(crate) fn load_pending_sidecar_submission(
    store: &crate::state::LocalStateStore,
    controller_id: &str,
    private_strand_id: &str,
    intent_digest: &str,
) -> Option<PendingSidecarSubmission> {
    let key = pending_sidecar_submission_key(controller_id, private_strand_id, intent_digest);
    let raw = store.load_private_data(controller_id, &key)?;
    serde_json::from_str::<PendingSidecarSubmission>(&raw)
        .ok()
        .filter(|pending| pending.controller_id == controller_id)
}

pub(crate) fn save_pending_sidecar_submission(
    store: &mut crate::state::LocalStateStore,
    intent_digest: &str,
    pending: &PendingSidecarSubmission,
) -> anyhow::Result<()> {
    let key = pending_sidecar_submission_key(
        &pending.controller_id,
        &pending.private_strand_id,
        intent_digest,
    );
    store.save_private_data(&pending.controller_id, key, serde_json::to_string(pending)?);
    Ok(())
}

pub(crate) fn remove_pending_sidecar_submission(
    store: &mut crate::state::LocalStateStore,
    controller_id: &str,
    private_strand_id: &str,
    intent_digest: &str,
) {
    let key = pending_sidecar_submission_key(controller_id, private_strand_id, intent_digest);
    store.remove_private_data(&key);
}

/// Every stored pending submission of this controller, with its storage key.
pub(crate) fn pending_sidecar_submissions(
    store: &crate::state::LocalStateStore,
    controller_id: &str,
) -> Vec<(String, PendingSidecarSubmission)> {
    let prefix = format!("{SIDECAR_PENDING_SUBMISSION_PREFIX}:{controller_id}:");
    store
        .private_data_keys()
        .into_iter()
        .filter(|key| key.starts_with(&prefix))
        .filter_map(|key| {
            let raw = store.load_private_data(controller_id, &key)?;
            let pending = serde_json::from_str::<PendingSidecarSubmission>(&raw).ok()?;
            (pending.controller_id == controller_id).then_some((key, pending))
        })
        .collect()
}

/// Durable local record of an accepted controller `role=request` Event.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct StoredSidecarExchangeRequestFact {
    pub controller_id: String,
    pub sidecar_id: arkret_sdk::SidecarId,
    pub private_strand_id: String,
    pub exchange_id: arkret_sdk::AgentSidecarExchangeId,
    pub request_event_id: String,
    /// Fold-fact HLC. The authoring device cannot read the accepted Event's
    /// server-stamped top-level HLC synchronously, so the request context's
    /// `source_hlc` stands in; it only feeds `max_hlc` display metadata.
    pub request_event_hlc: arkret_sdk::Hlc,
    /// Accepted controller actor-chain sequence. `0` when the authoring
    /// device could not observe the accepted value; it only participates in
    /// canonical-request selection under controller equivocation. The refold
    /// upgrades it from the accepted Event envelope once that syncs back.
    pub request_event_actor_seq: u64,
    /// Backing Circle the request Event was authored under (§7.2.1 scope).
    pub backing_circle_id: arkret_sdk::CircleId,
    pub request_context: arkret_sdk::AgentSidecarExchangeRequestContext,
}

/// Fold-scope identity of one Sidecar private Strand: which Sidecar it
/// belongs to AND which backing Circle its exchange Events must be scoped to.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SidecarExchangeScopeHint {
    pub private_strand_id: String,
    pub sidecar_id: arkret_sdk::SidecarId,
    pub backing_circle_id: arkret_sdk::CircleId,
}

fn sidecar_exchange_request_fact_key(
    controller_id: &str,
    private_strand_id: &str,
    exchange_id: &str,
) -> String {
    format!(
        "{SIDECAR_EXCHANGE_REQUEST_FACT_PREFIX}:{controller_id}:{private_strand_id}:{exchange_id}"
    )
}

fn save_stored_sidecar_exchange_request_fact(
    store: &mut crate::state::LocalStateStore,
    stored: &StoredSidecarExchangeRequestFact,
) -> anyhow::Result<()> {
    let key = sidecar_exchange_request_fact_key(
        &stored.controller_id,
        &stored.private_strand_id,
        stored.exchange_id.as_str(),
    );
    store.save_private_data(&stored.controller_id, key, serde_json::to_string(stored)?);
    Ok(())
}

fn stored_sidecar_exchange_request_facts(
    store: &crate::state::LocalStateStore,
    controller_id: &str,
) -> Vec<StoredSidecarExchangeRequestFact> {
    let prefix = format!("{SIDECAR_EXCHANGE_REQUEST_FACT_PREFIX}:{controller_id}:");
    store
        .private_data_keys()
        .into_iter()
        .filter(|key| key.starts_with(&prefix))
        .filter_map(|key| store.load_private_data(controller_id, &key))
        .filter_map(|raw| serde_json::from_str::<StoredSidecarExchangeRequestFact>(&raw).ok())
        .filter(|fact| fact.controller_id == controller_id)
        .collect()
}

fn request_fact_from_stored(
    stored: &StoredSidecarExchangeRequestFact,
) -> Option<garth::projection::SidecarExchangeRequestFact> {
    Some(garth::projection::SidecarExchangeRequestFact {
        event_id: arkret_sdk::EventId::new(stored.request_event_id.clone()).ok()?,
        hlc: stored.request_event_hlc.clone(),
        actor_id: arkret_sdk::Did::new(stored.controller_id.clone()).ok()?,
        actor_seq: stored.request_event_actor_seq,
        // The canonical Event digest is not tracked client-side; the accepted
        // Event id is a deterministic stand-in used ONLY for same-sequence
        // sibling tie-breaking under controller equivocation.
        event_digest: stored.request_event_id.clone(),
        exchange_id: stored.exchange_id.clone(),
        context: stored.request_context.clone(),
    })
}

/// Record a server-accepted request Event: persist the durable local request
/// fact and seed the fold cache with the folded (`delivered`) projection.
pub(crate) fn record_accepted_sidecar_exchange_request(
    store: &mut crate::state::LocalStateStore,
    pending: &PendingSidecarSubmission,
    accepted_event_id: &str,
) -> anyhow::Result<()> {
    let stored = StoredSidecarExchangeRequestFact {
        controller_id: pending.controller_id.clone(),
        sidecar_id: pending.sidecar_id.clone(),
        private_strand_id: pending.private_strand_id.clone(),
        exchange_id: pending.exchange_id.clone(),
        request_event_id: accepted_event_id.to_owned(),
        request_event_hlc: pending.request_context.source_hlc.clone(),
        request_event_actor_seq: 0,
        backing_circle_id: pending.backing_circle_id.clone(),
        request_context: pending.request_context.clone(),
    };
    save_stored_sidecar_exchange_request_fact(store, &stored)?;
    let scope = garth::projection::SidecarExchangeFoldScope {
        controller_id: arkret_sdk::Did::new(stored.controller_id.clone())?,
        sidecar_id: stored.sidecar_id.clone(),
        private_strand_id: arkret_sdk::StrandId::new(stored.private_strand_id.clone())?,
    };
    let fact = request_fact_from_stored(&stored)
        .ok_or_else(|| anyhow::anyhow!("accepted Sidecar request fact has invalid identifiers"))?;
    let projection =
        garth::projection::fold_sidecar_exchange(&scope, &stored.exchange_id, &[fact], &[], &[])?
            .ok_or_else(|| anyhow::anyhow!("accepted Sidecar request did not fold"))?;
    cache_sidecar_exchange_projection(store, &stored.controller_id, &projection)?;
    Ok(())
}

fn decrypt_sidecar_scoped_envelope(
    store: &crate::state::LocalStateStore,
    realm_id: &str,
    controller_id: &str,
    device_id: &str,
    circle_id: &str,
    envelope_value: &serde_json::Value,
) -> Option<Vec<u8>> {
    let envelope =
        serde_json::from_value::<arkret_sdk::EncryptedEnvelope>(envelope_value.clone()).ok()?;
    let payload_value =
        serde_json::to_value(arkret_sdk::mls::encrypted_envelope_to_payload(&envelope).ok()?)
            .ok()?;
    crate::state::projection::try_local_mls_decrypt_core_for_effective_scope(
        store,
        realm_id,
        controller_id,
        device_id,
        &payload_value,
        Some(circle_id),
    )
}

fn sidecar_history_events_for_realm(
    state: &crate::state::ClientLocalState,
    realm_id: &str,
) -> Vec<arkret_sdk::Event> {
    let mut by_event_id = std::collections::BTreeMap::<String, arkret_sdk::Event>::new();
    let mut ingest = |value: &serde_json::Value| {
        let Ok(event) = serde_json::from_value::<arkret_sdk::Event>(value.clone()) else {
            return;
        };
        if event.realm_id.as_str() != realm_id {
            return;
        }
        by_event_id.insert(event.event_id.to_string(), event);
    };
    for record in &state.raw_operations {
        if record
            .realm_id
            .as_deref()
            .is_none_or(|record_realm| record_realm == realm_id)
        {
            ingest(&record.payload);
        }
    }
    if let Some(events) = state
        .realm_tree_projections
        .get(realm_id)
        .and_then(|body| body.get("timeline"))
        .and_then(|projection| projection.get("events"))
        .and_then(serde_json::Value::as_array)
    {
        for event in events {
            ingest(event);
        }
    }
    by_event_id.into_values().collect()
}

fn event_refs_after(event: &arkret_sdk::Event) -> Vec<arkret_sdk::EventId> {
    event
        .refs
        .iter()
        .filter(|reference| reference.role == "after")
        .filter_map(|reference| arkret_sdk::EventId::new(reference.id.clone()).ok())
        .collect()
}

/// Refold every locally known exchange of `controller_id` in `realm_id` from
/// Event truth and refresh the local fold cache. Returns the number of cache
/// entries that changed.
///
/// Inputs per §7.2.4: durable local request facts (this device's own accepted
/// requests), plus request/response/internal bindings decrypted from
/// `encrypted_metadata` of Sidecar private-Strand `ak.message.create` Events,
/// plus decrypted `ak.agent.sidecar.exchange.control` Events. Any Event that
/// fails scope resolution, decryption, or closed-schema validation is
/// silently non-echo (fail closed).
///
/// `extra_scope_hints` names private Strands not yet present in any local
/// record (e.g. the active hosted session); without a Sidecar id AND its
/// backing Circle id an exchange cannot be folded.
pub(crate) fn refold_sidecar_exchanges_from_history(
    store: &mut crate::state::LocalStateStore,
    controller_id: &str,
    device_id: &str,
    realm_id: &str,
    extra_scope_hints: &[SidecarExchangeScopeHint],
) -> usize {
    let realm = realm_id.to_owned();
    let controller = controller_id.to_owned();
    let device = device_id.to_owned();
    refold_sidecar_exchanges_with_decrypt(
        store,
        controller_id,
        realm_id,
        extra_scope_hints,
        &move |store_ref, circle_id, envelope_value| {
            decrypt_sidecar_scoped_envelope(
                store_ref,
                &realm,
                &controller,
                &device,
                circle_id,
                envelope_value,
            )
        },
    )
}

/// Circle-scoped envelope decrypt hook: `(store, circle_id, envelope_value)`
/// → plaintext bytes (`None` fails closed to non-echo).
type SidecarEnvelopeDecrypt<'a> =
    &'a dyn Fn(&crate::state::LocalStateStore, &str, &serde_json::Value) -> Option<Vec<u8>>;

/// Decrypt-injectable core of [`refold_sidecar_exchanges_from_history`]
/// (tests substitute the MLS decrypt with a passthrough).
fn refold_sidecar_exchanges_with_decrypt(
    store: &mut crate::state::LocalStateStore,
    controller_id: &str,
    realm_id: &str,
    extra_scope_hints: &[SidecarExchangeScopeHint],
    decrypt: SidecarEnvelopeDecrypt<'_>,
) -> usize {
    let mut folded = Vec::new();
    let mut fact_upgrades = Vec::<StoredSidecarExchangeRequestFact>::new();
    {
        let store_ref: &crate::state::LocalStateStore = store;
        let state = store_ref.load();
        let mut stored_facts = stored_sidecar_exchange_request_facts(store_ref, controller_id);
        // private Strand id → (Sidecar id, backing Circle id). BOTH halves are
        // required: the Sidecar id names the fold scope, the backing Circle id
        // is the ONLY effective scope under which this context's exchange
        // Events are valid (§7.2.1 / §7.2.2 check 1). Cached projections are
        // deliberately NOT a hint source — the projection DTO does not carry
        // the backing Circle, so it cannot authorize the scope comparison.
        let mut scope_hints = std::collections::BTreeMap::<
            String,
            (arkret_sdk::SidecarId, arkret_sdk::CircleId),
        >::new();
        for hint in extra_scope_hints {
            scope_hints.insert(
                hint.private_strand_id.clone(),
                (hint.sidecar_id.clone(), hint.backing_circle_id.clone()),
            );
        }
        for fact in &stored_facts {
            scope_hints.insert(
                fact.private_strand_id.clone(),
                (fact.sidecar_id.clone(), fact.backing_circle_id.clone()),
            );
        }
        for (_, pending) in pending_sidecar_submissions(store_ref, controller_id) {
            scope_hints.insert(
                pending.private_strand_id.clone(),
                (
                    pending.sidecar_id.clone(),
                    pending.backing_circle_id.clone(),
                ),
            );
        }
        // No known Sidecar private Strand for this controller: nothing can
        // fold, so skip the (event-scan) work entirely.
        if scope_hints.is_empty() {
            return 0;
        }
        let stored_index_by_request_event_id = stored_facts
            .iter()
            .enumerate()
            .map(|(index, fact)| (fact.request_event_id.clone(), index))
            .collect::<std::collections::BTreeMap<_, _>>();

        type ExchangeKey = (String, String);
        let mut requests = std::collections::BTreeMap::<
            ExchangeKey,
            Vec<garth::projection::SidecarExchangeRequestFact>,
        >::new();
        let mut agent_facts = std::collections::BTreeMap::<
            ExchangeKey,
            Vec<garth::projection::SidecarExchangeAgentFact>,
        >::new();
        let mut controls = std::collections::BTreeMap::<
            ExchangeKey,
            Vec<garth::projection::SidecarExchangeControlFact>,
        >::new();
        let mut request_event_ids = std::collections::BTreeSet::<String>::new();
        let mut upgraded_exchange_keys = std::collections::BTreeSet::<ExchangeKey>::new();

        for event in sidecar_history_events_for_realm(&state, realm_id) {
            // §7.2.1 / §7.2.2 check 1: exchange bindings are valid ONLY under
            // THIS context's backing Circle scope. Any other Circle the
            // controller can decrypt (with a forged payload strand_id) MUST
            // fail closed to non-echo, so the event's effective-scope Circle
            // is compared against the hint's backing Circle, never just
            // "some Circle scope".
            let Some(arkret_wire::EffectiveScope::Circle { circle_id, .. }) =
                event.effective_scope.as_ref()
            else {
                continue;
            };
            let kind = event.kind.as_str();
            let Some(strand_id) = event
                .payload
                .get("strand_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
            else {
                continue;
            };
            let Some((_, backing_circle_id)) = scope_hints.get(&strand_id) else {
                continue;
            };
            if circle_id.as_str() != backing_circle_id.as_str() {
                continue;
            }
            if kind == arkret_sdk::events::EventKind::MESSAGE_CREATE {
                // F-3: the accepted request Event's envelope carries the real
                // `actor_seq` / top-level `hlc` in the clear. The authoring
                // device cannot decrypt its own metadata, so when the
                // envelope syncs back, upgrade the placeholder values in the
                // durable local request fact (the Event-id `event_digest`
                // stand-in stays — the canonical digest is still untracked).
                if event.actor_id.as_str() == controller_id
                    && let Some(index) = stored_index_by_request_event_id
                        .get(event.event_id.as_str())
                        .copied()
                    && let Some(envelope_hlc) = event.hlc.clone()
                {
                    let stored = &mut stored_facts[index];
                    if stored.request_event_actor_seq != event.actor_seq
                        || stored.request_event_hlc != envelope_hlc
                    {
                        stored.request_event_actor_seq = event.actor_seq;
                        stored.request_event_hlc = envelope_hlc;
                        fact_upgrades.push(stored.clone());
                        upgraded_exchange_keys.insert((
                            stored.private_strand_id.clone(),
                            stored.exchange_id.as_str().to_owned(),
                        ));
                    }
                }
                let Some(encrypted_metadata) = event.payload.get("encrypted_metadata") else {
                    continue;
                };
                let Some(plaintext) = decrypt(store_ref, circle_id.as_str(), encrypted_metadata)
                else {
                    continue;
                };
                let Some(metadata) =
                    serde_json::from_slice::<arkret_sdk::MessageMetadata>(&plaintext).ok()
                else {
                    continue;
                };
                // Fail-closed accessor: schema mismatch / unknown role /
                // field-validation failure all yield None (non-echo).
                let Some(binding) = metadata.sidecar_exchange_binding() else {
                    continue;
                };
                // §7.2 all exchange Events MUST carry a top-level HLC; fail
                // closed when absent (request, response and internal alike).
                let Some(hlc) = event.hlc.clone() else {
                    continue;
                };
                let exchange_key = (strand_id.clone(), binding.exchange_id.as_str().to_owned());
                match binding.role {
                    arkret_sdk::AgentSidecarExchangeBindingRole::Request => {
                        if event.actor_id.as_str() != controller_id {
                            continue;
                        }
                        let Some(context) = binding.request_context.clone() else {
                            continue;
                        };
                        request_event_ids.insert(event.event_id.to_string());
                        requests.entry(exchange_key).or_default().push(
                            garth::projection::SidecarExchangeRequestFact {
                                event_id: event.event_id.clone(),
                                hlc,
                                actor_id: event.actor_id.clone(),
                                actor_seq: event.actor_seq,
                                // Deterministic stand-in for the canonical
                                // Event digest; used only for same-sequence
                                // sibling tie-breaking.
                                event_digest: event.event_id.to_string(),
                                exchange_id: binding.exchange_id.clone(),
                                context,
                            },
                        );
                    }
                    arkret_sdk::AgentSidecarExchangeBindingRole::UserFacingResponse
                    | arkret_sdk::AgentSidecarExchangeBindingRole::Internal => {
                        agent_facts.entry(exchange_key).or_default().push(
                            garth::projection::SidecarExchangeAgentFact {
                                event_id: event.event_id.clone(),
                                hlc,
                                actor_id: event.actor_id.clone(),
                                binding,
                                refs_after: event_refs_after(&event),
                            },
                        );
                    }
                }
            } else if kind == arkret_sdk::events::EventKind::AGENT_SIDECAR_EXCHANGE_CONTROL {
                let Some(encrypted_payload) = event.payload.get("encrypted_payload") else {
                    continue;
                };
                let Some(plaintext) = decrypt(store_ref, circle_id.as_str(), encrypted_payload)
                else {
                    continue;
                };
                let Some(control) =
                    serde_json::from_slice::<arkret_sdk::AgentSidecarExchangeControl>(&plaintext)
                        .ok()
                        .filter(|control| control.validate().is_ok())
                else {
                    continue;
                };
                let Some(hlc) = event.hlc.clone() else {
                    continue;
                };
                let exchange_key = (strand_id, control.exchange_id.as_str().to_owned());
                controls.entry(exchange_key).or_default().push(
                    garth::projection::SidecarExchangeControlFact {
                        event_id: event.event_id.clone(),
                        hlc,
                        actor_id: event.actor_id.clone(),
                        actor_seq: event.actor_seq,
                        event_digest: event.event_id.to_string(),
                        // §7.2.3: the outer refs MUST cover the plaintext
                        // basis; the fold validates this coverage.
                        refs_after: event_refs_after(&event),
                        control,
                    },
                );
            }
        }

        // Merge this device's durable request facts for exchanges whose
        // accepted request Event was not (or cannot be) decrypted locally.
        for stored in &stored_facts {
            if request_event_ids.contains(&stored.request_event_id) {
                continue;
            }
            let Some(fact) = request_fact_from_stored(stored) else {
                continue;
            };
            if stored.request_context.source_track_ref.realm_id.as_str() != realm_id {
                continue;
            }
            requests
                .entry((
                    stored.private_strand_id.clone(),
                    stored.exchange_id.as_str().to_owned(),
                ))
                .or_default()
                .push(fact);
        }

        let mut exchange_keys = std::collections::BTreeSet::new();
        exchange_keys.extend(requests.keys().cloned());
        exchange_keys.extend(agent_facts.keys().cloned());
        exchange_keys.extend(controls.keys().cloned());
        let empty_requests = Vec::new();
        let empty_agent_facts = Vec::new();
        let empty_controls = Vec::new();
        for exchange_key in exchange_keys {
            let (strand_id, exchange_id_raw) = &exchange_key;
            let Some((sidecar_id, _)) = scope_hints.get(strand_id) else {
                continue;
            };
            let (Ok(controller_did), Ok(private_strand_id), Ok(exchange_id)) = (
                arkret_sdk::Did::new(controller_id.to_owned()),
                arkret_sdk::StrandId::new(strand_id.clone()),
                arkret_sdk::AgentSidecarExchangeId::new(exchange_id_raw.clone()),
            ) else {
                continue;
            };
            let exchange_requests = requests.get(&exchange_key).unwrap_or(&empty_requests);
            let exchange_agent_facts = agent_facts.get(&exchange_key).unwrap_or(&empty_agent_facts);
            let exchange_controls = controls.get(&exchange_key).unwrap_or(&empty_controls);
            // Controller-local equivocation diagnostic (§7.2.1): several
            // distinct accepted request Events sharing one exchange_id. The
            // deterministic canonical-request selection still applies; this
            // only surfaces the anomaly.
            let distinct_request_events = exchange_requests
                .iter()
                .map(|fact| fact.event_id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            if distinct_request_events.len() > 1 {
                tracing::warn!(
                    exchange_id = %exchange_id_raw,
                    request_event_count = distinct_request_events.len(),
                    "controller-local diagnostic: multiple accepted request Events share one Sidecar exchange_id (equivocation); canonical selection applies"
                );
            }
            // F-5 cache gate (§7.2.4): compare the persisted frontier against
            // the locally verified fact set before refolding.
            let cache_key =
                sidecar_exchange_fold_cache_key(controller_id, strand_id, exchange_id_raw);
            let cached_projection = store_ref
                .load_private_data(controller_id, &cache_key)
                .and_then(|raw| {
                    serde_json::from_str::<arkret_sdk::AgentSidecarExchangeProjection>(&raw).ok()
                });
            if let Some(cached) = cached_projection.as_ref()
                && !upgraded_exchange_keys.contains(&exchange_key)
            {
                let local_ids = exchange_requests
                    .iter()
                    .map(|fact| fact.event_id.clone())
                    .chain(
                        exchange_agent_facts
                            .iter()
                            .map(|fact| fact.event_id.clone()),
                    )
                    .chain(exchange_controls.iter().map(|fact| fact.event_id.clone()))
                    .collect::<std::collections::BTreeSet<_>>();
                match garth::projection::evaluate_sidecar_exchange_cache(
                    &cached.folded_frontier,
                    &local_ids,
                ) {
                    // The cache commits to exactly the local fact set: reuse
                    // it as-is, no refold needed.
                    Ok(garth::projection::SidecarExchangeCacheDecision::Fresh) => continue,
                    Ok(garth::projection::SidecarExchangeCacheDecision::Refold) => {}
                    Ok(garth::projection::SidecarExchangeCacheDecision::BackfillRequired) => {
                        // The cache references Events this device has not
                        // verified locally: incomparable frontiers. Keep the
                        // cache (never refold-over or LWW-pick) and mark the
                        // exchange as pending backfill; the actual union-
                        // history fetch is deferred to the sync engine.
                        tracing::debug!(
                            exchange_id = %exchange_id_raw,
                            "Sidecar exchange cache retained: frontier not covered by local history (backfill pending)"
                        );
                        continue;
                    }
                    // An unreadable/invalid cached frontier never blocks the
                    // deterministic refold from local facts.
                    Err(_) => {}
                }
            }
            let scope = garth::projection::SidecarExchangeFoldScope {
                controller_id: controller_did,
                sidecar_id: sidecar_id.clone(),
                private_strand_id,
            };
            let fold = garth::projection::fold_sidecar_exchange(
                &scope,
                &exchange_id,
                exchange_requests,
                exchange_agent_facts,
                exchange_controls,
            );
            match fold {
                Ok(Some(projection)) => folded.push(projection),
                Ok(None) => {}
                Err(error) => {
                    // Terminal basis not covered locally: backfill required.
                    // Keep the existing cache entry rather than guessing.
                    tracing::debug!(%error, "Sidecar exchange fold deferred pending backfill");
                }
            }
        }
    }
    for upgraded in fact_upgrades {
        if let Err(error) = save_stored_sidecar_exchange_request_fact(store, &upgraded) {
            tracing::warn!(%error, "Sidecar request fact upgrade persistence failed");
        }
    }
    let mut changed = 0;
    for projection in folded {
        match cache_sidecar_exchange_projection(store, controller_id, &projection) {
            Ok(true) => changed += 1,
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(%error, "Sidecar exchange fold cache write failed");
            }
        }
    }
    changed
}

pub fn cached_sidecar_display_mode(
    store: &crate::state::LocalStateStore,
    account_did: &str,
    session: &HostedSidecarState,
) -> Option<arkret_sdk::AgentSidecarDisplayMode> {
    let key = sidecar_view_state_cache_key(
        &session.controller_id,
        &session.source_realm_id,
        &session.source_strand_id,
    );
    let view_state = store
        .load_private_data(account_did, &key)
        .and_then(|raw| serde_json::from_str::<arkret_sdk::AgentSidecarViewState>(&raw).ok())?;
    (view_state.controller_id.as_str() == session.controller_id
        && view_state.sidecar_id == session.sidecar_id
        && view_state.context_ref.realm_id.as_str() == session.source_realm_id
        && view_state.context_ref.strand_id.as_str() == session.source_strand_id)
        .then_some(view_state.display_mode)
}

#[derive(Clone, Copy)]
pub struct HostedSidecarStateContext(pub Signal<Option<HostedSidecarState>>);

#[component]
pub fn HostedSidecarContextBar(base_url: String, api_token: String, device_id: String) -> Element {
    let mut hosted_state = use_context::<HostedSidecarStateContext>().0;
    let mut state_store = crate::app::SessionContext::get().state_store;
    let Some(session) = hosted_state() else {
        return rsx! {};
    };
    let security_label = if session.membership_ready() {
        "E2EE"
    } else {
        "Reconciling access"
    };
    let merged_base = base_url.clone();
    let merged_token = api_token.clone();
    let merged_device = device_id.clone();
    let sidecar_base = base_url;
    let sidecar_token = api_token;
    let sidecar_device = device_id;

    rsx! {
        div { class: "sidecar-context-strip", "data-testid": "sidecar-context-strip",
            div { class: "sidecar-context-main",
                strong { "Private Sidecar active" }
                span { class: "muted", "Only you and your eligible AI Agents · E2EE" }
                span {
                    class: "badge sidecar-write-target",
                    "data-testid": "sidecar-write-target",
                    "data-write-target": "private",
                    "Editing: Private Sidecar"
                }
            }
            div { class: "sidecar-display-mode", role: "group", "aria-label": "Private Sidecar display mode",
                button {
                    r#type: "button",
                    class: if session.display_mode == arkret_sdk::AgentSidecarDisplayMode::ContextMerged { "active" } else { "" },
                    "data-testid": "sidecar-mode-context-merged",
                    onclick: move |_| {
                        if let Some(mut current) = hosted_state() {
                            current.display_mode = arkret_sdk::AgentSidecarDisplayMode::ContextMerged;
                            push_sidecar_display_mode(
                                &mut state_store.write(),
                                merged_base.clone(),
                                merged_token.clone(),
                                current.controller_id.clone(),
                                merged_device.clone(),
                                &current,
                            );
                            hosted_state.set(Some(current));
                        }
                    },
                    "Original Strand + Sidecar"
                }
                button {
                    r#type: "button",
                    class: if session.display_mode == arkret_sdk::AgentSidecarDisplayMode::SidecarOnly { "active" } else { "" },
                    "data-testid": "sidecar-mode-sidecar-only",
                    onclick: move |_| {
                        if let Some(mut current) = hosted_state() {
                            current.display_mode = arkret_sdk::AgentSidecarDisplayMode::SidecarOnly;
                            push_sidecar_display_mode(
                                &mut state_store.write(),
                                sidecar_base.clone(),
                                sidecar_token.clone(),
                                current.controller_id.clone(),
                                sidecar_device.clone(),
                                &current,
                            );
                            hosted_state.set(Some(current));
                        }
                    },
                    "Sidecar only"
                }
                button {
                    r#type: "button",
                    "data-testid": "sidecar-exit",
                    onclick: move |_| hosted_state.set(None),
                    "Exit Private Sidecar"
                }
            }
            div { class: "sidecar-addressed-now", "data-testid": "sidecar-addressed-now",
                span { class: "muted", "Addressed now" }
                strong { "{session.addressed_agent_label}" }
                span { class: "badge", "{security_label}" }
            }
        }
    }
}

/// Best-effort encrypted cross-device persistence for the hosted Strand-level
/// display mode. The local signal is authoritative for the current frame; a
/// failed network write is retried naturally by a later user change/account
/// stream reconciliation and never mutates shared Strand state.
pub fn push_sidecar_display_mode(
    store: &mut crate::state::LocalStateStore,
    base_url: String,
    api_token: String,
    controller_id: String,
    device_id: String,
    session: &HostedSidecarState,
) {
    let context_ref = match (
        arkret_sdk::RealmId::new(session.source_realm_id.clone()),
        arkret_sdk::StrandId::new(session.source_strand_id.clone()),
        arkret_sdk::Did::new(controller_id.clone()),
        arkret_sdk::DeviceId::new(device_id.clone()),
    ) {
        (Ok(realm_id), Ok(strand_id), Ok(controller_id), Ok(origin_device_id)) => {
            (realm_id, strand_id, controller_id, origin_device_id)
        }
        _ => {
            tracing::warn!("Sidecar view-state contains an invalid typed identifier");
            return;
        }
    };
    let control_realm_id = arkret_sdk::principal_control_realm_id(&context_ref.2);
    let updated_hlc = match crate::signing_stamp::issue_protocol_hlc(
        context_ref.2.as_str(),
        context_ref.3.as_str(),
        &control_realm_id,
    ) {
        Ok(hlc) => hlc,
        Err(error) => {
            tracing::warn!(%error, "Sidecar view-state HLC allocation failed");
            return;
        }
    };
    let view_state = arkret_sdk::AgentSidecarViewState {
        schema: arkret_sdk::AgentSidecarViewStateSchema::V1,
        controller_id: context_ref.2,
        sidecar_id: session.sidecar_id.clone(),
        context_ref: arkret_sdk::AgentSidecarStrandContextRef {
            realm_id: context_ref.0,
            strand_id: context_ref.1,
        },
        display_mode: session.display_mode,
        pinned: None,
        collapsed: None,
        updated_hlc,
        origin_device_id: context_ref.3,
    };
    let account_data_key = view_state.account_data_key();
    if let Err(error) = cache_sidecar_view_state(store, &controller_id, &view_state) {
        tracing::warn!(%error, "Sidecar view-state local cache failed");
    }
    let plaintext = match serde_json::to_value(&view_state) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "Sidecar view-state serialization failed");
            return;
        }
    };
    let body = match crate::views::settings::account_data::encrypted_account_data_value(
        &account_data_key,
        &plaintext,
    ) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(%error, "Sidecar view-state encryption failed");
            return;
        }
    };
    spawn(async move {
        match crate::transport::auth::with_event_submitter(
            &base_url,
            api_token,
            |submitter| async move {
                crate::transport::account::set_account_data(&submitter, &account_data_key, body)
                    .await
            },
        )
        .await
        {
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(error = %error.display(), "Sidecar view-state sync failed")
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(
        pending: Vec<arkret_sdk::PendingSidecarAccessReconciliationItem>,
    ) -> HostedSidecarState {
        HostedSidecarState {
            trace_id: "019f0000-0000-7000-8000-000000000001".to_owned(),
            controller_id: "did:web:alice.example".to_owned(),
            addressed_agent_ids: vec!["did:web:agents.example:assistant".to_owned()],
            addressed_agent_label: "Assistant".to_owned(),
            source_realm_id: "ak:realm:019f0000-0000-7000-8000-000000000002".to_owned(),
            source_strand_id: "ak:strand:019f0000-0000-7000-8000-000000000003".to_owned(),
            sidecar_id: arkret_sdk::SidecarId::new(
                "ak:sidecar:019f0000-0000-7000-8000-000000000004".to_owned(),
            )
            .unwrap(),
            backing_scope_circle_id: arkret_sdk::CircleId::new(
                "ak:circle:019f0000-0000-7000-8000-000000000007".to_owned(),
            )
            .unwrap(),
            private_strand_id: "ak:strand:019f0000-0000-7000-8000-000000000005".to_owned(),
            private_relation_id: "ak:relation:019f0000-0000-7000-8000-000000000006".to_owned(),
            access_readiness: if pending.is_empty() {
                arkret_sdk::AgentSidecarAccessReadiness::Ready
            } else {
                arkret_sdk::AgentSidecarAccessReadiness::AccessReconciliationPending
            },
            pending_access_reconciliations: pending,
            mls_context: arkret_sdk::AgentSidecarMlsContext {
                desired_access_digest: arkret_sdk::Hash::new(format!("sha256:{}", "1".repeat(64)))
                    .unwrap(),
                control_frontier: vec![
                    arkret_sdk::NonEmptyString::new(
                        "ak:event:019f0000-0000-7000-8000-000000000005",
                    )
                    .unwrap(),
                ],
                mls_group_id: None,
                epoch: None,
                genesis_event_ref: None,
                current_controller_device_ready: false,
            },
            display_mode: arkret_sdk::AgentSidecarDisplayMode::ContextMerged,
            migrated_draft: String::new(),
            opened_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn pending_reconciliation_is_not_ready() {
        let session = session(vec![arkret_sdk::PendingSidecarAccessReconciliationItem {
            agent_id: arkret_sdk::Did::new("did:web:agents.example:assistant").unwrap(),
            provisioning_phase:
                arkret_sdk::PendingSidecarAccessReconciliationStage::BackingScopeMembership,
            reason: arkret_sdk::NonEmptyString::new("membership_projection_pending").unwrap(),
            membership_frontier: None,
        }]);
        assert!(!session.membership_ready());
        assert_eq!(session.pending_reconciliation_count(), 1);
        assert!(
            session
                .diagnostic_summary(
                    "Reconciling access",
                    "not started",
                    "not started",
                    "not reported",
                    "12:00:00",
                )
                .contains("reconciling (1 pending)")
        );
    }

    #[test]
    fn sidecar_readiness_and_mls_binding_require_the_current_device() {
        let mut session = session(Vec::new());
        assert!(!session.membership_ready());
        session.mls_context.current_controller_device_ready = true;
        assert!(session.membership_ready());

        let binding = session.mls_binding().unwrap();
        assert_eq!(binding.sidecar_id, session.sidecar_id);
        assert_eq!(
            binding.desired_access_digest,
            session.mls_context.desired_access_digest
        );
        assert_eq!(
            binding.control_frontier,
            session.mls_context.control_frontier
        );
    }

    #[test]
    fn route_match_requires_realm_and_source_strand() {
        let session = session(Vec::new());
        assert!(session.matches_route(&session.source_realm_id, &session.source_strand_id));
        assert!(!session.matches_route(&session.source_realm_id, &session.private_strand_id));
    }

    #[test]
    fn sidecar_view_state_cache_is_lww_and_context_scoped() {
        let account = "did:web:alice.example";
        let path = std::env::temp_dir().join(format!(
            "inkson-sidecar-view-state-{}.json",
            crate::operation::uuid_v7()
        ));
        let mut store = crate::state::LocalStateStore::with_path(path);
        let session = session(Vec::new());
        let view_state = |mode, hlc: &str, device: &str| arkret_sdk::AgentSidecarViewState {
            schema: arkret_sdk::AgentSidecarViewStateSchema::V1,
            controller_id: arkret_sdk::Did::new(account).unwrap(),
            sidecar_id: session.sidecar_id.clone(),
            context_ref: arkret_sdk::AgentSidecarStrandContextRef {
                realm_id: arkret_sdk::RealmId::new(session.source_realm_id.clone()).unwrap(),
                strand_id: arkret_sdk::StrandId::new(session.source_strand_id.clone()).unwrap(),
            },
            display_mode: mode,
            pinned: None,
            collapsed: None,
            updated_hlc: arkret_sdk::Hlc::new(hlc).unwrap(),
            origin_device_id: arkret_sdk::DeviceId::new(device).unwrap(),
        };
        let newer = view_state(
            arkret_sdk::AgentSidecarDisplayMode::SidecarOnly,
            "01970e589d21-0002-a13f9c2e",
            "ak:device:01964137-0000-7000-8000-000000000001",
        );
        let older = view_state(
            arkret_sdk::AgentSidecarDisplayMode::ContextMerged,
            "01970e589d21-0001-a13f9c2e",
            "ak:device:01964137-0000-7000-8000-000000000002",
        );

        assert!(cache_sidecar_view_state(&mut store, account, &newer).unwrap());
        assert!(!cache_sidecar_view_state(&mut store, account, &older).unwrap());
        assert_eq!(
            cached_sidecar_display_mode(&store, account, &session),
            Some(arkret_sdk::AgentSidecarDisplayMode::SidecarOnly)
        );
    }

    const EXCHANGE_ACCOUNT: &str = "did:web:alice.example";
    const EXCHANGE_AGENT: &str = "did:web:agents.example:assistant";
    const EXCHANGE_REQUEST_EVENT: &str = "ak:event:019f0000-0000-7000-8000-000000000009";
    const EXCHANGE_RESPONSE_EVENT: &str = "ak:event:019f0000-0000-7000-8000-00000000000a";

    fn exchange_test_store(label: &str) -> crate::state::LocalStateStore {
        let path = std::env::temp_dir().join(format!(
            "inkson-sidecar-{label}-{}.json",
            crate::operation::uuid_v7()
        ));
        crate::state::LocalStateStore::with_path(path)
    }

    fn exchange_request_context(
        session: &HostedSidecarState,
    ) -> arkret_sdk::AgentSidecarExchangeRequestContext {
        arkret_sdk::AgentSidecarExchangeRequestContext {
            source_track_ref: arkret_sdk::AgentSidecarSourceTrackRef {
                realm_id: arkret_sdk::RealmId::new(session.source_realm_id.clone()).unwrap(),
                strand_id: arkret_sdk::StrandId::new(session.source_strand_id.clone()).unwrap(),
                track_name: "discussion".to_owned(),
            },
            source_hlc: arkret_sdk::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            client_order_key: arkret_sdk::NonEmptyString::new("device-1-1").unwrap(),
            addressed_agent_ids: vec![arkret_sdk::Did::new(EXCHANGE_AGENT).unwrap()],
            completion_policy: arkret_sdk::AgentSidecarExchangeCompletionPolicy::Coordinator,
            coordinator_agent_id: None,
            source_frontier_anchor: None,
        }
    }

    fn exchange_pending_submission(session: &HostedSidecarState) -> PendingSidecarSubmission {
        PendingSidecarSubmission {
            controller_id: EXCHANGE_ACCOUNT.to_owned(),
            sidecar_id: session.sidecar_id.clone(),
            private_strand_id: session.private_strand_id.clone(),
            backing_circle_id: session.backing_scope_circle_id.clone(),
            exchange_id: arkret_sdk::AgentSidecarExchangeId::new("exchange-01964137000000000008")
                .unwrap(),
            request_context: exchange_request_context(session),
            message_id: "msg:019f0000-0000-7000-8000-0000000000aa".to_owned(),
            local_operation_id: "op:019f0000-0000-7000-8000-0000000000ab".to_owned(),
        }
    }

    #[test]
    fn pending_sidecar_submission_is_client_local_and_reused_for_retry() {
        let mut store = exchange_test_store("pending");
        let session = session(Vec::new());
        let pending = exchange_pending_submission(&session);
        let intent = sidecar_submission_intent_digest(
            &session.source_strand_id,
            "hello @assistant",
            &[EXCHANGE_AGENT.to_owned()],
        );
        save_pending_sidecar_submission(&mut store, &intent, &pending).unwrap();

        // The record is a client-local private_data entry, never an
        // account-data type, and never enters the fold cache.
        assert!(
            store
                .private_data_keys()
                .iter()
                .any(|key| { key.starts_with("ak.local.sidecar_pending_submission.v1:") })
        );
        assert!(
            cached_sidecar_exchange_projections(
                &store,
                EXCHANGE_ACCOUNT,
                session.source_realm_id.as_str()
            )
            .is_empty()
        );

        // A retry of the same intent resolves the SAME exchange_id.
        let reloaded = load_pending_sidecar_submission(
            &store,
            EXCHANGE_ACCOUNT,
            &session.private_strand_id,
            &intent,
        )
        .unwrap();
        assert_eq!(reloaded.exchange_id, pending.exchange_id);
        assert_eq!(reloaded.request_context, pending.request_context);

        // A different intent (different body) does NOT reuse the record.
        let other_intent = sidecar_submission_intent_digest(
            &session.source_strand_id,
            "different body",
            &[EXCHANGE_AGENT.to_owned()],
        );
        assert!(
            load_pending_sidecar_submission(
                &store,
                EXCHANGE_ACCOUNT,
                &session.private_strand_id,
                &other_intent,
            )
            .is_none()
        );

        remove_pending_sidecar_submission(
            &mut store,
            EXCHANGE_ACCOUNT,
            &session.private_strand_id,
            &intent,
        );
        assert!(pending_sidecar_submissions(&store, EXCHANGE_ACCOUNT).is_empty());
    }

    #[test]
    fn accepted_request_folds_to_delivered_in_the_local_cache_only() {
        let mut store = exchange_test_store("accepted");
        let session = session(Vec::new());
        let pending = exchange_pending_submission(&session);

        record_accepted_sidecar_exchange_request(&mut store, &pending, EXCHANGE_REQUEST_EVENT)
            .unwrap();

        let cached = cached_sidecar_exchange_projections(
            &store,
            EXCHANGE_ACCOUNT,
            session.source_realm_id.as_str(),
        );
        assert_eq!(cached.len(), 1);
        let projection = &cached[0];
        assert_eq!(
            projection.status,
            arkret_sdk::AgentSidecarExchangeStatus::Delivered
        );
        assert_eq!(
            projection.private_request_event_id.as_str(),
            EXCHANGE_REQUEST_EVENT
        );
        assert_eq!(
            projection.coordinator_agent_id.as_str(),
            EXCHANGE_AGENT,
            "single addressed Agent is the implied coordinator"
        );
        assert!(projection.user_facing_response_event_ids.is_empty());
        // Purely local storage: no account-data-shaped (`ak.agent.*`) key
        // anywhere — only the client-local fold cache / fact records.
        assert!(
            store
                .private_data_keys()
                .iter()
                .all(|key| !key.starts_with("ak.agent."))
        );
        // The fold cache replaces wholesale and is idempotent.
        assert!(
            !cache_sidecar_exchange_projection(&mut store, EXCHANGE_ACCOUNT, projection).unwrap()
        );
        // Controller binding still fails closed.
        assert!(
            cache_sidecar_exchange_projection(&mut store, "did:web:bob.example", projection)
                .is_err()
        );
    }

    #[test]
    fn received_user_facing_response_folds_to_responding_idempotently() {
        let mut store = exchange_test_store("respond");
        let session = session(Vec::new());
        let pending = exchange_pending_submission(&session);
        record_accepted_sidecar_exchange_request(&mut store, &pending, EXCHANGE_REQUEST_EVENT)
            .unwrap();

        // Craft the Agent-authored user_facing_response Event; the fake
        // decrypt below returns the mounted metadata value as plaintext.
        let binding = arkret_sdk::AgentSidecarEventExchangeBinding::user_facing_response(
            pending.exchange_id.clone(),
            arkret_sdk::EventId::new(EXCHANGE_REQUEST_EVENT).unwrap(),
        )
        .unwrap();
        let mut metadata = arkret_sdk::MessageMetadata::default();
        metadata.set_sidecar_exchange_binding(&binding).unwrap();
        let mut event = arkret_sdk::Event::new(
            arkret_sdk::events::EventKind::MESSAGE_CREATE,
            arkret_sdk::RealmId::new(session.source_realm_id.clone()).unwrap(),
            arkret_sdk::Did::new(EXCHANGE_AGENT).unwrap(),
            1,
            arkret_sdk::Hlc::new("01970e589d21-0002-a13f9c2e").unwrap(),
            serde_json::json!({
                "strand_id": session.private_strand_id.clone(),
                "track_name": "discussion",
                "encrypted_metadata": serde_json::to_value(&metadata).unwrap(),
            }),
        )
        .unwrap();
        event.event_id = arkret_sdk::EventId::new(EXCHANGE_RESPONSE_EVENT).unwrap();
        event.effective_scope = Some(arkret_wire::EffectiveScope::Circle {
            realm_id: arkret_sdk::RealmId::new(session.source_realm_id.clone()).unwrap(),
            circle_id: session.backing_scope_circle_id.clone(),
        });
        event.refs = vec![arkret_sdk::EventRef::new(EXCHANGE_REQUEST_EVENT, "after")];
        store.append_raw_operation(
            EXCHANGE_RESPONSE_EVENT.to_owned(),
            Some(session.source_realm_id.clone()),
            serde_json::to_value(&event).unwrap(),
        );

        let passthrough = |_: &crate::state::LocalStateStore,
                           _: &str,
                           value: &serde_json::Value|
         -> Option<Vec<u8>> { serde_json::to_vec(value).ok() };
        let changed = refold_sidecar_exchanges_with_decrypt(
            &mut store,
            EXCHANGE_ACCOUNT,
            &session.source_realm_id,
            &[],
            &passthrough,
        );
        assert_eq!(changed, 1);

        let cached = cached_sidecar_exchange_projections(
            &store,
            EXCHANGE_ACCOUNT,
            session.source_realm_id.as_str(),
        );
        assert_eq!(cached.len(), 1);
        assert_eq!(
            cached[0].status,
            arkret_sdk::AgentSidecarExchangeStatus::Responding
        );
        assert_eq!(
            cached[0]
                .user_facing_response_event_ids
                .iter()
                .map(|event_id| event_id.as_str().to_owned())
                .collect::<Vec<_>>(),
            vec![EXCHANGE_RESPONSE_EVENT.to_owned()]
        );
        assert_eq!(
            cached[0]
                .participating_agent_ids
                .iter()
                .map(|did| did.as_str().to_owned())
                .collect::<Vec<_>>(),
            vec![EXCHANGE_AGENT.to_owned()]
        );

        // Re-running the fold over the same history is idempotent: the
        // deterministic result matches the cache, so nothing changes.
        let unchanged = refold_sidecar_exchanges_with_decrypt(
            &mut store,
            EXCHANGE_ACCOUNT,
            &session.source_realm_id,
            &[],
            &passthrough,
        );
        assert_eq!(unchanged, 0);
    }

    /// F-1 (§7.2.1 / §7.2.2 check 1): a decryptable binding arriving under a
    /// DIFFERENT Circle scope than this context's backing Circle — even with
    /// a forged matching `payload.strand_id` — fails closed to non-echo.
    #[test]
    fn foreign_circle_scoped_binding_stays_non_echo() {
        let mut store = exchange_test_store("foreign-circle");
        let session = session(Vec::new());
        let pending = exchange_pending_submission(&session);
        record_accepted_sidecar_exchange_request(&mut store, &pending, EXCHANGE_REQUEST_EVENT)
            .unwrap();

        let binding = arkret_sdk::AgentSidecarEventExchangeBinding::user_facing_response(
            pending.exchange_id.clone(),
            arkret_sdk::EventId::new(EXCHANGE_REQUEST_EVENT).unwrap(),
        )
        .unwrap();
        let mut metadata = arkret_sdk::MessageMetadata::default();
        metadata.set_sidecar_exchange_binding(&binding).unwrap();
        let mut event = arkret_sdk::Event::new(
            arkret_sdk::events::EventKind::MESSAGE_CREATE,
            arkret_sdk::RealmId::new(session.source_realm_id.clone()).unwrap(),
            arkret_sdk::Did::new(EXCHANGE_AGENT).unwrap(),
            1,
            arkret_sdk::Hlc::new("01970e589d21-0002-a13f9c2e").unwrap(),
            serde_json::json!({
                // Forged strand_id pointing at the Sidecar private Strand …
                "strand_id": session.private_strand_id.clone(),
                "track_name": "discussion",
                "encrypted_metadata": serde_json::to_value(&metadata).unwrap(),
            }),
        )
        .unwrap();
        event.event_id = arkret_sdk::EventId::new(EXCHANGE_RESPONSE_EVENT).unwrap();
        // … but scoped to an unrelated Circle the controller can also read.
        event.effective_scope = Some(arkret_wire::EffectiveScope::Circle {
            realm_id: arkret_sdk::RealmId::new(session.source_realm_id.clone()).unwrap(),
            circle_id: arkret_sdk::CircleId::new("ak:circle:019f0000-0000-7000-8000-0000000000ff")
                .unwrap(),
        });
        event.refs = vec![arkret_sdk::EventRef::new(EXCHANGE_REQUEST_EVENT, "after")];
        store.append_raw_operation(
            EXCHANGE_RESPONSE_EVENT.to_owned(),
            Some(session.source_realm_id.clone()),
            serde_json::to_value(&event).unwrap(),
        );

        let passthrough = |_: &crate::state::LocalStateStore,
                           _: &str,
                           value: &serde_json::Value|
         -> Option<Vec<u8>> { serde_json::to_vec(value).ok() };
        let changed = refold_sidecar_exchanges_with_decrypt(
            &mut store,
            EXCHANGE_ACCOUNT,
            &session.source_realm_id,
            &[],
            &passthrough,
        );
        assert_eq!(changed, 0, "foreign-Circle events never enter the fold");
        let cached = cached_sidecar_exchange_projections(
            &store,
            EXCHANGE_ACCOUNT,
            session.source_realm_id.as_str(),
        );
        assert_eq!(
            cached[0].status,
            arkret_sdk::AgentSidecarExchangeStatus::Delivered,
            "the exchange stays delivered; no responses, no participation"
        );
        assert!(cached[0].user_facing_response_event_ids.is_empty());
        assert!(cached[0].participating_agent_ids.is_empty());
    }

    /// F-3: once the accepted request Event's envelope syncs back, its clear
    /// `actor_seq` / top-level `hlc` upgrade the authoring device's
    /// placeholder request fact — even though the metadata stays
    /// undecryptable for the author (MLS forward secrecy).
    #[test]
    fn request_envelope_syncback_upgrades_placeholder_fact_values() {
        let mut store = exchange_test_store("fact-upgrade");
        let session = session(Vec::new());
        let pending = exchange_pending_submission(&session);
        record_accepted_sidecar_exchange_request(&mut store, &pending, EXCHANGE_REQUEST_EVENT)
            .unwrap();

        let mut event = arkret_sdk::Event::new(
            arkret_sdk::events::EventKind::MESSAGE_CREATE,
            arkret_sdk::RealmId::new(session.source_realm_id.clone()).unwrap(),
            arkret_sdk::Did::new(EXCHANGE_ACCOUNT).unwrap(),
            7,
            arkret_sdk::Hlc::new("01970e589d21-0005-a13f9c2e").unwrap(),
            serde_json::json!({
                "strand_id": session.private_strand_id.clone(),
                "track_name": "discussion",
                "encrypted_metadata": {"opaque": "ciphertext"},
            }),
        )
        .unwrap();
        event.event_id = arkret_sdk::EventId::new(EXCHANGE_REQUEST_EVENT).unwrap();
        event.effective_scope = Some(arkret_wire::EffectiveScope::Circle {
            realm_id: arkret_sdk::RealmId::new(session.source_realm_id.clone()).unwrap(),
            circle_id: session.backing_scope_circle_id.clone(),
        });
        store.append_raw_operation(
            EXCHANGE_REQUEST_EVENT.to_owned(),
            Some(session.source_realm_id.clone()),
            serde_json::to_value(&event).unwrap(),
        );

        // The author device cannot decrypt its own metadata: decrypt always
        // fails, so ONLY the envelope-upgrade path can improve the fact.
        let author_device_decrypt = |_: &crate::state::LocalStateStore,
                                     _: &str,
                                     _: &serde_json::Value|
         -> Option<Vec<u8>> { None };
        let changed = refold_sidecar_exchanges_with_decrypt(
            &mut store,
            EXCHANGE_ACCOUNT,
            &session.source_realm_id,
            &[],
            &author_device_decrypt,
        );
        assert_eq!(changed, 1);
        let cached = cached_sidecar_exchange_projections(
            &store,
            EXCHANGE_ACCOUNT,
            session.source_realm_id.as_str(),
        );
        assert_eq!(
            cached[0].folded_frontier.max_hlc,
            arkret_sdk::Hlc::new("01970e589d21-0005-a13f9c2e").unwrap(),
            "the fold now rides the accepted envelope's real top-level HLC"
        );
        // The upgrade persisted: a second refold is a no-op (Fresh cache).
        let unchanged = refold_sidecar_exchanges_with_decrypt(
            &mut store,
            EXCHANGE_ACCOUNT,
            &session.source_realm_id,
            &[],
            &author_device_decrypt,
        );
        assert_eq!(unchanged, 0);
    }

    /// F-7: only one in-flight submit per `(controller, strand, intent)`;
    /// releasing the guard frees the slot for a retry.
    #[test]
    fn sidecar_submission_guard_blocks_concurrent_same_intent() {
        let strand = "ak:strand:019f0000-0000-7000-8000-0000000000e1";
        let intent = "guard-test-intent-digest";
        let first = try_begin_sidecar_submission(EXCHANGE_ACCOUNT, strand, intent);
        assert!(first.is_some());
        assert!(
            try_begin_sidecar_submission(EXCHANGE_ACCOUNT, strand, intent).is_none(),
            "the same intent cannot start a second concurrent submit"
        );
        assert!(
            try_begin_sidecar_submission(EXCHANGE_ACCOUNT, strand, "other-intent").is_some(),
            "different intents are independent"
        );
        drop(first);
        assert!(
            try_begin_sidecar_submission(EXCHANGE_ACCOUNT, strand, intent).is_some(),
            "dropping the guard releases the slot"
        );
    }
}
