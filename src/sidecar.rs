//! Ephemeral hosted-view state for an Agent Sidecar.
//!
//! This state deliberately stays in memory. It carries UI context from the
//! ensure action into the source Strand shell without inventing a wire type or
//! persisting message plaintext outside the existing composer lifecycle.

use dioxus::prelude::*;

#[derive(Clone, Debug, PartialEq)]
pub struct HostedSidecarState {
    pub trace_id: String,
    pub controller_account_id: arkret_sdk::AccountId,
    pub addressed_agent_ids: Vec<String>,
    pub addressed_agent_label: String,
    pub source_realm_id: String,
    pub source_strand_id: String,
    pub sidecar_id: arkret_sdk::SidecarId,
    pub access_readiness: arkret_sdk::AgentSidecarAccessReadiness,
    pub pending_access_reconciliations: Vec<arkret_sdk::PendingSidecarAccessReconciliationItem>,
    pub mls_context: arkret_sdk::AgentSidecarMlsContext,
    /// True only after this device has restored a snapshot keyed by the
    /// native `(realm_id, sidecar_id, mls_group_id)` scope. A server `ready`
    /// projection alone must never authorize a store this device cannot open.
    pub native_mls_ready: bool,
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
            && self.native_mls_ready
    }

    pub fn mls_binding(&self) -> arkret_sdk::Result<arkret_sdk::SidecarMlsBinding> {
        let binding = arkret_sdk::SidecarMlsBinding {
            sidecar_id: self.sidecar_id.clone(),
            participant_authority_digest: self.mls_context.participant_authority_digest.clone(),
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SidecarViewStateMergeDecision {
    UseCurrent,
    UseCandidate,
}

fn sidecar_view_state_merge_decision(
    current_plaintext: Option<&serde_json::Value>,
    account_data_namespace_key: &[u8],
    account_data_key: &str,
    candidate: &arkret_sdk::AgentSidecarViewState,
) -> anyhow::Result<SidecarViewStateMergeDecision> {
    candidate.validate_account_data_key(account_data_namespace_key, account_data_key)?;
    let Some(current_plaintext) = current_plaintext else {
        return Ok(SidecarViewStateMergeDecision::UseCandidate);
    };
    let current =
        serde_json::from_value::<arkret_sdk::AgentSidecarViewState>(current_plaintext.clone())?;
    current.validate_account_data_key(account_data_namespace_key, account_data_key)?;
    if current.sidecar_id != candidate.sidecar_id {
        anyhow::bail!("Sidecar view-state reuses one context key for different Sidecar ids");
    }
    if current.updated_hlc == candidate.updated_hlc
        && current.origin_device_id == candidate.origin_device_id
    {
        if current == *candidate {
            return Ok(SidecarViewStateMergeDecision::UseCurrent);
        }
        anyhow::bail!("Sidecar view-state conflicting payload reuses one LWW stamp");
    }
    let mut fold = garth::projection::SidecarProjectionFold::default();
    fold.apply_view_state(current);
    Ok(if fold.apply_view_state(candidate.clone()) {
        SidecarViewStateMergeDecision::UseCandidate
    } else {
        SidecarViewStateMergeDecision::UseCurrent
    })
}

fn apply_sidecar_view_state_checked(
    store: &mut crate::state::LocalStateStore,
    account_data_namespace_key: &[u8],
    view_state: &arkret_sdk::AgentSidecarViewState,
) -> anyhow::Result<bool> {
    let current = store.sidecar_view_state(
        &view_state.controller_account_id,
        &view_state.context_ref.realm_id,
        &view_state.context_ref.strand_id,
    );
    let current_plaintext = current.as_ref().map(serde_json::to_value).transpose()?;
    match sidecar_view_state_merge_decision(
        current_plaintext.as_ref(),
        account_data_namespace_key,
        &view_state.account_data_key(account_data_namespace_key)?,
        view_state,
    )? {
        SidecarViewStateMergeDecision::UseCurrent => Ok(false),
        SidecarViewStateMergeDecision::UseCandidate => {
            anyhow::ensure!(
                store.apply_sidecar_view_state(view_state.clone()),
                "Sidecar view-state checked merge did not replace the current fold"
            );
            Ok(true)
        }
    }
}

fn cache_sidecar_view_state_with_namespace(
    store: &mut crate::state::LocalStateStore,
    authority: &arkret_sdk::AccountId,
    namespace_key: &[u8],
    view_state: &arkret_sdk::AgentSidecarViewState,
) -> anyhow::Result<bool> {
    if &view_state.controller_account_id != authority {
        anyhow::bail!("Sidecar view-state controller does not match the account holder");
    }
    let key = view_state.account_data_key(namespace_key)?;
    if let Some(persisted) = store
        .load_plain_local_data(&key)
        .and_then(|raw| serde_json::from_str::<arkret_sdk::AgentSidecarViewState>(&raw).ok())
    {
        let persisted_plaintext = serde_json::to_value(&persisted)?;
        if sidecar_view_state_merge_decision(
            Some(&persisted_plaintext),
            namespace_key,
            &key,
            view_state,
        )? == SidecarViewStateMergeDecision::UseCurrent
        {
            apply_sidecar_view_state_checked(store, namespace_key, &persisted)?;
        }
    }
    let should_replace = apply_sidecar_view_state_checked(store, namespace_key, view_state)?;
    if should_replace {
        store.save_plain_local_data(key, serde_json::to_string(view_state)?);
    }
    Ok(should_replace)
}

fn cache_sidecar_view_state(
    store: &mut crate::state::LocalStateStore,
    authority: &arkret_sdk::AccountId,
    view_state: &arkret_sdk::AgentSidecarViewState,
) -> anyhow::Result<bool> {
    let namespace_key = crate::account_data::account_data_namespace_key(authority)?;
    cache_sidecar_view_state_with_namespace(store, authority, &namespace_key, view_state)
}

pub fn ingest_sidecar_view_state_account_data(
    store: &mut crate::state::LocalStateStore,
    authority: &arkret_sdk::AccountId,
    account_data_key: &str,
    entry: &impl serde::Serialize,
) -> anyhow::Result<bool> {
    if !account_data_key.starts_with(&format!(
        "{}:",
        arkret_sdk::AccountDataKey::AGENT_SIDECAR_VIEW_STATE_V1
    )) {
        return Ok(false);
    }
    let view_state: arkret_sdk::AgentSidecarViewState = serde_json::from_value(
        crate::account_data::decrypt_account_data_entry(authority, account_data_key, entry)?,
    )?;
    let namespace_key = crate::account_data::account_data_namespace_key(authority)?;
    view_state.validate_account_data_key(&namespace_key, account_data_key)?;
    if &view_state.controller_account_id != authority {
        anyhow::bail!("Sidecar view-state controller does not match the account holder");
    }
    cache_sidecar_view_state_with_namespace(store, authority, &namespace_key, &view_state)?;
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
/// Retryable controller-device-local intent to author a durable close Event.
/// This record is never folded as terminal truth. Even after the submit is
/// accepted, the projection remains `responding` until that control Event is
/// observed in accepted private-Strand history.
const SIDECAR_AUTO_CLOSE_INTENT_PREFIX: &str = "sidecar_exchange_auto_close_intent";
/// Controller-device-local recovery cache. These locators are derived from
/// accepted structural Event history and are never uploaded.
const SIDECAR_CONTEXT_LOCATOR_PREFIX: &str = "sidecar_context_locator";

fn sidecar_exchange_fold_cache_key(
    controller_principal_id: &str,
    sidecar_id: &str,
    exchange_id: &str,
) -> String {
    format!(
        "{SIDECAR_EXCHANGE_FOLD_CACHE_PREFIX}:{controller_principal_id}:{sidecar_id}:{exchange_id}"
    )
}

/// Replace the local fold cache entry for one exchange. The fold output is
/// authoritative for the cache: no LWW, no `updated_hlc` arbitration. Writes
/// are skipped when the cached value is already identical so reactive callers
/// do not loop on their own writes. Returns whether the cache changed.
pub(crate) fn cache_sidecar_exchange_projection(
    store: &mut crate::state::LocalStateStore,
    controller_account_id: &arkret_sdk::AccountId,
    projection: &arkret_sdk::AgentSidecarExchangeProjection,
) -> anyhow::Result<bool> {
    projection.validate()?;
    if &projection.controller_account_id != controller_account_id {
        anyhow::bail!("Sidecar exchange controller does not match the account holder");
    }
    store.apply_sidecar_exchange_projection(projection.clone())?;
    let key = sidecar_exchange_fold_cache_key(
        projection.controller_account_id.principal_id.as_str(),
        projection.sidecar_id.as_str(),
        projection.exchange_id.as_str(),
    );
    let current = store.load_plain_local_data(&key).and_then(|raw| {
        serde_json::from_str::<arkret_sdk::AgentSidecarExchangeProjection>(&raw).ok()
    });
    if current.as_ref() == Some(projection) {
        return Ok(false);
    }
    store.save_plain_local_data(key, serde_json::to_string(projection)?);
    Ok(true)
}

pub fn cached_sidecar_exchange_projections(
    store: &crate::state::LocalStateStore,
    controller_account_id: &arkret_sdk::AccountId,
    source_realm_id: &str,
) -> Vec<arkret_sdk::AgentSidecarExchangeProjection> {
    let Ok(realm_id) = arkret_sdk::RealmId::new(source_realm_id.to_owned()) else {
        return Vec::new();
    };
    let prefix = format!(
        "{SIDECAR_EXCHANGE_FOLD_CACHE_PREFIX}:{}:",
        controller_account_id.principal_id
    );
    // Persisted entries are rebuildable restart seeds only. The actual query
    // snapshot comes from the shared fold below, so ingest and UI cannot drift
    // into separate timeline implementations.
    let restart_seeds = store
        .plain_local_data_keys()
        .into_iter()
        .filter(|key| key.starts_with(&prefix))
        .filter_map(|key| store.load_plain_local_data(&key))
        .filter_map(|raw| {
            serde_json::from_str::<arkret_sdk::AgentSidecarExchangeProjection>(&raw).ok()
        })
        .filter(|projection| {
            projection.validate().is_ok()
                && projection.controller_account_id == *controller_account_id
                && projection.source_track_ref.realm_id.as_str() == source_realm_id
        })
        .collect::<Vec<_>>();
    let mut fold = store.sidecar_projection_fold_snapshot();
    for projection in restart_seeds {
        if let Err(error) = fold.apply_folded_exchange(projection) {
            tracing::warn!(%error, "persisted Sidecar exchange restart seed rejected");
        }
    }
    let mut projections = fold
        .exchanges_for_realm(&realm_id)
        .filter(|&projection| projection.controller_account_id == *controller_account_id)
        .cloned()
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

// ---------------------------------------------------------------------------
// Fold-cache evidence surface (`wasm-localstorage-secrets-test` only).
//
// A joint test that rebuilds a "frontier" from DOM messages is measuring the
// set of Events that happened to render, not
// `AgentSidecarExchangeFoldedFrontier`. That cannot show two controller devices
// hold a byte-identical fold cache, which is the actual §7.2.4 claim.
//
// So the evidence is read straight out of the validated cache instead. It is
// read-only, same-origin, and controller-only: every entry comes from
// `cached_sidecar_exchange_projections`, which already requires
// `projection.validate()` and `controller_principal_id == principal_id`. The whole surface
// is compiled out of production builds, and it is reachable only by an explicit
// call — never through a URL, a log line, a trace label, telemetry, or ordinary
// shared DOM — so it cannot widen the disclosure boundary
// `SidecarPrivacyGate` defends.
// ---------------------------------------------------------------------------

/// The evidence surface exists only in a build that opted into the test
/// feature, and within that build only where something can call it: the wasm
/// bundle installs the JS handle, and the native test target exercises the
/// serializer directly. A native production build compiles none of it.
macro_rules! fold_evidence_surface {
    ($($item:item)*) => {
        $(
            #[cfg(all(
                feature = "wasm-localstorage-secrets-test",
                any(target_arch = "wasm32", test)
            ))]
            $item
        )*
    };
}

fold_evidence_surface! {
/// Schema marker so a test can prove it read this surface and not a
/// same-shaped object some other layer happened to produce.
pub(crate) const SIDECAR_FOLD_EVIDENCE_SCHEMA: &str = "inkson.test.sidecar_fold_evidence.v1";

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct SidecarFoldEvidenceEntry {
    pub exchange_id: arkret_sdk::AgentSidecarExchangeId,
    pub status: arkret_sdk::AgentSidecarExchangeStatus,
    pub terminal_event_id: Option<arkret_sdk::EventId>,
    pub folded_frontier: arkret_sdk::AgentSidecarExchangeFoldedFrontier,
    /// Canonical digest of `projection`, so two devices can be compared with
    /// one equality check before anything is diffed field by field.
    pub projection_digest: arkret_sdk::Hash,
    /// The validated projection itself — the "projection bytes" a
    /// byte-identity assertion needs.
    pub projection: arkret_sdk::AgentSidecarExchangeProjection,
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct SidecarFoldEvidence {
    pub schema: &'static str,
    pub controller_account_id: arkret_sdk::AccountId,
    pub source_realm_id: String,
    pub exchanges: Vec<SidecarFoldEvidenceEntry>,
}

/// Structured fold-cache evidence for one controller and one source Realm.
///
/// Ordering follows `cached_sidecar_exchange_projections` (source HLC, then
/// exchange id), so two devices that folded the same history serialize in the
/// same order and can be compared as bytes.
pub(crate) fn sidecar_fold_evidence(
    store: &crate::state::LocalStateStore,
    controller_account_id: &arkret_sdk::AccountId,
    source_realm_id: &str,
) -> anyhow::Result<SidecarFoldEvidence> {
    let exchanges = cached_sidecar_exchange_projections(
        store,
        controller_account_id,
        source_realm_id,
    )
        .into_iter()
        .map(|projection| {
            Ok(SidecarFoldEvidenceEntry {
                exchange_id: projection.exchange_id.clone(),
                status: projection.status,
                terminal_event_id: projection.terminal_event_id.clone(),
                folded_frontier: projection.folded_frontier.clone(),
                projection_digest: arkret_sdk::Hash::new(
                    arkret_sdk::canonical::canonical_sha256(&projection)?,
                )?,
                projection,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(SidecarFoldEvidence {
        schema: SIDECAR_FOLD_EVIDENCE_SCHEMA,
        controller_account_id: controller_account_id.clone(),
        source_realm_id: source_realm_id.to_owned(),
        exchanges,
    })
}

/// Canonical JSON of [`sidecar_fold_evidence`]. Canonical rather than plain
/// `to_string` so the comparison the test performs is over stable bytes.
pub(crate) fn sidecar_fold_evidence_canonical_json(
    store: &crate::state::LocalStateStore,
    controller_account_id: &arkret_sdk::AccountId,
    source_realm_id: &str,
) -> anyhow::Result<String> {
    let evidence = sidecar_fold_evidence(store, controller_account_id, source_realm_id)?;
    Ok(arkret_sdk::canonical::canonical_json_string(&evidence)?)
}
}

/// Ordinary product surfaces that must never disclose Sidecar-private
/// identifiers or content. The hosted private overlay is deliberately absent:
/// callers rendering that controller-only surface do not pass through this
/// shared-disclosure gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SidecarDisclosureSurface {
    Search,
    Unread,
    Watch,
    Notification,
    PublicExport,
    SharedPublish,
}

/// One controller-device-local privacy boundary shared by every ordinary
/// disclosure surface. It is derived only from accepted/recovered local
/// Sidecar facts and is never uploaded.
#[derive(Clone, Debug, Default)]
pub(crate) struct SidecarPrivacyGate {
    private_identifiers: std::collections::BTreeSet<String>,
}

impl SidecarPrivacyGate {
    pub(crate) fn from_store(
        store: &crate::state::LocalStateStore,
        controller_principal_id: &str,
    ) -> Self {
        let mut private_identifiers = std::collections::BTreeSet::new();
        for key in store.plain_local_data_keys() {
            let belongs_to_controller = [
                SIDECAR_EXCHANGE_FOLD_CACHE_PREFIX,
                SIDECAR_PENDING_SUBMISSION_PREFIX,
                SIDECAR_EXCHANGE_REQUEST_FACT_PREFIX,
                SIDECAR_AUTO_CLOSE_INTENT_PREFIX,
                SIDECAR_CONTEXT_LOCATOR_PREFIX,
            ]
            .iter()
            .any(|prefix| key.starts_with(&format!("{prefix}:{controller_principal_id}:")));
            if !belongs_to_controller {
                continue;
            }
            let Some(raw) = store.load_plain_local_data(&key) else {
                continue;
            };
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
                continue;
            };
            collect_sidecar_private_identifiers(&value, &mut private_identifiers);
        }
        Self {
            private_identifiers,
        }
    }

    pub(crate) fn allows_strand(
        &self,
        _surface: SidecarDisclosureSurface,
        strand_id: &str,
    ) -> bool {
        let _ = strand_id;
        true
    }

    pub(crate) fn allows_serialized<T: serde::Serialize>(
        &self,
        _surface: SidecarDisclosureSurface,
        value: &T,
    ) -> bool {
        serde_json::to_value(value)
            .ok()
            .is_some_and(|value| !self.value_discloses_private_identifier(&value))
    }

    pub(crate) fn validate_shared_publish(
        &self,
        controller_confirmed: bool,
        target_strand_id: &str,
        allowlisted_body: &str,
    ) -> anyhow::Result<()> {
        if !controller_confirmed {
            anyhow::bail!("Sidecar publish requires explicit controller confirmation");
        }
        if !self.allows_strand(SidecarDisclosureSurface::SharedPublish, target_strand_id) {
            anyhow::bail!("Sidecar publish target must be a shared Strand");
        }
        if self
            .private_identifiers
            .iter()
            .any(|identifier| allowlisted_body.contains(identifier))
        {
            anyhow::bail!("Sidecar publish body contains a private Sidecar identifier");
        }
        Ok(())
    }

    pub(crate) fn validate_public_export<T: serde::Serialize>(
        &self,
        value: &T,
    ) -> anyhow::Result<()> {
        if !self.allows_serialized(SidecarDisclosureSurface::PublicExport, value) {
            anyhow::bail!("public export contains a private Sidecar identifier");
        }
        Ok(())
    }

    fn value_discloses_private_identifier(&self, value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::String(value) => self
                .private_identifiers
                .iter()
                .any(|identifier| value.contains(identifier)),
            serde_json::Value::Array(values) => values
                .iter()
                .any(|value| self.value_discloses_private_identifier(value)),
            serde_json::Value::Object(object) => object.iter().any(|(key, value)| {
                is_sidecar_private_identifier_key(key)
                    || self.value_discloses_private_identifier(value)
            }),
            serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
                false
            }
        }
    }
}

fn is_sidecar_private_identifier_key(key: &str) -> bool {
    matches!(
        key,
        "sidecar_id"
            | "exchange_id"
            | "request_binding"
            | "control_plaintext"
            | "private_history"
            | "private_event_id"
            | "internal_locator"
            | "scratchpad"
            | "tool_state"
            | "draft"
    )
}

fn collect_sidecar_private_identifiers(
    value: &serde_json::Value,
    private_identifiers: &mut std::collections::BTreeSet<String>,
) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                collect_sidecar_private_identifiers(value, private_identifiers);
            }
        }
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                if is_sidecar_private_identifier_key(key)
                    && let Some(identifier) = value.as_str()
                    && !identifier.trim().is_empty()
                {
                    private_identifiers.insert(identifier.to_owned());
                }
                collect_sidecar_private_identifiers(value, private_identifiers);
            }
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {}
    }
}

/// Client-local pre-submission state for one source-routed request intent.
/// Never a wire object: a rejected/failed submit keeps this record (so the
/// retry reuses the same `exchange_id`) and produces no durable exchange
/// state; server acceptance deletes it and seeds the local fold cache.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct PendingSidecarSubmission {
    pub controller_account_id: arkret_sdk::AccountId,
    pub sidecar_id: arkret_sdk::SidecarId,
    pub source_strand_id: String,
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
    controller_principal_id: &str,
    source_strand_id: &str,
    intent_digest: &str,
) -> Option<SidecarSubmissionGuard> {
    let key = format!("{controller_principal_id}\u{1f}{source_strand_id}\u{1f}{intent_digest}");
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
    controller_principal_id: &str,
    source_strand_id: &str,
    intent_digest: &str,
) -> String {
    format!(
        "{SIDECAR_PENDING_SUBMISSION_PREFIX}:{controller_principal_id}:{source_strand_id}:{intent_digest}"
    )
}

pub(crate) fn load_pending_sidecar_submission(
    store: &crate::state::LocalStateStore,
    controller_principal_id: &str,
    source_strand_id: &str,
    intent_digest: &str,
) -> Option<PendingSidecarSubmission> {
    let key =
        pending_sidecar_submission_key(controller_principal_id, source_strand_id, intent_digest);
    let raw = store.load_plain_local_data(&key)?;
    serde_json::from_str::<PendingSidecarSubmission>(&raw)
        .ok()
        .filter(|pending| {
            pending.controller_account_id.principal_id.as_str() == controller_principal_id
        })
}

pub(crate) fn save_pending_sidecar_submission(
    store: &mut crate::state::LocalStateStore,
    intent_digest: &str,
    pending: &PendingSidecarSubmission,
) -> anyhow::Result<()> {
    let key = pending_sidecar_submission_key(
        pending.controller_account_id.principal_id.as_str(),
        &pending.source_strand_id,
        intent_digest,
    );
    store.save_plain_local_data(key, serde_json::to_string(pending)?);
    Ok(())
}

pub(crate) fn remove_pending_sidecar_submission(
    store: &mut crate::state::LocalStateStore,
    controller_principal_id: &str,
    source_strand_id: &str,
    intent_digest: &str,
) {
    let key =
        pending_sidecar_submission_key(controller_principal_id, source_strand_id, intent_digest);
    store.remove_plain_local_data(&key);
}

/// Every stored pending submission of this controller, with its storage key.
pub(crate) fn pending_sidecar_submissions(
    store: &crate::state::LocalStateStore,
    controller_principal_id: &str,
) -> Vec<(String, PendingSidecarSubmission)> {
    let prefix = format!("{SIDECAR_PENDING_SUBMISSION_PREFIX}:{controller_principal_id}:");
    store
        .plain_local_data_keys()
        .into_iter()
        .filter(|key| key.starts_with(&prefix))
        .filter_map(|key| {
            let raw = store.load_plain_local_data(&key)?;
            let pending = serde_json::from_str::<PendingSidecarSubmission>(&raw).ok()?;
            (pending.controller_account_id.principal_id.as_str() == controller_principal_id)
                .then_some((key, pending))
        })
        .collect()
}

/// Durable local record of an accepted controller `role=request` Event.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct StoredSidecarExchangeRequestFact {
    pub controller_account_id: arkret_sdk::AccountId,
    pub sidecar_id: arkret_sdk::SidecarId,
    pub source_strand_id: String,
    pub exchange_id: arkret_sdk::AgentSidecarExchangeId,
    pub request_event_id: String,
    /// Canonical digest of the complete accepted Event Envelope. Submission
    /// responses expose only the Event id, so this remains `None` until the
    /// accepted Envelope syncs back. A fact without this digest is non-fold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_event_digest: Option<String>,
    /// Fold-fact HLC. The authoring device cannot read the accepted Event's
    /// server-stamped top-level HLC synchronously, so the request context's
    /// `source_hlc` stands in; it only feeds `max_hlc` display metadata.
    pub request_event_hlc: arkret_sdk::Hlc,
    /// Accepted controller actor-chain sequence. `0` when the authoring
    /// device could not observe the accepted value; it only participates in
    /// canonical-request selection under controller equivocation. The refold
    /// upgrades it from the accepted Event envelope once that syncs back.
    pub request_event_actor_seq: u64,
    pub request_context: arkret_sdk::AgentSidecarExchangeRequestContext,
}

/// Fold-scope identity for one source Strand attached to a native Sidecar.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SidecarExchangeScopeHint {
    pub source_strand_id: String,
    pub sidecar_id: arkret_sdk::SidecarId,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct PendingSidecarAutoCloseIntent {
    pub controller_account_id: arkret_sdk::AccountId,
    pub sidecar_id: arkret_sdk::SidecarId,
    pub source_strand_id: String,
    pub source_realm_id: String,
    pub exchange_id: arkret_sdk::AgentSidecarExchangeId,
    pub control: arkret_sdk::AgentSidecarExchangeControl,
    /// Present only after the server accepted the authored control. It is a
    /// retry/dedupe marker, not durable close state; history refold remains the
    /// only path that changes the projection to `complete`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_control_event_id: Option<String>,
    #[serde(default)]
    pub failed_attempts: u32,
}

fn sidecar_auto_close_intent_key(
    controller_principal_id: &str,
    source_strand_id: &str,
    exchange_id: &str,
) -> String {
    format!(
        "{SIDECAR_AUTO_CLOSE_INTENT_PREFIX}:{controller_principal_id}:{source_strand_id}:{exchange_id}"
    )
}

fn save_pending_sidecar_auto_close_intent(
    store: &mut crate::state::LocalStateStore,
    intent: &PendingSidecarAutoCloseIntent,
) -> anyhow::Result<()> {
    let key = sidecar_auto_close_intent_key(
        intent.controller_account_id.principal_id.as_str(),
        &intent.source_strand_id,
        intent.exchange_id.as_str(),
    );
    store.save_plain_local_data(key, serde_json::to_string(intent)?);
    Ok(())
}

pub(crate) fn pending_sidecar_auto_close_intents(
    store: &crate::state::LocalStateStore,
    controller_principal_id: &str,
    realm_id: &str,
) -> Vec<PendingSidecarAutoCloseIntent> {
    let prefix = format!("{SIDECAR_AUTO_CLOSE_INTENT_PREFIX}:{controller_principal_id}:");
    store
        .plain_local_data_keys()
        .into_iter()
        .filter(|key| key.starts_with(&prefix))
        .filter_map(|key| store.load_plain_local_data(&key))
        .filter_map(|raw| serde_json::from_str::<PendingSidecarAutoCloseIntent>(&raw).ok())
        .filter(|intent| {
            intent.controller_account_id.principal_id.as_str() == controller_principal_id
                && intent.source_realm_id == realm_id
                && intent.control.validate().is_ok()
        })
        .collect()
}

static SIDECAR_AUTO_CLOSES_IN_FLIGHT: std::sync::OnceLock<
    std::sync::Mutex<std::collections::BTreeSet<String>>,
> = std::sync::OnceLock::new();

struct SidecarAutoCloseGuard {
    key: String,
}

impl Drop for SidecarAutoCloseGuard {
    fn drop(&mut self) {
        if let Some(in_flight) = SIDECAR_AUTO_CLOSES_IN_FLIGHT.get()
            && let Ok(mut in_flight) = in_flight.lock()
        {
            in_flight.remove(&self.key);
        }
    }
}

fn try_begin_sidecar_auto_close(
    controller_principal_id: &str,
    source_strand_id: &str,
    exchange_id: &str,
) -> Option<SidecarAutoCloseGuard> {
    let key = format!("{controller_principal_id}\u{1f}{source_strand_id}\u{1f}{exchange_id}");
    let mut in_flight = SIDECAR_AUTO_CLOSES_IN_FLIGHT
        .get_or_init(|| std::sync::Mutex::new(Default::default()))
        .lock()
        .ok()?;
    in_flight
        .insert(key.clone())
        .then(|| SidecarAutoCloseGuard { key })
}

pub(crate) async fn submit_pending_sidecar_auto_close(
    base_url: &str,
    api_token: String,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
    intent: PendingSidecarAutoCloseIntent,
    sidecar_binding: arkret_sdk::SidecarMlsBinding,
) -> anyhow::Result<()> {
    if intent.accepted_control_event_id.is_some() {
        return Ok(());
    }
    let Some(_guard) = try_begin_sidecar_auto_close(
        intent.controller_account_id.principal_id.as_str(),
        &intent.source_strand_id,
        intent.exchange_id.as_str(),
    ) else {
        return Ok(());
    };
    let seal_view = state_store
        .read()
        .seal_view_for_realm(&intent.source_realm_id);
    let build = crate::views::secure_send::build_sidecar_exchange_control_send(
        state_store,
        &seal_view,
        &intent.source_realm_id,
        authority,
        intent.controller_account_id.principal_id.as_str(),
        device_id,
        &intent.source_strand_id,
        sidecar_binding,
        &intent.control,
    )
    .await
    .map_err(anyhow::Error::msg)?;
    let api = crate::transport::auth::authed_api_with_sync(base_url, api_token.clone(), None)?;
    let outcome = crate::views::secure_send::submit_secure_send(
        &api,
        state_store,
        build,
        &intent.source_realm_id,
        None,
    )
    .await;
    let result = match outcome {
        crate::views::secure_send::SecureSendOutcome::Sent { event_id, .. } => Ok(event_id),
        crate::views::secure_send::SecureSendOutcome::CommitFailed { message }
        | crate::views::secure_send::SecureSendOutcome::MessageFailed { message } => Err(message),
    };
    let mut next = intent;
    match result {
        Ok(event_id) => {
            next.accepted_control_event_id = Some(event_id);
            save_pending_sidecar_auto_close_intent(&mut state_store.write(), &next)?;
            Ok(())
        }
        Err(message) => {
            next.failed_attempts = next.failed_attempts.saturating_add(1);
            save_pending_sidecar_auto_close_intent(&mut state_store.write(), &next)?;
            anyhow::bail!(message)
        }
    }
}

fn sidecar_exchange_request_fact_key(
    controller_principal_id: &str,
    source_strand_id: &str,
    exchange_id: &str,
) -> String {
    format!(
        "{SIDECAR_EXCHANGE_REQUEST_FACT_PREFIX}:{controller_principal_id}:{source_strand_id}:{exchange_id}"
    )
}

fn save_stored_sidecar_exchange_request_fact(
    store: &mut crate::state::LocalStateStore,
    stored: &StoredSidecarExchangeRequestFact,
) -> anyhow::Result<()> {
    let key = sidecar_exchange_request_fact_key(
        stored.controller_account_id.principal_id.as_str(),
        &stored.source_strand_id,
        stored.exchange_id.as_str(),
    );
    store.save_plain_local_data(key, serde_json::to_string(stored)?);
    Ok(())
}

fn stored_sidecar_exchange_request_facts(
    store: &crate::state::LocalStateStore,
    controller_principal_id: &str,
) -> Vec<StoredSidecarExchangeRequestFact> {
    let prefix = format!("{SIDECAR_EXCHANGE_REQUEST_FACT_PREFIX}:{controller_principal_id}:");
    store
        .plain_local_data_keys()
        .into_iter()
        .filter(|key| key.starts_with(&prefix))
        .filter_map(|key| store.load_plain_local_data(&key))
        .filter_map(|raw| serde_json::from_str::<StoredSidecarExchangeRequestFact>(&raw).ok())
        .filter(|fact| fact.controller_account_id.principal_id.as_str() == controller_principal_id)
        .collect()
}

fn request_fact_from_stored(
    stored: &StoredSidecarExchangeRequestFact,
) -> Option<garth::projection::SidecarExchangeRequestFact> {
    Some(garth::projection::SidecarExchangeRequestFact {
        event_id: arkret_sdk::EventId::new(stored.request_event_id.clone()).ok()?,
        hlc: stored.request_event_hlc.clone(),
        actor_account_id: stored.controller_account_id.clone(),
        actor_seq: stored.request_event_actor_seq,
        event_digest: stored.request_event_digest.clone()?,
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
        controller_account_id: pending.controller_account_id.clone(),
        sidecar_id: pending.sidecar_id.clone(),
        source_strand_id: pending.source_strand_id.clone(),
        exchange_id: pending.exchange_id.clone(),
        request_event_id: accepted_event_id.to_owned(),
        request_event_digest: None,
        request_event_hlc: pending.request_context.source_hlc.clone(),
        request_event_actor_seq: 0,
        request_context: pending.request_context.clone(),
    };
    save_stored_sidecar_exchange_request_fact(store, &stored)?;
    Ok(())
}

fn decrypt_sidecar_scoped_envelope(
    store: &crate::state::LocalStateStore,
    realm_id: &str,
    controller_principal_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    sidecar_id: &str,
    envelope_value: &serde_json::Value,
    event: &serde_json::Value,
) -> Option<Vec<u8>> {
    let envelope =
        serde_json::from_value::<arkret_sdk::EncryptedEnvelope>(envelope_value.clone()).ok()?;
    let effective_scope = arkret_sdk::ScopeRef::Sidecar {
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned()).ok()?,
        sidecar_id: arkret_sdk::SidecarId::new(sidecar_id.to_owned()).ok()?,
    };
    let sender_domain = crate::views::chat::verified_chat_sender_domain_for_realm(
        realm_id,
        event,
        Some(store),
        Some((authority, controller_principal_id, device_id)),
    )?;
    let event_kind = event.get("kind")?.as_str()?;
    let payload = crate::mls::runtime::encrypted_payload_from_verified_event_context(
        store,
        &envelope,
        &effective_scope,
        event_kind,
        &sender_domain,
        None,
    )?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    crate::mls::runtime::decrypt_application_payload_for_scope_from_verified_sender(
        store,
        secure_store.as_ref(),
        realm_id,
        authority,
        device_id,
        &payload,
        &effective_scope,
        &sender_domain,
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

fn event_actor_id(event: &arkret_sdk::Event) -> Option<arkret_sdk::DidCoreId> {
    event.proofs.iter().find_map(|proof| {
        let proof = proof.as_producer()?;
        let controller = proof.verification_method.as_str().split_once('#')?.0;
        let did = arkret_sdk::Did::new(controller.to_owned()).ok()?;
        (arkret_sdk::project_did_to_core_id(&did).ok().as_ref()
            == Some(event.actor_id.signing_principal_id()))
        .then(|| event.actor_id.signing_principal_id().clone())
    })
}

/// Refold every locally known exchange of `controller_principal_id` in `realm_id` from
/// Event truth and refresh the local fold cache. The outcome also reports an
/// incomparable cached frontier so the caller can fetch complete accepted
/// history and refold the union.
///
/// Inputs per §7.2.4: durable local request facts (this device's own accepted
/// requests), plus request/response/internal bindings decrypted from
/// `encrypted_metadata` of Sidecar private-Strand `ak.message.create` Events,
/// plus decrypted `ak.agent.sidecar.exchange.control` Events. Any Event that
/// fails scope resolution, decryption, or closed-schema validation is
/// silently non-echo (fail closed).
///
/// `extra_scope_hints` names Sidecar scopes not yet present in any local
/// record (for example, the active hosted session).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SidecarRefoldOutcome {
    pub cache_entries_changed: usize,
    pub backfill_required: bool,
}

pub(crate) fn refold_sidecar_exchanges_from_history(
    store: &mut crate::state::LocalStateStore,
    controller_principal_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    realm_id: &str,
    extra_scope_hints: &[SidecarExchangeScopeHint],
) -> SidecarRefoldOutcome {
    if authority.principal_id.as_str() != controller_principal_id {
        return SidecarRefoldOutcome::default();
    }
    let realm = realm_id.to_owned();
    let controller = controller_principal_id.to_owned();
    let authority = authority.clone();
    let decrypt_authority = authority.clone();
    let device = device_id.clone();
    refold_sidecar_exchanges_with_decrypt_report(
        store,
        controller_principal_id,
        &authority,
        realm_id,
        extra_scope_hints,
        &move |store_ref, circle_id, envelope_value, event| {
            decrypt_sidecar_scoped_envelope(
                store_ref,
                &realm,
                &controller,
                &decrypt_authority,
                &device,
                circle_id,
                envelope_value,
                event,
            )
        },
    )
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SidecarBackgroundSyncOutcome {
    pub sidecar_views: usize,
    pub recovered_locators: usize,
    pub ingested_events: usize,
    pub cache_entries_changed: usize,
    pub backfill_required: bool,
}

/// Account-scoped Sidecar recovery and Event-truth maintenance.
///
/// This pass intentionally has no route or hosted-session input. It fully
/// paginates the controller's Sidecar list, fully scans every referenced
/// Realm, recovers private locators from accepted structural Events, ingests
/// the union history, refolds exchanges, and retries durable coordinator-close
/// intents from the recovered Sidecar view plus the local MLS snapshot.
pub(crate) async fn sync_sidecar_exchange_background(
    base_url: &str,
    api_token: String,
    controller_principal_id: &str,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    mut state_store: SyncSignal<crate::state::LocalStateStore>,
) -> anyhow::Result<SidecarBackgroundSyncOutcome> {
    let api = crate::transport::auth::authed_api_with_sync(base_url, api_token.clone(), None)?;
    let http = api.sdk_http_client()?;
    let mut sidecar_views = Vec::<arkret_sdk::AgentSidecarView>::new();
    let mut cursor = None::<String>;
    let mut seen_cursors = std::collections::BTreeSet::new();
    loop {
        let page = http
            .agent_sidecar_list(None, cursor.as_deref())
            .await
            .map_err(anyhow::Error::from)?;
        sidecar_views.extend(page.agent_sidecar_views);
        let Some(next_cursor) = page.next_cursor.map(|value| value.to_string()) else {
            break;
        };
        if !seen_cursors.insert(next_cursor.clone()) {
            anyhow::bail!("Sidecar list pagination repeated a cursor");
        }
        cursor = Some(next_cursor);
    }

    let mut views_by_realm =
        std::collections::BTreeMap::<String, Vec<arkret_sdk::AgentSidecarView>>::new();
    for view in sidecar_views {
        view.validate()?;
        if view.sidecar.controller_account_id != *authority {
            anyhow::bail!("Sidecar list returned a view for another controller");
        }
        views_by_realm
            .entry(view.sidecar.realm_id.to_string())
            .or_default()
            .push(view);
    }

    let mut outcome = SidecarBackgroundSyncOutcome::default();
    for (realm_id, realm_views) in views_by_realm {
        outcome.sidecar_views += realm_views.len();
        let backfill = api.event_submitter()?.backfill(&realm_id).await?;
        let accepted_events = backfill.complete_events("Sidecar context recovery")?;
        let locators =
            arkret_sdk::recover_agent_sidecar_context_locators(&realm_views, &accepted_events)?;
        outcome.recovered_locators += locators.len();
        {
            let mut store = state_store.write();
            for view in &realm_views {
                let key = format!(
                    "{SIDECAR_CONTEXT_LOCATOR_PREFIX}:{controller_principal_id}:{}",
                    view.sidecar.id
                );
                store.remove_plain_local_data(&key);
            }
            for locator in &locators {
                let key = format!(
                    "{SIDECAR_CONTEXT_LOCATOR_PREFIX}:{controller_principal_id}:{}",
                    locator.sidecar_id
                );
                store.save_plain_local_data(
                    key,
                    serde_json::json!({
                        "sidecar_id": locator.sidecar_id,
                        "source_context_ref": locator.source_context_ref,
                        "mapping_event_id": locator.mapping_event_id,
                        "version": locator.version,
                    })
                    .to_string(),
                );
            }
        }
        let event_values = accepted_events
            .into_iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()?;
        outcome.ingested_events += crate::sync_engine::ingest_message_projection_events(
            &mut state_store.write(),
            &realm_id,
            &event_values,
        );
        let hints = locators
            .iter()
            .filter_map(|locator| match &locator.source_context_ref {
                arkret_sdk::AgentSidecarContextRef::Strand(context) => {
                    Some(SidecarExchangeScopeHint {
                        source_strand_id: context.strand_id.to_string(),
                        sidecar_id: locator.sidecar_id.clone(),
                    })
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let refold = refold_sidecar_exchanges_from_history(
            &mut state_store.write(),
            controller_principal_id,
            authority,
            device_id,
            &realm_id,
            &hints,
        );
        outcome.cache_entries_changed += refold.cache_entries_changed;
        outcome.backfill_required |= refold.backfill_required;

        let views_by_sidecar = realm_views
            .iter()
            .map(|view| (view.sidecar.id.to_string(), view))
            .collect::<std::collections::BTreeMap<_, _>>();
        let retryable_closes = pending_sidecar_auto_close_intents(
            &state_store.read(),
            controller_principal_id,
            &realm_id,
        )
        .into_iter()
        .filter(|intent| intent.accepted_control_event_id.is_none())
        .collect::<Vec<_>>();
        for intent in retryable_closes {
            let Some(view) = views_by_sidecar.get(intent.sidecar_id.as_str()) else {
                continue;
            };
            let binding = arkret_sdk::SidecarMlsBinding {
                sidecar_id: view.sidecar.id.clone(),
                participant_authority_digest: view.mls_context.participant_authority_digest.clone(),
                control_frontier: view.mls_context.control_frontier.clone(),
            };
            submit_pending_sidecar_auto_close(
                base_url,
                api_token.clone(),
                authority,
                device_id,
                state_store,
                intent,
                binding,
            )
            .await?;
        }
    }
    Ok(outcome)
}

/// Sidecar-scoped envelope decrypt hook. The signed outer Event is required to
/// reconstruct the authenticated header.
/// → plaintext bytes (`None` fails closed to non-echo).
type SidecarEnvelopeDecrypt<'a> = &'a dyn Fn(
    &crate::state::LocalStateStore,
    &str,
    &serde_json::Value,
    &serde_json::Value,
) -> Option<Vec<u8>>;

/// Decrypt-injectable core of [`refold_sidecar_exchanges_from_history`]
/// (tests substitute the MLS decrypt with a passthrough).
#[cfg(test)]
fn refold_sidecar_exchanges_with_decrypt(
    store: &mut crate::state::LocalStateStore,
    controller_principal_id: &str,
    realm_id: &str,
    extra_scope_hints: &[SidecarExchangeScopeHint],
    decrypt: SidecarEnvelopeDecrypt<'_>,
) -> usize {
    let Ok(controller_core_id) = crate::mls_api_helpers::principal_core_id(controller_principal_id)
    else {
        return 0;
    };
    let Ok(station_id) = arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned())
    else {
        return 0;
    };
    let controller_account_id = arkret_sdk::AccountId::new(controller_core_id, station_id);
    refold_sidecar_exchanges_with_decrypt_report(
        store,
        controller_principal_id,
        &controller_account_id,
        realm_id,
        extra_scope_hints,
        decrypt,
    )
    .cache_entries_changed
}

// Invariant assertions: each `expect` message names the check that
// establishes it a few lines earlier. Rewriting them as `?` would add
// error paths no caller can reach.
#[allow(clippy::expect_used)]
fn refold_sidecar_exchanges_with_decrypt_report(
    store: &mut crate::state::LocalStateStore,
    controller_principal_id: &str,
    controller_account_id: &arkret_sdk::AccountId,
    realm_id: &str,
    extra_scope_hints: &[SidecarExchangeScopeHint],
    decrypt: SidecarEnvelopeDecrypt<'_>,
) -> SidecarRefoldOutcome {
    let Ok(controller_core_id) = crate::mls_api_helpers::principal_core_id(controller_principal_id)
    else {
        return SidecarRefoldOutcome::default();
    };
    let mut folded = Vec::new();
    let mut fact_upgrades = Vec::<StoredSidecarExchangeRequestFact>::new();
    let mut auto_close_updates = Vec::<PendingSidecarAutoCloseIntent>::new();
    let mut auto_close_removals = Vec::<String>::new();
    let mut backfill_required = false;
    {
        let store_ref: &crate::state::LocalStateStore = store;
        let state = store_ref.load();
        let mut stored_facts =
            stored_sidecar_exchange_request_facts(store_ref, controller_principal_id);
        // Source Strand id → native Sidecar id. The signed Event scope must
        // name this exact Sidecar; Realm/Circle scope is never substituted.
        let mut scope_hints = std::collections::BTreeMap::<String, arkret_sdk::SidecarId>::new();
        for hint in extra_scope_hints {
            scope_hints.insert(hint.source_strand_id.clone(), hint.sidecar_id.clone());
        }
        for fact in &stored_facts {
            scope_hints.insert(fact.source_strand_id.clone(), fact.sidecar_id.clone());
        }
        for (_, pending) in pending_sidecar_submissions(store_ref, controller_principal_id) {
            scope_hints.insert(pending.source_strand_id.clone(), pending.sidecar_id.clone());
        }
        // No known Sidecar private Strand for this controller: nothing can
        // fold, so skip the (event-scan) work entirely.
        if scope_hints.is_empty() {
            return SidecarRefoldOutcome::default();
        }
        let Some(digest_suite) = store_ref
            .trusted_mls_governance_checkpoint(realm_id)
            .map(|checkpoint| checkpoint.live_digest_suite)
        else {
            return SidecarRefoldOutcome {
                backfill_required: true,
                ..SidecarRefoldOutcome::default()
            };
        };
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
            let arkret_wire::ScopeRef::Sidecar { sidecar_id, .. } = &event.scope_ref else {
                continue;
            };
            let kind = &event.kind;
            let Some(strand_id) = event
                .payload
                .get("strand_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
            else {
                continue;
            };
            let Some(expected_sidecar_id) = scope_hints.get(&strand_id) else {
                continue;
            };
            if sidecar_id != expected_sidecar_id {
                continue;
            }
            let Ok(event_digest) = event.event_digest_with_digest_suite(digest_suite) else {
                continue;
            };
            let Ok(event_value) = serde_json::to_value(&event) else {
                continue;
            };
            if kind == &arkret_sdk::EventKind::MessageCreate {
                // The accepted request Event's complete envelope carries the
                // canonical digest, actor_seq, and top-level HLC. The authoring
                // device may be unable to decrypt its own metadata, so upgrade
                // its durable request fact before the decrypt path.
                if event.actor_id.signing_principal_id() == &controller_core_id
                    && let Some(index) = stored_index_by_request_event_id
                        .get(event.event_id.as_str())
                        .copied()
                    && let Some(envelope_hlc) = event.hlc.clone()
                {
                    let stored = &mut stored_facts[index];
                    if stored.request_event_actor_seq != event.actor_seq
                        || stored.request_event_hlc != envelope_hlc
                        || stored.request_event_digest.as_deref() != Some(event_digest.as_str())
                    {
                        stored.request_event_actor_seq = event.actor_seq;
                        stored.request_event_hlc = envelope_hlc;
                        stored.request_event_digest = Some(event_digest.clone());
                        fact_upgrades.push(stored.clone());
                        upgraded_exchange_keys.insert((
                            stored.source_strand_id.clone(),
                            stored.exchange_id.as_str().to_owned(),
                        ));
                    }
                }
                let Some(encrypted_metadata) = event.payload.get("encrypted_metadata") else {
                    continue;
                };
                let Some(plaintext) = decrypt(
                    store_ref,
                    sidecar_id.as_str(),
                    encrypted_metadata,
                    &event_value,
                ) else {
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
                let Some(actor_principal_id) = event_actor_id(&event) else {
                    continue;
                };
                let exchange_key = (strand_id.clone(), binding.exchange_id.as_str().to_owned());
                match binding.role {
                    arkret_sdk::AgentSidecarExchangeBindingRole::Request => {
                        if event.actor_id.signing_principal_id() != &controller_core_id {
                            continue;
                        }
                        let Some(context) = binding.request_context.clone() else {
                            continue;
                        };
                        let Some(actor_account_id) = event.actor_id.as_account_id().cloned() else {
                            continue;
                        };
                        request_event_ids.insert(event.event_id.to_string());
                        requests.entry(exchange_key).or_default().push(
                            garth::projection::SidecarExchangeRequestFact {
                                event_id: event.event_id.clone(),
                                hlc,
                                actor_account_id,
                                actor_seq: event.actor_seq,
                                event_digest: event_digest.clone(),
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
                                actor_principal_id,
                                binding,
                                refs_after: event_refs_after(&event),
                            },
                        );
                    }
                }
            } else if kind == &arkret_sdk::EventKind::AgentSidecarExchangeControl {
                let Some(encrypted_payload) = event.payload.get("encrypted_payload") else {
                    continue;
                };
                let Some(plaintext) = decrypt(
                    store_ref,
                    sidecar_id.as_str(),
                    encrypted_payload,
                    &event_value,
                ) else {
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
                if event_actor_id(&event).is_none() {
                    continue;
                }
                let Some(actor_account_id) = event.actor_id.as_account_id().cloned() else {
                    continue;
                };
                let exchange_key = (strand_id, control.exchange_id.as_str().to_owned());
                controls.entry(exchange_key).or_default().push(
                    garth::projection::SidecarExchangeControlFact {
                        event_id: event.event_id.clone(),
                        hlc,
                        actor_account_id,
                        actor_seq: event.actor_seq,
                        event_digest,
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
                    stored.source_strand_id.clone(),
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
            let Some(sidecar_id) = scope_hints.get(strand_id) else {
                continue;
            };
            let Ok(exchange_id) = arkret_sdk::AgentSidecarExchangeId::new(exchange_id_raw.clone())
            else {
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
            let cache_key = sidecar_exchange_fold_cache_key(
                controller_core_id.as_str(),
                sidecar_id.as_str(),
                exchange_id_raw,
            );
            let cached_projection = store_ref.load_plain_local_data(&cache_key).and_then(|raw| {
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
                        backfill_required = true;
                        continue;
                    }
                    // An unreadable/invalid cached frontier never blocks the
                    // deterministic refold from local facts.
                    Err(_) => {}
                }
            }
            let scope = garth::projection::SidecarExchangeFoldScope {
                controller_account_id: controller_account_id.clone(),
                sidecar_id: sidecar_id.clone(),
            };
            let fold = garth::projection::fold_sidecar_exchange(
                &scope,
                &exchange_id,
                exchange_requests,
                exchange_agent_facts,
                exchange_controls,
            );
            match fold {
                Ok(Some(projection)) => {
                    let auto_close_key = sidecar_auto_close_intent_key(
                        controller_principal_id,
                        strand_id,
                        exchange_id_raw,
                    );
                    if projection.terminal_event_id.is_some() {
                        auto_close_removals.push(auto_close_key);
                    } else if exchange_agent_facts.iter().any(|fact| {
                        fact.actor_principal_id == projection.coordinator_agent_id
                            && fact.binding.role
                                == arkret_sdk::AgentSidecarExchangeBindingRole::UserFacingResponse
                            && fact.binding.completes_exchange == Some(true)
                            && fact.binding.coordinator_assignment_event_id.as_ref()
                                == Some(&projection.coordinator_assignment_event_id)
                            && projection
                                .user_facing_response_event_ids
                                .contains(&fact.event_id)
                    }) {
                        let mut basis_event_ids = projection.folded_frontier.event_ids.clone();
                        basis_event_ids.sort_by(|left, right| {
                            left.as_str().as_bytes().cmp(right.as_str().as_bytes())
                        });
                        let control = arkret_sdk::AgentSidecarExchangeControl {
                            schema: arkret_sdk::AgentSidecarExchangeControlSchema::V1,
                            exchange_id: projection.exchange_id.clone(),
                            request_event_id: projection.private_request_event_id.clone(),
                            basis_event_ids,
                            action: arkret_sdk::AgentSidecarExchangeControlAction::Close,
                            response_event_ids: Some(
                                projection.user_facing_response_event_ids.clone(),
                            ),
                            failure_reason_code: None,
                            expected_coordinator_agent_id: None,
                            coordinator_agent_id: None,
                        };
                        if control.validate().is_ok() {
                            let existing = store_ref
                                .load_plain_local_data(&auto_close_key)
                                .and_then(|raw| {
                                    serde_json::from_str::<PendingSidecarAutoCloseIntent>(&raw).ok()
                                });
                            // Once a close submit is accepted, keep waiting for
                            // that exact Event to arrive through history. A
                            // newer local fold must not clear the dedupe marker
                            // and author a second control.
                            if existing
                                .as_ref()
                                .and_then(|intent| intent.accepted_control_event_id.as_ref())
                                .is_none()
                            {
                                auto_close_updates.push(PendingSidecarAutoCloseIntent {
                                    controller_account_id: controller_account_id.clone(),
                                    sidecar_id: sidecar_id.clone(),
                                    source_strand_id: strand_id.clone(),
                                    source_realm_id: realm_id.to_owned(),
                                    exchange_id: projection.exchange_id.clone(),
                                    control,
                                    accepted_control_event_id: None,
                                    failed_attempts: existing
                                        .map(|intent| intent.failed_attempts)
                                        .unwrap_or_default(),
                                });
                            }
                        }
                    }
                    folded.push(projection);
                }
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
    for key in auto_close_removals {
        store.remove_plain_local_data(&key);
    }
    for intent in auto_close_updates {
        if let Err(error) = save_pending_sidecar_auto_close_intent(store, &intent) {
            tracing::warn!(%error, "Sidecar auto-close intent persistence failed");
        }
    }
    let mut changed = 0;
    for projection in folded {
        match cache_sidecar_exchange_projection(store, controller_account_id, &projection) {
            Ok(true) => changed += 1,
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(%error, "Sidecar exchange fold cache write failed");
            }
        }
    }
    SidecarRefoldOutcome {
        cache_entries_changed: changed,
        backfill_required,
    }
}

pub fn cached_sidecar_display_mode(
    store: &crate::state::LocalStateStore,
    session: &HostedSidecarState,
) -> Option<arkret_sdk::AgentSidecarDisplayMode> {
    let realm_id = arkret_sdk::RealmId::new(session.source_realm_id.clone()).ok()?;
    let strand_id = arkret_sdk::StrandId::new(session.source_strand_id.clone()).ok()?;
    let view_state = store
        .sidecar_view_state(&session.controller_account_id, &realm_id, &strand_id)
        .or_else(|| {
            let namespace_key =
                crate::account_data::account_data_namespace_key(&session.controller_account_id)
                    .ok()?;
            let key = arkret_sdk::agent_sidecar_view_state_account_data_key(
                &namespace_key,
                &session.controller_account_id,
                &realm_id,
                &strand_id,
            )
            .ok()?;
            store.load_plain_local_data(&key).and_then(|raw| {
                serde_json::from_str::<arkret_sdk::AgentSidecarViewState>(&raw).ok()
            })
        })?;
    (view_state.controller_account_id == session.controller_account_id
        && view_state.sidecar_id == session.sidecar_id
        && view_state.context_ref.realm_id.as_str() == session.source_realm_id
        && view_state.context_ref.strand_id.as_str() == session.source_strand_id)
        .then_some(view_state.display_mode)
}

#[derive(Clone, Copy)]
pub struct HostedSidecarStateContext(pub Signal<Option<HostedSidecarState>>);

#[component]
pub fn HostedSidecarContextBar(base_url: String, api_token: String, device_id: String) -> Element {
    let _ = device_id;
    let mut hosted_state = use_context::<HostedSidecarStateContext>().0;
    let session_context = crate::app::SessionContext::get();
    let mut state_store = session_context.state_store;
    let Some(active_account) = session_context.active_account.read().clone() else {
        return rsx! {};
    };
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
    let merged_authority = active_account.authority.clone();
    let merged_did = active_account.did().clone();
    let merged_device = active_account.device_id.clone();
    let sidecar_base = base_url;
    let sidecar_token = api_token;
    let sidecar_authority = active_account.authority.clone();
    let sidecar_did = active_account.did().clone();
    let sidecar_device = active_account.device_id.clone();
    // Fold-cache evidence deliberately does NOT ride on this strip.
    //
    // A `data-*` attribute here is ordinary shared DOM: it is serialized into
    // the document, readable by anything else running on the page, captured by
    // DOM snapshots and screenshots, and present only while this strand's strip
    // happens to be rendered. The evidence surface is
    // `__inkson_sidecar_fold_evidence_v1` instead — read-only, controller-only,
    // reachable only by an explicit call, covering the whole Realm rather than
    // the visible strand, and compiled out of production builds. See
    // `sidecar_fold_evidence`.
    rsx! {
        div {
            class: "sidecar-context-strip",
            "data-testid": "sidecar-context-strip",
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
                            crate::views::chat::capture_chat_feed_scroll_position(
                                &current.source_realm_id,
                                &current.source_strand_id,
                            );
                            current.display_mode = arkret_sdk::AgentSidecarDisplayMode::ContextMerged;
                            push_sidecar_display_mode(
                                &mut state_store.write(),
                                merged_base.clone(),
                                merged_token.clone(),
                                merged_authority.clone(),
                                merged_did.clone(),
                                merged_device.clone(),
                                &current,
                            );
                            let realm_id = current.source_realm_id.clone();
                            let strand_id = current.source_strand_id.clone();
                            hosted_state.set(Some(current));
                            crate::views::chat::restore_chat_feed_scroll_position(
                                &realm_id,
                                &strand_id,
                            );
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
                            crate::views::chat::capture_chat_feed_scroll_position(
                                &current.source_realm_id,
                                &current.source_strand_id,
                            );
                            current.display_mode = arkret_sdk::AgentSidecarDisplayMode::SidecarOnly;
                            push_sidecar_display_mode(
                                &mut state_store.write(),
                                sidecar_base.clone(),
                                sidecar_token.clone(),
                                sidecar_authority.clone(),
                                sidecar_did.clone(),
                                sidecar_device.clone(),
                                &current,
                            );
                            let realm_id = current.source_realm_id.clone();
                            let strand_id = current.source_strand_id.clone();
                            hosted_state.set(Some(current));
                            crate::views::chat::restore_chat_feed_scroll_position(
                                &realm_id,
                                &strand_id,
                            );
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
    authority: arkret_sdk::AccountId,
    controller_did: arkret_sdk::Did,
    device_id: arkret_sdk::DeviceId,
    session: &HostedSidecarState,
) {
    let context_ref = match (
        arkret_sdk::RealmId::new(session.source_realm_id.clone()),
        arkret_sdk::StrandId::new(session.source_strand_id.clone()),
        device_id,
    ) {
        (Ok(realm_id), Ok(strand_id), origin_device_id) => (realm_id, strand_id, origin_device_id),
        _ => {
            tracing::warn!("Sidecar view-state contains an invalid typed identifier");
            return;
        }
    };
    let updated_hlc = match crate::signing_stamp::issue_account_data_hlc(
        controller_did.as_str(),
        context_ref.2.as_str(),
    ) {
        Ok(hlc) => hlc,
        Err(error) => {
            tracing::warn!(%error, "Sidecar view-state HLC allocation failed");
            return;
        }
    };
    let view_state = arkret_sdk::AgentSidecarViewState {
        schema: arkret_sdk::AgentSidecarViewStateSchema::V1,
        controller_account_id: authority.clone(),
        sidecar_id: session.sidecar_id.clone(),
        context_ref: arkret_sdk::AgentSidecarStrandContextRef {
            realm_id: context_ref.0,
            strand_id: context_ref.1,
        },
        display_mode: session.display_mode,
        pinned: None,
        collapsed: None,
        updated_hlc,
        origin_device_id: context_ref.2,
    };
    let namespace_key = match crate::account_data::account_data_namespace_key(&authority) {
        Ok(key) => key,
        Err(error) => {
            tracing::warn!(%error, "Sidecar view-state namespace derivation failed");
            return;
        }
    };
    let account_data_key = match view_state.account_data_key(&namespace_key) {
        Ok(key) => key,
        Err(error) => {
            tracing::warn!(%error, "Sidecar view-state account-data key derivation failed");
            return;
        }
    };
    if let Err(error) = cache_sidecar_view_state(store, &authority, &view_state) {
        tracing::warn!(%error, "Sidecar view-state local cache failed");
    }
    let plaintext = match serde_json::to_value(&view_state) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "Sidecar view-state serialization failed");
            return;
        }
    };
    let body = match crate::account_data::encrypt_account_data_value(
        &authority,
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
                crate::transport::account::update_account_data_with_conditional_merge(
                    &submitter,
                    &account_data_key,
                    |snapshot| {
                        let Some(current) = snapshot.entry.as_ref() else {
                            return Ok(
                                crate::transport::account::AccountDataMergeDecision::Replace(
                                    body.clone(),
                                ),
                            );
                        };
                        let current_plaintext = crate::account_data::decrypt_account_data_entry(
                            &authority,
                            &account_data_key,
                            current,
                        )?;
                        match sidecar_view_state_merge_decision(
                            Some(&current_plaintext),
                            &namespace_key,
                            &account_data_key,
                            &view_state,
                        )? {
                            SidecarViewStateMergeDecision::UseCandidate => Ok(
                                crate::transport::account::AccountDataMergeDecision::Replace(
                                    body.clone(),
                                ),
                            ),
                            SidecarViewStateMergeDecision::UseCurrent => Ok(
                                crate::transport::account::AccountDataMergeDecision::KeepCurrent,
                            ),
                        }
                    },
                )
                .await
            },
        )
        .await
        {
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(error = %error.display_diagnostic(), "Sidecar view-state sync failed")
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller_account() -> arkret_sdk::AccountId {
        crate::test_support::authority("did:web:alice.example")
    }

    fn account_data_namespace_key() -> [u8; 32] {
        [7; 32]
    }

    fn session(
        pending: Vec<arkret_sdk::PendingSidecarAccessReconciliationItem>,
    ) -> HostedSidecarState {
        HostedSidecarState {
            trace_id: "019f0000-0000-7000-8000-000000000001".to_owned(),
            controller_account_id: controller_account(),
            addressed_agent_ids: vec!["ak:did_core:web:agents.example:assistant".to_owned()],
            addressed_agent_label: "Assistant".to_owned(),
            source_realm_id: "ak:realm:AUqzNZlfuL-7z087TbZhKOdYyKUNPAa2o_neyoFRh3o2".to_owned(),
            source_strand_id: "ak:strand:AUvEs_-d1tc81yDszBZAVWapgIr3Gs6ofbmtZSLQNejL".to_owned(),
            sidecar_id: arkret_sdk::SidecarId::new(
                "ak:sidecar:Abbk-ALq9nZszIh8qJC26XasNIx9TYjU5-BzXWyqwDVx".to_owned(),
            )
            .unwrap(),
            access_readiness: if pending.is_empty() {
                arkret_sdk::AgentSidecarAccessReadiness::Ready
            } else {
                arkret_sdk::AgentSidecarAccessReadiness::KeyMaterialPending
            },
            pending_access_reconciliations: pending,
            mls_context: arkret_sdk::AgentSidecarMlsContext {
                participant_authority_digest: arkret_sdk::Hash::new(format!(
                    "sha256:{}",
                    "1".repeat(64)
                ))
                .unwrap(),
                control_frontier: vec![
                    arkret_sdk::NonEmptyString::new(
                        "ak:event:AVeCvdcuh1hDJWwYlZJb_1yRzWQwN1-pXxgZYTyd7BGT",
                    )
                    .unwrap(),
                ],
                mls_group_id: None,
                epoch: None,
                genesis_event_ref: None,
                current_controller_device_ready: false,
            },
            native_mls_ready: true,
            display_mode: arkret_sdk::AgentSidecarDisplayMode::ContextMerged,
            migrated_draft: String::new(),
            opened_at: chrono::Utc::now(),
        }
    }

    fn view_state(
        session: &HostedSidecarState,
        display_mode: arkret_sdk::AgentSidecarDisplayMode,
        hlc: &str,
        device: &str,
    ) -> arkret_sdk::AgentSidecarViewState {
        arkret_sdk::AgentSidecarViewState {
            schema: arkret_sdk::AgentSidecarViewStateSchema::V1,
            controller_account_id: controller_account(),
            sidecar_id: session.sidecar_id.clone(),
            context_ref: arkret_sdk::AgentSidecarStrandContextRef {
                realm_id: arkret_sdk::RealmId::new(session.source_realm_id.clone()).unwrap(),
                strand_id: arkret_sdk::StrandId::new(session.source_strand_id.clone()).unwrap(),
            },
            display_mode,
            pinned: None,
            collapsed: None,
            updated_hlc: arkret_sdk::Hlc::new(hlc).unwrap(),
            origin_device_id: arkret_sdk::DeviceId::new(device).unwrap(),
        }
    }

    fn merge_decision(
        current: &arkret_sdk::AgentSidecarViewState,
        candidate: &arkret_sdk::AgentSidecarViewState,
    ) -> anyhow::Result<SidecarViewStateMergeDecision> {
        sidecar_view_state_merge_decision(
            Some(&serde_json::to_value(current).unwrap()),
            &account_data_namespace_key(),
            &candidate
                .account_data_key(&account_data_namespace_key())
                .unwrap(),
            candidate,
        )
    }

    #[test]
    fn pending_reconciliation_is_not_ready() {
        let session = session(vec![arkret_sdk::PendingSidecarAccessReconciliationItem {
            agent_id: crate::mls_api_helpers::principal_core_id("did:web:agents.example:assistant")
                .unwrap(),
            provisioning_phase: arkret_sdk::PendingSidecarAccessReconciliationStage::MlsWelcome,
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
            binding.participant_authority_digest,
            session.mls_context.participant_authority_digest
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
        assert!(!session.matches_route(
            &session.source_realm_id,
            "ak:strand:AVeCvdcuh1hDJWwYlZJb_1yRzWQwN1-pXxgZYTyd7BGT"
        ));
    }

    #[test]
    fn sidecar_view_state_cache_is_lww_and_context_scoped() {
        let account = controller_account();
        let path = std::env::temp_dir().join(format!(
            "inkson-sidecar-view-state-{}.json",
            crate::operation::uuid_v7()
        ));
        let mut store = crate::state::LocalStateStore::with_path(path);
        let session = session(Vec::new());
        let newer = view_state(
            &session,
            arkret_sdk::AgentSidecarDisplayMode::SidecarOnly,
            "01970e589d21-0002-a13f9c2e",
            "ak:device:01964137-0000-7000-8000-000000000001",
        );
        let older = view_state(
            &session,
            arkret_sdk::AgentSidecarDisplayMode::ContextMerged,
            "01970e589d21-0001-a13f9c2e",
            "ak:device:01964137-0000-7000-8000-000000000002",
        );

        assert_eq!(
            merge_decision(&newer, &older).unwrap(),
            SidecarViewStateMergeDecision::UseCurrent
        );
        assert_eq!(
            merge_decision(&older, &newer).unwrap(),
            SidecarViewStateMergeDecision::UseCandidate
        );

        assert!(
            cache_sidecar_view_state_with_namespace(
                &mut store,
                &account,
                &account_data_namespace_key(),
                &newer,
            )
            .unwrap()
        );
        assert!(
            !cache_sidecar_view_state_with_namespace(
                &mut store,
                &account,
                &account_data_namespace_key(),
                &older,
            )
            .unwrap()
        );
        assert_eq!(
            cached_sidecar_display_mode(&store, &session),
            Some(arkret_sdk::AgentSidecarDisplayMode::SidecarOnly)
        );
    }

    #[test]
    fn sidecar_view_state_lww_uses_device_tie_break_and_is_idempotent() {
        let session = session(Vec::new());
        let state = |device| {
            view_state(
                &session,
                arkret_sdk::AgentSidecarDisplayMode::ContextMerged,
                "01970e589d21-0001-a13f9c2e",
                device,
            )
        };
        let lower = state("ak:device:01964137-0000-7000-8000-000000000001");
        let higher = state("ak:device:01964137-0000-7000-8000-000000000002");

        assert_eq!(
            merge_decision(&lower, &higher).unwrap(),
            SidecarViewStateMergeDecision::UseCandidate
        );
        assert_eq!(
            merge_decision(&higher, &lower).unwrap(),
            SidecarViewStateMergeDecision::UseCurrent
        );
        assert_eq!(
            merge_decision(&lower, &lower).unwrap(),
            SidecarViewStateMergeDecision::UseCurrent
        );

        let mut divergent = lower.clone();
        divergent.display_mode = arkret_sdk::AgentSidecarDisplayMode::SidecarOnly;
        assert!(merge_decision(&lower, &divergent).is_err());

        let mut wrong_sidecar = higher;
        wrong_sidecar.sidecar_id = arkret_sdk::SidecarId::new(
            "ak:sidecar:AWk_ywNSTc6WhrGkRSaK84HThnFXKBAy3vQ_RLJZ4kCY".to_owned(),
        )
        .unwrap();
        assert!(merge_decision(&lower, &wrong_sidecar).is_err());

        let dir = tempfile::tempdir().unwrap();
        let mut store = crate::state::LocalStateStore::with_path(dir.path().join("state.json"));
        assert!(
            cache_sidecar_view_state_with_namespace(
                &mut store,
                &controller_account(),
                &account_data_namespace_key(),
                &lower,
            )
            .unwrap()
        );
        assert!(
            cache_sidecar_view_state_with_namespace(
                &mut store,
                &controller_account(),
                &account_data_namespace_key(),
                &divergent,
            )
            .is_err()
        );
        assert!(
            cache_sidecar_view_state_with_namespace(
                &mut store,
                &controller_account(),
                &account_data_namespace_key(),
                &wrong_sidecar,
            )
            .is_err()
        );
        assert_eq!(
            store.sidecar_view_state(
                &lower.controller_account_id,
                &lower.context_ref.realm_id,
                &lower.context_ref.strand_id,
            ),
            Some(lower)
        );
    }

    #[test]
    fn sidecar_view_state_merge_rejects_malformed_remote_plaintext() {
        let session = session(Vec::new());
        let candidate = view_state(
            &session,
            arkret_sdk::AgentSidecarDisplayMode::ContextMerged,
            "01970e589d21-0001-a13f9c2e",
            "ak:device:01964137-0000-7000-8000-000000000001",
        );

        assert!(
            sidecar_view_state_merge_decision(
                Some(&serde_json::json!({"updated_hlc": "not-a-complete-view-state"})),
                &account_data_namespace_key(),
                &candidate
                    .account_data_key(&account_data_namespace_key())
                    .unwrap(),
                &candidate,
            )
            .is_err()
        );
    }

    /// The evidence surface must answer for exactly one controller and one
    /// source Realm, must carry a digest that is stable across two independently
    /// built stores holding the same projection, and must not leak a projection
    /// belonging to a different Realm.
    #[cfg(feature = "wasm-localstorage-secrets-test")]
    #[test]
    fn fold_evidence_is_controller_and_realm_scoped_with_a_stable_digest() {
        let account = controller_account();
        let realm = "ak:realm:AVMbYk6SunkGxvNL1uT9AigkdS6j5xko3u7tklJAzK1-";
        let other_realm = "ak:realm:AYJtJTaob5e3AuBrnCd-oA9WPc3ZrZyc-0GC98V_h0Qh";
        let projection = |realm_id: &str, exchange: &str| {
            let coordinator =
                arkret_sdk::DidCoreId::new("ak:did_core:web:agents.example:assistant").unwrap();
            let request_event =
                arkret_sdk::EventId::new("ak:event:AZWFWsK0mBAgeYWLiO1LU1RYz_ZXWHWYNdJDwfzCxKCG")
                    .unwrap();
            arkret_sdk::AgentSidecarExchangeProjection {
                schema: arkret_sdk::AgentSidecarExchangeProjectionSchema::V1,
                controller_account_id: account.clone(),
                sidecar_id: arkret_sdk::SidecarId::new(
                    "ak:sidecar:AWea2MtI5dOI1LSRyI266_gQVrWUd0po0dxZiJNsH8kN",
                )
                .unwrap(),
                exchange_id: arkret_sdk::AgentSidecarExchangeId::new(exchange).unwrap(),
                source_track_ref: arkret_sdk::AgentSidecarSourceTrackRef {
                    realm_id: arkret_sdk::RealmId::new(realm_id).unwrap(),
                    strand_id: arkret_sdk::StrandId::new(
                        "ak:strand:AUvEs_-d1tc81yDszBZAVWapgIr3Gs6ofbmtZSLQNejL",
                    )
                    .unwrap(),
                    track_name: "discussion".to_owned(),
                },
                source_event_id: None,
                source_hlc: arkret_sdk::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
                client_order_key: arkret_sdk::NonEmptyString::new("device-1-1").unwrap(),
                addressed_agent_ids: vec![coordinator.clone()],
                coordinator_agent_id: coordinator,
                coordinator_assignment_event_id: request_event.clone(),
                participating_agent_ids: Vec::new(),
                private_request_event_id: request_event.clone(),
                user_facing_response_event_ids: Vec::new(),
                status: arkret_sdk::AgentSidecarExchangeStatus::Delivered,
                failure_reason_code: None,
                terminal_event_id: None,
                folded_frontier: arkret_sdk::AgentSidecarExchangeFoldedFrontier {
                    event_ids: vec![request_event.clone()],
                    event_set_digest: arkret_sdk::agent_sidecar_exchange_event_set_digest(&[
                        request_event,
                    ])
                    .unwrap(),
                    max_hlc: arkret_sdk::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
                },
            }
        };

        let mut device_one = exchange_test_store("fold-evidence-one");
        cache_sidecar_exchange_projection(
            &mut device_one,
            &account,
            &projection(realm, "exchange-01964137000000000008"),
        )
        .unwrap();
        // A second Realm's exchange lives in the same cache and must not appear
        // in this Realm's evidence.
        cache_sidecar_exchange_projection(
            &mut device_one,
            &account,
            &projection(other_realm, "exchange-01964137000000000009"),
        )
        .unwrap();

        let evidence = sidecar_fold_evidence(&device_one, &account, realm).unwrap();
        assert_eq!(evidence.schema, SIDECAR_FOLD_EVIDENCE_SCHEMA);
        assert_eq!(evidence.controller_account_id, account.clone());
        assert_eq!(evidence.source_realm_id, realm);
        assert_eq!(evidence.exchanges.len(), 1);
        assert_eq!(
            evidence.exchanges[0].exchange_id.as_str(),
            "exchange-01964137000000000008"
        );
        assert!(
            evidence.exchanges[0]
                .projection_digest
                .as_str()
                .starts_with("sha256:")
        );

        // A different account's evidence request must not read this
        // controller's cache.
        let foreign_account = arkret_sdk::AccountId::new(
            crate::mls_api_helpers::principal_core_id("did:web:mallory.example").unwrap(),
            account.station_id.clone(),
        );
        let foreign = sidecar_fold_evidence(&device_one, &foreign_account, realm).unwrap();
        assert!(foreign.exchanges.is_empty());

        // Two devices that folded the same history serialize to the same bytes.
        let mut device_two = exchange_test_store("fold-evidence-two");
        cache_sidecar_exchange_projection(
            &mut device_two,
            &account,
            &projection(realm, "exchange-01964137000000000008"),
        )
        .unwrap();
        assert_eq!(
            sidecar_fold_evidence_canonical_json(&device_two, &account, realm).unwrap(),
            sidecar_fold_evidence_canonical_json(&device_one, &account, realm).unwrap(),
        );
    }

    const EXCHANGE_ACCOUNT: &str = "ak:did_core:web:alice.example";
    const EXCHANGE_AGENT: &str = "did:web:agents.example:assistant";
    const EXCHANGE_RESPONSE_EVENT: &str = "ak:event:AWgrDMnttudmVRcIZ3C76X4HW8sfi2eTKwkSUZDxwbbK";

    fn exchange_test_store(label: &str) -> crate::state::LocalStateStore {
        let path = std::env::temp_dir().join(format!(
            "inkson-sidecar-{label}-{}.json",
            crate::operation::uuid_v7()
        ));
        let mut store = crate::state::LocalStateStore::with_path(path);
        let realm_id = "ak:realm:AUqzNZlfuL-7z087TbZhKOdYyKUNPAa2o_neyoFRh3o2";
        crate::mls::governance_proof::seed_test_governance_result(
            &mut store,
            realm_id,
            None,
            arkret_sdk::base64url_encode(realm_id.as_bytes()),
            0,
            0,
        );
        store
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
            addressed_agent_ids: vec![
                crate::mls_api_helpers::principal_core_id(EXCHANGE_AGENT).unwrap(),
            ],
            completion_policy: arkret_sdk::AgentSidecarExchangeCompletionPolicy::Coordinator,
            coordinator_agent_id: None,
            source_event_id: None,
        }
    }

    fn exchange_pending_submission(session: &HostedSidecarState) -> PendingSidecarSubmission {
        PendingSidecarSubmission {
            controller_account_id: controller_account(),
            sidecar_id: session.sidecar_id.clone(),
            source_strand_id: session.source_strand_id.clone(),
            exchange_id: arkret_sdk::AgentSidecarExchangeId::new("exchange-01964137000000000008")
                .unwrap(),
            request_context: exchange_request_context(session),
            message_id: "msg:019f0000-0000-7000-8000-0000000000aa".to_owned(),
            local_operation_id: "op:019f0000-0000-7000-8000-0000000000ab".to_owned(),
        }
    }

    fn accepted_request_envelope(
        session: &HostedSidecarState,
        pending: &PendingSidecarSubmission,
    ) -> arkret_sdk::Event {
        let binding = arkret_sdk::AgentSidecarEventExchangeBinding::request(
            pending.exchange_id.clone(),
            pending.request_context.clone(),
        )
        .unwrap();
        let mut metadata = arkret_sdk::MessageMetadata::default();
        metadata.set_sidecar_exchange_binding(&binding).unwrap();
        arkret_wire::test_support::raw_event(
            arkret_sdk::EventKind::MessageCreate.as_str(),
            arkret_sdk::ScopeRef::Sidecar {
                realm_id: arkret_sdk::RealmId::new(session.source_realm_id.clone()).unwrap(),
                sidecar_id: session.sidecar_id.clone(),
            },
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            7,
            arkret_sdk::Hlc::new("01970e589d21-0005-a13f9c2e").unwrap(),
            serde_json::json!({
                "strand_id": session.source_strand_id.clone(),
                "track_name": "discussion",
                "encrypted_metadata": serde_json::to_value(&metadata).unwrap(),
            }),
        )
        .unwrap()
    }

    fn append_accepted_request_envelope(
        store: &mut crate::state::LocalStateStore,
        event: &arkret_sdk::Event,
    ) {
        store.append_raw_operation(
            event.event_id.to_string(),
            Some(event.realm_id.to_string()),
            serde_json::to_value(event).unwrap(),
        );
    }

    fn passthrough_sidecar_envelope(
        _: &crate::state::LocalStateStore,
        _: &str,
        value: &serde_json::Value,
        _: &serde_json::Value,
    ) -> Option<Vec<u8>> {
        serde_json::to_vec(value).ok()
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

        // The record is a client-local plain_local_data entry, never an
        // account-data type, and never enters the fold cache.
        assert!(
            store
                .plain_local_data_keys()
                .iter()
                .any(|key| { key.starts_with("ak.local.sidecar_pending_submission.v1:") })
        );
        assert!(
            cached_sidecar_exchange_projections(
                &store,
                &controller_account(),
                session.source_realm_id.as_str()
            )
            .is_empty()
        );

        // A retry of the same intent resolves the SAME exchange_id.
        let reloaded = load_pending_sidecar_submission(
            &store,
            EXCHANGE_ACCOUNT,
            &session.source_strand_id,
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
                &session.source_strand_id,
                &other_intent,
            )
            .is_none()
        );

        remove_pending_sidecar_submission(
            &mut store,
            EXCHANGE_ACCOUNT,
            &session.source_strand_id,
            &intent,
        );
        assert!(pending_sidecar_submissions(&store, EXCHANGE_ACCOUNT).is_empty());
    }

    #[test]
    fn accepted_request_waits_for_canonical_envelope_then_folds_to_delivered() {
        let mut store = exchange_test_store("accepted");
        let session = session(Vec::new());
        let pending = exchange_pending_submission(&session);
        let request = accepted_request_envelope(&session, &pending);
        let request_event_id = request.event_id.clone();

        record_accepted_sidecar_exchange_request(&mut store, &pending, request_event_id.as_str())
            .unwrap();
        assert!(
            cached_sidecar_exchange_projections(
                &store,
                &controller_account(),
                session.source_realm_id.as_str(),
            )
            .is_empty(),
            "an Event id alone is never used as a digest stand-in"
        );
        append_accepted_request_envelope(&mut store, &request);
        assert_eq!(
            refold_sidecar_exchanges_with_decrypt(
                &mut store,
                EXCHANGE_ACCOUNT,
                &session.source_realm_id,
                &[],
                &passthrough_sidecar_envelope,
            ),
            1
        );

        let cached = cached_sidecar_exchange_projections(
            &store,
            &controller_account(),
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
            request_event_id.as_str()
        );
        assert_eq!(
            projection.coordinator_agent_id.as_str(),
            crate::mls_api_helpers::principal_core_id(EXCHANGE_AGENT)
                .unwrap()
                .as_str(),
            "single addressed Agent is the implied coordinator"
        );
        assert!(projection.user_facing_response_event_ids.is_empty());
        // Purely local storage: no account-data-shaped (`ak.agent.*`) key
        // anywhere — only the client-local fold cache / fact records.
        assert!(
            store
                .plain_local_data_keys()
                .iter()
                .all(|key| !key.starts_with("ak.agent."))
        );
        // The fold cache replaces wholesale and is idempotent.
        assert!(
            !cache_sidecar_exchange_projection(&mut store, &controller_account(), projection)
                .unwrap()
        );
        // Controller binding still fails closed.
        assert!(
            cache_sidecar_exchange_projection(
                &mut store,
                &arkret_sdk::AccountId::new(
                    crate::mls_api_helpers::principal_core_id("did:web:bob.example").unwrap(),
                    controller_account().station_id,
                ),
                projection,
            )
            .is_err()
        );
    }

    #[test]
    fn received_user_facing_response_folds_to_responding_idempotently() {
        let mut store = exchange_test_store("respond");
        let session = session(Vec::new());
        let pending = exchange_pending_submission(&session);
        let request = accepted_request_envelope(&session, &pending);
        let request_event_id = request.event_id.clone();
        record_accepted_sidecar_exchange_request(&mut store, &pending, request_event_id.as_str())
            .unwrap();
        append_accepted_request_envelope(&mut store, &request);

        // Craft the Agent-authored user_facing_response Event; the fake
        // decrypt below returns the mounted metadata value as plaintext.
        let binding = arkret_sdk::AgentSidecarEventExchangeBinding::user_facing_response(
            pending.exchange_id.clone(),
            request_event_id.clone(),
        )
        .unwrap()
        .with_completion(request_event_id.clone())
        .unwrap();
        let mut metadata = arkret_sdk::MessageMetadata::default();
        metadata.set_sidecar_exchange_binding(&binding).unwrap();
        let mut event = arkret_wire::test_support::raw_event(
            arkret_sdk::EventKind::MessageCreate.as_str(),
            arkret_sdk::ScopeRef::Sidecar {
                realm_id: arkret_sdk::RealmId::new(session.source_realm_id.clone()).unwrap(),
                sidecar_id: session.sidecar_id.clone(),
            },
            crate::mls_api_helpers::principal_core_id(EXCHANGE_AGENT).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            1,
            arkret_sdk::Hlc::new("01970e589d21-0002-a13f9c2e").unwrap(),
            serde_json::json!({
                "strand_id": session.source_strand_id.clone(),
                "track_name": "discussion",
                "encrypted_metadata": serde_json::to_value(&metadata).unwrap(),
            }),
        )
        .unwrap();
        event.refs = vec![arkret_sdk::EventRef::new(
            request_event_id.as_str(),
            "after",
        )];
        event
            .refresh_content_bound_identity_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
            .unwrap();
        let response_event_id = event.event_id.clone();
        let event_digest = arkret_sdk::Hash::new(
            event
                .event_digest_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        event.proofs.push(
            arkret_sdk::ProducerEventProof {
                kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: arkret_sdk::DidUrl::new(format!(
                    "{EXCHANGE_AGENT}#ak:device:01964137-0000-7000-8000-000000000002"
                ))
                .unwrap(),
                event_digest,
                signer_resolution_evidence_ref: None,
                created_at: event.created_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "fixture..signature".to_owned(),
            }
            .into(),
        );
        store.append_raw_operation(
            response_event_id.to_string(),
            Some(session.source_realm_id.clone()),
            serde_json::to_value(&event).unwrap(),
        );

        let changed = refold_sidecar_exchanges_with_decrypt(
            &mut store,
            EXCHANGE_ACCOUNT,
            &session.source_realm_id,
            &[],
            &passthrough_sidecar_envelope,
        );
        assert_eq!(changed, 1);

        let cached = cached_sidecar_exchange_projections(
            &store,
            &controller_account(),
            session.source_realm_id.as_str(),
        );
        assert_eq!(cached.len(), 1);
        assert_eq!(
            cached[0].status,
            arkret_sdk::AgentSidecarExchangeStatus::Responding
        );
        let close_intents =
            pending_sidecar_auto_close_intents(&store, EXCHANGE_ACCOUNT, &session.source_realm_id);
        assert_eq!(close_intents.len(), 1);
        assert_eq!(
            close_intents[0].control.action,
            arkret_sdk::AgentSidecarExchangeControlAction::Close
        );
        assert_eq!(
            close_intents[0].control.response_event_ids.as_deref(),
            Some(&[response_event_id.clone()][..])
        );
        assert_eq!(
            close_intents[0].control.basis_event_ids,
            vec![response_event_id.clone()]
        );
        assert!(
            close_intents[0].accepted_control_event_id.is_none(),
            "local intent is retry metadata, never durable close truth"
        );
        assert_eq!(
            cached[0]
                .user_facing_response_event_ids
                .iter()
                .map(|event_id| event_id.as_str().to_owned())
                .collect::<Vec<_>>(),
            vec![response_event_id.to_string()]
        );
        assert_eq!(
            cached[0]
                .participating_agent_ids
                .iter()
                .map(|did| did.as_str().to_owned())
                .collect::<Vec<_>>(),
            vec![
                crate::mls_api_helpers::principal_core_id(EXCHANGE_AGENT)
                    .unwrap()
                    .to_string(),
            ]
        );

        // Re-running the fold over the same history is idempotent: the
        // deterministic result matches the cache, so nothing changes.
        let unchanged = refold_sidecar_exchanges_with_decrypt(
            &mut store,
            EXCHANGE_ACCOUNT,
            &session.source_realm_id,
            &[],
            &passthrough_sidecar_envelope,
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
        let request = accepted_request_envelope(&session, &pending);
        let request_event_id = request.event_id.clone();
        record_accepted_sidecar_exchange_request(&mut store, &pending, request_event_id.as_str())
            .unwrap();
        append_accepted_request_envelope(&mut store, &request);
        assert_eq!(
            refold_sidecar_exchanges_with_decrypt(
                &mut store,
                EXCHANGE_ACCOUNT,
                &session.source_realm_id,
                &[],
                &passthrough_sidecar_envelope,
            ),
            1
        );

        let binding = arkret_sdk::AgentSidecarEventExchangeBinding::user_facing_response(
            pending.exchange_id.clone(),
            request_event_id.clone(),
        )
        .unwrap();
        let mut metadata = arkret_sdk::MessageMetadata::default();
        metadata.set_sidecar_exchange_binding(&binding).unwrap();
        let mut event = arkret_wire::test_support::raw_event(
            arkret_sdk::EventKind::MessageCreate.as_str(),
            arkret_sdk::ScopeRef::Circle {
                realm_id: arkret_sdk::RealmId::new(session.source_realm_id.clone()).unwrap(),
                circle_id: arkret_sdk::CircleId::new(
                    "ak:circle:AW3knCMRmVvldfa_CEbYb97U_w_GbmmZ2UXnDdp3rr4r",
                )
                .unwrap(),
            },
            arkret_sdk::DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            1,
            arkret_sdk::Hlc::new("01970e589d21-0002-a13f9c2e").unwrap(),
            serde_json::json!({
                // Forged strand_id pointing at the Sidecar private Strand …
                "strand_id": session.source_strand_id.clone(),
                "track_name": "discussion",
                "encrypted_metadata": serde_json::to_value(&metadata).unwrap(),
            }),
        )
        .unwrap();
        event.refs = vec![arkret_sdk::EventRef::new(
            request_event_id.as_str(),
            "after",
        )];
        event
            .refresh_content_bound_identity_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
            .unwrap();
        store.append_raw_operation(
            event.event_id.to_string(),
            Some(session.source_realm_id.clone()),
            serde_json::to_value(&event).unwrap(),
        );

        let changed = refold_sidecar_exchanges_with_decrypt(
            &mut store,
            EXCHANGE_ACCOUNT,
            &session.source_realm_id,
            &[],
            &passthrough_sidecar_envelope,
        );
        assert_eq!(changed, 0, "foreign-Circle events never enter the fold");
        let cached = cached_sidecar_exchange_projections(
            &store,
            &controller_account(),
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

        let event = arkret_wire::test_support::raw_event(
            arkret_sdk::EventKind::MessageCreate.as_str(),
            arkret_sdk::ScopeRef::Sidecar {
                realm_id: arkret_sdk::RealmId::new(session.source_realm_id.clone()).unwrap(),
                sidecar_id: session.sidecar_id.clone(),
            },
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            7,
            arkret_sdk::Hlc::new("01970e589d21-0005-a13f9c2e").unwrap(),
            serde_json::json!({
                "strand_id": session.source_strand_id.clone(),
                "track_name": "discussion",
                "encrypted_metadata": {"opaque": "ciphertext"},
            }),
        )
        .unwrap();
        record_accepted_sidecar_exchange_request(&mut store, &pending, event.event_id.as_str())
            .unwrap();
        store.append_raw_operation(
            event.event_id.to_string(),
            Some(session.source_realm_id.clone()),
            serde_json::to_value(&event).unwrap(),
        );

        // The author device cannot decrypt its own metadata: decrypt always
        // fails, so ONLY the envelope-upgrade path can improve the fact.
        let author_device_decrypt = |_: &crate::state::LocalStateStore,
                                     _: &str,
                                     _: &serde_json::Value,
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
            &controller_account(),
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

    #[test]
    fn incomparable_cached_frontier_requests_union_history_backfill() {
        let mut store = exchange_test_store("incomparable-frontier");
        let session = session(Vec::new());
        let pending = exchange_pending_submission(&session);
        let request = accepted_request_envelope(&session, &pending);
        record_accepted_sidecar_exchange_request(&mut store, &pending, request.event_id.as_str())
            .unwrap();
        append_accepted_request_envelope(&mut store, &request);
        assert_eq!(
            refold_sidecar_exchanges_with_decrypt(
                &mut store,
                EXCHANGE_ACCOUNT,
                &session.source_realm_id,
                &[],
                &passthrough_sidecar_envelope,
            ),
            1
        );
        let mut cached = cached_sidecar_exchange_projections(
            &store,
            &controller_account(),
            session.source_realm_id.as_str(),
        )
        .pop()
        .unwrap();
        let response_event_id = arkret_sdk::EventId::new(EXCHANGE_RESPONSE_EVENT).unwrap();
        cached.status = arkret_sdk::AgentSidecarExchangeStatus::Responding;
        cached.participating_agent_ids =
            vec![crate::mls_api_helpers::principal_core_id(EXCHANGE_AGENT).unwrap()];
        cached.user_facing_response_event_ids = vec![response_event_id.clone()];
        cached.folded_frontier = arkret_sdk::AgentSidecarExchangeFoldedFrontier {
            event_ids: vec![response_event_id.clone()],
            event_set_digest: arkret_sdk::agent_sidecar_exchange_event_set_digest(&[
                response_event_id,
            ])
            .unwrap(),
            max_hlc: arkret_sdk::Hlc::new("01970e589d21-0002-a13f9c2e").unwrap(),
        };
        cache_sidecar_exchange_projection(&mut store, &controller_account(), &cached).unwrap();

        let no_history_decrypt = |_: &crate::state::LocalStateStore,
                                  _: &str,
                                  _: &serde_json::Value,
                                  _: &serde_json::Value|
         -> Option<Vec<u8>> { None };
        let outcome = refold_sidecar_exchanges_with_decrypt_report(
            &mut store,
            EXCHANGE_ACCOUNT,
            &controller_account(),
            &session.source_realm_id,
            &[],
            &no_history_decrypt,
        );

        assert_eq!(outcome.cache_entries_changed, 0);
        assert!(outcome.backfill_required);
        assert_eq!(
            cached_sidecar_exchange_projections(
                &store,
                &controller_account(),
                session.source_realm_id.as_str(),
            )[0],
            cached,
            "an incomparable cache is retained until accepted union history arrives"
        );
    }

    /// F-7: only one in-flight submit per `(controller, strand, intent)`;
    /// releasing the guard frees the slot for a retry.
    #[test]
    fn sidecar_submission_guard_blocks_concurrent_same_intent() {
        let strand = "ak:strand:AZTCRuIIAbIOwW3znwmstLFWrufZL_NdCOg0IKmx_ZxU";
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

    #[test]
    fn one_privacy_gate_blocks_private_sidecar_data_on_every_shared_surface() {
        let mut store = exchange_test_store("privacy-gate");
        let session = session(Vec::new());
        let pending = exchange_pending_submission(&session);
        save_pending_sidecar_submission(&mut store, "privacy-gate", &pending).unwrap();
        let gate = SidecarPrivacyGate::from_store(&store, EXCHANGE_ACCOUNT);

        for surface in [
            SidecarDisclosureSurface::Search,
            SidecarDisclosureSurface::Unread,
            SidecarDisclosureSurface::Watch,
            SidecarDisclosureSurface::Notification,
            SidecarDisclosureSurface::PublicExport,
            SidecarDisclosureSurface::SharedPublish,
        ] {
            assert!(
                gate.allows_strand(surface, &session.source_strand_id),
                "{surface:?} must keep the attached shared source Strand"
            );
        }

        assert!(!gate.allows_serialized(
            SidecarDisclosureSurface::PublicExport,
            &serde_json::json!({
                "body": "ordinary looking preview",
                "internal_locator": "ak:sidecar:ARtoYyyaAqwT8z7xX2YLO-x_zdkPXEy8ygoDx-tu-5fm",
            }),
        ));
        assert!(!gate.allows_serialized(
            SidecarDisclosureSurface::Notification,
            &serde_json::json!({
                "body": format!("internal locator {}", session.sidecar_id),
            }),
        ));
        assert!(gate.allows_serialized(
            SidecarDisclosureSurface::PublicExport,
            &serde_json::json!({
                "body": "controller-approved shared summary",
                "strand_id": session.source_strand_id,
            }),
        ));
    }

    #[test]
    fn explicit_publish_requires_confirmation_and_builds_only_shared_message_payload() {
        let mut store = exchange_test_store("explicit-publish");
        let session = session(Vec::new());
        let pending = exchange_pending_submission(&session);
        save_pending_sidecar_submission(&mut store, "explicit-publish", &pending).unwrap();
        let gate = SidecarPrivacyGate::from_store(&store, EXCHANGE_ACCOUNT);
        let message_id = "ak:message:AdV6KuD51EMEm2yZtha8GGZ_MPcUJG4GYRr_EwV86ycE";

        let unconfirmed = crate::views::chat::confirmed_sidecar_publish_message_operation(
            &gate,
            false,
            &session.source_realm_id,
            EXCHANGE_ACCOUNT,
            &session.source_strand_id,
            message_id,
            "approved summary",
        );
        assert!(unconfirmed.is_err());

        let leaked_identifier = crate::views::chat::confirmed_sidecar_publish_message_operation(
            &gate,
            true,
            &session.source_realm_id,
            EXCHANGE_ACCOUNT,
            &session.source_strand_id,
            message_id,
            &format!("internal {}", session.sidecar_id),
        );
        assert!(leaked_identifier.is_err());

        let published = crate::views::chat::confirmed_sidecar_publish_message_operation(
            &gate,
            true,
            &session.source_realm_id,
            EXCHANGE_ACCOUNT,
            &session.source_strand_id,
            message_id,
            "controller-approved shared summary",
        )
        .unwrap();
        assert_eq!(published.kind().as_str(), "ak.message.create");
        let published = crate::operation::author_for_test(&published);
        assert!(gate.allows_serialized(SidecarDisclosureSurface::SharedPublish, published.event()));
        let serialized = serde_json::to_value(published.event()).unwrap();
        assert_eq!(serialized["payload"]["strand_id"], session.source_strand_id);
        assert_eq!(
            serialized["payload"]["content"]["body"],
            "controller-approved shared summary"
        );
        for forbidden in [
            "sidecar_id",
            "exchange_id",
            "request_binding",
            "private_history",
            "internal_locator",
            "scratchpad",
            "tool_state",
            "draft",
        ] {
            assert!(
                !serialized.to_string().contains(forbidden),
                "shared publish leaked forbidden field {forbidden}"
            );
        }
    }
}
