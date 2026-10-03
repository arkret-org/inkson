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
    pub pending_access_reconciliations: Vec<arkret_sdk::PendingSidecarAccessReconciliation>,
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

    pub fn mls_scope_sidecar_id(&self) -> arkret_sdk::Result<arkret_sdk::SidecarId> {
        self.mls_context.validate_shape()?;
        Ok(self.sidecar_id.clone())
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

pub(crate) fn validate_agent_sidecar_view(
    view: &arkret_sdk::AgentSidecarView,
) -> arkret_sdk::Result<()> {
    view.sidecar.validate_shape()?;
    view.mls_context.validate_shape()?;
    if view
        .effective_agent_ids
        .iter()
        .any(|agent| !view.desired_agent_ids.contains(agent))
    {
        return Err(arkret_sdk::Error::Protocol(
            "effective Sidecar Agent set is not a subset of desired Agents".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SidecarViewStateMergeDecision {
    UseCurrent,
    UseCandidate,
}

fn sidecar_view_state_account_data_key_for_context(
    account_data_namespace_key: &[u8],
    controller_account_id: &arkret_sdk::AccountId,
    realm_id: &arkret_sdk::RealmId,
    strand_id: &arkret_sdk::StrandId,
) -> arkret_sdk::Result<String> {
    let controller_account_key =
        arkret_sdk::derive_account_data_key(account_data_namespace_key, controller_account_id)?;
    Ok(format!(
        "{}:{controller_account_key}:{realm_id}:{strand_id}",
        arkret_sdk::AccountDataKey::AGENT_SIDECAR_VIEW_STATE_V1
    ))
}

fn sidecar_view_state_account_data_key(
    account_data_namespace_key: &[u8],
    view_state: &arkret_sdk::AgentSidecarViewState,
) -> arkret_sdk::Result<String> {
    view_state.validate_shape()?;
    sidecar_view_state_account_data_key_for_context(
        account_data_namespace_key,
        &view_state.controller_account_id,
        &view_state.context_ref.realm_id,
        &view_state.context_ref.strand_id,
    )
}

fn validate_sidecar_view_state_account_data_key(
    account_data_namespace_key: &[u8],
    account_data_key: &str,
    view_state: &arkret_sdk::AgentSidecarViewState,
) -> arkret_sdk::Result<()> {
    let expected = sidecar_view_state_account_data_key(account_data_namespace_key, view_state)?;
    if account_data_key != expected {
        return Err(arkret_sdk::WireError::Protocol(
            "Sidecar view-state Account Data key does not match its controller/context".to_owned(),
        )
        .into());
    }
    Ok(())
}

fn compare_sidecar_view_state_stamp(
    left: &arkret_sdk::AgentSidecarViewState,
    right: &arkret_sdk::AgentSidecarViewState,
) -> arkret_sdk::Result<std::cmp::Ordering> {
    Ok(
        arkret_sdk::compare_hlc(left.updated_hlc.as_str(), right.updated_hlc.as_str())?.then_with(
            || {
                left.origin_device_id
                    .as_str()
                    .as_bytes()
                    .cmp(right.origin_device_id.as_str().as_bytes())
            },
        ),
    )
}

fn sidecar_view_state_merge_decision(
    current_plaintext: Option<&serde_json::Value>,
    account_data_namespace_key: &[u8],
    account_data_key: &str,
    candidate: &arkret_sdk::AgentSidecarViewState,
) -> anyhow::Result<SidecarViewStateMergeDecision> {
    validate_sidecar_view_state_account_data_key(
        account_data_namespace_key,
        account_data_key,
        candidate,
    )?;
    let Some(current_plaintext) = current_plaintext else {
        return Ok(SidecarViewStateMergeDecision::UseCandidate);
    };
    let current =
        serde_json::from_value::<arkret_sdk::AgentSidecarViewState>(current_plaintext.clone())?;
    validate_sidecar_view_state_account_data_key(
        account_data_namespace_key,
        account_data_key,
        &current,
    )?;
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
    Ok(
        if compare_sidecar_view_state_stamp(candidate, &current)?.is_gt() {
            SidecarViewStateMergeDecision::UseCandidate
        } else {
            SidecarViewStateMergeDecision::UseCurrent
        },
    )
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
        &sidecar_view_state_account_data_key(account_data_namespace_key, view_state)?,
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
    let key = sidecar_view_state_account_data_key(namespace_key, view_state)?;
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
    validate_sidecar_view_state_account_data_key(&namespace_key, account_data_key, &view_state)?;
    if &view_state.controller_account_id != authority {
        anyhow::bail!("Sidecar view-state controller does not match the account holder");
    }
    cache_sidecar_view_state_with_namespace(store, authority, &namespace_key, &view_state)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Controller-private view state and Sidecar exchange binding. Exchange
// projections remain unavailable until a verified Sidecar Commit/current
// input replaces the retired local Event scan (decision 0071).
// ---------------------------------------------------------------------------

/// Incremental controller-private Sidecar projection registry.
///
/// View states are encrypted Account Data and fold by their own LWW stamp.
/// Exchange projection insertion is reserved for a verified Sidecar stream
/// consumer; the ordinary read surface below does not expose this fold yet.
#[derive(Clone, Debug, Default)]
pub struct SidecarProjectionFold {
    view_states:
        std::collections::BTreeMap<(String, String, String), arkret_sdk::AgentSidecarViewState>,
}

impl SidecarProjectionFold {
    /// Last-writer-wins on `(updated_hlc, origin_device_id)`. Returns whether
    /// the candidate replaced the stored value.
    pub fn apply_view_state(&mut self, value: arkret_sdk::AgentSidecarViewState) -> bool {
        let key = (
            value.controller_account_id.to_string(),
            value.context_ref.realm_id.to_string(),
            value.context_ref.strand_id.to_string(),
        );
        let should_replace = self.view_states.get(&key).is_none_or(|current| {
            compare_sidecar_view_state_stamp(&value, current)
                .expect("typed Sidecar view-state stamps are canonical")
                .is_gt()
        });
        if should_replace {
            self.view_states.insert(key, value);
        }
        should_replace
    }

    pub fn view_state(
        &self,
        controller_account_key: &str,
        realm_id: &arkret_sdk::RealmId,
        strand_id: &arkret_sdk::StrandId,
    ) -> Option<&arkret_sdk::AgentSidecarViewState> {
        self.view_states.get(&(
            controller_account_key.to_owned(),
            realm_id.to_string(),
            strand_id.to_string(),
        ))
    }
}

/// Client-local fold-cache key prefix (deliberately NOT an `ak.*` account-data
/// type name).
const SIDECAR_EXCHANGE_FOLD_CACHE_PREFIX: &str = "sidecar_exchange_fold";
/// Client-local pre-submission intent records (`zh/models/sidecar.md` §7.2.4:
/// a rejected request has no durable exchange; retries of the same intent
/// MUST reuse the same `exchange_id`).
const SIDECAR_PENDING_SUBMISSION_PREFIX: &str = "ak.local.sidecar_pending_submission.v1";
/// Older local records are still considered by the privacy gate so their
/// identifiers are not exposed through shared surfaces. No producer remains.
const SIDECAR_EXCHANGE_REQUEST_FACT_PREFIX: &str = "sidecar_exchange_request_fact";
/// Older local auto-close records are privacy-scanned but never submitted.
const SIDECAR_AUTO_CLOSE_INTENT_PREFIX: &str = "sidecar_exchange_auto_close_intent";
/// Older local locator records are privacy-scanned but never trusted as current.
const SIDECAR_CONTEXT_LOCATOR_PREFIX: &str = "sidecar_context_locator";
const SIDECAR_EXCHANGE_BINDING_FIELD: &str = "sidecar_exchange_binding";

/// Mount the one canonical Sidecar exchange binding into encrypted Message
/// metadata. `MessageMetadata.extra` is the SDK's exact top-level carrier for
/// registered extension members; this helper accepts no legacy key or shape.
pub(crate) fn set_sidecar_exchange_binding(
    metadata: &mut arkret_sdk::MessageMetadata,
    binding: &arkret_sdk::AgentSidecarEventExchangeBinding,
) -> anyhow::Result<()> {
    binding.validate_shape()?;
    if metadata.extra.contains_key(SIDECAR_EXCHANGE_BINDING_FIELD) {
        anyhow::bail!("Sidecar exchange metadata already carries a binding");
    }
    metadata.extra.insert(
        SIDECAR_EXCHANGE_BINDING_FIELD.to_owned(),
        serde_json::to_value(binding)?,
    );
    Ok(())
}

/// Decode the canonical encrypted-metadata binding. Unknown/malformed shapes
/// fail closed to non-echo.
pub(crate) fn sidecar_exchange_binding(
    metadata: &arkret_sdk::MessageMetadata,
) -> Option<arkret_sdk::AgentSidecarEventExchangeBinding> {
    let binding = serde_json::from_value::<arkret_sdk::AgentSidecarEventExchangeBinding>(
        metadata.extra.get(SIDECAR_EXCHANGE_BINDING_FIELD)?.clone(),
    )
    .ok()?;
    binding.validate_shape().ok()?;
    Some(binding)
}

/// No exchange projection is exposed until it is rebuilt from a verified
/// contiguous Sidecar Commit stream and the Station's typed current controls.
/// Persisted old fold entries are not current authority.
pub fn cached_sidecar_exchange_projections(
    store: &crate::state::LocalStateStore,
    controller_account_id: &arkret_sdk::AccountId,
    source_realm_id: &str,
) -> anyhow::Result<Vec<arkret_sdk::AgentSidecarExchangeProjection>> {
    crate::sidecar_fold::rebuild(store, controller_account_id, source_realm_id)
}

/// The opt-in test hook does not report an empty successful fold while
/// verified Sidecar Commit/current input is unavailable.
#[cfg(all(
    feature = "wasm-localstorage-secrets-test",
    any(target_arch = "wasm32", test)
))]
pub(crate) fn sidecar_fold_evidence_canonical_json(
    store: &crate::state::LocalStateStore,
    controller_account_id: &arkret_sdk::AccountId,
    source_realm_id: &str,
) -> anyhow::Result<String> {
    let projections =
        cached_sidecar_exchange_projections(store, controller_account_id, source_realm_id)?;
    let exchanges = projections
        .into_iter()
        .map(|projection| {
            Ok(serde_json::json!({
                "projection_digest": arkret_sdk::canonical::canonical_sha256(&projection)?,
                "projection": projection,
            }))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(arkret_sdk::canonical::canonical_json_string(
        &serde_json::json!({
            "schema": "inkson.test.sidecar_fold_evidence.v1",
            "controller_account_id": controller_account_id,
            "source_realm_id": source_realm_id,
            "exchanges": exchanges,
        }),
    )?)
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
    verified_publish_targets: std::collections::BTreeSet<String>,
}

impl SidecarPrivacyGate {
    pub(crate) fn from_store(
        store: &crate::state::LocalStateStore,
        controller_principal_id: &str,
    ) -> Self {
        let mut private_identifiers = std::collections::BTreeSet::new();
        let mut verified_publish_targets = std::collections::BTreeSet::new();
        let state = store.load();
        if let Some(local) = &state.device_authoring_authority
            && local.account_id.principal_id.as_str() == controller_principal_id
        {
            for (realm, snapshot) in &state.verified_sidecar_current {
                for row in &snapshot.current_state_entries {
                    if let arkret_sdk::TypedCurrentResult::Value {
                        selector: arkret_sdk::CurrentSelector::Sidecar { sidecar_id },
                        value,
                        ..
                    } = row
                        && let Ok(sidecar) =
                            serde_json::from_value::<arkret_sdk::AgentSidecar>(value.clone())
                        && sidecar.controller_account_id == local.account_id
                    {
                        private_identifiers.insert(sidecar_id.to_string());
                        for rows in state.verified_sidecar_history.values() {
                            for row in rows {
                                if matches!(&row.commit().stream_ref, arkret_sdk::CommitStreamRef::Sidecar { sidecar_id: id, .. } if id == sidecar_id)
                                {
                                    private_identifiers.insert(row.commit().event_ref.to_string());
                                }
                            }
                        }
                    }
                }
                if let Ok(projections) =
                    cached_sidecar_exchange_projections(store, &local.account_id, realm)
                {
                    for projection in projections {
                        private_identifiers.insert(projection.exchange_id.clone());
                        if !projection.user_facing_response_event_ids.is_empty() {
                            verified_publish_targets
                                .insert(projection.source_track_ref.strand_id.to_string());
                        }
                    }
                }
            }
        }
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
            verified_publish_targets,
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
        if !self.verified_publish_targets.contains(target_strand_id) {
            anyhow::bail!("Sidecar publish requires verified Sidecar exchange current");
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
/// Never a wire object: a rejected/failed submit keeps this record so a
/// future verified retry can reuse the same `exchange_id`. It is not a
/// committed exchange or a local current projection.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct PendingSidecarSubmission {
    pub controller_account_id: arkret_sdk::AccountId,
    pub sidecar_id: arkret_sdk::SidecarId,
    pub source_strand_id: String,
    pub exchange_id: String,
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
            let key = sidecar_view_state_account_data_key_for_context(
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
        schema: arkret_sdk::SchemaId::AGENT_SIDECAR_VIEW_STATE_V1.to_owned(),
        controller_account_id: authority.clone(),
        sidecar_id: session.sidecar_id.clone(),
        context_ref: arkret_sdk::SidecarStrandContextRef {
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
    let account_data_key = match sidecar_view_state_account_data_key(&namespace_key, &view_state) {
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

    const EXCHANGE_ACCOUNT: &str = "ak:did_core:web:alice.example";
    const EXCHANGE_AGENT: &str = "did:web:agents.example:assistant";

    fn controller_account() -> arkret_sdk::AccountId {
        crate::test_support::authority("did:web:alice.example")
    }

    fn account_data_namespace_key() -> [u8; 32] {
        [7; 32]
    }

    fn session(pending: Vec<arkret_sdk::PendingSidecarAccessReconciliation>) -> HostedSidecarState {
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
                authority_stream_head: vec![
                    arkret_sdk::EventId::new(
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
            schema: arkret_sdk::SchemaId::AGENT_SIDECAR_VIEW_STATE_V1.to_owned(),
            controller_account_id: controller_account(),
            sidecar_id: session.sidecar_id.clone(),
            context_ref: arkret_sdk::SidecarStrandContextRef {
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
            &sidecar_view_state_account_data_key(&account_data_namespace_key(), candidate).unwrap(),
            candidate,
        )
    }

    #[test]
    fn pending_reconciliation_is_not_ready() {
        let session = session(vec![arkret_sdk::PendingSidecarAccessReconciliation {
            agent_id: crate::mls_api_helpers::principal_core_id("did:web:agents.example:assistant")
                .unwrap(),
            provisioning_phase: arkret_sdk::SidecarAccessProvisioningPhase::MlsWelcome,
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
    fn sidecar_readiness_and_mls_scope_require_the_current_device() {
        let mut session = session(Vec::new());
        assert!(!session.membership_ready());
        session.mls_context.current_controller_device_ready = true;
        assert!(session.membership_ready());

        let sidecar_id = session.mls_scope_sidecar_id().unwrap();
        assert_eq!(sidecar_id, session.sidecar_id);
    }

    #[test]
    fn exchange_binding_uses_only_the_canonical_encrypted_metadata_member() {
        let binding = arkret_sdk::AgentSidecarEventExchangeBinding {
            schema: arkret_sdk::SchemaId::AGENT_SIDECAR_EVENT_EXCHANGE_BINDING_V1.to_owned(),
            exchange_id: "exchange-01964137000000000008".to_owned(),
            role: arkret_sdk::AgentSidecarExchangeRole::Request,
            request_event_id: None,
            completes_exchange: None,
            coordinator_assignment_event_id: None,
            request_context: Some(arkret_sdk::AgentSidecarExchangeRequestContext {
                source_track_ref: arkret_sdk::SidecarSourceTrackRef {
                    realm_id: arkret_sdk::RealmId::new(
                        "ak:realm:AUqzNZlfuL-7z087TbZhKOdYyKUNPAa2o_neyoFRh3o2".to_owned(),
                    )
                    .unwrap(),
                    strand_id: arkret_sdk::StrandId::new(
                        "ak:strand:AUvEs_-d1tc81yDszBZAVWapgIr3Gs6ofbmtZSLQNejL".to_owned(),
                    )
                    .unwrap(),
                    track_name: "discussion".to_owned(),
                },
                source_hlc: arkret_sdk::Hlc::new("019641370000-0000-00000001").unwrap(),
                client_order_key: "01964137-0000-7000-8000-000000000008".to_owned(),
                addressed_agent_ids: vec![
                    crate::mls_api_helpers::principal_core_id("did:web:agents.example:assistant")
                        .unwrap(),
                ],
                coordinator_agent_id: None,
                source_checkpoint_anchor_id: None,
            }),
        };
        let mut metadata = arkret_sdk::MessageMetadata::default();
        set_sidecar_exchange_binding(&mut metadata, &binding).unwrap();

        assert_eq!(sidecar_exchange_binding(&metadata), Some(binding));
        assert!(metadata.fields.is_empty());
        assert_eq!(metadata.extra.len(), 1);
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
                &sidecar_view_state_account_data_key(&account_data_namespace_key(), &candidate)
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
            source_track_ref: arkret_sdk::SidecarSourceTrackRef {
                realm_id: arkret_sdk::RealmId::new(session.source_realm_id.clone()).unwrap(),
                strand_id: arkret_sdk::StrandId::new(session.source_strand_id.clone()).unwrap(),
                track_name: "discussion".to_owned(),
            },
            source_hlc: arkret_sdk::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            client_order_key: "device-1-1".to_owned(),
            addressed_agent_ids: vec![
                crate::mls_api_helpers::principal_core_id(EXCHANGE_AGENT).unwrap(),
            ],
            coordinator_agent_id: None,
            source_checkpoint_anchor_id: None,
        }
    }

    fn exchange_pending_submission(session: &HostedSidecarState) -> PendingSidecarSubmission {
        PendingSidecarSubmission {
            controller_account_id: controller_account(),
            sidecar_id: session.sidecar_id.clone(),
            source_strand_id: session.source_strand_id.clone(),
            exchange_id: "exchange-01964137000000000008".to_owned(),
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
            .is_err()
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
    fn legacy_exchange_cache_never_becomes_current_projection() {
        let mut store = exchange_test_store("legacy-cache");
        let session = session(Vec::new());
        store.save_plain_local_data(
            format!(
                "{SIDECAR_EXCHANGE_FOLD_CACHE_PREFIX}:{EXCHANGE_ACCOUNT}:{}:legacy",
                session.sidecar_id
            ),
            serde_json::json!({"status": "complete", "sidecar_id": session.sidecar_id}).to_string(),
        );
        assert!(
            cached_sidecar_exchange_projections(
                &store,
                &controller_account(),
                &session.source_realm_id,
            )
            .is_err()
        );
    }

    #[cfg(feature = "wasm-localstorage-secrets-test")]
    #[test]
    fn fold_evidence_rejects_unverified_history() {
        let store = exchange_test_store("unverified-fold");
        let session = session(Vec::new());
        assert!(
            sidecar_fold_evidence_canonical_json(
                &store,
                &controller_account(),
                &session.source_realm_id,
            )
            .is_err()
        );
    }

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
    fn explicit_publish_requires_verified_exchange_current() {
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

        let blocked = crate::views::chat::confirmed_sidecar_publish_message_operation(
            &gate,
            true,
            &session.source_realm_id,
            EXCHANGE_ACCOUNT,
            &session.source_strand_id,
            message_id,
            "controller-approved shared summary",
        );
        assert!(blocked.is_err());
    }
}
