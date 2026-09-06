//! Pure derivations behind the Agent settings panel.
//!
//! Directory row merging, the pairing-renewal reconciliation, the two runtime
//! gates and the list filter. None of it touches the network or a Signal, so
//! every rule below is reachable without mounting [`AgentAdminPanel`].

use super::*;

pub(super) fn normalize_agent_slug(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

/// Pairing renewal is offered for a controller-bound Agent whose runtime key is
/// still missing or whose handle expired. key-management.md §7.5.6: pairing
/// admission verifies current controller/Agent authority, proof-of-possession
/// and the accepted control frontier only — never a backup-readiness gate.
pub(super) fn should_offer_pairing_renewal(has_pcr_binding: bool, runtime_state: &str) -> bool {
    has_pcr_binding && matches!(runtime_state, "pending_runtime_key" | "pairing_expired")
}

pub(super) fn should_offer_security_refresh(has_key_state: bool, lifecycle_state: &str) -> bool {
    has_key_state && lifecycle_state != "deactivated"
}

pub(super) fn should_show_pairing_card(
    runtime_state: &str,
    has_pairing_handle: bool,
    pairing_is_expired: bool,
    replacement_pairing_requested: bool,
) -> bool {
    (matches!(runtime_state, "pending_runtime_key" | "pairing_expired")
        && (has_pairing_handle || pairing_is_expired))
        || (runtime_state == "replacing" && replacement_pairing_requested && has_pairing_handle)
}

pub(super) fn agent_id(agent: &AgentView) -> String {
    agent.agent.agent_id.to_string()
}

pub(super) fn selected_agent_binding_matches(
    selected_agent_id: &str,
    controller_principal_id: &arkret_sdk::DidCoreId,
    key_state: &KeyState,
) -> bool {
    arkret_sdk::DidCoreId::new(selected_agent_id.to_owned())
        .is_ok_and(|agent_id| agent_id == key_state.agent_id)
        && controller_principal_id == &key_state.controller_account_id.principal_id
}

pub(super) fn agent_slug_label(agent: &AgentView) -> String {
    let slug = agent.agent.slug.clone();
    if !slug.is_empty() {
        return slug;
    }
    let id = agent_id(agent);
    if id.is_empty() {
        "(unnamed agent)".to_owned()
    } else {
        short_protocol_id(&id)
    }
}

pub(super) fn requested_scope_matches_content_preset(
    scope: Option<&AgentKeyScope>,
    preset: AgentGrantPreset,
) -> bool {
    let Some(scope) = scope else {
        return false;
    };
    if !preset
        .actions()
        .iter()
        .all(|action| scope.actions.iter().any(|candidate| candidate == action))
    {
        return false;
    }
    if preset != AgentGrantPreset::ActOnBehalf {
        return true;
    }
    scope.constraints.iter().any(|constraint| {
        constraint.controller_approval_required == Some(true)
            || constraint.approval_required == Some(true)
    })
}

pub(super) fn requested_scope_matches_service_preset(
    scope: Option<&AgentKeyScope>,
    preset: AgentServiceScopePreset,
) -> bool {
    let Some(scope) = scope else {
        return false;
    };
    preset
        .actions()
        .iter()
        .all(|action| scope.actions.iter().any(|candidate| candidate == action))
}

pub(super) fn agent_view_runtime_state(agent: &AgentView) -> AgentRuntimeState {
    agent
        .key_state
        .as_ref()
        .map(key_state_runtime_state)
        .unwrap_or_else(|| {
            crate::views::agents::model::agent_projection_runtime_state(&agent.agent)
        })
}

pub(super) fn upsert_agent_view(rows: &mut Vec<AgentView>, view: AgentView) {
    let id = agent_id(&view);
    if id.is_empty() {
        return;
    }
    if let Some(existing) = rows.iter_mut().find(|row| agent_id(row) == id) {
        *existing = view;
    } else {
        rows.push(view);
    }
}

pub(super) fn replace_agent_directory(rows: &mut Vec<AgentView>, directory_rows: Vec<AgentView>) {
    let previous_rows = std::mem::take(rows);
    *rows = directory_rows
        .into_iter()
        .map(|mut directory_row| {
            if let Some(previous) = previous_rows
                .iter()
                .find(|row| agent_id(row) == agent_id(&directory_row))
            {
                directory_row.grants = previous.grants.clone();
                directory_row.key_state = previous.key_state.clone();
            }
            directory_row
        })
        .collect();
}

pub(super) fn update_agent_status(rows: &mut [AgentView], id: &str, status: AgentLifecycleState) {
    for row in rows.iter_mut() {
        if agent_id(row) == id {
            row.agent.lifecycle = status;
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum PairingActionPhase {
    #[default]
    Idle,
    RepairingRecovery,
    IssuingPairing,
    RefreshingAgent,
}

pub(super) fn apply_renewed_pairing(
    rows: &mut [AgentView],
    renewed_agent_id: &str,
    outcome: &AgentRenewPairingOutcome,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), &'static str> {
    if outcome.agent_id.as_str() != renewed_agent_id {
        return Err("renewed pairing response identifies a different Agent");
    }
    if outcome.pairing_request_id.trim().is_empty() {
        return Err("renewed pairing response omitted the pairing request id");
    }
    if outcome
        .pairing_code
        .as_deref()
        .is_none_or(|code| code.trim().is_empty())
    {
        return Err("renewed pairing response omitted the new pairing code");
    }
    if outcome.expires_at <= now {
        return Err("renewed pairing response already expired");
    }
    let row = rows
        .iter_mut()
        .find(|row| agent_id(row) == renewed_agent_id)
        .ok_or("renewed Agent is missing from the local directory")?;
    let key_state = row
        .key_state
        .as_mut()
        .ok_or("renewed Agent details are not loaded")?;
    let outcome_agent_actor_id = outcome.agent_id.clone();
    let requested_scope_digest = arkret_signatures::agent::agent_requested_scope_digest(
        &key_state.agent_id,
        &key_state.controller_account_id.principal_id,
        &key_state.requested_scope,
    )
    .map_err(|_| "loaded Agent scope is not digestible")?;
    if key_state.agent_id != outcome_agent_actor_id
        || key_state.principal_control_realm_id != outcome.principal_control_realm_id
        || key_state.controller_authorization_ref != outcome.controller_authorization_ref
        || requested_scope_digest != outcome.requested_scope_digest
    {
        return Err("renewed pairing response does not match the loaded Agent binding");
    }
    // Re-opening pairing never changes the lifecycle intent; only the derived
    // runtime_state moves (key-management.md §3.6.1). Bootstrap re-open applies
    // to a never-keyed agent, runtime replacement to one already holding an
    // active key — the pairing_mode must agree with the loaded key state.
    let has_active_authorization = !key_state.active_authorizations.is_empty();
    match outcome.pairing_mode {
        AgentPairingMode::Bootstrap if !has_active_authorization => {
            AgentRuntimeState::PendingRuntimeKey
        }
        AgentPairingMode::Replacement if has_active_authorization => AgentRuntimeState::Replacing,
        AgentPairingMode::Bootstrap => {
            return Err("bootstrap pairing response conflicts with the loaded Agent key state");
        }
        AgentPairingMode::Replacement => {
            return Err("replacement pairing response conflicts with the loaded Agent key state");
        }
    };
    key_state.pairing_request_id = Some(outcome.pairing_request_id.clone());
    key_state.pairing_mode = Some(outcome.pairing_mode);
    key_state.pairing_code = outcome.pairing_code.clone();
    key_state.pairing_expires_at = Some(outcome.expires_at);
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PairingReconcileOutcome {
    AppliedLocally,
    AppliedFromAuthoritativeView,
}

pub(super) enum PairingReconcileError {
    RefreshFailed(String),
    RefreshedViewRejected(&'static str),
}

pub(super) fn reconcile_refreshed_pairing(
    rows: &mut Vec<AgentView>,
    refreshed_view: AgentView,
    renewed_agent_id: &str,
    outcome: &AgentRenewPairingOutcome,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), &'static str> {
    let mut refreshed = vec![refreshed_view];
    apply_renewed_pairing(&mut refreshed, renewed_agent_id, outcome, now)?;
    upsert_agent_view(rows, refreshed.remove(0));
    Ok(())
}

pub(super) const AGENT_LIST_FILTERS: [(&str, &str); 3] =
    [("all", "All"), ("active", "Active"), ("paused", "Paused")];

pub(super) fn normalize_agent_filter(filter: &str) -> &'static str {
    match filter.trim().to_ascii_lowercase().as_str() {
        "active" => "active",
        "paused" => "paused",
        "deactivated" => "deactivated",
        _ => "all",
    }
}

pub(super) fn agent_matches_filter(status: &str, filter: &str) -> bool {
    match filter {
        "active" => status == "active",
        "paused" => status == "paused",
        "deactivated" => status == "deactivated",
        _ => status != "deactivated",
    }
}

/// Everything the panel reads off the Agent directory and the selected row.
///
/// This ran inline between the panel's `use_signal` declarations and its
/// `rsx!`. It only reads, so none of the gates below — which runtime state may
/// renew pairing, which may replace a runtime, when the pairing card appears —
/// was reachable without mounting the component.
pub(super) struct AgentAdminView {
    pub(super) visible_agents: Vec<AgentView>,
    pub(super) has_any_agents: bool,
    pub(super) selected_title: String,
    pub(super) selected_slug: String,
    /// The controller lifecycle intent (key-management.md §3.6.1). Pause,
    /// resume and the list filter key off this axis.
    pub(super) selected_status: String,
    /// The derived runtime readiness — the other axis. Pairing and replacement
    /// gates key off this one.
    pub(super) selected_runtime_state: String,
    pub(super) selected_key_state_owned: Option<KeyState>,
    pub(super) deactivate_status: AgentLifecycleState,
    pub(super) selected_has_pcr_binding: bool,
    pub(super) selected_pcr_bootstrap_target: Option<PcrBootstrapTarget>,
    pub(super) selected_should_offer_security_refresh: bool,
    pub(super) selected_pairing_request_id: String,
    pub(super) selected_pairing_code: String,
    pub(super) selected_pairing_is_expired: bool,
    pub(super) selected_has_pairing_handle: bool,
    pub(super) selected_is_replacement_pairing: bool,
    pub(super) selected_can_replace_runtime: bool,
    pub(super) selected_can_renew_pairing: bool,
    pub(super) selected_should_show_pairing_card: bool,
    pub(super) selected_created_at: String,
    pub(super) selected_updated_at: String,
    pub(super) selected_content_capabilities: Vec<(AgentGrantPreset, bool)>,
    pub(super) selected_service_capabilities: Vec<(AgentServiceScopePreset, bool)>,
}

/// The Agent, its principal-control Realm and the controller authorization the
/// PCR-bootstrap and security-refresh commands address. `None` whenever the
/// directory row and the key state disagree about which Agent this is, so a
/// mismatched projection can never be sealed under the wrong Agent.
pub(super) type PcrBootstrapTarget = (
    arkret_sdk::DidCoreId,
    arkret_sdk::RealmId,
    arkret_sdk::DidUrl,
);

pub(super) fn build_agent_admin_view(
    rows: &[AgentView],
    selected_id: &str,
    filter: &str,
    now_rfc3339: &str,
) -> AgentAdminView {
    let selected_agent = rows
        .iter()
        .find(|agent| {
            agent_id(agent) == selected_id
                && agent_matches_filter(agent_lifecycle_wire(agent.agent.lifecycle), filter)
        })
        .cloned();
    let visible_agents = rows
        .iter()
        .filter(|agent| agent_matches_filter(agent_lifecycle_wire(agent.agent.lifecycle), filter))
        .cloned()
        .collect::<Vec<_>>();
    let has_any_agents = rows
        .iter()
        .any(|agent| agent_matches_filter(agent_lifecycle_wire(agent.agent.lifecycle), "all"));

    let selected_title = selected_agent
        .as_ref()
        .map(agent_slug_label)
        .unwrap_or_else(|| "No agent selected".to_owned());
    let selected_slug = selected_agent
        .as_ref()
        .map(|agent| agent.agent.slug.clone())
        .unwrap_or_default();
    let selected_status = selected_agent
        .as_ref()
        .map(|agent| agent_lifecycle_wire(agent.agent.lifecycle).to_owned())
        .unwrap_or_default();
    let selected_key_state = selected_agent
        .as_ref()
        .and_then(|agent| agent.key_state.as_ref());
    // The detailed key-state projection carries the authoritative live pairing
    // handle and expiry. Prefer it over reconstructing the runtime axis from
    // directory readiness blockers, which are intentionally a summary and can
    // otherwise turn a live bootstrap handle into a false `pairing_expired`.
    let selected_runtime_state = selected_agent
        .as_ref()
        .map(|agent| agent_runtime_state_wire(agent_view_runtime_state(agent)).to_owned())
        .unwrap_or_default();
    let deactivate_status = selected_agent
        .as_ref()
        .map(|agent| agent.agent.lifecycle)
        .unwrap_or_default();
    let selected_has_pcr_binding = selected_key_state.is_some();
    let selected_pcr_bootstrap_target = selected_agent.as_ref().and_then(|agent| {
        let key_state = agent.key_state.as_ref()?;
        let agent_id = agent.agent.agent_id.clone();
        (agent_id == key_state.agent_id).then(|| {
            (
                agent_id,
                key_state.principal_control_realm_id.clone(),
                key_state.controller_authorization_ref.clone(),
            )
        })
    });
    let selected_should_offer_security_refresh =
        should_offer_security_refresh(selected_key_state.is_some(), &selected_status);
    let selected_pairing_request_id = selected_key_state
        .and_then(|key_state| key_state.pairing_request_id.as_deref())
        .unwrap_or_default();
    let selected_pairing_code = selected_key_state
        .and_then(|key_state| key_state.pairing_code.as_deref())
        .unwrap_or_default();
    let selected_pairing_expires_at = selected_key_state
        .and_then(|key_state| key_state.pairing_expires_at.as_ref())
        .map(chrono::DateTime::to_rfc3339)
        .unwrap_or_default();
    let selected_pairing_is_expired = selected_runtime_state == "pairing_expired"
        || is_pairing_request_expired(&selected_pairing_expires_at, now_rfc3339);
    let selected_has_pairing_handle =
        !selected_pairing_request_id.is_empty() && !selected_pairing_code.is_empty();
    // The authenticated projection is authoritative across reloads. The
    // service clears these fields after consumption/expiry, so local UI state
    // must never be used as the replacement-in-progress discriminator.
    // A keyed agent is ready to replace its runtime; forced pause is gone
    // (key-management.md §3.6.1). A replacement already in flight projects
    // runtime_state `replacing`.
    let selected_can_replace_runtime = selected_runtime_state == "ready";
    let selected_is_replacement_pairing = selected_runtime_state == "replacing";
    let selected_can_renew_pairing =
        should_offer_pairing_renewal(selected_has_pcr_binding, &selected_runtime_state)
            || (selected_is_replacement_pairing && selected_has_pcr_binding);
    let selected_should_show_pairing_card = should_show_pairing_card(
        &selected_runtime_state,
        selected_has_pairing_handle,
        selected_pairing_is_expired,
        selected_is_replacement_pairing,
    );
    let selected_created_at = selected_agent
        .as_ref()
        .and_then(|agent| agent.agent.created_at.as_ref())
        .map(chrono::DateTime::to_rfc3339)
        .unwrap_or_default();
    let selected_updated_at = selected_agent
        .as_ref()
        .and_then(|agent| agent.agent.updated_at.as_ref())
        .map(chrono::DateTime::to_rfc3339)
        .unwrap_or_default();
    let selected_scope = selected_key_state.map(|key_state| &key_state.requested_scope);
    let selected_content_capabilities = AgentGrantPreset::ALL
        .into_iter()
        .map(|preset| {
            (
                preset,
                requested_scope_matches_content_preset(selected_scope, preset),
            )
        })
        .collect();
    let selected_service_capabilities = AgentServiceScopePreset::ALL
        .into_iter()
        .map(|preset| {
            (
                preset,
                requested_scope_matches_service_preset(selected_scope, preset),
            )
        })
        .collect();

    AgentAdminView {
        visible_agents,
        has_any_agents,
        selected_title,
        selected_slug,
        selected_status,
        selected_runtime_state,
        selected_key_state_owned: selected_key_state.cloned(),
        deactivate_status,
        selected_has_pcr_binding,
        selected_pcr_bootstrap_target,
        selected_should_offer_security_refresh,
        selected_pairing_request_id: selected_pairing_request_id.to_owned(),
        selected_pairing_code: selected_pairing_code.to_owned(),
        selected_pairing_is_expired,
        selected_has_pairing_handle,
        selected_is_replacement_pairing,
        selected_can_replace_runtime,
        selected_can_renew_pairing,
        selected_should_show_pairing_card,
        selected_created_at,
        selected_updated_at,
        selected_content_capabilities,
        selected_service_capabilities,
    }
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
