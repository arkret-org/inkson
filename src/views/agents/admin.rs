//! Agent settings panel.
//!
//! This view is deliberately limited to settings backed by live server
//! calls: the agent directory row, runtime pairing/key state, lifecycle,
//! capability grants, and lifecycle controls. Per-Realm participation is
//! configured from that Realm's Members area.

use std::time::Duration;

use arkret_models_collaboration::agent_operations::{
    AgentDeactivateRequestBody, AgentLifecycleState, AgentPairingMode, AgentPauseRequestBody,
    AgentProvisionOutcome, AgentProvisionRequestBody, AgentRenewPairingOutcome,
    AgentResumeRequestBody, AgentRuntimeState, AgentView, KeyState,
};
use arkret_models_collaboration::events_payloads::agent::AgentKeyScope;
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_router::hooks::{use_navigator, use_route};

use super::model::{
    AgentGrantPreset, AgentServiceScopePreset, agent_lifecycle_wire, agent_runtime_state_wire,
    agent_state_badge_class, agent_state_label, agent_view_from_directory_row,
    build_agent_pairing_deep_link, build_agent_pairing_handoff_token, build_agent_provision_intent,
    is_pairing_request_expired, key_state_runtime_state, render_agent_pairing_qr_svg,
    requested_scope_for_presets,
};
use crate::components::{QrSharePanel, UiIcon};
use crate::routes::Route;
use crate::transport::auth::{with_authed_api, with_authed_sdk_client, with_event_submitter};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::dialog::Dialog;
use crate::ui::input::Input;
use crate::ui::switch::Switch;
use crate::views::helpers::short_protocol_id;

fn normalize_agent_slug(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

/// Pairing renewal is offered for a controller-bound Agent whose runtime key is
/// still missing or whose handle expired. key-management.md §7.5.6: pairing
/// admission verifies current controller/Agent authority, proof-of-possession
/// and the accepted control frontier only — never a backup-readiness gate.
pub(super) fn should_offer_pairing_renewal(has_pcr_binding: bool, runtime_state: &str) -> bool {
    has_pcr_binding && matches!(runtime_state, "pending_runtime_key" | "pairing_expired")
}

fn should_offer_security_refresh(has_key_state: bool, lifecycle_state: &str) -> bool {
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

fn agent_field(agent: &AgentView, key: &str) -> String {
    match key {
        "agent_id" => agent.agent.agent_id.to_string(),
        "display_name" => agent.agent.display_name.clone().unwrap_or_default(),
        "slug" => agent.agent.slug.clone(),
        "avatar_blob_ref" => agent
            .agent
            .avatar_blob_ref
            .as_ref()
            .map(|value| value.as_str().to_owned())
            .unwrap_or_default(),
        "status" => agent_lifecycle_wire(agent.agent.lifecycle).to_owned(),
        "created_at" => agent
            .agent
            .created_at
            .as_ref()
            .map(chrono::DateTime::to_rfc3339)
            .unwrap_or_default(),
        "updated_at" => agent
            .agent
            .updated_at
            .as_ref()
            .map(chrono::DateTime::to_rfc3339)
            .unwrap_or_default(),
        _ => String::new(),
    }
}

fn agent_id(agent: &AgentView) -> String {
    agent_field(agent, "agent_id")
}

fn selected_agent_binding_matches(
    selected_agent_id: &str,
    controller_id: &arkret_sdk::DidCoreId,
    key_state: &KeyState,
) -> bool {
    arkret_sdk::DidCoreId::new(selected_agent_id.to_owned())
        .is_ok_and(|agent_id| agent_id == key_state.agent_id)
        && controller_id == &key_state.controller_id
}

fn agent_slug_label(agent: &AgentView) -> String {
    let slug = agent_field(agent, "slug");
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

fn requested_scope_matches_content_preset(
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

fn requested_scope_matches_service_preset(
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

fn agent_view_runtime_state(agent: &AgentView) -> AgentRuntimeState {
    agent
        .key_state
        .as_ref()
        .map(key_state_runtime_state)
        .unwrap_or_else(|| super::model::agent_projection_runtime_state(&agent.agent))
}

fn upsert_agent_view(rows: &mut Vec<AgentView>, view: AgentView) {
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

fn replace_agent_directory(rows: &mut Vec<AgentView>, directory_rows: Vec<AgentView>) {
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

#[cfg(test)]
mod directory_refresh_tests {
    use super::*;

    #[test]
    fn security_refresh_is_available_without_replacing_an_existing_runtime() {
        assert!(should_offer_security_refresh(true, "active"));
        assert!(should_offer_security_refresh(true, "paused"));
        assert!(!should_offer_security_refresh(false, "active"));
        assert!(!should_offer_security_refresh(true, "deactivated"));
    }

    #[test]
    fn agent_slug_input_is_trimmed_and_lowercased() {
        assert_eq!(normalize_agent_slug(" AA "), "aa");
        assert_eq!(normalize_agent_slug("Summary_V2"), "summary_v2");
    }

    #[test]
    fn directory_refresh_updates_status_without_dropping_loaded_details() {
        let mut rows = vec![AgentView {
            agent: test_agent_projection(
                AgentLifecycleState::Active,
                AgentRuntimeState::PendingRuntimeKey,
            ),
            grants: vec![arkret_sdk::GrantSnapshot {
                grant_id: arkret_sdk::GrantId::new(
                    "ak:grant:AdIokNbDGo5OV8uIK_7oyEOrSIU423PwmxNVThDeiPwQ",
                )
                .unwrap(),
                realm_id: arkret_sdk::RealmId::new(
                    "ak:realm:AYzH43fmsgS6dn7noiHeYxAKUUdkhaJBnOGaWvu3MlBC",
                )
                .unwrap(),
                grant_digest: None,
                expires_at: None,
            }],
            key_state: None,
        }];
        let directory_rows = vec![AgentView {
            agent: test_agent_projection(AgentLifecycleState::Active, AgentRuntimeState::Ready),
            grants: Vec::new(),
            key_state: None,
        }];

        replace_agent_directory(&mut rows, directory_rows);

        assert_eq!(rows[0].agent.lifecycle, AgentLifecycleState::Active);
        assert_eq!(
            crate::views::agents::model::agent_projection_runtime_state(&rows[0].agent),
            AgentRuntimeState::Ready
        );
        assert_eq!(
            rows[0].grants[0].grant_id.as_str(),
            "ak:grant:AdIokNbDGo5OV8uIK_7oyEOrSIU423PwmxNVThDeiPwQ"
        );
    }

    fn test_agent_projection(
        status: AgentLifecycleState,
        runtime_state: AgentRuntimeState,
    ) -> arkret_sdk::AgentProjection {
        arkret_sdk::AgentProjection {
            agent_id: crate::mls_api_helpers::principal_core_id("did:web:agents.example:summary")
                .unwrap(),
            display_name: None,
            slug: "summary".to_owned(),
            avatar_blob_ref: None,
            lifecycle: status,
            readiness: arkret_sdk::AgentReadiness {
                state: if runtime_state == AgentRuntimeState::Ready {
                    arkret_sdk::AgentReadinessState::Ready
                } else {
                    arkret_sdk::AgentReadinessState::NotReady
                },
                blockers: match runtime_state {
                    AgentRuntimeState::Ready => Vec::new(),
                    AgentRuntimeState::Replacing => {
                        vec![arkret_sdk::AgentReadinessBlocker::PairingOpen]
                    }
                    AgentRuntimeState::PendingRuntimeKey => vec![
                        arkret_sdk::AgentReadinessBlocker::RuntimeKeyMissing,
                        arkret_sdk::AgentReadinessBlocker::PairingOpen,
                    ],
                    AgentRuntimeState::PairingExpired => {
                        vec![arkret_sdk::AgentReadinessBlocker::RuntimeKeyMissing]
                    }
                },
            },
            presence: arkret_sdk::AgentPresence {
                state: arkret_sdk::AgentPresenceState::Unknown,
                expires_at: crate::clock::now_utc(),
                refresh_after: crate::clock::now_utc(),
            },
            created_at: None,
            updated_at: None,
        }
    }

    fn keyed_authorizations()
    -> Vec<arkret_models_collaboration::governance::agent_artifacts::AgentKeyAuthorizationState>
    {
        vec![
            arkret_models_collaboration::governance::agent_artifacts::AgentKeyAuthorizationState {
                key_id: arkret_sdk::NonEmptyString::new("runtime-key-1").unwrap(),
                verification_method: arkret_sdk::DidUrl::new(
                    "did:web:agents.example:summary#runtime-key-1",
                )
                .unwrap(),
                authorized_event_ref: arkret_sdk::EventId::new(
                    "ak:event:ASlHbbnJj2aIvNxwyukjGz90ltQwXHCbjIihxsRDrRR5",
                )
                .unwrap(),
                expires_at: None,
            },
        ]
    }

    #[test]
    fn requested_scope_restores_configured_content_capabilities() {
        let scope = requested_scope_for_presets(
            &[AgentGrantPreset::Read, AgentGrantPreset::ReplyAsAgent],
            &[AgentServiceScopePreset::SubscribeEvents],
        )
        .unwrap();

        assert!(requested_scope_matches_content_preset(
            Some(&scope),
            AgentGrantPreset::Read,
        ));
        assert!(requested_scope_matches_content_preset(
            Some(&scope),
            AgentGrantPreset::ReplyAsAgent,
        ));
        assert!(!requested_scope_matches_content_preset(
            Some(&scope),
            AgentGrantPreset::ActOnBehalf,
        ));
    }

    #[test]
    fn live_pairing_detail_overrides_lossy_directory_runtime_summary() {
        let mut row = test_pairing_view(
            AgentLifecycleState::Active,
            AgentRuntimeState::PendingRuntimeKey,
        );
        row.agent = test_agent_projection(
            AgentLifecycleState::Active,
            AgentRuntimeState::PairingExpired,
        );

        assert_eq!(
            agent_view_runtime_state(&row),
            AgentRuntimeState::PendingRuntimeKey
        );
    }

    #[test]
    fn selected_agent_binding_compares_stable_core_ids_directly() {
        let row = test_pairing_view(AgentLifecycleState::Active, AgentRuntimeState::Ready);
        let key_state = row.key_state.as_ref().unwrap();

        assert!(selected_agent_binding_matches(
            key_state.agent_id.as_str(),
            &key_state.controller_id,
            key_state,
        ));
        assert!(!selected_agent_binding_matches(
            "did:web:agents.example:summary",
            &key_state.controller_id,
            key_state,
        ));
        assert!(!selected_agent_binding_matches(
            key_state.agent_id.as_str(),
            &arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            key_state,
        ));
    }

    fn test_pairing_view(
        status: AgentLifecycleState,
        runtime_state: AgentRuntimeState,
    ) -> AgentView {
        let agent_id = arkret_sdk::project_did_to_core_id(
            &arkret_sdk::Did::new("did:web:agents.example:summary").unwrap(),
        )
        .unwrap();
        let controller_id = arkret_sdk::project_did_to_core_id(
            &arkret_sdk::Did::new("did:web:alice.example").unwrap(),
        )
        .unwrap();
        let scope = requested_scope_for_presets(
            &[AgentGrantPreset::Read],
            &AgentServiceScopePreset::DEFAULTS,
        )
        .unwrap();
        // Keyed agents (ready/replacing) carry an active authorization; never-keyed
        // agents (pending_runtime_key/pairing_expired) do not.
        let active_authorizations = match runtime_state {
            AgentRuntimeState::Ready | AgentRuntimeState::Replacing => keyed_authorizations(),
            AgentRuntimeState::PendingRuntimeKey | AgentRuntimeState::PairingExpired => Vec::new(),
        };
        AgentView {
            agent: test_agent_projection(status, runtime_state),
            grants: Vec::new(),
            key_state: Some(KeyState {
                agent_id,
                controller_id,
                principal_control_realm_id: arkret_sdk::RealmId::new(
                    "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5".to_owned(),
                )
                .unwrap(),
                controller_authorization_ref: arkret_sdk::DidUrl::new(
                    "did:web:agents.example:summary#managed-controller",
                )
                .unwrap(),
                requested_scope: scope,
                pairing_request_id: matches!(
                    runtime_state,
                    AgentRuntimeState::PendingRuntimeKey | AgentRuntimeState::Replacing
                )
                .then(|| arkret_sdk::OpaqueLocalId::new("pairing-request-1").unwrap()),
                pairing_mode: match runtime_state {
                    AgentRuntimeState::PendingRuntimeKey => Some(AgentPairingMode::Bootstrap),
                    AgentRuntimeState::Replacing => Some(AgentPairingMode::Replacement),
                    AgentRuntimeState::Ready | AgentRuntimeState::PairingExpired => None,
                },
                pairing_code: matches!(
                    runtime_state,
                    AgentRuntimeState::PendingRuntimeKey | AgentRuntimeState::Replacing
                )
                .then(|| "pairing-code".to_owned()),
                pairing_expires_at: matches!(
                    runtime_state,
                    AgentRuntimeState::PendingRuntimeKey | AgentRuntimeState::Replacing
                )
                .then(|| crate::clock::now_utc() + chrono::Duration::hours(1)),
                approval_request_id: None,
                pending_runtime_key_request: None,
                approval_requested_at: None,
                authorized_event_ref: None,
                active_authorizations,
            }),
        }
    }

    fn test_renew_outcome(mode: AgentPairingMode) -> AgentRenewPairingOutcome {
        let row = match mode {
            AgentPairingMode::Bootstrap => test_pairing_view(
                AgentLifecycleState::Active,
                AgentRuntimeState::PairingExpired,
            ),
            AgentPairingMode::Replacement => {
                test_pairing_view(AgentLifecycleState::Paused, AgentRuntimeState::Ready)
            }
        };
        let agent_did = row.agent.agent_id;
        let key_state = row.key_state.unwrap();
        let requested_scope_digest = arkret_signatures::agent::agent_requested_scope_digest(
            &key_state.agent_id,
            &key_state.controller_id,
            &key_state.requested_scope,
        )
        .unwrap();
        AgentRenewPairingOutcome {
            agent_id: agent_did,
            principal_control_realm_id: key_state.principal_control_realm_id,
            controller_authorization_ref: key_state.controller_authorization_ref,
            requested_scope_digest,
            pairing_mode: mode,
            pairing_request_id: arkret_sdk::OpaqueLocalId::new("pairing-request-2").unwrap(),
            pairing_code: Some("fresh-code".to_owned()),
            expires_at: chrono::DateTime::parse_from_rfc3339("2099-07-18T01:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        }
    }

    #[test]
    fn bootstrap_renewal_reopens_expired_agent_and_exposes_fresh_material() {
        let mut rows = vec![test_pairing_view(
            AgentLifecycleState::Active,
            AgentRuntimeState::PairingExpired,
        )];
        let outcome = test_renew_outcome(AgentPairingMode::Bootstrap);
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-18T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        apply_renewed_pairing(&mut rows, outcome.agent_id.as_str(), &outcome, now).unwrap();

        // Bootstrap re-open preserves the lifecycle intent and moves only the
        // derived runtime_state back to pending_runtime_key.
        assert_eq!(rows[0].agent.lifecycle, AgentLifecycleState::Active);
        let key_state = rows[0].key_state.as_ref().unwrap();
        assert_eq!(
            crate::views::agents::model::key_state_runtime_state(key_state),
            AgentRuntimeState::PendingRuntimeKey
        );
        assert_eq!(key_state.pairing_code.as_deref(), Some("fresh-code"));
    }

    #[test]
    fn replacement_renewal_preserves_lifecycle_and_projects_replacing() {
        let mut rows = vec![test_pairing_view(
            AgentLifecycleState::Paused,
            AgentRuntimeState::Ready,
        )];
        let outcome = test_renew_outcome(AgentPairingMode::Replacement);
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-18T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        apply_renewed_pairing(&mut rows, outcome.agent_id.as_str(), &outcome, now).unwrap();

        // Runtime replacement preserves the lifecycle intent (paused stays
        // paused; an active agent would stay active) and only projects the
        // derived runtime_state as replacing (key-management.md §3.6.1).
        assert_eq!(rows[0].agent.lifecycle, AgentLifecycleState::Paused);
        let key_state = rows[0].key_state.as_ref().unwrap();
        assert_eq!(
            crate::views::agents::model::key_state_runtime_state(key_state),
            AgentRuntimeState::Replacing
        );
        assert_eq!(key_state.pairing_code.as_deref(), Some("fresh-code"));
    }
}

fn update_agent_status(rows: &mut [AgentView], id: &str, status: AgentLifecycleState) {
    for row in rows.iter_mut() {
        if agent_id(row) == id {
            row.agent.lifecycle = status;
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum PairingActionPhase {
    #[default]
    Idle,
    RepairingRecovery,
    IssuingPairing,
    RefreshingAgent,
}

fn apply_renewed_pairing(
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
        &key_state.controller_id,
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

async fn renew_agent_pairing(
    base: String,
    api_token: String,
    agent_id: String,
) -> Result<AgentRenewPairingOutcome, crate::transport::auth::ApiCallError> {
    with_authed_sdk_client(&base, api_token, move |http| {
        let agent_id = agent_id.clone();
        async move {
            http.agent_renew_pairing(
                &agent_id,
                &arkret_models_collaboration::agent_operations::AgentRenewPairingRequestBody::default(),
            )
            .await
            .map_err(anyhow::Error::from)
        }
    })
    .await
}

const AGENT_LIST_FILTERS: [(&str, &str); 3] =
    [("all", "All"), ("active", "Active"), ("paused", "Paused")];

fn normalize_agent_filter(filter: &str) -> &'static str {
    match filter.trim().to_ascii_lowercase().as_str() {
        "active" => "active",
        "paused" => "paused",
        "deactivated" => "deactivated",
        _ => "all",
    }
}

fn agent_matches_filter(status: &str, filter: &str) -> bool {
    match filter {
        "active" => status == "active",
        "paused" => status == "paused",
        "deactivated" => status == "deactivated",
        _ => status != "deactivated",
    }
}

fn spawn_refresh_agents(
    base: String,
    api_token: String,
    mut agents: Signal<Vec<AgentView>>,
    mut list_status: Signal<String>,
    mut refresh_epoch: Signal<u64>,
) {
    let request_epoch = (*refresh_epoch.peek()).saturating_add(1);
    refresh_epoch.set(request_epoch);
    spawn(async move {
        crate::runtime_helpers::sleep_for(Duration::from_millis(1)).await;
        if api_token.trim().is_empty() {
            if *refresh_epoch.peek() != request_epoch {
                return;
            }
            list_status.set("Sign in to load your agents.".to_owned());
            return;
        }
        match with_authed_sdk_client(&base, api_token, |http| async move {
            http.agent_list().await.map_err(anyhow::Error::from)
        })
        .await
        {
            Ok(resp) => {
                if *refresh_epoch.peek() != request_epoch {
                    return;
                }
                let total = resp.agent_projections.len();
                let rows: Vec<AgentView> = resp
                    .agent_projections
                    .into_iter()
                    .filter_map(agent_view_from_directory_row)
                    .collect();
                let skipped = total.saturating_sub(rows.len());
                if skipped > 0 {
                    list_status.set(format!("Skipped {} invalid agent row(s).", skipped,));
                } else {
                    list_status.set(String::new());
                }
                agents.with_mut(|current| replace_agent_directory(current, rows));
            }
            Err(err) => {
                if *refresh_epoch.peek() != request_epoch {
                    return;
                }
                list_status.set(format!("Failed to load agents: {}", err.display()));
            }
        }
    });
}

async fn fetch_agent_details(
    base: &str,
    api_token: &str,
    id: &str,
) -> Result<AgentView, crate::transport::auth::ApiCallError> {
    let id = id.to_owned();
    with_authed_sdk_client(base, api_token.to_owned(), move |http| {
        let id = id.clone();
        async move { http.agent_get(&id).await.map_err(anyhow::Error::from) }
    })
    .await
}

fn spawn_load_agent_details(
    base: String,
    api_token: String,
    id: String,
    mut agents: Signal<Vec<AgentView>>,
    mut last_op_status: Signal<String>,
) {
    spawn(async move {
        if id.trim().is_empty() {
            return;
        }
        match fetch_agent_details(&base, &api_token, &id).await {
            Ok(view) => {
                agents.with_mut(|rows| upsert_agent_view(rows, view));
            }
            Err(err) => {
                last_op_status.set(format!("Failed to load agent details: {}", err.display()))
            }
        }
    });
}

/// Notify the Contacts sidebar that this account's owned-agent set changed, so
/// it re-pulls `agent_list`. Signal-based (not `SessionContext::get()`) because
/// callers bump from inside spawned futures, where hooks must not run; the
/// `Signal<u64>` is captured during render and moved in.
fn bump_owned_agents_rev(mut owned_agents_rev: Signal<u64>) {
    let next = owned_agents_rev.peek().saturating_add(1);
    owned_agents_rev.set(next);
}

fn spawn_set_agent_enabled(
    base: String,
    api_token: String,
    id: String,
    controller_id: arkret_sdk::DidCoreId,
    key_state: Option<KeyState>,
    enabled: bool,
    mut agents: Signal<Vec<AgentView>>,
    mut last_op_status: Signal<String>,
    owned_agents_rev: Signal<u64>,
    // DID-P2-B: the account-level accepted-binding handle, captured during
    // render and moved into the spawned future. Passed explicitly (not read
    // from a context/global inside the future) because hooks must not run
    // there and because the acceptance must be filed under the account the
    // caller meant.
    state_store: dioxus::prelude::SyncSignal<crate::state::LocalStateStore>,
) {
    spawn(async move {
        if id.is_empty() {
            return;
        }
        let Some(key_state) = key_state else {
            last_op_status.set(
                "Agent key binding is unavailable; refresh the Agent details and retry.".to_owned(),
            );
            return;
        };
        if !selected_agent_binding_matches(&id, &controller_id, &key_state) {
            last_op_status.set(
                "Agent key binding does not match the selected Agent and controller; refresh and retry."
                    .to_owned(),
            );
            return;
        }
        let id_for_status = id.clone();
        let status_changed_at = crate::clock::now_utc_millis();
        let station_id = match crate::operation::authoring_station_id() {
            Ok(station_id) => station_id,
            Err(error) => {
                last_op_status.set(format!("Station route is unavailable: {error}"));
                return;
            }
        };
        let agent_actor_id = arkret_sdk::ActorId::service(key_state.agent_id.clone());
        let controller_actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            key_state.controller_id.clone(),
            station_id,
        ));
        let intent = if enabled {
            arkret_event_draft::build_agent_resume_intent(
                agent_actor_id.clone(),
                controller_actor_id.clone(),
                arkret_sdk::ScopeRef::Realm {
                    realm_id: key_state.principal_control_realm_id.clone(),
                },
                key_state.controller_authorization_ref.clone(),
                status_changed_at,
            )
        } else {
            let pause_reason = match arkret_sdk::AuditReasonText::new("controller_paused") {
                Ok(reason) => reason,
                Err(error) => {
                    last_op_status.set(format!("Agent pause reason is invalid: {error}"));
                    return;
                }
            };
            arkret_event_draft::build_agent_pause_intent(
                agent_actor_id.clone(),
                controller_actor_id,
                arkret_sdk::ScopeRef::Realm {
                    realm_id: key_state.principal_control_realm_id.clone(),
                },
                key_state.controller_authorization_ref.clone(),
                Some(pause_reason),
                status_changed_at,
            )
        };
        let operation = match intent {
            Ok(intent) => crate::operation::LocalOperation::new(intent),
            Err(error) => {
                last_op_status.set(format!("Agent lifecycle authoring failed: {error}"));
                return;
            }
        };
        let result = with_event_submitter(&base, api_token, move |submitter| async move {
            let account = crate::app::SessionContext::get()
                .active_account()
                .ok_or_else(|| anyhow::anyhow!("active controller account is unavailable"))?;
            anyhow::ensure!(
                account.principal_id() == &controller_id,
                "active controller authority changed before lifecycle submission"
            );
            let signer = crate::event_signer::active_signer()
                .ok_or_else(|| anyhow::anyhow!("active controller signer is unavailable"))?;
            let signer_account_scope = crate::secure_key_store::active_device_seed_scope();
            let device_id = super::bootstrap::controller_signer_device_id(
                account.did(),
                &account.authority,
                signer.as_ref(),
                signer_account_scope.as_ref(),
            )?;
            super::bootstrap::ensure_agent_pcr_seal_current(
                &submitter,
                submitter.http(),
                signer.as_ref(),
                account.did(),
                device_id.as_str(),
                &agent_actor_id,
                key_state.principal_control_realm_id.as_str(),
                state_store,
            )
            .await?;
            // The lifecycle Event rides its own request body rather than the
            // durable submit queue, so it is authored here and positioned by the
            // same submitter that reads the accepted actor frontier.
            let draft = submitter.author_for_direct_submission(&operation).await?;
            let lifecycle_event = submitter
                .prepare_initial_submissions(std::slice::from_ref(&draft))
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("lifecycle submission is missing"))?;
            let outcome = if enabled {
                let body = AgentResumeRequestBody { lifecycle_event };
                submitter
                    .http()
                    .agent_resume(&id, &body)
                    .await
                    .map_err(anyhow::Error::from)?
            } else {
                let body = AgentPauseRequestBody {
                    reason: Some(
                        arkret_sdk::AuditReasonText::new("controller_paused")
                            .map_err(anyhow::Error::msg)?,
                    ),
                    lifecycle_event,
                };
                submitter
                    .http()
                    .agent_pause(&id, &body)
                    .await
                    .map_err(anyhow::Error::from)?
            };
            let post_seal_warning = super::bootstrap::ensure_agent_pcr_seal_current(
                &submitter,
                submitter.http(),
                signer.as_ref(),
                account.did(),
                device_id.as_str(),
                &agent_actor_id,
                key_state.principal_control_realm_id.as_str(),
                state_store,
            )
            .await
            .err()
            .map(|error| error.to_string());
            Ok((outcome, post_seal_warning))
        })
        .await;
        match result {
            Ok((outcome, seal_warning)) => {
                let status = outcome.status;
                let status_wire = agent_lifecycle_wire(status);
                agents.with_mut(|rows| update_agent_status(rows, &id_for_status, status));
                bump_owned_agents_rev(owned_agents_rev);
                let mut message = if enabled {
                    format!("Resumed. Status: {status_wire}.")
                } else {
                    format!("Paused. Status: {status_wire}.")
                };
                if let Some(warning) = seal_warning {
                    message.push_str(&format!(" Seal refresh warning: {warning}"));
                }
                last_op_status.set(message);
            }
            Err(err) => last_op_status.set(format!(
                "{} failed: {}",
                if enabled { "Resume" } else { "Pause" },
                err.display()
            )),
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn spawn_deactivate_agent(
    base: String,
    api_token: String,
    id: String,
    controller_id: arkret_sdk::DidCoreId,
    status: AgentLifecycleState,
    key_state: Option<KeyState>,
    mut agents: Signal<Vec<AgentView>>,
    mut last_op_status: Signal<String>,
    mut deactivate_dialog_open: Signal<bool>,
    mut deactivate_confirm: Signal<String>,
    owned_agents_rev: Signal<u64>,
) {
    spawn(async move {
        if id.is_empty() {
            return;
        }
        let Some(key_state) = key_state else {
            last_op_status.set(
                "Agent key binding is unavailable; refresh the Agent details and retry.".to_owned(),
            );
            return;
        };
        if !selected_agent_binding_matches(&id, &controller_id, &key_state) {
            last_op_status.set(
                "Agent key binding does not match the selected Agent and controller; refresh and retry."
                    .to_owned(),
            );
            return;
        }
        if status == AgentLifecycleState::Deactivated {
            last_op_status.set("Agent is already deactivated.".to_owned());
            return;
        }

        let reason = match arkret_sdk::AuditReasonText::new("controller_deactivated") {
            Ok(reason) => reason,
            Err(error) => {
                last_op_status.set(format!("Agent deactivation reason is invalid: {error}"));
                return;
            }
        };
        let changed_at = crate::clock::now_utc_millis();
        let station_id = match crate::operation::authoring_station_id() {
            Ok(station_id) => station_id,
            Err(error) => {
                last_op_status.set(format!("Station route is unavailable: {error}"));
                return;
            }
        };
        let agent_actor_id = arkret_sdk::ActorId::service(key_state.agent_id.clone());
        let controller_actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            key_state.controller_id.clone(),
            station_id,
        ));
        let operation = match arkret_event_draft::build_agent_deactivate_intent(
            agent_actor_id,
            controller_actor_id,
            arkret_sdk::ScopeRef::Realm {
                realm_id: key_state.principal_control_realm_id.clone(),
            },
            key_state.controller_authorization_ref.clone(),
            status,
            Some(reason.clone()),
            changed_at,
        ) {
            Ok(intent) => crate::operation::LocalOperation::new(intent),
            Err(error) => {
                last_op_status.set(format!("Agent deactivation authoring failed: {error}"));
                return;
            }
        };

        let id_for_status = id.clone();
        let refresh_api_token = api_token.clone();
        let result = with_event_submitter(&base, api_token, move |submitter| async move {
            // Carried in the deactivate request body, so it is authored here
            // against the accepted actor frontier rather than queued.
            let authored = submitter.author_for_direct_submission(&operation).await?;
            let lifecycle_event = submitter
                .prepare_initial_submissions(std::slice::from_ref(&authored))
                .await?
                .pop()
                .ok_or_else(|| anyhow::anyhow!("deactivation lifecycle Event is missing"))?;
            let body = AgentDeactivateRequestBody {
                reason: Some(reason),
                lifecycle_event,
            };
            submitter
                .http()
                .agent_deactivate(&id, &body)
                .await
                .map_err(anyhow::Error::from)
        })
        .await;

        match result {
            Ok(outcome) => {
                agents.with_mut(|rows| update_agent_status(rows, &id_for_status, outcome.status));
                bump_owned_agents_rev(owned_agents_rev);
                // Deactivation revokes the Agent key and closes its principal-
                // control Realm. Refreshing that Realm's Seal afterwards is
                // both unnecessary and expected to return 404.
                last_op_status.set("Agent deactivated permanently.".to_owned());
                deactivate_dialog_open.set(false);
                deactivate_confirm.set(String::new());
            }
            Err(error) => {
                last_op_status.set(format!("Deactivate failed: {}", error.display()));
                spawn_load_agent_details(
                    base,
                    refresh_api_token,
                    id_for_status,
                    agents,
                    last_op_status,
                );
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn spawn_provision_agent(
    base: String,
    api_token: String,
    controller_id: arkret_sdk::DidCoreId,
    slug: String,
    _avatar_blob_ref: Option<arkret_sdk::BlobRef>,
    content_presets: Vec<AgentGrantPreset>,
    service_scopes: Vec<AgentServiceScopePreset>,
    agents: Signal<Vec<AgentView>>,
    list_status: Signal<String>,
    refresh_epoch: Signal<u64>,
    mut selected_agent_id: Signal<String>,
    mut create_mode: Signal<bool>,
    mut new_agent_avatar_blob_ref: Signal<String>,
    mut last_op_status: Signal<String>,
    owned_agents_rev: Signal<u64>,
    state_store: dioxus::prelude::SyncSignal<crate::state::LocalStateStore>,
) {
    spawn(async move {
        let account = match crate::app::SessionContext::get().active_account() {
            Some(account) => account,
            None => {
                last_op_status
                    .set("Create failed: active controller account is unavailable".to_owned());
                return;
            }
        };
        if account.principal_id() != &controller_id {
            last_op_status.set("Create failed: active controller authority changed".to_owned());
            return;
        }
        let slug = normalize_agent_slug(&slug);
        if slug.is_empty() {
            last_op_status.set("Slug is required.".to_owned());
            return;
        }
        if let Err(error) = arkret_models_identity::validate_agent_slug(&slug) {
            last_op_status.set(format!("Slug is invalid: {error}"));
            return;
        }
        let controller_did = account.did().clone();
        let (controller_recovery_evidence, controller_station_id) = match state_store
            .read()
            .recovery_material_evidence()
        {
            Some(evidence)
                if evidence.controller_authority.as_ref() == Some(&account.authority)
                    && evidence.principal_did == controller_did =>
            {
                let station_id = evidence
                    .controller_authority
                    .as_ref()
                    .map(|authority| authority.station_id.clone());
                match station_id {
                    Some(station_id) => (evidence, station_id),
                    None => unreachable!("the guarded evidence has an authority pair"),
                }
            }
            Some(_) => {
                last_op_status.set(
                    "Create failed: the saved controller PCR evidence does not match the signed-in identity and authority pair. Refresh identity recovery material before provisioning an Agent."
                        .to_owned(),
                );
                return;
            }
            None => {
                last_op_status.set(
                    "Create failed: this device has no controller authority pair. Refresh identity recovery material before provisioning an Agent."
                        .to_owned(),
                );
                return;
            }
        };
        let Some(requested_scope) = requested_scope_for_presets(&content_presets, &service_scopes)
        else {
            last_op_status.set("Select at least one runtime service surface.".to_owned());
            return;
        };
        let nonce = crate::operation::uuid_v7();
        let agent_did_local_id = format!("agent-{nonce}");
        let operation_id = match arkret_sdk::ProtocolOperationId::new(format!(
            "ak:operation:agent.provision.{nonce}"
        )) {
            Ok(value) => value,
            Err(error) => {
                last_op_status.set(format!("Create failed: operation id: {error}"));
                return;
            }
        };
        let idempotency_key = match arkret_sdk::IdempotencyKey::new(nonce) {
            Ok(value) => value,
            Err(error) => {
                last_op_status.set(format!("Create failed: idempotency key: {error}"));
                return;
            }
        };
        let (agent_inception, agent_did_keys) = match crate::agent_identity::prepare_inception(
            &base,
            &agent_did_local_id,
            &controller_id,
        ) {
            Ok(value) => value,
            Err(error) => {
                last_op_status.set(format!("Create failed: Agent DID inception: {error}"));
                return;
            }
        };
        let did = match arkret_sdk::Did::new(agent_inception.did.clone()) {
            Ok(value) => value,
            Err(error) => {
                last_op_status.set(format!("Create failed: generated Agent DID: {error}"));
                return;
            }
        };
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        if let Err(error) = crate::agent_identity::store_keys_durable(
            secure_store.as_ref(),
            did.as_str(),
            &agent_did_keys,
        )
        .await
        {
            last_op_status.set(format!(
                "Create failed: persist Agent DID update keys before inception: {error}"
            ));
            return;
        }
        let inception_submit = agent_inception.submit_body.clone();
        let inception_outcome =
            match with_authed_sdk_client(&base, api_token.clone(), move |http| {
                let inception_submit = inception_submit.clone();
                async move {
                    crate::transport::account::submit_did_operation(&http, &inception_submit).await
                }
            })
            .await
            {
                Ok(value) => value,
                Err(error) => {
                    last_op_status.set(format!(
                        "Create failed: publish Agent DID inception: {}",
                        error.display()
                    ));
                    return;
                }
            };
        if inception_outcome.did != did {
            last_op_status.set("Create failed: inception response DID mismatch".to_owned());
            return;
        }
        if inception_outcome.status == arkret_sdk::DidOperationSubmitStatus::Pending {
            last_op_status.set(
                "Agent DID inception is pending acceptance; retry creation after it is accepted."
                    .to_owned(),
            );
            return;
        }
        let prepare = AgentProvisionRequestBody::Prepare {
            operation_id: operation_id.clone(),
            idempotency_key: idempotency_key.clone(),
            did: did.clone(),
            controller_station_id,
            slug: slug.clone(),
            requested_scope: requested_scope.clone(),
            pairing_ttl_ms: None,
        };
        let preparation = match with_authed_sdk_client(&base, api_token.clone(), move |http| {
            let prepare = prepare.clone();
            async move {
                http.agent_provision(&prepare)
                    .await
                    .map_err(anyhow::Error::from)
            }
        })
        .await
        {
            Ok(AgentProvisionOutcome::AwaitingControllerEvent {
                agent_id,
                did: returned_did,
                initial_resolution,
                controller_realm_id,
                allocation_handle,
                controller_authorization_ref,
                requested_scope_digest,
            }) if returned_did == did => (
                agent_id,
                returned_did,
                initial_resolution,
                controller_realm_id,
                allocation_handle,
                controller_authorization_ref,
                requested_scope_digest,
            ),
            Ok(AgentProvisionOutcome::AwaitingPcrGenesis { .. }) => {
                last_op_status
                    .set("Create failed: prepare returned a committed allocation".to_owned());
                return;
            }
            Ok(AgentProvisionOutcome::Complete { .. }) => {
                last_op_status
                    .set("Create failed: prepare returned a completed allocation".to_owned());
                return;
            }
            Ok(AgentProvisionOutcome::AwaitingDidBinding { .. }) => {
                last_op_status.set(
                    "Create failed: prepare returned an allocation awaiting DID binding".to_owned(),
                );
                return;
            }
            Ok(AgentProvisionOutcome::AwaitingControllerEvent { .. }) => {
                last_op_status
                    .set("Create failed: prepare returned a different Agent DID".to_owned());
                return;
            }
            Err(error) => {
                last_op_status.set(format!("Create failed: {}", error.display()));
                return;
            }
        };
        let (
            agent_id,
            did,
            initial_resolution,
            controller_realm_id,
            allocation_handle,
            controller_authorization_ref,
            expected_digest,
        ) = preparation;
        let prepared_inception_head =
            match crate::canonical::canonical_sha256(&agent_inception.log_entry) {
                Ok(value) => value,
                Err(error) => {
                    last_op_status.set(format!(
                        "Create failed: digest Agent DID inception: {error}"
                    ));
                    return;
                }
            };
        if initial_resolution.did != did
            || initial_resolution.version_id != agent_inception.version_id
            || initial_resolution.method_history_head != prepared_inception_head
        {
            last_op_status.set(
                "Create failed: server did not pin the exact accepted Agent DID inception"
                    .to_owned(),
            );
            return;
        }
        let projected_agent_id = match arkret_sdk::project_did_to_core_id(&did) {
            Ok(value) => value,
            Err(error) => {
                last_op_status.set(format!("Create failed: allocated DID: {error}"));
                return;
            }
        };
        if projected_agent_id != agent_id {
            last_op_status.set(
                "Create failed: allocated DID does not project to the allocated Agent ID"
                    .to_owned(),
            );
            return;
        }
        let observed_digest = match arkret_signatures::agent::agent_requested_scope_digest(
            &agent_id,
            &controller_id,
            &requested_scope,
        ) {
            Ok(value) => value,
            Err(error) => {
                last_op_status.set(format!("Create failed: requested scope digest: {error}"));
                return;
            }
        };
        if observed_digest != expected_digest {
            last_op_status.set("Create failed: server allocation scope digest mismatch".to_owned());
            return;
        }
        if controller_recovery_evidence.principal_control_realm_id != controller_realm_id {
            last_op_status.set(
                "Create failed: the server allocation controller PCR does not match this device's verified bootstrap evidence."
                    .to_owned(),
            );
            return;
        }
        let controller_pcr_create = controller_recovery_evidence
            .pcr_genesis_unit
            .create()
            .clone();
        let controller_realm_for_checkpoint = controller_realm_id.clone();
        let controller_evidence_for_checkpoint = controller_recovery_evidence.clone();
        if let Err(error) = with_authed_api(&base, api_token.clone(), move |api| async move {
            crate::recovery_strand::verify_recovery_authority_evidence(
                &api,
                &controller_evidence_for_checkpoint,
            )
            .await?;
            crate::mls::creator_bootstrap::ensure_realm_governance_checkpoint(
                &api,
                state_store,
                controller_realm_for_checkpoint.as_str(),
            )
            .await
            .map_err(anyhow::Error::msg)
        })
        .await
        {
            last_op_status.set(format!(
                "Create failed: verify Controller PCR governance checkpoint: {}",
                error.display()
            ));
            return;
        }
        let agent_notary = match crate::event_builders::agent_inception_notary(
            &did,
            &agent_inception.root_public_key_multibase,
        ) {
            Ok(value) => value,
            Err(error) => {
                last_op_status.set(format!("Create failed: freeze Agent notary: {error}"));
                return;
            }
        };
        // Freeze and sign the exact Agent PCR create before authoring
        // the provision Event.  Its content-derived EventId is the only source
        // of the PCR Realm id carried by that provision declaration.
        let frozen_genesis = match with_event_submitter(&base, api_token.clone(), {
            let agent_id = agent_id.clone();
            let initial_resolution = initial_resolution.clone();
            let agent_notary = agent_notary.clone();
            let controller_id = controller_id.clone();
            let controller_authorization_ref = controller_authorization_ref.clone();
            move |submitter| async move {
                let describe = submitter.events_describe().await?;
                let draft = crate::event_builders::build_agent_pcr_create_event(
                    agent_id.as_str(),
                    initial_resolution,
                    agent_notary,
                    controller_id.as_str(),
                    controller_authorization_ref.as_str(),
                    describe.trust_domain.as_str(),
                )?;
                // A Agent PCR genesis is a one-Event unit: the create
                // names the Realm, so it is authored as a unit and its shape is
                // proven on the authored result.
                let intent = draft.into_intent();
                submitter
                    .author_event_unit(vec![Box::new(move |_| Ok(vec![intent]))])
                    .await?
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("prepared Agent PCR genesis is missing"))
            }
        })
        .await
        {
            Ok(value) => value,
            Err(error) => {
                last_op_status.set(format!(
                    "Create failed: freeze Agent PCR genesis: {}",
                    error.display()
                ));
                return;
            }
        };
        let principal_control_realm_id = frozen_genesis.realm_id.clone();
        let controller_station_id = match crate::operation::authoring_station_id() {
            Ok(value) => value,
            Err(error) => {
                last_op_status.set(format!(
                    "Create failed: resolve controller Station: {error}"
                ));
                return;
            }
        };
        let draft = match build_agent_provision_intent(
            &controller_did,
            &controller_station_id,
            &controller_realm_id,
            &agent_id,
            &principal_control_realm_id,
            &controller_authorization_ref,
            &slug,
            &expected_digest,
        ) {
            Ok(value) => value,
            Err(error) => {
                last_op_status.set(format!("Create failed: author provision Event: {error}"));
                return;
            }
        };
        let provision_event =
            match with_event_submitter(&base, api_token.clone(), move |submitter| async move {
                let authored = submitter
                    .author_independent_events(vec![draft.into_intent()])
                    .await?;
                let authored = authored
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("prepared provision Event is missing"))?;
                submitter.prepare_authority_authored_self_principal_submission(
                    authored,
                    &controller_pcr_create,
                )
            })
            .await
            {
                Ok(value) => value,
                Err(error) => {
                    last_op_status.set(format!(
                        "Create failed: sign provision Event: {}",
                        error.display()
                    ));
                    return;
                }
            };
        let provision_event_id = provision_event.event.event_id.clone();
        let commit = AgentProvisionRequestBody::Commit {
            operation_id,
            idempotency_key,
            agent_id: agent_id.clone(),
            did: did.clone(),
            principal_control_realm_id: principal_control_realm_id.clone(),
            allocation_handle: allocation_handle.clone(),
            slug: slug.clone(),
            requested_scope,
            provision_event: Box::new(provision_event),
            pairing_ttl_ms: None,
        };
        let commit_for_first_request = commit.clone();
        match with_authed_sdk_client(&base, api_token.clone(), move |http| async move {
            http.agent_provision(&commit_for_first_request)
                .await
                .map_err(anyhow::Error::from)
        })
        .await
        {
            Ok(AgentProvisionOutcome::AwaitingPcrGenesis {
                agent_id: returned_agent_id,
                did: returned_did,
                initial_resolution: returned_resolution,
                principal_control_realm_id: returned_realm_id,
                allocation_handle: returned_allocation,
                controller_authorization_ref: returned_authorization,
                requested_scope_digest: returned_digest,
            }) if returned_agent_id == agent_id
                && returned_did == did
                && returned_resolution == initial_resolution
                && returned_realm_id == principal_control_realm_id
                && returned_allocation == allocation_handle
                && returned_authorization == controller_authorization_ref
                && returned_digest == expected_digest => {}
            Ok(AgentProvisionOutcome::AwaitingPcrGenesis { .. }) => {
                last_op_status.set(
                    "Create failed: commit returned mismatched PCR authoring coordinates"
                        .to_owned(),
                );
                return;
            }
            Ok(AgentProvisionOutcome::Complete { .. }) => {
                last_op_status.set(
                    "Create failed: commit completed before the declared PCR genesis was submitted"
                        .to_owned(),
                );
                return;
            }
            Ok(AgentProvisionOutcome::AwaitingControllerEvent { .. }) => {
                last_op_status.set("Create failed: commit returned another preparation".to_owned());
                return;
            }
            Ok(AgentProvisionOutcome::AwaitingDidBinding { .. }) => {
                last_op_status.set(
                    "Create failed: commit requested DID binding before PCR acceptance".to_owned(),
                );
                return;
            }
            Err(error) => {
                last_op_status.set(format!("Create failed: {}", error.display()));
                return;
            }
        };
        let controller_realm_for_seal = controller_realm_id.clone();
        let controller_did_for_seal = controller_did.clone();
        if let Err(error) = with_authed_api(&base, api_token.clone(), move |api| async move {
            super::bootstrap::seal_self_principal_event_current(
                &api,
                &controller_did_for_seal,
                &controller_realm_for_seal,
                &provision_event_id,
            )
            .await
            .map(|_| ())
        })
        .await
        {
            last_op_status.set(format!(
                "Agent provision Event accepted, but Controller PCR Seal failed: {}",
                error.display()
            ));
            return;
        }
        let genesis_idempotency_key = frozen_genesis.event_id.to_string();
        let genesis_for_submit = frozen_genesis.clone();
        if let Err(error) =
            with_event_submitter(&base, api_token.clone(), move |submitter| async move {
                submitter
                    .submit_signed_sdk_events_batch(
                        std::slice::from_ref(&genesis_for_submit),
                        Some(&genesis_idempotency_key),
                    )
                    .await
                    .map(|_| ())
            })
            .await
        {
            last_op_status.set(format!(
                "Agent provision accepted, but PCR genesis submission failed: {}",
                error.display()
            ));
            return;
        }
        let pcr_realm_for_seal = principal_control_realm_id.clone();
        let agent_id_for_seal = agent_id.clone();
        let state_store_for_seal = state_store;
        let account_for_seal = account.clone();
        if let Err(error) = with_authed_api(&base, api_token.clone(), move |api| async move {
            super::bootstrap::seal_agent_pcr_current(
                &api,
                state_store_for_seal,
                &account_for_seal,
                &agent_id_for_seal,
                &pcr_realm_for_seal,
            )
            .await
            .map(|_| ())
        })
        .await
        {
            last_op_status.set(format!(
                "Agent PCR genesis accepted, but its Controller Seal failed: {}",
                error.display()
            ));
            return;
        }
        let commit_for_pcr_check = commit.clone();
        let binding_coordinates =
            match with_authed_sdk_client(&base, api_token.clone(), move |http| async move {
                http.agent_provision(&commit_for_pcr_check)
                    .await
                    .map_err(anyhow::Error::from)
            })
            .await
            {
                Ok(AgentProvisionOutcome::AwaitingDidBinding {
                    agent_id: returned_agent_id,
                    did: returned_did,
                    initial_resolution: returned_resolution,
                    principal_control_realm_id: returned_realm_id,
                    allocation_handle: returned_allocation,
                    controller_authorization_ref: returned_authorization,
                    requested_scope_digest: returned_digest,
                }) if returned_agent_id == agent_id
                    && returned_did == did
                    && returned_resolution == initial_resolution
                    && returned_realm_id == principal_control_realm_id
                    && returned_allocation == allocation_handle
                    && returned_authorization == controller_authorization_ref
                    && returned_digest == expected_digest =>
                {
                    (returned_realm_id, returned_digest)
                }
                Ok(AgentProvisionOutcome::AwaitingDidBinding { .. }) => {
                    last_op_status.set(
                        "Create failed: PCR acceptance returned mismatched DID-binding coordinates"
                            .to_owned(),
                    );
                    return;
                }
                Ok(AgentProvisionOutcome::Complete { .. }) => {
                    last_op_status.set(
                    "Create failed: Agent became visible before its DID PCR binding was accepted"
                        .to_owned(),
                );
                    return;
                }
                Ok(AgentProvisionOutcome::AwaitingPcrGenesis { .. }) => {
                    last_op_status.set(
                        "Create failed: PCR genesis was accepted but provisioning did not finalize"
                            .to_owned(),
                    );
                    return;
                }
                Ok(AgentProvisionOutcome::AwaitingControllerEvent { .. }) => {
                    last_op_status
                        .set("Create failed: final commit returned another preparation".to_owned());
                    return;
                }
                Err(error) => {
                    last_op_status.set(format!("Create failed: {}", error.display()));
                    return;
                }
            };
        let binding_update = match crate::agent_identity::prepare_binding_update(
            &agent_inception,
            &agent_did_keys,
            &controller_id,
            &binding_coordinates.0,
            &binding_coordinates.1,
        ) {
            Ok(value) => value,
            Err(error) => {
                last_op_status.set(format!(
                    "Create failed: build Agent DID PCR binding: {error}"
                ));
                return;
            }
        };
        let binding_submit = binding_update.submit_body.clone();
        let binding_outcome =
            match with_authed_sdk_client(&base, api_token.clone(), move |http| {
                let binding_submit = binding_submit.clone();
                async move {
                    crate::transport::account::submit_did_operation(&http, &binding_submit).await
                }
            })
            .await
            {
                Ok(value) => value,
                Err(error) => {
                    last_op_status.set(format!(
                        "Agent PCR accepted, but DID PCR binding publication failed: {}",
                        error.display()
                    ));
                    return;
                }
            };
        if binding_outcome.did != did
            || binding_outcome.status == arkret_sdk::DidOperationSubmitStatus::Pending
        {
            last_op_status.set(
                "Agent PCR accepted, but its DID binding is still pending acceptance.".to_owned(),
            );
            return;
        }
        let outcome =
            match with_authed_sdk_client(&base, api_token.clone(), move |http| async move {
                http.agent_provision(&commit)
                    .await
                    .map_err(anyhow::Error::from)
            })
            .await
            {
                Ok(AgentProvisionOutcome::Complete { outcome }) => outcome,
                Ok(AgentProvisionOutcome::AwaitingDidBinding { .. }) => {
                    last_op_status.set(
                        "Create failed: DID binding was accepted but provisioning did not finalize"
                            .to_owned(),
                    );
                    return;
                }
                Ok(AgentProvisionOutcome::AwaitingPcrGenesis { .. }) => {
                    last_op_status.set(
                        "Create failed: final commit lost the accepted PCR genesis".to_owned(),
                    );
                    return;
                }
                Ok(AgentProvisionOutcome::AwaitingControllerEvent { .. }) => {
                    last_op_status
                        .set("Create failed: final commit returned another preparation".to_owned());
                    return;
                }
                Err(error) => {
                    last_op_status.set(format!("Create failed: {}", error.display()));
                    return;
                }
            };
        let bootstrap_outcome = outcome.clone();
        let account_for_bootstrap = account;
        if let Err(error) = with_authed_api(&base, api_token.clone(), move |api| async move {
            super::bootstrap::bootstrap_provisioned_agent(
                &api,
                state_store,
                &account_for_bootstrap,
                &bootstrap_outcome.agent_id,
                &bootstrap_outcome.principal_control_realm_id,
            )
            .await
        })
        .await
        {
            last_op_status.set(format!(
                "Agent allocated, but PCR recovery setup failed: {}",
                error.display()
            ));
        } else {
            last_op_status.set(format!(
                "Created {} with recoverable Agent PCR.",
                short_protocol_id(agent_id.as_str())
            ));
        }
        selected_agent_id.set(agent_id.to_string());
        create_mode.set(false);
        new_agent_avatar_blob_ref.set(String::new());
        bump_owned_agents_rev(owned_agents_rev);
        spawn_refresh_agents(base, api_token, agents, list_status, refresh_epoch);
    });
}

// Invariant assertions: each `expect` message names the check that
// establishes it a few lines earlier. Rewriting them as `?` would add
// error paths no caller can reach.
#[allow(clippy::expect_used)]
#[component]
pub fn AgentAdminPanel(token: Signal<String>, controller_id: arkret_sdk::DidCoreId) -> Element {
    // A4 — base_url from session context instead of a prop.
    let base_url = crate::app::SessionContext::base_url_string();
    let navigator = use_navigator();
    let route = use_route::<Route>();
    let active_agent_filter = match &route {
        Route::SettingsSection {
            section, filter, ..
        } if section == "agents" => normalize_agent_filter(filter).to_owned(),
        _ => "all".to_owned(),
    };
    let mut agents = use_signal(Vec::<AgentView>::new);
    let list_status = use_signal(String::new);
    let mut selected_agent_id = use_signal(String::new);
    let mut create_mode = use_signal(|| false);
    let mut new_agent_slug = use_signal(String::new);
    let mut new_agent_avatar_blob_ref = use_signal(String::new);
    let mut provision_presets =
        use_signal(|| vec![AgentGrantPreset::Read, AgentGrantPreset::ReplyAsAgent]);
    let mut provision_service_scopes = use_signal(|| AgentServiceScopePreset::DEFAULTS.to_vec());
    let agent_list_refresh_epoch = use_signal(|| 0_u64);
    let mut deactivate_confirm = use_signal(String::new);
    let mut deactivate_dialog_open = use_signal(|| false);
    // Replacing a runtime atomically revokes the current key and takes the
    // running runtime offline, so it is gated behind an explicit confirmation
    // (key-management.md §3.6.1). Forced pause is no longer required.
    let mut replace_runtime_confirm_open = use_signal(|| false);
    let mut last_op_status = use_signal(String::new);
    let mut pairing_action_agent_id = use_signal(String::new);
    let mut pairing_action_phase = use_signal(PairingActionPhase::default);
    let state_store = crate::app::SessionContext::get().state_store;
    // Captured during render (a hook context); moved into the spawned mutation
    // futures below, which bump it so the Contacts sidebar re-pulls its agents.
    let owned_agents_rev = crate::app::SessionContext::get().owned_agents_rev;
    let approval_projection_version = use_memo(move || {
        let mut ids = state_store
            .read()
            .notification_projection()
            .into_iter()
            .filter_map(|value| {
                let (id, data) = value.agent_runtime_approval()?;
                Some(format!(
                    "{}:{}:{}",
                    id.as_str(),
                    data.approval_request_id,
                    data.expires_at
                ))
            })
            .collect::<Vec<_>>();
        ids.sort();
        ids
    });

    {
        let base = base_url.clone();
        use_effect(move || {
            let _ = approval_projection_version();
            let _ = owned_agents_rev();
            let api_token = token();
            if api_token.trim().is_empty() {
                return;
            }
            spawn_refresh_agents(
                base.clone(),
                api_token,
                agents,
                list_status,
                agent_list_refresh_epoch,
            );
        });
    }

    {
        let filter = active_agent_filter.clone();
        use_effect(move || {
            let current = selected_agent_id();
            let next = {
                let rows = agents.read();
                if rows.iter().any(|agent| {
                    agent_id(agent) == current
                        && agent_matches_filter(
                            agent_lifecycle_wire(agent.agent.lifecycle),
                            &filter,
                        )
                }) {
                    current.clone()
                } else {
                    rows.iter()
                        .find(|agent| {
                            agent_matches_filter(
                                agent_lifecycle_wire(agent.agent.lifecycle),
                                &filter,
                            )
                        })
                        .map(agent_id)
                        .unwrap_or_default()
                }
            };
            if next != current {
                selected_agent_id.set(next);
            }
        });
    }

    {
        let base = base_url.clone();
        use_effect(move || {
            let _ = owned_agents_rev();
            let id = selected_agent_id();
            if id.is_empty() {
                return;
            }
            spawn_load_agent_details(base.clone(), token(), id, agents, last_op_status);
        });
    }

    let selected_id_now = selected_agent_id();
    let is_create_mode = create_mode();
    let (selected_agent, visible_agents, has_any_agents) = {
        let rows = agents.read();
        let selected_agent = rows
            .iter()
            .find(|agent| {
                agent_id(agent) == selected_id_now
                    && agent_matches_filter(
                        agent_lifecycle_wire(agent.agent.lifecycle),
                        &active_agent_filter,
                    )
            })
            .cloned();
        let visible_agents = rows
            .iter()
            .filter(|agent| {
                agent_matches_filter(
                    agent_lifecycle_wire(agent.agent.lifecycle),
                    &active_agent_filter,
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        let has_any_agents = rows
            .iter()
            .any(|agent| agent_matches_filter(agent_lifecycle_wire(agent.agent.lifecycle), "all"));
        (selected_agent, visible_agents, has_any_agents)
    };
    let last_op_status_message = last_op_status();
    let list_status_message = list_status();
    let selected_title = selected_agent
        .as_ref()
        .map(agent_slug_label)
        .unwrap_or_else(|| "No agent selected".to_owned());
    let selected_slug = selected_agent
        .as_ref()
        .map(|agent| agent_field(agent, "slug"))
        .unwrap_or_default();
    // Two orthogonal axes (key-management.md §3.6.1): `selected_status` is the
    // controller lifecycle intent; `selected_runtime_state` is the derived
    // runtime readiness. Pairing/replacement gates key off the runtime axis;
    // pause/resume/filters key off the lifecycle axis.
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
    let selected_key_state_owned = selected_key_state.cloned();
    // Separate clones for the replace-runtime "Pause first" affordance, which is
    // rendered after the lifecycle switch closure has already moved the
    // originals.
    let replace_pause_controller_id = controller_id.clone();
    let replace_pause_key_state = selected_key_state_owned.clone();
    let deactivate_controller_id = controller_id.clone();
    let deactivate_key_state = selected_key_state_owned.clone();
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
    let security_refresh_target = selected_pcr_bootstrap_target.clone();
    let selected_pairing_request_id = selected_key_state
        .and_then(|key_state| key_state.pairing_request_id.as_deref())
        .unwrap_or_default()
        .to_owned();
    let selected_pairing_code = selected_key_state
        .and_then(|key_state| key_state.pairing_code.as_deref())
        .unwrap_or_default()
        .to_owned();
    let selected_pairing_expires_at = selected_key_state
        .and_then(|key_state| key_state.pairing_expires_at.as_ref())
        .map(chrono::DateTime::to_rfc3339)
        .unwrap_or_default();
    let now_rfc3339 = crate::clock::now_timestamp();
    let selected_pairing_is_expired = selected_runtime_state == "pairing_expired"
        || is_pairing_request_expired(&selected_pairing_expires_at, &now_rfc3339);
    let active_pairing_action_id = pairing_action_agent_id();
    let any_pairing_action_in_flight = !active_pairing_action_id.is_empty();
    let selected_pairing_action_in_flight =
        !selected_id_now.is_empty() && active_pairing_action_id == selected_id_now;
    let selected_pairing_action_phase = pairing_action_phase();
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
        .map(|agent| agent_field(agent, "created_at"))
        .unwrap_or_default();
    let selected_updated_at = selected_agent
        .as_ref()
        .map(|agent| agent_field(agent, "updated_at"))
        .unwrap_or_default();
    let selected_scope = selected_key_state.map(|key_state| &key_state.requested_scope);
    let selected_content_capabilities = AgentGrantPreset::ALL.map(|preset| {
        (
            preset,
            requested_scope_matches_content_preset(selected_scope, preset),
        )
    });
    let selected_service_capabilities = AgentServiceScopePreset::ALL.map(|preset| {
        (
            preset,
            requested_scope_matches_service_preset(selected_scope, preset),
        )
    });

    rsx! {
        div { class: "agent-admin-page", "data-testid": "agent-admin",
            if !last_op_status_message.is_empty() {
                div { class: "agent-admin-status", "data-testid": "agent-admin-last-op", "{last_op_status_message}" }
            }

            div { class: "agent-admin-layout",
                section { class: "event agent-admin-list-pane", "data-testid": "agent-admin-list",
                    div { class: "event-head",
                        span { "Agents" }
                        div { class: "actions agent-admin-list-actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                size: ButtonSize::IconSm,
                                class: "btn icon",
                                "data-testid": "agent-admin-refresh-button",
                                title: "Refresh agents",
                                "aria-label": "Refresh agents",
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        spawn_refresh_agents(
                                            base.clone(),
                                            token(),
                                            agents,
                                            list_status,
                                            agent_list_refresh_epoch,
                                        );
                                    }
                                },
                                UiIcon { name: "refresh" }
                            }
                            Button {
                                variant: if is_create_mode {
                                    ButtonVariant::Primary
                                } else {
                                    ButtonVariant::Secondary
                                },
                                size: ButtonSize::IconSm,
                                class: "btn icon",
                                "data-testid": "agent-admin-create-open-button",
                                title: "Create agent",
                                "aria-label": "Create agent",
                                onclick: move |_| {
                                    last_op_status.set(String::new());
                                    new_agent_slug.set(String::new());
                                    new_agent_avatar_blob_ref.set(String::new());
                                    create_mode.set(true);
                                },
                                UiIcon { name: "plus" }
                            }
                        }
                    }
                    div { class: "agent-admin-filter-bar", role: "tablist", "aria-label": "Agent filters",
                        for (filter, label) in AGENT_LIST_FILTERS {
                            {
                                let filter_value = filter.to_owned();
                                let is_active_filter = active_agent_filter == filter;
                                let filter_class = if is_active_filter {
                                    "agent-admin-filter-button active"
                                } else {
                                    "agent-admin-filter-button"
                                };
                                rsx! {
                                    button {
                                        r#type: "button",
                                        class: "{filter_class}",
                                        "data-testid": "agent-admin-filter-{filter}",
                                        role: "tab",
                                        "aria-selected": if is_active_filter { "true" } else { "false" },
                                        onclick: move |_| {
                                            navigator.push(Route::SettingsSection {
                                                section: "agents".to_owned(),
                                                filter: filter_value.clone(),
                                            });
                                        },
                                        "{label}"
                                    }
                                }
                            }
                        }
                    }
                    if !list_status_message.is_empty() {
                        div { class: "muted", "data-testid": "agent-admin-list-status", "{list_status_message}" }
                    }
                    div { class: "agent-admin-list-rows",
                        if visible_agents.is_empty() {
                            div { class: "members-empty compact", "data-testid": "agent-admin-list-empty",
                                div { class: "members-empty-title",
                                    if !has_any_agents {
                                        "No agents yet."
                                    } else {
                                        "No agents match this filter."
                                    }
                                }
                            }
                        }
                        for agent in visible_agents.iter() {
                            {
                                let id = agent_id(agent);
                                let slug_label = agent_slug_label(agent);
                                let status = agent_lifecycle_wire(agent.agent.lifecycle);
                                let runtime_state = agent_runtime_state_wire(
                                    super::model::agent_projection_runtime_state(&agent.agent),
                                );
                                let id_label = short_protocol_id(&id);
                                let is_selected = !is_create_mode && selected_id_now == id;
                                let row_class = if is_selected {
                                    "agent-admin-list-row active"
                                } else {
                                    "agent-admin-list-row"
                                };
                                rsx! {
                                    button {
                                        class: "{row_class}",
                                        "data-testid": "agent-admin-row",
                                        "data-agent-id": "{id}",
                                        "aria-pressed": if is_selected { "true" } else { "false" },
                                        onclick: {
                                            let id = id.clone();
                                            move |_| {
                                                create_mode.set(false);
                                                selected_agent_id.set(id.clone());
                                            }
                                        },
                                        span { class: "agent-admin-list-row-main",
                                            strong { "{slug_label}" }
                                            span { class: "{agent_state_badge_class(status)}", "{agent_state_label(status)}" }
                                            span { class: "{agent_state_badge_class(runtime_state)}", "{agent_state_label(runtime_state)}" }
                                        }
                                        span { class: "mono muted", title: "{id}", "{id_label}" }
                                    }
                                }
                            }
                        }
                    }

                }

                section { class: "event agent-admin-detail-pane", "data-testid": "agent-admin-detail",
                    if is_create_mode {
                        div { class: "agent-admin-create-page", "data-testid": "agent-admin-provision",
                            div { class: "agent-admin-detail-head",
                                div {
                                    div { class: "entity-title", "Create agent" }
                                    div { class: "muted", "Create an account-global personal AI agent. Realm data access starts when you add it to a Realm." }
                                }
                            }
                            div { class: "workflow-form",
                                Input {
                                    "data-testid": "agent-admin-provision-agent-slug",
                                    placeholder: "Slug (required)",
                                    value: "{new_agent_slug}",
                                    oninput: move |event: FormEvent| {
                                        last_op_status.set(String::new());
                                        new_agent_slug.set(normalize_agent_slug(&event.value()));
                                    },
                                }
                                div { class: "agent-admin-section-head",
                                    strong { "Avatar" }
                                    span { class: "muted", "Shown in contacts and agent conversations" }
                                }
                                crate::components::AvatarUploader {
                                    current_blob_ref: new_agent_avatar_blob_ref(),
                                    alt_text: if new_agent_slug().trim().is_empty() {
                                        "New agent".to_owned()
                                    } else {
                                        new_agent_slug().trim().to_owned()
                                    },
                                    api_token: token(),
                                    test_id_prefix: "agent-admin-provision-avatar".to_owned(),
                                    on_uploaded: move |blob_ref: String| {
                                        new_agent_avatar_blob_ref.set(blob_ref);
                                    },
                                    on_clear: move |_| {
                                        new_agent_avatar_blob_ref.set(String::new());
                                    },
                                }
                                div { class: "muted", "These settings are the Agent's maximum permissions. Joining a Realm can only grant a subset; anything disabled here stays unavailable in every Realm." }
                                div { class: "agent-admin-section-head",
                                    strong { "Content capabilities" }
                                    span { class: "muted", "Global maximum; Realm grants can only narrow it" }
                                }
                                div { class: "agent-admin-preset-list",
                                    for preset in AgentGrantPreset::ALL {
                                        {
                                            let is_on = provision_presets.read().contains(&preset);
                                            rsx! {
                                                label {
                                                    class: "agent-admin-preset-row",
                                                    "data-testid": "agent-admin-content-preset-row",
                                                    "data-preset": preset.preset_name(),
                                                    Checkbox {
                                                        "data-testid": "agent-admin-content-preset-checkbox",
                                                        checked: if is_on { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                                        on_checked_change: move |s: CheckboxState| {
                                                            let mut current = provision_presets.write();
                                                            if bool::from(s) {
                                                                if !current.contains(&preset) {
                                                                    current.push(preset);
                                                                }
                                                            } else {
                                                                current.retain(|p| *p != preset);
                                                            }
                                                        },
                                                    }
                                                    span {
                                                        strong { "{preset.label()}" }
                                                        span { class: "muted", "{preset.help()}" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                div { class: "agent-admin-section-head",
                                    strong { "Runtime service surface" }
                                    span { class: "muted", "Maximum endpoint operations for the agent key" }
                                }
                                div { class: "agent-admin-preset-list", "data-testid": "agent-admin-service-scope-list",
                                    for preset in AgentServiceScopePreset::ALL {
                                        {
                                            let is_on = provision_service_scopes.read().contains(&preset);
                                            rsx! {
                                                label {
                                                    class: "agent-admin-preset-row",
                                                    "data-testid": "agent-admin-service-scope-row",
                                                    "data-service-preset": preset.preset_name(),
                                                    Checkbox {
                                                        "data-testid": "agent-admin-service-scope-checkbox",
                                                        checked: if is_on { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                                        on_checked_change: move |s: CheckboxState| {
                                                            let mut current = provision_service_scopes.write();
                                                            if bool::from(s) {
                                                                if !current.contains(&preset) {
                                                                    current.push(preset);
                                                                }
                                                            } else {
                                                                current.retain(|p| *p != preset);
                                                            }
                                                        },
                                                    }
                                                    span {
                                                        strong { "{preset.label()}" }
                                                        span { class: "muted", "{preset.help()}" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "agent-admin-provision-button",
                                        disabled: new_agent_slug().trim().is_empty(),
                                        onclick: {
                                            let base = base_url.clone();
                                            let controller_id = controller_id.clone();
                                            move |_| {
                                                spawn_provision_agent(
                                                    base.clone(),
                                                    token(),
                                                    controller_id.clone(),
                                                    new_agent_slug(),
                                                    arkret_sdk::BlobRef::new(new_agent_avatar_blob_ref()).ok(),
                                                    provision_presets.read().clone(),
                                                    provision_service_scopes.read().clone(),
                                                    agents,
                                                    list_status,
                                                    agent_list_refresh_epoch,
                                                    selected_agent_id,
                                                    create_mode,
                                                    new_agent_avatar_blob_ref,
                                                    last_op_status,
                                                    owned_agents_rev,
                                                    state_store,
                                                );
                                            }
                                        },
                                        "Create"
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "agent-admin-create-cancel-button",
                                        onclick: move |_| {
                                            new_agent_avatar_blob_ref.set(String::new());
                                            create_mode.set(false);
                                        },
                                        "Cancel"
                                    }
                                }
                            }
                        }
                    } else if selected_id_now.is_empty() {
                        div { class: "agent-admin-empty-detail", "data-testid": "agent-admin-detail-empty",
                            strong { "Select an agent" }
                            span { class: "muted", "Choose an agent on the left, or create one first." }
                        }
                    } else {
                        div { class: "agent-admin-detail-head",
                            div {
                                div {
                                    class: "entity-title",
                                    "data-testid": "agent-admin-slug-title",
                                    "{selected_title}"
                                }
                                div { class: "mono muted", title: "{selected_id_now}", "{selected_id_now}" }
                            }
                        }

                        div { class: "agent-admin-detail-meta", "data-testid": "agent-admin-detail-meta",
                            div { class: "agent-admin-detail-meta-item",
                                span { class: "muted", "Created" }
                                if selected_created_at.is_empty() {
                                    span { "-" }
                                } else {
                                    span { "{selected_created_at}" }
                                }
                            }
                            div { class: "agent-admin-detail-meta-item",
                                span { class: "muted", "Updated" }
                                if selected_updated_at.is_empty() {
                                    span { "-" }
                                } else {
                                    span { "{selected_updated_at}" }
                                }
                            }
                        }

                        if selected_should_show_pairing_card {
                            {
                                let request_id = selected_pairing_request_id.clone();
                                let pairing_code = selected_pairing_code.clone();
                                let pairing_token = if selected_has_pairing_handle {
                                    build_agent_pairing_handoff_token(&request_id, &pairing_code)
                                } else {
                                    String::new()
                                };
                                let deep_link = if pairing_token.is_empty() {
                                    String::new()
                                } else {
                                    build_agent_pairing_deep_link(&base_url, &pairing_token)
                                };
                                let pairing_qr_svg = render_agent_pairing_qr_svg(&deep_link);
                                let pairing_badge = if !selected_has_pcr_binding {
                                    "badge amber"
                                } else if selected_pairing_is_expired {
                                    "badge red"
                                } else {
                                    "badge amber"
                                };
                                let pairing_label = if !selected_has_pcr_binding {
                                    "Setup incomplete"
                                } else if selected_pairing_is_expired {
                                    "Expired"
                                } else {
                                    agent_state_label(&selected_runtime_state)
                                };
                                let replacement_agent_slug = selected_slug.clone();
                                let pcr_bootstrap_target = selected_pcr_bootstrap_target.clone();
                                rsx! {
                                    div {
                                        class: "agent-admin-section agent-admin-pairing-card",
                                        "data-testid": "agent-admin-pairing-card",
                                        div { class: "agent-admin-section-head",
                                            strong {
                                                if selected_is_replacement_pairing {
                                                    "Connect the replacement runtime"
                                                } else {
                                                    "Connect an agent runtime"
                                                }
                                            }
                                            div { class: "agent-admin-pairing-head-actions",
                                                span { class: "{pairing_badge}", "{pairing_label}" }
                                            }
                                        }
                                        if !selected_has_pcr_binding {
                                            div {
                                                class: "agent-admin-status",
                                                "data-testid": "agent-admin-pcr-recovery-pending",
                                                if selected_pairing_is_expired {
                                                    "This pairing code expired before setup finished. Pair again to finish protecting this Agent and create a new code. The Agent and its settings will stay the same."
                                                } else {
                                                    "Finish protecting this Agent before connecting a runtime. This lets you restore it if its runtime or keys are lost."
                                                }
                                            }
                                            div { class: "actions",
                                                Button {
                                                    variant: ButtonVariant::Primary,
                                                    "data-testid": "agent-admin-finish-pcr-recovery-button",
                                                    disabled: pcr_bootstrap_target.is_none() || any_pairing_action_in_flight,
                                                    onclick: {
                                                        let base = base_url.clone();
                                                        let target = pcr_bootstrap_target.clone();
                                                        let pairing_expired = selected_pairing_is_expired;
                                                        let slug = replacement_agent_slug.clone();
                                                        move |_| {
                                                            let Some((agent_id, realm_id, _)) = target.clone() else {
                                                                last_op_status.set(
                                                                    "Agent PCR binding is unavailable; refresh the Agent details and retry."
                                                                        .to_owned(),
                                                                );
                                                                return;
                                                            };
                                                            if !pairing_action_agent_id.peek().is_empty() {
                                                                return;
                                                            }
                                                            pairing_action_agent_id.set(agent_id.to_string());
                                                            pairing_action_phase.set(PairingActionPhase::RepairingRecovery);
                                                            let base = base.clone();
                                                            let api_token = token();
                                                            let slug = slug.clone();
                                                            spawn(async move {
                                                                let account = match crate::app::SessionContext::get().active_account() {
                                                                    Some(account) => account,
                                                                    None => {
                                                                        pairing_action_agent_id.set(String::new());
                                                                        pairing_action_phase.set(PairingActionPhase::Idle);
                                                                        last_op_status.set("Agent recovery failed: active controller account is unavailable".to_owned());
                                                                        return;
                                                                    }
                                                                };
                                                                let bootstrap_agent_id = agent_id.clone();
                                                                let result = with_authed_api(
                                                                    &base,
                                                                    api_token.clone(),
                                                                    move |api| async move {
                                                                        super::bootstrap::bootstrap_provisioned_agent(
                                                                            &api,
                                                                            state_store,
                                                                            &account,
                                                                            &bootstrap_agent_id,
                                                                            &realm_id,
                                                                        )
                                                                        .await
                                                                    },
                                                                )
                                                                .await;
                                                                match result {
                                                                    Ok(()) => {
                                                                        if pairing_expired {
                                                                            pairing_action_phase.set(PairingActionPhase::IssuingPairing);
                                                                            let renewed_agent_id = agent_id.to_string();
                                                                            match renew_agent_pairing(
                                                                                base.clone(),
                                                                                api_token.clone(),
                                                                                renewed_agent_id.clone(),
                                                                            )
                                                                            .await
                                                                            {
                                                                                Ok(outcome) => {
                                                                                    let applied = agents.with_mut(|rows| {
                                                                                        apply_renewed_pairing(
                                                                                            rows,
                                                                                            &renewed_agent_id,
                                                                                            &outcome,
                                                                                            crate::clock::now_utc(),
                                                                                        )
                                                                                    });
                                                                                    match applied {
                                                                                        Ok(()) => last_op_status.set(format!(
                                                                                            "Ready to pair {}. Scan the new QR or copy the new link; the old one is dead.",
                                                                                            if slug.trim().is_empty() {
                                                                                                short_protocol_id(&renewed_agent_id)
                                                                                            } else {
                                                                                                slug.clone()
                                                                                            }
                                                                                        )),
                                                                                        Err(reason) => {
                                                                                            last_op_status.set(format!(
                                                                                                "A new pairing code was created, but the Agent view could not display it: {reason}. Refreshing details…"
                                                                                            ));
                                                                                            pairing_action_phase.set(PairingActionPhase::RefreshingAgent);
                                                                                            match fetch_agent_details(
                                                                                                &base,
                                                                                                &api_token,
                                                                                                &renewed_agent_id,
                                                                                            )
                                                                                            .await
                                                                                            {
                                                                                                Ok(view) => {
                                                                                                    let mut refreshed = vec![view];
                                                                                                    match apply_renewed_pairing(
                                                                                                        &mut refreshed,
                                                                                                        &renewed_agent_id,
                                                                                                        &outcome,
                                                                                                        crate::clock::now_utc(),
                                                                                                    ) {
                                                                                                        Ok(()) => {
                                                                                                            agents.with_mut(|rows| upsert_agent_view(rows, refreshed.remove(0)));
                                                                                                            last_op_status.set("Pairing code loaded from the authoritative Agent view.".to_owned());
                                                                                                        }
                                                                                                        Err(reason) => last_op_status.set(format!(
                                                                                                            "The authoritative Agent view still cannot display the new pairing code: {reason}"
                                                                                                        )),
                                                                                                    }
                                                                                                }
                                                                                                Err(error) => last_op_status.set(format!(
                                                                                                    "A new pairing code was created, but refreshing the Agent view failed: {}",
                                                                                                    error.display()
                                                                                                )),
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                                Err(err) => last_op_status.set(format!(
                                                                                    "Setup finished, but creating a new pairing code failed: {}",
                                                                                    err.display()
                                                                                )),
                                                                            }
                                                                        } else {
                                                                            last_op_status.set(
                                                                                "Setup finished. This Agent is protected and ready to connect."
                                                                                    .to_owned(),
                                                                            );
                                                                            spawn_load_agent_details(
                                                                                base,
                                                                                api_token,
                                                                                agent_id.to_string(),
                                                                                agents,
                                                                                last_op_status,
                                                                            );
                                                                        }
                                                                    }
                                                                    Err(err) => last_op_status.set(format!(
                                                                        "Could not finish Agent setup: {}",
                                                                        err.display()
                                                                    )),
                                                                }
                                                                pairing_action_agent_id.set(String::new());
                                                                pairing_action_phase.set(PairingActionPhase::Idle);
                                                            });
                                                        }
                                                    },
                                                    if selected_pairing_action_in_flight {
                                                        match selected_pairing_action_phase {
                                                            PairingActionPhase::IssuingPairing => "Creating code…",
                                                            PairingActionPhase::RefreshingAgent => "Refreshing Agent…",
                                                            _ => "Repairing recovery…",
                                                        }
                                                    } else if selected_pairing_is_expired {
                                                        "Pair again"
                                                    } else {
                                                        "Finish setup"
                                                    }
                                                }
                                            }
                                        }
                                        if selected_has_pcr_binding && selected_pairing_is_expired {
                                            div {
                                                class: "agent-admin-status error",
                                                "data-testid": "agent-admin-pairing-expired-message",
                                                "This pairing request expired. The expired code and link can never be used again; pair again to issue a fresh code and QR for this agent."
                                            }
                                        }
                                        if selected_has_pcr_binding && !selected_pairing_is_expired {
                                            QrSharePanel {
                                                qr_svg: pairing_qr_svg,
                                                url: deep_link,
                                                qr_aria_label: "Agent runtime pairing QR code".to_owned(),
                                                url_aria_label: "Agent runtime pairing URL".to_owned(),
                                                qr_test_id: "agent-admin-pairing-qr".to_owned(),
                                                url_test_id: "agent-admin-pairing-url".to_owned(),
                                                copy_test_id: "agent-admin-copy-pairing-link-button".to_owned(),
                                                url_rows: 5,
                                            }
                                        }
                                        if selected_can_renew_pairing {
                                            div { class: "actions",
                                                Button {
                                                    variant: ButtonVariant::Primary,
                                                    "data-testid": "agent-admin-renew-pairing-button",
                                                    disabled: any_pairing_action_in_flight,
                                                    onclick: {
                                                        // `ak.self.agent.command.renew_pairing.v1`:
                                                        // re-open pairing on this agent in place —
                                                        // fresh one-time code + QR, same principal,
                                                        // no replacement agent.
                                                        let base = base_url.clone();
                                                        let renew_agent_id = selected_id_now.clone();
                                                        let renew_slug = replacement_agent_slug.clone();
                                                        move |_| {
                                                            if !pairing_action_agent_id.peek().is_empty() {
                                                                return;
                                                            }
                                                            pairing_action_agent_id.set(renew_agent_id.clone());
                                                            pairing_action_phase.set(PairingActionPhase::IssuingPairing);
                                                            let base = base.clone();
                                                            let api_token = token();
                                                            let renewed_agent_id = renew_agent_id.clone();
                                                            let slug = renew_slug.clone();
                                                            spawn(async move {
                                                                let outcome = match renew_agent_pairing(
                                                                    base.clone(),
                                                                    api_token.clone(),
                                                                    renewed_agent_id.clone(),
                                                                )
                                                                .await {
                                                                    Ok(outcome) => outcome,
                                                                    Err(err) => {
                                                                        last_op_status.set(format!(
                                                                            "Pair again failed: {}",
                                                                            err.display()
                                                                        ));
                                                                        pairing_action_agent_id.set(String::new());
                                                                        pairing_action_phase.set(PairingActionPhase::Idle);
                                                                        return;
                                                                    }
                                                                };
                                                                // Patch the row locally so the pairing
                                                                // card re-renders immediately; the
                                                                // detail effect refetch reconciles with
                                                                // the server view afterwards.
                                                                let applied = agents.with_mut(|rows| {
                                                                    apply_renewed_pairing(
                                                                        rows,
                                                                        &renewed_agent_id,
                                                                        &outcome,
                                                                        crate::clock::now_utc(),
                                                                    )
                                                                });
                                                                match applied {
                                                                    Ok(()) => last_op_status.set(format!(
                                                                        "Pairing renewed for {}. Scan the new QR or copy the new link; the old one is dead.",
                                                                        if slug.trim().is_empty() {
                                                                            short_protocol_id(&renewed_agent_id)
                                                                        } else {
                                                                            slug.clone()
                                                                        }
                                                                    )),
                                                                    Err(reason) => {
                                                                        last_op_status.set(format!(
                                                                            "A new pairing code was created, but the Agent view could not display it: {reason}. Refreshing details…"
                                                                        ));
                                                                        pairing_action_phase.set(PairingActionPhase::RefreshingAgent);
                                                                        match fetch_agent_details(
                                                                            &base,
                                                                            &api_token,
                                                                            &renewed_agent_id,
                                                                        )
                                                                        .await
                                                                        {
                                                                            Ok(view) => {
                                                                                let mut refreshed = vec![view];
                                                                                match apply_renewed_pairing(
                                                                                    &mut refreshed,
                                                                                    &renewed_agent_id,
                                                                                    &outcome,
                                                                                    crate::clock::now_utc(),
                                                                                ) {
                                                                                    Ok(()) => {
                                                                                        agents.with_mut(|rows| upsert_agent_view(rows, refreshed.remove(0)));
                                                                                        last_op_status.set("Pairing code loaded from the authoritative Agent view.".to_owned());
                                                                                    }
                                                                                    Err(reason) => last_op_status.set(format!(
                                                                                        "The authoritative Agent view still cannot display the new pairing code: {reason}"
                                                                                    )),
                                                                                }
                                                                            }
                                                                            Err(error) => last_op_status.set(format!(
                                                                                "A new pairing code was created, but refreshing the Agent view failed: {}",
                                                                                error.display()
                                                                            )),
                                                                        }
                                                                    }
                                                                }
                                                                pairing_action_agent_id.set(String::new());
                                                                pairing_action_phase.set(PairingActionPhase::Idle);
                                                            });
                                                        }
                                                    },
                                                    if selected_pairing_action_in_flight { "Pairing…" } else { "Pair again" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        div { class: "agent-admin-section", "data-testid": "agent-admin-capabilities",
                            div { class: "agent-admin-section-head",
                                strong { "Content capabilities" }
                                span { class: "muted", "Configured when this agent was created" }
                            }
                            div { class: "muted",
                                "Actual access is the intersection of this ceiling with Realm membership, participation, and effective grants."
                            }
                            div { class: "agent-admin-preset-list", "data-testid": "agent-admin-content-capability-list",
                                for (preset, is_on) in selected_content_capabilities {
                                    label {
                                        class: "agent-admin-preset-row readonly",
                                        "data-testid": "agent-admin-content-capability-row",
                                        "data-preset": preset.preset_name(),
                                        Checkbox {
                                            "data-testid": "agent-admin-content-capability-checkbox",
                                            checked: if is_on { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                            disabled: true,
                                        }
                                        span {
                                            strong { "{preset.label()}" }
                                            span { class: "muted", "{preset.help()}" }
                                        }
                                    }
                                }
                            }
                            div { class: "agent-admin-section-head",
                                strong { "Runtime service surface" }
                                span { class: "muted", "Selected when this agent was created" }
                            }
                            div { class: "agent-admin-preset-list", "data-testid": "agent-admin-service-capability-list",
                                for (preset, is_on) in selected_service_capabilities {
                                    label {
                                        class: "agent-admin-preset-row readonly",
                                        "data-testid": "agent-admin-service-capability-row",
                                        "data-service-preset": preset.preset_name(),
                                        Checkbox {
                                            "data-testid": "agent-admin-service-capability-checkbox",
                                            checked: if is_on { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                            disabled: true,
                                        }
                                        span {
                                            strong { "{preset.label()}" }
                                            span { class: "muted", "{preset.help()}" }
                                        }
                                    }
                                }
                            }
                            if selected_status == "deactivated" {
                                div {
                                    class: "agent-admin-terminal-note",
                                    "data-testid": "agent-admin-deactivated-capabilities-note",
                                    "Historical grants have been revoked and are no longer usable."
                                }
                            }
                        }

                        div { class: "agent-admin-section", "data-testid": "agent-admin-agent-actions",
                            div { class: "agent-admin-section-head",
                                strong { "Lifecycle" }
                                span { class: "muted", "Loaded from selected agent" }
                            }
                            if selected_status == "deactivated" {
                                div {
                                    class: "agent-admin-terminal-note",
                                    "data-testid": "agent-admin-deactivated-terminal-note",
                                    strong { "Permanently deactivated" }
                                    span { "This agent cannot be enabled again. Create a new agent if you need a replacement." }
                                }
                            }
                            if matches!(selected_status.as_str(), "active" | "paused") {
                                label { class: "agent-admin-lifecycle-toggle-row",
                                    div {
                                        strong { "Agent enabled" }
                                        div { class: "muted",
                                            if selected_status == "active" {
                                                "Active — turn off to pause"
                                            } else {
                                                "Paused — turn on to resume"
                                            }
                                        }
                                    }
                                    div { class: "agent-admin-lifecycle-toggle-control",
                                        // Two orthogonal axes (key-management.md §3.6.1): the
                                        // lifecycle intent badge and the derived runtime
                                        // readiness badge (e.g. "Active · Awaiting replacement runtime").
                                        span { class: if selected_status == "active" { "badge green" } else { "badge amber" },
                                            if selected_status == "active" { "Active" } else { "Paused" }
                                        }
                                        span {
                                            class: "{agent_state_badge_class(&selected_runtime_state)}",
                                            "data-testid": "agent-admin-runtime-state-badge",
                                            "{agent_state_label(&selected_runtime_state)}"
                                        }
                                        Switch {
                                            "data-testid": "agent-admin-enabled-switch",
                                            checked: selected_status == "active",
                                            on_checked_change: {
                                                let base = base_url.clone();
                                                move |enabled: bool| {
                                                    spawn_set_agent_enabled(
                                                        base.clone(),
                                                        token(),
                                                        selected_agent_id(),
                                                        controller_id.clone(),
                                                        selected_key_state_owned.clone(),
                                                        enabled,
                                                        agents,
                                                        last_op_status,
                                                        owned_agents_rev,
                                                        state_store,
                                                    );
                                                }
                                            },
                                        }
                                    }
                                }
                            }
                            div { class: "actions",
                                    if selected_should_offer_security_refresh {
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "agent-admin-refresh-security-state-button",
                                            disabled: any_pairing_action_in_flight,
                                            onclick: {
                                                let base = base_url.clone();
                                                let target = security_refresh_target.clone();
                                                move |_| {
                                                    let Some((agent_id, realm_id, _)) = target.clone() else {
                                                        last_op_status.set("Agent security binding is unavailable; refresh details and retry.".to_owned());
                                                        return;
                                                    };
                                                    if !pairing_action_agent_id.peek().is_empty() {
                                                        return;
                                                    }
                                                    pairing_action_agent_id.set(agent_id.to_string());
                                                    pairing_action_phase.set(PairingActionPhase::RepairingRecovery);
                                                    let base = base.clone();
                                                    let api_token = token();
                                                    spawn(async move {
                                                        let account = match crate::app::SessionContext::get().active_account() {
                                                            Some(account) => account,
                                                            None => {
                                                                pairing_action_agent_id.set(String::new());
                                                                pairing_action_phase.set(PairingActionPhase::Idle);
                                                                last_op_status.set("Agent security refresh failed: active controller account is unavailable".to_owned());
                                                                return;
                                                            }
                                                        };
                                                        let repaired_agent_id = agent_id.clone();
                                                        let result = with_authed_api(&base, api_token, move |api| async move {
                                                            let _seal = super::bootstrap::seal_agent_pcr_current(
                                                                &api,
                                                                state_store,
                                                                &account,
                                                                &agent_id,
                                                                &realm_id,
                                                            )
                                                            .await?;
                                                            let recovery_warning = super::bootstrap::bootstrap_provisioned_agent(
                                                                &api,
                                                                state_store,
                                                                &account,
                                                                &agent_id,
                                                                &realm_id,
                                                            )
                                                            .await
                                                            .err()
                                                            .map(|error| error.to_string());
                                                            Ok::<_, anyhow::Error>(recovery_warning)
                                                        })
                                                        .await;
                                                        pairing_action_agent_id.set(String::new());
                                                        pairing_action_phase.set(PairingActionPhase::Idle);
                                                        match result {
                                                            Ok(Some(warning)) => last_op_status.set(format!(
                                                                "Agent authorization frontier is repaired. Recovery refresh warning: {warning}"
                                                            )),
                                                            Ok(None) => last_op_status.set(
                                                                "Agent authorization frontier and recovery state are current.".to_owned(),
                                                            ),
                                                            Err(error) => last_op_status.set(format!(
                                                                "Agent security refresh failed: {}",
                                                                error.display()
                                                            )),
                                                        }
                                                        bump_owned_agents_rev(owned_agents_rev);
                                                        selected_agent_id.set(repaired_agent_id.to_string());
                                                    });
                                                }
                                            },
                                            if selected_pairing_action_in_flight {
                                                "Refreshing security…"
                                            } else {
                                                "Refresh security state"
                                            }
                                        }
                                    }
                                    if selected_can_replace_runtime && !replace_runtime_confirm_open() {
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "agent-admin-replace-runtime-button",
                                            onclick: move |_| {
                                                replace_runtime_confirm_open.set(true);
                                            },
                                            "Replace runtime"
                                        }
                                    }
                                    if selected_can_replace_runtime && replace_runtime_confirm_open() {
                                        div {
                                            class: "agent-admin-replace-runtime-confirm",
                                            "data-testid": "agent-admin-replace-runtime-confirm",
                                            div { class: "muted",
                                                // §4 confirmation copy: state the atomic-revoke
                                                // fact plainly. No forced pause.
                                                "Completing this pairing atomically revokes this agent's current runtime key. The existing runtime goes offline immediately and stays offline until the new runtime publishes its KeyPackage pool. The agent's lifecycle intent is preserved — an active agent needs no resume."
                                            }
                                            div { class: "actions",
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    "data-testid": "agent-admin-replace-runtime-confirm-button",
                                                    onclick: {
                                                        // `ak.self.agent.command.renew_pairing.v1`:
                                                        // lifecycle intent, keys and grants stay
                                                        // untouched until the new runtime pairs;
                                                        // the old key is then atomically revoked
                                                        // (reason=superseded_by_repairing).
                                                        let base = base_url.clone();
                                                        let replace_agent_id = selected_id_now.clone();
                                                        move |_| {
                                                            replace_runtime_confirm_open.set(false);
                                                            let base = base.clone();
                                                            let api_token = token();
                                                            let replaced_agent_id = replace_agent_id.clone();
                                                            spawn(async move {
                                                                let renew_id = replaced_agent_id.clone();
                                                                let outcome = match with_authed_sdk_client(
                                                                    &base,
                                                                    api_token.clone(),
                                                                    move |http| {
                                                                        let renew_id = renew_id.clone();
                                                                        async move {
                                                                            http.agent_renew_pairing(
                                                                                &renew_id,
                                                                                &arkret_models_collaboration::agent_operations::AgentRenewPairingRequestBody::default(),
                                                                            )
                                                                            .await
                                                                            .map_err(anyhow::Error::from)
                                                                        }
                                                                    },
                                                                )
                                                                .await
                                                                {
                                                                    Ok(outcome) => outcome,
                                                                    Err(err) => {
                                                                        last_op_status.set(format!(
                                                                            "Replace runtime failed: {}",
                                                                            err.display()
                                                                        ));
                                                                        return;
                                                                    }
                                                                };
                                                                let applied = agents.with_mut(|rows| {
                                                                    apply_renewed_pairing(
                                                                        rows,
                                                                        &replaced_agent_id,
                                                                        &outcome,
                                                                        crate::clock::now_utc(),
                                                                    )
                                                                });
                                                                match applied {
                                                                    Ok(()) => {
                                                                        last_op_status.set(
                                                                            "Replacement pairing ready. The current runtime key is revoked the moment the new runtime pairs; the agent's lifecycle intent is unchanged.".to_owned(),
                                                                        );
                                                                    }
                                                                    Err(reason) => last_op_status.set(format!(
                                                                        "A replacement pairing was created, but its credentials could not be displayed: {reason}"
                                                                    )),
                                                                }
                                                            });
                                                        }
                                                    },
                                                    "Confirm replacement"
                                                }
                                                if selected_status == "active" {
                                                    Button {
                                                        variant: ButtonVariant::Secondary,
                                                        "data-testid": "agent-admin-replace-runtime-pause-first-button",
                                                        onclick: {
                                                            // Recommended when the key may be
                                                            // compromised: pause first so sessions
                                                            // are refused immediately, then replace.
                                                            let base = base_url.clone();
                                                            let controller_id = replace_pause_controller_id.clone();
                                                            let key_state = replace_pause_key_state.clone();
                                                            move |_| {
                                                                replace_runtime_confirm_open.set(false);
                                                                spawn_set_agent_enabled(
                                                                    base.clone(),
                                                                    token(),
                                                                    selected_agent_id(),
                                                                    controller_id.clone(),
                                                                    key_state.clone(),
                                                                    false,
                                                                    agents,
                                                                    last_op_status,
                                                                    owned_agents_rev,
                                                                    state_store,
                                                                );
                                                            }
                                                        },
                                                        "Pause first (recommended if the key may be compromised)"
                                                    }
                                                }
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    "data-testid": "agent-admin-replace-runtime-cancel-button",
                                                    onclick: move |_| {
                                                        replace_runtime_confirm_open.set(false);
                                                    },
                                                    "Cancel"
                                                }
                                            }
                                        }
                                    }
                                    if selected_status != "deactivated" {
                                        Button {
                                            variant: ButtonVariant::Destructive,
                                            "data-testid": "agent-admin-deactivate-button",
                                            onclick: move |_| {
                                                deactivate_confirm.set(String::new());
                                                deactivate_dialog_open.set(true);
                                            },
                                            "Deactivate"
                                        }
                                    }
                            }
                        }

                        if deactivate_dialog_open() {
                            Dialog {
                                open: true,
                                on_open_change: move |open: bool| {
                                    deactivate_dialog_open.set(open);
                                    if !open {
                                        deactivate_confirm.set(String::new());
                                    }
                                },
                                "data-testid": "agent-admin-deactivate-modal",
                                "aria-labelledby": "agent-admin-deactivate-title",
                                div { class: "modal event agent-admin-deactivate-modal",
                                    div { class: "modal-head event-head",
                                        h3 { id: "agent-admin-deactivate-title", "Deactivate {selected_title}?" }
                                        span { class: "badge red", "Permanent" }
                                    }
                                    div { class: "modal-body agent-admin-deactivate-modal-body",
                                        p {
                                            "Deactivation is permanent. It revokes this agent's keys, capabilities, and runtime access. Use Pause instead if you may want to resume the agent later."
                                        }
                                        label { class: "workflow-form",
                                            span { "Type " strong { class: "mono", "DEACTIVATE" } " to confirm." }
                                            Input {
                                                "data-testid": "agent-admin-deactivate-confirm-input",
                                                placeholder: "DEACTIVATE",
                                                value: "{deactivate_confirm}",
                                                oninput: move |event: FormEvent| deactivate_confirm.set(event.value()),
                                            }
                                        }
                                    }
                                    div { class: "modal-foot actions",
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "agent-admin-deactivate-cancel-button",
                                            onclick: move |_| {
                                                deactivate_dialog_open.set(false);
                                                deactivate_confirm.set(String::new());
                                            },
                                            "Cancel"
                                        }
                                        Button {
                                            variant: ButtonVariant::Destructive,
                                            "data-testid": "agent-admin-deactivate-confirm-button",
                                            disabled: deactivate_confirm() != "DEACTIVATE",
                                            onclick: {
                                                let base = base_url.clone();
                                                let controller_id = deactivate_controller_id.clone();
                                                let key_state = deactivate_key_state.clone();
                                                move |_| {
                                                    let id = selected_agent_id();
                                                    if id.is_empty() { return; }
                                                    spawn_deactivate_agent(
                                                        base.clone(),
                                                        token(),
                                                        id,
                                                        controller_id.clone(),
                                                        deactivate_status,
                                                        key_state.clone(),
                                                        agents,
                                                        last_op_status,
                                                        deactivate_dialog_open,
                                                        deactivate_confirm,
                                                        owned_agents_rev,
                                                    );
                                                }
                                            },
                                            "Deactivate agent"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
