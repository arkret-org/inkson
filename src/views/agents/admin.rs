//! Personal agent settings panel.
//!
//! This view is deliberately limited to settings backed by live server
//! calls: the agent directory row, runtime pairing/key state, lifecycle,
//! capability grants, and lifecycle controls. Per-Realm participation is
//! configured from that Realm's Members area.

use std::time::Duration;

use arkret_sdk::models::{
    AgentDeactivateRequestBody, AgentKeyScope, AgentLifecycleState, AgentPauseRequestBody,
    AgentPcrRecoveryState, AgentProjection, AgentProvisionRequestBody, AgentResumeRequestBody,
    AgentStatus, AgentView, KeyState,
};
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_router::hooks::{use_navigator, use_route};
use serde_json::Value;
use yoface::utils::dom::copy_text_to_clipboard;

use super::model::{
    AgentGrantPreset, AgentServiceScopePreset, agent_state_badge_class, agent_state_label,
    agent_status_wire, agent_view_from_directory_row, build_agent_pairing_deep_link,
    build_agent_pairing_handoff_token, is_pairing_request_expired, render_agent_pairing_qr_svg,
    requested_scope_for_presets,
};
use crate::components::UiIcon;
use crate::routes::Route;
use crate::transport::auth::{with_authed_api, with_authed_sdk_client};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::dialog::Dialog;
use crate::ui::input::Input;
use crate::ui::switch::Switch;
use crate::ui::textarea::Textarea;
use crate::views::helpers::short_protocol_id;

fn normalize_agent_slug(value: &str) -> String {
    value.trim().to_ascii_lowercase()
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
        "status" => agent_status_wire(agent.status).to_owned(),
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

fn pairing_material_can_be_exposed(pcr_recovery: Option<&AgentPcrRecoveryState>) -> bool {
    pcr_recovery.is_some_and(AgentPcrRecoveryState::is_ready)
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
    fn agent_slug_input_is_trimmed_and_lowercased() {
        assert_eq!(normalize_agent_slug(" AA "), "aa");
        assert_eq!(normalize_agent_slug("Summary_V2"), "summary_v2");
    }

    #[test]
    fn directory_refresh_updates_status_without_dropping_loaded_details() {
        let mut rows = vec![AgentView {
            agent: test_agent_projection(AgentStatus::PendingRuntimeKey),
            status: AgentStatus::PendingRuntimeKey,
            grants: vec![arkret_sdk::GrantSnapshot {
                grant_id: arkret_sdk::GrantId::new("ak:grant:01964137-0000-7000-8000-000000000010")
                    .unwrap(),
                status: None,
                grant_digest: None,
                expires_at: None,
            }],
            key_state: None,
        }];
        let directory_rows = vec![AgentView {
            agent: test_agent_projection(AgentStatus::Active),
            status: AgentStatus::Active,
            grants: Vec::new(),
            key_state: None,
        }];

        replace_agent_directory(&mut rows, directory_rows);

        assert_eq!(rows[0].status, AgentStatus::Active);
        assert_eq!(
            rows[0].grants[0].grant_id.as_str(),
            "ak:grant:01964137-0000-7000-8000-000000000010"
        );
    }

    fn test_agent_projection(status: AgentStatus) -> AgentProjection {
        AgentProjection {
            agent_id: arkret_sdk::Did::new("did:web:agents.example:summary").unwrap(),
            display_name: None,
            slug: "summary".to_owned(),
            avatar_blob_ref: None,
            status,
            created_at: None,
            updated_at: None,
        }
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
    fn pending_agent_pcr_does_not_expose_runtime_pairing_material() {
        assert!(!pairing_material_can_be_exposed(Some(
            &AgentPcrRecoveryState::Pending
        )));
        assert!(!pairing_material_can_be_exposed(None));
    }
}

fn update_agent_status(rows: &mut [AgentView], id: &str, status: AgentStatus) {
    for row in rows.iter_mut() {
        if agent_id(row) == id {
            row.status = status;
            row.agent.status = status;
        }
    }
}

fn agent_status_from_lifecycle(status: AgentLifecycleState) -> AgentStatus {
    match status {
        AgentLifecycleState::Active => AgentStatus::Active,
        AgentLifecycleState::Paused => AgentStatus::Paused,
        AgentLifecycleState::Deactivated => AgentStatus::Deactivated,
    }
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
                let total = resp.agents.len();
                let rows: Vec<AgentView> = resp
                    .agents
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
        match with_authed_sdk_client(&base, api_token, move |http| {
            let id = id.clone();
            async move { http.agent_get(&id).await.map_err(anyhow::Error::from) }
        })
        .await
        {
            Ok(view) => {
                agents.with_mut(|rows| upsert_agent_view(rows, view));
            }
            Err(err) => {
                last_op_status.set(format!("Failed to load agent details: {}", err.display()))
            }
        }
    });
}

fn spawn_set_agent_enabled(
    base: String,
    api_token: String,
    id: String,
    enabled: bool,
    mut agents: Signal<Vec<AgentView>>,
    mut last_op_status: Signal<String>,
) {
    spawn(async move {
        if id.is_empty() {
            return;
        }
        let id_for_status = id.clone();
        let result = if enabled {
            let body = AgentResumeRequestBody {
                sidecar_exposure_ack: None,
            };
            with_authed_sdk_client(&base, api_token, move |http| {
                let id = id.clone();
                let body = body.clone();
                async move {
                    http.agent_resume(&id, &body)
                        .await
                        .map_err(anyhow::Error::from)
                }
            })
            .await
        } else {
            let body = AgentPauseRequestBody {
                reason: Some("controller_paused".to_owned()),
            };
            with_authed_sdk_client(&base, api_token, move |http| {
                let id = id.clone();
                let body = body.clone();
                async move {
                    http.agent_pause(&id, &body)
                        .await
                        .map_err(anyhow::Error::from)
                }
            })
            .await
        };
        match result {
            Ok(outcome) => {
                let status = agent_status_from_lifecycle(outcome.status);
                let status_wire = agent_status_wire(status);
                agents.with_mut(|rows| update_agent_status(rows, &id_for_status, status));
                last_op_status.set(if enabled {
                    format!("Resumed. Status: {status_wire}.")
                } else {
                    format!("Paused. Status: {status_wire}.")
                });
            }
            Err(err) => last_op_status.set(format!(
                "{} failed: {}",
                if enabled { "Resume" } else { "Pause" },
                err.display()
            )),
        }
    });
}

#[component]
pub fn PersonalAgentAdminPanel(token: Signal<String>) -> Element {
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
    let mut agent_list_refresh_epoch = use_signal(|| 0_u64);
    let mut deactivate_confirm = use_signal(String::new);
    let mut deactivate_dialog_open = use_signal(|| false);
    let mut last_op_status = use_signal(String::new);
    let mut copied_pairing_url = use_signal(String::new);
    let state_store = crate::app::SessionContext::get().state_store;
    let approval_projection_version = use_memo(move || {
        let mut ids = state_store
            .read()
            .notification_projection()
            .into_iter()
            .filter(|value| {
                value.get("type").and_then(Value::as_str) == Some("agent")
                    && value.pointer("/data/kind").and_then(Value::as_str)
                        == Some("agent_runtime_approval")
            })
            .map(|value| value.to_string())
            .collect::<Vec<_>>();
        ids.sort();
        ids
    });

    {
        let base = base_url.clone();
        use_effect(move || {
            let _ = approval_projection_version();
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
                        && agent_matches_filter(agent_status_wire(agent.status), &filter)
                }) {
                    current.clone()
                } else {
                    rows.iter()
                        .find(|agent| {
                            agent_matches_filter(agent_status_wire(agent.status), &filter)
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
                    && agent_matches_filter(agent_status_wire(agent.status), &active_agent_filter)
            })
            .cloned();
        let visible_agents = rows
            .iter()
            .filter(|agent| {
                agent_matches_filter(agent_status_wire(agent.status), &active_agent_filter)
            })
            .cloned()
            .collect::<Vec<_>>();
        let has_any_agents = rows
            .iter()
            .any(|agent| agent_matches_filter(agent_status_wire(agent.status), "all"));
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
    let selected_status = selected_agent
        .as_ref()
        .map(|agent| agent_status_wire(agent.status).to_owned())
        .unwrap_or_default();
    let selected_key_state = selected_agent
        .as_ref()
        .and_then(|agent| agent.key_state.as_ref());
    let selected_pcr_recovery_ready = pairing_material_can_be_exposed(
        selected_key_state.map(|key_state| &key_state.pcr_recovery),
    );
    let selected_pcr_bootstrap_target = selected_key_state.map(|key_state: &KeyState| {
        (
            key_state.agent_id.clone(),
            key_state.principal_control_realm_id.clone(),
            key_state.controller_authorization_ref.clone(),
        )
    });
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
    let now_rfc3339 = crate::clock::now_rfc3339_secs();
    let selected_pairing_is_expired = selected_status == "pairing_expired"
        || is_pairing_request_expired(&selected_pairing_expires_at, &now_rfc3339);
    let selected_has_pairing_handle =
        !selected_pairing_request_id.is_empty() && !selected_pairing_code.is_empty();
    // Runtime replacement re-pairing (`ak.self.agent.command.renew_pairing`
    // on an active/paused agent): the existing key keeps working until the
    // new pairing completes, then is superseded.
    let selected_is_replaceable = matches!(selected_status.as_str(), "active" | "paused");
    let selected_should_show_pairing_card = (matches!(
        selected_status.as_str(),
        "pending_runtime_key" | "pairing_expired"
    ) && (selected_has_pairing_handle
        || selected_pairing_is_expired))
        || (selected_is_replaceable && selected_has_pairing_handle);
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
        div { class: "agent-admin-page", "data-testid": "personal-agent-admin",
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
                                let navigator = navigator.clone();
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
                                let status = agent_status_wire(agent.status);
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
                                            span { class: "{agent_state_badge_class(&status)}", "{agent_state_label(&status)}" }
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
                                            move |_| {
                                                let slug_value = normalize_agent_slug(&new_agent_slug());
                                                if slug_value.is_empty() {
                                                    last_op_status.set("Slug is required.".to_owned());
                                                    return;
                                                }
                                                if let Err(error) =
                                                    arkret_sdk::models::validate_agent_slug(&slug_value)
                                                {
                                                    last_op_status.set(format!("Slug is invalid: {error}"));
                                                    return;
                                                }
                                                let content_presets = provision_presets.read().clone();
                                                let service_scopes = provision_service_scopes.read().clone();
                                                if service_scopes.is_empty() {
                                                    last_op_status.set("Select at least one runtime service surface.".to_owned());
                                                    return;
                                                }
                                                let requested_scope = match requested_scope_for_presets(
                                                    &content_presets,
                                                    &service_scopes,
                                                ) {
                                                    Some(scope) => scope,
                                                    None => {
                                                        last_op_status.set("Select at least one runtime service surface.".to_owned());
                                                        return;
                                                    }
                                                };
                                                let avatar_blob_ref = arkret_sdk::BlobRef::new(
                                                    new_agent_avatar_blob_ref(),
                                                )
                                                .ok();
                                                let body = AgentProvisionRequestBody {
                                                    display_name: None,
                                                    slug: slug_value.clone(),
                                                    avatar_blob_ref: avatar_blob_ref.clone(),
                                                    requested_scope: requested_scope.clone(),
                                                    accountability: None,
                                                    pairing_ttl_ms: None,
                                                };
                                                let base = base.clone();
                                                let api_token = token();
                                                spawn(async move {
                                                    let outcome = match with_authed_sdk_client(
                                                        &base,
                                                        api_token.clone(),
                                                        move |http| {
                                                            let body = body.clone();
                                                            async move { http.agent_provision(&body).await.map_err(anyhow::Error::from) }
                                                        },
                                                    )
                                                    .await
                                                    {
                                                        Ok(outcome) => outcome,
                                                        Err(err) => {
                                                            last_op_status.set(format!(
                                                                "Create failed: {}",
                                                                err.display()
                                                            ));
                                                            return;
                                                        }
                                                    };
                                                    let bootstrap_outcome = outcome.clone();
                                                    if let Err(err) = with_authed_api(
                                                        &base,
                                                        api_token.clone(),
                                                        move |api| async move {
                                                            super::bootstrap::bootstrap_provisioned_agent(
                                                                &api,
                                                                state_store,
                                                                &bootstrap_outcome.agent_id,
                                                                &bootstrap_outcome.principal_control_realm_id,
                                                                &bootstrap_outcome.controller_authorization_ref,
                                                                None,
                                                            )
                                                            .await
                                                        },
                                                    )
                                                    .await
                                                    {
                                                        last_op_status.set(format!(
                                                            "Agent allocated, but PCR recovery setup failed: {}",
                                                            err.display()
                                                        ));
                                                        spawn_refresh_agents(
                                                            base.clone(),
                                                            api_token,
                                                            agents,
                                                            list_status,
                                                            agent_list_refresh_epoch,
                                                        );
                                                        return;
                                                    }
                                                    let agent_view = AgentView {
                                                        agent: AgentProjection {
                                                            agent_id: outcome.agent_id,
                                                            display_name: None,
                                                            slug: slug_value,
                                                            avatar_blob_ref,
                                                            status: AgentStatus::PendingRuntimeKey,
                                                            created_at: None,
                                                            updated_at: None,
                                                        },
                                                        status: AgentStatus::PendingRuntimeKey,
                                                        grants: Vec::new(),
                                                        key_state: None,
                                                    };
                                                    let created_id = agent_id(&agent_view);
                                                    agent_list_refresh_epoch.set(
                                                        agent_list_refresh_epoch()
                                                            .saturating_add(1),
                                                    );
                                                    agents.with_mut(|rows| upsert_agent_view(rows, agent_view));
                                                    selected_agent_id.set(created_id.clone());
                                                    create_mode.set(false);
                                                    new_agent_avatar_blob_ref.set(String::new());

                                                    last_op_status.set(format!(
                                                        "Created {} with recoverable Agent PCR. Add it to a Realm to enable data access.",
                                                        short_protocol_id(&created_id)
                                                    ));
                                                });
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
                                let pairing_url_was_copied = copied_pairing_url() == deep_link;
                                let pairing_qr_svg = render_agent_pairing_qr_svg(&deep_link);
                                let pairing_badge = if !selected_pcr_recovery_ready {
                                    "badge amber"
                                } else if selected_pairing_is_expired {
                                    "badge red"
                                } else {
                                    "badge amber"
                                };
                                let pairing_label = if !selected_pcr_recovery_ready {
                                    "Recovery required"
                                } else if selected_pairing_is_expired {
                                    "Expired"
                                } else {
                                    "Awaiting runtime"
                                };
                                let replacement_agent_slug = selected_slug.clone();
                                let pcr_bootstrap_target = selected_pcr_bootstrap_target.clone();
                                rsx! {
                                    div {
                                        class: "agent-admin-section agent-admin-pairing-card",
                                        "data-testid": "agent-admin-pairing-card",
                                        div { class: "agent-admin-section-head",
                                            strong { "Connect an agent runtime" }
                                            div { class: "agent-admin-pairing-head-actions",
                                                span { class: "{pairing_badge}", "{pairing_label}" }
                                                if selected_pcr_recovery_ready && !selected_pairing_is_expired {
                                                    Button {
                                                        variant: ButtonVariant::Secondary,
                                                        size: ButtonSize::Sm,
                                                        class: if pairing_url_was_copied {
                                                            "btn agent-admin-pairing-action success"
                                                        } else {
                                                            "btn agent-admin-pairing-action"
                                                        },
                                                        "data-testid": "agent-admin-copy-pairing-link-button",
                                                        disabled: deep_link.is_empty(),
                                                        onclick: {
                                                            let deep_link = deep_link.clone();
                                                            move |_| {
                                                                copy_text_to_clipboard(&deep_link);
                                                                copied_pairing_url.set(deep_link.clone());
                                                                let copied_url = deep_link.clone();
                                                                spawn(async move {
                                                                    crate::runtime_helpers::sleep_for(
                                                                        Duration::from_millis(2_000),
                                                                    )
                                                                    .await;
                                                                    if copied_pairing_url() == copied_url {
                                                                        copied_pairing_url.set(String::new());
                                                                    }
                                                                });
                                                            }
                                                        },
                                                        if pairing_url_was_copied {
                                                            UiIcon { name: "check" }
                                                        } else {
                                                            UiIcon { name: "copy" }
                                                        }
                                                        span {
                                                            "aria-live": "polite",
                                                            "aria-atomic": "true",
                                                            if pairing_url_was_copied { "Copied" } else { "Copy URL" }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        if !selected_pcr_recovery_ready {
                                            div {
                                                class: "agent-admin-status",
                                                "data-testid": "agent-admin-pcr-recovery-pending",
                                                if selected_pairing_is_expired {
                                                    "This pairing expired before the Agent's encrypted control state was backed up. Set up recovery on this device first; then you can issue a fresh pairing code. This step does not pair a runtime."
                                                } else {
                                                    "Back up this Agent's encrypted control state before connecting a runtime. The controller can then restore the Agent if its runtime or keys are lost."
                                                }
                                            }
                                            div { class: "actions",
                                                Button {
                                                    variant: ButtonVariant::Primary,
                                                    "data-testid": "agent-admin-finish-pcr-recovery-button",
                                                    disabled: pcr_bootstrap_target.is_none(),
                                                    onclick: {
                                                        let base = base_url.clone();
                                                        let target = pcr_bootstrap_target.clone();
                                                        move |_| {
                                                            let Some((agent_id, realm_id, authorization_ref)) = target.clone() else {
                                                                last_op_status.set(
                                                                    "Agent PCR binding is unavailable; refresh the Agent details and retry."
                                                                        .to_owned(),
                                                                );
                                                                return;
                                                            };
                                                            let base = base.clone();
                                                            let api_token = token();
                                                            spawn(async move {
                                                                let bootstrap_agent_id = agent_id.clone();
                                                                let result = with_authed_api(
                                                                    &base,
                                                                    api_token.clone(),
                                                                    move |api| async move {
                                                                        super::bootstrap::bootstrap_provisioned_agent(
                                                                            &api,
                                                                            state_store,
                                                                            &bootstrap_agent_id,
                                                                            &realm_id,
                                                                            &authorization_ref,
                                                                            None,
                                                                        )
                                                                        .await
                                                                    },
                                                                )
                                                                .await;
                                                                match result {
                                                                    Ok(()) => {
                                                                        last_op_status.set(
                                                                            "Agent PCR recovery is ready. Runtime pairing is now available."
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
                                                                    Err(err) => last_op_status.set(format!(
                                                                        "Agent PCR recovery setup failed: {}",
                                                                        err.display()
                                                                    )),
                                                                }
                                                            });
                                                        }
                                                    },
                                                    "Set up recovery"
                                                }
                                            }
                                        }
                                        if selected_pcr_recovery_ready && selected_pairing_is_expired {
                                            div {
                                                class: "agent-admin-status error",
                                                "data-testid": "agent-admin-pairing-expired-message",
                                                "This pairing request expired. The expired code and link can never be used again; pair again to issue a fresh code and QR for this agent."
                                            }
                                        }
                                        if selected_pcr_recovery_ready && !selected_pairing_is_expired {
                                            div { class: "agent-admin-pairing-panel",
                                                div { class: "agent-admin-pairing-qr-pane",
                                                    strong { class: "agent-admin-pairing-pane-label", "QR" }
                                                    if pairing_qr_svg.is_empty() {
                                                        div { class: "muted", "QR unavailable" }
                                                    } else {
                                                        div {
                                                            class: "agent-admin-qr",
                                                            "data-testid": "agent-admin-pairing-qr",
                                                            role: "img",
                                                            "aria-label": "Agent runtime pairing QR code",
                                                            dangerous_inner_html: "{pairing_qr_svg}",
                                                        }
                                                    }
                                                }
                                                div { class: "agent-admin-pairing-url-pane",
                                                    strong { class: "agent-admin-pairing-pane-label", "URL" }
                                                    Textarea {
                                                        class: "mono agent-admin-pairing-url-field",
                                                        "data-testid": "agent-admin-pairing-url",
                                                        readonly: true,
                                                        rows: "7",
                                                        value: "{deep_link}",
                                                    }
                                                }
                                            }
                                        }
                                        if selected_pcr_recovery_ready && selected_pairing_is_expired {
                                            div { class: "actions",
                                                Button {
                                                    variant: ButtonVariant::Primary,
                                                    "data-testid": "agent-admin-renew-pairing-button",
                                                    onclick: {
                                                        // `ak.self.agent.command.renew_pairing`:
                                                        // re-open pairing on this agent in place —
                                                        // fresh one-time code + QR, same principal,
                                                        // no replacement agent.
                                                        let base = base_url.clone();
                                                        let renew_agent_id = selected_id_now.clone();
                                                        let renew_slug = replacement_agent_slug.clone();
                                                        move |_| {
                                                            let base = base.clone();
                                                            let api_token = token();
                                                            let renewed_agent_id = renew_agent_id.clone();
                                                            let slug = renew_slug.clone();
                                                            spawn(async move {
                                                                let renew_id = renewed_agent_id.clone();
                                                                let outcome = match with_authed_sdk_client(
                                                                    &base,
                                                                    api_token.clone(),
                                                                    move |http| {
                                                                        let renew_id = renew_id.clone();
                                                                        async move {
                                                                            http.agent_renew_pairing(
                                                                                &renew_id,
                                                                                &arkret_sdk::models::AgentRenewPairingRequestBody::default(),
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
                                                                            "Pair again failed: {}",
                                                                            err.display()
                                                                        ));
                                                                        return;
                                                                    }
                                                                };
                                                                // Patch the row locally so the pairing
                                                                // card re-renders immediately; the
                                                                // detail effect refetch reconciles with
                                                                // the server view afterwards.
                                                                agents.with_mut(|rows| {
                                                                    for row in rows.iter_mut() {
                                                                        if agent_id(row) != renewed_agent_id.as_str() {
                                                                            continue;
                                                                        }
                                                                        row.status = AgentStatus::PendingRuntimeKey;
                                                                        row.agent.status = AgentStatus::PendingRuntimeKey;
                                                                        if let Some(key_state) = row.key_state.as_mut() {
                                                                            key_state.status = AgentStatus::PendingRuntimeKey;
                                                                            key_state.pairing_request_id = Some(outcome.pairing_request_id.clone());
                                                                            key_state.pairing_code = outcome.pairing_code.clone();
                                                                            key_state.pairing_expires_at = Some(outcome.expires_at);
                                                                        }
                                                                    }
                                                                });
                                                                last_op_status.set(format!(
                                                                    "Pairing renewed for {}. Scan the new QR or copy the new link; the old one is dead.",
                                                                    if slug.trim().is_empty() {
                                                                        short_protocol_id(&renewed_agent_id)
                                                                    } else {
                                                                        slug.clone()
                                                                    }
                                                                ));
                                                            });
                                                        }
                                                    },
                                                    "Pair again"
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
                                        span { class: if selected_status == "active" { "badge green" } else { "badge amber" },
                                            if selected_status == "active" { "Active" } else { "Paused" }
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
                                                        enabled,
                                                        agents,
                                                        last_op_status,
                                                    );
                                                }
                                            },
                                        }
                                    }
                                }
                            }
                            div { class: "actions",
                                    if selected_is_replaceable {
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "agent-admin-replace-runtime-button",
                                            onclick: {
                                                // `ak.self.agent.command.renew_pairing` on an
                                                // active/paused agent: runtime replacement
                                                // re-pairing. Status, keys and grants stay
                                                // untouched until the new runtime pairs; the
                                                // old key is then revoked
                                                // (reason=superseded_by_repairing).
                                                let base = base_url.clone();
                                                let replace_agent_id = selected_id_now.clone();
                                                move |_| {
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
                                                                        &arkret_sdk::models::AgentRenewPairingRequestBody::default(),
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
                                                        // Patch pairing fields only; the agent
                                                        // status is intentionally untouched
                                                        // (replacement is not a state
                                                        // transition).
                                                        agents.with_mut(|rows| {
                                                            for row in rows.iter_mut() {
                                                                if agent_id(row) != replaced_agent_id.as_str() {
                                                                    continue;
                                                                }
                                                                if let Some(key_state) = row.key_state.as_mut() {
                                                                    key_state.pairing_request_id = Some(outcome.pairing_request_id.clone());
                                                                    key_state.pairing_code = outcome.pairing_code.clone();
                                                                    key_state.pairing_expires_at = Some(outcome.expires_at);
                                                                }
                                                            }
                                                        });
                                                        last_op_status.set(
                                                            "Replacement pairing ready. The current runtime keeps working until the new one pairs; its key is then revoked.".to_owned(),
                                                        );
                                                    });
                                                }
                                            },
                                            "Replace runtime"
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
                                                move |_| {
                                                    let id = selected_agent_id();
                                                    if id.is_empty() { return; }
                                                    let id_for_status = id.clone();
                                                    let base = base.clone();
                                                    let api_token = token();
                                                    let body = AgentDeactivateRequestBody { reason: Some("controller_deactivated".to_owned()) };
                                                    spawn(async move {
                                                        match with_authed_sdk_client(&base, api_token, move |http| {
                                                            let id = id.clone();
                                                            let body = body.clone();
                                                            async move { http.agent_deactivate(&id, &body).await.map_err(anyhow::Error::from) }
                                                        })
                                                        .await
                                                        {
                                                            Ok(r) => {
                                                                let status = agent_status_from_lifecycle(r.status);
                                                                agents.with_mut(|rows| {
                                                                    update_agent_status(rows, &id_for_status, status)
                                                                });
                                                                last_op_status.set("Agent deactivated permanently.".to_owned());
                                                                deactivate_dialog_open.set(false);
                                                                deactivate_confirm.set(String::new());
                                                            }
                                                            Err(err) => last_op_status.set(format!(
                                                                "Deactivate failed: {}",
                                                                err.display()
                                                            )),
                                                        }
                                                    });
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
