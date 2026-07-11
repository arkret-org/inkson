//! Personal agent settings panel.
//!
//! This view is deliberately limited to settings backed by live server
//! calls: the agent directory row, runtime pairing/key state, lifecycle,
//! capability grants, and lifecycle controls. Per-Realm participation is
//! configured from that Realm's Members area.

use std::time::Duration;

use arkret_sdk::models::{
    AgentDeactivateRequestBody, AgentPauseRequestBody, AgentProvisionRequestBody,
    AgentResumeRequestBody, AgentView,
};
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_router::hooks::{use_navigator, use_route};
use serde_json::{Value, json};
use yoface::utils::dom::copy_text_to_clipboard;

use super::model::{
    AgentGrantPreset, AgentServiceScopePreset, agent_state_badge_class, agent_state_label,
    agent_view_from_directory_row, build_agent_pairing_deep_link,
    build_agent_pairing_handoff_token, is_pairing_request_expired, render_agent_pairing_qr_svg,
    requested_scope_for_presets,
};
use crate::components::UiIcon;
use crate::routes::Route;
use crate::transport::auth::with_authed_sdk_client;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::dialog::Dialog;
use crate::ui::input::Input;
use crate::ui::switch::Switch;
use crate::ui::textarea::Textarea;
use crate::views::helpers::short_protocol_id;

fn agent_field(agent: &AgentView, key: &str) -> String {
    agent
        .agent
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn agent_principal_id(agent: &AgentView) -> String {
    agent_field(agent, "agent_principal_id")
}

fn agent_display_name(agent: &AgentView) -> String {
    let display_name = agent_field(agent, "display_name");
    if !display_name.is_empty() {
        return display_name;
    }
    let slug = agent_field(agent, "agent_slug");
    if !slug.is_empty() {
        return slug;
    }
    let id = agent_principal_id(agent);
    if id.is_empty() {
        "(unnamed agent)".to_owned()
    } else {
        short_protocol_id(&id)
    }
}

fn value_actions(value: &Value) -> Vec<&str> {
    value
        .get("actions")
        .or_else(|| value.get("grant").and_then(|grant| grant.get("actions")))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

fn grant_matches_content_preset(grant: &Value, preset: AgentGrantPreset) -> bool {
    let actions = value_actions(grant);
    if !preset
        .actions()
        .iter()
        .all(|action| actions.contains(action))
    {
        return false;
    }
    if preset != AgentGrantPreset::ActOnBehalf {
        return true;
    }
    grant
        .get("constraints")
        .or_else(|| {
            grant
                .get("grant")
                .and_then(|value| value.get("constraints"))
        })
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|constraint| {
            constraint
                .get("controller_approval_required")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
}

fn requested_scope_matches_service_preset(
    key_state: &Value,
    preset: AgentServiceScopePreset,
) -> bool {
    let actions = key_state
        .get("requested_scope")
        .map(value_actions)
        .unwrap_or_default();
    preset
        .actions()
        .iter()
        .all(|action| actions.contains(action))
}

fn upsert_agent_view(rows: &mut Vec<AgentView>, view: AgentView) {
    let id = agent_principal_id(&view);
    if id.is_empty() {
        return;
    }
    if let Some(existing) = rows.iter_mut().find(|row| agent_principal_id(row) == id) {
        *existing = view;
    } else {
        rows.push(view);
    }
}

fn update_agent_status(rows: &mut [AgentView], id: &str, status: &str) {
    for row in rows.iter_mut() {
        if agent_principal_id(row) == id {
            row.status = status.to_owned();
            if let Some(object) = row.agent.as_object_mut() {
                object.insert("status".to_owned(), json!(status));
            }
        }
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
                agents.set(rows);
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
    mut selected_grants: Signal<Vec<Value>>,
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
                selected_grants.set(view.grants.clone());
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
                let status = outcome.status.as_wire_str().to_owned();
                agents.with_mut(|rows| update_agent_status(rows, &id_for_status, &status));
                last_op_status.set(if enabled {
                    format!("Resumed. Status: {status}.")
                } else {
                    format!("Paused. Status: {status}.")
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
    let mut new_display_name = use_signal(|| "my-personal-agent".to_owned());
    let mut new_agent_slug = use_signal(|| "summary".to_owned());
    let mut provision_presets =
        use_signal(|| vec![AgentGrantPreset::Read, AgentGrantPreset::ReplyAsAgent]);
    let mut provision_service_scopes = use_signal(|| AgentServiceScopePreset::DEFAULTS.to_vec());
    let mut selected_grants = use_signal(Vec::<Value>::new);
    let mut agent_list_refresh_epoch = use_signal(|| 0_u64);
    let mut deactivate_confirm = use_signal(String::new);
    let mut deactivate_dialog_open = use_signal(|| false);
    let mut last_op_status = use_signal(String::new);
    let mut copied_pairing_url = use_signal(String::new);

    {
        let base = base_url.clone();
        use_effect(move || {
            let api_token = token();
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
                    agent_principal_id(agent) == current
                        && agent_matches_filter(&agent.status, &filter)
                }) {
                    current.clone()
                } else {
                    rows.iter()
                        .find(|agent| agent_matches_filter(&agent.status, &filter))
                        .map(agent_principal_id)
                        .unwrap_or_default()
                }
            };
            if next != current {
                selected_agent_id.set(next);
                selected_grants.set(Vec::new());
            }
        });
    }

    {
        let base = base_url.clone();
        use_effect(move || {
            let id = selected_agent_id();
            if id.is_empty() {
                selected_grants.set(Vec::new());
                return;
            }
            spawn_load_agent_details(
                base.clone(),
                token(),
                id,
                agents,
                selected_grants,
                last_op_status,
            );
        });
    }

    let selected_id_now = selected_agent_id();
    let is_create_mode = create_mode();
    let (selected_agent, visible_agents, has_any_agents) = {
        let rows = agents.read();
        let selected_agent = rows
            .iter()
            .find(|agent| {
                agent_principal_id(agent) == selected_id_now
                    && agent_matches_filter(&agent.status, &active_agent_filter)
            })
            .cloned();
        let visible_agents = rows
            .iter()
            .filter(|agent| agent_matches_filter(&agent.status, &active_agent_filter))
            .cloned()
            .collect::<Vec<_>>();
        let has_any_agents = rows
            .iter()
            .any(|agent| agent_matches_filter(&agent.status, "all"));
        (selected_agent, visible_agents, has_any_agents)
    };
    let last_op_status_message = last_op_status();
    let list_status_message = list_status();
    let selected_title = selected_agent
        .as_ref()
        .map(agent_display_name)
        .unwrap_or_else(|| "No agent selected".to_owned());
    let selected_slug = selected_agent
        .as_ref()
        .map(|agent| agent_field(agent, "agent_slug"))
        .unwrap_or_default();
    let selected_status = selected_agent
        .as_ref()
        .map(|agent| agent.status.clone())
        .unwrap_or_default();
    let selected_key_state_value = selected_agent
        .as_ref()
        .map(|agent| agent.key_state.clone())
        .unwrap_or(Value::Null);
    let selected_pairing_request_id = selected_key_state_value
        .get("pairing_request_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let selected_pairing_code = selected_key_state_value
        .get("pairing_code")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let selected_pairing_expires_at = selected_key_state_value
        .get("pairing_expires_at")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let now_rfc3339 = crate::clock::now_rfc3339_secs();
    let selected_pairing_is_expired = selected_status == "pairing_expired"
        || is_pairing_request_expired(&selected_pairing_expires_at, &now_rfc3339);
    let selected_has_pairing_handle =
        !selected_pairing_request_id.is_empty() && !selected_pairing_code.is_empty();
    let selected_should_show_pairing_card = matches!(
        selected_status.as_str(),
        "pending_runtime_key" | "pairing_expired"
    ) && (selected_has_pairing_handle
        || selected_pairing_is_expired);
    let selected_created_at = selected_agent
        .as_ref()
        .map(|agent| agent_field(agent, "created_at"))
        .unwrap_or_default();
    let selected_updated_at = selected_agent
        .as_ref()
        .map(|agent| agent_field(agent, "updated_at"))
        .unwrap_or_default();
    let selected_grants_snapshot = selected_grants();
    let selected_content_capabilities = AgentGrantPreset::ALL.map(|preset| {
        (
            preset,
            selected_grants_snapshot
                .iter()
                .any(|grant| grant_matches_content_preset(grant, preset)),
        )
    });
    let selected_service_capabilities = AgentServiceScopePreset::ALL.map(|preset| {
        (
            preset,
            requested_scope_matches_service_preset(&selected_key_state_value, preset),
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
                                onclick: move |_| create_mode.set(true),
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
                                let id = agent_principal_id(agent);
                                let display_name = agent_display_name(agent);
                                let agent_slug = agent_field(agent, "agent_slug");
                                let status = agent.status.clone();
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
                                        "data-agent-principal-id": "{id}",
                                        "aria-pressed": if is_selected { "true" } else { "false" },
                                        onclick: {
                                            let id = id.clone();
                                            move |_| {
                                                create_mode.set(false);
                                                selected_agent_id.set(id.clone());
                                            }
                                        },
                                        span { class: "agent-admin-list-row-main",
                                            strong { "{display_name}" }
                                            span { class: "{agent_state_badge_class(&status)}", "{agent_state_label(&status)}" }
                                        }
                                        if !agent_slug.is_empty() {
                                            span { class: "muted", "{agent_slug}" }
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
                                    "data-testid": "agent-admin-provision-display-name",
                                    placeholder: "Display name",
                                    value: "{new_display_name}",
                                    oninput: move |event: FormEvent| new_display_name.set(event.value()),
                                }
                                Input {
                                    "data-testid": "agent-admin-provision-agent-slug",
                                    placeholder: "Slug",
                                    value: "{new_agent_slug}",
                                    oninput: move |event: FormEvent| new_agent_slug.set(event.value()),
                                }
                                div { class: "muted", "Service scope lets the runtime call subscribe, scan, submit, and resource endpoints. Realm membership and participation controls decide whether payloads can be read or messages can be created." }
                                div { class: "agent-admin-section-head",
                                    strong { "Content capabilities" }
                                    span { class: "muted", "Available after Realm membership allows them" }
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
                                    span { class: "muted", "Endpoint operations for the agent key" }
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
                                        onclick: {
                                            let base = base_url.clone();
                                            move |_| {
                                                let display = new_display_name().trim().to_owned();
                                                if display.is_empty() {
                                                    last_op_status.set("Display name is required.".to_owned());
                                                    return;
                                                }
                                                let slug_value = new_agent_slug().trim().to_owned();
                                                let agent_slug = if slug_value.is_empty() {
                                                    None
                                                } else {
                                                    Some(slug_value.clone())
                                                };
                                                let service_scopes = provision_service_scopes.read().clone();
                                                let requested_scope = match requested_scope_for_presets(
                                                    &service_scopes,
                                                ) {
                                                    Some(scope) => scope,
                                                    None => {
                                                        last_op_status.set("Select at least one runtime service surface.".to_owned());
                                                        return;
                                                    }
                                                };
                                                let body = AgentProvisionRequestBody {
                                                    display_name: Some(display.clone()),
                                                    agent_slug,
                                                    requested_scope: Some(requested_scope.clone()),
                                                    accountability: Value::Null,
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
                                                    let created_agent_id =
                                                        outcome.agent_principal_id.to_string();
                                                    let expires_at = outcome
                                                        .expires_at
                                                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                                                    let agent_object = json!({
                                                        "agent_principal_id": created_agent_id,
                                                        "display_name": display,
                                                        "agent_slug": slug_value,
                                                        "status": "pending_runtime_key",
                                                    });
                                                    let key_state = json!({
                                                        "status": "pending_runtime_key",
                                                        "pairing_request_id": outcome.pairing_request_id,
                                                        "pairing_code": outcome.pairing_code,
                                                        "pairing_expires_at": expires_at,
                                                        "requested_scope": requested_scope,
                                                    });
                                                    let agent_view = AgentView {
                                                        agent: agent_object,
                                                        status: "pending_runtime_key".to_owned(),
                                                        grants: Vec::new(),
                                                        key_state,
                                                    };
                                                    let created_id = agent_principal_id(&agent_view);
                                                    agent_list_refresh_epoch.set(
                                                        agent_list_refresh_epoch()
                                                            .saturating_add(1),
                                                    );
                                                    agents.with_mut(|rows| upsert_agent_view(rows, agent_view));
                                                    selected_agent_id.set(created_id.clone());
                                                    selected_grants.set(Vec::new());
                                                    create_mode.set(false);

                                                    last_op_status.set(format!(
                                                        "Created {}. Add it to a Realm to enable data access.",
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
                                        onclick: move |_| create_mode.set(false),
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
                                    "data-testid": "agent-admin-display-name",
                                    "{selected_title}"
                                }
                                div { class: "mono muted", title: "{selected_id_now}", "{selected_id_now}" }
                            }
                        }

                        div { class: "agent-admin-detail-meta", "data-testid": "agent-admin-detail-meta",
                            div { class: "agent-admin-detail-meta-item",
                                span { class: "muted", "Slug" }
                                if selected_slug.is_empty() {
                                    span { "-" }
                                } else {
                                    span { class: "mono", "{selected_slug}" }
                                }
                            }
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
                                let pairing_badge = if selected_pairing_is_expired { "badge red" } else { "badge green" };
                                let pairing_label = if selected_pairing_is_expired { "Expired" } else { "Ready" };
                                let replacement_display_name = selected_title.clone();
                                let replacement_agent_slug = selected_slug.clone();
                                rsx! {
                                    div {
                                        class: "agent-admin-section agent-admin-pairing-card",
                                        "data-testid": "agent-admin-pairing-card",
                                        div { class: "agent-admin-section-head",
                                            strong { "Connect an agent runtime" }
                                            div { class: "agent-admin-pairing-head-actions",
                                                span { class: "{pairing_badge}", "{pairing_label}" }
                                                if !selected_pairing_is_expired {
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
                                        if selected_pairing_is_expired {
                                            div {
                                                class: "agent-admin-status error",
                                                "data-testid": "agent-admin-pairing-expired-message",
                                                "This pairing request expired. The expired handle cannot be used again; pair again to get a fresh pairing request. Expired agents do not reserve the slug."
                                            }
                                        }
                                        if !selected_pairing_is_expired {
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
                                        if selected_pairing_is_expired {
                                            div { class: "actions",
                                                Button {
                                                    variant: ButtonVariant::Primary,
                                                    "data-testid": "agent-admin-create-replacement-button",
                                                    onclick: {
                                                        let replacement_display_name = replacement_display_name.clone();
                                                        let replacement_agent_slug = replacement_agent_slug.clone();
                                                        move |_| {
                                                            new_display_name.set(replacement_display_name.clone());
                                                            new_agent_slug.set(if replacement_agent_slug.trim().is_empty() {
                                                                "summary".to_owned()
                                                            } else {
                                                                replacement_agent_slug.clone()
                                                            });
                                                            create_mode.set(true);
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
                                span { class: "muted", "Current effective grants" }
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
                                                                let status = r.status.as_wire_str().to_owned();
                                                                agents.with_mut(|rows| {
                                                                    update_agent_status(rows, &id_for_status, &status)
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
