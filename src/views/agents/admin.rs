//! Personal agent settings panel.
//!
//! This view is deliberately limited to settings backed by live server
//! calls: the agent directory row, runtime pairing/key state, lifecycle,
//! capability grants, and per-Realm participation policy.

use std::time::Duration;

use arkret_sdk::RealmId;
use arkret_sdk::models::{
    AgentDeactivateRequestBody, AgentGrantAttachRequestBody, AgentParticipation,
    AgentParticipationEntry, AgentParticipationScope, AgentParticipationSetRequestBody,
    AgentPauseRequestBody, AgentProvisionRequestBody, AgentResumeRequestBody, AgentView,
};
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use serde_json::{Value, json};
use yoface::utils::dom::copy_text_to_clipboard;

use super::model::{
    AgentGrantPreset, AgentServiceScopePreset, agent_state_badge_class, agent_state_label,
    agent_view_from_directory_row, build_agent_pairing_deep_link,
    build_agent_pairing_handoff_token, is_pairing_request_expired, participation_ceiling_reason,
    render_agent_pairing_qr_svg, requested_scope_for_presets,
};
use crate::components::UiIcon;
use crate::transport::auth::with_authed_sdk_client;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::dialog::Dialog;
use crate::ui::input::Input;
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

fn grant_identifier(grant: &Value) -> String {
    grant
        .get("grant_id")
        .or_else(|| grant.get("id"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
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

fn agent_status_hidden_by_default(status: &str) -> bool {
    matches!(status, "pairing_expired" | "deactivated")
}

const AGENT_LIST_FILTERS: [(&str, &str); 4] = [
    ("all", "All"),
    ("active", "Active"),
    ("pending", "Pending"),
    ("inactive", "Inactive"),
];

fn agent_status_is_pending(status: &str) -> bool {
    matches!(status, "pending" | "pending_runtime_key")
}

fn agent_status_is_inactive(status: &str) -> bool {
    matches!(status, "paused" | "pairing_expired" | "deactivated")
}

fn agent_matches_filter(status: &str, filter: &str) -> bool {
    match filter {
        "active" => status == "active",
        "pending" => agent_status_is_pending(status),
        "inactive" => agent_status_is_inactive(status),
        _ => true,
    }
}

fn spawn_refresh_agents(
    base: String,
    api_token: String,
    mut agents: Signal<Vec<AgentView>>,
    mut selected_agent_id: Signal<String>,
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
                let current = selected_agent_id.peek().clone();
                if current.is_empty() || !rows.iter().any(|row| agent_principal_id(row) == current)
                {
                    selected_agent_id.set(
                        rows.iter()
                            .find(|row| !agent_status_hidden_by_default(&row.status))
                            .or_else(|| rows.first())
                            .map(agent_principal_id)
                            .unwrap_or_default(),
                    );
                }
                if skipped > 0 {
                    list_status.set(format!(
                        "Loaded {} agent(s); skipped {} invalid row(s).",
                        rows.len(),
                        skipped
                    ));
                } else {
                    list_status.set(format!("Loaded {} agent(s).", rows.len()));
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
                let loaded_id = agent_principal_id(&view);
                let grant_count = view.grants.len();
                agents.with_mut(|rows| upsert_agent_view(rows, view));
                last_op_status.set(format!(
                    "Loaded {} with {} grant(s).",
                    short_protocol_id(&loaded_id),
                    grant_count
                ));
            }
            Err(err) => {
                last_op_status.set(format!("Failed to load agent details: {}", err.display()))
            }
        }
    });
}

fn spawn_load_agent_participation(
    base: String,
    api_token: String,
    id: String,
    selected_agent_id: Signal<String>,
    mut participation_realm: Signal<String>,
    mut participation_reply: Signal<bool>,
    mut participation_mention: Signal<bool>,
    mut participation_aob: Signal<bool>,
    mut participation_entries: Signal<Vec<AgentParticipationEntry>>,
) {
    spawn(async move {
        if id.trim().is_empty() {
            participation_entries.set(Vec::new());
            return;
        }
        let requested_id = id.clone();
        let result = with_authed_sdk_client(&base, api_token, move |http| {
            let id = id.clone();
            async move {
                http.agent_participation_get(&id)
                    .await
                    .map_err(anyhow::Error::from)
            }
        })
        .await;
        if selected_agent_id() != requested_id {
            return;
        }
        let Ok(response) = result else {
            participation_entries.set(Vec::new());
            return;
        };

        if let Some(entry) = response.entries.first() {
            if let AgentParticipationScope::Realm { realm_id } = &entry.scope {
                participation_realm.set(realm_id.as_str().to_owned());
            }
            participation_reply.set(entry.selection.reply);
            participation_mention.set(entry.selection.accept_third_party_mention);
            participation_aob.set(entry.selection.act_on_behalf);
        } else {
            participation_realm.set(String::new());
            participation_reply.set(false);
            participation_mention.set(false);
            participation_aob.set(false);
        }
        participation_entries.set(response.entries);
    });
}

#[component]
pub fn PersonalAgentAdminPanel(token: Signal<String>, controller_did: String) -> Element {
    // A4 — base_url from session context instead of a prop.
    let base_url = crate::app::SessionContext::base_url_string();
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
    let mut agent_list_filter = use_signal(|| "all".to_owned());
    let mut agent_list_refresh_epoch = use_signal(|| 0_u64);
    let mut grant_json = use_signal(|| "{}".to_owned());
    let mut deactivate_confirm = use_signal(String::new);
    let mut deactivate_dialog_open = use_signal(|| false);
    let mut last_op_status = use_signal(String::new);
    let mut participation_realm = use_signal(String::new);
    let mut participation_reply = use_signal(|| false);
    let mut participation_mention = use_signal(|| false);
    let mut participation_aob = use_signal(|| false);
    let mut participation_entries = use_signal(Vec::<AgentParticipationEntry>::new);
    let mut copied_pairing_url = use_signal(String::new);

    {
        let base = base_url.clone();
        use_effect(move || {
            let api_token = token();
            spawn_refresh_agents(
                base.clone(),
                api_token,
                agents,
                selected_agent_id,
                list_status,
                agent_list_refresh_epoch,
            );
        });
    }

    {
        let base = base_url.clone();
        use_effect(move || {
            spawn_load_agent_participation(
                base.clone(),
                token(),
                selected_agent_id(),
                selected_agent_id,
                participation_realm,
                participation_reply,
                participation_mention,
                participation_aob,
                participation_entries,
            );
        });
    }

    let selected_id_now = selected_agent_id();
    let is_create_mode = create_mode();
    let active_agent_filter = agent_list_filter();
    let (selected_agent, visible_agents, has_any_agents) = {
        let rows = agents.read();
        let selected_agent = rows
            .iter()
            .find(|agent| agent_principal_id(agent) == selected_id_now)
            .cloned();
        let visible_agents = rows
            .iter()
            .filter(|agent| agent_matches_filter(&agent.status, &active_agent_filter))
            .cloned()
            .collect::<Vec<_>>();
        (selected_agent, visible_agents, !rows.is_empty())
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
    let owner_label = short_protocol_id(&controller_did);
    let selected_grants_snapshot = selected_grants();
    let participation_entries_snapshot = participation_entries();

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
                                            selected_agent_id,
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
                                        onclick: move |_| agent_list_filter.set(filter_value.clone()),
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
                                            let base = base_url.clone();
                                            let id = id.clone();
                                            move |_| {
                                                create_mode.set(false);
                                                selected_agent_id.set(id.clone());
                                                spawn_load_agent_details(
                                                    base.clone(),
                                                    token(),
                                                    id.clone(),
                                                    agents,
                                                    selected_grants,
                                                    last_op_status,
                                                );
                                            }
                                        },
                                        span { class: "agent-admin-list-row-main",
                                            strong { "{display_name}" }
                                            span { class: "{agent_state_badge_class(&status)}", "{agent_state_label(&status)}" }
                                        }
                                        if !agent_slug.is_empty() {
                                            span { class: "muted", "/{agent_slug}" }
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
                                div { class: "entity-title", "{selected_title}" }
                                div { class: "mono muted", title: "{selected_id_now}", "{selected_id_now}" }
                            }
                            if !selected_status.is_empty() {
                                div { class: "agent-admin-current-status",
                                    span { class: "muted", "Status" }
                                    span {
                                        class: "{agent_state_badge_class(&selected_status)}",
                                        "data-testid": "agent-state-badge",
                                        "data-state": "{selected_status}",
                                        "{agent_state_label(&selected_status)}"
                                    }
                                }
                            }
                        }

                        div { class: "metric-grid agent-admin-detail-grid",
                            div { class: "metric",
                                strong { "Owner" }
                                span { class: "mono", title: "{controller_did}", "{owner_label}" }
                            }
                            div { class: "metric",
                                strong { "Slug" }
                                if selected_slug.is_empty() {
                                    span { "-" }
                                } else {
                                    span { "/{selected_slug}" }
                                }
                            }
                            div { class: "metric",
                                strong { "Created" }
                                if selected_created_at.is_empty() {
                                    span { "-" }
                                } else {
                                    span { "{selected_created_at}" }
                                }
                            }
                            div { class: "metric",
                                strong { "Updated" }
                                if selected_updated_at.is_empty() {
                                    span { "-" }
                                } else {
                                    span { "{selected_updated_at}" }
                                }
                            }
                        }

                        div { class: "agent-admin-detail-actions actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "agent-admin-get-button",
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        spawn_load_agent_details(
                                            base.clone(),
                                            token(),
                                            selected_agent_id(),
                                            agents,
                                            selected_grants,
                                            last_op_status,
                                        );
                                    }
                                },
                                "Load details"
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

                        div { class: "agent-admin-section", "data-testid": "agent-admin-grants",
                            div { class: "agent-admin-section-head",
                                strong { "Capability grants" }
                                span { class: "muted", "Loaded from selected agent" }
                            }
                            if selected_grants_snapshot.is_empty() {
                                div { class: "muted", "data-testid": "agent-admin-grant-empty",
                                    "No grants returned for this agent."
                                }
                            } else {
                                div { class: "agent-admin-grant-list", "data-testid": "agent-admin-grant-list",
                                    for grant in selected_grants_snapshot.iter() {
                                        {
                                            let grant_id = grant_identifier(grant);
                                            let grant_status = grant
                                                .get("status")
                                                .and_then(Value::as_str)
                                                .unwrap_or("active")
                                                .to_owned();
                                            let expires_at = grant
                                                .get("expires_at")
                                                .and_then(Value::as_str)
                                                .unwrap_or("-")
                                                .to_owned();
                                            let grant_id_label = short_protocol_id(&grant_id);
                                            rsx! {
                                                div {
                                                    class: "agent-admin-grant-row",
                                                    "data-testid": "agent-admin-grant-row",
                                                    "data-grant-id": "{grant_id}",
                                                    div {
                                                        strong { class: "mono", title: "{grant_id}", "{grant_id_label}" }
                                                        div { class: "muted", "Expires: {expires_at}" }
                                                    }
                                                    span { class: "badge", "{grant_status}" }
                                                    Button {
                                                        variant: ButtonVariant::Secondary,
                                                        "data-testid": "agent-admin-grant-detach-button",
                                                        disabled: grant_id.is_empty(),
                                                        onclick: {
                                                            let base = base_url.clone();
                                                            let grant_id = grant_id.clone();
                                                            move |_| {
                                                                let id = selected_agent_id();
                                                                if id.is_empty() || grant_id.is_empty() { return; }
                                                                let base = base.clone();
                                                                let api_token = token();
                                                                let grant_id = grant_id.clone();
                                                                let grant_id_for_retain = grant_id.clone();
                                                                spawn(async move {
                                                                    match with_authed_sdk_client(&base, api_token, move |http| {
                                                                        let id = id.clone();
                                                                        let grant_id = grant_id.clone();
                                                                        async move {
                                                                            let grant_id = arkret_sdk::GrantId::new(grant_id)
                                                                                .map_err(|err| anyhow::anyhow!("invalid agent grant id: {err}"))?;
                                                                            http.agent_grant_detach(&id, &grant_id).await.map_err(anyhow::Error::from)
                                                                        }
                                                                    })
                                                                    .await
                                                                    {
                                                                        Ok(r) => {
                                                                            selected_grants.write().retain(|g| {
                                                                                grant_identifier(g) != grant_id_for_retain
                                                                            });
                                                                            last_op_status.set(format!(
                                                                                "Grant revoked at {}.",
                                                                                r.revoked_at
                                                                            ));
                                                                        }
                                                                        Err(err) => last_op_status.set(format!(
                                                                            "Grant revoke failed: {}",
                                                                            err.display()
                                                                        )),
                                                                    }
                                                                });
                                                            }
                                                        },
                                                        "Revoke"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            details { class: "agent-admin-advanced",
                                summary { "Attach grant JSON" }
                                div { class: "workflow-form",
                                    Input {
                                        "data-testid": "agent-admin-grant-kind-input",
                                        placeholder: "Grant object JSON",
                                        value: "{grant_json}",
                                        oninput: move |event: FormEvent| grant_json.set(event.value()),
                                    }
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "agent-admin-grant-attach-button",
                                        disabled: grant_json().trim().is_empty(),
                                        onclick: {
                                            let base = base_url.clone();
                                            move |_| {
                                                let id = selected_agent_id();
                                                if id.is_empty() { return; }
                                                let grant: Value = match serde_json::from_str(grant_json().as_str()) {
                                                    Ok(grant) => grant,
                                                    Err(err) => {
                                                        last_op_status.set(format!(
                                                            "Grant JSON is invalid: {err}"
                                                        ));
                                                        return;
                                                    }
                                                };
                                                let body = AgentGrantAttachRequestBody { grant };
                                                let base = base.clone();
                                                let api_token = token();
                                                spawn(async move {
                                                    match with_authed_sdk_client(&base, api_token, move |http| {
                                                        let id = id.clone();
                                                        let body = body.clone();
                                                        async move {
                                                            http.agent_grant_attach(&id, &body).await.map_err(anyhow::Error::from)
                                                        }
                                                    })
                                                    .await
                                                    {
                                                        Ok(r) => last_op_status.set(format!(
                                                            "Grant attached: {}.",
                                                            short_protocol_id(r.grant_id.as_str())
                                                        )),
                                                        Err(err) => last_op_status.set(format!(
                                                            "Grant attach failed: {}",
                                                            err.display()
                                                        )),
                                                    }
                                                });
                                            }
                                        },
                                        "Attach"
                                    }
                                }
                            }
                        }

                        div { class: "agent-admin-section", "data-testid": "agent-admin-participation",
                            div { class: "agent-admin-section-head",
                                strong { "Realm behavior" }
                                span { class: "muted", "Saved per Realm" }
                            }
                            div { class: "workflow-form",
                                Input {
                                    "data-testid": "agent-admin-participation-realm-input",
                                    placeholder: "Realm ID",
                                    value: "{participation_realm}",
                                    oninput: move |event: FormEvent| {
                                        let value = event.value();
                                        let matching_selection = participation_entries
                                            .read()
                                            .iter()
                                            .find_map(|entry| match &entry.scope {
                                                AgentParticipationScope::Realm { realm_id }
                                                    if realm_id.as_str() == value.trim() =>
                                                {
                                                    Some(entry.selection)
                                                }
                                                _ => None,
                                            });
                                        participation_realm.set(value);
                                        if let Some(selection) = matching_selection {
                                            participation_reply.set(selection.reply);
                                            participation_mention
                                                .set(selection.accept_third_party_mention);
                                            participation_aob.set(selection.act_on_behalf);
                                        }
                                    },
                                }
                                label { class: "agent-admin-toggle-row", "data-testid": "agent-admin-participation-reply-row",
                                    Checkbox {
                                        "data-testid": "agent-admin-participation-reply",
                                        checked: if participation_reply() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                        on_checked_change: move |s: CheckboxState| participation_reply.set(bool::from(s)),
                                    }
                                    span { "Reply as the agent" }
                                }
                                label { class: "agent-admin-toggle-row", "data-testid": "agent-admin-participation-mention-row",
                                    Checkbox {
                                        "data-testid": "agent-admin-participation-mention",
                                        checked: if participation_mention() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                        on_checked_change: move |s: CheckboxState| participation_mention.set(bool::from(s)),
                                    }
                                    span { "Accept @mentions from other users" }
                                }
                                label { class: "agent-admin-toggle-row", "data-testid": "agent-admin-participation-aob-row",
                                    Checkbox {
                                        "data-testid": "agent-admin-participation-aob",
                                        checked: if participation_aob() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                        on_checked_change: move |s: CheckboxState| participation_aob.set(bool::from(s)),
                                    }
                                    span { "Act on my behalf" }
                                }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "agent-admin-participation-save-button",
                                        disabled: participation_realm().trim().is_empty(),
                                        onclick: {
                                            let base = base_url.clone();
                                            move |_| {
                                                let id = selected_agent_id();
                                                if id.is_empty() { return; }
                                                let realm = participation_realm();
                                                let realm_id = match RealmId::new(realm.trim()) {
                                                    Ok(realm_id) => realm_id,
                                                    Err(_) => {
                                                        last_op_status.set("Realm ID is invalid.".to_owned());
                                                        return;
                                                    }
                                                };
                                                let body = AgentParticipationSetRequestBody {
                                                    scope: AgentParticipationScope::Realm { realm_id },
                                                    selection: AgentParticipation {
                                                        reply: participation_reply(),
                                                        accept_third_party_mention: participation_mention(),
                                                        act_on_behalf: participation_aob(),
                                                    },
                                                };
                                                let base = base.clone();
                                                let api_token = token();
                                                spawn(async move {
                                                    match with_authed_sdk_client(&base, api_token, move |http| {
                                                        let id = id.clone();
                                                        let body = body.clone();
                                                        async move {
                                                            http.agent_participation_replace(&id, &body).await.map_err(anyhow::Error::from)
                                                        }
                                                    })
                                                    .await
                                                    {
                                                        Ok(r) => {
                                                            let entry_count = r.entries.len();
                                                            participation_entries.set(r.entries);
                                                            last_op_status.set(format!(
                                                                "Realm behavior saved for {} scope(s).",
                                                                entry_count
                                                            ));
                                                        }
                                                        Err(err) => last_op_status.set(format!(
                                                            "Realm behavior save failed: {}",
                                                            err.display()
                                                        )),
                                                    }
                                                });
                                            }
                                        },
                                        "Save"
                                    }
                                    if selected_status == "active" {
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "agent-admin-pause-button",
                                            onclick: {
                                                let base = base_url.clone();
                                                move |_| {
                                                    let id = selected_agent_id();
                                                    if id.is_empty() { return; }
                                                    let id_for_status = id.clone();
                                                    let base = base.clone();
                                                    let api_token = token();
                                                    let body = AgentPauseRequestBody { reason: Some("controller_paused".to_owned()) };
                                                    spawn(async move {
                                                        match with_authed_sdk_client(&base, api_token, move |http| {
                                                            let id = id.clone();
                                                            let body = body.clone();
                                                            async move { http.agent_pause(&id, &body).await.map_err(anyhow::Error::from) }
                                                        })
                                                        .await
                                                        {
                                                            Ok(r) => {
                                                                let status = r.status.as_wire_str().to_owned();
                                                                agents.with_mut(|rows| {
                                                                    update_agent_status(rows, &id_for_status, &status)
                                                                });
                                                                last_op_status.set(format!("Paused. Status: {status}."));
                                                            }
                                                            Err(err) => last_op_status.set(format!(
                                                                "Pause failed: {}",
                                                                err.display()
                                                            )),
                                                        }
                                                    });
                                                }
                                            },
                                            "Pause"
                                        }
                                    }
                                    if selected_status == "paused" {
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "agent-admin-resume-button",
                                            onclick: {
                                                let base = base_url.clone();
                                                move |_| {
                                                    let id = selected_agent_id();
                                                    if id.is_empty() { return; }
                                                    let id_for_status = id.clone();
                                                    let base = base.clone();
                                                    let api_token = token();
                                                    let body = AgentResumeRequestBody { sidecar_exposure_ack: None };
                                                    spawn(async move {
                                                        match with_authed_sdk_client(&base, api_token, move |http| {
                                                            let id = id.clone();
                                                            let body = body.clone();
                                                            async move { http.agent_resume(&id, &body).await.map_err(anyhow::Error::from) }
                                                        })
                                                        .await
                                                        {
                                                            Ok(r) => {
                                                                let status = r.status.as_wire_str().to_owned();
                                                                agents.with_mut(|rows| {
                                                                    update_agent_status(rows, &id_for_status, &status)
                                                                });
                                                                last_op_status.set(format!("Resumed. Status: {status}."));
                                                            }
                                                            Err(err) => last_op_status.set(format!(
                                                                "Resume failed: {}",
                                                                err.display()
                                                            )),
                                                        }
                                                    });
                                                }
                                            },
                                            "Resume"
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
                                if !participation_entries_snapshot.is_empty() {
                                    div { class: "agent-admin-participation-entries", "data-testid": "agent-admin-participation-entries",
                                        for entry in participation_entries_snapshot.iter() {
                                            {
                                                let key = entry.scope.scope_key();
                                                let sel = entry.selection;
                                                let eff = entry.effective;
                                                let ceil = entry.ceiling;
                                                let ceiling_reason = participation_ceiling_reason(sel, ceil);
                                                rsx! {
                                                    div {
                                                        class: "agent-admin-participation-entry",
                                                        "data-testid": "agent-admin-participation-entry",
                                                        "data-scope-key": "{key}",
                                                        strong { class: "mono", "{key}" }
                                                        div { class: "muted",
                                                            "Selected: reply={sel.reply}, mentions={sel.accept_third_party_mention}, act={sel.act_on_behalf}"
                                                        }
                                                        div { class: "muted",
                                                            "Effective: reply={eff.reply}, mentions={eff.accept_third_party_mention}, act={eff.act_on_behalf}"
                                                        }
                                                        div { class: "muted", "data-testid": "agent-admin-participation-ceiling-reason",
                                                            "{ceiling_reason}"
                                                        }
                                                    }
                                                }
                                            }
                                        }
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
                                                                last_op_status.set(format!(
                                                                    "Deactivated. Status: {status}."
                                                                ));
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
