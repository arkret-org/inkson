//! Personal agent settings panel.
//!
//! This view is deliberately limited to settings backed by live server
//! calls: the agent directory row, runtime pairing/key state, lifecycle,
//! capability grants, and per-Realm participation policy.

use cokret_sdk::RealmId;
use cokret_sdk::models::{
    AgentDeactivateRequestBody, AgentGrantAttachRequestBody, AgentParticipation,
    AgentParticipationEntry, AgentParticipationScope, AgentParticipationSetRequestBody,
    AgentPauseRequestBody, AgentProvisionRequestBody, AgentResumeRequestBody,
    AgentRotateKeyRequestBody, AgentView,
};
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use serde_json::{Value, json};
use yoface::utils::dom::copy_text_to_clipboard;

use super::model::{
    AgentGrantPreset, AgentServiceScopePreset, agent_state_badge_class, agent_state_label,
    agent_view_from_directory_row, build_savfox_pairing_bootstrap_json, expand_preset_grant,
    is_pairing_request_expired, participation_ceiling_reason, requested_scope_for_presets,
};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::input::Input;
use crate::views::helpers::{short_protocol_id, with_authed_api};

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

fn json_inline(value: &Value) -> String {
    if value.is_null() {
        "not reported".to_owned()
    } else {
        serde_json::to_string(value).unwrap_or_else(|_| "unavailable".to_owned())
    }
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

fn spawn_refresh_agents(
    base: String,
    api_token: String,
    mut agents: Signal<Vec<AgentView>>,
    mut selected_agent_id: Signal<String>,
    mut list_status: Signal<String>,
) {
    spawn(async move {
        if api_token.trim().is_empty() {
            list_status.set("Sign in to load your agents.".to_owned());
            return;
        }
        match with_authed_api(
            &base,
            api_token,
            |api| async move { api.agent_list().await },
        )
        .await
        {
            Ok(resp) => {
                let rows: Vec<AgentView> = resp
                    .agents
                    .into_iter()
                    .filter_map(agent_view_from_directory_row)
                    .collect();
                let current = selected_agent_id();
                if current.is_empty() || !rows.iter().any(|row| agent_principal_id(row) == current)
                {
                    selected_agent_id.set(rows.first().map(agent_principal_id).unwrap_or_default());
                }
                list_status.set(format!("Loaded {} agent(s).", rows.len()));
                agents.set(rows);
            }
            Err(err) => list_status.set(format!("Failed to load agents: {}", err.display())),
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
        match with_authed_api(&base, api_token, move |api| {
            let id = id.clone();
            async move { api.agent_get(&id).await }
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

#[component]
pub fn PersonalAgentAdminPanel(
    base_url: String,
    token: Signal<String>,
    controller_did: String,
) -> Element {
    let mut agents = use_signal(Vec::<AgentView>::new);
    let list_status = use_signal(String::new);
    let mut selected_agent_id = use_signal(String::new);
    let mut create_mode = use_signal(|| false);
    let mut new_display_name = use_signal(|| "my-personal-agent".to_owned());
    let mut new_agent_slug = use_signal(|| "summary".to_owned());
    let mut provision_presets =
        use_signal(|| vec![AgentGrantPreset::Read, AgentGrantPreset::ReplyAsAgent]);
    let mut provision_service_scopes = use_signal(|| AgentServiceScopePreset::DEFAULTS.to_vec());
    let mut provision_realm = use_signal(String::new);
    let mut pairing_outcome = use_signal(|| Option::<cokret_sdk::AgentProvisionOutcome>::None);
    let mut pairing_bootstrap_json = use_signal(|| Option::<String>::None);
    let mut selected_grants = use_signal(Vec::<Value>::new);
    let mut rotate_body_json = use_signal(String::new);
    let mut grant_json = use_signal(|| "{}".to_owned());
    let mut deactivate_confirm = use_signal(String::new);
    let mut last_op_status = use_signal(String::new);
    let mut participation_realm = use_signal(String::new);
    let mut participation_reply = use_signal(|| false);
    let mut participation_mention = use_signal(|| false);
    let mut participation_aob = use_signal(|| false);
    let mut participation_entries = use_signal(Vec::<AgentParticipationEntry>::new);

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
            );
        });
    }

    let selected_id_now = selected_agent_id();
    let is_create_mode = create_mode();
    let selected_agent = {
        let rows = agents.read();
        rows.iter()
            .find(|agent| agent_principal_id(agent) == selected_id_now)
            .cloned()
    };
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
    let selected_key_state = selected_agent
        .as_ref()
        .map(|agent| json_inline(&agent.key_state))
        .unwrap_or_else(|| "not loaded".to_owned());
    let selected_created_at = selected_agent
        .as_ref()
        .map(|agent| agent_field(agent, "created_at"))
        .unwrap_or_default();
    let selected_updated_at = selected_agent
        .as_ref()
        .map(|agent| agent_field(agent, "updated_at"))
        .unwrap_or_default();
    let owner_label = short_protocol_id(&controller_did);

    rsx! {
        div { class: "agent-admin-page", "data-testid": "personal-agent-admin",
            div { class: "agent-admin-saved-scope", "data-testid": "agent-admin-saved-scope",
                div { class: "metric",
                    strong { "Agent record" }
                    span { "Saved on the server. Name, slug, DID, and status are shared across devices." }
                }
                div { class: "metric",
                    strong { "Runtime access" }
                    span { "Pairing and key rotation authorize the runtime key for this agent." }
                }
                div { class: "metric",
                    strong { "Realm behavior" }
                    span { "Per-Realm reply, @mention, and act-on-behalf policy is saved server-side and used by Realm members views." }
                }
                div { class: "metric",
                    strong { "Capability grants" }
                    span { "Starter permissions and grant revocation update the agent's server-side authorization state." }
                }
            }

            if !last_op_status().is_empty() {
                div { class: "agent-admin-status", "data-testid": "agent-admin-last-op", "{last_op_status}" }
            }

            div { class: "agent-admin-layout",
                section { class: "event agent-admin-list-pane", "data-testid": "agent-admin-list",
                    div { class: "event-head",
                        span { "Agents" }
                        span { class: "badge", "{agents.read().len()} total" }
                    }
                    div { class: "actions agent-admin-list-actions",
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "agent-admin-refresh-button",
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    spawn_refresh_agents(
                                        base.clone(),
                                        token(),
                                        agents,
                                        selected_agent_id,
                                        list_status,
                                    );
                                }
                            },
                            "Refresh"
                        }
                        Button {
                            variant: if is_create_mode { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                            "data-testid": "agent-admin-create-open-button",
                            onclick: move |_| create_mode.set(true),
                            "Create"
                        }
                    }
                    if !list_status().is_empty() {
                        div { class: "muted", "data-testid": "agent-admin-list-status", "{list_status}" }
                    }
                    div { class: "agent-admin-list-rows",
                        if agents.read().is_empty() {
                            div { class: "members-empty compact", "data-testid": "agent-admin-list-empty",
                                div { class: "members-empty-title", "No agents yet." }
                            }
                        }
                        for agent in agents.read().iter() {
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
                                    div { class: "muted", "Create a personal AI agent with explicit runtime endpoint scope and separate Realm-scoped content grants." }
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
                                Input {
                                    "data-testid": "agent-admin-provision-realm-input",
                                    placeholder: "Realm ID for runtime scope and starter grants",
                                    value: "{provision_realm}",
                                    oninput: move |event: FormEvent| provision_realm.set(event.value()),
                                }
                                div { class: "muted", "Service scope lets the runtime call subscribe, scan, submit, and resource endpoints. Content grants decide whether payloads can be read or messages can be created." }
                                div { class: "agent-admin-section-head",
                                    strong { "Content capability grants" }
                                    span { class: "muted", "Payload and write authority" }
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
                                                let presets = provision_presets.read().clone();
                                                let service_scopes = provision_service_scopes.read().clone();
                                                let realm = provision_realm();
                                                let realm_for_grant = if realm.trim().is_empty() {
                                                    None
                                                } else {
                                                    Some(realm.trim().to_owned())
                                                };
                                                if realm_for_grant.is_none() {
                                                    last_op_status.set("Realm ID is required to build an explicit agent key scope.".to_owned());
                                                    return;
                                                }
                                                let requested_scope = match requested_scope_for_presets(
                                                    &presets,
                                                    &service_scopes,
                                                    realm_for_grant.as_deref(),
                                                ) {
                                                    Some(scope) => scope,
                                                    None => {
                                                        last_op_status.set("Select at least one content grant or runtime service surface.".to_owned());
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
                                                    let outcome = match with_authed_api(
                                                        &base,
                                                        api_token.clone(),
                                                        move |api| {
                                                            let body = body.clone();
                                                            async move { api.agent_provision(&body).await }
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
                                                    let expires_at = outcome.expires_at.to_rfc3339();
                                                    match build_savfox_pairing_bootstrap_json(
                                                        &base,
                                                        &outcome,
                                                        &requested_scope,
                                                        &presets,
                                                    ) {
                                                        Ok(bootstrap) => pairing_bootstrap_json.set(Some(bootstrap)),
                                                        Err(err) => {
                                                            pairing_bootstrap_json.set(None);
                                                            last_op_status.set(format!(
                                                                "Created pairing handle but Savfox bootstrap serialization failed: {err}"
                                                            ));
                                                        }
                                                    }
                                                    pairing_outcome.set(Some(outcome));

                                                    let mut attached = 0usize;
                                                    let mut grant_errs: Vec<String> = Vec::new();
                                                    for preset in presets.iter() {
                                                        let grant = expand_preset_grant(
                                                            *preset,
                                                            &created_agent_id,
                                                            realm_for_grant.as_deref(),
                                                            &expires_at,
                                                        );
                                                        let attach_body = AgentGrantAttachRequestBody { grant };
                                                        let agent_id_for_call = created_agent_id.clone();
                                                        match with_authed_api(
                                                            &base,
                                                            api_token.clone(),
                                                            move |api| {
                                                                let body = attach_body.clone();
                                                                let id = agent_id_for_call.clone();
                                                                async move {
                                                                    api.agent_grant_attach(&id, &body).await
                                                                }
                                                            },
                                                        )
                                                        .await
                                                        {
                                                            Ok(_) => attached += 1,
                                                            Err(err) => grant_errs.push(format!(
                                                                "{}: {}",
                                                                preset.label(),
                                                                err.display()
                                                            )),
                                                        }
                                                    }

                                                    let agent_object = json!({
                                                        "agent_principal_id": created_agent_id,
                                                        "display_name": display,
                                                        "agent_slug": slug_value,
                                                        "status": "pending_runtime_key",
                                                    });
                                                    let agent_view = AgentView {
                                                        agent: agent_object,
                                                        status: "pending_runtime_key".to_owned(),
                                                        grants: Vec::new(),
                                                        key_state: Value::Null,
                                                    };
                                                    let created_id = agent_principal_id(&agent_view);
                                                    agents.with_mut(|rows| upsert_agent_view(rows, agent_view));
                                                    selected_agent_id.set(created_id.clone());
                                                    selected_grants.set(Vec::new());
                                                    create_mode.set(false);

                                                    if grant_errs.is_empty() {
                                                        last_op_status.set(format!(
                                                            "Created {}. {} starter grant(s) attached.",
                                                            short_protocol_id(&created_id),
                                                            attached
                                                        ));
                                                    } else {
                                                        last_op_status.set(format!(
                                                            "Created {}; {} starter grant(s) attached, errors: {}",
                                                            short_protocol_id(&created_id),
                                                            attached,
                                                            grant_errs.join("; ")
                                                        ));
                                                    }
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
                                span {
                                    class: "{agent_state_badge_class(&selected_status)}",
                                    "data-testid": "agent-state-badge",
                                    "data-state": "{selected_status}",
                                    "{agent_state_label(&selected_status)}"
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

                        if let Some(outcome) = pairing_outcome() {
                            {
                                let agent_id = outcome.agent_principal_id.to_string();
                                let request_id = outcome.pairing_request_id.clone();
                                let pairing_code = outcome.pairing_code.clone();
                                let expires_at = outcome.expires_at.to_rfc3339();
                                let bootstrap_json = pairing_bootstrap_json().unwrap_or_else(|| "{}".to_owned());
                                let pairing_expired =
                                    is_pairing_request_expired(&expires_at, &crate::clock::now_rfc3339_secs());
                                let pairing_badge = if pairing_expired { "badge red" } else { "badge green" };
                                let pairing_label = if pairing_expired { "Expired" } else { "Bootstrap ready" };
                                if agent_id == selected_id_now {
                                    rsx! {
                                        div {
                                            class: "agent-admin-section",
                                            "data-testid": "agent-admin-pairing-card",
                                            "data-pairing-request-id": "{request_id}",
                                        div { class: "agent-admin-section-head",
                                            strong { "Connect with Savfox" }
                                            span { class: "{pairing_badge}", "{pairing_label}" }
                                        }
                                        div { class: "muted",
                                            "Copy this bootstrap into Savfox. Savfox generates and keeps the runtime private key; this bootstrap only carries the short-lived pairing handle, requested service scope, and content grant summary. It expires at {expires_at}."
                                        }
                                        div { class: "metric-grid",
                                            div { class: "metric",
                                                strong { "Pairing code" }
                                                if let Some(code) = pairing_code.clone() {
                                                    span { class: "mono", "data-testid": "agent-admin-pairing-code", "{code}" }
                                                } else {
                                                    span { class: "muted", "data-testid": "agent-admin-pairing-code", "Not returned by server" }
                                                }
                                            }
                                            div { class: "metric",
                                                strong { "Request" }
                                                span { class: "mono", "data-testid": "agent-admin-pairing-request-id", "{request_id}" }
                                            }
                                        }
                                        div { class: "muted",
                                            "Yougen does not yet approve a returned runtime public key in this panel; the old dead pairing page link was removed until that controller-signing flow is implemented."
                                        }
                                        pre {
                                            class: "agent-admin-url",
                                            "data-testid": "agent-admin-savfox-bootstrap-json",
                                            "{bootstrap_json}"
                                        }
                                        div { class: "actions",
                                            Button {
                                                variant: ButtonVariant::Primary,
                                                "data-testid": "agent-admin-copy-savfox-bootstrap-button",
                                                disabled: pairing_expired,
                                                onclick: {
                                                    let bootstrap_json = bootstrap_json.clone();
                                                    move |_| copy_text_to_clipboard(&bootstrap_json)
                                                },
                                                "Copy bootstrap"
                                            }
                                        }
                                    }
                                    }
                                } else {
                                    rsx! {}
                                }
                            }
                        }

                        div { class: "agent-admin-section", "data-testid": "agent-admin-lifecycle",
                            div { class: "agent-admin-section-head",
                                strong { "Status" }
                                span { class: "muted", "Stored on server" }
                            }
                            div { class: "actions",
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
                                                match with_authed_api(&base, api_token, move |api| {
                                                    let id = id.clone();
                                                    let body = body.clone();
                                                    async move { api.agent_pause(&id, &body).await }
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
                                                match with_authed_api(&base, api_token, move |api| {
                                                    let id = id.clone();
                                                    let body = body.clone();
                                                    async move { api.agent_resume(&id, &body).await }
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
                            div { class: "workflow-form agent-admin-deactivate-form",
                                Input {
                                    "data-testid": "agent-admin-deactivate-confirm-input",
                                    placeholder: "Type DEACTIVATE to enable",
                                    value: "{deactivate_confirm}",
                                    oninput: move |event: FormEvent| deactivate_confirm.set(event.value()),
                                }
                                Button {
                                    variant: ButtonVariant::Destructive,
                                    "data-testid": "agent-admin-deactivate-button",
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
                                                match with_authed_api(&base, api_token, move |api| {
                                                    let id = id.clone();
                                                    let body = body.clone();
                                                    async move { api.agent_deactivate(&id, &body).await }
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
                                                    }
                                                    Err(err) => last_op_status.set(format!(
                                                        "Deactivate failed: {}",
                                                        err.display()
                                                    )),
                                                }
                                            });
                                            deactivate_confirm.set(String::new());
                                        }
                                    },
                                    "Deactivate"
                                }
                            }
                        }

                        div { class: "agent-admin-section", "data-testid": "agent-admin-grants",
                            div { class: "agent-admin-section-head",
                                strong { "Capability grants" }
                                span { class: "muted", "Loaded from selected agent" }
                            }
                            if selected_grants.read().is_empty() {
                                div { class: "muted", "data-testid": "agent-admin-grant-empty",
                                    "No grants returned for this agent."
                                }
                            } else {
                                div { class: "agent-admin-grant-list", "data-testid": "agent-admin-grant-list",
                                    for grant in selected_grants.read().iter() {
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
                                                                    match with_authed_api(&base, api_token, move |api| {
                                                                        let id = id.clone();
                                                                        let grant_id = grant_id.clone();
                                                                        async move {
                                                                            api.agent_grant_detach(&id, &grant_id).await
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
                                                    match with_authed_api(&base, api_token, move |api| {
                                                        let id = id.clone();
                                                        let body = body.clone();
                                                        async move {
                                                            api.agent_grant_attach(&id, &body).await
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
                                    oninput: move |event: FormEvent| participation_realm.set(event.value()),
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
                                                    match with_authed_api(&base, api_token, move |api| {
                                                        let id = id.clone();
                                                        let body = body.clone();
                                                        async move {
                                                            api.agent_participation_set(&id, &body).await
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
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "agent-admin-participation-load-button",
                                        onclick: {
                                            let base = base_url.clone();
                                            move |_| {
                                                let id = selected_agent_id();
                                                if id.is_empty() { return; }
                                                let base = base.clone();
                                                let api_token = token();
                                                spawn(async move {
                                                    match with_authed_api(&base, api_token, move |api| {
                                                        let id = id.clone();
                                                        async move {
                                                            api.agent_participation_get(&id).await
                                                        }
                                                    })
                                                    .await
                                                    {
                                                        Ok(r) => {
                                                            let entry_count = r.entries.len();
                                                            participation_entries.set(r.entries);
                                                            last_op_status.set(format!(
                                                                "Loaded Realm behavior for {} scope(s).",
                                                                entry_count
                                                            ));
                                                        }
                                                        Err(err) => last_op_status.set(format!(
                                                            "Realm behavior load failed: {}",
                                                            err.display()
                                                        )),
                                                    }
                                                });
                                            }
                                        },
                                        "Load"
                                    }
                                }
                                if !participation_entries.read().is_empty() {
                                    div { class: "agent-admin-participation-entries", "data-testid": "agent-admin-participation-entries",
                                        for entry in participation_entries.read().iter() {
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

                        details { class: "agent-admin-section agent-admin-advanced", "data-testid": "agent-admin-rotate-key",
                            summary { "Runtime key rotation" }
                            div { class: "metric",
                                strong { "Current key state" }
                                span { class: "mono agent-admin-json", "{selected_key_state}" }
                            }
                            div { class: "workflow-form",
                                Input {
                                    "data-testid": "agent-admin-rotate-vm-input",
                                    placeholder: "Replacement key and proof JSON",
                                    value: "{rotate_body_json}",
                                    oninput: move |event: FormEvent| rotate_body_json.set(event.value()),
                                }
                                Button {
                                    variant: ButtonVariant::Primary,
                                    "data-testid": "agent-admin-rotate-key-button",
                                    disabled: rotate_body_json().trim().is_empty(),
                                    onclick: {
                                        let base = base_url.clone();
                                        move |_| {
                                            let id = selected_agent_id();
                                            let raw = rotate_body_json();
                                            if id.is_empty() || raw.trim().is_empty() { return; }
                                            let body: AgentRotateKeyRequestBody =
                                                match serde_json::from_str(&raw) {
                                                    Ok(body) => body,
                                                    Err(err) => {
                                                        last_op_status.set(format!(
                                                            "Runtime key JSON is invalid: {err}"
                                                        ));
                                                        return;
                                                    }
                                                };
                                            let base = base.clone();
                                            let api_token = token();
                                            spawn(async move {
                                                match with_authed_api(&base, api_token, move |api| {
                                                    let id = id.clone();
                                                    let body = body.clone();
                                                    async move { api.agent_rotate_key(&id, &body).await }
                                                })
                                                .await
                                                {
                                                    Ok(r) => last_op_status.set(format!(
                                                        "Runtime key rotated: {}.",
                                                        short_protocol_id(r.authorized_event_ref.as_str())
                                                    )),
                                                    Err(err) => last_op_status.set(format!(
                                                        "Runtime key rotation failed: {}",
                                                        err.display()
                                                    )),
                                                }
                                            });
                                        }
                                    },
                                    "Rotate key"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
