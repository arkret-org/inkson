//! Agent settings panel.
//!
//! This view is deliberately limited to settings backed by live server
//! calls: the agent directory row, runtime pairing/key state, lifecycle,
//! capability grants, and lifecycle controls. Per-Realm participation is
//! configured from that Realm's Members area.

use std::time::Duration;

use arkret_models_collaboration::agent_operations::{
    AgentDeactivateRequestBody, AgentLifecycleState, AgentPauseRequestBody, AgentProvisionOutcome,
    AgentProvisionRequestBody, AgentRenewPairingOutcome, AgentResumeRequestBody, AgentRuntimeState,
    AgentView, KeyState,
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

mod controller;
mod model;

use controller::*;
use model::*;

// Invariant assertions: each `expect` message names the check that
// establishes it a few lines earlier. Rewriting them as `?` would add
// error paths no caller can reach.
#[allow(clippy::expect_used)]
#[component]
pub fn AgentAdminPanel(
    token: Signal<String>,
    controller_principal_id: arkret_sdk::DidCoreId,
) -> Element {
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
    let agents = use_signal(Vec::<AgentView>::new);
    let list_status = use_signal(String::new);
    let mut selected_agent_id = use_signal(String::new);
    let mut create_mode = use_signal(|| false);
    let mut new_agent_slug = use_signal(String::new);
    let mut new_agent_avatar_blob_ref = use_signal(String::new);
    let provision_in_flight = use_signal(|| false);
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
    let controller = AgentAdminController {
        agents,
        list_status,
        last_op_status,
        refresh_epoch: agent_list_refresh_epoch,
        selected_agent_id,
        create_mode,
        new_agent_avatar_blob_ref,
        provision_in_flight,
        deactivate_dialog_open,
        deactivate_confirm,
        pairing_action_agent_id,
        pairing_action_phase,
        owned_agents_rev,
        state_store,
    };
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
            controller.refresh_agents(base.clone(), api_token);
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
            controller.load_agent_details(base.clone(), token(), id);
        });
    }

    let selected_id_now = selected_agent_id();
    let is_create_mode = create_mode();
    let last_op_status_message = last_op_status();
    let list_status_message = list_status();
    let AgentAdminView {
        visible_agents,
        has_any_agents,
        selected_title,
        selected_slug,
        selected_status,
        selected_runtime_state,
        selected_key_state_owned,
        deactivate_status,
        selected_has_pcr_binding,
        selected_pcr_bootstrap_target,
        selected_should_offer_security_refresh,
        selected_pairing_request_id,
        selected_pairing_code,
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
    } = build_agent_admin_view(
        &agents.read(),
        &selected_id_now,
        &active_agent_filter,
        &crate::clock::now_timestamp(),
    );
    // Separate clones for the replace-runtime "Pause first" affordance, which is
    // rendered after the lifecycle switch closure has already moved the
    // originals.
    let replace_pause_controller_principal_id = controller_principal_id.clone();
    let replace_pause_key_state = selected_key_state_owned.clone();
    let deactivate_controller_principal_id = controller_principal_id.clone();
    let deactivate_key_state = selected_key_state_owned.clone();
    let security_refresh_target = selected_pcr_bootstrap_target.clone();
    let active_pairing_action_id = pairing_action_agent_id();
    let any_pairing_action_in_flight = !active_pairing_action_id.is_empty();
    let selected_pairing_action_in_flight =
        !selected_id_now.is_empty() && active_pairing_action_id == selected_id_now;
    let selected_pairing_action_phase = pairing_action_phase();
    let agent_provision_in_flight = provision_in_flight();

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
                                        controller.refresh_agents(base.clone(), token());
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
                                        disabled: new_agent_slug().trim().is_empty() || agent_provision_in_flight,
                                        onclick: {
                                            let base = base_url.clone();
                                            let controller_principal_id = controller_principal_id.clone();
                                            move |_| {
                                                controller.provision_agent(
                                                    base.clone(),
                                                    token(),
                                                    ProvisionAgentRequest {
                                                        controller_principal_id: controller_principal_id
                                                            .clone(),
                                                        slug: new_agent_slug(),
                                                        content_presets: provision_presets.read().clone(),
                                                        service_scopes: provision_service_scopes
                                                            .read()
                                                            .clone(),
                                                    },
                                                );
                                            }
                                        },
                                        if agent_provision_in_flight { "Creating…" } else { "Create" }
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "agent-admin-create-cancel-button",
                                        disabled: agent_provision_in_flight,
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
                                                            controller.finish_pcr_recovery(
                                                                base.clone(),
                                                                token(),
                                                                agent_id,
                                                                realm_id,
                                                                pairing_expired,
                                                                slug.clone(),
                                                            );
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
                                                            controller.renew_pairing(
                                                                base.clone(),
                                                                token(),
                                                                renew_agent_id.clone(),
                                                                renew_slug.clone(),
                                                            );
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
                                                    controller.set_agent_enabled(
                                                        base.clone(),
                                                        token(),
                                                        selected_agent_id(),
                                                        controller_principal_id.clone(),
                                                        selected_key_state_owned.clone(),
                                                        enabled,
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
                                                    controller.refresh_security_state(
                                                        base.clone(),
                                                        token(),
                                                        agent_id,
                                                        realm_id,
                                                    );
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
                                                            controller.replace_runtime(
                                                                base.clone(),
                                                                token(),
                                                                replace_agent_id.clone(),
                                                            );
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
                                                            let controller_principal_id = replace_pause_controller_principal_id.clone();
                                                            let key_state = replace_pause_key_state.clone();
                                                            move |_| {
                                                                replace_runtime_confirm_open.set(false);
                                                                controller.set_agent_enabled(
                                                                    base.clone(),
                                                                    token(),
                                                                    selected_agent_id(),
                                                                    controller_principal_id.clone(),
                                                                    key_state.clone(),
                                                                    false,
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
                                                let controller_principal_id = deactivate_controller_principal_id.clone();
                                                let key_state = deactivate_key_state.clone();
                                                move |_| {
                                                    let id = selected_agent_id();
                                                    if id.is_empty() { return; }
                                                    controller.deactivate_agent(
                                                        base.clone(),
                                                        token(),
                                                        id,
                                                        controller_principal_id.clone(),
                                                        deactivate_status,
                                                        key_state.clone(),
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
