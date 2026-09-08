use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SidecarDeliveryDiagnostics {
    pub(super) submit: &'static str,
    pub(super) fanout: &'static str,
    pub(super) receipt: &'static str,
    pub(super) last_updated: String,
}

#[component]
pub(super) fn DiscussionRightPanelTabs(
    active: DiscussionSidePanel,
    sidecar_mode: bool,
    mut right_panel: Signal<Option<DiscussionSidePanel>>,
) -> Element {
    rsx! {
        div { class: "discussion-right-tabs",
            Button {
                variant: ButtonVariant::Secondary,
                r#type: "button",
                class: if active == DiscussionSidePanel::Users { "discussion-right-tab active" } else { "discussion-right-tab" },
                "data-testid": "discussion-right-tab-members",
                onclick: move |_| right_panel.set(Some(DiscussionSidePanel::Users)),
                {if sidecar_mode { "Access".to_owned() } else { crate::i18n::tr("chat.tabs.members") }}
            }
            Button {
                variant: ButtonVariant::Secondary,
                r#type: "button",
                class: if active == DiscussionSidePanel::Settings { "discussion-right-tab active" } else { "discussion-right-tab" },
                "data-testid": "discussion-right-tab-settings",
                onclick: move |_| right_panel.set(Some(DiscussionSidePanel::Settings)),
                {if sidecar_mode { "Connection details".to_owned() } else { crate::i18n::tr("chat.tabs.settings") }}
            }
        }
    }
}

#[component]
pub(super) fn DiscussionUsersPanel(
    sidecar_mode: bool,
    right_panel: Signal<Option<DiscussionSidePanel>>,
    sidecar_session: Option<crate::sidecar::HostedSidecarState>,
    account_primary_handle: String,
    sidecar_owned_agents: Vec<SpaceParticipant>,
    sidecar_security_label: Option<String>,
    presence_participants: Vec<SpaceParticipant>,
    state_store: SyncSignal<LocalStateStore>,
    participants: Vec<SpaceParticipant>,
    participants_for_messages: Vec<SpaceParticipant>,
    presence_labels: Signal<std::collections::BTreeMap<String, String>>,
    presence_states: Signal<std::collections::BTreeMap<String, String>>,
    presence_status_messages: Signal<std::collections::BTreeMap<String, String>>,
    public_agent_ids: std::collections::BTreeSet<String>,
) -> Element {
    rsx! {
        aside { class: "discussion-panel discussion-details-panel", "data-testid": "discussion-users-panel",
            div { class: "discussion-panel-head",
                div { class: "discussion-title-row",
                    h2 { {if sidecar_mode { "Access".to_owned() } else { crate::i18n::tr("chat.users_header") }} }
                }
            }
            DiscussionRightPanelTabs {
                active: DiscussionSidePanel::Users,
                sidecar_mode,
                right_panel,
            }
            if let Some(session) = sidecar_session.as_ref() {
                div { class: "discussion-detail-section sidecar-access-section", "data-testid": "sidecar-access-panel",
                    div { class: "discussion-subhead", span { "Sidecar members" } }
                    div { class: "sidecar-access-row",
                        div {
                            strong {
                                if account_primary_handle.trim().is_empty() {
                                    "You"
                                } else {
                                    "{account_primary_handle}"
                                }
                            }
                            span { class: "muted", "Controller" }
                        }
                        span { class: "badge success", "Active" }
                    }
                    for agent in &sidecar_owned_agents {
                        {
                            let agent_id = agent.principal_id.to_string();
                            let slug = agent.agent_metadata.as_ref()
                                .map(|metadata| metadata.agent_slug.trim().to_owned())
                                .filter(|slug| !slug.is_empty())
                                .unwrap_or_else(|| short_principal_label(&agent_id));
                            let selector = agent_selector_label(agent);
                            let addressed_now = session.addressed_agent_ids.iter()
                                .any(|candidate| candidate == &agent_id);
                            rsx! {
                                div { class: "sidecar-access-row", key: "{agent_id}", "data-testid": "sidecar-agent-row",
                                    div {
                                        strong { "{slug}" }
                                        if let Some(selector) = selector {
                                            span { class: "muted", "@{selector}" }
                                        }
                                        span { class: "muted mono", "{agent_id}" }
                                    }
                                    span { class: if addressed_now { "badge accent" } else { "badge" },
                                        if addressed_now { "Addressed now" } else { "Eligible agent" }
                                    }
                                }
                            }
                        }
                    }
                    div { class: "event info",
                        "Sidecar access is derived from your eligible Agents. The badge marks the Agent addressed by the current message."
                    }
                    div { class: "discussion-subhead", span { "Encryption" } }
                    div { class: "detail-row", span { "Profile" } strong { {sidecar_security_label.as_deref().unwrap_or("Opening")} } }
                    div { class: "detail-row", span { "Membership reconciliation" } strong {
                        if session.membership_ready() { "Complete" } else { "Pending" }
                    } }
                    div { class: "detail-row", span { "Pending members" } strong { "{session.pending_reconciliation_count()}" } }
                }
            }
            // G3.Y2 — presence list. One row per participant with
            // `data-presence-state` derived from soland's live profile presence surface.
            div { class: "discussion-detail-section",
                div { class: "discussion-subhead", span { "Presence" } }
                div {
                    class: "presence-list",
                    "data-testid": "presence-list",
                    for participant in &presence_participants {
                        {
                            let principal_id_attr = participant.roster_key();
                            let live_labels = presence_labels();
                            let display = display_label_for_actor(
                                &state_store.read(),
                                &participants,
                                &live_labels,
                                &principal_id_attr,
                            );
                            let state = presence_states
                                .read()
                                .get(&principal_id_attr)
                                .cloned()
                                .unwrap_or_else(|| {
                                    if participant.is_self {
                                        "online".to_owned()
                                    } else {
                                        "offline".to_owned()
                                    }
                                });
                            let state_for_class = state.clone();
                            let status_message = presence_status_messages
                                .read()
                                .get(&principal_id_attr)
                                .cloned();
                            rsx! {
                                div {
                                    class: "presence-row presence-row-{state_for_class}",
                                    "data-testid": "presence-row",
                                    "data-actor-id": "{principal_id_attr}",
                                    "data-presence-state": "{state}",
                                    span { class: "presence-dot presence-dot-{state}" }
                                    span { class: "presence-name", title: "{principal_id_attr}",
                                        "{display}"
                                        if participant.is_self {
                                            SelfAttributionBadge {
                                                class: Some("participant-inline-self-badge".to_owned()),
                                                test_id: Some("presence-self-badge".to_owned()),
                                            }
                                        }
                                    }
                                    span { class: "muted", " ({state})" }
                                    if let Some(status_message) = status_message {
                                        span {
                                            class: "muted presence-status-message",
                                            "data-testid": "presence-status-message",
                                            " — {status_message}"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            div { class: "discussion-detail-section",
                div { class: "discussion-subhead", span { "Space users" } }
                for row in participant_roster_rows(&participants, &public_agent_ids) {
                    {
                        match row {
                            ParticipantRosterRow::Participant(participant) => {
                                let display_label = participant_roster_display_label(
                                    &state_store.read(),
                                    &participant,
                                );
                                rsx! {
                                    DiscussionParticipantRow {
                                        participant,
                                        participants: participants_for_messages.clone(),
                                        display_label,
                                        nested_agent: false,
                                        show_binding_details: true,
                                    }
                                }
                            }
                            ParticipantRosterRow::ControllerWithAgents { controller, agents } => {
                                let controller_principal_id = controller.principal_id.clone();
                                let agent_count = agents.len();
                                let display_label = participant_roster_display_label(
                                    &state_store.read(),
                                    &controller,
                                );
                                let agent_count_label = if agent_count == 1 {
                                    "1 agent".to_owned()
                                } else {
                                    format!("{agent_count} agents")
                                };
                                let group_aria_label = format!(
                                    "Show {agent_count_label} for {display_label}"
                                );
                                rsx! {
                                    details {
                                        class: "participant-agent-group",
                                        "data-testid": "participant-agent-group",
                                        "data-controller-principal-id": "{controller_principal_id}",
                                        summary {
                                            class: "participant-agent-group-summary",
                                            "aria-label": "{group_aria_label}",
                                            DiscussionParticipantRow {
                                                participant: controller,
                                                participants: participants_for_messages.clone(),
                                                display_label,
                                                nested_agent: false,
                                                show_binding_details: false,
                                            }
                                            span {
                                                class: "participant-agent-group-toggle muted",
                                                "data-testid": "participant-agent-group-toggle",
                                                "{agent_count_label}"
                                            }
                                        }
                                        div { class: "participant-agent-children",
                                            for agent in agents {
                                                {
                                                    let display_label = participant_roster_display_label(
                                                        &state_store.read(),
                                                        &agent,
                                                    );
                                                    rsx! {
                                                        DiscussionParticipantRow {
                                                            participant: agent,
                                                            participants: participants_for_messages.clone(),
                                                            display_label,
                                                            nested_agent: true,
                                                            show_binding_details: true,
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
            }
        }
    }
}

#[component]
pub(super) fn DiscussionSettingsPanel(
    sidecar_mode: bool,
    right_panel: Signal<Option<DiscussionSidePanel>>,
    sidecar_session: Option<crate::sidecar::HostedSidecarState>,
    sidecar_delivery_diagnostics: Option<SidecarDeliveryDiagnostics>,
    sidecar_security_label: Option<String>,
    state_store: SyncSignal<LocalStateStore>,
    selected_realm_id: String,
    selected_channel_id: String,
    selected_channel_category: String,
    selected_channel_unread: usize,
    visible_message_count: usize,
    on_open_agent_settings: EventHandler<()>,
) -> Element {
    // F-CHAT-DEAD-UI-1: these values remain local-state projections. This
    // renderer has no hooks and preserves the original synchronous writes.
    let realm_id_for_mute = selected_realm_id;
    let strand_id_for_rr = selected_channel_id;
    let muted_realms_now = state_store.read().muted_realms();
    let realm_is_muted = muted_realms_now.contains(&realm_id_for_mute);
    let rr_default_send = state_store.read().read_receipt_default_send();
    let rr_strand_override = state_store
        .read()
        .read_receipt_strand_override(&strand_id_for_rr);
    let rr_active = rr_strand_override.unwrap_or(rr_default_send);
    let rr_default_display = state_store.read().read_receipt_default_display();
    let rr_strand_display_override = state_store
        .read()
        .read_receipt_strand_display_override(&strand_id_for_rr);
    let rr_display_active = rr_strand_display_override.unwrap_or(rr_default_display);

    rsx! {
        aside { class: "discussion-panel discussion-details-panel", "data-testid": "discussion-settings-panel",
            div { class: "discussion-panel-head",
                div { class: "discussion-title-row",
                    h2 { {if sidecar_mode { "Connection details".to_owned() } else { crate::i18n::tr("chat.settings_header") }} }
                }
            }
            DiscussionRightPanelTabs {
                active: DiscussionSidePanel::Settings,
                sidecar_mode,
                right_panel,
            }
            if let (Some(session), Some(diagnostics)) =
                (sidecar_session.as_ref(), sidecar_delivery_diagnostics.as_ref())
            {
                div { class: "discussion-detail-section sidecar-diagnostics-section", "data-testid": "sidecar-connection-details",
                    div { class: "detail-row", span { "Trace ID" } strong { class: "mono", "{session.trace_id}" } }
                    div { class: "detail-row", span { "Ensure" } strong { "Complete" } }
                    div { class: "detail-row", span { "Private access" } strong {
                        if session.membership_ready() { "Complete" } else { "Reconciling" }
                    } }
                    div { class: "detail-row", span { "Encryption" } strong { {sidecar_security_label.as_deref().unwrap_or("Opening")} } }
                    div { class: "detail-row", span { "Message submit" } strong { "{diagnostics.submit}" } }
                    div { class: "detail-row", span { "Notification fanout" } strong { "{diagnostics.fanout}" } }
                    div { class: "detail-row", span { "Agent receipt" } strong { "{diagnostics.receipt}" } }
                    div { class: "detail-row", span { "Last updated" } strong { "{diagnostics.last_updated}" } }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "sidecar-copy-diagnostics",
                            onclick: {
                                let summary = session.diagnostic_summary(
                                    sidecar_security_label.as_deref().unwrap_or("Opening"),
                                    diagnostics.submit,
                                    diagnostics.fanout,
                                    diagnostics.receipt,
                                    &diagnostics.last_updated,
                                );
                                move |_| yoface::utils::dom::copy_text_to_clipboard(&summary)
                            },
                            "Copy diagnostic summary"
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            onclick: move |_| on_open_agent_settings.call(()),
                            "Open agent settings"
                        }
                    }
                }
            }
            div { class: "discussion-detail-section",
                div { class: "discussion-subhead", span { "Settings" } }
                label { class: "settings-row",
                    span { {crate::i18n::tr("chat.settings.mute_notifications")} }
                    Checkbox {
                        "data-testid": "discussion-settings-mute",
                        checked: if realm_is_muted { CheckboxState::Checked } else { CheckboxState::Unchecked },
                        on_checked_change: {
                            let realm_id = realm_id_for_mute.clone();
                            move |state: CheckboxState| {
                                let new_muted = bool::from(state);
                                state_store
                                    .write()
                                    .set_realm_muted(realm_id.clone(), new_muted);
                            }
                        },
                    }
                }
                label { class: "settings-row",
                    span { {crate::i18n::tr("chat.settings.read_receipts")} }
                    Checkbox {
                        "data-testid": "discussion-settings-read-receipts",
                        checked: if rr_active { CheckboxState::Checked } else { CheckboxState::Unchecked },
                        on_checked_change: {
                            let strand_id = strand_id_for_rr.clone();
                            move |state: CheckboxState| {
                                let new_value = bool::from(state);
                                state_store
                                    .write()
                                    .set_read_receipt_strand_override(
                                        strand_id.clone(),
                                        Some(new_value),
                                    );
                            }
                        },
                    }
                }
                label { class: "settings-row",
                    span { "Show others' read receipts" }
                    Checkbox {
                        "data-testid": "discussion-settings-read-receipts-display",
                        checked: if rr_display_active { CheckboxState::Checked } else { CheckboxState::Unchecked },
                        on_checked_change: {
                            let strand_id = strand_id_for_rr.clone();
                            move |state: CheckboxState| {
                                let new_value = bool::from(state);
                                state_store
                                    .write()
                                    .set_read_receipt_strand_display_override(
                                        strand_id.clone(),
                                        Some(new_value),
                                    );
                            }
                        },
                    }
                }
                div { class: "settings-row settings-row-readonly",
                    "data-testid": "discussion-settings-shared-history-note",
                    span { {crate::i18n::tr("chat.settings.shared_history")} }
                    span { class: "muted",
                        {crate::i18n::tr("chat.settings.shared_history_hint")}
                    }
                }
            }
            div { class: "discussion-detail-section",
                div { class: "discussion-subhead", span { "Selected" } }
                div { class: "detail-row", span { "Category" } strong { "{selected_channel_category}" } }
                div { class: "detail-row", span { "Unread" } strong { "{selected_channel_unread}" } }
                div { class: "detail-row", span { "Messages" } strong { "{visible_message_count}" } }
            }
        }
    }
}
