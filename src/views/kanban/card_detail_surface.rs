use arkret_wire::event_kind_str;

use super::*;

#[derive(Clone, PartialEq)]
pub(super) struct CardDetailContext {
    pub base_url: String,
    pub plaintext_service_id: String,
    pub principal_id: arkret_sdk::DidCoreId,
    pub account_primary_handle: String,
    pub device_id: arkret_sdk::DeviceId,
    pub selected_realm_id: String,
    pub projection_realm_id: String,
    pub token: Signal<String>,
    pub sync_cursor: Signal<String>,
    pub frontier_state: Signal<String>,
    pub realm_live_epoch: Signal<u64>,
    pub synthesis_entries: Memo<Vec<CardSynthesisTrackEntry>>,
    pub selected_scope_security_encrypted: Option<bool>,
    pub selected_scope_security_encrypted_or_secure: bool,
    pub realm_content_write_ready: bool,
    pub projected_strand_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SidecarTrackEditContext {
    source_strand_id: String,
}

fn canonicalized_edit_target(
    previous: &str,
    next: &str,
    aliases: &BTreeMap<String, String>,
) -> bool {
    !previous.is_empty()
        && previous != next
        && resolve_event_derived_target_alias(aliases, previous) == next
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SuspendedTrackEdit {
    pub(super) scope: CardEditScope,
    pub(super) synthesis: String,
    pub(super) synthesis_target_id: Option<String>,
}

/// Only the Synthesis scope edits track content, so it is the only draft a
/// Sidecar transition has to suspend. Summary / Calendar edits target
/// `metadata.*` and are unaffected.
pub(super) fn suspend_track_edit(
    scope: CardEditScope,
    synthesis: String,
    synthesis_target_id: Option<String>,
) -> Option<SuspendedTrackEdit> {
    (scope == CardEditScope::Synthesis).then_some(SuspendedTrackEdit {
        scope,
        synthesis,
        synthesis_target_id,
    })
}

/// Keep a content-editing session attached to the visible content tab. Drafts
/// live in separate signals, so moving between Description and Synthesis can
/// reveal the matching editor without discarding either draft. Summary and
/// Calendar forms are independent of the content tabs and remain untouched.
pub(super) fn content_edit_scope_for_tab(
    editing: bool,
    current_scope: CardEditScope,
    tab: CardDetailContentTab,
) -> Option<CardEditScope> {
    if !editing
        || !matches!(
            current_scope,
            CardEditScope::Description | CardEditScope::Synthesis
        )
    {
        return None;
    }

    match tab {
        CardDetailContentTab::Description => Some(CardEditScope::Description),
        CardDetailContentTab::Synthesis => Some(CardEditScope::Synthesis),
        CardDetailContentTab::Discussion => None,
    }
}

fn card_owned_agent_rows(
    members: &[RealmMemberRow],
    inventory: &BTreeMap<String, String>,
    station: &arkret_sdk::DidCoreId,
) -> Vec<(String, String, bool)> {
    let mut agents = inventory
        .iter()
        .filter_map(|(principal, slug)| {
            let principal = arkret_sdk::DidCoreId::new(principal.clone()).ok()?;
            let joined_actor = members.iter().find(|row| {
                row.membership == Some(arkret_sdk::sync::MemberRosterMembership::Join)
                    && row.actor_id.as_account_id().is_some_and(|account| {
                        account.principal_id == principal && account.station_id == *station
                    })
            });
            // Inventory proves ownership, not a Realm membership or AccountId.
            let identity = joined_actor
                .map(|row| row.actor_id.to_string())
                .unwrap_or_else(|| principal.to_string());
            Some((identity, slug.clone(), joined_actor.is_some()))
        })
        .collect::<Vec<_>>();
    agents.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    agents
}

#[component]
fn CardMemberMentionRow(
    member_id: String,
    label: String,
    #[props(default)] is_self: bool,
    agent_slug: Option<String>,
    #[props(default)] in_strand: bool,
    #[props(default = true)] in_realm: bool,
    onmention: EventHandler<crate::views::chat::MentionInsertRequest>,
) -> Element {
    let dot_class = if in_strand {
        "card-detail-actor-dot participant"
    } else {
        "card-detail-actor-dot"
    };
    let dot_title = if in_strand {
        "Participated in this Strand"
    } else if in_realm {
        "Realm member"
    } else {
        "Not in this Realm"
    };
    let mention_target = serde_json::from_str::<arkret_sdk::ActorId>(&member_id)
        .ok()
        .and_then(|actor| actor.as_account_id().cloned());
    let mentionable = in_realm && mention_target.is_some();
    let require_agent_identity = agent_slug.is_some();
    let agent_id = agent_slug.as_ref().and_then(|_| {
        mention_target
            .as_ref()
            .map(|account| account.principal_id.to_string())
            .or_else(|| {
                arkret_sdk::DidCoreId::new(member_id.clone())
                    .ok()
                    .map(|id| id.to_string())
            })
    });
    let row_class = format!(
        "card-detail-actor-row{}{}",
        if agent_slug.is_some() {
            " participant-agent-row"
        } else {
            ""
        },
        if in_strand { " participant" } else { "" },
    );
    let test_id = if agent_slug.is_some() {
        Some("card-detail-agent-row")
    } else {
        None
    };

    rsx! {
        div {
            class: "{row_class}",
            "data-testid": test_id,
            "data-member-id": "{member_id}",
            "data-agent-slug": agent_slug.as_deref(),
            "data-agent-id": agent_id,
            "data-strand-participant": "{in_strand}",
            button {
                r#type: "button",
                class: "card-detail-actor-mention-button",
                "data-testid": "card-detail-member-mention-button",
                "aria-label": "Mention {label}",
                disabled: !mentionable,
                onclick: {
                    let mention_target = mention_target.clone();
                    move |_| {
                        if let Some(account) = mention_target.as_ref() {
                            onmention.call(crate::views::chat::MentionInsertRequest::new(
                                account.clone(),
                                require_agent_identity,
                            ));
                        }
                    }
                },
                span { class: "{dot_class}", title: "{dot_title}", "aria-label": "{dot_title}" }
                ActorIdentityLabel {
                    label: label.clone(),
                    title: Some(member_id.clone()),
                    class: Some("card-detail-actor-id".to_owned()),
                    test_id: Some("card-detail-member".to_owned()),
                    self_badge_test_id: None,
                    agent_badge_test_id: None,
                    is_self,
                    agent_slug: agent_slug.clone(),
                }
            }
            if !in_realm {
                span { class: "card-detail-agent-membership", "Not in this Realm" }
            }
        }
    }
}

#[component]
pub(super) fn CardDetail(controller: KanbanController, context: CardDetailContext) -> Element {
    let CardDetailContext {
        base_url,
        plaintext_service_id,
        principal_id,
        account_primary_handle,
        device_id,
        selected_realm_id,
        projection_realm_id,
        token,
        sync_cursor,
        frontier_state,
        realm_live_epoch,
        synthesis_entries: synthesis_entries_memo,
        selected_scope_security_encrypted,
        selected_scope_security_encrypted_or_secure,
        realm_content_write_ready,
        projected_strand_ids,
    } = context;
    // Keep validation at the component boundary; local view helpers consume
    // only the canonical textual representation.
    let principal_core_id = principal_id.clone();
    let principal_id = principal_id.as_str().to_owned();
    let account_device_id = device_id.clone();
    let device_id = device_id.to_string();
    let state_store = crate::app::SessionContext::get().state_store;
    let hosted_sidecar_state = use_context::<crate::sidecar::HostedSidecarStateContext>().0;
    let navigator = use_navigator();
    let route = use_route::<Route>();
    let mut member_mention_request =
        use_signal(|| Option::<crate::views::chat::MentionInsertRequest>::None);
    let owned_agent_inventory = use_resource({
        let base = base_url.clone();
        move || {
            let base = base.clone();
            let api_token = token();
            async move {
                if api_token.trim().is_empty() {
                    return Err("authenticated Agent inventory is unavailable".to_owned());
                }
                with_authed_sdk_client(&base, api_token, |http| async move {
                    let list = http.agent_list().await?;
                    Ok::<_, anyhow::Error>(crate::views::agents::mentionable_owned_agent_slugs(
                        list.agents,
                    ))
                })
                .await
                .map_err(|error| error.display())
            }
        }
    });
    let KanbanController {
        board_space_options: _,
        selected_board,
        lifecycle_container_projection: _,
        lifecycle_strand_projection: _,
        new_board_title: _,
        new_column_title: _,
        new_card_title: _,
        adding_card_to: _,
        mut selected_card,
        mls_sidecar_restore_key_seen: _,
        board_popover: _,
        archive_board_confirm_open: _,
        list_archive_confirm: _,
        mut editing_card_detail,
        mut card_edit_scope,
        mut card_detail_sidebar_visible,
        mut card_detail_actions_open,
        mut card_detail_tab,
        mut card_detail_discussion_mounted_for,
        mut card_detail_sidebar_tab,
        mut card_detail_docked,
        mut card_detail_dock_width,
        mut card_detail_resizing,
        mut card_detail_resize_start_x,
        mut card_detail_resize_start_width,
        member_handle_fetching: _,
        mut card_edit_title,
        mut card_edit_description,
        mut card_edit_body,
        mut card_edit_synthesis,
        mut card_edit_synthesis_target_id,
        mut card_detail_edit_status,
        mut assignee_picker_open,
        mut assignee_filter,
        mut assignee_selected_actor_ids,
        mut assignee_edit_status,
        mut due_picker_open,
        mut due_edit_value,
        mut due_calendar_month,
        mut due_edit_status,
        mut card_edit_calendar,
        mut calendar_rsvp_occurrence,
        mut card_synthesis_history_open_id,
        mut card_synthesis_selected_revision_id,
        mut card_edit_labels,
        mut card_edit_assignee,
        mut card_edit_due,
        dragging_card: _,
        dragging_column: _,
        drop_target_column: _,
        editing_column_id: _,
        editing_column_title: _,
        mut board_status,
        command_queue: _,
    } = controller;
    let detail_send_scope = selected_card().and_then(|card| {
        let realm_id = arkret_sdk::RealmId::new(selected_realm_id.clone()).ok()?;
        let sidecar = hosted_sidecar_state().filter(|session| {
            session.source_realm_id == selected_realm_id
                && session.source_strand_id == card.primary_strand_id
        });
        match sidecar {
            Some(session) => session.mls_scope_sidecar_id().ok().map(|sidecar_id| {
                arkret_sdk::ScopeRef::Sidecar {
                    realm_id,
                    sidecar_id,
                }
            }),
            None => Some(arkret_sdk::ScopeRef::Realm { realm_id }),
        }
    });
    let detail_send_ready = crate::views::secure_send::use_scope_send_ready(
        state_store,
        detail_send_scope,
        account_device_id,
    );
    let mut sidecar_edit_context_seen = use_signal(SidecarTrackEditContext::default);
    let mut suspended_shared_track_edits = use_signal(BTreeMap::<String, SuspendedTrackEdit>::new);
    let mut card_detail_backdrop_pressed = use_signal(|| false);
    use_effect(move || {
        let selected_strand = selected_card()
            .map(|card| card.primary_strand_id)
            .unwrap_or_default();
        let next = SidecarTrackEditContext {
            source_strand_id: selected_strand,
        };
        let previous = sidecar_edit_context_seen.peek().clone();
        if previous == next {
            return;
        }
        // A pending card receiving its Event-derived Strand ID is the same
        // editing target. Keep all drafts and the active editor across that
        // identity reconciliation; only a different card suspends the edit.
        let aliases = event_derived_target_aliases(&state_store.read().load().raw_operations);
        if canonicalized_edit_target(&previous.source_strand_id, &next.source_strand_id, &aliases) {
            sidecar_edit_context_seen.set(next);
            return;
        }
        if editing_card_detail() {
            if let Some(edit) = suspend_track_edit(
                card_edit_scope(),
                card_edit_synthesis(),
                card_edit_synthesis_target_id(),
            ) && !previous.source_strand_id.is_empty()
            {
                suspended_shared_track_edits
                    .write()
                    .insert(previous.source_strand_id, edit);
            }
            editing_card_detail.set(false);
            card_detail_actions_open.set(false);
            card_detail_edit_status.set(String::new());
            card_edit_synthesis_target_id.set(None);
        }
        let suspended = suspended_shared_track_edits
            .write()
            .remove(&next.source_strand_id);
        sidecar_edit_context_seen.set(next);
        if let Some(edit) = suspended {
            card_edit_scope.set(edit.scope);
            card_edit_synthesis.set(edit.synthesis);
            card_edit_synthesis_target_id.set(edit.synthesis_target_id);
            editing_card_detail.set(true);
        }
    });

    rsx! {
            if let Some(ref card) = selected_card() {
                {
                    let card_id_label = short_protocol_id(&card.id);
                    let active_sidecar_session = hosted_sidecar_state().filter(|session| {
                        session.source_realm_id == selected_realm_id
                            && session.source_strand_id == card.primary_strand_id
                    });
                    let sidecar_track_write = active_sidecar_session.as_ref().map(|session| {
                        SidecarTrackWriteContext {
                            sidecar_id: session.mls_scope_sidecar_id().ok(),
                            ready: session.membership_ready(),
                        }
                    });
                    let private_track_card: Option<KanbanCard> = None;
                    let track_card = private_track_card.as_ref().unwrap_or(card);
                    let sidecar_track_active = active_sidecar_session.is_some();
                    let show_shared_track_base = active_sidecar_session.as_ref().is_some_and(|session| {
                        session.display_mode == arkret_sdk::AgentSidecarDisplayMode::ContextMerged
                    });
                    let board_route_after_close =
                        kanban_card_detail_board_route(&selected_realm_id, selected_board().as_ref());
                    let route_is_card_detail = matches!(
                        route,
                        Route::KanbanTask { .. } | Route::KanbanBoardTask { .. }
                    );
                    let sidebar_is_visible = card_detail_sidebar_visible();
                    let sidebar_toggle_label = if sidebar_is_visible {
                        "Hide details"
                    } else {
                        "Show details"
                    };
                    let sidebar_toggle_icon = if sidebar_is_visible {
                        "panel-right-close"
                    } else {
                        "panel-right-open"
                    };
                    let detail_layout_class = if sidebar_is_visible {
                        "card-detail-layout"
                    } else {
                        "card-detail-layout no-sidebar"
                    };
                    let is_docked = card_detail_docked();
                    let dock_width = card_detail_dock_width();
                    let dock_toggle_label = if is_docked {
                        "Expand to dialog"
                    } else {
                        "Dock to side"
                    };
                    let dock_toggle_icon = if is_docked { "maximize" } else { "minimize" };
                    let overlay_class = if is_docked {
                        "card-detail-overlay is-docked"
                    } else {
                        "card-detail-overlay"
                    };
                    let popup_class = if is_docked {
                        "card-detail-popup is-docked"
                    } else {
                        "card-detail-popup"
                    };
                    let popup_style = if is_docked {
                        format!("width: {dock_width}px;")
                    } else {
                        String::new()
                    };
                    let active_detail_tab = card_detail_tab();
                    let card_link_path = strand_detail_deep_link_path_with_tab(
                        &selected_realm_id,
                        &card.id,
                        active_detail_tab,
                    );
                    let description_tab_class = if active_detail_tab == CardDetailContentTab::Description {
                        "card-detail-tab active"
                    } else {
                        "card-detail-tab"
                    };
                    let synthesis_tab_class = if active_detail_tab == CardDetailContentTab::Synthesis {
                        "card-detail-tab active"
                    } else {
                        "card-detail-tab"
                    };
                    let discussion_tab_class = if active_detail_tab == CardDetailContentTab::Discussion {
                        "card-detail-tab active"
                    } else {
                        "card-detail-tab"
                    };
                    let discussion_panel_class = if active_detail_tab == CardDetailContentTab::Discussion {
                        "card-detail-discussion-panel"
                    } else {
                        "card-detail-discussion-panel is-hidden"
                    };
                    let discussion_panel_should_mount = active_detail_tab
                        == CardDetailContentTab::Discussion
                        || card_detail_discussion_mounted_for()
                            .as_deref()
                            .is_some_and(|strand_id| strand_id == card.primary_strand_id.as_str());
                    let discussion_target_ready = card_discussion_target_ready(card);
                    let action_menu_class = if editing_card_detail() {
                        "card-detail-action-menu is-editing"
                    } else {
                        "card-detail-action-menu"
                    };
                    let summary_text = card_summary_text(&card.description);
                    // Decrypt + replay is memoized at the component top level
                    // (`synthesis_entries_memo`) so it runs only when its inputs
                    // change, not on every re-render. Read the cached track here.
                    let synthesis_entries = synthesis_entries_memo();
                    let overlay_navigator = navigator;
                    let overlay_board_route = board_route_after_close.clone();
                    let close_navigator = navigator;
                    let close_board_route = board_route_after_close.clone();
                    rsx! {
                        if card_detail_resizing() {
                            div {
                                class: "card-detail-resize-capture",
                                "data-testid": "card-detail-resize-capture",
                                onmousemove: move |event: dioxus::events::MouseEvent| {
                                    let current_x = event.client_coordinates().x;
                                    let delta = card_detail_resize_start_x() - current_x;
                                    let next = (card_detail_resize_start_width() + delta)
                                        .clamp(CARD_DETAIL_DOCK_WIDTH_MIN, CARD_DETAIL_DOCK_WIDTH_MAX);
                                    card_detail_dock_width.set(next);
                                },
                                onmouseup: move |event: dioxus::events::MouseEvent| {
                                    event.stop_propagation();
                                    card_detail_resizing.set(false);
                                    persist_card_detail_dock_width(card_detail_dock_width());
                                },
                                onmouseleave: move |_| {
                                    card_detail_resizing.set(false);
                                    persist_card_detail_dock_width(card_detail_dock_width());
                                },
                            }
                        }
                        div {
                            class: "{overlay_class}",
                            "data-testid": "card-detail-overlay",
                            role: "presentation",
                            onmousedown: move |_| card_detail_backdrop_pressed.set(true),
                            onclick: move |_| {
                                if !card_detail_backdrop_pressed() {
                                    return;
                                }
                                card_detail_backdrop_pressed.set(false);
                                selected_card.set(None);
                                editing_card_detail.set(false);
                                card_detail_edit_status.set(String::new());
                                assignee_picker_open.set(false);
                                assignee_filter.set(String::new());
                                assignee_selected_actor_ids.set(BTreeSet::new());
                                assignee_edit_status.set(String::new());
                                due_picker_open.set(false);
                                due_edit_value.set(String::new());
                                due_calendar_month.set(default_due_calendar_month());
                                due_edit_status.set(String::new());
                                card_edit_calendar.set(CalendarCardFields::default());
                                calendar_rsvp_occurrence.set(String::new());
                                card_detail_actions_open.set(false);
                                if route_is_card_detail {
                                    let _ = overlay_navigator.push(overlay_board_route.clone());
                                }
                            },
                            div {
                                class: "{popup_class}",
                                style: "{popup_style}",
                                "data-testid": "card-detail-modal",
                                role: "dialog",
                                "aria-modal": "true",
                                onmousedown: move |event: dioxus::events::MouseEvent| {
                                    event.stop_propagation();
                                    card_detail_backdrop_pressed.set(false);
                                },
                                onmouseup: move |event: dioxus::events::MouseEvent| {
                                    event.stop_propagation();
                                    card_detail_backdrop_pressed.set(false);
                                },
                                onclick: move |event: dioxus::events::MouseEvent| event.stop_propagation(),
                                if is_docked {
                                    div {
                                        class: "card-detail-resize-handle",
                                        "data-testid": "card-detail-resize-handle",
                                        "aria-hidden": "true",
                                        onmousedown: move |event: dioxus::events::MouseEvent| {
                                            event.stop_propagation();
                                            card_detail_resize_start_x.set(event.client_coordinates().x);
                                            card_detail_resize_start_width.set(card_detail_dock_width());
                                            card_detail_resizing.set(true);
                                        },
                                    }
                                }
                                div { class: "card-detail-header",
                                    div { class: "card-detail-title-block",
                                        div { class: "card-detail-title-row",
                                            SecurityStateBadge {
                                                encrypted: card.security_encrypted.unwrap_or(selected_scope_security_encrypted_or_secure),
                                                compact: true,
                                                test_id: Some("strand-detail-security-state".to_owned()),
                                            }
                                            h2 { "{card.title}" }
                                            div { class: "card-detail-title-meta",
                                                WriteStateBadge { state: displayed_card_state(card, &projected_strand_ids) }
                                                for label in &card.labels {
                                                    span { key: "{label}", class: "badge", "{label}" }
                                                }
                                            }
                                        }
                                    }
                                    div { class: "card-detail-header-actions",
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            class: "card-detail-header-button",
                                            "data-testid": "card-detail-share-link-button",
                                            "aria-label": "Copy strand link",
                                            title: "Copy strand link",
                                            onclick: {
                                                let link_path = card_link_path.clone();
                                                move |_| {
                                                    share_kanban_strand_link(&link_path);
                                                    board_status.set("Strand link copied".to_owned());
                                                    card_detail_actions_open.set(false);
                                                }
                                            },
                                            UiIcon { name: "share" }
                                        }
                                        if !editing_card_detail() {
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                class: "card-detail-header-button",
                                                "data-testid": "card-detail-sidebar-toggle",
                                                "aria-label": "{sidebar_toggle_label}",
                                                "aria-pressed": "{sidebar_is_visible}",
                                                title: "{sidebar_toggle_label}",
                                                onclick: move |_| {
                                                    card_detail_sidebar_visible.set(!card_detail_sidebar_visible());
                                                    card_detail_actions_open.set(false);
                                                },
                                                UiIcon { name: sidebar_toggle_icon }
                                            }
                                        }
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            class: "card-detail-header-button",
                                            "data-testid": "card-detail-dock-toggle",
                                            "aria-label": "{dock_toggle_label}",
                                            "aria-pressed": "{is_docked}",
                                            title: "{dock_toggle_label}",
                                            onclick: move |_| {
                                                let next = !card_detail_docked();
                                                card_detail_docked.set(next);
                                                persist_card_detail_docked(next);
                                                card_detail_actions_open.set(false);
                                            },
                                            UiIcon { name: dock_toggle_icon }
                                        }
                                        div { class: "card-detail-action-menu-wrap",
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                class: "card-detail-header-button",
                                                "data-testid": "card-detail-actions-button",
                                                "aria-label": "Actions",
                                                "aria-expanded": "{card_detail_actions_open()}",
                                                title: "Actions",
                                                onclick: move |_| card_detail_actions_open.set(!card_detail_actions_open()),
                                                UiIcon { name: "more-horizontal" }
                                            }
                                            if card_detail_actions_open() {
                                                div { class: "{action_menu_class}", "data-testid": "card-detail-actions-menu",
                                                    if editing_card_detail() && card_edit_scope() == CardEditScope::Summary {
                                                        div { class: "card-detail-action-menu-field",
                                                            Label { html_for: "card-detail-labels-input-input", "Labels" }
                                                            Input {
                                                                id: "card-detail-labels-input-input",
                                                                class: "input",
                                                                "data-testid": "card-detail-labels-input",
                                                                value: "{card_edit_labels}",
                                                                placeholder: "release, ops",
                                                                oninput: move |event: FormEvent| card_edit_labels.set(event.value()),
                                                            }
                                                        }
                                                        div { class: "card-detail-action-menu-field",
                                                            Label { html_for: "card-detail-due-input-input", "Due date" }
                                                            Input {
                                                                id: "card-detail-due-input-input",
                                                                class: "input",
                                                                "data-testid": "card-detail-due-input",
                                                                value: "{card_edit_due}",
                                                                placeholder: "2026-05-20",
                                                                oninput: move |event: FormEvent| card_edit_due.set(event.value()),
                                                            }
                                                        }
                                                    } else if !sidecar_track_active {
                                                        Button {
                                                            variant: ButtonVariant::Secondary,
                                                            class: "card-detail-action-menu-item",
                                                            "data-testid": "card-detail-menu-edit-button",
                                                            disabled: !card_detail_edit_ready(card),
                                                            onclick: {
                                                                let current = card.clone();
                                                                move |_| {
                                                                    prepare_selected_card_for_edit(selected_card);
                                                                    let draft = card_detail_draft_from_card(&current);
                                                                    card_edit_title.set(draft.title);
                                                                    card_edit_description.set(draft.description);
                                                                    card_edit_body.set(draft.description_body);
                                                                    card_edit_synthesis.set(draft.synthesis);
                                                                    card_edit_synthesis_target_id.set(None);
                                                                    card_edit_labels.set(draft.labels.join(", "));
                                                                    card_edit_assignee.set(draft.assignee);
                                                                    card_edit_due.set(draft.due);
                                                                    card_edit_scope.set(CardEditScope::Summary);
                                                                    card_detail_edit_status.set(String::new());
                                                                    editing_card_detail.set(true);
                                                                    card_detail_actions_open.set(false);
                                                                }
                                                            },
                                                            UiIcon { name: "settings" }
                                                            span { {crate::i18n::tr("common.edit")} }
                                                        }
                                                        if matches!(
                                                            card.lifecycle,
                                                            StrandLifecycleState::Active
                                                                | StrandLifecycleState::Archived
                                                        ) {
                                                            {
                                                            let target = if card.lifecycle == StrandLifecycleState::Archived {
                                                                StrandLifecycleState::Active
                                                            } else {
                                                                StrandLifecycleState::Archived
                                                            };
                                                            let action = if target == StrandLifecycleState::Archived {
                                                                event_kind_str::STRAND_ARCHIVE
                                                            } else {
                                                                event_kind_str::STRAND_RESTORE
                                                            };
                                                            let label = if target == StrandLifecycleState::Archived {
                                                                crate::i18n::tr("kanban.archive_action")
                                                            } else {
                                                                crate::i18n::tr("kanban.restore_action")
                                                            };
                                                            let testid = if target == StrandLifecycleState::Archived {
                                                                "card-detail-archive-button"
                                                            } else {
                                                                "card-detail-restore-button"
                                                            };
                                                            let title_text = format!("{label} this card ({action})");
                                                            let action_navigator = navigator;
                                                            let action_board_route = board_route_after_close.clone();
                                                            rsx! {
                                                                Button {
                                                                    variant: ButtonVariant::Secondary,
                                                                    class: "card-detail-action-menu-item",
                                                                    "data-testid": testid,
                                                                    "data-strand-id": "{card.id}",
                                                                    "data-cap-gate": "open",
                                                                    title: title_text,
                                                                    onclick: {
                                                                        let base = base_url.clone();
                                                                        let realm = selected_realm_id.clone();
                                                                        let actor = principal_id.clone();
                                                                        let strand_id = card.id.clone();
                                                                        move |_| {
                                                                            dispatch_strand_lifecycle(
                                                                                base.clone(),
                                                                                token,
                                                                                realm.clone(),
                                                                                actor.clone(),
                                                                                strand_id.clone(),
                                                                                target,
                                                                                state_store,
                                                                                board_status,
                                                                            );
                                                                            selected_card.set(None);
                                                                            editing_card_detail.set(false);
                                                                            card_detail_edit_status.set(String::new());
                                                                            card_edit_calendar.set(CalendarCardFields::default());
                                                                            calendar_rsvp_occurrence.set(String::new());
                                                                            card_detail_actions_open.set(false);
                                                                            if route_is_card_detail {
                                                                                let _ = action_navigator.push(action_board_route.clone());
                                                                            }
                                                                        }
                                                                    },
                                                                    UiIcon { name: if target == StrandLifecycleState::Archived { "archive" } else { "refresh" } }
                                                                    span { "{label}" }
                                                                }
                                                            }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            class: "card-detail-header-button card-detail-close",
                                            "data-testid": "card-detail-close-button",
                                            "aria-label": "Close card detail",
                                            title: "Close",
                                            onclick: move |_| {
                                                selected_card.set(None);
                                                editing_card_detail.set(false);
                                                card_detail_edit_status.set(String::new());
                                                assignee_picker_open.set(false);
                                                assignee_filter.set(String::new());
                                                assignee_selected_actor_ids.set(BTreeSet::new());
                                                assignee_edit_status.set(String::new());
                                                due_picker_open.set(false);
                                                due_edit_value.set(String::new());
                                                due_calendar_month.set(default_due_calendar_month());
                                                due_edit_status.set(String::new());
                                                card_edit_calendar.set(CalendarCardFields::default());
                                                calendar_rsvp_occurrence.set(String::new());
                                                card_detail_actions_open.set(false);
                                                if route_is_card_detail {
                                                    let _ = close_navigator.push(close_board_route.clone());
                                                }
                                            },
                                            UiIcon { name: "x" }
                                        }
                                    }
                                }

                                div { class: "{detail_layout_class}",
                                        main { class: "card-detail-main",
                                            section { class: "card-detail-section",
                                                div { class: "card-detail-section-head",
                                                    div { class: "card-detail-section-title",
                                                        UiIcon { name: "file" }
                                                        span { "Summary" }
                                                    }
                                                    if !editing_card_detail() && !sidecar_track_active {
                                                        Button {
                                                            variant: ButtonVariant::Secondary,
                                                            class: "card-detail-mini-action card-detail-edit-action",
                                                            "data-testid": "card-detail-edit-button",
                                                            disabled: !card_detail_edit_ready(card),
                                                            onclick: {
                                                                let current = card.clone();
                                                                move |_| {
                                                                    prepare_selected_card_for_edit(selected_card);
                                                                    let draft = card_detail_draft_from_card(&current);
                                                                    card_edit_title.set(draft.title);
                                                                    card_edit_description.set(draft.description);
                                                                    card_edit_body.set(draft.description_body);
                                                                    card_edit_synthesis.set(draft.synthesis);
                                                                    card_edit_synthesis_target_id.set(None);
                                                                    card_edit_labels.set(draft.labels.join(", "));
                                                                    card_edit_assignee.set(draft.assignee);
                                                                    card_edit_due.set(draft.due);
                                                                    card_edit_scope.set(CardEditScope::Summary);
                                                                    card_detail_edit_status.set(String::new());
                                                                    editing_card_detail.set(true);
                                                                }
                                                            },
                                                            UiIcon { name: "settings" }
                                                            span { {crate::i18n::tr("common.edit")} }
                                                        }
                                                    }
                                                }
                                                if editing_card_detail() && card_edit_scope() == CardEditScope::Summary {
                                                    div { class: "workflow-form card-detail-edit-form", "data-testid": "card-detail-edit-form",
                                                        div { class: "field",
                                                            Label { html_for: "card-detail-title-input-input", "Title" }
                                                            Input {
                                                                id: "card-detail-title-input-input",
                                                                class: "input",
                                                                "data-testid": "card-detail-title-input",
                                                                value: "{card_edit_title}",
                                                                maxlength: "512",
                                                                oninput: move |event: FormEvent| card_edit_title.set(event.value()),
                                                            }
                                                        }
                                                        div { class: "field",
                                                            Label { html_for: "card-detail-summary-input", "Summary" }
                                                            CardMarkdownEditor {
                                                                key: "card-markdown-summary",
                                                                value: card_edit_description(),
                                                                token: token(),
                                                                realm_id: selected_realm_id.clone(),
                                                                allow_image_upload: !sidecar_track_active,
                                                                on_change: move |value| card_edit_description.set(value),
                                                                slot: "summary".to_owned(),
                                                            }
                                                        }
                                                        CardDetailEditActions {
                                                            save_disabled: !detail_send_ready || !card_detail_write_ready(card) || !realm_content_write_ready,
                                                            status: card_detail_edit_status(),
                                                            on_save: {
                                                                let base = base_url.clone();
                                                                let realm = selected_realm_id.clone();
                                                                let actor = principal_id.clone();
                                                                let device = device_id.clone();
                                                                let current = card.clone();
                                                                let entries = synthesis_entries.clone();
                                                                let sidecar_write = sidecar_track_write.clone();
                                                                move |_| {
                                                                    spawn(save_card_detail_edit(
                                                                        base.clone(),
                                                                        token,
                                                                        realm.clone(),
                                                                        actor.clone(),
                                                                        device.clone(),
                                                                        current.clone(),
                                                                        entries.clone(),
                                                                        selected_scope_security_encrypted,
                                                                        sidecar_write.clone(),
                                                                        card_edit_scope,
                                                                        card_edit_title,
                                                                        card_edit_description,
                                                                        card_edit_body,
                                                                        card_edit_synthesis,
                                                                        card_edit_synthesis_target_id,
                                                                        card_edit_labels,
                                                                        card_edit_assignee,
                                                                        card_edit_due,
                                                                        editing_card_detail,
                                                                        card_detail_actions_open,
                                                                        card_detail_edit_status,
                                                                        selected_card,
                                                                        state_store,
                                                                        board_status,
                                                                    ));
                                                                }
                                                            },
                                                            on_cancel: {
                                                                let current = card.clone();
                                                                move |_| {
                                                                    reset_card_detail_edit(
                                                                        &current,
                                                                        card_edit_title,
                                                                        card_edit_description,
                                                                        card_edit_body,
                                                                        card_edit_synthesis,
                                                                        card_edit_synthesis_target_id,
                                                                        card_edit_labels,
                                                                        card_edit_assignee,
                                                                        card_edit_due,
                                                                        editing_card_detail,
                                                                        card_detail_actions_open,
                                                                        card_synthesis_history_open_id,
                                                                        card_synthesis_selected_revision_id,
                                                                        card_detail_edit_status,
                                                                    );
                                                                }
                                                            },
                                                        }
                                                    }
                                                } else if summary_text.is_empty() {
                                                    div { class: "card-detail-empty", "No summary" }
                                                } else {
                                                    div {
                                                        class: "card-detail-summary",
                                                        "data-testid": "card-summary",
                                                        "{summary_text}"
                                                    }
                                                }
                                            }

                                            crate::sidecar::HostedSidecarContextBar {
                                                base_url: base_url.clone(),
                                                api_token: token(),
                                                device_id: device_id.clone(),
                                            }

                                            section { class: "card-detail-section card-detail-tabs-section",
                                                div {
                                                    class: "card-detail-tabs",
                                                    "data-testid": "card-detail-tabs",
                                                    role: "tablist",
                                                    "aria-label": "Strand content sections",
                                                    button {
                                                        r#type: "button",
                                                        class: "{description_tab_class}",
                                                        "data-testid": "card-detail-tab-description",
                                                        role: "tab",
                                                        "aria-selected": "{active_detail_tab == CardDetailContentTab::Description}",
                                                        onclick: {
                                                            let realm_id = selected_realm_id.clone();
                                                            let strand_id = card.primary_strand_id.clone();
                                                            move |_| {
                                                                crate::views::chat::capture_chat_feed_scroll_position(
                                                                    &realm_id,
                                                                    &strand_id,
                                                                );
                                                                if let Some(scope) = content_edit_scope_for_tab(
                                                                    editing_card_detail(),
                                                                    card_edit_scope(),
                                                                    CardDetailContentTab::Description,
                                                                ) {
                                                                    card_edit_scope.set(scope);
                                                                }
                                                                card_detail_tab.set(CardDetailContentTab::Description);
                                                                replace_card_detail_tab_query(CardDetailContentTab::Description);
                                                            }
                                                        },
                                                        "Description"
                                                    }
                                                    button {
                                                        r#type: "button",
                                                        class: "{synthesis_tab_class}",
                                                        "data-testid": "card-detail-tab-synthesis",
                                                        role: "tab",
                                                        "aria-selected": "{active_detail_tab == CardDetailContentTab::Synthesis}",
                                                        onclick: {
                                                            let realm_id = selected_realm_id.clone();
                                                            let strand_id = card.primary_strand_id.clone();
                                                            move |_| {
                                                                crate::views::chat::capture_chat_feed_scroll_position(
                                                                    &realm_id,
                                                                    &strand_id,
                                                                );
                                                                if let Some(scope) = content_edit_scope_for_tab(
                                                                    editing_card_detail(),
                                                                    card_edit_scope(),
                                                                    CardDetailContentTab::Synthesis,
                                                                ) {
                                                                    card_edit_scope.set(scope);
                                                                }
                                                                card_detail_tab.set(CardDetailContentTab::Synthesis);
                                                                replace_card_detail_tab_query(CardDetailContentTab::Synthesis);
                                                            }
                                                        },
                                                        "Synthesis"
                                                    }
                                                    button {
                                                        r#type: "button",
                                                        class: "{discussion_tab_class}",
                                                        "data-testid": "card-detail-tab-discussion",
                                                        role: "tab",
                                                        "aria-selected": "{active_detail_tab == CardDetailContentTab::Discussion}",
                                                        onclick: {
                                                            let strand_id = card.primary_strand_id.clone();
                                                            let realm_id = selected_realm_id.clone();
                                                            move |_| {
                                                                card_detail_discussion_mounted_for.set(Some(strand_id.clone()));
                                                                card_detail_tab.set(CardDetailContentTab::Discussion);
                                                                replace_card_detail_tab_query(CardDetailContentTab::Discussion);
                                                                crate::views::chat::restore_chat_feed_scroll_position(
                                                                    &realm_id,
                                                                    &strand_id,
                                                                );
                                                            }
                                                        },
                                                        "Discussion"
                                                    }
                                                }
                                                if active_detail_tab == CardDetailContentTab::Description {
                                                    div {
                                                        class: "card-detail-description-panel",
                                                        "data-testid": "card-description-panel",
                                                        role: "tabpanel",
                                                        if editing_card_detail()
                                                            && card_edit_scope() == CardEditScope::Description
                                                        {
                                                            div { class: "workflow-form card-detail-edit-form card-detail-inline-edit-form", "data-testid": "card-detail-edit-form",
                                                                div { class: "field",
                                                                    CardMarkdownEditor {
                                                                        key: "card-markdown-description",
                                                                        aria_label: "Description".to_owned(),
                                                                        value: card_edit_body(),
                                                                        token: token(),
                                                                        realm_id: selected_realm_id.clone(),
                                                                        allow_image_upload: true,
                                                                        on_change: move |value| card_edit_body.set(value),
                                                                        slot: "description".to_owned(),
                                                                    }
                                                                }
                                                                CardDetailEditActions {
                                                                    save_disabled: !detail_send_ready || !card_detail_write_ready(card) || !realm_content_write_ready,
                                                                    status: card_detail_edit_status(),
                                                                    on_save: {
                                                                        let base = base_url.clone();
                                                                        let realm = selected_realm_id.clone();
                                                                        let actor = principal_id.clone();
                                                                        let device = device_id.clone();
                                                                        let current = card.clone();
                                                                        let entries = synthesis_entries.clone();
                                                                        move |_| {
                                                                            spawn(save_card_detail_edit(
                                                                                base.clone(),
                                                                                token,
                                                                                realm.clone(),
                                                                                actor.clone(),
                                                                                device.clone(),
                                                                                current.clone(),
                                                                                entries.clone(),
                                                                                selected_scope_security_encrypted,
                                                                                None,
                                                                                card_edit_scope,
                                                                                card_edit_title,
                                                                                card_edit_description,
                                                                                card_edit_body,
                                                                                card_edit_synthesis,
                                                                                card_edit_synthesis_target_id,
                                                                                card_edit_labels,
                                                                                card_edit_assignee,
                                                                                card_edit_due,
                                                                                editing_card_detail,
                                                                                card_detail_actions_open,
                                                                                card_detail_edit_status,
                                                                                selected_card,
                                                                                state_store,
                                                                                board_status,
                                                                            ));
                                                                        }
                                                                    },
                                                                    on_cancel: {
                                                                        let current = card.clone();
                                                                        move |_| {
                                                                            reset_card_detail_edit(
                                                                                &current,
                                                                                card_edit_title,
                                                                                card_edit_description,
                                                                                card_edit_body,
                                                                                card_edit_synthesis,
                                                                                card_edit_synthesis_target_id,
                                                                                card_edit_labels,
                                                                                card_edit_assignee,
                                                                                card_edit_due,
                                                                                editing_card_detail,
                                                                                card_detail_actions_open,
                                                                                card_synthesis_history_open_id,
                                                                                card_synthesis_selected_revision_id,
                                                                                card_detail_edit_status,
                                                                            );
                                                                        }
                                                                    },
                                                                }
                                                            }
                                                        } else {
                                                            if card.description_locked {
                                                                div {
                                                                    class: "card-detail-empty",
                                                                    "data-testid": "card-detail-description-locked",
                                                                    "{MLS_LOCKED_FIELD_PLACEHOLDER}"
                                                                }
                                                            } else if card.description_body.trim().is_empty() {
                                                                div { class: "card-detail-empty", "No description" }
                                                            } else {
                                                                div { class: "card-detail-description", "data-testid": "card-description-body",
                                                                    {crate::content::render_blocks(
                                                                        &crate::content::parse_local_preview_body(&card.description_body),
                                                                    )}
                                                                }
                                                            }
                                                            if !sidecar_track_active && !card.description_locked {
                                                                div { class: "card-synthesis-footer-action",
                                                                    Button {
                                                                        variant: ButtonVariant::Secondary,
                                                                        class: "card-detail-mini-action",
                                                                        "data-testid": "card-detail-edit-description-button",
                                                                        disabled: !card_detail_edit_ready(card),
                                                                        onclick: {
                                                                            let current = card.clone();
                                                                            move |_| {
                                                                                prepare_selected_card_for_edit(selected_card);
                                                                                let draft = card_detail_draft_from_card(&current);
                                                                                card_edit_title.set(draft.title);
                                                                                card_edit_description.set(draft.description);
                                                                                card_edit_body.set(draft.description_body);
                                                                                card_edit_synthesis.set(draft.synthesis);
                                                                                card_edit_synthesis_target_id.set(None);
                                                                                card_edit_labels.set(draft.labels.join(", "));
                                                                                card_edit_assignee.set(draft.assignee);
                                                                                card_edit_due.set(draft.due);
                                                                                card_edit_scope.set(CardEditScope::Description);
                                                                                card_detail_edit_status.set(String::new());
                                                                                editing_card_detail.set(true);
                                                                                card_detail_actions_open.set(false);
                                                                            }
                                                                        },
                                                                        UiIcon { name: "settings" }
                                                                        span { {crate::i18n::tr("common.edit")} }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                } else if active_detail_tab == CardDetailContentTab::Synthesis {
                                                    div {
                                                        class: "card-detail-synthesis-panel",
                                                        "data-testid": "card-synthesis-panel",
                                                        role: "tabpanel",
                                                        if show_shared_track_base {
                                                            div { class: "sidecar-shared-track-base", "data-testid": "sidecar-shared-synthesis-base",
                                                                span { class: "badge", "Original Strand · read only" }
                                                                if card.synthesis.trim().is_empty() {
                                                                    div { class: "card-detail-empty", "No shared synthesis" }
                                                                } else {
                                                                    div { class: "card-detail-description card-synthesis-body",
                                                                        {crate::content::render_blocks(
                                                                            &crate::content::parse_local_preview_body(&card.synthesis),
                                                                        )}
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        if sidecar_track_active {
                                                            div { class: "sidecar-private-track-label", "data-testid": "sidecar-private-synthesis-label",
                                                                span { class: "badge", "Private Sidecar overlay" }
                                                            }
                                                        }
                                                        if synthesis_entries.is_empty()
                                                            && track_card.synthesis_locked
                                                        {
                                                            div {
                                                                class: "card-detail-empty",
                                                                "data-testid": "card-detail-synthesis-locked",
                                                                div { "{MLS_LOCKED_FIELD_PLACEHOLDER}" }
                                                            }
                                                        } else if synthesis_entries.is_empty() {
                                                            div { class: "card-detail-empty",
                                                                div { {if sidecar_track_active { "No private synthesis yet." } else { "No synthesis yet." }} }
                                                            }
                                                        } else {
                                                            div { class: "card-synthesis-track", "data-testid": "card-synthesis-track",
                                                                for entry in synthesis_entries.iter() {
                                                                    {
                                                                        let latest_revision = entry.revisions.last().cloned().unwrap_or_else(|| {
                                                                            CardSynthesisRevision {
                                                                                id: entry.id.clone(),
                                                                                body: entry.body.clone(),
                                                                                actor_id: entry.actor_id.clone(),
                                                                                author_label: entry.author_label.clone(),
                                                                                timestamp_label: entry.timestamp_label.clone(),
                                                                                sort_key: entry.sort_key.clone(),
                                                                            }
                                                                        });
                                                                        let selected_revision_id = card_synthesis_selected_revision_id();
                                                                        let selected_revision = selected_revision_id
                                                                            .as_deref()
                                                                            .and_then(|id| entry.revisions.iter().find(|revision| revision.id == id))
                                                                            .cloned();
                                                                        let display_revision = selected_revision.unwrap_or_else(|| latest_revision.clone());
                                                                        let display_revision_index = entry
                                                                            .revisions
                                                                            .iter()
                                                                            .position(|revision| revision.id == display_revision.id)
                                                                            .unwrap_or_else(|| entry.revisions.len().saturating_sub(1));
                                                                        let version_label = format!("v{}", display_revision_index + 1);
                                                                        let selected_synthesis_is_latest = display_revision.id == latest_revision.id;
                                                                        let version_state = if selected_synthesis_is_latest {
                                                                            "latest"
                                                                        } else {
                                                                            "history"
                                                                        };
                                                                        let synthesis_is_own =
                                                                            actor_is_current_account(&display_revision.actor_id, &principal_id);
                                                                        let entry_class = if selected_synthesis_is_latest {
                                                                            if synthesis_is_own {
                                                                                "card-synthesis-entry is-latest is-own"
                                                                            } else {
                                                                                "card-synthesis-entry is-latest"
                                                                            }
                                                                        } else {
                                                                            if synthesis_is_own {
                                                                                "card-synthesis-entry is-history is-own"
                                                                            } else {
                                                                                "card-synthesis-entry is-history"
                                                                            }
                                                                        };
                                                                        let history_open = card_synthesis_history_open_id()
                                                                            .as_deref()
                                                                            == Some(entry.id.as_str());
                                                                        let actor_title = if display_revision.actor_id.trim().is_empty() {
                                                                            "Unknown author".to_owned()
                                                                        } else {
                                                                            display_revision.actor_id.clone()
                                                                        };
                                                                        rsx! {
                                                                            article {
                                                                                key: "{entry.id}",
                                                                                class: "{entry_class}",
                                                                                "data-testid": "card-synthesis-entry",
                                                                                "data-synthesis-version-state": "{version_state}",
                                                                                header { class: "card-synthesis-entry-head",
                                                                                    ActorIdentityLabel {
                                                                                        label: display_revision.author_label.clone(),
                                                                                        title: Some(actor_title),
                                                                                        class: Some("card-synthesis-author".to_owned()),
                                                                                        test_id: Some("card-synthesis-author".to_owned()),
                                                                                        self_badge_test_id: Some("card-synthesis-self-badge".to_owned()),
                                                                                        agent_badge_test_id: None,
                                                                                        is_self: synthesis_is_own,
                                                                                        agent_slug: None,
                                                                                        agent_selector: None,
                                                                                    }
                                                                                    time { class: "card-synthesis-time", "{display_revision.timestamp_label}" }
                                                                                    span { class: "badge", "{version_label}" }
                                                                                    if selected_synthesis_is_latest {
                                                                                        span { class: "badge badge-success", "latest" }
                                                                                    } else {
                                                                                        span { class: "badge badge-warning", "historical version" }
                                                                                        Button {
                                                                                            variant: ButtonVariant::Secondary,
                                                                                            r#type: "button",
                                                                                            class: "badge card-synthesis-latest-button",
                                                                                            "data-testid": "card-synthesis-latest-button",
                                                                                            onclick: move |_| {
                                                                                                card_synthesis_selected_revision_id.set(None);
                                                                                                card_synthesis_history_open_id.set(None);
                                                                                            },
                                                                                            "Latest"
                                                                                        }
                                                                                    }
                                                                                    if entry.revisions.len() > 1 {
                                                                                        div { class: "card-synthesis-history-wrap",
                                                                                            Button {
                                                                                                variant: ButtonVariant::Secondary,
                                                                                                r#type: "button",
                                                                                                class: "badge card-synthesis-history-trigger",
                                                                                                "data-testid": "card-synthesis-history-trigger",
                                                                                                "aria-expanded": "{history_open}",
                                                                                                onclick: {
                                                                                                    let entry_id = entry.id.clone();
                                                                                                    move |_| {
                                                                                                        if card_synthesis_history_open_id().as_deref() == Some(entry_id.as_str()) {
                                                                                                            card_synthesis_history_open_id.set(None);
                                                                                                        } else {
                                                                                                            card_synthesis_history_open_id.set(Some(entry_id.clone()));
                                                                                                        }
                                                                                                    }
                                                                                                },
                                                                                                "edited"
                                                                                            }
                                                                                            if history_open {
                                                                                                div { class: "card-synthesis-history-menu", "data-testid": "card-synthesis-history-menu",
                                                                                                    div { class: "card-synthesis-history-title", "History" }
                                                                                                    for (history_index, history_entry) in entry.revisions.iter().enumerate().rev() {
                                                                                                        {
                                                                                                            let history_entry_id = history_entry.id.clone();
                                                                                                            let history_version_label = format!("v{}", history_index + 1);
                                                                                                            let history_is_latest = history_entry.id == latest_revision.id;
                                                                                                            let history_item_class = if history_entry.id == display_revision.id {
                                                                                                                "card-synthesis-history-item active"
                                                                                                            } else {
                                                                                                                "card-synthesis-history-item"
                                                                                                            };
                                                                                                            let history_author_title = if history_entry.actor_id.trim().is_empty() {
                                                                                                                "Unknown author".to_owned()
                                                                                                            } else {
                                                                                                                history_entry.actor_id.clone()
                                                                                                            };
                                                                                                            let preview = card_summary_text(&history_entry.body);
                                                                                                            let preview = if preview.chars().count() > 72 {
                                                                                                                let shortened = preview.chars().take(72).collect::<String>();
                                                                                                                format!("{shortened}...")
                                                                                                            } else {
                                                                                                                preview
                                                                                                            };
                                                                                                            let history_is_own =
                                                                                                                actor_is_current_account(&history_entry.actor_id, &principal_id);
                                                                                                            rsx! {
                                                                                                                Button {
                                                                                                                    variant: ButtonVariant::Secondary,
                                                                                                                    key: "{history_entry.id}",
                                                                                                                    r#type: "button",
                                                                                                                    class: "{history_item_class}",
                                                                                                                    "data-testid": "card-synthesis-history-item",
                                                                                                                    onclick: move |_| {
                                                                                                                        if history_is_latest {
                                                                                                                            card_synthesis_selected_revision_id.set(None);
                                                                                                                        } else {
                                                                                                                            card_synthesis_selected_revision_id.set(Some(history_entry_id.clone()));
                                                                                                                        }
                                                                                                                        card_synthesis_history_open_id.set(None);
                                                                                                                    },
                                                                                                                    span { class: "card-synthesis-history-meta",
                                                                                                                        span { class: "badge", "{history_version_label}" }
                                                                                                                        if history_is_latest {
                                                                                                                            span { class: "badge badge-success", "latest" }
                                                                                                                        }
                                                                                                                        ActorIdentityLabel {
                                                                                                                            label: history_entry.author_label.clone(),
                                                                                                                            title: Some(history_author_title),
                                                                                                                            class: Some("card-synthesis-history-author".to_owned()),
                                                                                                                            test_id: Some("card-synthesis-history-author".to_owned()),
                                                                                                                            self_badge_test_id: Some("card-synthesis-history-self-badge".to_owned()),
                                                                                                                            agent_badge_test_id: None,
                                                                                                                            is_self: history_is_own,
                                                                                                                            agent_slug: None,
                                                                                                                            agent_selector: None,
                                                                                                                        }
                                                                                                                        time { "{history_entry.timestamp_label}" }
                                                                                                                    }
                                                                                                                    span { class: "card-synthesis-history-preview", "{preview}" }
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                    if !editing_card_detail() {
                                                                                        Button {
                                                                                            variant: ButtonVariant::Secondary,
                                                                                            r#type: "button",
                                                                                            class: "card-detail-mini-action card-synthesis-entry-edit",
                                                                                            "data-testid": "card-detail-edit-synthesis-button",
                                                                                            disabled: !card_detail_edit_ready(track_card),
                                                                                            onclick: {
                                                                                                let current = track_card.clone();
                                                                                                let entry_id = entry.id.clone();
                                                                                                let entry_body = entry.body.clone();
                                                                                                move |_| {
                                                                                                    prepare_selected_card_for_edit(selected_card);
                                                                                                    let draft = card_detail_draft_from_card(&current);
                                                                                                    card_edit_title.set(draft.title);
                                                                                                    card_edit_description.set(draft.description);
                                                                                                    card_edit_body.set(draft.description_body);
                                                                                                    card_edit_synthesis.set(entry_body.clone());
                                                                                                    card_edit_synthesis_target_id.set(Some(entry_id.clone()));
                                                                                                    card_edit_labels.set(draft.labels.join(", "));
                                                                                                    card_edit_assignee.set(draft.assignee);
                                                                                                    card_edit_due.set(draft.due);
                                                                                                    card_edit_scope.set(CardEditScope::Synthesis);
                                                                                                    card_detail_edit_status.set(String::new());
                                                                                                    editing_card_detail.set(true);
                                                                                                    card_synthesis_history_open_id.set(None);
                                                                                                    card_synthesis_selected_revision_id.set(None);
                                                                                                }
                                                                                            },
                                                                                            UiIcon { name: "settings" }
                                                                                            span { {crate::i18n::tr("common.edit")} }
                                                                                        }
                                                                                    }
                                                                                }
                                                                                if editing_card_detail()
                                                                                    && card_edit_scope() == CardEditScope::Synthesis
                                                                                    && card_edit_synthesis_target_id().as_deref() == Some(entry.id.as_str()) {
                                                                                    div { class: "workflow-form card-detail-edit-form card-detail-inline-edit-form", "data-testid": "card-detail-edit-form",
                                                                                        div { class: "field",
                                                                                            CardMarkdownEditor {
                                                                                                key: "card-markdown-synthesis-{entry.id}",
                                                                                                aria_label: "Synthesis".to_owned(),
                                                                                                value: card_edit_synthesis(),
                                                                                                token: token(),
                                                                                                realm_id: selected_realm_id.clone(),
                                                                                                allow_image_upload: !sidecar_track_active,
                                                                                                on_change: move |value| card_edit_synthesis.set(value),
                                                                                                slot: "synthesis".to_owned(),
                                                                                            }
                                                                                        }
                                                                                        CardDetailEditActions {
                                                                                            save_disabled: !detail_send_ready || !card_detail_write_ready(card) || (!sidecar_track_active && !realm_content_write_ready),
                                                                                            status: card_detail_edit_status(),
                                                                                            on_save: {
                                                                                                let base = base_url.clone();
                                                                                                let realm = selected_realm_id.clone();
                                                                                                let actor = principal_id.clone();
                                                                                                let device = device_id.clone();
                                                                                                let current = track_card.clone();
                                                                                                let entries = synthesis_entries.clone();
                                                                                                let sidecar_write = sidecar_track_write.clone();
                                                                                                move |_| {
                                                                                                    spawn(save_card_detail_edit(
                                                                                                        base.clone(),
                                                                                                        token,
                                                                                                        realm.clone(),
                                                                                                        actor.clone(),
                                                                                                        device.clone(),
                                                                                                        current.clone(),
                                                                                                        entries.clone(),
                                                                                                        selected_scope_security_encrypted,
                                                                                                        sidecar_write.clone(),
                                                                                                        card_edit_scope,
                                                                                                        card_edit_title,
                                                                                                        card_edit_description,
                                                                                                        card_edit_body,
                                                                                                        card_edit_synthesis,
                                                                                                        card_edit_synthesis_target_id,
                                                                                                        card_edit_labels,
                                                                                                        card_edit_assignee,
                                                                                                        card_edit_due,
                                                                                                        editing_card_detail,
                                                                                                        card_detail_actions_open,
                                                                                                        card_detail_edit_status,
                                                                                                        selected_card,
                                                                                                        state_store,
                                                                                                        board_status,
                                                                                                    ));
                                                                                                }
                                                                                            },
                                                                                            on_cancel: {
                                                                                                let current = track_card.clone();
                                                                                                move |_| {
                                                                                                    reset_card_detail_edit(
                                                                                                        &current,
                                                                                                        card_edit_title,
                                                                                                        card_edit_description,
                                                                                                        card_edit_body,
                                                                                                        card_edit_synthesis,
                                                                                                        card_edit_synthesis_target_id,
                                                                                                        card_edit_labels,
                                                                                                        card_edit_assignee,
                                                                                                        card_edit_due,
                                                                                                        editing_card_detail,
                                                                                                        card_detail_actions_open,
                                                                                                        card_synthesis_history_open_id,
                                                                                                        card_synthesis_selected_revision_id,
                                                                                                        card_detail_edit_status,
                                                                                                    );
                                                                                                }
                                                                                            },
                                                                                        }
                                                                                    }
                                                                                } else {
                                                                                    div { class: "card-detail-description card-synthesis-body",
                                                                                        {crate::content::render_blocks(
                                                                                            &crate::content::parse_local_preview_body(&display_revision.body),
                                                                                        )}
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        if editing_card_detail()
                                                            && card_edit_scope() == CardEditScope::Synthesis
                                                            && card_edit_synthesis_target_id().is_none() {
                                                            div { class: "workflow-form card-detail-edit-form card-detail-inline-edit-form", "data-testid": "card-detail-edit-form",
                                                                div { class: "field",
                                                                    CardMarkdownEditor {
                                                                        key: "card-markdown-synthesis-new",
                                                                        aria_label: "Synthesis".to_owned(),
                                                                        value: card_edit_synthesis(),
                                                                        token: token(),
                                                                        realm_id: selected_realm_id.clone(),
                                                                        allow_image_upload: !sidecar_track_active,
                                                                        on_change: move |value| card_edit_synthesis.set(value),
                                                                        slot: "synthesis".to_owned(),
                                                                    }
                                                                }
                                                                CardDetailEditActions {
                                                                    save_disabled: !detail_send_ready || !card_detail_write_ready(card) || (!sidecar_track_active && !realm_content_write_ready),
                                                                    status: card_detail_edit_status(),
                                                                    on_save: {
                                                                        let base = base_url.clone();
                                                                        let realm = selected_realm_id.clone();
                                                                        let actor = principal_id.clone();
                                                                        let device = device_id.clone();
                                                                        let current = track_card.clone();
                                                                        let entries = synthesis_entries.clone();
                                                                        let sidecar_write = sidecar_track_write.clone();
                                                                        move |_| {
                                                                            spawn(save_card_detail_edit(
                                                                                base.clone(),
                                                                                token,
                                                                                realm.clone(),
                                                                                actor.clone(),
                                                                                device.clone(),
                                                                                current.clone(),
                                                                                entries.clone(),
                                                                                selected_scope_security_encrypted,
                                                                                sidecar_write.clone(),
                                                                                card_edit_scope,
                                                                                card_edit_title,
                                                                                card_edit_description,
                                                                                card_edit_body,
                                                                                card_edit_synthesis,
                                                                                card_edit_synthesis_target_id,
                                                                                card_edit_labels,
                                                                                card_edit_assignee,
                                                                                card_edit_due,
                                                                                editing_card_detail,
                                                                                card_detail_actions_open,
                                                                                card_detail_edit_status,
                                                                                selected_card,
                                                                                state_store,
                                                                                board_status,
                                                                            ));
                                                                        }
                                                                    },
                                                                    on_cancel: {
                                                                        let current = track_card.clone();
                                                                        move |_| {
                                                                            reset_card_detail_edit(
                                                                                &current,
                                                                                card_edit_title,
                                                                                card_edit_description,
                                                                                card_edit_body,
                                                                                card_edit_synthesis,
                                                                                card_edit_synthesis_target_id,
                                                                                card_edit_labels,
                                                                                card_edit_assignee,
                                                                                card_edit_due,
                                                                                editing_card_detail,
                                                                                card_detail_actions_open,
                                                                                card_synthesis_history_open_id,
                                                                                card_synthesis_selected_revision_id,
                                                                                card_detail_edit_status,
                                                                            );
                                                                        }
                                                                    },
                                                                }
                                                            }
                                                        }
                                                        if !editing_card_detail() {
                                                            div { class: "card-synthesis-footer-action",
                                                                Button {
                                                                    variant: ButtonVariant::Secondary,
                                                                    class: "card-detail-mini-action",
                                                                    "data-testid": "card-detail-new-synthesis-button",
                                                                    disabled: !card_detail_edit_ready(track_card),
                                                                    onclick: {
                                                                        let current = track_card.clone();
                                                                        move |_| {
                                                                            prepare_selected_card_for_edit(selected_card);
                                                                            let draft = card_detail_draft_from_card(&current);
                                                                            card_edit_title.set(draft.title);
                                                                            card_edit_description.set(draft.description);
                                                                            card_edit_body.set(draft.description_body);
                                                                            card_edit_synthesis.set(String::new());
                                                                            card_edit_synthesis_target_id.set(None);
                                                                            card_edit_labels.set(draft.labels.join(", "));
                                                                            card_edit_assignee.set(draft.assignee);
                                                                            card_edit_due.set(draft.due);
                                                                            card_edit_scope.set(CardEditScope::Synthesis);
                                                                            card_detail_edit_status.set(String::new());
                                                                            editing_card_detail.set(true);
                                                                            card_synthesis_history_open_id.set(None);
                                                                            card_synthesis_selected_revision_id.set(None);
                                                                        }
                                                                    },
                                                                    UiIcon { name: "plus" }
                                                                    span { "New" }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                if discussion_panel_should_mount {
                                                    div {
                                                        class: "{discussion_panel_class}",
                                                        "data-testid": "card-discussion-panel",
                                                        role: "tabpanel",
                                                        "aria-hidden": "{active_detail_tab != CardDetailContentTab::Discussion}",
                                                        if discussion_target_ready {
                                                            crate::views::chat::ChatPanel {
                                                                plaintext_service_id: plaintext_service_id.clone(),
                                                                principal_id: principal_core_id.clone(),
                                                                account_primary_handle: account_primary_handle.clone(),
                                                                device_id: device_id.clone(),
                                                                token,
                                                                selected_realm_id: selected_realm_id.clone(),
                                                                sync_cursor,
                                                                realm_live_epoch,
                                                                frontier_state,
                                                                initial_strand_id: card.primary_strand_id.clone(),
                                                                embedded: true,
                                                                direct_mode: false,
                                                                mention_insert_request: Some(member_mention_request),
                                                            }
                                                        } else {
                                                            div {
                                                                class: "card-detail-empty discussion-pending-target",
                                                                "data-testid": "card-discussion-pending-target",
                                                                role: "status",
                                                                "aria-live": "polite",
                                                                "This card is still being created. Discussion will be available after the server assigns its Strand ID."
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if sidebar_is_visible {
                                        aside { class: "card-detail-sidebar",
                                            {
                                                let store = state_store.read().load();
                                                let projection = store.realm_tree_projections.get(&selected_realm_id);
                                                let realm_context = member_roster_realm_context(
                                                    &selected_realm_id,
                                                    &projection_realm_id,
                                                    projection,
                                                );
                                                let realm_member_rows = realm_member_roster(
                                                    projection,
                                                );
                                                let realm_member_count = realm_member_rows.len();
                                                let participant_set: BTreeSet<String> = strand_participant_ids(
                                                    &store.raw_operations,
                                                    &card.primary_strand_id,
                                                )
                                                .into_iter()
                                                .collect();
                                                let owned_agent_inventory_snapshot =
                                                    owned_agent_inventory.read().clone();
                                                let active_sidebar_tab = card_detail_sidebar_tab();
                                                let on_member_mention = EventHandler::new({
                                                    let strand_id = card.primary_strand_id.clone();
                                                    move |request| {
                                                        member_mention_request.set(Some(request));
                                                        card_detail_discussion_mounted_for
                                                            .set(Some(strand_id.clone()));
                                                        card_detail_tab
                                                            .set(CardDetailContentTab::Discussion);
                                                        replace_card_detail_tab_query(
                                                            CardDetailContentTab::Discussion,
                                                        );
                                                    }
                                                });
                                                let details_tab_class = if active_sidebar_tab == CardDetailSidebarTab::Details {
                                                    "card-detail-tab active"
                                                } else {
                                                    "card-detail-tab"
                                                };
                                                let members_tab_class = if active_sidebar_tab == CardDetailSidebarTab::Members {
                                                    "card-detail-tab active"
                                                } else {
                                                    "card-detail-tab"
                                                };
                                                rsx! {
                                                    div {
                                                        class: "card-detail-tabs card-detail-sidebar-tabs",
                                                        "data-testid": "card-detail-sidebar-tabs",
                                                        role: "tablist",
                                                        "aria-label": "Sidebar views",
                                                        button {
                                                            r#type: "button",
                                                            class: "{details_tab_class}",
                                                            "data-testid": "card-detail-sidebar-tab-details",
                                                            role: "tab",
                                                            "aria-selected": "{active_sidebar_tab == CardDetailSidebarTab::Details}",
                                                            onclick: move |_| card_detail_sidebar_tab.set(CardDetailSidebarTab::Details),
                                                            "Details"
                                                        }
                                                        button {
                                                            r#type: "button",
                                                            class: "{members_tab_class}",
                                                            "data-testid": "card-detail-sidebar-tab-members",
                                                            role: "tab",
                                                            "aria-selected": "{active_sidebar_tab == CardDetailSidebarTab::Members}",
                                                            onclick: move |_| card_detail_sidebar_tab.set(CardDetailSidebarTab::Members),
                                                            "Members ({realm_member_count})"
                                                        }
                                                    }
                                                    if active_sidebar_tab == CardDetailSidebarTab::Details {
                                                        {
                                                            let assigned_actor_ids = card_assigned_actor_ids(card);
                                                            let assigned_people = {
                                                                let store = state_store.read();
                                                                assigned_actor_ids
                                                                    .iter()
                                                                    .map(|actor_id| {
                                                                        let label = assignee_label_for_actor(
                                                                            &store,
                                                                            &realm_context,
                                                                            &realm_member_rows,
                                                                            actor_id,
                                                                        );
                                                                        (actor_id.clone(), label)
                                                                    })
                                                                    .collect::<Vec<_>>()
                                                            };
                                                            let assignee_title = if assigned_actor_ids.is_empty() {
                                                                "unassigned".to_owned()
                                                            } else {
                                                                assigned_actor_ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
                                                            };
                                                            let picker_rows = assignment_picker_roster(&realm_member_rows, card);
                                                            let picker_filter = assignee_filter();
                                                            let selected_actor_ids = assignee_selected_actor_ids();
                                                            let picker_people = {
                                                                let store = state_store.read();
                                                                picker_rows
                                                                    .iter()
                                                                    .filter_map(|row| {
                                                                        let label = assignee_label_for_actor(
                                                                            &store,
                                                                            &realm_context,
                                                                            &realm_member_rows,
                                                                            &row.actor_id,
                                                                        );
                                                                        assignee_filter_matches(&picker_filter, &label, &row.actor_id.to_string()).then(|| {
                                                                            (
                                                                                row.actor_id.clone(),
                                                                                label.clone(),
                                                                                short_protocol_id(row.actor_id.signing_principal_id().as_str()),
                                                                            )
                                                                        })
                                                                    })
                                                                    .collect::<Vec<_>>()
                                                            };
                                                            let picker_open = assignee_picker_open();
                                                            let edit_status = assignee_edit_status();
                                                            rsx! {
                                                        div { class: "card-detail-side-fields", "data-testid": "card-fields",
                                                            dl { class: "card-detail-field-list",
                                                                div {
                                                                    dt { "Strand ID" }
                                                                    dd { class: "card-detail-field-code", title: "{card.id}", "{card_id_label}" }
                                                                }
                                                                div {
                                                                    dt { "Assignees" }
                                                                    dd {
                                                                        div {
                                                                            class: "assignee-editor",
                                                                            "data-testid": "card-detail-assignees",
                                                                            div { class: "assignee-chip-row", title: "{assignee_title}",
                                                                                if assigned_people.is_empty() {
                                                                                    Button {
                                                                                        variant: ButtonVariant::Secondary,
                                                                                        r#type: "button",
                                                                                        class: "assignee-add assignee-add-empty",
                                                                                        "aria-haspopup": "listbox",
                                                                                        "aria-expanded": "{picker_open}",
                                                                                        title: "Add assignees",
                                                                                        onclick: {
                                                                                            let current_selection = assigned_actor_ids
                                                                                                .iter()
                                                                                                .cloned()
                                                                                                .collect::<BTreeSet<_>>();
                                                                                            move |_| {
                                                                                                assignee_selected_actor_ids.set(current_selection.clone());
                                                                                                assignee_filter.set(String::new());
                                                                                                assignee_edit_status.set(String::new());
                                                                                                assignee_picker_open.set(!assignee_picker_open());
                                                                                            }
                                                                                        },
                                                                                        UiIcon { name: "plus" }
                                                                                        span { "Add assignees" }
                                                                                    }
                                                                                } else {
                                                                                    span { class: "assignee-chip-list",
                                                                                        for (actor_id, label) in assigned_people.iter() {
                                                                                            span {
                                                                                                key: "{actor_id}",
                                                                                                class: "assignee-chip",
                                                                                                title: "{actor_id}",
                                                                                                crate::components::IdentityAvatar {
                                                                                                    seed: actor_id.clone(),
                                                                                                    alt_text: label.clone(),
                                                                                                    class: "avatar-img assignee-avatar".to_owned(),
                                                                                                }
                                                                                                span { class: "assignee-chip-label", "{label}" }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                    Button {
                                                                                        variant: ButtonVariant::Secondary,
                                                                                        r#type: "button",
                                                                                        class: "assignee-add",
                                                                                        "aria-label": "Add or remove assignees",
                                                                                        "aria-haspopup": "listbox",
                                                                                        "aria-expanded": "{picker_open}",
                                                                                        title: "Add or remove assignees",
                                                                                        onclick: {
                                                                                            let current_selection = assigned_actor_ids
                                                                                                .iter()
                                                                                                .cloned()
                                                                                                .collect::<BTreeSet<_>>();
                                                                                            move |_| {
                                                                                                assignee_selected_actor_ids.set(current_selection.clone());
                                                                                                assignee_filter.set(String::new());
                                                                                                assignee_edit_status.set(String::new());
                                                                                                assignee_picker_open.set(!assignee_picker_open());
                                                                                            }
                                                                                        },
                                                                                        UiIcon { name: "plus" }
                                                                                    }
                                                                                    Button {
                                                                                        variant: ButtonVariant::Secondary,
                                                                                        r#type: "button",
                                                                                        class: "assignee-add assignee-clear",
                                                                                        "aria-label": "Clear assignees",
                                                                                        title: "Clear assignees",
                                                                                        onclick: {
                                                                                            let base = base_url.clone();
                                                                                            let realm = selected_realm_id.clone();
                                                                                            let actor = principal_id.clone();
                                                                                            let current_card = card.clone();
                                                                                            move |_| {
                                                                                                assignee_selected_actor_ids.set(BTreeSet::new());
                                                                                                if dispatch_card_assignees_update(
                                                                                                    base.clone(),
                                                                                                    token,
                                                                                                    realm.clone(),
                                                                                                    actor.clone(),
                                                                                                    current_card.clone(),
                                                                                                    BTreeSet::new(),
                                                                                                    selected_card,
                                                                                                    state_store,
                                                                                                    board_status,
                                                                                                    assignee_edit_status,
                                                                                                ) {
                                                                                                    assignee_picker_open.set(false);
                                                                                                    assignee_filter.set(String::new());
                                                                                                }
                                                                                            }
                                                                                        },
                                                                                        UiIcon { name: "x" }
                                                                                    }
                                                                                }
                                                                            }
                                                                            if picker_open {
                                                                                div {
                                                                                    class: "assignee-popover",
                                                                                    "data-testid": "card-detail-assignees-picker",
                                                                                    div { class: "assignee-search",
                                                                                        UiIcon { name: "search" }
                                                                                        Input {
                                                                                            class: "input",
                                                                                            "data-testid": "card-detail-assignees-search",
                                                                                            value: "{picker_filter}",
                                                                                            placeholder: "Filter members",
                                                                                            oninput: move |event: FormEvent| assignee_filter.set(event.value()),
                                                                                        }
                                                                                    }
                                                                                    div {
                                                                                        class: "assignee-options",
                                                                                        role: "listbox",
                                                                                        "aria-label": "Assignees",
                                                                                        if picker_people.is_empty() {
                                                                                            div { class: "assignee-option-empty", "No members match" }
                                                                                        } else {
                                                                                            for (actor_id, label, compact_id) in picker_people.iter() {
                                                                                                {
                                                                                                    let selected = selected_actor_ids.contains(actor_id);
                                                                                                    let option_class = if selected {
                                                                                                        "assignee-option selected"
                                                                                                    } else {
                                                                                                        "assignee-option"
                                                                                                    };
                                                                                                    let target_actor_id = actor_id.clone();
                                                                                                    rsx! {
                                                                                                        Button {
                                                                                                            variant: ButtonVariant::Secondary,
                                                                                                            key: "{actor_id}",
                                                                                                            r#type: "button",
                                                                                                            class: "{option_class}",
                                                                                                            role: "option",
                                                                                                            "aria-selected": "{selected}",
                                                                                                            onclick: move |_| {
                                                                                                                let mut next = assignee_selected_actor_ids();
                                                                                                                if next.contains(&target_actor_id) {
                                                                                                                    next.remove(&target_actor_id);
                                                                                                                } else {
                                                                                                                    next.insert(target_actor_id.clone());
                                                                                                                }
                                                                                                                assignee_selected_actor_ids.set(next);
                                                                                                            },
                                                                                                            span { class: "assignee-option-check",
                                                                                                                if selected {
                                                                                                                    UiIcon { name: "check" }
                                                                                                                }
                                                                                                            }
                                                                                                            crate::components::IdentityAvatar {
                                                                                                                seed: actor_id.clone(),
                                                                                                                alt_text: label.clone(),
                                                                                                                class: "avatar-img assignee-avatar".to_owned(),
                                                                                                            }
                                                                                                            span { class: "assignee-option-main",
                                                                                                                span { class: "assignee-option-label", "{label}" }
                                                                                                                span { class: "assignee-option-meta", "{compact_id}" }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                    if !edit_status.trim().is_empty() {
                                                                                        div {
                                                                                            class: "assignee-edit-status",
                                                                                            role: "status",
                                                                                            "aria-live": "polite",
                                                                                            "{edit_status}"
                                                                                        }
                                                                                    }
                                                                                    div { class: "assignee-popover-actions",
                                                                                        Button {
                                                                                            variant: ButtonVariant::Secondary,
                                                                                            r#type: "button",
                                                                                            onclick: move |_| assignee_selected_actor_ids.set(BTreeSet::new()),
                                                                                            "Clear"
                                                                                        }
                                                                                        Button {
                                                                                            variant: ButtonVariant::Secondary,
                                                                                            r#type: "button",
                                                                                            onclick: move |_| {
                                                                                                assignee_picker_open.set(false);
                                                                                                assignee_filter.set(String::new());
                                                                                                assignee_edit_status.set(String::new());
                                                                                            },
                                                                                            {crate::i18n::tr("common.cancel")}
                                                                                        }
                                                                                        Button {
                                                                                            variant: ButtonVariant::Primary,
                                                                                            r#type: "button",
                                                                                            onclick: {
                                                                                                let base = base_url.clone();
                                                                                                let realm = selected_realm_id.clone();
                                                                                                let actor = principal_id.clone();
                                                                                                let current_card = card.clone();
                                                                                                move |_| {
                                                                                                    if dispatch_card_assignees_update(
                                                                                                        base.clone(),
                                                                                                        token,
                                                                                                        realm.clone(),
                                                                                                        actor.clone(),
                                                                                                        current_card.clone(),
                                                                                                        assignee_selected_actor_ids(),
                                                                                                        selected_card,
                                                                                                        state_store,
                                                                                                        board_status,
                                                                                                        assignee_edit_status,
                                                                                                    ) {
                                                                                                        assignee_picker_open.set(false);
                                                                                                        assignee_filter.set(String::new());
                                                                                                    }
                                                                                                }
                                                                                            },
                                                                                            {crate::i18n::tr("common.save")}
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                                div {
                                                                    dt { "Due" }
                                                                    dd {
                                                                        {
                                                                            let due_editor_value = editor_value_for_optional_card_field(&card.due);
                                                                            let due_has_value = !due_editor_value.is_empty();
                                                                            let due_open = due_picker_open();
                                                                            let due_status = due_edit_status();
                                                                            let selected_date = parse_due_calendar_date(&due_edit_value());
                                                                            let today_date = due_calendar_today();
                                                                            let month = due_calendar_month();
                                                                            let month_label = due_calendar_month_label(month);
                                                                            let calendar_cells = due_calendar_cells(month);
                                                                            rsx! {
                                                                                div {
                                                                                    class: "due-editor",
                                                                                    "data-testid": "card-detail-due",
                                                                                    if due_has_value {
                                                                                        span {
                                                                                            class: "due-pill",
                                                                                            title: "{due_editor_value}",
                                                                                            "{due_editor_value}"
                                                                                        }
                                                                                        Button {
                                                                                            variant: ButtonVariant::Secondary,
                                                                                            r#type: "button",
                                                                                            class: "due-edit-button",
                                                                                            "aria-label": "Edit due date",
                                                                                            "aria-haspopup": "dialog",
                                                                                            "aria-expanded": "{due_open}",
                                                                                            title: "Edit due date",
                                                                                            onclick: {
                                                                                                let current_due = due_editor_value.clone();
                                                                                                move |_| {
                                                                                                    due_edit_value.set(current_due.clone());
                                                                                                    due_calendar_month.set(due_calendar_month_for_value(&current_due));
                                                                                                    due_edit_status.set(String::new());
                                                                                                    assignee_picker_open.set(false);
                                                                                                    due_picker_open.set(!due_picker_open());
                                                                                                }
                                                                                            },
                                                                                            UiIcon { name: "calendar" }
                                                                                        }
                                                                                        Button {
                                                                                            variant: ButtonVariant::Secondary,
                                                                                            r#type: "button",
                                                                                            class: "due-edit-button due-clear-button",
                                                                                            "aria-label": "Clear due date",
                                                                                            title: "Clear due date",
                                                                                            onclick: {
                                                                                                let base = base_url.clone();
                                                                                                let realm = selected_realm_id.clone();
                                                                                                let actor = principal_id.clone();
                                                                                                let device = device_id.clone();
                                                                                                let current_card = card.clone();
                                                                                                move |_| {
                                                                                                    due_edit_value.set(String::new());
                                                                                                    due_calendar_month.set(default_due_calendar_month());
                                                                                                    due_picker_open.set(true);
                                                                                                    let base = base.clone();
                                                                                                    let realm = realm.clone();
                                                                                                    let actor = actor.clone();
                                                                                                    let device = device.clone();
                                                                                                    let current_card = current_card.clone();
                                                                                                    spawn(async move { let _ = save_card_due_edit(
                                                                                                        base,
                                                                                                        token,
                                                                                                        realm,
                                                                                                        actor,
                                                                                                        device,
                                                                                                        current_card,
                                                                                                        String::new(),
                                                                                                        selected_scope_security_encrypted,
                                                                                                        due_picker_open,
                                                                                                        due_edit_status,
                                                                                                        selected_card,
                                                                                                        state_store,
                                                                                                        board_status,
                                                                                                    ).await; });
                                                                                                }
                                                                                            },
                                                                                            UiIcon { name: "x" }
                                                                                        }
                                                                                    } else {
                                                                                        Button {
                                                                                            variant: ButtonVariant::Secondary,
                                                                                            r#type: "button",
                                                                                            class: "due-add-button",
                                                                                            "aria-haspopup": "dialog",
                                                                                            "aria-expanded": "{due_open}",
                                                                                            title: "Add due date",
                                                                                            onclick: move |_| {
                                                                                                due_edit_value.set(String::new());
                                                                                                due_calendar_month.set(default_due_calendar_month());
                                                                                                due_edit_status.set(String::new());
                                                                                                assignee_picker_open.set(false);
                                                                                                due_picker_open.set(!due_picker_open());
                                                                                            },
                                                                                            UiIcon { name: "plus" }
                                                                                            span { "Add due date" }
                                                                                        }
                                                                                    }
                                                                                    if due_open {
                                                                                        crate::components::DismissiblePopup {
                                                                                            overlay_class: "due-date-modal-backdrop",
                                                                                            surface_class: "due-date-modal",
                                                                                            overlay_test_id: Some("card-detail-due-picker-backdrop".to_owned()),
                                                                                            surface_test_id: Some("card-detail-due-picker".to_owned()),
                                                                                            aria_label: "Set due date",
                                                                                            on_dismiss: {
                                                                                                let cancel_due = due_editor_value.clone();
                                                                                                move |_| {
                                                                                                    due_picker_open.set(false);
                                                                                                    due_edit_value.set(cancel_due.clone());
                                                                                                    due_calendar_month.set(due_calendar_month_for_value(&cancel_due));
                                                                                                    due_edit_status.set(String::new());
                                                                                                }
                                                                                            },
                                                                                            div { class: "due-date-modal-head",
                                                                                                div { class: "due-date-modal-title",
                                                                                                    h3 { "Set due date" }
                                                                                                    p { "Choose a date for this card." }
                                                                                                }
                                                                                                Button {
                                                                                                    variant: ButtonVariant::Secondary,
                                                                                                    r#type: "button",
                                                                                                    class: "due-date-modal-close",
                                                                                                    "aria-label": "Close due date dialog",
                                                                                                    title: "Close",
                                                                                                    onclick: {
                                                                                                        let cancel_due = due_editor_value.clone();
                                                                                                        move |_| {
                                                                                                            due_picker_open.set(false);
                                                                                                            due_edit_value.set(cancel_due.clone());
                                                                                                            due_calendar_month.set(due_calendar_month_for_value(&cancel_due));
                                                                                                            due_edit_status.set(String::new());
                                                                                                        }
                                                                                                    },
                                                                                                    UiIcon { name: "x" }
                                                                                                }
                                                                                            }
                                                                                            div { class: "due-date-modal-body",
                                                                                            div { class: "due-date-modal-field",
                                                                                                Label { html_for: "card-detail-due-inline-input-input", "Due date" }
                                                                                                Input {
                                                                                                    id: "card-detail-due-inline-input-input",
                                                                                                    class: "input",
                                                                                                    "data-testid": "card-detail-due-inline-input",
                                                                                                    value: "{due_edit_value}",
                                                                                                    placeholder: "YYYY-MM-DD",
                                                                                                    oninput: move |event: FormEvent| {
                                                                                                        let next = event.value();
                                                                                                        if let Some(date) = parse_due_calendar_date(&next) {
                                                                                                            due_calendar_month.set(start_of_due_calendar_month(date));
                                                                                                        }
                                                                                                        due_edit_value.set(next);
                                                                                                    },
                                                                                                }
                                                                                            }
                                                                                            div { class: "due-calendar",
                                                                                                div { class: "due-calendar-header",
                                                                                                    Button {
                                                                                                        variant: ButtonVariant::Secondary,
                                                                                                        r#type: "button",
                                                                                                        class: "due-calendar-nav",
                                                                                                        "aria-label": "Previous month",
                                                                                                        title: "Previous month",
                                                                                                        onclick: move |_| {
                                                                                                            due_calendar_month.set(add_due_calendar_months(due_calendar_month(), -1));
                                                                                                        },
                                                                                                        UiIcon { name: "chevron-left" }
                                                                                                    }
                                                                                                    strong { class: "due-calendar-title", "{month_label}" }
                                                                                                    Button {
                                                                                                        variant: ButtonVariant::Secondary,
                                                                                                        r#type: "button",
                                                                                                        class: "due-calendar-nav",
                                                                                                        "aria-label": "Next month",
                                                                                                        title: "Next month",
                                                                                                        onclick: move |_| {
                                                                                                            due_calendar_month.set(add_due_calendar_months(due_calendar_month(), 1));
                                                                                                        },
                                                                                                        UiIcon { name: "chevron-right" }
                                                                                                    }
                                                                                                }
                                                                                                div {
                                                                                                    class: "due-calendar-weekdays",
                                                                                                    span { "Sun" }
                                                                                                    span { "Mon" }
                                                                                                    span { "Tue" }
                                                                                                    span { "Wed" }
                                                                                                    span { "Thu" }
                                                                                                    span { "Fri" }
                                                                                                    span { "Sat" }
                                                                                                }
                                                                                                div {
                                                                                                    class: "due-calendar-grid",
                                                                                                    role: "grid",
                                                                                                    "aria-label": "Due date calendar",
                                                                                                    for cell in calendar_cells.iter() {
                                                                                                        {
                                                                                                            let selected = selected_date.is_some_and(|date| date == cell.date);
                                                                                                            let is_today = today_date == cell.date;
                                                                                                            let mut day_class = String::from("due-calendar-day");
                                                                                                            if !cell.in_current_month {
                                                                                                                day_class.push_str(" outside");
                                                                                                            }
                                                                                                            if is_today {
                                                                                                                day_class.push_str(" today");
                                                                                                            }
                                                                                                            if selected {
                                                                                                                day_class.push_str(" selected");
                                                                                                            }
                                                                                                            let iso_date = cell.iso_date.clone();
                                                                                                            let cell_label = format!("Select {iso_date}");
                                                                                                            rsx! {
                                                                                                                Button {
                                                                                                                    variant: ButtonVariant::Secondary,
                                                                                                                    key: "{cell.iso_date}",
                                                                                                                    r#type: "button",
                                                                                                                    class: "{day_class}",
                                                                                                                    role: "gridcell",
                                                                                                                    "aria-label": "{cell_label}",
                                                                                                                    "aria-pressed": "{selected}",
                                                                                                                    onclick: move |_| {
                                                                                                                        due_edit_value.set(iso_date.clone());
                                                                                                                        due_calendar_month.set(due_calendar_month_for_value(&iso_date));
                                                                                                                    },
                                                                                                                    "{cell.day}"
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                            if !due_status.trim().is_empty() {
                                                                                                div {
                                                                                                    class: "due-edit-status",
                                                                                                    role: "status",
                                                                                                    "aria-live": "polite",
                                                                                                    "{due_status}"
                                                                                                }
                                                                                            }
                                                                                            }
                                                                                            div { class: "due-date-modal-actions",
                                                                                                Button {
                                                                                                    variant: ButtonVariant::Secondary,
                                                                                                    r#type: "button",
                                                                                                    class: "due-date-clear-action",
                                                                                                    onclick: move |_| {
                                                                                                        due_edit_value.set(String::new());
                                                                                                        due_calendar_month.set(default_due_calendar_month());
                                                                                                    },
                                                                                                    "Clear"
                                                                                                }
                                                                                                Button {
                                                                                                    variant: ButtonVariant::Secondary,
                                                                                                    r#type: "button",
                                                                                                    onclick: {
                                                                                                        let cancel_due = due_editor_value.clone();
                                                                                                        move |_| {
                                                                                                            due_picker_open.set(false);
                                                                                                            due_edit_value.set(cancel_due.clone());
                                                                                                            due_calendar_month.set(due_calendar_month_for_value(&cancel_due));
                                                                                                            due_edit_status.set(String::new());
                                                                                                        }
                                                                                                    },
                                                                                                    {crate::i18n::tr("common.cancel")}
                                                                                                }
                                                                                                Button {
                                                                                                    variant: ButtonVariant::Primary,
                                                                                                    r#type: "button",
                                                                                                    onclick: {
                                                                                                        let base = base_url.clone();
                                                                                                        let realm = selected_realm_id.clone();
                                                                                                        let actor = principal_id.clone();
                                                                                                        let device = device_id.clone();
                                                                                                        let current_card = card.clone();
                                                                                                        move |_| {
                                                                                                            let base = base.clone();
                                                                                                            let realm = realm.clone();
                                                                                                            let actor = actor.clone();
                                                                                                            let device = device.clone();
                                                                                                            let current_card = current_card.clone();
                                                                                                            spawn(async move { let _ = save_card_due_edit(
                                                                                                                base,
                                                                                                                token,
                                                                                                                realm,
                                                                                                                actor,
                                                                                                                device,
                                                                                                                current_card,
                                                                                                                due_edit_value(),
                                                                                                                selected_scope_security_encrypted,
                                                                                                                due_picker_open,
                                                                                                                due_edit_status,
                                                                                                                selected_card,
                                                                                                                state_store,
                                                                                                                board_status,
                                                                                                            ).await; });
                                                                                                        }
                                                                                                    },
                                                                                                    {crate::i18n::tr("common.save")}
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                        }
                                                                                    }
                                                                                }
                                                                        }
                                                                    }
                                                                }
                                                                div {
                                                                    dt { "Calendar" }
                                                                    dd {
                                                                        {
                                                                            let schedule = card.calendar.clone();
                                                                            let has_schedule = schedule.has_schedule();
                                                                            let recurrence_label = schedule.recurrence_label();
                                                                            let occurrence_hint = calendar_occurrence_hint(&schedule);
                                                                            let rsvp_display = card.calendar_rsvp.clone();
                                                                            let agenda = calendar_agenda(
                                                                                &schedule,
                                                                                &card.calendar_schedule_basis_refs,
                                                                                chrono::Utc::now(),
                                                                            );
                                                                            let location_label = if schedule.location_locked {
                                                                                MLS_LOCKED_FIELD_PLACEHOLDER.to_owned()
                                                                            } else {
                                                                                schedule.location.clone()
                                                                            };
                                                                            rsx! {
                                                                                div {
                                                                                    class: "calendar-editor",
                                                                                    "data-testid": "card-detail-calendar",
                                                                                    if editing_card_detail() && card_edit_scope() == CardEditScope::Calendar {
                                                                                        crate::components::DismissiblePopup {
                                                                                            overlay_class: "due-date-modal-backdrop calendar-schedule-modal-backdrop",
                                                                                            surface_class: "due-date-modal calendar-schedule-modal",
                                                                                            overlay_test_id: Some("card-detail-calendar-editor-backdrop".to_owned()),
                                                                                            surface_test_id: Some("card-detail-calendar-editor-dialog".to_owned()),
                                                                                            aria_label: if has_schedule { "Edit calendar schedule" } else { "Add calendar schedule" },
                                                                                            on_dismiss: {
                                                                                                let current_calendar = card.calendar.clone();
                                                                                                move |_| {
                                                                                                    card_edit_calendar.set(current_calendar.clone());
                                                                                                    calendar_rsvp_occurrence.set(calendar_occurrence_hint(&current_calendar));
                                                                                                    editing_card_detail.set(false);
                                                                                                    card_detail_actions_open.set(false);
                                                                                                    card_detail_edit_status.set(String::new());
                                                                                                }
                                                                                            },
                                                                                            div { class: "due-date-modal-head",
                                                                                                div { class: "due-date-modal-title",
                                                                                                    h3 { if has_schedule { "Edit schedule" } else { "Add schedule" } }
                                                                                                    p { "Set the event time, recurrence, and calendar details." }
                                                                                                }
                                                                                                Button {
                                                                                                    variant: ButtonVariant::Secondary,
                                                                                                    r#type: "button",
                                                                                                    class: "due-date-modal-close",
                                                                                                    "aria-label": "Close calendar schedule dialog",
                                                                                                    title: "Close",
                                                                                                    onclick: {
                                                                                                        let current_calendar = card.calendar.clone();
                                                                                                        move |_| {
                                                                                                            card_edit_calendar.set(current_calendar.clone());
                                                                                                            calendar_rsvp_occurrence.set(calendar_occurrence_hint(&current_calendar));
                                                                                                            editing_card_detail.set(false);
                                                                                                            card_detail_actions_open.set(false);
                                                                                                            card_detail_edit_status.set(String::new());
                                                                                                        }
                                                                                                    },
                                                                                                    UiIcon { name: "x" }
                                                                                                }
                                                                                            }
                                                                                            CalendarScheduleEditForm {
                                                                                                calendar: card_edit_calendar,
                                                                                                status: card_detail_edit_status(),
                                                                                                on_save: {
                                                                                                    let base = base_url.clone();
                                                                                                    let realm = selected_realm_id.clone();
                                                                                                    let actor = principal_id.clone();
                                                                                                    let device = device_id.clone();
                                                                                                    let current_card = card.clone();
                                                                                                    move |_| {
                                                                                                        let base = base.clone();
                                                                                                        let realm = realm.clone();
                                                                                                        let actor = actor.clone();
                                                                                                        let device = device.clone();
                                                                                                        let current_card = current_card.clone();
                                                                                                        spawn(async move { let _ = save_card_calendar_edit(
                                                                                                            base,
                                                                                                            token,
                                                                                                            realm,
                                                                                                            actor,
                                                                                                            device,
                                                                                                            current_card,
                                                                                                            card_edit_calendar(),
                                                                                                            selected_scope_security_encrypted,
                                                                                                            editing_card_detail,
                                                                                                            card_detail_actions_open,
                                                                                                            card_detail_edit_status,
                                                                                                            selected_card,
                                                                                                            state_store,
                                                                                                            board_status,
                                                                                                        ).await; });
                                                                                                    }
                                                                                                },
                                                                                                on_cancel: {
                                                                                                    let current_calendar = card.calendar.clone();
                                                                                                    move |_| {
                                                                                                        card_edit_calendar.set(current_calendar.clone());
                                                                                                        calendar_rsvp_occurrence.set(calendar_occurrence_hint(&current_calendar));
                                                                                                        editing_card_detail.set(false);
                                                                                                        card_detail_actions_open.set(false);
                                                                                                        card_detail_edit_status.set(String::new());
                                                                                                    }
                                                                                                },
                                                                                            }
                                                                                        }
                                                                                    } else {
                                                                                        if has_schedule {
                                                                                            div { class: "calendar-summary",
                                                                                                if !schedule.start.trim().is_empty() {
                                                                                                    div {
                                                                                                        span { "Start" }
                                                                                                        strong { "{schedule.start}" }
                                                                                                    }
                                                                                                }
                                                                                                if !schedule.end.trim().is_empty() {
                                                                                                    div {
                                                                                                        span { "End" }
                                                                                                        strong { "{schedule.end}" }
                                                                                                    }
                                                                                                }
                                                                                                if !schedule.timezone.trim().is_empty() {
                                                                                                    div {
                                                                                                        span { "Timezone" }
                                                                                                        strong { "{schedule.timezone}" }
                                                                                                    }
                                                                                                }
                                                                                                if schedule.all_day {
                                                                                                    div {
                                                                                                        span { "Mode" }
                                                                                                        strong { "All day" }
                                                                                                    }
                                                                                                }
                                                                                                div {
                                                                                                    span { "Status" }
                                                                                                    strong { "{schedule.status}" }
                                                                                                }
                                                                                                if !recurrence_label.trim().is_empty() {
                                                                                                    div {
                                                                                                        span { "Recurrence" }
                                                                                                        strong { "{recurrence_label}" }
                                                                                                    }
                                                                                                }
                                                                                                if !location_label.trim().is_empty() {
                                                                                                    div {
                                                                                                        span { "Location" }
                                                                                                        strong { "{location_label}" }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                            match agenda {
                                                                                                Ok(items) if !items.is_empty() => rsx! {
                                                                                                    div {
                                                                                                        class: "calendar-agenda",
                                                                                                        "data-testid": "card-detail-calendar-agenda",
                                                                                                        span { "Upcoming" }
                                                                                                        ul {
                                                                                                            for item in items {
                                                                                                                li {
                                                                                                                    key: "{item.occurrence}",
                                                                                                                    strong { "{item.local_start}" }
                                                                                                                    span { " – {item.local_end}" }
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                },
                                                                                                Ok(_) => rsx! {
                                                                                                    div {
                                                                                                        class: "card-detail-empty",
                                                                                                        "data-testid": "card-detail-calendar-agenda-empty",
                                                                                                        "No occurrences in the next 90 days"
                                                                                                    }
                                                                                                },
                                                                                                Err(error) => rsx! {
                                                                                                    div {
                                                                                                        class: "card-detail-empty",
                                                                                                        "data-testid": "card-detail-calendar-agenda-unresolved",
                                                                                                        "Agenda unavailable: {error}"
                                                                                                    }
                                                                                                },
                                                                                            }
                                                                                        } else {
                                                                                            div { class: "card-detail-empty", "No schedule" }
                                                                                        }
                                                                                        Button {
                                                                                            variant: ButtonVariant::Secondary,
                                                                                            r#type: "button",
                                                                                            class: "card-detail-mini-action",
                                                                                            "data-testid": "card-detail-edit-calendar-button",
                                                                                            disabled: !card_detail_edit_ready(card),
                                                                                            "aria-haspopup": "dialog",
                                                                                            "aria-expanded": "false",
                                                                                            onclick: {
                                                                                                let current = card.clone();
                                                                                                move |_| {
                                                                                                    prepare_selected_card_for_edit(selected_card);
                                                                                                    let draft = card_detail_draft_from_card(&current);
                                                                                                    let calendar = draft.calendar.clone();
                                                                                                    card_edit_calendar.set(calendar.clone());
                                                                                                    calendar_rsvp_occurrence.set(calendar_occurrence_hint(&calendar));
                                                                                                    card_edit_scope.set(CardEditScope::Calendar);
                                                                                                    card_detail_edit_status.set(String::new());
                                                                                                    editing_card_detail.set(true);
                                                                                                    card_detail_actions_open.set(false);
                                                                                                    assignee_picker_open.set(false);
                                                                                                    due_picker_open.set(false);
                                                                                                }
                                                                                            },
                                                                                            UiIcon { name: if has_schedule { "settings" } else { "plus" } }
                                                                                            span { if has_schedule { "Edit schedule" } else { "Add schedule" } }
                                                                                        }
                                                                                        if has_schedule {
                                                                                            div {
                                                                                                class: "calendar-rsvp",
                                                                                                "data-testid": "card-detail-calendar-rsvp",
                                                                                                // Answer state before the buttons: a card that only
                                                                                                // offered "send once" could never show whether the
                                                                                                // response landed, who else answered, or that the
                                                                                                // responder needs to reconfirm after a schedule change.
                                                                                                if rsvp_display.has_any() {
                                                                                                    div {
                                                                                                        class: "calendar-rsvp-status",
                                                                                                        "data-testid": "card-detail-rsvp-status",
                                                                                                        if let Some(status) = rsvp_display.own_status.clone() {
                                                                                                            span {
                                                                                                                class: "calendar-rsvp-own",
                                                                                                                "data-testid": "card-detail-rsvp-own",
                                                                                                                "You: {status}"
                                                                                                            }
                                                                                                        }
                                                                                                        if rsvp_display.own_needs_reconfirmation {
                                                                                                            span {
                                                                                                                class: "calendar-rsvp-reconfirm",
                                                                                                                "data-testid": "card-detail-rsvp-reconfirm",
                                                                                                                "Schedule changed — please reconfirm"
                                                                                                            }
                                                                                                        }
                                                                                                        span {
                                                                                                            class: "calendar-rsvp-counts",
                                                                                                            "data-testid": "card-detail-rsvp-counts",
                                                                                                            "{rsvp_display.accepted} yes · {rsvp_display.tentative} maybe · {rsvp_display.declined} no"
                                                                                                        }
                                                                                                        if rsvp_display.excluded > 0 {
                                                                                                            span {
                                                                                                                class: "calendar-rsvp-excluded",
                                                                                                                "data-testid": "card-detail-rsvp-excluded",
                                                                                                                "{rsvp_display.excluded} response(s) no longer count"
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                                Label { html_for: "card-detail-calendar-rsvp-occurrence", "Occurrence" }
                                                                                                Input {
                                                                                                    id: "card-detail-calendar-rsvp-occurrence",
                                                                                                    class: "input",
                                                                                                    "data-testid": "card-detail-calendar-rsvp-occurrence",
                                                                                                    value: "{calendar_rsvp_occurrence}",
                                                                                                    placeholder: "{occurrence_hint}",
                                                                                                    oninput: move |event: FormEvent| calendar_rsvp_occurrence.set(event.value()),
                                                                                                }
                                                                                                div { class: "calendar-rsvp-actions",
                                                                                                    Button {
                                                                                                        variant: ButtonVariant::Secondary,
                                                                                                        r#type: "button",
                                                                                                        onclick: move |_| calendar_rsvp_occurrence.set(String::new()),
                                                                                                        "Series"
                                                                                                    }
                                                                                                    Button {
                                                                                                        variant: ButtonVariant::Secondary,
                                                                                                        r#type: "button",
                                                                                                        "data-testid": "card-detail-rsvp-accepted",
                                                                                                        onclick: {
                                                                                                            let base = base_url.clone();
                                                                                                            let realm = selected_realm_id.clone();
                                                                                                            let actor = principal_id.clone();
                                                                                                            let current_card = card.clone();
                                                                                                            move |_| {
                                                                                                                dispatch_calendar_rsvp(
                                                                                                                    base.clone(),
                                                                                                                    token,
                                                                                                                    realm.clone(),
                                                                                                                    actor.clone(),
                                                                                                                    current_card.clone(),
                                                                                                                    "accepted",
                                                                                                                    calendar_rsvp_occurrence(),
                                                                                                                    state_store,
                                                                                                                    board_status,
                                                                                                                );
                                                                                                            }
                                                                                                        },
                                                                                                        "Accept"
                                                                                                    }
                                                                                                    Button {
                                                                                                        variant: ButtonVariant::Secondary,
                                                                                                        r#type: "button",
                                                                                                        "data-testid": "card-detail-rsvp-tentative",
                                                                                                        onclick: {
                                                                                                            let base = base_url.clone();
                                                                                                            let realm = selected_realm_id.clone();
                                                                                                            let actor = principal_id.clone();
                                                                                                            let current_card = card.clone();
                                                                                                            move |_| {
                                                                                                                dispatch_calendar_rsvp(
                                                                                                                    base.clone(),
                                                                                                                    token,
                                                                                                                    realm.clone(),
                                                                                                                    actor.clone(),
                                                                                                                    current_card.clone(),
                                                                                                                    "tentative",
                                                                                                                    calendar_rsvp_occurrence(),
                                                                                                                    state_store,
                                                                                                                    board_status,
                                                                                                                );
                                                                                                            }
                                                                                                        },
                                                                                                        "Maybe"
                                                                                                    }
                                                                                                    Button {
                                                                                                        variant: ButtonVariant::Secondary,
                                                                                                        r#type: "button",
                                                                                                        "data-testid": "card-detail-rsvp-declined",
                                                                                                        onclick: {
                                                                                                            let base = base_url.clone();
                                                                                                            let realm = selected_realm_id.clone();
                                                                                                            let actor = principal_id.clone();
                                                                                                            let current_card = card.clone();
                                                                                                            move |_| {
                                                                                                                dispatch_calendar_rsvp(
                                                                                                                    base.clone(),
                                                                                                                    token,
                                                                                                                    realm.clone(),
                                                                                                                    actor.clone(),
                                                                                                                    current_card.clone(),
                                                                                                                    "declined",
                                                                                                                    calendar_rsvp_occurrence(),
                                                                                                                    state_store,
                                                                                                                    board_status,
                                                                                                                );
                                                                                                            }
                                                                                                        },
                                                                                                        "Decline"
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
                                                                div {
                                                                    dt { "Discussion scope" }
                                                                    dd { "{card.external_visibility}" }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                    }
                                                    if active_sidebar_tab == CardDetailSidebarTab::Members {
                                                        if realm_member_rows.is_empty() {
                                                            div { class: "card-detail-empty", "data-testid": "card-detail-realm-members",
                                                                div { "No members yet for this Realm." }
                                                            }
                                                        }
                                                            match owned_agent_inventory_snapshot.as_ref() {
                                                                None => rsx! {
                                                                    div { class: "card-detail-empty", "data-testid": "card-detail-member-identities-pending",
                                                                        "Loading member identities…"
                                                                    }
                                                                },
                                                                Some(Err(_)) => rsx! {
                                                                    div { class: "card-detail-empty", "data-testid": "card-detail-member-identities-error",
                                                                        "Member identities are temporarily unavailable."
                                                                    }
                                                                },
                                                                Some(Ok(owned_agent_slugs)) => rsx! {
                                                                    {
                                                                        let mut members = realm_member_rows.iter()
                                                                            .filter(|row| owned_agent_slug(row, owned_agent_slugs).is_none())
                                                                            .collect::<Vec<_>>();
                                                                        members.sort_by_key(|row| !card_member_is_current_account(row, &principal_id));
                                                                        let agents = crate::operation::authoring_station_id().ok()
                                                                            .map(|station| card_owned_agent_rows(&realm_member_rows, owned_agent_slugs, &station))
                                                                            .unwrap_or_default();
                                                                        rsx! { div {
                                                                            class: "card-detail-actor-list",
                                                                            "data-testid": "card-detail-realm-members",
                                                                            for row in members {
                                                                                {
                                                                                    let member_id = row.actor_id.to_string();
                                                                                    let is_self = card_member_is_current_account(row, &principal_id);
                                                                                    let label = crate::views::member_display::resolve_member_display(
                                                                                        &state_store.read(), &realm_context, row,
                                                                                    ).label;
                                                                                    rsx! {
                                                                                        CardMemberMentionRow {
                                                                                            key: "{member_id}",
                                                                                            in_strand: participant_set.contains(&member_id),
                                                                                            member_id,
                                                                                            label,
                                                                                            is_self,
                                                                                            agent_slug: None,
                                                                                            onmention: on_member_mention,
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                            if !agents.is_empty() {
                                                                                div { class: "card-detail-agent-heading", "Your AI agents ({agents.len()})" }
                                                                                for (actor, slug, in_realm) in agents {
                                                                                    CardMemberMentionRow {
                                                                                        key: "{actor}",
                                                                                        member_id: actor.clone(),
                                                                                        label: slug.clone(),
                                                                                        agent_slug: Some(slug),
                                                                                        in_realm,
                                                                                        in_strand: in_realm && participant_set.contains(&actor),
                                                                                        onmention: on_member_mention,
                                                                                    }
                                                                                }
                                                                            }
                                                                    } }
                                                                    }
                                                                },
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

#[cfg(test)]
mod edit_identity_tests {
    use super::*;

    #[test]
    fn owned_agent_inventory_is_visible_without_claiming_realm_membership() {
        let local = arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let remote = arkret_sdk::DidCoreId::new("ak:did_core:web:remote.example").unwrap();
        let inventory = BTreeMap::from([
            (
                "ak:did_core:web:joined.example".to_owned(),
                "alpha".to_owned(),
            ),
            (
                "ak:did_core:web:absent.example".to_owned(),
                "beta".to_owned(),
            ),
            (
                "ak:did_core:web:knocking.example".to_owned(),
                "gamma".to_owned(),
            ),
            ("invalid".to_owned(), "invalid".to_owned()),
        ]);
        let actor = |principal: &str, station: &arkret_sdk::DidCoreId| {
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new(principal).unwrap(),
                station.clone(),
            ))
        };
        let projection = serde_json::json!({"member_roster_entries": [
            {"actor_id": actor("ak:did_core:web:joined.example", &local), "membership": "join"},
            {"actor_id": actor("ak:did_core:web:absent.example", &remote), "membership": "join"},
            {"actor_id": actor("ak:did_core:web:knocking.example", &local), "membership": "knock"}
        ]});
        let members = realm_member_roster(Some(&projection));
        let rows = card_owned_agent_rows(&members, &inventory, &local);
        assert_eq!(rows.len(), 3);
        assert_eq!(
            rows.iter()
                .map(|(_, slug, joined)| (slug.as_str(), *joined))
                .collect::<Vec<_>>(),
            vec![("alpha", true), ("beta", false), ("gamma", false)]
        );
        assert_eq!(
            rows[0].0,
            actor("ak:did_core:web:joined.example", &local).to_string()
        );
        assert_eq!(rows[1].0, "ak:did_core:web:absent.example");
        assert_eq!(rows[2].0, "ak:did_core:web:knocking.example");
        assert_eq!(card_owned_agent_rows(&[], &inventory, &local).len(), 3);
    }

    #[test]
    fn card_identity_reconciliation_preserves_the_draft_only_for_its_resolved_target() {
        let aliases = BTreeMap::from([
            ("pending-card".to_owned(), "submitted-card".to_owned()),
            ("submitted-card".to_owned(), "accepted-strand".to_owned()),
        ]);
        assert!(canonicalized_edit_target(
            "pending-card",
            "accepted-strand",
            &aliases
        ));
        assert!(!canonicalized_edit_target(
            "pending-card",
            "other-strand",
            &aliases
        ));
        assert!(!canonicalized_edit_target("", "accepted-strand", &aliases));
        assert!(!canonicalized_edit_target(
            "unknown-card",
            "accepted-strand",
            &aliases
        ));
    }
}
