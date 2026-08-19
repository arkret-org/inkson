use arkret_wire::{AccountDataKey, CapabilityActionId};

use super::*;

thread_local! {
    static CHAT_FEED_SCROLL_OFFSETS: std::cell::RefCell<
        std::collections::BTreeMap<String, f64>,
    > = const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
}

pub(super) fn chat_feed_scroll_offset(key: &str) -> f64 {
    CHAT_FEED_SCROLL_OFFSETS.with(|offsets| offsets.borrow().get(key).copied().unwrap_or_default())
}

fn preserve_chat_feed_scroll_offset(key: &str, scroll_top: f64) {
    CHAT_FEED_SCROLL_OFFSETS.with(|offsets| {
        let mut offsets = offsets.borrow_mut();
        // A newly mounted browser element emits a synthetic zero before the
        // saved offset can be restored. Do not let that erase a real position.
        if scroll_top > 0.0 || !offsets.contains_key(key) {
            offsets.insert(key.to_owned(), scroll_top);
        }
    });
}

#[derive(Clone, PartialEq)]
pub(super) struct ChatTimelineContext {
    pub embedded: bool,
    pub visible_messages: Vec<ChatMessage>,
    pub visible_moderation_appeal_prompts: Vec<ModerationAppealPrompt>,
    pub strand_scope_lookup: std::collections::BTreeMap<String, StrandScopeCircle>,
    pub private_sidecar_strand_ids: std::collections::BTreeSet<String>,
    pub account_did: String,
    pub account_display_label: String,
    pub participants: Vec<SpaceParticipant>,
    pub selected_realm_id: String,
    pub selected_channel_id: String,
    pub sidecar_active: bool,
    pub device_id: String,
    pub plaintext_service_id: String,
    pub base_url: String,
    pub focus_message_id: String,
    pub blocked_dids: std::collections::BTreeSet<String>,
    pub selected_channel_security_encrypted: bool,
    pub visible_channels_empty: bool,
    pub visible_message_count: usize,
    pub loading: bool,
    pub token: Signal<String>,
    pub sync_cursor: Signal<String>,
    pub frontier_state: Signal<String>,
}

#[component]
pub(super) fn ChatTimeline(controller: ChatController, context: ChatTimelineContext) -> Element {
    let ChatTimelineContext {
        embedded,
        visible_messages,
        visible_moderation_appeal_prompts,
        strand_scope_lookup,
        private_sidecar_strand_ids,
        account_did,
        account_display_label,
        participants: participants_for_messages,
        selected_realm_id,
        selected_channel_id: selected_channel_value,
        sidecar_active,
        device_id,
        plaintext_service_id,
        base_url,
        focus_message_id,
        blocked_dids: blocked_did_set,
        selected_channel_security_encrypted,
        visible_channels_empty,
        visible_message_count,
        loading: discussion_feed_loading,
        token,
        sync_cursor,
        frontier_state,
    } = context;
    let scroll_offset_key = format!("{selected_realm_id}\u{1f}{selected_channel_value}");
    let scroll_offset_key_for_event = scroll_offset_key.clone();
    let state_store = crate::app::SessionContext::get().state_store;
    let command_context = ChatCommandContext {
        base_url: base_url.clone(),
        account_did: account_did.clone(),
        device_id: device_id.clone(),
        selected_realm_id: selected_realm_id.clone(),
        selected_channel_id: selected_channel_value.clone(),
        plaintext_service_id: plaintext_service_id.clone(),
        selected_channel_security_encrypted,
        token,
        sync_cursor,
        frontier_state,
    };
    // The parent folds durable lifecycle controls onto optimistic controller
    // rows before filtering this snapshot. Reading controller.messages here
    // would discard remote reactions/revisions that arrived before the
    // sender's canonical create was persisted locally.
    let all_messages_snapshot = (controller.messages)();
    let messages_for_reply_lookup = &all_messages_snapshot;
    let message_stream_cards = crate::views::message_streams::MessageStreamHub::try_use()
        .map(|hub| hub.visible_for(&selected_realm_id, &selected_channel_value))
        .unwrap_or_default();
    let pinned_target_set: std::collections::HashSet<String> = (controller.shared_pins)()
        .iter()
        .map(|pin| pin.target_ref.clone())
        .collect();
    let queued_outbound_local_operation_ids = (controller.queued_outbound_local_operation_ids)();
    let private_saved_target_set = (controller.private_saved_targets)();
    let ChatController {
        messages: _,
        shared_pins,
        private_saved_targets,
        private_saved_account_data: _,
        message_context_menu,
        moderation_report_draft,
        moderation_report_pending,
        status_msg: _,
        editing_message,
        edit_draft,
        redact_confirm,
        reaction_picker,
        poll_cards,
        promote_discussion_draft: _,
        promoted_targets,
        blocked_show_anyway,
        ..
    } = controller;

    rsx! {
                div { class: "discussion-chat-feed", "data-testid": "message-list",
                    onscroll: move |event: ScrollEvent| {
                        preserve_chat_feed_scroll_offset(
                            &scroll_offset_key_for_event,
                            event.data().scroll_top(),
                        );
                    },
                    onmounted: move |event: MountedEvent| {
                        let scroll_offset_key = scroll_offset_key.clone();
                        async move {
                            let scroll_top = chat_feed_scroll_offset(&scroll_offset_key);
                            if scroll_top > 0.0 {
                                let _ = event
                                    .scroll(
                                        dioxus::html::geometry::PixelsVector2D::new(0.0, scroll_top),
                                        ScrollBehavior::Instant,
                                    )
                                    .await;
                            }
                        }
                    },
                    for prompt in visible_moderation_appeal_prompts {
                        {
                            let current_state = prompt.state.clone();
                            let api_token = token();
                            rsx! {
                                AppealEntrypoint {
                                    key: "{prompt.decision_ref}",
                                    realm_id: prompt.realm_id.clone(),
                                    appellant: account_did.clone(),
                                    decision_event_id: prompt.decision_ref.clone(),
                                    target_ref: prompt.target_ref.clone(),
                                    api_token,
                                    current_state,
                                }
                            }
                        }
                    }
                    for preview in message_stream_cards {
                        div {
                            key: "{preview.message_id}",
                            class: if preview.stalled {
                                "chat-message message-stream-preview is-stalled"
                            } else {
                                "chat-message message-stream-preview"
                            },
                            "data-testid": "message-stream-preview",
                            "data-message-id": "{preview.message_id}",
                            "data-stream-state": if preview.stalled { "stalled" } else { "active" },
                            div { class: "message-meta",
                                span { class: "message-sender", "{preview.sender_actor_id}" }
                                span { class: "message-stream-badge", "Generating…" }
                            }
                            div { class: "msg-body",
                                if preview.text.is_empty() {
                                    span { class: "message-stream-waiting", "…" }
                                } else {
                                    "{preview.text}"
                                }
                                if preview.truncated {
                                    span {
                                        class: "message-stream-truncated",
                                        " Preview truncated; waiting for final message."
                                    }
                                }
                                if preview.stalled {
                                    span {
                                        class: "message-stream-stalled",
                                        " Generation paused; waiting for an update."
                                    }
                                }
                            }
                        }
                    }
                    for msg in visible_messages {
                        {
                            let message_is_private_sidecar =
                                private_sidecar_strand_ids.contains(&msg.strand_id);
                            let message_is_read_only_shared =
                                sidecar_active && !message_is_private_sidecar;
                            let scope_circle = (!message_is_private_sidecar)
                                .then(|| strand_scope_lookup.get(&msg.strand_id).cloned())
                                .flatten();
                            let scope_class = if scope_circle.is_some() {
                                " has-circle-accent-rail"
                            } else {
                                ""
                            };
                            let scope_attr = scope_circle
                                .as_ref()
                                .map(|c| c.circle_id.clone())
                                .unwrap_or_default();
                            let message_target_ref = msg.pin_saved_target_ref().to_owned();
                            // O(1) lookup into the prebuilt set, semantically
                            // equivalent to the original `.iter().any(...)`: a pin
                            // matches when target_ref equals the message target_ref or message id.
                            let message_is_pinned = pinned_target_set.contains(&message_target_ref)
                                || pinned_target_set.contains(&msg.id);
                            let message_is_saved_private =
                                private_saved_target_set.contains(&message_target_ref);
                            // The queue answers with holder-local ids, which the
                            // optimistic row carries as its own id until an
                            // accepted Event renames it.
                            let message_is_queued_offline = queued_outbound_local_operation_ids
                                .iter()
                                .any(|local_id| msg.matches_id_or_protocol(local_id));
                            let sender_is_own =
                                is_own_message_sender(&msg.sender, &account_did);
                            // Deep-link focus target (design/route-view-ia.md §3.2).
                            let is_focus_message =
                                !focus_message_id.is_empty() && msg.id == focus_message_id;
                            // Shared per-message dispatchers keep the overflow-button
                            // and context-click paths on the same action set.
                            // Signals are `Copy`, so each closure re-shadows the ones
                            // it mutates as a local `mut` copy to stay a plain `Fn`.
                            let reply_action: std::rc::Rc<dyn Fn()> = std::rc::Rc::new({
                                let reply_target =
                                    msg.reply_target_ref().map(ToOwned::to_owned);
                                move || {
                                    if let Some(target) = reply_target.clone() {
                                        controller.begin_reply(target);
                                    }
                                }
                            });
                            let react_action: std::rc::Rc<dyn Fn()> = std::rc::Rc::new({
                                let msg_id = msg.id.clone();
                                move || controller.toggle_reaction_picker(msg_id.clone())
                            });
                            let edit_action: std::rc::Rc<dyn Fn()> = std::rc::Rc::new({
                                let msg_id = msg.id.clone();
                                let body = msg.body.clone();
                                move || {
                                    controller.begin_edit(msg_id.clone(), body.clone());
                                }
                            });
                            let redact_action: std::rc::Rc<dyn Fn()> = std::rc::Rc::new({
                                let msg_id = msg.id.clone();
                                move || controller.confirm_redaction(msg_id.clone())
                            });
                            // Holder-private save is shared by every way the
                            // message action menu can be opened.
                            let private_save_action: std::rc::Rc<dyn Fn()> = std::rc::Rc::new({
                                let context = command_context.clone();
                                let target_ref = message_target_ref.clone();
                                move || controller.save_message_private(context.clone(), target_ref.clone())
                            });
                            let report_scope = arkret_sdk::RealmId::new(msg.realm_id.clone())
                                .ok()
                                .and_then(|realm_id| match scope_circle.as_ref() {
                                    Some(circle) => arkret_sdk::CircleId::new(circle.circle_id.clone())
                                        .ok()
                                        .map(|circle_id| arkret_sdk::ScopeRef::Circle {
                                            realm_id,
                                            circle_id,
                                        }),
                                    None => Some(arkret_sdk::ScopeRef::Realm { realm_id }),
                                });
                            let message_menu_is_open =
                                message_context_menu().as_deref() == Some(msg.id.as_str());
                            let message_menu_id = format!("message-actions-{}", msg.id);
                            rsx! {
                        div {
                            key: "{msg.id}",
                            id: "chat-msg-{msg.id}",
                            class: {
                                let mut base = if sender_is_own {
                                    if msg.failed { "discussion-message is-own is-failed".to_owned() } else { "discussion-message is-own".to_owned() }
                                } else if msg.failed {
                                    "discussion-message is-failed".to_owned()
                                } else {
                                    "discussion-message".to_owned()
                                };
                                // T7.4: grey out and italicise messages
                                // that are still waiting on key material.
                                if msg.crypto_state.is_pending() {
                                    base.push_str(" is-crypto-pending");
                                }
                                if message_is_pinned {
                                    base.push_str(" is-pinned");
                                }
                                if is_focus_message {
                                    base.push_str(" is-highlighted");
                                }
                                if message_is_private_sidecar {
                                    base.push_str(" is-private-sidecar");
                                }
                                base.push_str(scope_class);
                                base
                            },
                            // Deep-linked message swaps its testid so the e2e
                            // harness can assert the scroll/highlight landed.
                            "data-testid": if is_focus_message { "chat-highlighted-message" } else { "chat-message" },
                            onmounted: move |event: MountedEvent| async move {
                                if is_focus_message {
                                    // Scroll the deep-linked message into view once it
                                    // mounts; harmless no-op if already visible.
                                    let _ = event.scroll_to(ScrollBehavior::Smooth).await;
                                }
                            },
                            "data-circle-scope-id": "{scope_attr}",
                            "data-sidecar-provenance": if message_is_private_sidecar {
                                "private"
                            } else if sidecar_active {
                                "shared-read-only"
                            } else {
                                "shared"
                            },
                            "data-crypto-state": match msg.crypto_state {
                                MessageCryptoState::Plaintext => "plaintext",
                                MessageCryptoState::Decrypting => "decrypting",
                                MessageCryptoState::KeyMissing => "key_missing",
                                MessageCryptoState::NeedsVerification => "needs_verification",
                                MessageCryptoState::LateRecoveryRejected => "late_recovery_rejected",
                            },
                            // Right-click toggles a context menu with separate
                            // shared pin and holder-private saved actions.
                            // prevent_default suppresses the browser's
                            // native context menu so ours surfaces alone.
                            oncontextmenu: {
                                let msg_id = msg.id.clone();
                                move |evt| {
                                    evt.prevent_default();
                                    controller.toggle_message_menu(msg_id.clone());
                                }
                            },
                            // AKP-0007 P3B.2.4 — Circle scope accent
                            // rail. Renders a left-edge coloured ribbon
                            // with the Circle title as a tooltip when
                            // the message's enclosing Strand has a
                            // `scope_circle_id`. The CSS class
                            // `has-circle-accent-rail` on the outer
                            // message div positions the ribbon at the
                            // left margin.
                            if let Some(circle) = scope_circle.as_ref() {
                                div {
                                    class: "circle-accent-rail",
                                    "data-testid": "circle-accent-rail",
                                    "data-circle-id": "{circle.circle_id}",
                                    title: "Circle scope · {circle.title}",
                                    "aria-label": "This message is part of the Circle named {circle.title}",
                                }
                            }
                            // Shared pins and holder-private saved items remain
                            // distinct operations inside the same compact menu.
                            if message_menu_is_open {
                                div {
                                    class: "message-context-menu-scrim",
                                    "aria-hidden": "true",
                                    onclick: move |_| controller.close_message_menu(),
                                }
                                div {
                                    id: "{message_menu_id}",
                                    class: "message-context-menu",
                                    "data-testid": "message-context-menu",
                                    role: "menu",
                                    "aria-label": crate::i18n::tr("message.actions"),
                                    onkeydown: move |event: KeyboardEvent| {
                                        if event.key().to_string() == "Escape" {
                                            controller.close_message_menu();
                                        }
                                    },
                                    {
                                        let target_ref = msg.pin_saved_target_ref().to_owned();
                                        let is_pinned = shared_pins()
                                            .iter()
                                            .any(|pin| pin.target_ref == target_ref || pin.target_ref == msg.id);
                                        let is_saved_private =
                                            private_saved_targets().contains(&target_ref);
                                        let realm_for_pin = msg.realm_id.clone();
                                        let strand_for_pin = msg.strand_id.clone();
                                        let target_for_pin = target_ref.clone();
                                        rsx! {
                                            if !msg.redacted && !message_is_read_only_shared {
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    r#type: "button",
                                                    class: "message-context-menu-item",
                                                    role: "menuitem",
                                                    "data-testid": "message-context-reply-button",
                                                    disabled: msg.reply_target_ref().is_none(),
                                                    onclick: {
                                                        let reply_action = reply_action.clone();
                                                        move |_| {
                                                            (*reply_action)();
                                                            controller.close_message_menu();
                                                        }
                                                    },
                                                    {crate::i18n::tr("chat.button.reply")}
                                                }
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    r#type: "button",
                                                    class: "message-context-menu-item",
                                                    role: "menuitem",
                                                    "data-testid": "message-context-react-button",
                                                    onclick: {
                                                        let react_action = react_action.clone();
                                                        move |_| {
                                                            (*react_action)();
                                                            controller.close_message_menu();
                                                        }
                                                    },
                                                    {crate::i18n::tr("chat.button.react")}
                                                }
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    r#type: "button",
                                                    class: "message-context-menu-item",
                                                    role: "menuitem",
                                                    "data-testid": "message-context-edit-button",
                                                    onclick: {
                                                        let edit_action = edit_action.clone();
                                                        move |_| {
                                                            (*edit_action)();
                                                            controller.close_message_menu();
                                                        }
                                                    },
                                                    {crate::i18n::tr("common.edit")}
                                                }
                                            }
                                            if !message_is_read_only_shared {
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                r#type: "button",
                                                class: "message-context-menu-item",
                                                role: "menuitem",
                                                "data-testid": "message-shared-pin-button",
                                                "data-source": "shared-event",
                                                "data-permission": if is_pinned {
                                                    CapabilityActionId::PIN_REMOVE
                                                } else {
                                                    CapabilityActionId::PIN_ADD
                                                },
                                                onclick: {
                                                    let context = command_context.clone();
                                                    let realm_id = realm_for_pin.clone();
                                                    let strand_id = strand_for_pin.clone();
                                                    let target_ref = target_for_pin.clone();
                                                    move |_| controller.toggle_shared_pin(
                                                        context.clone(),
                                                        realm_id.clone(),
                                                        strand_id.clone(),
                                                        target_ref.clone(),
                                                    )
                                                },
                                                if is_pinned {
                                                    {crate::i18n::tr("message.shared_unpin")}
                                                } else {
                                                    {crate::i18n::tr("message.shared_pin")}
                                                }
                                            }
                                            }
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                r#type: "button",
                                                class: "message-context-menu-item",
                                                role: "menuitem",
                                                disabled: is_saved_private,
                                                "data-testid": "message-private-save-button",
                                                "data-source": "private-account-data",
                                                "data-account-data-prefix": AccountDataKey::SAVED_V1,
                                                onclick: {
                                                    let private_save_action = private_save_action.clone();
                                                    move |_| (*private_save_action)()
                                                },
                                                if is_saved_private {
                                                    {crate::i18n::tr("message.private_saved")}
                                                } else {
                                                    {crate::i18n::tr("message.private_save")}
                                                }
                                            }
                                            if !msg.redacted && !message_is_private_sidecar {
                                                Button {
                                                    variant: ButtonVariant::Destructive,
                                                    r#type: "button",
                                                    class: "message-context-menu-item danger",
                                                    role: "menuitem",
                                                    "data-testid": "message-context-report-button",
                                                    disabled: report_scope.is_none(),
                                                    onclick: {
                                                        let realm_id = msg.realm_id.clone();
                                                        let target_ref = message_target_ref.clone();
                                                        let effective_scope = report_scope.clone();
                                                        move |_| {
                                                            if let Some(effective_scope) = effective_scope.clone() {
                                                                controller.begin_moderation_report(
                                                                    realm_id.clone(),
                                                                    effective_scope,
                                                                    target_ref.clone(),
                                                                );
                                                            }
                                                        }
                                                    },
                                                    {crate::i18n::tr("moderation.report.action")}
                                                }
                                            }
                                            if !msg.redacted && !message_is_read_only_shared {
                                                Button {
                                                    variant: ButtonVariant::Destructive,
                                                    r#type: "button",
                                                    class: "message-context-menu-item danger",
                                                    role: "menuitem",
                                                    "data-testid": "message-context-redact-button",
                                                    onclick: {
                                                        let redact_action = redact_action.clone();
                                                        move |_| {
                                                            (*redact_action)();
                                                            controller.close_message_menu();
                                                        }
                                                    },
                                                    {crate::i18n::tr("chat.button.redact")}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            div { class: "msg-body",
                                if message_is_pinned {
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        r#type: "button",
                                        class: "message-pin-indicator",
                                        "data-testid": "message-pinned-button",
                                        "data-source": "shared-event",
                                        "data-target-ref": "{message_target_ref}",
                                        "aria-label": crate::i18n::tr("message.shared_pin"),
                                        title: crate::i18n::tr("message.shared_pin"),
                                        onclick: {
                                            let msg_id = msg.id.clone();
                                            move |_| {
                                                controller.toggle_message_menu(msg_id.clone());
                                            }
                                        },
                                        UiIcon { name: "pin" }
                                    }
                                }
                                if message_is_saved_private {
                                    span {
                                        class: "message-private-saved-indicator",
                                        "data-testid": "message-private-saved-indicator",
                                        "data-source": "private-account-data",
                                        "data-account-data-prefix": AccountDataKey::SAVED_V1,
                                        "data-target-ref": "{message_target_ref}",
                                        title: crate::i18n::tr("message.private_saved"),
                                        UiIcon { name: "check" }
                                    }
                                }
                                div { class: "msg-head",
                                    span { class: "name", "{sender_display_label(&msg.sender, &account_did, &account_display_label, &participants_for_messages)}" }
                                    if sender_is_own {
                                        SelfAttributionBadge {
                                            class: Some("message-self-badge".to_owned()),
                                            test_id: Some("message-self-badge".to_owned()),
                                        }
                                    }
                                    {
                                        let sender_participant = participants_for_messages
                                            .iter()
                                            .find(|p| p.did == msg.sender);
                                        let sender_is_agent = sender_participant
                                            .map(|participant| participant.is_agent)
                                            .unwrap_or(false);
                                        let sender_agent_owner = sender_participant
                                            .and_then(|participant| {
                                                agent_controller_label(
                                                    participant,
                                                    &participants_for_messages,
                                                )
                                            });
                                        // AKP-0008 §4.10 — act-on-behalf: the
                                        // controller (actor_id = msg.sender) is
                                        // the primary name, the agent executor
                                        // (executed_by) renders as "via {agent}".
                                        let act_on_behalf_agent = act_on_behalf_agent_label(
                                            &msg.sender,
                                            msg.executed_by.as_deref(),
                                            &participants_for_messages,
                                        );
                                        rsx! {
                                            if sender_is_agent {
                                                span {
                                                    class: "badge member-badge member-badge-agent",
                                                    "data-testid": "member-badge-agent",
                                                    title: "Automated member (bot)",
                                                    "\u{1f916} "
                                                    {crate::i18n::tr("member.badge.agent")}
                                                }
                                            }
                                            if let Some(owner_label) = sender_agent_owner {
                                                span {
                                                    class: "agent-owner-label",
                                                    "data-testid": "message-agent-owner",
                                                    "agent of {owner_label}"
                                                }
                                            }
                                            if let Some(agent_label) = act_on_behalf_agent {
                                                span {
                                                    class: "agent-via-label",
                                                    "data-testid": "message-act-on-behalf-via",
                                                    "data-executed-by": msg.executed_by.clone().unwrap_or_default(),
                                                    "via {agent_label}"
                                                }
                                            }
                                            if message_is_private_sidecar {
                                                span {
                                                    class: "message-privacy-badge message-privacy-badge--sidecar",
                                                    "data-testid": "message-private-sidecar-badge",
                                                    "data-visibility": "private-sidecar",
                                                    role: "img",
                                                    title: crate::i18n::tr("chat.message.private_sidecar.tooltip"),
                                                    "aria-label": crate::i18n::tr("chat.message.private_sidecar.tooltip"),
                                                    UiIcon { name: "lock" }
                                                    span { {crate::i18n::tr("chat.message.private_sidecar.label")} }
                                                }
                                            } else if sidecar_active {
                                                span {
                                                    class: "message-provenance-badge message-provenance-badge--shared",
                                                    "data-testid": "message-shared-read-only-badge",
                                                    "data-provenance": "shared",
                                                    title: "Original Strand · read only while Private Sidecar is active",
                                                    "aria-label": "Original Strand message, read only while Private Sidecar is active",
                                                    UiIcon { name: "lock" }
                                                    span { "Original Strand · read only" }
                                                }
                                            }
                                        }
                                    }
                                    time { "{msg.timestamp}" }
                                    if sender_is_own && msg.failed {
                                        span {
                                            class: "message-status-icon is-failed",
                                            "data-testid": "message-send-status",
                                            title: "Message send failed",
                                            "!"
                                        }
                                    } else if sender_is_own
                                        && msg.pending
                                        && message_is_queued_offline
                                    {
                                        // Parked in the offline outbox: distinct
                                        // from the in-flight "Sending" spinner so
                                        // the user (and E2E) can tell a message is
                                        // waiting for connectivity, not the server.
                                        span {
                                            class: "message-status-icon is-queued-offline",
                                            "data-testid": "message-send-status",
                                            "data-send-state": "queued_offline",
                                            title: crate::i18n::tr("chat.outbox.queued_offline"),
                                            "\u{23f8}"
                                        }
                                    } else if sender_is_own && msg.pending {
                                        span {
                                            class: "message-status-icon is-pending",
                                            "data-testid": "message-send-status",
                                            "data-send-state": "sending",
                                            title: "Sending"
                                        }
                                    }
                                    if msg.edited {
                                        span {
                                            class: "badge",
                                            "data-testid": "message-write-status",
                                            "data-revision-count": "{msg.revisions.len()}",
                                            title: crate::i18n::tr("chat.message.write_status"),
                                            {
                                                format!(
                                                    "{} ({})",
                                                    crate::i18n::tr("chat.message.revised"),
                                                    msg.revisions.len(),
                                                )
                                            }
                                        }
                                    }
                                }
                                // T7.4: per-message crypto status row.
                                // Sits directly under the head so the
                                // icon + label appear before the body
                                // when it's awaiting decrypt.
                                {
                                    match msg.crypto_state {
                                        MessageCryptoState::Plaintext => rsx! { },
                                        MessageCryptoState::Decrypting => rsx! {
                                            div {
                                                class: "crypto-status-row crypto-status-decrypting",
                                                "data-testid": "crypto-status-decrypting",
                                                span { class: "crypto-status-icon", "\u{23f3}" }
                                                span { {crate::i18n::tr("chat.crypto.decrypting")} }
                                            }
                                        },
                                        MessageCryptoState::KeyMissing => rsx! {
                                            div {
                                                class: "crypto-status-row crypto-status-key-missing",
                                                "data-testid": "crypto-status-key-missing",
                                                span { class: "crypto-status-icon", "\u{1f511}" }
                                                span { {crate::i18n::tr("chat.crypto.key_missing")} }
                                                span { class: "muted", {crate::i18n::tr("chat.crypto.key_missing_hint")} }
                                            }
                                        },
                                        MessageCryptoState::NeedsVerification => rsx! {
                                            div {
                                                class: "crypto-status-row crypto-status-needs-verification",
                                                "data-testid": "crypto-status-needs-verification",
                                                span { class: "crypto-status-icon", "\u{26a0}" }
                                                span { {crate::i18n::tr("chat.crypto.needs_verification")} }
                                            }
                                        },
                                        MessageCryptoState::LateRecoveryRejected => {
                                            // T6: map the raw protocol reason code to a
                                            // human-readable explanation. All known
                                            // `late_recovery_*` reason codes share the
                                            // late-recovery copy; anything else falls back
                                            // to a generic undecryptable message. The raw
                                            // code stays available in the tooltip for
                                            // debugging/support.
                                            let raw_code = msg
                                                .error
                                                .as_deref()
                                                .unwrap_or("late_recovery_rejected")
                                                .to_owned();
                                            let friendly = if raw_code.starts_with("late_recovery") {
                                                crate::i18n::tr("chat.crypto.late_recovery_rejected")
                                            } else {
                                                crate::i18n::tr("chat.crypto.undecryptable_generic")
                                            };
                                            rsx! {
                                                div {
                                                    class: "crypto-status-row crypto-status-late-recovery-rejected",
                                                    "data-testid": "crypto-status-late-recovery-rejected",
                                                    title: "{raw_code}",
                                                    span { class: "crypto-status-icon", "\u{26a0}" }
                                                    span { {friendly} }
                                                }
                                            }
                                        },
                                    }
                                }
                                if let Some(reply_id) = msg.reply_to.as_ref() {
                                    if let Some((quoted_name, quoted_body)) = chat_reply_quote_preview(
                                        messages_for_reply_lookup,
                                        reply_id,
                                        &account_did,
                                        &account_display_label,
                                        &participants_for_messages,
                                    ) {
                                        div { class: "chat-reply-quote", "data-testid": "chat-reply-indicator",
                                            span { class: "chat-reply-quote-name", "{quoted_name}" }
                                            div { class: "chat-reply-quote-body", "{quoted_body}" }
                                        }
                                    } else {
                                        div { class: "chat-reply-quote chat-reply-quote-missing", "data-testid": "chat-reply-indicator",
                                            "Replying to a message"
                                        }
                                    }
                                }
                                {
                                    let sender_blocked = blocked_did_set.contains(&msg.sender)
                                        && !blocked_show_anyway.read().contains(&msg.id);
                                    let content_kind = if msg.redacted {
                                        "msg-content redacted"
                                    } else if sender_blocked {
                                        "msg-content muted"
                                    } else {
                                        "msg-content"
                                    };
                                    let content_test_id = if msg.redacted {
                                        "chat-redacted-tombstone"
                                    } else if sender_blocked {
                                        "message-blocked-row"
                                    } else {
                                        "event-body"
                                    };
                                    rsx! {
                                        // Keep one stable content node across lifecycle folds.
                                        // Replacing the entire conditional node could leave the
                                        // live body mounted when a remote redaction arrived.
                                        div {
                                            class: "{content_kind}",
                                            "data-testid": "{content_test_id}",
                                            if msg.redacted {
                                                "[Message redacted]"
                                            } else if sender_blocked {
                                                {crate::i18n::tr("message.blocked_user")}
                                            } else {
                                                {render_message_body(&msg.body, &msg.mentions, &base_url)}
                                            }
                                        }
                                    }
                                }
                                if !msg.redacted
                                    && blocked_did_set.contains(&msg.sender)
                                    && !blocked_show_anyway.read().contains(&msg.id)
                                {
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "message-blocked-show-anyway",
                                        onclick: {
                                            let eid = msg.id.clone();
                                            move |_| controller.show_blocked_message(eid.clone())
                                        },
                                        {crate::i18n::tr("message.show_anyway")}
                                    }
                                }
                                // Keep a stable keyed-row child for reaction-only
                                // async updates. Dioxus can otherwise retain the
                                // already-mounted message body while skipping
                                // insertion of this formerly-absent conditional
                                // node when a remote reaction arrives.
                                div {
                                    class: "actions chat-chip-row",
                                    "data-testid": "chat-reactions",
                                    hidden: msg.reactions.is_empty(),
                                    for (emoji, senders) in &msg.reactions {
                                        span { class: "badge", "{emoji} {senders.len()}" }
                                    }
                                }
                                if msg.failed && !message_is_read_only_shared {
                                    div { class: "message-error-row", "data-testid": "chat-message-error",
                                        span { class: "message-error-mark", "!" }
                                        span {
                                            if let Some(error) = &msg.error {
                                                "{error}"
                                            } else {
                                                "Message send failed"
                                            }
                                        }
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            class: "message-retry-button",
                                            "data-testid": "chat-retry-button",
                                            onclick: {
                                                let context = command_context.clone();
                                                let message = msg.clone();
                                                move |_| controller.retry_message(
                                                    context.clone(),
                                                    message.clone(),
                                                )
                                            },
                                            {crate::i18n::tr("common.retry")}
                                        }
                                    }
                                }
                                if !msg.redacted {
                                    div {
                                        class: if message_menu_is_open {
                                            "chat-message-actions is-open"
                                        } else {
                                            "chat-message-actions"
                                        },
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            r#type: "button",
                                            class: "chat-message-menu-button",
                                            "data-testid": "chat-message-menu-button",
                                            title: crate::i18n::tr("message.actions"),
                                            "aria-label": crate::i18n::tr("message.actions"),
                                            "aria-haspopup": "menu",
                                            "aria-controls": "{message_menu_id}",
                                            "aria-expanded": if message_menu_is_open { "true" } else { "false" },
                                            onclick: {
                                                let msg_id = msg.id.clone();
                                                move |_| controller.toggle_message_menu(msg_id.clone())
                                            },
                                            onkeydown: move |event: KeyboardEvent| {
                                                if event.key().to_string() == "Escape" {
                                                    controller.close_message_menu();
                                                }
                                            },
                                            UiIcon { name: "more-horizontal" }
                                        }
                                    }
                                }
                                // Per-message read-receipt indicator: the actors
                                // whose latest `ak.receipt.read` Signal lands on
                                // this message (`read-receipts.md` §2.4 — the
                                // shared hint, not this actor's own private
                                // `ak.read_cursor.advance`). The projection is
                                // memory-only and fed by the encrypted Signal
                                // receive path, so a reader appears only after
                                // their device proof and the MLS AEAD verified.
                                {
                                    let readers: Vec<String> = msg
                                        .protocol_message_id
                                        .as_deref()
                                        .map(str::trim)
                                        .filter(|value| !value.is_empty())
                                        .and_then(|message_id| {
                                            let hub =
                                                crate::views::read_receipts::ReadReceiptHub::try_use()?;
                                            Some(hub.readers_of(
                                                &selected_realm_id,
                                                &selected_channel_value,
                                                message_id,
                                            ))
                                        })
                                        .unwrap_or_default();
                                    let should_display = {
                                        let store = state_store.read();
                                        chat_visible_read_receipt_should_display(
                                            &store,
                                            &selected_channel_value,
                                            &selected_realm_id,
                                        )
                                    };
                                    if should_display && !readers.is_empty() {
                                        let attr = readers.join(",");
                                        rsx! {
                                            div {
                                                class: "read-receipt-indicator",
                                                "data-testid": "read-receipt-indicator",
                                                "data-readers": "{attr}",
                                                for did in &readers {
                                                    crate::components::IdentityAvatar {
                                                        seed: did.clone(),
                                                        alt_text: did.clone(),
                                                        class: "read-receipt-avatar avatar-img".to_owned(),
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        rsx! {}
                                    }
                                }
                                // G3.Y2 — poll card. If this message
                                // carries a poll payload (currently
                                // matched by a poll_card entry whose
                                // message_id == msg.id), render the
                                // poll surface inline. The poll
                                // composer in the attachment menu
                                // pushes a new PollCard here on send.
                                {
                                    let card_lookup = poll_cards()
                                        .iter()
                                        .find(|card| card.message_id == msg.id)
                                        .cloned();
                                    match card_lookup {
                                        Some(card) => {
                                            let poll_id = card.poll_id.clone();
                                            let total = card.total_votes();
                                            let voted = card.actor_has_voted(&account_did);
                                            rsx! {
                                                div {
                                                    class: "poll-card message-event-poll",
                                                    "data-testid": "poll-card",
                                                    "data-poll-id": "{poll_id}",
                                                    div {
                                                        class: "poll-question",
                                                        "data-testid": "poll-question-text",
                                                        "{card.question}"
                                                    }
                                                    div {
                                                        class: "poll-state",
                                                        "data-testid": "poll-state",
                                                        if card.closed { "closed" } else { "open" }
                                                    }
                                                    for (idx, option) in card.options.iter().enumerate() {
                                                        {
                                                            let votes_for = card.votes_for(idx);
                                                            let option_index_attr = idx as i64;
                                                            let option_label = option.label.clone();
                                                            let option_id = option.id.clone();
                                                            let card_poll_id = poll_id.clone();
                                                            let card_message_id = card.message_id.clone();
                                                            let card_closed = card.closed;
                                                            rsx! {
                                                                div {
                                                                    class: "poll-result-row",
                                                                    "data-testid": "poll-result-row",
                                                                    "data-option-index": "{option_index_attr}",
                                                                    "data-option-text": "{option_label}",
                                                                    if !card_closed && !message_is_read_only_shared {
                                                                        Button {
                                                                            variant: ButtonVariant::Secondary,
                                                                            class: "poll-option poll-vote-button",
                                                                            "data-testid": "poll-option",
                                                                            disabled: card_closed,
                                                                            onclick: {
                                                                                let context = command_context.clone();
                                                                                let message_id = card_message_id.clone();
                                                                                let poll_ref = card_poll_id.clone();
                                                                                let option_id = option_id.clone();
                                                                                move |_| controller.vote_poll(
                                                                                    context.clone(),
                                                                                    message_id.clone(),
                                                                                    poll_ref.clone(),
                                                                                    option_id.clone(),
                                                                                    idx,
                                                                                )
                                                                            },
                                                                            "{option_label}"
                                                                        }
                                                                    } else {
                                                                        span {
                                                                            class: "poll-option-label",
                                                                            "{option_label}"
                                                                        }
                                                                    }
                                                                    span {
                                                                        class: "poll-vote-count",
                                                                        "data-testid": "poll-vote-count",
                                                                        "{votes_for}"
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                    if !card.closed && !message_is_read_only_shared {
                                                        Button {
                                                            variant: ButtonVariant::Secondary,
                                                            r#type: "button",
                                                            class: "poll-close-button",
                                                            "data-testid": "poll-close-button",
                                                            onclick: {
                                                                let card_message_id = card.message_id.clone();
                                                                move |_| controller.close_poll(card_message_id.clone())
                                                            },
                                                            "Close poll"
                                                        }
                                                    }
                                                    div {
                                                        class: "poll-total",
                                                        "data-testid": "poll-total-votes",
                                                        "{total} votes"
                                                    }
                                                    if voted {
                                                        div {
                                                            class: "poll-results-summary",
                                                            "data-testid": "poll-results-summary",
                                                            "Thanks for voting."
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        None => rsx! {},
                                    }
                                }
                                // G3.Y2 — discussion-promoted indicator.
                                // Lights up after a successful promote
                                // round-trip; the target is the private
                                // Circle-scoped discussion Strand.
                                {
                                    // After a successful promote, the
                                    // resulting private discussion Strand id lives in
                                    // `promoted_targets` keyed by the
                                    // source message id; we render an
                                    // seal row so the parent discussion
                                    // shows the divergence point.
                                    let promoted_to = promoted_targets()
                                        .get(&msg.id)
                                        .cloned();
                                    match promoted_to {
                                        Some(discussion_strand_id) => {
                                            let discussion_strand_id_label = short_protocol_id(&discussion_strand_id);
                                            let discussion_strand_href = format!(
                                                "/chat/{}",
                                                selected_realm_id
                                            );
                                            rsx! {
                                                div {
                                                    class: "discussion-promoted-indicator",
                                                    "data-testid": "discussion-promoted-indicator",
                                                    "data-discussion-strand-id": "{discussion_strand_id}",
                                                    span { "Discussion moved to private Strand " }
                                                    a {
                                                        href: "{discussion_strand_href}",
                                                        title: "{discussion_strand_id}",
                                                        "{discussion_strand_id_label}"
                                                    }
                                                }
                                            }
                                        },
                                        None => rsx! {},
                                    }
                                }
                                if !message_is_read_only_shared
                                    && reaction_picker() == Some(msg.id.clone())
                                {
                                    div { class: "actions chat-chip-row", "data-testid": "chat-reaction-picker",
                                        for emoji in CHAT_EMOJI_GRID {
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                class: "emoji-button",
                                                onclick: {
                                                    let context = command_context.clone();
                                                    let message_id = msg.id.clone();
                                                    let target_ref = msg.mutation_target_ref().to_owned();
                                                    let emoji = emoji.to_string();
                                                    move |_| controller.add_reaction(
                                                        context.clone(),
                                                        message_id.clone(),
                                                        target_ref.clone(),
                                                        emoji.clone(),
                                                    )
                                                },
                                                "{emoji}"
                                            }
                                        }
                                    }
                                }
                                if !message_is_read_only_shared
                                    && editing_message() == Some(msg.id.clone())
                                {
                                    div { class: "composer compact-composer", "data-testid": "chat-edit-composer",
                                        Textarea {
                                            value: "{edit_draft}",
                                            oninput: move |event: FormEvent| controller.update_edit_draft(event.value()),
                                        }
                                        div { class: "actions",
                                            Button {
                                                variant: ButtonVariant::Primary,
                                                "data-testid": "chat-save-edit-button",
                                                onclick: {
                                                    let context = command_context.clone();
                                                    let message_id = msg.id.clone();
                                                    let target_ref = msg.mutation_target_ref().to_owned();
                                                    move |_| controller.revise_message(
                                                        context.clone(),
                                                        message_id.clone(),
                                                        target_ref.clone(),
                                                        edit_draft(),
                                                    )
                                                },
                                                "Save"
                                            }
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                onclick: move |_| controller.cancel_edit(),
                                                "Cancel"
                                            }
                                        }
                                    }
                                }
                                if !message_is_read_only_shared
                                    && redact_confirm() == Some(msg.id.clone())
                                {
                                    div { class: "chat-redact-confirm", "data-testid": "chat-redact-confirm",
                                        div { class: "discussion-subhead", span { "Remove message" } }
                                        div { class: "actions",
                                            Button {
                                                variant: ButtonVariant::Primary,
                                                "data-testid": "chat-confirm-redact-button",
                                                onclick: {
                                                    let context = command_context.clone();
                                                    let message = msg.clone();
                                                    move |_| controller.redact_message(
                                                        context.clone(),
                                                        message.clone(),
                                                    )
                                                },
                                                "Confirm"
                                            }
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                onclick: move |_| controller.cancel_redaction(),
                                                "Cancel"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                            }
                        }
                    }
                    if let Some(report) = moderation_report_draft() {
                        div {
                            class: "discussion-modal-backdrop",
                            "data-testid": "moderation-report-modal",
                            div {
                                class: "discussion-modal",
                                role: "dialog",
                                "aria-modal": "true",
                                "aria-labelledby": "moderation-report-title",
                                div { class: "discussion-modal-head",
                                    h2 {
                                        id: "moderation-report-title",
                                        {crate::i18n::tr("moderation.report.title")}
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        r#type: "button",
                                        disabled: moderation_report_pending(),
                                        onclick: move |_| controller.cancel_moderation_report(),
                                        {crate::i18n::tr("common.cancel")}
                                    }
                                }
                                div { class: "discussion-modal-body workflow-form",
                                    p { {crate::i18n::tr("moderation.report.help")} }
                                    label { class: "form-row",
                                        span { {crate::i18n::tr("moderation.report.reason")} }
                                        select {
                                            "data-testid": "moderation-report-reason",
                                            value: "{report.reason}",
                                            disabled: moderation_report_pending(),
                                            onchange: move |event: FormEvent| {
                                                controller.update_moderation_report_reason(event.value());
                                            },
                                            for reason in [
                                                "spam",
                                                "harassment",
                                                "hate_speech",
                                                "nsfw",
                                                "illegal",
                                                "misinformation",
                                                "other",
                                            ] {
                                                option {
                                                    value: "{reason}",
                                                    {crate::i18n::tr(&format!("moderation.report.reason.{reason}"))}
                                                }
                                            }
                                        }
                                    }
                                    label { class: "form-row",
                                        span { {crate::i18n::tr("moderation.report.description")} }
                                        Textarea {
                                            "data-testid": "moderation-report-description",
                                            value: "{report.description}",
                                            disabled: moderation_report_pending(),
                                            oninput: move |event: FormEvent| {
                                                controller.update_moderation_report_description(event.value());
                                            },
                                        }
                                    }
                                }
                                div { class: "discussion-modal-actions",
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        r#type: "button",
                                        "data-testid": "moderation-report-submit",
                                        disabled: moderation_report_pending()
                                            || (report.reason == "other"
                                                && report.description.trim().is_empty()),
                                        onclick: {
                                            let context = command_context.clone();
                                            move |_| controller.submit_moderation_report(context.clone())
                                        },
                                        if moderation_report_pending() {
                                            {crate::i18n::tr("moderation.report.submitting")}
                                        } else {
                                            {crate::i18n::tr("moderation.report.submit")}
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if visible_channels_empty {
                        div { class: "empty-state discussion-empty-main", "data-testid": "discussion-main-empty",
                            div { class: "ico", UiIcon { name: "plus" } }
                            div { class: "t", {crate::i18n::tr("chat.empty.title")} }
                            div { class: "s", {crate::i18n::tr("chat.empty.description")} }
                            if !embedded {
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "discussion-empty-create-button",
                                        onclick: move |_| controller.open_create_dialog(),
                                        {crate::i18n::tr("chat.empty.create_button")}
                                    }
                                }
                            }
                        }
                    } else if visible_message_count == 0 {
                        if discussion_feed_loading {
                            div {
                                class: "discussion-empty discussion-loading",
                                "data-testid": "discussion-loading",
                                span { class: "discussion-loading-spinner", "aria-hidden": "true" }
                                span { {crate::i18n::tr("chat.loading_messages")} }
                            }
                        } else {
                            div { class: "discussion-empty", {crate::i18n::tr("chat.empty_messages")} }
                        }
                    }
                }
    }
}
