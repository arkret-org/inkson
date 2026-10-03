use arkret_wire::event_kind_str;

use super::*;

mod commands;

#[cfg(test)]
mod tests;

fn ordinary_composer_scope(realm: &str, channel: &ChannelEntity) -> Option<arkret_sdk::ScopeRef> {
    if channel.is_private_sidecar {
        return None;
    }
    let realm_id = arkret_sdk::RealmId::new(realm.to_owned()).ok()?;
    Some(match &channel.scope_circle {
        Some(scope) => arkret_sdk::ScopeRef::Circle {
            realm_id,
            circle_id: arkret_sdk::CircleId::new(scope.circle_id.clone()).ok()?,
        },
        None => arkret_sdk::ScopeRef::Realm { realm_id },
    })
}

#[derive(Clone, PartialEq)]
pub(super) struct ChatComposerContext {
    pub embedded: bool,
    pub selected_channel_info: Option<ChannelEntity>,
    pub authority: arkret_sdk::AccountId,
    pub did: arkret_sdk::Did,
    pub principal_id: arkret_sdk::DidCoreId,
    pub account_display_label: String,
    pub participants: Vec<SpaceParticipant>,
    pub selected_realm_id: String,
    pub device_id: arkret_sdk::DeviceId,
    pub selected_channel_security_encrypted: bool,
    pub selected_realm_pending_mls_binding: bool,
    pub selected_realm_pending_mls_binding_reason: Option<String>,
    pub active_sidecar_session: Option<crate::sidecar::HostedSidecarState>,
    pub sidecar_send_block_reason: Option<String>,
    pub public_agent_ids: std::collections::BTreeSet<String>,
    pub mention_insert_request: Option<Signal<Option<MentionInsertRequest>>>,
    pub mentions_enabled: bool,
    pub token: Signal<String>,
    pub sync_cursor: Signal<String>,
    pub frontier_state: Signal<String>,
}

pub(super) fn chat_mentions_enabled(direct_mode: bool) -> bool {
    !direct_mode
}

pub(super) fn chat_composer_placeholder(mentions_enabled: bool) -> &'static str {
    if mentions_enabled {
        "Message this discussion. Use @alice:example.com to mention a member or #task-123 to link a card."
    } else {
        "Message this discussion. Use #task-123 to link a card."
    }
}

pub(super) fn active_composer_mention_token(
    mentions_enabled: bool,
    value: &str,
) -> Option<(String, usize, usize)> {
    mentions_enabled
        .then(|| crate::messaging::mentions::active_mention_token_at_end(value))
        .flatten()
}

/// Match desktop chat conventions while leaving Shift+Enter to the textarea.
/// Ctrl/Cmd+Enter remain send aliases because those modifiers are not blockers.
pub(super) fn chat_composer_should_send_key(
    key: &str,
    shift: bool,
    alt: bool,
    is_composing: bool,
    is_auto_repeating: bool,
) -> bool {
    key == "Enter" && !shift && !alt && !is_composing && !is_auto_repeating
}

pub(super) fn chat_secure_send_blocked(
    pending_mls_binding: bool,
    creator_mls_bootstrap_pending: bool,
    sidecar_send_blocked: bool,
    sidecar_route_pending: bool,
) -> bool {
    pending_mls_binding
        || creator_mls_bootstrap_pending
        || sidecar_send_blocked
        || sidecar_route_pending
}

fn latest_source_event_anchor(
    messages: &[ChatMessage],
    realm_id: &str,
    strand_id: &str,
) -> Option<String> {
    messages
        .iter()
        .rev()
        .find(|message| {
            message.realm_id == realm_id
                && message.strand_id == strand_id
                && arkret_sdk::EventId::new(message.id.clone()).is_ok()
        })
        .map(|message| message.id.clone())
}

#[component]
fn OrdinarySendActions(
    plaintext: bool,
    plaintext_disabled: bool,
    secure_disabled: bool,
    mls_binding_pending: bool,
    creator_bootstrap_pending: bool,
    secure_title: String,
    opening: bool,
    on_plaintext: Callback<MouseEvent>,
    on_secure: Callback<MouseEvent>,
) -> Element {
    // Keep the primary button mounted while a fresh scope probe is pending.
    // Its identity and visibility must not depend on the encryption result.
    rsx! {
        Button {
            variant: ButtonVariant::Primary,
            "data-testid": "send-chat-button",
            "data-mls-binding-pending": mls_binding_pending.to_string(),
            "data-creator-bootstrap-pending": creator_bootstrap_pending.to_string(),
            title: if plaintext { String::new() } else { secure_title.clone() },
            disabled: if plaintext { plaintext_disabled } else { secure_disabled },
            onclick: move |event| {
                if plaintext {
                    on_plaintext.call(event);
                } else {
                    on_secure.call(event);
                }
            },
            if opening {
                "Opening…"
            } else {
                {crate::i18n::tr("chat.send")}
            }
        }
        if plaintext {
            Button {
                variant: ButtonVariant::Secondary,
                "data-testid": "send-e2ee-move-button",
                "data-mls-binding-pending": mls_binding_pending.to_string(),
                "data-creator-bootstrap-pending": creator_bootstrap_pending.to_string(),
                title: secure_title,
                disabled: secure_disabled,
                onclick: on_secure,
                if opening {
                    "Opening…"
                } else {
                    {crate::i18n::tr("chat.send_secure")}
                }
            }
        }
    }
}

#[component]
pub(super) fn ChatComposer(controller: ChatController, context: ChatComposerContext) -> Element {
    let ChatComposerContext {
        embedded: _,
        selected_channel_info,
        authority: sidecar_authority,
        did: sidecar_did,
        principal_id,
        account_display_label,
        participants: participants_for_messages,
        selected_realm_id,
        device_id,
        selected_channel_security_encrypted,
        selected_realm_pending_mls_binding,
        selected_realm_pending_mls_binding_reason,
        active_sidecar_session,
        sidecar_send_block_reason,
        public_agent_ids,
        mention_insert_request,
        mentions_enabled,
        token,
        sync_cursor,
        frontier_state,
    } = context;
    // The component boundary retains the validated identifier type. The view
    // helpers below only render or forward its canonical text.
    let principal_id = principal_id.as_str().to_owned();
    let base_url = crate::app::SessionContext::base_url_string();
    let sidecar_session = use_context::<crate::sidecar::HostedSidecarStateContext>().0;
    let state_store = crate::app::SessionContext::get().state_store;
    let messages_snapshot = (controller.messages)();
    let messages_for_composer_lookup = &messages_snapshot;
    let selected_channel_value = active_sidecar_session
        .as_ref()
        .map(|session| session.source_strand_id.clone())
        .unwrap_or_else(|| (controller.selected_channel)());
    let selected_channel_info = active_sidecar_session
        .as_ref()
        .map(|session| {
            let mut channel = selected_channel_info.clone().unwrap_or(ChannelEntity {
                strand_id: session.source_strand_id.clone(),
                name: "Private Sidecar".to_owned(),
                kind: "discussion".to_owned(),
                category: "discussion".to_owned(),
                topic: None,
                unread: 0,
                is_default: false,
                is_private_sidecar: true,
                security_encrypted: Some(true),
                scope_circle: None,
            });
            channel.strand_id = session.source_strand_id.clone();
            channel.is_private_sidecar = true;
            channel.security_encrypted = Some(true);
            channel.scope_circle = None;
            channel
        })
        .or(selected_channel_info);
    let selected_channel_is_circle_scoped = selected_channel_info
        .as_ref()
        .is_some_and(|channel| channel.scope_circle.is_some());
    let channels = controller.channels;
    let selected_channel = controller.selected_channel;
    let mut reply_to_message = controller.reply_to_message;
    let mut chat_draft = controller.draft;
    let mut compose_dragover = controller.compose_dragover;
    let mut compose_upload_status = controller.compose_upload_status;
    let mut mention_picker_state = controller.mention_picker_state;
    let mut attachment_menu_open = controller.attachment_menu_open;
    let mut poll_draft = controller.poll_draft;
    let mut poll_cards = controller.poll_cards;
    let mut messages = controller.messages;
    let mut is_online = controller.is_online;
    let mut status_msg = controller.status_msg;
    let mut sidecar_route_pending = use_signal(|| false);
    let mut scheduled_send_panel_open = use_signal(|| false);
    let mut mention_insert_request_seen = use_signal(String::new);
    let typing_throttle = controller.typing_throttle;
    let composer_class = "discussion-composer";
    let visible_channels_empty = channels.read().is_empty();
    let selected_channel_unavailable = selected_channel_info
        .as_ref()
        .is_none_or(|channel| channel.strand_id != selected_channel())
        || !channels()
            .iter()
            .any(|channel| channel.strand_id == selected_channel());
    let sidecar_send_blocked = sidecar_send_block_reason.is_some();
    let active_sidecar_present = active_sidecar_session.is_some();
    // content-types section 4.9 permits formal polls only in plaintext scopes.
    let polls_available = !selected_channel_security_encrypted && !active_sidecar_present;
    // Realm creation exposes the discussion surface as soon as the Genesis
    // Event is accepted, while the background verifier may still be advancing
    // the locally pinned governance checkpoint to the Seal that covers it.
    // Keep encrypted send disabled during that convergence window; the
    // state-store Signal rerenders this component when bootstrap completes.
    let creator_mls_bootstrap_pending_reason =
        if selected_channel_security_encrypted && !active_sidecar_present {
            selected_channel_info
                .as_ref()
                .and_then(|channel| channel.effective_scope(&selected_realm_id))
                .map_or(
                    Some("Waiting for the conversation's encryption scope."),
                    |scope| {
                        crate::mls::creator_bootstrap::creator_scope_mls_bootstrap_pending_reason(
                            &state_store.read(),
                            &scope,
                        )
                    },
                )
        } else {
            None
        };
    let creator_mls_bootstrap_pending = creator_mls_bootstrap_pending_reason.is_some();
    let participants_for_plaintext_sidecar = participants_for_messages.clone();
    let participants_for_encrypted_sidecar = participants_for_messages.clone();
    let composer_placeholder = chat_composer_placeholder(mentions_enabled);

    {
        use_effect(use_reactive(
            (&mentions_enabled,),
            move |(mentions_enabled,)| {
                if !mentions_enabled {
                    mention_picker_state.write().clear();
                }
            },
        ));
    }

    {
        let mut request_signal = mention_insert_request;
        let request_participants = participants_for_messages.clone();
        let request_principal_id = principal_id.clone();
        let request_public_agent_ids = public_agent_ids.clone();
        use_effect(use_reactive(
            (
                &mentions_enabled,
                &request_participants,
                &request_principal_id,
                &request_public_agent_ids,
            ),
            move |(
                mentions_enabled,
                request_participants,
                request_principal_id,
                request_public_agent_ids,
            )| {
                if !mentions_enabled {
                    if let Some(request_signal) = request_signal.as_mut()
                        && request_signal.peek().is_some()
                    {
                        request_signal.set(None);
                    }
                    return;
                }
                let Some(request_signal) = request_signal.as_mut() else {
                    return;
                };
                let Some(request) = request_signal() else {
                    return;
                };
                if mention_insert_request_seen.peek().as_str() == request.request_id {
                    return;
                }
                let candidate = request.resolve_candidate(
                    &request_participants,
                    &request_principal_id,
                    &request_public_agent_ids,
                );
                let Some(candidate) = candidate else {
                    return;
                };
                mention_insert_request_seen.set(request.request_id);
                request_signal.set(None);
                let inserted = mention_picker_state.write().insert(candidate.clone());
                if inserted {
                    let current = chat_draft();
                    chat_draft.set(crate::messaging::mentions::replace_active_mention_token(
                        &current,
                        None,
                        candidate.insert_label(),
                    ));
                }
                mention_picker_state.write().close();
                let _ = dioxus::document::eval(
                    r#"
                requestAnimationFrame(() => {
                  const input = document.querySelector('[data-testid="card-discussion-panel"] [data-testid="chat-input"]');
                  if (input instanceof HTMLElement) input.focus();
                });
                "#,
                );
            },
        ));
    }

    let typing_authority = sidecar_authority.clone();
    let scheduled_send_authority = sidecar_authority.clone();
    let plaintext_sidecar_authority = sidecar_authority.clone();
    let plaintext_sidecar_did = sidecar_did.clone();
    let secure_sidecar_authority = sidecar_authority.clone();
    let secure_sidecar_did = sidecar_did;
    let plaintext_send = use_callback::<MouseEvent, ()>({
        let base = base_url.clone();
        let realm = selected_realm_id.clone();
        let actor = principal_id.clone();
        let sidecar_device_id = device_id.clone();
        move |_| {
            let authority_for_sidecar = plaintext_sidecar_authority.clone();
            let did_for_sidecar = plaintext_sidecar_did.clone();
            let device_id_for_sidecar = sidecar_device_id.clone();
            let body = chat_draft().trim().to_owned();
            if body.is_empty() {
                return;
            }
            let inserted_candidates = mention_picker_state.read().inserted.clone();
            let mentions =
                composer_mention_nodes(mentions_enabled, &body, &inserted_candidates, &actor);
            let channel = channels()
                .iter()
                .find(|candidate| candidate.strand_id == selected_channel())
                .cloned();
            let Some(channel) = channel else {
                status_msg.set("select a discussion first".to_owned());
                return;
            };
            let local_owned_agent_ids = owned_agent_ids_from_composer(
                mentions_enabled,
                &mentions,
                &participants_for_plaintext_sidecar,
                &actor,
            );
            let targets_owned_agent = mentions_enabled
                && should_route_owned_agent_to_sidecar(
                    active_sidecar_present,
                    selected_channel_is_circle_scoped,
                    !local_owned_agent_ids.is_empty(),
                );
            if targets_owned_agent {
                sidecar_route_pending.set(true);
                status_msg.set("Activating Private Sidecar…".to_owned());
                let trace_id = uuid_v7();
                tracing::info!(
                    target: "sidecar",
                    event = "sidecar.route.requested",
                    trace_id = %trace_id,
                    source_realm_id = %realm,
                    source_strand_id = %channel.strand_id,
                );
                commands::route_to_owned_agent_sidecar(
                    controller,
                    sidecar_session,
                    sidecar_route_pending,
                    commands::OwnedAgentSidecarRoute {
                        base_url: base.clone(),
                        api_token: token(),
                        trace_id,
                        realm_id: realm.clone(),
                        strand_id: channel.strand_id.clone(),
                        actor: actor.clone(),
                        authority: authority_for_sidecar.clone(),
                        controller_did: did_for_sidecar.clone(),
                        device_id: device_id_for_sidecar.clone(),
                        mentions_enabled,
                        mentions,
                        body: body.clone(),
                        participants: participants_for_plaintext_sidecar.clone(),
                    },
                );
                return;
            }
            let local_id = new_chat_local_id();
            messages.write().push(ChatMessage {
                local_scope: ordinary_composer_scope(&realm, &channel),
                realm_id: realm.clone(),
                id: local_id.clone(),
                protocol_message_id: Some(local_id.clone()),
                actor_id: crate::mls_api_helpers::local_account_actor_id(&actor).ok(),
                sender: actor.clone(),
                executed_by: None,
                body: body.clone(),
                content_format: Some(arkret_sdk::TextFormat::Markdown),
                timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                created_at: Some(chrono::Utc::now()),
                strand_id: channel.strand_id.clone(),
                reply_to: reply_to_message(),
                reactions: Vec::new(),
                redacted: false,
                edited: false,
                revisions: Vec::new(),
                revision_source: None,
                pending: true,
                failed: false,
                error: None,
                mentions: mentions.clone(),
                // Local-only sends start plaintext;
                // the Send Secure flow may upgrade
                // them via a separate `messages.write()`
                // patch after `encrypt_payload`.
                crypto_state: MessageCryptoState::Plaintext,
            });

            // Continue into the ordinary submit path while
            // offline: EventSubmitter persists the stable SDK
            // Event in Garth before its first network attempt.
            // Queue status and replay both come from that one
            // durable source.
            let offline_now = !is_online() || !navigator_online();
            if offline_now {
                if *is_online.peek() {
                    is_online.set(false);
                }
                status_msg.set(crate::i18n::tr("chat.outbox.queued_offline"));
            }

            let base = base.clone();
            let realm = realm.clone();
            let api_token = token();
            let actor = actor.clone();
            let strand_id = channel.strand_id.clone();
            let reply_to = reply_to_message();
            // Clear the picker chip list now that
            // we've folded the mentions into the
            // pending send state.
            mention_picker_state.write().clear();
            let wait_for = active_sync_token(sync_cursor());
            commands::send_plaintext_message(
                controller,
                frontier_state,
                commands::PlaintextSendRequest {
                    base_url: base,
                    api_token,
                    wait_for,
                    realm_id: realm,
                    circle_id: channel
                        .scope_circle
                        .as_ref()
                        .map(|circle| circle.circle_id.clone()),
                    strand_id,
                    actor,
                    local_id,
                    body,
                    reply_to,
                    mentions,
                },
            );
            chat_draft.set(String::new());
            reply_to_message.set(None);
        }
    });
    let secure_send = use_callback::<MouseEvent, ()>({
        let device_id = device_id.clone();
        let active_sidecar_session = active_sidecar_session.clone();
        let base = base_url.clone();
        let realm = selected_realm_id.clone();
        let actor = principal_id.clone();
        let selected_strand = selected_channel_value.clone();
        let selected_circle = selected_channel_info
            .as_ref()
            .and_then(|channel| channel.scope_circle.as_ref())
            .map(|circle| circle.circle_id.clone());
        let pending_mls_binding = selected_realm_pending_mls_binding;
        let sidecar_device_id = device_id.clone();
        let pending_mls_binding_reason = selected_realm_pending_mls_binding_reason.clone();
        move |_| {
            let authority_for_sidecar = secure_sidecar_authority.clone();
            let did_for_sidecar = secure_sidecar_did.clone();
            let device_id_for_sidecar = sidecar_device_id.clone();
            if pending_mls_binding {
                status_msg.set(pending_mls_binding_reason.clone().unwrap_or_else(|| {
                    "epoch_update_required: membership frontier changed; MLS commit required"
                        .to_owned()
                }));
                return;
            }
            let body = chat_draft().trim().to_owned();
            if body.is_empty() {
                status_msg.set("Type a message before secure send".to_owned());
                return;
            }
            let inserted_candidates = mention_picker_state.read().inserted.clone();
            let mentions =
                composer_mention_nodes(mentions_enabled, &body, &inserted_candidates, &actor);
            let realm = realm.clone();
            let actor = actor.clone();
            if selected_strand.trim().is_empty() {
                status_msg.set(
                    "Default Strand is unavailable until its accepted projection arrives"
                        .to_owned(),
                );
                return;
            }
            let strand_id = selected_strand.clone();
            let local_owned_agent_ids = owned_agent_ids_from_composer(
                mentions_enabled,
                &mentions,
                &participants_for_encrypted_sidecar,
                &actor,
            );
            let active_sidecar_for_send = active_sidecar_session.clone();
            let targets_owned_agent = mentions_enabled
                && should_route_owned_agent_to_sidecar(
                    active_sidecar_for_send.is_some(),
                    selected_channel_is_circle_scoped,
                    !local_owned_agent_ids.is_empty(),
                );
            if targets_owned_agent {
                sidecar_route_pending.set(true);
                status_msg.set("Activating Private Sidecar…".to_owned());
                let trace_id = uuid_v7();
                tracing::info!(
                    target: "sidecar",
                    event = "sidecar.route.requested",
                    trace_id = %trace_id,
                    source_realm_id = %realm,
                    source_strand_id = %strand_id,
                );
                commands::route_to_owned_agent_sidecar(
                    controller,
                    sidecar_session,
                    sidecar_route_pending,
                    commands::OwnedAgentSidecarRoute {
                        base_url: base.clone(),
                        api_token: token(),
                        trace_id,
                        realm_id: realm.clone(),
                        strand_id: strand_id.clone(),
                        actor: actor.clone(),
                        authority: authority_for_sidecar.clone(),
                        controller_did: did_for_sidecar.clone(),
                        device_id: device_id_for_sidecar.clone(),
                        mentions_enabled,
                        mentions,
                        body: body.clone(),
                        participants: participants_for_encrypted_sidecar.clone(),
                    },
                );
                return;
            }
            if let Some(session) = active_sidecar_for_send {
                if !session.membership_ready() {
                    status_msg.set("Private Sidecar MLS access is not ready".to_owned());
                    return;
                }
                let local_id = new_chat_local_id();
                let source_strand_id = session.source_strand_id.clone();
                messages.write().push(ChatMessage {
                    local_scope: None,
                    realm_id: session.source_realm_id.clone(),
                    id: local_id.clone(),
                    protocol_message_id: Some(local_id.clone()),
                    actor_id: crate::mls_api_helpers::local_account_actor_id(&actor).ok(),
                    sender: actor.clone(),
                    executed_by: None,
                    body: body.clone(),
                    content_format: Some(arkret_sdk::TextFormat::Markdown),
                    timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                    created_at: Some(chrono::Utc::now()),
                    strand_id: source_strand_id.clone(),
                    reply_to: None,
                    reactions: Vec::new(),
                    redacted: false,
                    edited: false,
                    revisions: Vec::new(),
                    revision_source: None,
                    pending: true,
                    failed: false,
                    error: None,
                    mentions: mentions.clone(),
                    crypto_state: MessageCryptoState::Plaintext,
                });
                chat_draft.set(String::new());
                mention_picker_state.write().clear();
                reply_to_message.set(None);

                let base = base.clone();
                let api_token = token();
                let source_event_id = latest_source_event_anchor(
                    &messages.read(),
                    &session.source_realm_id,
                    &session.source_strand_id,
                );
                commands::send_sidecar_message(
                    controller,
                    commands::SidecarSendRequest {
                        base_url: base,
                        api_token,
                        session,
                        sidecar_strand_id: source_strand_id,
                        source_event_id,
                        actor,
                        authority: authority_for_sidecar,
                        device_id: device_id_for_sidecar,
                        local_id,
                        body,
                        mentions,
                    },
                );
                return;
            }
            // P2: preserve the composer's reply target on the
            // encrypted path (it was silently dropped before).
            let reply_to = reply_to_message().filter(|value| !value.trim().is_empty());
            let message_id = new_chat_local_id();
            messages.write().push(ChatMessage {
                local_scope: channels()
                    .iter()
                    .find(|channel| channel.strand_id == strand_id)
                    .and_then(|channel| ordinary_composer_scope(&realm, channel)),
                realm_id: realm.clone(),
                id: message_id.clone(),
                protocol_message_id: Some(message_id.clone()),
                actor_id: crate::mls_api_helpers::local_account_actor_id(&actor).ok(),
                sender: actor.clone(),
                executed_by: None,
                body: body.clone(),
                content_format: Some(arkret_sdk::TextFormat::Markdown),
                timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                created_at: Some(chrono::Utc::now()),
                strand_id: strand_id.clone(),
                reply_to: reply_to.clone(),
                reactions: Vec::new(),
                redacted: false,
                edited: false,
                revisions: Vec::new(),
                revision_source: None,
                pending: true,
                failed: false,
                error: None,
                mentions: mentions.clone(),
                crypto_state: MessageCryptoState::Plaintext,
            });
            mention_picker_state.write().clear();
            chat_draft.set(String::new());
            reply_to_message.set(None);
            let base = base.clone();
            let realm = realm.clone();
            let actor = actor.clone();
            let did = device_id.clone();
            let api_token = token();
            let wait_for = active_sync_token(sync_cursor());
            let backup_trigger_signal = crate::components::try_needs_mls_backup_signal();
            commands::send_encrypted_message(
                controller,
                frontier_state,
                commands::EncryptedSendRequest {
                    base_url: base,
                    api_token,
                    wait_for,
                    realm_id: realm,
                    circle_id: selected_circle.clone(),
                    strand_id,
                    actor,
                    authority: authority_for_sidecar,
                    device_id: did,
                    message_id,
                    body,
                    reply_to,
                    mentions,
                    backup_trigger_signal,
                },
            );
        }
    });
    rsx! {
            if !visible_channels_empty {
            div { class: "{composer_class}", "data-testid": "chat-composer",
                // P3B.2.3 — Circle composer banner. Rendered
                // at the top of the composer surface when the active
                // Strand carries a `scope_circle_id`. The component is
                // pure: `CircleScope::Realm` renders nothing, so the
                // surface stays quiet during normal Realm-scoped
                // writes.
                {
                    let scope = selected_channel_info
                        .as_ref()
                        .and_then(|channel| channel.scope_circle.clone())
                        .map(|circle| crate::circle::CircleScope::Circle {
                            circle_id: circle.circle_id,
                            title: circle.title,
                            member_count: circle.member_count,
                        })
                        .unwrap_or(crate::circle::CircleScope::Realm);
                    rsx! {
                        crate::components::CircleComposerBanner { scope }
                    }
                }
                if let Some(reply_id) = reply_to_message() {
                    div { class: "chat-reply-quote-banner", "data-testid": "chat-reply-banner",
                        if let Some((quoted_name, quoted_body)) = chat_reply_quote_preview(
                            messages_for_composer_lookup,
                            &reply_id,
                            &principal_id,
                            &account_display_label,
                            &participants_for_messages,
                        ) {
                            div { class: "chat-reply-quote",
                                span { class: "chat-reply-quote-name", "{quoted_name}" }
                                div { class: "chat-reply-quote-body", "{quoted_body}" }
                            }
                        } else {
                            div { class: "chat-reply-quote chat-reply-quote-missing",
                                "Replying to a message"
                            }
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            onclick: move |_| reply_to_message.set(None),
                            "Cancel"
                        }
                    }
                }
                // A6.2: drag-drop attachment zone wrapping the textarea.
                // Dropping a file uploads the bytes via
                // `upload_blob_bytes`, then appends `[Attachment: {ref}]`
                // to the draft so the existing send pipeline picks it
                // up as message body. `ondragover` is required to
                // prevent the browser's default open-the-file behaviour.
                div {
                    class: if compose_dragover() {
                        "compose-drop-zone is-dragover"
                    } else {
                        "compose-drop-zone"
                    },
                    "data-testid": "compose-drop-zone",
                    ondragover: move |evt| {
                        evt.prevent_default();
                        if !compose_dragover() { compose_dragover.set(true); }
                    },
                    ondragleave: move |_| compose_dragover.set(false),
                    ondrop: {
                        let base = base_url.clone();
                        let realm = selected_realm_id.clone();
                        move |evt| {
                            evt.prevent_default();
                            compose_dragover.set(false);
                            let files = evt.files();
                            if files.is_empty() {
                                // Some platforms (notably the desktop
                                // web embedder) deliver drops without
                                // file payloads — surface that rather
                                // than silently no-op.
                                compose_upload_status.set(
                                    crate::i18n::tr("compose.upload_error"),
                                );
                                return;
                            }
                            let api_token = token();
                            let base = base.clone();
                            let realm = realm.clone();
                            compose_upload_status.set(
                                crate::i18n::tr("compose.upload_progress"),
                            );
                            commands::upload_dropped_attachments(controller, base, api_token, realm, files);
                        }
                    },
                    Textarea {
                        "data-testid": "chat-input",
                        value: "{chat_draft}",
                        placeholder: "{composer_placeholder}",
                        onkeydown: move |event: KeyboardEvent| {
                            let key = event.key().to_string();
                            let modifiers = event.modifiers();
                            if chat_composer_should_send_key(
                                &key,
                                modifiers.shift(),
                                modifiers.alt(),
                                event.is_composing(),
                                event.is_auto_repeating(),
                            ) {
                                event.prevent_default();
                                event.stop_propagation();
                                let _ = dioxus::document::eval(
                                    r#"
                                    (() => {
                                      const target = document.activeElement;
                                      const composer =
                                        target instanceof HTMLElement ? target.closest('[data-testid="chat-composer"]') : null;
                                      const button = composer && composer.querySelector('[data-testid="send-chat-button"]');
                                      if (button instanceof HTMLElement) button.click();
                                    })();
                                    "#,
                                );
                            }
                        },
                        oninput: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let typing_device_id = device_id.clone();
                            let selected_strand = selected_channel_value.clone();
                            move |event: FormEvent| {
                                let value = event.value();
                                controller.update_draft(value.clone());
                                // G3.Y2 — auto-open the mention picker
                                // when the user types an `@`. The
                                // composer reads `mention_picker_state.open`
                                // to know whether to render the
                                // `mention-picker` element.
                                if let Some((query, start, end)) =
                                    active_composer_mention_token(mentions_enabled, &value)
                                {
                                    mention_picker_state
                                        .write()
                                        .set_active_token(query, start, end);
                                } else if mention_picker_state.read().open {
                                    mention_picker_state.write().close();
                                }
                                // G3.Y2 — typing signal, fire-and-forget so the
                                // composer never blocks; failures fall back
                                // silently per the spec. Perf (P0): the throttle
                                // emits `typing=true` on the leading edge (≤ once
                                // / 3s) and `typing=false` after the user stops,
                                // instead of one POST per keystroke. The
                                // receiving side TTL-expires stale entries.
                                // Typing follows a visibility policy at
                                // least as strict as presence
                                // (profiles-presence.md §3.5): with
                                // `presence_visibility="nobody"` the
                                // client MUST NOT send `ak.typing`,
                                // symmetric with the presence send gate.
                                if !state_store
                                    .read()
                                    .presence_visibility()
                                    .allows_presence_send()
                                {
                                    return;
                                }
                                let base = base.clone();
                                let realm = realm.clone();
                                let authority = typing_authority.clone();
                                let device = typing_device_id.clone();
                                if selected_strand.trim().is_empty() {
                                    return;
                                }
                                let strand_id = selected_strand.clone();
                                // Signal key material comes from the scope's
                                // accepted MLS state. No material means the
                                // Signal capability is withdrawn for this
                                // scope; v1 has no plaintext branch to fall
                                // back to, so simply do not send.
                                let Ok(material) = crate::signal::key_material_for_scope(
                                    &state_store.read(),
                                    &realm,
                                    None,
                                ) else {
                                    return;
                                };
                                let typing_store =
                                    crate::app::runtime_adapter::state_store_handle(state_store);
                                let typing_target = commands::TypingSignalTarget {
                                    base_url: base.clone(),
                                    realm_id: realm.clone(),
                                    strand_id: strand_id.clone(),
                                    authority: authority.clone(),
                                    device_id: device.clone(),
                                    material,
                                    store: typing_store,
                                };
                                typing_throttle.on_keystroke(move |is_typing| {
                                    commands::send_typing_signal(typing_target.clone(), token(), is_typing);
                                });
                            }
                        },
                    }
                    if mentions_enabled && mention_picker_state.read().open {
                        div { class: "mention-picker",
                            "data-testid": "mention-picker",
                            div { class: "mention-picker-head",
                                Input {
                                    r#type: "text",
                                    class: "mention-picker-query",
                                    placeholder: "Search members",
                                    value: "{mention_picker_state.read().query}",
                                    oninput: move |event: FormEvent| {
                                        mention_picker_state.write().set_query(event.value());
                                    },
                                }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    r#type: "button",
                                    "data-testid": "mention-picker-close-button",
                                    onclick: move |_| mention_picker_state.write().close(),
                                    "Close"
                                }
                            }
                            {
                                let mut candidates: Vec<crate::messaging::mentions::MentionCandidate> =
                                    participants_for_messages
                                        .iter()
                                        .filter(|p| agent_candidate_is_visible(p, &public_agent_ids, &principal_id))
                                        .filter_map(|p| mention_candidate_for_participant(
                                            p,
                                            &participants_for_messages,
                                            &principal_id,
                                        ))
                                        .collect();
                                candidates.sort_by_key(|candidate| {
                                    if candidate.subject_account_id.principal_id.as_str()
                                        == principal_id.trim()
                                    {
                                        0u8
                                    } else if candidate.is_agent
                                        && candidate
                                            .controller_subject_account_id
                                            .as_ref()
                                            .is_some_and(|controller| {
                                                controller.principal_id.as_str()
                                                    == principal_id.trim()
                                            })
                                    {
                                        1u8
                                    } else {
                                        2u8
                                    }
                                });
                                // `filter` borrows from `candidates`, not from the
                                // picker state, so we run it under the read guard and
                                // only clone the matched candidates we actually render
                                // instead of cloning the whole picker state first.
                                let matches: Vec<crate::messaging::mentions::MentionCandidate> =
                                    mention_picker_state
                                        .read()
                                        .filter(&candidates)
                                        .into_iter()
                                        .cloned()
                                        .collect();
                                rsx! {
                                    div { class: "mention-suggestions",
                                        if matches.is_empty() {
                                            div { class: "muted", "No matches" }
                                        } else {
                                            for candidate in matches {
                                                {
                                                    let candidate_label =
                                                        format!("@{}", candidate.insert_label());
                                                    let candidate_is_self =
                                                        candidate.subject_account_id.principal_id.as_str()
                                                            == principal_id.trim();
                                                    let candidate_agent_slug = candidate
                                                        .is_agent
                                                        .then(|| candidate.agent_slug_at_time.clone());
                                                    rsx! {
                                                        Button {
                                                            variant: ButtonVariant::Secondary,
                                                            key: "{candidate.subject_account_id.principal_id}@{candidate.subject_account_id.station_id}",
                                                            r#type: "button",
                                                            class: "mention-suggestion",
                                                            "data-testid": "mention-suggestion",
                                                            // Both components are exposed separately: the
                                                            // subject identity is the pair, never one of them.
                                                            "data-mention-principal-id": "{candidate.subject_account_id.principal_id}",
                                                            "data-mention-station-id": "{candidate.subject_account_id.station_id}",
                                                            title: "@{candidate.insert_label()}",
                                                            onclick: {
                                                                let candidate = candidate.clone();
                                                                move |_| {
                                                                    let inserted = mention_picker_state
                                                                        .write()
                                                                        .insert(candidate.clone());
                                                                    if inserted {
                                                                        let current = chat_draft();
                                                                        let active_range =
                                                                            mention_picker_state
                                                                                .read()
                                                                                .active_range;
                                                                        let insert_label =
                                                                            candidate.insert_label().to_owned();
                                                                        chat_draft.set(
                                                                            crate::messaging::mentions::replace_active_mention_token(
                                                                                &current,
                                                                                active_range,
                                                                                &insert_label,
                                                                            ),
                                                                        );
                                                                    }
                                                                    mention_picker_state.write().close();
                                                                }
                                                            },
                                                            ActorIdentityLabel {
                                                                label: candidate_label,
                                                                title: Some(format!("@{}", candidate.insert_label())),
                                                                class: Some("mention-suggestion-name".to_owned()),
                                                                test_id: Some("mention-suggestion".to_owned()),
                                                                self_badge_test_id: None,
                                                                agent_badge_test_id: Some("mention-suggestion-agent-badge".to_owned()),
                                                                is_self: candidate_is_self,
                                                                agent_slug: candidate_agent_slug,
                                                                agent_selector: None,
                                                            }
                                                            if !candidate.subtitle.is_empty() {
                                                                span { class: "mention-suggestion-subtitle",
                                                                    "{candidate.subtitle}"
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
                    // G3.Y2 — mention chip row. The picker renders directly
                    // below the textarea; this row keeps the explicit trigger
                    // button for cotest while production users open the picker
                    // by typing `@`.
                    div { class: "mention-chip-row",
                        if mentions_enabled {
                            Button {
                                variant: ButtonVariant::Secondary,
                                r#type: "button",
                                class: "composer-tool-button",
                                "data-testid": "mention-trigger-button",
                                title: "Mention member",
                                "aria-label": "Mention member",
                                onclick: move |_| {
                                    let mut state = mention_picker_state.write();
                                    if state.open {
                                        state.close();
                                    } else {
                                        state.open();
                                    }
                                },
                                UiIcon { name: "at-sign" }
                            }
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            r#type: "button",
                            class: "composer-tool-button",
                            "data-testid": "attachment-menu-button",
                            title: "Add attachment",
                            "aria-label": "Add attachment",
                            onclick: move |_| {
                                let current = attachment_menu_open();
                                attachment_menu_open.set(!current);
                            },
                            UiIcon { name: "plus" }
                        }
                        if polls_available {
                            Button {
                                variant: ButtonVariant::Secondary,
                                r#type: "button",
                                class: "composer-tool-button",
                                "data-testid": "open-poll-composer-button",
                                disabled: selected_channel_unavailable || selected_realm_pending_mls_binding,
                                title: "Create poll",
                                "aria-label": "Create poll",
                                onclick: move |_| {
                                    attachment_menu_open.set(false);
                                    poll_draft.set(Some(
                                        crate::messaging::polls::PollDraft::new(),
                                    ));
                                },
                                "Poll"
                            }
                        }
                        // Scheduled send (spec personal-productivity.md §4) is
                        // offered on the plaintext composer path only: the
                        // plan stores the future `ak.message.create` payload,
                        // and the MLS-encrypted send path would need
                        // dispatch-time encryption, which v1 does not wire.
                        if !selected_channel_security_encrypted && active_sidecar_session.is_none() {
                            Button {
                                variant: ButtonVariant::Secondary,
                                r#type: "button",
                                class: "composer-tool-button",
                                "data-testid": "open-scheduled-send-panel-button",
                                title: "Schedule message",
                                "aria-label": "Schedule message",
                                onclick: move |_| {
                                    let open = scheduled_send_panel_open();
                                    scheduled_send_panel_open.set(!open);
                                },
                                UiIcon { name: "calendar" }
                            }
                        }
                        if attachment_menu_open() {
                            div { class: "attachment-menu",
                                if polls_available {
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        r#type: "button",
                                        class: "attachment-menu-item",
                                        "data-testid": "attachment-menu-poll",
                                        disabled: selected_channel_unavailable || selected_realm_pending_mls_binding,
                                        onclick: move |_| {
                                            attachment_menu_open.set(false);
                                            poll_draft.set(Some(
                                                crate::messaging::polls::PollDraft::new(),
                                            ));
                                        },
                                        "Create poll"
                                    }
                                }
                            }
                        }
                        if mentions_enabled {
                            for chip in mention_picker_state.read().inserted.clone() {
                                div {
                                    class: "mention-chip",
                                    "data-testid": "mention-chip",
                                    "data-mention-principal-id": "{chip.subject_account_id.principal_id}",
                                    "data-mention-station-id": "{chip.subject_account_id.station_id}",
                                    span { "@{chip.insert_label()}" }
                                    if !chip.subtitle.is_empty() {
                                        span { class: "mention-chip-subtitle", "{chip.subtitle}" }
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        r#type: "button",
                                        onclick: {
                                            let subject_account_id = chip.subject_account_id.clone();
                                            move |_| mention_picker_state
                                                .write()
                                                .remove(&subject_account_id)
                                        },
                                        "\u{00d7}"
                                    }
                                }
                            }
                        }
                    }
                    if compose_dragover() {
                        div {
                            class: "compose-drop-zone-hint",
                            "data-testid": "compose-drop-hint",
                            {crate::i18n::tr("compose.drop_zone.hint")}
                        }
                    }
                }
                if !compose_upload_status().is_empty() {
                    div {
                        class: "compose-upload-progress",
                        "data-testid": "compose-upload-progress",
                        "{compose_upload_status}"
                    }
                }
                if polls_available {
                if let Some(draft) = poll_draft.read().clone() {
                    div { class: "poll-composer",
                        "data-testid": "poll-composer",
                        Input {
                            r#type: "text",
                            "data-testid": "poll-question-input",
                            placeholder: "Question",
                            value: "{draft.question}",
                            oninput: move |event: FormEvent| {
                                if let Some(current) = poll_draft.write().as_mut() {
                                    current.set_question(event.value());
                                }
                            },
                        }
                        for (idx, option) in draft.options.iter().enumerate() {
                            Input {
                                r#type: "text",
                                "data-testid": "poll-option-input",
                                "data-option-index": "{idx as i64}",
                                placeholder: "Option {idx + 1}",
                                value: "{option}",
                                oninput: move |event: FormEvent| {
                                    if let Some(current) = poll_draft.write().as_mut() {
                                        current.set_option(idx, event.value());
                                    }
                                },
                            }
                        }
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                r#type: "button",
                                "data-testid": "poll-add-option-button",
                                onclick: move |_| {
                                    if let Some(current) = poll_draft.write().as_mut() {
                                        current.add_option();
                                    }
                                },
                                "Add option"
                            }
                            Button {
                                variant: ButtonVariant::Primary,
                                r#type: "button",
                                "data-testid": "send-poll-button",
                                disabled: !draft.is_sendable() || selected_channel_unavailable || selected_realm_pending_mls_binding,
                                onclick: {
                                    let base = base_url.clone();
                                    let realm = selected_realm_id.clone();
                                    let actor = principal_id.clone();
                                    let selected_strand = selected_channel_value.clone();
                                    let protection = super::poll_submission::PollSubmissionContext {
                                        authority: sidecar_authority.clone(),
                                        device_id: device_id.clone(),
                                        encrypted: selected_channel_security_encrypted,
                                        circle_id: selected_channel_info.as_ref()
                                            .and_then(|channel| channel.scope_circle.as_ref())
                                            .map(|scope| scope.circle_id.clone()),
                                    };
                                    move |_| {
                                        let Some(draft_snapshot) = poll_draft.read().clone() else {
                                            return;
                                        };
                                        if !draft_snapshot.is_sendable() {
                                            return;
                                        }
                                        let poll_id = crate::messaging::polls::new_poll_id();
                                        // Build the content draft; the accepted Event receipt
                                        // will supply the Message identity used by responses.
                                        let op = match crate::messaging::polls::build_poll_create_op_scoped(
                                            &realm,
                                            &actor,
                                            &selected_strand,
                                            protection.circle_id.as_deref(),
                                            &draft_snapshot,
                                        ) {
                                            Ok(op) => op.with_local_operation_id(
                                                crate::operation::LocalOperationId::from_holder_key(
                                                    poll_id.clone(),
                                                ),
                                            ),
                                            Err(error) => {
                                                status_msg.set(format!("Poll send failed: {error}"));
                                                return;
                                            }
                                        };
                                        // The Message id is `retype(event_id)`, so it exists
                                        // only once the poll Event is accepted. The optimistic
                                        // card is keyed by the holder-local operation id until
                                        // then, and the author-owned plaintext sidecar is keyed
                                        // by the accepted id inside the submit arm below.
                                        let card = crate::messaging::polls::PollCard::from_draft(
                                            poll_id.clone(), &draft_snapshot,
                                        );
                                        // Optimistic UI: surface the
                                        // poll card immediately, then push
                                        // a synthetic ChatMessage so chat
                                        // renders it in place.
                                        poll_cards.write().push(card);
                                        messages.write().push(ChatMessage {
                                            local_scope: Some(op.intent().scope_ref().clone()),
                                            realm_id: realm.clone(),
                                            id: poll_id.clone(),
                                            protocol_message_id: None,
                                            actor_id: crate::mls_api_helpers::local_account_actor_id(&actor).ok(),
                                            sender: actor.clone(),
                                            executed_by: None,
                                            body: format!("[poll] {}", draft_snapshot.question),
                                            content_format: None,
                                            timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                                            created_at: Some(chrono::Utc::now()),
                                            strand_id: selected_strand.clone(),
                                            reply_to: None,
                                            reactions: Vec::new(),
                                            redacted: false,
                                            edited: false,
                                            revisions: Vec::new(),
                                            revision_source: None,
                                            pending: true,
                                            failed: false,
                                            error: None,
                                            mentions: Vec::new(),
                                            crypto_state: MessageCryptoState::Plaintext,
                                        });
                                        poll_draft.set(None);

                                        commands::send_poll(
                                            controller,
                                            base.clone(),
                                            token(),
                                            op,
                                            protection.clone(),
                                            poll_id.clone(),
                                            realm.clone(),
                                            selected_strand.clone(),
                                        );
                                    }
                                },
                                "Send poll"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                r#type: "button",
                                onclick: move |_| poll_draft.set(None),
                                "Cancel"
                            }
                        }
                    }
                }
                }
                if scheduled_send_panel_open()
                    && !selected_channel_security_encrypted
                    && active_sidecar_session.is_none()
                {
                    super::scheduled_send_panel::ScheduledSendPanel {
                        context: super::scheduled_send_panel::ScheduledSendPanelContext {
                            realm_id: selected_realm_id.clone(),
                            strand_id: selected_channel(),
                            authority: scheduled_send_authority.clone(),
                            device_id: device_id.clone(),
                            token,
                            draft: chat_draft,
                            status_msg,
                        }
                    }
                }
                div { class: "actions",
                    OrdinarySendActions {
                        plaintext: !selected_channel_security_encrypted && !active_sidecar_present,
                        plaintext_disabled: sidecar_send_blocked || sidecar_route_pending() || selected_channel_unavailable || selected_realm_pending_mls_binding,
                        secure_disabled: chat_secure_send_blocked(
                            selected_realm_pending_mls_binding,
                            creator_mls_bootstrap_pending,
                            sidecar_send_blocked,
                            sidecar_route_pending(),
                        ) || (!active_sidecar_present && selected_channel_unavailable),
                        mls_binding_pending: selected_realm_pending_mls_binding,
                        creator_bootstrap_pending: creator_mls_bootstrap_pending,
                        secure_title: selected_realm_pending_mls_binding_reason.clone().unwrap_or_else(|| {
                            creator_mls_bootstrap_pending_reason.unwrap_or_default().to_owned()
                        }),
                        opening: sidecar_route_pending(),
                        on_plaintext: plaintext_send,
                        on_secure: secure_send,
                    }
                }
                if !status_msg().is_empty() {
                    div {
                        class: "muted discussion-status",
                        "data-testid": "chat-status",
                        role: "status",
                        "aria-live": "polite",
                        // Keep the full status text discoverable even when the
                        // embedded panel clips the line.
                        title: "{status_msg}",
                        "{status_msg}"
                    }
                }
            }
            }
    }
}
