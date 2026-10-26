//! Exact original authoring paths behind native controls.
use super::*;
pub(super) fn plaintext(
    app: Rc<crate::presentation::InksonContext>,
    controller: ChatController,
    context: ChatComposerContext,
) {
    let ChatComposerContext {
        sidecar_route_pending,
        selected_channel_info,
        circle_display: _,
        circle_encrypted: _,
        authority: sidecar_authority,
        did: sidecar_did,
        principal_id,
        account_display_label: _,
        participants: participants_for_messages,
        selected_realm_id,
        device_id,
        selected_channel_security_encrypted: _,
        selected_realm_pending_mls_binding: _,
        selected_realm_pending_mls_binding_reason: _,
        send_readiness_checking: _,
        active_sidecar_session: _,
        sidecar_send_block_reason: _,
        public_agent_ids: _,
        interaction_modes,
        mention_insert_request: _,
        mentions_enabled,
        token,
        frontier_state,
    } = context;
    let principal_id = principal_id.as_str().to_owned();
    let base_url = app.base_url.get_untracked();
    let sidecar_session = app.hosted_sidecar;
    let _state_store = app.state_store.clone();
    let messages_snapshot = controller.messages.get_untracked();
    let _messages_for_composer_lookup = &messages_snapshot;
    let _selected_channel_value = controller.selected_channel.get_untracked();
    let selected_channel_is_circle_scoped = selected_channel_info
        .as_ref()
        .is_some_and(|channel| channel.scope_circle.is_some());
    let channels = controller.channels;
    let selected_channel = controller.selected_channel;
    let reply_to_message = controller.reply_to_message;
    let chat_draft = controller.draft;
    let _compose_dragover = controller.compose_dragover;
    let _compose_upload_status = controller.compose_upload_status;
    let mention_picker_state = controller.mention_picker_state;
    let _attachment_menu_open = controller.attachment_menu_open;
    let _poll_draft = controller.poll_draft;
    let _poll_cards = controller.poll_cards;
    let messages = controller.messages;
    let is_online = controller.is_online;
    let status_msg = controller.status_msg;
    let _sidecar_send_pending = controller.sidecar_send_pending;
    let composer_scope = if !mentions_enabled {
        arkret_sdk::AgentMentionComposerScope::Direct
    } else if selected_channel_is_circle_scoped {
        arkret_sdk::AgentMentionComposerScope::Circle
    } else {
        arkret_sdk::AgentMentionComposerScope::Realm
    };

    let plaintext_modes = interaction_modes.clone();
    let _encrypted_modes = interaction_modes.clone();
    let participants_for_plaintext_sidecar = participants_for_messages.clone();
    let _participants_for_encrypted_sidecar = participants_for_messages.clone();
    let plaintext_sidecar_authority = sidecar_authority.clone();
    let plaintext_sidecar_did = sidecar_did.clone();
    let _secure_sidecar_authority = sidecar_authority.clone();
    let _secure_sidecar_did = sidecar_did.clone();

    let send = {
        let base = base_url.clone();
        let realm = selected_realm_id.clone();
        let actor = principal_id.clone();
        let sidecar_device_id = device_id.clone();
        move || {
            let authority_for_sidecar = plaintext_sidecar_authority.clone();
            let did_for_sidecar = plaintext_sidecar_did.clone();
            let device_id_for_sidecar = sidecar_device_id.clone();
            let body = chat_draft.get().trim().to_owned();
            if body.is_empty() && controller.attachments.get_untracked().is_empty() {
                return;
            }
            let inserted_candidates = mention_picker_state
                .get()
                .bound_candidates(&chat_draft.get());
            let mentions =
                composer_mention_nodes(mentions_enabled, &body, &inserted_candidates, &actor);
            let channel = channels
                .get()
                .iter()
                .find(|candidate| candidate.strand_id == selected_channel.get())
                .cloned();
            let Some(channel) = channel else {
                {
                    let next_value = "select a discussion first".to_owned();
                    status_msg.revise(|value| *value = next_value);
                };
                return;
            };
            let route = composer_agent_mode_route(
                composer_scope,
                &mentions,
                &participants_for_plaintext_sidecar,
                &authority_for_sidecar,
                &inserted_candidates,
                &plaintext_modes,
            );
            if route == arkret_sdk::AgentMentionRoute::BlockedMixedPrivateTargets {
                {
                    let next_value = "Agent modes are unknown or these targets cannot share a scope. Keep the draft and edit the mentions; private Circle requests require a separate Realm draft.".to_owned();
                    status_msg.revise(|value| *value = next_value);
                };
                return;
            }
            let targets_owned_agent = route == arkret_sdk::AgentMentionRoute::Sidecar;
            if targets_owned_agent {
                {
                    let next_value = true;
                    sidecar_route_pending.revise(|value| *value = next_value);
                };
                {
                    let next_value = "Activating Private Sidecar…".to_owned();
                    status_msg.revise(|value| *value = next_value);
                };
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
                        api_token: token.get(),
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
                        draft_at_send: chat_draft.get(),
                        participants: participants_for_plaintext_sidecar.clone(),
                    },
                );
                return;
            }
            let local_id = new_chat_local_id();
            messages.revise(|value| {
                value.push(ChatMessage {
                    protocol_content: None,
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
                    reply_to: reply_to_message.get(),
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
                })
            });

            // Continue into the ordinary submit path while
            // offline: EventSubmitter persists the stable SDK
            // Event in Garth before its first network attempt.
            // Queue status and replay both come from that one
            // durable source.
            let offline_now = !is_online.get() || !navigator_online();
            if offline_now {
                if is_online.get_untracked() {
                    {
                        let next_value = false;
                        is_online.revise(|value| *value = next_value);
                    };
                }
                {
                    let next_value = crate::i18n::tr("chat.outbox.queued_offline");
                    status_msg.revise(|value| *value = next_value);
                };
            }

            let base = base.clone();
            let realm = realm.clone();
            let api_token = token.get();
            let actor = actor.clone();
            let strand_id = channel.strand_id.clone();
            let reply_to = reply_to_message.get();
            // Clear the picker chip list now that
            // we've folded the mentions into the
            // pending send state.
            mention_picker_state.revise(|value| value.clear());
            let wait_for = None;
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
                    shared_agent_targets: composer_shared_agent_targets(
                        composer_scope,
                        &mentions,
                        &participants_for_plaintext_sidecar,
                        &inserted_candidates,
                    ),
                    mentions,
                },
            );
            controller.update_draft(String::new());
            {
                let next_value = None;
                reply_to_message.revise(|value| *value = next_value);
            };
        }
    };
    send();
}
pub(super) fn secure(
    app: Rc<crate::presentation::InksonContext>,
    controller: ChatController,
    context: ChatComposerContext,
) {
    let ChatComposerContext {
        sidecar_route_pending,
        selected_channel_info,
        circle_display: _,
        circle_encrypted: _,
        authority: sidecar_authority,
        did: sidecar_did,
        principal_id,
        account_display_label: _,
        participants: participants_for_messages,
        selected_realm_id,
        device_id,
        selected_channel_security_encrypted: _,
        selected_realm_pending_mls_binding,
        selected_realm_pending_mls_binding_reason,
        send_readiness_checking: _,
        active_sidecar_session,
        sidecar_send_block_reason: _,
        public_agent_ids: _,
        interaction_modes,
        mention_insert_request: _,
        mentions_enabled,
        token,
        frontier_state,
    } = context;
    let principal_id = principal_id.as_str().to_owned();
    let base_url = app.base_url.get_untracked();
    let sidecar_session = app.hosted_sidecar;
    let _state_store = app.state_store.clone();
    let messages_snapshot = controller.messages.get_untracked();
    let _messages_for_composer_lookup = &messages_snapshot;
    let selected_channel_value = controller.selected_channel.get_untracked();
    let selected_channel_is_circle_scoped = selected_channel_info
        .as_ref()
        .is_some_and(|channel| channel.scope_circle.is_some());
    let channels = controller.channels;
    let _selected_channel = controller.selected_channel;
    let reply_to_message = controller.reply_to_message;
    let chat_draft = controller.draft;
    let _compose_dragover = controller.compose_dragover;
    let _compose_upload_status = controller.compose_upload_status;
    let mention_picker_state = controller.mention_picker_state;
    let _attachment_menu_open = controller.attachment_menu_open;
    let _poll_draft = controller.poll_draft;
    let _poll_cards = controller.poll_cards;
    let messages = controller.messages;
    let _is_online = controller.is_online;
    let status_msg = controller.status_msg;
    let sidecar_send_pending = controller.sidecar_send_pending;
    let composer_scope = if !mentions_enabled {
        arkret_sdk::AgentMentionComposerScope::Direct
    } else if selected_channel_is_circle_scoped {
        arkret_sdk::AgentMentionComposerScope::Circle
    } else {
        arkret_sdk::AgentMentionComposerScope::Realm
    };

    let _plaintext_modes = interaction_modes.clone();
    let encrypted_modes = interaction_modes.clone();
    let _participants_for_plaintext_sidecar = participants_for_messages.clone();
    let participants_for_encrypted_sidecar = participants_for_messages.clone();
    let _plaintext_sidecar_authority = sidecar_authority.clone();
    let _plaintext_sidecar_did = sidecar_did.clone();
    let secure_sidecar_authority = sidecar_authority.clone();
    let secure_sidecar_did = sidecar_did.clone();

    let send = {
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
        move || {
            let authority_for_sidecar = secure_sidecar_authority.clone();
            let did_for_sidecar = secure_sidecar_did.clone();
            let device_id_for_sidecar = sidecar_device_id.clone();
            let body = chat_draft.get().trim().to_owned();
            if body.is_empty() && controller.attachments.get_untracked().is_empty() {
                {
                    let next_value = "Type a message before secure send".to_owned();
                    status_msg.revise(|value| *value = next_value);
                };
                return;
            }
            let inserted_candidates = mention_picker_state
                .get()
                .bound_candidates(&chat_draft.get());
            let mentions =
                composer_mention_nodes(mentions_enabled, &body, &inserted_candidates, &actor);
            let realm = realm.clone();
            let actor = actor.clone();
            if selected_strand.trim().is_empty() {
                {
                    let next_value =
                        "Default Strand is unavailable until its accepted projection arrives"
                            .to_owned();
                    status_msg.revise(|value| *value = next_value);
                };
                return;
            }
            let strand_id = selected_strand.clone();
            let route = composer_agent_mode_route(
                composer_scope,
                &mentions,
                &participants_for_encrypted_sidecar,
                &authority_for_sidecar,
                &inserted_candidates,
                &encrypted_modes,
            );
            if route == arkret_sdk::AgentMentionRoute::BlockedMixedPrivateTargets {
                {
                    let next_value = "Agent modes are unknown or these targets cannot share a scope. Keep the draft and edit the mentions; private Circle requests require a separate Realm draft.".to_owned();
                    status_msg.revise(|value| *value = next_value);
                };
                return;
            }
            let active_sidecar_for_send =
                sidecar_session_for_draft(route, active_sidecar_session.as_ref()).cloned();
            let targets_owned_agent = route == arkret_sdk::AgentMentionRoute::Sidecar
                && active_sidecar_for_send.is_none();
            if targets_owned_agent {
                {
                    let next_value = true;
                    sidecar_route_pending.revise(|value| *value = next_value);
                };
                {
                    let next_value = "Activating Private Sidecar…".to_owned();
                    status_msg.revise(|value| *value = next_value);
                };
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
                        api_token: token.get(),
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
                        draft_at_send: chat_draft.get(),
                        participants: participants_for_encrypted_sidecar.clone(),
                    },
                );
                return;
            }
            if let Some(session) = active_sidecar_for_send {
                if sidecar_send_pending.get() {
                    return;
                }
                if !session.membership_ready() {
                    {
                        let next_value = "Private Sidecar MLS access is not ready".to_owned();
                        status_msg.revise(|value| *value = next_value);
                    };
                    return;
                }
                let addressed_agent_ids = sidecar_request_targets(
                    mentions_enabled,
                    &mentions,
                    &participants_for_encrypted_sidecar,
                    &actor,
                );
                if addressed_agent_ids.is_empty() {
                    {
                        let next_value =
                            "Select an Agent with @ before sending this private message".to_owned();
                        status_msg.revise(|value| *value = next_value);
                    };
                    return;
                }
                let local_id = new_chat_local_id();
                let source_strand_id = session.source_strand_id.clone();
                let base = base.clone();
                let api_token = token.get();
                let source_event_id = latest_source_event_anchor(
                    &messages.get(),
                    &session.source_realm_id,
                    &session.source_strand_id,
                );
                commands::send_sidecar_message(
                    controller,
                    commands::SidecarSendRequest {
                        base_url: base,
                        api_token,
                        session,
                        addressed_agent_ids,
                        draft_at_send: chat_draft.get(),
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
            if pending_mls_binding {
                {
                    let next_value = pending_mls_binding_reason.clone().unwrap_or_else(|| {
                        "epoch_update_required: membership frontier changed; MLS commit required"
                            .to_owned()
                    });
                    status_msg.revise(|value| *value = next_value);
                };
                return;
            }
            // P2: preserve the composer's reply target on the
            // encrypted path (it was silently dropped before).
            let reply_to = reply_to_message
                .get()
                .filter(|value| !value.trim().is_empty());
            let message_id = new_chat_local_id();
            messages.revise(|value| {
                value.push(ChatMessage {
                    protocol_content: None,
                    local_scope: channels
                        .get()
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
                })
            });
            mention_picker_state.revise(|value| value.clear());
            controller.update_draft(String::new());
            {
                let next_value = None;
                reply_to_message.revise(|value| *value = next_value);
            };
            let base = base.clone();
            let realm = realm.clone();
            let actor = actor.clone();
            let did = device_id.clone();
            let api_token = token.get();
            let wait_for = None;
            let backup_trigger_signal = Some(app.needs_mls_backup);
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
                    shared_agent_targets: composer_shared_agent_targets(
                        composer_scope,
                        &mentions,
                        &participants_for_encrypted_sidecar,
                        &inserted_candidates,
                    ),
                    mentions,
                    backup_trigger_signal,
                },
            );
        }
    };
    send();
}
pub(super) fn poll(
    app: Rc<crate::presentation::InksonContext>,
    controller: ChatController,
    context: ChatComposerContext,
) {
    let ChatComposerContext {
        sidecar_route_pending: _,
        selected_channel_info,
        circle_display: _,
        circle_encrypted: _,
        authority: sidecar_authority,
        did: sidecar_did,
        principal_id,
        account_display_label: _,
        participants: participants_for_messages,
        selected_realm_id,
        device_id,
        selected_channel_security_encrypted: _,
        selected_realm_pending_mls_binding: _,
        selected_realm_pending_mls_binding_reason: _,
        send_readiness_checking: _,
        active_sidecar_session: _,
        sidecar_send_block_reason: _,
        public_agent_ids: _,
        interaction_modes,
        mention_insert_request: _,
        mentions_enabled,
        token,
        frontier_state: _,
    } = context;
    let principal_id = principal_id.as_str().to_owned();
    let base_url = app.base_url.get_untracked();
    let _sidecar_session = app.hosted_sidecar;
    let _state_store = app.state_store.clone();
    let messages_snapshot = controller.messages.get_untracked();
    let _messages_for_composer_lookup = &messages_snapshot;
    let selected_channel_value = controller.selected_channel.get_untracked();
    let selected_channel_is_circle_scoped = selected_channel_info
        .as_ref()
        .is_some_and(|channel| channel.scope_circle.is_some());
    let _channels = controller.channels;
    let _selected_channel = controller.selected_channel;
    let _reply_to_message = controller.reply_to_message;
    let _chat_draft = controller.draft;
    let _compose_dragover = controller.compose_dragover;
    let _compose_upload_status = controller.compose_upload_status;
    let _mention_picker_state = controller.mention_picker_state;
    let _attachment_menu_open = controller.attachment_menu_open;
    let poll_draft = controller.poll_draft;
    let poll_cards = controller.poll_cards;
    let messages = controller.messages;
    let _is_online = controller.is_online;
    let status_msg = controller.status_msg;
    let _sidecar_send_pending = controller.sidecar_send_pending;
    let _composer_scope = if !mentions_enabled {
        arkret_sdk::AgentMentionComposerScope::Direct
    } else if selected_channel_is_circle_scoped {
        arkret_sdk::AgentMentionComposerScope::Circle
    } else {
        arkret_sdk::AgentMentionComposerScope::Realm
    };

    let _plaintext_modes = interaction_modes.clone();
    let _encrypted_modes = interaction_modes.clone();
    let _participants_for_plaintext_sidecar = participants_for_messages.clone();
    let _participants_for_encrypted_sidecar = participants_for_messages.clone();
    let _plaintext_sidecar_authority = sidecar_authority.clone();
    let _plaintext_sidecar_did = sidecar_did.clone();
    let _secure_sidecar_authority = sidecar_authority.clone();
    let _secure_sidecar_did = sidecar_did.clone();

    let send = {
        let base = base_url.clone();
        let realm = selected_realm_id.clone();
        let actor = principal_id.clone();
        let selected_strand = selected_channel_value.clone();
        let protection = super::poll_submission::PollSubmissionContext {
            authority: sidecar_authority.clone(),
            device_id: device_id.clone(),
            circle_id: selected_channel_info
                .as_ref()
                .and_then(|channel| channel.scope_circle.as_ref())
                .map(|scope| scope.circle_id.clone()),
        };
        move || {
            let Some(draft_snapshot) = poll_draft.get().clone() else {
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
                    crate::operation::LocalOperationId::from_holder_key(poll_id.clone()),
                ),
                Err(error) => {
                    {
                        let next_value = format!("Poll send failed: {error}");
                        status_msg.revise(|value| *value = next_value);
                    };
                    return;
                }
            };
            // The Message id is `retype(event_id)`, so it exists
            // only once the poll Event is accepted. The optimistic
            // card is keyed by the holder-local operation id until
            // then, and the author-owned plaintext sidecar is keyed
            // by the accepted id inside the submit arm below.
            let card =
                crate::messaging::polls::PollCard::from_draft(poll_id.clone(), &draft_snapshot);
            // Optimistic UI: surface the
            // poll card immediately, then push
            // a synthetic ChatMessage so chat
            // renders it in place.
            poll_cards.revise(|value| value.push(card));
            messages.revise(|value| {
                value.push(ChatMessage {
                    protocol_content: None,
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
                })
            });
            {
                let next_value = None;
                poll_draft.revise(|value| *value = next_value);
            };

            commands::send_poll(
                controller,
                base.clone(),
                token.get(),
                op,
                protection.clone(),
                poll_id.clone(),
                realm.clone(),
                selected_strand.clone(),
            );
        }
    };
    send();
}
