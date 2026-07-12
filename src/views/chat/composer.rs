use super::*;

#[derive(Clone, PartialEq)]
pub(super) struct ChatComposerContext {
    pub embedded: bool,
    pub selected_channel_info: Option<ChannelEntity>,
    pub account_did: String,
    pub account_display_label: String,
    pub participants: Vec<SpaceParticipant>,
    pub selected_realm_id: String,
    pub device_id: String,
    pub plaintext_service_id: String,
    pub selected_channel_security_encrypted: bool,
    pub selected_realm_pending_mls_binding: bool,
    pub sidecar_send_block_reason: Option<String>,
    pub public_agent_dids: std::collections::BTreeSet<String>,
    pub own_controller_handle: Option<String>,
    pub mention_insert_request: Option<Signal<Option<MentionInsertRequest>>>,
    pub token: Signal<String>,
    pub sync_cursor: Signal<String>,
    pub frontier_state: Signal<String>,
}

#[component]
pub(super) fn ChatComposer(controller: ChatController, context: ChatComposerContext) -> Element {
    let ChatComposerContext {
        embedded,
        selected_channel_info,
        account_did,
        account_display_label,
        participants: participants_for_messages,
        selected_realm_id,
        device_id,
        plaintext_service_id,
        selected_channel_security_encrypted,
        selected_realm_pending_mls_binding,
        sidecar_send_block_reason,
        public_agent_dids,
        own_controller_handle,
        mention_insert_request,
        token,
        sync_cursor,
        mut frontier_state,
    } = context;
    let base_url = crate::app::SessionContext::base_url_string();
    let navigator = use_navigator();
    let mut sidecar_session = use_context::<crate::sidecar::SidecarSessionContext>().0;
    let mut state_store = crate::app::SessionContext::get().state_store;
    let messages_snapshot = (controller.messages)();
    let messages_for_composer_lookup = &messages_snapshot;
    let selected_channel_value = (controller.selected_channel)();
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
    let mut mention_insert_request_seen = use_signal(String::new);
    let typing_throttle = controller.typing_throttle;
    let composer_class = "discussion-composer";
    let visible_channels_empty = channels.read().is_empty();
    let send_secure_variant = if selected_channel_security_encrypted {
        ButtonVariant::Primary
    } else {
        ButtonVariant::Secondary
    };
    let send_secure_testid = if selected_channel_security_encrypted {
        "send-chat-button"
    } else {
        "send-e2ee-move-button"
    };
    let send_secure_label = if selected_channel_security_encrypted {
        crate::i18n::tr("chat.send")
    } else {
        crate::i18n::tr("chat.send_secure")
    };
    let sidecar_send_blocked = sidecar_send_block_reason.is_some();
    let participants_for_plaintext_sidecar = participants_for_messages.clone();
    let participants_for_encrypted_sidecar = participants_for_messages.clone();

    {
        let mut request_signal = mention_insert_request;
        let request_participants = participants_for_messages.clone();
        let request_account_did = account_did.clone();
        let request_public_agent_dids = public_agent_dids.clone();
        let request_controller_handle = own_controller_handle.clone();
        use_effect(move || {
            let Some(request_signal) = request_signal.as_mut() else {
                return;
            };
            let Some(request) = request_signal() else {
                return;
            };
            if mention_insert_request_seen.peek().as_str() == request.request_id {
                return;
            }
            let Some(participant) = request_participants
                .iter()
                .find(|participant| participant.did.trim() == request.target_id.trim())
            else {
                return;
            };
            let Some(candidate) = mention_candidate_for_explicit_target(
                participant,
                &request_participants,
                &request_account_did,
                &request_public_agent_dids,
                request.agent_slug.as_deref(),
                request_controller_handle.as_deref(),
            ) else {
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
        });
    }

    rsx! {
            if !visible_channels_empty {
            div { class: "{composer_class}", "data-testid": "chat-composer",
                // AKP-0007 P3B.2.3 — Circle composer banner. Rendered
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
                            &account_did,
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
                            spawn(async move {
                                let api = match crate::transport::auth::authed_api_with_sync(
                                    &base,
                                    api_token,
                                    None,
                                ) {
                                    Ok(api) => api,
                                    Err(err) => {
                                        compose_upload_status.set(format!(
                                            "{}: {err}",
                                            crate::i18n::tr("compose.upload_error"),
                                        ));
                                        return;
                                    }
                                };
                                let clients = match api.sdk_http_client() {
                                    Ok(http) => crate::transport::EndpointClients::from_http(http),
                                    Err(err) => {
                                        compose_upload_status.set(format!(
                                            "{}: {err}",
                                            crate::i18n::tr("compose.upload_error"),
                                        ));
                                        return;
                                    }
                                };
                                let mut ok_count = 0usize;
                                let mut last_error: Option<String> = None;
                                for file in files {
                                    let filename = file.name();
                                    let content_type = file
                                        .content_type()
                                        .unwrap_or_else(|| "application/octet-stream".to_owned());
                                    let bytes = match file.read_bytes().await {
                                        Ok(b) => b.to_vec(),
                                        Err(err) => {
                                            last_error = Some(format!("{err}"));
                                            continue;
                                        }
                                    };
                                    match clients
                                        .blob()
                                        .upload_bytes_scoped(
                                            bytes,
                                            &content_type,
                                            Some(&realm),
                                            Some(&filename),
                                        )
                                        .await
                                    {
                                        Ok(resp) => {
                                            let current = chat_draft();
                                            let needs_space = !current.is_empty()
                                                && !current.ends_with(' ')
                                                && !current.ends_with('\n');
                                            let attachment = format!(
                                                "{}[Attachment: {}]",
                                                if needs_space { " " } else { "" },
                                                resp.blob_ref
                                            );
                                            chat_draft.set(format!("{current}{attachment}"));
                                            ok_count += 1;
                                        }
                                        Err(err) => {
                                            last_error = Some(err.to_string());
                                        }
                                    }
                                }
                                if let Some(err) = last_error {
                                    compose_upload_status.set(format!(
                                        "{}: {err}",
                                        crate::i18n::tr("compose.upload_error"),
                                    ));
                                } else if ok_count > 0 {
                                    compose_upload_status.set(format!(
                                        "{ok_count} attachment(s) uploaded"
                                    ));
                                } else {
                                    compose_upload_status.set(
                                        crate::i18n::tr("compose.upload_error"),
                                    );
                                }
                            });
                        }
                    },
                    Textarea {
                        "data-testid": "chat-input",
                        value: "{chat_draft}",
                        placeholder: "Message this discussion. Use @alice:example.com to mention a member or #task-123 to link a card.",
                        onkeydown: move |event: KeyboardEvent| {
                            let key = event.key().to_string();
                            let modifiers = event.modifiers();
                            if (modifiers.ctrl() || modifiers.meta()) && key == "Enter" {
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
                            let actor = account_did.clone();
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
                                    crate::messaging::mentions::active_mention_token_at_end(&value)
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
                                let actor = actor.clone();
                                let device = typing_device_id.clone();
                                let strand_id = if selected_strand.trim().is_empty() {
                                    default_discussion_strand_id(&realm)
                                } else {
                                    selected_strand.clone()
                                };
                                typing_throttle.on_keystroke(move |is_typing| {
                                    let base = base.clone();
                                    let realm = realm.clone();
                                    let actor = actor.clone();
                                    let device = device.clone();
                                    let strand_id = strand_id.clone();
                                    let api_token = token();
                                    spawn(async move {
                                        let _ = crate::transport::auth::with_event_submitter(
                                            &base,
                                            api_token,
                                            |sub| async move {
                                                sub.send_typing(
                                                    &realm,
                                                    &actor,
                                                    &device,
                                                    &strand_id,
                                                    is_typing,
                                                )
                                                .await
                                            },
                                        ).await;
                                    });
                                });
                            }
                        },
                    }
                    if mention_picker_state.read().open {
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
                                        .filter(|p| agent_candidate_is_visible(p, &public_agent_dids, &account_did))
                                        .filter_map(|p| mention_candidate_for_participant(
                                            p,
                                            &participants_for_messages,
                                            &account_did,
                                        ))
                                        .collect();
                                candidates.sort_by_key(|candidate| {
                                    if candidate.did.trim() == account_did.trim() {
                                        0u8
                                    } else if candidate.is_agent
                                        && candidate.controller_subject_id.trim()
                                            == account_did.trim()
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
                                                        candidate.did.trim() == account_did.trim();
                                                    let candidate_agent_slug = candidate
                                                        .is_agent
                                                        .then(|| candidate.agent_slug_at_time.clone());
                                                    rsx! {
                                                        Button {
                                                            variant: ButtonVariant::Secondary,
                                                            key: "{candidate.did}",
                                                            r#type: "button",
                                                            class: "mention-suggestion",
                                                            "data-testid": "mention-suggestion",
                                                            "data-mention-did": "{candidate.did}",
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
                        if crate::messaging::polls::polls_enabled() {
                            Button {
                                variant: ButtonVariant::Secondary,
                                r#type: "button",
                                class: "composer-tool-button",
                                "data-testid": "open-poll-composer-button",
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
                        if attachment_menu_open() {
                            div { class: "attachment-menu",
                                if crate::messaging::polls::polls_enabled() {
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        r#type: "button",
                                        class: "attachment-menu-item",
                                        "data-testid": "attachment-menu-poll",
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
                        for chip in mention_picker_state.read().inserted.clone() {
                            div {
                                class: "mention-chip",
                                "data-testid": "mention-chip",
                                "data-mention-did": "{chip.did}",
                                span { "@{chip.insert_label()}" }
                                if !chip.subtitle.is_empty() {
                                    span { class: "mention-chip-subtitle", "{chip.subtitle}" }
                                }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    r#type: "button",
                                    onclick: {
                                        let did = chip.did.clone();
                                        move |_| mention_picker_state.write().remove(&did)
                                    },
                                    "\u{00d7}"
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
                if crate::messaging::polls::polls_enabled() {
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
                                "data-testid": "poll-create-button",
                                disabled: !draft.is_sendable(),
                                onclick: {
                                    let base = base_url.clone();
                                    let realm = selected_realm_id.clone();
                                    let actor = account_did.clone();
                                    let selected_strand = selected_channel_value.clone();
                                    move |_| {
                                        let Some(draft_snapshot) = poll_draft.read().clone() else {
                                            return;
                                        };
                                        if !draft_snapshot.is_sendable() {
                                            return;
                                        }
                                        let poll_id = crate::messaging::polls::new_poll_id();
                                        // Build the canonical poll_block op up front (synchronous)
                                        // so the optimistic card can adopt the stamped wire
                                        // message id — the identity later
                                        // `poll_response.poll_ref` votes point at.
                                        let op = match crate::messaging::polls::build_poll_create_op(
                                            &realm,
                                            &actor,
                                            &selected_strand,
                                            &draft_snapshot,
                                        ) {
                                            Ok(op) => op,
                                            Err(error) => {
                                                status_msg.set(format!("Poll send failed: {error}"));
                                                return;
                                            }
                                        };
                                        let message_ref = crate::messaging::polls::poll_message_ref(&op);
                                        let mut card = crate::messaging::polls::PollCard::from_draft(
                                            poll_id.clone(),
                                            &draft_snapshot,
                                        );
                                        if let Some(message_ref) = message_ref.clone() {
                                            card.poll_id = message_ref;
                                        }
                                        // Optimistic UI: surface the
                                        // poll card immediately, then push
                                        // a synthetic ChatMessage so chat
                                        // renders it in place.
                                        poll_cards.write().push(card);
                                        messages.write().push(ChatMessage {
                                            realm_id: realm.clone(),
                                            id: poll_id.clone(),
                                            protocol_message_id: message_ref,
                                            sender: actor.clone(),
                                            executed_by: None,
                                            body: format!("[poll] {}", draft_snapshot.question),
                                            timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                                            created_at: Some(chrono::Utc::now()),
                                            strand_id: selected_strand.clone(),
                                            reply_to: None,
                                            reactions: Vec::new(),
                                            redacted: false,
                                            edited: false,
                                            revisions: Vec::new(),
                                            pending: true,
                                            failed: false,
                                            error: None,
                                            mentions: Vec::new(),
                                            crypto_state: MessageCryptoState::Plaintext,
                                        });
                                        poll_draft.set(None);

                                        let base = base.clone();
                                        let api_token = token();
                                        let poll_id_for_status = poll_id.clone();
                                        spawn(async move {
                                            match crate::transport::auth::with_authed_api(
                                                &base,
                                                api_token,
                                                |api| async move { api.event_submitter()?.submit_sdk_event(&op).await },
                                            )
                                            .await
                                            {
                                                Ok(_) => {
                                                    if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == poll_id_for_status) {
                                                        found.pending = false;
                                                        found.failed = false;
                                                        found.error = None;
                                                    }
                                                    status_msg.set("Poll sent".to_owned());
                                                }
                                                Err(error) => {
                                                    let error_text = error.display();
                                                    if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == poll_id_for_status) {
                                                        found.pending = false;
                                                        found.failed = true;
                                                        found.error = Some(format!("Poll send failed: {error_text}"));
                                                    }
                                                    status_msg.set(format!("Poll send failed: {error_text}"));
                                                }
                                            }
                                        });
                                    }
                                },
                                "Send poll"
                            }
                            // Cotest also references `send-poll-button`
                            // — wire it to the same handler so both
                            // testids resolve.
                            Button {
                                variant: ButtonVariant::Secondary,
                                r#type: "button",
                                "data-testid": "send-poll-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let realm = selected_realm_id.clone();
                                    let actor = account_did.clone();
                                    let selected_strand = selected_channel_value.clone();
                                    move |_| {
                                        let Some(draft_snapshot) = poll_draft.read().clone() else {
                                            return;
                                        };
                                        if !draft_snapshot.is_sendable() {
                                            return;
                                        }
                                        let poll_id = crate::messaging::polls::new_poll_id();
                                        // Same canonical poll_block flow as the primary
                                        // `poll-create-button` handler above.
                                        let op = match crate::messaging::polls::build_poll_create_op(
                                            &realm,
                                            &actor,
                                            &selected_strand,
                                            &draft_snapshot,
                                        ) {
                                            Ok(op) => op,
                                            Err(error) => {
                                                status_msg.set(format!("Poll send failed: {error}"));
                                                return;
                                            }
                                        };
                                        let message_ref = crate::messaging::polls::poll_message_ref(&op);
                                        let mut card = crate::messaging::polls::PollCard::from_draft(
                                            poll_id.clone(),
                                            &draft_snapshot,
                                        );
                                        if let Some(message_ref) = message_ref.clone() {
                                            card.poll_id = message_ref;
                                        }
                                        poll_cards.write().push(card);
                                        messages.write().push(ChatMessage {
                                            realm_id: realm.clone(),
                                            id: poll_id.clone(),
                                            protocol_message_id: message_ref,
                                            sender: actor.clone(),
                                            executed_by: None,
                                            body: format!("[poll] {}", draft_snapshot.question),
                                            timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                                            created_at: Some(chrono::Utc::now()),
                                            strand_id: selected_strand.clone(),
                                            reply_to: None,
                                            reactions: Vec::new(),
                                            redacted: false,
                                            edited: false,
                                            revisions: Vec::new(),
                                            pending: true,
                                            failed: false,
                                            error: None,
                                            mentions: Vec::new(),
                                            crypto_state: MessageCryptoState::Plaintext,
                                        });
                                        poll_draft.set(None);

                                        let base = base.clone();
                                        let api_token = token();
                                        let poll_id_for_status = poll_id.clone();
                                        spawn(async move {
                                            match crate::transport::auth::with_authed_api(
                                                &base,
                                                api_token,
                                                |api| async move { api.event_submitter()?.submit_sdk_event(&op).await },
                                            )
                                            .await
                                            {
                                                Ok(_) => {
                                                    if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == poll_id_for_status) {
                                                        found.pending = false;
                                                        found.failed = false;
                                                        found.error = None;
                                                    }
                                                    status_msg.set("Poll sent".to_owned());
                                                }
                                                Err(error) => {
                                                    let error_text = error.display();
                                                    if let Some(found) = messages.write().iter_mut().find(|candidate| candidate.id == poll_id_for_status) {
                                                        found.pending = false;
                                                        found.failed = true;
                                                        found.error = Some(format!("Poll send failed: {error_text}"));
                                                    }
                                                    status_msg.set(format!("Poll send failed: {error_text}"));
                                                }
                                            }
                                        });
                                    }
                                },
                                "Send"
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
                div { class: "actions",
                    if !selected_channel_security_encrypted {
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "send-chat-button",
                        disabled: sidecar_send_blocked,
                        onclick: {
                            let base = base_url.clone();
                            let service_id = plaintext_service_id.clone();
                            let realm = selected_realm_id.clone();
                            let actor = account_did.clone();
                            let own_controller_handle = own_controller_handle.clone();
                            let navigator = navigator.clone();
                            move |_| {
                                let own_controller_handle = own_controller_handle.clone();
                                let body = chat_draft().trim().to_owned();
                                if body.is_empty() {
                                    return;
                                }
                                if let Err(error) = chat_content_block_for_body(&body) {
                                    status_msg.set(format!("Message send failed: {error:#}"));
                                    return;
                                }
                                let mentions = composer_mention_nodes(
                                    &body,
                                    &mention_picker_state.read().inserted,
                                    &actor,
                                );
                                let channel = channels()
                                    .iter()
                                    .find(|candidate| candidate.strand_id == selected_channel())
                                    .cloned();
                                let Some(channel) = channel else {
                                    status_msg.set("select a discussion first".to_owned());
                                    return;
                                };
                                let targets_owned_agent = !selected_channel_is_circle_scoped
                                    && (!owned_agent_ids_from_mentions(&mentions, &actor).is_empty()
                                        || parse_agent_selector_mention_tokens(&body)
                                            .iter()
                                            .any(|token| token.controller_handle == "me"));
                                if targets_owned_agent {
                                    status_msg.set("Opening private AI sidecar thread…".to_owned());
                                    let trace_id = uuid_v7();
                                    tracing::info!(
                                        target: "sidecar",
                                        event = "sidecar.route.requested",
                                        trace_id = %trace_id,
                                        source_realm_id = %realm,
                                        source_strand_id = %channel.strand_id,
                                    );
                                    let base = base.clone();
                                    let api_token = token();
                                    let realm = realm.clone();
                                    let actor = actor.clone();
                                    let strand_id = channel.strand_id.clone();
                                    let body_for_resolution = body.clone();
                                    let own_controller_handle = own_controller_handle.clone();
                                    let wait_for = active_sync_token(sync_cursor());
                                    let mut resolved_mentions = mentions;
                                    let participants_for_sidecar =
                                        participants_for_plaintext_sidecar.clone();
                                    let navigator = navigator.clone();
                                    spawn(async move {
                                        for mention in resolve_agent_selector_mentions(
                                            &base,
                                            api_token.clone(),
                                            wait_for,
                                            &body_for_resolution,
                                            &realm,
                                            &actor,
                                            own_controller_handle.as_deref(),
                                        )
                                        .await
                                        {
                                            push_unique_mention_node(
                                                &mut resolved_mentions,
                                                mention,
                                            );
                                        }
                                        match ensure_owned_agent_sidecar(
                                            &base,
                                            api_token,
                                            &trace_id,
                                            &actor,
                                            &realm,
                                            &strand_id,
                                            &resolved_mentions,
                                        )
                                        .await
                                        {
                                            Ok(Some(sidecar)) => {
                                                let addressed_agent_ids = owned_agent_ids_from_mentions(
                                                    &resolved_mentions,
                                                    &actor,
                                                );
                                                let addressed_agent_label = sidecar_agent_label(
                                                    &addressed_agent_ids,
                                                    &participants_for_sidecar,
                                                );
                                                status_msg.set(
                                                    "Private AI sidecar opened; the message has not been sent."
                                                        .to_owned(),
                                                );
                                                sidecar_session.set(Some(crate::sidecar::SidecarSession {
                                                    trace_id,
                                                    controller_id: actor.clone(),
                                                    addressed_agent_ids,
                                                    addressed_agent_label,
                                                    source_realm_id: realm.clone(),
                                                    source_strand_id: strand_id,
                                                    private_circle_id: sidecar.private_circle_id.to_string(),
                                                    private_strand_id: sidecar.private_strand_id.to_string(),
                                                    private_relation_id: sidecar.private_relation_id.to_string(),
                                                    pending_member_reconciliations: sidecar.pending_member_reconciliations.clone(),
                                                    migrated_draft: body_for_resolution,
                                                    opened_at: chrono::Utc::now(),
                                                }));
                                                let _ = navigator.push(Route::DirectConversation {
                                                    realm_id: realm,
                                                    strand_id: sidecar.private_strand_id.to_string(),
                                                });
                                            }
                                            Ok(None) => status_msg.set(
                                                "Could not resolve an owned agent for the private sidecar."
                                                    .to_owned(),
                                            ),
                                            Err(error) => status_msg.set(format!(
                                                "Could not open private AI sidecar: {error:#}"
                                            )),
                                        }
                                    });
                                    return;
                                }
                                let local_id = new_chat_message_id();
                                messages.write().push(ChatMessage {
                                    realm_id: realm.clone(),
                                    id: local_id.clone(),
                                    protocol_message_id: Some(local_id.clone()),
                                    sender: actor.clone(),
                                    executed_by: None,
                                    body: body.clone(),
                                    timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                                    created_at: Some(chrono::Utc::now()),
                                    strand_id: channel.strand_id.clone(),
                                    reply_to: reply_to_message(),
                                    reactions: Vec::new(),
                                    redacted: false,
                                    edited: false,
                                    revisions: Vec::new(),
                                    pending: true,
                                    failed: false,
                                    error: None,
                                    mentions: mentions.clone(),
                                    // Local-only sends start plaintext;
                                    // the Send Secure strand may upgrade
                                    // them via a separate `messages.write()`
                                    // patch after `encrypt_payload`.
                                    crypto_state: MessageCryptoState::Plaintext,
                                });

                                // Continue into the ordinary submit path while
                                // offline: EventSubmitter persists the stable SDK
                                // Event in Garth before its first network attempt.
                                // The old chat-specific localStorage outbox is now
                                // read-only compatibility for entries created by
                                // earlier releases.
                                let offline_now = !is_online() || !navigator_online();
                                if offline_now {
                                    if *is_online.peek() {
                                        is_online.set(false);
                                    }
                                    status_msg.set(crate::i18n::tr("chat.outbox.queued_offline"));
                                }

                                let base = base.clone();
                                let service_id = service_id.clone();
                                let realm = realm.clone();
                                let api_token = token();
                                let actor = actor.clone();
                                let strand_id = channel.strand_id.clone();
                                let channel_kind = channel.kind.clone();
                                let message_id = local_id.clone();
                                let reply_to = reply_to_message();
                                // Clear the picker chip list now that
                                // we've folded the mentions into the
                                // pending send state.
                                mention_picker_state.write().clear();
                                let realm_for_record = realm.clone();
                                let actor_for_store = actor.clone();
                                let body_for_store = body.clone();
                                let body_for_restore = body.clone();
                                let body_for_resolve = body.clone();
                                let strand_id_for_store = strand_id.clone();
                                let message_id_for_store = message_id.clone();
                                let reply_to_for_store = reply_to.clone();
                                let projection = state_store
                                    .read()
                                    .load()
                                    .realm_tree_projections
                                    .get(&realm)
                                    .cloned();
                                let plaintext_services =
                                    plaintext_services_for_policy(projection.as_ref(), &service_id);
                                let wait_for = active_sync_token(sync_cursor());
                                let actor_for_retry = actor.clone();
                                spawn(async move {
                                    let mut mentions = mentions;
                                    for mention in resolve_agent_selector_mentions(
                                        &base,
                                        api_token.clone(),
                                        wait_for.clone(),
                                        &body_for_resolve,
                                        &realm,
                                        &actor,
                                        own_controller_handle.as_deref(),
                                    )
                                    .await
                                    {
                                        push_unique_mention_node(&mut mentions, mention);
                                    }
                                    if let Some(found) = messages
                                        .write()
                                        .iter_mut()
                                        .find(|candidate| candidate.id == local_id)
                                    {
                                        found.mentions = mentions.clone();
                                    }
                                    let mut op = match chat_message_create_operation(
                                        &realm,
                                        &actor,
                                        &strand_id,
                                        &channel_kind,
                                        &message_id,
                                        &body_for_resolve,
                                        &mentions,
                                        reply_to.as_deref(),
                                    ) {
                                        Ok(op) => op,
                                        Err(error) => {
                                            if let Some(found) = messages
                                                .write()
                                                .iter_mut()
                                                .find(|candidate| candidate.id == local_id)
                                            {
                                                found.pending = false;
                                                found.failed = true;
                                                found.error =
                                                    Some(format!("send failed: {error:#}"));
                                            }
                                            status_msg.set(format!("send failed: {error:#}"));
                                            return;
                                        }
                                    };
                                    // G3.Y2 — keep online sends and offline
                                    // replay on the same E2EE-safe notification
                                    // routing path.
                                    apply_mention_sidecar_hashes(&mut op, &realm, &mentions);
                                    let mention_values_for_store = mention_nodes_to_values(&mentions);
                                    match submit_chat_operation_with_auth_refresh(
                                        &base,
                                        &actor_for_retry,
                                        &realm,
                                        api_token,
                                        wait_for,
                                        &plaintext_services,
                                        &op,
                                    ).await {
                                        Ok(resp) => {
                                            {
                                                let mut store = state_store.write();
                                                store.append_raw_operation(
                                                    sdk_event_local_operation_id(&op).to_owned(),
                                                    Some(realm_for_record),
                                                    json!({
                                                        "event_id": resp.event_id.clone(),
                                                        "kind": "ak.message.create",
                                                        "actor_id": actor_for_store,
                                                        "body": body_for_store,
                                                        "strand_id": strand_id_for_store,
                                                        "message_id": message_id_for_store,
                                                        "mentions": mention_values_for_store,
                                                        "reply_to": reply_to_for_store,
                                                        "status": resp.status.clone(),
                                                    }),
                                                );
                                            }
                                            if let Some(found) = messages
                                                .write()
                                                .iter_mut()
                                                .find(|candidate| candidate.id == local_id)
                                            {
                                                found.id = resp.event_id.clone();
                                                found.pending = false;
                                                found.failed = false;
                                                found.error = None;
                                            }
                                            frontier_state.set(resp.event_id.clone());
                                            status_msg.set("Message sent".to_owned());
                                        }
                                        Err(error) => {
                                            if crate::event_submit::is_durably_queued_error(&error) {
                                                status_msg.set(crate::i18n::tr(
                                                    "chat.outbox.queued_offline",
                                                ));
                                                return;
                                            }
                                            let membership_denied =
                                                is_space_membership_denied_error(&error);
                                            let message = chat_send_error_message(&error);
                                            if membership_denied {
                                                messages
                                                    .write()
                                                    .retain(|candidate| candidate.id != local_id);
                                                if chat_draft().trim().is_empty() {
                                                    chat_draft.set(body_for_restore.clone());
                                                }
                                            } else if let Some(found) = messages
                                                .write()
                                                .iter_mut()
                                                .find(|candidate| candidate.id == local_id)
                                            {
                                                found.pending = false;
                                                found.failed = true;
                                                found.error = Some(message.clone());
                                            }
                                            status_msg.set(format!("Message send failed: {message}"));
                                        }
                                    }
                                });
                                chat_draft.set(String::new());
                                reply_to_message.set(None);
                            }
                        },
                        {crate::i18n::tr("chat.send")}
                    }
                    }
                    Button {
                        variant: send_secure_variant,
                        "data-testid": send_secure_testid,
                        disabled: selected_realm_pending_mls_binding || sidecar_send_blocked,
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor = account_did.clone();
                            let own_controller_handle = own_controller_handle.clone();
                            let selected_strand = selected_channel_value.clone();
                            let pending_mls_binding = selected_realm_pending_mls_binding;
                            let navigator = navigator.clone();
                            move |_| {
                                let own_controller_handle = own_controller_handle.clone();
                                if pending_mls_binding {
                                    status_msg.set(
                                        "epoch_update_required: membership frontier changed; MLS Remove commit required"
                                            .to_owned(),
                                    );
                                    return;
                                }
                                let body = chat_draft().trim().to_owned();
                                if body.is_empty() {
                                    status_msg.set("Type a message before secure send".to_owned());
                                    return;
                                }
                                let mentions = composer_mention_nodes(
                                    &body,
                                    &mention_picker_state.read().inserted,
                                    &actor,
                                );
                                let realm = realm.clone();
                                let actor = actor.clone();
                                let strand_id = if selected_strand.trim().is_empty() {
                                    default_discussion_strand_id(&realm)
                                } else {
                                    selected_strand.clone()
                                };
                                let targets_owned_agent = !selected_channel_is_circle_scoped
                                    && (!owned_agent_ids_from_mentions(&mentions, &actor).is_empty()
                                        || parse_agent_selector_mention_tokens(&body)
                                            .iter()
                                            .any(|token| token.controller_handle == "me"));
                                if targets_owned_agent {
                                    status_msg.set("Opening private AI sidecar thread…".to_owned());
                                    let trace_id = uuid_v7();
                                    tracing::info!(
                                        target: "sidecar",
                                        event = "sidecar.route.requested",
                                        trace_id = %trace_id,
                                        source_realm_id = %realm,
                                        source_strand_id = %strand_id,
                                    );
                                    let base = base.clone();
                                    let api_token = token();
                                    let wait_for = active_sync_token(sync_cursor());
                                    let realm_for_sidecar = realm.clone();
                                    let actor_for_sidecar = actor.clone();
                                    let strand_for_sidecar = strand_id.clone();
                                    let body_for_resolution = body.clone();
                                    let own_controller_handle = own_controller_handle.clone();
                                    let mut resolved_mentions = mentions;
                                    let participants_for_sidecar =
                                        participants_for_encrypted_sidecar.clone();
                                    let navigator = navigator.clone();
                                    spawn(async move {
                                        for mention in resolve_agent_selector_mentions(
                                            &base,
                                            api_token.clone(),
                                            wait_for,
                                            &body_for_resolution,
                                            &realm_for_sidecar,
                                            &actor_for_sidecar,
                                            own_controller_handle.as_deref(),
                                        )
                                        .await
                                        {
                                            push_unique_mention_node(
                                                &mut resolved_mentions,
                                                mention,
                                            );
                                        }
                                        match ensure_owned_agent_sidecar(
                                            &base,
                                            api_token,
                                            &trace_id,
                                            &actor_for_sidecar,
                                            &realm_for_sidecar,
                                            &strand_for_sidecar,
                                            &resolved_mentions,
                                        )
                                        .await
                                        {
                                            Ok(Some(sidecar)) => {
                                                let addressed_agent_ids = owned_agent_ids_from_mentions(
                                                    &resolved_mentions,
                                                    &actor_for_sidecar,
                                                );
                                                let addressed_agent_label = sidecar_agent_label(
                                                    &addressed_agent_ids,
                                                    &participants_for_sidecar,
                                                );
                                                status_msg.set(
                                                    "Private AI sidecar opened; the message has not been sent."
                                                        .to_owned(),
                                                );
                                                sidecar_session.set(Some(crate::sidecar::SidecarSession {
                                                    trace_id,
                                                    controller_id: actor_for_sidecar.clone(),
                                                    addressed_agent_ids,
                                                    addressed_agent_label,
                                                    source_realm_id: realm_for_sidecar.clone(),
                                                    source_strand_id: strand_for_sidecar,
                                                    private_circle_id: sidecar.private_circle_id.to_string(),
                                                    private_strand_id: sidecar.private_strand_id.to_string(),
                                                    private_relation_id: sidecar.private_relation_id.to_string(),
                                                    pending_member_reconciliations: sidecar.pending_member_reconciliations.clone(),
                                                    migrated_draft: body_for_resolution,
                                                    opened_at: chrono::Utc::now(),
                                                }));
                                                let _ = navigator.push(Route::DirectConversation {
                                                    realm_id: realm_for_sidecar,
                                                    strand_id: sidecar.private_strand_id.to_string(),
                                                });
                                            }
                                            Ok(None) => status_msg.set(
                                                "Could not resolve an owned agent for the private sidecar."
                                                    .to_owned(),
                                            ),
                                            Err(error) => status_msg.set(format!(
                                                "Could not open private AI sidecar: {error:#}"
                                            )),
                                        }
                                    });
                                    return;
                                }
                                // P2: preserve the composer's reply target on the
                                // encrypted path (it was silently dropped before).
                                let reply_to = reply_to_message()
                                    .filter(|value| !value.trim().is_empty());
                                let message_id = new_chat_message_id();
                                messages.write().push(ChatMessage {
                                    realm_id: realm.clone(),
                                    id: message_id.clone(),
                                    protocol_message_id: Some(message_id.clone()),
                                    sender: actor.clone(),
                                    executed_by: None,
                                    body: body.clone(),
                                    timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                                    created_at: Some(chrono::Utc::now()),
                                    strand_id: strand_id.clone(),
                                    reply_to: reply_to.clone(),
                                    reactions: Vec::new(),
                                    redacted: false,
                                    edited: false,
                                    revisions: Vec::new(),
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
                                let backup_trigger_signal =
                                    crate::components::try_needs_mls_backup_signal();
                                let base_for_backup_trigger = base.clone();
                                let token_for_backup_trigger = api_token.clone();
                                let actor_for_backup_trigger = actor.clone();
                                spawn(async move {
                                let mut mentions = mentions;
                                for mention in resolve_agent_selector_mentions(
                                    &base,
                                    api_token.clone(),
                                    wait_for.clone(),
                                    &body,
                                    &realm,
                                    &actor,
                                    own_controller_handle.as_deref(),
                                )
                                .await
                                {
                                    push_unique_mention_node(&mut mentions, mention);
                                }
                                if let Some(found) = messages
                                    .write()
                                    .iter_mut()
                                    .find(|candidate| candidate.id == message_id)
                                {
                                    found.mentions = mentions.clone();
                                }
                                // Encrypt the canonical Content Block JSON with
                                // its structured mention nodes. The UI-only
                                // `@me` alias has already resolved to the real
                                // controller handle before this content enters
                                // MLS ciphertext.
                                let actor_mentions = mentions
                                    .iter()
                                    .filter_map(|mention| mention.as_mention().cloned())
                                    .collect::<Vec<_>>();
                                let audience_mentions = mentions
                                    .iter()
                                    .filter_map(|mention| mention.as_audience_mention().cloned())
                                    .collect::<Vec<_>>();
                                let mut secure_content_block =
                                    match chat_content_block_for_body(&body) {
                                        Ok(content) => content,
                                        Err(err) => {
                                            fail_optimistic_chat_send(
                                                messages,
                                                chat_draft,
                                                status_msg,
                                                &message_id,
                                                &body,
                                                format!("Send Secure rejected message content: {err:#}"),
                                            );
                                            return;
                                        }
                                    };
                                if !actor_mentions.is_empty() {
                                    secure_content_block = match secure_content_block
                                        .with_mentions(actor_mentions)
                                    {
                                        Ok(content) => content,
                                        Err(err) => {
                                            fail_optimistic_chat_send(
                                                messages,
                                                chat_draft,
                                                status_msg,
                                                &message_id,
                                                &body,
                                                format!("Send Secure could not encode mentions: {err}"),
                                            );
                                            return;
                                        }
                                    };
                                }
                                if !audience_mentions.is_empty() {
                                    secure_content_block = match secure_content_block
                                        .with_audience_mentions(audience_mentions)
                                    {
                                        Ok(content) => content,
                                        Err(err) => {
                                            fail_optimistic_chat_send(
                                                messages,
                                                chat_draft,
                                                status_msg,
                                                &message_id,
                                                &body,
                                                format!("Send Secure could not encode audience mentions: {err}"),
                                            );
                                            return;
                                        }
                                    };
                                }
                                let secure_content_value = match sdk_payload_value(
                                    secure_content_block.to_value(),
                                    "chat encrypted content block serialize",
                                ) {
                                    Ok(value) => value,
                                    Err(err) => {
                                        fail_optimistic_chat_send(
                                            messages,
                                            chat_draft,
                                            status_msg,
                                            &message_id,
                                            &body,
                                            format!("Send Secure could not encode message content: {err:#}"),
                                        );
                                        return;
                                    }
                                };
                                let secure_content_bytes = match serde_json::to_vec(&secure_content_value) {
                                    Ok(bytes) => bytes,
                                    Err(err) => {
                                        fail_optimistic_chat_send(
                                            messages,
                                            chat_draft,
                                            status_msg,
                                            &message_id,
                                            &body,
                                            format!("Send Secure could not encode message content: {err}"),
                                        );
                                        return;
                                    }
                                };
                                let _hlc = Hlc::now("inkson").to_string();
                                let seal_view = state_store.read().seal_view_for_realm(&realm);
                                // Shared MLS core: encrypt → forced ak.mls.commit
                                // envelope (governance / prev→post epoch /
                                // policy_root / membership_frontier) → spec
                                // `ak.schema.encrypted_envelope.v1` wrap →
                                // `ak.schema.encrypted_envelopeis mirrors the
                                // shared secure send builder.
                                let secure_build = match crate::views::secure_send::build_secure_send(
                                    state_store,
                                    &seal_view,
                                    &realm,
                                    &actor,
                                    &did,
                                    &strand_id,
                                    &message_id,
                                    reply_to.as_deref(),
                                    &secure_content_bytes,
                                    None,
                                ) {
                                    Ok(build) => build,
                                    Err(message) => {
                                        fail_optimistic_chat_send(
                                            messages,
                                            chat_draft,
                                            status_msg,
                                            &message_id,
                                            &body,
                                            message,
                                        );
                                        return;
                                    }
                                };
                                let base = base.clone();
                                let realm_for_record = realm.clone();
                                let actor_for_audit = actor.clone();
                                let audit_delivered: Vec<String> = secure_build
                                    .member_dids
                                    .iter()
                                    .map(|did| did.as_str().to_owned())
                                    .collect();
                                let device_for_sidecar_backup = did.clone();
                                // X9: capture identifiers needed by the
                                // encrypted Ok(resp) arm to (A) clear the
                                // optimistic bubble's `pending` flag and (B)
                                // persist the message plaintext into the
                                // author-owned sidecar so reload / a new
                                // device can render the author's own
                                // (otherwise undecryptable) messages.
                                let message_id_for_lookup = message_id.clone();
                                let message_id_for_sidecar = message_id.clone();
                                // X10.6: also persisted into the raw_operation
                                // record below so the tab-switch / reload
                                // rebuild can reconstruct the sidecar key.
                                let message_id_for_record = message_id.clone();
                                let actor_for_record = actor.clone();
                                // The synced event carries this exact strand_id
                                // string (the payload was built with
                                // `strand_id_value(&strand_id)`, which wraps it
                                // verbatim), so the read-side sidecar lookup
                                // keyed on the event's `strand_id` matches.
                                let strand_id_for_sidecar = strand_id.clone();
                                let strand_id_for_record = strand_id.clone();
                                let body_for_sidecar = body.clone();
                                // P2: recoverable draft — if the encrypted send
                                // fails we restore the composer text instead of
                                // losing it.
                                let body_for_restore = body.clone();
                                let message_id_for_failure = message_id.clone();
                                // Capture the message op id BEFORE the build is
                                // moved into the shared submitter — the encrypted
                                // raw_operation record (X10.6 sidecar re-key) is
                                // keyed on it.
                                let msg_local_op_id =
                                    crate::operation::sdk_event_local_operation_id(
                                        &secure_build.message_event,
                                    )
                                    .to_owned();
                                spawn(async move {
                                    let Ok(api) = authed_api_with_sync(&base, api_token.clone(), wait_for) else {
                                        // P2: auth/API init failed — without this
                                        // arm the optimistic bubble spun forever
                                        // and no status was shown.
                                        fail_optimistic_chat_send(
                                            messages,
                                            chat_draft,
                                            status_msg,
                                            &message_id_for_failure,
                                            &body_for_restore,
                                            "Send Secure failed: could not start an authenticated session".to_owned(),
                                        );
                                        return;
                                    };
                                    // Shared submit: forced ak.mls.commit first
                                    // (persist-on-accept snapshot + §7.10 backup
                                    // schedule + move record), then the encrypted
                                    // ak.message.create.
                                    let outcome = crate::views::secure_send::submit_secure_send(
                                        &api,
                                        state_store,
                                        secure_build,
                                        &realm_for_record,
                                        &device_for_sidecar_backup,
                                        base.clone(),
                                        token_for_backup_trigger.clone(),
                                        actor_for_backup_trigger.clone(),
                                    )
                                    .await;
                                    let resp = match outcome {
                                        crate::views::secure_send::SecureSendOutcome::Sent {
                                            event_id,
                                            status,
                                        } => (event_id, status),
                                        crate::views::secure_send::SecureSendOutcome::CommitFailed {
                                            message,
                                        }
                                        | crate::views::secure_send::SecureSendOutcome::MessageFailed {
                                            message,
                                        } => {
                                            // P2: reconcile the optimistic bubble so
                                            // it doesn't spin forever, and keep the
                                            // draft recoverable.
                                            fail_optimistic_chat_send(
                                                messages,
                                                chat_draft,
                                                status_msg,
                                                &message_id_for_failure,
                                                &body_for_restore,
                                                message,
                                            );
                                            return;
                                        }
                                    };
                                    let (resp_event_id, resp_status) = resp;
                                    {
                                        let mut store = state_store.write();
                                        // X10.6: persist the message identity
                                        // (message_id + strand_id + actor), NOT the
                                        // plaintext body, into the raw_operation
                                        // record so the tab-switch / reload rebuild
                                        // can reconstruct the sidecar key
                                        // `message:{message_id}` under `strand_id`.
                                        // The body lives only in the account-private
                                        // `mls_private_plaintext` sidecar saved just
                                        // below. `encrypted_content` marks the row as
                                        // E2EE for readers with no sidecar (another
                                        // device / member).
                                        store.append_raw_operation(
                                            msg_local_op_id.clone(),
                                            Some(realm_for_record.clone()),
                                            json!({
                                                "event_id": resp_event_id.clone(),
                                                "kind": "ak.message.create",
                                                "actor_id": actor_for_record.clone(),
                                                "strand_id": strand_id_for_record.clone(),
                                                "message_id": message_id_for_record.clone(),
                                                "encrypted_content": true,
                                                "status": resp_status.clone(),
                                            }),
                                        );
                                        // BUG B (X9): persist the message plaintext
                                        // into the author-owned sidecar so reload / a
                                        // new device can render the author's own
                                        // encrypted messages (OpenMLS forbids an
                                        // author from decrypting their own
                                        // ciphertext). Keyed by `message:{message_id}`
                                        // under the discussion strand, sharing the
                                        // `mls_private_plaintext` map that the X5.3
                                        // cross-device backup already snapshots.
                                        store.save_private_plaintext(
                                            &realm_for_record,
                                            &strand_id_for_sidecar,
                                            &format!("message:{message_id_for_sidecar}"),
                                            &body_for_sidecar,
                                        );
                                    }
                                    // BUG A (X9): clear the optimistic bubble's
                                    // `pending` spinner now that the server accepted
                                    // the encrypted message (mirrors the plaintext
                                    // path). Reconcile the local id to the server
                                    // event_id so the synced copy dedups against this
                                    // echo.
                                    if let Some(found) = messages
                                        .write()
                                        .iter_mut()
                                        .find(|candidate| candidate.id == message_id_for_lookup)
                                    {
                                        found.id = resp_event_id.clone();
                                        found.pending = false;
                                        found.failed = false;
                                        found.error = None;
                                    }
                                    frontier_state.set(resp_event_id.clone());
                                    status_msg.set("Encrypted message sent".to_owned());
                                    crate::components::schedule_mls_private_plaintext_backup_after_encrypted_write(
                                        base_for_backup_trigger.clone(),
                                        token_for_backup_trigger.clone(),
                                        actor_for_backup_trigger.clone(),
                                        device_for_sidecar_backup.clone(),
                                        state_store,
                                    );

                                    // X11.2 — first-write trigger. After this
                                    // encrypted send landed, auto-back up the
                                    // account secret when possible; otherwise
                                    // fall back to the prompt. Best-effort.
                                    if let Some(signal) = backup_trigger_signal {
                                        crate::components::maybe_auto_backup_mls_after_encrypted_write(
                                            base_for_backup_trigger.clone(),
                                            token_for_backup_trigger.clone(),
                                            actor_for_backup_trigger.clone(),
                                            device_for_sidecar_backup.clone(),
                                            state_store,
                                            signal,
                                        )
                                        .await;
                                    }

                                    // Disclosed-audit hardening profile
                                    // (`ak.profile.disclosed_audit.e2ee.v1`): emit a
                                    // p`ak.profile.disclosed_auditceipt right after a
                                    // successful E2EE commit. Actor-private +
                                    // fire-and-forget; non-profile servers store it
                                    // as a regular operation.
                                    let audit_op = build_audit_ryw_receipt(
                                        &realm_for_record,
                                        &actor_for_audit,
                                        &resp_event_id,
                                        audit_delivered.clone(),
                                    )
                                    .build_sdk_event("inkson");
                                    // YOU-02-007: surface a silent receipt failure so
                                    // the sender knows the audit row is missing (the
                                    // message itself sent).
                                    match audit_op {
                                        Ok(audit_op) => {
                                            if let Err(err) = match api.event_submitter() {
                                                Ok(sub) => sub.submit_sdk_event(&audit_op).await,
                                                Err(err) => Err(err),
                                            }
                                            {
                                                tracing::warn!(
                                                    "audit RYW receipt for {} failed: {err:#}",
                                                    resp_event_id
                                                );
                                                status_msg.set(format!(
                                                    "Message sent; audit receipt failed: {err}"
                                                ));
                                            }
                                        }
                                        Err(err) => {
                                            tracing::warn!(
                                                "audit RYW receipt for {} failed to build: {err:#}",
                                                resp_event_id
                                            );
                                            status_msg.set(format!(
                                                "Message sent; audit receipt failed: {err}"
                                            ));
                                        }
                                    }
                                });
                                });
                            }
                        },
                        "{send_secure_label}"
                    }
                }
                if !embedded && !status_msg().is_empty() {
                    div { class: "muted discussion-status", "data-testid": "chat-status", "{status_msg}" }
                }
            }
            }
    }
}
