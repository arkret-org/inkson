#[cfg(target_arch = "wasm32")]
use super::message_actions::menu_items;
use super::*;

#[derive(Clone, PartialEq)]
struct BodyState {
    redacted: bool,
    blocked: bool,
    protocol: Option<AuthenticatedMessageContent>,
    body: String,
    format: Option<arkret_sdk::TextFormat>,
    mentions: Vec<MentionNode>,
    base: String,
}

pub(super) fn command_context(
    context: &timeline_surface::ChatTimelineContext,
    private: bool,
) -> ChatCommandContext {
    ChatCommandContext {
        base_url: context.base_url.clone(),
        authority: context.authority.clone(),
        principal_id: context.principal_id.clone(),
        device_id: context.device_id.clone(),
        selected_realm_id: context.selected_realm_id.clone(),
        selected_channel_id: context.selected_channel_id.clone(),
        selected_channel_security_encrypted: context.selected_channel_security_encrypted,
        token: context.token,
        frontier_state: context.frontier_state,
        known_agent_accounts: context
            .participants
            .iter()
            .filter(|participant| participant.is_agent)
            .filter_map(participant_mention_account)
            .collect(),
        private_agent_scope: context.direct_mode || private,
    }
}

fn is_private(message: &ChatMessage, context: &timeline_surface::ChatTimelineContext) -> bool {
    context.private_sidecar_event_ids.contains(&message.id)
}

fn dispatch(
    action: MessageMenuAction,
    controller: ChatController,
    row: Cage<ChatMessage>,
    context: Bond<timeline_surface::ChatTimelineContext>,
) {
    let message = row.get_untracked();
    let context = context.get_untracked();
    let private = is_private(&message, &context);
    if private && action != MessageMenuAction::PrivateSave {
        return;
    }
    if message.redacted
        && matches!(
            action,
            MessageMenuAction::Reply
                | MessageMenuAction::React
                | MessageMenuAction::Edit
                | MessageMenuAction::Report
                | MessageMenuAction::Redact
        )
    {
        return;
    }
    let command = command_context(&context, private);
    match action {
        MessageMenuAction::Reply => {
            if let Some(target) = message.reply_target_ref() {
                controller.begin_reply(target.into());
            }
        }
        MessageMenuAction::React => controller.toggle_reaction_picker(message.id),
        MessageMenuAction::Edit => controller.begin_edit(message.id, message.body),
        MessageMenuAction::SharedPin => controller.toggle_shared_pin(
            command,
            message.realm_id.clone(),
            message.strand_id.clone(),
            message.pin_saved_target_ref().into(),
        ),
        MessageMenuAction::PrivateSave => {
            controller.save_message_private(command, message.pin_saved_target_ref().into())
        }
        MessageMenuAction::Report => {
            let scope = arkret_sdk::RealmId::new(message.realm_id.clone())
                .ok()
                .and_then(
                    |realm_id| match context.strand_scope_lookup.get(&message.strand_id) {
                        Some(circle) => arkret_sdk::CircleId::new(circle.circle_id.clone())
                            .ok()
                            .map(|circle_id| arkret_sdk::ScopeRef::Circle {
                                realm_id,
                                circle_id,
                            }),
                        None => Some(arkret_sdk::ScopeRef::Realm { realm_id }),
                    },
                );
            if let Some(scope) = scope {
                let target = message.pin_saved_target_ref().to_owned();
                controller.begin_moderation_report(message.realm_id, scope, target);
            }
        }
        MessageMenuAction::Redact => controller.confirm_redaction(message.id),
    }
    if !matches!(
        action,
        MessageMenuAction::SharedPin | MessageMenuAction::PrivateSave
    ) {
        controller.close_message_menu();
    }
}

fn entries(
    scope: &Scope,
    app: Rc<crate::presentation::InksonContext>,
    controller: ChatController,
    row: Cage<ChatMessage>,
    context: Bond<timeline_surface::ChatTimelineContext>,
    private: bool,
    redacted: bool,
) -> Vec<MessageMenuEntry> {
    let mut actions = Vec::new();
    if !redacted && !private {
        actions.extend([
            MessageMenuAction::Reply,
            MessageMenuAction::React,
            MessageMenuAction::Edit,
        ]);
    }
    if !private {
        actions.push(MessageMenuAction::SharedPin);
    }
    actions.push(MessageMenuAction::PrivateSave);
    if !redacted && !private {
        actions.extend([MessageMenuAction::Report, MessageMenuAction::Redact]);
    }
    actions
        .into_iter()
        .map(|action| {
            let label_app = app.clone();
            let label =
                scope.bond(move || {
                    let message = row.get();
                    let target = message.pin_saved_target_ref();
                    let key =
                        match action {
                            MessageMenuAction::Reply => "chat.button.reply",
                            MessageMenuAction::React => "chat.button.react",
                            MessageMenuAction::Edit => "common.edit",
                            MessageMenuAction::SharedPin => {
                                if controller.shared_pins.get().iter().any(|pin| {
                                    pin.target_ref == target || pin.target_ref == message.id
                                }) {
                                    "message.shared_unpin"
                                } else {
                                    "message.shared_pin"
                                }
                            }
                            MessageMenuAction::PrivateSave => {
                                if controller.private_saved_targets.get().contains(target) {
                                    "message.private_saved"
                                } else {
                                    "message.private_save"
                                }
                            }
                            MessageMenuAction::Report => "moderation.report.action",
                            MessageMenuAction::Redact => "chat.button.redact",
                        };
                    label_app.tr(key)
                });
            let enabled = scope.bond(move || {
                let message = row.get();
                match action {
                    MessageMenuAction::Reply => message.reply_target_ref().is_some(),
                    MessageMenuAction::PrivateSave => !controller
                        .private_saved_targets
                        .get()
                        .contains(message.pin_saved_target_ref()),
                    MessageMenuAction::Report => arkret_sdk::RealmId::new(message.realm_id).is_ok(),
                    _ => true,
                }
            });
            let _ = context;
            MessageMenuEntry {
                action,
                label: label.into(),
                enabled: enabled.into(),
            }
        })
        .collect()
}

pub(super) fn message_row(
    scope: &Scope,
    app: Rc<crate::presentation::InksonContext>,
    controller: ChatController,
    row: Cage<ChatMessage>,
    context: Bond<timeline_surface::ChatTimelineContext>,
    boundary: MessageMenuBoundary,
) -> View {
    let phase = scope.bond(move || {
        let message = row.get();
        let context = context.get();
        (is_private(&message, &context), message.redacted)
    });
    crate::presentation::widgets::reactive_distinct(phase, move |scope, (private, redacted)| {
        row_surface(
            scope,
            app.clone(),
            controller,
            row,
            context,
            private,
            redacted,
            boundary,
        )
    })
}

fn row_surface(
    scope: &Scope,
    app: Rc<crate::presentation::InksonContext>,
    controller: ChatController,
    row: Cage<ChatMessage>,
    context: Bond<timeline_surface::ChatTimelineContext>,
    private: bool,
    redacted: bool,
    boundary: MessageMenuBoundary,
) -> View {
    use super::native::{block, button};
    use crate::presentation::widgets::{empty, line, paragraph, plain, reactive_distinct};
    let id = row.get_untracked().id;
    let dropdown_open = scope.cage(false);
    let context_open = scope.cage(false);
    scope.effect(move || {
        let active = controller.message_context_menu.get();
        if active.as_deref() != Some(row.get_untracked().id.as_str()) {
            dropdown_open.revise(|value| *value = false);
            context_open.revise(|value| *value = false);
        }
    });
    let action: Rc<dyn Fn(MessageMenuAction)> =
        Rc::new(move |action| dispatch(action, controller, row, context));
    let changed = Rc::new(move |open| {
        if open {
            context_open.revise(|value| *value = false);
            controller
                .message_context_menu
                .revise(|value| *value = Some(row.get_untracked().id));
        } else if !context_open.get_untracked() {
            controller.close_message_menu();
        }
    });
    let overflow = message_actions_menu(
        scope,
        MessageActionsMenuProps {
            key: format!("message-actions-{}", scope.id().slot()),
            label: app.translated(scope, "message.actions").into(),
            open: dropdown_open,
            entries: entries(
                scope,
                app.clone(),
                controller,
                row,
                context,
                private,
                redacted,
            ),
            on_open_change: changed,
            on_action: action.clone(),
            boundary: Some(boundary),
        },
    );
    let class = scope.bond(move || {
        let message = row.get();
        let context = context.get();
        let own = is_own_message_sender(&message.sender, context.principal_id.as_str());
        let pinned = controller.shared_pins.get().iter().any(|pin| {
            pin.target_ref == message.pin_saved_target_ref() || pin.target_ref == message.id
        });
        let mut class = "discussion-message chat-message chat-message-row".to_owned();
        if own {
            class.push_str(" is-own");
        }
        if message.failed {
            class.push_str(" is-failed");
        }
        if message.crypto_state.is_pending() {
            class.push_str(" is-crypto-pending");
        }
        if pinned {
            class.push_str(" is-pinned");
        }
        if !context.focus_message_id.is_empty() && context.focus_message_id == message.id {
            class.push_str(" is-highlighted chat-highlighted-message");
        }
        if private {
            class.push_str(" is-private-sidecar");
        }
        if !private && context.strand_scope_lookup.contains_key(&message.strand_id) {
            class.push_str(" has-circle-accent-rail");
        }
        class
    });
    let head_app = app.clone();
    let head_source = scope.bond(move || (head_app.state_revision.get(), row.get(), context.get()));
    let head_app = app.clone();
    let head = crate::presentation::widgets::reactive(
        head_source,
        move |scope, (_, message, context)| {
            let own = is_own_message_sender(&message.sender, context.principal_id.as_str());
            let participant = context
                .participants
                .iter()
                .find(|participant| participant.principal_id.as_str() == message.sender);
            let agent = participant.is_some_and(|participant| participant.is_agent)
                || message.actor_id.as_ref().is_some_and(|actor| {
                    arkret_sdk::EventId::new(message.id.clone()).is_ok_and(|event| {
                        head_app.state_store.read(|store| {
                        crate::identity::agent_signer_evidence::verified_historical_agent_author(
                            &event,
                            &message.realm_id,
                            actor,
                            store,
                        )
                    })
                    })
                });
            let mut parts = vec![paragraph(
                "name",
                sender_display_label(
                    &message.sender,
                    context.principal_id.as_str(),
                    &context.account_display_label,
                    &context.participants,
                ),
            )];
            if own {
                parts.push(crate::components::self_attribution_badge(
                    scope,
                    head_app.clone(),
                    crate::components::SelfAttributionBadgeProps {
                        class: Some("message-self-badge".into()),
                        test_id: None,
                    },
                ));
            }
            if agent {
                parts.push(paragraph(
                    "badge member-badge member-badge-agent",
                    head_app.translated(scope, "member.badge.agent"),
                ));
            }
            if let Some(owner) = participant
                .and_then(|participant| agent_controller_label(participant, &context.participants))
            {
                parts.push(paragraph(
                    "agent-owner-label message-agent-owner",
                    format!("agent of {owner}"),
                ));
            }
            if let Some(agent) = act_on_behalf_agent_label(
                &message.sender,
                message.executed_by.as_deref(),
                &context.participants,
            ) {
                parts.push(paragraph(
                    "agent-via-label message-act-on-behalf-via",
                    format!("via {agent}"),
                ));
            }
            if private {
                parts.push(line("message-privacy-badge message-privacy-badge--sidecar message-private-sidecar-badge",vec![crate::components::ui_icon("lock"),plain(head_app.translated(scope,"chat.message.private_sidecar.label"))]));
            } else if context.sidecar_active {
                parts.push(paragraph("message-provenance-badge message-provenance-badge--shared message-original-strand-badge","Original Strand"));
            }
            parts.push(paragraph("message-time", message.timestamp.clone()));
            if own && message.failed {
                parts.push(paragraph(
                    "message-status-icon is-failed message-send-status",
                    "!",
                ));
            } else if own && message.pending {
                let queued = head_app
                    .state_store
                    .read(|store| {
                        crate::event_submit::pending_chat_message_identities(
                            &controller.queued_outbound_local_operation_ids.get(),
                            &store.load(),
                        )
                    })
                    .iter()
                    .any(|id| message.matches_id_or_protocol(id));
                parts.push(if queued {
                    paragraph(
                        "message-status-icon is-queued-offline message-send-status",
                        "⏸",
                    )
                } else {
                    block(
                        "message-status-icon is-pending message-send-status",
                        Vec::new(),
                    )
                });
            }
            if message.edited {
                parts.push(paragraph(
                    "badge message-write-status",
                    format!(
                        "{} ({})",
                        head_app.tr("chat.message.revised"),
                        message.revisions.len()
                    ),
                ));
            }
            line("msg-head", parts)
        },
    );
    let crypto_app = app.clone();
    let crypto = reactive_distinct(
        scope.bond(move || row.get().crypto_state),
        move |scope, state| {
            let (class, key) = match state {
                MessageCryptoState::Plaintext => return empty(),
                MessageCryptoState::Decrypting => (
                    "crypto-status-row crypto-status-decrypting",
                    "chat.crypto.decrypting",
                ),
                MessageCryptoState::KeyMissing => (
                    "crypto-status-row crypto-status-key-missing",
                    "chat.crypto.key_missing",
                ),
                MessageCryptoState::NeedsVerification => (
                    "crypto-status-row crypto-status-needs-verification",
                    "chat.crypto.needs_verification",
                ),
            };
            let mut parts = vec![
                paragraph(
                    "crypto-status-icon",
                    if matches!(state, MessageCryptoState::KeyMissing) {
                        "🔑"
                    } else {
                        "⚠"
                    },
                ),
                plain(crypto_app.translated(scope, key)),
            ];
            if matches!(state, MessageCryptoState::KeyMissing) {
                parts.push(paragraph(
                    "muted",
                    crypto_app.translated(scope, "chat.crypto.key_missing_hint"),
                ));
            }
            line(class, parts)
        },
    );
    let reply = reactive_distinct(
        scope.bond(move || {
            let message = row.get();
            let context = context.get();
            message.reply_to.as_ref().map(|reply| {
                chat_reply_quote_preview(
                    &context.visible_messages.get(),
                    reply,
                    context.principal_id.as_str(),
                    &context.account_display_label,
                    &context.participants,
                )
            })
        }),
        move |_, reply| match reply {
            None => empty(),
            Some(Some((name, body))) => block(
                "chat-reply-quote chat-reply-indicator",
                vec![
                    paragraph("chat-reply-quote-name", name),
                    paragraph("chat-reply-quote-body", body),
                ],
            ),
            Some(None) => paragraph(
                "chat-reply-quote chat-reply-quote-missing chat-reply-indicator",
                "Replying to a message",
            ),
        },
    );
    let body_state = scope.bond(move || {
        let message = row.get();
        let context = context.get();
        let blocked = message.actor_id.as_ref().is_some_and(|actor| {
            crate::account_data::message_actor_is_blocked(actor, &context.blocked_actor_ids)
        }) && !controller.blocked_show_anyway.get().contains(&message.id);
        BodyState {
            redacted: message.redacted,
            blocked,
            protocol: message.protocol_content,
            body: message.body,
            format: message.content_format,
            mentions: message.mentions,
            base: context.base_url,
        }
    });
    let body_app = app.clone();
    let body = reactive_distinct(body_state, move |scope, state: BodyState| {
        if state.redacted {
            return paragraph(
                "msg-content redacted chat-redacted-tombstone",
                "[Message redacted]",
            );
        }
        if state.blocked {
            return block(
                "msg-content muted message-blocked-row",
                vec![
                    plain(body_app.translated(scope, "message.blocked_user")),
                    button(
                        body_app.translated(scope, "message.show_anyway"),
                        "secondary message-blocked-show-anyway",
                        true,
                        move || controller.show_blocked_message(row.get_untracked().id),
                    ),
                ],
            );
        }
        let content = if let Some(source) = state.protocol {
            super::attachment_renderer::render_protocol_content(
                scope,
                body_app.clone(),
                &source,
                &state.mentions,
                &state.base,
            )
        } else {
            render_message_body(
                scope,
                body_app.clone(),
                &state.body,
                state.format,
                &state.mentions,
                &state.base,
            )
        };
        block("msg-content event-body", vec![content])
    });
    let reactions = reactive_distinct(
        scope.bond(move || row.get().reactions),
        move |_, reactions| {
            if reactions.is_empty() {
                empty()
            } else {
                line(
                    "actions chat-chip-row chat-reactions",
                    reactions
                        .into_iter()
                        .map(|(emoji, senders)| {
                            paragraph("badge", format!("{emoji} {}", senders.len()))
                        })
                        .collect(),
                )
            }
        },
    );
    let retry_app = app.clone();
    let error = reactive_distinct(
        scope.bond(move || {
            let message = row.get();
            (!private && message.failed, message.error)
        }),
        move |scope, (failed, error)| {
            if !failed {
                return empty();
            };
            let command_context = context;
            line(
                "message-error-row chat-message-error",
                vec![
                    paragraph("message-error-mark", "!"),
                    paragraph(
                        "message-error-text",
                        error.unwrap_or_else(|| "Message send failed".into()),
                    ),
                    button(
                        retry_app.translated(scope, "common.retry"),
                        "secondary message-retry-button chat-retry-button",
                        true,
                        move || {
                            let message = row.get_untracked();
                            let current = command_context.get_untracked();
                            controller
                                .retry_message(command_context_for(&current, &message), message);
                        },
                    ),
                ],
            )
        },
    );
    let indicator = reactive_distinct(
        scope.bond(move || {
            let message = row.get();
            (
                controller.shared_pins.get().iter().any(|pin| {
                    pin.target_ref == message.pin_saved_target_ref() || pin.target_ref == message.id
                }),
                controller
                    .private_saved_targets
                    .get()
                    .contains(message.pin_saved_target_ref()),
            )
        }),
        move |_, (pinned, saved)| {
            let mut parts = Vec::new();
            if pinned {
                parts.push(button(
                    "Pinned",
                    "message-pin-indicator message-pinned-button",
                    true,
                    move || controller.toggle_message_menu(row.get_untracked().id),
                ));
            }
            if saved {
                parts.push(Box::new(
                    view()
                        .class("message-private-saved-indicator")
                        .fill(crate::components::ui_icon("check")),
                ));
            }
            line("message-indicators", parts)
        },
    );
    let accent = reactive_distinct(
        scope.bond(move || {
            let message = row.get();
            if private {
                None
            } else {
                context
                    .get()
                    .strand_scope_lookup
                    .get(&message.strand_id)
                    .cloned()
            }
        }),
        move |_, circle| {
            circle
                .map(|circle| {
                    Box::new(view().class("circle-accent-rail").name(format!(
                        "This message is part of the Circle named {}",
                        circle.title
                    ))) as View
                })
                .unwrap_or_else(empty)
        },
    );
    let polls = poll_card(
        scope,
        app.clone(),
        controller,
        row,
        context,
        body_state,
        private,
    );
    let editor = edit_controls(scope, app.clone(), controller, row, context, private);
    let receipt_app = app.clone();
    let receipt_revision = app.state_revision;
    let receipt = crate::presentation::widgets::reactive(
        scope.bond(move || {
            (
                receipt_revision.get(),
                row.get().protocol_message_id,
                row.get().actor_id,
                context.get().selected_channel_id,
            )
        }),
        move |scope, (..)| {
            let message = row.get_untracked();
            let current = context.get_untracked();
            let (display, policy) = receipt_app.state_store.read(|store| {
                (
                    chat_visible_read_receipt_should_display(
                        store,
                        &current.selected_channel_id,
                        &current.selected_realm_id,
                    ),
                    message
                        .protocol_content
                        .as_ref()
                        .and_then(|target| store.current_read_receipt_policy(&target.scope).ok()),
                )
            });
            crate::views::read_receipts::read_receipt_indicator(
                scope,
                receipt_app.clone(),
                crate::views::read_receipts::ReadReceiptIndicatorProps {
                    realm_id: current.selected_realm_id,
                    strand_id: current.selected_channel_id,
                    message_id: message.protocol_message_id,
                    target_author: message.actor_id,
                    viewer: arkret_sdk::ActorId::account(current.authority),
                    display,
                    policy,
                },
            )
        },
    );
    let promoted_app = app.clone();
    let promoted = reactive_distinct(
        scope.bond(move || {
            controller
                .promoted_targets
                .get()
                .get(&row.get().id)
                .cloned()
        }),
        move |_, target| {
            let Some(target) = target else { return empty() };
            let realm = context.get_untracked().selected_realm_id;
            let context = promoted_app.clone();
            let route = Route::Chat {
                realm_id: realm,
                message: String::new(),
            };
            Box::new(
                crate::presentation::widgets::internal_link()
                    .target(route.to_string())
                    .fill(text().content(format!(
                        "Discussion moved to private Strand {}",
                        short_protocol_id(&target)
                    )))
                    .on(glory::render::EventKind::Activate, move |_| {
                        context.navigate(route.clone())
                    }),
            ) as View
        },
    );
    let Ok(identity) =
        glory::render::SemanticId::new(format!("chat-message-{}", presentation_key(&id)))
    else {
        return paragraph(
            "message-error",
            "This message has an invalid presentation identity.",
        );
    };
    let surface = view()
        .class(class)
        .semantics(Some(Box::new(glory::render::Semantics {
            id: Some(identity),
            ..Default::default()
        })))
        .fill(vec![
            accent,
            block(
                "msg-body",
                vec![
                    indicator, head, crypto, reply, body, reactions, error, overflow, receipt,
                    polls, promoted, editor,
                ],
            ),
        ]);
    #[cfg(target_arch = "wasm32")]
    let on_context = move |open| {
        context_open.revise(|value| *value = open);
        if open {
            dropdown_open.revise(|value| *value = false);
            controller
                .message_context_menu
                .revise(|value| *value = Some(row.get_untracked().id));
        } else if !dropdown_open.get_untracked() {
            controller.close_message_menu();
        }
    };
    #[cfg(target_arch = "wasm32")]
    return Box::new(
        sapid::context_menu(format!("message-context-{}", scope.id().slot()))
            .unstyled()
            .class("message-context-menu")
            .label(app.translated(scope, "message.actions"))
            .target_name("Message")
            .open(context_open)
            .on_open_change(on_context)
            .items(menu_items(
                entries(scope, app, controller, row, context, private, redacted),
                action,
            ))
            .target(surface),
    );
    #[cfg(not(target_arch = "wasm32"))]
    Box::new(surface)
}

pub(super) fn presentation_key(identity: &str) -> String {
    arkret_sdk::canonical::sha256_hex(identity.as_bytes())
}

fn command_context_for(
    context: &timeline_surface::ChatTimelineContext,
    message: &ChatMessage,
) -> ChatCommandContext {
    command_context(context, is_private(message, context))
}

fn poll_card(
    scope: &Scope,
    app: Rc<crate::presentation::InksonContext>,
    controller: ChatController,
    row: Cage<ChatMessage>,
    context: Bond<timeline_surface::ChatTimelineContext>,
    body: Bond<BodyState>,
    private: bool,
) -> View {
    use super::native::{block, button};
    use crate::presentation::widgets::{empty, line, paragraph, reactive_distinct};
    let card = scope.bond(move || {
        let body = body.get();
        if body.redacted || body.blocked {
            return None;
        };
        let message = row.get();
        controller.poll_cards.get().into_iter().find(|card| {
            poll_card_matches_render_ids(card, &message.id, message.protocol_message_id.as_deref())
        })
    });
    reactive_distinct(card, move |_, card| {
        let Some(card) = card else { return empty() };
        let total = card.total_votes();
        let voted = card.actor_has_voted(&arkret_sdk::ActorId::account(
            context.get_untracked().authority,
        ));
        let mut parts = vec![
            paragraph("poll-question poll-question-text", card.question.clone()),
            paragraph(
                "poll-state",
                if card.provisional {
                    app.tr("poll_provisional")
                } else if card.closed {
                    "closed".into()
                } else {
                    "open".into()
                },
            ),
        ];
        for (index, option) in card.options.iter().enumerate() {
            let label = option.label.clone();
            let control = if !card.closed && !private {
                let poll_ref = card.poll_ref.clone();
                let id = card.message_id.clone();
                let option = option.id.clone();
                button(
                    label,
                    "secondary poll-option poll-vote-button",
                    !card.provisional && poll_ref.is_some(),
                    move || {
                        if let Some(reference) = poll_ref.clone() {
                            controller.vote_poll(
                                command_context(&context.get_untracked(), false),
                                id.clone(),
                                reference,
                                option.clone(),
                            );
                        }
                    },
                )
            } else {
                Box::new(text().class("poll-option-label").content(label)) as View
            };
            parts.push(line(
                "poll-result-row",
                vec![
                    control,
                    Box::new(
                        text()
                            .class("poll-vote-count")
                            .content(card.votes_for(index).to_string()),
                    ),
                ],
            ));
        }
        if !card.closed && !private {
            let id = card.message_id;
            parts.push(button(
                "Close poll",
                "secondary poll-close-button",
                true,
                move || controller.close_poll(id.clone()),
            ));
        }
        parts.push(paragraph(
            "poll-total poll-total-votes",
            format!("{total} votes"),
        ));
        if voted {
            parts.push(paragraph("poll-results-summary", "Thanks for voting."));
        }
        block("poll-card message-event-poll", parts)
    })
}

fn edit_controls(
    scope: &Scope,
    app: Rc<crate::presentation::InksonContext>,
    controller: ChatController,
    row: Cage<ChatMessage>,
    context: Bond<timeline_surface::ChatTimelineContext>,
    private: bool,
) -> View {
    use super::native::{block, button, field};
    use crate::presentation::widgets::{empty, line, paragraph, reactive_distinct};
    if private {
        return empty();
    };
    let phase = scope.bond(move || {
        let id = row.get().id;
        (
            !row.get().redacted && controller.reaction_picker.get().as_ref() == Some(&id),
            !row.get().redacted && controller.editing_message.get().as_ref() == Some(&id),
            !row.get().redacted && controller.redact_confirm.get().as_ref() == Some(&id),
        )
    });
    reactive_distinct(phase, move |_, (reactions, editing, redact)| {
        let mut parts = Vec::new();
        if reactions {
            parts.push(line(
                "actions chat-chip-row chat-reaction-picker",
                CHAT_EMOJI_GRID
                    .iter()
                    .copied()
                    .map(|emoji| {
                        button(emoji, "secondary emoji-button", true, move || {
                            let message = row.get_untracked();
                            controller.add_reaction(
                                command_context_for(&context.get_untracked(), &message),
                                message.id.clone(),
                                message.mutation_target_ref().to_owned(),
                                emoji.to_owned(),
                            );
                        })
                    })
                    .collect(),
            ));
        }
        if editing {
            parts.push(block(
                "composer compact-composer chat-edit-composer",
                vec![
                    field(
                        app.tr("common.edit"),
                        "chat-edit-draft",
                        controller.edit_draft,
                        true,
                        move |value| controller.update_edit_draft(value),
                    ),
                    line(
                        "actions",
                        vec![
                            button("Save", "primary chat-save-edit-button", true, move || {
                                let message = row.get_untracked();
                                controller.revise_message(
                                    command_context_for(&context.get_untracked(), &message),
                                    message.id.clone(),
                                    message.mutation_target_ref().to_owned(),
                                    controller.edit_draft.get_untracked(),
                                );
                            }),
                            button("Cancel", "secondary", true, move || {
                                controller.cancel_edit()
                            }),
                        ],
                    ),
                ],
            ));
        }
        if redact {
            parts.push(block(
                "chat-redact-confirm",
                vec![
                    paragraph("discussion-subhead", "Remove message"),
                    line(
                        "actions",
                        vec![
                            button(
                                "Confirm",
                                "primary chat-confirm-redact-button",
                                true,
                                move || {
                                    let message = row.get_untracked();
                                    controller.redact_message(
                                        command_context_for(&context.get_untracked(), &message),
                                        message,
                                    );
                                },
                            ),
                            button("Cancel", "secondary", true, move || {
                                controller.cancel_redaction()
                            }),
                        ],
                    ),
                ],
            ));
        }
        if parts.is_empty() {
            empty()
        } else {
            block("message-edit-controls", parts)
        }
    })
}
