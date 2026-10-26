use arkret_wire::event_kind_str;

use super::*;

mod commands;
mod files;
mod send;

fn primary_send_action(
    scope: &Scope,
    label: impl Into<Lotus<String>>,
    enabled: impl Into<Lotus<bool>>,
    busy: impl Into<Lotus<bool>>,
    mut send: impl FnMut() + 'static,
) -> View {
    let busy = busy.into();
    Box::new(
        glory::ui::button()
            .label(label)
            .enabled(enabled)
            .class(scope.bond({
                let busy = busy.clone();
                move || {
                    if busy.get() {
                        "primary send-chat-button send-readiness-checking".to_owned()
                    } else {
                        "primary send-chat-button".to_owned()
                    }
                }
            }))
            .semantics(scope.bond(move || {
                Some(Box::new(glory::render::Semantics {
                    busy: Some(busy.get()),
                    ..Default::default()
                }))
            }))
            .on(glory::render::EventKind::Activate, move |_| send()),
    )
}

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

#[derive(Clone)]
pub(super) struct ChatComposerContext {
    pub sidecar_route_pending: Cage<bool>,
    pub selected_channel_info: Option<ChannelEntity>,
    pub circle_display: Option<arkret_sdk::CircleDisplay>,
    pub circle_encrypted: Option<bool>,
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
    pub send_readiness_checking: bool,
    pub active_sidecar_session: Option<crate::sidecar::HostedSidecarState>,
    pub sidecar_send_block_reason: Option<String>,
    pub public_agent_ids: std::collections::BTreeSet<String>,
    pub interaction_modes:
        std::collections::BTreeMap<arkret_sdk::AccountId, arkret_sdk::AgentInteractionMode>,
    pub mention_insert_request: Option<Cage<Option<MentionInsertRequest>>>,
    pub mentions_enabled: bool,
    pub token: Cage<String>,
    pub frontier_state: Cage<String>,
}

pub(super) fn chat_mentions_enabled(direct_mode: bool) -> bool {
    !direct_mode
}

pub(super) fn chat_composer_placeholder(mentions_enabled: bool) -> String {
    crate::i18n::tr(if mentions_enabled {
        "chat.composer.placeholder_mentions"
    } else {
        "chat.composer.placeholder_direct"
    })
}

/// Local presentation copy is keyed by the typed route, never by user text.
fn composer_scope_label(
    route: arkret_sdk::AgentMentionRoute,
    scope: arkret_sdk::AgentMentionComposerScope,
    strand: &str,
) -> String {
    if matches!(
        route,
        arkret_sdk::AgentMentionRoute::Sidecar
            | arkret_sdk::AgentMentionRoute::BlockedMixedPrivateTargets
    ) {
        return crate::i18n::tr("chat.composer.private_scope");
    }
    let key = match scope {
        arkret_sdk::AgentMentionComposerScope::Circle => "chat.composer.circle_scope",
        arkret_sdk::AgentMentionComposerScope::Direct => "chat.composer.direct_scope",
        arkret_sdk::AgentMentionComposerScope::Realm
        | arkret_sdk::AgentMentionComposerScope::Sidecar => "chat.composer.original_scope",
    };
    crate::i18n::tr_args(key, &[("strand", strand.to_owned())])
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
#[cfg(test)]
pub(super) fn chat_composer_should_send_key(
    key: &str,
    shift: bool,
    alt: bool,
    is_composing: bool,
    is_auto_repeating: bool,
) -> bool {
    key == "Enter" && !shift && !alt && !is_composing && !is_auto_repeating
}

#[cfg(test)]
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
                && !message.pending
                && !message.failed
                && message.protocol_content.as_ref().is_some_and(|content| {
                    content.source.as_str() == message.id
                        && matches!(
                            &content.scope,
                            arkret_sdk::ScopeRef::Realm { realm_id: source }
                                | arkret_sdk::ScopeRef::Circle { realm_id: source, .. }
                                if source.as_str() == realm_id
                        )
                })
                && arkret_sdk::EventId::new(message.id.clone()).is_ok()
        })
        .map(|message| message.id.clone())
}

pub(super) fn sidecar_request_targets(
    mentions_enabled: bool,
    mentions: &[MentionNode],
    participants: &[SpaceParticipant],
    principal_id: &str,
) -> Vec<String> {
    owned_agent_ids_from_composer(mentions_enabled, mentions, participants, principal_id)
}

fn sidecar_session_for_draft(
    route: arkret_sdk::AgentMentionRoute,
    session: Option<&crate::sidecar::HostedSidecarState>,
) -> Option<&crate::sidecar::HostedSidecarState> {
    session.filter(|_| route == arkret_sdk::AgentMentionRoute::Sidecar)
}

fn draft_scope_send_blocked(
    route: arkret_sdk::AgentMentionRoute,
    original_blocked: bool,
    private_blocked: bool,
) -> bool {
    match route {
        arkret_sdk::AgentMentionRoute::Sidecar => private_blocked,
        arkret_sdk::AgentMentionRoute::BlockedMixedPrivateTargets => true,
        arkret_sdk::AgentMentionRoute::Shared | arkret_sdk::AgentMentionRoute::Direct => {
            original_blocked
        }
    }
}

fn installed_sidecar_send_blocked(
    private_draft: bool,
    session_installed: bool,
    access_blocked: bool,
    gate: Option<&crate::mls::send_gate::MlsSendGate>,
) -> bool {
    private_draft
        && session_installed
        && (access_blocked
            || !matches!(gate, Some(crate::mls::send_gate::MlsSendGate::Encrypted(_))))
}

#[derive(Clone, PartialEq)]
struct Preview {
    route: arkret_sdk::AgentMentionRoute,
    scope: arkret_sdk::AgentMentionComposerScope,
    upload_scope: Option<arkret_sdk::ScopeRef>,
    plaintext: bool,
    plain_enabled: bool,
    secure_enabled: bool,
    polls_available: bool,
    polls_enabled: bool,
    schedule_available: bool,
    pending: bool,
    title: String,
}

fn draft_route(
    controller: ChatController,
    context: &ChatComposerContext,
) -> (
    arkret_sdk::AgentMentionComposerScope,
    arkret_sdk::AgentMentionRoute,
) {
    let scope = if !context.mentions_enabled {
        arkret_sdk::AgentMentionComposerScope::Direct
    } else if context
        .selected_channel_info
        .as_ref()
        .is_some_and(|channel| channel.scope_circle.is_some())
    {
        arkret_sdk::AgentMentionComposerScope::Circle
    } else {
        arkret_sdk::AgentMentionComposerScope::Realm
    };
    let text = controller.draft.get();
    let candidates = controller
        .mention_picker_state
        .get()
        .bound_candidates(&text);
    let mentions = composer_mention_nodes(
        context.mentions_enabled,
        &text,
        &candidates,
        context.principal_id.as_str(),
    );
    let route = composer_agent_mode_route(
        scope,
        &mentions,
        &context.participants,
        &context.authority,
        &candidates,
        &context.interaction_modes,
    );
    (scope, route)
}

fn preview(
    app: &crate::presentation::InksonContext,
    controller: ChatController,
    context: &ChatComposerContext,
    probe: &crate::views::secure_send::ScopeSendProbe,
) -> Preview {
    let (scope, route) = draft_route(controller, context);
    let private = route == arkret_sdk::AgentMentionRoute::Sidecar;
    let mixed = route == arkret_sdk::AgentMentionRoute::BlockedMixedPrivateTargets;
    let private_scope = sidecar_session_for_draft(route, context.active_sidecar_session.as_ref())
        .and_then(|session| {
            Some(arkret_sdk::ScopeRef::Sidecar {
                realm_id: arkret_sdk::RealmId::new(session.source_realm_id.clone()).ok()?,
                sidecar_id: session.sidecar_id.clone(),
            })
        });
    let upload_scope = if private {
        private_scope
    } else if mixed {
        None
    } else {
        context
            .selected_channel_info
            .as_ref()
            .and_then(|channel| ordinary_composer_scope(&context.selected_realm_id, channel))
    };
    let unavailable = context
        .selected_channel_info
        .as_ref()
        .is_none_or(|channel| channel.strand_id != controller.selected_channel.get())
        || !controller
            .channels
            .get()
            .iter()
            .any(|channel| channel.strand_id == controller.selected_channel.get());
    let sidecar_blocked = installed_sidecar_send_blocked(
        private,
        context.active_sidecar_session.is_some(),
        context.sidecar_send_block_reason.is_some(),
        probe.gate.as_ref(),
    );
    let text = controller.draft.get();
    let candidates = controller
        .mention_picker_state
        .get()
        .bound_candidates(&text);
    let mentions = composer_mention_nodes(
        context.mentions_enabled,
        &text,
        &candidates,
        context.principal_id.as_str(),
    );
    let target_missing = private
        && sidecar_request_targets(
            context.mentions_enabled,
            &mentions,
            &context.participants,
            context.principal_id.as_str(),
        )
        .is_empty();
    let creator_reason = if context.selected_channel_security_encrypted && !private {
        context
            .selected_channel_info
            .as_ref()
            .and_then(|channel| channel.effective_scope(&context.selected_realm_id))
            .map_or(
                Some("Waiting for the conversation's encryption scope."),
                |scope| {
                    app.state_store.read(|store| {
                        crate::mls::creator_bootstrap::creator_scope_mls_bootstrap_pending_reason(
                            store, &scope,
                        )
                    })
                },
            )
    } else {
        None
    };
    let awaiting = controller
        .attachments
        .get()
        .iter()
        .any(|attachment| attachment.pending)
        || unavailable;
    let private_blocked = sidecar_blocked
        || context.sidecar_route_pending.get()
        || controller.sidecar_send_pending.get();
    let plain_enabled = !awaiting
        && !draft_scope_send_blocked(
            route,
            context.selected_realm_pending_mls_binding,
            private_blocked,
        );
    let secure_enabled = !awaiting
        && !draft_scope_send_blocked(
            route,
            context.selected_realm_pending_mls_binding || creator_reason.is_some(),
            private_blocked || target_missing,
        );
    let title = if target_missing {
        app.tr("chat.composer.private_target_missing")
    } else if private && context.active_sidecar_session.is_none() {
        app.tr("chat.sidecar.open_and_send")
    } else if private {
        context
            .sidecar_send_block_reason
            .clone()
            .unwrap_or_else(|| app.tr("chat.composer.private_state_pending"))
    } else {
        context
            .selected_realm_pending_mls_binding_reason
            .clone()
            .unwrap_or_else(|| creator_reason.unwrap_or_default().to_owned())
    };
    Preview {
        route,
        scope,
        upload_scope,
        plaintext: !context.selected_channel_security_encrypted && !private,
        plain_enabled,
        secure_enabled,
        polls_available: !context.selected_channel_security_encrypted && !private && !mixed,
        polls_enabled: !unavailable && !context.selected_realm_pending_mls_binding,
        schedule_available: !context.selected_channel_security_encrypted
            && !private
            && !mixed
            && candidates.is_empty(),
        pending: private
            && (controller.sidecar_send_pending.get() || context.sidecar_route_pending.get()),
        title,
    }
}

pub(super) fn scheduled_send_surface(
    open: Cage<bool>,
    render: impl Fn(&Scope) -> View + 'static,
) -> View {
    crate::presentation::widgets::reactive_distinct(open, move |scope, open| {
        if open {
            render(scope)
        } else {
            crate::presentation::widgets::empty()
        }
    })
}

pub(super) fn chat_composer(
    scope: &Scope,
    app: Rc<crate::presentation::InksonContext>,
    controller: ChatController,
    context: Bond<ChatComposerContext>,
    _available: Cage<bool>,
) -> View {
    use super::native::{block, button};
    use crate::presentation::widgets::{empty, line, paragraph, plain, reactive_distinct};
    let private_scope = scope.bond(move || {
        let context = context.get();
        let (_, route) = draft_route(controller, &context);
        sidecar_session_for_draft(route, context.active_sidecar_session.as_ref()).and_then(
            |session| {
                Some(arkret_sdk::ScopeRef::Sidecar {
                    realm_id: arkret_sdk::RealmId::new(session.source_realm_id.clone()).ok()?,
                    sidecar_id: session.sidecar_id.clone(),
                })
            },
        )
    });
    let device = scope.bond(move || context.get().device_id);
    let private_probe = crate::views::secure_send::scope_send_probe(
        scope,
        app.clone(),
        private_scope.into(),
        device.into(),
    );
    let preview_app = app.clone();
    let preview = scope.bond(move || {
        preview(
            &preview_app,
            controller,
            &context.get(),
            &private_probe.get(),
        )
    });
    let upload_app = app.clone();
    scope.effect(move || {
        let preview = preview.get();
        let context = context.get();
        let key = format!(
            "{:?}|{:?}|{:?}|{}",
            preview.upload_scope,
            preview.route,
            context.interaction_modes,
            context.selected_channel_security_encrypted
        );
        if controller.attachment_target_key.get_untracked() != key {
            controller
                .attachment_target_key
                .revise(|value| *value = key);
            controller
                .attachment_target_revision
                .revise(|value| *value = value.wrapping_add(1));
            if preview.upload_scope.is_some() {
                commands::upload_dropped_attachments(
                    controller,
                    upload_app.base_url.get_untracked(),
                    context.token.get_untracked(),
                    preview.upload_scope,
                    Vec::new(),
                );
            }
        }
    });
    let request_seen = scope.cage(String::new());
    let input_node = scope.cage(None);
    let request_owner = scope.downgrade();
    scope.effect(move || {
        let context = context.get();
        let Some(request_signal) = context.mention_insert_request else {
            return;
        };
        if !context.mentions_enabled {
            request_signal.revise(|value| *value = None);
            controller
                .mention_picker_state
                .revise(|picker| picker.clear());
            return;
        }
        let Some(request) = request_signal.get() else {
            return;
        };
        if request_seen.get_untracked() == request.request_id {
            return;
        }
        let Some(candidate) = request.resolve_candidate(
            &context.participants,
            context.principal_id.as_str(),
            &context.public_agent_ids,
        ) else {
            return;
        };
        request_seen.revise(|value| *value = request.request_id);
        request_signal.revise(|value| *value = None);
        let text = controller.draft.get_untracked();
        let updated = controller.mention_picker_state.revise(|picker| {
            let updated = picker.select(candidate, &text, None);
            picker.close();
            updated
        });
        controller.update_draft(updated);
        if let Some(owner) = request_owner.upgrade()
            && let Some(node) = input_node.get_untracked()
        {
            let _ = owner.action(glory::render::Action::Focus(node));
        }
    });
    let send_app = app.clone();
    let send: Rc<dyn Fn(bool)> = Rc::new(move |secure| {
        let current = preview.get_untracked();
        if secure {
            if current.secure_enabled {
                send::secure(send_app.clone(), controller, context.get_untracked());
            }
        } else if current.plain_enabled {
            send::plaintext(send_app.clone(), controller, context.get_untracked());
        }
    });
    let keyboard_send = send.clone();
    let change_app = app.clone();
    let input = Box::new(
        sapid::text_field()
            .unstyled()
            .name("Message")
            .class("chat-input")
            .multiline(true)
            .node_ref(input_node)
            .value(controller.draft)
            .on_value_change(move |value| {
                edit_draft(
                    change_app.clone(),
                    controller,
                    &context.get_untracked(),
                    value,
                )
            })
            .on(glory::render::EventKind::Keyboard, move |event| {
                if matches!(
                    event,
                    glory::render::Event::Keyboard {
                        command: glory::render::KeyboardCommand::Submit,
                        ..
                    }
                ) {
                    keyboard_send(!preview.get_untracked().plaintext);
                }
            }),
    ) as View;
    let hint_context = context;
    let hint = reactive_distinct(
        scope.bond(move || controller.draft.get().is_empty()),
        move |scope, visible| {
            if !visible {
                return empty();
            };
            paragraph(
                "chat-input-hint",
                scope.bond(move || chat_composer_placeholder(hint_context.get().mentions_enabled)),
            )
        },
    );
    let input = block("chat-input-host", vec![input, hint]);
    let scheduled = scope.cage(false);
    let mention_app = app.clone();
    let mention_tool = reactive_distinct(
        scope.bond(move || context.get().mentions_enabled),
        move |scope, visible| {
            if !visible {
                return empty();
            }
            super::native::icon_button(
                "at-sign",
                mention_app.translated(scope, "chat.composer.mention_member"),
                "secondary composer-tool-button mention-trigger-button",
                true,
                move || {
                    controller.mention_picker_state.revise(|picker| {
                        if picker.open {
                            picker.close()
                        } else {
                            picker.open()
                        }
                    })
                },
            )
        },
    );
    let mut tools = vec![
        mention_tool,
        super::native::icon_button(
            "plus",
            app.translated(scope, "chat.composer.add_attachment"),
            "secondary composer-tool-button attachment-menu-button",
            true,
            move || {
                controller
                    .attachment_menu_open
                    .revise(|value| *value = !*value)
            },
        ),
    ];
    let menu_app = app.clone();
    let mut menu_items = vec![reactive_distinct(
        scope.bond(move || preview.get().polls_available),
        move |scope, visible| {
            if !visible {
                return empty();
            }
            button(
                menu_app.translated(scope, "chat.composer.create_poll"),
                "secondary attachment-menu-item attachment-menu-poll",
                scope.bond(move || {
                    controller.attachment_menu_open.get() && preview.get().polls_enabled
                }),
                move || {
                    controller
                        .attachment_menu_open
                        .revise(|value| *value = false);
                    controller
                        .poll_draft
                        .revise(|draft| *draft = Some(crate::messaging::polls::PollDraft::new()));
                },
            )
        },
    )];
    #[cfg(target_arch = "wasm32")]
    {
        let file_control = scope.cage(None::<sapid::FileController>);
        let selected_leases = scope.cage(0usize);
        let owner = scope.downgrade();
        let upload_app = app.clone();
        menu_items.push(Box::new(
            sapid::file_button()
                .unstyled()
                .label(app.translated(scope, "chat.composer.add_attachment"))
                .class("secondary attachment-menu-item attachment-file-picker")
                .name(app.translated(scope, "chat.composer.add_attachment"))
                .configuration(glory::render::FileConfig {
                    multiple: true,
                    drop: true,
                    max_files: 32,
                    max_file_bytes: 64 * 1024 * 1024,
                    max_total_bytes: 64 * 1024 * 1024,
                    ..Default::default()
                })
                .controller_ref(file_control)
                .enabled(scope.bond(move || {
                    controller.attachment_menu_open.get() && preview.get().upload_scope.is_some()
                        || selected_leases.get() > 0
                }))
                .on_files(move |selected| {
                    let Some(owner) = owner.upgrade() else { return };
                    let Some(control) = file_control.get_untracked() else {
                        return;
                    };
                    let files = selected
                        .into_iter()
                        .map(|file| {
                            files::AttachmentFile::selected(
                                &owner,
                                control.clone(),
                                file,
                                selected_leases,
                                _available,
                            )
                        })
                        .collect();
                    controller
                        .attachment_menu_open
                        .revise(|value| *value = false);
                    commands::upload_dropped_attachments(
                        controller,
                        upload_app.base_url.get_untracked(),
                        context.get_untracked().token.get_untracked(),
                        preview.get_untracked().upload_scope,
                        files,
                    );
                }),
        ));
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let upload_app = app.clone();
        menu_items.push(button(
            app.translated(scope, "chat.composer.add_attachment"),
            "secondary attachment-menu-item attachment-file-picker",
            scope.bond(move || {
                controller.attachment_menu_open.get() && preview.get().upload_scope.is_some()
            }),
            move || {
                controller
                    .attachment_menu_open
                    .revise(|value| *value = false);
                let app = upload_app.clone();
                let target = preview.get_untracked().upload_scope;
                let context = context.get_untracked();
                super::task::chat_task(app.clone(), async move {
                    match files::choose_files().await {
                        Ok(files) => commands::upload_dropped_attachments(
                            controller,
                            app.base_url.get_untracked(),
                            context.token.get_untracked(),
                            target,
                            files,
                        ),
                        Err(error) => controller
                            .compose_upload_status
                            .revise(|value| *value = error.to_string()),
                    }
                });
            },
        ));
    }
    let poll_app = app.clone();
    tools.push(reactive_distinct(
        scope.bond(move || preview.get().polls_available),
        move |scope, visible| {
            if !visible {
                return empty();
            }
            Box::new(
                sapid::button()
                    .unstyled()
                    .label(poll_app.translated(scope, "chat.composer.poll"))
                    .name(poll_app.translated(scope, "chat.composer.create_poll"))
                    .class("secondary composer-tool-button open-poll-composer-button")
                    .enabled(scope.bond(move || preview.get().polls_enabled))
                    .on_press(move || {
                        controller
                            .attachment_menu_open
                            .revise(|value| *value = false);
                        controller.poll_draft.revise(|draft| {
                            *draft = Some(crate::messaging::polls::PollDraft::new())
                        });
                    }),
            ) as View
        },
    ));
    let schedule_app = app.clone();
    tools.push(reactive_distinct(
        scope.bond(move || preview.get().schedule_available),
        move |scope, visible| {
            if !visible {
                return empty();
            }
            super::native::icon_button(
                "calendar",
                schedule_app.translated(scope, "chat.composer.schedule_message"),
                "secondary composer-tool-button open-scheduled-send-panel-button",
                true,
                move || scheduled.revise(|value| *value = !*value),
            )
        },
    ));
    // Keep the official file control alive after the popup closes: active reads
    // use its accepted grant. CSS removes the popup from layout and focus.
    tools.push(Box::new(
        view()
            .class(scope.bond(move || {
                if controller.attachment_menu_open.get() {
                    "attachment-menu".to_owned()
                } else {
                    "attachment-menu attachment-menu-hidden".to_owned()
                }
            }))
            .fill(menu_items),
    ));
    let scope_label = scope.bond(move || {
        let preview = preview.get();
        composer_scope_label(
            preview.route,
            preview.scope,
            &controller.selected_channel.get(),
        )
    });
    let reply_app = app.clone();
    let reply_source = scope.bond(move || {
        let current = context.get();
        controller.reply_to_message.get().map(|reply| {
            chat_reply_quote_preview(
                &controller.messages.get(),
                &reply,
                current.principal_id.as_str(),
                &current.account_display_label,
                &current.participants,
            )
        })
    });
    let reply = reactive_distinct(reply_source, move |scope, reply| {
        let Some(reply) = reply else { return empty() };
        let quote = match reply {
            Some((name, body)) => block(
                "chat-reply-quote",
                vec![
                    paragraph("chat-reply-quote-name", name),
                    paragraph("chat-reply-quote-body", body),
                ],
            ),
            None => paragraph(
                "chat-reply-quote chat-reply-quote-missing",
                reply_app.translated(scope, "chat.composer.reply_missing"),
            ),
        };
        line(
            "chat-reply-quote-banner chat-reply-banner",
            vec![
                quote,
                button(
                    reply_app.translated(scope, "common.cancel"),
                    "secondary reply-cancel-button",
                    true,
                    move || controller.reply_to_message.revise(|value| *value = None),
                ),
            ],
        )
    });
    let circle_app = app.clone();
    let circle_source = scope.bond(move || {
        let current = context.get();
        let scope = current
            .selected_channel_info
            .and_then(|channel| channel.scope_circle)
            .map(|circle| crate::circle::CircleScope::Circle {
                circle_id: circle.circle_id,
                title: circle.title,
                member_count: circle.member_count,
            })
            .unwrap_or(crate::circle::CircleScope::Realm);
        (scope, current.circle_display, current.circle_encrypted)
    });
    let circle_banner =
        reactive_distinct(circle_source, move |scope, (circle, display, encrypted)| {
            crate::components::circle_composer_banner(
                scope,
                circle_app.clone(),
                crate::components::CircleComposerBannerProps {
                    scope: circle,
                    display,
                    encrypted,
                },
            )
        });
    let mention_context = context;
    let mentions = mention_picker(scope, app.clone(), controller, mention_context);
    let chip_source = scope.bond(move || controller.mention_picker_state.get().inserted);
    let chip_app = app.clone();
    let chips = reactive_distinct(chip_source, move |scope, chips| {
        if chips.is_empty() {
            return empty();
        }
        line(
            "mention-chip-row",
            chips
                .into_iter()
                .map(|chip| {
                    let label = format!("@{}", chip.insert_label());
                    let member = chip.insert_label().to_owned();
                    let remove_label = chip_app.translated_args(
                        scope,
                        "chat.composer.remove_mention",
                        move || vec![("member", member.clone())],
                    );
                    let mut children: Vec<View> =
                        vec![Box::new(text().class("mention-chip-label").content(label))];
                    if !chip.subtitle.is_empty() {
                        children.push(Box::new(
                            text().class("mention-chip-subtitle").content(chip.subtitle),
                        ));
                    }
                    let id = chip.subject_account_id;
                    let identity = format!(
                        "Principal: {} · Station: {}",
                        id.principal_id, id.station_id
                    );
                    use sha2::Digest;
                    let identity_id = match glory::render::SemanticId::new(format!(
                        "mention-recipient-{}",
                        hex::encode(sha2::Sha256::digest(id.to_string().as_bytes()))
                    )) {
                        Ok(id) => id,
                        Err(error) => {
                            scope.report_error(error);
                            return empty();
                        }
                    };
                    let described_by = identity_id.clone();
                    children.push(Box::new(
                        text()
                            .class("sr-only mention-chip-identity")
                            .content(identity)
                            .semantics(Some(Box::new(glory::render::Semantics {
                                id: Some(identity_id),
                                ..Default::default()
                            }))),
                    ));
                    children.push(Box::new(
                        glory::ui::button()
                            .name(remove_label)
                            .class("mention-chip-remove")
                            .fill(text().content("×"))
                            .on(glory::render::EventKind::Activate, move |_| {
                                controller
                                    .mention_picker_state
                                    .revise(|picker| picker.remove(&id))
                            }),
                    ));
                    Box::new(
                        view()
                            .role(glory::render::Role::Group)
                            .class("mention-chip")
                            .semantics(Some(Box::new(glory::render::Semantics {
                                described_by: Some(described_by),
                                ..Default::default()
                            })))
                            .fill(children),
                    ) as View
                })
                .collect(),
        )
    });
    let attachments = reactive_distinct(controller.attachments, move |_, attachments| {
        if attachments.is_empty() {
            return empty();
        }
        block(
            "compose-attachments",
            attachments
                .into_iter()
                .map(|attachment| {
                    let id = attachment.id;
                    line(
                        "compose-attachment",
                        vec![
                            plain(attachment.content.body),
                            button(
                                "Remove",
                                "secondary remove-compose-attachment",
                                true,
                                move || commands::discard_draft_attachment(controller, id.clone()),
                            ),
                        ],
                    )
                })
                .collect(),
        )
    });
    let retry_app = app.clone();
    let retry: View = Box::new(
        glory::ui::button()
            .label("Retry attachments")
            .class("retry-attachment-upload")
            .on(glory::render::EventKind::Activate, move |_| {
                commands::upload_dropped_attachments(
                    controller,
                    retry_app.base_url.get_untracked(),
                    context.get_untracked().token.get_untracked(),
                    preview.get_untracked().upload_scope,
                    Vec::new(),
                )
            }),
    );
    let upload_status = line(
        "compose-upload-progress",
        vec![
            Box::new(text().content(controller.compose_upload_status)),
            retry,
        ],
    );
    let poll = poll_composer(scope, app.clone(), controller, context, preview);
    let scheduled_context = context;
    let scheduled_app = app.clone();
    let scheduled_panel = scheduled_send_surface(scheduled, move |scope| {
        let context = scheduled_context.get_untracked();
        let generation = scheduled_app.session_generation.get_untracked();
        let account = scheduled_app.active_account.get_untracked();
        let realm_id = context.selected_realm_id.clone();
        let strand_id = controller.selected_channel.get_untracked();
        let authority = context.authority.clone();
        let device_id = context.device_id.clone();
        let current_app = scheduled_app.clone();
        let writable = scope.bond(move || {
            let _ = current_app.session_generation.get();
            let _ = current_app.active_account.get();
            let current = scheduled_context.get();
            let available = preview.get();
            available.schedule_available
                && available.plain_enabled
                && current.selected_realm_id == realm_id
                && controller.selected_channel.get() == strand_id
                && current.authority == authority
                && current.device_id == device_id
                && current_app.session_matches(generation, &account)
        });
        super::scheduled_send_panel::scheduled_send_panel(
            scope,
            scheduled_app.clone(),
            super::scheduled_send_panel::ScheduledSendPanelContext {
                realm_id: context.selected_realm_id,
                strand_id: controller.selected_channel.get_untracked(),
                authority: context.authority,
                device_id: context.device_id,
                token: context.token,
                draft: controller.draft,
                status_msg: controller.status_msg,
                writable: writable.into(),
            },
        )
    });
    let primary_send = send.clone();
    let secure_send = send;
    let label_app = app.clone();
    let label = scope.bond(move || {
        let preview = preview.get();
        label_app.tr(
            if controller.sidecar_send_pending.get() && preview.pending {
                "chat.composer.sending"
            } else if preview.pending {
                "chat.composer.opening"
            } else {
                "chat.send"
            },
        )
    });
    let primary = primary_send_action(
        scope,
        label,
        scope.bond(move || {
            let preview = preview.get();
            if preview.plaintext {
                preview.plain_enabled
            } else {
                preview.secure_enabled
            }
        }),
        scope.bond(move || {
            let current = context.get();
            let preview = preview.get();
            preview.pending
                || if matches!(preview.route, arkret_sdk::AgentMentionRoute::Sidecar) {
                    private_probe.get().checking
                } else {
                    current.send_readiness_checking
                }
        }),
        move || primary_send(!preview.get_untracked().plaintext),
    );
    let secure = reactive_distinct(
        scope.bond(move || preview.get().plaintext),
        move |scope, visible| {
            if visible {
                let send = secure_send.clone();
                button(
                    "Send secure",
                    "secondary send-e2ee-move-button",
                    scope.bond(move || preview.get().secure_enabled),
                    move || send(true),
                )
            } else {
                empty()
            }
        },
    );
    let storage_app = app.clone();
    let storage_error =
        reactive_distinct(
            scope.bond(move || controller.draft_storage_status() == "error"),
            move |scope, failed| {
                if failed {
                    Box::new(
                        view()
                            .class("draft-storage-error")
                            .role(glory::render::Role::Alert)
                            .fill(text().content(
                                storage_app.translated(scope, "compose.draft_storage_error"),
                            )),
                    )
                } else {
                    empty()
                }
            },
        );
    block(
        "discussion-composer chat-composer",
        vec![
            paragraph("composer-send-scope", scope_label),
            paragraph(
                "muted composer-send-diagnostic",
                scope.bond(move || preview.get().title),
            ),
            circle_banner,
            reply,
            block(
                "compose-drop-zone",
                vec![
                    storage_error,
                    input,
                    mentions,
                    chips,
                    line("mention-chip-row", tools),
                ],
            ),
            upload_status,
            attachments,
            poll,
            scheduled_panel,
            line("actions", vec![primary, secure]),
        ],
    )
}

fn edit_draft(
    app: Rc<crate::presentation::InksonContext>,
    controller: ChatController,
    context: &ChatComposerContext,
    value: String,
) {
    let previous = controller.draft.get_untracked();
    controller
        .mention_picker_state
        .revise(|picker| picker.edit(&previous, &value));
    controller.update_draft(value.clone());
    controller.mention_picker_state.revise(|picker| {
        if let Some((query, start, end)) =
            active_composer_mention_token(context.mentions_enabled, &value)
        {
            picker.set_active_token(query, start, end);
        } else if picker.open {
            picker.close();
        }
    });
    let (_, route) = draft_route(controller, context);
    if matches!(
        route,
        arkret_sdk::AgentMentionRoute::Sidecar
            | arkret_sdk::AgentMentionRoute::BlockedMixedPrivateTargets
    ) {
        return;
    }
    if !app
        .state_store
        .read(|store| store.presence_visibility().allows_presence_send())
    {
        return;
    }
    let strand = controller.selected_channel.get_untracked();
    if strand.trim().is_empty() {
        return;
    }
    let Ok(material) = app.state_store.read(|store| {
        crate::signal::key_material_for_scope(store, &context.selected_realm_id, None)
    }) else {
        return;
    };
    let target = commands::TypingSignalTarget {
        base_url: app.base_url.get_untracked(),
        realm_id: context.selected_realm_id.clone(),
        strand_id: strand,
        authority: context.authority.clone(),
        device_id: context.device_id.clone(),
        material,
        store: app.state_store.handle(),
    };
    let generation = app.session_generation.get_untracked();
    let account = app.active_account.get_untracked();
    let token = context.token;
    controller.typing_throttle.on_keystroke(move |typing| {
        if app.session_matches(generation, &account) {
            commands::send_typing_signal(target.clone(), token.get_untracked(), typing);
        }
    });
}

fn mention_picker(
    scope: &Scope,
    app: Rc<crate::presentation::InksonContext>,
    controller: ChatController,
    context: Bond<ChatComposerContext>,
) -> View {
    use super::native::{block, button, field};
    use crate::presentation::widgets::{empty, line, paragraph, reactive_distinct};
    let open = scope
        .bond(move || context.get().mentions_enabled && controller.mention_picker_state.get().open);
    reactive_distinct(open, move |scope, open| {
        if !open {
            return empty();
        }
        let query = scope.bond(move || controller.mention_picker_state.get().query);
        let matches = scope.bond(move || {
            let context = context.get();
            let principal = context.principal_id.as_str();
            let mut candidates = context
                .participants
                .iter()
                .filter(|participant| {
                    agent_candidate_is_visible(participant, &context.public_agent_ids, principal)
                })
                .filter_map(|participant| {
                    mention_candidate_for_participant(participant, &context.participants, principal)
                })
                .collect::<Vec<_>>();
            candidates.sort_by_key(|candidate| {
                if candidate.subject_account_id.principal_id.as_str() == principal.trim() {
                    0u8
                } else if candidate.is_agent
                    && candidate
                        .controller_subject_account_id
                        .as_ref()
                        .is_some_and(|account| account.principal_id.as_str() == principal.trim())
                {
                    1u8
                } else {
                    2u8
                }
            });
            controller
                .mention_picker_state
                .get()
                .filter(&candidates)
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        });
        let empty_app = app.clone();
        let suggestions = reactive_distinct(matches, move |scope, matches| {
            if matches.is_empty() {
                return paragraph(
                    "muted",
                    empty_app.translated(scope, "chat.composer.no_matches"),
                );
            }
            block(
                "mention-suggestions",
                matches
                    .into_iter()
                    .map(|candidate| {
                        let label = format!(
                            "@{} — {}",
                            candidate.insert_label(),
                            candidate.subject_account_id
                        );
                        let mut children: Vec<View> = vec![Box::new(
                            text()
                                .class("actor-identity-primary mention-suggestion-name")
                                .content(format!("@{}", candidate.insert_label())),
                        )];
                        if candidate.subject_account_id.principal_id
                            == context.get().principal_id
                        {
                            children.push(crate::components::self_attribution_badge_inline(
                                scope,
                                empty_app.clone(),
                                crate::components::SelfAttributionBadgeProps {
                                    class: Some("actor-identity-self-badge".into()),
                                    ..Default::default()
                                },
                            ));
                        }
                        if candidate.is_agent {
                            children.push(Box::new(text().class("badge member-badge member-badge-agent actor-identity-agent-badge mention-suggestion-agent-badge").content("Agent")));
                        }
                        if !candidate.subtitle.is_empty() {
                            children.push(Box::new(text().class("mention-suggestion-subtitle").content(candidate.subtitle.clone())));
                        }
                        Box::new(
                            glory::ui::button()
                                .name(label)
                                .class("secondary mention-suggestion")
                                .fill(group().fill(children))
                                .on(glory::render::EventKind::Activate, move |_| {
                                    let current = controller.draft.get_untracked();
                                    let updated = controller.mention_picker_state.revise(|picker| {
                                        let result = picker.select(candidate.clone(), &current, picker.active_range);
                                        picker.close();
                                        result
                                    });
                                    controller.update_draft(updated);
                                }),
                        ) as View
                    })
                    .collect(),
            )
        });
        block(
            "mention-picker",
            vec![
                line(
                    "mention-picker-head",
                    vec![
                        field(
                            app.translated(scope, "chat.composer.search_members"),
                            "mention-picker-query",
                            query,
                            false,
                            move |value| {
                                controller
                                    .mention_picker_state
                                    .revise(|picker| picker.set_query(value))
                            },
                        ),
                        button(
                            app.translated(scope, "common.close"),
                            "secondary mention-picker-close-button",
                            true,
                            move || {
                                controller
                                    .mention_picker_state
                                    .revise(|picker| picker.close())
                            },
                        ),
                    ],
                ),
                suggestions,
            ],
        )
    })
}

fn poll_composer(
    scope: &Scope,
    app: Rc<crate::presentation::InksonContext>,
    controller: ChatController,
    context: Bond<ChatComposerContext>,
    preview: Bond<Preview>,
) -> View {
    use super::native::{block, button, field};
    use crate::presentation::widgets::{empty, line, reactive_distinct};
    let phase = scope.bond(move || {
        (
            preview.get().polls_available,
            controller.poll_draft.get().map(|draft| draft.options.len()),
        )
    });
    reactive_distinct(phase, move |scope, (available, count)| {
        let Some(count) = count.filter(|_| available) else {
            return empty();
        };
        let question = scope.bond(move || {
            controller
                .poll_draft
                .get()
                .map(|draft| draft.question)
                .unwrap_or_default()
        });
        let mut children = vec![field(
            app.translated(scope, "chat.composer.poll_question"),
            "poll-question-input",
            question,
            false,
            move |value| {
                controller.poll_draft.revise(|draft| {
                    if let Some(draft) = draft {
                        draft.set_question(value)
                    }
                })
            },
        )];
        for index in 0..count {
            let value = scope.bond(move || {
                controller
                    .poll_draft
                    .get()
                    .and_then(|draft| draft.options.get(index).cloned())
                    .unwrap_or_default()
            });
            children.push(field(
                app.translated_args(scope, "chat.composer.poll_option", move || {
                    vec![("number", (index + 1).to_string())]
                }),
                "poll-option-input",
                value,
                false,
                move |value| {
                    controller.poll_draft.revise(|draft| {
                        if let Some(draft) = draft {
                            draft.set_option(index, value)
                        }
                    })
                },
            ));
        }
        let send_app = app.clone();
        children.push(line(
            "actions",
            vec![
                button(
                    app.translated(scope, "chat.composer.add_option"),
                    "secondary poll-add-option-button",
                    true,
                    move || {
                        controller.poll_draft.revise(|draft| {
                            if let Some(draft) = draft {
                                draft.add_option()
                            }
                        })
                    },
                ),
                button(
                    app.translated(scope, "chat.composer.send_poll"),
                    "primary send-poll-button",
                    scope.bond(move || {
                        preview.get().plain_enabled
                            && controller
                                .poll_draft
                                .get()
                                .is_some_and(|draft| draft.is_sendable())
                    }),
                    move || {
                        if preview.get_untracked().polls_available
                            && preview.get_untracked().plain_enabled
                        {
                            send::poll(send_app.clone(), controller, context.get_untracked());
                        }
                    },
                ),
                button(
                    app.translated(scope, "common.cancel"),
                    "secondary poll-cancel-button",
                    true,
                    move || controller.poll_draft.revise(|draft| *draft = None),
                ),
            ],
        ));
        block("poll-composer", children)
    })
}
