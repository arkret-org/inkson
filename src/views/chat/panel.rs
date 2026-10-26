use super::snapshot::ChatSnapshot;
use super::*;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "panel_lifetime_tests.rs"]
mod lifetime_tests;

pub(super) fn target(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    props: ChatPanelProps,
    account: crate::config::ActiveAccountContext,
    controller: ChatController,
    available: Cage<bool>,
) -> View {
    let demand_store = context.state_store.clone();
    let demand_account = account.authority.clone();
    let demand_realm = props.selected_realm_id.clone();
    scope.effect(move || {
        let strands = arkret_sdk::StrandId::new(controller.selected_channel.get())
            .ok()
            .into_iter()
            .collect();
        demand_store.read(|store| {
            store.set_product_current_demand(
                &demand_account,
                &demand_realm,
                Some(strands),
                Vec::new(),
            )
        });
    });
    let demand_store = context.state_store.clone();
    let demand_account = account.authority.clone();
    let demand_realm = props.selected_realm_id.clone();
    scope
        .on_cleanup(move || {
            demand_store.read(|store| {
                store.set_product_current_demand(&demand_account, &demand_realm, None, Vec::new())
            })
        })
        .unwrap_or_else(|error| scope.report_error(error));
    let basis = timeline_projection::timeline_projection_basis(scope, context.clone());
    let private = sidecar_projection::sidecar_timeline_projection(
        scope,
        context.state_store.clone(),
        basis,
        account.authority.clone(),
        account.device_id.clone(),
        props.selected_realm_id.clone(),
        crate::identity::device_directory::session_cache_epoch(),
    );
    let ordinary = timeline_projection::ordinary_timeline_projection(
        scope,
        context.state_store.clone(),
        basis,
        controller.messages,
        account.principal_id().to_string(),
        account.authority.clone(),
        account.device_id.clone(),
        crate::identity::device_directory::session_cache_epoch(),
    );
    let merged = scope.bond(move || {
        let mut rows = ordinary.get();
        merge_chat_messages(&mut rows, private.get().messages);
        rows
    });
    let visible_context = context.clone();
    let visible_props = props.clone();
    let visible_authority = account.authority.clone();
    let visible = scope.bond(move || {
        let private = private.get();
        let projections = private.current.clone().unwrap_or_default();
        let strand = controller.selected_channel.get();
        let sidecar = super::snapshot::active_sidecar(
            &visible_context,
            &visible_props,
            &visible_authority,
            &strand,
        );
        project_visible_messages(
            &merged.get(),
            &strand,
            &visible_props.selected_realm_id,
            sidecar
                .as_ref()
                .map(|session| session.source_strand_id.as_str()),
            &projections,
            private.current.is_ok(),
        )
    });
    let send_realm = props.selected_realm_id.clone();
    let send_scope = scope.bond(move || {
        let selected = controller.selected_channel.get();
        controller
            .channels
            .get()
            .iter()
            .find(|channel| channel.strand_id == selected)
            .and_then(|channel| channel.effective_scope(&send_realm))
    });
    let probe = crate::views::secure_send::scope_send_probe(
        scope,
        context.clone(),
        send_scope.into(),
        account.device_id.clone().into(),
    );
    let snapshot_context = context.clone();
    let snapshot_props = props.clone();
    let snapshot_account = account.clone();
    let before_modes = scope.bond(move || {
        super::snapshot::snapshot(
            &snapshot_context,
            &snapshot_props,
            controller,
            &snapshot_account,
            private,
            merged,
            visible,
            probe.get(),
            agent_modes::Modes::new(),
        )
    });
    let mode_key = scope.bond(move || before_modes.get().mode_key);
    let modes = agent_modes::agent_modes(
        scope,
        context.clone(),
        mode_key.into(),
        if props.embedded {
            "embedded_chat_composer"
        } else if props.direct_mode {
            "direct_chat_composer"
        } else {
            "realm_chat_composer"
        },
    );
    let snapshot_context = context.clone();
    let snapshot_props = props.clone();
    let snapshot_account = account.clone();
    let snapshot = scope.bond(move || {
        super::snapshot::snapshot(
            &snapshot_context,
            &snapshot_props,
            controller,
            &snapshot_account,
            private,
            merged,
            visible,
            probe.get(),
            modes.get(),
        )
    });
    let close_context = context.clone();
    let close_realm = props.selected_realm_id.clone();
    let close_account = account.clone();
    scope.effect(move || {
        let projection = private.get();
        if projection.closes.is_empty() {
            return;
        }
        let context = close_context.clone();
        let realm = close_realm.clone();
        let account = close_account.clone();
        let credential = context.token.get();
        let base = context.base_url.get();
        let store = context.state_store.clone();
        super::task::chat_task(context.clone(), async move {
            if drive_sidecar_completion_closes(
                context,
                base,
                credential,
                account.authority,
                account.device_id,
                realm,
                store,
                projection.closes,
                projection.close_cut,
            )
            .await
            .is_err()
            {
                tracing::warn!(
                    "Sidecar completion close is awaiting verified recovery or durable submission"
                );
            }
        });
    });
    let sidecar_pending = scope.cage(false);
    let composer_context = context.clone();
    let composer_props = props.clone();
    let composer_account = account.clone();
    let composer = scope.bond(move || {
        let snapshot = snapshot.get();
        let selected = controller.selected_channel.get();
        let sidecar = super::snapshot::active_sidecar(
            &composer_context,
            &composer_props,
            &composer_account.authority,
            &selected,
        );
        let circle_encrypted = snapshot.send_scope.as_ref().and_then(|scope| {
            composer_context.state_store.read(|store| {
                match store.installed_scope_mls_current(scope) {
                    crate::current_projection::ScopeMlsCurrent::Activated(_) => Some(true),
                    crate::current_projection::ScopeMlsCurrent::NotActivated => Some(false),
                    crate::current_projection::ScopeMlsCurrent::Unknown => None,
                }
            })
        });
        let circle_display = snapshot
            .selected_channel_info
            .as_ref()
            .and_then(|channel| channel.scope_circle.as_ref())
            .and_then(|scope| {
                controller
                    .eligible_circle_scopes
                    .get()
                    .into_iter()
                    .find(|circle| circle.id == scope.circle_id)
                    .map(|circle| circle.display)
            });
        composer::ChatComposerContext {
            sidecar_route_pending: sidecar_pending,
            selected_channel_info: snapshot.selected_channel_info,
            circle_display,
            circle_encrypted,
            authority: composer_account.authority.clone(),
            did: composer_account.did().clone(),
            principal_id: composer_account.principal_id().clone(),
            account_display_label: snapshot.account_display_label,
            participants: snapshot.composer_participants,
            selected_realm_id: composer_props.selected_realm_id.clone(),
            device_id: composer_account.device_id.clone(),
            selected_channel_security_encrypted: snapshot.selected_channel_security_encrypted,
            selected_realm_pending_mls_binding: snapshot.selected_realm_pending_mls_binding,
            selected_realm_pending_mls_binding_reason: snapshot
                .selected_realm_pending_mls_binding_reason,
            send_readiness_checking: snapshot.send_readiness_checking,
            active_sidecar_session: sidecar,
            sidecar_send_block_reason: snapshot.sidecar_send_block_reason,
            public_agent_ids: snapshot.public_agent_ids,
            interaction_modes: snapshot.interaction_modes_snapshot,
            mention_insert_request: composer_props.mention_insert_request,
            mentions_enabled: composer::chat_mentions_enabled(composer_props.direct_mode),
            token: composer_context.token,
            frontier_state: composer_context.frontier_state,
        }
    });
    let timeline_context = context.clone();
    let timeline_props = props.clone();
    let timeline_account = account.clone();
    let timeline = scope.bond(move || {
        let snapshot = snapshot.get();
        let private = private.get();
        let selected = controller.selected_channel.get();
        let sidecar = super::snapshot::active_sidecar(
            &timeline_context,
            &timeline_props,
            &timeline_account.authority,
            &selected,
        );
        let strand_scope_lookup = controller
            .channels
            .get()
            .into_iter()
            .filter_map(|channel| {
                channel
                    .scope_circle
                    .map(|circle| (channel.strand_id, circle))
            })
            .collect();
        timeline_surface::ChatTimelineContext {
            embedded: timeline_props.embedded,
            visible_messages: visible,
            strand_scope_lookup,
            private_sidecar_event_ids: private.private_event_ids,
            authority: timeline_account.authority.clone(),
            principal_id: timeline_account.principal_id().clone(),
            account_display_label: snapshot.account_display_label,
            participants: snapshot.participants_for_messages,
            selected_realm_id: timeline_props.selected_realm_id.clone(),
            selected_channel_id: sidecar
                .as_ref()
                .map(|session| session.source_strand_id.clone())
                .unwrap_or(selected),
            sidecar_active: sidecar.is_some(),
            direct_mode: timeline_props.direct_mode,
            device_id: timeline_account.device_id.clone(),
            base_url: timeline_context.base_url.get(),
            focus_message_id: timeline_props.focus_message_id.clone(),
            blocked_actor_ids: timeline_context.state_store.read(|store| {
                crate::account_data::blocked_message_actor_ids(&store.client_blocklist())
            }),
            selected_channel_security_encrypted: snapshot.selected_channel_security_encrypted,
            visible_channels_empty: snapshot.visible_channels.is_empty(),
            visible_message_count: visible.get().len(),
            loading: snapshot.discussion_feed_loading,
            token: timeline_context.token,
            frontier_state: timeline_context.frontier_state,
        }
    });
    let right_panel = scope.cage(
        if super::snapshot::active_sidecar(
            &context,
            &props,
            &account.authority,
            &controller.selected_channel.get_untracked(),
        )
        .is_some()
        {
            None
        } else {
            Some(DiscussionSidePanel::Users)
        },
    );
    let effect_context = context.clone();
    let effect_props = props.clone();
    let effect_account = account.clone();
    let queries =
        crate::presentation::widgets::reactive_distinct(available, move |scope, ready| {
            if !ready {
                return crate::presentation::widgets::empty();
            };
            let initial = snapshot.get_untracked();
            effects::chat_effects(
                scope,
                effect_context.clone(),
                controller,
                effect_account.authority.clone(),
                effect_account.principal_id().to_string(),
                effect_account.device_id.clone(),
                effect_props.selected_realm_id.clone(),
                effect_props.initial_strand_id.clone(),
                String::new(),
                ordinary,
                basis,
                effect_context.sync_cursor,
                effect_context.realm_live_epoch,
                effect_context.frontier_state,
                initial.agent_participation_sync_key.clone(),
                initial.selected_scope_circle.clone(),
                initial.readable_participation_agent_ids.clone(),
                initial.participant_ids_for_presence.clone(),
                initial.account_display_label.clone(),
                initial.has_remote_presence,
                initial.presence_sync_key.clone(),
                effect_context.token,
                snapshot,
            );
            crate::presentation::widgets::empty()
        });
    let content = shell(
        scope,
        context,
        props,
        account,
        controller,
        snapshot,
        timeline,
        composer,
        right_panel,
        merged,
        available,
    );
    Box::new(
        view()
            .class("chat-target-regions")
            .fill(vec![queries, retained_surface(scope, available, content)]),
    )
}

pub(super) fn retained_surface(scope: &Scope, available: Cage<bool>, content: View) -> View {
    Box::new(
        view()
            .class("chat-retained-target")
            .semantics(scope.bond(move || {
                let suspended = !available.get();
                Some(Box::new(glory::render::Semantics {
                    hidden: suspended,
                    inert: suspended,
                    ..Default::default()
                }))
            }))
            .fill(content),
    )
}

fn shell(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    props: ChatPanelProps,
    account: crate::config::ActiveAccountContext,
    controller: ChatController,
    snapshot: Bond<ChatSnapshot>,
    timeline: Bond<timeline_surface::ChatTimelineContext>,
    composer: Bond<composer::ChatComposerContext>,
    right_panel: Cage<Option<DiscussionSidePanel>>,
    all_messages: Bond<Vec<ChatMessage>>,
    available: Cage<bool>,
) -> View {
    use super::native::{block, button, icon_button};
    use crate::presentation::widgets::{empty, line, paragraph, plain, reactive_distinct};
    let shell_props = props.clone();
    let class = scope.bond(move || {
        let sidecar = composer.get().active_sidecar_session.is_some();
        let left =
            !shell_props.embedded && !shell_props.direct_mode && controller.left_panel_open.get();
        let right = !shell_props.embedded && right_panel.get().is_some();
        format!(
            "discussion-shell chat-panel{}{}{}{}{}",
            if shell_props.embedded {
                " embedded"
            } else {
                ""
            },
            if shell_props.direct_mode {
                " direct-mode"
            } else {
                ""
            },
            if sidecar { " sidecar-mode" } else { "" },
            if left { "" } else { " left-collapsed" },
            if right { "" } else { " right-collapsed" }
        )
    });
    let left_props = props.clone();
    let left_context = context.clone();
    let left = reactive_distinct(controller.left_panel_open, move |scope, open| {
        if left_props.embedded || left_props.direct_mode {
            return empty();
        };
        if !open {
            return block(
                "discussion-rail discussion-left-rail discussion-list-rail",
                vec![icon_button(
                    "panel-left-open",
                    "Show discussion list",
                    "secondary icon-button expand-discussion-list",
                    true,
                    move || controller.left_panel_open.revise(|value| *value = true),
                )],
            );
        }
        let track_context = left_context.clone();
        let track_realm = left_props.selected_realm_id.clone();
        let rows = reactive_distinct(
            scope.bond(move || snapshot.get().visible_channels),
            move |scope, channels| {
                if channels.is_empty() {
                    return paragraph("discussion-empty empty-discussion-list", "No discussions");
                }
                block(
                    "discussion-list channel-list",
                    channels
                        .into_iter()
                        .map(|channel| {
                            let id = channel.strand_id.clone();
                            let class = scope.bond(move || {
                                if controller.selected_channel.get() == id {
                                    "secondary discussion-track-row channel-item active".to_owned()
                                } else {
                                    "secondary discussion-track-row channel-item".to_owned()
                                }
                            });
                            let id = channel.strand_id.clone();
                            let label = format!(
                                "{}{}",
                                channel.name,
                                channel
                                    .topic
                                    .as_ref()
                                    .map(|topic| format!(" — {topic}"))
                                    .unwrap_or_default()
                            );
                            let encrypted = channel.effective_scope(&track_realm).and_then(|scope| {
                                track_context.state_store.read(|store| match store.installed_scope_mls_current(&scope) {
                                    crate::current_projection::ScopeMlsCurrent::Activated(_) => Some(true),
                                    crate::current_projection::ScopeMlsCurrent::NotActivated => Some(false),
                                    crate::current_projection::ScopeMlsCurrent::Unknown => None,
                                })
                            }).unwrap_or(true);
                            let mut children = vec![
                                crate::components::ui_icon(if encrypted { "shield-check" } else { "alert" }),
                                Box::new(text().class("discussion-track-name").content(channel.name)) as View,
                                Box::new(text().class("discussion-track-topic").content(channel.topic.unwrap_or_else(|| "No topic".into()))) as View,
                                Box::new(text().class("badge discussion-track-category").content(channel.category)) as View,
                            ];
                            if channel.unread > 0 {
                                children.push(Box::new(text().class("badge accent discussion-track-unread").content(channel.unread.to_string())));
                            }
                            Box::new(sapid::button().unstyled().class(class).name(label).fill(children)
                                .on_press(move || controller.select_channel(id.clone()))
                            ) as View
                        })
                        .collect(),
                )
            },
        );
        block(
            "discussion-panel discussion-sidebar-panel discussion-list-panel",
            vec![
                line(
                    "discussion-panel-head",
                    vec![
                        line(
                            "discussion-title-row",
                            vec![
                                crate::presentation::widgets::heading(
                                    2,
                                    "",
                                    left_context.translated(scope, "chat.discussions_header"),
                                ),
                                crate::components::help_tip(
                                    scope,
                                    left_context.clone(),
                                    crate::components::HelpTipProps {
                                        text: "Discussion is the selected Strand's track. The default Strand is always available for this Realm; the alternate filter includes every Strand with a discussion track.".into(),
                                    },
                                ),
                            ],
                        ),
                        line(
                            "discussion-panel-head-actions",
                            vec![
                                icon_button(
                                    "plus",
                                    left_context.translated(scope, "chat.new_strand"),
                                    "primary icon-button open-channel-dialog",
                                    true,
                                    move || controller.open_create_dialog(),
                                ),
                                icon_button(
                                    "panel-left-close",
                                    left_context.translated(scope, "chat.hide_list"),
                                    "secondary icon-button collapse-discussion-list",
                                    true,
                                    move || {
                                        controller.left_panel_open.revise(|value| *value = false)
                                    },
                                ),
                            ],
                        ),
                    ],
                ),
                line(
                    "discussion-filter segmented-control",
                    vec![
                        button(
                            "Default + discussion",
                            "secondary segment discussion-filter-only",
                            true,
                            move || {
                                controller
                                    .track_filter
                                    .revise(|value| *value = "discussion_only".into())
                            },
                        ),
                        button(
                            "All Strand tracks",
                            "secondary segment discussion-filter-track",
                            true,
                            move || {
                                controller
                                    .track_filter
                                    .revise(|value| *value = "with_discussion_track".into())
                            },
                        ),
                    ],
                ),
                rows,
            ],
        )
    });
    let mut actions = Vec::new();
    if !props.embedded {
        if crate::views::call::media_route_adapter_available() {
            for (video, icon, key) in [
                (false, "phone", "chat.call.voice"),
                (true, "video", "chat.call.video"),
            ] {
                let context = context.clone();
                let realm = props.selected_realm_id.clone();
                actions.push(icon_button(
                    icon,
                    context.translated(scope, key),
                    if video {
                        "secondary icon-button chat-call-video-button"
                    } else {
                        "secondary icon-button chat-call-voice-button"
                    },
                    !realm.is_empty(),
                    move || {
                        context.navigate(Route::Call {
                            call_id: String::new(),
                            peer: String::new(),
                            realm_id: realm.clone(),
                            video: if video { "1" } else { "0" }.into(),
                            incoming: "0".into(),
                        })
                    },
                ));
            }
        }
        actions.push(watch_picker(
            scope,
            context.clone(),
            props.clone(),
            account.authority.clone(),
            controller,
        ));
        actions.push(icon_button(
            "settings",
            "Settings",
            "secondary icon-button discussion-settings-toggle",
            true,
            move || {
                right_panel.revise(|value| {
                    *value = if *value == Some(DiscussionSidePanel::Settings) {
                        None
                    } else {
                        Some(DiscussionSidePanel::Settings)
                    }
                })
            },
        ));
        actions.push(icon_button(
            "users",
            "Members",
            "secondary icon-button discussion-users-toggle",
            true,
            move || {
                right_panel.revise(|value| {
                    *value = if *value == Some(DiscussionSidePanel::Users) {
                        None
                    } else {
                        Some(DiscussionSidePanel::Users)
                    }
                })
            },
        ));
    }
    let title_context = context.clone();
    let title = reactive_distinct(
        scope.bond(move || {
            let current = snapshot.get();
            (
                current.sidecar_security_label,
                current.selected_channel_security_encrypted,
            )
        }),
        move |scope, (sidecar_label, encrypted)| {
            let sidecar = sidecar_label.is_some();
            let security = if let Some(label) = sidecar_label {
                let class = if label == "E2EE" {
                    "badge success sidecar-security-state"
                } else if label == "Private but not E2EE" {
                    "badge warning sidecar-security-state"
                } else {
                    "badge amber sidecar-security-state"
                };
                paragraph(class, label)
            } else {
                crate::components::security_state_badge(
                    scope,
                    title_context.clone(),
                    crate::components::SecurityStateBadgeProps {
                        encrypted,
                        compact: true,
                        test_id: Some("selected-strand-security-state".into()),
                        ..Default::default()
                    },
                )
            };
            let mut row = vec![security];
            if sidecar {
                row.push(crate::components::ui_icon("bot"));
            }
            row.push(crate::presentation::widgets::heading(
                1,
                "discussion-title",
                scope.bond(move || snapshot.get().selected_channel_name),
            ));
            let mut stack = vec![line("discussion-title-row", row)];
            if sidecar {
                stack.push(paragraph(
                    "muted sidecar-subtitle",
                    "Private AI sidecar · you and eligible Agents in this Realm",
                ));
            }
            block("discussion-title-stack", stack)
        },
    );
    let head = line(
        "discussion-chat-head",
        vec![title, line("discussion-head-actions", actions)],
    );
    let warning = reactive_distinct(
        scope.bond(move || {
            let snapshot = snapshot.get();
            if snapshot.selected_channel_security_encrypted && !snapshot.send_readiness_checking {
                snapshot.selected_realm_pending_mls_binding_reason
            } else {
                None
            }
        }),
        move |_, reason| {
            reason
                .map(|reason| {
                    Box::new(
                        view()
                            .class("event warning-banner epoch-update-required-banner")
                            .role(glory::render::Role::Alert)
                            .fill(plain(reason)),
                    ) as View
                })
                .unwrap_or_else(empty)
        },
    );
    let typing_context = context.clone();
    let typing = scope.bond(move || {
        let names = controller
            .typing_actors
            .get()
            .into_iter()
            .filter(|actor| Some(actor) != snapshot.get().self_presence_actor.as_ref())
            .map(|actor| {
                typing_context.state_store.read(|store| {
                    display_label_for_actor(
                        store,
                        &snapshot.get().participants_for_messages,
                        &controller.presence_labels.get(),
                        &actor,
                    )
                })
            })
            .collect::<Vec<_>>();
        if names.is_empty() {
            String::new()
        } else {
            format!("{} is typing…", names.join(", "))
        }
    });
    let outbox_context = context.clone();
    let outbox = reactive_distinct(
        scope.bond(move || {
            (
                controller.is_online.get(),
                controller.queued_outbound_local_operation_ids.get().len(),
            )
        }),
        move |scope, (online, count)| {
            if online && count == 0 {
                return empty();
            };
            Box::new(
                view()
                    .class("chat-outbox-banner")
                    .role(glory::render::Role::Status)
                    .fill((
                        paragraph("chat-outbox-icon", "⏸"),
                        plain(outbox_context.translated(
                            scope,
                            if online {
                                "chat.outbox.flushing"
                            } else {
                                "chat.outbox.offline_banner"
                            },
                        )),
                        paragraph("chat-outbox-count", count.to_string()),
                    )),
            )
        },
    );
    let pinned = scope.bond(move || {
        let messages = all_messages.get();
        controller
            .shared_pins
            .get()
            .iter()
            .filter_map(|pin| {
                messages
                    .iter()
                    .find(|message| {
                        message.pin_saved_target_ref() == pin.target_ref
                            || message.id == pin.target_ref
                    })
                    .map(|message| (message.id.clone(), message.body.clone()))
            })
            .collect::<Vec<_>>()
    });
    let pins = reactive_distinct(pinned, move |_, pins| {
        if pins.is_empty() {
            return empty();
        };
        block(
            "pinned-bar",
            vec![
                line(
                    "pinned-bar-head",
                    vec![
                        crate::components::ui_icon("pin"),
                        plain(crate::i18n::tr("pinned_bar.title")),
                    ],
                ),
                line(
                    "pinned-bar-list",
                    pins.into_iter()
                        .map(|(id, body)| {
                            let label = if body.chars().count() > 40 {
                                format!("{}...", body.chars().take(40).collect::<String>())
                            } else {
                                body
                            };
                            Box::new(
                                glory::ui::button()
                                    .name(label.clone())
                                    .class("secondary pinned-bar-item")
                                    .fill(group().fill((
                                        crate::components::ui_icon("pin"),
                                        text().class("pinned-bar-preview").content(label),
                                    )))
                                    .on(glory::render::EventKind::Activate, move |_| {
                                        controller.status_msg.revise(|value| {
                                            *value = format!("jump to pinned message {id}")
                                        })
                                    }),
                            ) as View
                        })
                        .collect(),
                ),
            ],
        )
    });
    let typing = block(
        "discussion-typing-slot",
        vec![reactive_distinct(typing, move |_, text| {
            if text.is_empty() {
                empty()
            } else {
                paragraph("typing-indicator", text)
            }
        })],
    );
    let mut main = vec![head, outbox, pins, warning, typing];
    if props.direct_mode && !props.embedded {
        let select_context = context.clone();
        let realm = props.selected_realm_id.clone();
        main.push(direct_structure::direct_structure_panel(
            scope,
            context.clone(),
            direct_structure::DirectStructurePanelProps {
                realm: props.selected_realm_id.clone(),
                account: account.authority.clone(),
                device: account.device_id.clone(),
                token: context.token,
                selected: controller.selected_channel,
                frontier: context.frontier_state,
                live_epoch: context.realm_live_epoch,
                on_select: Rc::new(move |id| {
                    controller.select_channel(id.clone());
                    select_context.navigate(Route::DirectConversation {
                        realm_id: realm.clone(),
                        strand_id: id,
                    });
                }),
            },
        ));
    }
    main.push(timeline_surface::chat_timeline(
        scope,
        context.clone(),
        controller,
        timeline,
    ));
    let panel_context = context.clone();
    let panel_props = props.clone();
    let side = reactive_distinct(right_panel, move |scope, selected| {
        if panel_props.embedded {
            return empty();
        };
        match selected {
            Some(DiscussionSidePanel::Users) => right_panel::users_panel(
                scope,
                panel_context.clone(),
                controller,
                snapshot,
                right_panel,
            ),
            Some(DiscussionSidePanel::Settings) => right_panel::settings_panel(
                scope,
                panel_context.clone(),
                panel_props.clone(),
                controller,
                snapshot,
                right_panel,
            ),
            None => empty(),
        }
    });
    let create = create_dialog(scope, context.clone(), props.clone(), controller);
    let promote = promote_dialog(scope, context.clone(), props.clone(), controller);
    let composer = composer::chat_composer(scope, context.clone(), controller, composer, available);
    Box::new(view().class(class).fill(vec![
        left,
        block("discussion-panel discussion-main-panel", main),
        side,
        create,
        promote,
        composer,
        block(
            "discussion-status-slot",
            vec![paragraph(
                "muted discussion-status chat-status",
                controller.status_msg,
            )],
        ),
    ]))
}

fn create_dialog(
    _scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    props: ChatPanelProps,
    controller: ChatController,
) -> View {
    use super::native::{block, button, field};
    use crate::presentation::widgets::{empty, heading, line, reactive_distinct};
    reactive_distinct(controller.create_dialog_open, move |scope, open| {
        if !open || props.embedded || props.direct_mode {
            return empty();
        };
        let context = context.clone();
        let props = props.clone();
        crate::components::dismissible_popup(
            scope,
            context.clone(),
            crate::components::DismissiblePopupProps {
                overlay_class: "discussion-modal-backdrop channel-create-modal".into(),
                surface_class: "discussion-modal".into(),
                aria_label: "New Strand".into(),
                on_dismiss: Rc::new(move |()| {
                    controller.create_dialog_open.revise(|value| *value = false)
                }),
                overlay_test_id: None,
                surface_test_id: Some("channel-create-modal".into()),
                overlay_style: None,
                surface_style: None,
                children: Rc::new(move |scope| {
                    let select_context = context.clone();
                    let circles = reactive_distinct(
                        controller.eligible_circle_scopes,
                        move |scope, circles| {
                            crate::components::circle_scope_picker(
                                scope,
                                select_context.clone(),
                                crate::components::CircleScopePickerProps {
                                    selected: controller.new_channel_scope,
                                    circles,
                                    test_id: None,
                                    onchange: Rc::new(move |scope| {
                                        controller.new_channel_scope.revise(|value| *value = scope)
                                    }),
                                },
                            )
                        },
                    );
                    let create_context = context.clone();
                    let realm = props.selected_realm_id.clone();
                    let create = button(
                        context.translated(scope, "chat.button.create"),
                        "primary create-channel-button",
                        true,
                        move || {
                            let title = controller
                                .new_channel_name
                                .get_untracked()
                                .trim()
                                .to_owned();
                            if title.is_empty() {
                                controller
                                    .status_msg
                                    .revise(|value| *value = "Strand title is required".into());
                                return;
                            }
                            let Some(actor) = create_context.principal_id.get_untracked() else {
                                return;
                            };
                            let summary = controller
                                .new_channel_topic
                                .get_untracked()
                                .trim()
                                .to_owned();
                            let create_card = controller.new_channel_create_card.get_untracked();
                            let selected_scope_circle =
                                match controller.new_channel_scope.get_untracked() {
                                    CircleScope::Realm => None,
                                    CircleScope::Circle {
                                        circle_id,
                                        title,
                                        member_count,
                                    } => Some(StrandScopeCircle {
                                        circle_id,
                                        title,
                                        member_count,
                                    }),
                                };
                            let operation = ak_ops::discussion_strand_create(
                                &realm,
                                actor.as_str(),
                                &title,
                                "general",
                                (!summary.is_empty()).then_some(summary.as_str()),
                                selected_scope_circle
                                    .as_ref()
                                    .map(|scope| scope.circle_id.as_str()),
                                create_card,
                            )
                            .and_then(|builder| builder.build_sdk_event("inkson"));
                            match operation {
                                Ok(operation) => {
                                    controller
                                        .status_msg
                                        .revise(|value| *value = "Creating Strand".into());
                                    controller.create_strand(
                                        create_context.base_url.get_untracked(),
                                        create_context.token.get_untracked(),
                                        None,
                                        realm.clone(),
                                        operation,
                                        StrandCreateDraft {
                                            title,
                                            category: "general".into(),
                                            topic: (!summary.is_empty()).then_some(summary),
                                            create_card,
                                            scope_circle: selected_scope_circle,
                                            frontier_state: create_context.frontier_state,
                                        },
                                    );
                                }
                                Err(error) => controller.status_msg.revise(|value| {
                                    *value = format!("Could not create Strand: {error}")
                                }),
                            }
                        },
                    );
                    block(
                        "discussion-modal-content",
                        vec![
                            heading(2, "discussion-modal-head", "New Strand"),
                            block(
                                "discussion-modal-fields",
                                vec![
                                    field(
                                        "Strand title",
                                        "new-channel-name",
                                        controller.new_channel_name,
                                        false,
                                        move |value| {
                                            controller.new_channel_name.revise(|name| *name = value)
                                        },
                                    ),
                                    field(
                                        "Topic",
                                        "new-channel-topic",
                                        controller.new_channel_topic,
                                        true,
                                        move |value| {
                                            controller
                                                .new_channel_topic
                                                .revise(|topic| *topic = value)
                                        },
                                    ),
                                    circles,
                                    Box::new(
                                        sapid::checkbox()
                                            .unstyled()
                                            .class(
                                                "discussion-checkbox-row new-channel-create-card",
                                            )
                                            .label("Create matching Card")
                                            .checked(controller.new_channel_create_card)
                                            .on_checked_change(move |value| {
                                                controller
                                                    .new_channel_create_card
                                                    .revise(|checked| *checked = value)
                                            }),
                                    ),
                                ],
                            ),
                            line(
                                "discussion-modal-actions",
                                vec![
                                    button(
                                        context.translated(scope, "common.cancel"),
                                        "secondary cancel-channel-create",
                                        true,
                                        move || {
                                            controller
                                                .create_dialog_open
                                                .revise(|value| *value = false)
                                        },
                                    ),
                                    create,
                                ],
                            ),
                        ],
                    )
                }),
            },
        )
    })
}

fn promote_dialog(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    props: ChatPanelProps,
    controller: ChatController,
) -> View {
    use super::native::{block, button, field};
    use crate::presentation::widgets::{empty, heading, line, reactive_distinct};
    let open = scope.bond(move || {
        crate::messaging::discussion_promote::discussion_promote_enabled()
            && controller.promote_discussion_draft.get().is_open()
    });
    reactive_distinct(open, move |scope, open| {
        if !open {
            return empty();
        };
        let context = context.clone();
        let realm = props.selected_realm_id.clone();
        crate::components::dismissible_popup(
            scope,
            context.clone(),
            crate::components::DismissiblePopupProps {
                overlay_class: "discussion-modal-backdrop discussion-promote-modal".into(),
                surface_class: "discussion-modal".into(),
                aria_label: "Create a private Circle discussion".into(),
                on_dismiss: Rc::new(move |()| {
                    controller
                        .promote_discussion_draft
                        .revise(|draft| draft.close())
                }),
                overlay_test_id: None,
                surface_test_id: Some("discussion-promote-modal".into()),
                overlay_style: None,
                surface_style: None,
                children: Rc::new(move |scope| {
                    let title = scope.bond(move || controller.promote_discussion_draft.get().title);
                    let create_context = context.clone();
                    let realm = realm.clone();
                    block(
                        "discussion-modal-content",
                        vec![
                            heading(
                                2,
                                "discussion-modal-head",
                                "Create a private Circle discussion",
                            ),
                            field(
                                "Private discussion title",
                                "discussion-promote-confirm-input",
                                title,
                                false,
                                move |value| {
                                    controller
                                        .promote_discussion_draft
                                        .revise(|draft| draft.title = value)
                                },
                            ),
                            line(
                                "actions",
                                vec![
                                    button(
                                        "Cancel",
                                        "secondary discussion-promote-cancel",
                                        true,
                                        move || {
                                            controller
                                                .promote_discussion_draft
                                                .revise(|draft| draft.close())
                                        },
                                    ),
                                    button(
                                        "Create private discussion",
                                        "primary discussion-promote-confirm-button",
                                        scope.bond(move || {
                                            controller
                                                .promote_discussion_draft
                                                .get()
                                                .is_submittable()
                                        }),
                                        move || {
                                            let draft =
                                                controller.promote_discussion_draft.get_untracked();
                                            let Some(source) = draft.source_id else {
                                                return;
                                            };
                                            let Some(actor) =
                                                create_context.principal_id.get_untracked()
                                            else {
                                                return;
                                            };
                                            match crate::messaging::discussion_promote::build_promote_steps(&realm,actor.as_str(),&source,draft.title.trim()) {Ok(steps)=>{controller.promote_discussion_draft.revise(|draft|draft.close());controller.promote_private_discussion(create_context.base_url.get_untracked(),create_context.token.get_untracked(),source,steps);},Err(error)=>controller.status_msg.revise(|value|*value=format!("Private discussion creation failed: {error}"))}
                                        },
                                    ),
                                ],
                            ),
                        ],
                    )
                }),
            },
        )
    })
}

fn watch_picker(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    props: ChatPanelProps,
    authority: arkret_sdk::AccountId,
    controller: ChatController,
) -> View {
    use super::native::button;
    use crate::presentation::widgets::{empty, reactive_distinct};
    let state_context = context.clone();
    let realm = props.selected_realm_id.clone();
    let state = scope.bond(move || {
        let selected = controller.selected_channel.get();
        let sidecar =
            super::snapshot::active_sidecar(&state_context, &props, &authority, &selected)
                .is_some();
        let channel = controller
            .channels
            .get()
            .into_iter()
            .find(|channel| channel.strand_id == selected);
        let request = if !sidecar && channel.is_some_and(|channel| channel.scope_circle.is_none()) {
            arkret_sdk::RealmId::new(realm.clone())
                .ok()
                .zip(arkret_sdk::StrandId::new(selected).ok())
                .map(
                    |(realm_id, strand_id)| arkret_sdk::StrandWatchCurrentRequestBody {
                        realm_id,
                        strand_id,
                        watcher_actor_id: arkret_sdk::ActorId::account(authority.clone()),
                    },
                )
        } else {
            None
        };
        let observed = controller.strand_watch_current.get();
        let target_matches = request.as_ref().is_some_and(|request| {
            controller.strand_watch_target_is_current(
                &state_context.base_url.get(),
                &state_context.token.get(),
                request,
            )
        });
        let enabled = request
            .as_ref()
            .zip(observed.as_ref())
            .is_some_and(|(request, current)| current.validate_for_request(request).is_ok())
            && target_matches
            && !controller.strand_watch_pending.get();
        let level = observed.as_ref().and_then(|current| match current {
            arkret_sdk::StrandWatchCurrentResponseBody::Current { current_state, .. } => {
                match current_state.value {
                    arkret_sdk::StrandWatchValue::Set(value) => Some(value.level),
                    arkret_sdk::StrandWatchValue::Cleared(()) => None,
                }
            }
            arkret_sdk::StrandWatchCurrentResponseBody::NeverWritten { .. } => None,
        });
        (
            request,
            enabled,
            target_matches && controller.strand_watch_queued.get(),
            level,
        )
    });
    let label_context = context.clone();
    let status = scope.bond(move || {
        let (_, enabled, _, explicit) = state.get();
        let key = if controller.strand_watch_pending.get() {
            "chat.watch_level.pending_short"
        } else if enabled && explicit.is_none() {
            "chat.watch_level.default"
        } else if enabled {
            watch_level_label_key(controller.strand_watch_level.get())
        } else {
            "chat.watch_level.unavailable_short"
        };
        label_context.tr(key)
    });
    let prefix = context.translated(scope, "chat.watch_level.prefix");
    let label = scope.bond(move || format!("{}: {}", prefix.get(), status.get()));
    let mut options = Vec::new();
    for (level, key, description) in [
        (
            Some(arkret_sdk::StrandWatchLevel::MentionsOnly),
            "chat.watch_level.mentions_only",
            "chat.watch_level.mentions_only_description",
        ),
        (
            Some(arkret_sdk::StrandWatchLevel::Participating),
            "chat.watch_level.participating",
            "chat.watch_level.participating_description",
        ),
        (
            Some(arkret_sdk::StrandWatchLevel::All),
            "chat.watch_level.all",
            "chat.watch_level.all_description",
        ),
        (
            Some(arkret_sdk::StrandWatchLevel::Muted),
            "chat.watch_level.muted",
            "chat.watch_level.muted_description",
        ),
        (
            None,
            "chat.watch_level.clear",
            "chat.watch_level.clear_description",
        ),
    ] {
        let option_app = context.clone();
        let option_label = context.translated(scope, key);
        let description = context.translated(scope, description);
        let current = scope.bond(move || state.get().3 == level);
        let key = match level {
            Some(arkret_sdk::StrandWatchLevel::MentionsOnly) => "mentions-only",
            Some(arkret_sdk::StrandWatchLevel::Participating) => "participating",
            Some(arkret_sdk::StrandWatchLevel::All) => "all",
            Some(arkret_sdk::StrandWatchLevel::Muted) => "muted",
            None => "clear",
        };
        options.push(super::message_actions::FiniteMenuEntry {
            key: key.to_owned(),
            class: scope
                .bond(move || {
                    if current.get() {
                        "watch-level-option active".to_owned()
                    } else {
                        "watch-level-option".to_owned()
                    }
                })
                .into(),
            label: option_label.into(),
            enabled: scope.bond(move || state.get().1).into(),
            content: Some(Rc::new(move |scope| {
                Box::new(
                    group().fill((
                        text()
                            .class("watch-level-check")
                            .content(scope.bond(move || {
                                if current.get() {
                                    "✓".to_owned()
                                } else {
                                    String::new()
                                }
                            })),
                        text()
                            .class("watch-level-option-label")
                            .content(option_label),
                        text()
                            .class("watch-level-option-description")
                            .content(description),
                    )),
                )
            })),
            on_activate: Rc::new(move || {
                let (request, enabled, ..) = state.get_untracked();
                if enabled && let Some(request) = request {
                    controller.set_strand_watch_level(
                        option_app.base_url.get_untracked(),
                        option_app.token.get_untracked(),
                        request,
                        level,
                    );
                }
            }),
        });
    }
    let menu = super::message_actions::finite_menu(super::message_actions::FiniteMenuProps {
        key: format!("watch-level-{}", scope.id().slot()),
        label: label.into(),
        enabled: scope.bond(move || state.get().1).into(),
        open: controller.watch_level_menu_open,
        entries: options,
        on_open_change: Rc::new(move |open| {
            controller
                .watch_level_menu_open
                .revise(|value| *value = open)
        }),
        boundary: None,
        wrapper_class: "watch-level-picker",
        trigger_class: "watch-level-toggle",
        panel_class: "sapid-layer watch-level-menu",
        trigger_content: Rc::new(move |_| {
            Box::new(group().fill((
                crate::components::ui_icon("bell"),
                text().class("watch-level-toggle-label").content(prefix),
                text().class("watch-level-status").content(status),
                crate::components::ui_icon("chevron-down"),
            )))
        }),
        gap: 4.0,
    });
    let retry_context = context.clone();
    let retry = reactive_distinct(scope.bond(move || state.get().2), move |scope, queued| {
        if !queued {
            return empty();
        };
        let context = retry_context.clone();
        button(
            context.translated(scope, "common.retry"),
            "secondary watch-level-retry",
            scope.bond(move || !controller.strand_watch_write_pending()),
            move || {
                if let Some(request) = state.get_untracked().0 {
                    controller.recover_strand_watch(
                        context.base_url.get_untracked(),
                        context.token.get_untracked(),
                        request,
                    );
                }
            },
        )
    });
    Box::new(
        view()
            .class("watch-level-controls")
            .semantics(scope.bond(move || {
                Some(Box::new(glory::render::Semantics {
                    busy: Some(controller.strand_watch_read_running()),
                    ..Default::default()
                }))
            }))
            .fill(vec![retry, menu]),
    )
}
