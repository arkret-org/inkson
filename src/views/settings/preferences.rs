//! Persistent notification and privacy preferences over the single application store.

use super::*;

fn sync_watches(context: Rc<InksonContext>) {
    push_notification_rules_account_data(
        context.clone(),
        context.base_url.get(),
        context.token.get(),
        context.state_store.read(|store| store.realm_watch_levels()),
    );
}
fn sync_receipts(context: Rc<InksonContext>) {
    push_read_receipt_account_data(
        context.clone(),
        context.base_url.get(),
        context.token.get(),
        context.state_store.clone(),
    );
}
fn watch_options(_context: &InksonContext) -> Vec<(String, String)> {
    [
        WatchLevel::All,
        WatchLevel::Participating,
        WatchLevel::MentionsOnly,
        WatchLevel::Muted,
    ]
    .into_iter()
    .map(|level| (level.as_wire().to_owned(), watch_level_label(level)))
    .collect()
}
pub(super) fn notifications(scope: &Scope, context: Rc<InksonContext>) -> View {
    let controller = controller::SettingsController::new(scope, context.clone());
    let seed = context
        .state_store
        .read(|store| model::dnd_editor_seed(store.notification_dnd_settings().as_ref()));
    let dnd = scope.cage(seed.enabled);
    let mode = scope.cage(seed.mode);
    let feedback = scope.cage(String::new());
    let sound = scope.cage(
        context
            .state_store
            .read(crate::notification_sound::notification_sound_enabled),
    );
    let chosen_realm = scope.cage(String::new());
    let chosen_level = scope.cage(WatchLevel::Muted.as_wire().to_owned());
    let overrides = scope.cage(context.state_store.read(|store| store.realm_watch_levels()));
    let mut kind_controls = Vec::new();
    for (kind, label) in [
        ("mention", "settings.notifications.kind_mention"),
        ("reaction", "settings.notifications.kind_reaction"),
        ("invite", "settings.notifications.kind_invite"),
        ("message", "settings.notifications.kind_message"),
    ] {
        let enabled = scope.cage(
            context
                .state_store
                .read(|store| store.notification_kind_enabled(kind)),
        );
        let write_context = context.clone();
        let status_context = context.clone();
        let status_label = scope.bond(move || {
            status_context.tr(if enabled.get() {
                "settings.notifications.kind_enabled"
            } else {
                "settings.notifications.kind_muted"
            })
        });
        kind_controls.push(stack(
            format!("metric settings-notification-kind-{kind}"),
            vec![
                paragraph(
                    "settings-notification-kind-label",
                    context.translated(scope, label),
                ),
                Box::new(
                    sapid::checkbox()
                        .unstyled()
                        .class("settings-toggle settings-notification-kind-status")
                        .name(context.translated(scope, label))
                        .label(status_label)
                        .checked(enabled)
                        .on_checked_change(move |next| {
                            enabled.revise(|value| *value = next);
                            write_context
                                .state_store
                                .write(|store| store.set_notification_kind_enabled(kind, next));
                            crate::components::feedback::toast_success(
                                if next {
                                    "feedback.notification_kind_enabled"
                                } else {
                                    "feedback.notification_kind_muted"
                                },
                                vec![("label", write_context.tr(label))],
                            );
                        }),
                ),
            ],
        ));
    }
    let sound_context = context.clone();
    let save_context = context.clone();
    let list_context = context.clone();
    let list = reactive(overrides, move |scope, levels| {
        let context = list_context.clone();
        let mut rows = Vec::new();
        if levels.is_empty() {
            rows.push(paragraph(
                "muted",
                context.translated(scope, "settings.notifications.overrides_empty"),
            ));
        }
        for (realm, level) in levels {
            use sha2::Digest;

            let selected = scope.cage(level.as_wire().to_owned());
            let identity = match glory::render::SemanticId::new(format!(
                "notification-realm-{}",
                hex::encode(sha2::Sha256::digest(realm.as_bytes()))
            )) {
                Ok(id) => id,
                Err(error) => {
                    scope.report_error(error);
                    continue;
                }
            };
            let row_class = scope.bond(move || {
                format!(
                    "actions settings-realm-override-row{}",
                    if selected.get() == WatchLevel::Muted.as_wire() {
                        " settings-muted-realm-row"
                    } else {
                        ""
                    }
                )
            });
            let change_context = context.clone();
            let remove_context = context.clone();
            let change_id = realm.clone();
            let remove_id = realm.clone();
            rows.push(Box::new(
                glory::ui::view()
                    .class(row_class)
                    .role(glory::render::Role::Group)
                    .name(context.translated(scope, "friendly.realm"))
                    .semantics(Some(Box::new(glory::render::Semantics {
                        described_by: Some(identity.clone()),
                        ..Default::default()
                    })))
                    .fill(vec![
                        Box::new(
                            glory::ui::text()
                                .class("sr-only settings-realm-override-identity")
                                .content(realm.clone())
                                .semantics(Some(Box::new(glory::render::Semantics {
                                    id: Some(identity),
                                    ..Default::default()
                                }))),
                        ) as View,
                        plain(short_protocol_id(&realm)),
                        choice(
                            scope,
                            context.clone(),
                            &format!("watch-level-{}", rows.len()),
                            "settings.notifications.notify_label",
                            selected,
                            watch_options(&context),
                            true,
                            move |next| {
                                selected.revise(|value| *value = next.clone());
                                change_context.state_store.write(|store| {
                                    store.set_realm_watch_level(
                                        change_id.clone(),
                                        WatchLevel::from_wire(&next).unwrap_or_default(),
                                    )
                                });
                                sync_watches(change_context.clone());
                            },
                        ),
                        action(
                            scope,
                            context.clone(),
                            "settings-realm-override-remove",
                            "settings.notifications.remove_override",
                            "secondary",
                            true,
                            move || {
                                remove_context.state_store.write(|store| {
                                    store.set_realm_watch_level(
                                        remove_id.clone(),
                                        WatchLevel::default(),
                                    )
                                });
                                overrides.revise(|value| {
                                    *value = remove_context
                                        .state_store
                                        .read(|store| store.realm_watch_levels())
                                });
                                sync_watches(remove_context.clone());
                            },
                        ),
                    ]),
            ) as View);
        }
        stack("settings-list", rows)
    });
    let add_context = context.clone();
    let clear_context = context.clone();
    let push_register = controller.clone();
    let register_context = context.clone();
    let push_unregister = controller.clone();
    let unregister_context = context.clone();
    let push = context.state_store.read(|store| store.push_registration());
    let push_label = crate::push::push_status_label(push.as_ref());
    stack(
        "settings-card-grid",
        vec![
            card(
                scope,
                context.clone(),
                "settings.notifications.defaults_title",
                vec![
                    stack("metric-grid", kind_controls),
                    toggle(
                        scope,
                        context.clone(),
                        "settings-notification-sound-toggle",
                        "settings.notifications.sound_on",
                        sound,
                        true,
                        move |next| {
                            sound.revise(|value| *value = next);
                            sound_context.state_store.write(|store| {
                                crate::notification_sound::set_notification_sound_enabled(
                                    store, next,
                                )
                            });
                            if next {
                                crate::notification_sound::initialize_notification_audio();
                            }
                        },
                    ),
                    action(
                        scope,
                        context.clone(),
                        "settings-notification-sound-test",
                        "settings.notifications.sound_test",
                        "secondary",
                        sound,
                        move || {
                            if sound.get_untracked() {
                                crate::notification_sound::initialize_notification_audio();
                                crate::notification_sound::play_notification_sound();
                            }
                        },
                    ),
                    toggle(
                        scope,
                        context.clone(),
                        "dnd-enabled-toggle",
                        "settings.notifications.dnd",
                        dnd,
                        true,
                        move |next| dnd.revise(|value| *value = next),
                    ),
                    choice(
                        scope,
                        context.clone(),
                        "dnd-mode-select",
                        "settings.notifications.dnd",
                        mode,
                        vec![
                            ("off".into(), context.tr("settings.notifications.dnd_off")),
                            ("now".into(), context.tr("settings.notifications.dnd_now")),
                        ],
                        true,
                        move |next| mode.revise(|value| *value = next),
                    ),
                    action(
                        scope,
                        context.clone(),
                        "save-notification-settings-button",
                        "common.save",
                        "primary",
                        true,
                        move || {
                            let Some(account) = save_context.active_account.get() else {
                                return;
                            };
                            push_dnd_account_data(
                                save_context.clone(),
                                save_context.base_url.get(),
                                save_context.token.get(),
                                account.authority.clone(),
                                account.principal_id().to_string(),
                                account.device_id.to_string(),
                                dnd.get(),
                                mode.get(),
                                save_context.state_store.clone(),
                                None,
                                feedback,
                            );
                            sync_watches(save_context.clone());
                        },
                    ),
                    status(feedback),
                ],
            ),
            card(
                scope,
                context.clone(),
                "settings.notifications.overrides_title",
                vec![
                    paragraph(
                        "muted",
                        context.translated(scope, "settings.notifications.overrides_body"),
                    ),
                    line(
                        "actions",
                        vec![
                            realm_picker::picker(
                                scope,
                                context.clone(),
                                chosen_realm,
                                "realm-override-realm-select",
                            ),
                            choice(
                                scope,
                                context.clone(),
                                "realm-override-level-select",
                                "settings.notifications.notify_label",
                                chosen_level,
                                watch_options(&context),
                                true,
                                move |next| chosen_level.revise(|value| *value = next),
                            ),
                            action(
                                scope,
                                context.clone(),
                                "realm-override-add",
                                "settings.notifications.add_override",
                                "primary",
                                true,
                                move || {
                                    let realm = chosen_realm.get();
                                    if realm.trim().is_empty() {
                                        return;
                                    }
                                    add_context.state_store.write(|store| {
                                        store.set_realm_watch_level(
                                            realm,
                                            WatchLevel::from_wire(&chosen_level.get())
                                                .unwrap_or_default(),
                                        )
                                    });
                                    overrides.revise(|value| {
                                        *value = add_context
                                            .state_store
                                            .read(|store| store.realm_watch_levels())
                                    });
                                    chosen_realm.revise(|value| value.clear());
                                    sync_watches(add_context.clone());
                                },
                            ),
                        ],
                    ),
                    list,
                    action(
                        scope,
                        context.clone(),
                        "notifications-settings-clear-muted-realms",
                        "settings.notifications.clear_overrides",
                        "secondary",
                        true,
                        move || {
                            clear_context.state_store.write(|store| {
                                let ids: Vec<_> = store.realm_watch_levels().into_keys().collect();
                                for id in ids {
                                    store.set_realm_watch_level(id, WatchLevel::default());
                                }
                            });
                            overrides.revise(|value| {
                                *value = clear_context
                                    .state_store
                                    .read(|store| store.realm_watch_levels())
                            });
                            sync_watches(clear_context.clone());
                        },
                    ),
                ],
            ),
            card(
                scope,
                context.clone(),
                "settings.push.title",
                vec![
                    paragraph("muted", context.translated(scope, "settings.push.body")),
                    plain(push_label),
                    line(
                        "actions",
                        vec![
                            action(
                                scope,
                                context.clone(),
                                "push-register-button",
                                "settings.register_push",
                                "secondary",
                                true,
                                move || {
                                    let Some(account) = register_context.active_account.get()
                                    else {
                                        return;
                                    };
                                    push_register.clone().register_push(
                                        register_context.base_url.get(),
                                        register_context.token.get(),
                                        register_context.device_id.get(),
                                        account.authority,
                                        register_context
                                            .state_store
                                            .read(|store| store.session_grant()),
                                    );
                                },
                            ),
                            action(
                                scope,
                                context.clone(),
                                "push-unregister-button",
                                "settings.unregister_push",
                                "secondary",
                                true,
                                move || {
                                    push_unregister.clone().unregister_push(
                                        unregister_context.base_url.get(),
                                        unregister_context.token.get(),
                                        unregister_context.device_id.get(),
                                        unregister_context
                                            .state_store
                                            .read(|store| store.session_grant()),
                                        unregister_context
                                            .state_store
                                            .read(|store| store.push_registration()),
                                    );
                                },
                            ),
                        ],
                    ),
                    status(context.push_state),
                ],
            ),
        ],
    )
}

fn preference_card(
    scope: &Scope,
    context: Rc<InksonContext>,
    title: &str,
    badge: &str,
    children: Vec<View>,
) -> View {
    let mut nodes = vec![line(
        "event-head",
        vec![
            plain(context.translated(scope, title)),
            plain(context.translated(scope, badge)),
        ],
    )];
    nodes.extend(children);
    stack("event", nodes)
}

pub(super) fn privacy(scope: &Scope, context: Rc<InksonContext>) -> View {
    let visibility = scope.cage(
        context
            .state_store
            .read(|store| store.presence_visibility().as_wire().to_owned()),
    );
    let seed = context.state_store.read(|store| {
        model::presence_editor_seed(&store.presence_preference(), chrono::Utc::now())
    });
    let manual = scope.cage(seed.manual_state);
    let message = scope.cage(seed.status_message);
    let expiry = scope.cage("never".to_owned());
    let feedback = scope.cage(String::new());
    let send = scope.cage(
        context
            .state_store
            .read(|store| store.read_receipt_default_send()),
    );
    let display = scope.cage(
        context
            .state_store
            .read(|store| store.read_receipt_default_display()),
    );
    let receipt_overrides = scope.cage(
        context
            .state_store
            .read(|store| store.read_receipt_realm_overrides()),
    );
    let receipt_realm = scope.cage(String::new());
    let visibility_context = context.clone();
    let save_context = context.clone();
    let clear_context = context.clone();
    let send_context = context.clone();
    let display_context = context.clone();
    let receipt_context = context.clone();
    let receipt_rows = reactive(receipt_overrides, move |scope, overrides| {
        let context = receipt_context.clone();
        let mut rows = Vec::new();
        for (realm, send) in overrides {
            let policy = context
                .state_store
                .read(|store| store.read_receipt_policy_for_realm(&realm));
            let locked = policy.as_ref().is_some_and(|policy| {
                policy.disclosure != arkret_sdk::ReadReceiptDisclosure::Optional
            });
            let toggle_context = context.clone();
            let clear_context = context.clone();
            let toggle_id = realm.clone();
            let clear_id = realm.clone();
            rows.push(line(
                "actions read-receipt-override-row",
                vec![
                    plain(short_protocol_id(&realm)),
                    plain(context.translated(
                        scope,
                        if send {
                            "settings.read_receipts.badge_sending"
                        } else {
                            "settings.read_receipts.badge_skipping"
                        },
                    )),
                    action(
                        scope,
                        context.clone(),
                        "read-receipt-override-toggle",
                        if send {
                            "settings.read_receipts.switch_to_skip"
                        } else {
                            "settings.read_receipts.switch_to_send"
                        },
                        "secondary",
                        !locked,
                        move || {
                            if locked {
                                return;
                            }
                            toggle_context.state_store.write(|store| {
                                store
                                    .set_read_receipt_realm_override(toggle_id.clone(), Some(!send))
                            });
                            receipt_overrides.revise(|value| {
                                *value = toggle_context
                                    .state_store
                                    .read(|store| store.read_receipt_realm_overrides())
                            });
                            sync_receipts(toggle_context.clone());
                        },
                    ),
                    action(
                        scope,
                        context.clone(),
                        "read-receipt-override-clear",
                        "settings.read_receipts.inherit_default",
                        "secondary",
                        !locked,
                        move || {
                            if locked {
                                return;
                            }
                            clear_context.state_store.write(|store| {
                                store.set_read_receipt_realm_override(clear_id.clone(), None)
                            });
                            receipt_overrides.revise(|value| {
                                *value = clear_context
                                    .state_store
                                    .read(|store| store.read_receipt_realm_overrides())
                            });
                            sync_receipts(clear_context.clone());
                        },
                    ),
                ],
            ));
            if locked {
                rows.push(paragraph(
                    "muted",
                    context.translated(scope, "settings.read_receipts.locked"),
                ));
            }
        }
        stack("settings-list", rows)
    });
    let mut add_buttons = Vec::new();
    for send in [false, true] {
        let add_context = context.clone();
        add_buttons.push(action(
            scope,
            context.clone(),
            if send {
                "read-receipt-add-override-send"
            } else {
                "read-receipt-add-override-skip"
            },
            if send {
                "settings.read_receipts.add_send"
            } else {
                "settings.read_receipts.add_skip"
            },
            "secondary",
            {
                let read = context.clone();
                scope.bond(move || {
                    let _ = read.state_revision.get();
                    read.state_store.read(|store| {
                        selected_realm_id(&preference_realm_options(store), &receipt_realm.get())
                            .is_some()
                    })
                })
            },
            move || {
                let options = add_context.state_store.read(preference_realm_options);
                let Some(realm) = selected_realm_id(&options, &receipt_realm.get()) else {
                    return;
                };
                add_context.state_store.write(|store| {
                    store.set_read_receipt_realm_override(realm.to_string(), Some(send))
                });
                receipt_overrides.revise(|value| {
                    *value = add_context
                        .state_store
                        .read(|store| store.read_receipt_realm_overrides())
                });
                receipt_realm.revise(|value| value.clear());
                sync_receipts(add_context.clone());
            },
        ));
    }
    stack(
        "settings-content-stack privacy-settings",
        vec![
            preference_card(
                scope,
                context.clone(),
                "settings.group.privacy",
                "settings.privacy.badge",
                vec![
                    choice(
                        scope,
                        context.clone(),
                        "presence-visibility-select",
                        "settings.privacy.presence_visibility",
                        visibility,
                        ["public", "contacts_only", "consent_only", "nobody"]
                            .into_iter()
                            .map(|value| {
                                (
                                    value.to_owned(),
                                    context.tr(&format!(
                                        "settings.privacy.presence_visibility.{value}"
                                    )),
                                )
                            })
                            .collect(),
                        true,
                        move |next| {
                            let Some(parsed) = crate::state::PresenceVisibility::parse_wire(&next)
                            else {
                                return;
                            };
                            visibility.revise(|value| *value = next);
                            visibility_context
                                .state_store
                                .write(|store| store.set_presence_visibility(parsed));
                            push_presence_visibility_account_data(
                                visibility_context.clone(),
                                visibility_context.base_url.get(),
                                visibility_context.token.get(),
                                visibility_context.state_store.clone(),
                            );
                        },
                    ),
                    line(
                        "event-head",
                        vec![
                            plain(context.translated(scope, "settings.privacy.status_title")),
                            plain(context.translated(scope, "settings.privacy.status_badge")),
                        ],
                    ),
                    stack(
                        "settings-presence-editor",
                        vec![
                            choice(
                                scope,
                                context.clone(),
                                "presence-manual-state-select",
                                "settings.privacy.status_title",
                                manual,
                                ["auto", "online", "idle", "dnd"]
                                    .into_iter()
                                    .map(|value| {
                                        (
                                            value.to_owned(),
                                            context.tr(&format!(
                                                "settings.privacy.presence_state.{value}"
                                            )),
                                        )
                                    })
                                    .collect(),
                                true,
                                move |next| manual.revise(|value| *value = next),
                            ),
                            input_prompt(
                                scope,
                                context
                                    .translated(
                                        scope,
                                        "settings.privacy.status_message_placeholder",
                                    )
                                    .into(),
                                message,
                                input(
                                    scope,
                                    context.clone(),
                                    "presence-status-message-input",
                                    "settings.privacy.status_message_placeholder",
                                    message,
                                    true,
                                ),
                            ),
                        ],
                    ),
                    line(
                        "actions",
                        vec![
                            choice(
                                scope,
                                context.clone(),
                                "presence-status-expiry-select",
                                "settings.privacy.status_title",
                                expiry,
                                ["never", "30m", "1h", "today"]
                                    .into_iter()
                                    .map(|value| {
                                        (
                                            value.to_owned(),
                                            context.tr(&format!(
                                                "settings.privacy.status_expiry.{value}"
                                            )),
                                        )
                                    })
                                    .collect(),
                                true,
                                move |next| expiry.revise(|value| *value = next),
                            ),
                            action(
                                scope,
                                context.clone(),
                                "presence-status-save-button",
                                "settings.privacy.status_save",
                                "primary",
                                true,
                                move || {
                                    let message =
                                        arkret_sdk::canonical::to_nfc(message.get().trim());
                                    if let Err(error) =
                                        arkret_sdk::validate_status_message(&message)
                                    {
                                        feedback.revise(|value| *value = error.to_string());
                                        return;
                                    }
                                    let manual_state = match manual.get().as_str() {
                                        "auto" => None,
                                        "online" => Some(arkret_sdk::ManualPresenceState::Online),
                                        "idle" => Some(arkret_sdk::ManualPresenceState::Idle),
                                        "dnd" => Some(arkret_sdk::ManualPresenceState::Dnd),
                                        _ => return,
                                    };
                                    let has_preference =
                                        manual_state.is_some() || !message.is_empty();
                                    let preference = crate::state::PresencePreference {
                                        manual_state,
                                        status_message: (!message.is_empty()).then_some(message),
                                        clears_at: has_preference
                                            .then(|| presence_expiry_to_clears_at(&expiry.get()))
                                            .flatten(),
                                    };
                                    let cleared = preference.is_empty();
                                    save_context
                                        .state_store
                                        .write(|store| store.set_presence_preference(preference));
                                    feedback.revise(|value| {
                                        *value = save_context.tr(if cleared {
                                            "settings.privacy.status_cleared"
                                        } else {
                                            "settings.privacy.status_saved"
                                        })
                                    });
                                    push_presence_preference_account_data(
                                        save_context.clone(),
                                        save_context.base_url.get(),
                                        save_context.token.get(),
                                        save_context.state_store.clone(),
                                    );
                                },
                            ),
                            action(
                                scope,
                                context.clone(),
                                "presence-status-clear-button",
                                "settings.privacy.status_clear",
                                "secondary",
                                true,
                                move || {
                                    manual.revise(|value| *value = "auto".into());
                                    message.revise(|value| value.clear());
                                    expiry.revise(|value| *value = "never".into());
                                    clear_context.state_store.write(|store| {
                                        store.set_presence_preference(
                                            crate::state::PresencePreference::default(),
                                        )
                                    });
                                    feedback.revise(|value| {
                                        *value = clear_context.tr("settings.privacy.status_cleared")
                                    });
                                    push_presence_preference_account_data(
                                        clear_context.clone(),
                                        clear_context.base_url.get(),
                                        clear_context.token.get(),
                                        clear_context.state_store.clone(),
                                    );
                                },
                            ),
                        ],
                    ),
                    status(feedback),
                    line(
                        "event-head",
                        vec![
                            plain(context.translated(scope, "chat.settings.read_receipts")),
                            plain(
                                context.translated(scope, "settings.read_receipts.default_badge"),
                            ),
                        ],
                    ),
                    toggle(
                        scope,
                        context.clone(),
                        "read-receipts-default-toggle",
                        "settings.read_receipts.send_default",
                        send,
                        true,
                        move |next| {
                            send.revise(|value| *value = next);
                            send_context
                                .state_store
                                .write(|store| store.set_read_receipt_default_send(next));
                            sync_receipts(send_context.clone());
                        },
                    ),
                    toggle(
                        scope,
                        context.clone(),
                        "read-receipts-display-default-toggle",
                        "settings.read_receipts.display_default",
                        display,
                        true,
                        move |next| {
                            display.revise(|value| *value = next);
                            display_context
                                .state_store
                                .write(|store| store.set_read_receipt_default_display(next));
                            sync_receipts(display_context.clone());
                        },
                    ),
                    line(
                        "event-head",
                        vec![
                            plain(
                                context
                                    .translated(scope, "settings.read_receipts.realm_exceptions"),
                            ),
                            plain(scope.bond(move || {
                                format!("{} configured", receipt_overrides.get().len())
                            })),
                        ],
                    ),
                    receipt_rows,
                    line("actions privacy-receipt-controls", {
                        add_buttons.insert(
                            0,
                            realm_picker::picker(
                                scope,
                                context.clone(),
                                receipt_realm,
                                "read-receipt-realm-select",
                            ),
                        );
                        add_buttons
                    }),
                ],
            ),
            remarks(scope, context.clone()),
            preference_card(
                scope,
                context.clone(),
                "settings.contact_petnames.title",
                "settings.remarks.badge_private",
                context.state_store.read(|store| {
                    let remarks = store.contact_remarks();
                    let mut nodes = vec![paragraph(
                        "muted",
                        context.tr("settings.contact_petnames.body"),
                    )];
                    if remarks.is_empty() {
                        nodes.push(paragraph(
                            "muted contact-remarks-empty",
                            context.tr("settings.contact_petnames.empty"),
                        ));
                    }
                    nodes.extend(remarks.into_iter().map(|(id, remark)| {
                        line(
                            "actions",
                            vec![
                                plain(actor_display_label(store, &id)),
                                plain(remark.petname),
                            ],
                        )
                    }));
                    nodes
                }),
            ),
            card(
                scope,
                context.clone(),
                "settings.handle.title",
                vec![
                    paragraph(
                        "muted",
                        context.translated(scope, "settings.handle.managed_body"),
                    ),
                    crate::identity::account_auth::issuer_handle_management_url(
                        &context.base_url.get(),
                    )
                    .map(|href| {
                        Box::new(
                            glory::prelude::link()
                                .class("btn secondary")
                                .target(href)
                                .fill(glory::prelude::text().content(
                                    context.translated(scope, "settings.handle.issuer_link"),
                                )),
                        ) as View
                    })
                    .unwrap_or_else(|| {
                        // No verified issuer URL exists for an external navigation action.
                        action(
                            scope,
                            context.clone(),
                            "handle-issuer-link-disabled",
                            "settings.handle.issuer_link_unavailable",
                            "secondary",
                            false,
                            || {},
                        )
                    }),
                ],
            ),
        ],
    )
}

fn remarks(scope: &Scope, context: Rc<InksonContext>) -> View {
    let snapshot = scope.cage(context.state_store.read(|store| store.realm_remarks()));
    let chosen = scope.cage(String::new());
    let name = scope.cage(String::new());
    let list_context = context.clone();
    let list = reactive(snapshot, move |scope, remarks| {
        let context = list_context.clone();
        let mut rows = Vec::new();
        if remarks.is_empty() {
            rows.push(paragraph(
                "muted realm-remarks-empty",
                context.translated(scope, "settings.realm_remarks.empty"),
            ));
        }
        for (realm, remark) in remarks {
            let value = scope.cage(remark.local_name.clone());
            let save_context = context.clone();
            let pin_context = context.clone();
            let delete_context = context.clone();
            let save_id = realm.clone();
            let pin_id = realm.clone();
            let delete_id = realm.clone();
            let existing = remark.clone();
            let pin_existing = remark.clone();
            let pinned = !remark.pinned;
            rows.push(line(
                "actions realm-remark-row",
                vec![
                    plain(short_protocol_id(&realm)),
                    input(
                        scope,
                        context.clone(),
                        &format!("remark-{}", rows.len()),
                        "settings.realm_remarks.local_name_private",
                        value,
                        true,
                    ),
                    action(
                        scope,
                        context.clone(),
                        "realm-remark-pin-toggle",
                        if remark.pinned {
                            "realm.unpin"
                        } else {
                            "realm.pin"
                        },
                        "secondary",
                        true,
                        move || {
                            let Ok(typed) = arkret_sdk::RealmId::new(pin_id.clone()) else {
                                return;
                            };
                            let next =
                                crate::account_data::RealmRemark::with_pinned_preserving_fields(
                                    typed,
                                    Some(&pin_existing),
                                    pinned,
                                    chrono::Utc::now(),
                                );
                            pin_context.state_store.write(|store| {
                                store.set_realm_remark(pin_id.clone(), next.clone())
                            });
                            snapshot.revise(|value| {
                                *value = pin_context.state_store.read(|store| store.realm_remarks())
                            });
                            push_realm_remark_account_data_with_failure_toast(
                                pin_context.clone(),
                                pin_context.base_url.get(),
                                pin_context.token.get(),
                                pin_id.clone(),
                                next,
                            );
                        },
                    ),
                    action(
                        scope,
                        context.clone(),
                        "realm-remark-save",
                        "common.save",
                        "secondary",
                        true,
                        move || {
                            let mut next = existing.clone();
                            next.local_name = value.get().trim().to_owned();
                            next.updated_at = Some(chrono::Utc::now());
                            save_context.state_store.write(|store| {
                                store.set_realm_remark(save_id.clone(), next.clone())
                            });
                            snapshot.revise(|value| {
                                *value =
                                    save_context.state_store.read(|store| store.realm_remarks())
                            });
                            push_realm_remark_account_data(
                                save_context.clone(),
                                save_context.base_url.get(),
                                save_context.token.get(),
                                save_id.clone(),
                                next,
                            );
                        },
                    ),
                    action(
                        scope,
                        context.clone(),
                        "realm-remark-delete",
                        "common.delete",
                        "secondary",
                        true,
                        move || {
                            let Ok(typed) = arkret_sdk::RealmId::new(delete_id.clone()) else {
                                return;
                            };
                            delete_context
                                .state_store
                                .write(|store| store.remove_realm_remark(&delete_id));
                            snapshot.revise(|value| {
                                *value = delete_context
                                    .state_store
                                    .read(|store| store.realm_remarks())
                            });
                            push_realm_remark_account_data(
                                delete_context.clone(),
                                delete_context.base_url.get(),
                                delete_context.token.get(),
                                delete_id.clone(),
                                crate::account_data::RealmRemark::new(typed, chrono::Utc::now()),
                            );
                        },
                    ),
                ],
            ));
        }
        stack("settings-list", rows)
    });
    let add_context = context.clone();
    preference_card(
        scope,
        context.clone(),
        "settings.realm_remarks.title",
        "settings.remarks.badge_private",
        vec![
            list,
            realm_picker::picker(scope, context.clone(), chosen, "realm-remark-realm-select"),
            input_prompt(
                scope,
                context
                    .translated(scope, "settings.realm_remarks.local_name")
                    .into(),
                name,
                input(
                    scope,
                    context.clone(),
                    "realm-remark-add-name",
                    "settings.realm_remarks.local_name",
                    name,
                    true,
                ),
            ),
            action(
                scope,
                context.clone(),
                "realm-remark-add-save",
                "settings.realm_remarks.add",
                "secondary",
                {
                    let read = context.clone();
                    scope.bond(move || {
                        let _ = read.state_revision.get();
                        !name.get().trim().is_empty()
                            && read.state_store.read(|store| {
                                selected_realm_id(&preference_realm_options(store), &chosen.get())
                                    .is_some()
                            })
                    })
                },
                move || {
                    let options = add_context.state_store.read(preference_realm_options);
                    let Some(realm) = selected_realm_id(&options, &chosen.get()) else {
                        return;
                    };
                    let local_name = name.get().trim().to_owned();
                    if local_name.is_empty() {
                        return;
                    }
                    let id = realm.to_string();
                    let now = chrono::Utc::now();
                    let mut remark = crate::account_data::RealmRemark::new(realm, now);
                    remark.local_name = local_name;
                    remark.updated_at = Some(now);
                    add_context
                        .state_store
                        .write(|store| store.set_realm_remark(id.clone(), remark.clone()));
                    snapshot.revise(|value| {
                        *value = add_context.state_store.read(|store| store.realm_remarks())
                    });
                    chosen.revise(|value| value.clear());
                    name.revise(|value| value.clear());
                    push_realm_remark_account_data(
                        add_context.clone(),
                        add_context.base_url.get(),
                        add_context.token.get(),
                        id,
                        remark,
                    );
                },
            ),
        ],
    )
}

#[cfg(test)]
mod tests {
    use glory::render::{Event, Props};

    use super::*;

    #[test]
    fn actual_notification_control_retains_live_localized_status_and_persists_toggle() {
        let directory = tempfile::Builder::new()
            .prefix("notification-kind-ui-")
            .tempdir_in("D:/BuildCache/inkson-glory/tmp")
            .unwrap();
        let app = glory::App::memory();
        let context = InksonContext::new(
            app.scope(),
            crate::presentation::BootState {
                config_store: crate::config::LocalConfigStore::with_path(
                    directory.path().join("config.json"),
                ),
                config: crate::config::ClientConfig::default(),
                state_store: SharedStateStore::new(crate::state::LocalStateStore::with_path(
                    directory.path().join("state.json"),
                )),
                initial_credential: String::new(),
                realm_tree_nodes: Vec::new(),
            },
            Route::NotificationsSettings,
            |_| Box::pin(std::future::pending()),
        );
        context.locale.revise(|locale| *locale = UiLocale::En);
        app.mount(notifications(app.scope(), context.clone()))
            .unwrap();
        app.flush().unwrap();
        let mut pending = app.tree().roots().to_vec();
        let control = loop {
            let id = pending.pop().expect("mention checkbox is mounted");
            let tree = app.tree();
            let node = tree.node(id).unwrap();
            let view = node.descriptor.view();
            if matches!(view.props, Props::Check(_))
                && view.name.as_deref() == Some("Mention notifications")
            {
                break id;
            }
            pending.extend(node.children.iter().copied());
        };
        for locale in [UiLocale::En, UiLocale::Zh, UiLocale::En] {
            context.locale.revise(|value| *value = locale);
            app.flush().unwrap();
            let was_enabled = context
                .state_store
                .read(|store| store.notification_kind_enabled("mention"));
            assert!(
                app.dispatch(control, Event::CheckedChanged(!was_enabled))
                    .unwrap()
            );
            app.flush().unwrap();
            let enabled = context
                .state_store
                .read(|store| store.notification_kind_enabled("mention"));
            assert_eq!(enabled, !was_enabled);
            let tree = app.tree();
            let view = tree.node(control).unwrap().descriptor.view();
            assert_eq!(
                view.name.as_deref(),
                Some(context.tr("settings.notifications.kind_mention").as_str())
            );
            let Props::Check(props) = view.props else {
                panic!("same live checkbox remains mounted")
            };
            assert_eq!(props.checked, enabled);
            assert_eq!(
                props.label,
                context.tr(if enabled {
                    "settings.notifications.kind_enabled"
                } else {
                    "settings.notifications.kind_muted"
                })
            );
        }
    }
}
