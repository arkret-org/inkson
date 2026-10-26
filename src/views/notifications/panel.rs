use std::rc::Rc;

use glory::{Cage, Scope};

use super::actions::*;
use super::model::*;
use crate::i18n::tr;
use crate::notification_rules::{dnd_settings_from_account_data, push_rules_from_account_data};
use crate::presentation::{InksonContext, View};
use crate::routes::Route;
use crate::state::LocalStateStore;
use crate::views::helpers::short_protocol_id;
use crate::views::settings::widgets::*;
pub(crate) fn rehydrate_notifications(
    store: &LocalStateStore,
    authority: &arkret_sdk::AccountId,
    principal_id: &str,
) -> Vec<super::model::UiNotification> {
    let local_state = store.load();
    let account_data = store.current_account_data_events();
    let push_rules = push_rules_from_account_data(authority, &account_data);
    let account_dnd = dnd_settings_from_account_data(authority, &account_data);
    let effective_dnd = local_state
        .notification_dnd_settings
        .as_ref()
        .or(account_dnd.as_ref());
    let privacy_gate = crate::sidecar::SidecarPrivacyGate::from_store(store, principal_id);
    hydrate_notifications_with_privacy_gate(
        local_state.notification_projection.to_vec(),
        &local_state,
        Some(&arkret_sdk::ActorId::account(authority.clone())),
        push_rules.as_ref(),
        effective_dnd,
        &privacy_gate,
    )
}

#[derive(Clone)]
struct NotificationPage {
    context: Rc<InksonContext>,
    owner: glory::ui::WeakScope,
    authority: arkret_sdk::AccountId,
    notifications: Cage<Vec<UiNotification>>,
    status: Cage<NotificationFeedback>,
    restoring: Cage<std::collections::BTreeSet<String>>,
    previews: Rc<super::invite_preview::InvitePreviewResources>,
}
impl NotificationPage {
    fn refresh(&self) {
        refresh_notifications(
            self.owner.clone(),
            self.context.base_url.get_untracked(),
            self.context.token,
            self.authority.clone(),
            self.context.state_store.clone(),
            self.notifications,
            self.status,
        )
    }
    fn read(&self, notification: UiNotification, read: bool) {
        mark_notification_read_state(
            self.owner.clone(),
            self.context.base_url.get_untracked(),
            self.context.token.get_untracked(),
            self.authority.principal_id.to_string(),
            self.context.device_id.get_untracked(),
            notification,
            read,
            self.context.state_store.clone(),
            self.notifications,
            self.status,
        )
    }
    fn archive(&self, id: String) {
        set_notification_inbox_state(
            self.owner.clone(),
            self.context.base_url.get_untracked(),
            self.context.token.get_untracked(),
            self.authority.clone(),
            self.authority.principal_id.to_string(),
            self.context.device_id.get_untracked(),
            id,
            arkret_sdk::NotificationInboxState::Archived,
            self.context.state_store.clone(),
            self.notifications,
            self.status,
        )
    }
    fn restore(&self, id: String) {
        restore_notification_inbox(
            self.owner.clone(),
            self.context.base_url.get_untracked(),
            self.context.token.get_untracked(),
            self.authority.clone(),
            id,
            self.context.state_store.clone(),
            self.notifications,
            self.status,
            self.restoring,
        )
    }
    fn act(&self, notification: UiNotification) {
        if let Some(action) = notification.action {
            run_notification_action(
                self.owner.clone(),
                self.context.base_url.get_untracked(),
                self.context.token,
                self.authority.clone(),
                self.context.state_store.clone(),
                self.notifications,
                self.status,
                notification.id,
                action,
            )
        } else {
            self.status.revise(|status| {
                *status = NotificationFeedback::new("notifications.feedback.queued")
                    .with_title(notification.title, notification.title_is_key)
            });
        }
    }
}
fn icon_button(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: &str,
    label: &str,
    icon: &str,
    enabled: impl Into<glory::Lotus<bool>>,
    handler: impl FnMut() + 'static,
) -> View {
    Box::new(
        sapid::button()
            .unstyled()
            .class(format!("btn icon {key}"))
            .name(context.translated(scope, label))
            .fill(crate::components::ui_icon(icon))
            .enabled(enabled)
            .on_press(handler),
    )
}
pub fn page(scope: &Scope, context: Rc<InksonContext>, _route: Route) -> View {
    let Some(account) = context.active_account.get_untracked() else {
        return paragraph(
            "event error-banner",
            context.translated(scope, "notifications.no_account"),
        );
    };
    let authority = account.authority;
    let notifications =
        scope.cage(context.state_store.read(|store| {
            rehydrate_notifications(store, &authority, authority.principal_id.as_str())
        }));
    let status = scope.cage(NotificationFeedback::default());
    let state = NotificationPage {
        context: context.clone(),
        owner: scope.downgrade(),
        authority: authority.clone(),
        notifications,
        status,
        restoring: scope.cage(std::collections::BTreeSet::new()),
        previews: super::invite_preview::InvitePreviewResources::new(scope),
    };
    let group = scope.cage(UiNotificationGroup::Latest);
    let archived = scope.cage(false);
    let limit = scope.cage(50usize);
    state.refresh();
    {
        let ctx = context.clone();
        let authority = authority.clone();
        scope.effect(move || {
            let account = ctx.active_account.get();
            let hydrated = if account
                .as_ref()
                .is_some_and(|account| account.authority == authority)
            {
                ctx.state_store.read(|store| {
                    rehydrate_notifications(store, &authority, authority.principal_id.as_str())
                })
            } else {
                Vec::new()
            };
            if notifications.get_untracked() != hydrated {
                notifications.revise(|value| *value = hydrated);
            }
        });
    }
    let grouping = {
        let ctx = context.clone();
        reactive(group, move |scope, current| {
            Box::new(
                glory::ui::view()
                    .class("segmented-control")
                    .role(glory::render::Role::TabList)
                    .name(ctx.translated(scope, "notifications.grouping_label"))
                    .fill(
                        [
                            (UiNotificationGroup::Latest, "notifications.view.latest"),
                            (UiNotificationGroup::ByRealm, "notifications.view.realm"),
                            (UiNotificationGroup::ByType, "notifications.view.type"),
                        ]
                        .into_iter()
                        .map(|(value, label)| {
                            action(
                                scope,
                                ctx.clone(),
                                "notification-group",
                                label,
                                if value == current {
                                    "segment active"
                                } else {
                                    "segment"
                                },
                                true,
                                move || group.revise(|v| *v = value),
                            )
                        })
                        .collect::<Vec<View>>(),
                    ),
            )
        })
    };
    let all = {
        let st = state.clone();
        icon_button(
            scope,
            context.clone(),
            "mark-all-read-button",
            "notifications.tooltip.mark_all_read",
            "check",
            true,
            move || {
                mark_all_notifications_read(
                    st.owner.clone(),
                    st.context.base_url.get_untracked(),
                    st.context.token.get_untracked(),
                    st.authority.principal_id.to_string(),
                    st.context.device_id.get_untracked(),
                    st.context.state_store.clone(),
                    st.notifications,
                    st.status,
                )
            },
        )
    };
    let refresh = {
        let st = state.clone();
        icon_button(
            scope,
            context.clone(),
            "refresh-notifications",
            "notifications.tooltip.refresh",
            "refresh",
            true,
            move || st.refresh(),
        )
    };
    let archive_toggle = icon_button(
        scope,
        context.clone(),
        "toggle-archived",
        "notifications.tooltip.show_archived",
        "archive",
        true,
        move || archived.revise(|v| *v = !*v),
    );
    let contacts = {
        let ctx = context.clone();
        reactive(
            scope.bond(move || {
                let _ = ctx.state_revision.get();
                ctx.contact_rows.get()
            }),
            {
                let ctx = context.clone();
                move |scope, contacts| {
                    let blocklist = ctx.state_store.read(|store| store.client_blocklist());
                    stack(
                        "notification-contact-requests",
                        contacts
                            .into_iter()
                            .filter(|contact| {
                                contact.state == arkret_sdk::ContactState::PendingIncoming
                                    && !crate::account_data::hides_contact_request(
                                        &blocklist,
                                        &contact.peer.contact_actor_id(),
                                    )
                            })
                            .map(|contact| contact_request(scope, ctx.clone(), contact))
                            .collect(),
                    )
                }
            },
        )
    };
    let source = {
        let ctx = context.clone();
        scope.bond(move || {
            let _ = ctx.locale.get();
            let _ = ctx.state_revision.get();
            let _ = ctx.session_generation.get();
            let _ = ctx.active_account.get();
            let _ = ctx.base_url.get();
            let _ = ctx.token.get();
            (
                notifications.get(),
                group.get(),
                archived.get(),
                limit.get(),
            )
        })
    };
    let st = state.clone();
    let feed = reactive(source, move |scope, (all, group, archived, limit)| {
        let snapshot = st.context.snapshot();
        let total = all.len();
        let mut rows = all
            .into_iter()
            .filter(|row| {
                (archived || !row.archived)
                    && notification_kind_enabled(&snapshot, &row.kind)
                    && (!realm_is_muted(&snapshot, &row.realm_id)
                        || notification_overrides_realm_mute(row))
            })
            .collect::<Vec<_>>();
        match group {
            UiNotificationGroup::Latest => rows.sort_by(|a, b| b.timestamp.cmp(&a.timestamp)),
            UiNotificationGroup::ByRealm => rows.sort_by(|a, b| {
                a.realm_id
                    .cmp(&b.realm_id)
                    .then_with(|| b.timestamp.cmp(&a.timestamp))
            }),
            UiNotificationGroup::ByType => rows.sort_by(|a, b| {
                a.kind
                    .cmp(&b.kind)
                    .then_with(|| b.timestamp.cmp(&a.timestamp))
            }),
        }
        let _visible = rows.len();
        let rows = rows.into_iter().take(limit).collect::<Vec<_>>();
        let preview_keys = rows
            .iter()
            .filter_map(|row| match &row.action {
                Some(UiNotificationAction::AcceptInvite {
                    realm_id,
                    invite_id,
                    credential,
                }) => super::invite_preview::InvitePreviewUiKey::current(
                    &st.context,
                    &st.authority,
                    realm_id,
                    invite_id,
                    credential.clone(),
                )
                .ok(),
                _ => None,
            })
            .collect::<Vec<_>>();
        st.previews.retain_visible(&preview_keys);
        let mut children = rows
            .into_iter()
            .map(|notification| notification_row(scope, st.clone(), notification))
            .collect::<Vec<_>>();
        if total > 0 && children.is_empty() {
            children.push(crate::components::empty_state(
                scope,
                st.context.clone(),
                crate::components::EmptyStateProps {
                    title: tr("notifications.feed_title"),
                    kind: crate::components::EmptyStateKind::Filtered,
                    message: Some(tr("notifications.filtered_body")),
                    test_id: Some("notifications-muted-empty".into()),
                    badge_override: None,
                },
            ));
        }
        stack("notification-feed", children)
    });
    let load_more = {
        let ctx = context.clone();
        let source_context = context.clone();
        reactive(
            scope.bond(move || {
                let _ = source_context.state_revision.get();
                (notifications.get(), archived.get(), limit.get())
            }),
            move |scope, (rows, archived, window)| {
                let snapshot = ctx.snapshot();
                let count = rows
                    .into_iter()
                    .filter(|row| {
                        (archived || !row.archived)
                            && notification_kind_enabled(&snapshot, &row.kind)
                            && (!realm_is_muted(&snapshot, &row.realm_id)
                                || notification_overrides_realm_mute(row))
                    })
                    .count();
                if count <= window {
                    return empty();
                }
                line(
                    "actions notifications-load-more-row",
                    vec![
                        paragraph(
                            "muted",
                            format!("{} {} / {}", tr("notifications.showing"), window, count),
                        ),
                        action(
                            scope,
                            ctx.clone(),
                            "notifications-load-more",
                            "notifications.load_more",
                            "secondary",
                            true,
                            move || limit.revise(|v| *v = v.saturating_add(50)),
                        ),
                    ],
                )
            },
        )
    };
    Box::new(
        glory::ui::view()
            .class("timeline notifications-panel")
            .role(glory::render::Role::Section)
            .name(context.translated(scope, "notifications.panel_label"))
            .fill(vec![
                contacts,
                line(
                    "toolbar-row",
                    vec![
                        grouping,
                        line("icon-actions", vec![all, archive_toggle, refresh]),
                    ],
                ),
                paragraph(
                    "muted notifications-status",
                    scope.bond(move || status.get().render()),
                ),
                feed,
                load_more,
            ]),
    )
}
fn notification_row(scope: &Scope, state: NotificationPage, notification: UiNotification) -> View {
    let ctx = state.context.clone();
    let mut children = vec![
        line(
            "event-head",
            vec![
                plain(notification.render_title()),
                plain(format!(
                    "{} / {}",
                    notification.kind, notification.timestamp
                )),
            ],
        ),
        paragraph(
            if notification.read {
                "muted"
            } else {
                "entity-title"
            },
            notification.render_body(),
        ),
    ];
    if let Some(route) = ctx
        .state_store
        .read(|store| super::model::direct_notification_route(store, &notification))
    {
        let nav = ctx.clone();
        children.push(action(
            scope,
            ctx.clone(),
            "notification-open-chat",
            "notifications.open_chat",
            "secondary",
            true,
            move || nav.navigate(route.clone()),
        ));
    }
    if let Some(hint) = &notification.watch_hint {
        children.push(paragraph("muted notification-watch-hint", tr(hint)));
    }
    if !notification.realm_id.is_empty() {
        let label = notification
            .realm_label
            .as_ref()
            .filter(|label| !label.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| short_protocol_id(&notification.realm_id));
        children.push(paragraph(
            "muted",
            format!("{}: {}", tr(notification_scope_kind(&notification)), label),
        ));
    }
    if let Some(UiNotificationAction::AcceptInvite {
        realm_id,
        invite_id,
        credential,
    }) = notification.action.clone()
    {
        children.push(super::invite_preview::invite_preview(
            scope,
            ctx.clone(),
            state.previews.clone(),
            state.authority.clone(),
            realm_id,
            invite_id,
            credential,
        ));
    }
    let mut buttons = vec![];
    {
        let st = state.clone();
        let row = notification.clone();
        buttons.push(icon_button(
            scope,
            ctx.clone(),
            if notification.read {
                "mark-unread-button"
            } else {
                "mark-read-button"
            },
            if notification.read {
                "notifications.tooltip.mark_unread"
            } else {
                "notifications.tooltip.mark_read"
            },
            if notification.read { "bell" } else { "check" },
            true,
            move || st.read(row.clone(), !row.read),
        ));
    }
    if notification.archived
        && notification
            .id
            .parse::<arkret_wire::NotificationProjectionId>()
            .is_ok()
    {
        let st = state.clone();
        let id = notification.id.clone();
        let restoring = state.restoring;
        let enabled = {
            let id = id.clone();
            scope.bond(move || !restoring.get().contains(&id))
        };
        buttons.push(icon_button(
            scope,
            ctx.clone(),
            "unarchive-button",
            "notifications.tooltip.restore",
            "archive",
            enabled,
            move || st.restore(id.clone()),
        ));
    } else if !notification.archived {
        let st = state.clone();
        let id = notification.id.clone();
        buttons.push(icon_button(
            scope,
            ctx.clone(),
            "archive-button",
            "notifications.tooltip.archive",
            "archive",
            true,
            move || st.archive(id.clone()),
        ));
    }
    if !notification.realm_id.is_empty() {
        let ctx = ctx.clone();
        let realm = notification.realm_id.clone();
        let status = state.status;
        buttons.push(icon_button(
            scope,
            ctx.clone(),
            "mute-realm-button",
            "notifications.tooltip.mute_realm",
            "bell",
            true,
            move || {
                ctx.state_store
                    .write(|store| store.set_realm_muted(realm.clone(), true));
                status.revise(|v| {
                    *v = NotificationFeedback::new("notifications.feedback.muted")
                        .with("realm", short_protocol_id(&realm))
                });
            },
        ));
    }
    if let Some(label) = &notification.action_label {
        let st = state.clone();
        let row = notification.clone();
        buttons.push(action(
            scope,
            ctx.clone(),
            "notification-action",
            label,
            "primary",
            true,
            move || st.act(row.clone()),
        ));
    }
    children.push(line("actions", buttons));
    Box::new(
        glory::prelude::view()
            .class(if notification.read {
                "event notification-item notification-read"
            } else {
                "event notification-item"
            })
            .fill(children),
    )
}
fn contact_request(
    scope: &Scope,
    context: Rc<InksonContext>,
    contact: crate::models::ContactView,
) -> View {
    let busy = scope.cage(false);
    let status = scope.cage(crate::views::contacts::ContactFeedback::default());
    let peer = contact.peer.contact_actor_id().to_string();
    let request = contact.request_event_ref.as_ref().map(ToString::to_string);
    let label = context
        .state_store
        .read(|store| crate::views::helpers::contact_peer_label(store, &contact));
    let mut children = vec![
        plain(context.translated(scope, "notifications.contact_request.title")),
        plain(label),
    ];
    if let Some(message) = contact.request_message {
        children.push(paragraph("contact-request-message", message));
    }
    let ctx = context.clone();
    children.push(action(
        scope,
        context.clone(),
        "notification-contact-accept",
        "contacts.action.accept",
        "primary",
        scope.bond(move || !busy.get()),
        move || {
            let generation = ctx.session_generation.get_untracked();
            let peer_done = peer.clone();
            let request_done = request.clone();
            let callback = {
                let ctx = ctx.clone();
                Rc::new(move |_| {
                    if ctx.session_generation.get_untracked() == generation {
                        ctx.contact_rows.revise(|rows| {
                            rows.retain(|row| {
                                !(row.state == arkret_sdk::ContactState::PendingIncoming
                                    && row.peer.contact_actor_id().to_string() == peer_done
                                    && row.request_event_ref.as_ref().map(ToString::to_string)
                                        == request_done)
                            })
                        });
                    }
                })
            };
            crate::views::contacts::run_contact_action(
                ctx.clone(),
                ctx.base_url.get_untracked(),
                ctx.token.get_untracked(),
                crate::views::contacts::ContactRowAction::Respond {
                    requester: peer.clone(),
                    request_event_ref: request.clone(),
                    verb: "accept".into(),
                },
                "contacts.action.accepting",
                busy,
                status,
                callback,
                None,
            );
        },
    ));
    children.push(paragraph(
        "muted",
        scope.bond(move || status.get().render()),
    ));
    stack("event contact-request-notification", children)
}
