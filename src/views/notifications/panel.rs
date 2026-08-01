//! The `NotificationsPanel` RSX component: grouping toolbar, the paged
//! notification feed, and the row-level read / archive / mute / action
//! controls. The network handlers it invokes live in [`super::actions`]
//! and the projection logic in [`super::model`].

use dioxus::prelude::*;

use super::actions::{
    mark_all_notifications_read, mark_notification_read_state, refresh_notifications,
    run_notification_action, set_notification_inbox_state,
};
use super::model::{
    UiNotificationGroup, hydrate_notifications_with_privacy_gate, notification_kind_enabled,
    notification_overrides_realm_mute, notification_scope_kind, realm_is_muted,
};
use crate::components::{EmptyState, EmptyStateKind, UiIcon};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::views::helpers::short_protocol_id;

#[component]
pub fn NotificationsPanel(
    account_did: String,
    device_id: String,
    token: Signal<String>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = crate::app::SessionContext::get().state_store;
    let (initial_state, initial_privacy_gate) = {
        let store = state_store.read();
        (
            store.load(),
            crate::sidecar::SidecarPrivacyGate::from_store(&store, &account_did),
        )
    };
    let initial_notifications = hydrate_notifications_with_privacy_gate(
        initial_state.notification_projection.clone(),
        &initial_state,
        &account_did,
        None,
        initial_state.notification_dnd_settings.as_ref(),
        &initial_privacy_gate,
    );

    let notifications = use_signal(move || initial_notifications.clone());
    let mut group_by = use_signal(|| UiNotificationGroup::Latest);
    let mut show_archived = use_signal(|| false);
    let mut did_bootstrap = use_signal(|| false);
    let mut status_msg = use_signal(String::new);

    if !did_bootstrap() {
        did_bootstrap.set(true);
        refresh_notifications(
            base_url.clone(),
            token,
            state_store,
            notifications,
            status_msg,
        );
    }

    let local_state = state_store.read().load();
    let mut visible_notifications = notifications()
        .into_iter()
        .filter(|notification| {
            (show_archived() || !notification.archived)
                && notification_kind_enabled(&local_state, &notification.kind)
                && (!realm_is_muted(&local_state, &notification.realm_id)
                    || notification_overrides_realm_mute(notification))
        })
        .collect::<Vec<_>>();

    match group_by() {
        UiNotificationGroup::Latest => {
            visible_notifications.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
        }
        UiNotificationGroup::ByRealm => {
            visible_notifications.sort_by(|left, right| {
                left.realm_id
                    .cmp(&right.realm_id)
                    .then_with(|| right.timestamp.cmp(&left.timestamp))
            });
        }
        UiNotificationGroup::ByType => {
            visible_notifications.sort_by(|left, right| {
                left.kind
                    .cmp(&right.kind)
                    .then_with(|| right.timestamp.cmp(&left.timestamp))
            });
        }
    }

    let total_notifications = notifications().len();

    // F-NOTIF-VLIST-1: client-side paging — start by rendering only the
    // first 50 notifications and let the user expand the window via the
    // "Load more" button at the foot of the list. A user with 1000+
    // notifications no longer pays the full DOM cost on every render,
    // and the "0/N" badge below makes it obvious how much more is
    // available. Real virtualization (windowed rows) is a follow-up.
    let mut visible_limit = use_signal(|| 50usize);
    let visible_total = visible_notifications.len();
    let visible_window: usize = visible_total.min(visible_limit());
    let visible_notifications: Vec<_> = visible_notifications
        .into_iter()
        .take(visible_window)
        .collect();
    let has_more_to_load = visible_total > visible_window;
    let status_text = status_msg();

    rsx! {
        div { class: "timeline notifications-panel", "data-testid": "notifications-panel", role: "region", "aria-label": "Notifications",
            div { class: "toolbar-row",
                div { class: "segmented-control", role: "tablist", "aria-label": "Notification grouping",
                    Button {
                        variant: ButtonVariant::Secondary,
                        class: if group_by() == UiNotificationGroup::Latest { "segment active" } else { "segment" },
                        onclick: move |_| group_by.set(UiNotificationGroup::Latest),
                        {crate::i18n::tr("notifications.view.latest")}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        class: if group_by() == UiNotificationGroup::ByRealm { "segment active" } else { "segment" },
                        onclick: move |_| group_by.set(UiNotificationGroup::ByRealm),
                        {crate::i18n::tr("notifications.view.realm")}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        class: if group_by() == UiNotificationGroup::ByType { "segment active" } else { "segment" },
                        onclick: move |_| group_by.set(UiNotificationGroup::ByType),
                        {crate::i18n::tr("notifications.view.type")}
                    }
                }
                div { class: "icon-actions",
                    Button {
                        variant: ButtonVariant::Ghost,
                        size: ButtonSize::Sm,
                        class: "btn icon",
                        "data-testid": "mark-all-read-button",
                        title: crate::i18n::tr("notifications.tooltip.mark_all_read"),
                        "aria-label": crate::i18n::tr("notifications.tooltip.mark_all_read"),
                        onclick: {
                            let base_url = base_url.clone();
                            let account_did = account_did.clone();
                            let device_id = device_id.clone();
                            move |_| {
                                mark_all_notifications_read(
                                    base_url.clone(),
                                    token(),
                                    account_did.clone(),
                                    device_id.clone(),
                                    state_store,
                                    notifications,
                                    status_msg,
                                );
                            }
                        },
                        UiIcon { name: "check" }
                    }
                    Button {
                        variant: ButtonVariant::Ghost,
                        size: ButtonSize::Sm,
                        class: "btn icon",
                        "data-testid": "toggle-archived",
                        title: if show_archived() { crate::i18n::tr("notifications.tooltip.hide_archived") } else { crate::i18n::tr("notifications.tooltip.show_archived") },
                        "aria-label": if show_archived() { crate::i18n::tr("notifications.tooltip.hide_archived") } else { crate::i18n::tr("notifications.tooltip.show_archived") },
                        onclick: move |_| show_archived.set(!show_archived()),
                        UiIcon { name: "archive" }
                    }
                    Button {
                        variant: ButtonVariant::Ghost,
                        size: ButtonSize::Sm,
                        class: "btn icon",
                        "data-testid": "refresh-notifications",
                        title: crate::i18n::tr("notifications.tooltip.refresh"),
                        "aria-label": crate::i18n::tr("notifications.tooltip.refresh"),
                        onclick: {
                            let base_url = base_url.clone();
                            move |_| {
                                refresh_notifications(
                                    base_url.clone(),
                                    token,
                                    state_store,
                                    notifications,
                                    status_msg,
                                );
                            }
                        },
                        UiIcon { name: "refresh" }
                    }
                }
            }
            if !status_text.is_empty() {
                div {
                    class: "muted notifications-status",
                    "data-testid": "notifications-status",
                    role: "status",
                    "aria-live": "polite",
                    "{status_text}"
                }
            }

            for notification in visible_notifications.iter() {
                div {
                    class: "event",
                    "data-testid": "notification-item",
                    key: "{notification.id}",
                    style: if notification.read { "opacity: 0.6;" } else { "" },
                    div { class: "event-head",
                        // `title` may be server-provided copy or an i18n
                        // default-title key — `tr()` translates keys and
                        // passes unknown strings through unchanged.
                        span { {crate::i18n::tr(&notification.title)} }
                        span { "{notification.kind} / {notification.timestamp}" }
                    }
                    div {
                        class: if notification.read { "muted" } else { "entity-title" },
                        "{notification.body}"
                    }
                    if let Some(ref hint) = notification.watch_hint {
                        div {
                            class: "muted",
                            "data-testid": "notification-watch-hint",
                            // Watch hints are stored as i18n keys.
                            {crate::i18n::tr(hint)}
                        }
                    }
                    if !notification.realm_id.is_empty() {
                        {
                            let scope_kind = notification_scope_kind(notification);
                            let realm_label = notification
                                .realm_label
                                .as_deref()
                                .filter(|label| !label.trim().is_empty())
                                .map(ToOwned::to_owned)
                                .unwrap_or_else(|| short_protocol_id(&notification.realm_id));
                            rsx! {
                                div {
                                    class: "muted",
                                    title: "{notification.realm_id}",
                                    "{scope_kind}: {realm_label}"
                                }
                            }
                        }
                    }
                    div { class: "actions",
                        if !notification.read {
                            Button {
                                variant: ButtonVariant::Ghost,
                                size: ButtonSize::Sm,
                                class: "btn icon",
                                "data-testid": "mark-read-button",
                                title: "Mark read",
                                "aria-label": "Mark read",
                                onclick: {
                                    let base_url = base_url.clone();
                                    let account_did = account_did.clone();
                                    let device_id = device_id.clone();
                                    let notification = notification.clone();
                                    move |_| {
                                        mark_notification_read_state(
                                            base_url.clone(),
                                            token(),
                                            account_did.clone(),
                                            device_id.clone(),
                                            notification.clone(),
                                            true,
                                            state_store,
                                            notifications,
                                            status_msg,
                                        );
                                    }
                                },
                                UiIcon { name: "check" }
                            }
                        } else {
                            Button {
                                variant: ButtonVariant::Ghost,
                                size: ButtonSize::Sm,
                                class: "btn icon",
                                "data-testid": "mark-unread-button",
                                title: "Mark unread",
                                "aria-label": "Mark unread",
                                onclick: {
                                    let base_url = base_url.clone();
                                    let account_did = account_did.clone();
                                    let device_id = device_id.clone();
                                    let notification = notification.clone();
                                    move |_| {
                                        mark_notification_read_state(
                                            base_url.clone(),
                                            token(),
                                            account_did.clone(),
                                            device_id.clone(),
                                            notification.clone(),
                                            false,
                                            state_store,
                                            notifications,
                                            status_msg,
                                        );
                                    }
                                },
                                UiIcon { name: "bell" }
                            }
                        }
                        if !notification.archived {
                            Button {
                                variant: ButtonVariant::Ghost,
                                size: ButtonSize::Sm,
                                class: "btn icon",
                                "data-testid": "archive-button",
                                title: "Archive",
                                "aria-label": "Archive",
                                onclick: {
                                    let base_url = base_url.clone();
                                    let account_did = account_did.clone();
                                    let device_id = device_id.clone();
                                    let notification_id = notification.id.clone();
                                    move |_| {
                                        set_notification_inbox_state(
                                            base_url.clone(),
                                            token(),
                                            account_did.clone(),
                                            device_id.clone(),
                                            notification_id.clone(),
                                            arkret_sdk::NotificationInboxState::Archived,
                                            state_store,
                                            notifications,
                                            status_msg,
                                        );
                                    }
                                },
                                UiIcon { name: "archive" }
                            }
                        }
                        if !notification.realm_id.is_empty() {
                            Button {
                                variant: ButtonVariant::Ghost,
                                size: ButtonSize::Sm,
                                class: "btn icon",
                                "data-testid": "mute-realm-button",
                                title: "Mute this realm",
                                "aria-label": "Mute this realm",
                                onclick: {
                                    let realm_id = notification.realm_id.clone();
                                    move |_| {
                                        state_store.write().set_realm_muted(realm_id.clone(), true);
                                        status_msg.set(format!(
                                            "Muted notifications for {}.",
                                            short_protocol_id(&realm_id)
                                        ));
                                    }
                                },
                                UiIcon { name: "bell" }
                            }
                        }
                        if let Some(ref action) = notification.action_label {
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "notification-action",
                                onclick: {
                                    let action_to_run = notification.action.clone();
                                    let base_url = base_url.clone();
                                    let notification_id = notification.id.clone();
                                    // Translate now (default titles are i18n keys).
                                    let title = crate::i18n::tr(&notification.title);
                                    move |_| {
                                        if let Some(action_to_run) = action_to_run.clone() {
                                            run_notification_action(
                                                base_url.clone(),
                                                token,
                                                state_store,
                                                notifications,
                                                status_msg,
                                                notification_id.clone(),
                                                action_to_run,
                                            );
                                        } else {
                                            status_msg.set(format!("Action queued for {title}."));
                                        }
                                    }
                                },
                                // Action labels are stored as i18n keys.
                                {crate::i18n::tr(action)}
                            }
                        }
                    }
                }
            }

            if total_notifications > 0 && visible_notifications.is_empty() {
                EmptyState {
                    title: crate::i18n::tr("notifications.feed_title"),
                    kind: EmptyStateKind::Filtered,
                    message: Some(crate::i18n::tr("notifications.filtered_body")),
                    test_id: Some("notifications-muted-empty".to_owned()),
                }
            }

            // F-NOTIF-VLIST-1: progress + "Load more" affordance for the
            // client-side paging window. We surface the visible / total
            // count so the user knows there's more to expand, then step
            // the window forward by another page when they click.
            if has_more_to_load {
                div { class: "actions", "data-testid": "notifications-load-more-row",
                    div { class: "muted",
                        {format!(
                            "{} {} / {}",
                            crate::i18n::tr("notifications.showing"),
                            visible_window,
                            visible_total,
                        )}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "notifications-load-more",
                        onclick: move |_| {
                            visible_limit.with_mut(|n| *n = n.saturating_add(50));
                        },
                        {crate::i18n::tr("notifications.load_more")}
                    }
                }
            }
        }
    }
}
