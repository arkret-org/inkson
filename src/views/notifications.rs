use dioxus::prelude::*;
use dioxus_router::Link;
use serde_json::Value;

use crate::{
    components::{EmptyState, EmptyStateKind, HelpTip, UiIcon},
    local_state::{ClientLocalState, LocalStateStore},
    routes::Route,
    views::helpers::with_authed_api,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NotificationGroup {
    All,
    BySpace,
    ByType,
    ByTime,
}

#[derive(Clone, Debug, PartialEq)]
struct Notification {
    id: String,
    title: String,
    body: String,
    space_id: String,
    kind: String,
    read: bool,
    archived: bool,
    timestamp: String,
    action_label: Option<String>,
}

#[component]
pub fn NotificationsPanel(
    base_url: String,
    token: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let initial_state = state_store.read().load();
    let initial_notifications = hydrate_notifications(
        initial_state.notification_projection.clone(),
        &initial_state,
    );

    let mut notifications = use_signal(move || initial_notifications.clone());
    let mut group_by = use_signal(|| NotificationGroup::ByTime);
    let mut show_archived = use_signal(|| false);
    let mut did_bootstrap = use_signal(|| false);
    let mut status_msg = use_signal(|| String::new());
    let server_unread = use_signal(|| 0usize);

    if !did_bootstrap() {
        did_bootstrap.set(true);
        refresh_notifications(
            base_url.clone(),
            token(),
            state_store,
            notifications,
            status_msg,
            server_unread,
        );
    }

    let local_state = state_store.read().load();
    let mut visible_notifications = notifications()
        .into_iter()
        .filter(|notification| {
            (show_archived() || !notification.archived)
                && notification_kind_enabled(&local_state, &notification.kind)
                && !space_is_muted(&local_state, &notification.space_id)
        })
        .collect::<Vec<_>>();

    match group_by() {
        NotificationGroup::All | NotificationGroup::ByTime => {
            visible_notifications.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
        }
        NotificationGroup::BySpace => {
            visible_notifications.sort_by(|left, right| {
                left.space_id
                    .cmp(&right.space_id)
                    .then_with(|| right.timestamp.cmp(&left.timestamp))
            });
        }
        NotificationGroup::ByType => {
            visible_notifications.sort_by(|left, right| {
                left.kind
                    .cmp(&right.kind)
                    .then_with(|| right.timestamp.cmp(&left.timestamp))
            });
        }
    }

    let unread_visible = visible_notifications
        .iter()
        .filter(|notification| !notification.read)
        .count();
    let total_notifications = notifications().len();

    rsx! {
        div { class: "timeline", "data-testid": "notifications-panel", role: "region", "aria-label": "Notifications",
            div { class: "event notification-toolbar", role: "status", "aria-live": "polite",
                div { class: "event-head",
                    span { "Notifications" }
                    div { class: "section-tools",
                        HelpTip { text: "Notifications are derived from sync account data and filtered by local mute rules. Push only wakes the client; notification bodies are resolved locally." }
                        span { "{unread_visible} unread / {server_unread()} server" }
                    }
                }
                div { class: "toolbar-row",
                    div { class: "segmented-control", role: "tablist", "aria-label": "Notification grouping",
                        button {
                            class: if group_by() == NotificationGroup::All { "segment active" } else { "segment" },
                            onclick: move |_| group_by.set(NotificationGroup::All),
                            {crate::i18n::tr("notifications.group.all")}
                        }
                        button {
                            class: if group_by() == NotificationGroup::BySpace { "segment active" } else { "segment" },
                            onclick: move |_| group_by.set(NotificationGroup::BySpace),
                            {crate::i18n::tr("notifications.group.space")}
                        }
                        button {
                            class: if group_by() == NotificationGroup::ByType { "segment active" } else { "segment" },
                            onclick: move |_| group_by.set(NotificationGroup::ByType),
                            {crate::i18n::tr("notifications.group.type")}
                        }
                        button {
                            class: if group_by() == NotificationGroup::ByTime { "segment active" } else { "segment" },
                            onclick: move |_| group_by.set(NotificationGroup::ByTime),
                            {crate::i18n::tr("notifications.group.time")}
                        }
                    }
                    div { class: "icon-actions",
                        button {
                            class: "btn icon sm ghost",
                            "data-testid": "mark-all-read",
                            title: crate::i18n::tr("notifications.tooltip.mark_all_read"),
                            "aria-label": crate::i18n::tr("notifications.tooltip.mark_all_read"),
                            onclick: move |_| {
                                let ids = notifications().iter().map(|notification| notification.id.clone()).collect::<Vec<_>>();
                                for notification in notifications.write().iter_mut() {
                                    notification.read = true;
                                }
                                let mut store = state_store.write();
                                for id in ids {
                                    store.set_notification_read(id, true);
                                }
                                status_msg.set("All visible notifications marked read locally.".to_owned());
                            },
                            UiIcon { name: "check" }
                        }
                        button {
                            class: "btn icon sm ghost",
                            "data-testid": "toggle-archived",
                            title: if show_archived() { crate::i18n::tr("notifications.tooltip.hide_archived") } else { crate::i18n::tr("notifications.tooltip.show_archived") },
                            "aria-label": if show_archived() { crate::i18n::tr("notifications.tooltip.hide_archived") } else { crate::i18n::tr("notifications.tooltip.show_archived") },
                            onclick: move |_| show_archived.set(!show_archived()),
                            UiIcon { name: "archive" }
                        }
                    }
                    div { class: "icon-actions",
                    button {
                        class: "btn icon sm ghost",
                        "data-testid": "refresh-notifications",
                        title: crate::i18n::tr("notifications.tooltip.refresh"),
                        "aria-label": crate::i18n::tr("notifications.tooltip.refresh"),
                        onclick: move |_| {
                            refresh_notifications(
                                base_url.clone(),
                                token(),
                                state_store,
                                notifications,
                                status_msg,
                                server_unread,
                            );
                        },
                        UiIcon { name: "refresh" }
                    }
                    }
                }
                if !status_msg().is_empty() {
                    div { class: "muted", "data-testid": "notifications-status", "{status_msg}" }
                }
            }

            for notification in visible_notifications.iter() {
                div {
                    class: "event",
                    "data-testid": "notification-item",
                    key: "{notification.id}",
                    style: if notification.read { "opacity: 0.6;" } else { "" },
                    div { class: "event-head",
                        span { "{notification.title}" }
                        span { "{notification.kind} / {notification.timestamp}" }
                    }
                    div {
                        class: if notification.read { "muted" } else { "space-title" },
                        "{notification.body}"
                    }
                    if !notification.space_id.is_empty() {
                        div { class: "muted", "Space: {notification.space_id}" }
                    }
                    div { class: "actions",
                        if !notification.read {
                            button {
                                class: "btn icon sm ghost",
                                "data-testid": "mark-read-button",
                                title: "Mark read",
                                "aria-label": "Mark read",
                                onclick: {
                                    let notification_id = notification.id.clone();
                                    move |_| {
                                        if let Some(entry) = notifications.write().iter_mut().find(|candidate| candidate.id == notification_id) {
                                            entry.read = true;
                                        }
                                        state_store.write().set_notification_read(notification_id.clone(), true);
                                    }
                                },
                                UiIcon { name: "check" }
                            }
                        } else {
                            button {
                                class: "btn icon sm ghost",
                                "data-testid": "mark-unread-button",
                                title: "Mark unread",
                                "aria-label": "Mark unread",
                                onclick: {
                                    let notification_id = notification.id.clone();
                                    move |_| {
                                        if let Some(entry) = notifications.write().iter_mut().find(|candidate| candidate.id == notification_id) {
                                            entry.read = false;
                                        }
                                        state_store.write().set_notification_read(notification_id.clone(), false);
                                    }
                                },
                                UiIcon { name: "bell" }
                            }
                        }
                        if !notification.archived {
                            button {
                                class: "btn icon sm ghost",
                                "data-testid": "archive-button",
                                title: "Archive",
                                "aria-label": "Archive",
                                onclick: {
                                    let notification_id = notification.id.clone();
                                    move |_| {
                                        if let Some(entry) = notifications.write().iter_mut().find(|candidate| candidate.id == notification_id) {
                                            entry.archived = true;
                                        }
                                        state_store.write().set_notification_archived(notification_id.clone(), true);
                                    }
                                },
                                UiIcon { name: "archive" }
                            }
                        }
                        if !notification.space_id.is_empty() {
                            button {
                                class: "btn icon sm ghost",
                                "data-testid": "mute-space-button",
                                title: "Mute this space",
                                "aria-label": "Mute this space",
                                onclick: {
                                    let space_id = notification.space_id.clone();
                                    move |_| {
                                        state_store.write().set_space_muted(space_id.clone(), true);
                                        status_msg.set(format!("Muted notifications for {space_id}."));
                                    }
                                },
                                UiIcon { name: "bell" }
                            }
                        }
                        if let Some(ref action) = notification.action_label {
                            button {
                                class: "primary",
                                "data-testid": "notification-action",
                                onclick: {
                                    let title = notification.title.clone();
                                    move |_| status_msg.set(format!("Action queued for {title}."))
                                },
                                "{action}"
                            }
                        }
                    }
                }
            }

            if total_notifications == 0 {
                EmptyState {
                    title: crate::i18n::tr("notifications.title"),
                    kind: EmptyStateKind::Empty,
                    message: Some(crate::i18n::tr("notifications.empty_body")),
                    test_id: Some("notifications-empty".to_owned()),
                }
            } else if visible_notifications.is_empty() {
                EmptyState {
                    title: crate::i18n::tr("notifications.title"),
                    kind: EmptyStateKind::Filtered,
                    message: Some(crate::i18n::tr("notifications.filtered_body")),
                    test_id: Some("notifications-muted-empty".to_owned()),
                }
            }

            div { class: "event", "data-testid": "notifications-settings-hint",
                div { class: "event-head",
                    span { {crate::i18n::tr("notifications.settings_card")} }
                    span { {crate::i18n::tr("notifications.settings_card_hint")} }
                }
                div { class: "muted",
                    {crate::i18n::tr("notifications.settings_card_body")}
                }
                div { class: "actions",
                    Link {
                        class: "secondary",
                        to: Route::SettingsSection { section: "notifications".to_owned() },
                        UiIcon { name: "settings" }
                        {crate::i18n::tr("notifications.settings_card_open")}
                    }
                }
            }
        }
    }
}

fn refresh_notifications(
    base_url: String,
    access_token: String,
    mut state_store: Signal<LocalStateStore>,
    mut notifications: Signal<Vec<Notification>>,
    mut status_msg: Signal<String>,
    mut server_unread: Signal<usize>,
) {
    spawn(async move {
        match with_authed_api(&base_url, access_token, |api| async move {
            api.sync(None).await
        })
        .await
        {
            Ok(response) => {
                let raw_notifications = response
                    .account_data
                    .into_iter()
                    .filter(is_notification_account_data)
                    .collect::<Vec<_>>();
                server_unread.set(raw_notifications.len());
                let hydrated = {
                    let mut store = state_store.write();
                    store.save_notification_projection(raw_notifications.clone());
                    let local_state = store.load();
                    hydrate_notifications(raw_notifications, &local_state)
                };
                let loaded_count = hydrated.len();
                notifications.set(hydrated);
                status_msg.set(format!("Loaded {loaded_count} notification projection(s)."));
            }
            Err(err) => {
                status_msg.set(format!("Notification refresh: {}", err.display()));
            }
        }
    });
}

fn is_notification_account_data(value: &Value) -> bool {
    matches!(
        value
            .get("kind")
            .or_else(|| value.get("type"))
            .and_then(Value::as_str),
        Some("cx.notification")
            | Some("cx.notification.v1")
            | Some("cx.account.notification")
            | Some("notification")
    )
}

fn hydrate_notifications(
    raw_notifications: Vec<Value>,
    local_state: &ClientLocalState,
) -> Vec<Notification> {
    raw_notifications
        .into_iter()
        .enumerate()
        .map(|(index, value)| notification_from_value(index, value, local_state))
        .collect()
}

fn notification_from_value(
    index: usize,
    value: Value,
    local_state: &ClientLocalState,
) -> Notification {
    let id = value_string(&value, &["notification_id", "id"])
        .unwrap_or_else(|| format!("notification-{index}"));
    let client_state = local_state
        .notification_client_state
        .get(&id)
        .cloned()
        .unwrap_or_default();
    let kind = value_string(&value, &["notification_kind", "type", "kind"])
        .unwrap_or_else(|| "message".to_owned());
    let title =
        value_string(&value, &["title"]).unwrap_or_else(|| default_notification_title(&kind));
    let body = value_string(&value, &["body", "preview", "summary"])
        .unwrap_or_else(|| "Notification".to_owned());
    let space_id = value_string(&value, &["space_id"]).unwrap_or_default();
    let timestamp = value_string(&value, &["timestamp", "created_at"])
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

    Notification {
        id,
        title,
        body,
        space_id,
        kind: kind.clone(),
        read: value_bool(&value, "read").unwrap_or(client_state.read),
        archived: value_bool(&value, "archived").unwrap_or(client_state.archived),
        timestamp,
        action_label: Some(default_notification_action(&kind).to_owned()),
    }
}

fn default_notification_title(kind: &str) -> String {
    match kind {
        "invite" => "Space invite".to_owned(),
        "reaction" => "New reaction".to_owned(),
        "mention" => "You were mentioned".to_owned(),
        _ => "New message".to_owned(),
    }
}

fn default_notification_action(kind: &str) -> &'static str {
    match kind {
        "invite" => "Review",
        _ => "View",
    }
}

fn value_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(|field| field.as_str())
            .map(ToOwned::to_owned)
    })
}

fn value_bool(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(|field| field.as_bool())
}

fn space_is_muted(local_state: &ClientLocalState, space_id: &str) -> bool {
    !space_id.is_empty()
        && local_state
            .muted_spaces
            .get(space_id)
            .copied()
            .unwrap_or(false)
}

fn notification_kind_enabled(local_state: &ClientLocalState, kind: &str) -> bool {
    local_state
        .muted_notification_kinds
        .get(kind)
        .copied()
        .unwrap_or(true)
}
