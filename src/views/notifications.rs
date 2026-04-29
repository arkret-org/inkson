use dioxus::prelude::*;
use serde_json::Value;

use crate::{
    local_state::{ClientLocalState, LocalStateStore},
    views::helpers::authed_api,
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
    let muted_spaces = local_state
        .muted_spaces
        .iter()
        .filter_map(|(space_id, muted)| muted.then_some(space_id.clone()))
        .collect::<Vec<_>>();

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
        div { class: "timeline", "data-testid": "notifications-panel",
            div { class: "event",
                div { class: "event-head",
                    span { "Notifications" }
                    span { "{unread_visible} visible unread / {server_unread()} server unread" }
                }
                div { class: "muted",
                    "Derived from `POST /api/v1/index/notifications` and filtered by local mute rules."
                }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "refresh-notifications",
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
                        "Refresh"
                    }
                    button {
                        class: if group_by() == NotificationGroup::All { "primary" } else { "secondary" },
                        onclick: move |_| group_by.set(NotificationGroup::All),
                        "All"
                    }
                    button {
                        class: if group_by() == NotificationGroup::BySpace { "primary" } else { "secondary" },
                        onclick: move |_| group_by.set(NotificationGroup::BySpace),
                        "By Space"
                    }
                    button {
                        class: if group_by() == NotificationGroup::ByType { "primary" } else { "secondary" },
                        onclick: move |_| group_by.set(NotificationGroup::ByType),
                        "By Type"
                    }
                    button {
                        class: if group_by() == NotificationGroup::ByTime { "primary" } else { "secondary" },
                        onclick: move |_| group_by.set(NotificationGroup::ByTime),
                        "By Time"
                    }
                }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "mark-all-read",
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
                        "Mark All Read"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "toggle-archived",
                        onclick: move |_| show_archived.set(!show_archived()),
                        if show_archived() { "Hide Archived" } else { "Show Archived" }
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
                                class: "secondary",
                                "data-testid": "mark-read-button",
                                onclick: {
                                    let notification_id = notification.id.clone();
                                    move |_| {
                                        if let Some(entry) = notifications.write().iter_mut().find(|candidate| candidate.id == notification_id) {
                                            entry.read = true;
                                        }
                                        state_store.write().set_notification_read(notification_id.clone(), true);
                                    }
                                },
                                "Mark Read"
                            }
                        } else {
                            button {
                                class: "secondary",
                                "data-testid": "mark-unread-button",
                                onclick: {
                                    let notification_id = notification.id.clone();
                                    move |_| {
                                        if let Some(entry) = notifications.write().iter_mut().find(|candidate| candidate.id == notification_id) {
                                            entry.read = false;
                                        }
                                        state_store.write().set_notification_read(notification_id.clone(), false);
                                    }
                                },
                                "Mark Unread"
                            }
                        }
                        if !notification.archived {
                            button {
                                class: "secondary",
                                "data-testid": "archive-button",
                                onclick: {
                                    let notification_id = notification.id.clone();
                                    move |_| {
                                        if let Some(entry) = notifications.write().iter_mut().find(|candidate| candidate.id == notification_id) {
                                            entry.archived = true;
                                        }
                                        state_store.write().set_notification_archived(notification_id.clone(), true);
                                    }
                                },
                                "Archive"
                            }
                        }
                        if !notification.space_id.is_empty() {
                            button {
                                class: "secondary",
                                "data-testid": "mute-space-button",
                                onclick: {
                                    let space_id = notification.space_id.clone();
                                    move |_| {
                                        state_store.write().set_space_muted(space_id.clone(), true);
                                        status_msg.set(format!("Muted notifications for {space_id}."));
                                    }
                                },
                                "Mute Space"
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
                div { class: "event",
                    div { class: "event-head", span { "Notifications" } span { "empty" } }
                    div { class: "muted", "No server-derived notifications loaded yet." }
                }
            } else if visible_notifications.is_empty() {
                div { class: "event", "data-testid": "notifications-muted-empty",
                    div { class: "event-head", span { "Notifications" } span { "filtered" } }
                    div { class: "muted",
                        "All loaded notifications are currently hidden by archive, type, or per-space mute rules."
                    }
                }
            }

            div { class: "event", "data-testid": "bulk-actions",
                div { class: "event-head", span { "Bulk Actions" } span { "" } }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "archive-all-read",
                        onclick: move |_| {
                            let ids = notifications()
                                .iter()
                                .filter(|notification| notification.read)
                                .map(|notification| notification.id.clone())
                                .collect::<Vec<_>>();
                            for notification in notifications.write().iter_mut() {
                                if notification.read {
                                    notification.archived = true;
                                }
                            }
                            let mut store = state_store.write();
                            for id in ids {
                                store.set_notification_archived(id, true);
                            }
                            status_msg.set("Archived all read notifications locally.".to_owned());
                        },
                        "Archive All Read"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "delete-archived",
                        onclick: move |_| {
                            notifications.write().retain(|notification| !notification.archived);
                            status_msg.set("Archived notifications hidden from the local panel.".to_owned());
                        },
                        "Delete Archived"
                    }
                }
            }

            div { class: "event", "data-testid": "notification-rules",
                div { class: "event-head", span { "Notification Rules" } span { "" } }
                div { class: "muted", "Configure per-space and per-type notification muting." }

                div { class: "metric-grid",
                    {render_kind_toggle("mention", "Mention notifications", state_store, status_msg)}
                    {render_kind_toggle("reaction", "Reaction notifications", state_store, status_msg)}
                    {render_kind_toggle("invite", "Invite notifications", state_store, status_msg)}
                    {render_kind_toggle("message", "Message notifications", state_store, status_msg)}
                }

                div { class: "event", "data-testid": "muted-spaces-panel",
                    div { class: "event-head",
                        span { "Muted Spaces" }
                        span { "{muted_spaces.len()}" }
                    }
                    if muted_spaces.is_empty() {
                        div { class: "muted", "No spaces are muted." }
                    } else {
                        for space_id in muted_spaces {
                            div { class: "actions", "data-testid": "muted-space-row",
                                span { "{space_id}" }
                                button {
                                    class: "secondary",
                                    "data-testid": "unmute-space-button",
                                    onclick: {
                                        let space_id = space_id.clone();
                                        move |_| {
                                            state_store.write().set_space_muted(space_id.clone(), false);
                                            status_msg.set(format!("Unmuted notifications for {space_id}."));
                                        }
                                    },
                                    "Unmute"
                                }
                            }
                        }
                        button {
                            class: "secondary",
                            "data-testid": "clear-muted-spaces",
                            onclick: move |_| {
                                state_store.write().clear_muted_spaces();
                                status_msg.set("Cleared all muted spaces.".to_owned());
                            },
                            "Clear All"
                        }
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
        match authed_api(&base_url, access_token) {
            Ok(api) => match api.index_notifications(Some(50)).await {
                Ok(response) => {
                    let raw_notifications = response.notifications;
                    server_unread.set(response.unread_count);
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
                Err(error) => status_msg.set(format!("Notification refresh failed: {error}")),
            },
            Err(error) => status_msg.set(format!("Invalid URL: {error}")),
        }
    });
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
    let kind = value_string(&value, &["kind", "type"]).unwrap_or_else(|| "message".to_owned());
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

fn render_kind_toggle(
    kind: &'static str,
    label: &'static str,
    mut state_store: Signal<LocalStateStore>,
    mut status_msg: Signal<String>,
) -> Element {
    let enabled = state_store.read().notification_kind_enabled(kind);
    rsx! {
        div { class: "metric",
            strong { "{label}" }
            label {
                input {
                    r#type: "checkbox",
                    checked: enabled,
                    onchange: move |event| {
                        let enabled = event.value() == "true";
                        state_store.write().set_notification_kind_enabled(kind, enabled);
                        status_msg.set(format!(
                            "{} {}.",
                            label,
                            if enabled { "enabled" } else { "muted" }
                        ));
                    },
                }
                if enabled { " Enabled" } else { " Muted" }
            }
        }
    }
}

fn default_notification_title(kind: &str) -> String {
    match kind {
        "invite" => "Space invite".to_owned(),
        "contact" => "Contact request".to_owned(),
        "reaction" => "New reaction".to_owned(),
        "mention" => "You were mentioned".to_owned(),
        _ => "New message".to_owned(),
    }
}

fn default_notification_action(kind: &str) -> &'static str {
    match kind {
        "invite" => "Review",
        "contact" => "Accept",
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
