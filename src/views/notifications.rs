use dioxus::prelude::*;

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
pub fn NotificationsPanel(base_url: String, token: Signal<String>) -> Element {
    let mut notifications = use_signal(|| {
        vec![
            Notification {
                id: "notif-1".to_owned(),
                title: "New message".to_owned(),
                body: "Alice sent a message in Demo Space".to_owned(),
                space_id: "cx:space:demo".to_owned(),
                kind: "message".to_owned(),
                read: false,
                archived: false,
                timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                action_label: Some("View".to_owned()),
            },
            Notification {
                id: "notif-2".to_owned(),
                title: "Contact request".to_owned(),
                body: "Bob wants to connect".to_owned(),
                space_id: String::new(),
                kind: "contact".to_owned(),
                read: false,
                archived: false,
                timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                action_label: Some("Accept".to_owned()),
            },
        ]
    });
    let mut group_by = use_signal(|| NotificationGroup::All);
    let mut show_archived = use_signal(|| false);

    rsx! {
        div { class: "timeline", "data-testid": "notifications-panel",
            // Header with group selector
            div { class: "event",
                div { class: "event-head",
                    span { "Notifications" }
                    span { "{notifications().iter().filter(|n| !n.read).count()} unread" }
                }
                div { class: "actions",
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
                            for n in notifications.write().iter_mut() {
                                n.read = true;
                            }
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
            }

            // Notification list
            for notif in notifications() {
                if !notif.archived || show_archived() {
                    div {
                        class: "event",
                        "data-testid": "notification-item",
                        style: if notif.read { "opacity: 0.6;" } else { "" },
                        div { class: "event-head",
                            span { "{notif.title}" }
                            span { "{notif.kind} / {notif.timestamp}" }
                        }
                        div { class: if notif.read { "muted" } else { "space-title" }, "{notif.body}" }
                        if !notif.space_id.is_empty() {
                            div { class: "muted", "Space: {notif.space_id}" }
                        }
                        div { class: "actions",
                            if !notif.read {
                                button {
                                    class: "secondary",
                                    "data-testid": "mark-read-button",
                                    onclick: {
                                        let nid = notif.id.clone();
                                        move |_| {
                                            if let Some(n) = notifications.write().iter_mut().find(|n| n.id == nid) {
                                                n.read = true;
                                            }
                                        }
                                    },
                                    "Mark Read"
                                }
                            } else {
                                button {
                                    class: "secondary",
                                    "data-testid": "mark-unread-button",
                                    onclick: {
                                        let nid = notif.id.clone();
                                        move |_| {
                                            if let Some(n) = notifications.write().iter_mut().find(|n| n.id == nid) {
                                                n.read = false;
                                            }
                                        }
                                    },
                                    "Mark Unread"
                                }
                            }
                            if !notif.archived {
                                button {
                                    class: "secondary",
                                    "data-testid": "archive-button",
                                    onclick: {
                                        let nid = notif.id.clone();
                                        move |_| {
                                            if let Some(n) = notifications.write().iter_mut().find(|n| n.id == nid) {
                                                n.archived = true;
                                            }
                                        }
                                    },
                                    "Archive"
                                }
                            }
                            if let Some(ref action) = notif.action_label {
                                button {
                                    class: "primary",
                                    "data-testid": "notification-action",
                                    onclick: move |_| {
                                        // Action handler
                                    },
                                    "{action}"
                                }
                            }
                        }
                    }
                }
            }

            if notifications().is_empty() || notifications().iter().all(|n| n.archived && !show_archived()) {
                div { class: "event",
                    div { class: "event-head", span { "Notifications" } span { "empty" } }
                    div { class: "muted", "No notifications to display." }
                }
            }

            // Bulk actions
            div { class: "event", "data-testid": "bulk-actions",
                div { class: "event-head", span { "Bulk Actions" } span { "" } }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "archive-all-read",
                        onclick: move |_| {
                            for n in notifications.write().iter_mut() {
                                if n.read {
                                    n.archived = true;
                                }
                            }
                        },
                        "Archive All Read"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "delete-archived",
                        onclick: move |_| {
                            notifications.write().retain(|n| !n.archived);
                        },
                        "Delete Archived"
                    }
                }
            }

            // Notification rules section
            div { class: "event", "data-testid": "notification-rules",
                div { class: "event-head", span { "Notification Rules" } span { "" } }
                div { class: "muted", "Configure per-space and per-type notification muting." }

                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Mention notifications" }
                        label {
                            input {
                                r#type: "checkbox",
                                checked: true,
                                onchange: move |_| {},
                            }
                            " Enabled"
                        }
                    }
                    div { class: "metric",
                        strong { "Reaction notifications" }
                        label {
                            input {
                                r#type: "checkbox",
                                checked: true,
                                onchange: move |_| {},
                            }
                            " Enabled"
                        }
                    }
                    div { class: "metric",
                        strong { "Invite notifications" }
                        label {
                            input {
                                r#type: "checkbox",
                                checked: true,
                                onchange: move |_| {},
                            }
                            " Enabled"
                        }
                    }
                    div { class: "metric",
                        strong { "Message notifications" }
                        label {
                            input {
                                r#type: "checkbox",
                                checked: false,
                                onchange: move |_| {},
                            }
                            " Disabled (mentions only)"
                        }
                    }
                }
            }
        }
    }
}
