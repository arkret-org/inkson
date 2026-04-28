use dioxus::prelude::*;
use serde_json::json;

use crate::{
    api::ContrixApi,
    models::*,
    views::helpers::authed_api,
};

#[derive(Clone, Debug, PartialEq)]
struct Channel {
    id: String,
    name: String,
    kind: String,
    unread: usize,
}

#[derive(Clone, Debug, PartialEq)]
struct ChatMessage {
    id: String,
    sender: String,
    body: String,
    timestamp: String,
}

#[component]
pub fn ChatPanel(
    base_url: String,
    token: Signal<String>,
    selected_space: String,
) -> Element {
    let mut channels = use_signal(|| {
        vec![
            Channel { id: "dm-1".to_owned(), name: "Direct Messages".to_owned(), kind: "dm".to_owned(), unread: 0 },
            Channel { id: "group-1".to_owned(), name: "Group Chat".to_owned(), kind: "group".to_owned(), unread: 2 },
            Channel { id: "space-1".to_owned(), name: "Space Channel".to_owned(), kind: "space".to_owned(), unread: 0 },
        ]
    });
    let mut selected_channel = use_signal(|| "dm-1".to_owned());
    let mut messages = use_signal(Vec::<ChatMessage>::new);
    let mut chat_draft = use_signal(String::new);
    let mut new_channel_name = use_signal(String::new);
    let mut new_channel_kind = use_signal(|| "group".to_owned());
    let mut status_msg = use_signal(|| String::new());

    rsx! {
        div { class: "timeline", "data-testid": "chat-panel",
            // Channel list sidebar
            div { class: "event", "data-testid": "channel-list",
                div { class: "event-head", span { "Channels" } span { "{channels().len()}" } }
                for channel in channels() {
                    div {
                        class: if channel.id == selected_channel() { "space-button active" } else { "space-button" },
                        "data-testid": "channel-item",
                        onclick: {
                            let id = channel.id.clone();
                            move |_| selected_channel.set(id.clone())
                        },
                        div { class: "space-title", "{channel.name}" }
                        div { class: "space-meta", "{channel.kind}" }
                        if channel.unread > 0 {
                            div { class: "muted", "{channel.unread} unread" }
                        }
                    }
                }
            }

            // Channel creation
            div { class: "event", "data-testid": "channel-creation",
                div { class: "event-head", span { "Create Channel" } span { "" } }
                div { class: "workflow-form",
                    input {
                        "data-testid": "new-channel-name",
                        value: "{new_channel_name}",
                        placeholder: "Channel name",
                        oninput: move |evt| new_channel_name.set(evt.value()),
                    }
                    div { class: "actions",
                        button {
                            class: if new_channel_kind() == "dm" { "primary" } else { "secondary" },
                            onclick: move |_| new_channel_kind.set("dm".to_owned()),
                            "DM"
                        }
                        button {
                            class: if new_channel_kind() == "group" { "primary" } else { "secondary" },
                            onclick: move |_| new_channel_kind.set("group".to_owned()),
                            "Group"
                        }
                        button {
                            class: if new_channel_kind() == "space" { "primary" } else { "secondary" },
                            onclick: move |_| new_channel_kind.set("space".to_owned()),
                            "Space"
                        }
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "create-channel-button",
                            onclick: move |_| {
                                let name = new_channel_name().trim().to_owned();
                                if !name.is_empty() {
                                    channels.write().push(Channel {
                                        id: format!("ch-{}", chrono::Utc::now().timestamp_millis()),
                                        name: name,
                                        kind: new_channel_kind(),
                                        unread: 0,
                                    });
                                    new_channel_name.set(String::new());
                                }
                            },
                            "Create"
                        }
                    }
                }
            }

            // Message list
            div { class: "event", "data-testid": "message-list",
                div { class: "event-head",
                    span { "Messages" }
                    span { "channel: {selected_channel}" }
                }
                for msg in messages() {
                    div { class: "event", "data-testid": "chat-message",
                        div { class: "event-head",
                            span { "{msg.sender}" }
                            span { "{msg.timestamp}" }
                        }
                        div { "{msg.body}" }
                    }
                }
                if messages().is_empty() {
                    div { class: "muted", "No messages in this channel yet." }
                }
            }

            // Composer
            div { class: "composer", "data-testid": "chat-composer",
                textarea {
                    "data-testid": "chat-input",
                    value: "{chat_draft}",
                    placeholder: "Type a message...",
                    oninput: move |evt| chat_draft.set(evt.value()),
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "send-chat-button",
                        onclick: {
                            let base = base_url.clone();
                            let space = selected_space.clone();
                            move |_| {
                                let body = chat_draft().trim().to_owned();
                                if body.is_empty() {
                                    return;
                                }
                                messages.write().push(ChatMessage {
                                    id: format!("msg-{}", chrono::Utc::now().timestamp_millis()),
                                    sender: "clientx".to_owned(),
                                    body: body.clone(),
                                    timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                                });
                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        let _ = api.send_message(&space, None, json!({"msgtype": "m.text", "body": body}), false).await;
                                    }
                                });
                                chat_draft.set(String::new());
                            }
                        },
                        "Send"
                    }
                }
            }

            if !status_msg().is_empty() {
                div { class: "muted", "data-testid": "chat-status", "{status_msg}" }
            }
        }
    }
}
