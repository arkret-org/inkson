use dioxus::prelude::*;
use serde_json::json;

use crate::{
    local_state::LocalStateStore,
    operation::{CommitBuilder, cx_ops, uuid_v8},
    views::helpers::{
        StructuredMention, active_sync_token, authed_api_with_sync, parse_structured_mentions,
    },
};

#[derive(Clone, Debug, PartialEq)]
struct ChannelEntity {
    entity_id: String,
    name: String,
    kind: String,
    topic: Option<String>,
    unread: usize,
    operation_id: Option<String>,
    commit_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
struct ChatMessage {
    id: String,
    sender: String,
    body: String,
    timestamp: String,
    channel_id: String,
    mentions: Vec<StructuredMention>,
    operation_id: Option<String>,
    commit_id: Option<String>,
}

#[component]
pub fn ChatPanel(
    base_url: String,
    account_did: String,
    token: Signal<String>,
    selected_space: String,
    sync_cursor: Signal<String>,
    repo_state: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let mut channels = use_signal(|| {
        vec![
            ChannelEntity {
                entity_id: "cx:channel:general".to_owned(),
                name: "General Chat".to_owned(),
                kind: "chat".to_owned(),
                topic: Some("Default long-lived space channel".to_owned()),
                unread: 0,
                operation_id: None,
                commit_id: None,
            },
            ChannelEntity {
                entity_id: "cx:channel:announce".to_owned(),
                name: "Announcements".to_owned(),
                kind: "announce".to_owned(),
                topic: Some("Release notes and broadcast updates".to_owned()),
                unread: 2,
                operation_id: None,
                commit_id: None,
            },
            ChannelEntity {
                entity_id: "cx:channel:support".to_owned(),
                name: "Support Desk".to_owned(),
                kind: "support".to_owned(),
                topic: Some("Issue triage and operator escalations".to_owned()),
                unread: 0,
                operation_id: None,
                commit_id: None,
            },
            ChannelEntity {
                entity_id: "cx:channel:activity".to_owned(),
                name: "Activity Feed".to_owned(),
                kind: "activity".to_owned(),
                topic: Some("Machine and workflow activity stream".to_owned()),
                unread: 0,
                operation_id: None,
                commit_id: None,
            },
        ]
    });
    let mut selected_channel = use_signal(|| "cx:channel:general".to_owned());
    let mut messages = use_signal(Vec::<ChatMessage>::new);
    let mut chat_draft = use_signal(String::new);
    let mut new_channel_name = use_signal(String::new);
    let mut new_channel_kind = use_signal(|| "chat".to_owned());
    let mut new_channel_topic = use_signal(String::new);
    let mut status_msg = use_signal(String::new);

    rsx! {
        div { class: "timeline", "data-testid": "chat-panel",
            div { class: "event", "data-testid": "channel-list",
                div { class: "event-head", span { "Channels" } span { "{channels().len()}" } }
                for channel in channels() {
                    div {
                        class: if channel.entity_id == selected_channel() { "space-button active" } else { "space-button" },
                        "data-testid": "channel-item",
                        onclick: {
                            let id = channel.entity_id.clone();
                            move |_| selected_channel.set(id.clone())
                        },
                        div { class: "space-title", "{channel.name}" }
                        div { class: "space-meta", "{channel.kind} / {channel.entity_id}" }
                        if let Some(topic) = &channel.topic {
                            div { class: "muted", "{topic}" }
                        }
                        if let Some(operation_id) = &channel.operation_id {
                            div { class: "muted", "fact {operation_id}" }
                        }
                        if channel.unread > 0 {
                            div { class: "muted", "{channel.unread} unread" }
                        }
                    }
                }
            }

            div { class: "event", "data-testid": "channel-creation",
                div { class: "event-head", span { "Create Channel Entity" } span { "chat / announce / support / activity" } }
                div { class: "workflow-form",
                    input {
                        "data-testid": "new-channel-name",
                        value: "{new_channel_name}",
                        placeholder: "Channel name",
                        oninput: move |evt| new_channel_name.set(evt.value()),
                    }
                    input {
                        "data-testid": "new-channel-topic",
                        value: "{new_channel_topic}",
                        placeholder: "Channel topic / purpose",
                        oninput: move |evt| new_channel_topic.set(evt.value()),
                    }
                    div { class: "actions",
                        button {
                            class: if new_channel_kind() == "chat" { "primary" } else { "secondary" },
                            "data-testid": "channel-kind-chat",
                            onclick: move |_| new_channel_kind.set("chat".to_owned()),
                            "Chat"
                        }
                        button {
                            class: if new_channel_kind() == "announce" { "primary" } else { "secondary" },
                            "data-testid": "channel-kind-announce",
                            onclick: move |_| new_channel_kind.set("announce".to_owned()),
                            "Announce"
                        }
                        button {
                            class: if new_channel_kind() == "support" { "primary" } else { "secondary" },
                            "data-testid": "channel-kind-support",
                            onclick: move |_| new_channel_kind.set("support".to_owned()),
                            "Support"
                        }
                        button {
                            class: if new_channel_kind() == "activity" { "primary" } else { "secondary" },
                            "data-testid": "channel-kind-activity",
                            onclick: move |_| new_channel_kind.set("activity".to_owned()),
                            "Activity"
                        }
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "create-channel-button",
                            onclick: {
                                let base = base_url.clone();
                                let actor = account_did.clone();
                                let space = selected_space.clone();
                                move |_| {
                                    let name = new_channel_name().trim().to_owned();
                                    if name.is_empty() {
                                        status_msg.set("channel name is required".to_owned());
                                        return;
                                    }
                                    let kind = new_channel_kind();
                                    let topic = new_channel_topic().trim().to_owned();
                                    let channel_id = format!("cx:channel:{}", uuid_v8());
                                    let op = cx_ops::channel_create_entity(
                                        &space,
                                        &actor,
                                        &channel_id,
                                        &name,
                                        &kind,
                                        if topic.is_empty() { None } else { Some(topic.as_str()) },
                                    )
                                    .build("chask");
                                    let commit = CommitBuilder::new(actor.clone())
                                        .add_operation(op.clone())
                                        .build();
                                    let commit_value = match serde_json::to_value(&commit) {
                                        Ok(value) => value,
                                        Err(error) => {
                                            status_msg.set(format!("serialize failed: {error}"));
                                            return;
                                        }
                                    };
                                    let api_token = token();
                                    let wait_for = active_sync_token(&sync_cursor());
                                    let expected_head = expected_head(repo_state());
                                    let channel_topic = if topic.is_empty() { None } else { Some(topic) };
                                    let base = base.clone();
                                    let actor = actor.clone();
                                    let space = space.clone();
                                    status_msg.set("submitting channel entity".to_owned());
                                    spawn(async move {
                                        match authed_api_with_sync(&base, api_token, wait_for) {
                                            Ok(api) => match api
                                                .submit_commit(
                                                    &actor,
                                                    commit_value,
                                                    expected_head.as_deref(),
                                                    Some(&op.operation_id),
                                                )
                                                .await
                                            {
                                                Ok(submitted) => {
                                                    channels.write().push(ChannelEntity {
                                                        entity_id: channel_id.clone(),
                                                        name: name.clone(),
                                                        kind: kind.clone(),
                                                        topic: channel_topic.clone(),
                                                        unread: 0,
                                                        operation_id: Some(op.operation_id.clone()),
                                                        commit_id: Some(submitted.commit_id.clone()),
                                                    });
                                                    selected_channel.set(channel_id.clone());
                                                    repo_state.set(
                                                        submitted
                                                            .head_commit
                                                            .clone()
                                                            .unwrap_or(submitted.commit_id.clone()),
                                                    );
                                                    sync_cursor.set(submitted.sync_token.clone());
                                                    {
                                                        let mut store = state_store.write();
                                                        store.save_sync_cursor(submitted.sync_token.clone());
                                                        store.append_raw_operation(
                                                            op.operation_id.clone(),
                                                            Some(space.clone()),
                                                            json!({
                                                                "entity_id": channel_id,
                                                                "kind": "cx.channel.create",
                                                                "commit_id": submitted.commit_id,
                                                            }),
                                                        );
                                                    }
                                                    status_msg.set(format!(
                                                        "channel committed {}",
                                                        op.operation_id
                                                    ));
                                                    new_channel_name.set(String::new());
                                                    new_channel_topic.set(String::new());
                                                }
                                                Err(error) => status_msg.set(format!("channel create failed: {error}")),
                                            },
                                            Err(error) => status_msg.set(format!("invalid server URL: {error}")),
                                        }
                                    });
                                }
                            },
                            "Create"
                        }
                    }
                }
            }

            div { class: "event", "data-testid": "message-list",
                div { class: "event-head",
                    span { "Messages" }
                    span { "channel: {selected_channel}" }
                }
                for msg in messages().iter().filter(|msg| msg.channel_id == selected_channel()) {
                    div { class: "event", "data-testid": "chat-message",
                        div { class: "event-head",
                            span { "{msg.sender}" }
                            span { "{msg.timestamp}" }
                        }
                        div { "{msg.body}" }
                        if !msg.mentions.is_empty() {
                            div { class: "actions", "data-testid": "chat-mentions",
                                for mention in &msg.mentions {
                                    span { class: "muted", "{mention.kind}: {mention.target}" }
                                }
                            }
                        }
                        if let Some(operation_id) = &msg.operation_id {
                            div { class: "muted", "fact {operation_id}" }
                        }
                    }
                }
                if messages().iter().all(|msg| msg.channel_id != selected_channel()) {
                    div { class: "muted", "No messages in this channel yet." }
                }
            }

            div { class: "composer", "data-testid": "chat-composer",
                textarea {
                    "data-testid": "chat-input",
                    value: "{chat_draft}",
                    placeholder: "Type a message. Use @did:web:alice.example or #cx:task:123 for structured mentions.",
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
                                let mentions = parse_structured_mentions(&body);
                                let local_id = format!("chat-msg-{}", uuid_v8());
                                let channel = channels()
                                    .iter()
                                    .find(|candidate| candidate.entity_id == selected_channel())
                                    .cloned();
                                let Some(channel) = channel else {
                                    status_msg.set("select a channel first".to_owned());
                                    return;
                                };
                                messages.write().push(ChatMessage {
                                    id: local_id.clone(),
                                    sender: "chask".to_owned(),
                                    body: body.clone(),
                                    timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                                    channel_id: channel.entity_id.clone(),
                                    mentions: mentions.clone(),
                                    operation_id: None,
                                    commit_id: None,
                                });

                                let base = base.clone();
                                let space = space.clone();
                                let api_token = token();
                                let wait_for = active_sync_token(&sync_cursor());
                                let mention_values = mentions_to_json(&mentions);
                                let mention_values_for_store = mention_values.clone();
                                let mention_relations = mention_relation_json(&local_id, &mentions);
                                let channel_id = channel.entity_id.clone();
                                let channel_kind = channel.kind.clone();
                                let message_id = local_id.clone();
                                spawn(async move {
                                    match authed_api_with_sync(&base, api_token, wait_for) {
                                        Ok(api) => match api
                                            .send_message(
                                                &space,
                                                None,
                                                json!({
                                                    "message_id": message_id,
                                                    "msgtype": "m.text",
                                                    "body": body,
                                                    "channel_id": channel_id,
                                                    "channel_kind": channel_kind,
                                                    "mentions": mention_values,
                                                    "mention_relations": mention_relations,
                                                }),
                                                false,
                                            )
                                            .await
                                        {
                                            Ok(sent) => {
                                                if let Some(found) = messages
                                                    .write()
                                                    .iter_mut()
                                                    .find(|candidate| candidate.id == local_id)
                                                {
                                                    found.operation_id = Some(sent.operation_id.clone());
                                                    found.commit_id = Some(sent.commit_id.clone());
                                                }
                                                sync_cursor.set(sent.sync_token.clone());
                                                repo_state.set(
                                                    sent.head_commit
                                                        .clone()
                                                        .unwrap_or(sent.commit_id.clone()),
                                                );
                                                {
                                                    let mut store = state_store.write();
                                                    store.save_sync_cursor(sent.sync_token.clone());
                                                    store.append_raw_operation(
                                                        sent.operation_id.clone(),
                                                        Some(space),
                                                        json!({
                                                            "message_id": sent.event_id,
                                                            "kind": "cx.message.create",
                                                            "channel_id": channel_id,
                                                            "mentions": mention_values_for_store,
                                                        }),
                                                    );
                                                }
                                                status_msg.set(format!("message sent {}", sent.operation_id));
                                            }
                                            Err(error) => status_msg.set(format!("send failed: {error}")),
                                        },
                                        Err(error) => status_msg.set(format!("invalid server URL: {error}")),
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

fn expected_head(repo_state: String) -> Option<String> {
    repo_state.starts_with("cx:commit:").then_some(repo_state)
}

fn mentions_to_json(mentions: &[StructuredMention]) -> Vec<serde_json::Value> {
    mentions
        .iter()
        .map(|mention| {
            json!({
                "kind": mention.kind,
                "target": mention.target,
                "token": mention.token,
            })
        })
        .collect()
}

fn mention_relation_json(source: &str, mentions: &[StructuredMention]) -> Vec<serde_json::Value> {
    mentions
        .iter()
        .map(|mention| {
            json!({
                "relation_type": "mentions",
                "source": source,
                "target": mention.target,
            })
        })
        .collect()
}
