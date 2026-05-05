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
    flow_id: String,
    mentions: Vec<StructuredMention>,
    operation_id: Option<String>,
    commit_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
struct DiscussionTimelineFact {
    kind: &'static str,
    subject: &'static str,
    state: &'static str,
    detail: &'static str,
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
                entity_id: "cx:flow:general".to_owned(),
                name: "Launch board discussion".to_owned(),
                kind: "discussion".to_owned(),
                topic: Some("Default long-lived discussion for board coordination".to_owned()),
                unread: 0,
                operation_id: None,
                commit_id: None,
            },
            ChannelEntity {
                entity_id: "cx:flow:announce".to_owned(),
                name: "Announcements discussion".to_owned(),
                kind: "announce".to_owned(),
                topic: Some("Discussion-scoped release notes and broadcast updates".to_owned()),
                unread: 2,
                operation_id: None,
                commit_id: None,
            },
            ChannelEntity {
                entity_id: "cx:flow:support".to_owned(),
                name: "Support desk discussion".to_owned(),
                kind: "support".to_owned(),
                topic: Some("Issue triage discussion for operator escalations".to_owned()),
                unread: 0,
                operation_id: None,
                commit_id: None,
            },
            ChannelEntity {
                entity_id: "cx:flow:activity".to_owned(),
                name: "Activity audit discussion".to_owned(),
                kind: "activity".to_owned(),
                topic: Some("Machine and workflow messages with audit references".to_owned()),
                unread: 0,
                operation_id: None,
                commit_id: None,
            },
        ]
    });
    let mut selected_channel = use_signal(|| "cx:flow:general".to_owned());
    let mut messages = use_signal(Vec::<ChatMessage>::new);
    let mut chat_draft = use_signal(String::new);
    let mut new_channel_name = use_signal(String::new);
    let mut new_channel_kind = use_signal(|| "discussion".to_owned());
    let mut new_channel_topic = use_signal(String::new);
    let mut status_msg = use_signal(String::new);

    rsx! {
        div { class: "timeline", "data-testid": "chat-panel",
            // Ephemeral presence / typing — discovery/profiles-presence.md
            // 这两个 event 是 Ephemeral Channel events（不写入 Space history）：
            //   cx.presence — 发送方在线 / 离线 / dnd 状态
            //   cx.typing   — 发送方正在输入（短期 TTL；reducer 不会持久化）
            // 客户端 SHOULD 显示但 MUST NOT 把它们当作 audit / capability 输入。
            div { class: "event", "data-testid": "ephemeral-channel-banner",
                div { class: "event-head",
                    span { "Ephemeral signals" }
                    span { "cx.presence · cx.typing" }
                }
                div { class: "muted",
                    "Presence 与 typing 通过 Sync Service Ephemeral Channel 传播，不写入 Space history。Privacy 设置可关闭这两类对外发送（cx.account_data.set 控制）。"
                }
                div { class: "actions",
                    span { class: "badge green", "Mei · online" }
                    span { class: "badge blue", "Carlos · typing…" }
                    span { class: "badge", "α agent · idle" }
                    span { class: "muted", "TTL ≈ 30s · 不进入 audit 流" }
                }
            }

            div { class: "event", "data-testid": "channel-list",
                div { class: "event-head", span { "Discussions" } span { "{channels().len()}" } }
                div { class: "muted",
                    "Discussions use flow identifiers for canonical identity. Existing submissions still travel through flow create operations."
                }
                for channel in channels() {
                    div {
                        class: if channel.entity_id == selected_channel() { "space-button active" } else { "space-button" },
                        "data-testid": "channel-item",
                        onclick: {
                            let id = channel.entity_id.clone();
                            move |_| selected_channel.set(id.clone())
                        },
                        div { class: "space-title", "{channel.name}" }
                        div { class: "space-meta", "kind={channel.kind} / id={channel.entity_id}" }
                        if let Some(topic) = &channel.topic {
                            div { class: "muted", "{topic}" }
                        }
                        if let Some(operation_id) = &channel.operation_id {
                            div { class: "muted", "flow fact {operation_id}" }
                        }
                        if channel.unread > 0 {
                            div { class: "muted", "{channel.unread} unread" }
                        }
                    }
                }
            }

            div { class: "event", "data-testid": "channel-creation",
                div { class: "event-head", span { "Create Discussion Entity" } span { "discussion / announce / support / activity" } }
                div { class: "muted", "Submits via cx.flow.create operation with discussion branch and rank." }
                div { class: "workflow-form",
                    input {
                        "data-testid": "new-channel-name",
                        value: "{new_channel_name}",
                        placeholder: "Discussion name",
                        oninput: move |evt| new_channel_name.set(evt.value()),
                    }
                    input {
                        "data-testid": "new-channel-topic",
                        value: "{new_channel_topic}",
                        placeholder: "Discussion purpose / history visibility note",
                        oninput: move |evt| new_channel_topic.set(evt.value()),
                    }
                    div { class: "actions",
                        button {
                            class: if new_channel_kind() == "discussion" { "primary" } else { "secondary" },
                            "data-testid": "channel-kind-chat",
                            onclick: move |_| new_channel_kind.set("discussion".to_owned()),
                            "Discussion"
                        }
                        button {
                            class: if new_channel_kind() == "announce" { "primary" } else { "secondary" },
                            "data-testid": "channel-kind-announce",
                            onclick: move |_| new_channel_kind.set("announce".to_owned()),
                            "Announcement"
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
                                    status_msg.set("discussion name is required".to_owned());
                                    return;
                                }
                                let kind = new_channel_kind();
                                let topic = new_channel_topic().trim().to_owned();
                                let flow_id = format!("cx:flow:{}", uuid_v8());
                                let rank = format!("r{}", chrono::Utc::now().timestamp_millis());
                                let op = cx_ops::flow_create(
                                    &space,
                                    &actor,
                                    &space,
                                    &flow_id,
                                    &name,
                                    &kind,
                                    &rank,
                                )
                                .build("yougen");
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
                                status_msg.set("submitting flow.create operation".to_owned());
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
                                                        entity_id: flow_id.clone(),
                                                        name: name.clone(),
                                                        kind: kind.clone(),
                                                        topic: channel_topic.clone(),
                                                        unread: 0,
                                                        operation_id: Some(op.operation_id.clone()),
                                                        commit_id: Some(submitted.commit_id.clone()),
                                                    });
                                                    selected_channel.set(flow_id.clone());
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
                                                                "flow_id": flow_id,
                                                                "kind": "cx.flow.create",
                                                                "commit_id": submitted.commit_id,
                                                            }),
                                                        );
                                                    }
                                                    status_msg.set(format!(
                                                        "flow committed {}",
                                                        op.operation_id
                                                    ));
                                                    new_channel_name.set(String::new());
                                                    new_channel_topic.set(String::new());
                                                }
                                                Err(error) => status_msg.set(format!("flow create failed: {error}")),
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
                    span { "Discussion Messages" }
                    span { "discussion: {selected_channel}" }
                }
                for msg in messages().iter().filter(|msg| msg.flow_id == selected_channel()) {
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
                            div { class: "muted", "message fact {operation_id}" }
                        }
                    }
                }
                if messages().iter().all(|msg| msg.flow_id != selected_channel()) {
                    div { class: "muted", "No messages in this discussion yet." }
                }
            }

            div { class: "event", "data-testid": "discussion-timeline-protocol",
                div { class: "event-head", span { "Discussion Timeline" } span { "message chain / access" } }
                div { class: "muted",
                    "Discussion events keep their own ACL and history visibility. Linked discussion access is displayed as metadata, not as permission inheritance."
                }
                for fact in seed_discussion_timeline_facts() {
                    div { class: "event", "data-testid": "discussion-timeline-fact",
                        div { class: "event-head",
                            span { "{fact.kind}" }
                            span { class: timeline_state_class(fact.state), "{fact.state}" }
                        }
                        div { class: "space-title", "{fact.subject}" }
                        div { class: "muted", "{fact.detail}" }
                    }
                }
            }

            div { class: "composer", "data-testid": "chat-composer",
                textarea {
                    "data-testid": "chat-input",
                    value: "{chat_draft}",
                    placeholder: "Type a discussion message. Use @did:web:alice.example or #cx:task:123 for structured mentions.",
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
                                    status_msg.set("select a discussion first".to_owned());
                                    return;
                                };
                                messages.write().push(ChatMessage {
                                    id: local_id.clone(),
                                    sender: "yougen".to_owned(),
                                    body: body.clone(),
                                    timestamp: chrono::Utc::now().format("%H:%M").to_string(),
                                    flow_id: channel.entity_id.clone(),
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
                                let flow_id = channel.entity_id.clone();
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
                                                    "flow_id": flow_id.clone(),
                                                    "branch": "discussion",
                                                    "flow_kind": channel_kind,
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
                                                            "flow_id": flow_id,
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

fn seed_discussion_timeline_facts() -> Vec<DiscussionTimelineFact> {
    vec![
        DiscussionTimelineFact {
            kind: "cx.message.create",
            subject: "Initial launch question",
            state: "visible",
            detail: "message_id=cx:message:launch-1 / flow_id=cx:flow:launch",
        },
        DiscussionTimelineFact {
            kind: "cx.message.revise",
            subject: "Revision chain",
            state: "revised",
            detail: "replaces cx:message:launch-1 and keeps previous body available only through audit permissions",
        },
        DiscussionTimelineFact {
            kind: "cx.message.redact",
            subject: "Tombstone",
            state: "tombstone",
            detail: "body hidden; redaction reason and event hash remain visible",
        },
        DiscussionTimelineFact {
            kind: "cx.reaction.add",
            subject: "Reaction",
            state: "visible",
            detail: "reaction is scoped to the message event, not to the linked Discussion",
        },
        DiscussionTimelineFact {
            kind: "cx.flow.branch.member",
            subject: "Linked discussion access",
            state: "independent",
            detail: "discussion readable, flow projection readable separately; locked discussions fail closed",
        },
    ]
}

fn timeline_state_class(state: &str) -> &'static str {
    match state {
        "visible" | "independent" => "badge green",
        "revised" => "badge blue",
        "tombstone" => "badge amber",
        _ => "badge",
    }
}
