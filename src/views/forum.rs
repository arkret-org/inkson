use dioxus::prelude::*;
use serde_json::json;

use crate::views::helpers::authed_api;

#[derive(Clone, Debug, PartialEq)]
struct ForumTopic {
    id: String,
    title: String,
    author: String,
    body: String,
    tags: Vec<String>,
    reply_count: usize,
    created_at: String,
    replies: Vec<ForumReply>,
}

#[derive(Clone, Debug, PartialEq)]
struct ForumReply {
    id: String,
    author: String,
    body: String,
    created_at: String,
    parent_id: Option<String>,
    replies: Vec<ForumReply>,
}

#[component]
pub fn ForumPanel(base_url: String, token: Signal<String>, selected_space: String) -> Element {
    let mut topics = use_signal(|| {
        vec![ForumTopic {
            id: "topic-1".to_owned(),
            title: "Welcome to the forum".to_owned(),
            author: "chask".to_owned(),
            body: "This is the first topic in the forum. Start a discussion!".to_owned(),
            tags: vec!["welcome".to_owned(), "meta".to_owned()],
            reply_count: 0,
            created_at: chrono::Utc::now().format("%Y-%m-%d %H:%M").to_string(),
            replies: Vec::new(),
        }]
    });
    let mut open_topic = use_signal(|| Option::<usize>::None);
    let mut new_topic_title = use_signal(String::new);
    let mut new_topic_body = use_signal(String::new);
    let mut new_topic_tags = use_signal(String::new);
    let mut reply_draft = use_signal(String::new);
    let mut reply_to = use_signal(|| Option::<String>::None);
    let mut show_create = use_signal(|| false);

    rsx! {
        div { class: "timeline", "data-testid": "forum-panel",
            // Topic list header
            div { class: "event",
                div { class: "event-head",
                    span { "Forum" }
                    span { "{selected_space} / {topics().len()} topics" }
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "new-topic-button",
                        onclick: move |_| show_create.set(!show_create()),
                        if show_create() { "Cancel" } else { "New Topic" }
                    }
                }
            }

            // Topic creation form
            if show_create() {
                div { class: "event", "data-testid": "topic-creation",
                    div { class: "event-head", span { "New Topic" } span { "" } }
                    div { class: "workflow-form",
                        label { "Title" }
                        input {
                            "data-testid": "topic-title-input",
                            value: "{new_topic_title}",
                            placeholder: "Topic title",
                            oninput: move |evt| new_topic_title.set(evt.value()),
                        }
                        label { "Initial Post" }
                        textarea {
                            "data-testid": "topic-body-input",
                            value: "{new_topic_body}",
                            placeholder: "Write your post...",
                            oninput: move |evt| new_topic_body.set(evt.value()),
                        }
                        label { "Tags (comma-separated)" }
                        input {
                            "data-testid": "topic-tags-input",
                            value: "{new_topic_tags}",
                            placeholder: "tag1, tag2",
                            oninput: move |evt| new_topic_tags.set(evt.value()),
                        }
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "submit-topic-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let space = selected_space.clone();
                                    move |_| {
                                        let title = new_topic_title().trim().to_owned();
                                        let body = new_topic_body().trim().to_owned();
                                        if title.is_empty() || body.is_empty() {
                                            return;
                                        }
                                        let tags: Vec<String> = new_topic_tags()
                                            .split(',')
                                            .map(|s| s.trim().to_owned())
                                            .filter(|s| !s.is_empty())
                                            .collect();
                                        topics.write().push(ForumTopic {
                                            id: format!("topic-{}", chrono::Utc::now().timestamp_millis()),
                                            title: title.clone(),
                                            author: "chask".to_owned(),
                                            body: body.clone(),
                                            tags: tags,
                                            reply_count: 0,
                                            created_at: chrono::Utc::now().format("%Y-%m-%d %H:%M").to_string(),
                                            replies: Vec::new(),
                                        });
                                        let base = base.clone();
                                        let space = space.clone();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                let _ = api.send_message(&space, None, json!({
                                                    "msgtype": "m.text",
                                                    "body": format!("[{}] {}", title, body),
                                                }), false).await;
                                            }
                                        });
                                        new_topic_title.set(String::new());
                                        new_topic_body.set(String::new());
                                        new_topic_tags.set(String::new());
                                        show_create.set(false);
                                    }
                                },
                                "Create Topic"
                            }
                        }
                    }
                }
            }

            // Topic list or detail
            if let Some(idx) = open_topic() {
                if let Some(topic) = topics().get(idx) {
                    div { class: "event", "data-testid": "topic-detail",
                        div { class: "event-head",
                            span { "Topic" }
                            span { "{topic.created_at}" }
                        }
                        div { class: "space-title", "{topic.title}" }
                        div { class: "muted", "By: {topic.author}" }
                        div { "{topic.body}" }
                        div { class: "actions",
                            for tag in &topic.tags {
                                span { class: "muted", "#{tag} " }
                            }
                        }

                        // Replies
                        div { class: "section",
                            h2 { "Replies ({topic.replies.len()})" }
                            for reply in &topic.replies {
                                div { class: "event", "data-testid": "forum-reply",
                                    div { class: "event-head",
                                        span { "{reply.author}" }
                                        span { "{reply.created_at}" }
                                    }
                                    div { "{reply.body}" }
                                    // Nested replies
                                    for nested in &reply.replies {
                                        div { class: "event",
                                            style: "margin-left: 24px;",
                                            div { class: "event-head",
                                                span { "{nested.author}" }
                                                span { "{nested.created_at}" }
                                            }
                                            div { "{nested.body}" }
                                        }
                                    }
                                    div { class: "actions",
                                        button {
                                            class: "secondary",
                                            "data-testid": "reply-to-reply",
                                            onclick: {
                                                let rid = reply.id.clone();
                                                move |_| reply_to.set(Some(rid.clone()))
                                            },
                                            "Reply"
                                        }
                                    }
                                }
                            }
                        }

                        // Reply composer
                        div { class: "composer", "data-testid": "reply-composer",
                            if let Some(ref parent) = reply_to() {
                                div { class: "muted", "Replying to {parent}" }
                            }
                            textarea {
                                "data-testid": "reply-input",
                                value: "{reply_draft}",
                                placeholder: "Write a reply...",
                                oninput: move |evt| reply_draft.set(evt.value()),
                            }
                            div { class: "actions",
                                button {
                                    class: "primary",
                                    "data-testid": "submit-reply-button",
                                    onclick: move |_| {
                                        let body = reply_draft().trim().to_owned();
                                        if body.is_empty() {
                                            return;
                                        }
                                        if let Some(topic) = topics.write().get_mut(idx) {
                                            let parent = reply_to();
                                            if let Some(ref pid) = parent {
                                                // Nested reply
                                                if let Some(parent_reply) = topic.replies.iter_mut().find(|r| r.id == *pid) {
                                                    parent_reply.replies.push(ForumReply {
                                                        id: format!("reply-{}", chrono::Utc::now().timestamp_millis()),
                                                        author: "chask".to_owned(),
                                                        body: body,
                                                        created_at: chrono::Utc::now().format("%Y-%m-%d %H:%M").to_string(),
                                                        parent_id: parent,
                                                        replies: Vec::new(),
                                                    });
                                                }
                                            } else {
                                                topic.replies.push(ForumReply {
                                                    id: format!("reply-{}", chrono::Utc::now().timestamp_millis()),
                                                    author: "chask".to_owned(),
                                                    body: body,
                                                    created_at: chrono::Utc::now().format("%Y-%m-%d %H:%M").to_string(),
                                                    parent_id: None,
                                                    replies: Vec::new(),
                                                });
                                                topic.reply_count += 1;
                                            }
                                        }
                                        reply_draft.set(String::new());
                                        reply_to.set(None);
                                    },
                                    "Post Reply"
                                }
                                button {
                                    class: "secondary",
                                    onclick: move |_| open_topic.set(None),
                                    "Back to Topics"
                                }
                            }
                        }
                    }
                }
            } else {
                // Topic list
                for (idx, topic) in topics().iter().enumerate() {
                    div {
                        class: "event",
                        "data-testid": "forum-topic",
                        style: "cursor: pointer;",
                        onclick: move |_| open_topic.set(Some(idx)),
                        div { class: "event-head",
                            span { "{topic.author}" }
                            span { "{topic.created_at}" }
                        }
                        div { class: "space-title", "{topic.title}" }
                        div { class: "muted", "{topic.body}" }
                        div { class: "actions",
                            for tag in &topic.tags {
                                span { class: "muted", "#{tag} " }
                            }
                            span { class: "muted", "{topic.reply_count} replies" }
                        }
                    }
                }
                if topics().is_empty() {
                    div { class: "event",
                        div { class: "event-head", span { "Forum" } span { "empty" } }
                        div { class: "muted", "No topics yet. Create the first one!" }
                    }
                }
            }
        }
    }
}
