use dioxus::prelude::*;
use serde_json::json;

use crate::{
    local_state::LocalStateStore,
    operation::{CommitBuilder, OperationEnvelope, cx_ops, uuid_v8},
    views::helpers::{
        StructuredMention, active_sync_token, authed_api_with_sync, parse_structured_mentions,
    },
};

#[derive(Clone, Debug, PartialEq)]
struct ForumTopic {
    entity_id: String,
    title: String,
    author: String,
    body: String,
    tags: Vec<String>,
    created_at: String,
    anchor_kind: String,
    anchor_target: String,
    mentions: Vec<StructuredMention>,
    operation_id: Option<String>,
    commit_id: Option<String>,
    comments: Vec<ForumComment>,
}

#[derive(Clone, Debug, PartialEq)]
struct ForumComment {
    entity_id: String,
    author: String,
    body: String,
    created_at: String,
    parent_id: Option<String>,
    target_ref: String,
    mentions: Vec<StructuredMention>,
    operation_id: Option<String>,
    commit_id: Option<String>,
    comments: Vec<ForumComment>,
}

#[component]
pub fn ForumPanel(
    base_url: String,
    account_did: String,
    token: Signal<String>,
    selected_space: String,
    sync_cursor: Signal<String>,
    repo_state: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let mut topics = use_signal(|| {
        vec![ForumTopic {
            entity_id: "cx:topic:welcome".to_owned(),
            title: "Welcome to the forum".to_owned(),
            author: "chask".to_owned(),
            body: "This is the first anchored topic in the forum. Start a structured discussion."
                .to_owned(),
            tags: vec!["welcome".to_owned(), "meta".to_owned()],
            created_at: chrono::Utc::now().format("%Y-%m-%d %H:%M").to_string(),
            anchor_kind: "space".to_owned(),
            anchor_target: selected_space.clone(),
            mentions: Vec::new(),
            operation_id: None,
            commit_id: None,
            comments: Vec::new(),
        }]
    });
    let mut open_topic = use_signal(|| Option::<usize>::None);
    let mut new_topic_title = use_signal(String::new);
    let mut new_topic_body = use_signal(String::new);
    let mut new_topic_tags = use_signal(String::new);
    let mut new_topic_anchor_kind = use_signal(|| "space".to_owned());
    let mut new_topic_anchor_target = use_signal(|| selected_space.clone());
    let mut comment_draft = use_signal(String::new);
    let mut comment_to = use_signal(|| Option::<String>::None);
    let mut show_create = use_signal(|| false);
    let mut status_msg = use_signal(String::new);

    rsx! {
        div { class: "timeline", "data-testid": "forum-panel",
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

            if show_create() {
                div { class: "event", "data-testid": "topic-creation",
                    div { class: "event-head", span { "New Topic" } span { "anchored entity" } }
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
                            placeholder: "Write your post. Use @did:web:alice.example or #cx:task:123 for mentions.",
                            oninput: move |evt| new_topic_body.set(evt.value()),
                        }
                        label { "Tags (comma-separated)" }
                        input {
                            "data-testid": "topic-tags-input",
                            value: "{new_topic_tags}",
                            placeholder: "tag1, tag2",
                            oninput: move |evt| new_topic_tags.set(evt.value()),
                        }
                        label { "Anchor Kind" }
                        div { class: "actions",
                            button {
                                class: if new_topic_anchor_kind() == "space" { "primary" } else { "secondary" },
                                "data-testid": "anchor-kind-space",
                                onclick: move |_| new_topic_anchor_kind.set("space".to_owned()),
                                "Space"
                            }
                            button {
                                class: if new_topic_anchor_kind() == "board" { "primary" } else { "secondary" },
                                "data-testid": "anchor-kind-board",
                                onclick: move |_| new_topic_anchor_kind.set("board".to_owned()),
                                "Board"
                            }
                            button {
                                class: if new_topic_anchor_kind() == "task" { "primary" } else { "secondary" },
                                "data-testid": "anchor-kind-task",
                                onclick: move |_| new_topic_anchor_kind.set("task".to_owned()),
                                "Task"
                            }
                            button {
                                class: if new_topic_anchor_kind() == "run" { "primary" } else { "secondary" },
                                "data-testid": "anchor-kind-run",
                                onclick: move |_| new_topic_anchor_kind.set("run".to_owned()),
                                "Run"
                            }
                            button {
                                class: if new_topic_anchor_kind() == "memory" { "primary" } else { "secondary" },
                                "data-testid": "anchor-kind-memory",
                                onclick: move |_| new_topic_anchor_kind.set("memory".to_owned()),
                                "Memory"
                            }
                        }
                        input {
                            "data-testid": "topic-anchor-target-input",
                            value: "{new_topic_anchor_target}",
                            placeholder: "Anchor target ID",
                            oninput: move |evt| new_topic_anchor_target.set(evt.value()),
                        }
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "submit-topic-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let space = selected_space.clone();
                                    move |_| {
                                        let title = new_topic_title().trim().to_owned();
                                        let body = new_topic_body().trim().to_owned();
                                        if title.is_empty() || body.is_empty() {
                                            status_msg.set("topic title and body are required".to_owned());
                                            return;
                                        }
                                        let tags: Vec<String> = new_topic_tags()
                                            .split(',')
                                            .map(|s| s.trim().to_owned())
                                            .filter(|s| !s.is_empty())
                                            .collect();
                                        let anchor_kind = new_topic_anchor_kind();
                                        let anchor_target = new_topic_anchor_target().trim().to_owned();
                                        if anchor_target.is_empty() {
                                            status_msg.set("anchor target is required".to_owned());
                                            return;
                                        }
                                        let topic_id = format!("cx:topic:{}", uuid_v8());
                                        let mentions = parse_structured_mentions(&body);
                                        let topic_op = cx_ops::topic_create_anchored(
                                            &space,
                                            &actor,
                                            &topic_id,
                                            &title,
                                            &body,
                                            json!({
                                                "kind": anchor_kind,
                                                "target": anchor_target,
                                            }),
                                            tags.clone(),
                                            mentions_to_json(&mentions),
                                        )
                                        .build("chask");
                                        let mut operations = vec![topic_op.clone()];
                                        operations.extend(mention_relation_ops(&space, &actor, &topic_id, &mentions));
                                        let commit = operations.iter().cloned().fold(
                                            CommitBuilder::new(actor.clone()),
                                            |builder, op| builder.add_operation(op),
                                        )
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
                                        let base = base.clone();
                                        let actor = actor.clone();
                                        let space = space.clone();
                                        status_msg.set("submitting topic entity".to_owned());
                                        spawn(async move {
                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                Ok(api) => match api
                                                    .submit_commit(
                                                        &actor,
                                                        commit_value,
                                                        expected_head.as_deref(),
                                                        Some(&topic_op.operation_id),
                                                    )
                                                    .await
                                                {
                                                    Ok(submitted) => {
                                                        topics.write().push(ForumTopic {
                                                            entity_id: topic_id.clone(),
                                                            title: title.clone(),
                                                            author: "chask".to_owned(),
                                                            body: body.clone(),
                                                            tags: tags.clone(),
                                                            created_at: chrono::Utc::now().format("%Y-%m-%d %H:%M").to_string(),
                                                            anchor_kind: anchor_kind.clone(),
                                                            anchor_target: anchor_target.clone(),
                                                            mentions: mentions.clone(),
                                                            operation_id: Some(topic_op.operation_id.clone()),
                                                            commit_id: Some(submitted.commit_id.clone()),
                                                            comments: Vec::new(),
                                                        });
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
                                                            for op in &operations {
                                                                store.append_raw_operation(
                                                                    op.operation_id.clone(),
                                                                    Some(space.clone()),
                                                                    json!({
                                                                        "kind": op.op_type,
                                                                        "target_ref": op.target_ref,
                                                                        "topic_id": topic_id.clone(),
                                                                        "commit_id": submitted.commit_id.clone(),
                                                                    }),
                                                                );
                                                            }
                                                        }
                                                        status_msg.set(format!("topic committed {}", topic_op.operation_id));
                                                        new_topic_title.set(String::new());
                                                        new_topic_body.set(String::new());
                                                        new_topic_tags.set(String::new());
                                                        new_topic_anchor_target.set(space.clone());
                                                        new_topic_anchor_kind.set("space".to_owned());
                                                        show_create.set(false);
                                                    }
                                                    Err(error) => status_msg.set(format!("topic create failed: {error}")),
                                                },
                                                Err(error) => status_msg.set(format!("invalid server URL: {error}")),
                                            }
                                        });
                                    }
                                },
                                "Create Topic"
                            }
                        }
                    }
                }
            }

            if let Some(idx) = open_topic() {
                if let Some(topic) = topics().get(idx) {
                    div { class: "event", "data-testid": "topic-detail",
                        div { class: "event-head",
                            span { "Topic" }
                            span { "{topic.created_at}" }
                        }
                        div { class: "space-title", "{topic.title}" }
                        div { class: "muted", "By: {topic.author}" }
                        div { "data-testid": "topic-anchor", "Anchor: {topic.anchor_kind} / {topic.anchor_target}" }
                        div { "{topic.body}" }
                        if !topic.mentions.is_empty() {
                            div { class: "actions", "data-testid": "topic-mentions",
                                for mention in &topic.mentions {
                                    span { class: "muted", "{mention.kind}: {mention.target}" }
                                }
                            }
                        }
                        div { class: "actions",
                            for tag in &topic.tags {
                                span { class: "muted", "#{tag} " }
                            }
                            if let Some(operation_id) = &topic.operation_id {
                                span { class: "muted", "fact {operation_id}" }
                            }
                        }

                        div { class: "section",
                            h2 { "Comments ({count_comments(&topic.comments)})" }
                            for comment in &topic.comments {
                                {render_comment(comment, comment_to)}
                            }
                        }

                        div { class: "composer", "data-testid": "reply-composer",
                            if let Some(ref parent) = comment_to() {
                                div { class: "muted", "Commenting on {parent}" }
                            }
                            textarea {
                                "data-testid": "reply-input",
                                value: "{comment_draft}",
                                placeholder: "Write a comment. Comments are stored separately from chat messages.",
                                oninput: move |evt| comment_draft.set(evt.value()),
                            }
                            div { class: "actions",
                                button {
                                    class: "primary",
                                    "data-testid": "submit-reply-button",
                                    onclick: {
                                        let base = base_url.clone();
                                        let actor = account_did.clone();
                                        let space = selected_space.clone();
                                        let topic_id = topic.entity_id.clone();
                                        move |_| {
                                            let body = comment_draft().trim().to_owned();
                                            if body.is_empty() {
                                                status_msg.set("comment body is required".to_owned());
                                                return;
                                            }
                                            let comment_id = format!("cx:comment:{}", uuid_v8());
                                            let parent_id = comment_to();
                                            let mentions = parse_structured_mentions(&body);
                                            let comment_op = cx_ops::comment_create_structured(
                                                &space,
                                                &actor,
                                                &comment_id,
                                                &topic_id,
                                                &body,
                                                parent_id.as_deref(),
                                                mentions_to_json(&mentions),
                                            )
                                            .build("chask");
                                            let mut operations = vec![comment_op.clone()];
                                            operations.extend(mention_relation_ops(&space, &actor, &comment_id, &mentions));
                                            let commit = operations.iter().cloned().fold(
                                                CommitBuilder::new(actor.clone()),
                                                |builder, op| builder.add_operation(op),
                                            )
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
                                            let base = base.clone();
                                            let actor = actor.clone();
                                            let space = space.clone();
                                            let topic_id = topic_id.clone();
                                            status_msg.set("submitting comment entity".to_owned());
                                            spawn(async move {
                                                match authed_api_with_sync(&base, api_token, wait_for) {
                                                    Ok(api) => match api
                                                        .submit_commit(
                                                            &actor,
                                                            commit_value,
                                                            expected_head.as_deref(),
                                                            Some(&comment_op.operation_id),
                                                        )
                                                        .await
                                                    {
                                                        Ok(submitted) => {
                                                            let comment = ForumComment {
                                                                entity_id: comment_id.clone(),
                                                                author: "chask".to_owned(),
                                                                body: body.clone(),
                                                                created_at: chrono::Utc::now().format("%Y-%m-%d %H:%M").to_string(),
                                                                parent_id: parent_id.clone(),
                                                                target_ref: topic_id.clone(),
                                                                mentions: mentions.clone(),
                                                                operation_id: Some(comment_op.operation_id.clone()),
                                                                commit_id: Some(submitted.commit_id.clone()),
                                                                comments: Vec::new(),
                                                            };
                                                            if let Some(topic) = topics.write().get_mut(idx) {
                                                                if let Some(ref parent) = parent_id {
                                                                    if !insert_comment(&mut topic.comments, parent, comment.clone()) {
                                                                        topic.comments.push(comment);
                                                                    }
                                                                } else {
                                                                    topic.comments.push(comment);
                                                                }
                                                            }
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
                                                                for op in &operations {
                                                                    store.append_raw_operation(
                                                                        op.operation_id.clone(),
                                                                        Some(space.clone()),
                                                                        json!({
                                                                            "kind": op.op_type,
                                                                            "target_ref": op.target_ref,
                                                                            "comment_id": comment_id.clone(),
                                                                            "commit_id": submitted.commit_id.clone(),
                                                                        }),
                                                                    );
                                                                }
                                                            }
                                                            comment_draft.set(String::new());
                                                            comment_to.set(None);
                                                            status_msg.set(format!("comment committed {}", comment_op.operation_id));
                                                        }
                                                        Err(error) => status_msg.set(format!("comment create failed: {error}")),
                                                    },
                                                    Err(error) => status_msg.set(format!("invalid server URL: {error}")),
                                                }
                                            });
                                        }
                                    },
                                    "Post Comment"
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
                        div { class: "muted", "Anchor: {topic.anchor_kind} / {topic.anchor_target}" }
                        div { class: "actions",
                            for tag in &topic.tags {
                                span { class: "muted", "#{tag} " }
                            }
                            span { class: "muted", "{count_comments(&topic.comments)} comments" }
                        }
                    }
                }
                if topics().is_empty() {
                    div { class: "event",
                        div { class: "event-head", span { "Forum" } span { "empty" } }
                        div { class: "muted", "No topics yet. Create the first anchored discussion!" }
                    }
                }
            }

            if !status_msg().is_empty() {
                div { class: "muted", "data-testid": "forum-status", "{status_msg}" }
            }
        }
    }
}

fn render_comment(comment: &ForumComment, mut comment_to: Signal<Option<String>>) -> Element {
    let comment_id = comment.entity_id.clone();
    rsx! {
        div { class: "event", "data-testid": "forum-comment",
            div { class: "event-head",
                span { "{comment.author}" }
                span { "{comment.created_at}" }
            }
            div { "{comment.body}" }
            div { class: "muted", "Comment target: {comment.target_ref}" }
            if !comment.mentions.is_empty() {
                div { class: "actions",
                    for mention in &comment.mentions {
                        span { class: "muted", "{mention.kind}: {mention.target}" }
                    }
                }
            }
            if let Some(operation_id) = &comment.operation_id {
                div { class: "muted", "fact {operation_id}" }
            }
            div { class: "actions",
                button {
                    class: "secondary",
                    "data-testid": "reply-to-reply",
                    onclick: move |_| comment_to.set(Some(comment_id.clone())),
                    "Comment"
                }
            }
            for nested in &comment.comments {
                div { style: "margin-left: 24px;",
                    {render_comment(nested, comment_to)}
                }
            }
        }
    }
}

fn expected_head(repo_state: String) -> Option<String> {
    repo_state.starts_with("cx:commit:").then_some(repo_state)
}

fn count_comments(comments: &[ForumComment]) -> usize {
    comments.len()
        + comments
            .iter()
            .map(|comment| count_comments(&comment.comments))
            .sum::<usize>()
}

fn insert_comment(
    comments: &mut Vec<ForumComment>,
    parent_id: &str,
    comment: ForumComment,
) -> bool {
    for existing in comments {
        if existing.entity_id == parent_id {
            existing.comments.push(comment);
            return true;
        }
        if insert_comment(&mut existing.comments, parent_id, comment.clone()) {
            return true;
        }
    }
    false
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

fn mention_relation_ops(
    space_id: &str,
    actor: &str,
    source_id: &str,
    mentions: &[StructuredMention],
) -> Vec<OperationEnvelope> {
    mentions
        .iter()
        .map(|mention| {
            cx_ops::relation_create(space_id, actor, source_id, &mention.target, "mentions")
                .build("chask")
        })
        .collect()
}
