use dioxus::prelude::*;
use serde_json::json;

use crate::{
    local_state::LocalStateStore,
    operation::{CommitBuilder, cx_ops, uuid_v8},
    views::helpers::{active_sync_token, authed_api_with_sync},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemoryLayer {
    Working,
    Episodic,
    Semantic,
    Task,
}

impl MemoryLayer {
    fn as_str(self) -> &'static str {
        match self {
            Self::Working => "working",
            Self::Episodic => "episodic",
            Self::Semantic => "semantic",
            Self::Task => "task",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct MemoryEntry {
    id: String,
    layer: MemoryLayer,
    content: String,
    confidence: f64,
    source: String,
    timestamp: String,
    state: String,
    operation_id: Option<String>,
    commit_id: Option<String>,
}

#[component]
pub fn MemoryReviewPanel(
    base_url: String,
    account_did: String,
    token: Signal<String>,
    selected_space: String,
    sync_cursor: Signal<String>,
    repo_state: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let mut memories = use_signal(|| {
        vec![
            MemoryEntry {
                id: "cx:memory:demo-working".to_owned(),
                layer: MemoryLayer::Working,
                content: "User is currently reviewing the memory panel".to_owned(),
                confidence: 0.95,
                source: "session".to_owned(),
                timestamp: "2026-01-01 00:00".to_owned(),
                state: "candidate".to_owned(),
                operation_id: None,
                commit_id: None,
            },
            MemoryEntry {
                id: "cx:memory:demo-semantic".to_owned(),
                layer: MemoryLayer::Semantic,
                content: "Contrix uses DID-based identity for authentication".to_owned(),
                confidence: 0.99,
                source: "documentation".to_owned(),
                timestamp: "2026-01-01 00:00".to_owned(),
                state: "candidate".to_owned(),
                operation_id: None,
                commit_id: None,
            },
        ]
    });
    let mut filter_layer = use_signal(|| Option::<MemoryLayer>::None);
    let mut edit_id = use_signal(|| Option::<String>::None);
    let mut edit_text = use_signal(String::new);
    let mut new_memory_text = use_signal(|| "User prefers repo-backed memory review".to_owned());
    let mut new_memory_layer = use_signal(|| MemoryLayer::Semantic);
    let mut memory_status = use_signal(|| String::new());

    let filtered: Vec<MemoryEntry> = memories()
        .iter()
        .filter(|m| filter_layer().map_or(true, |layer| m.layer == layer))
        .cloned()
        .collect();
    let filtered_empty = filtered.is_empty();

    rsx! {
        div { class: "timeline", "data-testid": "memory-review-panel",
            div { class: "event",
                div { class: "event-head", span { "Memory Review" } span { "agent memories" } }
                div { class: "muted", "Review, edit, confirm, invalidate, or supersede agent memory facts." }
            }

            div { class: "event", "data-testid": "memory-create-form",
                div { class: "event-head", span { "Capture Candidate" } span { "{selected_space}" } }
                textarea {
                    "data-testid": "new-memory-input",
                    value: "{new_memory_text}",
                    oninput: move |event| new_memory_text.set(event.value()),
                    placeholder: "memory candidate",
                }
                div { class: "actions",
                    button {
                        class: if new_memory_layer() == MemoryLayer::Working { "primary" } else { "secondary" },
                        onclick: move |_| new_memory_layer.set(MemoryLayer::Working),
                        "Working"
                    }
                    button {
                        class: if new_memory_layer() == MemoryLayer::Episodic { "primary" } else { "secondary" },
                        onclick: move |_| new_memory_layer.set(MemoryLayer::Episodic),
                        "Episodic"
                    }
                    button {
                        class: if new_memory_layer() == MemoryLayer::Semantic { "primary" } else { "secondary" },
                        onclick: move |_| new_memory_layer.set(MemoryLayer::Semantic),
                        "Semantic"
                    }
                    button {
                        class: if new_memory_layer() == MemoryLayer::Task { "primary" } else { "secondary" },
                        onclick: move |_| new_memory_layer.set(MemoryLayer::Task),
                        "Task"
                    }
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "capture-memory-button",
                        onclick: {
                            let base = base_url.clone();
                            let actor = account_did.clone();
                            let space = selected_space.clone();
                            move |_| {
                                let content = new_memory_text().trim().to_owned();
                                if content.is_empty() {
                                    memory_status.set("memory content is required".to_owned());
                                    return;
                                }
                                let layer = new_memory_layer();
                                let memory_id = format!("cx:memory:{}", uuid_v8());
                                let op = cx_ops::memory_create_structured(
                                    &space,
                                    &actor,
                                    &memory_id,
                                    &content,
                                    layer.as_str(),
                                    "agent_review",
                                    0.91,
                                    "candidate",
                                )
                                .build("yougen");
                                let commit = CommitBuilder::new(actor.clone())
                                    .add_operation(op.clone())
                                    .build();
                                let commit_value = match serde_json::to_value(&commit) {
                                    Ok(value) => value,
                                    Err(error) => {
                                        memory_status.set(format!("serialize failed: {error}"));
                                        return;
                                    }
                                };
                                let api_token = token();
                                let wait_for = active_sync_token(&sync_cursor());
                                let expected_head = expected_head(repo_state());
                                let base = base.clone();
                                let actor = actor.clone();
                                let space = space.clone();
                                memory_status.set("submitting memory candidate".to_owned());
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
                                                memories.write().push(MemoryEntry {
                                                    id: memory_id.clone(),
                                                    layer,
                                                    content: content.clone(),
                                                    confidence: 0.91,
                                                    source: "agent_review".to_owned(),
                                                    timestamp: chrono::Utc::now()
                                                        .format("%Y-%m-%d %H:%M")
                                                        .to_string(),
                                                    state: "candidate".to_owned(),
                                                    operation_id: Some(op.operation_id.clone()),
                                                    commit_id: Some(submitted.commit_id.clone()),
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
                                                    store.append_raw_operation(
                                                        op.operation_id.clone(),
                                                        Some(space.clone()),
                                                        json!({
                                                            "memory_id": memory_id,
                                                            "kind": "cx.memory.create",
                                                            "commit_id": submitted.commit_id,
                                                        }),
                                                    );
                                                }
                                                new_memory_text.set(String::new());
                                                memory_status.set(format!("memory captured {}", op.operation_id));
                                            }
                                            Err(error) => memory_status.set(format!("memory create failed: {error}")),
                                        },
                                        Err(error) => memory_status.set(format!("invalid server URL: {error}")),
                                    }
                                });
                            }
                        },
                        "Capture"
                    }
                }
                if !memory_status().is_empty() {
                    div { class: "muted", "data-testid": "memory-status", "{memory_status}" }
                }
            }

            div { class: "event", "data-testid": "memory-filter",
                div { class: "actions",
                    button {
                        class: if filter_layer().is_none() { "primary" } else { "secondary" },
                        onclick: move |_| filter_layer.set(None),
                        "All"
                    }
                    button {
                        class: if filter_layer() == Some(MemoryLayer::Working) { "primary" } else { "secondary" },
                        onclick: move |_| filter_layer.set(Some(MemoryLayer::Working)),
                        "Working"
                    }
                    button {
                        class: if filter_layer() == Some(MemoryLayer::Episodic) { "primary" } else { "secondary" },
                        onclick: move |_| filter_layer.set(Some(MemoryLayer::Episodic)),
                        "Episodic"
                    }
                    button {
                        class: if filter_layer() == Some(MemoryLayer::Semantic) { "primary" } else { "secondary" },
                        onclick: move |_| filter_layer.set(Some(MemoryLayer::Semantic)),
                        "Semantic"
                    }
                    button {
                        class: if filter_layer() == Some(MemoryLayer::Task) { "primary" } else { "secondary" },
                        onclick: move |_| filter_layer.set(Some(MemoryLayer::Task)),
                        "Task"
                    }
                }
            }

            for memory in filtered {
                div {
                    class: "event",
                    "data-testid": "memory-entry",
                    style: if memory.state != "candidate" { "opacity: 0.68;" } else { "" },
                    div { class: "event-head",
                        span { "{memory.layer.as_str()}" }
                        span { "{memory.state} / {memory.source}" }
                    }
                    div { class: "space-title", "{memory.content}" }
                    div { class: "muted", "Confidence: {(memory.confidence * 100.0) as u32}%" }
                    div { class: "muted", "Created: {memory.timestamp}" }
                    div { class: "muted", "data-testid": "memory-id", "{memory.id}" }
                    if let Some(operation_id) = &memory.operation_id {
                        div { class: "muted", "data-testid": "memory-fact", "fact {operation_id}" }
                    }
                    if let Some(commit_id) = &memory.commit_id {
                        div { class: "muted", "commit {commit_id}" }
                    }

                    if edit_id() == Some(memory.id.clone()) {
                        div { class: "workflow-form",
                            textarea {
                                "data-testid": "memory-edit-input",
                                value: "{edit_text}",
                                oninput: move |evt| edit_text.set(evt.value()),
                            }
                            div { class: "actions",
                                button {
                                    class: "primary",
                                    "data-testid": "save-memory-edit",
                                    onclick: {
                                        let base = base_url.clone();
                                        let actor = account_did.clone();
                                        let space = selected_space.clone();
                                        let memory_id = memory.id.clone();
                                        move |_| {
                                            let text = edit_text().trim().to_owned();
                                            if text.is_empty() {
                                                memory_status.set("memory content is required".to_owned());
                                                return;
                                            }
                                            let op = cx_ops::memory_update(
                                                &space,
                                                &actor,
                                                &memory_id,
                                                json!({"content": text.clone(), "state": "candidate"}),
                                            )
                                            .build("yougen");
                                            let commit = CommitBuilder::new(actor.clone())
                                                .add_operation(op.clone())
                                                .build();
                                            let commit_value = match serde_json::to_value(&commit) {
                                                Ok(value) => value,
                                                Err(error) => {
                                                    memory_status.set(format!("serialize failed: {error}"));
                                                    return;
                                                }
                                            };
                                            let api_token = token();
                                            let wait_for = active_sync_token(&sync_cursor());
                                            let expected_head = expected_head(repo_state());
                                            let base = base.clone();
                                            let actor = actor.clone();
                                            let space = space.clone();
                                            let memory_id_for_task = memory_id.clone();
                                            memory_status.set("submitting memory update".to_owned());
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
                                                            if let Some(entry) = memories
                                                                .write()
                                                                .iter_mut()
                                                                .find(|entry| entry.id == memory_id_for_task)
                                                            {
                                                                entry.content = text.clone();
                                                                entry.operation_id = Some(op.operation_id.clone());
                                                                entry.commit_id = Some(submitted.commit_id.clone());
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
                                                                store.append_raw_operation(
                                                                    op.operation_id.clone(),
                                                                    Some(space.clone()),
                                                                    json!({
                                                                        "memory_id": memory_id_for_task,
                                                                        "kind": "cx.memory.update",
                                                                        "commit_id": submitted.commit_id,
                                                                    }),
                                                                );
                                                            }
                                                            edit_id.set(None);
                                                            edit_text.set(String::new());
                                                            memory_status.set(format!("memory updated {}", op.operation_id));
                                                        }
                                                        Err(error) => memory_status.set(format!("memory update failed: {error}")),
                                                    },
                                                    Err(error) => memory_status.set(format!("invalid server URL: {error}")),
                                                }
                                            });
                                        }
                                    },
                                    "Save"
                                }
                                button {
                                    class: "secondary",
                                    onclick: move |_| { edit_id.set(None); edit_text.set(String::new()); },
                                    "Cancel"
                                }
                            }
                        }
                    } else {
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "accept-memory-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let space = selected_space.clone();
                                    let memory_id = memory.id.clone();
                                    move |_| {
                                        let op = cx_ops::memory_confirm(&space, &actor, &memory_id).build("yougen");
                                        let commit = CommitBuilder::new(actor.clone())
                                            .add_operation(op.clone())
                                            .build();
                                        let commit_value = match serde_json::to_value(&commit) {
                                            Ok(value) => value,
                                            Err(error) => {
                                                memory_status.set(format!("serialize failed: {error}"));
                                                return;
                                            }
                                        };
                                        let api_token = token();
                                        let wait_for = active_sync_token(&sync_cursor());
                                        let expected_head = expected_head(repo_state());
                                        let base = base.clone();
                                        let actor = actor.clone();
                                        let space = space.clone();
                                        let memory_id_for_task = memory_id.clone();
                                        memory_status.set("submitting memory confirm".to_owned());
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
                                                        if let Some(entry) = memories
                                                            .write()
                                                            .iter_mut()
                                                            .find(|entry| entry.id == memory_id_for_task)
                                                        {
                                                            entry.state = "confirmed".to_owned();
                                                            entry.operation_id = Some(op.operation_id.clone());
                                                            entry.commit_id = Some(submitted.commit_id.clone());
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
                                                            store.append_raw_operation(
                                                                op.operation_id.clone(),
                                                                Some(space.clone()),
                                                                json!({
                                                                    "memory_id": memory_id_for_task,
                                                                    "kind": "cx.memory.confirm",
                                                                    "commit_id": submitted.commit_id,
                                                                }),
                                                            );
                                                        }
                                                        memory_status.set(format!("memory confirmed {}", op.operation_id));
                                                    }
                                                    Err(error) => memory_status.set(format!("memory confirm failed: {error}")),
                                                },
                                                Err(error) => memory_status.set(format!("invalid server URL: {error}")),
                                            }
                                        });
                                    }
                                },
                                "Accept"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "edit-memory-button",
                                onclick: {
                                    let mid = memory.id.clone();
                                    let content = memory.content.clone();
                                    move |_| {
                                        edit_id.set(Some(mid.clone()));
                                        edit_text.set(content.clone());
                                    }
                                },
                                "Edit"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "supersede-memory-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let space = selected_space.clone();
                                    let memory_id = memory.id.clone();
                                    let layer = memory.layer;
                                    let source_content = memory.content.clone();
                                    move |_| {
                                        let replacement_id = format!("cx:memory:{}", uuid_v8());
                                        let replacement_content = format!("{source_content} (superseded)");
                                        let create_op = cx_ops::memory_create_structured(
                                            &space,
                                            &actor,
                                            &replacement_id,
                                            &replacement_content,
                                            layer.as_str(),
                                            "agent_review",
                                            0.88,
                                            "candidate",
                                        )
                                        .build("yougen");
                                        let supersede_op = cx_ops::memory_supersede(
                                            &space,
                                            &actor,
                                            &memory_id,
                                            &replacement_id,
                                        )
                                        .build("yougen");
                                        let commit = CommitBuilder::new(actor.clone())
                                            .add_operation(create_op.clone())
                                            .add_operation(supersede_op.clone())
                                            .build();
                                        let commit_value = match serde_json::to_value(&commit) {
                                            Ok(value) => value,
                                            Err(error) => {
                                                memory_status.set(format!("serialize failed: {error}"));
                                                return;
                                            }
                                        };
                                        let api_token = token();
                                        let wait_for = active_sync_token(&sync_cursor());
                                        let expected_head = expected_head(repo_state());
                                        let base = base.clone();
                                        let actor = actor.clone();
                                        let space = space.clone();
                                        let memory_id_for_task = memory_id.clone();
                                        memory_status.set("submitting memory supersede".to_owned());
                                        spawn(async move {
                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                Ok(api) => match api
                                                    .submit_commit(
                                                        &actor,
                                                        commit_value,
                                                        expected_head.as_deref(),
                                                        Some(&supersede_op.operation_id),
                                                    )
                                                    .await
                                                {
                                                    Ok(submitted) => {
                                                        if let Some(entry) = memories
                                                            .write()
                                                            .iter_mut()
                                                            .find(|entry| entry.id == memory_id_for_task)
                                                        {
                                                            entry.state = "superseded".to_owned();
                                                            entry.operation_id = Some(supersede_op.operation_id.clone());
                                                            entry.commit_id = Some(submitted.commit_id.clone());
                                                        }
                                                        memories.write().push(MemoryEntry {
                                                            id: replacement_id.clone(),
                                                            layer,
                                                            content: replacement_content.clone(),
                                                            confidence: 0.88,
                                                            source: "agent_review".to_owned(),
                                                            timestamp: chrono::Utc::now()
                                                                .format("%Y-%m-%d %H:%M")
                                                                .to_string(),
                                                            state: "candidate".to_owned(),
                                                            operation_id: Some(create_op.operation_id.clone()),
                                                            commit_id: Some(submitted.commit_id.clone()),
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
                                                            store.append_raw_operation(
                                                                supersede_op.operation_id.clone(),
                                                                Some(space.clone()),
                                                                json!({
                                                                    "memory_id": memory_id_for_task,
                                                                    "replacement_id": replacement_id,
                                                                    "kind": "cx.memory.supersede",
                                                                    "commit_id": submitted.commit_id,
                                                                }),
                                                            );
                                                        }
                                                        memory_status.set(format!("memory superseded {}", supersede_op.operation_id));
                                                    }
                                                    Err(error) => memory_status.set(format!("memory supersede failed: {error}")),
                                                },
                                                Err(error) => memory_status.set(format!("invalid server URL: {error}")),
                                            }
                                        });
                                    }
                                },
                                "Supersede"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "reject-memory-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let space = selected_space.clone();
                                    let memory_id = memory.id.clone();
                                    move |_| {
                                        let op = cx_ops::memory_invalidate(&space, &actor, &memory_id, "review rejected").build("yougen");
                                        let commit = CommitBuilder::new(actor.clone())
                                            .add_operation(op.clone())
                                            .build();
                                        let commit_value = match serde_json::to_value(&commit) {
                                            Ok(value) => value,
                                            Err(error) => {
                                                memory_status.set(format!("serialize failed: {error}"));
                                                return;
                                            }
                                        };
                                        let api_token = token();
                                        let wait_for = active_sync_token(&sync_cursor());
                                        let expected_head = expected_head(repo_state());
                                        let base = base.clone();
                                        let actor = actor.clone();
                                        let space = space.clone();
                                        let memory_id_for_task = memory_id.clone();
                                        memory_status.set("submitting memory invalidate".to_owned());
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
                                                        if let Some(entry) = memories
                                                            .write()
                                                            .iter_mut()
                                                            .find(|entry| entry.id == memory_id_for_task)
                                                        {
                                                            entry.state = "invalidated".to_owned();
                                                            entry.operation_id = Some(op.operation_id.clone());
                                                            entry.commit_id = Some(submitted.commit_id.clone());
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
                                                            store.append_raw_operation(
                                                                op.operation_id.clone(),
                                                                Some(space.clone()),
                                                                json!({
                                                                    "memory_id": memory_id_for_task,
                                                                    "kind": "cx.memory.invalidate",
                                                                    "commit_id": submitted.commit_id,
                                                                }),
                                                            );
                                                        }
                                                        memory_status.set(format!("memory invalidated {}", op.operation_id));
                                                    }
                                                    Err(error) => memory_status.set(format!("memory invalidate failed: {error}")),
                                                },
                                                Err(error) => memory_status.set(format!("invalid server URL: {error}")),
                                            }
                                        });
                                    }
                                },
                                "Reject"
                            }
                        }
                    }
                }
            }

            if filtered_empty {
                div { class: "event",
                    div { class: "event-head", span { "Memory" } span { "empty" } }
                    div { class: "muted", "No memory entries match the current filter." }
                }
            }
        }
    }
}

fn expected_head(repo_state: String) -> Option<String> {
    repo_state.starts_with("cx:commit:").then_some(repo_state)
}
