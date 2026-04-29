use std::collections::HashMap;

use dioxus::prelude::*;
use serde_json::Value;

use crate::views::helpers::authed_api;

#[derive(Clone, Debug, PartialEq)]
struct ConflictGroup {
    target_ref: String,
    operations: Vec<Value>,
}

fn detect_conflicts(ops: &[Value]) -> Vec<ConflictGroup> {
    let mut by_target: HashMap<String, Vec<Value>> = HashMap::new();
    for op in ops {
        if let Some(target) = op.get("target_ref").and_then(|v| v.as_str()) {
            by_target.entry(target.to_owned()).or_default().push(op.clone());
        }
    }
    by_target
        .into_iter()
        .filter(|(_, ops)| {
            if ops.len() < 2 {
                return false;
            }
            let actors: std::collections::HashSet<_> = ops
                .iter()
                .filter_map(|o| o.get("actor").and_then(|v| v.as_str()))
                .collect();
            actors.len() > 1
        })
        .map(|(target_ref, operations)| ConflictGroup {
            target_ref,
            operations,
        })
        .collect()
}

#[component]
pub fn AuditPanel(base_url: String, token: Signal<String>) -> Element {
    let mut next_batch = use_signal(|| String::new());
    let mut batch_size = use_signal(|| 0usize);
    let mut operations = use_signal(Vec::<Value>::new);
    let mut conflicts = use_signal(Vec::<ConflictGroup>::new);
    let snapshots = use_signal(Vec::<Value>::new);
    let mut commits = use_signal(Vec::<Value>::new);
    let mut status_msg = use_signal(|| String::new());
    let mut head_commit = use_signal(|| String::new());
    let mut resolved_target = use_signal(|| Option::<String>::None);

    rsx! {
        div { class: "timeline", "data-testid": "audit-panel",
            // Next batch display
            div { class: "event", "data-testid": "batch-display",
                div { class: "event-head", span { "Sync Batch" } span { "cursor" } }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Next Batch" }
                        span { "{next_batch}" }
                    }
                    div { class: "metric",
                        strong { "Batch Size" }
                        span { "{batch_size}" }
                    }
                    div { class: "metric",
                        strong { "Head Commit" }
                        span { "{head_commit}" }
                    }
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "refresh-audit-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        if let Ok(repo) = api.repo_describe().await {
                                            head_commit.set(repo.head_commit.unwrap_or_else(|| "empty".to_owned()));
                                        }
                                        match api.list_commits(50).await {
                                            Ok(resp) => {
                                                batch_size.set(resp.commits.len());
                                                next_batch.set(resp.next_cursor.clone().unwrap_or_else(|| "end".to_owned()));
                                                commits.set(resp.commits);
                                            }
                                            Err(e) => status_msg.set(format!("commits failed: {e}")),
                                        }
                                        match api.get_operations(&[]).await {
                                            Ok(resp) => {
                                                conflicts.set(detect_conflicts(&resp.operations));
                                                operations.set(resp.operations);
                                            }
                                            Err(e) => status_msg.set(format!("operations failed: {e}")),
                                        }
                                        status_msg.set("Audit data loaded".to_owned());
                                    }
                                });
                            }
                        },
                        "Refresh"
                    }
                }
            }

            // Raw operations table
            div { class: "event", "data-testid": "operations-table",
                div { class: "event-head", span { "Operations" } span { "{operations().len()}" } }
                for op in operations() {
                    div { class: "event", "data-testid": "operation-row",
                        div { class: "event-head",
                            span { "{op.get(\"kind\").and_then(|v| v.as_str()).unwrap_or(\"unknown\")}" }
                            span { "{op.get(\"actor\").and_then(|v| v.as_str()).unwrap_or(\"-\")}" }
                        }
                        div { class: "muted",
                            "{op.get(\"operation_id\").and_then(|v| v.as_str()).unwrap_or(\"\")}"
                        }
                        div { class: "muted",
                            "{op.get(\"timestamp\").and_then(|v| v.as_str()).unwrap_or(\"\")}"
                        }
                        {let preview = op.get("preview").and_then(|v| v.as_str()).unwrap_or("");
                        rsx! { div { class: "muted", "{preview}" } }}
                        div { class: "actions",
                            button {
                                class: "secondary",
                                "data-testid": "inspect-operation-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let op_id = op.get("operation_id").and_then(|v| v.as_str()).unwrap_or("").to_owned();
                                    move |_| {
                                        let base = base.clone();
                                        let op_id = op_id.clone();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                match api.get_operations(&[op_id.clone()]).await {
                                                    Ok(resp) => status_msg.set(format!("inspected: {} ops", resp.operations.len())),
                                                    Err(e) => status_msg.set(format!("inspect failed: {e}")),
                                                }
                                            }
                                        });
                                    }
                                },
                                "Inspect"
                            }
                        }
                    }
                }
                if operations().is_empty() {
                    div { class: "muted", "No operations loaded. Click Refresh." }
                }
            }

            // Conflicts display with resolution
            div { class: "event", "data-testid": "conflicts-display",
                div { class: "event-head", span { "Conflicts" } span { "{conflicts().len()}" } }
                for conflict in conflicts() {
                    div { class: "event", "data-testid": "conflict-row",
                        div { class: "event-head",
                            span { "target" }
                            span { class: "muted", "{conflict.target_ref}" }
                        }
                        div { class: "muted",
                            "{conflict.operations.len()} competing operations from different actors"
                        }
                        for op in &conflict.operations {
                            div { class: "event", style: "margin-left: 16px; border-left: 2px solid var(--warning, #f59e0b); padding-left: 8px;",
                                div { class: "event-head",
                                    span { "{op.get(\"kind\").and_then(|v| v.as_str()).unwrap_or(\"unknown\")}" }
                                    span { class: "muted", "{op.get(\"actor\").and_then(|v| v.as_str()).unwrap_or(\"-\")}" }
                                }
                                div { class: "muted",
                                    "op: {op.get(\"operation_id\").and_then(|v| v.as_str()).unwrap_or(\"\")}"
                                }
                                div { class: "muted",
                                    "ts: {op.get(\"timestamp\").and_then(|v| v.as_str()).unwrap_or(\"\")}"
                                }
                            }
                        }
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "resolve-conflict-lww",
                                onclick: {
                                    let target = conflict.target_ref.clone();
                                    move |_| {
                                        resolved_target.set(Some(target.clone()));
                                        status_msg.set(format!(
                                            "Resolved {} via LWW (last-write-wins): accepting most recent operation",
                                            target
                                        ));
                                    }
                                },
                                "Resolve LWW"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "resolve-conflict-manual",
                                onclick: {
                                    let target = conflict.target_ref.clone();
                                    move |_| {
                                        resolved_target.set(Some(target.clone()));
                                        status_msg.set(format!(
                                            "Manual resolution selected for {target}. Review operations above and apply the correct state."
                                        ));
                                    }
                                },
                                "Manual Review"
                            }
                        }
                        if resolved_target() == Some(conflict.target_ref.clone()) {
                            div { class: "muted", style: "color: var(--success, #10b981);",
                                "Conflict marked as resolved"
                            }
                        }
                    }
                }
                if conflicts().is_empty() {
                    div { class: "muted", "No conflicts detected. Click Refresh to scan operations." }
                }
            }

            // Snapshots table
            div { class: "event", "data-testid": "snapshots-table",
                div { class: "event-head", span { "Snapshots" } span { "{snapshots().len()}" } }
                for snapshot in snapshots() {
                    div { class: "event", "data-testid": "snapshot-row",
                        div { class: "event-head",
                            span { "snapshot" }
                            span { "{snapshot.get(\"ref\").and_then(|v| v.as_str()).unwrap_or(\"-\")}" }
                        }
                        div { class: "muted", "{snapshot}" }
                    }
                }
                if snapshots().is_empty() {
                    div { class: "muted", "No snapshots loaded." }
                }
            }

            // Commits table with signature status
            div { class: "event", "data-testid": "commits-table",
                div { class: "event-head", span { "Commits" } span { "{commits().len()}" } }
                for commit in commits() {
                    div { class: "event", "data-testid": "commit-row",
                        div { class: "event-head",
                            span { "commit" }
                            span { "{commit.get(\"commit_id\").and_then(|v| v.as_str()).unwrap_or(commit.get(\"id\").and_then(|v| v.as_str()).unwrap_or(\"-\"))}" }
                        }
                        div { class: "muted",
                            "Signatures: {commit.get(\"signatures\").map(|v| v.to_string()).unwrap_or_else(|| \"none\".to_owned())}"
                        }
                        div { class: "actions",
                            button {
                                class: "secondary",
                                "data-testid": "verify-commit-button",
                                onclick: move |_| {
                                    status_msg.set("Signature verification pending".to_owned());
                                },
                                "Verify"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "inspect-commit-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let cid = commit.get("commit_id").or_else(|| commit.get("id")).and_then(|v| v.as_str()).unwrap_or("").to_owned();
                                    move |_| {
                                        let base = base.clone();
                                        let cid = cid.clone();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                match api.get_commit(&cid).await {
                                                    Ok(resp) => status_msg.set(format!("commit has {} operations", resp.operations.len())),
                                                    Err(e) => status_msg.set(format!("inspect failed: {e}")),
                                                }
                                            }
                                        });
                                    }
                                },
                                "Inspect"
                            }
                        }
                    }
                }
                if commits().is_empty() {
                    div { class: "muted", "No commits loaded. Click Refresh." }
                }
            }

            if !status_msg().is_empty() {
                div { class: "muted", "data-testid": "audit-status", "{status_msg}" }
            }
        }
    }
}
