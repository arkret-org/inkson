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
            by_target
                .entry(target.to_owned())
                .or_default()
                .push(op.clone());
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
    let mut capability_actor = use_signal(|| "did:web:alice.example".to_owned());
    let mut capability_action = use_signal(|| "space.read".to_owned());
    let mut capability_resource = use_signal(|| "cx:space:01js0sp0000000000000000000".to_owned());
    let mut capability_grants = use_signal(Vec::<Value>::new);
    let mut capability_state_hash = use_signal(|| Option::<String>::None);
    let mut capability_decision = use_signal(|| String::new());
    let mut capability_reason = use_signal(|| String::new());

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

            div { class: "event", "data-testid": "capability-explanation",
                div { class: "event-head", span { "Capability explanation" } span { "{capability_grants().len()} grants" } }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Actor" }
                        input {
                            "data-testid": "capability-actor-input",
                            value: "{capability_actor}",
                            oninput: move |event| capability_actor.set(event.value()),
                        }
                    }
                    div { class: "metric",
                        strong { "Action" }
                        input {
                            "data-testid": "capability-action-input",
                            value: "{capability_action}",
                            oninput: move |event| capability_action.set(event.value()),
                        }
                    }
                    div { class: "metric",
                        strong { "Resource" }
                        input {
                            "data-testid": "capability-resource-input",
                            value: "{capability_resource}",
                            oninput: move |event| capability_resource.set(event.value()),
                        }
                    }
                    div { class: "metric", "data-testid": "capability-decision",
                        strong { "Decision" }
                        span { if capability_decision().is_empty() { "not checked" } else { "{capability_decision}" } }
                    }
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "load-capabilities-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                let actor = capability_actor();
                                let action = capability_action();
                                let resource = capability_resource();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.effective_grants(&actor).await {
                                            Ok(resp) => {
                                                capability_state_hash.set(resp.state_hash.clone());
                                                capability_grants.set(resp.grants);
                                            }
                                            Err(error) => capability_reason.set(format!("effective grants failed: {error}")),
                                        }
                                        match api.authz_check(&actor, &action, &resource).await {
                                            Ok(decision) => {
                                                capability_decision.set(if decision.allowed { "allowed".to_owned() } else { "denied".to_owned() });
                                                capability_reason.set(decision.reason_code.unwrap_or_else(|| "frontier current".to_owned()));
                                            }
                                            Err(error) => {
                                                capability_decision.set("error".to_owned());
                                                capability_reason.set(format!("check failed: {error}"));
                                            }
                                        }
                                    }
                                });
                            }
                        },
                        "Load Capabilities"
                    }
                }
                if let Some(state_hash) = capability_state_hash() {
                    div { class: "muted", "data-testid": "capability-frontier",
                        "state frontier {state_hash}"
                    }
                }
                if !capability_reason().is_empty() {
                    div { class: "muted", "data-testid": "capability-reason",
                        "reason {capability_reason}"
                    }
                }
                for grant in capability_grants() {
                    div { class: "event", "data-testid": "capability-grant-row",
                        div { class: "event-head",
                            span { "{json_text(&grant, \"grant_id\")}" }
                            span { "{json_text(&grant, \"issuer\")}" }
                        }
                        div { class: "muted", "data-testid": "capability-resource-selectors",
                            "selectors {json_value(&grant, &[\"resource_selectors\", \"resources\", \"resource\"])}"
                        }
                        div { class: "muted", "data-testid": "capability-constraints",
                            "constraints {json_value(&grant, &[\"constraints\", \"obligations\"])}"
                        }
                        {
                            let allowed_facets = capability_allowed_entity_facets(&grant);
                            if !allowed_facets.is_empty() {
                                let allowed_facets_label = allowed_facets.join(", ");
                                rsx! {
                                    div { class: "muted", "data-testid": "capability-allowed-facets",
                                        "allowed entity facets {allowed_facets_label}"
                                    }
                                }
                            } else {
                                rsx! { div {} }
                            }
                        }
                        div { class: "muted", "data-testid": "capability-delegation-chain",
                            "delegation {json_value(&grant, &[\"delegation_chain\", \"proofs\"])}"
                        }
                    }
                }
                if capability_decision() == "denied" && !capability_reason().is_empty() {
                    div { class: "muted", "data-testid": "capability-denial-class",
                        "denial {capability_denial_label(&capability_reason())}"
                    }
                }
                if capability_grants().is_empty() {
                    div { class: "muted", "No grants loaded. Click Load Capabilities." }
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

fn json_text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_owned()
}

fn json_value(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| value.get(*key))
        .map(|v| v.to_string())
        .unwrap_or_else(|| "[]".to_owned())
}

fn capability_allowed_entity_facets(grant: &Value) -> Vec<String> {
    let mut facets = Vec::new();
    collect_string_array(grant.get("allowed_entity_facets"), &mut facets);

    if let Some(constraints) = grant.get("constraints").and_then(|v| v.as_array()) {
        for constraint in constraints {
            collect_string_array(constraint.get("allowed_entity_facets"), &mut facets);
            collect_string_array(
                constraint
                    .get("params")
                    .and_then(|params| params.get("allowed_entity_facets")),
                &mut facets,
            );
        }
    }

    facets
}

fn collect_string_array(value: Option<&Value>, target: &mut Vec<String>) {
    if let Some(values) = value.and_then(|v| v.as_array()) {
        for value in values {
            if let Some(text) = value.as_str() {
                let text = text.to_owned();
                if !target.contains(&text) {
                    target.push(text);
                }
            }
        }
    }
}

fn capability_denial_label(reason: &str) -> &'static str {
    let reason = reason.to_ascii_lowercase();
    if reason.contains("entity type") || reason.contains("entity_type") {
        "entity type label mismatch"
    } else if reason.contains("entity facet") || reason.contains("allowed_entity_facets") {
        "facet capability missing"
    } else if reason.contains("stale") || reason.contains("frontier") {
        "stale frontier"
    } else if reason.contains("review") {
        "requires review"
    } else {
        "access denied"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detects_multi_actor_conflicts_by_target_ref() {
        let ops = vec![
            json!({"operation_id": "op1", "target_ref": "cx:task:1", "actor": "did:web:alice"}),
            json!({"operation_id": "op2", "target_ref": "cx:task:1", "actor": "did:web:bob"}),
            json!({"operation_id": "op3", "target_ref": "cx:task:2", "actor": "did:web:alice"}),
        ];

        let conflicts = detect_conflicts(&ops);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].target_ref, "cx:task:1");
    }

    #[test]
    fn capability_explanation_helpers_extract_fallback_fields() {
        let grant = json!({
            "grant_id": "cx:grant:test",
            "resources": ["space:cx:space:test/**"],
            "constraints": [{"type": "temporal"}],
            "proofs": ["cx:grant:root"]
        });

        assert_eq!(json_text(&grant, "grant_id"), "cx:grant:test");
        assert!(
            json_value(&grant, &["resource_selectors", "resources"])
                .contains("space:cx:space:test")
        );
        assert!(json_value(&grant, &["constraints"]).contains("temporal"));
        assert!(json_value(&grant, &["delegation_chain", "proofs"]).contains("cx:grant:root"));
    }

    #[test]
    fn capability_explanation_extracts_allowed_entity_facets() {
        let grant = json!({
            "allowed_entity_facets": ["renderable"],
            "constraints": [
                {"type": "type_restriction", "params": {"allowed_entity_facets": ["stateful", "rankable"]}},
                {"type": "type_restriction", "allowed_entity_facets": ["renderable"]}
            ]
        });

        assert_eq!(
            capability_allowed_entity_facets(&grant),
            vec![
                "renderable".to_owned(),
                "stateful".to_owned(),
                "rankable".to_owned()
            ]
        );
    }

    #[test]
    fn capability_denial_label_distinguishes_type_and_facet_denials() {
        assert_eq!(
            capability_denial_label("entity type task not allowed"),
            "entity type label mismatch"
        );
        assert_eq!(
            capability_denial_label("entity facet rankable not allowed or unavailable"),
            "facet capability missing"
        );
    }
}
