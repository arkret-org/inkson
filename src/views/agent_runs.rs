use dioxus::prelude::*;
use serde_json::json;

use crate::{
    local_state::LocalStateStore,
    operation::{CommitBuilder, cx_ops, uuid_v8},
    views::helpers::{active_sync_token, authed_api_with_sync},
};

#[derive(Clone, Debug, PartialEq)]
struct AgentStep {
    id: String,
    name: String,
    status: String,
    tool_call: Option<String>,
    input: String,
    output: String,
    duration_ms: u64,
    operation_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
struct AgentRun {
    id: String,
    agent_name: String,
    status: String,
    started_at: String,
    completed_at: Option<String>,
    duration_ms: u64,
    steps: Vec<AgentStep>,
    input_summary: String,
    output_summary: String,
    operation_id: Option<String>,
    commit_id: Option<String>,
}

#[component]
pub fn AgentRunsPanel(
    base_url: String,
    account_did: String,
    token: Signal<String>,
    selected_space: String,
    sync_cursor: Signal<String>,
    repo_state: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let mut runs = use_signal(|| {
        vec![AgentRun {
            id: "cx:run:demo".to_owned(),
            agent_name: "demo-agent".to_owned(),
            status: "completed".to_owned(),
            started_at: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            completed_at: Some(chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()),
            duration_ms: 1234,
            steps: vec![
                AgentStep {
                    id: "step-1".to_owned(),
                    name: "parse_input".to_owned(),
                    status: "completed".to_owned(),
                    tool_call: None,
                    input: "user query".to_owned(),
                    output: "parsed intent".to_owned(),
                    duration_ms: 120,
                    operation_id: None,
                },
                AgentStep {
                    id: "step-2".to_owned(),
                    name: "call_api".to_owned(),
                    status: "completed".to_owned(),
                    tool_call: Some("ContrixApi::search_spaces".to_owned()),
                    input: "search query".to_owned(),
                    output: "3 results".to_owned(),
                    duration_ms: 890,
                    operation_id: None,
                },
            ],
            input_summary: "Search for demo spaces".to_owned(),
            output_summary: "Found 3 matching spaces".to_owned(),
            operation_id: None,
            commit_id: None,
        }]
    });
    let mut open_run = use_signal(|| Option::<usize>::None);
    let mut filter_status = use_signal(|| "all".to_owned());
    let mut new_agent_name = use_signal(|| "research-agent".to_owned());
    let mut new_run_input = use_signal(|| "Summarize release blockers".to_owned());
    let mut run_status = use_signal(|| String::new());

    rsx! {
        div { class: "timeline", "data-testid": "agent-runs-panel",
            div { class: "event",
                div { class: "event-head", span { "Agent Runs" } span { "{runs().len()} runs" } }
                div { class: "muted", "Create, update, complete, or fail agent runs as repo-backed facts." }
                div { class: "actions",
                    button {
                        class: if filter_status() == "all" { "primary" } else { "secondary" },
                        onclick: move |_| filter_status.set("all".to_owned()),
                        "All"
                    }
                    button {
                        class: if filter_status() == "completed" { "primary" } else { "secondary" },
                        onclick: move |_| filter_status.set("completed".to_owned()),
                        "Completed"
                    }
                    button {
                        class: if filter_status() == "running" { "primary" } else { "secondary" },
                        onclick: move |_| filter_status.set("running".to_owned()),
                        "Running"
                    }
                    button {
                        class: if filter_status() == "failed" { "primary" } else { "secondary" },
                        onclick: move |_| filter_status.set("failed".to_owned()),
                        "Failed"
                    }
                }
            }

            div { class: "event", "data-testid": "run-create-form",
                div { class: "event-head", span { "New Run" } span { "{selected_space}" } }
                input {
                    "data-testid": "run-agent-input",
                    value: "{new_agent_name}",
                    oninput: move |event| new_agent_name.set(event.value()),
                    placeholder: "agent name",
                }
                textarea {
                    "data-testid": "run-input",
                    value: "{new_run_input}",
                    oninput: move |event| new_run_input.set(event.value()),
                    placeholder: "run input",
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "start-run-button",
                        onclick: {
                            let base = base_url.clone();
                            let actor = account_did.clone();
                            let space = selected_space.clone();
                            move |_| {
                                let agent = new_agent_name().trim().to_owned();
                                let input = new_run_input().trim().to_owned();
                                if agent.is_empty() || input.is_empty() {
                                    run_status.set("agent name and input are required".to_owned());
                                    return;
                                }
                                let run_id = format!("cx:run:{}", uuid_v8());
                                let op = cx_ops::run_create_structured(
                                    &space,
                                    &actor,
                                    &run_id,
                                    &agent,
                                    json!({"summary": input.clone()}),
                                    "running",
                                )
                                .build("chask");
                                let commit = CommitBuilder::new(actor.clone())
                                    .add_operation(op.clone())
                                    .build();
                                let commit_value = match serde_json::to_value(&commit) {
                                    Ok(value) => value,
                                    Err(error) => {
                                        run_status.set(format!("serialize failed: {error}"));
                                        return;
                                    }
                                };
                                let api_token = token();
                                let wait_for = active_sync_token(&sync_cursor());
                                let expected_head = expected_head(repo_state());
                                let base = base.clone();
                                let actor = actor.clone();
                                let space = space.clone();
                                run_status.set("submitting run create".to_owned());
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
                                                runs.write().push(AgentRun {
                                                    id: run_id.clone(),
                                                    agent_name: agent.clone(),
                                                    status: "running".to_owned(),
                                                    started_at: chrono::Utc::now()
                                                        .format("%Y-%m-%d %H:%M:%S")
                                                        .to_string(),
                                                    completed_at: None,
                                                    duration_ms: 0,
                                                    steps: Vec::new(),
                                                    input_summary: input.clone(),
                                                    output_summary: "pending".to_owned(),
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
                                                            "run_id": run_id,
                                                            "kind": "cx.run.create",
                                                            "commit_id": submitted.commit_id,
                                                        }),
                                                    );
                                                }
                                                new_run_input.set(String::new());
                                                run_status.set(format!("run created {}", op.operation_id));
                                            }
                                            Err(error) => run_status.set(format!("run create failed: {error}")),
                                        },
                                        Err(error) => run_status.set(format!("invalid server URL: {error}")),
                                    }
                                });
                            }
                        },
                        "Start Run"
                    }
                }
                if !run_status().is_empty() {
                    div { class: "muted", "data-testid": "agent-run-status", "{run_status}" }
                }
            }

            if let Some(idx) = open_run() {
                if let Some(run) = runs().get(idx) {
                    div { class: "event", "data-testid": "run-detail",
                        div { class: "event-head",
                            span { "Run: {run.agent_name}" }
                            span { "{run.status}" }
                        }
                        div { class: "metric-grid",
                            div { class: "metric",
                                strong { "Run ID" }
                                span { "{run.id}" }
                            }
                            div { class: "metric",
                                strong { "Agent" }
                                span { "{run.agent_name}" }
                            }
                            div { class: "metric",
                                strong { "Duration" }
                                span { "{run.duration_ms}ms" }
                            }
                            div { class: "metric",
                                strong { "Steps" }
                                span { "{run.steps.len()}" }
                            }
                        }
                        div { class: "event",
                            div { class: "space-title", "Input" }
                            div { class: "muted", "{run.input_summary}" }
                        }
                        div { class: "event",
                            div { class: "space-title", "Output" }
                            div { class: "muted", "{run.output_summary}" }
                        }
                        if let Some(operation_id) = &run.operation_id {
                            div { class: "muted", "data-testid": "run-operation", "create fact {operation_id}" }
                        }
                        if let Some(commit_id) = &run.commit_id {
                            div { class: "muted", "commit {commit_id}" }
                        }

                        div { class: "section",
                            h2 { "Steps" }
                            for (step_idx, step) in run.steps.iter().enumerate() {
                                div { class: "event", "data-testid": "agent-step",
                                    div { class: "event-head",
                                        span { "Step {step_idx + 1}: {step.name}" }
                                        span { "{step.status} ({step.duration_ms}ms)" }
                                    }
                                    if let Some(ref tool) = step.tool_call {
                                        div { class: "muted", "Tool: {tool}" }
                                    }
                                    div { class: "muted",
                                        div { strong { "Input:" } }
                                        div { "{step.input}" }
                                    }
                                    div { class: "muted",
                                        div { strong { "Output:" } }
                                        div { "{step.output}" }
                                    }
                                    if let Some(operation_id) = &step.operation_id {
                                        div { class: "muted", "fact {operation_id}" }
                                    }
                                }
                            }
                        }

                        div { class: "actions",
                            button {
                                class: "secondary",
                                onclick: move |_| open_run.set(None),
                                "Back to Runs"
                            }
                        }
                    }
                }
            } else {
                for (idx, run) in runs().iter().enumerate() {
                    if filter_status() == "all" || run.status == filter_status() {
                        div {
                            class: "event",
                            "data-testid": "agent-run",
                            div { class: "event-head",
                                span { "{run.agent_name}" }
                                span { "{run.status} ({run.duration_ms}ms)" }
                            }
                            div { class: "space-title", "{run.input_summary}" }
                            div { class: "muted", "Steps: {run.steps.len()}" }
                            div { class: "muted", "Started: {run.started_at}" }
                            if let Some(operation_id) = &run.operation_id {
                                div { class: "muted", "data-testid": "run-operation", "fact {operation_id}" }
                            }
                            div { class: "actions",
                                button {
                                    class: "secondary",
                                    "data-testid": "open-run-button",
                                    onclick: move |_| open_run.set(Some(idx)),
                                    "Open"
                                }
                                if run.status == "running" {
                                    button {
                                        class: "secondary",
                                        "data-testid": "update-run-button",
                                        onclick: {
                                            let base = base_url.clone();
                                            let actor = account_did.clone();
                                            let space = selected_space.clone();
                                            let run_id = run.id.clone();
                                            move |_| {
                                                let step_id = format!("step-{}", runs().get(idx).map(|r| r.steps.len() + 1).unwrap_or(1));
                                                let op = cx_ops::run_update(
                                                    &space,
                                                    &actor,
                                                    &run_id,
                                                    "running",
                                                    json!({
                                                        "step_id": step_id,
                                                        "name": "tool_execution",
                                                        "status": "completed",
                                                        "tool_call": "mock.tool",
                                                        "input": "repo-backed step",
                                                        "output": "tool step recorded",
                                                        "duration_ms": 240,
                                                    }),
                                                )
                                                .build("chask");
                                                let commit = CommitBuilder::new(actor.clone())
                                                    .add_operation(op.clone())
                                                    .build();
                                                let commit_value = match serde_json::to_value(&commit) {
                                                    Ok(value) => value,
                                                    Err(error) => {
                                                        run_status.set(format!("serialize failed: {error}"));
                                                        return;
                                                    }
                                                };
                                                let api_token = token();
                                                let wait_for = active_sync_token(&sync_cursor());
                                                let expected_head = expected_head(repo_state());
                                                let base = base.clone();
                                                let actor = actor.clone();
                                                let space = space.clone();
                                                let run_id_for_task = run_id.clone();
                                                run_status.set("submitting run update".to_owned());
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
                                                                if let Some(run) = runs.write().iter_mut().find(|run| run.id == run_id_for_task) {
                                                                    run.duration_ms += 240;
                                                                    run.steps.push(AgentStep {
                                                                        id: step_id.clone(),
                                                                        name: "tool_execution".to_owned(),
                                                                        status: "completed".to_owned(),
                                                                        tool_call: Some("mock.tool".to_owned()),
                                                                        input: "repo-backed step".to_owned(),
                                                                        output: "tool step recorded".to_owned(),
                                                                        duration_ms: 240,
                                                                        operation_id: Some(op.operation_id.clone()),
                                                                    });
                                                                    run.commit_id = Some(submitted.commit_id.clone());
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
                                                                            "run_id": run_id_for_task,
                                                                            "kind": "cx.run.update",
                                                                            "commit_id": submitted.commit_id,
                                                                        }),
                                                                    );
                                                                }
                                                                run_status.set(format!("run updated {}", op.operation_id));
                                                            }
                                                            Err(error) => run_status.set(format!("run update failed: {error}")),
                                                        },
                                                        Err(error) => run_status.set(format!("invalid server URL: {error}")),
                                                    }
                                                });
                                            }
                                        },
                                        "Record Step"
                                    }
                                    button {
                                        class: "primary",
                                        "data-testid": "complete-run-button",
                                        onclick: {
                                            let base = base_url.clone();
                                            let actor = account_did.clone();
                                            let space = selected_space.clone();
                                            let run_id = run.id.clone();
                                            move |_| {
                                                let op = cx_ops::run_complete(
                                                    &space,
                                                    &actor,
                                                    &run_id,
                                                    json!({"summary": "Run completed from review panel"}),
                                                )
                                                .build("chask");
                                                let commit = CommitBuilder::new(actor.clone())
                                                    .add_operation(op.clone())
                                                    .build();
                                                let commit_value = match serde_json::to_value(&commit) {
                                                    Ok(value) => value,
                                                    Err(error) => {
                                                        run_status.set(format!("serialize failed: {error}"));
                                                        return;
                                                    }
                                                };
                                                let api_token = token();
                                                let wait_for = active_sync_token(&sync_cursor());
                                                let expected_head = expected_head(repo_state());
                                                let base = base.clone();
                                                let actor = actor.clone();
                                                let space = space.clone();
                                                let run_id_for_task = run_id.clone();
                                                run_status.set("submitting run completion".to_owned());
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
                                                                if let Some(run) = runs.write().iter_mut().find(|run| run.id == run_id_for_task) {
                                                                    run.status = "completed".to_owned();
                                                                    run.output_summary = "Run completed from review panel".to_owned();
                                                                    run.completed_at = Some(
                                                                        chrono::Utc::now()
                                                                            .format("%Y-%m-%d %H:%M:%S")
                                                                            .to_string(),
                                                                    );
                                                                    run.commit_id = Some(submitted.commit_id.clone());
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
                                                                            "run_id": run_id_for_task,
                                                                            "kind": "cx.run.complete",
                                                                            "commit_id": submitted.commit_id,
                                                                        }),
                                                                    );
                                                                }
                                                                run_status.set(format!("run completed {}", op.operation_id));
                                                            }
                                                            Err(error) => run_status.set(format!("run complete failed: {error}")),
                                                        },
                                                        Err(error) => run_status.set(format!("invalid server URL: {error}")),
                                                    }
                                                });
                                            }
                                        },
                                        "Complete"
                                    }
                                    button {
                                        class: "secondary",
                                        "data-testid": "fail-run-button",
                                        onclick: {
                                            let base = base_url.clone();
                                            let actor = account_did.clone();
                                            let space = selected_space.clone();
                                            let run_id = run.id.clone();
                                            move |_| {
                                                let op = cx_ops::run_fail(&space, &actor, &run_id, "manual failure").build("chask");
                                                let commit = CommitBuilder::new(actor.clone())
                                                    .add_operation(op.clone())
                                                    .build();
                                                let commit_value = match serde_json::to_value(&commit) {
                                                    Ok(value) => value,
                                                    Err(error) => {
                                                        run_status.set(format!("serialize failed: {error}"));
                                                        return;
                                                    }
                                                };
                                                let api_token = token();
                                                let wait_for = active_sync_token(&sync_cursor());
                                                let expected_head = expected_head(repo_state());
                                                let base = base.clone();
                                                let actor = actor.clone();
                                                let space = space.clone();
                                                let run_id_for_task = run_id.clone();
                                                run_status.set("submitting run failure".to_owned());
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
                                                                if let Some(run) = runs.write().iter_mut().find(|run| run.id == run_id_for_task) {
                                                                    run.status = "failed".to_owned();
                                                                    run.output_summary = "manual failure".to_owned();
                                                                    run.completed_at = Some(
                                                                        chrono::Utc::now()
                                                                            .format("%Y-%m-%d %H:%M:%S")
                                                                            .to_string(),
                                                                    );
                                                                    run.commit_id = Some(submitted.commit_id.clone());
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
                                                                            "run_id": run_id_for_task,
                                                                            "kind": "cx.run.fail",
                                                                            "commit_id": submitted.commit_id,
                                                                        }),
                                                                    );
                                                                }
                                                                run_status.set(format!("run failed {}", op.operation_id));
                                                            }
                                                            Err(error) => run_status.set(format!("run fail failed: {error}")),
                                                        },
                                                        Err(error) => run_status.set(format!("invalid server URL: {error}")),
                                                    }
                                                });
                                            }
                                        },
                                        "Fail"
                                    }
                                }
                            }
                        }
                    }
                }
                if runs().is_empty() {
                    div { class: "event",
                        div { class: "event-head", span { "Agent Runs" } span { "empty" } }
                        div { class: "muted", "No agent runs recorded yet." }
                    }
                }
            }
        }
    }
}

fn expected_head(repo_state: String) -> Option<String> {
    repo_state.starts_with("cx:commit:").then_some(repo_state)
}
