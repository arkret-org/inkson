use dioxus::prelude::*;

#[derive(Clone, Debug, PartialEq)]
struct AgentStep {
    id: String,
    name: String,
    status: String,
    tool_call: Option<String>,
    input: String,
    output: String,
    duration_ms: u64,
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
}

#[component]
pub fn AgentRunsPanel(
    base_url: String,
    token: Signal<String>,
) -> Element {
    let mut runs = use_signal(|| {
        vec![AgentRun {
            id: "run-1".to_owned(),
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
                },
                AgentStep {
                    id: "step-2".to_owned(),
                    name: "call_api".to_owned(),
                    status: "completed".to_owned(),
                    tool_call: Some("ContrixApi::search_spaces".to_owned()),
                    input: "search query".to_owned(),
                    output: "3 results".to_owned(),
                    duration_ms: 890,
                },
            ],
            input_summary: "Search for demo spaces".to_owned(),
            output_summary: "Found 3 matching spaces".to_owned(),
        }]
    });
    let mut open_run = use_signal(|| Option::<usize>::None);
    let mut filter_status = use_signal(|| "all".to_owned());

    rsx! {
        div { class: "timeline", "data-testid": "agent-runs-panel",
            div { class: "event",
                div { class: "event-head", span { "Agent Runs" } span { "{runs().len()} runs" } }
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

            // Run detail view
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

                        // Step-by-step trace
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
                // Run list
                for (idx, run) in runs().iter().enumerate() {
                    if filter_status() == "all" || run.status == filter_status() {
                        div {
                            class: "event",
                            "data-testid": "agent-run",
                            style: "cursor: pointer;",
                            onclick: move |_| open_run.set(Some(idx)),
                            div { class: "event-head",
                                span { "{run.agent_name}" }
                                span { "{run.status} ({run.duration_ms}ms)" }
                            }
                            div { class: "space-title", "{run.input_summary}" }
                            div { class: "muted", "Steps: {run.steps.len()}" }
                            div { class: "muted", "Started: {run.started_at}" }
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
