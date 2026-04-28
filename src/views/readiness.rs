use dioxus::prelude::*;

use crate::workflows::{WorkflowStage, blocked_release_workflows, production_release_workflows};

#[component]
pub fn ReadinessPanel(mut status: Signal<String>) -> Element {
    let workflows = production_release_workflows();
    let blocked_count = blocked_release_workflows().len();
    rsx! {
        div { class: "timeline", "data-testid": "readiness-panel",
            div { class: "event", "data-testid": "release-summary",
                div { class: "event-head", span { "Release readiness" } span { "{blocked_count} blockers" } }
                div { class: "space-title", "Not production-ready" }
                div { class: "muted", "Basic server-backed product flows exist in the client. Production release is still blocked by DID proof challenges, production auth, verification, recovery, privacy, retention, web crypto storage, and release engineering." }
            }
            for workflow in workflows {
                div { class: "event", "data-testid": "workflow-row",
                    div { class: "event-head",
                        span { "{workflow.stage.label()}" }
                        span { "{workflow.id}" }
                    }
                    div { class: "space-title", "{workflow.name}" }
                    div { class: "muted", "Client: {workflow.client_surface}" }
                    div { class: "muted", "Dependency: {workflow.server_dependency}" }
                    if workflow.stage == WorkflowStage::Blocked {
                        div { class: "actions",
                            button {
                                class: "secondary",
                                "data-testid": "blocked-workflow-button",
                                onclick: {
                                    let name = workflow.name;
                                    let dependency = workflow.server_dependency;
                                    move |_| status.set(format!("Blocked: {name} requires {dependency}"))
                                },
                                "Show blocker"
                            }
                        }
                    }
                }
            }
        }
    }
}
