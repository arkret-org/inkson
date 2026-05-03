use dioxus::prelude::*;

use crate::{
    conformance::{client_profile_declarations, profile_readiness},
    models::ServerDescription,
    workflows::{WorkflowStage, blocked_release_workflows, production_release_workflows},
};

#[component]
pub fn ReadinessPanel(
    mut status: Signal<String>,
    server_description: Option<ServerDescription>,
    server_probe_status: String,
) -> Element {
    let workflows = production_release_workflows();
    let blocked_count = blocked_release_workflows().len();
    let local_profiles = client_profile_declarations();
    let local_profile_count = local_profiles.len();
    let readiness: Vec<_> = profile_readiness(server_description.as_ref())
        .into_iter()
        .map(|profile| {
            let missing_label = if profile.missing.is_empty() {
                "none".to_owned()
            } else {
                profile.missing.join(", ")
            };
            (profile, missing_label)
        })
        .collect();
    let server_profile_count = server_description
        .as_ref()
        .map(|description| description.supported_profiles.len())
        .unwrap_or_default();
    let server_feature_count = server_description
        .as_ref()
        .map(|description| description.supported_features.len())
        .unwrap_or_default();
    let server_schema_profiles = server_description
        .as_ref()
        .map(|description| join_or_dash(&description.supported_schema_profiles))
        .unwrap_or_else(|| "-".to_owned());
    let server_reducer_profiles = server_description
        .as_ref()
        .map(|description| join_or_dash(&description.supported_reducer_profiles))
        .unwrap_or_else(|| "-".to_owned());
    let server_limits = server_description
        .as_ref()
        .map(|description| compact_json(&description.limits))
        .unwrap_or_else(|| "-".to_owned());
    rsx! {
        div { class: "timeline", "data-testid": "readiness-panel",
            div { class: "event", "data-testid": "release-summary",
                div { class: "event-head", span { "Release readiness" } span { "{blocked_count} blockers" } }
                div { class: "space-title", "Not production-ready" }
                div { class: "muted", "Basic server-backed product flows exist in the client. Production release is still blocked by DID proof challenges, production auth, verification, recovery, privacy, retention, web crypto storage, and release engineering." }
            }
            div { class: "event", "data-testid": "server-describe-readiness",
                div { class: "event-head", span { "Server describe" } span { "{server_probe_status}" } }
                if let Some(description) = server_description.as_ref() {
                    div { class: "space-title", "{description.service_type} / {description.protocol_version}" }
                    div { class: "muted", "Service DID: {description.service_did}" }
                    div { class: "muted", "Profiles: {server_profile_count}; features: {server_feature_count}" }
                    div { class: "muted", "Schema profiles: {server_schema_profiles}" }
                    div { class: "muted", "Reducer profiles: {server_reducer_profiles}" }
                    div { class: "muted", "Limits: {server_limits}" }
                } else {
                    div { class: "space-title", "No server declaration loaded" }
                    div { class: "muted", "Connect or fix the server URL so /server/describe can be evaluated." }
                }
            }
            div { class: "event", "data-testid": "local-profile-support",
                div { class: "event-head", span { "Local client profiles" } span { "{local_profile_count}" } }
                for profile in local_profiles {
                    div { class: "metric-grid", "data-testid": "local-profile-row",
                        div { class: "metric",
                            strong { "{profile.label}" }
                            span { "{profile.profile_id}" }
                        }
                        div { class: "metric",
                            strong { "Local" }
                            span { if profile.local_supported { "supported" } else { "not supported" } }
                        }
                    }
                    div { class: "muted", "{profile.description}" }
                }
            }
            div { class: "event", "data-testid": "profile-readiness",
                div { class: "event-head", span { "Profile gating" } span { "server/client gap" } }
                for (profile, missing_label) in readiness {
                    div { class: "event", "data-testid": "profile-readiness-row",
                        div { class: "event-head",
                            span { "{profile.label}" }
                            span { if profile.ready { "ready" } else { "degraded" } }
                        }
                        div { class: "muted", "{profile.profile_id}" }
                        div { class: "muted",
                            "Server declared profile: "
                            if profile.server_declared { "yes" } else { "no" }
                        }
                        div { class: "muted", "Missing requirements: {missing_label}" }
                        div { class: "muted", "Degradation: {profile.degradation_path}" }
                    }
                }
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

fn join_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_owned()
    } else {
        values.join(", ")
    }
}

fn compact_json(value: &serde_json::Value) -> String {
    if value.is_null() {
        "-".to_owned()
    } else {
        serde_json::to_string(value).unwrap_or_else(|_| "-".to_owned())
    }
}
