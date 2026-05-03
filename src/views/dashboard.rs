use dioxus::prelude::*;
use dioxus_router::Link;

use crate::{models::SpacePreview, routes::Route, views::helpers::authed_api};

#[component]
pub fn DashboardPanel(
    base_url: String,
    token: Signal<String>,
    spaces: Signal<Vec<SpacePreview>>,
    selected_space: Signal<String>,
    view: Signal<super::View>,
    device_queue: usize,
    repo_state: String,
    sync_cursor: String,
) -> Element {
    let recent_activity = use_signal(Vec::<String>::new);
    let mut protocol_health = use_signal(Vec::<(String, String)>::new);
    let mut health_loading = use_signal(|| false);

    rsx! {
        div { class: "timeline", "data-testid": "dashboard-panel",
            div { class: "event", "data-testid": "dashboard-hero",
                div { class: "event-head",
                    span { "Workspace" }
                    span { "frontier-aware home" }
                }
                div { class: "space-title", "Contrix workbench" }
                div { class: "muted",
                    "最近 Space、Board、讨论(Discussion)、Inbox 和同步健康集中在这里。写入状态和权限边界会在进入具体页面前先被暴露。"
                }
            }

            div { class: "metric-grid", "data-testid": "dashboard-metrics",
                div { class: "metric",
                    strong { "Spaces" }
                    span { "{spaces().len()}" }
                    div { class: "muted", "joined or discoverable" }
                }
                div { class: "metric",
                    strong { "Assigned cards" }
                    span { "7" }
                    div { class: "muted", "mock projection" }
                }
                div { class: "metric",
                    strong { "Unread discussions" }
                    span { "28" }
                    div { class: "muted", "permission-trimmed" }
                }
                div { class: "metric",
                    strong { "Local queue" }
                    span { "data-testid": "device-queue-card", "{device_queue}" }
                    div { class: "muted", "device/to-device pending" }
                }
            }

            div { class: "dashboard-layout",
                div { class: "event", "data-testid": "spaces-summary",
                    div { class: "event-head", span { "Spaces" } span { "{spaces().len()} spaces" } }
                    div { class: "space-list",
                        for space in spaces() {
                            Link {
                                class: if space.space_id == selected_space() { "space-button active" } else { "space-button" },
                                "data-testid": "dashboard-space-card",
                                to: Route::TimelineSpace { space_id: space.space_id.clone() },
                                onclick: {
                                    let id = space.space_id.clone();
                                    move |_| {
                                        selected_space.set(id.clone());
                                        view.set(super::View::Timeline);
                                    }
                                },
                                div { class: "space-title", "{space.name}" }
                                div { class: "space-meta", "{space.space_id}" }
                                div { class: "muted",
                                    "{space.description.clone().unwrap_or_else(|| \"No description\".to_owned())}"
                                }
                            }
                        }
                        if spaces().is_empty() {
                            div { class: "muted", "No spaces loaded." }
                        }
                    }
                }

                div { class: "event", "data-testid": "quick-actions",
                    div { class: "event-head", span { "Quick Actions" } span { "workspace" } }
                    div { class: "actions",
                        Link {
                            class: "primary",
                            "data-testid": "quick-create-space",
                            to: Route::Product,
                            onclick: move |_| view.set(super::View::Product),
                            "Create Space"
                        }
                        Link {
                            class: "secondary",
                            "data-testid": "quick-open-board",
                            to: Route::Kanban,
                            onclick: move |_| view.set(super::View::Kanban),
                            "Open Board"
                        }
                        Link {
                            class: "secondary",
                            "data-testid": "quick-new-message",
                            to: Route::Chat,
                            onclick: move |_| view.set(super::View::Chat),
                            "Open Discussion"
                        }
                        Link {
                            class: "secondary",
                            "data-testid": "quick-search",
                            to: Route::Directory,
                            onclick: move |_| view.set(super::View::Directory),
                            "Directory"
                        }
                        Link {
                            class: "secondary",
                            "data-testid": "quick-settings",
                            to: Route::Settings,
                            onclick: move |_| view.set(super::View::Settings),
                            "Settings"
                        }
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "Cursor" }
                            span { "{sync_cursor}" }
                        }
                        div { class: "metric",
                            strong { "Repo" }
                            span { "data-testid": "repo-head-card", "{repo_state}" }
                        }
                    }
                }
            }

            // Protocol health table
            div { class: "event", "data-testid": "protocol-health",
                div { class: "event-head", span { "Protocol Health" } span { "" } }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "check-health-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                health_loading.set(true);
                                spawn(async move {
                                    let mut checks = Vec::new();
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.health().await {
                                            Ok(h) => checks.push(("Health".to_owned(), format!("OK ({})", h.service))),
                                            Err(e) => checks.push(("Health".to_owned(), format!("Error: {e}"))),
                                        }
                                        match api.describe().await {
                                            Ok(d) => checks.push(("Server".to_owned(), format!("{} v{}", d.service_type, d.protocol_version))),
                                            Err(e) => checks.push(("Server".to_owned(), format!("Error: {e}"))),
                                        }
                                        match api.sync_describe().await {
                                            Ok(s) => checks.push(("Sync".to_owned(), format!("{} profiles", s.supported_sync_profiles.len()))),
                                            Err(e) => checks.push(("Sync".to_owned(), format!("Error: {e}"))),
                                        }
                                        match api.identity_describe().await {
                                            Ok(i) => checks.push(("Identity".to_owned(), format!("mode={}", i.registry_mode))),
                                            Err(e) => checks.push(("Identity".to_owned(), format!("Error: {e}"))),
                                        }
                                        match api.index_describe().await {
                                            Ok(idx) => checks.push(("Index".to_owned(), format!("{} query features", idx.query_features.len()))),
                                            Err(e) => checks.push(("Index".to_owned(), format!("Error: {e}"))),
                                        }
                                    }
                                    protocol_health.set(checks);
                                    health_loading.set(false);
                                });
                            }
                        },
                        if health_loading() { "Checking..." } else { "Run Health Check" }
                    }
                }
                for (name, status) in protocol_health() {
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "{name}" }
                            span { "{status}" }
                        }
                    }
                }
                if protocol_health().is_empty() {
                    div { class: "muted", "Click Run Health Check to verify protocol endpoints." }
                }
            }

            div { class: "event", "data-testid": "activity-feed",
                div { class: "event-head", span { "Recent Activity" } span { "derived projection" } }
                div { class: "event",
                    div { class: "event-head", span { "cx.flow.move" } span { "Launch Board" } }
                    div { class: "space-title", "Legal review moved into Doing" }
                    div { class: "muted", "Position edge accepted at current frontier." }
                }
                div { class: "event",
                    div { class: "event-head", span { "cx.message.create" } span { "Review discussion" } }
                    div { class: "space-title", "Bob mentioned you in a visible discussion" }
                    div { class: "muted", "Discussion visibility is checked independently from card visibility." }
                }
                for activity in recent_activity() {
                    div { class: "muted", "{activity}" }
                }
            }
        }
    }
}
