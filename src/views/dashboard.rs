use dioxus::prelude::*;

use crate::{
    api::ContrixApi,
    models::SpacePreview,
    views::helpers::authed_api,
};

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
    let mut recent_activity = use_signal(Vec::<String>::new);
    let mut protocol_health = use_signal(Vec::<(String, String)>::new);
    let mut health_loading = use_signal(|| false);

    rsx! {
        div { class: "timeline", "data-testid": "dashboard-panel",
            // Spaces summary with unread badges
            div { class: "event", "data-testid": "spaces-summary",
                div { class: "event-head", span { "Spaces" } span { "{spaces().len()} spaces" } }
                div { class: "space-list",
                    for space in spaces() {
                        div {
                            class: if space.space_id == selected_space() { "space-button active" } else { "space-button" },
                            "data-testid": "dashboard-space-card",
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

            // Quick-action bar
            div { class: "event", "data-testid": "quick-actions",
                div { class: "event-head", span { "Quick Actions" } span { "" } }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "quick-create-space",
                        onclick: move |_| view.set(super::View::Product),
                        "Create Space"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "quick-new-message",
                        onclick: move |_| view.set(super::View::Timeline),
                        "New Message"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "quick-search",
                        onclick: move |_| view.set(super::View::Directory),
                        "Search"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "quick-settings",
                        onclick: move |_| view.set(super::View::Settings),
                        "Settings"
                    }
                }
            }

            // Device queue status card
            div { class: "event", "data-testid": "device-queue-card",
                div { class: "event-head", span { "Device Queue" } span { "status" } }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Pending" }
                        span { "{device_queue}" }
                    }
                    div { class: "metric",
                        strong { "Sync Cursor" }
                        span { "{sync_cursor}" }
                    }
                }
            }

            // Repo head card
            div { class: "event", "data-testid": "repo-head-card",
                div { class: "event-head", span { "Repo Head" } span { "current state" } }
                div { class: "metric",
                    strong { "Head Commit" }
                    span { "{repo_state}" }
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

            // Recent activity feed
            div { class: "event", "data-testid": "activity-feed",
                div { class: "event-head", span { "Recent Activity" } span { "" } }
                for activity in recent_activity() {
                    div { class: "muted", "{activity}" }
                }
                if recent_activity().is_empty() {
                    div { class: "muted", "No recent activity. Actions will appear here." }
                }
            }
        }
    }
}
