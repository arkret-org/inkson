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
    let mut protocol_health = use_signal(Vec::<(String, String)>::new);
    let mut health_loading = use_signal(|| false);

    rsx! {
        div { class: "timeline", "data-testid": "dashboard-panel",
            div { class: "event home-hero", "data-testid": "dashboard-hero",
                div { class: "event-head",
                    span { "Home" }
                    span { "Contrix workspace" }
                }
                div { class: "space-title home-hero-title", "Acme Workspace" }
                div { class: "home-hero-copy",
                    "Organization Principal: Acme Inc. Principal Server is the connected service boundary; Spaces keep independent policy and history."
                }
            }

            div { class: "metric-grid", "data-testid": "dashboard-metrics",
                div { class: "metric",
                    strong { "Spaces" }
                    span { "{spaces().len()}" }
                    div { class: "muted", "joined or discovered" }
                }
                div { class: "metric",
                    strong { "Cross-org" }
                    span { "1" }
                    div { class: "muted", "closed federation" }
                }
                div { class: "metric",
                    strong { "Inbox" }
                    span { "28" }
                    div { class: "muted", "mentions and approvals" }
                }
                div { class: "metric",
                    strong { "Local queue" }
                    span { "data-testid": "device-queue-card", "{device_queue}" }
                    div { class: "muted", "pending local writes" }
                }
            }

            div { class: "dashboard-layout",
                div { class: "event", "data-testid": "spaces-summary",
                    div { class: "event-head", span { "Spaces" } span { "policy boundaries" } }
                    div { class: "home-card-list",
                        if spaces().is_empty() {
                            Link {
                                class: "space-button home-space-card active",
                                "data-testid": "dashboard-space-card",
                                to: Route::Timeline,
                                onclick: move |_| view.set(super::View::Timeline),
                                div { class: "space-title", "Acme Engineering" }
                                div { class: "space-meta", "Hub Space · org-backed" }
                                div { class: "home-badges",
                                    span { class: "badge green", "org principal" }
                                    span { class: "badge blue", "independent policy" }
                                }
                            }
                            Link {
                                class: "space-button home-space-card cross-org",
                                "data-testid": "dashboard-space-card",
                                to: Route::Kanban,
                                onclick: move |_| view.set(super::View::Kanban),
                                div { class: "space-title", "Acme x Beta Launch" }
                                div { class: "space-meta", "Controlled cross-org · closed federation" }
                                div { class: "home-badges",
                                    span { class: "badge green", "HA" }
                                    span { class: "badge blue", "closed" }
                                }
                            }
                            Link {
                                class: "space-button home-space-card",
                                "data-testid": "dashboard-space-card",
                                to: Route::Document,
                                onclick: move |_| view.set(super::View::Document),
                                div { class: "space-title", "My Drafts" }
                                div { class: "space-meta", "purpose=personal · no hub ownership implied" }
                                div { class: "home-badges",
                                    span { class: "badge amber", "private" }
                                }
                            }
                        } else {
                            for space in spaces() {
                                Link {
                                    class: if space.space_id == selected_space() { "space-button home-space-card active" } else { "space-button home-space-card" },
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
                                        "{space.description.clone().unwrap_or_else(|| \"Independent Space boundary\".to_owned())}"
                                    }
                                }
                            }
                        }
                    }
                }

                div { class: "event", "data-testid": "quick-actions",
                    div { class: "event-head", span { "Quick Actions" } span { "common paths" } }
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

            div { class: "event", "data-testid": "protocol-health",
                div { class: "event-head", span { "Protocol Health" } span { "server probes" } }
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
                    div { class: "metric",
                        strong { "{name}" }
                        span { "{status}" }
                    }
                }
                if protocol_health().is_empty() {
                    div { class: "muted", "Run checks when the Principal Server changes." }
                }
            }

            div { class: "event", "data-testid": "sync-health-banner", role: "status",
                div { class: "event-head",
                    span { "Sync Health" }
                    span { "frontier aligned" }
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Cursor" }
                        span { "{sync_cursor}" }
                        div { class: "muted", "read-your-writes barrier input" }
                    }
                    div { class: "metric",
                        strong { "Local queue" }
                        span { "{device_queue}" }
                        div { class: "muted", "writes waiting for replay" }
                    }
                    div { class: "metric",
                        strong { "Repo head" }
                        span { "{repo_state}" }
                        div { class: "muted", "Principal Server reported" }
                    }
                }
            }

            div { class: "event", "data-testid": "recent-boards",
                div { class: "event-head",
                    span { "Recent Boards" }
                    span { "kind=board" }
                }
                div { class: "home-card-list compact",
                    Link {
                        class: "space-button home-space-card",
                        "data-testid": "recent-board-release",
                        to: Route::Kanban,
                        onclick: move |_| view.set(super::View::Kanban),
                        div { class: "space-title", "Release Board" }
                        div { class: "space-meta", "kind=board · 5 lists · 38 flows" }
                        div { class: "muted", "renderer=board · view=v1.release" }
                    }
                    Link {
                        class: "space-button home-space-card",
                        "data-testid": "recent-board-triage",
                        to: Route::Kanban,
                        onclick: move |_| view.set(super::View::Kanban),
                        div { class: "space-title", "Triage Board" }
                        div { class: "space-meta", "kind=board · 3 lists · 92 flows · 7 overdue" }
                    }
                    Link {
                        class: "space-button home-space-card",
                        "aria-label": "Q3 Roadmap Board",
                        "data-testid": "recent-board-roadmap",
                        to: Route::Kanban,
                        onclick: move |_| view.set(super::View::Kanban),
                        div { class: "space-title", "Q3 Roadmap" }
                        div { class: "space-meta", "kind=board · timeline renderer" }
                    }
                }
            }

            div { class: "event", "data-testid": "pinned-inbox",
                div { class: "event-head",
                    span { "Pinned Inbox" }
                    span { "@ mention · assignment · approval" }
                }
                div { class: "actions",
                    Link {
                        class: "secondary",
                        "data-testid": "pinned-inbox-open",
                        to: Route::Notifications,
                        onclick: move |_| view.set(super::View::Notifications),
                        "Open Inbox"
                    }
                }
                div { class: "event nested-card",
                    div { class: "event-head", span { "@ mention" } span { "Review launch checklist" } }
                    div { class: "space-title", "Mei mentioned you" }
                    div { class: "muted", "branch=discussion · branch-scoped membership" }
                }
                div { class: "event nested-card",
                    div { class: "event-head", span { "approval" } span { "1 / 2 admin" } }
                    div { class: "space-title", "Researcher Agent requested read_flow" }
                    div { class: "muted", "approval_constraint=2_of_3_admin" }
                }
                div { class: "event nested-card",
                    div { class: "event-head", span { "conflict" } span { "cx.flow.move superseded" } }
                    div { class: "space-title", "Concurrent move resolved" }
                    div { class: "muted", "Losing write remains auditable." }
                }
            }

            div { class: "event", "data-testid": "activity-feed",
                div { class: "event-head", span { "Recent Activity" } span { "derived projection" } }
                div { class: "event nested-card",
                    div { class: "event-head", span { "cx.flow.move" } span { "Launch Board" } }
                    div { class: "space-title", "Legal review moved into Doing" }
                }
                div { class: "event nested-card",
                    div { class: "event-head", span { "cx.message.create" } span { "Review discussion" } }
                    div { class: "space-title", "Bob mentioned you in a visible discussion" }
                }
            }
        }
    }
}
