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
            div { class: "spread mb-24", "data-testid": "dashboard-hero",
                div {
                    h1 { style: "font-size: 22px; margin: 0 0 4px; letter-spacing: -0.01em;",
                        "Good afternoon, Alice"
                    }
                    div { class: "muted f-12",
                        "3 mentions need attention. Sync frontier and device queue are cleanly visible below."
                    }
                }
                div { class: "row gap-6 wrap",
                    Link {
                        class: "btn sm primary",
                        "data-testid": "quick-create-space",
                        to: Route::Product,
                        onclick: move |_| view.set(super::View::Product),
                        "+ New Space"
                    }
                    Link {
                        class: "btn sm",
                        to: Route::Call,
                        onclick: move |_| view.set(super::View::Call),
                        "Start call"
                    }
                }
            }

            div { class: "metric-grid mb-24", "data-testid": "dashboard-metrics",
                Link {
                    class: "metric",
                    to: Route::Notifications,
                    onclick: move |_| view.set(super::View::Notifications),
                    div { class: "lbl", "Inbox" }
                    div { class: "val", "3" }
                    div { class: "delta", "+2 since yesterday" }
                }
                Link {
                    class: "metric",
                    to: Route::Audit,
                    onclick: move |_| view.set(super::View::Audit),
                    div { class: "lbl", "Sync frontier" }
                    div { class: "val mono", style: "font-size: 14px;", "{sync_cursor}" }
                    div { class: "delta", "online · {device_queue} pending" }
                }
                Link {
                    class: "metric",
                    to: Route::Devices,
                    onclick: move |_| view.set(super::View::Devices),
                    div { class: "lbl", "Devices" }
                    div { class: "val", "3" }
                    div { class: "delta", "Chrome · iPhone · iPad" }
                }
                div { class: "metric", "data-testid": "device-queue-card",
                    div { class: "lbl", "Local queue" }
                    div { class: "val", "{device_queue}" }
                    div { class: "delta", "writes waiting for replay" }
                }
            }

            div { class: "callout warn mb-16", "data-testid": "sync-health-banner", role: "status",
                span { class: "ico", "!" }
                div { class: "body",
                    strong { "DID resolver fallback" }
                    div { class: "mt-4",
                        code { "did:webvh:acme.example.com" }
                        " is using cached evidence. New federation writes stay paused until resolver health returns."
                    }
                    div { class: "actions",
                        Link {
                            class: "btn xs",
                            to: Route::Audit,
                            onclick: move |_| view.set(super::View::Audit),
                            "Open audit"
                        }
                        Link {
                            class: "btn xs ghost",
                            to: Route::Readiness,
                            onclick: move |_| view.set(super::View::Readiness),
                            "Readiness"
                        }
                    }
                }
            }

            div { class: "dashboard-two-col",
                div { class: "stack",
                    div { class: "surface", "data-testid": "spaces-summary",
                        div { class: "row", style: "padding: 14px 16px; border-bottom: 1px solid var(--border);",
                            strong { "Recent Spaces" }
                            Link {
                                class: "btn xs ghost",
                                to: Route::Directory,
                                onclick: move |_| view.set(super::View::Directory),
                                style: "margin-left: auto;",
                                "Browse all"
                            }
                        }
                        div { class: "stack-sm", style: "padding: 10px 14px 14px;",
                            if spaces().is_empty() {
                                Link {
                                    class: "m-list-item",
                                    "data-testid": "dashboard-space-card",
                                    to: Route::Timeline,
                                    onclick: move |_| view.set(super::View::Timeline),
                                    span { class: "avatar org", style: "background: linear-gradient(135deg,#3730a3,#6366f1);", "E" }
                                    span { class: "grow",
                                        span { class: "title", "Engineering" }
                                        span { class: "sub", "Hub Space · org-backed · independent policy" }
                                    }
                                    span { class: "pill success dot", "E2EE" }
                                }
                                Link {
                                    class: "m-list-item",
                                    "data-testid": "dashboard-space-card",
                                    to: Route::Kanban,
                                    onclick: move |_| view.set(super::View::Kanban),
                                    span { class: "avatar org", style: "background: linear-gradient(135deg,#b45309,#f59e0b);", "B" }
                                    span { class: "grow",
                                        span { class: "title", "Acme x Beta partnership" }
                                        span { class: "sub", "Controlled cross-org · closed federation · partner members" }
                                    }
                                    span { class: "pill warning xs", "HA" }
                                    span { class: "pill muted xs", "closed" }
                                }
                                Link {
                                    class: "m-list-item",
                                    "data-testid": "dashboard-space-card",
                                    to: Route::Document,
                                    onclick: move |_| view.set(super::View::Document),
                                    span { class: "avatar", style: "background: linear-gradient(135deg,#475569,#94a3b8);", "N" }
                                    span { class: "grow",
                                        span { class: "title", "My notes" }
                                        span { class: "sub", "purpose=personal · not hub-owned" }
                                    }
                                    span { class: "pill muted xs", "private" }
                                }
                            } else {
                                for space in spaces() {
                                    Link {
                                        class: "m-list-item",
                                        "data-testid": "dashboard-space-card",
                                        to: Route::TimelineSpace { space_id: space.space_id.clone() },
                                        onclick: {
                                            let id = space.space_id.clone();
                                            move |_| {
                                                selected_space.set(id.clone());
                                                view.set(super::View::Timeline);
                                            }
                                        },
                                        span { class: "avatar org", "{space.name.chars().next().unwrap_or('S')}" }
                                        span { class: "grow",
                                            span { class: "title", "{space.name}" }
                                            span { class: "sub mono", "{space.space_id}" }
                                        }
                                        span { class: "pill muted xs", "Space" }
                                    }
                                }
                            }
                        }
                    }

                    div { class: "surface", "data-testid": "recent-boards",
                        div { class: "row", style: "padding: 14px 16px; border-bottom: 1px solid var(--border);",
                            strong { "Recent Flows" }
                        }
                        table { class: "tbl compact",
                            thead {
                                tr {
                                    th { "" }
                                    th { "Title" }
                                    th { "Space" }
                                    th { "State" }
                                    th { "Updated" }
                                }
                            }
                            tbody {
                                tr {
                                    td { span { class: "pill accent xs", "FLO-247" } }
                                    td {
                                        Link {
                                            to: Route::Kanban,
                                            onclick: move |_| view.set(super::View::Kanban),
                                            "Rank rebalance in cx.flow.move reducer"
                                        }
                                    }
                                    td { "Engineering" }
                                    td { span { class: "pill warning xs", "in_review" } }
                                    td { class: "dim mono", "2m" }
                                }
                                tr {
                                    td { span { class: "pill accent xs", "EXT-12" } }
                                    td {
                                        Link {
                                            "data-testid": "recent-board-release",
                                            to: Route::Kanban,
                                            onclick: move |_| view.set(super::View::Kanban),
                                            "Beta SDK integration review"
                                        }
                                    }
                                    td { "Acme x Beta" }
                                    td { span { class: "pill warning xs", "awaiting" } }
                                    td { class: "dim mono", "3h" }
                                }
                                tr {
                                    td { span { class: "pill accent xs", "DSN-89" } }
                                    td {
                                        Link {
                                            "data-testid": "recent-board-roadmap",
                                            to: Route::Kanban,
                                            onclick: move |_| view.set(super::View::Kanban),
                                            "Dark mode token revision"
                                        }
                                    }
                                    td { "Design" }
                                    td { span { class: "pill success xs", "closed" } }
                                    td { class: "dim mono", "1h" }
                                }
                                tr {
                                    td { span { class: "pill accent xs", "TRI-19" } }
                                    td {
                                        Link {
                                            "data-testid": "recent-board-triage",
                                            to: Route::Kanban,
                                            onclick: move |_| view.set(super::View::Kanban),
                                            "Triage board stale-card sweep"
                                        }
                                    }
                                    td { "Ops" }
                                    td { span { class: "pill xs", "backlog" } }
                                    td { class: "dim mono", "1d" }
                                }
                            }
                        }
                    }

                    div { class: "surface pad", "data-testid": "activity-feed",
                        div { class: "section-title mb-8", "Recent Activity" }
                        div { class: "stack-sm",
                            div { class: "m-list-item",
                                span { class: "pill accent xs", "cx.flow.move" }
                                span { class: "grow",
                                    span { class: "title", "Legal review moved into Doing" }
                                    span { class: "sub", "Launch Board" }
                                }
                            }
                            div { class: "m-list-item",
                                span { class: "pill accent xs", "cx.message.create" }
                                span { class: "grow",
                                    span { class: "title", "Bob mentioned you in a visible discussion" }
                                    span { class: "sub", "branch=discussion" }
                                }
                            }
                        }
                    }
                }

                div { class: "stack",
                    div { class: "surface", "data-testid": "quick-actions",
                        div { class: "row", style: "padding: 14px 16px; border-bottom: 1px solid var(--border);",
                            strong { "Quick Actions" }
                        }
                        div { class: "row gap-6 wrap", style: "padding: 12px 16px;",
                            Link {
                                class: "btn sm primary",
                                to: Route::Product,
                                onclick: move |_| view.set(super::View::Product),
                                "Create Space"
                            }
                            Link {
                                class: "btn sm",
                                "data-testid": "quick-open-board",
                                to: Route::Kanban,
                                onclick: move |_| view.set(super::View::Kanban),
                                "Open Board"
                            }
                            Link {
                                class: "btn sm",
                                "data-testid": "quick-new-message",
                                to: Route::Chat,
                                onclick: move |_| view.set(super::View::Chat),
                                "Discussion"
                            }
                            Link {
                                class: "btn sm",
                                "data-testid": "quick-search",
                                to: Route::Directory,
                                onclick: move |_| view.set(super::View::Directory),
                                "Directory"
                            }
                            Link {
                                class: "btn sm",
                                "data-testid": "quick-settings",
                                to: Route::Settings,
                                onclick: move |_| view.set(super::View::Settings),
                                "Settings"
                            }
                        }
                        div { class: "settings-row",
                            div {
                                div { class: "label f-12", "Local frontier" }
                                div { class: "sub mono", "{sync_cursor}" }
                            }
                            span { class: "pill success dot", "healthy" }
                        }
                        div { class: "settings-row",
                            div {
                                div { class: "label f-12", "Repo head" }
                                div { class: "sub", "Principal Server reported" }
                            }
                            span { class: "mono f-11", "data-testid": "repo-head-card", "{repo_state}" }
                        }
                    }

                    div { class: "surface", "data-testid": "protocol-health",
                        div { class: "row", style: "padding: 14px 16px; border-bottom: 1px solid var(--border);",
                            strong { "Protocol Health" }
                            button {
                                class: "btn xs ghost",
                                "data-testid": "check-health-button",
                                style: "margin-left: auto;",
                                disabled: health_loading(),
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
                                if health_loading() { "Checking..." } else { "Run" }
                            }
                        }
                        div { style: "padding: 12px 16px;",
                            if protocol_health().is_empty() {
                                div { class: "muted f-12", "Run checks after changing the Principal Server." }
                            } else {
                                div { class: "stack-sm",
                                    for (name, status) in protocol_health() {
                                        div { class: "settings-row",
                                            div { class: "label f-12", "{name}" }
                                            span { class: "mono f-11", "{status}" }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    div { class: "surface", "data-testid": "pinned-inbox",
                        div { class: "row", style: "padding: 14px 16px; border-bottom: 1px solid var(--border);",
                            strong { "Inbox" }
                            Link {
                                class: "btn xs ghost",
                                "data-testid": "pinned-inbox-open",
                                to: Route::Notifications,
                                onclick: move |_| view.set(super::View::Notifications),
                                style: "margin-left: auto;",
                                "Open"
                            }
                        }
                        div { class: "stack-sm", style: "padding: 8px 12px 12px;",
                            div { class: "m-list-item",
                                span { class: "avatar xs", style: "background: linear-gradient(135deg,#0ea5e9,#14b8a6);", "B" }
                                span { class: "grow",
                                    span { class: "title f-13", "Ben mentioned you" }
                                    span { class: "sub", "FLO-247 rank_exhausted recovery" }
                                }
                                span { class: "dim f-11 mono", "3m" }
                            }
                            div { class: "m-list-item",
                                span { class: "pill warning xs", "approval" }
                                span { class: "grow",
                                    span { class: "title f-13", "Researcher Agent requested read_flow" }
                                    span { class: "sub mono", "approval_constraint=2_of_3_admin" }
                                }
                            }
                            div { class: "m-list-item",
                                span { class: "pill xs", "conflict" }
                                span { class: "grow",
                                    span { class: "title f-13", "Concurrent move resolved" }
                                    span { class: "sub", "Losing write remains auditable." }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
