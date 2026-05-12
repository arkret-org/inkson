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
    let has_session = !token().trim().is_empty();
    let sync_delta = if has_session {
        format!("online · {device_queue} pending")
    } else {
        "offline · 0 pending".to_owned()
    };

    rsx! {
        div { class: "timeline", "data-testid": "dashboard-panel",
            div { class: "spread mb-24", "data-testid": "dashboard-hero",
                div {
                    h1 { style: "font-size: 22px; margin: 0 0 4px; letter-spacing: -0.01em;",
                        if has_session { "Workspace" } else { "No active session" }
                    }
                    div { class: "muted f-12",
                        if has_session { "Server-backed workspace data is shown below." } else { "Connect a Principal Server, then sign in to load spaces, inbox, devices, and flows." }
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
                    div { class: "val", "0" }
                    div { class: "delta", if has_session { "No loaded notifications" } else { "Sign in required" } }
                }
                Link {
                    class: "metric",
                    to: Route::Audit,
                    onclick: move |_| view.set(super::View::Audit),
                    div { class: "lbl", "Sync frontier" }
                    div { class: "val mono", style: "font-size: 14px;", "{sync_cursor}" }
                    div { class: "delta", "{sync_delta}" }
                }
                Link {
                    class: "metric",
                    to: Route::Devices,
                    onclick: move |_| view.set(super::View::Devices),
                    div { class: "lbl", "Devices" }
                    div { class: "val", if has_session { "1" } else { "0" } }
                    div { class: "delta", if has_session { "Current session device" } else { "No authenticated devices" } }
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
                    strong { if has_session { "Server data" } else { "Session required" } }
                    div { class: "mt-4",
                        if has_session {
                            "Use protocol health checks to verify this Principal Server before write-heavy workflows."
                        } else {
                            "No organization, space, or device data is shown until the server auth flow returns a real session."
                        }
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
                                div {
                                    class: "m-list-item",
                                    "data-testid": "dashboard-spaces-empty",
                                    span { class: "avatar", "0" }
                                    span { class: "grow",
                                        span { class: "title", if has_session { "No spaces loaded" } else { "Sign in to load spaces" } }
                                        span { class: "sub", if has_session { "The connected server did not return spaces yet." } else { "The client is not showing placeholder spaces." } }
                                    }
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
                                    td { class: "dim", colspan: "5",
                                        if has_session { "No recent flows loaded" } else { "Sign in to load recent flows" }
                                    }
                                }
                            }
                        }
                    }

                    div { class: "surface pad", "data-testid": "activity-feed",
                        div { class: "section-title mb-8", "Recent Activity" }
                        div { class: "stack-sm",
                            div { class: "m-list-item",
                                span { class: "pill muted xs", "empty" }
                                span { class: "grow",
                                    span { class: "title", if has_session { "No activity loaded" } else { "No session activity" } }
                                    span { class: "sub", if has_session { "Sync has not returned recent events." } else { "Activity appears after authenticated sync." } }
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
                            span { class: if has_session { "pill success dot" } else { "pill muted xs" }, if has_session { "loaded" } else { "not connected" } }
                        }
                        div { class: "settings-row",
                            div {
                                div { class: "label f-12", "Repo head" }
                                div { class: "sub", if has_session { "Principal Server reported" } else { "Not loaded" } }
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
                                span { class: "avatar xs", "0" }
                                span { class: "grow",
                                    span { class: "title f-13", if has_session { "No inbox items loaded" } else { "Sign in to load inbox" } }
                                    span { class: "sub", "Server-backed notifications only" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
