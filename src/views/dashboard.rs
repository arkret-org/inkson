use dioxus::prelude::*;
use dioxus_router::Link;

use crate::{
    components::{HelpTip, UiIcon},
    models::SpacePreview,
    routes::Route,
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
    frontier_state: String,
    sync_cursor: String,
) -> Element {
    let mut protocol_health = use_signal(Vec::<(String, String)>::new);
    let mut health_loading = use_signal(|| false);
    let has_session = !token().trim().is_empty();
    let active_space = spaces()
        .iter()
        .find(|space| space.space_id == selected_space())
        .cloned()
        .or_else(|| spaces().first().cloned());
    rsx! {
        div { class: "timeline", "data-testid": "dashboard-panel",
            div { class: "spread mb-24", "data-testid": "dashboard-hero",
                div {
                    h1 { style: "font-size: 22px; margin: 0 0 4px; letter-spacing: 0;",
                        if has_session { "Continue work" } else { "No active session" }
                    }
                    div { class: "muted f-12",
                        if has_session { "Pick a Space, clear inbox, or browse the directory. Diagnostics stay below in a separate operations surface." } else { "Connect a Principal Server, then sign in to load spaces, inbox, and collaboration views." }
                    }
                }
                div { class: "row gap-6 wrap",
                    Link {
                        class: "btn sm primary",
                        "data-testid": "quick-open-inbox",
                        to: Route::Notifications,
                        onclick: move |_| view.set(super::View::Notifications),
                        UiIcon { name: "inbox" }
                        "Open Inbox"
                    }
                    Link {
                        class: "btn sm",
                        "data-testid": "quick-browse-directory",
                        to: Route::Directory,
                        onclick: move |_| view.set(super::View::Directory),
                        UiIcon { name: "search" }
                        "Browse Directory"
                    }
                    Link {
                        class: "btn sm ghost",
                        "data-testid": "quick-workspace-setup",
                        to: Route::Setup,
                        onclick: move |_| view.set(super::View::Setup),
                        UiIcon { name: "plus" }
                        "Workspace Setup"
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
                    div { class: "delta", if has_session { "Unread and approvals" } else { "Sign in required" } }
                }
                Link {
                    class: "metric",
                    to: Route::Directory,
                    onclick: move |_| view.set(super::View::Directory),
                    div { class: "lbl", "Spaces" }
                    div { class: "val", "{spaces().len()}" }
                    div { class: "delta", if has_session { "Browse or join a Space" } else { "Sign in to load spaces" } }
                }
                if let Some(space) = active_space.as_ref() {
                    Link {
                        class: "metric",
                        to: Route::Space { space_id: space.space_id.clone() },
                        onclick: {
                            let id = space.space_id.clone();
                            move |_| {
                                selected_space.set(id.clone());
                                view.set(super::View::Timeline);
                            }
                        },
                        div { class: "lbl", "Current Space" }
                        div { class: "val", "{space.name}" }
                        div { class: "delta", "Resume in the current context" }
                    }
                    Link {
                        class: "metric",
                        to: Route::Space { space_id: space.space_id.clone() },
                        onclick: {
                            let id = space.space_id.clone();
                            move |_| {
                                selected_space.set(id.clone());
                                view.set(super::View::Timeline);
                            }
                        },
                        div { class: "lbl", "Continue" }
                        div { class: "val mono", style: "font-size: 14px;", "{space.space_id}" }
                        div { class: "delta", "Open the last active Space view" }
                    }
                } else {
                    Link {
                        class: "metric",
                        to: Route::Setup,
                        onclick: move |_| view.set(super::View::Setup),
                        div { class: "lbl", "Workspace Setup" }
                        div { class: "val", if has_session { "Ready" } else { "Sign in" } }
                        div { class: "delta", "Bootstrap your first Space and initial policy" }
                    }
                    Link {
                        class: "metric",
                        to: Route::Onboarding,
                        onclick: move |_| view.set(super::View::Onboarding),
                        div { class: "lbl", "Onboarding" }
                        div { class: "val", "4 steps" }
                        div { class: "delta", "Identity, device, and recovery setup" }
                    }
                }
            }

            div { class: "dashboard-two-col",
                div { class: "stack",
                    div { class: "surface", "data-testid": "spaces-summary",
                        div { class: "row", style: "padding: 14px 16px; border-bottom: 1px solid var(--border);",
                            strong { "Recent Spaces" }
                            Link {
                                class: "btn icon sm ghost",
                                to: Route::Directory,
                                onclick: move |_| view.set(super::View::Directory),
                                style: "margin-left: auto;",
                                title: "Browse spaces",
                                "aria-label": "Browse spaces",
                                UiIcon { name: "search" }
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
                                        to: Route::Space { space_id: space.space_id.clone() },
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
                    div { class: "surface", "data-testid": "pinned-inbox",
                        div { class: "row", style: "padding: 14px 16px; border-bottom: 1px solid var(--border);",
                            strong { "Needs Attention" }
                            Link {
                                class: "btn icon sm ghost",
                                "data-testid": "pinned-inbox-open",
                                to: Route::Notifications,
                                onclick: move |_| view.set(super::View::Notifications),
                                style: "margin-left: auto;",
                                title: "Open inbox",
                                "aria-label": "Open inbox",
                                UiIcon { name: "inbox" }
                            }
                        }
                        div { class: "stack-sm", style: "padding: 8px 12px 12px;",
                            div { class: "m-list-item",
                                span { class: "avatar xs", "0" }
                                span { class: "grow",
                                    span { class: "title f-13", if has_session { "No inbox items loaded" } else { "Sign in to load inbox" } }
                                    span { class: "sub", "Unread, approvals, and notifications appear here" }
                                }
                            }
                        }
                    }

                    div { class: "surface", "data-testid": "operations-surface",
                        div { class: "row", style: "padding: 14px 16px; border-bottom: 1px solid var(--border);",
                            strong { "Operations & Diagnostics" }
                            span { style: "margin-left: auto;",
                                HelpTip { text: "Operational status stays separate from collaboration entry points. Use this surface for sync, device, and release diagnostics." }
                            }
                        }
                        div { class: "settings-row",
                            div {
                                div { class: "label f-12", "Sync frontier" }
                                div { class: "sub mono", "{sync_cursor}" }
                            }
                            span { class: if has_session { "pill success dot" } else { "pill muted xs" }, if has_session { "loaded" } else { "not connected" } }
                        }
                        div { class: "settings-row",
                            div {
                                div { class: "label f-12", "Event frontier" }
                                div { class: "sub", if has_session { "Principal Server reported" } else { "Not loaded" } }
                            }
                            span { class: "mono f-11", "data-testid": "event-frontier-card", "{frontier_state}" }
                        }
                        div { class: "settings-row",
                            div {
                                div { class: "label f-12", "Queued writes" }
                                div { class: "sub", "local replay queue" }
                            }
                            span { class: "mono f-11", "{device_queue}" }
                        }
                        div { class: "actions", style: "padding: 12px 16px 0;",
                            Link {
                                class: "secondary",
                                to: Route::Devices,
                                onclick: move |_| view.set(super::View::Devices),
                                UiIcon { name: "monitor" }
                                "Devices"
                            }
                            Link {
                                class: "secondary",
                                to: Route::Readiness,
                                onclick: move |_| view.set(super::View::Readiness),
                                UiIcon { name: "check" }
                                "Readiness"
                            }
                            Link {
                                class: "secondary",
                                to: Route::Audit,
                                onclick: move |_| view.set(super::View::Audit),
                                UiIcon { name: "activity" }
                                "Audit"
                            }
                            button {
                                class: "btn icon sm ghost",
                                "data-testid": "check-health-button",
                                style: "margin-left: auto;",
                                title: if health_loading() { "Checking health" } else { "Run health checks" },
                                "aria-label": if health_loading() { "Checking health" } else { "Run health checks" },
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
                                UiIcon { name: "refresh" }
                            }
                        }
                        div { style: "padding: 12px 16px;",
                            if protocol_health().is_empty() {
                                div { class: "muted f-12", "Run checks after changing the Principal Server. Collaboration starts in Spaces; operational checks stay here." }
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
                }
            }
        }
    }
}
