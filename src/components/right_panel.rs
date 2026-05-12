use dioxus::prelude::*;
use dioxus_router::Link;

use crate::{models::SpacePreview, routes::Route};

use super::{Metric, StatusBadge};

#[derive(Clone, Debug, PartialEq)]
struct HierarchyChild {
    space_id: String,
    label: String,
    detail: Option<String>,
    edge_state: String,
    accessible: bool,
    lazy_link: bool,
    cycle_detected: bool,
}

#[derive(Clone, Debug, PartialEq)]
struct HierarchyEdge {
    from: String,
    to: String,
    state: String,
    lazy_link: bool,
    cycle_detected: bool,
}

#[derive(Clone, Debug, PartialEq)]
struct HierarchySnapshot {
    root_space_id: String,
    children: Vec<HierarchyChild>,
    edges: Vec<HierarchyEdge>,
    cycle_detected: bool,
}

#[component]
pub fn RightPanel(
    base_url: String,
    token: Signal<String>,
    selected_space: String,
    selected_preview: Option<SpacePreview>,
    spaces_count: usize,
    device_queue: usize,
    repo_state: String,
    push_state: String,
    account_did: String,
    device_id: String,
    crypto_state: String,
) -> Element {
    let _ = (&base_url, &token);
    let hierarchy = use_signal(|| Option::<HierarchySnapshot>::None);
    let hierarchy_status = use_signal(|| "Hierarchy not loaded yet.".to_owned());
    let hierarchy_loading = use_signal(|| false);
    let mut requested_space = use_signal(String::new);

    if !selected_space.trim().is_empty() && requested_space() != selected_space {
        let sid = selected_space.clone();
        requested_space.set(sid.clone());
        refresh_space_hierarchy(sid, hierarchy, hierarchy_status, hierarchy_loading);
    }

    let selected_name = selected_preview
        .as_ref()
        .map(|space| space.name.clone())
        .unwrap_or_else(|| {
            if selected_space.trim().is_empty() {
                "No space selected".to_owned()
            } else {
                selected_space.clone()
            }
        });
    let selected_detail = selected_preview.as_ref().and_then(|space| {
        space.description.clone().or_else(|| {
            space
                .category
                .as_ref()
                .map(|category| format!("Category: {category}"))
        })
    });
    let is_public = selected_preview
        .as_ref()
        .map(|space| {
            if space.public {
                "public".to_owned()
            } else {
                "restricted".to_owned()
            }
        })
        .unwrap_or_else(|| "unknown".to_owned());

    let response = hierarchy();
    let children = response
        .as_ref()
        .map(hierarchy_children)
        .unwrap_or_default();
    let edges = response.as_ref().map(hierarchy_edges).unwrap_or_default();
    let lazy_count = children.iter().filter(|child| child.lazy_link).count()
        + edges.iter().filter(|edge| edge.lazy_link).count();
    let cycle_detected = response
        .as_ref()
        .map(|response| {
            response.cycle_detected
                || children.iter().any(|child| child.cycle_detected)
                || edges.iter().any(|edge| edge.cycle_detected)
        })
        .unwrap_or(false);
    let root_id = response.as_ref().map(response_root_id).unwrap_or_else(|| {
        if selected_space.trim().is_empty() {
            "No space selected".to_owned()
        } else {
            selected_space.clone()
        }
    });

    rsx! {
        section {
            class: "panel right-panel",
            "data-testid": "right-panel",
            role: "complementary",
            "aria-label": "Space, sync, and device info",

            div { class: "section", "data-testid": "right-panel-space-info",
                div { class: "section-head",
                    h2 { "Space Boundary" }
                    StatusBadge { status: is_public, kind: Some("info".to_owned()) }
                }
                div { class: "metric",
                    strong { "Selected Space" }
                    span { "{selected_name}" }
                    if !selected_space.trim().is_empty() {
                        div { class: "muted", "{selected_space}" }
                    }
                    if let Some(detail) = selected_detail {
                        div { class: "muted", "{detail}" }
                    }
                }
                if !selected_space.trim().is_empty() {
                    nav {
                        class: "quick-nav",
                        "aria-label": "Space quick links",
                        Link {
                            class: "secondary quick-nav__item",
                            "data-testid": "right-panel-space-info-link",
                            to: Route::TimelineSpace { space_id: selected_space.clone() },
                            "Space Info"
                        }
                        Link {
                            class: "secondary quick-nav__item",
                            "data-testid": "right-panel-members-link",
                            to: Route::SpaceAdmin { space_id: selected_space.clone() },
                            "Members"
                        }
                        Link {
                            class: "secondary quick-nav__item",
                            "data-testid": "right-panel-files-link",
                            to: Route::DocumentSpace { space_id: selected_space.clone() },
                            "Files"
                        }
                        Link {
                            class: "secondary quick-nav__item",
                            "data-testid": "right-panel-pinned-link",
                            to: Route::TimelineSpace { space_id: selected_space.clone() },
                            "Pinned"
                        }
                        Link {
                            class: "secondary quick-nav__item",
                            "data-testid": "right-panel-notifications-link",
                            to: Route::Notifications,
                            "Notifications"
                        }
                    }
                }
            }

            div { class: "section", "data-testid": "right-panel-sync-section",
                h2 { "Sync" }
                div { class: "metric-grid", "data-testid": "sync-metrics",
                    Metric { label: "Spaces", value: spaces_count.to_string() }
                    Metric { label: "Device Queue", value: device_queue.to_string() }
                    Metric { label: "Repo", value: repo_state }
                    Metric { label: "Push", value: push_state }
                }
            }

            div { class: "section", "data-testid": "right-panel-hierarchy",
                div { class: "section-head",
                    h2 { "Hierarchy" }
                    button {
                        class: "secondary compact-button",
                        "data-testid": "right-panel-refresh-hierarchy",
                        disabled: hierarchy_loading() || selected_space.trim().is_empty(),
                        onclick: {
                            let sid = selected_space.clone();
                            move |_| {
                                refresh_space_hierarchy(
                                    sid.clone(),
                                    hierarchy,
                                    hierarchy_status,
                                    hierarchy_loading,
                                );
                            }
                        },
                        if hierarchy_loading() { "Refreshing" } else { "Refresh hierarchy" }
                    }
                }
                div { class: "muted", "data-testid": "hierarchy-query-shape",
                    "Navigation/discoverability only; hierarchy API is not part of the current protocol."
                }
                div { class: "muted", "data-testid": "hierarchy-status", role: "status", "aria-live": "polite",
                    "{hierarchy_status}"
                }
                div { class: "metric-grid", "data-testid": "hierarchy-metrics",
                    Metric { label: "Root", value: root_id }
                    Metric { label: "Children", value: children.len().to_string() }
                    Metric { label: "Edges", value: edges.len().to_string() }
                    Metric { label: "Lazy/Cycle", value: format!("{lazy_count} / {}", if cycle_detected { "yes" } else { "no" }) }
                }
                if cycle_detected {
                    div { class: "event error-banner", "data-testid": "hierarchy-cycle",
                        div { class: "event-head",
                            span { "Cycle" }
                            span { "truncated" }
                        }
                        div { class: "muted",
                            "The index reported a cycle; hierarchy traversal is displayed as a truncated graph view."
                        }
                    }
                }
                div {
                    class: "event hierarchy-boundary-note",
                    "data-testid": "hierarchy-no-cascade-note",
                    div { class: "event-head",
                        span { "Independent boundary" }
                        span { "no cascade" }
                    }
                    div { class: "muted",
                        "membership, capability grants, history visibility, and encryption stay per Space."
                    }
                }

                if children.is_empty() {
                    div { class: "muted", "data-testid": "space-hierarchy-children-empty",
                        "No hierarchy children returned for this Space."
                    }
                } else {
                    div { class: "hierarchy-list", "data-testid": "space-hierarchy-children",
                        for child in children.iter() {
                            div {
                                class: "hierarchy-row",
                                "data-testid": "space-hierarchy-child",
                                div { class: "hierarchy-row__main",
                                    strong { "{child.label}" }
                                    span { class: "muted", "{child.space_id}" }
                                    if let Some(detail) = &child.detail {
                                        span { class: "muted", "{detail}" }
                                    }
                                }
                                div { class: "hierarchy-row__badges",
                                    StatusBadge { status: child.edge_state.clone(), kind: Some(edge_badge_kind(&child.edge_state).to_owned()) }
                                    if !child.accessible {
                                        StatusBadge { status: "not accessible".to_owned(), kind: Some("warning".to_owned()) }
                                    }
                                    if child.lazy_link {
                                        span { class: "badge badge-warning", "data-testid": "hierarchy-lazy-link", "lazy link" }
                                    }
                                    if child.cycle_detected {
                                        span { class: "badge badge-error", "data-testid": "hierarchy-cycle", "cycle" }
                                    }
                                }
                            }
                        }
                    }
                }

                if !edges.is_empty() {
                    div { class: "hierarchy-list", "data-testid": "space-hierarchy-edges",
                        for edge in edges.iter() {
                            div {
                                class: "hierarchy-row hierarchy-row--edge",
                                "data-testid": "space-hierarchy-edge",
                                div { class: "hierarchy-row__main",
                                    strong { "{edge.from} -> {edge.to}" }
                                    span { class: "muted", "edge state: {edge.state}" }
                                }
                                div { class: "hierarchy-row__badges",
                                    StatusBadge { status: edge.state.clone(), kind: Some(edge_badge_kind(&edge.state).to_owned()) }
                                    if edge.lazy_link {
                                        span { class: "badge badge-warning", "data-testid": "hierarchy-edge-lazy-link", "lazy link" }
                                    }
                                    if edge.cycle_detected {
                                        span { class: "badge badge-error", "data-testid": "hierarchy-edge-cycle", "cycle" }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            div { class: "section", "data-testid": "right-panel-device-section",
                h2 { "Device" }
                div { class: "metric",
                    strong { "Account" }
                    span { "{account_did}" }
                }
                div { class: "metric",
                    strong { "Device ID" }
                    span { "{device_id}" }
                }
                div { class: "metric",
                    strong { "Crypto" }
                    span { "{crypto_state}" }
                }
            }
        }
    }
}

fn refresh_space_hierarchy(
    space_id: String,
    mut hierarchy: Signal<Option<HierarchySnapshot>>,
    mut hierarchy_status: Signal<String>,
    mut hierarchy_loading: Signal<bool>,
) {
    hierarchy_loading.set(true);
    hierarchy_status.set("Refreshing hierarchy...".to_owned());
    hierarchy.set(Some(HierarchySnapshot {
        root_space_id: space_id,
        children: Vec::new(),
        edges: Vec::new(),
        cycle_detected: false,
    }));
    hierarchy_status.set("Loaded selected Space boundary.".to_owned());
    hierarchy_loading.set(false);
}

fn hierarchy_children(response: &HierarchySnapshot) -> Vec<HierarchyChild> {
    response.children.clone()
}

fn hierarchy_edges(response: &HierarchySnapshot) -> Vec<HierarchyEdge> {
    response.edges.clone()
}

fn response_root_id(response: &HierarchySnapshot) -> String {
    response.root_space_id.clone()
}

fn edge_badge_kind(state: &str) -> &'static str {
    match state {
        "confirmed" | "accepted" => "success",
        "rejected" | "tombstoned" => "error",
        "unconfirmed_link" => "warning",
        _ => "info",
    }
}
