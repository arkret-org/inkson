use dioxus::prelude::*;
use dioxus_router::Link;
use serde_json::Value;

use crate::{
    models::{SpaceHierarchyResponse, SpacePreview},
    routes::Route,
    views::helpers::authed_api,
};

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
    let hierarchy = use_signal(|| Option::<SpaceHierarchyResponse>::None);
    let hierarchy_status = use_signal(|| "Hierarchy not loaded yet.".to_owned());
    let hierarchy_loading = use_signal(|| false);
    let mut requested_space = use_signal(String::new);

    if requested_space() != selected_space {
        let sid = selected_space.clone();
        requested_space.set(sid.clone());
        refresh_space_hierarchy(
            base_url.clone(),
            token(),
            sid,
            hierarchy,
            hierarchy_status,
            hierarchy_loading,
        );
    }

    let selected_name = selected_preview
        .as_ref()
        .map(|space| space.name.clone())
        .unwrap_or_else(|| selected_space.clone());
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
    let root_id = response
        .as_ref()
        .and_then(response_root_id)
        .unwrap_or_else(|| selected_space.clone());

    rsx! {
        section {
            class: "panel right-panel",
            "data-testid": "right-panel",
            role: "complementary",
            "aria-label": "Space, sync, and device info",

            div { class: "section", "data-testid": "right-panel-space-info",
                div { class: "section-head",
                    h2 { "Space Info" }
                    StatusBadge { status: is_public, kind: Some("info".to_owned()) }
                }
                div { class: "metric",
                    strong { "Selected Space" }
                    span { "{selected_name}" }
                    div { class: "muted", "{selected_space}" }
                    if let Some(detail) = selected_detail {
                        div { class: "muted", "{detail}" }
                    }
                }
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
                        disabled: hierarchy_loading(),
                        onclick: {
                            let base = base_url.clone();
                            let sid = selected_space.clone();
                            move |_| {
                                refresh_space_hierarchy(
                                    base.clone(),
                                    token(),
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
                    "GET /api/v1/index/space-hierarchy?space_id={selected_space}&depth=2&include_unconfirmed=true"
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
                        span { "Boundary" }
                        span { "no implicit cascade" }
                    }
                    div { class: "muted",
                        "membership, capability grants, history visibility, and encryption do not implicitly cascade across parent/child Space edges."
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
    base_url: String,
    access_token: String,
    space_id: String,
    mut hierarchy: Signal<Option<SpaceHierarchyResponse>>,
    mut hierarchy_status: Signal<String>,
    mut hierarchy_loading: Signal<bool>,
) {
    hierarchy_loading.set(true);
    hierarchy_status.set("Refreshing hierarchy...".to_owned());
    spawn(async move {
        match authed_api(&base_url, access_token) {
            Ok(api) => match api
                .index_space_hierarchy_with_options(&space_id, Some(2), Some(true))
                .await
            {
                Ok(response) => {
                    let child_count = hierarchy_children(&response).len();
                    let edge_count = hierarchy_edges(&response).len();
                    hierarchy.set(Some(response));
                    hierarchy_status.set(format!(
                        "Loaded {child_count} child Space(s) and {edge_count} edge(s)."
                    ));
                }
                Err(error) => hierarchy_status.set(format!("Hierarchy refresh failed: {error}")),
            },
            Err(error) => hierarchy_status.set(format!("Invalid server URL: {error}")),
        }
        hierarchy_loading.set(false);
    });
}

fn hierarchy_children(response: &SpaceHierarchyResponse) -> Vec<HierarchyChild> {
    let root_id = response_root_id(response);
    let source = if response.children.is_empty() {
        &response.spaces
    } else {
        &response.children
    };

    source
        .iter()
        .filter(|value| {
            let id = value_string(value, &["space_id", "id", "child_space_id", "room_id"]);
            id.as_ref() != root_id.as_ref()
        })
        .enumerate()
        .map(|(index, value)| hierarchy_child_from_value(index, value))
        .collect()
}

fn hierarchy_child_from_value(index: usize, value: &Value) -> HierarchyChild {
    let summary = value.get("summary");
    let space_id = value_string(value, &["space_id", "id", "child_space_id", "room_id"])
        .or_else(|| summary.and_then(|summary| value_string(summary, &["space_id", "id"])))
        .unwrap_or_else(|| format!("child-{index}"));
    let label = value_string(value, &["name", "title", "display_name"])
        .or_else(|| summary.and_then(|summary| value_string(summary, &["name", "title"])))
        .unwrap_or_else(|| space_id.clone());
    let detail = value_string(value, &["description", "topic", "summary"])
        .or_else(|| summary.and_then(|summary| value_string(summary, &["description", "topic"])));
    let edge_state = value_string(value, &["edge_state", "state", "status"])
        .unwrap_or_else(|| "confirmed".to_owned());
    let lazy_link = value_bool(value, &["lazy_link", "lazy", "unexpanded"]).unwrap_or(false)
        || edge_state == "unconfirmed_link";
    let accessible = value_bool(value, &["accessible", "can_read"]).unwrap_or(!lazy_link);
    let cycle_detected = value_bool(value, &["cycle_detected", "cycle"]).unwrap_or(false);

    HierarchyChild {
        space_id,
        label,
        detail,
        edge_state,
        accessible,
        lazy_link,
        cycle_detected,
    }
}

fn hierarchy_edges(response: &SpaceHierarchyResponse) -> Vec<HierarchyEdge> {
    response
        .edges
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let from = value_string(
                value,
                &[
                    "parent_space_id",
                    "from_space_id",
                    "source_space_id",
                    "from",
                    "source",
                ],
            )
            .unwrap_or_else(|| {
                response_root_id(response).unwrap_or_else(|| format!("edge-{index}-from"))
            });
            let to = value_string(
                value,
                &[
                    "child_space_id",
                    "to_space_id",
                    "target_space_id",
                    "to",
                    "target",
                ],
            )
            .unwrap_or_else(|| format!("edge-{index}-to"));
            let state = value_string(value, &["edge_state", "state", "status"])
                .unwrap_or_else(|| "confirmed".to_owned());
            let lazy_link = value_bool(value, &["lazy_link", "lazy", "unexpanded"])
                .unwrap_or(false)
                || state == "unconfirmed_link";
            let cycle_detected = value_bool(value, &["cycle_detected", "cycle"]).unwrap_or(false);

            HierarchyEdge {
                from,
                to,
                state,
                lazy_link,
                cycle_detected,
            }
        })
        .collect()
}

fn response_root_id(response: &SpaceHierarchyResponse) -> Option<String> {
    response.root_space_id.clone().or_else(|| {
        if response.root.is_string() {
            response.root.as_str().map(ToOwned::to_owned)
        } else {
            value_string(&response.root, &["space_id", "id", "root_space_id"])
        }
    })
}

fn value_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        let found = value.get(*key)?;
        match found {
            Value::String(text) if !text.trim().is_empty() => Some(text.clone()),
            Value::Number(number) => Some(number.to_string()),
            Value::Bool(flag) => Some(flag.to_string()),
            _ => None,
        }
    })
}

fn value_bool(value: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter().find_map(|key| match value.get(*key)? {
        Value::Bool(flag) => Some(*flag),
        Value::String(text) => match text.as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    })
}

fn edge_badge_kind(state: &str) -> &'static str {
    match state {
        "confirmed" | "accepted" => "success",
        "rejected" | "tombstoned" => "error",
        "unconfirmed_link" => "warning",
        _ => "info",
    }
}
