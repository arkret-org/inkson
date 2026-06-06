use dioxus::prelude::*;
use dioxus_router::Link;

use crate::components::{HelpTip, UiIcon};
use crate::i18n::tr;
use crate::local_state::{ClientLocalState, LocalStateStore};
use crate::models::{RealmTreeNode, RealmTreeNodeKind, projection_realm_id_for_known_node};
use crate::routes::Route;
use crate::views::helpers::{short_protocol_id, with_authed_api};

#[derive(Clone, Debug, PartialEq)]
struct DashboardNotificationSummary {
    id: String,
    title: String,
    body: String,
    kind: String,
    timestamp: String,
    read: bool,
}

#[component]
#[allow(clippy::redundant_closure)] // `|| signal()` is not equivalent to `&signal` here.
pub fn DashboardPanel(
    base_url: String,
    token: Signal<String>,
    realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    selected_realm_id: Signal<String>,
    view: Signal<super::View>,
    state_store: Signal<LocalStateStore>,
    device_queue: usize,
    frontier_state: String,
    sync_cursor: String,
) -> Element {
    let mut protocol_health = use_signal(Vec::<(String, String)>::new);
    let mut health_loading = use_signal(|| false);
    let mut recent_flows = use_signal(Vec::<crate::api::FlowProjectionView>::new);
    let mut recent_flows_loaded_for = use_signal(String::new);
    let mut recent_flows_status = use_signal(String::new);
    let has_session = !token().trim().is_empty();
    let sync_cursor_label = short_protocol_id(&sync_cursor);
    let frontier_state_label = short_protocol_id(&frontier_state);
    let raw_realm_tree_snapshot = realm_tree_nodes();
    let pinned_realm_ids: std::collections::BTreeSet<String> = state_store
        .read()
        .realm_remarks()
        .into_iter()
        .filter_map(|(realm_id, remark)| remark.pinned.then_some(realm_id))
        .collect();
    let realm_tree_snapshot: Vec<RealmTreeNode> =
        crate::realm_tree::realm_tree_items_with_pinned_realms(
            &raw_realm_tree_snapshot,
            &pinned_realm_ids,
        )
        .into_iter()
        .map(|item| item.node)
        .collect();
    let has_realms = realm_tree_snapshot
        .iter()
        .any(|space| space.kind == RealmTreeNodeKind::Realm);
    let has_product_spaces = realm_tree_snapshot
        .iter()
        .any(|node| node.kind == RealmTreeNodeKind::Space);
    let projection_label = projection_collection_label(has_realms, has_product_spaces);
    let recent_projection_label =
        recent_projection_collection_label(has_realms, has_product_spaces);
    let projection_browse_label =
        projection_collection_browse_label(has_realms, has_product_spaces);
    let projection_signin_label =
        projection_collection_signin_label(has_realms, has_product_spaces);
    let projection_empty_label = projection_collection_empty_label(has_realms, has_product_spaces);
    let projection_empty_help_label =
        projection_collection_empty_help_label(has_realms, has_product_spaces);
    let active_node = realm_tree_snapshot
        .iter()
        .find(|node| node.id == selected_realm_id())
        .cloned()
        .or_else(|| realm_tree_snapshot.first().cloned());
    let active_projection_kind_label = active_node
        .as_ref()
        .map(|node| projection_kind_label(node.kind))
        .unwrap_or("Realm");

    let notification_summaries = {
        let snapshot = state_store.read().load();
        dashboard_notification_summaries(&snapshot)
    };
    let unread_notifications = notification_summaries
        .iter()
        .filter(|notification| !notification.read)
        .count();

    let active_node_id = active_node
        .as_ref()
        .map(|space| space.id.clone())
        .unwrap_or_else(|| selected_realm_id());
    let active_projection_realm_id =
        projection_realm_id_for_known_node(&realm_tree_snapshot, &active_node_id)
            .unwrap_or_default();
    if has_session
        && !active_node_id.trim().is_empty()
        && !active_projection_realm_id.trim().is_empty()
        && recent_flows_loaded_for() != active_node_id
    {
        recent_flows_loaded_for.set(active_node_id.clone());
        let base = base_url.clone();
        let api_token = token();
        let realm_id = active_projection_realm_id.clone();
        spawn(async move {
            match with_authed_api(&base, api_token, |api| async move {
                api.list_flow_projections(&realm_id).await
            })
            .await
            {
                Ok(response) => {
                    let flow_count = response.items.len();
                    recent_flows.set(response.items);
                    recent_flows_status.set(format!(
                        "{flow_count} flow(s) loaded from Board projection."
                    ));
                }
                Err(err) => {
                    recent_flows.set(Vec::new());
                    recent_flows_status.set(format!("Recent flows unavailable: {}", err.display()));
                }
            }
        });
    }

    let visible_recent_flows = recent_flows()
        .into_iter()
        // R11: the Flow state enum is exactly {active, archived, redacted}
        // (flow.schema.json). "Recent flows" shows only `active`; `archived`
        // and `redacted` are hidden here. There is NO `deleted` state in the
        // spec, so it is intentionally not referenced.
        .filter(|flow| flow.state != "archived" && flow.state != "redacted")
        .take(5)
        .collect::<Vec<_>>();
    let visible_notifications = notification_summaries
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>();
    rsx! {
        div { class: "timeline", "data-testid": "dashboard-panel",
            div { class: "mb-24", "data-testid": "dashboard-hero",
                h1 { style: "font-size: 22px; margin: 0; letter-spacing: 0;", {tr("nav.dashboard")} }
            }

            div { class: "metric-grid mb-24", "data-testid": "dashboard-metrics",
                Link {
                    class: "metric",
                    to: Route::Notifications,
                    onclick: move |_| view.set(super::View::Notifications),
                    div { class: "lbl", {tr("dashboard.notifications_label")} }
                    div { class: "val", "data-testid": "dashboard-unread-notifications", "{unread_notifications}" }
                    div { class: "delta", if has_session { {tr("dashboard.notifications_delta_unread")} } else { {tr("dashboard.notifications_delta_signin")} } }
                }
                Link {
                    class: "metric",
                    to: Route::Directory,
                    onclick: move |_| view.set(super::View::Directory),
                    div { class: "lbl", "{projection_label}" }
                    div { class: "val", "{realm_tree_snapshot.len()}" }
                    div { class: "delta", if has_session { "{projection_browse_label}" } else { "{projection_signin_label}" } }
                }
                if let Some(space) = active_node.as_ref() {
                    Link {
                        class: "metric",
                        to: Route::Realm { realm_id: space.id.clone() },
                        onclick: {
                            let id = space.id.clone();
                            move |_| {
                                selected_realm_id.set(id.clone());
                                view.set(super::View::Timeline);
                            }
                        },
                        div { class: "lbl", "Current {active_projection_kind_label}" }
                        div { class: "val", "{space.title}" }
                        div { class: "delta", {crate::i18n::tr("dashboard.resume_context")} }
                    }
                    Link {
                        class: "metric",
                        to: Route::KanbanRealm { realm_id: space.id.clone() },
                        onclick: {
                            let id = space.id.clone();
                            move |_| {
                                selected_realm_id.set(id.clone());
                                view.set(super::View::Kanban);
                            }
                        },
                        div { class: "lbl", "Active flows" }
                        div { class: "val", "{visible_recent_flows.len()}" }
                        div { class: "delta", "Open the current Board" }
                    }
                } else {
                    Link {
                        class: "metric",
                        to: Route::Setup,
                        onclick: move |_| view.set(super::View::Setup),
                        div { class: "lbl", "Realm Setup" }
                        div { class: "val", if has_session { "Ready" } else { "Sign in" } }
                        div { class: "delta", "Bootstrap your first Realm and initial policy" }
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
                    div { class: "surface", "data-testid": "realm-tree-summary",
                        div { class: "row surface-head",
                            strong { "{recent_projection_label}" }
                            Link {
                                class: "btn icon sm ghost ml-auto",
                                to: Route::Directory,
                                onclick: move |_| view.set(super::View::Directory),
                                title: "{projection_browse_label}",
                                "aria-label": "{projection_browse_label}",
                                UiIcon { name: "search" }
                            }
                        }
                        div { class: "stack-sm", style: "padding: 10px 14px 14px;",
                            if realm_tree_snapshot.is_empty() {
                                div {
                                    class: "m-list-item",
                                    "data-testid": "dashboard-realm-tree-empty",
                                    span { class: "avatar", "0" }
                                    span { class: "grow",
                                        span { class: "title",
                                            if has_session { "{projection_empty_label}" } else { "{projection_signin_label}" }
                                        }
                                        span { class: "sub",
                                            if has_session { "{projection_empty_help_label}" } else { {crate::i18n::tr("dashboard.no_session_help")} }
                                        }
                                    }
                                }
                            } else {
                                for node in realm_tree_snapshot.iter() {
                                    {
                                        // Spec client-preferences.md §3.7:
                                        // prefer the actor-private Realm
                                        // remark `local_name` over the public
                                        // Realm title when set.
                                        let remark = if node.kind == crate::models::RealmTreeNodeKind::Realm {
                                            state_store.read().realm_remark(&node.id)
                                        } else {
                                            None
                                        };
                                        let display_name = remark
                                            .as_ref()
                                            .map(|r| r.display_name(&node.title).to_owned())
                                            .unwrap_or_else(|| node.title.clone());
                                        let avatar_seed = display_name
                                            .chars()
                                            .next()
                                            .unwrap_or('S');
                                        let has_remark = remark
                                            .as_ref()
                                            .is_some_and(|r| !r.local_name.trim().is_empty());
                                        let kind_label = projection_kind_label(node.kind);
                                        rsx! {
                                        Link {
                                            class: "m-list-item",
                                            "data-testid": "dashboard-realm-tree-card",
                                            title: "{node.title}",
                                            to: Route::Realm { realm_id: node.id.clone() },
                                            onclick: {
                                                let id = node.id.clone();
                                                move |_| {
                                                    selected_realm_id.set(id.clone());
                                                    view.set(super::View::Timeline);
                                                }
                                            },
                                            span { class: "avatar org", "{avatar_seed}" }
                                            span { class: "grow",
                                                span { class: "title", "{display_name}" }
                                                span { class: "sub",
                                                    {node.description.as_deref().unwrap_or("Open timeline")}
                                                }
                                            }
                                            if has_remark {
                                                span {
                                                    class: "pill muted xs",
                                                    "data-testid": "dashboard-realm-tree-realm-remark-badge",
                                                    "备注"
                                                }
                                            }
                                            span { class: "pill muted xs", "{kind_label}" }
                                        }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    div { class: "surface", "data-testid": "recent-boards",
                        div { class: "row surface-head",
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
                                if visible_recent_flows.is_empty() {
                                    tr {
                                        td { class: "dim", colspan: "5",
                                            if has_session { "No recent flows loaded" } else { "Sign in to load recent flows" }
                                        }
                                    }
                                } else {
                                    for flow in visible_recent_flows.iter() {
                                        tr {
                                            key: "{flow.flow_id}",
                                            td { class: "dim", "" }
                                            td { "{flow.title}" }
                                            td { "Current Board" }
                                            td { "{flow.state}" }
                                            td {
                                                {flow.fields
                                                    .get("due_at")
                                                    .or_else(|| flow.fields.get("due"))
                                                    .and_then(|value| value.as_str())
                                                    .unwrap_or("-")}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if !recent_flows_status().is_empty() {
                            div { class: "muted", style: "padding: 0 16px 12px;", "{recent_flows_status}" }
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
                    div { class: "surface", "data-testid": "pinned-notifications",
                        div { class: "row surface-head",
                            strong { "Notifications" }
                            Link {
                                class: "btn icon sm ghost ml-auto",
                                "data-testid": "pinned-notifications-open",
                                to: Route::Notifications,
                                onclick: move |_| view.set(super::View::Notifications),
                                title: "Open notifications",
                                "aria-label": "Open notifications",
                                UiIcon { name: "inbox" }
                            }
                        }
                        div { class: "stack-sm", style: "padding: 8px 12px 12px;",
                            if visible_notifications.is_empty() {
                                div { class: "m-list-item",
                                    span { class: "avatar xs", "0" }
                                    span { class: "grow",
                                        span { class: "title f-13",
                                            {crate::i18n::tr(if has_session { "dashboard.no_notifications" } else { "dashboard.notifications_signin" })}
                                        }
                                        span { class: "sub", {crate::i18n::tr("dashboard.notifications_empty_sub")} }
                                    }
                                }
                            } else {
                                for notification in visible_notifications.iter() {
                                    Link {
                                        class: "m-list-item",
                                        "data-testid": "dashboard-notification-card",
                                        key: "{notification.id}",
                                        to: Route::Notifications,
                                        onclick: move |_| view.set(super::View::Notifications),
                                        span { class: "avatar xs", if notification.read { "✓" } else { "!" } }
                                        span { class: "grow",
                                            span { class: "title f-13", "{notification.title}" }
                                            span { class: "sub", "{notification.body}" }
                                        }
                                        span { class: "pill muted xs", "{notification.kind}" }
                                    }
                                }
                            }
                        }
                    }

                    div { class: "surface", "data-testid": "operations-surface",
                        div { class: "row surface-head",
                            strong { "Client Status" }
                            span { class: "ml-auto",
                                HelpTip { text: "Operational status stays visible, but separate tool pages are no longer promoted in the main navigation." }
                            }
                        }
                        div { class: "settings-row",
                            div {
                                div { class: "label f-12", "Sync frontier" }
                                div { class: "sub mono", title: "{sync_cursor}", "{sync_cursor_label}" }
                            }
                            span { class: if has_session { "pill success dot" } else { "pill muted xs" }, if has_session { "loaded" } else { "not connected" } }
                        }
                        div { class: "settings-row",
                            div {
                                div { class: "label f-12", "Event frontier" }
                                div { class: "sub", if has_session { "Principal Server reported" } else { "Not loaded" } }
                            }
                            span { class: "mono f-11", "data-testid": "event-frontier-card", title: "{frontier_state}", "{frontier_state_label}" }
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
                                to: Route::SettingsSection { section: "release".to_owned() },
                                onclick: move |_| view.set(super::View::Settings),
                                UiIcon { name: "settings" }
                                "Advanced Diagnostics"
                            }
                            button {
                                class: "btn icon sm ghost ml-auto",
                                "data-testid": "check-health-button",
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
                                            // Fold the four sequential checks into a
                                            // single `with_authed_api` so an Unavailable or
                                            // AuthExpired error tags every row at once
                                            // instead of silently returning an empty Vec.
                                            let result = crate::views::helpers::with_authed_api(
                                                &base,
                                                api_token,
                                                |api| async move {
                                                    let mut rows = Vec::new();
                                                    match api.health().await {
                                                        Ok(h) => rows.push(("Health".to_owned(), format!("OK ({})", h.service))),
                                                        Err(e) => rows.push(("Health".to_owned(), format!("Error: {e}"))),
                                                    }
                                                    match api.describe().await {
                                                        Ok(d) => rows.push(("Server".to_owned(), format!("{} v{}", d.service_type, d.protocol_version))),
                                                        Err(e) => rows.push(("Server".to_owned(), format!("Error: {e}"))),
                                                    }
                                                    match api.sync_describe().await {
                                                        Ok(s) => rows.push(("Sync".to_owned(), format!("{} profiles", s.supported_sync_profiles.len()))),
                                                        Err(e) => rows.push(("Sync".to_owned(), format!("Error: {e}"))),
                                                    }
                                                    match api.identity_describe().await {
                                                        Ok(i) => rows.push(("Identity".to_owned(), format!("mode={}", i.registry_mode))),
                                                        Err(e) => rows.push(("Identity".to_owned(), format!("Error: {e}"))),
                                                    }
                                                    Ok::<_, anyhow::Error>(rows)
                                                },
                                            )
                                            .await;
                                            let checks = match result {
                                                Ok(rows) => rows,
                                                Err(err) => vec![(
                                                    "API".to_owned(),
                                                    format!("Error: {}", err.display()),
                                                )],
                                            };
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

fn dashboard_notification_summaries(
    snapshot: &ClientLocalState,
) -> Vec<DashboardNotificationSummary> {
    let mut notifications = snapshot
        .notification_projection
        .iter()
        .enumerate()
        .filter_map(|(index, value)| {
            let id = value_string(value, &["notification_id", "id"])
                .unwrap_or_else(|| format!("notification-{index}"));
            let client_state = snapshot
                .notification_client_state
                .get(&id)
                .cloned()
                .unwrap_or_default();
            let archived = value
                .get("archived")
                .and_then(|v| v.as_bool())
                .unwrap_or(client_state.archived);
            if archived {
                return None;
            }
            let kind = value_string(
                value,
                &["notification_type", "notification_kind", "type", "kind"],
            )
            .unwrap_or_else(|| "message".to_owned());
            Some(DashboardNotificationSummary {
                id,
                title: value_string(value, &["title"])
                    .unwrap_or_else(|| default_notification_title(&kind)),
                body: value_string(value, &["body", "preview", "summary"])
                    .unwrap_or_else(|| "Notification".to_owned()),
                kind,
                timestamp: value_string(value, &["timestamp", "created_at"]).unwrap_or_default(),
                read: value
                    .get("read")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(client_state.read),
            })
        })
        .collect::<Vec<_>>();
    notifications.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
    notifications
}

fn value_string(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(|field| field.as_str())
            .map(ToOwned::to_owned)
    })
}

fn default_notification_title(kind: &str) -> String {
    match kind {
        "invite" => "Realm invite".to_owned(),
        "reaction" => "New reaction".to_owned(),
        "mention" => "You were mentioned".to_owned(),
        _ => "New message".to_owned(),
    }
}

fn projection_kind_label(kind: RealmTreeNodeKind) -> &'static str {
    match kind {
        RealmTreeNodeKind::Realm => "Realm",
        RealmTreeNodeKind::Space => "Space",
    }
}

fn projection_collection_label(has_realms: bool, has_product_spaces: bool) -> &'static str {
    match (has_realms, has_product_spaces) {
        (true, true) => "Realms & Spaces",
        (false, true) => "Spaces",
        _ => "Realms",
    }
}

fn recent_projection_collection_label(has_realms: bool, has_product_spaces: bool) -> &'static str {
    match (has_realms, has_product_spaces) {
        (true, true) => "Recent Realms & Spaces",
        (false, true) => "Recent Spaces",
        _ => "Recent Realms",
    }
}

fn projection_collection_browse_label(has_realms: bool, has_product_spaces: bool) -> &'static str {
    match (has_realms, has_product_spaces) {
        (true, true) => "Search or join a Realm or Space",
        (false, true) => "Search or join a Space",
        _ => "Search or join a Realm",
    }
}

fn projection_collection_signin_label(has_realms: bool, has_product_spaces: bool) -> &'static str {
    match (has_realms, has_product_spaces) {
        (true, true) => "Sign in to load realms and Spaces",
        (false, true) => "Sign in to load Spaces",
        _ => "Sign in to load realms",
    }
}

fn projection_collection_empty_label(has_realms: bool, has_product_spaces: bool) -> &'static str {
    match (has_realms, has_product_spaces) {
        (true, true) => "No realms or Spaces loaded",
        (false, true) => "No Spaces loaded",
        _ => "No realms loaded",
    }
}

fn projection_collection_empty_help_label(
    has_realms: bool,
    has_product_spaces: bool,
) -> &'static str {
    match (has_realms, has_product_spaces) {
        (true, true) => "The connected server did not return realms or Spaces yet.",
        (false, true) => "The connected server did not return Spaces yet.",
        _ => "The connected server did not return realms yet.",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        projection_collection_label, projection_kind_label, recent_projection_collection_label,
    };
    use crate::models::RealmTreeNodeKind;

    #[test]
    fn projection_labels_follow_realm_space_kind() {
        assert_eq!(projection_kind_label(RealmTreeNodeKind::Realm), "Realm");
        assert_eq!(projection_kind_label(RealmTreeNodeKind::Space), "Space");
        assert_eq!(projection_collection_label(true, false), "Realms");
        assert_eq!(
            recent_projection_collection_label(true, false),
            "Recent Realms"
        );
        assert_eq!(
            recent_projection_collection_label(true, true),
            "Recent Realms & Spaces"
        );
    }
}
