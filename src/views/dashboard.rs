use dioxus::prelude::*;
use dioxus_router::Link;

use crate::components::{HelpTip, UiIcon};
use crate::i18n::tr;
use crate::local_state::{ClientLocalState, LocalStateStore};
use crate::models::{RealmTreeNode, RealmTreeNodeKind, projection_realm_id_for_known_node};
use crate::routes::Route;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
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

#[derive(Clone, Debug, Default, PartialEq)]
struct DashboardContactsSummary {
    accepted: usize,
    pending_incoming: usize,
    pending_outgoing: usize,
    direct_ready: usize,
}

impl DashboardContactsSummary {
    fn pending(&self) -> usize {
        self.pending_incoming + self.pending_outgoing
    }
}

#[component]
#[allow(clippy::redundant_closure)] // `|| signal()` is not equivalent to `&signal` here.
pub fn DashboardPanel(
    base_url: String,
    token: Signal<String>,
    realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    selected_realm_id: Signal<String>,
    view: Signal<super::AppView>,
    state_store: Signal<LocalStateStore>,
    device_queue: usize,
    frontier_state: String,
    sync_cursor: String,
) -> Element {
    let mut protocol_health = use_signal(Vec::<(String, String)>::new);
    let mut health_loading = use_signal(|| false);
    let mut recent_strands = use_signal(Vec::<crate::api::StrandProjectionView>::new);
    let mut recent_strands_loaded_for = use_signal(String::new);
    let mut recent_strands_status = use_signal(String::new);
    let mut contacts_summary = use_signal(Option::<DashboardContactsSummary>::default);
    let mut contacts_loaded_for = use_signal(String::new);
    let mut contacts_status = use_signal(String::new);
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
    // Label helpers return i18n keys; translate once here.
    let projection_label =
        crate::i18n::tr(projection_collection_label(has_realms, has_product_spaces));
    let recent_projection_label = crate::i18n::tr(recent_projection_collection_label(
        has_realms,
        has_product_spaces,
    ));
    let projection_browse_label = crate::i18n::tr(projection_collection_browse_label(
        has_realms,
        has_product_spaces,
    ));
    let projection_signin_label = crate::i18n::tr(projection_collection_signin_label(
        has_realms,
        has_product_spaces,
    ));
    let projection_empty_label = crate::i18n::tr(projection_collection_empty_label(
        has_realms,
        has_product_spaces,
    ));
    let projection_empty_help_label = crate::i18n::tr(projection_collection_empty_help_label(
        has_realms,
        has_product_spaces,
    ));
    let active_node = realm_tree_snapshot
        .iter()
        .find(|node| node.id == selected_realm_id())
        .cloned()
        .or_else(|| realm_tree_snapshot.first().cloned());

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
    if has_session {
        let api_token = token();
        let contacts_load_key = format!("{}|{}", base_url, api_token);
        if contacts_loaded_for() != contacts_load_key {
            contacts_loaded_for.set(contacts_load_key);
            contacts_summary.set(None);
            contacts_status.set("Loading contacts".to_owned());
            let base = base_url.clone();
            spawn(async move {
                match with_authed_api(&base, api_token, |api| async move { api.contacts().await })
                    .await
                {
                    Ok(response) => {
                        contacts_summary.set(Some(dashboard_contacts_summary(&response.contacts)));
                        contacts_status.set(String::new());
                    }
                    Err(_) => {
                        contacts_summary.set(None);
                        contacts_status.set("Contacts unavailable".to_owned());
                    }
                }
            });
        }
    } else if !contacts_loaded_for().is_empty()
        || contacts_summary().is_some()
        || !contacts_status().is_empty()
    {
        contacts_loaded_for.set(String::new());
        contacts_summary.set(None);
        contacts_status.set(String::new());
    }
    if has_session
        && !active_node_id.trim().is_empty()
        && !active_projection_realm_id.trim().is_empty()
        && recent_strands_loaded_for() != active_node_id
    {
        recent_strands_loaded_for.set(active_node_id.clone());
        let base = base_url.clone();
        let api_token = token();
        let realm_id = active_projection_realm_id.clone();
        spawn(async move {
            match with_authed_api(&base, api_token, |api| async move {
                api.list_strand_projections(&realm_id).await
            })
            .await
            {
                Ok(response) => {
                    let strand_count = response.items.len();
                    recent_strands.set(response.items);
                    recent_strands_status.set(format!(
                        "{strand_count} strand(s) loaded from Board projection."
                    ));
                }
                Err(err) => {
                    recent_strands.set(Vec::new());
                    recent_strands_status
                        .set(format!("Recent strands unavailable: {}", err.display()));
                }
            }
        });
    }

    let visible_recent_strands = recent_strands()
        .into_iter()
        // R11: the Strand state enum is exactly {active, archived, redacted}
        // (strand.schema.json). "Recent strands" shows only `active`; `archived`
        // and `redacted` are hidden here. There is NO `deleted` state in the
        // spec, so it is intentionally not referenced.
        .filter(|strand| strand.state != "archived" && strand.state != "redacted")
        .take(5)
        .collect::<Vec<_>>();
    let visible_notifications = notification_summaries
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>();
    let contacts_summary_snapshot = contacts_summary();
    let contacts_metric_value = contacts_summary_snapshot
        .as_ref()
        .map(|summary| summary.accepted.to_string())
        .unwrap_or_else(|| {
            if has_session && contacts_status() == "Loading contacts" {
                "...".to_owned()
            } else {
                "0".to_owned()
            }
        });
    let contacts_metric_delta = if !has_session {
        tr("contacts.sign_in")
    } else if let Some(summary) = contacts_summary_snapshot.as_ref() {
        contact_summary_delta(summary)
    } else if contacts_status().is_empty() {
        tr("contacts.empty")
    } else {
        contacts_status()
    };
    rsx! {
        div { class: "timeline", "data-testid": "dashboard-panel",
            div { class: "mb-24", "data-testid": "dashboard-hero",
                h1 { style: "font-size: 22px; margin: 0; letter-spacing: 0;", {tr("nav.dashboard")} }
            }

            div { class: "metric-grid mb-24", "data-testid": "dashboard-metrics",
                Link {
                    class: "metric",
                    to: Route::Notifications,
                    onclick: move |_| view.set(super::AppView::Notifications),
                    div { class: "lbl", {tr("dashboard.notifications_label")} }
                    div { class: "val", "data-testid": "dashboard-unread-notifications", "{unread_notifications}" }
                    div { class: "delta", if has_session { {tr("dashboard.notifications_delta_unread")} } else { {tr("dashboard.notifications_delta_signin")} } }
                }
                Link {
                    class: "metric",
                    to: Route::Directory,
                    onclick: move |_| view.set(super::AppView::Directory),
                    div { class: "lbl", "{projection_label}" }
                    div { class: "val", "{realm_tree_snapshot.len()}" }
                    div { class: "delta", if has_session { "{projection_browse_label}" } else { "{projection_signin_label}" } }
                }
                Link {
                    class: "metric",
                    "data-testid": "dashboard-contacts-card",
                    to: Route::Contacts,
                    onclick: move |_| view.set(super::AppView::Contacts),
                    div { class: "lbl", {tr("nav.contacts")} }
                    div { class: "val", "data-testid": "dashboard-contacts-count", "{contacts_metric_value}" }
                    div { class: "delta", "{contacts_metric_delta}" }
                }
                if let Some(space) = active_node.as_ref() {
                    Link {
                        class: "metric",
                        to: Route::KanbanRealm { realm_id: space.id.clone() },
                        onclick: {
                            let id = space.id.clone();
                            move |_| {
                                selected_realm_id.set(id.clone());
                                view.set(super::AppView::Kanban);
                            }
                        },
                        div { class: "lbl", "Active strands" }
                        div { class: "val", "{visible_recent_strands.len()}" }
                        div { class: "delta", "Open Board view" }
                    }
                } else {
                    Link {
                        class: "metric",
                        to: Route::Setup,
                        onclick: move |_| view.set(super::AppView::Setup),
                        div { class: "lbl", "Realm Setup" }
                        div { class: "val", if has_session { "Ready" } else { "Sign in" } }
                        div { class: "delta", "Bootstrap your first Realm and initial policy" }
                    }
                    Link {
                        class: "metric",
                        to: Route::Onboarding,
                        onclick: move |_| view.set(super::AppView::Onboarding),
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
                                onclick: move |_| view.set(super::AppView::Directory),
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
                                        let snapshot_status = if node.kind == crate::models::RealmTreeNodeKind::Realm {
                                            state_store.read().snapshot_sync_status(&node.id)
                                        } else {
                                            None
                                        };
                                        let snapshot_badge = snapshot_status.as_ref().and_then(|status| {
                                            match status.trust_state {
                                                crate::snapshot::SnapshotTrustState::LowerTrust => Some("lower-trust"),
                                                crate::snapshot::SnapshotTrustState::Degraded => Some("degraded"),
                                                crate::snapshot::SnapshotTrustState::Verified => None,
                                            }
                                        });
                                        let kind_label =
                                            crate::i18n::tr(projection_kind_label(node.kind));
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
                                                    view.set(super::AppView::Kanban);
                                                }
                                            },
                                            span { class: "avatar org", "{avatar_seed}" }
                                            span { class: "grow",
                                                span { class: "title", "{display_name}" }
                                                span { class: "sub",
                                                    {node.description.as_deref().unwrap_or("Open Board")}
                                                }
                                            }
                                            if has_remark {
                                                span {
                                                    class: "pill muted xs",
                                                    "data-testid": "dashboard-realm-tree-realm-remark-badge",
                                                    "备注"
                                                }
                                            }
                                            if let Some(snapshot_badge) = snapshot_badge {
                                                span {
                                                    class: "pill muted xs",
                                                    "data-testid": "dashboard-realm-tree-snapshot-badge",
                                                    "{snapshot_badge}"
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
                            strong { "Recent Strands" }
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
                                if visible_recent_strands.is_empty() {
                                    tr {
                                        td { class: "dim", colspan: "5",
                                            if has_session { "No recent strands loaded" } else { "Sign in to load recent strands" }
                                        }
                                    }
                                } else {
                                    for strand in visible_recent_strands.iter() {
                                        tr {
                                            key: "{strand.strand_id}",
                                            td { class: "dim", "" }
                                            td { "{strand.title}" }
                                            td { "Current Board" }
                                            td { "{strand.state}" }
                                            td {
                                                {strand.fields
                                                    .get("due_at")
                                                    .or_else(|| strand.fields.get("due"))
                                                    .and_then(|value| value.as_str())
                                                    .unwrap_or("-")}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if !recent_strands_status().is_empty() {
                            div { class: "muted", style: "padding: 0 16px 12px;", "{recent_strands_status}" }
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
                                onclick: move |_| view.set(super::AppView::Notifications),
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
                                        onclick: move |_| view.set(super::AppView::Notifications),
                                        span { class: "avatar xs", if notification.read { "✓" } else { "!" } }
                                        span { class: "grow",
                                            // `title` may be a server-provided string or an i18n
                                            // default-title key — `tr()` translates keys and
                                            // passes unknown strings through unchanged.
                                            span { class: "title f-13", {crate::i18n::tr(&notification.title)} }
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
                                onclick: move |_| view.set(super::AppView::Settings),
                                UiIcon { name: "settings" }
                                "Advanced Diagnostics"
                            }
                            Button {
                                variant: ButtonVariant::Ghost,
                                size: ButtonSize::Icon,
                                class: "btn sm ml-auto",
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
                                                    match api.describe().await {
                                                        Ok(d) => rows.push(("Describe".to_owned(), format!("{} v{}", d.service_type, d.protocol_version))),
                                                        Err(e) => rows.push(("Describe".to_owned(), format!("Error: {e}"))),
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
                    .unwrap_or_else(|| default_notification_title(&kind).to_owned()),
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

fn dashboard_contacts_summary(
    contacts: &[crate::models::ContactListRow],
) -> DashboardContactsSummary {
    let mut summary = DashboardContactsSummary::default();
    for contact in contacts {
        match contact.state.as_str() {
            "accepted" => {
                summary.accepted += 1;
                if contact.direct_conversation.is_some()
                    || contact
                        .bidirectional_scopes
                        .iter()
                        .any(|scope| scope == "direct_message")
                    || contact
                        .effective_scopes
                        .iter()
                        .any(|scope| scope == "direct_message")
                {
                    summary.direct_ready += 1;
                }
            }
            "pending_incoming" => summary.pending_incoming += 1,
            "pending_outgoing" | "pending" => summary.pending_outgoing += 1,
            _ => {}
        }
    }
    summary
}

fn contact_summary_delta(summary: &DashboardContactsSummary) -> String {
    format!(
        "Pending {} · Direct {}",
        summary.pending(),
        summary.direct_ready
    )
}

// Shared with the notifications model (single source, YGN-DRY-05):
use crate::views::notifications::{default_notification_title, value_string};

// The projection label helpers below return i18n KEYS; render sites pass
// them through `tr()` (model helpers stay runtime-free so unit tests can
// assert the key table without a Dioxus runtime).

fn projection_kind_label(kind: RealmTreeNodeKind) -> &'static str {
    match kind {
        RealmTreeNodeKind::Realm => "dashboard.node_kind.realm",
        RealmTreeNodeKind::Space => "dashboard.node_kind.space",
    }
}

fn projection_collection_label(has_realms: bool, has_product_spaces: bool) -> &'static str {
    match (has_realms, has_product_spaces) {
        (true, true) => "dashboard.collection.realms_and_spaces",
        (false, true) => "dashboard.collection.spaces",
        _ => "dashboard.collection.realms",
    }
}

fn recent_projection_collection_label(has_realms: bool, has_product_spaces: bool) -> &'static str {
    match (has_realms, has_product_spaces) {
        (true, true) => "dashboard.collection.recent_realms_and_spaces",
        (false, true) => "dashboard.collection.recent_spaces",
        _ => "dashboard.collection.recent_realms",
    }
}

fn projection_collection_browse_label(has_realms: bool, has_product_spaces: bool) -> &'static str {
    match (has_realms, has_product_spaces) {
        (true, true) => "dashboard.collection.browse_realm_or_space",
        (false, true) => "dashboard.collection.browse_space",
        _ => "dashboard.collection.browse_realm",
    }
}

fn projection_collection_signin_label(has_realms: bool, has_product_spaces: bool) -> &'static str {
    match (has_realms, has_product_spaces) {
        (true, true) => "dashboard.collection.signin_realms_and_spaces",
        (false, true) => "dashboard.collection.signin_spaces",
        _ => "dashboard.collection.signin_realms",
    }
}

fn projection_collection_empty_label(has_realms: bool, has_product_spaces: bool) -> &'static str {
    match (has_realms, has_product_spaces) {
        (true, true) => "dashboard.collection.empty_realms_and_spaces",
        (false, true) => "dashboard.collection.empty_spaces",
        _ => "dashboard.collection.empty_realms",
    }
}

fn projection_collection_empty_help_label(
    has_realms: bool,
    has_product_spaces: bool,
) -> &'static str {
    match (has_realms, has_product_spaces) {
        (true, true) => "dashboard.collection.empty_help_realms_and_spaces",
        (false, true) => "dashboard.collection.empty_help_spaces",
        _ => "dashboard.collection.empty_help_realms",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        contact_summary_delta, dashboard_contacts_summary, projection_collection_label,
        projection_kind_label, recent_projection_collection_label,
    };
    use crate::models::{ContactListRow, DirectConversationSummary, RealmTreeNodeKind};

    #[test]
    fn projection_labels_follow_realm_space_kind() {
        // The helpers return i18n keys (translated at render via tr()).
        assert_eq!(
            projection_kind_label(RealmTreeNodeKind::Realm),
            "dashboard.node_kind.realm"
        );
        assert_eq!(
            projection_kind_label(RealmTreeNodeKind::Space),
            "dashboard.node_kind.space"
        );
        assert_eq!(
            projection_collection_label(true, false),
            "dashboard.collection.realms"
        );
        assert_eq!(
            recent_projection_collection_label(true, false),
            "dashboard.collection.recent_realms"
        );
        assert_eq!(
            recent_projection_collection_label(true, true),
            "dashboard.collection.recent_realms_and_spaces"
        );
    }

    #[test]
    fn contact_summary_counts_actionable_rows() {
        let rows = vec![
            ContactListRow {
                peer: "did:example:alice".to_owned(),
                state: "accepted".to_owned(),
                bidirectional_scopes: vec!["direct_message".to_owned()],
                ..Default::default()
            },
            ContactListRow {
                peer: "did:example:bob".to_owned(),
                state: "accepted".to_owned(),
                direct_conversation: Some(DirectConversationSummary::default()),
                ..Default::default()
            },
            ContactListRow {
                peer: "did:example:casey".to_owned(),
                state: "pending_incoming".to_owned(),
                ..Default::default()
            },
            ContactListRow {
                peer: "did:example:drew".to_owned(),
                state: "blocked".to_owned(),
                ..Default::default()
            },
        ];

        let summary = dashboard_contacts_summary(&rows);

        assert_eq!(summary.accepted, 2);
        assert_eq!(summary.pending(), 1);
        assert_eq!(summary.direct_ready, 2);
        assert_eq!(contact_summary_delta(&summary), "Pending 1 · Direct 2");
    }
}
