use arkret_sdk::contact_operations::ContactScope;
use dioxus::prelude::*;
use dioxus_router::Link;

use crate::components::{HelpTip, UiIcon};
use crate::i18n::tr;
use crate::models::{RealmTreeNode, RealmTreeNodeKind, projection_realm_id_for_known_node};
use crate::routes::Route;
use crate::state::ClientLocalState;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::views::helpers::short_protocol_id;

#[derive(Clone, Debug, PartialEq)]
struct DashboardNotificationSummary {
    id: String,
    title: String,
    title_is_key: bool,
    body: String,
    body_translation: Option<(&'static str, Vec<(&'static str, String)>)>,
    kind: String,
    timestamp: String,
    read: bool,
}

impl DashboardNotificationSummary {
    fn render_title(&self) -> String {
        if self.title_is_key {
            tr(&self.title)
        } else {
            self.title.clone()
        }
    }

    fn render_body(&self) -> String {
        match &self.body_translation {
            Some((key, args)) => crate::i18n::tr_args(key, args),
            None => self.body.clone(),
        }
    }
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

fn projection_object_state_label(state: &arkret_sdk::ObjectState) -> &'static str {
    match state {
        arkret_sdk::ObjectState::Active => "active",
        arkret_sdk::ObjectState::Archived => "archived",
        arkret_sdk::ObjectState::Redacted => "redacted",
    }
}

#[component]
#[allow(clippy::redundant_closure)] // `|| signal()` is not equivalent to `&signal` here.
pub fn DashboardPanel(
    token: Signal<String>,
    realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    selected_realm_id: Signal<String>,
    view: Signal<super::AppView>,
    device_queue: usize,
    frontier_state: String,
    sync_cursor: String,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let state_store = crate::app::SessionContext::get().state_store;
    let mut protocol_health = use_signal(Vec::<(String, String)>::new);
    let mut health_loading = use_signal(|| false);
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

    let local_state_snapshot = state_store.read().load();
    let notification_summaries = dashboard_notification_summaries(&local_state_snapshot);
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
                match crate::transport::auth::with_endpoint_clients(
                    &base,
                    api_token,
                    None,
                    |clients| async move { clients.account().contacts().await },
                )
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
    // The sync-backed operation log is already the authorized source for the
    // event-sourced Board projection. Reusing it here avoids a second
    // visibility-sensitive request for a potentially stale selected Realm.
    let visible_recent_strands = dashboard_recent_strands(
        &local_state_snapshot.raw_operations,
        &active_projection_realm_id,
    )
    .into_iter()
    // R11: the Strand state enum is exactly {active, archived, redacted}
    // (strand.schema.json). "Recent strands" shows only `active`; `archived`
    // and `redacted` are hidden here. There is NO `deleted` state in the
    // spec, so it is intentionally not referenced.
    .filter(|strand| strand.state == arkret_sdk::ObjectState::Active)
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
            div { class: "metric-grid", "data-testid": "dashboard-metrics",
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
                                        let has_remark = remark
                                            .as_ref()
                                            .is_some_and(|r| !r.local_name.trim().is_empty());
                                        let snapshot_status = if node.kind == crate::models::RealmTreeNodeKind::Realm {
                                            state_store.read().realm_state_snapshot_sync_status(&node.id)
                                        } else {
                                            None
                                        };
                                        let snapshot_badge = snapshot_status.as_ref().and_then(|status| {
                                            match status.trust_state {
                                                crate::realm_state_snapshot::RealmStateSnapshotTrustState::LowerTrust => Some("lower-trust"),
                                                crate::realm_state_snapshot::RealmStateSnapshotTrustState::Degraded => Some("degraded"),
                                                crate::realm_state_snapshot::RealmStateSnapshotTrustState::Verified => None,
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
                                            crate::components::IdentityAvatar {
                                                seed: node.id.clone(),
                                                alt_text: display_name.clone(),
                                                class: "avatar avatar-img".to_owned(),
                                            }
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
                                            td { "{projection_object_state_label(&strand.state)}" }
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
                            strong { {tr("nav.notifications")} }
                            Link {
                                class: "btn icon sm ghost ml-auto",
                                "data-testid": "pinned-notifications-open",
                                to: Route::Notifications,
                                onclick: move |_| view.set(super::AppView::Notifications),
                                title: tr("dashboard.notifications_open"),
                                "aria-label": tr("dashboard.notifications_open"),
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
                                        "data-notification-id": "{notification.id}",
                                        "data-kind": "{notification.kind}",
                                        key: "{notification.id}",
                                        to: Route::Notifications,
                                        onclick: move |_| view.set(super::AppView::Notifications),
                                        span { class: "avatar xs", if notification.read { "✓" } else { "!" } }
                                        span { class: "grow",
                                            span { class: "title f-13", "data-testid": "dashboard-notification-title", {notification.render_title()} }
                                            span { class: "sub", "data-testid": "dashboard-notification-body", {notification.render_body()} }
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
                                div { class: "sub", if has_session { "Station reported" } else { "Not loaded" } }
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
                                to: Route::SettingsSection {
                                    section: "release".to_owned(),
                                    filter: String::new(),
                                },
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
                                            let result = crate::transport::auth::with_authed_api(
                                                &base,
                                                api_token,
                                                |api| async move {
                                                    let mut rows = Vec::new();
                                                    match api.describe().await {
                                                        Ok(d) => rows.push(("Describe".to_owned(), format!("{} v{}", d.service_kind, d.protocol_version))),
                                                        Err(e) => rows.push(("Describe".to_owned(), format!("Error: {e}"))),
                                                    }
                                                    match async { crate::transport::account::sync_describe(&api.sdk_http_client()?).await }.await {
                                                        Ok(s) => rows.push(("Sync".to_owned(), format!("{} profiles", s.supported_profiles.len()))),
                                                        Err(e) => rows.push(("Sync".to_owned(), format!("Error: {e}"))),
                                                    }
                                                    match async { crate::transport::account::identity_describe(&api.sdk_http_client()?).await }.await {
                                                        Ok(i) => rows.push(("Identity".to_owned(), format!("{} v{}", i.service_kind, i.protocol_version))),
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
                                div { class: "muted f-12", "Run checks after changing the Station. Collaboration starts in Spaces; operational checks stay here." }
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
        .filter_map(|value| {
            let id = value.notification_id();
            let client_state = snapshot
                .notification_client_state
                .get(&id)
                .cloned()
                .unwrap_or_default();
            let archived = client_state.archived;
            if archived {
                return None;
            }
            let kind = crate::state::projection::notifications::notification_kind_wire(
                &value.notification_kind(),
            )
            .to_owned();
            // Keep presentation provenance until rendering. Locale changes must not
            // translate literal previews that happen to match dictionary keys.
            let title = notification_title(value, &kind);
            let title_is_key = notification_title_is_key(value);
            let body = notification_body(value);
            let body_translation = notification_body_translation(value);
            Some(DashboardNotificationSummary {
                id,
                title,
                title_is_key,
                body,
                body_translation,
                kind,
                timestamp: arkret_sdk::canonical::format_timestamp_canonical(value.created_at()),
                read: client_state.read,
            })
        })
        .collect::<Vec<_>>();
    notifications.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
    notifications
}

fn dashboard_recent_strands(
    raw_operations: &[crate::state::RawOperationRecord],
    realm_id: &str,
) -> Vec<crate::state::projection_views::StrandProjectionView> {
    if realm_id.trim().is_empty() {
        return Vec::new();
    }
    crate::views::kanban::strand_views_from_ops(raw_operations)
        .into_iter()
        .filter(|strand| strand.realm_id == realm_id)
        .collect()
}

fn dashboard_contacts_summary(
    contacts: &[crate::models::ContactListRow],
) -> DashboardContactsSummary {
    let mut summary = DashboardContactsSummary::default();
    for contact in contacts {
        match contact.state {
            arkret_sdk::ContactState::Accepted => {
                summary.accepted += 1;
                if contact.direct_conversation.is_some()
                    || contact
                        .bidirectional_scopes
                        .contains(&ContactScope::DirectMessage)
                    || contact
                        .effective_scopes
                        .iter()
                        .flatten()
                        .any(|scope| *scope == ContactScope::DirectMessage)
                {
                    summary.direct_ready += 1;
                }
            }
            arkret_sdk::ContactState::PendingIncoming => summary.pending_incoming += 1,
            arkret_sdk::ContactState::PendingOutgoing => summary.pending_outgoing += 1,
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

// Shared with the notifications model; this dashboard does not hydrate or
// apply the feed's separate delivery filters.
use crate::views::notifications::{
    notification_body, notification_body_translation, notification_title, notification_title_is_key,
};

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
    use arkret_sdk::contact_operations::ContactScope;
    use serde_json::json;

    use super::{
        contact_summary_delta, dashboard_contacts_summary, dashboard_recent_strands,
        projection_collection_label, projection_kind_label, recent_projection_collection_label,
    };
    use crate::models::{ContactListRow, RealmTreeNodeKind};
    use crate::state::RawOperationRecord;

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
        fn contact(
            peer: &str,
            state: arkret_sdk::ContactState,
            direct_ready: bool,
        ) -> ContactListRow {
            ContactListRow {
                peer: arkret_sdk::contact_operations::ContactPeer::Human {
                    account_id: arkret_sdk::AccountId::new(
                        crate::mls_api_helpers::principal_core_id(peer).unwrap(),
                        arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                    ),
                },
                state,
                request_event_ref: None,
                request_message: None,
                response_event_ref: None,
                tombstone_event_ref: None,
                next_prepare_input: (state == arkret_sdk::ContactState::Accepted).then(|| {
                    arkret_sdk::contact_operations::ContactNextPrepareInput {
                        contact_round_id: arkret_sdk::Hash::new(
                            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        )
                        .unwrap(),
                        version: 2,
                        predecessor_event_ref: arkret_sdk::EventId::new(
                            "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                        )
                        .unwrap(),
                    }
                }),
                granted_to_peer_scopes: Vec::new(),
                granted_by_peer_scopes: Vec::new(),
                bidirectional_scopes: Vec::new(),
                effective_scopes: Some(Vec::new()),
                continuity_evidence: None,
                direct_conversation: direct_ready.then(|| arkret_sdk::DirectConversationSummary {
                    realm_id: arkret_sdk::RealmId::new(
                        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
                    )
                    .unwrap(),
                    main_strand_id: arkret_sdk::StrandId::new(
                        "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1".to_owned(),
                    )
                    .unwrap(),
                    binding_event_ref: arkret_sdk::EventId::new(
                        "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                    )
                    .unwrap(),
                    state: arkret_sdk::DirectConversationSummaryState::Found,
                }),
                contact_agent_projections: Vec::new(),
                peer_endpoint: None,
            }
        }

        let rows = vec![
            {
                let mut row = contact(
                    "did:web:alice.example",
                    arkret_sdk::ContactState::Accepted,
                    false,
                );
                row.bidirectional_scopes = vec![ContactScope::DirectMessage];
                row
            },
            contact(
                "did:web:bob.example",
                arkret_sdk::ContactState::Accepted,
                true,
            ),
            contact(
                "did:web:casey.example",
                arkret_sdk::ContactState::PendingIncoming,
                false,
            ),
            contact(
                "did:web:drew.example",
                arkret_sdk::ContactState::Tombstoned,
                false,
            ),
        ];

        let summary = dashboard_contacts_summary(&rows);

        assert_eq!(summary.accepted, 2);
        assert_eq!(summary.pending(), 1);
        assert_eq!(summary.direct_ready, 2);
        assert_eq!(contact_summary_delta(&summary), "Pending 1 · Direct 2");
    }

    #[test]
    fn recent_strands_use_only_sync_backed_operations_for_active_realm() {
        // Sync-backed record shape: the ingest funnel keys the record by the
        // ACCEPTED Event id, and the Strand is `retype(event_id)` — a create
        // payload names no object id of its own.
        let operation = |event_id: &str, realm_id: &str| RawOperationRecord {
            operation_id: event_id.to_owned(),
            realm_id: Some(realm_id.to_owned()),
            received_at: chrono::DateTime::parse_from_rfc3339("2026-07-13T00:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            payload: json!({
                "kind": "ak.strand.create",
                "operation_id": event_id,
                "realm_id": realm_id,
                "write_state": "synced",
                "body": {
                    "object": {
                        "realm_id": realm_id,
                        "metadata": { "title": event_id }
                    }
                }
            }),
        };
        let realm_a = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let realm_b = "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
        let operations = vec![
            operation(
                "ak:event:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934",
                realm_a,
            ),
            operation(
                "ak:event:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu",
                realm_b,
            ),
        ];

        let strands = dashboard_recent_strands(&operations, realm_a);

        assert_eq!(strands.len(), 1);
        assert_eq!(strands[0].realm_id, realm_a);
    }

    #[test]
    fn dashboard_notification_previews_keep_literal_keys_and_defaults_follow_locale() {
        use dioxus::prelude::*;

        use super::dashboard_notification_summaries;
        use crate::state::projection::notifications::test_event_notification;
        use crate::state::{ClientLocalState, NotificationClientState};

        let realm = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
        let event = |ordinal, preview| {
            test_event_notification(
                ordinal,
                arkret_sdk::NotificationKind::Message,
                realm,
                None,
                preview,
            )
        };
        let defaults = event(901, json!({}));
        let literal = event(
            902,
            json!({
                "title": "notifications.default_title.message",
                "body": "Original {realm} {error} / 原文"
            }),
        );
        let literal_body_key = event(
            903,
            json!({"title": "Original {title}", "summary": "notifications.default_body"}),
        );
        let explicit_empty = event(904, json!({"title": "", "body": ""}));
        let archived = event(905, json!({"title": "Archived literal preview"}));
        let mut snapshot = ClientLocalState::default();
        snapshot.notification_client_state.insert(
            literal.notification_id(),
            NotificationClientState {
                read: true,
                archived: false,
            },
        );
        snapshot.notification_client_state.insert(
            archived.notification_id(),
            NotificationClientState {
                read: false,
                archived: true,
            },
        );
        snapshot.notification_projection = vec![
            defaults.clone(),
            literal.clone(),
            literal_body_key.clone(),
            explicit_empty.clone(),
            archived,
        ];
        let rows = dashboard_notification_summaries(&snapshot);
        assert_eq!(
            rows.iter().map(|row| row.id.clone()).collect::<Vec<_>>(),
            vec![
                explicit_empty.notification_id(),
                literal_body_key.notification_id(),
                literal.notification_id(),
                defaults.notification_id(),
            ]
        );
        let by_id = |id: &str| rows.iter().find(|row| row.id == id).unwrap();
        assert!(by_id(&literal.notification_id()).read);
        let original_snapshot = snapshot.clone();
        let mut dom = VirtualDom::new(|| rsx! {});
        dom.rebuild_in_place();
        dom.in_scope(ScopeId::ROOT, || {
            let mut locale = provide_context(crate::i18n::init_i18n_with_locale(
                crate::i18n::UiLocale::En,
            ));
            for (language, title, body) in [
                (crate::i18n::UiLocale::En, "New message", "Notification"),
                (crate::i18n::UiLocale::Zh, "新消息", "通知"),
                (crate::i18n::UiLocale::En, "New message", "Notification"),
            ] {
                crate::i18n::set_locale(&mut locale, language);
                assert_eq!(by_id(&defaults.notification_id()).render_title(), title);
                assert_eq!(by_id(&defaults.notification_id()).render_body(), body);
                assert_eq!(
                    by_id(&literal.notification_id()).render_title(),
                    "notifications.default_title.message"
                );
                assert_eq!(
                    by_id(&literal.notification_id()).render_body(),
                    "Original {realm} {error} / 原文"
                );
                assert_eq!(
                    by_id(&literal_body_key.notification_id()).render_title(),
                    "Original {title}"
                );
                assert_eq!(
                    by_id(&literal_body_key.notification_id()).render_body(),
                    "notifications.default_body"
                );
                assert_eq!(by_id(&explicit_empty.notification_id()).render_title(), "");
                assert_eq!(by_id(&explicit_empty.notification_id()).render_body(), "");
                assert_eq!(dashboard_notification_summaries(&snapshot), rows);
                assert_eq!(
                    snapshot.notification_projection,
                    original_snapshot.notification_projection
                );
                assert_eq!(
                    snapshot.notification_client_state,
                    original_snapshot.notification_client_state
                );
            }
        });
    }

    #[test]
    fn dashboard_invite_and_runtime_approval_copy_retranslates_retained_summaries() {
        use dioxus::prelude::*;

        use super::dashboard_notification_summaries;
        use crate::state::projection::notifications::{
            raw_notifications_from_sources, test_invite,
        };
        use crate::state::{ClientLocalState, StoredInviteNotification, StoredNotification};

        let realm = "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
        let invite = test_invite(1, realm);
        let delta = arkret_sdk::sync::NotificationDelta::try_new(
            arkret_sdk::NotificationIdentity::AgentApproval(
                arkret_sdk::NotificationId::new(
                    "ak:notification:01964137-0000-7000-8000-000000000004",
                )
                .unwrap(),
            ),
            arkret_sdk::sync::NotificationDeltaAction::Upsert,
            Some(arkret_sdk::sync::NotificationData::AgentRuntimeApproval(
                arkret_sdk::sync::AgentRuntimeApprovalNotificationData {
                    approval_request_id: arkret_sdk::sync::AgentRuntimeApprovalRequestId::new(
                        "agent_runtime_approval:01964137-0000-7000-8000-000000000005",
                    )
                    .unwrap(),
                    agent_id: crate::mls_api_helpers::principal_core_id("did:web:agent.example")
                        .unwrap(),
                    requested_at: chrono::DateTime::parse_from_rfc3339("2026-05-29T00:00:00.000Z")
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                    expires_at: chrono::DateTime::parse_from_rfc3339("2026-05-29T00:10:00.000Z")
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                },
            )),
        )
        .unwrap();
        let mut snapshot = ClientLocalState::default();
        snapshot.notification_projection = raw_notifications_from_sources(Some(&[delta]), &[]);
        snapshot
            .notification_projection
            .push(StoredNotification::Invite {
                invite: StoredInviteNotification {
                    invite_id: invite.id,
                    realm_id: invite.realm_id,
                    created_at: invite.created_at,
                },
            });
        let rows = dashboard_notification_summaries(&snapshot);
        assert_eq!(rows.len(), 2);
        let invitation = rows.iter().find(|row| row.kind == "invite").unwrap();
        let approval = rows
            .iter()
            .find(|row| row.id.starts_with("ak:notification:"))
            .unwrap();
        let short_realm = crate::views::helpers::short_protocol_id(realm);
        let mut dom = VirtualDom::new(|| rsx! {});
        dom.rebuild_in_place();
        dom.in_scope(ScopeId::ROOT, || {
            let mut locale = provide_context(crate::i18n::init_i18n_with_locale(
                crate::i18n::UiLocale::En,
            ));
            for (language, invite_title, approval_title, approval_body) in [
                (
                    crate::i18n::UiLocale::En,
                    "Realm invite",
                    "Agent runtime approval",
                    "Review the pending Agent runtime key request.",
                ),
                (
                    crate::i18n::UiLocale::Zh,
                    "Realm 邀请",
                    "Agent 运行授权审批",
                    "审查待处理的 Agent 运行密钥请求。",
                ),
                (
                    crate::i18n::UiLocale::En,
                    "Realm invite",
                    "Agent runtime approval",
                    "Review the pending Agent runtime key request.",
                ),
            ] {
                crate::i18n::set_locale(&mut locale, language);
                assert_eq!(invitation.render_title(), invite_title);
                let invite_body = match language {
                    crate::i18n::UiLocale::En => format!("You were invited to join {short_realm}."),
                    crate::i18n::UiLocale::Zh => format!("你收到了加入 {short_realm} 的邀请。"),
                };
                assert_eq!(invitation.render_body(), invite_body);
                assert_eq!(approval.render_title(), approval_title);
                assert_eq!(approval.render_body(), approval_body);
                assert_eq!(dashboard_notification_summaries(&snapshot), rows);
            }
        });
    }
}
