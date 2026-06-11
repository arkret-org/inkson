use std::collections::{BTreeMap, BTreeSet};

use cokret_sdk::push_rule_core::{
    EventContext as PushRuleEventContext, ShouldNotify, evaluate_watch_level,
    reason_code as push_rule_reason_code,
};
use dioxus::prelude::*;
use serde_json::{Value, json};

use crate::components::{EmptyState, EmptyStateKind, UiIcon};
use crate::local_state::{ClientLocalState, LocalSealView, LocalStateStore};
use crate::models::ClientSyncOutcome;
use crate::notification_rules::{
    DndSettings, NotificationEvalContext, PushRulesConfig, WatchLevel,
    dnd_settings_from_account_data, evaluate_notification, push_rules_from_account_data,
};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::views::helpers::{short_protocol_id, with_authed_api};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NotificationGroup {
    Latest,
    ByRealm,
    ByType,
}

#[derive(Clone, Debug, PartialEq)]
enum NotificationAction {
    AcceptInvite {
        realm_id: String,
        invite_id: String,
        realm_label: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq)]
struct Notification {
    id: String,
    source_event_id: Option<String>,
    title: String,
    body: String,
    realm_id: String,
    flow_id: Option<String>,
    realm_label: Option<String>,
    kind: String,
    read: bool,
    archived: bool,
    timestamp: String,
    action_label: Option<String>,
    action: Option<NotificationAction>,
    /// T4.4 — User-facing hint surfaced when the watch level
    /// suppressed delivery (e.g. "You're not getting notifications
    /// for this discussion — change watch level"). `None` for
    /// notifications that pass the watch-level filter normally.
    watch_hint: Option<String>,
}

#[component]
pub fn NotificationsPanel(
    base_url: String,
    account_did: String,
    device_id: String,
    token: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let initial_state = state_store.read().load();
    let initial_notifications = hydrate_notifications(
        initial_state.notification_projection.clone(),
        &initial_state,
        None,
        None,
    );

    let mut notifications = use_signal(move || initial_notifications.clone());
    let mut group_by = use_signal(|| NotificationGroup::Latest);
    let mut show_archived = use_signal(|| false);
    let mut did_bootstrap = use_signal(|| false);
    let mut status_msg = use_signal(String::new);

    if !did_bootstrap() {
        did_bootstrap.set(true);
        refresh_notifications(
            base_url.clone(),
            token(),
            state_store,
            notifications,
            status_msg,
        );
    }

    let local_state = state_store.read().load();
    let mut visible_notifications = notifications()
        .into_iter()
        .filter(|notification| {
            (show_archived() || !notification.archived)
                && notification_kind_enabled(&local_state, &notification.kind)
                && (!realm_is_muted(&local_state, &notification.realm_id)
                    || notification_overrides_realm_mute(notification))
        })
        .collect::<Vec<_>>();

    match group_by() {
        NotificationGroup::Latest => {
            visible_notifications.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
        }
        NotificationGroup::ByRealm => {
            visible_notifications.sort_by(|left, right| {
                left.realm_id
                    .cmp(&right.realm_id)
                    .then_with(|| right.timestamp.cmp(&left.timestamp))
            });
        }
        NotificationGroup::ByType => {
            visible_notifications.sort_by(|left, right| {
                left.kind
                    .cmp(&right.kind)
                    .then_with(|| right.timestamp.cmp(&left.timestamp))
            });
        }
    }

    let total_notifications = notifications().len();

    // F-NOTIF-VLIST-1: client-side paging — start by rendering only the
    // first 50 notifications and let the user expand the window via the
    // "Load more" button at the foot of the list. A user with 1000+
    // notifications no longer pays the full DOM cost on every render,
    // and the "0/N" badge below makes it obvious how much more is
    // available. Real virtualization (windowed rows) is a follow-up.
    let mut visible_limit = use_signal(|| 50usize);
    let visible_total = visible_notifications.len();
    let visible_window: usize = visible_total.min(visible_limit());
    let visible_notifications: Vec<_> = visible_notifications
        .into_iter()
        .take(visible_window)
        .collect();
    let has_more_to_load = visible_total > visible_window;
    let status_text = status_msg();

    rsx! {
        div { class: "timeline notifications-panel", "data-testid": "notifications-panel", role: "region", "aria-label": "Notifications",
            div { class: "toolbar-row",
                div { class: "segmented-control", role: "tablist", "aria-label": "Notification grouping",
                    Button {
                        variant: ButtonVariant::Secondary,
                        class: if group_by() == NotificationGroup::Latest { "segment active" } else { "segment" },
                        onclick: move |_| group_by.set(NotificationGroup::Latest),
                        {crate::i18n::tr("notifications.view.latest")}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        class: if group_by() == NotificationGroup::ByRealm { "segment active" } else { "segment" },
                        onclick: move |_| group_by.set(NotificationGroup::ByRealm),
                        {crate::i18n::tr("notifications.view.realm")}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        class: if group_by() == NotificationGroup::ByType { "segment active" } else { "segment" },
                        onclick: move |_| group_by.set(NotificationGroup::ByType),
                        {crate::i18n::tr("notifications.view.type")}
                    }
                }
                div { class: "icon-actions",
                    Button {
                        variant: ButtonVariant::Ghost,
                        size: ButtonSize::Sm,
                        class: "btn icon",
                        "data-testid": "mark-all-read-button",
                        title: crate::i18n::tr("notifications.tooltip.mark_all_read"),
                        "aria-label": crate::i18n::tr("notifications.tooltip.mark_all_read"),
                        onclick: {
                            let base_url = base_url.clone();
                            let account_did = account_did.clone();
                            let device_id = device_id.clone();
                            move |_| {
                                mark_all_notifications_read(
                                    base_url.clone(),
                                    token(),
                                    account_did.clone(),
                                    device_id.clone(),
                                    state_store,
                                    notifications,
                                    status_msg,
                                );
                            }
                        },
                        UiIcon { name: "check" }
                    }
                    Button {
                        variant: ButtonVariant::Ghost,
                        size: ButtonSize::Sm,
                        class: "btn icon",
                        "data-testid": "toggle-archived",
                        title: if show_archived() { crate::i18n::tr("notifications.tooltip.hide_archived") } else { crate::i18n::tr("notifications.tooltip.show_archived") },
                        "aria-label": if show_archived() { crate::i18n::tr("notifications.tooltip.hide_archived") } else { crate::i18n::tr("notifications.tooltip.show_archived") },
                        onclick: move |_| show_archived.set(!show_archived()),
                        UiIcon { name: "archive" }
                    }
                    Button {
                        variant: ButtonVariant::Ghost,
                        size: ButtonSize::Sm,
                        class: "btn icon",
                        "data-testid": "refresh-notifications",
                        title: crate::i18n::tr("notifications.tooltip.refresh"),
                        "aria-label": crate::i18n::tr("notifications.tooltip.refresh"),
                        onclick: {
                            let base_url = base_url.clone();
                            move |_| {
                                refresh_notifications(
                                    base_url.clone(),
                                    token(),
                                    state_store,
                                    notifications,
                                    status_msg,
                                );
                            }
                        },
                        UiIcon { name: "refresh" }
                    }
                }
            }
            if !status_text.is_empty() {
                div {
                    class: "muted notifications-status",
                    "data-testid": "notifications-status",
                    role: "status",
                    "aria-live": "polite",
                    "{status_text}"
                }
            }

            for notification in visible_notifications.iter() {
                div {
                    class: "event",
                    "data-testid": "notification-item",
                    key: "{notification.id}",
                    style: if notification.read { "opacity: 0.6;" } else { "" },
                    div { class: "event-head",
                        span { "{notification.title}" }
                        span { "{notification.kind} / {notification.timestamp}" }
                    }
                    div {
                        class: if notification.read { "muted" } else { "entity-title" },
                        "{notification.body}"
                    }
                    if let Some(ref hint) = notification.watch_hint {
                        div {
                            class: "muted",
                            "data-testid": "notification-watch-hint",
                            "{hint}"
                        }
                    }
                    if !notification.realm_id.is_empty() {
                        {
                            let scope_kind = notification_scope_kind(notification);
                            let realm_label = notification
                                .realm_label
                                .as_deref()
                                .filter(|label| !label.trim().is_empty())
                                .map(ToOwned::to_owned)
                                .unwrap_or_else(|| short_protocol_id(&notification.realm_id));
                            rsx! {
                                div {
                                    class: "muted",
                                    title: "{notification.realm_id}",
                                    "{scope_kind}: {realm_label}"
                                }
                            }
                        }
                    }
                    div { class: "actions",
                        if !notification.read {
                            Button {
                                variant: ButtonVariant::Ghost,
                                size: ButtonSize::Sm,
                                class: "btn icon",
                                "data-testid": "mark-read-button",
                                title: "Mark read",
                                "aria-label": "Mark read",
                                onclick: {
                                    let notification_id = notification.id.clone();
                                    move |_| {
                                        if let Some(entry) = notifications.write().iter_mut().find(|candidate| candidate.id == notification_id) {
                                            entry.read = true;
                                        }
                                        state_store.write().set_notification_read(notification_id.clone(), true);
                                    }
                                },
                                UiIcon { name: "check" }
                            }
                        } else {
                            Button {
                                variant: ButtonVariant::Ghost,
                                size: ButtonSize::Sm,
                                class: "btn icon",
                                "data-testid": "mark-unread-button",
                                title: "Mark unread",
                                "aria-label": "Mark unread",
                                onclick: {
                                    let notification_id = notification.id.clone();
                                    move |_| {
                                        if let Some(entry) = notifications.write().iter_mut().find(|candidate| candidate.id == notification_id) {
                                            entry.read = false;
                                        }
                                        state_store.write().set_notification_read(notification_id.clone(), false);
                                    }
                                },
                                UiIcon { name: "bell" }
                            }
                        }
                        if !notification.archived {
                            Button {
                                variant: ButtonVariant::Ghost,
                                size: ButtonSize::Sm,
                                class: "btn icon",
                                "data-testid": "archive-button",
                                title: "Archive",
                                "aria-label": "Archive",
                                onclick: {
                                    let notification_id = notification.id.clone();
                                    move |_| {
                                        if let Some(entry) = notifications.write().iter_mut().find(|candidate| candidate.id == notification_id) {
                                            entry.archived = true;
                                        }
                                        state_store.write().set_notification_archived(notification_id.clone(), true);
                                    }
                                },
                                UiIcon { name: "archive" }
                            }
                        }
                        if !notification.realm_id.is_empty() {
                            Button {
                                variant: ButtonVariant::Ghost,
                                size: ButtonSize::Sm,
                                class: "btn icon",
                                "data-testid": "mute-realm-button",
                                title: "Mute this realm",
                                "aria-label": "Mute this realm",
                                onclick: {
                                    let realm_id = notification.realm_id.clone();
                                    move |_| {
                                        state_store.write().set_realm_muted(realm_id.clone(), true);
                                        status_msg.set(format!(
                                            "Muted notifications for {}.",
                                            short_protocol_id(&realm_id)
                                        ));
                                    }
                                },
                                UiIcon { name: "bell" }
                            }
                        }
                        if let Some(ref action) = notification.action_label {
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "notification-action",
                                onclick: {
                                    let action_to_run = notification.action.clone();
                                    let base_url = base_url.clone();
                                    let notification_id = notification.id.clone();
                                    let title = notification.title.clone();
                                    move |_| {
                                        if let Some(action_to_run) = action_to_run.clone() {
                                            run_notification_action(
                                                base_url.clone(),
                                                token(),
                                                state_store,
                                                notifications,
                                                status_msg,
                                                notification_id.clone(),
                                                action_to_run,
                                            );
                                        } else {
                                            status_msg.set(format!("Action queued for {title}."));
                                        }
                                    }
                                },
                                "{action}"
                            }
                        }
                    }
                }
            }

            if total_notifications > 0 && visible_notifications.is_empty() {
                EmptyState {
                    title: crate::i18n::tr("notifications.feed_title"),
                    kind: EmptyStateKind::Filtered,
                    message: Some(crate::i18n::tr("notifications.filtered_body")),
                    test_id: Some("notifications-muted-empty".to_owned()),
                }
            }

            // F-NOTIF-VLIST-1: progress + "Load more" affordance for the
            // client-side paging window. We surface the visible / total
            // count so the user knows there's more to expand, then step
            // the window forward by another page when they click.
            if has_more_to_load {
                div { class: "actions", "data-testid": "notifications-load-more-row",
                    div { class: "muted",
                        {format!(
                            "{} {} / {}",
                            crate::i18n::tr("notifications.showing"),
                            visible_window,
                            visible_total,
                        )}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "notifications-load-more",
                        onclick: move |_| {
                            visible_limit.with_mut(|n| *n = n.saturating_add(50));
                        },
                        {crate::i18n::tr("notifications.load_more")}
                    }
                }
            }
        }
    }
}

fn refresh_notifications(
    base_url: String,
    access_token: String,
    mut state_store: Signal<LocalStateStore>,
    mut notifications: Signal<Vec<Notification>>,
    mut status_msg: Signal<String>,
) {
    spawn(async move {
        match with_authed_api(&base_url, access_token, |api| async move {
            let response = api.account_subscribe_snapshot(None).await?;
            let invite_notifications = api
                .invites()
                .await
                .map(|response| response.invites)
                .unwrap_or_default();
            Ok::<_, anyhow::Error>((response, invite_notifications))
        })
        .await
        {
            Ok((response, invite_notifications)) => {
                let push_rules = push_rules_from_account_data(&response.account_data);
                let dnd = dnd_settings_from_account_data(&response.account_data);
                let mut raw_notifications = raw_notifications_from_sources(
                    Some(&response.notifications),
                    &response.account_data,
                );
                let joined_realms = joined_realm_ids(&response);
                merge_invite_notifications(
                    &mut raw_notifications,
                    invite_notifications,
                    &joined_realms,
                );
                let hydrated = {
                    let mut store = state_store.write();
                    store.save_notification_projection(raw_notifications.clone());
                    let local_state = store.load();
                    hydrate_notifications(
                        raw_notifications,
                        &local_state,
                        push_rules.as_ref(),
                        dnd.as_ref(),
                    )
                };
                notifications.set(hydrated);
                status_msg.set(String::new());
            }
            Err(err) => {
                status_msg.set(format!("Notification refresh: {}", err.display()));
            }
        }
    });
}

fn mark_all_notifications_read(
    base_url: String,
    access_token: String,
    actor_id: String,
    device_id: String,
    mut state_store: Signal<LocalStateStore>,
    mut notifications: Signal<Vec<Notification>>,
    mut status_msg: Signal<String>,
) {
    let snapshot = notifications();
    let ids = snapshot
        .iter()
        .map(|notification| notification.id.clone())
        .collect::<Vec<_>>();
    let read_targets = read_cursor_targets(&snapshot);
    for notification in notifications.write().iter_mut() {
        notification.read = true;
    }
    // Perf (P1): "mark all read" used to flush the whole local
    // state once per notification. Coalesce into a single flush.
    let markers = {
        let mut store = state_store.write();
        store.batch(|store| {
            for id in ids {
                store.set_notification_read(id, true);
            }
        });
        if actor_id.trim().is_empty() || device_id.trim().is_empty() {
            Vec::new()
        } else {
            read_targets
                .into_iter()
                .map(|target| {
                    store.save_read_cursor(
                        actor_id.clone(),
                        device_id.clone(),
                        target.realm_id,
                        target.flow_id,
                        target.event_id,
                    )
                })
                .collect::<Vec<_>>()
        }
    };
    if markers.is_empty() {
        status_msg.set("All loaded notifications marked read locally.".to_owned());
        return;
    }

    status_msg.set(format!(
        "All loaded notifications marked read; syncing {} read cursor(s)...",
        markers.len()
    ));
    spawn(async move {
        let marker_count = markers.len();
        match with_authed_api(&base_url, access_token, |api| async move {
            for marker in markers {
                api.submit_read_cursor_advance(&marker).await?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        {
            Ok(()) => status_msg.set(format!(
                "All loaded notifications marked read; synced {marker_count} read cursor(s)."
            )),
            Err(err) => status_msg.set(format!(
                "All loaded notifications marked read locally; read cursor sync failed: {}",
                err.display()
            )),
        }
    });
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NotificationReadTarget {
    realm_id: String,
    flow_id: Option<String>,
    event_id: String,
    timestamp: String,
}

fn read_cursor_targets(notifications: &[Notification]) -> Vec<NotificationReadTarget> {
    let mut latest_by_realm = BTreeMap::<String, NotificationReadTarget>::new();
    for notification in notifications {
        let Some(event_id) = notification.source_event_id.clone() else {
            continue;
        };
        if notification.realm_id.trim().is_empty() {
            continue;
        }
        let target = NotificationReadTarget {
            realm_id: notification.realm_id.clone(),
            flow_id: notification.flow_id.clone(),
            event_id,
            timestamp: notification.timestamp.clone(),
        };
        match latest_by_realm.get(&target.realm_id) {
            Some(existing) if existing.timestamp >= target.timestamp => {}
            _ => {
                latest_by_realm.insert(target.realm_id.clone(), target);
            }
        }
    }
    latest_by_realm.into_values().collect()
}

fn run_notification_action(
    base_url: String,
    access_token: String,
    state_store: Signal<LocalStateStore>,
    notifications: Signal<Vec<Notification>>,
    status_msg: Signal<String>,
    notification_id: String,
    action: NotificationAction,
) {
    match action {
        NotificationAction::AcceptInvite {
            realm_id,
            invite_id,
            realm_label,
        } => accept_invite_notification(
            base_url,
            access_token,
            state_store,
            notifications,
            status_msg,
            notification_id,
            realm_id,
            invite_id,
            realm_label,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn accept_invite_notification(
    base_url: String,
    access_token: String,
    mut state_store: Signal<LocalStateStore>,
    mut notifications: Signal<Vec<Notification>>,
    mut status_msg: Signal<String>,
    notification_id: String,
    realm_id: String,
    invite_id: String,
    realm_label: Option<String>,
) {
    let accepted_realm = realm_id;
    status_msg.set(format!(
        "Accepting Realm invite for {}...",
        short_protocol_id(&accepted_realm)
    ));
    spawn(async move {
        let accepted_realm_for_api = accepted_realm.clone();
        match with_authed_api(&base_url, access_token, |api| async move {
            let account = api.account_me().await?;
            let submit = api
                .join_realm_from_invite(&accepted_realm_for_api, &account.did, &invite_id)
                .await?;
            let read_api = api.clone().with_wait_for(submit.cursor);
            let sync = read_api.account_subscribe_snapshot(None).await;
            let invite_notifications = read_api
                .invites()
                .await
                .map(|response| response.invites)
                .unwrap_or_default();
            Ok::<_, anyhow::Error>((sync, invite_notifications))
        })
        .await
        {
            Ok((Ok(sync), invite_notifications)) => {
                let push_rules = push_rules_from_account_data(&sync.account_data);
                let dnd = dnd_settings_from_account_data(&sync.account_data);
                let mut hidden_realms = joined_realm_ids(&sync);
                hidden_realms.insert(accepted_realm.clone());
                let mut realm_title_hints = BTreeMap::new();
                if let Some(label) = realm_label
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    realm_title_hints.insert(accepted_realm.clone(), label.to_owned());
                }

                let mut raw_notifications =
                    raw_notifications_from_sources(Some(&sync.notifications), &sync.account_data);
                for (realm_id, title) in realm_title_hints_from_values(&raw_notifications) {
                    realm_title_hints.entry(realm_id).or_insert(title);
                }
                for (realm_id, title) in realm_title_hints_from_values(&invite_notifications) {
                    realm_title_hints.entry(realm_id).or_insert(title);
                }
                drop_joined_invite_notifications(&mut raw_notifications, &hidden_realms);
                append_invite_notifications(
                    &mut raw_notifications,
                    invite_notifications,
                    &hidden_realms,
                );
                if raw_notifications.iter().all(|notification| {
                    notification_id_for_dedupe(notification).as_deref() != Some(&notification_id)
                }) {
                    state_store
                        .write()
                        .set_notification_archived(notification_id.clone(), true);
                }
                let hydrated = {
                    let mut store = state_store.write();
                    apply_sync_projection_to_store(&mut store, &sync, &realm_title_hints);
                    store.save_notification_projection(raw_notifications.clone());
                    let local_state = store.load();
                    hydrate_notifications(
                        raw_notifications,
                        &local_state,
                        push_rules.as_ref(),
                        dnd.as_ref(),
                    )
                };
                notifications.set(hydrated);
                status_msg.set(format!(
                    "Joined Realm {}.",
                    short_protocol_id(&accepted_realm)
                ));
            }
            Ok((Err(sync_err), _invite_notifications)) => {
                hide_accepted_invite_notification(
                    &mut state_store,
                    &mut notifications,
                    &notification_id,
                    &accepted_realm,
                );
                status_msg.set(format!(
                    "Joined Realm {}. Refresh pending: {}",
                    short_protocol_id(&accepted_realm),
                    sync_err
                ));
            }
            Err(err) => {
                status_msg.set(format!("Accept invite failed: {}", err.display()));
            }
        }
    });
}

fn hide_accepted_invite_notification(
    state_store: &mut Signal<LocalStateStore>,
    notifications: &mut Signal<Vec<Notification>>,
    notification_id: &str,
    accepted_realm: &str,
) {
    state_store
        .write()
        .set_notification_archived(notification_id.to_owned(), true);
    notifications.with_mut(|items| {
        items.retain(|notification| {
            notification.id != notification_id
                && !(notification.kind == "invite" && notification.realm_id == accepted_realm)
        });
    });
}

pub(crate) fn is_notification_account_data(value: &Value) -> bool {
    matches!(
        value
            .get("kind")
            .or_else(|| value.get("type"))
            .and_then(Value::as_str),
        Some("ck.notification")
            | Some("ck.notification.v1")
            | Some("ck.account.notification")
            | Some("notification")
    )
}

fn raw_notifications_from_sources(
    notification_response: Option<&Value>,
    account_data: &[Value],
) -> Vec<Value> {
    notification_response
        .and_then(notification_items_from_value)
        .unwrap_or_else(|| {
            account_data
                .iter()
                .filter(|value| is_notification_account_data(value))
                .cloned()
                .collect::<Vec<_>>()
        })
}

pub(crate) fn notification_items_from_value(value: &Value) -> Option<Vec<Value>> {
    if value.is_null() {
        return None;
    }
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        return Some(items.clone());
    }
    if let Some(events) = value.get("events").and_then(Value::as_array) {
        return Some(events.clone());
    }
    value.as_array().cloned()
}

fn append_invite_notifications(
    raw_notifications: &mut Vec<Value>,
    invites: Vec<Value>,
    hidden_realms: &BTreeSet<String>,
) {
    let mut existing_targets = raw_notifications
        .iter()
        .filter_map(invite_notification_target_for_dedupe)
        .collect::<BTreeSet<_>>();
    for invite in invites {
        let Some(target_realm) = invite_realm_id_from_value(&invite) else {
            continue;
        };
        if hidden_realms.contains(&target_realm) || existing_targets.contains(&target_realm) {
            continue;
        }
        let Some(notification) = invite_notification_from_value(&invite) else {
            continue;
        };
        existing_targets.insert(target_realm);
        raw_notifications.push(notification);
    }
}

pub(crate) fn merge_invite_notifications(
    raw_notifications: &mut Vec<Value>,
    invites: Vec<Value>,
    hidden_realms: &BTreeSet<String>,
) {
    drop_joined_invite_notifications(raw_notifications, hidden_realms);
    append_invite_notifications(raw_notifications, invites, hidden_realms);
}

fn invite_notification_from_value(invite: &Value) -> Option<Value> {
    let invite_id = value_string(invite, &["id", "invite_id"])?;
    let realm_id = value_string(invite, &["realm_id"])?;
    let realm_title = realm_title_from_value(invite);
    let created_at = value_string(invite, &["created_at"])
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    let body = if let Some(title) = realm_title.as_deref() {
        format!("You were invited to join {title}.")
    } else {
        "You were invited to join a Realm.".to_owned()
    };

    Some(json!({
        // Key the notification identity on the unique invite id, not the
        // realm id. The realm id is stable across the realm's whole
        // lifetime, so a realm-scoped id made a *fresh* invite inherit the
        // archived/read client-state (and stale per-realm mute) of an
        // earlier invite to the same realm — silently hiding re-invites.
        // The invite id is unique per invitation yet stable across refreshes
        // of the same pending invite, so archive/read still persist while it
        // is pending, and a later re-invite gets a clean, visible entry.
        "notification_id": format!("invite:{invite_id}"),
        "invite_id": invite_id,
        "notification_kind": "invite",
        "notification_type": "invite",
        "kind": "invite",
        "title": "Realm invite",
        "body": body,
        "realm_id": realm_id,
        "realm_label": realm_title,
        "timestamp": created_at,
        "read": false,
    }))
}

fn notification_id_for_dedupe(value: &Value) -> Option<String> {
    value_string(value, &["notification_id", "id"])
}

fn invite_notification_target_for_dedupe(value: &Value) -> Option<String> {
    if !notification_is_invite(value) {
        return None;
    }
    invite_realm_id_from_value(value)
}

fn invite_realm_id_from_value(value: &Value) -> Option<String> {
    value_string(value, &["realm_id", "target_realm_id"])
}

fn realm_title_from_value(value: &Value) -> Option<String> {
    value_string(value, &["realm_label", "realm_title", "title", "name"])
        .or_else(|| nested_value_string(value, &["summary"], "title"))
        .or_else(|| nested_value_string(value, &["summary"], "name"))
        .or_else(|| nested_value_string(value, &["realm_preview"], "title"))
        .or_else(|| nested_value_string(value, &["preview"], "title"))
        .map(|title| title.trim().to_owned())
        .filter(|title| !title.is_empty())
}

pub(crate) fn realm_title_hints_from_values(values: &[Value]) -> BTreeMap<String, String> {
    values
        .iter()
        .filter_map(|value| {
            let realm_id = invite_realm_id_from_value(value)?;
            let title = realm_title_from_value(value)?;
            Some((realm_id, title))
        })
        .collect()
}

fn notification_is_invite(value: &Value) -> bool {
    ["notification_kind", "notification_type", "type", "kind"]
        .iter()
        .filter_map(|key| value.get(*key).and_then(Value::as_str))
        .any(|kind| matches!(kind, "invite" | "ck.invite" | "ck.invite.create"))
}

fn drop_joined_invite_notifications(
    raw_notifications: &mut Vec<Value>,
    joined_realms: &BTreeSet<String>,
) {
    raw_notifications.retain(|notification| {
        let Some(realm_id) = invite_notification_target_for_dedupe(notification) else {
            return true;
        };
        !joined_realms.contains(&realm_id)
    });
}

fn joined_realm_ids(response: &ClientSyncOutcome) -> BTreeSet<String> {
    response.realms.keys().cloned().collect()
}

fn apply_sync_projection_to_store(
    store: &mut LocalStateStore,
    response: &ClientSyncOutcome,
    realm_title_hints: &BTreeMap<String, String>,
) {
    store.save_sync_cursor(response.cursor.clone());
    for left_id in &response.left_realms {
        store.forget_realm_tree_projection(left_id);
    }
    for (id, body) in &response.realms {
        let projection = crate::realm_tree::projection_with_title_hint(
            id,
            body,
            realm_title_hints.get(id).map(String::as_str),
        );
        store.save_realm_tree_projection(id.clone(), projection);
        let view = LocalSealView::from_sync_body(body);
        store.set_realm_seal_view(id.clone(), view);
        store.ingest_move_event_states(id, body);
    }
}

fn hydrate_notifications(
    raw_notifications: Vec<Value>,
    local_state: &ClientLocalState,
    push_rules: Option<&PushRulesConfig>,
    dnd: Option<&DndSettings>,
) -> Vec<Notification> {
    let joined_realms = local_state
        .realm_tree_projections
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut seen_invite_targets = BTreeSet::new();
    raw_notifications
        .into_iter()
        .enumerate()
        .filter(|(_, value)| {
            let Some(target) = invite_notification_target_for_dedupe(value) else {
                return true;
            };
            !joined_realms.contains(&target) && seen_invite_targets.insert(target)
        })
        .filter_map(|(index, value)| {
            notification_from_value(index, value, local_state, push_rules, dnd)
        })
        .collect()
}

fn notification_from_value(
    index: usize,
    value: Value,
    local_state: &ClientLocalState,
    push_rules: Option<&PushRulesConfig>,
    dnd: Option<&DndSettings>,
) -> Option<Notification> {
    let mut eval_ctx = notification_eval_context(&value);
    // Apply the receiver's per-realm watch override (None when unconfigured).
    // Invites are exempt: they target a realm the receiver is not a member of,
    // so a leftover per-realm mute (e.g. from a prior membership) is stale and
    // must not short-circuit the invite out of the feed during hydration.
    eval_ctx.realm_watch_level = if eval_ctx.notification_type == "invite" {
        None
    } else {
        realm_watch_override(local_state, &eval_ctx.realm_id)
    };
    let decision = evaluate_notification(push_rules, dnd, &eval_ctx);

    // T4.4 — When the watch level (not DND, not muted-short-circuit)
    // is the reason we'd drop this entry, keep it in the list with a
    // small inline hint so the user can change watch level. Muted
    // flows still drop (they signal explicit user intent) and DND
    // continues to suppress quietly during the configured window.
    let watch_hint = if decision.watch_suppressed && !decision.muted_short_circuit {
        Some(watch_hint_for_event(&eval_ctx))
    } else {
        None
    };
    if !decision.should_notify && watch_hint.is_none() {
        return None;
    }

    let id = value_string(&value, &["notification_id", "id"])
        .unwrap_or_else(|| format!("notification-{index}"));
    let source_event_id = value_string_with_prefix(
        &value,
        &[
            "source_event_id",
            "event_id",
            "target_event_id",
            "message_event_id",
            "timeline_event_id",
        ],
        "ck:event:",
    )
    .or_else(|| id.strip_prefix("ck:event:").map(|_| id.clone()));
    let flow_id = value_string_with_prefix(
        &value,
        &["flow_id", "target_flow_id", "space_id"],
        "ck:flow:",
    );
    let client_state = local_state
        .notification_client_state
        .get(&id)
        .cloned()
        .unwrap_or_default();
    let kind = value_string(
        &value,
        &["notification_type", "notification_kind", "type", "kind"],
    )
    .unwrap_or_else(|| "message".to_owned());
    let title =
        value_string(&value, &["title"]).unwrap_or_else(|| default_notification_title(&kind));
    let body = value_string(&value, &["body", "preview", "summary"])
        .unwrap_or_else(|| "Notification".to_owned());
    let realm_id = value_string(&value, &["realm_id"]).unwrap_or_default();
    let invite_id = value_string(&value, &["invite_id"]);
    let realm_label = value_string(&value, &["realm_label", "realm_title"]);
    let action = if kind == "invite" {
        invite_id.clone().and_then(|invite_id| {
            if realm_id.is_empty() {
                None
            } else {
                Some(NotificationAction::AcceptInvite {
                    realm_id: realm_id.clone(),
                    invite_id,
                    realm_label: realm_label.clone(),
                })
            }
        })
    } else {
        None
    };
    let timestamp = value_string(&value, &["timestamp", "created_at"])
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

    Some(Notification {
        id,
        source_event_id,
        title,
        body,
        realm_id,
        flow_id,
        realm_label,
        kind: kind.clone(),
        read: value_bool(&value, "read").unwrap_or(client_state.read),
        archived: value_bool(&value, "archived").unwrap_or(client_state.archived),
        timestamp,
        action_label: action
            .as_ref()
            .map(|_| default_notification_action(&kind).to_owned()),
        action,
        watch_hint,
    })
}

/// T4.4 — Resolve the wire-safe reason code for a watch-suppressed
/// notification through the shared SDK `evaluate_watch_level`
/// helper, then map that to a localised UI string.
///
/// Routing the decision through the shared client helper (instead of
/// reading the reason from yougen's richer evaluator directly) keeps
/// the UI surface aligned with what the Sync Service would have
/// returned, so the same `(watch_level, event)` pair never produces
/// different copy across surfaces.
fn watch_hint_for_event(ctx: &NotificationEvalContext) -> String {
    // Default to `MentionsOnly` to match the yougen evaluator's
    // default; cosmetic only since the caller already established
    // `watch_suppressed=true`.
    let core_level = ctx.watch_level.unwrap_or_default();
    let core_ctx = PushRuleEventContext {
        mentions_actor: ctx.mentions_actor.unwrap_or(false),
        assigned_to_actor: ctx.assigned_to_actor,
        reply_to_self: ctx.reply_to_self,
        participating_thread_update: ctx.participating_thread_update,
        is_e2ee: ctx.is_e2ee,
        local_decrypted: ctx.local_decrypted,
    };
    let (decision, reason) = evaluate_watch_level(core_level, &core_ctx);

    // Even if the core says "Notify" (the inputs disagree with the
    // yougen evaluator's richer rules), still surface a generic
    // change-watch-level hint so the UI stays consistent with what
    // the user observed.
    match (decision, reason) {
        (ShouldNotify::DontNotify, push_rule_reason_code::NOT_MENTIONED) => {
            "You're not getting notifications for this discussion — change watch level".to_owned()
        }
        (ShouldNotify::DontNotify, push_rule_reason_code::NOT_PARTICIPATING) => {
            "You're only being notified about threads you've joined — change watch level".to_owned()
        }
        _ => "Notifications for this discussion are limited by your watch level".to_owned(),
    }
}

fn default_notification_title(kind: &str) -> String {
    match kind {
        "invite" => "Realm invite".to_owned(),
        "reaction" => "New reaction".to_owned(),
        "mention" => "You were mentioned".to_owned(),
        _ => "New message".to_owned(),
    }
}

fn default_notification_action(kind: &str) -> &'static str {
    match kind {
        "invite" => "Accept",
        _ => "View",
    }
}

fn notification_scope_kind(notification: &Notification) -> &'static str {
    if notification.kind == "invite" {
        "Realm"
    } else {
        "Space"
    }
}

fn value_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(|field| field.as_str())
            .map(ToOwned::to_owned)
    })
}

fn value_string_with_prefix(value: &Value, keys: &[&str], prefix: &str) -> Option<String> {
    value_string(value, keys).filter(|candidate| candidate.starts_with(prefix))
}

fn nested_value_string(value: &Value, parents: &[&str], key: &str) -> Option<String> {
    let mut current = value;
    for parent in parents {
        current = current.get(*parent)?;
    }
    current
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn value_bool(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(|field| field.as_bool())
}

fn value_u32(value: &Value, key: &str) -> Option<u32> {
    value
        .get(key)
        .and_then(|field| field.as_u64())
        .and_then(|field| u32::try_from(field).ok())
}

fn notification_eval_context(value: &Value) -> NotificationEvalContext {
    let notification_type = value_string(
        value,
        &["notification_type", "notification_kind", "type", "kind"],
    )
    .unwrap_or_else(|| "message".to_owned());
    let event_kind = value_string(value, &["event_kind", "source_event_kind", "kind", "type"])
        .unwrap_or_else(|| notification_type.clone());
    let is_e2ee = value_bool(value, "is_e2ee")
        .or_else(|| value_bool(value, "encrypted"))
        .unwrap_or_else(|| value.get("encrypted_content").is_some());
    let priority = value_string(value, &["priority", "notification_priority"])
        .map(|value| value.to_ascii_lowercase());
    let priority_override = value_bool(value, "priority_override").unwrap_or_else(|| {
        priority
            .as_deref()
            .is_some_and(|value| matches!(value, "critical" | "high" | "urgent" | "priority"))
    });
    NotificationEvalContext {
        event_kind,
        notification_type,
        realm_id: value_string(value, &["realm_id"]).unwrap_or_default(),
        flow_id: value_string(value, &["flow_id"]),
        flow_track: value_string(value, &["flow_track", "track_name"]),
        // Canonical notification attribution comes from the EventEnvelope
        // actor_id. Deprecated sender/sender_did wire names are ignored in
        // the default protocol path.
        sender: value_string(value, &["actor_id"]),
        body: value_string(value, &["body", "summary", "preview"]),
        is_e2ee,
        local_decrypted: value_bool(value, "local_decrypted").unwrap_or(!is_e2ee),
        mentions_actor: value_bool(value, "mentions_actor"),
        assigned_to_actor: value_bool(value, "assigned_to_actor").unwrap_or(false),
        reply_to_self: value_bool(value, "reply_to_self").unwrap_or(false),
        participating_thread_update: value_bool(value, "participating_thread_update")
            .unwrap_or(false),
        is_direct_message: value_bool(value, "is_direct_message").unwrap_or(false),
        member_count: value_u32(value, "member_count"),
        priority,
        priority_override,
        watch_level: value_string(value, &["watch_state", "watch_level"])
            .and_then(|level| WatchLevel::from_wire(&level)),
        // Filled by the caller from the receiver's per-realm override; left
        // `None` here so a bare context never resolves to a watch level.
        realm_watch_level: None,
        now_minutes: None,
    }
}

/// Receiver's explicit per-realm watch override, or `None` when the realm is
/// unconfigured (so the watch gate is skipped and global defaults apply).
fn realm_watch_override(local_state: &ClientLocalState, realm_id: &str) -> Option<WatchLevel> {
    if realm_id.is_empty() {
        return None;
    }
    local_state.realm_watch_levels.get(realm_id).copied()
}

fn realm_is_muted(local_state: &ClientLocalState, realm_id: &str) -> bool {
    realm_watch_override(local_state, realm_id) == Some(WatchLevel::Muted)
}

fn notification_kind_enabled(local_state: &ClientLocalState, kind: &str) -> bool {
    local_state
        .muted_notification_kinds
        .get(kind)
        .copied()
        .unwrap_or(true)
}

fn notification_overrides_realm_mute(notification: &Notification) -> bool {
    matches!(
        notification.kind.as_str(),
        // Invites bypass a per-realm mute: a pending invitation targets a
        // realm the receiver is not currently a member of (joined realms are
        // dropped before this filter), so any `realm_watch_levels` mute is
        // necessarily stale from a prior membership and must not swallow a
        // fresh, actionable invite.
        "invite" | "mention" | "priority" | "critical" | "urgent"
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn hydrate_notifications_applies_push_rules_and_dnd() {
        let raw = vec![json!({
            "notification_id": "n1",
            "kind": "ck.notification",
            "notification_type": "message",
            "realm_id": "ck:realm:quiet",
            "body": "hello"
        })];
        let rules = crate::notification_rules::parse_push_rules(&json!({
            "rules": [{
                "rule_id": "override.quiet",
                "conditions": [
                    {"kind": "field_match", "field": "realm_id", "pattern": "ck:realm:quiet"}
                ],
                "actions": ["dont_notify"]
            }]
        }))
        .unwrap();

        let notifications =
            hydrate_notifications(raw, &ClientLocalState::default(), Some(&rules), None);
        assert!(notifications.is_empty());
    }

    #[test]
    fn pending_invites_are_hydrated_as_notifications() {
        let invite = json!({
            "id": "ck:invite:01904100-0000-7000-8000-000000000001",
            "schema": "ck.schema.invite.v1",
            "realm_id": "ck:realm:01904100-0000-7000-8000-000000000002",
            "inviter": "did:web:alice.example",
            "state": "pending",
            "created_at": "2026-05-29T00:00:00Z",
        });
        let duplicate_invite = json!({
            "id": "ck:invite:01904100-0000-7000-8000-000000000099",
            "schema": "ck.schema.invite.v1",
            "realm_id": "ck:realm:01904100-0000-7000-8000-000000000002",
            "inviter": "did:web:alice.example",
            "state": "pending",
            "created_at": "2026-05-29T00:00:01Z",
        });
        let mut raw = Vec::new();
        append_invite_notifications(&mut raw, vec![invite.clone()], &BTreeSet::new());
        append_invite_notifications(&mut raw, vec![duplicate_invite], &BTreeSet::new());
        assert_eq!(raw.len(), 1, "same Realm invite should not duplicate");

        let notifications =
            hydrate_notifications(raw.clone(), &ClientLocalState::default(), None, None);
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].kind, "invite");
        assert_eq!(notifications[0].title, "Realm invite");
        assert_eq!(
            notifications[0].realm_id,
            "ck:realm:01904100-0000-7000-8000-000000000002"
        );
        assert_eq!(notifications[0].body, "You were invited to join a Realm.");
        assert_eq!(notifications[0].action_label.as_deref(), Some("Accept"));
        assert!(matches!(
            notifications[0].action.as_ref(),
            Some(NotificationAction::AcceptInvite { .. })
        ));

        let joined_realms =
            BTreeSet::from(["ck:realm:01904100-0000-7000-8000-000000000002".to_owned()]);
        append_invite_notifications(&mut raw, vec![invite], &joined_realms);
        drop_joined_invite_notifications(&mut raw, &joined_realms);
        assert!(raw.is_empty(), "joined Realm invites should be hidden");
    }

    #[test]
    fn fresh_invite_to_same_realm_survives_stale_archive_and_realm_mute() {
        let realm_id = "ck:realm:01904100-0000-7000-8000-000000000002";
        // Local state left over from an earlier invite to this realm: the
        // previous invite notification was archived, and the realm itself is
        // muted (e.g. a prior membership the receiver left). Both are keyed on
        // the realm — the regression was that they suppressed re-invites.
        let mut local_state = ClientLocalState::default();
        local_state
            .notification_client_state
            .entry("invite:ck:invite:00000000-0000-7000-8000-0000000000aa".to_owned())
            .or_default()
            .archived = true;
        local_state
            .realm_watch_levels
            .insert(realm_id.to_owned(), WatchLevel::Muted);

        // A brand-new invitation (distinct invite id) to the same realm.
        let invite = json!({
            "id": "ck:invite:00000000-0000-7000-8000-0000000000bb",
            "schema": "ck.schema.invite.v1",
            "realm_id": realm_id,
            "state": "pending",
            "created_at": "2026-06-10T00:00:00Z",
        });
        let mut raw = Vec::new();
        append_invite_notifications(&mut raw, vec![invite], &BTreeSet::new());

        let hydrated = hydrate_notifications(raw, &local_state, None, None);
        assert_eq!(hydrated.len(), 1, "fresh invite must hydrate");
        let notification = &hydrated[0];
        assert!(
            !notification.archived,
            "fresh invite must not inherit archive"
        );
        assert_eq!(
            notification.id, "invite:ck:invite:00000000-0000-7000-8000-0000000000bb",
            "invite notification id is keyed on the unique invite id"
        );
        // Realm mute must not hide an invite to a realm we are not in.
        assert!(notification_overrides_realm_mute(notification));
        assert!(realm_is_muted(&local_state, realm_id));
    }

    #[test]
    fn invite_title_is_preserved_for_accept_projection_hint() {
        let realm_id = "ck:realm:01904100-0000-7000-8000-000000000010";
        let invite = json!({
            "id": "ck:invite:01904100-0000-7000-8000-000000000011",
            "schema": "ck.schema.invite.v1",
            "realm_id": realm_id,
            "realm_title": "Partner Launch",
            "state": "pending",
            "created_at": "2026-05-29T00:00:00Z",
        });
        let mut raw = Vec::new();
        append_invite_notifications(&mut raw, vec![invite], &BTreeSet::new());

        let hints = realm_title_hints_from_values(&raw);
        let notifications = hydrate_notifications(raw, &ClientLocalState::default(), None, None);

        assert_eq!(
            hints.get(realm_id).map(String::as_str),
            Some("Partner Launch")
        );
        assert_eq!(
            notifications[0].body,
            "You were invited to join Partner Launch."
        );
        assert!(matches!(
            notifications[0].action.as_ref(),
            Some(NotificationAction::AcceptInvite {
                realm_label: Some(label),
                ..
            }) if label == "Partner Launch"
        ));
    }

    #[test]
    fn notification_eval_context_extracts_watch_and_e2ee_flags() {
        let ctx = notification_eval_context(&json!({
            "notification_id": "n1",
            "event_kind": "ck.message.create",
            "notification_type": "mention",
            "actor_id": "did:web:alice.example",
            "realm_id": "ck:realm:e2ee",
            "flow_id": "ck:flow:1",
            "track_name": "discussion",
            "watch_state": "participating",
            "encrypted": true,
            "local_decrypted": false,
            "mentions_actor": true
        }));

        assert_eq!(ctx.event_kind, "ck.message.create");
        assert_eq!(ctx.notification_type, "mention");
        assert_eq!(ctx.flow_track.as_deref(), Some("discussion"));
        assert_eq!(ctx.watch_level, Some(WatchLevel::Participating));
        assert!(ctx.is_e2ee);
        assert!(!ctx.local_decrypted);
        assert_eq!(ctx.mentions_actor, Some(true));
        assert_eq!(ctx.sender.as_deref(), Some("did:web:alice.example"));
    }

    #[test]
    fn notification_eval_context_ignores_deprecated_sender_fields() {
        let ctx = notification_eval_context(&json!({
            "notification_id": "n1",
            "event_kind": "ck.message.create",
            "notification_type": "mention",
            "sender": "did:web:legacy.example",
            "sender_did": "did:web:legacy-did.example",
            "sender_actor_id": "did:web:legacy-actor.example"
        }));

        assert_eq!(ctx.sender, None);
    }

    #[test]
    fn read_cursor_targets_pick_latest_event_per_realm() {
        let realm_a = "ck:realm:01904100-0000-7000-8000-000000000002";
        let flow_a = "ck:flow:01904100-0000-7000-8000-000000000003";
        let realm_b = "ck:realm:01904100-0000-7000-8000-000000000004";
        let raw = vec![
            json!({
                "notification_id": "old-a",
                "notification_type": "message",
                "realm_id": realm_a,
                "flow_id": flow_a,
                "source_event_id": "ck:event:01904100-0000-7000-8000-000000000005",
                "timestamp": "2026-05-29T00:00:00Z",
            }),
            json!({
                "notification_id": "new-a",
                "notification_type": "message",
                "realm_id": realm_a,
                "flow_id": flow_a,
                "event_id": "ck:event:01904100-0000-7000-8000-000000000006",
                "timestamp": "2026-05-29T00:00:01Z",
            }),
            json!({
                "notification_id": "no-position",
                "notification_type": "message",
                "realm_id": realm_a,
                "timestamp": "2026-05-29T00:00:02Z",
            }),
            json!({
                "notification_id": "new-b",
                "notification_type": "mention",
                "realm_id": realm_b,
                "source_event_id": "ck:event:01904100-0000-7000-8000-000000000007",
                "timestamp": "2026-05-29T00:00:03Z",
            }),
        ];

        let notifications = hydrate_notifications(raw, &ClientLocalState::default(), None, None);
        let targets = read_cursor_targets(&notifications);

        assert_eq!(targets.len(), 2);
        let target_a = targets
            .iter()
            .find(|target| target.realm_id == realm_a)
            .expect("realm A target");
        assert_eq!(
            target_a.event_id,
            "ck:event:01904100-0000-7000-8000-000000000006"
        );
        assert_eq!(target_a.flow_id.as_deref(), Some(flow_a));
        let target_b = targets
            .iter()
            .find(|target| target.realm_id == realm_b)
            .expect("realm B target");
        assert_eq!(
            target_b.event_id,
            "ck:event:01904100-0000-7000-8000-000000000007"
        );
        assert!(target_b.flow_id.is_none());
    }

    #[test]
    fn notification_source_falls_back_to_account_data_only_when_endpoint_missing() {
        let account_data = vec![
            json!({
                "kind": "ck.notification",
                "notification_id": "n1",
                "read": false
            }),
            json!({
                "kind": "ck.profile",
                "id": "profile"
            }),
        ];

        let fallback = raw_notifications_from_sources(None, &account_data);
        assert_eq!(fallback.len(), 1);

        let server_empty = json!({ "items": [], "unread_count": 0 });
        assert!(raw_notifications_from_sources(Some(&server_empty), &account_data).is_empty());

        let subscribe_delta = json!({
            "events": [{
                "notification_id": "n2",
                "kind": "mention",
                "read": false
            }],
            "unread_count": 1
        });
        let from_subscribe = raw_notifications_from_sources(Some(&subscribe_delta), &account_data);
        assert_eq!(from_subscribe.len(), 1);
        assert_eq!(from_subscribe[0]["notification_id"].as_str(), Some("n2"));
    }
}
