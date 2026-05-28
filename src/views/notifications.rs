use dioxus::prelude::*;
use dioxus_router::Link;
use serde_json::{Value, json};

use contrix_sdk::push_rule_core::{
    EventContext as PushRuleEventContext, ShouldNotify, evaluate_watch_level,
    reason_code as push_rule_reason_code,
};

use crate::{
    components::{EmptyState, EmptyStateKind, HelpTip, UiIcon},
    local_state::{ClientLocalState, LocalStateStore},
    notification_rules::{
        DndSettings, NotificationEvalContext, PushRulesConfig, WatchLevel,
        dnd_settings_from_account_data, evaluate_notification, push_rules_from_account_data,
    },
    routes::Route,
    views::helpers::{short_protocol_id, with_authed_api},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NotificationGroup {
    All,
    BySpace,
    ByType,
    ByTime,
}

#[derive(Clone, Debug, PartialEq)]
struct Notification {
    id: String,
    title: String,
    body: String,
    space_id: String,
    kind: String,
    read: bool,
    archived: bool,
    timestamp: String,
    action_label: Option<String>,
    /// T4.4 — User-facing hint surfaced when the watch level
    /// suppressed delivery (e.g. "You're not getting notifications
    /// for this discussion — change watch level"). `None` for
    /// notifications that pass the watch-level filter normally.
    watch_hint: Option<String>,
}

#[component]
pub fn NotificationsPanel(
    base_url: String,
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
    let mut group_by = use_signal(|| NotificationGroup::ByTime);
    let mut show_archived = use_signal(|| false);
    let mut did_bootstrap = use_signal(|| false);
    let mut status_msg = use_signal(String::new);
    let server_unread = use_signal(|| 0usize);

    if !did_bootstrap() {
        did_bootstrap.set(true);
        refresh_notifications(
            base_url.clone(),
            token(),
            state_store,
            notifications,
            status_msg,
            server_unread,
        );
    }

    let local_state = state_store.read().load();
    let mut visible_notifications = notifications()
        .into_iter()
        .filter(|notification| {
            (show_archived() || !notification.archived)
                && notification_kind_enabled(&local_state, &notification.kind)
                && (!space_is_muted(&local_state, &notification.space_id)
                    || notification_overrides_space_mute(notification))
        })
        .collect::<Vec<_>>();

    match group_by() {
        NotificationGroup::All | NotificationGroup::ByTime => {
            visible_notifications.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
        }
        NotificationGroup::BySpace => {
            visible_notifications.sort_by(|left, right| {
                left.space_id
                    .cmp(&right.space_id)
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

    let unread_visible = visible_notifications
        .iter()
        .filter(|notification| !notification.read)
        .count();
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

    rsx! {
        div { class: "timeline", "data-testid": "notifications-panel", role: "region", "aria-label": "Notifications",
            div { class: "event notification-toolbar", role: "status", "aria-live": "polite",
                div { class: "event-head",
                    span { "Notifications" }
                    div { class: "section-tools",
                        HelpTip { text: "Notifications are derived from sync account data and filtered by local mute rules. Push only wakes the client; notification bodies are resolved locally." }
                        span { "data-testid": "unread-count", "{unread_visible}" }
                        span { "{unread_visible} unread / {server_unread()} server" }
                    }
                }
                div { class: "toolbar-row",
                    div { class: "segmented-control", role: "tablist", "aria-label": "Notification grouping",
                        button {
                            class: if group_by() == NotificationGroup::All { "segment active" } else { "segment" },
                            onclick: move |_| group_by.set(NotificationGroup::All),
                            {crate::i18n::tr("notifications.group.all")}
                        }
                        button {
                            class: if group_by() == NotificationGroup::BySpace { "segment active" } else { "segment" },
                            onclick: move |_| group_by.set(NotificationGroup::BySpace),
                            {crate::i18n::tr("notifications.group.space")}
                        }
                        button {
                            class: if group_by() == NotificationGroup::ByType { "segment active" } else { "segment" },
                            onclick: move |_| group_by.set(NotificationGroup::ByType),
                            {crate::i18n::tr("notifications.group.type")}
                        }
                        button {
                            class: if group_by() == NotificationGroup::ByTime { "segment active" } else { "segment" },
                            onclick: move |_| group_by.set(NotificationGroup::ByTime),
                            {crate::i18n::tr("notifications.group.time")}
                        }
                    }
                    div { class: "icon-actions",
                        button {
                            class: "btn icon sm ghost",
                            "data-testid": "mark-all-read-button",
                            title: crate::i18n::tr("notifications.tooltip.mark_all_read"),
                            "aria-label": crate::i18n::tr("notifications.tooltip.mark_all_read"),
                            onclick: {
                                let base_url = base_url.clone();
                                move |_| {
                                    mark_all_notifications_read(
                                        base_url.clone(),
                                        token(),
                                        state_store,
                                        notifications,
                                        status_msg,
                                        server_unread,
                                    );
                                }
                            },
                            UiIcon { name: "check" }
                        }
                        button {
                            class: "btn icon sm ghost",
                            "data-testid": "toggle-archived",
                            title: if show_archived() { crate::i18n::tr("notifications.tooltip.hide_archived") } else { crate::i18n::tr("notifications.tooltip.show_archived") },
                            "aria-label": if show_archived() { crate::i18n::tr("notifications.tooltip.hide_archived") } else { crate::i18n::tr("notifications.tooltip.show_archived") },
                            onclick: move |_| show_archived.set(!show_archived()),
                            UiIcon { name: "archive" }
                        }
                    }
                    div { class: "icon-actions",
                    button {
                        class: "btn icon sm ghost",
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
                                    server_unread,
                                );
                            }
                        },
                        UiIcon { name: "refresh" }
                    }
                    }
                }
                if !status_msg().is_empty() {
                    div { class: "muted", "data-testid": "notifications-status", "{status_msg}" }
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
                        class: if notification.read { "muted" } else { "space-title" },
                        "{notification.body}"
                    }
                    if let Some(ref hint) = notification.watch_hint {
                        div {
                            class: "muted",
                            "data-testid": "notification-watch-hint",
                            "{hint}"
                        }
                    }
                    if !notification.space_id.is_empty() {
                        {
                            let space_id_label = short_protocol_id(&notification.space_id);
                            rsx! {
                                div {
                                    class: "muted",
                                    title: "{notification.space_id}",
                                    "Space: {space_id_label}"
                                }
                            }
                        }
                    }
                    div { class: "actions",
                        if !notification.read {
                            button {
                                class: "btn icon sm ghost",
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
                            button {
                                class: "btn icon sm ghost",
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
                            button {
                                class: "btn icon sm ghost",
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
                        if !notification.space_id.is_empty() {
                            button {
                                class: "btn icon sm ghost",
                                "data-testid": "mute-space-button",
                                title: "Mute this space",
                                "aria-label": "Mute this space",
                                onclick: {
                                    let space_id = notification.space_id.clone();
                                    move |_| {
                                        state_store.write().set_space_muted(space_id.clone(), true);
                                        status_msg.set(format!(
                                            "Muted notifications for {}.",
                                            short_protocol_id(&space_id)
                                        ));
                                    }
                                },
                                UiIcon { name: "bell" }
                            }
                        }
                        if let Some(ref action) = notification.action_label {
                            button {
                                class: "primary",
                                "data-testid": "notification-action",
                                onclick: {
                                    let title = notification.title.clone();
                                    move |_| status_msg.set(format!("Action queued for {title}."))
                                },
                                "{action}"
                            }
                        }
                    }
                }
            }

            if total_notifications == 0 {
                EmptyState {
                    title: crate::i18n::tr("notifications.title"),
                    kind: EmptyStateKind::Empty,
                    message: Some(crate::i18n::tr("notifications.empty_body")),
                    test_id: Some("notifications-empty".to_owned()),
                }
            } else if visible_notifications.is_empty() {
                EmptyState {
                    title: crate::i18n::tr("notifications.title"),
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
                    button {
                        class: "secondary",
                        "data-testid": "notifications-load-more",
                        onclick: move |_| {
                            visible_limit.with_mut(|n| *n = n.saturating_add(50));
                        },
                        {crate::i18n::tr("notifications.load_more")}
                    }
                }
            }

            div { class: "event", "data-testid": "notifications-settings-hint",
                div { class: "event-head",
                    span { {crate::i18n::tr("notifications.settings_card")} }
                    span { {crate::i18n::tr("notifications.settings_card_hint")} }
                }
                div { class: "muted",
                    {crate::i18n::tr("notifications.settings_card_body")}
                }
                div { class: "actions",
                    Link {
                        class: "secondary",
                        to: Route::SettingsSection { section: "notifications".to_owned() },
                        UiIcon { name: "settings" }
                        {crate::i18n::tr("notifications.settings_card_open")}
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
    mut server_unread: Signal<usize>,
) {
    spawn(async move {
        match with_authed_api(&base_url, access_token, |api| async move {
            let response = api.account_subscribe_snapshot(None).await?;
            let notification_response = api
                .list_notifications()
                .await
                .unwrap_or_else(|_| json!({ "items": [] }));
            Ok::<_, anyhow::Error>((response, notification_response))
        })
        .await
        {
            Ok((response, notification_response)) => {
                let push_rules = push_rules_from_account_data(&response.account_data);
                let dnd = dnd_settings_from_account_data(&response.account_data);
                let server_items = notification_response
                    .get("items")
                    .and_then(Value::as_array)
                    .cloned();
                let raw_notifications = server_items.unwrap_or_else(|| {
                    response
                        .account_data
                        .into_iter()
                        .filter(is_notification_account_data)
                        .collect::<Vec<_>>()
                });
                let unread_count = notification_response
                    .get("unread_count")
                    .and_then(Value::as_u64)
                    .and_then(|count| usize::try_from(count).ok())
                    .unwrap_or_else(|| {
                        raw_notifications
                            .iter()
                            .filter(|value| {
                                !value.get("read").and_then(Value::as_bool).unwrap_or(false)
                            })
                            .count()
                    });
                server_unread.set(unread_count);
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
                let loaded_count = hydrated.len();
                notifications.set(hydrated);
                status_msg.set(format!("Loaded {loaded_count} notification(s)."));
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
    mut state_store: Signal<LocalStateStore>,
    mut notifications: Signal<Vec<Notification>>,
    mut status_msg: Signal<String>,
    mut server_unread: Signal<usize>,
) {
    spawn(async move {
        match with_authed_api(&base_url, access_token, |api| async move {
            api.mark_all_notifications_read().await
        })
        .await
        {
            Ok(_) => {
                let ids = notifications()
                    .iter()
                    .map(|notification| notification.id.clone())
                    .collect::<Vec<_>>();
                for notification in notifications.write().iter_mut() {
                    notification.read = true;
                }
                let mut store = state_store.write();
                for id in ids {
                    store.set_notification_read(id, true);
                }
                server_unread.set(0);
                status_msg.set("All visible notifications marked read.".to_owned());
            }
            Err(err) => {
                status_msg.set(format!("Mark all read failed: {}", err.display()));
            }
        }
    });
}

pub(crate) fn is_notification_account_data(value: &Value) -> bool {
    matches!(
        value
            .get("kind")
            .or_else(|| value.get("type"))
            .and_then(Value::as_str),
        Some("cx.notification")
            | Some("cx.notification.v1")
            | Some("cx.account.notification")
            | Some("notification")
    )
}

fn hydrate_notifications(
    raw_notifications: Vec<Value>,
    local_state: &ClientLocalState,
    push_rules: Option<&PushRulesConfig>,
    dnd: Option<&DndSettings>,
) -> Vec<Notification> {
    raw_notifications
        .into_iter()
        .enumerate()
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
    let eval_ctx = notification_eval_context(&value);
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
    let client_state = local_state
        .notification_client_state
        .get(&id)
        .cloned()
        .unwrap_or_default();
    let kind = value_string(&value, &["notification_kind", "type", "kind"])
        .unwrap_or_else(|| "message".to_owned());
    let title =
        value_string(&value, &["title"]).unwrap_or_else(|| default_notification_title(&kind));
    let body = value_string(&value, &["body", "preview", "summary"])
        .unwrap_or_else(|| "Notification".to_owned());
    let space_id = value_string(&value, &["space_id"]).unwrap_or_default();
    let timestamp = value_string(&value, &["timestamp", "created_at"])
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

    Some(Notification {
        id,
        title,
        body,
        space_id,
        kind: kind.clone(),
        read: value_bool(&value, "read").unwrap_or(client_state.read),
        archived: value_bool(&value, "archived").unwrap_or(client_state.archived),
        timestamp,
        action_label: Some(default_notification_action(&kind).to_owned()),
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
        "invite" => "Space invite".to_owned(),
        "reaction" => "New reaction".to_owned(),
        "mention" => "You were mentioned".to_owned(),
        _ => "New message".to_owned(),
    }
}

fn default_notification_action(kind: &str) -> &'static str {
    match kind {
        "invite" => "Review",
        _ => "View",
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
        .unwrap_or_else(|| value.get("encrypted_payload").is_some());
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
        space_id: value_string(value, &["space_id"]).unwrap_or_default(),
        flow_id: value_string(value, &["flow_id"]),
        flow_track: value_string(value, &["flow_track", "track_name"]),
        sender: value_string(value, &["sender", "sender_did", "actor_id"]),
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
        now_minutes: None,
    }
}

fn space_is_muted(local_state: &ClientLocalState, space_id: &str) -> bool {
    !space_id.is_empty()
        && local_state
            .muted_spaces
            .get(space_id)
            .copied()
            .unwrap_or(false)
}

fn notification_kind_enabled(local_state: &ClientLocalState, kind: &str) -> bool {
    local_state
        .muted_notification_kinds
        .get(kind)
        .copied()
        .unwrap_or(true)
}

fn notification_overrides_space_mute(notification: &Notification) -> bool {
    matches!(
        notification.kind.as_str(),
        "mention" | "priority" | "critical" | "urgent"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hydrate_notifications_applies_push_rules_and_dnd() {
        let raw = vec![json!({
            "notification_id": "n1",
            "kind": "cx.notification",
            "notification_type": "message",
            "space_id": "cx:space:quiet",
            "body": "hello"
        })];
        let rules = crate::notification_rules::parse_push_rules(&json!({
            "rules": [{
                "rule_id": "override.quiet",
                "conditions": [
                    {"kind": "field_match", "field": "space_id", "pattern": "cx:space:quiet"}
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
    fn notification_eval_context_extracts_watch_and_e2ee_flags() {
        let ctx = notification_eval_context(&json!({
            "notification_id": "n1",
            "event_kind": "cx.message.create",
            "notification_type": "mention",
            "space_id": "cx:space:e2ee",
            "flow_id": "cx:flow:1",
            "track_name": "discussion",
            "watch_state": "participating",
            "encrypted": true,
            "local_decrypted": false,
            "mentions_actor": true
        }));

        assert_eq!(ctx.event_kind, "cx.message.create");
        assert_eq!(ctx.notification_type, "mention");
        assert_eq!(ctx.flow_track.as_deref(), Some("discussion"));
        assert_eq!(ctx.watch_level, Some(WatchLevel::Participating));
        assert!(ctx.is_e2ee);
        assert!(!ctx.local_decrypted);
        assert_eq!(ctx.mentions_actor, Some(true));
    }
}
