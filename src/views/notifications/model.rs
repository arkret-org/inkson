//! Notifications - data types plus the pure hydration / projection /
//! value-extraction helpers shared by the panel and the action handlers.
//!
//! Everything here is free of `spawn`/IO; the network-driven handlers
//! live in [`super::actions`] and the RSX surface in [`super::panel`].

use std::collections::{BTreeMap, BTreeSet};

use cokret_sdk::push_rule_core::{
    EventContext as PushRuleEventContext, ShouldNotify, evaluate_watch_level,
    reason_code as push_rule_reason_code,
};
use serde_json::{Value, json};

use crate::local_state::{ClientLocalState, LocalSealView, LocalStateStore};
use crate::models::ClientSyncOutcome;
use crate::notification_rules::{
    DndSettings, NotificationEvalContext, PushRulesConfig, WatchLevel, evaluate_notification,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UiNotificationGroup {
    Latest,
    ByRealm,
    ByType,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum UiNotificationAction {
    AcceptInvite {
        realm_id: String,
        invite_id: String,
        realm_label: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct UiNotification {
    pub(crate) id: String,
    pub(crate) source_event_id: Option<String>,
    pub(crate) title: String,
    pub(crate) body: String,
    pub(crate) realm_id: String,
    pub(crate) strand_id: Option<String>,
    pub(crate) realm_label: Option<String>,
    pub(crate) kind: String,
    pub(crate) read: bool,
    pub(crate) archived: bool,
    pub(crate) timestamp: String,
    pub(crate) action_label: Option<String>,
    pub(crate) action: Option<UiNotificationAction>,
    /// T4.4 — User-facing hint surfaced when the watch level
    /// suppressed delivery (e.g. "You're not getting notifications
    /// for this discussion — change watch level"). `None` for
    /// notifications that pass the watch-level filter normally.
    pub(crate) watch_hint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UiNotificationReadTarget {
    pub(crate) realm_id: String,
    pub(crate) strand_id: Option<String>,
    pub(crate) event_id: String,
    pub(crate) timestamp: String,
}

pub(crate) fn read_cursor_targets(
    notifications: &[UiNotification],
) -> Vec<UiNotificationReadTarget> {
    let mut latest_by_realm = BTreeMap::<String, UiNotificationReadTarget>::new();
    for notification in notifications {
        let Some(event_id) = notification.source_event_id.clone() else {
            continue;
        };
        if notification.realm_id.trim().is_empty() {
            continue;
        }
        let target = UiNotificationReadTarget {
            realm_id: notification.realm_id.clone(),
            strand_id: notification.strand_id.clone(),
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

pub(crate) fn is_notification_account_data(value: &Value) -> bool {
    value.get("schema").and_then(Value::as_str) == Some("ck.schema.notification.v1")
}

pub(crate) fn raw_notifications_from_sources(
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

pub(crate) fn append_invite_notifications(
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

pub(crate) fn notification_id_for_dedupe(value: &Value) -> Option<String> {
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

pub(crate) fn drop_joined_invite_notifications(
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

pub(crate) fn joined_realm_ids(response: &ClientSyncOutcome) -> BTreeSet<String> {
    response.realms.keys().cloned().collect()
}

pub(crate) fn apply_sync_projection_to_store(
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

pub(crate) fn hydrate_notifications(
    raw_notifications: Vec<Value>,
    local_state: &ClientLocalState,
    push_rules: Option<&PushRulesConfig>,
    dnd: Option<&DndSettings>,
) -> Vec<UiNotification> {
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
) -> Option<UiNotification> {
    let mut eval_ctx = notification_eval_context(&value);
    if eval_ctx.sender.as_deref().is_some_and(|sender| {
        crate::account_data::is_blocked(&local_state.client_blocklist, sender)
    }) {
        return None;
    }
    // Apply the receiver's per-realm watch override (None when unconfigured).
    // Invites and directed overrides are exempt: invites can target a realm the
    // receiver is not currently in, and mentions/priority notifications are the
    // explicit spec exceptions that must survive a coarse realm mute. Event-level
    // `watch_state=muted` still short-circuits because `watch_level` is more
    // specific than this realm override.
    eval_ctx.realm_watch_level = if eval_context_overrides_realm_mute(&eval_ctx) {
        None
    } else {
        realm_watch_override(local_state, &eval_ctx.realm_id)
    };
    let decision = evaluate_notification(push_rules, dnd, &eval_ctx);

    // T4.4 — When the watch level (not DND, not muted-short-circuit)
    // is the reason we'd drop this entry, keep it in the list with a
    // small inline hint so the user can change watch level. Muted
    // strands still drop (they signal explicit user intent) and DND
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
    let strand_id = value_string_with_prefix(
        &value,
        &["strand_id", "target_strand_id", "space_id"],
        "ck:strand:",
    );
    let client_state = local_state.notification_client_state.get(&id).cloned();
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
                Some(UiNotificationAction::AcceptInvite {
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

    Some(UiNotification {
        id,
        source_event_id,
        title,
        body,
        realm_id,
        strand_id,
        realm_label,
        kind: kind.clone(),
        read: client_state
            .as_ref()
            .map(|state| state.read)
            .unwrap_or_else(|| value_bool(&value, "read").unwrap_or(false)),
        archived: client_state
            .as_ref()
            .map(|state| state.archived)
            .unwrap_or_else(|| value_bool(&value, "archived").unwrap_or(false)),
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

pub(crate) fn notification_scope_kind(notification: &UiNotification) -> &'static str {
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

pub(crate) fn notification_eval_context(value: &Value) -> NotificationEvalContext {
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
        strand_id: value_string(value, &["strand_id"]),
        strand_track: value_string(value, &["strand_track", "track_name"]),
        // Canonical notification attribution comes from the SDK Event
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

fn eval_context_overrides_realm_mute(ctx: &NotificationEvalContext) -> bool {
    matches!(
        ctx.notification_type.as_str(),
        "invite" | "mention" | "priority" | "critical" | "urgent"
    ) || ctx.mentions_actor.unwrap_or(false)
        || ctx.priority_override
}

pub(crate) fn realm_is_muted(local_state: &ClientLocalState, realm_id: &str) -> bool {
    realm_watch_override(local_state, realm_id) == Some(WatchLevel::Muted)
}

pub(crate) fn notification_kind_enabled(local_state: &ClientLocalState, kind: &str) -> bool {
    local_state
        .muted_notification_kinds
        .get(kind)
        .copied()
        .unwrap_or(true)
}

pub(crate) fn notification_overrides_realm_mute(notification: &UiNotification) -> bool {
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
