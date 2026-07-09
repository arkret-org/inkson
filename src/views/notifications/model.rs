//! Notifications - data types plus the pure hydration / projection /
//! value-extraction helpers shared by the panel and the action handlers.
//!
//! Everything here is free of `spawn`/IO; the network-driven handlers
//! live in [`super::actions`] and the RSX surface in [`super::panel`].

use std::collections::{BTreeMap, BTreeSet};

use arkret_sdk::push_rule_core::{
    EventContext as PushRuleEventContext, ShouldNotify, evaluate_watch_level,
    reason_code as push_rule_reason_code,
};
use serde_json::Value;

use crate::local_state::{ClientLocalState, LocalSealView, LocalStateStore};
use crate::models::ClientSyncOutcome;
use crate::notification_rules::{
    DndSettings, NotificationEvalContext, PushRulesConfig, WatchLevel, evaluate_notification,
};
// Notification wire-payload projection primitives now live in the sync
// projection layer (`projection::notifications`, YGN-ARCH-01 step 3). They
// are re-exported here so the notification view's other call sites and the
// crate-level `views::notifications::*` re-export keep resolving unchanged.
pub(crate) use crate::projection::notifications::{
    append_invite_notifications, default_notification_title, drop_joined_invite_notifications,
    invite_notification_target_for_dedupe, merge_invite_notifications, notification_id_for_dedupe,
    raw_notifications_from_sources, realm_title_hints_from_values, value_string,
    value_string_with_prefix,
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

pub(crate) fn notification_value_read_by_cursor(
    index: usize,
    value: &Value,
    local_state: &ClientLocalState,
) -> bool {
    let id = notification_id_from_value(index, value);
    let Some(source_event_id) = notification_source_event_id_from_value(value, &id) else {
        return false;
    };
    let realm_id = value_string(value, &["realm_id"]).unwrap_or_default();
    let strand_id = value_string_with_prefix(
        value,
        &["strand_id", "target_strand_id", "space_id"],
        "ak:strand:",
    );
    read_cursor_covers_notification(
        local_state,
        &realm_id,
        strand_id.as_deref(),
        &source_event_id,
    )
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
    let mut notifications = raw_notifications
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
        .collect::<Vec<_>>();
    apply_read_cursors_to_notifications(&mut notifications, local_state);
    notifications
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
    // Invites are exempt because they can target a realm the receiver is not
    // currently in; directed message notifications still respect `muted`.
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

    let id = notification_id_from_value(index, &value);
    let source_event_id = notification_source_event_id_from_value(&value, &id);
    let strand_id = value_string_with_prefix(
        &value,
        &["strand_id", "target_strand_id", "space_id"],
        "ak:strand:",
    );
    let client_state = local_state.notification_client_state.get(&id).cloned();
    let kind = value_string(
        &value,
        &["notification_type", "notification_kind", "type", "kind"],
    )
    .unwrap_or_else(|| "message".to_owned());
    let title = value_string(&value, &["title"])
        .unwrap_or_else(|| default_notification_title(&kind).to_owned());
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

fn apply_read_cursors_to_notifications(
    notifications: &mut [UiNotification],
    local_state: &ClientLocalState,
) {
    let target_timestamp_by_event = notifications
        .iter()
        .filter_map(|notification| {
            let event_id = notification.source_event_id.as_ref()?;
            Some((event_id.clone(), notification.timestamp.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    for notification in notifications {
        let Some(source_event_id) = notification.source_event_id.as_deref() else {
            continue;
        };
        if read_cursor_covers_notification_at(
            local_state,
            &notification.realm_id,
            notification.strand_id.as_deref(),
            source_event_id,
            &notification.timestamp,
            &target_timestamp_by_event,
        ) {
            notification.read = true;
        }
    }
}

fn notification_id_from_value(index: usize, value: &Value) -> String {
    value_string(value, &["notification_id", "id"])
        .unwrap_or_else(|| format!("notification-{index}"))
}

fn notification_source_event_id_from_value(value: &Value, id: &str) -> Option<String> {
    value_string_with_prefix(
        value,
        &[
            "source_event_id",
            "event_id",
            "target_event_id",
            "message_event_id",
            "timeline_event_id",
        ],
        "ak:event:",
    )
    .or_else(|| id.strip_prefix("ak:event:").map(|_| id.to_owned()))
}

fn read_cursor_covers_notification(
    local_state: &ClientLocalState,
    realm_id: &str,
    strand_id: Option<&str>,
    source_event_id: &str,
) -> bool {
    read_cursor_covers_notification_at(
        local_state,
        realm_id,
        strand_id,
        source_event_id,
        "",
        &BTreeMap::new(),
    )
}

fn read_cursor_covers_notification_at(
    local_state: &ClientLocalState,
    realm_id: &str,
    strand_id: Option<&str>,
    source_event_id: &str,
    notification_timestamp: &str,
    target_timestamp_by_event: &BTreeMap<String, String>,
) -> bool {
    if realm_id.trim().is_empty() || source_event_id.trim().is_empty() {
        return false;
    }
    local_state.read_cursors.values().any(|marker| {
        marker.body.realm_id == realm_id
            && read_scope_covers_notification(
                realm_id,
                strand_id,
                &marker.body.read_scope.kind,
                marker.body.read_scope.object_ref.as_deref(),
            )
            && read_cursor_position_covers_event(
                source_event_id,
                notification_timestamp,
                &marker.body.position.event_id,
                target_timestamp_by_event,
            )
    })
}

fn read_scope_covers_notification(
    realm_id: &str,
    strand_id: Option<&str>,
    scope_kind: &str,
    scope_ref: Option<&str>,
) -> bool {
    match scope_kind {
        "realm" => true,
        "strand" => {
            let notification_strand = strand_id
                .map(ToOwned::to_owned)
                .or_else(|| crate::local_state::read_scope_for_cursor(realm_id, None).object_ref);
            scope_ref == notification_strand.as_deref()
        }
        _ => false,
    }
}

fn read_cursor_position_covers_event(
    source_event_id: &str,
    notification_timestamp: &str,
    cursor_event_id: &str,
    target_timestamp_by_event: &BTreeMap<String, String>,
) -> bool {
    if source_event_id == cursor_event_id {
        return true;
    }
    if let Some(target_timestamp) = target_timestamp_by_event.get(cursor_event_id)
        && !notification_timestamp.is_empty()
    {
        return notification_timestamp <= target_timestamp.as_str();
    }
    source_event_id <= cursor_event_id
}

/// T4.4 — Resolve the wire-safe reason code for a watch-suppressed
/// notification through the shared SDK `evaluate_watch_level`
/// helper, then map that to a localised UI string.
///
/// Routing the decision through the shared client helper (instead of
/// reading the reason from inkson's richer evaluator directly) keeps
/// the UI surface aligned with what the Sync Service would have
/// returned, so the same `(watch_level, event)` pair never produces
/// different copy across surfaces.
fn watch_hint_for_event(ctx: &NotificationEvalContext) -> String {
    // Default to `MentionsOnly` to match the inkson evaluator's
    // default; cosmetic only since the caller already established
    // `watch_suppressed=true`.
    let core_level = ctx.watch_level.unwrap_or_default();
    let core_ctx = PushRuleEventContext {
        mentions_actor: ctx.mentions_actor.unwrap_or(false),
        assigned_to_actor: ctx.assigned_to_actor || ctx.schedule_target,
        reply_to_self: ctx.reply_to_self,
        participating_thread_update: ctx.participating_thread_update,
        is_e2ee: ctx.is_e2ee,
        local_decrypted: ctx.local_decrypted,
    };
    let (decision, reason) = evaluate_watch_level(core_level, &core_ctx);

    // Even if the core says "Notify" (the inputs disagree with the
    // inkson evaluator's richer rules), still surface a generic
    // change-watch-level hint so the UI stays consistent with what
    // the user observed.
    //
    // Returns an i18n KEY (not final copy): model helpers must stay
    // runtime-free, so translation happens at render via `tr()`.
    match (decision, reason) {
        (ShouldNotify::DontNotify, push_rule_reason_code::NOT_MENTIONED) => {
            "notifications.watch_hint.not_mentioned".to_owned()
        }
        (ShouldNotify::DontNotify, push_rule_reason_code::NOT_PARTICIPATING) => {
            "notifications.watch_hint.not_participating".to_owned()
        }
        _ => "notifications.watch_hint.limited".to_owned(),
    }
}

/// i18n KEY for the default action button label of `kind` (see
/// [`default_notification_title`] for the key-through-`tr()` convention).
fn default_notification_action(kind: &str) -> &'static str {
    match kind {
        "invite" => "notifications.default_action.accept",
        _ => "notifications.default_action.view",
    }
}

pub(crate) fn notification_scope_kind(notification: &UiNotification) -> &'static str {
    if notification.kind == "invite" {
        "Realm"
    } else {
        "Space"
    }
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
        schedule_target: value_bool(value, "schedule_target").unwrap_or(false),
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
    matches!(ctx.notification_type.as_str(), "invite")
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
        "invite"
    )
}
