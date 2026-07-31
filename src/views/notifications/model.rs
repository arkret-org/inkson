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

use crate::models::AccountSyncStep;
use crate::notification_rules::{
    DndSettings, NotificationEvalContext, PushRulesConfig, WatchLevel, evaluate_notification,
};
#[cfg(test)]
pub(crate) use crate::state::projection::notifications::actor_is_joined_member;
// Notification wire-payload projection primitives now live in the sync
// projection layer (`projection::notifications`, YGN-ARCH-01 step 3). They
// are re-exported here so the notification view's other call sites and the
// crate-level `views::notifications::*` re-export keep resolving unchanged.
pub(crate) use crate::state::projection::notifications::{
    JoinedRealmIds, append_invite_notifications, default_notification_title,
    drop_joined_invite_notifications, invite_notification_target_for_dedupe,
    merge_invite_notifications, notification_id_for_dedupe, notification_kind_wire,
    raw_notifications_from_sources, realm_title_hints_from_invites,
};
use crate::state::{ClientLocalState, LocalStateStore, StoredNotification};

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
        invite_token: Option<String>,
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
    let mut latest_by_scope = BTreeMap::<(String, Option<String>), UiNotificationReadTarget>::new();
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
        let key = (target.realm_id.clone(), target.strand_id.clone());
        match latest_by_scope.get(&key) {
            Some(existing) if existing.timestamp >= target.timestamp => {}
            _ => {
                latest_by_scope.insert(key, target);
            }
        }
    }
    latest_by_scope.into_values().collect()
}

pub(crate) fn notification_value_read_by_cursor(
    _index: usize,
    value: &StoredNotification,
    local_state: &ClientLocalState,
) -> bool {
    let Some(source_event_id) = value.source_event_id() else {
        return false;
    };
    read_cursor_covers_notification(
        local_state,
        value.realm_id().unwrap_or_default(),
        value.strand_id(),
        source_event_id,
    )
}

pub(crate) fn apply_sync_projection_to_store(
    store: &mut LocalStateStore,
    response: &AccountSyncStep,
    realm_title_hints: &BTreeMap<String, String>,
) {
    store.save_sync_cursor(response.cursor.clone());
    for (id, body) in &response.realm_projections {
        let projection = crate::realm_tree::projection_with_title_hint(
            id,
            body,
            realm_title_hints.get(id).map(String::as_str),
        );
        store.save_realm_tree_projection(id.clone(), projection);
        store.save_realm_collaboration_role(id.clone(), response.collaboration_role(id));
        store.merge_realm_seal_view_from_sync_body(id, body);
        store.ingest_move_event_states(id, body);
    }
}

#[cfg(test)]
pub(crate) fn hydrate_notifications(
    raw_notifications: Vec<StoredNotification>,
    local_state: &ClientLocalState,
    push_rules: Option<&PushRulesConfig>,
    dnd: Option<&DndSettings>,
) -> Vec<UiNotification> {
    hydrate_notifications_with_privacy_gate(
        raw_notifications,
        local_state,
        "",
        push_rules,
        dnd,
        &crate::sidecar::SidecarPrivacyGate::default(),
    )
}

#[cfg(test)]
pub(crate) fn hydrate_notifications_for_actor(
    raw_notifications: Vec<StoredNotification>,
    local_state: &ClientLocalState,
    actor_id: &str,
) -> Vec<UiNotification> {
    hydrate_notifications_with_privacy_gate(
        raw_notifications,
        local_state,
        actor_id,
        None,
        None,
        &crate::sidecar::SidecarPrivacyGate::default(),
    )
}

pub(crate) fn hydrate_notifications_with_privacy_gate(
    raw_notifications: Vec<StoredNotification>,
    local_state: &ClientLocalState,
    actor_id: &str,
    push_rules: Option<&PushRulesConfig>,
    dnd: Option<&DndSettings>,
    sidecar_privacy_gate: &crate::sidecar::SidecarPrivacyGate,
) -> Vec<UiNotification> {
    let joined_realms =
        JoinedRealmIds::from_local_projections(&local_state.realm_tree_projections, actor_id);
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
            notification_from_stored(
                index,
                value,
                local_state,
                push_rules,
                dnd,
                sidecar_privacy_gate,
            )
        })
        .collect::<Vec<_>>();
    apply_read_cursors_to_notifications(&mut notifications, local_state);
    notifications
}

fn notification_from_stored(
    _index: usize,
    value: StoredNotification,
    local_state: &ClientLocalState,
    push_rules: Option<&PushRulesConfig>,
    dnd: Option<&DndSettings>,
    sidecar_privacy_gate: &crate::sidecar::SidecarPrivacyGate,
) -> Option<UiNotification> {
    if value.strand_id().is_some_and(|strand_id| {
        !sidecar_privacy_gate.allows_strand(
            crate::sidecar::SidecarDisclosureSurface::Notification,
            strand_id,
        )
    }) || !sidecar_privacy_gate.allows_serialized(
        crate::sidecar::SidecarDisclosureSurface::Notification,
        &value,
    ) {
        return None;
    }
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

    let id = value.notification_id();
    let source_event_id = value.source_event_id().map(ToOwned::to_owned);
    let strand_id = value.strand_id().map(ToOwned::to_owned);
    let client_state = local_state.notification_client_state.get(&id).cloned();
    let kind = notification_kind_wire(&value.notification_kind()).to_owned();
    let title = notification_title(&value, &kind);
    let body = notification_body(&value);
    let realm_id = value.realm_id().unwrap_or_default().to_owned();
    let realm_label = notification_realm_label(&value);
    let action = value
        .invite()
        .map(|invite| UiNotificationAction::AcceptInvite {
            realm_id: invite.realm_id.as_str().to_owned(),
            invite_id: invite.invite_id.as_str().to_owned(),
            invite_token: invite.invite_token.clone(),
            realm_label: invite.realm_label.clone(),
        });
    let timestamp = arkret_sdk::canonical::format_timestamp_canonical(value.created_at());
    let (projection_read, projection_archived) = notification_wire_state(&value);

    Some(UiNotification {
        id,
        source_event_id,
        title,
        body,
        realm_id,
        strand_id,
        realm_label,
        kind: kind.clone(),
        read: projection_read
            || client_state
                .as_ref()
                .map(|state| state.read)
                .unwrap_or(false),
        archived: projection_archived
            || client_state
                .as_ref()
                .map(|state| state.archived)
                .unwrap_or(false),
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
                marker.body.read_scope.kind.as_str(),
                marker.body.read_scope.container_ref.as_deref(),
            )
            && read_cursor_position_covers_event(
                source_event_id,
                notification_timestamp,
                marker.body.position.event_id.as_str(),
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
                .or_else(|| crate::state::read_scope_for_cursor(realm_id, None).container_ref);
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
    false
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

fn notification_preview(value: &StoredNotification) -> Option<&BTreeMap<String, Value>> {
    match value {
        StoredNotification::Event { notification } => notification.preview.as_ref(),
        StoredNotification::AgentRuntimeApproval { .. } | StoredNotification::Invite { .. } => None,
    }
}

fn preview_bool(value: &StoredNotification, key: &str) -> Option<bool> {
    notification_preview(value)?
        .get(key)
        .and_then(Value::as_bool)
}

fn preview_string(value: &StoredNotification, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        notification_preview(value)?
            .get(*key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    })
}

fn preview_u32(value: &StoredNotification, key: &str) -> Option<u32> {
    notification_preview(value)?
        .get(key)
        .and_then(|field| field.as_u64())
        .and_then(|field| u32::try_from(field).ok())
}

pub(crate) fn notification_eval_context(value: &StoredNotification) -> NotificationEvalContext {
    let notification_kind = notification_kind_wire(&value.notification_kind()).to_owned();
    let event_kind =
        preview_string(value, &["event_kind"]).unwrap_or_else(|| notification_kind.clone());
    let is_e2ee = preview_bool(value, "is_e2ee")
        .or_else(|| preview_bool(value, "encrypted"))
        .unwrap_or(false);
    let priority = match value {
        StoredNotification::Event { notification } => Some(
            match notification.priority {
                arkret_sdk::NotificationPriority::Low => "low",
                arkret_sdk::NotificationPriority::Normal => "normal",
                arkret_sdk::NotificationPriority::High => "high",
                arkret_sdk::NotificationPriority::Urgent => "urgent",
            }
            .to_owned(),
        ),
        StoredNotification::AgentRuntimeApproval { .. } | StoredNotification::Invite { .. } => None,
    };
    let priority_override = preview_bool(value, "priority_override").unwrap_or_else(|| {
        priority
            .as_deref()
            .is_some_and(|value| matches!(value, "critical" | "high" | "urgent" | "priority"))
    });
    NotificationEvalContext {
        event_kind,
        notification_kind,
        realm_id: value.realm_id().unwrap_or_default().to_owned(),
        strand_id: value.strand_id().map(ToOwned::to_owned),
        strand_track: preview_string(value, &["strand_track", "track_name"]),
        sender: match value {
            StoredNotification::Event { notification } => {
                Some(notification.actor_id.as_str().to_owned())
            }
            StoredNotification::AgentRuntimeApproval { .. } | StoredNotification::Invite { .. } => {
                None
            }
        },
        body: preview_string(value, &["body", "summary"]),
        is_e2ee,
        local_decrypted: preview_bool(value, "local_decrypted").unwrap_or(!is_e2ee),
        mentions_actor: preview_bool(value, "mentions_actor"),
        assigned_to_actor: preview_bool(value, "assigned_to_actor").unwrap_or(false),
        schedule_target: preview_bool(value, "schedule_target").unwrap_or(false),
        reply_to_self: preview_bool(value, "reply_to_self").unwrap_or(false),
        participating_thread_update: preview_bool(value, "participating_thread_update")
            .unwrap_or(false),
        is_direct_message: preview_bool(value, "is_direct_message").unwrap_or(false),
        member_count: preview_u32(value, "member_count"),
        priority,
        priority_override,
        watch_level: preview_string(value, &["watch_state", "watch_level"])
            .and_then(|level| WatchLevel::from_wire(&level)),
        // Filled by the caller from the receiver's per-realm override; left
        // `None` here so a bare context never resolves to a watch level.
        realm_watch_level: None,
        now_minutes: None,
    }
}

fn notification_title(value: &StoredNotification, kind: &str) -> String {
    match value {
        StoredNotification::Event { .. } => preview_string(value, &["title"])
            .unwrap_or_else(|| default_notification_title(kind).to_owned()),
        StoredNotification::AgentRuntimeApproval { .. } => "Agent runtime approval".to_owned(),
        StoredNotification::Invite { .. } => default_notification_title("invite").to_owned(),
    }
}

fn notification_body(value: &StoredNotification) -> String {
    match value {
        StoredNotification::Event { .. } => {
            preview_string(value, &["body", "summary"]).unwrap_or_else(|| "Notification".to_owned())
        }
        StoredNotification::AgentRuntimeApproval { data, .. } => {
            format!("Approve a runtime key for {}.", data.agent_id.as_str())
        }
        StoredNotification::Invite { invite } => invite
            .realm_label
            .as_deref()
            .map(|title| format!("You were invited to join {title}."))
            .unwrap_or_else(|| "You were invited to join a Realm.".to_owned()),
    }
}

fn notification_realm_label(value: &StoredNotification) -> Option<String> {
    match value {
        StoredNotification::Event { .. } => preview_string(value, &["realm_label", "realm_title"]),
        StoredNotification::AgentRuntimeApproval { .. } => None,
        StoredNotification::Invite { invite } => invite.realm_label.clone(),
    }
}

pub(crate) fn notification_wire_state(value: &StoredNotification) -> (bool, bool) {
    match value {
        StoredNotification::Event { notification } => match notification.state {
            arkret_sdk::NotificationState::Unread => (false, false),
            arkret_sdk::NotificationState::Read => (true, false),
            arkret_sdk::NotificationState::Dismissed | arkret_sdk::NotificationState::Archived => {
                (true, true)
            }
        },
        StoredNotification::AgentRuntimeApproval { .. } | StoredNotification::Invite { .. } => {
            (false, false)
        }
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
    matches!(ctx.notification_kind.as_str(), "invite")
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
