//! Notification wire-payload projection primitives (YGN-ARCH-01 step 3,
//! pure move from `views/notifications/model.rs`, zero behavior change).
//!
//! These are the IO-free / RSX-free helpers that fold notification and
//! invite wire payloads into the local `Vec<Value>` notification
//! projection. They are consumed by the sync layer (`sync_engine`,
//! `app::connect`) and re-exported from `views::notifications::model` so
//! the notification view keeps its existing intra-module call sites. This
//! module contains no Dioxus state and no rendering.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

pub(crate) fn is_notification_account_data(value: &Value) -> bool {
    value.get("schema").and_then(Value::as_str) == Some("ak.schema.notification.v1")
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
        // i18n key — translated at render via `tr()` (see
        // `default_notification_title`).
        "title": default_notification_title("invite"),
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

pub(crate) fn invite_notification_target_for_dedupe(value: &Value) -> Option<String> {
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
        .any(|kind| matches!(kind, "invite" | "ak.invite" | "ck.invite.create"))
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

/// i18n KEY for the default notification title of `kind`. The model layer
/// stores the key in `UiNotification::title` (server-provided titles are
/// stored verbatim); render sites pass the field through `tr()`, which
/// translates dictionary keys and returns unknown strings unchanged.
/// Shared with the dashboard's recent-notifications card (single source for
/// the kind → default-title table).
pub(crate) fn default_notification_title(kind: &str) -> &'static str {
    match kind {
        "invite" => "notifications.default_title.invite",
        "reaction" => "notifications.default_title.reaction",
        "mention" => "notifications.default_title.mention",
        "assignment" => "notifications.default_title.assignment",
        "schedule" => "notifications.default_title.schedule",
        _ => "notifications.default_title.message",
    }
}

/// First string field found under any of `keys`. Shared with the dashboard's
/// recent-notifications card (single source, see YGN-DRY-05).
pub(crate) fn value_string(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(|field| field.as_str())
            .map(ToOwned::to_owned)
    })
}

pub(crate) fn value_string_with_prefix(
    value: &Value,
    keys: &[&str],
    prefix: &str,
) -> Option<String> {
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
