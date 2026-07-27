//! Typed notification projection and reducer.
//!
//! Wire `NotificationDelta` values are never persisted as current
//! notifications. Event notifications, open Agent approvals, and pending
//! invites are represented by separate enum branches and folded by the single
//! reducer in this module.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::governance::operation_wire::Invite;
use arkret_sdk::{
    Notification, NotificationData, NotificationDelta, NotificationDeltaAction, NotificationKind,
};
use serde_json::Value;

use crate::state::{StoredInviteNotification, StoredNotification};

pub(crate) fn notification_kind_wire(kind: &NotificationKind) -> &'static str {
    match kind {
        NotificationKind::Message => "message",
        NotificationKind::Mention => "mention",
        NotificationKind::Reply => "reply",
        NotificationKind::Assignment => "assignment",
        NotificationKind::Schedule => "schedule",
        NotificationKind::Invite => "invite",
        NotificationKind::Reaction => "reaction",
        NotificationKind::Policy => "policy",
        NotificationKind::Call => "call",
        NotificationKind::Applet => "applet",
        NotificationKind::Agent => "agent",
        NotificationKind::Moderation => "moderation",
        NotificationKind::System => "system",
    }
}

fn account_event_notification(event: &arkret_sdk::Event) -> Option<StoredNotification> {
    let notification =
        serde_json::from_value::<Notification>(serde_json::to_value(&event.payload).ok()?).ok()?;
    Some(StoredNotification::Event { notification })
}

fn invite_notification(invite: Invite) -> StoredNotification {
    let realm_label = invite
        .join_rule_snapshot
        .get("realm_title")
        .or_else(|| invite.join_rule_snapshot.get("title"))
        .or_else(|| {
            invite
                .join_rule_snapshot
                .get("summary")
                .and_then(|summary| summary.get("title"))
        })
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|title| !title.is_empty())
        .map(ToOwned::to_owned);
    let invite_token = invite
        .join_rule_snapshot
        .get("invite_token")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    StoredNotification::Invite {
        invite: StoredInviteNotification {
            invite_id: invite.id,
            realm_id: invite.realm_id,
            invite_token,
            realm_label,
            created_at: invite.created_at,
        },
    }
}

/// Fold all notification sources into one current projection.
///
/// A full account snapshot replaces Event notifications and resets the open
/// Agent approval branch before applying the supplied deltas. Incremental
/// frames only replace Event notifications when the frame actually carries a
/// typed notification account-data payload.
pub(crate) fn apply_notification_projection(
    current: &mut Vec<StoredNotification>,
    deltas: &[NotificationDelta],
    account_data: &[arkret_sdk::Event],
    is_full_sync: bool,
    invites: Option<Vec<Invite>>,
    joined_realms: &BTreeSet<String>,
) {
    let event_notifications = account_data
        .iter()
        .filter_map(account_event_notification)
        .collect::<Vec<_>>();
    if is_full_sync || !event_notifications.is_empty() {
        current.retain(|item| !matches!(item, StoredNotification::Event { .. }));
        current.extend(event_notifications);
    }
    if is_full_sync {
        current.retain(|item| !matches!(item, StoredNotification::AgentRuntimeApproval { .. }));
    }
    for delta in deltas {
        let id = delta.id.as_str();
        match (delta.action, delta.data.as_ref()) {
            (
                NotificationDeltaAction::Add | NotificationDeltaAction::Update,
                Some(NotificationData::AgentRuntimeApproval(data)),
            ) => {
                let replacement = StoredNotification::AgentRuntimeApproval {
                    id: delta.id.clone(),
                    data: data.clone(),
                };
                if let Some(existing) = current
                    .iter_mut()
                    .find(|candidate| candidate.notification_id() == id)
                {
                    *existing = replacement;
                } else {
                    current.push(replacement);
                }
            }
            (NotificationDeltaAction::Remove, _) => {
                current.retain(|candidate| candidate.notification_id() != id);
            }
            _ => {
                tracing::error!(
                    notification_id = id,
                    "SDK admitted an invalid notification delta branch"
                );
            }
        }
    }
    if let Some(invites) = invites {
        current.retain(|item| {
            item.invite()
                .is_none_or(|invite| !joined_realms.contains(invite.realm_id.as_str()))
        });
        let mut existing_realms = current
            .iter()
            .filter_map(StoredNotification::invite)
            .map(|invite| invite.realm_id.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        for invite in invites {
            if joined_realms.contains(invite.realm_id.as_str())
                || !existing_realms.insert(invite.realm_id.as_str().to_owned())
            {
                continue;
            }
            current.push(invite_notification(invite));
        }
    }
}

pub(crate) fn raw_notifications_from_sources(
    notification_response: Option<&[NotificationDelta]>,
    account_data: &[arkret_sdk::Event],
) -> Vec<StoredNotification> {
    let mut projection = Vec::new();
    apply_notification_projection(
        &mut projection,
        notification_response.unwrap_or_default(),
        account_data,
        true,
        None,
        &BTreeSet::new(),
    );
    projection
}

pub(crate) fn append_invite_notifications(
    notifications: &mut Vec<StoredNotification>,
    invites: Vec<Invite>,
    hidden_realms: &BTreeSet<String>,
) {
    apply_notification_projection(notifications, &[], &[], false, Some(invites), hidden_realms);
}

pub(crate) fn merge_invite_notifications(
    notifications: &mut Vec<StoredNotification>,
    invites: Vec<Invite>,
    hidden_realms: &BTreeSet<String>,
) {
    append_invite_notifications(notifications, invites, hidden_realms);
}

pub(crate) fn drop_joined_invite_notifications(
    notifications: &mut Vec<StoredNotification>,
    joined_realms: &BTreeSet<String>,
) {
    notifications.retain(|notification| {
        notification
            .invite()
            .is_none_or(|invite| !joined_realms.contains(invite.realm_id.as_str()))
    });
}

pub(crate) fn notification_id_for_dedupe(value: &StoredNotification) -> Option<String> {
    Some(value.notification_id())
}

pub(crate) fn invite_notification_target_for_dedupe(value: &StoredNotification) -> Option<String> {
    value
        .invite()
        .map(|invite| invite.realm_id.as_str().to_owned())
}

pub(crate) fn realm_title_hints_from_invites(invites: &[Invite]) -> BTreeMap<String, String> {
    invites
        .iter()
        .filter_map(|invite| {
            let notification = invite_notification(invite.clone());
            let invite = notification.invite()?;
            Some((
                invite.realm_id.as_str().to_owned(),
                invite.realm_label.clone()?,
            ))
        })
        .collect()
}

/// i18n key for the default notification title.
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

pub(crate) fn event_preview_string(notification: &Notification, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        notification
            .preview
            .as_ref()?
            .get(*key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    })
}

#[cfg(test)]
pub(crate) fn test_event_notification(
    ordinal: u64,
    kind: NotificationKind,
    realm_id: &str,
    source_event_id: Option<&str>,
    preview: Value,
) -> StoredNotification {
    let source_event_id = source_event_id
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("ak:event:0196419b-0000-7000-8000-{ordinal:012x}"));
    StoredNotification::Event {
        notification: Notification {
            id: arkret_sdk::NotificationId::new(format!(
                "ak:notification:0196419b-0000-7000-8000-{ordinal:012x}"
            ))
            .expect("valid test notification id"),
            schema: arkret_sdk::NotificationSchema::V1,
            actor_id: arkret_sdk::Did::new("did:web:alice.example".to_owned())
                .expect("valid test actor"),
            source: arkret_sdk::NotificationSource::Event(arkret_sdk::NotificationEventSource {
                source_event_id: arkret_sdk::EventId::new(source_event_id)
                    .expect("valid test Event id"),
                realm_id: Some(
                    arkret_sdk::RealmId::new(realm_id.to_owned()).expect("valid test Realm id"),
                ),
                source_ref: None,
                strand_id: preview
                    .get("strand_id")
                    .and_then(Value::as_str)
                    .map(|value| {
                        arkret_sdk::StrandId::new(value.to_owned()).expect("valid test Strand id")
                    }),
                track_name: preview
                    .get("track_name")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
            }),
            notification_kind: kind,
            priority: arkret_sdk::NotificationPriority::Normal,
            state: arkret_sdk::NotificationState::Unread,
            preview: preview.as_object().map(|object| {
                object
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect()
            }),
            created_at: chrono::DateTime::parse_from_rfc3339("2026-05-29T00:00:00.000Z")
                .expect("valid test timestamp")
                .with_timezone(&chrono::Utc)
                + chrono::Duration::seconds(ordinal as i64),
            updated_at: None,
        },
    }
}

#[cfg(test)]
pub(crate) fn test_invite(
    ordinal: u64,
    realm_id: &str,
    realm_title: Option<&str>,
    invite_token: Option<&str>,
) -> Invite {
    let mut join_rule_snapshot = BTreeMap::new();
    if let Some(title) = realm_title {
        join_rule_snapshot.insert("title".to_owned(), Value::String(title.to_owned()));
    }
    if let Some(token) = invite_token {
        join_rule_snapshot.insert("invite_token".to_owned(), Value::String(token.to_owned()));
    }
    Invite {
        id: arkret_sdk::InviteId::new(format!("ak:invite:0196419b-0000-7000-8000-{ordinal:012x}"))
            .expect("valid test invite id"),
        schema: "ak.schema.invite.v1".to_owned(),
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned()).expect("valid test Realm id"),
        inviter: arkret_sdk::Did::new("did:web:alice.example".to_owned())
            .expect("valid test inviter"),
        invitee: None,
        invite_delivery_target: None,
        introduction_evidence_digest: None,
        third_party_id: None,
        join_rule_snapshot,
        capability_grant_refs: Vec::new(),
        state: arkret_sdk::InviteState::Pending,
        expires_at: chrono::DateTime::parse_from_rfc3339("2027-05-29T00:00:00.000Z")
            .expect("valid test timestamp")
            .with_timezone(&chrono::Utc),
        created_at: chrono::DateTime::parse_from_rfc3339("2026-05-29T00:00:00.000Z")
            .expect("valid test timestamp")
            .with_timezone(&chrono::Utc),
        updated_by: None,
        updated_at: None,
    }
}
