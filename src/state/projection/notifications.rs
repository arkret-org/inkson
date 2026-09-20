//! Typed notification projection and reducer.
//!
//! Wire `NotificationDelta` values are never persisted as current
//! notifications. Event notifications, open Agent approvals, and pending
//! invites are represented by separate enum branches and folded by the single
//! reducer in this module.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::governance::invite_addressing::InviteDeliveryEntry;
#[cfg(test)]
use arkret_models_collaboration::governance::operation_wire::Invite;
use arkret_sdk::sync::{
    NotificationData, NotificationDelta, NotificationDeltaAction, RealmSyncEntry,
};
use arkret_sdk::{MembershipState, Notification, NotificationKind, RealmId};
use serde::Deserialize;
use serde_json::Value;

use crate::state::{StoredInviteNotification, StoredNotification};

/// Host view of one member-roster row of a Realm sync entry.
///
/// The wire roster is carried as an opaque projection value, so this is the
/// closed shape the client is willing to read out of it. Anything that does not
/// parse leaves the Realm out of the joined set rather than granting membership
/// the client cannot prove.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct MemberRosterEntry {
    pub actor_id: arkret_sdk::ActorId,
    pub membership: MembershipState,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct MemberRosterView {
    #[serde(default)]
    entries: Vec<MemberRosterEntry>,
}

/// Realms whose typed roster records this actor's membership as exactly
/// `join`.
///
/// The set a projection map's keys describe is "Realms the server told us
/// about" — it includes discoverable previews and Realms this actor was only
/// invited or knocked into. Treating that set as membership is what once
/// deleted a pending invite notification before it could be folded. So the
/// distinction is carried by a type: the only ways to obtain this value are the
/// two constructors below, both of which read a typed `MemberRosterEntry`, and
/// neither of which will infer authorization from a projection merely existing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct JoinedRealmIds(BTreeSet<String>);

impl JoinedRealmIds {
    /// From the sync response's typed Realm roster.
    ///
    /// `actor` is this account's complete ActorId. Membership is judged on the
    /// whole value: the same principal joined at another Station is a different
    /// account, and treating its row as ours would hide a Realm invite this
    /// account never accepted (account-lifecycle.md §156).
    pub(crate) fn from_realm_entries(
        entries: &BTreeMap<RealmId, RealmSyncEntry>,
        actor: &arkret_sdk::ActorId,
    ) -> Self {
        Self(
            entries
                .iter()
                .filter(|(_, entry)| actor_is_joined_member(entry, actor))
                .map(|(realm_id, _)| realm_id.as_str().to_owned())
                .collect(),
        )
    }

    /// From locally stored Realm projections.
    ///
    /// Each roster member is deserialized into the SDK's `MemberRosterEntry`
    /// before it is judged; an entry that fails to parse leaves the Realm out of
    /// the joined set, so an unreadable roster keeps an invite visible rather
    /// than silently claiming an authorization it cannot prove.
    pub(crate) fn from_local_projections(
        projections: &BTreeMap<String, Value>,
        actor: Option<&arkret_sdk::ActorId>,
    ) -> Self {
        let Some(actor) = actor else {
            return Self::default();
        };
        Self(
            projections
                .iter()
                .filter(|(_, projection)| {
                    projection
                        .get("member_roster_entries")
                        .and_then(Value::as_array)
                        .is_some_and(|members| {
                            members.iter().any(|member| {
                                serde_json::from_value::<MemberRosterEntry>(member.clone())
                                    .is_ok_and(|member| {
                                        member.actor_id == *actor
                                            && member.membership == MembershipState::Join
                                    })
                            })
                        })
                })
                .map(|(realm_id, _)| realm_id.clone())
                .collect(),
        )
    }

    /// Record a Realm this actor has just joined.
    ///
    /// The accepted join transition is itself membership evidence, so an invite
    /// for that Realm must disappear immediately rather than waiting for the
    /// next roster snapshot to catch up.
    #[cfg(test)]
    pub(crate) fn joined_now(mut self, realm_id: String) -> Self {
        self.0.insert(realm_id);
        self
    }

    pub(crate) fn contains(&self, realm_id: &str) -> bool {
        self.0.contains(realm_id)
    }
}

pub(crate) fn actor_is_joined_member(entry: &RealmSyncEntry, actor: &arkret_sdk::ActorId) -> bool {
    entry
        .member_roster
        .as_ref()
        .and_then(|roster| serde_json::from_value::<MemberRosterView>(roster.clone()).ok())
        .is_some_and(|roster| {
            roster.entries.iter().any(|member| {
                member.actor_id == *actor && member.membership == MembershipState::Join
            })
        })
}

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

/// Project a newly received holder-private invite delivery into the local
/// notification inbox.
///
/// The delivery cell is the normative live notify carrier. It deliberately
/// does not contain the complete Invite object, but it does contain the stable
/// invite/Realm identities and the receipt timestamp needed by the inbox. A
/// drawer renders this durable local projection directly; it does not issue a
/// second authz Invite read to manufacture notification state.
pub(crate) fn upsert_invite_delivery_notification(
    current: &mut Vec<StoredNotification>,
    entry: &InviteDeliveryEntry,
) {
    current.retain(|candidate| {
        candidate.invite().is_none_or(|invite| {
            invite.invite_id != entry.invite_id && invite.realm_id != entry.realm_id
        })
    });
    current.push(StoredNotification::Invite {
        invite: StoredInviteNotification {
            invite_id: entry.invite_id.clone(),
            realm_id: entry.realm_id.clone(),
            // This is the time the notify carrier reached the holder's
            // account, which is the relevant ordering point for the inbox.
            created_at: entry.received_at,
        },
    });
}

/// Materialize one validated account-subscribe upsert into the display-side
/// Notification model.
///
/// The delta's typed union is authoritative. Ordinary rows deliberately omit
/// recipient and inbox state, while Agent approval rows carry only their
/// account-private artifact coordinate. Re-serializing either branch and
/// guessing the old full-Notification shape would reintroduce wire fields the
/// current protocol removed.
fn notification_from_upsert(
    delta: &NotificationDelta,
    recipient_actor: &arkret_sdk::ActorId,
) -> arkret_sdk::Result<Notification> {
    delta.validate_shape()?;
    let recipient = recipient_actor.as_account_id().ok_or_else(|| {
        arkret_sdk::Error::Protocol(
            "notification recipient must be a complete account ActorId".to_owned(),
        )
    })?;
    let notification = match (&delta.id, delta.data.as_ref()) {
        (
            arkret_sdk::NotificationIdentity::Projection(delivered_id),
            Some(NotificationData::OrdinaryProjection(content)),
        ) => content.clone().into_notification(
            recipient,
            delivered_id.clone(),
            arkret_sdk::NotificationState::Unread,
        )?,
        (
            arkret_sdk::NotificationIdentity::AgentApproval(_),
            Some(NotificationData::AgentRuntimeApproval(data)),
        ) => {
            data.validate()?;
            Notification {
                id: delta.id.clone(),
                schema: arkret_sdk::NotificationSchema::V1,
                actor_id: recipient_actor.clone(),
                source: arkret_sdk::NotificationSource::AccountArtifact(
                    arkret_sdk::NotificationAccountArtifactSource {
                        source_account_artifact: arkret_sdk::NotificationAccountArtifact {
                            kind: arkret_sdk::NotificationAccountArtifactKind::AgentRuntimeApproval,
                            id: arkret_sdk::OpaqueLocalId::new(
                                data.approval_request_id.as_str().to_owned(),
                            )
                            .map_err(|error| arkret_sdk::Error::Protocol(error.to_owned()))?,
                        },
                    },
                ),
                notification_kind: NotificationKind::Agent,
                priority: arkret_sdk::NotificationPriority::Normal,
                state: arkret_sdk::NotificationState::Unread,
                preview: None,
                created_at: data.requested_at,
                updated_at: None,
            }
        }
        _ => {
            return Err(arkret_sdk::Error::Protocol(
                "notification upsert does not match its typed identity branch".to_owned(),
            ));
        }
    };
    notification.validate()?;
    Ok(notification)
}

/// Fold all notification sources into one current projection.
///
/// Frames upsert individual identities. Completed baseline cleanup belongs
/// to the durable demand-sync reducer, never to a partial frame.
pub(crate) fn apply_notification_projection(
    current: &mut Vec<StoredNotification>,
    deltas: &[NotificationDelta],
    recipient_actor: &arkret_sdk::ActorId,
    joined_realms: &JoinedRealmIds,
) {
    for delta in deltas {
        let id = delta.id.as_str();
        match delta.action {
            NotificationDeltaAction::Upsert => {
                let notification = match notification_from_upsert(delta, recipient_actor) {
                    Ok(notification) => notification,
                    Err(error) => {
                        tracing::error!(
                            notification_id = id,
                            %error,
                            "discarding a notification delta that does not match its typed branch"
                        );
                        continue;
                    }
                };
                let replacement = StoredNotification::Event { notification };
                if let Some(existing) = current
                    .iter_mut()
                    .find(|candidate| candidate.notification_id() == id)
                {
                    *existing = replacement;
                } else {
                    current.push(replacement);
                }
            }
            NotificationDeltaAction::Remove => {
                current.retain(|candidate| candidate.notification_id() != id);
            }
        }
    }
    current.retain(|item| {
        item.invite()
            .is_none_or(|invite| !joined_realms.contains(invite.realm_id.as_str()))
    });
}

#[cfg(test)]
pub(crate) fn raw_notifications_from_sources(
    notification_response: Option<&[NotificationDelta]>,
    _account_data: &[arkret_sdk::Event],
) -> Vec<StoredNotification> {
    let mut projection = Vec::new();
    let recipient = crate::mls_api_helpers::local_account_actor_id("did:web:alice.example")
        .expect("valid test account actor");
    apply_notification_projection(
        &mut projection,
        notification_response.unwrap_or_default(),
        &recipient,
        &JoinedRealmIds::default(),
    );
    projection
}

pub(crate) fn notification_id_for_dedupe(value: &StoredNotification) -> Option<String> {
    Some(value.notification_id())
}

pub(crate) fn invite_notification_target_for_dedupe(value: &StoredNotification) -> Option<String> {
    value
        .invite()
        .map(|invite| invite.realm_id.as_str().to_owned())
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
    let source_event_id = source_event_id.map(ToOwned::to_owned).unwrap_or_else(|| {
        let mut digest = [0_u8; 32];
        digest[..8].copy_from_slice(&ordinal.to_be_bytes());
        arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, digest)
            .to_string()
    });
    StoredNotification::Event {
        notification: Notification {
            id: arkret_sdk::derive_notification_projection_id(
                crate::mls_api_helpers::local_account_actor_id("did:web:alice.example")
                    .expect("valid test actor")
                    .as_account_id()
                    .expect("account"),
                &arkret_sdk::RealmId::new(realm_id.to_owned()).expect("Realm"),
                &arkret_sdk::EventId::new(source_event_id.clone()).expect("Event"),
                arkret_sdk::OrdinaryNotificationKind::try_from(&kind)
                    .expect("ordinary notification kind"),
            )
            .expect("valid test notification id")
            .into(),
            schema: arkret_sdk::NotificationSchema::V1,
            actor_id: crate::mls_api_helpers::local_account_actor_id("did:web:alice.example")
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
pub(crate) fn test_invite(ordinal: u64, realm_id: &str) -> Invite {
    // Frozen accepted Event identities keep this projection helper honest:
    // tests must not manufacture Event tokens by mutating bytes or truncating
    // an ordinal into a digest-shaped buffer.
    let invite_event_id = match ordinal {
        1 => "ak:event:AVcXEfJCoV9ydvyShgTJWTjBgeMxd7RTn-vxyjJj70BD",
        0x10 => "ak:event:AYYa5sMg42gq2sCKD5eAndBtYb2F6W4k_AK-c5l_KDWF",
        0x11 => "ak:event:Afab7TswzXygzB72iKHz5hHvOQNcFdGZSuVfr1sdl2HA",
        99 => "ak:event:ASis-E9AaWZ7FbUsZJMfg3XeRgIqBNYupIr3JDSTcvtM",
        0xbb => "ak:event:AXVaAVgJFKciaxCSX0EDb06FldpREjeSNx3e2AAsxwsL",
        other => panic!("missing frozen invite Event fixture for ordinal {other}"),
    };
    let invite_event_id =
        arkret_sdk::EventId::new(invite_event_id.to_owned()).expect("valid test Event token");
    Invite {
        id: arkret_sdk::InviteId::from_event_id(&invite_event_id),
        schema: "ak.schema.invite.v1".to_owned(),
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned()).expect("valid test Realm id"),
        inviter_account_id: arkret_sdk::AccountId::new(
            crate::mls_api_helpers::principal_core_id("did:web:alice.example")
                .expect("valid test inviter"),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ),
        invitee_account_id: None,
        introduction_evidence_digest: None,
        third_party_invite: None,
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
