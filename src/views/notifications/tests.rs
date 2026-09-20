use serde_json::json;

use super::model::{
    JoinedRealmIds, UiNotificationAction, actor_is_joined_member, hydrate_notifications,
    hydrate_notifications_for_actor, notification_eval_context, notification_overrides_realm_mute,
    raw_notifications_from_sources, read_cursor_targets, realm_is_muted,
};
use crate::notification_rules::WatchLevel;
use crate::state::projection::notifications::{test_event_notification, test_invite};
use crate::state::{
    ClientLocalState, LocalStateStore, NotificationClientState, ReadCursorPosition, ReadMarkerBody,
    ReadMarkerRecord, StoredInviteNotification, StoredNotification, read_scope_for_cursor,
};

fn push_test_invite_projection(
    notifications: &mut Vec<StoredNotification>,
    invites: Vec<arkret_models_collaboration::governance::operation_wire::Invite>,
    hidden_realms: &JoinedRealmIds,
) {
    notifications.retain(|candidate| {
        candidate
            .invite()
            .is_none_or(|invite| !hidden_realms.contains(invite.realm_id.as_str()))
    });
    for invite in invites {
        if hidden_realms.contains(invite.realm_id.as_str()) {
            continue;
        }
        notifications.retain(|candidate| {
            candidate.invite().is_none_or(|existing| {
                existing.invite_id != invite.id && existing.realm_id != invite.realm_id
            })
        });
        notifications.push(StoredNotification::Invite {
            invite: StoredInviteNotification {
                invite_id: invite.id,
                realm_id: invite.realm_id,
                created_at: invite.created_at,
            },
        });
    }
}

#[test]
fn realm_state_snapshot_refresh_preserves_an_existing_live_invite_projection() {
    let path = std::env::temp_dir().join(format!(
        "inkson-notification-snapshot-{}.json",
        crate::operation::uuid_v7()
    ));
    let mut store = LocalStateStore::with_path(path.clone());
    let invite = test_invite(
        0x10,
        "ak:realm:AeWYNl1hiGDuy4WCQ03g5lgs2NZzf_SFYgjsfhG-t9cg",
    );
    let invite_id = invite.id.clone();
    let mut live_projection = Vec::new();
    push_test_invite_projection(
        &mut live_projection,
        vec![invite],
        &JoinedRealmIds::default(),
    );
    store.save_notification_projection(live_projection);

    let _current = store.current_account_projection_step();
    let folded = store.notification_projection();
    assert!(folded.iter().any(|notification| {
        notification
            .invite()
            .is_some_and(|invite| invite.invite_id == invite_id)
    }));
    let _ = std::fs::remove_file(path);
}

fn event(
    ordinal: u64,
    kind: arkret_sdk::NotificationKind,
    realm_id: &str,
    source_event_id: Option<&str>,
    preview: serde_json::Value,
) -> crate::state::StoredNotification {
    test_event_notification(ordinal, kind, realm_id, source_event_id, preview)
}

fn account_data_event(payload: serde_json::Value) -> arkret_sdk::Event {
    arkret_wire::test_support::raw_event(
        "ak.message.create",
        arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
            )
            .unwrap(),
        },
        arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        1,
        arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        payload,
    )
    .unwrap()
}

#[test]
fn notification_baseline_segments_preserve_previous_segment_and_upsert_by_id() {
    let realm = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let first = event(
        1,
        arkret_sdk::NotificationKind::Mention,
        realm,
        None,
        json!({}),
    );
    let second = event(
        2,
        arkret_sdk::NotificationKind::Mention,
        realm,
        None,
        json!({}),
    );
    let mut current = vec![first.clone()];
    let StoredNotification::Event { notification } = second.clone() else {
        unreachable!()
    };
    let arkret_sdk::NotificationSource::Event(source) = &notification.source else {
        unreachable!()
    };
    let delta = arkret_sdk::sync::NotificationDelta::try_new(
        notification.id.clone(),
        arkret_sdk::sync::NotificationDeltaAction::Upsert,
        Some(arkret_sdk::sync::NotificationData::OrdinaryProjection(
            Box::new(arkret_sdk::OrdinaryProjectionContent {
                realm_id: source.realm_id.clone().unwrap(),
                source_event_id: source.source_event_id.clone(),
                source_ref: source.source_ref.clone(),
                strand_id: source.strand_id.clone(),
                track_name: source.track_name.clone(),
                notification_kind: arkret_sdk::OrdinaryNotificationKind::Mention,
                priority: notification.priority,
                preview: notification.preview.clone(),
                created_at: notification.created_at,
                updated_at: notification.updated_at,
            }),
        )),
    )
    .unwrap();
    for _ in 0..2 {
        crate::state::projection::notifications::apply_notification_projection(
            &mut current,
            std::slice::from_ref(&delta),
            &crate::mls_api_helpers::local_account_actor_id("did:web:alice.example").unwrap(),
            &JoinedRealmIds::default(),
        );
    }
    assert_eq!(current.len(), 2);
    assert!(
        current
            .iter()
            .any(|item| item.notification_id() == first.notification_id())
    );
    assert!(
        current
            .iter()
            .any(|item| item.notification_id() == second.notification_id())
    );
}

#[test]
fn hydrate_notifications_applies_push_rules_and_dnd() {
    let raw = vec![event(
        1,
        arkret_sdk::NotificationKind::Message,
        "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
        None,
        json!({"body": "hello"}),
    )];
    let rules = crate::notification_rules::parse_push_rules(&json!({
        "rules": [{
            "rule_id": "override.quiet",
            "kind": "override",
            "evaluation_locus": "client",
            "conditions": [
                {"kind": "field_match", "field": "realm_id", "pattern": "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo"}
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
    let invite = test_invite(1, "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1");
    let duplicate_invite = test_invite(99, "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1");
    let mut raw = Vec::new();
    push_test_invite_projection(&mut raw, vec![invite.clone()], &JoinedRealmIds::default());
    push_test_invite_projection(&mut raw, vec![duplicate_invite], &JoinedRealmIds::default());
    assert_eq!(raw.len(), 1, "same Realm invite should not duplicate");

    let notifications =
        hydrate_notifications(raw.clone(), &ClientLocalState::default(), None, None);
    assert_eq!(notifications.len(), 1);
    assert_eq!(notifications[0].kind, "invite");
    // Default titles / action labels are stored as i18n keys and
    // translated at render via tr().
    assert_eq!(notifications[0].title, "notifications.default_title.invite");
    assert_eq!(
        notifications[0].realm_id,
        "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1"
    );
    // The Invite object carries no Realm title (`governance-objects.md` §5.3),
    // so the short protocol id is the name available before the accept flow
    // resolves a directory preview.
    assert_eq!(
        notifications[0].body,
        format!(
            "You were invited to join {}.",
            crate::views::helpers::short_protocol_id(
                "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1"
            )
        )
    );
    assert_eq!(
        notifications[0].action_label.as_deref(),
        Some("notifications.default_action.accept")
    );
    assert!(matches!(
        notifications[0].action.as_ref(),
        Some(UiNotificationAction::AcceptInvite { .. })
    ));

    let joined_realms = JoinedRealmIds::default()
        .joined_now("ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1".to_owned());
    push_test_invite_projection(&mut raw, vec![invite], &joined_realms);
    assert!(raw.is_empty(), "joined Realm invites should be hidden");
}

#[test]
fn visible_realm_preview_does_not_masquerade_as_joined_membership() {
    let actor_id = "ak:did_core:webvh:z6mkfixture:bob.example";
    let entry = |membership: &str| {
        serde_json::from_value::<arkret_sdk::sync::RealmSyncEntry>(json!({
            "member_roster": {
                "entries": [{
                    "actor_id": {"kind": "account", "account_id": {
                        "principal_id": actor_id,
                        "station_id": "ak:did_core:web:principal.example"
                    }},
                    "membership": membership
                }],
                "limited": false
            }
        }))
        .expect("valid typed Realm sync entry")
    };

    // `account-subscribe-frame.schema.json#/$defs/member_roster_entry` closes
    // `membership` to `join | knock` and states that invite lifecycle records
    // are not membership and MUST NOT appear on the roster, so there is no
    // `"invite"` row to assert against — the typed roster cannot carry one.
    let account_actor = crate::test_support::account_actor(actor_id);
    assert!(actor_is_joined_member(&entry("join"), &account_actor));
    assert!(!actor_is_joined_member(&entry("knock"), &account_actor));
    assert!(!actor_is_joined_member(
        &arkret_sdk::sync::RealmSyncEntry::default(),
        &account_actor
    ));
    // The same principal joined at another Station is a different account and
    // must not count as this account's membership (account-lifecycle.md §156).
    let other_station = arkret_sdk::ActorId::account(crate::test_support::authority_at_station(
        actor_id,
        crate::test_support::SERVER_STATION_ID,
    ));
    assert!(!actor_is_joined_member(&entry("join"), &other_station));
}

#[test]
fn hydrate_pending_invite_uses_typed_local_membership() {
    let actor_id = "ak:did_core:webvh:z6mkfixture:bob.example";
    let realm_id = "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    let projection = |membership: &str| {
        json!({
            "member_roster_entries": [{
                "actor_id": {"kind": "account", "account_id": {
                    "principal_id": actor_id,
                    "station_id": "ak:did_core:web:principal.example"
                }},
                "membership": membership
            }]
        })
    };
    let invite = || test_invite(1, realm_id);

    let mut invited_state = ClientLocalState::default();
    // Same closed enum as the wire roster: `knock` is the roster's real
    // "present but not joined" row. Feeding `"invite"` here only exercised the
    // deserialization-failure path while claiming to test a membership value.
    invited_state
        .realm_tree_projections
        .insert(realm_id.to_owned(), projection("knock"));
    let mut invited_raw = Vec::new();
    push_test_invite_projection(&mut invited_raw, vec![invite()], &JoinedRealmIds::default());
    assert_eq!(
        hydrate_notifications_for_actor(
            invited_raw,
            &invited_state,
            &crate::test_support::account_actor(actor_id)
        )
        .len(),
        1,
        "a visible invite preview must retain its pending invite notification"
    );

    let mut joined_state = ClientLocalState::default();
    joined_state
        .realm_tree_projections
        .insert(realm_id.to_owned(), projection("join"));
    let mut joined_raw = Vec::new();
    push_test_invite_projection(&mut joined_raw, vec![invite()], &JoinedRealmIds::default());
    assert!(
        hydrate_notifications_for_actor(
            joined_raw,
            &joined_state,
            &crate::test_support::account_actor(actor_id)
        )
        .is_empty(),
        "an authoritative joined membership must suppress stale invites"
    );
}

#[test]
fn hydrate_notifications_uses_local_read_overlay_over_projection() {
    let notification = event(
        1,
        arkret_sdk::NotificationKind::Mention,
        "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
        None,
        json!({"body": "hello"}),
    );
    let mut local_state = ClientLocalState::default();
    local_state.notification_client_state.insert(
        notification.notification_id().to_owned(),
        NotificationClientState {
            read: true,
            archived: false,
        },
    );
    let notifications = hydrate_notifications(vec![notification], &local_state, None, None);

    assert_eq!(notifications.len(), 1);
    assert!(notifications[0].read);
}

#[test]
fn hydrate_notifications_applies_synced_read_cursor() {
    let realm_id = "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    let strand_id = "ak:strand:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy";
    let old_event = "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM";
    let cursor_event = "ak:event:AVWVGlDqGwJJ7DILnxJ4oq7JGdtoXGIQaK4PoiEf2yBZ";
    let read_scope = read_scope_for_cursor(realm_id, Some(strand_id));
    let mut local_state = ClientLocalState::default();
    local_state.read_cursors.insert(
        "cursor".to_owned(),
        ReadMarkerRecord {
            body: ReadMarkerBody {
                schema: "ak.schema.read_cursor.v1".to_owned(),
                realm_id: realm_id.to_owned(),
                read_scope,
                position: ReadCursorPosition {
                    event_id: arkret_sdk::EventId::new(cursor_event).unwrap(),
                    hlc: arkret_sdk::Hlc::new("019041000000-0001-deadbeef").unwrap(),
                },
            },
            actor: "did:web:bob.example".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000007".to_owned(),
            updated_at: chrono::Utc::now(),
        },
    );

    let notifications = hydrate_notifications(
        vec![
            event(
                1,
                arkret_sdk::NotificationKind::Mention,
                realm_id,
                Some(old_event),
                json!({"strand_id": strand_id, "body": "old mention"}),
            ),
            event(
                2,
                arkret_sdk::NotificationKind::Mention,
                realm_id,
                Some(cursor_event),
                json!({"strand_id": strand_id, "body": "cursor mention"}),
            ),
        ],
        &local_state,
        None,
        None,
    );

    assert_eq!(notifications.len(), 2);
    assert!(notifications.iter().all(|notification| notification.read));
}

#[test]
fn hydrate_notifications_does_not_order_missing_cursor_target_by_event_id() {
    let realm_id = "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    let strand_id = "ak:strand:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy";
    let mut local_state = ClientLocalState::default();
    local_state.read_cursors.insert(
        "cursor".to_owned(),
        ReadMarkerRecord {
            body: ReadMarkerBody {
                schema: "ak.schema.read_cursor.v1".to_owned(),
                realm_id: realm_id.to_owned(),
                read_scope: read_scope_for_cursor(realm_id, Some(strand_id)),
                position: ReadCursorPosition {
                    event_id: arkret_sdk::EventId::new(
                        "ak:event:AdGAhhjx8Y3XQNfetd3DTBNMzZje_RzjhvG3c5aMUs4g",
                    )
                    .unwrap(),
                    hlc: arkret_sdk::Hlc::new("019041000000-0001-deadbeef").unwrap(),
                },
            },
            actor: "did:web:bob.example".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000007".to_owned(),
            updated_at: chrono::Utc::now(),
        },
    );

    let notifications = hydrate_notifications(
        vec![event(
            1,
            arkret_sdk::NotificationKind::Mention,
            realm_id,
            Some("ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM"),
            json!({"strand_id": strand_id, "body": "target is not in this page"}),
        )],
        &local_state,
        None,
        None,
    );

    assert_eq!(notifications.len(), 1);
    assert!(!notifications[0].read);
}

#[test]
fn fresh_invite_to_same_realm_survives_stale_archive_and_realm_mute() {
    let realm_id = "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    // Local state left over from an earlier invite to this realm: the
    // previous invite notification was archived, and the realm itself is
    // muted (e.g. a prior membership the receiver left). Both are keyed on
    // the realm — the regression was that they suppressed re-invites.
    let mut local_state = ClientLocalState::default();
    local_state
        .notification_client_state
        .entry("invite:ak:invite:AfiWyNHtuPokqYPDK4Coh056hQn040Bq_jLeToFl2VoZ".to_owned())
        .or_default()
        .archived = true;
    local_state
        .realm_watch_levels
        .insert(realm_id.to_owned(), WatchLevel::Muted);

    // A brand-new invitation (distinct invite id) to the same realm.
    let invite = test_invite(0xbb, realm_id);
    let expected_notification_id = format!("invite:{}", invite.id);
    let mut raw = Vec::new();
    push_test_invite_projection(&mut raw, vec![invite], &JoinedRealmIds::default());

    let hydrated = hydrate_notifications(raw, &local_state, None, None);
    assert_eq!(hydrated.len(), 1, "fresh invite must hydrate");
    let notification = &hydrated[0];
    assert!(
        !notification.archived,
        "fresh invite must not inherit archive"
    );
    assert_eq!(
        notification.id, expected_notification_id,
        "invite notification id is keyed on the unique invite id"
    );
    // Realm mute must not hide an invite to a realm we are not in.
    assert!(notification_overrides_realm_mute(notification));
    assert!(realm_is_muted(&local_state, realm_id));
}

#[test]
fn mention_notification_respects_realm_mute_hydration() {
    let realm_id = "ak:realm:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml";
    let mut local_state = ClientLocalState::default();
    local_state
        .realm_watch_levels
        .insert(realm_id.to_owned(), WatchLevel::Muted);
    let raw = vec![
        event(
            1,
            arkret_sdk::NotificationKind::Message,
            realm_id,
            None,
            json!({"body": "muted normal message"}),
        ),
        event(
            2,
            arkret_sdk::NotificationKind::Mention,
            realm_id,
            None,
            json!({"body": "@bob muted mention override", "mentions_actor": true}),
        ),
    ];

    let hydrated = hydrate_notifications(raw, &local_state, None, None);

    assert!(
        hydrated.is_empty(),
        "muted realms suppress ordinary and directed message notifications"
    );
}

#[test]
fn assignment_and_schedule_notifications_respect_realm_mute_hydration() {
    let realm_id = "ak:realm:ARKSHgBichO7ZjwprTMf4UrKn7x1GHkl16zz6U4xm586";
    let mut local_state = ClientLocalState::default();
    local_state
        .realm_watch_levels
        .insert(realm_id.to_owned(), WatchLevel::Muted);
    let raw = vec![
        event(
            1,
            arkret_sdk::NotificationKind::Assignment,
            realm_id,
            None,
            json!({
                "body": "You were assigned to a Strand.",
                "assigned_to_actor": true
            }),
        ),
        event(
            2,
            arkret_sdk::NotificationKind::Schedule,
            realm_id,
            None,
            json!({
                "body": "A due date or calendar schedule changed.",
                "schedule_target": true
            }),
        ),
    ];

    let hydrated = hydrate_notifications(raw, &local_state, None, None);

    assert!(
        hydrated.is_empty(),
        "muted realms suppress assignment and schedule notifications"
    );
}

#[test]
fn invite_notification_carries_no_unregistered_invite_members() {
    let realm_id = "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h";
    let invite = test_invite(0x11, realm_id);
    let mut raw = Vec::new();
    push_test_invite_projection(&mut raw, vec![invite], &JoinedRealmIds::default());

    let notifications = hydrate_notifications(raw, &ClientLocalState::default(), None, None);

    // `invite.schema.json` registers neither a Realm title nor the private
    // delivery token, and `governance-objects.md` §5.3 forbids materializing
    // transport material on the Invite. The projection MUST NOT invent either.
    assert_eq!(notifications[0].realm_label, None);
    assert!(matches!(
        notifications[0].action.as_ref(),
        Some(UiNotificationAction::AcceptInvite {
            invite_token: None,
            realm_id: action_realm_id,
            ..
        }) if action_realm_id == realm_id
    ));
}

#[test]
fn invite_notification_token_comes_only_from_private_credential_state() {
    let realm_id = "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h";
    let invite = test_invite(0x11, realm_id);
    let invite_id = invite.id.as_str().to_owned();
    let mut raw = Vec::new();
    push_test_invite_projection(&mut raw, vec![invite], &JoinedRealmIds::default());

    let mut local_state = ClientLocalState::default();
    local_state.invite_credentials.insert(
        invite_id,
        crate::state::StoredInviteCredential {
            realm_id: arkret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            invite_token: "ak:invite-token:delivered".to_owned(),
            expires_at: Some(
                chrono::DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            received_at: chrono::Utc::now(),
        },
    );

    let notifications = hydrate_notifications(raw, &local_state, None, None);

    assert!(matches!(
        notifications[0].action.as_ref(),
        Some(UiNotificationAction::AcceptInvite {
            invite_token: Some(token),
            ..
        }) if token == "ak:invite-token:delivered"
    ));
}

#[test]
fn notification_eval_context_extracts_watch_and_e2ee_flags() {
    let notification = event(
        1,
        arkret_sdk::NotificationKind::Mention,
        "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
        None,
        json!({
            "event_kind": "ak.message.create",
            "strand_id": "ak:strand:AeWYNl1hiGDuy4WCQ03g5lgs2NZzf_SFYgjsfhG-t9cg",
            "track_name": "discussion",
            "watch_state": "participating",
            "encrypted": true,
            "local_decrypted": false,
            "mentions_actor": true
        }),
    );
    let ctx = notification_eval_context(&notification);

    assert_eq!(ctx.event_kind, "ak.message.create");
    assert_eq!(ctx.notification_kind, "mention");
    assert_eq!(ctx.strand_track.as_deref(), Some("discussion"));
    assert_eq!(ctx.watch_level, Some(WatchLevel::Participating));
    assert!(ctx.is_e2ee);
    assert!(!ctx.local_decrypted);
    assert_eq!(ctx.mentions_actor, Some(true));
    assert_eq!(ctx.sender.as_deref(), Some("ak:did_core:web:alice.example"));
}

#[test]
fn notification_eval_context_extracts_schedule_target() {
    let notification = event(
        1,
        arkret_sdk::NotificationKind::Schedule,
        "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
        None,
        json!({
            "event_kind": "ak.strand.update",
            "schedule_target": true
        }),
    );
    let ctx = notification_eval_context(&notification);

    assert_eq!(ctx.notification_kind, "schedule");
    assert!(ctx.schedule_target);
}

#[test]
fn notification_eval_context_uses_typed_actor_not_preview_aliases() {
    let notification = event(
        1,
        arkret_sdk::NotificationKind::Mention,
        "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
        None,
        json!({
            "event_kind": "ak.message.create",
            "sender": "did:web:removed.example",
            "sender_did": "did:web:removed-did.example",
            "sender_actor_id": "did:web:removed-actor.example"
        }),
    );
    let ctx = notification_eval_context(&notification);

    assert_eq!(ctx.sender.as_deref(), Some("ak:did_core:web:alice.example"));
}

#[test]
fn read_cursor_targets_pick_latest_event_per_read_scope() {
    let realm_a = "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    let strand_a = "ak:strand:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy";
    let strand_b = "ak:strand:AemeC-S9hxNmOvsKHbhTUFcxu1dcUy2rKPJ-dWVot_KM";
    let realm_b = "ak:realm:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM";
    let raw = vec![
        event(
            1,
            arkret_sdk::NotificationKind::Message,
            realm_a,
            Some("ak:event:AVWVGlDqGwJJ7DILnxJ4oq7JGdtoXGIQaK4PoiEf2yBZ"),
            json!({"strand_id": strand_a}),
        ),
        event(
            2,
            arkret_sdk::NotificationKind::Message,
            realm_a,
            Some("ak:event:AWgGCEbMHnelRQfzqg1C_onV9Ej_FdpdAZyM_JoFgAd3"),
            json!({"strand_id": strand_a}),
        ),
        event(
            4,
            arkret_sdk::NotificationKind::Message,
            realm_a,
            Some("ak:event:AdGAhhjx8Y3XQNfetd3DTBNMzZje_RzjhvG3c5aMUs4g"),
            json!({"strand_id": strand_b}),
        ),
        event(
            3,
            arkret_sdk::NotificationKind::Mention,
            realm_b,
            Some("ak:event:ATFrN4sYtiDvJD5G4wKxYY3xMKfo-Xqa_o9Xkb-XnzFN"),
            json!({}),
        ),
    ];

    let notifications = hydrate_notifications(raw, &ClientLocalState::default(), None, None);
    let targets = read_cursor_targets(&notifications);

    assert_eq!(targets.len(), 3);
    let target_a = targets
        .iter()
        .find(|target| target.realm_id == realm_a && target.strand_id.as_deref() == Some(strand_a))
        .expect("realm A strand A target");
    assert_eq!(
        target_a.event_id,
        "ak:event:AWgGCEbMHnelRQfzqg1C_onV9Ej_FdpdAZyM_JoFgAd3"
    );
    assert_eq!(target_a.strand_id.as_deref(), Some(strand_a));
    let target_b = targets
        .iter()
        .find(|target| target.realm_id == realm_a && target.strand_id.as_deref() == Some(strand_b))
        .expect("realm A strand B target");
    assert_eq!(
        target_b.event_id,
        "ak:event:AdGAhhjx8Y3XQNfetd3DTBNMzZje_RzjhvG3c5aMUs4g"
    );
    let realm_b_target = targets
        .iter()
        .find(|target| target.realm_id == realm_b)
        .expect("realm B target");
    assert_eq!(
        realm_b_target.event_id,
        "ak:event:ATFrN4sYtiDvJD5G4wKxYY3xMKfo-Xqa_o9Xkb-XnzFN"
    );
    assert!(realm_b_target.strand_id.is_none());
}

#[test]
fn notification_sources_use_typed_subscribe_deltas_only() {
    let stored = event(
        1,
        arkret_sdk::NotificationKind::Message,
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        Some("ak:event:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL"),
        json!({"body": "hello"}),
    );
    let crate::state::StoredNotification::Event { notification } = stored else {
        unreachable!("test fixture is Event notification");
    };
    let arkret_sdk::NotificationSource::Event(source) = &notification.source else {
        unreachable!("test fixture is Event notification");
    };
    let account_data = vec![account_data_event(
        serde_json::to_value(&notification).unwrap(),
    )];

    let fallback = raw_notifications_from_sources(None, &account_data);
    assert!(fallback.is_empty());

    let server_empty = Vec::<arkret_sdk::sync::NotificationDelta>::new();
    assert_eq!(
        raw_notifications_from_sources(Some(&server_empty), &account_data).len(),
        0
    );

    let ordinary = arkret_sdk::OrdinaryProjectionContent {
        realm_id: source.realm_id.clone().unwrap(),
        source_event_id: source.source_event_id.clone(),
        source_ref: source.source_ref.clone(),
        strand_id: source.strand_id.clone(),
        track_name: source.track_name.clone(),
        notification_kind: arkret_sdk::OrdinaryNotificationKind::Message,
        priority: arkret_sdk::NotificationPriority::Normal,
        preview: notification.preview.clone(),
        created_at: notification.created_at,
        updated_at: notification.updated_at,
    };
    let subscribe_delta = vec![
        arkret_sdk::sync::NotificationDelta::try_new(
            notification.id.clone(),
            arkret_sdk::sync::NotificationDeltaAction::Upsert,
            Some(arkret_sdk::sync::NotificationData::OrdinaryProjection(
                Box::new(ordinary),
            )),
        )
        .unwrap(),
        arkret_sdk::sync::NotificationDelta::try_new(
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
        .unwrap(),
    ];
    let from_subscribe = raw_notifications_from_sources(Some(&subscribe_delta), &account_data);
    assert_eq!(from_subscribe.len(), 2);
    let runtime_approval = from_subscribe
        .iter()
        .find(|item| item.agent_runtime_approval().is_some())
        .expect("runtime approval notification");
    assert!(
        runtime_approval
            .agent_runtime_approval()
            .is_some_and(|(id, _)| {
                id.as_str() == "ak:notification:01964137-0000-7000-8000-000000000004"
            })
    );
    let context = notification_eval_context(runtime_approval);
    assert_eq!(context.notification_kind, "agent");
    assert!(context.sender.is_none());
    assert!(context.realm_id.is_empty());
    assert!(
        from_subscribe
            .iter()
            .any(|item| matches!(item, crate::state::StoredNotification::Event { .. }))
    );
}

#[test]
fn ordinary_notification_with_another_recipient_id_is_discarded() {
    let realm_id = arkret_sdk::RealmId::new(
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-".to_owned(),
    )
    .unwrap();
    let source_event_id = arkret_sdk::EventId::new(
        "ak:event:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL".to_owned(),
    )
    .unwrap();
    let content = arkret_sdk::OrdinaryProjectionContent {
        realm_id: realm_id.clone(),
        source_event_id: source_event_id.clone(),
        source_ref: None,
        strand_id: None,
        track_name: None,
        notification_kind: arkret_sdk::OrdinaryNotificationKind::Message,
        priority: arkret_sdk::NotificationPriority::Normal,
        preview: None,
        created_at: "2026-09-10T00:00:00Z".parse().unwrap(),
        updated_at: None,
    };
    let other = arkret_sdk::AccountId::new(
        crate::mls_api_helpers::principal_core_id("did:web:bob.example").unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:localhost".to_owned()).unwrap(),
    );
    let delta = arkret_sdk::sync::NotificationDelta::try_new(
        content.derive_id(&other).unwrap().into(),
        arkret_sdk::sync::NotificationDeltaAction::Upsert,
        Some(arkret_sdk::sync::NotificationData::OrdinaryProjection(
            Box::new(content),
        )),
    )
    .unwrap();

    assert!(raw_notifications_from_sources(Some(&[delta]), &[]).is_empty());
}
