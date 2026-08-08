use serde_json::json;

use super::model::{
    JoinedRealmIds, UiNotificationAction, actor_is_joined_member, append_invite_notifications,
    drop_joined_invite_notifications, hydrate_notifications, hydrate_notifications_for_actor,
    notification_eval_context, notification_overrides_realm_mute, raw_notifications_from_sources,
    read_cursor_targets, realm_is_muted, realm_title_hints_from_invites,
};
use crate::notification_rules::WatchLevel;
use crate::state::projection::notifications::{test_event_notification, test_invite};
use crate::state::{
    ClientLocalState, NotificationClientState, ReadCursorPosition, ReadMarkerBody,
    ReadMarkerRecord, read_scope_for_cursor,
};

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
    arkret_sdk::Event::new(
        "ak.account_data.set",
        arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
            )
            .unwrap(),
        },
        arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        1,
        arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        payload,
    )
    .unwrap()
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
    let invite = test_invite(
        1,
        "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
        None,
        None,
    );
    let duplicate_invite = test_invite(
        99,
        "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
        None,
        None,
    );
    let mut raw = Vec::new();
    append_invite_notifications(&mut raw, vec![invite.clone()], &JoinedRealmIds::default());
    append_invite_notifications(&mut raw, vec![duplicate_invite], &JoinedRealmIds::default());
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
    assert_eq!(notifications[0].body, "You were invited to join a Realm.");
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
    append_invite_notifications(&mut raw, vec![invite], &joined_realms);
    drop_joined_invite_notifications(&mut raw, &joined_realms);
    assert!(raw.is_empty(), "joined Realm invites should be hidden");
}

#[test]
fn visible_realm_preview_does_not_masquerade_as_joined_membership() {
    let actor_id = "did:webvh:z6mkfixture:bob.example";
    let entry = |membership: &str| {
        serde_json::from_value::<arkret_sdk::RealmSyncEntry>(json!({
            "members": [{
                "actor_id": actor_id,
                "membership": membership
            }]
        }))
        .expect("valid typed Realm sync entry")
    };

    assert!(actor_is_joined_member(&entry("join"), actor_id));
    assert!(!actor_is_joined_member(&entry("invite"), actor_id));
    assert!(!actor_is_joined_member(&entry("knock"), actor_id));
    assert!(!actor_is_joined_member(
        &arkret_sdk::RealmSyncEntry::default(),
        actor_id
    ));
}

#[test]
fn hydrate_pending_invite_uses_typed_local_membership() {
    let actor_id = "did:webvh:z6mkfixture:bob.example";
    let realm_id = "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    let projection = |membership: &str| {
        json!({
            "members": [{
                "actor_id": actor_id,
                "membership": membership
            }]
        })
    };
    let invite = || test_invite(1, realm_id, None, None);

    let mut invited_state = ClientLocalState::default();
    invited_state
        .realm_tree_projections
        .insert(realm_id.to_owned(), projection("invite"));
    let mut invited_raw = Vec::new();
    append_invite_notifications(&mut invited_raw, vec![invite()], &JoinedRealmIds::default());
    assert_eq!(
        hydrate_notifications_for_actor(invited_raw, &invited_state, actor_id).len(),
        1,
        "a visible invite preview must retain its pending invite notification"
    );

    let mut joined_state = ClientLocalState::default();
    joined_state
        .realm_tree_projections
        .insert(realm_id.to_owned(), projection("join"));
    let mut joined_raw = Vec::new();
    append_invite_notifications(&mut joined_raw, vec![invite()], &JoinedRealmIds::default());
    assert!(
        hydrate_notifications_for_actor(joined_raw, &joined_state, actor_id).is_empty(),
        "an authoritative joined membership must suppress stale invites"
    );
}

#[test]
fn hydrate_notifications_uses_local_read_overlay_over_projection() {
    let mut local_state = ClientLocalState::default();
    local_state.notification_client_state.insert(
        "ak:notification:0196419b-0000-7000-8000-000000000001".to_owned(),
        NotificationClientState {
            read: true,
            archived: false,
        },
    );
    let notifications = hydrate_notifications(
        vec![event(
            1,
            arkret_sdk::NotificationKind::Mention,
            "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
            None,
            json!({"body": "hello"}),
        )],
        &local_state,
        None,
        None,
    );

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
                id: "ak:read_cursor:01904100-0000-7000-8000-000000000006".to_owned(),
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
                id: "ak:read_cursor:01904100-0000-7000-8000-000000000006".to_owned(),
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
    let invite = test_invite(0xbb, realm_id, None, None);
    let mut raw = Vec::new();
    append_invite_notifications(&mut raw, vec![invite], &JoinedRealmIds::default());

    let hydrated = hydrate_notifications(raw, &local_state, None, None);
    assert_eq!(hydrated.len(), 1, "fresh invite must hydrate");
    let notification = &hydrated[0];
    assert!(
        !notification.archived,
        "fresh invite must not inherit archive"
    );
    assert_eq!(
        notification.id, "invite:ak:invite:AfRC97FTnyCEsuiktfOeqyhvtwC2_dzzc3GT2Q9TdrAV",
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
fn invite_title_is_preserved_for_accept_projection_hint() {
    let realm_id = "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h";
    let invite = test_invite(
        0x11,
        realm_id,
        Some("Partner Launch"),
        Some("ak:invite-token:01904100-0000-7000-8000-000000000012"),
    );
    let hints = realm_title_hints_from_invites(std::slice::from_ref(&invite));
    let mut raw = Vec::new();
    append_invite_notifications(&mut raw, vec![invite], &JoinedRealmIds::default());

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
        Some(UiNotificationAction::AcceptInvite {
            invite_token: Some(token),
            realm_label: Some(label),
            ..
        }) if label == "Partner Launch"
            && token == "ak:invite-token:01904100-0000-7000-8000-000000000012"
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
    assert_eq!(ctx.sender.as_deref(), Some("did:web:alice.example"));
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

    assert_eq!(ctx.sender.as_deref(), Some("did:web:alice.example"));
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
fn notification_sources_merge_account_data_with_typed_subscribe_deltas() {
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
    let account_data = vec![
        account_data_event(serde_json::to_value(notification).unwrap()),
        account_data_event(json!({
            "kind": "ak.profile",
            "id": "profile"
        })),
    ];

    let fallback = raw_notifications_from_sources(None, &account_data);
    assert_eq!(fallback.len(), 1);

    let server_empty = Vec::<arkret_sdk::NotificationDelta>::new();
    assert_eq!(
        raw_notifications_from_sources(Some(&server_empty), &account_data).len(),
        1
    );

    let subscribe_delta = vec![
        arkret_sdk::NotificationDelta::try_new(
            arkret_sdk::NotificationId::new("ak:notification:01964137-0000-7000-8000-000000000004")
                .unwrap(),
            arkret_sdk::NotificationKind::Agent,
            arkret_sdk::NotificationDeltaAction::Add,
            Some(arkret_sdk::NotificationData::AgentRuntimeApproval(
                arkret_sdk::AgentRuntimeApprovalNotificationData {
                    kind: arkret_sdk::AccountNotificationDataKind::AgentRuntimeApproval,
                    approval_request_id: arkret_sdk::OpaqueLocalId::new(
                        "agent_runtime_approval:01964137-0000-7000-8000-000000000005",
                    )
                    .unwrap(),
                    agent_id: arkret_sdk::Did::new("did:web:agent.example".to_owned()).unwrap(),
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
    assert!(from_subscribe.iter().any(|item| {
        item.agent_runtime_approval().is_some_and(|(id, _)| {
            id.as_str() == "ak:notification:01964137-0000-7000-8000-000000000004"
        })
    }));
    assert!(
        from_subscribe
            .iter()
            .any(|item| matches!(item, crate::state::StoredNotification::Event { .. }))
    );
}
