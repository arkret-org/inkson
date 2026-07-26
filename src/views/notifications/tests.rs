#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;

    use super::super::model::{
        UiNotificationAction, append_invite_notifications, drop_joined_invite_notifications,
        hydrate_notifications, notification_eval_context, notification_overrides_realm_mute,
        raw_notifications_from_sources, read_cursor_targets, realm_is_muted,
        realm_title_hints_from_values,
    };
    use crate::notification_rules::WatchLevel;
    use crate::state::{
        ClientLocalState, NotificationClientState, ReadCursorPosition, ReadMarkerBody,
        ReadMarkerRecord, read_scope_for_cursor,
    };

    fn account_data_event(payload: serde_json::Value) -> arkret_sdk::Event {
        arkret_sdk::Event::new(
            "ak.account_data.set",
            arkret_sdk::RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000001").unwrap(),
            arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            1,
            arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            payload,
        )
        .unwrap()
    }

    #[test]
    fn hydrate_notifications_applies_push_rules_and_dnd() {
        let raw = vec![json!({
            "notification_id": "n1",
            "schema": "ak.schema.notification.v1",
            "notification_kind": "message",
            "realm_id": "ak:realm:quiet",
            "body": "hello"
        })];
        let rules = crate::notification_rules::parse_push_rules(&json!({
            "rules": [{
                "rule_id": "override.quiet",
                "conditions": [
                    {"kind": "field_match", "field": "realm_id", "pattern": "ak:realm:quiet"}
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
            "id": "ak:invite:01904100-0000-7000-8000-000000000001",
            "schema": "ak.schema.invite.v1",
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000002",
            "inviter": "did:web:alice.example",
            "state": "pending",
            "created_at": "2026-05-29T00:00:00.000Z",
        });
        let duplicate_invite = json!({
            "id": "ak:invite:01904100-0000-7000-8000-000000000099",
            "schema": "ak.schema.invite.v1",
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000002",
            "inviter": "did:web:alice.example",
            "state": "pending",
            "created_at": "2026-05-29T00:00:01.000Z",
        });
        let mut raw = Vec::new();
        append_invite_notifications(&mut raw, vec![invite.clone()], &BTreeSet::new());
        append_invite_notifications(&mut raw, vec![duplicate_invite], &BTreeSet::new());
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
            "ak:realm:01904100-0000-7000-8000-000000000002"
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

        let joined_realms =
            BTreeSet::from(["ak:realm:01904100-0000-7000-8000-000000000002".to_owned()]);
        append_invite_notifications(&mut raw, vec![invite], &joined_realms);
        drop_joined_invite_notifications(&mut raw, &joined_realms);
        assert!(raw.is_empty(), "joined Realm invites should be hidden");
    }

    #[test]
    fn hydrate_notifications_uses_local_read_overlay_over_projection() {
        let mut local_state = ClientLocalState::default();
        local_state.notification_client_state.insert(
            "n1".to_owned(),
            NotificationClientState {
                read: true,
                archived: false,
            },
        );
        let notifications = hydrate_notifications(
            vec![json!({
                "notification_id": "n1",
                "schema": "ak.schema.notification.v1",
                "notification_kind": "mention",
                "realm_id": "ak:realm:quiet",
                "body": "hello",
                "read": false
            })],
            &local_state,
            None,
            None,
        );

        assert_eq!(notifications.len(), 1);
        assert!(notifications[0].read);
    }

    #[test]
    fn hydrate_notifications_applies_synced_read_cursor() {
        let realm_id = "ak:realm:01904100-0000-7000-8000-000000000002";
        let strand_id = "ak:strand:01904100-0000-7000-8000-000000000003";
        let old_event = "ak:event:01904100-0000-7000-8000-000000000004";
        let cursor_event = "ak:event:01904100-0000-7000-8000-000000000005";
        let read_scope = read_scope_for_cursor(realm_id, Some(strand_id));
        let mut local_state = ClientLocalState::default();
        local_state.read_cursors.insert(
            "cursor".to_owned(),
            ReadMarkerRecord {
                marker_type: "ak.read_cursor.advance".to_owned(),
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
                json!({
                    "notification_id": "old",
                    "notification_kind": "mention",
                    "realm_id": realm_id,
                    "strand_id": strand_id,
                    "source_event_id": old_event,
                    "timestamp": "2026-05-29T00:00:00.000Z",
                    "body": "old mention",
                    "read": false
                }),
                json!({
                    "notification_id": "cursor",
                    "notification_kind": "mention",
                    "realm_id": realm_id,
                    "strand_id": strand_id,
                    "source_event_id": cursor_event,
                    "timestamp": "2026-05-29T00:00:01.000Z",
                    "body": "cursor mention",
                    "read": false
                }),
            ],
            &local_state,
            None,
            None,
        );

        assert_eq!(notifications.len(), 2);
        assert!(notifications.iter().all(|notification| notification.read));
    }

    #[test]
    fn fresh_invite_to_same_realm_survives_stale_archive_and_realm_mute() {
        let realm_id = "ak:realm:01904100-0000-7000-8000-000000000002";
        // Local state left over from an earlier invite to this realm: the
        // previous invite notification was archived, and the realm itself is
        // muted (e.g. a prior membership the receiver left). Both are keyed on
        // the realm — the regression was that they suppressed re-invites.
        let mut local_state = ClientLocalState::default();
        local_state
            .notification_client_state
            .entry("invite:ak:invite:00000000-0000-7000-8000-0000000000aa".to_owned())
            .or_default()
            .archived = true;
        local_state
            .realm_watch_levels
            .insert(realm_id.to_owned(), WatchLevel::Muted);

        // A brand-new invitation (distinct invite id) to the same realm.
        let invite = json!({
            "id": "ak:invite:00000000-0000-7000-8000-0000000000bb",
            "schema": "ak.schema.invite.v1",
            "realm_id": realm_id,
            "state": "pending",
            "created_at": "2026-06-10T00:00:00.000Z",
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
            notification.id, "invite:ak:invite:00000000-0000-7000-8000-0000000000bb",
            "invite notification id is keyed on the unique invite id"
        );
        // Realm mute must not hide an invite to a realm we are not in.
        assert!(notification_overrides_realm_mute(notification));
        assert!(realm_is_muted(&local_state, realm_id));
    }

    #[test]
    fn mention_notification_respects_realm_mute_hydration() {
        let realm_id = "ak:realm:01904100-0000-7000-8000-0000000000aa";
        let mut local_state = ClientLocalState::default();
        local_state
            .realm_watch_levels
            .insert(realm_id.to_owned(), WatchLevel::Muted);
        let raw = vec![
            json!({
                "notification_id": "normal",
                "notification_kind": "message",
                "realm_id": realm_id,
                "body": "muted normal message",
            }),
            json!({
                "notification_id": "mention",
                "notification_kind": "mention",
                "realm_id": realm_id,
                "body": "@bob muted mention override",
                "mentions_actor": true,
            }),
        ];

        let hydrated = hydrate_notifications(raw, &local_state, None, None);

        assert!(
            hydrated.is_empty(),
            "muted realms suppress ordinary and directed message notifications"
        );
    }

    #[test]
    fn assignment_and_schedule_notifications_respect_realm_mute_hydration() {
        let realm_id = "ak:realm:01904100-0000-7000-8000-0000000000ab";
        let mut local_state = ClientLocalState::default();
        local_state
            .realm_watch_levels
            .insert(realm_id.to_owned(), WatchLevel::Muted);
        let raw = vec![
            json!({
                "notification_id": "assignment",
                "notification_kind": "assignment",
                "realm_id": realm_id,
                "body": "You were assigned to a Strand.",
                "assigned_to_actor": true,
            }),
            json!({
                "notification_id": "schedule",
                "notification_kind": "schedule",
                "realm_id": realm_id,
                "body": "A due date or calendar schedule changed.",
                "schedule_target": true,
            }),
        ];

        let hydrated = hydrate_notifications(raw, &local_state, None, None);

        assert!(
            hydrated.is_empty(),
            "muted realms suppress assignment and schedule notifications"
        );
    }

    #[test]
    fn invite_title_is_preserved_for_accept_projection_hint() {
        let realm_id = "ak:realm:01904100-0000-7000-8000-000000000010";
        let invite = json!({
            "id": "ak:invite:01904100-0000-7000-8000-000000000011",
            "schema": "ak.schema.invite.v1",
            "realm_id": realm_id,
            "realm_title": "Partner Launch",
            "join_rule_snapshot": {
                "invite_token": "ak:invite-token:01904100-0000-7000-8000-000000000012"
            },
            "state": "pending",
            "created_at": "2026-05-29T00:00:00.000Z",
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
        let ctx = notification_eval_context(&json!({
            "notification_id": "n1",
            "event_kind": "ak.message.create",
            "notification_kind": "mention",
            "actor_id": "did:web:alice.example",
            "realm_id": "ak:realm:e2ee",
            "strand_id": "ak:strand:1",
            "track_name": "discussion",
            "watch_state": "participating",
            "encrypted": true,
            "local_decrypted": false,
            "mentions_actor": true
        }));

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
        let ctx = notification_eval_context(&json!({
            "notification_id": "n1",
            "event_kind": "ak.strand.update",
            "notification_kind": "schedule",
            "schedule_target": true,
        }));

        assert_eq!(ctx.notification_kind, "schedule");
        assert!(ctx.schedule_target);
    }

    #[test]
    fn notification_eval_context_ignores_deprecated_sender_fields() {
        let ctx = notification_eval_context(&json!({
            "notification_id": "n1",
            "event_kind": "ak.message.create",
            "notification_kind": "mention",
            "sender": "did:web:removed.example",
            "sender_did": "did:web:removed-did.example",
            "sender_actor_id": "did:web:removed-actor.example"
        }));

        assert_eq!(ctx.sender, None);
    }

    #[test]
    fn read_cursor_targets_pick_latest_event_per_realm() {
        let realm_a = "ak:realm:01904100-0000-7000-8000-000000000002";
        let strand_a = "ak:strand:01904100-0000-7000-8000-000000000003";
        let realm_b = "ak:realm:01904100-0000-7000-8000-000000000004";
        let raw = vec![
            json!({
                "notification_id": "old-a",
                "notification_kind": "message",
                "realm_id": realm_a,
                "strand_id": strand_a,
                "source_event_id": "ak:event:01904100-0000-7000-8000-000000000005",
                "timestamp": "2026-05-29T00:00:00.000Z",
            }),
            json!({
                "notification_id": "new-a",
                "notification_kind": "message",
                "realm_id": realm_a,
                "strand_id": strand_a,
                "event_id": "ak:event:01904100-0000-7000-8000-000000000006",
                "timestamp": "2026-05-29T00:00:01.000Z",
            }),
            json!({
                "notification_id": "no-position",
                "notification_kind": "message",
                "realm_id": realm_a,
                "timestamp": "2026-05-29T00:00:02.000Z",
            }),
            json!({
                "notification_id": "new-b",
                "notification_kind": "mention",
                "realm_id": realm_b,
                "source_event_id": "ak:event:01904100-0000-7000-8000-000000000007",
                "timestamp": "2026-05-29T00:00:03.000Z",
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
            "ak:event:01904100-0000-7000-8000-000000000006"
        );
        assert_eq!(target_a.strand_id.as_deref(), Some(strand_a));
        let target_b = targets
            .iter()
            .find(|target| target.realm_id == realm_b)
            .expect("realm B target");
        assert_eq!(
            target_b.event_id,
            "ak:event:01904100-0000-7000-8000-000000000007"
        );
        assert!(target_b.strand_id.is_none());
    }

    #[test]
    fn notification_sources_merge_account_data_with_typed_subscribe_deltas() {
        let account_data = vec![
            account_data_event(json!({
                "schema": "ak.schema.notification.v1",
                "notification_id": "n1",
                "read": false
            })),
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

        let subscribe_delta = vec![arkret_sdk::NotificationDelta {
            id: arkret_sdk::NotificationId::new(
                "ak:notification:01964137-0000-7000-8000-000000000004",
            )
            .unwrap(),
            notification_kind: arkret_sdk::NotificationKind::Agent,
            action: arkret_sdk::NotificationDeltaAction::Remove,
            data: None,
        }];
        let from_subscribe = raw_notifications_from_sources(Some(&subscribe_delta), &account_data);
        assert_eq!(from_subscribe.len(), 2);
        assert_eq!(
            from_subscribe[0]["id"].as_str(),
            Some("ak:notification:01964137-0000-7000-8000-000000000004")
        );
        assert_eq!(from_subscribe[1]["notification_id"].as_str(), Some("n1"));
    }
}
