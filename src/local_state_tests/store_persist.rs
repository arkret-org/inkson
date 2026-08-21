//! Core store persistence: cursors, projections, notifications,
//! watch levels, read cursors, push registration, OIDC / DPoP secure storage,
//! and account-scope lifecycle.

use super::*;

#[test]
fn local_state_store_tracks_cursor_operations_and_projections() {
    let path = temp_state_path("tracks");
    let mut store = LocalStateStore::with_path(path);
    store.save_sync_cursor("sx:next");
    store.append_raw_operation(
        "ak:operation:local-01",
        Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE".to_owned()),
        serde_json::json!({"type": "ak.message.create"}),
    );
    store.save_realm_tree_projection(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        serde_json::json!({"name": "Demo"}),
    );

    let state = store.load();
    assert_eq!(state.sync_cursor.as_deref(), Some("sx:next"));
    assert_eq!(
        state.raw_operations[0].operation_id,
        "ak:operation:local-01"
    );
    assert_eq!(
        state.realm_tree_projections["ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE"]["name"],
        "Demo"
    );
}

#[test]
fn raw_operation_upsert_is_noop_for_identical_payload() {
    let path = temp_state_path("raw-op-upsert-noop");
    let mut store = LocalStateStore::with_path(path);
    let payload = serde_json::json!({
        "kind": "ak.strand.create",
        "event_id": "ak:event:A5CjrOiB2Ou5vIR73MtO1wiMh7Rt344Nx5_IemCvaBts",
        "operation_id": "op-upsert-1",
        "write_state": "synced",
        "body": {
            "object": {
                "id": "ak:strand:A2cyp-wJlPuymjpJ-uzhnuAOjpb5swIvzF282O3Hpsuc",
                "metadata": { "title": "Card" }
            }
        }
    });

    assert!(store.upsert_raw_operation(
        "op-upsert-1",
        Some("ak:realm:ANoIW62UhXZPVnYmlcWdw9pgsz6DguGcC8BtiQ5cPCW0".to_owned()),
        payload.clone()
    ));
    let first = store.load().raw_operations[0].clone();

    assert!(!store.upsert_raw_operation(
        "op-upsert-1",
        Some("ak:realm:ANoIW62UhXZPVnYmlcWdw9pgsz6DguGcC8BtiQ5cPCW0".to_owned()),
        payload
    ));
    let state = store.load();
    assert_eq!(state.raw_operations.len(), 1);
    assert_eq!(state.raw_operations[0].received_at, first.received_at);
    assert_eq!(state.raw_operations[0].payload, first.payload);
}

#[test]
fn raw_operation_upsert_reports_real_payload_changes() {
    let path = temp_state_path("raw-op-upsert-change");
    let mut store = LocalStateStore::with_path(path);
    let base = serde_json::json!({
        "kind": "ak.strand.update",
        "event_id": "ak:event:A4IDUD8Q8tl7ewzlG-L4VcakuszIKLzt14jlk_iVbMlo",
        "operation_id": "op-upsert-2",
        "write_state": "synced",
        "body": { "patch": { "title": { "$op": "set", "value": "Before" } } }
    });
    let enriched = serde_json::json!({
        "kind": "ak.strand.update",
        "event_id": "ak:event:A4IDUD8Q8tl7ewzlG-L4VcakuszIKLzt14jlk_iVbMlo",
        "operation_id": "op-upsert-2",
        "write_state": "synced",
        "synthesis_entry_id": "ak:synthesis:entry-1",
        "body": { "patch": { "title": { "$op": "set", "value": "After" } } }
    });

    assert!(store.upsert_raw_operation(
        "op-upsert-2",
        Some("ak:realm:ANoIW62UhXZPVnYmlcWdw9pgsz6DguGcC8BtiQ5cPCW0".to_owned()),
        base
    ));
    assert!(store.upsert_raw_operation(
        "op-upsert-2",
        Some("ak:realm:ANoIW62UhXZPVnYmlcWdw9pgsz6DguGcC8BtiQ5cPCW0".to_owned()),
        enriched
    ));
    let state = store.load();
    assert_eq!(state.raw_operations.len(), 1);
    assert_eq!(
        state.raw_operations[0].payload["synthesis_entry_id"],
        "ak:synthesis:entry-1"
    );
    assert_eq!(
        state.raw_operations[0].payload["body"]["patch"]["title"]["value"],
        "After"
    );
}

#[test]
fn raw_operation_upsert_keeps_redaction_tombstone_over_plaintext_create() {
    let path = temp_state_path("raw-op-upsert-redacted");
    let mut store = LocalStateStore::with_path(path);
    let tombstone = serde_json::json!({
        "kind": "ak.message.create",
        "event_id": "ak:event:AvjbTlKsgMrdHA0cxqw1cfj_MTtMB-TEM07Fypa1kO3c",
        "message_id": "ak:message:AzDvYhWMGpOMfhBP_S-EiVteQXCF4nbozLCGcAUoJeFo",
        "redacted": true,
        "state": "redacted",
        "content": {"kind": "ak.content.text", "body": "[redacted]"}
    });
    let plaintext = serde_json::json!({
        "kind": "ak.message.create",
        "event_id": "ak:event:AvjbTlKsgMrdHA0cxqw1cfj_MTtMB-TEM07Fypa1kO3c",
        "message_id": "ak:message:AzDvYhWMGpOMfhBP_S-EiVteQXCF4nbozLCGcAUoJeFo",
        "content": {"kind": "ak.content.text", "body": "secret"}
    });

    assert!(store.upsert_raw_operation(
        "ak:event:AvjbTlKsgMrdHA0cxqw1cfj_MTtMB-TEM07Fypa1kO3c",
        Some("ak:realm:ANoIW62UhXZPVnYmlcWdw9pgsz6DguGcC8BtiQ5cPCW0".to_owned()),
        tombstone
    ));
    assert!(!store.upsert_raw_operation(
        "ak:event:AvjbTlKsgMrdHA0cxqw1cfj_MTtMB-TEM07Fypa1kO3c",
        Some("ak:realm:ANoIW62UhXZPVnYmlcWdw9pgsz6DguGcC8BtiQ5cPCW0".to_owned()),
        plaintext
    ));
    let state = store.load();
    assert_eq!(state.raw_operations.len(), 1);
    assert_eq!(state.raw_operations[0].payload["redacted"], true);
    assert_eq!(
        state.raw_operations[0].payload["content"]["body"],
        "[redacted]"
    );
}

#[test]
fn raw_operation_upsert_replaces_message_timeline_projection_by_message_id() {
    let path = temp_state_path("raw-op-upsert-message-id");
    let mut store = LocalStateStore::with_path(path);
    let realm_id = Some("ak:realm:ANoIW62UhXZPVnYmlcWdw9pgsz6DguGcC8BtiQ5cPCW0".to_owned());
    let message_id = "ak:message:AntDks2Ypq2edZVciQhfNWCud9e-LBe42626eTdnAitw";
    let original = serde_json::json!({
        "kind": "ak.message.create",
        "event_id": "ak:event:ApXhaaMwhtt1qJI3KzG1An1ycgAATlgkoY-sh0vvwPyg",
        "message_id": message_id,
        "content": {"kind": "ak.content.text", "body": "original"}
    });
    let revised_projection = serde_json::json!({
        "kind": "ak.message.create",
        "event_id": "ak:event:AQ5mkqPk7A8twbpnrMESIjejFOquaCm65zFB3pWgINVc",
        "message_id": message_id,
        "content": {"kind": "ak.content.text", "body": "edited"}
    });
    let redacted_projection = serde_json::json!({
        "kind": "ak.message.create",
        "event_id": "ak:event:AQ5mkqPk7A8twbpnrMESIjejFOquaCm65zFB3pWgINVc",
        "message_id": message_id,
        "redacted": true,
        "state": "redacted",
        "content": {"kind": "ak.content.text", "body": "[redacted]"}
    });

    assert!(store.upsert_raw_operation(
        "ak:event:ApXhaaMwhtt1qJI3KzG1An1ycgAATlgkoY-sh0vvwPyg",
        realm_id.clone(),
        original,
    ));
    assert!(store.upsert_raw_operation(
        "ak:event:AQ5mkqPk7A8twbpnrMESIjejFOquaCm65zFB3pWgINVc",
        realm_id.clone(),
        revised_projection,
    ));
    assert!(store.upsert_raw_operation(
        "ak:event:AQ5mkqPk7A8twbpnrMESIjejFOquaCm65zFB3pWgINVc",
        realm_id,
        redacted_projection,
    ));

    let state = store.load();
    assert_eq!(state.raw_operations.len(), 1);
    assert_eq!(
        state.raw_operations[0].payload["event_id"],
        "ak:event:AQ5mkqPk7A8twbpnrMESIjejFOquaCm65zFB3pWgINVc"
    );
    assert_eq!(
        state.raw_operations[0].payload["content"]["body"],
        "[redacted]"
    );
    assert_eq!(state.raw_operations[0].payload["redacted"], true);
}

#[test]
fn realm_destroy_receipt_tracks_destroy_without_raw_operation_scan() {
    let path = temp_state_path("realm-lifecycle");
    let mut store = LocalStateStore::with_path(path.clone());
    let realm_id = "ak:realm:A1DWRbYpSLqaz1EXdp9PmxYNU_btez6laT2_ddyijO3g";

    assert!(!store.realm_is_destroyed(realm_id));
    store.append_raw_operation(
        "ak:operation:destroy",
        Some(realm_id.to_owned()),
        serde_json::json!({"kind": "ak.realm.destroy"}),
    );

    assert!(store.realm_is_destroyed(realm_id));
    let lifecycle = store.load().realm_destroy_receipts;
    assert!(lifecycle[realm_id].destroyed);
    assert_eq!(
        lifecycle[realm_id].destroyed_operation_id.as_deref(),
        Some("ak:operation:destroy")
    );

    let reader = LocalStateStore::with_path(path);
    assert!(reader.realm_is_destroyed(realm_id));

    store.forget_realm_tree_projection(realm_id);
    assert!(!store.realm_is_destroyed(realm_id));
}

#[test]
fn local_state_store_persists_to_disk_between_instances() {
    let path = temp_state_path("persisted");
    let mut writer = LocalStateStore::with_path(path.clone());
    writer.save_sync_cursor("sx:persisted");

    let reader = LocalStateStore::with_path(path);
    let state = reader.load();
    assert_eq!(state.sync_cursor.as_deref(), Some("sx:persisted"));
}

#[test]
fn local_state_store_persists_notifications_and_mute_preferences() {
    let path = temp_state_path("notifications");
    let mut store = LocalStateStore::with_path(path.clone());
    let notification = crate::state::projection::notifications::test_event_notification(
        1,
        arkret_sdk::NotificationKind::Message,
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        None,
        serde_json::json!({"body": "Hello"}),
    );
    let notification_id = notification.notification_id();
    store.save_notification_projection(vec![notification]);
    store.set_notification_read(notification_id.clone(), true);
    store.set_notification_archived(notification_id.clone(), true);
    store.set_realm_muted(
        "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        true,
    );
    store.set_notification_kind_enabled("message", false);

    let reader = LocalStateStore::with_path(path);
    assert_eq!(reader.notification_projection().len(), 1);
    assert!(reader.notification_state_for(&notification_id).read);
    assert!(reader.notification_state_for(&notification_id).archived);
    assert!(reader.is_realm_muted("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"));
    assert!(!reader.notification_kind_enabled("message"));
}

#[test]
fn realm_watch_level_set_get_roundtrip() {
    let path = temp_state_path("watch-level-roundtrip");
    let mut store = LocalStateStore::with_path(path.clone());
    store.set_realm_watch_level(
        "ak:realm:ASN5uMi28AEbWgFm2GmchqhztuhBSoOzWPAht4VgFoXk",
        WatchLevel::All,
    );
    store.set_realm_watch_level(
        "ak:realm:AF-jk6ju8IdjVa7Gf0eeCnOu9EHYKDaY47I98_7lPyfo",
        WatchLevel::Muted,
    );
    // Setting the protocol default clears the override.
    store.set_realm_watch_level(
        "ak:realm:A07tgRPkVdM8D0plTHJpzI0saqQ6lVjWeBAfNVhSjnCE",
        WatchLevel::Participating,
    );
    store.set_realm_watch_level(
        "ak:realm:A07tgRPkVdM8D0plTHJpzI0saqQ6lVjWeBAfNVhSjnCE",
        WatchLevel::MentionsOnly,
    );

    let reader = LocalStateStore::with_path(path);
    assert_eq!(
        reader.realm_watch_level("ak:realm:ASN5uMi28AEbWgFm2GmchqhztuhBSoOzWPAht4VgFoXk"),
        WatchLevel::All
    );
    assert_eq!(
        reader.realm_watch_level("ak:realm:AF-jk6ju8IdjVa7Gf0eeCnOu9EHYKDaY47I98_7lPyfo"),
        WatchLevel::Muted
    );
    assert_eq!(
        reader.realm_watch_level("ak:realm:A07tgRPkVdM8D0plTHJpzI0saqQ6lVjWeBAfNVhSjnCE"),
        WatchLevel::MentionsOnly
    );
    assert!(
        !reader
            .realm_watch_levels()
            .contains_key("ak:realm:A07tgRPkVdM8D0plTHJpzI0saqQ6lVjWeBAfNVhSjnCE")
    );
    // The binary-mute helper only reports `Muted` realms.
    assert_eq!(
        reader.muted_realms(),
        vec!["ak:realm:AF-jk6ju8IdjVa7Gf0eeCnOu9EHYKDaY47I98_7lPyfo".to_owned()]
    );
    assert!(reader.is_realm_muted("ak:realm:AF-jk6ju8IdjVa7Gf0eeCnOu9EHYKDaY47I98_7lPyfo"));
    assert!(!reader.is_realm_muted("ak:realm:ASN5uMi28AEbWgFm2GmchqhztuhBSoOzWPAht4VgFoXk"));
}

#[test]
fn local_state_store_persists_private_read_cursors() {
    let path = temp_state_path("read-cursor");
    let mut store = LocalStateStore::with_path(path.clone());
    const DEVICE_ID: &str = "ak:device:01964137-0000-7000-8000-000000000001";
    const REALM_ID: &str = "ak:realm:AV56KkeEaMSR4caEiVYFp1MtJk3sQ_Zn0VETrzEWQlU3";
    const EVENT_ID: &str = "ak:event:AapALysveT_m0ubp6kTGkXSK9371_ilR-kAJwNFmxyjr";
    let marker = store
        .build_read_cursor_candidate("did:web:alice.example", DEVICE_ID, REALM_ID, None, EVENT_ID)
        .unwrap();
    store.seed_read_cursor_projection(marker.clone()).unwrap();

    assert_eq!(marker.body.realm_id, REALM_ID);
    assert_eq!(marker.body.position.event_id.as_str(), EVENT_ID);
    assert_eq!(marker.body.read_scope.kind.as_str(), "realm");
    assert_eq!(marker.body.read_scope.track, None);

    let reader = LocalStateStore::with_path(path);
    let persisted = reader
        .read_cursor_for(REALM_ID, None)
        .expect("read marker persisted");
    assert_eq!(persisted.body.id, marker.body.id);
    assert_eq!(persisted.actor, "did:web:alice.example");
    assert_eq!(persisted.device_id, DEVICE_ID);
    assert_eq!(persisted.body.position.event_id.as_str(), EVENT_ID);
}

#[test]
fn local_state_store_persists_canonical_read_cursor_outcome() {
    let path = temp_state_path("read-cursor-outcome");
    let mut store = LocalStateStore::with_path(path.clone());
    let outcome = arkret_sdk::ReadMarkerOutcome {
        realm_id: arkret_sdk::RealmId::new("ak:realm:AV56KkeEaMSR4caEiVYFp1MtJk3sQ_Zn0VETrzEWQlU3")
            .unwrap(),
        actor_id: crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap(),
        device_id: arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001")
            .unwrap(),
        read_scope: read_scope_for_cursor(
            "ak:realm:AV56KkeEaMSR4caEiVYFp1MtJk3sQ_Zn0VETrzEWQlU3",
            None,
        ),
        position: ReadCursorPosition {
            event_id: arkret_sdk::EventId::new(
                "ak:event:AapALysveT_m0ubp6kTGkXSK9371_ilR-kAJwNFmxyjr",
            )
            .unwrap(),
            hlc: arkret_sdk::Hlc::new("019641370000-0001-deadbeef").unwrap(),
        },
        updated_at: chrono::DateTime::parse_from_rfc3339("2026-07-30T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    };

    store.apply_read_cursor_outcome(outcome).unwrap();

    let persisted = LocalStateStore::with_path(path)
        .read_cursor_for(
            "ak:realm:AV56KkeEaMSR4caEiVYFp1MtJk3sQ_Zn0VETrzEWQlU3",
            None,
        )
        .expect("canonical read cursor outcome persisted");
    assert_eq!(
        persisted.body.position.event_id.as_str(),
        "ak:event:AapALysveT_m0ubp6kTGkXSK9371_ilR-kAJwNFmxyjr"
    );
    assert_eq!(
        persisted.updated_at.to_rfc3339(),
        "2026-07-30T00:00:00+00:00"
    );
}

#[test]
fn local_state_store_ingests_read_cursor_update_to_device() {
    let path = temp_state_path("read-cursor-update");
    let mut store = LocalStateStore::with_path(path.clone());
    store.ingest_to_device_messages(&[serde_json::from_value(serde_json::json!({
        "device_message_id": "ak:device_message:01904100-0000-7000-8000-000000000005",
        "kind": "ak.read_cursor.update",
        "sender_principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
        "sender_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
        "recipient_principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
        "recipient_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
        "sent_at": "2026-06-24T00:00:00.000Z",
        "expires_at": "2099-06-25T00:00:00.000Z",
        "content": {
            "schema": "ak.schema.read_cursor.v1",
            "actor_id": "ak:did_core:web:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "realm_id": "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            "read_scope": {
                "kind": "strand",
                "container_ref": "ak:strand:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
                "track_name": "discussion"
            },
            "position": {
                "event_id": "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
                "hlc": "019041000000-0001-deadbeef"
            },
            "updated_at": "2026-06-24T00:00:00.000Z"
        }
    }))
    .unwrap()]);

    let reader = LocalStateStore::with_path(path);
    let marker = reader
        .read_cursor_for(
            "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            Some("ak:strand:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy"),
        )
        .expect("read cursor update persisted");
    assert_eq!(marker.actor, "ak:did_core:web:alice.example");
    assert_eq!(
        marker.body.position.event_id.as_str(),
        "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM"
    );
}

#[test]
fn local_state_store_accepts_server_read_cursor_winner_with_lower_hlc() {
    let path = temp_state_path("read-cursor-server-winner");
    let mut store = LocalStateStore::with_path(path.clone());
    let envelope = |message_suffix: &str, event_suffix: &str, hlc: &str, sent_at: &str| {
        let event_seed = u8::from_str_radix(&event_suffix[event_suffix.len() - 2..], 16).unwrap();
        let event_id = arkret_sdk::EventId::from_digest(
            arkret_sdk::canonical::DigestSuite::Sha256,
            [event_seed; 32],
        );
        serde_json::from_value(serde_json::json!({
            "device_message_id": format!(
                "ak:device_message:01904100-0000-7000-8000-{message_suffix}"
            ),
            "kind": "ak.read_cursor.update",
            "sender_principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
            "sender_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "recipient_principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
            "recipient_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "sent_at": sent_at,
            "expires_at": "2099-06-25T00:00:00.000Z",
            "content": {
                "schema": "ak.schema.read_cursor.v1",
                "actor_id": "ak:did_core:web:alice.example",
                "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "realm_id": "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
                "read_scope": {
                    "kind": "strand",
                    "container_ref": "ak:strand:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
                    "track_name": "discussion"
                },
                "position": {
                    "event_id": event_id,
                    "hlc": hlc
                },
                "updated_at": sent_at
            }
        }))
        .unwrap()
    };
    let locally_known = envelope(
        "000000000006",
        "000000000004",
        "019041000000-0002-deadbeef",
        "2026-06-24T00:00:00.000Z",
    );
    let canonical_server_winner = envelope(
        "000000000007",
        "000000000005",
        "019041000000-0001-deadbeef",
        "2026-06-24T00:00:01.000Z",
    );
    let canonical_server_event_id =
        arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [5; 32]);

    assert_eq!(store.ingest_to_device_messages(&[locally_known]), 1);
    assert_eq!(
        store.ingest_to_device_messages(&[canonical_server_winner]),
        1
    );

    let reader = LocalStateStore::with_path(path);
    let marker = reader
        .read_cursor_for(
            "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            Some("ak:strand:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy"),
        )
        .expect("canonical server read cursor persisted");
    assert_eq!(
        marker.body.position.event_id.as_str(),
        canonical_server_event_id.as_str()
    );
    assert_eq!(
        marker.body.position.hlc.as_str(),
        "019041000000-0001-deadbeef"
    );
}

#[test]
fn local_state_store_durably_deduplicates_device_message_envelopes() {
    let path = temp_state_path("device-message-dedup");
    let message: arkret_sdk::DeviceMessageEnvelope = serde_json::from_value(serde_json::json!({
    "device_message_id": "ak:device_message:0196419b-0000-7000-8000-000000000071",
    "kind": "ak.key.verification.request",
    "sender_principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
    "sender_device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
    "recipient_principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
    "recipient_device_id": "ak:device:0196419b-0000-7000-8000-000000000002",
    "sent_at": "2026-07-17T00:00:00.000Z",
    "expires_at": "2099-07-17T00:10:00.000Z",
    "content": {
        "from_device": "ak:device:0196419b-0000-7000-8000-000000000001",
        "pairing_code": "7H2K9M4Q"
    }
    }))
    .unwrap();

    let mut writer = LocalStateStore::with_path(path.clone());
    assert_eq!(
        writer.ingest_to_device_messages(std::slice::from_ref(&message)),
        1
    );
    assert_eq!(
        writer.ingest_to_device_messages(std::slice::from_ref(&message)),
        0
    );
    assert_eq!(writer.to_device_inbox().len(), 1);
    assert_eq!(writer.load().to_device_receipts.len(), 1);
    assert_eq!(
        writer.dismiss_pairing_to_device_message(
            "ak:device:0196419b-0000-7000-8000-000000000001",
            "7H2K9M4Q",
        ),
        1
    );

    let mut reopened = LocalStateStore::with_path(path);
    assert_eq!(reopened.ingest_to_device_messages(&[message]), 0);
    assert!(reopened.to_device_inbox().is_empty());

    let conflicting: arkret_sdk::DeviceMessageEnvelope =
        serde_json::from_value(serde_json::json!({
        "device_message_id": "ak:device_message:0196419b-0000-7000-8000-000000000071",
        "kind": "ak.key.verification.request",
        "sender_principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
        "sender_device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
        "recipient_principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
        "recipient_device_id": "ak:device:0196419b-0000-7000-8000-000000000002",
        "sent_at": "2026-07-17T00:00:00.000Z",
        "expires_at": "2099-07-17T00:10:00.000Z",
        "content": {
            "from_device": "ak:device:0196419b-0000-7000-8000-000000000001",
            "pairing_code": "8J3L5N7P"
        }
        }))
        .unwrap();
    assert_eq!(reopened.ingest_to_device_messages(&[conflicting]), 0);
    assert!(
        reopened
            .persist_error()
            .is_some_and(|error| error.contains("device_message_conflict"))
    );
    assert!(reopened.to_device_inbox().is_empty());
}

#[test]
fn local_state_store_keeps_thread_read_cursors_separate() {
    let path = temp_state_path("thread-read-cursor");
    let mut store = LocalStateStore::with_path(path);
    const REALM_ID: &str = "ak:realm:AYzH43fmsgS6dn7noiHeYxAKUUdkhaJBnOGaWvu3MlBC";
    const TOPIC_EVENT_ID: &str = "ak:event:AUJCoQiXEV11T2wYGgq5vjXcfFcLnKQHPCp3GyzHYTDe";
    const THREAD_ID: &str = "ak:thread:01964137-0000-7000-8000-000000000031";
    const THREAD_EVENT_ID: &str = "ak:event:AXSojayi5PgA26VxFw98EsOKL49Nzr4Vvr9LPxdqgzZP";
    let topic_marker = store
        .build_read_cursor_candidate(
            "did:web:alice.example",
            "ak:device:01964137-0000-7000-8000-000000000001",
            REALM_ID,
            None,
            TOPIC_EVENT_ID,
        )
        .unwrap();
    store.seed_read_cursor_projection(topic_marker).unwrap();
    let thread_marker = store
        .build_read_cursor_candidate(
            "did:web:alice.example",
            "ak:device:01964137-0000-7000-8000-000000000001",
            REALM_ID,
            Some(THREAD_ID.to_owned()),
            THREAD_EVENT_ID,
        )
        .unwrap();
    store.seed_read_cursor_projection(thread_marker).unwrap();

    assert_eq!(
        store
            .read_cursor_for(REALM_ID, None)
            .expect("topic marker")
            .body
            .position
            .event_id
            .as_str(),
        TOPIC_EVENT_ID
    );
    assert_eq!(
        store
            .read_cursor_for(REALM_ID, Some(THREAD_ID))
            .expect("thread marker")
            .body
            .position
            .event_id
            .as_str(),
        THREAD_EVENT_ID
    );
}

#[test]
fn local_state_store_persists_push_registration_state() {
    let path = temp_state_path("push-registration");
    let mut store = LocalStateStore::with_path(path.clone());
    store.save_push_registration(PushRegistrationState {
        schema_version: chime::PUSH_REGISTRATION_STATE_SCHEMA_VERSION,
        principal_id: None,
        registration_id: Some("push:local".to_owned()),
        device_id: "dev_inkson".to_owned(),
        platform: Some("desktop".to_owned()),
        app_id: Some("inkson".to_owned()),
        push_gateway: "https://push.example/_arkret/edge/push/notify".to_owned(),
        push_key_hash: "sha256:abc".to_owned(),
        push_key_preview: "desktop:<redacted,len=5>".to_owned(),
        registered_at: Some("2026-04-29T00:00:00.000Z".to_owned()),
        expires_at: None,
        refresh_hint: None,
        last_success_at: Some("2026-04-29T00:00:00.000Z".to_owned()),
        last_error: None,
    });

    let mut reader = LocalStateStore::with_path(path);
    let state = reader.push_registration().expect("push registration");
    assert_eq!(state.registration_id.as_deref(), Some("push:local"));
    assert_eq!(state.device_id, "dev_inkson");

    reader.clear_push_registration();
    assert!(reader.push_registration().is_none());
}

#[test]
fn dpop_device_key_uses_secure_key_store() {
    use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore};
    // The secure-store write/read path resolves the user namespace through
    // the process-global device-seed scope; hold the guard so a parallel
    // test cannot clear or re-point that scope mid-test.
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
    let path = temp_state_path("dpop-secure-store");
    let mut store = LocalStateStore::with_path(path);
    let secure = MemorySecureKeyStore::default();
    let user_store = crate::secure_key_store::UserLocalStore::new(
        arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
    );
    user_store.activate();
    let record = DpopDeviceKeyRecord {
        seed_b64: "seed-material".to_owned(),
        jkt: "jkt-1".to_owned(),
        created_at: Utc::now(),
    };

    let public_record = store
        .set_dpop_device_key_with_secure_store(Some(record.clone()), &secure)
        .expect("store dpop key")
        .expect("public record");
    assert_eq!(public_record.jkt, "jkt-1");
    assert!(public_record.seed_b64.is_empty());
    assert!(store.dpop_device_key().unwrap().seed_b64.is_empty());

    let secure_json = secure
        .get_secret(&user_store.secret_key(LocalStateStore::SECURE_DPOP_DEVICE_KEY))
        .expect("read secure dpop")
        .expect("secure dpop present");
    assert!(secure_json.contains("seed-material"));

    let loaded = store
        .load_dpop_device_key_with_secure_store(&secure)
        .expect("load dpop key")
        .expect("dpop key present");
    assert_eq!(loaded, record);

    store
        .set_dpop_device_key_with_secure_store(None, &secure)
        .expect("clear dpop key");
    assert!(store.dpop_device_key().is_none());
    assert!(
        secure
            .get_secret(&user_store.secret_key(LocalStateStore::SECURE_DPOP_DEVICE_KEY))
            .expect("read secure dpop after clear")
            .is_none()
    );
}

#[test]
fn clear_account_scoped_preserves_device_level_and_session_grant_state() {
    let path = temp_state_path("clear-account");
    let mut store = LocalStateStore::with_path(path);
    // Account-scoped projections.
    store.save_sync_cursor("sx:before");
    store.save_realm_tree_projection("ak:space:a", serde_json::json!({}));
    store.save_private_data("did:web:tester.example", "theme", "night");
    store.ensure_cached_loaded();
    store.cached.saved_account_data.insert(
        "ak.saved.v1:test".to_owned(),
        serde_json::json!({ "kind": "saved_item" }),
    );
    // Device-level state that MUST survive. ensure_local_identity
    // generates a fresh seed + DID and persists the record under
    // local_identity — the canonical device-level field this helper
    // is responsible for not nuking.
    let identity = store
        .ensure_local_identity()
        .expect("ensure_local_identity should succeed in plaintext mode");
    let grant = PersistedSessionGrant {
        grant_jwt: "alice.grant".to_owned(),
        session_private_key_pem: "pem".to_owned(),
        grant_id: "g-alice".to_owned(),
        audience: "did:web:principal.example".to_owned(),
        principal_id: "did:web:alice.example".to_owned(),
        device_id: "device-1".to_owned(),
        principal_server_url: "https://principal.example".to_owned(),
        grant_expires_at: None,
        stored_at: chrono::Utc::now(),
    };
    store.set_session_grant(Some(grant.clone()));

    store.clear_account_scoped();

    let state = store.load();
    assert!(state.sync_cursor.is_none(), "sync cursor should be wiped");
    assert!(
        state.realm_tree_projections.is_empty(),
        "projections should be wiped"
    );
    assert!(
        state.saved_account_data.is_empty(),
        "saved account_data staging should be wiped"
    );
    assert!(
        state.private_data.is_empty(),
        "private_data is account-scoped and should be wiped"
    );
    assert!(
        state.local_identity.is_some(),
        "device identity must survive an account-level wipe"
    );
    assert_eq!(
        state.local_identity.as_ref().unwrap().did_key,
        identity.local_signing_did,
    );
    assert_eq!(state.session_grant.as_ref(), Some(&grant));
}

#[test]
fn production_persist_policy_strips_session_credentials_from_account_state() {
    let state = ClientLocalState {
        sync_cursor: Some("ak:cursor:safe".to_owned()),
        session_grant: Some(PersistedSessionGrant {
            grant_jwt: "secret.grant.jwt".to_owned(),
            session_private_key_pem: "secret-session-private-key".to_owned(),
            grant_id: "grant-id".to_owned(),
            audience: "did:web:principal.example".to_owned(),
            principal_id: "did:web:alice.example".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
            principal_server_url: "https://principal.example".to_owned(),
            grant_expires_at: None,
            stored_at: chrono::Utc::now(),
        }),
        ..Default::default()
    };

    let persisted = e2ee_safe_persist_state_with_policy(&state, true);
    let json = serde_json::to_string(&persisted).unwrap();
    assert!(persisted.session_grant.is_none());
    assert_eq!(persisted.sync_cursor.as_deref(), Some("ak:cursor:safe"));
    assert!(!json.contains("secret.grant.jwt"));
    assert!(!json.contains("secret-session-private-key"));
}

#[test]
fn switch_active_account_isolates_accounts_per_did() {
    let path = temp_state_path("adopt-account-scope");
    let mut store = LocalStateStore::with_path(path);

    // Establish alice as the active account with a grant + cursor + projection.
    assert!(
        store.switch_active_account("did:web:alice.example"),
        "first adopt (no active account) switches and reports a change"
    );
    assert_eq!(
        store.active_account_did().as_deref(),
        Some("did:web:alice.example")
    );
    store.save_sync_cursor("sx:alice");
    store.save_realm_tree_projection("ak:space:a", serde_json::json!({}));
    store.set_session_grant(Some(PersistedSessionGrant {
        grant_jwt: "alice.grant".to_owned(),
        session_private_key_pem: "pem".to_owned(),
        grant_id: "g-alice".to_owned(),
        audience: "did:web:principal.example".to_owned(),
        principal_id: "did:web:alice.example".to_owned(),
        device_id: "device-1".to_owned(),
        principal_server_url: "https://principal.example".to_owned(),
        grant_expires_at: None,
        stored_at: chrono::Utc::now(),
    }));

    // Re-adopting the same actor is a no-op and keeps alice's state.
    assert!(!store.switch_active_account("did:web:alice.example"));
    assert_eq!(store.load().sync_cursor.as_deref(), Some("sx:alice"));
    assert!(store.load().session_grant.is_some());

    // Switching to a different identity loads bob's OWN (empty) entry — alice's
    // grant/cursor/projection live in a separate key and can never leak into
    // bob's session.
    assert!(store.switch_active_account("did:web:bob.example"));
    let state = store.load();
    assert!(
        state.sync_cursor.is_none(),
        "bob's fresh entry has no cursor"
    );
    assert!(
        state.realm_tree_projections.is_empty(),
        "bob's fresh entry has no projections"
    );
    assert!(
        state.session_grant.is_none(),
        "alice's grant must not appear in bob's entry"
    );
    assert_eq!(
        store.active_account_did().as_deref(),
        Some("did:web:bob.example"),
        "active account points at the new identity"
    );

    // Both accounts are tracked, and switching back to alice restores her own
    // independent state — structural per-account isolation, not a wipe.
    let mut known = store.known_account_dids();
    known.sort();
    assert_eq!(known, vec!["did:web:alice.example", "did:web:bob.example"]);
    assert!(store.switch_active_account("did:web:alice.example"));
    assert_eq!(store.load().sync_cursor.as_deref(), Some("sx:alice"));
    assert!(
        store.load().session_grant.is_some(),
        "alice's grant survives a round-trip through bob"
    );
}

#[test]
fn per_account_entries_persist_independently_across_store_instances() {
    let path = temp_state_path("per-account-persist");
    {
        let mut store = LocalStateStore::with_path(path.clone());
        store.switch_active_account("did:web:alice.example");
        store.save_sync_cursor("sx:alice");
        store.switch_active_account("did:web:bob.example");
        store.save_sync_cursor("sx:bob");
        // Bob is the active account at flush time.
    }
    // A fresh store reloads the persisted active account (bob) + index.
    let reader = LocalStateStore::with_path(path.clone());
    assert_eq!(
        reader.active_account_did().as_deref(),
        Some("did:web:bob.example")
    );
    assert_eq!(reader.load().sync_cursor.as_deref(), Some("sx:bob"));
    // Switching back to alice reads alice's OWN persisted entry, untouched.
    let mut reader = reader;
    reader.switch_active_account("did:web:alice.example");
    assert_eq!(reader.load().sync_cursor.as_deref(), Some("sx:alice"));
}

#[test]
fn stale_store_instance_cannot_flush_previous_account_into_new_account() {
    let path = temp_state_path("stale-instance-account-fence");
    let facebook = "ak:realm:Abs3Q1pCqMmpdkCB57E6rKcrsHG2Xc8YeTBUR3YVG7ld";

    let mut stale = LocalStateStore::with_path(path.clone());
    stale.switch_active_account("did:web:alice.example");
    stale.save_realm_tree_projection(
        facebook,
        serde_json::json!({"summary": {"name": "Facebook"}}),
    );

    // A second live store instance changes the shared root to Bob. This models
    // a late async task that still retains Alice's in-memory cache after account
    // registration/switch completed elsewhere.
    let mut switcher = LocalStateStore::with_path(path.clone());
    switcher.switch_active_account("did:web:bob.example");
    switcher.save_sync_cursor("sx:bob");

    let error = stale
        .flush()
        .expect_err("a stale cache scope must never write into the active account");
    assert!(error.to_string().contains("refusing cross-account"));
    assert!(
        stale.load().realm_tree_projections.is_empty(),
        "reads from a stale instance must resolve the active account, not expose Alice"
    );

    let reader = LocalStateStore::with_path(path);
    assert_eq!(reader.load().sync_cursor.as_deref(), Some("sx:bob"));
    assert!(
        !reader.load().realm_tree_projections.contains_key(facebook),
        "Alice's Facebook realm must not be persisted under Bob"
    );
}

#[test]
fn active_account_match_uses_stable_core_id() {
    let path = temp_state_path("active-account-core-id");
    let mut store = LocalStateStore::with_path(path);
    store.switch_active_account("did:webvh:zSameScid:old.example:users:alice");

    assert!(store.active_account_matches("ak:did_core:webvh:zSameScid"));
    assert!(store.active_account_matches("did:webvh:zSameScid:new.example:people:alice"));
    assert!(!store.active_account_matches("did:webvh:zOtherScid:new.example:people:alice"));
}

#[test]
fn same_core_full_id_update_reuses_the_local_account_state() {
    let path = temp_state_path("same-core-local-state");
    let mut store = LocalStateStore::with_path(path);
    store.switch_active_account("did:webvh:zSameScid:old.example:users:alice");
    store.save_sync_cursor("sx:before-resolution-update");
    store.save_realm_tree_projection(
        "ak:realm:ASameCoreRealm11111111111111111111111111111111111",
        serde_json::json!({"summary": {"name": "same identity"}}),
    );

    store.switch_active_account("did:webvh:zSameScid:new.example:people:alice");
    assert_eq!(
        store.load().sync_cursor.as_deref(),
        Some("sx:before-resolution-update")
    );
    assert_eq!(store.load().realm_tree_projections.len(), 1);
}

#[test]
fn forget_account_purges_only_the_target_entry_and_device_prefs_survive() {
    let path = temp_state_path("forget-account");
    let mut store = LocalStateStore::with_path(path);
    store.set_device_pref("theme", "night");
    store.switch_active_account("did:web:alice.example");
    store.save_sync_cursor("sx:alice");
    store.switch_active_account("did:web:bob.example");
    store.save_sync_cursor("sx:bob");

    store.forget_account("did:web:bob.example");
    assert!(
        !store
            .known_account_dids()
            .iter()
            .any(|did| did == "did:web:bob.example"),
        "purged account leaves known_dids"
    );
    assert!(
        store.active_account_did().is_none(),
        "purging the active account clears the active pointer"
    );
    // Cross-account device prefs are untouched by purging an account.
    assert_eq!(store.device_pref("theme").as_deref(), Some("night"));
    // Alice's entry is intact.
    store.switch_active_account("did:web:alice.example");
    assert_eq!(store.load().sync_cursor.as_deref(), Some("sx:alice"));
}

#[test]
fn primary_handle_is_per_account_and_readable_by_did() {
    let path = temp_state_path("primary-handle");
    let mut store = LocalStateStore::with_path(path);

    store.switch_active_account("did:webvh:zA:alice.example");
    store.set_primary_handle("alice");
    store.switch_active_account("did:webvh:zB:david.example");
    store.set_primary_handle("david");

    // Each account's handle is readable BY DID without making it active.
    assert_eq!(
        store
            .primary_handle_for_did("did:webvh:zA:alice.example")
            .as_deref(),
        Some("alice")
    );
    assert_eq!(
        store
            .primary_handle_for_did("did:webvh:zB:david.example")
            .as_deref(),
        Some("david")
    );
    // Unknown / empty → None.
    assert!(
        store
            .primary_handle_for_did("did:webvh:zC:nobody.example")
            .is_none()
    );
    assert!(store.primary_handle_for_did("").is_none());
}

#[test]
fn explicit_account_primary_handle_update_is_scoped_and_can_clear() {
    let path = temp_state_path("explicit-primary-handle");
    let mut store = LocalStateStore::with_path(path);
    let alice = "did:webvh:zA:alice.example";
    let david = "did:webvh:zB:david.example";

    store.switch_active_account(david);
    store.set_primary_handle_for_did(alice, "alice:local.host");

    assert_eq!(store.active_account_did().as_deref(), Some(david));
    assert_eq!(
        store.primary_handle_for_did(alice).as_deref(),
        Some("alice:local.host")
    );

    store.set_primary_handle_for_did(alice, "");

    assert_eq!(store.active_account_did().as_deref(), Some(david));
    assert!(store.primary_handle_for_did(alice).is_none());
}

#[test]
fn known_accounts_lists_each_account_with_its_handle_and_device() {
    let path = temp_state_path("known-accounts");
    let mut store = LocalStateStore::with_path(path);

    store.register_known_account("did:webvh:zA:alice.example");
    store.switch_active_account("did:webvh:zA:alice.example");
    store.set_primary_handle("alice");
    store.set_session_grant(Some(PersistedSessionGrant {
        grant_jwt: "alice.grant".to_owned(),
        session_private_key_pem: "pem".to_owned(),
        grant_id: "g-alice".to_owned(),
        audience: "did:web:alice.example".to_owned(),
        principal_id: "did:webvh:zA:alice.example".to_owned(),
        device_id: "ak:device:alice-1".to_owned(),
        principal_server_url: "https://alice.example".to_owned(),
        grant_expires_at: None,
        stored_at: chrono::Utc::now(),
    }));

    store.register_known_account("did:webvh:zB:david.example");
    store.switch_active_account("did:webvh:zB:david.example");
    store.set_primary_handle("david");

    let accounts = store.known_accounts();
    assert_eq!(accounts.len(), 2);
    let alice = accounts
        .iter()
        .find(|account| account.did == "did:webvh:zA:alice.example")
        .expect("alice present");
    assert_eq!(alice.handle, "alice");
    // device_id / server_url come from alice's OWN persisted grant, read by DID
    // (not the active account, which is currently david).
    assert_eq!(alice.device_id, "ak:device:alice-1");
    assert_eq!(alice.server_url, "https://alice.example");
    let david = accounts
        .iter()
        .find(|account| account.did == "did:webvh:zB:david.example")
        .expect("david present");
    assert_eq!(david.handle, "david");
}

#[test]
fn adopt_pending_login_keeps_pending_device_for_new_account() {
    // begin/adopt_pending_login mutate the process-global pending-login id.
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
    let path = temp_state_path("pending-new");
    let mut store = LocalStateStore::with_path(path);
    store.begin_pending_login("ak:device:new-1", Some("jkt-new"));
    assert!(store.pending_login().is_some());

    // A DID never seen on this browser is a new account.
    let newcomer = arkret_sdk::DidFullId::new("did:web:newcomer.example".to_owned()).unwrap();
    let is_new = store.adopt_pending_login(&newcomer);
    assert!(is_new, "an unknown DID adopts as a new account");
    assert!(store.pending_login().is_none(), "pending is cleared");
    assert_eq!(
        store.active_account_did().as_deref(),
        Some("did:web:newcomer.example")
    );
}

#[test]
fn pending_login_clears_the_previous_accounts_process_signer() {
    // begin_pending_login mutates the process-global pending-login id; the
    // seed-scope guard comes first, matching the crate-wide lock order.
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
    let _signer_guard = crate::event_signer::ActiveSignerTestGuard::replace(None);
    crate::event_signer::activate_device_signer_from_seed_for_device(
        [3; 32],
        None,
        Some("ak:device:019f0000-0000-7000-8000-000000000099"),
    )
    .unwrap();
    assert!(crate::event_signer::active_signer().is_some());
    let path = temp_state_path("pending-clears-process-signer");
    let mut store = LocalStateStore::with_path(path);

    store.begin_pending_login("ak:device:019f0000-0000-7000-8000-000000000001", None);

    assert!(crate::event_signer::active_signer().is_none());
}

#[test]
fn adopt_pending_login_preserves_returning_account_entry() {
    // begin/adopt_pending_login mutate the process-global pending-login id.
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
    let path = temp_state_path("pending-returning");
    let mut store = LocalStateStore::with_path(path);
    // Alice already has a persisted entry on this browser.
    store.switch_active_account("did:web:alice.example");
    store.save_sync_cursor("sx:alice");
    // Sign out, then a fresh sign-in kicks off pending device material.
    store.begin_pending_login("ak:device:fresh-2", Some("jkt-fresh"));
    assert!(
        store.active_account_did().is_none(),
        "pending transaction must not expose an authenticated account"
    );
    assert_eq!(
        store.last_selected_account_did().as_deref(),
        Some("did:web:alice.example"),
        "pending login must retain the last-selected account for cancellation/reload"
    );
    assert!(
        store.load().sync_cursor.is_none(),
        "anonymous pre-DID state must not expose Alice's projections"
    );
    let alice = arkret_sdk::DidFullId::new("did:web:alice.example".to_owned()).unwrap();
    let is_new = store.adopt_pending_login(&alice);
    assert!(!is_new, "a returning DID is not a new account");
    assert!(store.pending_login().is_none());
    // Alice's own entry (with her cursor) is restored, not wiped. The
    // secure-store seed/device_id tuple was already re-homed before this root
    // marker is adopted.
    assert_eq!(store.load().sync_cursor.as_deref(), Some("sx:alice"));
}

#[test]
fn fresh_pending_login_never_moves_previous_account_onboarding_fields() {
    // begin/adopt_pending_login mutate the process-global pending-login id.
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
    let path = temp_state_path("pending-isolates-previous-onboarding");
    let mut store = LocalStateStore::with_path(path);
    store.switch_active_account("did:web:old.example");
    store.save_sync_cursor("sx:old");
    store.set_primary_handle("old-user");
    store.set_dpop_device_key(Some(DpopDeviceKeyRecord {
        seed_b64: "old-account-dpop-seed".to_owned(),
        jkt: "old-account-jkt".to_owned(),
        created_at: chrono::Utc::now(),
    }));
    let handoff = PendingAccountHandoff {
        principal_server_url: "https://principal.example".to_owned(),
        gate_account_base: "https://auth.example/_arkret/gate/account".to_owned(),
        request_id: "ak:request:019f0000-0000-7000-8000-000000000099".to_owned(),
        oidc_state: None,
        account_handle: "new:auth.example".to_owned(),
        account_subject: Some(arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap()),
        holder_jkt: "holder-jkt".to_owned(),
        audience: "did:webvh:z6mkfixture:principal.example".to_owned(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        lease_id: Some("lease-new".to_owned()),
        lease_fence: Some(1),
        lease_expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(15)),
        identity_creation_state: Some(arkret_sdk::IdentityCreationLeaseState::Active),
        reserved_identity: None,
        identity_abandonment: None,
        retry_after_ms: None,
        device_id: "ak:device:019f0000-0000-7000-8000-000000000099".to_owned(),
        trust_domain: "ak:trust_domain:auth.example".to_owned(),
        bound_principal_id: None,
    };
    store
        .set_pending_account_handoff(Some(handoff.clone()))
        .unwrap();
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let checkpoint = crate::identity::principal_registration::prepare_registration_checkpoint(
        &handoff,
        &handoff.device_id,
        &recovery_key,
    )
    .unwrap();
    let previous_did = checkpoint.did.clone();
    store
        .set_pending_principal_registration(Some(checkpoint))
        .unwrap();

    store.begin_pending_login(&handoff.device_id, Some(&handoff.holder_jkt));

    assert!(store.active_account_did().is_none());
    assert_eq!(
        store.last_selected_account_did().as_deref(),
        Some("did:web:old.example")
    );
    assert!(store.pending_account_handoff().is_none());
    assert!(store.pending_principal_registration().is_none());
    assert!(store.load().sync_cursor.is_none());
    assert!(
        store.dpop_device_key().is_none(),
        "anonymous registration must not expose the previous account's DPoP state"
    );
    assert!(
        store.primary_handle_for_did("anonymous").is_none(),
        "anonymous registration must not inherit the previous account's profile"
    );

    let newcomer = arkret_sdk::DidFullId::new("did:web:new.example".to_owned()).unwrap();
    assert!(store.adopt_pending_login(&newcomer));
    assert!(store.load().sync_cursor.is_none());
    assert!(store.pending_account_handoff().is_none());
    assert!(store.pending_principal_registration().is_none());
    assert!(store.dpop_device_key().is_none());
    assert!(store.primary_handle_for_did(newcomer.as_str()).is_none());

    store.switch_active_account("did:web:old.example");
    assert_eq!(store.load().sync_cursor.as_deref(), Some("sx:old"));
    assert_eq!(
        store
            .primary_handle_for_did("did:web:old.example")
            .as_deref(),
        Some("old-user")
    );
    assert_eq!(
        store.dpop_device_key().as_ref().map(|key| key.jkt.as_str()),
        Some("old-account-jkt"),
        "starting another registration must preserve the old account in its own namespace"
    );
    assert_eq!(
        store
            .pending_account_handoff()
            .as_ref()
            .map(|pending| pending.request_id.as_str()),
        Some(handoff.request_id.as_str()),
        "fresh registration must leave the old account's handoff scoped to it"
    );
    assert_eq!(
        store
            .pending_principal_registration()
            .as_ref()
            .map(|pending| pending.did.as_str()),
        Some(previous_did.as_str()),
        "fresh registration must not expose the old identity draft anonymously"
    );
}

#[test]
fn adopt_pending_login_moves_the_unfinished_handoff_with_its_registration() {
    // resume/adopt_pending_login mutate the process-global pending-login id.
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
    let path = temp_state_path("pending-onboarding-handoff");
    let mut store = LocalStateStore::with_path(path);
    let device = "ak:device:019f0000-0000-7000-8000-000000000001";
    let handoff = PendingAccountHandoff {
        principal_server_url: "https://principal.example".to_owned(),
        gate_account_base: "https://auth.example/_arkret/gate/account".to_owned(),
        request_id: "ak:request:019f0000-0000-7000-8000-000000000000".to_owned(),
        oidc_state: None,
        account_handle: "alice:auth.example".to_owned(),
        account_subject: Some(arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap()),
        holder_jkt: "holder-jkt".to_owned(),
        audience: "did:webvh:z6mkfixture:principal.example".to_owned(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        lease_id: Some("lease-1".to_owned()),
        lease_fence: Some(1),
        lease_expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(15)),
        identity_creation_state: Some(arkret_sdk::IdentityCreationLeaseState::Active),
        reserved_identity: None,
        identity_abandonment: None,
        retry_after_ms: None,
        device_id: device.to_owned(),
        trust_domain: "ak:trust_domain:auth.example".to_owned(),
        bound_principal_id: None,
    };
    let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
    let checkpoint = crate::identity::principal_registration::prepare_registration_checkpoint(
        &handoff,
        device,
        &recovery_key,
    )
    .unwrap();
    let did = checkpoint.did.clone();

    store
        .set_pending_account_handoff(Some(handoff.clone()))
        .unwrap();
    store
        .set_pending_principal_registration(Some(checkpoint))
        .unwrap();
    assert!(!store.can_resume_pending_login(device));
    let dpop_jkt = "resume-holder-jkt".to_owned();
    store.set_dpop_device_key(Some(DpopDeviceKeyRecord {
        seed_b64: "test-seed".to_owned(),
        jkt: dpop_jkt.clone(),
        created_at: chrono::Utc::now(),
    }));
    assert!(!store.can_resume_pending_login(device));
    let mut resumed_handoff = handoff.clone();
    resumed_handoff.holder_jkt = dpop_jkt;
    store
        .set_pending_account_handoff(Some(resumed_handoff))
        .unwrap();
    assert!(!store.can_resume_pending_login("ak:device:019f0000-0000-7000-8000-000000000099"));
    assert!(store.can_resume_pending_login(device));
    assert!(store.resume_pending_login(device));

    let principal_id = arkret_sdk::DidFullId::new(did.clone()).unwrap();
    store.adopt_pending_login(&principal_id);

    assert_eq!(
        store
            .pending_account_handoff()
            .as_ref()
            .map(|pending| pending.request_id.as_str()),
        Some(handoff.request_id.as_str())
    );
    assert_eq!(
        store
            .pending_principal_registration()
            .as_ref()
            .map(|pending| pending.did.as_str()),
        Some(did.as_str())
    );
}

#[test]
fn returning_login_clears_consumed_handoff_from_anonymous_namespace() {
    // begin/adopt_pending_login mutate the process-global pending-login id.
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
    let path = temp_state_path("returning-login-clears-anonymous-handoff");
    let mut store = LocalStateStore::with_path(path);
    let principal = "did:web:alice.example";
    let device = "ak:device:019f0000-0000-7000-8000-000000000001";
    store.switch_active_account(principal);
    store.register_known_account(principal);
    store.begin_pending_login(device, Some("holder-jkt"));
    store
        .set_pending_account_handoff(Some(PendingAccountHandoff {
            principal_server_url: "https://principal.example".to_owned(),
            gate_account_base: "https://auth.example/_arkret/gate/account".to_owned(),
            request_id: "ak:request:019f0000-0000-7000-8000-000000000123".to_owned(),
            oidc_state: Some("oidc-state".to_owned()),
            account_handle: "alice:auth.example".to_owned(),
            account_subject: Some(
                arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            ),
            holder_jkt: "holder-jkt".to_owned(),
            audience: "did:webvh:z6mkfixture:principal.example".to_owned(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
            lease_id: None,
            lease_fence: None,
            lease_expires_at: None,
            identity_creation_state: None,
            reserved_identity: None,
            identity_abandonment: None,
            retry_after_ms: None,
            device_id: device.to_owned(),
            trust_domain: "ak:trust_domain:auth.example".to_owned(),
            bound_principal_id: Some(principal.to_owned()),
        }))
        .unwrap();

    let principal_id = arkret_sdk::DidFullId::new(principal.to_owned()).unwrap();
    assert!(!store.adopt_pending_login(&principal_id));
    assert!(
        store.pending_account_handoff().is_some(),
        "handoff remains recoverable on the target account until completion commits"
    );
    store.set_pending_account_handoff(None).unwrap();

    store.switch_active_account("anonymous");
    assert!(
        store.pending_account_handoff().is_none(),
        "returning completion must remove the consumed checkpoint from anonymous storage"
    );
}
