use std::time::{SystemTime, UNIX_EPOCH};

use super::*;
use crate::secure_key_store::SecureKeyStore;

#[test]
fn move_submission_state_maps_pending_seal_and_effective() {
    assert_eq!(
        MoveSubmissionState::from_submit_state("pending", None),
        MoveSubmissionState::PendingSeal
    );
    assert_eq!(
        MoveSubmissionState::from_submit_state("pending_seal", None),
        MoveSubmissionState::PendingSeal
    );
    assert_eq!(
        MoveSubmissionState::from_submit_state("accepted", None),
        MoveSubmissionState::PendingSeal
    );
    assert_eq!(
        MoveSubmissionState::from_submit_state("effective", None),
        MoveSubmissionState::Effective
    );
    assert_eq!(
        MoveSubmissionState::from_submit_state("sealed", None),
        MoveSubmissionState::Effective
    );
}

#[test]
fn move_submission_state_maps_failure_reasons() {
    assert_eq!(
        MoveSubmissionState::from_submit_state(
            "rejected",
            Some("notary_paused: recovery notary not signed")
        ),
        MoveSubmissionState::NotaryPaused
    );
    assert_eq!(
        MoveSubmissionState::from_submit_state(
            "rejected",
            Some("seal_signature_invalid for batch")
        ),
        MoveSubmissionState::RejectedSeal
    );
    assert_eq!(
        MoveSubmissionState::from_submit_state(
            "rejected",
            Some("bottom: cell has concurrent candidates")
        ),
        MoveSubmissionState::FailedBottom
    );
    assert_eq!(
        MoveSubmissionState::from_submit_state("rejected", Some("covered_seals mismatch")),
        MoveSubmissionState::PendingMlsBinding
    );
    assert_eq!(
        MoveSubmissionState::from_submit_state("rejected", Some("if_state did not match")),
        MoveSubmissionState::FailedPrecondition
    );
}

#[test]
fn private_plaintext_snapshot_json_round_trips_through_merge() {
    // X5.3 — write sidecar entries, snapshot to JSON, then merge that JSON
    // into a FRESH store (the new-browser restore case) and read them back.
    let path = temp_state_path("private-plaintext-snapshot");
    let mut store = LocalStateStore::with_path(path);
    assert!(store.private_plaintext_is_empty());
    store.save_private_plaintext("ck:realm:s1", "ck:strand:f1", "body", "\"hello body\"");
    store.save_private_plaintext(
        "ck:realm:s1",
        "ck:strand:f1",
        "synthesis",
        "\"hello synthesis\"",
    );
    store.save_private_plaintext("ck:realm:s2", "ck:strand:f2", "body", "\"other body\"");
    assert!(!store.private_plaintext_is_empty());

    let json = store.private_plaintext_snapshot_json();
    let map: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>> =
        serde_json::from_slice(&json).unwrap();

    // Fresh store (empty) merges the snapshot -> every field reappears.
    let fresh_path = temp_state_path("private-plaintext-merged");
    let mut fresh = LocalStateStore::with_path(fresh_path);
    assert!(fresh.private_plaintext_is_empty());
    fresh.merge_private_plaintext_map(map);
    assert_eq!(
        fresh.private_plaintext_for("ck:realm:s1", "ck:strand:f1", "body"),
        Some("\"hello body\"".to_owned())
    );
    assert_eq!(
        fresh.private_plaintext_for("ck:realm:s1", "ck:strand:f1", "synthesis"),
        Some("\"hello synthesis\"".to_owned())
    );
    assert_eq!(
        fresh.private_plaintext_for("ck:realm:s2", "ck:strand:f2", "body"),
        Some("\"other body\"".to_owned())
    );
}

#[test]
fn merge_private_plaintext_map_keeps_local_value_on_conflict() {
    // X5.3 merge semantics: incoming only FILLS missing fields; an existing
    // local value wins on conflict.
    let path = temp_state_path("private-plaintext-conflict");
    let mut store = LocalStateStore::with_path(path);
    store.save_private_plaintext("ck:realm:s1", "ck:strand:f1", "body", "\"local newer\"");

    let mut fields = BTreeMap::new();
    fields.insert("body".to_owned(), "\"backup older\"".to_owned()); // conflict
    fields.insert("synthesis".to_owned(), "\"backup synthesis\"".to_owned()); // gap
    let mut strands = BTreeMap::new();
    strands.insert("ck:strand:f1".to_owned(), fields);
    let mut incoming = BTreeMap::new();
    incoming.insert("ck:realm:s1".to_owned(), strands);
    store.merge_private_plaintext_map(incoming);

    // Conflict: local value kept.
    assert_eq!(
        store.private_plaintext_for("ck:realm:s1", "ck:strand:f1", "body"),
        Some("\"local newer\"".to_owned())
    );
    // Gap: backup fills it.
    assert_eq!(
        store.private_plaintext_for("ck:realm:s1", "ck:strand:f1", "synthesis"),
        Some("\"backup synthesis\"".to_owned())
    );
}

#[test]
fn move_submission_record_round_trips_through_store() {
    let path = temp_state_path("move-submission");
    let mut store = LocalStateStore::with_path(path.clone());
    let realm = "ck:realm:0196419b-0000-7000-8000-000000000001";
    let mid = "sha256:111";
    store.record_move_submission(
        mid,
        realm,
        "ck.consent.grant",
        MoveSubmissionState::PendingSeal,
        None,
        Some("ck:seal:sha256:abc".to_owned()),
    );
    let listed = store.move_submissions_for_realm(realm);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].move_id, mid);
    assert_eq!(listed[0].state, MoveSubmissionState::PendingSeal);
    assert!(!store.realm_has_paused_notary(realm));

    // Update to NotaryPaused — Space should now flag the banner.
    assert!(store.update_move_submission_state(
        mid,
        MoveSubmissionState::NotaryPaused,
        Some("recovery notary not signed".to_owned()),
    ));
    assert!(store.realm_has_paused_notary(realm));
    let listed = store.move_submissions_for_realm(realm);
    assert_eq!(listed[0].state, MoveSubmissionState::NotaryPaused);
    assert_eq!(
        listed[0].reason.as_deref(),
        Some("recovery notary not signed")
    );

    // Persistence: a fresh reader sees the same state.
    let reader = LocalStateStore::with_path(path);
    assert!(reader.realm_has_paused_notary(realm));

    // Drop it and the banner clears.
    let mut store = LocalStateStore::with_path(reader.path.clone());
    store.drop_move_submission(mid);
    assert!(!store.realm_has_paused_notary(realm));
}

#[test]
fn private_plaintext_sidecar_round_trips_through_store() {
    // X5.1 — save → reload via a fresh reader → read back. The local
    // plaintext sidecar must survive a reload (serde-persisted), since
    // it is the only place the author's own encrypted content lives.
    let path = temp_state_path("private-plaintext-sidecar");
    let realm = "ck:realm:0196419b-0000-7000-8000-000000000001";
    let strand = "ck:strand:0196419b-0000-7000-8000-0000000000aa";
    {
        let mut store = LocalStateStore::with_path(path.clone());
        store.save_private_plaintext(realm, strand, "body", "\"author body\"");
        store.save_private_plaintext(realm, strand, "synthesis", "\"author synthesis\"");
    }
    // Fresh reader (simulating a process restart / reload).
    let reader = LocalStateStore::with_path(path.clone());
    assert_eq!(
        reader.private_plaintext_for(realm, strand, "body").as_deref(),
        Some("\"author body\"")
    );
    assert_eq!(
        reader
            .private_plaintext_for(realm, strand, "synthesis")
            .as_deref(),
        Some("\"author synthesis\"")
    );
    let fields = reader.private_plaintext_fields(realm, strand);
    assert_eq!(fields.len(), 2);
    // Missing keys return None.
    assert!(
        reader
            .private_plaintext_for(realm, strand, "content")
            .is_none()
    );
    assert!(
        reader
            .private_plaintext_for("ck:realm:other", strand, "body")
            .is_none()
    );

    // Clearing a field (empty plaintext) removes it and persists.
    let mut writer = LocalStateStore::with_path(path.clone());
    writer.save_private_plaintext(realm, strand, "body", "");
    let reader = LocalStateStore::with_path(path);
    assert!(reader.private_plaintext_for(realm, strand, "body").is_none());
    assert_eq!(
        reader
            .private_plaintext_for(realm, strand, "synthesis")
            .as_deref(),
        Some("\"author synthesis\"")
    );
}

#[test]
fn sync_event_states_update_submission_by_event_id() {
    let path = temp_state_path("move-event-state");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ck:realm:0196419b-0000-7000-8000-000000000001";
    let local_id = "sha256:local-submit";
    let event_id = "ck:event:0196419b-0000-7000-8000-0000000000aa";
    store.record_move_submission_with_event_id(
        local_id,
        Some(event_id.to_owned()),
        realm,
        "ck.strand.move",
        MoveSubmissionState::PendingSeal,
        None,
        Some("ck:seal:sha256:abc".to_owned()),
    );

    let updated = store.ingest_move_event_states(
        realm,
        &serde_json::json!({
            "event_states": [{
                "event_id": event_id,
                "event_state": "effective"
            }]
        }),
    );

    assert_eq!(updated, 1);
    let listed = store.move_submissions_for_realm(realm);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].move_id, local_id);
    assert_eq!(listed[0].event_id.as_deref(), Some(event_id));
    assert_eq!(listed[0].state, MoveSubmissionState::Effective);
}

#[test]
fn sync_event_states_update_legacy_submission_keyed_by_event_id() {
    let path = temp_state_path("legacy-move-event-state");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ck:realm:0196419b-0000-7000-8000-000000000001";
    let event_id = "ck:event:0196419b-0000-7000-8000-0000000000bb";
    store.record_move_submission(
        event_id,
        realm,
        "mls_member_remove",
        MoveSubmissionState::PendingMlsBinding,
        None,
        None,
    );

    let updated = store.ingest_move_event_states(
        realm,
        &serde_json::json!({
            "event_states": [{
                "event_id": event_id,
                "event_state": "failed_bottom",
                "event_state_reason_code": "cell_in_bottom_state"
            }]
        }),
    );

    assert_eq!(updated, 1);
    let listed = store.move_submissions_for_realm(realm);
    assert_eq!(listed[0].event_id.as_deref(), Some(event_id));
    assert_eq!(listed[0].state, MoveSubmissionState::FailedBottom);
    assert_eq!(listed[0].reason.as_deref(), Some("cell_in_bottom_state"));
}

#[test]
fn sync_event_states_update_submission_when_event_and_move_ids_are_present() {
    let path = temp_state_path("move-event-and-move-id-state");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ck:realm:0196419b-0000-7000-8000-000000000001";
    let move_id = "sha256:local-submit-with-server-event";
    let event_id = "ck:event:0196419b-0000-7000-8000-0000000000cc";
    store.record_move_submission(
        move_id,
        realm,
        "ck.strand.move",
        MoveSubmissionState::PendingSeal,
        None,
        None,
    );

    let updated = store.ingest_move_event_states(
        realm,
        &serde_json::json!({
            "event_states": [{
                "event_id": event_id,
                "move_id": move_id,
                "event_state": "effective"
            }]
        }),
    );

    assert_eq!(updated, 1);
    let listed = store.move_submissions_for_realm(realm);
    assert_eq!(listed[0].move_id, move_id);
    assert_eq!(listed[0].event_id.as_deref(), Some(event_id));
    assert_eq!(listed[0].state, MoveSubmissionState::Effective);
}

#[test]
fn move_submission_pending_mls_binding_drives_toast() {
    let path = temp_state_path("move-mls-binding");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ck:realm:0196419b-0000-7000-8000-000000000002";
    store.record_move_submission(
        "sha256:222",
        realm,
        "ck.message.create",
        MoveSubmissionState::PendingMlsBinding,
        Some("covered_seals missing".to_owned()),
        None,
    );
    assert!(store.realm_has_pending_mls_binding(realm));
    assert!(!store.realm_has_paused_notary(realm));
}

#[test]
fn mls_encrypted_projection_detects_epoch_pause_scope() {
    let path = temp_state_path("mls-encrypted-projection");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ck:realm:0196419b-0000-7000-8000-0000000000ee";
    store.save_realm_tree_projection(
        realm.to_owned(),
        json!({
            "schema": "ck.schema.realm.v1",
            "summary": {
                "title": "Encrypted",
                "encryption_profile": "mls_rfc9420"
            }
        }),
    );
    assert!(store.realm_projection_is_mls_encrypted(realm));

    let plain = "ck:realm:0196419b-0000-7000-8000-0000000000ef";
    store.save_realm_tree_projection(
        plain.to_owned(),
        json!({
            "schema": "ck.schema.realm.v1",
            "summary": {
                "title": "Plain",
                "encryption_profile": "none"
            }
        }),
    );
    assert!(!store.realm_projection_is_mls_encrypted(plain));
}

#[test]
fn minimal_metadata_projection_detected_from_profiles_arrays() {
    // SEC-08 — the committer reads minimal-metadata status off the cached
    // projection. Recognised under `profiles[]` / `active_profiles[]` at the
    // top level and inside the nested realm body; absent / unknown ⇒ false.
    let path = temp_state_path("minimal-metadata-projection");
    let mut store = LocalStateStore::with_path(path);

    let top = "ck:realm:0196419b-0000-7000-8000-0000000000a1";
    store.save_realm_tree_projection(
        top.to_owned(),
        json!({ "profiles": [cokret_sdk::mls::MINIMAL_METADATA_REALM_PROFILE] }),
    );
    assert!(store.realm_projection_is_minimal_metadata(top));

    let nested = "ck:realm:0196419b-0000-7000-8000-0000000000a2";
    store.save_realm_tree_projection(
        nested.to_owned(),
        json!({
            "summary": {
                "active_profiles": [
                    "ck.profile.core.v1",
                    cokret_sdk::mls::MINIMAL_METADATA_REALM_PROFILE
                ]
            }
        }),
    );
    assert!(store.realm_projection_is_minimal_metadata(nested));

    let plain = "ck:realm:0196419b-0000-7000-8000-0000000000a3";
    store.save_realm_tree_projection(
        plain.to_owned(),
        json!({ "profiles": ["ck.profile.core.v1"] }),
    );
    assert!(!store.realm_projection_is_minimal_metadata(plain));

    // Unknown Realm (no projection) ⇒ treated as non-minimal.
    assert!(
        !store
            .realm_projection_is_minimal_metadata("ck:realm:0196419b-0000-7000-8000-0000000000a9")
    );
}

#[test]
fn member_handle_cache_is_realm_and_digest_scoped() {
    let path = temp_state_path("member-handle-cache");
    let mut store = LocalStateStore::with_path(path);
    let subject = "did:webvh:zQmMember";
    let realm = "ck:realm:0196419b-0000-7000-8000-000000000001";
    store.save_member_handle_lookup(
        subject,
        Some(realm.to_owned()),
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()),
        Some("Alice:Example.COM".to_owned()),
        1,
        Some(Utc::now()),
        Some(Utc::now() + chrono::Duration::hours(2)),
    );

    let entry = store
        .cached_member_handle_lookup(
            subject,
            Some(realm),
            Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        )
        .expect("fresh cache entry");
    assert_eq!(entry.primary_handle.as_deref(), Some("alice:example.com"));
    assert!(
        store
            .cached_member_handle_lookup(
                subject,
                Some(realm),
                Some("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            )
            .is_none()
    );
    assert!(
        store
            .cached_member_handle_lookup(
                subject,
                Some("ck:realm:0196419b-0000-7000-8000-000000000002"),
                Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            )
            .is_none()
    );
}

#[test]
fn member_handle_cache_records_fresh_negative_lookup() {
    let path = temp_state_path("member-handle-negative-cache");
    let mut store = LocalStateStore::with_path(path);
    let subject = "did:webvh:zQmNoVisibleHandle";
    store.save_member_handle_lookup(
        subject,
        Some("ck:realm:0196419b-0000-7000-8000-000000000001".to_owned()),
        None,
        None,
        0,
        None,
        None,
    );

    let entry = store
        .cached_member_handle_lookup(
            subject,
            Some("ck:realm:0196419b-0000-7000-8000-000000000001"),
            None,
        )
        .expect("fresh negative entry");
    assert!(entry.primary_handle.is_none());
}

#[test]
fn move_submission_state_label_and_badge_class_distinct_per_state() {
    for state in [
        MoveSubmissionState::PendingSeal,
        MoveSubmissionState::Effective,
        MoveSubmissionState::FailedPrecondition,
        MoveSubmissionState::FailedBottom,
        MoveSubmissionState::RejectedSeal,
        MoveSubmissionState::NotaryPaused,
        MoveSubmissionState::PendingMlsBinding,
    ] {
        assert!(!state.slug().is_empty());
        assert!(!state.label_zh().is_empty());
        assert!(state.badge_class().starts_with("badge"));
    }
    assert!(MoveSubmissionState::NotaryPaused.is_failed());
    assert!(!MoveSubmissionState::PendingSeal.is_failed());
    assert!(!MoveSubmissionState::Effective.is_failed());
}

#[test]
fn local_state_store_tracks_cursor_operations_projections_and_drafts() {
    let path = temp_state_path("tracks");
    let mut store = LocalStateStore::with_path(path);
    store.save_sync_cursor("sx:next");
    store.append_raw_operation(
        "ck:operation:local-01",
        Some("ck:realm:demo".to_owned()),
        serde_json::json!({"type": "ck.message.create"}),
    );
    store.save_realm_tree_projection("ck:realm:demo", serde_json::json!({"name": "Demo"}));
    store.save_draft("ck:realm:demo", "hello");

    let state = store.load();
    assert_eq!(state.sync_cursor.as_deref(), Some("sx:next"));
    assert_eq!(
        state.raw_operations[0].operation_id,
        "ck:operation:local-01"
    );
    assert_eq!(
        state.realm_tree_projections["ck:realm:demo"]["name"],
        "Demo"
    );
    assert_eq!(store.draft_for("ck:realm:demo"), "hello");

    store.save_draft("ck:realm:demo", " ");
    assert!(store.draft_for("ck:realm:demo").is_empty());
}

#[test]
fn realm_lifecycle_state_tracks_destroy_without_raw_operation_scan() {
    let path = temp_state_path("realm-lifecycle");
    let mut store = LocalStateStore::with_path(path.clone());
    let realm_id = "ck:realm:destroyed";

    assert!(!store.realm_is_destroyed(realm_id));
    store.append_raw_operation(
        "ck:operation:destroy",
        Some(realm_id.to_owned()),
        serde_json::json!({"kind": "ck.realm.destroy"}),
    );

    assert!(store.realm_is_destroyed(realm_id));
    let lifecycle = store.load().realm_lifecycle_state;
    assert!(lifecycle[realm_id].destroyed);
    assert_eq!(
        lifecycle[realm_id].destroyed_operation_id.as_deref(),
        Some("ck:operation:destroy")
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
    writer.save_draft("ck:realm:persisted", "draft survives restart");

    let reader = LocalStateStore::with_path(path);
    let state = reader.load();
    assert_eq!(state.sync_cursor.as_deref(), Some("sx:persisted"));
    assert_eq!(state.drafts["ck:realm:persisted"], "draft survives restart");
}

#[test]
fn local_state_store_persists_notifications_and_mute_preferences() {
    let path = temp_state_path("notifications");
    let mut store = LocalStateStore::with_path(path.clone());
    store.save_notification_projection(vec![serde_json::json!({
        "notification_id": "notif-1",
        "realm_id": "ck:realm:demo",
        "kind": "message",
        "body": "Hello"
    })]);
    store.set_notification_read("notif-1", true);
    store.set_notification_archived("notif-1", true);
    store.set_realm_muted("ck:realm:demo", true);
    store.set_notification_kind_enabled("message", false);

    let reader = LocalStateStore::with_path(path);
    assert_eq!(reader.notification_projection().len(), 1);
    assert!(reader.notification_state_for("notif-1").read);
    assert!(reader.notification_state_for("notif-1").archived);
    assert!(reader.is_realm_muted("ck:realm:demo"));
    assert!(!reader.notification_kind_enabled("message"));
}

#[test]
fn realm_watch_level_set_get_roundtrip() {
    let path = temp_state_path("watch-level-roundtrip");
    let mut store = LocalStateStore::with_path(path.clone());
    store.set_realm_watch_level("ck:realm:a", WatchLevel::All);
    store.set_realm_watch_level("ck:realm:b", WatchLevel::Muted);
    // Setting the protocol default clears the override.
    store.set_realm_watch_level("ck:realm:c", WatchLevel::Participating);
    store.set_realm_watch_level("ck:realm:c", WatchLevel::MentionsOnly);

    let reader = LocalStateStore::with_path(path);
    assert_eq!(reader.realm_watch_level("ck:realm:a"), WatchLevel::All);
    assert_eq!(reader.realm_watch_level("ck:realm:b"), WatchLevel::Muted);
    assert_eq!(
        reader.realm_watch_level("ck:realm:c"),
        WatchLevel::MentionsOnly
    );
    assert!(!reader.realm_watch_levels().contains_key("ck:realm:c"));
    // The binary-mute compatibility view only reports `Muted` realms.
    assert_eq!(reader.muted_realms(), vec!["ck:realm:b".to_owned()]);
    assert!(reader.is_realm_muted("ck:realm:b"));
    assert!(!reader.is_realm_muted("ck:realm:a"));
}

#[test]
fn legacy_muted_realms_migrate_to_watch_level() {
    let path = temp_state_path("legacy-mute-migration");
    // Persist a snapshot in the legacy shape (binary `muted_realms` map).
    let mut value = serde_json::to_value(ClientLocalState::default()).unwrap();
    value["muted_realms"] = serde_json::json!({
        "ck:realm:legacy": true,
        "ck:realm:already-unmuted": false,
    });
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

    let store = LocalStateStore::with_path(path);
    assert_eq!(
        store.realm_watch_level("ck:realm:legacy"),
        WatchLevel::Muted
    );
    assert_eq!(
        store.realm_watch_level("ck:realm:already-unmuted"),
        WatchLevel::MentionsOnly
    );
    // The legacy key must not survive a round-trip back to storage.
    let reserialized = serde_json::to_value(store.load()).unwrap();
    assert!(reserialized.get("muted_realms").is_none());
}

#[test]
fn local_state_store_persists_private_read_cursors() {
    let path = temp_state_path("read-cursor");
    let mut store = LocalStateStore::with_path(path.clone());
    let marker = store.save_read_cursor(
        "did:web:alice.example",
        "device-1",
        "ck:realm:demo",
        None,
        "ck:event:read-1",
    );

    assert_eq!(marker.marker_type, "ck.read_cursor.advance");
    assert_eq!(marker.body.realm_id, "ck:realm:demo");
    assert_eq!(marker.body.position.event_id, "ck:event:read-1");
    assert_eq!(marker.body.read_scope.kind, "strand");
    assert_eq!(
        marker.body.read_scope.track_name.as_deref(),
        Some("discussion")
    );
    assert_eq!(
        marker.ck_read_cursor_operation(),
        serde_json::json!({
            "kind": "ck.read_cursor.advance",
            "payload": {
                "id": &marker.body.id,
                "schema": "ck.schema.read_cursor.v1",
                "actor_id": "did:web:alice.example",
                "device_id": "device-1",
                "realm_id": "ck:realm:demo",
                "read_scope": {
                    "kind": "strand",
                    "ref": "ck:strand:demo",
                    "track_name": "discussion"
                },
                "position": {
                    "event_id": "ck:event:read-1",
                    "hlc": &marker.body.position.hlc
                },
                "updated_at": &marker.updated_at,
            },
        })
    );

    let reader = LocalStateStore::with_path(path);
    let persisted = reader
        .read_cursor_for("ck:realm:demo", None)
        .expect("read marker persisted");
    assert_eq!(persisted.body.id, marker.body.id);
    assert_eq!(persisted.actor, "did:web:alice.example");
    assert_eq!(persisted.device_id, "device-1");
    assert_eq!(persisted.body.position.event_id, "ck:event:read-1");
}

#[test]
fn local_state_store_keeps_thread_read_cursors_separate() {
    let path = temp_state_path("thread-read-cursor");
    let mut store = LocalStateStore::with_path(path);
    store.save_read_cursor(
        "did:web:alice.example",
        "desktop",
        "ck:realm:demo",
        None,
        "ck:event:topic",
    );
    store.save_read_cursor(
        "did:web:alice.example",
        "desktop",
        "ck:realm:demo",
        Some("ck:thread:reply-1".to_owned()),
        "ck:event:thread",
    );

    assert_eq!(
        store
            .read_cursor_for("ck:realm:demo", None)
            .expect("topic marker")
            .body
            .position
            .event_id,
        "ck:event:topic"
    );
    assert_eq!(
        store
            .read_cursor_for("ck:realm:demo", Some("ck:thread:reply-1"))
            .expect("thread marker")
            .body
            .position
            .event_id,
        "ck:event:thread"
    );
}

#[test]
fn local_state_store_persists_push_registration_state() {
    let path = temp_state_path("push-registration");
    let mut store = LocalStateStore::with_path(path.clone());
    store.save_push_registration(PushRegistrationState {
        schema_version: chime::PUSH_REGISTRATION_STATE_SCHEMA_VERSION,
        principal_id: None,
        registration_id: Some("ck:push:local".to_owned()),
        device_id: "dev_yougen".to_owned(),
        platform: Some("desktop".to_owned()),
        app_id: Some("yougen".to_owned()),
        push_gateway: "https://push.example/_cokret/edge/push/notify".to_owned(),
        push_key_hash: "sha256:abc".to_owned(),
        push_key_preview: "desktop:<redacted,len=5>".to_owned(),
        registered_at: Some("2026-04-29T00:00:00Z".to_owned()),
        expires_at: None,
        refresh_hint: None,
        last_success_at: Some("2026-04-29T00:00:00Z".to_owned()),
        last_error: None,
    });

    let mut reader = LocalStateStore::with_path(path);
    let state = reader.push_registration().expect("push registration");
    assert_eq!(state.registration_id.as_deref(), Some("ck:push:local"));
    assert_eq!(state.device_id, "dev_yougen");

    reader.clear_push_registration();
    assert!(reader.push_registration().is_none());
}

/// `set_oidc_tokens_with_secure_store`
/// MUST move the `refresh_token` AND the `access_token` out of the
/// disk-backed `state.json` into the supplied `SecureKeyStore`
/// keyed by `coauth.refresh_token.<actor_id>` /
/// `coauth.access_token.<actor_id>`. The companion `load_*`
/// helper reads them back. The on-disk JSON MUST NOT contain
/// either bearer credential after the migration.
#[test]
fn oidc_tokens_migrate_into_secure_key_store_and_round_trip() {
    use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore};
    let path = temp_state_path("h3-refresh-token");
    let mut store = LocalStateStore::with_path(path.clone());
    let secure = MemorySecureKeyStore::default();
    let actor = "did:web:alice.example";

    let bundle = OidcTokenBundle {
        access_token: "atok".to_owned(),
        refresh_token: Some("rtok-secret".to_owned()),
        token_type: "Bearer".to_owned(),
        expires_at_unix: Some(2_000_000_000),
        id_token: None,
        scope: None,
        audience: None,
        stored_at: Utc::now(),
    };
    let stripped = store
        .set_oidc_tokens_with_secure_store(Some(bundle), actor, &secure)
        .expect("bundle persisted");
    // Post-migration: in-state bundle MUST NOT carry either bearer
    // credential any more (the secure store is the new authority).
    assert!(stripped.refresh_token.is_none());
    assert!(stripped.access_token.is_empty());

    // The disk-backed bundle agrees.
    let on_disk = store.oidc_tokens().expect("bundle still on disk");
    assert!(on_disk.refresh_token.is_none());
    assert!(on_disk.access_token.is_empty());

    // Secure store holds the secrets under the per-actor keys.
    let secret = secure
        .get_secret(&format!("coauth.refresh_token.{actor}"))
        .expect("read ok")
        .expect("secret present");
    assert_eq!(secret, "rtok-secret");
    let access = secure
        .get_secret(&format!("coauth.access_token.{actor}"))
        .expect("read ok")
        .expect("access secret present");
    assert_eq!(access, "atok");

    // Load helper reattaches both tokens from the store.
    let reattached = store
        .load_oidc_tokens_with_secure_store(actor, &secure)
        .expect("bundle visible");
    assert_eq!(reattached.refresh_token.as_deref(), Some("rtok-secret"));
    assert_eq!(reattached.access_token, "atok");

    // Clearing the bundle deletes the secure-store entries too.
    store.set_oidc_tokens_with_secure_store(None, actor, &secure);
    assert!(
        secure
            .get_secret(&format!("coauth.refresh_token.{actor}"))
            .expect("read ok after clear")
            .is_none()
    );
    assert!(
        secure
            .get_secret(&format!("coauth.access_token.{actor}"))
            .expect("read ok after clear")
            .is_none()
    );
}

#[test]
fn dpop_device_key_migrates_into_secure_key_store() {
    use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore};
    let path = temp_state_path("dpop-secure-store");
    let mut store = LocalStateStore::with_path(path);
    let secure = MemorySecureKeyStore::default();
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
        .get_secret(LocalStateStore::SECURE_DPOP_DEVICE_KEY)
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
            .get_secret(LocalStateStore::SECURE_DPOP_DEVICE_KEY)
            .expect("read secure dpop after clear")
            .is_none()
    );
}

fn temp_state_path(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("yougen-state-{name}-{stamp}.json"))
}

fn snapshot_event_id(suffix: &str) -> cokret_sdk::EventId {
    cokret_sdk::EventId::new(format!("ck:event:01904100-0000-7000-8000-{suffix}")).unwrap()
}

fn snapshot_hash(seed: u8) -> cokret_sdk::Hash {
    cokret_sdk::Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).unwrap()
}

fn snapshot_manifest_for_items(
    items: Vec<cokret_sdk::SnapshotMaterializedItem>,
) -> (
    cokret_sdk::SnapshotManifest,
    Vec<cokret_sdk::SnapshotChunkPayload>,
) {
    let snapshot_id =
        cokret_sdk::SnapshotId::new("ck:snapshot:01904100-0000-7000-8000-0000000000aa").unwrap();
    let realm_id =
        cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-0000000000aa").unwrap();
    let service_did = cokret_sdk::Did::new("did:web:server.example").unwrap();
    let state_digest = cokret_sdk::state_digest_from_items(&items).unwrap();
    let built = cokret_sdk::build_snapshot_chunks(
        &snapshot_id,
        cokret_sdk::SNAPSHOT_REDUCER_PROFILE_V1,
        items,
        4096,
    )
    .unwrap();
    let chunk_payloads = built
        .iter()
        .map(|chunk| chunk.payload.clone())
        .collect::<Vec<_>>();
    let chunks = built
        .into_iter()
        .map(|chunk| chunk.descriptor)
        .collect::<Vec<_>>();
    let created_at = Utc::now();
    let mut manifest = cokret_sdk::SnapshotManifest {
        id: snapshot_id,
        realm_id,
        reducer_profile: cokret_sdk::SNAPSHOT_REDUCER_PROFILE_V1.to_owned(),
        schema_profile_refs: vec!["ck.profile.core_event_store.v1".to_owned()],
        state_digest,
        frontier: cokret_sdk::SnapshotFrontier {
            event_ids: vec![snapshot_event_id("0000000000a2")],
            timeline_hlc: cokret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        },
        event_set_commitment: cokret_sdk::EventSetCommitment {
            algorithm: cokret_sdk::EventSetCommitmentAlgorithm::MerkleEventSetV1,
            root: snapshot_hash(9),
            covered_event_count: 2,
            covered_seals: vec![snapshot_event_id("0000000000a2")],
            actor_seq_ranges: Vec::new(),
        },
        chunks,
        security_class: cokret_sdk::SnapshotSecurityClass::Standard,
        verification_hints: None,
        created_by: service_did.clone(),
        created_at,
        authority_binding: cokret_sdk::AuthorityBinding {
            issuer: service_did,
            authority_kind: cokret_sdk::SnapshotAuthorityKind::RealmPolicySnapshotIssuer,
            auth_state_digest: snapshot_hash(1),
            auth_frontier: vec![snapshot_event_id("0000000000a2")],
            checked_at: created_at,
            witness_attestations: Vec::new(),
        },
        signature: cokret_sdk::DetachedJwsProof::eddsa(
            "did:web:server.example#snapshot".to_owned(),
            snapshot_hash(2),
            created_at,
            "header..signature".to_owned(),
        ),
    };
    manifest.signature.payload_digest = manifest.expected_signature_digest().unwrap();
    (manifest, chunk_payloads)
}

#[test]
fn apply_snapshot_chunks_imports_projection_status_and_encrypted_payload() {
    let path = temp_state_path("snapshot-apply");
    let mut store = LocalStateStore::with_path(path.clone());
    let message_id = "ck:message:01904100-0000-7000-8000-0000000000a1";
    let realm_id = "ck:realm:01904100-0000-7000-8000-0000000000aa";
    let encrypted_message = json!({
        "schema": "ck.schema.encrypted_envelope.v1",
        "scheme": "mls-rfc9420",
        "group_id": realm_id,
        "epoch": 1,
        "content_type": "application/vnd.cokret.message+json",
        "ciphertext": "AA",
        "payload_digest": format!("sha256:{}", "ab".repeat(32)),
        "key_ref": {
            "algorithm": "mls-rfc9420",
            "group_state_ref": format!("{realm_id}:1")
        }
    });
    let items = vec![
        cokret_sdk::SnapshotMaterializedItem {
            kind: "ck.schema.encrypted_envelope.v1".to_owned(),
            id: message_id.to_owned(),
            object: encrypted_message.clone(),
            source_event_id: snapshot_event_id("0000000000a1"),
        },
        cokret_sdk::SnapshotMaterializedItem {
            kind: "realm".to_owned(),
            id: realm_id.to_owned(),
            object: json!({
                "id": realm_id,
                "title": "Snapshot Realm"
            }),
            source_event_id: snapshot_event_id("0000000000a2"),
        },
    ];
    let (manifest, chunks) = snapshot_manifest_for_items(items);

    store
        .apply_snapshot_chunks(
            &manifest,
            &chunks,
            crate::snapshot::SnapshotTrustState::LowerTrust,
        )
        .unwrap();

    let loaded = store.load();
    assert_eq!(
        loaded.realm_tree_projections.get(message_id),
        Some(&encrypted_message)
    );
    let status = loaded.snapshot_sync.get(realm_id).unwrap();
    assert_eq!(status.manifest_id, manifest.id.to_string());
    assert_eq!(
        status.trust_state,
        crate::snapshot::SnapshotTrustState::LowerTrust
    );
    assert_eq!(status.source_event_ids.len(), 2);
    assert_eq!(store.pending_encrypted_count(), 1);

    let reader = LocalStateStore::with_path(path);
    assert_eq!(reader.pending_encrypted_count(), 1);
    assert_eq!(
        reader.snapshot_sync_status(realm_id).unwrap().trust_state,
        crate::snapshot::SnapshotTrustState::LowerTrust
    );
}

#[test]
fn retain_realm_tree_projections_prunes_per_realm_caches() {
    let path = temp_state_path("retain-prunes");
    let mut store = LocalStateStore::with_path(path);
    // Seed three realms with overlapping per-realm caches.
    for id in ["ck:realm:keep", "ck:realm:drop-a", "ck:realm:drop-b"] {
        store.save_realm_tree_projection(id, serde_json::json!({"name": id}));
        store.save_draft(id, "draft");
        store.set_realm_seal_view(id, LocalSealView::default());
        store.set_realm_muted(id, true);
    }
    // Independently keyed records that should follow the prune.
    store.save_read_cursor(
        "did:web:tester.example",
        "device-1",
        "ck:realm:drop-a",
        None,
        "ck:event:42",
    );
    store.save_read_cursor(
        "did:web:tester.example",
        "device-1",
        "ck:realm:keep",
        None,
        "ck:event:99",
    );

    let pruned = store.retain_realm_tree_projections(|id| id == "ck:realm:keep");
    assert_eq!(pruned.len(), 2);
    assert!(pruned.contains(&"ck:realm:drop-a".to_owned()));
    assert!(pruned.contains(&"ck:realm:drop-b".to_owned()));

    let state = store.load();
    assert_eq!(state.realm_tree_projections.len(), 1);
    assert!(state.realm_tree_projections.contains_key("ck:realm:keep"));
    assert!(!state.drafts.contains_key("ck:realm:drop-a"));
    assert!(state.drafts.contains_key("ck:realm:keep"));
    assert!(!state.seal_views.contains_key("ck:realm:drop-a"));
    assert!(state.seal_views.contains_key("ck:realm:keep"));
    assert!(!state.realm_watch_levels.contains_key("ck:realm:drop-b"));
    assert!(state.realm_watch_levels.contains_key("ck:realm:keep"));
    let kept_marker_keys: Vec<&str> = state.read_cursors.keys().map(String::as_str).collect();
    assert!(
        kept_marker_keys
            .iter()
            .any(|k| k.starts_with("ck:realm:keep\n")),
        "kept realm marker should survive prune: {kept_marker_keys:?}",
    );
    assert!(
        kept_marker_keys
            .iter()
            .all(|k| !k.starts_with("ck:realm:drop-a\n")),
        "pruned realm marker should be gone: {kept_marker_keys:?}",
    );
}

#[test]
fn retain_realm_tree_projections_keeps_everything_when_all_match() {
    let path = temp_state_path("retain-all");
    let mut store = LocalStateStore::with_path(path);
    store.save_realm_tree_projection("ck:space:a", serde_json::json!({}));
    store.save_realm_tree_projection("ck:space:b", serde_json::json!({}));
    let pruned = store.retain_realm_tree_projections(|_| true);
    assert!(pruned.is_empty());
    assert_eq!(store.load().realm_tree_projections.len(), 2);
}

#[test]
fn forget_realm_tree_projection_clears_a_single_space() {
    let path = temp_state_path("forget-one");
    let mut store = LocalStateStore::with_path(path);
    for id in ["ck:space:gone", "ck:space:stay"] {
        store.save_realm_tree_projection(id, serde_json::json!({}));
        store.save_draft(id, "draft");
        store.set_realm_seal_view(id, LocalSealView::default());
    }

    store.forget_realm_tree_projection("ck:space:gone");

    let state = store.load();
    assert!(!state.realm_tree_projections.contains_key("ck:space:gone"));
    assert!(state.realm_tree_projections.contains_key("ck:space:stay"));
    assert!(!state.drafts.contains_key("ck:space:gone"));
    assert!(state.drafts.contains_key("ck:space:stay"));
}

#[test]
fn clear_account_scoped_preserves_device_level_and_token_state() {
    let path = temp_state_path("clear-account");
    let mut store = LocalStateStore::with_path(path);
    // Account-scoped projections.
    store.save_sync_cursor("sx:before");
    store.save_realm_tree_projection("ck:space:a", serde_json::json!({}));
    store.save_draft("ck:space:a", "draft");
    store.save_private_data("did:web:tester.example", "theme", "night");
    // Device-level state that MUST survive. ensure_local_identity
    // generates a fresh seed + DID and persists the record under
    // local_identity — the canonical device-level field this helper
    // is responsible for not nuking.
    let identity = store
        .ensure_local_identity()
        .expect("ensure_local_identity should succeed in plaintext mode");
    // Auth-token state that clear_account_scoped MUST preserve too.
    let bundle = OidcTokenBundle {
        access_token: "at".to_owned(),
        refresh_token: Some("rt".to_owned()),
        token_type: "Bearer".to_owned(),
        expires_at_unix: None,
        id_token: None,
        scope: None,
        audience: None,
        stored_at: chrono::Utc::now(),
    };
    store.set_oidc_tokens(Some(bundle.clone()));

    store.clear_account_scoped();

    let state = store.load();
    assert!(state.sync_cursor.is_none(), "sync cursor should be wiped");
    assert!(
        state.realm_tree_projections.is_empty(),
        "projections should be wiped"
    );
    assert!(state.drafts.is_empty(), "drafts should be wiped");
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
    assert!(
        state.oidc_tokens.is_some(),
        "OIDC tokens must survive — login strand owns them",
    );
    assert!(
        state.oidc_tokens.as_ref().unwrap().access_token.is_empty(),
        "access_token must not be serialised to state.json",
    );
    assert!(
        state.oidc_tokens.as_ref().unwrap().refresh_token.is_none(),
        "refresh_token must not be serialised to state.json",
    );
}

#[test]
fn adopt_account_scope_resets_grant_cursor_and_oidc_on_identity_change() {
    let path = temp_state_path("adopt-account-scope");
    let mut store = LocalStateStore::with_path(path);

    // Establish alice's scope with a grant + OIDC + cursor + projection.
    assert!(
        store.adopt_account_scope("did:web:alice.example"),
        "first adopt (owner None) stamps and reports a reset"
    );
    let identity = store
        .ensure_local_identity()
        .expect("ensure_local_identity should succeed in plaintext mode");
    store.save_sync_cursor("sx:alice");
    store.save_realm_tree_projection("ck:space:a", serde_json::json!({}));
    store.set_oidc_tokens(Some(OidcTokenBundle {
        access_token: "alice-at".to_owned(),
        refresh_token: Some("alice-rt".to_owned()),
        token_type: "Bearer".to_owned(),
        expires_at_unix: None,
        id_token: None,
        scope: None,
        audience: None,
        stored_at: chrono::Utc::now(),
    }));
    store.set_session_grant(Some(PersistedSessionGrant {
        grant_jwt: "alice.grant".to_owned(),
        session_private_key_pem: "pem".to_owned(),
        grant_id: "g-alice".to_owned(),
        audience: "https://principal.example/api".to_owned(),
        principal_id: "did:web:alice.example".to_owned(),
        device_id: "device-1".to_owned(),
        principal_server_url: "https://principal.example".to_owned(),
        session_grant_exchange_path: "_cokret/gate/account/session-grants".to_owned(),
        grant_expires_at: None,
        session_expires_at: None,
        stored_at: chrono::Utc::now(),
    }));

    // Re-adopting the same actor is a no-op and keeps state.
    assert!(!store.adopt_account_scope("did:web:alice.example"));
    assert_eq!(store.load().sync_cursor.as_deref(), Some("sx:alice"));
    assert!(store.load().session_grant.is_some());

    // A different identity wipes the previous scope — including the
    // (possibly revoked) grant and the foreign-principal cursor — so
    // they can't leak into bob's session.
    assert!(store.adopt_account_scope("did:web:bob.example"));
    let state = store.load();
    assert!(state.sync_cursor.is_none(), "stale cursor must be wiped");
    assert!(
        state.realm_tree_projections.is_empty(),
        "projections must be wiped"
    );
    assert!(
        state.session_grant.is_none(),
        "previous identity's grant must be wiped, not preserved"
    );
    assert!(
        state.oidc_tokens.is_none(),
        "previous OIDC bundle must be wiped"
    );
    assert_eq!(
        state.account_scope_owner.as_deref(),
        Some("did:web:bob.example"),
        "owner is stamped to the new identity"
    );
    // Device-level identity survives the account-scope swap.
    assert_eq!(
        state.local_identity.as_ref().unwrap().did_key,
        identity.local_signing_did,
    );
}

#[test]
fn xor_encrypt_decrypt_roundtrip() {
    let key = "did:web:alice.example";
    let plaintext = "my secret preference";
    let encrypted = xor_encrypt(key, plaintext);
    assert_ne!(encrypted, plaintext);
    let decrypted = xor_decrypt(key, &encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn xor_encrypt_empty_key_returns_original() {
    assert_eq!(xor_encrypt("", "hello"), "hello");
}

#[test]
fn private_data_store_encrypts_and_persists() {
    let path = temp_state_path("private");
    let mut store = LocalStateStore::with_path(path.clone());
    let account_key = "did:web:alice.example";
    store.save_private_data(account_key, "theme", "dark");
    store.save_private_data(account_key, "custom_emoji", "party_parrot");

    assert_eq!(
        store.load_private_data(account_key, "theme"),
        Some("dark".to_owned())
    );
    assert_eq!(
        store.load_private_data(account_key, "custom_emoji"),
        Some("party_parrot".to_owned())
    );
    assert!(store.load_private_data(account_key, "missing").is_none());
    assert_eq!(store.private_data_keys().len(), 2);

    // Verify data is encrypted on disk
    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(!raw.contains("dark"));
    assert!(!raw.contains("party_parrot"));

    // Verify wrong key cannot decrypt
    assert_ne!(
        store.load_private_data("wrong-key", "theme"),
        Some("dark".to_owned())
    );
}

#[test]
fn private_data_remove_works() {
    let path = temp_state_path("private-remove");
    let mut store = LocalStateStore::with_path(path);
    store.save_private_data("key", "temp", "value");
    assert!(store.load_private_data("key", "temp").is_some());
    store.remove_private_data("temp");
    assert!(store.load_private_data("key", "temp").is_none());
}

#[test]
fn read_receipt_default_is_send_until_user_opts_out() {
    let path = temp_state_path("read-receipt-default");
    let mut store = LocalStateStore::with_path(path.clone());
    assert!(store.read_receipt_default_send());
    assert!(store.read_receipt_should_send(None, Some("ck:realm:any")));

    store.set_read_receipt_default_send(false);
    let reader = LocalStateStore::with_path(path);
    assert!(!reader.read_receipt_default_send());
    assert!(!reader.read_receipt_should_send(None, Some("ck:realm:any")));
}

#[test]
fn read_receipt_resolution_strand_overrides_realm_overrides_default() {
    let path = temp_state_path("read-receipt-resolve");
    let mut store = LocalStateStore::with_path(path.clone());
    // default = true (send)
    store.set_read_receipt_realm_override("ck:realm:demo", Some(false));
    store.set_read_receipt_strand_override("ck:strand:demo", Some(true));

    let reader = LocalStateStore::with_path(path);
    // Strand override wins.
    assert!(reader.read_receipt_should_send(Some("ck:strand:demo"), Some("ck:realm:demo")));
    // Space override wins over default when no strand override.
    assert!(!reader.read_receipt_should_send(None, Some("ck:realm:demo")));
    // Default applies when nothing matches.
    assert!(reader.read_receipt_should_send(None, Some("ck:realm:other")));
}

#[test]
fn read_receipt_clearing_override_falls_back_to_default() {
    let path = temp_state_path("read-receipt-clear");
    let mut store = LocalStateStore::with_path(path);
    store.set_read_receipt_realm_override("ck:realm:demo", Some(false));
    assert!(!store.read_receipt_should_send(None, Some("ck:realm:demo")));

    store.set_read_receipt_realm_override("ck:realm:demo", None);
    assert!(store.read_receipt_should_send(None, Some("ck:realm:demo")));
    assert!(store.read_receipt_realm_override("ck:realm:demo").is_none());
}

#[test]
fn server_policy_required_locks_user_choice_to_send() {
    let path = temp_state_path("read-receipt-policy-required");
    let mut store = LocalStateStore::with_path(path);
    // User opted out of the Space.
    store.set_read_receipt_realm_override("ck:realm:demo", Some(false));
    // But server publishes disclosure=required → must override to true.
    store.set_read_receipt_policy_snapshot(
        "ck:realm:demo",
        Some(ReadReceiptPolicySnapshot {
            disclosure: "required".to_owned(),
            visibility: Some("public".to_owned()),
        }),
    );
    assert!(store.read_receipt_should_send(None, Some("ck:realm:demo")));
    let snap = store
        .read_receipt_policy_for_realm("ck:realm:demo")
        .unwrap();
    assert!(snap.locks_user_choice());
    assert!(!snap.lock_reason().is_empty());
}

#[test]
fn server_policy_disabled_locks_user_choice_to_skip() {
    let path = temp_state_path("read-receipt-policy-disabled");
    let mut store = LocalStateStore::with_path(path);
    // User opts in.
    store.set_read_receipt_default_send(true);
    // Server publishes disclosure=disabled → must override to false.
    store.set_read_receipt_policy_snapshot(
        "ck:realm:demo",
        Some(ReadReceiptPolicySnapshot {
            disclosure: "disabled".to_owned(),
            visibility: Some("private".to_owned()),
        }),
    );
    assert!(!store.read_receipt_should_send(None, Some("ck:realm:demo")));
}

#[test]
fn server_policy_optional_does_not_lock() {
    let path = temp_state_path("read-receipt-policy-optional");
    let mut store = LocalStateStore::with_path(path);
    store.set_read_receipt_realm_override("ck:realm:demo", Some(false));
    store.set_read_receipt_policy_snapshot(
        "ck:realm:demo",
        Some(ReadReceiptPolicySnapshot {
            disclosure: "optional".to_owned(),
            visibility: None,
        }),
    );
    // optional → user override wins.
    assert!(!store.read_receipt_should_send(None, Some("ck:realm:demo")));
    let snap = store
        .read_receipt_policy_for_realm("ck:realm:demo")
        .unwrap();
    assert!(!snap.locks_user_choice());
    assert_eq!(snap.lock_reason(), "");
}

#[test]
fn seal_view_default_returns_empty_bytes_sentinel() {
    let path = temp_state_path("seal-default");
    let store = LocalStateStore::with_path(path);
    let view = store.seal_view_for_realm("ck:realm:demo");
    assert!(view.frontier.is_empty());
    assert!(view.leaves.is_empty());
    assert!(view.state_root.is_none());
    assert_eq!(view.move_seal_ref(), LocalSealView::EMPTY_ANCHOR_REF);
    assert_eq!(
        store.seal_ref_for_realm_move("ck:realm:demo"),
        LocalSealView::EMPTY_ANCHOR_REF
    );
}

#[test]
fn seal_view_set_persists_and_picks_lex_min_frontier() {
    let path = temp_state_path("seal-set");
    {
        let mut store = LocalStateStore::with_path(path.clone());
        store.set_realm_seal_view(
            "ck:realm:demo",
            LocalSealView {
                frontier: vec![
                    "ck:seal:sha256:bbb".to_owned(),
                    "ck:seal:sha256:aaa".to_owned(),
                ],
                leaves: vec!["sha256:lf1".to_owned()],
                state_root: Some("ck:state:sha256:abc".to_owned()),
                bottom_cells: BTreeMap::new(),
                mls_epoch: None,
                covered_seals: None,
                covered_seals_lag: None,
                key_schedule_hash: None,
            },
        );
    }
    let reader = LocalStateStore::with_path(path);
    let view = reader.seal_view_for_realm("ck:realm:demo");
    assert_eq!(view.frontier.len(), 2);
    assert_eq!(view.leaves.len(), 1);
    assert_eq!(view.state_root.as_deref(), Some("ck:state:sha256:abc"));
    assert_eq!(view.move_seal_ref(), "ck:seal:sha256:aaa");
    assert_eq!(
        reader.seal_ref_for_realm_move("ck:realm:demo"),
        "ck:seal:sha256:aaa"
    );
}

#[test]
fn seal_view_bottom_cells_signal_conflict() {
    let mut view = LocalSealView::default();
    assert!(!view.has_bottom_cells());
    view.bottom_cells.insert(
        "ck:cell:ck.component.member.state.v1:did:web:alice".to_owned(),
        BottomCellInfo {
            status: "expose".to_owned(),
            heads: vec![],
        },
    );
    assert!(view.has_bottom_cells());
}

#[test]
fn safer_winner_for_member_state_prefers_ban_over_join() {
    let mut view = LocalSealView::default();
    let cell = "ck:cell:ck.component.member.state.v1:did:web:alice".to_owned();
    view.bottom_cells.insert(
        cell.clone(),
        BottomCellInfo {
            status: "expose".to_owned(),
            heads: vec![
                BottomCellHead {
                    move_id: "ck:event:joined".to_owned(),
                    value: serde_json::json!({"membership": "join"}),
                },
                BottomCellHead {
                    move_id: "ck:event:banned".to_owned(),
                    value: serde_json::json!({"membership": "ban", "reason": "abuse"}),
                },
            ],
        },
    );
    let (head_a, head_b, winner) = view.safer_winner_for(&cell).expect("ban beats join");
    assert_eq!(head_a, "ck:event:joined");
    assert_eq!(head_b, "ck:event:banned");
    assert_eq!(
        winner.get("membership").and_then(|v| v.as_str()),
        Some("ban")
    );
}

#[test]
fn safer_winner_for_capability_grant_prefers_revoked_over_active() {
    let mut view = LocalSealView::default();
    let cell = "ck:cell:ck.component.capability.grant.v1:ck.grant.01".to_owned();
    view.bottom_cells.insert(
        cell.clone(),
        BottomCellInfo {
            status: "expose".to_owned(),
            heads: vec![
                BottomCellHead {
                    move_id: "ck:event:granted".to_owned(),
                    value: serde_json::json!({"status": "active"}),
                },
                BottomCellHead {
                    move_id: "ck:event:revoked".to_owned(),
                    value: serde_json::json!({"status": "revoked"}),
                },
            ],
        },
    );
    let (_, _, winner) = view.safer_winner_for(&cell).expect("revoked beats active");
    assert_eq!(
        winner.get("status").and_then(|v| v.as_str()),
        Some("revoked")
    );
}

#[test]
fn safer_winner_for_unknown_cell_family_returns_none() {
    let mut view = LocalSealView::default();
    let cell = "ck:cell:ck.component.test.unknown.v1:ck:realm:demo".to_owned();
    view.bottom_cells.insert(
        cell.clone(),
        BottomCellInfo {
            status: "expose".to_owned(),
            heads: vec![
                BottomCellHead {
                    move_id: "ck:event:a".to_owned(),
                    value: serde_json::json!({"title": "alpha"}),
                },
                BottomCellHead {
                    move_id: "ck:event:b".to_owned(),
                    value: serde_json::json!({"title": "beta"}),
                },
            ],
        },
    );
    // No semantic safety ordering for this test-only cell family — operator
    // must pick manually.
    assert!(view.safer_winner_for(&cell).is_none());
}

#[test]
fn safer_winner_for_tied_heads_returns_none() {
    let mut view = LocalSealView::default();
    let cell = "ck:cell:ck.component.member.state.v1:did:web:alice".to_owned();
    view.bottom_cells.insert(
        cell.clone(),
        BottomCellInfo {
            status: "expose".to_owned(),
            heads: vec![
                BottomCellHead {
                    move_id: "ck:event:ban-a".to_owned(),
                    value: serde_json::json!({"membership": "ban", "reason": "spam"}),
                },
                BottomCellHead {
                    move_id: "ck:event:ban-b".to_owned(),
                    value: serde_json::json!({"membership": "ban", "reason": "abuse"}),
                },
            ],
        },
    );
    // Both heads tie on safety rank → no preference; operator picks.
    assert!(view.safer_winner_for(&cell).is_none());
}

#[test]
fn safer_winner_for_missing_heads_returns_none() {
    let mut view = LocalSealView::default();
    let cell = "ck:cell:ck.component.member.state.v1:did:web:alice".to_owned();
    view.bottom_cells.insert(
        cell.clone(),
        BottomCellInfo {
            status: "expose".to_owned(),
            heads: vec![],
        },
    );
    assert!(view.safer_winner_for(&cell).is_none());
}

#[test]
fn seal_view_from_sync_body_parses_full_payload() {
    let body = serde_json::json!({
        "seal_view": {
            "frontier": ["ck:seal:sha256:aaa", "ck:seal:sha256:bbb"],
            "leaves":   ["sha256:lf1"],
            "state_root": "ck:state:sha256:abc",
            "cells": {
                "ck:cell:ck.component.member.state.v1:did:web:alice": {
                    "bottom": "expose",
                    "heads": [
                        {
                            "move_id": "ck:event:joined",
                            "value": {"membership": "join"}
                        },
                        {
                            "move_id": "ck:event:banned",
                            "value": {"membership": "ban", "reason": "abuse"}
                        }
                    ]
                },
                "ck:cell:ck.component.consent.grant.v1:cnt.x":         { "bottom": "reject" }
            }
        }
    });
    let view = LocalSealView::from_sync_body(&body);
    assert_eq!(view.frontier.len(), 2);
    assert_eq!(view.leaves, vec!["sha256:lf1".to_owned()]);
    assert_eq!(view.state_root.as_deref(), Some("ck:state:sha256:abc"));
    // Only `bottom=expose` cells are surfaced — `reject` cells stay
    // out of the conflict map.
    assert_eq!(view.bottom_cells.len(), 1);
    let info = view
        .bottom_cells
        .get("ck:cell:ck.component.member.state.v1:did:web:alice")
        .expect("expose cell present");
    assert_eq!(info.status, "expose");
    assert_eq!(info.heads.len(), 2);
    assert_eq!(info.heads[0].move_id, "ck:event:joined");
    assert_eq!(
        info.heads[1]
            .value
            .get("membership")
            .and_then(|v| v.as_str()),
        Some("ban")
    );
}

#[test]
fn seal_view_from_sync_body_parses_structured_bottoms() {
    let body = serde_json::json!({
        "bottoms": [{
            "cell": "ck:cell:ck.component.strand.position.v1:ck:space:board:ck:strand:card",
            "status": "conflict",
            "bottom": {
                "kind": "conflict",
                "cells": [
                    "ck:cell:ck.component.strand.position.v1:ck:space:board:ck:strand:card"
                ],
                "event_ids": [
                    "ck:event:0196419b-0000-7000-8000-000000000001",
                    "ck:event:0196419b-0000-7000-8000-000000000002"
                ],
                "heads": [
                    {"list_space_id": "ck:space:list-a", "rank": "U"},
                    {"list_space_id": "ck:space:list-b", "rank": "U"}
                ]
            }
        }]
    });

    let view = LocalSealView::from_sync_body(&body);
    let info = view
        .bottom_cells
        .get("ck:cell:ck.component.strand.position.v1:ck:space:board:ck:strand:card")
        .expect("structured bottom conflict surfaced");
    assert_eq!(info.status, "conflict");
    assert_eq!(info.heads.len(), 2);
    assert_eq!(
        info.heads[0].move_id,
        "ck:event:0196419b-0000-7000-8000-000000000001"
    );
    assert_eq!(
        info.heads[1]
            .value
            .get("list_space_id")
            .and_then(|v| v.as_str()),
        Some("ck:space:list-b")
    );
}

#[test]
fn seal_view_from_sync_body_extracts_mls_epoch_and_covered_seals() {
    let body = serde_json::json!({
        "seal_view": {
            "frontier": ["ck:seal:sha256:aaa"],
            "leaves": [],
            "cells": {
                "ck:cell:ck.component.mls.epoch.v1:ck:realm:demo": {
                    "value": 7
                },
                "ck:cell:ck.component.governance.covered_seals.v1:ck:realm:demo": {
                    "register": { "value": "ck:state:sha256:abcd" }
                }
            }
        }
    });
    let view = LocalSealView::from_sync_body(&body);
    assert_eq!(view.mls_epoch, Some(7));
    assert_eq!(view.covered_seals.as_deref(), Some("ck:state:sha256:abcd"));
}

#[test]
fn seal_view_mls_epoch_supports_object_value_with_epoch_field() {
    // Some soland builds emit the MLS epoch cell as `{ "value": { "epoch": N } }`
    // (typed view) instead of a bare integer. Both shapes need to round-trip.
    let body = serde_json::json!({
        "seal_view": {
            "frontier": [],
            "cells": {
                "ck:cell:ck.component.mls.epoch.v1:ck:realm:demo": {
                    "value": { "epoch": 42, "members": 3 }
                }
            }
        }
    });
    let view = LocalSealView::from_sync_body(&body);
    assert_eq!(view.mls_epoch, Some(42));
}

#[test]
fn seal_view_from_sync_body_extracts_covered_seals_lag() {
    let body = serde_json::json!({
        "seal_view": {
            "frontier": ["ck:seal:sha256:aaa"],
            "leaves": [],
            "covered_seals_lag": 12,
            "cells": {}
        }
    });
    let view = LocalSealView::from_sync_body(&body);
    assert_eq!(view.covered_seals_lag, Some(12));
    // default threshold is 5 -> 12 > 5
    assert!(view.covered_seals_lag_above(5));
    assert!(!view.covered_seals_lag_above(20));
}

#[test]
fn seal_view_lag_above_returns_false_when_lag_unknown() {
    let view = LocalSealView::default();
    assert!(!view.covered_seals_lag_above(5));
    assert!(!view.covered_seals_lag_above(0));
}

#[test]
fn seal_view_from_sync_body_missing_returns_default() {
    let body = serde_json::json!({"summary": {"summary": "hi"}});
    let view = LocalSealView::from_sync_body(&body);
    assert_eq!(view, LocalSealView::default());
}

#[test]
fn seal_views_aggregates_across_realms() {
    let path = temp_state_path("seal-aggregate");
    let mut store = LocalStateStore::with_path(path);
    store.set_realm_seal_view(
        "ck:realm:one",
        LocalSealView {
            frontier: vec!["ck:seal:sha256:one".to_owned()],
            ..LocalSealView::default()
        },
    );
    store.set_realm_seal_view(
        "ck:realm:two",
        LocalSealView {
            frontier: vec!["ck:seal:sha256:two".to_owned()],
            ..LocalSealView::default()
        },
    );
    let all = store.seal_views();
    assert_eq!(all.len(), 2);
    assert!(all.contains_key("ck:realm:one"));
    assert!(all.contains_key("ck:realm:two"));
}

#[test]
fn ensure_local_identity_generates_persists_and_round_trips() {
    let path = temp_state_path("local-identity");
    let id = {
        let mut store = LocalStateStore::with_path(path.clone());
        assert!(store.local_identity_record().is_none());
        assert!(store.local_identity().is_none());
        let id = store.ensure_local_identity().expect("first generate");
        assert!(id.local_signing_did.starts_with("did:key:z"));
        // Idempotent on the same store instance.
        let again = store.ensure_local_identity().expect("idempotent");
        assert_eq!(id, again);
        id
    };
    // Round-trip across store instances.
    let reader = LocalStateStore::with_path(path);
    let loaded = reader.local_identity().expect("persisted identity loads");
    assert_eq!(loaded.local_signing_did, id.local_signing_did);
    assert_eq!(loaded.signing_key.to_bytes(), id.signing_key.to_bytes());
}

#[test]
fn secure_identity_handoff_moves_seed_out_of_state_record() {
    let path = temp_state_path("local-identity-secure");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let id = {
        let mut store = LocalStateStore::with_path(path.clone());
        store
            .ensure_local_identity_with_secure_store(&secure)
            .expect("secure identity")
    };
    assert!(
        LocalStateStore::with_path(path)
            .load()
            .local_identity
            .is_none(),
        "state.json must not keep the identity seed after secure-store handoff",
    );
    let stored = secure
        .get_secret(LocalStateStore::SECURE_IDENTITY_KEY)
        .expect("secure read")
        .expect("identity secret");
    let record: LocalIdentityRecord = serde_json::from_str(&stored).unwrap();
    assert_eq!(record.did_key, id.local_signing_did);
    assert_eq!(
        LocalIdentity::from_record(&record)
            .unwrap()
            .signing_key
            .to_bytes(),
        id.signing_key.to_bytes(),
    );
}

#[test]
fn secure_identity_handoff_migrates_existing_plaintext_seed() {
    let path = temp_state_path("local-identity-migrate");
    let existing = {
        let mut store = LocalStateStore::with_path(path.clone());
        store
            .ensure_local_identity_in_plaintext_state()
            .expect("plaintext test identity")
    };
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let migrated = {
        let mut store = LocalStateStore::with_path(path.clone());
        store
            .ensure_local_identity_with_secure_store(&secure)
            .expect("secure migration")
    };
    assert_eq!(migrated.local_signing_did, existing.local_signing_did);
    assert!(
        LocalStateStore::with_path(path)
            .load()
            .local_identity
            .is_none()
    );
    assert!(
        secure
            .get_secret(LocalStateStore::SECURE_IDENTITY_KEY)
            .unwrap()
            .is_some()
    );
}

#[test]
fn local_identity_two_calls_to_generate_diverge() {
    // Sanity: two `generate()` calls produce distinct keys (otherwise
    // the rng plumbing is broken). This guards against an accidental
    // regression to the deterministic [42; 32] seed.
    let one = LocalIdentity::generate().unwrap();
    let two = LocalIdentity::generate().unwrap();
    assert_ne!(one.local_signing_did, two.local_signing_did);
    assert_ne!(one.signing_key.to_bytes(), two.signing_key.to_bytes());
    assert_ne!(one.signing_key.to_bytes(), [42u8; 32]);
    assert_ne!(two.signing_key.to_bytes(), [42u8; 32]);
}

#[test]
fn local_identity_record_tamper_detection_regenerates() {
    let path = temp_state_path("local-identity-tamper");
    let mut store = LocalStateStore::with_path(path.clone());
    let original = store.ensure_local_identity().unwrap();
    // Tamper: scramble the cached did_key while keeping the seed valid.
    // The next `ensure_local_identity` must reject + regenerate.
    store.cached.local_identity = Some(LocalIdentityRecord {
        seed_hex: original.to_record().seed_hex.clone(),
        did_key: "did:key:zTAMPERED".to_owned(),
    });
    let _ = store.flush();
    let regenerated = store.ensure_local_identity().unwrap();
    assert_ne!(regenerated.local_signing_did, "did:key:zTAMPERED");
    assert_ne!(
        regenerated.signing_key.to_bytes(),
        original.signing_key.to_bytes(),
        "regenerated identity is fresh, not the tampered original"
    );
}

#[test]
fn read_receipt_policy_snapshot_persists_across_store_instances() {
    let path = temp_state_path("read-receipt-policy-persists");
    {
        let mut store = LocalStateStore::with_path(path.clone());
        store.set_read_receipt_policy_snapshot(
            "ck:realm:demo",
            Some(ReadReceiptPolicySnapshot {
                disclosure: "required".to_owned(),
                visibility: Some("track_scoped".to_owned()),
            }),
        );
    }
    let reader = LocalStateStore::with_path(path);
    let snap = reader
        .read_receipt_policy_for_realm("ck:realm:demo")
        .unwrap();
    assert_eq!(snap.disclosure, "required");
    assert_eq!(snap.visibility.as_deref(), Some("track_scoped"));
}

#[test]
fn mls_snapshot_persists_and_round_trips_through_store() {
    // MLS snapshot envelope is durable across store instances and the
    // boot path can rehydrate every realm's group from the persisted
    // record.
    use crate::mls::persistence::encrypt_state;
    let path = temp_state_path("mls-snapshot-persist");
    let realm = "ck:realm:round28-mls";
    let envelope = encrypt_state(
        realm,
        "deadbeef",
        5,
        b"placeholder-state-bytes",
        "round28-pass",
        b"deterministic-salt",
    );
    {
        let mut writer = LocalStateStore::with_path(path.clone());
        assert!(writer.mls_snapshot_for(realm).is_none());
        writer.save_mls_snapshot(realm, envelope.clone());
    }
    let reader = LocalStateStore::with_path(path);
    let restored = reader.mls_snapshot_for(realm).expect("envelope persists");
    assert_eq!(restored.realm_id, envelope.realm_id);
    assert_eq!(restored.epoch, 5);
    assert_eq!(restored.ciphertext_hex, envelope.ciphertext_hex);
    assert_eq!(reader.mls_snapshots().len(), 1);
}

#[test]
fn mls_snapshot_drop_clears_persisted_record() {
    use crate::mls::persistence::encrypt_state;
    let path = temp_state_path("mls-snapshot-drop");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ck:realm:drop-me";
    store.save_mls_snapshot(realm, encrypt_state(realm, "abcd", 1, b"x", "p", b"salt"));
    assert!(store.mls_snapshot_for(realm).is_some());
    store.drop_mls_snapshot(realm);
    assert!(store.mls_snapshot_for(realm).is_none());
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test(flavor = "multi_thread")]
async fn flush_telemetry_404_re_buffers_entries() {
    // When the audit endpoint isn't wired (404), the flush
    // re-buffers each entry so a later flush attempt picks it up. We
    // simulate the 404 by pointing the API at a localhost port that
    // nothing's listening on - reqwest emits a connection error which
    // maps to `AuditPostError::Other`. To exercise the 404 path
    // specifically we spawn a minimal hyper-free TCP listener that
    // blanket-replies with 404.
    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::telemetry::{UserActionOutcome, build_user_action_entry};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        // Reply 404 to a single request — enough for one
        // telemetry entry.
        for _ in 0..3 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            // Drain the request body opportunistically so the
            // client sees the response.
            let _ = socket.read(&mut buf).await;
            let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = socket.write_all(resp).await;
            let _ = socket.shutdown().await;
        }
    });

    let mut store = LocalStateStore::with_path(temp_state_path("flush-404"));
    store.append_telemetry(build_user_action_entry(
        "did:key:zAlice",
        "settings.theme.set",
        UserActionOutcome::Success,
        None,
    ));
    assert_eq!(store.telemetry_log().len(), 1);

    let base = format!("http://{}/", addr);
    let api = crate::api::CokretApi::new(&base).unwrap();
    let sent = store.flush_telemetry_to_server(&api).await;
    assert_eq!(sent, 0, "404 must not count as sent");
    // 404-tolerant: entry survives for next attempt.
    assert_eq!(
        store.telemetry_log().len(),
        1,
        "404 must re-buffer the entry"
    );
    server.abort();
}

#[test]
fn audit_post_error_display_and_classification() {
    // The typed error variants are how callers branch between
    // "re-buffer" and "drop" - the strings here drive operator-facing
    // copy and are part of the contract.
    let not_wired = crate::api::AuditPostError::NotWired;
    assert!(not_wired.to_string().contains("404"));
    let other = crate::api::AuditPostError::Other("conn refused".to_owned());
    assert!(other.to_string().contains("conn refused"));
}

// ── Realm remarks (spec client-preferences.md §3.7) ─

#[test]
fn realm_remark_set_and_display_name_prefers_local_name() {
    let path = temp_state_path("realm-remark-set");
    let mut store = LocalStateStore::with_path(path);
    let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
    assert!(store.realm_remark(realm_id).is_none());
    assert_eq!(
        store.display_name_for_realm(realm_id, "Engineering"),
        "Engineering",
        "no remark → public title"
    );

    let remark = crate::account_data::RealmRemark::new(realm_id, "Acme · Eng");
    store.set_realm_remark(realm_id, remark);
    assert_eq!(
        store.display_name_for_realm(realm_id, "Engineering"),
        "Acme · Eng",
        "remark → local_name"
    );
    assert!(store.realm_remarks().contains_key(realm_id));
}

#[test]
fn realm_remark_empty_value_tombstones_entry() {
    let path = temp_state_path("realm-remark-tombstone");
    let mut store = LocalStateStore::with_path(path);
    let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
    store.set_realm_remark(
        realm_id,
        crate::account_data::RealmRemark::new(realm_id, "x"),
    );
    assert!(store.realm_remark(realm_id).is_some());

    // Whitespace-only local_name is treated as tombstone — see
    // RealmRemark::is_empty.
    store.set_realm_remark(
        realm_id,
        crate::account_data::RealmRemark {
            local_name: "   ".into(),
            ..crate::account_data::RealmRemark::default()
        },
    );
    assert!(
        store.realm_remark(realm_id).is_none(),
        "empty remark must remove the entry"
    );
}

#[test]
fn realm_remark_remove_clears_only_target_realm() {
    let path = temp_state_path("realm-remark-remove");
    let mut store = LocalStateStore::with_path(path);
    let a = "ck:realm:00000000-0000-7000-8000-000000000001";
    let b = "ck:realm:00000000-0000-7000-8000-000000000002";
    store.set_realm_remark(a, crate::account_data::RealmRemark::new(a, "A"));
    store.set_realm_remark(b, crate::account_data::RealmRemark::new(b, "B"));

    store.remove_realm_remark(a);
    assert!(store.realm_remark(a).is_none());
    assert_eq!(
        store.realm_remark(b).map(|r| r.local_name),
        Some("B".to_owned()),
        "removing one Realm remark must not touch the other"
    );
}

#[test]
fn realm_remark_persists_to_disk_between_instances() {
    let path = temp_state_path("realm-remark-persist");
    let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000000";
    {
        let mut writer = LocalStateStore::with_path(path.clone());
        writer.set_realm_remark(
            realm_id,
            crate::account_data::RealmRemark::new(realm_id, "Acme · Eng"),
        );
    }
    let reader = LocalStateStore::with_path(path);
    assert_eq!(
        reader.display_name_for_realm(realm_id, "Engineering"),
        "Acme · Eng"
    );
}

#[test]
fn contact_remark_set_tombstone_and_display_name() {
    let path = temp_state_path("contact-remark-set");
    let mut store = LocalStateStore::with_path(path);
    let did = "did:web:alice.example";
    assert_eq!(store.display_name_for_actor(did, "Alice"), "Alice");

    store.set_contact_remark(
        did,
        crate::account_data::ContactRemark::new(did, "Alice from Ops"),
    );
    assert_eq!(store.display_name_for_actor(did, "Alice"), "Alice from Ops");
    assert!(store.contact_remarks().contains_key(did));

    store.set_contact_remark(
        did,
        crate::account_data::ContactRemark {
            actor_id: did.to_owned(),
            ..crate::account_data::ContactRemark::default()
        },
    );
    assert!(store.contact_remark(did).is_none());
}
