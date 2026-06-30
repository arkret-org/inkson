//! Core store persistence: cursors, projections, drafts, notifications,
//! watch levels, read cursors, push registration, OIDC / DPoP secure-store
//! migration, and account-scope lifecycle.

use super::*;

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
fn raw_operation_upsert_is_noop_for_identical_payload() {
    let path = temp_state_path("raw-op-upsert-noop");
    let mut store = LocalStateStore::with_path(path);
    let payload = serde_json::json!({
        "kind": "ck.strand.create",
        "event_id": "ck:event:upsert-1",
        "operation_id": "op-upsert-1",
        "write_state": "synced",
        "body": {
            "object": {
                "id": "ck:strand:upsert-1",
                "metadata": { "title": "Card" }
            }
        }
    });

    assert!(store.upsert_raw_operation(
        "op-upsert-1",
        Some("ck:realm:upsert".to_owned()),
        payload.clone()
    ));
    let first = store.load().raw_operations[0].clone();

    assert!(!store.upsert_raw_operation(
        "op-upsert-1",
        Some("ck:realm:upsert".to_owned()),
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
        "kind": "ck.strand.update",
        "event_id": "ck:event:upsert-2",
        "operation_id": "op-upsert-2",
        "write_state": "synced",
        "body": { "patch": { "title": { "$op": "set", "value": "Before" } } }
    });
    let enriched = serde_json::json!({
        "kind": "ck.strand.update",
        "event_id": "ck:event:upsert-2",
        "operation_id": "op-upsert-2",
        "write_state": "synced",
        "synthesis_entry_id": "ck:synthesis:entry-1",
        "body": { "patch": { "title": { "$op": "set", "value": "After" } } }
    });

    assert!(store.upsert_raw_operation("op-upsert-2", Some("ck:realm:upsert".to_owned()), base));
    assert!(store.upsert_raw_operation(
        "op-upsert-2",
        Some("ck:realm:upsert".to_owned()),
        enriched
    ));
    let state = store.load();
    assert_eq!(state.raw_operations.len(), 1);
    assert_eq!(
        state.raw_operations[0].payload["synthesis_entry_id"],
        "ck:synthesis:entry-1"
    );
    assert_eq!(
        state.raw_operations[0].payload["body"]["patch"]["title"]["value"],
        "After"
    );
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
fn local_state_migrates_local_only_drafts_to_account_data_staging() {
    let path = temp_state_path("draft-account-data-migration");
    let mut store = LocalStateStore::with_path(path.clone());
    store.save_draft(
        "ck:realm:01904100-0000-7000-8000-000000000001",
        "draft survives migration",
    );

    let migrated = store
        .migrate_local_only_drafts_to_account_data(
            b"yougen-account-data-test-key",
            "ck:device:01904100-0000-7000-8000-000000000001",
            "01970e589d21-0000-a13f9c2e",
            "2026-06-07T00:00:00Z",
        )
        .unwrap();
    assert_eq!(migrated.len(), 1);
    assert!(!migrated[0].account_data_key.contains("ck:realm:"));

    let reader = LocalStateStore::with_path(path);
    let entries = reader.draft_account_data_entries();
    let value = entries
        .get(&migrated[0].account_data_key)
        .expect("migrated draft persisted");
    assert_eq!(value["content"]["body"], "draft survives migration");
    assert_eq!(
        value["origin_device_id"],
        "ck:device:01904100-0000-7000-8000-000000000001"
    );
    assert_eq!(
        reader
            .load()
            .drafts
            .get("ck:realm:01904100-0000-7000-8000-000000000001")
            .map(String::as_str),
        Some("draft survives migration")
    );
}

#[test]
fn local_state_stages_saved_items_as_private_account_data() {
    let path = temp_state_path("saved-account-data-migration");
    let mut store = LocalStateStore::with_path(path.clone());
    let migrated = store
        .migrate_local_only_saved_items_to_account_data(
            b"yougen-account-data-test-key",
            &[crate::account_data::LegacySavedItem {
                collection_title: "Focus".to_owned(),
                target_ref: "ck:message:01904100-0000-7000-8000-000000000001".to_owned(),
                note: Some("read later".to_owned()),
            }],
            "01970e589d21-0000-a13f9c2e",
        )
        .unwrap();
    assert_eq!(migrated.len(), 1);
    assert!(!migrated[0].account_data_key.contains("Focus"));
    assert!(!migrated[0].account_data_key.contains("ck:message:"));

    let reader = LocalStateStore::with_path(path);
    let entries = reader.saved_account_data_entries();
    let value = entries
        .get(&migrated[0].account_data_key)
        .expect("migrated saved item persisted");
    assert_eq!(value["kind"], "saved_item");
    assert_eq!(value["collection_title"], "Focus");
    assert_eq!(
        value["target_ref"],
        "ck:message:01904100-0000-7000-8000-000000000001"
    );
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
    // The binary-mute helper only reports `Muted` realms.
    assert_eq!(reader.muted_realms(), vec!["ck:realm:b".to_owned()]);
    assert!(reader.is_realm_muted("ck:realm:b"));
    assert!(!reader.is_realm_muted("ck:realm:a"));
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
                "updated_at": marker.updated_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
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
fn local_state_store_ingests_read_cursor_update_to_device() {
    let path = temp_state_path("read-cursor-update");
    let mut store = LocalStateStore::with_path(path.clone());
    store.ingest_to_device_messages(&[serde_json::json!({
        "kind": "ck.read_cursor.update",
        "sender_device_id": "ck:device:01904100-0000-7000-8000-000000000001",
        "content": {
            "schema": "ck.schema.read_cursor.v1",
            "actor_id": "did:web:alice.example",
            "device_id": "ck:device:01904100-0000-7000-8000-000000000001",
            "realm_id": "ck:realm:01904100-0000-7000-8000-000000000002",
            "read_scope": {
                "kind": "strand",
                "ref": "ck:strand:01904100-0000-7000-8000-000000000003",
                "track_name": "discussion"
            },
            "position": {
                "event_id": "ck:event:01904100-0000-7000-8000-000000000004",
                "hlc": "019041000000-0001-device"
            },
            "updated_at": "2026-06-24T00:00:00Z"
        }
    })]);

    let reader = LocalStateStore::with_path(path);
    let marker = reader
        .read_cursor_for(
            "ck:realm:01904100-0000-7000-8000-000000000002",
            Some("ck:strand:01904100-0000-7000-8000-000000000003"),
        )
        .expect("read cursor update persisted");
    assert_eq!(marker.actor, "did:web:alice.example");
    assert_eq!(
        marker.body.position.event_id,
        "ck:event:01904100-0000-7000-8000-000000000004"
    );
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

#[test]
fn clear_account_scoped_preserves_device_level_and_session_grant_state() {
    let path = temp_state_path("clear-account");
    let mut store = LocalStateStore::with_path(path);
    // Account-scoped projections.
    store.save_sync_cursor("sx:before");
    store.save_realm_tree_projection("ck:space:a", serde_json::json!({}));
    store.save_draft("ck:space:a", "draft");
    store.save_private_data("did:web:tester.example", "theme", "night");
    store
        .migrate_local_only_drafts_to_account_data(
            b"yougen-account-data-test-key",
            "ck:device:01904100-0000-7000-8000-000000000001",
            "01970e589d21-0000-a13f9c2e",
            "2026-06-07T00:00:00Z",
        )
        .unwrap();
    store
        .migrate_local_only_saved_items_to_account_data(
            b"yougen-account-data-test-key",
            &[crate::account_data::LegacySavedItem {
                collection_title: "Focus".to_owned(),
                target_ref: "ck:message:01904100-0000-7000-8000-000000000001".to_owned(),
                note: None,
            }],
            "01970e589d21-0000-a13f9c2e",
        )
        .unwrap();
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
        audience: "https://principal.example/api".to_owned(),
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
    assert!(state.drafts.is_empty(), "drafts should be wiped");
    assert!(
        state.draft_account_data.is_empty(),
        "draft account_data staging should be wiped"
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
fn adopt_account_scope_isolates_accounts_per_did() {
    let path = temp_state_path("adopt-account-scope");
    let mut store = LocalStateStore::with_path(path);

    // Establish alice as the active account with a grant + cursor + projection.
    assert!(
        store.adopt_account_scope("did:web:alice.example"),
        "first adopt (no active account) switches and reports a change"
    );
    assert_eq!(
        store.active_account_did().as_deref(),
        Some("did:web:alice.example")
    );
    store.save_sync_cursor("sx:alice");
    store.save_realm_tree_projection("ck:space:a", serde_json::json!({}));
    store.set_session_grant(Some(PersistedSessionGrant {
        grant_jwt: "alice.grant".to_owned(),
        session_private_key_pem: "pem".to_owned(),
        grant_id: "g-alice".to_owned(),
        audience: "https://principal.example/api".to_owned(),
        principal_id: "did:web:alice.example".to_owned(),
        device_id: "device-1".to_owned(),
        principal_server_url: "https://principal.example".to_owned(),
        grant_expires_at: None,
        stored_at: chrono::Utc::now(),
    }));

    // Re-adopting the same actor is a no-op and keeps alice's state.
    assert!(!store.adopt_account_scope("did:web:alice.example"));
    assert_eq!(store.load().sync_cursor.as_deref(), Some("sx:alice"));
    assert!(store.load().session_grant.is_some());

    // Switching to a different identity loads bob's OWN (empty) entry — alice's
    // grant/cursor/projection live in a separate key and can never leak into
    // bob's session.
    assert!(store.adopt_account_scope("did:web:bob.example"));
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
    assert!(store.adopt_account_scope("did:web:alice.example"));
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
        store.adopt_account_scope("did:web:alice.example");
        store.save_sync_cursor("sx:alice");
        store.adopt_account_scope("did:web:bob.example");
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
    reader.adopt_account_scope("did:web:alice.example");
    assert_eq!(reader.load().sync_cursor.as_deref(), Some("sx:alice"));
}

#[test]
fn forget_account_purges_only_the_target_entry_and_device_prefs_survive() {
    let path = temp_state_path("forget-account");
    let mut store = LocalStateStore::with_path(path);
    store.set_device_pref("theme", "night");
    store.adopt_account_scope("did:web:alice.example");
    store.save_sync_cursor("sx:alice");
    store.adopt_account_scope("did:web:bob.example");
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
    store.adopt_account_scope("did:web:alice.example");
    assert_eq!(store.load().sync_cursor.as_deref(), Some("sx:alice"));
}

#[test]
fn primary_handle_is_per_account_and_readable_by_did() {
    let path = temp_state_path("primary-handle");
    let mut store = LocalStateStore::with_path(path);

    store.adopt_account_scope("did:webvh:zA:alice.example");
    store.set_primary_handle("alice");
    store.adopt_account_scope("did:webvh:zB:david.example");
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
fn known_accounts_lists_each_account_with_its_handle_and_device() {
    let path = temp_state_path("known-accounts");
    let mut store = LocalStateStore::with_path(path);

    store.register_known_account("did:webvh:zA:alice.example");
    store.adopt_account_scope("did:webvh:zA:alice.example");
    store.set_primary_handle("alice");
    store.set_session_grant(Some(PersistedSessionGrant {
        grant_jwt: "alice.grant".to_owned(),
        session_private_key_pem: "pem".to_owned(),
        grant_id: "g-alice".to_owned(),
        audience: "https://alice.example/api".to_owned(),
        principal_id: "did:webvh:zA:alice.example".to_owned(),
        device_id: "ck:device:alice-1".to_owned(),
        principal_server_url: "https://alice.example".to_owned(),
        grant_expires_at: None,
        stored_at: chrono::Utc::now(),
    }));

    store.register_known_account("did:webvh:zB:david.example");
    store.adopt_account_scope("did:webvh:zB:david.example");
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
    assert_eq!(alice.device_id, "ck:device:alice-1");
    assert_eq!(alice.server_url, "https://alice.example");
    let david = accounts
        .iter()
        .find(|account| account.did == "did:webvh:zB:david.example")
        .expect("david present");
    assert_eq!(david.handle, "david");
}

#[test]
fn account_entry_without_primary_handle_field_loads() {
    // Backward-compat: an account entry written before `primary_handle` existed
    // must still deserialize (serde default → empty handle).
    let path = temp_state_path("legacy-account-entry");
    let did = "did:webvh:zLegacy:user.example";
    let store = LocalStateStore::with_path(path.clone());
    // Hand-write the account entry file WITHOUT the primary_handle field.
    let account_file = {
        use base64::Engine as _;
        let sanitized = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(did.as_bytes());
        let stem = path.file_stem().unwrap().to_str().unwrap();
        let ext = path.extension().unwrap().to_str().unwrap();
        path.parent()
            .unwrap()
            .join(format!("{stem}.account.{sanitized}.{ext}"))
    };
    // Serialize a full entry, then strip the `primary_handle` field to mimic a
    // pre-field on-disk blob (the other fields must still be present so the
    // entry parses; `#[serde(default)]` only fills the absent handle).
    let mut entry = serde_json::to_value(ClientLocalState {
        sync_cursor: Some("sx:legacy".to_owned()),
        ..ClientLocalState::default()
    })
    .unwrap();
    entry.as_object_mut().unwrap().remove("primary_handle");
    assert!(
        entry.get("primary_handle").is_none(),
        "primary_handle stripped to mimic legacy blob"
    );
    std::fs::write(&account_file, serde_json::to_vec_pretty(&entry).unwrap()).unwrap();
    // Reading the legacy entry's handle by DID succeeds with no handle.
    assert!(store.primary_handle_for_did(did).is_none());
    // And the entry is otherwise loadable.
    let mut store = store;
    store.adopt_account_scope(did);
    assert_eq!(store.load().sync_cursor.as_deref(), Some("sx:legacy"));
}

#[test]
fn root_index_is_shared_across_clones_not_cached_per_clone() {
    // Regression: `LocalStateStore` is `#[derive(Clone)]` and held in a
    // widely-cloned `Signal<_>`. The root index (active_did / pending_login /
    // known_dids) MUST be read through the backing store, never cached per
    // clone, or a clone that didn't start the sign-in reads a stale empty root
    // (login takes the wrong branch) and a stale clone's later flush clobbers a
    // freshly-adopted active_did back to null.
    let path = temp_state_path("root-shared-clones");
    let mut a = LocalStateStore::with_path(path.clone());
    let b = a.clone();

    // `a` starts a pending sign-in...
    a.begin_pending_login("ck:device:clone-race-1", Some("jkt-1"));
    // ...and `b` (a different clone) must observe it through storage.
    let pending = b.pending_login().expect("clone b sees pending login");
    assert_eq!(pending.device_id, "ck:device:clone-race-1");

    // `b` adopts onto a resolved DID...
    let mut b = b;
    let is_new = b.adopt_pending_login("did:web:clone.example");
    assert!(is_new, "an unknown DID adopts as a new account");

    // ...and `a` (the clone that started the flow) must observe the adopted
    // active account and the cleared pending — cross-clone consistency, no
    // stale-clone overwrite.
    assert_eq!(
        a.active_account_did().as_deref(),
        Some("did:web:clone.example"),
        "clone a sees the adopted active account"
    );
    assert!(
        a.pending_login().is_none(),
        "clone a sees pending cleared, not a stale per-clone copy"
    );

    // A later flush on the stale clone must NOT rewrite the root index back to
    // null (write_persisted_state no longer co-writes the root).
    a.save_draft("ck:realm:demo", "scratch");
    let reader = LocalStateStore::with_path(path);
    assert_eq!(
        reader.active_account_did().as_deref(),
        Some("did:web:clone.example"),
        "active_did survives a stale-clone flush"
    );
}

#[test]
fn adopt_pending_login_keeps_pending_device_for_new_account() {
    let path = temp_state_path("pending-new");
    let mut store = LocalStateStore::with_path(path);
    store.begin_pending_login("ck:device:new-1", Some("jkt-new"));
    assert!(store.pending_login().is_some());

    // A DID never seen on this browser is a new account.
    let is_new = store.adopt_pending_login("did:web:newcomer.example");
    assert!(is_new, "an unknown DID adopts as a new account");
    assert!(store.pending_login().is_none(), "pending is cleared");
    assert_eq!(
        store.active_account_did().as_deref(),
        Some("did:web:newcomer.example")
    );
}

#[test]
fn adopt_pending_login_preserves_returning_account_entry() {
    let path = temp_state_path("pending-returning");
    let mut store = LocalStateStore::with_path(path);
    // Alice already has a persisted entry on this browser.
    store.adopt_account_scope("did:web:alice.example");
    store.save_sync_cursor("sx:alice");
    // Sign out, then a fresh sign-in kicks off pending device material.
    store.begin_pending_login("ck:device:fresh-2", Some("jkt-fresh"));
    let is_new = store.adopt_pending_login("did:web:alice.example");
    assert!(!is_new, "a returning DID is not a new account");
    assert!(store.pending_login().is_none());
    // Alice's own entry (with her cursor) is restored, not wiped. The
    // secure-store seed/device_id tuple was already re-homed before this root
    // marker is adopted.
    assert_eq!(store.load().sync_cursor.as_deref(), Some("sx:alice"));
}

#[test]
fn legacy_single_blob_migrates_to_root_index_and_account_entry() {
    let path = temp_state_path("legacy-migrate");
    // Hand-write a legacy global blob: a `ClientLocalState` at the root key
    // with an `account_scope_owner`, exactly the pre-refactor shape.
    let owner = "did:web:legacy.example";
    let mut legacy = serde_json::to_value(ClientLocalState {
        sync_cursor: Some("sx:legacy".to_owned()),
        ..ClientLocalState::default()
    })
    .unwrap();
    legacy
        .as_object_mut()
        .unwrap()
        .insert("account_scope_owner".to_owned(), serde_json::json!(owner));
    std::fs::write(&path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();

    // First load runs the read-time migration.
    let store = LocalStateStore::with_path(path.clone());
    assert_eq!(store.active_account_did().as_deref(), Some(owner));
    assert!(store.known_account_dids().iter().any(|did| did == owner));
    assert_eq!(store.load().sync_cursor.as_deref(), Some("sx:legacy"));

    // The root key now holds a RootIndex (has `known_dids`), not a ClientLocalState.
    let raw = std::fs::read_to_string(&path).unwrap();
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert!(value.get("known_dids").is_some(), "root is now an index");
    assert!(
        value.get("sync_cursor").is_none(),
        "the blob moved out of the root key"
    );
}
