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
        Some("ak:realm:demo".to_owned()),
        serde_json::json!({"type": "ak.message.create"}),
    );
    store.save_realm_tree_projection("ak:realm:demo", serde_json::json!({"name": "Demo"}));

    let state = store.load();
    assert_eq!(state.sync_cursor.as_deref(), Some("sx:next"));
    assert_eq!(
        state.raw_operations[0].operation_id,
        "ak:operation:local-01"
    );
    assert_eq!(
        state.realm_tree_projections["ak:realm:demo"]["name"],
        "Demo"
    );
}

#[test]
fn raw_operation_upsert_is_noop_for_identical_payload() {
    let path = temp_state_path("raw-op-upsert-noop");
    let mut store = LocalStateStore::with_path(path);
    let payload = serde_json::json!({
        "kind": "ak.strand.create",
        "event_id": "ak:event:upsert-1",
        "operation_id": "op-upsert-1",
        "write_state": "synced",
        "body": {
            "object": {
                "id": "ak:strand:upsert-1",
                "metadata": { "title": "Card" }
            }
        }
    });

    assert!(store.upsert_raw_operation(
        "op-upsert-1",
        Some("ak:realm:upsert".to_owned()),
        payload.clone()
    ));
    let first = store.load().raw_operations[0].clone();

    assert!(!store.upsert_raw_operation(
        "op-upsert-1",
        Some("ak:realm:upsert".to_owned()),
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
        "event_id": "ak:event:upsert-2",
        "operation_id": "op-upsert-2",
        "write_state": "synced",
        "body": { "patch": { "title": { "$op": "set", "value": "Before" } } }
    });
    let enriched = serde_json::json!({
        "kind": "ak.strand.update",
        "event_id": "ak:event:upsert-2",
        "operation_id": "op-upsert-2",
        "write_state": "synced",
        "synthesis_entry_id": "ak:synthesis:entry-1",
        "body": { "patch": { "title": { "$op": "set", "value": "After" } } }
    });

    assert!(store.upsert_raw_operation("op-upsert-2", Some("ak:realm:upsert".to_owned()), base));
    assert!(store.upsert_raw_operation(
        "op-upsert-2",
        Some("ak:realm:upsert".to_owned()),
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
        "event_id": "ak:event:upsert-redacted",
        "message_id": "ak:message:upsert-redacted",
        "redacted": true,
        "state": "redacted",
        "content": {"kind": "ak.content.text", "body": "[redacted]"}
    });
    let plaintext = serde_json::json!({
        "kind": "ak.message.create",
        "event_id": "ak:event:upsert-redacted",
        "message_id": "ak:message:upsert-redacted",
        "content": {"kind": "ak.content.text", "body": "secret"}
    });

    assert!(store.upsert_raw_operation(
        "ak:event:upsert-redacted",
        Some("ak:realm:upsert".to_owned()),
        tombstone
    ));
    assert!(!store.upsert_raw_operation(
        "ak:event:upsert-redacted",
        Some("ak:realm:upsert".to_owned()),
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
    let realm_id = Some("ak:realm:upsert".to_owned());
    let message_id = "ak:message:upsert-message-id";
    let original = serde_json::json!({
        "kind": "ak.message.create",
        "event_id": "ak:event:upsert-message-original",
        "message_id": message_id,
        "content": {"kind": "ak.content.text", "body": "original"}
    });
    let revised_projection = serde_json::json!({
        "kind": "ak.message.create",
        "event_id": "ak:event:upsert-message-revision",
        "message_id": message_id,
        "content": {"kind": "ak.content.text", "body": "edited"}
    });
    let redacted_projection = serde_json::json!({
        "kind": "ak.message.create",
        "event_id": "ak:event:upsert-message-revision",
        "message_id": message_id,
        "redacted": true,
        "state": "redacted",
        "content": {"kind": "ak.content.text", "body": "[redacted]"}
    });

    assert!(store.upsert_raw_operation(
        "ak:event:upsert-message-original",
        realm_id.clone(),
        original,
    ));
    assert!(store.upsert_raw_operation(
        "ak:event:upsert-message-revision",
        realm_id.clone(),
        revised_projection,
    ));
    assert!(store.upsert_raw_operation(
        "ak:event:upsert-message-revision",
        realm_id,
        redacted_projection,
    ));

    let state = store.load();
    assert_eq!(state.raw_operations.len(), 1);
    assert_eq!(
        state.raw_operations[0].payload["event_id"],
        "ak:event:upsert-message-revision"
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
    let realm_id = "ak:realm:destroyed";

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
    store.save_notification_projection(vec![serde_json::json!({
        "notification_id": "notif-1",
        "realm_id": "ak:realm:demo",
        "kind": "message",
        "body": "Hello"
    })]);
    store.set_notification_read("notif-1", true);
    store.set_notification_archived("notif-1", true);
    store.set_realm_muted("ak:realm:demo", true);
    store.set_notification_kind_enabled("message", false);

    let reader = LocalStateStore::with_path(path);
    assert_eq!(reader.notification_projection().len(), 1);
    assert!(reader.notification_state_for("notif-1").read);
    assert!(reader.notification_state_for("notif-1").archived);
    assert!(reader.is_realm_muted("ak:realm:demo"));
    assert!(!reader.notification_kind_enabled("message"));
}

#[test]
fn realm_watch_level_set_get_roundtrip() {
    let path = temp_state_path("watch-level-roundtrip");
    let mut store = LocalStateStore::with_path(path.clone());
    store.set_realm_watch_level("ak:realm:a", WatchLevel::All);
    store.set_realm_watch_level("ak:realm:b", WatchLevel::Muted);
    // Setting the protocol default clears the override.
    store.set_realm_watch_level("ak:realm:c", WatchLevel::Participating);
    store.set_realm_watch_level("ak:realm:c", WatchLevel::MentionsOnly);

    let reader = LocalStateStore::with_path(path);
    assert_eq!(reader.realm_watch_level("ak:realm:a"), WatchLevel::All);
    assert_eq!(reader.realm_watch_level("ak:realm:b"), WatchLevel::Muted);
    assert_eq!(
        reader.realm_watch_level("ak:realm:c"),
        WatchLevel::MentionsOnly
    );
    assert!(!reader.realm_watch_levels().contains_key("ak:realm:c"));
    // The binary-mute helper only reports `Muted` realms.
    assert_eq!(reader.muted_realms(), vec!["ak:realm:b".to_owned()]);
    assert!(reader.is_realm_muted("ak:realm:b"));
    assert!(!reader.is_realm_muted("ak:realm:a"));
}

#[test]
fn local_state_store_persists_private_read_cursors() {
    let path = temp_state_path("read-cursor");
    let mut store = LocalStateStore::with_path(path.clone());
    const DEVICE_ID: &str = "ak:device:01964137-0000-7000-8000-000000000001";
    const REALM_ID: &str = "ak:realm:01964137-0000-7000-8000-000000000010";
    const EVENT_ID: &str = "ak:event:01964137-0000-7000-8000-000000000020";
    let marker = store
        .save_read_cursor("did:web:alice.example", DEVICE_ID, REALM_ID, None, EVENT_ID)
        .unwrap();

    assert_eq!(marker.marker_type, "ak.read_cursor.advance");
    assert_eq!(marker.body.realm_id, REALM_ID);
    assert_eq!(marker.body.position.event_id.as_str(), EVENT_ID);
    assert_eq!(marker.body.read_scope.kind.as_str(), "strand");
    assert_eq!(marker.body.read_scope.track.as_deref(), Some("discussion"));
    assert_eq!(
        marker.ak_read_cursor_operation(),
        serde_json::json!({
            "kind": "ak.read_cursor.advance",
            "payload": {
                "id": &marker.body.id,
                "schema": "ak.schema.read_cursor.v1",
                "actor_id": "did:web:alice.example",
                "device_id": DEVICE_ID,
                "realm_id": REALM_ID,
                "read_scope": {
                    "kind": "strand",
                    "container_ref": "ak:strand:01964137-0000-7000-8000-000000000010",
                    "track_name": "discussion"
                },
                "position": {
                    "event_id": EVENT_ID,
                    "hlc": &marker.body.position.hlc
                },
                "updated_at": marker.updated_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            },
        })
    );

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
fn local_state_store_ingests_read_cursor_update_to_device() {
    let path = temp_state_path("read-cursor-update");
    let mut store = LocalStateStore::with_path(path.clone());
    store.ingest_to_device_messages(&[serde_json::from_value(serde_json::json!({
        "message_id": "ak:device_message:01904100-0000-7000-8000-000000000005",
        "kind": "ak.read_cursor.update",
        "sender_principal_id": "did:webvh:z6mkfixture:alice.example",
        "sender_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
        "recipient_principal_id": "did:webvh:z6mkfixture:alice.example",
        "recipient_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
        "sent_at": "2026-06-24T00:00:00Z",
        "expires_at": "2099-06-25T00:00:00Z",
        "content": {
            "schema": "ak.schema.read_cursor.v1",
            "actor_id": "did:web:alice.example",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000002",
            "read_scope": {
                "kind": "strand",
                "container_ref": "ak:strand:01904100-0000-7000-8000-000000000003",
                "track_name": "discussion"
            },
            "position": {
                "event_id": "ak:event:01904100-0000-7000-8000-000000000004",
                "hlc": "019041000000-0001-deadbeef"
            },
            "updated_at": "2026-06-24T00:00:00Z"
        }
    }))
    .unwrap()]);

    let reader = LocalStateStore::with_path(path);
    let marker = reader
        .read_cursor_for(
            "ak:realm:01904100-0000-7000-8000-000000000002",
            Some("ak:strand:01904100-0000-7000-8000-000000000003"),
        )
        .expect("read cursor update persisted");
    assert_eq!(marker.actor, "did:web:alice.example");
    assert_eq!(
        marker.body.position.event_id.as_str(),
        "ak:event:01904100-0000-7000-8000-000000000004"
    );
}

#[test]
fn local_state_store_durably_deduplicates_device_message_envelopes() {
    let path = temp_state_path("device-message-dedup");
    let message: arkret_sdk::DeviceMessageEnvelope = serde_json::from_value(serde_json::json!({
    "message_id": "ak:device_message:0196419b-0000-7000-8000-000000000071",
    "kind": "ak.key.verification.request",
    "sender_principal_id": "did:webvh:z6mkfixture:alice.example",
    "sender_device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
    "recipient_principal_id": "did:webvh:z6mkfixture:alice.example",
    "recipient_device_id": "ak:device:0196419b-0000-7000-8000-000000000002",
    "sent_at": "2026-07-17T00:00:00Z",
    "expires_at": "2099-07-17T00:10:00Z",
    "content": {
        "from_device": "ak:device:0196419b-0000-7000-8000-000000000001",
        "pairing_code": "123456"
    }
    }))
    .unwrap();

    let mut writer = LocalStateStore::with_path(path.clone());
    assert_eq!(writer.ingest_to_device_messages(&[message.clone()]), 1);
    assert_eq!(writer.ingest_to_device_messages(&[message.clone()]), 0);
    assert_eq!(writer.to_device_inbox().len(), 1);
    assert_eq!(writer.load().to_device_receipts.len(), 1);
    assert_eq!(
        writer.dismiss_pairing_to_device_message(
            "ak:device:0196419b-0000-7000-8000-000000000001",
            "123456",
        ),
        1
    );

    let mut reopened = LocalStateStore::with_path(path);
    assert_eq!(reopened.ingest_to_device_messages(&[message]), 0);
    assert!(reopened.to_device_inbox().is_empty());

    let conflicting: arkret_sdk::DeviceMessageEnvelope =
        serde_json::from_value(serde_json::json!({
        "message_id": "ak:device_message:0196419b-0000-7000-8000-000000000071",
        "kind": "ak.key.verification.request",
        "sender_principal_id": "did:webvh:z6mkfixture:alice.example",
        "sender_device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
        "recipient_principal_id": "did:webvh:z6mkfixture:alice.example",
        "recipient_device_id": "ak:device:0196419b-0000-7000-8000-000000000002",
        "sent_at": "2026-07-17T00:00:00Z",
        "expires_at": "2099-07-17T00:10:00Z",
        "content": {
            "from_device": "ak:device:0196419b-0000-7000-8000-000000000001",
            "pairing_code": "654321"
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
    const REALM_ID: &str = "ak:realm:01964137-0000-7000-8000-000000000011";
    const TOPIC_EVENT_ID: &str = "ak:event:01964137-0000-7000-8000-000000000021";
    const THREAD_ID: &str = "ak:thread:01964137-0000-7000-8000-000000000031";
    const THREAD_EVENT_ID: &str = "ak:event:01964137-0000-7000-8000-000000000022";
    store
        .save_read_cursor(
            "did:web:alice.example",
            "ak:device:01964137-0000-7000-8000-000000000001",
            REALM_ID,
            None,
            TOPIC_EVENT_ID,
        )
        .unwrap();
    store
        .save_read_cursor(
            "did:web:alice.example",
            "ak:device:01964137-0000-7000-8000-000000000001",
            REALM_ID,
            Some(THREAD_ID.to_owned()),
            THREAD_EVENT_ID,
        )
        .unwrap();

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
        registration_id: Some("ak:push:local".to_owned()),
        device_id: "dev_inkson".to_owned(),
        platform: Some("desktop".to_owned()),
        app_id: Some("inkson".to_owned()),
        push_gateway: "https://push.example/_arkret/edge/push/notify".to_owned(),
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
    assert_eq!(state.registration_id.as_deref(), Some("ak:push:local"));
    assert_eq!(state.device_id, "dev_inkson");

    reader.clear_push_registration();
    assert!(reader.push_registration().is_none());
}

#[test]
fn dpop_device_key_uses_secure_key_store() {
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
    let mut state = ClientLocalState::default();
    state.sync_cursor = Some("ak:cursor:safe".to_owned());
    state.session_grant = Some(PersistedSessionGrant {
        grant_jwt: "secret.grant.jwt".to_owned(),
        session_private_key_pem: "secret-session-private-key".to_owned(),
        grant_id: "grant-id".to_owned(),
        audience: "did:web:principal.example".to_owned(),
        principal_id: "did:web:alice.example".to_owned(),
        device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
        principal_server_url: "https://principal.example".to_owned(),
        grant_expires_at: None,
        stored_at: chrono::Utc::now(),
    });

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
    let path = temp_state_path("pending-new");
    let mut store = LocalStateStore::with_path(path);
    store.begin_pending_login("ak:device:new-1", Some("jkt-new"));
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
    store.switch_active_account("did:web:alice.example");
    store.save_sync_cursor("sx:alice");
    // Sign out, then a fresh sign-in kicks off pending device material.
    store.begin_pending_login("ak:device:fresh-2", Some("jkt-fresh"));
    let is_new = store.adopt_pending_login("did:web:alice.example");
    assert!(!is_new, "a returning DID is not a new account");
    assert!(store.pending_login().is_none());
    // Alice's own entry (with her cursor) is restored, not wiped. The
    // secure-store seed/device_id tuple was already re-homed before this root
    // marker is adopted.
    assert_eq!(store.load().sync_cursor.as_deref(), Some("sx:alice"));
}

#[test]
fn adopt_pending_login_moves_the_unfinished_handoff_with_its_registration() {
    let path = temp_state_path("pending-onboarding-handoff");
    let mut store = LocalStateStore::with_path(path);
    let device = "ak:device:019f0000-0000-7000-8000-000000000001";
    let handoff = PendingAccountHandoff {
        principal_server_url: "https://principal.example".to_owned(),
        gate_account_base: "https://auth.example/_arkret/gate/account".to_owned(),
        request_id: "ak:request:019f0000-0000-7000-8000-000000000000".to_owned(),
        account_handle: "alice:auth.example".to_owned(),
        holder_jkt: "holder-jkt".to_owned(),
        audience: "did:webvh:z6mkfixture:principal.example".to_owned(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        lease_id: Some("lease-1".to_owned()),
        lease_fence: Some(1),
        lease_expires_at: Some(chrono::Utc::now() + chrono::Duration::minutes(15)),
        retry_after_ms: None,
        device_id: device.to_owned(),
        enrollment_authority_did: "did:key:z6MkrJVnaZkeFzdQyKjzgRHjhBfE6ZscXDFHq8T7TYNy9v1t"
            .to_owned(),
        trust_domain: "ak:trust-domain:test".to_owned(),
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
    store.begin_pending_login(device, Some(&handoff.holder_jkt));

    store.adopt_pending_login(&did);

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
