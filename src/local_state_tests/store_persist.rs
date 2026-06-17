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
