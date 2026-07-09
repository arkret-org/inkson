//! XOR non-sensitive-preference obfuscation helpers and MLS snapshot envelope
//! persistence.

use super::*;

#[test]
fn obfuscate_nonsensitive_roundtrip() {
    let key = "did:webvh:z6mkfixture:alice.example";
    let plaintext = "my ui preference";
    let obfuscated = obfuscate_nonsensitive(key, plaintext);
    assert_ne!(obfuscated, plaintext);
    let recovered = deobfuscate_nonsensitive(key, &obfuscated).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn obfuscate_nonsensitive_empty_key_returns_original() {
    assert_eq!(obfuscate_nonsensitive("", "hello"), "hello");
}

#[test]
fn mls_snapshot_persists_and_round_trips_through_store() {
    // MLS snapshot envelope is durable across store instances and the
    // boot path can rehydrate every realm's group from the persisted
    // record.
    use crate::mls::persistence::encrypt_state;
    let path = temp_state_path("mls-snapshot-persist");
    let realm = "ak:realm:round28-mls";
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
    let realm = "ak:realm:drop-me";
    store.save_mls_snapshot(realm, encrypt_state(realm, "abcd", 1, b"x", "p", b"salt"));
    assert!(store.mls_snapshot_for(realm).is_some());
    store.drop_mls_snapshot(realm);
    assert!(store.mls_snapshot_for(realm).is_none());
}

#[test]
fn logout_session_clear_preserves_account_e2ee_state() {
    use crate::mls::persistence::encrypt_state;

    let path = temp_state_path("logout-preserves-mls");
    let realm = "ak:realm:logout-preserves";
    let actor = "did:web:alice.example";
    let grant = PersistedSessionGrant {
        grant_jwt: "alice.grant".to_owned(),
        session_private_key_pem: "pem".to_owned(),
        grant_id: "g-alice".to_owned(),
        audience: "https://principal.example/api".to_owned(),
        principal_id: actor.to_owned(),
        device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
        principal_server_url: "https://principal.example".to_owned(),
        grant_expires_at: None,
        stored_at: chrono::Utc::now(),
    };
    let dpop = DpopDeviceKeyRecord {
        seed_b64: "seed".to_owned(),
        jkt: "jkt-old".to_owned(),
        created_at: chrono::Utc::now(),
    };

    {
        let mut store = LocalStateStore::with_path(path.clone());
        store.adopt_account_scope(actor);
        store.save_mls_snapshot(
            realm,
            encrypt_state(realm, "abcd", 1, b"state", "secret", b"salt"),
        );
        store.save_realm_tree_projection(realm, serde_json::json!({"title": "Project"}));
        store.save_draft(realm, "draft");
        store.set_session_grant(Some(grant));
        store.set_dpop_device_key(Some(dpop));

        store.clear_session_scoped_for_logout();
    }

    let reader = LocalStateStore::with_path(path);
    assert_eq!(reader.active_account_did().as_deref(), Some(actor));
    assert!(reader.session_grant().is_none());
    assert!(reader.dpop_device_key().is_none());
    assert!(
        reader.mls_snapshot_for(realm).is_some(),
        "logout must preserve local MLS snapshot for returning account"
    );
    assert!(
        reader.load().realm_tree_projections.get(realm).is_some(),
        "logout must preserve the account's own projection cache"
    );
    assert_eq!(
        reader.load().drafts.get(realm).map(String::as_str),
        Some("draft")
    );
}
