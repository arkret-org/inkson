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
    let realm = "ak:realm:AR9U75vD82XqGon9r2GYv6cwT3_W8U4BtjeOCoODErj_";
    let envelope = encrypt_state(
        realm,
        "deadbeef",
        5,
        b"placeholder-state-bytes",
        "mls-local-state-passphrase",
        b"deterministic-salt",
    );
    {
        let mut writer = LocalStateStore::with_path(path.clone());
        assert!(writer.mls_snapshot_for(realm).is_none());
        writer.save_mls_snapshot(realm, envelope.clone()).unwrap();
    }
    let reader = LocalStateStore::with_path(path);
    let restored = reader.mls_snapshot_for(realm).expect("envelope persists");
    assert_eq!(restored.realm_id, envelope.realm_id);
    assert_eq!(restored.epoch, 5);
    assert_eq!(restored.ciphertext_hex, envelope.ciphertext_hex);
    assert_eq!(reader.mls_snapshots().len(), 1);
}

#[test]
fn logout_session_clear_shreds_memory_and_preserves_encrypted_e2ee_state() {
    use crate::mls::persistence::encrypt_state;
    use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore};

    let path = temp_state_path("logout-preserves-mls");
    let realm = "ak:realm:ARkI10daMTZLo_cMC-hjorA_xQhU-5dVl4H0BWDB_xTA";
    let actor = "did:web:alice.example";
    let strand = "ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL";
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let secure = MemorySecureKeyStore::new();
    let grant = PersistedSessionGrant {
        grant_jwt: "alice.grant".to_owned(),
        session_private_key_pem: "pem".to_owned(),
        grant_id: "g-alice".to_owned(),
        audience_id: arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        principal_id: crate::mls_api_helpers::principal_core_id(actor).unwrap(),
        service_account_id: arkret_sdk::ServiceAccountId::new("account-1").unwrap(),
        device_id: arkret_sdk::DeviceId::new(
            "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
        )
        .unwrap(),
        station_url: url::Url::parse("https://principal.example").unwrap(),
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
        store.switch_test_account(actor);
        store
            .save_mls_snapshot(
                realm,
                encrypt_state(realm, "abcd", 1, b"state", "secret", b"salt"),
            )
            .unwrap();
        store.save_private_plaintext(realm, strand, "body", "author secret");
        store.advance_mls_receive_chain(
            realm,
            encrypt_state(realm, "abcd", 2, b"advanced", "secret", b"salt"),
            digest,
            b"remote secret",
        );
        store
            .persist_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap();
        store.save_realm_tree_projection(realm, serde_json::json!({"title": "Project"}));
        store.set_session_grant(Some(grant));
        store.set_dpop_device_key(Some(dpop));

        store.clear_session_scoped_for_logout();
        assert!(store.private_plaintext_for(realm, strand, "body").is_none());
        assert!(store.mls_decrypted_plaintext_for(realm, digest).is_none());

        let namespace = store.active_authority_namespace_for_test();
        let cache_key = crate::secure_key_store::e2ee_plaintext_cache_store_key(&namespace);
        assert!(secure.get_secret(&cache_key).unwrap().is_some());
        store
            .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap();
        assert_eq!(
            store
                .private_plaintext_for(realm, strand, "body")
                .as_deref(),
            Some("author secret")
        );
        assert_eq!(
            store.mls_decrypted_plaintext_for(realm, digest).as_deref(),
            Some(&b"remote secret"[..])
        );
    }

    let reader = LocalStateStore::with_path(path);
    assert_eq!(
        reader.active_principal_id().as_deref(),
        Some("ak:did_core:web:alice.example")
    );
    assert!(reader.session_grant().is_none());
    assert!(reader.dpop_device_key().is_none());
    assert!(
        reader.mls_snapshot_for(realm).is_some(),
        "logout must preserve local MLS snapshot for returning account"
    );
    assert!(
        reader.load().realm_tree_projections.contains_key(realm),
        "logout must preserve the account's own projection cache"
    );
}
