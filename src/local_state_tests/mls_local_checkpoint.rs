//! MLS snapshot envelope persistence.

use super::*;

#[test]
fn stale_secure_creator_cache_cannot_replace_the_accepted_private_checkpoint() {
    use crate::mls::persistence::encrypt_state;
    use crate::secure_key_store::MemorySecureKeyStore;
    let realm =
        arkret_sdk::RealmId::new("ak:realm:AR9U75vD82XqGon9r2GYv6cwT3_W8U4BtjeOCoODErj_").unwrap();
    let event =
        arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [71; 32]);
    let circle_id = arkret_sdk::CircleId::from_event_id(&event);
    for scope in [
        arkret_sdk::ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        arkret_sdk::ScopeRef::Circle {
            realm_id: realm.clone(),
            circle_id,
        },
    ] {
        let path = temp_state_path(&format!(
            "accepted-creator-cache-{}",
            scope.canonical_mls_group_id().unwrap()
        ));
        let secure = MemorySecureKeyStore::new();
        let mut store = LocalStateStore::with_path(path.clone());
        store.switch_test_account("did:web:alice.example");
        let group = scope.canonical_mls_group_id().unwrap().to_string();
        let old = encrypt_state(
            realm.as_str(),
            &group,
            0,
            b"closed attempt",
            "secret",
            b"old-salt",
        );
        store.save_mls_checkpoint_for_scope(&scope, old).unwrap();
        store
            .persist_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap();
        let winning = encrypt_state(
            realm.as_str(),
            &group,
            0,
            b"winning attempt",
            "secret",
            b"winning-salt",
        );
        store
            .save_mls_checkpoint_for_scope(&scope, winning.clone())
            .unwrap();
        store
            .mark_mls_genesis_emitted_for_scope_with_event(&scope, &event)
            .unwrap();
        let mut expected = winning;
        expected.group_state_event_id = Some(event.clone());
        store
            .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap();
        assert_eq!(
            store.mls_checkpoint_for_scope(&scope),
            Some(expected.clone())
        );
        assert_eq!(
            store.durable_mls_checkpoint_for_scope(&scope).unwrap(),
            Some(expected)
        );
        assert!(
            !crate::mls::creator_bootstrap::creator_scope_mls_bootstrap_pending(&store, &scope)
        );
    }
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
        assert!(writer.mls_checkpoint_for(realm).is_none());
        writer.save_mls_checkpoint(realm, envelope.clone()).unwrap();
    }
    let reader = LocalStateStore::with_path(path);
    let restored = reader.mls_checkpoint_for(realm).expect("envelope persists");
    assert_eq!(restored.realm_id, envelope.realm_id);
    assert_eq!(restored.epoch, 5);
    assert_eq!(restored.ciphertext_hex, envelope.ciphertext_hex);
    assert_eq!(reader.mls_local_checkpoints().len(), 1);
}

#[test]
fn receive_ratchet_preserves_exact_accepted_group_state_event() {
    use crate::mls::persistence::encrypt_state;

    let path = temp_state_path("mls-receive-accepted-ref");
    let realm = "ak:realm:AR9U75vD82XqGon9r2GYv6cwT3_W8U4BtjeOCoODErj_";
    let event =
        arkret_sdk::EventId::new("ak:event:AapALysveT_m0ubp6kTGkXSK9371_ilR-kAJwNFmxyjr").unwrap();
    let mut initial = encrypt_state(realm, "abcd", 1, b"initial", "secret", b"initial-salt");
    initial.group_state_event_id = Some(event.clone());
    let mut store = LocalStateStore::with_path(path.clone());
    store.switch_test_account("did:web:alice.example");
    store.save_mls_checkpoint(realm, initial).unwrap();

    let advanced = encrypt_state(realm, "abcd", 1, b"advanced", "secret", b"advanced-salt");
    assert!(advanced.group_state_event_id.is_none());
    store.advance_mls_receive_chain(
        realm,
        advanced,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        b"received",
    );
    assert_eq!(
        store
            .mls_group_state_ref_for_effective_scope(realm, None, "abcd", 1)
            .unwrap(),
        event
    );
    store.set_read_receipt_default_send(true);
    drop(store);

    let restored = LocalStateStore::with_path(path);
    assert_eq!(
        restored
            .mls_group_state_ref_for_effective_scope(realm, None, "abcd", 1)
            .unwrap(),
        event
    );
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
        granted_scope: Vec::new(),
        account_id: arkret_sdk::AccountId::new(
            crate::mls_api_helpers::principal_core_id(actor).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        ),
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
            .save_mls_checkpoint(
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
        reader.mls_checkpoint_for(realm).is_some(),
        "logout must preserve local MLS snapshot for returning account"
    );
    assert!(
        reader.load().realm_tree_projections.contains_key(realm),
        "logout must preserve the account's own projection cache"
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn rejected_mls_checkpoint_and_cleanup_marker_share_one_durable_main_cut() {
    let path = temp_state_path("rejected-mls-cut");
    let realm =
        arkret_sdk::RealmId::new("ak:realm:AR9U75vD82XqGon9r2GYv6cwT3_W8U4BtjeOCoODErj_").unwrap();
    let scope = arkret_sdk::ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let event =
        arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [71; 32]);
    let group = scope.canonical_mls_group_id().unwrap().to_string();
    let mut store = LocalStateStore::with_path(path.clone());
    store.switch_test_account("did:web:alice.example");
    let pending = crate::mls::persistence::encrypt_state(
        realm.as_str(),
        &group,
        1,
        b"pending candidate with advanced ratchet",
        "secret",
        b"pending-salt",
    );
    store
        .save_mls_checkpoint_for_scope(&scope, pending.clone())
        .unwrap();
    let cleared = crate::mls::persistence::encrypt_state(
        realm.as_str(),
        &group,
        1,
        b"candidate removed with same advanced ratchet",
        "secret",
        b"cleared-salt",
    );
    store
        .save_rejected_mls_checkpoint(&scope, cleared.clone(), &event)
        .unwrap();
    let mut before = LocalStateStore::with_path(path.clone());
    before.switch_test_account("did:web:alice.example");
    assert_eq!(before.mls_checkpoint_for_scope(&scope), Some(pending));
    assert!(before.mls_rejection_cleared_checkpoint(&event).is_none());
    store.begin_durable_flush().unwrap().wait().await.unwrap();
    let mut recovered = LocalStateStore::with_path(path);
    recovered.switch_test_account("did:web:alice.example");
    assert_eq!(
        recovered.mls_checkpoint_for_scope(&scope),
        Some(cleared.clone())
    );
    assert_eq!(
        recovered.mls_rejection_cleared_checkpoint(&event),
        Some(cleared)
    );
}
