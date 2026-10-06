//! Narrow reads must retain the same account and receive-overlay authority
//! while avoiding copies of unrelated account history on every displayed row.

use super::*;

const REALM: &str = "ak:realm:ARUALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE";

fn store() -> (tempfile::TempDir, LocalStateStore) {
    let directory = tempfile::tempdir().unwrap();
    let mut store = LocalStateStore::with_path(directory.path().join("state.json"));
    store.switch_test_account("did:web:alice.example");
    store.ensure_cached_loaded();
    (directory, store)
}

fn add_unrelated_history(store: &mut LocalStateStore) {
    store.cached.raw_operations = (0..10_000)
        .map(|index| RawOperationRecord {
            operation_id: format!("unrelated-audit-{index}"),
            realm_id: Some("unrelated".into()),
            received_at: Utc::now(),
            payload: serde_json::json!({"unrelated": "x".repeat(128)}),
        })
        .collect();
}

fn signed_link() -> LocallyAuthenticatedIdentityLink {
    use ed25519_dalek::Signer as _;
    let key = ed25519_dalek::SigningKey::from_bytes(&[41; 32]);
    let public_key = key.verifying_key().to_bytes();
    let key_id = arkret_sdk::canonical::ed25519_pubkey_to_did_key_multibase(&public_key);
    let did = arkret_sdk::Did::new(format!("did:key:{key_id}")).unwrap();
    let method = format!("{did}#{key_id}");
    let placeholder = arkret_sdk::canonical::sha256_digest(b"placeholder");
    let mut link: arkret_sdk::IdentityLink = serde_json::from_value(serde_json::json!({
        "schema": arkret_sdk::IdentityLink::SCHEMA,
        "pairwise_actor_id": arkret_sdk::project_did_to_core_id(&did).unwrap(),
        "principal_id": "ak:did_core:web:alice.example",
        "device_id": "ak:device:01964137-0000-7000-8000-000000000001",
        "realm_id": REALM,
        "trust_domain": "ak:trust_domain:station.example",
        "mls_group_id": "AQID", "mls_leaf_index": 4, "mls_epoch": 2,
        "response_signing_verification_method": method,
        "response_signing_algorithm": "Ed25519",
        "response_signing_public_key_b64u": arkret_sdk::base64url_encode(&public_key),
        "response_signing_public_key_digest": arkret_sdk::canonical::sha256_digest(&public_key),
        "effective_at": "2026-10-06T00:00:00.000Z",
        "proof": {"verification_method": method, "signature_algorithm": "Ed25519",
            "payload_digest": placeholder, "signature": "pending"}
    }))
    .unwrap();
    link.proof.payload_digest = link.canonical_payload_digest().unwrap();
    link.proof.signature =
        arkret_sdk::base64url_encode(&key.sign(&link.canonical_proof_input().unwrap()).to_bytes());
    link.validate_minimal().unwrap();
    let bytes = arkret_sdk::canonical::canonical_json_bytes(&link).unwrap();
    LocallyAuthenticatedIdentityLink {
        identity_link: link,
        identity_link_canonical_bytes_b64u: arkret_sdk::Base64UrlString::new(
            arkret_sdk::base64url_encode(&bytes),
        )
        .unwrap(),
        identity_link_digest: arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(&bytes))
            .unwrap(),
        leaf_node_canonical_bytes_b64u: arkret_sdk::Base64UrlString::new("AQID").unwrap(),
        leaf_node_digest: arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(&[1, 2, 3]))
            .unwrap(),
        winning_group_state_ref: arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [71; 32],
        ),
    }
}

fn install_empty_signed_cut(store: &mut LocalStateStore) {
    use crate::test_support::committed_event::{
        FixtureStation, fixture_time, verified_realm_fixture_as,
    };
    let realm = arkret_sdk::RealmId::new(REALM).unwrap();
    let (bundle, ..) = verified_realm_fixture_as(
        realm.clone(),
        Vec::new(),
        "alice.example",
        "ak:device:01964137-0000-7000-8000-000000000001",
    );
    let mut snapshot = arkret_sdk::RealmStateSnapshot {
        snapshot_id: arkret_sdk::RealmSnapshotId::from_digest([0; 32]),
        realm_id: realm,
        governance_generation: 0,
        visible_stream_heads: Vec::new(),
        current_state_entries: Vec::new(),
        retention_and_history_floor: arkret_sdk::RetentionAndHistoryFloor {
            history_access: arkret_sdk::HistoryAccess::SinceJoin,
            stream_floors: Vec::new(),
        },
        created_at: fixture_time(10),
        signature: bundle.genesis_commit.signature,
    };
    FixtureStation::did_web().sign_snapshot(&mut snapshot);
    // These tests exercise reads of an already admitted cut. Signature
    // admission and complete nonempty native chains have separate fold tests.
    store
        .cached
        .verified_sidecar_current
        .insert(REALM.into(), snapshot);
}

#[test]
fn cache_projection_preserves_exact_receive_bytes_without_copying_account_history() {
    use crate::mls::persistence::encrypt_state;
    let (_directory, mut store) = store();
    add_unrelated_history(&mut store);
    store.cached.mls_private_plaintext.insert(
        REALM.into(),
        BTreeMap::from([(
            "strand".into(),
            BTreeMap::from([("body".into(), "author".into())]),
        )]),
    );
    let original = encrypt_state(REALM, "AQID", 1, b"before", "secret", b"salt");
    let advanced = encrypt_state(REALM, "AQID", 2, b"after", "secret", b"salt");
    store
        .cached
        .mls_local_checkpoints
        .insert(REALM.into(), original.clone());
    store.cached.mls_decrypted_plaintext.insert(
        REALM.into(),
        BTreeMap::from([
            ("digest".into(), "before".into()),
            ("base-only".into(), "unchanged".into()),
        ]),
    );
    let link = signed_link();
    {
        let mut overlay = store.lock_mls_receive_overlay();
        overlay.snapshots.insert(REALM.into(), advanced);
        overlay.recovery_snapshots.insert(REALM.into(), original);
        overlay.plaintexts.insert(
            REALM.into(),
            BTreeMap::from([("digest".into(), "after".into())]),
        );
        overlay.identity_links.insert("link".into(), link);
    }
    let effective = store.effective_state_for_persist();
    let expected = serde_json::json!({
        "mls_snapshots": effective.mls_local_checkpoints,
        "private_plaintext": effective.mls_private_plaintext,
        "decrypted_plaintext": effective.mls_decrypted_plaintext,
        "authenticated_identity_links": effective.authenticated_identity_links,
    });
    FULL_STATE_READ_COPIES.with(|count| count.set(0));
    for _ in 0..32 {
        let (_, Some(json)) = store.e2ee_plaintext_cache_secure_write().unwrap().unwrap() else {
            panic!("receive overlay must produce a secure cache entry");
        };
        assert_eq!(serde_json::from_str::<Value>(&json).unwrap(), expected);
        assert_eq!(store.e2ee_plaintext_cache_usage().entry_count(), 3);
    }
    assert_eq!(FULL_STATE_READ_COPIES.with(|count| count.get()), 0);
    assert!(
        !store.lock_mls_receive_overlay().is_empty(),
        "a read must not absorb the receive chain"
    );
}

#[test]
fn identity_link_replay_is_narrow_but_conflicting_authenticated_bytes_still_fail() {
    let (_directory, mut store) = store();
    add_unrelated_history(&mut store);
    let link = signed_link();
    store
        .cache_locally_authenticated_identity_link(link.clone())
        .unwrap();
    FULL_STATE_READ_COPIES.with(|count| count.set(0));
    for _ in 0..100 {
        store
            .cache_locally_authenticated_identity_link(link.clone())
            .unwrap();
        assert_eq!(
            store.locally_authenticated_identity_link(&link.identity_link.realm_id, "AQID", 2, 4,),
            Some(link.clone())
        );
    }
    assert_eq!(FULL_STATE_READ_COPIES.with(|count| count.get()), 0);
    let mut conflicting = link.clone();
    conflicting.winning_group_state_ref =
        arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [72; 32]);
    assert!(
        store
            .cache_locally_authenticated_identity_link(conflicting.clone())
            .is_err()
    );
    store.absorb_mls_receive_overlay();
    assert!(
        store
            .cache_locally_authenticated_identity_link(conflicting)
            .is_err()
    );
    assert_eq!(
        store.locally_authenticated_identity_link(&link.identity_link.realm_id, "AQID", 2, 4,),
        Some(link)
    );
}

#[test]
fn admitted_sidecar_cut_reads_do_not_copy_other_account_history() {
    let (_directory, mut store) = store();
    install_empty_signed_cut(&mut store);
    add_unrelated_history(&mut store);
    let expected = store.cached.verified_sidecar_current[REALM].clone();
    FULL_STATE_READ_COPIES.with(|count| count.set(0));
    for _ in 0..100 {
        let (snapshot, histories) = store.verified_sidecar_inputs(REALM).unwrap();
        assert_eq!(snapshot, expected);
        assert!(histories.is_empty());
    }
    assert_eq!(FULL_STATE_READ_COPIES.with(|count| count.get()), 0);
    store.invalidate_sidecar_current(Some(REALM));
    assert!(store.verified_sidecar_inputs(REALM).is_err());
}

#[test]
fn narrow_projection_reads_follow_active_account_instead_of_a_detached_old_cache() {
    let (_directory, mut store) = store();
    install_empty_signed_cut(&mut store);
    store.cached.server_trust_domain = Some("ak:trust_domain:alice.example".into());
    store.cached.mls_private_plaintext.insert(
        REALM.into(),
        BTreeMap::from([(
            "strand".into(),
            BTreeMap::from([("body".into(), "alice secret".into())]),
        )]),
    );
    store.flush().unwrap();
    let stale = store.clone();
    store.switch_test_account("did:web:bob.example");
    store.cached.server_trust_domain = Some("ak:trust_domain:bob.example".into());
    store.flush().unwrap();
    assert_eq!(
        stale.server_trust_domain().as_deref(),
        Some("ak:trust_domain:bob.example")
    );
    assert!(stale.verified_sidecar_inputs(REALM).is_err());
    let (key, json) = stale.e2ee_plaintext_cache_secure_write().unwrap().unwrap();
    assert_eq!(
        key,
        store
            .e2ee_plaintext_cache_secure_write()
            .unwrap()
            .unwrap()
            .0
    );
    assert!(
        json.is_none(),
        "Alice's old plaintext cannot enter Bob's secure namespace"
    );
    assert_eq!(stale.e2ee_plaintext_cache_usage().entry_count(), 0);
}
