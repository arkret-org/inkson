//! Tests for welcome application, application-payload encrypt / decrypt, and
//! §5.6 receive-chain persistence.

use serde_json::json;

use crate::local_state::isolated_store_for_tests as temp_state_store;
use crate::mls::runtime::*;
use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStoreError};

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn creator_snapshot_bootstrap_makes_space_encryptable() {
    let mut state = temp_state_store("creator-bootstrap");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ck:device:01904100-0000-7000-8000-000000000001";
    let realm = "ck:realm:01904100-0000-7000-8000-000000000001";

    let summary = ensure_creator_mls_snapshot(&mut state, &secure, realm, actor, device).unwrap();

    let summary = summary.expect("missing creator snapshot should be created");
    assert_eq!(summary.realm_id, realm);
    assert_eq!(summary.epoch, 0);
    assert!(state.mls_snapshot_for(realm).is_some());
    // Ordinary application messages ride epoch 0; no commit event or
    // post-commit snapshot is returned.
    let encrypted = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        actor,
        device,
        "application/vnd.cokret.test+json",
        &[br#""private""#.to_vec()],
    )
    .unwrap();
    assert_eq!(encrypted.2.len(), 1);
    assert!(encrypted.3.is_none());
    assert!(encrypted.4.is_none());
    assert_eq!(state.mls_snapshot_for(realm).unwrap().epoch, 0);
    let encrypted_again = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        actor,
        device,
        "application/vnd.cokret.test+json",
        &[br#""private-again""#.to_vec()],
    )
    .unwrap();
    assert_eq!(encrypted_again.2.len(), 1);
    assert!(encrypted_again.3.is_none());
    assert!(encrypted_again.4.is_none());
    assert_eq!(state.mls_snapshot_for(realm).unwrap().epoch, 0);
}

// ── YOU-02-004: receive-chain persistence (§5.6) ─────────────────

/// Build a two-member group: alice (in-memory sender) + bob, whose
/// post-Welcome group state is persisted into `state` under `realm` the
/// same way `apply_welcome_messages_with_device_snapshot` would.
/// Returns alice's live group for minting application messages.
#[cfg(not(target_arch = "wasm32"))]
fn two_member_group_with_bob_snapshot(
    state: &mut crate::local_state::LocalStateStore,
    secure: &MemorySecureKeyStore,
    realm: &str,
    bob_actor: &str,
    bob_device: &str,
) -> cokret_sdk::CokretMlsGroup {
    let alice = cokret_sdk::CokretMlsIdentity::new_basic(
        cokret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap(),
        cokret_sdk::DeviceId::new("ck:device:01904100-0000-7000-8000-0000000000a1".to_owned())
            .unwrap(),
    )
    .unwrap();
    let bob = cokret_sdk::CokretMlsIdentity::new_basic(
        cokret_sdk::Did::new(bob_actor.to_owned()).unwrap(),
        cokret_sdk::DeviceId::new(bob_device.to_owned()).unwrap(),
    )
    .unwrap();
    let bob_key_package = bob.key_package_record().unwrap();
    let mut alice_group = alice.create_group(realm.as_bytes()).unwrap();
    let add = alice_group.add_member(&bob_key_package).unwrap();
    let bob_group = cokret_sdk::CokretMlsGroup::join_from_welcome(bob, &add.welcome).unwrap();

    let secret = load_or_create_device_snapshot_secret(secure, bob_actor, bob_device).unwrap();
    let post_state = bob_group.export_state_record().unwrap();
    let serialized = serde_json::to_vec(&post_state).unwrap();
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).unwrap();
    let envelope = crate::mls::persistence::encrypt_state(
        realm,
        &post_state.group_id,
        post_state.epoch,
        &serialized,
        &secret,
        &salt,
    );
    state.save_mls_snapshot(realm.to_owned(), envelope);
    alice_group
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn receive_chain_persists_across_restart_and_serves_plaintext_cache() {
    // §5.6 MUST: after a successful decrypt the advanced group state is
    // persisted; the same-epoch NEXT message decrypts after a "restart"
    // (fresh store over the same backing file), and the already-decrypted
    // message re-renders from the plaintext cache (its ratchet key was
    // deliberately consumed by the write-back).
    let path = std::env::temp_dir().join(format!(
        "yougen-test-receive-chain-{}.json",
        crate::operation::uuid_v7()
    ));
    let mut state = crate::local_state::LocalStateStore::with_path(path.clone());
    let secure = MemorySecureKeyStore::new();
    let realm = "ck:realm:01904100-0000-7000-8000-0000000000b1";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ck:device:01904100-0000-7000-8000-0000000000b2";

    let mut alice_group =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    let base_envelope = state.mls_snapshot_for(realm).unwrap();

    let m1 = alice_group
        .encrypt_payload("application/json", br#"{"body":"m1"}"#)
        .unwrap();
    let m2 = alice_group
        .encrypt_payload("application/json", br#"{"body":"m2"}"#)
        .unwrap();

    // Decrypt m1: plaintext returned AND the persisted snapshot advanced
    // (same epoch, new ciphertext, observed-message counter bumped).
    let plain1 = decrypt_application_payload(&state, &secure, realm, bob_actor, bob_device, &m1)
        .expect("bob decrypts m1");
    assert_eq!(plain1, br#"{"body":"m1"}"#);
    let advanced = state.mls_snapshot_for(realm).unwrap();
    assert_eq!(advanced.epoch, base_envelope.epoch);
    assert_ne!(advanced.ciphertext_hex, base_envelope.ciphertext_hex);
    assert_eq!(advanced.app_messages_observed, 1);

    // "Restart": a brand-new store over the same backing file must see
    // the advanced receive chain (NOT the pre-decrypt snapshot).
    let restarted = crate::local_state::LocalStateStore::with_path(path.clone());
    let reloaded = restarted.mls_snapshot_for(realm).unwrap();
    assert_eq!(reloaded.ciphertext_hex, advanced.ciphertext_hex);
    // m1 re-renders from the persisted plaintext cache (a ratchet replay
    // would fail — its message key was consumed before the write-back).
    let replay1 =
        decrypt_application_payload(&restarted, &secure, realm, bob_actor, bob_device, &m1)
            .expect("m1 served from the plaintext cache after restart");
    assert_eq!(replay1, br#"{"body":"m1"}"#);
    // m2 (the next generation in the same epoch) decrypts from the
    // persisted advanced chain.
    let plain2 =
        decrypt_application_payload(&restarted, &secure, realm, bob_actor, bob_device, &m2)
            .expect("bob decrypts m2 after restart");
    assert_eq!(plain2, br#"{"body":"m2"}"#);
    assert_eq!(
        restarted
            .mls_snapshot_for(realm)
            .unwrap()
            .app_messages_observed,
        2
    );
    let _ = std::fs::remove_file(path);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn out_of_order_skipped_keys_survive_restart() {
    // §5.6: the persisted state includes the bounded skipped-message-key
    // cache. Bob decrypts m3 first (m1/m2 keys become skipped keys),
    // restarts, then decrypts the earlier m1 — which requires the
    // skipped keys to have been persisted with the advanced chain.
    let path = std::env::temp_dir().join(format!(
        "yougen-test-skipped-keys-{}.json",
        crate::operation::uuid_v7()
    ));
    let mut state = crate::local_state::LocalStateStore::with_path(path.clone());
    let secure = MemorySecureKeyStore::new();
    let realm = "ck:realm:01904100-0000-7000-8000-0000000000c1";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ck:device:01904100-0000-7000-8000-0000000000c2";

    let mut alice_group =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    let m1 = alice_group
        .encrypt_payload("application/json", br#""one""#)
        .unwrap();
    let _m2 = alice_group
        .encrypt_payload("application/json", br#""two""#)
        .unwrap();
    let m3 = alice_group
        .encrypt_payload("application/json", br#""three""#)
        .unwrap();

    // Out-of-order: m3 first (within OpenMLS's default
    // out_of_order_tolerance of 5).
    let plain3 = decrypt_application_payload(&state, &secure, realm, bob_actor, bob_device, &m3)
        .expect("bob decrypts m3 ahead of m1/m2");
    assert_eq!(plain3, br#""three""#);

    // Restart, then decrypt the skipped earlier message.
    let restarted = crate::local_state::LocalStateStore::with_path(path.clone());
    let plain1 =
        decrypt_application_payload(&restarted, &secure, realm, bob_actor, bob_device, &m1)
            .expect("persisted skipped key decrypts m1 after restart");
    assert_eq!(plain1, br#""one""#);
    let _ = std::fs::remove_file(path);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn author_own_ciphertext_stays_soft_failure_without_state_regression() {
    // OpenMLS forbids an author from decrypting their own application
    // message; the receive-chain path must surface that as a soft `None`
    // without polluting the plaintext cache or regressing the snapshot.
    // (The author's own visibility keeps flowing through the existing
    // send-time plaintext sidecar — `mls_private_plaintext`.)
    let mut state = temp_state_store("own-ciphertext-soft-fail");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ck:device:01904100-0000-7000-8000-0000000000d1";
    let realm = "ck:realm:01904100-0000-7000-8000-0000000000d2";

    ensure_creator_mls_snapshot(&mut state, &secure, realm, actor, device).unwrap();
    let (_, _, encrypted_values, ..) = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        actor,
        device,
        "application/json",
        &[br#""mine""#.to_vec()],
    )
    .unwrap();
    let payload: cokret_sdk::EncryptedPayload =
        serde_json::from_value(encrypted_values[0].clone()).unwrap();
    let after_send = state.mls_snapshot_for(realm).unwrap();

    let decrypted = decrypt_application_payload(&state, &secure, realm, actor, device, &payload);
    assert!(decrypted.is_none(), "author must not decrypt own message");
    // No cache entry and no snapshot churn from the failed attempt.
    assert!(
        state
            .mls_decrypted_plaintext_for(realm, payload.payload_digest.as_str())
            .is_none()
    );
    assert_eq!(
        state.mls_snapshot_for(realm).unwrap().ciphertext_hex,
        after_send.ciphertext_hex
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn plaintext_cache_outlives_group_state() {
    // Once decrypted, a message stays renderable from the cache even if
    // the MLS snapshot is later dropped (e.g. leave/rotate) — the cache,
    // not a ratchet replay, is the §5.6-compliant re-render path.
    let mut state = temp_state_store("plaintext-cache-outlives");
    let secure = MemorySecureKeyStore::new();
    let realm = "ck:realm:01904100-0000-7000-8000-0000000000e1";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ck:device:01904100-0000-7000-8000-0000000000e2";

    let mut alice_group =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    let m1 = alice_group
        .encrypt_payload("application/json", br#""cached""#)
        .unwrap();
    let first = decrypt_application_payload(&state, &secure, realm, bob_actor, bob_device, &m1)
        .expect("first decrypt");
    assert_eq!(first, br#""cached""#);

    state.drop_mls_snapshot(realm);
    assert!(state.mls_snapshot_for(realm).is_none());
    let cached = decrypt_application_payload(&state, &secure, realm, bob_actor, bob_device, &m1)
        .expect("cache hit requires no group state");
    assert_eq!(cached, br#""cached""#);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_write_with_snapshot_requires_existing_device_secret() {
    let mut state = temp_state_store("missing-secret");
    let store = MemorySecureKeyStore::new();
    let envelope = crate::mls::persistence::encrypt_state(
        "ck:realm:01904100-0000-7000-8000-000000000001",
        "group-for-missing-secret-test",
        1,
        b"not-a-real-group-state",
        "other-device-secret",
        b"deterministic-salt",
    );
    state.save_mls_snapshot("ck:realm:01904100-0000-7000-8000-000000000001", envelope);

    let error = encrypt_values_with_device_snapshot(
        &mut state,
        &store,
        "ck:realm:01904100-0000-7000-8000-000000000001",
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-000000000001",
        "text/plain",
        &[b"secret".to_vec()],
    )
    .unwrap_err();

    assert!(matches!(
        error,
        MlsRuntimeError::DeviceSecret(SecureKeyStoreError::NotFound)
    ));
    assert!(store.is_empty());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_write_uses_device_key_snapshot_when_ready() {
    use cokret_sdk::{CokretMlsIdentity, DeviceId, Did};

    let actor = "did:web:alice.example";
    let device = "ck:device:01904100-0000-7000-8000-000000000001";
    let realm = "ck:realm:01904100-0000-7000-8000-000000000003";
    let store = MemorySecureKeyStore::new();
    let secret = load_or_create_device_snapshot_secret(&store, actor, device).unwrap();
    let identity = CokretMlsIdentity::new_basic(
        Did::new(actor.to_owned()).unwrap(),
        DeviceId::new(device.to_owned()).unwrap(),
    )
    .unwrap();
    let group = identity.create_group(realm.as_bytes()).unwrap();
    let record = group.export_state_record().unwrap();
    let bytes = serde_json::to_vec(&record).unwrap();
    let envelope = crate::mls::persistence::encrypt_state(
        realm,
        &record.group_id,
        record.epoch,
        &bytes,
        &secret,
        b"deterministic-salt",
    );
    let mut state = temp_state_store("ready-encrypt");
    state.save_mls_snapshot(realm, envelope);

    let (_schedule_hash, member_dids, encrypted_values, _commit, _new_envelope) =
        encrypt_values_with_device_snapshot(
            &mut state,
            &store,
            realm,
            actor,
            device,
            "text/plain",
            &[b"secret".to_vec()],
        )
        .unwrap();

    assert_eq!(member_dids.len(), 1);
    assert_eq!(encrypted_values.len(), 1);
    assert!(encrypted_values[0].get("ciphertext").is_some());
    assert!(state.mls_snapshot_for(realm).is_some());
}

/// X14 — persist-on-accept contract for forced commits: the stored snapshot
/// epoch only moves when the caller saves the returned envelope (which it
/// does ONLY after the server accepts the `ck.mls.commit`). This is the
/// invariant that keeps `snapshot.epoch == server.epoch` in lockstep and
/// prevents the permanent `mls_epoch_skew` that optimistic pre-accept
/// persistence caused.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypt_does_not_persist_snapshot_until_caller_saves_on_accept() {
    let actor = "did:web:alice.example";
    let device = "ck:device:01904100-0000-7000-8000-000000000001";
    let secure = MemorySecureKeyStore::new();
    let _ = load_or_create_device_snapshot_secret(&secure, actor, device).unwrap();
    let mut state = temp_state_store("persist-on-accept");
    let realm = "ck:realm:01904100-0000-7000-8000-000000000099";

    state.save_realm_tree_projection(
        realm,
        json!({ "active_profiles": [cokret_sdk::mls::MINIMAL_METADATA_REALM_PROFILE] }),
    );
    assert!(state.realm_projection_is_minimal_metadata(realm));

    // Genesis installs the epoch-0 snapshot.
    ensure_creator_mls_snapshot(&mut state, &secure, realm, actor, device)
        .unwrap()
        .expect("creator snapshot created");
    let epoch_before = state.mls_snapshot_for(realm).unwrap().epoch;
    let mut overdue = state.mls_snapshot_for(realm).unwrap();
    overdue.epoch_started_at = chrono::Utc::now() - chrono::Duration::hours(2);
    state.save_mls_snapshot(realm, overdue);

    // An overdue minimal-metadata epoch forces a post-commit envelope at
    // epoch+1 WITHOUT touching the persisted snapshot.
    let result = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        actor,
        device,
        "application/vnd.cokret.test+json",
        &[br#""private""#.to_vec()],
    )
    .unwrap();
    assert!(result.3.is_some());
    let post_commit_envelope = result.4.expect("forced commit returns snapshot");
    assert_eq!(
        state.mls_snapshot_for(realm).unwrap().epoch,
        epoch_before,
        "encrypt must NOT advance the persisted snapshot (persist-on-accept)"
    );
    assert!(
        post_commit_envelope.epoch > epoch_before,
        "returned envelope carries the post-commit (advanced) epoch"
    );

    // The caller saving the returned envelope (simulating server-accept)
    // is what advances the persisted snapshot.
    state.save_mls_snapshot(realm, post_commit_envelope.clone());
    assert_eq!(
        state.mls_snapshot_for(realm).unwrap().epoch,
        post_commit_envelope.epoch
    );
}

#[test]
fn empty_welcome_set_reports_no_work() {
    let mut state = temp_state_store("empty");
    let store = MemorySecureKeyStore::new();
    let outcome = apply_welcome_messages_with_device_snapshot(
        &mut state,
        &store,
        "ck:realm:empty",
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-000000000001",
        &json!({ "messages": [] }),
    )
    .unwrap();
    assert_eq!(outcome, WelcomeApplyOutcome::default());
    assert_eq!(outcome.applied, 0);
    assert_eq!(outcome.failed, 0);
    assert!(outcome.first_error.is_none());
    // No welcomes present => no secret was created either.
    assert!(store.is_empty());
}

#[test]
fn malformed_welcome_is_counted_not_swallowed() {
    let mut state = temp_state_store("malformed");
    let store = MemorySecureKeyStore::new();
    // A welcome entry whose content is not a valid MlsWelcomeEnvelope.
    let messages = json!({
        "messages": [
            { "kind": "ck.mls.welcome", "content": { "not": "a welcome" } }
        ]
    });
    let outcome = apply_welcome_messages_with_device_snapshot(
        &mut state,
        &store,
        "ck:realm:malformed",
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-000000000001",
        &messages,
    )
    .unwrap();
    assert_eq!(outcome.applied, 0);
    assert_eq!(outcome.failed, 1);
    assert!(outcome.first_error.is_some());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn welcome_apply_uses_key_package_identity_state() {
    let mut state = temp_state_store("welcome-keypackage-state");
    let store = MemorySecureKeyStore::new();
    let realm = "ck:realm:01904100-0000-7000-8000-0000000000c1";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ck:device:01904100-0000-7000-8000-0000000000c2";
    let alice = cokret_sdk::CokretMlsIdentity::new_basic(
        cokret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap(),
        cokret_sdk::DeviceId::new("ck:device:01904100-0000-7000-8000-0000000000a1".to_owned())
            .unwrap(),
    )
    .unwrap();
    let bob = cokret_sdk::CokretMlsIdentity::new_basic(
        cokret_sdk::Did::new(bob_actor.to_owned()).unwrap(),
        cokret_sdk::DeviceId::new(bob_device.to_owned()).unwrap(),
    )
    .unwrap();
    let bob_key_package = bob.key_package_record().unwrap();
    let bob_private_state = bob.export_private_state().unwrap();
    store_mls_key_package_identity_state(
        &store,
        bob_actor,
        bob_device,
        &bob_key_package.keypackage_id,
        &bob_private_state,
    )
    .unwrap();
    let mut alice_group = alice.create_group(realm.as_bytes()).unwrap();
    let add = alice_group.add_member(&bob_key_package).unwrap();
    let messages = json!({
        "messages": [
            {
                "kind": "ck.mls.welcome",
                "content": serde_json::to_value(&add.welcome).unwrap(),
                "unsigned": {
                    "key_package_id": bob_key_package.keypackage_id.clone(),
                },
            }
        ]
    });

    let outcome = apply_welcome_messages_with_device_snapshot(
        &mut state, &store, realm, bob_actor, bob_device, &messages,
    )
    .unwrap();

    assert_eq!(outcome.applied, 1);
    assert_eq!(outcome.failed, 0);
    assert!(state.mls_snapshot_for(realm).is_some());
    assert!(
        load_mls_key_package_identity_state(
            &store,
            bob_actor,
            bob_device,
            &bob_key_package.keypackage_id,
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn durable_welcome_payload_without_claim_envelope_fails_closed() {
    let mut state = temp_state_store("welcome-claim-envelope");
    let store = MemorySecureKeyStore::new();
    let messages = json!({
        "messages": [
            {
                "kind": "ck.mls.welcome",
                "content": {
                    "mls_group_id": "mls-group-a",
                    "epoch": 1,
                    "recipient_principal_id": "did:web:alice.example",
                    "recipient_device_id": "ck:device:01904100-0000-7000-8000-000000000001",
                    "keypackage_ref": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                    "keypackage_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "claim_id": "claim-1",
                    "claim_ref": {
                        "claim_id": "claim-1",
                        "keypackage_ref": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                        "keypackage_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "capabilities_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "ssk_generation": 1
                    },
                    "ciphertext": "AQID",
                    "expires_at": "2100-01-01T00:00:00Z"
                }
            }
        ]
    });
    let outcome = apply_welcome_messages_with_device_snapshot(
        &mut state,
        &store,
        "ck:realm:welcome-claim-envelope",
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-000000000001",
        &messages,
    )
    .unwrap();
    assert_eq!(outcome.applied, 0);
    assert_eq!(outcome.failed, 1);
    assert!(
        outcome
            .first_error
            .as_deref()
            .unwrap_or_default()
            .contains(cokret_sdk::error::REASON_KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)
    );
}

#[test]
fn local_welcome_hint_filters_by_realm_group_id() {
    let realm = "ck:realm:01904100-0000-7000-8000-000000000001";
    let other_realm = "ck:realm:01904100-0000-7000-8000-000000000002";
    let messages = vec![
        json!({
            "kind": "ck.mls.welcome",
            "content": {
                "group_id": mls_group_id_for_realm(realm),
                "welcome_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
            "unsigned": {
                "mls_welcome_id": "ck:mls_welcome:01904100-0000-7000-8000-0000000000aa",
            },
        }),
        json!({
            "kind": "ck.mls.welcome",
            "content": {
                "group_id": mls_group_id_for_realm(other_realm),
                "welcome_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            },
        }),
        json!({
            "kind": "ck.key.verification.request",
            "content": {
                "group_id": mls_group_id_for_realm(realm),
            },
        }),
    ];

    assert_eq!(
        collect_mls_welcome_messages_for_realm(&messages, realm).len(),
        1
    );
    assert_eq!(
        local_mls_welcome_hint_for_realm(&messages, realm),
        "1:ck:mls_welcome:01904100-0000-7000-8000-0000000000aa"
    );
    assert_eq!(
        local_mls_welcome_hint_for_realm(&messages, other_realm),
        "1:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
}
