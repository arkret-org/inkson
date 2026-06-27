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

// ── History sharing (encryption-and-audit.md): provider push +
//    receiver ingest + tier-3 history decrypt ──────────────────────

/// Build a `ck.realm_key.share` envelope sealing `secrets` to `recipient_pub`,
/// as the provider's `build_realm_key_share_event` would emit it on the wire
/// (the `content` is the `RealmKeySharePayload`).
#[cfg(not(target_arch = "wasm32"))]
fn realm_key_share_envelope(
    realm: &str,
    recipient_actor: &str,
    recipient_device: &str,
    sender_device: &str,
    recipient_pub: &[u8],
    secrets: &[(u64, Vec<u8>)],
) -> serde_json::Value {
    let sealed =
        cokret_sdk::secret_share::seal_history_secret_to_device_pubkey(recipient_pub, secrets)
            .unwrap();
    let (lo, hi) = secrets.iter().fold((u64::MAX, 0_u64), |(lo, hi), (e, _)| {
        (lo.min(*e), hi.max(*e))
    });
    let event = crate::mls::admission::build_realm_key_share_event(
        realm,
        "did:web:alice.example",
        sender_device,
        recipient_actor,
        recipient_device,
        lo,
        hi,
        sealed,
    )
    .unwrap();
    json!({
        "kind": event.kind.as_str(),
        "content": event.content,
    })
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn ingest_realm_key_share_installs_history_secrets() {
    // A provider seals two epochs' history secrets to bob's device HPKE public
    // key; bob ingests the share and both secrets land in local state.
    let mut state = temp_state_store("history-share-ingest");
    let secure = MemorySecureKeyStore::new();
    let realm = "ck:realm:01904100-0000-7000-8000-0000000000e1";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ck:device:01904100-0000-7000-8000-0000000000e2";
    let alice_device = "ck:device:01904100-0000-7000-8000-0000000000a1";

    let (_priv, bob_pub) =
        load_or_create_device_hpke_keypair(&secure, bob_actor, bob_device).unwrap();
    let secrets = vec![(3_u64, vec![3u8; 32]), (4_u64, vec![4u8; 32])];
    let share = realm_key_share_envelope(
        realm,
        bob_actor,
        bob_device,
        alice_device,
        &bob_pub,
        &secrets,
    );

    // Routing filter accepts the share for this realm.
    let matched = collect_realm_key_share_messages_for_realm(&[share.clone()], realm);
    assert_eq!(matched.len(), 1);

    let installed =
        ingest_realm_key_share(&mut state, &secure, realm, bob_actor, bob_device, &share);
    assert_eq!(installed, 2);
    assert_eq!(state.history_secret_for(realm, 3), Some(vec![3u8; 32]));
    assert_eq!(state.history_secret_for(realm, 4), Some(vec![4u8; 32]));
    assert_eq!(state.history_secrets_for(realm).len(), 2);

    // A share addressed to a different device installs nothing.
    let other = "ck:device:01904100-0000-7000-8000-0000000000ff";
    let foreign =
        realm_key_share_envelope(realm, bob_actor, other, alice_device, &bob_pub, &secrets);
    assert_eq!(
        ingest_realm_key_share(&mut state, &secure, realm, bob_actor, bob_device, &foreign),
        0
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn history_secrets_survive_json_persistence_round_trip() {
    // The store flushes to JSON; a granted history_secret must survive a
    // "restart" (fresh store over the same backing file). Regression guard for
    // the map key type — `serde_json` cannot serialize a non-string map key, so
    // this would fail loudly if `history_secrets` reverted to a tuple key.
    let path = std::env::temp_dir().join(format!(
        "yougen-test-history-secret-persist-{}.json",
        crate::operation::uuid_v7()
    ));
    let realm = "ck:realm:01904100-0000-7000-8000-0000000000d9";
    {
        let mut state = crate::local_state::LocalStateStore::with_path(path.clone());
        state.save_history_secret(realm.to_owned(), 7, vec![9u8; 32]);
        state.save_history_secret(realm.to_owned(), 8, vec![8u8; 32]);
        assert!(
            state.persist_error().is_none(),
            "history secrets must persist"
        );
    }
    let restarted = crate::local_state::LocalStateStore::with_path(path.clone());
    assert_eq!(restarted.history_secret_for(realm, 7), Some(vec![9u8; 32]));
    assert_eq!(restarted.history_secrets_for(realm).len(), 2);
    let _ = std::fs::remove_file(path);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn tier3_history_decrypt_reads_provider_exporter_aead_content() {
    // End-to-end tier-3: the provider (alice) encrypts content under the
    // `mls-exporter-aead-v1` scheme and shares the epoch's `history_secret`;
    // bob installs it and `decrypt_application_payload` opens the pre-join
    // content the live receive ratchet cannot.
    let mut state = temp_state_store("history-share-tier3");
    let secure = MemorySecureKeyStore::new();
    let realm = "ck:realm:01904100-0000-7000-8000-0000000000f1";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ck:device:01904100-0000-7000-8000-0000000000f2";
    let alice_device = "ck:device:01904100-0000-7000-8000-0000000000a1";

    // Bob holds a join-epoch snapshot (so `decrypt_application_payload` can
    // instantiate a group), but cannot ratchet to alice's exporter-aead content.
    let mut alice_group =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    let epoch = alice_group.epoch();

    // Provider encrypts content via exporter-aead, binding the shared
    // `history_content_aad_bytes(realm, epoch)` AAD (constraint ①), and exports
    // the epoch's history secret.
    let aad_bytes = history_content_aad_bytes(realm, epoch);
    let plaintext = br#"{"body":"pre-join history"}"#;
    let nonce_and_ct = alice_group
        .encrypt_content_exporter_aead(realm, &aad_bytes, plaintext)
        .unwrap();
    let history_secret = alice_group
        .export_history_secret_range(epoch, epoch)
        .into_iter()
        .find(|(e, _)| *e == epoch)
        .map(|(_, secret)| secret)
        .expect("retained history secret for the current epoch");

    // Wrap the exporter-aead blob as the `EncryptedPayload` a content event
    // would carry (epoch + base64url(nonce||ct)).
    let payload = cokret_sdk::EncryptedPayload {
        scheme: cokret_sdk::EncryptedPayloadScheme::MlsRfc9420,
        group_id: mls_group_id_for_realm(realm),
        epoch,
        content_type: "application/json".to_owned(),
        ciphertext: cokret_sdk::base64url_encode(&nonce_and_ct),
        aad: None,
        payload_digest: cokret_sdk::Hash::new(cokret_sdk::canonical::sha256_digest(&nonce_and_ct))
            .unwrap(),
        key_ref: None,
    };

    // Before the share: bob cannot decrypt (no history secret; live ratchet
    // cannot open exporter-aead content).
    assert!(
        decrypt_application_payload(&state, &secure, realm, bob_actor, bob_device, &payload)
            .is_none(),
        "bob must not read pre-join content before the share lands"
    );

    // Provider seals + bob ingests the share.
    let (_priv, bob_pub) =
        load_or_create_device_hpke_keypair(&secure, bob_actor, bob_device).unwrap();
    let share = realm_key_share_envelope(
        realm,
        bob_actor,
        bob_device,
        alice_device,
        &bob_pub,
        &[(epoch, history_secret)],
    );
    assert_eq!(
        ingest_realm_key_share(&mut state, &secure, realm, bob_actor, bob_device, &share),
        1
    );

    // After the share: tier-3 history decrypt reads the content.
    let decrypted =
        decrypt_application_payload(&state, &secure, realm, bob_actor, bob_device, &payload)
            .expect("tier-3 history decrypt opens pre-join content");
    assert_eq!(decrypted, plaintext);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn tier3_history_decrypt_works_without_local_snapshot() {
    // Group-free tier-3: a member granted a `history_secret` but holding NO
    // local MLS snapshot for the Realm (e.g. granted before processing its own
    // Welcome) still reads pre-join exporter-aead content via the standalone
    // SDK path. Regression guard for the "must have a snapshot first" relaxation.
    let mut state = temp_state_store("history-share-no-snapshot");
    let secure = MemorySecureKeyStore::new();
    let realm = "ck:realm:01904100-0000-7000-8000-0000000000f3";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ck:device:01904100-0000-7000-8000-0000000000f4";

    // Build alice's group WITHOUT persisting any snapshot into `state`.
    let alice = cokret_sdk::CokretMlsIdentity::new_basic(
        cokret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap(),
        cokret_sdk::DeviceId::new("ck:device:01904100-0000-7000-8000-0000000000a1".to_owned())
            .unwrap(),
    )
    .unwrap();
    let mut alice_group = alice.create_group(realm.as_bytes()).unwrap();
    let epoch = alice_group.epoch();

    let aad_bytes = history_content_aad_bytes(realm, epoch);
    let plaintext = br#"{"body":"no-snapshot history"}"#;
    let nonce_and_ct = alice_group
        .encrypt_content_exporter_aead(realm, &aad_bytes, plaintext)
        .unwrap();
    let history_secret = alice_group
        .export_history_secret_range(epoch, epoch)
        .into_iter()
        .find(|(e, _)| *e == epoch)
        .map(|(_, secret)| secret)
        .expect("retained history secret for the current epoch");

    let payload = cokret_sdk::EncryptedPayload {
        scheme: cokret_sdk::EncryptedPayloadScheme::MlsRfc9420,
        group_id: mls_group_id_for_realm(realm),
        epoch,
        content_type: "application/json".to_owned(),
        ciphertext: cokret_sdk::base64url_encode(&nonce_and_ct),
        aad: None,
        payload_digest: cokret_sdk::Hash::new(cokret_sdk::canonical::sha256_digest(&nonce_and_ct))
            .unwrap(),
        key_ref: None,
    };

    // No snapshot for the realm: the live-ratchet path cannot even instantiate
    // a group, but the granted history secret still opens the content.
    assert!(state.mls_snapshot_for(realm).is_none());
    assert!(
        decrypt_application_payload(&state, &secure, realm, bob_actor, bob_device, &payload)
            .is_none(),
        "without the granted secret there is nothing to decrypt"
    );

    state.save_history_secret(realm.to_owned(), epoch, history_secret);
    let decrypted =
        decrypt_application_payload(&state, &secure, realm, bob_actor, bob_device, &payload)
            .expect("group-free tier-3 decrypt opens content with no local snapshot");
    assert_eq!(decrypted, plaintext);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn realm_key_share_sender_signature_round_trips() {
    // Provider signs `sender_signing_input()` with the active Ed25519 device
    // signer; the receiver verifies it. A tampered body, a wrong key, or a
    // missing signature are each handled as specified (reject on bad signature,
    // tolerate an absent one).
    use ed25519_dalek::SigningKey;

    let _signer_guard = {
        let seed = [42u8; 32];
        let verifying = SigningKey::from_bytes(&seed).verifying_key();
        let did = crate::did_key::did_key_from_verifying_key(&verifying);
        let signer = std::sync::Arc::new(crate::event_signer::build_ed25519_signer(seed, did));
        crate::event_signer::replace_active_signer(Some(signer));
        // Restore the global signer slot when the test ends.
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                crate::event_signer::replace_active_signer(None);
            }
        }
        Restore
    };

    let realm = "ck:realm:01904100-0000-7000-8000-0000000000f5";
    let recipient_actor = "did:web:bob.example";
    let recipient_device = "ck:device:01904100-0000-7000-8000-0000000000f6";
    let sender_device = "ck:device:01904100-0000-7000-8000-0000000000a1";

    let event = crate::mls::admission::build_realm_key_share_event(
        realm,
        "did:web:alice.example",
        sender_device,
        recipient_actor,
        recipient_device,
        3,
        4,
        "c2VhbGVk".to_owned(),
    )
    .unwrap();
    let payload: cokret_sdk::RealmKeySharePayload =
        serde_json::from_value(event.content.clone()).unwrap();

    // A real signature object was attached, and it verifies.
    assert!(
        payload
            .sender_device_signature
            .get("signature")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "an active signer must attach a real sender_device_signature"
    );
    // SEC-02: with no cached directory record (None sender principal → Miss),
    // verification falls back to the self-asserted embedded key.
    assert!(verify_realm_key_share_sender_signature(&payload, None));

    // Tamper with the covered body → signature must no longer verify.
    let mut tampered = payload.clone();
    tampered.ciphertext = Some("dGFtcGVyZWQ".to_owned());
    assert!(!verify_realm_key_share_sender_signature(&tampered, None));

    // An empty signature object is tolerated on the Miss path (HPKE seal gates).
    let mut unsigned = payload.clone();
    unsigned.sender_device_signature = json!({});
    assert!(verify_realm_key_share_sender_signature(&unsigned, None));
}
