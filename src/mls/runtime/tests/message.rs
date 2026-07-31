//! Tests for welcome application, application-payload encrypt / decrypt, and
//! §5.6 receive-chain persistence.

use serde_json::json;

use crate::mls::runtime::*;
use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStoreError};
use crate::state::isolated_store_for_tests as temp_state_store;

#[cfg(not(target_arch = "wasm32"))]
fn seed_complete_rfc9420_projection(
    state: &mut crate::state::LocalStateStore,
    realm: &str,
    actor: &str,
) {
    state.save_realm_tree_projection(
        realm,
        json!({
            "content_scheme": "mls_rfc9420",
            "members_limited": false,
            "members": [{ "actor_id": actor, "membership": "join" }]
        }),
    );
}

#[cfg(not(target_arch = "wasm32"))]
fn seed_history_share_policy_projection(state: &mut crate::state::LocalStateStore, realm: &str) {
    state.save_realm_tree_projection(
        realm,
        json!({
            "state": {"events": [{
                "event_id": "ak:event:01904100-0000-7000-8000-0000000000e7",
                "kind": "ak.realm.history_sharing_policy",
                "payload": {
                    "allowed_key_sources": ["verified_member_device"],
                    "allowed_receiver_states": ["active_member"]
                }
            }]}
        }),
    );
}

#[cfg(not(target_arch = "wasm32"))]
async fn commit_pending_history(
    state: &mut crate::state::LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    pending_writes: Vec<crate::state::PendingHistorySecrets>,
) -> usize {
    let mut committed = 0;
    for pending in pending_writes {
        pending.persist(secure_store).await.unwrap();
        committed += pending.new_secret_count();
        state.publish_history_secrets(pending);
    }
    committed
}

#[cfg(not(target_arch = "wasm32"))]
struct ActiveSignerGuard {
    _guard: crate::event_signer::ActiveSignerTestGuard,
}

#[cfg(not(target_arch = "wasm32"))]
impl ActiveSignerGuard {
    fn install(seed: [u8; 32], signer_did: &str) -> Self {
        let signer =
            std::sync::Arc::new(crate::event_signer::build_ed25519_signer(seed, signer_did));
        Self {
            _guard: crate::event_signer::ActiveSignerTestGuard::replace(Some(signer)),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn creator_snapshot_bootstrap_makes_space_encryptable() {
    let mut state = temp_state_store("creator-bootstrap");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:01904100-0000-7000-8000-000000000001";

    super::seed_genesis_governance_proof(&mut state, realm);
    state.save_realm_tree_projection(
        realm,
        json!({
            "content_scheme": "mls_rfc9420",
            "members_limited": false,
            "members": [{ "actor_id": actor, "membership": "join" }]
        }),
    );
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
        "application/vnd.arkret.test+json",
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
        "application/vnd.arkret.test+json",
        &[br#""private-again""#.to_vec()],
    )
    .unwrap();
    assert_eq!(encrypted_again.2.len(), 1);
    assert!(encrypted_again.3.is_none());
    assert!(encrypted_again.4.is_none());
    assert_eq!(state.mls_snapshot_for(realm).unwrap().epoch, 0);
}

/// Sidecar exchange binding transport (`zh/models/sidecar.md` §7.2.1): the
/// optional `encrypted_metadata` plaintext is encrypted as a SECOND
/// application message on the same restored group session, riding the same
/// epoch as the content payload (never a separate restore, which would fork
/// the ratchet or double-commit).
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn message_encrypt_carries_metadata_plaintext_on_the_same_epoch() {
    let mut state = temp_state_store("metadata-same-epoch");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:01904100-0000-7000-8000-00000000feed";

    super::seed_genesis_governance_proof(&mut state, realm);
    seed_complete_rfc9420_projection(&mut state, realm, actor);
    ensure_creator_mls_snapshot(&mut state, &secure, realm, actor, device)
        .unwrap()
        .expect("creator snapshot");

    let aad = arkret_sdk::EncryptedEnvelopeAad::hidden(
        arkret_sdk::RealmId::new(realm).unwrap(),
        "ak.message.create",
    );
    let (_, _, content_payload, metadata_payload, commit, snapshot, _, mention_routing_key) =
        encrypt_message_with_device_snapshot(
            &mut state,
            &secure,
            realm,
            actor,
            device,
            "application/vnd.arkret.message+json",
            aad,
            br#"{"kind":"ak.content.text","body":"routed"}"#,
            Some(br#"{"sidecar_exchange_binding":{}}"#.as_slice()),
            None,
            None,
        )
        .unwrap();
    let metadata_payload = metadata_payload.expect("metadata ciphertext");
    assert_eq!(metadata_payload.epoch, content_payload.epoch);
    assert_ne!(
        metadata_payload.payload_digest,
        content_payload.payload_digest
    );
    assert!(commit.is_none());
    assert!(snapshot.is_none());
    // This Realm's projection declares no `mention_routing_hint`, so §4.5
    // fails closed and the encrypt surfaces no routing key to attach.
    assert!(mention_routing_key.is_none());
    // Both application messages advanced the §5.6 observed counter.
    assert_eq!(
        state.mls_snapshot_for(realm).unwrap().app_messages_observed,
        2
    );
}

/// client-sync.md §8.1: once a complete roster hint exposes a mismatch with
/// the local MLS group, sending pauses conservatively until admission
/// converges. This is the exact regression that produced an epoch-0 message
/// after the add-member commit had already advanced the Realm to epoch 1.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_write_blocks_complete_roster_ahead_of_local_group() {
    let mut state = temp_state_store("send-pause-membership-ahead");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:01904100-0000-7000-8000-0000000000f8";

    super::seed_genesis_governance_proof(&mut state, realm);
    ensure_creator_mls_snapshot(&mut state, &secure, realm, actor, device)
        .unwrap()
        .expect("creator snapshot");
    state.save_realm_tree_projection(
        realm,
        json!({
            "encrypted": true,
            "members_limited": false,
            "members": [
                { "actor_id": actor, "membership": "join" },
                { "actor_id": "did:web:bob.example", "membership": "join" }
            ]
        }),
    );

    let error = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        actor,
        device,
        "application/vnd.arkret.test+json",
        &[br#""must-not-send-on-epoch-zero""#.to_vec()],
    )
    .unwrap_err();

    assert!(matches!(
        error,
        MlsRuntimeError::EncryptionTransitionPending
    ));
    assert_eq!(state.mls_snapshot_for(realm).unwrap().epoch, 0);
}

/// A roster-only account-sync frame can arrive before the Realm's create /
/// policy-components state. It must not make the wire scheme depend on timing.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_write_blocks_until_content_scheme_projection_arrives() {
    let mut state = temp_state_store("send-pause-policy-pending");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:01904100-0000-7000-8000-0000000000f9";

    super::seed_genesis_governance_proof(&mut state, realm);
    ensure_creator_mls_snapshot(&mut state, &secure, realm, actor, device)
        .unwrap()
        .expect("creator snapshot");
    state.save_realm_tree_projection(
        realm,
        json!({
            "encrypted": true,
            "members_limited": false,
            "members": [{ "actor_id": actor, "membership": "join" }]
        }),
    );

    let error = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        actor,
        device,
        "application/vnd.arkret.test+json",
        &[br#""must-wait-for-policy""#.to_vec()],
    )
    .unwrap_err();

    assert!(matches!(error, MlsRuntimeError::EncryptionPolicyPending));
    assert_eq!(state.mls_snapshot_for(realm).unwrap().epoch, 0);
}

/// §2.10 history sharing: authoring `mls_exporter_aead_v1` content MUST retain
/// the authoring epoch's `history_secret` locally. The author never decrypts
/// its own ciphertext, so if the encrypt path does not retain here, the secret
/// is lost once the epoch advances (forward secrecy) and
/// `share_history_to_requester` has nothing to seal for a late joiner —
/// permanently locking every pre-join card. See `encrypt_values_with_device_snapshot`.
#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn authoring_exporter_aead_content_retains_history_secret() {
    let mut state = temp_state_store("author-retains-history-secret");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    // history_secret persistence is a PROCESS-GLOBAL secure store keyed only by
    // realm_id (see `prepare_history_secrets` → `PendingHistorySecrets::persist`), so
    // this test MUST use a realm id no other test writes, or the `is_none()`
    // precondition below would observe another test's retained secret.
    let realm = "ak:realm:01904100-0000-7000-8000-0000000000f7";
    let history_store = crate::secure_key_store::default_secure_key_store("inkson");
    let history_key = crate::secure_key_store::mls_history_secret_store_key(realm);
    let _ = history_store.delete_secret(&history_key);

    super::seed_genesis_governance_proof(&mut state, realm);
    ensure_creator_mls_snapshot(&mut state, &secure, realm, actor, device)
        .unwrap()
        .expect("creator snapshot");
    // Use the same optimistic projection written immediately after Realm
    // creation. Account sync may not have delivered the authoritative
    // projection before the first content write, so this local shape must
    // carry the scheme all the way into encryption dispatch.
    let optimistic = crate::realm_tree::OptimisticRealmTreeProjection::realm(
        crate::realm_tree::RealmProjectionInput {
            owner: actor.to_owned(),
            admins: vec![actor.to_owned()],
            members: vec![actor.to_owned()],
            title: "Shared history".to_owned(),
            summary: String::new(),
            discoverability: "restricted".to_owned(),
            encryption_profile: "mls_rfc9420".to_owned(),
            content_scheme: "mls_exporter_aead_v1".to_owned(),
            history_visibility: "shared".to_owned(),
            plaintext_visible_services: Vec::new(),
            collaboration_role: None,
            encryption_floor: Some("e2ee_required".to_owned()),
        },
    )
    .into_value();
    state.save_realm_tree_projection(realm, optimistic);
    // Reproduce the account catch-up race: the next full frame can predate
    // the newly accepted Realm. Reconcile must retain its optimistic body
    // until the authoritative Realm projection arrives.
    let keep = crate::realm_tree::full_sync_projection_keep_set(
        &std::collections::BTreeSet::from(["ak:realm:control".to_owned()]),
        &state.load().realm_tree_projections,
    );
    state.retain_realm_tree_projections(|id| keep.contains(id));
    assert!(realm_content_scheme_is_exporter_aead(&state, realm));

    // No secret is retained before any content is authored.
    assert!(state.history_secret_for(realm, 0).is_none());

    let encrypted = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        actor,
        device,
        "application/vnd.arkret.test+json",
        &[br#""private""#.to_vec()],
    )
    .unwrap();
    let pending = encrypted
        .5
        .expect("exporter-aead authoring must prepare history secret");
    assert_eq!(
        encrypted.2[0]["scheme"],
        serde_json::Value::String("mls_exporter_aead_v1".to_owned())
    );
    pending.persist(&secure).await.unwrap();
    state.publish_history_secrets(pending);

    // The epoch-0 history_secret is now retained and non-empty, so it can be
    // sealed into a later ak.realm_key.share for a late joiner.
    let retained = state
        .history_secret_for(realm, 0)
        .expect("authoring exporter-aead content must retain the epoch history_secret");
    assert!(!retained.is_empty());
    let _ = history_store.delete_secret(&history_key);
}

// ── YOU-02-004: receive-chain persistence (§5.6) ─────────────────

/// Build a two-member group: alice (in-memory sender) + bob, whose
/// post-Welcome group state is persisted into `state` under `realm` the
/// same way `apply_welcome_messages_with_device_snapshot` would.
/// Returns alice's live group for minting application messages.
#[cfg(not(target_arch = "wasm32"))]
fn two_member_group_with_bob_snapshot(
    state: &mut crate::state::LocalStateStore,
    secure: &MemorySecureKeyStore,
    realm: &str,
    bob_actor: &str,
    bob_device: &str,
) -> arkret_sdk::ArkretMlsGroup {
    let alice = arkret_sdk::ArkretMlsIdentity::new_basic(
        arkret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap(),
        arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000a1".to_owned())
            .unwrap(),
    )
    .unwrap();
    let bob = arkret_sdk::ArkretMlsIdentity::new_basic(
        arkret_sdk::Did::new(bob_actor.to_owned()).unwrap(),
        arkret_sdk::DeviceId::new(bob_device.to_owned()).unwrap(),
    )
    .unwrap();
    let bob_key_package = bob.key_package_record().unwrap();
    let mut alice_group = alice.create_group(realm.as_bytes()).unwrap();
    let add = alice_group.add_member(&bob_key_package).unwrap();
    let bob_group = arkret_sdk::ArkretMlsGroup::join_from_welcome(bob, &add.welcome).unwrap();

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
fn historical_author_view_survives_epoch_rotation() {
    let mut state = temp_state_store("historical-author-view");
    let secure = MemorySecureKeyStore::new();
    let realm = "ak:realm:01904100-0000-7000-8000-0000000000c1";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000c2";
    let mut alice_group =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    let epoch_one_snapshot = state.mls_snapshot_for(realm).unwrap();
    let epoch_one_ref =
        arkret_sdk::EventId::new("ak:event:01904100-0000-7000-8000-0000000000c3").unwrap();
    state
        .record_mls_group_state_ref_for_effective_scope(
            realm,
            None,
            &epoch_one_snapshot.group_id,
            epoch_one_snapshot.epoch,
            epoch_one_ref.clone(),
        )
        .unwrap();
    let original_view = minimal_metadata_author_view(
        &state,
        &secure,
        realm,
        bob_actor,
        bob_device,
        &epoch_one_snapshot.group_id,
        epoch_one_snapshot.epoch,
        epoch_one_ref.as_str(),
    )
    .expect("current epoch author view");

    let secret = load_device_snapshot_secret(&secure, bob_actor, bob_device).unwrap();
    let mut bob_group =
        crate::mls::persistence::restore_envelope(&epoch_one_snapshot, &secret, 0).unwrap();
    let commit = alice_group.self_update_commit().unwrap();
    bob_group.apply_commit(&commit).unwrap();
    let post_state = bob_group.export_state_record().unwrap();
    let serialized = serde_json::to_vec(&post_state).unwrap();
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).unwrap();
    let epoch_two_snapshot = crate::mls::persistence::encrypt_state(
        realm,
        &post_state.group_id,
        post_state.epoch,
        &serialized,
        &secret,
        &salt,
    );
    let epoch_two_ref =
        arkret_sdk::EventId::new("ak:event:01904100-0000-7000-8000-0000000000c4").unwrap();
    state
        .record_mls_group_state_ref_for_effective_scope(
            realm,
            None,
            &epoch_two_snapshot.group_id,
            epoch_two_snapshot.epoch,
            epoch_two_ref,
        )
        .unwrap();
    state.save_mls_snapshot(realm, epoch_two_snapshot);

    let historical_view = minimal_metadata_author_view(
        &state,
        &secure,
        realm,
        bob_actor,
        bob_device,
        &epoch_one_snapshot.group_id,
        epoch_one_snapshot.epoch,
        epoch_one_ref.as_str(),
    )
    .expect("historical epoch author view");
    assert_eq!(historical_view, original_view);
    assert!(
        minimal_metadata_author_view(
            &state,
            &secure,
            realm,
            bob_actor,
            bob_device,
            &epoch_one_snapshot.group_id,
            epoch_one_snapshot.epoch,
            "ak:event:01904100-0000-7000-8000-0000000000ff",
        )
        .is_none(),
        "non-winning historical ref must fail closed"
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn receive_chain_persists_across_restart_and_plaintext_is_never_at_rest() {
    // §5.6 MUST + E2EE-at-rest hardening: after a successful decrypt the
    // advanced group state is persisted (so the same-epoch NEXT message
    // decrypts after a "restart"), and the already-decrypted message re-renders
    // from the in-session plaintext cache (its ratchet key was deliberately
    // consumed by the write-back). Crucially, that plaintext cache is
    // in-memory ONLY: `e2ee_safe_persist_state` strips `mls_decrypted_plaintext`
    // before anything touches durable storage, so a real restart (fresh store
    // over the same backing file) must NOT be able to re-render the consumed
    // message — its plaintext is never written at rest.
    let path = std::env::temp_dir().join(format!(
        "inkson-test-receive-chain-{}.json",
        crate::operation::uuid_v7()
    ));
    let mut state = crate::state::LocalStateStore::with_path(path.clone());
    let secure = MemorySecureKeyStore::new();
    let realm = "ak:realm:01904100-0000-7000-8000-0000000000b1";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000b2";

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

    // Same session: m1 re-renders from the in-memory plaintext cache (a ratchet
    // replay would fail — its message key was consumed before the write-back).
    let same_session_replay1 =
        decrypt_application_payload(&state, &secure, realm, bob_actor, bob_device, &m1)
            .expect("m1 served from the in-session plaintext cache");
    assert_eq!(same_session_replay1, br#"{"body":"m1"}"#);

    // "Restart": a brand-new store over the same backing file must see
    // the advanced receive chain (NOT the pre-decrypt snapshot).
    let restarted = crate::state::LocalStateStore::with_path(path.clone());
    let reloaded = restarted.mls_snapshot_for(realm).unwrap();
    assert_eq!(reloaded.ciphertext_hex, advanced.ciphertext_hex);
    // E2EE-at-rest: the plaintext cache is stripped before persist, so after a
    // real restart m1 is NOT recoverable — its ratchet key was consumed and its
    // plaintext was never written to durable storage.
    assert!(
        decrypt_application_payload(&restarted, &secure, realm, bob_actor, bob_device, &m1)
            .is_none(),
        "consumed-message plaintext must never survive a restart (nothing at rest)"
    );
    // m2 (the next generation in the same epoch) still decrypts from the
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
fn circle_scoped_decrypt_uses_and_advances_only_the_circle_snapshot() {
    let mut state = temp_state_store("circle-scoped-receive-chain");
    let secure = MemorySecureKeyStore::new();
    let realm = "ak:realm:01904100-0000-7000-8000-0000000000b3";
    let circle = "ak:circle:01904100-0000-7000-8000-0000000000b4";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000b5";

    let mut alice_group =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    let circle_snapshot = state.mls_snapshot_for(realm).unwrap();
    state.drop_mls_snapshot(realm);
    state.save_mls_snapshot_for_effective_scope(
        realm.to_owned(),
        Some(circle),
        circle_snapshot.clone(),
    );
    let encrypted = alice_group
        .encrypt_payload("application/json", br#"{"body":"sidecar"}"#)
        .unwrap();

    assert!(
        decrypt_application_payload(&state, &secure, realm, bob_actor, bob_device, &encrypted)
            .is_none(),
        "Realm-scoped decrypt must not borrow a Circle snapshot"
    );
    let plaintext = decrypt_application_payload_for_effective_scope(
        &state,
        &secure,
        realm,
        bob_actor,
        bob_device,
        &encrypted,
        Some(circle),
    )
    .expect("Circle-scoped message decrypts with the Circle snapshot");
    assert_eq!(plaintext, br#"{"body":"sidecar"}"#);
    assert!(state.mls_snapshot_for(realm).is_none());
    let advanced = state
        .mls_snapshot_for_effective_scope(realm, Some(circle))
        .unwrap();
    assert_ne!(advanced.ciphertext_hex, circle_snapshot.ciphertext_hex);
    assert_eq!(advanced.app_messages_observed, 1);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn out_of_order_skipped_keys_survive_restart() {
    // §5.6: the persisted state includes the bounded skipped-message-key
    // cache. Bob decrypts m3 first (m1/m2 keys become skipped keys),
    // restarts, then decrypts the earlier m1 — which requires the
    // skipped keys to have been persisted with the advanced chain.
    let path = std::env::temp_dir().join(format!(
        "inkson-test-skipped-keys-{}.json",
        crate::operation::uuid_v7()
    ));
    let mut state = crate::state::LocalStateStore::with_path(path.clone());
    let secure = MemorySecureKeyStore::new();
    let realm = "ak:realm:01904100-0000-7000-8000-0000000000c1";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000c2";

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
    let restarted = crate::state::LocalStateStore::with_path(path.clone());
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
    let device = "ak:device:01904100-0000-7000-8000-0000000000d1";
    let realm = "ak:realm:01904100-0000-7000-8000-0000000000d2";

    super::seed_genesis_governance_proof(&mut state, realm);
    seed_complete_rfc9420_projection(&mut state, realm, actor);
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
    let payload: arkret_sdk::EncryptedPayload =
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
    let realm = "ak:realm:01904100-0000-7000-8000-0000000000e1";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000e2";

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
        "ak:realm:01904100-0000-7000-8000-000000000001",
        "group-for-missing-secret-test",
        1,
        b"not-a-real-group-state",
        "other-device-secret",
        b"deterministic-salt",
    );
    state.save_mls_snapshot("ak:realm:01904100-0000-7000-8000-000000000001", envelope);

    let error = encrypt_values_with_device_snapshot(
        &mut state,
        &store,
        "ak:realm:01904100-0000-7000-8000-000000000001",
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
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
    use arkret_sdk::{ArkretMlsIdentity, DeviceId, Did};

    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:01904100-0000-7000-8000-000000000003";
    let store = MemorySecureKeyStore::new();
    let secret = load_or_create_device_snapshot_secret(&store, actor, device).unwrap();
    let identity = ArkretMlsIdentity::new_basic(
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
    seed_complete_rfc9420_projection(&mut state, realm, actor);

    let (_schedule_hash, member_dids, encrypted_values, _commit, _new_envelope, _) =
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
/// does ONLY after the server accepts the `ak.mls.commit`). This is the
/// invariant that keeps `snapshot.epoch == server.epoch` in lockstep and
/// prevents the permanent `mls_epoch_skew` that optimistic pre-accept
/// persistence caused.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypt_does_not_persist_snapshot_until_caller_saves_on_accept() {
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let secure = MemorySecureKeyStore::new();
    let _ = load_or_create_device_snapshot_secret(&secure, actor, device).unwrap();
    let mut state = temp_state_store("persist-on-accept");
    let realm = "ak:realm:01904100-0000-7000-8000-000000000099";

    state.save_realm_tree_projection(
        realm,
        json!({
            "active_profiles": [arkret_sdk::mls::MINIMAL_METADATA_REALM_PROFILE],
            "content_scheme": "mls_rfc9420",
            "members_limited": false,
            "members": [{ "actor_id": actor, "membership": "join" }]
        }),
    );
    assert!(state.realm_projection_is_minimal_metadata(realm));

    // Genesis installs the epoch-0 snapshot.
    super::seed_genesis_governance_proof(&mut state, realm);
    ensure_creator_mls_snapshot(&mut state, &secure, realm, actor, device)
        .unwrap()
        .expect("creator snapshot created");
    let epoch_before = state.mls_snapshot_for(realm).unwrap().epoch;
    let mut overdue = state.mls_snapshot_for(realm).unwrap();
    overdue.epoch_started_at = chrono::Utc::now() - chrono::Duration::hours(2);
    state.save_mls_snapshot(realm, overdue);
    super::seed_next_governance_proof(&mut state, realm);

    // An overdue minimal-metadata epoch forces a post-commit envelope at
    // epoch+1 WITHOUT touching the persisted snapshot.
    let result = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        actor,
        device,
        "application/vnd.arkret.test+json",
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
        "ak:realm:empty",
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
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
            { "kind": "ak.mls.welcome", "content": { "not": "a welcome" } }
        ]
    });
    let outcome = apply_welcome_messages_with_device_snapshot(
        &mut state,
        &store,
        "ak:realm:malformed",
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
        &messages,
    )
    .unwrap();
    assert_eq!(outcome.applied, 0);
    assert_eq!(outcome.failed, 1);
    assert!(outcome.first_error.is_some());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn welcome_without_verified_seal_proof_does_not_persist_snapshot() {
    let mut state = temp_state_store("welcome-keypackage-state");
    let store = MemorySecureKeyStore::new();
    let realm = "ak:realm:01904100-0000-7000-8000-0000000000c1";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000c2";
    let alice = arkret_sdk::ArkretMlsIdentity::new_basic(
        arkret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap(),
        arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000a1".to_owned())
            .unwrap(),
    )
    .unwrap();
    let bob = arkret_sdk::ArkretMlsIdentity::new_basic(
        arkret_sdk::Did::new(bob_actor.to_owned()).unwrap(),
        arkret_sdk::DeviceId::new(bob_device.to_owned()).unwrap(),
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
                "kind": "ak.mls.welcome",
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

    assert_eq!(outcome.applied, 0);
    assert_eq!(outcome.failed, 1);
    assert!(
        outcome
            .first_error
            .as_deref()
            .is_some_and(|reason| reason.contains("decryption_pending"))
    );
    assert!(
        state.mls_snapshot_for(realm).is_none(),
        "an unverified Welcome must never persist joined MLS state"
    );
    // The KeyPackage identity state (init private key) is RETAINED after a
    // Welcome applies — NOT consumed. Invitees publish reusable `last_resort`
    // KeyPackages, whose init key must survive across Welcomes; deleting it here
    // was the deadlock root ("no local KeyPackage identity state" / invitee
    // could never apply a second Welcome). See
    // [[mls-keypackage-consumed-deadlock-last-resort]].
    assert!(
        load_mls_key_package_identity_state(
            &store,
            bob_actor,
            bob_device,
            &bob_key_package.keypackage_id,
        )
        .unwrap()
        .is_some()
    );
}

#[test]
fn durable_welcome_payload_without_claim_envelope_fails_closed() {
    let mut state = temp_state_store("welcome-claim-envelope");
    let store = MemorySecureKeyStore::new();
    let messages = json!({
        "messages": [
            {
                "kind": "ak.mls.welcome",
                "content": {
                    "mls_group_id": "mls-group-a",
                    "epoch": 1,
                    "recipient_principal_id": "did:web:alice.example",
                    "recipient_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
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
                    "expires_at": "2100-01-01T00:00:00.000Z"
                }
            }
        ]
    });
    let outcome = apply_welcome_messages_with_device_snapshot(
        &mut state,
        &store,
        "ak:realm:welcome-claim-envelope",
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
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
            .contains(arkret_sdk::error::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)
    );
}

#[test]
fn durable_welcome_projection_context_is_removed_without_hiding_unknown_payload_fields() {
    let projected = json!({
        "keypackage_ref": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "event_id": "ak:event:01904100-0000-7000-8000-000000000001",
        "sender": "did:web:alice.example",
        "hlc": "019041000000-0001-00000001",
        "executed_by": "did:key:z6MkExecutor",
        "authorization_ref": "ak:event:01904100-0000-7000-8000-000000000002",
        "seal_ref": "ak:seal:sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "seal_basis": {"state_root": "sha256:3333333333333333333333333333333333333333333333333333333333333333"},
        "preconditions": {"expected_epoch": 0},
        "effects": {"next_epoch": 1},
        "accepted_event_id": "ak:event:01904100-0000-7000-8000-000000000001",
        "unexpected_business_field": true
    });

    let wire = durable_welcome_wire_payload(&projected);
    for field in [
        "event_id",
        "sender",
        "hlc",
        "executed_by",
        "authorization_ref",
        "seal_ref",
        "seal_basis",
        "preconditions",
        "effects",
        "accepted_event_id",
    ] {
        assert!(
            wire.get(field).is_none(),
            "projection field {field} remained"
        );
    }
    assert_eq!(wire.get("unexpected_business_field"), Some(&json!(true)));

    let reason = durable_welcome_payload_reject_reason(&wire).expect("incomplete payload rejects");
    assert!(reason.contains("unknown field `unexpected_business_field`"));
}

#[test]
fn local_welcome_hint_filters_by_realm_group_id() {
    let realm = "ak:realm:01904100-0000-7000-8000-000000000001";
    let other_realm = "ak:realm:01904100-0000-7000-8000-000000000002";
    let messages = vec![
        json!({
            "kind": "ak.mls.welcome",
            "content": {
                "group_id": mls_group_id_for_realm(realm),
                "welcome_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
            "unsigned": {
                "mls_welcome_id": "ak:mls_welcome:01904100-0000-7000-8000-0000000000aa",
            },
        }),
        json!({
            "kind": "ak.mls.welcome",
            "content": {
                "group_id": mls_group_id_for_realm(other_realm),
                "welcome_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            },
        }),
        json!({
            "kind": "ak.key.verification.request",
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
        "1:ak:mls_welcome:01904100-0000-7000-8000-0000000000aa"
    );
    assert_eq!(
        local_mls_welcome_hint_for_realm(&messages, other_realm),
        "1:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
}

// ── History sharing (encryption-and-audit.md): provider push +
//    receiver ingest + tier-3 history decrypt ──────────────────────

/// Build a `ak.realm_key.share` envelope sealing `secrets` to `recipient_pub`,
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
    let _signer_guard =
        ActiveSignerGuard::install([17u8; 32], "did:key:zRealmKeyShareRuntimeTestSigner");
    let sealed =
        arkret_crypto::secret_share::seal_history_secret_to_device_pubkey(recipient_pub, secrets)
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
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        sealed,
        "ak:event:01904100-0000-7000-8000-0000000000e7",
        "ak:grant:01904100-0000-7000-8000-0000000000e8",
    )
    .unwrap();
    json!({
        "kind": event.kind.as_str(),
        "payload": event.payload,
    })
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn ingest_realm_key_share_installs_history_secrets() {
    // A provider seals two epochs' history secrets to bob's device HPKE public
    // key; bob ingests the share and both secrets land in local state.
    let mut state = temp_state_store("history-share-ingest");
    let secure = MemorySecureKeyStore::new();
    let realm = "ak:realm:01904100-0000-7000-8000-0000000000e1";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000e2";
    let alice_device = "ak:device:01904100-0000-7000-8000-0000000000a1";
    seed_history_share_policy_projection(&mut state, realm);

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

    let pending =
        ingest_realm_key_share(&state, &secure, realm, bob_actor, bob_device, &share).unwrap();
    let installed = commit_pending_history(&mut state, &secure, pending).await;
    assert_eq!(installed, 2);
    assert_eq!(state.history_secret_for(realm, 3), Some(vec![3u8; 32]));
    assert_eq!(state.history_secret_for(realm, 4), Some(vec![4u8; 32]));
    assert_eq!(state.history_secrets_for(realm).len(), 2);

    // A share addressed to a different device installs nothing.
    let other = "ak:device:01904100-0000-7000-8000-0000000000ff";
    let foreign =
        realm_key_share_envelope(realm, bob_actor, other, alice_device, &bob_pub, &secrets);
    assert_eq!(
        ingest_realm_key_share(&state, &secure, realm, bob_actor, bob_device, &foreign)
            .unwrap()
            .len(),
        0
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn ingest_realm_key_share_accepts_projected_payload_envelope() {
    // soland projects durable ak.realm_key.share events into device_messages as
    // `{ kind, realm_id, sender_principal_id, sender_device_id, payload }`. The receiver
    // must parse the spec payload field or Bob never installs the shared
    // history key.
    let mut state = temp_state_store("history-share-projected-payload");
    let secure = MemorySecureKeyStore::new();
    let realm = "ak:realm:01904100-0000-7000-8000-0000000000e8";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000e9";
    let alice_actor = "did:web:alice.example";
    let alice_device = "ak:device:01904100-0000-7000-8000-0000000000a1";
    seed_history_share_policy_projection(&mut state, realm);

    let (_priv, bob_pub) =
        load_or_create_device_hpke_keypair(&secure, bob_actor, bob_device).unwrap();
    let secrets = vec![(0_u64, vec![7u8; 32])];
    let local = realm_key_share_envelope(
        realm,
        bob_actor,
        bob_device,
        alice_device,
        &bob_pub,
        &secrets,
    );
    let projected = json!({
        "kind": "ak.realm_key.share",
        "sender_principal_id": alice_actor,
        "sender_device_id": alice_device,
        "realm_id": realm,
        "operation_id": "ak:event:01904100-0000-7000-8000-0000000000ee",
        "payload": local.get("payload").unwrap().clone(),
    });

    assert_eq!(
        realm_key_share_message_realm_id(&projected),
        Some(realm.to_owned())
    );
    assert_eq!(
        collect_realm_key_share_messages_for_realm(&[projected.clone()], realm).len(),
        1
    );
    assert_eq!(
        realm_key_share_sender_device_pair(&projected),
        Some((alice_actor.to_owned(), alice_device.to_owned()))
    );
    let mut legacy = projected.clone();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("sender_principal_id");
    legacy["sender"] = json!(alice_actor);
    assert_eq!(realm_key_share_sender_device_pair(&legacy), None);
    assert_eq!(
        realm_key_share_message_operation_id(&projected).as_deref(),
        Some("ak:event:01904100-0000-7000-8000-0000000000ee")
    );
    let mut ingestable = projected.clone();
    ingestable
        .as_object_mut()
        .unwrap()
        .remove("sender_principal_id");
    let pending =
        ingest_realm_key_share(&state, &secure, realm, bob_actor, bob_device, &ingestable).unwrap();
    assert_eq!(
        commit_pending_history(&mut state, &secure, pending).await,
        1
    );
    assert_eq!(state.history_secret_for(realm, 0), Some(vec![7u8; 32]));
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn ingest_realm_key_share_accepts_soland_content_payload_envelope() {
    // The REAL soland wire shape (sync `to_device[]` and device-messages,
    // projection/apply.rs) nests the spec payload one level deeper than the
    // fixture above:
    //   { kind, sender_principal_id, sender_device_id,
    //     content: { operation_id, realm_id, payload: { key_scope, ... } } }
    // The 2026-07-09 joint-full run proved the old parser silently dropped
    // this shape: Bob's install loop never grouped the share by realm, so the
    // pre-join history secret was never installed and the card stayed locked.
    let mut state = temp_state_store("history-share-content-payload");
    let secure = MemorySecureKeyStore::new();
    let realm = "ak:realm:01904100-0000-7000-8000-0000000000f0";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000f1";
    let alice_actor = "did:web:alice.example";
    let alice_device = "ak:device:01904100-0000-7000-8000-0000000000a2";
    seed_history_share_policy_projection(&mut state, realm);

    let (_priv, bob_pub) =
        load_or_create_device_hpke_keypair(&secure, bob_actor, bob_device).unwrap();
    let secrets = vec![(0_u64, vec![5u8; 32])];
    let local = realm_key_share_envelope(
        realm,
        bob_actor,
        bob_device,
        alice_device,
        &bob_pub,
        &secrets,
    );
    let projected = json!({
        "kind": "ak.realm_key.share",
        "sender_principal_id": alice_actor,
        "sender_device_id": alice_device,
        "content": {
            "operation_id": "ak:event:01904100-0000-7000-8000-0000000000f2",
            "realm_id": realm,
            "payload": local.get("payload").unwrap().clone(),
        },
    });

    assert_eq!(
        realm_key_share_message_realm_id(&projected),
        Some(realm.to_owned())
    );
    assert_eq!(
        collect_realm_key_share_messages_for_realm(&[projected.clone()], realm).len(),
        1
    );
    assert_eq!(
        realm_key_share_sender_device_pair(&projected),
        Some((alice_actor.to_owned(), alice_device.to_owned()))
    );
    assert_eq!(
        realm_key_share_message_operation_id(&projected).as_deref(),
        Some("ak:event:01904100-0000-7000-8000-0000000000f2")
    );
    let mut ingestable = projected.clone();
    ingestable
        .as_object_mut()
        .unwrap()
        .remove("sender_principal_id");
    let pending =
        ingest_realm_key_share(&state, &secure, realm, bob_actor, bob_device, &ingestable).unwrap();
    assert_eq!(
        commit_pending_history(&mut state, &secure, pending).await,
        1
    );
    assert_eq!(state.history_secret_for(realm, 0), Some(vec![5u8; 32]));
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn history_secrets_do_not_land_in_account_state_json() {
    use base64::Engine as _;

    let path = std::env::temp_dir().join(format!(
        "inkson-test-history-secret-at-rest-{}.json",
        crate::operation::uuid_v7()
    ));
    let realm = "ak:realm:01904100-0000-7000-8000-0000000000d9";
    let secret = vec![9u8; 32];
    let store = crate::secure_key_store::default_secure_key_store("inkson");
    let key = crate::secure_key_store::mls_history_secret_store_key(realm);
    let _ = store.delete_secret(&key);
    {
        let mut state = crate::state::LocalStateStore::with_path(path.clone());
        let pending = state
            .prepare_history_secrets(store.as_ref(), realm.to_owned(), [(7, secret.clone())])
            .unwrap()
            .unwrap();
        pending.persist(store.as_ref()).await.unwrap();
        state.publish_history_secrets(pending);
        assert_eq!(state.history_secret_for(realm, 7), Some(secret.clone()));
    }

    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let stem = path.file_stem().and_then(|value| value.to_str()).unwrap();
    let mut combined_json = String::new();
    for entry in std::fs::read_dir(parent).unwrap() {
        let path = entry.unwrap().path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if name.starts_with(stem)
            && name.ends_with(".json")
            && let Ok(raw) = std::fs::read_to_string(&path)
        {
            combined_json.push_str(&raw);
        }
    }
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&secret);
    assert!(!combined_json.contains("history_secrets"));
    assert!(!combined_json.contains(&encoded));

    let _ = store.delete_secret(&key);
    let _ = std::fs::remove_file(path);
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn tier3_history_decrypt_reads_provider_exporter_aead_content() {
    // End-to-end tier-3: the provider (alice) encrypts content under the
    // `mls_exporter_aead_v1` scheme and shares the epoch's `history_secret`;
    // bob installs it and `decrypt_application_payload` opens the pre-join
    // content the live receive ratchet cannot.
    let mut state = temp_state_store("history-share-tier3");
    let secure = MemorySecureKeyStore::new();
    let realm = "ak:realm:01904100-0000-7000-8000-0000000000f1";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000f2";
    let alice_device = "ak:device:01904100-0000-7000-8000-0000000000a1";
    let history_store = crate::secure_key_store::default_secure_key_store("inkson");
    let history_key = crate::secure_key_store::mls_history_secret_store_key(realm);
    let _ = history_store.delete_secret(&history_key);

    // Bob holds a join-epoch snapshot (so `decrypt_application_payload` can
    // instantiate a group), but cannot ratchet to alice's exporter-aead content.
    let mut alice_group =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    seed_history_share_policy_projection(&mut state, realm);
    // Advance past the epoch bob snapshotted. Without this the content epoch is
    // bob's own, and exporter-aead's history_secret is an exporter output every
    // member of that epoch can derive — so bob would read the content from his
    // group state and the share below would prove nothing. The pre-share
    // assertion only means something for an epoch bob does not hold.
    alice_group.self_update_commit().unwrap();
    let epoch = alice_group.epoch();

    // Provider encrypts content via exporter-aead, binding the typed routing
    // AAD, key reference and epoch in the immutable header, then exports the
    // epoch's history secret.
    let aad = arkret_sdk::EncryptedEnvelopeAad::hidden(
        arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
        "ak.strand.update",
    );
    let key_ref = arkret_sdk::KeyRefObject::mls_exporter_aead(alice_group.group_id(), epoch);
    let plaintext = br#"{"body":"pre-join history"}"#;
    let payload = alice_group
        .encrypt_payload_exporter_aead("application/json", realm, key_ref, aad, plaintext)
        .unwrap();
    let history_secret = alice_group
        .export_history_secret_range(epoch, epoch)
        .into_iter()
        .find(|(e, _)| *e == epoch)
        .map(|(_, secret)| secret)
        .expect("retained history secret for the current epoch");

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
        &[(epoch, history_secret.to_vec())],
    );
    let pending =
        ingest_realm_key_share(&state, &secure, realm, bob_actor, bob_device, &share).unwrap();
    assert_eq!(
        commit_pending_history(&mut state, &secure, pending).await,
        1
    );

    // After the share: tier-3 history decrypt reads the content.
    let decrypted =
        decrypt_application_payload(&state, &secure, realm, bob_actor, bob_device, &payload)
            .expect("tier-3 history decrypt opens pre-join content");
    assert_eq!(decrypted, plaintext);
    let _ = history_store.delete_secret(&history_key);
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn tier3_history_decrypt_works_without_local_snapshot() {
    // Group-free tier-3: a member granted a `history_secret` but holding NO
    // local MLS snapshot for the Realm (e.g. granted before processing its own
    // Welcome) still reads pre-join exporter-aead content via the standalone
    // SDK path. Regression guard for the "must have a snapshot first" relaxation.
    let mut state = temp_state_store("history-share-no-snapshot");
    let secure = MemorySecureKeyStore::new();
    let realm = "ak:realm:01904100-0000-7000-8000-0000000000f3";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000f4";
    let history_store = crate::secure_key_store::default_secure_key_store("inkson");
    let history_key = crate::secure_key_store::mls_history_secret_store_key(realm);
    let _ = history_store.delete_secret(&history_key);

    // Build alice's group WITHOUT persisting any snapshot into `state`.
    let alice = arkret_sdk::ArkretMlsIdentity::new_basic(
        arkret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap(),
        arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000a1".to_owned())
            .unwrap(),
    )
    .unwrap();
    let mut alice_group = alice.create_group(realm.as_bytes()).unwrap();
    let epoch = alice_group.epoch();

    let aad = arkret_sdk::EncryptedEnvelopeAad::hidden(
        arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
        "ak.strand.update",
    );
    let key_ref = arkret_sdk::KeyRefObject::mls_exporter_aead(alice_group.group_id(), epoch);
    let plaintext = br#"{"body":"no-snapshot history"}"#;
    let payload = alice_group
        .encrypt_payload_exporter_aead("application/json", realm, key_ref, aad, plaintext)
        .unwrap();
    let history_secret = alice_group
        .export_history_secret_range(epoch, epoch)
        .into_iter()
        .find(|(e, _)| *e == epoch)
        .map(|(_, secret)| secret)
        .expect("retained history secret for the current epoch");

    // No snapshot for the realm: the live-ratchet path cannot even instantiate
    // a group, but the granted history secret still opens the content.
    assert!(state.mls_snapshot_for(realm).is_none());
    assert!(
        decrypt_application_payload(&state, &secure, realm, bob_actor, bob_device, &payload)
            .is_none(),
        "without the granted secret there is nothing to decrypt"
    );

    let pending = state
        .prepare_history_secrets(
            history_store.as_ref(),
            realm.to_owned(),
            [(epoch, history_secret.to_vec())],
        )
        .unwrap()
        .unwrap();
    pending.persist(history_store.as_ref()).await.unwrap();
    state.publish_history_secrets(pending);
    let decrypted =
        decrypt_application_payload(&state, &secure, realm, bob_actor, bob_device, &payload)
            .expect("group-free tier-3 decrypt opens content with no local snapshot");
    assert_eq!(decrypted, plaintext);

    let _ = history_store.delete_secret(&history_key);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn realm_key_share_sender_signature_round_trips() {
    // Provider signs `sender_signing_input()` with the active Ed25519 device
    // signer; the receiver verifies it. A tampered body, a wrong key, or a
    // missing signature are each handled as specified (reject on bad signature,
    // tolerate an absent one).
    use ed25519_dalek::SigningKey;

    let seed = [42u8; 32];
    let verifying = SigningKey::from_bytes(&seed).verifying_key();
    let did = crate::identity::did_key::did_key_from_verifying_key(&verifying);
    let _signer_guard = ActiveSignerGuard::install(seed, &did);

    let realm = "ak:realm:01904100-0000-7000-8000-0000000000f5";
    let recipient_actor = "did:web:bob.example";
    let recipient_device = "ak:device:01904100-0000-7000-8000-0000000000f6";
    let sender_device = "ak:device:01904100-0000-7000-8000-0000000000a1";

    let event = crate::mls::admission::build_realm_key_share_event(
        realm,
        "did:web:alice.example",
        sender_device,
        recipient_actor,
        recipient_device,
        3,
        4,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "c2VhbGVk".to_owned(),
        "ak:event:01904100-0000-7000-8000-0000000000e7",
        "ak:grant:01904100-0000-7000-8000-0000000000e8",
    )
    .unwrap();
    let payload: arkret_sdk::RealmKeySharePayload =
        serde_json::from_value(serde_json::to_value(&event.payload).unwrap()).unwrap();

    // A real signature object was attached, and it verifies.
    assert!(
        matches!(
            &payload.sender_device_signature,
            arkret_sdk::SignatureMaterial::Variant1(signature)
                if signature
                    .get("signature")
                    .and_then(serde_json::Value::as_str)
                    .is_some()
        ),
        "an active signer must attach a real sender_device_signature"
    );
    // SEC-02: with no cached directory record (None sender principal → Miss),
    // verification falls back to the self-asserted embedded key.
    assert!(verify_realm_key_share_sender_signature(&payload, None));

    // Tamper with the covered body → signature must no longer verify.
    let mut tampered = payload.clone();
    tampered.material = arkret_sdk::RealmKeyShareMaterial::Ciphertext {
        ciphertext: arkret_sdk::NonEmptyString::new("dGFtcGVyZWQ").unwrap(),
    };
    assert!(!verify_realm_key_share_sender_signature(&tampered, None));

    // An empty signature object is tolerated on the Miss path (HPKE seal gates).
    let mut unsigned = payload.clone();
    unsigned.sender_device_signature = arkret_sdk::SignatureMaterial::Variant1(Default::default());
    assert!(verify_realm_key_share_sender_signature(&unsigned, None));
}
