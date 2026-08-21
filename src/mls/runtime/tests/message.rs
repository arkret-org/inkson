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
    let actor_id = crate::mls_api_helpers::principal_core_id(actor).unwrap();
    state.save_realm_tree_projection(
        realm,
        json!({
            "content_scheme": "mls_rfc9420",
            "members_limited": false,
            "members": [{ "actor_id": actor_id, "membership": "join" }]
        }),
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn creator_snapshot_bootstrap_makes_space_encryptable() {
    let mut state = temp_state_store("creator-bootstrap");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    super::seed_genesis_governance_proof(&mut state, realm);
    state.save_realm_tree_projection(
        realm,
        json!({
            "content_scheme": "mls_rfc9420",
            "members_limited": false,
            "members": [{
                "actor_id": crate::mls_api_helpers::principal_core_id(actor).unwrap(),
                "membership": "join"
            }]
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
    let realm = "ak:realm:AekaXR7egHsJjC7lxnkHz8popOxRV27nKlKY8RDyuOBa";

    super::seed_genesis_governance_proof(&mut state, realm);
    seed_complete_rfc9420_projection(&mut state, realm, actor);
    ensure_creator_mls_snapshot(&mut state, &secure, realm, actor, device)
        .unwrap()
        .expect("creator snapshot");

    let aad_scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm).unwrap(),
    };
    let aad = arkret_sdk::EncryptedEnvelopeAad::hidden(&aad_scope, "ak.message.create").unwrap();
    let (_, _, content_payload, metadata_payload, commit, snapshot, _) =
        encrypt_message_with_device_snapshot(
            &mut state,
            &secure,
            realm,
            actor,
            device,
            "application/vnd.arkret.message+json",
            aad,
            br#"{"kind":"ak.content.text","body":"routed"}"#,
            Some(arkret_sdk::MESSAGE_METADATA_MLS_CONTENT_TYPE),
            Some(br#"{"sidecar_exchange_binding":{}}"#.as_slice()),
            None,
            None,
        )
        .unwrap();
    let metadata_payload = metadata_payload.expect("metadata ciphertext");
    assert_eq!(
        content_payload.content_type,
        arkret_sdk::MESSAGE_CONTENT_BLOCK_MLS_CONTENT_TYPE
    );
    assert_eq!(
        metadata_payload.content_type,
        arkret_sdk::MESSAGE_METADATA_MLS_CONTENT_TYPE
    );
    assert_eq!(metadata_payload.epoch, content_payload.epoch);
    assert_ne!(
        metadata_payload.payload_digest,
        content_payload.payload_digest
    );
    assert!(commit.is_none());
    assert!(snapshot.is_none());
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
    let realm = "ak:realm:AcysOZi_v0RXNBYf47wJaNxuBSTq_WGE_xQtBPfwAWoj";

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
                {
                    "actor_id": crate::mls_api_helpers::principal_core_id(actor).unwrap(),
                    "membership": "join"
                },
                { "actor_id": "ak:did_core:web:bob.example", "membership": "join" }
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
    let realm = "ak:realm:AS5FqwC40o7__sjiREHUnzw9YDYeOTIYVGSZyZasRuaN";

    super::seed_genesis_governance_proof(&mut state, realm);
    ensure_creator_mls_snapshot(&mut state, &secure, realm, actor, device)
        .unwrap()
        .expect("creator snapshot");
    state.save_realm_tree_projection(
        realm,
        json!({
            "encrypted": true,
            "members_limited": false,
            "members": [{
                "actor_id": crate::mls_api_helpers::principal_core_id(actor).unwrap(),
                "membership": "join"
            }]
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
/// is lost once the epoch advances (forward secrecy). See
/// `encrypt_values_with_device_snapshot`.
#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn authoring_exporter_aead_content_retains_history_secret() {
    let mut state = temp_state_store("author-retains-history-secret");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    // History-secret persistence is process-global secure storage keyed by the
    // exact scope/group pair, so this test uses a unique Realm.
    let realm = "ak:realm:Ae6wQDaXscJ6lZGbcWqFv_CW7o0_w5CGmtuB6TvlwNh2";
    super::seed_genesis_governance_proof(&mut state, realm);
    ensure_creator_mls_snapshot(&mut state, &secure, realm, actor, device)
        .unwrap()
        .expect("creator snapshot");
    let scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
    };
    let group_id = state.mls_snapshot_for(realm).unwrap().group_id;
    let scope_group_key =
        crate::state::mls_scope_snapshot_key_for_group(&scope, &group_id).unwrap();
    let history_store = crate::secure_key_store::default_secure_key_store("inkson");
    let history_key = crate::secure_key_store::mls_history_secret_store_key(&scope_group_key);
    let _ = history_store.delete_secret(&history_key);
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
            history_access: "all_history_for_current_members".to_owned(),
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
        &std::collections::BTreeSet::from([
            "ak:realm:APCEv_eZJS-G3Rl9hDcbEIFNJxcYpqP2nkoGb6FOPmVc".to_owned(),
        ]),
        &state.load().realm_tree_projections,
    );
    state.retain_realm_tree_projections(|id| keep.contains(id));
    assert!(realm_content_scheme_is_exporter_aead(&state, realm));
    // No secret is retained before any content is authored.
    assert!(state.history_secret_for(&scope, &group_id, 0).is_none());

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
    // retained locally for a later history-key response.
    let retained = state
        .history_secret_for(&scope, &group_id, 0)
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
        crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap(),
        arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000a1".to_owned())
            .unwrap(),
    )
    .unwrap();
    let bob = arkret_sdk::ArkretMlsIdentity::new_basic(
        crate::mls_api_helpers::principal_core_id(bob_actor).unwrap(),
        arkret_sdk::DeviceId::new(bob_device.to_owned()).unwrap(),
    )
    .unwrap();
    let bob_key_package = bob.key_package_record().unwrap();
    let mut alice_group = alice.create_group(realm.as_bytes()).unwrap();
    let add = alice_group.add_member(&bob_key_package).unwrap();
    let bob_group = arkret_sdk::ArkretMlsGroup::join_from_welcome(bob, &add.welcome).unwrap();

    let secret = load_or_create_account_mls_secret(secure, bob_actor).unwrap();
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
    state.save_mls_snapshot(realm.to_owned(), envelope).unwrap();
    alice_group
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn historical_author_view_survives_epoch_rotation() {
    let mut state = temp_state_store("historical-author-view");
    let secure = MemorySecureKeyStore::new();
    let realm = "ak:realm:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000c2";
    let mut alice_group =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    let epoch_one_snapshot = state.mls_snapshot_for(realm).unwrap();
    let epoch_one_ref =
        arkret_sdk::EventId::new("ak:event:AR9d8WoyQJCOjt6n46diPUzg9zsrG9OZ9TAgE1rz6tJa").unwrap();
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
        arkret_sdk::EventId::new("ak:event:AWhyWU9v6_Jf6dcpqJcl22lGSxmg31pmhZOT0-xJVYVj").unwrap();
    state
        .record_mls_group_state_ref_for_effective_scope(
            realm,
            None,
            &epoch_two_snapshot.group_id,
            epoch_two_snapshot.epoch,
            epoch_two_ref,
        )
        .unwrap();
    state.save_mls_snapshot(realm, epoch_two_snapshot).unwrap();

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
            "ak:event:AbQHDTvS4ZELwYOPkH_Rdpweaio8GKWhHTHvvDJIAgzZ",
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
    let realm = "ak:realm:AZaaHAEvC1DejakImwHCcJHb0F1pgE-Jd-3_9BGirbuW";
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
    let realm = "ak:realm:Ab-u0alSwVcrUhqmeFQmMzuYs83_IrjXlRSBnpm-B-JL";
    let circle = "ak:circle:AZSmUwZFkNevUaVm0adiKDKw0OuAQqfAX6DFwhnIqF9I";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000b5";

    let mut alice_group =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    let circle_snapshot = state.mls_snapshot_for(realm).unwrap();
    state.drop_mls_snapshot(realm);
    state
        .save_mls_snapshot_for_effective_scope(
            realm.to_owned(),
            Some(circle),
            circle_snapshot.clone(),
        )
        .expect("valid effective scope");
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
    let realm = "ak:realm:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN";
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
    let realm = "ak:realm:AbTY4xkfqhJ_gKIwE_mty8Xoat_WVCf7dqfoHV5C3ziC";

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
    let realm = "ak:realm:AWLjsk0JkbLdfBfaY2GoxT61q1Ttw6HFu7sU-XGFywHc";
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
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "group-for-missing-secret-test",
        1,
        b"not-a-real-group-state",
        "other-device-secret",
        b"deterministic-salt",
    );
    state
        .save_mls_snapshot(
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            envelope,
        )
        .unwrap();

    let error = encrypt_values_with_device_snapshot(
        &mut state,
        &store,
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
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
    use arkret_sdk::{ArkretMlsIdentity, DeviceId};

    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy";
    let store = MemorySecureKeyStore::new();
    let secret = load_or_create_account_mls_secret(&store, actor).unwrap();
    let identity = ArkretMlsIdentity::new_basic(
        crate::mls_api_helpers::principal_core_id(actor).unwrap(),
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
    state.save_mls_snapshot(realm, envelope).unwrap();
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
    let _ = load_or_create_account_mls_secret(&secure, actor).unwrap();
    let mut state = temp_state_store("persist-on-accept");
    let realm = "ak:realm:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk";

    state.save_realm_tree_projection(
        realm,
        json!({
            "active_profiles": [arkret_sdk::ProfileId::MLS_MINIMAL_METADATA_REALM_V1],
            "content_scheme": "mls_rfc9420",
            "members_limited": false,
            "members": [{
                "actor_id": crate::mls_api_helpers::principal_core_id(actor).unwrap(),
                "membership": "join"
            }]
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
    state.save_mls_snapshot(realm, overdue).unwrap();
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
    state
        .save_mls_snapshot(realm, post_commit_envelope.clone())
        .unwrap();
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
        "ak:realm:Awkt11sH1cqYGNwG-NdGAvUk2xwJeJ7AC-93lG5ups2U",
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
    store_account_mls_secret(&store, "did:web:alice.example", "snapshot-secret").unwrap();
    // A welcome entry whose content is not a valid MlsWelcomeEnvelope.
    let messages = json!({
        "messages": [
            { "kind": "ak.mls.welcome", "content": { "not": "a welcome" } }
        ]
    });
    let outcome = apply_welcome_messages_with_device_snapshot(
        &mut state,
        &store,
        "ak:realm:Ae4L5dU13P9VksvkJAOF29Z7lsbKvgUqVqVh7q2H-E2I",
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
    let realm = "ak:realm:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000c2";
    let alice = arkret_sdk::ArkretMlsIdentity::new_basic(
        crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap(),
        arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000a1".to_owned())
            .unwrap(),
    )
    .unwrap();
    let bob = arkret_sdk::ArkretMlsIdentity::new_basic(
        crate::mls_api_helpers::principal_core_id(bob_actor).unwrap(),
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
    store_account_mls_secret(&store, bob_actor, "snapshot-secret").unwrap();
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
    store_account_mls_secret(&store, "did:web:alice.example", "snapshot-secret").unwrap();
    let messages = json!({
        "messages": [
            {
                "kind": "ak.mls.welcome",
                "content": {
                    "mls_group_id": "mls-group-a",
                    "epoch": 1,
                    "recipient_principal_id": "ak:did_core:web:alice.example",
                    "recipient_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                    "keypackage_ref": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                    "keypackage_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "claim_id": "claim-1",
                    "claim_ref": {
                        "claim_id": "claim-1",
                        "keypackage_ref": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                        "keypackage_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "capabilities_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "device_authorize_event_id": "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1"
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
        "ak:realm:Akb0VAmKqt26zC2oOrzxcUkvENt4KqxzU7fgzKks_4jk",
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
        "event_id": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "sender": "did:web:alice.example",
        "hlc": "019041000000-0001-00000001",
        "executed_by": "did:key:z6MkExecutor",
        "authorization_ref": "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
        "seal_ref": "ak:seal:sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "seal_basis": {"state_root": "sha256:3333333333333333333333333333333333333333333333333333333333333333"},
        "preconditions": {"expected_epoch": 0},
        "effects": {"next_epoch": 1},
        "accepted_event_id": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
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
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let other_realm = "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    let messages = vec![
        json!({
            "kind": "ak.mls.welcome",
            "content": {
                "group_id": mls_group_id_for_realm(realm).unwrap(),
                "welcome_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
            "unsigned": {
                "mls_welcome_id": "ak:mls_welcome:01904100-0000-7000-8000-0000000000aa",
            },
        }),
        json!({
            "kind": "ak.mls.welcome",
            "content": {
                "group_id": mls_group_id_for_realm(other_realm).unwrap(),
                "welcome_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            },
        }),
        json!({
            "kind": "ak.key.verification.request",
            "content": {
                "group_id": mls_group_id_for_realm(realm).unwrap(),
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

#[test]
fn realm_welcome_filter_keeps_circle_scope_from_same_realm() {
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let circle = "ak:circle:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    let message = json!({
        "kind": "ak.mls.welcome",
        "content": {
            "mls_group_id": arkret_sdk::ScopeRef::Circle {
                realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
                circle_id: arkret_sdk::CircleId::new(circle.to_owned()).unwrap(),
            }.canonical_mls_group_id().unwrap(),
            "governance_binding": {
                "effective_scope": {
                    "kind": "circle",
                    "realm_id": realm,
                    "circle_id": circle,
                }
            }
        }
    });
    assert!(mls_welcome_message_matches_realm(&message, realm));
}

#[test]
fn ordinary_exporter_sender_domain_requires_canonical_device_id() {
    let device = "ak:device:01904100-0000-7000-8000-0000000000a1";
    assert!(verify_exporter_sender_domain_for_send(device, false, true).is_ok());
    assert!(matches!(
        verify_exporter_sender_domain_for_send("not-a-device", false, true),
        Err(MlsRuntimeError::Identity(_))
    ));
}

#[test]
fn minimal_exporter_sender_domain_is_unavailable_before_leaf_identity_closes() {
    let device = "ak:device:01904100-0000-7000-8000-0000000000a1";
    let error = verify_exporter_sender_domain_for_send(device, true, true).unwrap_err();
    assert!(matches!(error, MlsRuntimeError::Encrypt(_)));
    assert!(error.user_message().contains("principal#device"));
}
