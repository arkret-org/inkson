//! Tests for welcome application, application-payload encrypt / decrypt, and
//! §5.6 receive-chain persistence.

use serde_json::json;

use crate::mls::runtime::*;
use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore, SecureKeyStoreError};
use crate::state::isolated_store_for_tests as temp_state_store;
use crate::test_support as fixture;

#[cfg(not(target_arch = "wasm32"))]
fn seed_complete_rfc9420_projection(
    state: &mut crate::state::LocalStateStore,
    realm: &str,
    actor: &str,
) {
    let actor_id = arkret_sdk::ActorId::account(fixture::authority(actor));
    state.save_realm_tree_projection(
        realm,
        json!({
            "member_roster_entries_limited": false,
            "member_roster_entries": [{ "actor_id": actor_id, "membership": "join" }]
        }),
    );
    seed_accepted_rfc9420_binding(state, realm);
}

/// The group's accepted `content_scheme`, delivered the only way a client may
/// learn it: the Station's installed `ak.component.mls.epoch.v1` value.
#[cfg(not(target_arch = "wasm32"))]
fn seed_accepted_rfc9420_binding(state: &mut crate::state::LocalStateStore, realm: &str) {
    fixture::install_accepted_mls_group(
        state,
        &arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
        },
    );
}

#[cfg(not(target_arch = "wasm32"))]
fn test_message_header(
    group: &arkret_sdk::ArkretMlsGroup,
    realm: &str,
) -> arkret_sdk::EventContentPreEncryptionHeader {
    arkret_sdk::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/json",
        arkret_sdk::EncryptedPayloadScheme::MlsRfc9420,
        arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
        },
        arkret_wire::event_kind_str::MESSAGE_CREATE,
        group.epoch(),
        arkret_sdk::EventId::new(
            "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM".to_owned(),
        )
        .unwrap(),
        group.local_content_sender_domain().unwrap(),
        None,
        arkret_sdk::EventContentRoutingContext::None,
    )
    .unwrap()
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn creator_realm_state_snapshot_bootstrap_makes_space_encryptable() {
    let mut state = temp_state_store("creator-bootstrap");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    super::seed_human_creator_authorization(actor, device);
    state.save_realm_tree_projection(
        realm,
        json!({
            "member_roster_entries_limited": false,
            "member_roster_entries": [{
                "actor_id": arkret_sdk::ActorId::account(fixture::authority(actor)),
                "membership": "join"
            }]
        }),
    );
    seed_accepted_rfc9420_binding(&mut state, realm);
    let summary = ensure_creator_mls_checkpoint(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
    )
    .unwrap();

    let summary = summary.expect("missing creator snapshot should be created");
    assert_eq!(summary.realm_id, realm);
    assert_eq!(summary.epoch, 0);
    assert!(state.mls_checkpoint_for(realm).is_some());
    super::seed_current_group_state_ref(&mut state, realm);
    // Ordinary application messages ride epoch 0; no commit event or
    // post-commit snapshot is returned.
    let (_, encrypted_values) = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
        "application/vnd.arkret.test+json",
        &[br#""private""#.to_vec()],
    )
    .unwrap();
    assert_eq!(encrypted_values.len(), 1);
    assert_eq!(state.mls_checkpoint_for(realm).unwrap().epoch, 0);
    let (_, encrypted_values_again) = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
        "application/vnd.arkret.test+json",
        &[br#""private-again""#.to_vec()],
    )
    .unwrap();
    assert_eq!(encrypted_values_again.len(), 1);
    assert_eq!(state.mls_checkpoint_for(realm).unwrap().epoch, 0);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn complete_membership_hint_does_not_alias_same_principal_at_another_station() {
    let mut state = temp_state_store("station-scoped-roster-hint");
    let secure = MemorySecureKeyStore::new();
    let principal = "did:web:alice.example";
    let authority = fixture::authority(principal);
    let device = fixture::device_id("ak:device:01904100-0000-7000-8000-000000000001");
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    super::seed_human_creator_authorization(principal, device.as_str());
    seed_complete_rfc9420_projection(&mut state, realm, principal);
    ensure_creator_mls_checkpoint(&mut state, &secure, realm, &authority, &device).unwrap();
    super::seed_current_group_state_ref(&mut state, realm);
    assert_eq!(
        realm_mls_roster_matches_complete_membership_hint(
            &state, &secure, realm, &authority, &device,
        ),
        Some(true)
    );

    let foreign = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        authority.principal_id.clone(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
    ));
    state.save_realm_tree_projection(
        realm,
        json!({
            "member_roster_entries_limited": false,
            "member_roster_entries": [{ "actor_id": foreign, "membership": "join" }],
        }),
    );
    assert_eq!(
        realm_mls_roster_matches_complete_membership_hint(
            &state, &secure, realm, &authority, &device,
        ),
        Some(false)
    );
    assert!(matches!(
        encrypt_values_with_device_snapshot(
            &mut state,
            &secure,
            realm,
            &authority,
            &device,
            "application/vnd.arkret.test+json",
            &[b"must not send".to_vec()],
        ),
        Err(MlsRuntimeError::EncryptionTransitionPending)
    ));

    state.save_realm_tree_projection(realm, json!({
        "member_roster_entries_limited": false,
        "member_roster_entries": [
            { "actor_id": arkret_sdk::ActorId::account(authority.clone()), "membership": "join" },
            { "actor_id": foreign, "membership": "join" },
        ],
    }));
    assert_eq!(
        state
            .complete_joined_member_hint_for_realm(realm)
            .unwrap()
            .unwrap()
            .len(),
        2
    );
    state.save_realm_tree_projection(
        realm,
        json!({
            "member_roster_entries_limited": false,
            "member_roster_entries": [{ "actor_id": principal, "membership": "join" }],
        }),
    );
    assert!(state.complete_joined_member_hint_for_realm(realm).is_err());
    assert_eq!(
        realm_mls_roster_matches_complete_membership_hint(
            &state, &secure, realm, &authority, &device,
        ),
        Some(false)
    );
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

    super::seed_human_creator_authorization(actor, device);
    seed_complete_rfc9420_projection(&mut state, realm, actor);
    ensure_creator_mls_checkpoint(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
    )
    .unwrap()
    .expect("creator snapshot");
    super::seed_current_group_state_ref(&mut state, realm);

    let effective_scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm).unwrap(),
    };
    let snapshot = state.mls_checkpoint_for_scope(&effective_scope).unwrap();
    let group_state_ref = state
        .mls_group_state_ref_for_scope(&effective_scope, &snapshot.group_id, snapshot.epoch)
        .unwrap();
    let encrypted = encrypt_message_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
        "application/vnd.arkret.message+json",
        arkret_wire::event_kind_str::MESSAGE_CREATE,
        group_state_ref,
        br#"{"kind":"ak.content.text","body":"routed"}"#,
        Some(arkret_sdk::MESSAGE_METADATA_MLS_CONTENT_TYPE),
        Some(br#"{"sidecar_exchange_binding":{}}"#.as_slice()),
        None,
        None,
        None,
    )
    .unwrap();
    let metadata_payload = encrypted.metadata.expect("metadata ciphertext");
    assert_eq!(
        encrypted.content.content_type,
        arkret_sdk::MESSAGE_CONTENT_BLOCK_MLS_CONTENT_TYPE
    );
    assert_eq!(
        metadata_payload.content_type,
        arkret_sdk::MESSAGE_METADATA_MLS_CONTENT_TYPE
    );
    assert_eq!(metadata_payload.epoch, encrypted.content.epoch);
    assert_ne!(
        metadata_payload.payload_digest,
        encrypted.content.payload_digest
    );
    // Both application messages advanced the §5.6 observed counter.
    assert_eq!(
        state
            .mls_checkpoint_for(realm)
            .unwrap()
            .app_messages_observed,
        2
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn replacement_sender_domain_blocks_before_counter_advance() {
    let mut state = temp_state_store("replacement-sender-fence");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:Ae1aXR7egHsJjC7lxnkHz8popOxRV27nKlKY8RDyuOBb";

    super::seed_human_creator_authorization(actor, device);
    seed_complete_rfc9420_projection(&mut state, realm, actor);
    ensure_creator_mls_checkpoint(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
    )
    .unwrap()
    .expect("creator snapshot");
    let effective_scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm).unwrap(),
    };
    super::seed_current_group_state_ref(&mut state, realm);
    let before = state.mls_checkpoint_for_scope(&effective_scope).unwrap();
    let group_state_ref = arkret_sdk::EventId::new(
        "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM".to_owned(),
    )
    .unwrap();
    let error = encrypt_message_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
        "application/vnd.arkret.message+json",
        arkret_wire::event_kind_str::MESSAGE_CREATE,
        group_state_ref,
        br#"{"kind":"ak.content.text","body":"blocked"}"#,
        None,
        None,
        Some("ak:did_core:key:z6Mkreplacement"),
        None,
        None,
    )
    .err()
    .expect("a replacement sender domain must pause encryption");
    assert!(matches!(
        error,
        MlsRuntimeError::EncryptionTransitionPending
    ));
    assert_eq!(
        state.mls_checkpoint_for_scope(&effective_scope),
        Some(before)
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

    super::seed_human_creator_authorization(actor, device);
    ensure_creator_mls_checkpoint(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
    )
    .unwrap()
    .expect("creator snapshot");
    super::seed_current_group_state_ref(&mut state, realm);
    state.save_realm_tree_projection(
        realm,
        json!({
            "encrypted": true,
            "member_roster_entries_limited": false,
            "member_roster_entries": [
                {
                    "actor_id": arkret_sdk::ActorId::account(fixture::authority(actor)),
                    "membership": "join"
                },
                { "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}}, "membership": "join" }
            ]
        }),
    );

    let error = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
        "application/vnd.arkret.test+json",
        &[br#""must-not-send-on-epoch-zero""#.to_vec()],
    )
    .unwrap_err();

    assert!(matches!(
        error,
        MlsRuntimeError::EncryptionTransitionPending
    ));
    assert_eq!(state.mls_checkpoint_for(realm).unwrap().epoch, 0);
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

    super::seed_human_creator_authorization(actor, device);
    ensure_creator_mls_checkpoint(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
    )
    .unwrap()
    .expect("creator snapshot");
    super::seed_current_group_state_ref(&mut state, realm);
    state.save_realm_tree_projection(
        realm,
        json!({
            "encrypted": true,
            "member_roster_entries_limited": false,
            "member_roster_entries": [{
                "actor_id": arkret_sdk::ActorId::account(fixture::authority(actor)),
                "membership": "join"
            }]
        }),
    );

    let error = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
        "application/vnd.arkret.test+json",
        &[br#""must-wait-for-policy""#.to_vec()],
    )
    .unwrap_err();

    assert!(matches!(
        error,
        MlsRuntimeError::EncryptionTransitionPending
    ));
    assert_eq!(state.mls_checkpoint_for(realm).unwrap().epoch, 0);
}

// ── receive-chain persistence (§5.6) ─────────────────

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
) -> (
    arkret_sdk::ArkretMlsGroup,
    Vec<arkret_sdk::MlsEndpointIdentity>,
) {
    let alice_actor = crate::test_support::account_actor("did:web:alice.example");
    let bob_actor_id = crate::test_support::account_actor(bob_actor);
    let alice = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
        alice_actor.clone(),
        arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000a1".to_owned())
            .unwrap(),
    )
    .unwrap();
    let bob = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
        bob_actor_id.clone(),
        arkret_sdk::DeviceId::new(bob_device.to_owned()).unwrap(),
    )
    .unwrap();
    let bob_key_package = crate::test_support::claimed_mls_key_package(
        bob.key_package_record().unwrap(),
        1_760_000_000_011,
    );
    let alice_endpoint = alice.endpoint_identity();
    let bob_endpoint = bob.endpoint_identity();
    let endpoints = vec![alice_endpoint, bob_endpoint];
    let effective_scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
    };
    let mut alice_group = alice.create_group(&effective_scope).unwrap();
    let add = alice_group.add_member(&bob_key_package).unwrap();
    let accepted_commit = crate::test_support::accepted_mls_commit(
        &effective_scope,
        alice_actor,
        &add.commit,
        arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x51; 32]),
        0x52,
    );
    let delivery = crate::test_support::accepted_mls_welcome(
        &add.welcome,
        bob_actor_id,
        &accepted_commit,
        1_760_000_000_012,
    );
    alice_group
        .install_accepted_commit(&accepted_commit)
        .unwrap();
    let mut bob_group = arkret_sdk::ArkretMlsGroup::join_from_verified_welcome_delivery(
        bob,
        &delivery,
        &accepted_commit,
    )
    .unwrap();
    bob_group
        .install_test_leaf_bindings(endpoints.clone())
        .unwrap();

    let secret = load_or_create_account_mls_secret(secure, &fixture::authority(bob_actor)).unwrap();
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
    state
        .save_mls_checkpoint(realm.to_owned(), envelope)
        .unwrap();
    (alice_group, endpoints)
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn historical_author_view_survives_epoch_rotation() {
    let mut state = temp_state_store("historical-author-view");
    let secure = MemorySecureKeyStore::new();
    let realm = "ak:realm:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000c2";
    let (mut alice_group, leaf_endpoints) =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    let epoch_one_snapshot = state.mls_checkpoint_for(realm).unwrap();
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
    let original_view = verified_author_group_view(
        &state,
        &secure,
        realm,
        &fixture::authority(bob_actor),
        &fixture::device_id(bob_device),
        &epoch_one_snapshot.group_id,
        epoch_one_snapshot.epoch,
        epoch_one_ref.as_str(),
    )
    .expect("current epoch author view");

    let secret = load_device_checkpoint_secret(
        &secure,
        &fixture::authority(bob_actor),
        &fixture::device_id(bob_device),
    )
    .unwrap();
    let mut bob_group =
        crate::mls::persistence::restore_envelope(&epoch_one_snapshot, &secret, 0).unwrap();
    let commit = alice_group.self_update_commit().unwrap();
    let effective_scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
    };
    let accepted_commit = crate::test_support::accepted_mls_commit(
        &effective_scope,
        crate::test_support::account_actor("did:web:alice.example"),
        &commit,
        epoch_one_ref.clone(),
        0x53,
    );
    alice_group
        .install_accepted_commit(&accepted_commit)
        .unwrap();
    bob_group.install_accepted_commit(&accepted_commit).unwrap();
    bob_group
        .install_test_leaf_bindings(leaf_endpoints)
        .unwrap();
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
    state
        .save_mls_checkpoint(realm, epoch_two_snapshot)
        .unwrap();

    let historical_view = verified_author_group_view(
        &state,
        &secure,
        realm,
        &fixture::authority(bob_actor),
        &fixture::device_id(bob_device),
        &epoch_one_snapshot.group_id,
        epoch_one_snapshot.epoch,
        epoch_one_ref.as_str(),
    )
    .expect("historical epoch author view");
    assert_eq!(historical_view, original_view);
    assert!(
        verified_author_group_view(
            &state,
            &secure,
            realm,
            &fixture::authority(bob_actor),
            &fixture::device_id(bob_device),
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

    let (mut alice_group, _) =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    let base_envelope = state.mls_checkpoint_for(realm).unwrap();

    let m1_header = test_message_header(&alice_group, realm);
    let m1 = alice_group
        .encrypt_payload(m1_header, br#"{"body":"m1"}"#)
        .unwrap();
    let m2_header = test_message_header(&alice_group, realm);
    let m2 = alice_group
        .encrypt_payload(m2_header, br#"{"body":"m2"}"#)
        .unwrap();

    // Decrypt m1: plaintext returned AND the persisted snapshot advanced
    // (same epoch, new ciphertext, observed-message counter bumped).
    let plain1 = decrypt_application_payload_for_effective_scope_internal(
        &state,
        &secure,
        realm,
        &fixture::authority(bob_actor),
        &fixture::device_id(bob_device),
        &m1,
        None,
        None,
    )
    .expect("bob decrypts m1");
    assert_eq!(plain1, br#"{"body":"m1"}"#);
    let advanced = state.mls_checkpoint_for(realm).unwrap();
    assert_eq!(advanced.epoch, base_envelope.epoch);
    assert_ne!(advanced.ciphertext_hex, base_envelope.ciphertext_hex);
    assert_eq!(advanced.app_messages_observed, 1);

    // Same session: m1 re-renders from the in-memory plaintext cache (a ratchet
    // replay would fail — its message key was consumed before the write-back).
    let same_session_replay1 = decrypt_application_payload_for_effective_scope_internal(
        &state,
        &secure,
        realm,
        &fixture::authority(bob_actor),
        &fixture::device_id(bob_device),
        &m1,
        None,
        None,
    )
    .expect("m1 served from the in-session plaintext cache");
    assert_eq!(same_session_replay1, br#"{"body":"m1"}"#);

    // "Restart": a brand-new store over the same backing file must see
    // the advanced receive chain (NOT the pre-decrypt snapshot).
    let restarted = crate::state::LocalStateStore::with_path(path.clone());
    let reloaded = restarted.mls_checkpoint_for(realm).unwrap();
    assert_eq!(reloaded.ciphertext_hex, advanced.ciphertext_hex);
    // E2EE-at-rest: the plaintext cache is stripped before persist, so after a
    // real restart m1 is NOT recoverable — its ratchet key was consumed and its
    // plaintext was never written to durable storage.
    assert!(
        decrypt_application_payload_for_effective_scope_internal(
            &restarted,
            &secure,
            realm,
            &fixture::authority(bob_actor),
            &fixture::device_id(bob_device),
            &m1,
            None,
            None,
        )
        .is_none(),
        "consumed-message plaintext must never survive a restart (nothing at rest)"
    );
    // m2 (the next generation in the same epoch) still decrypts from the
    // persisted advanced chain.
    let plain2 = decrypt_application_payload_for_effective_scope_internal(
        &restarted,
        &secure,
        realm,
        &fixture::authority(bob_actor),
        &fixture::device_id(bob_device),
        &m2,
        None,
        None,
    )
    .expect("bob decrypts m2 after restart");
    assert_eq!(plain2, br#"{"body":"m2"}"#);
    assert_eq!(
        restarted
            .mls_checkpoint_for(realm)
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

    let (mut alice_group, _) =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    let circle_snapshot = state.mls_checkpoint_for(realm).unwrap();
    state.drop_mls_checkpoint_for_test(realm);
    state
        .save_mls_checkpoint_for_effective_scope(
            realm.to_owned(),
            Some(circle),
            circle_snapshot.clone(),
        )
        .expect("valid effective scope");
    let header = test_message_header(&alice_group, realm);
    let encrypted = alice_group
        .encrypt_payload(header, br#"{"body":"sidecar"}"#)
        .unwrap();

    assert!(
        decrypt_application_payload_for_effective_scope_internal(
            &state,
            &secure,
            realm,
            &fixture::authority(bob_actor),
            &fixture::device_id(bob_device),
            &encrypted,
            None,
            None,
        )
        .is_none(),
        "Realm-scoped decrypt must not borrow a Circle snapshot"
    );
    let plaintext = decrypt_application_payload_for_effective_scope_internal(
        &state,
        &secure,
        realm,
        &fixture::authority(bob_actor),
        &fixture::device_id(bob_device),
        &encrypted,
        Some(circle),
        None,
    )
    .expect("Circle-scoped message decrypts with the Circle snapshot");
    assert_eq!(plaintext, br#"{"body":"sidecar"}"#);
    assert!(state.mls_checkpoint_for(realm).is_none());
    let advanced = state
        .mls_checkpoint_for_effective_scope(realm, Some(circle))
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

    let (mut alice_group, _) =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    let m1_header = test_message_header(&alice_group, realm);
    let m1 = alice_group.encrypt_payload(m1_header, br#""one""#).unwrap();
    let m2_header = test_message_header(&alice_group, realm);
    let _m2 = alice_group.encrypt_payload(m2_header, br#""two""#).unwrap();
    let m3_header = test_message_header(&alice_group, realm);
    let m3 = alice_group
        .encrypt_payload(m3_header, br#""three""#)
        .unwrap();

    // Out-of-order: m3 first (within OpenMLS's default
    // out_of_order_tolerance of 5).
    let plain3 = decrypt_application_payload_for_effective_scope_internal(
        &state,
        &secure,
        realm,
        &fixture::authority(bob_actor),
        &fixture::device_id(bob_device),
        &m3,
        None,
        None,
    )
    .expect("bob decrypts m3 ahead of m1/m2");
    assert_eq!(plain3, br#""three""#);

    // Restart, then decrypt the skipped earlier message.
    let restarted = crate::state::LocalStateStore::with_path(path.clone());
    let plain1 = decrypt_application_payload_for_effective_scope_internal(
        &restarted,
        &secure,
        realm,
        &fixture::authority(bob_actor),
        &fixture::device_id(bob_device),
        &m1,
        None,
        None,
    )
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

    super::seed_human_creator_authorization(actor, device);
    seed_complete_rfc9420_projection(&mut state, realm, actor);
    ensure_creator_mls_checkpoint(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
    )
    .unwrap();
    super::seed_current_group_state_ref(&mut state, realm);
    let (_, encrypted_values) = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
        "application/json",
        &[br#""mine""#.to_vec()],
    )
    .unwrap();
    let payload: arkret_sdk::EncryptedPayload =
        serde_json::from_value(encrypted_values[0].clone()).unwrap();
    let after_send = state.mls_checkpoint_for(realm).unwrap();

    let decrypted = decrypt_application_payload_for_effective_scope_internal(
        &state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
        &payload,
        None,
        None,
    );
    assert!(decrypted.is_none(), "author must not decrypt own message");
    // No cache entry and no snapshot churn from the failed attempt.
    assert!(
        state
            .mls_decrypted_plaintext_for(realm, payload.payload_digest.as_str())
            .is_none()
    );
    assert_eq!(
        state.mls_checkpoint_for(realm).unwrap().ciphertext_hex,
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

    let (mut alice_group, _) =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    let header = test_message_header(&alice_group, realm);
    let m1 = alice_group.encrypt_payload(header, br#""cached""#).unwrap();
    let first = decrypt_application_payload_for_effective_scope_internal(
        &state,
        &secure,
        realm,
        &fixture::authority(bob_actor),
        &fixture::device_id(bob_device),
        &m1,
        None,
        None,
    )
    .expect("first decrypt");
    assert_eq!(first, br#""cached""#);

    state.drop_mls_checkpoint_for_test(realm);
    assert!(state.mls_checkpoint_for(realm).is_none());
    let cached = decrypt_application_payload_for_effective_scope_internal(
        &state,
        &secure,
        realm,
        &fixture::authority(bob_actor),
        &fixture::device_id(bob_device),
        &m1,
        None,
        None,
    )
    .expect("cache hit requires no group state");
    assert_eq!(cached, br#""cached""#);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_write_without_current_mls_group_is_fail_closed() {
    let mut state = temp_state_store("missing-group");
    let store = MemorySecureKeyStore::new();
    let error = encrypt_values_with_device_snapshot(
        &mut state,
        &store,
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        &fixture::authority("did:web:alice.example"),
        &fixture::device_id("ak:device:01904100-0000-7000-8000-000000000001"),
        "text/plain",
        &[b"secret".to_vec()],
    )
    .unwrap_err();
    assert!(matches!(error, MlsRuntimeError::MissingWelcome));
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
        .save_mls_checkpoint(
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            envelope,
        )
        .unwrap();
    super::seed_current_group_state_ref(
        &mut state,
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
    );

    let error = encrypt_values_with_device_snapshot(
        &mut state,
        &store,
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        &fixture::authority("did:web:alice.example"),
        &fixture::device_id("ak:device:01904100-0000-7000-8000-000000000001"),
        "text/plain",
        &[b"secret".to_vec()],
    )
    .unwrap_err();

    assert!(matches!(
        error,
        MlsRuntimeError::DeviceSecret(SecureKeyStoreError::NotFound)
    ));
    assert!(store.list_secret_keys(None).unwrap().is_empty());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_write_uses_device_key_snapshot_when_ready() {
    use arkret_sdk::{ArkretMlsIdentity, DeviceId};

    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy";
    let store = MemorySecureKeyStore::new();
    let secret = load_or_create_account_mls_secret(&store, &fixture::authority(actor)).unwrap();
    let identity = ArkretMlsIdentity::new_test_human_device(
        crate::test_support::account_actor(actor),
        DeviceId::new(device.to_owned()).unwrap(),
    )
    .unwrap();
    let effective_scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm).unwrap(),
    };
    let mut group = identity.create_group(&effective_scope).unwrap();
    group
        .install_local_creator_binding(
            arkret_sdk::ActorId::account(fixture::authority(actor)),
            Some(
                arkret_sdk::EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1")
                    .unwrap(),
            ),
        )
        .unwrap();
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
    state.save_mls_checkpoint(realm, envelope).unwrap();
    super::seed_current_group_state_ref(&mut state, realm);
    seed_complete_rfc9420_projection(&mut state, realm, actor);

    let (member_ids, encrypted_values) = encrypt_values_with_device_snapshot(
        &mut state,
        &store,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
        "text/plain",
        &[b"secret".to_vec()],
    )
    .unwrap();

    assert_eq!(member_ids.len(), 1);
    assert_eq!(encrypted_values.len(), 1);
    assert!(encrypted_values[0].get("ciphertext").is_some());
    assert!(state.mls_checkpoint_for(realm).is_some());
}

/// 0352 D1: a cached old profile marker cannot select a legacy epoch cap or
/// authorize ordinary encryption; reject before touching an MLS checkpoint.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn retired_minimal_metadata_marker_blocks_encryption_before_checkpoint_access() {
    let actor = "did:web:minimal-counter.example";
    let device = "ak:device:01964137-0000-7000-8000-0000000000c1";
    let secure = MemorySecureKeyStore::new();
    let mut state = temp_state_store("minimal-counter-transition-fence");
    let realm = "ak:realm:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk";

    state.save_realm_tree_projection(
        realm,
        json!({
            "schema_refs": ["ak.profile.mls.minimal_metadata_realm.v1"],
            "member_roster_entries_limited": false,
            "member_roster_entries": [{
                "actor_id": arkret_sdk::ActorId::account(fixture::authority(actor)),
                "membership": "join"
            }]
        }),
    );
    assert!(state.realm_projection_has_retired_minimal_metadata_marker(realm));

    let error = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
        "application/vnd.arkret.test+json",
        &[br#""private""#.to_vec()],
    )
    .unwrap_err();
    assert!(
        matches!(error, MlsRuntimeError::Identity(message) if message.contains("retired minimal-metadata"))
    );
    assert!(state.mls_checkpoint_for(realm).is_none());
}

// ── accepted MLS binding (`ak.component.mls.epoch.v1`) ─────────────────
