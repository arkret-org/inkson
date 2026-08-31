//! Tests for welcome application, application-payload encrypt / decrypt, and
//! §5.6 receive-chain persistence.

use serde_json::json;

use crate::mls::runtime::*;
use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore, SecureKeyStoreError};
use crate::state::isolated_store_for_tests as temp_state_store;

fn test_authority(actor: &str) -> arkret_sdk::AccountId {
    arkret_sdk::AccountId {
        principal_id: crate::mls_api_helpers::principal_core_id(actor).unwrap(),
        station_id: arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned())
            .unwrap(),
    }
}

fn test_device(device: &str) -> arkret_sdk::DeviceId {
    arkret_sdk::DeviceId::new(device.to_owned()).unwrap()
}

#[cfg(not(target_arch = "wasm32"))]
fn seed_complete_rfc9420_projection(
    state: &mut crate::state::LocalStateStore,
    realm: &str,
    actor: &str,
) {
    let actor_id = arkret_sdk::ActorId::account(test_authority(actor));
    state.save_realm_tree_projection(
        realm,
        json!({
            "content_scheme": "mls_rfc9420",
            "member_roster_entries_limited": false,
            "member_roster_entries": [{ "actor_id": actor_id, "membership": "join" }]
        }),
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
fn creator_snapshot_bootstrap_makes_space_encryptable() {
    let mut state = temp_state_store("creator-bootstrap");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    super::seed_genesis_governance_proof(&mut state, realm);
    super::seed_human_creator_authorization(actor, device);
    state.save_realm_tree_projection(
        realm,
        json!({
            "content_scheme": "mls_rfc9420",
            "member_roster_entries_limited": false,
            "member_roster_entries": [{
                "actor_id": arkret_sdk::ActorId::account(test_authority(actor)),
                "membership": "join"
            }]
        }),
    );
    let summary = ensure_creator_mls_snapshot(
        &mut state,
        &secure,
        realm,
        &test_authority(actor),
        &test_device(device),
    )
    .unwrap();

    let summary = summary.expect("missing creator snapshot should be created");
    assert_eq!(summary.realm_id, realm);
    assert_eq!(summary.epoch, 0);
    assert!(state.mls_snapshot_for(realm).is_some());
    super::seed_current_group_state_ref(&mut state, realm);
    // Ordinary application messages ride epoch 0; no commit event or
    // post-commit snapshot is returned.
    let encrypted = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &test_authority(actor),
        &test_device(device),
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
        &test_authority(actor),
        &test_device(device),
        "application/vnd.arkret.test+json",
        &[br#""private-again""#.to_vec()],
    )
    .unwrap();
    assert_eq!(encrypted_again.2.len(), 1);
    assert!(encrypted_again.3.is_none());
    assert!(encrypted_again.4.is_none());
    assert_eq!(state.mls_snapshot_for(realm).unwrap().epoch, 0);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn complete_membership_hint_does_not_alias_same_principal_at_another_station() {
    let mut state = temp_state_store("station-scoped-roster-hint");
    let secure = MemorySecureKeyStore::new();
    let principal = "did:web:alice.example";
    let authority = test_authority(principal);
    let device = test_device("ak:device:01904100-0000-7000-8000-000000000001");
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    super::seed_genesis_governance_proof(&mut state, realm);
    super::seed_human_creator_authorization(principal, device.as_str());
    seed_complete_rfc9420_projection(&mut state, realm, principal);
    ensure_creator_mls_snapshot(&mut state, &secure, realm, &authority, &device).unwrap();
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
            "content_scheme": "mls_rfc9420",
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

    super::seed_genesis_governance_proof(&mut state, realm);
    super::seed_human_creator_authorization(actor, device);
    seed_complete_rfc9420_projection(&mut state, realm, actor);
    ensure_creator_mls_snapshot(
        &mut state,
        &secure,
        realm,
        &test_authority(actor),
        &test_device(device),
    )
    .unwrap()
    .expect("creator snapshot");
    super::seed_current_group_state_ref(&mut state, realm);

    let effective_scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm).unwrap(),
    };
    let snapshot = state.mls_snapshot_for_scope(&effective_scope).unwrap();
    let group_state_ref = state
        .mls_group_state_ref_for_scope(&effective_scope, &snapshot.group_id, snapshot.epoch)
        .unwrap();
    let (_, _, content_payload, metadata_payload, commit, snapshot, _) =
        encrypt_message_with_device_snapshot(
            &mut state,
            &secure,
            realm,
            &test_authority(actor),
            &test_device(device),
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

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn replacement_sender_domain_blocks_before_counter_advance() {
    let mut state = temp_state_store("replacement-sender-fence");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:Ae1aXR7egHsJjC7lxnkHz8popOxRV27nKlKY8RDyuOBb";

    super::seed_genesis_governance_proof(&mut state, realm);
    super::seed_human_creator_authorization(actor, device);
    seed_complete_rfc9420_projection(&mut state, realm, actor);
    ensure_creator_mls_snapshot(
        &mut state,
        &secure,
        realm,
        &test_authority(actor),
        &test_device(device),
    )
    .unwrap()
    .expect("creator snapshot");
    let effective_scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm).unwrap(),
    };
    super::seed_current_group_state_ref(&mut state, realm);
    let before = state.mls_snapshot_for_scope(&effective_scope).unwrap();
    let group_state_ref = arkret_sdk::EventId::new(
        "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM".to_owned(),
    )
    .unwrap();
    let error = encrypt_message_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &test_authority(actor),
        &test_device(device),
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
    .unwrap_err();
    assert!(matches!(
        error,
        MlsRuntimeError::EncryptionTransitionPending
    ));
    assert_eq!(state.mls_snapshot_for_scope(&effective_scope), Some(before));
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
    super::seed_human_creator_authorization(actor, device);
    ensure_creator_mls_snapshot(
        &mut state,
        &secure,
        realm,
        &test_authority(actor),
        &test_device(device),
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
                    "actor_id": arkret_sdk::ActorId::account(test_authority(actor)),
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
        &test_authority(actor),
        &test_device(device),
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
    super::seed_human_creator_authorization(actor, device);
    ensure_creator_mls_snapshot(
        &mut state,
        &secure,
        realm,
        &test_authority(actor),
        &test_device(device),
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
                "actor_id": arkret_sdk::ActorId::account(test_authority(actor)),
                "membership": "join"
            }]
        }),
    );

    let error = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &test_authority(actor),
        &test_device(device),
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
async fn authoring_exporter_aead_content_requires_accepted_transition_evidence() {
    let mut state = temp_state_store("author-retains-history-secret");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    // History-secret persistence is process-global secure storage keyed by the
    // exact scope/group pair, so this test uses a unique Realm.
    let realm = "ak:realm:Ae6wQDaXscJ6lZGbcWqFv_CW7o0_w5CGmtuB6TvlwNh2";
    super::seed_genesis_governance_proof(&mut state, realm);
    super::seed_human_creator_authorization(actor, device);
    ensure_creator_mls_snapshot(
        &mut state,
        &secure,
        realm,
        &test_authority(actor),
        &test_device(device),
    )
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

    let error = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &test_authority(actor),
        &test_device(device),
        "application/vnd.arkret.test+json",
        &[br#""private""#.to_vec()],
    )
    .unwrap_err();
    assert!(matches!(
        error,
        MlsRuntimeError::EncryptionTransitionPending
    ));
    assert!(state.history_secret_for(&scope, &group_id, 0).is_none());
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
) -> (
    arkret_sdk::ArkretMlsGroup,
    Vec<arkret_sdk::MlsEndpointIdentity>,
) {
    let alice = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
        crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap(),
        arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000a1".to_owned())
            .unwrap(),
    )
    .unwrap();
    let bob = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
        crate::mls_api_helpers::principal_core_id(bob_actor).unwrap(),
        arkret_sdk::DeviceId::new(bob_device.to_owned()).unwrap(),
    )
    .unwrap();
    let bob_key_package = bob.key_package_record().unwrap();
    let alice_endpoint = alice.endpoint_identity();
    let bob_endpoint = bob.endpoint_identity();
    let endpoints = vec![alice_endpoint, bob_endpoint];
    let mut alice_group = alice.create_group(realm.as_bytes()).unwrap();
    let add = alice_group.add_member(&bob_key_package).unwrap();
    let mut bob_group = arkret_sdk::ArkretMlsGroup::join_from_welcome(bob, &add.welcome).unwrap();
    bob_group
        .install_test_leaf_bindings(endpoints.clone())
        .unwrap();

    let secret = load_or_create_account_mls_secret(secure, &test_authority(bob_actor)).unwrap();
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
        &test_authority(bob_actor),
        &test_device(bob_device),
        &epoch_one_snapshot.group_id,
        epoch_one_snapshot.epoch,
        epoch_one_ref.as_str(),
    )
    .expect("current epoch author view");

    let secret = load_device_snapshot_secret(
        &secure,
        &test_authority(bob_actor),
        &test_device(bob_device),
    )
    .unwrap();
    let mut bob_group =
        crate::mls::persistence::restore_envelope(&epoch_one_snapshot, &secret, 0).unwrap();
    let commit = alice_group.self_update_commit().unwrap();
    bob_group.apply_commit(&commit).unwrap();
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
    state.save_mls_snapshot(realm, epoch_two_snapshot).unwrap();

    let historical_view = minimal_metadata_author_view(
        &state,
        &secure,
        realm,
        &test_authority(bob_actor),
        &test_device(bob_device),
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
            &test_authority(bob_actor),
            &test_device(bob_device),
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
    let base_envelope = state.mls_snapshot_for(realm).unwrap();

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
        &test_authority(bob_actor),
        &test_device(bob_device),
        &m1,
        None,
        None,
    )
    .expect("bob decrypts m1");
    assert_eq!(plain1, br#"{"body":"m1"}"#);
    let advanced = state.mls_snapshot_for(realm).unwrap();
    assert_eq!(advanced.epoch, base_envelope.epoch);
    assert_ne!(advanced.ciphertext_hex, base_envelope.ciphertext_hex);
    assert_eq!(advanced.app_messages_observed, 1);

    // Same session: m1 re-renders from the in-memory plaintext cache (a ratchet
    // replay would fail — its message key was consumed before the write-back).
    let same_session_replay1 = decrypt_application_payload_for_effective_scope_internal(
        &state,
        &secure,
        realm,
        &test_authority(bob_actor),
        &test_device(bob_device),
        &m1,
        None,
        None,
    )
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
        decrypt_application_payload_for_effective_scope_internal(
            &restarted,
            &secure,
            realm,
            &test_authority(bob_actor),
            &test_device(bob_device),
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
        &test_authority(bob_actor),
        &test_device(bob_device),
        &m2,
        None,
        None,
    )
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

    let (mut alice_group, _) =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    let circle_snapshot = state.mls_snapshot_for(realm).unwrap();
    state.drop_mls_snapshot_for_test(realm);
    state
        .save_mls_snapshot_for_effective_scope(
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
            &test_authority(bob_actor),
            &test_device(bob_device),
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
        &test_authority(bob_actor),
        &test_device(bob_device),
        &encrypted,
        Some(circle),
        None,
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
        &test_authority(bob_actor),
        &test_device(bob_device),
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
        &test_authority(bob_actor),
        &test_device(bob_device),
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

    super::seed_genesis_governance_proof(&mut state, realm);
    super::seed_human_creator_authorization(actor, device);
    seed_complete_rfc9420_projection(&mut state, realm, actor);
    ensure_creator_mls_snapshot(
        &mut state,
        &secure,
        realm,
        &test_authority(actor),
        &test_device(device),
    )
    .unwrap();
    super::seed_current_group_state_ref(&mut state, realm);
    let (_, _, encrypted_values, ..) = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &test_authority(actor),
        &test_device(device),
        "application/json",
        &[br#""mine""#.to_vec()],
    )
    .unwrap();
    let payload: arkret_sdk::EncryptedPayload =
        serde_json::from_value(encrypted_values[0].clone()).unwrap();
    let after_send = state.mls_snapshot_for(realm).unwrap();

    let decrypted = decrypt_application_payload_for_effective_scope_internal(
        &state,
        &secure,
        realm,
        &test_authority(actor),
        &test_device(device),
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

    let (mut alice_group, _) =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    let header = test_message_header(&alice_group, realm);
    let m1 = alice_group.encrypt_payload(header, br#""cached""#).unwrap();
    let first = decrypt_application_payload_for_effective_scope_internal(
        &state,
        &secure,
        realm,
        &test_authority(bob_actor),
        &test_device(bob_device),
        &m1,
        None,
        None,
    )
    .expect("first decrypt");
    assert_eq!(first, br#""cached""#);

    state.drop_mls_snapshot_for_test(realm);
    assert!(state.mls_snapshot_for(realm).is_none());
    let cached = decrypt_application_payload_for_effective_scope_internal(
        &state,
        &secure,
        realm,
        &test_authority(bob_actor),
        &test_device(bob_device),
        &m1,
        None,
        None,
    )
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
    super::seed_current_group_state_ref(
        &mut state,
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
    );

    let error = encrypt_values_with_device_snapshot(
        &mut state,
        &store,
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        &test_authority("did:web:alice.example"),
        &test_device("ak:device:01904100-0000-7000-8000-000000000001"),
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
    let secret = load_or_create_account_mls_secret(&store, &test_authority(actor)).unwrap();
    let identity = ArkretMlsIdentity::new_test_human_device(
        crate::mls_api_helpers::principal_core_id(actor).unwrap(),
        DeviceId::new(device.to_owned()).unwrap(),
    )
    .unwrap();
    let mut group = identity.create_group(realm.as_bytes()).unwrap();
    group
        .install_local_creator_binding(
            arkret_sdk::ActorId::account(test_authority(actor)),
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
    state.save_mls_snapshot(realm, envelope).unwrap();
    super::seed_current_group_state_ref(&mut state, realm);
    seed_complete_rfc9420_projection(&mut state, realm, actor);

    let (_schedule_hash, member_ids, encrypted_values, _commit, _new_envelope, _) =
        encrypt_values_with_device_snapshot(
            &mut state,
            &store,
            realm,
            &test_authority(actor),
            &test_device(device),
            "text/plain",
            &[b"secret".to_vec()],
        )
        .unwrap();

    assert_eq!(member_ids.len(), 1);
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
fn minimal_overdue_epoch_blocks_before_counter_advance() {
    let actor = "did:web:minimal-counter.example";
    let device = "ak:device:01964137-0000-7000-8000-0000000000c1";
    let secure = MemorySecureKeyStore::new();
    let _ = load_or_create_account_mls_secret(&secure, &test_authority(actor)).unwrap();
    crate::identity::authoring_generation::cache_verified_principal_generation_for_test(
        crate::mls_api_helpers::principal_core_id(actor)
            .unwrap()
            .as_str(),
        device,
        "ak:event:AYwRmQJZYC4bmkTzqa4XVqbjE6FJmJxq4OTxMe44Ned1",
    );
    let mut state = temp_state_store("minimal-counter-transition-fence");
    let realm = "ak:realm:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk";

    state.save_realm_tree_projection(
        realm,
        json!({
            "schema_refs": [arkret_sdk::ProfileId::MLS_MINIMAL_METADATA_REALM_V1],
            "content_scheme": "mls_rfc9420",
            "member_roster_entries_limited": false,
            "member_roster_entries": [{
                "actor_id": arkret_sdk::ActorId::account(test_authority(actor)),
                "membership": "join"
            }]
        }),
    );
    assert!(state.realm_projection_is_minimal_metadata(realm));

    // Genesis installs the epoch-0 snapshot.
    super::seed_genesis_governance_proof(&mut state, realm);
    super::seed_human_creator_authorization(actor, device);
    ensure_creator_mls_snapshot(
        &mut state,
        &secure,
        realm,
        &test_authority(actor),
        &test_device(device),
    )
    .unwrap()
    .expect("creator snapshot created");
    let before = state.mls_snapshot_for(realm).unwrap();
    let mut overdue = state.mls_snapshot_for(realm).unwrap();
    overdue.epoch_started_at = chrono::Utc::now() - chrono::Duration::hours(2);
    state.save_mls_snapshot(realm, overdue).unwrap();
    let overdue_snapshot = state.mls_snapshot_for(realm).unwrap();

    let error = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &test_authority(actor),
        &test_device(device),
        "application/vnd.arkret.test+json",
        &[br#""private""#.to_vec()],
    )
    .unwrap_err();
    assert!(matches!(
        error,
        MlsRuntimeError::EncryptionTransitionPending
    ));
    assert_eq!(state.mls_snapshot_for(realm), Some(overdue_snapshot));
    assert_eq!(before.app_messages_observed, 0);
}

#[test]
fn empty_welcome_set_reports_no_work() {
    let mut state = temp_state_store("empty");
    let store = MemorySecureKeyStore::new();
    let outcome = apply_welcome_messages_with_device_snapshot(
        &mut state,
        &store,
        "ak:realm:Awkt11sH1cqYGNwG-NdGAvUk2xwJeJ7AC-93lG5ups2U",
        &test_authority("did:web:alice.example"),
        "did:web:alice.example",
        &test_device("ak:device:01904100-0000-7000-8000-000000000001"),
        &json!({ "messages": [] }),
    )
    .unwrap();
    assert_eq!(outcome, WelcomeApplyOutcome::default());
    assert_eq!(outcome.applied, 0);
    assert_eq!(outcome.failed, 0);
    assert!(outcome.first_error.is_none());
    // No welcomes present => no secret was created either.
    assert!(store.list_secret_keys(None).unwrap().is_empty());
}

#[test]
fn malformed_welcome_is_counted_not_swallowed() {
    let mut state = temp_state_store("malformed");
    let store = MemorySecureKeyStore::new();
    store_account_mls_secret(
        &store,
        &test_authority("did:web:alice.example"),
        "snapshot-secret",
    )
    .unwrap();
    // A welcome entry whose content is not a valid durable MlsWelcomePayload.
    let messages = json!({
        "messages": [
            { "kind": "ak.mls.welcome", "content": { "not": "a welcome" } }
        ]
    });
    let outcome = apply_welcome_messages_with_device_snapshot(
        &mut state,
        &store,
        "ak:realm:Ae4L5dU13P9VksvkJAOF29Z7lsbKvgUqVqVh7q2H-E2I",
        &test_authority("did:web:alice.example"),
        "did:web:alice.example",
        &test_device("ak:device:01904100-0000-7000-8000-000000000001"),
        &messages,
    )
    .unwrap();
    assert_eq!(outcome.applied, 0);
    assert_eq!(outcome.failed, 1);
    assert!(outcome.first_error.is_some());
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test(flavor = "current_thread")]
async fn welcome_consume_redelivery_reuses_exact_signed_body_and_rejects_drift() {
    let store = MemorySecureKeyStore::new();
    let actor_did = "did:web:alice.example";
    let authority = test_authority(actor_did);
    let device = test_device("ak:device:01904100-0000-7000-8000-000000000001");
    let identity = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
        authority.principal_id.clone(),
        device.clone(),
    )
    .unwrap();
    let key_package = identity.key_package_record().unwrap();
    store_mls_key_package_identity_state(
        &store,
        &authority,
        &device,
        &key_package.keypackage_id,
        &identity.export_private_state().unwrap(),
    )
    .unwrap();
    let verification_method = format!("{actor_did}#{}", device.as_str());
    let signer = std::sync::Arc::new(
        crate::event_signer::build_ed25519_signer_with_verification_method(
            [19u8; 32],
            actor_did,
            verification_method,
        ),
    );
    let _signer_guard = crate::event_signer::ActiveSignerTestGuard::replace(Some(signer));
    let candidate = WelcomeConsumeCandidate {
        key_package_id: key_package.keypackage_id,
        claim_id: "claim-exact-replay".to_owned(),
        claim_request_id: arkret_sdk::Base64UrlString::new("Y2xhaW0tcmVxdWVzdA").unwrap(),
        recipient_principal_id: authority.principal_id.clone(),
        recipient: arkret_sdk::MlsWelcomeRecipient::Device {
            recipient_device_id: device.clone(),
        },
        recipient_id: authority.principal_id.clone(),
        welcome_event_id: "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM".to_owned(),
        realm_id: "ak:realm:AYlS_mnxn8_f65A0YrWEeLzd0F1vnM347xZzMSQEcrlz".to_owned(),
        strand_id: None,
        mls_group_id: "mls-group-exact-replay".to_owned(),
        epoch: 1,
        welcome_digest: arkret_sdk::Hash::new(
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap(),
    };

    let first = sign_welcome_consume_request(&store, &authority, &device, &candidate)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let replay = sign_welcome_consume_request(&store, &authority, &device, &candidate)
        .await
        .unwrap();
    assert_eq!(
        arkret_sdk::canonical::canonical_json_bytes(&first).unwrap(),
        arkret_sdk::canonical::canonical_json_bytes(&replay).unwrap(),
        "Welcome redelivery must reuse durable_at and both exact signatures"
    );
    assert_eq!(
        first.recipient_durable_receipt.signature.sig,
        replay.recipient_durable_receipt.signature.sig
    );
    assert_eq!(first.signature.sig, replay.signature.sig);

    let mut drifted = candidate;
    drifted.epoch += 1;
    let error = sign_welcome_consume_request(&store, &authority, &device, &drifted)
        .await
        .unwrap_err();
    assert!(error.contains("conflicts with Welcome claim_id=claim-exact-replay"));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn retired_direct_welcome_envelope_does_not_persist_snapshot_or_consume_keypackage_state() {
    let mut state = temp_state_store("welcome-keypackage-state");
    let store = MemorySecureKeyStore::new();
    let realm = "ak:realm:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000c2";
    let alice = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
        crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap(),
        arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000a1".to_owned())
            .unwrap(),
    )
    .unwrap();
    let bob = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
        crate::mls_api_helpers::principal_core_id(bob_actor).unwrap(),
        arkret_sdk::DeviceId::new(bob_device.to_owned()).unwrap(),
    )
    .unwrap();
    let bob_key_package = bob.key_package_record().unwrap();
    let bob_private_state = bob.export_private_state().unwrap();
    store_mls_key_package_identity_state(
        &store,
        &test_authority(bob_actor),
        &test_device(bob_device),
        &bob_key_package.keypackage_id,
        &bob_private_state,
    )
    .unwrap();
    store_account_mls_secret(&store, &test_authority(bob_actor), "snapshot-secret").unwrap();
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
        &mut state,
        &store,
        realm,
        &test_authority(bob_actor),
        bob_actor,
        &test_device(bob_device),
        &messages,
    )
    .unwrap();

    assert_eq!(outcome.applied, 0);
    assert_eq!(outcome.failed, 1);
    assert!(
        outcome
            .first_error
            .as_deref()
            .is_some_and(|reason| reason.contains("mls_group_id"))
    );
    assert!(
        state.mls_snapshot_for(realm).is_none(),
        "a retired direct Welcome envelope must never persist joined MLS state"
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
            &test_authority(bob_actor),
            &test_device(bob_device),
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
    store_account_mls_secret(
        &store,
        &test_authority("did:web:alice.example"),
        "snapshot-secret",
    )
    .unwrap();
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
        &test_authority("did:web:alice.example"),
        "did:web:alice.example",
        &test_device("ak:device:01904100-0000-7000-8000-000000000001"),
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
            .contains(arkret_sdk::error_codes::ReasonCode::KEYPACKAGE_WELCOME_ENVELOPE_MISMATCH)
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

fn embedded_pairwise_welcome_value() -> serde_json::Value {
    arkret_schema_conformance::spec_json_artifact("fixtures/keypackage-pairwise-welcome-fixture.json").unwrap()
        ["schema_validation_cases"][0]["instance"]
        .clone()
}

#[test]
fn welcome_claim_receipt_context_must_match_exact_requester_realm_group_and_target() {
    let valid = embedded_pairwise_welcome_value();
    let typed: arkret_sdk::MlsWelcomePayload = serde_json::from_value(valid.clone()).unwrap();
    assert!(validate_welcome_claim_receipt_context(&typed).is_ok());

    for (name, path, replacement) in [
        (
            "requester_id",
            vec!["claim_receipt", "request", "requester_id"],
            json!("ak:did_core:webvh:z6mkfixturebobexample"),
        ),
        (
            "realm",
            vec!["claim_receipt", "request", "intended_realm_id"],
            json!("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"),
        ),
        (
            "group",
            vec!["claim_receipt", "request", "mls_group_id"],
            json!("different-fixture-group"),
        ),
        (
            "target",
            vec!["claim_receipt", "request", "target_principal_id"],
            json!("ak:did_core:webvh:z6mkfixture"),
        ),
    ] {
        let mut mismatched = valid.clone();
        let mut cursor = &mut mismatched;
        for segment in &path[..path.len() - 1] {
            cursor = cursor.get_mut(*segment).unwrap();
        }
        cursor[path[path.len() - 1]] = replacement;
        let typed: arkret_sdk::MlsWelcomePayload = serde_json::from_value(mismatched).unwrap();
        assert!(
            validate_welcome_claim_receipt_context(&typed).is_err(),
            "mismatched {name} context was accepted"
        );
    }
}

#[test]
fn legacy_direct_welcome_envelope_is_not_a_durable_payload() {
    let legacy = json!({
        "group_id": "fixture-group",
        "epoch": 1,
        "welcome": "AQID",
        "welcome_hash": "sha256:039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81"
    });
    assert!(durable_welcome_payload_reject_reason(&legacy).is_some());
    assert!(decode_welcome_envelope(&legacy).is_err());
}

#[test]
fn local_welcome_hint_filters_by_realm_group_id() {
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let other_realm = "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    let messages = vec![
        json!({
            "kind": "ak.mls.welcome",
            "content": {
                "mls_group_id": mls_group_id_for_realm(realm).unwrap(),
            },
            "unsigned": {
                "mls_welcome_id": "ak:mls_welcome:01904100-0000-7000-8000-0000000000aa",
            },
        }),
        json!({
            "kind": "ak.mls.welcome",
            "content": {
                "mls_group_id": mls_group_id_for_realm(other_realm).unwrap(),
                "claim_envelope": {
                    "welcome_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                },
            },
        }),
        json!({
            "kind": "ak.mls.welcome",
            "content": {
                "group_id": mls_group_id_for_realm(realm).unwrap(),
                "welcome_hash": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            },
        }),
        json!({
            "kind": "ak.key.verification.request",
            "content": {
                "mls_group_id": mls_group_id_for_realm(realm).unwrap(),
            },
        }),
    ];

    assert_eq!(
        collect_mls_welcome_messages_for_realm(&messages, realm).len(),
        1
    );
    assert!(!mls_welcome_message_matches_realm(&messages[2], realm));
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
fn minimal_exporter_sender_domain_uses_the_active_pairwise_leaf() {
    let device = "ak:device:01904100-0000-7000-8000-0000000000a1";
    assert!(verify_exporter_sender_domain_for_send(device, true, true).is_ok());
}
