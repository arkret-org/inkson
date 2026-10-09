//! Tests for welcome application, application-payload encrypt / decrypt, and
//! §5.6 receive-chain persistence.

use serde_json::json;

use crate::mls::runtime::*;
use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore, SecureKeyStoreError};
use crate::state::isolated_store_for_tests as temp_state_store;
use crate::test_support as fixture;

#[cfg(not(target_arch = "wasm32"))]
fn accepted_mls_base_current(
    effective_scope: &arkret_sdk::ScopeRef,
    genesis_event_ref: arkret_sdk::EventId,
    current_event_ref: arkret_sdk::EventId,
    epoch: u64,
) -> arkret_wire::MlsGroupCurrent {
    arkret_wire::MlsGroupCurrent {
        effective_scope: effective_scope.clone(),
        genesis_event_ref,
        cipher_suite: arkret_wire::NonEmptyString::new(
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        )
        .unwrap(),
        current_mls_commit_event_ref: current_event_ref,
        epoch,
        current_key_access_revision: 0,
        covered_key_access_revision: 0,
        public_tree_ref: arkret_sdk::BlobRef::new(format!("ak:blob:sha256:{}", "33".repeat(32)))
            .unwrap(),
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn coverage_commit_pins_durable_revision_when_product_view_lags() {
    // Creator fixtures share the session tests' exact device-directory cache.
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
    let mut state = temp_state_store("coverage-durable-binding");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let authority = fixture::authority(actor);
    let device = fixture::device_id("ak:device:01904100-0000-7000-8000-000000000001");
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm).unwrap(),
    };
    super::seed_human_creator_authorization(actor, device.as_str());
    ensure_creator_mls_checkpoint_for_effective_scope(
        &mut state, &secure, realm, None, &authority, &device,
    )
    .unwrap();
    fixture::install_accepted_mls_group(&mut state, &scope);
    let mut durable = state.current_mls_group_for_scope(&scope).unwrap();
    let before = state.mls_checkpoint_for_scope(&scope).unwrap();
    state
        .record_mls_group_state_ref_for_scope(
            &scope,
            &before.group_id,
            before.epoch,
            durable.current_mls_commit_event_ref.clone(),
        )
        .unwrap();
    durable.current_key_access_revision = 7;
    let before = state.mls_checkpoint_for_scope(&scope).unwrap();
    assert_eq!(
        state
            .current_mls_group_for_scope(&scope)
            .unwrap()
            .current_key_access_revision,
        0
    );
    let binding = crate::mls::governance_proof::binding_for_current_transition(&durable).unwrap();
    let staged =
        force_epoch_rotation_commit_with_binding(&state, &secure, &binding, &authority, &device)
            .unwrap();
    let operation = crate::mls::group_events::mls_commit_event_with_binding(
        &state,
        actor,
        &staged.envelope,
        &binding,
    )
    .unwrap();
    assert_eq!(
        operation.payload()["governance_binding"],
        serde_json::to_value(&binding).unwrap()
    );
    assert_eq!(operation.payload()["covers_key_access_revision"], json!(7));
    assert_eq!(state.mls_checkpoint_for_scope(&scope), Some(before));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn circle_commit_restoration_uses_only_its_own_accepted_epoch() {
    // Creator fixtures share the session tests' exact device-directory cache.
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
    let mut state = temp_state_store("circle-own-commit-floor");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = fixture::device_id("ak:device:01904100-0000-7000-8000-000000000001");
    let authority = fixture::authority(actor);
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let circle = "ak:circle:AZSmUwZFkNevUaVm0adiKDKw0OuAQqfAX6DFwhnIqF9I";
    let realm_scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm).unwrap(),
    };
    let circle_scope = arkret_sdk::ScopeRef::Circle {
        realm_id: arkret_sdk::RealmId::new(realm).unwrap(),
        circle_id: arkret_sdk::CircleId::new(circle).unwrap(),
    };
    super::seed_human_creator_authorization(actor, device.as_str());
    ensure_creator_mls_checkpoint_for_effective_scope(
        &mut state,
        &secure,
        realm,
        Some(circle),
        &authority,
        &device,
    )
    .unwrap();
    fixture::install_accepted_mls_group_at_epoch(&mut state, &realm_scope, 7, 0);
    fixture::install_accepted_mls_group(&mut state, &circle_scope);
    let before = state.mls_checkpoint_for_scope(&circle_scope).unwrap();
    assert!(matches!(
        force_epoch_rotation_commit_for_effective_scope(
            &state,
            &secure,
            realm,
            Some(circle),
            &authority,
            &device,
        ),
        Err(MlsRuntimeError::Commit(_))
    ));
    let circle_base = state
        .current_mls_group_for_scope(&circle_scope)
        .unwrap()
        .current_mls_commit_event_ref;
    state
        .record_mls_group_state_ref_for_scope(
            &circle_scope,
            &before.group_id,
            before.epoch,
            circle_base,
        )
        .unwrap();
    let before = state.mls_checkpoint_for_scope(&circle_scope).unwrap();
    let staged = force_epoch_rotation_commit_for_effective_scope(
        &state,
        &secure,
        realm,
        Some(circle),
        &authority,
        &device,
    )
    .expect("the Circle's epoch-zero private state must not inherit the Realm's epoch-seven floor");
    assert_eq!(staged.staged_checkpoint.epoch, 0);
    assert_eq!(
        state.mls_checkpoint_for_scope(&circle_scope),
        Some(before.clone())
    );
    let state_ref = state
        .current_mls_group_for_scope(&circle_scope)
        .unwrap()
        .current_mls_commit_event_ref;
    let plaintext = arkret_sdk::canonical::canonical_json_bytes(&arkret_sdk::ContentBlock::text(
        "independent Circle",
    ))
    .unwrap();
    let (_, values) = encrypt_values_with_device_snapshot_for_effective_scope(
        &mut state,
        &secure,
        realm,
        &authority,
        &device,
        "application/vnd.arkret.message+json",
        &[plaintext.clone()],
        arkret_sdk::EventKind::MessageCreate.as_str(),
        state_ref.clone(),
        Some(circle),
        None,
    )
    .unwrap();
    assert_eq!(values.len(), 1);
    encrypt_message_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &authority,
        &device,
        "application/vnd.arkret.message+json",
        arkret_sdk::EventKind::MessageCreate.as_str(),
        state_ref,
        &plaintext,
        None,
        None,
        None,
        Some(circle),
        None,
    )
    .unwrap();
    let before = state.mls_checkpoint_for_scope(&circle_scope).unwrap();
    fixture::install_accepted_mls_group_at_epoch(&mut state, &circle_scope, 2, 0);
    assert!(
        matches!(
            force_epoch_rotation_commit_for_effective_scope(
                &state,
                &secure,
                realm,
                Some(circle),
                &authority,
                &device
            ),
            Err(MlsRuntimeError::CheckpointRestore(_))
        ),
        "the same private state is stale under its own accepted Circle epoch"
    );
    assert_eq!(state.mls_checkpoint_for_scope(&circle_scope), Some(before));
}

#[cfg(not(target_arch = "wasm32"))]
fn seed_complete_rfc9420_projection(
    state: &mut crate::state::LocalStateStore,
    realm: &str,
    actor: &str,
) {
    let actor_id = arkret_sdk::ActorId::account(fixture::authority(actor));
    fixture::install_complete_joined_members(state, realm, vec![actor_id]);
    seed_accepted_rfc9420_binding(state, realm);
}

/// The scope's accepted MLS Genesis, delivered the only way a client may learn
/// it: the Station's typed `mls_group` current result.
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
        arkret_sdk::EventContentRoutingContext::None,
    )
    .unwrap()
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn creator_realm_state_snapshot_bootstrap_makes_space_encryptable() {
    // Creator fixtures share the session tests' exact device-directory cache.
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
    let mut state = temp_state_store("creator-bootstrap");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    super::seed_human_creator_authorization(actor, device);
    fixture::install_complete_joined_members(
        &mut state,
        realm,
        vec![arkret_sdk::ActorId::account(fixture::authority(actor))],
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
    // Creator fixtures share the session tests' exact device-directory cache.
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
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
    fixture::install_complete_joined_members(&mut state, realm, vec![foreign.clone()]);
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

    fixture::install_complete_joined_members(
        &mut state,
        realm,
        vec![arkret_sdk::ActorId::account(authority.clone()), foreign],
    );
    assert_eq!(
        state
            .complete_joined_member_hint_for_realm(realm)
            .unwrap()
            .unwrap()
            .len(),
        2
    );
    assert!(
        serde_json::from_value::<arkret_wire::CurrentSelector>(json!({
            "kind": "member_state", "actor_id": principal,
        }))
        .is_err()
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn direct_epoch_zero_send_requires_exact_verified_founder_bootstrap_context() {
    // Creator fixtures share the session tests' exact device-directory cache.
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
    let mut state = temp_state_store("direct-provisional-sending");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:provisional-founder.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let authority = fixture::authority(actor);
    state
        .switch_active_account(&fixture::AccountFixture::new(actor).device(device).build())
        .unwrap();
    super::seed_human_creator_authorization(actor, device);
    seed_complete_rfc9420_projection(&mut state, realm, actor);
    ensure_creator_mls_checkpoint(
        &mut state,
        &secure,
        realm,
        &authority,
        &fixture::device_id(device),
    )
    .unwrap();
    let reference = super::seed_current_group_state_ref(&mut state, realm);
    let peer_account = fixture::authority("did:web:provisional-peer.example");
    let peer = arkret_sdk::contact_operations::ContactPeer::Human {
        account_id: peer_account.clone(),
    };
    let self_actor = arkret_sdk::ActorId::account(authority.clone());
    let pair = vec![
        self_actor.clone(),
        arkret_sdk::ActorId::account(peer_account),
    ];
    fixture::install_complete_joined_members(&mut state, realm, pair.clone());
    let ready = |state: &crate::state::LocalStateStore| {
        realm_mls_roster_matches_complete_membership_hint(
            state,
            &secure,
            realm,
            &authority,
            &fixture::device_id(device),
        )
    };
    assert_eq!(
        ready(&state),
        Some(false),
        "ordinary roster mismatch remains blocked"
    );
    state.save_realm_collaboration_role(
        realm,
        Some(arkret_sdk::CollaborationRealmRole::DirectConversation),
    );
    assert_eq!(
        ready(&state),
        Some(false),
        "Direct purpose alone cannot authorize"
    );
    state
        .save_direct_conversation_peer(realm.into(), peer.clone())
        .unwrap();
    let sequence = crate::mls::direct_binding::begin_query(&authority, &peer).unwrap();
    let context = crate::state::DirectMessageContext {
        account: authority.clone(),
        session_epoch: crate::identity::device_directory::session_cache_epoch(),
        query_sequence: sequence,
        authority_source: arkret_wire::AuthoritySourceId::DirectConversationBootstrapParticipantV1,
        authority_event_ref: arkret_sdk::EventId::new(realm.replace("ak:realm:", "ak:event:"))
            .unwrap(),
        group_state_ref: reference.clone(),
    };
    state.set_direct_message_context(realm.into(), Some(context.clone()));
    assert_eq!(ready(&state), Some(true));
    let (_, encrypted) = encrypt_values_with_device_snapshot_for_effective_scope(
        &mut state,
        &secure,
        realm,
        &authority,
        &fixture::device_id(device),
        "application/vnd.arkret.test+json",
        &[b"founder-only encrypted history".to_vec()],
        arkret_wire::event_kind_str::MESSAGE_CREATE,
        reference.clone(),
        None,
        None,
    )
    .unwrap();
    assert_eq!(encrypted.len(), 1);
    assert_eq!(state.mls_checkpoint_for(realm).unwrap().epoch, 0);
    assert_eq!(
        mls_group_member_actor_ids_for_effective_scope(
            &state,
            &secure,
            realm,
            None,
            &authority,
            &fixture::device_id(device)
        )
        .unwrap(),
        vec![self_actor.clone()]
    );
    let mut bound = context.clone();
    bound.authority_source = arkret_wire::AuthoritySourceId::DirectConversationParticipantV1;
    state.set_direct_message_context(realm.into(), Some(bound));
    assert_eq!(
        ready(&state),
        Some(false),
        "a bound group must cover the pair"
    );
    let mut foreign_founder = context.clone();
    foreign_founder.account = fixture::authority("did:web:another-founder.example");
    state.set_direct_message_context(realm.into(), Some(foreign_founder));
    assert_eq!(ready(&state), Some(false));
    let mut wrong_genesis = context.clone();
    wrong_genesis.authority_event_ref = reference.clone();
    state.set_direct_message_context(realm.into(), Some(wrong_genesis));
    assert_eq!(ready(&state), Some(false));
    let mut wrong_group = context.clone();
    wrong_group.group_state_ref =
        arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [77; 32]);
    state.set_direct_message_context(realm.into(), Some(wrong_group));
    assert_eq!(ready(&state), Some(false));
    state.set_direct_message_context(realm.into(), Some(context));
    fixture::install_complete_joined_members(
        &mut state,
        realm,
        vec![
            self_actor.clone(),
            arkret_sdk::ActorId::account(fixture::authority("did:web:third-person.example")),
        ],
    );
    assert_eq!(ready(&state), Some(false), "the exact peer must match");
    let mut three = pair;
    three.push(arkret_sdk::ActorId::account(fixture::authority(
        "did:web:third-person.example",
    )));
    fixture::install_complete_joined_members(&mut state, realm, three);
    assert_eq!(ready(&state), Some(false));
    fixture::install_complete_joined_members(
        &mut state,
        realm,
        vec![
            self_actor,
            arkret_sdk::ActorId::account(fixture::authority("did:web:provisional-peer.example")),
        ],
    );
    fixture::install_accepted_mls_group_at_epoch(
        &mut state,
        &arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(realm).unwrap(),
        },
        1,
        0,
    );
    assert_eq!(
        ready(&state),
        Some(false),
        "provisional history cannot use a stale epoch zero"
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
    // Creator fixtures share the session tests' exact device-directory cache.
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
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
    for (payload, plaintext) in [
        (
            &encrypted.content,
            br#"{"kind":"ak.content.text","body":"routed"}"#.as_slice(),
        ),
        (
            encrypted.metadata.as_ref().unwrap(),
            br#"{"sidecar_exchange_binding":{}}"#.as_slice(),
        ),
    ] {
        let echoed = decrypt_application_payload_for_effective_scope_internal(
            &state,
            &secure,
            realm,
            &fixture::authority(actor),
            &fixture::device_id(device),
            payload,
            None,
            None,
        )
        .expect("authored content remains readable without decrypting the own-leaf echo");
        assert_eq!(echoed, plaintext);
    }
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
    // Creator fixtures share the session tests' exact device-directory cache.
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
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
    // Creator fixtures share the session tests' exact device-directory cache.
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
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
    fixture::install_complete_joined_members(
        &mut state,
        realm,
        vec![
            arkret_sdk::ActorId::account(fixture::authority(actor)),
            arkret_sdk::ActorId::account(fixture::authority("did:web:bob.example")),
        ],
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

/// An accepted MLS group is the content-scheme authority. A legacy projection
/// field must not be required once that typed current result is installed.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_write_uses_accepted_mls_group_without_legacy_scheme_projection() {
    // Creator fixtures share the session tests' exact device-directory cache.
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
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
    fixture::install_complete_joined_members(
        &mut state,
        realm,
        vec![arkret_sdk::ActorId::account(fixture::authority(actor))],
    );

    let (_, encrypted_values) = encrypt_values_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
        "application/vnd.arkret.test+json",
        &[br#""must-wait-for-policy""#.to_vec()],
    )
    .expect("accepted MLS current permits encrypted content without a legacy scheme field");

    assert_eq!(encrypted_values.len(), 1);
    assert_eq!(encrypted_values[0]["scheme"], "mls_rfc9420");
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
    let base_event_ref =
        arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x51; 32]);
    let transition_binding = arkret_sdk::MlsGovernanceBindingPayload::new(
        effective_scope.clone(),
        Some(base_event_ref.clone()),
        0,
        1,
        0,
    )
    .unwrap();
    let add = alice_group
        .add_member_with_governance_binding(&bob_key_package, &transition_binding)
        .unwrap();
    let accepted_commit = crate::test_support::accepted_mls_commit(
        &effective_scope,
        alice_actor,
        &add.commit,
        base_event_ref.clone(),
        0x52,
    );
    let delivery = crate::test_support::accepted_mls_welcome(
        &add.welcome,
        bob_actor_id,
        &accepted_commit,
        1_760_000_000_012,
    );
    let base_current = accepted_mls_base_current(
        &effective_scope,
        base_event_ref.clone(),
        base_event_ref.clone(),
        0,
    );
    // Recovery must merge the exact staged own Commit after serialization,
    // without a moving current result or a new Add/KeyPackage claim.
    let staged = alice_group.export_state_record().unwrap();
    let mut recovered = arkret_sdk::ArkretMlsGroup::restore_from_state_record(&staged).unwrap();
    let wrong_base = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x53; 32]);
    assert!(
        recovered
            .install_recovered_own_commit(&accepted_commit, &wrong_base)
            .is_err()
    );
    assert_eq!(recovered.epoch(), 0);
    assert_eq!(
        recovered
            .install_recovered_own_commit(&accepted_commit, &base_event_ref)
            .unwrap(),
        1
    );
    assert!(
        recovered
            .install_recovered_own_commit(&accepted_commit, &base_event_ref)
            .is_err()
    );
    alice_group
        .install_accepted_commit(&accepted_commit, &base_current)
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
fn committed_sender_credential_reconstructs_real_standard_mls_content_aad() {
    let mut state = temp_state_store("committed-content-aad");
    let secure = MemorySecureKeyStore::new();
    let realm = "ak:realm:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000b2";
    let (mut alice, _) =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    let header = test_message_header(&alice, realm);
    let encrypted = alice
        .encrypt_payload(header.clone(), b"verified private content")
        .unwrap();
    let envelope = arkret_sdk::mls::encrypted_envelope_from_payload(&encrypted).unwrap();
    let event = arkret_test_kit::signed_event::SignedEventFixtureBuilder::new(
        arkret_sdk::EventKind::MessageCreate.as_str(),
        header.effective_scope.clone(),
        fixture::account_actor("did:web:alice.example"),
        json!({
            "strand_id": "ak:strand:ALH536fxXVv9EDZIoWa7sN1gzbTVJQ02x6AugHURwkvE",
            "track_name": "discussion", "encrypted_content": envelope,
        }),
    )
    .build_unsigned()
    .unwrap();
    let signer = arkret_test_kit::keys::seeded_signer(
        arkret_sdk::Did::new("did:web:alice.example").unwrap(),
        arkret_sdk::DidUrl::new(
            "did:web:alice.example#ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .unwrap(),
    );
    let event = arkret_test_kit::signed_event::sign_verifiable_event(
        event,
        &signer,
        arkret_sdk::DigestSuite::Sha256,
    )
    .unwrap()
    .expect_verifiable();
    let sender = crate::views::chat::verified_chat_sender_domain_for_realm(
        realm,
        &serde_json::to_value(&event).unwrap(),
        None,
        None,
    )
    .unwrap();
    let rebuilt = envelope
        .reconstruct_pre_encryption_header(
            arkret_sdk::EncryptedPayloadScheme::MlsRfc9420,
            header.effective_scope.clone(),
            event.kind.as_str(),
            std::str::from_utf8(&sender).unwrap(),
            None,
        )
        .unwrap();
    assert_eq!(
        rebuilt.canonical_bytes().unwrap(),
        header.canonical_bytes().unwrap()
    );
    let payload =
        arkret_sdk::mls::encrypted_envelope_to_payload_with_verified_header(&envelope, rebuilt)
            .unwrap();
    let snapshot = state.mls_checkpoint_for(realm).unwrap();
    let secret = load_device_checkpoint_secret(
        &secure,
        &fixture::authority(bob_actor),
        &fixture::device_id(bob_device),
    )
    .unwrap();
    let mut bob = crate::mls::persistence::restore_envelope(&snapshot, &secret, 0).unwrap();
    assert_eq!(
        bob.decrypt_payload(&payload).unwrap(),
        b"verified private content"
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn historical_author_view_survives_epoch_rotation() {
    let mut state = temp_state_store("historical-author-view");
    let secure = MemorySecureKeyStore::new();
    let realm = "ak:realm:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000c2";
    let (mut alice_group, mut leaf_endpoints) =
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
    let effective_scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
    };
    let charlie = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
        crate::test_support::account_actor("did:web:charlie.example"),
        arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000c3".to_owned())
            .unwrap(),
    )
    .unwrap();
    let charlie_endpoint = charlie.endpoint_identity();
    let charlie_key_package = crate::test_support::claimed_mls_key_package(
        charlie.key_package_record().unwrap(),
        1_760_000_000_013,
    );
    let transition_binding = arkret_sdk::MlsGovernanceBindingPayload::new(
        effective_scope.clone(),
        Some(epoch_one_ref.clone()),
        epoch_one_snapshot.epoch,
        epoch_one_snapshot.epoch.checked_add(1).unwrap(),
        0,
    )
    .unwrap();
    let add = alice_group
        .add_member_with_governance_binding(&charlie_key_package, &transition_binding)
        .unwrap();
    let accepted_commit = crate::test_support::accepted_mls_commit(
        &effective_scope,
        crate::test_support::account_actor("did:web:alice.example"),
        &add.commit,
        epoch_one_ref.clone(),
        0x53,
    );
    let base_current = accepted_mls_base_current(
        &effective_scope,
        arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x51; 32]),
        epoch_one_ref.clone(),
        epoch_one_snapshot.epoch,
    );
    alice_group
        .install_accepted_commit(&accepted_commit, &base_current)
        .unwrap();
    bob_group
        .install_accepted_commit(&accepted_commit, &base_current)
        .unwrap();
    leaf_endpoints.push(charlie_endpoint);
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
fn sidecar_author_leaf_view_preserves_exact_scope_and_historical_epoch() {
    let mut state = temp_state_store("sidecar-author-leaf-view");
    let secure = MemorySecureKeyStore::new();
    let authority = fixture::authority("did:web:alice.example");
    let actor = arkret_sdk::ActorId::account(authority.clone());
    let device = fixture::device_id("ak:device:01904100-0000-7000-8000-0000000000a1");
    let realm =
        arkret_sdk::RealmId::new("ak:realm:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN").unwrap();
    let scope = arkret_sdk::ScopeRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: arkret_sdk::SidecarId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [0x61; 32],
        )),
    };
    let identity =
        arkret_sdk::ArkretMlsIdentity::new_test_human_device(actor.clone(), device.clone())
            .unwrap();
    let endpoint = identity.endpoint_identity();
    let mut group = identity.create_group(&scope).unwrap();
    group
        .install_local_creator_binding(
            actor.clone(),
            Some(arkret_sdk::EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [0x65; 32],
            )),
        )
        .unwrap();
    let secret = load_or_create_account_mls_secret(&secure, &authority).unwrap();
    let checkpoint = |group: &arkret_sdk::ArkretMlsGroup| {
        let record = group.export_state_record().unwrap();
        crate::mls::persistence::encrypt_state(
            realm.as_str(),
            &record.group_id,
            record.epoch,
            &serde_json::to_vec(&record).unwrap(),
            &secret,
            &[0x62; 16],
        )
    };
    let genesis = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x63; 32]);
    state
        .install_accepted_mls_transition(&scope, checkpoint(&group), &genesis)
        .unwrap();
    let group_id = group.group_id().to_string();
    let view_at = |state: &crate::state::LocalStateStore,
                   scope: &arkret_sdk::ScopeRef,
                   epoch: u64,
                   event_ref: &str| {
        verified_author_group_view_for_scope(
            state, &secure, &authority, &device, scope, &group_id, epoch, event_ref,
        )
    };
    let before = view_at(&state, &scope, 0, genesis.as_str()).unwrap();
    assert_eq!(before.active_leaves.len(), 1);
    assert!(matches!(
        &before.active_leaves[0].credential,
        arkret_sdk::mls::AuthorLeafCredential::Basic { identity }
            if arkret_sdk::decode_mls_basic_credential_identity(identity).unwrap() == actor
    ));
    assert!(view_at(&state, &scope, 1, genesis.as_str()).is_none());
    assert!(
        view_at(
            &state,
            &scope,
            0,
            "ak:event:AbQHDTvS4ZELwYOPkH_Rdpweaio8GKWhHTHvvDJIAgzZ"
        )
        .is_none()
    );
    assert!(
        view_at(
            &state,
            &arkret_sdk::ScopeRef::Realm {
                realm_id: realm.clone()
            },
            0,
            genesis.as_str(),
        )
        .is_none()
    );

    let arkret_sdk::ScopeRef::Sidecar { sidecar_id, .. } = &scope else {
        unreachable!();
    };
    // This local RFC restoration fixture does not certify Station admission.
    let binding = arkret_sdk::MlsGovernanceBindingPayload::sidecar(
        realm.clone(),
        sidecar_id.clone(),
        Some(genesis.clone()),
        0,
        1,
        0,
        arkret_sdk::sidecar_participant_authority_digest(sidecar_id, &realm, &authority, &[])
            .unwrap(),
        vec![arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [0x61; 32],
        )],
    )
    .unwrap();
    let update = group
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    let accepted = fixture::accepted_mls_commit_with_binding(actor, &update, binding, 0x64);
    let base = accepted_mls_base_current(&scope, genesis.clone(), genesis.clone(), 0);
    group.install_accepted_commit(&accepted, &base).unwrap();
    group.install_test_leaf_bindings(vec![endpoint]).unwrap();
    state
        .install_accepted_mls_transition(&scope, checkpoint(&group), &accepted.event.event_id)
        .unwrap();
    let durable_before_read = state.mls_checkpoint_for_scope(&scope).unwrap();
    assert!(view_at(&state, &scope, 1, accepted.event.event_id.as_str()).is_some());
    assert_eq!(view_at(&state, &scope, 0, genesis.as_str()), Some(before));
    assert!(view_at(&state, &scope, 0, accepted.event.event_id.as_str()).is_none());
    assert_eq!(
        state.mls_checkpoint_for_scope(&scope),
        Some(durable_before_read)
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
fn author_own_ciphertext_uses_secure_cache_without_state_regression() {
    // Creator fixtures share the session tests' exact device-directory cache.
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
    // Own-leaf echoes are not decryptable. Retained send bytes can render
    // without replaying the ratchet; without that cache the echo stays pending.
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
    assert_eq!(decrypted.as_deref(), Some(br#""mine""#.as_slice()));
    let mut uncached = temp_state_store("own-ciphertext-no-cache");
    let scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm).unwrap(),
    };
    uncached
        .save_mls_checkpoint_for_scope(&scope, after_send.clone())
        .unwrap();
    assert!(
        decrypt_application_payload_for_effective_scope_internal(
            &uncached,
            &secure,
            realm,
            &fixture::authority(actor),
            &fixture::device_id(device),
            &payload,
            None,
            None,
        )
        .is_none()
    );
    assert!(
        uncached
            .mls_decrypted_plaintext_for(realm, payload.payload_digest.as_str())
            .is_none()
    );
    assert_eq!(
        uncached.mls_checkpoint_for(realm).unwrap().ciphertext_hex,
        after_send.ciphertext_hex
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

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn frozen_message_real_mls_retry_and_durable_reopen_preserve_sender_state() {
    let mut state = temp_state_store("frozen-message-real-mls-retry");
    let secure = MemorySecureKeyStore::new();
    let realm = "ak:realm:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000b2";
    let (mut alice, endpoints) =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    // The accepted add/Welcome fixture installs Bob's complete binding map.
    // Install the same exact active endpoints on Alice for this isolated
    // cryptographic composition; this does not claim production device admission.
    alice.install_test_leaf_bindings(endpoints).unwrap();
    assert_eq!(alice.verified_leaf_bindings().unwrap().len(), 2);
    let before_encryption = alice.export_state_record().unwrap().serialized_state;
    let header = test_message_header(&alice, realm);
    let encrypted = alice
        .encrypt_payload(header.clone(), b"once encrypted retry")
        .unwrap();
    let after_encryption = alice.export_state_record().unwrap().serialized_state;
    assert_ne!(
        before_encryption, after_encryption,
        "real encryption must advance sender state"
    );
    let envelope = arkret_sdk::mls::encrypted_envelope_from_payload(&encrypted).unwrap();
    let unsigned = arkret_test_kit::signed_event::SignedEventFixtureBuilder::new(
        arkret_sdk::EventKind::MessageCreate.as_str(),
        header.effective_scope.clone(),
        fixture::account_actor("did:web:alice.example"),
        json!({
            "strand_id": "ak:strand:ALH536fxXVv9EDZIoWa7sN1gzbTVJQ02x6AugHURwkvE",
            "track_name": "discussion", "encrypted_content": envelope,
        }),
    )
    .build_unsigned()
    .unwrap();
    let authored = arkret_sdk::AuthoredEvent::finalize_with_digest_suite(
        unsigned,
        arkret_sdk::DigestSuite::Sha256,
    )
    .unwrap();
    let signer = arkret_test_kit::keys::seeded_signer(
        arkret_sdk::Did::new("did:web:alice.example").unwrap(),
        arkret_sdk::DidUrl::new(
            "did:web:alice.example#ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .unwrap(),
    );
    let frozen = garth::MessageAuthoringSession::from_authored_event(authored)
        .unwrap()
        .sign(&signer, arkret_sdk::signatures::SignEventOptions::new())
        .unwrap();
    let exact_bytes = frozen.canonical_submission_bytes().to_vec();
    let saved = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(saved.path(), serde_json::to_vec(&frozen).unwrap()).unwrap();
    drop(frozen);
    let reopened: garth::FrozenMessageSubmission =
        serde_json::from_slice(&std::fs::read(saved.path()).unwrap()).unwrap();
    assert_eq!(reopened.canonical_submission_bytes(), exact_bytes);
    assert_eq!(
        alice.export_state_record().unwrap().serialized_state,
        after_encryption
    );
    let frozen_event = reopened.request().submission.event.clone();
    let mut attempts = 0;
    let result =
        crate::event_submit::retry_frozen_message(reopened.into_queued_submission(), |queued| {
            attempts += 1;
            assert_eq!(
                arkret_sdk::canonical::canonical_json_bytes(&queued.request).unwrap(),
                exact_bytes
            );
            assert_eq!(
                alice.export_state_record().unwrap().serialized_state,
                after_encryption
            );
            let result = if attempts == 1 {
                Err(garth::MessageAuthoringFailure::SubmissionOutcomeUnknown {
                    detail: "transport response lost after sending frozen ciphertext".to_owned(),
                })
            } else {
                Ok(crate::models::SubmitEventResult::queued(
                    queued.event_id.to_string(),
                ))
            };
            std::future::ready(result)
        })
        .await
        .unwrap();
    assert_eq!(attempts, 2);
    assert_eq!(result.status, garth::SendQueueStatus::Queued);
    assert!(result.commit.is_none());
    assert_eq!(
        alice.export_state_record().unwrap().serialized_state,
        after_encryption
    );
    let delivered: arkret_sdk::EncryptedEnvelope =
        serde_json::from_value(frozen_event.payload["encrypted_content"].clone()).unwrap();
    let payload =
        arkret_sdk::mls::encrypted_envelope_to_payload_with_verified_header(&delivered, header)
            .unwrap();
    let secret = load_device_checkpoint_secret(
        &secure,
        &fixture::authority(bob_actor),
        &fixture::device_id(bob_device),
    )
    .unwrap();
    let mut bob = crate::mls::persistence::restore_envelope(
        &state.mls_checkpoint_for(realm).unwrap(),
        &secret,
        0,
    )
    .unwrap();
    assert_eq!(
        bob.decrypt_payload(&payload).unwrap(),
        b"once encrypted retry"
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn calendar_current_source_opens_metadata_without_old_events_or_plaintext_cache() {
    let mut state = temp_state_store("calendar-current-cold");
    let secure = MemorySecureKeyStore::new();
    let realm = "ak:realm:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000b2";
    let (mut alice, _) =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    let realm_id = arkret_sdk::RealmId::new(realm).unwrap();
    let event =
        |byte| arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [byte; 32]);
    let scope = arkret_sdk::ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let snapshot = state.mls_checkpoint_for_scope(&scope).unwrap();
    let group_ref = event(61);
    state
        .record_mls_group_state_ref_for_effective_scope(
            realm,
            None,
            &snapshot.group_id,
            snapshot.epoch,
            group_ref.clone(),
        )
        .unwrap();
    let header = arkret_sdk::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/vnd.arkret.strand-metadata+json",
        arkret_sdk::EncryptedPayloadScheme::MlsRfc9420,
        scope.clone(),
        "ak.strand.update",
        alice.epoch(),
        group_ref.clone(),
        alice.local_content_sender_domain().unwrap(),
        arkret_sdk::EventContentRoutingContext::None,
    )
    .unwrap();
    let plaintext = json!({"title":"Cold calendar","fields":{"calendar":{"start":"2026-10-07","end":"2026-10-08","timezone":"UTC","tzdb_version":"2025b","all_day":true,"status":"confirmed"}}});
    let encrypted = alice
        .encrypt_payload(header, &serde_json::to_vec(&plaintext).unwrap())
        .unwrap();
    let envelope = arkret_sdk::mls::encrypted_envelope_from_payload(&encrypted).unwrap();
    let strand_id = arkret_sdk::StrandId::from_event_id(&event(62));
    let mut strand = arkret_sdk::Strand::discussion(
        strand_id.clone(),
        realm_id.clone(),
        "",
        fixture::account_actor("did:web:alice.example"),
    );
    strand.metadata = None;
    strand.encrypted_metadata = Some(envelope.clone());
    let stream = arkret_sdk::CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let revision = arkret_sdk::CurrentRevision {
        commit_id: arkret_sdk::RealmCommitId::from_digest([65; 32]),
        stream_position: 65,
    };
    let source_ref = arkret_sdk::CommittedEventRef {
        event_id: event(63),
        commit_id: arkret_sdk::RealmCommitId::from_digest([63; 32]),
        stream_ref: stream.clone(),
        stream_position: 63,
    };
    let source = arkret_wire::CalendarScheduleSourceValue {
        effective_scope: scope.clone(),
        source: Some(source_ref.clone()),
        strand_revision: revision.clone(),
        metadata_context: Some(arkret_wire::CalendarMetadataContext {
            source: source_ref,
            event_kind: arkret_sdk::EventKind::StrandUpdate,
            signer_id: fixture::account_actor("did:web:alice.example"),
            payload_digest: envelope.payload_digest().unwrap(),
        }),
    };
    let rows = vec![
        arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::Strand {
                strand_id: strand_id.clone(),
            },
            source_stream_ref: stream.clone(),
            revision: revision.clone(),
            value: serde_json::to_value(strand).unwrap(),
        },
        arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::CalendarScheduleSource {
                strand_id: strand_id.clone(),
            },
            source_stream_ref: stream.clone(),
            revision: revision.clone(),
            value: serde_json::to_value(source).unwrap(),
        },
        arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::MlsGroup {
                scope_ref: scope.clone(),
            },
            source_stream_ref: stream,
            revision,
            value: serde_json::to_value(accepted_mls_base_current(
                &scope,
                event(60),
                group_ref,
                snapshot.epoch,
            ))
            .unwrap(),
        },
    ];
    fixture::install_current_entries(&mut state, realm, rows.clone());
    assert!(state.load().raw_operations.is_empty());
    assert!(
        state
            .mls_decrypted_plaintext_for(realm, envelope.payload_digest().unwrap().as_str())
            .is_none()
    );
    let open = |state: &crate::state::LocalStateStore, keys: &MemorySecureKeyStore| {
        crate::views::metadata::open_metadata_with_secure_store(
            state,
            realm,
            strand_id.as_str(),
            &envelope,
            &fixture::authority(bob_actor),
            &fixture::device_id(bob_device),
            keys,
        )
    };
    let mut bad = rows.clone();
    let arkret_wire::TypedCurrentRow::Value { value, .. } = &mut bad[1];
    value["metadata_context"]["signer_id"] =
        json!(fixture::account_actor("did:web:mallory.example"));
    fixture::install_current_entries(&mut state, realm, bad);
    assert!(open(&state, &secure).is_none());
    fixture::install_current_entries(&mut state, realm, rows);
    assert!(open(&state, &MemorySecureKeyStore::new()).is_none());
    assert_eq!(open(&state, &secure), Some(plaintext));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn ordinary_recovery_refreezes_received_private_base_after_proof() {
    use super::super::artifact_consumer::{
        refreeze_recovery_base, require_unchanged_recovery_base,
    };
    let mut state = temp_state_store("recovery-refreeze-private-base");
    let secure = MemorySecureKeyStore::new();
    let realm = "ak:realm:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000b2";
    let (mut alice, _) =
        two_member_group_with_bob_snapshot(&mut state, &secure, realm, bob_actor, bob_device);
    let scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm).unwrap(),
    };
    let reference = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [0x61; 32]);
    let mut requested = state.mls_checkpoint_for(realm).unwrap();
    requested.group_state_event_id = Some(reference.clone());
    let secret = load_device_checkpoint_secret(
        &secure,
        &fixture::authority(bob_actor),
        &fixture::device_id(bob_device),
    )
    .unwrap();
    let mut bob = crate::mls::persistence::restore_envelope(&requested, &secret, 1).unwrap();
    let first = alice
        .encrypt_payload(test_message_header(&alice, realm), b"first")
        .unwrap();
    let second = alice
        .encrypt_payload(test_message_header(&alice, realm), b"second")
        .unwrap();
    // A legitimate receive runs while the bounded source proof is in flight.
    assert_eq!(bob.decrypt_payload(&second).unwrap(), b"second");
    let received_state = bob.export_state_record().unwrap();
    let mut received = crate::mls::persistence::encrypt_state(
        realm,
        &received_state.group_id,
        received_state.epoch,
        &serde_json::to_vec(&received_state).unwrap(),
        &secret,
        &[0x62; 16],
    );
    received.group_state_event_id = Some(reference.clone());
    assert_ne!(received.ciphertext_hex, requested.ciphertext_hex);
    assert!(require_unchanged_recovery_base(&received, &requested, &reference, 1).is_err());
    let frozen = refreeze_recovery_base(&received, &requested).unwrap();
    assert_eq!(frozen, received);
    let mut recovered = crate::mls::persistence::restore_envelope(&frozen, &secret, 1).unwrap();
    // The newer provider retains its skipped receive key after serialization.
    assert_eq!(recovered.decrypt_payload(&first).unwrap(), b"first");
    let changed_state = recovered.export_state_record().unwrap();
    let mut changed = crate::mls::persistence::encrypt_state(
        realm,
        &changed_state.group_id,
        changed_state.epoch,
        &serde_json::to_vec(&changed_state).unwrap(),
        &secret,
        &[0x63; 16],
    );
    changed.group_state_event_id = Some(reference.clone());
    // A receive after freezing still fences installation: the durable candidate
    // remains byte-for-byte untouched by this rejected installation attempt.
    let before = changed.clone();
    assert!(require_unchanged_recovery_base(&changed, &frozen, &reference, 1).is_err());
    assert_eq!(changed, before);
    let binding = arkret_sdk::MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(reference.clone()),
        1,
        2,
        0,
    )
    .unwrap();
    let commit = alice
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    let accepted = crate::test_support::accepted_mls_commit(
        &scope,
        fixture::account_actor("did:web:alice.example"),
        &commit,
        reference.clone(),
        0x64,
    );
    // Consume the actual accepted RFC Commit from the refrozen provider, rather
    // than authoring a new rotation to compensate for the public current.
    let mut recovered = crate::mls::persistence::restore_envelope(&frozen, &secret, 1).unwrap();
    require_unchanged_recovery_base(&received, &frozen, &reference, 1).unwrap();
    recovered
        .install_recovered_remote_commit(&accepted, &reference)
        .unwrap();
    assert_eq!(recovered.epoch(), 2);
}
