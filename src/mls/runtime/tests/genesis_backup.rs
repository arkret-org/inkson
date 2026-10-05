//! Tests for `ak.mls.genesis` payload construction and local persistence.

use crate::mls::runtime::*;
use crate::secure_key_store::MemorySecureKeyStore;
use crate::state::isolated_store_for_tests as temp_state_store;
use crate::test_support as fixture;

fn genesis_governance_binding() -> arkret_sdk::MlsGovernanceBindingPayload {
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
    // Genesis is the only transition with no base group state: epoch 0 -> 0,
    // key-access revision 0, and no `base_group_state_ref`.
    arkret_sdk::MlsGovernanceBindingPayload::realm(realm_id, None, 0, 0, 0).unwrap()
}

#[test]
fn sidecar_epoch_zero_restores_only_its_pinned_authority_and_creator_device() {
    let mut state = temp_state_store("sidecar-pinned-genesis");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let authority = fixture::authority(actor);
    let device = fixture::device_id("ak:device:01904100-0000-7000-8000-000000000001");
    let realm = genesis_governance_binding()
        .effective_scope()
        .realm_id()
        .clone();
    super::seed_human_creator_authorization(actor, device.as_str());
    ensure_creator_mls_checkpoint(&mut state, &secure, realm.as_str(), &authority, &device)
        .unwrap();
    let create =
        arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [17; 32]);
    let sidecar = arkret_sdk::SidecarId::from_event_id(&create);
    let scope = arkret_sdk::ScopeRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    let digest =
        arkret_sdk::sidecar_participant_authority_digest(&sidecar, &realm, &authority, &[])
            .unwrap();
    let binding = arkret_sdk::MlsGovernanceBindingPayload::sidecar(
        realm.clone(),
        sidecar.clone(),
        None,
        0,
        0,
        0,
        digest.clone(),
        vec![create.clone()],
    )
    .unwrap();
    let secret = load_device_checkpoint_secret(&secure, &authority, &device).unwrap();
    let (checkpoint, original) =
        generate_creator_epoch_zero(&scope, &authority, &device, &binding, &secret, None).unwrap();
    state
        .save_mls_checkpoint_for_scope(&scope, checkpoint)
        .unwrap();
    let restore = |binding: &arkret_sdk::MlsGovernanceBindingPayload,
                   device: &arkret_sdk::DeviceId| {
        initial_mls_checkpoint_summary_with_pinned_binding(
            &state,
            &secure,
            realm.as_str(),
            None,
            &authority,
            device,
            Some(sidecar.clone()),
            Some(binding),
        )
    };
    let restored = restore(&binding, &device).unwrap().unwrap();
    assert_eq!(restored.group_id, original.group_id);
    assert_eq!(restored.group_info_bytes, original.group_info_bytes);
    assert_eq!(restored.ratchet_tree_bytes, original.ratchet_tree_bytes);
    let changed_cut = arkret_sdk::MlsGovernanceBindingPayload::sidecar(
        realm.clone(),
        sidecar.clone(),
        None,
        0,
        0,
        0,
        digest,
        vec![arkret_sdk::EventId::from_digest(
            arkret_sdk::canonical::DigestSuite::Sha256,
            [18; 32],
        )],
    )
    .unwrap();
    assert!(
        restore(&changed_cut, &device).is_err(),
        "a retry cannot substitute another authority cut"
    );
    let other_scope =
        arkret_sdk::MlsGovernanceBindingPayload::realm(realm.clone(), None, 0, 0, 0).unwrap();
    assert!(
        restore(&other_scope, &device).is_err(),
        "parent Realm material cannot bootstrap Sidecar"
    );
    assert!(
        restore(
            &binding,
            &fixture::device_id("ak:device:01904100-0000-7000-8000-000000000002")
        )
        .is_err(),
        "another device cannot resume the creator's private material"
    );
    assert_eq!(state.mls_checkpoint_for_scope(&scope).unwrap().epoch, 0);
}

#[test]
fn sidecar_add_keeps_exact_binding_and_stages_private_state_until_acceptance() {
    let mut state = temp_state_store("sidecar-add-binding");
    let secure = MemorySecureKeyStore::new();
    let authority = fixture::authority("did:web:alice.example");
    let device = fixture::device_id("ak:device:01904100-0000-7000-8000-000000000001");
    let realm = genesis_governance_binding()
        .effective_scope()
        .realm_id()
        .clone();
    super::seed_human_creator_authorization("did:web:alice.example", device.as_str());
    ensure_creator_mls_checkpoint(&mut state, &secure, realm.as_str(), &authority, &device)
        .unwrap();
    let create = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [21; 32]);
    let sidecar = arkret_sdk::SidecarId::from_event_id(&create);
    let scope = arkret_sdk::ScopeRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    let digest =
        arkret_sdk::sidecar_participant_authority_digest(&sidecar, &realm, &authority, &[])
            .unwrap();
    let genesis = arkret_sdk::MlsGovernanceBindingPayload::sidecar(
        realm.clone(),
        sidecar.clone(),
        None,
        0,
        0,
        0,
        digest.clone(),
        vec![create.clone()],
    )
    .unwrap();
    let secret = load_device_checkpoint_secret(&secure, &authority, &device).unwrap();
    let (checkpoint, _) =
        generate_creator_epoch_zero(&scope, &authority, &device, &genesis, &secret, None).unwrap();
    state
        .save_mls_checkpoint_for_scope(&scope, checkpoint.clone())
        .unwrap();
    let base = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [22; 32]);
    state
        .record_mls_group_state_ref_for_scope(&scope, &checkpoint.group_id, 0, base.clone())
        .unwrap();
    let before = state.mls_checkpoint_for_scope(&scope).unwrap();
    let member_actor = arkret_sdk::ActorId::account(authority.clone());
    let member_device = fixture::device_id("ak:device:01904100-0000-7000-8000-000000000002");
    let member =
        arkret_sdk::ArkretMlsIdentity::new_test_human_device(member_actor.clone(), member_device)
            .unwrap();
    let key_package =
        fixture::claimed_mls_key_package(member.key_package_record().unwrap(), 1_760_000_000_011);
    let leaf = arkret_sdk::mls::author_leaf_from_key_package_bytes(
        &arkret_sdk::base64url_decode(key_package.keypackage.as_bytes()).unwrap(),
        0,
    )
    .unwrap();
    let hint = crate::mls::governance_proof::MlsLeafAuthorityHint {
        actor_id: member_actor.clone(),
        signature_key: arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(
            &leaf.signature_key,
        ))
        .unwrap(),
        endpoint: key_package.endpoint.clone(),
        device_authorize_event_id: Some(create.clone()),
    };
    let binding = arkret_sdk::MlsGovernanceBindingPayload::sidecar(
        realm.clone(),
        sidecar.clone(),
        Some(base.clone()),
        0,
        1,
        7,
        digest.clone(),
        vec![create.clone()],
    )
    .unwrap();
    let build = |binding: &arkret_sdk::MlsGovernanceBindingPayload| {
        build_add_member_commit_with_binding(
            &state,
            &secure,
            &scope,
            &authority,
            &device,
            &key_package,
            std::slice::from_ref(&hint),
            Some(&member_actor),
            Some(binding),
        )
    };
    let (_, staged) = build(&binding).unwrap();
    assert_eq!(staged.envelope.epoch, 1);
    assert_eq!(staged.staged_checkpoint.epoch, 0);
    assert_eq!(state.mls_checkpoint_for_scope(&scope).unwrap(), before);
    let operation = crate::mls::group_events::mls_commit_event_with_binding(
        &state,
        authority.principal_id.as_str(),
        &staged.envelope,
        &binding,
    )
    .unwrap();
    assert_eq!(operation.intent().scope_ref(), &scope);
    let payload: arkret_sdk::MlsCommitPayload =
        serde_json::from_value(serde_json::to_value(operation.intent().payload()).unwrap())
            .unwrap();
    assert_eq!(payload.governance_binding(), &binding);
    let wrong_base = arkret_sdk::MlsGovernanceBindingPayload::sidecar(
        realm.clone(),
        sidecar,
        Some(create.clone()),
        0,
        1,
        7,
        digest,
        vec![create],
    )
    .unwrap();
    assert!(build(&wrong_base).is_err());
    let parent =
        arkret_sdk::MlsGovernanceBindingPayload::realm(realm, Some(base), 0, 1, 7).unwrap();
    assert!(build(&parent).is_err());
    assert_eq!(state.mls_checkpoint_for_scope(&scope).unwrap(), before);
}

#[test]
fn build_mls_genesis_payload_has_required_fields() {
    let mut state = temp_state_store("genesis-payload");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    super::seed_human_creator_authorization(actor, device);
    let summary = ensure_creator_mls_checkpoint(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
    )
    .unwrap()
    .expect("creator snapshot should be created");
    let binding = genesis_governance_binding();
    let typed_payload = build_mls_genesis_payload(&summary, &binding).unwrap();
    let payload = serde_json::to_value(&typed_payload).unwrap();

    typed_payload.validate().unwrap();
    assert_eq!(
        typed_payload.mls_group_id().unwrap().as_str(),
        summary.group_id
    );
    assert_eq!(
        typed_payload.creator_leaf_authority,
        summary.creator_leaf_authority
    );
    assert_eq!(
        arkret_sdk::base64url_decode(
            typed_payload
                .creator_leaf_authority
                .leaf_signature_key_b64u
                .as_str()
        )
        .unwrap()
        .len(),
        32
    );
    assert_eq!(
        typed_payload.creator_leaf_authority.endpoint,
        arkret_sdk::MlsWelcomeRecipientEndpoint::Device {
            device_id: fixture::device_id(device),
        }
    );
    assert_eq!(
        typed_payload
            .creator_leaf_authority
            .authorization_event_ref
            .as_str(),
        "ak:event:AdU2TJKBkRBC1Jk1dY8ExFkUgDvhnVG8jmKT5BdWMeYp"
    );
    assert!(payload.get("epoch").is_none());
    assert!(payload.get("mls_group_id").is_none());
    // cipher_suite is the SDK ciphersuite string form — non-empty.
    assert!(!payload["cipher_suite"].as_str().unwrap_or("").is_empty());
    // governance_binding present and carries the genesis 0 -> 0 epochs.
    assert!(payload.get("governance_binding").is_some());
    assert_eq!(
        payload["governance_binding"]["previous_epoch"].as_u64(),
        Some(0)
    );
    assert_eq!(
        payload["governance_binding"]["next_epoch"].as_u64(),
        Some(0)
    );
    assert_eq!(typed_payload.effective_scope(), binding.effective_scope());
    assert!(payload.get("effective_scope").is_none());
    assert!(payload["governance_binding"].get("mls_group_id").is_none());
    let mut wrong_summary = summary.clone();
    wrong_summary.group_id = "different-group".to_owned();
    assert!(build_mls_genesis_payload(&wrong_summary, &binding).is_err());
    // Content digests are carried only by the refs; sibling digest mirrors are forbidden.
    assert!(payload.get("group_info_digest").is_none());
    assert!(payload.get("ratchet_tree_digest").is_none());
    assert!(
        payload["group_info_ref"]
            .as_str()
            .is_some_and(|value| value.starts_with("ak:blob:sha256:"))
    );
    assert!(
        payload["ratchet_tree_ref"]
            .as_str()
            .is_some_and(|value| value.starts_with("ak:blob:sha256:"))
    );
    // created_at present.
    assert!(payload["created_at"].as_str().unwrap_or("").contains('T'));

    // Validate against the registered canonical `mls_genesis_payload`
    // schema so the full payload passes strict client/server validation.
    let catalog = arkret_schema_conformance::event_payload_validator_catalog().unwrap();
    if catalog
        .missing_payload_validators_for(std::iter::once("ak.mls.genesis"))
        .is_empty()
    {
        catalog
            .validate_payload("ak.mls.genesis", &payload)
            .expect("genesis payload must satisfy the registered schema");
    }
}

#[test]
fn sidecar_withdrawal_keeps_the_other_agent_and_recovers_the_pending_commit() {
    let mut state = temp_state_store("sidecar-withdrawal");
    let secure = MemorySecureKeyStore::new();
    let authority = fixture::authority("did:web:alice.example");
    let device = fixture::device_id("ak:device:01904100-0000-7000-8000-000000000001");
    let realm = genesis_governance_binding()
        .effective_scope()
        .realm_id()
        .clone();
    super::seed_human_creator_authorization("did:web:alice.example", device.as_str());
    ensure_creator_mls_checkpoint(&mut state, &secure, realm.as_str(), &authority, &device)
        .unwrap();
    let secret = load_device_checkpoint_secret(&secure, &authority, &device).unwrap();
    let event =
        |seed| arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [seed; 32]);
    let sidecar = arkret_sdk::SidecarId::from_event_id(&event(71));
    let scope = arkret_sdk::ScopeRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    let agents = [
        "ak:did_core:web:first-agent.example",
        "ak:did_core:web:second-agent.example",
    ]
    .map(|id| arkret_sdk::DidCoreId::new(id).unwrap());
    let digest = |desired: &[arkret_sdk::DidCoreId]| {
        arkret_sdk::sidecar_participant_authority_digest(&sidecar, &realm, &authority, desired)
            .unwrap()
    };
    let binding = |base, epoch, desired: &[arkret_sdk::DidCoreId]| {
        arkret_sdk::MlsGovernanceBindingPayload::sidecar(
            realm.clone(),
            sidecar.clone(),
            base,
            epoch,
            if epoch == 0 && desired.is_empty() {
                0
            } else {
                epoch + 1
            },
            0,
            digest(desired),
            vec![event(71)],
        )
        .unwrap()
    };
    let genesis = binding(None, 0, &[]);
    let (checkpoint, _) =
        generate_creator_epoch_zero(&scope, &authority, &device, &genesis, &secret, None).unwrap();
    let mut group = crate::mls::persistence::restore_envelope(&checkpoint, &secret, 0).unwrap();
    let mut base = event(72);
    let mut agent_actors = Vec::new();
    for (index, agent) in agents.iter().enumerate() {
        let actor = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            agent.clone(),
            authority.station_id.clone(),
        ));
        agent_actors.push(actor.clone());
        let identity = arkret_sdk::ArkretMlsIdentity::new_agent(
            actor,
            arkret_sdk::DidUrl::new(format!(
                "did:web:{}#runtime",
                if index == 0 {
                    "first-agent.example"
                } else {
                    "second-agent.example"
                }
            ))
            .unwrap(),
            event(73 + index as u8),
            arkret_sdk::ArkretMlsSigner::from_ed25519_signing_key(
                ed25519_dalek::SigningKey::from_bytes(&[74 + index as u8; 32]),
            ),
        )
        .unwrap();
        let key_package = fixture::claimed_mls_key_package(
            identity.key_package_record().unwrap(),
            1_760_000_000_011 + index as u64,
        );
        let leaf = arkret_sdk::mls::author_leaf_from_key_package_bytes(
            &arkret_sdk::base64url_decode(key_package.keypackage.as_bytes()).unwrap(),
            0,
        )
        .unwrap();
        let hint = crate::mls::governance_proof::MlsLeafAuthorityHint {
            actor_id: identity.actor_id.clone(),
            signature_key: arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(
                &leaf.signature_key,
            ))
            .unwrap(),
            endpoint: key_package.endpoint.clone(),
            device_authorize_event_id: None,
        };
        let previous = group.verified_leaf_bindings().unwrap();
        let transition = binding(Some(base.clone()), group.epoch(), &agents);
        let add = group
            .add_member_with_governance_binding(&key_package, &transition)
            .unwrap();
        let accepted = fixture::accepted_mls_commit_with_binding(
            arkret_sdk::ActorId::account(authority.clone()),
            &add.commit,
            transition,
            76 + index as u8,
        );
        group
            .install_recovered_own_commit(&accepted, &base)
            .unwrap();
        crate::mls::governance_proof::install_post_transition_leaf_bindings(
            &mut group,
            &previous,
            &[hint],
        )
        .unwrap();
        base = accepted.event.event_id;
    }
    assert_eq!(group.verified_leaf_bindings().unwrap().len(), 3);
    let encoded = serde_json::to_vec(&group.export_state_record().unwrap()).unwrap();
    let checkpoint = crate::mls::persistence::encrypt_state(
        realm.as_str(),
        &group.group_id(),
        group.epoch(),
        &encoded,
        &secret,
        &[78; 16],
    );
    state
        .save_mls_checkpoint_for_scope(&scope, checkpoint)
        .unwrap();
    state
        .record_mls_group_state_ref_for_scope(
            &scope,
            &group.group_id(),
            group.epoch(),
            base.clone(),
        )
        .unwrap();
    let before = state.mls_checkpoint_for_scope(&scope).unwrap();
    let transition = binding(Some(base.clone()), 2, &agents[1..]);
    let wrong_base = binding(Some(event(79)), 2, &agents[1..]);
    assert!(
        build_sidecar_access_commit(
            &state,
            &secure,
            &authority,
            &device,
            &wrong_base,
            &agent_actors[..1]
        )
        .is_err()
    );
    assert!(
        build_sidecar_access_commit(
            &state,
            &secure,
            &authority,
            &device,
            &transition,
            &[arkret_sdk::ActorId::account(authority.clone())]
        )
        .is_err()
    );
    let staged = build_sidecar_access_commit(
        &state,
        &secure,
        &authority,
        &device,
        &transition,
        &agent_actors[..1],
    )
    .unwrap();
    assert_eq!(state.mls_checkpoint_for_scope(&scope).unwrap(), before);
    let previous = group.verified_leaf_bindings().unwrap();
    let mut restarted =
        crate::mls::persistence::restore_envelope(&staged.staged_checkpoint, &secret, 2).unwrap();
    assert_eq!(restarted.epoch(), 2);
    let accepted = fixture::accepted_mls_commit_with_binding(
        arkret_sdk::ActorId::account(authority.clone()),
        &staged.envelope,
        transition,
        80,
    );
    assert!(
        restarted
            .install_recovered_own_commit(&accepted, &event(79))
            .is_err()
    );
    assert_eq!(restarted.epoch(), 2);
    restarted
        .install_recovered_own_commit(&accepted, &base)
        .unwrap();
    crate::mls::governance_proof::install_post_transition_leaf_bindings(
        &mut restarted,
        &previous,
        &[],
    )
    .unwrap();
    let leaves = restarted.verified_leaf_bindings().unwrap();
    assert_eq!(restarted.epoch(), 3);
    assert_eq!(leaves.len(), 2);
    assert!(leaves.iter().all(|leaf| leaf.actor_id != agent_actors[0]));
    assert!(leaves.iter().any(|leaf| leaf.actor_id == agent_actors[1]));
    let encoded = serde_json::to_vec(&restarted.export_state_record().unwrap()).unwrap();
    let checkpoint = crate::mls::persistence::encrypt_state(
        realm.as_str(),
        &restarted.group_id(),
        3,
        &encoded,
        &secret,
        &[81; 16],
    );
    state
        .save_mls_checkpoint_for_scope(&scope, checkpoint)
        .unwrap();
    state
        .record_mls_group_state_ref_for_scope(
            &scope,
            &restarted.group_id(),
            3,
            accepted.event.event_id.clone(),
        )
        .unwrap();
    let rotation = arkret_sdk::MlsGovernanceBindingPayload::sidecar(
        realm.clone(),
        sidecar.clone(),
        Some(accepted.event.event_id.clone()),
        3,
        4,
        0,
        digest(&agents[1..]),
        vec![event(71), event(82)],
    )
    .unwrap();
    let before = state.mls_checkpoint_for_scope(&scope).unwrap();
    let staged =
        build_sidecar_access_commit(&state, &secure, &authority, &device, &rotation, &[]).unwrap();
    assert_eq!(state.mls_checkpoint_for_scope(&scope).unwrap(), before);
    let mut rotated =
        crate::mls::persistence::restore_envelope(&staged.staged_checkpoint, &secret, 3).unwrap();
    let rotated_commit = fixture::accepted_mls_commit_with_binding(
        arkret_sdk::ActorId::account(authority),
        &staged.envelope,
        rotation.clone(),
        83,
    );
    rotated
        .install_recovered_own_commit(&rotated_commit, &accepted.event.event_id)
        .unwrap();
    crate::mls::governance_proof::install_post_transition_leaf_bindings(&mut rotated, &leaves, &[])
        .unwrap();
    assert_eq!(rotated.verified_leaf_bindings().unwrap().len(), 2);
    let (info, tree) = rotated.public_group_state_bytes().unwrap();
    let public =
        arkret_sdk::MlsPublicGroupTracker::from_external(&info, &tree, &rotated.group_id(), 4)
            .unwrap();
    assert_eq!(public.governance_binding().unwrap(), rotation);
}

#[test]
fn existing_epoch_zero_snapshot_restores_genesis_summary() {
    let mut state = temp_state_store("genesis-summary-restore");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    super::seed_human_creator_authorization(actor, device);
    let fresh = ensure_creator_mls_checkpoint(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
    )
    .unwrap()
    .expect("creator snapshot should be created");
    let restored = initial_mls_checkpoint_summary_from_existing(
        &state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
    )
    .unwrap()
    .expect("epoch-0 snapshot restores summary");

    assert_eq!(restored.realm_id, fresh.realm_id);
    assert_eq!(restored.group_id, fresh.group_id);
    assert_eq!(restored.epoch, 0);
    assert_eq!(restored.group_info_bytes, fresh.group_info_bytes);
    assert_eq!(restored.ratchet_tree_bytes, fresh.ratchet_tree_bytes);
    assert_eq!(
        restored.creator_leaf_authority,
        fresh.creator_leaf_authority
    );
}

#[test]
fn persisted_creator_epoch_zero_is_reused_and_never_recreated() {
    let mut state = temp_state_store("genesis-no-recreate");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    super::seed_human_creator_authorization(actor, device);
    ensure_creator_mls_checkpoint(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
    )
    .unwrap()
    .expect("creator snapshot should be created");
    let staged = state.mls_checkpoint_for(realm).unwrap();
    assert!(
        ensure_creator_mls_checkpoint(
            &mut state,
            &secure,
            realm,
            &fixture::authority(actor),
            &fixture::device_id(device)
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(state.mls_checkpoint_for(realm), Some(staged.clone()));
    let mut corrupt = staged;
    corrupt.group_id = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [0x73; 32],
        )),
    }
    .canonical_mls_group_id()
    .unwrap()
    .to_string();
    state.save_mls_checkpoint(realm, corrupt.clone()).unwrap();
    assert!(
        ensure_creator_mls_checkpoint(
            &mut state,
            &secure,
            realm,
            &fixture::authority(actor),
            &fixture::device_id(device)
        )
        .is_err()
    );
    assert_eq!(
        state.mls_checkpoint_for(realm),
        Some(corrupt),
        "inconsistent persisted material must never be replaced with new randomness"
    );
}

#[test]
fn mls_genesis_emitted_flag_is_idempotent() {
    let mut state = temp_state_store("genesis-idempotent");
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    assert!(!state.mls_genesis_emitted_for(realm));
    state.mark_mls_genesis_emitted(realm).expect("valid Realm");
    assert!(state.mls_genesis_emitted_for(realm));
    // Re-marking is a no-op / stays true.
    state.mark_mls_genesis_emitted(realm).expect("valid Realm");
    assert!(state.mls_genesis_emitted_for(realm));
}

#[test]
fn pinned_creator_binding_mismatch_generates_no_epoch_zero_checkpoint() {
    let mut state = temp_state_store("pin-mismatch");
    let secure = MemorySecureKeyStore::new();
    let authority = fixture::authority("did:web:alice.example");
    let device = fixture::device_id("ak:device:01904100-0000-7000-8000-000000000001");
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let wrong_realm = arkret_sdk::RealmId::from_event_id(
        &arkret_sdk::EventId::new("ak:event:AdU2TJKBkRBC1Jk1dY8ExFkUgDvhnVG8jmKT5BdWMeYp").unwrap(),
    );
    let wrong = arkret_sdk::MlsGovernanceBindingPayload::realm(wrong_realm, None, 0, 0, 0).unwrap();
    assert!(
        ensure_creator_mls_checkpoint_with_pinned_binding(
            &mut state,
            &secure,
            realm,
            &authority,
            &device,
            Some(&wrong)
        )
        .is_err()
    );
    assert!(state.mls_checkpoint_for(realm).is_none());
}
