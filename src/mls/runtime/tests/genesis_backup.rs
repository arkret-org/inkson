//! Tests for `ak.mls.genesis` payload construction and local persistence.

use crate::mls::runtime::*;
use crate::secure_key_store::MemorySecureKeyStore;
use crate::state::isolated_store_for_tests as temp_state_store;

fn genesis_governance_binding(group_id: &str) -> arkret_sdk::MlsGovernanceBindingPayload {
    let realm_id =
        arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
    let security_frontier_digest = arkret_sdk::Hash::new(
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    .unwrap();
    // Genesis installs epoch 0 (governance binding epoch 0 -> 0).
    arkret_sdk::MlsGovernanceBindingPayload::realm(
        realm_id,
        group_id,
        0,
        0,
        security_frontier_digest,
        arkret_sdk::ContentScheme::MlsRfc9420,
        None,
        arkret_sdk::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
        arkret_sdk::CORE_REDUCER_PROFILE,
    )
    .unwrap()
}

#[test]
fn build_mls_genesis_payload_has_required_fields() {
    let mut state = temp_state_store("genesis-payload");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    super::seed_genesis_governance_proof(&mut state, realm);
    let summary = ensure_creator_mls_snapshot(&mut state, &secure, realm, actor, device)
        .unwrap()
        .expect("creator snapshot should be created");
    let binding = genesis_governance_binding(&summary.group_id);
    let typed_payload = build_mls_genesis_payload(&summary, &binding).unwrap();
    let payload = serde_json::to_value(&typed_payload).unwrap();

    // epoch MUST be the literal 0 the schema/reducer require.
    assert_eq!(payload["epoch"].as_u64(), Some(0));
    assert_eq!(
        payload["mls_group_id"].as_str(),
        Some(summary.group_id.as_str())
    );
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
    // effective_scope mirrors the governance binding's.
    assert_eq!(
        payload["effective_scope"],
        payload["governance_binding"]["effective_scope"]
    );
    // group_info / ratchet_tree digest fields present and sha256-shaped.
    let group_info_digest = payload["group_info_digest"].as_str().unwrap();
    let ratchet_tree_digest = payload["ratchet_tree_digest"].as_str().unwrap();
    assert!(group_info_digest.starts_with("sha256:"));
    assert!(ratchet_tree_digest.starts_with("sha256:"));
    assert_eq!(
        group_info_digest,
        crate::canonical::sha256_digest(&summary.group_info_bytes)
    );
    assert_eq!(
        payload["group_info_ref"].as_str(),
        Some(format!("ak:blob:{group_info_digest}").as_str())
    );
    assert_eq!(
        payload["ratchet_tree_ref"].as_str(),
        Some(format!("ak:blob:{ratchet_tree_digest}").as_str())
    );
    // created_at present.
    assert!(payload["created_at"].as_str().unwrap_or("").contains('T'));

    // Validate against the registered canonical `mls_genesis_payload`
    // schema so the full payload passes strict client/server validation.
    let catalog = arkret_sdk::schema::event_payload_validator_catalog().unwrap();
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
fn existing_epoch_zero_snapshot_restores_genesis_summary() {
    let mut state = temp_state_store("genesis-summary-restore");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    super::seed_genesis_governance_proof(&mut state, realm);
    let fresh = ensure_creator_mls_snapshot(&mut state, &secure, realm, actor, device)
        .unwrap()
        .expect("creator snapshot should be created");
    let restored =
        initial_mls_snapshot_summary_from_existing(&state, &secure, realm, actor, device)
            .unwrap()
            .expect("epoch-0 snapshot restores summary");

    assert_eq!(restored.realm_id, fresh.realm_id);
    assert_eq!(restored.group_id, fresh.group_id);
    assert_eq!(restored.epoch, 0);
    assert_eq!(restored.group_info_bytes, fresh.group_info_bytes);
    assert_eq!(restored.ratchet_tree_bytes, fresh.ratchet_tree_bytes);
}

#[test]
fn legacy_epoch_zero_snapshot_without_governance_binding_fails_closed() {
    let mut state = temp_state_store("legacy-genesis-summary");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let secret = load_or_create_account_mls_secret(&secure, actor).unwrap();
    let identity = arkret_sdk::ArkretMlsIdentity::new_basic(
        crate::mls_api_helpers::principal_core_id(actor).unwrap(),
        arkret_sdk::DeviceId::new(device.to_owned()).unwrap(),
    )
    .unwrap();
    let group = identity.create_group(realm.as_bytes()).unwrap();
    assert!(group.current_governance_binding().unwrap().is_none());
    let record = group.export_state_record().unwrap();
    let bytes = serde_json::to_vec(&record).unwrap();
    let snapshot = crate::mls::persistence::encrypt_state(
        realm,
        &record.group_id,
        record.epoch,
        &bytes,
        &secret,
        b"legacy-genesis-salt",
    );
    state.save_mls_snapshot(realm, snapshot).unwrap();
    super::seed_genesis_governance_proof(&mut state, realm);

    let error = initial_mls_snapshot_summary_from_existing(&state, &secure, realm, actor, device)
        .unwrap_err();

    assert!(error.user_message().contains("recreate local MLS state"));
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
