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
}

#[test]
fn only_unaccepted_epoch_zero_snapshot_can_be_recreated() {
    let mut state = temp_state_store("genesis-unaccepted-recreate");
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

    let recreated = recreate_unaccepted_creator_mls_checkpoint(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
    )
    .expect("unaccepted epoch-0 state may be safely recreated");
    let replacement = state.mls_checkpoint_for(realm).unwrap();
    assert_eq!(recreated.epoch, 0);
    assert_eq!(replacement.epoch, 0);
    assert_eq!(replacement.group_id, staged.group_id);
    assert_ne!(replacement.salt_hex, staged.salt_hex);
    assert!(replacement.group_state_event_id.is_none());

    let accepted =
        arkret_sdk::EventId::new("ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk").unwrap();
    state
        .mark_mls_genesis_emitted_with_event(realm, &accepted)
        .unwrap();
    assert!(
        recreate_unaccepted_creator_mls_checkpoint(
            &mut state,
            &secure,
            realm,
            &fixture::authority(actor),
            &fixture::device_id(device),
        )
        .is_err()
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
