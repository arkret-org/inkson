//! Tests for §2.9 E2EE reaction sealing and routing-tag derivation.

use crate::mls::runtime::*;
use crate::secure_key_store::MemorySecureKeyStore;
use crate::state::isolated_store_for_tests as temp_state_store;
use crate::test_support as fixture;

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn retired_minimal_metadata_marker_rejects_reaction_before_checkpoint_access() {
    // 0352 D1: the old marker is neither a profile activation nor a reason
    // to enter the dedicated pairwise/one-hour branch. Reject even when a
    // checkpoint is absent, so ordinary MLS readiness cannot mask this fact.
    use serde_json::json;

    let mut state = temp_state_store("retired-minimal-reaction");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";

    state.save_realm_tree_projection(
        realm,
        json!({ "schema_refs": ["ak.profile.mls.minimal_metadata_realm.v1"] }),
    );
    assert!(state.realm_projection_has_retired_minimal_metadata_marker(realm));

    let target =
        arkret_sdk::EventId::new("ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM").unwrap();
    let result = encrypt_reaction_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
        &target,
        chrono::Utc::now(),
        "👍",
    );
    assert!(
        matches!(result, Err(MlsRuntimeError::Identity(message)) if message.contains("retired minimal-metadata"))
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn non_minimal_reaction_never_forces_commit_and_persists_in_place() {
    // Creator fixtures share the session tests' exact device-directory cache.
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
    // Control: a non-minimal Realm with an equally-old epoch never forces a
    // commit; the reaction rides the current epoch and persists immediately.
    let mut state = temp_state_store("non-minimal-reaction");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy";

    state.save_realm_tree_projection(
        realm,
        serde_json::json!({
            "member_roster_entries_limited": false,
            "member_roster_entries": [{
                "actor_id": crate::mls_api_helpers::local_account_actor_id(actor).unwrap(),
                "membership": "join"
            }]
        }),
    );
    fixture::install_accepted_mls_group(
        &mut state,
        &arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
        },
    );
    super::seed_human_creator_authorization(actor, device);
    ensure_creator_mls_checkpoint(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
    )
    .unwrap();
    super::seed_current_group_state_ref(&mut state, realm);
    let base_epoch = state.mls_checkpoint_for(realm).unwrap().epoch;
    let mut overdue = state.mls_checkpoint_for(realm).unwrap();
    overdue.epoch_started_at = chrono::Utc::now() - chrono::Duration::hours(2);
    state.save_mls_checkpoint(realm, overdue).unwrap();

    assert!(!state.realm_projection_is_minimal_metadata(realm));
    let target =
        arkret_sdk::EventId::new("ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM").unwrap();
    let _sealed = encrypt_reaction_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
        &target,
        chrono::Utc::now(),
        "👍",
    )
    .unwrap();
    // Same epoch persisted in place (no skew), epoch clock carried forward.
    let after = state.mls_checkpoint_for(realm).unwrap();
    assert_eq!(after.epoch, base_epoch);
}
