//! Tests for §2.9 E2EE reaction sealing and routing-tag derivation.

use crate::mls::runtime::*;
use crate::secure_key_store::MemorySecureKeyStore;
use crate::state::isolated_store_for_tests as temp_state_store;

fn authority(actor: &str) -> arkret_sdk::AccountId {
    arkret_sdk::AccountId {
        principal_id: crate::mls_api_helpers::principal_core_id(actor).unwrap(),
        station_id: arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned())
            .unwrap(),
    }
}

fn typed_device(device: &str) -> arkret_sdk::DeviceId {
    arkret_sdk::DeviceId::new(device.to_owned()).unwrap()
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn minimal_metadata_reaction_forces_commit_when_epoch_overdue() {
    // SEC-08 end-to-end (native): a minimal-metadata Realm whose epoch is
    // older than 1h must force a `ak.mls.commit` (epoch advance) on the next
    // reaction, and MUST NOT persist the advanced snapshot internally
    // (X14 persist-on-accept) — the snapshot is handed back instead.
    use serde_json::json;

    let mut state = temp_state_store("minimal-reaction-force");
    let secure = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";

    // Declare the minimal-metadata profile on the cached projection.
    state.save_realm_tree_projection(
        realm,
        json!({ "schema_refs": [arkret_sdk::ProfileId::MLS_MINIMAL_METADATA_REALM_V1] }),
    );
    assert!(state.realm_projection_is_minimal_metadata(realm));
    crate::identity::authoring_generation::cache_verified_principal_generation_for_test(
        crate::mls_api_helpers::principal_core_id(actor)
            .unwrap()
            .as_str(),
        device,
        "ak:event:AdU2TJKBkRBC1Jk1dY8ExFkUgDvhnVG8jmKT5BdWMeYp",
    );

    super::seed_genesis_governance_proof(&mut state, realm);
    super::seed_human_creator_authorization(actor, device);
    ensure_creator_mls_snapshot(
        &mut state,
        &secure,
        realm,
        &authority(actor),
        &typed_device(device),
    )
    .unwrap();
    super::seed_current_group_state_ref(&mut state, realm);
    let base_epoch = state.mls_snapshot_for(realm).unwrap().epoch;

    // Backdate the persisted snapshot's epoch clock past the 1h cap.
    let mut overdue = state.mls_snapshot_for(realm).unwrap();
    overdue.epoch_started_at = chrono::Utc::now() - chrono::Duration::hours(2);
    state.save_mls_snapshot(realm, overdue).unwrap();
    super::seed_next_governance_proof(&mut state, realm);

    let target =
        arkret_sdk::EventId::new("ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM").unwrap();
    let result = encrypt_reaction_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &authority(actor),
        &typed_device(device),
        &target,
        chrono::Utc::now(),
        "👍",
    );
    let Err(error) = result else {
        panic!("overdue minimal-metadata reaction unexpectedly encrypted");
    };
    assert!(matches!(
        error,
        MlsRuntimeError::EncryptionTransitionPending
    ));
    assert_eq!(state.mls_snapshot_for(realm).unwrap().epoch, base_epoch);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn non_minimal_reaction_never_forces_commit_and_persists_in_place() {
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
            "content_scheme": "mls_rfc9420",
            "member_roster_entries_limited": false,
            "member_roster_entries": [{
                "actor_id": crate::mls_api_helpers::local_account_actor_id(actor).unwrap(),
                "membership": "join"
            }]
        }),
    );
    super::seed_genesis_governance_proof(&mut state, realm);
    super::seed_human_creator_authorization(actor, device);
    ensure_creator_mls_snapshot(
        &mut state,
        &secure,
        realm,
        &authority(actor),
        &typed_device(device),
    )
    .unwrap();
    super::seed_current_group_state_ref(&mut state, realm);
    let base_epoch = state.mls_snapshot_for(realm).unwrap().epoch;
    let mut overdue = state.mls_snapshot_for(realm).unwrap();
    overdue.epoch_started_at = chrono::Utc::now() - chrono::Duration::hours(2);
    state.save_mls_snapshot(realm, overdue).unwrap();

    assert!(!state.realm_projection_is_minimal_metadata(realm));
    let target =
        arkret_sdk::EventId::new("ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM").unwrap();
    let _sealed = encrypt_reaction_with_device_snapshot(
        &mut state,
        &secure,
        realm,
        &authority(actor),
        &typed_device(device),
        &target,
        chrono::Utc::now(),
        "👍",
    )
    .unwrap();
    // Same epoch persisted in place (no skew), epoch clock carried forward.
    let after = state.mls_snapshot_for(realm).unwrap();
    assert_eq!(after.epoch, base_epoch);
}
