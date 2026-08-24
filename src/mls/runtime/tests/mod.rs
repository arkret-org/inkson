//! Unit and integration tests for the MLS runtime helpers, grouped by the
//! runtime submodule each set exercises.

fn seed_genesis_governance_proof(
    state: &mut crate::state::LocalStateStore,
    realm_id: &str,
) -> arkret_sdk::MlsGovernanceBindingPayload {
    crate::mls::governance_proof::seed_test_governance_proof(
        state,
        realm_id,
        None,
        arkret_sdk::base64url_encode(realm_id.as_bytes()),
        0,
        0,
    )
}

fn seed_next_governance_proof(
    state: &mut crate::state::LocalStateStore,
    realm_id: &str,
) -> arkret_sdk::MlsGovernanceBindingPayload {
    let snapshot = state.mls_snapshot_for(realm_id).unwrap();
    crate::mls::governance_proof::seed_test_governance_proof(
        state,
        realm_id,
        None,
        snapshot.group_id,
        snapshot.epoch,
        snapshot.epoch + 1,
    )
}

fn seed_current_group_state_ref(
    state: &mut crate::state::LocalStateStore,
    realm_id: &str,
) -> arkret_sdk::EventId {
    let snapshot = state.mls_snapshot_for(realm_id).unwrap();
    let event_id =
        arkret_sdk::EventId::new("ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml").unwrap();
    state
        .record_mls_group_state_ref_for_effective_scope(
            realm_id,
            None,
            &snapshot.group_id,
            snapshot.epoch,
            event_id.clone(),
        )
        .unwrap();
    event_id
}

mod commit;
mod genesis_backup;
mod message;
mod reaction;
mod secret;
