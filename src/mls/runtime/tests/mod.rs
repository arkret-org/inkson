//! Unit and integration tests for the MLS runtime helpers, grouped by the
//! runtime submodule each set exercises.

fn seed_human_creator_authorization(actor: &str, device: &str) {
    let actor = crate::mls_api_helpers::principal_core_id(actor).unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[41; 32])
        .verifying_key()
        .to_bytes()
        .to_vec();
    crate::identity::device_directory::seed_device_authorization_for_test(
        actor.as_str(),
        device,
        arkret_sdk::signatures::PublicKeyMaterial::Ed25519Raw { bytes: key },
        arkret_sdk::EventId::new(
            "ak:event:AdU2TJKBkRBC1Jk1dY8ExFkUgDvhnVG8jmKT5BdWMeYp".to_owned(),
        )
        .unwrap(),
    );
}

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

mod genesis_backup;
mod message;
mod reaction;
