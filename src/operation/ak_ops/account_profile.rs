use super::*;

// Both builders take the author's closed `AccountId`: the caller has already
// verified it against the durable PCR evidence, so the Station is named
// explicitly instead of being read back from the ambient authoring slot
// (account-lifecycle.md §156).
pub fn account_profile_create(
    principal_control_realm_id: &arkret_sdk::RealmId,
    account_id: &arkret_sdk::AccountId,
    profile: arkret_models_identity::ActorProfile,
) -> anyhow::Result<crate::operation::LocalOperation> {
    TypedOperationBuilder::new_for_station::<arkret_sdk::event_spec::ProfileCreate>(
        principal_control_realm_id.as_str(),
        account_id.principal_id.as_str(),
        account_id.station_id.clone(),
        arkret_models_collaboration::events_payloads::ActorProfileCreatePayload { object: profile },
    )
    .build_sdk_event("inkson")
}

pub fn account_profile_update(
    principal_control_realm_id: &arkret_sdk::RealmId,
    account_id: &arkret_sdk::AccountId,
    profile_id: arkret_sdk::ActorProfileId,
    patch: arkret_sdk::Patch,
) -> anyhow::Result<crate::operation::LocalOperation> {
    TypedOperationBuilder::new_for_station::<arkret_sdk::event_spec::ProfileUpdate>(
        principal_control_realm_id.as_str(),
        account_id.principal_id.as_str(),
        account_id.station_id.clone(),
        arkret_models_collaboration::events_payloads::ActorProfileUpdatePayload {
            target_ref: profile_id,
            patch,
            expected_state_digest: None,
        },
    )
    .build_sdk_event("inkson")
}
