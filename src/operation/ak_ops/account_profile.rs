use super::*;

pub fn account_profile_create(
    principal_control_realm_id: &arkret_sdk::RealmId,
    principal_id: &arkret_sdk::DidCoreId,
    profile: arkret_models_identity::ActorProfile,
) -> anyhow::Result<crate::operation::LocalOperation> {
    TypedOperationBuilder::new::<arkret_sdk::event_spec::ProfileCreate>(
        principal_control_realm_id.as_str(),
        principal_id.as_str(),
        arkret_models_collaboration::events_payloads::ActorProfileCreatePayload { object: profile },
    )
    .build_sdk_event("inkson")
}

pub fn account_profile_update(
    principal_control_realm_id: &arkret_sdk::RealmId,
    principal_id: &arkret_sdk::DidCoreId,
    profile_id: arkret_sdk::ActorProfileId,
    patch: arkret_sdk::Patch,
) -> anyhow::Result<crate::operation::LocalOperation> {
    TypedOperationBuilder::new::<arkret_sdk::event_spec::ProfileUpdate>(
        principal_control_realm_id.as_str(),
        principal_id.as_str(),
        arkret_models_collaboration::events_payloads::ActorProfileUpdatePayload {
            target_ref: profile_id,
            patch,
            expected_state_digest: None,
        },
    )
    .build_sdk_event("inkson")
}
