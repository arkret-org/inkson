//! Holder-signed complete exact-peer permission replacement.

use super::TypedOperationBuilder;

/// Parse a complete ActorId, or an explicit Account principal and Station.
/// The Station and Realm dimensions are never inferred from the local holder.
pub fn consent_actor_peer(
    principal_id: &str,
    station_id: Option<&str>,
) -> anyhow::Result<arkret_sdk::ConsentPeer> {
    if principal_id.trim_start().starts_with('{') {
        if let Ok(actor_id) = serde_json::from_str::<arkret_sdk::ActorId>(principal_id) {
            return Ok(arkret_sdk::ConsentPeer::Actor { actor_id });
        }
    }
    Ok(arkret_sdk::ConsentPeer::Actor {
        actor_id: arkret_sdk::ActorId::account(crate::mls_api_helpers::closed_account_id_input(
            principal_id,
            station_id,
        )?),
    })
}

/// Build one complete exact-peer replacement with the reviewed CAS precondition.
pub fn consent_replace(
    holder_pcr_realm_id: &str,
    holder: &str,
    root_authorization_ref: &arkret_sdk::EventId,
    peer: &arkret_sdk::ConsentPeer,
    expected_current: arkret_sdk::ConsentExpectedCurrent,
    permissions: Vec<arkret_sdk::ConsentPermission>,
) -> anyhow::Result<TypedOperationBuilder> {
    let payload = arkret_sdk::ConsentReplacePayload {
        peer: peer.clone(),
        expected_current,
        permissions,
    };
    payload.validate()?;
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::ConsentReplace>(
            holder_pcr_realm_id,
            holder,
            payload,
        )
        .authorization_ref(root_authorization_ref.as_str()),
    )
}
