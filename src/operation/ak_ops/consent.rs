//! Holder-signed complete exact-peer Consent replacement.

use super::TypedOperationBuilder;

/// Build the `{kind:"actor"}` consent peer for an ordinary Account
/// counterparty.
///
/// Spec `zh/identity/consent-model.md` section 6.1 query step 1 matches this
/// branch on the **complete** ActorId, so the counterparty's own Station is
/// part of the value, not something the granter may leave implicit: a grant
/// written against the wrong Station simply never matches. The counterparty is
/// therefore either pasted as its canonical account selector or typed as a
/// principal together with its Station; there is no fallback to this client's
/// authoring Station, which is not the counterparty's Station and would name a
/// different account whenever they differ (account-lifecycle.md §156/§158).
pub fn consent_actor_peer(
    principal_id: &str,
    station_id: Option<&str>,
) -> anyhow::Result<arkret_sdk::ConsentPeer> {
    Ok(arkret_sdk::ConsentPeer::Actor {
        actor_id: arkret_sdk::ActorId::account(crate::mls_api_helpers::closed_account_id_input(
            principal_id,
            station_id,
        )?),
    })
}

/// Replace the complete exact-peer current under holder root authorization.
/// The expected state comes exclusively from one authenticated complete read.
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
