//! Holder-signed Consent Event builders. Stable consent_id names one PCR
//! current record; revoke carries its exact RealmCommit revision.

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

/// Build a canonical `ak.consent.grant` Event in the holder's principal
/// control Realm.
///
/// A grant creates a new stable consent_id once. Revoke targets that ID and
/// its exact revision; a revoked ID cannot be granted again. The complete
/// peer ActorId is frozen by the grant.
pub fn consent_grant(
    holder_pcr_realm_id: &str,
    holder: &str,
    root_authorization_ref: &arkret_sdk::EventId,
    consent_id: &arkret_sdk::ConsentId,
    peer: &arkret_sdk::ConsentPeer,
    consent_scope: &str,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> anyhow::Result<TypedOperationBuilder> {
    let payload = arkret_sdk::ConsentGrantPayload {
        consent_id: consent_id.clone(),
        peer: peer.clone(),
        consent_scope: consent_scope.trim().parse()?,
        not_before: None,
        expires_at,
        constraints: None,
        evidence_ref: None,
        reason: None,
    };
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::ConsentGrant>(
            holder_pcr_realm_id,
            holder,
            payload,
        )
        .authorization_ref(root_authorization_ref.as_str()),
    )
}

/// Build a canonical `ak.consent.revoke` Event.
///
/// `expected_revision` MUST be the complete typed revision the holder just read
/// back from the current consent result. The governance Station compares both
/// the RealmCommit id and stream position; neither coordinate may be rebuilt or
/// reduced to a local counter. That exact compare closes the concurrent-revoke
/// race the observed-dot vocabulary used to carry.
pub fn consent_revoke(
    holder_pcr_realm_id: &str,
    holder: &str,
    root_authorization_ref: &arkret_sdk::EventId,
    consent_id: &arkret_sdk::ConsentId,
    expected_revision: &arkret_sdk::CurrentRevision,
) -> anyhow::Result<TypedOperationBuilder> {
    let payload = arkret_sdk::ConsentRevokePayload {
        consent_id: consent_id.clone(),
        expected_revision: expected_revision.clone(),
        revoked_at: Some(crate::clock::now_utc_millis()),
        reason: None,
    };
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::ConsentRevoke>(
            holder_pcr_realm_id,
            holder,
            payload,
        )
        .authorization_ref(root_authorization_ref.as_str()),
    )
}
