//! Consent Control Move builders.
//!
//! `ak.self.consent.command.{grant,revoke}` take the holder-signed Control Move,
//! so both are authored here. `consent_id` is producer-allocated (it is the cell
//! subject, not something derived from an Event), and the or_set add dot falls out
//! of the Event's own `event_id`, so neither is the server's to pick.

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
///
/// There is deliberately no string-shaped path into the
/// `{kind:"pairwise_principal"}` branch. That branch names a Realm-local
/// ephemeral pairwise actor, which only exists as a `(realm_id, principal_id)`
/// pair inside a minimal-metadata Realm; callers obtain one from a real
/// pairwise identity or read it back from an existing cell, never by guessing
/// a kind from the shape of a DID.
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

/// Build a canonical `ak.consent.grant` Control Move in the holder's principal
/// control Realm.
///
/// `consent_id` is the cell subject: the same value must be reused by every later
/// grant or revoke on that cell, so callers pass one they already hold rather than
/// letting this mint a fresh one per call. `peer` is the exact closed
/// `consent_peer` this cell freezes; both kinds go through unchanged, because
/// the two are separate identities and the builder is not allowed to pick one.
pub fn consent_grant(
    holder_pcr_realm_id: &str,
    holder: &str,
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
    )
}

/// Build a canonical `ak.consent.revoke` Event.
///
/// `expected_revision` MUST be the `revision.stream_position` the holder just
/// read back from the current consent result. The governance Station rejects a
/// revoke whose expected revision has moved on, which is what closes the
/// concurrent-revoke race the observed-dot vocabulary used to carry.
pub fn consent_revoke(
    holder_pcr_realm_id: &str,
    holder: &str,
    consent_id: &arkret_sdk::ConsentId,
    expected_revision: u64,
) -> anyhow::Result<TypedOperationBuilder> {
    let payload = arkret_sdk::ConsentRevokePayload {
        consent_id: consent_id.clone(),
        expected_revision,
        revoked_at: Some(crate::clock::now_utc_millis()),
        reason: None,
    };
    Ok(TypedOperationBuilder::new::<
        arkret_sdk::event_spec::ConsentRevoke,
    >(holder_pcr_realm_id, holder, payload))
}

