//! Consent Control Move builders.
//!
//! `ak.self.consent.command.{grant,revoke}` take the holder-signed Control Move,
//! so both are authored here. `consent_id` is producer-allocated (it is the cell
//! subject, not something derived from an Event), and the or_set add dot falls out
//! of the Event's own `event_id`, so neither is the server's to pick.

use super::{TypedOperationBuilder, did_id};

/// Build the `{kind:"actor"}` consent peer for an ordinary Account
/// counterparty.
///
/// Spec `zh/identity/consent-model.md` section 6.1 query step 1 matches this
/// branch on the **complete** ActorId, so the counterparty's own Station is
/// part of the value, not something the granter may leave implicit: a grant
/// written against the wrong Station simply never matches. `station_id` is
/// therefore explicit, defaulting to this client's authoring Station only for
/// a counterparty hosted here.
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
    let station_id = match station_id.map(str::trim).filter(|value| !value.is_empty()) {
        Some(station_id) => did_id(station_id)?,
        None => crate::operation::authoring_station_id()?,
    };
    Ok(arkret_sdk::ConsentPeer::Actor {
        actor_id: arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            did_id(principal_id)?,
            station_id,
        )),
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
        .authorization_ref(arkret_wire::REALM_AUTHORITY_ROOT_CELL),
    )
}

/// Build a canonical `ak.consent.revoke` Control Move.
///
/// `observed_dots` MUST enumerate every active dot that becomes inactive, read
/// back from `ConsentCellView::active_grant_dots`. An observe-remove OR-Set
/// revoker that does not name the dots it observed lets two concurrent revokes
/// race, one removing the old dot and the other the new one while both report
/// success (spec `zh/identity/consent-model.md` section 3.2).
pub fn consent_revoke(
    holder_pcr_realm_id: &str,
    holder: &str,
    consent_id: &arkret_sdk::ConsentId,
    observed_dots: &[String],
) -> anyhow::Result<TypedOperationBuilder> {
    if observed_dots.is_empty() {
        anyhow::bail!(
            "ak.consent.revoke requires at least one observed dot; \
             read them from ConsentCellView::active_grant_dots"
        );
    }
    let payload = arkret_sdk::ConsentRevokePayload {
        consent_id: consent_id.clone(),
        observed_dot_ids: observed_dots
            .iter()
            .cloned()
            .map(arkret_sdk::ConsentObservedDot::new)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(anyhow::Error::from)?,
        revoked_at: Some(crate::clock::now_utc_millis()),
        reason: None,
    };
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::ConsentRevoke>(
            holder_pcr_realm_id,
            holder,
            payload,
        )
        .authorization_ref(arkret_wire::REALM_AUTHORITY_ROOT_CELL),
    )
}

/// Recover the `consent_id` a consent cell is keyed on from its `cell_id`.
///
/// `cell_id` is `ak:cell:ak.component.consent.grant.v1:<consent_id>` (spec
/// `zh/identity/consent-model.md` section 3.1). A cell keyed on a digest
/// subject instead has no recoverable `consent_id`, and revoking it needs that
/// subject repaired first rather than a guess here.
pub fn consent_id_from_cell_id(cell_id: &str) -> anyhow::Result<arkret_sdk::ConsentId> {
    const PREFIX: &str = "ak:cell:ak.component.consent.grant.v1:";
    let subject = cell_id.strip_prefix(PREFIX).ok_or_else(|| {
        anyhow::anyhow!("consent cell_id {cell_id:?} is not an ak.component.consent.grant.v1 cell")
    })?;
    arkret_sdk::ConsentId::new(subject.to_owned()).map_err(|err| {
        anyhow::anyhow!(
            "consent cell {cell_id:?} is keyed on {subject:?}, not a consent_id, \
             so its subject must be repaired before it can be revoked: {err:?}"
        )
    })
}
