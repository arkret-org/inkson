//! Capability grant / revoke builders.
//!
//! Capability grants write the OrSet cell `ak.component.capability.grant.v1`.

use serde_json::Value;

use super::{TypedOperationBuilder, trim_realm_id};

/// The committed Realm-authority decision a new grant's `realm_authority`
/// `issuer_authority_refs` entry binds to.
///
/// It names the governance Station that admitted the decision, the authority
/// generation it was admitted under, and the exact committed Event that carries
/// it. All three come from the verified `RealmAuthorityBundle` the client
/// authenticated for this Realm: a grant minted against a superseded generation
/// binds an authority route that is no longer current.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerRealmAuthorityBasis {
    pub governance_station_id: arkret_sdk::DidCoreId,
    pub authority_generation: u64,
    pub basis: arkret_wire::CommittedEventRef,
}

impl IssuerRealmAuthorityBasis {
    /// Coordinates taken from a `RealmAuthorityBundle` this client already
    /// validated for `realm_id`, using the genesis commit when the Realm has
    /// never handed its authority off and the last transition otherwise.
    pub fn from_verified_bundle(bundle: &arkret_wire::RealmAuthorityBundle) -> Self {
        let (event_id, commit) = bundle.authority_transitions.last().map_or_else(
            || (&bundle.genesis_event.event_id, &bundle.genesis_commit),
            |transition| (&transition.change_event.event_id, &transition.change_commit),
        );
        Self {
            governance_station_id: bundle.current_service_id.clone(),
            authority_generation: bundle.current_generation,
            basis: arkret_wire::CommittedEventRef {
                event_id: event_id.clone(),
                commit_id: commit.commit_id.clone(),
                stream_ref: commit.stream_ref.clone(),
                stream_position: commit.stream_position,
            },
        }
    }
}

/// `ak.capability.revoke` — drop a standing grant, addressed by `grant_id`.
/// `reason` shows up in the audit trail and lets the UI explain why the
/// capability was dropped.
///
/// Uses the SDK `CapabilityRevokePayload` strong type
/// (`event-payload.schema.json#/$defs/capability_revoke_payload`,
/// `deny_unknown_fields`) so the wire body cannot drift — the earlier hand
/// -rolled body carried a `tag` field the schema forbids.
pub fn capability_revoke(
    realm_id: &str,
    actor: &str,
    grant_id: &str,
    reason: Option<&str>,
) -> anyhow::Result<TypedOperationBuilder> {
    let grant_id_typed = arkret_sdk::GrantId::new(grant_id.to_owned())
        .map_err(|err| anyhow::anyhow!("capability revoke grant_id {grant_id:?}: {err}"))?;
    let payload = arkret_sdk::CapabilityRevokePayload {
        grant_ref: None,
        grant_id: grant_id_typed,
        reason: reason.map(ToOwned::to_owned),
    };
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::CapabilityRevoke>(
            realm_id, actor, payload,
        )
        .target_ref(grant_id),
    )
}

/// `ak.capability.grant` event carrying the canonical
/// `capability_grant_payload` wrapper (`{grant_id, grant:{…}}`) the P1
/// soland reducer (`apply_capability`) reads `issuer` / `subject` /
/// `actions` / `resources` from. This is the only capability-grant
/// builder: every directed grant (e.g. setting a Realm admin via
/// `actions=[ak.realm.admin]`, or an admin-panel capability grant to a
/// `subject`) carries the full grant object, because the reducer fails
/// closed on a grant body with no `issuer` or no `actions`.
///
/// `subject` is the delegee's complete account; `actor` is the issuer (and
/// the Envelope signer). The subject is closed by the caller (resolved from
/// the Realm roster or pasted as the canonical selector) because a grant to
/// `(principal, this Station)` for a member hosted elsewhere would name an
/// account that is not in the Realm at all (account-lifecycle.md §156).
/// `resources` defaults to a single
/// `{kind:"realm", realm_id}` selector — the management surface this
/// covers. The Envelope `seal_basis` / signature carries the issuer
/// proof; the per-grant `proofs[]` the strict SDK builder mints is not
/// re-derived here (consistent with the rest of the inkson `ak_ops`
/// event pipeline, which signs at the Envelope boundary).
pub fn capability_grant_actions(
    realm_id: &str,
    actor: &str,
    subject: &arkret_sdk::AccountId,
    actions: &[&str],
    expires_at: Option<&str>,
    constraints: Value,
    root_basis: &IssuerRealmAuthorityBasis,
) -> anyhow::Result<TypedOperationBuilder> {
    let realm = trim_realm_id(realm_id);
    capability_grant_actions_with_resources(
        &realm,
        actor,
        subject,
        actions,
        vec![arkret_sdk::WireResourceSelector::realm(
            arkret_sdk::RealmId::new(realm.clone())?,
        )],
        expires_at,
        constraints,
        root_basis,
    )
}

// Invariant assertions: each `expect` message names the check that
// establishes it a few lines earlier. Rewriting them as `?` would add
// error paths no caller can reach.
#[allow(clippy::expect_used)]
/// Build a capability grant with caller-supplied canonical resource selectors.
/// Participation uses this form for Circle and Strand scopes; the ordinary
/// Realm-admin helper above keeps its Realm-wide default.
pub fn capability_grant_actions_with_resources(
    realm_id: &str,
    actor: &str,
    subject: &arkret_sdk::AccountId,
    actions: &[&str],
    resources: Vec<arkret_sdk::WireResourceSelector>,
    expires_at: Option<&str>,
    constraints: Value,
    root_basis: &IssuerRealmAuthorityBasis,
) -> anyhow::Result<TypedOperationBuilder> {
    let realm = trim_realm_id(realm_id);
    let realm_typed = arkret_sdk::RealmId::new(realm.clone())?;
    let actor_typed = crate::mls_api_helpers::principal_core_id(actor)?;
    let expires_at = expires_at
        .map(str::parse)
        .transpose()
        .map_err(|error| anyhow::anyhow!("invalid capability grant expires_at: {error}"))?;
    let mut constraints_typed = if constraints.is_null() {
        Vec::new()
    } else {
        serde_json::from_value::<Vec<arkret_sdk::GrantConstraint>>(constraints)?
    };
    if let Some(expires_at) = expires_at {
        let mut temporal = arkret_sdk::GrantConstraint::new(
            arkret_sdk::GrantConstraintKind::Temporal,
            arkret_sdk::GrantConstraintEffect::Allow,
        );
        temporal.expires_at = Some(expires_at);
        constraints_typed.push(temporal);
    }
    let station_id = crate::operation::authoring_station_id()?;
    let grant = arkret_sdk::CapabilityGrantCreateBody {
        schema: arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),
        realm_id: Some(realm_typed.clone()),
        issuer_id: arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            actor_typed,
            station_id,
        )),
        subject: arkret_sdk::CapabilitySubject::Actor(arkret_sdk::ActorId::account(
            subject.clone(),
        )),
        actions: actions.iter().map(|action| (*action).to_owned()).collect(),
        resources,
        constraints: constraints_typed,
        // The authority coordinates come from the caller-verified
        // `RealmAuthorityBundle` (`IssuerRealmAuthorityBasis::from_verified_bundle`):
        // the grant binds the exact committed decision and the generation it was
        // admitted under, so a later handoff cannot be mistaken for the one this
        // grant was issued against.
        issuer_authority_refs: vec![arkret_sdk::IssuerAuthorityRef::RealmAuthority {
            realm_id: realm_typed,
            governance_station_id: root_basis.governance_station_id.clone(),
            authority_generation: root_basis.authority_generation,
            basis: root_basis.basis.clone(),
        }],
        issued_at: crate::clock::now_utc_millis(),
    };
    let payload = arkret_sdk::CapabilityGrantPayload { grant };
    Ok(TypedOperationBuilder::new::<
        arkret_sdk::event_spec::CapabilityGrant,
    >(&realm, actor, payload))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn authority_basis(generation: u64) -> IssuerRealmAuthorityBasis {
        IssuerRealmAuthorityBasis {
            governance_station_id: arkret_sdk::DidCoreId::new("ak:did_core:web:station.example")
                .unwrap(),
            authority_generation: generation,
            basis: arkret_wire::CommittedEventRef {
                event_id: arkret_sdk::EventId::new(
                    "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                )
                .unwrap(),
                commit_id: arkret_sdk::RealmCommitId::new(
                    "ak:realm_commit:0196419b-0000-7000-8000-000000000001",
                )
                .unwrap(),
                stream_ref: arkret_wire::CommitStreamRef::Realm {
                    realm_id: arkret_sdk::RealmId::new(
                        "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
                    )
                    .unwrap(),
                },
                stream_position: 0,
            },
        }
    }

    #[test]
    fn grant_binds_the_committed_realm_authority_decision() {
        let operation = capability_grant_actions(
            "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            "did:web:issuer.example",
            &crate::test_support::authority("did:web:subject.example"),
            &["ak.message.create"],
            None,
            Value::Null,
            &authority_basis(1),
        )
        .unwrap()
        .build_sdk_event("inkson")
        .unwrap();
        assert_eq!(
            operation.payload()["grant"]["issuer_authority_refs"],
            json!([{
                "kind": "realm_authority",
                "realm_id": "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
                "governance_station_id": "ak:did_core:web:station.example",
                "authority_generation": 1,
                "basis": {
                    "event_id": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                    "commit_id": "ak:realm_commit:0196419b-0000-7000-8000-000000000001",
                    "stream_ref": {
                        "kind": "realm",
                        "realm_id": "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM"
                    },
                    "stream_position": 0
                }
            }])
        );
    }

    #[test]
    fn a_later_authority_generation_produces_a_different_issuer_ref() {
        let build = |generation: u64| {
            capability_grant_actions(
                "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
                "did:web:issuer.example",
                &crate::test_support::authority("did:web:subject.example"),
                &["ak.realm.admin"],
                None,
                Value::Null,
                &authority_basis(generation),
            )
            .unwrap()
            .build_sdk_event("inkson")
            .unwrap()
            .payload()["grant"]["issuer_authority_refs"]
                .clone()
        };
        assert_ne!(build(0), build(1));
    }
}
