//! Capability grant / revoke builders.
//!
//! Capability grants write the OrSet cell `ak.component.capability.grant.v1`.

use serde_json::Value;

use super::{TypedOperationBuilder, trim_realm_id};

/// Authority-root coordinates a new grant's `realm_root`
/// `issuer_authority_refs` entry binds to.
///
/// Realm creation locks the v1 root to controller epoch 0 / generation 0, so
/// [`Default`] is exactly the genesis basis. After `ak.realm.owner.transfer`
/// or `ak.realm.authority.reset` the values MUST come from the resolved root
/// ([`garth::realm_authority_root_value_for_realm`]), or the
/// grant is minted against a superseded root and its authority audit binds
/// the wrong epoch/generation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IssuerRootBasis {
    pub controller_epoch_at_issuance: u64,
    pub authority_generation: u64,
}

impl IssuerRootBasis {
    /// Coordinates from the locally resolved authority root; genesis (0/0)
    /// when the projection has not resolved the root cell — identical to the
    /// create-locked value for a Realm that never transferred or reset.
    pub fn from_resolved_root(
        root: Option<&arkret_policy::realm_bootstrap::RealmAuthorityRootValue>,
    ) -> Self {
        root.map_or_else(Self::default, |root| Self {
            controller_epoch_at_issuance: root.controller_epoch,
            authority_generation: root.authority_generation,
        })
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
/// `subject` is the delegee DID the grant authorizes; `actor` is the
/// issuer (and the Envelope signer). `resources` defaults to a single
/// `{kind:"realm", realm_id}` selector — the management surface this
/// covers. The Envelope `seal_basis` / signature carries the issuer
/// proof; the per-grant `proofs[]` the strict SDK builder mints is not
/// re-derived here (consistent with the rest of the inkson `ak_ops`
/// event pipeline, which signs at the Envelope boundary).
pub fn capability_grant_actions(
    realm_id: &str,
    actor: &str,
    subject: &str,
    actions: &[&str],
    expires_at: Option<&str>,
    constraints: Value,
    root_basis: IssuerRootBasis,
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
    subject: &str,
    actions: &[&str],
    resources: Vec<arkret_sdk::WireResourceSelector>,
    expires_at: Option<&str>,
    constraints: Value,
    root_basis: IssuerRootBasis,
) -> anyhow::Result<TypedOperationBuilder> {
    let realm = trim_realm_id(realm_id);
    let realm_typed = arkret_sdk::RealmId::new(realm.clone())?;
    let actor_typed = crate::mls_api_helpers::principal_core_id(actor)?;
    let subject_typed = crate::mls_api_helpers::principal_core_id(subject)?;
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
            station_id.clone(),
        )),
        subject: arkret_sdk::CapabilitySubject::Actor(arkret_sdk::ActorId::account(
            arkret_sdk::AccountId::new(subject_typed, station_id),
        )),
        actions: actions.iter().map(|action| (*action).to_owned()).collect(),
        resources,
        constraints: constraints_typed,
        // The root coordinates come from the caller-resolved authority root
        // (`IssuerRootBasis::from_resolved_root`): a Realm that never ran
        // `ak.realm.owner.transfer` / `ak.realm.authority.reset` is still the
        // create-locked epoch 0 / generation 0, and after either transition
        // the grant must bind the superseding root, not genesis.
        issuer_authority_refs: vec![arkret_sdk::IssuerAuthorityRef::RealmRoot {
            realm_id: realm_typed,
            cell_ref: arkret_wire::REALM_AUTHORITY_ROOT_CELL.to_owned(),
            controller_epoch_at_issuance: root_basis.controller_epoch_at_issuance,
            authority_generation: root_basis.authority_generation,
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

    #[test]
    fn grant_binds_the_resolved_root_epoch_and_generation() {
        let operation = capability_grant_actions(
            "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            "did:web:issuer.example",
            "did:web:subject.example",
            &["ak.message.create"],
            None,
            Value::Null,
            IssuerRootBasis {
                controller_epoch_at_issuance: 2,
                authority_generation: 1,
            },
        )
        .unwrap()
        .build_sdk_event("inkson")
        .unwrap();
        assert_eq!(
            operation.payload()["grant"]["issuer_authority_refs"],
            json!([{
                "kind": "realm_root",
                "realm_id": "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
                "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                "controller_epoch_at_issuance": 2,
                "authority_generation": 1
            }])
        );
    }

    #[test]
    fn aggregate_admin_grant_projects_the_registered_cell_write() {
        let operation = capability_grant_actions(
            "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            "did:web:issuer.example",
            "did:web:subject.example",
            &["ak.realm.admin"],
            None,
            Value::Null,
            IssuerRootBasis::default(),
        )
        .unwrap()
        .build_sdk_event("inkson")
        .unwrap();

        assert_eq!(
            operation.payload()["grant"]["issuer_authority_refs"],
            json!([{
                "kind": "realm_root",
                "realm_id": "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
                "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                "controller_epoch_at_issuance": 0,
                "authority_generation": 0
            }])
        );
        // v1 derives the OR-Set write from the registered contract instead of
        // shipping it. The dot is `<event_id>:<write_index>` and the element
        // value is the WHOLE payload (`{"field":"payload"}`), not the inner
        // `grant` object the producer-side table used to stamp. The cell itself
        // is named by `retype(event_id)`, so the write only has a subject once
        // the Event is finalized.
        let event = crate::operation::author_for_test(&operation);
        let projected = arkret_sdk::schema::project_registered_cell_writes_with_authority_resolver(
            &event,
            arkret_sdk::DigestSuite::Sha256,
            &|_| None,
        )
        .unwrap();
        let writes = projected
            .iter()
            .filter_map(arkret_sdk::ProjectedCellWrite::as_direct)
            .collect::<Vec<_>>();
        assert_eq!(writes.len(), 1);
        let grant_id = arkret_sdk::GrantId::from_event_id(event.event_id());
        assert_eq!(
            writes[0].cell_id.as_str(),
            format!("ak:cell:ak.component.capability.grant.v1:{grant_id}")
        );
        assert_eq!(writes[0].op.op_type, arkret_sdk::LatticeOpType::Add);
        assert_eq!(
            writes[0].op.tag.as_deref(),
            Some(format!("{}:0", event.event_id()).as_str())
        );
        let mut projected_payload = operation.payload().clone();
        let projected_grant = projected_payload
            .get_mut("grant")
            .and_then(Value::as_object_mut)
            .unwrap();
        projected_grant.insert("authority_depth".to_owned(), json!(1));
        projected_grant.insert(
            "authority_root_refs".to_owned(),
            json!([{
                "kind": "realm_root",
                "realm_id": "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
                "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                "authority_generation": 0
            }]),
        );
        assert_eq!(
            writes[0].op.value.as_ref(),
            Some(&Value::Object(projected_payload.into_iter().collect()))
        );
    }
}
