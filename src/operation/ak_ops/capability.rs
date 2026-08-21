//! Capability grant / revoke builders.
//!
//! Capability grants write the OrSet cell `ak.component.capability.grant.v1`.

use serde_json::Value;

use super::{TypedOperationBuilder, trim_realm_id};

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
) -> anyhow::Result<TypedOperationBuilder> {
    let realm = trim_realm_id(realm_id);
    let realm_typed = arkret_sdk::RealmId::new(realm.clone())?;
    let actor_typed = crate::mls_api_helpers::principal_core_id(actor)?;
    let subject_typed = crate::mls_api_helpers::principal_core_id(subject)?;
    let constraints_typed = if constraints.is_null() {
        Vec::new()
    } else {
        serde_json::from_value::<Vec<arkret_sdk::GrantConstraint>>(constraints)?
    };
    let carries_aggregate_admin = actions.iter().any(|action| {
        arkret_sdk::schema::embedded_capability_action(action)
            .ok()
            .flatten()
            .is_some_and(|descriptor| descriptor.event_mapping_kind == "aggregate_admin")
    });
    let registry_digest = carries_aggregate_admin
        .then(arkret_sdk::current_capability_action_registry_digest)
        .transpose()?;
    let expires_at = expires_at
        .map(str::parse)
        .transpose()
        .map_err(|error| anyhow::anyhow!("invalid capability grant expires_at: {error}"))?;
    let grant = arkret_sdk::CapabilityGrantCreateBody {
        schema: arkret_wire::SchemaId::CAPABILITY_V1.to_owned(),
        realm_id: Some(realm_typed.clone()),
        issuer: actor_typed,
        subject: arkret_sdk::CapabilitySubject::CoreDid(subject_typed),
        subject_principal_server_id: Some(crate::operation::authoring_principal_server_id()?),
        actions: actions.iter().map(|action| (*action).to_owned()).collect(),
        resources,
        capability_action_registry_digest: registry_digest,
        constraints: constraints_typed,
        // Realm creation locks the v1 authority root to controller epoch 0 and
        // generation 0. Owner transfer/reset is not a v1 authoring surface;
        // when it is introduced this value must come from the resolved root.
        issuer_authority_refs: vec![arkret_sdk::IssuerAuthorityRef::RealmRoot {
            realm_id: realm_typed,
            cell_ref: arkret_wire::REALM_AUTHORITY_ROOT_CELL.to_owned(),
            controller_epoch_at_issuance: 0,
            authority_generation: 0,
        }],
        issued_at: crate::clock::now_utc_millis(),
        not_before: None,
        expires_at,
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
    fn aggregate_admin_grant_authorship_binds_the_registry_snapshot() {
        let operation = capability_grant_actions(
            "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            "did:web:issuer.example",
            "did:web:subject.example",
            &["ak.realm.admin"],
            None,
            Value::Null,
        )
        .unwrap()
        .build_sdk_event("inkson")
        .unwrap();

        assert_eq!(
            operation.payload()["grant"]["capability_action_registry_digest"],
            serde_json::to_value(arkret_sdk::current_capability_action_registry_digest().unwrap())
                .unwrap()
        );
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
        let writes = crate::operation::direct_registered_cell_writes(
            &event,
            arkret_sdk::DigestSuite::Sha256,
        )
        .unwrap();
        assert_eq!(writes.len(), 1);
        let grant_id = arkret_sdk::GrantId::from_event_id(event.event_id());
        assert_eq!(
            writes[0].cell.as_str(),
            format!("ak:cell:ak.component.capability.grant.v1:{grant_id}")
        );
        assert_eq!(writes[0].op.op_type, arkret_sdk::LatticeOpType::Add);
        assert_eq!(
            writes[0].op.tag.as_deref(),
            Some(format!("{}:0", event.event_id()).as_str())
        );
        let mut projected_payload = operation.payload().clone();
        projected_payload
            .get_mut("grant")
            .and_then(Value::as_object_mut)
            .unwrap()
            .insert(
                "issuer_principal_server_id".to_owned(),
                Value::String(operation.intent().principal_server_id().to_string()),
            );
        assert_eq!(
            writes[0].op.value.as_ref(),
            Some(&Value::Object(projected_payload.into_iter().collect()))
        );
    }
}
