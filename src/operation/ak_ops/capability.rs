//! Capability grant / revoke builders.
//!
//! Capability grants write the OrSet cell `ak.component.capability.grant.v1`.

use serde_json::{Value, json};

use super::{OperationBuilder, payload_value, trim_realm_id};

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
) -> anyhow::Result<OperationBuilder> {
    let grant_id_typed = arkret_sdk::GrantId::new(grant_id.to_owned())
        .map_err(|err| anyhow::anyhow!("capability revoke grant_id {grant_id:?}: {err}"))?;
    let payload = arkret_sdk::CapabilityRevokePayload {
        grant_ref: None,
        grant_id: grant_id_typed,
        reason: reason.map(ToOwned::to_owned),
    };
    Ok(
        OperationBuilder::new(realm_id, actor, arkret_sdk::EventKind::CapabilityRevoke)
            .target_ref(grant_id)
            .body(payload_value(&payload, "capability_revoke payload")?),
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
/// covers. The submit pipeline attaches the grant's issuer-attestation
/// proof before freezing the durable semantic intent, then signs the outer
/// Event envelope separately.
pub fn capability_grant_actions(
    realm_id: &str,
    actor: &str,
    grant_id: &str,
    subject: &str,
    actions: &[&str],
    expires_at: Option<&str>,
    constraints: Value,
) -> OperationBuilder {
    let realm = trim_realm_id(realm_id);
    capability_grant_actions_with_resources(
        &realm,
        actor,
        grant_id,
        subject,
        actions,
        vec![json!({ "kind": "realm", "realm_id": realm })],
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
    grant_id: &str,
    subject: &str,
    actions: &[&str],
    resources: Vec<Value>,
    expires_at: Option<&str>,
    constraints: Value,
) -> OperationBuilder {
    let realm = trim_realm_id(realm_id);
    let constraints = match constraints {
        Value::Null => json!([non_regrantable_authority_constraint()]),
        Value::Array(mut items) => {
            let has_authority_control = items.iter().any(|item| {
                item.get("constraint_kind").and_then(Value::as_str) == Some("authority_control")
            });
            if !has_authority_control {
                items.push(non_regrantable_authority_constraint());
            }
            Value::Array(items)
        }
        other => other,
    };
    let mut grant = json!({
        "id": grant_id,
        "schema": "ak.schema.capability.v1",
        "realm_id": realm,
        "issuer": actor,
        "subject": subject,
        "actions": actions,
        "resources": resources,
        // Current Inkson authoring supports direct Realm-root issuance. The
        // typed ref is part of the signed grant body; membership / created_by
        // must never be inferred as authority by the receiver.
        "issuer_authority_refs": [{
            "kind": "realm_root",
            "realm_id": realm,
            "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
            "controller_epoch_at_issuance": 0,
            "authority_generation": 0,
        }],
        "issued_at": crate::clock::now_timestamp(),
        "constraints": constraints,
        "proofs": [],
    });
    let carries_aggregate_admin = actions.iter().any(|action| {
        arkret_sdk::schema::embedded_capability_action(action)
            .ok()
            .flatten()
            .is_some_and(|descriptor| descriptor.event_mapping_kind == "aggregate_admin")
    });
    if carries_aggregate_admin {
        grant["capability_action_registry_digest"] = json!(
            arkret_sdk::current_capability_action_registry_digest()
                .expect("embedded capability-action registry must be available to author grants")
        );
    }
    if let Some(expires_at) = expires_at {
        grant["expires_at"] = json!(expires_at);
    }
    OperationBuilder::new(&realm, actor, arkret_sdk::EventKind::CapabilityGrant)
        .target_ref(grant_id)
        .body(json!({
            "grant_id": grant_id,
            "grant": grant,
        }))
}

fn non_regrantable_authority_constraint() -> Value {
    json!({
        "constraint_kind": "authority_control",
        "effect": "allow",
        "max_authority_depth": 0,
        "authority_regrant_allowed": false,
        "authority_scope": "narrowing_only",
        "scope_expansion_allowed": false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_admin_grant_authorship_binds_the_registry_snapshot() {
        let event = capability_grant_actions(
            "ak:realm:019f9000-0000-7000-8000-000000000001",
            "did:web:issuer.example",
            "ak:grant:019f9000-0000-7000-8000-000000000002",
            "did:web:subject.example",
            &["ak.realm.admin"],
            None,
            Value::Null,
        )
        .build_sdk_event("inkson")
        .unwrap();

        assert_eq!(
            event.payload["grant"]["capability_action_registry_digest"],
            serde_json::to_value(arkret_sdk::current_capability_action_registry_digest().unwrap())
                .unwrap()
        );
        assert_eq!(
            event.payload["grant"]["issuer_authority_refs"],
            json!([{
                "kind": "realm_root",
                "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000001",
                "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                "controller_epoch_at_issuance": 0,
                "authority_generation": 0,
            }])
        );
        assert_eq!(
            event.payload["grant"]["constraints"],
            json!([{
                "constraint_kind": "authority_control",
                "effect": "allow",
                "max_authority_depth": 0,
                "authority_regrant_allowed": false,
                "authority_scope": "narrowing_only",
                "scope_expansion_allowed": false,
            }])
        );
        // v1 derives the OR-Set write from the registered contract instead of
        // shipping it. The dot is `<event_id>:<write_index>` and the element
        // value is the WHOLE payload (`{"field":"payload"}`), not the inner
        // `grant` object the producer-side table used to stamp.
        let writes = crate::operation::direct_registered_cell_writes(&event).unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(
            writes[0].cell.as_str(),
            "ak:cell:ak.component.capability.grant.v1:ak:grant:019f9000-0000-7000-8000-000000000002"
        );
        assert_eq!(writes[0].op.op_type, arkret_sdk::LatticeOpType::Add);
        assert_eq!(
            writes[0].op.tag.as_deref(),
            Some(format!("{}:0", event.event_id).as_str())
        );
        assert_eq!(
            writes[0].op.value.as_ref(),
            Some(&Value::Object(
                event
                    .payload
                    .clone()
                    .into_iter()
                    .collect::<serde_json::Map<_, _>>()
            ))
        );
    }
}
