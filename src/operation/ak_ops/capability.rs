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
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::CapabilityRevoke,
    )
    .target_ref(grant_id)
    .body(payload_value(&payload, "capability_revoke payload")?))
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
    grant_id: &str,
    subject: &str,
    actions: &[&str],
    expires_at: Option<&str>,
    constraints: Value,
) -> OperationBuilder {
    let realm = trim_realm_id(realm_id);
    let mut grant = json!({
        "id": grant_id,
        "schema": "ak.schema.capability.v1",
        "realm_id": realm,
        "issuer": actor,
        "subject": subject,
        "actions": actions,
        "resources": [{ "kind": "realm", "realm_id": realm }],
        "issued_at": crate::clock::now_rfc3339_secs(),
        "proofs": [],
    });
    if let Some(expires_at) = expires_at {
        grant["expires_at"] = json!(expires_at);
    }
    if !constraints.is_null() {
        grant["constraints"] = constraints;
    }
    OperationBuilder::new(
        &realm,
        actor,
        arkret_sdk::events::kinds::EventKind::CapabilityGrant,
    )
    .target_ref(grant_id)
    .body(json!({
        "grant_id": grant_id,
        "grant": grant,
    }))
}
