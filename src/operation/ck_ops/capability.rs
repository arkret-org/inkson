//! Capability grant / revoke builders.
//!
//! Capability grants write the OrSet cell `ck.component.capability.grant.v1`.

use serde_json::{Value, json};

use super::{OperationBuilder, trim_realm_id};

/// `ck.capability.grant` event with optional structured constraints
/// (e.g. `temporal.window`). `tag` is the capability action the grant
/// authorises (e.g. `discussion.message.create`).
pub fn capability_grant(
    realm_id: &str,
    actor: &str,
    grant_id: &str,
    tag: &str,
    constraints: Value,
) -> OperationBuilder {
    let mut body = json!({
        "grant_id": grant_id,
        "tag": tag,
    });
    if !constraints.is_null() {
        body["constraints"] = constraints;
    }
    OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::CapabilityGrant,
    )
    .target_ref(grant_id)
    .body(body)
}

/// `ck.capability.revoke` event. `reason` shows up in the audit
/// trail and lets the UI explain why the capability was dropped.
pub fn capability_revoke(
    realm_id: &str,
    actor: &str,
    grant_id: &str,
    tag: &str,
    reason: Option<&str>,
) -> OperationBuilder {
    let mut body = json!({
        "grant_id": grant_id,
        "tag": tag,
    });
    if let Some(reason) = reason {
        body["reason"] = json!(reason);
    }
    OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::CapabilityRevoke,
    )
    .target_ref(grant_id)
    .body(body)
}

/// `ck.capability.grant` event carrying the canonical
/// `capability_grant_payload` wrapper (`{grant_id, grant:{…}}`) the P1
/// soland reducer (`apply_capability`) reads `issuer` / `subject` /
/// `actions` / `resources` from. Use this — not [`capability_grant`] —
/// for any directed grant (e.g. setting a Realm admin via
/// `actions=[ck.realm.admin]`), because the reducer fails closed on a
/// grant body with no `issuer` or no `actions`.
///
/// `subject` is the delegee DID the grant authorizes; `actor` is the
/// issuer (and the Envelope signer). `resources` defaults to a single
/// `{kind:"realm", realm_id}` selector — the management surface this
/// covers. The Envelope `seal_basis` / signature carries the issuer
/// proof; the per-grant `proofs[]` the strict SDK builder mints is not
/// re-derived here (consistent with the rest of the yougen `ck_ops`
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
        "schema": "ck.schema.capability_grant.v1",
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
        cokret_sdk::events::kinds::EventKind::CapabilityGrant,
    )
    .target_ref(grant_id)
    .body(json!({
        "grant_id": grant_id,
        "grant": grant,
    }))
}
