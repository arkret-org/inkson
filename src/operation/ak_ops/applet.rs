//! Applet protocol-family builders.
//!
//! Spec: `extensions/applet-integration.md` + canonical event-kind
//! registry rows `ak.applet.registration` / `ak.applet.discovery` /
//! `ak.applet.bridge_error`.
//!
//! The builders below produce the wire shape soland validators and the
//! SDK reducer consume. Each carries the canonical `applet_id` (or
//! `service_id` for registration / discovery) as `target_ref` so
//! soland's `target-ref-required` envelope-shape check passes.

use super::OperationBuilder;

/// `ak.applet.discovery` — the network discovery surface that lists
/// what an applet exposes; emitted by directory crawlers and by the
/// applet itself on registration round-trip.
pub fn applet_discovery(
    realm_id: &str,
    actor: &str,
    service_id: &str,
    manifest: serde_json::Value,
) -> OperationBuilder {
    OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::AppletDiscovery,
    )
    .target_ref(service_id)
    .body(json!({
        "service_id": service_id,
        "manifest": manifest,
    }))
}

/// Validate an `applet_id` against the canonical
/// [`arkret_sdk::AppletIdentifier`] shape (DID *or*
/// `ak:applet:<uuidv7>`). Returns the typed identifier so callers
/// can stash it without re-parsing. Wire-breaking: plain strings
/// outside these two forms are rejected.
pub fn parse_applet_identifier(applet_id: &str) -> Result<arkret_sdk::AppletIdentifier, String> {
    if applet_id.starts_with("did:") {
        arkret_sdk::Did::new(applet_id)
            .map(arkret_sdk::AppletIdentifier::Did)
            .map_err(|e| format!("invalid applet DID: {e}"))
    } else if applet_id.starts_with("ak:applet:") {
        arkret_sdk::AppletId::new(applet_id)
            .map(arkret_sdk::AppletIdentifier::Cx)
            .map_err(|e| format!("invalid ak:applet:<uuidv7>: {e}"))
    } else {
        Err(format!(
            "applet_id {applet_id:?} is neither a DID nor ak:applet:<uuidv7>"
        ))
    }
}

/// `ak.applet.bridge_error` — emitted by the applet bridge when a
/// transaction fails outside the spec's typed result.
pub fn applet_bridge_error(
    realm_id: &str,
    actor: &str,
    applet_id: &str,
    failed_transaction_ref: &str,
    error_class: &str,
    error_code: &str,
    retriable: bool,
    visibility_scope: &str,
    message: &str,
) -> anyhow::Result<OperationBuilder> {
    let visibility_scope = match visibility_scope.trim() {
        "realm_admins" => arkret_sdk::AppletBridgeVisibilityScope::RealmAdmins,
        "applet_controller" => arkret_sdk::AppletBridgeVisibilityScope::AppletController,
        "realm_members" => arkret_sdk::AppletBridgeVisibilityScope::RealmMembers,
        other => anyhow::bail!("invalid applet bridge visibility_scope {other:?}"),
    };
    let payload = arkret_sdk::AppletBridgeErrorPayload {
        applet_id: parse_applet_identifier(applet_id).map_err(anyhow::Error::msg)?,
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid realm id {realm_id:?}: {err}"))?,
        failed_transaction_ref: arkret_sdk::ObjectRef::new(failed_transaction_ref.to_owned())?,
        error_class: error_class.to_owned(),
        error_code: arkret_sdk::NonEmptyString::new(error_code)?,
        retriable,
        visibility_scope,
        external_ref: None,
        message: Some(message.to_owned()),
        retry_after_ms: None,
    };
    let body = serde_json::to_value(payload)
        .map_err(|err| anyhow::anyhow!("applet_bridge_error_payload serialize: {err}"))?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::AppletBridgeError,
    )
    .target_ref(failed_transaction_ref)
    .body(body))
}
