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

use arkret_models_integration::{
    AppletBridgeErrorClass, AppletBridgeErrorPayload, AppletBridgeVisibilityScope,
};
use arkret_wire::{AppletId, AppletIdentifier, Did, NonEmptyString, RealmId};
use serde_json::json;

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
        arkret_sdk::EventKind::AppletDiscovery,
    )
    .target_ref(service_id)
    // `resource_discovery_state_payload` is closed over
    // `{resource_id, value, state, reason}`: `resource_id` is the stable cell
    // subject the registered contract derives the
    // `ak.component.applet.discovery.v1` cell from, and the manifest is
    // schema-versioned discovery state inside `value`.
    .body(json!({
        "resource_id": service_id,
        "value": {
            "service_id": service_id,
            "manifest": manifest,
        },
    }))
}

/// Validate an `applet_id` against the canonical
/// [`AppletIdentifier`] shape (DID *or*
/// `ak:applet:<uuidv7>`). Returns the typed identifier so callers
/// can stash it without re-parsing. Wire-breaking: plain strings
/// outside these two forms are rejected.
pub fn parse_applet_identifier(applet_id: &str) -> Result<AppletIdentifier, String> {
    if applet_id.starts_with("did:") {
        Did::new(applet_id)
            .map(AppletIdentifier::Did)
            .map_err(|e| format!("invalid applet DID: {e}"))
    } else if applet_id.starts_with("ak:applet:") {
        AppletId::new(applet_id)
            .map(AppletIdentifier::Cx)
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
        "realm_admins" => AppletBridgeVisibilityScope::RealmAdmins,
        "applet_controller" => AppletBridgeVisibilityScope::AppletController,
        "realm_members" => AppletBridgeVisibilityScope::RealmMembers,
        other => anyhow::bail!("invalid applet bridge visibility_scope {other:?}"),
    };
    let error_class = match error_class.trim() {
        "external_network" => AppletBridgeErrorClass::ExternalNetwork,
        "auth" => AppletBridgeErrorClass::Auth,
        "schema" => AppletBridgeErrorClass::Schema,
        "rate_limit" => AppletBridgeErrorClass::RateLimit,
        "policy" => AppletBridgeErrorClass::Policy,
        other => anyhow::bail!("invalid applet bridge error_class {other:?}"),
    };
    let payload = AppletBridgeErrorPayload {
        applet_id: parse_applet_identifier(applet_id).map_err(anyhow::Error::msg)?,
        realm_id: RealmId::new(realm_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid realm id {realm_id:?}: {err}"))?,
        failed_transaction_ref: failed_transaction_ref.to_owned(),
        error_class,
        error_code: NonEmptyString::new(error_code).map_err(anyhow::Error::msg)?,
        retriable,
        visibility_scope,
        external_ref: None,
        message: Some(message.to_owned()),
        retry_after_ms: None,
    };
    let body = serde_json::to_value(payload)
        .map_err(|err| anyhow::anyhow!("applet_bridge_error_payload serialize: {err}"))?;
    Ok(
        OperationBuilder::new(realm_id, actor, arkret_sdk::EventKind::AppletBridgeError)
            .target_ref(failed_transaction_ref)
            .body(body),
    )
}
