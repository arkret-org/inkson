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
use arkret_wire::{AppletId, AppletIdentifier, NonEmptyString, RealmId};

use super::TypedOperationBuilder;

/// `ak.applet.discovery` — the network discovery surface that lists
/// what an applet exposes; emitted by directory crawlers and by the
/// applet itself on registration round-trip.
pub fn applet_discovery(
    realm_id: &str,
    actor: &str,
    service_id: &str,
    manifest: serde_json::Value,
) -> anyhow::Result<TypedOperationBuilder> {
    let payload = arkret_sdk::ResourceDiscoveryStatePayload {
        resource_id: NonEmptyString::new(service_id).map_err(anyhow::Error::msg)?,
        value: Some(serde_json::json!({
            "service_id": service_id,
            "manifest": manifest,
        })),
        state: None,
        reason: None,
    };
    // `resource_discovery_state_payload` is closed over
    // `{resource_id, value, state, reason}`: `resource_id` is the stable cell
    // subject the registered contract derives the
    // `ak.component.applet.discovery.v1` cell from, and the manifest is
    // schema-versioned discovery state inside `value`.
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::AppletDiscovery>(
            realm_id, actor, payload,
        )
        .target_ref(service_id),
    )
}

/// Validate an `applet_id` against the canonical
/// [`AppletIdentifier`] shape (DID *or*
/// `ak:applet:<uuidv7>`). Returns the typed identifier so callers
/// can stash it without re-parsing. Wire-breaking: plain strings
/// outside these two forms are rejected.
pub fn parse_applet_identifier(applet_id: &str) -> Result<AppletIdentifier, String> {
    if applet_id.starts_with("did:") || applet_id.starts_with("ak:did_core:") {
        return crate::mls_api_helpers::principal_core_id(applet_id)
            .map(AppletIdentifier::Service)
            .map_err(|e| format!("invalid applet service identity: {e}"));
    }
    // The `AppletId` newtype — not an `ak:applet:` prefix test — decides
    // whether the value is a canonical applet id: the prefix admits any tail,
    // while the type enforces the registered `ak:applet:<uuidv7>` shape.
    AppletId::new(applet_id)
        .map(AppletIdentifier::Cx)
        .map_err(|e| {
            format!("applet_id {applet_id:?} is neither a DID nor ak:applet:<uuidv7>: {e}")
        })
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
) -> anyhow::Result<TypedOperationBuilder> {
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
    Ok(
        TypedOperationBuilder::new::<arkret_sdk::event_spec::AppletBridgeError>(
            realm_id, actor, payload,
        )
        .target_ref(failed_transaction_ref),
    )
}
