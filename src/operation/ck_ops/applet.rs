//! Applet protocol-family builders.
//!
//! Spec: `extensions/applet-integration.md` + canonical event-kind
//! registry rows `ck.applet.registration` / `ck.applet.discovery` /
//! `ck.applet.interop_session.{start,status}` / `ck.applet.bridge_error`.
//!
//! The builders below produce the wire shape soland validators and the
//! SDK reducer consume. Each carries the canonical `applet_id` (or
//! `service_did` for registration / discovery) as `target_ref` so
//! soland's `target-ref-required` envelope-shape check passes.

use serde_json::json;

use super::OperationBuilder;

/// `ck.applet.registration` — declare an applet service_did + the
/// event-kind subset / namespaces / capabilities it can write.
pub fn applet_registration(
    realm_id: &str,
    actor: &str,
    service_did: &str,
    namespace: &str,
    capabilities: &[&str],
) -> OperationBuilder {
    OperationBuilder::new(realm_id, actor, "ck.applet.registration")
        .target_ref(service_did)
        .body(json!({
            "service_did": service_did,
            "namespace": namespace,
            "capabilities": capabilities,
        }))
}

/// `ck.applet.discovery` — the network discovery surface that lists
/// what an applet exposes; emitted by directory crawlers and by the
/// applet itself on registration round-trip.
pub fn applet_discovery(
    realm_id: &str,
    actor: &str,
    service_did: &str,
    manifest: serde_json::Value,
) -> OperationBuilder {
    OperationBuilder::new(realm_id, actor, "ck.applet.discovery")
        .target_ref(service_did)
        .body(json!({
            "service_did": service_did,
            "manifest": manifest,
        }))
}

/// Round 4 (spec a77b995) — validate an `applet_id` against the
/// canonical [`cokret_sdk::AppletIdentifier`] shape (DID *or*
/// `ck:applet:<uuidv7>`). Returns the typed identifier so callers
/// can stash it without re-parsing. Wire-breaking: plain strings
/// outside these two forms are rejected.
pub fn parse_applet_identifier(applet_id: &str) -> Result<cokret_sdk::AppletIdentifier, String> {
    if applet_id.starts_with("did:") {
        cokret_sdk::Did::new(applet_id)
            .map(cokret_sdk::AppletIdentifier::Did)
            .map_err(|e| format!("invalid applet DID: {e}"))
    } else if applet_id.starts_with("ck:applet:") {
        cokret_sdk::AppletId::new(applet_id)
            .map(cokret_sdk::AppletIdentifier::Cx)
            .map_err(|e| format!("invalid ck:applet:<uuidv7>: {e}"))
    } else {
        Err(format!(
            "applet_id {applet_id:?} is neither a DID nor ck:applet:<uuidv7> \
             (round 4 schema_violation)"
        ))
    }
}

/// `ck.applet.interop_session.start` — open a per-session channel
/// between a Realm member and an applet (used for portal-style RPC
/// + agent invocation).
pub fn applet_interop_session_start(
    realm_id: &str,
    actor: &str,
    applet_id: &str,
    session_id: &str,
    params: serde_json::Value,
) -> OperationBuilder {
    OperationBuilder::new(realm_id, actor, "ck.applet.interop_session.start")
        .target_ref(session_id)
        .body(json!({
            "applet_id": applet_id,
            "session_id": session_id,
            "params": params,
        }))
}

/// `ck.applet.interop_session.status` — applet → caller status push
/// (progress, intermediate result, completion).
pub fn applet_interop_session_status(
    realm_id: &str,
    actor: &str,
    session_id: &str,
    status: &str,
    detail: serde_json::Value,
) -> OperationBuilder {
    OperationBuilder::new(realm_id, actor, "ck.applet.interop_session.status")
        .target_ref(session_id)
        .body(json!({
            "session_id": session_id,
            "status": status,
            "detail": detail,
        }))
}

/// `ck.applet.bridge_error` — emitted by the applet bridge when a
/// interop_session call fails outside the spec's typed result.
pub fn applet_bridge_error(
    realm_id: &str,
    actor: &str,
    session_id: &str,
    error_code: &str,
    message: &str,
) -> OperationBuilder {
    OperationBuilder::new(realm_id, actor, "ck.applet.bridge_error")
        .target_ref(session_id)
        .body(json!({
            "session_id": session_id,
            "error_code": error_code,
            "message": message,
        }))
}
