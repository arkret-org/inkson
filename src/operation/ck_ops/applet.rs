//! Applet protocol-family builders.
//!
//! Spec: `extensions/applet-integration.md` + canonical event-kind
//! registry rows `ak.applet.registration` / `ak.applet.discovery` /
//! `ak.applet.interop_session.{start,status}` / `ak.applet.bridge_error`.
//!
//! The builders below produce the wire shape soland validators and the
//! SDK reducer consume. Each carries the canonical `applet_id` (or
//! `service_did` for registration / discovery) as `target_ref` so
//! soland's `target-ref-required` envelope-shape check passes.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::OperationBuilder;

fn optional_object(value: Value, context: &str) -> anyhow::Result<Option<BTreeMap<String, Value>>> {
    match value {
        Value::Null => Ok(None),
        Value::Object(map) => Ok(Some(map.into_iter().collect())),
        _ => anyhow::bail!("{context} must be a JSON object"),
    }
}

/// Map a wire `runtime_status` token onto the closed SDK enum. Fail-closed:
/// unknown tokens are rejected rather than forwarded as free-form strings.
fn parse_runtime_status(runtime_status: &str) -> anyhow::Result<arkret_sdk::AppletRuntimeStatus> {
    serde_json::from_value(Value::String(runtime_status.to_owned())).map_err(|_| {
        anyhow::anyhow!(
            "unknown applet runtime status {runtime_status:?} \
             (spec enum: pending|running|completed|failed|cancelled)"
        )
    })
}

/// `ak.applet.registration` — declare an applet service_did + the
/// event-kind subset / namespaces / capabilities it can write.
pub fn applet_registration(
    realm_id: &str,
    actor: &str,
    service_did: &str,
    namespace: &str,
    capabilities: &[&str],
) -> OperationBuilder {
    OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::AppletRegistration,
    )
    .target_ref(service_did)
    .body(json!({
        "service_did": service_did,
        "namespace": namespace,
        "capabilities": capabilities,
    }))
}

/// `ak.applet.discovery` — the network discovery surface that lists
/// what an applet exposes; emitted by directory crawlers and by the
/// applet itself on registration round-trip.
pub fn applet_discovery(
    realm_id: &str,
    actor: &str,
    service_did: &str,
    manifest: serde_json::Value,
) -> OperationBuilder {
    OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::AppletDiscovery,
    )
    .target_ref(service_did)
    .body(json!({
        "service_did": service_did,
        "manifest": manifest,
    }))
}

/// Round 4 (spec a77b995) — validate an `applet_id` against the
/// canonical [`arkret_sdk::AppletIdentifier`] shape (DID *or*
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
            "applet_id {applet_id:?} is neither a DID nor ak:applet:<uuidv7> \
             (round 4 schema_violation)"
        ))
    }
}

/// `ak.applet.interop_session.start` — open a per-session channel
/// between a Realm member and an applet (used for portal-style RPC
/// + agent invocation).
pub fn applet_interop_session_start(
    realm_id: &str,
    actor: &str,
    applet_id: &str,
    session_id: &str,
    params: serde_json::Value,
) -> anyhow::Result<OperationBuilder> {
    let applet_id = parse_applet_identifier(applet_id).map_err(|err| anyhow::anyhow!("{err}"))?;
    let mut payload =
        arkret_sdk::AppletInteropSessionStartPayload::new(applet_id, session_id.to_owned());
    if let Some(params) = optional_object(params, "applet session params")? {
        payload = payload.with_params(params);
    }
    let body = payload
        .to_value()
        .map_err(|err| anyhow::anyhow!("applet_interop_session_start_payload serialize: {err}"))?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::AppletInteropSessionStart,
    )
    .target_ref(session_id)
    .body(body))
}

/// `ak.applet.interop_session.status` — applet → caller status push
/// (progress, intermediate result, completion).
pub fn applet_interop_session_status(
    realm_id: &str,
    actor: &str,
    applet_id: &str,
    session_id: &str,
    runtime_status: &str,
    detail: serde_json::Value,
) -> anyhow::Result<OperationBuilder> {
    let applet_id = parse_applet_identifier(applet_id).map_err(|err| anyhow::anyhow!("{err}"))?;
    let mut payload = arkret_sdk::AppletInteropSessionStatusPayload::new(
        applet_id,
        session_id.to_owned(),
        parse_runtime_status(runtime_status)?,
    );
    if let Some(detail) = optional_object(detail, "applet session status detail")? {
        payload = payload.with_detail(detail);
    }
    let body = payload
        .to_value()
        .map_err(|err| anyhow::anyhow!("applet_interop_session_status_payload serialize: {err}"))?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::AppletInteropSessionStatus,
    )
    .target_ref(session_id)
    .body(body))
}

/// `ak.applet.bridge_error` — emitted by the applet bridge when a
/// interop_session call fails outside the spec's typed result.
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
    let payload = arkret_sdk::AppletBridgeErrorPayload {
        applet_id: json!(applet_id),
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid realm id {realm_id:?}: {err}"))?,
        failed_transaction_ref: json!(failed_transaction_ref),
        error_class: error_class.to_owned(),
        error_code: json!(error_code),
        retriable,
        visibility_scope: json!(visibility_scope),
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
