//! Agent protocol-family builders.
//!
//! Spec: `extensions/agent-integration.md` + canonical event-kind
//! registry rows `ck.agent.endpoint` / `ck.agent.interop_session.
//! {start,status,result}`. Agents are server-side delegates a member
//! grants narrow capabilities to (e.g. a read-strand Researcher Agent);
//! the wire shape lets soland and the SDK reducer track which agent
//! owns which session, what status, and what result.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::{OperationBuilder, trim_realm_id};

fn value_object(value: Value, context: &str) -> anyhow::Result<BTreeMap<String, Value>> {
    match value {
        Value::Object(map) => Ok(map.into_iter().collect()),
        _ => anyhow::bail!("{context} must be a JSON object"),
    }
}

fn value_object_list(
    value: Value,
    context: &str,
) -> anyhow::Result<Option<Vec<BTreeMap<String, Value>>>> {
    match value {
        Value::Null => Ok(None),
        Value::Array(values) => values
            .into_iter()
            .map(|value| value_object(value, context))
            .collect::<anyhow::Result<Vec<_>>>()
            .map(|values| (!values.is_empty()).then_some(values)),
        value => Ok(Some(vec![value_object(value, context)?])),
    }
}

/// Round 4 — validate an `agent_id` against the canonical
/// [`arkret_sdk::AgentId`] shape (strict DID). Wire-breaking: the
/// pre-round-4 permissive plain-string form is rejected.
pub fn parse_agent_identifier(agent_id: &str) -> Result<arkret_sdk::AgentId, String> {
    arkret_sdk::Did::new(agent_id).map_err(|e| format!("invalid agent DID: {e}"))
}

/// Map a wire `protocol` token onto the closed SDK enum. Fail-closed: an
/// unknown token (which the spec schema would also reject) surfaces here
/// instead of shipping an out-of-enum string to soland.
fn parse_interop_protocol(protocol: &str) -> anyhow::Result<arkret_sdk::AgentInteropProtocol> {
    serde_json::from_value(Value::String(protocol.to_owned())).map_err(|_| {
        anyhow::anyhow!(
            "unknown agent interop protocol {protocol:?} (spec enum: a2a|acp|mcp_bridge|http_custom)"
        )
    })
}

/// Map a wire session `status` token onto the closed SDK enum. Fail-closed:
/// unknown tokens are rejected rather than forwarded as free-form strings.
fn parse_session_status(status: &str) -> anyhow::Result<arkret_sdk::AgentInteropSessionStatus> {
    serde_json::from_value(Value::String(status.to_owned()))
        .map_err(|_| anyhow::anyhow!("unknown agent interop session status {status:?}"))
}

/// `ck.agent.endpoint` — register an agent id + invocation endpoints.
pub fn agent_endpoint(
    realm_id: &str,
    actor: &str,
    agent_id: &str,
    protocol: &str,
    capabilities: &[&str],
) -> anyhow::Result<OperationBuilder> {
    let mut endpoint = BTreeMap::new();
    endpoint.insert("protocol".to_owned(), json!(protocol));
    endpoint.insert("capabilities".to_owned(), json!(capabilities));
    let payload = arkret_sdk::AgentEndpointPayload {
        agent_id: parse_agent_identifier(agent_id).map_err(|err| anyhow::anyhow!("{err}"))?,
        endpoints: vec![endpoint],
    };
    let body = serde_json::to_value(payload)
        .map_err(|err| anyhow::anyhow!("agent_endpoint_payload serialize: {err}"))?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::AgentEndpoint,
    )
    .target_ref(agent_id)
    .body(body))
}

/// `ck.agent.interop_session.start` — kick off an agent
/// invocation;  body carries the parameter payload + the
/// capability proof bundle.
pub fn agent_interop_session_start(
    realm_id: &str,
    actor: &str,
    counterparty_agent: &str,
    session_id: &str,
    protocol: &str,
    _params: serde_json::Value,
    capability_grant: &str,
) -> anyhow::Result<OperationBuilder> {
    let counterparty_agent = arkret_sdk::Did::new(counterparty_agent.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid counterparty agent DID: {err}"))?;
    let capability_grant = arkret_sdk::GrantId::new(capability_grant.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid capability grant id: {err}"))?;
    let body = arkret_sdk::AgentInteropSessionStartPayload::new(
        session_id.to_owned(),
        counterparty_agent,
        parse_interop_protocol(protocol)?,
        capability_grant,
    )
    .to_value()
    .map_err(|err| anyhow::anyhow!("agent_interop_session_start_payload serialize: {err}"))?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::AgentInteropSessionStart,
    )
    .target_ref(session_id)
    .body(body))
}

/// Build the capability-constraint object an external-handoff grant
/// carries (agent-protocol-interop.md §7). `allowed_endpoints` is a
/// single-valued list pinned to the exact runtime base URL — the spec
/// §6 step 4 host-pinning convergence (the wildcard `https://*.trusted.example`
/// form is collapsed to a precise value for an authored grant). The
/// `requires_human_approval` flag mirrors the explicit human-approval
/// gate the publish modal enforces before the grant is signed.
pub fn interop_capability_constraint(
    allowed_endpoint: &str,
    allowed_protocols: &[&str],
    requires_human_approval: bool,
    max_duration_seconds: u64,
    max_artifact_bytes: u64,
    egress_policy: &str,
    audit_mode: &str,
) -> serde_json::Value {
    json!({
        "allowed_protocols": allowed_protocols,
        "allowed_endpoints": [allowed_endpoint],
        "max_duration_seconds": max_duration_seconds,
        "max_artifact_bytes": max_artifact_bytes,
        "requires_human_approval": requires_human_approval,
        "egress_policy": egress_policy,
        "audit_mode": audit_mode,
    })
}

/// `ck.agent.interop_session.status` — agent progress signal.
pub fn agent_interop_session_status(
    realm_id: &str,
    actor: &str,
    session_id: &str,
    status: &str,
    _detail: serde_json::Value,
) -> anyhow::Result<OperationBuilder> {
    let body = arkret_sdk::AgentInteropSessionStatusPayload::new(
        session_id.to_owned(),
        parse_session_status(status)?,
    )
    .to_value()
    .map_err(|err| anyhow::anyhow!("agent_interop_session_status_payload serialize: {err}"))?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::AgentInteropSessionStatus,
    )
    .target_ref(session_id)
    .body(body))
}

/// `ck.agent.interop_session.result` — terminal event carrying the
/// agent's result objects and any artifact objects emitted by the session.
pub fn agent_interop_session_result(
    realm_id: &str,
    actor: &str,
    session_id: &str,
    result: serde_json::Value,
    audit_binding: serde_json::Value,
) -> anyhow::Result<OperationBuilder> {
    // `completed` terminal status; the builder's `to_value` enforces the spec
    // anyOf (at least one of result_objects / artifacts / reason_code). Only
    // attach the optional collections when they carry entries so the omission
    // rule matches the previous `skip_serializing_if` behavior.
    let mut payload = arkret_sdk::AgentInteropSessionResultPayload::new(
        session_id.to_owned(),
        arkret_sdk::AgentInteropResultStatus::Completed,
    );
    if let Some(result_objects) = value_object_list(result, "agent result_objects")? {
        payload = payload.with_result_objects(result_objects);
    }
    if let Some(artifacts) = value_object_list(audit_binding, "agent artifacts")? {
        payload = payload.with_artifacts(artifacts);
    }
    let body = payload
        .to_value()
        .map_err(|err| anyhow::anyhow!("agent_interop_session_result_payload serialize: {err}"))?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::AgentInteropSessionResult,
    )
    .target_ref(session_id)
    .body(body))
}

/// Build the publish-to-source `ck.strand.create` operation for an
/// agent handoff result (agent-protocol-interop.md §5.4 / §6 step 8-9).
///
/// The new Strand is authored by the controller (`actor` =
/// `actor_id`) but preserves the executing agent's `attribution`
/// (`remote_agent` DID) at the object root, plus a `synthesis` track
/// and a `workflow_type=synthesis` metadata field so the source space
/// reflects who actually produced the artifact. `result_object_ref` /
/// `artifact_object_ref` are recorded as metadata so the published
/// Strand carries back-references to the agent result + Morph artifact.
pub fn agent_publish_attribution_strand(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    title: &str,
    attribution_agent: &str,
    result_object_ref: &str,
    artifact_object_ref: &str,
) -> anyhow::Result<OperationBuilder> {
    let typed_realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|e| anyhow::anyhow!("invalid realm_id: {e:?}"))?;
    let did = arkret_sdk::Did::new(actor.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid actor DID: {e:?}"))?;
    let typed_strand_id = arkret_sdk::StrandId::new(strand_id.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid strand_id: {e:?}"))?;
    let strand = arkret_sdk::StrandCreateObject::new(typed_strand_id, typed_realm_id, did)
        .with_metadata_title(title)
        .with_metadata_field("workflow_type", json!("synthesis"))
        .with_metadata_field("result_object_ref", json!(result_object_ref))
        .with_metadata_field("artifact_object_ref", json!(artifact_object_ref))
        .with_track("synthesis", arkret_sdk::StrandTrackConfig::synthesis())
        .with_extra("attribution", json!(attribution_agent));
    let payload = arkret_sdk::ObjectCreatePayload::new(strand)
        .to_value()
        .map_err(|e| anyhow::anyhow!("ak.strand.create attribution payload serialize: {e}"))?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::StrandCreate,
    )
    .target_ref(strand_id)
    .body(payload))
}
