//! Agent protocol-family builders.
//!
//! Spec: `extensions/agent-integration.md` + canonical event-kind
//! registry rows `ck.agent.endpoint` / `ck.agent.interop_session.
//! {start,status,result}`. Agents are server-side delegates a member
//! grants narrow capabilities to (e.g. a read-strand Researcher Agent);
//! the wire shape lets soland and the SDK reducer track which agent
//! owns which session, what status, and what result.

use serde_json::json;

use super::{OperationBuilder, trim_realm_id};

/// Round 4 — validate an `agent_id` against the canonical
/// [`cokret_sdk::AgentId`] shape (strict DID). Wire-breaking: the
/// pre-round-4 permissive plain-string form is rejected.
pub fn parse_agent_identifier(agent_id: &str) -> Result<cokret_sdk::AgentId, String> {
    cokret_sdk::Did::new(agent_id).map_err(|e| format!("invalid agent DID: {e}"))
}

/// `ck.agent.endpoint` — register an agent id + invocation endpoints.
pub fn agent_endpoint(
    realm_id: &str,
    actor: &str,
    agent_id: &str,
    protocol: &str,
    capabilities: &[&str],
) -> OperationBuilder {
    let endpoints = json!([{
        "protocol": protocol,
        "capabilities": capabilities,
    }]);
    OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::AgentEndpoint,
    )
    .target_ref(agent_id)
    .body(json!({
        "agent_id": agent_id,
        "endpoints": endpoints,
    }))
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
    params: serde_json::Value,
    capability_grant: &str,
) -> OperationBuilder {
    OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::AgentInteropSessionStart,
    )
    .target_ref(session_id)
    .body(json!({
        "counterparty_agent": counterparty_agent,
        "session_id": session_id,
        "protocol": protocol,
        "params": params,
        "capability_grant": capability_grant,
    }))
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
    detail: serde_json::Value,
) -> OperationBuilder {
    OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::AgentInteropSessionStatus,
    )
    .target_ref(session_id)
    .body(json!({
        "session_id": session_id,
        "status": status,
        "detail": detail,
    }))
}

/// `ck.agent.interop_session.result` — terminal event carrying the
/// agent's signed result + the audit-binding proof.
pub fn agent_interop_session_result(
    realm_id: &str,
    actor: &str,
    session_id: &str,
    result: serde_json::Value,
    audit_binding: serde_json::Value,
) -> OperationBuilder {
    OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::AgentInteropSessionResult,
    )
    .target_ref(session_id)
    .body(json!({
        "session_id": session_id,
        "result": result,
        "audit_binding": audit_binding,
    }))
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
    let typed_realm_id = cokret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|e| anyhow::anyhow!("invalid realm_id: {e:?}"))?;
    let did = cokret_sdk::Did::new(actor.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid actor DID: {e:?}"))?;
    let typed_strand_id = cokret_sdk::StrandId::new(strand_id.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid strand_id: {e:?}"))?;
    let strand = cokret_sdk::StrandCreateObject::new(typed_strand_id, typed_realm_id, did)
        .with_metadata_title(title)
        .with_metadata_field("workflow_type", json!("synthesis"))
        .with_metadata_field("result_object_ref", json!(result_object_ref))
        .with_metadata_field("artifact_object_ref", json!(artifact_object_ref))
        .with_track("synthesis", cokret_sdk::StrandTrackConfig::synthesis())
        .with_extra("attribution", json!(attribution_agent));
    let payload = cokret_sdk::ObjectCreatePayload::new(strand)
        .to_value()
        .map_err(|e| anyhow::anyhow!("ck.strand.create attribution payload serialize: {e}"))?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::StrandCreate,
    )
    .target_ref(strand_id)
    .body(payload))
}
