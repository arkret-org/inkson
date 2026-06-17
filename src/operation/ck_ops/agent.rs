//! Agent protocol-family builders.
//!
//! Spec: `extensions/agent-integration.md` + canonical event-kind
//! registry rows `ck.agent.endpoint` / `ck.agent.interop_session.
//! {start,status,result}`. Agents are server-side delegates a member
//! grants narrow capabilities to (e.g. a read-strand Researcher Agent);
//! the wire shape lets soland and the SDK reducer track which agent
//! owns which session, what status, and what result.

use serde_json::json;

use super::OperationBuilder;

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
    OperationBuilder::new(realm_id, actor, "ck.agent.endpoint")
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
    OperationBuilder::new(realm_id, actor, "ck.agent.interop_session.start")
        .target_ref(session_id)
        .body(json!({
            "counterparty_agent": counterparty_agent,
            "session_id": session_id,
            "protocol": protocol,
            "params": params,
            "capability_grant": capability_grant,
        }))
}

/// `ck.agent.interop_session.status` — agent progress signal.
pub fn agent_interop_session_status(
    realm_id: &str,
    actor: &str,
    session_id: &str,
    status: &str,
    detail: serde_json::Value,
) -> OperationBuilder {
    OperationBuilder::new(realm_id, actor, "ck.agent.interop_session.status")
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
    OperationBuilder::new(realm_id, actor, "ck.agent.interop_session.result")
        .target_ref(session_id)
        .body(json!({
            "session_id": session_id,
            "result": result,
            "audit_binding": audit_binding,
        }))
}
