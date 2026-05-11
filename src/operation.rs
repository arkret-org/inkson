//! Minimal operation-envelope helpers for yougen's active write paths.
//!
//! Repo-commit and event-envelope helper paths were removed; active writes use
//! the current operation/event surfaces directly.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::hlc::{Hlc, next_seq};

/// An operation envelope per contrix-spec section 6.3.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationEnvelope {
    /// Unique operation identifier (UUID v8 recommended).
    pub operation_id: String,
    /// The space this operation targets.
    pub space_id: String,
    /// The actor (DID) performing this operation.
    pub actor: String,
    /// Operation type in cx.<domain>.<verb> format.
    #[serde(rename = "type")]
    pub op_type: String,
    /// Optional target entity/relation reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
    /// Causal metadata.
    pub causal: CausalMetadata,
    /// Operation body (domain-specific payload).
    pub body: Value,
    /// Optional authorization reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authz_ref: Option<String>,
    /// Signature over the operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Causal metadata for ordering and dependency tracking.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CausalMetadata {
    /// IDs of operations this operation depends on.
    #[serde(default)]
    pub deps: Vec<String>,
    /// Hybrid Logical Clock timestamp.
    pub hlc: String,
    /// Per-actor monotonic sequence number.
    pub actor_seq: u64,
}

/// Builder for creating operation envelopes.
pub struct OperationBuilder {
    space_id: String,
    actor: String,
    op_type: String,
    target_ref: Option<String>,
    body: Value,
    authz_ref: Option<String>,
}

impl OperationBuilder {
    pub fn new(
        space_id: impl Into<String>,
        actor: impl Into<String>,
        op_type: impl Into<String>,
    ) -> Self {
        Self {
            space_id: space_id.into(),
            actor: actor.into(),
            op_type: op_type.into(),
            target_ref: None,
            body: Value::Null,
            authz_ref: None,
        }
    }

    pub fn target_ref(mut self, target_ref: impl Into<String>) -> Self {
        self.target_ref = Some(target_ref.into());
        self
    }

    pub fn body(mut self, body: Value) -> Self {
        self.body = body;
        self
    }

    pub fn authz_ref(mut self, authz_ref: impl Into<String>) -> Self {
        self.authz_ref = Some(authz_ref.into());
        self
    }

    pub fn build(self, node_id: &str) -> OperationEnvelope {
        self.build_with_deps(node_id, Vec::new())
    }

    pub fn build_with_deps(self, node_id: &str, deps: Vec<String>) -> OperationEnvelope {
        let hlc = Hlc::now(node_id);
        OperationEnvelope {
            operation_id: uuid_v8(),
            space_id: self.space_id,
            actor: self.actor,
            op_type: self.op_type,
            target_ref: self.target_ref,
            causal: CausalMetadata {
                deps,
                hlc: hlc.encode(),
                actor_seq: next_seq(),
            },
            body: self.body,
            authz_ref: self.authz_ref,
            signature: None,
        }
    }
}

/// Generate a UUID v8-style identifier (timestamp + random).
pub fn uuid_v8() -> String {
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let ts_hi = (now >> 16) as u32;
    let ts_lo = (now & 0xFFFF) as u16;
    let rand_a: u16 = 0x8000 | (rand_u16() & 0x0FFF);
    let rand_b = rand_u64();
    format!("{:08x}-{:04x}-{:04x}-{:016x}", ts_hi, ts_lo, rand_a, rand_b)
}

/// Generate a canonical UUIDv7 string for typed protocol identifiers.
pub fn uuid_v7() -> String {
    let now_ms = chrono::Utc::now().timestamp_millis() as u64 & 0x0000_ffff_ffff_ffff;
    let time_low = (now_ms >> 16) as u32;
    let time_mid = (now_ms & 0xffff) as u16;
    let time_hi_and_version = 0x7000 | (rand_u16() & 0x0fff);
    let variant_and_rand = 0x8000_0000_0000_0000u64 | (rand_u64() & 0x3fff_ffff_ffff_ffff);
    let clock_seq = (variant_and_rand >> 48) as u16;
    let node = variant_and_rand & 0x0000_ffff_ffff_ffff;
    format!("{time_low:08x}-{time_mid:04x}-{time_hi_and_version:04x}-{clock_seq:04x}-{node:012x}")
}

fn rand_u16() -> u16 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let s = RandomState::new();
    let mut hasher = s.build_hasher();
    hasher.write_u64(chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64);
    (hasher.finish() & 0xFFFF) as u16
}

fn rand_u64() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let s = RandomState::new();
    let mut hasher = s.build_hasher();
    hasher.write_u64(chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64);
    hasher.finish()
}

/// Canonical helper constructors used by the current UI.
pub mod cx_ops {
    use super::OperationBuilder;
    use serde_json::json;

    /// Build a canonical `cx.flow.create` discussion operation with the full
    /// typed Flow payload expected by the current reducers.
    pub fn discussion_flow_create(
        space_id: &str,
        actor: &str,
        flow_id: &str,
        title: &str,
    ) -> anyhow::Result<OperationBuilder> {
        use contrix_sdk::{Did, Flow, SpaceId};

        let space = SpaceId::new(space_id.to_owned())
            .map_err(|e| anyhow::anyhow!("invalid space_id: {e:?}"))?;
        let did =
            Did::new(actor.to_owned()).map_err(|e| anyhow::anyhow!("invalid actor DID: {e:?}"))?;
        let flow = Flow::discussion(flow_id.to_owned(), space, title.to_owned(), did);
        let flow_value = serde_json::to_value(&flow)?;
        Ok(OperationBuilder::new(space_id, actor, "cx.flow.create")
            .target_ref(space_id)
            .body(json!({
                "list_id": space_id,
                "flow_id": flow_id,
                "title": title,
                "rank": "r0",
                "flow": flow_value,
            })))
    }

    pub fn invite_create_structured(
        space_id: &str,
        actor: &str,
        invite_id: &str,
        target: &str,
        role: Option<&str>,
        state: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.invite.create").body(json!({
            "invite_id": invite_id,
            "target": target,
            "role": role,
            "state": state,
        }))
    }

    pub fn invite_accept(space_id: &str, actor: &str, invite_id: &str) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.invite.accept")
            .target_ref(invite_id)
            .body(json!({"state": "accepted"}))
    }

    pub fn invite_cancel(
        space_id: &str,
        actor: &str,
        invite_id: &str,
        reason: Option<&str>,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.invite.cancel")
            .target_ref(invite_id)
            .body(json!({"state": "canceled", "reason": reason}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn operation_builder_generates_valid_envelope() {
        let op = OperationBuilder::new("cx:space:test", "did:web:alice", "cx.message.create")
            .body(json!({"body": "hello"}))
            .build("test_node");

        assert!(!op.operation_id.is_empty());
        assert_eq!(op.space_id, "cx:space:test");
        assert_eq!(op.actor, "did:web:alice");
        assert_eq!(op.op_type, "cx.message.create");
        assert!(!op.causal.hlc.is_empty());
        assert!(op.causal.actor_seq > 0);
    }

    #[test]
    fn operation_round_trip_serde() {
        let op = OperationBuilder::new("cx:space:s1", "did:web:bob", "cx.message.create")
            .body(json!({"body": "hello world"}))
            .build("node");
        let json = serde_json::to_string(&op).unwrap();
        let parsed: OperationEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(op, parsed);
    }

    #[test]
    fn discussion_flow_create_emits_canonical_kind() {
        let op = cx_ops::discussion_flow_create(
            "cx:space:test",
            "did:web:alice.example",
            "cx:flow:test",
            "Ops",
        )
        .unwrap()
        .build("node");
        assert_eq!(op.op_type, "cx.flow.create");
        assert_eq!(op.body["flow_id"], "cx:flow:test");
        assert_eq!(op.body["flow"]["kind"], "discussion");
    }

    #[test]
    fn invite_helpers_emit_canonical_kinds() {
        let create = cx_ops::invite_create_structured(
            "cx:space:test",
            "did:web:alice.example",
            "cx:invite:test",
            "did:web:bob.example",
            Some("member"),
            "pending",
        )
        .build("node");
        assert_eq!(create.op_type, "cx.invite.create");
        assert_eq!(create.body["invite_id"], "cx:invite:test");

        let accept =
            cx_ops::invite_accept("cx:space:test", "did:web:bob.example", "cx:invite:test")
                .build("node");
        assert_eq!(accept.op_type, "cx.invite.accept");

        let cancel = cx_ops::invite_cancel(
            "cx:space:test",
            "did:web:alice.example",
            "cx:invite:test",
            Some("expired"),
        )
        .build("node");
        assert_eq!(cancel.op_type, "cx.invite.cancel");
        assert_eq!(cancel.body["reason"], "expired");
    }
}
