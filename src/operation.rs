//! Operation envelope and commit builder per contrix-spec sections 6.2–6.6.
//!
//! An operation envelope contains: operation_id, space_id, actor, type,
//! target_ref, causal (deps, hlc, actor_seq), body, authz_ref, signature.
//!
//! A commit contains: commit_id, repo_did, prev_commit, seq, created_at,
//! operations[], signature.

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

/// A repo commit per contrix-spec section 6.2.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RepoCommit {
    /// Unique commit identifier.
    pub commit_id: String,
    /// The repo (DID) this commit belongs to.
    pub repo_did: String,
    /// Previous commit ID (forms the chain).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_commit: Option<String>,
    /// Monotonic sequence number within this repo.
    pub seq: u64,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    /// Operations contained in this commit.
    #[serde(default)]
    pub operations: Vec<OperationEnvelope>,
    /// Signature over the commit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
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
    /// Start building an operation.
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

    /// Set the target reference.
    pub fn target_ref(mut self, target_ref: impl Into<String>) -> Self {
        self.target_ref = Some(target_ref.into());
        self
    }

    /// Set the operation body.
    pub fn body(mut self, body: Value) -> Self {
        self.body = body;
        self
    }

    /// Set the authorization reference.
    pub fn authz_ref(mut self, authz_ref: impl Into<String>) -> Self {
        self.authz_ref = Some(authz_ref.into());
        self
    }

    /// Build the operation envelope with auto-generated ID, HLC, and sequence.
    pub fn build(self, node_id: &str) -> OperationEnvelope {
        let hlc = Hlc::now(node_id);
        OperationEnvelope {
            operation_id: uuid_v8(),
            space_id: self.space_id,
            actor: self.actor,
            op_type: self.op_type,
            target_ref: self.target_ref,
            causal: CausalMetadata {
                deps: Vec::new(),
                hlc: hlc.encode(),
                actor_seq: next_seq(),
            },
            body: self.body,
            authz_ref: self.authz_ref,
            signature: None,
        }
    }

    /// Build with explicit dependencies.
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

/// Builder for creating repo commits.
pub struct CommitBuilder {
    repo_did: String,
    prev_commit: Option<String>,
    operations: Vec<OperationEnvelope>,
}

impl CommitBuilder {
    /// Start building a commit for a given repo.
    pub fn new(repo_did: impl Into<String>) -> Self {
        Self {
            repo_did: repo_did.into(),
            prev_commit: None,
            operations: Vec::new(),
        }
    }

    /// Set the previous commit ID.
    pub fn prev_commit(mut self, prev: impl Into<String>) -> Self {
        self.prev_commit = Some(prev.into());
        self
    }

    /// Add an operation to the commit.
    pub fn add_operation(mut self, op: OperationEnvelope) -> Self {
        self.operations.push(op);
        self
    }

    /// Add multiple operations to the commit.
    pub fn add_operations(mut self, ops: Vec<OperationEnvelope>) -> Self {
        self.operations.extend(ops);
        self
    }

    /// Build the commit with auto-generated ID and sequence.
    pub fn build(self) -> RepoCommit {
        RepoCommit {
            commit_id: uuid_v8(),
            repo_did: self.repo_did,
            prev_commit: self.prev_commit,
            seq: next_seq(),
            created_at: chrono::Utc::now().to_rfc3339(),
            operations: self.operations,
            signature: None,
        }
    }
}

/// Generate a UUID v8-style identifier (timestamp + random).
pub fn uuid_v8() -> String {
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let ts_hi = (now >> 16) as u32;
    let ts_lo = (now & 0xFFFF) as u16;
    let rand_a: u16 = 0x8000 | (rand_u16() & 0x0FFF); // version 8
    let rand_b = rand_u64();
    format!("{:08x}-{:04x}-{:04x}-{:016x}", ts_hi, ts_lo, rand_a, rand_b)
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

// ── Standard operation type constructors ────────────────────────

/// Standard operation types per contrix-spec section 6.6.
pub mod cx_ops {
    use super::OperationBuilder;
    use serde_json::{Value, json};

    // Space/Schema/Policy
    pub fn space_create(space_id: &str, actor: &str, name: &str) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.space.create").body(json!({"name": name}))
    }

    pub fn space_update(space_id: &str, actor: &str, changes: Value) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.space.update").body(changes)
    }

    // Entity
    pub fn entity_create(
        space_id: &str,
        actor: &str,
        entity_type: &str,
        body: Value,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.entity.create")
            .body(json!({"entity_type": entity_type, "data": body}))
    }

    pub fn entity_update(
        space_id: &str,
        actor: &str,
        entity_id: &str,
        changes: Value,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.entity.update")
            .target_ref(entity_id)
            .body(changes)
    }

    pub fn entity_delete(space_id: &str, actor: &str, entity_id: &str) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.entity.delete")
            .target_ref(entity_id)
            .body(json!({}))
    }

    pub fn entity_restore(space_id: &str, actor: &str, entity_id: &str) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.entity.restore")
            .target_ref(entity_id)
            .body(json!({}))
    }

    // Relation
    pub fn relation_create(
        space_id: &str,
        actor: &str,
        source: &str,
        target: &str,
        rel_type: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.relation.create")
            .body(json!({"source": source, "target": target, "relation_type": rel_type}))
    }

    pub fn relation_delete(space_id: &str, actor: &str, relation_id: &str) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.relation.delete")
            .target_ref(relation_id)
            .body(json!({}))
    }

    // Message
    pub fn message_create(
        space_id: &str,
        actor: &str,
        channel: &str,
        body: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.message.create")
            .body(json!({"channel": channel, "msgtype": "m.text", "body": body}))
    }

    pub fn message_revise(
        space_id: &str,
        actor: &str,
        message_id: &str,
        new_body: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.message.revise")
            .target_ref(message_id)
            .body(json!({"body": new_body}))
    }

    pub fn message_redact(
        space_id: &str,
        actor: &str,
        message_id: &str,
        reason: Option<&str>,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.message.redact")
            .target_ref(message_id)
            .body(json!({"reason": reason}))
    }

    // Reaction
    pub fn reaction_add(
        space_id: &str,
        actor: &str,
        message_id: &str,
        reaction: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.reaction.add")
            .target_ref(message_id)
            .body(json!({"reaction": reaction}))
    }

    pub fn reaction_remove(
        space_id: &str,
        actor: &str,
        message_id: &str,
        reaction: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.reaction.remove")
            .target_ref(message_id)
            .body(json!({"reaction": reaction}))
    }

    // Channel
    pub fn channel_create(space_id: &str, actor: &str, name: &str, kind: &str) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.channel.create")
            .body(json!({"name": name, "kind": kind}))
    }

    pub fn channel_create_entity(
        space_id: &str,
        actor: &str,
        channel_id: &str,
        name: &str,
        kind: &str,
        topic: Option<&str>,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.channel.create").body(json!({
            "channel_id": channel_id,
            "name": name,
            "kind": kind,
            "topic": topic,
            "lifecycle": "active",
        }))
    }

    // Topic
    pub fn topic_create(space_id: &str, actor: &str, title: &str, body: &str) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.topic.create")
            .body(json!({"title": title, "body": body}))
    }

    pub fn topic_create_anchored(
        space_id: &str,
        actor: &str,
        topic_id: &str,
        title: &str,
        body: &str,
        anchor_ref: Value,
        tags: Vec<String>,
        mentions: Vec<Value>,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.topic.create").body(json!({
            "topic_id": topic_id,
            "title": title,
            "body": body,
            "anchor_ref": anchor_ref,
            "tags": tags,
            "mentions": mentions,
        }))
    }

    // Comment
    pub fn comment_create(
        space_id: &str,
        actor: &str,
        target: &str,
        body: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.comment.create")
            .target_ref(target)
            .body(json!({"body": body}))
    }

    pub fn comment_create_structured(
        space_id: &str,
        actor: &str,
        comment_id: &str,
        target: &str,
        body: &str,
        parent_comment_id: Option<&str>,
        mentions: Vec<Value>,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.comment.create")
            .target_ref(target)
            .body(json!({
                "comment_id": comment_id,
                "body": body,
                "parent_comment_id": parent_comment_id,
                "mentions": mentions,
            }))
    }

    // Run/Memory
    pub fn run_create(
        space_id: &str,
        actor: &str,
        agent_name: &str,
        input: Value,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.run.create")
            .body(json!({"agent_name": agent_name, "input": input}))
    }

    pub fn run_create_structured(
        space_id: &str,
        actor: &str,
        run_id: &str,
        agent_name: &str,
        input: Value,
        status: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.run.create").body(json!({
            "run_id": run_id,
            "agent_name": agent_name,
            "input": input,
            "status": status,
        }))
    }

    pub fn run_update(
        space_id: &str,
        actor: &str,
        run_id: &str,
        status: &str,
        step: Value,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.run.update")
            .target_ref(run_id)
            .body(json!({"status": status, "step": step}))
    }

    pub fn run_complete(
        space_id: &str,
        actor: &str,
        run_id: &str,
        output: Value,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.run.complete")
            .target_ref(run_id)
            .body(json!({"status": "completed", "output": output}))
    }

    pub fn run_fail(space_id: &str, actor: &str, run_id: &str, reason: &str) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.run.fail")
            .target_ref(run_id)
            .body(json!({"status": "failed", "reason": reason}))
    }

    pub fn memory_create(
        space_id: &str,
        actor: &str,
        content: &str,
        layer: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.memory.create")
            .body(json!({"content": content, "layer": layer}))
    }

    pub fn memory_create_structured(
        space_id: &str,
        actor: &str,
        memory_id: &str,
        content: &str,
        layer: &str,
        source: &str,
        confidence: f64,
        state: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.memory.create").body(json!({
            "memory_id": memory_id,
            "content": content,
            "layer": layer,
            "source": source,
            "confidence": confidence,
            "state": state,
        }))
    }

    pub fn memory_update(
        space_id: &str,
        actor: &str,
        memory_id: &str,
        changes: Value,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.memory.update")
            .target_ref(memory_id)
            .body(changes)
    }

    pub fn memory_confirm(space_id: &str, actor: &str, memory_id: &str) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.memory.confirm")
            .target_ref(memory_id)
            .body(json!({"state": "confirmed"}))
    }

    pub fn memory_invalidate(
        space_id: &str,
        actor: &str,
        memory_id: &str,
        reason: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.memory.invalidate")
            .target_ref(memory_id)
            .body(json!({"state": "invalidated", "reason": reason}))
    }

    pub fn memory_supersede(
        space_id: &str,
        actor: &str,
        memory_id: &str,
        superseded_by: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.memory.supersede")
            .target_ref(memory_id)
            .body(json!({"state": "superseded", "superseded_by": superseded_by}))
    }

    // Invite
    pub fn invite_create(space_id: &str, actor: &str, target: &str) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.invite.create").body(json!({"target": target}))
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

    // Read marker
    pub fn read_marker(
        space_id: &str,
        actor: &str,
        entity_id: &str,
        position: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.read.marker")
            .target_ref(entity_id)
            .body(json!({"position": position}))
    }

    // Capability
    pub fn capability_grant(
        space_id: &str,
        actor: &str,
        subject: &str,
        actions: Vec<&str>,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.capability.grant")
            .body(json!({"subject": subject, "actions": actions}))
    }

    pub fn capability_revoke(space_id: &str, actor: &str, grant_id: &str) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.capability.revoke")
            .target_ref(grant_id)
            .body(json!({}))
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
    fn commit_builder_generates_valid_commit() {
        let op = OperationBuilder::new("cx:space:test", "did:web:alice", "cx.entity.create")
            .body(json!({"entity_type": "task", "title": "Test"}))
            .build("node");

        let commit = CommitBuilder::new("did:web:alice")
            .add_operation(op)
            .build();

        assert!(!commit.commit_id.is_empty());
        assert_eq!(commit.repo_did, "did:web:alice");
        assert_eq!(commit.operations.len(), 1);
        assert!(commit.seq > 0);
    }

    #[test]
    fn operation_round_trip_serde() {
        let op = cx_ops::message_create("cx:space:s1", "did:web:bob", "general", "hello world")
            .build("node");
        let json = serde_json::to_string(&op).unwrap();
        let parsed: OperationEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(op, parsed);
    }

    #[test]
    fn commit_round_trip_serde() {
        let commit = CommitBuilder::new("did:web:carol")
            .add_operation(
                cx_ops::space_create("cx:space:new", "did:web:carol", "My Space").build("node"),
            )
            .prev_commit("prev_commit_id")
            .build();

        let json = serde_json::to_string(&commit).unwrap();
        let parsed: RepoCommit = serde_json::from_str(&json).unwrap();
        assert_eq!(commit, parsed);
    }

    #[test]
    fn cx_ops_cover_all_standard_types() {
        // Verify constructors produce correct operation types
        assert_eq!(
            cx_ops::space_create("s", "a", "n").build("n").op_type,
            "cx.space.create"
        );
        assert_eq!(
            cx_ops::space_update("s", "a", json!({})).build("n").op_type,
            "cx.space.update"
        );
        assert_eq!(
            cx_ops::entity_create("s", "a", "task", json!({}))
                .build("n")
                .op_type,
            "cx.entity.create"
        );
        assert_eq!(
            cx_ops::entity_update("s", "a", "e", json!({}))
                .build("n")
                .op_type,
            "cx.entity.update"
        );
        assert_eq!(
            cx_ops::entity_delete("s", "a", "e").build("n").op_type,
            "cx.entity.delete"
        );
        assert_eq!(
            cx_ops::entity_restore("s", "a", "e").build("n").op_type,
            "cx.entity.restore"
        );
        assert_eq!(
            cx_ops::relation_create("s", "a", "x", "y", "dep")
                .build("n")
                .op_type,
            "cx.relation.create"
        );
        assert_eq!(
            cx_ops::relation_delete("s", "a", "r").build("n").op_type,
            "cx.relation.delete"
        );
        assert_eq!(
            cx_ops::message_create("s", "a", "c", "b")
                .build("n")
                .op_type,
            "cx.message.create"
        );
        assert_eq!(
            cx_ops::message_revise("s", "a", "m", "b")
                .build("n")
                .op_type,
            "cx.message.revise"
        );
        assert_eq!(
            cx_ops::message_redact("s", "a", "m", None)
                .build("n")
                .op_type,
            "cx.message.redact"
        );
        assert_eq!(
            cx_ops::reaction_add("s", "a", "m", "+1").build("n").op_type,
            "cx.reaction.add"
        );
        assert_eq!(
            cx_ops::reaction_remove("s", "a", "m", "+1")
                .build("n")
                .op_type,
            "cx.reaction.remove"
        );
        assert_eq!(
            cx_ops::channel_create("s", "a", "c", "chat")
                .build("n")
                .op_type,
            "cx.channel.create"
        );
        let channel_entity =
            cx_ops::channel_create_entity("s", "a", "cx:channel:1", "c", "announce", Some("topic"))
                .build("n");
        assert_eq!(channel_entity.body["channel_id"], "cx:channel:1");
        assert_eq!(channel_entity.body["kind"], "announce");
        assert_eq!(
            cx_ops::topic_create("s", "a", "t", "b").build("n").op_type,
            "cx.topic.create"
        );
        let topic = cx_ops::topic_create_anchored(
            "s",
            "a",
            "cx:topic:1",
            "t",
            "b",
            json!({"kind": "run", "target": "cx:run:1"}),
            vec!["ops".to_owned()],
            vec![json!({"kind": "actor", "target": "did:web:bob.example"})],
        )
        .build("n");
        assert_eq!(topic.body["topic_id"], "cx:topic:1");
        assert_eq!(topic.body["anchor_ref"]["kind"], "run");
        assert_eq!(
            cx_ops::comment_create("s", "a", "e", "b")
                .build("n")
                .op_type,
            "cx.comment.create"
        );
        let comment = cx_ops::comment_create_structured(
            "s",
            "a",
            "cx:comment:1",
            "cx:topic:1",
            "b",
            Some("cx:comment:0"),
            vec![json!({"kind": "entity", "target": "cx:task:1"})],
        )
        .build("n");
        assert_eq!(comment.body["comment_id"], "cx:comment:1");
        assert_eq!(comment.body["parent_comment_id"], "cx:comment:0");
        assert_eq!(
            cx_ops::run_create("s", "a", "agent", json!({}))
                .build("n")
                .op_type,
            "cx.run.create"
        );
        let run = cx_ops::run_create_structured(
            "s",
            "a",
            "cx:run:1",
            "agent",
            json!({"prompt": "demo"}),
            "running",
        )
        .build("n");
        assert_eq!(run.body["run_id"], "cx:run:1");
        assert_eq!(run.body["status"], "running");
        assert_eq!(
            cx_ops::run_update("s", "a", "cx:run:1", "running", json!({"name": "tool"}))
                .build("n")
                .op_type,
            "cx.run.update"
        );
        assert_eq!(
            cx_ops::run_complete("s", "a", "cx:run:1", json!({"summary": "done"}))
                .build("n")
                .op_type,
            "cx.run.complete"
        );
        assert_eq!(
            cx_ops::run_fail("s", "a", "cx:run:1", "timeout")
                .build("n")
                .op_type,
            "cx.run.fail"
        );
        assert_eq!(
            cx_ops::memory_create("s", "a", "fact", "semantic")
                .build("n")
                .op_type,
            "cx.memory.create"
        );
        let memory = cx_ops::memory_create_structured(
            "s",
            "a",
            "cx:memory:1",
            "fact",
            "semantic",
            "review",
            0.92,
            "candidate",
        )
        .build("n");
        assert_eq!(memory.body["memory_id"], "cx:memory:1");
        assert_eq!(memory.body["state"], "candidate");
        assert_eq!(
            cx_ops::memory_update("s", "a", "cx:memory:1", json!({"content": "updated"}))
                .build("n")
                .op_type,
            "cx.memory.update"
        );
        assert_eq!(
            cx_ops::memory_confirm("s", "a", "cx:memory:1")
                .build("n")
                .op_type,
            "cx.memory.confirm"
        );
        assert_eq!(
            cx_ops::memory_invalidate("s", "a", "cx:memory:1", "bad source")
                .build("n")
                .op_type,
            "cx.memory.invalidate"
        );
        assert_eq!(
            cx_ops::memory_supersede("s", "a", "cx:memory:1", "cx:memory:2")
                .build("n")
                .op_type,
            "cx.memory.supersede"
        );
        assert_eq!(
            cx_ops::invite_create("s", "a", "t").build("n").op_type,
            "cx.invite.create"
        );
        let invite = cx_ops::invite_create_structured(
            "s",
            "a",
            "cx:invite:1",
            "did:web:bob.example",
            Some("member"),
            "pending",
        )
        .build("n");
        assert_eq!(invite.body["invite_id"], "cx:invite:1");
        assert_eq!(invite.body["role"], "member");
        assert_eq!(
            cx_ops::invite_accept("s", "a", "cx:invite:1")
                .build("n")
                .op_type,
            "cx.invite.accept"
        );
        assert_eq!(
            cx_ops::invite_cancel("s", "a", "cx:invite:1", Some("expired"))
                .build("n")
                .op_type,
            "cx.invite.cancel"
        );
        assert_eq!(
            cx_ops::read_marker("s", "a", "e", "p").build("n").op_type,
            "cx.read.marker"
        );
        assert_eq!(
            cx_ops::capability_grant("s", "a", "sub", vec!["read"])
                .build("n")
                .op_type,
            "cx.capability.grant"
        );
        assert_eq!(
            cx_ops::capability_revoke("s", "a", "g").build("n").op_type,
            "cx.capability.revoke"
        );
    }
}
