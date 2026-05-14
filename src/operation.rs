//! Minimal operation-envelope helpers for yougen's active write paths.
//!
//! Legacy commit-envelope helper paths were removed; active writes use the
//! current operation/event surfaces directly.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::{canonical_json_bytes, canonical_sha256};
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
    /// Pre-state assertions per `models/event-and-patch.md` reducer rules.
    /// Empty when the envelope is a side-effect-only signal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preconditions: Vec<Value>,
    /// Post-state effects per `models/event-and-patch.md` reducer rules.
    /// Empty when the envelope is a query / read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effects: Vec<Value>,
    /// Anchor reference if this operation has been anchored to a Lattice
    /// merge ordering anchor (`models/move-anchor-lattice.md`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_ref: Option<String>,
    /// Detached JWS proof. Spec §6.3 calls this `proof`; callers MUST set this
    /// before [`crate::api::Api::submit_operation_event`] for any durable kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
    /// Legacy free-form signature string. Retained for call sites that have not
    /// migrated to the typed [`Proof`] surface yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Detached JWS proof over the canonical body of an [`OperationEnvelope`].
///
/// Mirrors `MoveSignature` from `contrix_core` but stays as a JSON-only DTO so
/// yougen can serialize / deserialize proofs without dragging the SDK's
/// `MoveSignature` typed surface into every call site.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// DID of the signing principal.
    pub signer_did: String,
    /// Verification method id (`<did>#<fragment>`).
    pub key_id: String,
    /// JWS `alg` parameter — `EdDSA` for Ed25519, per encoding.md §6.
    pub alg: String,
    /// `sha256:<hex>` digest over the canonical body.
    pub payload_hash: String,
    /// Detached JWS string `<protected>..<signature>` (RFC 7515 §3.7).
    pub jws: String,
    /// RFC 3339 UTC timestamp.
    pub created_at: String,
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
            preconditions: Vec::new(),
            effects: Vec::new(),
            anchor_ref: None,
            proof: None,
            signature: None,
        }
    }
}

/// Body shape we feed into canonical JSON before signing. Excludes the proof
/// itself so the resulting digest is stable across signing rounds.
#[derive(Serialize)]
struct CanonicalView<'a> {
    operation_id: &'a str,
    space_id: &'a str,
    actor: &'a str,
    #[serde(rename = "type")]
    op_type: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_ref: Option<&'a str>,
    causal: &'a CausalMetadata,
    body: &'a Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    authz_ref: Option<&'a str>,
    #[serde(skip_serializing_if = "<[Value]>::is_empty")]
    preconditions: &'a [Value],
    #[serde(skip_serializing_if = "<[Value]>::is_empty")]
    effects: &'a [Value],
    #[serde(skip_serializing_if = "Option::is_none")]
    anchor_ref: Option<&'a str>,
}

impl OperationEnvelope {
    /// Canonical JSON bytes used for hashing / signing. Excludes any present
    /// proof so the digest is stable round-trip.
    pub fn canonical_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let view = CanonicalView {
            operation_id: &self.operation_id,
            space_id: &self.space_id,
            actor: &self.actor,
            op_type: &self.op_type,
            target_ref: self.target_ref.as_deref(),
            causal: &self.causal,
            body: &self.body,
            authz_ref: self.authz_ref.as_deref(),
            preconditions: &self.preconditions,
            effects: &self.effects,
            anchor_ref: self.anchor_ref.as_deref(),
        };
        canonical_json_bytes(&view)
    }

    /// `sha256:<hex>` digest of [`canonical_bytes`].
    pub fn canonical_digest(&self) -> anyhow::Result<String> {
        let view = CanonicalView {
            operation_id: &self.operation_id,
            space_id: &self.space_id,
            actor: &self.actor,
            op_type: &self.op_type,
            target_ref: self.target_ref.as_deref(),
            causal: &self.causal,
            body: &self.body,
            authz_ref: self.authz_ref.as_deref(),
            preconditions: &self.preconditions,
            effects: &self.effects,
            anchor_ref: self.anchor_ref.as_deref(),
        };
        canonical_sha256(&view)
    }

    /// Sign the envelope with an Ed25519 key and attach a detached JWS [`Proof`].
    ///
    /// Mirrors the SDK's `Ed25519MoveSigner::sign_payload` JWS layout so the
    /// receiver can verify with a `did:key`-derived public key.
    pub fn sign_ed25519(
        &mut self,
        signer_did: impl Into<String>,
        key_id: impl Into<String>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> anyhow::Result<()> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use ed25519_dalek::Signer;

        let canonical = self.canonical_bytes()?;
        let payload_hash = crate::canonical::sha256_digest(&canonical);

        let header = r#"{"alg":"EdDSA","typ":"JWT"}"#;
        let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(&canonical);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let jws = format!("{header_b64}..{sig_b64}");

        self.proof = Some(Proof {
            signer_did: signer_did.into(),
            key_id: key_id.into(),
            alg: "EdDSA".to_owned(),
            payload_hash,
            jws,
            created_at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        });
        Ok(())
    }

    /// Returns `Ok(())` when a typed [`Proof`] is attached. Used by submit
    /// paths that want to reject unsigned envelopes for durable event kinds.
    pub fn require_proof(&self) -> anyhow::Result<&Proof> {
        self.proof
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("operation envelope missing proof"))
    }
}

/// Generate a protocol-compatible UUIDv7 identifier.
///
/// The function name is kept for older UI call sites, but typed Contrix IDs
/// are validated as UUIDv7 at service boundaries.
pub fn uuid_v8() -> String {
    uuid_v7()
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
    fn discussion_flow_create_emits_discussion_track() {
        let op = cx_ops::discussion_flow_create(
            "cx:space:0196419b-0000-7000-8000-000000000000",
            "did:web:alice.example",
            "cx:flow:0196419b-0000-7000-8000-000000000001",
            "Ops",
        )
        .unwrap()
        .build("node");
        assert_eq!(op.op_type, "cx.flow.create");
        assert_eq!(
            op.body["flow_id"],
            "cx:flow:0196419b-0000-7000-8000-000000000001"
        );
        assert_eq!(
            op.body["flow"]["tracks"]["discussion"]["profile"],
            "discussion"
        );
        assert_eq!(op.body["flow"]["tracks"]["discussion"]["is_primary"], true);
        assert!(op.body["flow"].get("kind").is_none());
    }

    #[test]
    fn canonical_digest_is_stable_across_key_order() {
        let mut op_a = OperationBuilder::new("cx:space:s1", "did:web:alice", "cx.message.create")
            .body(json!({"b": 2, "a": 1}))
            .build("node");
        op_a.operation_id = "fixed".into();
        op_a.causal.hlc = "0000000000000000-00000000-00000000".into();
        op_a.causal.actor_seq = 1;

        let mut op_b = op_a.clone();
        op_b.body = json!({"a": 1, "b": 2});

        assert_eq!(op_a.canonical_digest().unwrap(), op_b.canonical_digest().unwrap());
    }

    #[test]
    fn sign_ed25519_attaches_typed_proof() {
        use ed25519_dalek::SigningKey;
        let mut op =
            OperationBuilder::new("cx:space:s1", "did:web:alice", "cx.message.create")
                .body(json!({"body": "hi"}))
                .build("node");
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        op.sign_ed25519("did:web:alice", "did:web:alice#k1", &signing_key)
            .expect("sign ok");
        let proof = op.proof.as_ref().expect("proof present");
        assert_eq!(proof.alg, "EdDSA");
        assert_eq!(proof.signer_did, "did:web:alice");
        assert!(proof.payload_hash.starts_with("sha256:"));
        // JWS layout: header.. (detached) ..sig — 3 parts separated by '.'.
        assert_eq!(proof.jws.matches('.').count(), 2);
        assert!(op.require_proof().is_ok());
    }

    #[test]
    fn require_proof_fails_when_unsigned() {
        let op = OperationBuilder::new("cx:space:s1", "did:web:alice", "cx.message.create")
            .body(json!({"body": "hi"}))
            .build("node");
        assert!(op.require_proof().is_err());
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
