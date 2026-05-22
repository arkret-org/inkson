//! Typed v1 Event Envelope used by yougen's active write paths.
//!
//! Spec source of truth: `contrix-spec/spec/v1/artifacts/schemas/event-schema.json`.
//!
//! # Signing
//!
//! All envelopes are produced with `proofs: Vec::new()`. The detached JWS
//! proof is attached exclusively by [`crate::event_signer::sign_with_active`]
//! from inside [`crate::api::ContrixApi::submit_event_envelope`]. There is
//! NO placeholder proof: a submit without an installed signer is rejected
//! locally with `no active signer configured` rather than shipped to the
//! wire in any form.
//!
//! Internal Rust field names match the wire JSON names exactly — there are
//! no `#[serde(rename)]` rewrites on this struct.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::canonical_sha256;
use crate::hlc::{Hlc, next_seq};

/// Active client-side proof attachment mode. Retained so the settings UI
/// can surface which signer backend is wired and so the signer bootstrap
/// path can flip from `Production` (fail-closed) to `RealEd25519` /
/// `ExternalSigner` once a real signer is installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofMode {
    /// A real Ed25519 signing key is wired into the build pipeline.
    RealEd25519,
    /// An external signer (OS keychain, WebAuthn, HSM) is wired in.
    ExternalSigner,
    /// No signer is configured. The submit guard refuses to ship
    /// anything; this is the fail-closed default.
    Production,
}

impl ProofMode {
    /// i18n key suffix (lowercased) for status-bar/settings display.
    pub fn i18n_key(self) -> &'static str {
        match self {
            ProofMode::RealEd25519 => "settings.proof_mode.real_ed25519",
            ProofMode::ExternalSigner => "settings.proof_mode.external_signer",
            ProofMode::Production => "settings.proof_mode.production",
        }
    }

    /// Human-readable English label (fallback when i18n is not wired up).
    pub fn label_en(self) -> &'static str {
        match self {
            ProofMode::RealEd25519 => "real Ed25519",
            ProofMode::ExternalSigner => "external signer",
            ProofMode::Production => "no signer (production)",
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            ProofMode::RealEd25519 => 1,
            ProofMode::ExternalSigner => 2,
            ProofMode::Production => 3,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => ProofMode::RealEd25519,
            2 => ProofMode::ExternalSigner,
            _ => ProofMode::Production,
        }
    }
}

const DEFAULT_PROOF_MODE: ProofMode = ProofMode::Production;

static PROOF_MODE: AtomicU8 = AtomicU8::new(0xFF);

/// Returns the active [`ProofMode`]. Defaults to [`ProofMode::Production`]
/// (fail-closed) until the signer bootstrap installs a real signer.
pub fn current_proof_mode() -> ProofMode {
    let raw = PROOF_MODE.load(Ordering::Relaxed);
    if raw == 0xFF {
        DEFAULT_PROOF_MODE
    } else {
        ProofMode::from_u8(raw)
    }
}

/// Set the active [`ProofMode`]. Called by the key-store / signer
/// bootstrap when a real signing identity becomes available.
pub fn set_proof_mode(mode: ProofMode) {
    PROOF_MODE.store(mode.as_u8(), Ordering::Relaxed);
}

pub(crate) fn scope_id_as_realm_id(value: &str) -> String {
    value
        .strip_prefix("cx:space:")
        .map(|suffix| format!("cx:realm:{suffix}"))
        .unwrap_or_else(|| value.to_owned())
}

/// Typed semantic reference per spec `event-schema.json $defs/semantic_ref`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SemanticRef {
    pub id: String,
    pub role: String,
    #[serde(default = "default_true")]
    pub critical: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<InclusionProof>,
}

fn default_true() -> bool {
    true
}

/// Typed inclusion-proof body per spec `event-schema.json $defs/semantic_ref.proof`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub kind: String,
    pub leaf_hash: String,
    pub audit_path: Vec<String>,
    pub leaf_index: u64,
    pub tree_size: u64,
}

/// Typed precondition per spec `event-schema.json $defs/precondition`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Precondition {
    pub cell: String,
    pub predicate: Predicate,
}

/// Typed predicate per spec `event-schema.json $defs/predicate`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Predicate {
    pub op: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate_id: Option<String>,
}

/// Typed effect per spec `event-schema.json $defs/effect`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Effect {
    pub cell: String,
    pub op: LatticeOp,
}

/// Typed lattice op per spec `event-schema.json $defs/lattice_op`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LatticeOp {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub element_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor: Option<String>,
}

/// Typed envelope requirements block per spec `event-schema.json
/// properties.requirements`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EventRequirements {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schema: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reducer: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub critical_extensions: Vec<CriticalExtension>,
}

/// Typed critical-extension declaration per spec `event-schema.json
/// $defs/criticalExtension`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CriticalExtension {
    pub id: String,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_ref: Option<String>,
    pub fail_closed: bool,
}

/// Current v1 Event Envelope used by active write paths.
///
/// Field names match the wire JSON exactly per spec `event-schema.json` —
/// no serde renames. `preconditions` / `effects` / `anchor_ref` are
/// `Option<Vec<...>>` / `Option<String>` because reducer-input event kinds
/// require them and non-reducer kinds (read marker, account_data, ...)
/// must omit them entirely.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_id: String,
    pub kind: String,
    pub realm_id: String,
    pub actor_id: String,
    pub actor_seq: u64,
    pub created_at: String,
    pub hlc: String,
    #[serde(default)]
    pub prev_refs: Vec<String>,
    #[serde(default)]
    pub refs: Vec<SemanticRef>,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preconditions: Vec<Precondition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effects: Vec<Effect>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirements: Option<EventRequirements>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacts: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unsigned: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<EventProof>,
}

/// Detached proof entry on an [`EventEnvelope`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventProof {
    pub kind: String,
    pub alg: String,
    pub verification_method: String,
    pub payload_hash: String,
    pub created_at: String,
    pub jws: String,
}

/// Builder for creating typed event envelopes. Callers attach
/// preconditions / effects / anchor_ref / requirements after `new()`
/// and before `build()`; `build()` produces an unsigned envelope and the
/// `submit_event_envelope` path requires an active signer to attach the
/// detached JWS proof before going on the wire.
pub struct OperationBuilder {
    realm_id: String,
    actor: String,
    op_type: String,
    target_ref: Option<String>,
    body: Value,
    authz_ref: Option<String>,
    preconditions: Vec<Precondition>,
    effects: Vec<Effect>,
    refs: Vec<SemanticRef>,
    anchor_ref: Option<String>,
    requirements: Option<EventRequirements>,
    redacts: Option<String>,
}

impl OperationBuilder {
    pub fn new(
        realm_id: impl Into<String>,
        actor: impl Into<String>,
        op_type: impl Into<String>,
    ) -> Self {
        Self {
            realm_id: realm_id.into(),
            actor: actor.into(),
            op_type: op_type.into(),
            target_ref: None,
            body: Value::Null,
            authz_ref: None,
            preconditions: Vec::new(),
            effects: Vec::new(),
            refs: Vec::new(),
            anchor_ref: None,
            requirements: None,
            redacts: None,
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

    pub fn preconditions(mut self, preconditions: Vec<Precondition>) -> Self {
        self.preconditions = preconditions;
        self
    }

    pub fn effects(mut self, effects: Vec<Effect>) -> Self {
        self.effects = effects;
        self
    }

    pub fn refs(mut self, refs: Vec<SemanticRef>) -> Self {
        self.refs = refs;
        self
    }

    pub fn anchor_ref(mut self, anchor_ref: impl Into<String>) -> Self {
        self.anchor_ref = Some(anchor_ref.into());
        self
    }

    pub fn requirements(mut self, requirements: EventRequirements) -> Self {
        self.requirements = Some(requirements);
        self
    }

    pub fn redacts(mut self, redacts: impl Into<String>) -> Self {
        self.redacts = Some(redacts.into());
        self
    }

    pub fn build(self, node_id: &str) -> EventEnvelope {
        self.build_with_deps(node_id, Vec::new())
    }

    pub fn build_with_deps(self, node_id: &str, deps: Vec<String>) -> EventEnvelope {
        let hlc = Hlc::now(node_id);
        let operation_id = typed_operation_id(&uuid_v7());
        let mut unsigned = BTreeMap::new();
        unsigned.insert(
            "local_operation_idempotency_alias".to_owned(),
            Value::String(operation_id),
        );
        if let Some(target_ref) = self.target_ref {
            unsigned.insert("local_target_ref".to_owned(), Value::String(target_ref));
        }
        if let Some(authz_ref) = self.authz_ref {
            unsigned.insert("local_authz_ref".to_owned(), Value::String(authz_ref));
        }
        let actor_seq = next_seq();
        // Normalise the wire `realm_id` field — callers may still hand in
        // the legacy `cx:space:` form during the inversion migration.
        let realm_id = scope_id_as_realm_id(&self.realm_id);
        EventEnvelope {
            event_id: format!("cx:event:{}", uuid_v7()),
            kind: self.op_type,
            actor_id: self.actor,
            actor_seq,
            realm_id,
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            hlc: hlc.encode(),
            prev_refs: deps,
            refs: self.refs,
            payload: self.body,
            preconditions: self.preconditions,
            effects: self.effects,
            anchor_ref: self.anchor_ref,
            requirements: self.requirements,
            redacts: self.redacts,
            unsigned,
            proofs: Vec::new(),
        }
    }
}

impl EventEnvelope {
    pub fn local_operation_idempotency_alias(&self) -> Option<&str> {
        self.unsigned
            .get("local_operation_idempotency_alias")
            .and_then(Value::as_str)
    }

    pub fn local_operation_id(&self) -> &str {
        self.local_operation_idempotency_alias()
            .unwrap_or(self.event_id.as_str())
    }

    pub fn local_target_ref(&self) -> Option<&str> {
        self.unsigned
            .get("local_target_ref")
            .and_then(Value::as_str)
    }

    pub fn canonical_digest(&self) -> anyhow::Result<String> {
        let mut canonical = serde_json::to_value(self)?;
        if let Value::Object(object) = &mut canonical {
            object.remove("proofs");
            object.remove("unsigned");
        }
        canonical_sha256(&canonical)
    }

    pub fn refresh_proof_hashes(&mut self) -> anyhow::Result<()> {
        let digest = self.canonical_digest()?;
        for proof in &mut self.proofs {
            proof.payload_hash = digest.clone();
        }
        Ok(())
    }

    pub fn sign_ed25519(
        &mut self,
        signer_did: impl Into<String>,
        key_id: impl Into<String>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> anyhow::Result<()> {
        // Delegate to the SDK pipeline via
        // [`crate::event_signer::YougenEventSigner::sign_envelope`] so a
        // bug fix in the canonical-bytes / detached-JWS path lands in
        // one place (the SDK) instead of being mirrored across coauth,
        // soland, and yougen.
        use contrix_sdk::signatures::proof::Ed25519DetachedJwsSigner;
        use std::sync::Arc;

        let signer_did = signer_did.into();
        let key_id = key_id.into();
        let sdk_signer = Ed25519DetachedJwsSigner::new(signing_key.clone(), key_id.clone());
        let signer = crate::event_signer::YougenEventSigner::from_dyn_signer(
            Arc::new(sdk_signer),
            signer_did.clone(),
        );
        signer
            .sign_envelope(self)
            .map_err(|err| anyhow::anyhow!("Ed25519 sign rejected: {err}"))?;
        if let Some(proof) = self.proofs.first_mut() {
            proof.verification_method = key_id;
        }
        if self.actor_id.is_empty() {
            self.actor_id = signer_did;
        }
        Ok(())
    }

    pub fn require_proof(&self) -> anyhow::Result<&EventProof> {
        self.proofs
            .first()
            .ok_or_else(|| anyhow::anyhow!("event envelope missing proof"))
    }
}

fn typed_operation_id(operation_id: &str) -> String {
    if operation_id.starts_with("cx:operation:") {
        operation_id.to_owned()
    } else {
        format!("cx:operation:{operation_id}")
    }
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
    use super::{OperationBuilder, scope_id_as_realm_id};
    use serde_json::{Value, json};

    fn object_patch_payload_value(
        object_ref: &str,
        legacy_id_field: &str,
        patch: contrix_sdk::Patch,
    ) -> Value {
        let mut payload = contrix_sdk::ObjectPatchPayload::for_target(object_ref, patch)
            .and_then(|payload| payload.to_value())
            .unwrap_or_else(|err| {
                panic!("invalid object_patch_payload for {object_ref}: {err}");
            });
        payload
            .as_object_mut()
            .expect("object_patch_payload serializes as an object")
            .insert(legacy_id_field.to_owned(), json!(object_ref));
        payload
    }

    fn flow_object_patch_payload_value(flow_id: &str, patch: contrix_sdk::Patch) -> Value {
        object_patch_payload_value(flow_id, "flow_id", patch)
    }

    fn patch_set(path: &str, value: Value) -> contrix_sdk::Patch {
        let mut patch = contrix_sdk::Patch::new();
        patch
            .insert_op(path, contrix_sdk::PatchOp::set(value))
            .unwrap_or_else(|err| {
                panic!("invalid cx.patch.v1 path {path:?}: {err}");
            });
        patch
    }

    fn patch_from_value(patch: Value) -> contrix_sdk::Patch {
        let patch: contrix_sdk::Patch = serde_json::from_value(patch).unwrap_or_else(|err| {
            panic!("cx.flow.update patch must match cx.patch.v1: {err}");
        });
        patch.validate().unwrap_or_else(|err| {
            panic!("cx.flow.update patch must match cx.patch.v1: {err}");
        });
        patch
    }

    /// Build a canonical `cx.flow.create` discussion operation with the full
    /// typed Flow payload expected by the current reducers.
    ///
    /// The full Flow lives under the spec-canonical `object` key —
    /// see soland `routing/events/operations.rs::FLOW_CREATE_REQUIREMENTS`
    /// and SDK `crates/core/src/schema/payloads.rs` which both gate
    /// `cx.flow.create` on `payload.object`.
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
                "space_id": space_id,
                "flow_id": flow_id,
                "title": title,
                "rank": "r0",
                "object": flow_value,
            })))
    }

    /// Build a `cx.flow.watch.set` operation. Spec:
    /// `contrix-spec/spec/v1/zh/models/flow-and-message.md §8.3` —
    /// writes the cas-register cell `cx.component.flow.watch.v1` keyed by
    /// `(flow_id, actor_did)`.
    ///
    /// `level` is one of `mentions_only` / `participating` / `all` / `muted`,
    /// or `None` to clear the cell (equivalent to `mentions_only` default).
    /// `level_public` is the opt-in flag from §8.5 — when `true`, projection
    /// to non-self viewers does not strip the level value (but `muted` still
    /// stays invisible). Caller MUST omit `level_public` when `level` is None.
    ///
    /// Default reducer invariant: `target_actor` MUST equal `sender_actor`
    /// unless the sender holds `cx.flow.watch.manage_others`. Callers
    /// helping someone else subscribe (e.g. Flow creator seeding
    /// watchers on create) need that capability.
    pub fn flow_watch_set(
        space_id: &str,
        sender_actor: &str,
        target_actor_did: &str,
        flow_id: &str,
        level: Option<&str>,
        level_public: Option<bool>,
    ) -> OperationBuilder {
        let mut payload = json!({
            "flow_id": flow_id,
            "actor_did": target_actor_did,
            "level": level,
        });
        // Schema-level allOf in flow_watch_set_payload forbids
        // level_public when level is null; only emit it on non-null level.
        if level.is_some() {
            if let Some(public) = level_public {
                payload["level_public"] = json!(public);
            }
        }
        OperationBuilder::new(space_id, sender_actor, "cx.flow.watch.set")
            .target_ref(flow_id)
            .body(payload)
    }

    /// Build a `cx.flow.tracks.update` operation. Spec:
    /// `contrix-spec/spec/v1/zh/models/flow-and-message.md §3` (post dc01ad7).
    ///
    /// This is the single unified track-mutation event that replaces
    /// `cx.flow.track.{enable,disable,update,set_primary}`.
    /// `patch` is a `cx.patch.v1` JSON Patch object against the `Flow.tracks`
    /// map (keys are track names like `synthesis` / `discussion`). For
    /// example, enabling the `discussion` track is:
    ///
    /// ```json
    /// { "tracks.discussion.enabled": { "$op": "set", "value": true } }
    /// ```
    ///
    /// Disabling, renaming, or marking a track primary all flow through the
    /// same patch shape. Callers that only know a track name should compose
    /// the patch via the helpers below (`flow_tracks_update_enable`,
    /// `flow_tracks_update_disable`, `flow_tracks_update_set_primary`).
    pub fn flow_tracks_update(
        space_id: &str,
        actor: &str,
        flow_id: &str,
        patch: serde_json::Value,
    ) -> OperationBuilder {
        let patch = patch_from_value(patch);
        OperationBuilder::new(space_id, actor, "cx.flow.tracks.update")
            .target_ref(flow_id)
            .body(flow_object_patch_payload_value(flow_id, patch))
    }

    /// Convenience wrapper: enable `track` on `flow_id`. Emits the unified
    /// `cx.flow.tracks.update` event with a `cx.patch.v1` set-op against
    /// `tracks.<name>.enabled`.
    pub fn flow_tracks_update_enable(
        space_id: &str,
        actor: &str,
        flow_id: &str,
        track: &str,
    ) -> OperationBuilder {
        let key = format!("tracks.{track}.enabled");
        let patch = json!({ key: { "$op": "set", "value": true } });
        flow_tracks_update(space_id, actor, flow_id, patch)
    }

    /// Convenience wrapper: disable `track` on `flow_id`.
    pub fn flow_tracks_update_disable(
        space_id: &str,
        actor: &str,
        flow_id: &str,
        track: &str,
    ) -> OperationBuilder {
        let key = format!("tracks.{track}.enabled");
        let patch = json!({ key: { "$op": "set", "value": false } });
        flow_tracks_update(space_id, actor, flow_id, patch)
    }

    /// Convenience wrapper: mark `track` as the Flow's primary track.
    /// Carries a single set-op against `tracks.<name>.is_primary`. The reducer
    /// is responsible for clearing the previous primary cell.
    pub fn flow_tracks_update_set_primary(
        space_id: &str,
        actor: &str,
        flow_id: &str,
        track: &str,
    ) -> OperationBuilder {
        let key = format!("tracks.{track}.is_primary");
        let patch = json!({ key: { "$op": "set", "value": true } });
        flow_tracks_update(space_id, actor, flow_id, patch)
    }

    /// Build a `cx.space.create` operation for Board/List container Spaces.
    ///
    /// After R1.7 realm/space inversion, Board/List containers are Space
    /// objects and the security boundary is Realm. The optional
    /// `parent_space_id` + `rank` fields carry the board/list structural
    /// placement while the object id and event kind stay canonical.
    pub fn space_create(
        realm_id: &str,
        actor: &str,
        container_space_id: &str,
        kind: &str,
        title: &str,
        parent_space_id: Option<&str>,
        rank: Option<&str>,
    ) -> OperationBuilder {
        let mut body = json!({
            "object": {
                "id": container_space_id,
                "schema": "cx.schema.space.v1",
                "realm_id": scope_id_as_realm_id(realm_id),
                "kind": kind,
                "title": title,
                "created_by": actor,
                "created_at": chrono::Utc::now()
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            },
        });
        if let Some(parent_space_id) = parent_space_id {
            body["object"]["parent_ref"] = json!(parent_space_id);
        }
        if let Some(rank) = rank {
            body["object"]["rank"] = json!(rank);
        }
        OperationBuilder::new(realm_id, actor, "cx.space.create")
            .target_ref(container_space_id)
            .body(body)
    }

    /// Compatibility alias for pre-R1.7 call sites. New production code
    /// should call [`space_create`].
    pub fn place_create(
        realm_id: &str,
        actor: &str,
        container_space_id: &str,
        kind: &str,
        title: &str,
        parent_space_id: Option<&str>,
        rank: Option<&str>,
    ) -> OperationBuilder {
        space_create(
            realm_id,
            actor,
            container_space_id,
            kind,
            title,
            parent_space_id,
            rank,
        )
    }

    /// Build a `cx.flow.create` for a document Flow.
    ///
    /// Document content travels on the Flow's synthesis track in
    /// `body.fields.document` (an opaque JSON blob defined by the
    /// client). The synthesis track is the spec-blessed home for
    /// human-authored long-form content; see `models/flow-and-message.md`
    /// §synthesis_track.
    pub fn document_flow_create(
        space_id: &str,
        actor: &str,
        flow_id: &str,
        title: &str,
        document_body: serde_json::Value,
    ) -> OperationBuilder {
        let object = json!({
            "schema": "cx.schema.flow.v1",
            "id": flow_id,
            "space_id": space_id,
            "title": title,
            "tracks": { "synthesis": {} },
            "fields": { "document": document_body.clone() },
            "created_by": actor,
            "created_at": chrono::Utc::now()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        });
        OperationBuilder::new(space_id, actor, "cx.flow.create")
            .target_ref(space_id)
            .body(json!({
                "space_id": space_id,
                "flow_id": flow_id,
                "title": title,
                "rank": "r0",
                "kind": "document",
                "fields": {
                    "document": document_body,
                },
                "object": object,
            }))
    }

    /// Build a `cx.flow.create` for a Kanban card Flow and include the
    /// initial Board/List position component used by board projections.
    pub fn kanban_card_flow_create(
        space_id: &str,
        actor: &str,
        flow_id: &str,
        board_space_id: &str,
        list_space_id: &str,
        title: &str,
        rank: &str,
    ) -> OperationBuilder {
        let realm_id = scope_id_as_realm_id(space_id);
        let created_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let position_cell_id =
            format!("cx:cell:cx.component.flow.position.v1:{board_space_id}:{flow_id}");
        let object = json!({
            "schema": "cx.schema.flow.v1",
            "id": flow_id,
            "realm_id": realm_id,
            "space_id": space_id,
            "title": title,
            "tracks": {
                "synthesis": {
                    "is_primary": true,
                    "profile": "kanban_card"
                }
            },
            "fields": {
                "flow_kind": "card",
                "board_space_id": board_space_id,
                "list_space_id": list_space_id,
                "rank": rank
            },
            "created_by": actor,
            "created_at": created_at,
        });
        OperationBuilder::new(space_id, actor, "cx.flow.create")
            .target_ref(flow_id)
            .body(json!({
                "space_id": space_id,
                "flow_id": flow_id,
                "title": title,
                "rank": rank,
                "object": object,
                "components": [
                    {
                        "family": "cx.component.flow.position.v1",
                        "cell_id": position_cell_id,
                        "board_space_id": board_space_id,
                        "flow_id": flow_id,
                        "list_space_id": list_space_id,
                        "rank": rank
                    }
                ]
            }))
    }

    /// Build a `cx.flow.update` carrying a new document body on the
    /// synthesis track. `flow_id` must already exist on the server (i.e.
    /// the corresponding `cx.flow.create` has been accepted).
    pub fn document_flow_update(
        space_id: &str,
        actor: &str,
        flow_id: &str,
        document_body: serde_json::Value,
    ) -> OperationBuilder {
        let payload =
            flow_object_patch_payload_value(flow_id, patch_set("fields.document", document_body));
        OperationBuilder::new(space_id, actor, "cx.flow.update")
            .target_ref(flow_id)
            .body(payload)
    }

    /// Build a `cx.flow.update` delta operation using the canonical
    /// `cx.patch.v1` payload shape. Non-create Flow updates should carry
    /// only changed fields; callers are responsible for composing patch paths
    /// that are valid for the Flow schema/profile.
    pub fn flow_update_patch(
        space_id: &str,
        actor: &str,
        flow_id: &str,
        patch: serde_json::Value,
    ) -> OperationBuilder {
        let patch = patch_from_value(patch);
        OperationBuilder::new(space_id, actor, "cx.flow.update")
            .target_ref(flow_id)
            .body(flow_object_patch_payload_value(flow_id, patch))
    }

    /// Build a `cx.morph.update` patch operation. Mirrors
    /// [`flow_update_patch`] for Morph objects; soland's
    /// `apply_morph_update` reducer accepts `payload.patch` with the
    /// standard `cx.schema.patch.v1` shape.
    pub fn morph_update_patch(
        space_id: &str,
        actor: &str,
        morph_id: &str,
        patch: serde_json::Value,
    ) -> OperationBuilder {
        let patch = patch_from_value(patch);
        OperationBuilder::new(space_id, actor, "cx.morph.update")
            .target_ref(morph_id)
            .body(object_patch_payload_value(morph_id, "morph_id", patch))
    }

    /// Build a `cx.policy.update` patch operation. The reducer-side
    /// integration for cx.policy.* events is not yet wired in soland;
    /// in the meantime clients can apply policy patches via the
    /// `PATCH /api/v1/policies/{policy_id}` admin endpoint (`patch`
    /// body field). This builder is the future-proof event-stream
    /// form so clients don't have to wait for that wiring.
    pub fn policy_update_patch(
        space_id: &str,
        actor: &str,
        policy_id: &str,
        patch: serde_json::Value,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.policy.update")
            .target_ref(policy_id)
            .body(json!({
                "policy_id": policy_id,
                "patch": patch,
            }))
    }

    /// Build a `cx.actor_profile.update` patch operation. Same
    /// caveat as [`policy_update_patch`]: the reducer-side wiring is
    /// deferred; the builder keeps client code spec-shape correct.
    pub fn actor_profile_update_patch(
        space_id: &str,
        actor: &str,
        actor_profile_id: &str,
        patch: serde_json::Value,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.actor_profile.update")
            .target_ref(actor_profile_id)
            .body(json!({
                "actor_profile_id": actor_profile_id,
                "patch": patch,
            }))
    }

    /// Build a `cx.message.revise` patch operation. Spec: revise is
    /// supposed to carry `payload.patch` like the other `*.update`
    /// events. Soland today accepts both the legacy full-content
    /// shape and the new patch shape (additive). New clients SHOULD
    /// emit patches; legacy clients sending `{content: <full body>}`
    /// keep working.
    pub fn message_revise_patch(
        space_id: &str,
        actor: &str,
        message_id: &str,
        patch: serde_json::Value,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.message.revise")
            .target_ref(message_id)
            .body(json!({
                "message_id": message_id,
                "patch": patch,
            }))
    }

    /// Build a `cx.realm.update` patch operation. The reducer accepts
    /// both flat fields (action/owner/title/security_class) and
    /// `payload.patch`; the patch shape is preferred for non-lifecycle
    /// edits (title / description).
    pub fn realm_update_patch(
        space_id: &str,
        actor: &str,
        realm_id: &str,
        patch: serde_json::Value,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.realm.update")
            .target_ref(realm_id)
            .body(json!({
                "realm_id": realm_id,
                "patch": patch,
            }))
    }

    /// Build a `cx.moderation.report.submit` operation. Note: this is
    /// the event-stream form; today yougen also has a direct HTTP
    /// path via `api::Client::report_moderation`. Keep both — the
    /// HTTP path goes through `/api/v1/moderation/report` and is
    /// validated/authorised inline; the event-stream form rides on
    /// the standard operation submit pipeline.
    pub fn moderation_report_submit(
        space_id: &str,
        actor: &str,
        report_id: &str,
        target_ref: &str,
        reason: &str,
        description: Option<&str>,
        evidence_refs: Vec<String>,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.moderation.report.submit")
            .target_ref(report_id)
            .body(json!({
                "report_id": report_id,
                "target_ref": target_ref,
                "reason": reason,
                "description": description,
                "evidence_refs": evidence_refs,
            }))
    }

    /// Build a `cx.moderation.appeal.submit` operation. Mirrors the
    /// 4-state moderation appeal FSM (see
    /// `contrix_sdk::round23::AppealSubmitPayload`).
    pub fn moderation_appeal_submit(
        space_id: &str,
        actor: &str,
        appeal_id: &str,
        realm_id: &str,
        decision_ref: &str,
        target_ref: &str,
        reason_text_ref: &str,
        evidence_refs: Vec<String>,
        evidence_visibility: Option<&str>,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.moderation.appeal.submit")
            .target_ref(appeal_id)
            .body(json!({
                "appeal_id": appeal_id,
                "realm_id": realm_id,
                "decision_ref": decision_ref,
                "target_ref": target_ref,
                "appellant": actor,
                "reason_text_ref": reason_text_ref,
                "evidence_refs": evidence_refs,
                "evidence_visibility": evidence_visibility,
            }))
    }

    pub fn invite_create_structured(
        space_id: &str,
        actor: &str,
        invite_id: &str,
        target: &str,
        role: Option<&str>,
        state: &str,
    ) -> OperationBuilder {
        let mut body = serde_json::Map::new();
        body.insert("invite_id".to_owned(), json!(invite_id));
        body.insert("target".to_owned(), json!(target));
        if let Some(role) = role {
            body.insert("role".to_owned(), json!(role));
        }
        body.insert("state".to_owned(), json!(state));
        OperationBuilder::new(space_id, actor, "cx.invite.create").body(Value::Object(body))
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

    /// Build a `cx.space.archive` operation against a container Space. The
    /// Space transitions from `Active` to `Archived`; reversible via
    /// [`space_restore`]. Spec: `models/realm-and-space.md` §4.4. The wire
    /// payload uses canonical `space_id` (no legacy alias).
    pub fn space_archive(
        realm_id: &str,
        actor: &str,
        container_space_id: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(realm_id, actor, "cx.space.archive")
            .target_ref(container_space_id)
            .body(json!({ "space_id": container_space_id }))
    }

    /// Build a `cx.space.restore` operation. Reverses [`space_archive`]
    /// (`archived -> active`). The SDK reducer enforces `state == archived`
    /// at apply time; tombstoned container Spaces MUST NOT be restored. Spec:
    /// `models/realm-and-space.md` §4.4 (post-R1.7 rename), `common-fields.md §5`.
    pub fn space_restore(
        realm_id: &str,
        actor: &str,
        container_space_id: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(realm_id, actor, "cx.space.restore")
            .target_ref(container_space_id)
            .body(json!({ "space_id": container_space_id }))
    }

    /// Build a `cx.flow.archive` operation. Spec: `flow-and-message.md §3`
    /// and `common-fields.md §5.1`; payload shape is the
    /// `object_lifecycle_payload` from
    /// `artifacts/schemas/event-payload.schema.json`, which requires one of
    /// `target_ref` / `object_ref` / `status`. SDK reducer rejects with
    /// `flow_not_active` when source state is not `active`.
    pub fn flow_archive(space_id: &str, actor: &str, flow_id: &str) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.flow.archive")
            .target_ref(flow_id)
            // Spec-canonical payload field is `target_ref`. `flow_id` is
            // retained as a non-normative alias for in-flight servers that
            // still read it; remove once soland's `apply_flow_lifecycle`
            // and `FLOW_LIFECYCLE_REQUIREMENTS` stop accepting it.
            .body(json!({ "target_ref": flow_id, "flow_id": flow_id }))
    }

    /// Build a `cx.flow.restore` operation. Reverses [`flow_archive`]
    /// (`archived -> active`). SDK reducer rejects with `flow_not_archived`
    /// when source state is not `archived`. Payload shape mirrors the
    /// archive op (spec `object_lifecycle_payload`).
    pub fn flow_restore(space_id: &str, actor: &str, flow_id: &str) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.flow.restore")
            .target_ref(flow_id)
            .body(json!({ "target_ref": flow_id, "flow_id": flow_id }))
    }

    // ── Consent (OrSet cell `cx.component.consent.grant.v1`) ─────────

    /// `cx.consent.grant` event. Spec: events.submit applies this to the
    /// `cx.component.consent.grant.v1` OrSet cell as an add op with `tag`.
    pub fn consent_grant(
        realm_id: &str,
        actor: &str,
        consent_id: &str,
        tag: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(realm_id, actor, "cx.consent.grant")
            .target_ref(consent_id)
            .body(json!({
                "consent_id": consent_id,
                "tag": tag,
            }))
    }

    /// `cx.consent.revoke` event with required `observed_dots` (round 4
    /// wire). Pass an empty slice only for non-causal revoke.
    pub fn consent_revoke(
        realm_id: &str,
        actor: &str,
        consent_id: &str,
        tag: &str,
        reason: Option<&str>,
        observed_dots: &[contrix_sdk::Dot],
    ) -> OperationBuilder {
        let mut body = json!({
            "consent_id": consent_id,
            "tag": tag,
            "observed_dots": serde_json::to_value(observed_dots)
                .unwrap_or(json!([])),
        });
        if let Some(reason) = reason {
            body["reason"] = json!(reason);
        }
        OperationBuilder::new(realm_id, actor, "cx.consent.revoke")
            .target_ref(consent_id)
            .body(body)
    }

    // ── Capability (OrSet cell `cx.component.capability.grant.v1`) ───

    /// `cx.capability.grant` event with optional structured constraints
    /// (e.g. `temporal.window`). `tag` is the capability action the grant
    /// authorises (e.g. `discussion.message.create`).
    pub fn capability_grant(
        realm_id: &str,
        actor: &str,
        grant_id: &str,
        tag: &str,
        constraints: Value,
    ) -> OperationBuilder {
        let mut body = json!({
            "grant_id": grant_id,
            "tag": tag,
        });
        if !constraints.is_null() {
            body["constraints"] = constraints;
        }
        OperationBuilder::new(realm_id, actor, "cx.capability.grant")
            .target_ref(grant_id)
            .body(body)
    }

    /// `cx.capability.revoke` event. `reason` shows up in the audit
    /// trail and lets the UI explain why the capability was dropped.
    pub fn capability_revoke(
        realm_id: &str,
        actor: &str,
        grant_id: &str,
        tag: &str,
        reason: Option<&str>,
    ) -> OperationBuilder {
        let mut body = json!({
            "grant_id": grant_id,
            "tag": tag,
        });
        if let Some(reason) = reason {
            body["reason"] = json!(reason);
        }
        OperationBuilder::new(realm_id, actor, "cx.capability.revoke")
            .target_ref(grant_id)
            .body(body)
    }

    // ── Member state FSM (Realm `cx.component.member.state.v1`) ─────

    /// `cx.member.state` FSM transition (kick / ban / unban / leave).
    /// Pass `from_state` to express an explicit FSM precondition (the
    /// server reducer rejects with `state_mismatch` if the current
    /// state doesn't match).
    pub fn member_state_transition(
        realm_id: &str,
        actor: &str,
        member: &str,
        from_state: Option<&str>,
        to_state: &str,
        reason: &str,
    ) -> OperationBuilder {
        let mut body = json!({
            "actor_id": member,
            "membership": to_state,
            "reason": reason,
        });
        if to_state == "join" {
            body["delivery_status"] = json!("unroutable");
        }
        if let Some(from_state) = from_state {
            body["from"] = json!(from_state);
        }
        OperationBuilder::new(realm_id, actor, "cx.member.state")
            .target_ref(member)
            .body(body)
    }

    // ── MLS epoch (per-Realm group ratchet) ─────────────────────────

    /// `cx.mls.commit` event carrying the canonical
    /// `mls_governance_binding.full.v1` preconditions + effects from the
    /// SDK governance binding payload. The server reducer enforces the
    /// binding by matching the precondition / effect tuples and the
    /// referenced binding hash against the spec shape.
    pub fn mls_commit_with_governance(
        realm_id: &str,
        actor: &str,
        group_id: &str,
        preconditions: Vec<Value>,
        effects: Vec<Value>,
        binding_hash: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(realm_id, actor, "cx.mls.commit")
            .target_ref(group_id)
            .body(json!({
                "group_id": group_id,
                "preconditions": preconditions,
                "effects": effects,
                "binding_hash": binding_hash,
            }))
    }

    // ── Conflict repair (admin-only) ────────────────────────────────

    /// `cx.conflict.repair` event for bottom=expose cells. Admin / moderator
    /// only — soland's authz reducer rejects submissions without a valid
    /// `recovery_capability_ref` in the actor's grants.
    pub fn conflict_repair(
        realm_id: &str,
        actor: &str,
        cell_id: &str,
        conflict_heads: &[String],
        recovery_capability_ref: &str,
        winner_value: Value,
    ) -> OperationBuilder {
        OperationBuilder::new(realm_id, actor, "cx.conflict.repair")
            .target_ref(cell_id)
            .body(json!({
                "cell_id": cell_id,
                "conflict_heads": conflict_heads,
                "recovery_capability_ref": recovery_capability_ref,
                "winner_value": winner_value,
            }))
    }

    /// `cx.realm.update` patch event on the organization cell. Mirrors the
    /// legacy `build_signed_space_organization_update` Move shape (name /
    /// topic / description / etc.). Pass the merge patch as `value`.
    pub fn realm_organization_update(
        realm_id: &str,
        actor: &str,
        value: Value,
    ) -> OperationBuilder {
        let patch = patch_from_value(value);
        OperationBuilder::new(realm_id, actor, "cx.realm.update")
            .target_ref(realm_id)
            .body(object_patch_payload_value(realm_id, "realm_id", patch))
    }

    /// Legacy flow position update (kanban card position).
    ///
    /// Current protocol writes new position changes through
    /// `cx.flow.move` / `cx.flow.reorder`; this helper remains for old
    /// local drafts that still carry a generic `position` object, but it
    /// still emits the canonical `object_patch_payload` shape.
    pub fn flow_position_update(
        realm_id: &str,
        actor: &str,
        flow_id: &str,
        position_value: Value,
    ) -> OperationBuilder {
        flow_update_patch(
            realm_id,
            actor,
            flow_id,
            json!({
                "position": { "$op": "set", "value": position_value },
            }),
        )
    }

    /// Flow position CAS update — same cell as
    /// [`flow_position_update`] but carries an `expected_position`
    /// the server reducer compares to the cell's current value; on
    /// mismatch the response is `cas_conflict` and the client should
    /// rebase against the new head.
    pub fn flow_position_cas_update(
        realm_id: &str,
        actor: &str,
        kind: &str,
        board_space_id: &str,
        flow_id: &str,
        expected_position: Value,
        effect_position: Value,
    ) -> OperationBuilder {
        let position_field = |value: &Value, field: &str| {
            value
                .get(field)
                .or_else(|| match field {
                    "space_id" => value.get("list_space_id"),
                    _ => None,
                })
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let expected_space = position_field(&expected_position, "space_id");
        let expected_rank = position_field(&expected_position, "rank");
        let effect_space = position_field(&effect_position, "space_id");
        let effect_rank = position_field(&effect_position, "rank");

        let Some(effect_space) = effect_space else {
            let mut payload =
                flow_object_patch_payload_value(flow_id, patch_set("position", effect_position));
            let object = payload
                .as_object_mut()
                .expect("object_patch_payload serializes as an object");
            object.insert("board_space_id".to_owned(), json!(board_space_id));
            object.insert("expected_position".to_owned(), expected_position);
            return OperationBuilder::new(realm_id, actor, "cx.flow.update")
                .target_ref(flow_id)
                .body(payload);
        };
        let Some(effect_rank) = effect_rank else {
            let mut payload =
                flow_object_patch_payload_value(flow_id, patch_set("position", effect_position));
            let object = payload
                .as_object_mut()
                .expect("object_patch_payload serializes as an object");
            object.insert("board_space_id".to_owned(), json!(board_space_id));
            object.insert("expected_position".to_owned(), expected_position);
            return OperationBuilder::new(realm_id, actor, "cx.flow.update")
                .target_ref(flow_id)
                .body(payload);
        };

        let mut body = serde_json::Map::new();
        body.insert("board_space_id".to_owned(), json!(board_space_id));
        body.insert("flow_id".to_owned(), json!(flow_id));
        body.insert("rank".to_owned(), json!(effect_rank));

        match kind {
            "cx.flow.reorder" => {
                body.insert("space_id".to_owned(), json!(effect_space));
                if let Some(rank) = expected_rank {
                    body.insert("expected_position".to_owned(), json!({ "rank": rank }));
                }
                OperationBuilder::new(realm_id, actor, "cx.flow.reorder")
                    .target_ref(flow_id)
                    .body(Value::Object(body))
            }
            _ => {
                body.insert("target_space_id".to_owned(), json!(effect_space));
                if let Some(space_id) = expected_space {
                    body.insert("from_space_id".to_owned(), json!(space_id));
                }
                if let (Some(space_id), Some(rank)) = (
                    position_field(&expected_position, "space_id"),
                    expected_rank,
                ) {
                    body.insert(
                        "expected_position".to_owned(),
                        json!({ "space_id": space_id, "rank": rank }),
                    );
                }
                OperationBuilder::new(realm_id, actor, "cx.flow.move")
                    .target_ref(flow_id)
                    .body(Value::Object(body))
            }
        }
    }

    // ── Applet protocol family ────────────────────────────────────────
    //
    // Spec: `extensions/applet-integration.md` + canonical event-kind
    // registry rows `cx.applet.registration` / `cx.applet.discovery` /
    // `cx.applet.protocol_session.{start,status}` / `cx.applet.bridge_error`.
    //
    // The builders below produce the wire shape soland validators and the
    // SDK reducer consume. Each carries the canonical `applet_id` (or
    // `service_did` for registration / discovery) as `target_ref` so
    // soland's `target-ref-required` envelope-shape check passes.

    /// `cx.applet.registration` — declare an applet service_did + the
    /// event-kind subset / namespaces / capabilities it can write.
    pub fn applet_registration(
        space_id: &str,
        actor: &str,
        service_did: &str,
        namespace: &str,
        capabilities: &[&str],
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.applet.registration")
            .target_ref(service_did)
            .body(json!({
                "service_did": service_did,
                "namespace": namespace,
                "capabilities": capabilities,
            }))
    }

    /// `cx.applet.discovery` — the network discovery surface that lists
    /// what an applet exposes; emitted by directory crawlers and by the
    /// applet itself on registration round-trip.
    pub fn applet_discovery(
        space_id: &str,
        actor: &str,
        service_did: &str,
        manifest: serde_json::Value,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.applet.discovery")
            .target_ref(service_did)
            .body(json!({
                "service_did": service_did,
                "manifest": manifest,
            }))
    }

    /// Round 4 (spec a77b995) — validate an `applet_id` against the
    /// canonical [`contrix_sdk::AppletIdentifier`] shape (DID *or*
    /// `cx:applet:<uuidv7>`). Returns the typed identifier so callers
    /// can stash it without re-parsing. Wire-breaking: plain strings
    /// outside these two forms are rejected.
    pub fn parse_applet_identifier(
        applet_id: &str,
    ) -> Result<contrix_sdk::AppletIdentifier, String> {
        if applet_id.starts_with("did:") {
            contrix_sdk::Did::new(applet_id)
                .map(contrix_sdk::AppletIdentifier::Did)
                .map_err(|e| format!("invalid applet DID: {e}"))
        } else if applet_id.starts_with("cx:applet:") {
            contrix_sdk::AppletId::new(applet_id)
                .map(contrix_sdk::AppletIdentifier::Cx)
                .map_err(|e| format!("invalid cx:applet:<uuidv7>: {e}"))
        } else {
            Err(format!(
                "applet_id {applet_id:?} is neither a DID nor cx:applet:<uuidv7> \
                 (round 4 schema_violation)"
            ))
        }
    }

    /// Round 4 — validate an `agent_id` against the canonical
    /// [`contrix_sdk::AgentId`] shape (strict DID). Wire-breaking: the
    /// pre-round-4 permissive plain-string form is rejected.
    pub fn parse_agent_identifier(agent_id: &str) -> Result<contrix_sdk::AgentId, String> {
        contrix_sdk::Did::new(agent_id).map_err(|e| format!("invalid agent DID: {e}"))
    }

    /// `cx.applet.protocol_session.start` — open a per-session channel
    /// between a Space member and an applet (used for portal-style RPC
    /// + agent invocation).
    pub fn applet_protocol_session_start(
        space_id: &str,
        actor: &str,
        applet_id: &str,
        session_id: &str,
        params: serde_json::Value,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.applet.protocol_session.start")
            .target_ref(session_id)
            .body(json!({
                "applet_id": applet_id,
                "session_id": session_id,
                "params": params,
            }))
    }

    /// `cx.applet.protocol_session.status` — applet → caller status push
    /// (progress, intermediate result, completion).
    pub fn applet_protocol_session_status(
        space_id: &str,
        actor: &str,
        session_id: &str,
        status: &str,
        detail: serde_json::Value,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.applet.protocol_session.status")
            .target_ref(session_id)
            .body(json!({
                "session_id": session_id,
                "status": status,
                "detail": detail,
            }))
    }

    /// `cx.applet.bridge_error` — emitted by the applet bridge when a
    /// protocol_session call fails outside the spec's typed result.
    pub fn applet_bridge_error(
        space_id: &str,
        actor: &str,
        session_id: &str,
        error_code: &str,
        message: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.applet.bridge_error")
            .target_ref(session_id)
            .body(json!({
                "session_id": session_id,
                "error_code": error_code,
                "message": message,
            }))
    }

    // ── Agent protocol family ─────────────────────────────────────────
    //
    // Spec: `extensions/agent-integration.md` + canonical event-kind
    // registry rows `cx.agent.endpoint` / `cx.agent.protocol_session.
    // {start,status,result}`. Agents are server-side delegates a member
    // grants narrow capabilities to (e.g. a read-flow Researcher Agent);
    // the wire shape lets soland and the SDK reducer track which agent
    // owns which session, what status, and what result.

    /// `cx.agent.endpoint` — register an agent service_did + its
    /// invocation protocol + capability requirements.
    pub fn agent_endpoint(
        space_id: &str,
        actor: &str,
        agent_did: &str,
        protocol: &str,
        capabilities: &[&str],
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.agent.endpoint")
            .target_ref(agent_did)
            .body(json!({
                "agent_did": agent_did,
                "protocol": protocol,
                "capabilities": capabilities,
            }))
    }

    /// `cx.agent.protocol_session.start` — kick off an agent
    /// invocation;  body carries the parameter payload + the
    /// capability proof bundle.
    pub fn agent_protocol_session_start(
        space_id: &str,
        actor: &str,
        agent_did: &str,
        session_id: &str,
        params: serde_json::Value,
        capability_proof: serde_json::Value,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.agent.protocol_session.start")
            .target_ref(session_id)
            .body(json!({
                "agent_did": agent_did,
                "session_id": session_id,
                "params": params,
                "capability_proof": capability_proof,
            }))
    }

    /// `cx.agent.protocol_session.status` — agent progress signal.
    pub fn agent_protocol_session_status(
        space_id: &str,
        actor: &str,
        session_id: &str,
        status: &str,
        detail: serde_json::Value,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.agent.protocol_session.status")
            .target_ref(session_id)
            .body(json!({
                "session_id": session_id,
                "status": status,
                "detail": detail,
            }))
    }

    /// `cx.agent.protocol_session.result` — terminal event carrying the
    /// agent's signed result + the audit-binding proof.
    pub fn agent_protocol_session_result(
        space_id: &str,
        actor: &str,
        session_id: &str,
        result: serde_json::Value,
        audit_binding: serde_json::Value,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.agent.protocol_session.result")
            .target_ref(session_id)
            .body(json!({
                "session_id": session_id,
                "result": result,
                "audit_binding": audit_binding,
            }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::path::Path;

    fn spec_schema(name: &str) -> serde_json::Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../contrix-spec/spec/v1/artifacts/schemas")
            .join(name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read spec schema {}: {err}", path.display()));
        serde_json::from_str(&text).unwrap_or_else(|err| {
            panic!("parse spec schema {}: {err}", path.display());
        })
    }

    fn assert_registered_payload_valid(event: &EventEnvelope) {
        let catalog = contrix_sdk::schema::event_payload_validator_catalog();
        catalog
            .validate_payload(&event.kind, &event.payload)
            .unwrap_or_else(|err| {
                panic!(
                    "{} payload violates registered spec schema: {err}\npayload: {}",
                    event.kind,
                    serde_json::to_string_pretty(&event.payload).unwrap()
                );
            });
    }

    fn assert_payload_field_names_are_soland_canonical(value: &serde_json::Value) {
        fn check(value: &serde_json::Value) -> Result<(), String> {
            match value {
                serde_json::Value::Array(values) => {
                    for value in values {
                        check(value)?;
                    }
                }
                serde_json::Value::Object(object) => {
                    for (key, value) in object {
                        let name_part = key.strip_prefix('$').unwrap_or(key);
                        if name_part.is_empty()
                            || !name_part
                                .chars()
                                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                            || name_part.starts_with('_')
                            || name_part.ends_with('_')
                            || name_part.contains("__")
                        {
                            return Err(format!("non-canonical field name {key:?}"));
                        }
                        check(value)?;
                    }
                }
                _ => {}
            }
            Ok(())
        }
        check(value).unwrap_or_else(|err| {
            panic!("payload violates soland canonical JSON gate: {err}\npayload: {value}")
        });
    }

    // R1.7 (realm-rework): kept as local schema-test helpers for cases that
    // need to assert required-property presence directly.
    #[allow(dead_code)]
    fn required_fields(schema: &serde_json::Value) -> Vec<String> {
        schema
            .get("required")
            .and_then(serde_json::Value::as_array)
            .unwrap_or_else(|| panic!("schema missing required[]"))
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect()
    }

    #[allow(dead_code)]
    fn assert_required_fields_present(schema: &serde_json::Value, value: &serde_json::Value) {
        for field in required_fields(schema) {
            assert!(
                value.get(&field).is_some(),
                "payload missing required schema field `{field}`: {value}"
            );
        }
    }

    fn patch_schema_ops(schema: &serde_json::Value) -> Vec<String> {
        schema["additionalProperties"]["oneOf"][1]["properties"]["$op"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn proof_mode_labels_are_distinct() {
        let modes = [
            ProofMode::RealEd25519,
            ProofMode::ExternalSigner,
            ProofMode::Production,
        ];
        let labels: Vec<_> = modes.iter().map(|m| m.label_en()).collect();
        let i18n_keys: Vec<_> = modes.iter().map(|m| m.i18n_key()).collect();
        for label in &labels {
            assert_eq!(labels.iter().filter(|l| **l == *label).count(), 1);
        }
        for key in &i18n_keys {
            assert_eq!(i18n_keys.iter().filter(|k| **k == *key).count(), 1);
        }
    }

    #[test]
    fn operation_builder_generates_valid_envelope() {
        let op = OperationBuilder::new("cx:realm:test", "did:web:alice", "cx.message.create")
            .body(json!({"body": "hello"}))
            .build("test_node");

        assert!(!op.local_operation_id().is_empty());
        assert_eq!(op.realm_id, "cx:realm:test");
        assert_eq!(op.actor_id, "did:web:alice");
        assert_eq!(op.kind, "cx.message.create");
        assert!(!op.hlc.is_empty());
        assert!(op.actor_seq > 0);
        // Spec compliance: build() never attaches a placeholder proof —
        // the submit path requires an installed signer.
        assert!(op.proofs.is_empty());
    }

    #[test]
    fn operation_round_trip_serde() {
        let op = OperationBuilder::new("cx:space:s1", "did:web:bob", "cx.message.create")
            .body(json!({"body": "hello world"}))
            .build("node");
        let json = serde_json::to_string(&op).unwrap();
        let parsed: EventEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(op, parsed);
    }

    #[test]
    fn document_flow_create_carries_synthesis_body() {
        let op = cx_ops::document_flow_create(
            "cx:space:doc-test",
            "did:web:alice",
            "cx:flow:doc-1",
            "Untitled Document",
            json!({"blocks": [{"id": "block-1", "kind": "Heading", "content": "Hi"}]}),
        )
        .build("test_node");

        assert_eq!(op.kind, "cx.flow.create");
        assert_eq!(op.payload["flow_id"], "cx:flow:doc-1");
        assert_eq!(op.payload["kind"], "document");
        assert_eq!(
            op.payload["fields"]["document"]["blocks"][0]["kind"],
            "Heading"
        );
    }

    #[test]
    fn kanban_card_flow_create_carries_position_component() {
        let op = cx_ops::kanban_card_flow_create(
            "cx:space:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "cx:flow:0196419b-0000-7000-8000-000000000004",
            "cx:space:0196419b-0000-7000-8000-000000000002",
            "cx:space:0196419b-0000-7000-8000-000000000003",
            "Move-backed card",
            "h1",
        )
        .build("node");
        let flow_schema = spec_schema("flow.schema.json");

        assert_eq!(op.kind, "cx.flow.create");
        assert_eq!(op.realm_id, "cx:realm:0196419b-0000-7000-8000-000000000001");
        assert_eq!(
            op.payload["object"]["realm_id"],
            "cx:realm:0196419b-0000-7000-8000-000000000001"
        );
        assert_required_fields_present(&flow_schema, &op.payload["object"]);
        assert_eq!(
            op.payload["object"]["tracks"]["synthesis"]["profile"],
            "kanban_card"
        );
        assert_eq!(
            op.payload["components"][0]["family"],
            "cx.component.flow.position.v1"
        );
        assert_eq!(
            op.payload["components"][0]["cell_id"],
            "cx:cell:cx.component.flow.position.v1:cx:space:0196419b-0000-7000-8000-000000000002:cx:flow:0196419b-0000-7000-8000-000000000004"
        );
        assert!(op.payload.get("patch").is_none());
        assert_registered_payload_valid(&op);
        assert_payload_field_names_are_soland_canonical(&op.payload);
    }

    #[test]
    fn document_flow_update_targets_existing_flow_id() {
        let op = cx_ops::document_flow_update(
            "cx:space:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "cx:flow:0196419b-0000-7000-8000-000000000002",
            json!({"blocks": []}),
        )
        .build("test_node");

        assert_eq!(op.kind, "cx.flow.update");
        assert_eq!(
            op.payload["flow_id"],
            "cx:flow:0196419b-0000-7000-8000-000000000002"
        );
        assert!(op.payload.get("fields").is_none());
        assert!(op.payload["patch"]["fields.document"]["value"]["blocks"].is_array());
        assert_registered_payload_valid(&op);
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
        assert_eq!(op.kind, "cx.flow.create");
        assert_eq!(
            op.payload["flow_id"],
            "cx:flow:0196419b-0000-7000-8000-000000000001"
        );
        assert_eq!(
            op.payload["object"]["tracks"]["discussion"]["profile"],
            "discussion"
        );
        assert_eq!(
            op.payload["object"]["tracks"]["discussion"]["is_primary"],
            true
        );
        assert!(op.payload["object"].get("kind").is_none());
    }

    #[test]
    fn flow_tracks_update_primary_uses_is_primary_patch_key() {
        let flow_id = "cx:flow:0196419b-0000-7000-8000-000000000001";
        let op = cx_ops::flow_tracks_update_set_primary(
            "cx:space:0196419b-0000-7000-8000-000000000010",
            "did:web:alice.example",
            flow_id,
            "discussion",
        )
        .build("node");
        assert_eq!(op.kind, "cx.flow.tracks.update");
        assert_eq!(
            op.payload["patch"]["tracks.discussion.is_primary"]["value"],
            true
        );
        assert!(
            op.payload["patch"]
                .get("tracks.discussion.primary")
                .is_none()
        );
    }

    #[test]
    fn flow_update_patch_uses_canonical_payload_patch() {
        let flow_id = "cx:flow:0196419b-0000-7000-8000-000000000002";
        let op = cx_ops::flow_update_patch(
            "cx:space:0196419b-0000-7000-8000-000000000010",
            "did:web:alice.example",
            flow_id,
            json!({
                "title": { "$op": "set", "value": "Launch checklist" },
                "fields.due_at": { "$op": "set", "value": "2026-05-20" },
            }),
        )
        .build("node");
        assert_eq!(op.kind, "cx.flow.update");
        assert_eq!(op.local_target_ref(), Some(flow_id));
        assert_eq!(op.payload["flow_id"], flow_id);
        assert_eq!(op.payload["patch"]["title"]["value"], "Launch checklist");
        assert!(op.payload.get("fields").is_none());
    }

    #[test]
    fn flow_update_builders_match_registered_object_patch_schema() {
        let space_id = "cx:space:0196419b-0000-7000-8000-000000000001";
        let actor = "did:web:alice.example";
        let flow_id = "cx:flow:0196419b-0000-7000-8000-000000000002";
        let board_space_id = "cx:space:0196419b-0000-7000-8000-000000000010";
        let list_space_id = "cx:space:0196419b-0000-7000-8000-000000000011";

        let events = [
            cx_ops::document_flow_update(space_id, actor, flow_id, json!({"blocks": []}))
                .build("node"),
            cx_ops::flow_update_patch(
                space_id,
                actor,
                flow_id,
                json!({
                    "title": { "$op": "set", "value": "Launch checklist" },
                    "fields.due_at": { "$op": "set", "value": "2026-05-20" },
                }),
            )
            .build("node"),
            cx_ops::flow_position_update(
                space_id,
                actor,
                flow_id,
                json!({
                    "flow_id": flow_id,
                    "board_space_id": board_space_id,
                    "list_space_id": list_space_id,
                    "rank": "U",
                }),
            )
            .build("node"),
            // Null effect_position triggers the legacy cx.flow.update fallback
            // inside flow_position_cas_update. It still must satisfy
            // object_patch_payload instead of leaking top-level `position`.
            cx_ops::flow_position_cas_update(
                space_id,
                actor,
                "cx.flow.move",
                board_space_id,
                flow_id,
                json!({"list_space_id": list_space_id, "rank": "U"}),
                Value::Null,
            )
            .build("node"),
        ];

        for event in &events {
            assert_eq!(event.kind, "cx.flow.update");
            assert!(event.payload.get("patch").is_some());
            assert!(event.payload.get("fields").is_none());
            assert!(event.payload.get("position").is_none());
            assert_registered_payload_valid(event);
        }

        let catalog = contrix_sdk::schema::event_payload_validator_catalog();
        assert!(
            catalog
                .validate_payload(
                    "cx.flow.update",
                    &json!({
                        "flow_id": flow_id,
                        "fields": { "document": { "blocks": [] } },
                    }),
                )
                .is_err(),
            "legacy top-level fields must not validate as cx.flow.update"
        );
    }

    #[test]
    fn object_patch_family_builders_match_registered_payload_schema() {
        let realm_id = "cx:realm:0196419b-0000-7000-8000-000000000001";
        let actor = "did:web:alice.example";
        let flow_id = "cx:flow:0196419b-0000-7000-8000-000000000002";
        let morph_id = "cx:morph:0196419b-0000-7000-8000-000000000003";

        let events = [
            cx_ops::flow_tracks_update_set_primary(realm_id, actor, flow_id, "discussion")
                .build("node"),
            cx_ops::morph_update_patch(
                realm_id,
                actor,
                morph_id,
                json!({ "title": { "$op": "set", "value": "Spec note" } }),
            )
            .build("node"),
            cx_ops::realm_organization_update(
                realm_id,
                actor,
                json!({ "title": { "$op": "set", "value": "Engineering" } }),
            )
            .build("node"),
        ];

        for event in &events {
            assert!(event.payload.get("patch").is_some(), "{}", event.kind);
            assert!(event.payload.get("target_ref").is_some(), "{}", event.kind);
            assert_registered_payload_valid(event);
        }
    }

    #[test]
    fn flow_position_cas_update_emits_canonical_move_payload() {
        let op = cx_ops::flow_position_cas_update(
            "cx:space:0196419b-0000-7000-8000-000000000001",
            "did:web:alice",
            "cx.flow.move",
            "cx:space:0196419b-0000-7000-8000-000000000010",
            "cx:flow:0196419b-0000-7000-8000-000000000020",
            json!({
                "list_space_id": "cx:space:0196419b-0000-7000-8000-000000000030",
                "rank": "a1"
            }),
            json!({
                "list_space_id": "cx:space:0196419b-0000-7000-8000-000000000040",
                "rank": "b1"
            }),
        )
        .build("node");

        assert_eq!(op.kind, "cx.flow.move");
        assert_eq!(
            op.payload["board_space_id"],
            "cx:space:0196419b-0000-7000-8000-000000000010"
        );
        assert_eq!(
            op.payload["target_space_id"],
            "cx:space:0196419b-0000-7000-8000-000000000040"
        );
        assert_eq!(op.payload["rank"], "b1");
        assert_eq!(
            op.payload["expected_position"]["space_id"],
            "cx:space:0196419b-0000-7000-8000-000000000030"
        );
        assert_eq!(op.payload["expected_position"]["rank"], "a1");
        assert!(op.payload.get("board_place_id").is_none());
        assert!(op.payload.get("target_place_id").is_none());
        assert!(op.payload.get("position").is_none());
    }

    #[test]
    fn flow_position_cas_update_emits_canonical_reorder_payload() {
        let op = cx_ops::flow_position_cas_update(
            "cx:space:0196419b-0000-7000-8000-000000000001",
            "did:web:alice",
            "cx.flow.reorder",
            "cx:space:0196419b-0000-7000-8000-000000000010",
            "cx:flow:0196419b-0000-7000-8000-000000000020",
            json!({
                "list_space_id": "cx:space:0196419b-0000-7000-8000-000000000030",
                "rank": "a1"
            }),
            json!({
                "list_space_id": "cx:space:0196419b-0000-7000-8000-000000000030",
                "rank": "a2"
            }),
        )
        .build("node");

        assert_eq!(op.kind, "cx.flow.reorder");
        assert_eq!(
            op.payload["board_space_id"],
            "cx:space:0196419b-0000-7000-8000-000000000010"
        );
        assert_eq!(
            op.payload["space_id"],
            "cx:space:0196419b-0000-7000-8000-000000000030"
        );
        assert_eq!(op.payload["rank"], "a2");
        assert_eq!(op.payload["expected_position"]["rank"], "a1");
        assert!(op.payload["expected_position"].get("space_id").is_none());
        assert!(op.payload.get("target_space_id").is_none());
        assert!(op.payload.get("position").is_none());
    }

    #[test]
    fn space_create_emits_canonical_space_object() {
        let op = cx_ops::space_create(
            "cx:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice",
            "cx:space:0196419b-0000-7000-8000-000000000002",
            "list",
            "To Do",
            Some("cx:space:0196419b-0000-7000-8000-000000000003"),
            Some("U"),
        )
        .build("node");
        assert_eq!(op.kind, "cx.space.create");
        assert_eq!(
            op.local_target_ref(),
            Some("cx:space:0196419b-0000-7000-8000-000000000002")
        );
        assert!(op.payload.get("place_id").is_none());
        assert!(op.payload.get("board_place_id").is_none());
        assert_eq!(op.payload["object"]["schema"], "cx.schema.space.v1");
        assert_eq!(
            op.payload["object"]["id"],
            "cx:space:0196419b-0000-7000-8000-000000000002"
        );
        assert_eq!(
            op.payload["object"]["realm_id"],
            "cx:realm:0196419b-0000-7000-8000-000000000001"
        );
        assert!(op.payload["object"].get("space_id").is_none());
        assert_eq!(op.payload["object"]["kind"], "list");
        assert!(op.payload["object"].get("board_place_id").is_none());
        assert_eq!(
            op.payload["object"]["parent_ref"],
            "cx:space:0196419b-0000-7000-8000-000000000003"
        );
        assert_eq!(op.payload["object"]["rank"], "U");
        assert_eq!(op.payload["object"]["created_by"], "did:web:alice");
        assert!(
            op.payload["object"]["created_at"]
                .as_str()
                .unwrap()
                .ends_with('Z')
        );
    }

    #[test]
    fn spec_space_schema_accepts_client_space_create_payload_shape() {
        // R1.7 rename: the container schema artifact is now space.schema.json
        // (the former place.schema.json was retired in contrix-spec's R1.7
        // pass). The builder still has the legacy helper name
        // `space_create` emits a canonical Space object.
        let schema = spec_schema("space.schema.json");
        let op = cx_ops::space_create(
            "cx:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "cx:space:0196419b-0000-7000-8000-000000000002",
            "list",
            "To Do",
            Some("cx:space:0196419b-0000-7000-8000-000000000003"),
            Some("U"),
        )
        .build("node");
        let object = &op.payload["object"];

        assert_eq!(object["schema"], schema["properties"]["schema"]["const"]);
        assert_eq!(
            object["realm_id"],
            "cx:realm:0196419b-0000-7000-8000-000000000001"
        );
        assert_eq!(op.kind, "cx.space.create");
        assert!(op.payload.get("place_id").is_none());
        assert!(serde_json::to_string(&op).unwrap().contains("\"realm_id\""));
        assert!(!serde_json::to_string(&op).unwrap().contains("cx:list:"));
    }

    #[test]
    fn spec_patch_schema_accepts_client_flow_tracks_update_payload_shape() {
        let schema = spec_schema("patch.schema.json");
        let ops = patch_schema_ops(&schema);
        let op = cx_ops::flow_tracks_update_set_primary(
            "cx:space:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "cx:flow:0196419b-0000-7000-8000-000000000004",
            "discussion",
        )
        .build("node");
        let patch = op.payload["patch"].as_object().unwrap();

        assert!(!patch.is_empty());
        assert!(patch.contains_key("tracks.discussion.is_primary"));
        assert!(!patch.contains_key("tracks.discussion.primary"));
        for value in patch.values() {
            let op = value["$op"].as_str().unwrap();
            assert!(ops.iter().any(|allowed| allowed == op));
            if matches!(op, "set" | "add" | "remove") {
                assert!(value.get("value").is_some());
            }
        }
    }

    #[test]
    fn spec_patch_schema_accepts_client_flow_update_payload_shape() {
        let schema = spec_schema("patch.schema.json");
        let ops = patch_schema_ops(&schema);
        let op = cx_ops::flow_update_patch(
            "cx:space:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "cx:flow:0196419b-0000-7000-8000-000000000004",
            json!({
                "title": { "$op": "set", "value": "Launch checklist" },
                "summary": { "$op": "set", "value": "Ship blockers only" },
                "fields.labels": { "$op": "set", "value": ["release", "ops"] },
                "fields.assignee": { "$op": "set", "value": "did:web:alice.example" },
                "fields.due_at": { "$op": "set", "value": "2026-05-20" },
            }),
        )
        .build("node");
        let patch = op.payload["patch"].as_object().unwrap();

        assert!(!patch.is_empty());
        assert_eq!(op.kind, "cx.flow.update");
        assert!(patch.contains_key("title"));
        assert!(patch.contains_key("summary"));
        assert!(patch.contains_key("fields.labels"));
        assert!(patch.contains_key("fields.assignee"));
        assert!(patch.contains_key("fields.due_at"));
        for value in patch.values() {
            let op = value["$op"].as_str().unwrap();
            assert!(ops.iter().any(|allowed| allowed == op));
            if matches!(op, "set" | "add" | "remove") {
                assert!(value.get("value").is_some());
            }
        }
    }

    #[test]
    fn spec_event_schema_lists_client_write_kinds() {
        let schema_text = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../contrix-spec/spec/v1/artifacts/schemas/event-schema.json"),
        )
        .unwrap();
        for kind in [
            "cx.account_data.set",
            "cx.flow.update",
            "cx.flow.tracks.update",
            // R1.7 rename: former `cx.place.create` is the container
            // `cx.space.create`.
            "cx.space.create",
        ] {
            assert!(
                schema_text.contains(&format!("\"{kind}\"")),
                "event-schema artifact must list client write kind {kind}"
            );
        }
    }

    #[test]
    fn canonical_digest_is_stable_across_key_order() {
        let mut op_a = OperationBuilder::new("cx:space:s1", "did:web:alice", "cx.message.create")
            .body(json!({"b": 2, "a": 1}))
            .build("node");
        op_a.event_id = "fixed".into();
        op_a.hlc = "000000000000-0000-00000000".into();
        op_a.actor_seq = 1;

        let mut op_b = op_a.clone();
        op_b.payload = json!({"a": 1, "b": 2});

        assert_eq!(
            op_a.canonical_digest().unwrap(),
            op_b.canonical_digest().unwrap()
        );
    }

    #[test]
    fn sign_ed25519_attaches_typed_proof() {
        use ed25519_dalek::SigningKey;
        let mut op = OperationBuilder::new("cx:space:s1", "did:web:alice", "cx.message.create")
            .body(json!({"body": "hi"}))
            .build("node");
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        op.sign_ed25519("did:web:alice", "did:web:alice#k1", &signing_key)
            .expect("sign ok");
        let proof = op.proofs.first().expect("proof present");
        assert_eq!(proof.alg, "EdDSA");
        assert_eq!(proof.verification_method, "did:web:alice#k1");
        assert!(proof.payload_hash.starts_with("sha256:"));
        // JWS layout: header.. (detached) ..sig — 3 parts separated by '.'.
        assert_eq!(proof.jws.matches('.').count(), 2);
        assert!(op.require_proof().is_ok());
    }

    #[test]
    fn require_proof_fails_when_unsigned() {
        let mut op = OperationBuilder::new("cx:space:s1", "did:web:alice", "cx.message.create")
            .body(json!({"body": "hi"}))
            .build("node");
        op.proofs.clear();
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
        assert_eq!(create.kind, "cx.invite.create");
        assert_eq!(create.payload["invite_id"], "cx:invite:test");

        let accept =
            cx_ops::invite_accept("cx:space:test", "did:web:bob.example", "cx:invite:test")
                .build("node");
        assert_eq!(accept.kind, "cx.invite.accept");

        let cancel = cx_ops::invite_cancel(
            "cx:space:test",
            "did:web:alice.example",
            "cx:invite:test",
            Some("expired"),
        )
        .build("node");
        assert_eq!(cancel.kind, "cx.invite.cancel");
        assert_eq!(cancel.payload["reason"], "expired");
    }

    #[test]
    fn space_lifecycle_helpers_emit_canonical_kinds() {
        let container_space_id = "cx:space:01904100-0000-7000-8000-1fb50799ad42";
        let archive = cx_ops::space_archive(
            "cx:realm:01904100-0000-7000-8000-1fb50799ad40",
            "did:web:alice.example",
            container_space_id,
        )
        .build("node");
        assert_eq!(archive.kind, "cx.space.archive");
        assert_eq!(archive.payload["space_id"], container_space_id);
        assert!(archive.payload.get("place_id").is_none());
        assert_eq!(archive.local_target_ref(), Some(container_space_id));

        let restore = cx_ops::space_restore(
            "cx:realm:01904100-0000-7000-8000-1fb50799ad40",
            "did:web:alice.example",
            container_space_id,
        )
        .build("node");
        assert_eq!(restore.kind, "cx.space.restore");
        assert_eq!(restore.payload["space_id"], container_space_id);
        assert!(restore.payload.get("place_id").is_none());
        assert_eq!(restore.local_target_ref(), Some(container_space_id));
    }

    #[test]
    fn flow_lifecycle_helpers_emit_canonical_kinds() {
        let flow_id = "cx:flow:01904100-0000-7000-8000-1fb50799ad50";
        let archive =
            cx_ops::flow_archive("cx:space:test", "did:web:alice.example", flow_id).build("node");
        assert_eq!(archive.kind, "cx.flow.archive");
        assert_eq!(archive.payload["flow_id"], flow_id);
        assert_eq!(archive.local_target_ref(), Some(flow_id));

        let restore =
            cx_ops::flow_restore("cx:space:test", "did:web:alice.example", flow_id).build("node");
        assert_eq!(restore.kind, "cx.flow.restore");
        assert_eq!(restore.payload["flow_id"], flow_id);
        assert_eq!(restore.local_target_ref(), Some(flow_id));
    }

    /// Pin the canonical op_type + target_ref + body shape for every
    /// `cx.applet.*` builder so server-side validators (soland operation
    /// requirements) keep accepting them.
    #[test]
    fn applet_helpers_emit_canonical_kinds_and_target_refs() {
        let service_did = "did:web:applet.example";
        let session_id = "cx:session:01904100-0000-7000-8000-aa55aa55aa55";
        let space = "cx:space:test";
        let actor = "did:web:alice.example";

        let reg = cx_ops::applet_registration(space, actor, service_did, "extensions", &["read"])
            .build("node");
        assert_eq!(reg.kind, "cx.applet.registration");
        assert_eq!(reg.payload["service_did"], service_did);
        assert_eq!(reg.payload["namespace"], "extensions");
        assert_eq!(reg.payload["capabilities"][0], "read");
        assert_eq!(reg.local_target_ref(), Some(service_did));

        let disc = cx_ops::applet_discovery(space, actor, service_did, json!({"version": 1}))
            .build("node");
        assert_eq!(disc.kind, "cx.applet.discovery");
        assert_eq!(disc.payload["manifest"]["version"], 1);
        assert_eq!(disc.local_target_ref(), Some(service_did));

        let start = cx_ops::applet_protocol_session_start(
            space,
            actor,
            "cx:applet:dummy",
            session_id,
            json!({"op": "ping"}),
        )
        .build("node");
        assert_eq!(start.kind, "cx.applet.protocol_session.start");
        assert_eq!(start.payload["session_id"], session_id);
        assert_eq!(start.local_target_ref(), Some(session_id));

        let status = cx_ops::applet_protocol_session_status(
            space,
            actor,
            session_id,
            "running",
            json!({"progress": 0.5}),
        )
        .build("node");
        assert_eq!(status.kind, "cx.applet.protocol_session.status");
        assert_eq!(status.payload["status"], "running");

        let err = cx_ops::applet_bridge_error(
            space,
            actor,
            session_id,
            "applet_unavailable",
            "service did not respond",
        )
        .build("node");
        assert_eq!(err.kind, "cx.applet.bridge_error");
        assert_eq!(err.payload["error_code"], "applet_unavailable");
    }

    /// Same pinning at the agent layer.
    #[test]
    fn agent_helpers_emit_canonical_kinds_and_target_refs() {
        let agent = "did:web:researcher.agent.example";
        let session_id = "cx:session:01904100-0000-7000-8000-bb66bb66bb66";
        let space = "cx:space:test";
        let actor = "did:web:alice.example";

        let endpoint = cx_ops::agent_endpoint(space, actor, agent, "cx.agent.v1", &["flow.read"])
            .build("node");
        assert_eq!(endpoint.kind, "cx.agent.endpoint");
        assert_eq!(endpoint.payload["protocol"], "cx.agent.v1");
        assert_eq!(endpoint.local_target_ref(), Some(agent));

        let start = cx_ops::agent_protocol_session_start(
            space,
            actor,
            agent,
            session_id,
            json!({"query": "summarize"}),
            json!({"grant_id": "cap-1"}),
        )
        .build("node");
        assert_eq!(start.kind, "cx.agent.protocol_session.start");
        assert_eq!(start.payload["agent_did"], agent);
        assert_eq!(start.payload["capability_proof"]["grant_id"], "cap-1");

        let status =
            cx_ops::agent_protocol_session_status(space, actor, session_id, "thinking", json!({}))
                .build("node");
        assert_eq!(status.kind, "cx.agent.protocol_session.status");

        let result = cx_ops::agent_protocol_session_result(
            space,
            actor,
            session_id,
            json!({"summary": "TL;DR"}),
            json!({"merkle_root": "sha256:abc"}),
        )
        .build("node");
        assert_eq!(result.kind, "cx.agent.protocol_session.result");
        assert_eq!(result.payload["audit_binding"]["merkle_root"], "sha256:abc");
    }
}
