//! Typed v1 Event Envelope used by yougen's active write paths.
//!
//! Spec source of truth: `cokret-spec/spec/v1/artifacts/schemas/event-envelope.schema.json`.
//!
//! # Signing
//!
//! All envelopes are produced with `proofs: Vec::new()`. The detached JWS
//! proof is attached exclusively by [`crate::event_signer::sign_with_active`]
//! from inside [`crate::api::CokretApi::submit_event_envelope`]. There is
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

pub(crate) fn trim_realm_id(value: &str) -> String {
    value.trim().to_owned()
}

/// Typed semantic reference per spec `event-envelope.schema.json $defs/semantic_ref`.
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

/// Typed inclusion-proof body per spec `event-envelope.schema.json $defs/semantic_ref.proof`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub kind: String,
    pub leaf_hash: String,
    pub audit_path: Vec<String>,
    pub leaf_index: u64,
    pub tree_size: u64,
}

/// Typed precondition per spec `event-envelope.schema.json $defs/precondition`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Precondition {
    pub cell: String,
    pub predicate: Predicate,
}

/// Typed predicate per spec `event-envelope.schema.json $defs/predicate`.
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

/// Typed effect per spec `event-envelope.schema.json $defs/effect`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Effect {
    pub cell: String,
    pub op: LatticeOp,
}

/// Typed lattice op per spec `event-envelope.schema.json $defs/lattice_op`.
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

/// Typed envelope requirements block per spec `event-envelope.schema.json
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

/// Typed critical-extension declaration per spec `event-envelope.schema.json
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
/// Field names match the wire JSON exactly per spec `event-envelope.schema.json` —
/// no serde renames. `preconditions` / `effects` / `anchor_ref` are
/// `Option<Vec<...>>` / `Option<String>` because reducer-input event kinds
/// require them and non-reducer kinds (read marker, account_data, ...)
/// must omit them entirely.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope {
    pub event_id: String,
    pub kind: String,
    pub realm_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<Value>,
    pub actor_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_kind: Option<String>,
    pub actor_seq: u64,
    pub created_at: String,
    pub hlc: String,
    #[serde(default)]
    pub prev_refs: Vec<String>,
    #[serde(default)]
    pub refs: Vec<SemanticRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preconditions: Vec<Precondition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effects: Vec<Effect>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacts: Option<String>,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unsigned: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<EventProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirements: Option<EventRequirements>,
}

/// Detached proof entry on an [`EventEnvelope`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventProof {
    pub kind: String,
    pub alg: String,
    pub verification_method: String,
    pub event_digest: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<EventProofAudience>,
    pub jws: String,
}

/// EventProof `audience` accepts the v1 scalar and multi-audience shapes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventProofAudience {
    Single(String),
    Multiple(Vec<String>),
}

impl EventProofAudience {
    pub fn single(value: impl Into<String>) -> Self {
        Self::Single(value.into())
    }

    pub fn multiple(values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::Multiple(values.into_iter().map(Into::into).collect())
    }
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
    executed_by: Option<String>,
    authorization_ref: Option<String>,
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
            executed_by: None,
            authorization_ref: None,
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

    pub fn executed_by(mut self, executed_by: impl Into<String>) -> Self {
        self.executed_by = Some(executed_by.into());
        self
    }

    pub fn authorization_ref(mut self, authorization_ref: impl Into<String>) -> Self {
        self.authorization_ref = Some(authorization_ref.into());
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
        // Normalize the wire `realm_id` field without accepting alternate
        // protocol namespaces.
        let realm_id = trim_realm_id(&self.realm_id);
        EventEnvelope {
            event_id: format!("ck:event:{}", uuid_v7()),
            kind: self.op_type,
            realm_id,
            effective_scope: None,
            actor_id: self.actor,
            executed_by: self.executed_by,
            authorization_ref: self.authorization_ref,
            actor_kind: None,
            actor_seq,
            created_at: crate::clock::now_rfc3339_secs(),
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
            proof.event_digest = digest.clone();
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
        use std::sync::Arc;

        use cokret_sdk::signatures::proof::Ed25519DetachedJwsSigner;

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
    if operation_id.starts_with("ck:operation:") {
        operation_id.to_owned()
    } else {
        format!("ck:operation:{operation_id}")
    }
}

/// Generate a canonical UUIDv7 string for typed protocol identifiers.
///
/// Thin wrapper over the SDK's `new_prefixed_uuid7` (RFC 9562 UUIDv7 via the
/// `uuid` crate, with same-millisecond monotonicity) called with an empty
/// prefix. Callers add their own typed prefix (`ck:operation:`, `ck:device:`,
/// etc.). Replaces the previous hand-rolled bit-packing helper, which had no
/// same-millisecond monotonic guarantee.
pub fn uuid_v7() -> String {
    cokret_sdk::identifiers::new_prefixed_uuid7("")
}

/// Canonical helper constructors used by the current UI.
pub mod ck_ops {
    use serde_json::{Value, json};

    use super::{OperationBuilder, trim_realm_id};

    // YOU-02-001: every fallible helper below returns `anyhow::Result`
    // instead of panicking. The ids these helpers parse ultimately come from
    // server sync data (bare `String` fields in `models.rs` flow into local
    // UI state), so a non-canonical id from a buggy or malicious server must
    // surface as a recoverable error — on wasm a panic kills the whole page.

    fn did_id(value: &str) -> anyhow::Result<cokret_sdk::Did> {
        cokret_sdk::Did::new(value.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid DID {value:?}: {err:?}"))
    }

    /// Build a spec `invite_payload` (invite_id-ref anyOf branch) value for
    /// `ck.invite.accept` / `ck.invite.cancel` via the SDK strong type.
    fn invite_ref_payload_value(invite_id: &str, reason: Option<&str>) -> anyhow::Result<Value> {
        let invite_id_typed = cokret_sdk::InviteId::new(invite_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invite_id not canonical {invite_id:?}: {err}"))?;
        let mut payload = cokret_sdk::model::InviteRefPayload::new(invite_id_typed);
        if let Some(reason) = reason {
            payload = payload.with_reason(reason);
        }
        payload
            .to_value()
            .map_err(|err| anyhow::anyhow!("invite ref payload: {err}"))
    }

    fn realm_id_value(value: &str) -> anyhow::Result<cokret_sdk::RealmId> {
        cokret_sdk::RealmId::new(value.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid realm id {value:?}: {err:?}"))
    }

    fn space_id_value(value: &str) -> anyhow::Result<cokret_sdk::SpaceId> {
        cokret_sdk::SpaceId::new(value.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid space id {value:?}: {err:?}"))
    }

    fn circle_id_value(value: &str) -> anyhow::Result<cokret_sdk::CircleId> {
        cokret_sdk::CircleId::new(value.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid circle id {value:?}: {err:?}"))
    }

    fn flow_id_value(value: &str) -> anyhow::Result<cokret_sdk::FlowId> {
        cokret_sdk::FlowId::new(value.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid flow id {value:?}: {err:?}"))
    }

    fn morph_id_value(value: &str) -> anyhow::Result<cokret_sdk::MorphId> {
        cokret_sdk::MorphId::new(value.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid morph id {value:?}: {err:?}"))
    }

    fn sdk_payload_value(result: cokret_sdk::Result<Value>, context: &str) -> anyhow::Result<Value> {
        result.map_err(|err| anyhow::anyhow!("{context}: {err}"))
    }

    fn object_create_payload_value<T: serde::Serialize>(
        object: T,
        context: &str,
    ) -> anyhow::Result<Value> {
        sdk_payload_value(
            cokret_sdk::ObjectCreatePayload::new(object).to_value(),
            context,
        )
    }

    fn object_patch_payload_value(
        object_ref: &str,
        patch: cokret_sdk::Patch,
    ) -> anyhow::Result<Value> {
        cokret_sdk::ObjectPatchPayload::for_target(object_ref, patch)
            .and_then(|payload| payload.to_value())
            .map_err(|err| {
                anyhow::anyhow!("invalid object_patch_payload for {object_ref}: {err}")
            })
    }

    fn flow_object_patch_payload_value(
        flow_id: &str,
        patch: cokret_sdk::Patch,
    ) -> anyhow::Result<Value> {
        object_patch_payload_value(flow_id, patch)
    }

    fn flow_tracks_update_payload_value(
        flow_id: &str,
        patch: cokret_sdk::Patch,
    ) -> anyhow::Result<Value> {
        cokret_sdk::FlowPatchPayload::for_flow(flow_id_value(flow_id)?, patch)
            .and_then(|payload| payload.to_value())
            .map_err(|err| {
                anyhow::anyhow!("invalid ck.flow.tracks.update payload for {flow_id}: {err}")
            })
    }

    fn flow_watch_level_value(level: &str) -> anyhow::Result<cokret_sdk::FlowWatchLevel> {
        match level {
            "mentions_only" => Ok(cokret_sdk::FlowWatchLevel::MentionsOnly),
            "participating" => Ok(cokret_sdk::FlowWatchLevel::Participating),
            "all" => Ok(cokret_sdk::FlowWatchLevel::All),
            "muted" => Ok(cokret_sdk::FlowWatchLevel::Muted),
            other => Err(anyhow::anyhow!("unknown ck.flow.watch.set level {other:?}")),
        }
    }

    /// Build the canonical `flow_watch_set_payload` body via the SDK strong
    /// type. `level=None` clears the cell (`level:null`); per the schema
    /// `allOf`, the typed constructor forces `level_public` off on that path.
    fn flow_watch_set_payload_value(
        flow_id: &str,
        watcher_actor_id: &str,
        level: Option<&str>,
        level_public: Option<bool>,
    ) -> anyhow::Result<Value> {
        let payload = match level {
            Some(level) => cokret_sdk::FlowWatchSetPayload::set(
                flow_id_value(flow_id)?,
                did_id(watcher_actor_id)?,
                flow_watch_level_value(level)?,
                level_public,
            ),
            None => cokret_sdk::FlowWatchSetPayload::clear(
                flow_id_value(flow_id)?,
                did_id(watcher_actor_id)?,
            ),
        };
        payload
            .to_value()
            .map_err(|err| anyhow::anyhow!("invalid flow_watch_set_payload for {flow_id}: {err}"))
    }

    /// Build the canonical `flow_move_payload` body via the SDK strong type.
    /// `additionalProperties:false` — the destination is single-sourced by
    /// `target_space_id`; the optional `from_space_id` / `expected_position`
    /// (space_id + rank) are CAS hints.
    fn flow_move_payload_value(
        board_space_id: &str,
        flow_id: &str,
        target_space_id: &str,
        rank: &str,
        from_space_id: Option<&str>,
        expected: Option<(Option<&str>, Option<&str>)>,
    ) -> anyhow::Result<Value> {
        let mut payload = cokret_sdk::FlowMovePayload::new(
            space_id_value(board_space_id)?,
            flow_id_value(flow_id)?,
            space_id_value(target_space_id)?,
            rank.to_owned(),
        );
        if let Some(from) = from_space_id {
            payload = payload.with_from_space_id(space_id_value(from)?);
        }
        if let Some((expected_space, expected_rank)) = expected {
            payload = payload.with_expected_position(cokret_sdk::FlowMoveExpectedPosition {
                space_id: expected_space.map(space_id_value).transpose()?,
                rank: expected_rank.map(ToOwned::to_owned),
                relation_id: None,
            });
        }
        payload
            .to_value()
            .map_err(|err| anyhow::anyhow!("invalid flow_move_payload for {flow_id}: {err}"))
    }

    /// Build the canonical `flow_reorder_payload` body via the SDK strong
    /// type. Re-ranks within a single List Space (`space_id`); the optional
    /// `expected_position` carries only a rank (no space_id field).
    fn flow_reorder_payload_value(
        board_space_id: &str,
        flow_id: &str,
        space_id: &str,
        rank: &str,
        expected_rank: Option<&str>,
    ) -> anyhow::Result<Value> {
        let mut payload = cokret_sdk::FlowReorderPayload::new(
            space_id_value(board_space_id)?,
            flow_id_value(flow_id)?,
            space_id_value(space_id)?,
            rank.to_owned(),
        );
        if let Some(expected_rank) = expected_rank {
            payload = payload.with_expected_position(cokret_sdk::FlowReorderExpectedPosition {
                rank: Some(expected_rank.to_owned()),
                relation_id: None,
            });
        }
        payload
            .to_value()
            .map_err(|err| anyhow::anyhow!("invalid flow_reorder_payload for {flow_id}: {err}"))
    }

    /// Build the canonical `object_lifecycle_payload` body via the SDK strong
    /// type. Single truth source `target_ref` (`additionalProperties:false`).
    fn object_lifecycle_payload_value(target_ref: &str) -> anyhow::Result<Value> {
        cokret_sdk::ObjectLifecyclePayload::new(target_ref.to_owned())
            .to_value()
            .map_err(|err| {
                anyhow::anyhow!("invalid object_lifecycle_payload for {target_ref}: {err}")
            })
    }

    /// Build the canonical `relation_create_payload` body (flat
    /// `{kind, from_ref, to_ref}` form) via the SDK strong type. The
    /// schema is `additionalProperties:false`, so any legacy
    /// `relation_id` / `scope_circle_id` / `fields` keys are dropped:
    /// the relation id is routed via the operation `target_ref`, and the
    /// extra annotation fields were never spec-legal (they tripped
    /// `schema_violation`).
    fn relation_create_payload_value(
        kind: &str,
        from_ref: &str,
        to_ref: &str,
    ) -> anyhow::Result<Value> {
        cokret_sdk::RelationCreatePayload::new(kind, from_ref.to_owned(), to_ref.to_owned())
            .to_value()
            .map_err(|err| {
                anyhow::anyhow!(
                    "invalid relation_create_payload ({kind} {from_ref}->{to_ref}): {err}"
                )
            })
    }

    fn patch_set(path: &str, value: Value) -> anyhow::Result<cokret_sdk::Patch> {
        let mut patch = cokret_sdk::Patch::new();
        patch
            .insert_op(path, cokret_sdk::PatchOp::set(value))
            .map_err(|err| anyhow::anyhow!("invalid ck.patch.v1 path {path:?}: {err}"))?;
        Ok(patch)
    }

    fn patch_from_value(patch: Value) -> anyhow::Result<cokret_sdk::Patch> {
        let patch: cokret_sdk::Patch = serde_json::from_value(patch).map_err(|err| {
            anyhow::anyhow!("ck.flow.update patch must match ck.patch.v1: {err}")
        })?;
        patch.validate().map_err(|err| {
            anyhow::anyhow!("ck.flow.update patch must match ck.patch.v1: {err}")
        })?;
        Ok(patch)
    }

    /// Build a canonical `ck.flow.create` discussion operation with the full
    /// typed Flow payload expected by the current reducers.
    ///
    /// The full Flow lives under the spec-canonical `object` key —
    /// see soland `routing/events/operations.rs::FLOW_CREATE_REQUIREMENTS`
    /// and SDK `crates/core/src/schema/payloads.rs` which both gate
    /// `ck.flow.create` on `payload.object`.
    pub fn discussion_flow_create(
        realm_id: &str,
        actor: &str,
        flow_id: &str,
        title: &str,
    ) -> anyhow::Result<OperationBuilder> {
        let typed_realm_id = cokret_sdk::RealmId::new(trim_realm_id(realm_id))
            .map_err(|e| anyhow::anyhow!("invalid realm_id: {e:?}"))?;
        let did = cokret_sdk::Did::new(actor.to_owned())
            .map_err(|e| anyhow::anyhow!("invalid actor DID: {e:?}"))?;
        let typed_flow_id = cokret_sdk::FlowId::new(flow_id.to_owned())
            .map_err(|e| anyhow::anyhow!("invalid flow_id: {e:?}"))?;
        let flow = cokret_sdk::FlowCreateObject::new(typed_flow_id, typed_realm_id, did)
            .with_metadata_title(title)
            .with_track(
                "discussion",
                cokret_sdk::FlowTrackConfig::discussion_primary(),
            );
        let payload = cokret_sdk::ObjectCreatePayload::new(flow)
            .to_value()
            .map_err(|e| anyhow::anyhow!("ck.flow.create payload serialize: {e}"))?;
        Ok(OperationBuilder::new(realm_id, actor, "ck.flow.create")
            .target_ref(flow_id)
            .body(payload))
    }

    /// Build a canonical `ck.circle.create` operation for a private
    /// discussion scope inside `realm_id`.
    pub fn discussion_circle_create(
        realm_id: &str,
        actor: &str,
        circle_id: &str,
        title: &str,
    ) -> anyhow::Result<OperationBuilder> {
        let display = cokret_sdk::CircleDisplay {
            short_name: title.trim().chars().take(16).collect::<String>(),
            color_token: cokret_sdk::CircleColorToken::Indigo,
            symbol: cokret_sdk::CircleSymbol::Glyph {
                glyph: cokret_sdk::CircleGlyph::Lock,
            },
        };
        let circle = cokret_sdk::Circle::new(
            circle_id_value(circle_id)?,
            realm_id_value(&trim_realm_id(realm_id))?,
            title.trim(),
            display,
            did_id(actor)?,
        );
        let body = object_create_payload_value(circle, "ck.circle.create payload serialize")?;
        Ok(OperationBuilder::new(realm_id, actor, "ck.circle.create")
            .target_ref(circle_id)
            .body(body))
    }

    /// Build a `ck.flow.create` operation whose full Flow scope is a
    /// private discussion Circle.
    pub fn scoped_discussion_flow_create(
        realm_id: &str,
        actor: &str,
        flow_id: &str,
        circle_id: &str,
        title: &str,
    ) -> anyhow::Result<OperationBuilder> {
        let typed_realm_id = cokret_sdk::RealmId::new(trim_realm_id(realm_id))
            .map_err(|e| anyhow::anyhow!("invalid realm_id: {e:?}"))?;
        let did = cokret_sdk::Did::new(actor.to_owned())
            .map_err(|e| anyhow::anyhow!("invalid actor DID: {e:?}"))?;
        let typed_flow_id = cokret_sdk::FlowId::new(flow_id.to_owned())
            .map_err(|e| anyhow::anyhow!("invalid flow_id: {e:?}"))?;
        let mut flow = cokret_sdk::FlowCreateObject::new(typed_flow_id, typed_realm_id, did)
            .with_metadata_title(title)
            .with_track(
                "discussion",
                cokret_sdk::FlowTrackConfig::discussion_primary(),
            );
        flow.scope_circle_id = Some(circle_id_value(circle_id)?);
        let payload = cokret_sdk::ObjectCreatePayload::new(flow)
            .to_value()
            .map_err(|e| anyhow::anyhow!("ck.flow.create payload serialize: {e}"))?;
        Ok(OperationBuilder::new(realm_id, actor, "ck.flow.create")
            .target_ref(flow_id)
            .body(payload))
    }

    /// Build the private-side relation from a Circle-scoped discussion Flow
    /// back to the public anchor Flow/message.
    pub fn confidential_discussion_relation_create(
        realm_id: &str,
        actor: &str,
        private_flow_id: &str,
        public_anchor_ref: &str,
        circle_id: &str,
    ) -> anyhow::Result<OperationBuilder> {
        // `circle_id` is unused on the wire: relation_create_payload is
        // additionalProperties:false and the private-side scope is already
        // carried by the Circle-scoped Flow itself.
        let _ = circle_id;
        Ok(OperationBuilder::new(realm_id, actor, "ck.relation.create")
            .target_ref(private_flow_id)
            .body(relation_create_payload_value(
                "confidential_discussion_of",
                private_flow_id,
                public_anchor_ref,
            )?))
    }

    /// Build a `ck.flow.watch.set` operation. Spec:
    /// `cokret-spec/spec/v1/zh/models/flow-and-message.md §8.3` —
    /// writes the cas-register cell `ck.component.flow.watch.v1` keyed by
    /// `(flow_id, watcher_actor_id)`.
    ///
    /// `level` is one of `mentions_only` / `participating` / `all` / `muted`,
    /// or `None` to clear the cell (equivalent to `mentions_only` default).
    /// `level_public` is the opt-in flag from §8.5 — when `true`, projection
    /// to non-self viewers does not strip the level value (but `muted` still
    /// stays invisible). Caller MUST omit `level_public` when `level` is None.
    ///
    /// Default reducer invariant: `target_actor` MUST equal `sender_actor`
    /// unless the sender holds `ck.flow.watch.set.others`. Callers
    /// helping someone else subscribe (e.g. Flow creator seeding
    /// watchers on create) need that capability.
    pub fn flow_watch_set(
        realm_id: &str,
        sender_actor: &str,
        target_actor_id: &str,
        flow_id: &str,
        level: Option<&str>,
        level_public: Option<bool>,
    ) -> anyhow::Result<OperationBuilder> {
        // Strong type: flow_watch_set_payload (additionalProperties:false +
        // allOf forbidding level_public when level is null). The typed
        // constructors keep the clear path (level:null) free of level_public.
        let payload = flow_watch_set_payload_value(flow_id, target_actor_id, level, level_public)?;
        Ok(OperationBuilder::new(realm_id, sender_actor, "ck.flow.watch.set")
            .target_ref(flow_id)
            .body(payload))
    }

    /// Build a `ck.flow.tracks.update` operation. Spec:
    /// `cokret-spec/spec/v1/zh/models/flow-and-message.md §3` (post dc01ad7).
    ///
    /// This is the single unified track-mutation event that replaces
    /// `ck.flow.track.{enable,disable,update,set_primary}`.
    /// `patch` is a `ck.patch.v1` JSON Patch object against the `Flow.tracks`
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
        realm_id: &str,
        actor: &str,
        flow_id: &str,
        patch: serde_json::Value,
    ) -> anyhow::Result<OperationBuilder> {
        let patch = patch_from_value(patch)?;
        Ok(OperationBuilder::new(realm_id, actor, "ck.flow.tracks.update")
            .target_ref(flow_id)
            .body(flow_tracks_update_payload_value(flow_id, patch)?))
    }

    /// Convenience wrapper: enable `track` on `flow_id`. Emits the unified
    /// `ck.flow.tracks.update` event with a `ck.patch.v1` set-op against
    /// `tracks.<name>.enabled`.
    pub fn flow_tracks_update_enable(
        realm_id: &str,
        actor: &str,
        flow_id: &str,
        track: &str,
    ) -> anyhow::Result<OperationBuilder> {
        let key = format!("tracks.{track}.enabled");
        let patch = json!({ key: { "$op": "set", "value": true } });
        flow_tracks_update(realm_id, actor, flow_id, patch)
    }

    /// Convenience wrapper: disable `track` on `flow_id`.
    pub fn flow_tracks_update_disable(
        realm_id: &str,
        actor: &str,
        flow_id: &str,
        track: &str,
    ) -> anyhow::Result<OperationBuilder> {
        let key = format!("tracks.{track}.enabled");
        let patch = json!({ key: { "$op": "set", "value": false } });
        flow_tracks_update(realm_id, actor, flow_id, patch)
    }

    /// Convenience wrapper: mark `track` as the Flow's primary track.
    /// Carries a single set-op against `tracks.<name>.is_primary`. The reducer
    /// is responsible for clearing the previous primary cell.
    pub fn flow_tracks_update_set_primary(
        realm_id: &str,
        actor: &str,
        flow_id: &str,
        track: &str,
    ) -> anyhow::Result<OperationBuilder> {
        let key = format!("tracks.{track}.is_primary");
        let patch = json!({ key: { "$op": "set", "value": true } });
        flow_tracks_update(realm_id, actor, flow_id, patch)
    }

    /// Build a `ck.space.create` operation for Board/List container Spaces.
    ///
    /// Board/List containers are Space objects and the security boundary is
    /// Realm. The optional
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
    ) -> anyhow::Result<OperationBuilder> {
        let mut object = cokret_sdk::SpaceCreateObject::new(
            space_id_value(container_space_id)?,
            realm_id_value(&trim_realm_id(realm_id))?,
            kind,
            title,
            did_id(actor)?,
        );
        if let Some(parent_space_id) = parent_space_id {
            object.parent_space_id = Some(space_id_value(parent_space_id)?);
        }
        if let Some(rank) = rank {
            object.rank = Some(rank.to_owned());
        }
        let body = object_create_payload_value(object, "ck.space.create payload serialize")?;
        Ok(OperationBuilder::new(realm_id, actor, "ck.space.create")
            .target_ref(container_space_id)
            .body(body))
    }

    /// Build a `ck.morph.create` for a document Morph.
    pub fn document_morph_create(
        realm_id: &str,
        actor: &str,
        morph_id: &str,
        title: &str,
        document_body: serde_json::Value,
    ) -> anyhow::Result<OperationBuilder> {
        let realm_id = trim_realm_id(realm_id);
        let object = cokret_sdk::MorphCreateObject::new(
            morph_id_value(morph_id)?,
            realm_id_value(&realm_id)?,
            "document",
            did_id(actor)?,
        )
        .with_title(title)
        .with_facet("documentable", json!({}))
        .with_field("document", document_body);
        Ok(OperationBuilder::new(&realm_id, actor, "ck.morph.create")
            .target_ref(morph_id)
            .body(sdk_payload_value(
                object.to_create_payload_value(),
                "ck.morph.create document payload serialize",
            )?))
    }

    /// Build a `ck.flow.create` for an incident response Flow. The
    /// common incident workflow status is carried in `fields.status` so
    /// soland can enforce the profile FSM and emit
    /// `incident.status.transition` audit rows on subsequent updates.
    pub fn incident_flow_create(
        realm_id: &str,
        actor: &str,
        flow_id: &str,
        title: &str,
        status: &str,
        priority: &str,
    ) -> anyhow::Result<OperationBuilder> {
        let realm_id = trim_realm_id(realm_id);
        let object = cokret_sdk::FlowCreateObject::new(
            flow_id_value(flow_id)?,
            realm_id_value(&realm_id)?,
            did_id(actor)?,
        )
        .with_metadata_title(title)
        .with_metadata_field("flow_kind", json!("incident"))
        .with_metadata_field("status", json!(status))
        .with_metadata_field("incident_priority", json!(priority))
        .with_track(
            "synthesis",
            cokret_sdk::FlowTrackConfig::new()
                .primary()
                .with_profile("incident_response"),
        )
        .with_track(
            "discussion",
            cokret_sdk::FlowTrackConfig::new().with_profile("war_room"),
        );
        Ok(OperationBuilder::new(&realm_id, actor, "ck.flow.create")
            .target_ref(flow_id)
            .body(object_create_payload_value(
                object,
                "ck.flow.create incident payload serialize",
            )?))
    }

    /// Build a `ck.flow.update` for the incident `fields.status` FSM.
    pub fn incident_status_update(
        realm_id: &str,
        actor: &str,
        flow_id: &str,
        status: &str,
    ) -> anyhow::Result<OperationBuilder> {
        flow_update_patch(
            realm_id,
            actor,
            flow_id,
            json!({ "fields": { "$op": "set", "value": { "status": status } } }),
        )
    }

    /// Build a `ck.flow.create` for a Kanban card Flow and include the
    /// initial Board/List position component used by board projections.
    pub fn kanban_card_flow_create(
        realm_id: &str,
        actor: &str,
        flow_id: &str,
        board_space_id: &str,
        list_space_id: &str,
        title: &str,
        rank: &str,
    ) -> anyhow::Result<OperationBuilder> {
        let realm_id = trim_realm_id(realm_id);
        let object = cokret_sdk::FlowCreateObject::new(
            flow_id_value(flow_id)?,
            realm_id_value(&realm_id)?,
            did_id(actor)?,
        )
        .with_metadata_title(title)
        .with_metadata_field("flow_kind", json!("card"))
        .with_metadata_field("board_space_id", json!(board_space_id))
        .with_metadata_field("list_space_id", json!(list_space_id))
        .with_metadata_field("rank", json!(rank))
        .with_track(
            "synthesis",
            cokret_sdk::FlowTrackConfig::new()
                .primary()
                .with_profile("kanban_card"),
        );
        Ok(OperationBuilder::new(&realm_id, actor, "ck.flow.create")
            .target_ref(flow_id)
            .body(object_create_payload_value(
                object,
                "ck.flow.create kanban card payload serialize",
            )?))
    }

    /// Build a `ck.morph.update` carrying a new document body.
    pub fn document_morph_update(
        realm_id: &str,
        actor: &str,
        morph_id: &str,
        document_body: serde_json::Value,
    ) -> anyhow::Result<OperationBuilder> {
        morph_update_patch(
            realm_id,
            actor,
            morph_id,
            json!({
                "fields": {
                    "$op": "set",
                    "value": {
                        "document": document_body
                    }
                }
            }),
        )
    }

    /// Build a range-anchored document comment as `ck.message.create`.
    pub fn document_comment_create(
        realm_id: &str,
        actor: &str,
        morph_id: &str,
        start: u32,
        end: u32,
        body: &str,
        reply_to: Option<&str>,
    ) -> anyhow::Result<OperationBuilder> {
        let realm_id = trim_realm_id(realm_id);
        let discussion_flow_id = realm_id
            .strip_prefix("ck:realm:")
            .map(|suffix| format!("ck:flow:{suffix}"))
            .unwrap_or_else(|| morph_id.to_owned());
        let content = cokret_sdk::ContentBlock::text(body)
            .with_field(
                "anchor_range",
                json!({
                    "end": end,
                    "start": start,
                    "target_ref": morph_id
                }),
            )
            .with_field("morph_id", json!(morph_id));
        let mut payload = cokret_sdk::MessageCreatePayload::with_content(
            flow_id_value(&discussion_flow_id)?,
            "discussion",
            sdk_payload_value(content.to_value(), "document comment content serialize")?,
        );
        if let Some(parent) = reply_to.map(str::trim).filter(|value| !value.is_empty()) {
            payload = payload.with_reply_to(parent);
        }
        Ok(OperationBuilder::new(&realm_id, actor, "ck.message.create")
            .target_ref(morph_id)
            .body(sdk_payload_value(
                payload.to_value(),
                "ck.message.create document comment payload serialize",
            )?))
    }

    /// Build a Relation linking a document Morph to another object.
    pub fn document_relation_create(
        realm_id: &str,
        actor: &str,
        morph_id: &str,
        target_ref: &str,
    ) -> anyhow::Result<OperationBuilder> {
        Ok(OperationBuilder::new(realm_id, actor, "ck.relation.create")
            .target_ref(morph_id)
            .body(relation_create_payload_value(
                "references",
                morph_id,
                target_ref,
            )?))
    }

    /// Build a schema-legal `ck.relation.create` event. The Relation id is
    /// server-normalized from the accepted event id; payload keeps only the
    /// v1 `kind` / `from_ref` / `to_ref` endpoints.
    pub fn relation_create(
        realm_id: &str,
        actor: &str,
        kind: &str,
        from_ref: &str,
        to_ref: &str,
    ) -> anyhow::Result<OperationBuilder> {
        Ok(OperationBuilder::new(realm_id, actor, "ck.relation.create")
            .target_ref(from_ref)
            .body(relation_create_payload_value(kind, from_ref, to_ref)?))
    }

    /// Build a `ck.relation.tombstone` event targeting an existing Relation.
    pub fn relation_tombstone(realm_id: &str, actor: &str, relation_id: &str) -> OperationBuilder {
        OperationBuilder::new(realm_id, actor, "ck.relation.tombstone")
            .target_ref(relation_id)
            .body(json!({ "relation_id": relation_id }))
    }

    /// Build a `ck.flow.update` delta operation using the canonical
    /// `ck.patch.v1` payload shape. Non-create Flow updates should carry
    /// only changed fields; callers are responsible for composing patch paths
    /// that are valid for the Flow schema/profile.
    pub fn flow_update_patch(
        realm_id: &str,
        actor: &str,
        flow_id: &str,
        patch: serde_json::Value,
    ) -> anyhow::Result<OperationBuilder> {
        let patch = patch_from_value(patch)?;
        Ok(OperationBuilder::new(realm_id, actor, "ck.flow.update")
            .target_ref(flow_id)
            .body(flow_object_patch_payload_value(flow_id, patch)?))
    }

    /// Build a `ck.morph.update` patch operation. Mirrors
    /// [`flow_update_patch`] for Morph objects; soland's
    /// `apply_morph_update` reducer accepts `payload.patch` with the
    /// standard `ck.schema.patch.v1` shape.
    pub fn morph_update_patch(
        realm_id: &str,
        actor: &str,
        morph_id: &str,
        patch: serde_json::Value,
    ) -> anyhow::Result<OperationBuilder> {
        let patch = patch_from_value(patch)?;
        Ok(OperationBuilder::new(realm_id, actor, "ck.morph.update")
            .target_ref(morph_id)
            .body(object_patch_payload_value(morph_id, patch)?))
    }

    // YOU-01-011: the former `ck.policy.update` / `ck.actor_profile.update`
    // builders were removed — neither kind is in the spec
    // event-kind-registry, and unregistered wire kinds must not be mintable
    // from client code. Re-add once the kinds are registered via CKP.

    /// Build a `ck.message.revise` patch operation. Spec: revise is
    /// supposed to carry `payload.patch` like the other `*.update`
    /// events. Soland today accepts both the legacy full-content
    /// shape and the new patch shape (additive). New clients SHOULD
    /// emit patches; legacy clients sending `{content: <full body>}`
    /// keep working.
    pub fn message_revise_patch(
        realm_id: &str,
        actor: &str,
        message_id: &str,
        patch: serde_json::Value,
    ) -> OperationBuilder {
        OperationBuilder::new(realm_id, actor, "ck.message.revise")
            .target_ref(message_id)
            .body(json!({
                "message_id": message_id,
                "patch": patch,
            }))
    }

    /// Build a `ck.realm.update` patch operation. The reducer accepts
    /// both flat fields (action/owner/title/security_class) and
    /// `payload.patch`; the patch shape is preferred for non-lifecycle
    /// edits (title / description).
    pub fn realm_update_patch(
        envelope_realm_id: &str,
        actor: &str,
        realm_id: &str,
        patch: serde_json::Value,
    ) -> anyhow::Result<OperationBuilder> {
        let patch = patch_from_value(patch)?;
        Ok(OperationBuilder::new(envelope_realm_id, actor, "ck.realm.update")
            .target_ref(realm_id)
            .body(object_patch_payload_value(realm_id, patch)?))
    }

    /// Build a `ck.space.update` patch operation for structural Space
    /// metadata (`title`, `summary`, `rank`, `fields`, ...). The event lives
    /// in the Space's home Realm; `space_id` stays as the object target.
    pub fn space_update_patch(
        realm_id: &str,
        actor: &str,
        space_id: &str,
        patch: serde_json::Value,
    ) -> anyhow::Result<OperationBuilder> {
        let patch = patch_from_value(patch)?;
        Ok(OperationBuilder::new(realm_id, actor, "ck.space.update")
            .target_ref(space_id)
            .body(object_patch_payload_value(space_id, patch)?))
    }

    // YOU-01-011: the former `ck.moderation.report.submit` builder was
    // removed — the kind is not in the spec event-kind-registry (the
    // registered reporting surface is `ck.self.moderation.report` over
    // the HTTP path via `api::Client::report_moderation`). Re-add only
    // if an event-stream report kind is registered via CKP.

    /// Build a `ck.moderation.appeal.submit` operation. Mirrors the
    /// 4-state moderation appeal FSM. The wire body is the strong SDK
    /// [`cokret_sdk::AppealSubmitPayload`] (`ck.schema.moderation_appeal.v1`)
    /// rather than a hand-rolled `json!{}` — malformed ids fail at build time.
    /// (The live UI path is [`crate::views::moderation_appeal::build_appeal_submit_op`];
    /// this is the generic operation-builder form.)
    #[allow(clippy::too_many_arguments)]
    pub fn moderation_appeal_submit(
        envelope_realm_id: &str,
        actor: &str,
        appeal_id: &str,
        realm_id: &str,
        decision_ref: &str,
        target_ref: &str,
        reason_text_ref: &str,
        evidence_refs: Vec<String>,
        evidence_visibility: Option<&str>,
    ) -> anyhow::Result<OperationBuilder> {
        let evidence_visibility = evidence_visibility
            .map(|raw| {
                serde_json::from_value::<cokret_sdk::AppealEvidenceVisibility>(json!(raw))
                    .map_err(|err| anyhow::anyhow!("invalid evidence_visibility {raw:?}: {err}"))
            })
            .transpose()?;
        let payload = cokret_sdk::AppealSubmitPayload {
            appeal_id: cokret_sdk::TypedAppealId::new(appeal_id)
                .map_err(|err| anyhow::anyhow!("invalid appeal_id: {err}"))?,
            realm_id: cokret_sdk::RealmId::new(realm_id.to_owned())
                .map_err(|err| anyhow::anyhow!("invalid realm_id: {err}"))?,
            decision_ref: cokret_sdk::EventId::new(decision_ref)
                .map_err(|err| anyhow::anyhow!("invalid decision_ref: {err}"))?,
            target_ref: target_ref.to_owned(),
            appellant: cokret_sdk::Did::new(actor)
                .map_err(|err| anyhow::anyhow!("invalid appellant did: {err}"))?,
            reason_text_ref: reason_text_ref.to_owned(),
            evidence_refs,
            evidence_visibility,
            created_at: chrono::Utc::now(),
        };
        cokret_sdk::ModerationAppealPayload::Submit(payload.clone()).validate_minimal()?;
        Ok(
            OperationBuilder::new(envelope_realm_id, actor, "ck.moderation.appeal.submit")
                .target_ref(appeal_id)
                .body(serde_json::to_value(&payload)?),
        )
    }

    pub fn invite_create_structured(
        realm_id: &str,
        actor: &str,
        invite_id: &str,
        invitee: &str,
        role: Option<&str>,
        invite_delivery_target: cokret_sdk::InviteDeliveryTarget,
        introduction_evidence_digest: &str,
    ) -> anyhow::Result<OperationBuilder> {
        // Strong `invite_payload` (directed-create anyOf branch). The id /
        // digest strings are parsed into SDK newtypes so malformed wire is a
        // build-time error, and `x_role` is carried via the typed extension
        // map (re-prefixed on serialize).
        let invite_id_typed = cokret_sdk::InviteId::new(invite_id.to_owned())
            .map_err(|err| anyhow::anyhow!("invite_id not canonical {invite_id:?}: {err}"))?;
        let invitee_did = cokret_sdk::Did::new(invitee.to_owned())
            .map_err(|err| anyhow::anyhow!("invitee not a DID {invitee:?}: {err}"))?;
        let digest = cokret_sdk::Hash::new(introduction_evidence_digest.to_owned())
            .map_err(|err| anyhow::anyhow!("introduction_evidence_digest invalid: {err}"))?;
        let mut payload = cokret_sdk::model::InviteCreatePayload::new(
            invite_id_typed,
            invitee_did,
            invite_delivery_target,
            digest,
            chrono::Utc::now() + chrono::Duration::days(7),
        );
        if let Some(role) = role {
            payload = payload.with_extension("role", json!(role));
        }
        let body = payload
            .to_value()
            .map_err(|err| anyhow::anyhow!("invite create payload: {err}"))?;
        Ok(OperationBuilder::new(realm_id, actor, "ck.invite.create").body(body))
    }

    pub fn invite_accept(
        realm_id: &str,
        actor: &str,
        invite_id: &str,
    ) -> anyhow::Result<OperationBuilder> {
        let body = invite_ref_payload_value(invite_id, None)?;
        Ok(OperationBuilder::new(realm_id, actor, "ck.invite.accept")
            .target_ref(invite_id)
            .body(body))
    }

    pub fn invite_cancel(
        realm_id: &str,
        actor: &str,
        invite_id: &str,
        reason: Option<&str>,
    ) -> anyhow::Result<OperationBuilder> {
        let body = invite_ref_payload_value(invite_id, reason)?;
        Ok(OperationBuilder::new(realm_id, actor, "ck.invite.cancel")
            .target_ref(invite_id)
            .body(body))
    }

    /// Build a `ck.space.archive` operation against a container Space. The
    /// Space transitions from `Active` to `Archived`; reversible via
    /// [`space_restore`]. Spec: `models/realm-and-space.md` §4.4. The wire
    /// payload uses canonical `space_id` (no legacy alias).
    pub fn realm_archive(
        realm_id: &str,
        actor: &str,
        container_space_id: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(realm_id, actor, "ck.space.archive")
            .target_ref(container_space_id)
            .body(json!({ "space_id": container_space_id }))
    }

    /// Build a `ck.space.restore` operation. Reverses [`realm_archive`]
    /// (`archived -> active`). The SDK reducer enforces `state == archived`
    /// at apply time; tombstoned container Spaces MUST NOT be restored. Spec:
    /// `models/realm-and-space.md` §4.4, `common-fields.md §5`.
    pub fn space_restore(
        realm_id: &str,
        actor: &str,
        container_space_id: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(realm_id, actor, "ck.space.restore")
            .target_ref(container_space_id)
            .body(json!({ "space_id": container_space_id }))
    }

    /// Build a `ck.flow.archive` operation. Spec: `flow-and-message.md §3`
    /// and `common-fields.md §5.1`; payload shape is the
    /// `object_lifecycle_payload` from
    /// `artifacts/schemas/event-payload.schema.json`, which requires
    /// `target_ref`. SDK reducer rejects with
    /// `flow_not_active` when source state is not `active`.
    pub fn flow_archive(
        realm_id: &str,
        actor: &str,
        flow_id: &str,
    ) -> anyhow::Result<OperationBuilder> {
        Ok(OperationBuilder::new(realm_id, actor, "ck.flow.archive")
            .target_ref(flow_id)
            .body(object_lifecycle_payload_value(flow_id)?))
    }

    /// Build a `ck.flow.restore` operation. Reverses [`flow_archive`]
    /// (`archived -> active`). SDK reducer rejects with `flow_not_archived`
    /// when source state is not `archived`. Payload shape mirrors the
    /// archive op (spec `object_lifecycle_payload`).
    pub fn flow_restore(
        realm_id: &str,
        actor: &str,
        flow_id: &str,
    ) -> anyhow::Result<OperationBuilder> {
        Ok(OperationBuilder::new(realm_id, actor, "ck.flow.restore")
            .target_ref(flow_id)
            .body(object_lifecycle_payload_value(flow_id)?))
    }

    // ── Consent (OrSet cell `ck.component.consent.grant.v1`) ─────────

    /// `ck.consent.grant` event. Spec: events.submit applies this to the
    /// `ck.component.consent.grant.v1` OrSet cell as an add op with `tag`.
    pub fn consent_grant(
        realm_id: &str,
        actor: &str,
        consent_id: &str,
        tag: &str,
    ) -> OperationBuilder {
        OperationBuilder::new(realm_id, actor, "ck.consent.grant")
            .target_ref(consent_id)
            .body(json!({
                "consent_id": consent_id,
                "tag": tag,
            }))
    }

    /// `ck.consent.revoke` event with required `observed_dots` (round 4
    /// wire). Pass an empty slice only for non-causal revoke.
    pub fn consent_revoke(
        realm_id: &str,
        actor: &str,
        consent_id: &str,
        tag: &str,
        reason: Option<&str>,
        observed_dots: &[cokret_sdk::Dot],
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
        OperationBuilder::new(realm_id, actor, "ck.consent.revoke")
            .target_ref(consent_id)
            .body(body)
    }

    // ── Capability (OrSet cell `ck.component.capability.grant.v1`) ───

    /// `ck.capability.grant` event with optional structured constraints
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
        OperationBuilder::new(realm_id, actor, "ck.capability.grant")
            .target_ref(grant_id)
            .body(body)
    }

    /// `ck.capability.revoke` event. `reason` shows up in the audit
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
        OperationBuilder::new(realm_id, actor, "ck.capability.revoke")
            .target_ref(grant_id)
            .body(body)
    }

    // ── MLS epoch (per-Realm group ratchet) ─────────────────────────

    /// `ck.mls.commit` event carrying the current wire-schema MLS
    /// governance binding. The commit bytes themselves are stored out of
    /// band; the event carries `commit_digest` plus the schema-closed
    /// epoch and governance binding fields soland validates before
    /// projection.
    pub fn mls_commit_with_governance(
        realm_id: &str,
        actor: &str,
        payload: &cokret_sdk::MlsCommitPayload,
    ) -> anyhow::Result<OperationBuilder> {
        let group_id = payload.mls_group_id().to_owned();
        let body = serde_json::to_value(payload)?;
        Ok(OperationBuilder::new(realm_id, actor, "ck.mls.commit")
            .target_ref(group_id)
            .body(body))
    }

    /// `ck.mls.genesis` event installing an MLS group at epoch 0. Emitted
    /// once when a creator's local group is first observed by the server so
    /// the canonical audit record + creator/covered_frontier seed exist and
    /// the server epoch starts in lockstep with the local snapshot before
    /// the first `ck.mls.commit` bumps it to 1.
    ///
    /// `payload` is the full canonical `mls_genesis_payload` Value (see
    /// [`crate::mls::runtime::build_mls_genesis_payload`]); `group_id` is the
    /// genesis target ref.
    pub fn mls_genesis_with_governance(
        realm_id: &str,
        actor: &str,
        group_id: &str,
        payload: &Value,
    ) -> OperationBuilder {
        OperationBuilder::new(realm_id, actor, "ck.mls.genesis")
            .target_ref(group_id.to_owned())
            .body(payload.clone())
    }

    // YOU-01-011: the former `ck.conflict.repair` builder (admin
    // conflict-repair Move) was removed — the kind is absent from the
    // spec event-kind-registry and from the spec text entirely, so the
    // client must not mint it. Re-add once a repair kind is registered
    // via CKP.

    /// `ck.realm.update` patch event on the organization cell. Mirrors the
    /// Realm organization update Move shape (name /
    /// topic / description / etc.). Pass the merge patch as `value`.
    pub fn realm_organization_update(
        realm_id: &str,
        actor: &str,
        value: Value,
    ) -> anyhow::Result<OperationBuilder> {
        let patch = patch_from_value(value)?;
        Ok(OperationBuilder::new(realm_id, actor, "ck.realm.update")
            .target_ref(realm_id)
            .body(object_patch_payload_value(realm_id, patch)?))
    }

    /// Legacy flow position update (kanban card position).
    ///
    /// Current protocol writes new position changes through
    /// `ck.flow.move` / `ck.flow.reorder`; this helper remains for old
    /// local drafts that still carry a generic `position` object, but it
    /// still emits the canonical `object_patch_payload` shape.
    pub fn flow_position_update(
        realm_id: &str,
        actor: &str,
        flow_id: &str,
        position_value: Value,
    ) -> anyhow::Result<OperationBuilder> {
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
    ) -> anyhow::Result<OperationBuilder> {
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
            let payload =
                flow_object_patch_payload_value(flow_id, patch_set("position", effect_position)?)?;
            return Ok(OperationBuilder::new(realm_id, actor, "ck.flow.update")
                .target_ref(flow_id)
                .body(payload));
        };
        let Some(effect_rank) = effect_rank else {
            let payload =
                flow_object_patch_payload_value(flow_id, patch_set("position", effect_position)?)?;
            return Ok(OperationBuilder::new(realm_id, actor, "ck.flow.update")
                .target_ref(flow_id)
                .body(payload));
        };

        // Strong types: flow_reorder_payload / flow_move_payload
        // (additionalProperties:false). The reorder path stays within a
        // single List Space (effect_space == space_id); the move path treats
        // effect_space as the destination target_space_id and carries the
        // optional from_space_id / expected_position CAS hints.
        match kind {
            "ck.flow.reorder" => {
                let payload = flow_reorder_payload_value(
                    board_space_id,
                    flow_id,
                    &effect_space,
                    &effect_rank,
                    expected_rank.as_deref(),
                )?;
                Ok(OperationBuilder::new(realm_id, actor, "ck.flow.reorder")
                    .target_ref(flow_id)
                    .body(payload))
            }
            _ => {
                // expected_position is only emitted when BOTH a prior
                // space_id and rank are known (matches the legacy guard).
                let expected = match (expected_space.as_deref(), expected_rank.as_deref()) {
                    (Some(space), Some(rank)) => Some((Some(space), Some(rank))),
                    _ => None,
                };
                let payload = flow_move_payload_value(
                    board_space_id,
                    flow_id,
                    &effect_space,
                    &effect_rank,
                    expected_space.as_deref(),
                    expected,
                )?;
                Ok(OperationBuilder::new(realm_id, actor, "ck.flow.move")
                    .target_ref(flow_id)
                    .body(payload))
            }
        }
    }

    // ── Applet protocol family ────────────────────────────────────────
    //
    // Spec: `extensions/applet-integration.md` + canonical event-kind
    // registry rows `ck.applet.registration` / `ck.applet.discovery` /
    // `ck.applet.interop_session.{start,status}` / `ck.applet.bridge_error`.
    //
    // The builders below produce the wire shape soland validators and the
    // SDK reducer consume. Each carries the canonical `applet_id` (or
    // `service_did` for registration / discovery) as `target_ref` so
    // soland's `target-ref-required` envelope-shape check passes.

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
    pub fn parse_applet_identifier(
        applet_id: &str,
    ) -> Result<cokret_sdk::AppletIdentifier, String> {
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

    /// Round 4 — validate an `agent_id` against the canonical
    /// [`cokret_sdk::AgentId`] shape (strict DID). Wire-breaking: the
    /// pre-round-4 permissive plain-string form is rejected.
    pub fn parse_agent_identifier(agent_id: &str) -> Result<cokret_sdk::AgentId, String> {
        cokret_sdk::Did::new(agent_id).map_err(|e| format!("invalid agent DID: {e}"))
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

    // ── Agent protocol family ─────────────────────────────────────────
    //
    // Spec: `extensions/agent-integration.md` + canonical event-kind
    // registry rows `ck.agent.endpoint` / `ck.agent.interop_session.
    // {start,status,result}`. Agents are server-side delegates a member
    // grants narrow capabilities to (e.g. a read-flow Researcher Agent);
    // the wire shape lets soland and the SDK reducer track which agent
    // owns which session, what status, and what result.

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
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::{Value, json};

    use super::*;

    fn spec_schema(name: &str) -> serde_json::Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../cokret-spec/spec/v1/artifacts/schemas")
            .join(name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read spec schema {}: {err}", path.display()));
        serde_json::from_str(&text).unwrap_or_else(|err| {
            panic!("parse spec schema {}: {err}", path.display());
        })
    }

    fn assert_registered_payload_valid(event: &EventEnvelope) {
        let catalog = cokret_sdk::schema::event_payload_validator_catalog();
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

    fn required_fields(schema: &serde_json::Value) -> Vec<String> {
        schema
            .get("required")
            .and_then(serde_json::Value::as_array)
            .unwrap_or_else(|| panic!("schema missing required[]"))
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect()
    }

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
        let op = OperationBuilder::new("ck:realm:test", "did:web:alice", "ck.message.create")
            .body(json!({"content": {"kind": "ck.content.text", "body": "hello"}}))
            .build("test_node");

        assert!(!op.local_operation_id().is_empty());
        assert_eq!(op.realm_id, "ck:realm:test");
        assert_eq!(op.actor_id, "did:web:alice");
        assert_eq!(op.kind, "ck.message.create");
        assert!(!op.hlc.is_empty());
        assert!(op.actor_seq > 0);
        // Spec compliance: build() never attaches a placeholder proof —
        // the submit path requires an installed signer.
        assert!(op.proofs.is_empty());
    }

    #[test]
    fn operation_round_trip_serde() {
        let op = OperationBuilder::new("ck:realm:s1", "did:web:bob", "ck.message.create")
            .body(json!({"content": {"kind": "ck.content.text", "body": "hello world"}}))
            .build("node");
        let json = serde_json::to_string(&op).unwrap();
        let parsed: EventEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(op, parsed);
    }

    #[test]
    fn operation_builder_can_emit_signed_authorization_binding() {
        let op = OperationBuilder::new("ck:realm:s1", "did:web:bob", "ck.message.create")
            .body(json!({"content": {"kind": "ck.content.text", "body": "hello world"}}))
            .executed_by("did:web:agent.example")
            .authorization_ref("ck:grant:0196419b-0000-7000-8000-000000000001")
            .build("node");

        assert_eq!(op.executed_by.as_deref(), Some("did:web:agent.example"));
        assert_eq!(
            op.authorization_ref.as_deref(),
            Some("ck:grant:0196419b-0000-7000-8000-000000000001")
        );
        assert!(op.unsigned.get("local_authz_ref").is_none());

        let mut canonical = serde_json::to_value(&op).unwrap();
        if let serde_json::Value::Object(object) = &mut canonical {
            object.remove("proofs");
            object.remove("unsigned");
        }
        assert_eq!(canonical["executed_by"], "did:web:agent.example");
        assert_eq!(
            canonical["authorization_ref"],
            "ck:grant:0196419b-0000-7000-8000-000000000001"
        );
    }

    #[test]
    fn event_envelope_accepts_current_optional_top_level_fields() {
        let op = OperationBuilder::new("ck:realm:s1", "did:web:bob", "ck.message.create")
            .body(json!({"content": {"kind": "ck.content.text", "body": "hello world"}}))
            .build("node");
        let mut value = serde_json::to_value(&op).unwrap();
        let object = value.as_object_mut().unwrap();
        object.insert(
            "effective_scope".to_owned(),
            json!({"kind": "realm", "realm_id": "ck:realm:s1"}),
        );
        object.insert("executed_by".to_owned(), json!("did:web:agent.example"));
        object.insert(
            "authorization_ref".to_owned(),
            json!("ck:grant:0196419b-0000-7000-8000-000000000001"),
        );
        object.insert("actor_kind".to_owned(), json!("agent"));

        let parsed: EventEnvelope = serde_json::from_value(value).unwrap();
        assert_eq!(
            parsed.effective_scope,
            Some(json!({"kind": "realm", "realm_id": "ck:realm:s1"}))
        );
        assert_eq!(parsed.executed_by.as_deref(), Some("did:web:agent.example"));
        assert_eq!(
            parsed.authorization_ref.as_deref(),
            Some("ck:grant:0196419b-0000-7000-8000-000000000001")
        );
        assert_eq!(parsed.actor_kind.as_deref(), Some("agent"));
    }

    #[test]
    fn event_envelope_rejects_unknown_top_level_fields() {
        let op = OperationBuilder::new("ck:realm:s1", "did:web:bob", "ck.message.create")
            .body(json!({"content": {"kind": "ck.content.text", "body": "hello world"}}))
            .build("node");
        let mut value = serde_json::to_value(&op).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("sender".to_owned(), json!("did:web:legacy.example"));

        assert!(
            serde_json::from_value::<EventEnvelope>(value).is_err(),
            "deprecated/unknown top-level envelope fields must fail closed"
        );
    }

    #[test]
    fn document_morph_create_carries_document_body() {
        let op = ck_ops::document_morph_create(
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "ck:morph:0196419b-0000-7000-8000-000000000002",
            "Untitled Document",
            json!({"blocks": [{"id": "block-1", "kind": "Heading", "content": "Hi"}]}),
        ).expect("builds")
        .build("test_node");

        assert_eq!(op.kind, "ck.morph.create");
        assert_eq!(
            op.payload["object"]["id"],
            "ck:morph:0196419b-0000-7000-8000-000000000002"
        );
        assert!(op.payload.get("morph_id").is_none());
        assert_eq!(op.payload["object"]["morph_type"], "document");
        assert_eq!(
            op.payload["object"]["fields"]["document"]["blocks"][0]["kind"],
            "Heading"
        );
        assert!(op.payload["object"]["facets"]["documentable"].is_object());
        assert_registered_payload_valid(&op);
        assert_payload_field_names_are_soland_canonical(&op.payload);
    }

    #[test]
    fn kanban_card_flow_create_carries_position_in_metadata_fields() {
        let op = ck_ops::kanban_card_flow_create(
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "ck:flow:0196419b-0000-7000-8000-000000000004",
            "ck:space:0196419b-0000-7000-8000-000000000002",
            "ck:space:0196419b-0000-7000-8000-000000000003",
            "Move-backed card",
            "h1",
        ).expect("builds")
        .build("node");
        let flow_schema = spec_schema("flow.schema.json");

        assert_eq!(op.kind, "ck.flow.create");
        assert_eq!(op.realm_id, "ck:realm:0196419b-0000-7000-8000-000000000001");
        assert_eq!(
            op.payload["object"]["realm_id"],
            "ck:realm:0196419b-0000-7000-8000-000000000001"
        );
        assert_required_fields_present(&flow_schema, &op.payload["object"]);
        assert_eq!(
            op.payload["object"]["tracks"]["synthesis"]["profile"],
            "kanban_card"
        );
        assert_eq!(
            op.payload["object"]["metadata"]["fields"]["board_space_id"],
            "ck:space:0196419b-0000-7000-8000-000000000002"
        );
        assert_eq!(
            op.payload["object"]["metadata"]["fields"]["list_space_id"],
            "ck:space:0196419b-0000-7000-8000-000000000003"
        );
        assert_eq!(
            op.payload["object"]["metadata"]["title"],
            "Move-backed card"
        );
        assert!(op.payload["object"].get("fields").is_none());
        assert!(op.payload["object"].get("title").is_none());
        assert!(op.payload["object"].get("space_id").is_none());
        assert!(op.payload.get("components").is_none());
        assert!(op.payload.get("patch").is_none());
        assert_registered_payload_valid(&op);
        assert_payload_field_names_are_soland_canonical(&op.payload);
    }

    #[test]
    fn mls_commit_builder_matches_registered_payload_schema() {
        let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000001";
        let group_id = "ck:mls_group:kanban-test";
        let governance_binding = cokret_sdk::MlsGovernanceBindingPayload::realm(
            cokret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            group_id,
            0,
            1,
            vec![
                cokret_sdk::EventId::new(
                    "ck:event:0196419b-0000-7000-8000-000000000002".to_owned(),
                )
                .unwrap(),
            ],
            cokret_sdk::Hash::new(
                "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                    .to_owned(),
            )
            .unwrap(),
        )
        .unwrap();
        let payload = cokret_sdk::MlsCommitPayload::new(
            group_id,
            0,
            "ck:event:0196419b-0000-7000-8000-000000000001",
            Vec::new(),
            1,
            cokret_sdk::Hash::new(
                "sha256:7777777777777777777777777777777777777777777777777777777777777777"
                    .to_owned(),
            )
            .unwrap(),
            governance_binding,
        )
        .unwrap();
        let op = ck_ops::mls_commit_with_governance(realm_id, "did:web:alice.example", &payload)
            .unwrap()
            .build("node");

        assert_eq!(op.kind, "ck.mls.commit");
        assert!(op.payload.get("group_id").is_none());
        assert!(op.payload.get("preconditions").is_none());
        assert!(op.payload.get("effects").is_none());
        assert_registered_payload_valid(&op);
        assert_payload_field_names_are_soland_canonical(&op.payload);
    }

    #[test]
    fn document_morph_update_targets_existing_morph_id() {
        let op = ck_ops::document_morph_update(
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "ck:morph:0196419b-0000-7000-8000-000000000002",
            json!({"blocks": []}),
        ).expect("builds")
        .build("test_node");

        assert_eq!(op.kind, "ck.morph.update");
        assert_eq!(
            op.payload["target_ref"],
            "ck:morph:0196419b-0000-7000-8000-000000000002"
        );
        assert!(op.payload.get("morph_id").is_none());
        assert!(op.payload["patch"]["fields"]["value"]["document"]["blocks"].is_array());
        assert_registered_payload_valid(&op);
        assert_payload_field_names_are_soland_canonical(&op.payload);
    }

    #[test]
    fn document_comment_create_carries_anchor_range() {
        let op = ck_ops::document_comment_create(
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "ck:morph:0196419b-0000-7000-8000-000000000002",
            4,
            9,
            "needs detail",
            None,
        ).expect("builds")
        .build("test_node");

        assert_eq!(op.kind, "ck.message.create");
        assert_eq!(
            op.payload["content"]["morph_id"],
            "ck:morph:0196419b-0000-7000-8000-000000000002"
        );
        assert_eq!(op.payload["content"]["anchor_range"]["start"], 4);
        assert_eq!(op.payload["content"]["anchor_range"]["end"], 9);
        assert_registered_payload_valid(&op);
        assert_payload_field_names_are_soland_canonical(&op.payload);
    }

    #[test]
    fn incident_status_update_uses_schema_safe_fields_patch() {
        let flow_id = "ck:flow:0196419b-0000-7000-8000-000000000002";
        let op = ck_ops::incident_status_update(
            "ck:realm:0196419b-0000-7000-8000-000000000010",
            "did:web:alice.example",
            flow_id,
            "mitigated",
        ).expect("builds")
        .build("node");

        assert_eq!(op.kind, "ck.flow.update");
        assert_eq!(op.payload["target_ref"], flow_id);
        assert!(op.payload.get("flow_id").is_none());
        assert!(op.payload["patch"].get("fields.status").is_none());
        assert_eq!(
            op.payload["patch"]["fields"]["value"]["status"],
            "mitigated"
        );
        assert_registered_payload_valid(&op);
        assert_payload_field_names_are_soland_canonical(&op.payload);
    }

    #[test]
    fn discussion_flow_create_emits_discussion_track() {
        let op = ck_ops::discussion_flow_create(
            "ck:realm:0196419b-0000-7000-8000-000000000000",
            "did:web:alice.example",
            "ck:flow:0196419b-0000-7000-8000-000000000001",
            "Ops",
        )
        .unwrap()
        .build("node");
        assert_eq!(op.kind, "ck.flow.create");
        assert_eq!(
            op.payload["object"]["id"],
            "ck:flow:0196419b-0000-7000-8000-000000000001"
        );
        assert!(op.payload.get("flow_id").is_none());
        assert_eq!(
            op.payload["object"]["tracks"]["discussion"]["profile"],
            "discussion"
        );
        assert_eq!(
            op.payload["object"]["tracks"]["discussion"]["is_primary"],
            true
        );
        assert_eq!(op.payload["object"]["metadata"]["title"], "Ops");
        assert!(op.payload["object"].get("title").is_none());
        assert_registered_payload_valid(&op);
        assert!(op.payload["object"].get("kind").is_none());
    }

    #[test]
    fn flow_tracks_update_primary_uses_is_primary_patch_key() {
        let flow_id = "ck:flow:0196419b-0000-7000-8000-000000000001";
        let op = ck_ops::flow_tracks_update_set_primary(
            "ck:realm:0196419b-0000-7000-8000-000000000010",
            "did:web:alice.example",
            flow_id,
            "discussion",
        ).expect("builds")
        .build("node");
        assert_eq!(op.kind, "ck.flow.tracks.update");
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
        let flow_id = "ck:flow:0196419b-0000-7000-8000-000000000002";
        let op = ck_ops::flow_update_patch(
            "ck:realm:0196419b-0000-7000-8000-000000000010",
            "did:web:alice.example",
            flow_id,
            json!({
                "title": { "$op": "set", "value": "Launch checklist" },
                "fields.due_at": { "$op": "set", "value": "2026-05-20" },
            }),
        ).expect("builds")
        .build("node");
        assert_eq!(op.kind, "ck.flow.update");
        assert_eq!(op.local_target_ref(), Some(flow_id));
        assert_eq!(op.payload["target_ref"], flow_id);
        assert!(op.payload.get("flow_id").is_none());
        assert_eq!(op.payload["patch"]["title"]["value"], "Launch checklist");
        assert!(op.payload.get("fields").is_none());
    }

    #[test]
    fn flow_update_builders_match_registered_object_patch_schema() {
        let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000001";
        let actor = "did:web:alice.example";
        let flow_id = "ck:flow:0196419b-0000-7000-8000-000000000002";
        let board_space_id = "ck:space:0196419b-0000-7000-8000-000000000010";
        let list_space_id = "ck:space:0196419b-0000-7000-8000-000000000011";

        let events = [
            ck_ops::flow_update_patch(
                realm_id,
                actor,
                flow_id,
                json!({
                    "title": { "$op": "set", "value": "Launch checklist" },
                    "fields.due_at": { "$op": "set", "value": "2026-05-20" },
                }),
            ).expect("builds")
            .build("node"),
            ck_ops::flow_position_update(
                realm_id,
                actor,
                flow_id,
                json!({
                    "flow_id": flow_id,
                    "board_space_id": board_space_id,
                    "list_space_id": list_space_id,
                    "rank": "U",
                }),
            ).expect("builds")
            .build("node"),
            // Null effect_position triggers the legacy ck.flow.update fallback
            // inside flow_position_cas_update. It still must satisfy
            // object_patch_payload instead of leaking top-level `position`.
            ck_ops::flow_position_cas_update(
                realm_id,
                actor,
                "ck.flow.move",
                board_space_id,
                flow_id,
                json!({"list_space_id": list_space_id, "rank": "U"}),
                Value::Null,
            ).expect("builds")
            .build("node"),
        ];

        for event in &events {
            assert_eq!(event.kind, "ck.flow.update");
            assert!(event.payload.get("patch").is_some());
            assert_eq!(event.payload["target_ref"], flow_id);
            assert!(event.payload.get("flow_id").is_none());
            assert!(event.payload.get("fields").is_none());
            assert!(event.payload.get("position").is_none());
            assert!(event.payload.get("board_space_id").is_none());
            assert!(event.payload.get("expected_position").is_none());
            assert_registered_payload_valid(event);
        }
    }

    #[test]
    fn object_patch_family_builders_match_registered_payload_schema() {
        let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000001";
        let actor = "did:web:alice.example";
        let flow_id = "ck:flow:0196419b-0000-7000-8000-000000000002";
        let morph_id = "ck:morph:0196419b-0000-7000-8000-000000000003";
        let space_id = "ck:space:0196419b-0000-7000-8000-000000000004";

        let events = [
            ck_ops::flow_tracks_update_set_primary(realm_id, actor, flow_id, "discussion").expect("builds")
                .build("node"),
            ck_ops::morph_update_patch(
                realm_id,
                actor,
                morph_id,
                json!({ "title": { "$op": "set", "value": "Spec note" } }),
            ).expect("builds")
            .build("node"),
            ck_ops::realm_organization_update(
                realm_id,
                actor,
                json!({ "title": { "$op": "set", "value": "Engineering" } }),
            ).expect("builds")
            .build("node"),
            ck_ops::space_update_patch(
                realm_id,
                actor,
                space_id,
                json!({ "title": "Roadmap Board", "summary": "Q2 planning" }),
            ).expect("builds")
            .build("node"),
        ];

        for event in &events {
            assert!(event.payload.get("patch").is_some(), "{}", event.kind);
            if event.kind == "ck.flow.tracks.update" {
                assert_eq!(event.payload["flow_id"], flow_id);
                assert!(event.payload.get("target_ref").is_none(), "{}", event.kind);
            } else {
                assert!(event.payload.get("target_ref").is_some(), "{}", event.kind);
            }
            assert_registered_payload_valid(event);
        }
    }

    #[test]
    fn flow_position_cas_update_emits_canonical_move_payload() {
        let op = ck_ops::flow_position_cas_update(
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice",
            "ck.flow.move",
            "ck:space:0196419b-0000-7000-8000-000000000010",
            "ck:flow:0196419b-0000-7000-8000-000000000020",
            json!({
                "list_space_id": "ck:space:0196419b-0000-7000-8000-000000000030",
                "rank": "a1"
            }),
            json!({
                "list_space_id": "ck:space:0196419b-0000-7000-8000-000000000040",
                "rank": "b1"
            }),
        ).expect("builds")
        .build("node");

        assert_eq!(op.kind, "ck.flow.move");
        assert_eq!(
            op.payload["board_space_id"],
            "ck:space:0196419b-0000-7000-8000-000000000010"
        );
        assert_eq!(
            op.payload["target_space_id"],
            "ck:space:0196419b-0000-7000-8000-000000000040"
        );
        assert_eq!(op.payload["rank"], "b1");
        assert_eq!(
            op.payload["expected_position"]["space_id"],
            "ck:space:0196419b-0000-7000-8000-000000000030"
        );
        assert_eq!(op.payload["expected_position"]["rank"], "a1");
        assert!(op.payload.get("position").is_none());
    }

    #[test]
    fn flow_position_cas_update_emits_canonical_reorder_payload() {
        let op = ck_ops::flow_position_cas_update(
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice",
            "ck.flow.reorder",
            "ck:space:0196419b-0000-7000-8000-000000000010",
            "ck:flow:0196419b-0000-7000-8000-000000000020",
            json!({
                "list_space_id": "ck:space:0196419b-0000-7000-8000-000000000030",
                "rank": "a1"
            }),
            json!({
                "list_space_id": "ck:space:0196419b-0000-7000-8000-000000000030",
                "rank": "a2"
            }),
        ).expect("builds")
        .build("node");

        assert_eq!(op.kind, "ck.flow.reorder");
        assert_eq!(
            op.payload["board_space_id"],
            "ck:space:0196419b-0000-7000-8000-000000000010"
        );
        assert_eq!(
            op.payload["space_id"],
            "ck:space:0196419b-0000-7000-8000-000000000030"
        );
        assert_eq!(op.payload["rank"], "a2");
        assert_eq!(op.payload["expected_position"]["rank"], "a1");
        assert!(op.payload["expected_position"].get("space_id").is_none());
        assert!(op.payload.get("target_space_id").is_none());
        assert!(op.payload.get("position").is_none());
    }

    #[test]
    fn space_create_emits_canonical_space_object() {
        let op = ck_ops::space_create(
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice",
            "ck:space:0196419b-0000-7000-8000-000000000002",
            "list",
            "To Do",
            Some("ck:space:0196419b-0000-7000-8000-000000000003"),
            Some("U"),
        ).expect("builds")
        .build("node");
        assert_eq!(op.kind, "ck.space.create");
        assert_eq!(
            op.local_target_ref(),
            Some("ck:space:0196419b-0000-7000-8000-000000000002")
        );
        assert_eq!(op.payload["object"]["schema"], "ck.schema.space.v1");
        assert_eq!(
            op.payload["object"]["id"],
            "ck:space:0196419b-0000-7000-8000-000000000002"
        );
        assert_eq!(
            op.payload["object"]["realm_id"],
            "ck:realm:0196419b-0000-7000-8000-000000000001"
        );
        assert!(op.payload["object"].get("space_id").is_none());
        assert_eq!(op.payload["object"]["kind"], "list");
        assert_eq!(
            op.payload["object"]["parent_space_id"],
            "ck:space:0196419b-0000-7000-8000-000000000003"
        );
        assert_eq!(op.payload["object"]["rank"], "U");
        assert_eq!(op.payload["object"]["created_by"], "did:web:alice");
        let created_at = op.payload["object"]["created_at"].as_str().unwrap();
        assert_eq!(created_at.len(), 20);
        assert!(created_at.ends_with('Z'));
        assert!(!created_at.contains('.'));
    }

    #[test]
    fn spec_space_schema_accepts_client_space_create_payload_shape() {
        let schema = spec_schema("space.schema.json");
        let op = ck_ops::space_create(
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "ck:space:0196419b-0000-7000-8000-000000000002",
            "list",
            "To Do",
            Some("ck:space:0196419b-0000-7000-8000-000000000003"),
            Some("U"),
        ).expect("builds")
        .build("node");
        let object = &op.payload["object"];

        assert_eq!(object["schema"], schema["properties"]["schema"]["const"]);
        assert_eq!(
            object["realm_id"],
            "ck:realm:0196419b-0000-7000-8000-000000000001"
        );
        assert_eq!(op.kind, "ck.space.create");
        assert!(serde_json::to_string(&op).unwrap().contains("\"realm_id\""));
        assert!(!serde_json::to_string(&op).unwrap().contains("ck:list:"));
    }

    #[test]
    fn spec_patch_schema_accepts_client_flow_tracks_update_payload_shape() {
        let schema = spec_schema("patch.schema.json");
        let ops = patch_schema_ops(&schema);
        let op = ck_ops::flow_tracks_update_set_primary(
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "ck:flow:0196419b-0000-7000-8000-000000000004",
            "discussion",
        ).expect("builds")
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
        let op = ck_ops::flow_update_patch(
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "ck:flow:0196419b-0000-7000-8000-000000000004",
            json!({
                "metadata.title": { "$op": "set", "value": "Launch checklist" },
                "metadata.summary": { "$op": "set", "value": "Ship blockers only" },
                "metadata.fields.labels": { "$op": "set", "value": ["release", "ops"] },
                "metadata.fields.priority": { "$op": "set", "value": "high" },
                "metadata.fields.due_at": { "$op": "set", "value": "2026-05-20" },
            }),
        ).expect("builds")
        .build("node");
        let patch = op.payload["patch"].as_object().unwrap();

        assert!(!patch.is_empty());
        assert_eq!(op.kind, "ck.flow.update");
        assert!(patch.contains_key("metadata.title"));
        assert!(patch.contains_key("metadata.summary"));
        assert!(patch.contains_key("metadata.fields.labels"));
        assert!(patch.contains_key("metadata.fields.priority"));
        assert!(patch.contains_key("metadata.fields.due_at"));
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
                .join("../cokret-spec/spec/v1/artifacts/schemas/event-envelope.schema.json"),
        )
        .unwrap();
        for kind in [
            "ck.account_data.set",
            "ck.flow.update",
            "ck.flow.tracks.update",
            "ck.space.create",
        ] {
            assert!(
                schema_text.contains(&format!("\"{kind}\"")),
                "event-schema artifact must list client write kind {kind}"
            );
        }
    }

    #[test]
    fn canonical_digest_is_stable_across_key_order() {
        let mut op_a = OperationBuilder::new("ck:realm:s1", "did:web:alice", "ck.message.create")
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
        let mut op = OperationBuilder::new("ck:realm:s1", "did:web:alice", "ck.message.create")
            .body(json!({"body": "hi"}))
            .build("node");
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        op.sign_ed25519("did:web:alice", "did:web:alice#k1", &signing_key)
            .expect("sign ok");
        let proof = op.proofs.first().expect("proof present");
        assert_eq!(proof.alg, "EdDSA");
        assert_eq!(proof.verification_method, "did:web:alice#k1");
        assert!(proof.event_digest.starts_with("sha256:"));
        // JWS layout: header.. (detached) ..sig — 3 parts separated by '.'.
        assert_eq!(proof.jws.matches('.').count(), 2);
        assert!(op.require_proof().is_ok());
    }

    #[test]
    fn require_proof_fails_when_unsigned() {
        let mut op = OperationBuilder::new("ck:realm:s1", "did:web:alice", "ck.message.create")
            .body(json!({"body": "hi"}))
            .build("node");
        op.proofs.clear();
        assert!(op.require_proof().is_err());
    }

    #[test]
    fn invite_helpers_emit_canonical_kinds() {
        let invite_id = "ck:invite:01904100-0000-7000-8000-000000000001";
        let invite_delivery_target = cokret_sdk::InviteDeliveryTarget {
            recipient_service_did: cokret_sdk::Did::new("did:web:server.example").unwrap(),
            recipient_service_type: Some("principal_server".to_owned()),
        };
        let introduction_evidence_digest =
            crate::canonical::canonical_sha256(&json!({"kind": "explicit_address"})).unwrap();
        let create = ck_ops::invite_create_structured(
            "ck:realm:01904100-0000-7000-8000-000000000010",
            "did:web:alice.example",
            invite_id,
            "did:web:bob.example",
            Some("member"),
            invite_delivery_target.clone(),
            &introduction_evidence_digest,
        ).expect("builds")
        .build("node");
        assert_eq!(create.kind, "ck.invite.create");
        assert_eq!(create.payload["invite_id"], invite_id);
        assert_eq!(create.payload["invitee"], "did:web:bob.example");
        assert_eq!(
            create.payload["invite_delivery_target"],
            serde_json::to_value(invite_delivery_target).unwrap()
        );
        assert_eq!(
            create.payload["introduction_evidence_digest"],
            introduction_evidence_digest
        );
        assert!(
            cokret_sdk::canonical::validate_timestamp_canonical(
                create.payload["expires_at"].as_str().unwrap()
            )
            .is_ok()
        );
        assert_eq!(create.payload["x_role"], "member");
        assert!(
            create
                .payload
                .get("expires_at")
                .and_then(|value| value.as_str())
                .is_some()
        );
        assert!(create.payload.get("target").is_none());
        assert!(create.payload.get("role").is_none());
        assert!(create.payload.get("state").is_none());
        assert!(create.payload.get("x_member_delivery_binding").is_none());
        assert_registered_payload_valid(&create);

        let accept = ck_ops::invite_accept(
            "ck:realm:01904100-0000-7000-8000-000000000010",
            "did:web:bob.example",
            invite_id,
        ).expect("builds")
        .build("node");
        assert_eq!(accept.kind, "ck.invite.accept");
        assert_eq!(accept.payload["invite_id"], invite_id);
        assert!(accept.payload.get("state").is_none());
        assert_registered_payload_valid(&accept);

        let cancel = ck_ops::invite_cancel(
            "ck:realm:01904100-0000-7000-8000-000000000010",
            "did:web:alice.example",
            invite_id,
            Some("expired"),
        ).expect("builds")
        .build("node");
        assert_eq!(cancel.kind, "ck.invite.cancel");
        assert_eq!(cancel.payload["invite_id"], invite_id);
        assert_eq!(cancel.payload["reason"], "expired");
        assert!(cancel.payload.get("state").is_none());
        assert_registered_payload_valid(&cancel);
    }

    #[test]
    fn space_lifecycle_helpers_emit_canonical_kinds() {
        let container_space_id = "ck:space:01904100-0000-7000-8000-1fb50799ad42";
        let archive = ck_ops::realm_archive(
            "ck:realm:01904100-0000-7000-8000-1fb50799ad40",
            "did:web:alice.example",
            container_space_id,
        )
        .build("node");
        assert_eq!(archive.kind, "ck.space.archive");
        assert_eq!(archive.payload["space_id"], container_space_id);
        assert_eq!(archive.local_target_ref(), Some(container_space_id));

        let restore = ck_ops::space_restore(
            "ck:realm:01904100-0000-7000-8000-1fb50799ad40",
            "did:web:alice.example",
            container_space_id,
        )
        .build("node");
        assert_eq!(restore.kind, "ck.space.restore");
        assert_eq!(restore.payload["space_id"], container_space_id);
        assert_eq!(restore.local_target_ref(), Some(container_space_id));
    }

    #[test]
    fn flow_lifecycle_helpers_emit_canonical_kinds() {
        let flow_id = "ck:flow:01904100-0000-7000-8000-1fb50799ad50";
        let archive =
            ck_ops::flow_archive("ck:realm:test", "did:web:alice.example", flow_id).expect("builds").build("node");
        assert_eq!(archive.kind, "ck.flow.archive");
        assert_eq!(archive.payload["target_ref"], flow_id);
        assert!(archive.payload.get("flow_id").is_none());
        assert_eq!(archive.local_target_ref(), Some(flow_id));
        assert_registered_payload_valid(&archive);

        let restore =
            ck_ops::flow_restore("ck:realm:test", "did:web:alice.example", flow_id).expect("builds").build("node");
        assert_eq!(restore.kind, "ck.flow.restore");
        assert_eq!(restore.payload["target_ref"], flow_id);
        assert!(restore.payload.get("flow_id").is_none());
        assert_eq!(restore.local_target_ref(), Some(flow_id));
        assert_registered_payload_valid(&restore);
    }

    /// Pin the canonical op_type + target_ref + body shape for every
    /// `ck.applet.*` builder so server-side validators (soland operation
    /// requirements) keep accepting them.
    #[test]
    fn applet_helpers_emit_canonical_kinds_and_target_refs() {
        let service_did = "did:web:applet.example";
        let session_id = "ck:session:01904100-0000-7000-8000-aa55aa55aa55";
        let realm = "ck:realm:test";
        let actor = "did:web:alice.example";

        let reg = ck_ops::applet_registration(realm, actor, service_did, "extensions", &["read"])
            .build("node");
        assert_eq!(reg.kind, "ck.applet.registration");
        assert_eq!(reg.payload["service_did"], service_did);
        assert_eq!(reg.payload["namespace"], "extensions");
        assert_eq!(reg.payload["capabilities"][0], "read");
        assert_eq!(reg.local_target_ref(), Some(service_did));

        let disc = ck_ops::applet_discovery(realm, actor, service_did, json!({"version": 1}))
            .build("node");
        assert_eq!(disc.kind, "ck.applet.discovery");
        assert_eq!(disc.payload["manifest"]["version"], 1);
        assert_eq!(disc.local_target_ref(), Some(service_did));

        let start = ck_ops::applet_interop_session_start(
            realm,
            actor,
            "ck:applet:dummy",
            session_id,
            json!({"op": "ping"}),
        )
        .build("node");
        assert_eq!(start.kind, "ck.applet.interop_session.start");
        assert_eq!(start.payload["session_id"], session_id);
        assert_eq!(start.local_target_ref(), Some(session_id));

        let status = ck_ops::applet_interop_session_status(
            realm,
            actor,
            session_id,
            "running",
            json!({"progress": 0.5}),
        )
        .build("node");
        assert_eq!(status.kind, "ck.applet.interop_session.status");
        assert_eq!(status.payload["status"], "running");

        let err = ck_ops::applet_bridge_error(
            realm,
            actor,
            session_id,
            "applet_unavailable",
            "service did not respond",
        )
        .build("node");
        assert_eq!(err.kind, "ck.applet.bridge_error");
        assert_eq!(err.payload["error_code"], "applet_unavailable");
    }

    /// Same pinning at the agent layer.
    #[test]
    fn agent_helpers_emit_canonical_kinds_and_target_refs() {
        let agent = "did:web:researcher.agent.example";
        let session_id = "ck:session:01904100-0000-7000-8000-bb66bb66bb66";
        let realm = "ck:realm:test";
        let actor = "did:web:alice.example";

        let endpoint = ck_ops::agent_endpoint(realm, actor, agent, "ck.agent.v1", &["flow.read"])
            .build("node");
        assert_eq!(endpoint.kind, "ck.agent.endpoint");
        assert_eq!(endpoint.payload["endpoints"][0]["protocol"], "ck.agent.v1");
        assert_eq!(endpoint.local_target_ref(), Some(agent));

        let start = ck_ops::agent_interop_session_start(
            realm,
            actor,
            agent,
            session_id,
            "http_custom",
            json!({"query": "summarize"}),
            "ck:grant:01904100-0000-7000-8000-000000000099",
        )
        .build("node");
        assert_eq!(start.kind, "ck.agent.interop_session.start");
        assert_eq!(start.payload["counterparty_agent"], agent);
        assert_eq!(
            start.payload["capability_grant"],
            "ck:grant:01904100-0000-7000-8000-000000000099"
        );

        let status =
            ck_ops::agent_interop_session_status(realm, actor, session_id, "thinking", json!({}))
                .build("node");
        assert_eq!(status.kind, "ck.agent.interop_session.status");

        let result = ck_ops::agent_interop_session_result(
            realm,
            actor,
            session_id,
            json!({"summary": "TL;DR"}),
            json!({"merkle_root": "sha256:abc"}),
        )
        .build("node");
        assert_eq!(result.kind, "ck.agent.interop_session.result");
        assert_eq!(result.payload["audit_binding"]["merkle_root"], "sha256:abc");
    }
}
