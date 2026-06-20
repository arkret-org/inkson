//! Typed v1 Event Envelope used by yougen's active write paths.
//!
//! Spec source of truth: `cokret-spec/spec/v1/artifacts/schemas/event-envelope.schema.json`.
//!
//! # Signing
//!
//! All envelopes are produced with `proofs: Vec::new()`. The detached JWS
//! proof is attached through the SDK event signing path before submit. There is
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

/// Typed Control Move basis per spec `event-envelope.schema.json
/// $defs/seal_basis` — the accepted Seal view the author signed under.
/// Mint a single-leaf basis from the registered sourcing
/// (`events_frontier_realm_seal_view(realm).seal_basis()`); never
/// fabricate one (SPEC-SOL-003 resolution).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealBasis {
    pub leaves: Vec<String>,
    pub control_event_set_root: String,
    pub state_root: String,
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
/// no serde renames. `preconditions` / `effects` / `seal_ref` are
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
    pub seal_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_basis: Option<SealBasis>,
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
/// preconditions / effects / seal_ref / requirements after `new()`
/// and before `build_sdk_event()`; the SDK event submit path requires an active
/// signer to attach the detached JWS proof before going on the wire.
#[derive(Debug)]
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
    seal_ref: Option<String>,
    seal_basis: Option<SealBasis>,
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
            seal_ref: None,
            seal_basis: None,
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

    pub fn seal_ref(mut self, seal_ref: impl Into<String>) -> Self {
        self.seal_ref = Some(seal_ref.into());
        self
    }

    /// Control Move only — attach the signed `seal_basis` (mutually
    /// exclusive with `seal_ref` per the spec envelope schema).
    pub fn seal_basis(mut self, seal_basis: SealBasis) -> Self {
        self.seal_basis = Some(seal_basis);
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

    pub fn build_sdk_event(self, node_id: &str) -> anyhow::Result<cokret_sdk::Event> {
        self.build(node_id).to_sdk_event_for_submit()
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
            seal_ref: self.seal_ref,
            seal_basis: self.seal_basis,
            requirements: self.requirements,
            redacts: self.redacts,
            unsigned,
            proofs: Vec::new(),
        }
    }

    pub fn build_sdk_event_with_deps(
        self,
        node_id: &str,
        deps: Vec<String>,
    ) -> anyhow::Result<cokret_sdk::Event> {
        self.build_with_deps(node_id, deps)
            .to_sdk_event_for_submit()
    }
}

impl EventEnvelope {
    /// Decode this local builder envelope through the SDK's canonical Event
    /// model before it is allowed onto the HTTP wire.
    ///
    /// Yougen still builds envelopes with the local `OperationBuilder`, but
    /// soland owns the accepted submit structure. This conversion keeps the
    /// network boundary pinned to `cokret_sdk::Event` while the remaining
    /// builder migration happens behind it.
    pub fn to_sdk_event(&self) -> anyhow::Result<cokret_sdk::Event> {
        let mut value = serde_json::to_value(self)?;
        if let Value::Object(object) = &mut value {
            object
                .entry("proofs".to_owned())
                .or_insert_with(|| Value::Array(Vec::new()));
        }
        serde_json::from_value(value)
            .map_err(|err| anyhow::anyhow!("event does not match SDK Event wire model: {err}"))
    }

    pub fn to_sdk_event_for_submit(&self) -> anyhow::Result<cokret_sdk::Event> {
        let sdk_event = self.to_sdk_event()?;
        let local_digest = self.canonical_digest()?;
        let sdk_digest = sdk_event
            .event_digest()
            .map_err(|err| anyhow::anyhow!("SDK Event digest failed: {err}"))?;
        if local_digest != sdk_digest {
            anyhow::bail!(
                "event digest drift between yougen builder and SDK Event: local={local_digest}, sdk={sdk_digest}"
            );
        }
        for proof in &self.proofs {
            if proof.event_digest != sdk_digest {
                anyhow::bail!(
                    "event proof digest {} does not match SDK Event digest {sdk_digest}",
                    proof.event_digest
                );
            }
        }
        Ok(sdk_event)
    }

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
pub mod ck_ops;

#[cfg(test)]
#[path = "../operation_tests.rs"]
mod tests;
