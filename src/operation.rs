//! Minimal event-envelope helpers for yougen's active write paths.
//!
//! Active writes use the current operation/event surfaces directly.
//!
//! # Proof mode (T1.3)
//!
//! [`OperationBuilder::build`] historically attached a placeholder proof
//! (`jws == "a..b"`) so dev fixtures and dev-mode soland round-trip
//! cleanly. That is unsafe against a production soland (`SOLAND_DEVELOPMENT_MODE=false`)
//! because the placeholder *looks* like a valid envelope until soland
//! rejects it on the wire — and worse, lets a developer build that does
//! not actually have a real signer ship envelopes that *appear* signed.
//!
//! The runtime [`ProofMode`] now gates the placeholder attach behavior:
//!
//! - [`ProofMode::PlaceholderDev`] — default; `build()` attaches the
//!   placeholder so existing dev flows work. Equivalent to the
//!   historical behavior.
//! - [`ProofMode::RealEd25519`] / [`ProofMode::ExternalSigner`] — the
//!   builder still produces an envelope, but the placeholder is left
//!   off so the signing path can fill in the real `jws`.
//! - [`ProofMode::Production`] — no signer is configured. `build()`
//!   leaves `proofs` empty; the submit guard in
//!   [`crate::api::ContrixApi::submit_event_envelope`] refuses to send.
//!
//! The dev feature flag `dev_proof` enables `PlaceholderDev` as the
//! compile-time default. Builds without the feature start in
//! `Production`, forcing callers to opt into a real signer.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::{canonical_json_bytes, canonical_sha256};
use crate::hlc::{Hlc, next_seq};

/// Active client-side proof attachment mode. See module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofMode {
    /// `attach_placeholder_proof` is invoked by [`OperationBuilder::build`].
    /// Compatible with `SOLAND_DEVELOPMENT_MODE=true` soland instances and
    /// the existing test suite. **Never safe to use against a
    /// production soland** — the placeholder `jws == "a..b"` fails the
    /// strict-JWS check and reveals the dev origin in the audit log.
    PlaceholderDev,
    /// A real Ed25519 signing key is wired into the build pipeline.
    /// `build()` produces an unsigned envelope; the signer fills in
    /// `proofs[0].jws` before submit.
    RealEd25519,
    /// An external signer (OS keychain, WebAuthn, HSM) is wired in.
    /// `build()` produces an unsigned envelope; the signer round-trip
    /// happens out of process before submit.
    ExternalSigner,
    /// No signer is configured. `build()` returns an envelope with no
    /// proofs, and the submit guard refuses to ship it. This is the
    /// fail-closed default when the `dev_proof` feature is disabled.
    Production,
}

impl ProofMode {
    /// i18n key suffix (lowercased) for status-bar/settings display.
    pub fn i18n_key(self) -> &'static str {
        match self {
            ProofMode::PlaceholderDev => "settings.proof_mode.placeholder_dev",
            ProofMode::RealEd25519 => "settings.proof_mode.real_ed25519",
            ProofMode::ExternalSigner => "settings.proof_mode.external_signer",
            ProofMode::Production => "settings.proof_mode.production",
        }
    }

    /// Human-readable English label (fallback when i18n is not wired up).
    pub fn label_en(self) -> &'static str {
        match self {
            ProofMode::PlaceholderDev => "placeholder dev",
            ProofMode::RealEd25519 => "real Ed25519",
            ProofMode::ExternalSigner => "external signer",
            ProofMode::Production => "no signer (production)",
        }
    }

    /// True when [`OperationBuilder::build`] should call
    /// [`EventEnvelope::attach_placeholder_proof`].
    pub fn attaches_placeholder(self) -> bool {
        matches!(self, ProofMode::PlaceholderDev)
    }

    /// True when the submit guard should refuse to ship envelopes that
    /// were never signed by a real (Ed25519 / external) signer.
    pub fn enforces_real_signer(self) -> bool {
        matches!(
            self,
            ProofMode::Production | ProofMode::RealEd25519 | ProofMode::ExternalSigner
        )
    }

    fn as_u8(self) -> u8 {
        match self {
            ProofMode::PlaceholderDev => 0,
            ProofMode::RealEd25519 => 1,
            ProofMode::ExternalSigner => 2,
            ProofMode::Production => 3,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            0 => ProofMode::PlaceholderDev,
            1 => ProofMode::RealEd25519,
            2 => ProofMode::ExternalSigner,
            _ => ProofMode::Production,
        }
    }
}

#[cfg(feature = "dev_proof")]
const DEFAULT_PROOF_MODE: ProofMode = ProofMode::PlaceholderDev;
#[cfg(not(feature = "dev_proof"))]
const DEFAULT_PROOF_MODE: ProofMode = ProofMode::Production;

static PROOF_MODE: AtomicU8 = AtomicU8::new(0xFF);

/// Returns the active [`ProofMode`]. Defaults to [`ProofMode::PlaceholderDev`]
/// when the `dev_proof` cargo feature is enabled (so the existing dev
/// fixtures keep working), otherwise [`ProofMode::Production`].
pub fn current_proof_mode() -> ProofMode {
    let raw = PROOF_MODE.load(Ordering::Relaxed);
    if raw == 0xFF {
        DEFAULT_PROOF_MODE
    } else {
        ProofMode::from_u8(raw)
    }
}

/// Set the active [`ProofMode`]. Called by the key-store / signer
/// bootstrap when a real signing identity becomes available, and by
/// settings UI / startup code to opt into the dev placeholder when
/// connecting to a known dev soland.
pub fn set_proof_mode(mode: ProofMode) {
    PROOF_MODE.store(mode.as_u8(), Ordering::Relaxed);
}

/// `jws` value the placeholder proof uses. Exposed so the submit guard
/// and tests can detect the unsafe shape.
pub const PLACEHOLDER_PROOF_JWS: &str = "a..b";

/// Current v1 Event Envelope used by active write paths.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_id: String,
    pub kind: String,
    pub actor_id: String,
    pub actor_seq: u64,
    pub space_id: String,
    pub created_at: String,
    pub hlc: String,
    #[serde(default)]
    pub prev_refs: Vec<String>,
    #[serde(default)]
    pub refs: Vec<String>,
    pub payload: Value,
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

/// Legacy operation envelope kept only as an adapter input for persisted
/// drafts/tests that have not been migrated yet.
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
    /// Detached JWS proof on the old operation DTO.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

/// Detached JWS proof over the canonical body of a legacy [`OperationEnvelope`].
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

/// Builder for creating event envelopes.
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
        let mut event = EventEnvelope {
            event_id: format!("cx:event:{}", uuid_v7()),
            kind: self.op_type,
            actor_id: self.actor,
            actor_seq,
            space_id: self.space_id,
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            hlc: hlc.encode(),
            prev_refs: deps,
            refs: Vec::new(),
            payload: self.body,
            unsigned,
            proofs: Vec::new(),
        };
        // Only the explicit dev mode attaches the placeholder. Real-signer
        // and production modes leave `proofs` empty so the downstream
        // signer (Ed25519, external) fills in a real `jws`, and the
        // submit guard fails closed when nothing does.
        if current_proof_mode().attaches_placeholder() {
            event.attach_placeholder_proof();
        }
        event
    }
}

impl EventEnvelope {
    /// Convert a persisted legacy operation envelope into the current Event
    /// Envelope. This is the only supported legacy adapter.
    pub fn from_legacy_operation(operation: &OperationEnvelope) -> anyhow::Result<Self> {
        let mut unsigned = BTreeMap::new();
        unsigned.insert(
            "local_operation_idempotency_alias".to_owned(),
            Value::String(typed_operation_id(&operation.operation_id)),
        );
        if let Some(target_ref) = &operation.target_ref {
            unsigned.insert(
                "local_target_ref".to_owned(),
                Value::String(target_ref.clone()),
            );
        }
        if let Some(authz_ref) = &operation.authz_ref {
            unsigned.insert(
                "local_authz_ref".to_owned(),
                Value::String(authz_ref.clone()),
            );
        }
        if !operation.preconditions.is_empty() {
            unsigned.insert(
                "legacy_preconditions".to_owned(),
                Value::Array(operation.preconditions.clone()),
            );
        }
        if !operation.effects.is_empty() {
            unsigned.insert(
                "legacy_effects".to_owned(),
                Value::Array(operation.effects.clone()),
            );
        }
        if let Some(anchor_ref) = &operation.anchor_ref {
            unsigned.insert(
                "legacy_anchor_ref".to_owned(),
                Value::String(anchor_ref.clone()),
            );
        }

        let mut event = Self {
            event_id: format!("cx:event:{}", uuid_v7()),
            kind: operation.op_type.clone(),
            actor_id: operation.actor.clone(),
            actor_seq: operation.causal.actor_seq,
            space_id: operation.space_id.clone(),
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            hlc: operation.causal.hlc.clone(),
            prev_refs: operation.causal.deps.clone(),
            refs: Vec::new(),
            payload: operation.body.clone(),
            unsigned,
            proofs: Vec::new(),
        };
        if current_proof_mode().attaches_placeholder() {
            event.attach_placeholder_proof();
        }
        Ok(event)
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
            proof.payload_hash = digest.clone();
        }
        Ok(())
    }

    pub fn attach_placeholder_proof(&mut self) {
        if self.proofs.is_empty() {
            self.proofs.push(EventProof {
                kind: "detached_jws".to_owned(),
                alg: "EdDSA".to_owned(),
                verification_method: format!("{}#yougen", self.actor_id),
                payload_hash: String::new(),
                created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                jws: "a..b".to_owned(),
            });
        }
        let _ = self.refresh_proof_hashes();
    }

    pub fn sign_ed25519(
        &mut self,
        signer_did: impl Into<String>,
        key_id: impl Into<String>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> anyhow::Result<()> {
        // T5.2 — delegate to the SDK pipeline via
        // [`crate::event_signer::YougenEventSigner::sign_envelope`] so a
        // bug fix in the canonical-bytes / detached-JWS path lands in
        // one place (the SDK) instead of being mirrored across coauth,
        // soland, and yougen. The signer is built per-call here because
        // the legacy entry point hands in a SigningKey directly; the
        // active-signer registry handles the runtime auto-sign path.
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
        // Preserve the historical contract: callers passed an explicit
        // `key_id`, so even after `from_dyn_signer` derives the default
        // `<did>#device` shape we restore the provided value.
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
        OperationBuilder::new(space_id, actor, "cx.flow.tracks.update")
            .target_ref(flow_id)
            .body(json!({
                "flow_id": flow_id,
                "patch": patch,
            }))
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
    /// After R1.7 realm/space inversion, what used to be called "Place"
    /// (Board/List containers) are now "Space" objects. The security
    /// boundary that used to be Space is now Realm. The optional
    /// `board_place_id` + `rank` fields let the Kanban UI keep carrying the
    /// board ordering hint while the object id and event kind stay canonical.
    pub fn place_create(
        space_id: &str,
        actor: &str,
        place_id: &str,
        kind: &str,
        title: &str,
        board_place_id: Option<&str>,
        rank: Option<&str>,
    ) -> OperationBuilder {
        let mut body = json!({
            "place_id": place_id,
            "object": {
                "id": place_id,
                "schema": "cx.schema.space.v1",
                "space_id": space_id,
                "kind": kind,
                "title": title,
                "created_by": actor,
                "created_at": chrono::Utc::now()
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            },
        });
        if let Some(board_place_id) = board_place_id {
            body["board_place_id"] = json!(board_place_id);
            body["object"]["board_place_id"] = json!(board_place_id);
            body["object"]["parent_ref"] = json!(board_place_id);
        }
        if let Some(rank) = rank {
            body["rank"] = json!(rank);
            body["object"]["rank"] = json!(rank);
        }
        OperationBuilder::new(space_id, actor, "cx.space.create")
            .target_ref(place_id)
            .body(body)
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
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
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

    /// Build a `cx.flow.update` carrying a new document body on the
    /// synthesis track. `flow_id` must already exist on the server (i.e.
    /// the corresponding `cx.flow.create` has been accepted).
    pub fn document_flow_update(
        space_id: &str,
        actor: &str,
        flow_id: &str,
        document_body: serde_json::Value,
    ) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.flow.update")
            .target_ref(flow_id)
            .body(json!({
                "flow_id": flow_id,
                "fields": {
                    "document": document_body,
                },
            }))
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
        OperationBuilder::new(space_id, actor, "cx.flow.update")
            .target_ref(flow_id)
            .body(json!({
                "flow_id": flow_id,
                "patch": patch,
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

    /// Build a `cx.space.archive` operation against a container Space (former
    /// Place). The Space transitions from `Active` to `Archived`; reversible
    /// via [`place_restore`]. Spec: `models/realm-and-space.md` §4.4 (post-R1.7
    /// rename). Soland's lifecycle requirements validator requires the
    /// `place_id` field on the wire.
    // TODO(realm-rework): rename `place_id` payload field to `space_id` once
    // soland's reducer accepts the new name.
    pub fn place_archive(space_id: &str, actor: &str, place_id: &str) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.space.archive")
            .target_ref(place_id)
            .body(json!({ "place_id": place_id }))
    }

    /// Build a `cx.space.restore` operation. Reverses [`place_archive`]
    /// (`archived -> active`). The SDK reducer enforces `state == archived`
    /// at apply time; tombstoned container Spaces MUST NOT be restored. Spec:
    /// `models/realm-and-space.md` §4.4 (post-R1.7 rename), `common-fields.md §5`.
    pub fn place_restore(space_id: &str, actor: &str, place_id: &str) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.space.restore")
            .target_ref(place_id)
            .body(json!({ "place_id": place_id }))
    }

    /// Build a `cx.flow.archive` operation. Spec: `flow-and-message.md §3`
    /// and `common-fields.md §5.1`. Reducer rejects with `flow_not_active`
    /// when source state is not `active`.
    pub fn flow_archive(space_id: &str, actor: &str, flow_id: &str) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.flow.archive")
            .target_ref(flow_id)
            .body(json!({ "flow_id": flow_id }))
    }

    /// Build a `cx.flow.restore` operation. Reverses [`flow_archive`]
    /// (`archived -> active`). SDK reducer rejects with `flow_not_archived`
    /// when source state is not `archived`.
    pub fn flow_restore(space_id: &str, actor: &str, flow_id: &str) -> OperationBuilder {
        OperationBuilder::new(space_id, actor, "cx.flow.restore")
            .target_ref(flow_id)
            .body(json!({ "flow_id": flow_id }))
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
    use serde_json::json;
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

    // R1.7 (realm-rework): `required_fields` / `assert_required_fields_present`
    // helpers were retired with `spec_place_schema_accepts_client_place_create_payload_shape`'s
    // tightened assertions — the new container `space.schema.json` requires a
    // `realm_id` that the client builder does not yet emit. Restore once the
    // builder is wired to emit `realm_id`.
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

    /// Guards mutations of the global [`PROOF_MODE`] so the proof-mode
    /// tests cannot race the rest of the suite (which relies on the
    /// default `PlaceholderDev` mode).
    static PROOF_MODE_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// T1.3 — switching the runtime proof mode to anything other than
    /// `PlaceholderDev` MUST cause `OperationBuilder::build` to skip the
    /// placeholder attach so the production submit guard fires.
    #[test]
    fn build_skips_placeholder_in_production_mode() {
        let _guard = PROOF_MODE_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = current_proof_mode();
        set_proof_mode(ProofMode::Production);
        let event = OperationBuilder::new("cx:space:test", "did:web:alice", "cx.message.create")
            .body(json!({"body": "hi"}))
            .build("test_node");
        set_proof_mode(prior);

        assert!(
            event.proofs.is_empty(),
            "Production proof mode must not attach the placeholder: {:?}",
            event.proofs
        );
    }

    #[test]
    fn build_attaches_placeholder_in_dev_mode() {
        let _guard = PROOF_MODE_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prior = current_proof_mode();
        set_proof_mode(ProofMode::PlaceholderDev);
        let event = OperationBuilder::new("cx:space:test", "did:web:alice", "cx.message.create")
            .body(json!({"body": "hi"}))
            .build("test_node");
        set_proof_mode(prior);

        let proof = event.proofs.first().expect("dev proof attached");
        assert_eq!(proof.jws, PLACEHOLDER_PROOF_JWS);
    }

    #[test]
    fn proof_mode_labels_are_distinct() {
        let modes = [
            ProofMode::PlaceholderDev,
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
        let op = OperationBuilder::new("cx:space:test", "did:web:alice", "cx.message.create")
            .body(json!({"body": "hello"}))
            .build("test_node");

        assert!(!op.local_operation_id().is_empty());
        assert_eq!(op.space_id, "cx:space:test");
        assert_eq!(op.actor_id, "did:web:alice");
        assert_eq!(op.kind, "cx.message.create");
        assert!(!op.hlc.is_empty());
        assert!(op.actor_seq > 0);
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
    fn document_flow_update_targets_existing_flow_id() {
        let op = cx_ops::document_flow_update(
            "cx:space:doc-test",
            "did:web:alice",
            "cx:flow:doc-1",
            json!({"blocks": []}),
        )
        .build("test_node");

        assert_eq!(op.kind, "cx.flow.update");
        assert_eq!(op.payload["flow_id"], "cx:flow:doc-1");
        assert!(op.payload["fields"]["document"]["blocks"].is_array());
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
        let op = cx_ops::flow_tracks_update_set_primary(
            "cx:space:s1",
            "did:web:alice",
            "cx:flow:f1",
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
        let op = cx_ops::flow_update_patch(
            "cx:space:s1",
            "did:web:alice",
            "cx:flow:f1",
            json!({
                "title": { "$op": "set", "value": "Launch checklist" },
                "fields.due_at": { "$op": "set", "value": "2026-05-20" },
            }),
        )
        .build("node");
        assert_eq!(op.kind, "cx.flow.update");
        assert_eq!(op.local_target_ref(), Some("cx:flow:f1"));
        assert_eq!(op.payload["flow_id"], "cx:flow:f1");
        assert_eq!(op.payload["patch"]["title"]["value"], "Launch checklist");
        assert!(op.payload.get("fields").is_none());
    }

    #[test]
    fn place_create_emits_canonical_place_object() {
        let op = cx_ops::place_create(
            "cx:space:0196419b-0000-7000-8000-000000000001",
            "did:web:alice",
            "cx:place:0196419b-0000-7000-8000-000000000002",
            "list",
            "To Do",
            Some("cx:place:0196419b-0000-7000-8000-000000000003"),
            Some("U"),
        )
        .build("node");
        assert_eq!(op.kind, "cx.space.create");
        assert_eq!(
            op.local_target_ref(),
            Some("cx:place:0196419b-0000-7000-8000-000000000002")
        );
        assert_eq!(
            op.payload["place_id"],
            "cx:place:0196419b-0000-7000-8000-000000000002"
        );
        assert_eq!(op.payload["object"]["schema"], "cx.schema.space.v1");
        assert_eq!(
            op.payload["object"]["space_id"],
            "cx:space:0196419b-0000-7000-8000-000000000001"
        );
        assert_eq!(op.payload["object"]["kind"], "list");
        assert_eq!(
            op.payload["object"]["board_place_id"],
            "cx:place:0196419b-0000-7000-8000-000000000003"
        );
        assert_eq!(
            op.payload["object"]["parent_ref"],
            "cx:place:0196419b-0000-7000-8000-000000000003"
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
    fn spec_place_schema_accepts_client_place_create_payload_shape() {
        // R1.7 rename: the container schema artifact is now space.schema.json
        // (the former place.schema.json was retired in contrix-spec's R1.7
        // pass). The builder still names its locals `space_id` / `place_id`
        // for the security-boundary id vs container id distinction; the
        // wire-level object schema is the renamed cx.schema.space.v1.
        // TODO(realm-rework): the test below only spot-checks that the
        // wire schema string matches and that key fields (`schema`, `kind`,
        // `title`, `created_by`, `created_at`) are present; the new
        // space.schema.json's required `realm_id` is not yet emitted by
        // the client builder. Wire that through once soland accepts both
        // shapes.
        let schema = spec_schema("space.schema.json");
        // TODO(realm-rework): the first arg should be a `cx:realm:` id
        // once SDK validators accept the new prefix.
        let op = cx_ops::place_create(
            "cx:space:0196419b-0000-7000-8000-000000000001",
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
        assert_eq!(op.kind, "cx.space.create");
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
        op_a.hlc = "0000000000000000-00000000-00000000".into();
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
    fn place_lifecycle_helpers_emit_canonical_kinds() {
        let place_id = "cx:place:01904100-0000-7000-8000-1fb50799ad42";
        let archive =
            cx_ops::place_archive("cx:space:test", "did:web:alice.example", place_id).build("node");
        assert_eq!(archive.kind, "cx.space.archive");
        assert_eq!(archive.payload["place_id"], place_id);
        assert_eq!(archive.local_target_ref(), Some(place_id));

        let restore =
            cx_ops::place_restore("cx:space:test", "did:web:alice.example", place_id).build("node");
        assert_eq!(restore.kind, "cx.space.restore");
        assert_eq!(restore.payload["place_id"], place_id);
        assert_eq!(restore.local_target_ref(), Some(place_id));
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
