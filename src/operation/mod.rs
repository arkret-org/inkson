//! SDK-backed v1 Event Envelope builder used by inkson's active write paths.
//!
//! Spec source of truth: `arkret-spec/spec/v1/artifacts/schemas/event-envelope.schema.json`.
//!
//! # Signing
//!
//! All envelopes are produced with `proofs: Vec::new()`. The detached JWS
//! proof is attached through the SDK event signing path before submit. There is
//! NO placeholder proof: a submit without an installed signer is rejected
//! locally with `no active signer configured` rather than shipped to the
//! wire in any form.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, Ordering};

pub use arkret_sdk::events::kinds::EventKind;
pub use arkret_sdk::{
    Audience as EventProofAudience, CriticalExtension, Effect, Event, EventRef as SemanticRef,
    EventRequirements, LatticeOp, LatticeOpType, Precondition, Predicate, PredicateOp,
    Proof as EventProof, SealBasis,
};
use serde_json::Value;

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

/// Builder for creating typed event envelopes. Callers attach
/// preconditions / effects / seal_ref / requirements after `new()`
/// and before `build_sdk_event()`; the SDK event submit path requires an active
/// signer to attach the detached JWS proof before going on the wire.
#[derive(Debug)]
pub struct OperationBuilder {
    event_id: Option<arkret_sdk::EventId>,
    realm_id: String,
    actor: String,
    op_type: EventKind,
    target_ref: Option<String>,
    body: Value,
    authz_ref: Option<String>,
    executed_by: Option<String>,
    authorization_ref: Option<String>,
    preconditions: Vec<Precondition>,
    effects: Vec<Effect>,
    causal_refs: Vec<arkret_sdk::Hash>,
    refs: Vec<SemanticRef>,
    seal_ref: Option<String>,
    seal_basis: Option<SealBasis>,
    requirements: Option<EventRequirements>,
    redacts: Option<arkret_sdk::EventId>,
    created_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl OperationBuilder {
    pub fn new(realm_id: impl Into<String>, actor: impl Into<String>, op_type: EventKind) -> Self {
        Self {
            event_id: None,
            realm_id: realm_id.into(),
            actor: actor.into(),
            op_type,
            target_ref: None,
            body: Value::Null,
            authz_ref: None,
            executed_by: None,
            authorization_ref: None,
            preconditions: Vec::new(),
            effects: Vec::new(),
            causal_refs: Vec::new(),
            refs: Vec::new(),
            seal_ref: None,
            seal_basis: None,
            requirements: None,
            redacts: None,
            created_at: None,
        }
    }

    pub fn target_ref(mut self, target_ref: impl Into<String>) -> Self {
        self.target_ref = Some(target_ref.into());
        self
    }

    /// Pin the Event identifier before envelope construction. This is required
    /// when the payload atomically self-binds to its containing Event.
    pub fn event_id(mut self, event_id: arkret_sdk::EventId) -> Self {
        self.event_id = Some(event_id);
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

    /// Semantic causal predecessors. RSVP carries the observed schedule
    /// revision frontier here: the entry basis MUST be a subset of it, and a
    /// receiver uses the same edges to decide which earlier heads this response
    /// dominates.
    pub fn causal_refs(mut self, causal_refs: Vec<arkret_sdk::Hash>) -> Self {
        self.causal_refs = causal_refs;
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

    /// Pin the Event to an exact authoring instant.
    ///
    /// The SDK constructor normalizes this value to the protocol's fixed
    /// millisecond Event profile. Callers use this when a payload object and
    /// its containing Event must carry the same timestamp.
    pub fn created_at(mut self, created_at: chrono::DateTime<chrono::Utc>) -> Self {
        self.created_at = Some(created_at);
        self
    }

    #[allow(clippy::expect_used)]
    pub fn redacts(mut self, redacts: impl Into<String>) -> Self {
        let redacts = redacts.into();
        self.redacts = Some(
            arkret_sdk::EventId::new(redacts).expect("redacts must be a canonical ak:event id"),
        );
        self
    }

    #[allow(clippy::expect_used)]
    pub fn build(self, node_id: &str) -> Event {
        self.build_sdk_event(node_id)
            .expect("OperationBuilder emitted an invalid SDK Event")
    }

    pub fn build_sdk_event(self, node_id: &str) -> anyhow::Result<arkret_sdk::Event> {
        self.build_sdk_event_with_deps(node_id, Vec::new())
    }

    #[allow(clippy::expect_used)]
    pub fn build_with_deps(self, node_id: &str, deps: Vec<String>) -> Event {
        self.build_sdk_event_with_deps(node_id, deps)
            .expect("OperationBuilder emitted an invalid SDK Event")
    }

    pub fn build_sdk_event_with_deps(
        self,
        node_id: &str,
        deps: Vec<String>,
    ) -> anyhow::Result<arkret_sdk::Event> {
        let _ = node_id;
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
        let realm_id = trim_realm_id(&self.realm_id);
        let prev_refs = deps
            .into_iter()
            .map(|dep| {
                arkret_sdk::EventId::new(dep)
                    .map_err(|err| anyhow::anyhow!("invalid prev_refs event id: {err}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let realm_id = arkret_sdk::RealmId::new(realm_id)
            .map_err(|err| anyhow::anyhow!("invalid realm_id: {err}"))?;
        let actor_id = arkret_sdk::Did::new(self.actor)
            .map_err(|err| anyhow::anyhow!("invalid actor_id DID: {err}"))?;
        let hlc = arkret_sdk::Hlc::new("000000000000-0000-00000000")
            .map_err(|err| anyhow::anyhow!("placeholder HLC is invalid: {err}"))?;
        let created_at = self.created_at.unwrap_or_else(crate::clock::now_utc_millis);
        let mut event = if let Some(event_id) = self.event_id {
            arkret_sdk::Event::new_with_id_at(
                event_id,
                self.op_type.as_str(),
                realm_id,
                actor_id,
                1,
                hlc,
                self.body,
                created_at,
            )
        } else {
            arkret_sdk::Event::new_at(
                self.op_type.as_str(),
                realm_id,
                actor_id,
                1,
                hlc,
                self.body,
                created_at,
            )
        }
        .map_err(|err| anyhow::anyhow!("SDK Event construction failed: {err}"))?;
        event.prev_refs = prev_refs;
        event.refs = self.refs;
        event.causal_refs = self.causal_refs;
        event.preconditions = self.preconditions;
        event.effects = self.effects;
        event.seal_ref = self
            .seal_ref
            .map(arkret_sdk::SealId::new)
            .transpose()
            .map_err(|err| anyhow::anyhow!("invalid seal_ref: {err}"))?;
        event.seal_basis = self.seal_basis;
        event.requirements = self.requirements.unwrap_or_default();
        event.redacts = self.redacts;
        event.executed_by = self
            .executed_by
            .map(arkret_sdk::Did::new)
            .transpose()
            .map_err(|err| anyhow::anyhow!("invalid executed_by DID: {err}"))?;
        event.authorization_ref = self.authorization_ref;
        event.unsigned = unsigned;
        if event.kind.as_str() == arkret_sdk::events::EventKind::CAPABILITY_GRANT
            && event.effects.is_empty()
        {
            arkret_sdk::schema::materialize_capability_grant_event_contract(&mut event).map_err(
                |error| anyhow::anyhow!("capability grant effect derivation failed: {error}"),
            )?;
        }
        // These reducer-input kinds have a complete registry projection, so a
        // producer failure must abort authoring. Swallowing the error here
        // would recreate the effect-less RSVP defect this path is meant to
        // prevent.
        if event.effects.is_empty()
            && matches!(
                event.kind.as_str(),
                arkret_sdk::events::EventKind::CALL_STATE
                    | arkret_sdk::events::EventKind::CALL_RECORDING_START
                    | arkret_sdk::events::EventKind::RSVP_SET
            )
        {
            arkret_sdk::schema::materialize_registered_cell_writes(&mut event)
                .map_err(|error| anyhow::anyhow!("Event cell-effect derivation failed: {error}"))?;
            arkret_sdk::schema::validate_registered_cell_writes(&event)
                .map_err(|error| anyhow::anyhow!("Event cell-effect validation failed: {error}"))?;
        }
        Ok(event)
    }
}

/// Free-function form of [`EventExt::local_operation_id`]: the local
/// reconciliation/dedupe key for an SDK event — the optimistic write chain's
/// `unsigned.local_operation_idempotency_alias` when present, else the event
/// id. Single source (YGN-DRY-03); every view consumes this one definition so
/// the dedupe fallback rule can never drift between surfaces.
pub(crate) fn sdk_event_local_operation_id(event: &Event) -> &str {
    event.local_operation_id()
}

pub trait EventExt {
    fn local_operation_idempotency_alias(&self) -> Option<&str>;
    fn local_operation_id(&self) -> &str;
    fn local_target_ref(&self) -> Option<&str>;
    fn canonical_digest(&self) -> anyhow::Result<String>;
    fn refresh_proof_hashes(&mut self) -> anyhow::Result<()>;
    fn sign_ed25519(
        &mut self,
        signer_did: impl Into<String>,
        key_id: impl Into<String>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> anyhow::Result<()>;
    fn require_proof(&self) -> anyhow::Result<&EventProof>;
}

impl EventExt for Event {
    fn local_operation_idempotency_alias(&self) -> Option<&str> {
        self.unsigned
            .get("local_operation_idempotency_alias")
            .and_then(Value::as_str)
    }

    fn local_operation_id(&self) -> &str {
        self.local_operation_idempotency_alias()
            .unwrap_or_else(|| self.event_id.as_str())
    }

    fn local_target_ref(&self) -> Option<&str> {
        self.unsigned
            .get("local_target_ref")
            .and_then(Value::as_str)
    }

    fn canonical_digest(&self) -> anyhow::Result<String> {
        self.event_digest()
            .map_err(|err| anyhow::anyhow!("SDK Event digest failed: {err}"))
    }

    fn refresh_proof_hashes(&mut self) -> anyhow::Result<()> {
        let digest = self.canonical_digest()?;
        let digest = arkret_sdk::Hash::new(digest)
            .map_err(|err| anyhow::anyhow!("event digest is not a SDK Hash: {err}"))?;
        for proof in &mut self.proofs {
            proof.event_digest = digest.clone();
        }
        Ok(())
    }

    fn sign_ed25519(
        &mut self,
        signer_did: impl Into<String>,
        _key_id: impl Into<String>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> anyhow::Result<()> {
        use std::sync::Arc;

        use arkret_sdk::signatures::proof::Ed25519DetachedJwsSigner;

        let signer_did = signer_did.into();
        let sdk_signer =
            Ed25519DetachedJwsSigner::new(signing_key.clone(), format!("{signer_did}#device"));
        let signer = crate::event_signer::InksonEventSigner::from_dyn_signer(
            Arc::new(sdk_signer),
            signer_did.clone(),
        );
        signer
            .sign_envelope(self)
            .map_err(|err| anyhow::anyhow!("Ed25519 sign rejected: {err}"))?;
        Ok(())
    }

    fn require_proof(&self) -> anyhow::Result<&EventProof> {
        self.proofs
            .first()
            .ok_or_else(|| anyhow::anyhow!("event envelope missing proof"))
    }
}

fn typed_operation_id(operation_id: &str) -> String {
    if operation_id.starts_with("ak:operation:") {
        operation_id.to_owned()
    } else {
        format!("ak:operation:{operation_id}")
    }
}

/// Generate a canonical UUIDv7 string for typed protocol identifiers.
///
/// Thin wrapper over the SDK's `new_prefixed_uuid7` (RFC 9562 UUIDv7 via the
/// `uuid` crate, with same-millisecond monotonicity) called with an empty
/// prefix. Callers add their own typed prefix (`ak:operation:`, `ak:device:`,
/// etc.). Replaces the previous hand-rolled bit-packing helper, which had no
/// same-millisecond monotonic guarantee.
pub fn uuid_v7() -> String {
    arkret_sdk::identifiers::new_prefixed_uuid7("")
}

/// Canonical helper constructors used by the current UI.
pub mod ak_ops;

#[cfg(test)]
#[path = "../operation_tests.rs"]
mod tests;
