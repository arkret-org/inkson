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
    Audience as EventProofAudience, CriticalExtension, Effect, Event as EventEnvelope,
    EventRef as SemanticRef, EventRequirements, LatticeOp, LatticeOpType, Precondition, Predicate,
    PredicateOp, Proof as EventProof, SealBasis,
};
use serde_json::Value;

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

pub(crate) fn realm_effective_scope_value(realm_id: &str) -> Result<Value, String> {
    let realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|err| format!("invalid realm effective_scope realm_id: {err:?}"))?;
    serde_json::to_value(arkret_sdk::EffectiveScope::Realm { realm_id })
        .map_err(|err| format!("serialize realm effective_scope: {err}"))
}

/// Builder for creating typed event envelopes. Callers attach
/// preconditions / effects / seal_ref / requirements after `new()`
/// and before `build_sdk_event()`; the SDK event submit path requires an active
/// signer to attach the detached JWS proof before going on the wire.
#[derive(Debug)]
pub struct OperationBuilder {
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
    refs: Vec<SemanticRef>,
    seal_ref: Option<String>,
    seal_basis: Option<SealBasis>,
    requirements: Option<EventRequirements>,
    redacts: Option<arkret_sdk::EventId>,
}

impl OperationBuilder {
    pub fn new(realm_id: impl Into<String>, actor: impl Into<String>, op_type: EventKind) -> Self {
        Self {
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

    #[allow(clippy::expect_used)]
    pub fn redacts(mut self, redacts: impl Into<String>) -> Self {
        let redacts = redacts.into();
        self.redacts = Some(
            arkret_sdk::EventId::new(redacts).expect("redacts must be a canonical ck:event id"),
        );
        self
    }

    #[allow(clippy::expect_used)]
    pub fn build(self, node_id: &str) -> EventEnvelope {
        self.build_sdk_event(node_id)
            .expect("OperationBuilder emitted an invalid SDK Event")
    }

    pub fn build_sdk_event(self, node_id: &str) -> anyhow::Result<arkret_sdk::Event> {
        self.build_sdk_event_with_deps(node_id, Vec::new())
    }

    #[allow(clippy::expect_used)]
    pub fn build_with_deps(self, node_id: &str, deps: Vec<String>) -> EventEnvelope {
        self.build_sdk_event_with_deps(node_id, deps)
            .expect("OperationBuilder emitted an invalid SDK Event")
    }

    pub fn build_sdk_event_with_deps(
        self,
        node_id: &str,
        deps: Vec<String>,
    ) -> anyhow::Result<arkret_sdk::Event> {
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
        let realm_id = trim_realm_id(&self.realm_id);
        let prev_refs = deps
            .into_iter()
            .map(|dep| {
                arkret_sdk::EventId::new(dep)
                    .map_err(|err| anyhow::anyhow!("invalid prev_refs event id: {err}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let created_at = chrono::DateTime::parse_from_rfc3339(&crate::clock::now_rfc3339_secs())
            .map_err(|err| anyhow::anyhow!("event timestamp is not canonical RFC3339: {err}"))?
            .with_timezone(&chrono::Utc);
        Ok(arkret_sdk::Event {
            event_id: arkret_sdk::EventId::new(format!("ak:event:{}", uuid_v7()))
                .map_err(|err| anyhow::anyhow!("generated event_id is invalid: {err}"))?,
            kind: self.op_type,
            realm_id: arkret_sdk::RealmId::new(realm_id)
                .map_err(|err| anyhow::anyhow!("invalid realm_id: {err}"))?,
            effective_scope: None,
            actor_id: arkret_sdk::Did::new(self.actor)
                .map_err(|err| anyhow::anyhow!("invalid actor_id DID: {err}"))?,
            executed_by: self
                .executed_by
                .map(arkret_sdk::Did::new)
                .transpose()
                .map_err(|err| anyhow::anyhow!("invalid executed_by DID: {err}"))?,
            authorization_ref: self.authorization_ref,
            actor_kind: None,
            actor_seq,
            created_at,
            hlc: arkret_sdk::Hlc::new(hlc.encode())
                .map_err(|err| anyhow::anyhow!("generated HLC is invalid: {err}"))?,
            prev_refs,
            refs: self.refs,
            payload: self.body,
            preconditions: self.preconditions,
            effects: self.effects,
            seal_ref: self
                .seal_ref
                .map(arkret_sdk::SealId::new)
                .transpose()
                .map_err(|err| anyhow::anyhow!("invalid seal_ref: {err}"))?,
            auth_context: None,
            seal_basis: self.seal_basis,
            requirements: self.requirements.unwrap_or_default(),
            redacts: self.redacts,
            applet_id: None,
            external_ref: None,
            unsigned,
            proofs: Vec::new(),
        })
    }
}

/// Free-function form of [`EventEnvelopeExt::local_operation_id`]: the local
/// reconciliation/dedupe key for an SDK event — the optimistic write chain's
/// `unsigned.local_operation_idempotency_alias` when present, else the event
/// id. Single source (YGN-DRY-03); every view consumes this one definition so
/// the dedupe fallback rule can never drift between surfaces.
pub(crate) fn sdk_event_local_operation_id(event: &EventEnvelope) -> &str {
    event.local_operation_id()
}

pub trait EventEnvelopeExt {
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

impl EventEnvelopeExt for EventEnvelope {
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
pub mod ck_ops;

#[cfg(test)]
#[path = "../operation_tests.rs"]
mod tests;
