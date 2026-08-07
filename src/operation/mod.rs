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
    Audience as EventProofAudience, CriticalExtension, Event, EventRef as SemanticRef,
    EventRequirements, LatticeOp, LatticeOpType, Precondition, Predicate, PredicateOp,
    ProjectedCellWrite, ProjectionEffect, Proof as EventProof, ScopeRef, SealBasis,
};
use serde_json::Value;

/// Single registry projection evaluator for this client.
///
/// v1 removed the producer-written `effects[]` channel: what an Event writes
/// is derived from `kind + payload` through the generated reducer contract
/// (`models/event-and-patch.md` §2.4.2). Every inkson call site — authoring
/// pre-checks, MLS governance state roots and the SDK crates that sit below
/// `arkret-schema` and take an injected projector — routes through this one
/// function so no surface can grow a private table of cell writes.
pub fn project_registered_cell_writes(
    event: &Event,
) -> Result<Vec<ProjectedCellWrite>, EventCellProjectionError> {
    project_registered_cell_writes_with_digest_suite(
        event,
        arkret_sdk::canonical::DigestSuite::Sha256,
    )
}

pub fn project_registered_cell_writes_with_digest_suite(
    event: &Event,
    digest_suite: arkret_sdk::canonical::DigestSuite,
) -> Result<Vec<ProjectedCellWrite>, EventCellProjectionError> {
    arkret_sdk::schema::project_registered_cell_writes(event, digest_suite)
}

pub type EventCellProjectionError = arkret_sdk::schema::EventCellContractError;

/// [`project_registered_cell_writes`] adapted to the SDK's injected
/// `CellWriteProjector` callback shape (`Result<_, String>`).
pub fn cell_write_projector(event: &Event) -> Result<Vec<ProjectedCellWrite>, String> {
    project_registered_cell_writes(event).map_err(|error| error.to_string())
}

/// Every registered write of `event` that is fully determined by the signed
/// Event, i.e. needs no frozen pre-state.
///
/// `transition_to` / `apply_patch` / `remove_observed` deliberately stay
/// unresolved: only a reducer holding accepted pre-state may resolve them, and
/// a client that invented an operand would be re-asserting a pre-state it never
/// observed.
pub fn direct_registered_cell_writes(
    event: &Event,
) -> Result<Vec<ProjectionEffect>, EventCellProjectionError> {
    Ok(project_registered_cell_writes(event)?
        .iter()
        .filter_map(ProjectedCellWrite::as_direct)
        .collect())
}

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
/// preconditions / seal_ref / requirements after `new()` and before
/// `build_sdk_event()`; the SDK event submit path requires an active signer to
/// attach the detached JWS proof before going on the wire.
///
/// There is no `effects` setter: the Event wire has no producer-written cell
/// writes in v1. Everything this Event writes is derived by the receiver from
/// `kind + payload` through the registered reducer contract, and the builder
/// only pre-checks that the contract is evaluable.
#[derive(Debug)]
pub struct OperationBuilder {
    event_id: Option<arkret_sdk::EventId>,
    realm_id: String,
    circle_id: Option<String>,
    actor: String,
    op_type: EventKind,
    target_ref: Option<String>,
    body: Value,
    authz_ref: Option<String>,
    executed_by: Option<String>,
    authorization_ref: Option<String>,
    preconditions: Vec<Precondition>,
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
            circle_id: None,
            actor: actor.into(),
            op_type,
            target_ref: None,
            body: Value::Null,
            authz_ref: None,
            executed_by: None,
            authorization_ref: None,
            preconditions: Vec::new(),
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

    /// Narrow the signed `scope_ref` from the Realm default to a Circle.
    ///
    /// `scope_ref` is producer-signed and part of the canonical digest, so this
    /// must come from the target's accepted projection — never from
    /// user-supplied payload text.
    pub fn circle_id(mut self, circle_id: impl Into<String>) -> Self {
        self.circle_id = Some(circle_id.into());
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
        let operation_id =
            arkret_sdk::OperationId::new_v7_at(crate::clock::now_unix_ms()).into_string();
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
        // Spec realm-and-space.md section 2.5.0: a Realm genesis carries the
        // closed `realm_genesis` scope and no realm_id — the Realm's id is
        // derived from the genesis Event itself.
        let scope_ref = if self.op_type == EventKind::RealmCreate {
            if self.circle_id.is_some() {
                return Err(anyhow::anyhow!(
                    "ak.realm.create cannot be narrowed to a Circle scope"
                ));
            }
            ScopeRef::RealmGenesis
        } else {
            match self.circle_id {
                Some(circle_id) => ScopeRef::Circle {
                    realm_id,
                    circle_id: arkret_sdk::CircleId::new(circle_id)
                        .map_err(|err| anyhow::anyhow!("invalid circle_id: {err}"))?,
                },
                None => ScopeRef::Realm { realm_id },
            }
        };
        let actor_id = arkret_sdk::Did::new(self.actor)
            .map_err(|err| anyhow::anyhow!("invalid actor_id DID: {err}"))?;
        let hlc = arkret_sdk::Hlc::new("000000000000-0000-00000000")
            .map_err(|err| anyhow::anyhow!("placeholder HLC is invalid: {err}"))?;
        let created_at = self.created_at.unwrap_or_else(crate::clock::now_utc_millis);
        let mut event = if let Some(event_id) = self.event_id {
            arkret_sdk::Event::new_with_id_at(
                event_id,
                self.op_type.as_str(),
                scope_ref,
                actor_id,
                1,
                hlc,
                self.body,
                created_at,
            )
        } else {
            arkret_sdk::Event::new_at(
                self.op_type.as_str(),
                scope_ref,
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
        event.authorization_ref = self
            .authorization_ref
            .map(arkret_sdk::AuthorizationRef::new)
            .transpose()
            .map_err(|err| anyhow::anyhow!("invalid authorization_ref: {err}"))?;
        event.unsigned = unsigned;
        // A create whose object id is `event_derived` has exactly one legal
        // local handle: the id the receiver will derive. Stamp it here so no
        // caller has to invent one — inventing was the whole class of bug the
        // content-bound id form removes (spec `zh/models/common-fields.md`
        // section 6.0).
        if let Some(object_id) = arkret_sdk::schema::derived_object_id(&event) {
            event
                .unsigned
                .insert("local_target_ref".to_owned(), Value::String(object_id));
        }
        // Authoring pre-check. All 163 active reducer-input kinds carry a
        // complete `cell_writes[]` contract, so the receiver can always derive
        // this Event's writes from `kind + payload`. A projection that does not
        // evaluate here would be rejected at admission, and shipping it anyway
        // is exactly the effect-less-Event defect the old producer `effects[]`
        // path kept re-creating. The CBA plane check is deliberately NOT run:
        // `seal_basis` / `seal_ref` / `auth_context` are attached after
        // authoring, so it belongs to the submit gate.
        //
        // Non-reducer-input kinds project no writes and pass trivially.
        match project_registered_cell_writes(&event) {
            Ok(_) => {}
            // Some registered contracts deliberately compare a signed operand
            // with accepted frozen pre-state (for example a direct invite
            // cancel's invitee binding). The authoring layer has no accepted
            // snapshot to supply, so leave only this requirement unresolved;
            // admission must evaluate it atomically with the real pre-state.
            Err(EventCellProjectionError::PreStateRequirement { .. }) => {}
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "{} has no evaluable registered cell-write contract: {error}",
                    event.kind.as_str()
                ));
            }
        }
        Ok(event)
    }
}

/// Re-derive an Event's content-bound identity after its payload was edited.
///
/// `event_id` is a function of the finished Event (spec
/// `zh/conformance/encoding.md` section 4.0), and for an `event_derived` create
/// the object id is a function of `event_id` in turn. A surface that edits the
/// payload after [`OperationBuilder::build_sdk_event`] therefore invalidates
/// both; this restores them in the one order that has a fixed point.
pub(crate) fn rederive_event_identity(event: &mut Event) -> anyhow::Result<()> {
    event.event_id = event
        .derive_event_id()
        .map_err(|err| anyhow::anyhow!("re-derive event_id after payload edit: {err}"))?;
    if let Some(object_id) = arkret_sdk::schema::derived_object_id(event) {
        event
            .unsigned
            .insert("local_target_ref".to_owned(), Value::String(object_id));
    }
    Ok(())
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

/// Generate a bare UUIDv7 for local opaque correlation values.
///
/// The returned value is not itself an Arkret wire identifier.
/// Protocol identifiers must use the SDK's concrete typed constructors (for
/// example `RealmId::new_v7_at`) instead of adding a wire prefix to this value.
/// The SDK still owns UUID layout and monotonicity; Inkson supplies only its
/// platform-safe clock reading.
/// A canonical-shaped `event_id` that stands in while an envelope is being
/// assembled. Every builder that needs an id before the content is final uses
/// this one and re-derives before submit — the real id is a function of the
/// finished Event (spec `zh/conformance/encoding.md` section 4.0).
pub const PLACEHOLDER_EVENT_ID: &str = "ak:event:00000000-0000-8000-8000-000000000000";

pub fn uuid_v7() -> String {
    arkret_sdk::identifiers::uuid_v7_at(crate::clock::now_unix_ms()).to_string()
}

/// Canonical helper constructors used by the current UI.
pub mod ak_ops;

#[cfg(test)]
#[path = "../operation_tests.rs"]
mod tests;
