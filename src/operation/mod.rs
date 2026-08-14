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

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{OnceLock, RwLock};

pub use arkret_sdk::events::kinds::EventKind;
pub use arkret_sdk::{
    Audience as EventProofAudience, CriticalExtension, Event, EventRef as SemanticRef,
    EventRequirements, LatticeOp, LatticeOpType, Precondition, Predicate, PredicateOp,
    ProducerEventProof as EventProof, ProjectedCellWrite, ProjectionEffect, ScopeRef, SealBasis,
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
static AUTHORING_PRINCIPAL_SERVER_ID: OnceLock<RwLock<Option<arkret_sdk::DidCoreId>>> =
    OnceLock::new();

pub fn set_authoring_principal_server_id(principal_server_id: Option<arkret_sdk::DidCoreId>) {
    let slot = AUTHORING_PRINCIPAL_SERVER_ID.get_or_init(|| RwLock::new(None));
    *slot
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = principal_server_id;
}

pub(crate) fn authoring_principal_server_id() -> anyhow::Result<arkret_sdk::DidCoreId> {
    if let Some(principal_server_id) = AUTHORING_PRINCIPAL_SERVER_ID.get().and_then(|slot| {
        slot.read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }) {
        return Ok(principal_server_id);
    }
    #[cfg(test)]
    {
        return arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example")
            .map_err(anyhow::Error::msg);
    }
    #[cfg(not(test))]
    anyhow::bail!("no authoring Principal Server is selected")
}

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

/// Standard Event builder whose kind is fixed by the SDK payload marker.
///
/// This boundary never accepts a runtime `EventKind` or an erased JSON
/// payload. The only constructor requires the
/// payload associated with `K`, and erasure happens inside
/// [`arkret_sdk::TypedEventDraft`] after its marker-specific validation.
#[derive(Debug)]
pub struct TypedOperationBuilder {
    event: anyhow::Result<Event>,
    target_ref: Option<String>,
}

impl TypedOperationBuilder {
    pub fn new<K>(
        realm_id: impl Into<String>,
        actor: impl Into<String>,
        payload: K::Payload,
    ) -> Self
    where
        K: arkret_sdk::EventSpec,
    {
        let principal_server_id = authoring_principal_server_id();
        let event = principal_server_id.and_then(|principal_server_id| {
            Self::author_event::<K>(realm_id, actor, principal_server_id, payload)
        });
        Self {
            event,
            target_ref: None,
        }
    }

    pub fn new_for_principal_server<K>(
        realm_id: impl Into<String>,
        actor: impl Into<String>,
        principal_server_id: arkret_sdk::DidCoreId,
        payload: K::Payload,
    ) -> Self
    where
        K: arkret_sdk::EventSpec,
    {
        Self {
            event: Self::author_event::<K>(realm_id, actor, principal_server_id, payload),
            target_ref: None,
        }
    }

    fn author_event<K>(
        realm_id: impl Into<String>,
        actor: impl Into<String>,
        principal_server_id: arkret_sdk::DidCoreId,
        payload: K::Payload,
    ) -> anyhow::Result<Event>
    where
        K: arkret_sdk::EventSpec,
    {
        let event = (|| {
            let realm_id = arkret_sdk::RealmId::new(trim_realm_id(&realm_id.into()))
                .map_err(|err| anyhow::anyhow!("invalid realm_id: {err}"))?;
            let scope_ref = if K::KIND == EventKind::RealmCreate {
                ScopeRef::RealmGenesis
            } else {
                ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                }
            };
            let actor_id = crate::mls_api_helpers::principal_core_id(&actor.into())
                .map_err(|err| anyhow::anyhow!("invalid actor_id core_id: {err}"))?;
            let hlc = arkret_sdk::Hlc::new("000000000000-0000-00000000")
                .map_err(|err| anyhow::anyhow!("placeholder HLC is invalid: {err}"))?;
            arkret_sdk::TypedEventDraft::<K>::new(scope_ref, actor_id, principal_server_id, payload)
                .map_err(|err| anyhow::anyhow!("typed Event draft construction failed: {err}"))?
                .author(1, hlc, crate::clock::now_utc_millis())
                .map_err(|err| anyhow::anyhow!("typed Event authoring failed: {err}"))
        })();
        event
    }

    fn map_event(mut self, update: impl FnOnce(&mut Event) -> anyhow::Result<()>) -> Self {
        if let Ok(event) = &mut self.event
            && let Err(error) = update(event)
        {
            self.event = Err(error);
        }
        self
    }

    pub fn target_ref(mut self, target_ref: impl Into<String>) -> Self {
        self.target_ref = Some(target_ref.into());
        self
    }

    pub fn executed_by(self, executed_by: impl Into<String>) -> Self {
        self.map_event(|event| {
            let executed_by = executed_by.into();
            event.executed_by = Some(
                crate::mls_api_helpers::principal_core_id(&executed_by)
                    .map_err(|err| anyhow::anyhow!("invalid executed_by core_id: {err}"))?,
            );
            Ok(())
        })
    }

    pub fn authorization_ref(self, authorization_ref: impl Into<String>) -> Self {
        self.map_event(|event| {
            event.authorization_ref = Some(
                arkret_sdk::AuthorizationRef::new(authorization_ref.into())
                    .map_err(|err| anyhow::anyhow!("invalid authorization_ref: {err}"))?,
            );
            Ok(())
        })
    }

    pub fn preconditions(self, preconditions: Vec<Precondition>) -> Self {
        self.map_event(|event| {
            event.preconditions = preconditions;
            Ok(())
        })
    }

    pub fn circle_id(self, circle_id: impl Into<String>) -> Self {
        self.map_event(|event| {
            if event.kind == EventKind::RealmCreate {
                return Err(anyhow::anyhow!(
                    "ak.realm.create cannot be narrowed to a Circle scope"
                ));
            }
            event.scope_ref = ScopeRef::Circle {
                realm_id: event.realm_id.clone(),
                circle_id: arkret_sdk::CircleId::new(circle_id.into())
                    .map_err(|err| anyhow::anyhow!("invalid circle_id: {err}"))?,
            };
            Ok(())
        })
    }

    pub fn refs(self, refs: Vec<SemanticRef>) -> Self {
        self.map_event(|event| {
            event.refs = refs;
            Ok(())
        })
    }

    pub fn causal_refs(self, causal_refs: Vec<arkret_sdk::Hash>) -> Self {
        self.map_event(|event| {
            event.causal_refs = causal_refs;
            Ok(())
        })
    }

    pub fn seal_ref(self, seal_ref: impl Into<String>) -> Self {
        self.map_event(|event| {
            event.seal_ref = Some(
                arkret_sdk::SealId::new(seal_ref.into())
                    .map_err(|err| anyhow::anyhow!("invalid seal_ref: {err}"))?,
            );
            Ok(())
        })
    }

    pub fn seal_basis(self, seal_basis: SealBasis) -> Self {
        self.map_event(|event| {
            event.seal_basis = Some(seal_basis);
            Ok(())
        })
    }

    pub fn requirements(self, requirements: EventRequirements) -> Self {
        self.map_event(|event| {
            event.requirements = requirements;
            Ok(())
        })
    }

    pub fn created_at(self, created_at: chrono::DateTime<chrono::Utc>) -> Self {
        self.map_event(|event| {
            event.created_at = arkret_sdk::canonical::normalize_timestamp_canonical(created_at);
            Ok(())
        })
    }

    pub fn redacts(self, redacts: impl Into<String>) -> Self {
        self.map_event(|event| {
            event.redacts = Some(
                arkret_sdk::EventId::new(redacts.into())
                    .map_err(|err| anyhow::anyhow!("invalid redacts Event id: {err}"))?,
            );
            Ok(())
        })
    }

    #[allow(clippy::expect_used)]
    pub fn build(self, node_id: &str) -> Event {
        self.build_sdk_event(node_id)
            .expect("TypedOperationBuilder emitted an invalid SDK Event")
    }

    pub fn build_sdk_event(self, node_id: &str) -> anyhow::Result<Event> {
        let _ = node_id;
        let mut event = self.event?;
        let operation_id =
            arkret_sdk::OperationId::new_v7_at(crate::clock::now_unix_ms()).into_string();
        event.unsigned.insert(
            "local_operation_idempotency_alias".to_owned(),
            Value::String(operation_id),
        );
        if let Some(target_ref) = self.target_ref {
            event
                .unsigned
                .insert("local_target_ref".to_owned(), Value::String(target_ref));
        }
        event
            .refresh_content_bound_identity()
            .map_err(|err| anyhow::anyhow!("derive final event_id: {err}"))?;
        if let Some(object_id) = arkret_sdk::schema::derived_object_id(&event) {
            event
                .unsigned
                .insert("local_target_ref".to_owned(), Value::String(object_id));
        }
        match project_registered_cell_writes(&event) {
            Ok(_) | Err(EventCellProjectionError::PreStateRequirement { .. }) => {}
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
/// `zh/conformance/encoding.md` section 4.0). Event-derived create payloads
/// omit their own object id, so refreshing the Event identity is a single
/// acyclic step; the retyped object id is stored only as a local unsigned hint.
pub(crate) fn rederive_event_identity(event: &mut Event) -> anyhow::Result<()> {
    rederive_event_identity_with_digest_suite(event, arkret_sdk::canonical::DigestSuite::Sha256)
}

pub(crate) fn rederive_event_identity_with_digest_suite(
    event: &mut Event,
    digest_suite: arkret_sdk::canonical::DigestSuite,
) -> anyhow::Result<()> {
    event
        .refresh_content_bound_identity_with_digest_suite(digest_suite)
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
            if let arkret_sdk::EventProof::Producer(proof) = proof {
                proof.event_digest = digest.clone();
            }
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
            .iter()
            .find_map(arkret_sdk::EventProof::as_producer)
            .ok_or_else(|| anyhow::anyhow!("event envelope missing proof"))
    }
}

/// Generate a bare UUIDv7 for local opaque correlation values.
///
/// The returned value is not itself an Arkret wire identifier.
/// Protocol identifiers must use the SDK's concrete typed constructors instead
/// of adding a wire prefix to this value. Event-derived ids are materialized
/// only after the containing Event's full digest is known.
/// The SDK still owns UUID layout and monotonicity; Inkson supplies only its
/// platform-safe clock reading.
pub fn uuid_v7() -> String {
    arkret_sdk::identifiers::uuid_v7_at(crate::clock::now_unix_ms()).to_string()
}

/// Canonical helper constructors used by the current UI.
pub mod ak_ops;

#[cfg(test)]
#[path = "../operation_tests.rs"]
mod tests;
