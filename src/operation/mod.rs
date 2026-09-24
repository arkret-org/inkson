//! SDK-backed v1 Event Envelope builder used by inkson's active write paths.
//!
//! Spec source of truth: `arkret-spec/spec/v1/artifacts/schemas/event-envelope.schema.json`.
//!
//! # Signing
//!
//! All envelopes are produced with `producer_proof: None`. The detached JWS
//! proof is attached through the SDK event signing path before submit. There is
//! NO placeholder proof: a submit without an installed signer is rejected
//! locally with `no active signer configured` rather than shipped to the
//! wire in any form.

use std::sync::atomic::{AtomicU8, Ordering};
#[cfg(not(test))]
use std::sync::{OnceLock, RwLock};

pub use arkret_sdk::events::kinds::EventKind;
pub use arkret_sdk::{
    Audience, AuthoredEvent, CriticalExtension, Event, EventIntent, ProducerEventProof, ScopeRef,
    SemanticRef,
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
#[cfg(not(test))]
static AUTHORING_STATION_ID: OnceLock<RwLock<Option<arkret_sdk::DidCoreId>>> = OnceLock::new();

#[cfg(test)]
thread_local! {
    static TEST_AUTHORING_STATION_ID: std::cell::RefCell<Option<arkret_sdk::DidCoreId>> =
        const { std::cell::RefCell::new(None) };
}

pub fn set_authoring_station_id(station_id: Option<arkret_sdk::DidCoreId>) {
    #[cfg(test)]
    {
        TEST_AUTHORING_STATION_ID.with(|slot| *slot.borrow_mut() = station_id);
    }
    #[cfg(not(test))]
    {
        let slot = AUTHORING_STATION_ID.get_or_init(|| RwLock::new(None));
        *slot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = station_id;
    }
}

/// The Station this session is connected to, installed by `connect.rs` once
/// `describe` succeeds and cleared when describe fails, the account changes, or
/// the session ends.
///
/// This is the correct Station for exactly one thing: identities this session
/// creates on the connected Station (the active account, and the Agents it
/// owns and hosts here). `connect.rs` accepts an `ActiveAccountContext` only
/// when `authority.station_id` equals the described Station, so for those
/// identities the slot agrees with the closed `AccountId` in the store.
///
/// It is NOT a substitute for a closed `AccountId` a caller already holds
/// (pass that instead: account-lifecycle.md §156 forbids passing the two
/// components as a loose identity), it is never the Station of a remote
/// subject (an inviter, invitee, grantee, holder, requester or contact), and
/// it is not installed yet while first enrollment runs ahead of `describe`.
/// Event builders use this only to construct the stable local `AccountId`.
/// Submission later needs the producer proof and cached authority evidence;
/// it does not contact this Station or ask it to approve each Event.
pub(crate) fn authoring_station_id() -> anyhow::Result<arkret_sdk::DidCoreId> {
    #[cfg(test)]
    if let Some(station_id) = TEST_AUTHORING_STATION_ID.with(|slot| slot.borrow().clone()) {
        return Ok(station_id);
    }
    #[cfg(not(test))]
    if let Some(station_id) = AUTHORING_STATION_ID.get().and_then(|slot| {
        slot.read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }) {
        return Ok(station_id);
    }
    #[cfg(test)]
    {
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").map_err(anyhow::Error::msg)
    }
    #[cfg(not(test))]
    anyhow::bail!("no authoring Station is selected")
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

/// The holder-local identity of one user write.
///
/// Optimistic UI, the durable submit queue and receipt reconciliation all need a
/// key for "this write" that exists *before* the Event is authored. They used to
/// borrow the draft `event_id` — and everything derived from it, including
/// `retype(event_id)` Board/List/Card ids — which authoring then changed,
/// leaving the UI holding a second object that no accepted Event ever named.
///
/// This value is that key, and it is deliberately not an Arkret identifier: it
/// never derives protocol identity, never authorizes anything, and never leaves
/// this holder except as the unsigned reconciliation alias the server echoes
/// back verbatim.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalOperationId(String);

impl LocalOperationId {
    /// Allocate a fresh holder-local operation identity.
    pub fn new() -> Self {
        Self(uuid_v7())
    }

    /// Adopt a holder-local key this client already minted for the same write.
    ///
    /// An optimistic row usually exists before the write can be built — the UI
    /// needs something to key it by immediately — so that key becomes the
    /// write's identity instead of a second, unrelated one. Two keys for one
    /// user operation is exactly how a queue slot and the row it belongs to
    /// stopped recognizing each other.
    pub fn from_holder_key(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl Default for LocalOperationId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for LocalOperationId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A user write as this client holds it before submission: the semantic Event
/// intent, plus the holder-local identities only this device uses.
///
/// The intent carries no `event_id`, so nothing downstream of this type can
/// derive an object id, a route or a storage key from an identity that authoring
/// has not settled yet. The single finalize boundary is
/// [`crate::event_submit`]'s authoring step.
#[derive(Clone, Debug)]
pub struct LocalOperation {
    intent: EventIntent,
    local_operation_id: LocalOperationId,
    local_target_ref: Option<String>,
    publication_event: Option<arkret_sdk::Event>,
}

impl LocalOperation {
    /// Wrap a bare intent as a submittable write with a fresh holder-local
    /// identity. Used where the intent comes from an SDK builder rather than
    /// from [`TypedOperationBuilder`].
    pub fn new(intent: EventIntent) -> Self {
        Self {
            intent,
            local_operation_id: LocalOperationId::new(),
            local_target_ref: None,
            publication_event: None,
        }
    }

    pub fn with_publication_event(mut self, event: arkret_sdk::Event) -> anyhow::Result<Self> {
        anyhow::ensure!(
            *self.intent.kind() == arkret_sdk::EventKind::AgentActionApprove,
            "publication dependency requires Agent action approval"
        );
        self.publication_event = Some(event);
        Ok(self)
    }

    pub fn publication_event(&self) -> Option<&arkret_sdk::Event> {
        self.publication_event.as_ref()
    }

    /// The semantic operation, ready to be positioned on the actor chain.
    pub fn intent(&self) -> &EventIntent {
        &self.intent
    }

    /// Consume this operation, keeping only the intent.
    pub fn into_intent(self) -> EventIntent {
        self.intent
    }

    pub fn local_operation_id(&self) -> &LocalOperationId {
        &self.local_operation_id
    }

    /// The object this write targets, when the payload already names one.
    ///
    /// A create names its object by `retype(event_id)`, so it has no target to
    /// report here: until the final Event id arrives, the object is known only
    /// by [`Self::local_operation_id`].
    pub fn local_target_ref(&self) -> Option<&str> {
        self.local_target_ref.as_deref()
    }

    /// The holder-local handle a projection keys this write's object by.
    ///
    /// Existing objects answer with their protocol id; a pending create answers
    /// with its holder-local operation id, which the projection migrates to the
    /// event-derived id once the receipt lands.
    pub fn local_object_handle(&self) -> &str {
        self.local_target_ref
            .as_deref()
            .unwrap_or_else(|| self.local_operation_id.as_str())
    }

    /// Adopt a holder-local identity that was allocated before this write could
    /// be built.
    ///
    /// An optimistic row has to exist before the Event does — for an encrypted
    /// write the payload cannot even be sealed until the epoch's Event is
    /// authored — so the identity is minted first and the write joins it here.
    pub fn with_local_operation_id(mut self, local_operation_id: LocalOperationId) -> Self {
        self.local_operation_id = local_operation_id;
        self
    }

    /// Narrow this write to its accepted effective scope (Circle or Sidecar).
    pub fn with_effective_scope(mut self, scope_ref: ScopeRef) -> anyhow::Result<Self> {
        self.intent = self
            .intent
            .with_scope_ref(scope_ref)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        Ok(self)
    }

    /// Record the principal that executes this write on the actor's behalf.
    pub fn with_executed_by(mut self, executed_by: arkret_sdk::DidCoreId) -> Self {
        let account_id = arkret_sdk::AccountId::new(
            executed_by,
            self.intent.actor_id().route_service_id().clone(),
        );
        self.intent = self
            .intent
            .with_executed_by(arkret_sdk::ActorId::account(account_id));
        self
    }

    /// Pin the authorization this write is authored under.
    ///
    /// A producer decision, so it belongs on the intent: the authoring boundary
    /// leaves an already-claimed authorization alone.
    pub fn with_authorization_ref(
        mut self,
        authorization_ref: arkret_sdk::AuthorizationRef,
    ) -> Self {
        self.intent = self.intent.with_authorization_ref(authorization_ref);
        self
    }

    pub fn kind(&self) -> &EventKind {
        self.intent.kind()
    }

    pub fn payload(&self) -> &std::collections::BTreeMap<String, Value> {
        self.intent.payload()
    }

    /// Read the payload back through its marker's typed shape.
    pub fn typed_payload<K: arkret_sdk::EventSpec>(&self) -> anyhow::Result<K::Payload> {
        self.intent
            .typed_payload::<K>()
            .map_err(|error| anyhow::anyhow!("{error}"))
    }

    pub fn payload_value(&self) -> Value {
        Value::Object(self.intent.payload().clone().into_iter().collect())
    }

    pub fn actor_id(&self) -> &arkret_sdk::ActorId {
        self.intent.actor_id()
    }

    pub fn created_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.intent.created_at()
    }

    /// The Realm this write is scoped to, or `None` for a Realm genesis whose
    /// Realm id is a function of the create Event id.
    pub fn realm_id_opt(&self) -> Option<&arkret_sdk::RealmId> {
        self.intent.realm_id_opt()
    }
}

/// Durable outbound-record field carrying the holder-local operation identity.
///
/// It is a local reconciliation key only: producer Events have no holder-local
/// members, so this never reaches the wire.
pub(crate) const LOCAL_OPERATION_IDEMPOTENCY_ALIAS: &str = "local_operation_idempotency_alias";
/// Durable outbound-record field naming the existing object a non-create write
/// targets. Local only, for the same reason.
pub(crate) const LOCAL_TARGET_REF: &str = "local_target_ref";

/// Standard Event builder whose kind is fixed by the SDK payload marker.
///
/// This boundary never accepts a runtime `EventKind` or an erased JSON payload.
/// The only constructor requires the payload associated with `K`, and erasure
/// happens inside [`arkret_sdk::TypedEventDraft`] after its marker-specific
/// validation.
///
/// It produces a [`LocalOperation`], never an `Event`: the actor-chain position,
/// HLC and CBS basis are not known here, and a builder that authored anyway
/// would be handing out an identity it is about to change.
#[derive(Debug)]
pub struct TypedOperationBuilder {
    intent: anyhow::Result<EventIntent>,
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
        let station_id = authoring_station_id();
        let intent = station_id
            .and_then(|station_id| Self::draft_intent::<K>(realm_id, actor, station_id, payload));
        Self {
            intent,
            target_ref: None,
        }
    }

    pub fn new_for_station<K>(
        realm_id: impl Into<String>,
        actor: impl Into<String>,
        station_id: arkret_sdk::DidCoreId,
        payload: K::Payload,
    ) -> Self
    where
        K: arkret_sdk::EventSpec,
    {
        Self {
            intent: Self::draft_intent::<K>(realm_id, actor, station_id, payload),
            target_ref: None,
        }
    }

    fn draft_intent<K>(
        realm_id: impl Into<String>,
        actor: impl Into<String>,
        station_id: arkret_sdk::DidCoreId,
        payload: K::Payload,
    ) -> anyhow::Result<EventIntent>
    where
        K: arkret_sdk::EventSpec,
    {
        let realm_id = arkret_sdk::RealmId::new(trim_realm_id(&realm_id.into()))
            .map_err(|err| anyhow::anyhow!("invalid realm_id: {err}"))?;
        let scope_ref = if K::KIND == EventKind::RealmCreate {
            ScopeRef::RealmGenesis
        } else {
            ScopeRef::Realm { realm_id }
        };
        let principal_id = crate::mls_api_helpers::principal_core_id(&actor.into())
            .map_err(|err| anyhow::anyhow!("invalid actor_id core_id: {err}"))?;
        let actor_id =
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(principal_id, station_id));
        arkret_sdk::TypedEventDraft::<K>::new(scope_ref, actor_id, payload)
            .map_err(|err| anyhow::anyhow!("typed Event draft construction failed: {err}"))?
            .into_intent(crate::clock::now_utc_millis())
            .map_err(|err| anyhow::anyhow!("typed Event intent erasure failed: {err}"))
    }

    fn map_intent(
        mut self,
        update: impl FnOnce(EventIntent) -> anyhow::Result<EventIntent>,
    ) -> Self {
        self.intent = self.intent.and_then(update);
        self
    }

    /// Borrow the drafted intent, e.g. to project the registered cell a
    /// precondition must name. There is deliberately no way to author from this
    /// borrow: the finalize boundary stays in the submit path.
    pub fn intent(&self) -> anyhow::Result<&EventIntent> {
        self.intent
            .as_ref()
            .map_err(|error| anyhow::anyhow!("{error:#}"))
    }

    pub fn target_ref(mut self, target_ref: impl Into<String>) -> Self {
        self.target_ref = Some(target_ref.into());
        self
    }

    pub fn executed_by(self, executed_by: impl Into<String>) -> Self {
        self.map_intent(|intent| {
            let executed_by = executed_by.into();
            let principal_id = crate::mls_api_helpers::principal_core_id(&executed_by)
                .map_err(|err| anyhow::anyhow!("invalid executed_by core_id: {err}"))?;
            let account_id = arkret_sdk::AccountId::new(
                principal_id,
                intent.actor_id().route_service_id().clone(),
            );
            Ok(intent.with_executed_by(arkret_sdk::ActorId::account(account_id)))
        })
    }

    pub fn authorization_ref(self, authorization_ref: impl Into<String>) -> Self {
        self.map_intent(|intent| {
            Ok(intent.with_authorization_ref(
                arkret_sdk::AuthorizationRef::new(authorization_ref.into())
                    .map_err(|err| anyhow::anyhow!("invalid authorization_ref: {err}"))?,
            ))
        })
    }

    pub fn circle_id(self, circle_id: impl Into<String>) -> Self {
        self.map_intent(|intent| {
            let realm_id = intent
                .realm_id_opt()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("a Realm genesis has no Circle scope"))?;
            let circle_id = arkret_sdk::CircleId::new(circle_id.into())
                .map_err(|err| anyhow::anyhow!("invalid circle_id: {err}"))?;
            intent
                .with_scope_ref(ScopeRef::Circle {
                    realm_id,
                    circle_id,
                })
                .map_err(|err| anyhow::anyhow!("{err}"))
        })
    }

    /// Narrow this write to its accepted effective scope (Circle or Sidecar).
    ///
    /// `scope_ref` is producer-signed, so it is part of the content the identity
    /// is derived from; setting it here keeps it inside the one finalize
    /// boundary instead of after it.
    pub fn effective_scope(self, scope_ref: ScopeRef) -> Self {
        self.map_intent(|intent| {
            intent
                .with_scope_ref(scope_ref)
                .map_err(|err| anyhow::anyhow!("{err}"))
        })
    }

    pub fn semantic_refs(self, semantic_refs: Vec<SemanticRef>) -> Self {
        self.map_intent(|intent| Ok(intent.with_semantic_refs(semantic_refs)))
    }

    pub fn created_at(self, created_at: chrono::DateTime<chrono::Utc>) -> Self {
        self.map_intent(|intent| Ok(intent.with_created_at(created_at)))
    }

    #[allow(clippy::expect_used)]
    pub fn build(self, node_id: &str) -> LocalOperation {
        self.build_sdk_event(node_id)
            .expect("TypedOperationBuilder emitted an invalid SDK Event intent")
    }

    pub fn build_sdk_event(self, node_id: &str) -> anyhow::Result<LocalOperation> {
        let _ = node_id;
        Ok(LocalOperation {
            intent: self.intent?,
            local_operation_id: LocalOperationId::new(),
            local_target_ref: self.target_ref,
            publication_event: None,
        })
    }
}

pub trait EventExt {
    /// The holder-local key for this write.
    ///
    /// A producer Event carries no holder-local members, so once the Event is
    /// authored its own content-derived id is the only stable key. The
    /// pre-authoring alias lives on [`LocalOperation`] and in the durable
    /// outbound record, never on the wire.
    fn local_operation_id(&self) -> &str;
    fn canonical_digest(&self, digest_suite: arkret_sdk::DigestSuite) -> anyhow::Result<String>;
    fn require_proof(&self) -> anyhow::Result<&ProducerEventProof>;
}

/// Signing helper for an Event that has finished authoring.
///
/// Only [`AuthoredEvent`] carries one, because attaching a proof to anything
/// else would be signing an envelope whose identity is still moving.
pub trait AuthoredEventExt {
    fn sign_ed25519(
        &mut self,
        signer_did: impl Into<String>,
        key_id: impl Into<String>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> anyhow::Result<()>;
}

impl AuthoredEventExt for AuthoredEvent {
    fn sign_ed25519(
        &mut self,
        signer_did: impl Into<String>,
        key_id: impl Into<String>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> anyhow::Result<()> {
        use std::sync::Arc;

        use arkret_sdk::signatures::proof::Ed25519DetachedJwsSigner;

        let signer_did = signer_did.into();
        let sdk_signer = Ed25519DetachedJwsSigner::new(signing_key.clone(), key_id.into());
        let signer = crate::event_signer::InksonEventSigner::from_dyn_signer(
            Arc::new(sdk_signer),
            signer_did.clone(),
        );
        signer
            .sign_envelope_with_context(
                self,
                crate::event_signer::ProducerProofContext::new()
                    .with_digest_suite(self.digest_suite()),
            )
            .map_err(|err| anyhow::anyhow!("Ed25519 sign rejected: {err}"))?;
        Ok(())
    }
}

impl EventExt for Event {
    fn local_operation_id(&self) -> &str {
        self.event_id.as_str()
    }

    fn canonical_digest(&self, digest_suite: arkret_sdk::DigestSuite) -> anyhow::Result<String> {
        self.event_digest_with_digest_suite(digest_suite)
            .map_err(|err| anyhow::anyhow!("SDK Event digest failed: {err}"))
    }

    fn require_proof(&self) -> anyhow::Result<&ProducerEventProof> {
        let Some(proof) = self.producer_proof.as_ref() else {
            anyhow::bail!("event envelope must contain exactly one producer proof");
        };
        Ok(proof)
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

/// Finalize a built operation so a test can assert on producer-signed content.
///
/// Producer-signed content is only complete once the actor chain and the HLC are
/// stamped, so the envelope a test wants to inspect does not exist until then.
/// Production takes both from the realm actor frontier and the durable
/// signing-stamp allocator; a test has neither, so it pins them.
///
/// Test-only: nothing in production may author against a pinned actor chain.
#[cfg(test)]
pub(crate) fn author_for_test(operation: &LocalOperation) -> arkret_sdk::AuthoredEvent {
    author_intent_for_test(operation.intent().clone())
}

/// [`author_for_test`] for a bare intent.
#[cfg(test)]
pub(crate) fn author_intent_for_test(intent: EventIntent) -> arkret_sdk::AuthoredEvent {
    author_intent_for_test_at_seq(intent, 1)
}

/// [`author_intent_for_test`] for one member of a multi-Event unit.
///
/// A producer Event has no actor chain, so `nth` only disambiguates the
/// authoring timestamps of several Events built inside one test.
#[cfg(test)]
pub(crate) fn author_intent_for_test_at_seq(
    intent: EventIntent,
    nth: u64,
) -> arkret_sdk::AuthoredEvent {
    intent
        .with_created_at(test_authoring_created_at_at_seq(nth))
        .author_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
        .expect("a test intent finalizes")
}

/// The pinned authoring timestamp for the first Event of a test path.
#[cfg(test)]
pub(crate) fn test_authoring_created_at() -> chrono::DateTime<chrono::Utc> {
    test_authoring_created_at_at_seq(1)
}

/// The pinned authoring timestamp for the `nth` Event of a test path.
#[cfg(test)]
pub(crate) fn test_authoring_created_at_at_seq(nth: u64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(1_760_000_000_000 + i64::try_from(nth).unwrap_or(0))
        .expect("a pinned test timestamp parses")
}

#[cfg(test)]
#[path = "../operation_tests.rs"]
mod tests;
