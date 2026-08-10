//! Personal-agent data types, presets, and lifecycle helpers.
//!
//! These items carry no RSX; they are the unit-testable core behind the
//! personal-agent administration surfaces.

use arkret_models_collaboration::agent_operations::{
    AgentLifecycleState, AgentProjection, AgentReadinessBlocker, AgentReadinessState,
    AgentRuntimeState, AgentView,
};
use arkret_models_collaboration::events_payloads::agent::{
    AgentKeyScope, AgentKeyScopeResource, AgentKeyScopeResourceKind,
};
use arkret_models_identity::handle::HandleVisibility;
use arkret_sdk::{
    AgentKeyApprovalEvidence, AgentKeyApprovalEvidenceKind, AgentKeyAuthorizePayload,
    AgentKeyPairRequestBody, AgentKeySupersession, AgentPairingBootstrap,
    AgentRequestedScopeDisclosure, AgentRuntimeApprovalControllerProjection,
    AgentSigningKeyBinding, Did, DidUrl, Event, GrantConstraint, GrantConstraintEffect,
    GrantConstraintKind, GrantConstraintSubkind, Hash, KeyState, NonEmptyString, OpaqueLocalId,
    Proof, RealmId, RequestId,
};
use chrono::Utc;
use serde_json::{Value, json};

pub fn build_agent_provision_event_draft(
    controller_id: &Did,
    controller_realm_id: &RealmId,
    agent_id: &Did,
    principal_control_realm_id: &RealmId,
    controller_authorization_ref: &DidUrl,
    agent_slug: &str,
    requested_scope_digest: &Hash,
) -> anyhow::Result<Event> {
    let created_at = crate::clock::now_utc();
    let controller_actor_id =
        arkret_sdk::ActorId::from(arkret_sdk::project_full_id_to_core_id(controller_id)?);
    let hlc = crate::signing_stamp::issue_protocol_hlc_for_active_device(
        controller_actor_id.as_str(),
        controller_realm_id.as_str(),
    )?;
    Ok(arkret_bootstrap::build_agent_provision_event_draft(
        controller_id,
        controller_realm_id,
        agent_id,
        principal_control_realm_id,
        controller_authorization_ref,
        agent_slug,
        requested_scope_digest,
        HandleVisibility::Private,
        None,
        arkret_bootstrap::AgentProvisionEventDraftOptions {
            created_at,
            actor_seq: 0,
            hlc,
            prev_refs: Vec::new(),
            seal_basis: None,
        },
    )?)
}

// ─────────────────────────────────────────────────────────────────────
// AKP-0008 / AKP-0009 — Envelope `actor_kind` reducer-stamped
// projection. SDK 4d5a1af exposes `EnvelopeActorKind { Native, Ghost,
// Service, Agent }`. The UI labels below MUST stay user-facing
// readable: actor lists, sidecar disclosure cards, and the personal-
// agent admin all want a stable mapping.
// ─────────────────────────────────────────────────────────────────────

/// Returns a short, user-facing label for an envelope-level
/// `actor_kind`. Returns `None` when the value is missing or not one
/// of the four canonical variants (the reducer is the only writer; an
/// unrecognized value means the envelope is from a future reducer
/// version and the UI should fall back to a neutral "actor" label).
pub fn actor_kind_label(actor_kind: Option<&str>) -> Option<&'static str> {
    match actor_kind? {
        "native" => Some("Native"),
        "ghost" => Some("Ghost Actor"),
        "service" => Some("Service"),
        "agent" => Some("Personal Agent"),
        _ => None,
    }
}

/// Maps an envelope-level `actor_kind` to the badge CSS class. Native
/// devices get the neutral chip; ghost actors (applet-bound) get the
/// amber chip so users can tell at a glance the message did not
/// originate from a real device; agents and services get distinct
/// tints.
pub fn actor_kind_badge_class(actor_kind: Option<&str>) -> &'static str {
    match actor_kind {
        Some("native") => "badge",
        Some("ghost") => "badge amber",
        Some("service") => "badge blue",
        Some("agent") => "badge green",
        _ => "badge",
    }
}

// ─────────────────────────────────────────────────────────────────────
// AKP-0008 §4.7 — additive content grant presets. The five presets are
// UI/SDK affordances only; the canonical content authorization is the
// expanded `ak.capability.grant` object for each preset (actions +
// resource selector + registered constraints + TTL). Runtime endpoint
// access is selected separately through `AgentServiceScopePreset`; both
// selections enter `requested_scope`, while effective content access still
// requires the materialized grant, Realm membership, and participation.
// ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentGrantPreset {
    /// `read` preset — agent subscribes/reads selected objects.
    Read,
    /// `draft` preset — agent proposes controller-private drafts.
    Draft,
    /// `reply_as_agent` — agent posts as itself.
    ReplyAsAgent,
    /// `act_on_behalf` — controller is actor_id, agent is executed_by.
    /// High risk: the expanded grant carries a controller-approval
    /// constraint per §4.10.
    ActOnBehalf,
    /// `organizer` — agent creates/updates Strands and relations.
    Organizer,
}

impl AgentGrantPreset {
    pub const ALL: [AgentGrantPreset; 5] = [
        Self::Read,
        Self::Draft,
        Self::ReplyAsAgent,
        Self::ActOnBehalf,
        Self::Organizer,
    ];

    /// The §4.7 preset name. Used only for UI labels and as a
    /// `data-preset` attribute; never written to the canonical wire.
    pub fn preset_name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Draft => "draft",
            Self::ReplyAsAgent => "reply_as_agent",
            Self::ActOnBehalf => "act_on_behalf",
            Self::Organizer => "organizer",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Read => "Read",
            Self::Draft => "Draft",
            Self::ReplyAsAgent => "Reply as agent",
            Self::ActOnBehalf => "Act on my behalf",
            Self::Organizer => "Organizer",
        }
    }

    pub fn help(self) -> &'static str {
        match self {
            Self::Read => "Read payloads allowed by the Realm-scoped content grant.",
            Self::Draft => "Create controller-private draft proposals for your approval.",
            Self::ReplyAsAgent => "Post and react as the agent itself, accountable to you.",
            Self::ActOnBehalf => {
                "Post as you (you stay the actor, the agent is recorded as executor). High risk; each action needs your approval."
            }
            Self::Organizer => "Create and update Strands and relations, plus limited posting.",
        }
    }

    /// Registered capability actions for this preset (AKP-0008 §4.7 /
    /// §4.9). Only actions present in `capability-action-registry.json`
    /// are emitted so soland never fail-closes on an unknown action.
    pub fn actions(self) -> &'static [&'static str] {
        match self {
            Self::Read => &["ak.event.read"],
            Self::Draft => &["ak.agent.draft.propose", "ak.agent.action_request"],
            Self::ReplyAsAgent => &["ak.message.create", "ak.reaction.add"],
            Self::ActOnBehalf => &["ak.message.create"],
            Self::Organizer => &[
                "ak.strand.create",
                "ak.strand.update",
                "ak.relation.create",
                "ak.message.create",
            ],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentServiceScopePreset {
    SubscribeEvents,
    ScanCatchUp,
    SubmitEvents,
    SecureMessaging,
    ResolveResources,
}

impl AgentServiceScopePreset {
    pub const ALL: [AgentServiceScopePreset; 5] = [
        Self::SubscribeEvents,
        Self::ScanCatchUp,
        Self::SubmitEvents,
        Self::SecureMessaging,
        Self::ResolveResources,
    ];

    pub const DEFAULTS: [AgentServiceScopePreset; 4] = [
        Self::SubscribeEvents,
        Self::ScanCatchUp,
        Self::SubmitEvents,
        Self::SecureMessaging,
    ];

    pub fn preset_name(self) -> &'static str {
        match self {
            Self::SubscribeEvents => "subscribe_events",
            Self::ScanCatchUp => "scan_catch_up",
            Self::SubmitEvents => "submit_events",
            Self::SecureMessaging => "secure_messaging",
            Self::ResolveResources => "resolve_resources",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::SubscribeEvents => "Subscribe events",
            Self::ScanCatchUp => "Scan catch-up",
            Self::SubmitEvents => "Submit events",
            Self::SecureMessaging => "Secure messaging",
            Self::ResolveResources => "Resolve resources",
        }
    }

    pub fn help(self) -> &'static str {
        match self {
            Self::SubscribeEvents => "Open the self events stream for live delivery.",
            Self::ScanCatchUp => "Query missed events after the runtime reconnects.",
            Self::SubmitEvents => {
                "Fetch the current Realm frontier, issue publication evidence, and submit approved durable writes."
            }
            Self::SecureMessaging => {
                "Publish and consume MLS key packages, receive encrypted device messages, and send encrypted live presence."
            }
            Self::ResolveResources => "Fetch event resources referenced by allowed payloads.",
        }
    }

    pub fn actions(self) -> &'static [&'static str] {
        match self {
            Self::SubscribeEvents => &["ak.self.events.stream.subscribe"],
            Self::ScanCatchUp => &["ak.self.events.read.scan"],
            Self::SubmitEvents => &[
                "ak.self.events.read.frontier",
                "ak.self.authorization_leases.command.issue",
                "ak.self.events.command.submit",
            ],
            Self::SecureMessaging => &[
                "ak.self.keys.keypackages.upload.create",
                "ak.self.keys.keypackages.command.consume",
                // Standard KeyPackage lifecycle is upload|claim|consume|revoke
                // (device-lifecycle §9). The runtime revokes its own published
                // pool on unbind/replacement, and the requested_scope ceiling
                // is immutable after provisioning (key-management §4.5), so
                // revoke must be part of the default ceiling from day one.
                "ak.self.keys.keypackages.command.revoke",
                "ak.self.device_messages.read.list",
                "ak.self.device_messages.command.ack",
                "ak.self.signal.command.send",
            ],
            Self::ResolveResources => &["ak.self.events.resource.get"],
        }
    }
}

pub fn is_pairing_request_expired(expires_at: &str, now: &str) -> bool {
    let Ok(expires_at) =
        chrono::DateTime::parse_from_rfc3339(expires_at).map(|dt| dt.with_timezone(&chrono::Utc))
    else {
        return false;
    };
    let Ok(now) =
        chrono::DateTime::parse_from_rfc3339(now).map(|dt| dt.with_timezone(&chrono::Utc))
    else {
        return false;
    };
    now > expires_at
}

fn push_unique_action(actions: &mut Vec<String>, action: &str) {
    if !actions.iter().any(|existing| existing == action) {
        actions.push(action.to_owned());
    }
}

pub fn content_actions_for_presets(presets: &[AgentGrantPreset]) -> Vec<String> {
    let mut actions = Vec::new();
    for preset in presets {
        for action in preset.actions() {
            push_unique_action(&mut actions, action);
        }
    }
    actions
}

pub fn service_actions_for_presets(presets: &[AgentServiceScopePreset]) -> Vec<String> {
    let mut actions = Vec::new();
    for preset in presets {
        for action in preset.actions() {
            push_unique_action(&mut actions, action);
        }
    }
    actions
}

/// Build the `requested_scope` (`AgentKeyScope`, the spec object
/// `{actions, resources, constraints}`) for the provision call from the
/// selected content presets and runtime service surface. This scope is the
/// Agent's global hard ceiling, not a Realm grant: later Realm grants and
/// participation can only narrow the listed actions. Service actions carry
/// operation selectors; content resources are supplied only by later grants.
pub fn requested_scope_for_presets(
    content_presets: &[AgentGrantPreset],
    service_presets: &[AgentServiceScopePreset],
) -> Option<AgentKeyScope> {
    let content_actions = content_actions_for_presets(content_presets);
    let service_actions = service_actions_for_presets(service_presets);
    if service_actions.is_empty() {
        return None;
    }
    let mut actions: Vec<String> = Vec::new();
    for action in &content_actions {
        push_unique_action(&mut actions, action);
    }
    for action in &service_actions {
        push_unique_action(&mut actions, action);
    }
    if actions.is_empty() {
        return None;
    }

    let resources = service_actions
        .into_iter()
        .map(|action| AgentKeyScopeResource {
            kind: AgentKeyScopeResourceKind::Operation,
            realm_id: None,
            resource_ref: None,
            schema_ref: None,
            operation: Some(action),
            service_id: None,
        })
        .collect();
    let constraints = if content_presets.contains(&AgentGrantPreset::ActOnBehalf) {
        let mut constraint = GrantConstraint::new(
            GrantConstraintKind::ClaimBased,
            GrantConstraintEffect::RequireReview,
        );
        constraint.constraint_subkind = Some(GrantConstraintSubkind::Accountability);
        constraint.applies_to_actions = vec!["ak.message.create".to_owned()];
        constraint.controller_approval_required = Some(true);
        vec![constraint]
    } else {
        Vec::new()
    };
    Some(AgentKeyScope {
        actions,
        resources,
        constraints,
    })
}

/// Builds the runtime-agnostic pairing bootstrap (AKP-0008 §4.4): the six
/// short-lived fields any agent runtime needs to start key pairing. It carries
/// no scope payload — the authoritative ceiling lives in `ak.agent.key.authorize`
/// and the effective-permission intersection, and the requested scope is shown
/// separately in the admin card, not baked into the QR.
pub fn build_agent_pairing_bootstrap_json(
    base_url: &str,
    service_id: &str,
    outcome: &arkret_sdk::AgentProvisionComplete,
) -> serde_json::Result<String> {
    let base_url = base_url.trim_end_matches('/');
    let bootstrap = AgentPairingBootstrap {
        arkret_base_url: base_url.to_owned(),
        service_id: Did::new(service_id.trim().to_owned()).map_err(json_invalid_input)?,
        agent_id: outcome.agent_id.clone(),
        pairing_request_id: outcome.pairing_request_id.clone(),
        pairing_code: outcome.pairing_code.clone().unwrap_or_default(),
        pairing_expires_at: outcome.expires_at,
    };
    serde_json::to_string_pretty(&bootstrap)
}

/// Wraps the bootstrap into a standard HTTPS Universal/App Link whose host is the
/// deployment's `arkret_base_url` (AKP-0008 forbids a custom URI scheme).
/// The fragment carries only a short handoff token; runtimes resolve it through
/// `POST /_arkret/open/agent-pairing/resolve` to obtain the six-field bootstrap.
pub fn build_agent_pairing_deep_link(base_url: &str, pairing_token: &str) -> String {
    let base = base_url.trim_end_matches('/');
    format!("{base}/_arkret/open/agent-pairing/resolve#token={pairing_token}")
}

pub fn build_agent_pairing_handoff_token(pairing_request_id: &str, pairing_code: &str) -> String {
    arkret_sdk::base64url_encode(
        serde_json::to_vec(&json!({
            "r": pairing_request_id,
            "c": pairing_code,
        }))
        .unwrap_or_default(),
    )
}

pub fn render_agent_pairing_qr_svg(deep_link: &str) -> String {
    if deep_link.trim().is_empty() {
        return String::new();
    }
    match qrcode::QrCode::with_error_correction_level(deep_link.as_bytes(), qrcode::EcLevel::M) {
        Ok(code) => code
            .render::<qrcode::render::svg::Color<'_>>()
            .min_dimensions(192, 192)
            .quiet_zone(true)
            .build(),
        Err(_) => String::new(),
    }
}

fn json_invalid_input(error: impl std::fmt::Display) -> serde_json::Error {
    serde_json::Error::io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        error.to_string(),
    ))
}

pub fn into_agent_key_pair_request(
    request: AgentRuntimeApprovalControllerProjection,
    requested_scope_disclosure: AgentRequestedScopeDisclosure,
    authorize_event: arkret_wire::EventInitialSubmission,
    signing_key_binding: AgentSigningKeyBinding,
) -> AgentKeyPairRequestBody {
    AgentKeyPairRequestBody {
        pairing_request_id: request.pairing_request_id,
        agent_id: request.agent_id,
        verification_method: request.verification_method,
        public_key: request.public_key,
        proof_of_possession: request.proof_of_possession,
        requested_scope_disclosure,
        runtime_attestation: request.runtime_attestation,
        authorize_event,
        signing_key_binding,
    }
}

pub fn build_requested_scope_disclosure_for_pairing(
    controller_id: &str,
    service_full_id: &str,
    key_state: &KeyState,
    request: &AgentRuntimeApprovalControllerProjection,
) -> anyhow::Result<AgentRequestedScopeDisclosure> {
    let controller_id = Did::new(controller_id.trim().to_owned())?;
    let agent_id = request.agent_id.clone();
    let controller_actor_id =
        arkret_sdk::ActorId::from(arkret_sdk::project_full_id_to_core_id(&controller_id)?);
    let agent_actor_id =
        arkret_sdk::ActorId::from(arkret_sdk::project_full_id_to_core_id(&agent_id)?);
    if key_state.controller_id != controller_actor_id {
        anyhow::bail!("agent key_state.controller_id does not match the signed-in controller");
    }
    if key_state.agent_id != agent_actor_id {
        anyhow::bail!("runtime request agent_id does not match this agent key state");
    }
    let pairing_request_id = key_state
        .pairing_request_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("agent key_state.pairing_request_id is required"))?;
    if pairing_request_id != &request.pairing_request_id {
        anyhow::bail!("runtime request pairing_request_id does not match this agent");
    }
    let request_uuid = pairing_request_id
        .as_str()
        .strip_prefix("agent_pairing_request:")
        .ok_or_else(|| anyhow::anyhow!("agent pairing_request_id is invalid"))?;
    let requested_scope = key_state.requested_scope.clone();
    let requested_scope_digest = arkret_signatures::agent::agent_requested_scope_digest(
        &agent_id,
        &controller_id,
        &requested_scope,
    )?;
    if requested_scope_digest != key_state.requested_scope_digest {
        anyhow::bail!("agent key_state requested_scope digest does not match its trusted scope");
    }
    let verifier_did = arkret_sdk::FullId::new(service_full_id.trim().to_owned())?;
    let verifier_service_id =
        arkret_sdk::ServiceId::from(arkret_sdk::project_full_id_to_core_id(&verifier_did)?);
    if request.proof_of_possession.audience != verifier_service_id {
        anyhow::bail!("runtime request audience does not match the current service");
    }
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("no active device signer is available"))?;
    let verification_method = arkret_sdk::DidUrl::new(
        signer
            .device_id()
            .map(|device_id| format!("{}#{device_id}", controller_id.as_str()))
            .unwrap_or_else(|| signer.verification_method().to_owned()),
    )
    .map_err(|error| anyhow::anyhow!("agent disclosure verification method is invalid: {error}"))?;
    let issued_at = crate::clock::now_utc();
    let expires_at = std::cmp::min(
        issued_at + chrono::Duration::minutes(5),
        request.proof_of_possession.expires_at,
    );
    if expires_at <= issued_at {
        anyhow::bail!("runtime key request has expired");
    }
    let mut disclosure = AgentRequestedScopeDisclosure {
        schema: arkret_sdk::SchemaId::AgentRequestedScopeDisclosureV1,
        request_id: RequestId::new(format!("ak:request:{request_uuid}"))?,
        agent_id,
        controller_id,
        requested_scope,
        requested_scope_digest,
        verifier_did,
        audience: NonEmptyString::new("ak.gate.account.command.pair_agent_key")
            .map_err(anyhow::Error::msg)?,
        challenge: NonEmptyString::new(pairing_request_id.as_str().to_owned())
            .map_err(anyhow::Error::msg)?,
        issued_at,
        expires_at,
        proofs: vec![Proof {
            kind: "detached_jws".to_owned(),
            verification_method: verification_method.clone(),
            event_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            created_at: issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: String::new(),
        }],
    };
    disclosure.proofs[0].event_digest = disclosure.payload_digest()?;
    let binding = disclosure.canonical_proof_binding_bytes(&disclosure.proofs[0])?;
    disclosure.proofs[0].jws =
        signer.detached_jws_over_payload_with_kid(&verification_method, &binding)?;
    disclosure.validate()?;
    Ok(disclosure)
}

pub fn parse_runtime_key_approval_request(
    raw: &str,
) -> anyhow::Result<AgentRuntimeApprovalControllerProjection> {
    let request: AgentRuntimeApprovalControllerProjection = serde_json::from_str(raw.trim())?;
    Ok(request)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeKeyApprovalSummary {
    pub pairing_request_id: OpaqueLocalId,
    pub agent_id: Did,
    pub verification_method: DidUrl,
    pub public_key_fingerprint: Hash,
    pub proof_expires_at: String,
}

pub fn summarize_runtime_key_approval_request(
    raw: &str,
) -> anyhow::Result<RuntimeKeyApprovalSummary> {
    let request = parse_runtime_key_approval_request(raw)?;
    let public_key_fingerprint = arkret_signatures::agent::validate_agent_runtime_public_key(
        &request.public_key,
        &request.verification_method,
    )?
    .runtime_request_digest;
    let proof_expires_at =
        arkret_sdk::canonical::format_timestamp_canonical(request.proof_of_possession.expires_at);
    Ok(RuntimeKeyApprovalSummary {
        pairing_request_id: request.pairing_request_id,
        agent_id: request.agent_id,
        verification_method: request.verification_method,
        public_key_fingerprint,
        proof_expires_at,
    })
}

pub fn runtime_key_pairing_error_message(error: impl std::fmt::Display) -> String {
    let error = error.to_string();
    let normalized = error.to_ascii_lowercase();
    let message = if normalized.contains("expired")
        || normalized.contains("pairing_request_expired")
    {
        "Pairing expired. Create a new pairing and paste the fresh runtime key request."
    } else if normalized.contains("pairing_request_id")
        || normalized.contains("pairing code")
        || normalized.contains("different agent")
        || normalized.contains("request_canonical_digest")
    {
        "Wrong pairing request or code. Use the bootstrap from this agent and paste the matching runtime key request."
    } else if normalized.contains("public_key.kid")
        || normalized.contains("verification_method")
        || normalized.contains("runtime public_key")
        || normalized.contains("proof")
    {
        "Runtime key mismatch. Regenerate the runtime key request from the same runtime key and bootstrap."
    } else if normalized.contains("controller") || normalized.contains("accountable") {
        "Controller mismatch. Sign in as this agent's controller and retry."
    } else {
        "Server rejected the runtime key approval. Refresh the agent, regenerate the runtime key request, and retry."
    };
    message.to_owned()
}

pub struct AgentKeyAuthorizationForPairing {
    pub authorize_event: Event,
    pub signing_key_binding: AgentSigningKeyBinding,
}

pub fn build_agent_key_authorization_for_pairing(
    controller_id: &str,
    service_id: &str,
    key_state: &KeyState,
    request: &AgentRuntimeApprovalControllerProjection,
) -> anyhow::Result<AgentKeyAuthorizationForPairing> {
    let controller = Did::new(controller_id.trim().to_owned())?;
    let controller_actor_id =
        arkret_sdk::ActorId::from(arkret_sdk::project_full_id_to_core_id(&controller)?);
    if key_state.controller_id != controller_actor_id {
        anyhow::bail!("agent key_state.controller_id does not match the signed-in controller");
    }
    let request_agent_actor_id =
        arkret_sdk::ActorId::from(arkret_sdk::project_full_id_to_core_id(&request.agent_id)?);
    if request_agent_actor_id != key_state.agent_id {
        anyhow::bail!("runtime request agent_id does not match this agent key state");
    }
    if key_state.pairing_request_id.as_ref() != Some(&request.pairing_request_id) {
        anyhow::bail!("runtime request pairing_request_id does not match this agent");
    }
    let pairing_code = key_state
        .pairing_code
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("agent key_state.pairing_code is required"))?;
    let pairing_expires_at = key_state
        .pairing_expires_at
        .ok_or_else(|| anyhow::anyhow!("agent key_state.pairing_expires_at is required"))?;
    let requested_scope = key_state.requested_scope.clone();
    let validated_runtime_public_key = arkret_signatures::agent::validate_agent_runtime_public_key(
        &request.public_key,
        &request.verification_method,
    )?;
    let endpoint_fragment = request
        .verification_method
        .as_str()
        .split_once('#')
        .map(|(_, fragment)| fragment)
        .ok_or_else(|| anyhow::anyhow!("runtime verification_method has no endpoint fragment"))?;
    arkret_sdk::DeviceId::new(endpoint_fragment.to_owned()).map_err(|error| {
        anyhow::anyhow!(
            "runtime verification_method fragment must be the stable Agent endpoint device_id: {error}"
        )
    })?;
    let pairing_digest =
        arkret_models_collaboration::agent_operations::agent_key_pairing_request_binding_digest(
            arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY,
            &controller,
            &request.agent_id,
            &request.pairing_request_id,
            pairing_code,
            pairing_expires_at,
            &arkret_sdk::ServiceId::new(service_id.trim().to_owned())?,
            &request.proof_of_possession.runtime_key_binding_digest,
            &request.proof_of_possession,
        )?;
    let issued_at = chrono::DateTime::<Utc>::from_timestamp_millis(Utc::now().timestamp_millis())
        .expect("current UTC timestamp must fit the canonical millisecond wire range");
    let runtime_attestation = request.runtime_attestation.clone();
    // Runtime replacement re-pairing (key-management §3.6.1): the new key
    // supersedes EVERY currently-accepted active authorization of this agent.
    // coauth's `validate_authorize_event_supersedes` requires the supplied set
    // to equal the authoritative `active_authorizations` exactly — including an
    // authorization that shares this key_id/verification_method (runtime keys
    // always use `#runtime-1`, so a re-pair's old authorization has the same
    // key_id but a different authorized_event_ref). Filtering by key_id dropped
    // that old authorization, producing an empty `supersedes` that failed the
    // exact-match check with a CONFLICT ("Server rejected the runtime key
    // approval"). Supersede all active authorizations, keyed by their distinct
    // authorized_event_ref.
    let supersedes = if !key_state.active_authorizations.is_empty() {
        key_state
            .active_authorizations
            .iter()
            .map(|authorization| AgentKeySupersession {
                key_id: authorization.key_id.clone(),
                authorized_event_ref: authorization.authorized_event_ref.clone(),
            })
            .collect()
        // A keyed agent — projected on the runtime readiness axis as ready or
        // replacing (key-management.md §3.6.1), never the lifecycle status which
        // now reads "active" for a never-keyed bootstrap agent too — MUST expose
        // its authoritative active_authorizations so the replacement supersedes
        // them exactly. A bootstrap pairing (pending_runtime_key / pairing_expired)
        // legitimately has none.
    } else if matches!(
        key_state_runtime_state(key_state),
        AgentRuntimeState::Ready | AgentRuntimeState::Replacing
    ) {
        anyhow::bail!("keyed agent key_state must expose authoritative active_authorizations")
    } else {
        Vec::new()
    };
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("no active controller signer is available"))?;
    let controller_verification_method = DidUrl::new(
        signer
            .device_id()
            .map(|device_id| format!("{}#{device_id}", controller.as_str()))
            .unwrap_or_else(|| signer.verification_method().to_owned()),
    )
    .map_err(anyhow::Error::msg)?;
    let agent_key_id = NonEmptyString::new(request.verification_method.as_str().to_owned())
        .map_err(anyhow::Error::msg)?;
    let signing_key_binding_core =
        arkret_signatures::agent_evidence::prepare_agent_signing_key_binding_core(
            arkret_sdk::ActorId::from(arkret_sdk::project_full_id_to_core_id(&request.agent_id)?),
            agent_key_id.clone(),
            request.verification_method.clone(),
            &request.public_key,
            issued_at,
            None,
            controller_actor_id.clone(),
        )
        .map_err(|reason| anyhow::anyhow!(reason.as_str()))?;
    let signing_key_binding_digest =
        arkret_signatures::agent_evidence::agent_signing_key_binding_core_digest(
            &signing_key_binding_core,
        )
        .map_err(|reason| anyhow::anyhow!(reason.as_str()))?;
    let payload = AgentKeyAuthorizePayload {
        agent_id: request.agent_id.clone(),
        key_id: agent_key_id.clone(),
        verification_method: request.verification_method.clone(),
        public_key_digest: validated_runtime_public_key.authorization_digest,
        signing_key_binding_digest,
        accountable_principal_id: controller.clone(),
        agent_key_scope: requested_scope,
        audience: vec![service_id.to_owned()],
        issued_at,
        // Longevity-safe default: no expiry, the authorization is governed
        // by revocation (key-management.md §3.6.1).
        expires_at: None,
        approval_evidence: AgentKeyApprovalEvidence {
            kind: AgentKeyApprovalEvidenceKind::PairingRequest,
            evidence_ref: None,
            request_canonical_digest: Some(Hash::new(pairing_digest.as_str().to_owned())?),
            pairing_request_id: Some(request.pairing_request_id.clone()),
            approved_by: Some(controller.clone()),
        },
        supersedes,
        revocation_check_ref: None,
        runtime_attestation,
    };
    let realm_id = key_state.principal_control_realm_id.clone();
    let authorization_ref = key_state.controller_authorization_ref.clone();
    let hlc = crate::signing_stamp::issue_protocol_hlc_for_active_device(
        controller_actor_id.as_str(),
        realm_id.as_str(),
    )?;
    let mut event = arkret_event_draft::build_agent_key_authorize_event(
        &payload,
        arkret_sdk::ScopeRef::Realm { realm_id },
        arkret_sdk::ActorId::from(arkret_sdk::project_full_id_to_core_id(&request.agent_id)?),
        controller_actor_id,
        authorization_ref,
        1,
        hlc,
    )?;
    let signing_key_binding_to_sign =
        arkret_signatures::agent_evidence::materialize_agent_signing_key_binding(
            signing_key_binding_core,
            event.event_id.clone(),
            controller_verification_method.clone(),
        )
        .map_err(|reason| anyhow::anyhow!(reason.as_str()))?;
    let binding_bytes = arkret_signatures::agent_evidence::agent_signing_key_binding_to_sign_bytes(
        &signing_key_binding_to_sign,
    )
    .map_err(|reason| anyhow::anyhow!(reason.as_str()))?;
    let controller_jws = signer.detached_jws_over_payload_with_kid(
        controller_verification_method.as_str(),
        &binding_bytes,
    )?;
    let signing_key_binding = arkret_signatures::agent_evidence::finish_agent_signing_key_binding(
        signing_key_binding_to_sign,
        &controller_jws,
    )
    .map_err(|reason| anyhow::anyhow!(reason.as_str()))?;
    event.unsigned.insert(
        "pairing_request_id".to_owned(),
        json!(request.pairing_request_id),
    );
    event.unsigned.insert(
        "agent_signing_key_binding".to_owned(),
        serde_json::to_value(&signing_key_binding)?,
    );
    Ok(AgentKeyAuthorizationForPairing {
        authorize_event: event,
        signing_key_binding,
    })
}

pub fn build_agent_key_authorize_event_for_pairing(
    controller_id: &str,
    service_id: &str,
    key_state: &KeyState,
    request: &AgentRuntimeApprovalControllerProjection,
) -> anyhow::Result<Event> {
    Ok(
        build_agent_key_authorization_for_pairing(controller_id, service_id, key_state, request)?
            .authorize_event,
    )
}

/// Expand one preset into a canonical `ak.capability.grant` object for
/// `ak.self.agent.grant.command.attach`. The agent principal id is the
/// grant `subject`; `realm_id` scopes it; `expires_at` (RFC3339 Z)
/// bounds the TTL. This is a separate Realm-scoped grant and is never
/// materialized by provisioning.
///
/// `act_on_behalf` additionally attaches a `claim_based` /
/// `accountability` constraint (`controller_approval_required=true`) per
/// §4.10 so the high-risk executor path cannot run without controller
/// approval.
/// R3 spec sync (b47ff6ec) — UI label for an agent FSM state.
///
/// `ak.agent.{pause,resume,deactivate}` lattice is now `fsm` (terminal:
/// `deactivated`). The badge text mirrors the wire vocabulary; unknown
/// values fall through so future state additions are still legible.
pub fn agent_state_label(state: &str) -> &str {
    match state {
        "pending" | "pending_runtime_key" => "Awaiting runtime",
        "ready" => "Ready",
        "replacing" => "Awaiting replacement runtime",
        "active" => "Active",
        "pairing_expired" => "Pairing expired",
        "paused" => "Paused",
        "deactivated" => "Deactivated",
        other => other,
    }
}

/// R3 — badge CSS class for an agent FSM state. Mirrors the chip
/// palette already used for actor_kind: active = green, paused = amber,
/// deactivated = red.
pub fn agent_state_badge_class(state: &str) -> &'static str {
    match state {
        "pending" | "pending_runtime_key" => "badge amber",
        "ready" => "badge green",
        "replacing" => "badge amber",
        "active" => "badge green",
        "pairing_expired" => "badge red",
        "paused" => "badge amber",
        "deactivated" => "badge red",
        _ => "badge",
    }
}

/// R3 — whether the agent admin list should hide this row by default.
/// `deactivated` is terminal and hidden from ordinary UI filters. A direct
/// `?filter=deactivated` audit deep link can still reveal those records.
pub fn agent_state_is_terminal(state: &str) -> bool {
    state == "deactivated"
}

/// State machine for the action_approve dialog. The dialog gates the
/// controller's review of an incoming `ak.agent.action_request`
/// notification (digest + expiry + single-use nonce status) before a
/// `ak.agent.action_approve` event is published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionApproveDialogState {
    /// No request to review.
    Idle,
    /// Dialog open; controller is reviewing payload + nonce + expiry.
    Reviewing,
    /// Controller confirmed; an approve event is being submitted.
    Submitting,
    /// Approve event landed; dialog can close.
    Submitted,
    /// Controller explicitly rejected (or a `ak.agent.action_reject`
    /// is being submitted).
    Rejected,
    /// The single-use nonce was already consumed by another approve
    /// or the expiry passed.
    NonceExhausted,
}

impl ActionApproveDialogState {
    pub fn as_data_state(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Reviewing => "reviewing",
            Self::Submitting => "submitting",
            Self::Submitted => "submitted",
            Self::Rejected => "rejected",
            Self::NonceExhausted => "nonce_exhausted",
        }
    }
}

/// Returns true when the per-request expiry timestamp has already
/// passed. The dialog must refuse to submit an approve event once
/// expiry elapses (AKP-0008 §4 action_request invariants).
pub fn is_action_request_expired(expires_at: &str, now: &str) -> bool {
    // Both arguments are RFC3339 timestamps emitted by the SDK
    // event-canonicalizer; do a lexicographic compare on UTC ISO-8601
    // strings as a safe baseline. TODO(P3-impl): swap to chrono
    // DateTime parsing once the timezone normalization path is
    // settled.
    !expires_at.is_empty() && !now.is_empty() && now > expires_at
}

/// Single-use nonce status. The reducer is the source of truth — the
/// UI displays a hint here so the controller can see whether their
/// approval would race a duplicate submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionRequestNonceStatus {
    /// Unused — safe to approve.
    Fresh,
    /// Already consumed by a previous approve / reject.
    Consumed,
    /// Server has not projected the nonce yet (UI should treat as
    /// `fresh` for display but flag it to the controller).
    Unknown,
}

impl ActionRequestNonceStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Consumed => "consumed",
            Self::Unknown => "unknown",
        }
    }

    pub fn badge_class(self) -> &'static str {
        match self {
            Self::Fresh => "badge green",
            Self::Consumed => "badge red",
            Self::Unknown => "badge",
        }
    }
}

pub(crate) fn agent_view_from_directory_row(row: AgentProjection) -> Option<AgentView> {
    if row.agent_id.as_str().trim().is_empty() {
        return None;
    }
    Some(AgentView {
        agent: row,
        grants: Vec::new(),
        key_state: None,
    })
}

pub(crate) fn agent_projection_runtime_state(row: &AgentProjection) -> AgentRuntimeState {
    if row.readiness.state == AgentReadinessState::Ready {
        return AgentRuntimeState::Ready;
    }
    let key_missing = row
        .readiness
        .blockers
        .contains(&AgentReadinessBlocker::RuntimeKeyMissing);
    let pairing_open = row
        .readiness
        .blockers
        .contains(&AgentReadinessBlocker::PairingOpen);
    AgentRuntimeState::derive(!key_missing, pairing_open)
}

pub(crate) fn key_state_runtime_state(key_state: &KeyState) -> AgentRuntimeState {
    let has_active_authorization = !key_state.active_authorizations.is_empty();
    let has_open_pairing = key_state.pairing_request_id.is_some()
        && key_state
            .pairing_expires_at
            .is_some_and(|expires_at| expires_at > crate::clock::now_utc());
    AgentRuntimeState::derive(has_active_authorization, has_open_pairing)
}

/// Wire string for the lifecycle intent axis (`status`, schema `agent_status`).
pub(crate) fn agent_lifecycle_wire(status: AgentLifecycleState) -> &'static str {
    status.as_wire_str()
}

/// Wire string for the derived runtime readiness axis (`runtime_state`, schema
/// `agent_runtime_state`).
pub(crate) fn agent_runtime_state_wire(runtime_state: AgentRuntimeState) -> &'static str {
    runtime_state.as_wire_str()
}

/// Build the controller-owned agent identity index used by compact member
/// surfaces and mention pickers. Terminal and unusable pairing rows are not
/// candidates; the Realm roster remains responsible for deciding which of
/// these account-global agents is actually a member of the current Realm.
pub(crate) fn mentionable_owned_agent_slugs(
    agents: impl IntoIterator<Item = AgentProjection>,
) -> std::collections::BTreeMap<String, String> {
    agents
        .into_iter()
        .filter(|agent| {
            // Terminal lifecycle intent (deactivated) or a never-keyed agent
            // whose bootstrap window lapsed (runtime_state pairing_expired) is
            // not a mention candidate (key-management.md §3.6.1).
            agent.lifecycle != AgentLifecycleState::Deactivated
                && agent_projection_runtime_state(agent) != AgentRuntimeState::PairingExpired
        })
        .filter_map(|agent| {
            let agent_id = agent.agent_id.as_str().trim();
            let slug = agent.slug.trim();
            if agent_id.is_empty()
                || slug.is_empty()
                || arkret_models_identity::validate_agent_slug(slug).is_err()
            {
                return None;
            }
            Some((agent_id.to_owned(), slug.to_owned()))
        })
        .collect()
}

/// Hash pasted draft content or action request payload fragments.
/// Return a sha256 digest for canonical JSON.
fn canonical_digest(value: &Value) -> Option<String> {
    arkret_sdk::canonical::canonical_json_bytes(value)
        .map(arkret_sdk::canonical::sha256_digest)
        .ok()
}

fn non_empty_field(payload: &Value, field: &str) -> Option<String> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

/// Build a `ak.agent.action_approve` payload for a controller-owned
/// draft or action request using the current schema fields.
pub fn build_action_approve_payload(
    request: &Value,
    controller_id: &str,
    approved_at: &str,
    expires_at: &str,
) -> anyhow::Result<arkret_sdk::AgentActionApprovePayload> {
    let draft_content_digest = request.get("content").and_then(canonical_digest);
    let approved_payload_digest = non_empty_field(request, "approved_payload_digest")
        .or_else(|| non_empty_field(request, "request_canonical_digest"))
        .or_else(|| draft_content_digest.clone())
        .unwrap_or_default();
    let agent_id = request
        .get("agent_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let proposed_action = request
        .get("proposed_action")
        .and_then(Value::as_str)
        .unwrap_or("");
    let target = request
        .get("target")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("agent action approval requires target"))?;
    Ok(arkret_sdk::AgentActionApprovePayload {
        approval_id: format!("ak:agent_approval:{}", crate::operation::uuid_v7()),
        request_id: non_empty_field(request, "request_id"),
        draft_id: non_empty_field(request, "draft_id"),
        agent_id: arkret_sdk::Did::new(agent_id.to_owned())?,
        controller_id: arkret_sdk::Did::new(controller_id.to_owned())?,
        proposed_action: proposed_action.to_owned(),
        target: serde_json::from_value(target)?,
        approved_payload_digest: arkret_sdk::Hash::new(approved_payload_digest)?,
        draft_content_digest: draft_content_digest
            .map(arkret_sdk::Hash::new)
            .transpose()?,
        approval_nonce: crate::operation::uuid_v7(),
        approved_at: chrono::DateTime::parse_from_rfc3339(approved_at)?.with_timezone(&chrono::Utc),
        expires_at: chrono::DateTime::parse_from_rfc3339(expires_at)?.with_timezone(&chrono::Utc),
    })
}

/// Build a `ak.agent.action_reject` payload for a draft or action
/// request. A human-entered reason is included when present.
pub fn build_action_reject_payload(
    request: &Value,
    controller_id: &str,
    rejected_at: &str,
    reason: Option<&str>,
) -> anyhow::Result<arkret_sdk::AgentActionRejectPayload> {
    Ok(arkret_sdk::AgentActionRejectPayload {
        rejection_id: format!("ak:agent_rejection:{}", crate::operation::uuid_v7()),
        request_id: non_empty_field(request, "request_id"),
        draft_id: non_empty_field(request, "draft_id"),
        agent_id: arkret_sdk::Did::new(
            request
                .get("agent_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
        )?,
        controller_id: arkret_sdk::Did::new(controller_id.to_owned())?,
        reason: reason
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        rejected_at: chrono::DateTime::parse_from_rfc3339(rejected_at)?.with_timezone(&chrono::Utc),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_act_on_behalf_message_operation(
    realm_id: &str,
    controller_id: &str,
    agent_id: &str,
    authorization_ref: &str,
    strand_id: &str,
    body: &str,
) -> anyhow::Result<arkret_sdk::Event> {
    let strand_id_typed = arkret_sdk::StrandId::new(strand_id.to_owned())
        .map_err(|error| anyhow::anyhow!("invalid strand id {strand_id:?}: {error:?}"))?;
    let content = arkret_sdk::ContentBlock::text(body);
    let mut payload =
        arkret_sdk::MessageCreatePayload::with_content(strand_id_typed, "discussion", content);
    payload.agent_context = Some(arkret_sdk::MessageAgentContext {
        agent_id: arkret_sdk::Did::new(agent_id.to_owned())?,
        operator_or_controller: controller_id.to_owned(),
        execution_purpose: "act_on_behalf".to_owned(),
        authorization_ref: authorization_ref.to_owned(),
    });
    crate::operation::TypedOperationBuilder::new::<arkret_sdk::event_spec::MessageCreate>(
        realm_id,
        controller_id,
        payload,
    )
    .target_ref(strand_id)
    .executed_by(agent_id)
    .authorization_ref(authorization_ref)
    .build_sdk_event("inkson")
}
