//! Personal-agent data types, presets, and lifecycle helpers.
//!
//! These items carry no RSX; they are the unit-testable core behind the
//! personal-agent administration surfaces.

use arkret_sdk::models::{
    AgentKeyScope, AgentKeyScopeResource, AgentKeyScopeResourceKind, AgentParticipation,
    AgentProjection, AgentStatus, AgentView,
};
use arkret_sdk::{
    AgentKeyApprovalEvidence, AgentKeyApprovalEvidenceKind, AgentKeyAuthorizePayload,
    AgentKeyAuthorizePayloadRuntimeAttestation, AgentKeyPairRequestBody, AgentKeySupersession,
    AgentPairingBootstrap, Did, DidUrl, Event, EventId, GrantConstraint, GrantConstraintEffect,
    GrantConstraintSubtype, GrantConstraintType, Hash, NonEmptyJsonObject, NonEmptyString,
    PublicKey, RealmId,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

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
    ResolveResources,
}

impl AgentServiceScopePreset {
    pub const ALL: [AgentServiceScopePreset; 4] = [
        Self::SubscribeEvents,
        Self::ScanCatchUp,
        Self::SubmitEvents,
        Self::ResolveResources,
    ];

    pub const DEFAULTS: [AgentServiceScopePreset; 3] =
        [Self::SubscribeEvents, Self::ScanCatchUp, Self::SubmitEvents];

    pub fn preset_name(self) -> &'static str {
        match self {
            Self::SubscribeEvents => "subscribe_events",
            Self::ScanCatchUp => "scan_catch_up",
            Self::SubmitEvents => "submit_events",
            Self::ResolveResources => "resolve_resources",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::SubscribeEvents => "Subscribe events",
            Self::ScanCatchUp => "Scan catch-up",
            Self::SubmitEvents => "Submit events",
            Self::ResolveResources => "Resolve resources",
        }
    }

    pub fn help(self) -> &'static str {
        match self {
            Self::SubscribeEvents => "Open the self events stream for live delivery.",
            Self::ScanCatchUp => "Query missed events after the runtime reconnects.",
            Self::SubmitEvents => "Call the durable submit endpoint for approved writes.",
            Self::ResolveResources => "Fetch event resources referenced by allowed payloads.",
        }
    }

    pub fn actions(self) -> &'static [&'static str] {
        match self {
            Self::SubscribeEvents => &["ak.self.events.stream.subscribe"],
            Self::ScanCatchUp => &["ak.self.events.query.scan"],
            Self::SubmitEvents => &["ak.self.events.command.submit"],
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
            GrantConstraintType::ClaimBased,
            GrantConstraintEffect::RequireReview,
        );
        constraint.subtype = Some(GrantConstraintSubtype::Accountability);
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
    outcome: &arkret_sdk::AgentProvisionOutcome,
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

#[derive(Clone, Debug, Deserialize)]
pub struct RuntimeKeyApprovalRequest {
    pub pairing_request_id: NonEmptyString,
    pub agent_id: Did,
    pub verification_method: DidUrl,
    pub public_key: PublicKey,
    pub proof_of_possession: NonEmptyJsonObject,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<AgentKeyAuthorizePayloadRuntimeAttestation>,
}

impl RuntimeKeyApprovalRequest {
    pub fn into_pair_request(self, authorize_event: Event) -> AgentKeyPairRequestBody {
        AgentKeyPairRequestBody {
            pairing_request_id: self.pairing_request_id,
            agent_id: self.agent_id,
            verification_method: self.verification_method,
            public_key: self.public_key,
            proof_of_possession: self.proof_of_possession,
            runtime_attestation: self.runtime_attestation,
            authorize_event,
        }
    }
}

pub fn parse_runtime_key_approval_request(raw: &str) -> anyhow::Result<RuntimeKeyApprovalRequest> {
    let request: RuntimeKeyApprovalRequest = serde_json::from_str(raw.trim())?;
    Ok(request)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeKeyApprovalSummary {
    pub pairing_request_id: String,
    pub agent_id: String,
    pub verification_method: String,
    pub public_key_fingerprint: String,
    pub proof_expires_at: String,
}

pub fn summarize_runtime_key_approval_request(
    raw: &str,
) -> anyhow::Result<RuntimeKeyApprovalSummary> {
    let request = parse_runtime_key_approval_request(raw)?;
    let public_key_fingerprint = arkret_sdk::agent_runtime_public_key_digest(&request.public_key)?
        .as_str()
        .to_owned();
    let proof_expires_at = request
        .proof_of_possession
        .as_map()
        .get("expires_at")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Ok(RuntimeKeyApprovalSummary {
        pairing_request_id: request.pairing_request_id.as_str().to_owned(),
        agent_id: request.agent_id.to_string(),
        verification_method: request.verification_method.as_str().to_owned(),
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
    format!("{message} Detail: {error}")
}

fn key_state_str<'a>(key_state: &'a Value, key: &str) -> anyhow::Result<&'a str> {
    key_state
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("agent key_state.{key} is required"))
}

pub fn build_agent_key_authorize_event_for_pairing(
    controller_id: &str,
    service_id: &str,
    key_state: &Value,
    request: &RuntimeKeyApprovalRequest,
) -> anyhow::Result<arkret_sdk::Event> {
    let controller = Did::new(controller_id.trim().to_owned())?;
    if key_state_str(key_state, "controller_id")? != controller.as_str() {
        anyhow::bail!("agent key_state.controller_id does not match the signed-in controller");
    }
    if request.agent_id.as_str() != key_state_str(key_state, "agent_id")? {
        anyhow::bail!("runtime request agent_id does not match this agent key state");
    }
    if request.pairing_request_id.as_str() != key_state_str(key_state, "pairing_request_id")? {
        anyhow::bail!("runtime request pairing_request_id does not match this agent");
    }
    let pairing_code = key_state_str(key_state, "pairing_code")?;
    let pairing_expires_at = key_state_str(key_state, "pairing_expires_at")?;
    let requested_scope: AgentKeyScope = serde_json::from_value(
        key_state
            .get("requested_scope")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("agent key_state.requested_scope is required"))?,
    )?;
    let runtime_public_key_digest =
        arkret_sdk::agent_runtime_public_key_digest(&request.public_key)?;
    let runtime_public_key = request.public_key.clone();
    if runtime_public_key.kid.as_str() != request.verification_method.as_str() {
        anyhow::bail!("runtime request public_key.kid does not match verification_method");
    }
    let pairing_digest = arkret_sdk::agent_key_pairing_request_binding_digest(
        &controller,
        &request.agent_id,
        &request.verification_method,
        &runtime_public_key_digest,
        request.pairing_request_id.as_str(),
        pairing_code,
        pairing_expires_at,
        service_id,
    )?;
    let issued_at = Utc::now();
    let runtime_attestation = request.runtime_attestation.clone();
    let supersedes = match key_state.get("active_authorizations") {
        Some(Value::Array(authorizations)) => authorizations
            .iter()
            .filter(|authorization| {
                authorization.get("key_id").and_then(Value::as_str)
                    != Some(request.verification_method.as_str())
            })
            .map(|authorization| {
                Ok(AgentKeySupersession {
                    key_id: key_state_str(authorization, "key_id")?.to_owned(),
                    authorized_event_ref: EventId::new(
                        key_state_str(authorization, "authorized_event_ref")?.to_owned(),
                    )?,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
        Some(_) => anyhow::bail!("agent key_state.active_authorizations must be an array"),
        None if matches!(
            key_state.get("status").and_then(Value::as_str),
            Some("active" | "paused")
        ) =>
        {
            anyhow::bail!("active agent key_state must expose authoritative active_authorizations")
        }
        None => Vec::new(),
    };
    let payload = AgentKeyAuthorizePayload {
        agent_id: request.agent_id.clone(),
        key_id: request.verification_method.as_str().to_owned(),
        verification_method: request.verification_method.as_str().to_owned(),
        public_key_digest: Some(Hash::new(runtime_public_key_digest.as_str().to_owned())?),
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
            pairing_request_id: Some(request.pairing_request_id.as_str().to_owned()),
            approved_by: Some(controller.clone()),
        },
        supersedes,
        revocation_check_ref: None,
        runtime_attestation,
    };
    let realm_id = RealmId::new(key_state_str(key_state, "principal_control_realm_id")?)?;
    let authorization_ref = key_state_str(key_state, "controller_authorization_ref")?;
    let hlc = crate::signing_stamp::issue_protocol_hlc_for_active_device(
        controller.as_str(),
        realm_id.as_str(),
    )?;
    let mut event = arkret_sdk::agent::build_agent_key_authorize_event(
        &payload,
        realm_id,
        request.agent_id.clone(),
        controller,
        authorization_ref,
        1,
        hlc,
    )?;
    event.unsigned.insert(
        "pairing_request_id".to_owned(),
        json!(request.pairing_request_id),
    );
    Ok(event)
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
pub fn expand_preset_grant(
    preset: AgentGrantPreset,
    agent_id: &str,
    realm_id: Option<&str>,
    expires_at: &str,
) -> Value {
    let actions: Vec<&str> = preset.actions().to_vec();
    // Resource selector: scope every preset grant to the Realm when one
    // is supplied; otherwise leave `resources` empty so the controller
    // narrows it after provisioning (soland fail-closes an empty
    // selector for write actions).
    let resources: Vec<Value> = match realm_id {
        Some(realm) if !realm.trim().is_empty() => vec![json!({
            "kind": "realm",
            "realm_id": realm.trim(),
        })],
        _ => Vec::new(),
    };
    let mut grant = json!({
        "actions": actions,
        "resources": resources,
        "subject": agent_id,
        "expires_at": expires_at,
    });
    if preset == AgentGrantPreset::ActOnBehalf {
        grant["constraints"] = json!([
            {
                "constraint_type": "claim_based",
                "effect": "require_review",
                "subtype": "accountability",
                "applies_to_actions": ["ak.message.create"],
                "controller_approval_required": true,
            }
        ]);
    }
    grant
}

/// R3 spec sync (b47ff6ec) — UI label for an agent FSM state.
///
/// `ak.agent.{pause,resume,deactivate}` lattice is now `fsm` (terminal:
/// `deactivated`). The badge text mirrors the wire vocabulary; unknown
/// values fall through so future state additions are still legible.
pub fn agent_state_label(state: &str) -> &str {
    match state {
        "pending" | "pending_runtime_key" => "Pending",
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

pub fn participation_ceiling_reason(
    selection: AgentParticipation,
    ceiling: AgentParticipation,
) -> String {
    let mut blocked = Vec::new();
    if selection.reply && !ceiling.reply {
        blocked.push("reply capped by governance ceiling");
    }
    if selection.accept_third_party_mention && !ceiling.accept_third_party_mention {
        blocked.push("third-party mentions capped by governance ceiling");
    }
    if selection.act_on_behalf && !ceiling.act_on_behalf {
        blocked.push("act-on-behalf capped by governance ceiling");
    }

    if blocked.is_empty() {
        "ceiling reason: no selected participation bit is capped".to_owned()
    } else {
        format!("ceiling reason: {}", blocked.join("; "))
    }
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
    let status = row.status;
    Some(AgentView {
        agent: row,
        status,
        grants: Vec::new(),
        key_state: None,
    })
}

/// Wire string for an `AgentStatus` (matches the schema `agent_status` enum).
pub(crate) fn agent_status_wire(status: AgentStatus) -> &'static str {
    match status {
        AgentStatus::PendingRuntimeKey => "pending_runtime_key",
        AgentStatus::Active => "active",
        AgentStatus::PairingExpired => "pairing_expired",
        AgentStatus::Paused => "paused",
        AgentStatus::Deactivated => "deactivated",
    }
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
            !matches!(
                agent_status_wire(agent.status),
                "deactivated" | "pairing_expired"
            )
        })
        .filter_map(|agent| {
            let agent_id = agent.agent_id.as_str().trim();
            let slug = agent.slug.trim();
            if agent_id.is_empty()
                || slug.is_empty()
                || arkret_sdk::models::validate_agent_slug(slug).is_err()
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
) -> Value {
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
    let target = request.get("target").cloned().unwrap_or(Value::Null);
    let mut payload = json!({
        "approval_id": format!("ak:agent_approval:{}", crate::operation::uuid_v7()),
        "agent_id": agent_id,
        "controller_id": controller_id,
        "proposed_action": proposed_action,
        "target": target,
        "approved_payload_digest": approved_payload_digest,
        "approval_nonce": crate::operation::uuid_v7(),
        "approved_at": approved_at,
        "expires_at": expires_at,
    });
    if let Some(object) = payload.as_object_mut() {
        if let Some(request_id) = non_empty_field(request, "request_id") {
            object.insert("request_id".to_owned(), json!(request_id));
        }
        if let Some(draft_id) = non_empty_field(request, "draft_id") {
            object.insert("draft_id".to_owned(), json!(draft_id));
        }
        if let Some(digest) = draft_content_digest {
            object.insert("draft_content_digest".to_owned(), json!(digest));
        }
    }
    payload
}

/// Build a `ak.agent.action_reject` payload for a draft or action
/// request. A human-entered reason is included when present.
pub fn build_action_reject_payload(
    request: &Value,
    controller_id: &str,
    rejected_at: &str,
    reason: Option<&str>,
) -> Value {
    let mut payload = json!({
        "rejection_id": format!("ak:agent_rejection:{}", crate::operation::uuid_v7()),
        "agent_id": request
            .get("agent_id")
            .and_then(Value::as_str)
            .unwrap_or(""),
        "controller_id": controller_id,
        "rejected_at": rejected_at,
    });
    if let Some(object) = payload.as_object_mut() {
        if let Some(request_id) = non_empty_field(request, "request_id") {
            object.insert("request_id".to_owned(), json!(request_id));
        }
        if let Some(draft_id) = non_empty_field(request, "draft_id") {
            object.insert("draft_id".to_owned(), json!(draft_id));
        }
        if let Some(reason) = reason.map(str::trim).filter(|value| !value.is_empty()) {
            object.insert("reason".to_owned(), json!(reason));
        }
    }
    payload
}

#[allow(clippy::too_many_arguments)]
pub fn build_act_on_behalf_message_operation(
    realm_id: &str,
    controller_id: &str,
    agent_id: &str,
    authorization_ref: &str,
    approval_request_id: &str,
    approval_nonce: &str,
    strand_id: &str,
    body: &str,
) -> anyhow::Result<arkret_sdk::Event> {
    let strand_id_typed = arkret_sdk::StrandId::new(strand_id.to_owned())
        .map_err(|error| anyhow::anyhow!("invalid strand id {strand_id:?}: {error:?}"))?;
    let content = arkret_sdk::ContentBlock::text(body);
    let mut payload =
        arkret_sdk::MessageCreatePayload::with_content(strand_id_typed, "discussion", content)
            .to_value()
            .map_err(|error| anyhow::anyhow!("act-on-behalf message payload serialize: {error}"))?;
    if let Some(object) = payload.as_object_mut() {
        object.insert("approval_request_id".to_owned(), json!(approval_request_id));
        object.insert("approval_nonce".to_owned(), json!(approval_nonce));
    }
    crate::operation::OperationBuilder::new(
        realm_id,
        controller_id,
        arkret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .target_ref(strand_id)
    .executed_by(agent_id)
    .authorization_ref(authorization_ref)
    .body(payload)
    .build_sdk_event("inkson")
}
