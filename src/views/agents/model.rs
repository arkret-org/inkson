//! Agents - pure data types, presets, state machines, and verification
//! helpers shared by the agent panels.
//!
//! These items carry no RSX; they are the unit-testable core behind the
//! endpoint registry, the personal-agent admin, and the handoff
//! surfaces.

use cokret_sdk::models::{
    AgentKeyScope, AgentKeyScopeResource, AgentKeyScopeResourceKind, AgentParticipation, AgentView,
};
use serde::Serialize;
use serde_json::{Value, json};

// ─────────────────────────────────────────────────────────────────────
// CKP-0008 / CKP-0009 — Envelope `actor_kind` reducer-stamped
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

/// Whether the local UI should expose the agent endpoint / handoff panel.
pub fn agents_enabled() -> bool {
    cfg!(feature = "experimental-agents")
}

// ─────────────────────────────────────────────────────────────────────
// CKP-0008 §4.7 — additive content grant presets. The five presets are
// UI/SDK affordances only; the canonical content authorization is the
// expanded `ck.capability.grant` object for each preset (actions +
// resource selector + registered constraints + TTL). Runtime endpoint
// access is selected separately through `AgentServiceScopePreset`; both
// layers are included in `requested_scope` so the agent key has an
// explicit operation ceiling, while content payload access remains gated
// by capability grants.
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

    /// Registered capability actions for this preset (CKP-0008 §4.7 /
    /// §4.9). Only actions present in `capability-action-registry.json`
    /// are emitted so soland never fail-closes on an unknown action.
    pub fn actions(self) -> &'static [&'static str] {
        match self {
            Self::Read => &["ck.event.read"],
            Self::Draft => &["ck.agent.draft.propose", "ck.agent.action_request"],
            Self::ReplyAsAgent => &["ck.message.create", "ck.reaction.add"],
            Self::ActOnBehalf => &["ck.message.create"],
            Self::Organizer => &[
                "ck.strand.create",
                "ck.strand.update",
                "ck.relation.create",
                "ck.message.create",
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
            Self::SubscribeEvents => &["ck.self.events.stream.subscribe"],
            Self::ScanCatchUp => &["ck.self.events.query.scan"],
            Self::SubmitEvents => &["ck.self.events.command.submit"],
            Self::ResolveResources => &["ck.self.events.resource.get"],
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

/// Combine the `requested_scope` (`AgentKeyScope`, the spec object
/// `{actions, resources, constraints}`) for the provision call from the
/// selected service surface and content presets. The returned
/// `AgentKeyScope.actions` intentionally contains both endpoint
/// operation tokens (for runtime reachability) and content action tokens
/// (as the key's maximum content ceiling). Capability grants still decide
/// whether payloads can be read or messages can be created. The schema
/// requires `resources` to be non-empty, so `None` is returned when no
/// action is selected or no Realm is chosen.
pub fn requested_scope_for_presets(
    content_presets: &[AgentGrantPreset],
    service_presets: &[AgentServiceScopePreset],
    realm_id: Option<&str>,
) -> Option<AgentKeyScope> {
    let realm = realm_id.map(str::trim).filter(|value| !value.is_empty())?;
    let realm_id = cokret_sdk::RealmId::new(realm.to_owned()).ok()?;
    let mut actions: Vec<String> = Vec::new();
    for action in service_actions_for_presets(service_presets) {
        push_unique_action(&mut actions, &action);
    }
    for action in content_actions_for_presets(content_presets) {
        push_unique_action(&mut actions, &action);
    }
    if actions.is_empty() {
        return None;
    }
    Some(AgentKeyScope {
        actions,
        resources: vec![AgentKeyScopeResource {
            kind: AgentKeyScopeResourceKind::Realm,
            realm_id: Some(realm_id),
            r#ref: None,
            operation: None,
            service_did: None,
        }],
        constraints: Vec::new(),
    })
}

#[derive(Serialize)]
struct SavfoxPairingBootstrap<'a> {
    bootstrap_kind: &'static str,
    protocol_version: &'static str,
    base_url: &'a str,
    agent_principal_id: String,
    pairing_request_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pairing_code: Option<&'a str>,
    expires_at: String,
    requested_scope: &'a AgentKeyScope,
    requested_service_scope: Vec<String>,
    content_grant_summary: Value,
}

pub fn build_savfox_pairing_bootstrap_json(
    base_url: &str,
    outcome: &cokret_sdk::AgentProvisionOutcome,
    requested_scope: &AgentKeyScope,
    content_presets: &[AgentGrantPreset],
) -> serde_json::Result<String> {
    let base_url = base_url.trim_end_matches('/');
    let content_actions = content_actions_for_presets(content_presets);
    let content_grant_summary = json!({
        "presets": content_presets
            .iter()
            .map(|preset| preset.preset_name())
            .collect::<Vec<_>>(),
        "actions": content_actions,
        "authorization_model": "service scope gates endpoints; content capability grants gate readable payloads and writable content",
    });
    let bootstrap = SavfoxPairingBootstrap {
        bootstrap_kind: "cokret.savfox.agent_pairing_bootstrap.v1",
        protocol_version: "v1",
        base_url,
        agent_principal_id: outcome.agent_principal_id.to_string(),
        pairing_request_id: outcome.pairing_request_id.as_str(),
        pairing_code: outcome.pairing_code.as_deref(),
        expires_at: outcome.expires_at.to_rfc3339(),
        requested_service_scope: requested_scope
            .actions
            .iter()
            .filter(|action| action.starts_with("ck.self."))
            .cloned()
            .collect(),
        requested_scope,
        content_grant_summary,
    };
    serde_json::to_string_pretty(&bootstrap)
}

/// Expand one preset into a canonical `ck.capability.grant` object for
/// `ck.self.agent.grant.command.attach`. The agent principal id is the
/// grant `subject`; `realm_id` scopes it; `expires_at` (RFC3339 Z)
/// bounds the TTL. The grant carries
/// `effective_after_first_authorized_key=true` (§4.3.2) so it is durable
/// but inactive until pairing completes.
///
/// `act_on_behalf` additionally attaches a `claim_based` /
/// `accountability` constraint (`controller_approval_required=true`) per
/// §4.10 so the high-risk executor path cannot run without controller
/// approval.
pub fn expand_preset_grant(
    preset: AgentGrantPreset,
    agent_principal_id: &str,
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
        "subject": agent_principal_id,
        "expires_at": expires_at,
        "effective_after_first_authorized_key": true,
    });
    if preset == AgentGrantPreset::ActOnBehalf {
        grant["constraints"] = json!([
            {
                "constraint_type": "claim_based",
                "subtype": "accountability",
                "controller_approval_required": true,
            }
        ]);
    }
    grant
}

/// R3 spec sync (b47ff6ec) — UI label for an agent FSM state.
///
/// `ck.agent.{pause,resume,deactivate}` lattice is now `fsm` (terminal:
/// `deactivated`). The badge text below mirrors the wire vocabulary
/// surfaced by the soland `AgentResBody.state` field; unknown values
/// fall through to the raw wire string so future state additions are
/// still legible.
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
/// `deactivated` is terminal; the default list filters it out, but a
/// "Show deactivated" toggle re-includes it for audit purposes.
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

/// G3.Y4 — handoff lifecycle. Drives
/// `agent-protocol-handoff-status`'s `data-state`. The transition
/// machine is purely client-side (the durable counterpart is the
/// `ck.agent.interop_session.{start,status,result}` family); the
/// panel uses it to gate which sub-controls are visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandoffState {
    /// No handoff initiated.
    Idle,
    /// User clicked the initiate button but has not confirmed.
    Pending,
    /// User confirmed; the start event is being submitted.
    Approved,
    /// The agent acknowledged via status(running).
    Running,
    /// Terminal: agent emitted a result(completed).
    Completed,
    /// Terminal: agent failed or the start was rejected.
    Failed,
}

impl HandoffState {
    pub fn as_data_state(self) -> &'static str {
        match self {
            HandoffState::Idle => "idle",
            HandoffState::Pending => "pending",
            HandoffState::Approved => "approved",
            HandoffState::Running => "running",
            HandoffState::Completed => "completed",
            HandoffState::Failed => "failed",
        }
    }

    /// Returns true iff the panel should render the confirm button
    /// (we are between the initiate click and the start submission).
    pub fn awaits_confirmation(self) -> bool {
        matches!(self, HandoffState::Pending)
    }

    /// Returns true iff the panel should show the status transcript
    /// surface (we have entered the durable lifecycle).
    pub fn has_transcript(self) -> bool {
        matches!(
            self,
            HandoffState::Approved
                | HandoffState::Running
                | HandoffState::Completed
                | HandoffState::Failed
        )
    }
}

/// G3.Y4 (Phase B) — interop capability-approval modal state. Drives
/// `agent-interop-publish-modal`'s `data-state`. The modal authors a
/// `ck.capability.grant` carrying `actions=[ck.agent.interop_session.start]`
/// plus the §7 constraint, gated behind an explicit human-approval
/// acknowledgement (spec §4 / §8 "sensitive Realms default require human
/// approval").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InteropApprovalState {
    /// Modal closed.
    Closed,
    /// Modal open; controller is filling in the endpoint / constraints
    /// but has not acknowledged the human-approval gate yet.
    Drafting,
    /// Human-approval gate acknowledged; confirm is now enabled.
    Acknowledged,
    /// The capability grant is being submitted.
    Submitting,
    /// Terminal: grant accepted.
    Granted,
    /// Terminal: grant submission failed.
    Failed,
}

impl InteropApprovalState {
    pub fn as_data_state(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Drafting => "drafting",
            Self::Acknowledged => "acknowledged",
            Self::Submitting => "submitting",
            Self::Granted => "granted",
            Self::Failed => "failed",
        }
    }

    /// Confirm is allowed only once the human-approval gate is
    /// acknowledged (spec §4 explicit + authorizable handoff).
    pub fn can_confirm(self) -> bool {
        matches!(self, Self::Acknowledged)
    }

    /// Whether the modal surface should render at all.
    pub fn is_open(self) -> bool {
        !matches!(self, Self::Closed)
    }
}

/// G3.Y4 (Phase D) — publish-to-source modal state. Drives the
/// `publish-modal-*` surface that lands a Strand carrying the executing
/// agent's attribution (spec §5.4 / §6 step 8-9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishModalState {
    Closed,
    /// Modal open; controller reviews the result artifact + chooses the
    /// signer (self-with-attribution).
    Reviewing,
    Submitting,
    Published,
    Failed,
}

impl PublishModalState {
    pub fn as_data_state(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Reviewing => "reviewing",
            Self::Submitting => "submitting",
            Self::Published => "published",
            Self::Failed => "failed",
        }
    }

    pub fn is_open(self) -> bool {
        !matches!(self, Self::Closed)
    }
}

/// G3.Y4 (Phase C) — one row of the live interop-session transcript
/// rebuilt from the soland events surface. `status` reflects the latest
/// `ck.agent.interop_session.status` (or `start`/`result`) observed for
/// the session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveSessionRow {
    pub session_id: String,
    pub status: String,
    pub status_count: usize,
}

/// Reduce a set of fetched soland events (each a JSON object with
/// `event_kind` + `payload`) into a per-session live transcript row.
///
/// The displayed `status` reflects the latest streaming
/// `ck.agent.interop_session.status` (or the seeding `start`), NOT the
/// terminal `result`: the result lands in the dedicated audit-bound
/// results panel, while this row tracks the §5.3 streaming lifecycle
/// (negotiating → accepted → working → ...). `start` seeds the row as
/// `negotiating` (the first standard §5.3 state). Events are assumed to
/// be in causal order (the events API returns them ordered). This is the
/// pure core behind the `agent-session-row` live render so it is
/// unit-testable without a `use_future`.
pub fn live_session_rows(events: &[Value]) -> Vec<LiveSessionRow> {
    use std::collections::BTreeMap;
    // Preserve first-seen order while folding the latest status.
    let mut order: Vec<String> = Vec::new();
    let mut rows: BTreeMap<String, LiveSessionRow> = BTreeMap::new();
    for event in events {
        let kind = event
            .get("event_kind")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !kind.starts_with("ck.agent.interop_session.") {
            continue;
        }
        let payload = event.get("payload").cloned().unwrap_or(Value::Null);
        let Some(session_id) = payload.get("session_id").and_then(Value::as_str) else {
            continue;
        };
        let session_id = session_id.to_owned();
        // Seed the row from `start`; a terminal `result` does not overwrite
        // the streaming status (that lives in the results panel).
        let entry = rows.entry(session_id.clone()).or_insert_with(|| {
            order.push(session_id.clone());
            LiveSessionRow {
                session_id: session_id.clone(),
                status: "negotiating".to_owned(),
                status_count: 0,
            }
        });
        match kind {
            "ck.agent.interop_session.start" => {
                // Seed only; keep `negotiating` as the initial state.
            }
            "ck.agent.interop_session.status" => {
                if let Some(status) = payload.get("status").and_then(Value::as_str) {
                    entry.status = status.to_owned();
                }
                entry.status_count += 1;
            }
            _ => {
                // `result` and other kinds do not move the streaming status.
            }
        }
    }
    order
        .into_iter()
        .filter_map(|session_id| rows.remove(&session_id))
        .collect()
}

/// Audit verification outcome for the full
/// start → status* → result chain. Carries the value the panel
/// stamps onto `agent-protocol-audit-verify-result`'s `data-state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditChainVerifyOutcome {
    Valid,
    ChainBreak,
    SignatureInvalid,
}

impl AuditChainVerifyOutcome {
    pub fn as_data_state(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::ChainBreak => "chain_break",
            Self::SignatureInvalid => "signature_invalid",
        }
    }
}

/// Verify a chain of session events: must start with `*.start`,
/// contain zero or more `*.status`, end with `*.result`, and the
/// terminal result must carry a verifiable `audit_binding`.
pub fn verify_audit_chain(events: &[serde_json::Value]) -> AuditChainVerifyOutcome {
    if events.is_empty() {
        return AuditChainVerifyOutcome::ChainBreak;
    }
    let kind_of = |e: &serde_json::Value| -> Option<String> {
        e.get("kind")
            .or_else(|| e.get("event_kind"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
    };
    let first_kind = match kind_of(&events[0]) {
        Some(k) => k,
        None => return AuditChainVerifyOutcome::ChainBreak,
    };
    if first_kind != "ck.agent.interop_session.start" {
        return AuditChainVerifyOutcome::ChainBreak;
    }
    let Some(last_event) = events.last() else {
        return AuditChainVerifyOutcome::ChainBreak;
    };
    let last_kind = match kind_of(last_event) {
        Some(k) => k,
        None => return AuditChainVerifyOutcome::ChainBreak,
    };
    if last_kind != "ck.agent.interop_session.result" {
        return AuditChainVerifyOutcome::ChainBreak;
    }
    // Middle events MUST be status events.
    for e in &events[1..events.len() - 1] {
        let k = match kind_of(e) {
            Some(k) => k,
            None => return AuditChainVerifyOutcome::ChainBreak,
        };
        if k != "ck.agent.interop_session.status" {
            return AuditChainVerifyOutcome::ChainBreak;
        }
    }
    // Result event audit_binding must verify.
    let result_payload = last_event
        .get("payload")
        .cloned()
        .unwrap_or_else(|| last_event.clone());
    match cokret_sdk::agent_binding::verify_audit_binding_by_kind(&result_payload) {
        cokret_sdk::agent_binding::AuditBindingVerifyOutcome::Valid => {
            AuditChainVerifyOutcome::Valid
        }
        cokret_sdk::agent_binding::AuditBindingVerifyOutcome::Absent => {
            AuditChainVerifyOutcome::ChainBreak
        }
        _ => AuditChainVerifyOutcome::SignatureInvalid,
    }
}

/// V3: parsed verify outcome for a result event's `audit_binding`
/// block. Renders as a colored badge. Pure function so it's
/// unit-testable without spawning a use_future.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuditVerifyStatus {
    /// Signature recomputes against the carried Ed25519 key.
    Valid,
    /// `canonical_subject` field disagrees with the per-field
    /// (session_id, agent_id, echo, actor) tuple.
    SubjectMismatch,
    /// Signature decoded but did not verify.
    SignatureMismatch,
    /// `signature` or `public_key_b64` was not a valid encoding.
    Malformed,
    /// `binding_kind` is not one of the supported values, or the
    /// envelope is missing required fields.
    Unsupported,
    /// No `audit_binding` block at all (e.g. the soland fail-closed
    /// result for unknown_agent).
    Absent,
}

impl AuditVerifyStatus {
    pub(crate) fn badge_label(&self) -> &'static str {
        match self {
            Self::Valid => "audit valid",
            Self::SubjectMismatch => "subject mismatch",
            Self::SignatureMismatch => "signature mismatch",
            Self::Malformed => "malformed binding",
            Self::Unsupported => "unsupported binding",
            Self::Absent => "no binding",
        }
    }
    pub(crate) fn badge_class(&self) -> &'static str {
        match self {
            Self::Valid => "badge green",
            Self::Absent => "badge",
            // Any non-Valid, non-Absent outcome is a hard failure —
            // either tampering, configuration mismatch, or a
            // future binding_kind we don't speak yet.
            _ => "badge red",
        }
    }
}

/// Verify a soland `ck.agent.interop_session.result` payload's
/// `audit_binding` block. Yougen delegates the `binding_kind` switch
/// to the SDK so future schemes land in one place instead of being
/// re-implemented by every client surface.
pub(crate) fn verify_agent_audit_binding(payload: &Value) -> AuditVerifyStatus {
    match cokret_sdk::agent_binding::verify_audit_binding_by_kind(payload) {
        cokret_sdk::agent_binding::AuditBindingVerifyOutcome::Valid => AuditVerifyStatus::Valid,
        cokret_sdk::agent_binding::AuditBindingVerifyOutcome::SubjectMismatch => {
            AuditVerifyStatus::SubjectMismatch
        }
        cokret_sdk::agent_binding::AuditBindingVerifyOutcome::SignatureMismatch => {
            AuditVerifyStatus::SignatureMismatch
        }
        cokret_sdk::agent_binding::AuditBindingVerifyOutcome::Malformed => {
            AuditVerifyStatus::Malformed
        }
        cokret_sdk::agent_binding::AuditBindingVerifyOutcome::Unsupported => {
            AuditVerifyStatus::Unsupported
        }
        cokret_sdk::agent_binding::AuditBindingVerifyOutcome::Absent => AuditVerifyStatus::Absent,
    }
}

/// State machine for the action_approve dialog. The dialog gates the
/// controller's review of an incoming `ck.agent.action_request`
/// notification (digest + expiry + single-use nonce status) before a
/// `ck.agent.action_approve` event is published.
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
    /// Controller explicitly rejected (or a `ck.agent.action_reject`
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
/// expiry elapses (CKP-0008 §4 action_request invariants).
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

pub(crate) fn agent_view_from_directory_row(row: Value) -> Option<AgentView> {
    if let Ok(view) = serde_json::from_value::<AgentView>(row.clone()) {
        return Some(view);
    }
    row.get("agent_principal_id").and_then(Value::as_str)?;
    let status = row
        .get("status")
        .or_else(|| row.get("state"))
        .and_then(Value::as_str)
        .unwrap_or("active")
        .to_owned();
    Some(AgentView {
        agent: row,
        status,
        grants: Vec::new(),
        key_state: Value::Null,
    })
}

/// Hash pasted draft content or action request payload fragments.
/// Return a sha256 digest for canonical JSON.
fn canonical_digest(value: &Value) -> Option<String> {
    cokret_sdk::canonical::canonical_json_bytes(value)
        .map(cokret_sdk::canonical::sha256_digest)
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

/// Build a `ck.agent.action_approve` payload for a controller-owned
/// draft or action request using the current schema fields.
pub fn build_action_approve_payload(
    request: &Value,
    controller_principal_id: &str,
    approved_at: &str,
    expires_at: &str,
) -> Value {
    let draft_content_digest = request.get("content").and_then(canonical_digest);
    let approved_payload_digest = non_empty_field(request, "approved_payload_digest")
        .or_else(|| non_empty_field(request, "request_canonical_digest"))
        .or_else(|| draft_content_digest.clone())
        .unwrap_or_default();
    let agent_principal_id = request
        .get("agent_principal_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let proposed_action = request
        .get("proposed_action")
        .and_then(Value::as_str)
        .unwrap_or("");
    let target = request.get("target").cloned().unwrap_or(Value::Null);
    let mut payload = json!({
        "approval_id": format!("ck:agent_approval:{}", crate::operation::uuid_v7()),
        "agent_principal_id": agent_principal_id,
        "controller_principal_id": controller_principal_id,
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

/// Build a `ck.agent.action_reject` payload for a draft or action
/// request. A human-entered reason is included when present.
pub fn build_action_reject_payload(
    request: &Value,
    controller_principal_id: &str,
    rejected_at: &str,
    reason: Option<&str>,
) -> Value {
    let mut payload = json!({
        "rejection_id": format!("ck:agent_rejection:{}", crate::operation::uuid_v7()),
        "agent_principal_id": request
            .get("agent_principal_id")
            .and_then(Value::as_str)
            .unwrap_or(""),
        "controller_principal_id": controller_principal_id,
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
    controller_principal_id: &str,
    agent_principal_id: &str,
    authorization_ref: &str,
    approval_request_id: &str,
    approval_nonce: &str,
    strand_id: &str,
    body: &str,
) -> anyhow::Result<cokret_sdk::Event> {
    let strand_id_typed = cokret_sdk::StrandId::new(strand_id.to_owned())
        .map_err(|error| anyhow::anyhow!("invalid strand id {strand_id:?}: {error:?}"))?;
    let content = cokret_sdk::ContentBlock::text(body)
        .to_value()
        .map_err(|error| anyhow::anyhow!("act-on-behalf content serialize: {error}"))?;
    let mut payload =
        cokret_sdk::MessageCreatePayload::with_content(strand_id_typed, "discussion", content)
            .to_value()
            .map_err(|error| anyhow::anyhow!("act-on-behalf message payload serialize: {error}"))?;
    if let Some(object) = payload.as_object_mut() {
        object.insert("approval_request_id".to_owned(), json!(approval_request_id));
        object.insert("approval_nonce".to_owned(), json!(approval_nonce));
    }
    crate::operation::OperationBuilder::new(
        realm_id,
        controller_principal_id,
        cokret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .target_ref(strand_id)
    .executed_by(agent_principal_id)
    .authorization_ref(authorization_ref)
    .body(payload)
    .build_sdk_event("yougen")
}
