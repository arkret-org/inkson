//! Agents - pure data types, presets, state machines, and verification
//! helpers shared by the agent panels.
//!
//! These items carry no RSX; they are the unit-testable core behind the
//! endpoint registry, the personal-agent admin, and the handoff
//! surfaces.

use cokret_sdk::models::{AgentKeyScope, AgentView};
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
// CKP-0008 §4.7 — permission presets. The five presets are UI/SDK
// affordances only; the canonical wire is `requested_scope`
// (`AgentKeyScope`) for the provision call plus a fully expanded
// `ck.capability.grant` object for each preset (actions + resource
// selector + registered constraints + TTL). The preset names never
// enter the canonical wire — `expand_preset_grant` materializes the
// concrete capability grant per §4.9.
// ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentPermissionPreset {
    /// `read_only` — agent subscribes/reads selected objects.
    ReadOnly,
    /// `draft_only` — agent proposes controller-private drafts.
    DraftOnly,
    /// `reply_as_agent` — agent posts as itself.
    ReplyAsAgent,
    /// `act_on_behalf` — controller is actor_id, agent is executed_by.
    /// High risk: the expanded grant carries a controller-approval
    /// constraint per §4.10.
    ActOnBehalf,
    /// `organizer` — agent creates/updates Strands and relations.
    Organizer,
}

impl AgentPermissionPreset {
    pub const ALL: [AgentPermissionPreset; 5] = [
        Self::ReadOnly,
        Self::DraftOnly,
        Self::ReplyAsAgent,
        Self::ActOnBehalf,
        Self::Organizer,
    ];

    /// The §4.7 preset name. Used only for UI labels and as a
    /// `data-preset` attribute; never written to the canonical wire.
    pub fn preset_name(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::DraftOnly => "draft_only",
            Self::ReplyAsAgent => "reply_as_agent",
            Self::ActOnBehalf => "act_on_behalf",
            Self::Organizer => "organizer",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::ReadOnly => "Read only",
            Self::DraftOnly => "Draft only",
            Self::ReplyAsAgent => "Reply as agent",
            Self::ActOnBehalf => "Act on my behalf",
            Self::Organizer => "Organizer",
        }
    }

    pub fn help(self) -> &'static str {
        match self {
            Self::ReadOnly => "Subscribe and read selected objects. No writes.",
            Self::DraftOnly => {
                "Propose controller-private drafts for your approval before anything is published."
            }
            Self::ReplyAsAgent => "Post and react as the agent itself, accountable to you.",
            Self::ActOnBehalf => {
                "Post as you (you stay the actor, the agent is recorded as executor). High risk; each action needs your approval."
            }
            Self::Organizer => "Create and update Strands and relations, plus limited posting.",
        }
    }

    /// The coarse agent-key scope this preset implies for the provision
    /// call. Read/draft presets are `Limited`; write-capable presets run
    /// at `Realm` scope.
    pub fn key_scope(self) -> AgentKeyScope {
        match self {
            Self::ReadOnly | Self::DraftOnly => AgentKeyScope::Limited,
            Self::ReplyAsAgent | Self::ActOnBehalf | Self::Organizer => AgentKeyScope::Realm,
        }
    }

    /// Registered capability actions for this preset (CKP-0008 §4.7 /
    /// §4.9). Only actions present in `capability-action-registry.json`
    /// are emitted so soland never fail-closes on an unknown action.
    pub fn actions(self) -> &'static [&'static str] {
        match self {
            Self::ReadOnly => &["ck.event.read"],
            Self::DraftOnly => &["ck.agent.draft.propose", "ck.agent.action_request"],
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

/// Build the pairing deep-link the controller hands to the runtime.
/// CKP-0008 §4.3 mandates a plain HTTPS URL assembled from the
/// deployment-known `cokret_base_url`; no custom URI scheme. Mobile OSes
/// route this via Universal Links / App Links.
pub fn agent_pair_url(base_url: &str, pairing_request_id: &str) -> String {
    let base = base_url.trim_end_matches('/');
    format!("{base}/auth/account/agent-pair?request={pairing_request_id}")
}

/// Combine the `requested_scope` (`AgentKeyScope`) for the provision
/// call from the selected presets. The widest implied key scope wins:
/// `Realm` ⊃ `Limited`. Returns `None` when no preset is selected so the
/// provision body omits `requested_scope` and soland picks its default.
pub fn requested_scope_for_presets(presets: &[AgentPermissionPreset]) -> Option<AgentKeyScope> {
    let mut widest: Option<AgentKeyScope> = None;
    for preset in presets {
        let scope = preset.key_scope();
        widest = Some(match (widest, scope) {
            (Some(AgentKeyScope::Realm), _) | (_, AgentKeyScope::Realm) => AgentKeyScope::Realm,
            _ => AgentKeyScope::Limited,
        });
    }
    widest
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
    preset: AgentPermissionPreset,
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
    if preset == AgentPermissionPreset::ActOnBehalf {
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
        "active" => "Active",
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
        "active" => "badge green",
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
    let last_kind = match kind_of(events.last().unwrap()) {
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
    let result_payload = events
        .last()
        .unwrap()
        .get("payload")
        .cloned()
        .unwrap_or_else(|| events.last().unwrap().clone());
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

/// CKP-0008 §4.8 / §4.8.1 — build a `ck.agent.action_approve` payload
/// for a controller-owned `ck.agent.draft.v1` draft. Binds `draft_id`,
/// content digest, target descriptor, `proposed_action`, approved
/// payload digest, approval expiry, and a single-use nonce. The content
/// digest covers the draft's `content` object; the approved payload
/// digest covers the same payload the publish executor will emit (the
/// controller may edit before approving — here they approve as-is, so
/// both digests are over `content`).
pub fn build_action_approve_payload(draft: &Value, approval_expires_at: &str) -> Value {
    let draft_id = draft.get("draft_id").and_then(Value::as_str).unwrap_or("");
    let agent_principal_id = draft
        .get("agent_principal_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let proposed_action = draft
        .get("proposed_action")
        .and_then(Value::as_str)
        .unwrap_or("");
    let target = draft.get("target").cloned().unwrap_or(Value::Null);
    let content = draft.get("content").cloned().unwrap_or(Value::Null);
    let content_digest = cokret_sdk::canonical::canonical_json_bytes(&content)
        .map(cokret_sdk::canonical::sha256_digest)
        .unwrap_or_default();
    json!({
        "draft_id": draft_id,
        "agent_principal_id": agent_principal_id,
        "proposed_action": proposed_action,
        "target": target,
        "content_digest": content_digest,
        "approved_payload_digest": content_digest,
        "approval_expires_at": approval_expires_at,
        "nonce": crate::operation::uuid_v7(),
    })
}

/// Build a `ck.agent.action_reject` payload for a draft (CKP-0008
/// §4.8.1). Carries the `draft_id` so the reducer transitions the draft
/// to `rejected`.
pub fn build_action_reject_payload(draft: &Value) -> Value {
    json!({
        "draft_id": draft.get("draft_id").and_then(Value::as_str).unwrap_or(""),
        "agent_principal_id": draft
            .get("agent_principal_id")
            .and_then(Value::as_str)
            .unwrap_or(""),
    })
}
