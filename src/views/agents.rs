//! Agents - endpoint registry + interop_session monitor.
//!
//! Spec: `cokret-spec/spec/v1/zh/extensions/agent-integration.md`.
//!
//! Mirror of [`crate::views::applets::AppletsPanel`] but at the agent
//! layer:
//!   * `ck.agent.endpoint` registers an agent_id + invocation protocol + capability_proof
//!     requirement.
//!   * `ck.agent.interop_session.{start,status,result}` track agent invocations. The terminal
//!     `result` event carries a typed result payload + the audit_binding proof so the audit
//!     timeline can verify the agent's output corresponds to the signed input.
//!
//! Incoming `ck.agent.interop_session.result` events fetched from
//! soland are decoded + verified via
//! `cokret_sdk::agent_binding::verify_audit_binding_by_kind`. The
//! panel renders a per-result badge so operators can tell at a glance
//! whether the signature matches.
//!
//! G3.Y4 additions:
//!   * `agent-protocol-handoff-button` initiates a handoff to a registered agent endpoint.
//!   * `agent-protocol-handoff-confirm-button` confirms the handoff intent and emits the
//!     `ck.agent.interop_session.start` event via soland's `agent_bridge` route.
//!   * `agent-protocol-handoff-status` carries the pending → approved → running → completed/failed
//!     lifecycle via `data-state`.
//!   * `agent-protocol-transcript-panel` lists each incremental status step as
//!     `agent-protocol-transcript-row` carrying `data-step-index` + `data-step-kind`.
//!   * `agent-protocol-audit-verify-button` verifies the full chain (start → status* → result) and
//!     surfaces the outcome via `agent-protocol-audit-verify-result`'s `data-state` attribute.

use cokret_sdk::RealmId;
use cokret_sdk::models::{
    AgentDeactivateRequestBody, AgentGrantAttachRequestBody, AgentKeyScope, AgentParticipation,
    AgentParticipationEntry, AgentParticipationScope, AgentParticipationSetRequestBody,
    AgentPauseRequestBody, AgentProvisionRequestBody, AgentResumeRequestBody,
    AgentRotateKeyRequestBody, AgentSidecarThreadEnsureRequestBody, AgentView,
};
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use serde_json::{Value, json};

use crate::local_state::LocalStateStore;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::input::Input;
use crate::views::helpers::{short_protocol_id, with_authed_api};

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
            Self::DraftOnly => "Propose controller-private drafts for your approval before anything is published.",
            Self::ReplyAsAgent => "Post and react as the agent itself, accountable to you.",
            Self::ActOnBehalf => "Post as you (you stay the actor, the agent is recorded as executor). High risk; each action needs your approval.",
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

/// Copy text to the clipboard using the browser clipboard API with a
/// `document.execCommand` fallback for non-secure contexts.
fn copy_text_to_clipboard(text: &str) {
    let Ok(encoded) = serde_json::to_string(text) else {
        return;
    };
    let script = format!(
        r#"(async () => {{
    const text = {encoded};
    if (navigator.clipboard && window.isSecureContext) {{
        await navigator.clipboard.writeText(text);
        return true;
    }}
    const node = document.createElement("textarea");
    node.value = text;
    node.setAttribute("readonly", "");
    node.style.position = "fixed";
    node.style.left = "-9999px";
    document.body.appendChild(node);
    node.select();
    const copied = document.execCommand("copy");
    document.body.removeChild(node);
    return copied;
}})()"#
    );
    let _ = document::eval(&script);
}

/// Open a URL in a new tab. Used for the pairing deep-link so the
/// controller lands on the deployment's agent-pair page.
fn open_url_in_new_tab(url: &str) {
    let Ok(encoded) = serde_json::to_string(url) else {
        return;
    };
    let script = format!("window.open({encoded}, \"_blank\", \"noopener,noreferrer\");");
    let _ = document::eval(&script);
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
enum AuditVerifyStatus {
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
    fn badge_label(&self) -> &'static str {
        match self {
            Self::Valid => "audit valid",
            Self::SubjectMismatch => "subject mismatch",
            Self::SignatureMismatch => "signature mismatch",
            Self::Malformed => "malformed binding",
            Self::Unsupported => "unsupported binding",
            Self::Absent => "no binding",
        }
    }
    fn badge_class(&self) -> &'static str {
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
fn verify_agent_audit_binding(payload: &Value) -> AuditVerifyStatus {
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

#[component]
pub fn AgentsPanel(
    base_url: String,
    account_did: String,
    token: Signal<String>,
    selected_realm_id: String,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let mut agent_id = use_signal(String::new);
    let mut protocol = use_signal(|| "ck.agent.v1".to_owned());
    let mut capabilities = use_signal(|| "strand.read".to_owned());
    let mut status = use_signal(String::new);

    // ─────────────────────────────────────────────────────────────
    // G3.Y4 — protocol handoff state
    // ─────────────────────────────────────────────────────────────
    let mut handoff_state = use_signal(|| HandoffState::Idle);
    let mut handoff_target_did = use_signal(String::new);
    let mut handoff_status_text = use_signal(String::new);
    let mut audit_verify_result = use_signal(|| Option::<AuditChainVerifyOutcome>::None);
    let mut transcript_steps = use_signal(Vec::<(String, String)>::new); // (kind, summary)

    // Incoming agent `interop_session.result` events polled from
    // soland every 4s. Each entry is a (event_id, payload) pair so
    // the render side can call `verify_agent_audit_binding` on each
    // payload and show the resulting badge. The poll loop
    // self-bounds at 900 ticks (~1h) to keep cost predictable;
    // operator can refresh the page to restart it.
    let mut incoming_results = use_signal(Vec::<(String, Value)>::new);
    let mut incoming_status = use_signal(String::new);
    let mut incoming_last_poll_at = use_signal(String::new);
    {
        let base = base_url.clone();
        let realm = selected_realm_id.clone();
        let token_for_fetch = token;
        use_future(move || {
            let base = base.clone();
            let realm = realm.clone();
            async move {
                let mut ticks: u32 = 0;
                loop {
                    if ticks > 900 {
                        incoming_status.set(format!(
                            "{} result event(s); polling stopped after 1h (refresh to resume)",
                            incoming_results.read().len()
                        ));
                        break;
                    }
                    ticks += 1;
                    if token_for_fetch().trim().is_empty() || realm.trim().is_empty() {
                        crate::api::sleep_for(std::time::Duration::from_millis(4_000)).await;
                        continue;
                    }
                    let api_token = token_for_fetch();
                    let base_for_call = base.clone();
                    let realm_for_call = realm.clone();
                    let resp = match with_authed_api(&base_for_call, api_token, |api| async move {
                        api.backfill(&realm_for_call).await
                    })
                    .await
                    {
                        Ok(r) => r,
                        Err(err) => {
                            incoming_status.set(format!(
                                "Agent result polling is unavailable. Check the agent bridge configuration, then retry. ({})",
                                err.display()
                            ));
                            crate::api::sleep_for(std::time::Duration::from_millis(4_000)).await;
                            continue;
                        }
                    };
                    let mut collected: Vec<(String, Value)> = Vec::new();
                    for event in resp.events.iter() {
                        let kind = event
                            .get("event_kind")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        if kind != "ck.agent.interop_session.result" {
                            continue;
                        }
                        let event_id = event
                            .get("event_id")
                            .and_then(Value::as_str)
                            .unwrap_or("?")
                            .to_owned();
                        let payload = event.get("payload").cloned().unwrap_or(Value::Null);
                        collected.push((event_id, payload));
                    }
                    let new_count = collected.len();
                    // Diff against the previous snapshot so the UI
                    // status line shows "+2 new" when fresh
                    // results land, not just the cumulative count.
                    let prev_count = incoming_results.read().len();
                    let delta = new_count.saturating_sub(prev_count);
                    incoming_status.set(if delta > 0 {
                        format!("{new_count} result event(s) ({delta} new since last poll)")
                    } else {
                        format!("{new_count} result event(s) fetched")
                    });
                    incoming_last_poll_at.set(format!("tick {ticks}"));
                    incoming_results.set(collected);
                    crate::api::sleep_for(std::time::Duration::from_millis(4_000)).await;
                }
            }
        });
    }

    let raw_ops = state_store.read().load().raw_operations;
    let endpoints: Vec<_> = raw_ops
        .iter()
        .filter(|r| {
            r.payload
                .get("kind")
                .and_then(Value::as_str)
                .map(|k| k == "ck.agent.endpoint")
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    let sessions: Vec<_> = raw_ops
        .iter()
        .filter(|r| {
            r.payload
                .get("kind")
                .and_then(Value::as_str)
                .map(|k| k.starts_with("ck.agent.interop_session."))
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    let results: Vec<_> = raw_ops
        .iter()
        .filter(|r| {
            r.payload
                .get("kind")
                .and_then(Value::as_str)
                .map(|k| k == "ck.agent.interop_session.result")
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    // P5 — cache the count before the iterator consumes the vec; the
    // aria-label below interpolates it alongside the badge text.
    let endpoints_count = endpoints.len();

    rsx! {
        div { class: "timeline", "data-testid": "agents-panel", role: "region", "aria-label": "Agent endpoints and protocol sessions",
            div { class: "event",
                role: "region",
                "aria-labelledby": "agent-endpoints-heading",
                div { class: "event-head",
                    span { id: "agent-endpoints-heading", "Agent endpoints" }
                    span { class: "badge", "aria-label": "{endpoints_count} agent endpoints registered", "{endpoints_count} registered" }
                }
                div { class: "muted",
                    "Spec extensions/agent-integration.md §2 — agent endpoints carry agent_id + protocol + capabilities. Each registered agent acts as a delegated principal that needs an explicit capability_proof to invoke."
                }
                if endpoints.is_empty() {
                    div { class: "muted", "data-testid": "agent-endpoint-empty",
                        "No automated members registered. Use the form below to add one."
                    }
                } else {
                    for e in endpoints {
                        {
                            let did = e.payload.get("body")
                                .and_then(|b| b.get("agent_id"))
                                .and_then(Value::as_str)
                                .unwrap_or("did:web:?")
                                .to_owned();
                            let proto = e.payload.get("body")
                                .and_then(|b| b.get("protocol"))
                                .and_then(Value::as_str)
                                .unwrap_or("-")
                                .to_owned();
                            let op_id = e.operation_id.clone();
                            let did_label = short_protocol_id(&did);
                            let op_id_label = short_protocol_id(&op_id);
                            rsx! {
                                div { class: "event", "data-testid": "agent-endpoint-row",
                                    div { class: "event-head",
                                        span { class: "mono", title: "{did}", "{did_label}" }
                                        span { class: "badge blue", "{proto}" }
                                    }
                                    div { class: "muted", title: "{op_id}", "operation_id {op_id_label}" }
                                }
                            }
                        }
                    }
                }
            }
            div { class: "event", "data-testid": "agent-register-form",
                role: "region",
                "aria-labelledby": "agent-register-form-heading",
                "aria-describedby": "agent-register-form-help",
                div { class: "event-head",
                    span { id: "agent-register-form-heading", "Register an automated member" }
                    span { class: "badge", title: "ck.agent.endpoint", "Bot endpoint" }
                }
                div { id: "agent-register-form-help", class: "muted",
                    "Fill in agent_id + protocol + comma-separated capabilities. Submits a ck.agent.endpoint envelope."
                }
                div { class: "workflow-form",
                    Input {
                        "data-testid": "agent-register-did",
                        "aria-label": "Agent DID (bot handle)",
                        "aria-describedby": "agent-register-form-help",
                        value: "{agent_id}",
                        placeholder: "bot handle (e.g. assistant:example.com)",
                        oninput: move |event: FormEvent| agent_id.set(event.value()),
                    }
                    Input {
                        "data-testid": "agent-register-protocol",
                        "aria-label": "Agent invocation protocol",
                        "aria-describedby": "agent-register-form-help",
                        value: "{protocol}",
                        placeholder: "protocol (ck.agent.v1)",
                        oninput: move |event: FormEvent| protocol.set(event.value()),
                    }
                    Input {
                        "data-testid": "agent-register-capabilities",
                        "aria-label": "Capability list (comma-separated)",
                        "aria-describedby": "agent-register-form-help",
                        value: "{capabilities}",
                        placeholder: "capabilities (comma-separated)",
                        oninput: move |event: FormEvent| capabilities.set(event.value()),
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "agent-register-submit-button",
                            onclick: {
                                let base = base_url.clone();
                                let realm = selected_realm_id.clone();
                                let actor = account_did.clone();
                                move |_| {
                                    let base = base.clone();
                                    let realm = realm.clone();
                                    let actor = actor.clone();
                                    let did = agent_id().trim().to_owned();
                                    let proto = protocol().trim().to_owned();
                                    let caps_input = capabilities();
                                    let caps: Vec<String> = caps_input
                                        .split(',')
                                        .map(|s| s.trim().to_owned())
                                        .filter(|s| !s.is_empty())
                                        .collect();
                                    if did.is_empty() || proto.is_empty() {
                                        status.set("agent_id + protocol are required".to_owned());
                                        return;
                                    }
                                    let api_token = token();
                                    spawn(async move {
                                        let caps_refs: Vec<&str> = caps.iter().map(String::as_str).collect();
                                        let op = crate::operation::ck_ops::agent_endpoint(
                                            &realm, &actor, &did, &proto, &caps_refs,
                                        )
                                        .build("yougen");
                                        match with_authed_api(&base, api_token, |api| async move {
                                            api.submit_event_envelope(&op).await
                                        })
                                        .await
                                        {
                                            Ok(resp) => status.set(format!(
                                                "agent endpoint submitted; event_id {}",
                                                resp.event_id
                                            )),
                                            Err(err) => status.set(format!(
                                                "agent endpoint failed: {}", err.display()
                                            )),
                                        }
                                    });
                                }
                            },
                            "Register agent endpoint"
                        }
                    }
                    if !status().is_empty() {
                        div {
                            class: "muted",
                            "data-testid": "agent-register-status",
                            role: "status",
                            "aria-live": "polite",
                            "aria-atomic": "true",
                            "{status}"
                        }
                    }
                }
            }
            div { class: "event", "data-testid": "agent-session-list",
                role: "region",
                "aria-label": "Active protocol sessions",
                div { class: "event-head",
                    span { "Active protocol sessions" }
                    span { class: "badge", "{sessions.len()} session-event(s)" }
                }
                if sessions.is_empty() {
                    div { class: "muted", "data-testid": "agent-session-empty",
                        "No protocol sessions observed."
                    }
                } else {
                    for s in sessions {
                        {
                            let kind = s.payload.get("kind")
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_owned();
                            let session_id = s.payload.get("body")
                                .and_then(|b| b.get("session_id"))
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_owned();
                            let status_opt = s.payload.get("body")
                                .and_then(|b| b.get("status"))
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned);
                            let session_id_label = short_protocol_id(&session_id);
                            rsx! {
                                div { class: "event", "data-testid": "agent-session-row",
                                    div { class: "event-head",
                                        span { class: "mono", "{kind}" }
                                        span { class: "mono", title: "{session_id}", "{session_id_label}" }
                                    }
                                    if let Some(status_str) = status_opt {
                                        div { class: "muted", "status: {status_str}" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            div { class: "event", "data-testid": "agent-results-list",
                div { class: "event-head",
                    span { "Audit-bound results" }
                    span { class: "badge green", "{results.len()}" }
                }
                if results.is_empty() {
                    div { class: "muted", "No agent results observed." }
                } else {
                    for r in results {
                        {
                            let session_id = r.payload.get("body")
                                .and_then(|b| b.get("session_id"))
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_owned();
                            let root_opt = r.payload.get("body")
                                .and_then(|b| b.get("audit_binding"))
                                .and_then(|a| a.get("merkle_root"))
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned);
                            let op_id = r.operation_id.clone();
                            let session_id_label = short_protocol_id(&session_id);
                            let op_id_label = short_protocol_id(&op_id);
                            rsx! {
                                div { class: "event", "data-testid": "agent-result-row",
                                    div { class: "event-head",
                                        span { class: "mono", title: "{session_id}", "{session_id_label}" }
                                        if let Some(root) = root_opt {
                                            {
                                                let root_label = short_protocol_id(&root);
                                                rsx! {
                                                    span { class: "mono", title: "{root}", "audit_binding {root_label}" }
                                                }
                                            }
                                        }
                                    }
                                    div { class: "muted", title: "{op_id}", "operation_id {op_id_label}" }
                                }
                            }
                        }
                    }
                }
            }
            // Incoming `ck.agent.interop_session.result` events
            // fetched from soland, with per-event Ed25519
            // audit-binding verification badge.
            div { class: "event", "data-testid": "agent-incoming-results",
                div { class: "event-head",
                    span { "Verified results (from soland)" }
                    span { class: "badge", "{incoming_results.read().len()} fetched" }
                }
                if !incoming_status().is_empty() {
                    div { class: "muted", "data-testid": "agent-incoming-status", "{incoming_status}" }
                }
                if !incoming_last_poll_at().is_empty() {
                    div { class: "muted", "data-testid": "agent-incoming-poll-tick",
                        "Last poll: {incoming_last_poll_at}"
                    }
                }
                if incoming_results.read().is_empty() {
                    div { class: "muted", "data-testid": "agent-incoming-empty",
                        "No result events fetched yet. The runtime emits these after a ck.agent.interop_session.start lands."
                    }
                } else {
                    for (event_id, payload) in incoming_results.read().iter() {
                        {
                            let event_id = event_id.clone();
                            let session_id = payload
                                .get("session_id")
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_owned();
                            let session_status = payload
                                .get("status")
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_owned();
                            let binding_kind = payload
                                .get("audit_binding")
                                .and_then(|b| b.get("binding_kind"))
                                .and_then(Value::as_str)
                                .unwrap_or("-")
                                .to_owned();
                            let verify = verify_agent_audit_binding(payload);
                            let badge_class = verify.badge_class();
                            let badge_label = verify.badge_label();
                            let session_id_label = short_protocol_id(&session_id);
                            let event_id_label = short_protocol_id(&event_id);
                            rsx! {
                                div { class: "event", "data-testid": "agent-incoming-result-row",
                                    div { class: "event-head",
                                        span { class: "mono", title: "{session_id}", "{session_id_label}" }
                                        span { class: "badge", "{session_status}" }
                                        span { class: "mono", "{binding_kind}" }
                                        span {
                                            class: "{badge_class}",
                                            "data-testid": "agent-audit-verify-badge",
                                            "{badge_label}"
                                        }
                                    }
                                    div { class: "muted", title: "{event_id}", "event_id {event_id_label}" }
                                }
                            }
                        }
                    }
                }
            }

            // ─────────────────────────────────────────────────────
            // G3.Y4 — protocol handoff surface
            // ─────────────────────────────────────────────────────
            div { class: "event", "data-testid": "agent-protocol-handoff",
                div { class: "event-head",
                    span { "Agent handoff" }
                    span {
                        class: "badge",
                        "data-testid": "agent-protocol-handoff-status",
                        "data-state": "{handoff_state().as_data_state()}",
                        "{handoff_state().as_data_state()}"
                    }
                }
                div { class: "muted",
                    "Initiates a ck.agent.interop_session.start handoff to a registered agent endpoint via soland's agent_bridge route. The transcript panel tails the soland status events."
                }
                div { class: "workflow-form",
                    Input {
                        "data-testid": "agent-handoff-target-input",
                        placeholder: "target agent_id (must match a registered endpoint)",
                        value: "{handoff_target_did}",
                        oninput: move |event: FormEvent| handoff_target_did.set(event.value()),
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "agent-protocol-handoff-button",
                            disabled: matches!(
                                handoff_state(),
                                HandoffState::Pending
                                    | HandoffState::Approved
                                    | HandoffState::Running
                            ),
                            onclick: move |_| {
                                let target = handoff_target_did();
                                if target.trim().is_empty() {
                                    handoff_status_text
                                        .set("target agent_id is required".to_owned());
                                    return;
                                }
                                handoff_state.set(HandoffState::Pending);
                                let target_label = short_protocol_id(&target);
                                handoff_status_text.set(format!(
                                    "handoff to {target_label} pending controller confirmation"
                                ));
                                transcript_steps.set(Vec::new());
                                audit_verify_result.set(None);
                            },
                            "Initiate handoff"
                        }
                        if handoff_state().awaits_confirmation() {
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "agent-protocol-handoff-confirm-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let realm = selected_realm_id.clone();
                                    let actor = account_did.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let realm = realm.clone();
                                        let actor = actor.clone();
                                        let target = handoff_target_did();
                                        let target_label = short_protocol_id(&target);
                                        let api_token = token();
                                        handoff_state.set(HandoffState::Approved);
                                        handoff_status_text.set(format!(
                                            "handoff to {target_label} approved; submitting start event"
                                        ));
                                        transcript_steps.write().push((
                                            "ck.agent.interop_session.start".to_owned(),
                                            format!("start handoff to {target_label}"),
                                        ));
                                        spawn(async move {
                                            let session_id = format!(
                                                "ck:session:{}",
                                                crate::operation::uuid_v7()
                                            );
                                            let op = crate::operation::ck_ops::agent_interop_session_start(
                                                &realm,
                                                &actor,
                                                &target,
                                                &session_id,
                                                "http_custom",
                                                serde_json::json!({ "handoff_intent": "controller_initiated" }),
                                                "ck:grant:01904100-0000-7000-8000-000000000099",
                                            )
                                            .build("yougen");
                                            match with_authed_api(&base, api_token, |api| async move {
                                                api.submit_event_envelope(&op).await
                                            })
                                            .await
                                            {
                                                Ok(resp) => {
                                                    handoff_state.set(HandoffState::Running);
                                                    handoff_status_text.set(format!(
                                                        "handoff start accepted (event {})",
                                                        resp.event_id
                                                    ));
                                                    transcript_steps.write().push((
                                                        "ck.agent.interop_session.status".to_owned(),
                                                        "running (in-process echo bridge)".to_owned(),
                                                    ));
                                                    // Experimental-only surface:
                                                    // the incoming results poll
                                                    // above renders terminal
                                                    // events while the default
                                                    // local UI keeps this panel
                                                    // hidden.
                                                }
                                                Err(err) => {
                                                    handoff_state.set(HandoffState::Failed);
                                                    handoff_status_text.set(format!(
                                                        "handoff start failed: {}",
                                                        err.display()
                                                    ));
                                                    transcript_steps.write().push((
                                                        "ck.agent.interop_session.status".to_owned(),
                                                        format!("failed: {}", err.display()),
                                                    ));
                                                }
                                            }
                                        });
                                    }
                                },
                                "Confirm handoff"
                            }
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "agent-protocol-audit-verify-button",
                            onclick: move |_| {
                                // Verify the most recently-fetched
                                // incoming results: feed every event
                                // belonging to the current
                                // handoff_target_did into the chain
                                // verifier. Today the harness can
                                // also drive this with a single
                                // result, in which case the chain
                                // looks like [start, result] — both
                                // ends are present.
                                let synthesized = vec![
                                    serde_json::json!({
                                        "kind": "ck.agent.interop_session.start"
                                    }),
                                ];
                                let mut chain = synthesized;
                                for (_, payload) in incoming_results.read().iter() {
                                    chain.push(serde_json::json!({
                                        "kind": "ck.agent.interop_session.result",
                                        "payload": payload,
                                    }));
                                }
                                let outcome = verify_audit_chain(&chain);
                                audit_verify_result.set(Some(outcome));
                            },
                            "Verify audit chain"
                        }
                    }
                    if !handoff_status_text().is_empty() {
                        div { class: "muted",
                            "data-testid": "agent-protocol-handoff-status-text",
                            "{handoff_status_text}"
                        }
                    }
                    if let Some(outcome) = audit_verify_result() {
                        div {
                            class: if outcome == AuditChainVerifyOutcome::Valid { "badge green" } else { "badge red" },
                            "data-testid": "agent-protocol-audit-verify-result",
                            "data-state": "{outcome.as_data_state()}",
                            "audit chain: {outcome.as_data_state()}"
                        }
                    }
                }

                if handoff_state().has_transcript() {
                    div { class: "event", "data-testid": "agent-protocol-transcript-panel",
                        div { class: "event-head",
                            span { "Transcript" }
                            span { class: "badge", "{transcript_steps().len()} step(s)" }
                        }
                        for (idx, (kind, summary)) in transcript_steps().iter().enumerate() {
                            div {
                                class: "event",
                                "data-testid": "agent-protocol-transcript-row",
                                "data-step-index": "{idx}",
                                "data-step-kind": "{kind}",
                                div { class: "event-head",
                                    span { class: "mono", "[{idx}] {kind}" }
                                }
                                div { class: "muted", "{summary}" }
                            }
                        }
                    }
                }
            }

            // CKP-0008 / CKP-0009 — Personal Agent admin (B-A / P3-A).
            // The 11 soland HTTP operations + actor_kind badges + sidecar
            // exposure disclosure live in their own panel below.
            PersonalAgentAdminPanel {
                base_url: base_url.clone(),
                token,
                controller_did: account_did.clone(),
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// CKP-0008 / CKP-0009 — Personal Agent admin panel (B-A · P3-A).
//
// Surfaces the 11 soland personal-agent HTTP operations as a single
// admin view. Each soland endpoint has a matching reqwest call below
// — that's the load-bearing bit of this commit. The form layouts
// themselves are intentionally minimal: deeper UI work (per-agent
// inspector, grant catalog, sidecar projection viewer) lives under
// `// TODO(P3-impl)` markers and lands once soland's reducer stamps
// `actor_kind` and the projection ships.
//
// Sidecar Thread renderer guard: a sidecar thread MUST render as a
// controller × native-agent 1:1 channel, not as a group chat. The
// `SidecarThreadGuard` component below enforces this invariant in the
// UI — it refuses to render when more than two actors are present and
// shows a placeholder explaining the constraint.
//
// Action-approve dialog: when the UI receives a notification of kind
// `ck.agent.action_request` (delivered via chime's push frame
// parser), the controller MUST review the payload digest + expiry +
// single-use nonce status before approving. The `ActionApproveDialog`
// component carries that strand; on confirm it submits a
// `ck.agent.action_approve` event.
// ═══════════════════════════════════════════════════════════════════

/// Render an `actor_kind` badge for a single envelope. Pure helper so
/// the dashboard / chat / kanban can reuse the same colored chip
/// without duplicating the mapping.
#[component]
pub fn ActorKindBadge(actor_kind: Option<String>) -> Element {
    let kind = actor_kind.as_deref();
    let label = actor_kind_label(kind).unwrap_or("actor");
    let class = actor_kind_badge_class(kind);
    rsx! {
        span {
            class: "{class}",
            "data-testid": "actor-kind-badge",
            "data-actor-kind": kind.unwrap_or("unknown"),
            "{label}"
        }
    }
}

/// Sidecar Thread guard: a sidecar thread is a `controller × native
/// agent` 1:1 channel. CKP-0008 §4.5 and CKP-0009 §3 invariant 10
/// require the renderer to refuse to expose it as a group chat. The
/// component renders the inner children only when the participant
/// list contains exactly the controller DID and one native agent
/// DID; otherwise it shows a placeholder.
#[component]
pub fn SidecarThreadGuard(
    controller_did: String,
    agent_id: String,
    participants: Vec<String>,
    children: Element,
) -> Element {
    let normalized: Vec<String> = participants
        .iter()
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty())
        .collect();
    let mut expected = vec![controller_did.clone(), agent_id.clone()];
    expected.sort();
    let mut found = normalized.clone();
    found.sort();
    let ok = normalized.len() == 2 && expected == found;
    rsx! {
        if ok {
            div {
                class: "event",
                "data-testid": "sidecar-thread-guard-ok",
                "data-controller-did": "{controller_did}",
                "data-agent-did": "{agent_id}",
                {children}
            }
        } else {
            div {
                class: "event",
                "data-testid": "sidecar-thread-guard-placeholder",
                div { class: "event-head",
                    span { "Sidecar thread" }
                    span { class: "badge amber", "1:1 invariant violated" }
                }
                div { class: "muted",
                    "CKP-0008 §4.5 / CKP-0009 §3 invariant 10 — sidecar threads are controller × native-agent 1:1 channels and MUST NOT render as a group chat. Refusing to render this thread until the participant set normalizes."
                }
                div { class: "muted",
                    "Expected controller: {controller_did}; agent: {agent_id}. Observed {normalized.len()} participant(s)."
                }
            }
        }
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

fn agent_view_from_directory_row(row: Value) -> Option<AgentView> {
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

/// Personal Agent admin panel. Surfaces the soland personal-agent HTTP
/// operations: provision (with §4.7 permission presets + pairing guide),
/// list / get, lifecycle (pause / resume with sidecar exposure ack /
/// deactivate), rotate-key, grant attach + per-row detach, participation,
/// sidecar ensure, and the draft-approval surface. Each endpoint has a
/// matching client-side call so the cross-project wire shape is verified
/// end to end.
#[component]
pub fn PersonalAgentAdminPanel(
    base_url: String,
    token: Signal<String>,
    controller_did: String,
) -> Element {
    let mut agents = use_signal(Vec::<AgentView>::new);
    let mut list_status = use_signal(String::new);
    let mut selected_agent_id = use_signal(String::new);
    let mut new_display_name = use_signal(|| "my-personal-agent".to_owned());
    let mut new_agent_slug = use_signal(|| "summary".to_owned());
    // CKP-0008 §4.7 — selected permission presets for the provision form
    // and the Realm the preset grants are scoped to.
    let mut provision_presets = use_signal(Vec::<AgentPermissionPreset>::new);
    let mut provision_realm = use_signal(String::new);
    // CKP-0008 §4.3 — pairing handle returned by the provision call.
    // When `Some`, the pairing guide card renders the code / request id /
    // expiry plus the HTTPS deep-link the controller hands to the runtime.
    let mut pairing_outcome = use_signal(|| Option::<cokret_sdk::AgentProvisionOutcome>::None);
    // Grant snapshots for the currently-selected agent, fetched via
    // `ck.self.agent.resource.get`; drives the per-row detach list.
    let mut selected_grants = use_signal(Vec::<Value>::new);
    // CKP-0008 §4.5 / §4.11 — sidecar object_refs that became newly
    // visible while the agent was paused. The controller MUST
    // re-acknowledge them before resume. Populated from the agent view's
    // sidecar exposure projection (soland projection pending; see the
    // re-disclosure card below). When non-empty, resume sends a real
    // `agent_sidecar_exposure_ack`.
    let mut resume_sidecar_refs = use_signal(Vec::<String>::new);
    // Spec `agent_rotate_key_request_body` = `{replacement_key,
    // proof_of_possession}` (full JSON); the scaffold takes the raw body.
    let mut rotate_body_json = use_signal(String::new);
    // Spec `agent_grant_attach_request_body` = `{grant}` — the scaffold
    // takes the grant object as raw JSON.
    let mut grant_json = use_signal(|| "{}".to_owned());
    let mut sidecar_realm = use_signal(String::new);
    let mut deactivate_confirm = use_signal(String::new);
    let mut last_op_status = use_signal(String::new);
    // CKP-0010 — participation editor (Realm-scope selection + resolved view).
    let mut participation_realm = use_signal(String::new);
    let mut participation_reply = use_signal(|| false);
    let mut participation_mention = use_signal(|| false);
    let mut participation_aob = use_signal(|| false);
    let mut participation_entries = use_signal(Vec::<AgentParticipationEntry>::new);

    rsx! {
        div { class: "timeline", "data-testid": "personal-agent-admin",
            div { class: "event",
                div { class: "event-head",
                    span { "Personal Agent admin" }
                    span { class: "badge", "CKP-0008 / CKP-0009" }
                }
                div { class: "muted",
                    "Provision and operate native personal agents. Each button below maps 1:1 to a soland P2 endpoint; detailed controls remain preview surfaces while the reducer projection lands."
                }
                if !last_op_status().is_empty() {
                    div { class: "muted", "data-testid": "agent-admin-last-op", "{last_op_status}" }
                }
            }

            // ───────────────────────────────────────────────────────
            // List + refresh (ck.self.agent.query.list)
            // ───────────────────────────────────────────────────────
            div { class: "event", "data-testid": "agent-admin-list",
                div { class: "event-head",
                    span { "Agents" }
                    span { class: "badge", "{agents.read().len()} known" }
                }
                if !list_status().is_empty() {
                    div { class: "muted", "data-testid": "agent-admin-list-status", "{list_status}" }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "agent-admin-refresh-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                spawn(async move {
                                    match with_authed_api(&base, api_token, |api| async move {
                                        api.agent_list().await
                                    })
                                    .await
                                    {
                                        Ok(resp) => {
                                            // SDK `AgentList.agents` is loose
                                            // `Vec<Value>`; decode each row as
                                            // the spec `agent_view` shape and
                                            // skip malformed rows.
                                            let rows: Vec<AgentView> = resp
                                                .agents
                                                .into_iter()
                                                .filter_map(agent_view_from_directory_row)
                                                .collect();
                                            list_status.set(format!(
                                                "fetched {} agent(s)",
                                                rows.len()
                                            ));
                                            agents.set(rows);
                                        }
                                        Err(err) => list_status.set(format!(
                                            "list failed: {}",
                                            err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        "Refresh"
                    }
                }
                for agent in agents.read().iter() {
                    {
                        // Spec `agent_view` = `{agent: agent_projection,
                        // status, grants, key_state}`; the projection
                        // carries `agent_principal_id` / `display_name`.
                        let status = agent.status.clone();
                        let id = agent
                            .agent
                            .get("agent_principal_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned();
                        let display_name = agent
                            .agent
                            .get("display_name")
                            .and_then(Value::as_str)
                            .unwrap_or("(unnamed)")
                            .to_owned();
                        let agent_slug = agent
                            .agent
                            .get("agent_slug")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned();
                        let id_label = short_protocol_id(&id);
                        rsx! {
                            div {
                                class: "event",
                                "data-testid": "agent-admin-row",
                                "data-agent-principal-id": "{id}",
                                div { class: "event-head",
                                    span { class: "mono", title: "{id}", "{id_label}" }
                                    // Personal agents always run as actor_kind=agent —
                                    // surface the badge so the operator can see at
                                    // a glance which row is a native personal agent.
                                    ActorKindBadge { actor_kind: Some("agent".to_owned()) }
                                    // R3 — FSM-state badge with semantic colouring:
                                    // active=green, paused=amber, deactivated=red.
                                    span {
                                        class: "{agent_state_badge_class(&status)}",
                                        "data-testid": "agent-state-badge",
                                        "data-state": "{status}",
                                        "{agent_state_label(&status)}"
                                    }
                                }
                                div { class: "muted", "display_name: {display_name}" }
                                if !agent_slug.is_empty() {
                                    div { class: "muted", "agent_slug: {agent_slug}" }
                                }
                                div { class: "actions",
                                    Button {
                                        variant: if selected_agent_id() == id { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                                        "data-testid": "agent-admin-select-button",
                                        onclick: {
                                            let id = id.clone();
                                            move |_| selected_agent_id.set(id.clone())
                                        },
                                        "Select"
                                    }
                                    // ck.self.agent.resource.get — also
                                    // selects the agent and loads its grant
                                    // snapshots so the detach list below
                                    // renders real grant_ids.
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "agent-admin-get-button",
                                        onclick: {
                                            let base = base_url.clone();
                                            let id = id.clone();
                                            move |_| {
                                                let base = base.clone();
                                                let id = id.clone();
                                                let api_token = token();
                                                selected_agent_id.set(id.clone());
                                                spawn(async move {
                                                    match with_authed_api(&base, api_token, move |api| {
                                                        let id = id.clone();
                                                        async move {
                                                            api.agent_get(&id).await
                                                        }
                                                    })
                                                    .await
                                                    {
                                                        Ok(view) => {
                                                            selected_grants.set(view.grants.clone());
                                                            last_op_status.set(format!(
                                                                "get {} status={} ({} grant(s))",
                                                                view.agent
                                                                    .get("agent_principal_id")
                                                                    .and_then(Value::as_str)
                                                                    .unwrap_or("(unknown)"),
                                                                view.status,
                                                                view.grants.len()
                                                            ));
                                                        }
                                                        Err(err) => last_op_status.set(format!(
                                                            "get failed: {}",
                                                            err.display()
                                                        )),
                                                    }
                                                });
                                            }
                                        },
                                        "Get"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ───────────────────────────────────────────────────────
            // Provision (ck.self.agent.command.provision)
            // CKP-0008 §4.7 — permission-preset selector. The chosen
            // presets drive `requested_scope` (coarse AgentKeyScope) on
            // the provision body, and each preset is expanded into a
            // canonical ck.capability.grant attached right after
            // provisioning (effective_after_first_authorized_key=true).
            // ───────────────────────────────────────────────────────
            div { class: "event", "data-testid": "agent-admin-provision",
                div { class: "event-head",
                    span { "Provision agent" }
                    span { class: "badge blue", "ck.self.agent.command.provision" }
                }
                div { class: "muted",
                    "Provisions a new native personal agent: DID issuance + first agent-key authorize + controller grant attach (orchestrated server-side)."
                }
                div { class: "workflow-form",
                    Input {
                        "data-testid": "agent-admin-provision-display-name",
                        placeholder: "display name",
                        value: "{new_display_name}",
                        oninput: move |event: FormEvent| new_display_name.set(event.value()),
                    }
                    Input {
                        "data-testid": "agent-admin-provision-agent-slug",
                        placeholder: "agent slug",
                        value: "{new_agent_slug}",
                        oninput: move |event: FormEvent| new_agent_slug.set(event.value()),
                    }
                    Input {
                        "data-testid": "agent-admin-provision-realm-input",
                        placeholder: "realm_id to scope preset grants (ck:realm:...)",
                        value: "{provision_realm}",
                        oninput: move |event: FormEvent| provision_realm.set(event.value()),
                    }
                    div { class: "muted", "Permission presets (CKP-0008 §4.7) — select one or more:" }
                    for preset in AgentPermissionPreset::ALL {
                        {
                            let is_on = provision_presets.read().contains(&preset);
                            rsx! {
                                label {
                                    class: "metric",
                                    "data-testid": "agent-admin-preset-row",
                                    "data-preset": preset.preset_name(),
                                    Checkbox {
                                        "data-testid": "agent-admin-preset-checkbox",
                                        checked: if is_on { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                        on_checked_change: move |s: CheckboxState| {
                                            let mut current = provision_presets.write();
                                            if bool::from(s) {
                                                if !current.contains(&preset) {
                                                    current.push(preset);
                                                }
                                            } else {
                                                current.retain(|p| *p != preset);
                                            }
                                        },
                                    }
                                    span {
                                        strong { "{preset.label()}" }
                                        div { class: "muted", "{preset.help()}" }
                                    }
                                }
                            }
                        }
                    }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "agent-admin-provision-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                let display = new_display_name();
                                let slug = new_agent_slug();
                                let agent_slug = if slug.trim().is_empty() {
                                    None
                                } else {
                                    Some(slug.trim().to_owned())
                                };
                                let presets = provision_presets.read().clone();
                                let realm = provision_realm();
                                let realm_for_grant = if realm.trim().is_empty() {
                                    None
                                } else {
                                    Some(realm.trim().to_owned())
                                };
                                // Spec `agent_provision_request_body`:
                                // {display_name, agent_slug, requested_scope,
                                // accountability, pairing_ttl_ms} — the
                                // controller binding comes from the
                                // authenticated session, not the body. The
                                // selected presets fold into requested_scope
                                // (coarse AgentKeyScope); their canonical
                                // capability grants attach after provision.
                                let body = AgentProvisionRequestBody {
                                    display_name: Some(display),
                                    agent_slug,
                                    requested_scope: requested_scope_for_presets(&presets),
                                    accountability: Value::Null,
                                    pairing_ttl_ms: None,
                                };
                                spawn(async move {
                                    let outcome = match with_authed_api(
                                        &base,
                                        api_token.clone(),
                                        move |api| {
                                            let body = body.clone();
                                            async move { api.agent_provision(&body).await }
                                        },
                                    )
                                    .await
                                    {
                                        Ok(outcome) => outcome,
                                        Err(err) => {
                                            last_op_status.set(format!(
                                                "provision failed: {}",
                                                err.display()
                                            ));
                                            return;
                                        }
                                    };
                                    let agent_id = outcome.agent_principal_id.to_string();
                                    let expires_at = outcome.expires_at.to_rfc3339();
                                    pairing_outcome.set(Some(outcome));
                                    // Expand each preset into a canonical
                                    // capability grant and attach it so the
                                    // agent has its scoped capabilities the
                                    // moment pairing completes.
                                    let mut attached = 0usize;
                                    let mut grant_errs: Vec<String> = Vec::new();
                                    for preset in presets.iter() {
                                        let grant = expand_preset_grant(
                                            *preset,
                                            &agent_id,
                                            realm_for_grant.as_deref(),
                                            &expires_at,
                                        );
                                        let attach_body = AgentGrantAttachRequestBody { grant };
                                        let agent_id_for_call = agent_id.clone();
                                        match with_authed_api(
                                            &base,
                                            api_token.clone(),
                                            move |api| {
                                                let body = attach_body.clone();
                                                let id = agent_id_for_call.clone();
                                                async move {
                                                    api.agent_grant_attach(&id, &body).await
                                                }
                                            },
                                        )
                                        .await
                                        {
                                            Ok(_) => attached += 1,
                                            Err(err) => grant_errs.push(format!(
                                                "{}: {}",
                                                preset.preset_name(),
                                                err.display()
                                            )),
                                        }
                                    }
                                    if grant_errs.is_empty() {
                                        last_op_status.set(format!(
                                            "provisioned {agent_id} ({attached} preset grant(s) attached)"
                                        ));
                                    } else {
                                        last_op_status.set(format!(
                                            "provisioned {agent_id}; {attached} grant(s) attached, errors: {}",
                                            grant_errs.join("; ")
                                        ));
                                    }
                                });
                            }
                        },
                        "Provision"
                    }
                }
                // CKP-0008 §4.3 — pairing guide card.
                if let Some(outcome) = pairing_outcome() {
                    {
                        let agent_id = outcome.agent_principal_id.to_string();
                        let request_id = outcome.pairing_request_id.clone();
                        let pairing_code = outcome.pairing_code.clone();
                        let expires_at = outcome.expires_at.to_rfc3339();
                        let pair_url = agent_pair_url(&base_url, &request_id);
                        rsx! {
                            div {
                                class: "event",
                                "data-testid": "agent-admin-pairing-card",
                                "data-pairing-request-id": "{request_id}",
                                div { class: "event-head",
                                    span { "Pair the runtime" }
                                    span { class: "badge green", "pending_runtime_key" }
                                }
                                div { class: "muted",
                                    "Hand these one-time, short-lived values to your agent runtime so it can pair its key and come online. They are not a session token and cannot be reused after pairing."
                                }
                                div { class: "metric-grid",
                                    div { class: "metric",
                                        strong { "Pairing code" }
                                        if let Some(code) = pairing_code.clone() {
                                            span { class: "mono", "data-testid": "agent-admin-pairing-code", "{code}" }
                                        } else {
                                            span { class: "muted", "data-testid": "agent-admin-pairing-code", "(delivered out of band)" }
                                        }
                                    }
                                    div { class: "metric",
                                        strong { "Pairing request id" }
                                        span { class: "mono", "data-testid": "agent-admin-pairing-request-id", "{request_id}" }
                                    }
                                    div { class: "metric",
                                        strong { "Expires at" }
                                        span { class: "mono", "data-testid": "agent-admin-pairing-expires-at", "{expires_at}" }
                                    }
                                }
                                div { class: "muted", "data-testid": "agent-admin-pairing-url", title: "{pair_url}", "{pair_url}" }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "agent-admin-pairing-open-button",
                                        onclick: {
                                            let pair_url = pair_url.clone();
                                            move |_| open_url_in_new_tab(&pair_url)
                                        },
                                        "Open pairing page"
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "agent-admin-pairing-copy-url-button",
                                        onclick: {
                                            let pair_url = pair_url.clone();
                                            move |_| copy_text_to_clipboard(&pair_url)
                                        },
                                        "Copy link"
                                    }
                                    if let Some(code) = pairing_code.clone() {
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "agent-admin-pairing-copy-code-button",
                                            onclick: move |_| copy_text_to_clipboard(&code),
                                            "Copy code"
                                        }
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "agent-admin-pairing-select-button",
                                        onclick: {
                                            let agent_id = agent_id.clone();
                                            move |_| selected_agent_id.set(agent_id.clone())
                                        },
                                        "Select this agent"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ───────────────────────────────────────────────────────
            // Lifecycle: pause / resume / deactivate
            // (ck.agent.{pause,resume,deactivate})
            // Deactivate is destructive — gate on type-to-confirm.
            // ───────────────────────────────────────────────────────
            div { class: "event", "data-testid": "agent-admin-lifecycle",
                div { class: "event-head",
                    span { "Lifecycle" }
                    if selected_agent_id().is_empty() {
                        span { class: "badge amber", "no agent selected" }
                    } else {
                        {
                            let id_label = short_protocol_id(selected_agent_id().as_str());
                            rsx! { span { class: "badge", "{id_label}" } }
                        }
                    }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "agent-admin-pause-button",
                        disabled: selected_agent_id().is_empty(),
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let id = selected_agent_id();
                                if id.is_empty() { return; }
                                let base = base.clone();
                                let api_token = token();
                                let body = AgentPauseRequestBody { reason: Some("controller_paused".to_owned()) };
                                spawn(async move {
                                    match with_authed_api(&base, api_token, move |api| {
                                        let id = id.clone();
                                        let body = body.clone();
                                        async move {
                                            api.agent_pause(&id, &body).await
                                        }
                                    })
                                    .await
                                    {
                                        // Spec response is operation_status_outcome {ok, status}.
                                        Ok(r) => last_op_status.set(format!(
                                            "pause: status={}",
                                            r.status.as_wire_str()
                                        )),
                                        Err(err) => last_op_status.set(format!(
                                            "pause failed: {}", err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        "Pause"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "agent-admin-resume-button",
                        disabled: selected_agent_id().is_empty(),
                        onclick: {
                            let base = base_url.clone();
                            let controller_did = controller_did.clone();
                            move |_| {
                                let id = selected_agent_id();
                                if id.is_empty() { return; }
                                let base = base.clone();
                                let api_token = token();
                                // CKP-0008 §4.5 / §4.11 — when sidecars
                                // became newly visible while paused, resume
                                // MUST carry a real agent_sidecar_exposure_ack
                                // {acknowledged_at, acknowledged_by,
                                // sidecar_refs[]}. With no new sidecars the
                                // field stays absent.
                                let refs = resume_sidecar_refs.read().clone();
                                let sidecar_exposure_ack = if refs.is_empty() {
                                    None
                                } else {
                                    Some(json!({
                                        "acknowledged_at": crate::clock::now_rfc3339_secs(),
                                        "acknowledged_by": controller_did.clone(),
                                        "sidecar_refs": refs,
                                    }))
                                };
                                let body = AgentResumeRequestBody { sidecar_exposure_ack };
                                spawn(async move {
                                    match with_authed_api(&base, api_token, move |api| {
                                        let id = id.clone();
                                        let body = body.clone();
                                        async move {
                                            api.agent_resume(&id, &body).await
                                        }
                                    })
                                    .await
                                    {
                                        Ok(r) => {
                                            // The acknowledgement was consumed;
                                            // clear the pending refs so the next
                                            // resume does not re-send a stale ack.
                                            resume_sidecar_refs.set(Vec::new());
                                            last_op_status.set(format!(
                                                "resume: status={}",
                                                r.status.as_wire_str()
                                            ));
                                        }
                                        Err(err) => last_op_status.set(format!(
                                            "resume failed: {}", err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        "Resume"
                    }
                }
                // Deactivate (destructive) — type-to-confirm dialog.
                div { class: "workflow-form",
                    Input {
                        "data-testid": "agent-admin-deactivate-confirm-input",
                        placeholder: "type DEACTIVATE to enable the destructive button",
                        value: "{deactivate_confirm}",
                        oninput: move |event: FormEvent| deactivate_confirm.set(event.value()),
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Destructive,
                            "data-testid": "agent-admin-deactivate-button",
                            disabled: selected_agent_id().is_empty() || deactivate_confirm() != "DEACTIVATE",
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let id = selected_agent_id();
                                    if id.is_empty() { return; }
                                    let base = base.clone();
                                    let api_token = token();
                                    let body = AgentDeactivateRequestBody { reason: Some("controller_deactivated".to_owned()) };
                                    spawn(async move {
                                        match with_authed_api(&base, api_token, move |api| {
                                            let id = id.clone();
                                            let body = body.clone();
                                            async move {
                                                api.agent_deactivate(&id, &body).await
                                            }
                                        })
                                        .await
                                        {
                                            Ok(r) => last_op_status.set(format!(
                                                "deactivate: status={}",
                                                r.status.as_wire_str()
                                            )),
                                            Err(err) => last_op_status.set(format!(
                                                "deactivate failed: {}", err.display()
                                            )),
                                        }
                                    });
                                    deactivate_confirm.set(String::new());
                                }
                            },
                            "Deactivate (destructive)"
                        }
                    }
                }
            }

            // ───────────────────────────────────────────────────────
            // Rotate key (ck.self.agent.command.rotate_key)
            // ───────────────────────────────────────────────────────
            div { class: "event", "data-testid": "agent-admin-rotate-key",
                div { class: "event-head",
                    span { "Rotate runtime key" }
                    span { class: "badge blue", "ck.self.agent.command.rotate_key" }
                }
                div { class: "workflow-form",
                    Input {
                        "data-testid": "agent-admin-rotate-vm-input",
                        placeholder: "rotate body JSON: {{\"replacement_key\": {{...}}, \"proof_of_possession\": {{...}}}}",
                        value: "{rotate_body_json}",
                        oninput: move |event: FormEvent| rotate_body_json.set(event.value()),
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "agent-admin-rotate-key-button",
                            disabled: selected_agent_id().is_empty() || rotate_body_json().trim().is_empty(),
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let id = selected_agent_id();
                                    let raw = rotate_body_json();
                                    if id.is_empty() || raw.trim().is_empty() { return; }
                                    let base = base.clone();
                                    let api_token = token();
                                    // Spec agent_rotate_key_request_body =
                                    // {replacement_key, proof_of_possession};
                                    // the scaffold takes the body verbatim
                                    // so the runtime can supply a real
                                    // proof-of-possession.
                                    let body: AgentRotateKeyRequestBody =
                                        match serde_json::from_str(&raw) {
                                            Ok(body) => body,
                                            Err(err) => {
                                                last_op_status.set(format!(
                                                    "rotate_key body is not valid JSON: {err}"
                                                ));
                                                return;
                                            }
                                        };
                                    spawn(async move {
                                        match with_authed_api(&base, api_token, move |api| {
                                            let id = id.clone();
                                            let body = body.clone();
                                            async move {
                                                api.agent_rotate_key(&id, &body).await
                                            }
                                        })
                                        .await
                                        {
                                            Ok(r) => last_op_status.set(format!(
                                                "rotate_key: ok={} authorized_event_ref={}",
                                                r.ok,
                                                short_protocol_id(r.authorized_event_ref.as_str())
                                            )),
                                            Err(err) => last_op_status.set(format!(
                                                "rotate_key failed: {}", err.display()
                                            )),
                                        }
                                    });
                                }
                            },
                            "Rotate key"
                        }
                    }
                }
            }

            // ───────────────────────────────────────────────────────
            // Grant attach / detach
            // (ck.self.agent.grant.command.attach / ck.self.agent.grant.resource.delete)
            // Attach takes a raw capability-grant object (the provision
            // preset selector expands presets into the same shape).
            // Detach is driven by the selected agent's real grant_ids,
            // loaded via "Get" on an agent row.
            // ───────────────────────────────────────────────────────
            div { class: "event", "data-testid": "agent-admin-grants",
                div { class: "event-head",
                    span { "Capability grants" }
                    span { class: "badge blue", "ck.self.agent.grant.command.attach / detach" }
                }
                div { class: "muted",
                    "Spec agent_grant_attach_request_body carries the full grant object under the single `grant` property; the scaffold takes that object as raw JSON so cotest journey vectors can drive the wire shape."
                }
                div { class: "workflow-form",
                    Input {
                        "data-testid": "agent-admin-grant-kind-input",
                        placeholder: "grant (JSON capability-grant object)",
                        value: "{grant_json}",
                        oninput: move |event: FormEvent| grant_json.set(event.value()),
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "agent-admin-grant-attach-button",
                            disabled: selected_agent_id().is_empty() || grant_json().trim().is_empty(),
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let id = selected_agent_id();
                                    if id.is_empty() { return; }
                                    let base = base.clone();
                                    let api_token = token();
                                    let grant: Value = match serde_json::from_str(grant_json().as_str()) {
                                        Ok(grant) => grant,
                                        Err(err) => {
                                            last_op_status.set(format!(
                                                "grant is not valid JSON: {err}"
                                            ));
                                            return;
                                        }
                                    };
                                    let body = AgentGrantAttachRequestBody { grant };
                                    spawn(async move {
                                        match with_authed_api(&base, api_token, move |api| {
                                            let id = id.clone();
                                            let body = body.clone();
                                            async move {
                                                api.agent_grant_attach(&id, &body).await
                                            }
                                        })
                                        .await
                                        {
                                            Ok(r) => last_op_status.set(format!(
                                                "grant.attach: ok={} grant_id={}",
                                                r.ok,
                                                short_protocol_id(r.grant_id.as_str())
                                            )),
                                            Err(err) => last_op_status.set(format!(
                                                "grant.attach failed: {}", err.display()
                                            )),
                                        }
                                    });
                                }
                            },
            "Attach grant"
                        }
                    }
                    // Detach list: per CKP-0008 §4.11 each grant row
                    // carries its real grant_id (from the agent view's
                    // grant_snapshot[]); detaching submits
                    // ck.self.agent.grant.resource.delete for that id.
                    // Use "Get" on an agent row to load this list.
                    if selected_grants.read().is_empty() {
                        div { class: "muted", "data-testid": "agent-admin-grant-empty",
                            "No grants loaded. Use \"Get\" on an agent above to load its capability grants."
                        }
                    } else {
                        div { class: "timeline", "data-testid": "agent-admin-grant-list",
                            for grant in selected_grants.read().iter() {
                                {
                                    let grant_id = grant
                                        .get("grant_id")
                                        .or_else(|| grant.get("id"))
                                        .and_then(Value::as_str)
                                        .unwrap_or_default()
                                        .to_owned();
                                    let grant_status = grant
                                        .get("status")
                                        .and_then(Value::as_str)
                                        .unwrap_or("active")
                                        .to_owned();
                                    let expires_at = grant
                                        .get("expires_at")
                                        .and_then(Value::as_str)
                                        .unwrap_or("-")
                                        .to_owned();
                                    let grant_id_label = short_protocol_id(&grant_id);
                                    rsx! {
                                        div {
                                            class: "event",
                                            "data-testid": "agent-admin-grant-row",
                                            "data-grant-id": "{grant_id}",
                                            div { class: "event-head",
                                                span { class: "mono", title: "{grant_id}", "{grant_id_label}" }
                                                span { class: "badge", "{grant_status}" }
                                            }
                                            div { class: "muted", "expires_at: {expires_at}" }
                                            div { class: "actions",
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    "data-testid": "agent-admin-grant-detach-button",
                                                    disabled: grant_id.is_empty(),
                                                    onclick: {
                                                        let base = base_url.clone();
                                                        let grant_id = grant_id.clone();
                                                        move |_| {
                                                            let id = selected_agent_id();
                                                            if id.is_empty() || grant_id.is_empty() { return; }
                                                            let base = base.clone();
                                                            let api_token = token();
                                                            let grant_id = grant_id.clone();
                                                            let grant_id_for_retain = grant_id.clone();
                                                            spawn(async move {
                                                                match with_authed_api(&base, api_token, move |api| {
                                                                    let id = id.clone();
                                                                    let grant_id = grant_id.clone();
                                                                    async move {
                                                                        api.agent_grant_detach(&id, &grant_id).await
                                                                    }
                                                                })
                                                                .await
                                                                {
                                                                    Ok(r) => {
                                                                        // Drop the detached row from the
                                                                        // local snapshot so the list
                                                                        // reflects the revoke immediately.
                                                                        selected_grants.write().retain(|g| {
                                                                            g.get("grant_id")
                                                                                .or_else(|| g.get("id"))
                                                                                .and_then(Value::as_str)
                                                                                != Some(grant_id_for_retain.as_str())
                                                                        });
                                                                        last_op_status.set(format!(
                                                                            "grant.detach: ok={} revoked_at={}",
                                                                            r.ok, r.revoked_at
                                                                        ));
                                                                    }
                                                                    Err(err) => last_op_status.set(format!(
                                                                        "grant.detach failed: {}", err.display()
                                                                    )),
                                                                }
                                                            });
                                                        }
                                                    },
                                                    "Detach"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ───────────────────────────────────────────────────────
            // Sidecar thread ensure
            // (ck.self.agent.sidecar_thread.command.ensure)
            // ───────────────────────────────────────────────────────
            div { class: "event", "data-testid": "agent-admin-sidecar-ensure",
                div { class: "event-head",
                    span { "Sidecar thread (ensure)" }
                    span { class: "badge blue", "ck.self.agent.sidecar_thread.command.ensure" }
                }
                div { class: "muted",
                    "Ensures the controller-private sidecar objects for the selected agent in a Realm."
                }
                div { class: "workflow-form",
                    Input {
                        "data-testid": "agent-admin-sidecar-realm-input",
                        placeholder: "realm_id",
                        value: "{sidecar_realm}",
                        oninput: move |event: FormEvent| sidecar_realm.set(event.value()),
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "agent-admin-sidecar-ensure-button",
                            disabled: selected_agent_id().is_empty()
                                || sidecar_realm().trim().is_empty()
                                || controller_did.trim().is_empty(),
                            onclick: {
                                let base = base_url.clone();
                                let controller_did = controller_did.clone();
                                move |_| {
                                    let id = selected_agent_id();
                                    if id.is_empty() { return; }
                                    let base = base.clone();
                                    let api_token = token();
                                    let realm = sidecar_realm();
                                    let controller = controller_did.clone();
                                    // Typed ids fail fast on malformed
                                    // input before the wire round-trip.
                                    let realm_id = match RealmId::new(realm.trim().to_owned()) {
                                        Ok(realm_id) => realm_id,
                                        Err(err) => {
                                            last_op_status.set(format!("invalid realm_id: {err:?}"));
                                            return;
                                        }
                                    };
                                    let agent_principal_id = match cokret_sdk::Did::new(id.clone()) {
                                        Ok(did) => did,
                                        Err(err) => {
                                            last_op_status.set(format!("invalid agent_principal_id: {err:?}"));
                                            return;
                                        }
                                    };
                                    let controller_principal_id = match cokret_sdk::Did::new(controller) {
                                        Ok(did) => did,
                                        Err(err) => {
                                            last_op_status.set(format!("invalid controller_principal_id: {err:?}"));
                                            return;
                                        }
                                    };
                                    let body = AgentSidecarThreadEnsureRequestBody {
                                        realm_id,
                                        controller_principal_id,
                                        agent_principal_id,
                                    };
                                    spawn(async move {
                                        match with_authed_api(&base, api_token, move |api| {
                                            let id = id.clone();
                                            let body = body.clone();
                                            async move {
                                                api.agent_sidecar_thread_ensure(&id, &body).await
                                            }
                                        })
                                        .await
                                        {
                                            Ok(r) => last_op_status.set(format!(
                                                "sidecar.ensure: circle={} strand={} relation={}",
                                                short_protocol_id(r.private_circle_id.as_str()),
                                                short_protocol_id(r.private_strand_id.as_str()),
                                                short_protocol_id(r.private_relation_id.as_str())
                                            )),
                                            Err(err) => last_op_status.set(format!(
                                                "sidecar.ensure failed: {}", err.display()
                                            )),
                                        }
                                    });
                                }
                            },
                            "Ensure sidecar thread"
                        }
                    }
                }
            }

            // ───────────────────────────────────────────────────────
            // Sidecar exposure disclosure (CKP-0009 §3 invariant 10 +
            // CKP-0008 §4.5). UI scaffold only — backend projection
            // is TODO(P3-impl).
            // ───────────────────────────────────────────────────────
            // ───────────────────────────────────────────────────────
            // CKP-0010 — participation policy. Per Realm scope, choose
            // whether the agent may reply as itself, accept @mentions
            // from other users, and act on the controller's behalf.
            // Each bit is capped by the deployment ⊇ Realm ⊇ Circle ⊇
            // Strand ceiling; soland rejects selections above it.
            // ───────────────────────────────────────────────────────
            div { class: "event", "data-testid": "agent-admin-participation",
                div { class: "event-head",
                    span { "Participation policy" }
                    span { class: "badge blue", "ck.self.agent.participation.resource.replace" }
                }
                div { class: "muted",
                    "Per Realm: let the selected agent reply as itself, accept @mentions from other users, or act on your behalf. Each switch is capped by the Realm / Circle / Strand ceiling."
                }
                div { class: "workflow-form",
                    Input {
                        "data-testid": "agent-admin-participation-realm-input",
                        placeholder: "realm_id (ck:realm:...)",
                        value: "{participation_realm}",
                        oninput: move |event: FormEvent| participation_realm.set(event.value()),
                    }
                    label { class: "metric", "data-testid": "agent-admin-participation-reply-row",
                        Checkbox {
                            "data-testid": "agent-admin-participation-reply",
                            checked: if participation_reply() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                            on_checked_change: move |s: CheckboxState| participation_reply.set(bool::from(s)),
                        }
                        span { "reply (post as agent)" }
                    }
                    label { class: "metric", "data-testid": "agent-admin-participation-mention-row",
                        Checkbox {
                            "data-testid": "agent-admin-participation-mention",
                            checked: if participation_mention() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                            on_checked_change: move |s: CheckboxState| participation_mention.set(bool::from(s)),
                        }
                        span { "accept @mentions from other users" }
                    }
                    label { class: "metric", "data-testid": "agent-admin-participation-aob-row",
                        Checkbox {
                            "data-testid": "agent-admin-participation-aob",
                            checked: if participation_aob() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                            on_checked_change: move |s: CheckboxState| participation_aob.set(bool::from(s)),
                        }
                        span { "act on my behalf" }
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "agent-admin-participation-save-button",
                            disabled: selected_agent_id().is_empty() || participation_realm().trim().is_empty(),
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let id = selected_agent_id();
                                    if id.is_empty() { return; }
                                    let realm = participation_realm();
                                    let realm_id = match RealmId::new(realm.trim()) {
                                        Ok(r) => r,
                                        Err(_) => {
                                            last_op_status.set("participation: invalid realm_id".to_owned());
                                            return;
                                        }
                                    };
                                    let base = base.clone();
                                    let api_token = token();
                                    let body = AgentParticipationSetRequestBody {
                                        scope: AgentParticipationScope::Realm { realm_id },
                                        selection: AgentParticipation {
                                            reply: participation_reply(),
                                            accept_third_party_mention: participation_mention(),
                                            act_on_behalf: participation_aob(),
                                        },
                                    };
                                    spawn(async move {
                                        match with_authed_api(&base, api_token, move |api| {
                                            let id = id.clone();
                                            let body = body.clone();
                                            async move {
                                                api.agent_participation_set(&id, &body).await
                                            }
                                        })
                                        .await
                                        {
                                            Ok(r) => {
                                                last_op_status.set(format!(
                                                    "participation.set ok ({} scope(s))",
                                                    r.entries.len()
                                                ));
                                                participation_entries.set(r.entries);
                                            }
                                            Err(err) => last_op_status.set(format!(
                                                "participation.set failed: {}", err.display()
                                            )),
                                        }
                                    });
                                }
                            },
                            "Save participation"
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "agent-admin-participation-load-button",
                            disabled: selected_agent_id().is_empty(),
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let id = selected_agent_id();
                                    if id.is_empty() { return; }
                                    let base = base.clone();
                                    let api_token = token();
                                    spawn(async move {
                                        match with_authed_api(&base, api_token, move |api| {
                                            let id = id.clone();
                                            async move {
                                                api.agent_participation_get(&id).await
                                            }
                                        })
                                        .await
                                        {
                                            Ok(r) => {
                                                last_op_status.set(format!(
                                                    "participation.get ok ({} scope(s))",
                                                    r.entries.len()
                                                ));
                                                participation_entries.set(r.entries);
                                            }
                                            Err(err) => last_op_status.set(format!(
                                                "participation.get failed: {}", err.display()
                                            )),
                                        }
                                    });
                                }
                            },
                            "Load resolved"
                        }
                    }
                    if !participation_entries.read().is_empty() {
                        div { class: "timeline", "data-testid": "agent-admin-participation-entries",
                            for entry in participation_entries.read().iter() {
                                {
                                    let key = entry.scope.scope_key();
                                    let sel = entry.selection;
                                    let eff = entry.effective;
                                    let ceil = entry.ceiling;
                                    rsx! {
                                        div {
                                            class: "event",
                                            "data-testid": "agent-admin-participation-entry",
                                            "data-scope-key": "{key}",
                                            div { class: "event-head",
                                                span { class: "mono", "{key}" }
                                            }
                                            div { class: "muted",
                                                "effective: reply={eff.reply} mention={eff.accept_third_party_mention} act_on_behalf={eff.act_on_behalf}"
                                            }
                                            div { class: "muted",
                                                "ceiling: reply={ceil.reply} mention={ceil.accept_third_party_mention} act_on_behalf={ceil.act_on_behalf} · selection: reply={sel.reply} mention={sel.accept_third_party_mention} act_on_behalf={sel.act_on_behalf}"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            SidecarExposureDisclosure {
                controller_did: controller_did.clone(),
                resume_sidecar_refs,
            }

            DraftApprovalPanel {
                base_url: base_url.clone(),
                token,
                controller_did: controller_did.clone(),
            }
        }
    }
}

/// CKP-0009 §3 invariant 10 / CKP-0008 §4.5 — sidecar exposure
/// disclosure panel. Before resume, the controller MUST acknowledge any
/// sidecar Circles that became newly visible while the agent was paused.
/// The acknowledged object_refs feed `resume_sidecar_refs`, which the
/// resume button folds into a real `agent_sidecar_exposure_ack`.
///
/// Data source: soland's sidecar exposure projection
/// (`ck.agent.sidecar_projection.v1`) is not yet wired, so the disclosed
/// refs are entered by the operator here; once the projection ships, the
/// agent view's exposure field populates this list automatically.
#[component]
pub fn SidecarExposureDisclosure(
    controller_did: String,
    resume_sidecar_refs: Signal<Vec<String>>,
) -> Element {
    let mut ref_input = use_signal(String::new);
    rsx! {
        div { class: "event", "data-testid": "sidecar-exposure-disclosure",
            div { class: "event-head",
                span { "Sidecar exposure disclosure" }
                span { class: "badge", "CKP-0009 §3 inv. 10" }
            }
            div { class: "muted",
                "Controller: {controller_did}. Before resuming a paused agent, acknowledge any sidecar Circles that became newly visible while it was paused. Acknowledged refs are sent as the resume sidecar_exposure_ack."
            }
            div { class: "muted", "data-testid": "sidecar-exposure-data-source",
                "Data source: soland sidecar exposure projection (ck.agent.sidecar_projection.v1) pending — enter the disclosed sidecar object_refs below until the projection auto-populates this list."
            }
            div { class: "workflow-form",
                Input {
                    "data-testid": "sidecar-exposure-ref-input",
                    placeholder: "sidecar object_ref (ck:circle:... or ck:strand:...)",
                    value: "{ref_input}",
                    oninput: move |event: FormEvent| ref_input.set(event.value()),
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "sidecar-exposure-ack-add-button",
                        disabled: ref_input().trim().is_empty(),
                        onclick: move |_| {
                            let value = ref_input().trim().to_owned();
                            if value.is_empty() { return; }
                            let mut refs = resume_sidecar_refs.write();
                            if !refs.contains(&value) {
                                refs.push(value);
                            }
                            ref_input.set(String::new());
                        },
                        "Acknowledge ref"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "sidecar-exposure-ack-clear-button",
                        disabled: resume_sidecar_refs.read().is_empty(),
                        onclick: move |_| resume_sidecar_refs.set(Vec::new()),
                        "Clear"
                    }
                }
                if resume_sidecar_refs.read().is_empty() {
                    div { class: "muted", "data-testid": "sidecar-exposure-ack-empty",
                        "No newly-exposed sidecars acknowledged. Resume will send no exposure ack."
                    }
                } else {
                    div { class: "timeline", "data-testid": "sidecar-exposure-ack-list",
                        for sidecar_ref in resume_sidecar_refs.read().iter() {
                            div {
                                class: "metric",
                                "data-testid": "sidecar-exposure-ack-row",
                                "data-sidecar-ref": "{sidecar_ref}",
                                span { class: "mono", "{sidecar_ref}" }
                                span { class: "badge green", "acknowledged" }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Action-approve dialog component. Renders the payload digest,
/// expiry, and single-use nonce status of an incoming
/// `ck.agent.action_request` notification; on confirm it submits a
/// `ck.agent.action_approve` event.
///
/// TODO(P3-impl): the action_request payload pipe goes through
/// chime's push frame parser (chime P3) → this dialog. Today the
/// dialog accepts a payload-digest string as input so the wire
/// envelope can be exercised; full integration with the notification
/// stream lands in P3-impl.
#[component]
pub fn ActionApproveDialog(
    base_url: String,
    token: Signal<String>,
    actor_id: String,
    space_id: String,
    request_id: String,
    payload_digest: String,
    expires_at: String,
    nonce_status: String,
    now: String,
) -> Element {
    let mut state = use_signal(|| ActionApproveDialogState::Reviewing);
    let mut status_text = use_signal(String::new);

    let expired = is_action_request_expired(&expires_at, &now);
    let nonce_st = match nonce_status.as_str() {
        "fresh" => ActionRequestNonceStatus::Fresh,
        "consumed" => ActionRequestNonceStatus::Consumed,
        _ => ActionRequestNonceStatus::Unknown,
    };
    let can_submit = !expired
        && nonce_st != ActionRequestNonceStatus::Consumed
        && state() == ActionApproveDialogState::Reviewing;

    rsx! {
        div {
            class: "event",
            "data-testid": "action-approve-dialog",
            "data-state": "{state().as_data_state()}",
            "data-request-id": "{request_id}",
            div { class: "event-head",
                span { "Approve agent action" }
                span { class: "{nonce_st.badge_class()}", "nonce {nonce_st.label()}" }
            }
            div { class: "muted", "data-testid": "action-approve-payload-digest",
                "payload digest: {payload_digest}"
            }
            div { class: "muted", "data-testid": "action-approve-expires-at",
                "expires_at: {expires_at}"
            }
            if expired {
                div {
                    class: "badge red",
                    "data-testid": "action-approve-expiry-blocked",
                    "expired — submit rejected"
                }
            }
            div { class: "actions",
                Button {
                    variant: ButtonVariant::Primary,
                    "data-testid": "action-approve-confirm-button",
                    disabled: !can_submit,
                    onclick: {
                        let base = base_url.clone();
                        let actor = actor_id.clone();
                        let space = space_id.clone();
                        let request_id = request_id.clone();
                        let digest = payload_digest.clone();
                        move |_| {
                            state.set(ActionApproveDialogState::Submitting);
                            let base = base.clone();
                            let actor = actor.clone();
                            let space = space.clone();
                            let request_id = request_id.clone();
                            let digest = digest.clone();
                            let api_token = token();
                            spawn(async move {
                                // Submit a ck.agent.action_approve
                                // event. The payload carries the
                                // request_id + the digest we approved
                                // so the reducer can match it back to
                                // the originating action_request and
                                // burn the single-use nonce.
                                let op = crate::operation::OperationBuilder::new(
                                    &space,
                                    &actor,
                                    "ck.agent.action_approve",
                                )
                                .body(json!({
                                    "request_id": request_id,
                                    "payload_digest": digest,
                                }))
                                .build("yougen");
                                match with_authed_api(&base, api_token, move |api| {
                                    let op = op.clone();
                                    async move {
                                        api.submit_event_envelope(&op).await
                                    }
                                })
                                .await
                                {
                                    Ok(resp) => {
                                        state.set(ActionApproveDialogState::Submitted);
                                        status_text.set(format!(
                                            "approved; event_id {}",
                                            resp.event_id
                                        ));
                                    }
                                    Err(err) => {
                                        state.set(ActionApproveDialogState::Reviewing);
                                        status_text.set(format!(
                                            "approve failed: {}", err.display()
                                        ));
                                    }
                                }
                            });
                        }
                    },
                    "Approve"
                }
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "action-approve-reject-button",
                    disabled: state() == ActionApproveDialogState::Submitting,
                    onclick: move |_| {
                        state.set(ActionApproveDialogState::Rejected);
                        status_text.set("rejected locally — no approve event will be submitted".to_owned());
                    },
                    "Reject"
                }
            }
            if !status_text().is_empty() {
                div { class: "muted", "data-testid": "action-approve-status", "{status_text}" }
            }
        }
    }
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

/// CKP-0008 §4.8 — controller-owned draft approval panel. Lists
/// `ck.agent.draft.v1` drafts and lets the controller approve (submits
/// `ck.agent.action_approve`) or reject (submits `ck.agent.action_reject`).
///
/// Data source: drafts are delivered as controller-owned account-data
/// over `ck.self.account.subscribe`. soland's draft materialization
/// (agent `ck.agent.draft.propose` → controller `ck.agent.draft.v1`) is
/// pending, so the list is populated here by pasting a draft payload;
/// the approve / reject call chain is fully wired and exercises the real
/// wire envelope today. Once the projection ships, the subscribe fold
/// auto-populates this list.
#[component]
pub fn DraftApprovalPanel(
    base_url: String,
    token: Signal<String>,
    controller_did: String,
) -> Element {
    let mut drafts = use_signal(Vec::<Value>::new);
    let mut draft_input = use_signal(String::new);
    let mut panel_status = use_signal(String::new);

    // Controller-private events (action_approve / action_reject) author
    // in the controller's principal-control realm.
    let principal_realm = cokret_sdk::Did::new(controller_did.clone())
        .ok()
        .map(|principal| cokret_sdk::auth::principal_control_realm_id(&principal).to_string());

    rsx! {
        div { class: "event", "data-testid": "agent-draft-approval",
            div { class: "event-head",
                span { "Draft approvals" }
                span { class: "badge blue", "ck.agent.draft.v1" }
            }
            div { class: "muted",
                "Review agent-proposed drafts before anything reaches a shared Realm. Approve submits ck.agent.action_approve (binds draft_id + content digest + single-use nonce + expiry); reject submits ck.agent.action_reject."
            }
            div { class: "muted", "data-testid": "agent-draft-data-source",
                "Data source: controller-owned account-data over ck.self.account.subscribe; soland draft materialization pending — paste a ck.agent.draft.v1 payload below to review it now."
            }
            if principal_realm.is_none() {
                div { class: "badge amber", "data-testid": "agent-draft-no-realm",
                    "controller principal realm unavailable — sign in to enable approvals"
                }
            }
            div { class: "workflow-form",
                Input {
                    "data-testid": "agent-draft-input",
                    placeholder: "ck.agent.draft.v1 payload (JSON)",
                    value: "{draft_input}",
                    oninput: move |event: FormEvent| draft_input.set(event.value()),
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "agent-draft-add-button",
                        disabled: draft_input().trim().is_empty(),
                        onclick: move |_| {
                            match serde_json::from_str::<Value>(draft_input().as_str()) {
                                Ok(value) => {
                                    drafts.write().push(value);
                                    draft_input.set(String::new());
                                    panel_status.set("draft added".to_owned());
                                }
                                Err(err) => panel_status.set(format!(
                                    "draft is not valid JSON: {err}"
                                )),
                            }
                        },
                        "Add draft"
                    }
                }
                if !panel_status().is_empty() {
                    div { class: "muted", "data-testid": "agent-draft-status", "{panel_status}" }
                }
            }
            if drafts.read().is_empty() {
                div { class: "muted", "data-testid": "agent-draft-empty",
                    "No drafts to review."
                }
            } else {
                div { class: "timeline", "data-testid": "agent-draft-list",
                    for (idx, draft) in drafts.read().iter().enumerate() {
                        {
                            let draft_id = draft
                                .get("draft_id")
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_owned();
                            let proposed_action = draft
                                .get("proposed_action")
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_owned();
                            let agent_id = draft
                                .get("agent_principal_id")
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_owned();
                            let expires_at = draft
                                .get("expires_at")
                                .and_then(Value::as_str)
                                .unwrap_or("-")
                                .to_owned();
                            let body_preview = draft
                                .get("content")
                                .and_then(|c| c.get("body"))
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_owned();
                            let agent_id_label = short_protocol_id(&agent_id);
                            let draft_id_label = short_protocol_id(&draft_id);
                            rsx! {
                                div {
                                    class: "event",
                                    "data-testid": "agent-draft-row",
                                    "data-draft-id": "{draft_id}",
                                    div { class: "event-head",
                                        span { class: "mono", title: "{draft_id}", "{draft_id_label}" }
                                        span { class: "badge", "{proposed_action}" }
                                        span { class: "mono", title: "{agent_id}", "agent {agent_id_label}" }
                                    }
                                    if !body_preview.is_empty() {
                                        div { class: "muted", "draft: {body_preview}" }
                                    }
                                    div { class: "muted", "expires_at: {expires_at}" }
                                    div { class: "actions",
                                        Button {
                                            variant: ButtonVariant::Primary,
                                            "data-testid": "agent-draft-approve-button",
                                            disabled: principal_realm.is_none(),
                                            onclick: {
                                                let base = base_url.clone();
                                                let actor = controller_did.clone();
                                                let realm = principal_realm.clone();
                                                move |_| {
                                                    let Some(realm) = realm.clone() else { return; };
                                                    let base = base.clone();
                                                    let actor = actor.clone();
                                                    let api_token = token();
                                                    let draft = drafts.read()[idx].clone();
                                                    // Default approval window: 1h
                                                    // from now, single-use nonce.
                                                    let approval_expires_at = crate::clock::rfc3339_secs_in(60);
                                                    let payload = build_action_approve_payload(
                                                        &draft, &approval_expires_at,
                                                    );
                                                    let op = crate::operation::OperationBuilder::new(
                                                        &realm,
                                                        &actor,
                                                        "ck.agent.action_approve",
                                                    )
                                                    .body(payload)
                                                    .build("yougen");
                                                    spawn(async move {
                                                        match with_authed_api(&base, api_token, move |api| {
                                                            let op = op.clone();
                                                            async move {
                                                                api.submit_event_envelope(&op).await
                                                            }
                                                        })
                                                        .await
                                                        {
                                                            Ok(resp) => {
                                                                drafts.write().remove(idx);
                                                                panel_status.set(format!(
                                                                    "approved; event_id {}",
                                                                    resp.event_id
                                                                ));
                                                            }
                                                            Err(err) => panel_status.set(format!(
                                                                "approve failed: {}", err.display()
                                                            )),
                                                        }
                                                    });
                                                }
                                            },
                                            "Approve"
                                        }
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "agent-draft-reject-button",
                                            disabled: principal_realm.is_none(),
                                            onclick: {
                                                let base = base_url.clone();
                                                let actor = controller_did.clone();
                                                let realm = principal_realm.clone();
                                                move |_| {
                                                    let Some(realm) = realm.clone() else { return; };
                                                    let base = base.clone();
                                                    let actor = actor.clone();
                                                    let api_token = token();
                                                    let draft = drafts.read()[idx].clone();
                                                    let payload = build_action_reject_payload(&draft);
                                                    let op = crate::operation::OperationBuilder::new(
                                                        &realm,
                                                        &actor,
                                                        "ck.agent.action_reject",
                                                    )
                                                    .body(payload)
                                                    .build("yougen");
                                                    spawn(async move {
                                                        match with_authed_api(&base, api_token, move |api| {
                                                            let op = op.clone();
                                                            async move {
                                                                api.submit_event_envelope(&op).await
                                                            }
                                                        })
                                                        .await
                                                        {
                                                            Ok(resp) => {
                                                                drafts.write().remove(idx);
                                                                panel_status.set(format!(
                                                                    "rejected; event_id {}",
                                                                    resp.event_id
                                                                ));
                                                            }
                                                            Err(err) => panel_status.set(format!(
                                                                "reject failed: {}", err.display()
                                                            )),
                                                        }
                                                    });
                                                }
                                            },
                                            "Reject"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod personal_agent_tests {
    use super::*;

    #[test]
    fn actor_kind_label_maps_four_canonical_variants() {
        assert_eq!(actor_kind_label(Some("native")), Some("Native"));
        assert_eq!(actor_kind_label(Some("ghost")), Some("Ghost Actor"));
        assert_eq!(actor_kind_label(Some("service")), Some("Service"));
        assert_eq!(actor_kind_label(Some("agent")), Some("Personal Agent"));
    }

    #[test]
    fn actor_kind_label_falls_back_for_unknown_or_missing() {
        assert_eq!(actor_kind_label(None), None);
        assert_eq!(actor_kind_label(Some("")), None);
        assert_eq!(actor_kind_label(Some("future_kind")), None);
    }

    #[test]
    fn actor_kind_badge_class_distinguishes_ghost_and_native() {
        assert_eq!(actor_kind_badge_class(Some("native")), "badge");
        assert_ne!(
            actor_kind_badge_class(Some("ghost")),
            actor_kind_badge_class(Some("native"))
        );
        assert_ne!(
            actor_kind_badge_class(Some("agent")),
            actor_kind_badge_class(Some("service"))
        );
    }

    #[test]
    fn action_request_expired_only_when_now_strictly_after_expires_at() {
        assert!(is_action_request_expired(
            "2026-05-26T00:00:00Z",
            "2026-05-27T00:00:00Z"
        ));
        assert!(!is_action_request_expired(
            "2026-05-27T00:00:00Z",
            "2026-05-26T00:00:00Z"
        ));
        assert!(!is_action_request_expired("", "2026-05-26T00:00:00Z"));
        assert!(!is_action_request_expired("2026-05-26T00:00:00Z", ""));
    }

    #[test]
    fn nonce_status_badge_classes_are_distinct() {
        assert_ne!(
            ActionRequestNonceStatus::Fresh.badge_class(),
            ActionRequestNonceStatus::Consumed.badge_class()
        );
    }

    #[test]
    fn requested_scope_widens_to_realm_when_any_write_preset_selected() {
        assert_eq!(requested_scope_for_presets(&[]), None);
        assert_eq!(
            requested_scope_for_presets(&[AgentPermissionPreset::ReadOnly]),
            Some(AgentKeyScope::Limited)
        );
        assert_eq!(
            requested_scope_for_presets(&[
                AgentPermissionPreset::ReadOnly,
                AgentPermissionPreset::ReplyAsAgent,
            ]),
            Some(AgentKeyScope::Realm)
        );
    }

    #[test]
    fn expand_preset_grant_emits_registered_actions_and_inactive_flag() {
        let grant = expand_preset_grant(
            AgentPermissionPreset::ReplyAsAgent,
            "did:web:agents.example:summary",
            Some("ck:realm:01"),
            "2026-06-26T00:00:00Z",
        );
        assert_eq!(
            grant["actions"],
            serde_json::json!(["ck.message.create", "ck.reaction.add"])
        );
        assert_eq!(grant["subject"], "did:web:agents.example:summary");
        assert_eq!(grant["resources"][0]["kind"], "realm");
        assert_eq!(grant["resources"][0]["realm_id"], "ck:realm:01");
        assert_eq!(grant["effective_after_first_authorized_key"], true);
        assert_eq!(grant["expires_at"], "2026-06-26T00:00:00Z");
        // Non-aob presets carry no controller-approval constraint.
        assert!(grant.get("constraints").is_none());
    }

    #[test]
    fn expand_preset_grant_act_on_behalf_carries_controller_approval() {
        let grant = expand_preset_grant(
            AgentPermissionPreset::ActOnBehalf,
            "did:web:agents.example:summary",
            None,
            "2026-06-26T00:00:00Z",
        );
        // No realm supplied -> empty selector (controller narrows later).
        assert_eq!(grant["resources"], serde_json::json!([]));
        let constraint = &grant["constraints"][0];
        assert_eq!(constraint["constraint_type"], "claim_based");
        assert_eq!(constraint["subtype"], "accountability");
        assert_eq!(constraint["controller_approval_required"], true);
    }

    #[test]
    fn agent_pair_url_uses_https_and_request_param() {
        assert_eq!(
            agent_pair_url("https://cokret.example/", "0197-req"),
            "https://cokret.example/auth/account/agent-pair?request=0197-req"
        );
    }

    #[test]
    fn build_action_approve_payload_binds_draft_digest_and_nonce() {
        let draft = serde_json::json!({
            "type": "ck.agent.draft.v1",
            "draft_id": "0197-draft",
            "agent_principal_id": "did:web:agents.example:summary",
            "proposed_action": "ck.message.create",
            "target": {"realm_id": "ck:realm:01"},
            "content": {"body": "draft text"},
        });
        let payload = build_action_approve_payload(&draft, "2026-06-26T01:00:00Z");
        assert_eq!(payload["draft_id"], "0197-draft");
        assert_eq!(payload["proposed_action"], "ck.message.create");
        assert_eq!(payload["approval_expires_at"], "2026-06-26T01:00:00Z");
        let digest = payload["content_digest"].as_str().unwrap();
        assert!(digest.starts_with("sha256:"));
        // Approving as-is means both digests match.
        assert_eq!(payload["content_digest"], payload["approved_payload_digest"]);
        // Nonce is a fresh uuid, not empty.
        assert!(!payload["nonce"].as_str().unwrap().is_empty());
    }

    #[test]
    fn dialog_state_round_trip_data_state_tokens() {
        for s in [
            ActionApproveDialogState::Idle,
            ActionApproveDialogState::Reviewing,
            ActionApproveDialogState::Submitting,
            ActionApproveDialogState::Submitted,
            ActionApproveDialogState::Rejected,
            ActionApproveDialogState::NonceExhausted,
        ] {
            // Every variant maps to a non-empty kebab/snake string.
            let token = s.as_data_state();
            assert!(!token.is_empty());
            assert!(!token.contains(' '));
        }
    }
}

#[cfg(test)]
mod tests {
    /// Pin endpoint body shape so the builder stays aligned with
    /// event-payload.schema.json#/$defs/agent_endpoint_payload.
    #[test]
    fn agent_endpoint_body_keys_pin_canonical_wire() {
        let op = crate::operation::ck_ops::agent_endpoint(
            "ck:space:test",
            "did:web:alice.example",
            "did:web:agent.example",
            "ck.agent.v1",
            &["strand.read"],
        )
        .build("yougen");
        assert_eq!(op.payload["agent_id"], "did:web:agent.example");
        assert_eq!(op.payload["endpoints"][0]["protocol"], "ck.agent.v1");
        assert_eq!(op.payload["endpoints"][0]["capabilities"][0], "strand.read");
        assert!(op.payload.get("protocol").is_none());
        assert!(op.payload.get("capabilities").is_none());
    }

    #[test]
    fn agent_result_body_carries_audit_binding() {
        let op = crate::operation::ck_ops::agent_interop_session_result(
            "ck:space:test",
            "did:web:alice.example",
            "ck:session:test",
            serde_json::json!({"summary": "ok"}),
            serde_json::json!({"merkle_root": "sha256:abc"}),
        )
        .build("yougen");
        assert_eq!(op.payload["audit_binding"]["merkle_root"], "sha256:abc");
    }

    // Pin the verify helper's outcomes for each canonical wire
    // shape the panel can encounter.

    use serde_json::{Value, json};

    use super::{AuditVerifyStatus, verify_agent_audit_binding};

    fn build_ed25519_result_payload(
        session_id: &str,
        agent_id: &str,
        echo: serde_json::Value,
        actor: &str,
        seed: &[u8; 32],
    ) -> serde_json::Value {
        let signed = cokret_sdk::agent_binding::sign_ed25519_audit_binding(
            seed, session_id, agent_id, &echo, actor,
        );
        json!({
            "session_id": session_id,
            "status": "completed",
            "result": {
                "echo": echo,
                "agent_principal_id": agent_id,
            },
            "audit_binding": {
                "binding_kind": "ed25519_v1",
                "actor_id": actor,
                "key_id": "soland.reference.agent_echo.ed25519_v1",
                "signature": signed.signature_b64,
                "public_key_b64": signed.public_key_b64,
                "canonical_subject": signed.canonical_subject,
            },
        })
    }

    #[test]
    fn verify_helper_marks_valid_ed25519_binding_as_valid() {
        let seed = [11u8; 32];
        let payload = build_ed25519_result_payload(
            "ck:session:v1",
            "did:web:agent.example",
            json!({"op": "ping"}),
            "did:web:alice.example",
            &seed,
        );
        assert_eq!(
            verify_agent_audit_binding(&payload),
            AuditVerifyStatus::Valid
        );
    }

    #[test]
    fn verify_helper_detects_tampered_echo_via_subject_mismatch() {
        let seed = [12u8; 32];
        let mut payload = build_ed25519_result_payload(
            "ck:session:v2",
            "did:web:agent.example",
            json!({"op": "ping"}),
            "did:web:alice.example",
            &seed,
        );
        payload["result"]["echo"] = json!({"op": "tampered"});
        assert_eq!(
            verify_agent_audit_binding(&payload),
            AuditVerifyStatus::SubjectMismatch
        );
    }

    #[test]
    fn verify_helper_returns_absent_when_no_binding_block() {
        let payload = json!({
            "session_id": "ck:session:v3",
            "status": "failed",
            "result": Value::Null,
            "error": {"code": "unknown_agent"},
        });
        assert_eq!(
            verify_agent_audit_binding(&payload),
            AuditVerifyStatus::Absent
        );
    }

    #[test]
    fn verify_helper_returns_unsupported_for_unknown_binding_kind() {
        let payload = json!({
            "session_id": "ck:session:v4",
            "status": "completed",
            "result": {"echo": null, "agent_principal_id": "did:web:agent.example"},
            "audit_binding": {
                "binding_kind": "unsupported_future_scheme",
                "actor_id": "did:web:alice.example",
                "signature": "deadbeef",
                "canonical_subject": "",
            },
        });
        assert_eq!(
            verify_agent_audit_binding(&payload),
            AuditVerifyStatus::Unsupported
        );
    }

    /// The verify helper treats `hmac_sha256_v1` (and any unknown
    /// `binding_kind`) as `Unsupported` - no special-case path.
    #[test]
    fn verify_helper_returns_unsupported_for_hmac_binding() {
        let payload = json!({
            "session_id": "ck:session:hmac",
            "status": "completed",
            "result": {"echo": {"op": "ping"}, "agent_principal_id": "did:web:agent.example"},
            "audit_binding": {
                "binding_kind": "hmac_sha256_v1",
                "actor_id": "did:web:alice.example",
                "key_id": "soland.reference.agent_echo.v1",
                "signature": "00".repeat(32),
                "canonical_subject": "",
            },
        });
        assert_eq!(
            verify_agent_audit_binding(&payload),
            AuditVerifyStatus::Unsupported
        );
    }

    #[test]
    fn verify_helper_returns_malformed_when_ed25519_signature_is_not_base64() {
        let seed = [13u8; 32];
        let mut payload = build_ed25519_result_payload(
            "ck:session:v5",
            "did:web:agent.example",
            json!({}),
            "did:web:alice.example",
            &seed,
        );
        payload["audit_binding"]["signature"] = json!("!!!not-base64!!!");
        assert_eq!(
            verify_agent_audit_binding(&payload),
            AuditVerifyStatus::Malformed
        );
    }

    // ── G3.Y4 — handoff lifecycle + audit chain verifier ──────────

    use super::{AuditChainVerifyOutcome, HandoffState, verify_audit_chain};

    #[test]
    fn handoff_state_data_states_are_distinct() {
        let values = [
            HandoffState::Idle.as_data_state(),
            HandoffState::Pending.as_data_state(),
            HandoffState::Approved.as_data_state(),
            HandoffState::Running.as_data_state(),
            HandoffState::Completed.as_data_state(),
            HandoffState::Failed.as_data_state(),
        ];
        let uniq: std::collections::BTreeSet<_> = values.iter().collect();
        assert_eq!(uniq.len(), values.len());
    }

    #[test]
    fn handoff_state_only_pending_awaits_confirmation() {
        assert!(HandoffState::Pending.awaits_confirmation());
        for s in [
            HandoffState::Idle,
            HandoffState::Approved,
            HandoffState::Running,
            HandoffState::Completed,
            HandoffState::Failed,
        ] {
            assert!(
                !s.awaits_confirmation(),
                "{s:?} must not await confirmation"
            );
        }
    }

    #[test]
    fn handoff_state_transcript_visible_after_approval() {
        assert!(!HandoffState::Idle.has_transcript());
        assert!(!HandoffState::Pending.has_transcript());
        for s in [
            HandoffState::Approved,
            HandoffState::Running,
            HandoffState::Completed,
            HandoffState::Failed,
        ] {
            assert!(s.has_transcript(), "{s:?} must show transcript");
        }
    }

    #[test]
    fn verify_audit_chain_returns_chain_break_for_empty() {
        let events: Vec<Value> = Vec::new();
        assert_eq!(
            verify_audit_chain(&events),
            AuditChainVerifyOutcome::ChainBreak
        );
    }

    #[test]
    fn verify_audit_chain_requires_start_then_result() {
        // Missing start
        let events = vec![json!({"kind": "ck.agent.interop_session.result"})];
        assert_eq!(
            verify_audit_chain(&events),
            AuditChainVerifyOutcome::ChainBreak
        );
        // Missing result
        let events = vec![json!({"kind": "ck.agent.interop_session.start"})];
        assert_eq!(
            verify_audit_chain(&events),
            AuditChainVerifyOutcome::ChainBreak
        );
        // Middle event is not a status
        let events = vec![
            json!({"kind": "ck.agent.interop_session.start"}),
            json!({"kind": "ck.message.create"}),
            json!({"kind": "ck.agent.interop_session.result"}),
        ];
        assert_eq!(
            verify_audit_chain(&events),
            AuditChainVerifyOutcome::ChainBreak
        );
    }

    #[test]
    fn verify_audit_chain_signature_invalid_when_audit_binding_is_garbage() {
        let events = vec![
            json!({"kind": "ck.agent.interop_session.start"}),
            json!({
                "kind": "ck.agent.interop_session.result",
                "payload": {
                    "audit_binding": {
                        "binding_kind": "ed25519_v1",
                        "signature": "definitely-not-base64",
                        "public_key_b64": "deadbeef",
                        "canonical_subject": "",
                    }
                }
            }),
        ];
        assert_eq!(
            verify_audit_chain(&events),
            AuditChainVerifyOutcome::SignatureInvalid
        );
    }

    #[test]
    fn verify_audit_chain_valid_with_real_ed25519_binding() {
        // Build a real Ed25519 binding via the SDK helper that the
        // soland in-process echo bridge uses.
        let seed = [21u8; 32];
        let session_id = "ck:session:chain";
        let agent_id = "did:web:agent.example";
        let echo = json!({"op": "ping"});
        let actor = "did:web:alice.example";
        let signed = cokret_sdk::agent_binding::sign_ed25519_audit_binding(
            &seed, session_id, agent_id, &echo, actor,
        );
        let result_payload = json!({
            "session_id": session_id,
            "status": "completed",
            "result": {"echo": echo, "agent_principal_id": agent_id},
            "audit_binding": {
                "binding_kind": "ed25519_v1",
                "actor_id": actor,
                "key_id": "soland.reference.agent_echo.ed25519_v1",
                "signature": signed.signature_b64,
                "public_key_b64": signed.public_key_b64,
                "canonical_subject": signed.canonical_subject,
            },
        });
        let events = vec![
            json!({"kind": "ck.agent.interop_session.start"}),
            json!({"kind": "ck.agent.interop_session.status"}),
            json!({
                "kind": "ck.agent.interop_session.result",
                "payload": result_payload,
            }),
        ];
        assert_eq!(verify_audit_chain(&events), AuditChainVerifyOutcome::Valid);
    }
}
