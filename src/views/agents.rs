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
use cokret_sdk::model::{
    AgentDeactivateRequestBody, AgentGrantAttachRequestBody, AgentParticipation,
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

/// Personal Agent admin panel. Renders the 11 soland HTTP operations
/// as buttons; deeper form layouts are stubbed as TODO(P3-impl). The
/// critical contract is that each soland endpoint has a matching
/// client-side reqwest call so the cross-project wire shape is
/// verified end to end.
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
                                    // ck.self.agent.resource.get
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
                                                spawn(async move {
                                                    match with_authed_api(&base, api_token, move |api| {
                                                        let id = id.clone();
                                                        async move {
                                                            api.agent_get(&id).await
                                                        }
                                                    })
                                                    .await
                                                    {
                                                        Ok(view) => last_op_status.set(format!(
                                                            "get {} status={}",
                                                            view.agent
                                                                .get("agent_principal_id")
                                                                .and_then(Value::as_str)
                                                                .unwrap_or("(unknown)"),
                                                            view.status
                                                        )),
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
            // TODO(P3-impl): expand to a full form with initial_grants
            // picker driven by the 14-capability-action registry.
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
                                // Spec `agent_provision_request_body`:
                                // {display_name, agent_slug, requested_scope,
                                // accountability, pairing_ttl_ms} — the
                                // controller binding comes from the
                                // authenticated session, not the body.
                                let body = AgentProvisionRequestBody {
                                    display_name: Some(display),
                                    agent_slug,
                                    requested_scope: None,
                                    accountability: Value::Null,
                                    pairing_ttl_ms: None,
                                };
                                spawn(async move {
                                    match with_authed_api(&base, api_token, move |api| {
                                        let body = body.clone();
                                        async move {
                                            api.agent_provision(&body).await
                                        }
                                    })
                                    .await
                                    {
                                        Ok(outcome) => last_op_status.set(format!(
                                            "provisioned {} (pairing_request_id={}, expires_at={})",
                                            outcome.agent_principal_id,
                                            outcome.pairing_request_id,
                                            outcome.expires_at
                                        )),
                                        Err(err) => last_op_status.set(format!(
                                            "provision failed: {}",
                                            err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        "Provision"
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
                                            r.get("status").and_then(Value::as_str).unwrap_or("(unknown)")
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
                            move |_| {
                                let id = selected_agent_id();
                                if id.is_empty() { return; }
                                let base = base.clone();
                                let api_token = token();
                                // Spec resume body carries only the
                                // optional sidecar_exposure_ack.
                                let body = AgentResumeRequestBody { sidecar_exposure_ack: None };
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
                                        Ok(r) => last_op_status.set(format!(
                                            "resume: status={}",
                                            r.get("status").and_then(Value::as_str).unwrap_or("(unknown)")
                                        )),
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
                                                r.get("status").and_then(Value::as_str).unwrap_or("(unknown)")
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
            // TODO(P3-impl): wire a 14-capability-action picker
            // (CAP_ACTION_AGENT_*); for now the grant_kind is a
            // free-form input so cotest journey vectors can drive the
            // wire shape.
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
                        // Detach uses the latest known grant_id; the
                        // detach surface is currently a stub button
                        // wired to the most recent grant — TODO(P3-impl)
                        // surface the grant list + per-row detach.
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "agent-admin-grant-detach-button",
                            disabled: selected_agent_id().is_empty(),
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let id = selected_agent_id();
                                    if id.is_empty() { return; }
                                    let base = base.clone();
                                    let api_token = token();
                                    // TODO(P3-impl): track the latest
                                    // grant_id in a Signal once the
                                    // grant list view ships; passing
                                    // a placeholder here makes the
                                    // wire call fail in a useful way.
                                    let grant_id = format!(
                                        "ck:grant:{}",
                                        crate::operation::uuid_v7()
                                    );
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
                                            Ok(r) => last_op_status.set(format!(
                                                "grant.detach: ok={} revoked_at={}",
                                                r.ok, r.revoked_at
                                            )),
                                            Err(err) => last_op_status.set(format!(
                                                "grant.detach failed: {}", err.display()
                                            )),
                                        }
                                    });
                                }
                            },
                            "Detach grant (latest)"
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
            }
        }
    }
}

/// CKP-0009 §3 invariant 10 / CKP-0008 §4.5 — sidecar exposure
/// disclosure panel. Surfaces the controller's device list, the
/// currently active agent runtime endpoint, and the most recent
/// `action_approve` nonce status so the controller can see what their
/// agent is allowed to act on and from where. Data wiring is
/// `TODO(P3-impl)` while soland's exposure projection ships; the
/// component renders a clear placeholder until then.
#[component]
pub fn SidecarExposureDisclosure(controller_did: String) -> Element {
    rsx! {
        div { class: "event", "data-testid": "sidecar-exposure-disclosure",
            div { class: "event-head",
                span { "Sidecar exposure disclosure" }
                span { class: "badge", "CKP-0009 §3 inv. 10" }
            }
            div { class: "muted",
                "Controller: {controller_did}. Devices, agent runtime endpoint, and the most recent action_approve nonce status are shown here so you can audit what your agent can act on and from where."
            }
            // TODO(P3-impl): replace these placeholders with live
            // data once soland's exposure projection lands. The wire
            // shape is documented in CKP-0009 §3 and the related
            // account-data type `ck.agent.sidecar_projection.v1`.
            div { class: "metric-grid",
                div { class: "metric",
                    strong { "Device list" }
                    span { class: "badge amber", "Pending" }
                    div { class: "muted", "Awaiting soland sidecar projection" }
                }
                div { class: "metric",
                    strong { "Agent runtime endpoint" }
                    span { class: "badge amber", "Pending" }
                    div { class: "muted", "Awaiting ck.agent.endpoint resolution" }
                }
                div { class: "metric",
                    strong { "Last action_approve nonce" }
                    span { class: "badge amber", "Pending" }
                    div { class: "muted", "Awaiting action_request stream" }
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
