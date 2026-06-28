//! Agents - endpoint registry + interop_session monitor.
//!
//! Spec: `cokret-spec/spec/v1/zh/extensions/agent-integration.md`.
//!
//! Mirror of [`crate::views::applets::AppletsPanel`] but at the agent
//! layer:
//!   * `ck.agent.endpoint` registers an agent_id + invocation protocol + capability_proof
//!     requirement.
//!   * `ck.agent.interop_session.{start,status,result}` track agent invocations. The terminal
//!     `result` event carries a typed result payload + the audit_binding proof so the audit chat
//!     can verify the agent's output corresponds to the signed input.
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
//!
//! Module layout (purely structural split; the external path
//! `crate::views::agents::*` stays identical via the re-exports below):
//!   * [`model`]      — pure data types, presets, state machines, and verification helpers.
//!   * [`panel`]      — the `AgentsPanel` endpoint registry + interop monitor.
//!   * [`admin`]      — the `PersonalAgentAdminPanel`.
//!   * [`components`] — reusable agent components (badges, dialogs, disclosure panels).

mod admin;
mod components;
mod model;
mod panel;

#[cfg(test)]
mod tests;

pub use admin::PersonalAgentAdminPanel;
pub use components::{
    ActionApproveDialog, ActorKindBadge, DraftApprovalPanel, SidecarExposureDisclosure,
    SidecarThreadGuard,
};
pub use model::{
    ActionApproveDialogState, ActionRequestNonceStatus, AgentGrantPreset, AuditChainVerifyOutcome,
    HandoffState, InteropApprovalState, LiveSessionRow, PublishModalState, actor_kind_badge_class,
    actor_kind_label, agent_pair_url, agent_state_badge_class, agent_state_is_terminal,
    agent_state_label, agents_enabled, build_act_on_behalf_message_operation,
    build_action_approve_payload, build_action_reject_payload, expand_preset_grant,
    is_action_request_expired, is_pairing_request_expired, live_session_rows,
    participation_ceiling_reason, requested_scope_for_presets, verify_audit_chain,
};
pub use panel::AgentsPanel;
