//! Personal-agent administration, approval, and lifecycle surfaces.

mod admin;
mod components;
pub(crate) mod model;

#[cfg(test)]
mod tests;

pub use admin::PersonalAgentAdminPanel;
pub use components::{
    ActionApproveDialog, ActorKindBadge, DraftApprovalPanel, SidecarExposureDisclosure,
    SidecarThreadGuard,
};
pub(crate) use model::mentionable_owned_agent_slugs;
pub use model::{
    ActionApproveDialogState, ActionRequestNonceStatus, AgentGrantPreset, AgentServiceScopePreset,
    actor_kind_badge_class, actor_kind_label, agent_state_badge_class, agent_state_is_terminal,
    agent_state_label, build_act_on_behalf_message_operation, build_action_approve_payload,
    build_action_reject_payload, build_agent_key_authorize_event_for_pairing,
    build_agent_pairing_bootstrap_json, content_actions_for_presets, expand_preset_grant,
    is_action_request_expired, is_pairing_request_expired, parse_runtime_key_approval_request,
    participation_ceiling_reason, requested_scope_for_presets, runtime_key_pairing_error_message,
    service_actions_for_presets, summarize_runtime_key_approval_request,
};
