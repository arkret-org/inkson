//! Integration tests for `cx.profile.agent_workspace.v1` UI components.
//!
//! Spec: `contrix-spec/spec/v1/zh/extensions/agent-workspace-profile.md`
//!       (§4.7 publish-back, §4.8 transparency_lost banner, §4.3 source
//!        authority revoke banner).
//!
//! These tests cover the **non-Dioxus-runtime parts** of the new UI
//! components: the public structural helpers and FSM-gating predicates.
//! Render-tree integration tests (Playwright) for the dashboard, publish
//! flow, and chat compose modes are tracked separately in
//! `_todos.md` AW-3.15 / AW-3.16.
//!
//! Note: Dioxus `tr()` / signal-using components panic outside a runtime,
//! so tests here exercise the pure-Rust API surface only. The view file
//! `src/views/agent_workspace.rs` carries the in-module unit tests for
//! every other invariant.

use yougen::agent_workspace_watcher::{
    SourceAuthorityRevokeReason, WatcherIntent, classify_source_event,
};
use yougen::views::agent_workspace::{
    AgentMemberProfile, AgentMembershipChangeKind, ExecutionState, OwnedAgentSummary,
    PublishSignerChoice, PublishToSourceArgs, SourceAuthorityState, TransparencyState,
    agent_runtime_may_execute, draft_mentions_owned_agent, is_controller_owned_agent,
};

// ── AW-3.7 + AW-3.16: publish-to-source modal gating ────────────────────

#[test]
fn publish_modal_is_disabled_unless_execution_active() {
    let args = PublishToSourceArgs {
        task_id: "cx:agent_task:01".to_owned(),
        source_flow_label: "ProjectX/legal".to_owned(),
        draft_preview: "draft".to_owned(),
        current_execution_state: ExecutionState::Active,
    };
    assert!(args.publish_enabled());
    assert!(args.publish_disabled_reason().is_none());

    let mut cloned = args.clone();
    cloned.current_execution_state = ExecutionState::CancelledByController;
    assert!(!cloned.publish_enabled());
    assert!(cloned.publish_disabled_reason().is_some());

    cloned.current_execution_state = ExecutionState::PendingSourceStub;
    assert!(!cloned.publish_enabled());
    assert!(cloned.publish_disabled_reason().is_some());
}

#[test]
fn publish_default_signer_is_minimum_disclosure() {
    // AW-3.20: default = AsSelf (no agent attribution).
    assert_eq!(PublishSignerChoice::default(), PublishSignerChoice::AsSelf);
}

// ── AW-3.8: add agent modal ─────────────────────────────────────────────

#[test]
fn add_agent_default_profile_is_mention_respond_only() {
    assert_eq!(
        AgentMemberProfile::default(),
        AgentMemberProfile::MentionRespondOnly
    );
}

// ── AW-3.10: private compose detection ──────────────────────────────────

#[test]
fn private_compose_detected_only_for_owned_agents() {
    let owned = vec![OwnedAgentSummary {
        agent_did: "did:web:agent.example".to_owned(),
        display_name: "agent".to_owned(),
        active_in_sources: Vec::new(),
        in_mirror_space: true,
    }];
    assert!(is_controller_owned_agent("did:web:agent.example", &owned));
    assert!(!is_controller_owned_agent("did:web:bob.example", &owned));
    assert!(draft_mentions_owned_agent(
        Some("did:web:agent.example"),
        &owned
    ));
    assert!(!draft_mentions_owned_agent(
        Some("did:web:bob.example"),
        &owned
    ));
    assert!(!draft_mentions_owned_agent(None, &owned));
}

// ── AW-3.11: watcher classification ─────────────────────────────────────

#[test]
fn watcher_classifies_redaction_with_pair_id_as_transparency_lost() {
    let result = classify_source_event(
        "cx:event:01",
        "cx.redaction",
        &serde_json::json!({
            "redacted_mention_redirect": {
                "redirect_pair_id": "01964200-0000-7000-8000-aaaaaaaaaaaa"
            }
        }),
    );
    matches!(result, WatcherIntent::MarkTransparencyLost { .. })
        .then_some(())
        .expect("redaction with redirect_pair_id must classify to MarkTransparencyLost");
}

#[test]
fn watcher_classifies_capability_revoke_as_source_authority_revoked() {
    let result = classify_source_event(
        "cx:event:02",
        "cx.capability.revoke",
        &serde_json::json!({ "grant_subject": "did:web:agent.example" }),
    );
    match result {
        WatcherIntent::MarkSourceAuthorityRevoked {
            agent_did, reason, ..
        } => {
            assert_eq!(agent_did, "did:web:agent.example");
            assert_eq!(reason, SourceAuthorityRevokeReason::CapabilityRevoke);
        }
        other => panic!("expected MarkSourceAuthorityRevoked, got {other:?}"),
    }
}

#[test]
fn watcher_member_state_added_is_noop() {
    let result = classify_source_event(
        "cx:event:03",
        "cx.member.state",
        &serde_json::json!({
            "actor_id": "did:web:agent.example",
            "state": "joined"
        }),
    );
    assert_eq!(result, WatcherIntent::NoOp);
}

// ── AW-3.12: notification renderer classification ───────────────────────

#[test]
fn membership_change_kinds_have_stable_label_keys() {
    let keys = [
        AgentMembershipChangeKind::Add.label_key(),
        AgentMembershipChangeKind::Remove.label_key(),
        AgentMembershipChangeKind::ProfileChange.label_key(),
    ];
    for key in &keys {
        // All keys start with the canonical agent_workspace.notification.* prefix
        assert!(
            key.starts_with("agent_workspace.notification."),
            "{key} missing canonical prefix"
        );
    }
}

// ── §4.8 / §4.3 invariant: gate stays the source of truth ───────────────

#[test]
fn agent_runtime_gate_blocks_when_any_dimension_degraded() {
    // Happy path
    assert!(agent_runtime_may_execute(
        ExecutionState::Active,
        TransparencyState::Ok,
        SourceAuthorityState::Ok
    ));

    // Transparency lost alone blocks
    assert!(!agent_runtime_may_execute(
        ExecutionState::Active,
        TransparencyState::Lost,
        SourceAuthorityState::Ok
    ));

    // Source authority revoked alone blocks
    assert!(!agent_runtime_may_execute(
        ExecutionState::Active,
        TransparencyState::Ok,
        SourceAuthorityState::Revoked
    ));

    // Both degraded together — explicitly blocks
    assert!(!agent_runtime_may_execute(
        ExecutionState::Active,
        TransparencyState::Lost,
        SourceAuthorityState::Revoked
    ));

    // Reconfirmed states are explicit "controller continues anyway" —
    // gate should re-allow execution.
    assert!(agent_runtime_may_execute(
        ExecutionState::Active,
        TransparencyState::ReconfirmedAfterLoss,
        SourceAuthorityState::ReconfirmedAfterRevoke
    ));

    // Terminal execution always blocks regardless of other dimensions.
    assert!(!agent_runtime_may_execute(
        ExecutionState::Completed,
        TransparencyState::Ok,
        SourceAuthorityState::Ok
    ));
    assert!(!agent_runtime_may_execute(
        ExecutionState::CancelledByController,
        TransparencyState::Ok,
        SourceAuthorityState::Ok
    ));
}
