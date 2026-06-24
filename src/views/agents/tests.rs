#[cfg(test)]
mod personal_agent_tests {
    use cokret_sdk::models::{AgentKeyScope, AgentParticipation};

    use super::super::*;

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
    fn agent_state_badges_cover_management_lifecycle() {
        assert_eq!(agent_state_label("pending_runtime_key"), "Pending");
        assert_eq!(agent_state_label("active"), "Active");
        assert_eq!(agent_state_label("paused"), "Paused");
        assert_eq!(agent_state_label("deactivated"), "Deactivated");
        assert_eq!(
            agent_state_badge_class("pending_runtime_key"),
            "badge amber"
        );
        assert_eq!(agent_state_badge_class("active"), "badge green");
        assert_eq!(agent_state_badge_class("paused"), "badge amber");
        assert_eq!(agent_state_badge_class("deactivated"), "badge red");
    }

    #[test]
    fn participation_ceiling_reason_names_capped_selected_bits() {
        let selection = AgentParticipation {
            reply: true,
            accept_third_party_mention: true,
            act_on_behalf: true,
        };
        let ceiling = AgentParticipation {
            reply: true,
            accept_third_party_mention: false,
            act_on_behalf: false,
        };
        let reason = participation_ceiling_reason(selection, ceiling);
        assert!(reason.contains("third-party mentions capped"));
        assert!(reason.contains("act-on-behalf capped"));
        assert!(!reason.contains("reply capped"));
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
    fn pairing_request_expiry_parses_rfc3339_offsets() {
        assert!(is_pairing_request_expired(
            "2026-06-26T00:00:00+00:00",
            "2026-06-26T00:00:01Z"
        ));
        assert!(!is_pairing_request_expired(
            "2026-06-26T00:00:00+00:00",
            "2026-06-26T00:00:00Z"
        ));
        assert!(!is_pairing_request_expired(
            "not-a-timestamp",
            "2026-06-26T00:00:01Z"
        ));
    }

    #[test]
    fn build_action_approve_payload_binds_draft_digest_and_nonce() {
        let draft = serde_json::json!({
            "type": "ck.agent.draft.v1",
            "draft_id": "0197-draft",
            "agent_principal_id": "did:web:agents.example:summary",
            "proposed_action": "ck.message.create",
            "target": {"kind": "realm", "realm_id": "ck:realm:01"},
            "content": {"body": "draft text"},
        });
        let payload = build_action_approve_payload(
            &draft,
            "did:web:alice.example",
            "2026-06-26T00:00:00Z",
            "2026-06-26T01:00:00Z",
        );
        assert_eq!(payload["draft_id"], "0197-draft");
        assert_eq!(payload["controller_principal_id"], "did:web:alice.example");
        assert_eq!(payload["proposed_action"], "ck.message.create");
        assert_eq!(payload["approved_at"], "2026-06-26T00:00:00Z");
        assert_eq!(payload["expires_at"], "2026-06-26T01:00:00Z");
        let digest = payload["draft_content_digest"].as_str().unwrap();
        assert!(digest.starts_with("sha256:"));
        // Approving as-is means both digests match.
        assert_eq!(
            payload["draft_content_digest"],
            payload["approved_payload_digest"]
        );
        // Nonce is a fresh uuid, not empty.
        assert!(!payload["approval_nonce"].as_str().unwrap().is_empty());
        assert!(!payload["approval_id"].as_str().unwrap().is_empty());
    }

    #[test]
    fn build_action_approve_payload_prefers_action_request_digest() {
        let request = serde_json::json!({
            "request_id": "ck:agent-action-request:0197",
            "agent_principal_id": "did:web:agents.example:summary",
            "proposed_action": "ck.message.create",
            "target": {"kind": "realm", "realm_id": "ck:realm:01"},
            "request_canonical_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        });
        let payload = build_action_approve_payload(
            &request,
            "did:web:alice.example",
            "2026-06-26T00:00:00Z",
            "2026-06-26T01:00:00Z",
        );
        assert_eq!(payload["request_id"], "ck:agent-action-request:0197");
        assert_eq!(
            payload["approved_payload_digest"],
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert!(payload.get("draft_content_digest").is_none());
    }

    #[test]
    fn build_action_reject_payload_carries_reason_and_controller() {
        let request = serde_json::json!({
            "request_id": "ck:agent-action-request:0198",
            "agent_principal_id": "did:web:agents.example:summary",
        });
        let payload = build_action_reject_payload(
            &request,
            "did:web:alice.example",
            "2026-06-26T00:00:00Z",
            Some("needs review"),
        );
        assert_eq!(payload["request_id"], "ck:agent-action-request:0198");
        assert_eq!(payload["controller_principal_id"], "did:web:alice.example");
        assert_eq!(payload["rejected_at"], "2026-06-26T00:00:00Z");
        assert_eq!(payload["reason"], "needs review");
        assert!(!payload["rejection_id"].as_str().unwrap().is_empty());
    }

    #[test]
    fn act_on_behalf_message_operation_carries_dual_identity_and_approval() {
        let operation = build_act_on_behalf_message_operation(
            "ck:realm:01904100-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "did:web:agents.example:summary",
            "ck:grant:01904100-0000-7000-8000-000000000002",
            "ck:agent-action-request:01904100-0000-7000-8000-000000000003",
            "nonce-01904100",
            "ck:strand:01904100-0000-7000-8000-000000000004",
            "approved message",
        )
        .unwrap();

        assert_eq!(operation.kind.as_str(), "ck.message.create");
        assert_eq!(operation.actor_id.as_str(), "did:web:alice.example");
        assert_eq!(
            operation.executed_by.as_ref().map(|did| did.as_str()),
            Some("did:web:agents.example:summary")
        );
        assert_eq!(
            operation.authorization_ref.as_deref(),
            Some("ck:grant:01904100-0000-7000-8000-000000000002")
        );
        assert_eq!(
            operation.content["approval_request_id"],
            "ck:agent-action-request:01904100-0000-7000-8000-000000000003"
        );
        assert_eq!(operation.content["approval_nonce"], "nonce-01904100");
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
        assert_eq!(op.content["agent_id"], "did:web:agent.example");
        assert_eq!(op.content["endpoints"][0]["protocol"], "ck.agent.v1");
        assert_eq!(op.content["endpoints"][0]["capabilities"][0], "strand.read");
        assert!(op.content.get("protocol").is_none());
        assert!(op.content.get("capabilities").is_none());
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
        assert_eq!(op.content["audit_binding"]["merkle_root"], "sha256:abc");
    }

    // Pin the verify helper's outcomes for each canonical wire
    // shape the panel can encounter.

    use serde_json::{Value, json};

    use super::super::model::{AuditVerifyStatus, verify_agent_audit_binding};

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

    use super::super::{AuditChainVerifyOutcome, HandoffState, verify_audit_chain};

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

    // ── G3.Y4 — Phase B/C/D model helpers ─────────────────────────

    use super::super::{InteropApprovalState, LiveSessionRow, PublishModalState, live_session_rows};

    #[test]
    fn interop_approval_confirm_gated_on_human_acknowledgement() {
        assert!(!InteropApprovalState::Drafting.can_confirm());
        assert!(InteropApprovalState::Acknowledged.can_confirm());
        assert!(!InteropApprovalState::Submitting.can_confirm());
        assert!(!InteropApprovalState::Granted.can_confirm());
        assert!(!InteropApprovalState::Closed.is_open());
        assert!(InteropApprovalState::Drafting.is_open());
        let states = [
            InteropApprovalState::Closed.as_data_state(),
            InteropApprovalState::Drafting.as_data_state(),
            InteropApprovalState::Acknowledged.as_data_state(),
            InteropApprovalState::Submitting.as_data_state(),
            InteropApprovalState::Granted.as_data_state(),
            InteropApprovalState::Failed.as_data_state(),
        ];
        let uniq: std::collections::BTreeSet<_> = states.iter().collect();
        assert_eq!(uniq.len(), states.len());
    }

    #[test]
    fn publish_modal_open_state_round_trips() {
        assert!(!PublishModalState::Closed.is_open());
        assert!(PublishModalState::Reviewing.is_open());
        let states = [
            PublishModalState::Closed.as_data_state(),
            PublishModalState::Reviewing.as_data_state(),
            PublishModalState::Submitting.as_data_state(),
            PublishModalState::Published.as_data_state(),
            PublishModalState::Failed.as_data_state(),
        ];
        let uniq: std::collections::BTreeSet<_> = states.iter().collect();
        assert_eq!(uniq.len(), states.len());
    }

    #[test]
    fn live_session_rows_fold_latest_status_in_order() {
        let session = "ck:agent_interop_session:0197-aaa";
        let events = vec![
            json!({
                "event_kind": "ck.agent.interop_session.start",
                "payload": {"session_id": session},
            }),
            json!({
                "event_kind": "ck.agent.interop_session.status",
                "payload": {"session_id": session, "status": "negotiating"},
            }),
            json!({
                "event_kind": "ck.agent.interop_session.status",
                "payload": {"session_id": session, "status": "accepted"},
            }),
            json!({
                "event_kind": "ck.agent.interop_session.status",
                "payload": {"session_id": session, "status": "working"},
            }),
        ];
        let rows = live_session_rows(&events);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0],
            LiveSessionRow {
                session_id: session.to_owned(),
                status: "working".to_owned(),
                status_count: 3,
            }
        );
    }

    #[test]
    fn live_session_rows_seed_start_as_negotiating_and_ignore_other_kinds() {
        let session = "ck:agent_interop_session:0197-bbb";
        let events = vec![
            json!({"event_kind": "ck.message.create", "payload": {"body": "x"}}),
            json!({
                "event_kind": "ck.agent.interop_session.start",
                "payload": {"session_id": session},
            }),
        ];
        let rows = live_session_rows(&events);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "negotiating");
        assert_eq!(rows[0].status_count, 0);
    }

    #[test]
    fn live_session_rows_result_does_not_overwrite_streaming_status() {
        // The terminal result lives in the results panel; the session row
        // keeps the latest STREAMING status so a later completed result
        // does not collapse a `working` transcript.
        let session = "ck:agent_interop_session:0197-ccc";
        let events = vec![
            json!({
                "event_kind": "ck.agent.interop_session.start",
                "payload": {"session_id": session},
            }),
            json!({
                "event_kind": "ck.agent.interop_session.status",
                "payload": {"session_id": session, "status": "working"},
            }),
            json!({
                "event_kind": "ck.agent.interop_session.result",
                "payload": {"session_id": session, "status": "completed"},
            }),
        ];
        let rows = live_session_rows(&events);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "working");
        assert_eq!(rows[0].status_count, 1);
    }

    #[test]
    fn interop_capability_constraint_pins_single_endpoint_and_action_intent() {
        let constraint = crate::operation::ck_ops::interop_capability_constraint(
            "https://runtime.example/v1/a2a/tasks",
            &["a2a"],
            true,
            3600,
            10_485_760,
            "metadata_only",
            "summary_and_artifacts",
        );
        assert_eq!(
            constraint["allowed_endpoints"],
            json!(["https://runtime.example/v1/a2a/tasks"])
        );
        assert_eq!(constraint["allowed_protocols"], json!(["a2a"]));
        assert_eq!(constraint["requires_human_approval"], true);
        assert_eq!(constraint["egress_policy"], "metadata_only");
    }

    #[test]
    fn agent_publish_attribution_strand_preserves_agent_attribution() {
        let op = crate::operation::ck_ops::agent_publish_attribution_strand(
            "ck:realm:01904100-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "ck:strand:01904100-0000-7000-8000-000000000004",
            "Agent synthesis result",
            "did:web:remote-agent.example",
            "ck:strand:01904100-0000-7000-8000-00000000aaaa",
            "ck:morph:01904100-0000-7000-8000-00000000bbbb",
        )
        .unwrap()
        .build("yougen");
        // actor_id is the controller; attribution preserves the agent.
        assert_eq!(op.actor_id.as_str(), "did:web:alice.example");
        assert_eq!(
            op.content["object"]["attribution"],
            "did:web:remote-agent.example"
        );
        assert_eq!(
            op.content["object"]["metadata"]["fields"]["workflow_type"],
            "synthesis"
        );
        assert!(
            op.content["object"]["tracks"]
                .get("synthesis")
                .is_some()
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
