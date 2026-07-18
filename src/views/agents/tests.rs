#[cfg(test)]
mod personal_agent_tests {
    use arkret_sdk::models::AgentParticipation;

    use super::super::*;
    use crate::views::agents::model::{
        build_agent_key_authorize_event_for_pairing, build_agent_pairing_deep_link,
        build_agent_pairing_handoff_token, build_requested_scope_disclosure_for_pairing,
        parse_runtime_key_approval_request, render_agent_pairing_qr_svg,
        runtime_key_pairing_error_message, summarize_runtime_key_approval_request,
    };

    #[test]
    fn pairing_renewal_is_available_before_an_open_request_expires() {
        assert!(super::super::admin::should_offer_pairing_renewal(
            true,
            "pending_runtime_key"
        ));
        assert!(super::super::admin::should_offer_pairing_renewal(
            true,
            "pairing_expired"
        ));
        assert!(!super::super::admin::should_offer_pairing_renewal(
            false,
            "pending_runtime_key"
        ));
        assert!(!super::super::admin::should_offer_pairing_renewal(
            true,
            "deactivated"
        ));
    }

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
    fn agent_grant_preset_names_are_positive_capabilities() {
        assert_eq!(AgentGrantPreset::Read.preset_name(), "read");
        assert_eq!(AgentGrantPreset::Draft.preset_name(), "draft");
        assert_eq!(
            AgentServiceScopePreset::SubscribeEvents.preset_name(),
            "subscribe_events"
        );
    }

    #[test]
    fn requested_scope_is_global_ceiling_without_realm_grants() {
        assert!(requested_scope_for_presets(&[], &[]).is_none());
        assert!(requested_scope_for_presets(&[AgentGrantPreset::Read], &[]).is_none());

        let scope = requested_scope_for_presets(
            &[AgentGrantPreset::Read, AgentGrantPreset::ReplyAsAgent],
            &AgentServiceScopePreset::DEFAULTS,
        )
        .expect("selected presets produce an agent key scope");
        assert_eq!(
            scope.actions,
            vec![
                "ak.event.read",
                "ak.message.create",
                "ak.reaction.add",
                "ak.self.events.stream.subscribe",
                "ak.self.events.query.scan",
                "ak.self.events.command.submit",
            ]
        );
        let wire = serde_json::to_value(&scope).unwrap();
        assert_eq!(
            wire["resources"],
            serde_json::json!([
                {
                    "kind": "operation",
                    "operation": "ak.self.events.stream.subscribe"
                },
                {
                    "kind": "operation",
                    "operation": "ak.self.events.query.scan"
                },
                {
                    "kind": "operation",
                    "operation": "ak.self.events.command.submit"
                }
            ])
        );
        assert!(scope.constraints.is_empty());
    }

    #[test]
    fn content_presets_expand_the_provision_scope() {
        let scope = requested_scope_for_presets(
            &[AgentGrantPreset::Read, AgentGrantPreset::Draft],
            &[AgentServiceScopePreset::SubscribeEvents],
        )
        .expect("service scope is required for runtime reachability");

        assert_eq!(
            scope.actions,
            vec![
                "ak.event.read".to_owned(),
                "ak.agent.draft.propose".to_owned(),
                "ak.agent.action_request".to_owned(),
                "ak.self.events.stream.subscribe".to_owned(),
            ]
        );
    }

    #[test]
    fn requested_scope_can_include_service_surface_without_content_grant() {
        let scope = requested_scope_for_presets(
            &[],
            &[
                AgentServiceScopePreset::ScanCatchUp,
                AgentServiceScopePreset::ResolveResources,
            ],
        )
        .expect("service-only scope is still a valid agent key ceiling");

        assert_eq!(
            scope.actions,
            vec!["ak.self.events.query.scan", "ak.self.events.resource.get"]
        );
    }

    #[test]
    fn act_on_behalf_scope_requires_controller_review_for_message_create() {
        let scope = requested_scope_for_presets(
            &[AgentGrantPreset::ActOnBehalf],
            &[AgentServiceScopePreset::SubmitEvents],
        )
        .expect("act-on-behalf produces an explicit scope");

        let wire = serde_json::to_value(scope).unwrap();
        let constraint = &wire["constraints"][0];
        assert_eq!(constraint["constraint_type"], "claim_based");
        assert_eq!(constraint["effect"], "require_review");
        assert_eq!(constraint["subtype"], "accountability");
        assert_eq!(constraint["applies_to_actions"][0], "ak.message.create");
        assert_eq!(constraint["controller_approval_required"], true);
    }

    #[test]
    fn expand_preset_grant_emits_registered_actions() {
        let grant = expand_preset_grant(
            AgentGrantPreset::ReplyAsAgent,
            "did:web:agents.example:summary",
            Some("ak:realm:01"),
            "2026-06-26T00:00:00Z",
        );
        assert_eq!(
            grant["actions"],
            serde_json::json!(["ak.message.create", "ak.reaction.add"])
        );
        assert_eq!(grant["subject"], "did:web:agents.example:summary");
        assert_eq!(grant["resources"][0]["kind"], "realm");
        assert_eq!(grant["resources"][0]["realm_id"], "ak:realm:01");
        assert_eq!(grant["expires_at"], "2026-06-26T00:00:00Z");
        // Non-aob presets carry no controller-approval constraint.
        assert!(grant.get("constraints").is_none());
    }

    #[test]
    fn expand_preset_grant_act_on_behalf_carries_controller_approval() {
        let grant = expand_preset_grant(
            AgentGrantPreset::ActOnBehalf,
            "did:web:agents.example:summary",
            None,
            "2026-06-26T00:00:00Z",
        );
        // No realm supplied -> empty selector (controller narrows later).
        assert_eq!(grant["resources"], serde_json::json!([]));
        let constraint = &grant["constraints"][0];
        assert_eq!(constraint["constraint_type"], "claim_based");
        assert_eq!(constraint["effect"], "require_review");
        assert_eq!(constraint["subtype"], "accountability");
        assert_eq!(constraint["applies_to_actions"][0], "ak.message.create");
        assert_eq!(constraint["controller_approval_required"], true);
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
    fn bootstrap_serializes_spec_six_fields_without_scope_or_private_key() {
        let outcome = arkret_sdk::AgentProvisionComplete {
            agent_id: arkret_sdk::Did::new("did:web:agents.example:summary").unwrap(),
            principal_control_realm_id: arkret_sdk::RealmId::new(
                "ak:realm:01964137-0000-7000-8000-000000000005",
            )
            .unwrap(),
            controller_authorization_ref: "ak:event:01964137-0000-7000-8000-000000000006"
                .to_owned(),
            requested_scope_digest: arkret_sdk::Hash::new(format!("sha256:{}", "1".repeat(64)))
                .unwrap(),
            pcr_recovery: arkret_sdk::AgentProvisionPcrRecovery::default(),
            pairing_request_id: "0197-req".to_owned(),
            pairing_code: Some("123456".to_owned()),
            expires_at: chrono::DateTime::parse_from_rfc3339("2026-06-26T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        };

        let raw = build_agent_pairing_bootstrap_json(
            "https://arkret.example/",
            "did:web:arkret.example",
            &outcome,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();

        // AKP-0008 §4.4: exactly the six pairing fields, no scope payload. The
        // base-URL field is the SDK/spec wire name `arkret_base_url` (a wire key,
        // deliberately not renamed by the arkret→arkret source rename).
        assert_eq!(value["arkret_base_url"], "https://arkret.example");
        assert_eq!(value["service_id"], "did:web:arkret.example");
        assert_eq!(value["agent_id"], "did:web:agents.example:summary");
        assert_eq!(value["pairing_request_id"], "0197-req");
        assert_eq!(value["pairing_code"], "123456");
        assert_eq!(value["pairing_expires_at"], "2026-06-26T00:00:00Z");
        assert!(value.get("schema").is_none());
        assert!(value.get("requested_scope").is_none());
        assert!(value.get("service_scope").is_none());
        assert!(value.get("content_grant_summary").is_none());
        assert_eq!(value.as_object().unwrap().len(), 6);
        assert!(!raw.contains("private_key"));
    }

    #[test]
    fn deep_link_is_https_universal_link_wrapping_a_short_pairing_token() {
        let outcome = arkret_sdk::AgentProvisionComplete {
            agent_id: arkret_sdk::Did::new("did:web:agents.example:summary").unwrap(),
            principal_control_realm_id: arkret_sdk::RealmId::new(
                "ak:realm:01964137-0000-7000-8000-000000000005",
            )
            .unwrap(),
            controller_authorization_ref: "ak:event:01964137-0000-7000-8000-000000000006"
                .to_owned(),
            requested_scope_digest: arkret_sdk::Hash::new(format!("sha256:{}", "1".repeat(64)))
                .unwrap(),
            pcr_recovery: arkret_sdk::AgentProvisionPcrRecovery::default(),
            pairing_request_id: "0197-req".to_owned(),
            pairing_code: Some("123456".to_owned()),
            expires_at: chrono::DateTime::parse_from_rfc3339("2026-06-26T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        };
        let raw = build_agent_pairing_bootstrap_json(
            "https://arkret.example/",
            "did:web:arkret.example",
            &outcome,
        )
        .unwrap();

        let token = build_agent_pairing_handoff_token("0197-req", "123456");
        let deep_link = build_agent_pairing_deep_link("https://arkret.example/", &token);
        let encoded = deep_link
            .strip_prefix("https://arkret.example/_arkret/open/agent-pairing/resolve#token=")
            .expect("deep link is an https universal link with the token in the fragment");
        let decoded: serde_json::Value =
            serde_json::from_slice(&arkret_sdk::base64url_decode(encoded).unwrap()).unwrap();

        assert_eq!(
            decoded,
            serde_json::json!({ "r": "0197-req", "c": "123456" })
        );
        assert!(deep_link.len() < raw.len());
        assert!(!deep_link.contains("savfox"));
        assert!(!deep_link.contains("agent_id"));
        assert!(!deep_link.contains("private_key"));
    }

    #[test]
    fn pairing_qr_renders_deep_link_svg() {
        let svg = render_agent_pairing_qr_svg(
            "https://arkret.example/_arkret/open/agent-pairing/resolve#token=abc",
        );

        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
    }

    #[test]
    fn runtime_key_request_summary_exposes_sdk_fingerprint() {
        let verification_method = "did:web:agents.example:summary#runtime-key-1";
        let raw = serde_json::json!({
            "pairing_request_id": "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
            "agent_id": "did:web:agents.example:summary",
            "verification_method": verification_method,
            "public_key": {
                "kty": "OKP",
                "kid": verification_method,
                "alg": "Ed25519",
                "key": arkret_sdk::base64url_encode([9u8; 32]),
            },
            "proof_of_possession": {
                "challenge": "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
                "audience": "did:web:arkret.example",
                "request_canonical_digest": format!("sha256:{}", "0".repeat(64)),
                "expires_at": "2026-07-06T00:15:00.000Z",
                "signature": arkret_sdk::base64url_encode([1u8; 64]),
            },
        })
        .to_string();
        let summary = summarize_runtime_key_approval_request(&raw).unwrap();
        let request = parse_runtime_key_approval_request(&raw).unwrap();
        let expected = arkret_sdk::agent_runtime_public_key_digest(&request.public_key).unwrap();

        assert_eq!(summary.public_key_fingerprint, expected.as_str());
        assert_eq!(summary.verification_method, verification_method);
        assert_eq!(summary.proof_expires_at, "2026-07-06T00:15:00.000Z");
    }

    #[test]
    fn runtime_key_pairing_error_message_classifies_known_failures() {
        assert!(
            runtime_key_pairing_error_message("pairing_request_expired")
                .contains("Pairing expired")
        );
        assert!(
            runtime_key_pairing_error_message("runtime request pairing_request_id mismatch")
                .contains("Wrong pairing request or code")
        );
        assert!(
            runtime_key_pairing_error_message("public_key.kid does not match verification_method")
                .contains("Runtime key mismatch")
        );
        assert!(
            runtime_key_pairing_error_message("wrong controller principal")
                .contains("Controller mismatch")
        );
        assert!(
            runtime_key_pairing_error_message("database unavailable").contains("Server rejected")
        );
        assert!(!runtime_key_pairing_error_message("database unavailable").contains("Detail:"));
    }

    #[test]
    fn runtime_key_authorize_event_binds_request_and_scope() {
        struct ActiveSignerGuard(Option<std::sync::Arc<crate::event_signer::InksonEventSigner>>);

        impl Drop for ActiveSignerGuard {
            fn drop(&mut self) {
                let previous = self.0.take();
                let _ = crate::event_signer::replace_active_signer(previous);
            }
        }

        let controller = "did:web:controller.example";
        let service_id = "did:web:arkret.example";
        let agent = "did:web:agents.example:summary";
        let verification_method = "did:web:agents.example:summary#runtime-key-1";
        let signer = std::sync::Arc::new(crate::event_signer::build_ed25519_device_signer(
            [41u8; 32],
            controller,
            "ak:device:01964137-0000-7000-8000-000000000007",
        ));
        let _signer_guard =
            ActiveSignerGuard(crate::event_signer::replace_active_signer(Some(signer)));
        let scope = requested_scope_for_presets(&[], &AgentServiceScopePreset::DEFAULTS).unwrap();
        let key_state = serde_json::json!({
            "agent_id": agent,
            "controller_id": controller,
            "principal_control_realm_id": "ak:realm:01964137-0000-7000-8000-000000000005",
            "controller_authorization_ref": "ak:event:01964137-0000-7000-8000-000000000006",
            "status": "pending_runtime_key",
            "pairing_request_id": "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
            "pairing_code": "12345678",
            "pairing_expires_at": "2026-07-06T00:15:00.000123Z",
            "requested_scope": scope,
        });
        let raw = serde_json::json!({
            "pairing_request_id": "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
            "agent_id": agent,
            "verification_method": verification_method,
            "public_key": {
                "kty": "OKP",
                "kid": verification_method,
                "alg": "Ed25519",
                "key": arkret_sdk::base64url_encode([9u8; 32]),
            },
            "proof_of_possession": {
                "challenge": "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
                "audience": service_id,
                "request_canonical_digest": format!("sha256:{}", "0".repeat(64)),
                "expires_at": "2026-07-06T00:15:00.000Z",
                "signature": arkret_sdk::base64url_encode([1u8; 64]),
            },
        })
        .to_string();
        let request = parse_runtime_key_approval_request(&raw).unwrap();

        let disclosure = build_requested_scope_disclosure_for_pairing(
            controller, service_id, &key_state, &request,
        )
        .unwrap();

        let event = build_agent_key_authorize_event_for_pairing(
            controller, service_id, &key_state, &request,
        )
        .unwrap();

        assert_eq!(disclosure.agent_id.as_str(), agent);
        assert_eq!(disclosure.controller_id.as_str(), controller);
        assert_eq!(
            disclosure.requested_scope,
            serde_json::from_value(key_state["requested_scope"].clone()).unwrap()
        );

        let runtime_digest =
            arkret_sdk::agent_runtime_public_key_digest(&request.public_key).unwrap();
        let expected_pairing_digest = arkret_sdk::agent_key_pairing_request_binding_digest(
            &arkret_sdk::Did::new(controller.to_owned()).unwrap(),
            &request.agent_id,
            verification_method,
            &runtime_digest,
            &request.pairing_request_id,
            "12345678",
            "2026-07-06T00:15:00.000Z",
            service_id,
        )
        .unwrap();

        assert_eq!(
            event.kind.as_str(),
            arkret_sdk::events::EventKind::AGENT_KEY_AUTHORIZE
        );
        assert_eq!(event.payload["agent_id"], agent);
        assert_eq!(event.payload["verification_method"], verification_method);
        assert_eq!(event.payload["public_key_digest"], runtime_digest.as_str());
        let event_wire = serde_json::to_value(&event).unwrap();
        let event_created_at = event_wire["created_at"].as_str().unwrap();
        assert_eq!(event_created_at.len(), 24);
        arkret_sdk::canonical::validate_timestamp_millis_canonical(event_created_at).unwrap();
        event.payload["issued_at"]
            .as_str()
            .unwrap()
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap();
        // Longevity-safe default: the authorize payload declares no
        // expires_at; the authorization is revocation-governed
        // (key-management.md §3.6.1).
        assert!(event.payload.get("expires_at").is_none());
        assert_eq!(
            event.payload["approval_evidence"]["request_canonical_digest"],
            expected_pairing_digest.as_str()
        );
        assert_eq!(
            event.payload["approval_evidence"]["pairing_request_id"],
            request.pairing_request_id.as_str()
        );
        assert_eq!(
            event.payload["approval_evidence"]["kind"],
            "pairing_request"
        );
        assert!(
            event.payload["approval_evidence"]
                .get("evidence_ref")
                .is_none()
        );
    }

    #[test]
    fn build_action_approve_payload_binds_draft_digest_and_nonce() {
        let draft = serde_json::json!({
            "type": "ak.agent.draft.v1",
            "draft_id": "0197-draft",
            "agent_id": "did:web:agents.example:summary",
            "proposed_action": "ak.message.create",
            "target": {"kind": "realm", "realm_id": "ak:realm:01"},
            "content": {"body": "draft text"},
        });
        let payload = build_action_approve_payload(
            &draft,
            "did:web:alice.example",
            "2026-06-26T00:00:00Z",
            "2026-06-26T01:00:00Z",
        );
        assert_eq!(payload["draft_id"], "0197-draft");
        assert_eq!(payload["controller_id"], "did:web:alice.example");
        assert_eq!(payload["proposed_action"], "ak.message.create");
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
            "request_id": "ak:agent-action-request:0197",
            "agent_id": "did:web:agents.example:summary",
            "proposed_action": "ak.message.create",
            "target": {"kind": "realm", "realm_id": "ak:realm:01"},
            "request_canonical_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        });
        let payload = build_action_approve_payload(
            &request,
            "did:web:alice.example",
            "2026-06-26T00:00:00Z",
            "2026-06-26T01:00:00Z",
        );
        assert_eq!(payload["request_id"], "ak:agent-action-request:0197");
        assert_eq!(
            payload["approved_payload_digest"],
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert!(payload.get("draft_content_digest").is_none());
    }

    #[test]
    fn build_action_reject_payload_carries_reason_and_controller() {
        let request = serde_json::json!({
            "request_id": "ak:agent-action-request:0198",
            "agent_id": "did:web:agents.example:summary",
        });
        let payload = build_action_reject_payload(
            &request,
            "did:web:alice.example",
            "2026-06-26T00:00:00Z",
            Some("needs review"),
        );
        assert_eq!(payload["request_id"], "ak:agent-action-request:0198");
        assert_eq!(payload["controller_id"], "did:web:alice.example");
        assert_eq!(payload["rejected_at"], "2026-06-26T00:00:00Z");
        assert_eq!(payload["reason"], "needs review");
        assert!(!payload["rejection_id"].as_str().unwrap().is_empty());
    }

    #[test]
    fn act_on_behalf_message_operation_carries_dual_identity_and_approval() {
        let operation = build_act_on_behalf_message_operation(
            "ak:realm:01904100-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "did:web:agents.example:summary",
            "ak:grant:01904100-0000-7000-8000-000000000002",
            "ak:agent-action-request:01904100-0000-7000-8000-000000000003",
            "nonce-01904100",
            "ak:strand:01904100-0000-7000-8000-000000000004",
            "approved message",
        )
        .unwrap();

        assert_eq!(operation.kind.as_str(), "ak.message.create");
        assert_eq!(operation.actor_id.as_str(), "did:web:alice.example");
        assert_eq!(
            operation.executed_by.as_ref().map(|did| did.as_str()),
            Some("did:web:agents.example:summary")
        );
        assert_eq!(
            operation.authorization_ref.as_deref(),
            Some("ak:grant:01904100-0000-7000-8000-000000000002")
        );
        assert_eq!(
            operation.payload["approval_request_id"],
            "ak:agent-action-request:01904100-0000-7000-8000-000000000003"
        );
        assert_eq!(operation.payload["approval_nonce"], "nonce-01904100");
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
