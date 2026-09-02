#[cfg(test)]
mod agent_tests {

    use super::super::*;
    use crate::views::agents::model::{
        build_agent_pairing_deep_link, build_agent_pairing_handoff_token,
        build_requested_scope_disclosure_for_pairing, finish_agent_key_authorization_for_pairing,
        parse_runtime_key_approval_request, prepare_agent_key_authorize_pairing,
        render_agent_pairing_qr_svg, runtime_key_pairing_error_message,
        summarize_runtime_key_approval_request,
    };

    fn agent_initial_resolution(did: &arkret_sdk::Did) -> arkret_sdk::ResolutionCommitment {
        arkret_sdk::ResolutionCommitment {
            did: did.clone(),
            method_history_head: format!("sha256:{}", "8".repeat(64)),
            version_id: "1-Qmfixture".to_owned(),
        }
    }

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
        // Bootstrap renewal is offered only for the never-keyed runtime states;
        // ready/replacing (keyed) are not bootstrap-renewable.
        assert!(!super::super::admin::should_offer_pairing_renewal(
            true, "ready"
        ));
        assert!(!super::super::admin::should_offer_pairing_renewal(
            true,
            "replacing"
        ));
    }

    #[test]
    fn pairing_credentials_require_bootstrap_or_explicit_replacement_state() {
        use super::super::admin::should_show_pairing_card;

        assert!(should_show_pairing_card(
            "pending_runtime_key",
            true,
            false,
            false
        ));
        assert!(should_show_pairing_card(
            "pairing_expired",
            true,
            true,
            false
        ));
        assert!(!should_show_pairing_card("ready", true, false, true));
        assert!(!should_show_pairing_card("replacing", true, false, false));
        assert!(should_show_pairing_card("replacing", true, false, true));
    }

    #[test]
    fn actor_kind_label_maps_canonical_variants() {
        assert_eq!(actor_kind_label(Some("user")), Some("User"));
        assert_eq!(actor_kind_label(Some("organization")), Some("Organization"));
        assert_eq!(actor_kind_label(Some("team")), Some("Team"));
        assert_eq!(actor_kind_label(Some("bot")), Some("Bot"));
        assert_eq!(actor_kind_label(Some("service")), Some("Service"));
        assert_eq!(actor_kind_label(Some("agent")), Some("Agent"));
        assert_eq!(actor_kind_label(Some("integration")), Some("Integration"));
    }

    #[test]
    fn actor_kind_label_falls_back_for_unknown_or_missing() {
        assert_eq!(actor_kind_label(None), None);
        assert_eq!(actor_kind_label(Some("")), None);
        assert_eq!(actor_kind_label(Some("future_kind")), None);
    }

    #[test]
    fn actor_kind_badge_class_distinguishes_bot_and_user() {
        assert_eq!(actor_kind_badge_class(Some("user")), "badge");
        assert_ne!(
            actor_kind_badge_class(Some("bot")),
            actor_kind_badge_class(Some("user"))
        );
        assert_ne!(
            actor_kind_badge_class(Some("agent")),
            actor_kind_badge_class(Some("service"))
        );
    }

    #[test]
    fn agent_state_badges_cover_management_lifecycle() {
        assert_eq!(agent_state_label("pending_runtime_key"), "Awaiting runtime");
        assert_eq!(
            agent_state_label("replacing"),
            "Awaiting replacement runtime"
        );
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
    fn action_request_expired_only_when_now_strictly_after_expires_at() {
        assert!(is_action_request_expired(
            "2026-05-26T00:00:00.000Z",
            "2026-05-27T00:00:00.000Z"
        ));
        assert!(!is_action_request_expired(
            "2026-05-27T00:00:00.000Z",
            "2026-05-26T00:00:00.000Z"
        ));
        assert!(!is_action_request_expired("", "2026-05-26T00:00:00.000Z"));
        assert!(!is_action_request_expired("2026-05-26T00:00:00.000Z", ""));
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
                "ak.self.events.command.submit.v1",
                "ak.self.events.read.frontier.v1",
                "ak.self.events.read.scan.v1",
                "ak.self.events.stream.subscribe.v1",
                "ak.self.keys.keypackages.upload.create.v1",
                "ak.self.seals.read.frontier.v1",
                "ak.self.authorization_leases.command.issue.v1",
                "ak.self.keys.keypackages.command.consume.v1",
                "ak.self.keys.keypackages.command.revoke.v1",
                "ak.self.device_messages.read.list.v1",
                "ak.self.device_messages.command.ack.v1",
                "ak.self.signal.command.send.v1",
            ]
        );
        let wire = serde_json::to_value(&scope).unwrap();
        assert_eq!(
            wire["resources"],
            serde_json::json!([
                {
                    "kind": "operation",
                    "operation": "ak.self.events.command.submit.v1"
                },
                {
                    "kind": "operation",
                    "operation": "ak.self.events.read.frontier.v1"
                },
                {
                    "kind": "operation",
                    "operation": "ak.self.events.read.scan.v1"
                },
                {
                    "kind": "operation",
                    "operation": "ak.self.events.stream.subscribe.v1"
                },
                {
                    "kind": "operation",
                    "operation": "ak.self.keys.keypackages.upload.create.v1"
                },
                {
                    "kind": "operation",
                    "operation": "ak.self.seals.read.frontier.v1"
                },
                {
                    "kind": "operation",
                    "operation": "ak.self.authorization_leases.command.issue.v1"
                },
                {
                    "kind": "operation",
                    "operation": "ak.self.keys.keypackages.command.consume.v1"
                },
                {
                    "kind": "operation",
                    "operation": "ak.self.keys.keypackages.command.revoke.v1"
                },
                {
                    "kind": "operation",
                    "operation": "ak.self.device_messages.read.list.v1"
                },
                {
                    "kind": "operation",
                    "operation": "ak.self.device_messages.command.ack.v1"
                },
                {
                    "kind": "operation",
                    "operation": "ak.self.signal.command.send.v1"
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
                "ak.self.events.command.submit.v1".to_owned(),
                "ak.self.events.read.frontier.v1".to_owned(),
                "ak.self.events.read.scan.v1".to_owned(),
                "ak.self.events.stream.subscribe.v1".to_owned(),
                "ak.self.seals.read.frontier.v1".to_owned(),
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
            vec![
                "ak.self.events.command.submit.v1",
                "ak.self.events.read.frontier.v1",
                "ak.self.events.read.scan.v1",
                "ak.self.events.stream.subscribe.v1",
                "ak.self.seals.read.frontier.v1",
                "ak.self.events.resource.get.v1",
            ]
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
        assert_eq!(constraint["constraint_kind"], "claim_based");
        assert_eq!(constraint["effect"], "require_review");
        assert_eq!(constraint["constraint_subkind"], "accountability");
        assert_eq!(constraint["applies_to_actions"][0], "ak.message.create");
        assert_eq!(constraint["controller_approval_required"], true);
    }

    #[test]
    fn pairing_request_expiry_parses_rfc3339_offsets() {
        assert!(is_pairing_request_expired(
            "2026-06-26T00:00:00+00:00",
            "2026-06-26T00:00:01.000Z"
        ));
        assert!(!is_pairing_request_expired(
            "2026-06-26T00:00:00+00:00",
            "2026-06-26T00:00:00.000Z"
        ));
        assert!(!is_pairing_request_expired(
            "not-a-timestamp",
            "2026-06-26T00:00:01.000Z"
        ));
    }

    #[test]
    fn bootstrap_serializes_spec_six_fields_without_scope_or_private_key() {
        let outcome = arkret_sdk::AgentProvisionComplete {
            agent_id: crate::mls_api_helpers::principal_core_id("did:web:agents.example:summary")
                .unwrap(),
            did: arkret_sdk::Did::new("did:web:agents.example:summary").unwrap(),
            initial_resolution: agent_initial_resolution(
                &arkret_sdk::Did::new("did:web:agents.example:summary").unwrap(),
            ),
            principal_control_realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc",
            )
            .unwrap(),
            controller_authorization_ref: arkret_sdk::DidUrl::new(
                "did:web:controller.example#controller-authorization",
            )
            .unwrap(),
            requested_scope_digest: arkret_sdk::Hash::new(format!("sha256:{}", "1".repeat(64)))
                .unwrap(),
            pairing_request_id: arkret_sdk::OpaqueLocalId::new("0197-req").unwrap(),
            pairing_code: Some("123456".to_owned()),
            expires_at: chrono::DateTime::parse_from_rfc3339("2026-06-26T00:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        };

        let raw = build_agent_pairing_bootstrap_json(
            "https://arkret.example/",
            "ak:did_core:web:arkret.example",
            &outcome,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();

        // §4.4: exactly the six pairing fields, no scope payload. The
        // Base URI field is the SDK/spec wire name `arkret_base_url`.
        assert_eq!(value["arkret_base_url"], "https://arkret.example");
        assert_eq!(value["service_id"], "ak:did_core:web:arkret.example");
        assert_eq!(value["agent_id"], "ak:did_core:web:agents.example:summary");
        assert_eq!(value["pairing_request_id"], "0197-req");
        assert_eq!(value["pairing_code"], "123456");
        assert_eq!(value["pairing_expires_at"], "2026-06-26T00:00:00.000Z");
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
            agent_id: crate::mls_api_helpers::principal_core_id("did:web:agents.example:summary")
                .unwrap(),
            did: arkret_sdk::Did::new("did:web:agents.example:summary").unwrap(),
            initial_resolution: agent_initial_resolution(
                &arkret_sdk::Did::new("did:web:agents.example:summary").unwrap(),
            ),
            principal_control_realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc",
            )
            .unwrap(),
            controller_authorization_ref: arkret_sdk::DidUrl::new(
                "did:web:controller.example#controller-authorization",
            )
            .unwrap(),
            requested_scope_digest: arkret_sdk::Hash::new(format!("sha256:{}", "1".repeat(64)))
                .unwrap(),
            pairing_request_id: arkret_sdk::OpaqueLocalId::new("0197-req").unwrap(),
            pairing_code: Some("123456".to_owned()),
            expires_at: chrono::DateTime::parse_from_rfc3339("2026-06-26T00:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        };
        let raw = build_agent_pairing_bootstrap_json(
            "https://arkret.example/",
            "ak:did_core:web:arkret.example",
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
        let verification_method =
            "did:web:agents.example:summary#ak:device:01964137-0000-7000-8000-000000000008";
        let raw = serde_json::json!({
            "pairing_request_id": "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
            "agent_id": "ak:did_core:web:agents.example:summary",
            "verification_method": verification_method,
            "public_key": {
                "kty": "OKP",
                "kid": verification_method,
                "algorithm": "Ed25519",
                "key": arkret_sdk::base64url_encode([9u8; 32]),
            },
            "proof_of_possession": {
                "kind": "agent_runtime_key_possession",
                "verification_method": verification_method,
                "signature_algorithm": "Ed25519",
                "challenge": "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
                "audience_id": "ak:did_core:web:arkret.example",
                "created_at": "2026-07-06T00:10:00.000Z",
                "expires_at": "2026-07-06T00:15:00.000Z",
                "runtime_key_binding_digest": format!("sha256:{}", "0".repeat(64)),
                "transcript_digest": format!("sha256:{}", "1".repeat(64)),
                "signature": arkret_sdk::base64url_encode([1u8; 64]),
            },
        })
        .to_string();
        let summary = summarize_runtime_key_approval_request(&raw).unwrap();
        let request = parse_runtime_key_approval_request(&raw).unwrap();
        let expected =
            arkret_signatures::agent::agent_runtime_public_key_digest(&request.public_key).unwrap();

        assert_eq!(summary.public_key_fingerprint, expected);
        assert_eq!(summary.verification_method.as_str(), verification_method);
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
        let controller = "did:web:controller.example";
        let service_did = "did:web:arkret.example";
        let service_id = "ak:did_core:web:arkret.example";
        let agent = "did:web:agents.example:summary";
        let verification_method =
            "did:web:agents.example:summary#ak:device:01964137-0000-7000-8000-000000000008";
        let signer = std::sync::Arc::new(crate::event_signer::build_ed25519_device_signer(
            [41u8; 32],
            controller,
            "ak:device:01964137-0000-7000-8000-000000000007",
        ));
        let _signer_guard = crate::event_signer::ActiveSignerTestGuard::replace(Some(signer));
        let scope = requested_scope_for_presets(&[], &AgentServiceScopePreset::DEFAULTS).unwrap();
        let agent_did = arkret_sdk::Did::new(agent.to_owned()).unwrap();
        let controller_did = arkret_sdk::Did::new(controller.to_owned()).unwrap();
        let agent_actor_id = arkret_sdk::project_did_to_core_id(&agent_did).unwrap();
        let controller_actor_id = arkret_sdk::project_did_to_core_id(&controller_did).unwrap();
        let created_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            crate::clock::now_utc().timestamp_millis(),
        )
        .unwrap();
        let expires_at = created_at + chrono::Duration::minutes(5);
        let key_state: arkret_sdk::KeyState = serde_json::from_value(serde_json::json!({
            "agent_id": agent_actor_id,
            "controller_id": controller_actor_id,
            "principal_control_realm_id": "ak:realm:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc",
            "controller_authorization_ref": "did:web:controller.example#controller-authorization",
            "pairing_request_id": "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
            "pairing_code": "12345678",
            "pairing_expires_at": expires_at,
            "requested_scope": scope,
        }))
        .unwrap();
        let pairing_request_id = arkret_wire::OpaqueLocalId::new(
            "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
        )
        .unwrap();
        let agent_id = crate::mls_api_helpers::principal_core_id(agent).unwrap();
        let verification_method = arkret_wire::DidUrl::new(verification_method).unwrap();
        let public_key = arkret_models_collaboration::governance::agent_artifacts::PublicKey {
            kty: arkret_wire::NonEmptyString::new("OKP").unwrap(),
            kid: arkret_wire::NonEmptyString::new(verification_method.as_str()).unwrap(),
            algorithm: arkret_wire::NonEmptyString::new("Ed25519").unwrap(),
            key: arkret_wire::Base64UrlString::new(arkret_sdk::base64url_encode([9u8; 32]))
                .unwrap(),
            key_digest: None,
        };
        let runtime_key_binding_digest =
            arkret_models_collaboration::agent_operations::agent_runtime_key_binding_digest(
                &agent_id,
                &pairing_request_id,
                &verification_method,
                &public_key,
                None,
            )
            .unwrap();
        let request =
            arkret_models_collaboration::agent_operations::AgentRuntimeApprovalControllerProjection {
                pairing_request_id: pairing_request_id.clone(),
                agent_id,
                verification_method: verification_method.clone(),
                public_key,
                proof_of_possession:
                    arkret_models_collaboration::agent_operations::AgentRuntimeKeyPossessionProof {
                        kind: arkret_models_collaboration::agent_operations::AgentRuntimeKeyPossessionProofKind::AgentRuntimeKeyPossession,
                        verification_method: verification_method.clone(),
                        signature_algorithm: arkret_models_collaboration::agent_operations::AgentRuntimeKeyAlgorithm::Ed25519,
                        challenge: pairing_request_id,
                        audience_id: arkret_sdk::DidCoreId::new(service_id.to_owned()).unwrap(),
                        created_at,
                        expires_at,
                        runtime_key_binding_digest,
                        transcript_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                        signature: arkret_wire::Base64UrlString::new(
                            arkret_sdk::base64url_encode([1u8; 64]),
                        )
                        .unwrap(),
                    },
                runtime_attestation: None,
            };

        let disclosure = build_requested_scope_disclosure_for_pairing(
            controller,
            service_did,
            &key_state,
            &request,
        )
        .unwrap();

        // The controller's binding commits to the authorize Event's final id, so
        // the write is authored between the two halves of the builder.
        let plan =
            prepare_agent_key_authorize_pairing(controller, service_id, &key_state, &request)
                .unwrap();
        let authored = crate::operation::author_intent_for_test(plan.intent().clone());
        let authorization = finish_agent_key_authorization_for_pairing(plan, authored).unwrap();
        let event = authorization.authorize_event;
        let signing_key_binding = authorization.signing_key_binding;

        assert_eq!(disclosure.agent_id, agent_actor_id);
        assert_eq!(disclosure.controller_id, controller_actor_id);
        assert_eq!(disclosure.requested_scope, key_state.requested_scope);

        let expected_pairing_digest =
            arkret_models_collaboration::agent_operations::agent_key_pairing_request_binding_digest(
                arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1,
                &controller_actor_id,
                &request.agent_id,
                &request.pairing_request_id,
                "12345678",
                expires_at,
                &arkret_sdk::DidCoreId::new(service_id.to_owned()).unwrap(),
                &request.proof_of_possession.runtime_key_binding_digest,
                &request.proof_of_possession,
            )
            .unwrap();

        assert_eq!(
            event.kind.as_str(),
            arkret_sdk::EventKind::AgentKeyAuthorize.as_str()
        );
        assert_eq!(event.payload["agent_id"], agent_actor_id.as_str());
        assert_eq!(
            event.payload["verification_method"],
            verification_method.as_str()
        );
        let authorize_public_key_digest =
            arkret_signatures::agent_evidence::agent_signing_public_key_digest(
                &signing_key_binding.public_key,
            )
            .unwrap();
        let runtime_request_public_key_digest =
            arkret_signatures::agent_evidence::agent_signing_public_key_runtime_request_digest(
                &request.verification_method,
                &signing_key_binding.public_key,
            )
            .unwrap();
        assert_ne!(
            authorize_public_key_digest, runtime_request_public_key_digest,
            "the public authorization and private runtime-request digest domains must stay distinct"
        );
        assert_eq!(
            event.payload["public_key_digest"],
            authorize_public_key_digest.as_str()
        );
        let binding_digest = arkret_signatures::agent_evidence::agent_signing_key_binding_digest(
            &signing_key_binding,
        )
        .unwrap();
        assert_eq!(
            event.payload["signing_key_binding_digest"],
            binding_digest.as_str()
        );
        arkret_signatures::agent_evidence::verify_agent_signing_key_binding(
            &signing_key_binding,
            &request.agent_id,
            &signing_key_binding.agent_key_id,
            &signing_key_binding.controller_id,
            &request.verification_method,
            &event.event_id,
            &authorize_public_key_digest,
            &binding_digest,
            &arkret_sdk::signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: ed25519_dalek::SigningKey::from_bytes(&[41u8; 32])
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            },
        )
        .unwrap();
        let event_wire = serde_json::to_value(event.event()).unwrap();
        let event_created_at = event_wire["created_at"].as_str().unwrap();
        assert_eq!(event_created_at.len(), 24);
        arkret_sdk::canonical::validate_timestamp_canonical(event_created_at).unwrap();
        event.payload["issued_at"]
            .as_str()
            .unwrap()
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap();
        // Longevity-safe default: the authorize payload declares no
        // expires_at; the authorization is revocation-governed
        // (key-management.md §3.6.1).
        assert!(!event.payload.contains_key("expires_at"));
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

        let noncanonical_key_state = serde_json::json!({
            "agent_id": agent_actor_id,
            "controller_id": controller_actor_id,
            "principal_control_realm_id": "ak:realm:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc",
            "controller_authorization_ref": "did:web:controller.example#controller-authorization",
            "status": "active",
            "runtime_state": "pending_runtime_key",
            "pairing_request_id": "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
            "pairing_code": "12345678",
            "pairing_expires_at": "2026-07-06T00:15:00.000123Z",
            "requested_scope": key_state.requested_scope,
        });
        assert!(serde_json::from_value::<arkret_sdk::KeyState>(noncanonical_key_state).is_err());
    }

    #[test]
    fn runtime_key_reauthorize_supersedes_same_key_active_authorization() {
        // Regression: re-pairing an active agent reuses the same stable
        // endpoint-bound verification method.
        // verification_method, so the currently-active authorization shares the
        // new authorization's key_id. `supersedes` MUST still include it —
        // coauth requires an exact match against the authoritative
        // `active_authorizations`. A key_id filter dropped that authorization,
        // yielding an empty `supersedes` that failed coauth's exact-match check
        // with a CONFLICT surfaced as "Server rejected the runtime key approval".
        let controller = "did:web:controller.example";
        let service_id = "ak:did_core:web:arkret.example";
        let agent = "did:web:agents.example:summary";
        let verification_method =
            "did:web:agents.example:summary#ak:device:01964137-0000-7000-8000-000000000008";
        let old_event = "ak:event:AfCohWegfBhEKqSVC-suYPF9jT5A0uR-BnFk1GppvjQz";
        let signer = std::sync::Arc::new(crate::event_signer::build_ed25519_device_signer(
            [41u8; 32],
            controller,
            "ak:device:01964137-0000-7000-8000-000000000007",
        ));
        let _signer_guard = crate::event_signer::ActiveSignerTestGuard::replace(Some(signer));
        let scope = requested_scope_for_presets(&[], &AgentServiceScopePreset::DEFAULTS).unwrap();
        let agent_actor_id =
            arkret_sdk::project_did_to_core_id(&arkret_sdk::Did::new(agent.to_owned()).unwrap())
                .unwrap();
        let controller_actor_id = arkret_sdk::project_did_to_core_id(
            &arkret_sdk::Did::new(controller.to_owned()).unwrap(),
        )
        .unwrap();
        let key_state: arkret_sdk::KeyState = serde_json::from_value(serde_json::json!({
            "agent_id": agent_actor_id,
            "controller_id": controller_actor_id,
            "principal_control_realm_id": "ak:realm:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc",
            "controller_authorization_ref": "did:web:controller.example#controller-authorization",
            "pairing_request_id": "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
            "pairing_code": "12345678",
            "pairing_expires_at": "2026-07-06T00:15:00.000Z",
            "requested_scope": scope,
            "active_authorizations": [{
                "key_id": verification_method,
                "verification_method": verification_method,
                "authorized_event_ref": old_event,
            }],
        }))
        .unwrap();
        let raw = serde_json::json!({
            "pairing_request_id": "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
            "agent_id": agent_actor_id,
            "verification_method": verification_method,
            "public_key": {
                "kty": "OKP",
                "kid": verification_method,
                "algorithm": "Ed25519",
                "key": arkret_sdk::base64url_encode([9u8; 32]),
            },
            "proof_of_possession": {
                "kind": "agent_runtime_key_possession",
                "verification_method": verification_method,
                "signature_algorithm": "Ed25519",
                "challenge": "agent_pairing_request:01999999-0000-7000-8000-00000000feed",
                "audience_id": service_id,
                "created_at": "2026-07-06T00:10:00.000Z",
                "expires_at": "2026-07-06T00:15:00.000Z",
                "runtime_key_binding_digest": format!("sha256:{}", "0".repeat(64)),
                "transcript_digest": format!("sha256:{}", "1".repeat(64)),
                "signature": arkret_sdk::base64url_encode([1u8; 64]),
            },
        })
        .to_string();
        let request = parse_runtime_key_approval_request(&raw).unwrap();

        // Re-pairing's supersedes set is settled before authoring: it names the
        // authorizations this key replaces, not anything about the new Event.
        let intent =
            prepare_agent_key_authorize_pairing(controller, service_id, &key_state, &request)
                .unwrap()
                .intent()
                .clone();

        let supersedes = intent.payload()["supersedes"]
            .as_array()
            .expect("re-pair authorize event must carry a supersedes array");
        assert_eq!(
            supersedes.len(),
            1,
            "re-pair must supersede the single active authorization, even with the same key_id"
        );
        assert_eq!(supersedes[0]["key_id"], verification_method);
        assert_eq!(supersedes[0]["authorized_event_ref"], old_event);
    }

    #[test]
    fn build_action_approve_payload_binds_draft_digest_and_nonce() {
        let draft = serde_json::json!({
            "type": "ak.agent.draft.v1",
            "draft_id": "0197-draft",
            "agent_id": "ak:did_core:web:agents.example:summary",
            "proposed_action": "ak.message.create",
            "target": {"kind": "realm", "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"},
            "content": {"body": "draft text"},
        });
        let payload = serde_json::to_value(
            build_action_approve_payload(
                &draft,
                "did:web:alice.example",
                "2026-06-26T00:00:00.000Z",
                "2026-06-26T01:00:00.000Z",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(payload["draft_id"], "0197-draft");
        assert_eq!(payload["controller_id"], "ak:did_core:web:alice.example");
        assert_eq!(payload["proposed_action"], "ak.message.create");
        assert_eq!(payload["approved_at"], "2026-06-26T00:00:00.000Z");
        assert_eq!(payload["expires_at"], "2026-06-26T01:00:00.000Z");
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
            "agent_id": "ak:did_core:web:agents.example:summary",
            "proposed_action": "ak.message.create",
            "target": {"kind": "realm", "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"},
            "request_canonical_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        });
        let payload = serde_json::to_value(
            build_action_approve_payload(
                &request,
                "did:web:alice.example",
                "2026-06-26T00:00:00.000Z",
                "2026-06-26T01:00:00.000Z",
            )
            .unwrap(),
        )
        .unwrap();
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
            "agent_id": "ak:did_core:web:agents.example:summary",
        });
        let payload = serde_json::to_value(
            build_action_reject_payload(
                &request,
                "did:web:alice.example",
                "2026-06-26T00:00:00.000Z",
                Some("needs review"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(payload["request_id"], "ak:agent-action-request:0198");
        assert_eq!(payload["controller_id"], "ak:did_core:web:alice.example");
        assert_eq!(payload["rejected_at"], "2026-06-26T00:00:00.000Z");
        assert_eq!(payload["reason"], "needs review");
        assert!(!payload["rejection_id"].as_str().unwrap().is_empty());
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
