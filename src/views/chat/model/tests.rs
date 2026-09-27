#[cfg(test)]
mod committed_producer_proof_tests {
    use serde_json::json;

    use super::super::*;

    const REALM: &str = "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI";
    const DEVICE: &str = "ak:device:0196419b-0000-7000-8000-0000000000f1";
    const FOREIGN_STATION: &str = "ak:did_core:web:foreign-station.example";

    fn account_actor(host: &str) -> arkret_sdk::ActorId {
        arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(format!("ak:did_core:web:{host}")).unwrap(),
            arkret_sdk::DidCoreId::new(FOREIGN_STATION).unwrap(),
        ))
    }

    /// A canonical committed `ak.message.create` signed by `signer_host` with
    /// the method fragment `fragment`.
    fn committed_message(
        actor: arkret_sdk::ActorId,
        executed_by: Option<arkret_sdk::ActorId>,
        signer_host: &str,
        fragment: &str,
    ) -> Value {
        let mut event = arkret_test_kit::signed_event::SignedEventFixtureBuilder::new(
            arkret_sdk::EventKind::MessageCreate.as_str(),
            arkret_sdk::ScopeRef::Realm {
                realm_id: arkret_sdk::RealmId::new(REALM).unwrap(),
            },
            actor,
            json!({
                "strand_id": "ak:strand:ALH536fxXVv9EDZIoWa7sN1gzbTVJQ02x6AugHURwkvE",
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "hello from a committed Event"}
            }),
        )
        .build_unsigned()
        .unwrap();
        event.executed_by = executed_by;
        let signer = arkret_test_kit::keys::seeded_signer(
            arkret_sdk::Did::new(format!("did:web:{signer_host}")).unwrap(),
            arkret_sdk::DidUrl::new(format!("did:web:{signer_host}#{fragment}")).unwrap(),
        );
        let event = arkret_test_kit::signed_event::sign_verifiable_event(
            event,
            &signer,
            arkret_sdk::DigestSuite::Sha256,
        )
        .unwrap()
        .expect_verifiable();
        serde_json::to_value(&event).unwrap()
    }

    fn foreign_device_message() -> Value {
        let host = "chat-foreign.example";
        committed_message(account_actor(host), None, host, DEVICE)
    }

    fn assert_rejected(event: &Value) {
        assert_eq!(
            verify_committed_chat_producer_proof(event),
            ChatProofVerdict::Rejected
        );
        assert!(chat_message_from_event(REALM, event).is_none());
    }

    #[test]
    fn foreign_producer_without_a_cached_device_key_is_verified() {
        let event = foreign_device_message();
        let actor = event["actor_id"].clone();
        let actor = serde_json::from_value::<arkret_sdk::ActorId>(actor).unwrap();
        crate::identity::device_directory::invalidate_actor(&actor.to_string());
        assert!(matches!(
            crate::identity::device_directory::cached_device_signing_key(
                &actor.to_string(),
                DEVICE
            ),
            crate::identity::device_directory::CacheLookup::Miss
                | crate::identity::device_directory::CacheLookup::NegativeHit
        ));

        assert_eq!(
            verify_committed_chat_producer_proof(&event),
            ChatProofVerdict::Verified
        );
        let message = chat_message_from_event(REALM, &event)
            .expect("a self-consistent committed Event enters the view");
        assert_eq!(message.crypto_state, MessageCryptoState::Plaintext);
        assert_eq!(message.sender, "ak:did_core:web:chat-foreign.example");
        assert_eq!(
            verified_chat_sender_domain_for_realm(REALM, &event, None, None),
            Some(arkret_sdk::mls_basic_credential_identity(&actor).unwrap())
        );
    }

    #[test]
    fn digest_over_other_bytes_is_rejected() {
        let mut event = foreign_device_message();
        event["payload"]["content"]["body"] = json!("tampered after signing");
        assert_rejected(&event);
    }

    #[test]
    fn device_fragment_that_is_not_a_device_id_is_rejected() {
        let mut event = foreign_device_message();
        event["producer_proof"]["verification_method"] =
            json!("did:web:chat-foreign.example#ak:device:dev_foreign_1");
        assert_rejected(&event);
    }

    #[test]
    fn method_of_another_principal_is_rejected() {
        let mut event = foreign_device_message();
        event["producer_proof"]["verification_method"] =
            json!(format!("did:web:imposter.example#{DEVICE}"));
        assert_rejected(&event);
    }

    #[test]
    fn proof_bearing_row_that_is_not_an_event_is_rejected() {
        let mut event = foreign_device_message();
        event["device_id"] = json!(DEVICE);
        assert_rejected(&event);
    }

    #[test]
    fn proofless_attributed_projection_is_rejected() {
        let mut event = foreign_device_message();
        event.as_object_mut().unwrap().remove("producer_proof");
        assert_rejected(&event);
    }

    #[test]
    fn retired_minimal_metadata_marker_rejects_even_a_consistent_proof() {
        let event = foreign_device_message();
        let mut state = crate::state::isolated_store_for_tests("retired-chat-profile");
        state.save_realm_tree_projection(
            REALM,
            json!({ "schema_refs": ["ak.profile.mls.minimal_metadata_realm.v1"] }),
        );
        assert_eq!(
            verify_chat_envelope_proof_for_realm(REALM, &event, Some(&state), None),
            ChatProofVerdict::Rejected
        );
    }

    #[test]
    fn account_runtime_method_without_agent_evidence_remains_unresolved() {
        let host = "chat-agent.example";
        let event = committed_message(account_actor(host), None, host, "runtime-1");
        assert_eq!(
            verify_chat_envelope_proof_for_realm(REALM, &event, None, None),
            ChatProofVerdict::Unresolved
        );
    }

    #[test]
    fn applet_executor_proof_is_unresolved_instead_of_rejected() {
        let executor = arkret_sdk::ActorId::service(
            arkret_sdk::DidCoreId::new("ak:did_core:web:applet.example").unwrap(),
        );
        let event = committed_message(
            account_actor("ghost.example"),
            Some(executor),
            "applet.example",
            "applet-service-key",
        );
        assert_eq!(
            verify_committed_chat_producer_proof(&event),
            ChatProofVerdict::Unresolved
        );
        let message = chat_message_from_event(REALM, &event)
            .expect("an unresolved Applet executor remains visible and flagged");
        assert_eq!(message.sender, "ak:did_core:web:ghost.example");
        assert_eq!(message.crypto_state, MessageCryptoState::NeedsVerification);
    }
}

#[cfg(test)]
mod act_on_behalf_tests {
    use super::super::*;

    fn agent_participant(principal_id: &str) -> SpaceParticipant {
        SpaceParticipant {
            actor_id: None,
            principal_id: normalize_participant_id(principal_id)
                .expect("valid participant core id"),
            display_name: Some("Summary Assistant".to_owned()),
            handle_label: None,
            display_name_rank: 1,
            role: SpaceParticipantRole::Member,
            is_self: false,
            is_agent: true,
            agent_metadata: Some(AgentParticipantMetadata {
                controller_principal_id: "ak:did_core:web:example.com:users:alice".to_owned(),
                controller_handle: "alice".to_owned(),
                agent_slug: "summary".to_owned(),
                display_name: "Summary Assistant".to_owned(),
            }),
        }
    }

    #[test]
    fn act_on_behalf_label_resolves_executor_agent() {
        let agent = "ak:did_core:web:agents.example:summary";
        let controller = "ak:did_core:web:example.com:users:alice";
        let participants = vec![agent_participant(agent)];
        // Controller is actor_id (sender); agent is executed_by.
        let label = act_on_behalf_agent_label(controller, Some(agent), &participants);
        assert_eq!(label.as_deref(), Some("Summary Assistant"));
    }

    #[test]
    fn act_on_behalf_label_none_when_no_executed_by() {
        let controller = "ak:did_core:web:example.com:users:alice";
        assert_eq!(act_on_behalf_agent_label(controller, None, &[]), None);
        assert_eq!(act_on_behalf_agent_label(controller, Some(""), &[]), None);
    }

    #[test]
    fn act_on_behalf_label_none_when_executor_equals_sender() {
        // Reply-as-agent: the agent itself is the sender, so there is no
        // separate "via" attribution.
        let agent = "ak:did_core:web:agents.example:summary";
        let participants = vec![agent_participant(agent)];
        assert_eq!(
            act_on_behalf_agent_label(agent, Some(agent), &participants),
            None
        );
    }
}
