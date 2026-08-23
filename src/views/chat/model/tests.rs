#[cfg(test)]
mod device_identity_proof_tests {
    use serde_json::json;

    use super::super::*;

    /// Build a signed persistent message envelope: `proofs:[<detached_jws>]`
    /// over the canonical proof binding object, with `event_digest` = canonical
    /// hash of the envelope without `proofs` / `unsigned` (matching
    /// `event_signer::sign_envelope`).
    fn signed_message_envelope(
        signer: &crate::event_signer::InksonEventSigner,
        actor_id: &str,
        device_id: &str,
    ) -> Value {
        signed_message_envelope_inner(signer, actor_id, Some(device_id))
    }

    fn authority(actor: &str) -> arkret_sdk::PrincipalAuthorityKey {
        let principal_id = crate::mls_api_helpers::principal_core_id(actor).unwrap();
        arkret_sdk::PrincipalAuthorityKey {
            principal_server_id: principal_id.clone(),
            principal_id,
        }
    }

    fn signed_message_envelope_inner(
        signer: &crate::event_signer::InksonEventSigner,
        actor_full_id: &str,
        device_id: Option<&str>,
    ) -> Value {
        let actor_id = crate::mls_api_helpers::principal_core_id(actor_full_id).unwrap();
        let mut envelope = json!({
            "kind": "ak.message.create",
            "realm_id": "ak:realm:AtlzwcCCnyKBD2b_hQX9YJKlbvZu2jVHq9qsQsIaBWHI",
            "actor_id": actor_id,
            "created_at": "2026-06-16T00:00:00.000Z",
            "message_id": "ak:msg:1",
            "strand_id": "ak:strand:ALH536fxXVv9EDZIoWa7sN1gzbTVJQ02x6AugHURwkvE",
            "content": { "body": "hello from a verified device" }
        });
        if let Some(device_id) = device_id {
            envelope
                .as_object_mut()
                .unwrap()
                .insert("device_id".to_owned(), json!(device_id));
        }
        let canonical_bytes = crate::canonical::canonical_json_bytes(&envelope).unwrap();
        let event_digest = crate::canonical::sha256_digest(&canonical_bytes);
        let verification_method =
            arkret_sdk::DidUrl::new(signer.verification_method().to_owned()).unwrap();
        // Build the proof binding via the SDK's authoritative
        // `ProducerEventProof::canonical_binding_bytes` (which folds in the
        // `context = "ak.event_proof.v1"` domain tag) — the SAME transcript both
        // the production signer and the verifier use, so this test can never drift
        // from the on-wire binding again.
        let proof_created_at = chrono::DateTime::parse_from_rfc3339("2026-06-16T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let did = arkret_sdk::DidFullId::new(actor_full_id.to_owned()).unwrap();
        let mut proof = arkret_sdk::ProducerEventProof {
            kind: "detached_jws".to_owned(),
            verification_method: verification_method.clone(),
            event_digest: arkret_sdk::Hash::new(event_digest).unwrap(),
            signer_resolution_evidence_ref: None,
            signer_resolution_evidence_digest: None,
            created_at: proof_created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: String::new(),
        };
        let binding_bytes = proof
            .canonical_binding_bytes(&arkret_sdk::project_full_id_to_core_id(&did).unwrap())
            .unwrap();
        proof.jws = signer.detached_jws_over(&binding_bytes).unwrap();
        envelope.as_object_mut().unwrap().insert(
            "proofs".to_owned(),
            json!([serde_json::to_value(&proof).unwrap()]),
        );
        envelope
    }

    fn pubkey(seed: u8) -> arkret_sdk::signatures::PublicKeyMaterial {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let did = crate::identity::did_key::did_key_from_verifying_key(&sk.verifying_key());
        crate::identity::device_directory::public_key_from_directory_value(&did).unwrap()
    }

    fn core_id(full_id: &str) -> String {
        crate::mls_api_helpers::principal_core_id(full_id)
            .unwrap()
            .to_string()
    }

    #[test]
    fn verified_message_enters_view() {
        let actor = "did:web:chat-alice.example";
        let device = "ak:device:chat-a1";
        let seed = 51u8;
        let signer = crate::event_signer::build_ed25519_signer([seed; 32], actor);
        let envelope = signed_message_envelope(&signer, actor, device);
        let actor_core = core_id(actor);
        crate::identity::device_directory::seed_positive_for_test(
            &actor_core,
            device,
            pubkey(seed),
        );

        assert_eq!(
            verify_chat_envelope_proof(&envelope),
            ChatProofVerdict::Verified
        );
        let message = chat_message_from_event(
            "ak:realm:AtlzwcCCnyKBD2b_hQX9YJKlbvZu2jVHq9qsQsIaBWHI",
            &envelope,
        )
        .expect("verified message must enter the view");
        assert_eq!(message.sender, actor_core);
        crate::identity::device_directory::invalidate_actor(&actor_core);
    }

    #[test]
    fn wrong_key_drops_message() {
        let actor = "did:web:chat-bob.example";
        let device = "ak:device:chat-b1";
        let signer = crate::event_signer::build_ed25519_signer([52u8; 32], actor);
        let envelope = signed_message_envelope(&signer, actor, device);
        let actor_core = core_id(actor);
        // Cache holds a DIFFERENT device's key → verification fails → drop.
        crate::identity::device_directory::seed_positive_for_test(&actor_core, device, pubkey(123));
        assert_eq!(
            verify_chat_envelope_proof(&envelope),
            ChatProofVerdict::Rejected
        );
        assert!(
            chat_message_from_event(
                "ak:realm:AtlzwcCCnyKBD2b_hQX9YJKlbvZu2jVHq9qsQsIaBWHI",
                &envelope
            )
            .is_none()
        );
        crate::identity::device_directory::invalidate_actor(&actor_core);
    }

    #[test]
    fn revoked_device_drops_message() {
        let actor = "did:web:chat-carol.example";
        let device = "ak:device:chat-c1";
        let signer = crate::event_signer::build_ed25519_signer([53u8; 32], actor);
        let envelope = signed_message_envelope(&signer, actor, device);
        let actor_core = core_id(actor);
        crate::identity::device_directory::seed_negative_for_test(&actor_core, device);
        assert_eq!(
            verify_chat_envelope_proof(&envelope),
            ChatProofVerdict::Rejected
        );
        assert!(
            chat_message_from_event(
                "ak:realm:AtlzwcCCnyKBD2b_hQX9YJKlbvZu2jVHq9qsQsIaBWHI",
                &envelope
            )
            .is_none()
        );
        crate::identity::device_directory::invalidate_actor(&actor_core);
    }

    #[test]
    fn controller_mismatch_drops_message() {
        let actor = "did:web:chat-dave.example";
        let device = "ak:device:chat-d1";
        let seed = 54u8;
        let signer = crate::event_signer::build_ed25519_signer([seed; 32], actor);
        let mut envelope = signed_message_envelope(&signer, actor, device);
        let actor_core = core_id(actor);
        // Point the verification_method at a different controller DID.
        envelope["proofs"][0]["verification_method"] = json!("did:web:imposter.example#device");
        crate::identity::device_directory::seed_positive_for_test(
            &actor_core,
            device,
            pubkey(seed),
        );
        assert_eq!(
            verify_chat_envelope_proof(&envelope),
            ChatProofVerdict::Rejected
        );
        crate::identity::device_directory::invalidate_actor(&actor_core);
    }

    #[test]
    fn cache_miss_flags_needs_verification_but_still_shows() {
        let actor = "did:web:chat-erin.example";
        let device = "ak:device:chat-e1";
        let signer = crate::event_signer::build_ed25519_signer([55u8; 32], actor);
        let envelope = signed_message_envelope(&signer, actor, device);
        let actor_core = core_id(actor);
        // No cache entry → Unresolved → message visible but flagged.
        crate::identity::device_directory::invalidate_actor(&actor_core);
        assert_eq!(
            verify_chat_envelope_proof(&envelope),
            ChatProofVerdict::Unresolved
        );
        let message = chat_message_from_event(
            "ak:realm:AtlzwcCCnyKBD2b_hQX9YJKlbvZu2jVHq9qsQsIaBWHI",
            &envelope,
        )
        .expect("unresolved message stays visible (flagged)");
        assert_eq!(message.crypto_state, MessageCryptoState::NeedsVerification);
    }

    #[test]
    fn cache_miss_verifies_self_authored_message_with_active_device_key() {
        let actor = "did:web:chat-local.example";
        let device = "ak:device:chat-local-1";
        let seed = 57u8;
        let signer = std::sync::Arc::new(crate::event_signer::build_ed25519_device_signer(
            [seed; 32], actor, device,
        ));
        let envelope = signed_message_envelope(&signer, actor, device);
        let actor_core = core_id(actor);
        let authority = authority(actor);
        let device_id = arkret_sdk::DeviceId::new(device.to_owned()).unwrap();
        crate::identity::device_directory::invalidate_actor(&actor_core);
        let _signer_guard = crate::event_signer::ActiveSignerTestGuard::replace(Some(signer));

        let message = chat_message_from_event_with_sidecar(
            "ak:realm:AtlzwcCCnyKBD2b_hQX9YJKlbvZu2jVHq9qsQsIaBWHI",
            &envelope,
            None,
            Some((&authority, &actor_core, &device_id)),
        )
        .expect("self-authored message must verify with its active device key");
        assert_eq!(message.crypto_state, MessageCryptoState::Plaintext);
    }

    #[test]
    fn local_device_key_does_not_override_directory_revocation() {
        let actor = "did:web:chat-local-revoked.example";
        let device = "ak:device:chat-local-revoked-1";
        let signer = std::sync::Arc::new(crate::event_signer::build_ed25519_device_signer(
            [58u8; 32], actor, device,
        ));
        let envelope = signed_message_envelope(&signer, actor, device);
        let actor_core = core_id(actor);
        let authority = authority(actor);
        let device_id = arkret_sdk::DeviceId::new(device.to_owned()).unwrap();
        crate::identity::device_directory::seed_negative_for_test(&actor_core, device);
        let _signer_guard = crate::event_signer::ActiveSignerTestGuard::replace(Some(signer));

        assert_eq!(
            verify_chat_envelope_proof_for_realm(
                "ak:realm:AtlzwcCCnyKBD2b_hQX9YJKlbvZu2jVHq9qsQsIaBWHI",
                &envelope,
                None,
                Some((&authority, &actor_core, &device_id)),
            ),
            ChatProofVerdict::Rejected
        );
        crate::identity::device_directory::invalidate_actor(&actor_core);
    }

    #[test]
    fn standard_event_without_device_id_uses_proof_fragment_device() {
        let actor = "did:web:chat-fran.example";
        let device = "ak:device:chat-f1";
        let signer = crate::event_signer::build_ed25519_signer_with_verification_method(
            [56u8; 32],
            actor,
            format!("{actor}#{device}"),
        );
        let envelope = signed_message_envelope_inner(&signer, actor, None);
        let actor_core = core_id(actor);
        crate::identity::device_directory::seed_positive_for_test(&actor_core, device, pubkey(56));

        assert_eq!(
            verify_chat_envelope_proof(&envelope),
            ChatProofVerdict::Verified
        );
        let message = chat_message_from_event(
            "ak:realm:AtlzwcCCnyKBD2b_hQX9YJKlbvZu2jVHq9qsQsIaBWHI",
            &envelope,
        )
        .expect("standard Event envelope without device_id uses proof fragment");
        assert_eq!(message.crypto_state, MessageCryptoState::Plaintext);
        crate::identity::device_directory::invalidate_actor(&actor_core);
    }

    #[test]
    fn ordinary_native_agent_without_evidence_remains_unresolved() {
        let agent = "did:web:chat-agent.example";
        let signer = crate::event_signer::build_ed25519_signer_with_verification_method(
            [59u8; 32],
            agent,
            format!("{agent}#runtime-1"),
        );
        let envelope = signed_message_envelope_inner(&signer, agent, None);

        assert_eq!(
            verify_chat_envelope_proof_for_realm(
                "ak:realm:AzuLpzKBwC3cxyHqYqQRSx5Ox3nr7S9FtADPyvdaYpXY",
                &envelope,
                None,
                None
            ),
            ChatProofVerdict::Unresolved
        );
    }

    #[test]
    fn proofless_attributed_projection_is_rejected() {
        let envelope = json!({
            "kind": "ak.message.create",
            "actor_id": "ak:did_core:web:alice.example",
            "device_id": "ak:device:alice",
            "message_id": "ak:msg:proofless",
            "strand_id": "ak:strand:ALH536fxXVv9EDZIoWa7sN1gzbTVJQ02x6AugHURwkvE",
            "content": { "body": "proofless message" }
        });
        assert_eq!(
            verify_chat_envelope_proof(&envelope),
            ChatProofVerdict::Rejected
        );
        assert!(
            chat_message_from_event(
                "ak:realm:AtlzwcCCnyKBD2b_hQX9YJKlbvZu2jVHq9qsQsIaBWHI",
                &envelope
            )
            .is_none()
        );
    }

    #[test]
    fn applet_executor_proof_is_unresolved_instead_of_rejected() {
        let actor_full = "did:web:ghost.example:external-user";
        let executor_full = "did:web:applet.example";
        let actor = core_id(actor_full);
        let executor = core_id(executor_full);
        let mut envelope = json!({
            "kind": "ak.message.create",
            "realm_id": "ak:realm:AtlzwcCCnyKBD2b_hQX9YJKlbvZu2jVHq9qsQsIaBWHI",
            "actor_id": actor,
            "executed_by": executor,
            "created_at": "2026-06-16T00:00:00.000Z",
            "message_id": "ak:msg:applet",
            "strand_id": "ak:strand:ALH536fxXVv9EDZIoWa7sN1gzbTVJQ02x6AugHURwkvE",
            "content": { "body": "hello through an applet" }
        });
        let canonical_bytes = crate::canonical::canonical_json_bytes(&envelope).unwrap();
        let event_digest = crate::canonical::sha256_digest(&canonical_bytes);
        envelope["proofs"] = json!([{
            "kind": "detached_jws",
            "verification_method": format!("{executor_full}#applet-service-key"),
            "event_digest": event_digest,
            "created_at": "2026-06-16T00:00:00.000Z",
            "jws": "fixture"
        }]);

        assert_eq!(
            verify_chat_envelope_proof(&envelope),
            ChatProofVerdict::Unresolved
        );
        let message = chat_message_from_event(
            "ak:realm:AtlzwcCCnyKBD2b_hQX9YJKlbvZu2jVHq9qsQsIaBWHI",
            &envelope,
        )
        .expect("an unresolved Applet executor remains visible and flagged");
        assert_eq!(message.sender, actor);
        assert_eq!(message.crypto_state, MessageCryptoState::NeedsVerification);
    }
}

#[cfg(test)]
mod act_on_behalf_tests {
    use super::super::*;

    fn agent_participant(did: &str) -> SpaceParticipant {
        SpaceParticipant {
            did: did.to_owned(),
            display_name: Some("Summary Assistant".to_owned()),
            handle_label: None,
            display_name_rank: 1,
            role: SpaceParticipantRole::Member,
            is_self: false,
            is_agent: true,
            agent_metadata: Some(AgentParticipantMetadata {
                controller_id: "did:web:example.com:users:alice".to_owned(),
                controller_handle: "alice".to_owned(),
                agent_slug: "summary".to_owned(),
                display_name: "Summary Assistant".to_owned(),
            }),
        }
    }

    #[test]
    fn act_on_behalf_label_resolves_executor_agent() {
        let agent = "did:web:agents.example:summary";
        let controller = "did:web:example.com:users:alice";
        let participants = vec![agent_participant(agent)];
        // Controller is actor_id (sender); agent is executed_by.
        let label = act_on_behalf_agent_label(controller, Some(agent), &participants);
        assert_eq!(label.as_deref(), Some("Summary Assistant"));
    }

    #[test]
    fn act_on_behalf_label_none_when_no_executed_by() {
        let controller = "did:web:example.com:users:alice";
        assert_eq!(act_on_behalf_agent_label(controller, None, &[]), None);
        assert_eq!(act_on_behalf_agent_label(controller, Some(""), &[]), None);
    }

    #[test]
    fn act_on_behalf_label_none_when_executor_equals_sender() {
        // Reply-as-agent: the agent itself is the sender, so there is no
        // separate "via" attribution.
        let agent = "did:web:agents.example:summary";
        let participants = vec![agent_participant(agent)];
        assert_eq!(
            act_on_behalf_agent_label(agent, Some(agent), &participants),
            None
        );
    }
}
