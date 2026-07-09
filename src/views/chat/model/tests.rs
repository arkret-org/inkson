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

    fn signed_message_envelope_inner(
        signer: &crate::event_signer::InksonEventSigner,
        actor_id: &str,
        device_id: Option<&str>,
    ) -> Value {
        let mut envelope = json!({
            "kind": "ck.message.create",
            "realm_id": "ak:realm:r",
            "actor_id": actor_id,
            "created_at": "2026-06-16T00:00:00Z",
            "message_id": "ak:msg:1",
            "strand_id": "ak:strand:general",
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
        let verification_method = signer.verification_method().to_owned();
        // Build the proof binding via the SDK's authoritative
        // `Proof::canonical_binding_bytes` (which folds in the
        // `context = "ck-event-proof-v1"` domain tag) — the SAME transcript both
        // the production signer and the verifier use, so this test can never drift
        // from the on-wire binding again.
        let proof_created_at = chrono::DateTime::parse_from_rfc3339("2026-06-16T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let did = cokret_sdk::Did::new(actor_id.to_owned()).unwrap();
        let mut proof = cokret_sdk::Proof {
            kind: "detached_jws".to_owned(),
            alg: signer.algorithm().to_owned(),
            verification_method: verification_method.clone(),
            event_digest: cokret_sdk::Hash::new(event_digest).unwrap(),
            created_at: proof_created_at,
            domain: None,
            audience: None,
            jws: String::new(),
        };
        let binding_bytes = proof.canonical_binding_bytes(&did).unwrap();
        proof.jws = signer.detached_jws_over(&binding_bytes).unwrap();
        envelope.as_object_mut().unwrap().insert(
            "proofs".to_owned(),
            json!([serde_json::to_value(&proof).unwrap()]),
        );
        envelope
    }

    fn pubkey(seed: u8) -> cokret_sdk::signatures::PublicKeyMaterial {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let did = crate::did_key::did_key_from_verifying_key(&sk.verifying_key());
        crate::device_directory::public_key_from_directory_value(&did).unwrap()
    }

    #[test]
    fn verified_message_enters_view() {
        let actor = "did:web:chat-alice.example";
        let device = "ak:device:chat-a1";
        let seed = 51u8;
        let signer = crate::event_signer::build_ed25519_signer([seed; 32], actor);
        let envelope = signed_message_envelope(&signer, actor, device);
        crate::device_directory::seed_positive_for_test(actor, device, pubkey(seed));

        assert_eq!(
            verify_chat_envelope_proof(&envelope),
            ChatProofVerdict::Verified
        );
        let message = chat_message_from_event("ak:realm:r", &envelope)
            .expect("verified message must enter the view");
        assert_eq!(message.sender, actor);
        crate::device_directory::invalidate(actor, device);
    }

    #[test]
    fn wrong_key_drops_message() {
        let actor = "did:web:chat-bob.example";
        let device = "ak:device:chat-b1";
        let signer = crate::event_signer::build_ed25519_signer([52u8; 32], actor);
        let envelope = signed_message_envelope(&signer, actor, device);
        // Cache holds a DIFFERENT device's key → verification fails → drop.
        crate::device_directory::seed_positive_for_test(actor, device, pubkey(123));
        assert_eq!(
            verify_chat_envelope_proof(&envelope),
            ChatProofVerdict::Rejected
        );
        assert!(chat_message_from_event("ak:realm:r", &envelope).is_none());
        crate::device_directory::invalidate(actor, device);
    }

    #[test]
    fn revoked_device_drops_message() {
        let actor = "did:web:chat-carol.example";
        let device = "ak:device:chat-c1";
        let signer = crate::event_signer::build_ed25519_signer([53u8; 32], actor);
        let envelope = signed_message_envelope(&signer, actor, device);
        crate::device_directory::seed_negative_for_test(actor, device);
        assert_eq!(
            verify_chat_envelope_proof(&envelope),
            ChatProofVerdict::Rejected
        );
        assert!(chat_message_from_event("ak:realm:r", &envelope).is_none());
        crate::device_directory::invalidate(actor, device);
    }

    #[test]
    fn controller_mismatch_drops_message() {
        let actor = "did:web:chat-dave.example";
        let device = "ak:device:chat-d1";
        let seed = 54u8;
        let signer = crate::event_signer::build_ed25519_signer([seed; 32], actor);
        let mut envelope = signed_message_envelope(&signer, actor, device);
        // Point the verification_method at a different controller DID.
        envelope["proofs"][0]["verification_method"] = json!("did:web:imposter.example#device");
        crate::device_directory::seed_positive_for_test(actor, device, pubkey(seed));
        assert_eq!(
            verify_chat_envelope_proof(&envelope),
            ChatProofVerdict::Rejected
        );
        crate::device_directory::invalidate(actor, device);
    }

    #[test]
    fn cache_miss_flags_needs_verification_but_still_shows() {
        let actor = "did:web:chat-erin.example";
        let device = "ak:device:chat-e1";
        let signer = crate::event_signer::build_ed25519_signer([55u8; 32], actor);
        let envelope = signed_message_envelope(&signer, actor, device);
        // No cache entry → Unresolved → message visible but flagged.
        crate::device_directory::invalidate(actor, device);
        assert_eq!(
            verify_chat_envelope_proof(&envelope),
            ChatProofVerdict::Unresolved
        );
        let message = chat_message_from_event("ak:realm:r", &envelope)
            .expect("unresolved message stays visible (flagged)");
        assert_eq!(message.crypto_state, MessageCryptoState::NeedsVerification);
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
        crate::device_directory::seed_positive_for_test(actor, device, pubkey(56));

        assert_eq!(
            verify_chat_envelope_proof(&envelope),
            ChatProofVerdict::Verified
        );
        let message = chat_message_from_event("ak:realm:r", &envelope)
            .expect("standard Event envelope without device_id uses proof fragment");
        assert_eq!(message.crypto_state, MessageCryptoState::Plaintext);
        crate::device_directory::invalidate(actor, device);
    }

    #[test]
    fn proofless_projection_is_not_applicable() {
        let envelope = json!({
            "kind": "ck.message.create",
            "actor_id": "did:web:legacy.example",
            "device_id": "ak:device:legacy",
            "message_id": "ak:msg:legacy",
            "strand_id": "ak:strand:general",
            "content": { "body": "legacy proofless message" }
        });
        assert_eq!(
            verify_chat_envelope_proof(&envelope),
            ChatProofVerdict::NotApplicable
        );
        // No regression: a proofless projection still renders.
        assert!(chat_message_from_event("ak:realm:r", &envelope).is_some());
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
                controller_did: "did:web:example.com:users:alice".to_owned(),
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
