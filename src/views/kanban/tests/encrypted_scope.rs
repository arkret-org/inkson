use super::*;

struct ActiveAccountScopeTestGuard {
    // Drop the signer guard before the account-scope guard so restoration follows
    // the inverse of the documented scope-then-signer lock order.
    _signer: crate::event_signer::ActiveSignerTestGuard,
    _scope: crate::secure_key_store::DeviceSeedScopeTestGuard,
}

fn active_account_scope(actor: &str, device: &str) -> ActiveAccountScopeTestGuard {
    let authority = fixture::authority(actor);
    let device = fixture::device_id(device);
    let scope =
        crate::secure_key_store::DeviceSeedScopeTestGuard::replace(Some((&authority, &device)));
    let signer = crate::event_signer::ActiveSignerTestGuard::replace(Some(std::sync::Arc::new(
        crate::event_signer::build_ed25519_device_signer(
            [41; 32],
            authority.principal_id.as_str(),
            device.as_str(),
        ),
    )));
    ActiveAccountScopeTestGuard {
        _signer: signer,
        _scope: scope,
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn pending_welcome_delivery(
    scope: &arkret_sdk::ScopeRef,
    recipient_actor: &str,
    recipient_device: &str,
    welcome_id: &str,
    draft: &arkret_sdk::mls::MlsWelcomeDraft,
) -> arkret_wire::MlsWelcomeDelivery {
    let recipient_device = fixture::device_id(recipient_device);
    assert_eq!(
        draft.recipient,
        arkret_sdk::MlsEndpointIdentity::human_device(
            crate::mls_api_helpers::principal_core_id(recipient_actor).unwrap(),
            recipient_device.clone(),
        )
    );
    let delivery = arkret_wire::MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new(welcome_id).unwrap(),
        realm_id: scope.realm_id_opt().unwrap().clone(),
        effective_scope: scope.clone(),
        commit_event_ref: arkret_sdk::EventId::new(
            "ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml",
        )
        .unwrap(),
        recipient_actor_id: arkret_sdk::ActorId::account(fixture::authority(recipient_actor)),
        recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: recipient_device,
        },
        keypackage_claim_ref: draft.keypackage_claim_ref.clone(),
        ciphertext_base64url: draft.ciphertext_base64url.clone(),
        producer_proof: arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: arkret_sdk::DidUrl::new("did:web:alice.example#device-key")
                .unwrap(),
            signed_digest: arkret_sdk::Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
            created_at: "2026-09-22T00:00:00.000Z".parse().unwrap(),
            signature: arkret_sdk::Base64UrlString::new("A".repeat(86)).unwrap(),
        },
    };
    delivery.validate_shape().unwrap();
    delivery
}

fn seed_device_authorization(actor: &str, device: &str) {
    let actor = crate::mls_api_helpers::principal_core_id(actor).unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[41; 32])
        .verifying_key()
        .to_bytes()
        .to_vec();
    crate::identity::device_directory::seed_device_authorization_for_test(
        actor.as_str(),
        device,
        arkret_sdk::signatures::PublicKeyMaterial::Ed25519Raw { bytes: key },
        arkret_sdk::EventId::new(
            "ak:event:AdU2TJKBkRBC1Jk1dY8ExFkUgDvhnVG8jmKT5BdWMeYp".to_owned(),
        )
        .unwrap(),
    );
}

#[cfg(not(target_arch = "wasm32"))]
fn seed_ready_creator_snapshot(
    state: &mut crate::state::LocalStateStore,
    secure: &crate::secure_key_store::MemorySecureKeyStore,
    realm: &str,
    actor: &str,
    device: &str,
) -> arkret_sdk::EventId {
    seed_device_authorization(actor, device);
    fixture::install_complete_joined_members(
        state,
        realm,
        vec![arkret_sdk::ActorId::account(fixture::authority(actor))],
    );
    crate::mls::runtime::ensure_creator_mls_checkpoint(
        state,
        secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
    )
    .unwrap()
    .expect("fixture creates the current creator MLS snapshot");
    let snapshot = state.mls_checkpoint_for(realm).unwrap();
    let accepted_ref =
        arkret_sdk::EventId::new("ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml").unwrap();
    state
        .record_mls_group_state_ref_for_effective_scope(
            realm,
            None,
            &snapshot.group_id,
            snapshot.epoch,
            accepted_ref.clone(),
        )
        .unwrap();
    state.mark_mls_genesis_emitted(realm).unwrap();
    accepted_ref
}

/// Seal an encrypted write against its already accepted MLS epoch.
#[cfg(not(target_arch = "wasm32"))]
fn seal_against_accepted_epoch(
    plan: super::super::mls_encrypt::EncryptedPatchPlan,
    _mls_events: &super::super::mls_encrypt::EncryptedWriteMlsEvents,
) -> Value {
    plan.seal(None, None)
        .expect("an encrypted write seals against its accepted epoch")
}

/// The local plaintext sidecar stores the JSON-serialized patch VALUE, which is
/// now the canonical ContentBlock rather than a bare string.
fn content_block_json(body: &str) -> String {
    serde_json::to_string(&json!({
        "kind": "ak.content.text", "format": "markdown", "body": body
    }))
    .expect("content block serializes")
}

#[test]
fn encrypted_scope_blocks_plaintext_strand_update_payload() {
    let event = crate::operation::ak_ops::strand_update_patch(
        TEST_REALM_ID,
        "ak:did_core:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "content": {"$op": "set", "value": {
                "kind": "ak.content.text", "format": "markdown",
                "body": "private description"
            }},
        }),
    )
    .expect("builds")
    .build("inkson");

    assert!(kanban_event_carries_plaintext_private_content(&event));
    let reason = kanban_plaintext_block_reason(Some(true), &event).unwrap();
    assert!(reason.contains("Encrypted Realm blocks plaintext ak.strand.update"));
    assert!(kanban_plaintext_block_reason(Some(false), &event).is_none());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn private_body_original_survives_without_an_operation_tail_or_author_plaintext() {
    let actor = "ak:did_core:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let _account_scope = active_account_scope(actor, device);
    let secure = std::sync::Arc::new(crate::secure_key_store::MemorySecureKeyStore::new());
    let _secure = crate::secure_key_store::DefaultSecureKeyStoreTestGuard::replace(secure.clone());
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("private-body.json");
    let mut state = crate::state::LocalStateStore::with_path(&path);
    state.promote_accepted_context_for_test(&"did:web:alice.example".parse().unwrap());
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let account = fixture::authority(actor);
    let device_id = fixture::device_id(device);
    state.save_realm_tree_projection(
        realm,
        creator_realm_projection(&account.principal_id, "mls_rfc9420"),
    );
    let scope = arkret_sdk::ScopeRef::Realm {
        realm_id: realm.parse().unwrap(),
    };
    fixture::install_accepted_mls_group(&mut state, &scope);
    let reference = seed_ready_creator_snapshot(&mut state, secure.as_ref(), realm, actor, device);
    let checkpoint = state.mls_checkpoint_for(realm).unwrap();
    let secret =
        crate::mls::runtime::load_device_checkpoint_secret(secure.as_ref(), &account, &device_id)
            .unwrap();
    let mut group =
        crate::mls::persistence::restore_envelope(&checkpoint, &secret, checkpoint.epoch).unwrap();
    let strand = "ak:strand:AbQHDTvS4ZELwYOPkH_Rdpweaio8GKWhHTHvvDJIAgzZ";
    let plaintext =
        json!({"kind":"ak.content.text","format":"markdown","body":"retained private body"});
    let mut unsigned = arkret_test_kit::signed_event::SignedEventFixtureBuilder::new(
        "ak.strand.update",
        scope.clone(),
        fixture::account_actor(actor),
        arkret_sdk::StrandPatchPayload::for_strand(
            strand.parse().unwrap(),
            serde_json::from_value(json!({"content":{"$op":"set","value":plaintext}})).unwrap(),
        )
        .unwrap()
        .to_value()
        .unwrap(),
    )
    .build_unsigned()
    .unwrap();
    let mut material = fixture::content::material(&group, "ak.strand.update", &reference);
    material.outer_event =
        arkret_models_crypto::EventContentMaterial::outer_event_for(&unsigned).unwrap();
    fixture::content::retain_root(
        secure.as_ref(),
        &account,
        &device_id,
        &group,
        &material.content_context.root_context,
    );
    let header = arkret_sdk::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
        arkret_sdk::EncryptedPayloadScheme::EpochContentAead,
        scope,
        "ak.strand.update",
        group.epoch(),
        reference,
        group.local_content_sender_domain().unwrap(),
        arkret_sdk::EventContentRoutingContext::None,
        material,
    )
    .unwrap();
    let encrypted = group
        .encrypt_payload(header, &serde_json::to_vec(&plaintext).unwrap())
        .unwrap();
    let envelope = arkret_sdk::mls::encrypted_envelope_from_payload(&encrypted).unwrap();
    unsigned.payload = serde_json::from_value(
        arkret_sdk::StrandPatchPayload::for_strand(
            strand.parse().unwrap(),
            serde_json::from_value(json!({"encrypted_content":{"$op":"set","value":envelope}}))
                .unwrap(),
        )
        .unwrap()
        .to_value()
        .unwrap(),
    )
    .unwrap();
    let method = format!("did:web:alice.example#{device}");
    let signer = arkret_test_kit::keys::seeded_signer_for_seed(
        [41; 32],
        "did:web:alice.example".parse().unwrap(),
        arkret_sdk::DidUrl::new(method.clone()).unwrap(),
    );
    let original = arkret_test_kit::signed_event::sign_verifiable_event(
        unsigned,
        &signer,
        arkret_sdk::DigestSuite::Sha256,
    )
    .unwrap()
    .expect_verifiable();
    assert!(
        !arkret_event_draft::EventContentEnvelopesExt::event_content_envelopes(&original)
            .expect("registered private body slot")
            .is_empty()
    );
    assert_eq!(
        crate::identity::committed_sender::verify_chat_envelope_proof_for_realm(
            realm,
            &serde_json::to_value(&original).unwrap(),
            Some(&state),
            Some((&account, account.principal_id.as_str(), &device_id)),
        ),
        crate::identity::committed_sender::ChatProofVerdict::Verified
    );
    crate::identity::metadata::retain_accepted_encrypted_original_for_test(
        &state,
        &original,
        &account,
        &device_id,
        secure.as_ref(),
    );
    assert_eq!(state.encrypted_originals_for(realm), vec![original]);
    assert!(state.load().raw_operations.is_empty());
    assert!(
        state
            .private_plaintext_for(realm, strand, KANBAN_ENCRYPTED_CONTENT_PATH)
            .is_none()
    );
    let value = serde_json::to_value(&envelope).unwrap();
    let live_context = MlsDecryptCtx {
        state_store: &state,
        realm_id: realm,
        identity: Some((&account, device)),
    };
    assert_eq!(
        private_strand_field_text(
            Some(&live_context),
            strand,
            KANBAN_ENCRYPTED_CONTENT_PATH,
            Some(&value)
        ),
        "retained private body",
        "the retained original must decrypt before cold loading"
    );
    state.flush().unwrap();
    assert!(
        state
            .persist_e2ee_plaintext_cache_with_secure_store(secure.as_ref())
            .unwrap()
    );
    let mut restored = crate::state::LocalStateStore::with_path(&path);
    restored.promote_accepted_context_for_test(&"did:web:alice.example".parse().unwrap());
    restored
        .hydrate_e2ee_plaintext_cache_with_secure_store(secure.as_ref())
        .unwrap();
    assert_eq!(restored.encrypted_originals_for(realm).len(), 1);
    assert!(restored.load().raw_operations.is_empty());
    let context = MlsDecryptCtx {
        state_store: &restored,
        realm_id: realm,
        identity: Some((&account, device)),
    };
    assert_eq!(
        private_strand_field_text(
            Some(&context),
            strand,
            KANBAN_ENCRYPTED_CONTENT_PATH,
            Some(&value)
        ),
        "retained private body"
    );
    assert!(!private_strand_field_locked(
        Some(&context),
        strand,
        KANBAN_ENCRYPTED_CONTENT_PATH,
        Some(&value)
    ));
    assert!(
        private_strand_field_text(
            Some(&context),
            "ak:strand:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN",
            KANBAN_ENCRYPTED_CONTENT_PATH,
            Some(&value)
        )
        .is_empty()
    );
}

/// R4 fail-closed: when the Realm security state is UNKNOWN (`None`, i.e.
/// the security projection has not synced yet) the guard MUST block a
/// plaintext private-content write rather than defaulting to plaintext.
/// A known-plaintext Realm (`Some(false)`) is the legitimate case that
/// MUST still be allowed — that is what keeps fail-closed from breaking
/// normal plaintext strands.
#[test]
fn unknown_scope_security_blocks_plaintext_private_content_fail_closed() {
    let private_update = crate::operation::ak_ops::strand_update_patch(
        TEST_REALM_ID,
        "ak:did_core:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "content": {"$op": "set", "value": {
                "kind": "ak.content.text", "format": "markdown",
                "body": "private description"
            }},
        }),
    )
    .expect("builds")
    .build("inkson");
    assert!(kanban_event_carries_plaintext_private_content(
        &private_update
    ));
    // Unknown security state → fail-closed block.
    assert!(
        kanban_plaintext_block_reason(None, &private_update).is_some(),
        "unknown security state must fail closed for plaintext private content"
    );
    // Known-plaintext Realm → legitimate plaintext write, never blocked.
    assert!(
        kanban_plaintext_block_reason(Some(false), &private_update).is_none(),
        "known-plaintext Realm must keep allowing plaintext writes"
    );

    // Non-private metadata (container scaffold) is exempt even when the
    // security state is unknown, so board/list creation is not bricked
    // while the projection is in flight.
    let board_create = crate::operation::ak_ops::space_create(
        TEST_REALM_ID,
        "ak:did_core:web:alice.example",
        "board",
        "Roadmap",
        None,
        None,
    )
    .expect("builds")
    .build("inkson");
    assert!(
        kanban_plaintext_block_reason(None, &board_create).is_none(),
        "container scaffold metadata must not be blocked by unknown security state"
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn encrypted_scope_allows_encrypted_strand_update_patch_value() {
    // The ciphertext is produced by the production encryption path
    // (`kanban::mls_encrypt` → `mls::runtime`), not by a local MLS harness, so
    // the guard is exercised against the exact value shape the product writes.
    let actor = "ak:did_core:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let _account_scope = active_account_scope(actor, device);
    let actor_id = crate::mls_api_helpers::principal_core_id(actor).unwrap();
    let mut state = isolated_store_for_tests("encrypted-scope-allows-encrypted-value");
    state.save_realm_tree_projection(
        TEST_REALM_ID,
        creator_realm_projection(&actor_id, "mls_rfc9420"),
    );
    fixture::install_accepted_mls_group(
        &mut state,
        &arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(TEST_REALM_ID.to_owned()).unwrap(),
        },
    );
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    seed_ready_creator_snapshot(&mut state, &secure, TEST_REALM_ID, actor, device);
    let (patched, _mls_events) = encrypt_private_card_detail_patch_values_with_store(
        json!({
            "content": {"$op": "set", "value": {
                "kind": "ak.content.text", "format": "markdown", "body": "private description"
            }},
        }),
        TEST_REALM_ID,
        DEMO_STRAND_LEGAL_REVIEW_ID,
        actor,
        device,
        &mut state,
        &secure,
    )
    .await
    .expect("complete creator projection must reach the encrypted success path");
    let patched = seal_against_accepted_epoch(patched, &_mls_events);
    let encrypted_payload = patched["encrypted_content"]["value"].clone();
    assert!(
        encrypted_payload.get("ciphertext").is_some(),
        "production encryption must replace the plaintext value with a ciphertext envelope"
    );

    let event = crate::operation::ak_ops::strand_update_patch(
        TEST_REALM_ID,
        actor,
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "encrypted_content": {"$op": "set", "value": encrypted_payload},
        }),
    )
    .expect("builds")
    .build("inkson");

    assert!(!kanban_event_carries_plaintext_private_content(&event));
    assert!(kanban_plaintext_block_reason(Some(true), &event).is_none());
}

#[test]
fn private_patch_value_collection_targets_only_canonical_content_fields() {
    let patch = json!({
        "metadata.title": {"$op": "set", "value": "metadata is allowed"},
        "metadata.summary": {"$op": "set", "value": "metadata is allowed"},
        "content": {"$op": "set", "value": {
            "kind": "ak.content.text", "format": "markdown", "body": "private description"
        }},
        "tracks.synthesis.content": {"$op": "set", "value": {
            "kind": "ak.content.text", "format": "markdown", "body": "private synthesis"
        }},
        // Retired non-spec paths must not be collected for encryption: a write
        // that used them is a schema violation the server rejects, and treating
        // them as private content would silently paper over that.
        "body": {"$op": "set", "value": "non-spec body"},
        "synthesis": {"$op": "set", "value": "non-spec synthesis"},
        "fields.body": {"$op": "set", "value": "non-spec fields body"},
        "tracks.synthesis.body": {"$op": "set", "value": "non-spec track body"},
    });

    let values = collect_encryptable_private_patch_values(&patch).unwrap();
    assert_eq!(values.len(), 2);
    let description = values
        .iter()
        .find(|(path, _)| path == KANBAN_CONTENT_PATH)
        .expect("Description is independently encryptable");
    assert_eq!(
        serde_json::from_slice::<Value>(&description.1).unwrap(),
        json!({ "kind": "ak.content.text", "format": "markdown", "body": "private description" })
    );
    let synthesis = values
        .iter()
        .find(|(path, _)| path == KANBAN_SYNTHESIS_CONTENT_PATH)
        .expect("Synthesis is independently encryptable");
    assert_eq!(
        serde_json::from_slice::<Value>(&synthesis.1).unwrap(),
        json!({ "kind": "ak.content.text", "format": "markdown", "body": "private synthesis" })
    );
    assert_eq!(
        kanban_encrypted_patch_path(KANBAN_CONTENT_PATH),
        KANBAN_ENCRYPTED_CONTENT_PATH
    );
    assert_eq!(
        kanban_encrypted_patch_path(KANBAN_SYNTHESIS_CONTENT_PATH),
        KANBAN_ENCRYPTED_SYNTHESIS_CONTENT_PATH
    );
}

#[test]
fn private_patch_replacement_keeps_description_and_synthesis_separate() {
    let mut patch = json!({
        (KANBAN_CONTENT_PATH): {"$op": "set", "value": {"body": "Description"}},
        (KANBAN_SYNTHESIS_CONTENT_PATH): {"$op": "set", "value": {"body": "Synthesis"}},
    });
    replace_private_patch_values(
        &mut patch,
        &[
            KANBAN_CONTENT_PATH.to_owned(),
            KANBAN_SYNTHESIS_CONTENT_PATH.to_owned(),
        ],
        vec![
            json!({"ciphertext": "description"}),
            json!({"ciphertext": "synthesis"}),
        ],
    )
    .unwrap();

    assert!(patch.get(KANBAN_CONTENT_PATH).is_none());
    assert!(patch.get(KANBAN_SYNTHESIS_CONTENT_PATH).is_none());
    assert_eq!(
        patch[KANBAN_ENCRYPTED_CONTENT_PATH]["value"]["ciphertext"],
        "description"
    );
    assert_eq!(
        patch[KANBAN_ENCRYPTED_SYNTHESIS_CONTENT_PATH]["value"]["ciphertext"],
        "synthesis"
    );
}

#[tokio::test]
async fn encrypted_private_patch_without_checkpoint_proven_snapshot_is_blocked_before_queueing() {
    let _account_scope = active_account_scope(
        "ak:did_core:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
    );
    let mut state = isolated_store_for_tests("missing-mls");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let patch = json!({
        "content": {"$op": "set", "value": {
            "kind": "ak.content.text", "format": "markdown", "body": "private description"
        }},
        "tracks.synthesis.content": {"$op": "set", "value": {
            "kind": "ak.content.text", "format": "markdown", "body": "private synthesis"
        }},
    });

    let error = encrypt_private_card_detail_patch_values_with_store(
        patch,
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "ak:strand:AbQHDTvS4ZELwYOPkH_Rdpweaio8GKWhHTHvvDJIAgzZ",
        "ak:did_core:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
        &mut state,
        &secure,
    )
    .await
    .unwrap_err();

    assert_eq!(error, "checkpoint-proven MLS group state is pending");
    assert!(
        state
            .mls_checkpoint_for("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
            .is_none()
    );
    assert!(state.load().raw_operations.is_empty());
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn kanban_write_does_not_consume_pending_welcome_without_checkpoint() {
    use arkret_sdk::{ArkretMlsIdentity, DeviceId};

    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let bob_actor = "ak:did_core:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000b2";
    let _account_scope = active_account_scope(bob_actor, bob_device);
    let alice = ArkretMlsIdentity::new_test_human_device(
        crate::test_support::account_actor("ak:did_core:web:alice.example"),
        DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000a1".to_owned()).unwrap(),
    )
    .unwrap();
    let bob = ArkretMlsIdentity::new_test_human_device(
        crate::test_support::account_actor(bob_actor),
        DeviceId::new(bob_device.to_owned()).unwrap(),
    )
    .unwrap();
    let bob_key_package = crate::test_support::claimed_mls_key_package(
        bob.key_package_record().unwrap(),
        1_900_000_000_000,
    );
    let scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
    };
    let mut alice_group = alice.create_group(&scope).unwrap();
    let add = alice_group.add_member(&bob_key_package).unwrap();
    let pending_welcome = pending_welcome_delivery(
        &scope,
        bob_actor,
        bob_device,
        "ak:mls_welcome_delivery:01904100-0000-7000-8000-0000000000ff",
        &add.welcome,
    );

    let mut state = isolated_store_for_tests("pending-local-welcome");
    state
        .ingest_recipient_deliveries(&[
            arkret_models_collaboration::device_messages::RecipientDelivery::MlsWelcome {
                mls_welcome: pending_welcome,
            },
        ])
        .unwrap();
    // Welcome validation and application belong to the MLS runtime sync path.
    // The Kanban writer consumes only checkpoint-proven active group state.
    assert!(crate::mls::runtime::has_pending_mls_welcome_for_endpoint(
        &state,
        &fixture::authority(bob_actor),
        &fixture::device_id(bob_device),
    ));
    assert!(!crate::mls::runtime::has_pending_mls_welcome_for_endpoint(
        &state,
        &fixture::authority(bob_actor),
        &fixture::device_id("ak:device:01904100-0000-7000-8000-0000000000b9",),
    ));
    let mut other_station = fixture::authority(bob_actor);
    other_station.station_id =
        arkret_sdk::DidCoreId::new("ak:did_core:web:other-station.example".to_owned()).unwrap();
    assert!(!crate::mls::runtime::has_pending_mls_welcome_for_endpoint(
        &state,
        &other_station,
        &fixture::device_id(bob_device),
    ));
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    crate::mls::runtime::store_account_mls_secret(
        &secure,
        &fixture::authority(bob_actor),
        "snapshot-secret",
    )
    .unwrap();
    let patch = json!({
        "content": {"$op": "set", "value": {
            "kind": "ak.content.text", "format": "markdown",
            "body": "private description from invited member"
        }},
    });
    let strand_id = "ak:strand:AbQHDTvS4ZELwYOPkH_Rdpweaio8GKWhHTHvvDJIAgzZ";

    let error = encrypt_private_card_detail_patch_values_with_store(
        patch, realm, strand_id, bob_actor, bob_device, &mut state, &secure,
    )
    .await
    .unwrap_err();

    assert_eq!(error, "checkpoint-proven MLS group state is pending");
    assert!(state.mls_checkpoint_for(realm).is_none());
    assert!(
        state
            .private_plaintext_for(realm, strand_id, KANBAN_ENCRYPTED_CONTENT_PATH)
            .is_none()
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn kanban_write_waits_for_runtime_to_apply_pending_welcome() {
    use arkret_sdk::{ArkretMlsIdentity, DeviceId};

    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let bob_actor = "ak:did_core:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000b3";
    let _account_scope = active_account_scope(bob_actor, bob_device);
    let alice = ArkretMlsIdentity::new_test_human_device(
        crate::test_support::account_actor("ak:did_core:web:alice.example"),
        DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000a1".to_owned()).unwrap(),
    )
    .unwrap();
    let bob = ArkretMlsIdentity::new_test_human_device(
        crate::test_support::account_actor(bob_actor),
        DeviceId::new(bob_device.to_owned()).unwrap(),
    )
    .unwrap();
    let bob_key_package = crate::test_support::claimed_mls_key_package(
        bob.key_package_record().unwrap(),
        1_900_000_000_001,
    );
    let bob_private_state = bob.export_private_state().unwrap();
    let scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
    };
    let mut alice_group = alice.create_group(&scope).unwrap();
    let add = alice_group.add_member(&bob_key_package).unwrap();
    let pending_welcome = pending_welcome_delivery(
        &scope,
        bob_actor,
        bob_device,
        "ak:mls_welcome_delivery:01904100-0000-7000-8000-0000000000f1",
        &add.welcome,
    );

    let mut state = isolated_store_for_tests("pending-local-welcome-with-state");
    state
        .ingest_recipient_deliveries(&[
            arkret_models_collaboration::device_messages::RecipientDelivery::MlsWelcome {
                mls_welcome: pending_welcome,
            },
        ])
        .unwrap();
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    crate::mls::runtime::store_account_mls_secret(
        &secure,
        &fixture::authority(bob_actor),
        "snapshot-secret",
    )
    .unwrap();
    crate::mls::runtime::store_mls_key_package_identity_state(
        &secure,
        &fixture::authority(bob_actor),
        &fixture::device_id(bob_device),
        &bob_key_package.keypackage_id,
        &bob_private_state,
    )
    .unwrap();
    let patch = json!({
        "content": {"$op": "set", "value": {
            "kind": "ak.content.text", "format": "markdown",
            "body": "private description from invited member"
        }},
    });
    let strand_id = "ak:strand:AbQHDTvS4ZELwYOPkH_Rdpweaio8GKWhHTHvvDJIAgzZ";

    let error = encrypt_private_card_detail_patch_values_with_store(
        patch, realm, strand_id, bob_actor, bob_device, &mut state, &secure,
    )
    .await
    .unwrap_err();
    assert_eq!(error, "checkpoint-proven MLS group state is pending");
    assert!(state.mls_checkpoint_for(realm).is_none());
    assert!(
        state
            .private_plaintext_for(realm, strand_id, KANBAN_ENCRYPTED_CONTENT_PATH)
            .is_none()
    );
    // The writer does not consume or delete KeyPackage state; the runtime owns
    // that transition and its claim-envelope validation.
    assert!(
        crate::mls::runtime::load_mls_key_package_identity_state(
            &secure,
            &fixture::authority(bob_actor),
            &fixture::device_id(bob_device),
            &bob_key_package.keypackage_id,
        )
        .unwrap()
        .is_some()
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn encrypted_private_patch_uses_checkpoint_proven_creator_snapshot() {
    let actor = "ak:did_core:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let _account_scope = active_account_scope(actor, device);
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let actor_id = crate::mls_api_helpers::principal_core_id(actor).unwrap();
    let mut state = isolated_store_for_tests("creator-bootstrap-mls");
    state.save_realm_tree_projection(realm, creator_realm_projection(&actor_id, "mls_rfc9420"));
    fixture::install_accepted_mls_group(
        &mut state,
        &arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
        },
    );
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let accepted_ref = seed_ready_creator_snapshot(&mut state, &secure, realm, actor, device);
    let patch = json!({
        "content": {"$op": "set", "value": {
            "kind": "ak.content.text", "format": "markdown", "body": "private description"
        }},
    });

    let strand_id = "ak:strand:AbQHDTvS4ZELwYOPkH_Rdpweaio8GKWhHTHvvDJIAgzZ";
    let (patched, mls_events) = encrypt_private_card_detail_patch_values_with_store(
        patch, realm, strand_id, actor, device, &mut state, &secure,
    )
    .await
    .expect("checkpoint-proven creator state must reach the encrypted success path");

    assert!(state.mls_checkpoint_for(realm).is_some());
    assert_eq!(
        state.private_plaintext_for(realm, strand_id, KANBAN_ENCRYPTED_CONTENT_PATH),
        Some(content_block_json("private description"))
    );
    let _ = mls_events;
    let patched = patched.seal(None, None).unwrap();
    assert_eq!(
        patched["encrypted_content"]["value"]["content_type"],
        KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE
    );
    assert_eq!(patched["encrypted_content"]["value"]["version"], "1.0");
    assert_eq!(
        patched["encrypted_content"]["value"]["encryption_context"]["group_state_ref"],
        accepted_ref.as_str()
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn encrypted_private_patch_rejects_epoch_zero_without_accepted_genesis_reference() {
    let actor = "ak:did_core:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let _account_scope = active_account_scope(actor, device);
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let actor_id = crate::mls_api_helpers::principal_core_id(actor).unwrap();
    let mut state = isolated_store_for_tests("creator-persisted-epoch-zero");
    state.save_realm_tree_projection(realm, creator_realm_projection(&actor_id, "mls_rfc9420"));
    fixture::install_accepted_mls_group(
        &mut state,
        &arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
        },
    );
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    seed_device_authorization(actor, device);
    crate::mls::runtime::ensure_creator_mls_checkpoint(
        &mut state,
        &secure,
        realm,
        &fixture::authority(actor),
        &fixture::device_id(device),
    )
    .unwrap()
    .expect("fixture creates and persists epoch-0 MLS state");
    // A local snapshot and emitted marker are not accepted group-state
    // authority. The independent bootstrap/recovery flow must restore the
    // accepted genesis reference before ordinary content authoring resumes.
    state.mark_mls_genesis_emitted(realm).expect("valid Realm");
    assert!(
        state
            .mls_group_state_ref_for_effective_scope(
                realm,
                None,
                &arkret_sdk::base64url_encode(realm.as_bytes()),
                0,
            )
            .is_err()
    );

    let patch = json!({
        "content": {"$op": "set", "value": {
            "kind": "ak.content.text", "format": "markdown", "body": "first description"
        }},
    });
    let strand_id = "ak:strand:AbQHDTvS4ZELwYOPkH_Rdpweaio8GKWhHTHvvDJIAgzZ";
    let error = encrypt_private_card_detail_patch_values_with_store(
        patch, realm, strand_id, actor, device, &mut state, &secure,
    )
    .await
    .unwrap_err();
    assert!(
        error.contains("MLS group-state Event must be accepted before encrypting"),
        "unexpected failure: {error}"
    );
    assert!(state.load().raw_operations.is_empty());
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn encrypted_private_patch_with_ready_checkpoint_replaces_plaintext() {
    use arkret_sdk::{ArkretMlsIdentity, DeviceId};

    let actor = "ak:did_core:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let _account_scope = active_account_scope(actor, device);
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let mut state = isolated_store_for_tests("ready-mls");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let secret =
        crate::mls::runtime::load_or_create_account_mls_secret(&secure, &fixture::authority(actor))
            .unwrap();
    let identity = ArkretMlsIdentity::new_test_human_device(
        crate::test_support::account_actor(actor),
        DeviceId::new(device.to_owned()).unwrap(),
    )
    .unwrap();
    let scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
    };
    state.save_realm_tree_projection(
        realm,
        json!({
            "schema_refs": [],
            "content_scheme": "mls_rfc9420",
            "member_roster_entries_limited": false,
            "member_roster_entries": [{
                "actor_id": arkret_sdk::ActorId::account(fixture::authority(actor)),
                "membership": "join"
            }]
        }),
    );
    fixture::install_accepted_mls_group(&mut state, &scope);
    fixture::install_complete_joined_members(
        &mut state,
        realm,
        vec![arkret_sdk::ActorId::account(fixture::authority(actor))],
    );
    let governance_binding = crate::mls::governance_proof::genesis_binding(&scope).unwrap();
    let mut group = identity
        .create_group_with_governance_binding(&scope, &governance_binding)
        .unwrap();
    group
        .install_local_creator_binding(
            arkret_sdk::ActorId::account(fixture::authority(actor)),
            Some(
                arkret_sdk::EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1")
                    .unwrap(),
            ),
        )
        .unwrap();
    let record = group.export_state_record().unwrap();
    let mut envelope = garth::mls::checkpoint::encrypt_state(
        realm,
        &record.group_id,
        record.epoch,
        &serde_json::to_vec(&record).unwrap(),
        &secret,
        b"deterministic-salt",
    );
    // Current MLS state comes from the authority-signed Realm projection. The
    // exact accepted Event below is the durable group-state basis; no local
    // Seal/frontier surrogate participates in authoring readiness.
    let base_group_state_ref = "ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml";
    envelope.epoch_started_at = chrono::Utc::now();
    state.save_mls_checkpoint(realm, envelope).unwrap();
    state
        .record_mls_group_state_ref_for_effective_scope(
            realm,
            None,
            &record.group_id,
            record.epoch,
            arkret_sdk::EventId::new(base_group_state_ref.to_owned()).unwrap(),
        )
        .unwrap();
    let patch = json!({
        "content": {"$op": "set", "value": {
            "kind": "ak.content.text", "format": "markdown", "body": "private description"
        }},
        "tracks.synthesis.content": {"$op": "set", "value": {
            "kind": "ak.content.text", "format": "markdown", "body": "private synthesis"
        }},
    });

    let strand_id = "ak:strand:AbQHDTvS4ZELwYOPkH_Rdpweaio8GKWhHTHvvDJIAgzZ";
    let (patched, mls_events) = encrypt_private_card_detail_patch_values_with_store(
        patch, realm, strand_id, actor, device, &mut state, &secure,
    )
    .await
    .expect("complete projection and ready snapshot must encrypt the patch");

    let patched = seal_against_accepted_epoch(patched, &mls_events);
    assert_eq!(
        patched["encrypted_content"]["value"]["content_type"],
        KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE
    );
    assert!(
        patched["encrypted_content"]["value"]
            .get("ciphertext")
            .is_some()
    );
    // X5.2 gate — the on-the-wire patch value is an MLS envelope (no
    // plaintext), while the local sidecar now holds the plaintext.
    assert!(value_is_mls_envelope(
        &patched["encrypted_content"]["value"]
    ));
    let envelope_str = serde_json::to_string(&patched["encrypted_content"]["value"]).unwrap();
    assert!(
        !envelope_str.contains("private description"),
        "on-wire envelope must not contain the plaintext"
    );
    assert_eq!(
        state.private_plaintext_for(realm, strand_id, KANBAN_ENCRYPTED_CONTENT_PATH),
        Some(content_block_json("private description"))
    );
    // The snapshot already existed (not freshly created here), so there is
    // no fresh epoch-0 material and genesis is not emitted on this path.
    let _ = mls_events;
    assert_eq!(
        patched["encrypted_content"]["value"]["encryption_context"]["group_state_ref"],
        base_group_state_ref
    );
    assert!(state.load().raw_operations.is_empty());
    let queued = RawOperationRecord {
        operation_id: "pending-description-synthesis".to_owned(),
        realm_id: Some(realm.to_owned()),
        received_at: chrono::Utc::now(),
        payload: json!({
            "kind": "ak.strand.update",
            "write_state": "queued",
            "encrypted_payload_local": true,
            "body": {"strand_id": strand_id, "patch": patched},
        }),
    };
    let ctx = MlsDecryptCtx {
        state_store: &state,
        realm_id: realm,
        identity: None,
    };
    let update = local_card_update_from_raw_operation(&queued, Some(&ctx)).unwrap();
    assert_eq!(
        update.description_body,
        Some(PrivateFieldOverlay::Set("private description".to_owned()))
    );
    assert_eq!(
        update.synthesis,
        Some(PrivateFieldOverlay::Set("private synthesis".to_owned()))
    );
    let queued_json = serde_json::to_string(&queued.payload).unwrap();
    assert!(!queued_json.contains("private description"));
    assert!(!queued_json.contains("private synthesis"));
}

#[tokio::test]
async fn encrypted_metadata_only_patch_does_not_require_mls_snapshot() {
    let _account_scope = active_account_scope(
        "ak:did_core:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
    );
    let mut state = isolated_store_for_tests("metadata-only");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let patch = json!({
        "summary": {"$op": "set", "value": "metadata summary"},
    });

    let (patched, mls_events) = encrypt_private_card_detail_patch_values_with_store(
        patch.clone(),
        TEST_REALM_ID,
        "ak:strand:AbQHDTvS4ZELwYOPkH_Rdpweaio8GKWhHTHvvDJIAgzZ",
        "ak:did_core:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
        &mut state,
        &secure,
    )
    .await
    .unwrap();

    assert!(patched.is_plaintext());
    assert_eq!(seal_against_accepted_epoch(patched, &mls_events), patch);
    let _ = mls_events;
    assert!(state.load().local_identity.is_none());
}

#[tokio::test]
async fn encrypted_write_accepts_resolvable_did_for_active_core_identity() {
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let _account_scope = active_account_scope("ak:did_core:web:alice.example", device);
    let mut state = isolated_store_for_tests("DID-active-account-match");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let patch = json!({
        "summary": {"$op": "set", "value": "metadata summary"},
    });

    let (patched, mls_events) = encrypt_private_card_detail_patch_values_with_store(
        patch.clone(),
        TEST_REALM_ID,
        "ak:strand:AbQHDTvS4ZELwYOPkH_Rdpweaio8GKWhHTHvvDJIAgzZ",
        "ak:did_core:web:alice.example",
        device,
        &mut state,
        &secure,
    )
    .await
    .expect("the active Core DID must match its resolvable DID");

    assert_eq!(seal_against_accepted_epoch(patched, &mls_events), patch);
}

#[tokio::test]
async fn encrypted_write_rejects_did_for_a_different_active_identity() {
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let _account_scope = active_account_scope("ak:did_core:web:alice.example", device);
    let mut state = isolated_store_for_tests("different-DID-active-account");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();

    let error = encrypt_private_card_detail_patch_values_with_store(
        json!({"summary": {"$op": "set", "value": "metadata summary"}}),
        TEST_REALM_ID,
        "ak:strand:AbQHDTvS4ZELwYOPkH_Rdpweaio8GKWhHTHvvDJIAgzZ",
        "ak:did_core:web:bob.example",
        device,
        &mut state,
        &secure,
    )
    .await
    .unwrap_err();

    assert_eq!(
        error,
        "encrypted write identity does not match the active account"
    );
}

#[test]
fn kanban_metadata_intents_reach_the_shared_sealing_boundary() {
    let strand = crate::operation::ak_ops::kanban_card_strand_create(
        TEST_REALM_ID,
        "ak:did_core:web:alice.example",
        "private card title",
    )
    .expect("builds")
    .build("inkson");
    let space = crate::operation::ak_ops::space_create(
        TEST_REALM_ID,
        "ak:did_core:web:alice.example",
        "list",
        "private list title",
        Some("ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"),
        Some("U"),
    )
    .expect("builds")
    .build("inkson");

    assert!(kanban_plaintext_block_reason(Some(true), &strand).is_none());
    assert!(kanban_plaintext_block_reason(Some(true), &space).is_none());
}

/// This UI guard rejects unprepared private bodies. Metadata intents proceed
/// to the shared producer boundary, which seals complete user metadata before
/// the generic send gate. Structural rank remains readable by the Station.
#[test]
fn kanban_structural_intents_proceed_but_unprepared_private_bodies_are_blocked() {
    let board = crate::operation::ak_ops::space_create(
        TEST_REALM_ID,
        "ak:did_core:web:alice.example",
        "board",
        "ZZTEST board title",
        None,
        None,
    )
    .expect("builds")
    .build("inkson");
    assert_eq!(board.kind().as_str(), "ak.space.create");
    assert!(
        kanban_plaintext_block_reason(Some(true), &board).is_none(),
        "encrypted scope must not block board container create"
    );

    let list = crate::operation::ak_ops::space_create(
        TEST_REALM_ID,
        "ak:did_core:web:alice.example",
        "list",
        "Todos list title",
        Some("ak:space:Acu6LoN-LFmj9DSd_alwrkXEKF2pIHOHM94FS3OE0CC9"),
        Some("r001"),
    )
    .expect("builds")
    .build("inkson");
    assert_eq!(list.kind().as_str(), "ak.space.create");
    assert!(
        kanban_plaintext_block_reason(Some(true), &list).is_none(),
        "encrypted scope must not block list container create"
    );

    let list_rank_update = crate::operation::ak_ops::space_update_patch(
        TEST_REALM_ID,
        "ak:did_core:web:alice.example",
        "ak:space:Af1Pi9BryFSPKbIS5B4pB9_rXFtOAL3hL4MoyX6i-uCE",
        json!({ "rank": "r000" }),
    )
    .expect("builds")
    .build("inkson");
    assert_eq!(list_rank_update.kind().as_str(), "ak.space.update");
    assert!(
        kanban_plaintext_block_reason(Some(true), &list_rank_update).is_none(),
        "encrypted scope must not block list rank update"
    );

    // Counter-case: plaintext private body in a strand update is still blocked.
    let private_update = crate::operation::ak_ops::strand_update_patch(
        TEST_REALM_ID,
        "ak:did_core:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "content": {"$op": "set", "value": {
                "kind": "ak.content.text", "format": "markdown",
                "body": "private description"
            }},
        }),
    )
    .expect("builds")
    .build("inkson");
    assert!(
        kanban_plaintext_block_reason(Some(true), &private_update).is_some(),
        "encrypted scope must still block plaintext private strand content"
    );
}

#[test]
fn encrypted_scope_allows_strand_summary_metadata_update() {
    let event = crate::operation::ak_ops::strand_update_patch(
        TEST_REALM_ID,
        "ak:did_core:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "metadata.summary": {"$op": "set", "value": "metadata summary"},
        }),
    )
    .expect("builds")
    .build("inkson");

    assert!(!kanban_event_carries_plaintext_private_content(&event));
    assert!(kanban_plaintext_block_reason(Some(true), &event).is_none());
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn sidecar_track_patch_encrypts_with_only_the_native_sidecar_snapshot() {
    let mut state = isolated_store_for_tests("sidecar-track-circle-encrypt");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let actor = "ak:did_core:web:alice.example";
    let device = "ak:device:0196419b-0000-7000-8000-000000000021";
    let _account_scope = active_account_scope(actor, device);
    let realm = "ak:realm:AYkxMogpjqRFcRiejZN897KN1bjKnAjkbNCCRbsgxeHR";
    let strand = "ak:strand:AWSjtu5m07wmq4GIr0siQOr8dsPMpOK3Wel8pRMGO3ZU";
    let sidecar_id = arkret_sdk::SidecarId::new(
        "ak:sidecar:ATob4lPqhrmzS4tLm6aZjJ77NIrYnI5OGb4qpgykXoRa".to_owned(),
    )
    .unwrap();
    let effective_scope = arkret_sdk::ScopeRef::Sidecar {
        realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
        sidecar_id: sidecar_id.clone(),
    };
    let identity = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
        crate::test_support::account_actor(actor),
        arkret_sdk::DeviceId::new(device.to_owned()).unwrap(),
    )
    .unwrap();
    let group = identity.create_group(&effective_scope).unwrap();
    let post_state = group.export_state_record().unwrap();
    let serialized = serde_json::to_vec(&post_state).unwrap();
    let secret =
        crate::mls::runtime::load_or_create_account_mls_secret(&secure, &fixture::authority(actor))
            .unwrap();
    let mut salt = [0_u8; 16];
    getrandom::fill(&mut salt).unwrap();
    let snapshot = garth::mls::checkpoint::encrypt_state(
        realm,
        &post_state.group_id,
        post_state.epoch,
        &serialized,
        &secret,
        &salt,
    );
    let realm_identity = arkret_sdk::ArkretMlsIdentity::new_test_human_device(
        crate::test_support::account_actor(actor),
        arkret_sdk::DeviceId::new(device.to_owned()).unwrap(),
    )
    .unwrap();
    let realm_scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
    };
    let realm_group = realm_identity.create_group(&realm_scope).unwrap();
    let realm_state = realm_group.export_state_record().unwrap();
    let realm_serialized = serde_json::to_vec(&realm_state).unwrap();
    let mut realm_salt = [0_u8; 16];
    getrandom::fill(&mut realm_salt).unwrap();
    let realm_snapshot = garth::mls::checkpoint::encrypt_state(
        realm,
        &realm_state.group_id,
        realm_state.epoch,
        &realm_serialized,
        &secret,
        &realm_salt,
    );
    state
        .save_mls_checkpoint(realm.to_owned(), realm_snapshot.clone())
        .unwrap();
    state
        .save_mls_checkpoint_for_scope(&effective_scope, snapshot)
        .expect("valid effective scope");
    state
        .record_mls_group_state_ref_for_scope(
            &effective_scope,
            &post_state.group_id,
            post_state.epoch,
            arkret_sdk::EventId::new(
                "ak:event:AXOcDC3EfKDsROtRCskvfBlBSDUo6v4NxBuFO3jguIWC".to_owned(),
            )
            .unwrap(),
        )
        .unwrap();
    let context = SidecarTrackWriteContext {
        sidecar_id: Some(sidecar_id),
        ready: true,
    };

    let material = crate::test_support::content::checkpoint_material(
        &state,
        &secure,
        &crate::test_support::authority(actor),
        &crate::test_support::device_id(device),
        &effective_scope,
        arkret_wire::event_kind_str::STRAND_UPDATE,
        &arkret_sdk::EventId::new("ak:event:AXOcDC3EfKDsROtRCskvfBlBSDUo6v4NxBuFO3jguIWC").unwrap(),
    );

    let (patch, events) = encrypt_private_card_detail_patch_values_with_store_for_effective_scope(
        json!({ "content": { "$op": "set", "value": {
            "kind": "ak.content.text", "format": "markdown", "body": "private overlay"
        } } }),
        realm,
        strand,
        actor,
        device,
        &mut state,
        &secure,
        Some(&context),
        &[material],
    )
    .unwrap();

    let patch = seal_against_accepted_epoch(patch, &events);
    assert!(value_is_mls_envelope(&patch["encrypted_content"]["value"]));
    let _ = events;
    assert_eq!(state.mls_checkpoint_for(realm), Some(realm_snapshot));
    assert!(state.mls_checkpoint_for_scope(&effective_scope).is_some());
    assert_eq!(
        state.private_plaintext_for(realm, strand, KANBAN_ENCRYPTED_CONTENT_PATH),
        Some(content_block_json("private overlay"))
    );
}
