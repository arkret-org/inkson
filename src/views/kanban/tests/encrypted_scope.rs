use super::*;

/// Seal an encrypted write against the epoch its own MLS Events establish.
///
/// Production seals inside the submit lane, once the genesis or commit this write
/// forced has been accepted. A test has no transport, so it authors those Events
/// and seals against the identities they derive.
#[cfg(not(target_arch = "wasm32"))]
fn seal_against_accepted_epoch(
    plan: super::super::mls_encrypt::EncryptedPatchPlan,
    mls_events: &super::super::mls_encrypt::EncryptedWriteMlsEvents,
) -> Value {
    let accepted = |operation: &Option<crate::operation::LocalOperation>| {
        operation.as_ref().map(|operation| {
            crate::operation::author_for_test(operation)
                .event_id()
                .clone()
        })
    };
    let commit = accepted(&mls_events.commit);
    let genesis = accepted(&mls_events.genesis);
    plan.seal(commit.as_ref(), genesis.as_ref())
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
        "did:web:alice.example",
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
        "did:web:alice.example",
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
        "did:web:alice.example",
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
#[test]
fn encrypted_scope_allows_encrypted_strand_update_patch_value() {
    // The ciphertext is produced by the production encryption path
    // (`kanban::mls_encrypt` → `mls::runtime`), not by a local MLS harness, so
    // the guard is exercised against the exact value shape the product writes.
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let actor_id = crate::mls_api_helpers::principal_core_id(actor).unwrap();
    let mut state = temp_state_store("encrypted-scope-allows-encrypted-value");
    state.save_realm_tree_projection(
        TEST_REALM_ID,
        creator_realm_projection(TEST_REALM_ID, &actor_id, "mls_rfc9420"),
    );
    crate::mls::governance_proof::seed_test_governance_proof(
        &mut state,
        TEST_REALM_ID,
        None,
        arkret_sdk::base64url_encode(TEST_REALM_ID.as_bytes()),
        0,
        0,
    );
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
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

#[test]
fn encrypted_private_patch_without_mls_snapshot_is_blocked_before_queueing() {
    let mut state = temp_state_store("missing-mls");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let patch = json!({
        "content": {"$op": "set", "value": {
            "kind": "ak.content.text", "format": "markdown", "body": "private description"
        }},
    });

    let error = encrypt_private_card_detail_patch_values_with_store(
        patch,
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "ak:strand:AbQHDTvS4ZELwYOPkH_Rdpweaio8GKWhHTHvvDJIAgzZ",
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
        &mut state,
        &secure,
    )
    .unwrap_err();

    assert!(error.contains("MLS Welcome"));
    assert!(
        state
            .mls_snapshot_for("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
            .is_none()
    );
    assert!(state.load().raw_operations.is_empty());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_private_patch_rejects_pending_welcome_without_claim_envelope() {
    use arkret_sdk::{ArkretMlsIdentity, DeviceId};

    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let bob_actor = "did:web:bob.example";
    let bob_principal_id = crate::mls_api_helpers::principal_core_id(bob_actor).unwrap();
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000b2";
    let alice = ArkretMlsIdentity::new_basic(
        crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap(),
        DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000a1".to_owned()).unwrap(),
    )
    .unwrap();
    let bob = ArkretMlsIdentity::new_basic(
        crate::mls_api_helpers::principal_core_id(bob_actor).unwrap(),
        DeviceId::new(bob_device.to_owned()).unwrap(),
    )
    .unwrap();
    let bob_key_package = bob.key_package_record().unwrap();
    let mut alice_group = alice.create_group(realm.as_bytes()).unwrap();
    let add = alice_group.add_member(&bob_key_package).unwrap();

    let mut state = temp_state_store("pending-local-welcome");
    state.ingest_to_device_messages(&[serde_json::from_value(json!({
        "device_message_id": "ak:device_message:01904100-0000-7000-8000-0000000000e1",
        "kind": "ak.mls.welcome",
        "sender_principal_id": crate::mls_api_helpers::principal_core_id(
            "did:web:alice.example"
        ).unwrap(),
        "sender_device_id": "ak:device:01904100-0000-7000-8000-0000000000a1",
        "recipient_principal_id": bob_principal_id,
        "recipient_device_id": bob_device,
        "sent_at": arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now()),
        "expires_at": arkret_sdk::canonical::format_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::hours(1)
        ),
        "content": serde_json::to_value(&add.welcome).unwrap(),
        "unsigned": {
            "mls_welcome_id": "ak:mls_welcome:01904100-0000-7000-8000-0000000000ff",
            "key_package_id": bob_key_package.keypackage_id.clone(),
        },
    }))
    .unwrap()]);
    // A durable Welcome without its accepted claim envelope is not authorized,
    // irrespective of whether local KeyPackage private state is also absent.
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    crate::mls::runtime::store_account_mls_secret(&secure, bob_actor, "snapshot-secret").unwrap();
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
    .unwrap_err();

    assert!(
        error.contains("MLS Welcome could not be applied from local device inbox"),
        "{error}"
    );
    assert!(error.contains("claim_envelope missing"), "{error}");
    assert!(state.mls_snapshot_for(realm).is_none());
    assert!(
        state
            .private_plaintext_for(realm, strand_id, KANBAN_ENCRYPTED_CONTENT_PATH)
            .is_none()
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_private_patch_applies_pending_welcome_with_key_package_state() {
    use arkret_sdk::{ArkretMlsIdentity, DeviceId};

    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let bob_actor = "did:web:bob.example";
    let bob_principal_id = crate::mls_api_helpers::principal_core_id(bob_actor).unwrap();
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000b3";
    let alice = ArkretMlsIdentity::new_basic(
        crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap(),
        DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000a1".to_owned()).unwrap(),
    )
    .unwrap();
    let bob = ArkretMlsIdentity::new_basic(
        crate::mls_api_helpers::principal_core_id(bob_actor).unwrap(),
        DeviceId::new(bob_device.to_owned()).unwrap(),
    )
    .unwrap();
    let bob_key_package = bob.key_package_record().unwrap();
    let bob_private_state = bob.export_private_state().unwrap();
    let mut alice_group = alice.create_group(realm.as_bytes()).unwrap();
    let add = alice_group.add_member(&bob_key_package).unwrap();

    let mut state = temp_state_store("pending-local-welcome-with-state");
    state.ingest_to_device_messages(&[serde_json::from_value(json!({
        "device_message_id": "ak:device_message:01904100-0000-7000-8000-0000000000e2",
        "kind": "ak.mls.welcome",
        "sender_principal_id": crate::mls_api_helpers::principal_core_id(
            "did:web:alice.example"
        ).unwrap(),
        "sender_device_id": "ak:device:01904100-0000-7000-8000-0000000000a1",
        "recipient_principal_id": bob_principal_id,
        "recipient_device_id": bob_device,
        "sent_at": arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now()),
        "expires_at": arkret_sdk::canonical::format_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::hours(1)
        ),
        "content": serde_json::to_value(&add.welcome).unwrap(),
        "unsigned": {
            "mls_welcome_id": "ak:mls_welcome:01904100-0000-7000-8000-0000000000f1",
            "key_package_id": bob_key_package.keypackage_id.clone(),
        },
    }))
    .unwrap()]);
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    crate::mls::runtime::store_account_mls_secret(&secure, bob_actor, "snapshot-secret").unwrap();
    crate::mls::runtime::store_mls_key_package_identity_state(
        &secure,
        bob_actor,
        bob_device,
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

    let blocked = encrypt_private_card_detail_patch_values_with_store(
        patch, realm, strand_id, bob_actor, bob_device, &mut state, &secure,
    );
    let (patched, mls_events) = match blocked {
        Ok(value) => value,
        Err(error) => {
            assert!(
                error.contains("decryption_pending") || error.contains("state_mismatch"),
                "{error}"
            );
            assert!(state.mls_snapshot_for(realm).is_none());
            return;
        }
    };

    assert!(state.mls_snapshot_for(realm).is_some());
    let patched = seal_against_accepted_epoch(patched, &mls_events);
    assert_eq!(
        patched["encrypted_content"]["value"]["content_type"],
        KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE
    );
    assert!(value_is_mls_envelope(
        &patched["encrypted_content"]["value"]
    ));
    assert_eq!(
        state.private_plaintext_for(realm, strand_id, KANBAN_ENCRYPTED_CONTENT_PATH),
        Some(content_block_json(
            "private description from invited member"
        ))
    );
    // The KeyPackage init private state is retained after a successful apply so
    // a redelivered durable Welcome remains an idempotent replay until ACK.
    assert!(
        crate::mls::runtime::load_mls_key_package_identity_state(
            &secure,
            bob_actor,
            bob_device,
            &bob_key_package.keypackage_id,
        )
        .unwrap()
        .is_some()
    );
    assert!(mls_events.genesis.is_none());
    assert!(mls_events.commit.is_none());
    assert!(mls_events.snapshot.is_none());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_private_patch_creator_bootstraps_initial_mls_snapshot() {
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let actor_id = crate::mls_api_helpers::principal_core_id(actor).unwrap();
    let mut state = temp_state_store("creator-bootstrap-mls");
    state.save_realm_tree_projection(
        realm,
        creator_realm_projection(realm, &actor_id, "mls_rfc9420"),
    );
    crate::mls::governance_proof::seed_test_governance_proof(
        &mut state,
        realm,
        None,
        arkret_sdk::base64url_encode(realm.as_bytes()),
        0,
        0,
    );
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let patch = json!({
        "content": {"$op": "set", "value": {
            "kind": "ak.content.text", "format": "markdown", "body": "private description"
        }},
    });

    let strand_id = "ak:strand:AbQHDTvS4ZELwYOPkH_Rdpweaio8GKWhHTHvvDJIAgzZ";
    let (patched, mls_events) = encrypt_private_card_detail_patch_values_with_store(
        patch, realm, strand_id, actor, device, &mut state, &secure,
    )
    .expect("complete creator projection must reach the encrypted success path");

    assert!(state.mls_snapshot_for(realm).is_some());
    // X5.1 — the author's own plaintext is persisted to the local
    // sidecar so a re-projection can render it (the author can never
    // decrypt their own ciphertext).
    assert_eq!(
        state.private_plaintext_for(realm, strand_id, KANBAN_ENCRYPTED_CONTENT_PATH),
        Some(content_block_json("private description"))
    );
    assert!(mls_events.commit.is_none());
    assert!(mls_events.snapshot.is_none());
    // A freshly-created creator group must still produce a one-time
    // ak.mls.genesis event; ordinary application writes ride epoch 0
    // without a per-write commit.
    let genesis = mls_events
        .genesis
        .expect("freshly-created creator group should emit genesis");
    // Sealing is what binds the envelope to the accepted epoch, and the id it
    // binds to is the genesis Event's — which only exists once that Event is
    // authored. A different accepted genesis produces a different binding, with
    // no rewrite of already-sealed bytes anywhere in between.
    let accepted_genesis = crate::operation::author_for_test(&genesis)
        .event_id()
        .clone();
    let patched = patched
        .seal(None, Some(&accepted_genesis))
        .expect("epoch-0 write seals against its accepted genesis");
    assert_eq!(
        patched["encrypted_content"]["value"]["content_type"],
        KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE
    );
    assert_eq!(patched["encrypted_content"]["value"]["version"], "1.0");
    assert_eq!(
        patched["encrypted_content"]["value"]["encryption_context"]["group_state_ref"],
        accepted_genesis.as_str()
    );
    assert_eq!(genesis.kind().as_str(), "ak.mls.genesis");
    assert_eq!(genesis.payload()["epoch"].as_u64(), Some(0));
    assert_eq!(
        genesis.payload()["creator_principal_id"].as_str(),
        Some(actor_id.as_str())
    );
    assert!(genesis.payload().contains_key("governance_binding"));
    assert_registered_payload_valid(&genesis);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_private_patch_repairs_persisted_epoch_zero_without_genesis_reference() {
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let actor_id = crate::mls_api_helpers::principal_core_id(actor).unwrap();
    let mut state = temp_state_store("creator-persisted-epoch-zero");
    state.save_realm_tree_projection(
        realm,
        creator_realm_projection(realm, &actor_id, "mls_rfc9420"),
    );
    crate::mls::governance_proof::seed_test_governance_proof(
        &mut state,
        realm,
        None,
        arkret_sdk::base64url_encode(realm.as_bytes()),
        0,
        0,
    );
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    crate::mls::runtime::ensure_creator_mls_snapshot(&mut state, &secure, realm, actor, device)
        .unwrap()
        .expect("fixture creates and persists epoch-0 MLS state");
    // Reproduce the broken state seen after first-Realm creation: the local
    // group exists and an incomplete path set the emitted bit, but no
    // accepted Event id was attached to the snapshot.
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
    let (patched, mls_events) = encrypt_private_card_detail_patch_values_with_store(
        patch, realm, strand_id, actor, device, &mut state, &secure,
    )
    .expect("persisted epoch-0 state must rebuild genesis for the first encrypted write");

    let genesis = mls_events
        .genesis
        .expect("missing accepted genesis reference must be repaired by resubmission");
    assert_eq!(genesis.kind().as_str(), "ak.mls.genesis");
    let accepted_genesis = crate::operation::author_for_test(&genesis)
        .event_id()
        .clone();
    let patched = patched
        .seal(None, Some(&accepted_genesis))
        .expect("the repaired epoch-0 write seals against its accepted genesis");
    assert_eq!(
        patched["encrypted_content"]["value"]["encryption_context"]["group_state_ref"],
        accepted_genesis.as_str()
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_private_patch_with_ready_snapshot_replaces_plaintext() {
    use arkret_sdk::{ArkretMlsIdentity, DeviceId};

    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let mut state = temp_state_store("ready-mls");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let secret = crate::mls::runtime::load_or_create_account_mls_secret(&secure, actor).unwrap();
    let identity = ArkretMlsIdentity::new_basic(
        crate::mls_api_helpers::principal_core_id(actor).unwrap(),
        DeviceId::new(device.to_owned()).unwrap(),
    )
    .unwrap();
    let group_id = arkret_sdk::base64url_encode(realm.as_bytes());
    crate::mls::governance_proof::seed_test_governance_proof(
        &mut state,
        realm,
        None,
        group_id.clone(),
        0,
        0,
    );
    let proof_request =
        crate::mls::governance_proof::proof_request(&state, realm, None, group_id, 0, 0).unwrap();
    let governance_binding =
        crate::mls::governance_proof::cached_verified_binding(&state, &proof_request).unwrap();
    let group = identity
        .create_group_with_governance_binding(realm.as_bytes(), &governance_binding)
        .unwrap();
    let record = group.export_state_record().unwrap();
    let mut envelope = crate::mls::persistence::encrypt_state(
        realm,
        &record.group_id,
        record.epoch,
        &serde_json::to_vec(&record).unwrap(),
        &secret,
        b"deterministic-salt",
    );
    state.save_realm_tree_projection(
        realm,
        json!({
            "active_profiles": [arkret_sdk::ProfileId::MLS_MINIMAL_METADATA_REALM_V1],
            "content_scheme": "mls_rfc9420",
            "members_limited": false,
            "members": [{
                "actor_id": crate::mls_api_helpers::principal_core_id(actor).unwrap(),
                "membership": "join"
            }]
        }),
    );
    // Match the accepted-Seal frontier installed by
    // `seed_test_governance_proof`; the emitted binding must carry that exact
    // verified frontier.
    let base_group_state_ref = "ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml";
    state.set_realm_seal_view(
        realm,
        crate::state::LocalSealView {
            frontier: vec![base_group_state_ref.to_owned()],
            ..crate::state::LocalSealView::default()
        },
    );
    envelope.epoch_started_at = chrono::Utc::now() - chrono::Duration::hours(2);
    state.save_mls_snapshot(realm, envelope).unwrap();
    state
        .record_mls_group_state_ref_for_effective_scope(
            realm,
            None,
            &record.group_id,
            record.epoch,
            arkret_sdk::EventId::new(base_group_state_ref.to_owned()).unwrap(),
        )
        .unwrap();
    crate::mls::governance_proof::seed_test_governance_proof(
        &mut state,
        realm,
        None,
        record.group_id.clone(),
        record.epoch,
        record.epoch + 1,
    );
    let patch = json!({
        "content": {"$op": "set", "value": {
            "kind": "ak.content.text", "format": "markdown", "body": "private description"
        }},
    });

    let strand_id = "ak:strand:AbQHDTvS4ZELwYOPkH_Rdpweaio8GKWhHTHvvDJIAgzZ";
    let (patched, mls_events) = encrypt_private_card_detail_patch_values_with_store(
        patch, realm, strand_id, actor, device, &mut state, &secure,
    )
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
    assert!(mls_events.genesis.is_none());
    assert!(mls_events.snapshot.is_some());
    let commit = mls_events
        .commit
        .as_ref()
        .expect("overdue minimal metadata MLS snapshot should emit commit event");
    // The envelope is bound to the commit that established this epoch, by that
    // commit's own final id.
    assert_eq!(
        patched["encrypted_content"]["value"]["encryption_context"]["group_state_ref"],
        crate::operation::author_for_test(commit)
            .event_id()
            .as_str()
    );
    assert_eq!(commit.kind().as_str(), "ak.mls.commit");
    assert_registered_payload_valid(commit);
    assert!(!commit.payload().contains_key("group_id"));
    assert!(!commit.payload().contains_key("expected_prev_epoch"));
    assert!(
        commit.payload()["commit_bytes_b64"]
            .as_str()
            .is_some_and(|value| !value.is_empty()),
        "durable MLS commits must inline the complete RFC 9420 Commit bytes"
    );
    assert!(!commit.payload().contains_key("preconditions"));
    assert!(!commit.payload().contains_key("effects"));
    assert_eq!(
        commit.payload()["governance_binding"]["realm_id"],
        json!("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
    );
    assert_eq!(
        commit.payload()["governance_binding"]["effective_scope"],
        json!({
            "kind": "realm",
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        })
    );
    assert_eq!(
        commit.payload()["base_epoch_ref"],
        json!(base_group_state_ref)
    );
    assert!(commit.payload()["governance_binding"]["security_frontier_digest"].is_string());
    assert!(
        !commit.payload()["governance_binding"]
            .as_object()
            .unwrap()
            .contains_key("membership_frontier")
    );
    assert!(state.load().raw_operations.is_empty());
}

#[test]
fn encrypted_metadata_only_patch_does_not_require_mls_snapshot() {
    let mut state = temp_state_store("metadata-only");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let patch = json!({
        "summary": {"$op": "set", "value": "metadata summary"},
    });

    let (patched, mls_events) = encrypt_private_card_detail_patch_values_with_store(
        patch.clone(),
        "ak:space:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "ak:strand:AbQHDTvS4ZELwYOPkH_Rdpweaio8GKWhHTHvvDJIAgzZ",
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
        &mut state,
        &secure,
    )
    .unwrap();

    assert!(patched.is_plaintext());
    assert_eq!(seal_against_accepted_epoch(patched, &mls_events), patch);
    assert!(mls_events.commit.is_none());
    assert!(mls_events.genesis.is_none());
    assert!(state.local_identity_record().is_none());
}

#[test]
fn encrypted_scope_allows_structural_strand_position_update() {
    let event = crate::operation::ak_ops::strand_position_update(
        TEST_REALM_ID,
        "did:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "board_space_id": "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
            "list_space_id": "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL",
            "rank": "U",
        }),
    )
    .expect("builds")
    .build("inkson");

    assert_eq!(event.kind().as_str(), "ak.strand.update");
    assert!(!kanban_event_carries_plaintext_private_content(&event));
    assert!(kanban_plaintext_block_reason(Some(true), &event).is_none());
}

#[test]
fn encrypted_scope_allows_content_only_metadata_create_payloads() {
    let strand = crate::operation::ak_ops::kanban_card_strand_create(
        TEST_REALM_ID,
        "did:web:alice.example",
        "ak:space:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
        "ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL",
        "private card title",
        "U",
    )
    .expect("builds")
    .build("inkson");
    let space = crate::operation::ak_ops::space_create(
        TEST_REALM_ID,
        "did:web:alice.example",
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

/// X13 regression: in an encrypted scope, container creation/update
/// (`ak.space.create` for BOTH board and list, plus `ak.space.update` rank
/// patches) MUST NOT be blocked — title/kind/parent/rank are non-secret
/// metadata that has to reach the server so a second device can render the real
/// Board/List name and order. By contrast a `ak.strand.update` carrying
/// plaintext private body MUST stay blocked (only E2EE may leave the client for
/// that field).
#[test]
fn encrypted_scope_never_blocks_container_metadata_but_blocks_plaintext_private_content() {
    let board = crate::operation::ak_ops::space_create(
        TEST_REALM_ID,
        "did:web:alice.example",
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
        "did:web:alice.example",
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
        "did:web:alice.example",
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
        "did:web:alice.example",
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
        "did:web:alice.example",
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
#[test]
fn sidecar_track_patch_encrypts_with_only_the_native_sidecar_snapshot() {
    let mut state = temp_state_store("sidecar-track-circle-encrypt");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:0196419b-0000-7000-8000-000000000021";
    let realm = "ak:realm:AYkxMogpjqRFcRiejZN897KN1bjKnAjkbNCCRbsgxeHR";
    let circle = "ak:circle:ATglM2Ok0jsPzyPkbQub_EuKAtcyKvX2itC1Y7229amh";
    let strand = "ak:strand:AWSjtu5m07wmq4GIr0siQOr8dsPMpOK3Wel8pRMGO3ZU";
    let identity = arkret_sdk::ArkretMlsIdentity::new_basic(
        crate::mls_api_helpers::principal_core_id(actor).unwrap(),
        arkret_sdk::DeviceId::new(device.to_owned()).unwrap(),
    )
    .unwrap();
    let group = identity.create_group(circle.as_bytes()).unwrap();
    let post_state = group.export_state_record().unwrap();
    let serialized = serde_json::to_vec(&post_state).unwrap();
    let secret = crate::mls::runtime::load_or_create_account_mls_secret(&secure, actor).unwrap();
    let mut salt = [0_u8; 16];
    getrandom::fill(&mut salt).unwrap();
    let snapshot = crate::mls::persistence::encrypt_state(
        realm,
        &post_state.group_id,
        post_state.epoch,
        &serialized,
        &secret,
        &salt,
    );
    let realm_identity = arkret_sdk::ArkretMlsIdentity::new_basic(
        crate::mls_api_helpers::principal_core_id(actor).unwrap(),
        arkret_sdk::DeviceId::new(device.to_owned()).unwrap(),
    )
    .unwrap();
    let realm_group = realm_identity.create_group(realm.as_bytes()).unwrap();
    let realm_state = realm_group.export_state_record().unwrap();
    let realm_serialized = serde_json::to_vec(&realm_state).unwrap();
    let mut realm_salt = [0_u8; 16];
    getrandom::fill(&mut realm_salt).unwrap();
    let realm_snapshot = crate::mls::persistence::encrypt_state(
        realm,
        &realm_state.group_id,
        realm_state.epoch,
        &realm_serialized,
        &secret,
        &realm_salt,
    );
    state
        .save_mls_snapshot(realm.to_owned(), realm_snapshot.clone())
        .unwrap();
    let binding = arkret_sdk::SidecarMlsBinding {
        sidecar_id: arkret_sdk::SidecarId::new(
            "ak:sidecar:ATob4lPqhrmzS4tLm6aZjJ77NIrYnI5OGb4qpgykXoRa".to_owned(),
        )
        .unwrap(),
        participant_authority_digest: arkret_sdk::Hash::new(format!("sha256:{}", "1".repeat(64)))
            .unwrap(),
        control_frontier: vec![
            arkret_sdk::NonEmptyString::new(
                "ak:event:AWayOxLqYDB7vOFfk4_1lduA5vDNHd7gwk_LRwQOnGDJ",
            )
            .unwrap(),
        ],
    };
    let effective_scope = arkret_sdk::ScopeRef::Sidecar {
        realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
        sidecar_id: binding.sidecar_id.clone(),
    };
    state
        .save_mls_snapshot_for_scope(&effective_scope, snapshot)
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
        binding: Some(binding),
        ready: true,
    };

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
    )
    .unwrap();

    let patch = seal_against_accepted_epoch(patch, &events);
    assert!(value_is_mls_envelope(&patch["encrypted_content"]["value"]));
    assert!(events.genesis.is_none());
    assert!(events.commit.is_none());
    assert_eq!(state.mls_snapshot_for(realm), Some(realm_snapshot));
    assert!(state.mls_snapshot_for_scope(&effective_scope).is_some());
    assert_eq!(
        state.private_plaintext_for(realm, strand, KANBAN_ENCRYPTED_CONTENT_PATH),
        Some(content_block_json("private overlay"))
    );
}
