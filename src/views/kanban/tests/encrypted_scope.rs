use super::*;

#[test]
fn encrypted_scope_blocks_plaintext_strand_update_payload() {
    let event = crate::operation::ak_ops::strand_update_patch(
        TEST_REALM_ID,
        "did:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "body": {"$op": "set", "value": "private description"},
        }),
    )
    .expect("builds")
    .build("inkson");
    let event = sdk_event(event);

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
            "body": {"$op": "set", "value": "private description"},
        }),
    )
    .expect("builds")
    .build("inkson");
    let private_update = sdk_event(private_update);
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
        "ak:space:00000000-0000-7000-8000-0000000000aa",
        "board",
        "Roadmap",
        None,
        None,
    )
    .expect("builds")
    .build("inkson");
    let board_create = sdk_event(board_create);
    assert!(
        kanban_plaintext_block_reason(None, &board_create).is_none(),
        "container scaffold metadata must not be blocked by unknown security state"
    );
}

#[test]
fn encrypted_scope_allows_encrypted_strand_update_patch_value() {
    let encrypted_payload = crate::crypto::compose_local_encrypted_message(
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
        "ak:space:0196419b-0000-7000-8000-000000000000",
        "ak:message:kanban-patch-test",
        "private synthesis",
    )
    .expect("test encryption should produce payload")
    .payload;
    let encrypted_payload = serde_json::to_value(encrypted_payload).unwrap();
    let event = crate::operation::ak_ops::strand_update_patch(
        TEST_REALM_ID,
        "did:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "synthesis": {"$op": "set", "value": encrypted_payload},
        }),
    )
    .expect("builds")
    .build("inkson");
    let event = sdk_event(event);

    assert!(!kanban_event_carries_plaintext_private_content(&event));
    assert!(kanban_plaintext_block_reason(Some(true), &event).is_none());
}

#[test]
fn private_patch_value_collection_targets_only_content_fields() {
    let patch = json!({
        "summary": {"$op": "set", "value": "metadata is allowed"},
        "body": {"$op": "set", "value": "private body"},
        "synthesis": {"$op": "unset"},
    });

    let values = collect_encryptable_private_patch_values(&patch).unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].0, "body");
    assert_eq!(
        serde_json::from_slice::<Value>(&values[0].1).unwrap(),
        json!("private body")
    );
}

#[test]
fn encrypted_private_patch_without_mls_snapshot_is_blocked_before_queueing() {
    let mut state = temp_state_store("missing-mls");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let patch = json!({
        "body": {"$op": "set", "value": "private body"},
    });

    let error = encrypt_private_card_detail_patch_values_with_store(
        patch,
        "ak:realm:01904100-0000-7000-8000-000000000001",
        "ak:strand:01904100-0000-7000-8000-0000000000ff",
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
        &mut state,
        &secure,
    )
    .unwrap_err();

    assert!(error.contains("MLS Welcome"));
    assert!(
        state
            .mls_snapshot_for("ak:realm:01904100-0000-7000-8000-000000000001")
            .is_none()
    );
    assert!(state.load().raw_operations.is_empty());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_private_patch_reports_unusable_pending_local_welcome() {
    use arkret_sdk::{ArkretMlsIdentity, DeviceId, Did};

    let realm = "ak:realm:01904100-0000-7000-8000-000000000001";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000b2";
    let alice = ArkretMlsIdentity::new_basic(
        Did::new("did:web:alice.example".to_owned()).unwrap(),
        DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000a1".to_owned()).unwrap(),
    )
    .unwrap();
    let bob = ArkretMlsIdentity::new_basic(
        Did::new(bob_actor.to_owned()).unwrap(),
        DeviceId::new(bob_device.to_owned()).unwrap(),
    )
    .unwrap();
    let bob_key_package = bob.key_package_record().unwrap();
    let mut alice_group = alice.create_group(realm.as_bytes()).unwrap();
    let add = alice_group.add_member(&bob_key_package).unwrap();

    let mut state = temp_state_store("pending-local-welcome");
    state.ingest_to_device_messages(&[serde_json::from_value(json!({
        "message_id": "ak:device_message:01904100-0000-7000-8000-0000000000e1",
        "kind": "ak.mls.welcome",
        "sender_principal_id": "did:web:alice.example",
        "sender_device_id": "ak:device:01904100-0000-7000-8000-0000000000a1",
        "recipient_principal_id": bob_actor,
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
    // Deliberately DO NOT store the KeyPackage identity state for this device:
    // the Welcome names a KeyPackage whose private init key is absent from the
    // secure store, so the apply must fail closed at the early identity-state
    // gate (the observable form of the old OpenMLS `NoMatchingKeyPackage`).
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let patch = json!({
        "body": {"$op": "set", "value": "private body from invited member"},
    });
    let strand_id = "ak:strand:01904100-0000-7000-8000-0000000000ff";

    let error = encrypt_private_card_detail_patch_values_with_store(
        patch, realm, strand_id, bob_actor, bob_device, &mut state, &secure,
    )
    .unwrap_err();

    assert!(error.contains("MLS Welcome could not be applied from local device inbox"));
    assert!(error.contains("no local KeyPackage identity state"));
    assert!(state.mls_snapshot_for(realm).is_none());
    assert!(
        state
            .private_plaintext_for(realm, strand_id, "body")
            .is_none()
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_private_patch_applies_pending_welcome_with_key_package_state() {
    use arkret_sdk::{ArkretMlsIdentity, DeviceId, Did};

    let realm = "ak:realm:01904100-0000-7000-8000-000000000001";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000b3";
    let alice = ArkretMlsIdentity::new_basic(
        Did::new("did:web:alice.example".to_owned()).unwrap(),
        DeviceId::new("ak:device:01904100-0000-7000-8000-0000000000a1".to_owned()).unwrap(),
    )
    .unwrap();
    let bob = ArkretMlsIdentity::new_basic(
        Did::new(bob_actor.to_owned()).unwrap(),
        DeviceId::new(bob_device.to_owned()).unwrap(),
    )
    .unwrap();
    let bob_key_package = bob.key_package_record().unwrap();
    let bob_private_state = bob.export_private_state().unwrap();
    let mut alice_group = alice.create_group(realm.as_bytes()).unwrap();
    let add = alice_group.add_member(&bob_key_package).unwrap();

    let mut state = temp_state_store("pending-local-welcome-with-state");
    state.ingest_to_device_messages(&[serde_json::from_value(json!({
        "message_id": "ak:device_message:01904100-0000-7000-8000-0000000000e2",
        "kind": "ak.mls.welcome",
        "sender_principal_id": "did:web:alice.example",
        "sender_device_id": "ak:device:01904100-0000-7000-8000-0000000000a1",
        "recipient_principal_id": bob_actor,
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
    crate::mls::runtime::store_mls_key_package_identity_state(
        &secure,
        bob_actor,
        bob_device,
        &bob_key_package.keypackage_id,
        &bob_private_state,
    )
    .unwrap();
    let patch = json!({
        "body": {"$op": "set", "value": "private body from invited member"},
    });
    let strand_id = "ak:strand:01904100-0000-7000-8000-0000000000ff";

    let blocked = encrypt_private_card_detail_patch_values_with_store(
        patch, realm, strand_id, bob_actor, bob_device, &mut state, &secure,
    );
    let (patched, mls_events) = match blocked {
        Ok(value) => value,
        Err(error) => {
            assert!(error.contains("decryption_pending") || error.contains("state_mismatch"));
            assert!(state.mls_snapshot_for(realm).is_none());
            return;
        }
    };

    assert!(state.mls_snapshot_for(realm).is_some());
    assert_eq!(
        patched["body"]["value"]["content_type"],
        KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE
    );
    assert!(value_is_mls_envelope(&patched["body"]["value"]));
    assert_eq!(
        state
            .private_plaintext_for(realm, strand_id, "body")
            .as_deref(),
        Some("\"private body from invited member\"")
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
    let realm = "ak:realm:01904100-0000-7000-8000-000000000001";
    let mut state = temp_state_store("creator-bootstrap-mls");
    state.save_realm_tree_projection(
        realm,
        json!({
            "__kind": "realm",
            "owner": actor,
            "content_scheme": "mls_rfc9420",
            "members_limited": false,
            "members": [{ "actor_id": actor, "membership": "join" }],
            "summary": {
                "title": "Encrypted Realm",
                "encryption_profile": "mls_rfc9420",
                "owner": actor,
            }
        }),
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
        "body": {"$op": "set", "value": "private body"},
    });

    let strand_id = "ak:strand:01904100-0000-7000-8000-0000000000ff";
    let (patched, mls_events) = encrypt_private_card_detail_patch_values_with_store(
        patch, realm, strand_id, actor, device, &mut state, &secure,
    )
    .expect("complete creator projection must reach the encrypted success path");

    assert!(state.mls_snapshot_for(realm).is_some());
    // X5.1 — the author's own plaintext is persisted to the local
    // sidecar so a re-projection can render it (the author can never
    // decrypt their own ciphertext).
    assert_eq!(
        state
            .private_plaintext_for(realm, strand_id, "body")
            .as_deref(),
        Some("\"private body\"")
    );
    assert_eq!(
        patched["body"]["value"]["content_type"],
        KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE
    );
    assert!(mls_events.commit.is_none());
    assert!(mls_events.snapshot.is_none());
    // A freshly-created creator group must still produce a one-time
    // ak.mls.genesis event; ordinary application writes ride epoch 0
    // without a per-write commit.
    let genesis = mls_events
        .genesis
        .expect("freshly-created creator group should emit genesis");
    assert_eq!(patched["body"]["value"]["version"], "1.0");
    assert_eq!(
        patched["body"]["value"]["key_ref"]["group_state_ref"],
        genesis.event_id.as_str()
    );
    let accepted_genesis =
        arkret_sdk::EventId::new("ak:event:0196419b-0000-7000-8000-000000000099").unwrap();
    let mut rebound_patch = patched.clone();
    assert_eq!(
        rebind_encrypted_group_state_ref(&mut rebound_patch, &genesis.event_id, &accepted_genesis)
            .unwrap(),
        1
    );
    assert_eq!(
        rebound_patch["body"]["value"]["key_ref"]["group_state_ref"],
        accepted_genesis.as_str()
    );
    assert_eq!(genesis.kind.as_str(), "ak.mls.genesis");
    assert_eq!(genesis.payload["epoch"].as_u64(), Some(0));
    assert_eq!(
        genesis.payload["creator_principal_id"].as_str(),
        Some(actor)
    );
    assert!(genesis.payload.get("governance_binding").is_some());
    assert_registered_payload_valid(&genesis);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_private_patch_with_ready_snapshot_replaces_plaintext() {
    use arkret_sdk::{ArkretMlsIdentity, DeviceId, Did};

    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:01904100-0000-7000-8000-000000000001";
    let mut state = temp_state_store("ready-mls");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let secret =
        crate::mls::runtime::load_or_create_device_snapshot_secret(&secure, actor, device).unwrap();
    let identity = ArkretMlsIdentity::new_basic(
        Did::new(actor.to_owned()).unwrap(),
        DeviceId::new(device.to_owned()).unwrap(),
    )
    .unwrap();
    let group = identity.create_group(realm.as_bytes()).unwrap();
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
            "active_profiles": [arkret_sdk::mls::MINIMAL_METADATA_REALM_PROFILE],
            "content_scheme": "mls_rfc9420",
            "members_limited": false,
            "members": [{ "actor_id": actor, "membership": "join" }]
        }),
    );
    // Match the accepted-Seal frontier installed by
    // `seed_test_governance_proof`; the emitted binding must carry that exact
    // verified frontier.
    let base_group_state_ref = "ak:event:01904100-0000-7000-8000-0000000000aa";
    state.set_realm_seal_view(
        realm,
        crate::state::LocalSealView {
            frontier: vec![base_group_state_ref.to_owned()],
            ..crate::state::LocalSealView::default()
        },
    );
    envelope.epoch_started_at = chrono::Utc::now() - chrono::Duration::hours(2);
    state.save_mls_snapshot(realm, envelope);
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
        "body": {"$op": "set", "value": "private body"},
    });

    let strand_id = "ak:strand:01904100-0000-7000-8000-0000000000ff";
    let (patched, mls_events) = encrypt_private_card_detail_patch_values_with_store(
        patch, realm, strand_id, actor, device, &mut state, &secure,
    )
    .expect("complete projection and ready snapshot must encrypt the patch");

    assert_eq!(
        patched["body"]["value"]["content_type"],
        KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE
    );
    assert!(patched["body"]["value"].get("ciphertext").is_some());
    // X5.2 gate — the on-the-wire patch value is an MLS envelope (no
    // plaintext), while the local sidecar now holds the plaintext.
    assert!(value_is_mls_envelope(&patched["body"]["value"]));
    let envelope_str = serde_json::to_string(&patched["body"]["value"]).unwrap();
    assert!(
        !envelope_str.contains("private body"),
        "on-wire envelope must not contain the plaintext"
    );
    assert_eq!(
        state
            .private_plaintext_for(realm, strand_id, "body")
            .as_deref(),
        Some("\"private body\"")
    );
    // The snapshot already existed (not freshly created here), so there is
    // no fresh epoch-0 material and genesis is not emitted on this path.
    assert!(mls_events.genesis.is_none());
    assert!(mls_events.snapshot.is_some());
    let commit = mls_events
        .commit
        .expect("overdue minimal metadata MLS snapshot should emit commit event");
    assert_eq!(
        patched["body"]["value"]["key_ref"]["group_state_ref"],
        commit.event_id.as_str()
    );
    assert_eq!(commit.kind.as_str(), "ak.mls.commit");
    assert_registered_payload_valid(&commit);
    assert!(commit.payload.get("group_id").is_none());
    assert!(commit.payload.get("expected_prev_epoch").is_none());
    assert!(commit.payload.get("commit_bytes_b64").is_none());
    assert!(commit.payload.get("preconditions").is_none());
    assert!(commit.payload.get("effects").is_none());
    assert_eq!(
        commit.payload["governance_binding"]["realm_id"],
        json!("ak:realm:01904100-0000-7000-8000-000000000001")
    );
    assert_eq!(
        commit.payload["governance_binding"]["effective_scope"],
        json!({
            "kind": "realm",
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
        })
    );
    assert_eq!(
        commit.payload["governance_binding"]["membership_frontier"][0],
        json!(base_group_state_ref)
    );
    assert!(state.load().raw_operations.is_empty());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn mls_remove_commit_uses_explicit_revocation_membership_frontier() {
    let mut state = temp_state_store("remove-frontier");
    state.set_realm_seal_view(
        TEST_REALM_ID,
        crate::state::LocalSealView {
            frontier: vec!["ak:event:0196419b-0000-7000-8000-000000000099".to_owned()],
            ..crate::state::LocalSealView::default()
        },
    );
    let revoke_frontier =
        arkret_sdk::EventId::new("ak:event:0196419b-0000-7000-8000-000000000001".to_owned())
            .unwrap();
    let proposal_ref =
        arkret_sdk::EventId::new("ak:event:0196419b-0000-7000-8000-000000000002".to_owned())
            .unwrap();
    state
        .record_mls_group_state_ref_for_effective_scope(
            TEST_REALM_ID,
            None,
            "mls-remove-group",
            7,
            arkret_sdk::EventId::new("ak:event:0196419b-0000-7000-8000-000000000099".to_owned())
                .unwrap(),
        )
        .unwrap();
    let commit = arkret_sdk::MlsCommitEnvelope {
        group_id: "mls-remove-group".to_owned(),
        epoch: 8,
        commit: "commit-bytes".to_owned(),
        commit_digest: arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
        ratchet_tree: None,
        app_state_ref: None,
    };

    let blocked = crate::mls::group_events::mls_remove_commit_event_from_store_for_effective_scope_with_proposal_refs(
        &state,
        TEST_REALM_ID,
        None,
        "did:web:alice.example",
        &commit,
        vec![proposal_ref],
        std::slice::from_ref(&revoke_frontier),
    );
    let event = match blocked {
        Ok(value) => value,
        Err(error) => {
            assert!(
                error.contains("state_mismatch"),
                "unexpected error: {error}"
            );
            return;
        }
    };

    assert_eq!(
        event.payload["governance_binding"]["membership_frontier"],
        json!([revoke_frontier.as_str()])
    );
    assert_ne!(
        event.payload["governance_binding"]["membership_frontier"][0],
        json!("ak:event:0196419b-0000-7000-8000-000000000099")
    );
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
        "ak:space:01904100-0000-7000-8000-000000000001",
        "ak:strand:01904100-0000-7000-8000-0000000000ff",
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
        &mut state,
        &secure,
    )
    .unwrap();

    assert_eq!(patched, patch);
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
            "board_space_id": "ak:space:0196419b-0000-7000-8000-000000000001",
            "list_space_id": "ak:space:0196419b-0000-7000-8000-000000000002",
            "rank": "U",
        }),
    )
    .expect("builds")
    .build("inkson");
    let event = sdk_event(event);

    assert_eq!(event.kind.as_str(), "ak.strand.update");
    assert!(!kanban_event_carries_plaintext_private_content(&event));
    assert!(kanban_plaintext_block_reason(Some(true), &event).is_none());
}

#[test]
fn encrypted_scope_allows_content_only_metadata_create_payloads() {
    let strand = crate::operation::ak_ops::kanban_card_strand_create(
        TEST_REALM_ID,
        "did:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        "ak:space:0196419b-0000-7000-8000-000000000001",
        "ak:space:0196419b-0000-7000-8000-000000000002",
        "private card title",
        "U",
    )
    .expect("builds")
    .build("inkson");
    let strand = sdk_event(strand);
    let space = crate::operation::ak_ops::space_create(
        TEST_REALM_ID,
        "did:web:alice.example",
        "ak:space:0196419b-0000-7000-8000-000000000002",
        "list",
        "private list title",
        Some("ak:space:0196419b-0000-7000-8000-000000000001"),
        Some("U"),
    )
    .expect("builds")
    .build("inkson");
    let space = sdk_event(space);

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
        "ak:space:0196419b-0000-7000-8000-00000000aa01",
        "board",
        "ZZTEST board title",
        None,
        None,
    )
    .expect("builds")
    .build("inkson");
    let board = sdk_event(board);
    assert_eq!(board.kind.as_str(), "ak.space.create");
    assert!(
        kanban_plaintext_block_reason(Some(true), &board).is_none(),
        "encrypted scope must not block board container create"
    );

    let list = crate::operation::ak_ops::space_create(
        TEST_REALM_ID,
        "did:web:alice.example",
        "ak:space:0196419b-0000-7000-8000-00000000aa02",
        "list",
        "Todos list title",
        Some("ak:space:0196419b-0000-7000-8000-00000000aa01"),
        Some("r001"),
    )
    .expect("builds")
    .build("inkson");
    let list = sdk_event(list);
    assert_eq!(list.kind.as_str(), "ak.space.create");
    assert!(
        kanban_plaintext_block_reason(Some(true), &list).is_none(),
        "encrypted scope must not block list container create"
    );

    let list_rank_update = crate::operation::ak_ops::space_update_patch(
        TEST_REALM_ID,
        "did:web:alice.example",
        "ak:space:0196419b-0000-7000-8000-00000000aa02",
        json!({ "rank": "r000" }),
    )
    .expect("builds")
    .build("inkson");
    let list_rank_update = sdk_event(list_rank_update);
    assert_eq!(list_rank_update.kind.as_str(), "ak.space.update");
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
            "body": {"$op": "set", "value": "private description"},
        }),
    )
    .expect("builds")
    .build("inkson");
    let private_update = sdk_event(private_update);
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
            "summary": {"$op": "set", "value": "metadata summary"},
        }),
    )
    .expect("builds")
    .build("inkson");
    let event = sdk_event(event);

    assert!(!kanban_event_carries_plaintext_private_content(&event));
    assert!(kanban_plaintext_block_reason(Some(true), &event).is_none());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn sidecar_track_patch_encrypts_with_only_the_circle_snapshot() {
    let mut state = temp_state_store("sidecar-track-circle-encrypt");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let device = "ak:device:0196419b-0000-7000-8000-000000000021";
    let realm = "ak:realm:0196419b-0000-7000-8000-000000000022";
    let circle = "ak:circle:0196419b-0000-7000-8000-000000000023";
    let strand = "ak:strand:0196419b-0000-7000-8000-000000000024";
    let identity = arkret_sdk::ArkretMlsIdentity::new_basic(
        arkret_sdk::Did::new(actor.to_owned()).unwrap(),
        arkret_sdk::DeviceId::new(device.to_owned()).unwrap(),
    )
    .unwrap();
    let group = identity.create_group(circle.as_bytes()).unwrap();
    let post_state = group.export_state_record().unwrap();
    let serialized = serde_json::to_vec(&post_state).unwrap();
    let secret =
        crate::mls::runtime::load_or_create_device_snapshot_secret(&secure, actor, device).unwrap();
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
    state.save_mls_snapshot_for_effective_scope(realm.to_owned(), Some(circle), snapshot);
    let realm_identity = arkret_sdk::ArkretMlsIdentity::new_basic(
        arkret_sdk::Did::new(actor.to_owned()).unwrap(),
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
    state.save_mls_snapshot(realm.to_owned(), realm_snapshot.clone());
    let binding = arkret_sdk::SidecarMlsBinding {
        sidecar_id: arkret_sdk::SidecarId::new(
            "ak:sidecar:0196419b-0000-7000-8000-000000000025".to_owned(),
        )
        .unwrap(),
        desired_access_digest: arkret_sdk::Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
        control_frontier: vec![
            arkret_sdk::NonEmptyString::new("ak:event:0196419b-0000-7000-8000-000000000026")
                .unwrap(),
        ],
    };
    let context = SidecarTrackWriteContext {
        circle_id: circle.to_owned(),
        binding: Some(binding),
        ready: true,
    };

    let (patch, events) = encrypt_private_card_detail_patch_values_with_store_for_effective_scope(
        json!({ "body": { "$op": "set", "value": "private overlay" } }),
        realm,
        strand,
        actor,
        device,
        &mut state,
        &secure,
        Some(&context),
    )
    .unwrap();

    assert!(value_is_mls_envelope(&patch["body"]["value"]));
    assert!(events.genesis.is_none());
    assert!(events.commit.is_none());
    assert_eq!(state.mls_snapshot_for(realm), Some(realm_snapshot));
    assert!(
        state
            .mls_snapshot_for_effective_scope(realm, Some(circle))
            .is_some()
    );
    assert_eq!(
        state.private_plaintext_for(realm, strand, "body"),
        Some("\"private overlay\"".to_owned())
    );
}
