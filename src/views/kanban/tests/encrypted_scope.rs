use super::*;

#[test]
fn encrypted_scope_blocks_plaintext_strand_update_payload() {
    let event = crate::operation::ck_ops::strand_update_patch(
        TEST_REALM_ID,
        "did:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "body": {"$op": "set", "value": "private description"},
        }),
    )
    .expect("builds")
    .build("yougen");
    let event = sdk_event(event);

    assert!(kanban_event_carries_plaintext_private_content(&event));
    let reason = kanban_plaintext_block_reason(Some(true), &event).unwrap();
    assert!(reason.contains("Encrypted Realm blocks plaintext ck.strand.update"));
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
    let private_update = crate::operation::ck_ops::strand_update_patch(
        TEST_REALM_ID,
        "did:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "body": {"$op": "set", "value": "private description"},
        }),
    )
    .expect("builds")
    .build("yougen");
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
    let board_create = crate::operation::ck_ops::space_create(
        TEST_REALM_ID,
        "did:web:alice.example",
        "ck:space:00000000-0000-7000-8000-0000000000aa",
        "board",
        "Roadmap",
        None,
        None,
    )
    .expect("builds")
    .build("yougen");
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
        "ck:device:01904100-0000-7000-8000-000000000001",
        "ck:space:0196419b-0000-7000-8000-000000000000",
        "ck:message:kanban-patch-test",
        "private synthesis",
    )
    .expect("test encryption should produce payload")
    .payload;
    let encrypted_payload = serde_json::to_value(encrypted_payload).unwrap();
    let event = crate::operation::ck_ops::strand_update_patch(
        TEST_REALM_ID,
        "did:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "synthesis": {"$op": "set", "value": encrypted_payload},
        }),
    )
    .expect("builds")
    .build("yougen");
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
        "ck:realm:01904100-0000-7000-8000-000000000001",
        "ck:strand:01904100-0000-7000-8000-0000000000ff",
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-000000000001",
        &mut state,
        &secure,
    )
    .unwrap_err();

    assert!(error.contains("MLS Welcome"));
    assert!(
        state
            .mls_snapshot_for("ck:realm:01904100-0000-7000-8000-000000000001")
            .is_none()
    );
    assert!(state.load().raw_operations.is_empty());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_private_patch_reports_unusable_pending_local_welcome() {
    use cokret_sdk::{CokretMlsIdentity, DeviceId, Did};

    let realm = "ck:realm:01904100-0000-7000-8000-000000000001";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ck:device:01904100-0000-7000-8000-0000000000b2";
    let alice = CokretMlsIdentity::new_basic(
        Did::new("did:web:alice.example".to_owned()).unwrap(),
        DeviceId::new("ck:device:01904100-0000-7000-8000-0000000000a1".to_owned()).unwrap(),
    )
    .unwrap();
    let bob = CokretMlsIdentity::new_basic(
        Did::new(bob_actor.to_owned()).unwrap(),
        DeviceId::new(bob_device.to_owned()).unwrap(),
    )
    .unwrap();
    let bob_key_package = bob.key_package_record().unwrap();
    let mut alice_group = alice.create_group(realm.as_bytes()).unwrap();
    let add = alice_group.add_member(&bob_key_package).unwrap();

    let mut state = temp_state_store("pending-local-welcome");
    state.ingest_to_device_messages(&[json!({
        "kind": "ck.mls.welcome",
        "sender_principal_id": "did:web:alice.example",
        "sender_device_id": "ck:device:01904100-0000-7000-8000-0000000000a1",
        "recipient_principal_id": bob_actor,
        "recipient_device_id": bob_device,
        "sent_at": chrono::Utc::now().to_rfc3339(),
        "expires_at": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        "content": serde_json::to_value(&add.welcome).unwrap(),
        "unsigned": {
            "mls_welcome_id": "ck:mls_welcome:01904100-0000-7000-8000-0000000000ff",
        },
    })]);
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let patch = json!({
        "body": {"$op": "set", "value": "private body from invited member"},
    });
    let strand_id = "ck:strand:01904100-0000-7000-8000-0000000000ff";

    let error = encrypt_private_card_detail_patch_values_with_store(
        patch, realm, strand_id, bob_actor, bob_device, &mut state, &secure,
    )
    .unwrap_err();

    assert!(error.contains("MLS Welcome could not be applied from local device inbox"));
    assert!(error.contains("NoMatchingKeyPackage"));
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
    use cokret_sdk::{CokretMlsIdentity, DeviceId, Did};

    let realm = "ck:realm:01904100-0000-7000-8000-000000000001";
    let bob_actor = "did:web:bob.example";
    let bob_device = "ck:device:01904100-0000-7000-8000-0000000000b3";
    let alice = CokretMlsIdentity::new_basic(
        Did::new("did:web:alice.example".to_owned()).unwrap(),
        DeviceId::new("ck:device:01904100-0000-7000-8000-0000000000a1".to_owned()).unwrap(),
    )
    .unwrap();
    let bob = CokretMlsIdentity::new_basic(
        Did::new(bob_actor.to_owned()).unwrap(),
        DeviceId::new(bob_device.to_owned()).unwrap(),
    )
    .unwrap();
    let bob_key_package = bob.key_package_record().unwrap();
    let bob_private_state = bob.export_private_state().unwrap();
    let mut alice_group = alice.create_group(realm.as_bytes()).unwrap();
    let add = alice_group.add_member(&bob_key_package).unwrap();

    let mut state = temp_state_store("pending-local-welcome-with-state");
    state.ingest_to_device_messages(&[json!({
        "kind": "ck.mls.welcome",
        "sender_principal_id": "did:web:alice.example",
        "sender_device_id": "ck:device:01904100-0000-7000-8000-0000000000a1",
        "recipient_principal_id": bob_actor,
        "recipient_device_id": bob_device,
        "sent_at": chrono::Utc::now().to_rfc3339(),
        "expires_at": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        "content": serde_json::to_value(&add.welcome).unwrap(),
        "unsigned": {
            "mls_welcome_id": "ck:mls_welcome:01904100-0000-7000-8000-0000000000f1",
            "key_package_id": bob_key_package.keypackage_id.clone(),
        },
    })]);
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
    let strand_id = "ck:strand:01904100-0000-7000-8000-0000000000ff";

    let (patched, mls_events) = encrypt_private_card_detail_patch_values_with_store(
        patch, realm, strand_id, bob_actor, bob_device, &mut state, &secure,
    )
    .unwrap();

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
    assert!(
        crate::mls::runtime::load_mls_key_package_identity_state(
            &secure,
            bob_actor,
            bob_device,
            &bob_key_package.keypackage_id,
        )
        .unwrap()
        .is_none()
    );
    assert!(mls_events.genesis.is_none());
    assert!(mls_events.commit.is_none());
    assert!(mls_events.snapshot.is_none());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_private_patch_creator_bootstraps_initial_mls_snapshot() {
    let actor = "did:web:alice.example";
    let device = "ck:device:01904100-0000-7000-8000-000000000001";
    let realm = "ck:realm:01904100-0000-7000-8000-000000000001";
    let mut state = temp_state_store("creator-bootstrap-mls");
    state.save_realm_tree_projection(
        realm,
        json!({
            "__kind": "realm",
            "owner": actor,
            "summary": {
                "title": "Encrypted Realm",
                "encryption_profile": "mls_rfc9420",
                "owner": actor,
            }
        }),
    );
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let patch = json!({
        "body": {"$op": "set", "value": "private body"},
    });

    let strand_id = "ck:strand:01904100-0000-7000-8000-0000000000ff";
    let (patched, mls_events) = encrypt_private_card_detail_patch_values_with_store(
        patch, realm, strand_id, actor, device, &mut state, &secure,
    )
    .unwrap();

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
    // ck.mls.genesis event; ordinary application writes ride epoch 0
    // without a per-write commit.
    let genesis = mls_events
        .genesis
        .expect("freshly-created creator group should emit genesis");
    assert_eq!(genesis.kind.as_str(), "ck.mls.genesis");
    assert_eq!(genesis.content["epoch"].as_u64(), Some(0));
    assert_eq!(
        genesis.content["creator_principal_id"].as_str(),
        Some(actor)
    );
    assert!(genesis.content.get("governance_binding").is_some());
    assert_registered_payload_valid(&genesis);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn encrypted_private_patch_with_ready_snapshot_replaces_plaintext() {
    use cokret_sdk::{CokretMlsIdentity, DeviceId, Did};

    let actor = "did:web:alice.example";
    let device = "ck:device:01904100-0000-7000-8000-000000000001";
    let realm = "ck:realm:01904100-0000-7000-8000-000000000001";
    let mut state = temp_state_store("ready-mls");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let secret =
        crate::mls::runtime::load_or_create_device_snapshot_secret(&secure, actor, device).unwrap();
    let identity = CokretMlsIdentity::new_basic(
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
        json!({ "active_profiles": [cokret_sdk::mls::MINIMAL_METADATA_REALM_PROFILE] }),
    );
    let base_group_state_ref = "ck:event:0196419b-0000-7000-8000-000000000010";
    state.set_realm_seal_view(
        realm,
        crate::local_state::LocalSealView {
            frontier: vec![base_group_state_ref.to_owned()],
            ..crate::local_state::LocalSealView::default()
        },
    );
    envelope.epoch_started_at = chrono::Utc::now() - chrono::Duration::hours(2);
    state.save_mls_snapshot(realm, envelope);
    let patch = json!({
        "body": {"$op": "set", "value": "private body"},
    });

    let strand_id = "ck:strand:01904100-0000-7000-8000-0000000000ff";
    let (patched, mls_events) = encrypt_private_card_detail_patch_values_with_store(
        patch, realm, strand_id, actor, device, &mut state, &secure,
    )
    .unwrap();

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
    assert_eq!(commit.kind.as_str(), "ck.mls.commit");
    assert_registered_payload_valid(&commit);
    assert!(commit.content.get("group_id").is_none());
    assert!(commit.content.get("expected_prev_epoch").is_none());
    assert!(commit.content.get("commit_bytes_b64").is_none());
    assert!(commit.content.get("preconditions").is_none());
    assert!(commit.content.get("effects").is_none());
    assert_eq!(
        commit.content["governance_binding"]["realm_id"],
        json!("ck:realm:01904100-0000-7000-8000-000000000001")
    );
    assert_eq!(
        commit.content["governance_binding"]["effective_scope"],
        json!({
            "kind": "realm",
            "realm_id": "ck:realm:01904100-0000-7000-8000-000000000001",
        })
    );
    assert_eq!(
        commit.content["governance_binding"]["membership_frontier"][0],
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
        crate::local_state::LocalSealView {
            frontier: vec!["ck:event:0196419b-0000-7000-8000-000000000099".to_owned()],
            ..crate::local_state::LocalSealView::default()
        },
    );
    let revoke_frontier =
        cokret_sdk::EventId::new("ck:event:0196419b-0000-7000-8000-000000000001".to_owned())
            .unwrap();
    let proposal_ref =
        cokret_sdk::EventId::new("ck:event:0196419b-0000-7000-8000-000000000002".to_owned())
            .unwrap();
    let commit = cokret_sdk::MlsCommitEnvelope {
        group_id: "mls-remove-group".to_owned(),
        epoch: 8,
        commit: "commit-bytes".to_owned(),
        commit_digest: cokret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
        ratchet_tree: None,
        app_state_ref: None,
    };

    let event = crate::mls::group_events::mls_remove_commit_event_from_store_for_effective_scope_with_proposal_refs(
        &state,
        TEST_REALM_ID,
        None,
        "did:web:alice.example",
        &commit,
        vec![proposal_ref],
        std::slice::from_ref(&revoke_frontier),
    )
    .unwrap();

    assert_eq!(
        event.content["governance_binding"]["membership_frontier"],
        json!([revoke_frontier.as_str()])
    );
    assert_ne!(
        event.content["governance_binding"]["membership_frontier"][0],
        json!("ck:event:0196419b-0000-7000-8000-000000000099")
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
        "ck:space:01904100-0000-7000-8000-000000000001",
        "ck:strand:01904100-0000-7000-8000-0000000000ff",
        "did:web:alice.example",
        "ck:device:01904100-0000-7000-8000-000000000001",
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
    let event = crate::operation::ck_ops::strand_position_update(
        TEST_REALM_ID,
        "did:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "board_space_id": "ck:space:0196419b-0000-7000-8000-000000000001",
            "list_space_id": "ck:space:0196419b-0000-7000-8000-000000000002",
            "rank": "U",
        }),
    )
    .expect("builds")
    .build("yougen");
    let event = sdk_event(event);

    assert_eq!(event.kind.as_str(), "ck.strand.update");
    assert!(!kanban_event_carries_plaintext_private_content(&event));
    assert!(kanban_plaintext_block_reason(Some(true), &event).is_none());
}

#[test]
fn encrypted_scope_allows_content_only_metadata_create_payloads() {
    let strand = crate::operation::ck_ops::kanban_card_strand_create(
        TEST_REALM_ID,
        "did:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        "ck:space:0196419b-0000-7000-8000-000000000001",
        "ck:space:0196419b-0000-7000-8000-000000000002",
        "private card title",
        "U",
    )
    .expect("builds")
    .build("yougen");
    let strand = sdk_event(strand);
    let space = crate::operation::ck_ops::space_create(
        TEST_REALM_ID,
        "did:web:alice.example",
        "ck:space:0196419b-0000-7000-8000-000000000002",
        "list",
        "private list title",
        Some("ck:space:0196419b-0000-7000-8000-000000000001"),
        Some("U"),
    )
    .expect("builds")
    .build("yougen");
    let space = sdk_event(space);

    assert!(kanban_plaintext_block_reason(Some(true), &strand).is_none());
    assert!(kanban_plaintext_block_reason(Some(true), &space).is_none());
}

/// X13 regression: in an encrypted scope, container creation/update
/// (`ck.space.create` for BOTH board and list, plus `ck.space.update` rank
/// patches) MUST NOT be blocked — title/kind/parent/rank are non-secret
/// metadata that has to reach the server so a second device can render the real
/// Board/List name and order. By contrast a `ck.strand.update` carrying
/// plaintext private body MUST stay blocked (only E2EE may leave the client for
/// that field).
#[test]
fn encrypted_scope_never_blocks_container_metadata_but_blocks_plaintext_private_content() {
    let board = crate::operation::ck_ops::space_create(
        TEST_REALM_ID,
        "did:web:alice.example",
        "ck:space:0196419b-0000-7000-8000-00000000aa01",
        "board",
        "ZZTEST board title",
        None,
        None,
    )
    .expect("builds")
    .build("yougen");
    let board = sdk_event(board);
    assert_eq!(board.kind.as_str(), "ck.space.create");
    assert!(
        kanban_plaintext_block_reason(Some(true), &board).is_none(),
        "encrypted scope must not block board container create"
    );

    let list = crate::operation::ck_ops::space_create(
        TEST_REALM_ID,
        "did:web:alice.example",
        "ck:space:0196419b-0000-7000-8000-00000000aa02",
        "list",
        "Todos list title",
        Some("ck:space:0196419b-0000-7000-8000-00000000aa01"),
        Some("r001"),
    )
    .expect("builds")
    .build("yougen");
    let list = sdk_event(list);
    assert_eq!(list.kind.as_str(), "ck.space.create");
    assert!(
        kanban_plaintext_block_reason(Some(true), &list).is_none(),
        "encrypted scope must not block list container create"
    );

    let list_rank_update = crate::operation::ck_ops::space_update_patch(
        TEST_REALM_ID,
        "did:web:alice.example",
        "ck:space:0196419b-0000-7000-8000-00000000aa02",
        json!({ "rank": "r000" }),
    )
    .expect("builds")
    .build("yougen");
    let list_rank_update = sdk_event(list_rank_update);
    assert_eq!(list_rank_update.kind.as_str(), "ck.space.update");
    assert!(
        kanban_plaintext_block_reason(Some(true), &list_rank_update).is_none(),
        "encrypted scope must not block list rank update"
    );

    // Counter-case: plaintext private body in a strand update is still blocked.
    let private_update = crate::operation::ck_ops::strand_update_patch(
        TEST_REALM_ID,
        "did:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "body": {"$op": "set", "value": "private description"},
        }),
    )
    .expect("builds")
    .build("yougen");
    let private_update = sdk_event(private_update);
    assert!(
        kanban_plaintext_block_reason(Some(true), &private_update).is_some(),
        "encrypted scope must still block plaintext private strand content"
    );
}

#[test]
fn encrypted_scope_allows_strand_summary_metadata_update() {
    let event = crate::operation::ck_ops::strand_update_patch(
        TEST_REALM_ID,
        "did:web:alice.example",
        DEMO_STRAND_LEGAL_REVIEW_ID,
        json!({
            "summary": {"$op": "set", "value": "metadata summary"},
        }),
    )
    .expect("builds")
    .build("yougen");
    let event = sdk_event(event);

    assert!(!kanban_event_carries_plaintext_private_content(&event));
    assert!(kanban_plaintext_block_reason(Some(true), &event).is_none());
}
