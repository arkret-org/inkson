use serde_json::json;

use super::*;

#[test]
fn sealed_command_requires_its_exact_unit_to_be_committed() {
    let first = arkret_sdk::Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap();
    let member = arkret_sdk::Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap();
    let absent = arkret_sdk::Hash::new(format!("sha256:{}", "33".repeat(32))).unwrap();
    let committed = arkret_sdk::SealCommandOutcome::committed(
        first.clone(),
        vec![first.clone(), member.clone()],
        vec![],
        arkret_sdk::DigestSuite::Sha256,
    )
    .unwrap();
    assert!(require_committed_unit_result(std::slice::from_ref(&committed), &member).is_ok());
    assert!(require_committed_unit_result(std::slice::from_ref(&committed), &absent).is_err());
    assert!(require_committed_unit_result(&[committed.clone(), committed], &member).is_err());
    let rejected = arkret_sdk::SealCommandOutcome::rejected(
        first.clone(),
        vec![first, member.clone()],
        arkret_sdk::ReasonCode::ActorSignatureRevoked,
        arkret_sdk::DigestSuite::Sha256,
    )
    .unwrap();
    assert!(require_committed_unit_result(&[rejected], &member).is_err());
}

#[test]
fn recovery_gate_cache_key_normalizes_full_and_core_principal_ids() {
    let device_id = "ak:device:01964137-0000-7000-8000-0000000000a1";
    assert_eq!(
        normalized_recovery_gate_cache_key("did:web:alice.example", device_id),
        normalized_recovery_gate_cache_key("ak:did_core:web:alice.example", device_id)
    );
}

fn decode_queued_sdk_event(value: Value) -> garth::Result<QueuedSdkEvent> {
    let queued: QueuedSdkEvent = serde_json::from_value(value)?;
    queued.validate()?;
    Ok(queued)
}

fn test_authoring_generation() -> crate::identity::authoring_generation::AuthoringGeneration {
    crate::identity::authoring_generation::AuthoringGeneration {
        authority_model:
            crate::identity::authoring_generation::AuthoringAuthorityModel::AcceptedDevice,
        authority_principal_id: arkret_sdk::DidCoreId::new(
            "ak:did_core:web:alice.example".to_owned(),
        )
        .unwrap(),
        generation_ref: "1-QmCurrent".to_owned(),
    }
}

fn fixture_event_id(event_id: &str) -> arkret_sdk::EventId {
    arkret_sdk::EventId::new(event_id).unwrap()
}

/// A locally built write, as an intent.
///
/// The fixture cannot invent an `event_id`, an `actor_seq` or an HLC because
/// an intent has nowhere to put them: they belong to authoring, which has
/// not happened yet.
fn sdk_intent_with_kind(realm_id: &str, kind: &str, actor_id: &str) -> EventIntent {
    let actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        crate::mls_api_helpers::principal_core_id(actor_id).unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
    ));
    serde_json::from_value(json!({
        "kind": kind,
        "scope_ref": {"kind": "realm", "realm_id": realm_id},
        "actor_id": actor_id,
        "created_at": "2026-05-19T00:00:00.000Z",
        "payload": {}
    }))
    .unwrap()
}

/// The queue slot a locally built write occupies.
fn fixture_queued_intent(intent: EventIntent) -> QueuedEventIntent {
    QueuedEventIntent::new(intent, arkret_sdk::DigestSuite::Sha256)
}

#[test]
fn account_authority_client_allows_only_insecure_loopback() {
    assert!(account_authority_http_client("http://localhost:8787").is_ok());
    assert!(account_authority_http_client("http://127.0.0.1:8787").is_ok());
    assert!(account_authority_http_client("http://accounts.example").is_err());
}

#[test]
fn agent_pcr_genesis_does_not_bypass_control_proposal_ack_authoring() {
    let mut managed = realm_create_sdk_event(
        "ak:event:Af2HCFbsrVezIXsZGcgB3mjkpqGK-C4DmteWaG3H0Xbh",
        "did:web:agent.example",
    );
    managed.executed_by = Some(
        crate::mls_api_helpers::local_account_actor_id("ak:did_core:web:alice.example").unwrap(),
    );
    managed.authorization_ref = Some(
        arkret_sdk::AuthorizationRef::new("did:web:agent.example#managed-controller").unwrap(),
    );

    assert!(crate::authorization_lease::is_agent_pcr_genesis(&managed));
    assert!(!uses_bare_online_anchor_submission(true, &managed));

    let ordinary = realm_create_sdk_event(
        "ak:event:Ab0jbIKlPZ-M3WbarZlCPLYtkCWggYwWZeRDlW-ShdQ9",
        "did:web:alice.example",
    );
    assert!(uses_bare_online_anchor_submission(true, &ordinary));
}

#[test]
fn queued_event_rejects_pre_generation_shape() {
    let event = sdk_event_without_proof("did:web:alice.example");
    let mut encoded = serde_json::to_value(
        QueuedSdkEvent::unauthored(
            fixture_queued_intent(EventIntent::from_authored(&event)),
            "local-operation-1".to_owned(),
            "attempt-1".to_owned(),
            None,
            test_authoring_generation(),
            None,
        )
        .unwrap(),
    )
    .unwrap();
    encoded
        .as_object_mut()
        .unwrap()
        .remove("authoring_generation");
    let error = decode_queued_sdk_event(encoded).unwrap_err();
    assert!(error.to_string().contains("authoring_generation"));
}

#[test]
fn durable_sent_item_repairs_optimistic_operation_by_local_id() {
    let local_operation_id = "0196419b-0000-7000-8000-000000000001";
    let remote_event_id = fixture_event_id("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19");
    let realm_id = arkret_sdk::RealmId::new(
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
    )
    .unwrap();
    let intent = EventIntent::from_authored(&sdk_event_without_proof("did:web:alice.example"));
    let queued = QueuedSdkEvent::unauthored(
        fixture_queued_intent(intent),
        local_operation_id.to_owned(),
        "immutable-attempt-id".to_owned(),
        None,
        test_authoring_generation(),
        None,
    )
    .unwrap();
    let mut queue = garth::SendQueue::new();
    let mut sent = queue
        .enqueue(
            Some("immutable-attempt-id".to_owned()),
            realm_id,
            QueuedRecord::SdkEvent(Box::new(queued)),
            Vec::new(),
            chrono::Utc::now(),
        )
        .unwrap();
    // A frontier re-author can change the queue transaction id, but the holder-local
    // operation id remains the join key for the optimistic row.
    sent.local_operation_id = local_operation_id.to_owned();
    sent.status = garth::SendQueueStatus::Sent;
    sent.remote_event_id = Some(remote_event_id.clone());

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "inkson-event-submit-receipt-reconcile-{stamp}.json"
    ));
    let mut store = crate::state::LocalStateStore::with_path(path);
    store.upsert_raw_operation(
        local_operation_id,
        None,
        json!({"kind": "ak.strand.create", "write_state": "queued"}),
    );

    assert!(reconcile_sent_outbound_item(&mut store, &sent));
    let state = store.load();
    let operation = state
        .raw_operations
        .iter()
        .find(|operation| operation.operation_id == local_operation_id)
        .expect("optimistic operation remains addressable by its local id");
    assert_eq!(operation.payload["write_state"], "accepted");
    assert_eq!(operation.payload["event_id"], remote_event_id.as_str());
}

#[test]
fn scheduled_dispatch_crash_retry_preserves_exact_signed_event_bytes() {
    let event: arkret_sdk::Event = serde_json::from_value(json!({
        "event_id": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "kind": "ak.message.create",
        "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "scope_ref": {
            "kind": "realm",
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
        },
        "actor_id": {
            "kind": "account",
            "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:principal.example"
            }
        },
        "actor_seq": 7,
        "created_at": "2026-08-07T00:00:00.000Z",
        "hlc": "01986f440000-0001-a13f9c2e",
        "prev_refs": [],
        "payload": {
            "strand_id": "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "body": "frozen scheduled text"}
        },
        "proofs": []
    }))
    .unwrap();
    // The scheduler stores exact authored bytes, so the fixture has to reach
    // it the way production does: finalized, then signed.
    let mut event = arkret_sdk::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_sdk::canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let signer = crate::event_signer::build_ed25519_device_signer(
        [73; 32],
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
    );
    signer
        .sign_sdk_event_with_context(
            &mut event,
            crate::event_signer::test_producer_proof_context(arkret_sdk::DigestSuite::Sha256),
        )
        .unwrap();

    let scheduled_send_id = arkret_identifiers::ScheduledSendId::new(
        "ak:scheduled_send:01904100-0000-7000-8000-000000000003".to_owned(),
    )
    .unwrap();
    let queued = QueuedSdkEvent::scheduled_authored(
        scheduled_send_id.clone(),
        event.clone(),
        test_authoring_generation(),
    )
    .unwrap();
    let frozen_bytes = queued
        .scheduled_dispatch
        .as_ref()
        .unwrap()
        .canonical_signed_event_bytes
        .clone();

    // Simulate the durable record being reopened after scheduler handoff.
    let persisted = serde_json::to_value(&queued).unwrap();
    let mut reopened = decode_queued_sdk_event(persisted).unwrap();
    assert!(reopened.mark_scheduled_submission_uncertain());

    // The Prepared outcome is persisted before HTTP. A crash with an
    // unknown submission result reopens this exact record, and a retry may
    // not transition or author it again.
    let prepared = serde_json::to_value(&reopened).unwrap();
    let mut retry = decode_queued_sdk_event(prepared).unwrap();
    assert!(!retry.mark_scheduled_submission_uncertain());
    let dispatch = retry.scheduled_dispatch.as_ref().unwrap();
    assert_eq!(dispatch.scheduled_send_id, scheduled_send_id);
    assert_eq!(&dispatch.event_id, event.event_id());
    assert_eq!(
        dispatch.message_id,
        arkret_sdk::MessageId::from_event_id(event.event_id())
    );
    assert_eq!(
        dispatch.submission_state,
        ScheduledSendSubmissionState::SubmissionUncertain
    );
    assert_eq!(dispatch.canonical_signed_event_bytes, frozen_bytes);
    assert_eq!(
        retry
            .authored_attempt
            .as_ref()
            .unwrap()
            .canonical_body_bytes,
        frozen_bytes
    );
}

/// Every retry re-reads the authoring position and mints a fresh transport
/// key, so neither may move the queue slot's semantic identity.
#[test]
fn queued_intent_survives_a_reauthored_attempt_at_a_new_chain_position() {
    let intent = EventIntent::from_authored(&sdk_event_without_proof("did:web:alice.example"));
    let queued = fixture_queued_intent(intent.clone());

    let first = intent
        .clone()
        .author_with_digest_suite(
            1,
            crate::operation::test_authoring_hlc_at_seq(1),
            arkret_sdk::DigestSuite::Sha256,
        )
        .unwrap();
    let mut second = intent
        .with_prev_refs(vec![fixture_event_id(
            "ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk",
        )])
        .author_with_digest_suite(
            42,
            crate::operation::test_authoring_hlc_at_seq(42),
            arkret_sdk::DigestSuite::Sha256,
        )
        .unwrap();
    second.insert_unsigned(
        crate::operation::LOCAL_OPERATION_IDEMPOTENCY_ALIAS,
        Value::String("attempt-two".to_owned()),
    );

    // Two attempts at one operation: different identities and transport
    // keys, one unchanged semantic key, and both still express the intent.
    assert_ne!(first.event_id(), second.event_id());
    assert!(queued.authored_envelope_matches(first.event()));
    assert!(queued.authored_envelope_matches(second.event()));
    assert_eq!(
        queued.digest().unwrap(),
        fixture_queued_intent(EventIntent::from_authored(second.event()))
            .digest()
            .unwrap()
    );
}

#[test]
fn event_intent_digest_changes_with_semantic_payload() {
    let first = sdk_event_without_proof("did:web:alice.example");
    let mut second = first.clone();
    second
        .payload
        .insert("state".to_owned(), Value::String("away".to_owned()));

    let first = fixture_queued_intent(EventIntent::from_authored(&first));
    let second = fixture_queued_intent(EventIntent::from_authored(&second));
    assert_ne!(first, second);
    assert_ne!(first.digest().unwrap(), second.digest().unwrap());
}

/// The grant's issuer signature is the Event envelope proof: no nested grant
/// proof exists on the wire, and validating the payload must not add one or
/// otherwise move what the queue froze.
#[test]
fn capability_payload_validation_does_not_mutate_queue_intent() {
    let operation = crate::operation::ak_ops::capability_grant_actions(
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "did:web:alice.example",
        &crate::test_support::authority("did:web:bob.example"),
        &["ak.message.create"],
        None,
        Value::Null,
        crate::operation::ak_ops::IssuerRootBasis::default(),
    )
    .unwrap()
    .build_sdk_event("inkson")
    .unwrap();
    let frozen = QueuedSdkEvent::unauthored(
        fixture_queued_intent(operation.intent().clone()),
        "capability-operation".to_owned(),
        "capability-attempt".to_owned(),
        None,
        test_authoring_generation(),
        None,
    )
    .unwrap();
    validate_capability_grant_payload(&frozen.intent).unwrap();
    assert_eq!(
        frozen.intent,
        fixture_queued_intent(operation.intent().clone())
    );
    assert!(frozen.intent.payload()["grant"].get("proofs").is_none());

    // A later attempt re-authors from that same frozen intent, and the
    // validator still accepts the result without having touched it.
    let attempt = crate::operation::author_intent_for_test(operation.into_intent());
    validate_capability_grant_payload(&EventIntent::from_authored(attempt.event())).unwrap();
    assert!(frozen.intent.authored_envelope_matches(attempt.event()));
    assert!(attempt.payload["grant"].get("proofs").is_none());
}

#[test]
fn frontier_context_preserves_retryable_transport_error() {
    let error = actor_frontier_refresh_error(
        "did:web:alice.example",
        arkret_sdk::http_client::Error::Http("browser offline".to_owned()).into(),
    );

    assert_eq!(outbound_retry_delay(&error), Some(Duration::from_secs(1)));
    assert!(format!("{error:#}").contains("browser offline"));
}

#[test]
fn wasm_string_only_transport_error_remains_retryable() {
    let error =
        anyhow::anyhow!("resolve authoring generation: HTTP request failed: error sending request");

    assert_eq!(outbound_retry_delay(&error), Some(Duration::from_secs(1)));
}

#[test]
fn accepted_admission_commit_never_discards_welcome_on_protocol_rejection() {
    let error = anyhow::anyhow!("welcome rejected with deterministic policy error");

    assert_eq!(outbound_retry_delay(&error), None);
    assert_eq!(
        mls_admission_welcome_retry_delay(&error),
        Duration::from_secs(60)
    );
}

#[test]
fn admission_cas_conflict_keeps_exact_saga_queued_for_repair() {
    let outcome = mls_admission_repair_retry_outcome("frontier changed");

    match outcome {
        OutboundSubmitOutcome::RetryAfter { delay, reason } => {
            assert_eq!(delay, Duration::from_secs(60));
            assert!(reason.contains("repair required"));
        }
        other => panic!("admission CAS conflict must remain retryable, got {other:?}"),
    }
}

#[test]
fn generic_mls_drainer_cannot_finalize_before_snapshot_convergence() {
    let outcome = accepted_mls_state_store_for_finalization::<()>(None)
        .expect_err("a drainer without an accepted-state store must keep the saga queued");

    match outcome {
        OutboundSubmitOutcome::RetryAfter { delay, reason } => {
            assert_eq!(delay, Duration::from_secs(1));
            assert!(reason.contains("snapshot convergence"));
        }
        other => panic!("missing accepted-state store must remain retryable, got {other:?}"),
    }

    assert_eq!(
        accepted_mls_state_store_for_finalization(Some("accepted-state-store")),
        Ok("accepted-state-store"),
        "the accepted-store drainer may proceed to checkpoint-proven convergence"
    );
}

#[test]
fn pending_chat_projection_ignores_sent_items_and_other_conversations() {
    let realm = arkret_sdk::RealmId::new(
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
    )
    .unwrap();
    let actor = "did:web:alice.example";
    let mut queue = garth::SendQueue::new();
    let pending = sdk_event_with_kind(
        "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        realm.as_str(),
        "ak.message.create",
        actor,
    );
    let mut pending = pending;
    // A queued `ak.message.create` carries no Message id: the Message is
    // named by the create Event, which nothing has accepted yet.
    pending.payload = serde_json::from_value(json!({
        "strand_id": "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h"
    }))
    .unwrap();
    queue
        .enqueue(
            Some("pending-operation".to_owned()),
            realm.clone(),
            QueuedRecord::SdkEvent(Box::new(
                QueuedSdkEvent::unauthored(
                    fixture_queued_intent(EventIntent::from_authored(&pending)),
                    "pending-operation".to_owned(),
                    "pending-attempt".to_owned(),
                    None,
                    test_authoring_generation(),
                    None,
                )
                .unwrap(),
            )),
            Vec::new(),
            chrono::Utc::now(),
        )
        .unwrap();

    let mut other_conversation = sdk_event_with_kind(
        "ak:event:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
        realm.as_str(),
        "ak.message.create",
        actor,
    );
    other_conversation.payload = serde_json::from_value(json!({
        "strand_id": "ak:strand:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk"
    }))
    .unwrap();
    queue
        .enqueue(
            Some("other-operation".to_owned()),
            realm.clone(),
            QueuedRecord::SdkEvent(Box::new(
                QueuedSdkEvent::unauthored(
                    fixture_queued_intent(EventIntent::from_authored(&other_conversation)),
                    "other-operation".to_owned(),
                    "other-attempt".to_owned(),
                    None,
                    test_authoring_generation(),
                    None,
                )
                .unwrap(),
            )),
            Vec::new(),
            chrono::Utc::now(),
        )
        .unwrap();

    let sent = sdk_event_with_kind(
        "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
        realm.as_str(),
        "ak.message.create",
        actor,
    );
    let sent_transaction = "sent-operation".to_owned();
    queue
        .enqueue(
            Some(sent_transaction.clone()),
            realm.clone(),
            QueuedRecord::SdkEvent(Box::new(
                QueuedSdkEvent::unauthored(
                    fixture_queued_intent(EventIntent::from_authored(&sent)),
                    "sent-operation".to_owned(),
                    "sent-attempt".to_owned(),
                    None,
                    test_authoring_generation(),
                    None,
                )
                .unwrap(),
            )),
            Vec::new(),
            chrono::Utc::now(),
        )
        .unwrap();
    // An acceptance now has to carry its ingress receipts: they are the
    // only evidence the Event landed inside its authorization-lease window,
    // and the queue refuses a `Sent` transition without them.
    let issued_at = chrono::Utc::now();
    let lease = crate::authorization_lease::test_support::lease(
        realm.clone(),
        actor,
        "ak.message.create",
        issued_at,
        issued_at + chrono::Duration::hours(1),
    );
    queue
        .mark_sent(
            &sent_transaction,
            arkret_sdk::EventId::new(
                "ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk".to_owned(),
            )
            .unwrap(),
            vec![crate::authorization_lease::test_support::receipt(
                &lease,
                issued_at + chrono::Duration::minutes(1),
            )],
            issued_at,
        )
        .unwrap();

    // Only the still-queued send in this strand, reported by the
    // holder-local key its optimistic row also carries.
    assert_eq!(
        pending_chat_local_operation_ids_from_snapshot(
            &queue.snapshot(),
            realm.as_str(),
            "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        ),
        std::collections::BTreeSet::from(["pending-operation".to_owned()])
    );
}

fn sdk_event_without_proof(actor_id: &str) -> arkret_sdk::Event {
    let actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        crate::mls_api_helpers::principal_core_id(actor_id).unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
    ));
    serde_json::from_value(json!({
        "event_id": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "kind": "ak.presence",
        "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"},
        "actor_id": actor_id,
        "actor_seq": 1,
        "created_at": "2026-05-19T00:00:00.000Z",
        "hlc": "01970e589d21-0001-a13f9c2e",
        "prev_refs": [],
        "payload": {
            "actor_id": actor_id,
            "state": "online"
        },
        "proofs": []
    }))
    .unwrap()
}

fn sdk_event_with_kind(
    event_id: &str,
    realm_id: &str,
    kind: &str,
    actor_id: &str,
) -> arkret_sdk::Event {
    let actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        crate::mls_api_helpers::principal_core_id(actor_id).unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
    ));
    serde_json::from_value(json!({
        "event_id": event_id,
        "kind": kind,
        "realm_id": realm_id,
        "scope_ref": {"kind": "realm", "realm_id": realm_id},
        "actor_id": actor_id,
        "actor_seq": 1,
        "created_at": "2026-05-19T00:00:00.000Z",
        "hlc": "01970e589d21-0001-a13f9c2e",
        "prev_refs": [],
        "payload": {},
        "proofs": []
    }))
    .unwrap()
}

/// A genesis `ak.realm.create` carries no `realm_id` and no
/// `payload.object.id`: both are derived from `event_id`, so the caller
/// picks the Event id and reads the Realm id back off the envelope.
fn realm_create_sdk_event(event_id: &str, created_by: &str) -> arkret_sdk::Event {
    let created_by = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        crate::mls_api_helpers::principal_core_id(created_by).unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
    ));
    let mut event: arkret_sdk::Event = serde_json::from_value(json!({
        "event_id": event_id,
        "kind": "ak.realm.create",
        "scope_ref": {"kind": "realm_genesis"},
        "actor_id": created_by,
        "actor_seq": 1,
        "created_at": "2026-05-19T00:00:00.000Z",
        "hlc": "01970e589d21-0001-a13f9c2e",
        "prev_refs": [],
        "payload": {},
        "proofs": []
    }))
    .unwrap();
    event.payload.insert("object".to_owned(), json!({}));
    event
}

const AUTHORITY_GENESIS_EVENT: &str = "ak:event:ASgi2U7PbVyNs4UpiQAoXKoHv84g07gpBvuddCGiMMG1";
/// Any well-formed Realm id: used by the non-genesis events below, which
/// still carry `realm_id` on the wire.
const AUTHORITY_REALM: &str = "ak:realm:ATOz4l-vKJUCGZDmS_knGS9TjZ64pkOzx-HNGAgY5RGJ";
const AUTHORITY_CONTROLLER: &str = "did:web:alice.example";

const AUTHORITY_CONTROLLER_CORE: &str = "ak:did_core:web:alice.example";
fn authority_controller_actor() -> arkret_sdk::ActorId {
    crate::test_support::account_actor(AUTHORITY_CONTROLLER_CORE)
}
#[test]
fn realm_create_authority_resolves_the_root_controller() {
    let events = [realm_create_sdk_event(
        AUTHORITY_GENESIS_EVENT,
        AUTHORITY_CONTROLLER,
    )];
    let realm_id = events[0].realm_id.to_string();
    assert_eq!(
        realm_create_authority_from_events(&events, &realm_id),
        Some(RealmCreateAuthority::Root {
            controller: authority_controller_actor()
        })
    );
}

#[test]
fn direct_conversation_never_claims_ordinary_realm_owner_authority() {
    let mut create = realm_create_sdk_event(AUTHORITY_GENESIS_EVENT, AUTHORITY_CONTROLLER);
    create.payload.insert(
        "object".to_owned(),
        json!({"purpose":"direct_conversation"}),
    );
    let realm = create.realm_id.to_string();
    let authority = realm_create_authority_from_events(&[create], &realm);
    assert_eq!(authority, Some(RealmCreateAuthority::DirectConversation));
    let intent = sdk_intent_with_kind(
        &realm,
        arkret_sdk::EventKind::MessageCreate.as_str(),
        AUTHORITY_CONTROLLER,
    );
    assert_eq!(
        realm_authority_root_claim(&intent, authority.as_ref()),
        None
    );
}

#[test]
fn realm_create_authority_ignores_other_realms_and_kinds() {
    // A create for a *different* Realm: a different genesis Event id, so a
    // different derived Realm id.
    let other_realm = realm_create_sdk_event(
        "ak:event:ASyFf0qTUQ55a2qZp5fuTXRnIgf3ovKChQZ_XSkxdIPK",
        "did:web:mallory.example",
    );
    let authority_realm = realm_create_sdk_event(AUTHORITY_GENESIS_EVENT, AUTHORITY_CONTROLLER)
        .realm_id
        .to_string();
    let other_kind = sdk_event_with_kind(
        "ak:event:AZpUEIyW7TNKR7LXG3WwW7XhlXVKyRQXiuhWXSw19pzj",
        &authority_realm,
        "ak.strand.create",
        AUTHORITY_CONTROLLER,
    );
    assert_eq!(
        realm_create_authority_from_events(&[other_realm, other_kind], &authority_realm),
        None
    );
}

#[test]
fn realm_owner_coverage_gates_the_root_claim() {
    // `ak.strand.create` is in the owner aggregate's registry-derived
    // operational coverage; `ak.realm.create` is deliberately excluded
    // (creating another Realm is not a capability inside this one).
    assert!(realm_owner_covers_event_kind("ak.strand.create"));
    assert!(realm_owner_covers_event_kind("ak.space.create"));
    assert!(realm_owner_covers_event_kind("ak.mls.genesis"));
    assert!(realm_owner_covers_event_kind("ak.message.create"));
    assert!(!realm_owner_covers_event_kind("ak.rsvp.set"));
    assert!(!realm_owner_covers_event_kind("ak.realm.create"));
    assert!(!realm_owner_covers_event_kind("ak.not.a.kind"));

    // Consent writes are root-control-only and therefore deliberately not in
    // the ordinary owner aggregate. They still require the same root claim.
    assert!(!realm_owner_covers_event_kind("ak.consent.grant"));
    assert!(realm_authority_root_covers_event_kind("ak.consent.grant"));
    assert!(realm_authority_root_covers_event_kind("ak.consent.revoke"));
}

#[test]
fn realm_authority_root_claim_stamps_only_the_matching_controller() {
    let root = RealmCreateAuthority::Root {
        controller: authority_controller_actor(),
    };
    let event = |actor: &str| sdk_intent_with_kind(AUTHORITY_REALM, "ak.strand.create", actor);

    assert_eq!(
        realm_authority_root_claim(&event(AUTHORITY_CONTROLLER), Some(&root)),
        Some(arkret_sdk::AuthorizationRef::new(arkret_wire::REALM_AUTHORITY_ROOT_CELL).unwrap())
    );
    let rsvp = sdk_intent_with_kind(AUTHORITY_REALM, "ak.rsvp.set", AUTHORITY_CONTROLLER);
    assert_eq!(realm_authority_root_claim(&rsvp, Some(&root)), None);
    let consent = sdk_intent_with_kind(AUTHORITY_REALM, "ak.consent.grant", AUTHORITY_CONTROLLER);
    assert_eq!(
        realm_authority_root_claim(&consent, Some(&root)),
        Some(arkret_sdk::AuthorizationRef::new(arkret_wire::REALM_AUTHORITY_ROOT_CELL).unwrap())
    );
    assert_eq!(
        realm_authority_root_claim(&event("did:web:bob.example"), Some(&root)),
        None
    );
    let wrong_station: EventIntent = serde_json::from_value(json!({
        "kind": "ak.strand.create",
        "scope_ref": {"kind": "realm", "realm_id": AUTHORITY_REALM},
        "actor_id": {
            "kind": "account",
            "account_id": {
                "principal_id": AUTHORITY_CONTROLLER_CORE,
                "station_id": "ak:did_core:web:other-station.example"
            }
        },
        "created_at": "2026-08-31T00:00:00.000Z",
        "payload": {}
    }))
    .unwrap();
    assert_eq!(
        realm_authority_root_claim(&wrong_station, Some(&root)),
        None
    );
    assert_eq!(
        realm_authority_root_claim(&event(AUTHORITY_CONTROLLER), None),
        None
    );
}

#[test]
fn realm_authority_root_claim_defers_to_producer_chosen_authorization() {
    let root = RealmCreateAuthority::Root {
        controller: authority_controller_actor(),
    };
    let with_grant =
        sdk_intent_with_kind(AUTHORITY_REALM, "ak.strand.create", AUTHORITY_CONTROLLER)
            .with_authorization_ref(
                arkret_sdk::AuthorizationRef::new(
                    "ak:grant:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH",
                )
                .unwrap(),
            );
    assert_eq!(realm_authority_root_claim(&with_grant, Some(&root)), None);

    let executed_by_service =
        sdk_intent_with_kind(AUTHORITY_REALM, "ak.strand.create", AUTHORITY_CONTROLLER)
            .with_executed_by(arkret_sdk::ActorId::service(
                arkret_sdk::DidCoreId::new("ak:did_core:web:service.example").unwrap(),
            ));
    assert_eq!(
        realm_authority_root_claim(&executed_by_service, Some(&root)),
        None
    );
}

fn dead_endpoint_submitter() -> EventSubmitter {
    EventSubmitter::new(
        arkret_sdk::http_client::Client::builder("http://127.0.0.1:9/".parse().unwrap())
            .allow_insecure_localhost()
            .build()
            .unwrap(),
    )
    .with_authority(test_authority())
}

fn test_authority() -> arkret_sdk::AccountId {
    crate::test_support::authority_at_station(
        "ak:did_core:web:alice.example",
        crate::test_support::SERVER_STATION_ID,
    )
}

#[tokio::test]
async fn stamp_realm_authority_root_claim_stamps_from_cached_create_facts() {
    // Unique Realm id: the create-facts cache is process-global and tests
    // run in parallel.
    let realm = "ak:realm:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml";
    realm_create_authority_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(
            realm.to_owned(),
            RealmCreateAuthority::Root {
                controller: authority_controller_actor(),
            },
        );
    let intent = dead_endpoint_submitter()
        .stamp_realm_authority_root_claim(
            sdk_intent_with_kind(realm, "ak.strand.create", AUTHORITY_CONTROLLER),
            None,
        )
        .await;
    assert_eq!(
        intent
            .authorization_ref()
            .map(arkret_sdk::AuthorizationRef::as_str),
        Some(arkret_wire::REALM_AUTHORITY_ROOT_CELL)
    );
}

/// Regression lock (2026-08-01): Events queued while the session was dead
/// froze their intents with `authorization_ref = None` (the authority
/// lookup 401ed). A post-re-login replay used the fresh-authoring prepare,
/// stamped the claim onto the envelope, diverged from the frozen intent
/// and the queue's semantic guard cancelled the item — the discussion
/// message could never send. Frozen-intent re-authoring MUST reproduce
/// the intent's authorization choice verbatim even when the claim is now
/// resolvable.
#[tokio::test]
async fn frozen_intent_replay_must_not_upgrade_the_authorization_claim() {
    let realm = "ak:realm:Aa9ST4mV9PwPifTwudPs8hENCT9iNyCpkWSVDjEH7hJ_";
    realm_create_authority_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(
            realm.to_owned(),
            RealmCreateAuthority::Root {
                controller: authority_controller_actor(),
            },
        );
    // Outage-era intent: owner-authored kind, but no claim was resolvable
    // at enqueue time.
    let frozen = sdk_intent_with_kind(realm, "ak.message.create", AUTHORITY_CONTROLLER);
    assert!(frozen.authorization_ref().is_none());

    // Fresh authoring would stamp (the claim is resolvable from cache)…
    let freshly_authored = dead_endpoint_submitter()
        .stamp_realm_authority_root_claim(frozen.clone(), None)
        .await;
    assert!(freshly_authored.authorization_ref().is_some());

    // …but a replay of the frozen intent must reproduce its choice verbatim,
    // or the authored envelope diverges from the intent it is bound to.
    let frozen_queued = fixture_queued_intent(frozen.clone());
    let replayed = frozen
        .author_with_digest_suite(
            7,
            crate::operation::test_authoring_hlc_at_seq(7),
            arkret_sdk::DigestSuite::Sha256,
        )
        .unwrap();
    let upgraded = freshly_authored
        .author_with_digest_suite(
            7,
            crate::operation::test_authoring_hlc_at_seq(7),
            arkret_sdk::DigestSuite::Sha256,
        )
        .unwrap();
    assert!(frozen_queued.authored_envelope_matches(replayed.event()));
    assert!(
        !frozen_queued.authored_envelope_matches(upgraded.event()),
        "queue must reject a fresh authority claim added to a frozen intent"
    );
}

#[tokio::test]
async fn stamp_realm_authority_root_claim_swallows_lookup_failures() {
    // Unknown Realm + unreachable endpoint: the claim must be skipped, not
    // fail the submit — a member's ordinary grant path stays usable when
    // the create lookup is unavailable.
    let intent = dead_endpoint_submitter()
        .stamp_realm_authority_root_claim(
            sdk_intent_with_kind(
                "ak:realm:ARKSHgBichO7ZjwprTMf4UrKn7x1GHkl16zz6U4xm586",
                "ak.strand.create",
                AUTHORITY_CONTROLLER,
            ),
            None,
        )
        .await;
    assert!(intent.authorization_ref().is_none());
}

#[tokio::test]
async fn direct_message_create_facts_do_not_replace_current_station_result() {
    let realm = "ak:realm:AerU-5uN-bPQWS8OybUSGMJ12UmZuQwsqVsMKHRlgrDL";
    realm_create_authority_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(realm.to_owned(), RealmCreateAuthority::DirectConversation);
    let original = sdk_intent_with_kind(realm, "ak.message.create", AUTHORITY_CONTROLLER);
    let result = dead_endpoint_submitter()
        .stamp_realm_authority_root_claim(original.clone(), None)
        .await;
    assert_eq!(result, original);
    assert!(result.authorization_ref().is_none());
    assert!(result.auth_context().is_none());
}

#[test]
fn stamped_intent_round_trips_through_authoring_without_semantic_drift() {
    // Reproduce the queued-submit lifecycle for a kanban card create:
    // freeze a stamped intent, author the envelope from it the way the
    // outbound drive does, and require `EventIntent` equality — the exact
    // check `decode_queued_sdk_event` enforces on the persisted attempt.
    let realm = "ak:realm:AU2D21msYuLaXwOH8_eGJzFL4TqkaJ0gxxClWY-3IywJ";
    realm_create_authority_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(
            realm.to_owned(),
            RealmCreateAuthority::Root {
                controller: authority_controller_actor(),
            },
        );
    let operation = crate::operation::ak_ops::kanban_card_strand_create(
        realm,
        AUTHORITY_CONTROLLER,
        "probe card",
    )
    .unwrap()
    .build_sdk_event("inkson")
    .unwrap();

    // Mirror the enqueue-side stamp: the authority-root claim is a semantic
    // choice, so it is part of what the queue freezes.
    let intent = operation.into_intent().with_authorization_ref(
        realm_authority_root_claim(
            &sdk_intent_with_kind(realm, "ak.strand.create", AUTHORITY_CONTROLLER),
            Some(&RealmCreateAuthority::Root {
                controller: authority_controller_actor(),
            }),
        )
        .expect("claim must stamp"),
    );
    let queued = QueuedSdkEvent::unauthored(
        fixture_queued_intent(intent.clone()),
        "local-op".to_owned(),
        "authoring-key".to_owned(),
        None,
        test_authoring_generation(),
        None,
    )
    .unwrap();

    // Mirror one attempt by the outbound drive: an actor-chain position, the
    // CBS basis it resolved for this attempt, and the holder-local alias.
    // None of those is part of the operation, so none may make the attempt
    // stop expressing the intent it is bound to.
    let mut authored = intent
        .with_prev_refs(vec![fixture_event_id(
            "ak:event:AdymfEYKFegRsXpyi5Or3ormR7igvbwtXIp8HyMfOvWE",
        )])
        .with_auth_context(arkret_sdk::AuthContext {
            key_id: arkret_sdk::OpaqueLocalId::new("device").unwrap(),
            key_epoch: 0,
            credential_epoch: None,
            authority_refs: vec![arkret_sdk::SealId::new(
                "ak:seal:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_owned(),
            )
            .unwrap()],
        })
        .author_with_digest_suite(
            7,
            crate::operation::test_authoring_hlc_at_seq(7),
            arkret_sdk::DigestSuite::Sha256,
        )
        .unwrap();
    authored.insert_unsigned(
        crate::operation::LOCAL_OPERATION_IDEMPOTENCY_ALIAS,
        Value::String("authoring-key".to_owned()),
    );

    if !queued.intent.authored_envelope_matches(authored.event()) {
        let left = serde_json::to_value(authored.event()).unwrap();
        let right = serde_json::to_value(&queued.intent).unwrap();
        panic!(
            "authored envelope drifted from bound intent:\nauthored: {left:#}\nintent:   {right:#}"
        );
    }
}

#[test]
fn queued_mls_admission_round_trips_exact_welcome_material() {
    let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    // The admission Commit ships as exact authored bytes, and the Welcomes
    // name it by its FINAL id — so the Commit is authored first and the
    // Welcome is only then authorable at all.
    let proposal_intent =
        sdk_intent_with_kind(realm_id, "ak.mls.proposal", "did:web:alice.example");
    let mut proposal = crate::operation::author_intent_for_test_at_seq(proposal_intent, 1);
    {
        use crate::operation::AuthoredEventExt;
        proposal
            .sign_ed25519(
                "did:web:alice.example",
                "did:web:alice.example#device",
                &ed25519_dalek::SigningKey::from_bytes(&[30_u8; 32]),
                crate::event_signer::test_producer_proof_context(arkret_sdk::DigestSuite::Sha256)
                    .signer_resolution_evidence_ref
                    .unwrap(),
            )
            .expect("the Proposal signs");
    }
    let authored_proposal = proposal.event().clone();
    let mut accepted_proposal = authored_proposal.clone();
    assert!(
        accepted_event_preserves_authored_envelope(
            &accepted_proposal,
            &authored_proposal,
            proposal.digest_suite(),
        )
        .unwrap()
    );
    accepted_proposal
        .payload
        .insert("tampered".to_owned(), serde_json::Value::Bool(true));
    assert!(
        !accepted_event_preserves_authored_envelope(
            &accepted_proposal,
            &authored_proposal,
            proposal.digest_suite(),
        )
        .unwrap()
    );
    let commit_intent = serde_json::from_value::<EventIntent>(json!({
        "kind": "ak.mls.commit",
        "scope_ref": {"kind": "realm", "realm_id": realm_id},
        "actor_id": {
            "kind": "account",
            "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:principal.example"
            }
        },
        "created_at": "2026-05-19T00:00:00.000Z",
        "payload": {"proposal_refs": [proposal.event_id()]}
    }))
    .unwrap();
    let mut commit = crate::operation::author_intent_for_test_at_seq(commit_intent.clone(), 2);
    // The durable authored record must freeze the submission's MLS leaf input.
    // This fixture tests queue persistence, not MLS transition admission.
    assert!(
        serde_json::to_value(&commit)
            .unwrap_err()
            .to_string()
            .contains("mls_frontier_leaves are required exactly for MLS Genesis/Commit")
    );
    commit
        .bind_mls_frontier_leaves(vec![arkret_sdk::MlsSecurityFrontierLeaf {
            leaf_index: 0,
            actor_id: commit.actor_id.clone(),
            credential_ref: arkret_sdk::NonEmptyString::new(
                "ak:device:01904100-0000-7000-8000-000000000001",
            )
            .unwrap(),
        }])
        .unwrap();
    let mut welcome = crate::operation::author_intent_for_test_at_seq(
        serde_json::from_value::<EventIntent>(json!({
            "kind": "ak.mls.welcome",
            "scope_ref": {"kind": "realm", "realm_id": realm_id},
            "actor_id": {
                "kind": "account",
                "account_id": {
                    "principal_id": "ak:did_core:web:alice.example",
                    "station_id": "ak:did_core:web:principal.example"
                }
            },
            "created_at": "2026-05-19T00:00:00.000Z",
            "payload": {
                "commit_ref": commit.event_id(),
                "recipient_principal_id": "ak:did_core:web:bob.example"
            }
        }))
        .unwrap(),
        2,
    );
    // An `Authored` Welcome is one that is ready to ship, so it carries its
    // producer proof; the queue refuses the pair otherwise.
    {
        use crate::operation::AuthoredEventExt;
        welcome
            .sign_ed25519(
                "did:web:alice.example",
                "did:web:alice.example#device",
                &ed25519_dalek::SigningKey::from_bytes(&[31_u8; 32]),
                crate::event_signer::test_producer_proof_context(arkret_sdk::DigestSuite::Sha256)
                    .signer_resolution_evidence_ref
                    .unwrap(),
            )
            .expect("the Welcome signs");
    }
    let snapshot = crate::mls::persistence::MlsLocalCheckpointEnvelope {
        realm_id: realm_id.to_owned(),
        group_id: "010203".to_owned(),
        epoch: 1,
        admission_epoch: 0,
        group_state_event_id: None,
        salt_hex: "00".repeat(16),
        ciphertext_hex: "11".repeat(32),
        mac_hex: "22".repeat(12),
        recorded_at: chrono::Utc::now(),
        epoch_started_at: chrono::Utc::now(),
        app_messages_observed: 0,
        aead_version: crate::mls::persistence::AEAD_VERSION_CHACHA20_POLY1305,
    };
    let queued = QueuedSdkEvent::authored(
        fixture_queued_intent(commit_intent),
        commit.clone(),
        "mls-admission-operation".to_owned(),
        commit.event_id().to_string(),
        arkret_sdk::canonical::canonical_json_bytes(&commit).unwrap(),
        None,
        test_authoring_generation(),
        Some(PostAcceptAction::MlsAdmission {
            realm_id: realm_id.to_owned(),
            actor_id: "ak:did_core:web:alice.example".to_owned(),
            device_id: "ak:device:01904100-0000-7000-8000-000000000001".to_owned(),
            proposal_events: vec![proposal],
            stage: MlsAdmissionStage::WelcomesAcceptedWaitingSeal,
            commit_ingress_receipts: Vec::new(),
            commit_was_duplicate: false,
            welcomes: garth::QueuedMlsWelcomes {
                events: vec![welcome.clone()],
            },
            snapshot: snapshot.into_queued(),
        }),
    )
    .unwrap();

    let decoded = decode_queued_sdk_event(serde_json::to_value(&queued).unwrap()).unwrap();
    let queued_record = QueuedRecord::SdkEvent(Box::new(decoded.clone()));
    assert!(is_unfinished_mls_admission_record(
        garth::SendQueueStatus::Failed,
        &queued_record,
        realm_id,
    ));
    assert!(!is_unfinished_mls_admission_record(
        garth::SendQueueStatus::Sent,
        &queued_record,
        realm_id,
    ));
    assert!(is_mls_admission_snapshot_finalization_record(
        garth::SendQueueStatus::Failed,
        &queued_record,
    ));
    assert!(!is_mls_admission_snapshot_finalization_record(
        garth::SendQueueStatus::Sent,
        &queued_record,
    ));
    let mut finalization_queue = garth::SendQueue::new();
    finalization_queue
        .enqueue(
            Some("mls-finalization".to_owned()),
            arkret_sdk::RealmId::new(realm_id.to_owned()).unwrap(),
            queued_record.clone(),
            Vec::new(),
            chrono::Utc::now(),
        )
        .unwrap();
    let snapshot = finalization_queue.snapshot();
    let unchanged = snapshot.clone();
    for _ in 0..64 {
        assert!(mls_outbound_requires_accepted_state_store(&snapshot));
    }
    assert_eq!(
        snapshot, unchanged,
        "repeated generic-drainer preflights must not claim or reschedule finalization"
    );
    let Some(PostAcceptAction::MlsAdmission { welcomes, .. }) = decoded.post_accept else {
        panic!("queued admission action was not preserved");
    };
    // Restoring the record re-proves each Welcome's identity against its own
    // content: a durable record is not a trusted source of identity.
    assert_eq!(welcomes.authored(), [welcome].as_slice());
    assert_eq!(
        decoded
            .authored_attempt
            .as_ref()
            .unwrap()
            .canonical_body_bytes,
        queued
            .authored_attempt
            .as_ref()
            .unwrap()
            .canonical_body_bytes
    );
}

/// The accepted frontier is an authoring input: the position it reports lands
/// on the envelope through `author`, not through a later write.
#[test]
fn the_accepted_frontier_positions_the_authored_envelope() {
    let intent = EventIntent::from_authored(&sdk_event_without_proof("did:web:alice.example"));
    let frontier_event_id =
        arkret_sdk::EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap();
    let frontier = arkret_sdk::RealmActorFrontierView::new(
        intent.realm_id_opt().unwrap().clone(),
        intent.actor_id().clone(),
        8,
        vec![frontier_event_id.clone()],
        arkret_sdk::canonical::DigestSuite::Sha256,
    )
    .unwrap();
    frontier.validate().unwrap();

    let authored = intent
        .with_prev_refs(frontier.frontier_event_ids.clone())
        .author_with_digest_suite(
            frontier.next_actor_seq,
            crate::operation::test_authoring_hlc_at_seq(frontier.next_actor_seq),
            arkret_sdk::DigestSuite::Sha256,
        )
        .unwrap();

    assert_eq!(authored.actor_seq, 8);
    assert_eq!(authored.prev_refs, vec![frontier_event_id]);
    authored.verify_identity().unwrap();
}

/// `contract-registry.json` (`event_kind_registry.registry_rules`) closes
/// the question the old version of this test guessed at: *every*
/// `ordered_log` append MUST project `issuer_seq` from `envelope.actor_seq`
/// exactly, and a registry row MUST NOT declare a cell-local constant. A
/// genesis append is not special-cased into slot zero, so the frontier
/// stamp is required to carry into `ak.realm.create`'s create-log append —
/// while every other registered write of that Event, none of which reads
/// `actor_seq`, must come out byte-identical.
#[test]
fn actor_frontier_stamp_carries_into_the_ordered_log_issuer_seq() {
    let intent = crate::event_builders::build_realm_create_event(
        arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
        "did:web:alice.example",
        crate::event_builders::test_authority_notary("did:web:alice.example").unwrap(),
        "Frontier",
        None,
        "invite_only",
        "invite",
        "since_join",
        // `encryption_profile` is the closed realm-genesis schema enum
        // {none, mls_rfc9420, external}; "plaintext" was never a member and
        // only survived here because the object used to be hand-built JSON.
        "none",
        "standard",
        "open",
        "sha256",
        "ak:trust_domain:did.web.example",
        None,
    )
    .unwrap()
    .into_intent();
    let create_log_issuer_seq = |event: &arkret_sdk::Event| {
        crate::operation::direct_registered_cell_writes(event, arkret_sdk::DigestSuite::Sha256)
            .unwrap()
            .into_iter()
            .find(|write| write.cell_id.as_str() == arkret_bootstrap::REALM_CREATE_CELL)
            .expect("realm.create projects the create-log append")
            .op
            .issuer_seq
    };
    let other_writes = |event: &arkret_sdk::Event| {
        crate::operation::direct_registered_cell_writes(event, arkret_sdk::DigestSuite::Sha256)
            .unwrap()
            .into_iter()
            .filter(|write| write.cell_id.as_str() != arkret_bootstrap::REALM_CREATE_CELL)
            .collect::<Vec<_>>()
    };

    // Genesis opens its own chain at 0; the same intent authored at an
    // ordinary chain position must move `issuer_seq` with it and leave every
    // other registered write of that Event byte-identical.
    let at_genesis = crate::operation::author_intent_for_test_at_seq(intent.clone(), 0);
    assert_eq!(create_log_issuer_seq(&at_genesis), Some(0));
    let before_other = other_writes(&at_genesis);

    let frontier = arkret_sdk::RealmActorFrontierView::new(
        at_genesis.realm_id.clone(),
        at_genesis.actor_id.clone(),
        8,
        vec![
            arkret_sdk::EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1")
                .unwrap(),
        ],
        arkret_sdk::canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let at_frontier = crate::operation::author_intent_for_test_at_seq(
        intent.with_prev_refs(frontier.frontier_event_ids.clone()),
        frontier.next_actor_seq,
    );

    assert_eq!(at_frontier.actor_seq, 8);
    assert_eq!(create_log_issuer_seq(&at_frontier), Some(8));
    assert_eq!(other_writes(&at_frontier), before_other);
}

#[test]
fn a_frontier_for_another_actor_is_not_a_chain_basis() {
    let intent = EventIntent::from_authored(&sdk_event_without_proof("did:web:alice.example"));
    let realm_id = intent.realm_id_opt().unwrap().clone();
    let mismatched = arkret_sdk::RealmActorFrontierView::new(
        realm_id.clone(),
        arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            intent.actor_id().route_service_id().clone(),
        )),
        8,
        vec![
            arkret_sdk::EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1")
                .unwrap(),
        ],
        arkret_sdk::canonical::DigestSuite::Sha256,
    )
    .unwrap();

    let error = actor_chain_basis_from_frontier(&realm_id, intent.actor_id(), mismatched)
        .unwrap_err()
        .to_string();

    assert!(error.contains("realm actor frontier mismatch"), "{error}");
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn receiver_frontier_preserves_account_station_and_rejects_substitution() {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    let actor = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        "ak:did_core:web:alice-frontier.example".parse().unwrap(),
        "ak:did_core:web:origin-a.example".parse().unwrap(),
    ));
    let realm = arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::DigestSuite::Sha256,
        [31; 32],
    ));
    for substitute_station in [false, true] {
        let response_actor = if substitute_station {
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                actor.signing_principal_id().clone(),
                "ak:did_core:web:receiver-b.example".parse().unwrap(),
            ))
        } else {
            actor.clone()
        };
        let frontier = arkret_sdk::RealmActorFrontierView::new(
            realm.clone(),
            response_actor,
            0,
            vec![],
            arkret_sdk::DigestSuite::Sha256,
        )
        .unwrap();
        assert_eq!(
            actor_chain_basis_from_frontier(&realm, &actor, frontier.clone()).is_err(),
            substitute_station,
        );
        let response = serde_json::to_vec(&arkret_sdk::EventsFrontierState {
            frontier: arkret_sdk::EventsFrontierView::RealmActor(frontier),
        })
        .unwrap();
        let receiver = TcpListener::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let url = format!("http://{}/", receiver.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let (mut stream, _) = loop {
                match receiver.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "frontier request did not reach receiver B"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("receiver failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 4096];
            let (body_start, body_len) = loop {
                let count = stream.read(&mut buffer).unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&buffer[..count]);
                if let Some(index) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..index]);
                    assert!(headers.starts_with("QUERY /_arkret/self/events/frontier HTTP/1.1"));
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    break (index + 4, length);
                }
            };
            while request.len() < body_start + body_len {
                let count = stream.read(&mut buffer).unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&buffer[..count]);
            }
            let body: Value =
                serde_json::from_slice(&request[body_start..body_start + body_len]).unwrap();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
            stream.write_all(&response).unwrap();
            body
        });
        let http = arkret_sdk::http_client::Client::builder(url.parse().unwrap())
            .allow_insecure_localhost()
            .build()
            .unwrap();
        let result = EventSubmitter::new(http)
            .events_frontier_actor(&actor, &realm)
            .await;
        let request = server.join().unwrap();
        assert_eq!(request["actor_id"], serde_json::to_value(&actor).unwrap());
        assert_eq!(request["realm_id"], serde_json::to_value(&realm).unwrap());
        assert_eq!(result.is_err(), substitute_station);
    }
}

#[test]
fn an_empty_frontier_authors_the_first_chain_position() {
    let intent = EventIntent::from_authored(&sdk_event_without_proof("did:web:alice.example"));
    let frontier = arkret_sdk::RealmActorFrontierView::new(
        intent.realm_id_opt().unwrap().clone(),
        intent.actor_id().clone(),
        0,
        vec![],
        arkret_sdk::canonical::DigestSuite::Sha256,
    )
    .unwrap();
    frontier.validate().unwrap();

    let authored = crate::operation::author_intent_for_test_at_seq(
        intent.with_prev_refs(frontier.frontier_event_ids.clone()),
        frontier.next_actor_seq,
    );

    assert_eq!(authored.actor_seq, 0);
    assert!(authored.prev_refs.is_empty());
}

#[tokio::test]
async fn realm_bootstrap_preparation_requires_verified_producer_evidence() {
    crate::operation::set_authoring_station_id(Some(
        arkret_sdk::DidCoreId::new("ak:did_core:web:server.example").unwrap(),
    ));
    let _signer = crate::event_signer::ActiveSignerTestGuard::replace(Some(std::sync::Arc::new(
        crate::event_signer::build_ed25519_device_signer(
            [42_u8; 32],
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-a11ce0000001",
        ),
    )));
    let steps = crate::event_builders::build_realm_bootstrap_steps_for_station(
        crate::test_support::core_id(crate::test_support::SERVER_STATION_ID),
        arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
        "did:web:alice.example",
        "did:web:server.example",
        crate::event_builders::test_authority_notary("did:web:server.example").unwrap(),
        "https://server.example",
        "Engineering",
        Some("Realm genesis must not query its own nonexistent frontier"),
        "listed",
        "invite",
        "since_join",
        "mls_rfc9420",
        "standard",
        "restricted",
        "sha256",
        "ak:trust_domain:server.example",
        &["did:web:server.example".to_owned()],
        None,
        None,
    )
    .unwrap();
    let http = arkret_sdk::http_client::Client::builder("http://127.0.0.1:9/".parse().unwrap())
        .allow_insecure_localhost()
        .build()
        .unwrap();

    let previous_proof_mode = crate::operation::current_proof_mode();
    crate::operation::set_proof_mode(crate::operation::ProofMode::RealEd25519);
    let error = EventSubmitter::new(http)
        .with_authority(test_authority())
        .author_event_unit(steps)
        .await
        .expect_err("authoring must have verified producer evidence");
    crate::operation::set_proof_mode(previous_proof_mode);
    assert!(format!("{error:#}").contains("verified signer-resolution evidence"));
}

#[tokio::test]
async fn space_update_metadata_authoring_skips_seal_refresh_but_policy_requires_it() {
    let mut source = sdk_event_without_proof("did:web:alice.example");
    source.kind = arkret_sdk::EventKind::SpaceUpdate;
    source.payload = serde_json::from_value(json!({
        "space_id": "ak:space:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "patch": {"title": {"$op": "set", "value": "Renamed"}}
    }))
    .unwrap();
    source.auth_context = Some(arkret_sdk::AuthContext {
        key_id: arkret_sdk::OpaqueLocalId::new("device").unwrap(),
        key_epoch: 0,
        credential_epoch: None,
        authority_refs: vec![
            arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "11".repeat(32))).unwrap(),
        ],
    });
    let http = arkret_sdk::http_client::Client::builder("http://127.0.0.1:9/".parse().unwrap())
        .allow_insecure_localhost()
        .build()
        .unwrap();
    let submitter =
        EventSubmitter::new(http).with_authority(source.actor_id.as_account_id().unwrap().clone());
    let ordinary = EventIntent::from_authored(&source);
    assert_eq!(
        cbs_effect_plane_for_intent(&ordinary).unwrap(),
        Some(CbsEffectPlane::Data)
    );
    assert_eq!(
        arkret_schema::classify_event_execution(&source).unwrap(),
        Some(CbsEffectPlane::Data)
    );
    let mut authored = crate::operation::author_intent_for_test(ordinary.clone());
    validate_projected_cbs_plane(&authored).unwrap();
    // This exercises wrapper routing and structural proof binding; signature
    // cryptography is checked at the separate producer verification boundary.
    authored.attach_proof(arkret_sdk::ProducerEventProof {
        kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: arkret_sdk::DidUrl::new("did:web:alice.example#device").unwrap(),
        event_digest: arkret_sdk::Hash::new(
            authored
                .event()
                .event_digest_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap(),
        signer_resolution_evidence_ref: Some(
            arkret_sdk::SignerEvidenceRef::new(format!(
                "ak:signer_evidence:sha256:{}",
                "22".repeat(32)
            ))
            .unwrap(),
        ),
        created_at: authored.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "fixture..signature".to_owned(),
    });
    let submission = crate::authorization_lease::standard_initial_submission(
        &submitter.http,
        authored.event(),
        arkret_sdk::DigestSuite::Sha256,
        None,
    )
    .await
    .expect("metadata-only SpaceUpdate must not query proposal authority");
    assert!(submission.control_proposal_ack.is_none());
    assert!(submission.authorization_lease.is_none());
    let error = submitter
        .author_intent(
            &ordinary,
            "metadata-update",
            SemanticAuthoring::Fresh,
            arkret_sdk::DigestSuite::Sha256,
        )
        .await
        .err()
        .expect("the receiver's actor frontier is unavailable");
    assert!(
        format!("{error:#}").contains("refresh actor frontier"),
        "{error:#}"
    );

    source.auth_context = None;
    let error = submitter
        .stamp_cbs_basis_for_intent(EventIntent::from_authored(&source))
        .await
        .err()
        .expect("ordinary authority evidence must already be retained locally");
    assert!(
        format!("{error:#}").contains("verified local authority store"),
        "{error:#}"
    );

    source.payload.insert(
        "child_scope_policy".to_owned(),
        json!({"kind": "allow_any"}),
    );
    let control = EventIntent::from_authored(&source);
    assert_eq!(
        cbs_effect_plane_for_intent(&control).unwrap(),
        Some(CbsEffectPlane::Control)
    );
    let pinned_control = control.clone().with_seal_basis(arkret_sdk::SealBasis {
        leaves: vec![
            arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "11".repeat(32))).unwrap(),
        ],
    });
    validate_projected_cbs_plane(&crate::operation::author_intent_for_test(pinned_control))
        .unwrap();
    let error = submitter
        .stamp_cbs_basis_for_intent(control)
        .await
        .err()
        .expect("a safety write queries its current Seal basis");
    assert!(
        !format!("{error:#}").contains("verified local authority store"),
        "{error:#}"
    );
}

#[tokio::test]
async fn ordinary_event_preparation_queries_receiver_frontier_without_describe() {
    crate::operation::set_authoring_station_id(Some(
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
    ));
    let intent = EventIntent::from_authored(&sdk_event_without_proof("did:web:alice.example"));
    let http = arkret_sdk::http_client::Client::builder("http://127.0.0.1:9/".parse().unwrap())
        .allow_insecure_localhost()
        .build()
        .unwrap();

    let error = EventSubmitter::new(http)
        // The intent's actor lives at the fixture Station, so the captured
        // authority must too; a mismatch is the guard tested below.
        .with_authority(crate::test_support::authority("ak:did_core:web:alice.example"))
        .author_independent_events(vec![intent])
        .await
        .expect_err("ordinary Realm Event must query the selected receiver's actor frontier");

    let detail = format!("{error:#}");
    assert!(
        detail.contains("refresh actor frontier") && !detail.contains("server describe"),
        "unexpected preparation error: {detail}"
    );
}

/// account-lifecycle.md §156: the account is one closed value. An Event whose
/// account actor carries the authenticated principal at another Station was
/// rebuilt from the principal plus a stale ambient authoring slot, and must be
/// refused before any network round trip rather than authored under the other
/// account.
#[tokio::test]
async fn event_actor_station_must_match_the_captured_authority() {
    let intent = EventIntent::from_authored(&sdk_event_without_proof("did:web:alice.example"));
    let http = arkret_sdk::http_client::Client::builder("http://127.0.0.1:9/".parse().unwrap())
        .allow_insecure_localhost()
        .build()
        .unwrap();

    let error = EventSubmitter::new(http)
        .with_authority(test_authority())
        .author_independent_events(vec![intent])
        .await
        .expect_err("an actor at another Station must not be authored");

    let detail = format!("{error:#}");
    assert!(
        detail.contains("but the authenticated account is hosted at"),
        "unexpected preparation error: {detail}"
    );
}

#[test]
fn actor_seq_cas_conflict_classifier_is_narrow() {
    let current_frontier = arkret_sdk::RealmActorFrontierView::new(
        arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap(),
        crate::mls_api_helpers::local_account_actor_id("ak:did_core:web:alice.example").unwrap(),
        0,
        vec![],
        arkret_sdk::canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let details = arkret_sdk::EventsActorCasConflictProblem {
        accepted: false,
        current_frontier,
    };
    let details = serde_json::to_value(details).unwrap();
    let cas: anyhow::Error = TransportClientError {
        status: StatusCode::CONFLICT,
        error: Problem::from_code(
            "cas_conflict",
            "actor_seq is older than the accepted actor frontier",
        )
        .with_extension("accepted", details["accepted"].clone())
        .with_extension("current_frontier", details["current_frontier"].clone()),
    }
    .into();
    assert!(crate::api_error::is_actor_seq_cas_conflict_error(&cas));

    let different_conflict: anyhow::Error = TransportClientError {
        status: StatusCode::CONFLICT,
        error: Problem::from_code("cas_conflict", "expected head mismatch"),
    }
    .into();
    assert!(!crate::api_error::is_actor_seq_cas_conflict_error(
        &different_conflict
    ));
}

#[test]
fn mls_genesis_event_lookup_filters_kind_and_realm() {
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let other_realm = "ak:realm:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk";
    let expected =
        arkret_sdk::EventId::new("ak:event:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy").unwrap();
    let outcome = arkret_sdk::EventsQueryOutcome {
        events: vec![
            sdk_event_with_kind(
                "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                realm,
                "ak.message.create",
                "did:web:alice.example",
            )
            .into(),
            sdk_event_with_kind(
                "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
                other_realm,
                "ak.mls.genesis",
                "did:web:alice.example",
            )
            .into(),
            sdk_event_with_kind(
                expected.as_str(),
                realm,
                "ak.mls.genesis",
                "did:web:alice.example",
            )
            .into(),
        ],
        realm_state_snapshot_bootstrap: None,
        next_cursor: None,
        prev_cursor: None,
        has_more: false,
    };

    assert_eq!(
        mls_genesis_event_id_from_events(&outcome, realm).unwrap(),
        Some(expected)
    );
    assert_eq!(
        mls_genesis_event_id_from_events(
            &outcome,
            "ak:realm:AfXCJ1DUe3g7MVHuVBpMsl89749WyrXAJP7EvoU9mwBH"
        )
        .unwrap(),
        None
    );
}

#[test]
fn prepared_join_signing_scope_rejects_cross_station_and_device_switch() {
    let account = arkret_sdk::AccountId::new(
        arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    );
    let scope = crate::secure_key_store::ActiveDeviceSeedScope {
        authority: account.clone(),
        device_id: arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001")
            .unwrap(),
    };
    validate_prepared_join_signing_scope(
        &account,
        &account,
        &scope,
        Some(&scope),
        Some(scope.device_id.as_str()),
    )
    .unwrap();
    let mut foreign = account.clone();
    foreign.station_id = arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap();
    assert!(
        validate_prepared_join_signing_scope(
            &foreign,
            &account,
            &scope,
            Some(&scope),
            Some(scope.device_id.as_str())
        )
        .is_err()
    );
    let mut switched = scope.clone();
    switched.device_id =
        arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap();
    assert!(
        validate_prepared_join_signing_scope(
            &account,
            &account,
            &scope,
            Some(&switched),
            Some(switched.device_id.as_str())
        )
        .is_err()
    );
    assert!(
        validate_prepared_join_signing_scope(
            &account,
            &account,
            &scope,
            None,
            Some(scope.device_id.as_str())
        )
        .is_err()
    );
    assert!(
        validate_prepared_join_signing_scope(
            &account,
            &account,
            &scope,
            Some(&scope),
            Some(switched.device_id.as_str())
        )
        .is_err()
    );
}
