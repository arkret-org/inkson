use serde_json::json;

use super::*;

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
    let actor_id = crate::mls_api_helpers::principal_core_id(actor_id).unwrap();
    serde_json::from_value(json!({
        "kind": kind,
        "scope_ref": {"kind": "realm", "realm_id": realm_id},
        "actor_id": actor_id,
        "principal_server_id": "ak:did_core:web:principal.example",
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
fn managed_agent_pcr_genesis_does_not_bypass_control_proposal_ack_authoring() {
    let mut managed = realm_create_sdk_event(
        "ak:event:Af2HCFbsrVezIXsZGcgB3mjkpqGK-C4DmteWaG3H0Xbh",
        "did:web:agent.example",
    );
    managed.executed_by =
        Some(arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap());
    managed.authorization_ref = Some(
        arkret_sdk::AuthorizationRef::new("did:web:agent.example#managed-controller").unwrap(),
    );

    assert!(crate::authorization_lease::is_managed_agent_pcr_genesis(
        &managed
    ));
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
fn scheduled_dispatch_crash_retry_preserves_exact_signed_event_bytes() {
    let event: arkret_sdk::Event = serde_json::from_value(json!({
        "event_id": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "kind": "ak.message.create",
        "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "scope_ref": {
            "kind": "realm",
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
        },
        "actor_id": "ak:did_core:web:alice.example",
        "principal_server_id": "ak:did_core:web:principal.example",
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
            crate::event_signer::EventProofContext::default(),
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
        "did:web:bob.example",
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
    let actor_id = crate::mls_api_helpers::principal_core_id(actor_id).unwrap();
    serde_json::from_value(json!({
        "event_id": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "kind": "ak.presence",
        "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"},
        "actor_id": actor_id,
        "principal_server_id": "ak:did_core:web:principal.example",
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
    let actor_id = crate::mls_api_helpers::principal_core_id(actor_id).unwrap();
    serde_json::from_value(json!({
        "event_id": event_id,
        "kind": kind,
        "realm_id": realm_id,
        "scope_ref": {"kind": "realm", "realm_id": realm_id},
        "actor_id": actor_id,
        "principal_server_id": "ak:did_core:web:principal.example",
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
    let created_by = crate::mls_api_helpers::principal_core_id(created_by).unwrap();
    let mut event: arkret_sdk::Event = serde_json::from_value(json!({
        "event_id": event_id,
        "kind": "ak.realm.create",
        "scope_ref": {"kind": "realm_genesis"},
        "actor_id": created_by,
        "principal_server_id": "ak:did_core:web:principal.example",
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
            controller_id: AUTHORITY_CONTROLLER_CORE.to_owned()
        })
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
    assert!(!realm_owner_covers_event_kind("ak.realm.create"));
    assert!(!realm_owner_covers_event_kind("ak.not.a.kind"));
}

#[test]
fn realm_authority_root_claim_stamps_only_the_matching_controller() {
    let root = RealmCreateAuthority::Root {
        controller_id: AUTHORITY_CONTROLLER_CORE.to_owned(),
    };
    let event = |actor: &str| sdk_intent_with_kind(AUTHORITY_REALM, "ak.strand.create", actor);

    assert_eq!(
        realm_authority_root_claim(&event(AUTHORITY_CONTROLLER), Some(&root)),
        Some(arkret_sdk::AuthorizationRef::new(arkret_wire::REALM_AUTHORITY_ROOT_CELL).unwrap())
    );
    assert_eq!(
        realm_authority_root_claim(&event("did:web:bob.example"), Some(&root)),
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
        controller_id: AUTHORITY_CONTROLLER_CORE.to_owned(),
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
            .with_executed_by(
                arkret_sdk::DidCoreId::new("ak:did_core:web:service.example").unwrap(),
            );
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

fn test_authority() -> arkret_sdk::PrincipalAuthorityKey {
    arkret_sdk::PrincipalAuthorityKey::new(
        arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:server.example".to_owned()).unwrap(),
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
                controller_id: AUTHORITY_CONTROLLER_CORE.to_owned(),
            },
        );
    let intent = dead_endpoint_submitter()
        .stamp_realm_authority_root_claim(sdk_intent_with_kind(
            realm,
            "ak.strand.create",
            AUTHORITY_CONTROLLER,
        ))
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
                controller_id: AUTHORITY_CONTROLLER_CORE.to_owned(),
            },
        );
    // Outage-era intent: owner-authored kind, but no claim was resolvable
    // at enqueue time.
    let frozen = sdk_intent_with_kind(realm, "ak.message.create", AUTHORITY_CONTROLLER);
    assert!(frozen.authorization_ref().is_none());

    // Fresh authoring would stamp (the claim is resolvable from cache)…
    let freshly_authored = dead_endpoint_submitter()
        .stamp_realm_authority_root_claim(frozen.clone())
        .await;
    assert!(freshly_authored.authorization_ref().is_some());

    // …but a replay of the frozen intent must reproduce its choice verbatim,
    // or the authored envelope diverges from the intent it is bound to.
    let frozen_queued = fixture_queued_intent(frozen.clone());
    let replayed = dead_endpoint_submitter()
        .author_frozen_intent(&frozen_queued, "frozen-operation")
        .await;
    // The dead endpoint fails the attempt later, at the seal fetch; what
    // this test pins down is that the claim decision was never revisited.
    assert!(replayed.is_err());
    assert!(
        fixture_queued_intent(frozen.clone())
            .authorization_ref()
            .is_none(),
        "frozen-intent replay stamped a claim the intent does not carry"
    );
}

#[tokio::test]
async fn stamp_realm_authority_root_claim_swallows_lookup_failures() {
    // Unknown Realm + unreachable endpoint: the claim must be skipped, not
    // fail the submit — a member's ordinary grant path stays usable when
    // the create lookup is unavailable.
    let intent = dead_endpoint_submitter()
        .stamp_realm_authority_root_claim(sdk_intent_with_kind(
            "ak:realm:ARKSHgBichO7ZjwprTMf4UrKn7x1GHkl16zz6U4xm586",
            "ak.strand.create",
            AUTHORITY_CONTROLLER,
        ))
        .await;
    assert!(intent.authorization_ref().is_none());
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
                controller_id: AUTHORITY_CONTROLLER_CORE.to_owned(),
            },
        );
    let operation = crate::operation::ak_ops::kanban_card_strand_create(
        realm,
        AUTHORITY_CONTROLLER,
        "ak:space:Aa5chVG-4dxTy5sBQLuc7faYg5r3Odrl_3Q7uLf7FY_Y",
        "ak:space:ARO6sshXyY_8aIrsd0F5-zoAcfxTRnG5n7zA6tFwGX2l",
        "probe card",
        "a0",
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
                controller_id: AUTHORITY_CONTROLLER_CORE.to_owned(),
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
    // CBA basis it resolved for this attempt, and the holder-local alias.
    // None of those is part of the operation, so none may make the attempt
    // stop expressing the intent it is bound to.
    let mut authored = intent
        .with_prev_refs(vec![fixture_event_id(
            "ak:event:AdymfEYKFegRsXpyi5Or3ormR7igvbwtXIp8HyMfOvWE",
        )])
        .with_seal_ref(
            arkret_sdk::SealId::new(
                "ak:seal:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_owned(),
            )
            .unwrap(),
        )
        .with_auth_context(arkret_sdk::AuthContext {
            key_id: arkret_sdk::OpaqueLocalId::new("device").unwrap(),
            key_epoch: 0,
            credential_epoch: None,
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
            )
            .expect("the Proposal signs");
    }
    let authored_proposal = proposal.event().clone();
    let producer = authored_proposal
        .proofs
        .iter()
        .find_map(arkret_sdk::EventProof::as_producer)
        .cloned()
        .expect("the authored Proposal has its producer proof");
    let mut accepted_proposal = authored_proposal.clone();
    accepted_proposal.proofs.push(
        arkret_sdk::PrincipalServerAdmissionProof {
            kind: arkret_sdk::PrincipalServerAdmissionProofKind::PrincipalServerAdmission,
            verification_method: arkret_sdk::DidUrl::new(
                "did:web:principal.example#admission-1",
            )
            .unwrap(),
            event_digest: producer.event_digest.clone(),
            producer_proof_digest:
                arkret_sdk::PrincipalServerAdmissionProof::producer_proof_digest(&producer)
                    .unwrap(),
            producer_verification_method: producer.verification_method.clone(),
            producer_signing_key_did: arkret_sdk::DidKey::new("did:key:z6MkhFixtureDeviceKey")
                .unwrap(),
            producer_signer_resolution_evidence_ref: producer
                .signer_resolution_evidence_ref
                .clone(),
            producer_signer_resolution_evidence_digest: producer
                .signer_resolution_evidence_digest
                .clone(),
            signer_resolution_evidence_ref: arkret_sdk::SignerEvidenceRef::new(format!(
                "ak:signer_evidence:sha256:{}",
                "11".repeat(32)
            ))
            .unwrap(),
            signer_resolution_evidence_digest: arkret_sdk::Hash::new(format!(
                "sha256:{}",
                "11".repeat(32)
            ))
            .unwrap(),
            accepted_at: authored_proposal.created_at,
            jws: "header..admission".to_owned(),
        }
        .into(),
    );
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
        "actor_id": "ak:did_core:web:alice.example",
        "principal_server_id": "ak:did_core:web:principal.example",
        "created_at": "2026-05-19T00:00:00.000Z",
        "payload": {"proposal_refs": [proposal.event_id()]}
    }))
    .unwrap();
    let commit = crate::operation::author_intent_for_test_at_seq(commit_intent.clone(), 2);
    let mut welcome = crate::operation::author_intent_for_test_at_seq(
        serde_json::from_value::<EventIntent>(json!({
            "kind": "ak.mls.welcome",
            "scope_ref": {"kind": "realm", "realm_id": realm_id},
            "actor_id": "ak:did_core:web:alice.example",
            "principal_server_id": "ak:did_core:web:principal.example",
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
            )
            .expect("the Welcome signs");
    }
    let snapshot = crate::mls::persistence::MlsSnapshotEnvelope {
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
            stage: MlsAdmissionStage::WelcomesAuthored,
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
        arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
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
        crate::event_builders::test_single_signer_notary("did:web:alice.example").unwrap(),
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
        arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
        8,
        vec![
            arkret_sdk::EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1")
                .unwrap(),
        ],
        arkret_sdk::canonical::DigestSuite::Sha256,
    )
    .unwrap();

    let error = actor_chain_basis_from_frontier(&realm_id, intent.actor_id().as_str(), mismatched)
        .unwrap_err()
        .to_string();

    assert!(error.contains("realm actor frontier mismatch"), "{error}");
}

#[test]
fn an_empty_frontier_authors_the_first_chain_position() {
    let intent = EventIntent::from_authored(&sdk_event_without_proof("did:web:alice.example"));
    let frontier = arkret_sdk::RealmActorFrontierView::new(
        intent.realm_id_opt().unwrap().clone(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
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
async fn realm_bootstrap_preparation_requires_a_described_principal_server() {
    crate::operation::set_authoring_principal_server_id(Some(
        arkret_sdk::DidCoreId::new("ak:did_core:web:server.example").unwrap(),
    ));
    let _signer = crate::event_signer::ActiveSignerTestGuard::replace(Some(std::sync::Arc::new(
        crate::event_signer::build_ed25519_device_signer(
            [42_u8; 32],
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-a11ce0000001",
        ),
    )));
    let steps = crate::event_builders::build_realm_bootstrap_steps(
        arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
        "did:web:alice.example",
        "did:web:server.example",
        crate::event_builders::test_single_signer_notary("did:web:server.example").unwrap(),
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
        .expect_err("authoring must resolve the selected Principal Server");
    crate::operation::set_proof_mode(previous_proof_mode);
    assert!(format!("{error:#}").contains("server describe"));
}

#[tokio::test]
async fn ordinary_event_preparation_requires_describe_before_remote_frontier() {
    crate::operation::set_authoring_principal_server_id(Some(
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
    ));
    let intent = EventIntent::from_authored(&sdk_event_without_proof("did:web:alice.example"));
    let http = arkret_sdk::http_client::Client::builder("http://127.0.0.1:9/".parse().unwrap())
        .allow_insecure_localhost()
        .build()
        .unwrap();

    let error = EventSubmitter::new(http)
        .with_authority(test_authority())
        .author_independent_events(vec![intent])
        .await
        .expect_err("ordinary Realm Event must refresh its combined actor frontier");

    let detail = format!("{error:#}");
    assert!(
        detail.contains("server describe"),
        "unexpected preparation error: {detail}"
    );
}

#[test]
fn actor_seq_cas_conflict_classifier_is_narrow() {
    let current_frontier = arkret_sdk::RealmActorFrontierView::new(
        arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
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
        error: ErrorEnvelope::new(
            "cas_conflict",
            "actor_seq is older than the accepted actor frontier",
        )
        .with_detail("accepted", details["accepted"].clone())
        .with_detail("current_frontier", details["current_frontier"].clone()),
    }
    .into();
    assert!(crate::api_error::is_actor_seq_cas_conflict_error(&cas));

    let different_conflict: anyhow::Error = TransportClientError {
        status: StatusCode::CONFLICT,
        error: ErrorEnvelope::new("cas_conflict", "expected head mismatch"),
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
        snapshot_bootstrap: None,
        next_cursor: None,
        prev_cursor: None,
        has_more: false,
        range_completeness: None,
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
