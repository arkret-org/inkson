use std::collections::BTreeSet;

use serde_json::json;

use super::*;

const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
const OTHER_REALM: &str = "ak:realm:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk";
const PRINCIPAL: &str = "did:web:alice.example";
const PRINCIPAL_CORE: &str = "ak:did_core:web:alice.example";
const DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000001";

fn realm_id(value: &str) -> arkret_sdk::RealmId {
    arkret_sdk::RealmId::new(value.to_owned()).unwrap()
}

fn test_authority() -> arkret_sdk::AccountId {
    crate::test_support::authority_at_station(
        PRINCIPAL_CORE,
        crate::test_support::SERVER_STATION_ID,
    )
}

fn account_actor() -> arkret_sdk::ActorId {
    arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        crate::mls_api_helpers::principal_core_id(PRINCIPAL).unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
    ))
}

/// A committed Event as the Station hands it back.
///
/// A producer Event carries no chain position, predecessor or logical clock,
/// so the fixture has nothing to invent beyond the content itself.
fn event_with_kind(event_id: &str, realm: &str, kind: &str, payload: Value) -> arkret_sdk::Event {
    serde_json::from_value(json!({
        "event_id": event_id,
        "kind": kind,
        "realm_id": realm,
        "scope_ref": {"kind": "realm", "realm_id": realm},
        "actor_id": account_actor(),
        "created_at": "2026-05-19T00:00:00.000Z",
        "payload": payload
    }))
    .unwrap()
}

fn message_intent(realm: &str, strand_id: &str) -> EventIntent {
    serde_json::from_value(json!({
        "kind": "ak.message.create",
        "scope_ref": {"kind": "realm", "realm_id": realm},
        "actor_id": account_actor(),
        "created_at": "2026-05-19T00:00:00.000Z",
        "payload": {
            "strand_id": strand_id,
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "body": "hello"}
        }
    }))
    .unwrap()
}

fn test_signer() -> crate::event_signer::InksonEventSigner {
    crate::event_signer::build_ed25519_device_signer([73; 32], PRINCIPAL, DEVICE)
}

/// Finalize and sign one intent the way production does: the identity is
/// derived from the finished content, then a single producer proof is added.
fn author_and_sign(
    intent: EventIntent,
    signer: &crate::event_signer::InksonEventSigner,
) -> arkret_sdk::AuthoredEvent {
    let mut event = intent
        .author_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
        .unwrap();
    signer
        .sign_sdk_event_with_context(
            &mut event,
            crate::event_signer::test_producer_proof_context(arkret_sdk::DigestSuite::Sha256),
        )
        .unwrap();
    event
}

fn detached_signature(
    context: arkret_wire::DetachedSignatureContext,
) -> arkret_wire::DetachedObjectSignature {
    arkret_wire::DetachedObjectSignature {
        context,
        signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
        verification_method: arkret_wire::DidUrl::new("did:web:authority.example#key-1").unwrap(),
        signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
        created_at: chrono::DateTime::parse_from_rfc3339("2026-05-19T00:00:01.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        sig: arkret_wire::Base64UrlString::new("AA").unwrap(),
    }
}

/// One authority-signed commit that covers `event` at `position` of the
/// Event's own scope stream.
fn commit_for(event: &arkret_sdk::Event, position: u64) -> arkret_wire::RealmCommit {
    arkret_wire::RealmCommit {
        commit_id: arkret_wire::RealmCommitId::from_digest([position as u8 + 1; 32]),
        realm_id: event.realm_id.clone(),
        stream_ref: arkret_wire::CommitStreamRef::from_scope(
            &event.scope_ref,
            Some(event.realm_id.clone()),
        )
        .unwrap(),
        stream_position: position,
        previous_commit_ref: (position > 0)
            .then(|| arkret_wire::RealmCommitId::from_digest([position as u8; 32])),
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            arkret_wire::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [9; 32]),
        ),
        committed_at: chrono::DateTime::parse_from_rfc3339("2026-05-19T00:00:02.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        signature: detached_signature(arkret_wire::DetachedSignatureContext::RealmCommit),
    }
}

fn local_state_store(tag: &str) -> crate::state::LocalStateStore {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    crate::state::LocalStateStore::with_path(
        std::env::temp_dir().join(format!("inkson-event-submit-{tag}-{stamp}.json")),
    )
}

// ───────────────────────────── authoring gates ─────────────────────────────

#[test]
fn founding_realm_bypasses_only_its_own_local_detail_freshness_gap() {
    let founding = realm_id(REALM);

    assert!(!local_detail_blocks_authoring(
        Some(&founding),
        founding.as_str(),
        true,
    ));
    assert!(local_detail_blocks_authoring(
        Some(&founding),
        OTHER_REALM,
        true,
    ));
    assert!(local_detail_blocks_authoring(None, founding.as_str(), true));
    assert!(!local_detail_blocks_authoring(
        None,
        founding.as_str(),
        false
    ));
}

#[test]
fn recovery_gate_cache_key_normalizes_full_and_core_principal_ids() {
    let device_id = "ak:device:01964137-0000-7000-8000-0000000000a1";
    assert_eq!(
        normalized_recovery_gate_cache_key("did:web:alice.example", device_id),
        normalized_recovery_gate_cache_key("ak:did_core:web:alice.example", device_id)
    );
}

#[test]
fn account_authority_client_allows_only_insecure_loopback() {
    assert!(account_authority_http_client("http://localhost:8787").is_ok());
    assert!(account_authority_http_client("http://127.0.0.1:8787").is_ok());
    assert!(account_authority_http_client("http://accounts.example").is_err());
}

/// The grant's issuer signature is the Event envelope proof: no nested grant
/// proof exists on the wire, and validating the payload must not add one.
#[test]
fn capability_payload_validation_reads_the_intent_without_changing_it() {
    let genesis = event_with_kind(
        "ak:event:ASgi2U7PbVyNs4UpiQAoXKoHv84g07gpBvuddCGiMMG1",
        REALM,
        "ak.realm.create",
        json!({"object": {}}),
    );
    let basis = crate::operation::ak_ops::IssuerRealmAuthorityBasis {
        authority_generation: 0,
        authority_event_ref: genesis.event_id.clone(),
    };
    let operation = crate::operation::ak_ops::capability_grant_actions(
        REALM,
        PRINCIPAL,
        &crate::test_support::authority("did:web:bob.example"),
        &["ak.message.create"],
        None,
        Value::Null,
        &basis,
    )
    .unwrap()
    .build_sdk_event("inkson")
    .unwrap();
    let before = operation.intent().clone();

    validate_capability_grant_payload(operation.intent()).unwrap();

    assert_eq!(operation.intent(), &before);
    assert!(before.payload()["grant"].get("proofs").is_none());
}

#[tokio::test]
async fn event_actor_station_must_match_the_captured_authority() {
    let intent = message_intent(
        REALM,
        "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
    );
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
        "unexpected authoring error: {detail}"
    );
}

// ─────────────────────────── retry classification ──────────────────────────

#[test]
fn a_transport_failure_is_retryable_and_keeps_its_cause() {
    let error = anyhow::Error::new(arkret_sdk::http_client::Error::Http(
        "browser offline".to_owned(),
    ))
    .context("submit queued Event");

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
fn a_deterministic_refusal_is_never_retried_locally() {
    let error = anyhow::anyhow!("the Station refused this Event with a policy error");

    assert_eq!(outbound_retry_delay(&error), None);
}

// ──────────────────────────── queue projections ────────────────────────────

/// Build one queue snapshot out of frozen submissions plus their statuses.
fn snapshot_of(
    items: Vec<(arkret_sdk::AuthoredEvent, SendQueueStatus)>,
) -> garth::SendQueueSnapshot {
    let mut queue = garth::SendQueue::default();
    let now = chrono::Utc::now();
    for (event, _) in &items {
        queue
            .enqueue(event_submission(event).unwrap(), now)
            .unwrap();
    }
    let mut snapshot = queue.snapshot();
    for (queued, (event, status)) in snapshot.items.iter_mut().zip(items.iter()) {
        queued.status = *status;
        if *status == SendQueueStatus::Committed {
            queued.submission.state = garth::SubmissionState::Committed {
                status: arkret_wire::AuthorityCommitStatus::Committed,
                commit: Box::new(commit_for(event.event(), 0)),
            };
        }
    }
    snapshot
}

#[test]
fn pending_chat_projection_ignores_settled_items_and_other_conversations() {
    let signer = test_signer();
    let strand = "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h";
    let other_strand = "ak:strand:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk";

    let pending = author_and_sign(message_intent(REALM, strand), &signer);
    let committed_send = author_and_sign(
        message_intent(REALM, strand).with_created_at(
            chrono::DateTime::parse_from_rfc3339("2026-05-19T00:00:05.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        ),
        &signer,
    );
    let other_strand_send = author_and_sign(message_intent(REALM, other_strand), &signer);

    let snapshot = snapshot_of(vec![
        (pending.clone(), SendQueueStatus::Queued),
        (committed_send, SendQueueStatus::Committed),
        (other_strand_send, SendQueueStatus::Queued),
    ]);

    assert_eq!(
        pending_chat_event_ids_from_snapshot(&snapshot, REALM, strand),
        BTreeSet::from([pending.event_id().to_string()]),
        "only the unsettled send in this Strand is pending"
    );
}

#[test]
fn the_genesis_lane_projection_counts_committed_and_unsettled_attempts() {
    let signer = test_signer();
    let genesis_intent: EventIntent = serde_json::from_value(json!({
        "kind": "ak.mls.genesis",
        "scope_ref": {"kind": "realm", "realm_id": REALM},
        "actor_id": account_actor(),
        "created_at": "2026-05-19T00:00:00.000Z",
        "payload": {}
    }))
    .unwrap();
    let genesis = author_and_sign(genesis_intent, &signer);

    let queued = snapshot_of(vec![(genesis.clone(), SendQueueStatus::Queued)]);
    assert!(durable_mls_genesis_for_realm_from_snapshot(&queued, REALM));

    let committed = snapshot_of(vec![(genesis.clone(), SendQueueStatus::Committed)]);
    assert!(
        durable_mls_genesis_for_realm_from_snapshot(&committed, REALM),
        "the window between commit and local projection is not absence"
    );

    let cancelled = snapshot_of(vec![(genesis, SendQueueStatus::Cancelled)]);
    assert!(!durable_mls_genesis_for_realm_from_snapshot(
        &cancelled, REALM
    ));
    assert!(!durable_mls_genesis_for_realm_from_snapshot(
        &committed,
        OTHER_REALM
    ));
}

#[test]
fn mls_genesis_event_lookup_filters_kind_and_realm() {
    let expected =
        arkret_sdk::EventId::new("ak:event:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy").unwrap();
    let events = vec![
        event_with_kind(
            "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            REALM,
            "ak.message.create",
            json!({}),
        ),
        event_with_kind(
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
            OTHER_REALM,
            "ak.mls.genesis",
            json!({}),
        ),
        event_with_kind(expected.as_str(), REALM, "ak.mls.genesis", json!({})),
    ];

    assert_eq!(
        mls_genesis_event_id_from_events(&events, REALM),
        Some(expected)
    );
    assert_eq!(
        mls_genesis_event_id_from_events(
            &events,
            "ak:realm:AfXCJ1DUe3g7MVHuVBpMsl89749WyrXAJP7EvoU9mwBH"
        ),
        None
    );
}

// ─────────────────────── optimistic-row reconciliation ─────────────────────

#[test]
fn enqueueing_stamps_the_final_event_identity_on_the_optimistic_row() {
    let signer = test_signer();
    let event = author_and_sign(
        message_intent(
            REALM,
            "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        ),
        &signer,
    );
    let local_operation_id = "0196419b-0000-7000-8000-000000000001";
    let mut store = local_state_store("queued-identity");
    store.upsert_raw_operation(
        local_operation_id,
        None,
        json!({"kind": "ak.message.create", "write_state": "queued"}),
    );

    assert!(record_queued_operation_identity(
        &mut store,
        local_operation_id,
        event.event_id()
    ));

    let state = store.load();
    let row = state
        .raw_operations
        .iter()
        .find(|row| row.operation_id == local_operation_id)
        .expect("the optimistic row stays addressable by its holder-local id");
    assert_eq!(row.payload["event_id"], event.event_id().as_str());
    assert_eq!(row.payload["write_state"], "queued");
    assert_eq!(
        local_operation_for_event(&state, event.event_id()).as_deref(),
        Some(local_operation_id),
        "the durable queue joins back to the operation through the stamped id"
    );
}

#[test]
fn a_committed_item_moves_its_optimistic_row_to_accepted() {
    let signer = test_signer();
    let event = author_and_sign(
        message_intent(
            REALM,
            "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        ),
        &signer,
    );
    let local_operation_id = "0196419b-0000-7000-8000-000000000002";
    let mut store = local_state_store("committed-row");
    store.upsert_raw_operation(
        local_operation_id,
        None,
        json!({"kind": "ak.message.create", "write_state": "queued"}),
    );
    record_queued_operation_identity(&mut store, local_operation_id, event.event_id());

    let snapshot = snapshot_of(vec![(event.clone(), SendQueueStatus::Committed)]);
    assert!(reconcile_settled_outbound_item(
        &mut store,
        &snapshot.items[0]
    ));

    let state = store.load();
    let row = &state.raw_operations[0];
    assert_eq!(row.operation_id, local_operation_id);
    assert_eq!(row.payload["write_state"], "accepted");
    assert_eq!(row.payload["event_id"], event.event_id().as_str());
}

#[test]
fn a_rejected_item_reports_the_station_reason_code_on_its_row() {
    let signer = test_signer();
    let event = author_and_sign(
        message_intent(
            REALM,
            "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        ),
        &signer,
    );
    let local_operation_id = "0196419b-0000-7000-8000-000000000003";
    let mut store = local_state_store("rejected-row");
    store.upsert_raw_operation(
        local_operation_id,
        None,
        json!({"kind": "ak.message.create", "write_state": "queued"}),
    );
    record_queued_operation_identity(&mut store, local_operation_id, event.event_id());

    let mut snapshot = snapshot_of(vec![(event, SendQueueStatus::Queued)]);
    let item = &mut snapshot.items[0];
    item.status = SendQueueStatus::Rejected;
    item.submission.state = garth::SubmissionState::Rejected {
        status: arkret_wire::AuthorityRejectionStatus::Rejected,
        reason_code: "policy_violation".to_owned(),
    };

    assert!(reconcile_settled_outbound_item(&mut store, item));
    let state = store.load();
    assert_eq!(state.raw_operations[0].payload["write_state"], "rejected");
    assert_eq!(state.raw_operations[0].payload["error"], "policy_violation");

    let error = settled_outbound_result(item)
        .expect_err("a Station refusal is an error for the calling write");
    assert!(crate::ephemeral::authority_rejected_for_reason(
        &error,
        "policy_violation"
    ));
}

#[test]
fn a_committed_item_yields_the_commit_that_covers_exactly_this_event() {
    let signer = test_signer();
    let event = author_and_sign(
        message_intent(
            REALM,
            "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        ),
        &signer,
    );
    let snapshot = snapshot_of(vec![(event.clone(), SendQueueStatus::Committed)]);

    let result = settled_outbound_result(&snapshot.items[0]).unwrap();

    assert!(result.is_committed());
    assert_eq!(result.event_id, event.event_id().as_str());
    assert_eq!(result.stream_position(), Some(0));
    assert_eq!(
        result.stream_ref(),
        Some(&arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id(REALM)
        })
    );
}

#[test]
fn queued_and_forwarding_items_never_report_realm_commit_acceptance() {
    let signer = test_signer();
    let event = author_and_sign(
        message_intent(
            REALM,
            "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        ),
        &signer,
    );
    for status in [SendQueueStatus::Queued, SendQueueStatus::Forwarding] {
        let snapshot = snapshot_of(vec![(event.clone(), status)]);
        let error = settled_outbound_result(&snapshot.items[0])
            .expect_err("a local pending state must not be reported as accepted");
        assert!(is_durably_queued_error(&error), "{status:?}: {error:#}");
    }
}

// ───────────────────── durable submission state transitions ────────────────

/// One scripted governance-authority transport.
///
/// It answers exactly one submit per queued Event, so a test can observe the
/// full queued → forwarding → settled transition through the real engine
/// rather than asserting on a hand-written state machine.
#[derive(Clone)]
struct ScriptedAuthority {
    outcome: arkret_wire::AuthoritySubmitOutcome,
    submits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl garth::AuthorityTransport for ScriptedAuthority {
    async fn submit(
        &self,
        _request: &arkret_wire::AuthoritySubmitRequest,
        _options: &arkret_sdk::http_client::ClientRequestOptions,
    ) -> garth::Result<arkret_wire::AuthoritySubmitOutcome> {
        self.submits
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(self.outcome.clone())
    }

    async fn scan(
        &self,
        _request: &arkret_wire::StreamScanRequest,
    ) -> garth::Result<arkret_wire::StreamScanOutcome> {
        Err(garth::Error::Protocol("scan is not scripted".to_owned()))
    }

    async fn authority_bundle(
        &self,
        _request: &arkret_wire::AuthorityBundleRequest,
    ) -> garth::Result<arkret_wire::RealmAuthorityBundle> {
        Err(garth::Error::Protocol("bundle is not scripted".to_owned()))
    }

    async fn install_handoff(
        &self,
        _request: &arkret_wire::AuthorityHandoffRequest,
        _options: &arkret_sdk::http_client::ClientRequestOptions,
    ) -> garth::Result<arkret_wire::RealmAuthorityHandoff> {
        Err(garth::Error::Protocol("handoff is not scripted".to_owned()))
    }
}

fn scripted_engine(
    outcome: arkret_wire::AuthoritySubmitOutcome,
) -> (
    OutboundEngine<garth::MemoryOutboundQueueStore, InksonHostClock>,
    garth::AuthorityClient<ScriptedAuthority>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    let submits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    (
        OutboundEngine::new(garth::MemoryOutboundQueueStore::new(), InksonHostClock),
        garth::AuthorityClient::new(ScriptedAuthority {
            outcome,
            submits: submits.clone(),
        }),
        submits,
    )
}

#[tokio::test]
async fn a_queued_write_reaches_committed_through_the_durable_engine() {
    let signer = test_signer();
    let event = author_and_sign(
        message_intent(
            REALM,
            "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        ),
        &signer,
    );
    let commit = commit_for(event.event(), 4);
    let (engine, authority, submits) =
        scripted_engine(arkret_wire::AuthoritySubmitOutcome::Accepted {
            status: arkret_wire::AuthorityCommitStatus::Committed,
            commit: commit.clone(),
        });

    engine
        .enqueue(event_submission(&event).unwrap())
        .await
        .unwrap();
    let queued = engine.snapshot().await.unwrap();
    assert_eq!(queued.items[0].status, SendQueueStatus::Queued);
    assert!(queued.items[0].commit().is_none());

    let outcome = engine
        .submit_next(
            &authority,
            &arkret_sdk::http_client::ClientRequestOptions::new(),
        )
        .await
        .unwrap();

    let garth::OutboundEngineOutcome::Committed { item, commit: got } = outcome else {
        panic!("a scripted acceptance must commit the queued Event");
    };
    assert_eq!(item.status, SendQueueStatus::Committed);
    assert_eq!(got.event_ref, *event.event_id());
    assert_eq!(got.stream_position, 4);
    assert_eq!(submits.load(std::sync::atomic::Ordering::SeqCst), 1);

    // A committed item is terminal: the engine never forwards it again.
    assert!(matches!(
        engine
            .submit_next(
                &authority,
                &arkret_sdk::http_client::ClientRequestOptions::new()
            )
            .await
            .unwrap(),
        garth::OutboundEngineOutcome::Idle
    ));
    assert_eq!(submits.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_station_refusal_settles_the_item_with_its_exact_reason_code() {
    let signer = test_signer();
    let event = author_and_sign(
        message_intent(
            REALM,
            "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        ),
        &signer,
    );
    let (engine, authority, _) = scripted_engine(arkret_wire::AuthoritySubmitOutcome::Rejected {
        status: arkret_wire::AuthorityRejectionStatus::Rejected,
        reason_code: "mls_activation_required".to_owned(),
    });

    engine
        .enqueue(event_submission(&event).unwrap())
        .await
        .unwrap();
    let outcome = engine
        .submit_next(
            &authority,
            &arkret_sdk::http_client::ClientRequestOptions::new(),
        )
        .await
        .unwrap();

    let garth::OutboundEngineOutcome::Rejected { item, reason_code } = outcome else {
        panic!("a scripted refusal must settle the queued Event as rejected");
    };
    assert_eq!(reason_code, "mls_activation_required");
    assert_eq!(item.status, SendQueueStatus::Rejected);
    assert_eq!(
        SubmitEventResult::from(&*item)
            .rejection_reason_code
            .as_deref(),
        Some("mls_activation_required"),
        "the Station's reason code reaches the caller verbatim"
    );
}

// ─────────────────────────── MLS commit submission ─────────────────────────

fn welcome_delivery(commit_event: &arkret_sdk::Event, nth: u64) -> arkret_wire::MlsWelcomeDelivery {
    arkret_wire::MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new_v7_at(1_760_000_000_000 + nth),
        realm_id: commit_event.realm_id.clone(),
        effective_scope: commit_event.scope_ref.clone(),
        commit_event_ref: commit_event.event_id.clone(),
        recipient_actor_id: account_actor(),
        recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: arkret_wire::DeviceId::new(DEVICE.to_owned()).unwrap(),
        },
        keypackage_claim_ref: arkret_wire::KeypackageClaimId::new_v7_at(1_760_000_000_000 + nth),
        ciphertext_b64: arkret_wire::Base64UrlString::new("AQID").unwrap(),
        producer_proof: detached_signature(
            arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
        ),
    }
}

fn mls_commit_event(signer: &crate::event_signer::InksonEventSigner) -> arkret_sdk::AuthoredEvent {
    let intent: EventIntent = serde_json::from_value(json!({
        "kind": "ak.mls.commit",
        "scope_ref": {"kind": "realm", "realm_id": REALM},
        "actor_id": account_actor(),
        "created_at": "2026-05-19T00:00:00.000Z",
        "payload": {}
    }))
    .unwrap();
    author_and_sign(intent, signer)
}

#[tokio::test]
async fn one_mls_commit_and_its_welcomes_are_a_single_atomic_submission() {
    let signer = test_signer();
    let commit_event = mls_commit_event(&signer);
    let welcomes = vec![
        welcome_delivery(commit_event.event(), 2),
        welcome_delivery(commit_event.event(), 1),
    ];
    let mut sorted = welcomes.clone();
    sorted.sort_by(|left, right| left.welcome_id.cmp(&right.welcome_id));

    let submission = QueuedSubmission::new(arkret_wire::AuthoritySubmitRequest::MlsCommit(
        arkret_wire::MlsCommitSubmission {
            commit_event: commit_event.event().clone(),
            welcomes: sorted.clone(),
            idempotency_key: arkret_wire::UuidV7::new(arkret_sdk::identifiers::uuid_v7_at(
                1_760_000_000_000,
            ))
            .unwrap(),
        },
    ))
    .expect("a commit plus its sorted Welcome deliveries is one valid submission");

    assert_eq!(&submission.event_id, commit_event.event_id());

    let commit = commit_for(commit_event.event(), 1);
    let (engine, authority, _) = scripted_engine(arkret_wire::AuthoritySubmitOutcome::Accepted {
        status: arkret_wire::AuthorityCommitStatus::Committed,
        commit,
    });
    engine.enqueue(submission).await.unwrap();

    // The frozen queue item still carries every Welcome: nothing delivers
    // them separately, and nothing waits for a recipient acknowledgement.
    let queued = engine.snapshot().await.unwrap();
    let arkret_wire::AuthoritySubmitRequest::MlsCommit(stored) = queued.items[0].request() else {
        panic!("the MLS lane freezes an MlsCommit submission");
    };
    assert_eq!(stored.welcomes, sorted);

    let outcome = engine
        .submit_next(
            &authority,
            &arkret_sdk::http_client::ClientRequestOptions::new(),
        )
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        garth::OutboundEngineOutcome::Committed { .. }
    ));
}

#[test]
fn unsorted_welcome_deliveries_are_refused_before_anything_is_queued() {
    let signer = test_signer();
    let commit_event = mls_commit_event(&signer);
    let mut welcomes = vec![
        welcome_delivery(commit_event.event(), 1),
        welcome_delivery(commit_event.event(), 2),
    ];
    welcomes.reverse();

    let error = QueuedSubmission::new(arkret_wire::AuthoritySubmitRequest::MlsCommit(
        arkret_wire::MlsCommitSubmission {
            commit_event: commit_event.event().clone(),
            welcomes,
            idempotency_key: arkret_wire::UuidV7::new(arkret_sdk::identifiers::uuid_v7_at(
                1_760_000_000_000,
            ))
            .unwrap(),
        },
    ))
    .expect_err("Welcome deliveries must be sorted and unique by welcome_id");

    assert!(format!("{error}").contains("sorted"));
}

// ──────────────────────────── replay generation fence ──────────────────────

fn principal_core() -> arkret_sdk::DidCoreId {
    crate::mls_api_helpers::principal_core_id(PRINCIPAL).unwrap()
}

#[test]
fn the_fence_forwards_a_write_signed_by_this_devices_current_method() {
    let signer = test_signer();
    let event = author_and_sign(
        message_intent(
            REALM,
            "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        ),
        &signer,
    );

    assert_eq!(
        generation_decision_for_signer(
            &principal_core(),
            signer.verification_method(),
            event.event()
        ),
        GenerationFenceDecision::Current
    );
}

#[test]
fn a_superseded_signing_method_quarantines_the_queued_write() {
    let signer = test_signer();
    let event = author_and_sign(
        message_intent(
            REALM,
            "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        ),
        &signer,
    );
    let replacement = crate::event_signer::build_ed25519_device_signer([91; 32], PRINCIPAL, DEVICE)
        .verification_method()
        .to_owned();
    let replacement = format!("{replacement}-generation-2");

    assert_eq!(
        generation_decision_for_signer(&principal_core(), &replacement, event.event()),
        GenerationFenceDecision::Quarantine {
            reason: "authoring_generation_superseded".to_owned()
        },
        "a write signed under a replaced device generation must never be forwarded"
    );
}

#[test]
fn a_write_this_device_did_not_author_is_left_to_its_own_principal() {
    let signer = test_signer();
    let event = author_and_sign(
        message_intent(
            REALM,
            "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        ),
        &signer,
    );
    let other_principal =
        arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example".to_owned()).unwrap();

    assert_eq!(
        generation_decision_for_signer(
            &other_principal,
            "did:web:bob.example#device",
            event.event()
        ),
        GenerationFenceDecision::Current
    );
}

#[tokio::test]
async fn a_quarantined_item_is_withdrawn_instead_of_forwarded() {
    let signer = test_signer();
    let event = author_and_sign(
        message_intent(
            REALM,
            "ak:strand:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        ),
        &signer,
    );
    let (engine, authority, submits) =
        scripted_engine(arkret_wire::AuthoritySubmitOutcome::Accepted {
            status: arkret_wire::AuthorityCommitStatus::Committed,
            commit: commit_for(event.event(), 0),
        });
    engine
        .enqueue(event_submission(&event).unwrap())
        .await
        .unwrap();

    // The host resolves the fence and withdraws the item itself: garth's
    // engine has no fence hook, and a cancelled item is never claimed.
    assert!(engine.cancel(event.event_id().clone()).await.unwrap());

    assert!(matches!(
        engine
            .submit_next(
                &authority,
                &arkret_sdk::http_client::ClientRequestOptions::new()
            )
            .await
            .unwrap(),
        garth::OutboundEngineOutcome::Idle
    ));
    assert_eq!(
        submits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a quarantined write must never reach the Station"
    );
    assert_eq!(
        engine.snapshot().await.unwrap().items[0].status,
        SendQueueStatus::Cancelled
    );
}
