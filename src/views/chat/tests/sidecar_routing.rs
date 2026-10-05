//! Private routed echo and sidecar-projection visibility.

use super::*;

#[test]
fn circle_scope_request_is_single_flight_and_semantically_deduplicated() {
    let key = "https://example.test\u{1f}ak:did_core:web:alice\u{1f}ak:realm:one";
    assert!(!should_start_circle_scope_request("", "", false, key));
    assert!(should_start_circle_scope_request("grant", "", false, key));
    assert!(!should_start_circle_scope_request("grant", key, false, key));
    assert!(!should_start_circle_scope_request("grant", "", true, key));
    assert!(should_start_circle_scope_request(
        "grant",
        key,
        false,
        "https://example.test\u{1f}ak:did_core:web:alice\u{1f}ak:realm:two",
    ));
}

#[test]
fn pending_display_joins_history_without_reordering_accepted_rows() {
    let strand = "ak:strand:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N";
    let at = |seconds| chrono::DateTime::from_timestamp(seconds, 0);
    let mut first = sidecar_projection_message("first", strand, "first accepted");
    first.created_at = at(20);
    let mut second = sidecar_projection_message("second", strand, "second accepted");
    second.created_at = at(10);
    let mut pending = sidecar_projection_message("pending", strand, "new send");
    pending.created_at = at(30);
    pending.pending = true;
    let mut failed = sidecar_projection_message("failed", strand, "older failed send");
    failed.created_at = at(5);
    failed.failed = true;
    let projected = position_local_timeline_rows(vec![pending, failed, first, second]);
    assert_eq!(
        projected
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        vec!["failed", "first", "second", "pending"]
    );
    let settled = projected
        .into_iter()
        .map(|mut row| {
            row.pending = false;
            row
        })
        .collect();
    assert_eq!(
        position_local_timeline_rows(settled).last().unwrap().id,
        "pending"
    );
}

#[test]
fn chat_message_matches_protocol_id_after_server_rekeys_render_id() {
    let mut message = sidecar_projection_message(
        "ak:message:Ams1BtISTcaHSjyArAO3RssCwK-vFi70Bs1FzWVrXhck",
        "ak:strand:AsLgUd73PSI9_dWVG49ZfkmPc0yCUf4zdrfGlSidlNnU",
        "hello",
    );
    message.protocol_message_id =
        Some("ak:message:Ams1BtISTcaHSjyArAO3RssCwK-vFi70Bs1FzWVrXhck".to_owned());
    message.id = "ak:event:ApfLd21JpG9eFxiZSOjnlVNQnQV8Bu7OP_TAtMdAAa30".to_owned();

    assert!(
        message.matches_id_or_protocol("ak:event:ApfLd21JpG9eFxiZSOjnlVNQnQV8Bu7OP_TAtMdAAa30")
    );
    assert!(
        message.matches_id_or_protocol("ak:message:Ams1BtISTcaHSjyArAO3RssCwK-vFi70Bs1FzWVrXhck")
    );
    assert!(
        !message.matches_id_or_protocol("ak:message:A8a_riy5QTAQw2ZF0lV4Wr_lyFIe2yzXKQYapE970EXw")
    );
}

#[test]
fn committed_retry_hides_only_its_rejected_bubble_and_keeps_signed_audit() {
    let realm = "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5";
    let strand = "ak:strand:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N";
    let fixture = |at: &str, target: &str| {
        signed_chat_event(
            "ak.message.create",
            realm,
            json!({"kind":"account","account_id":{
                "principal_id":"ak:did_core:web:alice.example",
                "station_id":"ak:did_core:web:principal.example"
            }}),
            at,
            json!({"content":{"kind":"ak.content.text","body":"hello"},"strand_id":target,"track_name":"discussion"}),
        )
    };
    let previous = fixture("2026-07-08T01:44:39.000Z", strand);
    let replacement = fixture("2026-07-08T01:44:40.000Z", strand);
    let prior_id = previous["event_id"].as_str().unwrap();
    let replacement_id = replacement["event_id"].as_str().unwrap();
    let path = std::env::temp_dir().join(format!("chat-retry-{}.json", uuid_v7()));
    let mut store = LocalStateStore::with_path(&path);
    store.append_raw_operation(
        "old-send",
        Some(realm.into()),
        json!({
            "event":previous,"event_id":prior_id,"write_state":"rejected","error":"denied"
        }),
    );
    store.mark_message_retry_replacement(realm, prior_id, replacement_id);
    let retained = store.load().raw_operations[0].payload.clone();
    assert_eq!(retained["event"], previous);
    assert_eq!(retained["write_state"], "rejected");
    let retry =
        |status| json!({"event":replacement,"event_id":replacement_id,"write_state":status});
    for status in ["queued", "rejected"] {
        let rows = chat_messages_from_events_with_sidecar(
            realm,
            &[retained.clone(), retry(status)],
            None,
            None,
        );
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(|row| row.id == prior_id && row.failed));
    }
    let rows = chat_messages_from_events_with_sidecar(
        realm,
        &[retained.clone(), retry("committed")],
        None,
        None,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, replacement_id);
    let wrong_strand = fixture(
        "2026-07-08T01:44:41.000Z",
        "ak:strand:AsLgUd73PSI9_dWVG49ZfkmPc0yCUf4zdrfGlSidlNnU",
    );
    assert!(chat_message_from_event(realm, &wrong_strand).is_some());
    let mut wrong_ref = retained.clone();
    wrong_ref["retry_replacement_event_id"] = wrong_strand["event_id"].clone();
    let wrong_rows =
        chat_messages_from_events_with_sidecar(realm, &[wrong_ref, wrong_strand], None, None);
    assert_eq!(
        wrong_rows.len(),
        2,
        "wrong-strand retry rows: {wrong_rows:?}"
    );
    let reopened = LocalStateStore::with_path(&path);
    assert_eq!(reopened.load().raw_operations[0].payload, retained);
    let _ = std::fs::remove_file(path);
}

#[test]
fn signed_sidecar_event_with_source_strand_id_never_enters_ordinary_timeline() {
    let realm = "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5";
    let source = "ak:strand:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N";
    let mut shared = json!({
        "event_id": "ak:event:ATrYU3cGlcWkAcHXWgJ8sIYfraoV9pIwEHNNStEqHvFh",
        "kind": "ak.message.create",
        "realm_id": realm,
        "scope_ref": {"kind": "realm", "realm_id": realm},
        "actor_id": {"kind":"account","account_id":{
            "principal_id":"ak:did_core:web:alice.example",
            "station_id":"ak:did_core:web:principal.example"
        }},
        "created_at": "2026-07-08T01:44:39.000Z",
        "payload": {
            "content": {"kind":"ak.content.text","body":"shared"},
            "strand_id": source,
            "track_name": "discussion"
        }
    });
    let mut private = shared.clone();
    private["event_id"] = json!("ak:event:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc");
    private["scope_ref"] = json!({
        "kind": "sidecar",
        "realm_id": realm,
        "sidecar_id": "ak:sidecar:AWea2MtI5dOI1LSRyI266_gQVrWUd0po0dxZiJNsH8kN"
    });
    private["payload"]["content"]["body"] = json!("private");
    sign_chat_fixture(&mut shared);
    sign_chat_fixture(&mut private);
    assert_eq!(
        verify_committed_chat_producer_proof(&shared),
        ChatProofVerdict::Verified
    );
    assert_eq!(
        verify_committed_chat_producer_proof(&private),
        ChatProofVerdict::Verified
    );

    let events = vec![private, shared];
    let synced = chat_messages_from_events_with_sidecar(realm, &events, None, None);
    assert_eq!(synced.len(), 1);
    assert_eq!(synced[0].body, "shared");
    assert_eq!(
        project_visible_messages(&synced, source, realm, None, &[], false).len(),
        1,
        "an ordinary Realm view still displays verified durable rows"
    );
    let mut private_pending = sidecar_projection_message_for_realm(
        realm,
        "local-message:unverified-private",
        source,
        "private optimistic body",
    );
    private_pending.pending = true;
    let mut original_pending = sidecar_projection_message_for_realm(
        realm,
        "local-message:ordinary-queued",
        source,
        "ordinary queued body",
    );
    original_pending.pending = true;
    original_pending.local_scope = Some(arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
    });
    let mut wrong_realm = synced[0].clone();
    wrong_realm.realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".into();
    let mut mixed_rows = synced.clone();
    let mut accepted_private = synced[0].clone();
    accepted_private.id = "ak:event:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc".into();
    accepted_private.body = "private accepted body".into();
    accepted_private.local_scope = Some(arkret_sdk::ScopeRef::Sidecar {
        realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
        sidecar_id: arkret_sdk::SidecarId::new(
            "ak:sidecar:AWea2MtI5dOI1LSRyI266_gQVrWUd0po0dxZiJNsH8kN",
        )
        .unwrap(),
    });
    assert!(
        project_visible_messages(&[accepted_private.clone()], source, realm, None, &[], true)
            .is_empty()
    );
    mixed_rows.extend([
        private_pending,
        accepted_private,
        original_pending.clone(),
        wrong_realm,
    ]);
    assert_eq!(
        project_visible_messages(&mixed_rows, source, realm, Some(source), &[], false),
        vec![synced[0].clone(), original_pending],
        "private verification failure must preserve verified original history and ordinary scoped pending rows, without exposing a private optimistic row or another Realm"
    );

    let records = message_operations_from_events(realm, &events);
    assert_eq!(
        records.len(),
        2,
        "both signed Events reach the local input boundary"
    );
    let local = ClientLocalState {
        raw_operations: records,
        ..ClientLocalState::default()
    };
    let restored = chat_messages_from_local_state_with_sidecar(&local, None, None);
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].body, "shared");
}

#[test]
fn locally_scoped_pending_rows_survive_timeline_rebuild_without_becoming_history() {
    let realm = "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5";
    let strand = "ak:strand:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N";
    let mut row =
        sidecar_projection_message_for_realm(realm, "local-message:queued", strand, "offline");
    row.pending = true;
    row.local_scope = Some(arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
    });
    assert_eq!(
        verified_scope_timeline_seed(&[row.clone()]),
        vec![row.clone()]
    );
    row.pending = false;
    assert!(verified_scope_timeline_seed(&[row.clone()]).is_empty());
    row.failed = true;
    assert_eq!(
        verified_scope_timeline_seed(&[row.clone()]),
        vec![row.clone()]
    );
    row.realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned();
    assert!(verified_scope_timeline_seed(&[row]).is_empty());
}

#[test]
fn unscoped_chat_seed_cannot_enter_ordinary_realm_projection() {
    let realm = "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5";
    let source = "ak:strand:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N";
    // The old optimistic Sidecar row has already lost its signed scope and
    // even uses the ordinary source Strand. Its shape is otherwise identical
    // to a normal local optimistic row, so neither is trusted as a seed.
    let private_seed = sidecar_projection_message_for_realm(
        realm,
        "local-message:old-private-row",
        source,
        "private body",
    );
    let scoped_seed = verified_scope_timeline_seed(&[private_seed.clone()]);
    assert!(scoped_seed.is_empty());
    assert!(project_visible_messages(&scoped_seed, source, realm, None, &[], false).is_empty());
    assert!(
        project_visible_messages(&[private_seed], source, realm, Some(source), &[], false,)
            .is_empty(),
        "unavailable exchange current hides an unscoped private row without treating it as ordinary history"
    );
}

#[test]
fn unverified_projection_tombstone_suppresses_exact_visible_body() {
    let realm = "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5";
    let event_id = "ak:event:ATrYU3cGlcWkAcHXWgJ8sIYfraoV9pIwEHNNStEqHvFh";
    let message_id =
        arkret_sdk::MessageId::from_event_id(&arkret_sdk::EventId::new(event_id).unwrap());
    let mut shared = json!({
        "event_id": event_id,
        "kind": "ak.message.create",
        "realm_id": realm,
        "scope_ref": {"kind": "realm", "realm_id": realm},
        "actor_id": {"kind":"account","account_id":{
            "principal_id":"ak:did_core:web:alice.example",
            "station_id":"ak:did_core:web:principal.example"
        }},
        "created_at": "2026-07-08T01:44:39.000Z",
        "payload": {
            "content": {"kind":"ak.content.text","body":"must not survive redaction"},
            "strand_id":"ak:strand:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N",
            "track_name":"discussion"
        }
    });
    sign_chat_fixture(&mut shared);
    let tombstone = json!({
        "event_id":"ak:event:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc",
        "kind":"ak.message.revise",
        "realm_id":realm,
        "actor_id":{"kind":"account","account_id":{
            "principal_id":"ak:did_core:web:alice.example",
            "station_id":"ak:did_core:web:principal.example"
        }},
        "payload":{
            "message_id":message_id.as_str(),
            "redacted":true,
            "state":"redacted",
            "content":{"kind":"ak.content.text","body":"[redacted]"}
        },
        "unsigned":{"projection_only":true,"local_target_ref":message_id.as_str()},
        "producer_proof":null
    });
    let ordinary = chat_messages_from_events_with_sidecar(realm, &[shared.clone()], None, None);
    assert_eq!(ordinary.len(), 1);
    assert_eq!(ordinary[0].body, "must not survive redaction");
    let mut cross_realm = tombstone.clone();
    cross_realm["realm_id"] = json!("ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0");
    let cross_realm_result =
        chat_messages_from_events_with_sidecar(realm, &[shared.clone(), cross_realm], None, None);
    assert_eq!(cross_realm_result.len(), 1);
    assert_eq!(cross_realm_result[0].body, "must not survive redaction");

    let mut no_target = tombstone.clone();
    no_target["payload"]
        .as_object_mut()
        .unwrap()
        .remove("message_id");
    no_target["unsigned"]
        .as_object_mut()
        .unwrap()
        .remove("local_target_ref");
    let no_target_result =
        chat_messages_from_events_with_sidecar(realm, &[shared.clone(), no_target], None, None);
    assert_eq!(no_target_result.len(), 1);
    assert_eq!(no_target_result[0].body, "must not survive redaction");

    assert!(
        chat_messages_from_events_with_sidecar(realm, &[shared.clone(), tombstone], None, None,)
            .is_empty()
    );

    // A local replacement may keep a different create EventId. Its explicit
    // protocol message_id, not that EventId, is the exact suppression target.
    let local_replacement = json!({
        "event_id":"ak:event:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc",
        "kind":"ak.message.create",
        "realm_id":realm,
        "message_id":message_id.as_str(),
        "redacted":true,
        "state":"redacted",
        "producer_proof":null
    });
    assert!(
        chat_messages_from_events_with_sidecar(realm, &[shared, local_replacement], None, None)
            .is_empty()
    );
}

/// §7.2.1 producer shape: the typed request binding lives ONLY in the
/// `encrypted_metadata` plaintext (`message_metadata.sidecar_exchange_binding`)
/// and round-trips through the SDK's fail-closed consumer accessor; the wire
/// message payload carries no plaintext `metadata` at all.
#[test]
fn routed_request_binding_travels_only_in_encrypted_metadata_plaintext() {
    let context = arkret_sdk::AgentSidecarExchangeRequestContext {
        source_track_ref: arkret_sdk::SidecarSourceTrackRef {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5",
            )
            .unwrap(),
            strand_id: arkret_sdk::StrandId::new(
                "ak:strand:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N",
            )
            .unwrap(),
            track_name: "discussion".to_owned(),
        },
        source_hlc: arkret_sdk::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        client_order_key: "device-1-1".to_owned(),
        addressed_agent_ids: vec![
            crate::mls_api_helpers::principal_core_id(
                "ak:did_core:web:example.test:agents:assistant",
            )
            .unwrap(),
        ],
        coordinator_agent_id: None,
        source_checkpoint_anchor_id: None,
    };
    let binding = arkret_sdk::AgentSidecarEventExchangeBinding {
        schema: arkret_sdk::SchemaId::AGENT_SIDECAR_EVENT_EXCHANGE_BINDING_V1.to_owned(),
        exchange_id: "exchange-01964137000000000008".to_owned(),
        role: arkret_sdk::AgentSidecarExchangeRole::Request,
        request_event_id: None,
        completes_exchange: None,
        coordinator_assignment_event_id: None,
        request_context: Some(context),
    };
    binding.validate_shape().unwrap();
    let mut metadata = arkret_sdk::MessageMetadata::default();
    crate::sidecar::set_sidecar_exchange_binding(&mut metadata, &binding).unwrap();

    // The encrypted_metadata plaintext is exactly the MessageMetadata JSON
    // with the binding under the spec key.
    let plaintext = serde_json::to_value(&metadata).unwrap();
    assert!(plaintext.get("sidecar_exchange_binding").is_some());
    let parsed: arkret_sdk::MessageMetadata = serde_json::from_value(plaintext).unwrap();
    assert_eq!(
        crate::sidecar::sidecar_exchange_binding(&parsed),
        Some(binding)
    );

    // The content block on the encrypted send path never carries the binding.
    let chat_content = chat_content_block_for_body("hi @assistant").unwrap();
    let content_value = chat_content.to_value().unwrap();
    assert!(
        !serde_json::to_string(&content_value)
            .unwrap()
            .contains("sidecar_exchange_binding"),
        "the content block never carries the binding"
    );
}

#[test]
fn sidecar_native_message_never_appears_in_the_source_without_a_projection() {
    let realm = "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5";
    let source = "ak:strand:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N";
    let private = "ak:strand:AcbZeQX0xMn0M0LtYe9f9_xr8Z7FPPgaq35ALTQg0tks";
    let native = "ak:event:ATrYU3cGlcWkAcHXWgJ8sIYfraoV9pIwEHNNStEqHvFh";
    let messages = vec![sidecar_projection_message_for_realm(
        realm, native, private, "native",
    )];

    assert!(project_visible_messages(&messages, source, realm, None, &[], true).is_empty());
}

fn timeline_exchange_fixture(
    request: &str,
    response: &str,
) -> arkret_sdk::AgentSidecarExchangeProjection {
    let request = arkret_sdk::EventId::new(request).unwrap();
    let response = arkret_sdk::EventId::new(response).unwrap();
    let agent =
        crate::mls_api_helpers::principal_core_id("did:web:example.test:agents:assistant").unwrap();
    arkret_sdk::AgentSidecarExchangeProjection {
        schema: arkret_sdk::SchemaId::AGENT_SIDECAR_EXCHANGE_PROJECTION_V1.to_owned(),
        controller_account_id: local_fixture_account("did:web:alice.example"),
        sidecar_id: arkret_sdk::SidecarId::new(
            "ak:sidecar:AWea2MtI5dOI1LSRyI266_gQVrWUd0po0dxZiJNsH8kN",
        )
        .unwrap(),
        exchange_id: "exchange-display-fixture".to_owned(),
        source_track_ref: arkret_sdk::SidecarSourceTrackRef {
            realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5",
            )
            .unwrap(),
            strand_id: arkret_sdk::StrandId::new(
                "ak:strand:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N",
            )
            .unwrap(),
            track_name: "discussion".to_owned(),
        },
        source_event_id: None,
        source_hlc: arkret_sdk::Hlc::from_components(10_000, 0, "a13f9c2e").unwrap(),
        client_order_key: "display-fixture".to_owned(),
        addressed_agent_ids: vec![agent.clone()],
        coordinator_agent_id: agent.clone(),
        coordinator_assignment_event_id: request.clone(),
        participating_agent_ids: vec![agent],
        private_request_event_id: request.clone(),
        user_facing_response_event_ids: vec![response.clone()],
        status: arkret_sdk::AgentSidecarExchangeStatus::Responding,
        failure_reason_code: None,
        terminal_event_id: None,
        folded_checkpoint: arkret_sdk::AgentSidecarFoldedCheckpoint {
            event_ids: vec![request, response],
            event_set_digest: arkret_sdk::Hash::new(format!("sha256:{}", "00".repeat(32))).unwrap(),
            max_hlc: arkret_sdk::Hlc::from_components(15_000, 0, "a13f9c2e").unwrap(),
        },
    }
}

#[test]
fn new_ordinary_messages_follow_older_private_history_in_the_merged_feed() {
    let request = "ak:event:ATrYU3cGlcWkAcHXWgJ8sIYfraoV9pIwEHNNStEqHvFh";
    let response = "ak:event:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc";
    let projection = timeline_exchange_fixture(request, response);
    projection.validate_shape().unwrap();
    let realm = projection.source_track_ref.realm_id.as_str();
    let source = projection.source_track_ref.strand_id.as_str();
    let row = |id, seconds| {
        let mut row = sidecar_projection_message_for_realm(realm, id, source, id);
        row.created_at = chrono::DateTime::from_timestamp(seconds, 0);
        row
    };
    let mut request_row = row(request, 10);
    request_row.created_at = None;
    let rows = vec![
        row("ordinary-old", 20),
        row("ordinary-new", 30),
        request_row,
        row(response, 15),
    ];
    let projected = project_visible_messages(
        &rows,
        source,
        realm,
        None,
        std::slice::from_ref(&projection),
        true,
    );
    assert_eq!(
        projected
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        vec![request, response, "ordinary-old", "ordinary-new"]
    );
    assert_eq!(
        project_visible_messages(
            &rows,
            source,
            realm,
            None,
            std::slice::from_ref(&projection),
            false
        )
        .iter()
        .map(|row| row.id.as_str())
        .collect::<Vec<_>>(),
        vec!["ordinary-old", "ordinary-new"]
    );
}

#[test]
fn merged_feed_preserves_both_stream_orders_despite_clock_skew() {
    let request = "ak:event:ATrYU3cGlcWkAcHXWgJ8sIYfraoV9pIwEHNNStEqHvFh";
    let response = "ak:event:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc";
    let projection = timeline_exchange_fixture(request, response);
    let realm = projection.source_track_ref.realm_id.as_str();
    let source = projection.source_track_ref.strand_id.as_str();
    let row = |id, seconds| {
        let mut row = sidecar_projection_message_for_realm(realm, id, source, id);
        row.created_at = chrono::DateTime::from_timestamp(seconds, 0);
        row
    };
    let rows = vec![
        row("ordinary-first", 20),
        row("ordinary-second", 5),
        row(request, 10),
        row(response, 1),
    ];
    let projected = project_visible_messages(
        &rows,
        source,
        realm,
        None,
        std::slice::from_ref(&projection),
        true,
    );
    assert_eq!(
        projected
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        vec![request, response, "ordinary-first", "ordinary-second"]
    );
}

#[test]
fn private_echo_stays_after_its_source_anchor_but_before_future_ordinary_messages() {
    let request = "ak:event:ATrYU3cGlcWkAcHXWgJ8sIYfraoV9pIwEHNNStEqHvFh";
    let response = "ak:event:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc";
    let anchor_id = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [11; 32]);
    let anchor = anchor_id.as_str();
    let mut projection = timeline_exchange_fixture(request, response);
    projection.source_event_id = Some(anchor_id.clone());
    let realm = projection.source_track_ref.realm_id.as_str();
    let source = projection.source_track_ref.strand_id.as_str();
    let row = |id, seconds| {
        let mut row = sidecar_projection_message_for_realm(realm, id, source, id);
        row.created_at = chrono::DateTime::from_timestamp(seconds, 0);
        row
    };
    let rows = vec![
        row(anchor, 20),
        row("ordinary-new", 30),
        row(request, 10),
        row(response, 15),
    ];
    let projected = project_visible_messages(
        &rows,
        source,
        realm,
        None,
        std::slice::from_ref(&projection),
        true,
    );
    assert_eq!(
        projected
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        vec![anchor, request, response, "ordinary-new"]
    );
    let without_anchor = rows
        .into_iter()
        .filter(|row| row.id != anchor)
        .collect::<Vec<_>>();
    let projected = project_visible_messages(
        &without_anchor,
        source,
        realm,
        None,
        std::slice::from_ref(&projection),
        true,
    );
    assert_eq!(projected.len(), 1);
    assert_eq!(projected[0].id, "ordinary-new");
}
