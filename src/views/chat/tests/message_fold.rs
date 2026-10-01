//! Folding and merging event streams into the timeline projection.

use super::*;

// Positive fold fixtures represent signed ordinary Realm Events. Keep their
// signed scope explicit: an attributed Event with no signed scope is no longer
// eligible for the ordinary timeline, even when payload.strand_id matches.
fn sign_chat_fixture(value: &mut Value) {
    fn add_realm_scope(value: &mut Value) {
        match value {
            Value::Array(values) => values.iter_mut().for_each(add_realm_scope),
            Value::Object(object) => {
                if object.contains_key("actor_id")
                    && !object.contains_key("scope_ref")
                    && let Some(realm_id) = object.get("realm_id").cloned()
                {
                    object.insert(
                        "scope_ref".to_owned(),
                        json!({"kind":"realm","realm_id":realm_id}),
                    );
                }
                object.values_mut().for_each(add_realm_scope);
            }
            _ => {}
        }
    }
    add_realm_scope(value);
    super::sign_chat_fixture(value);
}

fn sign_chat_fixtures(values: &mut [Value]) {
    for value in values {
        sign_chat_fixture(value);
    }
}

fn verified_chat_create(
    realm: &arkret_sdk::RealmId,
    principal: &str,
    body: &str,
) -> arkret_sdk::CommittedEventFullView {
    fixture::committed_event::verified_realm_item_as(
        realm.clone(),
        arkret_sdk::EventKind::MessageCreate.as_str(),
        json!({
            "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "body": body}
        }),
        principal,
        "ak:device:0196419b-0000-7000-8000-000000000001",
    )
}

#[test]
fn optimistic_chat_ids_do_not_claim_protocol_identity() {
    let id = new_chat_local_id();

    assert!(id.starts_with("local-message:"));
    assert!(!is_schema_message_id(&id));
    assert!(!is_schema_message_id(
        "ak:message:AHbH2yLChpf91PjGaWTBKXEDczbsLgmfYK-BPnehnlGI"
    ));
    assert!(!is_schema_message_id("chat-msg-local"));
    assert!(message_id_or_new_local_id("chat-msg-local").starts_with("local-message:"));
}

#[test]
fn restores_messages_from_local_raw_operations() {
    let realm = arkret_sdk::RealmId::new(
        "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI".to_owned(),
    )
    .unwrap();
    let committed = verified_chat_create(&realm, "alice.example", "local fallback message");
    let state = ClientLocalState {
        raw_operations: vec![crate::state::RawOperationRecord {
            operation_id: "ak:operation:local".to_owned(),
            realm_id: Some(realm.to_string()),
            received_at: chrono::Utc::now(),
            payload: serde_json::to_value(&committed.event).unwrap(),
        }],
        ..ClientLocalState::default()
    };

    let messages = chat_messages_from_local_state_with_sidecar(&state, None, None);

    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].realm_id, realm.as_str());
    assert_eq!(
        messages[0].strand_id,
        "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE"
    );
    assert_eq!(messages[0].sender, "ak:did_core:web:alice.example");
    assert_eq!(messages[0].body, "local fallback message");
}

#[test]
fn restores_canonical_actor_id_from_local_raw_operations() {
    let realm = arkret_sdk::RealmId::new(
        "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI".to_owned(),
    )
    .unwrap();
    let committed =
        verified_chat_create(&realm, "local.host:users:alice", "canonical local message");
    let state = ClientLocalState {
        raw_operations: vec![crate::state::RawOperationRecord {
            operation_id: "ak:operation:local".to_owned(),
            realm_id: Some(realm.to_string()),
            received_at: chrono::Utc::now(),
            payload: serde_json::to_value(&committed.event).unwrap(),
        }],
        ..ClientLocalState::default()
    };

    let messages = chat_messages_from_local_state_with_sidecar(&state, None, None);

    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].sender, "ak:did_core:web:local.host:users:alice");
    assert_eq!(messages[0].body, "canonical local message");
}

#[test]
fn message_operations_from_events_folds_create_and_renders_local_first() {
    // Discussion local-first: a canonical `ak.message.create` from the realm
    // timeline folds into a `raw_operations` record (full event payload,
    // dedup id = event_id) that `chat_messages_from_local_state_with_sidecar`
    // renders WITHOUT any backfill — the event-sourced replacement for the
    // per-open realm refetch.
    let realm = arkret_sdk::RealmId::new(
        "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI".to_owned(),
    )
    .unwrap();
    let committed = verified_chat_create(&realm, "bob.example", "hello from bob");
    let create = serde_json::to_value(&committed.event).unwrap();
    // A non-message timeline event (e.g. a poll close) MUST be ignored.
    let poll = json!({
        "event_id": "ak:event:AemHyQfTHaRP4hPsEzDRoY0ybwSW0ZIu_kPanXYJ_cJ8",
        "kind": "ak.content.poll.close",
        "realm_id": "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE"
    });

    let records = message_operations_from_events(realm.as_str(), &[create.clone(), poll]);
    assert_eq!(records.len(), 1, "only the message-create event is folded");
    assert_eq!(records[0].operation_id, committed.event.event_id.as_str());
    assert_eq!(records[0].realm_id.as_deref(), Some(realm.as_str()));
    assert_eq!(
        records[0].payload, create,
        "full event stored for proof/ciphertext"
    );

    let state = ClientLocalState {
        raw_operations: records,
        ..ClientLocalState::default()
    };
    let messages = chat_messages_from_local_state_with_sidecar(&state, None, None);
    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].strand_id,
        "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE"
    );
    assert_eq!(messages[0].sender, "ak:did_core:web:bob.example");
    assert_eq!(messages[0].body, "hello from bob");
}

#[test]
fn chat_messages_do_not_trust_projected_reaction_summary_without_commit() {
    let mut event = json!({
        "event_id": "ak:event:AeXSP2D5ttfuvggcWpTJuFUXOvTRhSBXonyaWHskxaqc",
        "kind": "ak.message.create",
        "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}},
        "realm_id": "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI",
        "created_at": "2026-05-22T10:00:00.000Z",
        "payload": {
            "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
            "content": {"kind": "ak.content.text", "body": "hello from alice"}
        }
    });
    sign_chat_fixture(&mut event);
    // The projected summary rides next to the exact signed Event.
    let events = vec![json!({
        "event": event,
        "reaction_summary": {
            "+1": ["ak:did_core:web:bob.example", "ak:did_core:web:carol.example"]
        }
    })];

    let messages = chat_messages_from_events_with_sidecar(
        "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI",
        &events,
        None,
        None,
    );

    assert_eq!(messages.len(), 1);
    assert!(messages[0].reactions.is_empty());
}

#[test]
fn chat_messages_keep_bare_reaction_events_without_promoting_membership() {
    let mut events = vec![
        json!({
            "event_id": "ak:event:AeXSP2D5ttfuvggcWpTJuFUXOvTRhSBXonyaWHskxaqc",
            "kind": "ak.message.create",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}},
            "realm_id": "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI",
            "created_at": "2026-05-22T10:00:00.000Z",
            "payload": {
                "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
                "message_id": "ak:message:AZhIGxyGMJYSpWhMOugJZewLoNM88CzSBohQQRpKgw1c",
                "content": {"kind": "ak.content.text", "body": "hello from alice"}
            }
        }),
        json!({
            "event_id": "ak:event:AQnQ4vQpIlqkjkQiXR6H-aFpDQtU9QIqZUUOyhD651bQ",
            "kind": "ak.reaction.add",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "realm_id": "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI",
            "created_at": "2026-05-22T10:01:00.000Z",
            "payload": {"target_ref": "ak:message:AZhIGxyGMJYSpWhMOugJZewLoNM88CzSBohQQRpKgw1c", "key": "+1"}
        }),
        json!({
            "event_id": "ak:event:AYAHWeIu5Mo1OonYBugKyH6S4a3sR2DjsutRWGcM-7UY",
            "kind": "ak.reaction.add",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:carol.example","station_id":"ak:did_core:web:principal.example"}},
            "realm_id": "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI",
            "created_at": "2026-05-22T10:02:00.000Z",
            "payload": {"target_ref": "ak:event:AeXSP2D5ttfuvggcWpTJuFUXOvTRhSBXonyaWHskxaqc", "key": "+1"}
        }),
        json!({
            "event_id": "ak:event:AU9fNJ-s5wHOmkdCxh3R42mSETgDQzmk3fMm-gCnHXXw",
            "kind": "ak.reaction.remove",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "realm_id": "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI",
            "created_at": "2026-05-22T10:03:00.000Z",
            "payload": {"target_ref": "ak:message:AZhIGxyGMJYSpWhMOugJZewLoNM88CzSBohQQRpKgw1c", "key": "+1"}
        }),
    ];
    sign_chat_fixtures(&mut events);

    let messages = chat_messages_from_events_with_sidecar(
        "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI",
        &events,
        None,
        None,
    );

    assert_eq!(messages.len(), 1);
    assert!(messages[0].reactions.is_empty());

    let records = message_operations_from_events(
        "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI",
        &events,
    );
    assert_eq!(
        records.len(),
        4,
        "create plus reaction add/remove events must survive raw ingest"
    );
    let state = ClientLocalState {
        raw_operations: records,
        ..ClientLocalState::default()
    };
    let restored = chat_messages_from_local_state_with_sidecar(&state, None, None);
    assert_eq!(restored.len(), 1);
    assert!(restored[0].reactions.is_empty());
}

#[test]
fn chat_messages_do_not_promote_projection_reaction_without_verified_scan() {
    let realm = arkret_sdk::RealmId::new(
        "ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI".to_owned(),
    )
    .unwrap();
    let create_payload = json!({
        "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
        "track_name": "discussion",
        "content": {"kind": "ak.content.text", "body": "projection hello"}
    });
    let create = verified_chat_create(&realm, "bob.example", "projection hello");
    let message_id = arkret_sdk::MessageId::from_event_id(&create.event.event_id);
    let committed = fixture::committed_event::verified_realm_items_as(
        realm.clone(),
        vec![
            (
                arkret_sdk::EventKind::MessageCreate.as_str().to_owned(),
                create_payload,
            ),
            (
                arkret_sdk::EventKind::ReactionAdd.as_str().to_owned(),
                json!({"target_ref": message_id, "key": "+1"}),
            ),
        ],
        "bob.example",
        "ak:device:0196419b-0000-7000-8000-000000000001",
    );
    assert_eq!(committed[0].event.event_id, create.event.event_id);
    assert_eq!(
        committed[0].commit.stream_position + 1,
        committed[1].commit.stream_position
    );
    let unrelated = arkret_sdk::MessageId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::canonical::DigestSuite::Sha256,
        [0x63; 32],
    ));
    assert_ne!(unrelated, message_id);
    let events = vec![
        json!({"event_kind": "ak.message.create", "message_id": unrelated, "event": committed[0].event}),
        json!({"event_kind": "ak.reaction.add", "message_id": unrelated, "event": committed[1].event}),
    ];

    let messages = chat_messages_from_events_with_sidecar(realm.as_str(), &events, None, None);

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].protocol_message_id.as_deref(),
        Some(message_id.as_str())
    );
    assert!(messages[0].reactions.is_empty());

    let records = message_operations_from_events(realm.as_str(), &events);
    assert_eq!(
        records.len(),
        2,
        "message create and reaction projection frames must both survive raw ingest"
    );
    let state = ClientLocalState {
        raw_operations: records,
        ..ClientLocalState::default()
    };
    let restored = chat_messages_from_local_state_with_sidecar(&state, None, None);
    assert_eq!(restored.len(), 1);
    assert_eq!(
        restored[0].protocol_message_id.as_deref(),
        Some(message_id.as_str())
    );
    assert!(restored[0].reactions.is_empty());
}

#[test]
fn chat_messages_keep_streamed_reaction_envelope_provisional_without_commit() {
    let mut events = vec![
        json!({
            "event_id": "ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z",
            "kind": "ak.message.create",
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"},
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}},
            "created_at": "2026-07-08T01:44:39.000Z",
            "payload": {
                "content": {"kind": "ak.content.text", "body": "canonical hello"},
                "strand_id": "ak:strand:AbZt0K_NvenxSDAkOnSDRtorrvUXhGqxSoqT2bFL7m8H",
                "track_name": "discussion"
            }
        }),
        json!({
            "event_id": "ak:event:AbHexNOxiiU334tA-ZHyM5pRxJxbMY0jvwlMVDY3Xjrz",
            "kind": "ak.reaction.add",
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"},
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "created_at": "2026-07-08T01:44:43.000Z",
            "payload": {
                "key": "👍",
                "target_ref": "ak:message:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z"
            }
        }),
    ];
    sign_chat_fixtures(&mut events);

    let records = message_operations_from_events(
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        &events,
    );
    let state = ClientLocalState {
        raw_operations: records,
        ..ClientLocalState::default()
    };
    let messages = chat_messages_from_local_state_with_sidecar(&state, None, None);

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].protocol_message_id.as_deref(),
        Some("ak:message:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z")
    );
    assert!(messages[0].reactions.is_empty());
}

#[test]
fn bare_reaction_does_not_fold_onto_controller_only_create() {
    let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let message_id = "ak:message:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z";
    let mut events = vec![
        json!({
            "event_id": "ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z",
            "kind": "ak.message.create",
            "realm_id": realm_id,
            "scope_ref": {"kind": "realm", "realm_id": realm_id},
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}},
            "created_at": "2026-07-08T01:44:39.000Z",
            "payload": {
                "content": {"kind": "ak.content.text", "body": "optimistic first"},
                "strand_id": "ak:strand:AbZt0K_NvenxSDAkOnSDRtorrvUXhGqxSoqT2bFL7m8H",
                "track_name": "discussion"
            }
        }),
        json!({
            "event_id": "ak:event:AbHexNOxiiU334tA-ZHyM5pRxJxbMY0jvwlMVDY3Xjrz",
            "kind": "ak.reaction.add",
            "realm_id": realm_id,
            "scope_ref": {"kind": "realm", "realm_id": realm_id},
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "created_at": "2026-07-08T01:44:43.000Z",
            "payload": {"key": "👍", "target_ref": message_id}
        }),
    ];
    sign_chat_fixtures(&mut events);

    let seed = chat_messages_from_events_with_sidecar(realm_id, &events[..1], None, None);
    let reaction_records = message_operations_from_events(realm_id, &events[1..]);
    let state = ClientLocalState {
        raw_operations: reaction_records,
        ..ClientLocalState::default()
    };

    let messages = fold_local_state_into_chat_messages_with_sidecar(seed, &state, None, None);

    assert_eq!(messages.len(), 1);
    assert!(messages[0].reactions.is_empty());
}

#[test]
fn durable_redaction_folds_onto_controller_only_create() {
    let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let message_id = "ak:message:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0";
    let seed = vec![ChatMessage {
        local_scope: None,
        id: "ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z".to_owned(),
        protocol_message_id: Some(message_id.to_owned()),
        realm_id: realm_id.to_owned(),
        strand_id: "ak:strand:AbZt0K_NvenxSDAkOnSDRtorrvUXhGqxSoqT2bFL7m8H".to_owned(),
        actor_id: None,
        sender: "ak:did_core:web:alice.example".to_owned(),
        body: "sensitive body".to_owned(),
        content_format: None,
        timestamp: "10:00".to_owned(),
        created_at: None,
        pending: false,
        failed: false,
        error: None,
        executed_by: None,
        edited: false,
        redacted: false,
        revisions: Vec::new(),
        revision_source: None,
        reply_to: None,
        reactions: Vec::new(),
        mentions: Vec::new(),
        crypto_state: MessageCryptoState::Plaintext,
    }];
    let mut redactions = vec![json!({
        "event_id": "ak:event:AbHexNOxiiU334tA-ZHyM5pRxJxbMY0jvwlMVDY3Xjrz",
        "kind": "ak.message.redact",
        "realm_id": realm_id,
        "scope_ref": {"kind": "realm", "realm_id": realm_id},
        "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}},
        "created_at": "2026-07-08T01:44:43.000Z",
        "payload": {"message_id": message_id, "reason": "user requested tombstone"}
    })];
    sign_chat_fixtures(&mut redactions);
    let state = ClientLocalState {
        raw_operations: message_operations_from_events(realm_id, &redactions),
        ..ClientLocalState::default()
    };

    let messages = fold_local_state_into_chat_messages_with_sidecar(seed, &state, None, None);

    assert_eq!(messages.len(), 1);
    assert!(messages[0].redacted);
    assert!(messages[0].body.is_empty());
}

#[test]
fn chat_messages_fold_revision_chain_into_latest_message() {
    let revision_v2 = "ak:event:AegQeQYGPoF9zEbbEIcD8ndn7DUoCaZVaJ9EM6u1rvuo";
    let mut events = vec![
        json!({
            "event_id": "ak:event:AeVYtOcVkQu9JLkr0AO35k8Vn36NgL7qI1NnvHuzyDDs",
            "kind": "ak.message.create",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "realm_id": "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-05-22T10:00:00.000Z",
            "payload": {
                "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
                "message_id": "ak:message:AeVYtOcVkQu9JLkr0AO35k8Vn36NgL7qI1NnvHuzyDDs",
                "content": {"kind": "ak.content.text", "body": "v1"}
            }
        }),
        json!({
            "event_id": revision_v2,
            "kind": "ak.message.revise",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "realm_id": "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-05-22T10:01:00.000Z",
            "payload": {
                "message_id": "ak:message:AeVYtOcVkQu9JLkr0AO35k8Vn36NgL7qI1NnvHuzyDDs",
                "content": {"kind": "ak.content.text", "body": "v2"}
            }
        }),
        json!({
            "event_id": "ak:event:AWDOsZS5t1FOYT8QB0mLKRUnOOqWz9iWSIfk6RKZ91T8",
            "kind": "ak.message.revise",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "realm_id": "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-05-22T10:02:00.000Z",
            "payload": {
                "message_id": "ak:message:AeVYtOcVkQu9JLkr0AO35k8Vn36NgL7qI1NnvHuzyDDs",
                "content": {"kind": "ak.content.text", "body": "v3"}
            }
        }),
    ];
    sign_chat_fixtures(&mut events);

    let messages = chat_messages_from_events_with_sidecar(
        "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &events,
        None,
        None,
    );

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].id,
        "ak:event:AeVYtOcVkQu9JLkr0AO35k8Vn36NgL7qI1NnvHuzyDDs"
    );
    assert_eq!(messages[0].body, "v3");
    assert!(messages[0].edited);
    assert_eq!(
        messages[0].revisions,
        vec!["v1".to_owned(), "v2".to_owned()]
    );

    let incomplete = chat_messages_from_events_with_sidecar(
        "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &[events[0].clone(), events[2].clone()],
        None,
        None,
    );
    // A current-result batch can omit an earlier accepted revision. The
    // later accepted revision still supplies the visible current value.
    assert_eq!(incomplete[0].body, "v3");
    assert_eq!(
        incomplete[0].revision_source,
        Some(
            arkret_sdk::EventId::new(
                "ak:event:AWDOsZS5t1FOYT8QB0mLKRUnOOqWz9iWSIfk6RKZ91T8".to_owned(),
            )
            .unwrap()
            .event_digest(),
        )
    );

    let stale_state = ClientLocalState {
        raw_operations: message_operations_from_events(
            "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            &events[..2],
        ),
        ..ClientLocalState::default()
    };
    let optimistic = fold_local_state_into_chat_messages_with_sidecar(
        messages.clone(),
        &stale_state,
        None,
        None,
    );
    assert_eq!(optimistic[0].body, "v3");
    assert_eq!(
        optimistic[0].revisions,
        vec!["v1".to_owned(), "v2".to_owned()],
        "an older durable fold must not replace a locally projected later revision"
    );

    let records = message_operations_from_events(
        "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &events,
    );
    assert_eq!(
        records.len(),
        3,
        "create and both revisions must survive raw ingest"
    );
    let state = ClientLocalState {
        raw_operations: records,
        ..ClientLocalState::default()
    };
    let restored = chat_messages_from_local_state_with_sidecar(&state, None, None);
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].body, "v3");
    assert_eq!(restored[0].revisions.len(), 2);

    let replayed = fold_local_state_into_chat_messages_with_sidecar(restored, &state, None, None);
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed[0].body, "v3");
    assert_eq!(
        replayed[0].revisions,
        vec!["v1".to_owned(), "v2".to_owned()],
        "replaying durable history onto an already-folded row must not count the current body as a revision"
    );
}

#[test]
fn message_revisions_follow_accepted_commit_order() {
    let message_event = "ak:event:AeVYtOcVkQu9JLkr0AO35k8Vn36NgL7qI1NnvHuzyDDs";
    let message_id = "ak:message:AeVYtOcVkQu9JLkr0AO35k8Vn36NgL7qI1NnvHuzyDDs";
    let revision_a = "ak:event:AegQeQYGPoF9zEbbEIcD8ndn7DUoCaZVaJ9EM6u1rvuo";
    let revision_b = "ak:event:AWDOsZS5t1FOYT8QB0mLKRUnOOqWz9iWSIfk6RKZ91T8";
    let mut events = vec![
        json!({
            "event_id": message_event,
            "kind": "ak.message.create",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "realm_id": "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-05-22T10:00:00.000Z",
            "payload": {
                "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
                "message_id": message_id,
                "content": {"kind": "ak.content.text", "body": "original"}
            }
        }),
        json!({
            "event_id": revision_a,
            "kind": "ak.message.revise",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "realm_id": "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-05-22T10:01:00.000Z",
            "payload": {"message_id": message_id, "content": {"kind": "ak.content.text", "body": "branch a"}}
        }),
        json!({
            "event_id": revision_b,
            "kind": "ak.message.revise",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}},
            "realm_id": "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-05-22T10:02:00.000Z",
            "payload": {"message_id": message_id, "content": {"kind": "ak.content.text", "body": "branch b"}}
        }),
    ];
    sign_chat_fixtures(&mut events);
    let mut reversed = events.clone();
    reversed.reverse();

    let forward = chat_messages_from_events_with_sidecar(
        "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &events,
        None,
        None,
    );
    let backward = chat_messages_from_events_with_sidecar(
        "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &reversed,
        None,
        None,
    );

    let id_a = arkret_sdk::EventId::new(revision_a.to_owned()).unwrap();
    let id_b = arkret_sdk::EventId::new(revision_b.to_owned()).unwrap();
    assert_eq!(forward[0].revision_source, Some(id_b.event_digest()));
    assert_eq!(forward[0].body, "branch b");
    assert_eq!(backward[0].revision_source, Some(id_a.event_digest()));
    assert_eq!(backward[0].body, "branch a");
    let mut visible = forward[0].revisions.clone();
    visible.push(forward[0].body.clone());
    assert!(visible.contains(&"branch a".to_owned()));
    assert!(visible.contains(&"branch b".to_owned()));
}

#[test]
fn chat_messages_keep_folded_timeline_revision_over_older_backfill_create() {
    let message_id = "ak:message:AQeShrdBR3zl1gbuH87IF4AakXuLntks0PE5vC00cCYC";
    let reply_to = "ak:message:AXdL6bIGrKOX2V48TJBOTvyoFqW-S0CMHLws0asddnGj";
    let mut events = vec![
        json!({
            "event_id": "ak:event:AadoaZa-0djgJsY3CYuv_X3xsG9VX8MDqugQkXxFqVPK",
            "kind": "ak.message.revise",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "realm_id": "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-07-07T05:58:23.000Z",
            "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
            "target_ref": message_id,
            "content": {"kind": "ak.content.text", "body": "edited body"}
        }),
        json!({
            "event_id": "ak:event:AQeShrdBR3zl1gbuH87IF4AakXuLntks0PE5vC00cCYC",
            "kind": "ak.message.create",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "realm_id": "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-07-07T05:58:22.000Z",
            "payload": {
                "content": {"kind": "ak.content.text", "body": "original body"},
                "reply_to_id": reply_to,
                "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
                "track_name": "discussion"
            }
        }),
        json!({
            "event_id": "ak:event:AadoaZa-0djgJsY3CYuv_X3xsG9VX8MDqugQkXxFqVPK",
            "kind": "ak.message.revise",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "realm_id": "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-07-07T05:58:23.000Z",
            "payload": {
                "content": {"kind": "ak.content.text", "body": "edited body"},
                "target_ref": message_id
            }
        }),
    ];
    sign_chat_fixtures(&mut events);

    let messages = chat_messages_from_events_with_sidecar(
        "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &events,
        None,
        None,
    );

    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].protocol_message_id.as_deref(), Some(message_id));
    assert_eq!(messages[0].body, "edited body");
    assert_eq!(messages[0].reply_to.as_deref(), Some(reply_to));
    assert!(messages[0].edited);
    assert_eq!(messages[0].revisions, vec!["original body".to_owned()]);
}

#[test]
fn chat_messages_fold_redacted_revision_tombstone_into_root_tombstone() {
    let mut events = vec![
        json!({
            "event_id": "ak:event:AfxNwg4EH3ln9hAfUC_K-ohgQR9Kaedpmn99LHxDfocw",
            "kind": "ak.message.revise",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "realm_id": "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-05-22T10:01:00.000Z",
            "payload": {
                "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
                "target_ref": "ak:message:AQLmz4zWkDYecrEZnVupSWR2EqdHzYP-bSwUXf4qQ82E",
                "redacted": true,
                "state": "redacted",
                "content": {"kind": "ak.content.text", "body": "[redacted]"}
            }
        }),
        json!({
            "event_id": "ak:event:AZyIPFgvmgij09wqLnZMFu6qyMVd1cGRZ3bq2gvBKEfQ",
            "kind": "ak.message.create",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "realm_id": "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-05-22T10:00:00.000Z",
            "payload": {
                "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
                "message_id": "ak:message:AQLmz4zWkDYecrEZnVupSWR2EqdHzYP-bSwUXf4qQ82E",
                "redacted": true,
                "state": "redacted",
                "content": {"kind": "ak.content.text", "body": "[redacted]"}
            }
        }),
    ];
    sign_chat_fixtures(&mut events);

    let messages = chat_messages_from_events_with_sidecar(
        "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &events,
        None,
        None,
    );

    assert_eq!(messages.len(), 1);
    assert!(messages[0].redacted);
}

#[test]
fn chat_messages_do_not_render_standalone_proofless_redacted_revision() {
    let events = vec![json!({
        "event_id": "ak:event:AV7Qnsn3l-7MwwweunecsEKX84zMkYIeBOIm-5M-YYkQ",
        "kind": "ak.message.revise",
        "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
        "realm_id": "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        "created_at": "2026-05-22T10:02:00.000Z",
        "payload": {
            "content": {"kind": "ak.content.text", "body": "[redacted]"},
            "message_id": "ak:message:AQLmz4zWkDYecrEZnVupSWR2EqdHzYP-bSwUXf4qQ82E",
            "redacted": true,
            "redacted_at": "2026-05-22T10:05:00.000Z",
            "redaction_ref": "ak:event:ASDsFwzGYsHL_LWmOT3j7ExtCtCKAbGiXAZDrawyms2Y",
            "state": "redacted"
        },
        "unsigned": {
            "local_target_ref": "ak:message:AQLmz4zWkDYecrEZnVupSWR2EqdHzYP-bSwUXf4qQ82E",
            "projection_only": true
        },
        "producer_proof": null
    })];

    let messages = chat_messages_from_events_with_sidecar(
        "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &events,
        None,
        None,
    );

    // A proofless projection-only tombstone may suppress an already known
    // exact target, but cannot invent an attributed standalone message row.
    assert!(messages.is_empty());
}

#[test]
fn chat_messages_fold_nested_server_redacted_revision_tombstone_into_root_tombstone() {
    let mut events = vec![
        json!({
            "event_id": "ak:event:AXLf0mAo4UUC50gymplf5Oowi6lfIjnA1pl45rHyZXXs",
            "kind": "ak.message.create",
            "realm_id": "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "created_at": "2026-05-22T10:00:00.000Z",
            "payload": {
                "content": {"kind": "ak.content.text", "body": "[redacted]"},
                "event_id": "ak:event:AXLf0mAo4UUC50gymplf5Oowi6lfIjnA1pl45rHyZXXs",
                "message_id": "ak:message:AXLf0mAo4UUC50gymplf5Oowi6lfIjnA1pl45rHyZXXs",
                "redacted": true,
                "redacted_at": "2026-05-22T10:05:00.000Z",
                "redaction_ref": "ak:event:AVDqt89EJm8Vurg41PAsnseqxyxB0Gg-Xr0WywWjcia0",
                "state": "redacted",
                "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE"
            },
            "producer_proof": null
        }),
        json!({
            "event_id": "ak:event:ATU1l-Eisb3OsJErxiFpnMdIrcBcnCih6I8bEfreUYQ4",
            "kind": "ak.message.revise",
            "realm_id": "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "created_at": "2026-05-22T10:01:00.000Z",
            "payload": {
                "content": {"kind": "ak.content.text", "body": "[redacted]"},
                "event_id": "ak:event:ATU1l-Eisb3OsJErxiFpnMdIrcBcnCih6I8bEfreUYQ4",
                "redacted": true,
                "redacted_at": "2026-05-22T10:05:00.000Z",
                "redaction_ref": "ak:event:AVDqt89EJm8Vurg41PAsnseqxyxB0Gg-Xr0WywWjcia0",
                "state": "redacted",
                "message_id": "ak:message:AXLf0mAo4UUC50gymplf5Oowi6lfIjnA1pl45rHyZXXs"
            },
            "producer_proof": null
        }),
    ];
    sign_chat_fixtures(&mut events);

    let messages = chat_messages_from_events_with_sidecar(
        "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &events,
        None,
        None,
    );

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].id,
        "ak:event:AXLf0mAo4UUC50gymplf5Oowi6lfIjnA1pl45rHyZXXs"
    );
    assert!(messages[0].redacted);
}

#[test]
fn merge_chat_messages_dedupes_tombstones_by_protocol_message_id() {
    fn redacted_message(id: &str, protocol_message_id: &str) -> ChatMessage {
        ChatMessage {
            local_scope: None,
            realm_id: "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0".to_owned(),
            id: id.to_owned(),
            protocol_message_id: Some(protocol_message_id.to_owned()),
            actor_id: None,
            sender: "ak:did_core:web:bob.example".to_owned(),
            executed_by: None,
            body: String::new(),
            content_format: None,
            timestamp: "10:05".to_owned(),
            created_at: None,
            strand_id: "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE".to_owned(),
            reply_to: None,
            reactions: Vec::new(),
            redacted: true,
            edited: false,
            revisions: Vec::new(),
            revision_source: None,
            pending: false,
            failed: false,
            error: None,
            mentions: Vec::new(),
            crypto_state: MessageCryptoState::Plaintext,
        }
    }

    let protocol_message_id = "ak:message:AXVgsB123jP90mQo21keg3CLCveTDRLikepykbzkqVDU";
    let mut target = vec![
        redacted_message(
            "ak:event:AcKQoR8zOkA_YLRPM8kfj-LWD-gFyGj0gDzDi1yR8__w",
            protocol_message_id,
        ),
        redacted_message(
            "ak:event:AZIef_emAh7eYAOuF7eGO1bNoy3aKoOtR486JTWV0mwU",
            protocol_message_id,
        ),
        ChatMessage {
            body: "unrelated".to_owned(),
            redacted: false,
            protocol_message_id: Some(
                "ak:message:Aca_riy5QTAQw2ZF0lV4Wr_lyFIe2yzXKQYapE970EXw".to_owned(),
            ),
            id: "ak:event:AUKTSEncSq-7S2g7j9s8ssEEgqbX4On6J9NtKdAwE9rI".to_owned(),
            ..redacted_message(
                "ak:event:AUKTSEncSq-7S2g7j9s8ssEEgqbX4On6J9NtKdAwE9rI",
                "ak:message:Aca_riy5QTAQw2ZF0lV4Wr_lyFIe2yzXKQYapE970EXw",
            )
        },
    ];
    target[0].edited = true;
    target[0].revisions.push("v1".to_owned());

    merge_chat_messages(
        &mut target,
        vec![redacted_message(
            "ak:event:AcKQoR8zOkA_YLRPM8kfj-LWD-gFyGj0gDzDi1yR8__w",
            protocol_message_id,
        )],
    );

    let matching = target
        .iter()
        .filter(|message| message.protocol_message_id.as_deref() == Some(protocol_message_id))
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1);
    assert_eq!(
        matching[0].id,
        "ak:event:AcKQoR8zOkA_YLRPM8kfj-LWD-gFyGj0gDzDi1yR8__w"
    );
    assert!(matching[0].redacted);
    assert!(matching[0].edited);
    assert_eq!(matching[0].revisions, vec!["v1".to_owned()]);
    assert!(
        target
            .iter()
            .any(|message| message.id == "ak:event:AUKTSEncSq-7S2g7j9s8ssEEgqbX4On6J9NtKdAwE9rI")
    );
}

#[test]
fn merge_chat_messages_keeps_newer_revision_when_older_create_arrives_late() {
    fn at(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        Some(
            chrono::DateTime::parse_from_rfc3339(value)
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
    }

    fn message(id: &str, protocol_message_id: &str, body: &str, created_at: &str) -> ChatMessage {
        ChatMessage {
            local_scope: None,
            realm_id: "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0".to_owned(),
            id: id.to_owned(),
            protocol_message_id: Some(protocol_message_id.to_owned()),
            actor_id: None,
            sender: "ak:did_core:web:bob.example".to_owned(),
            executed_by: None,
            body: body.to_owned(),
            content_format: None,
            timestamp: "10:00".to_owned(),
            created_at: at(created_at),
            strand_id: "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE".to_owned(),
            reply_to: Some("ak:message:AZhIGxyGMJYSpWhMOugJZewLoNM88CzSBohQQRpKgw1c".to_owned()),
            reactions: Vec::new(),
            redacted: false,
            edited: false,
            revisions: Vec::new(),
            revision_source: None,
            pending: false,
            failed: false,
            error: None,
            mentions: Vec::new(),
            crypto_state: MessageCryptoState::Plaintext,
        }
    }

    let protocol_message_id = "ak:message:AVrxbbWNTU3fu27uUUMC3ilKugGpnApLyJXvm-E-33Mo";
    let mut target = vec![message(
        "ak:event:AXDTUwNSETOJ-pBxghvljssZF9_39FJn1yECyAVFAlFU",
        protocol_message_id,
        "edited body",
        "2026-07-07T06:19:22.000Z",
    )];
    target[0].edited = true;

    let mut incoming = message(
        "ak:event:AbK5Uaew7bX6Q59MX37cd5ChptN8Mn4AORWZkldj0FBk",
        protocol_message_id,
        "original body",
        "2026-07-07T06:19:20.000Z",
    );
    incoming.reactions = vec![(
        "+1".to_owned(),
        vec![
            "ak:did_core:web:bob.example".to_owned(),
            "ak:did_core:web:carol.example".to_owned(),
        ],
    )];

    merge_chat_messages(&mut target, vec![incoming]);

    assert_eq!(target.len(), 1);
    assert_eq!(
        target[0].id,
        "ak:event:AXDTUwNSETOJ-pBxghvljssZF9_39FJn1yECyAVFAlFU"
    );
    assert_eq!(target[0].body, "edited body");
    assert!(target[0].edited);
    assert_eq!(target[0].revisions, vec!["original body"]);
    assert_eq!(
        target[0].reply_to.as_deref(),
        Some("ak:message:AZhIGxyGMJYSpWhMOugJZewLoNM88CzSBohQQRpKgw1c")
    );
    assert_eq!(
        target[0].reactions,
        vec![(
            "+1".to_owned(),
            vec![
                "ak:did_core:web:bob.example".to_owned(),
                "ak:did_core:web:carol.example".to_owned()
            ],
        )]
    );
}

#[test]
fn durable_echo_settles_newer_optimistic_message_by_protocol_id() {
    let mut optimistic = sidecar_projection_message(
        "ak:message:AWs1BtISTcaHSjyArAO3RssCwK-vFi70Bs1FzWVrXhck",
        "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
        "hello",
    );
    optimistic.protocol_message_id =
        Some("ak:message:AWs1BtISTcaHSjyArAO3RssCwK-vFi70Bs1FzWVrXhck".to_owned());
    optimistic.created_at = Some(chrono::Utc::now());
    optimistic.pending = true;

    let mut durable = sidecar_projection_message(
        "ak:event:AZfLd21JpG9eFxiZSOjnlVNQnQV8Bu7OP_TAtMdAAa30",
        "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
        "hello",
    );
    durable.protocol_message_id =
        Some("ak:message:AWs1BtISTcaHSjyArAO3RssCwK-vFi70Bs1FzWVrXhck".to_owned());
    durable.created_at = None;

    merge_duplicate_create_message(&mut optimistic, durable);

    assert_eq!(
        optimistic.id,
        "ak:message:AWs1BtISTcaHSjyArAO3RssCwK-vFi70Bs1FzWVrXhck"
    );
    assert!(!optimistic.pending);
    assert!(!optimistic.failed);
    assert!(optimistic.error.is_none());
}

#[test]
fn message_operations_redaction_tombstone_dedupes_over_create_by_event_id() {
    // The server folds a redaction into a tombstone form reusing the same
    // `ak.message.create` kind + `event_id`. Both fold to the SAME
    // `operation_id`, so `upsert_raw_operation` replaces the create with the
    // tombstone and the local-first render shows the redacted marker.
    let create = json!({
        "event_id": "ak:event:AbK5Uaew7bX6Q59MX37cd5ChptN8Mn4AORWZkldj0FBk",
        "kind": "ak.message.create",
        "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
        "realm_id": "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        "created_at": "2026-05-22T10:00:00.000Z",
        "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
        "message_id": "ak:message:AVrxbbWNTU3fu27uUUMC3ilKugGpnApLyJXvm-E-33Mo",
        "body": "secret"
    });
    let tombstone = json!({
        "event_id": "ak:event:AbK5Uaew7bX6Q59MX37cd5ChptN8Mn4AORWZkldj0FBk",
        "kind": "ak.message.create",
        "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
        "realm_id": "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        "created_at": "2026-05-22T10:05:00.000Z",
        "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
        "message_id": "ak:message:AVrxbbWNTU3fu27uUUMC3ilKugGpnApLyJXvm-E-33Mo",
        "redacted": true
    });

    let create_record = message_operations_from_events(
        "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &[create],
    );
    let tombstone_record = message_operations_from_events(
        "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &[tombstone],
    );
    assert_eq!(
        create_record[0].operation_id,
        tombstone_record[0].operation_id
    );
}

#[test]
fn message_operations_fold_independent_redaction_event_by_message_id() {
    let realm =
        arkret_sdk::RealmId::new("ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI").unwrap();
    let create_payload = json!({
        "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
        "track_name": "discussion",
        "content": {"kind": "ak.content.text", "body": "secret"}
    });
    // The helper signs and verifies a real Event and its covering RealmCommit.
    // Derive the redact target from the same deterministic create bytes that
    // the contiguous stream below will commit.
    let create_id = fixture::committed_event::verified_realm_item(
        realm.clone(),
        arkret_sdk::EventKind::MessageCreate.as_str(),
        create_payload.clone(),
    )
    .event
    .event_id;
    let message_id = arkret_sdk::MessageId::from_event_id(&create_id);
    let committed = fixture::committed_event::verified_realm_items(
        realm.clone(),
        vec![
            (
                arkret_sdk::EventKind::MessageCreate.as_str().to_owned(),
                create_payload,
            ),
            (
                arkret_sdk::EventKind::MessageRedact.as_str().to_owned(),
                json!({"message_id": message_id, "reason": "user requested tombstone"}),
            ),
        ],
    );
    assert_eq!(committed[0].event.event_id, create_id);
    assert_eq!(committed[0].commit.stream_position, 1);
    assert_eq!(committed[1].commit.stream_position, 2);
    let create = serde_json::to_value(&committed[0].event).unwrap();
    let redaction = serde_json::to_value(&committed[1].event).unwrap();
    let visible =
        chat_messages_from_events_with_sidecar(realm.as_str(), &[create.clone()], None, None);
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].body, "secret");
    assert!(!visible[0].redacted);

    for events in [
        vec![create.clone(), redaction.clone()],
        vec![redaction, create],
    ] {
        let records = message_operations_from_events(realm.as_str(), &events);
        assert_eq!(records.len(), 2);
        let state = ClientLocalState {
            raw_operations: records,
            ..ClientLocalState::default()
        };
        let messages = chat_messages_from_local_state_with_sidecar(&state, None, None);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].redacted);
        assert_eq!(messages[0].body, "");
    }
}

#[test]
fn committed_create_revision_redaction_folds_in_any_arrival_order() {
    let realm =
        arkret_sdk::RealmId::new("ak:realm:AUkVX3O4YS1KHnF-rBBp6xN650srYAO3w11NkWM23fXI").unwrap();
    let create_payload = json!({
        "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
        "track_name": "discussion",
        "content": {"kind": "ak.content.text", "body": "original"}
    });
    let create_id = fixture::committed_event::verified_realm_item(
        realm.clone(),
        arkret_sdk::EventKind::MessageCreate.as_str(),
        create_payload.clone(),
    )
    .event
    .event_id;
    let message_id = arkret_sdk::MessageId::from_event_id(&create_id);
    let committed = fixture::committed_event::verified_realm_items(
        realm.clone(),
        vec![
            (
                arkret_sdk::EventKind::MessageCreate.as_str().to_owned(),
                create_payload,
            ),
            (
                arkret_sdk::EventKind::MessageRevise.as_str().to_owned(),
                json!({
                    "message_id": message_id,
                    "track_name": "discussion",
                    "content": {"kind": "ak.content.text", "body": "edited"}
                }),
            ),
            (
                arkret_sdk::EventKind::MessageRedact.as_str().to_owned(),
                json!({"message_id": message_id, "reason": "withdrawn"}),
            ),
        ],
    );
    assert_eq!(committed[0].event.event_id, create_id);
    assert_eq!(
        committed
            .iter()
            .map(|item| item.commit.stream_position)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    let events = committed
        .iter()
        .map(|item| serde_json::to_value(&item.event).unwrap())
        .collect::<Vec<_>>();
    let before_redaction =
        chat_messages_from_events_with_sidecar(realm.as_str(), &events[..2], None, None);
    assert_eq!(before_redaction.len(), 1);
    assert_eq!(before_redaction[0].body, "edited");
    assert_eq!(before_redaction[0].revisions, vec!["original".to_owned()]);
    assert!(before_redaction[0].edited);

    for ordered in [events.clone(), events.into_iter().rev().collect()] {
        let messages = chat_messages_from_events_with_sidecar(realm.as_str(), &ordered, None, None);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].redacted);
        assert!(messages[0].body.is_empty());
    }
}

#[test]
fn message_operations_from_events_folds_shared_pin_control_events() {
    let strand_id = "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE";
    let pin_scope = SharedPinScope::strand(strand_id);
    let target_ref = "ak:message:AT8ObsRsspa-eB4BB9XHU491RECO-qv_y2FbDrDKRo74";
    let pin = json!({
        "event_id": "ak:event:Ad7uZHFkaOZeWWKBxVQkHwbJkLtnGHpMCcZYcFcswPgc",
        "event_kind": "ak.pin.add",
        "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:mei.example","station_id":"ak:did_core:web:principal.example"}},
        "realm_id": "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        "created_at": "2026-05-22T10:10:00.000Z",
        "payload": {
            "pin_scope": {"kind": "strand", "id": strand_id},
            "target_ref": target_ref,
            "rank": "r001"
        }
    });

    let records = message_operations_from_events(
        "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &[pin],
    );
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].operation_id,
        "ak:event:Ad7uZHFkaOZeWWKBxVQkHwbJkLtnGHpMCcZYcFcswPgc"
    );
    assert_eq!(
        records[0].realm_id.as_deref(),
        Some("ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0")
    );

    let pins = shared_message_pins_from_raw_operations(&records, &pin_scope);
    assert_eq!(
        pins,
        vec![SharedMessagePin::new(
            &pin_scope,
            target_ref.to_owned(),
            "r001".to_owned(),
        )]
    );
}

#[test]
fn local_redaction_tombstone_without_signed_scope_cannot_render_row() {
    let remote_actor = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:remote-station.example").unwrap(),
    ));
    let redacted_at = chrono::DateTime::parse_from_rfc3339("2026-05-22T10:05:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let message = ChatMessage {
        local_scope: None,
        realm_id: "ak:realm:ARqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0".to_owned(),
        id: "ak:event:AeVYtOcVkQu9JLkr0AO35k8Vn36NgL7qI1NnvHuzyDDs".to_owned(),
        protocol_message_id: Some(
            "ak:message:Acg8IZtPYZi06QwoJAIWUIU5xUWxDRtHCQPTUuSSipb8".to_owned(),
        ),
        actor_id: Some(remote_actor.clone()),
        sender: "ak:did_core:web:bob.example".to_owned(),
        executed_by: None,
        body: "secret".to_owned(),
        content_format: None,
        timestamp: "10:00".to_owned(),
        created_at: None,
        strand_id: "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE".to_owned(),
        reply_to: None,
        reactions: Vec::new(),
        redacted: false,
        edited: false,
        revisions: Vec::new(),
        revision_source: None,
        pending: false,
        failed: false,
        error: None,
        mentions: Vec::new(),
        crypto_state: MessageCryptoState::Plaintext,
    };

    let tombstone = local_redaction_tombstone_for_message(
        &message,
        redacted_at,
        Some("ak:event:AeRSupDyayuw4R7tIwZPpZWnF36wsoZuXYPDzQJ-jmhk"),
    );
    assert_eq!(tombstone["event_id"], message.id);
    assert_eq!(
        tombstone["actor_id"],
        serde_json::to_value(remote_actor).unwrap()
    );
    assert_eq!(
        tombstone["message_id"],
        "ak:message:Acg8IZtPYZi06QwoJAIWUIU5xUWxDRtHCQPTUuSSipb8"
    );
    assert_eq!(tombstone["redacted"], true);
    assert_eq!(tombstone["state"], "redacted");
    assert_eq!(
        tombstone["redaction_ref"],
        "ak:event:AeRSupDyayuw4R7tIwZPpZWnF36wsoZuXYPDzQJ-jmhk"
    );
    assert_eq!(
        tombstone["content"]["body"],
        arkret_sdk::events::REDACTED_MESSAGE_PLACEHOLDER
    );
    assert!(tombstone.get("body").is_none());

    let mut state = ClientLocalState {
        raw_operations: vec![crate::state::RawOperationRecord {
            operation_id: message.id.clone(),
            realm_id: Some(message.realm_id.clone()),
            received_at: redacted_at,
            payload: tombstone,
        }],
        ..ClientLocalState::default()
    };
    // This local replacement has no signed scope; it can only suppress an
    // exact existing target, not become a new attributed timeline row.
    super::sign_chat_fixture(&mut state.raw_operations[0].payload);
    let restored = chat_messages_from_local_state_with_sidecar(&state, None, None);
    assert!(restored.is_empty());
}
