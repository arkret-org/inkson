use super::*;

/// The Welcome-receive shuttle iterates `events[]` from
/// `DeviceMessagesGetOutcome` and surfaces only
/// `ck.mls.welcome` payloads.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn collect_welcome_entries_filters_cx_mls_welcome_and_drops_other_kinds() {
    let value = json!({
        "events": [
            {"type": "ck.mls.welcome", "content": {"welcome_envelope_id": "w-1"}},
            {"type": "ck.key.verify.request", "content": {"ignore_me": true}},
            {"type": "ck.mls.welcome", "content": {"welcome_envelope_id": "w-2"}},
            {"type": "ck.mls.welcome", "content": {"welcome_envelope_id": "w-3"}},
            {"type": "ck.device.message", "content": {"ignore_me": true}},
        ]
    });
    let welcomes = crate::mls::runtime::collect_welcome_entries(&value);
    let ids: Vec<&str> = welcomes
        .iter()
        .filter_map(|w| w.get("welcome_envelope_id").and_then(|v| v.as_str()))
        .collect();
    assert_eq!(ids.len(), 3);
    assert!(ids.contains(&"w-1"));
    assert!(ids.contains(&"w-2"));
    assert!(ids.contains(&"w-3"));
}

/// Empty / missing `events` envelope returns no welcomes — the
/// shuttle silently returns instead of panicking.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn collect_welcome_entries_tolerates_missing_events_envelope() {
    assert!(crate::mls::runtime::collect_welcome_entries(&json!({})).is_empty());
    assert!(crate::mls::runtime::collect_welcome_entries(&json!({"events": null})).is_empty());
    assert!(crate::mls::runtime::collect_welcome_entries(&json!({"events": []})).is_empty());
}

#[test]
fn parses_message_event_with_operation_body_shape() {
    let event = json!({
        "id": "ck:event:body-shape",
        "type": "ck.message.create",
        "actor": "did:web:alice.example",
        "realm_id": "ck:realm:demo",
        "created_at": "2026-05-14T01:23:45Z",
        "causal": {"actor_seq": 42},
        "body": {
            "body": "restored from durable history",
            "strand_id": "ck:strand:announce",
            "message_id": "chat-msg-local",
            "mentions": [{
                "kind": "mention",
                "subject_id": "did:web:bob.example",
                "mention_text_original": "@bob"
            }]
        }
    });

    let message = chat_message_from_event("ck:realm:fallback", &event).unwrap();

    assert_eq!(message.id, "ck:event:body-shape");
    assert_eq!(message.realm_id, "ck:realm:demo");
    assert_eq!(message.strand_id, "ck:strand:announce");
    assert_eq!(message.body, "restored from durable history");
    assert_eq!(message.sender, "did:web:alice.example");
    assert_eq!(message.mentions[0].target_id(), "did:web:bob.example");
}

#[test]
fn parses_message_event_with_nested_envelope_payload_shape() {
    let event = json!({
        "event": {
            "event_id": "ck:event:nested",
            "kind": "ck.message.create",
            "actor_id": "did:web:alice.example",
            "actor_seq": 43,
            "payload": {
                "content": {
                    "kind": "ck.content.text",
                    "body": "nested payload message"
                },
                "strand_id": "ck:strand:support",
                "message_id": "chat-msg-nested"
            }
        }
    });

    let message = chat_message_from_event("ck:realm:demo", &event).unwrap();

    assert_eq!(message.id, "ck:event:nested");
    assert_eq!(message.strand_id, "ck:strand:support");
    assert_eq!(message.body, "nested payload message");
}

#[test]
fn chat_message_create_operation_emits_schema_canonical_content() {
    let op = chat_message_create_operation(
        "ck:realm:01904100-0000-7000-8000-000000000010",
        "did:web:alice.example",
        "ck:strand:01904100-0000-7000-8000-000000000001",
        "discussion",
        "ck:message:01904100-0000-7000-8000-000000000001",
        "hello from chat",
        &[],
        None,
    )
    .expect("builds");

    assert_eq!(op.kind, "ck.message.create");
    assert_eq!(
        op.payload["message_id"].as_str(),
        Some("ck:message:01904100-0000-7000-8000-000000000001")
    );
    assert_eq!(
        op.payload["strand_id"].as_str(),
        Some("ck:strand:01904100-0000-7000-8000-000000000001")
    );
    assert_eq!(op.payload["track_name"].as_str(), Some("discussion"));
    assert_eq!(
        op.payload["content"]["kind"].as_str(),
        Some("ck.content.text")
    );
    assert_eq!(
        op.payload["content"]["body"].as_str(),
        Some("hello from chat")
    );
    assert!(op.payload["content"].get("blocks").is_none());
    assert!(op.payload.get("body").is_none());
    assert!(op.payload.get("encrypted").is_none());
    assert!(op.payload.get("kind").is_none());
    assert!(op.payload.get("mentions").is_none());
    assert!(op.payload.get("audience_mentions").is_none());
    assert!(op.payload.get("mention_relations").is_none());
    assert!(op.payload.get("reply_to").is_none());
    assert!(op.payload.get("thread_id").is_none());
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(&op.kind, &op.payload)
        .unwrap();
}

#[test]
fn chat_message_create_operation_embeds_audience_mentions_in_content_only() {
    let mentions = parse_mention_nodes("ping @here and @carol:example.com");
    let op = chat_message_create_operation(
        "ck:realm:01904100-0000-7000-8000-000000000010",
        "did:web:alice.example",
        "ck:strand:01904100-0000-7000-8000-000000000001",
        "discussion",
        "ck:message:01904100-0000-7000-8000-000000000002",
        "ping @here and @carol:example.com",
        &mentions,
        None,
    )
    .expect("builds");

    assert_eq!(
        op.payload["content"]["audience_mentions"][0]["audience"].as_str(),
        Some("strand_engaged")
    );
    assert!(op.payload.get("audience_mentions").is_none());
    assert!(op.payload.get("mentions").is_none());
    assert!(op.payload.get("mention_relations").is_none());
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(&op.kind, &op.payload)
        .unwrap();
}

#[test]
fn chat_message_create_operation_embeds_agent_selector_mention_metadata() {
    let mentions = vec![MentionNode::mention(
        cokret_sdk::Mention::new(cokret_sdk::Did::new("did:web:agent.example".to_owned()).unwrap())
            .with_agent_selector_metadata(
                cokret_sdk::Did::new("did:web:example.com:users:alice".to_owned()).unwrap(),
                cokret_sdk::Handle::parse("alice:example.com").unwrap(),
                "summary",
            )
            .with_mention_text_original("@alice:example.com/summary")
            .with_resolved_at(
                chrono::DateTime::parse_from_rfc3339("2026-06-11T00:00:00.000Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
    )];
    let op = chat_message_create_operation(
        "ck:realm:01904100-0000-7000-8000-000000000010",
        "did:web:bob.example",
        "ck:strand:01904100-0000-7000-8000-000000000001",
        "discussion",
        "ck:message:01904100-0000-7000-8000-000000000003",
        "ask @alice:example.com/summary",
        &mentions,
        None,
    )
    .expect("builds");

    let mention = &op.payload["content"]["mentions"][0];
    assert_eq!(mention["kind"].as_str(), Some("mention"));
    assert_eq!(
        mention["subject_id"].as_str(),
        Some("did:web:agent.example")
    );
    assert_eq!(
        mention["controller_subject_id"].as_str(),
        Some("did:web:example.com:users:alice")
    );
    assert_eq!(
        mention["controller_handle_at_time"].as_str(),
        Some("alice:example.com")
    );
    assert_eq!(mention["agent_slug_at_time"].as_str(), Some("summary"));
    assert!(mention.get("target").is_none());
    assert!(op.payload.get("mentions").is_none());
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(&op.kind, &op.payload)
        .unwrap();
}

#[test]
fn chat_message_create_operation_includes_reply_fields_only_when_present() {
    let op = chat_message_create_operation(
        "ck:realm:01904100-0000-7000-8000-000000000010",
        "did:web:alice.example",
        "ck:strand:01904100-0000-7000-8000-000000000001",
        "discussion",
        "ck:message:01904100-0000-7000-8000-000000000003",
        "reply body",
        &[],
        Some("ck:message:01904100-0000-7000-8000-000000000004"),
    )
    .expect("builds");

    assert_eq!(
        op.payload["reply_to"].as_str(),
        Some("ck:message:01904100-0000-7000-8000-000000000004")
    );
    assert!(op.payload.get("thread_id").is_none());
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(&op.kind, &op.payload)
        .unwrap();
}

#[test]
fn shared_pin_operations_use_pin_events_not_account_data() {
    let strand_id = "ck:strand:01904100-0000-7000-8000-000000000001";
    let target_ref = "ck:message:01904100-0000-7000-8000-000000000002";
    let add = shared_message_pin_add_operation(
        "ck:realm:01904100-0000-7000-8000-000000000010",
        "did:web:alice.example",
        strand_id,
        target_ref,
        "r100",
    )
    .expect("shared pin add builds");

    assert_eq!(add.kind, "ck.pin.add");
    assert_eq!(add.payload["pin_scope"]["kind"], "strand");
    assert_eq!(add.payload["pin_scope"]["id"], strand_id);
    assert_eq!(add.payload["target_ref"], target_ref);
    assert_eq!(add.payload["rank"], "r100");
    assert!(add.payload.get("key").is_none());
    assert!(add.payload.get("encrypted_payload").is_none());
    assert!(add.payload.get("body").is_none());

    let remove = shared_message_pin_remove_operation(
        "ck:realm:01904100-0000-7000-8000-000000000010",
        "did:web:alice.example",
        strand_id,
        target_ref,
    )
    .expect("shared pin remove builds");
    assert_eq!(remove.kind, "ck.pin.remove");
    assert_eq!(remove.payload["target_ref"], target_ref);
    assert!(remove.payload.get("key").is_none());
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(&add.kind, &add.payload)
        .unwrap();
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(&remove.kind, &remove.payload)
        .unwrap();
}

#[test]
fn private_saved_item_uses_saved_account_data_not_pin_event() {
    let namespace_key =
        crate::account_data::productivity_account_data_namespace_key("test-account-secret")
            .expect("namespace key");
    let target_ref = "ck:message:01904100-0000-7000-8000-000000000002";
    let item =
        chat_saved_account_data_item(&namespace_key, target_ref, "01970e589d21-0000-a13f9c2e")
            .expect("saved item");

    assert!(item.account_data_key.starts_with("ck.saved.v1:"));
    assert!(!item.account_data_key.contains(target_ref));
    assert!(
        !item
            .account_data_key
            .contains(CHAT_PRIVATE_SAVED_COLLECTION_TITLE)
    );
    assert_eq!(item.value.target_ref, target_ref);
    let wire = crate::account_data::saved_item_account_data_value(&item.value).unwrap();
    assert_eq!(wire["kind"], "saved_item");

    let op = crate::account_data::build_private_account_data_set(
        "ck:realm:01904100-0000-7000-8000-000000000010",
        "did:web:alice.example",
        &item.account_data_key,
        wire,
    )
    .unwrap()
    .build("yougen");
    assert_eq!(op.kind, "ck.account_data.set");
    assert_eq!(op.payload["key"], item.account_data_key);
    assert_eq!(op.payload["encrypted_payload"]["kind"], "saved_item");
    assert!(op.payload.get("body").is_none());
    assert_ne!(op.kind, "ck.pin.add");
}

#[test]
fn shared_pin_projection_ignores_private_saved_account_data() {
    use chrono::Utc;

    let strand_id = "ck:strand:01904100-0000-7000-8000-000000000001";
    let other_strand_id = "ck:strand:01904100-0000-7000-8000-000000000099";
    let target_ref = "ck:message:01904100-0000-7000-8000-000000000002";
    let other_target = "ck:message:01904100-0000-7000-8000-000000000003";
    let records = vec![
        crate::local_state::RawOperationRecord {
            operation_id: "ck:operation:pin-add".to_owned(),
            realm_id: Some("ck:realm:demo".to_owned()),
            received_at: Utc::now(),
            payload: json!({
                "kind": "ck.pin.add",
                "payload": {
                    "pin_scope": {"kind": "strand", "id": strand_id},
                    "target_ref": target_ref,
                    "rank": "r200"
                }
            }),
        },
        crate::local_state::RawOperationRecord {
            operation_id: "ck:operation:saved-private".to_owned(),
            realm_id: Some("ck:realm:demo".to_owned()),
            received_at: Utc::now(),
            payload: json!({
                "kind": "ck.account_data.set",
                "payload": {
                    "key": "ck.saved.v1:collection:target",
                    "encrypted_payload": {
                        "kind": "saved_item",
                        "collection_title": "Saved",
                        "target_ref": other_target,
                        "updated_hlc": "01970e589d21-0000-a13f9c2e"
                    }
                }
            }),
        },
        crate::local_state::RawOperationRecord {
            operation_id: "ck:operation:other-pin".to_owned(),
            realm_id: Some("ck:realm:demo".to_owned()),
            received_at: Utc::now(),
            payload: json!({
                "kind": "ck.pin.add",
                "payload": {
                    "pin_scope": {"kind": "strand", "id": other_strand_id},
                    "target_ref": other_target,
                    "rank": "r100"
                }
            }),
        },
        crate::local_state::RawOperationRecord {
            operation_id: "ck:operation:pin-reorder".to_owned(),
            realm_id: Some("ck:realm:demo".to_owned()),
            received_at: Utc::now(),
            payload: json!({
                "kind": "ck.pin.reorder",
                "payload": {
                    "pin_scope": {"kind": "strand", "id": strand_id},
                    "target_ref": target_ref,
                    "rank": "r050"
                }
            }),
        },
    ];

    let pins = shared_message_pins_from_raw_operations(&records, strand_id);
    assert_eq!(
        pins,
        vec![SharedMessagePin {
            pin_scope_id: strand_id.to_owned(),
            target_ref: target_ref.to_owned(),
            rank: "r050".to_owned(),
        }]
    );
}

#[test]
fn chat_message_ids_use_schema_prefix() {
    let id = new_chat_message_id();

    assert!(id.starts_with("ck:message:"));
    assert!(is_schema_message_id(&id));
    assert!(is_schema_message_id("ck:message:local-1"));
    assert!(!is_schema_message_id("chat-msg-local"));
    assert!(schema_message_id_or_new("chat-msg-local").starts_with("ck:message:"));
}

#[test]
fn restores_messages_from_local_raw_operations() {
    let state = ClientLocalState {
        raw_operations: vec![crate::local_state::RawOperationRecord {
            operation_id: "ck:operation:local".to_owned(),
            realm_id: Some("ck:realm:local".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "event_id": "ck:event:local",
                "kind": "ck.message.create",
                "actor": "did:web:alice.example",
                "body": "local fallback message",
                "strand_id": "ck:strand:announce",
                "message_id": "chat-msg-local"
            }),
        }],
        ..ClientLocalState::default()
    };

    let messages = chat_messages_from_local_state_with_sidecar(&state, None, None);

    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].realm_id, "ck:realm:local");
    assert_eq!(messages[0].strand_id, "ck:strand:announce");
    assert_eq!(messages[0].sender, "did:web:alice.example");
    assert_eq!(messages[0].body, "local fallback message");
}

#[test]
fn restores_canonical_actor_id_from_local_raw_operations() {
    let state = ClientLocalState {
        raw_operations: vec![crate::local_state::RawOperationRecord {
            operation_id: "ck:operation:local".to_owned(),
            realm_id: Some("ck:realm:local".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "event_id": "ck:event:local",
                "kind": "ck.message.create",
                "actor_id": "did:web:local.host:users:alice",
                "body": "canonical local message",
                "strand_id": "ck:strand:announce",
                "message_id": "chat-msg-local"
            }),
        }],
        ..ClientLocalState::default()
    };

    let messages = chat_messages_from_local_state_with_sidecar(&state, None, None);

    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].sender, "did:web:local.host:users:alice");
    assert_eq!(messages[0].body, "canonical local message");
}

#[test]
fn rebuild_restores_authors_own_encrypted_message_from_sidecar() {
    // X10.6 regression: an encrypted send persists a body-less
    // raw_operation stub (it MUST NOT store the plaintext in
    // raw_operations) plus the plaintext into the account-private
    // sidecar keyed by `message:{message_id}` under the strand. On a
    // card-detail Discussion tab switch / reload the ChatPanel remounts
    // and re-derives the feed from raw_operations via
    // `chat_messages_from_local_state_with_sidecar`. The stub now carries
    // `message_id` + `strand_id`, so the rebuild can re-key the sidecar and
    // restore the author's own (otherwise undecryptable) message body.
    let temp = std::env::temp_dir().join(format!("yougen-x10_6-rebuild-sidecar-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    store.save_private_plaintext(
        "ck:realm:local",
        "ck:strand:announce",
        "message:chat-msg-enc",
        "secret discussion body",
    );

    let state = ClientLocalState {
        raw_operations: vec![crate::local_state::RawOperationRecord {
            operation_id: "ck:operation:enc".to_owned(),
            realm_id: Some("ck:realm:local".to_owned()),
            received_at: chrono::Utc::now(),
            // Encrypted stub: identity only, NO plaintext body.
            payload: json!({
                "event_id": "ck:event:enc",
                "kind": "ck.message.create",
                "actor_id": "did:web:alice.example",
                "strand_id": "ck:strand:announce",
                "message_id": "chat-msg-enc",
                "encrypted_content": true,
                "status": "accepted"
            }),
        }],
        ..ClientLocalState::default()
    };

    // Without the sidecar (e.g. another device) the stub has no readable
    // body, but it must still surface as an encrypted/locked row so the
    // discussion does not look empty.
    let without_sidecar = chat_messages_from_local_state_with_sidecar(&state, None, None);
    assert_eq!(without_sidecar.len(), 1);
    assert_eq!(without_sidecar[0].strand_id, "ck:strand:announce");
    assert_eq!(without_sidecar[0].sender, "did:web:alice.example");
    assert_eq!(without_sidecar[0].body, "");
    assert!(matches!(
        without_sidecar[0].crypto_state,
        MessageCryptoState::Decrypting
    ));

    // With the sidecar (same device, tab switch / reload) the body is
    // restored and the message is fully resolved (not stuck decrypting).
    let restored = chat_messages_from_local_state_with_sidecar(&state, Some(&store), None);
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].strand_id, "ck:strand:announce");
    assert_eq!(restored[0].sender, "did:web:alice.example");
    assert_eq!(restored[0].body, "secret discussion body");
    assert!(matches!(
        restored[0].crypto_state,
        MessageCryptoState::Plaintext
    ));
}

#[test]
fn treats_canonical_account_did_as_own_sender() {
    let participants = Vec::new();

    assert!(is_own_message_sender(
        "did:web:alice.example",
        "did:web:alice.example"
    ));
    assert_eq!(
        sender_display_label(
            "did:web:alice.example",
            "did:web:alice.example",
            "",
            &participants
        ),
        "alice.example"
    );
    assert_eq!(
        sender_display_label(
            "did:web:alice.example",
            "did:web:alice.example",
            "Alice Local",
            &participants,
        ),
        "Alice Local"
    );
    assert_eq!(
        sender_display_label(
            "did:web:local.host:users:alice",
            "did:web:local.host:users:alice",
            "alice:local.host",
            &participants,
        ),
        "alice:local.host"
    );
}

#[test]
fn participant_display_name_prefers_local_remark() {
    let participants = vec![SpaceParticipant {
        did: "did:web:bob.example".to_owned(),
        display_name: Some("Bobby".to_owned()),
        handle_label: None,
        display_name_rank: 0,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: false,
        agent_metadata: None,
    }];

    assert_eq!(
        sender_display_label(
            "did:web:bob.example",
            "did:web:alice.example",
            "Alice",
            &participants,
        ),
        "Bobby"
    );
    assert_eq!(
        sender_display_label(
            "did:web:carol.example",
            "did:web:alice.example",
            "Alice",
            &participants
        ),
        "carol.example"
    );
}

#[test]
fn sender_display_label_prefers_full_handle_over_handle_localpart() {
    let participants = vec![SpaceParticipant {
        did: "did:web:local.host:users:alice".to_owned(),
        display_name: Some("alice".to_owned()),
        handle_label: None,
        display_name_rank: 2,
        role: SpaceParticipantRole::Member,
        is_self: true,
        is_agent: false,
        agent_metadata: None,
    }];

    assert_eq!(
        sender_display_label(
            "did:web:local.host:users:alice",
            "did:web:local.host:users:alice",
            "alice",
            &participants,
        ),
        "alice:local.host"
    );
}

#[test]
fn own_sender_label_prefers_account_handle_over_did_derived_materialized_id() {
    let participants = vec![SpaceParticipant {
        did: "did:web:auth.local.host:users:01ktwstvaef1dby1xf5mnkxss8".to_owned(),
        display_name: None,
        handle_label: None,
        display_name_rank: u8::MAX,
        role: SpaceParticipantRole::Member,
        is_self: true,
        is_agent: false,
        agent_metadata: None,
    }];

    assert_eq!(
        sender_display_label(
            "did:web:auth.local.host:users:01ktwstvaef1dby1xf5mnkxss8",
            "did:web:auth.local.host:users:01ktwstvaef1dby1xf5mnkxss8",
            "alice:local.host",
            &participants,
        ),
        "alice:local.host"
    );
}

#[test]
fn sender_display_label_prefers_projection_handle_label() {
    let participants = vec![SpaceParticipant {
        did: "did:web:example.com:users:bob".to_owned(),
        display_name: Some("bob".to_owned()),
        handle_label: Some("bob:example.com".to_owned()),
        display_name_rank: 2,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: false,
        agent_metadata: None,
    }];

    assert_eq!(
        sender_display_label(
            "did:web:example.com:users:bob",
            "did:web:local.host:users:alice",
            "alice:local.host",
            &participants,
        ),
        "bob:example.com"
    );
}

#[test]
fn account_handle_display_from_server_expands_account_localpart() {
    assert_eq!(
        account_handle_display_from_server("alice", "https://local.host").as_deref(),
        Some("alice:local.host")
    );
    assert_eq!(
        account_handle_display_from_server("alice:example.com", "https://local.host").as_deref(),
        Some("alice:example.com")
    );
    assert_eq!(
        account_handle_display_from_server("  ", "https://local.host"),
        None
    );
}

#[test]
fn extracts_participant_display_name_from_projection() {
    let projection = json!({
        "members": [
            {
                "did": "did:web:bob.example",
                "display_name": "Bob Example",
                "remark": "Bob from ops"
            }
        ]
    });

    let participants = space_participants(Some(&projection), "did:web:alice.example");
    let bob = participants
        .iter()
        .find(|participant| participant.did == "did:web:bob.example")
        .unwrap();

    assert_eq!(bob.display_name.as_deref(), Some("Bob from ops"));
}

#[test]
fn extracts_participant_handle_label_from_projection() {
    // R3.1: canonical wire field is `handle` (`<localpart>:<domain>`).
    let projection = json!({
        "members": [
            {
                "actor_id": "did:web:example.com:users:bob",
                "handle": "bob:example.com"
            }
        ]
    });

    let participants = space_participants(Some(&projection), "did:web:alice.example");
    let bob = participants
        .iter()
        .find(|participant| participant.did == "did:web:example.com:users:bob")
        .unwrap();

    assert_eq!(
        mention_label_for_participant(bob).as_deref(),
        Some("bob:example.com")
    );
}

#[test]
fn mention_label_for_participant_falls_back_to_materialized_handle_did() {
    let participant = SpaceParticipant {
        did: "did:web:example.com:users:bob".to_owned(),
        display_name: None,
        handle_label: None,
        display_name_rank: u8::MAX,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: false,
        agent_metadata: None,
    };

    assert_eq!(
        mention_label_for_participant(&participant).as_deref(),
        Some("bob:example.com")
    );
}

#[test]
fn mention_label_for_participant_requires_handle() {
    let participant = SpaceParticipant {
        did: "did:webvh:zQmed2r1bBnz5cpB6SoL1UxvqNQPQpimEnHy7Rc9VLLrifC:local.host:webvh:01ks6dnzv"
            .to_owned(),
        display_name: None,
        handle_label: None,
        display_name_rank: u8::MAX,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: false,
        agent_metadata: None,
    };

    assert!(mention_label_for_participant(&participant).is_none());
}

#[test]
fn mention_inline_parts_styles_only_full_handles() {
    let mention = MentionNode::mention(
        cokret_sdk::Mention::new(
            cokret_sdk::Did::new("did:web:local.host:users:alice".to_owned()).unwrap(),
        )
        .with_display_name_at_time("alice:local.host")
        .with_handle_at_time(cokret_sdk::Handle::parse("alice:local.host").unwrap())
        .with_mention_text_original("@alice:local.host"),
    );

    let parts = mention_inline_parts(
        "@alice Hello @alice:local.host.",
        &[mention],
        "https://auth.local.host",
    );
    assert!(
        parts
            .iter()
            .any(|part| part.mention_label.as_deref() == Some("alice:local.host") && part.is_local)
    );
    assert!(
        parts
            .iter()
            .any(|part| part.text == "@alice" && part.mention_label.is_none())
    );
}

#[test]
fn mention_inline_parts_marks_external_handles_remote() {
    let mention = MentionNode::mention(
        cokret_sdk::Mention::new(
            cokret_sdk::Did::new("did:web:example.com:users:bob".to_owned()).unwrap(),
        )
        .with_display_name_at_time("bob:example.com")
        .with_handle_at_time(cokret_sdk::Handle::parse("bob:example.com").unwrap())
        .with_mention_text_original("@bob:example.com"),
    );

    let parts = mention_inline_parts("@bob:example.com", &[mention], "https://local.host");
    let mention_part = parts
        .iter()
        .find(|part| part.mention_label.as_deref() == Some("bob:example.com"))
        .unwrap();
    assert!(!mention_part.is_local);
}

#[test]
fn participant_with_agent_id_renders_with_agent_badge() {
    // Three participants in the realm: Alice (the local account),
    // Bob (a real human member), and a Researcher Agent registered
    // via `ck.agent.endpoint`. After `annotate_agent_participants`
    // the agent DID must carry `is_agent = true` while the human
    // members stay `false`.
    let mut participants = vec![
        SpaceParticipant {
            did: "did:web:alice.example".to_owned(),
            display_name: Some("Alice".to_owned()),
            handle_label: None,
            display_name_rank: 0,
            role: SpaceParticipantRole::Owner,
            is_self: true,
            is_agent: false,
            agent_metadata: None,
        },
        SpaceParticipant {
            did: "did:web:bob.example".to_owned(),
            display_name: Some("Bob".to_owned()),
            handle_label: None,
            display_name_rank: 1,
            role: SpaceParticipantRole::Member,
            is_self: false,
            is_agent: false,
            agent_metadata: None,
        },
        SpaceParticipant {
            did: "did:web:researcher-agent.example".to_owned(),
            display_name: None,
            handle_label: None,
            display_name_rank: u8::MAX,
            role: SpaceParticipantRole::Member,
            is_self: false,
            is_agent: false,
            agent_metadata: None,
        },
    ];

    annotate_agent_participants(
        &mut participants,
        &["did:web:researcher-agent.example".to_owned()],
    );

    let alice = &participants[0];
    let bob = &participants[1];
    let agent = &participants[2];
    assert!(!alice.is_agent, "human owner must not be flagged as agent");
    assert!(!bob.is_agent, "human member must not be flagged as agent");
    assert!(
        agent.is_agent,
        "DID registered via ck.agent.endpoint must be flagged as agent"
    );
}

#[test]
fn agent_ids_from_raw_operations_filters_by_realm_and_kind() {
    use chrono::Utc;

    use crate::local_state::RawOperationRecord;

    // Mixed bag of raw ops: an agent endpoint for the right realm,
    // an agent endpoint for a different realm (should be filtered
    // out by space_id), and a non-agent kind (should be filtered
    // out by kind).
    let records = vec![
        RawOperationRecord {
            operation_id: "op-1".to_owned(),
            realm_id: Some("ck:realm:demo".to_owned()),
            received_at: Utc::now(),
            payload: json!({
                "kind": "ck.agent.endpoint",
                "body": { "agent_id": "did:web:researcher-agent.example" }
            }),
        },
        RawOperationRecord {
            operation_id: "op-2".to_owned(),
            realm_id: Some("ck:realm:other".to_owned()),
            received_at: Utc::now(),
            payload: json!({
                "kind": "ck.agent.endpoint",
                "body": { "agent_id": "did:web:other-agent.example" }
            }),
        },
        RawOperationRecord {
            operation_id: "op-3".to_owned(),
            realm_id: Some("ck:realm:demo".to_owned()),
            received_at: Utc::now(),
            payload: json!({
                "kind": "ck.message.create",
                "body": { "body": "hello" }
            }),
        },
    ];

    let agent_ids = agent_ids_from_raw_operations(&records, "ck:realm:demo");
    assert_eq!(
        agent_ids,
        vec!["did:web:researcher-agent.example".to_owned()]
    );
}

#[test]
fn agent_metadata_from_raw_operations_reads_controller_scoped_selector_fields() {
    use chrono::Utc;

    use crate::local_state::RawOperationRecord;

    let records = vec![RawOperationRecord {
        operation_id: "op-1".to_owned(),
        realm_id: Some("ck:realm:demo".to_owned()),
        received_at: Utc::now(),
        payload: json!({
            "kind": "ck.agent.endpoint",
            "actor_id": "did:web:example.com:users:alice",
            "payload": {
                "agent_id": "did:web:agents.example:summary",
                "display_name": "Summary Assistant",
                "agent_slug": "summary",
                "controller_handle": "alice:example.com"
            }
        }),
    }];

    let metadata = agent_metadata_from_raw_operations(&records, "ck:realm:demo");
    let summary = metadata
        .get("did:web:agents.example:summary")
        .expect("agent metadata");
    assert_eq!(summary.controller_did, "did:web:example.com:users:alice");
    assert_eq!(summary.controller_handle, "alice:example.com");
    assert_eq!(summary.agent_slug, "summary");
    assert_eq!(summary.display_name, "Summary Assistant");
}

#[test]
fn agent_metadata_from_mentions_recovers_selector_audit_metadata() {
    let messages = vec![ChatMessage {
        realm_id: "ck:realm:demo".to_owned(),
        id: "ck:event:1".to_owned(),
        protocol_message_id: Some("ck:message:01964137-0000-7000-8000-000000000001".to_owned()),
        sender: "did:web:example.com:users:bob".to_owned(),
        executed_by: None,
        body: "@alice:example.com/summary".to_owned(),
        timestamp: "10:00".to_owned(),
        strand_id: "ck:strand:demo".to_owned(),
        reply_to: None,
        reactions: Vec::new(),
        redacted: false,
        edited: false,
        revisions: Vec::new(),
        pending: false,
        failed: false,
        error: None,
        mentions: vec![MentionNode::mention(
            cokret_sdk::Mention::new(
                cokret_sdk::Did::new("did:web:agents.example:summary".to_owned()).unwrap(),
            )
            .with_display_name_at_time("Summary Assistant")
            .with_agent_selector_metadata(
                cokret_sdk::Did::new("did:web:example.com:users:alice".to_owned()).unwrap(),
                cokret_sdk::Handle::parse("alice:example.com").unwrap(),
                "summary",
            )
            .with_mention_text_original("@alice:example.com/summary")
            .with_resolved_at(
                chrono::DateTime::parse_from_rfc3339("2026-06-12T00:00:00.000Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
        )],
        crypto_state: MessageCryptoState::Plaintext,
    }];

    let metadata = agent_metadata_from_mentions(&messages);
    let summary = metadata
        .get("did:web:agents.example:summary")
        .expect("agent metadata");
    assert_eq!(summary.controller_did, "did:web:example.com:users:alice");
    assert_eq!(summary.controller_handle, "alice:example.com");
    assert_eq!(summary.agent_slug, "summary");
    assert_eq!(summary.display_name, "Summary Assistant");
}

#[test]
fn participant_roster_rows_groups_agents_under_visible_controller() {
    let controller = SpaceParticipant {
        did: "did:web:example.com:users:alice".to_owned(),
        display_name: Some("Alice".to_owned()),
        handle_label: Some("alice:example.com".to_owned()),
        display_name_rank: 0,
        role: SpaceParticipantRole::Owner,
        is_self: true,
        is_agent: false,
        agent_metadata: None,
    };
    let agent = SpaceParticipant {
        did: "did:web:agents.example:summary".to_owned(),
        display_name: Some("Summary Assistant".to_owned()),
        handle_label: None,
        display_name_rank: 1,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: true,
        agent_metadata: Some(AgentParticipantMetadata {
            controller_did: controller.did.clone(),
            controller_handle: "alice:example.com".to_owned(),
            agent_slug: "summary".to_owned(),
            display_name: "Summary Assistant".to_owned(),
        }),
    };
    let rows = participant_roster_rows(&[controller.clone(), agent.clone()]);
    assert_eq!(rows.len(), 1);
    match &rows[0] {
        ParticipantRosterRow::ControllerWithAgents { controller, agents } => {
            assert_eq!(controller.did, "did:web:example.com:users:alice");
            assert_eq!(agents.len(), 1);
            assert_eq!(agents[0].did, "did:web:agents.example:summary");
        }
        ParticipantRosterRow::Participant(_) => panic!("expected grouped controller row"),
    }
}

#[test]
fn mention_candidate_for_agent_uses_controller_scoped_selector() {
    let controller = SpaceParticipant {
        did: "did:web:example.com:users:alice".to_owned(),
        display_name: Some("Alice".to_owned()),
        handle_label: Some("alice:example.com".to_owned()),
        display_name_rank: 0,
        role: SpaceParticipantRole::Owner,
        is_self: true,
        is_agent: false,
        agent_metadata: None,
    };
    let agent = SpaceParticipant {
        did: "did:web:agents.example:summary".to_owned(),
        display_name: Some("Summary Assistant".to_owned()),
        handle_label: None,
        display_name_rank: 1,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: true,
        agent_metadata: Some(AgentParticipantMetadata {
            controller_did: controller.did.clone(),
            controller_handle: "alice:example.com".to_owned(),
            agent_slug: "summary".to_owned(),
            display_name: "Summary Assistant".to_owned(),
        }),
    };
    let participants = vec![controller, agent.clone()];
    let candidate =
        mention_candidate_for_participant(&agent, &participants).expect("agent mention candidate");
    assert_eq!(candidate.display_name, "Summary Assistant");
    assert_eq!(candidate.insert_label(), "alice:example.com/summary");
    assert_eq!(
        candidate.controller_subject_id,
        "did:web:example.com:users:alice"
    );
    assert_eq!(candidate.controller_handle_at_time, "alice:example.com");
    assert_eq!(candidate.agent_slug_at_time, "summary");
}

#[test]
fn channel_from_strand_event_requires_real_discussion_track() {
    let event = json!({
        "event_id": "ck:event:strand",
        "kind": "ck.strand.create",
        "realm_id": "ck:realm:demo",
        "strand_id": "ck:strand:ops",
        "title": "Ops discussion",
        "category": "support",
        "summary": "Operations support",
        "strand": {
            "id": "ck:strand:ops",
            "title": "Ops discussion",
            "tracks": {
                "discussion": {"profile": "discussion"}
            }
        }
    });

    let channel = channel_from_strand_event("ck:realm:demo", &event).unwrap();

    assert_eq!(channel.strand_id, "ck:strand:ops");
    assert_eq!(channel.name, "Ops discussion");
    assert_eq!(channel.category, "support");
    assert_eq!(channel.kind, "discussion");
    assert_eq!(channel.topic.as_deref(), Some("Operations support"));
    assert!(!channel.is_default);
}

#[test]
fn channel_from_strand_event_ignores_non_discussion_strands() {
    let event = json!({
        "event_id": "ck:event:strand",
        "kind": "ck.strand.create",
        "realm_id": "ck:realm:demo",
        "strand_id": "ck:strand:doc",
        "title": "Doc strand",
        "strand": {
            "id": "ck:strand:doc",
            "title": "Doc strand",
            "tracks": {
                "document": {"profile": "document"}
            }
        }
    });

    assert!(channel_from_strand_event("ck:realm:demo", &event).is_none());
}

#[test]
fn default_discussion_channel_uses_realm_default_strand_projection() {
    let body = json!({
        "summary": {
            "title": "Demo Realm",
            "strand": {
                "strand_id": "ck:strand:demo",
                "title": "General",
                "summary": "Realm-wide conversation",
                "tracks": {
                    "discussion": {"enabled": true},
                    "synthesis": {"enabled": true}
                }
            }
        }
    });

    let channel = default_discussion_channel("ck:realm:demo", Some(&body));

    assert_eq!(channel.strand_id, "ck:strand:demo");
    assert_eq!(channel.name, "General");
    assert_eq!(channel.kind, "discussion");
    assert_eq!(channel.topic.as_deref(), Some("Realm-wide conversation"));
    assert!(channel.is_default);
}

#[test]
fn default_discussion_channel_synthesizes_default_strand_when_projection_is_absent() {
    let channel = default_discussion_channel("ck:realm:demo", None);

    assert_eq!(channel.strand_id, "ck:strand:demo");
    assert_eq!(channel.name, "Discussion");
    assert_eq!(channel.category, "default strand");
    assert!(channel.is_default);
}

#[test]
fn presence_maps_from_sync_events_prefers_account_subscribe_presence() {
    let participants = vec![
        "did:web:alice.example".to_owned(),
        "did:web:bob.example".to_owned(),
        "did:web:carol.example".to_owned(),
    ];
    let events = vec![
        json!({
            "user_id": "did:web:bob.example",
            "presence": "online",
            "updated_at": "2026-05-29T04:12:43Z"
        }),
        json!({
            "actor_id": "did:web:mallory.example",
            "presence": "online"
        }),
    ];

    let (states, labels) =
        presence_maps_from_sync_events(&events, &participants, "did:web:alice.example", "Alice")
            .expect("presence events should match participants");

    assert_eq!(
        states.get("did:web:alice.example"),
        Some(&"online".to_owned())
    );
    assert_eq!(
        states.get("did:web:bob.example"),
        Some(&"online".to_owned())
    );
    assert_eq!(
        states.get("did:web:carol.example"),
        Some(&"offline".to_owned())
    );
    assert_eq!(
        labels.get("did:web:alice.example"),
        Some(&"Alice".to_owned())
    );
    assert!(!states.contains_key("did:web:mallory.example"));
}

#[test]
fn watch_level_wire_round_trip() {
    for level in [
        WatchLevel::MentionsOnly,
        WatchLevel::Participating,
        WatchLevel::All,
        WatchLevel::Muted,
    ] {
        assert_eq!(watch_level_from_wire(watch_level_wire_value(level)), level);
    }
    assert_eq!(watch_level_from_wire("none"), WatchLevel::Muted);
}

// ── T7.4 crypto state helpers ────────────────────────────────

#[test]
fn message_crypto_state_pending_detects_grey_states() {
    assert!(!MessageCryptoState::Plaintext.is_pending());
    assert!(MessageCryptoState::Decrypting.is_pending());
    assert!(MessageCryptoState::KeyMissing.is_pending());
    assert!(!MessageCryptoState::NeedsVerification.is_pending());
}

#[test]
fn secure_content_block_round_trips_back_to_text() {
    // P1: the secure send path encrypts the canonical Content Block JSON
    // (not raw body bytes), and the decrypt-on-read path extracts the text
    // back out via `text_body_from_value`. This locks that symmetry without
    // standing up a full MLS group.
    let body = "secret hello with spaces";
    let content_value = cokret_sdk::ContentBlock::text(body)
        .to_value()
        .expect("content block serializes");
    let bytes = serde_json::to_vec(&content_value).expect("content block bytes");
    let parsed: Value = serde_json::from_slice(&bytes).expect("content block parses");
    assert_eq!(text_body_from_value(&parsed).as_deref(), Some(body));
}

#[test]
fn decrypt_chat_encrypted_content_soft_fails_without_snapshot() {
    // No local MLS snapshot for this realm -> decrypt-on-read returns None
    // so the caller leaves the message in Decrypting/KeyMissing rather than
    // surfacing garbage.
    let temp = std::env::temp_dir().join(format!(
        "yougen-chat-decrypt-{}.json",
        crate::operation::uuid_v7()
    ));
    let store = LocalStateStore::with_path(temp);
    let envelope = json!({
        "scheme": "mls-rfc9420",
        "group_id": "group-x",
        "epoch": 1,
        "content_type": "application/vnd.cokret.message+json",
        "ciphertext": "AAAA",
        "payload_digest": "sha256:0",
    });
    assert!(
        decrypt_chat_encrypted_content(
            &store,
            "ck:realm:none",
            "did:web:alice.example",
            "ck:device:01964137-0000-7000-8000-000000000001",
            &envelope,
        )
        .is_none()
    );
}

#[test]
fn chat_message_from_event_flags_encrypted_payload_as_decrypting() {
    let event = json!({
        "event_id": "evt:1",
        "content": {
            "type": "ck.message.create",
            "body": "[encrypted]",
            "strand_id": "ck:strand:1",
            "encrypted_content": {"ciphertext": "blob"},
        }
    });
    let msg = chat_message_from_event("ck:realm:demo", &event).expect("message");
    assert_eq!(msg.crypto_state, MessageCryptoState::Decrypting);
}

#[test]
fn chat_message_from_event_keeps_bodyless_encrypted_payload_visible() {
    let event = json!({
        "event_id": "evt:bodyless",
        "content": {
            "type": "ck.message.create",
            "strand_id": "ck:strand:1",
            "message_id": "ck:message:1",
            "encrypted_content": {
                "scheme": "mls-rfc9420",
                "version": "1.0",
                "group_id": "ck:mls:test",
                "epoch": 1,
                "content_type": "application/vnd.cokret.message+json",
                "ciphertext": "AAAA",
                "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
        }
    });

    let msg = chat_message_from_event("ck:realm:demo", &event).expect("message");

    assert_eq!(msg.body, "");
    assert_eq!(msg.strand_id, "ck:strand:1");
    assert_eq!(msg.crypto_state, MessageCryptoState::Decrypting);
}

#[test]
fn chat_message_revise_operation_uses_schema_target_ref() {
    let op = chat_message_revise_operation(
        "ck:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22",
        "did:web:bob.example",
        "ck:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23",
        "edited",
    );

    assert_eq!(
        op.payload["target_ref"],
        "ck:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23"
    );
    assert_eq!(op.payload["content"]["kind"], "ck.content.text");
    assert_eq!(op.payload["content"]["body"], "edited");
    assert!(op.payload.get("body").is_none());
    assert!(op.payload.get("target_event_id").is_none());
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(&op.kind, &op.payload)
        .unwrap();
}

#[test]
fn chat_reaction_add_operation_uses_schema_target_ref() {
    let op = chat_reaction_add_operation(
        "ck:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22",
        "did:web:bob.example",
        "ck:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23",
        "+1",
    );

    assert_eq!(
        op.payload["target_ref"],
        "ck:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23"
    );
    assert_eq!(op.payload["key"], "+1");
    assert!(op.payload.get("event_id").is_none());
    assert!(op.payload.get("actor").is_none());
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(&op.kind, &op.payload)
        .unwrap();
}
