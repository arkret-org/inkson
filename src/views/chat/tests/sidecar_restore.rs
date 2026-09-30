//! Restoring an author's own encrypted content from sidecar material.

use super::*;

/// The author's own committed encrypted Event: identity only, no readable
/// body, and the protocol message id the read side derives from it.
fn own_encrypted_message(realm_id: &str, strand_id: &str) -> (Value, arkret_sdk::MessageId) {
    let event = signed_chat_event(
        "ak.message.create",
        realm_id,
        json!({"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}}),
        "2026-07-08T01:44:39.000Z",
        json!({"strand_id": strand_id, "encrypted_content": true}),
    );
    let message_id = arkret_sdk::MessageId::from_event_id(
        &serde_json::from_value::<arkret_sdk::EventId>(event["event_id"].clone()).unwrap(),
    );
    (event, message_id)
}

#[test]
fn rebuild_restores_authors_own_encrypted_message_from_sidecar() {
    // X10.6 regression: an encrypted send keeps no plaintext in
    // raw_operations; the plaintext lives in the account-private sidecar
    // keyed by `message:{message_id}` under the strand, where `message_id`
    // is derived from the accepted event id. On a Discussion tab switch /
    // reload the feed is re-derived from raw_operations via
    // `chat_messages_from_local_state_with_sidecar`, which re-keys the
    // sidecar and restores the author's own (otherwise undecryptable) body.
    let temp = std::env::temp_dir().join(format!("inkson-x10_6-rebuild-sidecar-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    let (event, message_id) = own_encrypted_message(
        "ak:realm:ATwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q",
        "ak:strand:AWXzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c",
    );
    let sidecar_content = serde_json::to_string(
        &arkret_sdk::ContentBlock::markdown_text("secret discussion body")
            .to_value()
            .unwrap(),
    )
    .unwrap();
    store.save_private_plaintext(
        "ak:realm:ATwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q",
        "ak:strand:AWXzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c",
        &format!("message:{message_id}"),
        &sidecar_content,
    );

    let state = ClientLocalState {
        raw_operations: vec![crate::state::RawOperationRecord {
            operation_id: "ak:operation:enc".to_owned(),
            realm_id: Some("ak:realm:ATwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q".to_owned()),
            received_at: chrono::Utc::now(),
            payload: event,
        }],
        ..ClientLocalState::default()
    };

    // Without the sidecar (e.g. another device) the row has no readable
    // body, but it must still surface as an encrypted/locked row so the
    // discussion does not look empty.
    let without_sidecar = chat_messages_from_local_state_with_sidecar(&state, None, None);
    assert_eq!(without_sidecar.len(), 1);
    assert_eq!(
        without_sidecar[0].strand_id,
        "ak:strand:AWXzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c"
    );
    assert_eq!(without_sidecar[0].sender, "ak:did_core:web:alice.example");
    assert_eq!(without_sidecar[0].body, "");
    assert!(matches!(
        without_sidecar[0].crypto_state,
        MessageCryptoState::Decrypting
    ));

    // With the sidecar (same device, tab switch / reload) the body is
    // restored and the message is fully resolved (not stuck decrypting).
    let restored = chat_messages_from_local_state_with_sidecar(&state, Some(&store), None);
    assert_eq!(restored.len(), 1);
    assert_eq!(
        restored[0].strand_id,
        "ak:strand:AWXzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c"
    );
    assert_eq!(restored[0].sender, "ak:did_core:web:alice.example");
    assert_eq!(restored[0].body, "secret discussion body");
    assert_eq!(
        restored[0].content_format,
        Some(arkret_sdk::TextFormat::Markdown)
    );
    assert!(matches!(
        restored[0].crypto_state,
        MessageCryptoState::Plaintext
    ));
}

#[test]
fn encrypted_poll_sidecar_is_not_a_formal_v1_poll() {
    let temp = std::env::temp_dir().join(format!("inkson-poll-content-sidecar-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    let realm = "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h";
    let strand = "ak:strand:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934";
    let (event, message_id) = own_encrypted_message(realm, strand);
    let content = json!({
        "kind": "ak.content.poll",
        "body": "Deploy now?",
        "poll": {
            "kind": "disclosed",
            "max_selections": 1,
            "answers": [
                {
                    "id": "opt-0",
                    "text": {
                        "kind": "ak.content.text",
                        "body": "Now"
                    }
                },
                {
                    "id": "opt-1",
                    "text": {
                        "kind": "ak.content.text",
                        "body": "After backup"
                    }
                }
            ]
        }
    });
    store.save_private_plaintext(
        realm,
        strand,
        &format!("message:{message_id}"),
        "Deploy now?",
    );
    store.save_private_plaintext(
        realm,
        strand,
        &format!("message-content:{message_id}"),
        &serde_json::to_string(&content).expect("content serializes"),
    );

    let cards = poll_cards_from_events_with_sidecar(realm, &[event], Some(&store), None);

    assert!(cards.is_empty());
}

#[test]
fn poll_projection_merge_preserves_optimistic_message_render_id() {
    let mut draft = crate::messaging::polls::PollDraft::new();
    draft.set_question("Deploy now?".to_owned());
    draft.set_option(0, "Now".to_owned());
    draft.set_option(1, "After backup".to_owned());
    let wire_poll_id = "ak:message:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu";
    let mut optimistic =
        crate::messaging::polls::PollCard::from_draft("poll-local".to_owned(), &draft);
    optimistic.poll_ref = Some(arkret_sdk::MessageId::new(wire_poll_id).unwrap());
    let mut projected = crate::messaging::polls::PollCard::from_draft(
        "ak:event:AZfLd21JpG9eFxiZSOjnlVNQnQV8Bu7OP_TAtMdAAa30".to_owned(),
        &draft,
    );
    projected.poll_ref = Some(arkret_sdk::MessageId::new(wire_poll_id).unwrap());
    projected.votes[1].push(serde_json::from_value(serde_json::json!({"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:station.example"}})).unwrap());
    let mut cards = vec![optimistic];

    replace_poll_projection(&mut cards, vec![projected]);

    assert_eq!(cards.len(), 1);
    assert_eq!(cards[0].message_id, "poll-local");
    assert_eq!(cards[0].votes_for(1), 1);
    assert!(poll_card_matches_render_ids(
        &cards[0],
        "ak:event:AZfLd21JpG9eFxiZSOjnlVNQnQV8Bu7OP_TAtMdAAa30",
        Some(wire_poll_id),
    ));
    assert!(!poll_card_matches_render_ids(
        &cards[0],
        "ak:event:AZfLd21JpG9eFxiZSOjnlVNQnQV8Bu7OP_TAtMdAAa30",
        None,
    ));
    let pending = crate::messaging::polls::PollCard::from_draft("pending-local".to_owned(), &draft);
    cards.push(pending);
    replace_poll_projection(&mut cards, Vec::new());
    assert_eq!(cards.len(), 1);
    assert_eq!(cards[0].message_id, "pending-local");
    assert!(cards[0].poll_ref.is_none());
}

#[test]
fn pending_message_refreshes_from_restored_private_plaintext_sidecar() {
    let temp = std::env::temp_dir().join(format!("inkson-pending-sidecar-refresh-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    let realm = "ak:realm:ATwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q";
    let strand = "ak:strand:AWXzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c";
    let message_id = "ak:message:AWYcbgQPjPWiFZOW87QxvndGtWcImO9Xf2-TcOjH1pXs";
    let mut messages = vec![ChatMessage {
        realm_id: realm.to_owned(),
        id: "ak:event:AZhsY0DZJGk1qN28pQapwgLRRgx7kyis3JdX2xGL1Cj8".to_owned(),
        protocol_message_id: Some(message_id.to_owned()),
        actor_id: None,
        sender: "ak:did_core:web:alice.example".to_owned(),
        executed_by: None,
        body: String::new(),
        content_format: None,
        timestamp: "10:00".to_owned(),
        created_at: None,
        strand_id: strand.to_owned(),
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
        crypto_state: MessageCryptoState::KeyMissing,
    }];

    assert!(!pending_messages_have_private_plaintext_sidecar(
        &messages, &store, realm
    ));
    assert!(!restore_pending_messages_from_private_plaintext_sidecar(
        messages.as_mut_slice(),
        &store,
        realm
    ));

    let sidecar_content = serde_json::to_string(
        &arkret_sdk::ContentBlock::markdown_text("restored after sidecar sync")
            .to_value()
            .unwrap(),
    )
    .unwrap();
    store.save_private_plaintext(
        realm,
        strand,
        &format!("message:{message_id}"),
        &sidecar_content,
    );

    let mut missing_scope = messages.clone();
    missing_scope[0].realm_id.clear();
    assert!(
        !pending_messages_have_private_plaintext_sidecar(&missing_scope, &store, realm),
        "a message without its own Realm cannot borrow the selected Realm's private plaintext"
    );
    assert!(!restore_pending_messages_from_private_plaintext_sidecar(
        &mut missing_scope,
        &store,
        realm
    ));
    assert!(missing_scope[0].body.is_empty());
    let mut foreign_scope = messages.clone();
    foreign_scope[0].realm_id = arkret_sdk::RealmId::from_event_id(
        &arkret_sdk::EventId::new(messages[0].id.clone()).unwrap(),
    )
    .to_string();
    assert!(!pending_messages_have_private_plaintext_sidecar(
        &foreign_scope,
        &store,
        realm
    ));
    assert!(!restore_pending_messages_from_private_plaintext_sidecar(
        &mut foreign_scope,
        &store,
        realm
    ));

    assert!(pending_messages_have_private_plaintext_sidecar(
        &messages, &store, realm
    ));
    assert!(restore_pending_messages_from_private_plaintext_sidecar(
        messages.as_mut_slice(),
        &store,
        realm
    ));
    assert_eq!(messages[0].body, "restored after sidecar sync");
    assert_eq!(
        messages[0].content_format,
        Some(arkret_sdk::TextFormat::Markdown)
    );
    assert_eq!(messages[0].crypto_state, MessageCryptoState::Plaintext);
    assert!(!restore_pending_messages_from_private_plaintext_sidecar(
        messages.as_mut_slice(),
        &store,
        realm
    ));
}

#[test]
fn legacy_late_recovery_marker_does_not_override_verified_sidecar_path() {
    let temp = std::env::temp_dir().join(format!("inkson-sidecar-legacy-marker-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    let realm = "ak:realm:ATwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q";
    let strand = "ak:strand:AWXzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c";
    let event = signed_chat_event(
        "ak.message.create",
        realm,
        json!({"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}}),
        "2026-07-08T01:44:39.000Z",
        json!({"strand_id": strand, "content": {"encrypted_content": true}}),
    );
    let message_id = arkret_sdk::MessageId::from_event_id(
        &serde_json::from_value::<arkret_sdk::EventId>(event["event_id"].clone()).unwrap(),
    );
    store.save_private_plaintext(
        realm,
        strand,
        &format!("message:{message_id}"),
        "late plaintext",
    );
    let event = json!({
        "event": event,
        "decryption_state": "decryption_failed",
        "late_recovery": {
            "receiver_visible_at_t0": false
        }
    });

    let message =
        chat_message_from_event_with_sidecar(realm, &event, Some(&store), None).expect("message");

    assert_eq!(message.body, "late plaintext");
    assert_eq!(message.crypto_state, MessageCryptoState::Plaintext);
    assert_eq!(message.error, None);
}
