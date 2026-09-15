//! Locally authored chat operations: create, revise, redact, react, pin.

use super::*;

fn production_chat_message_create_operation(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    local_message_id: &str,
    body: &str,
    mentions: &[MentionNode],
    reply_to: Option<&str>,
) -> anyhow::Result<crate::operation::LocalOperation> {
    chat_message_create_operation_with_content(
        realm_id,
        actor,
        strand_id,
        local_message_id,
        body,
        chat_content_block_for_body(body)?,
        mentions,
        reply_to,
    )
}

#[test]
fn chat_message_create_operation_emits_schema_canonical_content() {
    let op = production_chat_message_create_operation(
        "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        "ak:did_core:web:alice.example",
        "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "local-message:test",
        "hello from chat",
        &[],
        None,
    )
    .expect("builds");

    assert_eq!(op.kind().as_str(), "ak.message.create");
    assert!(!op.payload().contains_key("message_id"));
    // The Message is named by its own create Event: the id is `retype(event_id)`
    // of the finalized envelope, and the producer never carries one in payload.
    let authored = crate::operation::author_for_test(&op);
    let message_id = arkret_sdk::MessageId::from_event_id(authored.event_id());
    assert_eq!(message_id.token_bytes(), authored.event_id().token_bytes());
    assert_eq!(
        op.payload()["strand_id"].as_str(),
        Some("ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
    );
    assert_eq!(op.payload()["track_name"].as_str(), Some("discussion"));
    assert_eq!(
        op.payload()["content"]["kind"].as_str(),
        Some("ak.content.text")
    );
    assert_eq!(
        op.payload()["content"]["body"].as_str(),
        Some("hello from chat")
    );
    assert_eq!(op.payload()["content"]["format"], "markdown");
    assert!(op.payload()["content"].get("blocks").is_none());
    assert!(!op.payload().contains_key("body"));
    assert!(!op.payload().contains_key("encrypted"));
    assert!(!op.payload().contains_key("kind"));
    assert!(!op.payload().contains_key("mentions"));
    assert!(!op.payload().contains_key("audience_mentions"));
    assert!(!op.payload().contains_key("mention_relations"));
    assert!(!op.payload().contains_key("reply_to_id"));
    arkret_schema_conformance::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind().as_str(),
            &serde_json::to_value(op.payload()).unwrap(),
        )
        .unwrap();
}

#[test]
fn chat_inline_content_declares_markdown_at_the_utf8_boundary() {
    let body = "a".repeat(arkret_sdk::CONTENT_TEXT_INLINE_MAX_BYTES);
    let content = chat_content_block_for_body(&body).unwrap();
    assert_eq!(content.kind, arkret_sdk::ContentBlockKind::Text);
    assert_eq!(
        content.text_format(),
        Some(arkret_sdk::TextFormat::Markdown)
    );

    let over = "a".repeat(arkret_sdk::CONTENT_TEXT_INLINE_MAX_BYTES + 1);
    assert!(chat_content_block_for_body(&over).is_err());
}

#[test]
fn chat_message_create_operation_blocks_sensitive_public_update() {
    let err = production_chat_message_create_operation(
        "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        "ak:did_core:web:alice.example",
        "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "ak:message:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "Public update: root cause leaked token",
        &[],
        None,
    )
    .expect_err("sensitive public updates must be blocked before send");

    assert!(err.to_string().contains("public_update_blocked"));
}

#[test]
fn chat_message_create_operation_keeps_public_update_notification_projection_out_of_content() {
    let op = production_chat_message_create_operation(
        "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        "ak:did_core:web:alice.example",
        "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "ak:message:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "SEV-1 public update: checkout latency is recovering",
        &[],
        None,
    )
    .expect("builds");

    assert!(!op.payload().contains_key("priority"));
    assert!(op.payload()["content"].get("priority").is_none());
    assert!(op.payload()["content"].get("notification").is_none());
    assert_eq!(
        op.payload()["content"]["body"].as_str(),
        Some("SEV-1 public update: checkout latency is recovering")
    );
    arkret_schema_conformance::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind().as_str(),
            &serde_json::to_value(op.payload()).unwrap(),
        )
        .unwrap();
}

#[test]
fn chat_message_create_operation_embeds_audience_mentions_in_content_only() {
    let mentions = parse_mention_nodes("ping @here and @carol:example.com");
    let op = production_chat_message_create_operation(
        "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        "ak:did_core:web:alice.example",
        "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "ak:message:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
        "ping @here and @carol:example.com",
        &mentions,
        None,
    )
    .expect("builds");

    assert_eq!(
        op.payload()["content"]["audience_mentions"][0]["audience"].as_str(),
        Some("strand_engaged")
    );
    assert!(!op.payload().contains_key("audience_mentions"));
    assert!(!op.payload().contains_key("mentions"));
    assert!(!op.payload().contains_key("mention_relations"));
    arkret_schema_conformance::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind().as_str(),
            &serde_json::to_value(op.payload()).unwrap(),
        )
        .unwrap();
}

#[test]
fn chat_message_create_operation_embeds_agent_selector_mention_metadata() {
    let mentions = vec![MentionNode::mention(
        arkret_sdk::Mention::new(local_fixture_account("ak:did_core:web:agent.example"))
            .with_agent_selector_metadata(
                local_fixture_account("ak:did_core:web:example.com:users:alice"),
                arkret_sdk::Handle::parse("alice:example.com").unwrap(),
                "summary",
            )
            .with_mention_text_original("@alice:example.com/summary")
            .with_resolved_at(
                chrono::DateTime::parse_from_rfc3339("2026-06-11T00:00:00.000Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
    )];
    let op = production_chat_message_create_operation(
        "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        "ak:did_core:web:bob.example",
        "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "ak:message:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
        "ask @alice:example.com/summary",
        &mentions,
        None,
    )
    .expect("builds");

    let mention = &op.payload()["content"]["mentions"][0];
    assert_eq!(mention["kind"].as_str(), Some("mention"));
    assert_eq!(
        mention["subject_account_id"],
        serde_json::to_value(local_fixture_account("ak:did_core:web:agent.example")).unwrap()
    );
    assert_eq!(
        mention["controller_subject_account_id"],
        serde_json::to_value(local_fixture_account(
            "ak:did_core:web:example.com:users:alice"
        ))
        .unwrap()
    );
    assert_eq!(
        mention["controller_handle_at_time"].as_str(),
        Some("alice:example.com")
    );
    assert_eq!(mention["agent_slug_at_time"].as_str(), Some("summary"));
    assert!(mention.get("target").is_none());
    assert!(!op.payload().contains_key("mentions"));
    arkret_schema_conformance::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind().as_str(),
            &serde_json::to_value(op.payload()).unwrap(),
        )
        .unwrap();
}

#[test]
fn chat_message_create_operation_includes_reply_fields_only_when_present() {
    let op = production_chat_message_create_operation(
        "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        "ak:did_core:web:alice.example",
        "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "ak:message:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
        "reply body",
        &[],
        Some("ak:message:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM"),
    )
    .expect("builds");

    assert_eq!(
        op.payload()["reply_to_id"].as_str(),
        Some("ak:message:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM")
    );
    arkret_schema_conformance::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind().as_str(),
            &serde_json::to_value(op.payload()).unwrap(),
        )
        .unwrap();
}

#[test]
fn chat_message_create_operation_rejects_event_id_reply_target() {
    let err = production_chat_message_create_operation(
        "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        "ak:did_core:web:alice.example",
        "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "ak:message:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
        "reply body",
        &[],
        Some("ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM"),
    )
    .expect_err("event ids are not valid message reply targets");

    assert!(err.to_string().contains("reply_to must be a ak:message id"));
}

#[test]
fn chat_message_reply_target_prefers_protocol_message_id() {
    let message = ChatMessage {
        realm_id: "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE".to_owned(),
        id: "ak:event:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5".to_owned(),
        protocol_message_id: Some(
            "ak:message:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N".to_owned(),
        ),
        actor_id: None,
        sender: "ak:did_core:web:example.com:users:bob".to_owned(),
        executed_by: None,
        body: "hello".to_owned(),
        content_format: None,
        timestamp: "10:00".to_owned(),
        created_at: None,
        strand_id: "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q".to_owned(),
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

    assert_eq!(
        message.reply_target_ref(),
        Some("ak:message:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N")
    );
}

#[test]
fn chat_message_mutation_target_prefers_protocol_message_id_after_revision() {
    let message = ChatMessage {
        realm_id: "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE".to_owned(),
        id: "ak:operation:01964137-0000-7000-8000-000000000001".to_owned(),
        protocol_message_id: Some(
            "ak:message:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N".to_owned(),
        ),
        actor_id: None,
        sender: "ak:did_core:web:example.com:users:bob".to_owned(),
        executed_by: None,
        body: "edited".to_owned(),
        content_format: None,
        timestamp: "10:00".to_owned(),
        created_at: None,
        strand_id: "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q".to_owned(),
        reply_to: None,
        reactions: Vec::new(),
        redacted: false,
        edited: true,
        revisions: vec!["hello".to_owned()],
        revision_source: None,
        pending: false,
        failed: false,
        error: None,
        mentions: Vec::new(),
        crypto_state: MessageCryptoState::Plaintext,
    };

    assert_eq!(
        message.mutation_target_ref(),
        "ak:message:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N"
    );
}

#[test]
fn shared_pin_operations_use_pin_events_not_account_data() {
    let strand_id = "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let pin_scope = SharedPinScope::strand(strand_id);
    let target_ref = "ak:message:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    let add = shared_message_pin_add_operation(
        "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        "ak:did_core:web:alice.example",
        &pin_scope,
        target_ref,
        "r100",
    )
    .expect("shared pin add builds");

    assert_eq!(add.kind().as_str(), "ak.pin.add");
    assert_eq!(add.payload()["pin_scope"]["kind"], "strand");
    assert_eq!(add.payload()["pin_scope"]["id"], strand_id);
    assert_eq!(add.payload()["target_ref"], target_ref);
    assert_eq!(add.payload()["rank"], "r100");
    assert!(!add.payload().contains_key("key"));
    assert!(!add.payload().contains_key("encrypted_payload"));
    assert!(!add.payload().contains_key("body"));

    let remove = shared_message_pin_remove_operation(
        "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        "ak:did_core:web:alice.example",
        &pin_scope,
        target_ref,
    )
    .expect("shared pin remove builds");
    assert_eq!(remove.kind().as_str(), "ak.pin.remove");
    assert_eq!(remove.payload()["target_ref"], target_ref);
    assert!(!remove.payload().contains_key("key"));
    arkret_schema_conformance::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            add.kind().as_str(),
            &serde_json::to_value(add.payload()).unwrap(),
        )
        .unwrap();
    arkret_schema_conformance::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            remove.kind().as_str(),
            &serde_json::to_value(remove.payload()).unwrap(),
        )
        .unwrap();
}

#[test]
fn selected_discussion_shared_pin_uses_exact_strand_scope() {
    let realm_id = "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h";
    let strand_id = "ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL";
    let pin_scope = shared_pin_scope_for_message(realm_id, strand_id);
    let target_ref = "ak:message:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    let add = shared_message_pin_add_operation(
        realm_id,
        "ak:did_core:web:alice.example",
        &pin_scope,
        target_ref,
        "r100",
    )
    .expect("shared pin add builds");

    assert_eq!(add.kind().as_str(), "ak.pin.add");
    assert_eq!(add.payload()["pin_scope"]["kind"], "strand");
    assert_eq!(add.payload()["pin_scope"]["id"], strand_id);
    assert_eq!(add.payload()["target_ref"], target_ref);
    arkret_schema_conformance::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            add.kind().as_str(),
            &serde_json::to_value(add.payload()).unwrap(),
        )
        .unwrap();
}

#[test]
fn private_saved_item_uses_saved_account_data_not_pin_event() {
    let namespace_key =
        crate::account_data::productivity_account_data_namespace_key("test-account-secret")
            .expect("namespace key");
    let target_ref = "ak:message:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    let item =
        chat_saved_account_data_item(&namespace_key, target_ref, "01970e589d21-0000-a13f9c2e")
            .expect("saved item");

    assert!(item.account_data_key.starts_with("ak.saved.v1:"));
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
        "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
        "ak:did_core:web:alice.example",
        &item.account_data_key,
        wire,
        0,
    )
    .unwrap()
    .build("inkson");
    assert_eq!(op.kind(), "ak.account_data.set");
    assert_eq!(op.payload()["key"], item.account_data_key);
    assert_eq!(op.payload()["expected_revision"], 0);
    assert_eq!(op.payload()["encrypted_payload"]["kind"], "saved_item");
    assert!(!op.payload().contains_key("body"));
    assert_ne!(op.kind(), "ak.pin.add");
}

#[test]
fn shared_pin_projection_ignores_private_saved_account_data() {
    use chrono::Utc;

    let strand_id = "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let pin_scope = SharedPinScope::strand(strand_id);
    let other_strand_id = "ak:strand:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk";
    let target_ref = "ak:message:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    let other_target = "ak:message:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy";
    let records = vec![
        crate::state::RawOperationRecord {
            operation_id: "ak:operation:pin-add".to_owned(),
            realm_id: Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE".to_owned()),
            received_at: Utc::now(),
            payload: json!({
                "kind": "ak.pin.add",
                "payload": {
                    "pin_scope": {"kind": "strand", "id": strand_id},
                    "target_ref": target_ref,
                    "rank": "r200"
                }
            }),
        },
        crate::state::RawOperationRecord {
            operation_id: "ak:operation:saved-private".to_owned(),
            realm_id: Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE".to_owned()),
            received_at: Utc::now(),
            payload: json!({
                "kind": "ak.account_data.set",
                "payload": {
                    "key": "ak.saved.v1:collection:target",
                    "encrypted_payload": {
                        "kind": "saved_item",
                        "collection_title": "Saved",
                        "target_ref": other_target,
                        "updated_hlc": "01970e589d21-0000-a13f9c2e"
                    }
                }
            }),
        },
        crate::state::RawOperationRecord {
            operation_id: "ak:operation:other-pin".to_owned(),
            realm_id: Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE".to_owned()),
            received_at: Utc::now(),
            payload: json!({
                "kind": "ak.pin.add",
                "payload": {
                    "pin_scope": {"kind": "strand", "id": other_strand_id},
                    "target_ref": other_target,
                    "rank": "r100"
                }
            }),
        },
        crate::state::RawOperationRecord {
            operation_id: "ak:operation:pin-reorder".to_owned(),
            realm_id: Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE".to_owned()),
            received_at: Utc::now(),
            payload: json!({
                "kind": "ak.pin.reorder",
                "payload": {
                    "pin_scope": {"kind": "strand", "id": strand_id},
                    "target_ref": target_ref,
                    "rank": "r050"
                }
            }),
        },
    ];

    let pins = shared_message_pins_from_raw_operations(&records, &pin_scope);
    assert_eq!(
        pins,
        vec![SharedMessagePin::new(
            &pin_scope,
            target_ref.to_owned(),
            "r050".to_owned(),
        )]
    );
}

/// `message_revise_payload` registers exactly one target carrier, `message_id`.
/// An `ak:event:` create token handed to the builder is retyped to
/// `ak:message:` (`common-fields.md` §6.0) rather than written verbatim, so the
/// same Message can never be addressed two ways.
#[test]
fn chat_message_revise_operation_retypes_event_target_to_message_id() {
    let op = chat_message_revise_operation(
        "ak:realm:AcLZB9aC8iMR8iBq1sUbB77yPclZIvptyHtZVgiszdI5",
        "ak:did_core:web:bob.example",
        "ak:event:AfzYurOSCYsUDGb3xQWTsa9dxNQ7f1QNrv24y4BoMawo",
        "edited",
    )
    .expect("builds");

    assert_eq!(
        op.payload()["message_id"],
        "ak:message:AfzYurOSCYsUDGb3xQWTsa9dxNQ7f1QNrv24y4BoMawo"
    );
    assert_eq!(op.payload()["content"]["kind"], "ak.content.text");
    assert_eq!(op.payload()["content"]["body"], "edited");
    assert_eq!(op.payload()["content"]["format"], "markdown");
    assert!(!op.payload().contains_key("body"));
    for retired in ["target_ref", "target_event_id", "revision_of"] {
        assert!(!op.payload().contains_key(retired));
    }
    arkret_schema_conformance::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind().as_str(),
            &serde_json::to_value(op.payload()).unwrap(),
        )
        .unwrap();
}

#[test]
fn chat_message_revise_operation_addresses_message_target_via_message_id() {
    // `message_id` is the only registered target carrier, so an already-typed
    // `ak:message:` target passes through unchanged.
    let op = chat_message_revise_operation(
        "ak:realm:AcLZB9aC8iMR8iBq1sUbB77yPclZIvptyHtZVgiszdI5",
        "ak:did_core:web:bob.example",
        "ak:message:AfzYurOSCYsUDGb3xQWTsa9dxNQ7f1QNrv24y4BoMawo",
        "edited",
    )
    .expect("builds");

    assert_eq!(
        op.payload()["message_id"],
        "ak:message:AfzYurOSCYsUDGb3xQWTsa9dxNQ7f1QNrv24y4BoMawo"
    );
    assert!(!op.payload().contains_key("target_ref"));
    assert_eq!(op.payload()["content"]["kind"], "ak.content.text");
    assert_eq!(op.payload()["content"]["body"], "edited");
    assert_eq!(op.payload()["content"]["format"], "markdown");
    arkret_schema_conformance::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind().as_str(),
            &serde_json::to_value(op.payload()).unwrap(),
        )
        .unwrap();
}

#[test]
fn chat_message_revise_operation_supersedes_only_the_observed_winner() {
    let winner = arkret_sdk::Hash::new(format!("sha256:{}", "32".repeat(32))).unwrap();
    let content = chat_content_block_for_body("next revision").unwrap();
    let op = chat_message_revise_operation_with_content(
        "ak:realm:AcLZB9aC8iMR8iBq1sUbB77yPclZIvptyHtZVgiszdI5",
        "ak:did_core:web:bob.example",
        "ak:message:AfzYurOSCYsUDGb3xQWTsa9dxNQ7f1QNrv24y4BoMawo",
        content,
        Some(winner.clone()),
    )
    .expect("builds");

    assert_eq!(op.intent().causal_refs(), vec![winner]);
}

/// Same single-carrier rule for `message_redact_payload`.
#[test]
fn chat_message_redact_operation_retypes_event_target_to_message_id() {
    let op = chat_message_redact_operation(
        "ak:realm:AcLZB9aC8iMR8iBq1sUbB77yPclZIvptyHtZVgiszdI5",
        "ak:did_core:web:bob.example",
        "ak:event:AfzYurOSCYsUDGb3xQWTsa9dxNQ7f1QNrv24y4BoMawo",
        "author_redaction",
    )
    .expect("builds");

    assert_eq!(
        op.payload()["message_id"],
        "ak:message:AfzYurOSCYsUDGb3xQWTsa9dxNQ7f1QNrv24y4BoMawo"
    );
    assert_eq!(op.payload()["reason"], "author_redaction");
    for retired in ["target_ref", "event_id", "target_event_id"] {
        assert!(!op.payload().contains_key(retired));
    }
    arkret_schema_conformance::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind().as_str(),
            &serde_json::to_value(op.payload()).unwrap(),
        )
        .unwrap();
}

#[test]
fn chat_message_redact_operation_uses_message_id_for_message_target() {
    let op = chat_message_redact_operation(
        "ak:realm:AcLZB9aC8iMR8iBq1sUbB77yPclZIvptyHtZVgiszdI5",
        "ak:did_core:web:bob.example",
        "ak:message:AfzYurOSCYsUDGb3xQWTsa9dxNQ7f1QNrv24y4BoMawo",
        "author_redaction",
    )
    .expect("builds");

    assert_eq!(
        op.payload()["message_id"],
        "ak:message:AfzYurOSCYsUDGb3xQWTsa9dxNQ7f1QNrv24y4BoMawo"
    );
    assert_eq!(op.payload()["reason"], "author_redaction");
    assert!(!op.payload().contains_key("target_event_id"));
    arkret_schema_conformance::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind().as_str(),
            &serde_json::to_value(op.payload()).unwrap(),
        )
        .unwrap();
}

#[test]
fn chat_reaction_add_operation_uses_schema_target_ref() {
    let op = chat_reaction_add_operation(
        "ak:realm:AcLZB9aC8iMR8iBq1sUbB77yPclZIvptyHtZVgiszdI5",
        "ak:did_core:web:bob.example",
        "ak:event:AfzYurOSCYsUDGb3xQWTsa9dxNQ7f1QNrv24y4BoMawo",
        "+1",
    )
    .expect("builds");

    assert_eq!(
        op.payload()["target_ref"],
        "ak:event:AfzYurOSCYsUDGb3xQWTsa9dxNQ7f1QNrv24y4BoMawo"
    );
    assert_eq!(op.payload()["key"], "+1");
    assert!(!op.payload().contains_key("event_id"));
    assert!(!op.payload().contains_key("actor"));
    arkret_schema_conformance::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind().as_str(),
            &serde_json::to_value(op.payload()).unwrap(),
        )
        .unwrap();
}

/// Every send outcome has to say something different, and something true.
///
/// The old plaintext path answered any unclassified failure with the error's
/// own `Display` text, so a user waiting on their authorization to be sealed
/// and a user whose Station returned a different message than they wrote both
/// read "Message send failed". A duplicate key here would put that back.
#[test]
fn every_send_failure_has_its_own_message() {
    let failures = [
        garth::MessageAuthoringFailure::AuthorizationNotSealed {
            detail: String::new(),
        },
        garth::MessageAuthoringFailure::DependencyUnavailable {
            detail: String::new(),
        },
        garth::MessageAuthoringFailure::PlaintextRefused {
            detail: String::new(),
        },
        garth::MessageAuthoringFailure::EncryptionContextChanged {
            detail: String::new(),
        },
        garth::MessageAuthoringFailure::PreparationExpired {
            detail: String::new(),
        },
        garth::MessageAuthoringFailure::DuplicateConflict {
            detail: String::new(),
        },
        garth::MessageAuthoringFailure::PreparedIntentMismatch {
            detail: String::new(),
        },
        garth::MessageAuthoringFailure::ActorChainConflict {
            detail: String::new(),
        },
        garth::MessageAuthoringFailure::SubmissionOutcomeUnknown {
            detail: String::new(),
        },
        garth::MessageAuthoringFailure::Refused {
            code: "policy_denied".to_owned(),
            detail: String::new(),
        },
    ];
    let mut keys = Vec::new();
    let mut rendered = Vec::new();
    for failure in &failures {
        let key = chat_authoring_failure_message(failure);
        let text = crate::i18n::tr(key);
        assert_ne!(text, key, "{key} has no localized line");
        assert!(!rendered.contains(&text), "{key} repeats another line");
        keys.push(key);
        rendered.push(text);
    }
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), failures.len());
}

/// A reply target is the only relation an ordinary message expresses, and it
/// has to be a Message id: anything else would ask the Station to bind the
/// message to something the user did not name.
#[test]
fn a_message_intent_carries_only_its_reply_target() {
    let strand = "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let content = arkret_sdk::MessageAuthoringContent::Plaintext {
        content: chat_content_block_for_body("hello").expect("content"),
        metadata: None,
    };
    let intent = chat_message_authoring_intent(strand, content.clone(), None).expect("intent");
    assert_eq!(intent.strand_id.as_str(), strand);
    assert!(intent.reply_to_id.is_none());
    assert!(intent.blob_refs.is_empty());
    let payload = intent.payload();
    assert!(payload.encrypted_content.is_none());
    assert!(payload.reply_to_id.is_none());

    let replied = chat_message_authoring_intent(
        strand,
        content.clone(),
        Some("ak:message:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"),
    )
    .expect("reply intent");
    assert_eq!(
        replied.reply_to_id.as_deref(),
        Some("ak:message:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
    );
    assert!(chat_message_authoring_intent(strand, content, Some("not-a-message-id")).is_err());
}
