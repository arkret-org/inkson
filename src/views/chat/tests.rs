use super::*;

#[test]
fn circle_scope_request_is_single_flight_and_semantically_deduplicated() {
    let key = "https://example.test\u{1f}did:web:alice\u{1f}ak:realm:one";
    assert!(!should_start_circle_scope_request("", "", false, key));
    assert!(should_start_circle_scope_request("grant", "", false, key));
    assert!(!should_start_circle_scope_request("grant", key, false, key));
    assert!(!should_start_circle_scope_request("grant", "", true, key));
    assert!(should_start_circle_scope_request(
        "grant",
        key,
        false,
        "https://example.test\u{1f}did:web:alice\u{1f}ak:realm:two",
    ));
}

fn sidecar_projection_message(id: &str, strand_id: &str, body: &str) -> ChatMessage {
    sidecar_projection_message_for_realm("ak:realm:test", id, strand_id, body)
}

fn sidecar_projection_message_for_realm(
    realm_id: &str,
    id: &str,
    strand_id: &str,
    body: &str,
) -> ChatMessage {
    ChatMessage {
        realm_id: realm_id.to_owned(),
        id: id.to_owned(),
        protocol_message_id: None,
        sender: "did:web:example.test:alice".to_owned(),
        executed_by: None,
        body: body.to_owned(),
        timestamp: "12:00".to_owned(),
        created_at: None,
        strand_id: strand_id.to_owned(),
        reply_to: None,
        reactions: Vec::new(),
        redacted: false,
        edited: false,
        revisions: Vec::new(),
        pending: false,
        failed: false,
        error: None,
        mentions: Vec::new(),
        crypto_state: MessageCryptoState::Plaintext,
    }
}

/// A valid `delivered` Event-fold projection (§7.2.4 shape: no Pending, no
/// updated_hlc; coordinator + folded_frontier are required).
fn delivered_exchange_projection_fixture(
    realm_id: &str,
    source_strand_id: &str,
    private_strand_id: &str,
    source_frontier_anchor: Option<&str>,
    request_event_id: &str,
) -> arkret_sdk::AgentSidecarExchangeProjection {
    let coordinator = arkret_sdk::Did::new("did:web:example.test:agents:assistant").unwrap();
    let request_event = arkret_sdk::EventId::new(request_event_id).unwrap();
    arkret_sdk::AgentSidecarExchangeProjection {
        schema: arkret_sdk::AgentSidecarExchangeProjectionSchema::V1,
        controller_id: arkret_sdk::Did::new("did:web:example.test:alice").unwrap(),
        sidecar_id: arkret_sdk::SidecarId::new("ak:sidecar:01964137-0000-7000-8000-000000000007")
            .unwrap(),
        private_strand_id: arkret_sdk::StrandId::new(private_strand_id).unwrap(),
        exchange_id: arkret_sdk::AgentSidecarExchangeId::new("exchange-01964137000000000008")
            .unwrap(),
        origin: arkret_sdk::AgentSidecarExchangeOrigin::SourceTrackRouted,
        source_track_ref: arkret_sdk::AgentSidecarSourceTrackRef {
            realm_id: arkret_sdk::RealmId::new(realm_id).unwrap(),
            strand_id: arkret_sdk::StrandId::new(source_strand_id).unwrap(),
            track_name: "discussion".to_owned(),
        },
        source_frontier_anchor: source_frontier_anchor
            .map(|anchor| arkret_sdk::EventId::new(anchor).unwrap()),
        source_hlc: arkret_sdk::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        client_order_key: arkret_sdk::NonEmptyString::new("device-1-1").unwrap(),
        addressed_agent_ids: vec![coordinator.clone()],
        completion_policy: arkret_sdk::AgentSidecarExchangeCompletionPolicy::Coordinator,
        coordinator_agent_id: coordinator,
        coordinator_assignment_event_id: request_event.clone(),
        participating_agent_ids: Vec::new(),
        private_request_event_id: request_event.clone(),
        user_facing_response_event_ids: Vec::new(),
        status: arkret_sdk::AgentSidecarExchangeStatus::Delivered,
        failure_code: None,
        terminal_event_id: None,
        folded_frontier: arkret_sdk::AgentSidecarExchangeFoldedFrontier {
            event_ids: vec![request_event.clone()],
            event_set_digest: arkret_sdk::agent_sidecar_exchange_event_set_digest(&[request_event])
                .unwrap(),
            max_hlc: arkret_sdk::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        },
    }
}

#[test]
fn hosted_sidecar_projection_dedupes_echo_and_prefers_private_event() {
    let shared = "ak:strand:source";
    let private = "ak:strand:private";
    let messages = vec![
        sidecar_projection_message("ak:event:echo", shared, "echo overlay"),
        sidecar_projection_message("ak:event:shared", shared, "shared"),
        sidecar_projection_message("ak:event:echo", private, "private event"),
        sidecar_projection_message("ak:event:private", private, "native private"),
    ];

    let merged = project_visible_messages(
        &messages,
        shared,
        "ak:realm:test",
        Some((
            shared,
            private,
            arkret_sdk::AgentSidecarDisplayMode::ContextMerged,
        )),
        &[],
    );
    assert_eq!(merged.len(), 3);
    assert_eq!(merged[0].body, "private event");
    assert_eq!(merged[0].strand_id, private);
    assert_eq!(merged[1].body, "shared");
    assert_eq!(merged[2].body, "native private");

    let private_only = project_visible_messages(
        &messages,
        shared,
        "ak:realm:test",
        Some((
            shared,
            private,
            arkret_sdk::AgentSidecarDisplayMode::SidecarOnly,
        )),
        &[],
    );
    assert_eq!(private_only.len(), 2);
    assert!(
        private_only
            .iter()
            .all(|message| message.strand_id == private)
    );
}

#[test]
fn source_routed_echo_is_private_and_stably_follows_its_anchor() {
    let realm = "ak:realm:01964137-0000-7000-8000-000000000001";
    let source = "ak:strand:01964137-0000-7000-8000-000000000002";
    let private = "ak:strand:01964137-0000-7000-8000-000000000003";
    let anchor = "ak:event:01964137-0000-7000-8000-000000000004";
    let echo = "ak:event:01964137-0000-7000-8000-000000000005";
    let later = "ak:event:01964137-0000-7000-8000-000000000006";
    let projection =
        delivered_exchange_projection_fixture(realm, source, private, Some(anchor), echo);
    let messages = vec![
        sidecar_projection_message_for_realm(realm, anchor, source, "anchor"),
        sidecar_projection_message_for_realm(realm, later, source, "later shared"),
        sidecar_projection_message_for_realm(realm, echo, private, "private echo"),
    ];

    let visible = project_visible_messages(&messages, source, realm, None, &[projection]);

    assert_eq!(
        visible
            .iter()
            .map(|message| message.id.as_str())
            .collect::<Vec<_>>(),
        vec![anchor, echo, later]
    );
    assert_eq!(visible[1].strand_id, private);
}

#[test]
fn source_routed_echo_waits_until_its_anchor_is_visible() {
    let realm = "ak:realm:01964137-0000-7000-8000-000000000001";
    let source = "ak:strand:01964137-0000-7000-8000-000000000002";
    let private = "ak:strand:01964137-0000-7000-8000-000000000003";
    let missing_anchor = "ak:event:01964137-0000-7000-8000-000000000004";
    let echo = "ak:event:01964137-0000-7000-8000-000000000005";
    let mut projection =
        delivered_exchange_projection_fixture(realm, source, private, Some(missing_anchor), echo);
    let messages = vec![sidecar_projection_message_for_realm(
        realm,
        echo,
        private,
        "private echo",
    )];

    assert!(
        project_visible_messages(&messages, source, realm, None, &[projection.clone()]).is_empty()
    );

    projection.source_frontier_anchor = None;
    let visible = project_visible_messages(&messages, source, realm, None, &[projection]);
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].id, echo);
}

/// §7.2.1 producer shape: the typed request binding lives ONLY in the
/// `encrypted_metadata` plaintext (`message_metadata.sidecar_exchange_binding`)
/// and round-trips through the SDK's fail-closed consumer accessor; the wire
/// message payload carries no plaintext `metadata` at all.
#[test]
fn routed_request_binding_travels_only_in_encrypted_metadata_plaintext() {
    let context = arkret_sdk::AgentSidecarExchangeRequestContext {
        source_track_ref: arkret_sdk::AgentSidecarSourceTrackRef {
            realm_id: arkret_sdk::RealmId::new("ak:realm:01964137-0000-7000-8000-000000000001")
                .unwrap(),
            strand_id: arkret_sdk::StrandId::new("ak:strand:01964137-0000-7000-8000-000000000002")
                .unwrap(),
            track_name: "discussion".to_owned(),
        },
        source_hlc: arkret_sdk::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        client_order_key: arkret_sdk::NonEmptyString::new("device-1-1").unwrap(),
        addressed_agent_ids: vec![
            arkret_sdk::Did::new("did:web:example.test:agents:assistant").unwrap(),
        ],
        completion_policy: arkret_sdk::AgentSidecarExchangeCompletionPolicy::Coordinator,
        coordinator_agent_id: None,
        source_frontier_anchor: None,
    };
    let binding = arkret_sdk::AgentSidecarEventExchangeBinding::request(
        arkret_sdk::AgentSidecarExchangeId::new("exchange-01964137000000000008").unwrap(),
        context,
    )
    .unwrap();
    let mut metadata = arkret_sdk::MessageMetadata::default();
    metadata.set_sidecar_exchange_binding(&binding).unwrap();

    // The encrypted_metadata plaintext is exactly the MessageMetadata JSON
    // with the binding under the spec key.
    let plaintext = serde_json::to_value(&metadata).unwrap();
    assert!(
        plaintext
            .get(arkret_sdk::MESSAGE_METADATA_SIDECAR_EXCHANGE_BINDING_KEY)
            .is_some()
    );
    let parsed: arkret_sdk::MessageMetadata = serde_json::from_value(plaintext).unwrap();
    assert_eq!(parsed.sidecar_exchange_binding(), Some(binding));

    // The content block on the encrypted send path never carries the binding.
    let chat_content = chat_content_block_for_body("hi @assistant").unwrap();
    let content_value = chat_content.to_value().unwrap();
    assert!(
        !serde_json::to_string(&content_value)
            .unwrap()
            .contains(arkret_sdk::MESSAGE_METADATA_SIDECAR_EXCHANGE_BINDING_KEY),
        "the content block never carries the binding"
    );
}

#[test]
fn sidecar_native_message_never_appears_in_the_source_without_a_projection() {
    let realm = "ak:realm:01964137-0000-7000-8000-000000000001";
    let source = "ak:strand:01964137-0000-7000-8000-000000000002";
    let private = "ak:strand:01964137-0000-7000-8000-000000000003";
    let native = "ak:event:01964137-0000-7000-8000-000000000004";
    let messages = vec![sidecar_projection_message_for_realm(
        realm, native, private, "native",
    )];

    assert!(project_visible_messages(&messages, source, realm, None, &[]).is_empty());
}

const CHAT_FIXTURE_DEVICE: &str = "ak:device:01964137-0000-7000-8000-00000000cafe";
const CHAT_FIXTURE_SEED: [u8; 32] = [91; 32];

fn sign_chat_fixture(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                sign_chat_fixture(value);
            }
        }
        Value::Object(object) => {
            for child in object.values_mut() {
                sign_chat_fixture(child);
            }
            let Some(actor_id) = object
                .get("actor_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
            else {
                return;
            };
            if !actor_id.starts_with("did:") {
                return;
            }
            object.insert("device_id".to_owned(), json!(CHAT_FIXTURE_DEVICE));
            object.remove("proofs");
            object.remove("unsigned");
            let signer = crate::event_signer::build_ed25519_signer_with_verification_method(
                CHAT_FIXTURE_SEED,
                &actor_id,
                format!("{actor_id}#{CHAT_FIXTURE_DEVICE}"),
            );
            let canonical_bytes = crate::canonical::canonical_json_bytes(value).unwrap();
            let event_digest = crate::canonical::sha256_digest(&canonical_bytes);
            let mut proof = arkret_sdk::Proof {
                kind: "detached_jws".to_owned(),
                alg: signer.algorithm().to_owned(),
                verification_method: signer.verification_method().to_owned(),
                event_digest: arkret_sdk::Hash::new(event_digest).unwrap(),
                created_at: chrono::DateTime::parse_from_rfc3339("2026-07-10T00:00:00.000Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: String::new(),
            };
            let actor = arkret_sdk::Did::new(actor_id.clone()).unwrap();
            let binding = proof.canonical_binding_bytes(&actor).unwrap();
            proof.jws = signer.detached_jws_over(&binding).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert("proofs".to_owned(), json!([proof]));

            let signing_key = ed25519_dalek::SigningKey::from_bytes(&CHAT_FIXTURE_SEED);
            let did_key =
                crate::identity::did_key::did_key_from_verifying_key(&signing_key.verifying_key());
            let public_key =
                crate::identity::device_directory::public_key_from_directory_value(&did_key)
                    .unwrap();
            crate::identity::device_directory::seed_positive_for_test(
                &actor_id,
                CHAT_FIXTURE_DEVICE,
                public_key,
            );
        }
        _ => {}
    }
}

fn sign_chat_fixtures(values: &mut [Value]) {
    for value in values {
        sign_chat_fixture(value);
    }
}

/// The Welcome-receive shuttle iterates `events[]` from
/// `DeviceMessagesGetOutcome` and surfaces only
/// `ak.mls.welcome` payloads.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn collect_welcome_entries_filters_cx_mls_welcome_and_drops_other_kinds() {
    let value = json!({
        "events": [
            {"type": "ak.mls.welcome", "content": {"welcome_envelope_id": "w-1"}},
            {"type": "ak.key.verify.request", "content": {"ignore_me": true}},
            {"type": "ak.mls.welcome", "content": {"welcome_envelope_id": "w-2"}},
            {"type": "ak.mls.welcome", "content": {"welcome_envelope_id": "w-3"}},
            {"type": "ak.device.message", "content": {"ignore_me": true}},
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
        "id": "ak:event:body-shape",
        "type": "ak.message.create",
        "actor": "did:web:alice.example",
        "realm_id": "ak:realm:demo",
        "created_at": "2026-05-14T01:23:45.000Z",
        "causal": {"actor_seq": 42},
        "body": {
            "body": "restored from durable history",
            "strand_id": "ak:strand:announce",
            "message_id": "chat-msg-local",
            "mentions": [{
                "kind": "mention",
                "subject_id": "did:web:bob.example",
                "mention_text_original": "@bob"
            }]
        }
    });

    let message = chat_message_from_event("ak:realm:fallback", &event).unwrap();

    assert_eq!(message.id, "ak:event:body-shape");
    assert_eq!(message.realm_id, "ak:realm:demo");
    assert_eq!(message.strand_id, "ak:strand:announce");
    assert_eq!(message.body, "restored from durable history");
    assert_eq!(message.sender, "did:web:alice.example");
    assert_eq!(message.mentions[0].target_id(), "did:web:bob.example");
}

#[test]
fn parses_message_event_with_nested_envelope_payload_shape() {
    let mut event = json!({
        "event": {
            "event_id": "ak:event:nested",
            "kind": "ak.message.create",
            "actor_id": "did:web:alice.example",
            "actor_seq": 43,
            "payload": {
                "content": {
                    "kind": "ak.content.text",
                    "body": "nested payload message"
                },
                "strand_id": "ak:strand:support",
                "message_id": "chat-msg-nested"
            }
        }
    });
    sign_chat_fixture(&mut event);

    let message = chat_message_from_event("ak:realm:demo", &event).unwrap();

    assert_eq!(message.id, "ak:event:nested");
    assert_eq!(message.strand_id, "ak:strand:support");
    assert_eq!(message.body, "nested payload message");
}

#[test]
fn folds_received_redaction_tombstone_onto_message() {
    // soland surfaces a redacted ak.message.create as a per-message tombstone:
    // event_id preserved, body stripped, redacted/state markers added. The
    // receive path MUST render the tombstone (redacted=true, empty body) even
    // though this is the only copy of the message the reader ever sees.
    let mut event = json!({
        "kind": "ak.message.create",
        "event_id": "ak:event:tombstone",
        "message_id": "ak:message:tombstone",
        "realm_id": "ak:realm:demo",
        "strand_id": "ak:strand:support",
        "sender": "did:web:bob.example",
        "actor_id": "did:web:bob.example",
        "created_at": "2026-05-14T01:23:45.000Z",
        "redacted": true,
        "state": "redacted",
        "redacted_at": "2026-05-14T02:00:00.000Z",
        "redaction_ref": "ak:event:redact-1",
        "content": {"kind": "ak.content.text", "body": "[redacted]"}
    });
    sign_chat_fixture(&mut event);

    let message = chat_message_from_event("ak:realm:demo", &event).unwrap();

    assert_eq!(message.id, "ak:event:tombstone");
    assert!(message.redacted);
    assert_eq!(message.body, "");
}

#[test]
fn chat_visible_read_receipt_send_respects_preferences() {
    let temp = std::env::temp_dir().join(format!("inkson-chat-rr-pref-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    assert!(chat_visible_read_receipt_should_send(
        &store,
        "ak:strand:demo",
        "ak:realm:demo",
    ));

    store.set_read_receipt_default_send(false);
    assert!(!chat_visible_read_receipt_should_send(
        &store,
        "ak:strand:demo",
        "ak:realm:demo",
    ));

    store.set_read_receipt_realm_override("ak:realm:demo", Some(true));
    assert!(chat_visible_read_receipt_should_send(
        &store,
        "ak:strand:other",
        "ak:realm:demo",
    ));

    store.set_read_receipt_strand_override("ak:strand:demo", Some(false));
    assert!(!chat_visible_read_receipt_should_send(
        &store,
        "ak:strand:demo",
        "ak:realm:demo",
    ));

    store.set_read_receipt_policy_snapshot(
        "ak:realm:demo",
        Some(crate::state::ReadReceiptPolicySnapshot {
            disclosure: "required".to_owned(),
            visibility: Some("public".to_owned()),
        }),
    );
    assert!(chat_visible_read_receipt_should_send(
        &store,
        "ak:strand:demo",
        "ak:realm:demo",
    ));

    store.set_read_receipt_policy_snapshot(
        "ak:realm:demo",
        Some(crate::state::ReadReceiptPolicySnapshot {
            disclosure: "disabled".to_owned(),
            visibility: Some("private".to_owned()),
        }),
    );
    assert!(!chat_visible_read_receipt_should_send(
        &store,
        "ak:strand:demo",
        "ak:realm:demo",
    ));
}

#[test]
fn chat_visible_read_receipt_display_respects_local_preferences() {
    let temp = std::env::temp_dir().join(format!("inkson-chat-rr-display-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    assert!(chat_visible_read_receipt_should_display(
        &store,
        "ak:strand:demo",
        "ak:realm:demo",
    ));

    store.set_read_receipt_default_display(false);
    assert!(!chat_visible_read_receipt_should_display(
        &store,
        "ak:strand:demo",
        "ak:realm:demo",
    ));

    store.set_read_receipt_realm_display_override("ak:realm:demo", Some(true));
    assert!(chat_visible_read_receipt_should_display(
        &store,
        "ak:strand:other",
        "ak:realm:demo",
    ));

    store.set_read_receipt_strand_display_override("ak:strand:demo", Some(false));
    assert!(!chat_visible_read_receipt_should_display(
        &store,
        "ak:strand:demo",
        "ak:realm:demo",
    ));

    store.set_read_receipt_policy_snapshot(
        "ak:realm:demo",
        Some(crate::state::ReadReceiptPolicySnapshot {
            disclosure: "required".to_owned(),
            visibility: Some("public".to_owned()),
        }),
    );
    assert!(!chat_visible_read_receipt_should_display(
        &store,
        "ak:strand:demo",
        "ak:realm:demo",
    ));
}

#[test]
fn chat_message_create_operation_emits_schema_canonical_content() {
    let op = chat_message_create_operation(
        "ak:realm:01904100-0000-7000-8000-000000000010",
        "did:web:alice.example",
        "ak:strand:01904100-0000-7000-8000-000000000001",
        "discussion",
        "ak:message:01904100-0000-7000-8000-000000000001",
        "hello from chat",
        &[],
        None,
    )
    .expect("builds");

    assert_eq!(op.kind.as_str(), "ak.message.create");
    assert_eq!(
        op.payload["message_id"].as_str(),
        Some("ak:message:01904100-0000-7000-8000-000000000001")
    );
    assert_eq!(
        op.payload["strand_id"].as_str(),
        Some("ak:strand:01904100-0000-7000-8000-000000000001")
    );
    assert_eq!(op.payload["track_name"].as_str(), Some("discussion"));
    assert_eq!(
        op.payload["content"]["kind"].as_str(),
        Some("ak.content.text")
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
    arkret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind.as_str(),
            &serde_json::to_value(&op.payload).unwrap(),
        )
        .unwrap();
}

#[test]
fn chat_message_create_operation_blocks_sensitive_public_update() {
    let err = chat_message_create_operation(
        "ak:realm:01904100-0000-7000-8000-000000000010",
        "did:web:alice.example",
        "ak:strand:01904100-0000-7000-8000-000000000001",
        "discussion",
        "ak:message:01904100-0000-7000-8000-000000000001",
        "Public update: root cause leaked token",
        &[],
        None,
    )
    .expect_err("sensitive public updates must be blocked before send");

    assert!(err.to_string().contains("public_update_blocked"));
}

#[test]
fn chat_message_create_operation_keeps_public_update_notification_projection_out_of_content() {
    let op = chat_message_create_operation(
        "ak:realm:01904100-0000-7000-8000-000000000010",
        "did:web:alice.example",
        "ak:strand:01904100-0000-7000-8000-000000000001",
        "discussion",
        "ak:message:01904100-0000-7000-8000-000000000001",
        "SEV-1 public update: checkout latency is recovering",
        &[],
        None,
    )
    .expect("builds");

    assert!(op.payload.get("priority").is_none());
    assert!(op.payload["content"].get("priority").is_none());
    assert!(op.payload["content"].get("notification").is_none());
    assert_eq!(
        op.payload["content"]["body"].as_str(),
        Some("SEV-1 public update: checkout latency is recovering")
    );
    arkret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind.as_str(),
            &serde_json::to_value(&op.payload).unwrap(),
        )
        .unwrap();
}

#[test]
fn chat_message_create_operation_with_expiry_puts_contract_at_payload_top_level() {
    let expiry = arkret_sdk::DisappearingMessageExpiry::new(
        60_000,
        arkret_sdk::DisappearingMessageExpiryTrigger::OnFirstRead,
    )
    .unwrap()
    .with_grace_ms(5_000);
    let op = chat_message_create_operation_with_expiry(
        "ak:realm:01904100-0000-7000-8000-000000000010",
        "did:web:alice.example",
        "ak:strand:01904100-0000-7000-8000-000000000001",
        "discussion",
        "ak:message:01904100-0000-7000-8000-000000000005",
        "short lived",
        &[],
        None,
        Some(expiry),
    )
    .expect("builds");

    assert_eq!(op.payload["expiry"]["ttl_ms"], 60_000);
    assert_eq!(op.payload["expiry"]["trigger"], "on_first_read");
    assert_eq!(op.payload["expiry"]["grace_ms"], 5_000);
    assert!(op.payload["content"].get("expiry").is_none());
    arkret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind.as_str(),
            &serde_json::to_value(&op.payload).unwrap(),
        )
        .unwrap();
}

#[test]
fn chat_message_create_operation_embeds_audience_mentions_in_content_only() {
    let mentions = parse_mention_nodes("ping @here and @carol:example.com");
    let op = chat_message_create_operation(
        "ak:realm:01904100-0000-7000-8000-000000000010",
        "did:web:alice.example",
        "ak:strand:01904100-0000-7000-8000-000000000001",
        "discussion",
        "ak:message:01904100-0000-7000-8000-000000000002",
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
    arkret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind.as_str(),
            &serde_json::to_value(&op.payload).unwrap(),
        )
        .unwrap();
}

#[test]
fn chat_message_create_operation_embeds_agent_selector_mention_metadata() {
    let mentions = vec![MentionNode::mention(
        arkret_sdk::Mention::new(arkret_sdk::Did::new("did:web:agent.example".to_owned()).unwrap())
            .with_agent_selector_metadata(
                arkret_sdk::Did::new("did:web:example.com:users:alice".to_owned()).unwrap(),
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
    let op = chat_message_create_operation(
        "ak:realm:01904100-0000-7000-8000-000000000010",
        "did:web:bob.example",
        "ak:strand:01904100-0000-7000-8000-000000000001",
        "discussion",
        "ak:message:01904100-0000-7000-8000-000000000003",
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
    arkret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind.as_str(),
            &serde_json::to_value(&op.payload).unwrap(),
        )
        .unwrap();
}

#[test]
fn mention_sidecar_hashes_are_applied_to_replayed_events() {
    let realm = "ak:realm:01904100-0000-7000-8000-000000000010";
    let mentions = vec![MentionNode::mention(arkret_sdk::Mention::new(
        arkret_sdk::Did::new("did:web:agent.example".to_owned()).unwrap(),
    ))];
    let mut event = chat_message_create_operation(
        realm,
        "did:web:alice.example",
        "ak:strand:01904100-0000-7000-8000-000000000001",
        "discussion",
        "ak:message:01904100-0000-7000-8000-000000000003",
        "hello agent",
        &mentions,
        None,
    )
    .expect("builds");

    apply_mention_sidecar_hashes(&mut event, realm, &mentions);

    let hashes = event.payload["content"]["mention_sidecar_hash"]
        .as_array()
        .expect("mention sidecar hashes");
    assert_eq!(hashes.len(), 1);
    assert_eq!(hashes[0].as_str().map(str::len), Some(64));
}

#[test]
fn chat_message_create_operation_includes_reply_fields_only_when_present() {
    let op = chat_message_create_operation(
        "ak:realm:01904100-0000-7000-8000-000000000010",
        "did:web:alice.example",
        "ak:strand:01904100-0000-7000-8000-000000000001",
        "discussion",
        "ak:message:01904100-0000-7000-8000-000000000003",
        "reply body",
        &[],
        Some("ak:message:01904100-0000-7000-8000-000000000004"),
    )
    .expect("builds");

    assert_eq!(
        op.payload["reply_to"].as_str(),
        Some("ak:message:01904100-0000-7000-8000-000000000004")
    );
    assert!(op.payload.get("thread_id").is_none());
    arkret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind.as_str(),
            &serde_json::to_value(&op.payload).unwrap(),
        )
        .unwrap();
}

#[test]
fn chat_message_create_operation_rejects_event_id_reply_target() {
    let err = chat_message_create_operation(
        "ak:realm:01904100-0000-7000-8000-000000000010",
        "did:web:alice.example",
        "ak:strand:01904100-0000-7000-8000-000000000001",
        "discussion",
        "ak:message:01904100-0000-7000-8000-000000000003",
        "reply body",
        &[],
        Some("ak:event:01904100-0000-7000-8000-000000000004"),
    )
    .expect_err("event ids are not valid message reply targets");

    assert!(err.to_string().contains("reply_to must be a ak:message id"));
}

#[test]
fn chat_message_reply_target_prefers_protocol_message_id() {
    let message = ChatMessage {
        realm_id: "ak:realm:demo".to_owned(),
        id: "ak:event:01964137-0000-7000-8000-000000000001".to_owned(),
        protocol_message_id: Some("ak:message:01964137-0000-7000-8000-000000000002".to_owned()),
        sender: "did:web:example.com:users:bob".to_owned(),
        executed_by: None,
        body: "hello".to_owned(),
        timestamp: "10:00".to_owned(),
        created_at: None,
        strand_id: "ak:strand:demo".to_owned(),
        reply_to: None,
        reactions: Vec::new(),
        redacted: false,
        edited: false,
        revisions: Vec::new(),
        pending: false,
        failed: false,
        error: None,
        mentions: Vec::new(),
        crypto_state: MessageCryptoState::Plaintext,
    };

    assert_eq!(
        message.reply_target_ref(),
        Some("ak:message:01964137-0000-7000-8000-000000000002")
    );
}

#[test]
fn chat_message_mutation_target_prefers_protocol_message_id_after_revision() {
    let message = ChatMessage {
        realm_id: "ak:realm:demo".to_owned(),
        id: "ak:operation:01964137-0000-7000-8000-000000000001".to_owned(),
        protocol_message_id: Some("ak:message:01964137-0000-7000-8000-000000000002".to_owned()),
        sender: "did:web:example.com:users:bob".to_owned(),
        executed_by: None,
        body: "edited".to_owned(),
        timestamp: "10:00".to_owned(),
        created_at: None,
        strand_id: "ak:strand:demo".to_owned(),
        reply_to: None,
        reactions: Vec::new(),
        redacted: false,
        edited: true,
        revisions: vec!["hello".to_owned()],
        pending: false,
        failed: false,
        error: None,
        mentions: Vec::new(),
        crypto_state: MessageCryptoState::Plaintext,
    };

    assert_eq!(
        message.mutation_target_ref(),
        "ak:message:01964137-0000-7000-8000-000000000002"
    );
}

#[test]
fn shared_pin_operations_use_pin_events_not_account_data() {
    let strand_id = "ak:strand:01904100-0000-7000-8000-000000000001";
    let pin_scope = SharedPinScope::strand(strand_id);
    let target_ref = "ak:message:01904100-0000-7000-8000-000000000002";
    let add = shared_message_pin_add_operation(
        "ak:realm:01904100-0000-7000-8000-000000000010",
        "did:web:alice.example",
        &pin_scope,
        target_ref,
        "r100",
    )
    .expect("shared pin add builds");

    assert_eq!(add.kind.as_str(), "ak.pin.add");
    assert_eq!(add.payload["pin_scope"]["kind"], "strand");
    assert_eq!(add.payload["pin_scope"]["id"], strand_id);
    assert_eq!(add.payload["target_ref"], target_ref);
    assert_eq!(add.payload["rank"], "r100");
    assert!(add.payload.get("key").is_none());
    assert!(add.payload.get("encrypted_payload").is_none());
    assert!(add.payload.get("body").is_none());

    let remove = shared_message_pin_remove_operation(
        "ak:realm:01904100-0000-7000-8000-000000000010",
        "did:web:alice.example",
        &pin_scope,
        target_ref,
    )
    .expect("shared pin remove builds");
    assert_eq!(remove.kind.as_str(), "ak.pin.remove");
    assert_eq!(remove.payload["target_ref"], target_ref);
    assert!(remove.payload.get("key").is_none());
    arkret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            add.kind.as_str(),
            &serde_json::to_value(&add.payload).unwrap(),
        )
        .unwrap();
    arkret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            remove.kind.as_str(),
            &serde_json::to_value(&remove.payload).unwrap(),
        )
        .unwrap();
}

#[test]
fn default_discussion_shared_pin_uses_realm_scope() {
    let realm_id = "ak:realm:01904100-0000-7000-8000-000000000010";
    let strand_id = default_discussion_strand_id(realm_id);
    let pin_scope = shared_pin_scope_for_message(realm_id, &strand_id);
    let target_ref = "ak:message:01904100-0000-7000-8000-000000000002";
    let add = shared_message_pin_add_operation(
        realm_id,
        "did:web:alice.example",
        &pin_scope,
        target_ref,
        "r100",
    )
    .expect("shared pin add builds");

    assert_eq!(add.kind.as_str(), "ak.pin.add");
    assert_eq!(add.payload["pin_scope"]["kind"], "realm");
    assert_eq!(add.payload["pin_scope"]["id"], realm_id);
    assert_eq!(add.payload["target_ref"], target_ref);
    arkret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            add.kind.as_str(),
            &serde_json::to_value(&add.payload).unwrap(),
        )
        .unwrap();
}

#[test]
fn private_saved_item_uses_saved_account_data_not_pin_event() {
    let namespace_key =
        crate::account_data::productivity_account_data_namespace_key("test-account-secret")
            .expect("namespace key");
    let target_ref = "ak:message:01904100-0000-7000-8000-000000000002";
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
        "ak:realm:01904100-0000-7000-8000-000000000010",
        "did:web:alice.example",
        &item.account_data_key,
        wire,
    )
    .unwrap()
    .build("inkson");
    assert_eq!(op.kind, "ak.account_data.set");
    assert_eq!(op.payload["key"], item.account_data_key);
    assert_eq!(op.payload["encrypted_payload"]["kind"], "saved_item");
    assert!(op.payload.get("body").is_none());
    assert_ne!(op.kind, "ak.pin.add");
}

#[test]
fn shared_pin_projection_ignores_private_saved_account_data() {
    use chrono::Utc;

    let strand_id = "ak:strand:01904100-0000-7000-8000-000000000001";
    let pin_scope = SharedPinScope::strand(strand_id);
    let other_strand_id = "ak:strand:01904100-0000-7000-8000-000000000099";
    let target_ref = "ak:message:01904100-0000-7000-8000-000000000002";
    let other_target = "ak:message:01904100-0000-7000-8000-000000000003";
    let records = vec![
        crate::state::RawOperationRecord {
            operation_id: "ak:operation:pin-add".to_owned(),
            realm_id: Some("ak:realm:demo".to_owned()),
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
            realm_id: Some("ak:realm:demo".to_owned()),
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
            realm_id: Some("ak:realm:demo".to_owned()),
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
            realm_id: Some("ak:realm:demo".to_owned()),
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

#[test]
fn chat_message_ids_use_schema_prefix() {
    let id = new_chat_message_id();

    assert!(id.starts_with("ak:message:"));
    assert!(is_schema_message_id(&id));
    assert!(is_schema_message_id("ak:message:local-1"));
    assert!(!is_schema_message_id("chat-msg-local"));
    assert!(schema_message_id_or_new("chat-msg-local").starts_with("ak:message:"));
}

#[test]
fn restores_messages_from_local_raw_operations() {
    let state = ClientLocalState {
        raw_operations: vec![crate::state::RawOperationRecord {
            operation_id: "ak:operation:local".to_owned(),
            realm_id: Some("ak:realm:local".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "event_id": "ak:event:local",
                "kind": "ak.message.create",
                "actor": "did:web:alice.example",
                "body": "local fallback message",
                "strand_id": "ak:strand:announce",
                "message_id": "chat-msg-local"
            }),
        }],
        ..ClientLocalState::default()
    };

    let messages = chat_messages_from_local_state_with_sidecar(&state, None, None);

    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].realm_id, "ak:realm:local");
    assert_eq!(messages[0].strand_id, "ak:strand:announce");
    assert_eq!(messages[0].sender, "did:web:alice.example");
    assert_eq!(messages[0].body, "local fallback message");
}

#[test]
fn restores_canonical_actor_id_from_local_raw_operations() {
    let mut state = ClientLocalState {
        raw_operations: vec![crate::state::RawOperationRecord {
            operation_id: "ak:operation:local".to_owned(),
            realm_id: Some("ak:realm:local".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "event_id": "ak:event:local",
                "kind": "ak.message.create",
                "actor_id": "did:web:local.host:users:alice",
                "realm_id": "ak:realm:local",
                "body": "canonical local message",
                "strand_id": "ak:strand:announce",
                "message_id": "chat-msg-local"
            }),
        }],
        ..ClientLocalState::default()
    };
    sign_chat_fixture(&mut state.raw_operations[0].payload);

    let messages = chat_messages_from_local_state_with_sidecar(&state, None, None);

    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].sender, "did:web:local.host:users:alice");
    assert_eq!(messages[0].body, "canonical local message");
}

#[test]
fn message_operations_from_events_folds_create_and_renders_local_first() {
    // Discussion local-first: a canonical `ak.message.create` from the realm
    // timeline folds into a `raw_operations` record (full event payload,
    // dedup id = event_id) that `chat_messages_from_local_state_with_sidecar`
    // renders WITHOUT any backfill — the event-sourced replacement for the
    // per-open realm refetch.
    let mut create = json!({
        "event_id": "ak:event:msg-1",
        "kind": "ak.message.create",
        "actor_id": "did:web:bob.example",
        "realm_id": "ak:realm:r1",
        "created_at": "2026-05-22T10:00:00.000Z",
        "strand_id": "ak:strand:topic",
        "message_id": "ak:message:m1",
        "body": "hello from bob"
    });
    sign_chat_fixture(&mut create);
    // A non-message timeline event (e.g. a poll close) MUST be ignored.
    let poll = json!({
        "event_id": "ak:event:poll-1",
        "kind": "ak.content.poll.close",
        "realm_id": "ak:realm:r1",
        "strand_id": "ak:strand:topic"
    });

    let records = message_operations_from_events("ak:realm:r1", &[create.clone(), poll]);
    assert_eq!(records.len(), 1, "only the message-create event is folded");
    assert_eq!(records[0].operation_id, "ak:event:msg-1");
    assert_eq!(records[0].realm_id.as_deref(), Some("ak:realm:r1"));
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
    assert_eq!(messages[0].strand_id, "ak:strand:topic");
    assert_eq!(messages[0].sender, "did:web:bob.example");
    assert_eq!(messages[0].body, "hello from bob");
}

#[test]
fn chat_messages_read_projected_reaction_summary() {
    let mut events = vec![json!({
        "event_id": "ak:event:msg-1",
        "kind": "ak.message.create",
        "actor_id": "did:web:alice.example",
        "realm_id": "ak:realm:r1",
        "created_at": "2026-05-22T10:00:00.000Z",
        "strand_id": "ak:strand:topic",
        "message_id": "ak:message:m1",
        "body": "hello from alice",
        "reaction_summary": {
            "+1": ["did:web:bob.example", "did:web:carol.example"]
        }
    })];
    sign_chat_fixtures(&mut events);

    let messages = chat_messages_from_events_with_sidecar("ak:realm:r1", &events, None, None);

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].reactions,
        vec![(
            "+1".to_owned(),
            vec![
                "did:web:bob.example".to_owned(),
                "did:web:carol.example".to_owned()
            ],
        )]
    );
}

#[test]
fn chat_messages_fold_reaction_events_by_target_ref() {
    let mut events = vec![
        json!({
            "event_id": "ak:event:msg-1",
            "kind": "ak.message.create",
            "actor_id": "did:web:alice.example",
            "realm_id": "ak:realm:r1",
            "created_at": "2026-05-22T10:00:00.000Z",
            "strand_id": "ak:strand:topic",
            "message_id": "ak:message:m1",
            "body": "hello from alice"
        }),
        json!({
            "event_id": "ak:event:react-bob",
            "kind": "ak.reaction.add",
            "actor_id": "did:web:bob.example",
            "realm_id": "ak:realm:r1",
            "target_ref": "ak:message:m1",
            "key": "+1"
        }),
        json!({
            "event_id": "ak:event:react-carol",
            "kind": "ak.reaction.add",
            "actor_id": "did:web:carol.example",
            "realm_id": "ak:realm:r1",
            "target_ref": "ak:event:msg-1",
            "key": "+1"
        }),
        json!({
            "event_id": "ak:event:remove-bob",
            "kind": "ak.reaction.remove",
            "actor_id": "did:web:bob.example",
            "realm_id": "ak:realm:r1",
            "target_ref": "ak:message:m1",
            "key": "+1"
        }),
    ];
    sign_chat_fixtures(&mut events);

    let messages = chat_messages_from_events_with_sidecar("ak:realm:r1", &events, None, None);

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].reactions,
        vec![("+1".to_owned(), vec!["did:web:carol.example".to_owned()])]
    );

    let records = message_operations_from_events("ak:realm:r1", &events);
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
    assert_eq!(
        restored[0].reactions,
        vec![("+1".to_owned(), vec!["did:web:carol.example".to_owned()])]
    );
}

#[test]
fn chat_messages_fold_projection_reaction_target_ref_over_envelope_message_id() {
    let mut events = vec![
        json!({
            "event_id": "ak:event:create-projection",
            "event_kind": "ak.message.create",
            "actor_id": "did:web:alice.example",
            "sender_actor_id": "did:web:alice.example",
            "realm_id": "ak:realm:r1",
            "created_at": "2026-07-08T01:44:39.000Z",
            "strand_id": "ak:strand:topic",
            "track_name": "discussion",
            "message_id": "ak:message:envelope-create",
            "payload": {
                "content": {"kind": "ak.content.text", "body": "projection hello"},
                "event_id": "ak:event:create-projection",
                "message_id": "ak:message:canonical-target",
                "sender": "did:web:alice.example",
                "strand_id": "ak:strand:topic",
                "thread_id": "ak:strand:topic",
                "track_name": "discussion"
            }
        }),
        json!({
            "event_id": "ak:event:reaction-projection",
            "event_kind": "ak.reaction.add",
            "actor_id": "did:web:bob.example",
            "sender_actor_id": "did:web:bob.example",
            "realm_id": "ak:realm:r1",
            "created_at": "2026-07-08T01:44:43.000Z",
            "strand_id": "ak:strand:topic",
            "track_name": "discussion",
            "message_id": "ak:message:envelope-reaction",
            "payload": {
                "event_id": "ak:event:reaction-projection",
                "key": "+1",
                "sender": "did:web:bob.example",
                "target_ref": "ak:message:canonical-target"
            }
        }),
    ];
    sign_chat_fixtures(&mut events);

    let messages = chat_messages_from_events_with_sidecar("ak:realm:r1", &events, None, None);

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].protocol_message_id.as_deref(),
        Some("ak:message:canonical-target")
    );
    assert_eq!(
        messages[0].reactions,
        vec![("+1".to_owned(), vec!["did:web:bob.example".to_owned()])]
    );

    let records = message_operations_from_events("ak:realm:r1", &events);
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
        Some("ak:message:canonical-target")
    );
    assert_eq!(
        restored[0].reactions,
        vec![("+1".to_owned(), vec!["did:web:bob.example".to_owned()])]
    );
}

#[test]
fn chat_messages_fold_canonical_create_with_streamed_reaction_envelope() {
    let mut events = vec![
        json!({
            "event_id": "ak:event:01904100-0000-7000-8000-000000000101",
            "kind": "ak.message.create",
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
            "actor_id": "did:web:alice.example",
            "actor_seq": 1,
            "created_at": "2026-07-08T01:44:39.000Z",
            "hlc": "01970e589d21-0004-a13f9c2e",
            "prev_refs": [],
            "refs": [],
            "payload": {
                "content": {"kind": "ak.content.text", "body": "canonical hello"},
                "message_id": "ak:message:01904100-0000-7000-8000-000000000201",
                "strand_id": "ak:strand:01904100-0000-7000-8000-000000000301",
                "track_name": "discussion"
            }
        }),
        json!({
            "event_id": "ak:event:01904100-0000-7000-8000-000000000102",
            "kind": "ak.reaction.add",
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
            "actor_id": "did:web:bob.example",
            "actor_seq": 2,
            "created_at": "2026-07-08T01:44:43.000Z",
            "hlc": "01970e589d22-0004-a13f9c2e",
            "prev_refs": [],
            "refs": [],
            "payload": {
                "key": "👍",
                "target_ref": "ak:message:01904100-0000-7000-8000-000000000201"
            }
        }),
    ];
    sign_chat_fixtures(&mut events);

    let records =
        message_operations_from_events("ak:realm:01904100-0000-7000-8000-000000000001", &events);
    let state = ClientLocalState {
        raw_operations: records,
        ..ClientLocalState::default()
    };
    let messages = chat_messages_from_local_state_with_sidecar(&state, None, None);

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].protocol_message_id.as_deref(),
        Some("ak:message:01904100-0000-7000-8000-000000000201")
    );
    assert_eq!(
        messages[0].reactions,
        vec![("👍".to_owned(), vec!["did:web:bob.example".to_owned()])]
    );
}

#[test]
fn durable_reaction_folds_onto_controller_only_create() {
    let realm_id = "ak:realm:01904100-0000-7000-8000-000000000001";
    let message_id = "ak:message:01904100-0000-7000-8000-000000000201";
    let mut events = vec![
        json!({
            "event_id": "ak:event:01904100-0000-7000-8000-000000000101",
            "kind": "ak.message.create",
            "realm_id": realm_id,
            "actor_id": "did:web:alice.example",
            "actor_seq": 1,
            "created_at": "2026-07-08T01:44:39.000Z",
            "hlc": "01970e589d21-0004-a13f9c2e",
            "prev_refs": [],
            "refs": [],
            "payload": {
                "content": {"kind": "ak.content.text", "body": "optimistic first"},
                "message_id": message_id,
                "strand_id": "ak:strand:01904100-0000-7000-8000-000000000301",
                "track_name": "discussion"
            }
        }),
        json!({
            "event_id": "ak:event:01904100-0000-7000-8000-000000000102",
            "kind": "ak.reaction.add",
            "realm_id": realm_id,
            "actor_id": "did:web:bob.example",
            "actor_seq": 2,
            "created_at": "2026-07-08T01:44:43.000Z",
            "hlc": "01970e589d22-0004-a13f9c2e",
            "prev_refs": [],
            "refs": [],
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
    assert_eq!(
        messages[0].reactions,
        vec![("👍".to_owned(), vec!["did:web:bob.example".to_owned()])]
    );
}

#[test]
fn durable_redaction_folds_onto_controller_only_create() {
    let realm_id = "ak:realm:01904100-0000-7000-8000-000000000001";
    let message_id = "ak:message:01904100-0000-7000-8000-000000000201";
    let seed = vec![ChatMessage {
        id: "ak:event:01904100-0000-7000-8000-000000000101".to_owned(),
        protocol_message_id: Some(message_id.to_owned()),
        realm_id: realm_id.to_owned(),
        strand_id: "ak:strand:01904100-0000-7000-8000-000000000301".to_owned(),
        sender: "did:web:alice.example".to_owned(),
        body: "sensitive body".to_owned(),
        timestamp: "10:00".to_owned(),
        created_at: None,
        pending: false,
        failed: false,
        error: None,
        executed_by: None,
        edited: false,
        redacted: false,
        revisions: Vec::new(),
        reply_to: None,
        reactions: Vec::new(),
        mentions: Vec::new(),
        crypto_state: MessageCryptoState::Plaintext,
    }];
    let mut redactions = vec![json!({
        "event_id": "ak:event:01904100-0000-7000-8000-000000000102",
        "kind": "ak.message.redact",
        "realm_id": realm_id,
        "actor_id": "did:web:alice.example",
        "actor_seq": 2,
        "created_at": "2026-07-08T01:44:43.000Z",
        "hlc": "01970e589d22-0004-a13f9c2e",
        "prev_refs": [],
        "refs": [],
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
    let mut events = vec![
        json!({
            "event_id": "ak:event:msg-3",
            "kind": "ak.message.create",
            "actor_id": "did:web:bob.example",
            "realm_id": "ak:realm:r1",
            "created_at": "2026-05-22T10:00:00.000Z",
            "strand_id": "ak:strand:topic",
            "message_id": "ak:message:m3",
            "content": {"kind": "ak.content.text", "body": "v1"}
        }),
        json!({
            "event_id": "ak:event:msg-3-rev-1",
            "kind": "ak.message.revise",
            "actor_id": "did:web:bob.example",
            "realm_id": "ak:realm:r1",
            "created_at": "2026-05-22T10:01:00.000Z",
            "strand_id": "ak:strand:topic",
            "target_ref": "ak:message:m3",
            "content": {"kind": "ak.content.text", "body": "v2"}
        }),
        json!({
            "event_id": "ak:event:msg-3-rev-2",
            "kind": "ak.message.revise",
            "actor_id": "did:web:bob.example",
            "realm_id": "ak:realm:r1",
            "created_at": "2026-05-22T10:02:00.000Z",
            "strand_id": "ak:strand:topic",
            "target_ref": "ak:message:m3",
            "content": {"kind": "ak.content.text", "body": "v3"}
        }),
    ];
    sign_chat_fixtures(&mut events);

    let messages = chat_messages_from_events_with_sidecar("ak:realm:r1", &events, None, None);

    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].id, "ak:event:msg-3");
    assert_eq!(messages[0].body, "v3");
    assert!(messages[0].edited);
    assert_eq!(
        messages[0].revisions,
        vec!["v1".to_owned(), "v2".to_owned()]
    );

    let stale_state = ClientLocalState {
        raw_operations: message_operations_from_events("ak:realm:r1", &events[..2]),
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

    let records = message_operations_from_events("ak:realm:r1", &events);
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
fn chat_messages_keep_folded_timeline_revision_over_older_backfill_create() {
    let message_id = "ak:message:019f3b27-f521-70f0-84f3-e06f95177dbf";
    let reply_to = "ak:message:019f3b27-e366-7d70-9fe4-fb3e8442b449";
    let mut events = vec![
        json!({
            "event_id": "ak:event:019f3b27-fb61-7ed3-af84-04cc68eac2f6",
            "kind": "ak.message.create",
            "actor_id": "did:web:bob.example",
            "realm_id": "ak:realm:r1",
            "created_at": "2026-07-07T05:58:23.000Z",
            "strand_id": "ak:strand:topic",
            "message_id": message_id,
            "content": {"kind": "ak.content.text", "body": "edited body"}
        }),
        json!({
            "event_id": "ak:event:019f3b27-f523-7571-89cb-5e27479d5e6d",
            "kind": "ak.message.create",
            "actor_id": "did:web:bob.example",
            "realm_id": "ak:realm:r1",
            "created_at": "2026-07-07T05:58:22.000Z",
            "payload": {
                "content": {"kind": "ak.content.text", "body": "original body"},
                "message_id": message_id,
                "reply_to": reply_to,
                "strand_id": "ak:strand:topic",
                "track_name": "discussion"
            }
        }),
        json!({
            "event_id": "ak:event:019f3b27-fb61-7ed3-af84-04cc68eac2f6",
            "kind": "ak.message.revise",
            "actor_id": "did:web:bob.example",
            "realm_id": "ak:realm:r1",
            "created_at": "2026-07-07T05:58:23.000Z",
            "payload": {
                "content": {"kind": "ak.content.text", "body": "edited body"},
                "target_ref": message_id
            }
        }),
    ];
    sign_chat_fixtures(&mut events);

    let messages = chat_messages_from_events_with_sidecar("ak:realm:r1", &events, None, None);

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
            "event_id": "ak:event:msg-4-rev-1",
            "kind": "ak.message.revise",
            "actor_id": "did:web:bob.example",
            "realm_id": "ak:realm:r1",
            "created_at": "2026-05-22T10:01:00.000Z",
            "strand_id": "ak:strand:topic",
            "target_ref": "ak:message:m4",
            "redacted": true,
            "state": "redacted",
            "content": {"kind": "ak.content.text", "body": "[redacted]"}
        }),
        json!({
            "event_id": "ak:event:msg-4",
            "kind": "ak.message.create",
            "actor_id": "did:web:bob.example",
            "realm_id": "ak:realm:r1",
            "created_at": "2026-05-22T10:00:00.000Z",
            "strand_id": "ak:strand:topic",
            "message_id": "ak:message:m4",
            "redacted": true,
            "state": "redacted",
            "content": {"kind": "ak.content.text", "body": "[redacted]"}
        }),
    ];
    sign_chat_fixtures(&mut events);

    let messages = chat_messages_from_events_with_sidecar("ak:realm:r1", &events, None, None);

    assert_eq!(messages.len(), 1);
    assert!(messages[0].redacted);
}

#[test]
fn chat_messages_keep_standalone_server_redacted_revision_tombstone() {
    let events = vec![json!({
        "event_id": "ak:event:msg-4-rev-2",
        "kind": "ak.message.revise",
        "actor_id": "did:web:bob.example",
        "realm_id": "ak:realm:r1",
        "created_at": "2026-05-22T10:02:00.000Z",
        "payload": {
            "content": {"kind": "ak.content.text", "body": "[redacted]"},
            "message_id": "ak:message:m4",
            "redacted": true,
            "redacted_at": "2026-05-22T10:05:00.000Z",
            "redaction_ref": "ak:event:redact-4",
            "state": "redacted"
        },
        "unsigned": {
            "local_target_ref": "ak:message:m4",
            "projection_only": true
        },
        "proofs": []
    })];

    let messages = chat_messages_from_events_with_sidecar("ak:realm:r1", &events, None, None);

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].protocol_message_id.as_deref(),
        Some("ak:message:m4")
    );
    assert!(messages[0].redacted);
    assert!(messages[0].body.is_empty());
}

#[test]
fn chat_messages_fold_nested_server_redacted_revision_tombstone_into_root_tombstone() {
    let mut events = vec![
        json!({
            "event_id": "ak:event:msg-5",
            "kind": "ak.message.create",
            "realm_id": "ak:realm:r1",
            "actor_id": "did:web:bob.example",
            "created_at": "2026-05-22T10:00:00.000Z",
            "payload": {
                "content": {"kind": "ak.content.text", "body": "[redacted]"},
                "event_id": "ak:event:msg-5",
                "message_id": "ak:message:m5",
                "redacted": true,
                "redacted_at": "2026-05-22T10:05:00.000Z",
                "redaction_ref": "ak:event:redact-5",
                "sender": "did:web:bob.example",
                "state": "redacted",
                "strand_id": "ak:strand:topic"
            },
            "proofs": []
        }),
        json!({
            "event_id": "ak:event:msg-5-rev-1",
            "kind": "ak.message.revise",
            "realm_id": "ak:realm:r1",
            "actor_id": "did:web:bob.example",
            "created_at": "2026-05-22T10:01:00.000Z",
            "payload": {
                "content": {"kind": "ak.content.text", "body": "[redacted]"},
                "event_id": "ak:event:msg-5-rev-1",
                "redacted": true,
                "redacted_at": "2026-05-22T10:05:00.000Z",
                "redaction_ref": "ak:event:redact-5",
                "sender": "did:web:bob.example",
                "state": "redacted",
                "target_ref": "ak:message:m5"
            },
            "proofs": []
        }),
    ];
    sign_chat_fixtures(&mut events);

    let messages = chat_messages_from_events_with_sidecar("ak:realm:r1", &events, None, None);

    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].id, "ak:event:msg-5");
    assert!(messages[0].redacted);
}

#[test]
fn merge_chat_messages_dedupes_tombstones_by_protocol_message_id() {
    fn redacted_message(id: &str, protocol_message_id: &str) -> ChatMessage {
        ChatMessage {
            realm_id: "ak:realm:r1".to_owned(),
            id: id.to_owned(),
            protocol_message_id: Some(protocol_message_id.to_owned()),
            sender: "did:web:bob.example".to_owned(),
            executed_by: None,
            body: String::new(),
            timestamp: "10:05".to_owned(),
            created_at: None,
            strand_id: "ak:strand:topic".to_owned(),
            reply_to: None,
            reactions: Vec::new(),
            redacted: true,
            edited: false,
            revisions: Vec::new(),
            pending: false,
            failed: false,
            error: None,
            mentions: Vec::new(),
            crypto_state: MessageCryptoState::Plaintext,
        }
    }

    let protocol_message_id = "ak:message:m6";
    let mut target = vec![
        redacted_message("ak:event:msg-6", protocol_message_id),
        redacted_message("ak:event:msg-6-rev-1", protocol_message_id),
        ChatMessage {
            body: "unrelated".to_owned(),
            redacted: false,
            protocol_message_id: Some("ak:message:other".to_owned()),
            id: "ak:event:other".to_owned(),
            ..redacted_message("ak:event:other", "ak:message:other")
        },
    ];
    target[0].edited = true;
    target[0].revisions.push("v1".to_owned());

    merge_chat_messages(
        &mut target,
        vec![redacted_message("ak:event:msg-6", protocol_message_id)],
    );

    let matching = target
        .iter()
        .filter(|message| message.protocol_message_id.as_deref() == Some(protocol_message_id))
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0].id, "ak:event:msg-6");
    assert!(matching[0].redacted);
    assert!(matching[0].edited);
    assert_eq!(matching[0].revisions, vec!["v1".to_owned()]);
    assert!(target.iter().any(|message| message.id == "ak:event:other"));
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
            realm_id: "ak:realm:r1".to_owned(),
            id: id.to_owned(),
            protocol_message_id: Some(protocol_message_id.to_owned()),
            sender: "did:web:bob.example".to_owned(),
            executed_by: None,
            body: body.to_owned(),
            timestamp: "10:00".to_owned(),
            created_at: at(created_at),
            strand_id: "ak:strand:topic".to_owned(),
            reply_to: Some("ak:message:m1".to_owned()),
            reactions: Vec::new(),
            redacted: false,
            edited: false,
            revisions: Vec::new(),
            pending: false,
            failed: false,
            error: None,
            mentions: Vec::new(),
            crypto_state: MessageCryptoState::Plaintext,
        }
    }

    let protocol_message_id = "ak:message:m2";
    let mut target = vec![message(
        "ak:event:msg-2-rev-1",
        protocol_message_id,
        "edited body",
        "2026-07-07T06:19:22.000Z",
    )];
    target[0].edited = true;

    let mut incoming = message(
        "ak:event:msg-2",
        protocol_message_id,
        "original body",
        "2026-07-07T06:19:20.000Z",
    );
    incoming.reactions = vec![(
        "+1".to_owned(),
        vec![
            "did:web:bob.example".to_owned(),
            "did:web:carol.example".to_owned(),
        ],
    )];

    merge_chat_messages(&mut target, vec![incoming]);

    assert_eq!(target.len(), 1);
    assert_eq!(target[0].id, "ak:event:msg-2-rev-1");
    assert_eq!(target[0].body, "edited body");
    assert!(target[0].edited);
    assert_eq!(target[0].revisions, vec!["original body"]);
    assert_eq!(target[0].reply_to.as_deref(), Some("ak:message:m1"));
    assert_eq!(
        target[0].reactions,
        vec![(
            "+1".to_owned(),
            vec![
                "did:web:bob.example".to_owned(),
                "did:web:carol.example".to_owned()
            ],
        )]
    );
}

#[test]
fn message_operations_redaction_tombstone_dedupes_over_create_by_event_id() {
    // The server folds a redaction into a tombstone form reusing the same
    // `ak.message.create` kind + `event_id`. Both fold to the SAME
    // `operation_id`, so `upsert_raw_operation` replaces the create with the
    // tombstone and the local-first render shows the redacted marker.
    let create = json!({
        "event_id": "ak:event:msg-2",
        "kind": "ak.message.create",
        "actor_id": "did:web:bob.example",
        "realm_id": "ak:realm:r1",
        "created_at": "2026-05-22T10:00:00.000Z",
        "strand_id": "ak:strand:topic",
        "message_id": "ak:message:m2",
        "body": "secret"
    });
    let tombstone = json!({
        "event_id": "ak:event:msg-2",
        "kind": "ak.message.create",
        "actor_id": "did:web:bob.example",
        "realm_id": "ak:realm:r1",
        "created_at": "2026-05-22T10:05:00.000Z",
        "strand_id": "ak:strand:topic",
        "message_id": "ak:message:m2",
        "redacted": true
    });

    let create_record = message_operations_from_events("ak:realm:r1", &[create]);
    let tombstone_record = message_operations_from_events("ak:realm:r1", &[tombstone]);
    assert_eq!(
        create_record[0].operation_id,
        tombstone_record[0].operation_id
    );
}

#[test]
fn message_operations_fold_independent_redaction_event_by_message_id() {
    let mut create = json!({
        "event_id": "ak:event:msg-3",
        "kind": "ak.message.create",
        "actor_id": "did:web:bob.example",
        "realm_id": "ak:realm:r1",
        "created_at": "2026-05-22T10:00:00.000Z",
        "strand_id": "ak:strand:topic",
        "message_id": "ak:message:m3",
        "body": "secret"
    });
    sign_chat_fixture(&mut create);
    let mut redaction = json!({
        "event_id": "ak:event:redact-3",
        "event_kind": "ak.message.redact",
        "actor_id": "did:web:bob.example",
        "realm_id": "ak:realm:r1",
        "created_at": "2026-05-22T10:05:00.000Z",
        "payload": {
            "event_id": "ak:event:redact-3",
            "message_id": "ak:message:m3",
            "reason": "user requested tombstone"
        }
    });
    sign_chat_fixture(&mut redaction);

    for events in [
        vec![create.clone(), redaction.clone()],
        vec![redaction, create],
    ] {
        let records = message_operations_from_events("ak:realm:r1", &events);
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
fn message_operations_from_events_folds_shared_pin_control_events() {
    let strand_id = "ak:strand:topic";
    let pin_scope = SharedPinScope::strand(strand_id);
    let target_ref = "ak:message:pinned";
    let pin = json!({
        "event_id": "ak:event:pin-1",
        "event_kind": "ak.pin.add",
        "actor_id": "did:web:mei.example",
        "realm_id": "ak:realm:r1",
        "created_at": "2026-05-22T10:10:00.000Z",
        "payload": {
            "pin_scope": {"kind": "strand", "id": strand_id},
            "target_ref": target_ref,
            "rank": "r001"
        }
    });

    let records = message_operations_from_events("ak:realm:r1", &[pin]);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].operation_id, "ak:event:pin-1");
    assert_eq!(records[0].realm_id.as_deref(), Some("ak:realm:r1"));

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
fn local_redaction_tombstone_replaces_raw_message_without_plaintext() {
    let redacted_at = chrono::DateTime::parse_from_rfc3339("2026-05-22T10:05:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let message = ChatMessage {
        realm_id: "ak:realm:r1".to_owned(),
        id: "ak:event:msg-3".to_owned(),
        protocol_message_id: Some("ak:message:m3".to_owned()),
        sender: "did:web:bob.example".to_owned(),
        executed_by: None,
        body: "secret".to_owned(),
        timestamp: "10:00".to_owned(),
        created_at: None,
        strand_id: "ak:strand:topic".to_owned(),
        reply_to: None,
        reactions: Vec::new(),
        redacted: false,
        edited: false,
        revisions: Vec::new(),
        pending: false,
        failed: false,
        error: None,
        mentions: Vec::new(),
        crypto_state: MessageCryptoState::Plaintext,
    };

    let tombstone =
        local_redaction_tombstone_for_message(&message, redacted_at, Some("ak:event:redact-1"));
    assert_eq!(tombstone["event_id"], message.id);
    assert_eq!(tombstone["message_id"], "ak:message:m3");
    assert_eq!(tombstone["redacted"], true);
    assert_eq!(tombstone["state"], "redacted");
    assert_eq!(tombstone["redaction_ref"], "ak:event:redact-1");
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
    sign_chat_fixture(&mut state.raw_operations[0].payload);
    let restored = chat_messages_from_local_state_with_sidecar(&state, None, None);
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].id, message.id);
    assert!(restored[0].redacted);
    assert_eq!(restored[0].body, "");
    assert_eq!(restored[0].reply_to, None);
}

#[test]
fn moderation_appeal_prompts_fold_decision_and_current_appellant_state() {
    let realm_id = "ak:realm:01904100-0000-7000-8000-000000000001";
    let appellant = "did:web:appellant.example";
    let events = vec![
        json!({
            "event_id": "ak:event:01904100-0000-7000-8000-000000000101",
            "kind": "ak.moderation.decision",
            "realm_id": realm_id,
            "payload": {
                "target_ref": "ak:message:01904100-0000-7000-8000-000000000201",
                "decision": "quarantine"
            }
        }),
        json!({
            "kind": "ak.moderation.appeal.submit",
            "realm_id": realm_id,
            "payload": {
                "appeal_id": "ak:appeal:01904100-0000-7000-8000-000000000301",
                "decision_ref": "ak:event:01904100-0000-7000-8000-000000000101",
                "target_ref": "ak:message:01904100-0000-7000-8000-000000000201",
                "appellant": appellant
            }
        }),
        json!({
            "kind": "ak.moderation.appeal.decision",
            "realm_id": realm_id,
            "payload": {
                "appeal_id": "ak:appeal:01904100-0000-7000-8000-000000000301",
                "verdict": "uphold"
            }
        }),
    ];

    let prompts = moderation_appeal_prompts_from_events(realm_id, &events, appellant);

    assert_eq!(prompts.len(), 1);
    assert_eq!(
        prompts[0].decision_ref,
        "ak:event:01904100-0000-7000-8000-000000000101"
    );
    assert_eq!(prompts[0].state, "decided");
    assert_eq!(prompts[0].verdict.as_deref(), Some("uphold"));

    let lifted = vec![
        events[0].clone(),
        json!({
            "kind": "ak.moderation.decision.lift",
            "realm_id": realm_id,
            "payload": {
                "decision_ref": "ak:event:01904100-0000-7000-8000-000000000101"
            }
        }),
    ];
    assert!(moderation_appeal_prompts_from_events(realm_id, &lifted, appellant).is_empty());
}

#[test]
fn moderation_appeal_prompts_read_control_plane_sync_state() {
    let realm_id = "ak:realm:01904100-0000-7000-8000-000000000001";
    let mut realms = std::collections::BTreeMap::new();
    realms.insert(
        realm_id.to_owned(),
        json!({
            "timeline": { "events": [] },
            "state": {
                "events": [{
                    "event_id": "ak:event:01904100-0000-7000-8000-000000000101",
                    "kind": "ak.moderation.decision",
                    "realm_id": realm_id,
                    "payload": {
                        "target_ref": "ak:message:01904100-0000-7000-8000-000000000201",
                        "decision": "quarantine"
                    }
                }]
            }
        }),
    );

    let prompts = moderation_appeal_prompts_from_sync_realms(&realms, "did:web:appellant.example");

    assert_eq!(prompts.len(), 1);
    assert_eq!(
        prompts[0].decision_ref,
        "ak:event:01904100-0000-7000-8000-000000000101"
    );
}

#[test]
fn moderation_appeal_prompts_survive_sdk_event_round_trip() {
    let realm_id = "ak:realm:01904100-0000-7000-8000-000000000001";
    let event: arkret_sdk::Event = serde_json::from_value(json!({
        "event_id": "ak:event:01904100-0000-7000-8000-000000000101",
        "kind": "ak.moderation.decision",
        "realm_id": realm_id,
        "actor_id": "did:web:moderator.example",
        "actor_seq": 1,
        "created_at": "2026-07-19T00:00:00.000Z",
        "hlc": "019f73a34c00-0000-12345678",
        "prev_refs": [],
        "refs": [],
        "requirements": { "schema": ["ak.schema.event_payload.v1"] },
        "payload": {
            "target_ref": "ak:message:01904100-0000-7000-8000-000000000201",
            "decision": "quarantine",
            "issuer": "did:web:moderator.example",
            "reason_code": "abuse_review",
            "request_canonical_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        },
        "proofs": []
    }))
    .unwrap();
    let wire = serde_json::to_value(event).unwrap();

    let prompts =
        moderation_appeal_prompts_from_events(realm_id, &[wire], "did:web:appellant.example");

    assert_eq!(prompts.len(), 1);
}

#[test]
fn timeline_projection_key_tracks_moderation_prompt_lifecycle() {
    let prompt = ModerationAppealPrompt {
        realm_id: "ak:realm:01904100-0000-7000-8000-000000000001".to_owned(),
        decision_ref: "ak:event:01904100-0000-7000-8000-000000000101".to_owned(),
        target_ref: "ak:message:01904100-0000-7000-8000-000000000201".to_owned(),
        state: "none".to_owned(),
        verdict: None,
    };
    let empty_key = timeline_projection_key(&prompt.realm_id, 1, &[], &[], &Default::default());
    let initial_key = timeline_projection_key(
        &prompt.realm_id,
        1,
        &[],
        std::slice::from_ref(&prompt),
        &Default::default(),
    );
    let mut submitted = prompt.clone();
    submitted.state = "submitted".to_owned();
    let submitted_key = timeline_projection_key(
        &submitted.realm_id,
        1,
        &[],
        std::slice::from_ref(&submitted),
        &Default::default(),
    );

    assert_ne!(empty_key, initial_key);
    assert_ne!(initial_key, submitted_key);
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
    let temp = std::env::temp_dir().join(format!("inkson-x10_6-rebuild-sidecar-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    store.save_private_plaintext(
        "ak:realm:local",
        "ak:strand:announce",
        "message:chat-msg-enc",
        "secret discussion body",
    );

    let mut state = ClientLocalState {
        raw_operations: vec![crate::state::RawOperationRecord {
            operation_id: "ak:operation:enc".to_owned(),
            realm_id: Some("ak:realm:local".to_owned()),
            received_at: chrono::Utc::now(),
            // Encrypted stub: identity only, NO plaintext body.
            payload: json!({
                "event_id": "ak:event:enc",
                "kind": "ak.message.create",
                "actor_id": "did:web:alice.example",
                "realm_id": "ak:realm:local",
                "strand_id": "ak:strand:announce",
                "message_id": "chat-msg-enc",
                "encrypted_content": true,
                "status": "accepted"
            }),
        }],
        ..ClientLocalState::default()
    };
    sign_chat_fixture(&mut state.raw_operations[0].payload);

    // Without the sidecar (e.g. another device) the stub has no readable
    // body, but it must still surface as an encrypted/locked row so the
    // discussion does not look empty.
    let without_sidecar = chat_messages_from_local_state_with_sidecar(&state, None, None);
    assert_eq!(without_sidecar.len(), 1);
    assert_eq!(without_sidecar[0].strand_id, "ak:strand:announce");
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
    assert_eq!(restored[0].strand_id, "ak:strand:announce");
    assert_eq!(restored[0].sender, "did:web:alice.example");
    assert_eq!(restored[0].body, "secret discussion body");
    assert!(matches!(
        restored[0].crypto_state,
        MessageCryptoState::Plaintext
    ));
}

#[test]
fn rebuild_restores_authors_own_encrypted_poll_from_content_sidecar() {
    let temp = std::env::temp_dir().join(format!("inkson-poll-content-sidecar-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    let realm = "ak:realm:01904100-0000-7000-8000-000000000010";
    let strand = "ak:strand:01904100-0000-7000-8000-000000000011";
    let message_id = "ak:message:01904100-0000-7000-8000-000000000012";
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
    let mut event = json!({
        "event_id": "ak:event:01904100-0000-7000-8000-000000000013",
        "kind": "ak.message.create",
        "actor_id": "did:web:alice.example",
        "realm_id": realm,
        "strand_id": strand,
        "message_id": message_id,
        "encrypted_content": true,
        "status": "accepted"
    });
    sign_chat_fixture(&mut event);

    let cards = poll_cards_from_events_with_sidecar(realm, &[event], Some(&store), None);

    assert_eq!(cards.len(), 1);
    assert_eq!(cards[0].poll_id, message_id);
    assert_eq!(cards[0].question, "Deploy now?");
    assert_eq!(cards[0].options.len(), 2);
    assert_eq!(cards[0].options[1].label, "After backup");
}

#[test]
fn poll_projection_merge_preserves_optimistic_message_render_id() {
    let mut draft = crate::messaging::polls::PollDraft::new();
    draft.set_question("Deploy now?".to_owned());
    draft.set_option(0, "Now".to_owned());
    draft.set_option(1, "After backup".to_owned());
    let wire_poll_id = "ak:message:01904100-0000-7000-8000-000000000012";
    let mut optimistic =
        crate::messaging::polls::PollCard::from_draft("poll-local".to_owned(), &draft);
    optimistic.poll_id = wire_poll_id.to_owned();
    let mut projected =
        crate::messaging::polls::PollCard::from_draft("ak:event:accepted".to_owned(), &draft);
    projected.poll_id = wire_poll_id.to_owned();
    projected.vote("did:web:bob.example", 1);
    let mut cards = vec![optimistic];

    merge_poll_cards(&mut cards, vec![projected]);

    assert_eq!(cards.len(), 1);
    assert_eq!(cards[0].message_id, "poll-local");
    assert_eq!(cards[0].votes_for(1), 1);
}

#[test]
fn pending_message_refreshes_from_restored_private_plaintext_sidecar() {
    let temp = std::env::temp_dir().join(format!("inkson-pending-sidecar-refresh-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    let realm = "ak:realm:local";
    let strand = "ak:strand:announce";
    let message_id = "ak:message:restored";
    let mut messages = vec![ChatMessage {
        realm_id: realm.to_owned(),
        id: "ak:event:restored".to_owned(),
        protocol_message_id: Some(message_id.to_owned()),
        sender: "did:web:alice.example".to_owned(),
        executed_by: None,
        body: String::new(),
        timestamp: "10:00".to_owned(),
        created_at: None,
        strand_id: strand.to_owned(),
        reply_to: None,
        reactions: Vec::new(),
        redacted: false,
        edited: false,
        revisions: Vec::new(),
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

    store.save_private_plaintext(
        realm,
        strand,
        &format!("message:{message_id}"),
        "restored after sidecar sync",
    );

    assert!(pending_messages_have_private_plaintext_sidecar(
        &messages, &store, realm
    ));
    assert!(restore_pending_messages_from_private_plaintext_sidecar(
        messages.as_mut_slice(),
        &store,
        realm
    ));
    assert_eq!(messages[0].body, "restored after sidecar sync");
    assert_eq!(messages[0].crypto_state, MessageCryptoState::Plaintext);
    assert!(!restore_pending_messages_from_private_plaintext_sidecar(
        messages.as_mut_slice(),
        &store,
        realm
    ));
}

#[test]
fn expiry_stub_does_not_restore_authors_plaintext_sidecar() {
    let temp = std::env::temp_dir().join(format!("inkson-expiry-stub-sidecar-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    let realm = "ak:realm:local";
    let strand = "ak:strand:announce";
    let message_id = "ak:message:expiring";
    store.save_private_plaintext(
        realm,
        strand,
        &format!("message:{message_id}"),
        "secret discussion body",
    );
    let mut event = json!({
        "event_id": "ak:event:expired",
        "kind": "ak.message.create",
        "actor_id": "did:web:alice.example",
        "realm_id": realm,
        "strand_id": strand,
        "message_id": message_id,
        "expiry_stub": true,
        "expiry_state": "expired",
        "content": {
            "kind": "ak.content.text",
            "body": "[expired]"
        }
    });
    sign_chat_fixture(&mut event);

    let message =
        chat_message_from_event_with_sidecar(realm, &event, Some(&store), None).expect("message");

    assert_eq!(message.body, "[expired]");
    assert_eq!(message.crypto_state, MessageCryptoState::Plaintext);
}

#[test]
fn late_recovery_guards_block_sidecar_plaintext_before_timeline_entry() {
    let temp = std::env::temp_dir().join(format!("inkson-late-recovery-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    let realm = "ak:realm:local";
    let strand = "ak:strand:announce";
    let message_id = "ak:message:late";
    store.save_private_plaintext(
        realm,
        strand,
        &format!("message:{message_id}"),
        "late plaintext",
    );
    let mut rejected = json!({
        "event_id": "ak:event:late",
        "kind": "ak.message.create",
        "actor_id": "did:web:alice.example",
        "realm_id": realm,
        "strand_id": strand,
        "message_id": message_id,
        "decryption_state": "decryption_failed",
        "late_recovery": {
            "receiver_visible_at_t0": false,
            "source_rechecked_current_share_policy": true,
            "event_expired": false
        },
        "content": {
            "encrypted_content": true
        }
    });
    sign_chat_fixture(&mut rejected);

    let message = chat_message_from_event_with_sidecar(realm, &rejected, Some(&store), None)
        .expect("message");

    assert_eq!(message.body, "");
    assert_eq!(
        message.crypto_state,
        MessageCryptoState::LateRecoveryRejected
    );
    assert_eq!(
        message.error.as_deref(),
        Some(arkret_sdk::ReasonCode::LATE_RECOVERY_REJECTED_MEMBERSHIP)
    );
}

#[test]
fn late_recovery_guards_allow_sidecar_plaintext_when_all_pass() {
    let temp = std::env::temp_dir().join(format!("inkson-late-recovery-ok-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    let realm = "ak:realm:local";
    let strand = "ak:strand:announce";
    let message_id = "ak:message:late-ok";
    store.save_private_plaintext(
        realm,
        strand,
        &format!("message:{message_id}"),
        "late plaintext",
    );
    let mut accepted = json!({
        "event_id": "ak:event:late-ok",
        "kind": "ak.message.create",
        "actor_id": "did:web:alice.example",
        "realm_id": realm,
        "strand_id": strand,
        "message_id": message_id,
        "decryption_state": "decryption_failed",
        "late_recovery": {
            "receiver_visible_at_t0": true,
            "source_rechecked_current_share_policy": true,
            "event_expired": false,
            "content_key_destroyed_by_retention": false
        },
        "content": {
            "encrypted_content": true
        }
    });
    sign_chat_fixture(&mut accepted);

    let message = chat_message_from_event_with_sidecar(realm, &accepted, Some(&store), None)
        .expect("message");

    assert_eq!(message.body, "late plaintext");
    assert_eq!(message.crypto_state, MessageCryptoState::Plaintext);
    assert_eq!(message.error, None);
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
        crate::views::helpers::short_protocol_id("did:web:alice.example")
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
        crate::views::helpers::short_protocol_id("did:web:carol.example")
    );
}

#[test]
fn sender_display_label_does_not_invent_domain_for_localpart() {
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
        "alice"
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
fn account_handle_requires_a_complete_verified_handle() {
    assert_eq!(normalize_account_handle("alice"), None);
    assert_eq!(
        normalize_account_handle("alice:example.com").as_deref(),
        Some("alice:example.com")
    );
    assert_eq!(normalize_account_handle("  "), None);
}

#[test]
fn participant_roster_ignores_noncanonical_identity_fields() {
    let projection = json!({
        "members": [
            {
                "did": "did:web:bob.example",
                "display_name": "Bob Example",
                "remark": "Bob from ops"
            }
        ]
    });
    let temp = std::env::temp_dir().join(format!("inkson-chat-roster-{}", uuid_v7()));
    let store = LocalStateStore::with_path(temp);
    let participants = space_participants(
        Some(&projection),
        &store,
        "ak:realm:demo",
        "did:web:alice.example",
    );
    assert_eq!(participants.len(), 1);
    assert!(participants[0].is_self);
}

#[test]
fn participant_roster_rejects_naked_handle_field() {
    let projection = json!({
        "members": [
            {
                "actor_id": "did:web:example.com:users:bob",
                "handle": "bob:example.com"
            }
        ]
    });

    let temp = std::env::temp_dir().join(format!("inkson-chat-roster-{}", uuid_v7()));
    let store = LocalStateStore::with_path(temp);
    let participants = space_participants(
        Some(&projection),
        &store,
        "ak:realm:demo",
        "did:web:alice.example",
    );
    let bob = participants
        .iter()
        .find(|participant| participant.did == "did:web:example.com:users:bob")
        .unwrap();

    assert!(mention_label_for_participant(bob).is_none());
}

#[test]
fn extracts_participant_handle_label_from_inline_handle_claims() {
    let projection = json!({
        "members": [
            {
                "actor_id": "did:web:bob.example",
                "subject_id": "did:web:bob.example",
                "handle_claims": [{
                    "schema": "ak.schema.handle_claim.v1",
                    "handle": "bob:local.host",
                    "subject": "did:web:bob.example",
                    "binding_state": "verified"
                }]
            }
        ]
    });

    let temp = std::env::temp_dir().join(format!("inkson-chat-roster-{}", uuid_v7()));
    let store = LocalStateStore::with_path(temp);
    let participants = space_participants(
        Some(&projection),
        &store,
        "ak:realm:demo",
        "did:web:alice.example",
    );
    let bob = participants
        .iter()
        .find(|participant| participant.did == "did:web:bob.example")
        .unwrap();

    assert_eq!(
        mention_label_for_participant(bob).as_deref(),
        Some("bob:local.host")
    );
}

#[test]
fn mention_label_for_participant_never_derives_handle_from_did() {
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

    assert!(mention_label_for_participant(&participant).is_none());
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
        arkret_sdk::Mention::new(
            arkret_sdk::Did::new("did:web:local.host:users:alice".to_owned()).unwrap(),
        )
        .with_display_name_at_time("alice:local.host")
        .with_handle_at_time(arkret_sdk::Handle::parse("alice:local.host").unwrap())
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
        arkret_sdk::Mention::new(
            arkret_sdk::Did::new("did:web:example.com:users:bob".to_owned()).unwrap(),
        )
        .with_display_name_at_time("bob:example.com")
        .with_handle_at_time(arkret_sdk::Handle::parse("bob:example.com").unwrap())
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
fn agent_metadata_from_mentions_recovers_selector_audit_metadata() {
    let messages = vec![ChatMessage {
        realm_id: "ak:realm:demo".to_owned(),
        id: "ak:event:1".to_owned(),
        protocol_message_id: Some("ak:message:01964137-0000-7000-8000-000000000001".to_owned()),
        sender: "did:web:example.com:users:bob".to_owned(),
        executed_by: None,
        body: "@alice:example.com/summary".to_owned(),
        timestamp: "10:00".to_owned(),
        created_at: None,
        strand_id: "ak:strand:demo".to_owned(),
        reply_to: None,
        reactions: Vec::new(),
        redacted: false,
        edited: false,
        revisions: Vec::new(),
        pending: false,
        failed: false,
        error: None,
        mentions: vec![MentionNode::mention(
            arkret_sdk::Mention::new(
                arkret_sdk::Did::new("did:web:agents.example:summary".to_owned()).unwrap(),
            )
            .with_display_name_at_time("Summary Assistant")
            .with_agent_selector_metadata(
                arkret_sdk::Did::new("did:web:example.com:users:alice".to_owned()).unwrap(),
                arkret_sdk::Handle::parse("alice:example.com").unwrap(),
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
    assert_eq!(summary.controller_id, "did:web:example.com:users:alice");
    assert_eq!(summary.controller_handle, "alice:example.com");
    assert_eq!(summary.agent_slug, "summary");
    assert_eq!(summary.display_name, "Summary Assistant");
}

#[test]
fn mention_audit_metadata_cannot_promote_or_rebind_an_agent() {
    let agent_id = "did:web:agents.example:summary";
    let mut authoritative = std::collections::BTreeMap::from([(
        agent_id.to_owned(),
        AgentParticipantMetadata {
            controller_id: "did:web:example.com:users:alice".to_owned(),
            controller_handle: "alice:example.com".to_owned(),
            agent_slug: "summary".to_owned(),
            display_name: "summary".to_owned(),
        },
    )]);
    let audit_metadata = std::collections::BTreeMap::from([
        (
            agent_id.to_owned(),
            AgentParticipantMetadata {
                controller_id: "did:web:example.com:users:mallory".to_owned(),
                controller_handle: "mallory:example.com".to_owned(),
                agent_slug: "stolen".to_owned(),
                display_name: "Forged Agent".to_owned(),
            },
        ),
        (
            "did:web:example.com:users:bob".to_owned(),
            AgentParticipantMetadata {
                controller_id: "did:web:example.com:users:alice".to_owned(),
                controller_handle: "alice:example.com".to_owned(),
                agent_slug: "review".to_owned(),
                display_name: "Forged Bob Agent".to_owned(),
            },
        ),
    ]);

    enrich_authoritative_agent_metadata(&mut authoritative, audit_metadata);

    assert_eq!(authoritative.len(), 1);
    let summary = authoritative.get(agent_id).unwrap();
    assert_eq!(summary.controller_id, "did:web:example.com:users:alice");
    assert_eq!(summary.controller_handle, "alice:example.com");
    assert_eq!(summary.agent_slug, "summary");
    assert_eq!(summary.display_name, "summary");
}

#[test]
fn owned_agent_ids_only_select_current_controllers_agents() {
    let controller = "did:web:example.com:users:alice";
    let own_agent = arkret_sdk::Mention::new(
        arkret_sdk::Did::new("did:web:agents.example:summary".to_owned()).unwrap(),
    )
    .with_agent_selector_metadata(
        arkret_sdk::Did::new(controller.to_owned()).unwrap(),
        arkret_sdk::Handle::parse("alice:example.com").unwrap(),
        "summary",
    );
    let other_agent = arkret_sdk::Mention::new(
        arkret_sdk::Did::new("did:web:agents.example:review".to_owned()).unwrap(),
    )
    .with_agent_selector_metadata(
        arkret_sdk::Did::new("did:web:example.com:users:bob".to_owned()).unwrap(),
        arkret_sdk::Handle::parse("bob:example.com").unwrap(),
        "review",
    );

    let ids = owned_agent_ids_from_mentions(
        &[
            MentionNode::mention(own_agent.clone()),
            MentionNode::mention(other_agent),
            MentionNode::mention(own_agent),
        ],
        controller,
    );

    assert_eq!(ids, vec!["did:web:agents.example:summary"]);
}

#[test]
fn composer_owned_agent_ids_keep_verified_picker_agent_before_handle_loads() {
    let controller = "did:web:example.com:users:alice";
    let picker = vec![crate::messaging::mentions::MentionCandidate {
        did: "did:web:agents.example:summary".to_owned(),
        display_name: "Summary Assistant".to_owned(),
        insert_label: "me/summary".to_owned(),
        subtitle: "Your agent".to_owned(),
        is_agent: true,
        controller_subject_id: controller.to_owned(),
        controller_handle_at_time: String::new(),
        agent_slug_at_time: "summary".to_owned(),
    }];

    let ids = owned_agent_ids_from_composer(
        true,
        "ask @me/summary for an update",
        &[],
        &picker,
        controller,
    );

    assert_eq!(ids, vec!["did:web:agents.example:summary"]);
    assert!(
        owned_agent_ids_from_composer(true, "ask for an update", &[], &picker, controller)
            .is_empty()
    );
}

#[test]
fn owned_agent_mentions_do_not_reopen_sidecar_from_private_composer() {
    assert!(should_route_owned_agent_to_sidecar(
        false, false, true, true
    ));
    assert!(!should_route_owned_agent_to_sidecar(
        true, false, true, true
    ));
    assert!(!should_route_owned_agent_to_sidecar(
        false, true, true, true
    ));
}

#[test]
fn embedded_sidecar_activation_keeps_the_source_strand_shell() {
    assert!(!composer::sidecar_activation_should_navigate(true));
    assert!(composer::sidecar_activation_should_navigate(false));
}

#[test]
fn direct_chat_disables_mention_ui_triggers_and_send_metadata() {
    let account_did = "did:web:example.com:users:alice";
    let stale_picker = vec![crate::messaging::mentions::MentionCandidate {
        did: "did:web:example.com:users:bob".to_owned(),
        display_name: "Bob".to_owned(),
        insert_label: "bob:example.com".to_owned(),
        subtitle: String::new(),
        is_agent: false,
        controller_subject_id: String::new(),
        controller_handle_at_time: String::new(),
        agent_slug_at_time: String::new(),
    }];

    let mentions_enabled = composer::chat_mentions_enabled(true);
    assert!(!mentions_enabled);
    assert!(
        !composer::chat_composer_placeholder(mentions_enabled).contains('@'),
        "direct-chat placeholder must not advertise mentions"
    );
    assert!(
        composer::active_composer_mention_token(mentions_enabled, "hello @").is_none(),
        "typing @ in direct chat must not activate the picker"
    );
    assert!(
        composer_mention_nodes(
            mentions_enabled,
            "hello @me @all @bob:example.com",
            &stale_picker,
            account_did,
        )
        .is_empty(),
        "direct-chat sends must not carry mention metadata"
    );
    assert!(
        owned_agent_ids_from_composer(
            mentions_enabled,
            "ask @me/summary",
            &[],
            &stale_picker,
            account_did,
        )
        .is_empty(),
        "direct-chat text must not trigger agent mention routing"
    );

    let collaboration_mentions_enabled = composer::chat_mentions_enabled(false);
    assert!(collaboration_mentions_enabled);
    assert!(
        composer::active_composer_mention_token(collaboration_mentions_enabled, "hello @")
            .is_some()
    );
    assert!(
        composer::chat_composer_placeholder(collaboration_mentions_enabled).contains('@'),
        "collaboration composer must keep advertising mentions"
    );
}

#[test]
fn composer_enter_behavior_matches_chat_conventions_and_protects_ime_input() {
    assert!(composer::chat_composer_should_send_key(
        "Enter", false, false, false, false,
    ));
    assert!(
        !composer::chat_composer_should_send_key("Enter", true, false, false, false),
        "Shift+Enter must remain available for new lines"
    );
    assert!(
        !composer::chat_composer_should_send_key("Enter", false, false, true, false),
        "IME candidate confirmation must not send a message"
    );
    assert!(
        !composer::chat_composer_should_send_key("Enter", false, false, false, true),
        "holding Enter must not trigger repeated sends"
    );
    assert!(
        !composer::chat_composer_should_send_key("Enter", false, true, false, false),
        "Alt+Enter must remain available to the platform"
    );
    assert!(!composer::chat_composer_should_send_key(
        "Space", false, false, false, false,
    ));
}

#[test]
fn participation_visibility_uses_most_specific_effective_scope() {
    use arkret_models_collaboration::governance::agent_participation::{
        AgentParticipation, AgentParticipationEntry, AgentParticipationScope,
    };

    let realm = "ak:realm:0196419b-0000-7000-8000-000000000000";
    let circle = "ak:circle:0196419b-0000-7000-8000-000000000001";
    let realm_entry = AgentParticipationEntry {
        scope: AgentParticipationScope::Realm {
            realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
        },
        selection: AgentParticipation::ALL,
        ceiling: AgentParticipation::ALL,
        effective: AgentParticipation::ALL,
    };
    let circle_entry = AgentParticipationEntry {
        scope: AgentParticipationScope::Circle {
            realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
            circle_id: arkret_sdk::CircleId::new(circle.to_owned()).unwrap(),
        },
        selection: AgentParticipation::NONE,
        ceiling: AgentParticipation::NONE,
        effective: AgentParticipation::NONE,
    };

    assert!(participation_allows_public_reply(
        std::slice::from_ref(&realm_entry),
        realm,
        None,
        "ak:strand:0196419b-0000-7000-8000-000000000002",
    ));
    assert!(!participation_allows_public_reply(
        &[realm_entry, circle_entry],
        realm,
        Some(circle),
        "ak:strand:0196419b-0000-7000-8000-000000000002",
    ));
}

#[test]
fn participation_visibility_can_target_the_synthesized_default_discussion_strand() {
    use arkret_models_collaboration::governance::agent_participation::{
        AgentParticipation, AgentParticipationEntry, AgentParticipationScope,
    };

    let realm = "ak:realm:0196419b-0000-7000-8000-000000000010";
    let strand = default_discussion_strand_id(realm);
    let entry = AgentParticipationEntry {
        scope: AgentParticipationScope::Strand {
            realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
            strand_id: arkret_sdk::StrandId::new(strand.clone()).unwrap(),
        },
        selection: AgentParticipation::NONE,
        ceiling: AgentParticipation::ALL,
        effective: AgentParticipation::ALL,
    };

    assert!(participation_allows_public_reply(
        std::slice::from_ref(&entry),
        realm,
        None,
        &strand,
    ));
}

#[test]
fn mention_only_participation_does_not_expose_agent_in_roster() {
    use arkret_models_collaboration::governance::agent_participation::{
        AgentParticipation, AgentParticipationEntry, AgentParticipationScope,
    };

    let realm = "ak:realm:0196419b-0000-7000-8000-000000000020";
    let mention_only = AgentParticipation {
        reply: false,
        accept_third_party_mention: true,
        act_on_behalf: false,
    };
    let entry = AgentParticipationEntry {
        scope: AgentParticipationScope::Realm {
            realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
        },
        selection: mention_only,
        ceiling: AgentParticipation::ALL,
        effective: mention_only,
    };

    assert!(!participation_allows_public_reply(
        std::slice::from_ref(&entry),
        realm,
        None,
        "ak:strand:0196419b-0000-7000-8000-000000000021",
    ));
}

#[test]
fn participant_roster_rows_groups_agents_under_visible_controller() {
    let controller = SpaceParticipant {
        did: "did:web:example.com:users:alice".to_owned(),
        display_name: Some("Alice".to_owned()),
        handle_label: Some("alice:example.com".to_owned()),
        display_name_rank: 0,
        role: SpaceParticipantRole::Member,
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
            controller_id: controller.did.clone(),
            controller_handle: "alice:example.com".to_owned(),
            agent_slug: "summary".to_owned(),
            display_name: "Summary Assistant".to_owned(),
        }),
    };
    let visible = std::collections::BTreeSet::from([agent.did.clone()]);
    assert_eq!(
        participant_roster_display_label(&crate::state::LocalStateStore::default(), &controller,),
        "alice:example.com"
    );
    assert_eq!(
        participant_roster_display_label(&crate::state::LocalStateStore::default(), &agent,),
        "summary"
    );
    let rows = participant_roster_rows(&[controller.clone(), agent.clone()], &visible);
    assert_eq!(rows.len(), 1);
    match &rows[0] {
        ParticipantRosterRow::ControllerWithAgents { controller, agents } => {
            assert_eq!(controller.did, "did:web:example.com:users:alice");
            assert_eq!(agents.len(), 1);
            assert_eq!(agents[0].did, "did:web:agents.example:summary");
        }
        ParticipantRosterRow::Participant(_) => panic!("expected grouped controller row"),
    }

    let private_rows = participant_roster_rows(
        &[controller.clone(), agent],
        &std::collections::BTreeSet::new(),
    );
    assert_eq!(
        private_rows,
        vec![ParticipantRosterRow::Participant(controller)]
    );
}

#[test]
fn mention_candidate_for_own_agent_uses_me_alias() {
    let controller = SpaceParticipant {
        did: "did:web:example.com:users:alice".to_owned(),
        display_name: Some("Alice".to_owned()),
        handle_label: Some("alice:example.com".to_owned()),
        display_name_rank: 0,
        role: SpaceParticipantRole::Member,
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
            controller_id: controller.did.clone(),
            controller_handle: "alice:example.com".to_owned(),
            agent_slug: "summary".to_owned(),
            display_name: "Summary Assistant".to_owned(),
        }),
    };
    let participants = vec![controller.clone(), agent.clone()];
    let candidate = mention_candidate_for_participant(&agent, &participants, &controller.did)
        .expect("agent mention candidate");
    assert_eq!(candidate.display_name, "Summary Assistant");
    assert_eq!(candidate.insert_label(), "me/summary");
    assert_eq!(
        candidate.controller_subject_id,
        "did:web:example.com:users:alice"
    );
    assert_eq!(candidate.controller_handle_at_time, "alice:example.com");
    assert_eq!(candidate.agent_slug_at_time, "summary");
}

#[test]
fn mention_candidate_for_current_user_uses_structured_me_alias() {
    let participant = SpaceParticipant {
        did: "did:web:example.com:users:alice".to_owned(),
        display_name: Some("Alice".to_owned()),
        handle_label: None,
        display_name_rank: 0,
        role: SpaceParticipantRole::Member,
        is_self: true,
        is_agent: false,
        agent_metadata: None,
    };

    let candidate = mention_candidate_for_participant(
        &participant,
        std::slice::from_ref(&participant),
        &participant.did,
    )
    .expect("current-user mention candidate");
    assert_eq!(candidate.did, participant.did);
    assert_eq!(candidate.insert_label(), "me");
    assert_eq!(candidate.subtitle, "You");

    let mentions = composer_mention_nodes(
        true,
        "ping @me",
        std::slice::from_ref(&candidate),
        &participant.did,
    );
    let mention = mentions[0].as_mention().expect("structured self mention");
    assert_eq!(mention.subject_id.as_str(), participant.did);
    assert_eq!(mention.mention_text_original.as_deref(), Some("@me"));

    let typed_mentions = composer_mention_nodes(true, "ping @me", &[], &participant.did);
    let typed_mention = typed_mentions[0]
        .as_mention()
        .expect("typed structured self mention");
    assert_eq!(typed_mention.subject_id.as_str(), participant.did);
    assert_eq!(typed_mention.mention_text_original.as_deref(), Some("@me"));

    assert!(composer_mention_nodes(true, "ask @me/summary", &[], &participant.did).is_empty());
}

#[test]
fn resolved_owned_agent_chip_suppresses_duplicate_directory_lookup() {
    let controller = "did:web:example.com:users:alice";
    let mention =
        arkret_sdk::Mention::new(arkret_sdk::Did::new("did:web:agents.example:summary").unwrap())
            .with_agent_selector_metadata(
                arkret_sdk::Did::new(controller).unwrap(),
                arkret_sdk::Handle::parse("alice:example.com").unwrap(),
                "summary",
            )
            .with_mention_text_original("@me/summary");
    let mentions = vec![MentionNode::mention(mention)];
    let owned = parse_agent_selector_mention_tokens("ask @me/summary")
        .into_iter()
        .next()
        .unwrap();
    let remote = parse_agent_selector_mention_tokens("ask @alice:example.com/summary")
        .into_iter()
        .next()
        .unwrap();
    let unresolved = parse_agent_selector_mention_tokens("ask @me/digest")
        .into_iter()
        .next()
        .unwrap();

    assert!(agent_selector_mention_is_already_resolved(
        &mentions, &owned, controller
    ));
    assert!(agent_selector_mention_is_already_resolved(
        &mentions, &remote, controller
    ));
    assert!(!agent_selector_mention_is_already_resolved(
        &mentions,
        &unresolved,
        controller
    ));
}

#[test]
fn owned_agent_inventory_enriches_existing_realm_member_metadata() {
    let slugs = std::collections::BTreeMap::from([(
        "did:web:agents.example:summary".to_owned(),
        "summary".to_owned(),
    )]);
    let metadata = owned_agent_metadata(
        &slugs,
        "did:web:example.com:users:alice",
        Some("alice:example.com"),
    );
    let summary = metadata
        .get("did:web:agents.example:summary")
        .expect("owned agent metadata");
    assert_eq!(summary.controller_id, "did:web:example.com:users:alice");
    assert_eq!(summary.controller_handle, "alice:example.com");
    assert_eq!(summary.agent_slug, "summary");
}

#[test]
fn explicit_member_click_builds_user_and_owned_agent_mentions() {
    let account_did = "did:web:example.com:users:alice";
    let member = SpaceParticipant {
        did: "did:web:example.com:users:bob".to_owned(),
        display_name: Some("Bob".to_owned()),
        handle_label: None,
        display_name_rank: 0,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: false,
        agent_metadata: None,
    };
    let clicked_member = mention_candidate_for_explicit_target(
        &member,
        std::slice::from_ref(&member),
        account_did,
        &std::collections::BTreeSet::new(),
        None,
        Some("alice:example.com"),
    )
    .expect("explicit member mention");
    assert_eq!(clicked_member.did, member.did);
    assert!(!clicked_member.is_agent);

    let unannotated_owned_agent = SpaceParticipant {
        did: "did:web:agents.example:summary".to_owned(),
        display_name: None,
        handle_label: None,
        display_name_rank: u8::MAX,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: false,
        agent_metadata: None,
    };
    let clicked_agent = mention_candidate_for_explicit_target(
        &unannotated_owned_agent,
        std::slice::from_ref(&unannotated_owned_agent),
        account_did,
        &std::collections::BTreeSet::new(),
        Some("summary"),
        Some("alice:example.com"),
    )
    .expect("explicit owned-agent mention");
    assert_eq!(clicked_agent.insert_label(), "me/summary");
    assert!(clicked_agent.is_agent);
    assert_eq!(clicked_agent.controller_subject_id, account_did);
    assert_eq!(clicked_agent.agent_slug_at_time, "summary");

    let before_handle_load = owned_agent_mention_candidate(
        &unannotated_owned_agent.did,
        Some("summary"),
        account_did,
        None,
    )
    .expect("@me selector must not wait for the account handle");
    assert_eq!(before_handle_load.insert_label(), "me/summary");
    assert!(before_handle_load.controller_handle_at_time.is_empty());
    assert!(
        composer_mention_nodes(
            true,
            "ask @me/summary",
            std::slice::from_ref(&before_handle_load),
            account_did,
        )
        .is_empty()
    );
}

#[test]
fn mention_candidate_for_other_agent_keeps_canonical_controller_handle() {
    let controller = SpaceParticipant {
        did: "did:web:example.com:users:bob".to_owned(),
        display_name: Some("Bob".to_owned()),
        handle_label: Some("bob:example.com".to_owned()),
        display_name_rank: 0,
        role: SpaceParticipantRole::Member,
        is_self: false,
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
            controller_id: controller.did.clone(),
            controller_handle: "bob:example.com".to_owned(),
            agent_slug: "summary".to_owned(),
            display_name: "Summary Assistant".to_owned(),
        }),
    };
    let participants = vec![controller, agent.clone()];

    let candidate =
        mention_candidate_for_participant(&agent, &participants, "did:web:example.com:users:alice")
            .expect("agent mention candidate");

    assert_eq!(candidate.insert_label(), "bob:example.com/summary");
}

#[test]
fn agent_candidate_visibility_keeps_owned_agents_and_hides_private_remote_agents() {
    let own_controller = SpaceParticipant {
        did: "did:web:example.com:users:alice".to_owned(),
        display_name: Some("Alice".to_owned()),
        handle_label: Some("alice:example.com".to_owned()),
        display_name_rank: 0,
        role: SpaceParticipantRole::Member,
        is_self: true,
        is_agent: false,
        agent_metadata: None,
    };
    let own_agent = SpaceParticipant {
        did: "did:web:agents.example:alice-summary".to_owned(),
        display_name: Some("Alice Summary".to_owned()),
        handle_label: None,
        display_name_rank: 1,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: true,
        agent_metadata: Some(AgentParticipantMetadata {
            controller_id: own_controller.did.clone(),
            controller_handle: "alice:example.com".to_owned(),
            agent_slug: "summary".to_owned(),
            display_name: "Alice Summary".to_owned(),
        }),
    };
    let remote_agent = SpaceParticipant {
        did: "did:web:agents.example:bob-summary".to_owned(),
        display_name: Some("Bob Summary".to_owned()),
        handle_label: None,
        display_name_rank: 1,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: true,
        agent_metadata: Some(AgentParticipantMetadata {
            controller_id: "did:web:example.com:users:bob".to_owned(),
            controller_handle: "bob:example.com".to_owned(),
            agent_slug: "summary".to_owned(),
            display_name: "Bob Summary".to_owned(),
        }),
    };
    let account_did = own_controller.did.as_str();
    let visible = std::collections::BTreeSet::new();

    assert!(agent_candidate_is_visible(
        &own_agent,
        &visible,
        account_did
    ));
    assert!(!agent_candidate_is_visible(
        &remote_agent,
        &visible,
        account_did
    ));
    assert!(agent_candidate_is_visible(
        &remote_agent,
        &std::collections::BTreeSet::from([remote_agent.did.clone()]),
        account_did
    ));
    let sidecar_mentions = sidecar_owned_agent_participants(
        &[
            own_controller.clone(),
            own_agent.clone(),
            remote_agent.clone(),
        ],
        account_did,
    );
    assert_eq!(sidecar_mentions, vec![own_agent.clone()]);
    assert_eq!(
        readable_participation_agent_ids(&[own_agent.clone(), remote_agent], account_did),
        vec![own_agent.did]
    );
}

#[test]
fn sidecar_presence_excludes_realm_humans_and_foreign_agents() {
    let controller = SpaceParticipant {
        did: "did:web:example.com:users:alice".to_owned(),
        display_name: Some("Alice".to_owned()),
        handle_label: Some("alice:example.com".to_owned()),
        display_name_rank: 0,
        role: SpaceParticipantRole::Member,
        is_self: true,
        is_agent: false,
        agent_metadata: None,
    };
    let realm_human = SpaceParticipant {
        did: "did:web:example.com:users:bob".to_owned(),
        display_name: Some("Bob".to_owned()),
        handle_label: Some("bob:example.com".to_owned()),
        display_name_rank: 1,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: false,
        agent_metadata: None,
    };
    let owned_agent = SpaceParticipant {
        did: "did:web:agents.example:alice-summary".to_owned(),
        display_name: Some("Alice Summary".to_owned()),
        handle_label: None,
        display_name_rank: 1,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: true,
        agent_metadata: Some(AgentParticipantMetadata {
            controller_id: controller.did.clone(),
            controller_handle: "alice:example.com".to_owned(),
            agent_slug: "summary".to_owned(),
            display_name: "Alice Summary".to_owned(),
        }),
    };
    let foreign_agent = SpaceParticipant {
        did: "did:web:agents.example:bob-summary".to_owned(),
        display_name: Some("Bob Summary".to_owned()),
        handle_label: None,
        display_name_rank: 1,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: true,
        agent_metadata: Some(AgentParticipantMetadata {
            controller_id: realm_human.did.clone(),
            controller_handle: "bob:example.com".to_owned(),
            agent_slug: "summary".to_owned(),
            display_name: "Bob Summary".to_owned(),
        }),
    };

    let visible = sidecar_presence_participants(
        &[
            controller.clone(),
            realm_human,
            owned_agent.clone(),
            foreign_agent,
        ],
        &controller.did,
    );

    assert_eq!(visible, vec![controller, owned_agent]);
}

#[test]
fn mention_candidate_without_handle_is_not_displayed_as_did() {
    let participant = SpaceParticipant {
        did: "did:web:bob.example".to_owned(),
        display_name: Some("Bob Example".to_owned()),
        handle_label: None,
        display_name_rank: 0,
        role: SpaceParticipantRole::Member,
        is_self: false,
        is_agent: false,
        agent_metadata: None,
    };

    assert!(
        mention_candidate_for_participant(
            &participant,
            std::slice::from_ref(&participant),
            "did:web:alice.example",
        )
        .is_none()
    );
}

#[test]
fn mention_candidate_uses_cached_member_handle() {
    let temp = std::env::temp_dir().join(format!("inkson-chat-mention-handle-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    store.save_member_handle_lookup(
        "did:web:bob.example",
        Some("ak:realm:demo".to_owned()),
        None,
        Some("bob:local.host".to_owned()),
        1,
        None,
        None,
    );
    let projection = json!({"members": [{
        "actor_id": "did:web:bob.example"
    }]});
    let participants = space_participants(
        Some(&projection),
        &store,
        "ak:realm:demo",
        "did:web:alice.example",
    );
    let bob = participants
        .iter()
        .find(|participant| participant.did == "did:web:bob.example")
        .expect("bob participant");
    let candidate = mention_candidate_for_participant(bob, &participants, "did:web:alice.example")
        .expect("member mention candidate");
    assert_eq!(candidate.did, "did:web:bob.example");
    assert_eq!(candidate.display_name, "bob:local.host");
    assert_eq!(candidate.insert_label(), "bob:local.host");
    assert_eq!(candidate.subtitle, "");
}

#[test]
fn late_join_discussion_sender_resolves_cached_member_handle() {
    let sender = "did:webvh:zQmHistoricalAuthor";
    let realm = "ak:realm:late-join";
    let temp = std::env::temp_dir().join(format!("inkson-chat-late-join-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    store.save_member_handle_lookup(
        sender,
        Some(realm.to_owned()),
        None,
        Some("alice:local.host".to_owned()),
        1,
        None,
        None,
    );
    let projection = json!({"members": [{
        "actor_id": sender,
        "membership": "join"
    }]});
    let participants = space_participants(
        Some(&projection),
        &store,
        realm,
        "did:webvh:zQmLateJoiningReader",
    );

    assert_eq!(
        sender_display_label(
            sender,
            "did:webvh:zQmLateJoiningReader",
            "reader:local.host",
            &participants,
        ),
        "alice:local.host"
    );
}

#[test]
fn unresolved_historical_sender_uses_the_shared_protocol_id_fallback() {
    let sender = "did:webvh:zQmHistoricalAuthor0123456789abcdefghijk";
    assert_eq!(
        sender_display_label(sender, "did:web:alice.example", "Alice", &[]),
        crate::views::helpers::short_protocol_id(sender)
    );
}

#[test]
fn channel_from_strand_event_requires_real_discussion_track() {
    let event = json!({
        "event_id": "ak:event:strand",
        "kind": "ak.strand.create",
        "realm_id": "ak:realm:demo",
        "strand_id": "ak:strand:ops",
        "title": "Ops discussion",
        "category": "support",
        "summary": "Operations support",
        "strand": {
            "id": "ak:strand:ops",
            "title": "Ops discussion",
            "tracks": {
                "discussion": {"profile": "discussion"}
            }
        }
    });

    let channel = channel_from_strand_event("ak:realm:demo", &event).unwrap();

    assert_eq!(channel.strand_id, "ak:strand:ops");
    assert_eq!(channel.name, "Ops discussion");
    assert_eq!(channel.category, "support");
    assert_eq!(channel.kind, "discussion");
    assert_eq!(channel.topic.as_deref(), Some("Operations support"));
    assert!(!channel.is_default);
    assert!(!channel.is_private_sidecar);
}

#[test]
fn sidecar_strand_title_reads_canonical_metadata_object() {
    let strand_id = "ak:strand:01964137-0000-7000-8000-0000000000a2";
    let projection = json!({
        "strand_id": strand_id,
        "metadata": {
            "title": "AI sidecar",
            "summary": "Controller-private AI workspace"
        },
        "tracks": { "discussion": { "enabled": true } }
    });
    let projected = channel_from_strand_projection("ak:realm:demo", &projection, false)
        .expect("discussion projection");
    assert_eq!(projected.name, "AI sidecar");
    assert_ne!(projected.name, strand_id);

    let event = json!({
        "kind": "ak.strand.create",
        "payload": {
            "object": {
                "id": strand_id,
                "metadata": { "title": "AI sidecar" },
                "tracks": { "discussion": { "enabled": true } }
            }
        }
    });
    let projected = channel_from_strand_event("ak:realm:demo", &event).expect("discussion event");
    assert_eq!(projected.name, "AI sidecar");
}

#[test]
fn channel_from_strand_event_never_infers_private_sidecar_identity() {
    let event = json!({
        "event_id": "ak:event:sidecar-strand",
        "kind": "ak.strand.create",
        "realm_id": "ak:realm:demo",
        "object": {
            "id": "ak:strand:sidecar",
            "metadata": {
                "title": "AI sidecar",
                "fields": { "client_private_hint": true }
            },
            "tracks": {
                "discussion": {"enabled": true, "is_primary": true}
            }
        }
    });

    let channel = channel_from_strand_event("ak:realm:demo", &event).unwrap();

    assert_eq!(channel.strand_id, "ak:strand:sidecar");
    assert!(!channel.is_private_sidecar);
}

#[test]
fn channel_from_strand_event_ignores_non_discussion_strands() {
    let event = json!({
        "event_id": "ak:event:strand",
        "kind": "ak.strand.create",
        "realm_id": "ak:realm:demo",
        "strand_id": "ak:strand:doc",
        "title": "Doc strand",
        "strand": {
            "id": "ak:strand:doc",
            "title": "Doc strand",
            "tracks": {
                "document": {"profile": "document"}
            }
        }
    });

    assert!(channel_from_strand_event("ak:realm:demo", &event).is_none());
}

#[test]
fn default_discussion_channel_uses_realm_default_strand_projection() {
    let body = json!({
        "summary": {
            "title": "Demo Realm",
            "strand": {
                "strand_id": "ak:strand:demo",
                "title": "General",
                "summary": "Realm-wide conversation",
                "tracks": {
                    "discussion": {"enabled": true},
                    "synthesis": {"enabled": true}
                }
            }
        }
    });

    let channel = default_discussion_channel("ak:realm:demo", Some(&body));

    assert_eq!(channel.strand_id, "ak:strand:demo");
    assert_eq!(channel.name, "General");
    assert_eq!(channel.kind, "discussion");
    assert_eq!(channel.topic.as_deref(), Some("Realm-wide conversation"));
    assert!(channel.is_default);
}

#[test]
fn default_discussion_channel_synthesizes_default_strand_when_projection_is_absent() {
    let channel = default_discussion_channel("ak:realm:demo", None);

    assert_eq!(channel.strand_id, "ak:strand:demo");
    assert_eq!(channel.name, "Discussion");
    assert_eq!(channel.category, "default strand");
    assert!(channel.is_default);
}

#[test]
fn presence_maps_from_sync_events_prefers_account_subscribe_presence() {
    let now = chrono::Utc::now();
    let sent_at = now - chrono::Duration::seconds(5);
    let expires_at = now + chrono::Duration::seconds(55);
    let participants = vec![
        "did:web:alice.example".to_owned(),
        "did:web:bob.example".to_owned(),
        "did:web:carol.example".to_owned(),
    ];
    let events = vec![
        json!({
            "kind": "ak.presence",
            "actor_id": "did:web:bob.example",
            "device_id": "ak:device:bob",
            "sent_at": sent_at,
            "expires_at": expires_at,
            "payload": {
                "state": "online",
                "status_message": "On vacation until May 5",
                "ttl_ms": 60000
            }
        }),
        json!({
            "actor_id": "did:web:carol.example",
            // Matrix-legacy `unavailable` fails closed to offline.
            "status": "unavailable"
        }),
        json!({
            "actor_id": "did:web:mallory.example",
            "state": "online"
        }),
    ];

    let (states, labels, status_messages) =
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
    assert_eq!(
        status_messages.get("did:web:bob.example"),
        Some(&"On vacation until May 5".to_owned())
    );
    assert!(!states.contains_key("did:web:mallory.example"));
}

#[test]
fn presence_projection_refresh_key_changes_without_a_cursor_advance() {
    let online = vec![json!({
        "kind": "ak.presence",
        "actor_id": "did:web:bob.example",
        "state": "online",
    })];
    let offline = vec![json!({
        "kind": "ak.presence",
        "actor_id": "did:web:bob.example",
        "state": "offline",
    })];

    let online_key = presence_projection_refresh_key("realm|participants", "cursor-7", &online);
    assert_eq!(
        online_key,
        presence_projection_refresh_key("realm|participants", "cursor-7", &online)
    );
    assert_ne!(
        online_key,
        presence_projection_refresh_key("realm|participants", "cursor-7", &offline)
    );
}

#[test]
fn presence_maps_from_sync_events_aggregates_live_device_envelopes() {
    let now = chrono::Utc::now();
    let participants = vec![
        "did:web:alice.example".to_owned(),
        "did:web:bob.example".to_owned(),
    ];
    let events = vec![
        json!({
            "kind": "ak.presence",
            "actor_id": "did:web:bob.example",
            "device_id": "ak:device:bob-a",
            "sent_at": now - chrono::Duration::seconds(20),
            "expires_at": now + chrono::Duration::seconds(40),
            "payload": {
                "state": "dnd",
                "status_message": "Heads down",
                "ttl_ms": 60000
            }
        }),
        json!({
            "kind": "ak.presence",
            "actor_id": "did:web:bob.example",
            "device_id": "ak:device:bob-b",
            "sent_at": now - chrono::Duration::seconds(10),
            "expires_at": now + chrono::Duration::seconds(50),
            "payload": {
                "state": "online",
                "status_message": "Available soon",
                "ttl_ms": 60000
            }
        }),
        json!({
            "kind": "ak.presence",
            "actor_id": "did:web:bob.example",
            "device_id": "ak:device:bob-expired",
            "sent_at": now - chrono::Duration::seconds(70),
            "expires_at": now - chrono::Duration::seconds(10),
            "payload": {
                "state": "dnd",
                "status_message": "Expired override",
                "ttl_ms": 60000
            }
        }),
    ];

    let (states, _, status_messages) =
        presence_maps_from_sync_events(&events, &participants, "did:web:alice.example", "Alice")
            .expect("live remote presence should match participants");

    assert_eq!(states.get("did:web:bob.example"), Some(&"dnd".to_owned()));
    assert_eq!(
        status_messages.get("did:web:bob.example"),
        Some(&"Available soon".to_owned())
    );
}

#[test]
fn typing_actor_snapshot_filters_expired_and_self_entries() {
    let now = chrono::Utc::now();
    let expired = now - chrono::Duration::seconds(30);
    let future = now + chrono::Duration::seconds(60);
    let realms = std::collections::BTreeMap::from([(
        "ak:realm:demo".to_owned(),
        json!({
            "ephemeral": { "events": [
                {
                    "kind": "ak.typing",
                    "actor_id": "did:web:alice.example",
                    "expires_at": arkret_sdk::canonical::format_timestamp_canonical(future),
                    "payload": { "typing": true, "strand_id": "ak:strand:demo" }
                },
                {
                    "kind": "ak.typing",
                    "actor_id": "did:web:bob.example",
                    "expires_at": arkret_sdk::canonical::format_timestamp_canonical(expired),
                    "payload": { "typing": true, "strand_id": "ak:strand:demo" }
                },
                {
                    "kind": "ak.typing",
                    "actor_id": "did:web:self.example",
                    "expires_at": arkret_sdk::canonical::format_timestamp_canonical(future),
                    "payload": { "typing": true, "strand_id": "ak:strand:demo" }
                }
            ] }
        }),
    )]);

    let snapshot = typing_actor_snapshot_from_sync_realms(
        &realms,
        "ak:realm:demo",
        "ak:strand:demo",
        "did:web:self.example",
    );

    assert_eq!(snapshot.actors, vec!["did:web:alice.example".to_owned()]);
    assert_eq!(snapshot.next_expires_at_ms, Some(future.timestamp_millis()));
    assert_eq!(
        typing_actors_from_sync_realms(
            &realms,
            "ak:realm:demo",
            "ak:strand:demo",
            "did:web:self.example",
        ),
        vec!["did:web:alice.example".to_owned()]
    );
}

#[test]
fn typing_actor_snapshot_reads_canonical_ephemeral_envelopes() {
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(60);
    let realms = std::collections::BTreeMap::from([(
        "ak:realm:demo".to_owned(),
        json!({
            "ephemeral": {"events": [
                {
                    "kind": "ak.typing",
                    "actor_id": "did:web:alice.example",
                    "expires_at": arkret_sdk::canonical::format_timestamp_canonical(expires_at),
                    "payload": {"strand_id": "ak:strand:demo", "typing": true}
                },
                {
                    "kind": "ak.typing",
                    "actor_id": "did:web:bob.example",
                    "expires_at": arkret_sdk::canonical::format_timestamp_canonical(expires_at),
                    "payload": {"strand_id": "ak:strand:demo", "typing": false}
                }
            ]}
        }),
    )]);

    let snapshot = typing_actor_snapshot_from_sync_realms(
        &realms,
        "ak:realm:demo",
        "ak:strand:demo",
        "did:web:self.example",
    );

    assert_eq!(snapshot.actors, vec!["did:web:alice.example".to_owned()]);
    assert_eq!(
        snapshot.next_expires_at_ms,
        Some(expires_at.timestamp_millis())
    );
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
    assert!(!MessageCryptoState::LateRecoveryRejected.is_pending());
}

#[test]
fn secure_content_block_round_trips_back_to_text() {
    // P1: the secure send path encrypts the canonical Content Block JSON
    // (not raw body bytes), and the decrypt-on-read path extracts the text
    // back out via `text_body_from_value`. This locks that symmetry without
    // standing up a full MLS group.
    let body = "secret hello with spaces";
    let content_value = arkret_sdk::ContentBlock::text(body)
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
        "inkson-chat-decrypt-{}.json",
        crate::operation::uuid_v7()
    ));
    let store = LocalStateStore::with_path(temp);
    let envelope = json!({
        "scheme": "mls-rfc9420",
        "group_id": "group-x",
        "epoch": 1,
        "content_type": "application/vnd.arkret.message+json",
        "ciphertext": "AAAA",
        "payload_digest": "sha256:0",
    });
    assert!(
        decrypt_chat_encrypted_content(
            &store,
            "ak:realm:none",
            "did:web:alice.example",
            "ak:device:01964137-0000-7000-8000-000000000001",
            None,
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
            "type": "ak.message.create",
            "body": "[encrypted]",
            "strand_id": "ak:strand:1",
            "encrypted_content": {"ciphertext": "blob"},
        }
    });
    let msg = chat_message_from_event("ak:realm:demo", &event).expect("message");
    assert_eq!(msg.crypto_state, MessageCryptoState::Decrypting);
}

#[test]
fn circle_scoped_message_does_not_require_forbidden_payload_scope_field() {
    let event = json!({
        "event_id": "ak:event:01964137-0000-7000-8000-0000000000c1",
        "kind": "ak.message.create",
        "effective_scope": {
            "kind": "circle",
            "realm_id": "ak:realm:01964137-0000-7000-8000-0000000000c2",
            "circle_id": "ak:circle:01964137-0000-7000-8000-0000000000c3"
        },
        "payload": {
            "strand_id": "ak:strand:01964137-0000-7000-8000-0000000000c4",
            "message_id": "message-circle-scoped",
            "track_name": "discussion",
            "content": { "body": "private" }
        }
    });

    let message =
        chat_message_from_event("ak:realm:01964137-0000-7000-8000-0000000000c2", &event).unwrap();
    assert_eq!(message.crypto_state, MessageCryptoState::Plaintext);
    assert_eq!(message.body, "private");
}

#[test]
fn chat_message_from_event_keeps_bodyless_encrypted_payload_visible() {
    let event = json!({
        "event_id": "evt:bodyless",
        "content": {
            "type": "ak.message.create",
            "strand_id": "ak:strand:1",
            "message_id": "ak:message:1",
            "encrypted_content": {
                "scheme": "mls-rfc9420",
                "version": "1.0",
                "group_id": "ak:mls:test",
                "epoch": 1,
                "content_type": "application/vnd.arkret.message+json",
                "ciphertext": "AAAA",
                "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
        }
    });

    let msg = chat_message_from_event("ak:realm:demo", &event).expect("message");

    assert_eq!(msg.body, "");
    assert_eq!(msg.strand_id, "ak:strand:1");
    assert_eq!(msg.crypto_state, MessageCryptoState::Decrypting);
}

#[test]
fn chat_message_from_event_marks_failed_local_decrypt_as_key_missing() {
    let temp = std::env::temp_dir().join(format!(
        "inkson-chat-key-missing-{}.json",
        crate::operation::uuid_v7()
    ));
    let store = LocalStateStore::with_path(temp);
    let event = json!({
        "event_id": "evt:key-missing",
        "content": {
            "type": "ak.message.create",
            "strand_id": "ak:strand:1",
            "message_id": "ak:message:1",
            "encrypted_content": {
                "scheme": "mls-rfc9420",
                "version": "1.0",
                "group_id": "ak:mls:test",
                "epoch": 1,
                "content_type": "application/vnd.arkret.message+json",
                "ciphertext": "AAAA",
                "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
        }
    });

    let msg = chat_message_from_event_with_sidecar(
        "ak:realm:none",
        &event,
        Some(&store),
        Some((
            "did:web:bob.example",
            "ak:device:01964137-0000-7000-8000-000000000001",
        )),
    )
    .expect("message");

    assert_eq!(msg.body, "");
    assert_eq!(msg.crypto_state, MessageCryptoState::KeyMissing);
}

#[test]
fn chat_message_revise_operation_uses_schema_target_ref() {
    let op = chat_message_revise_operation(
        "ak:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22",
        "did:web:bob.example",
        "ak:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23",
        "edited",
    )
    .expect("builds");

    assert_eq!(
        op.payload["target_ref"],
        "ak:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23"
    );
    assert_eq!(op.payload["content"]["kind"], "ak.content.text");
    assert_eq!(op.payload["content"]["body"], "edited");
    assert!(op.payload.get("body").is_none());
    assert!(op.payload.get("target_event_id").is_none());
    arkret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind.as_str(),
            &serde_json::to_value(&op.payload).unwrap(),
        )
        .unwrap();
}

#[test]
fn chat_message_revise_operation_addresses_message_target_via_message_id() {
    // A `ak:message:` target is addressed through the payload's `message_id`
    // field (like `chat_message_redact_operation`), not `target_ref` — both are
    // valid per the message_revise_payload anyOf, and message_id is the typed
    // form the SDK builder emits for message ids.
    let op = chat_message_revise_operation(
        "ak:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22",
        "did:web:bob.example",
        "ak:message:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23",
        "edited",
    )
    .expect("builds");

    assert_eq!(
        op.payload["message_id"],
        "ak:message:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23"
    );
    assert!(op.payload.get("target_ref").is_none());
    assert_eq!(op.payload["content"]["kind"], "ak.content.text");
    assert_eq!(op.payload["content"]["body"], "edited");
    arkret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind.as_str(),
            &serde_json::to_value(&op.payload).unwrap(),
        )
        .unwrap();
}

#[test]
fn chat_message_redact_operation_uses_event_target_for_event_id() {
    let op = chat_message_redact_operation(
        "ak:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22",
        "did:web:bob.example",
        "ak:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23",
        "author_redaction",
    )
    .expect("builds");

    assert_eq!(
        op.payload["target_event_id"],
        "ak:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23"
    );
    assert_eq!(op.payload["reason"], "author_redaction");
    assert!(op.payload.get("message_id").is_none());
    arkret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind.as_str(),
            &serde_json::to_value(&op.payload).unwrap(),
        )
        .unwrap();
}

#[test]
fn chat_message_redact_operation_uses_message_id_for_message_target() {
    let op = chat_message_redact_operation(
        "ak:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22",
        "did:web:bob.example",
        "ak:message:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23",
        "author_redaction",
    )
    .expect("builds");

    assert_eq!(
        op.payload["message_id"],
        "ak:message:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23"
    );
    assert_eq!(op.payload["reason"], "author_redaction");
    assert!(op.payload.get("target_event_id").is_none());
    arkret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind.as_str(),
            &serde_json::to_value(&op.payload).unwrap(),
        )
        .unwrap();
}

#[test]
fn chat_reaction_add_operation_uses_schema_target_ref() {
    let op = chat_reaction_add_operation(
        "ak:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22",
        "did:web:bob.example",
        "ak:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23",
        "+1",
    )
    .expect("builds");

    assert_eq!(
        op.payload["target_ref"],
        "ak:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23"
    );
    assert_eq!(op.payload["key"], "+1");
    assert!(op.payload.get("event_id").is_none());
    assert!(op.payload.get("actor").is_none());
    arkret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind.as_str(),
            &serde_json::to_value(&op.payload).unwrap(),
        )
        .unwrap();
}

/// D1: the former `events.rs` / `strands.rs` merge-helper twins were unified
/// into the single canonical `merge_duplicate_create_message`. These tests pin
/// the aligned semantics: the `>=` same-version tie-break, local-metadata
/// preservation, revision-body append, reaction union/sort, whitespace-trim on
/// reaction keys/actors, and the folded-in `created_at` carry-forward.
#[cfg(test)]
mod merge_duplicate_create_message_alignment_tests {
    use super::*;

    fn at(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        Some(
            chrono::DateTime::parse_from_rfc3339(value)
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
    }

    fn msg(id: &str, body: &str, created_at: Option<chrono::DateTime<chrono::Utc>>) -> ChatMessage {
        ChatMessage {
            realm_id: "ak:realm:r1".to_owned(),
            id: id.to_owned(),
            protocol_message_id: Some("ak:message:m1".to_owned()),
            sender: "did:web:bob.example".to_owned(),
            executed_by: None,
            body: body.to_owned(),
            timestamp: "10:00".to_owned(),
            created_at,
            strand_id: "ak:strand:topic".to_owned(),
            reply_to: None,
            reactions: Vec::new(),
            redacted: false,
            edited: false,
            revisions: Vec::new(),
            pending: false,
            failed: false,
            error: None,
            mentions: Vec::new(),
            crypto_state: MessageCryptoState::Plaintext,
        }
    }

    // The `>=` same-version tie-break is the load-bearing predicate the two
    // former merge families now share. On an equal timestamp the incoming row
    // wins (and thus carries local metadata forward) iff its id is `>=`.
    #[test]
    fn newer_or_same_lifecycle_version_uses_ge_id_tiebreak_on_equal_timestamp() {
        let existing = msg("ak:event:b", "existing", at("2026-07-07T06:19:20.000Z"));
        let same_id = msg("ak:event:b", "incoming", at("2026-07-07T06:19:20.000Z"));
        let higher_id = msg("ak:event:c", "incoming", at("2026-07-07T06:19:20.000Z"));
        let lower_id = msg("ak:event:a", "incoming", at("2026-07-07T06:19:20.000Z"));
        assert!(same_id.is_newer_or_same_lifecycle_version_than(&existing));
        assert!(higher_id.is_newer_or_same_lifecycle_version_than(&existing));
        assert!(!lower_id.is_newer_or_same_lifecycle_version_than(&existing));
    }

    #[test]
    fn newer_or_same_lifecycle_version_prefers_strictly_newer_timestamp() {
        let existing = msg("ak:event:b", "existing", at("2026-07-07T06:19:20.000Z"));
        // A strictly newer timestamp wins regardless of the id tie-break.
        let newer = msg("ak:event:a", "incoming", at("2026-07-07T06:19:30.000Z"));
        let older = msg("ak:event:c", "incoming", at("2026-07-07T06:19:10.000Z"));
        assert!(newer.is_newer_or_same_lifecycle_version_than(&existing));
        assert!(!older.is_newer_or_same_lifecycle_version_than(&existing));
    }

    #[test]
    fn newer_or_same_lifecycle_version_missing_timestamps() {
        let existing_none = msg("ak:event:a", "existing", None);
        let existing_some = msg("ak:event:a", "existing", at("2026-07-07T06:19:20.000Z"));
        let incoming_none = msg("ak:event:a", "incoming", None);
        let incoming_some = msg("ak:event:a", "incoming", at("2026-07-07T06:19:20.000Z"));
        // incoming timestamped, existing not → incoming newer.
        assert!(incoming_some.is_newer_or_same_lifecycle_version_than(&existing_none));
        // existing timestamped, incoming not → NOT newer.
        assert!(!incoming_none.is_newer_or_same_lifecycle_version_than(&existing_some));
        // neither timestamped → treat incoming as newer-or-same.
        assert!(incoming_none.is_newer_or_same_lifecycle_version_than(&existing_none));
    }

    // A newer incoming replaces the row but preserves locally-tracked edit
    // metadata (edited flag + revision history) and folds the previous body
    // into the revision list.
    #[test]
    fn merge_newer_incoming_preserves_local_edit_metadata_and_appends_old_body() {
        let mut existing = msg(
            "ak:event:rev-1",
            "edited body",
            at("2026-07-07T06:19:22.000Z"),
        );
        existing.edited = true;
        existing.revisions = vec!["draft".to_owned()];
        let incoming = msg(
            "ak:event:base",
            "newer body",
            at("2026-07-07T06:19:30.000Z"),
        );

        merge_duplicate_create_message(&mut existing, incoming);

        assert_eq!(existing.id, "ak:event:base");
        assert_eq!(existing.body, "newer body");
        assert!(existing.edited, "edited flag carried forward");
        assert_eq!(
            existing.revisions,
            vec!["draft".to_owned(), "edited body".to_owned()]
        );
    }

    // A late older create folds into the existing (newer) row: existing stays
    // authoritative, the older body is appended as a revision, reactions union.
    #[test]
    fn merge_older_incoming_keeps_existing_and_folds_body_into_revisions() {
        let mut existing = msg(
            "ak:event:rev-1",
            "current body",
            at("2026-07-07T06:19:30.000Z"),
        );
        existing.edited = true;
        let mut incoming = msg(
            "ak:event:base",
            "original body",
            at("2026-07-07T06:19:20.000Z"),
        );
        incoming.reactions = vec![("+1".to_owned(), vec!["did:web:carol.example".to_owned()])];

        merge_duplicate_create_message(&mut existing, incoming);

        assert_eq!(existing.id, "ak:event:rev-1");
        assert_eq!(existing.body, "current body");
        assert_eq!(existing.revisions, vec!["original body".to_owned()]);
        assert_eq!(
            existing.reactions,
            vec![("+1".to_owned(), vec!["did:web:carol.example".to_owned()])]
        );
    }

    // Reaction members from both sides union, dedupe overlapping reactors, and
    // sort by key then by member.
    #[test]
    fn merge_unions_and_sorts_reaction_members() {
        let mut existing = msg("ak:event:base", "body", at("2026-07-07T06:19:20.000Z"));
        existing.reactions = vec![("+1".to_owned(), vec!["did:web:bob.example".to_owned()])];
        let mut incoming = msg("ak:event:base2", "body", at("2026-07-07T06:19:30.000Z"));
        incoming.reactions = vec![
            (
                "\u{2764}".to_owned(),
                vec!["did:web:dave.example".to_owned()],
            ),
            (
                "+1".to_owned(),
                vec![
                    "did:web:carol.example".to_owned(),
                    "did:web:bob.example".to_owned(),
                ],
            ),
        ];

        merge_duplicate_create_message(&mut existing, incoming);

        assert_eq!(
            existing.reactions,
            vec![
                (
                    "+1".to_owned(),
                    vec![
                        "did:web:bob.example".to_owned(),
                        "did:web:carol.example".to_owned(),
                    ],
                ),
                (
                    "\u{2764}".to_owned(),
                    vec!["did:web:dave.example".to_owned()]
                ),
            ]
        );
    }

    // The retained (events) `push_reaction_member` trims whitespace on both the
    // reaction key and the actor — the divergence that the deleted strands twin
    // did NOT apply. Exercised through the real construction path.
    #[test]
    fn reactions_from_summary_trim_whitespace_in_key_and_actor() {
        let mut events = vec![json!({
            "event_id": "ak:event:msg-r",
            "kind": "ak.message.create",
            "actor_id": "did:web:bob.example",
            "realm_id": "ak:realm:r1",
            "created_at": "2026-07-07T06:19:20.000Z",
            "strand_id": "ak:strand:topic",
            "message_id": "ak:message:mr",
            "body": "hi",
            "reaction_summary": { " +1 ": { "members": [" did:web:carol.example "] } },
            "proofs": []
        })];
        sign_chat_fixtures(&mut events);
        let messages = chat_messages_from_events_with_sidecar("ak:realm:r1", &events, None, None);
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0].reactions,
            vec![("+1".to_owned(), vec!["did:web:carol.example".to_owned()])]
        );
    }

    // Folded-in strands improvement: a redaction tombstone that arrives without
    // its own `created_at` keeps the existing row's timestamp so ordering is
    // stable. (The former events twin dropped the timestamp here.)
    #[test]
    fn merge_redaction_tombstone_without_timestamp_keeps_existing_created_at() {
        let mut existing = msg("ak:event:base", "secret", at("2026-07-07T06:19:20.000Z"));
        let mut tombstone = msg("ak:event:base", "", None);
        tombstone.redacted = true;

        merge_duplicate_create_message(&mut existing, tombstone);

        assert!(existing.redacted);
        assert_eq!(existing.created_at, at("2026-07-07T06:19:20.000Z"));
    }
}
