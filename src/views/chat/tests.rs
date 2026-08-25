use super::*;

fn test_authority(actor: &str) -> arkret_sdk::PrincipalAuthorityKey {
    arkret_sdk::PrincipalAuthorityKey::new(
        crate::mls_api_helpers::principal_core_id(actor).unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
    )
}

fn test_device_id(value: &str) -> arkret_sdk::DeviceId {
    arkret_sdk::DeviceId::new(value.to_owned()).unwrap()
}

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
    sidecar_projection_message_for_realm(
        "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw",
        id,
        strand_id,
        body,
    )
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
        content_format: None,
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

/// A valid `delivered` Event-fold projection (§7.2.4 shape: no Pending, no
/// updated_hlc; coordinator + folded_frontier are required).
fn delivered_exchange_projection_fixture(
    realm_id: &str,
    source_strand_id: &str,
    source_event_id: Option<&str>,
    request_event_id: &str,
) -> arkret_sdk::AgentSidecarExchangeProjection {
    let coordinator =
        crate::mls_api_helpers::principal_core_id("did:web:example.test:agents:assistant").unwrap();
    let request_event = arkret_sdk::EventId::new(request_event_id).unwrap();
    arkret_sdk::AgentSidecarExchangeProjection {
        schema: arkret_sdk::AgentSidecarExchangeProjectionSchema::V1,
        controller_id: crate::mls_api_helpers::principal_core_id("did:web:example.test:alice")
            .unwrap(),
        sidecar_id: arkret_sdk::SidecarId::new(
            "ak:sidecar:AWea2MtI5dOI1LSRyI266_gQVrWUd0po0dxZiJNsH8kN",
        )
        .unwrap(),
        exchange_id: arkret_sdk::AgentSidecarExchangeId::new("exchange-01964137000000000008")
            .unwrap(),
        origin: arkret_sdk::AgentSidecarExchangeOrigin::SourceTrackRouted,
        source_track_ref: arkret_sdk::AgentSidecarSourceTrackRef {
            realm_id: arkret_sdk::RealmId::new(realm_id).unwrap(),
            strand_id: arkret_sdk::StrandId::new(source_strand_id).unwrap(),
            track_name: "discussion".to_owned(),
        },
        source_event_id: source_event_id.map(|anchor| arkret_sdk::EventId::new(anchor).unwrap()),
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
        failure_reason_code: None,
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
fn source_routed_echo_is_private_and_stably_follows_its_anchor() {
    let realm = "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5";
    let source = "ak:strand:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N";
    let anchor = "ak:event:ATrYU3cGlcWkAcHXWgJ8sIYfraoV9pIwEHNNStEqHvFh";
    let echo = "ak:event:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc";
    let later = "ak:event:AS7wchHFRbXWnMQPln42BrokXsPCf18uboKMm-yhYquI";
    let projection = delivered_exchange_projection_fixture(realm, source, Some(anchor), echo);
    let messages = vec![
        sidecar_projection_message_for_realm(realm, anchor, source, "anchor"),
        sidecar_projection_message_for_realm(realm, later, source, "later shared"),
        sidecar_projection_message_for_realm(realm, echo, source, "private echo"),
    ];

    let visible = project_visible_messages(&messages, source, realm, None, &[projection]);

    assert_eq!(
        visible
            .iter()
            .map(|message| message.id.as_str())
            .collect::<Vec<_>>(),
        vec![anchor, echo, later]
    );
    assert_eq!(visible[1].strand_id, source);
}

#[test]
fn source_routed_echo_waits_until_its_anchor_is_visible() {
    let realm = "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5";
    let source = "ak:strand:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N";
    let missing_anchor = "ak:event:ATrYU3cGlcWkAcHXWgJ8sIYfraoV9pIwEHNNStEqHvFh";
    let echo = "ak:event:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc";
    let mut projection =
        delivered_exchange_projection_fixture(realm, source, Some(missing_anchor), echo);
    let messages = vec![sidecar_projection_message_for_realm(
        realm,
        echo,
        source,
        "private echo",
    )];

    assert!(
        project_visible_messages(&messages, source, realm, None, &[projection.clone()]).is_empty()
    );

    projection.source_event_id = None;
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
        client_order_key: arkret_sdk::NonEmptyString::new("device-1-1").unwrap(),
        addressed_agent_ids: vec![
            crate::mls_api_helpers::principal_core_id("did:web:example.test:agents:assistant")
                .unwrap(),
        ],
        completion_policy: arkret_sdk::AgentSidecarExchangeCompletionPolicy::Coordinator,
        coordinator_agent_id: None,
        source_event_id: None,
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
    let realm = "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5";
    let source = "ak:strand:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N";
    let private = "ak:strand:AcbZeQX0xMn0M0LtYe9f9_xr8Z7FPPgaq35ALTQg0tks";
    let native = "ak:event:ATrYU3cGlcWkAcHXWgJ8sIYfraoV9pIwEHNNStEqHvFh";
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
            let actor_core_id = if actor_id.starts_with("did:") {
                crate::mls_api_helpers::principal_core_id(&actor_id).unwrap()
            } else {
                arkret_sdk::DidCoreId::new(actor_id.clone()).unwrap()
            };
            // Proof fixtures need an exact full DID for their verification
            // URL. These fixtures use reversible did:web ids only; production
            // code never performs this core-to-full reconstruction.
            let signer_full_id = actor_id
                .strip_prefix("ak:did_core:web:")
                .map(|suffix| format!("did:web:{suffix}"))
                .unwrap_or_else(|| actor_id.clone());
            object.insert("device_id".to_owned(), json!(CHAT_FIXTURE_DEVICE));
            object.remove("proofs");
            object.remove("unsigned");
            let signer = crate::event_signer::build_ed25519_signer_with_verification_method(
                CHAT_FIXTURE_SEED,
                &signer_full_id,
                format!("{signer_full_id}#{CHAT_FIXTURE_DEVICE}"),
            );
            // The `encoding.md` §6 preimage comes from the SDK. A fixture signer
            // that restates the rule is how this file once signed bytes no
            // verifier could reproduce.
            let preimage = arkret_sdk::event_digest_preimage(value).unwrap();
            let canonical_bytes = crate::canonical::canonical_json_bytes(&preimage).unwrap();
            let event_digest = crate::canonical::sha256_digest(&canonical_bytes);
            let mut proof = arkret_sdk::ProducerEventProof {
                kind: "detached_jws".to_owned(),
                verification_method: arkret_sdk::DidUrl::new(
                    signer.verification_method().to_owned(),
                )
                .unwrap(),
                event_digest: arkret_sdk::Hash::new(event_digest).unwrap(),
                signer_resolution_evidence_ref: None,
                signer_resolution_evidence_digest: None,
                created_at: chrono::DateTime::parse_from_rfc3339("2026-07-10T00:00:00.000Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: String::new(),
            };
            let binding = proof.canonical_binding_bytes(&actor_core_id).unwrap();
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
                actor_core_id.as_str(),
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

#[test]
fn parses_message_event_with_operation_body_shape() {
    let event = json!({
        "id": "ak:event:AZccWZlaAUrqgOzXQ7OucnyL0J8C4O-JnwPOLdtlGX9k",
        "type": "ak.message.create",
        "actor": "did:web:alice.example",
        "realm_id": "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        "created_at": "2026-05-14T01:23:45.000Z",
        "causal": {"actor_seq": 42},
        "body": {
            "body": "restored from durable history",
            "strand_id": "ak:strand:A2XzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c",
            "message_id": "chat-msg-local",
            "mentions": [{
                "kind": "mention",
                "subject_id": "ak:did_core:web:bob.example",
                "mention_text_original": "@bob"
            }]
        }
    });

    let message = chat_message_from_event(
        "ak:realm:Ag51V75jn75rRYCrxiU0PfMG0uo93vCh_5AfJiv15VPU",
        &event,
    )
    .unwrap();

    assert_eq!(
        message.id,
        "ak:event:AZccWZlaAUrqgOzXQ7OucnyL0J8C4O-JnwPOLdtlGX9k"
    );
    assert_eq!(
        message.realm_id,
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE"
    );
    assert_eq!(
        message.strand_id,
        "ak:strand:A2XzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c"
    );
    assert_eq!(message.body, "restored from durable history");
    assert_eq!(message.content_format, None);
    assert_eq!(message.sender, "did:web:alice.example");
    assert_eq!(
        message.mentions[0].target_id(),
        "ak:did_core:web:bob.example"
    );
}

#[test]
fn parses_message_event_with_nested_envelope_payload_shape() {
    let mut event = json!({
        "event": {
            "event_id": "ak:event:Ah6V68zzvc5Qi7Qo6XcK38HBtXkkopkL0Y-dhmOTIlmE",
            "kind": "ak.message.create",
            "actor_id": "ak:did_core:web:alice.example",
            "actor_seq": 43,
            "payload": {
                "content": {
                    "kind": "ak.content.text",
                    "body": "nested payload message",
                    "format": "markdown"
                },
                "strand_id": "ak:strand:A-KafHE4KSJLkmXVT_Mi2jvxt9YuOP_vQeOTOtjeaXSc",
                "message_id": "chat-msg-nested"
            }
        }
    });
    sign_chat_fixture(&mut event);

    let message = chat_message_from_event(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        &event,
    )
    .unwrap();

    assert_eq!(
        message.id,
        "ak:event:Ah6V68zzvc5Qi7Qo6XcK38HBtXkkopkL0Y-dhmOTIlmE"
    );
    assert_eq!(
        message.strand_id,
        "ak:strand:A-KafHE4KSJLkmXVT_Mi2jvxt9YuOP_vQeOTOtjeaXSc"
    );
    assert_eq!(message.body, "nested payload message");
    assert_eq!(
        message.content_format,
        Some(arkret_sdk::TextFormat::Markdown)
    );
}

#[test]
fn long_text_projection_preserves_its_declared_markdown_format() {
    let mut event = json!({
        "event_id": "ak:event:A3YyTPegfva2k0jRQeI4iVcOhvxyHN1MeQ2dpTfPOF0l",
        "kind": "ak.message.create",
        "actor_id": "ak:did_core:web:alice.example",
        "payload": {
            "strand_id": "ak:strand:A-KafHE4KSJLkmXVT_Mi2jvxt9YuOP_vQeOTOtjeaXSc",
            "message_id": "chat-msg-long-text",
            "content": {
                "kind": "ak.content.long_text",
                "body": "# fallback",
                "format": "markdown",
                "body_kind": "prefix",
                "blob_ref": format!("ak:blob:sha256:{}", "a".repeat(64)),
                "size_bytes": 262_145,
                "media_type": "text/markdown"
            }
        }
    });
    sign_chat_fixture(&mut event);

    let message = chat_message_from_event(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        &event,
    )
    .unwrap();
    assert_eq!(
        message.content_format,
        Some(arkret_sdk::TextFormat::Markdown)
    );
    assert!(message.body.starts_with('\u{1e}'));
}

#[test]
fn folds_received_redaction_tombstone_onto_message() {
    // soland surfaces a redacted ak.message.create as a per-message tombstone:
    // event_id preserved, body stripped, redacted/state markers added. The
    // receive path MUST render the tombstone (redacted=true, empty body) even
    // though this is the only copy of the message the reader ever sees.
    let mut event = json!({
        "kind": "ak.message.create",
        "event_id": "ak:event:AOpOUPvtrgs_YaMdpjTSrJvTrtQP8fvBxcu1UnOriMzY",
        "message_id": "ak:message:AST13ozMXrAgNmz6E-qiQFr9vg-w3JDZGPHpHPq_JTpY",
        "realm_id": "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        "strand_id": "ak:strand:A-KafHE4KSJLkmXVT_Mi2jvxt9YuOP_vQeOTOtjeaXSc",
        "sender": "did:web:bob.example",
        "actor_id": "ak:did_core:web:bob.example",
        "created_at": "2026-05-14T01:23:45.000Z",
        "redacted": true,
        "state": "redacted",
        "redacted_at": "2026-05-14T02:00:00.000Z",
        "redaction_ref": "ak:event:A-RSupDyayuw4R7tIwZPpZWnF36wsoZuXYPDzQJ-jmhk",
        "content": {"kind": "ak.content.text", "body": "[redacted]"}
    });
    sign_chat_fixture(&mut event);

    let message = chat_message_from_event(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        &event,
    )
    .unwrap();

    assert_eq!(
        message.id,
        "ak:event:AOpOUPvtrgs_YaMdpjTSrJvTrtQP8fvBxcu1UnOriMzY"
    );
    assert!(message.redacted);
    assert_eq!(message.body, "");
}

#[test]
fn chat_visible_read_receipt_send_respects_preferences() {
    let temp = std::env::temp_dir().join(format!("inkson-chat-rr-pref-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    assert!(chat_visible_read_receipt_should_send(
        &store,
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));

    store.set_read_receipt_default_send(false);
    assert!(!chat_visible_read_receipt_should_send(
        &store,
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));

    store.set_read_receipt_realm_override(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(true),
    );
    assert!(chat_visible_read_receipt_should_send(
        &store,
        "ak:strand:A4EpRDvQloG8EYOGEPnGhe1SLpxBiLQbOvlptwBvvPkA",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));

    store.set_read_receipt_strand_override(
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        Some(false),
    );
    assert!(!chat_visible_read_receipt_should_send(
        &store,
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));

    store.set_read_receipt_policy_snapshot(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(crate::state::ReadReceiptPolicySnapshot {
            disclosure: "required".to_owned(),
            visibility: Some("public".to_owned()),
        }),
    );
    assert!(chat_visible_read_receipt_should_send(
        &store,
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));

    store.set_read_receipt_policy_snapshot(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(crate::state::ReadReceiptPolicySnapshot {
            disclosure: "disabled".to_owned(),
            visibility: Some("private".to_owned()),
        }),
    );
    assert!(!chat_visible_read_receipt_should_send(
        &store,
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));
}

#[test]
fn chat_visible_read_receipt_display_respects_local_preferences() {
    let temp = std::env::temp_dir().join(format!("inkson-chat-rr-display-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    assert!(chat_visible_read_receipt_should_display(
        &store,
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));

    store.set_read_receipt_default_display(false);
    assert!(!chat_visible_read_receipt_should_display(
        &store,
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));

    store.set_read_receipt_realm_display_override(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(true),
    );
    assert!(chat_visible_read_receipt_should_display(
        &store,
        "ak:strand:A4EpRDvQloG8EYOGEPnGhe1SLpxBiLQbOvlptwBvvPkA",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));

    store.set_read_receipt_strand_display_override(
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        Some(false),
    );
    assert!(!chat_visible_read_receipt_should_display(
        &store,
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));

    store.set_read_receipt_policy_snapshot(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(crate::state::ReadReceiptPolicySnapshot {
            disclosure: "required".to_owned(),
            visibility: Some("public".to_owned()),
        }),
    );
    assert!(!chat_visible_read_receipt_should_display(
        &store,
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));
}

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
        "did:web:alice.example",
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
    assert!(!op.payload().contains_key("reply_to"));
    assert!(!op.payload().contains_key("thread_id"));
    arkret_sdk::schema::event_payload_validator_catalog()
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
        "did:web:alice.example",
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
        "did:web:alice.example",
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
    arkret_sdk::schema::event_payload_validator_catalog()
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
        "did:web:alice.example",
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
    arkret_sdk::schema::event_payload_validator_catalog()
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
        arkret_sdk::Mention::new(
            crate::mls_api_helpers::principal_core_id("did:web:agent.example").unwrap(),
        )
        .with_agent_selector_metadata(
            crate::mls_api_helpers::principal_core_id("did:web:example.com:users:alice").unwrap(),
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
        "did:web:bob.example",
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
        mention["subject_id"].as_str(),
        Some("ak:did_core:web:agent.example")
    );
    assert_eq!(
        mention["controller_subject_id"].as_str(),
        Some("ak:did_core:web:example.com:users:alice")
    );
    assert_eq!(
        mention["controller_handle_at_time"].as_str(),
        Some("alice:example.com")
    );
    assert_eq!(mention["agent_slug_at_time"].as_str(), Some("summary"));
    assert!(mention.get("target").is_none());
    assert!(!op.payload().contains_key("mentions"));
    arkret_sdk::schema::event_payload_validator_catalog()
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
        "did:web:alice.example",
        "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "ak:message:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
        "reply body",
        &[],
        Some("ak:message:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM"),
    )
    .expect("builds");

    assert_eq!(
        op.payload()["reply_to"].as_str(),
        Some("ak:message:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM")
    );
    assert!(!op.payload().contains_key("thread_id"));
    arkret_sdk::schema::event_payload_validator_catalog()
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
        "did:web:alice.example",
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
        sender: "did:web:example.com:users:bob".to_owned(),
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
        sender: "did:web:example.com:users:bob".to_owned(),
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
        "did:web:alice.example",
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
        "did:web:alice.example",
        &pin_scope,
        target_ref,
    )
    .expect("shared pin remove builds");
    assert_eq!(remove.kind().as_str(), "ak.pin.remove");
    assert_eq!(remove.payload()["target_ref"], target_ref);
    assert!(!remove.payload().contains_key("key"));
    arkret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            add.kind().as_str(),
            &serde_json::to_value(add.payload()).unwrap(),
        )
        .unwrap();
    arkret_sdk::schema::event_payload_validator_catalog()
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
        "did:web:alice.example",
        &pin_scope,
        target_ref,
        "r100",
    )
    .expect("shared pin add builds");

    assert_eq!(add.kind().as_str(), "ak.pin.add");
    assert_eq!(add.payload()["pin_scope"]["kind"], "strand");
    assert_eq!(add.payload()["pin_scope"]["id"], strand_id);
    assert_eq!(add.payload()["target_ref"], target_ref);
    arkret_sdk::schema::event_payload_validator_catalog()
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
        "did:web:alice.example",
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
    let state = ClientLocalState {
        raw_operations: vec![crate::state::RawOperationRecord {
            operation_id: "ak:operation:local".to_owned(),
            realm_id: Some("ak:realm:AjwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "event_id": "ak:event:A4z3EXS8Sy0uqnc2LYMOAl9wdzpzu9JxTnPoGI2aWOf0",
                "kind": "ak.message.create",
                "actor": "did:web:alice.example",
                "body": "local fallback message",
                "strand_id": "ak:strand:A2XzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c",
                "message_id": "chat-msg-local"
            }),
        }],
        ..ClientLocalState::default()
    };

    let messages = chat_messages_from_local_state_with_sidecar(&state, None, None);

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].realm_id,
        "ak:realm:AjwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q"
    );
    assert_eq!(
        messages[0].strand_id,
        "ak:strand:A2XzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c"
    );
    assert_eq!(messages[0].sender, "did:web:alice.example");
    assert_eq!(messages[0].body, "local fallback message");
}

#[test]
fn restores_canonical_actor_id_from_local_raw_operations() {
    let mut state = ClientLocalState {
        raw_operations: vec![crate::state::RawOperationRecord {
            operation_id: "ak:operation:local".to_owned(),
            realm_id: Some("ak:realm:AjwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "event_id": "ak:event:A4z3EXS8Sy0uqnc2LYMOAl9wdzpzu9JxTnPoGI2aWOf0",
                "kind": "ak.message.create",
                "actor_id": "ak:did_core:web:local.host:users:alice",
                "realm_id": "ak:realm:AjwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q",
                "body": "canonical local message",
                "strand_id": "ak:strand:A2XzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c",
                "message_id": "chat-msg-local"
            }),
        }],
        ..ClientLocalState::default()
    };
    sign_chat_fixture(&mut state.raw_operations[0].payload);

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
    let mut create = json!({
        "event_id": "ak:event:AeXSP2D5ttfuvggcWpTJuFUXOvTRhSBXonyaWHskxaqc",
        "kind": "ak.message.create",
        "actor_id": "ak:did_core:web:bob.example",
        "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        "created_at": "2026-05-22T10:00:00.000Z",
        "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
        "message_id": "ak:message:AZhIGxyGMJYSpWhMOugJZewLoNM88CzSBohQQRpKgw1c",
        "body": "hello from bob"
    });
    sign_chat_fixture(&mut create);
    // A non-message timeline event (e.g. a poll close) MUST be ignored.
    let poll = json!({
        "event_id": "ak:event:A-mHyQfTHaRP4hPsEzDRoY0ybwSW0ZIu_kPanXYJ_cJ8",
        "kind": "ak.content.poll.close",
        "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE"
    });

    let records = message_operations_from_events(
        "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &[create.clone(), poll],
    );
    assert_eq!(records.len(), 1, "only the message-create event is folded");
    assert_eq!(
        records[0].operation_id,
        "ak:event:AeXSP2D5ttfuvggcWpTJuFUXOvTRhSBXonyaWHskxaqc"
    );
    assert_eq!(
        records[0].realm_id.as_deref(),
        Some("ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0")
    );
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
fn chat_messages_read_projected_reaction_summary() {
    let mut events = vec![json!({
        "event_id": "ak:event:AeXSP2D5ttfuvggcWpTJuFUXOvTRhSBXonyaWHskxaqc",
        "kind": "ak.message.create",
        "actor_id": "ak:did_core:web:alice.example",
        "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        "created_at": "2026-05-22T10:00:00.000Z",
        "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
        "message_id": "ak:message:AZhIGxyGMJYSpWhMOugJZewLoNM88CzSBohQQRpKgw1c",
        "body": "hello from alice",
        "reaction_summary": {
            "+1": ["did:web:bob.example", "did:web:carol.example"]
        }
    })];
    sign_chat_fixtures(&mut events);

    let messages = chat_messages_from_events_with_sidecar(
        "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &events,
        None,
        None,
    );

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
            "event_id": "ak:event:AeXSP2D5ttfuvggcWpTJuFUXOvTRhSBXonyaWHskxaqc",
            "kind": "ak.message.create",
            "actor_id": "ak:did_core:web:alice.example",
            "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-05-22T10:00:00.000Z",
            "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
            "message_id": "ak:message:AZhIGxyGMJYSpWhMOugJZewLoNM88CzSBohQQRpKgw1c",
            "body": "hello from alice"
        }),
        json!({
            "event_id": "ak:event:AgnQ4vQpIlqkjkQiXR6H-aFpDQtU9QIqZUUOyhD651bQ",
            "kind": "ak.reaction.add",
            "actor_id": "ak:did_core:web:bob.example",
            "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "target_ref": "ak:message:AZhIGxyGMJYSpWhMOugJZewLoNM88CzSBohQQRpKgw1c",
            "key": "+1"
        }),
        json!({
            "event_id": "ak:event:AYAHWeIu5Mo1OonYBugKyH6S4a3sR2DjsutRWGcM-7UY",
            "kind": "ak.reaction.add",
            "actor_id": "ak:did_core:web:carol.example",
            "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "target_ref": "ak:event:AeXSP2D5ttfuvggcWpTJuFUXOvTRhSBXonyaWHskxaqc",
            "key": "+1"
        }),
        json!({
            "event_id": "ak:event:A09fNJ-s5wHOmkdCxh3R42mSETgDQzmk3fMm-gCnHXXw",
            "kind": "ak.reaction.remove",
            "actor_id": "ak:did_core:web:bob.example",
            "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "target_ref": "ak:message:AZhIGxyGMJYSpWhMOugJZewLoNM88CzSBohQQRpKgw1c",
            "key": "+1"
        }),
    ];
    sign_chat_fixtures(&mut events);

    let messages = chat_messages_from_events_with_sidecar(
        "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &events,
        None,
        None,
    );

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].reactions,
        vec![(
            "+1".to_owned(),
            vec!["ak:did_core:web:carol.example".to_owned()]
        )]
    );

    let records = message_operations_from_events(
        "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
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
    assert_eq!(
        restored[0].reactions,
        vec![(
            "+1".to_owned(),
            vec!["ak:did_core:web:carol.example".to_owned()]
        )]
    );
}

#[test]
fn chat_messages_fold_projection_reaction_target_ref_over_envelope_message_id() {
    let mut events = vec![
        json!({
            "event_id": "ak:event:AOOI0zLj06bpcNgRMFMP4JOl0MZWGhQZ5j0hTISOImcg",
            "event_kind": "ak.message.create",
            "actor_id": "ak:did_core:web:alice.example",
            "sender_actor_id": "did:web:alice.example",
            "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-07-08T01:44:39.000Z",
            "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
            "track_name": "discussion",
            "message_id": "ak:message:AIWq0lfBWlF1m50KYI9kpAdern2SCswm8T4YkkWyU17c",
            "payload": {
                "content": {"kind": "ak.content.text", "body": "projection hello"},
                "event_id": "ak:event:AOOI0zLj06bpcNgRMFMP4JOl0MZWGhQZ5j0hTISOImcg",
                "message_id": "ak:message:Al0hjLfzAqduLFaBFHqpVgugJnkcc6jI5BmYnNiihIUY",
                "sender": "did:web:alice.example",
                "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
                "thread_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
                "track_name": "discussion"
            }
        }),
        json!({
            "event_id": "ak:event:AzxKx70X-Q4e1QAhFVEYl97CXxmGGxXPaB1SM9Qi_kO0",
            "event_kind": "ak.reaction.add",
            "actor_id": "ak:did_core:web:bob.example",
            "sender_actor_id": "did:web:bob.example",
            "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-07-08T01:44:43.000Z",
            "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
            "track_name": "discussion",
            "message_id": "ak:message:Al5XZBjhevpsMMLoRMInf3P3NfbsDatZjIxno3fG8-BU",
            "payload": {
                "event_id": "ak:event:AzxKx70X-Q4e1QAhFVEYl97CXxmGGxXPaB1SM9Qi_kO0",
                "key": "+1",
                "sender": "did:web:bob.example",
                "target_ref": "ak:message:Al0hjLfzAqduLFaBFHqpVgugJnkcc6jI5BmYnNiihIUY"
            }
        }),
    ];
    sign_chat_fixtures(&mut events);

    let messages = chat_messages_from_events_with_sidecar(
        "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &events,
        None,
        None,
    );

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].protocol_message_id.as_deref(),
        Some("ak:message:Al0hjLfzAqduLFaBFHqpVgugJnkcc6jI5BmYnNiihIUY")
    );
    assert_eq!(
        messages[0].reactions,
        vec![(
            "+1".to_owned(),
            vec!["ak:did_core:web:bob.example".to_owned()]
        )]
    );

    let records = message_operations_from_events(
        "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &events,
    );
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
        Some("ak:message:Al0hjLfzAqduLFaBFHqpVgugJnkcc6jI5BmYnNiihIUY")
    );
    assert_eq!(
        restored[0].reactions,
        vec![(
            "+1".to_owned(),
            vec!["ak:did_core:web:bob.example".to_owned()]
        )]
    );
}

#[test]
fn chat_messages_fold_canonical_create_with_streamed_reaction_envelope() {
    let mut events = vec![
        json!({
            "event_id": "ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z",
            "kind": "ak.message.create",
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"},
            "actor_id": "ak:did_core:web:alice.example",
            "actor_seq": 1,
            "created_at": "2026-07-08T01:44:39.000Z",
            "hlc": "01970e589d21-0004-a13f9c2e",
            "prev_refs": [],
            "refs": [],
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
            "actor_id": "ak:did_core:web:bob.example",
            "actor_seq": 2,
            "created_at": "2026-07-08T01:44:43.000Z",
            "hlc": "01970e589d22-0004-a13f9c2e",
            "prev_refs": [],
            "refs": [],
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
    assert_eq!(
        messages[0].reactions,
        vec![(
            "👍".to_owned(),
            vec!["ak:did_core:web:bob.example".to_owned()]
        )]
    );
}

#[test]
fn durable_reaction_folds_onto_controller_only_create() {
    let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let message_id = "ak:message:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z";
    let mut events = vec![
        json!({
            "event_id": "ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z",
            "kind": "ak.message.create",
            "realm_id": realm_id,
            "scope_ref": {"kind": "realm", "realm_id": realm_id},
            "actor_id": "ak:did_core:web:alice.example",
            "actor_seq": 1,
            "created_at": "2026-07-08T01:44:39.000Z",
            "hlc": "01970e589d21-0004-a13f9c2e",
            "prev_refs": [],
            "refs": [],
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
            "actor_id": "ak:did_core:web:bob.example",
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
        vec![(
            "👍".to_owned(),
            vec!["ak:did_core:web:bob.example".to_owned()]
        )]
    );
}

#[test]
fn durable_redaction_folds_onto_controller_only_create() {
    let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let message_id = "ak:message:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0";
    let seed = vec![ChatMessage {
        id: "ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z".to_owned(),
        protocol_message_id: Some(message_id.to_owned()),
        realm_id: realm_id.to_owned(),
        strand_id: "ak:strand:AbZt0K_NvenxSDAkOnSDRtorrvUXhGqxSoqT2bFL7m8H".to_owned(),
        sender: "did:web:alice.example".to_owned(),
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
        "actor_id": "ak:did_core:web:alice.example",
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
            "event_id": "ak:event:AuVYtOcVkQu9JLkr0AO35k8Vn36NgL7qI1NnvHuzyDDs",
            "kind": "ak.message.create",
            "actor_id": "ak:did_core:web:bob.example",
            "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-05-22T10:00:00.000Z",
            "payload": {
                "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
                "message_id": "ak:message:AuVYtOcVkQu9JLkr0AO35k8Vn36NgL7qI1NnvHuzyDDs",
                "content": {"kind": "ak.content.text", "body": "v1"}
            }
        }),
        json!({
            "event_id": "ak:event:AugQeQYGPoF9zEbbEIcD8ndn7DUoCaZVaJ9EM6u1rvuo",
            "kind": "ak.message.revise",
            "actor_id": "ak:did_core:web:bob.example",
            "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-05-22T10:01:00.000Z",
            "payload": {
                "message_id": "ak:message:AuVYtOcVkQu9JLkr0AO35k8Vn36NgL7qI1NnvHuzyDDs",
                "content": {"kind": "ak.content.text", "body": "v2"}
            }
        }),
        json!({
            "event_id": "ak:event:AmDOsZS5t1FOYT8QB0mLKRUnOOqWz9iWSIfk6RKZ91T8",
            "kind": "ak.message.revise",
            "actor_id": "ak:did_core:web:bob.example",
            "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-05-22T10:02:00.000Z",
            "payload": {
                "message_id": "ak:message:AuVYtOcVkQu9JLkr0AO35k8Vn36NgL7qI1NnvHuzyDDs",
                "content": {"kind": "ak.content.text", "body": "v3"}
            }
        }),
    ];
    sign_chat_fixtures(&mut events);

    let messages = chat_messages_from_events_with_sidecar(
        "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &events,
        None,
        None,
    );

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].id,
        "ak:event:AuVYtOcVkQu9JLkr0AO35k8Vn36NgL7qI1NnvHuzyDDs"
    );
    assert_eq!(messages[0].body, "v3");
    assert!(messages[0].edited);
    assert_eq!(
        messages[0].revisions,
        vec!["v1".to_owned(), "v2".to_owned()]
    );

    let stale_state = ClientLocalState {
        raw_operations: message_operations_from_events(
            "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
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
        "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
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
fn chat_messages_keep_folded_timeline_revision_over_older_backfill_create() {
    let message_id = "ak:message:AQeShrdBR3zl1gbuH87IF4AakXuLntks0PE5vC00cCYC";
    let reply_to = "ak:message:AXdL6bIGrKOX2V48TJBOTvyoFqW-S0CMHLws0asddnGj";
    let mut events = vec![
        json!({
            "event_id": "ak:event:AadoaZa-0djgJsY3CYuv_X3xsG9VX8MDqugQkXxFqVPK",
            "kind": "ak.message.revise",
            "actor_id": "ak:did_core:web:bob.example",
            "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-07-07T05:58:23.000Z",
            "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
            "target_ref": message_id,
            "content": {"kind": "ak.content.text", "body": "edited body"}
        }),
        json!({
            "event_id": "ak:event:AQeShrdBR3zl1gbuH87IF4AakXuLntks0PE5vC00cCYC",
            "kind": "ak.message.create",
            "actor_id": "ak:did_core:web:bob.example",
            "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-07-07T05:58:22.000Z",
            "payload": {
                "content": {"kind": "ak.content.text", "body": "original body"},
                "reply_to": reply_to,
                "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
                "track_name": "discussion"
            }
        }),
        json!({
            "event_id": "ak:event:AadoaZa-0djgJsY3CYuv_X3xsG9VX8MDqugQkXxFqVPK",
            "kind": "ak.message.revise",
            "actor_id": "ak:did_core:web:bob.example",
            "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-07-07T05:58:23.000Z",
            "payload": {
                "content": {"kind": "ak.content.text", "body": "edited body"},
                "target_ref": message_id
            }
        }),
    ];
    sign_chat_fixtures(&mut events);

    let messages = chat_messages_from_events_with_sidecar(
        "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
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
            "actor_id": "ak:did_core:web:bob.example",
            "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-05-22T10:01:00.000Z",
            "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
            "target_ref": "ak:message:AALmz4zWkDYecrEZnVupSWR2EqdHzYP-bSwUXf4qQ82E",
            "redacted": true,
            "state": "redacted",
            "content": {"kind": "ak.content.text", "body": "[redacted]"}
        }),
        json!({
            "event_id": "ak:event:AJyIPFgvmgij09wqLnZMFu6qyMVd1cGRZ3bq2gvBKEfQ",
            "kind": "ak.message.create",
            "actor_id": "ak:did_core:web:bob.example",
            "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-05-22T10:00:00.000Z",
            "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
            "message_id": "ak:message:AALmz4zWkDYecrEZnVupSWR2EqdHzYP-bSwUXf4qQ82E",
            "redacted": true,
            "state": "redacted",
            "content": {"kind": "ak.content.text", "body": "[redacted]"}
        }),
    ];
    sign_chat_fixtures(&mut events);

    let messages = chat_messages_from_events_with_sidecar(
        "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &events,
        None,
        None,
    );

    assert_eq!(messages.len(), 1);
    assert!(messages[0].redacted);
}

#[test]
fn chat_messages_keep_standalone_server_redacted_revision_tombstone() {
    let events = vec![json!({
        "event_id": "ak:event:Al7Qnsn3l-7MwwweunecsEKX84zMkYIeBOIm-5M-YYkQ",
        "kind": "ak.message.revise",
        "actor_id": "ak:did_core:web:bob.example",
        "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        "created_at": "2026-05-22T10:02:00.000Z",
        "payload": {
            "content": {"kind": "ak.content.text", "body": "[redacted]"},
            "message_id": "ak:message:AALmz4zWkDYecrEZnVupSWR2EqdHzYP-bSwUXf4qQ82E",
            "redacted": true,
            "redacted_at": "2026-05-22T10:05:00.000Z",
            "redaction_ref": "ak:event:ACDsFwzGYsHL_LWmOT3j7ExtCtCKAbGiXAZDrawyms2Y",
            "state": "redacted"
        },
        "unsigned": {
            "local_target_ref": "ak:message:AALmz4zWkDYecrEZnVupSWR2EqdHzYP-bSwUXf4qQ82E",
            "projection_only": true
        },
        "proofs": []
    })];

    let messages = chat_messages_from_events_with_sidecar(
        "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &events,
        None,
        None,
    );

    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].protocol_message_id.as_deref(),
        Some("ak:message:AALmz4zWkDYecrEZnVupSWR2EqdHzYP-bSwUXf4qQ82E")
    );
    assert!(messages[0].redacted);
    assert!(messages[0].body.is_empty());
}

#[test]
fn chat_messages_fold_nested_server_redacted_revision_tombstone_into_root_tombstone() {
    let mut events = vec![
        json!({
            "event_id": "ak:event:AXLf0mAo4UUC50gymplf5Oowi6lfIjnA1pl45rHyZXXs",
            "kind": "ak.message.create",
            "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "actor_id": "ak:did_core:web:bob.example",
            "created_at": "2026-05-22T10:00:00.000Z",
            "payload": {
                "content": {"kind": "ak.content.text", "body": "[redacted]"},
                "event_id": "ak:event:AXLf0mAo4UUC50gymplf5Oowi6lfIjnA1pl45rHyZXXs",
                "message_id": "ak:message:AXLf0mAo4UUC50gymplf5Oowi6lfIjnA1pl45rHyZXXs",
                "redacted": true,
                "redacted_at": "2026-05-22T10:05:00.000Z",
                "redaction_ref": "ak:event:A1Dqt89EJm8Vurg41PAsnseqxyxB0Gg-Xr0WywWjcia0",
                "sender": "did:web:bob.example",
                "state": "redacted",
                "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE"
            },
            "proofs": []
        }),
        json!({
            "event_id": "ak:event:AjU1l-Eisb3OsJErxiFpnMdIrcBcnCih6I8bEfreUYQ4",
            "kind": "ak.message.revise",
            "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "actor_id": "ak:did_core:web:bob.example",
            "created_at": "2026-05-22T10:01:00.000Z",
            "payload": {
                "content": {"kind": "ak.content.text", "body": "[redacted]"},
                "event_id": "ak:event:AjU1l-Eisb3OsJErxiFpnMdIrcBcnCih6I8bEfreUYQ4",
                "redacted": true,
                "redacted_at": "2026-05-22T10:05:00.000Z",
                "redaction_ref": "ak:event:A1Dqt89EJm8Vurg41PAsnseqxyxB0Gg-Xr0WywWjcia0",
                "sender": "did:web:bob.example",
                "state": "redacted",
                "message_id": "ak:message:AXLf0mAo4UUC50gymplf5Oowi6lfIjnA1pl45rHyZXXs"
            },
            "proofs": []
        }),
    ];
    sign_chat_fixtures(&mut events);

    let messages = chat_messages_from_events_with_sidecar(
        "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
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
            realm_id: "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0".to_owned(),
            id: id.to_owned(),
            protocol_message_id: Some(protocol_message_id.to_owned()),
            sender: "did:web:bob.example".to_owned(),
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
            pending: false,
            failed: false,
            error: None,
            mentions: Vec::new(),
            crypto_state: MessageCryptoState::Plaintext,
        }
    }

    let protocol_message_id = "ak:message:A3VgsB123jP90mQo21keg3CLCveTDRLikepykbzkqVDU";
    let mut target = vec![
        redacted_message(
            "ak:event:AcKQoR8zOkA_YLRPM8kfj-LWD-gFyGj0gDzDi1yR8__w",
            protocol_message_id,
        ),
        redacted_message(
            "ak:event:AJIef_emAh7eYAOuF7eGO1bNoy3aKoOtR486JTWV0mwU",
            protocol_message_id,
        ),
        ChatMessage {
            body: "unrelated".to_owned(),
            redacted: false,
            protocol_message_id: Some(
                "ak:message:A8a_riy5QTAQw2ZF0lV4Wr_lyFIe2yzXKQYapE970EXw".to_owned(),
            ),
            id: "ak:event:A0KTSEncSq-7S2g7j9s8ssEEgqbX4On6J9NtKdAwE9rI".to_owned(),
            ..redacted_message(
                "ak:event:A0KTSEncSq-7S2g7j9s8ssEEgqbX4On6J9NtKdAwE9rI",
                "ak:message:A8a_riy5QTAQw2ZF0lV4Wr_lyFIe2yzXKQYapE970EXw",
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
            .any(|message| message.id == "ak:event:A0KTSEncSq-7S2g7j9s8ssEEgqbX4On6J9NtKdAwE9rI")
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
            realm_id: "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0".to_owned(),
            id: id.to_owned(),
            protocol_message_id: Some(protocol_message_id.to_owned()),
            sender: "did:web:bob.example".to_owned(),
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
            pending: false,
            failed: false,
            error: None,
            mentions: Vec::new(),
            crypto_state: MessageCryptoState::Plaintext,
        }
    }

    let protocol_message_id = "ak:message:AFrxbbWNTU3fu27uUUMC3ilKugGpnApLyJXvm-E-33Mo";
    let mut target = vec![message(
        "ak:event:AnDTUwNSETOJ-pBxghvljssZF9_39FJn1yECyAVFAlFU",
        protocol_message_id,
        "edited body",
        "2026-07-07T06:19:22.000Z",
    )];
    target[0].edited = true;

    let mut incoming = message(
        "ak:event:A7K5Uaew7bX6Q59MX37cd5ChptN8Mn4AORWZkldj0FBk",
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
    assert_eq!(
        target[0].id,
        "ak:event:AnDTUwNSETOJ-pBxghvljssZF9_39FJn1yECyAVFAlFU"
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
                "did:web:bob.example".to_owned(),
                "did:web:carol.example".to_owned()
            ],
        )]
    );
}

#[test]
fn durable_echo_settles_newer_optimistic_message_by_protocol_id() {
    let mut optimistic = sidecar_projection_message(
        "ak:message:Ams1BtISTcaHSjyArAO3RssCwK-vFi70Bs1FzWVrXhck",
        "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
        "hello",
    );
    optimistic.protocol_message_id =
        Some("ak:message:Ams1BtISTcaHSjyArAO3RssCwK-vFi70Bs1FzWVrXhck".to_owned());
    optimistic.created_at = Some(chrono::Utc::now());
    optimistic.pending = true;

    let mut durable = sidecar_projection_message(
        "ak:event:ApfLd21JpG9eFxiZSOjnlVNQnQV8Bu7OP_TAtMdAAa30",
        "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
        "hello",
    );
    durable.protocol_message_id =
        Some("ak:message:Ams1BtISTcaHSjyArAO3RssCwK-vFi70Bs1FzWVrXhck".to_owned());
    durable.created_at = None;

    merge_duplicate_create_message(&mut optimistic, durable);

    assert_eq!(
        optimistic.id,
        "ak:message:Ams1BtISTcaHSjyArAO3RssCwK-vFi70Bs1FzWVrXhck"
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
        "event_id": "ak:event:A7K5Uaew7bX6Q59MX37cd5ChptN8Mn4AORWZkldj0FBk",
        "kind": "ak.message.create",
        "actor_id": "ak:did_core:web:bob.example",
        "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        "created_at": "2026-05-22T10:00:00.000Z",
        "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
        "message_id": "ak:message:AFrxbbWNTU3fu27uUUMC3ilKugGpnApLyJXvm-E-33Mo",
        "body": "secret"
    });
    let tombstone = json!({
        "event_id": "ak:event:A7K5Uaew7bX6Q59MX37cd5ChptN8Mn4AORWZkldj0FBk",
        "kind": "ak.message.create",
        "actor_id": "ak:did_core:web:bob.example",
        "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        "created_at": "2026-05-22T10:05:00.000Z",
        "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
        "message_id": "ak:message:AFrxbbWNTU3fu27uUUMC3ilKugGpnApLyJXvm-E-33Mo",
        "redacted": true
    });

    let create_record = message_operations_from_events(
        "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &[create],
    );
    let tombstone_record = message_operations_from_events(
        "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &[tombstone],
    );
    assert_eq!(
        create_record[0].operation_id,
        tombstone_record[0].operation_id
    );
}

#[test]
fn message_operations_fold_independent_redaction_event_by_message_id() {
    let mut create = json!({
        "event_id": "ak:event:AuVYtOcVkQu9JLkr0AO35k8Vn36NgL7qI1NnvHuzyDDs",
        "kind": "ak.message.create",
        "actor_id": "ak:did_core:web:bob.example",
        "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        "created_at": "2026-05-22T10:00:00.000Z",
        "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
        "message_id": "ak:message:AuVYtOcVkQu9JLkr0AO35k8Vn36NgL7qI1NnvHuzyDDs",
        "body": "secret"
    });
    sign_chat_fixture(&mut create);
    let mut redaction = json!({
        "event_id": "ak:event:AtY-hYO7pukUvpVZYBYuADSkUgaU1o6T5TbYmPtzUnco",
        "kind": "ak.message.redact",
        "actor_id": "ak:did_core:web:bob.example",
        "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        "created_at": "2026-05-22T10:05:00.000Z",
        "payload": {
            "event_id": "ak:event:AtY-hYO7pukUvpVZYBYuADSkUgaU1o6T5TbYmPtzUnco",
            "message_id": "ak:message:AuVYtOcVkQu9JLkr0AO35k8Vn36NgL7qI1NnvHuzyDDs",
            "reason": "user requested tombstone"
        }
    });
    sign_chat_fixture(&mut redaction);

    for events in [
        vec![create.clone(), redaction.clone()],
        vec![redaction, create],
    ] {
        let records = message_operations_from_events(
            "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            &events,
        );
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
    let strand_id = "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE";
    let pin_scope = SharedPinScope::strand(strand_id);
    let target_ref = "ak:message:Aj8ObsRsspa-eB4BB9XHU491RECO-qv_y2FbDrDKRo74";
    let pin = json!({
        "event_id": "ak:event:At7uZHFkaOZeWWKBxVQkHwbJkLtnGHpMCcZYcFcswPgc",
        "event_kind": "ak.pin.add",
        "actor_id": "ak:did_core:web:mei.example",
        "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        "created_at": "2026-05-22T10:10:00.000Z",
        "payload": {
            "pin_scope": {"kind": "strand", "id": strand_id},
            "target_ref": target_ref,
            "rank": "r001"
        }
    });

    let records = message_operations_from_events(
        "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
        &[pin],
    );
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].operation_id,
        "ak:event:At7uZHFkaOZeWWKBxVQkHwbJkLtnGHpMCcZYcFcswPgc"
    );
    assert_eq!(
        records[0].realm_id.as_deref(),
        Some("ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0")
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
fn local_redaction_tombstone_replaces_raw_message_without_plaintext() {
    let redacted_at = chrono::DateTime::parse_from_rfc3339("2026-05-22T10:05:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let message = ChatMessage {
        realm_id: "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0".to_owned(),
        id: "ak:event:AuVYtOcVkQu9JLkr0AO35k8Vn36NgL7qI1NnvHuzyDDs".to_owned(),
        protocol_message_id: Some(
            "ak:message:Asg8IZtPYZi06QwoJAIWUIU5xUWxDRtHCQPTUuSSipb8".to_owned(),
        ),
        sender: "did:web:bob.example".to_owned(),
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
        pending: false,
        failed: false,
        error: None,
        mentions: Vec::new(),
        crypto_state: MessageCryptoState::Plaintext,
    };

    let tombstone = local_redaction_tombstone_for_message(
        &message,
        redacted_at,
        Some("ak:event:A-RSupDyayuw4R7tIwZPpZWnF36wsoZuXYPDzQJ-jmhk"),
    );
    assert_eq!(tombstone["event_id"], message.id);
    assert_eq!(
        tombstone["message_id"],
        "ak:message:Asg8IZtPYZi06QwoJAIWUIU5xUWxDRtHCQPTUuSSipb8"
    );
    assert_eq!(tombstone["redacted"], true);
    assert_eq!(tombstone["state"], "redacted");
    assert_eq!(
        tombstone["redaction_ref"],
        "ak:event:A-RSupDyayuw4R7tIwZPpZWnF36wsoZuXYPDzQJ-jmhk"
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
    let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let appellant = "ak:did_core:web:appellant.example";
    let events = vec![
        json!({
            "event_id": "ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z",
            "kind": "ak.moderation.decision",
            "realm_id": realm_id,
            "body": {
                "target_ref": "ak:message:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0",
                "decision": "quarantine",
                "issuer": "ak:did_core:web:moderator.example",
                "request_canonical_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            }
        }),
        json!({
            "kind": "ak.moderation.appeal.submit",
            "event_id": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "realm_id": realm_id,
            "body": {
                "decision_ref": "ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z",
                "target_ref": "ak:message:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0",
                "appellant": appellant,
                "realm_id": realm_id,
                "reason_text_ref": "ak:text:appeal-reason",
                "created_at": "2026-07-19T00:00:01.000Z"
            }
        }),
        json!({
            "kind": "ak.moderation.appeal.decision",
            "realm_id": realm_id,
            "body": {
                "appeal_id": "ak:appeal:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "realm_id": realm_id,
                "reviewer": "ak:did_core:web:reviewer.example",
                "decision": "uphold",
                "reason_text_ref": "ak:text:decision-reason",
                "decided_at": "2026-07-19T00:00:02.000Z"
            }
        }),
    ];

    let prompts = moderation_appeal_prompts_from_local_records(realm_id, &events, appellant);

    assert_eq!(prompts.len(), 1);
    assert_eq!(
        prompts[0].decision_ref,
        "ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z"
    );
    assert_eq!(
        prompts[0].state,
        AppealState::Decided {
            decision: arkret_sdk::AppealDecision::Uphold,
        }
    );

    let lifted = vec![
        events[0].clone(),
        json!({
            "kind": "ak.moderation.decision.lift",
            "realm_id": realm_id,
            "body": {
                "target_ref": "ak:message:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0",
                "decision_ref": "ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z"
            }
        }),
    ];
    assert!(moderation_appeal_prompts_from_local_records(realm_id, &lifted, appellant).is_empty());
}

#[test]
fn moderation_appeal_prompts_read_control_plane_sync_state() {
    let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let mut event = arkret_wire::test_support::raw_event(
        arkret_sdk::EventKind::ModerationDecision.as_str(),
        arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(realm_id).unwrap(),
        },
        arkret_sdk::DidCoreId::new("ak:did_core:web:moderator.example").unwrap(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        1,
        arkret_sdk::Hlc::new("019f73a34c00-0000-12345678").unwrap(),
        json!({
            "target_ref": "ak:message:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0",
            "decision": "quarantine",
            "issuer": "ak:did_core:web:moderator.example",
            "request_canonical_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        }),
    )
    .unwrap();
    event.event_id =
        arkret_sdk::EventId::new("ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z").unwrap();
    let mut realms = std::collections::BTreeMap::new();
    realms.insert(
        realm_id.to_owned(),
        json!({
            "timeline": { "events": [] },
            "state": {
                "events": [serde_json::to_value(event).unwrap()]
            }
        }),
    );

    let prompts = moderation_appeal_prompts_from_sync_realms(&realms, "did:web:appellant.example");

    assert_eq!(prompts.len(), 1);
    assert_eq!(
        prompts[0].decision_ref,
        "ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z"
    );
}

#[test]
fn moderation_appeal_prompts_survive_sdk_event_round_trip() {
    let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let event: arkret_sdk::Event = serde_json::from_value(json!({
        "event_id": "ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z",
        "kind": "ak.moderation.decision",
        "realm_id": realm_id,
        "scope_ref": {"kind": "realm", "realm_id": realm_id},
        "actor_id": "ak:did_core:web:moderator.example",
        "principal_server_id": "ak:did_core:web:principal.example",
        "actor_seq": 1,
        "created_at": "2026-07-19T00:00:00.000Z",
        "hlc": "019f73a34c00-0000-12345678",
        "prev_refs": [],
        "refs": [],
        "requirements": { "schema": ["ak.schema.event_payload.v1"] },
        "payload": {
            "target_ref": "ak:message:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0",
            "decision": "quarantine",
            "issuer": "ak:did_core:web:moderator.example",
            "reason_code": "abuse_review",
            "request_canonical_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        },
        "proofs": []
    }))
    .unwrap();
    let prompts =
        moderation_appeal_prompts_from_sdk_events(realm_id, &[event], "did:web:appellant.example");

    assert_eq!(prompts.len(), 1);
}

#[test]
fn timeline_projection_key_tracks_moderation_prompt_lifecycle() {
    let prompt = ModerationAppealPrompt {
        realm_id: "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
        decision_ref: "ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z".to_owned(),
        target_ref: "ak:message:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0".to_owned(),
        state: AppealState::None,
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
    submitted.state = AppealState::Submitted;
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
    let sidecar_content = serde_json::to_string(
        &arkret_sdk::ContentBlock::markdown_text("secret discussion body")
            .to_value()
            .unwrap(),
    )
    .unwrap();
    store.save_private_plaintext(
        "ak:realm:AjwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q",
        "ak:strand:A2XzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c",
        "message:chat-msg-enc",
        &sidecar_content,
    );

    let mut state = ClientLocalState {
        raw_operations: vec![crate::state::RawOperationRecord {
            operation_id: "ak:operation:enc".to_owned(),
            realm_id: Some("ak:realm:AjwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q".to_owned()),
            received_at: chrono::Utc::now(),
            // Encrypted stub: identity only, NO plaintext body.
            payload: json!({
                "event_id": "ak:event:AwF-oOhhx26_6pizrJdZKnGd4znSSuoeNZmFDAJWlc70",
                "kind": "ak.message.create",
                "actor_id": "ak:did_core:web:alice.example",
                "realm_id": "ak:realm:AjwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q",
                "strand_id": "ak:strand:A2XzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c",
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
    assert_eq!(
        without_sidecar[0].strand_id,
        "ak:strand:A2XzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c"
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
        "ak:strand:A2XzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c"
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
fn rebuild_restores_author_body_from_event_derived_sidecar_key() {
    // The encrypted send path keys the author plaintext sidecar by the
    // protocol message id derived from the accepted event id
    // (`MessageId::from_event_id` — the same id the read-side projection
    // derives first). A record written under that convention must restore
    // the body even though the raw_operation's `message_id` never wins
    // candidate selection.
    let temp = std::env::temp_dir().join(format!("inkson-derived-sidecar-key-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    let event_id = "ak:event:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu";
    let protocol_message_id = arkret_sdk::MessageId::from_event_id(
        &arkret_sdk::EventId::new(event_id.to_owned()).expect("fixture event id"),
    )
    .as_str()
    .to_owned();
    store.save_private_plaintext(
        "ak:realm:AjwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q",
        "ak:strand:A2XzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c",
        &format!("message:{protocol_message_id}"),
        "secret discussion body",
    );

    let mut state = ClientLocalState {
        raw_operations: vec![crate::state::RawOperationRecord {
            operation_id: "ak:operation:enc-derived".to_owned(),
            realm_id: Some("ak:realm:AjwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q".to_owned()),
            received_at: chrono::Utc::now(),
            payload: json!({
                "event_id": event_id,
                "kind": "ak.message.create",
                "actor_id": "ak:did_core:web:alice.example",
                "realm_id": "ak:realm:AjwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q",
                "strand_id": "ak:strand:A2XzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c",
                "message_id": protocol_message_id,
                "encrypted_content": true,
                "status": "accepted"
            }),
        }],
        ..ClientLocalState::default()
    };
    sign_chat_fixture(&mut state.raw_operations[0].payload);

    let restored = chat_messages_from_local_state_with_sidecar(&state, Some(&store), None);
    assert_eq!(restored.len(), 1);
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
    let realm = "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h";
    let strand = "ak:strand:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934";
    let message_id = "ak:message:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu";
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
        "event_id": "ak:event:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu",
        "kind": "ak.message.create",
        "actor_id": "ak:did_core:web:alice.example",
        "realm_id": realm,
        "strand_id": strand,
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
    let wire_poll_id = "ak:message:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu";
    let mut optimistic =
        crate::messaging::polls::PollCard::from_draft("poll-local".to_owned(), &draft);
    optimistic.poll_id = wire_poll_id.to_owned();
    let mut projected = crate::messaging::polls::PollCard::from_draft(
        "ak:event:ApfLd21JpG9eFxiZSOjnlVNQnQV8Bu7OP_TAtMdAAa30".to_owned(),
        &draft,
    );
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
    let realm = "ak:realm:AjwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q";
    let strand = "ak:strand:A2XzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c";
    let message_id = "ak:message:A2YcbgQPjPWiFZOW87QxvndGtWcImO9Xf2-TcOjH1pXs";
    let mut messages = vec![ChatMessage {
        realm_id: realm.to_owned(),
        id: "ak:event:AJhsY0DZJGk1qN28pQapwgLRRgx7kyis3JdX2xGL1Cj8".to_owned(),
        protocol_message_id: Some(message_id.to_owned()),
        sender: "did:web:alice.example".to_owned(),
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
fn late_recovery_guards_block_sidecar_plaintext_before_timeline_entry() {
    let temp = std::env::temp_dir().join(format!("inkson-late-recovery-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    let realm = "ak:realm:AjwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q";
    let strand = "ak:strand:A2XzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c";
    let message_id = "ak:message:A2bMpjWQ3C_PCkkoYC30GDh4ogDBgC5-GGJ1v0zt9VKa";
    store.save_private_plaintext(
        realm,
        strand,
        &format!("message:{message_id}"),
        "late plaintext",
    );
    let mut rejected = json!({
        "event_id": "ak:event:A4BWEYesKK6NG4kEzOZXc7FlBfXuJdaVxsjAp4V6hygg",
        "kind": "ak.message.create",
        "actor_id": "ak:did_core:web:alice.example",
        "realm_id": realm,
        "strand_id": strand,
        "message_id": message_id,
        "decryption_state": "decryption_failed",
        "late_recovery": {
            "receiver_visible_at_t0": false
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
    let realm = "ak:realm:AjwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q";
    let strand = "ak:strand:A2XzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c";
    let message_id = "ak:message:AS_yTKQy1F_tu5CuneCbCvtUhx-TRFeH5RVSYYeWMGeA";
    store.save_private_plaintext(
        realm,
        strand,
        &format!("message:{message_id}"),
        "late plaintext",
    );
    let mut accepted = json!({
        "event_id": "ak:event:AxgU4syRvuaha7eYDoK-By_Sl3Ngv-6Q0_WiiElGwB24",
        "kind": "ak.message.create",
        "actor_id": "ak:did_core:web:alice.example",
        "realm_id": realm,
        "strand_id": strand,
        "message_id": message_id,
        "decryption_state": "decryption_failed",
        "late_recovery": {
            "receiver_visible_at_t0": true
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
fn treats_core_id_and_full_did_spellings_of_same_principal_as_own_sender() {
    // The synced envelope's `actor_id` (core id) and `account.did` (full DID)
    // can spell the same principal differently; both directions must count as
    // own so the author's echo stays on the author's side.
    assert!(is_own_message_sender(
        "ak:did_core:web:alice.example",
        "did:web:alice.example"
    ));
    assert!(is_own_message_sender(
        "did:web:alice.example",
        "ak:did_core:web:alice.example"
    ));
    assert!(!is_own_message_sender(
        "ak:did_core:web:bob.example",
        "did:web:alice.example"
    ));
    assert!(!is_own_message_sender("", "did:web:alice.example"));
}

#[test]
fn treats_canonical_principal_id_as_own_sender() {
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
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
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
                "actor_id": "ak:did_core:web:example.com:users:bob",
                "handle": "bob:example.com"
            }
        ]
    });

    let temp = std::env::temp_dir().join(format!("inkson-chat-roster-{}", uuid_v7()));
    let store = LocalStateStore::with_path(temp);
    let participants = space_participants(
        Some(&projection),
        &store,
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        "did:web:alice.example",
    );
    let bob = participants
        .iter()
        .find(|participant| participant.did == "ak:did_core:web:example.com:users:bob")
        .unwrap();

    assert!(mention_label_for_participant(bob).is_none());
}

#[test]
fn extracts_participant_handle_label_from_inline_handle_claims() {
    let projection = json!({
        "members": [
            {
                "actor_id": "ak:did_core:web:bob.example",
                "subject_id": "ak:did_core:web:bob.example",
                "handle_claims": [{
                    "schema": "ak.schema.handle_claim.v1",
                    "handle": "bob:local.host",
                    "subject": "ak:did_core:web:bob.example",
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
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        "did:web:alice.example",
    );
    let bob = participants
        .iter()
        .find(|participant| participant.did == "ak:did_core:web:bob.example")
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
fn agent_metadata_from_mentions_recovers_selector_audit_metadata() {
    let messages = vec![ChatMessage {
        realm_id: "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE".to_owned(),
        id: "ak:event:A42FkwFdQPw7aC_yPcdlVU5ZjKLAnFCbmrXTVRJTNhRc".to_owned(),
        protocol_message_id: Some(
            "ak:message:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5".to_owned(),
        ),
        sender: "did:web:example.com:users:bob".to_owned(),
        executed_by: None,
        body: "@alice:example.com/summary".to_owned(),
        content_format: None,
        timestamp: "10:00".to_owned(),
        created_at: None,
        strand_id: "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q".to_owned(),
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
                crate::mls_api_helpers::principal_core_id("did:web:agents.example:summary")
                    .unwrap(),
            )
            .with_display_name_at_time("Summary Assistant")
            .with_agent_selector_metadata(
                crate::mls_api_helpers::principal_core_id("did:web:example.com:users:alice")
                    .unwrap(),
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
        .get("ak:did_core:web:agents.example:summary")
        .expect("agent metadata");
    assert_eq!(
        summary.controller_id,
        "ak:did_core:web:example.com:users:alice"
    );
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
        crate::mls_api_helpers::principal_core_id("did:web:agents.example:summary").unwrap(),
    )
    .with_agent_selector_metadata(
        crate::mls_api_helpers::principal_core_id(controller).unwrap(),
        arkret_sdk::Handle::parse("alice:example.com").unwrap(),
        "summary",
    );
    let other_agent = arkret_sdk::Mention::new(
        crate::mls_api_helpers::principal_core_id("did:web:agents.example:review").unwrap(),
    )
    .with_agent_selector_metadata(
        crate::mls_api_helpers::principal_core_id("did:web:example.com:users:bob").unwrap(),
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

    assert_eq!(ids, vec!["ak:did_core:web:agents.example:summary"]);
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

    assert_eq!(ids, vec!["ak:did_core:web:agents.example:summary"]);
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
fn direct_chat_disables_mention_ui_triggers_and_send_metadata() {
    let principal_id = "did:web:example.com:users:alice";
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
            principal_id,
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
            principal_id,
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
        AgentParticipationEntry, ParticipationBits, ParticipationNextReplaceInput,
        ParticipationScope,
    };

    let realm = "ak:realm:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j";
    let circle = "ak:circle:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let realm_entry = AgentParticipationEntry {
        scope: ParticipationScope::Realm {
            realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
        },
        selection: ParticipationBits::ALL,
        version: 1,
        next_replace_input: ParticipationNextReplaceInput {
            expected_version: 1,
        },
    };
    let circle_entry = AgentParticipationEntry {
        scope: ParticipationScope::Circle {
            realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
            circle_id: arkret_sdk::CircleId::new(circle.to_owned()).unwrap(),
        },
        selection: ParticipationBits::NONE,
        version: 1,
        next_replace_input: ParticipationNextReplaceInput {
            expected_version: 1,
        },
    };

    assert!(participation_allows_public_reply(
        std::slice::from_ref(&realm_entry),
        realm,
        None,
        "ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL",
    ));
    assert!(!participation_allows_public_reply(
        &[realm_entry, circle_entry],
        realm,
        Some(circle),
        "ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL",
    ));
}

#[test]
fn participation_visibility_can_target_an_authoritative_discussion_strand() {
    use arkret_models_collaboration::governance::agent_participation::{
        AgentParticipationEntry, ParticipationBits, ParticipationNextReplaceInput,
        ParticipationScope,
    };

    let realm = "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo";
    let strand = "ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL".to_owned();
    let entry = AgentParticipationEntry {
        scope: ParticipationScope::Strand {
            realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
            strand_id: arkret_sdk::StrandId::new(strand.clone()).unwrap(),
        },
        selection: ParticipationBits::ALL,
        version: 1,
        next_replace_input: ParticipationNextReplaceInput {
            expected_version: 1,
        },
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
        AgentParticipationEntry, ParticipationBits, ParticipationNextReplaceInput,
        ParticipationScope,
    };

    let realm = "ak:realm:AUuXpUO-yBwwyCNB7AS1IIm5_sgsxyEsG7PBmmkXdFog";
    let mention_only = ParticipationBits {
        reply_message: false,
        reaction_add: false,
        reaction_remove: false,
        accept_third_party_mention: true,
        act_on_behalf: false,
    };
    let entry = AgentParticipationEntry {
        scope: ParticipationScope::Realm {
            realm_id: arkret_sdk::RealmId::new(realm.to_owned()).unwrap(),
        },
        selection: mention_only,
        version: 1,
        next_replace_input: ParticipationNextReplaceInput {
            expected_version: 1,
        },
    };

    assert!(!participation_allows_public_reply(
        std::slice::from_ref(&entry),
        realm,
        None,
        "ak:strand:AYdzR-cxE5CaMt7Xeab7lJ6oTMVcXRDFIfPqcXOahgQ4",
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
fn direct_agent_peer_visibility_does_not_require_reply_participation() {
    let agent = "did:web:example.com:agents:aa";
    let projected_members = std::collections::BTreeSet::from([agent.to_owned()]);
    assert!(direct_agent_is_conversation_peer(
        agent,
        "",
        &projected_members
    ));
    assert!(direct_agent_is_conversation_peer(
        agent,
        agent,
        &std::collections::BTreeSet::new()
    ));
    assert!(!direct_agent_is_conversation_peer(
        "did:web:example.com:agents:other",
        agent,
        &projected_members
    ));
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
    assert_eq!(
        mention.subject_id.as_str(),
        "ak:did_core:web:example.com:users:alice"
    );
    assert_eq!(mention.mention_text_original.as_deref(), Some("@me"));

    let typed_mentions = composer_mention_nodes(true, "ping @me", &[], &participant.did);
    let typed_mention = typed_mentions[0]
        .as_mention()
        .expect("typed structured self mention");
    assert_eq!(
        typed_mention.subject_id.as_str(),
        "ak:did_core:web:example.com:users:alice"
    );
    assert_eq!(typed_mention.mention_text_original.as_deref(), Some("@me"));

    assert!(composer_mention_nodes(true, "ask @me/summary", &[], &participant.did).is_empty());
}

#[test]
fn resolved_owned_agent_chip_suppresses_duplicate_directory_lookup() {
    let controller = "did:web:example.com:users:alice";
    let mention = arkret_sdk::Mention::new(
        crate::mls_api_helpers::principal_core_id("did:web:agents.example:summary").unwrap(),
    )
    .with_agent_selector_metadata(
        crate::mls_api_helpers::principal_core_id(controller).unwrap(),
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
    let principal_id = "did:web:example.com:users:alice";
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
        principal_id,
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
        principal_id,
        &std::collections::BTreeSet::new(),
        Some("summary"),
        Some("alice:example.com"),
    )
    .expect("explicit owned-agent mention");
    assert_eq!(clicked_agent.insert_label(), "me/summary");
    assert!(clicked_agent.is_agent);
    assert_eq!(clicked_agent.controller_subject_id, principal_id);
    assert_eq!(clicked_agent.agent_slug_at_time, "summary");

    let before_handle_load = owned_agent_mention_candidate(
        &unannotated_owned_agent.did,
        Some("summary"),
        principal_id,
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
            principal_id,
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
    let principal_id = own_controller.did.as_str();
    let visible = std::collections::BTreeSet::new();

    assert!(agent_candidate_is_visible(
        &own_agent,
        &visible,
        principal_id
    ));
    assert!(!agent_candidate_is_visible(
        &remote_agent,
        &visible,
        principal_id
    ));
    assert!(agent_candidate_is_visible(
        &remote_agent,
        &std::collections::BTreeSet::from([remote_agent.did.clone()]),
        principal_id
    ));
    let sidecar_mentions = sidecar_owned_agent_participants(
        &[
            own_controller.clone(),
            own_agent.clone(),
            remote_agent.clone(),
        ],
        principal_id,
    );
    assert_eq!(sidecar_mentions, vec![own_agent.clone()]);
    assert_eq!(
        readable_participation_agent_ids(&[own_agent.clone(), remote_agent], principal_id),
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
        "ak:did_core:web:bob.example",
        Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE".to_owned()),
        None,
        Some("bob:local.host".to_owned()),
        1,
        None,
        None,
    );
    let projection = json!({"members": [{
        "actor_id": "ak:did_core:web:bob.example"
    }]});
    let participants = space_participants(
        Some(&projection),
        &store,
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        "did:web:alice.example",
    );
    let bob = participants
        .iter()
        .find(|participant| participant.did == "ak:did_core:web:bob.example")
        .expect("bob participant");
    let candidate = mention_candidate_for_participant(bob, &participants, "did:web:alice.example")
        .expect("member mention candidate");
    assert_eq!(candidate.did, "ak:did_core:web:bob.example");
    assert_eq!(candidate.display_name, "bob:local.host");
    assert_eq!(candidate.insert_label(), "bob:local.host");
    assert_eq!(candidate.subtitle, "");
}

#[test]
fn late_join_discussion_sender_resolves_cached_member_handle() {
    let sender = "ak:did_core:web:history.example:alice";
    let realm = "ak:realm:AhbOTVxMlBQEJeDfw_EHOeGGCT2uJ17cMT4QctC7CaFI";
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
    let participants =
        space_participants(Some(&projection), &store, realm, "did:web:reader.example");

    assert_eq!(
        sender_display_label(
            sender,
            "did:web:reader.example",
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
        "event_id": "ak:event:ACN6-zee0KV01VOfolkRd2zFaZq0QslDtjPt55WGqTpk",
        "kind": "ak.strand.create",
        "realm_id": "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        "strand_id": "ak:strand:Ac19GaGmchhLqPeXsofsVdQCPnHo5URGMEFiQj6tRLz0",
        "title": "Ops discussion",
        "category": "support",
        "summary": "Operations support",
        "strand": {
            "id": "ak:strand:Ac19GaGmchhLqPeXsofsVdQCPnHo5URGMEFiQj6tRLz0",
            "title": "Ops discussion",
            "tracks": {
                "discussion": {"profile": "discussion"}
            }
        }
    });

    let channel = channel_from_strand_event(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        &event,
    )
    .unwrap();

    assert_eq!(
        channel.strand_id,
        "ak:strand:Ac19GaGmchhLqPeXsofsVdQCPnHo5URGMEFiQj6tRLz0"
    );
    assert_eq!(channel.name, "Ops discussion");
    assert_eq!(channel.category, "support");
    assert_eq!(channel.kind, "discussion");
    assert_eq!(channel.topic.as_deref(), Some("Operations support"));
    assert!(!channel.is_default);
    assert!(!channel.is_private_sidecar);
}

#[test]
fn sidecar_strand_title_reads_canonical_metadata_object() {
    let strand_id = "ak:strand:ASy992JMe_xzh5pluAqo5YuyCnAfDdFni4lmeHQldlUM";
    let projection = json!({
        "strand_id": strand_id,
        "metadata": {
            "title": "AI sidecar",
            "summary": "Controller-private AI context"
        },
        "tracks": { "discussion": { "enabled": true } }
    });
    let projected =
        channel_from_strand_projection(&projection, false).expect("discussion projection");
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
    let projected = channel_from_strand_event(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        &event,
    )
    .expect("discussion event");
    assert_eq!(projected.name, "AI sidecar");
}

#[test]
fn channel_from_strand_event_never_infers_private_sidecar_identity() {
    let event = json!({
        "event_id": "ak:event:AWKTKW6JVP47hz_MHIT7bR8pFouEmtlyLzIyaqjy3Bjw",
        "kind": "ak.strand.create",
        "realm_id": "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        "object": {
            "id": "ak:strand:AkUVEiKlUkt3ZQkgRtsNooAKfHAnagj6Vjh_Xb-Nj5Bo",
            "metadata": {
                "title": "AI sidecar",
                "fields": { "client_private_hint": true }
            },
            "tracks": {
                "discussion": {"enabled": true, "is_primary": true}
            }
        }
    });

    let channel = channel_from_strand_event(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        &event,
    )
    .unwrap();

    assert_eq!(
        channel.strand_id,
        "ak:strand:AkUVEiKlUkt3ZQkgRtsNooAKfHAnagj6Vjh_Xb-Nj5Bo"
    );
    assert!(!channel.is_private_sidecar);
}

#[test]
fn channel_from_strand_event_ignores_non_discussion_strands() {
    let event = json!({
        "event_id": "ak:event:ACN6-zee0KV01VOfolkRd2zFaZq0QslDtjPt55WGqTpk",
        "kind": "ak.strand.create",
        "realm_id": "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        "strand_id": "ak:strand:AwoWa5E6h1_MkJ9iJso4SrkR-9rZJi2ynkhMyYA06pwg",
        "title": "Doc strand",
        "strand": {
            "id": "ak:strand:AwoWa5E6h1_MkJ9iJso4SrkR-9rZJi2ynkhMyYA06pwg",
            "title": "Doc strand",
            "tracks": {
                "document": {"profile": "document"}
            }
        }
    });

    assert!(
        channel_from_strand_event(
            "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
            &event
        )
        .is_none()
    );
}

#[test]
fn default_discussion_channel_uses_realm_default_strand_projection() {
    let body = json!({
        "summary": {
            "title": "Demo Realm",
            "strand": {
                "strand_id": "ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL",
                "title": "General",
                "summary": "Realm-wide conversation",
                "tracks": {
                    "discussion": {"enabled": true},
                    "synthesis": {"enabled": true}
                }
            }
        }
    });

    let channel = default_discussion_channel(Some(&body))
        .expect("accepted projection exposes its default Strand");

    assert_eq!(
        channel.strand_id,
        "ak:strand:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL"
    );
    assert_eq!(channel.name, "General");
    assert_eq!(channel.kind, "discussion");
    assert_eq!(channel.topic.as_deref(), Some("Realm-wide conversation"));
    assert!(channel.is_default);
}

#[test]
fn default_discussion_channel_fails_closed_when_projection_is_absent() {
    assert!(default_discussion_channel(None).is_none());
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
            "actor_id": "ak:did_core:web:bob.example",
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
            "actor_id": "ak:did_core:web:carol.example",
            // Matrix `unavailable` fails closed to offline.
            "status": "unavailable"
        }),
        json!({
            "actor_id": "ak:did_core:web:mallory.example",
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
        "actor_id": "ak:did_core:web:bob.example",
        "state": "online",
    })];
    let offline = vec![json!({
        "kind": "ak.presence",
        "actor_id": "ak:did_core:web:bob.example",
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
            "actor_id": "ak:did_core:web:bob.example",
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
            "actor_id": "ak:did_core:web:bob.example",
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
            "actor_id": "ak:did_core:web:bob.example",
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
    let content_value = arkret_sdk::ContentBlock::markdown_text(body)
        .to_value()
        .expect("content block serializes");
    let bytes = serde_json::to_vec(&content_value).expect("content block bytes");
    let parsed: Value = serde_json::from_slice(&bytes).expect("content block parses");
    assert_eq!(text_body_from_value(&parsed), Some(body));
    assert_eq!(
        content_format_from_value(&parsed),
        Some(arkret_sdk::TextFormat::Markdown)
    );
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
        "scheme": "mls_rfc9420",
        "group_id": "group-x",
        "epoch": 1,
        "content_type": "application/vnd.arkret.message+json",
        "ciphertext": "AAAA",
        "payload_digest": "sha256:0",
    });
    let authority = test_authority("did:web:alice.example");
    let device_id = test_device_id("ak:device:01964137-0000-7000-8000-000000000001");
    assert!(
        decrypt_chat_encrypted_content(
            &store,
            "ak:realm:AacL7ZYuTtiI1Wvq5aTmbQo8CihIcuFhJ4WKAZZMxlxY",
            &authority,
            &device_id,
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
            "strand_id": "ak:strand:AI5OKPo7cL4WAh-kQD_G9aUudPNU0xGaEiCVn1F1nFGA",
            "encrypted_content": {"ciphertext": "blob"},
        }
    });
    let msg = chat_message_from_event(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        &event,
    )
    .expect("message");
    assert_eq!(msg.crypto_state, MessageCryptoState::Decrypting);
}

#[test]
fn circle_scoped_message_does_not_require_forbidden_payload_scope_field() {
    let event = json!({
        "event_id": "ak:event:ASUb86fbFm5UEUFKFTuMNfbNsMTlueGP2DFFuE8vHwt0",
        "kind": "ak.message.create",
        "effective_scope": {
            "kind": "circle",
            "realm_id": "ak:realm:AZ50TDWNf7-ZvnbVpb3-bD97v_NiKs0krmIiZeXokdCg",
            "circle_id": "ak:circle:Ad3sAE8SdL97yMaxfdHCkPiyKsWulMWC1Eisx0zigFOe"
        },
        "payload": {
            "strand_id": "ak:strand:AegcXfEz2IA1aMoPIHXpIIKiqHdDUdO6mYsEziNN-gnj",
            "message_id": "message-circle-scoped",
            "track_name": "discussion",
            "content": { "body": "private" }
        }
    });

    let message = chat_message_from_event(
        "ak:realm:AZ50TDWNf7-ZvnbVpb3-bD97v_NiKs0krmIiZeXokdCg",
        &event,
    )
    .unwrap();
    assert_eq!(message.crypto_state, MessageCryptoState::Plaintext);
    assert_eq!(message.body, "private");
}

#[test]
fn chat_message_from_event_keeps_bodyless_encrypted_payload_visible() {
    let event = json!({
        "event_id": "evt:bodyless",
        "content": {
            "type": "ak.message.create",
            "strand_id": "ak:strand:AI5OKPo7cL4WAh-kQD_G9aUudPNU0xGaEiCVn1F1nFGA",
            "message_id": "ak:message:Abz8ZrG1_9zdkxN9VA-u0IBsaEOpJkC71uo1V6fZ72VY",
            "encrypted_content": {
                "scheme": "mls_rfc9420",
                "version": "1.0",
                "group_id": "ak:mls:test",
                "epoch": 1,
                "content_type": "application/vnd.arkret.message+json",
                "ciphertext": "AAAA",
                "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
        }
    });

    let msg = chat_message_from_event(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        &event,
    )
    .expect("message");

    assert_eq!(msg.body, "");
    assert_eq!(
        msg.strand_id,
        "ak:strand:AI5OKPo7cL4WAh-kQD_G9aUudPNU0xGaEiCVn1F1nFGA"
    );
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
            "strand_id": "ak:strand:AI5OKPo7cL4WAh-kQD_G9aUudPNU0xGaEiCVn1F1nFGA",
            "message_id": "ak:message:Abz8ZrG1_9zdkxN9VA-u0IBsaEOpJkC71uo1V6fZ72VY",
            "encrypted_content": {
                "scheme": "mls_rfc9420",
                "version": "1.0",
                "group_id": "ak:mls:test",
                "epoch": 1,
                "content_type": "application/vnd.arkret.message+json",
                "ciphertext": "AAAA",
                "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
        }
    });
    let authority = test_authority("did:web:bob.example");
    let device_id = test_device_id("ak:device:01964137-0000-7000-8000-000000000001");

    let msg = chat_message_from_event_with_sidecar(
        "ak:realm:AacL7ZYuTtiI1Wvq5aTmbQo8CihIcuFhJ4WKAZZMxlxY",
        &event,
        Some(&store),
        Some((&authority, "did:web:bob.example", &device_id)),
    )
    .expect("message");

    assert_eq!(msg.body, "");
    assert_eq!(msg.crypto_state, MessageCryptoState::KeyMissing);
}

/// `message_revise_payload` registers exactly one target carrier, `message_id`.
/// An `ak:event:` create token handed to the builder is retyped to
/// `ak:message:` (`common-fields.md` §6.0) rather than written verbatim, so the
/// same Message can never be addressed two ways.
#[test]
fn chat_message_revise_operation_retypes_event_target_to_message_id() {
    let op = chat_message_revise_operation(
        "ak:realm:AcLZB9aC8iMR8iBq1sUbB77yPclZIvptyHtZVgiszdI5",
        "did:web:bob.example",
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
    arkret_sdk::schema::event_payload_validator_catalog()
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
        "did:web:bob.example",
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
    arkret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind().as_str(),
            &serde_json::to_value(op.payload()).unwrap(),
        )
        .unwrap();
}

/// Same single-carrier rule for `message_redact_payload`.
#[test]
fn chat_message_redact_operation_retypes_event_target_to_message_id() {
    let op = chat_message_redact_operation(
        "ak:realm:AcLZB9aC8iMR8iBq1sUbB77yPclZIvptyHtZVgiszdI5",
        "did:web:bob.example",
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
    arkret_sdk::schema::event_payload_validator_catalog()
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
        "did:web:bob.example",
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
    arkret_sdk::schema::event_payload_validator_catalog()
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
        "did:web:bob.example",
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
    arkret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(
            op.kind().as_str(),
            &serde_json::to_value(op.payload()).unwrap(),
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
            realm_id: "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0".to_owned(),
            id: id.to_owned(),
            protocol_message_id: Some(
                "ak:message:AZhIGxyGMJYSpWhMOugJZewLoNM88CzSBohQQRpKgw1c".to_owned(),
            ),
            sender: "did:web:bob.example".to_owned(),
            executed_by: None,
            body: body.to_owned(),
            content_format: None,
            timestamp: "10:00".to_owned(),
            created_at,
            strand_id: "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE".to_owned(),
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
        let existing = msg(
            "ak:event:AWSsryl67JAGALOqh0ZH5T-813hPA-GnZxpV3_U9Xp8c",
            "existing",
            at("2026-07-07T06:19:20.000Z"),
        );
        let same_id = msg(
            "ak:event:AWSsryl67JAGALOqh0ZH5T-813hPA-GnZxpV3_U9Xp8c",
            "incoming",
            at("2026-07-07T06:19:20.000Z"),
        );
        let higher_id = msg(
            "ak:event:AZccWZlaAUrqgOzXQ7OucnyL0J8C4O-JnwPOLdtlGX9k",
            "incoming",
            at("2026-07-07T06:19:20.000Z"),
        );
        let lower_id = msg(
            "ak:event:ASnA61b1h_g939GicWajzCOTfc2Z3pGGQvQlQ_YHYbN4",
            "incoming",
            at("2026-07-07T06:19:20.000Z"),
        );
        assert!(same_id.is_newer_or_same_lifecycle_version_than(&existing));
        assert!(higher_id.is_newer_or_same_lifecycle_version_than(&existing));
        assert!(!lower_id.is_newer_or_same_lifecycle_version_than(&existing));
    }

    #[test]
    fn newer_or_same_lifecycle_version_prefers_strictly_newer_timestamp() {
        let existing = msg(
            "ak:event:AWSsryl67JAGALOqh0ZH5T-813hPA-GnZxpV3_U9Xp8c",
            "existing",
            at("2026-07-07T06:19:20.000Z"),
        );
        // A strictly newer timestamp wins regardless of the id tie-break.
        let newer = msg(
            "ak:event:ASnA61b1h_g939GicWajzCOTfc2Z3pGGQvQlQ_YHYbN4",
            "incoming",
            at("2026-07-07T06:19:30.000Z"),
        );
        let older = msg(
            "ak:event:ATwS2vge4nnhtaqL3ss6x3XcMjGpGXRvnIbosXzWy_PY",
            "incoming",
            at("2026-07-07T06:19:10.000Z"),
        );
        assert!(newer.is_newer_or_same_lifecycle_version_than(&existing));
        assert!(!older.is_newer_or_same_lifecycle_version_than(&existing));
    }

    #[test]
    fn newer_or_same_lifecycle_version_missing_timestamps() {
        let existing_none = msg(
            "ak:event:ASnA61b1h_g939GicWajzCOTfc2Z3pGGQvQlQ_YHYbN4",
            "existing",
            None,
        );
        let existing_some = msg(
            "ak:event:ASnA61b1h_g939GicWajzCOTfc2Z3pGGQvQlQ_YHYbN4",
            "existing",
            at("2026-07-07T06:19:20.000Z"),
        );
        let incoming_none = msg(
            "ak:event:ASnA61b1h_g939GicWajzCOTfc2Z3pGGQvQlQ_YHYbN4",
            "incoming",
            None,
        );
        let incoming_some = msg(
            "ak:event:ASnA61b1h_g939GicWajzCOTfc2Z3pGGQvQlQ_YHYbN4",
            "incoming",
            at("2026-07-07T06:19:20.000Z"),
        );
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
            "ak:event:Az44QHRciASAFcKvTeHUu3sA84dj1h1KUH4_ZULaOFck",
            "edited body",
            at("2026-07-07T06:19:22.000Z"),
        );
        existing.edited = true;
        existing.revisions = vec!["draft".to_owned()];
        let incoming = msg(
            "ak:event:AR7M-BmzB0WZaDxMCMGGTR6MG8p04uMLRtEf7jJsmZlk",
            "newer body",
            at("2026-07-07T06:19:30.000Z"),
        );

        merge_duplicate_create_message(&mut existing, incoming);

        assert_eq!(
            existing.id,
            "ak:event:AR7M-BmzB0WZaDxMCMGGTR6MG8p04uMLRtEf7jJsmZlk"
        );
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
            "ak:event:Az44QHRciASAFcKvTeHUu3sA84dj1h1KUH4_ZULaOFck",
            "current body",
            at("2026-07-07T06:19:30.000Z"),
        );
        existing.edited = true;
        let mut incoming = msg(
            "ak:event:AR7M-BmzB0WZaDxMCMGGTR6MG8p04uMLRtEf7jJsmZlk",
            "original body",
            at("2026-07-07T06:19:20.000Z"),
        );
        incoming.reactions = vec![("+1".to_owned(), vec!["did:web:carol.example".to_owned()])];

        merge_duplicate_create_message(&mut existing, incoming);

        assert_eq!(
            existing.id,
            "ak:event:Az44QHRciASAFcKvTeHUu3sA84dj1h1KUH4_ZULaOFck"
        );
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
        let mut existing = msg(
            "ak:event:AR7M-BmzB0WZaDxMCMGGTR6MG8p04uMLRtEf7jJsmZlk",
            "body",
            at("2026-07-07T06:19:20.000Z"),
        );
        existing.reactions = vec![("+1".to_owned(), vec!["did:web:bob.example".to_owned()])];
        let mut incoming = msg(
            "ak:event:AIS3CfzQ4_aXiTARf8qv5G4C8b5BRZ7VN-tyB7K8oZmA",
            "body",
            at("2026-07-07T06:19:30.000Z"),
        );
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
            "event_id": "ak:event:AzlDwYnXxsrAJPnV18jXnpRSyNg1pwLq9kdhlLSr3PlI",
            "kind": "ak.message.create",
            "actor_id": "ak:did_core:web:bob.example",
            "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            "created_at": "2026-07-07T06:19:20.000Z",
            "strand_id": "ak:strand:ARJxD7BSUwmnyinQVd_KxLCG7gwfyIFlTzeJk7F_phHE",
            "message_id": "ak:message:AiMtOq_gs6Il6jSfTW_-c3OYzV-X5k9afNn8RSyisj38",
            "body": "hi",
            "reaction_summary": { " +1 ": { "members": [" did:web:carol.example "] } },
            "proofs": []
        })];
        sign_chat_fixtures(&mut events);
        let messages = chat_messages_from_events_with_sidecar(
            "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0",
            &events,
            None,
            None,
        );
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
        let mut existing = msg(
            "ak:event:AR7M-BmzB0WZaDxMCMGGTR6MG8p04uMLRtEf7jJsmZlk",
            "secret",
            at("2026-07-07T06:19:20.000Z"),
        );
        let mut tombstone = msg(
            "ak:event:AR7M-BmzB0WZaDxMCMGGTR6MG8p04uMLRtEf7jJsmZlk",
            "",
            None,
        );
        tombstone.redacted = true;

        merge_duplicate_create_message(&mut existing, tombstone);

        assert!(existing.redacted);
        assert_eq!(existing.created_at, at("2026-07-07T06:19:20.000Z"));
    }

    // An echo / re-projection that could not recover the plaintext arrives
    // with an empty body; the merge must not blank out the body the local
    // (optimistic) copy already rendered, and the carried body must not leak
    // into the edit history.
    #[test]
    fn merge_newer_incoming_with_empty_body_preserves_rendered_body() {
        let mut existing = msg(
            "ak:event:Az44QHRciASAFcKvTeHUu3sA84dj1h1KUH4_ZULaOFck",
            "rendered body",
            at("2026-07-07T06:19:20.000Z"),
        );
        let incoming = msg(
            "ak:event:Az44QHRciASAFcKvTeHUu3sA84dj1h1KUH4_ZULaOFck",
            "",
            at("2026-07-07T06:19:30.000Z"),
        );

        merge_duplicate_create_message(&mut existing, incoming);

        assert_eq!(existing.body, "rendered body");
        assert!(existing.revisions.is_empty());
    }
}
