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
        crate::mls_api_helpers::principal_core_id("ak:did_core:web:example.test:agents:assistant")
            .unwrap();
    let request_event = arkret_sdk::EventId::new(request_event_id).unwrap();
    arkret_sdk::AgentSidecarExchangeProjection {
        schema: arkret_sdk::AgentSidecarExchangeProjectionSchema::V1,
        controller_account_id: arkret_sdk::AccountId::new(
            crate::mls_api_helpers::principal_core_id("ak:did_core:web:example.test:alice")
                .unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap(),
        ),
        sidecar_id: arkret_sdk::SidecarId::new(
            "ak:sidecar:AWea2MtI5dOI1LSRyI266_gQVrWUd0po0dxZiJNsH8kN",
        )
        .unwrap(),
        exchange_id: arkret_sdk::AgentSidecarExchangeId::new("exchange-01964137000000000008")
            .unwrap(),
        source_track_ref: arkret_sdk::AgentSidecarSourceTrackRef {
            realm_id: arkret_sdk::RealmId::new(realm_id).unwrap(),
            strand_id: arkret_sdk::StrandId::new(source_strand_id).unwrap(),
            track_name: "discussion".to_owned(),
        },
        source_event_id: source_event_id.map(|anchor| arkret_sdk::EventId::new(anchor).unwrap()),
        source_hlc: arkret_sdk::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        client_order_key: arkret_sdk::NonEmptyString::new("device-1-1").unwrap(),
        addressed_agent_ids: vec![coordinator.clone()],
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
            crate::mls_api_helpers::principal_core_id(
                "ak:did_core:web:example.test:agents:assistant",
            )
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
