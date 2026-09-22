use super::sync::projection_events_from_sync_realms;

const GOLDEN_REALM: &str = "ak:realm:AeEFmfOZxsx5kLi2kpOJu8m7TFXZ_G8E4019rUp4wmT6";

fn golden_realm_id() -> arkret_sdk::RealmId {
    crate::test_support::realm_id(GOLDEN_REALM)
}

fn golden_actor() -> arkret_sdk::DidCoreId {
    arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap()
}

fn golden_event(
    event_id: &str,
    kind: &str,
    created_at: &str,
    payload: serde_json::Value,
) -> arkret_sdk::Event {
    let mut event = arkret_wire::test_support::raw_event(
        kind,
        arkret_sdk::ScopeRef::Realm {
            realm_id: golden_realm_id(),
        },
        golden_actor(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        payload,
    )
    .unwrap();
    event.event_id = arkret_sdk::EventId::new(event_id).unwrap();
    event.created_at = created_at.parse().unwrap();
    event
}

#[test]
fn client_core_message_decode_golden_matches_inkson_ingest() {
    let create = golden_event(
        "ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z",
        arkret_sdk::EventKind::MessageCreate.as_str(),
        "2026-07-08T00:00:00.000Z",
        serde_json::json!({
            "strand_id": "ak:strand:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0",
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "body": "hello"}
        }),
    );
    let reaction = golden_event(
        "ak:event:AbHexNOxiiU334tA-ZHyM5pRxJxbMY0jvwlMVDY3Xjrz",
        arkret_sdk::EventKind::ReactionAdd.as_str(),
        "2026-07-08T00:00:01.000Z",
        serde_json::json!({
            "target_ref": "ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z",
            "key": "+1"
        }),
    );
    let events = [create, reaction];
    let decoder = garth::InboundDecoder::new();

    let decoded: Vec<_> = events
        .iter()
        .cloned()
        .map(|event| decoder.try_decode_event(event).unwrap())
        .collect();
    assert!(matches!(
        &decoded[0],
        garth::DecodedInbound::Message(message)
            if matches!(
                message.as_ref(),
                garth::DecodedMessage {
                    payload: arkret_sdk::MessageEventPayload::Create(_),
                    ..
                }
            )
    ));
    assert!(matches!(
        &decoded[1],
        garth::DecodedInbound::Message(message)
            if matches!(
                message.as_ref(),
                garth::DecodedMessage {
                    payload: arkret_sdk::MessageEventPayload::ReactionAdd(_),
                    ..
                }
            )
    ));

    let event_values: Vec<_> = events
        .iter()
        .map(|event| serde_json::to_value(event).unwrap())
        .collect();
    let records = super::message_ops::message_operations_from_events(GOLDEN_REALM, &event_values);

    assert_eq!(records.len(), 2);
    assert_eq!(
        records[0].operation_id,
        "ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z"
    );
    assert_eq!(
        records[0].payload["payload"]["content"]["body"],
        serde_json::json!("hello")
    );
    assert_eq!(
        records[1].operation_id,
        "ak:event:AbHexNOxiiU334tA-ZHyM5pRxJxbMY0jvwlMVDY3Xjrz"
    );
    assert_eq!(
        records[1].payload["payload"]["key"],
        serde_json::json!("+1")
    );
}

#[test]
fn projection_does_not_turn_audit_policy_access_into_chat_authority() {
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let realms = std::collections::BTreeMap::from([(
        realm.to_owned(),
        serde_json::json!({
            "summary": {"summary": "Demo"},
            "timeline": {
                "events": [{
                    "kind": arkret_wire::event_kind_str::AUDIT_ACCESSED,
                    "event_id": "ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk",
                    "original_received_at": "2026-05-20T00:00:00.000Z",
                    "late_recovery": {
                        "receiver_visible_at_t0": true
                    },
                    "payload": {
                        "realm_id": realm,
                        "actor": "ak:did_core:web:alice.example",
                        "access_kind": "e2ee_late_recovery",
                        "late_recovery_original_event_id": "ak:event:ATFrN4sYtiDvJD5G4wKxYY3xMKfo-Xqa_o9Xkb-XnzFN",
                        "observed_at": "2026-05-20T00:30:00.000Z"
                    }
                }]
            }
        }),
    )]);

    let events = projection_events_from_sync_realms(&realms, None, None);
    assert!(
        events
            .iter()
            .all(|event| !event.id.starts_with("late-recovery-"))
    );
}
