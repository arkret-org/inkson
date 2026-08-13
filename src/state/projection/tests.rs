use super::sync::projection_events_from_sync_realms;

const GOLDEN_REALM: &str = "ak:realm:AeEFmfOZxsx5kLi2kpOJu8m7TFXZ_G8E4019rUp4wmT6";

fn golden_realm_id() -> arkret_sdk::RealmId {
    arkret_sdk::RealmId::new(GOLDEN_REALM).unwrap()
}

fn golden_actor() -> arkret_sdk::DidCoreId {
    arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap()
}

fn golden_event(
    event_id: &str,
    kind: &str,
    actor_seq: u64,
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
        actor_seq,
        arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
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
        1,
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
        2,
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
fn projection_late_recovery_rejection_blocks_sidecar_plaintext() {
    let path = std::env::temp_dir().join(format!(
        "inkson-projection-late-recovery-{}.json",
        crate::operation::uuid_v7()
    ));
    let mut store = crate::state::LocalStateStore::with_path(path);
    let realm = "ak:realm:AcLZB9aC8iMR8iBq1sUbB77yPclZIvptyHtZVgiszdI5";
    let strand = "ak:strand:AcLZB9aC8iMR8iBq1sUbB77yPclZIvptyHtZVgiszdI5";
    let message = "ak:message:AWZMmWc7y9r8WlGaMEq-hImiHKsg6Oztmr6RWaAmigKO";
    store.save_private_plaintext(realm, strand, &format!("message:{message}"), "secret body");
    let realms = std::collections::BTreeMap::from([(
        realm.to_owned(),
        serde_json::json!({
            "summary": {"summary": "Demo"},
            "timeline": {
                "events": [{
                    "kind": "ak.message.create",
                    "event_id": "ak:event:A4BWEYeaKK6NG4kEzOZXc7FlBfXuJdsVxsjAp4V6hygg",
                    "actor_id": "ak:did_core:web:alice.example",
                    "realm_id": realm,
                    "strand_id": strand,
                    "message_id": message,
                    "decryption_state": "decryption_failed",
                    "late_recovery": {
                        "receiver_visible_at_t0": true,
                        "source_rechecked_current_share_policy": false
                    },
                    "content": {"encrypted_content": true}
                }]
            }
        }),
    )]);

    let events = projection_events_from_sync_realms(&realms, Some(&store), None);
    let rejected = events
        .iter()
        .find(|event| event.id == "ak:event:A4BWEYeaKK6NG4kEzOZXc7FlBfXuJdsVxsjAp4V6hygg")
        .expect("late recovery event");

    assert_eq!(rejected.body, "");
    assert!(rejected.failed);
    assert_eq!(
        rejected.error.as_deref(),
        Some(arkret_sdk::ReasonCode::LATE_RECOVERY_SHARE_NOT_AUTHORIZED)
    );
}

#[test]
fn projection_audit_policy_access_late_recovery_marker_is_guarded() {
    let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let realms = std::collections::BTreeMap::from([(
        realm.to_owned(),
        serde_json::json!({
            "summary": {"summary": "Demo"},
            "timeline": {
                "events": [{
                    "kind": "ak.audit.policy_access",
                    "event_id": "ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk",
                    "original_received_at": "2026-05-20T00:00:00.000Z",
                    "late_recovery": {
                        "receiver_visible_at_t0": true,
                        "source_rechecked_current_share_policy": true
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
    let marker = events
        .iter()
        .find(|event| {
            event.id == "late-recovery-ak:event:ATFrN4sYtiDvJD5G4wKxYY3xMKfo-Xqa_o9Xkb-XnzFN"
        })
        .expect("late recovery audit marker");

    assert!(marker.body.contains("30"));
    assert!(!marker.failed);
    assert_eq!(
        marker.event_id.as_deref(),
        Some("ak:event:ATFrN4sYtiDvJD5G4wKxYY3xMKfo-Xqa_o9Xkb-XnzFN")
    );
}
