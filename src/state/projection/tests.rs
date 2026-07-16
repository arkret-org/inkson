use super::sync::projection_events_from_sync_realms;

const GOLDEN_REALM: &str = "ak:realm:019f1071-0000-7000-8000-000000000000";

#[test]
fn projection_expiry_stub_does_not_restore_authors_plaintext_sidecar() {
    let path = std::env::temp_dir().join(format!(
        "inkson-projection-expiry-stub-{}.json",
        crate::operation::uuid_v7()
    ));
    let mut store = crate::state::LocalStateStore::with_path(path);
    let realm = "ak:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22";
    let strand = "ak:strand:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22";
    let message = "ak:message:019e4fd4-4e26-7cc9-af7e-d7102d6f4a24";
    store.save_private_plaintext(realm, strand, &format!("message:{message}"), "secret body");
    let realms = std::collections::BTreeMap::from([(
        realm.to_owned(),
        serde_json::json!({
            "summary": {"summary": "Demo"},
            "timeline": {
                "events": [{
                    "kind": "ak.message.create",
                    "event_id": "ak:event:expired",
                    "actor_id": "did:web:alice.example",
                    "realm_id": realm,
                    "strand_id": strand,
                    "message_id": message,
                    "expiry_stub": true,
                    "expiry_state": "expired",
                    "content": {"kind": "ak.content.text", "body": "[expired]"}
                }]
            }
        }),
    )]);

    let events = projection_events_from_sync_realms(&realms, Some(&store), None);
    let expired = events
        .iter()
        .find(|event| event.id == "ak:event:expired")
        .expect("expired event");

    assert_eq!(expired.body, "[expired]");
}

fn golden_realm_id() -> arkret_sdk::RealmId {
    arkret_sdk::RealmId::new(GOLDEN_REALM).unwrap()
}

fn golden_actor() -> arkret_sdk::Did {
    arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
}

fn golden_event(
    event_id: &str,
    kind: &str,
    actor_seq: u64,
    created_at: &str,
    payload: serde_json::Value,
) -> arkret_sdk::Event {
    let mut event = arkret_sdk::Event::new(
        kind,
        golden_realm_id(),
        golden_actor(),
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
        "ak:event:01904100-0000-7000-8000-000000000101",
        arkret_sdk::events::EventKind::MESSAGE_CREATE,
        1,
        "2026-07-08T00:00:00Z",
        serde_json::json!({
            "strand_id": "ak:strand:01904100-0000-7000-8000-000000000201",
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "body": "hello"}
        }),
    );
    let reaction = golden_event(
        "ak:event:01904100-0000-7000-8000-000000000102",
        arkret_sdk::events::EventKind::REACTION_ADD,
        2,
        "2026-07-08T00:00:01Z",
        serde_json::json!({
            "target_ref": "ak:event:01904100-0000-7000-8000-000000000101",
            "key": "+1"
        }),
    );
    let events = vec![create, reaction];
    let decoder = arkret_sdk::InboundDecoder::new();

    let decoded: Vec<_> = events
        .iter()
        .cloned()
        .map(|event| decoder.try_decode_event(event).unwrap())
        .collect();
    assert!(matches!(
        &decoded[0],
        arkret_sdk::DecodedInbound::Message(arkret_sdk::DecodedMessage {
            payload: arkret_sdk::MessageEventPayload::Create(_),
            ..
        })
    ));
    assert!(matches!(
        &decoded[1],
        arkret_sdk::DecodedInbound::Message(arkret_sdk::DecodedMessage {
            payload: arkret_sdk::MessageEventPayload::ReactionAdd(_),
            ..
        })
    ));

    let event_values: Vec<_> = events
        .iter()
        .map(|event| serde_json::to_value(event).unwrap())
        .collect();
    let records = super::message_ops::message_operations_from_events(GOLDEN_REALM, &event_values);

    assert_eq!(records.len(), 2);
    assert_eq!(
        records[0].operation_id,
        "ak:event:01904100-0000-7000-8000-000000000101"
    );
    assert_eq!(
        records[0].payload["payload"]["content"]["body"],
        serde_json::json!("hello")
    );
    assert_eq!(
        records[1].operation_id,
        "ak:event:01904100-0000-7000-8000-000000000102"
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
    let realm = "ak:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22";
    let strand = "ak:strand:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22";
    let message = "ak:message:019e4fd4-4e26-7cc9-af7e-d7102d6f4a24";
    store.save_private_plaintext(realm, strand, &format!("message:{message}"), "secret body");
    let realms = std::collections::BTreeMap::from([(
        realm.to_owned(),
        serde_json::json!({
            "summary": {"summary": "Demo"},
            "timeline": {
                "events": [{
                    "kind": "ak.message.create",
                    "event_id": "ak:event:late",
                    "actor_id": "did:web:alice.example",
                    "realm_id": realm,
                    "strand_id": strand,
                    "message_id": message,
                    "decryption_state": "decryption_failed",
                    "late_recovery": {
                        "receiver_visible_at_t0": true,
                        "source_rechecked_current_share_policy": false,
                        "event_expired": false
                    },
                    "content": {"encrypted_content": true}
                }]
            }
        }),
    )]);

    let events = projection_events_from_sync_realms(&realms, Some(&store), None);
    let rejected = events
        .iter()
        .find(|event| event.id == "ak:event:late")
        .expect("late recovery event");

    assert_eq!(rejected.body, "");
    assert!(rejected.failed);
    assert_eq!(
        rejected.error.as_deref(),
        Some(crate::late_recovery::ReasonCode::LATE_RECOVERY_SHARE_NOT_AUTHORIZED)
    );
}

#[test]
fn projection_audit_policy_access_late_recovery_marker_is_guarded() {
    let realm = "ak:realm:01904100-0000-7000-8000-000000000001";
    let realms = std::collections::BTreeMap::from([(
        realm.to_owned(),
        serde_json::json!({
            "summary": {"summary": "Demo"},
            "timeline": {
                "events": [{
                    "kind": "ak.audit.policy_access",
                    "event_id": "ak:event:01904100-0000-7000-8000-000000000099",
                    "original_received_at": "2026-05-20T00:00:00Z",
                    "late_recovery": {
                        "receiver_visible_at_t0": true,
                        "source_rechecked_current_share_policy": true,
                        "event_expired": false
                    },
                    "payload": {
                        "realm_id": realm,
                        "actor": "did:web:alice.example",
                        "access_kind": "e2ee_late_recovery",
                        "late_recovery_original_event_id": "ak:event:01904100-0000-7000-8000-000000000007",
                        "observed_at": "2026-05-20T00:30:00Z"
                    }
                }]
            }
        }),
    )]);

    let events = projection_events_from_sync_realms(&realms, None, None);
    let marker = events
        .iter()
        .find(|event| event.id.starts_with("late-recovery-ak:event:01904100"))
        .expect("late recovery audit marker");

    assert!(marker.body.contains("30"));
    assert!(!marker.failed);
    assert_eq!(
        marker.event_id.as_deref(),
        Some("ak:event:01904100-0000-7000-8000-000000000007")
    );
}
