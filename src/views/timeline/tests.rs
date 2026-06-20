use super::operations::{
    message_create_operation, message_create_operation_with_expiry, message_revise_operation,
    public_update_requires_sanitization, reaction_add_operation,
};
use super::sync::timeline_events_from_sync_realms;

#[test]
fn message_create_operation_retags_realm_scope_to_strand_id() {
    let op = message_create_operation(
        "ck:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22",
        "did:web:bob.example",
        None,
        "hello",
        None,
    )
    .expect("builds");

    assert_eq!(
        op.content["strand_id"],
        "ck:strand:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22"
    );
    assert_eq!(op.content["track_name"], "discussion");
    assert_eq!(op.content["content"]["kind"], "ck.content.text");
    assert!(op.content.get("body").is_none());
    assert!(op.content.get("encrypted").is_none());
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(op.kind.as_str(), &op.content)
        .unwrap();
}

#[test]
fn message_create_operation_attaches_incident_priority_under_realm() {
    let op = message_create_operation(
        "ck:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22",
        "did:web:bob.example",
        None,
        "hello",
        Some("sev1"),
    )
    .expect("builds");

    assert_eq!(
        op.content["strand_id"],
        "ck:strand:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22"
    );
    assert!(op.content.get("priority").is_none());
    assert!(op.content.get("notification_priority").is_none());
    assert!(op.content.get("priority_override").is_none());
    assert_eq!(op.content["content"]["priority"], "critical");
    assert_eq!(
        op.content["content"]["notification"]["priority"],
        "critical"
    );
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(op.kind.as_str(), &op.content)
        .unwrap();
}

#[test]
fn message_create_operation_with_expiry_attaches_top_level_expiry() {
    let expiry = cokret_sdk::DisappearingMessageExpiry::new(
        30_000,
        cokret_sdk::DisappearingMessageExpiryTrigger::OnSend,
    )
    .unwrap();
    let op = message_create_operation_with_expiry(
        "ck:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22",
        "did:web:bob.example",
        None,
        "short lived",
        None,
        Some(expiry),
    )
    .expect("builds");

    assert_eq!(op.content["expiry"]["ttl_ms"], 30_000);
    assert_eq!(op.content["expiry"]["trigger"], "on_send");
    assert!(op.content["content"].get("expiry").is_none());
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(op.kind.as_str(), &op.content)
        .unwrap();
}

#[test]
fn timeline_expiry_stub_does_not_restore_authors_plaintext_sidecar() {
    let path = std::env::temp_dir().join(format!(
        "yougen-timeline-expiry-stub-{}.json",
        crate::operation::uuid_v7()
    ));
    let mut store = crate::local_state::LocalStateStore::with_path(path);
    let realm = "ck:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22";
    let strand = "ck:strand:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22";
    let message = "ck:message:019e4fd4-4e26-7cc9-af7e-d7102d6f4a24";
    store.save_private_plaintext(realm, strand, &format!("message:{message}"), "secret body");
    let realms = std::collections::BTreeMap::from([(
        realm.to_owned(),
        serde_json::json!({
            "summary": {"summary": "Demo"},
            "timeline": {
                "events": [{
                    "kind": "ck.message.create",
                    "event_id": "ck:event:expired",
                    "actor_id": "did:web:alice.example",
                    "realm_id": realm,
                    "strand_id": strand,
                    "message_id": message,
                    "expiry_stub": true,
                    "expiry_state": "expired",
                    "content": {"kind": "ck.content.text", "body": "[expired]"}
                }]
            }
        }),
    )]);

    let events = timeline_events_from_sync_realms(&realms, Some(&store), None);
    let expired = events
        .iter()
        .find(|event| event.id == "ck:event:expired")
        .expect("expired event");

    assert_eq!(expired.body, "[expired]");
}

#[test]
fn public_update_guard_flags_internal_details() {
    assert!(public_update_requires_sanitization(
        "Public update: root cause is a leaked token"
    ));
    assert!(!public_update_requires_sanitization(
        "Public update: checkout latency is recovering"
    ));
}

#[test]
fn message_revise_operation_carries_schema_target_ref() {
    let op = message_revise_operation(
        "ck:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22",
        "did:web:bob.example",
        "ck:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23",
        "edited",
    )
    .expect("builds");

    assert_eq!(
        op.content["target_ref"],
        "ck:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23"
    );
    assert_eq!(op.content["content"]["kind"], "ck.content.text");
    assert_eq!(op.content["content"]["body"], "edited");
    assert!(op.content.get("body").is_none());
    assert!(op.content.get("target_event_id").is_none());
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(op.kind.as_str(), &op.content)
        .unwrap();
}

#[test]
fn reaction_add_operation_uses_schema_target_ref() {
    let op = reaction_add_operation(
        "ck:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22",
        "did:web:bob.example",
        "ck:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23",
        "+1",
    )
    .expect("builds");

    assert_eq!(
        op.content["target_ref"],
        "ck:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23"
    );
    assert_eq!(op.content["key"], "+1");
    assert!(op.content.get("event_id").is_none());
    assert!(op.content.get("actor").is_none());
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(op.kind.as_str(), &op.content)
        .unwrap();
}
