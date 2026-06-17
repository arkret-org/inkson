use super::operations::{
    message_create_operation, message_revise_operation, public_update_requires_sanitization,
    reaction_add_operation,
};

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
        op.payload["strand_id"],
        "ck:strand:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22"
    );
    assert_eq!(op.payload["track_name"], "discussion");
    assert_eq!(op.payload["content"]["kind"], "ck.content.text");
    assert!(op.payload.get("body").is_none());
    assert!(op.payload.get("encrypted").is_none());
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(&op.kind, &op.payload)
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
        op.payload["strand_id"],
        "ck:strand:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22"
    );
    assert!(op.payload.get("priority").is_none());
    assert!(op.payload.get("notification_priority").is_none());
    assert!(op.payload.get("priority_override").is_none());
    assert_eq!(op.payload["content"]["priority"], "critical");
    assert_eq!(
        op.payload["content"]["notification"]["priority"],
        "critical"
    );
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(&op.kind, &op.payload)
        .unwrap();
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
fn reaction_add_operation_uses_schema_target_ref() {
    let op = reaction_add_operation(
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
