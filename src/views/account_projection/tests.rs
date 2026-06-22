use super::sync::projection_events_from_sync_realms;

#[test]
fn projection_expiry_stub_does_not_restore_authors_plaintext_sidecar() {
    let path = std::env::temp_dir().join(format!(
        "yougen-projection-expiry-stub-{}.json",
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

    let events = projection_events_from_sync_realms(&realms, Some(&store), None);
    let expired = events
        .iter()
        .find(|event| event.id == "ck:event:expired")
        .expect("expired event");

    assert_eq!(expired.body, "[expired]");
}

#[test]
fn projection_late_recovery_rejection_blocks_sidecar_plaintext() {
    let path = std::env::temp_dir().join(format!(
        "yougen-projection-late-recovery-{}.json",
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
                    "event_id": "ck:event:late",
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
        .find(|event| event.id == "ck:event:late")
        .expect("late recovery event");

    assert_eq!(rejected.body, "");
    assert!(rejected.failed);
    assert_eq!(
        rejected.error.as_deref(),
        Some(crate::late_recovery::REASON_LATE_RECOVERY_SHARE_NOT_AUTHORIZED)
    );
}

#[test]
fn projection_audit_policy_access_late_recovery_marker_is_guarded() {
    let realm = "ck:realm:01904100-0000-7000-8000-000000000001";
    let realms = std::collections::BTreeMap::from([(
        realm.to_owned(),
        serde_json::json!({
            "summary": {"summary": "Demo"},
            "timeline": {
                "events": [{
                    "kind": "ck.audit.policy_access",
                    "event_id": "ck:event:01904100-0000-7000-8000-000000000099",
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
                        "late_recovery_original_event_id": "ck:event:01904100-0000-7000-8000-000000000007",
                        "observed_at": "2026-05-20T00:30:00Z"
                    }
                }]
            }
        }),
    )]);

    let events = projection_events_from_sync_realms(&realms, None, None);
    let marker = events
        .iter()
        .find(|event| event.id.starts_with("late-recovery-ck:event:01904100"))
        .expect("late recovery audit marker");

    assert!(marker.body.contains("30"));
    assert!(!marker.failed);
    assert_eq!(
        marker.event_id.as_deref(),
        Some("ck:event:01904100-0000-7000-8000-000000000007")
    );
}
