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
