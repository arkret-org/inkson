use std::collections::BTreeMap;

use serde_json::Value;

pub const EXPIRED_MESSAGE_PLACEHOLDER: &str = "[expired]";

pub fn message_event_is_expiry_stub(event: &Value) -> bool {
    event.get("expiry_stub").and_then(Value::as_bool) == Some(true)
}

pub fn message_expiry_stub_body(event: &Value) -> String {
    event
        .get("content")
        .and_then(|content| content.get("body"))
        .and_then(Value::as_str)
        .unwrap_or(EXPIRED_MESSAGE_PLACEHOLDER)
        .to_owned()
}

fn string_field<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

fn encrypted_payload_digest(event: &Value) -> Option<String> {
    event
        .get("encrypted_content")
        .or_else(|| {
            event
                .get("content")
                .and_then(|content| content.get("encrypted_content"))
        })
        .and_then(|encrypted| encrypted.get("payload_digest"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub fn shred_expired_message_plaintext_from_sync_realms(
    store: &mut crate::local_state::LocalStateStore,
    realms: &BTreeMap<String, Value>,
) -> usize {
    let mut dropped = 0usize;
    for (realm_id, body) in realms {
        let Some(events) = body
            .get("timeline")
            .and_then(|timeline| timeline.get("events"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for event in events {
            if !message_event_is_expiry_stub(event) {
                continue;
            }
            let event_realm = string_field(event, &["realm_id"]).unwrap_or(realm_id);
            let Some(strand_id) = string_field(event, &["strand_id", "thread_id"]) else {
                continue;
            };
            let Some(message_id) = string_field(event, &["message_id"]) else {
                continue;
            };
            if store.drop_disappearing_message_plaintext(
                event_realm,
                strand_id,
                message_id,
                encrypted_payload_digest(event).as_deref(),
            ) {
                dropped += 1;
            }
        }
    }
    dropped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_stub_detection_uses_explicit_projection_flag() {
        assert!(message_event_is_expiry_stub(
            &serde_json::json!({"expiry_stub": true})
        ));
        assert!(!message_event_is_expiry_stub(
            &serde_json::json!({"expiry_state": "expired"})
        ));
    }

    #[test]
    fn expiry_stub_body_falls_back_to_metadata_only_placeholder() {
        assert_eq!(
            message_expiry_stub_body(&serde_json::json!({
                "expiry_stub": true,
                "content": {"kind": "ck.content.text", "body": "[expired]"}
            })),
            "[expired]"
        );
        assert_eq!(
            message_expiry_stub_body(&serde_json::json!({"expiry_stub": true})),
            EXPIRED_MESSAGE_PLACEHOLDER
        );
    }

    #[test]
    fn sync_realm_shredder_drops_author_sidecar_for_expiry_stub() {
        let path = std::env::temp_dir().join(format!(
            "inkson-disappearing-shred-{}.json",
            crate::operation::uuid_v7()
        ));
        let realm = "ck:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22";
        let strand = "ck:strand:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22";
        let message = "ck:message:019e4fd4-4e26-7cc9-af7e-d7102d6f4a24";
        let mut store = crate::local_state::LocalStateStore::with_path(path);
        store.save_private_plaintext(realm, strand, &format!("message:{message}"), "secret body");
        let realms = BTreeMap::from([(
            realm.to_owned(),
            serde_json::json!({
                "timeline": {
                    "events": [{
                        "kind": "ck.message.create",
                        "realm_id": realm,
                        "strand_id": strand,
                        "message_id": message,
                        "expiry_stub": true,
                        "content": {"kind": "ck.content.text", "body": "[expired]"}
                    }]
                }
            }),
        )]);

        assert_eq!(
            shred_expired_message_plaintext_from_sync_realms(&mut store, &realms),
            1
        );
        assert!(
            store
                .private_plaintext_for(realm, strand, &format!("message:{message}"))
                .is_none()
        );
    }
}
