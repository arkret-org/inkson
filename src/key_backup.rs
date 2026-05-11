use chrono::SecondsFormat;
use serde_json::{Value, json};

pub fn build_key_backup_put_body(
    backup_id: &str,
    actor_did: &str,
    device_id: &str,
    ciphertext: &str,
    ciphertext_digest: &str,
) -> Value {
    let mut body = json!({
        "backup_id": backup_id,
        "actor_id": actor_did,
        "backup_class": "mls_history",
        "backup_version": "kb_1",
        "created_at": chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "encryption": {
            "recipient_method": "passphrase_kdf",
            "recipient_key_ref": device_id,
            "kdf": {
                "name": "argon2id",
                "salt": "yougen_demo_salt"
            },
            "aead": {
                "name": "xchacha20_poly1305",
                "nonce": "yougen_demo_nonce"
            }
        },
        "contents": [{
            "item_type": "mls_group_state",
            "secret_id": "yougen_current_device_mls_state"
        }],
        "ciphertext": ciphertext,
        "ciphertext_digest": ciphertext_digest,
    });
    if is_protocol_device_id(device_id)
        && let Some(object) = body.as_object_mut()
    {
        object.insert("device_id".to_owned(), Value::String(device_id.to_owned()));
    }
    body
}

fn is_protocol_device_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("cx:device:") else {
        return false;
    };
    rest.len() == 36
        && rest.chars().enumerate().all(|(idx, ch)| match idx {
            8 | 13 | 18 | 23 => ch == '-',
            14 => ch == '7',
            19 => matches!(ch, '8' | '9' | 'a' | 'b'),
            _ => ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_key_backup_put_body_round_trips_required_fields() {
        let body = build_key_backup_put_body(
            "cx:backup:01964137-0000-7000-8000-000000000000",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000001",
            "BASE64URL_OPAQUE_BLOB",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(
            body["backup_id"],
            "cx:backup:01964137-0000-7000-8000-000000000000"
        );
        assert_eq!(body["actor_id"], "did:web:alice.example");
        assert_eq!(
            body["device_id"],
            "cx:device:01964137-0000-7000-8000-000000000001"
        );
        assert_eq!(body["backup_class"], "mls_history");
        assert_eq!(body["backup_version"], "kb_1");
        assert_eq!(body["encryption"]["recipient_method"], "passphrase_kdf");
        assert_eq!(body["encryption"]["aead"]["name"], "xchacha20_poly1305");
        assert_eq!(body["contents"][0]["item_type"], "mls_group_state");
        assert_eq!(body["ciphertext"], "BASE64URL_OPAQUE_BLOB");
        assert_eq!(
            body["ciphertext_digest"],
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn build_key_backup_put_body_uses_recipient_key_ref() {
        let body = build_key_backup_put_body(
            "cx:backup:01964137-0000-7000-8000-000000000000",
            "did:web:alice.example",
            "dev_alice",
            "BASE64URL_OPAQUE_BLOB",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(body.get("device_id").is_none());
        assert_eq!(body["encryption"]["recipient_key_ref"], "dev_alice");
    }
}
