use arkret_wire::SchemaId;
use serde_json::{Value, json};

use super::{BackupKind, key_backup_hkdf_info};

pub fn attach_key_backup_domain_separation(body: &mut Value, class: BackupKind, subdomain: &str) {
    let item_kinds = body
        .get("contents")
        .and_then(Value::as_array)
        .map(|contents| {
            contents
                .iter()
                .filter_map(|item| item.get("item_kind").and_then(Value::as_str))
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let recipient_key_ref = body
        .get("encryption")
        .and_then(|encryption| encryption.get("recipient_key_ref"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let device_id = body
        .get("device_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| recipient_key_ref.clone());
    // SEC-04: bind the envelope's `recipient_method` (and the
    // `recipient_key_ref` that names the recipient key / verification method)
    // into the AEAD AAD so two envelopes that share every other identity field
    // (e.g. the `passphrase_kdf` and `recovery_public_key` account-secret
    // backups under the same `mls_account_secret` item type) can never have a
    // ciphertext cross-opened under the wrong recipient interpretation. The
    // receiver MUST fail closed on a method/AAD mismatch (key-management.md
    // §7.5 / §7.8). Both sealer and opener reconstruct this AAD byte-identically
    // from the stored envelope, so the binding is symmetric.
    let recipient_method = body
        .get("encryption")
        .and_then(|encryption| encryption.get("recipient_method"))
        .cloned()
        .unwrap_or(Value::Null);
    let domain_separation = json!({
        "hkdf_info": key_backup_hkdf_info(class, subdomain),
        "subdomain": subdomain,
        "aead_aad": {
            "schema": SchemaId::KEY_BACKUP_V1,
            "actor_id": body.get("actor_id").cloned().unwrap_or(Value::Null),
            "device_id": device_id,
            "backup_kind": class.as_str(),
            "backup_version": body.get("backup_version").cloned().unwrap_or(Value::Null),
            "created_at": body.get("created_at").cloned().unwrap_or(Value::Null),
            "item_kinds": item_kinds,
            "recipient_method": recipient_method,
            "recipient_key_ref": recipient_key_ref,
        }
    });
    body["domain_separation"] = domain_separation;
}

pub fn attach_key_backup_genesis_series(body: &mut Value) {
    if let Some(object) = body.as_object_mut() {
        object
            .entry("series_id")
            .or_insert_with(|| json!(format!("ak:backup_series:{}", crate::operation::uuid_v7())));
        object.entry("series_seq").or_insert_with(|| json!(0));
        object.remove("supersedes");
        object.remove("supersedes_digest");
    }
}
