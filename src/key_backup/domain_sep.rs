use serde_json::{Value, json};

use super::{KEY_BACKUP_SCHEMA, KeyBackupClass, key_backup_hkdf_info};

pub fn attach_key_backup_domain_separation(
    body: &mut Value,
    class: KeyBackupClass,
    subdomain: &str,
) {
    let item_types = body
        .get("contents")
        .and_then(Value::as_array)
        .map(|contents| {
            contents
                .iter()
                .filter_map(|item| item.get("item_type").and_then(Value::as_str))
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let device_id = body
        .get("device_id")
        .or_else(|| {
            body.get("encryption")
                .and_then(|encryption| encryption.get("recipient_key_ref"))
        })
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    body["domain_separation"] = json!({
        "hkdf_info": key_backup_hkdf_info(class, subdomain),
        "subdomain": subdomain,
        "aead_aad": {
            "schema": KEY_BACKUP_SCHEMA,
            "actor_id": body.get("actor_id").cloned().unwrap_or(Value::Null),
            "device_id": device_id,
            "backup_class": class.as_str(),
            "backup_version": body.get("backup_version").cloned().unwrap_or(Value::Null),
            "created_at": body.get("created_at").cloned().unwrap_or(Value::Null),
            "item_types": item_types,
        }
    });
}

pub fn attach_key_backup_genesis_series(body: &mut Value) {
    if let Some(object) = body.as_object_mut() {
        object
            .entry("series_id")
            .or_insert_with(|| json!(format!("ck:backup_series:{}", crate::operation::uuid_v7())));
        object.entry("series_seq").or_insert_with(|| json!(0));
        object.remove("supersedes");
        object.remove("supersedes_digest");
    }
}
