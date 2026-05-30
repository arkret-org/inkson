use chrono::SecondsFormat;
use serde_json::{Value, json};

const KEY_BACKUP_SCHEMA: &str = "cx.schema.key_backup.v1";
pub const KEY_BACKUP_DELETE_PROOF_HEADER: &str = "x-contrix-key-backup-delete-proof";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyBackupClass {
    DidRecovery,
    SecretStorage,
    MlsHistory,
}

impl KeyBackupClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DidRecovery => "did_recovery",
            Self::SecretStorage => "secret_storage",
            Self::MlsHistory => "mls_history",
        }
    }
}

impl TryFrom<&str> for KeyBackupClass {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "did_recovery" => Ok(Self::DidRecovery),
            "secret_storage" => Ok(Self::SecretStorage),
            "mls_history" => Ok(Self::MlsHistory),
            other => Err(format!("unsupported backup_class {other}")),
        }
    }
}

pub fn key_backup_hkdf_info(class: KeyBackupClass, subdomain: &str) -> String {
    format!("contrix-key-backup/{}/{subdomain}/v1", class.as_str())
}

pub fn key_backup_delete_ownership_proof(actor_did: &str, backup_id: &str) -> String {
    format!("dev-ssk-delete:v1:{actor_did}:{backup_id}")
}

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
            .or_insert_with(|| json!(format!("cx:backup_series:{}", crate::operation::uuid_v7())));
        object.entry("series_seq").or_insert_with(|| json!(0));
    }
}

pub fn validate_key_backup_put_request(backup_id: &str, body: &Value) -> Result<(), String> {
    validate_key_backup_envelope(body, None)?;
    let body_backup_id = required_str(body, "backup_id")?;
    if body_backup_id != backup_id {
        return Err(format!(
            "backup_id path/body mismatch: path={backup_id} body={body_backup_id}"
        ));
    }
    Ok(())
}

pub fn validate_key_backup_envelope(
    body: &Value,
    expected_class: Option<KeyBackupClass>,
) -> Result<(), String> {
    let backup_id = required_str(body, "backup_id")?;
    if !is_protocol_backup_id(backup_id) {
        return Err("backup_id must be cx:backup:<uuidv7>".to_owned());
    }
    let series_id = required_str(body, "series_id")?;
    if !is_protocol_backup_series_id(series_id) {
        return Err("series_id must be cx:backup_series:<uuidv7>".to_owned());
    }
    if body.get("series_seq").and_then(Value::as_u64).is_none() {
        return Err("series_seq must be a non-negative integer".to_owned());
    }
    let actor_id = required_str(body, "actor_id")?;
    if !actor_id.starts_with("did:") {
        return Err("actor_id must be a DID".to_owned());
    }
    let class = KeyBackupClass::try_from(required_str(body, "backup_class")?)?;
    if let Some(expected) = expected_class
        && expected != class
    {
        return Err(format!(
            "backup_class mismatch: expected {} got {}",
            expected.as_str(),
            class.as_str()
        ));
    }
    let backup_version = required_str(body, "backup_version")?;
    if !backup_version.starts_with("kb_") {
        return Err("backup_version must start with kb_".to_owned());
    }
    let created_at = required_str(body, "created_at")?;
    if !created_at.ends_with('Z') {
        return Err("created_at must be UTC RFC3339 ending in Z".to_owned());
    }
    if let Some(device_id) = body.get("device_id").and_then(Value::as_str)
        && !is_protocol_device_id(device_id)
    {
        return Err("device_id must be cx:device:<uuidv7> when present".to_owned());
    }

    validate_contents(body, class)?;
    validate_encryption(body, class)?;
    if class == KeyBackupClass::MlsHistory {
        validate_mls_history_opaque_only(body)?;
    }
    validate_domain_separation(body, class)?;

    let ciphertext = required_str(body, "ciphertext")?;
    if !is_base64url_token(ciphertext) {
        return Err("ciphertext must be base64url".to_owned());
    }
    let ciphertext_digest = required_str(body, "ciphertext_digest")?;
    if !is_sha_digest(ciphertext_digest) {
        return Err("ciphertext_digest must be a sha digest".to_owned());
    }
    Ok(())
}

/// Build the PUT body for a real Encrypted Cloud Vault upload, with the
/// actual Argon2id salt and XChaCha20-Poly1305 nonce that were used to
/// produce `ciphertext`. Recovery-vault material is carried as a
/// `secret_storage` backup containing a `recovery_secret` item.
pub fn build_recovery_vault_backup_body(
    backup_id: &str,
    actor_did: &str,
    device_id: &str,
    ciphertext_b64: &str,
    ciphertext_digest: &str,
    salt_b64: &str,
    nonce_b64: &str,
    argon2_m_kib: u32,
    argon2_t: u32,
    argon2_p: u32,
) -> Value {
    let mut body = json!({
        "backup_id": backup_id,
        "actor_id": actor_did,
        "backup_class": "secret_storage",
        "backup_version": "kb_1",
        "created_at": chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "encryption": {
            "recipient_method": "passphrase_kdf",
            "recipient_key_ref": device_id,
            "kdf": {
                "name": "argon2id",
                "salt": salt_b64,
                "params": {
                    "memory_kib": argon2_m_kib,
                    "iterations": argon2_t,
                    "parallelism": argon2_p
                }
            },
            "aead": {
                "name": "xchacha20_poly1305",
                "nonce": nonce_b64,
            }
        },
        "contents": [{
            "item_type": "recovery_secret",
            "secret_id": "yougen_recovery_vault_payload",
        }],
        "ciphertext": ciphertext_b64,
        "ciphertext_digest": ciphertext_digest,
    });
    if is_protocol_device_id(device_id)
        && let Some(object) = body.as_object_mut()
    {
        object.insert("device_id".to_owned(), Value::String(device_id.to_owned()));
    }
    attach_key_backup_genesis_series(&mut body);
    attach_key_backup_domain_separation(&mut body, KeyBackupClass::SecretStorage, "recovery_vault");
    body
}

pub fn build_did_recovery_backup_body(
    backup_id: &str,
    actor_did: &str,
    device_id: &str,
    ciphertext_b64: &str,
    ciphertext_digest: &str,
    salt_b64: &str,
    nonce_b64: &str,
) -> Value {
    let mut body = json!({
        "backup_id": backup_id,
        "actor_id": actor_did,
        "backup_class": "did_recovery",
        "backup_version": "kb_1",
        "created_at": chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "encryption": {
            "recipient_method": "passphrase_kdf",
            "recipient_key_ref": device_id,
            "kdf": {
                "name": "argon2id",
                "salt": salt_b64,
                "params": {
                    "memory_kib": 65_536,
                    "iterations": 3,
                    "parallelism": 1
                }
            },
            "aead": {
                "name": "xchacha20_poly1305",
                "nonce": nonce_b64,
            }
        },
        "contents": [{
            "item_type": "recovery_key_share",
            "secret_id": "yougen_did_recovery_share",
        }],
        "ciphertext": ciphertext_b64,
        "ciphertext_digest": ciphertext_digest,
    });
    if is_protocol_device_id(device_id)
        && let Some(object) = body.as_object_mut()
    {
        object.insert("device_id".to_owned(), Value::String(device_id.to_owned()));
    }
    attach_key_backup_genesis_series(&mut body);
    attach_key_backup_domain_separation(&mut body, KeyBackupClass::DidRecovery, "recovery_policy");
    body
}

fn validate_contents(body: &Value, class: KeyBackupClass) -> Result<(), String> {
    let contents = body
        .get("contents")
        .and_then(Value::as_array)
        .ok_or_else(|| "contents must be a non-empty array".to_owned())?;
    if contents.is_empty() {
        return Err("contents must be a non-empty array".to_owned());
    }
    for item in contents {
        let item_type = required_str(item, "item_type")?;
        if !item_type_allowed_for_class(class, item_type) {
            return Err(format!(
                "item_type {item_type} is not allowed in backup_class {}",
                class.as_str()
            ));
        }
    }
    Ok(())
}

fn validate_encryption(body: &Value, class: KeyBackupClass) -> Result<(), String> {
    let encryption = body
        .get("encryption")
        .ok_or_else(|| "encryption is required".to_owned())?;
    let method = required_str(encryption, "recipient_method")?;
    let aead = encryption
        .get("aead")
        .ok_or_else(|| "encryption.aead is required".to_owned())?;
    let aead_name = required_str(aead, "name")?;
    if !matches!(aead_name, "xchacha20_poly1305" | "aes_256_gcm") {
        return Err("encryption.aead.name is unsupported".to_owned());
    }
    let nonce = required_str(aead, "nonce")?;
    if !is_base64url_token(nonce) || nonce.contains("placeholder") || nonce.contains("demo") {
        return Err("encryption.aead.nonce must be real base64url metadata".to_owned());
    }
    match method {
        "passphrase_kdf" => {
            if class == KeyBackupClass::MlsHistory {
                return Err("mls_history backups must use device_snapshot_secret".to_owned());
            }
            let kdf = encryption
                .get("kdf")
                .ok_or_else(|| "passphrase_kdf requires encryption.kdf".to_owned())?;
            validate_kdf(
                kdf,
                body.get("mixed_secret_storage").and_then(Value::as_bool) == Some(true),
            )?;
        }
        "device_snapshot_secret" => {
            if class != KeyBackupClass::MlsHistory {
                return Err(
                    "device_snapshot_secret is only valid for mls_history backups".to_owned(),
                );
            }
            let device_id = required_str(encryption, "recipient_key_ref")?;
            if !is_protocol_device_id(device_id) {
                return Err(
                    "device_snapshot_secret recipient_key_ref must be cx:device:<uuidv7>"
                        .to_owned(),
                );
            }
            if encryption.get("kdf").is_some() {
                return Err(
                    "device_snapshot_secret backups must not carry encryption.kdf".to_owned(),
                );
            }
        }
        other => return Err(format!("unsupported recipient_method {other}")),
    }
    Ok(())
}

fn validate_kdf(kdf: &Value, mixed_secret_storage: bool) -> Result<(), String> {
    let name = required_str(kdf, "name")?;
    let salt = required_str(kdf, "salt")?;
    if !is_base64url_token(salt) || salt.contains("demo") {
        return Err("kdf.salt must be real base64url metadata".to_owned());
    }
    let params = kdf
        .get("params")
        .ok_or_else(|| "kdf.params is required".to_owned())?;
    match name {
        "argon2id" => {
            let memory = required_u64(params, "memory_kib")?;
            let iterations = required_u64(params, "iterations")?;
            let parallelism = required_u64(params, "parallelism")?;
            let min_memory = if mixed_secret_storage {
                262_144
            } else {
                65_536
            };
            let min_iterations = if mixed_secret_storage { 4 } else { 3 };
            if memory < min_memory || iterations < min_iterations || parallelism < 1 {
                return Err("argon2id parameters below key backup profile floor".to_owned());
            }
        }
        "pbkdf2" => {
            let iterations = required_u64(params, "iterations")?;
            let hash = required_str(params, "hash")?;
            if iterations < 600_000 || !matches!(hash, "sha256" | "sha384" | "sha512") {
                return Err("pbkdf2 parameters below degraded profile floor".to_owned());
            }
            if kdf
                .get("degraded_profile_reason")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err("pbkdf2 key backup requires degraded_profile_reason".to_owned());
            }
        }
        _ => return Err("unsupported kdf.name".to_owned()),
    }
    Ok(())
}

fn validate_domain_separation(body: &Value, class: KeyBackupClass) -> Result<(), String> {
    let domain = body
        .get("domain_separation")
        .ok_or_else(|| "domain_separation metadata is required".to_owned())?;
    let subdomain = required_str(domain, "subdomain")?;
    let expected_info = key_backup_hkdf_info(class, subdomain);
    if required_str(domain, "hkdf_info")? != expected_info {
        return Err("domain_separation.hkdf_info does not match backup_class".to_owned());
    }
    let aad = domain
        .get("aead_aad")
        .ok_or_else(|| "domain_separation.aead_aad is required".to_owned())?;
    for key in ["actor_id", "backup_class", "backup_version", "created_at"] {
        if aad.get(key) != body.get(key) {
            return Err(format!("domain_separation.aead_aad.{key} mismatch"));
        }
    }
    if aad.get("schema").and_then(Value::as_str) != Some(KEY_BACKUP_SCHEMA) {
        return Err("domain_separation.aead_aad.schema mismatch".to_owned());
    }
    let expected_device = body
        .get("device_id")
        .or_else(|| {
            body.get("encryption")
                .and_then(|encryption| encryption.get("recipient_key_ref"))
        })
        .and_then(Value::as_str)
        .unwrap_or_default();
    if aad.get("device_id").and_then(Value::as_str) != Some(expected_device) {
        return Err("domain_separation.aead_aad.device_id mismatch".to_owned());
    }
    let expected_item_types = body
        .get("contents")
        .and_then(Value::as_array)
        .map(|contents| {
            contents
                .iter()
                .filter_map(|item| item.get("item_type").and_then(Value::as_str))
                .map(|item| Value::String(item.to_owned()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if aad.get("item_types").and_then(Value::as_array) != Some(&expected_item_types) {
        return Err("domain_separation.aead_aad.item_types mismatch".to_owned());
    }
    Ok(())
}

fn validate_mls_history_opaque_only(body: &Value) -> Result<(), String> {
    fn scan(value: &Value, path: &str) -> Result<(), String> {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    let key_lower = key.to_ascii_lowercase();
                    if matches!(
                        key_lower.as_str(),
                        "plaintext"
                            | "plain_text"
                            | "serialized_state"
                            | "state_bytes"
                            | "group_state"
                            | "passphrase"
                            | "mls_passphrase"
                            | "snapshot_secret"
                    ) {
                        return Err(format!(
                            "mls_history backups must not carry plaintext field {path}/{key}"
                        ));
                    }
                    let child_path = if path.is_empty() {
                        format!("/{key}")
                    } else {
                        format!("{path}/{key}")
                    };
                    scan(child, &child_path)?;
                }
                Ok(())
            }
            Value::Array(items) => {
                for (idx, child) in items.iter().enumerate() {
                    scan(child, &format!("{path}/{idx}"))?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    scan(body, "")
}

fn item_type_allowed_for_class(class: KeyBackupClass, item_type: &str) -> bool {
    match class {
        KeyBackupClass::DidRecovery => matches!(item_type, "recovery_key_share"),
        KeyBackupClass::SecretStorage => matches!(
            item_type,
            "self_signing_key"
                | "user_signing_key"
                | "recovery_secret"
                | "mls_account_secret"
                | "mls_group_secrets_backup_key"
                | "private_account_state"
        ),
        KeyBackupClass::MlsHistory => matches!(
            item_type,
            "mls_group_state" | "mls_epoch_secret" | "pending_welcome"
        ),
    }
}

fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} is required"))
}

fn required_u64(value: &Value, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{key} is required"))
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

fn is_protocol_backup_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("cx:backup:") else {
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

fn is_protocol_backup_series_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("cx:backup_series:") else {
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

fn is_base64url_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

fn is_sha_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit()))
        || value
            .strip_prefix("sha3_256:")
            .is_some_and(|hex| hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit()))
        || value
            .strip_prefix("blake3:")
            .is_some_and(|hex| hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit()))
        || value
            .strip_prefix("sha512:")
            .is_some_and(|hex| hex.len() == 128 && hex.chars().all(|ch| ch.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_recovery_vault_backup_body_carries_kdf_and_aead_metadata() {
        let body = build_recovery_vault_backup_body(
            "cx:backup:01964137-0000-7000-8000-00000000beef",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000001",
            "AAAA_CIPHERTEXT_B64",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "U0FMVF9CNjQ",
            "Tk9OQ0VfQjY0XzI0Ynl0ZXM",
            65_536,
            3,
            4,
        );
        assert_eq!(body["backup_class"], "secret_storage");
        assert!(
            body["series_id"]
                .as_str()
                .is_some_and(is_protocol_backup_series_id)
        );
        assert_eq!(body["series_seq"], 0);
        assert_eq!(body["encryption"]["recipient_method"], "passphrase_kdf");
        assert_eq!(body["encryption"]["kdf"]["name"], "argon2id");
        assert_eq!(body["encryption"]["kdf"]["salt"], "U0FMVF9CNjQ");
        assert_eq!(body["encryption"]["kdf"]["params"]["memory_kib"], 65_536);
        assert_eq!(body["encryption"]["kdf"]["params"]["iterations"], 3);
        assert_eq!(body["encryption"]["kdf"]["params"]["parallelism"], 4);
        assert_eq!(body["encryption"]["aead"]["name"], "xchacha20_poly1305");
        assert_eq!(
            body["encryption"]["aead"]["nonce"],
            "Tk9OQ0VfQjY0XzI0Ynl0ZXM"
        );
        assert_eq!(body["contents"][0]["item_type"], "recovery_secret");
        assert_eq!(body["ciphertext"], "AAAA_CIPHERTEXT_B64");
        assert_eq!(
            body["device_id"],
            "cx:device:01964137-0000-7000-8000-000000000001"
        );
        assert_eq!(
            body["domain_separation"]["hkdf_info"],
            "contrix-key-backup/secret_storage/recovery_vault/v1"
        );
        validate_key_backup_put_request("cx:backup:01964137-0000-7000-8000-00000000beef", &body)
            .expect("secret_storage recovery vault envelope should validate");
    }

    #[test]
    fn did_recovery_backup_uses_separate_domain() {
        let body = build_did_recovery_backup_body(
            "cx:backup:01964137-0000-7000-8000-00000000d1d0",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000001",
            "AAAA_CIPHERTEXT_B64",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "U0FMVF9ESURfUkVDT1ZFUlk",
            "Tk9OQ0VfRElEX1JFQ09WRVJZ",
        );

        assert_eq!(body["backup_class"], "did_recovery");
        assert!(
            body["series_id"]
                .as_str()
                .is_some_and(is_protocol_backup_series_id)
        );
        assert_eq!(body["series_seq"], 0);
        assert_eq!(body["contents"][0]["item_type"], "recovery_key_share");
        assert_eq!(
            body["domain_separation"]["hkdf_info"],
            "contrix-key-backup/did_recovery/recovery_policy/v1"
        );
        validate_key_backup_envelope(&body, Some(KeyBackupClass::DidRecovery))
            .expect("did_recovery envelope should validate");
    }

    #[test]
    fn key_backup_validator_rejects_cross_domain_item_mix() {
        let mut body = build_recovery_vault_backup_body(
            "cx:backup:01964137-0000-7000-8000-00000000beef",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000001",
            "AAAA_CIPHERTEXT_B64",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "U0FMVF9CNjQ",
            "Tk9OQ0VfQjY0XzI0Ynl0ZXM",
            65_536,
            3,
            1,
        );
        body["contents"][0]["item_type"] = json!("mls_group_state");
        attach_key_backup_domain_separation(
            &mut body,
            KeyBackupClass::SecretStorage,
            "recovery_vault",
        );

        let err = validate_key_backup_envelope(&body, Some(KeyBackupClass::SecretStorage))
            .expect_err("secret_storage must not carry MLS history items");
        assert!(err.contains("not allowed"));
    }

    #[test]
    fn key_backup_validator_rejects_missing_domain_separation() {
        let mut body = build_recovery_vault_backup_body(
            "cx:backup:01964137-0000-7000-8000-00000000beef",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000001",
            "AAAA_CIPHERTEXT_B64",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "U0FMVF9CNjQ",
            "Tk9OQ0VfQjY0XzI0Ynl0ZXM",
            65_536,
            3,
            1,
        );
        body.as_object_mut().unwrap().remove("domain_separation");

        let err = validate_key_backup_envelope(&body, Some(KeyBackupClass::SecretStorage))
            .expect_err("domain separation metadata is required");
        assert!(err.contains("domain_separation"));
    }

    #[test]
    fn key_backup_validator_rejects_missing_series_fields() {
        let mut body = build_recovery_vault_backup_body(
            "cx:backup:01964137-0000-7000-8000-00000000beef",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000001",
            "AAAA_CIPHERTEXT_B64",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "U0FMVF9CNjQ",
            "Tk9OQ0VfQjY0XzI0Ynl0ZXM",
            65_536,
            3,
            1,
        );
        body.as_object_mut().unwrap().remove("series_id");

        let err = validate_key_backup_envelope(&body, Some(KeyBackupClass::SecretStorage))
            .expect_err("series_id is mandatory");
        assert!(err.contains("series_id"));
    }

    #[test]
    fn mls_history_rejects_passphrase_kdf() {
        let mut body = build_recovery_vault_backup_body(
            "cx:backup:01964137-0000-7000-8000-00000000beef",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000001",
            "AAAA_CIPHERTEXT_B64",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "U0FMVF9CNjQ",
            "Tk9OQ0VfQjY0XzI0Ynl0ZXM",
            65_536,
            3,
            1,
        );
        body["backup_class"] = json!("mls_history");
        body["contents"][0]["item_type"] = json!("mls_group_state");
        attach_key_backup_domain_separation(&mut body, KeyBackupClass::MlsHistory, "mls_snapshot");

        let err = validate_key_backup_envelope(&body, Some(KeyBackupClass::MlsHistory))
            .expect_err("MLS history passphrase KDF backup must be rejected");
        assert!(err.contains("device_snapshot_secret"));
    }

    #[test]
    fn mls_history_rejects_obvious_plaintext_fields() {
        let envelope = crate::mls::persistence::encrypt_state(
            "cx:space:demo",
            "group-a",
            3,
            b"not real sdk state",
            "device-secret",
            b"salt",
        );
        let mut body = envelope.to_key_backup_body(
            "cx:backup:01964137-0000-7000-8000-00000000beef",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000001",
        );
        body["serialized_state"] = json!("plaintext sdk bytes");

        let err = validate_key_backup_envelope(&body, Some(KeyBackupClass::MlsHistory))
            .expect_err("MLS history backups must stay opaque");
        assert!(err.contains("plaintext field"));
    }

    #[test]
    fn key_backup_validator_rejects_weak_argon2id() {
        let mut body = build_recovery_vault_backup_body(
            "cx:backup:01964137-0000-7000-8000-00000000beef",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000001",
            "AAAA_CIPHERTEXT_B64",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "U0FMVF9CNjQ",
            "Tk9OQ0VfQjY0XzI0Ynl0ZXM",
            1,
            1,
            1,
        );
        attach_key_backup_domain_separation(
            &mut body,
            KeyBackupClass::SecretStorage,
            "recovery_vault",
        );

        let err = validate_key_backup_envelope(&body, Some(KeyBackupClass::SecretStorage))
            .expect_err("weak KDF parameters must be rejected");
        assert!(err.contains("argon2id"));
    }

    #[test]
    fn key_backup_put_request_rejects_path_body_mismatch() {
        let body = build_recovery_vault_backup_body(
            "cx:backup:01964137-0000-7000-8000-00000000beef",
            "did:web:alice.example",
            "cx:device:01964137-0000-7000-8000-000000000001",
            "AAAA_CIPHERTEXT_B64",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "U0FMVF9CNjQ",
            "Tk9OQ0VfQjY0XzI0Ynl0ZXM",
            65_536,
            3,
            1,
        );

        let err = validate_key_backup_put_request(
            "cx:backup:01964137-0000-7000-8000-00000000badd",
            &body,
        )
        .expect_err("path/body backup id mismatch must be rejected");
        assert!(err.contains("mismatch"));
    }

    #[test]
    fn delete_ownership_proof_binds_actor_and_backup() {
        assert_eq!(
            key_backup_delete_ownership_proof(
                "did:web:alice.example",
                "cx:backup:01964137-0000-7000-8000-00000000beef"
            ),
            "dev-ssk-delete:v1:did:web:alice.example:cx:backup:01964137-0000-7000-8000-00000000beef"
        );
    }
}
