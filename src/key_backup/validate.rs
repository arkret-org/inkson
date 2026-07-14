use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::Value;

use super::{
    BackupClass, KEY_BACKUP_SCHEMA, is_base64url_token, is_protocol_backup_id,
    is_protocol_backup_series_id, is_protocol_device_id, is_sha_digest, key_backup_hkdf_info,
    required_str, required_u64,
};

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

/// Verify that a decrypted v1 keybag is byte-for-byte bound to the public
/// envelope metadata and to the managed-principal canonical set in HPKE AAD.
pub fn validate_key_backup_plaintext_binding(
    body: &Value,
    plaintext: &Value,
) -> Result<(), String> {
    if plaintext.get("schema").and_then(Value::as_str)
        != Some(crate::key_backup::KEY_BACKUP_PLAINTEXT_SCHEMA)
    {
        return Err("key-backup plaintext schema mismatch".to_owned());
    }
    for field in ["backup_id", "backup_class", "series_id", "series_seq"] {
        if body.get(field) != plaintext.get(field) {
            return Err(format!(
                "key-backup plaintext {field} does not match its envelope"
            ));
        }
    }
    let public_items = body
        .get("contents")
        .and_then(Value::as_array)
        .ok_or_else(|| "key-backup envelope contents must be an array".to_owned())?;
    let plaintext_items = plaintext
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| "key-backup plaintext items must be an array".to_owned())?;
    if public_items.len() != plaintext_items.len() {
        return Err("key-backup public/plaintext item counts differ".to_owned());
    }
    for (public, secret) in public_items.iter().zip(plaintext_items) {
        for field in [
            "item_type",
            "realm_id",
            "managed_principal_binding",
            "mls_group_id",
            "epoch",
        ] {
            if public.get(field) != secret.get(field) {
                return Err(format!(
                    "key-backup plaintext item {field} does not match public contents"
                ));
            }
        }
        let secret_b64u = secret
            .get("secret_b64u")
            .and_then(Value::as_str)
            .ok_or_else(|| "key-backup plaintext secret_b64u is missing".to_owned())?;
        B64.decode(secret_b64u.as_bytes())
            .map_err(|error| format!("key-backup plaintext secret_b64u is invalid: {error}"))?;
    }
    let canonical_bindings = |items: &[Value]| -> Result<Vec<Value>, String> {
        items
            .iter()
            .filter_map(|item| item.get("managed_principal_binding").cloned())
            .map(|binding| {
                let canonical = crate::canonical::canonical_json_bytes(&binding)
                    .map_err(|error| format!("canonicalize managed principal binding: {error}"))?;
                Ok((canonical, binding))
            })
            .collect::<Result<std::collections::BTreeMap<_, _>, String>>()
            .map(|bindings| bindings.into_values().collect())
    };
    let public_bindings = canonical_bindings(public_items)?;
    let plaintext_bindings = canonical_bindings(plaintext_items)?;
    let aad_bindings = body
        .pointer("/domain_separation/aead_aad/managed_principal_bindings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if public_bindings != plaintext_bindings || public_bindings != aad_bindings {
        return Err("key-backup public/plaintext/AAD managed binding sets differ".to_owned());
    }
    Ok(())
}

pub fn validate_key_backup_envelope(
    body: &Value,
    expected_class: Option<BackupClass>,
) -> Result<(), String> {
    let backup_id = required_str(body, "backup_id")?;
    if !is_protocol_backup_id(backup_id) {
        return Err("backup_id must be ak:backup:<uuidv7>".to_owned());
    }
    let series_id = required_str(body, "series_id")?;
    if !is_protocol_backup_series_id(series_id) {
        return Err("series_id must be ak:backup_series:<uuidv7>".to_owned());
    }
    if body.get("series_seq").and_then(Value::as_u64).is_none() {
        return Err("series_seq must be a non-negative integer".to_owned());
    }
    let actor_id = required_str(body, "actor_id")?;
    if !actor_id.starts_with("did:") {
        return Err("actor_id must be a DID".to_owned());
    }
    let class = BackupClass::try_from(required_str(body, "backup_class")?)?;
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
        return Err("device_id must be ak:device:<uuidv7> when present".to_owned());
    }

    validate_contents(body, class)?;
    validate_encryption(body, class)?;
    if class == BackupClass::MlsHistory {
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

fn validate_contents(body: &Value, class: BackupClass) -> Result<(), String> {
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

fn validate_encryption(body: &Value, class: BackupClass) -> Result<(), String> {
    let encryption = body
        .get("encryption")
        .ok_or_else(|| "encryption is required".to_owned())?;
    let method = required_str(encryption, "recipient_method")?;
    let aead = encryption
        .get("aead")
        .ok_or_else(|| "encryption.aead is required".to_owned())?;
    let aead_name = required_str(aead, "name")?;
    if !matches!(
        aead_name,
        "xchacha20_poly1305" | "aes_256_gcm" | "chacha20_poly1305"
    ) {
        return Err("encryption.aead.name is unsupported".to_owned());
    }
    // The wire AEAD `nonce` is required for the symmetric methods
    // (passphrase_kdf / secret_storage_key); HPKE (`recovery_public_key`)
    // derives its nonce internally and carries `enc` instead, so it is checked
    // in its own branch below.
    if method != "recovery_public_key" {
        let nonce = required_str(aead, "nonce")?;
        if !is_base64url_token(nonce) || nonce.contains("placeholder") || nonce.contains("demo") {
            return Err("encryption.aead.nonce must be real base64url metadata".to_owned());
        }
    }
    match method {
        "passphrase_kdf" => {
            // Spec §5.0.1 first-backup gate: a did_recovery envelope MUST encrypt
            // to recovery_public_key, while threshold / hardware factors live
            // in the recovery policy proof layer. passphrase_kdf alone is
            // forbidden because a single passphrase must not control DID
            // recovery.
            if class == BackupClass::DidRecovery {
                return Err(
                    "did_recovery backups must not use passphrase_kdf alone; use recovery_public_key or satisfy threshold/hardware factors in the recovery policy proof layer"
                        .to_owned(),
                );
            }
            if class == BackupClass::MlsHistory {
                return Err(
                    "mls_history backups must use secret_storage_key or recovery_public_key"
                        .to_owned(),
                );
            }
            let kdf = encryption
                .get("kdf")
                .ok_or_else(|| "passphrase_kdf requires encryption.kdf".to_owned())?;
            validate_kdf(
                kdf,
                body.get("mixed_secret_storage").and_then(Value::as_bool) == Some(true),
            )?;
            // Spec §7.5: passphrase_kdf MUST carry a producer-generated
            // `nonce_salt` (deterministic nonce transcript) and
            // `encryption.key_commitment` (wrong-passphrase fail-fast).
            let nonce_salt = aead
                .get("nonce_salt")
                .and_then(Value::as_str)
                .ok_or_else(|| "passphrase_kdf requires encryption.aead.nonce_salt".to_owned())?;
            if !is_base64url_token(nonce_salt) {
                return Err("encryption.aead.nonce_salt must be base64url".to_owned());
            }
            let key_commitment = required_str(encryption, "key_commitment")?;
            if !is_sha_digest(key_commitment) {
                return Err("key_commitment must be a sha digest".to_owned());
            }
        }
        "secret_storage_key" => {
            // mls_history (and secret_storage caches) are wrapped under a named
            // secret_storage key; recovered after the secret_storage root is
            // unlocked. recipient_key_ref names that key id (NOT a device id),
            // and no passphrase KDF travels on the wire.
            if !matches!(class, BackupClass::MlsHistory | BackupClass::SecretStorage) {
                return Err(
                    "secret_storage_key is only valid for mls_history or secret_storage backups"
                        .to_owned(),
                );
            }
            let key_ref = required_str(encryption, "recipient_key_ref")?;
            if key_ref.trim().is_empty() {
                return Err("secret_storage_key requires a non-empty recipient_key_ref".to_owned());
            }
            if encryption.get("kdf").is_some() {
                return Err("secret_storage_key backups must not carry encryption.kdf".to_owned());
            }
        }
        "recovery_public_key" => {
            // Spec §7.5.2: HPKE base-mode to the recovery public key. The KEM
            // encapsulation rides in `encryption.aead.enc`; no passphrase KDF,
            // no wire nonce, no nonce_salt/key_commitment (HPKE binds them).
            let key_ref = required_str(encryption, "recipient_key_ref")?;
            if key_ref.trim().is_empty() {
                return Err("recovery_public_key requires a non-empty recipient_key_ref".to_owned());
            }
            let enc = required_str(aead, "enc")?;
            if !is_base64url_token(enc) {
                return Err("recovery_public_key encryption.aead.enc must be base64url".to_owned());
            }
            if encryption.get("kdf").is_some() {
                return Err("recovery_public_key backups must not carry encryption.kdf".to_owned());
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
            if params.get("hash").is_some() {
                return Err("pbkdf2 params.hash is forbidden; use digest_algorithm".to_owned());
            }
            let digest_algorithm = required_str(params, "digest_algorithm")?;
            if iterations < 600_000 || !matches!(digest_algorithm, "sha256" | "sha384" | "sha512") {
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

fn validate_domain_separation(body: &Value, class: BackupClass) -> Result<(), String> {
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
    // SEC-04: the recipient-method binding in the AAD MUST agree with the
    // envelope's `encryption.recipient_method` / `recipient_key_ref`, so a
    // ciphertext can never be reinterpreted under a different recipient method.
    let encryption = body.get("encryption");
    let expected_method = encryption
        .and_then(|encryption| encryption.get("recipient_method"))
        .cloned()
        .unwrap_or(Value::Null);
    if aad.get("recipient_method").unwrap_or(&Value::Null) != &expected_method {
        return Err("domain_separation.aead_aad.recipient_method mismatch".to_owned());
    }
    let expected_key_ref = encryption
        .and_then(|encryption| encryption.get("recipient_key_ref"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if aad
        .get("recipient_key_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        != expected_key_ref
    {
        return Err("domain_separation.aead_aad.recipient_key_ref mismatch".to_owned());
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
    let expected_managed_bindings = body
        .get("contents")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("managed_principal_binding").cloned())
        .map(|binding| {
            let canonical = crate::canonical::canonical_json_bytes(&binding)
                .map_err(|error| format!("canonicalize managed principal binding: {error}"))?;
            Ok((canonical, binding))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>, String>>()?
        .into_values()
        .collect::<Vec<_>>();
    let actual_managed_bindings = aad
        .get("managed_principal_bindings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if actual_managed_bindings != expected_managed_bindings {
        return Err("domain_separation.aead_aad.managed_principal_bindings mismatch".to_owned());
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

fn item_type_allowed_for_class(class: BackupClass, item_type: &str) -> bool {
    match class {
        BackupClass::DidRecovery => matches!(item_type, "recovery_key_share"),
        BackupClass::SecretStorage => matches!(
            item_type,
            "self_signing_key"
                | "user_signing_key"
                | "recovery_secret"
                | "mls_account_secret"
                | "mls_private_plaintext"
                | "mls_group_secrets_backup_key"
                | "private_account_state"
        ),
        BackupClass::MlsHistory => matches!(
            item_type,
            "mls_group_state" | "mls_epoch_secret" | "pending_welcome"
        ),
    }
}
