//! Storage / path / at-rest-crypto utility free functions for the local
//! state store: to-device dedup + expiry keys, read-cursor scope/key
//! derivation, browser/native storage + app-data-dir resolution, the XOR
//! at-rest cipher + hex codec, secure-store identity / DPoP key load+store,
//! the plaintext-seed dev gate, and snapshot encrypted-payload extraction.
//! Moved out of `local_state.rs` (YOU-07-001, move only) — all callers are the
//! parent `impl LocalStateStore` block and `local_state_tests.rs`; the glob
//! re-export keeps `super::*` resolution unchanged.

use super::*;

pub(crate) fn to_device_message_dedup_key(message: &Value) -> String {
    let sender = message
        .get("sender_principal_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let sender_device = message
        .get("sender_device_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let message_id = message
        .get("message_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    format!("{sender}|{sender_device}|{message_id}")
}

pub(crate) fn to_device_message_expired(message: &Value, now: DateTime<Utc>) -> bool {
    to_device_message_expiry(message)
        .map(|expires_at| expires_at <= now)
        .unwrap_or(false)
}

pub(crate) fn to_device_message_expiry(message: &Value) -> Option<DateTime<Utc>> {
    message
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|expires_at| expires_at.with_timezone(&Utc))
}

pub(crate) fn read_scope_for_cursor(_realm_id: &str, topic_id: Option<&str>) -> ReadScope {
    match topic_id.map(str::trim).filter(|topic| !topic.is_empty()) {
        Some(topic) if topic.starts_with("ak:thread:") => ReadScope::thread(topic),
        Some(topic) if topic.starts_with("ak:strand:") => {
            ReadScope::strand(topic, Some("discussion"))
        }
        // A Realm id and its default Strand id are independently derived from
        // different accepted Events. When no authoritative topic coordinate is
        // available, retain the Realm scope instead of fabricating a Strand by
        // retyping the Realm token.
        _ => ReadScope::realm(),
    }
}

/// YOU-05-010: shared test fixture — build a `LocalStateStore` rooted at a
/// unique temp file so tests never read or pollute the developer's real
/// `state.json` (or the `INKSON_STATE_PATH` override). On wasm32 the
/// default store is memory-only and therefore already hermetic. The `tag`
/// keeps any leftover temp file attributable to the test that created it;
/// uniqueness comes from the uuid_v7 suffix.
#[cfg(test)]
pub(crate) fn isolated_store_for_tests(tag: &str) -> LocalStateStore {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let path = std::env::temp_dir().join(format!(
            "inkson-test-{tag}-{}.json",
            crate::operation::uuid_v7()
        ));
        LocalStateStore::with_path(path)
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = tag;
        LocalStateStore::default()
    }
}

pub(crate) fn new_read_cursor_id() -> String {
    format!("ak:read_cursor:{}", crate::operation::uuid_v7())
}

pub(crate) fn read_cursor_key(realm_id: &str, read_scope: &ReadScope) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        realm_id,
        read_scope.kind.as_str(),
        read_scope.container_ref.as_deref().unwrap_or(""),
        read_scope.track.as_deref().unwrap_or("")
    )
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn browser_storage() -> Option<web_sys::Storage> {
    web_sys::window().and_then(|window| window.local_storage().ok().flatten())
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn default_state_path() -> PathBuf {
    std::env::var_os("INKSON_STATE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| app_data_dir().join("state.json"))
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn app_data_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("APPDATA"))
        .or_else(|| std::env::var_os("HOME").map(|home| Path::new(&home).join(".config").into()))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("inkson")
}

/// Reversible XOR obfuscation for **non-sensitive** client-side preferences.
///
/// This is NOT encryption: the key is the public `account_did()` (recomputable
/// by anyone holding the on-disk data) and XOR is trivially invertible. It only
/// keeps UI preferences (theme, avatar ref, sidebar width, recovery-hint
/// markers) from being casually readable as plaintext on disk. NEVER route
/// secret material (seeds, private keys, tokens) through this — use the OS
/// keychain / non-exportable SubtleCrypto path instead.
///
/// The same function obfuscates and de-obfuscates since XOR is its own inverse.
pub(crate) fn obfuscate_nonsensitive(key: &str, data: &str) -> String {
    let key_bytes = key.as_bytes();
    if key_bytes.is_empty() {
        return data.to_owned();
    }
    let encrypted: Vec<u8> = data
        .bytes()
        .enumerate()
        .map(|(i, b)| b ^ key_bytes[i % key_bytes.len()])
        .collect();
    // Encode as hex for safe storage
    crate::canonical::hex_encode(&encrypted)
}

/// Decode hex-encoded [`obfuscate_nonsensitive`] output back to plaintext.
pub(crate) fn deobfuscate_nonsensitive(key: &str, hex_data: &str) -> Option<String> {
    let key_bytes = key.as_bytes();
    if key_bytes.is_empty() {
        return Some(hex_data.to_owned());
    }
    let bytes = hex_to_bytes(hex_data)?;
    let decrypted: Vec<u8> = bytes
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()])
        .collect();
    String::from_utf8(decrypted).ok()
}

pub(crate) fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

pub(crate) fn load_identity_record_from_secure_store(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Option<LocalIdentityRecord> {
    #[cfg(target_arch = "wasm32")]
    if let Err(error) =
        crate::secure_key_store::require_wasm_indexeddb_ed25519_seed_store(secure_store)
    {
        tracing::warn!(?error, "secure identity read refused on wasm");
        return None;
    }
    match secure_store.get_secret(LocalStateStore::SECURE_IDENTITY_KEY) {
        Ok(Some(json)) => serde_json::from_str(&json).ok(),
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(?error, "secure identity read failed");
            None
        }
    }
}

pub(crate) fn store_identity_record_in_secure_store(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    record: &LocalIdentityRecord,
) -> Result<(), crate::secure_key_store::SecureKeyStoreError> {
    crate::secure_key_store::require_wasm_indexeddb_ed25519_seed_store(secure_store)?;
    let json = serde_json::to_string(record).map_err(|error| {
        crate::secure_key_store::SecureKeyStoreError::Backend(format!(
            "serialize identity record: {error}"
        ))
    })?;
    secure_store.store_secret(LocalStateStore::SECURE_IDENTITY_KEY, &json)
}

pub(crate) fn load_dpop_device_key_from_secure_store(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Result<Option<DpopDeviceKeyRecord>, crate::secure_key_store::SecureKeyStoreError> {
    let Some(json) =
        secure_store.get_secret(&crate::secure_key_store::account_scoped_device_key(
            LocalStateStore::SECURE_DPOP_DEVICE_KEY,
        ))?
    else {
        return Ok(None);
    };
    let record = serde_json::from_str(&json).map_err(|error| {
        crate::secure_key_store::SecureKeyStoreError::Backend(format!(
            "parse DPoP device key record: {error}"
        ))
    })?;
    Ok(Some(record))
}

pub(crate) fn store_dpop_device_key_in_secure_store(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    record: &DpopDeviceKeyRecord,
) -> Result<(), crate::secure_key_store::SecureKeyStoreError> {
    let json = serde_json::to_string(record).map_err(|error| {
        crate::secure_key_store::SecureKeyStoreError::Backend(format!(
            "serialize DPoP device key record: {error}"
        ))
    })?;
    secure_store.store_secret(
        &crate::secure_key_store::account_scoped_device_key(
            LocalStateStore::SECURE_DPOP_DEVICE_KEY,
        ),
        &json,
    )
}

pub(crate) fn load_session_grant_from_secure_store(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Result<Option<PersistedSessionGrant>, crate::secure_key_store::SecureKeyStoreError> {
    let key = crate::secure_key_store::account_scoped_device_key(
        LocalStateStore::SECURE_SESSION_GRANT_KEY,
    );
    let Some(json) = secure_store.get_secret(&key)? else {
        return Ok(None);
    };
    serde_json::from_str(&json).map(Some).map_err(|error| {
        crate::secure_key_store::SecureKeyStoreError::Backend(format!(
            "parse session grant: {error}"
        ))
    })
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn store_session_grant_in_secure_store(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    grant: &PersistedSessionGrant,
) -> Result<(), crate::secure_key_store::SecureKeyStoreError> {
    let json = serde_json::to_string(grant).map_err(|error| {
        crate::secure_key_store::SecureKeyStoreError::Backend(format!(
            "serialize session grant: {error}"
        ))
    })?;
    secure_store.store_secret(
        &crate::secure_key_store::account_scoped_device_key(
            LocalStateStore::SECURE_SESSION_GRANT_KEY,
        ),
        &json,
    )
}

pub(crate) fn plaintext_identity_seed_fallback_allowed() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        cfg!(test)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        cfg!(test)
            || std::env::var("INKSON_ALLOW_PLAINTEXT_IDENTITY_SEED")
                .ok()
                .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
    }
}

pub(crate) fn snapshot_item_encrypted_payload(
    item: &arkret_sdk::SnapshotMaterializedItem,
) -> Option<EncryptedPayload> {
    let schema = item
        .object
        .get("schema")
        .or_else(|| item.object.get("type"))
        .and_then(Value::as_str);
    let is_envelope = item.kind == "ak.schema.encrypted_envelope.v1"
        || schema == Some("ak.schema.encrypted_envelope.v1");
    if !is_envelope {
        return None;
    }
    serde_json::from_value(item.object.clone()).ok()
}
