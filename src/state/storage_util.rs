//! Storage / path / at-rest-crypto utility free functions for the local
//! state store: to-device dedup + expiry keys, read-cursor scope/key
//! derivation, browser/native storage + app-data-dir resolution, the XOR
//! at-rest cipher + hex codec, secure-store identity / DPoP key load+store,
//! the plaintext-seed dev gate, and snapshot encrypted-payload extraction.
//! Moved out of `local_state.rs` (YOU-07-001, move only) — all callers are the
//! parent `impl LocalStateStore` block and `local_state_tests.rs`; the glob
//! re-export keeps `super::*` resolution unchanged.

use arkret_wire::SchemaId;

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
    let device_message_id = message
        .get("device_message_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    format!("{sender}|{sender_device}|{device_message_id}")
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

pub(super) fn active_user_local_store()
-> Result<crate::secure_key_store::UserLocalStore, crate::secure_key_store::SecureKeyStoreError> {
    let principal = crate::secure_key_store::active_device_seed_scope().ok_or_else(|| {
        crate::secure_key_store::SecureKeyStoreError::Backend(
            "user local store is unavailable before a principal core id is active".to_owned(),
        )
    })?;
    user_local_store_for_principal(&principal)
}

pub(super) fn user_local_store_for_principal(
    principal: &str,
) -> Result<crate::secure_key_store::UserLocalStore, crate::secure_key_store::SecureKeyStoreError> {
    let core_id = match arkret_sdk::DidCoreId::new(principal.to_owned()) {
        Ok(core_id) => core_id,
        Err(_) => {
            let full_id = arkret_sdk::DidFullId::new(principal.to_owned()).map_err(|error| {
                crate::secure_key_store::SecureKeyStoreError::Backend(format!(
                    "principal id is invalid: {error}"
                ))
            })?;
            arkret_sdk::project_full_id_to_core_id(&full_id).map_err(|error| {
                crate::secure_key_store::SecureKeyStoreError::Backend(format!(
                    "principal cannot be projected to core id: {error}"
                ))
            })?
        }
    };
    Ok(crate::secure_key_store::UserLocalStore::new(core_id))
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
    let user_store = match active_user_local_store() {
        Ok(user_store) => user_store,
        Err(error) => {
            tracing::warn!(?error, "secure identity read skipped without user scope");
            return None;
        }
    };
    match user_store.load_secret(secure_store, LocalStateStore::SECURE_IDENTITY_KEY) {
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
    active_user_local_store()?.save_secret(
        secure_store,
        LocalStateStore::SECURE_IDENTITY_KEY,
        &json,
    )
}

pub(crate) fn load_dpop_device_key_from_secure_store(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Result<Option<DpopDeviceKeyRecord>, crate::secure_key_store::SecureKeyStoreError> {
    let Some(json) = active_user_local_store()?
        .load_secret(secure_store, LocalStateStore::SECURE_DPOP_DEVICE_KEY)?
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
    active_user_local_store()?.save_secret(
        secure_store,
        LocalStateStore::SECURE_DPOP_DEVICE_KEY,
        &json,
    )
}

pub(crate) fn load_session_grant_from_user_secure_store(
    user_store: &crate::secure_key_store::UserLocalStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Result<Option<PersistedSessionGrant>, crate::secure_key_store::SecureKeyStoreError> {
    let Some(json) =
        user_store.load_secret(secure_store, LocalStateStore::SECURE_SESSION_GRANT_KEY)?
    else {
        return Ok(None);
    };
    serde_json::from_str(&json).map(Some).map_err(|error| {
        crate::secure_key_store::SecureKeyStoreError::Backend(format!(
            "parse session grant: {error}"
        ))
    })
}

#[cfg_attr(test, allow(dead_code))]
// Counterpart of `store_session_grant_in_secure_store` below. The only caller
// is `app::secure_store_effects::apply_test_session_grant_expiry_override`,
// which is gated on the same cfg, so this carries the caller's cfg rather than
// an `allow(dead_code)`. Do not delete it as an "uncalled thin wrapper": a
// native-host build (including `--all-features`) never compiles the call site,
// so a plain reachability scan cannot see it. The joint-e2e web fixture build
// (`dx build --platform web --features wasm-localstorage-secrets-test`) does.
#[cfg(all(target_arch = "wasm32", feature = "wasm-localstorage-secrets-test"))]
pub(crate) fn load_session_grant_from_secure_store(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Result<Option<PersistedSessionGrant>, crate::secure_key_store::SecureKeyStoreError> {
    load_session_grant_from_user_secure_store(&active_user_local_store()?, secure_store)
}

pub(crate) fn store_session_grant_in_secure_store(
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    grant: &PersistedSessionGrant,
) -> Result<(), crate::secure_key_store::SecureKeyStoreError> {
    store_session_grant_in_user_secure_store(&active_user_local_store()?, secure_store, grant)
}

pub(crate) fn store_session_grant_in_user_secure_store(
    user_store: &crate::secure_key_store::UserLocalStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    grant: &PersistedSessionGrant,
) -> Result<(), crate::secure_key_store::SecureKeyStoreError> {
    let json = serde_json::to_string(grant).map_err(|error| {
        crate::secure_key_store::SecureKeyStoreError::Backend(format!(
            "serialize session grant: {error}"
        ))
    })?;
    user_store.save_secret(
        secure_store,
        LocalStateStore::SECURE_SESSION_GRANT_KEY,
        &json,
    )
}

/// Whether the device identity seed may live in the plaintext local-state
/// blob instead of the [`SecureKeyStore`](crate::secure_key_store::SecureKeyStore).
///
/// Unit tests only, on every target. A shipped build — debug or release,
/// native or wasm — has **no** way to turn this on: when the secure store is
/// unavailable, identity bootstrap fails with a diagnosable error rather than
/// silently writing an Ed25519 seed where a disk dump can read it. There is
/// deliberately no environment variable, config key, or feature that relaxes
/// this; a developer without a working keyring is meant to fix the keyring.
pub(crate) fn plaintext_identity_seed_fallback_allowed() -> bool {
    cfg!(test)
}

pub(crate) fn snapshot_item_encrypted_payload(
    item: &arkret_sdk::SnapshotMaterializedItem,
) -> Option<EncryptedPayload> {
    let schema = item.object.get("schema").and_then(Value::as_str);
    let is_envelope = item.kind == SchemaId::ENCRYPTED_ENVELOPE_V1
        || schema == Some(SchemaId::ENCRYPTED_ENVELOPE_V1);
    if !is_envelope {
        return None;
    }
    serde_json::from_value(item.object.clone()).ok()
}
