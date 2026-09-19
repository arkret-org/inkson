//! Storage / path utility free functions for the local state store:
//! to-device dedup + expiry keys, read-cursor scope/key derivation, native
//! app-data-dir resolution, the hex codec, secure-store identity / DPoP key
//! load+store, and the plaintext-seed dev gate. All callers are the parent
//! `impl LocalStateStore` block and `local_state_tests.rs`; the glob
//! re-export keeps `super::*` resolution unchanged.

use super::*;

fn to_device_sender_dedup_key(
    sender: &arkret_sdk::DeviceMessageSender,
    device_message_id: &arkret_sdk::DeviceMessageId,
) -> String {
    match sender {
        arkret_sdk::DeviceMessageSender::Account {
            sender_account_id,
            sender_device_id,
        } => format!(
            "account:{}:{}|{}|{}",
            sender_account_id.principal_id.as_str(),
            sender_account_id.station_id.as_str(),
            sender_device_id.as_str(),
            device_message_id.as_str()
        ),
        arkret_sdk::DeviceMessageSender::Agent {
            sender_agent_id, ..
        } => format!(
            "agent:{}|{}",
            sender_agent_id.as_str(),
            device_message_id.as_str()
        ),
        arkret_sdk::DeviceMessageSender::Station { sender_id } => {
            format!(
                "station:{}|{}",
                sender_id.as_str(),
                device_message_id.as_str()
            )
        }
    }
}

pub(crate) fn to_device_envelope_dedup_key(envelope: &arkret_sdk::DeviceMessageEnvelope) -> String {
    to_device_sender_dedup_key(&envelope.sender, &envelope.device_message_id)
}

pub(crate) fn to_device_message_dedup_key(message: &Value) -> Result<String, String> {
    let envelope: arkret_sdk::DeviceMessageEnvelope = serde_json::from_value(message.clone())
        .map_err(|error| format!("invalid durable to-device envelope: {error}"))?;
    Ok(to_device_envelope_dedup_key(&envelope))
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

pub(crate) fn read_scope_for_cursor(_realm_id: &str, topic_id: Option<&str>) -> ReadCursorScope {
    match topic_id.map(str::trim).filter(|topic| !topic.is_empty()) {
        Some(topic) if topic.starts_with("ak:thread:") => ReadCursorScope::thread(topic),
        Some(topic) if topic.starts_with("ak:strand:") => {
            ReadCursorScope::strand(topic, Some("discussion"))
        }
        // A Realm id and its default Strand id are independently derived from
        // different accepted Events. When no authoritative topic coordinate is
        // available, retain the Realm scope instead of fabricating a Strand by
        // retyping the Realm token.
        _ => ReadCursorScope::realm(),
    }
}

/// Shared test fixture — build a `LocalStateStore` rooted at a
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

pub(crate) fn read_cursor_key(realm_id: &str, read_scope: &ReadCursorScope) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        realm_id,
        read_scope.kind.as_str(),
        read_scope.container_ref.as_deref().unwrap_or(""),
        read_scope.track.as_deref().unwrap_or("")
    )
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

pub(crate) fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

pub(crate) fn active_user_local_store()
-> Result<crate::secure_key_store::UserLocalStore, crate::secure_key_store::SecureKeyStoreError> {
    let scope = crate::secure_key_store::active_device_seed_scope().ok_or_else(|| {
        crate::secure_key_store::SecureKeyStoreError::Backend(
            "user local store is unavailable before an account authority/device is active"
                .to_owned(),
        )
    })?;
    crate::secure_key_store::UserLocalStore::new(scope.authority, scope.device_id)
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
    let key = active_user_local_store()?.secret_key(LocalStateStore::SECURE_IDENTITY_KEY);
    secure_store.store_secret(&key, &json)
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
    let key = active_user_local_store()?.secret_key(LocalStateStore::SECURE_DPOP_DEVICE_KEY);
    secure_store.store_secret(&key, &json)
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

pub(crate) async fn store_session_grant_in_user_secure_store_durable(
    user_store: &crate::secure_key_store::UserLocalStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    grant: &PersistedSessionGrant,
) -> Result<(), crate::secure_key_store::SecureKeyStoreError> {
    let json = serde_json::to_string(grant).map_err(|error| {
        crate::secure_key_store::SecureKeyStoreError::Backend(format!(
            "serialize session grant: {error}"
        ))
    })?;
    user_store
        .save_secret_durable(
            secure_store,
            LocalStateStore::SECURE_SESSION_GRANT_KEY,
            &json,
        )
        .await
}

#[cfg_attr(test, allow(dead_code))]
// The only caller
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

#[cfg(test)]
mod dedup_key_tests {
    use super::*;

    #[test]
    fn typed_sender_branches_use_the_closed_protocol_dedup_coordinates() {
        let message_id = arkret_sdk::DeviceMessageId::new(
            "ak:device_message:0196419b-0000-7000-8000-000000000071".to_owned(),
        )
        .unwrap();
        let senders = [
            (
                serde_json::json!({
                "sender_account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkfixturealice",
                    "station_id": "ak:did_core:webvh:z6mkfixturestation"
                },
                "sender_device_id": "ak:device:0196419b-0000-7000-8000-000000000001"
                }),
                "account:ak:did_core:webvh:z6mkfixturealice:ak:did_core:webvh:z6mkfixturestation|ak:device:0196419b-0000-7000-8000-000000000001|ak:device_message:0196419b-0000-7000-8000-000000000071",
            ),
            (
                serde_json::json!({
                "sender_agent_id": "ak:did_core:webvh:z6mkfixtureagent",
                "sender_agent_verification_method":
                    "did:webvh:z6mkfixtureagent:agent.example#agent-key-1",
                "sender_agent_key_authorize_event_id":
                    "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e"
                }),
                "agent:ak:did_core:webvh:z6mkfixtureagent|ak:device_message:0196419b-0000-7000-8000-000000000071",
            ),
            (
                serde_json::json!({
                "sender_id": "ak:did_core:webvh:z6mkfixturestation"
                }),
                "station:ak:did_core:webvh:z6mkfixturestation|ak:device_message:0196419b-0000-7000-8000-000000000071",
            ),
        ];
        let keys = senders
            .into_iter()
            .map(|(value, expected)| {
                let sender: arkret_sdk::DeviceMessageSender =
                    serde_json::from_value(value).unwrap();
                let key = to_device_sender_dedup_key(&sender, &message_id);
                assert_eq!(key, expected);
                key
            })
            .collect::<BTreeSet<_>>();

        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn agent_reauthorization_does_not_change_the_protocol_dedup_coordinate() {
        let message_id = arkret_sdk::DeviceMessageId::new(
            "ak:device_message:0196419b-0000-7000-8000-000000000071".to_owned(),
        )
        .unwrap();
        let sender = |method: &str, event_id: &str| {
            serde_json::from_value::<arkret_sdk::DeviceMessageSender>(serde_json::json!({
                "sender_agent_id": "ak:did_core:webvh:z6mkfixtureagent",
                "sender_agent_verification_method": method,
                "sender_agent_key_authorize_event_id": event_id
            }))
            .unwrap()
        };

        assert_eq!(
            to_device_sender_dedup_key(
                &sender(
                    "did:webvh:z6mkfixtureagent:agent.example#agent-key-1",
                    "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e"
                ),
                &message_id
            ),
            to_device_sender_dedup_key(
                &sender(
                    "did:webvh:z6mkfixtureagent:agent.example#agent-key-2",
                    "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1"
                ),
                &message_id
            )
        );
    }
}
