//! `ak.account_data.set` operation envelope builders and private
//! account-data key derivation/validation helpers.

use serde_json::Value;

use super::AccountDataKey;
use crate::operation::OperationBuilder;

/// Build a `ak.account_data.set` operation envelope for `key` -> `value`.
///
/// `ak.account_data.set` is classified `actor_private_event` in
/// `conformance.rs:393`; reducers MUST NOT include it in shared Realm state.
pub fn build_account_data_set(
    realm_id: &str,
    actor: &str,
    key: &AccountDataKey,
    value: Value,
) -> OperationBuilder {
    let value_field = if private_account_data_key_prefix(key.as_wire()).is_some() {
        "encrypted_payload"
    } else {
        "body"
    };
    let mut payload = serde_json::json!({
        "key": key.as_wire(),
        "owner": actor,
        "updated_at": arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now()),
    });
    payload[value_field] = value;
    OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::AccountDataSet,
    )
    .body(payload)
}

pub fn build_account_data_tombstone(
    realm_id: &str,
    actor: &str,
    key: &AccountDataKey,
) -> OperationBuilder {
    OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::AccountDataSet,
    )
    .body(serde_json::json!({
        "key": key.as_wire(),
        "owner": actor,
        "tombstone": true,
        "updated_at": arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now()),
    }))
}

pub fn private_account_data_key_prefix(key: &str) -> Option<&'static str> {
    if let Some(prefix) = [
        arkret_sdk::ACCOUNT_DATA_TYPE_CONTACTS_ACTOR,
        arkret_sdk::ACCOUNT_DATA_TYPE_CONTACTS_REALM,
    ]
    .into_iter()
    .find(|prefix| {
        key.strip_prefix(*prefix)
            .is_some_and(|rest| rest.starts_with('.'))
    }) {
        return Some(prefix);
    }

    [
        arkret_sdk::ACCOUNT_DATA_TYPE_REMINDER,
        arkret_sdk::ACCOUNT_DATA_TYPE_SCHEDULED_SEND,
        arkret_sdk::ACCOUNT_DATA_TYPE_SNOOZE,
        arkret_sdk::ACCOUNT_DATA_TYPE_SAVED,
        arkret_sdk::ACCOUNT_DATA_TYPE_DRAFT,
        arkret_sdk::ACCOUNT_DATA_TYPE_FILE_TRANSFER,
        arkret_sdk::ACCOUNT_DATA_TYPE_SEARCH_INDEX_MANIFEST,
    ]
    .into_iter()
    .find(|prefix| {
        key.strip_prefix(*prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(':'))
    })
}

pub fn validate_private_account_data_key(key: &str) -> anyhow::Result<()> {
    arkret_sdk::validate_private_account_data_key(key)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

pub fn reminder_account_data_key(id: &str) -> anyhow::Result<String> {
    arkret_sdk::reminder_account_data_key(id).map_err(|error| anyhow::anyhow!(error.to_string()))
}

pub fn scheduled_send_account_data_key(planned_message_id: &str) -> anyhow::Result<String> {
    let planned_message_id = arkret_sdk::MessageId::new(planned_message_id.to_owned())
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(arkret_sdk::scheduled_send_account_data_key(
        &planned_message_id,
    ))
}

pub fn snooze_account_data_key(namespace_key: &[u8], target_ref: &str) -> anyhow::Result<String> {
    arkret_sdk::snooze_account_data_key(namespace_key, target_ref)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

pub fn saved_account_data_key(
    namespace_key: &[u8],
    collection_title: &str,
    target_ref: &str,
) -> anyhow::Result<String> {
    arkret_sdk::saved_account_data_key(namespace_key, collection_title, target_ref)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

pub fn draft_account_data_key(
    namespace_key: &[u8],
    kind: arkret_sdk::DraftKind,
    target_ref: &str,
    draft_slot: &str,
) -> anyhow::Result<String> {
    arkret_sdk::draft_account_data_key(namespace_key, kind, target_ref, draft_slot)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

pub fn search_index_manifest_account_data_key(
    namespace_key: &[u8],
    realm_id: &str,
) -> anyhow::Result<String> {
    let realm_id = arkret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    arkret_sdk::search_index_manifest_account_data_key(namespace_key, &realm_id)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

pub fn file_transfer_account_data_key(
    namespace_key: &[u8],
    transfer_id: &str,
) -> anyhow::Result<String> {
    arkret_sdk::file_transfer_account_data_key(namespace_key, transfer_id)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

pub fn build_private_account_data_set(
    realm_id: &str,
    actor: &str,
    key: &str,
    encrypted_payload: Value,
) -> anyhow::Result<OperationBuilder> {
    build_private_account_data_set_with_cas(realm_id, actor, key, encrypted_payload, None)
}

pub fn build_private_account_data_set_with_cas(
    realm_id: &str,
    actor: &str,
    key: &str,
    encrypted_payload: Value,
    expected_state_digest: Option<&str>,
) -> anyhow::Result<OperationBuilder> {
    validate_private_account_data_key(key)?;
    let mut payload = serde_json::json!({
        "key": key,
        "owner": actor,
        "encrypted_payload": encrypted_payload,
        "updated_at": arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now()),
    });
    if let Some(expected_state_digest) = expected_state_digest {
        validate_sha256_digest(expected_state_digest)?;
        payload["expected_state_digest"] = Value::String(expected_state_digest.to_owned());
    }
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::AccountDataSet,
    )
    .body(payload))
}

pub fn build_private_account_data_tombstone(
    realm_id: &str,
    actor: &str,
    key: &str,
) -> anyhow::Result<OperationBuilder> {
    validate_private_account_data_key(key)?;
    Ok(OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::AccountDataSet,
    )
    .body(serde_json::json!({
        "key": key,
        "owner": actor,
        "tombstone": true,
        "updated_at": arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now()),
    })))
}

fn validate_sha256_digest(value: &str) -> anyhow::Result<()> {
    // State digests are pinned to sha256 here, so require that prefix, then
    // delegate the hex/casing grammar to the single canonical validator
    // `arkret_sdk::Hash::new` instead of re-deriving the rule locally.
    if value.strip_prefix("sha256:").is_none() {
        anyhow::bail!("expected_state_digest must use sha256:<hex>");
    }
    if arkret_sdk::Hash::new(value).is_err() {
        anyhow::bail!("expected_state_digest must be a lowercase sha256 digest");
    }
    Ok(())
}
