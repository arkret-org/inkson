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
    expected_revision: u64,
) -> OperationBuilder {
    let value_field = if private_account_data_key_prefix(key.as_wire()).is_some() {
        "encrypted_payload"
    } else {
        "body"
    };
    let mut payload = serde_json::json!({
        "key": key.as_wire(),
        "owner": actor,
        "expected_revision": expected_revision,
        "updated_at": arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now()),
    });
    payload[value_field] = value;
    OperationBuilder::new(realm_id, actor, arkret_sdk::EventKind::AccountDataSet).body(payload)
}

pub fn build_account_data_tombstone(
    realm_id: &str,
    actor: &str,
    key: &AccountDataKey,
    expected_revision: u64,
) -> OperationBuilder {
    OperationBuilder::new(realm_id, actor, arkret_sdk::EventKind::AccountDataSet).body(
        serde_json::json!({
            "key": key.as_wire(),
            "owner": actor,
            "expected_revision": expected_revision,
            "tombstone": true,
            "updated_at": arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now()),
        }),
    )
}

pub fn private_account_data_key_prefix(key: &str) -> Option<&'static str> {
    if let Some(prefix) = [
        arkret_sdk::AccountDataKey::CONTACTS_ACTOR,
        arkret_sdk::AccountDataKey::CONTACTS_REALM,
    ]
    .into_iter()
    .find(|prefix| {
        key.strip_prefix(*prefix)
            .is_some_and(|rest| rest.starts_with('.'))
    }) {
        return Some(prefix);
    }

    [
        arkret_sdk::AccountDataKey::REMINDERS_V1,
        arkret_sdk::AccountDataKey::SCHEDULED_SEND_V1,
        arkret_sdk::AccountDataKey::SNOOZE_V1,
        arkret_sdk::AccountDataKey::SAVED_V1,
        arkret_sdk::AccountDataKey::DRAFT_V1,
        arkret_sdk::AccountDataKey::FILE_TRANSFER_V1,
        arkret_sdk::AccountDataKey::SEARCH_INDEX_MANIFEST_V1,
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
    expected_revision: u64,
) -> anyhow::Result<OperationBuilder> {
    validate_private_account_data_key(key)?;
    let payload = serde_json::json!({
        "key": key,
        "owner": actor,
        "expected_revision": expected_revision,
        "encrypted_payload": encrypted_payload,
        "updated_at": arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now()),
    });
    Ok(OperationBuilder::new(realm_id, actor, arkret_sdk::EventKind::AccountDataSet).body(payload))
}

pub fn build_private_account_data_tombstone(
    realm_id: &str,
    actor: &str,
    key: &str,
    expected_revision: u64,
) -> anyhow::Result<OperationBuilder> {
    validate_private_account_data_key(key)?;
    Ok(
        OperationBuilder::new(realm_id, actor, arkret_sdk::EventKind::AccountDataSet).body(
            serde_json::json!({
                "key": key,
                "owner": actor,
                "expected_revision": expected_revision,
                "tombstone": true,
                "updated_at": arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now()),
            }),
        ),
    )
}
