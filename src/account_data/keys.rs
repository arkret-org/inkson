//! `ak.account_data.set` operation envelope builders and private
//! account-data key derivation/validation helpers.

use serde_json::Value;

use crate::operation::TypedOperationBuilder;

/// Build a `ak.account_data.set` operation envelope for `key` -> `value`.
///
/// `key` is the registered namespace literal (an `arkret_wire::AccountDataKey`
/// constant) or a derived key from one of the helpers below — the same `&str`
/// the wire carries, not a re-encoded local vocabulary.
///
/// `ak.account_data.set` is classified `actor_private_event` in
/// `conformance.rs:393`; reducers MUST NOT include it in shared Realm state.
pub fn build_account_data_set(
    realm_id: &str,
    actor: &str,
    key: &str,
    value: Value,
    expected_revision: u64,
) -> anyhow::Result<TypedOperationBuilder> {
    let value_field = if private_account_data_key_prefix(key).is_some() {
        "encrypted_payload"
    } else {
        "body"
    };
    let (body, encrypted_payload) = if value_field == "encrypted_payload" {
        let Value::Object(value) = value else {
            anyhow::bail!("private account_data encrypted_payload must be an object");
        };
        (
            arkret_sdk::AccountDataBody::Absent,
            Some(value.into_iter().collect()),
        )
    } else {
        (arkret_sdk::AccountDataBody::Value(value), None)
    };
    let payload = arkret_sdk::AccountDataSetPayload {
        key: arkret_sdk::NonEmptyString::new(key).map_err(anyhow::Error::msg)?,
        expected_revision,
        body,
        encrypted_payload,
        tombstone: false,
        updated_at: Some(crate::clock::now_utc_millis()),
    };
    Ok(TypedOperationBuilder::new::<
        arkret_sdk::event_spec::AccountDataSet,
    >(realm_id, actor, payload))
}

pub fn build_account_data_tombstone(
    realm_id: &str,
    actor: &str,
    key: &str,
    expected_revision: u64,
) -> anyhow::Result<TypedOperationBuilder> {
    let payload = arkret_sdk::AccountDataSetPayload {
        key: arkret_sdk::NonEmptyString::new(key).map_err(anyhow::Error::msg)?,
        expected_revision,
        body: arkret_sdk::AccountDataBody::Absent,
        encrypted_payload: None,
        tombstone: true,
        updated_at: Some(crate::clock::now_utc_millis()),
    };
    Ok(TypedOperationBuilder::new::<
        arkret_sdk::event_spec::AccountDataSet,
    >(realm_id, actor, payload))
}

pub fn private_account_data_key_prefix(key: &str) -> Option<&'static str> {
    if let Some(prefix) = [
        arkret_sdk::AccountDataKey::CONTACTS_ACTOR,
        arkret_sdk::AccountDataKey::CONTACTS_REALM,
        arkret_sdk::AccountDataKey::VIEWS_PRIVATE,
        arkret_sdk::AccountDataKey::NOTIFICATIONS_INBOX,
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

pub fn scheduled_send_account_data_key(scheduled_send_id: &str) -> anyhow::Result<String> {
    let scheduled_send_id = arkret_identifiers::ScheduledSendId::new(scheduled_send_id.to_owned())
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(arkret_sdk::scheduled_send_account_data_key(
        &scheduled_send_id,
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

pub fn private_view_account_data_key(view_id: &str) -> anyhow::Result<String> {
    let view_id = arkret_sdk::ViewId::new(view_id.to_owned())
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(arkret_sdk::private_view_account_data_key(&view_id))
}

pub fn notification_inbox_account_data_key(notification_id: &str) -> anyhow::Result<String> {
    let notification_id = arkret_sdk::NotificationId::new(notification_id.to_owned())
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(arkret_sdk::notification_inbox_account_data_key(
        &notification_id,
    ))
}

pub fn build_private_account_data_set(
    realm_id: &str,
    actor: &str,
    key: &str,
    encrypted_payload: Value,
    expected_revision: u64,
) -> anyhow::Result<TypedOperationBuilder> {
    validate_private_account_data_key(key)?;
    let Value::Object(encrypted_payload) = encrypted_payload else {
        anyhow::bail!("private account_data encrypted_payload must be an object");
    };
    let payload = arkret_sdk::AccountDataSetPayload {
        key: arkret_sdk::NonEmptyString::new(key).map_err(anyhow::Error::msg)?,
        expected_revision,
        body: arkret_sdk::AccountDataBody::Absent,
        encrypted_payload: Some(encrypted_payload.into_iter().collect()),
        tombstone: false,
        updated_at: Some(crate::clock::now_utc_millis()),
    };
    Ok(TypedOperationBuilder::new::<
        arkret_sdk::event_spec::AccountDataSet,
    >(realm_id, actor, payload))
}

pub fn build_private_account_data_tombstone(
    realm_id: &str,
    actor: &str,
    key: &str,
    expected_revision: u64,
) -> anyhow::Result<TypedOperationBuilder> {
    validate_private_account_data_key(key)?;
    let payload = arkret_sdk::AccountDataSetPayload {
        key: arkret_sdk::NonEmptyString::new(key).map_err(anyhow::Error::msg)?,
        expected_revision,
        body: arkret_sdk::AccountDataBody::Absent,
        encrypted_payload: None,
        tombstone: true,
        updated_at: Some(crate::clock::now_utc_millis()),
    };
    Ok(TypedOperationBuilder::new::<
        arkret_sdk::event_spec::AccountDataSet,
    >(realm_id, actor, payload))
}
