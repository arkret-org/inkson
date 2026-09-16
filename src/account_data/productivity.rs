//! Personal productivity account-data helpers for draft sync and saved items.

use std::cmp::Ordering;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use serde_json::Value;
use sha2::Sha256;

use crate::canonical::{canonical_sha256, validate_timestamp_canonical};

/// Spec `models/personal-productivity.md` §4: a scheduled-send plan MUST NOT
/// pre-mint, cache, or imply the future Event / Message identity, so the
/// stored `message_payload` carries neither `event_id` nor `message_id`. The
/// typed `MessageCreatePayload` structurally has no such fields (its
/// `deny_unknown_fields` serde bound rejects them on decode); this check is
/// the explicit spec-facing guard on the serialized form.
fn validate_message_payload_omits_event_identity(
    message_payload: &arkret_sdk::MessageCreatePayload,
) -> anyhow::Result<()> {
    let serialized = serde_json::to_value(message_payload)?;
    let Some(object) = serialized.as_object() else {
        anyhow::bail!("scheduled_send message_payload must serialize to an object");
    };
    if object.contains_key("event_id") || object.contains_key("message_id") {
        anyhow::bail!("scheduled_send message_payload must omit event_id and message_id");
    }
    Ok(())
}

pub fn validate_scheduled_send_value(value: &arkret_sdk::ScheduledSendValue) -> anyhow::Result<()> {
    validate_timestamp_canonical(&value.send_at)
        .map_err(|error| anyhow::anyhow!("send_at is not canonical: {error:?}"))?;
    arkret_sdk::Hlc::new(value.updated_hlc.clone())?;
    validate_message_payload_omits_event_identity(&value.message_payload)?;
    Ok(())
}

pub fn build_scheduled_send_value(
    scheduled_send_id: &str,
    send_at: &str,
    message_payload: arkret_sdk::MessageCreatePayload,
    updated_hlc: &str,
) -> anyhow::Result<arkret_sdk::ScheduledSendValue> {
    let value = arkret_sdk::ScheduledSendValue {
        scheduled_send_id: arkret_identifiers::ScheduledSendId::new(scheduled_send_id.to_owned())
            .map_err(|error| anyhow::anyhow!(error.to_string()))?,
        send_at: send_at.to_owned(),
        message_payload,
        updated_hlc: updated_hlc.to_owned(),
    };
    validate_scheduled_send_value(&value)?;
    Ok(value)
}

pub fn scheduled_send_value_from_account_data(
    value: &Value,
) -> anyhow::Result<arkret_sdk::ScheduledSendValue> {
    let scheduled_send = match serde_json::from_value(value.clone())? {
        arkret_sdk::PersonalProductivityValue::ScheduledSend(scheduled_send) => *scheduled_send,
        _ => anyhow::bail!("account-data value is not a scheduled_send"),
    };
    validate_scheduled_send_value(&scheduled_send)?;
    Ok(scheduled_send)
}

pub fn scheduled_send_account_data_value(
    value: &arkret_sdk::ScheduledSendValue,
) -> anyhow::Result<Value> {
    validate_scheduled_send_value(value)?;
    Ok(serde_json::to_value(
        arkret_sdk::PersonalProductivityValue::ScheduledSend(Box::new(value.clone())),
    )?)
}

/// Elect the plan that survives an atomic revision retry. Spec §4 leaves the
/// merge on the decrypted plaintext to the client; both candidates MUST bind
/// the same `scheduled_send_id` (the account-data key already does), and the
/// newer `updated_hlc` wins, mirroring the draft-sync last-writer-wins rule.
pub fn merge_scheduled_send_values(
    local: arkret_sdk::ScheduledSendValue,
    remote: Option<&arkret_sdk::ScheduledSendValue>,
) -> anyhow::Result<arkret_sdk::ScheduledSendValue> {
    validate_scheduled_send_value(&local)?;
    let Some(remote) = remote else {
        return Ok(local);
    };
    validate_scheduled_send_value(remote)?;
    if local.scheduled_send_id != remote.scheduled_send_id {
        anyhow::bail!("scheduled_send merge requires the same scheduled_send_id");
    }
    if canonical_sha256(&local)? == canonical_sha256(remote)? {
        return Ok(local);
    }
    match arkret_sdk::compare_hlc(&local.updated_hlc, &remote.updated_hlc)? {
        Ordering::Less => Ok(remote.clone()),
        Ordering::Greater => Ok(local),
        Ordering::Equal => {
            anyhow::bail!("scheduled_send conflict has identical updated_hlc but different plans")
        }
    }
}

/// Merge body for the account-data CAS retry loop: decrypt what the server
/// currently holds, elect the winner on plaintext, and re-seal. A stored
/// value that does not decrypt or does not bind this key is refused rather
/// than overwritten.
pub fn merge_scheduled_send_account_data(
    authority: &arkret_sdk::AccountId,
    account_data_key: &str,
    candidate: &arkret_sdk::ScheduledSendValue,
    current: Option<&arkret_sdk::AccountDataRow>,
) -> anyhow::Result<Value> {
    let remote = match current {
        Some(current) => {
            let plaintext =
                super::decrypt_account_data_entry(authority, account_data_key, current)?;
            let value = scheduled_send_value_from_account_data(&plaintext)?;
            let value_key =
                super::scheduled_send_account_data_key(value.scheduled_send_id.as_str())?;
            if value_key != account_data_key {
                anyhow::bail!("scheduled_send account-data value does not bind its own key");
            }
            Some(value)
        }
        None => None,
    };
    let winner = merge_scheduled_send_values(candidate.clone(), remote.as_ref())?;
    super::encrypt_account_data_value(
        authority,
        account_data_key,
        &scheduled_send_account_data_value(&winner)?,
    )
}

pub const PRODUCTIVITY_ACCOUNT_DATA_NAMESPACE_KEY_LEN: usize = 32;

const PRODUCTIVITY_ACCOUNT_DATA_NAMESPACE_INFO: &[u8] =
    b"arkret-personal-productivity-account-data-key-v1";

#[derive(Clone, Debug, PartialEq)]
pub struct SavedAccountDataItem {
    pub account_data_key: String,
    pub value: arkret_sdk::SavedItemValue,
}

pub fn productivity_account_data_namespace_key(
    account_secret: &str,
) -> anyhow::Result<[u8; PRODUCTIVITY_ACCOUNT_DATA_NAMESPACE_KEY_LEN]> {
    let ikm = match URL_SAFE_NO_PAD.decode(account_secret.trim()) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        _ => account_secret.as_bytes().to_vec(),
    };
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = [0u8; PRODUCTIVITY_ACCOUNT_DATA_NAMESPACE_KEY_LEN];
    hk.expand(PRODUCTIVITY_ACCOUNT_DATA_NAMESPACE_INFO, &mut out)
        .map_err(|_| anyhow::anyhow!("productivity account-data namespace HKDF expand failed"))?;
    Ok(out)
}

pub fn saved_item_value_from_account_data(
    value: &Value,
) -> anyhow::Result<arkret_sdk::SavedItemValue> {
    let saved = match serde_json::from_value(value.clone())? {
        arkret_sdk::PersonalProductivityValue::SavedItem(saved) => saved,
        _ => anyhow::bail!("account-data value is not a saved_item"),
    };
    validate_saved_item_value(&saved)?;
    Ok(saved)
}

pub fn validate_saved_item_value(value: &arkret_sdk::SavedItemValue) -> anyhow::Result<()> {
    if value.collection_title.trim().is_empty() {
        anyhow::bail!("saved item collection_title must not be empty");
    }
    arkret_sdk::Hlc::new(value.updated_hlc.as_str())?;
    super::saved_account_data_key(
        b"inkson-saved-validation-namespace",
        &value.collection_title,
        &value.target_ref,
    )?;
    Ok(())
}

pub fn saved_account_data_item(
    namespace_key: &[u8],
    value: arkret_sdk::SavedItemValue,
) -> anyhow::Result<SavedAccountDataItem> {
    validate_saved_item_value(&value)?;
    let account_data_key =
        super::saved_account_data_key(namespace_key, &value.collection_title, &value.target_ref)?;
    Ok(SavedAccountDataItem {
        account_data_key,
        value,
    })
}

pub fn saved_item_account_data_value(value: &arkret_sdk::SavedItemValue) -> anyhow::Result<Value> {
    validate_saved_item_value(value)?;
    Ok(serde_json::to_value(
        arkret_sdk::PersonalProductivityValue::SavedItem(value.clone()),
    )?)
}
