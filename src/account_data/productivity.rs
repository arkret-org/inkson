//! Personal productivity account-data helpers for draft sync and saved items.

use std::cmp::Ordering;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use serde_json::Value;
use sha2::Sha256;

use crate::canonical::{canonical_sha256, validate_timestamp_canonical};

pub const DRAFT_MESSAGE_SLOT: &str = "compose";
pub const DRAFT_STRAND_FIELD_SLOT_PREFIX: &str = "field_";
pub const PRODUCTIVITY_ACCOUNT_DATA_NAMESPACE_KEY_LEN: usize = 32;

const PRODUCTIVITY_ACCOUNT_DATA_NAMESPACE_INFO: &[u8] =
    b"arkret-personal-productivity-account-data-key-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountDataMergeChoice {
    Local,
    Remote,
    Equal,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DraftMergeOutcome {
    pub choice: AccountDataMergeChoice,
    pub winner: arkret_sdk::DraftSyncValue,
    pub conflict_copy: Option<arkret_sdk::DraftSyncValue>,
}

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

pub fn draft_slot_for_strand_field_path(field_path: &Value) -> anyhow::Result<String> {
    let digest = canonical_sha256(field_path)?;
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("field path digest is not sha256"))?;
    Ok(format!("{DRAFT_STRAND_FIELD_SLOT_PREFIX}{hex}"))
}

pub fn validate_draft_slot(kind: arkret_sdk::DraftKind, draft_slot: &str) -> anyhow::Result<()> {
    match kind {
        arkret_sdk::DraftKind::Message => {
            if draft_slot != DRAFT_MESSAGE_SLOT {
                anyhow::bail!("message draft_slot must be compose");
            }
        }
        arkret_sdk::DraftKind::StrandField => {
            let Some(hex) = draft_slot.strip_prefix(DRAFT_STRAND_FIELD_SLOT_PREFIX) else {
                anyhow::bail!("strand_field draft_slot must start with field_");
            };
            // The slot carries a bare 64-char lowercase sha256 hex; validate the
            // hex/casing grammar via the canonical `arkret_sdk::Hash::new` by
            // re-attaching the `sha256:` prefix it expects, rather than
            // re-deriving the rule inline.
            if arkret_sdk::Hash::new(format!("sha256:{hex}")).is_err() {
                anyhow::bail!("strand_field draft_slot must carry a lowercase sha256 hex digest");
            }
        }
    }
    Ok(())
}

pub fn validate_draft_sync_value(value: &arkret_sdk::DraftSyncValue) -> anyhow::Result<()> {
    if value.content.is_empty() {
        anyhow::bail!("draft content must not be null");
    }
    validate_draft_slot(value.kind, &value.draft_slot)?;
    arkret_sdk::Hlc::new(value.updated_hlc.as_str())?;
    validate_timestamp_canonical(&value.retention_expires_at)
        .map_err(|error| anyhow::anyhow!("retention_expires_at is not canonical: {error:?}"))?;
    super::draft_account_data_key(
        b"inkson-draft-validation-namespace",
        value.kind,
        &value.target_ref,
        &value.draft_slot,
    )?;
    Ok(())
}

pub fn draft_sync_value_from_account_data(
    value: &Value,
) -> anyhow::Result<arkret_sdk::DraftSyncValue> {
    let draft: arkret_sdk::DraftSyncValue = serde_json::from_value(value.clone())?;
    validate_draft_sync_value(&draft)?;
    Ok(draft)
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

pub fn build_message_draft_sync_value(
    target_ref: &str,
    content: Value,
    updated_hlc: &str,
    origin_device_id: &str,
    retention_expires_at: &str,
) -> anyhow::Result<arkret_sdk::DraftSyncValue> {
    let value = arkret_sdk::DraftSyncValue {
        target_ref: target_ref.to_owned(),
        kind: arkret_sdk::DraftKind::Message,
        draft_slot: DRAFT_MESSAGE_SLOT.to_owned(),
        content: serde_json::from_value(content)?,
        updated_hlc: updated_hlc.to_owned(),
        origin_device_id: arkret_sdk::DeviceId::new(origin_device_id.to_owned())
            .map_err(|error| anyhow::anyhow!("origin_device_id is invalid: {error:?}"))?,
        retention_expires_at: retention_expires_at.to_owned(),
    };
    validate_draft_sync_value(&value)?;
    Ok(value)
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

pub fn compare_draft_versions(
    local: &arkret_sdk::DraftSyncValue,
    remote: &arkret_sdk::DraftSyncValue,
) -> anyhow::Result<Ordering> {
    validate_same_draft_cell(local, remote)?;
    validate_draft_sync_value(local)?;
    validate_draft_sync_value(remote)?;
    match arkret_sdk::compare_hlc(&local.updated_hlc, &remote.updated_hlc)? {
        Ordering::Equal => Ok(local
            .origin_device_id
            .to_string()
            .cmp(&remote.origin_device_id.to_string())),
        other => Ok(other),
    }
}

pub fn merge_draft_values(
    local: Option<&arkret_sdk::DraftSyncValue>,
    remote: arkret_sdk::DraftSyncValue,
) -> anyhow::Result<DraftMergeOutcome> {
    validate_draft_sync_value(&remote)?;
    let Some(local) = local else {
        return Ok(DraftMergeOutcome {
            choice: AccountDataMergeChoice::Remote,
            winner: remote,
            conflict_copy: None,
        });
    };
    validate_same_draft_cell(local, &remote)?;
    validate_draft_sync_value(local)?;
    let local_digest = canonical_sha256(local)?;
    let remote_digest = canonical_sha256(&remote)?;
    if local_digest == remote_digest {
        return Ok(DraftMergeOutcome {
            choice: AccountDataMergeChoice::Equal,
            winner: local.clone(),
            conflict_copy: None,
        });
    }

    match compare_draft_versions(local, &remote)? {
        Ordering::Less => Ok(DraftMergeOutcome {
            choice: AccountDataMergeChoice::Remote,
            winner: remote,
            conflict_copy: Some(local.clone()),
        }),
        Ordering::Greater => Ok(DraftMergeOutcome {
            choice: AccountDataMergeChoice::Local,
            winner: local.clone(),
            conflict_copy: Some(remote),
        }),
        Ordering::Equal => {
            anyhow::bail!("draft conflict has identical updated_hlc and origin_device_id")
        }
    }
}

fn validate_same_draft_cell(
    local: &arkret_sdk::DraftSyncValue,
    remote: &arkret_sdk::DraftSyncValue,
) -> anyhow::Result<()> {
    if local.target_ref != remote.target_ref
        || local.kind != remote.kind
        || local.draft_slot != remote.draft_slot
    {
        anyhow::bail!("draft merge requires the same target_ref, kind, and draft_slot");
    }
    Ok(())
}
