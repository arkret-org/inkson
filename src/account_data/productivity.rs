//! Personal productivity account-data helpers for draft sync and saved items.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::canonical::{canonical_sha256, validate_timestamp_canonical};
use crate::hlc::Hlc;

pub const DRAFT_MESSAGE_SLOT: &str = "compose";
pub const DRAFT_STRAND_FIELD_SLOT_PREFIX: &str = "field_";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountDataMergeChoice {
    Local,
    Remote,
    Equal,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DraftMergeOutcome {
    pub choice: AccountDataMergeChoice,
    pub winner: cokret_sdk::DraftSyncValue,
    pub conflict_copy: Option<cokret_sdk::DraftSyncValue>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DraftAccountDataItem {
    pub account_data_key: String,
    pub value: cokret_sdk::DraftSyncValue,
    pub state_digest: String,
    pub legacy_scope_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacySavedItem {
    pub collection_title: String,
    pub target_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SavedAccountDataItem {
    pub account_data_key: String,
    pub value: cokret_sdk::SavedItemValue,
    pub state_digest: String,
}

pub fn draft_slot_for_strand_field_path(field_path: &Value) -> anyhow::Result<String> {
    let digest = canonical_sha256(field_path)?;
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("field path digest is not sha256"))?;
    Ok(format!("{DRAFT_STRAND_FIELD_SLOT_PREFIX}{hex}"))
}

pub fn validate_draft_slot(kind: cokret_sdk::DraftKind, draft_slot: &str) -> anyhow::Result<()> {
    match kind {
        cokret_sdk::DraftKind::Message => {
            if draft_slot != DRAFT_MESSAGE_SLOT {
                anyhow::bail!("message draft_slot must be compose");
            }
        }
        cokret_sdk::DraftKind::StrandField => {
            let Some(hex) = draft_slot.strip_prefix(DRAFT_STRAND_FIELD_SLOT_PREFIX) else {
                anyhow::bail!("strand_field draft_slot must start with field_");
            };
            if hex.len() != 64
                || !hex
                    .as_bytes()
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            {
                anyhow::bail!("strand_field draft_slot must carry a lowercase sha256 hex digest");
            }
        }
    }
    Ok(())
}

pub fn validate_draft_sync_value(value: &cokret_sdk::DraftSyncValue) -> anyhow::Result<()> {
    if value.content.is_null() {
        anyhow::bail!("draft content must not be null");
    }
    validate_draft_slot(value.kind, &value.draft_slot)?;
    Hlc::parse(&value.updated_hlc)?;
    validate_timestamp_canonical(&value.retention_expires_at)
        .map_err(|error| anyhow::anyhow!("retention_expires_at is not canonical: {error:?}"))?;
    super::draft_account_data_key(
        b"yougen-draft-validation-namespace",
        value.kind,
        &value.target_ref,
        &value.draft_slot,
    )?;
    Ok(())
}

pub fn draft_sync_value_from_account_data(
    value: &Value,
) -> anyhow::Result<cokret_sdk::DraftSyncValue> {
    let draft: cokret_sdk::DraftSyncValue = serde_json::from_value(value.clone())?;
    validate_draft_sync_value(&draft)?;
    Ok(draft)
}

pub fn saved_item_value_from_account_data(
    value: &Value,
) -> anyhow::Result<cokret_sdk::SavedItemValue> {
    let saved = match serde_json::from_value(value.clone())? {
        cokret_sdk::PersonalProductivityValue::SavedItem(saved) => saved,
        _ => anyhow::bail!("account-data value is not a saved_item"),
    };
    validate_saved_item_value(&saved)?;
    Ok(saved)
}

pub fn validate_saved_item_value(value: &cokret_sdk::SavedItemValue) -> anyhow::Result<()> {
    if value.collection_title.trim().is_empty() {
        anyhow::bail!("saved item collection_title must not be empty");
    }
    Hlc::parse(&value.updated_hlc)?;
    super::saved_account_data_key(
        b"yougen-saved-validation-namespace",
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
) -> anyhow::Result<cokret_sdk::DraftSyncValue> {
    let value = cokret_sdk::DraftSyncValue {
        target_ref: target_ref.to_owned(),
        kind: cokret_sdk::DraftKind::Message,
        draft_slot: DRAFT_MESSAGE_SLOT.to_owned(),
        content,
        updated_hlc: updated_hlc.to_owned(),
        origin_device_id: cokret_sdk::DeviceId::new(origin_device_id.to_owned())
            .map_err(|error| anyhow::anyhow!("origin_device_id is invalid: {error:?}"))?,
        retention_expires_at: retention_expires_at.to_owned(),
    };
    validate_draft_sync_value(&value)?;
    Ok(value)
}

pub fn draft_account_data_item(
    namespace_key: &[u8],
    value: cokret_sdk::DraftSyncValue,
    legacy_scope_id: Option<String>,
) -> anyhow::Result<DraftAccountDataItem> {
    validate_draft_sync_value(&value)?;
    let account_data_key = super::draft_account_data_key(
        namespace_key,
        value.kind,
        &value.target_ref,
        &value.draft_slot,
    )?;
    let state_digest = canonical_sha256(&value)?;
    Ok(DraftAccountDataItem {
        account_data_key,
        value,
        state_digest,
        legacy_scope_id,
    })
}

pub fn saved_account_data_item(
    namespace_key: &[u8],
    value: cokret_sdk::SavedItemValue,
) -> anyhow::Result<SavedAccountDataItem> {
    validate_saved_item_value(&value)?;
    let account_data_key =
        super::saved_account_data_key(namespace_key, &value.collection_title, &value.target_ref)?;
    let state_digest = canonical_sha256(&saved_item_account_data_value(&value)?)?;
    Ok(SavedAccountDataItem {
        account_data_key,
        value,
        state_digest,
    })
}

pub fn saved_item_account_data_value(value: &cokret_sdk::SavedItemValue) -> anyhow::Result<Value> {
    validate_saved_item_value(value)?;
    Ok(serde_json::to_value(
        cokret_sdk::PersonalProductivityValue::SavedItem(value.clone()),
    )?)
}

pub fn migrate_legacy_local_drafts(
    namespace_key: &[u8],
    drafts: &BTreeMap<String, String>,
    origin_device_id: &str,
    updated_hlc: &str,
    retention_expires_at: &str,
) -> anyhow::Result<Vec<DraftAccountDataItem>> {
    cokret_sdk::DeviceId::new(origin_device_id.to_owned())
        .map_err(|error| anyhow::anyhow!("origin_device_id is invalid: {error:?}"))?;
    Hlc::parse(updated_hlc)?;
    validate_timestamp_canonical(retention_expires_at)
        .map_err(|error| anyhow::anyhow!("retention_expires_at is not canonical: {error:?}"))?;

    let mut migrated = Vec::new();
    for (scope_id, draft) in drafts {
        let body = draft.trim();
        if body.is_empty() {
            continue;
        }
        let value = build_message_draft_sync_value(
            scope_id,
            json!({ "body": body }),
            updated_hlc,
            origin_device_id,
            retention_expires_at,
        )?;
        migrated.push(draft_account_data_item(
            namespace_key,
            value,
            Some(scope_id.clone()),
        )?);
    }
    Ok(migrated)
}

pub fn migrate_legacy_saved_items(
    namespace_key: &[u8],
    items: &[LegacySavedItem],
    updated_hlc: &str,
) -> anyhow::Result<Vec<SavedAccountDataItem>> {
    Hlc::parse(updated_hlc)?;
    let mut migrated = Vec::new();
    for item in items {
        if item.collection_title.trim().is_empty() || item.target_ref.trim().is_empty() {
            continue;
        }
        let value = cokret_sdk::SavedItemValue {
            collection_title: item.collection_title.clone(),
            target_ref: item.target_ref.clone(),
            note: item
                .note
                .as_deref()
                .map(str::trim)
                .filter(|note| !note.is_empty())
                .map(ToOwned::to_owned),
            updated_hlc: updated_hlc.to_owned(),
        };
        migrated.push(saved_account_data_item(namespace_key, value)?);
    }
    Ok(migrated)
}

pub fn compare_draft_versions(
    local: &cokret_sdk::DraftSyncValue,
    remote: &cokret_sdk::DraftSyncValue,
) -> anyhow::Result<Ordering> {
    validate_same_draft_cell(local, remote)?;
    validate_draft_sync_value(local)?;
    validate_draft_sync_value(remote)?;
    let local_hlc = Hlc::parse(&local.updated_hlc)?;
    let remote_hlc = Hlc::parse(&remote.updated_hlc)?;
    match local_hlc.cmp(&remote_hlc) {
        Ordering::Equal => Ok(local
            .origin_device_id
            .to_string()
            .cmp(&remote.origin_device_id.to_string())),
        other => Ok(other),
    }
}

pub fn merge_draft_values(
    local: Option<&cokret_sdk::DraftSyncValue>,
    remote: cokret_sdk::DraftSyncValue,
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
    local: &cokret_sdk::DraftSyncValue,
    remote: &cokret_sdk::DraftSyncValue,
) -> anyhow::Result<()> {
    if local.target_ref != remote.target_ref
        || local.kind != remote.kind
        || local.draft_slot != remote.draft_slot
    {
        anyhow::bail!("draft merge requires the same target_ref, kind, and draft_slot");
    }
    Ok(())
}
