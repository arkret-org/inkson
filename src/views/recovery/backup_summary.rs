//! Backup-list parsing, recency sorting, and inventory-status formatting.

use super::types::BackupSummaryRow;

pub(crate) fn parse_backup_summary(v: &serde_json::Value) -> Option<BackupSummaryRow> {
    let backup_id = v.get("backup_id")?.as_str()?.to_owned();
    let backup_kind = v
        .get("backup_kind")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_owned();
    let created_at = v
        .get("created_at")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_owned();
    Some(BackupSummaryRow {
        backup_id,
        backup_kind,
        created_at,
    })
}

/// Extract `BackupSummaryRow`s from the typed `list_key_backups`
/// response (`{"backups": [...]}`).
pub(crate) fn parse_backup_list(payload: &serde_json::Value) -> Vec<BackupSummaryRow> {
    payload
        .get("backups")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_backup_summary).collect())
        .unwrap_or_default()
}

fn backup_created_epoch_ms(row: &BackupSummaryRow) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(&row.created_at)
        .ok()
        .map(|dt| dt.timestamp_millis())
}

fn compare_backup_recency_desc(a: &BackupSummaryRow, b: &BackupSummaryRow) -> std::cmp::Ordering {
    match (backup_created_epoch_ms(a), backup_created_epoch_ms(b)) {
        (Some(a_ms), Some(b_ms)) => b_ms.cmp(&a_ms),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.backup_id.cmp(&b.backup_id),
    }
}

pub(crate) fn sorted_backups_latest_first(rows: &[BackupSummaryRow]) -> Vec<BackupSummaryRow> {
    let mut sorted = rows.to_vec();
    sorted.sort_by(compare_backup_recency_desc);
    sorted
}

pub(crate) fn fmt_backup_timestamp(iso: &str) -> String {
    if iso.is_empty() {
        return "Unknown time".to_owned();
    }
    chrono::DateTime::parse_from_rfc3339(iso)
        .map(|dt| {
            dt.with_timezone(&chrono::Utc)
                .format("%Y-%m-%d %H:%M UTC")
                .to_string()
        })
        .unwrap_or_else(|_| iso.to_owned())
}

/// Inventory summary for the backup-history panel: whether the server
/// listed any backups, and if so how many plus the latest timestamp.
/// Copy is localized by the caller (`recovery.panel.inventory_*` keys);
/// this type carries data only so it can cross the spawned-task boundary
/// where `tr()` has no Dioxus context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BackupInventoryStatus {
    Empty,
    Loaded { count: usize, latest: String },
}

pub(crate) fn backup_inventory_status(rows: &[BackupSummaryRow]) -> BackupInventoryStatus {
    if rows.is_empty() {
        return BackupInventoryStatus::Empty;
    }
    let latest = sorted_backups_latest_first(rows)
        .first()
        .map(|row| fmt_backup_timestamp(&row.created_at))
        .unwrap_or_else(|| "Unknown time".to_owned());
    BackupInventoryStatus::Loaded {
        count: rows.len(),
        latest,
    }
}
