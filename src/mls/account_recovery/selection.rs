//! Pure selection helpers over a `list_key_backups`-shaped payload.

use arkret_wire::SchemaId;
use serde_json::Value;

use super::backup_body::{
    is_mls_private_plaintext_backup, is_passphrase_account_secret_backup,
    is_recovery_public_key_account_secret_backup,
};

/// Pure body-selection: pick the latest `mls_private_plaintext` backup from a
/// `list_key_backups`-shaped payload, if present. Newer `series_seq` wins,
/// followed by the creation timestamp.
pub fn select_mls_private_plaintext_backup(list_payload: &Value) -> Option<Value> {
    let active_series = active_series_id_for_backup_class(
        list_payload,
        crate::key_backup::BackupKind::SecretStorage.as_str(),
    );
    iter_backup_bodies(list_payload)
        .filter(|body| is_mls_private_plaintext_backup(body))
        .filter(|body| matches_active_series(body, active_series))
        .max_by(|a, b| {
            (backup_series_seq(a), backup_created_at(a))
                .cmp(&(backup_series_seq(b), backup_created_at(b)))
        })
        .cloned()
}

/// Iterate the `{"backups": [...]}` payload returned by
/// [`crate::transport::TransportClient::list_key_backups`].
///
/// The selection helpers below are consumed by the async auto-restore helpers
/// (now available on all targets) and their tests.
pub(super) fn iter_backup_bodies(list_payload: &Value) -> impl Iterator<Item = &Value> {
    list_payload
        .get("backups")
        .and_then(Value::as_array)
        .map(|arr| arr.iter())
        .into_iter()
        .flatten()
}

pub(super) fn backup_series_seq(body: &Value) -> u64 {
    body.get("series_seq").and_then(Value::as_u64).unwrap_or(0)
}

pub(super) fn backup_created_at(body: &Value) -> &str {
    body.get("created_at")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

pub(super) fn active_series_id_for_backup_class<'a>(
    list_payload: &'a Value,
    backup_kind: &str,
) -> Option<&'a str> {
    list_payload
        .get("active_series")
        .and_then(Value::as_array)
        .and_then(|records| {
            records.iter().find(|record| {
                record.get("schema").and_then(Value::as_str)
                    == Some(SchemaId::KEY_BACKUP_ACTIVE_SERIES_V1)
                    && record.get("backup_kind").and_then(Value::as_str) == Some(backup_kind)
            })
        })
        .and_then(|record| record.get("active_series_id"))
        .and_then(Value::as_str)
        .filter(|series_id| !series_id.is_empty())
}

fn matches_active_series(body: &Value, active_series: Option<&str>) -> bool {
    match active_series {
        Some(series_id) => !series_id.is_empty() && backup_series_id(body) == series_id,
        None => false,
    }
}

fn backup_secret_version(body: &Value) -> u64 {
    body.get("contents")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .and_then(|item| item.get("secret_version"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

/// Version recorded in an `mls_account_secret` backup.
pub fn mls_account_secret_backup_version(body: &Value) -> u32 {
    backup_secret_version(body)
        .try_into()
        .ok()
        .filter(|version| *version > 0)
        .unwrap_or(crate::mls::runtime::ACCOUNT_MLS_SECRET_CURRENT_VERSION)
}

/// Pure body-selection: pick the latest `mls_account_secret` backup from a
/// `list_key_backups`-shaped payload, if present.
///
/// Ordering is `(secret_version, series_seq, created_at)` — `secret_version`
/// FIRST so a rotation that opens a NEW series (genesis `series_seq=0` but a
/// bumped `secret_version`, per key-management.md §9.1) wins over the old
/// series' tail; then `series_seq` so that **within one series the true tail
/// always wins regardless of `created_at`** (a malicious/replaying server MUST
/// NOT be able to resurrect an old low-seq link by stamping a newer
/// timestamp); `created_at` is only a last-resort tiebreak.
///
/// A verified active-series record (key-management.md section 7.6) selects the
/// only eligible series. Missing active-series metadata fails closed.
pub fn select_mls_account_secret_backup(list_payload: &Value) -> Option<Value> {
    let active_series = active_series_id_for_backup_class(
        list_payload,
        crate::key_backup::BackupKind::SecretStorage.as_str(),
    );
    iter_backup_bodies(list_payload)
        .filter(|body| is_passphrase_account_secret_backup(body))
        .filter(|body| matches_active_series(body, active_series))
        .max_by(|a, b| {
            (
                backup_secret_version(a),
                backup_series_seq(a),
                backup_created_at(a),
            )
                .cmp(&(
                    backup_secret_version(b),
                    backup_series_seq(b),
                    backup_created_at(b),
                ))
        })
        .cloned()
}

/// Select the newest HPKE `recovery_public_key` account-secret backup (the
/// passphrase-free fresh-device recovery path). Newest by
/// `(secret_version, series_seq, created_at)`.
pub fn select_mls_account_secret_recovery_public_key_backup(list_payload: &Value) -> Option<Value> {
    let active_series = active_series_id_for_backup_class(
        list_payload,
        crate::key_backup::BackupKind::SecretStorage.as_str(),
    );
    iter_backup_bodies(list_payload)
        .filter(|body| is_recovery_public_key_account_secret_backup(body))
        .filter(|body| matches_active_series(body, active_series))
        .max_by(|a, b| {
            (
                backup_secret_version(a),
                backup_series_seq(a),
                backup_created_at(a),
            )
                .cmp(&(
                    backup_secret_version(b),
                    backup_series_seq(b),
                    backup_created_at(b),
                ))
        })
        .cloned()
}

/// Select the preferred account-secret backup for fresh-device recovery.
pub fn select_preferred_mls_account_secret_backup(list_payload: &Value) -> Option<Value> {
    select_mls_account_secret_recovery_public_key_backup(list_payload)
}

/// Pure body-selection: collect every `mls_history` backup body from a
/// `list_key_backups`-shaped payload.
pub fn select_mls_history_backups(list_payload: &Value) -> Vec<Value> {
    let active_series = active_series_id_for_backup_class(
        list_payload,
        crate::key_backup::BackupKind::MlsHistory.as_str(),
    );
    iter_backup_bodies(list_payload)
        .filter(|body| {
            body.get("backup_kind").and_then(Value::as_str)
                == Some(crate::key_backup::BackupKind::MlsHistory.as_str())
        })
        .filter(|body| matches_active_series(body, active_series))
        .cloned()
        .collect()
}

/// Select the newest immutable object for every effective scope in the active
/// `(actor_id, backup_kind=mls_history)` series. Earlier links remain required
/// for chain verification, but must not reintroduce history intentionally
/// removed by a later object for the same scope.
pub(super) fn latest_mls_history_backups_by_scope(list_payload: &Value) -> Vec<Value> {
    let mut latest = std::collections::BTreeMap::<String, Value>::new();
    for body in select_mls_history_backups(list_payload) {
        let Some(scope) = body
            .get("contents")
            .and_then(Value::as_array)
            .and_then(|contents| contents.first())
            .and_then(|item| item.get("effective_scope"))
            .and_then(|scope| {
                serde_json::from_value::<arkret_sdk::HistoryEffectiveScope>(scope.clone()).ok()
            })
        else {
            continue;
        };
        let Ok(scope_key) = serde_json::to_string(&scope) else {
            continue;
        };
        let replace = latest.get(&scope_key).is_none_or(|current| {
            (backup_series_seq(&body), backup_created_at(&body))
                > (backup_series_seq(current), backup_created_at(current))
        });
        if replace {
            latest.insert(scope_key, body);
        }
    }
    latest.into_values().collect()
}

/// Collect every envelope in the active `secret_storage` series.
///
/// A series may interleave account-secret and private-sidecar
/// items. Chain verification must retain those intermediate links even when
/// the selected decrypt target is an account-secret envelope.
pub(super) fn all_mls_account_secret_backups(list_payload: &Value) -> Vec<Value> {
    let active_series = active_series_id_for_backup_class(
        list_payload,
        crate::key_backup::BackupKind::SecretStorage.as_str(),
    );
    iter_backup_bodies(list_payload)
        .filter(|body| {
            body.get("backup_kind").and_then(Value::as_str)
                == Some(crate::key_backup::BackupKind::SecretStorage.as_str())
        })
        .filter(|body| matches_active_series(body, active_series))
        .cloned()
        .collect()
}

pub(super) fn backup_series_id(body: &Value) -> &str {
    body.get("series_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

pub(super) fn is_mls_history_backup(body: &Value) -> bool {
    body.get("backup_kind").and_then(Value::as_str)
        == Some(crate::key_backup::BackupKind::MlsHistory.as_str())
}

#[cfg(test)]
mod history_scope_selection_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn newest_history_object_is_selected_independently_per_scope() {
        let realm_a = "ak:realm:ASlHbbnJj2aIvNxwyukjGz90ltQwXHCbjIihxsRDrRR5";
        let realm_b = "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5";
        let history = |backup_id: &str, realm_id: &str, series_seq: u64| {
            json!({
                "backup_id": backup_id,
                "backup_kind": "mls_history",
                "series_id": "ak:backup_series:01964137-0000-7000-8000-000000000001",
                "series_seq": series_seq,
                "created_at": format!("2026-08-24T00:00:0{series_seq}.000Z"),
                "contents": [{
                    "item_kind": "history_secret_ranges",
                    "effective_scope": {"kind": "realm", "realm_id": realm_id},
                    "ranges": [{"from_epoch": 0, "to_epoch": series_seq}],
                }],
            })
        };
        let payload = json!({
            "active_series": [{
                "schema": arkret_sdk::SchemaId::KEY_BACKUP_ACTIVE_SERIES_V1,
                "backup_kind": "mls_history",
                "active_series_id": "ak:backup_series:01964137-0000-7000-8000-000000000001",
            }],
            "backups": [
                history("old-a", realm_a, 0),
                history("scope-b", realm_b, 1),
                history("new-a", realm_a, 2),
            ],
        });

        let selected = latest_mls_history_backups_by_scope(&payload);
        let ids = selected
            .iter()
            .filter_map(|body| body.get("backup_id").and_then(Value::as_str))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(ids, std::collections::BTreeSet::from(["new-a", "scope-b"]));
    }
}
