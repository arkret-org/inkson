//! Pure selection helpers over a `list_key_backups`-shaped payload.

use serde_json::Value;

use super::backup_body::{
    is_mls_account_secret_backup, is_mls_private_plaintext_backup,
    is_passphrase_account_secret_backup, is_recovery_public_key_account_secret_backup,
};

/// Pure body-selection: pick the latest `mls_private_plaintext` backup from a
/// `list_key_backups`-shaped payload, if present. Newer `series_seq` wins,
/// followed by the creation timestamp.
pub fn select_mls_private_plaintext_backup(list_payload: &Value) -> Option<Value> {
    iter_backup_bodies(list_payload)
        .filter(|body| is_mls_private_plaintext_backup(body))
        .max_by(|a, b| {
            (backup_series_seq(a), backup_created_at(a))
                .cmp(&(backup_series_seq(b), backup_created_at(b)))
        })
        .cloned()
}

/// Iterate the `{"backups": [...]}` payload returned by
/// [`crate::api::CokretApi::list_key_backups`].
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
/// NOTE: this is the interim "active series pointer". The complete defense is a
/// signed active-series record (key-management.md §7.6) so a forged
/// higher-`secret_version` series cannot be injected ACROSS series; until that
/// lands, `verify_series_chain` still fails closed on a broken chain WITHIN the
/// selected series.
pub fn select_mls_account_secret_backup(list_payload: &Value) -> Option<Value> {
    iter_backup_bodies(list_payload)
        .filter(|body| is_passphrase_account_secret_backup(body))
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
/// `(secret_version, created_at)`.
pub fn select_mls_account_secret_recovery_public_key_backup(list_payload: &Value) -> Option<Value> {
    iter_backup_bodies(list_payload)
        .filter(|body| is_recovery_public_key_account_secret_backup(body))
        .max_by(|a, b| {
            (backup_secret_version(a), backup_created_at(a))
                .cmp(&(backup_secret_version(b), backup_created_at(b)))
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
    iter_backup_bodies(list_payload)
        .filter(|body| {
            body.get("backup_class").and_then(Value::as_str)
                == Some(crate::key_backup::KeyBackupClass::MlsHistory.as_str())
        })
        .cloned()
        .collect()
}

/// Collect every `mls_account_secret` backup body from a `list_key_backups`
/// payload (used to verify the series chain before trusting a selected tail).
pub(super) fn all_mls_account_secret_backups(list_payload: &Value) -> Vec<Value> {
    iter_backup_bodies(list_payload)
        .filter(|body| is_mls_account_secret_backup(body))
        .cloned()
        .collect()
}

/// Realm a `mls_history` backup body belongs to (`envelope_meta.realm_ref`,
/// falling back to `contents[0].realm_ref`). Both survive soland's
/// list-metadata redaction, so tail selection works on the redacted list.
fn mls_history_backup_realm_ref(body: &Value) -> Option<&str> {
    body.get("envelope_meta")
        .and_then(|meta| meta.get("realm_ref"))
        .and_then(Value::as_str)
        .or_else(|| {
            body.get("contents")
                .and_then(Value::as_array)
                .and_then(|c| c.first())
                .and_then(|item| item.get("realm_ref"))
                .and_then(Value::as_str)
        })
}

pub(super) fn backup_series_id(body: &Value) -> &str {
    body.get("series_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

pub(super) fn is_mls_history_backup(body: &Value) -> bool {
    body.get("backup_class").and_then(Value::as_str)
        == Some(crate::key_backup::KeyBackupClass::MlsHistory.as_str())
}

/// Series-tail `backup_id`s among the `mls_history` backups in `list_payload`.
///
/// Grouped per `series_id` (a missing `series_id` degrades to per-backup
/// grouping); the tail is the highest
/// `(series_seq, created_at)` link. The continuous-backup writer folds each
/// Realm's epoch material into the tail of one series, so restore only needs
/// the tail per series — soland's per-principal 24h full-ciphertext download
/// quota (default 64) would otherwise be burned on superseded chain links.
pub fn mls_history_series_tail_ids(list_payload: &Value) -> std::collections::BTreeSet<String> {
    let mut tails: std::collections::BTreeMap<String, &Value> = std::collections::BTreeMap::new();
    for body in iter_backup_bodies(list_payload).filter(|body| is_mls_history_backup(body)) {
        let backup_id = body
            .get("backup_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let series = backup_series_id(body);
        let group_key = if series.is_empty() {
            format!("backup:{backup_id}")
        } else {
            format!("series:{series}")
        };
        let replace = match tails.get(group_key.as_str()) {
            Some(current) => {
                (backup_series_seq(body), backup_created_at(body))
                    > (backup_series_seq(current), backup_created_at(current))
            }
            None => true,
        };
        if replace {
            tails.insert(group_key, body);
        }
    }
    tails
        .values()
        .filter_map(|body| body.get("backup_id").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect()
}

/// Pick the series tail to chain the next continuous `mls_history` upload of
/// `realm_id` onto: the highest `(series_seq, created_at)` body among that
/// Realm's `mls_history` backups. `None` means no prior series — the upload is
/// a genesis.
pub fn select_mls_history_tail_for_realm(list_payload: &Value, realm_id: &str) -> Option<Value> {
    iter_backup_bodies(list_payload)
        .filter(|body| is_mls_history_backup(body))
        .filter(|body| mls_history_backup_realm_ref(body) == Some(realm_id))
        .max_by(|a, b| {
            (backup_series_seq(a), backup_created_at(a))
                .cmp(&(backup_series_seq(b), backup_created_at(b)))
        })
        .cloned()
}
