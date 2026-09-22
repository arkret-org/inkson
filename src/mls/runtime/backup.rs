//! MLS epoch floors and host-side key-backup selection.
//!
//! Two unrelated host concerns share this module because both answer "which
//! stored artifact may this device open right now":
//!
//!   * the epoch floor a local MLS checkpoint must clear before it is restored, so a device that
//!     already knows of a newer accepted epoch never binds to a stale snapshot and forks the group;
//!     and
//!   * which envelope of the active key-backup series carries the account MLS secret or the
//!     private-plaintext sidecar.
//!
//! The selection half is host runtime logic rather than protocol judgement:
//! `garth::mls::backup_selection` owns the shared rule (the Station's
//! active-series pointer narrows the eligible series and the tail is ordered by
//! `(series_seq, created_at)`), and what stays here is the item-kind and
//! recipient-method narrowing that only a client restoring its own material
//! needs.

use serde_json::Value;

/// The epoch a locally stored MLS checkpoint must be at or above before this
/// device restores it.
///
/// Takes the higher of the scope's accepted current MLS epoch and this device's
/// own installed epoch, so a rolled-back or overwritten local checkpoint is
/// refused by [`crate::mls::persistence::decrypt_with_epoch_check`].
pub fn mls_restore_epoch_floor(state_store: &crate::state::LocalStateStore, realm_id: &str) -> u64 {
    let accepted = accepted_mls_epoch_floor(state_store, realm_id);
    let local = state_store
        .mls_checkpoint_for(realm_id)
        .map(|snapshot| snapshot.epoch)
        .unwrap_or(0);
    accepted.max(local)
}

/// The Realm's accepted current MLS epoch, used as the `current_epoch_floor`
/// the on-disk checkpoint write paths (commit / encrypt / reaction-send) pass to
/// [`crate::mls::persistence::restore_envelope`].
///
/// Unlike [`mls_restore_epoch_floor`] this does NOT fold in the local
/// checkpoint's own epoch: at a write site the checkpoint being restored *is*
/// the local one, so folding its epoch back in would make the freshness check a
/// tautology that can never fire. Returning only the independently sourced
/// accepted epoch lets `OutdatedCheckpoint` actually trip when a concurrently
/// overwritten or rolled-back local checkpoint has fallen behind the scope's
/// accepted MLS group. When the scope's current MLS group has not been
/// delivered yet the floor is `0`, matching first-boot rehydrate semantics.
pub fn accepted_mls_epoch_floor(
    state_store: &crate::state::LocalStateStore,
    realm_id: &str,
) -> u64 {
    let Ok(realm_id) = arkret_sdk::RealmId::new(realm_id.trim().to_owned()) else {
        return 0;
    };
    state_store
        .current_mls_group_for_scope(&arkret_sdk::ScopeRef::Realm { realm_id })
        .map(|current| current.epoch)
        .unwrap_or(0)
}

/// Iterate the `{"backups": [...]}` payload a key-backup listing produced.
pub(crate) fn iter_backup_bodies(list_payload: &Value) -> impl Iterator<Item = &Value> {
    list_payload
        .get("backups")
        .and_then(Value::as_array)
        .map(|bodies| bodies.iter())
        .into_iter()
        .flatten()
}

/// The Station's active `secret_storage` series id, or `None` when the pointer
/// is absent or malformed. A missing pointer never permits guessing an eligible
/// series from the envelopes themselves.
pub(crate) fn active_secret_storage_series_id(list_payload: &Value) -> Option<String> {
    let active_series: arkret_sdk::BackupActiveSeriesState =
        serde_json::from_value(list_payload.get("active_series")?.clone()).ok()?;
    garth::mls::backup_selection::active_series_id(&active_series)
        .map(|series_id| series_id.as_str().to_owned())
}

fn backup_series_id(body: &Value) -> &str {
    body.get("series_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// The `series_seq` an envelope body claims. A missing value reads as the
/// genesis link rather than as "unknown", so an envelope that hides its
/// position can never outrank a real tail.
pub(crate) fn backup_series_seq_of(body: &Value) -> u64 {
    body.get("series_seq").and_then(Value::as_u64).unwrap_or(0)
}

/// Adapter for callers that still name the backup class explicitly. There is
/// exactly one class left, so a caller naming any other one selects nothing.
pub(crate) fn active_secret_storage_series_id_for(
    list_payload: &Value,
    backup_kind: arkret_sdk::BackupKind,
) -> Option<String> {
    match backup_kind {
        arkret_sdk::BackupKind::SecretStorage => active_secret_storage_series_id(list_payload),
    }
}

fn backup_created_at(body: &Value) -> &str {
    body.get("created_at")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn backup_item_kind(body: &Value) -> Option<&str> {
    body.get("contents")
        .and_then(Value::as_array)
        .and_then(|contents| contents.first())
        .and_then(|item| item.get("item_kind"))
        .and_then(Value::as_str)
}

fn backup_recipient_method(body: &Value) -> Option<&str> {
    body.pointer("/encryption/recipient_method")
        .and_then(Value::as_str)
}

fn backup_secret_version(body: &Value) -> u64 {
    body.get("contents")
        .and_then(Value::as_array)
        .and_then(|contents| contents.first())
        .and_then(|item| item.get("secret_version"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

fn carries_item_kind(body: &Value, item_kind: arkret_sdk::SecretStorageItemKind) -> bool {
    let expected = serde_json::to_value(item_kind)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned));
    expected
        .as_deref()
        .is_some_and(|expected| backup_item_kind(body) == Some(expected))
}

/// True when `body` is an MLS account-secret envelope under any recipient
/// method.
pub(crate) fn is_mls_account_secret_backup(body: &Value) -> bool {
    carries_item_kind(body, arkret_sdk::SecretStorageItemKind::MlsAccountSecret)
}

/// True when `body` is the passphrase-recoverable account-secret envelope.
///
/// The account secret has two envelopes sharing one item kind — a passphrase
/// one and an HPKE `recovery_public_key` one — so the passphrase restore path
/// MUST pick only this variant, or it would try to passphrase-decrypt an HPKE
/// envelope.
pub(crate) fn is_passphrase_account_secret_backup(body: &Value) -> bool {
    is_mls_account_secret_backup(body) && backup_recipient_method(body) == Some("passphrase_kdf")
}

/// True when `body` is the HPKE `recovery_public_key` account-secret envelope,
/// the passphrase-free fresh-device recovery path.
pub(crate) fn is_recovery_public_key_account_secret_backup(body: &Value) -> bool {
    is_mls_account_secret_backup(body)
        && backup_recipient_method(body) == Some("recovery_public_key")
}

/// True when `body` is the encrypted local-plaintext sidecar envelope.
pub(crate) fn is_mls_private_plaintext_backup(body: &Value) -> bool {
    carries_item_kind(body, arkret_sdk::SecretStorageItemKind::MlsPrivatePlaintext)
}

/// The account-secret version an envelope records, defaulting to the current
/// local version when the envelope predates explicit versioning.
pub(crate) fn mls_account_secret_backup_version(body: &Value) -> u32 {
    backup_secret_version(body)
        .try_into()
        .ok()
        .filter(|version| *version > 0)
        .unwrap_or(super::ACCOUNT_MLS_SECRET_CURRENT_VERSION)
}

fn in_active_series<'a>(
    list_payload: &'a Value,
    keep: impl Fn(&Value) -> bool + 'a,
) -> impl Iterator<Item = &'a Value> {
    let active_series = active_secret_storage_series_id(list_payload);
    iter_backup_bodies(list_payload).filter(move |body| {
        active_series
            .as_deref()
            .is_some_and(|series_id| !series_id.is_empty() && backup_series_id(body) == series_id)
            && keep(body)
    })
}

/// Ordering for an account-secret envelope: `secret_version` FIRST so a
/// rotation that opens a new series (genesis `series_seq = 0` but a bumped
/// `secret_version`) wins over the old series' tail; then `series_seq` so the
/// true tail of one series always wins regardless of `created_at` (a replaying
/// service MUST NOT be able to resurrect an old low-seq link by stamping a
/// newer timestamp); `created_at` is only a last-resort tiebreak.
fn account_secret_order(body: &Value) -> (u64, u64, &str) {
    (
        backup_secret_version(body),
        backup_series_seq_of(body),
        backup_created_at(body),
    )
}

/// The latest passphrase-opened account-secret envelope in the active series.
pub(crate) fn select_mls_account_secret_backup(list_payload: &Value) -> Option<Value> {
    in_active_series(list_payload, is_passphrase_account_secret_backup)
        .max_by(|left, right| account_secret_order(left).cmp(&account_secret_order(right)))
        .cloned()
}

/// The latest HPKE `recovery_public_key` account-secret envelope in the active
/// series.
pub(crate) fn select_mls_account_secret_recovery_public_key_backup(
    list_payload: &Value,
) -> Option<Value> {
    in_active_series(list_payload, is_recovery_public_key_account_secret_backup)
        .max_by(|left, right| account_secret_order(left).cmp(&account_secret_order(right)))
        .cloned()
}

/// The account-secret envelope a fresh device should prefer: the
/// passphrase-free recovery-key one.
pub(crate) fn select_preferred_mls_account_secret_backup(list_payload: &Value) -> Option<Value> {
    select_mls_account_secret_recovery_public_key_backup(list_payload)
}

/// The latest private-plaintext sidecar envelope in the active series.
pub(crate) fn select_mls_private_plaintext_backup(list_payload: &Value) -> Option<Value> {
    in_active_series(list_payload, is_mls_private_plaintext_backup)
        .max_by(|left, right| {
            (backup_series_seq_of(left), backup_created_at(left))
                .cmp(&(backup_series_seq_of(right), backup_created_at(right)))
        })
        .cloned()
}

/// Every envelope in the active `secret_storage` series.
///
/// A series may interleave account-secret and private-sidecar items, and chain
/// verification must retain those intermediate links even when the selected
/// decrypt target is an account-secret envelope.
pub(crate) fn all_secret_storage_backups(list_payload: &Value) -> Vec<Value> {
    in_active_series(list_payload, |_| true).cloned().collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn body(
        seq: u64,
        series: &str,
        item_kind: &str,
        recipient_method: &str,
        secret_version: u64,
    ) -> Value {
        json!({
            "backup_id": format!("ak:backup:0196419b-0000-7000-8000-00000000003{seq}"),
            "backup_kind": "secret_storage",
            "series_id": series,
            "series_seq": seq,
            "created_at": format!("2026-05-0{}T00:00:00.000Z", seq + 1),
            "encryption": {"recipient_method": recipient_method},
            "contents": [{"item_kind": item_kind, "secret_version": secret_version}],
        })
    }

    fn list(active: Option<&str>, backups: Vec<Value>) -> Value {
        let pointer = match active {
            Some(series) => json!({
                "state": "active",
                "active_series_id": series,
                "series_pointer_version": 4
            }),
            None => json!({"state": "absent"}),
        };
        json!({
            "backups": backups,
            "active_series": {
                "account_id": {
                    "principal_id": "ak:did_core:web:alice.example",
                    "station_id": "ak:did_core:web:station.example"
                },
                "control_realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "secret_storage": pointer
            }
        })
    }

    const SERIES: &str = "ak:backup_series:0196419b-0000-7000-8000-000000000010";
    const OTHER: &str = "ak:backup_series:0196419b-0000-7000-8000-000000000011";

    #[test]
    fn an_absent_active_series_pointer_selects_nothing() {
        let payload = list(
            None,
            vec![body(3, SERIES, "mls_account_secret", "passphrase_kdf", 1)],
        );
        assert!(select_mls_account_secret_backup(&payload).is_none());
        assert!(all_secret_storage_backups(&payload).is_empty());
    }

    #[test]
    fn an_envelope_outside_the_active_series_is_never_selected() {
        let payload = list(
            Some(SERIES),
            vec![
                body(9, OTHER, "mls_account_secret", "passphrase_kdf", 1),
                body(2, SERIES, "mls_account_secret", "passphrase_kdf", 1),
            ],
        );
        let selected = select_mls_account_secret_backup(&payload).unwrap();
        assert_eq!(selected["series_seq"], json!(2));
        assert_eq!(selected["series_id"], json!(SERIES));
    }

    #[test]
    fn the_passphrase_and_recovery_key_envelopes_are_selected_separately() {
        let payload = list(
            Some(SERIES),
            vec![
                body(1, SERIES, "mls_account_secret", "passphrase_kdf", 1),
                body(2, SERIES, "mls_account_secret", "recovery_public_key", 1),
                body(3, SERIES, "mls_private_plaintext", "passphrase_kdf", 1),
            ],
        );
        assert_eq!(
            select_mls_account_secret_backup(&payload).unwrap()["series_seq"],
            json!(1)
        );
        assert_eq!(
            select_preferred_mls_account_secret_backup(&payload).unwrap()["series_seq"],
            json!(2)
        );
        assert_eq!(
            select_mls_private_plaintext_backup(&payload).unwrap()["series_seq"],
            json!(3)
        );
        assert_eq!(all_secret_storage_backups(&payload).len(), 3);
    }

    #[test]
    fn a_bumped_secret_version_wins_over_an_older_series_tail() {
        let payload = list(
            Some(SERIES),
            vec![
                body(7, SERIES, "mls_account_secret", "passphrase_kdf", 1),
                body(0, SERIES, "mls_account_secret", "passphrase_kdf", 2),
            ],
        );
        let selected = select_mls_account_secret_backup(&payload).unwrap();
        assert_eq!(selected["contents"][0]["secret_version"], json!(2));
        assert_eq!(mls_account_secret_backup_version(&selected), 2);
    }

    #[test]
    fn an_unversioned_envelope_reads_as_the_current_local_version() {
        let mut unversioned = body(1, SERIES, "mls_account_secret", "passphrase_kdf", 0);
        unversioned["contents"][0]
            .as_object_mut()
            .unwrap()
            .remove("secret_version");
        assert_eq!(
            mls_account_secret_backup_version(&unversioned),
            super::super::ACCOUNT_MLS_SECRET_CURRENT_VERSION
        );
    }
}
