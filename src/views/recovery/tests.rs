//! Tests for backup-summary parsing and recovery-state predicates.

use serde_json::json;

use super::backup_summary::{
    BackupInventoryStatus, backup_inventory_status, parse_backup_list, parse_backup_summary,
    sorted_backups_latest_first,
};
use super::state::{decode_recovery_public_key_multibase, recovery_state_has_user_material};
use super::types::RecoveryState;

#[test]
fn parse_backup_summary_extracts_visible_metadata() {
    let row = parse_backup_summary(&json!({
        "backup_id": "ak:backup:01964137-0000-7000-8000-000000000000",
        "backup_kind": "secret_storage",
        "backup_version": "kb_1",
        "created_at": "2026-05-15T00:00:00.000Z",
        "ciphertext_digest": "sha256:abc",
        "encryption": {
            "recipient_method": "passphrase_kdf",
            "kdf": { "name": "argon2id", "salt": "U0FMVA" },
            "aead": { "name": "xchacha20_poly1305", "nonce": "Tk9OQ0U" }
        },
        "ciphertext": "Q1Q"
    }))
    .unwrap();
    assert_eq!(
        row.backup_id,
        "ak:backup:01964137-0000-7000-8000-000000000000"
    );
    assert_eq!(row.backup_kind, "secret_storage");
    assert_eq!(row.created_at, "2026-05-15T00:00:00.000Z");
}

#[test]
fn parse_backup_list_handles_envelope() {
    let enveloped = json!({"backups": [{"backup_id": "ak:backup:x"}]});
    assert_eq!(parse_backup_list(&enveloped).len(), 1);
    assert!(parse_backup_list(&json!([{"backup_id": "ak:backup:y"}])).is_empty());
}

#[test]
fn parse_backup_summary_rejects_missing_id() {
    assert!(parse_backup_summary(&json!({})).is_none());
}

#[test]
fn backup_inventory_status_marks_empty_server_as_empty() {
    assert_eq!(backup_inventory_status(&[]), BackupInventoryStatus::Empty);
}

#[test]
fn backup_inventory_status_reports_count_and_latest() {
    let rows = parse_backup_list(&json!({
        "backups": [
            {
                "backup_id": "ak:backup:b",
                "backup_kind": "secret_storage",
                "created_at": "2026-05-15T00:00:00.000Z",
                "encryption": {"recipient_method": "recovery_public_key"}
            },
            {
                "backup_id": "ak:backup:c",
                "backup_kind": "mls_history",
                "created_at": "2026-05-16T00:00:00.000Z",
                "encryption": {"recipient_method": "secret_storage_key"}
            }
        ]
    }));
    assert_eq!(
        backup_inventory_status(&rows),
        BackupInventoryStatus::Loaded {
            count: 2,
            latest: "2026-05-16 00:00 UTC".to_owned(),
        }
    );
}

#[test]
fn sorted_backups_latest_first_orders_by_created_at() {
    let rows = parse_backup_list(&json!({
        "backups": [
            {
                "backup_id": "ak:backup:older",
                "created_at": "2026-05-15T00:00:00.000Z"
            },
            {
                "backup_id": "ak:backup:newer",
                "created_at": "2026-05-16T00:00:00.000Z"
            }
        ]
    }));
    let sorted = sorted_backups_latest_first(&rows);
    assert_eq!(sorted.first().unwrap().backup_id, "ak:backup:newer");
}

#[test]
fn recovery_state_without_user_material_is_not_configured() {
    assert!(!recovery_state_has_user_material(&RecoveryState::default()));
}

#[test]
fn recovery_state_with_key_is_configured() {
    let keyed = RecoveryState {
        recovery_key_fingerprint: "sha256:abc".to_owned(),
        ..Default::default()
    };
    assert!(recovery_state_has_user_material(&keyed));
}

#[test]
fn recovery_public_multikey_decodes_normative_x25519_kat() {
    let decoded =
        decode_recovery_public_key_multibase("z6LSriWhVBzW9Vz2PvqbieSz7Aa2hPLzTKJuDwXTMKFeomeW")
            .unwrap();
    assert_eq!(
        crate::canonical::hex_encode(&decoded),
        "df788d7169420382ba1358ff083c77f48a8d98cf4b6f08efdc2555af8f41b06f"
    );
}

#[test]
fn recovery_public_multikey_rejects_an_ed25519_key() {
    assert!(
        decode_recovery_public_key_multibase("z6MkogKw38hXxUkpMWitoBubBGHZzeGrQJ4oHF36iegUbmpA")
            .is_err()
    );
}
