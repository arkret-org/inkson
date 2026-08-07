//! Tests for account- and device-scoped snapshot-secret management.

use crate::mls::runtime::*;
use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore, SecureKeyStoreError};
use crate::state::isolated_store_for_tests as temp_state_store;

#[test]
fn device_snapshot_secret_is_created_and_reused() {
    let store = MemorySecureKeyStore::new();
    let first = load_or_create_device_snapshot_secret(
        &store,
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
    )
    .unwrap();
    let second = load_or_create_device_snapshot_secret(
        &store,
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
    )
    .unwrap();
    assert_eq!(first, second);
    assert_eq!(first.len(), 43);
}

#[test]
fn device_snapshot_secret_load_does_not_create() {
    let store = MemorySecureKeyStore::new();
    let missing = load_device_snapshot_secret(
        &store,
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
    )
    .unwrap_err();
    assert!(matches!(missing, SecureKeyStoreError::NotFound));
    assert!(store.is_empty());
}

#[test]
fn account_secret_is_shared_across_devices() {
    let store = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    let from_a = load_or_create_device_snapshot_secret(&store, actor, "ak:device:a").unwrap();
    // A different device of the SAME account must resolve the SAME secret.
    let from_b = load_or_create_device_snapshot_secret(&store, actor, "ak:device:b").unwrap();
    assert_eq!(from_a, from_b);
    // It is stored under the account key, not a device key.
    assert!(
        store
            .get_secret(&account_mls_secret_key(actor))
            .unwrap()
            .is_some()
    );
}

#[test]
fn store_account_mls_secret_round_trips() {
    let store = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    store_account_mls_secret(&store, actor, "recovered-secret").unwrap();
    let loaded = load_device_snapshot_secret(&store, actor, "ak:device:fresh").unwrap();
    assert_eq!(loaded, "recovered-secret");
}

#[test]
fn account_secret_load_picks_highest_version() {
    let store = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    store_account_mls_secret_version(&store, actor, 1, "old-secret").unwrap();
    store_account_mls_secret_version(&store, actor, 3, "new-secret").unwrap();

    let loaded = load_account_mls_secret(&store, actor)
        .unwrap()
        .expect("secret present");

    assert_eq!(loaded.version, 3);
    assert_eq!(loaded.secret, "new-secret");
    assert_eq!(
        load_device_snapshot_secret(&store, actor, "ak:device:any").unwrap(),
        "new-secret"
    );
}

#[test]
fn store_account_mls_secret_rejects_empty() {
    let store = MemorySecureKeyStore::new();
    assert!(store_account_mls_secret(&store, "did:web:alice.example", "  ").is_err());
    assert!(store_account_mls_secret(&store, "  ", "secret").is_err());
}

#[test]
fn replace_account_mls_secret_removes_higher_stale_versions() {
    let store = MemorySecureKeyStore::new();
    let actor = "did:web:alice.example";
    store_account_mls_secret_version(&store, actor, 2, "server-secret").unwrap();
    store_account_mls_secret_version(&store, actor, 3, "stale-local-secret").unwrap();

    replace_account_mls_secret_version(&store, actor, 2, "recovered-secret").unwrap();

    let loaded = load_account_mls_secret(&store, actor)
        .unwrap()
        .expect("secret present");
    assert_eq!(loaded.version, 2);
    assert_eq!(loaded.secret, "recovered-secret");
    assert_eq!(
        store
            .get_secret(&account_mls_secret_key_for_version(actor, 3))
            .unwrap(),
        None
    );
}

#[test]
fn missing_welcome_message_points_to_backup_restore() {
    let message = MlsRuntimeStatus::MissingWelcome.user_message();
    assert_eq!(
        message,
        "MLS state is not ready on this device yet; wait for an MLS Welcome or restore this device's encrypted MLS history backup."
    );
}

#[test]
fn account_secret_rotation_rewraps_backups_old_secret_cannot_decrypt() {
    use std::collections::BTreeMap;

    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let realm = "ak:realm:AdGAhhjx8Y3XQNfetd3DTBNMzZje_RzjhvG3c5aMUs4g";
    let old_secret = "old-account-secret";
    let plaintext = b"opaque sdk state before revoke";
    let store = MemorySecureKeyStore::new();
    store_account_mls_secret_version(&store, actor, 1, old_secret).unwrap();
    let original = crate::mls::persistence::encrypt_state(
        realm,
        "group-after-revoke",
        12,
        plaintext,
        old_secret,
        b"deterministic-salt",
    );
    let snapshots = BTreeMap::from([(realm.to_owned(), original)]);

    let rotation = prepare_account_mls_secret_rotation(&store, actor, device, &snapshots).unwrap();

    assert_eq!(rotation.previous_version, 1);
    assert_eq!(rotation.new_version, 2);
    assert_ne!(rotation.new_secret, old_secret);
    let rotated = rotation
        .rewrapped_snapshots
        .get(realm)
        .expect("rewrapped snapshot");
    let (_backup_id, body) = build_mls_history_backup_body_with_secret(
        rotated,
        actor,
        device,
        &rotation.new_secret,
        None,
    )
    .unwrap();
    let typed = parse_mls_history_backup(&body).unwrap();
    let decoded = decode_mls_history_backup_envelope(&typed, &rotation.new_secret).unwrap();
    assert!(
        crate::mls::persistence::decrypt_envelope(&decoded, old_secret).is_err(),
        "revoked device's old account secret must not decrypt the new backup"
    );
    let recovered =
        crate::mls::persistence::decrypt_envelope(&decoded, &rotation.new_secret).unwrap();
    assert_eq!(recovered, plaintext);

    let mut state = temp_state_store("rotate-commit");
    commit_account_mls_secret_rotation(&mut state, &store, actor, &rotation).unwrap();
    assert_eq!(
        load_device_snapshot_secret(&store, actor, device).unwrap(),
        rotation.new_secret
    );
    assert!(
        store
            .get_secret(&account_mls_secret_key_for_version(actor, 1))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        state.mls_snapshot_for(realm).unwrap().ciphertext_hex,
        rotated.ciphertext_hex
    );
}

#[test]
fn account_secret_rotation_skips_undecryptable_realm_and_records_failure() {
    // COR-12: one realm snapshot that cannot be decrypted with the previous
    // secret (corrupt / format-drifted) MUST NOT block the rotation of the
    // other realms; it is skipped and recorded in `failed_realms`.
    use std::collections::BTreeMap;

    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let good_realm = "ak:realm:ATOz4l-vKJUCGZDmS_knGS9TjZ64pkOzx-HNGAgY5RGJ";
    let bad_realm = "ak:realm:ASyFf0qTUQ55a2qZp5fuTXRnIgf3ovKChQZ_XSkxdIPK";
    let old_secret = "old-account-secret";
    let store = MemorySecureKeyStore::new();
    store_account_mls_secret_version(&store, actor, 1, old_secret).unwrap();

    // good_realm: wrapped under the previous secret (decryptable).
    let good = crate::mls::persistence::encrypt_state(
        good_realm,
        "group-good",
        3,
        b"good opaque state",
        old_secret,
        b"salt-good",
    );
    // bad_realm: wrapped under a DIFFERENT secret → won't decrypt with old_secret.
    let bad = crate::mls::persistence::encrypt_state(
        bad_realm,
        "group-bad",
        4,
        b"bad opaque state",
        "some-other-secret",
        b"salt-bad",
    );
    let snapshots = BTreeMap::from([(good_realm.to_owned(), good), (bad_realm.to_owned(), bad)]);

    let rotation = prepare_account_mls_secret_rotation(&store, actor, device, &snapshots).unwrap();

    // Good realm rotated; bad realm skipped + recorded.
    assert!(rotation.rewrapped_snapshots.contains_key(good_realm));
    assert!(!rotation.rewrapped_snapshots.contains_key(bad_realm));
    assert_eq!(rotation.failed_realms.len(), 1);
    assert_eq!(rotation.failed_realms[0].0, bad_realm);
}
