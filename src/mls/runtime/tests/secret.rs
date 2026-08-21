//! Tests for account- and device-scoped snapshot-secret management.

use crate::mls::runtime::*;
use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore, SecureKeyStoreError};
use crate::state::isolated_store_for_tests as temp_state_store;

#[test]
fn device_snapshot_secret_is_created_and_reused() {
    let store = MemorySecureKeyStore::new();
    let first = load_or_create_account_mls_secret(&store, "did:web:alice.example").unwrap();
    let second = load_or_create_account_mls_secret(&store, "did:web:alice.example").unwrap();
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
    let from_a = load_or_create_account_mls_secret(&store, actor).unwrap();
    // A different device of the SAME account must resolve the SAME secret.
    let from_b = load_or_create_account_mls_secret(&store, actor).unwrap();
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

    let rotation = prepare_account_mls_secret_rotation(&store, actor, &snapshots).unwrap();

    assert_eq!(rotation.previous_version, 1);
    assert_eq!(rotation.new_version, 2);
    assert_ne!(rotation.new_secret, old_secret);
    let rotated = rotation
        .rewrapped_snapshots
        .get(realm)
        .expect("rewrapped snapshot");
    assert!(
        crate::mls::persistence::decrypt_envelope(rotated, old_secret).is_err(),
        "revoked device's old account secret must not decrypt the rewrapped local snapshot"
    );
    let recovered =
        crate::mls::persistence::decrypt_envelope(rotated, &rotation.new_secret).unwrap();
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

    let rotation = prepare_account_mls_secret_rotation(&store, actor, &snapshots).unwrap();

    // Good realm rotated; bad realm skipped + recorded.
    assert!(rotation.rewrapped_snapshots.contains_key(good_realm));
    assert!(!rotation.rewrapped_snapshots.contains_key(bad_realm));
    assert_eq!(rotation.failed_realms.len(), 1);
    assert_eq!(rotation.failed_realms[0].0, bad_realm);
}

/// D4 — the local KeyPackage publish marker is pinned at `.v1`.
///
/// Local key material has no parallel version axis in this project, so the
/// marker prefix is fixed. A key written under any other prefix is not this
/// marker and MUST NOT be read back through a fallback.
#[test]
fn key_package_publish_marker_key_is_pinned_at_v1() {
    let key = mls_key_package_publish_marker_key(
        "https://local.host",
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000001",
    )
    .unwrap();

    assert!(key.starts_with("inkson.mls_key_package.publish_marker.v1."));
    assert!(!key.contains("publish_marker.v4"));
    // The three scope components are distinct: a different device must not
    // collide with this device's marker.
    let other_device = mls_key_package_publish_marker_key(
        "https://local.host",
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-000000000002",
    )
    .unwrap();
    assert_ne!(key, other_device);
}

/// D4 — a leftover marker written under the retired `.v4` prefix cannot block
/// this device from safely publishing a fresh KeyPackage, and the current
/// marker stays idempotent across repeated publishes of the same KeyPackage.
#[test]
fn a_retired_marker_does_not_block_a_safe_key_package_republish() {
    let store = MemorySecureKeyStore::new();
    let server = "https://local.host";
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";

    // A leftover marker from the retired prefix. There is no fallback read, so
    // the loader reports "never published" and the caller mints a new
    // KeyPackage — the safe re-publish, not a stuck client.
    let retired_key = mls_key_package_publish_marker_key(server, actor, device)
        .unwrap()
        .replace("publish_marker.v1.", "publish_marker.v4.");
    store
        .store_secret(&retired_key, "ak:keypackage:retired")
        .unwrap();
    assert_eq!(
        load_mls_key_package_publish_marker(&store, server, actor, device).unwrap(),
        None
    );

    // Publishing records the new marker.
    store_mls_key_package_publish_marker(&store, server, actor, device, "ak:keypackage:fresh")
        .unwrap();
    assert_eq!(
        load_mls_key_package_publish_marker(&store, server, actor, device).unwrap(),
        Some("ak:keypackage:fresh".to_owned())
    );

    // Re-publishing the same KeyPackage is idempotent: one marker, same value.
    store_mls_key_package_publish_marker(&store, server, actor, device, "ak:keypackage:fresh")
        .unwrap();
    assert_eq!(
        load_mls_key_package_publish_marker(&store, server, actor, device).unwrap(),
        Some("ak:keypackage:fresh".to_owned())
    );

    // The retired key is never read and never rewritten by the current marker.
    assert_eq!(
        store.get_secret(&retired_key).unwrap().as_deref(),
        Some("ak:keypackage:retired")
    );

    // Clearing a stale marker (the "identity state is gone" repair path) is
    // idempotent and leaves the loader reporting "never published" again.
    delete_mls_key_package_publish_marker(&store, server, actor, device).unwrap();
    delete_mls_key_package_publish_marker(&store, server, actor, device).unwrap();
    assert_eq!(
        load_mls_key_package_publish_marker(&store, server, actor, device).unwrap(),
        None
    );
}

/// D4 — the publish gate itself: with a marker AND its KeyPackage identity
/// state present the client skips republishing; when the identity state is
/// gone the marker is cleared so the next attempt mints a fresh KeyPackage
/// instead of advertising one it can no longer decrypt Welcomes for.
#[test]
fn publish_marker_only_suppresses_republish_while_its_key_material_survives() {
    let store = MemorySecureKeyStore::new();
    let server = "https://local.host";
    let actor = "did:web:alice.example";
    let device = "ak:device:01904100-0000-7000-8000-000000000001";
    let key_package_id = "ak:keypackage:fresh";

    store_mls_key_package_publish_marker(&store, server, actor, device, key_package_id).unwrap();
    store_mls_key_package_identity_state(&store, actor, device, key_package_id, b"private-state")
        .unwrap();
    assert_eq!(
        load_mls_key_package_publish_marker(&store, server, actor, device).unwrap(),
        Some(key_package_id.to_owned())
    );
    assert!(
        load_mls_key_package_identity_state(&store, actor, device, key_package_id)
            .unwrap()
            .is_some(),
        "marker plus live identity state means the publish is already done"
    );

    delete_mls_key_package_identity_state(&store, actor, device, key_package_id).unwrap();
    assert!(
        load_mls_key_package_identity_state(&store, actor, device, key_package_id)
            .unwrap()
            .is_none()
    );
    delete_mls_key_package_publish_marker(&store, server, actor, device).unwrap();
    assert_eq!(
        load_mls_key_package_publish_marker(&store, server, actor, device).unwrap(),
        None,
        "a marker without key material must not suppress the next publish"
    );
}
