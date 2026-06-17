//! XOR private-data crypto helpers and MLS snapshot envelope persistence.

use super::*;

#[test]
fn xor_encrypt_decrypt_roundtrip() {
    let key = "did:web:alice.example";
    let plaintext = "my secret preference";
    let encrypted = xor_encrypt(key, plaintext);
    assert_ne!(encrypted, plaintext);
    let decrypted = xor_decrypt(key, &encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn xor_encrypt_empty_key_returns_original() {
    assert_eq!(xor_encrypt("", "hello"), "hello");
}

#[test]
fn mls_snapshot_persists_and_round_trips_through_store() {
    // MLS snapshot envelope is durable across store instances and the
    // boot path can rehydrate every realm's group from the persisted
    // record.
    use crate::mls::persistence::encrypt_state;
    let path = temp_state_path("mls-snapshot-persist");
    let realm = "ck:realm:round28-mls";
    let envelope = encrypt_state(
        realm,
        "deadbeef",
        5,
        b"placeholder-state-bytes",
        "round28-pass",
        b"deterministic-salt",
    );
    {
        let mut writer = LocalStateStore::with_path(path.clone());
        assert!(writer.mls_snapshot_for(realm).is_none());
        writer.save_mls_snapshot(realm, envelope.clone());
    }
    let reader = LocalStateStore::with_path(path);
    let restored = reader.mls_snapshot_for(realm).expect("envelope persists");
    assert_eq!(restored.realm_id, envelope.realm_id);
    assert_eq!(restored.epoch, 5);
    assert_eq!(restored.ciphertext_hex, envelope.ciphertext_hex);
    assert_eq!(reader.mls_snapshots().len(), 1);
}

#[test]
fn mls_snapshot_drop_clears_persisted_record() {
    use crate::mls::persistence::encrypt_state;
    let path = temp_state_path("mls-snapshot-drop");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ck:realm:drop-me";
    store.save_mls_snapshot(realm, encrypt_state(realm, "abcd", 1, b"x", "p", b"salt"));
    assert!(store.mls_snapshot_for(realm).is_some());
    store.drop_mls_snapshot(realm);
    assert!(store.mls_snapshot_for(realm).is_none());
}
