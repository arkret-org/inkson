//! Private plaintext sidecar, merge semantics, and encrypted private-data tests.

use super::*;

#[test]
fn private_plaintext_snapshot_json_round_trips_through_merge() {
    // X5.3 — write sidecar entries, snapshot to JSON, then merge that JSON
    // into a FRESH store (the new-browser restore case) and read them back.
    let path = temp_state_path("private-plaintext-snapshot");
    let mut store = LocalStateStore::with_path(path);
    assert!(store.private_plaintext_is_empty());
    store.save_private_plaintext("ak:realm:s1", "ak:strand:f1", "body", "\"hello body\"");
    store.save_private_plaintext(
        "ak:realm:s1",
        "ak:strand:f1",
        "synthesis",
        "\"hello synthesis\"",
    );
    store.save_private_plaintext("ak:realm:s2", "ak:strand:f2", "body", "\"other body\"");
    assert!(!store.private_plaintext_is_empty());

    let json = store.private_plaintext_snapshot_json();
    let map: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>> =
        serde_json::from_slice(&json).unwrap();

    // Fresh store (empty) merges the snapshot -> every field reappears.
    let fresh_path = temp_state_path("private-plaintext-merged");
    let mut fresh = LocalStateStore::with_path(fresh_path);
    assert!(fresh.private_plaintext_is_empty());
    fresh.merge_private_plaintext_map(map);
    assert_eq!(
        fresh.private_plaintext_for("ak:realm:s1", "ak:strand:f1", "body"),
        Some("\"hello body\"".to_owned())
    );
    assert_eq!(
        fresh.private_plaintext_for("ak:realm:s1", "ak:strand:f1", "synthesis"),
        Some("\"hello synthesis\"".to_owned())
    );
    assert_eq!(
        fresh.private_plaintext_for("ak:realm:s2", "ak:strand:f2", "body"),
        Some("\"other body\"".to_owned())
    );
}

#[test]
fn merge_private_plaintext_map_keeps_local_value_on_conflict() {
    // X5.3 merge semantics: incoming only FILLS missing fields; an existing
    // local value wins on conflict.
    let path = temp_state_path("private-plaintext-conflict");
    let mut store = LocalStateStore::with_path(path);
    store.save_private_plaintext("ak:realm:s1", "ak:strand:f1", "body", "\"local newer\"");

    let mut fields = BTreeMap::new();
    fields.insert("body".to_owned(), "\"backup older\"".to_owned()); // conflict
    fields.insert("synthesis".to_owned(), "\"backup synthesis\"".to_owned()); // gap
    let mut strands = BTreeMap::new();
    strands.insert("ak:strand:f1".to_owned(), fields);
    let mut incoming = BTreeMap::new();
    incoming.insert("ak:realm:s1".to_owned(), strands);
    store.merge_private_plaintext_map(incoming);

    // Conflict: local value kept.
    assert_eq!(
        store.private_plaintext_for("ak:realm:s1", "ak:strand:f1", "body"),
        Some("\"local newer\"".to_owned())
    );
    // Gap: backup fills it.
    assert_eq!(
        store.private_plaintext_for("ak:realm:s1", "ak:strand:f1", "synthesis"),
        Some("\"backup synthesis\"".to_owned())
    );
}

#[test]
fn private_plaintext_sidecar_stays_memory_only_without_secure_store() {
    // Fail-closed fallback: without a hardened store, keep the current-process
    // cache but never serialize the plaintext sidecar into account-state JSON.
    let path = temp_state_path("private-plaintext-sidecar");
    let realm = "ak:realm:0196419b-0000-7000-8000-000000000001";
    let strand = "ak:strand:0196419b-0000-7000-8000-0000000000aa";
    {
        let mut store = LocalStateStore::with_path(path.clone());
        store.save_private_plaintext(realm, strand, "body", "\"author body\"");
        store.save_private_plaintext(realm, strand, "synthesis", "\"author synthesis\"");
        assert_eq!(
            store
                .private_plaintext_for(realm, strand, "body")
                .as_deref(),
            Some("\"author body\"")
        );
        assert_eq!(
            store
                .private_plaintext_for(realm, strand, "synthesis")
                .as_deref(),
            Some("\"author synthesis\"")
        );
        let fields = store.private_plaintext_fields(realm, strand);
        assert_eq!(fields.len(), 2);
        let account_path = store.account_state_path(&store.effective_account_key());
        let raw = std::fs::read_to_string(&account_path).expect("account state written");
        assert!(!raw.contains("author body"));
        assert!(!raw.contains("author synthesis"));
        assert!(!raw.contains("mls_private_plaintext"));
        assert!(!raw.contains("mls_decrypted_plaintext"));
    }
    // Fresh reader (simulating a process restart / reload).
    let reader = LocalStateStore::with_path(path.clone());
    assert!(
        reader
            .private_plaintext_for(realm, strand, "body")
            .is_none()
    );
    assert!(
        reader
            .private_plaintext_for(realm, strand, "synthesis")
            .is_none()
    );
    let fields = reader.private_plaintext_fields(realm, strand);
    assert!(fields.is_empty());
    // Missing keys return None.
    assert!(
        reader
            .private_plaintext_for(realm, strand, "content")
            .is_none()
    );
    assert!(
        reader
            .private_plaintext_for("ak:realm:other", strand, "body")
            .is_none()
    );

    // Clearing a field (empty plaintext) removes it and persists.
    let mut writer = LocalStateStore::with_path(path.clone());
    writer.save_private_plaintext(realm, strand, "body", "");
    let reader = LocalStateStore::with_path(path);
    assert!(
        reader
            .private_plaintext_for(realm, strand, "body")
            .is_none()
    );
    assert!(
        reader
            .private_plaintext_for(realm, strand, "synthesis")
            .is_none()
    );
}

#[test]
fn e2ee_plaintext_cache_round_trips_through_account_scoped_secure_store() {
    use crate::mls::persistence::encrypt_state;
    use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore};

    let path = temp_state_path("e2ee-secure-cache-roundtrip");
    let actor = "did:web:alice.example";
    let realm = "ak:realm:0196419b-0000-7000-8000-000000000010";
    let strand = "ak:strand:0196419b-0000-7000-8000-000000000011";
    let digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let secure = MemorySecureKeyStore::new();

    {
        let mut writer = LocalStateStore::with_path(path.clone());
        assert!(writer.switch_active_account(actor));
        writer.save_private_plaintext(realm, strand, "body", "\"author secret\"");
        writer.advance_mls_receive_chain(
            realm,
            encrypt_state(realm, "abcd", 1, b"state", "profile", b"salt"),
            digest,
            b"remote secret",
        );
        assert!(
            writer
                .persist_e2ee_plaintext_cache_with_secure_store(&secure)
                .unwrap()
        );

        let account_path = writer.account_state_path(actor);
        let raw = std::fs::read_to_string(account_path).expect("account state written");
        assert!(!raw.contains("author secret"));
        assert!(!raw.contains("remote secret"));
        assert!(!raw.contains("mls_private_plaintext"));
        assert!(!raw.contains("mls_decrypted_plaintext"));

        let key = crate::secure_key_store::e2ee_plaintext_cache_store_key(actor);
        assert!(secure.get_secret(&key).unwrap().is_some());
    }

    let mut reader = LocalStateStore::with_path(path);
    assert!(!reader.switch_active_account(actor));
    assert!(
        reader
            .private_plaintext_for(realm, strand, "body")
            .is_none()
    );
    assert!(reader.mls_decrypted_plaintext_for(realm, digest).is_none());

    assert!(
        reader
            .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap()
    );
    assert_eq!(
        reader
            .private_plaintext_for(realm, strand, "body")
            .as_deref(),
        Some("\"author secret\"")
    );
    assert_eq!(
        reader.mls_decrypted_plaintext_for(realm, digest).as_deref(),
        Some(&b"remote secret"[..])
    );
}

#[test]
fn receive_snapshot_and_plaintext_share_one_secure_entry() {
    use crate::mls::persistence::encrypt_state;
    use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore};

    let actor = "did:web:alice.example";
    let realm = "ak:realm:0196419b-0000-7000-8000-000000000015";
    let digest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let secure = MemorySecureKeyStore::new();
    let envelope = encrypt_state(realm, "abcd", 4, b"advanced", "profile", b"salt");

    let mut writer = LocalStateStore::with_path(temp_state_path("e2ee-combined-writer"));
    writer.switch_active_account(actor);
    writer.advance_mls_receive_chain(realm, envelope.clone(), digest, b"combined remote secret");
    writer
        .persist_e2ee_plaintext_cache_with_secure_store(&secure)
        .unwrap();

    let key = crate::secure_key_store::e2ee_plaintext_cache_store_key(actor);
    let raw = secure.get_secret(&key).unwrap().expect("combined entry");
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert!(value["mls_snapshots"].get(realm).is_some());
    assert!(value["decrypted_plaintext"][realm].get(digest).is_some());

    let mut reloaded = LocalStateStore::with_path(temp_state_path("e2ee-combined-reader"));
    reloaded.switch_active_account(actor);
    assert!(reloaded.mls_snapshot_for(realm).is_none());
    assert!(
        reloaded
            .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap()
    );
    assert_eq!(reloaded.mls_snapshot_for(realm), Some(envelope));
    assert_eq!(
        reloaded
            .mls_decrypted_plaintext_for(realm, digest)
            .as_deref(),
        Some(&b"combined remote secret"[..])
    );
}

#[test]
fn secure_snapshot_replaces_stale_same_epoch_account_snapshot() {
    use crate::mls::persistence::encrypt_state;
    use crate::secure_key_store::MemorySecureKeyStore;

    let actor = "did:web:alice.example";
    let realm = "ak:realm:0196419b-0000-7000-8000-000000000016";
    let secure = MemorySecureKeyStore::new();
    let stale = encrypt_state(realm, "abcd", 5, b"stale", "profile", b"salt");
    let current = encrypt_state(realm, "abcd", 5, b"current", "profile", b"salt");

    let mut secure_writer = LocalStateStore::with_path(temp_state_path("e2ee-current-writer"));
    secure_writer.switch_active_account(actor);
    secure_writer.save_mls_snapshot(realm, current.clone());
    secure_writer
        .persist_e2ee_plaintext_cache_with_secure_store(&secure)
        .unwrap();

    let local_path = temp_state_path("e2ee-stale-local");
    let mut reloaded = LocalStateStore::with_path(local_path);
    reloaded.switch_active_account(actor);
    reloaded.save_mls_snapshot(realm, stale.clone());
    assert_eq!(reloaded.mls_snapshot_for(realm), Some(stale));
    assert!(
        reloaded
            .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap()
    );
    assert_eq!(reloaded.mls_snapshot_for(realm), Some(current));
}

#[test]
fn missing_secure_checkpoint_rolls_back_to_pre_decrypt_snapshot() {
    use crate::mls::persistence::encrypt_state;
    use crate::secure_key_store::MemorySecureKeyStore;

    let path = temp_state_path("e2ee-interrupted-checkpoint");
    let actor = "did:web:alice.example";
    let realm = "ak:realm:0196419b-0000-7000-8000-000000000017";
    let digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let base = encrypt_state(realm, "abcd", 6, b"base", "profile", b"salt");
    let advanced = encrypt_state(realm, "abcd", 6, b"advanced", "profile", b"salt");

    {
        let mut writer = LocalStateStore::with_path(path.clone());
        writer.switch_active_account(actor);
        writer.save_mls_snapshot(realm, base.clone());
        writer.advance_mls_receive_chain(realm, advanced.clone(), digest, b"interrupted plaintext");
        assert_eq!(writer.mls_snapshot_for(realm), Some(advanced.clone()));
        assert_eq!(
            writer.load().mls_receive_recovery_snapshots.get(realm),
            Some(&base)
        );
    }

    // Simulate a page exit before the combined IndexedDB entry commits: the
    // account file has the advanced encrypted snapshot and recovery checkpoint,
    // while the hardened store is still empty and contains no plaintext.
    let secure = MemorySecureKeyStore::new();
    let mut reloaded = LocalStateStore::with_path(path);
    assert!(!reloaded.switch_active_account(actor));
    assert_eq!(reloaded.mls_snapshot_for(realm), Some(advanced));
    assert!(
        reloaded
            .mls_decrypted_plaintext_for(realm, digest)
            .is_none()
    );
    assert!(
        reloaded
            .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap()
    );
    assert_eq!(reloaded.mls_snapshot_for(realm), Some(base));
    assert!(
        reloaded
            .mls_decrypted_plaintext_for(realm, digest)
            .is_none()
    );

    // Bootstrap now persisted a coherent checkpoint; cleanup can remove the
    // temporary rollback journal without touching that secure entry.
    reloaded.clear_mls_receive_recovery_snapshots().unwrap();
    assert!(reloaded.load().mls_receive_recovery_snapshots.is_empty());
}

#[test]
fn dropping_mls_snapshot_also_drops_receive_recovery_checkpoint() {
    use crate::mls::persistence::encrypt_state;
    use crate::secure_key_store::MemorySecureKeyStore;

    let path = temp_state_path("e2ee-drop-recovery-checkpoint");
    let actor = "did:web:alice.example";
    let realm = "ak:realm:0196419b-0000-7000-8000-000000000018";
    let digest = "sha256:abababababababababababababababababababababababababababababababab";
    let secure = MemorySecureKeyStore::new();
    {
        let mut writer = LocalStateStore::with_path(path.clone());
        writer.switch_active_account(actor);
        writer.save_mls_snapshot(
            realm,
            encrypt_state(realm, "abcd", 7, b"base", "profile", b"salt"),
        );
        writer.advance_mls_receive_chain(
            realm,
            encrypt_state(realm, "abcd", 7, b"advanced", "profile", b"salt"),
            digest,
            b"cached plaintext",
        );
        writer.drop_mls_snapshot(realm);
        assert!(writer.mls_snapshot_for(realm).is_none());
        assert!(writer.load().mls_receive_recovery_snapshots.is_empty());
        writer
            .persist_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap();
    }

    let mut reloaded = LocalStateStore::with_path(path);
    assert!(!reloaded.switch_active_account(actor));
    reloaded
        .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
        .unwrap();
    assert!(reloaded.mls_snapshot_for(realm).is_none());
}

#[test]
fn secure_cache_hydration_fills_gaps_without_overwriting_live_values() {
    use crate::mls::persistence::encrypt_state;
    use crate::secure_key_store::MemorySecureKeyStore;

    let actor = "did:web:alice.example";
    let realm = "ak:realm:0196419b-0000-7000-8000-000000000020";
    let strand = "ak:strand:0196419b-0000-7000-8000-000000000021";
    let digest_conflict = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let digest_gap = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let secure = MemorySecureKeyStore::new();

    let mut persisted = LocalStateStore::with_path(temp_state_path("e2ee-secure-cache-old"));
    persisted.switch_active_account(actor);
    persisted.save_private_plaintext(realm, strand, "body", "\"stored older\"");
    persisted.save_private_plaintext(realm, strand, "synthesis", "\"stored gap\"");
    persisted.advance_mls_receive_chain(
        realm,
        encrypt_state(realm, "abcd", 1, b"stored-a", "profile", b"salt"),
        digest_conflict,
        b"stored remote older",
    );
    persisted.advance_mls_receive_chain(
        realm,
        encrypt_state(realm, "abcd", 2, b"stored-b", "profile", b"salt"),
        digest_gap,
        b"stored remote gap",
    );
    persisted
        .persist_e2ee_plaintext_cache_with_secure_store(&secure)
        .unwrap();

    let mut live = LocalStateStore::with_path(temp_state_path("e2ee-secure-cache-live"));
    live.switch_active_account(actor);
    live.save_private_plaintext(realm, strand, "body", "\"live newer\"");
    live.advance_mls_receive_chain(
        realm,
        encrypt_state(realm, "abcd", 3, b"live", "profile", b"salt"),
        digest_conflict,
        b"live remote newer",
    );

    assert!(
        live.hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap()
    );
    assert_eq!(
        live.private_plaintext_for(realm, strand, "body").as_deref(),
        Some("\"live newer\"")
    );
    assert_eq!(
        live.private_plaintext_for(realm, strand, "synthesis")
            .as_deref(),
        Some("\"stored gap\"")
    );
    assert_eq!(
        live.mls_decrypted_plaintext_for(realm, digest_conflict)
            .as_deref(),
        Some(&b"live remote newer"[..])
    );
    assert_eq!(
        live.mls_decrypted_plaintext_for(realm, digest_gap)
            .as_deref(),
        Some(&b"stored remote gap"[..])
    );
}

#[test]
fn secure_cache_bootstrap_persists_live_values_when_no_entry_exists_yet() {
    use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore};

    let actor = "did:web:alice.example";
    let realm = "ak:realm:0196419b-0000-7000-8000-000000000030";
    let strand = "ak:strand:0196419b-0000-7000-8000-000000000031";
    let secure = MemorySecureKeyStore::new();
    let mut live = LocalStateStore::with_path(temp_state_path("e2ee-secure-cache-first-frame"));
    live.switch_active_account(actor);
    live.save_private_plaintext(realm, strand, "body", "\"written before init\"");

    let key = crate::secure_key_store::e2ee_plaintext_cache_store_key(actor);
    assert!(secure.get_secret(&key).unwrap().is_none());
    assert!(
        !live
            .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap()
    );
    assert!(secure.get_secret(&key).unwrap().is_some());

    let mut reloaded =
        LocalStateStore::with_path(temp_state_path("e2ee-secure-cache-first-frame-reload"));
    reloaded.switch_active_account(actor);
    assert!(
        reloaded
            .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap()
    );
    assert_eq!(
        reloaded
            .private_plaintext_for(realm, strand, "body")
            .as_deref(),
        Some("\"written before init\"")
    );
}

#[test]
fn history_secret_is_never_written_to_plaintext_state() {
    let mut by_epoch = BTreeMap::new();
    by_epoch.insert(7, b"history-secret".to_vec());
    let mut state = ClientLocalState::default();
    state
        .history_secrets
        .insert("ak:realm:history".to_owned(), by_epoch);

    let persisted = e2ee_safe_persist_state(&state);
    assert!(
        persisted.history_secrets.is_empty(),
        "history_secret must never enter plaintext persistence"
    );
}

#[test]
fn disappearing_message_plaintext_drop_clears_sidecar_and_decrypt_cache() {
    use crate::mls::persistence::encrypt_state;

    let path = temp_state_path("disappearing-shred");
    let realm = "ak:realm:0196419b-0000-7000-8000-000000000001";
    let strand = "ak:strand:0196419b-0000-7000-8000-0000000000aa";
    let message = "ak:message:0196419b-0000-7000-8000-0000000000bb";
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut store = LocalStateStore::with_path(path.clone());
    store.save_private_plaintext(realm, strand, &format!("message:{message}"), "secret body");
    store.advance_mls_receive_chain(
        realm,
        encrypt_state(realm, "abcd", 1, b"x", "p", b"salt"),
        digest,
        b"remote secret body",
    );

    assert_eq!(
        store.private_plaintext_for(realm, strand, &format!("message:{message}")),
        Some("secret body".to_owned())
    );
    assert_eq!(
        store.mls_decrypted_plaintext_for(realm, digest).as_deref(),
        Some(&b"remote secret body"[..])
    );

    assert!(store.drop_disappearing_message_plaintext(realm, strand, message, Some(digest)));
    assert!(!store.drop_disappearing_message_plaintext(realm, strand, message, Some(digest)));

    let reader = LocalStateStore::with_path(path);
    assert!(
        reader
            .private_plaintext_for(realm, strand, &format!("message:{message}"))
            .is_none()
    );
    assert!(reader.mls_decrypted_plaintext_for(realm, digest).is_none());
}

#[test]
fn private_data_store_encrypts_and_persists() {
    let path = temp_state_path("private");
    let mut store = LocalStateStore::with_path(path.clone());
    let account_key = "did:web:alice.example";
    store.save_private_data(account_key, "theme", "dark");
    store.save_private_data(account_key, "custom_emoji", "party_parrot");

    assert_eq!(
        store.load_private_data(account_key, "theme"),
        Some("dark".to_owned())
    );
    assert_eq!(
        store.load_private_data(account_key, "custom_emoji"),
        Some("party_parrot".to_owned())
    );
    assert!(store.load_private_data(account_key, "missing").is_none());
    assert_eq!(store.private_data_keys().len(), 2);

    // Verify data is encrypted on disk. With per-account isolation the active
    // blob persists to a sibling `<stem>.account.<sanitized>.json` file (the
    // root `path` now only holds the small index). Signed out, the namespace is
    // the anonymous sentinel; its filename segment is URL-safe-base64 of the
    // namespace, matching `sanitize_did_for_filename`.
    let account_file = {
        use base64::Engine as _;
        let sanitized =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("anonymous".as_bytes());
        let stem = path.file_stem().unwrap().to_str().unwrap();
        let ext = path.extension().unwrap().to_str().unwrap();
        path.parent()
            .unwrap()
            .join(format!("{stem}.account.{sanitized}.{ext}"))
    };
    let raw = std::fs::read_to_string(&account_file).unwrap();
    assert!(!raw.contains("dark"));
    assert!(!raw.contains("party_parrot"));

    // Verify wrong key cannot decrypt
    assert_ne!(
        store.load_private_data("wrong-key", "theme"),
        Some("dark".to_owned())
    );
}

#[test]
fn private_data_remove_works() {
    let path = temp_state_path("private-remove");
    let mut store = LocalStateStore::with_path(path);
    store.save_private_data("key", "temp", "value");
    assert!(store.load_private_data("key", "temp").is_some());
    store.remove_private_data("temp");
    assert!(store.load_private_data("key", "temp").is_none());
}
