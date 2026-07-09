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
fn private_plaintext_sidecar_stays_memory_only_in_account_state() {
    // X5.1: save into the current process cache, but never serialize the
    // plaintext sidecar into account-state JSON.
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
fn history_secret_inline_copy_survives_until_secure_store_persist_succeeds() {
    let mut by_epoch = BTreeMap::new();
    by_epoch.insert(7, b"history-secret".to_vec());
    let mut state = ClientLocalState::default();
    state
        .history_secrets
        .insert("ak:realm:history".to_owned(), by_epoch);

    let not_migrated = e2ee_safe_persist_state_after_history_migration(&state, false);
    assert!(
        not_migrated
            .history_secrets
            .contains_key("ak:realm:history"),
        "history_secret stays durable until IndexedDB persist succeeds"
    );

    let migrated = e2ee_safe_persist_state_after_history_migration(&state, true);
    assert!(
        migrated.history_secrets.is_empty(),
        "history_secret is stripped once hardened storage accepted it"
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
