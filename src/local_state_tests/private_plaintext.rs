//! Private plaintext sidecar, merge semantics, and plain local-data tests.

use super::*;

#[cfg(not(target_arch = "wasm32"))]
struct DelayedClearStore {
    inner: crate::secure_key_store::MemorySecureKeyStore,
    release: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    fail: bool,
}

#[cfg(not(target_arch = "wasm32"))]
impl crate::secure_key_store::SecureKeyStore for DelayedClearStore {
    fn store_secret_bytes(
        &self,
        key: &str,
        value: &[u8],
    ) -> Result<(), crate::secure_key_store::SecureKeyStoreError> {
        self.inner.store_secret_bytes(key, value)
    }

    fn store_secret_bytes_durable<'a>(
        &'a self,
        key: &'a str,
        value: &'a [u8],
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<(), crate::secure_key_store::SecureKeyStoreError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let release = self.release.lock().unwrap().take();
            if let Some(release) = release {
                release.await.unwrap();
            }
            if self.fail {
                return Err(crate::secure_key_store::SecureKeyStoreError::Backend(
                    "delayed clear failed".into(),
                ));
            }
            self.inner.store_secret_bytes(key, value)
        })
    }

    fn get_secret_bytes(
        &self,
        key: &str,
    ) -> Result<Option<arkret_sdk::KeyBytes>, crate::secure_key_store::SecureKeyStoreError> {
        self.inner.get_secret_bytes(key)
    }
    fn delete_secret(&self, key: &str) -> Result<(), crate::secure_key_store::SecureKeyStoreError> {
        self.inner.delete_secret(key)
    }
    fn list_secret_keys(
        &self,
        prefix: Option<&str>,
    ) -> Result<Vec<String>, crate::secure_key_store::SecureKeyStoreError> {
        self.inner.list_secret_keys(prefix)
    }
    fn backend_info(&self) -> garth::SecureKeyStoreBackendInfo {
        self.inner.backend_info()
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn delayed_clear_blocks_stale_hydration_and_keeps_later_input() {
    use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore};

    for scope in [
        E2eePlaintextCacheClearScope::All,
        E2eePlaintextCacheClearScope::Realm("realm-a".into()),
    ] {
        let path = temp_state_path("delayed-cache-clear");
        let authority = test_authority("did:web:alice.example");
        let device = test_device_id();
        let other_device =
            crate::test_support::device_id("ak:device:01964137-0000-7000-8000-000000000002");
        let inner = MemorySecureKeyStore::default();
        let mut original = LocalStateStore::with_path(path.clone());
        original.switch_test_account("did:web:alice.example");
        for (target_device, realm, body) in [
            (&device, "realm-a", "old A"),
            (&other_device, "realm-a", "old other device"),
            (&device, "realm-b", "old B"),
        ] {
            original
                .prepare_composer_draft_write(&authority, target_device, realm, "chat", body.into())
                .unwrap();
        }
        original
            .persist_e2ee_plaintext_cache_with_secure_store(&inner)
            .unwrap();
        // Mount a new state whose plaintext has not yet been hydrated.
        let mut state = LocalStateStore::with_path(path);
        state.switch_test_account("did:web:alice.example");
        assert_eq!(state.composer_draft(&device, "realm-a", "chat"), "");
        let (release, gate) = tokio::sync::oneshot::channel();
        let secure = DelayedClearStore {
            inner,
            release: std::sync::Mutex::new(Some(gate)),
            fail: false,
        };
        let pending = state
            .prepare_e2ee_plaintext_cache_clear_with_secure_store(&scope, &secure)
            .unwrap()
            .unwrap();
        let mut write = Box::pin(pending.persist(&secure));
        assert!(futures_util::poll!(write.as_mut()).is_pending());
        let mut remounted = state.clone();
        remounted
            .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap();
        assert_eq!(remounted.composer_draft(&device, "realm-a", "chat"), "");
        assert_eq!(
            remounted.composer_draft(&other_device, "realm-a", "chat"),
            ""
        );
        assert_eq!(
            remounted.composer_draft(&device, "realm-b", "chat"),
            if scope == E2eePlaintextCacheClearScope::All {
                ""
            } else {
                "old B"
            }
        );
        state
            .prepare_composer_draft_write(
                &authority,
                &device,
                "realm-a",
                "chat",
                "new input".into(),
            )
            .unwrap();
        state
            .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap();
        assert_eq!(
            state.composer_draft(&device, "realm-a", "chat"),
            "new input"
        );
        release.send(()).unwrap();
        write.await.unwrap();
        drop(pending);
        // Native callers persist synchronously; the WASM FIFO already orders
        // this newer whole-cache snapshot after the awaited clear barrier.
        state
            .persist_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap();
        let raw = secure
            .get_secret(&crate::secure_key_store::e2ee_plaintext_cache_store_key(
                &state.active_authority_namespace_for_test(),
            ))
            .unwrap()
            .unwrap();
        assert!(raw.contains("new input"));
        assert!(!raw.contains("old A"));
        assert!(!raw.contains("old other device"));
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn delayed_failed_clear_is_exclusive_and_rolls_back_only_removed_realm() {
    let authority = test_authority("did:web:alice.example");
    let device = test_device_id();
    let mut state = LocalStateStore::with_path(temp_state_path("delayed-clear-rollback"));
    state.switch_test_account("did:web:alice.example");
    for (realm, body) in [("realm-a", "old A"), ("realm-b", "old B")] {
        state
            .prepare_composer_draft_write(&authority, &device, realm, "chat", body.into())
            .unwrap();
    }
    let (release, gate) = tokio::sync::oneshot::channel();
    let secure = DelayedClearStore {
        inner: Default::default(),
        release: std::sync::Mutex::new(Some(gate)),
        fail: true,
    };
    state
        .persist_e2ee_plaintext_cache_with_secure_store(&secure)
        .unwrap();
    let scope = E2eePlaintextCacheClearScope::Realm("realm-a".into());
    let pending = state
        .prepare_e2ee_plaintext_cache_clear_with_secure_store(&scope, &secure)
        .unwrap()
        .unwrap();
    let mut write = Box::pin(pending.persist(&secure));
    assert!(futures_util::poll!(write.as_mut()).is_pending());
    for next in [
        E2eePlaintextCacheClearScope::All,
        E2eePlaintextCacheClearScope::Realm("realm-b".into()),
    ] {
        assert!(
            state
                .clone()
                .prepare_e2ee_plaintext_cache_clear_with_secure_store(&next, &secure)
                .is_err()
        );
    }
    state
        .prepare_composer_draft_write(&authority, &device, "realm-a", "chat", "new A".into())
        .unwrap();
    // Another local operation removes B while A is in flight. A's rollback
    // must not restore entries that A never removed.
    state
        .cached
        .composer_drafts
        .get_mut(device.as_str())
        .unwrap()
        .remove("realm-b");
    release.send(()).unwrap();
    assert!(write.await.is_err());
    state.rollback_e2ee_plaintext_cache_clear(pending);
    assert_eq!(state.composer_draft(&device, "realm-a", "chat"), "new A");
    assert_eq!(state.composer_draft(&device, "realm-b", "chat"), "");
    assert!(
        state
            .prepare_e2ee_plaintext_cache_clear(&scope)
            .unwrap()
            .is_some()
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn delayed_clear_failure_cannot_roll_back_across_account_or_reset_epoch() {
    for reset in ["account-return", "device", "logout", "soft", "login"] {
        let authority = test_authority("did:web:alice.example");
        let device = test_device_id();
        let mut state = LocalStateStore::with_path(temp_state_path("clear-reset-epoch"));
        state.switch_test_account("did:web:alice.example");
        state
            .prepare_composer_draft_write(&authority, &device, "realm-a", "chat", "old A".into())
            .unwrap();
        let (release, gate) = tokio::sync::oneshot::channel();
        let secure = DelayedClearStore {
            inner: Default::default(),
            release: std::sync::Mutex::new(Some(gate)),
            fail: true,
        };
        state
            .persist_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap();
        let pending = state
            .prepare_e2ee_plaintext_cache_clear_with_secure_store(
                &E2eePlaintextCacheClearScope::All,
                &secure,
            )
            .unwrap()
            .unwrap();
        let mut write = Box::pin(pending.persist(&secure));
        assert!(futures_util::poll!(write.as_mut()).is_pending());
        match reset {
            "account-return" => {
                state.switch_test_account("did:web:bob.example");
                state
                    .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
                    .unwrap();
                assert_eq!(state.composer_draft(&device, "realm-a", "chat"), "");
                // A's pending clear cannot lock the unrelated B cache key.
                assert!(
                    state
                        .prepare_e2ee_plaintext_cache_clear(&E2eePlaintextCacheClearScope::All)
                        .unwrap()
                        .is_none()
                );
                state.switch_test_account("did:web:alice.example");
            }
            "device" => state.clear_device_scoped(),
            "logout" => state.clear_session_scoped_for_logout(),
            "soft" => state.clear_account_scoped(),
            "login" => {
                state.begin_pending_login(&device, None);
                state.switch_test_account("did:web:alice.example");
            }
            _ => unreachable!(),
        }
        state
            .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap();
        assert_eq!(
            state.composer_draft(&device, "realm-a", "chat"),
            "",
            "old-key hydration fence must survive {reset}"
        );
        state
            .prepare_composer_draft_write(
                &authority,
                &device,
                "realm-a",
                "new-chat",
                "new session input".into(),
            )
            .unwrap();
        release.send(()).unwrap();
        assert!(write.await.is_err());
        state.rollback_e2ee_plaintext_cache_clear(pending);
        assert_eq!(
            state.composer_draft(&device, "realm-a", "chat"),
            "",
            "stale rollback after {reset}"
        );
        assert_eq!(
            state.composer_draft(&device, "realm-a", "new-chat"),
            "new session input"
        );
    }
}

#[test]
fn private_plaintext_snapshot_json_round_trips_through_merge() {
    // X5.3 — write sidecar entries, snapshot to JSON, then merge that JSON
    // into a FRESH store (the new-browser restore case) and read them back.
    let path = temp_state_path("private-plaintext-snapshot");
    let mut store = LocalStateStore::with_path(path);
    assert!(store.private_plaintext_is_empty());
    store.save_private_plaintext(
        "ak:realm:Af1zqB3_Jrboro34y4gO5sGw_9WdcaJpJ0RFj0J3Czok",
        "ak:strand:ACO0mgcDtIZrNCmU08vIqkIuP8CD6VrARiuEFskkdlWs",
        "body",
        "\"hello body\"",
    );
    store.save_private_plaintext(
        "ak:realm:Af1zqB3_Jrboro34y4gO5sGw_9WdcaJpJ0RFj0J3Czok",
        "ak:strand:ACO0mgcDtIZrNCmU08vIqkIuP8CD6VrARiuEFskkdlWs",
        "synthesis",
        "\"hello synthesis\"",
    );
    store.save_private_plaintext(
        "ak:realm:AxGJ5bnb2NT29k-kJ71MFoiFFSRsCSvI3e2k_GdVpqJE",
        "ak:strand:AaKpoM7I3iy6d1PX7gkqfR_AELjR5119vkMmYl6H8Jw8",
        "body",
        "\"other body\"",
    );
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
        fresh.private_plaintext_for(
            "ak:realm:Af1zqB3_Jrboro34y4gO5sGw_9WdcaJpJ0RFj0J3Czok",
            "ak:strand:ACO0mgcDtIZrNCmU08vIqkIuP8CD6VrARiuEFskkdlWs",
            "body"
        ),
        Some("\"hello body\"".to_owned())
    );
    assert_eq!(
        fresh.private_plaintext_for(
            "ak:realm:Af1zqB3_Jrboro34y4gO5sGw_9WdcaJpJ0RFj0J3Czok",
            "ak:strand:ACO0mgcDtIZrNCmU08vIqkIuP8CD6VrARiuEFskkdlWs",
            "synthesis"
        ),
        Some("\"hello synthesis\"".to_owned())
    );
    assert_eq!(
        fresh.private_plaintext_for(
            "ak:realm:AxGJ5bnb2NT29k-kJ71MFoiFFSRsCSvI3e2k_GdVpqJE",
            "ak:strand:AaKpoM7I3iy6d1PX7gkqfR_AELjR5119vkMmYl6H8Jw8",
            "body"
        ),
        Some("\"other body\"".to_owned())
    );
}

#[test]
fn merge_private_plaintext_map_keeps_local_value_on_conflict() {
    // X5.3 merge semantics: incoming only FILLS missing fields; an existing
    // local value wins on conflict.
    let path = temp_state_path("private-plaintext-conflict");
    let mut store = LocalStateStore::with_path(path);
    store.save_private_plaintext(
        "ak:realm:Af1zqB3_Jrboro34y4gO5sGw_9WdcaJpJ0RFj0J3Czok",
        "ak:strand:ACO0mgcDtIZrNCmU08vIqkIuP8CD6VrARiuEFskkdlWs",
        "body",
        "\"local newer\"",
    );

    let mut fields = BTreeMap::new();
    fields.insert("body".to_owned(), "\"backup older\"".to_owned()); // conflict
    fields.insert("synthesis".to_owned(), "\"backup synthesis\"".to_owned()); // gap
    let mut strands = BTreeMap::new();
    strands.insert(
        "ak:strand:ACO0mgcDtIZrNCmU08vIqkIuP8CD6VrARiuEFskkdlWs".to_owned(),
        fields,
    );
    let mut incoming = BTreeMap::new();
    incoming.insert(
        "ak:realm:Af1zqB3_Jrboro34y4gO5sGw_9WdcaJpJ0RFj0J3Czok".to_owned(),
        strands,
    );
    store.merge_private_plaintext_map(incoming);

    // Conflict: local value kept.
    assert_eq!(
        store.private_plaintext_for(
            "ak:realm:Af1zqB3_Jrboro34y4gO5sGw_9WdcaJpJ0RFj0J3Czok",
            "ak:strand:ACO0mgcDtIZrNCmU08vIqkIuP8CD6VrARiuEFskkdlWs",
            "body"
        ),
        Some("\"local newer\"".to_owned())
    );
    // Gap: backup fills it.
    assert_eq!(
        store.private_plaintext_for(
            "ak:realm:Af1zqB3_Jrboro34y4gO5sGw_9WdcaJpJ0RFj0J3Czok",
            "ak:strand:ACO0mgcDtIZrNCmU08vIqkIuP8CD6VrARiuEFskkdlWs",
            "synthesis"
        ),
        Some("\"backup synthesis\"".to_owned())
    );
}

#[test]
fn private_plaintext_sidecar_stays_memory_only_without_secure_store() {
    // Fail-closed fallback: without a hardened store, keep the current-process
    // cache but never serialize the plaintext sidecar into account-state JSON.
    let path = temp_state_path("private-plaintext-sidecar");
    let realm = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let strand = "ak:strand:AXKJvMpMFIFTD9GYNEzOeImU-2ytvLCtsCq3Mrq9-Ci8";
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
        let fields = store
            .load()
            .mls_private_plaintext
            .get(realm)
            .and_then(|strands| strands.get(strand))
            .cloned()
            .unwrap_or_default();
        assert_eq!(fields.len(), 2);
        let raw = store.persisted_account_records_for_test(&store.effective_account_key());
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
    let fields = reader
        .load()
        .mls_private_plaintext
        .get(realm)
        .and_then(|strands| strands.get(strand))
        .cloned()
        .unwrap_or_default();
    assert!(fields.is_empty());
    // Missing keys return None.
    assert!(
        reader
            .private_plaintext_for(realm, strand, "content")
            .is_none()
    );
    assert!(
        reader
            .private_plaintext_for(
                "ak:realm:ALxDZio2znRUoLNW5_OmFXNttc8yHs8Jw8_b6vk0QYXo",
                strand,
                "body"
            )
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
    use garth::mls::checkpoint::encrypt_state;

    use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore};

    let path = temp_state_path("e2ee-secure-cache-roundtrip");
    let actor = "did:web:alice.example";
    let realm = "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo";
    let strand = "ak:strand:AeWYNl1hiGDuy4WCQ03g5lgs2NZzf_SFYgjsfhG-t9cg";
    let digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let secure = MemorySecureKeyStore::new();

    {
        let mut writer = LocalStateStore::with_path(path.clone());
        assert!(writer.switch_test_account(actor));
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

        let namespace = writer.active_authority_namespace_for_test();
        let raw = writer.persisted_account_records_for_test(&namespace);
        assert!(!raw.contains("author secret"));
        assert!(!raw.contains("remote secret"));
        assert!(!raw.contains("mls_private_plaintext"));
        assert!(!raw.contains("mls_decrypted_plaintext"));

        let key = crate::secure_key_store::e2ee_plaintext_cache_store_key(&namespace);
        assert!(secure.get_secret(&key).unwrap().is_some());
    }

    let mut reader = LocalStateStore::with_path(path);
    assert!(!reader.switch_test_account(actor));
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
fn account_switch_and_reload_isolate_private_plaintext_and_user_projections() {
    let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
    let path = temp_state_path("account-data-isolation-roundtrip");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let realm = "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo";
    let strand = "ak:strand:AeWYNl1hiGDuy4WCQ03g5lgs2NZzf_SFYgjsfhG-t9cg";
    let accounts = [
        ("did:web:alice.example", "ak:did_core:web:station-a.example"),
        ("did:web:bob.example", "ak:did_core:web:station-a.example"),
        ("did:web:alice.example", "ak:did_core:web:station-b.example"),
    ]
    .map(|(principal, station)| {
        let did = arkret_sdk::Did::new(principal.to_owned()).unwrap();
        super::test_account_context_for_authority(
            &did,
            super::test_authority_at_server(principal, station),
        )
    });
    let mut store = LocalStateStore::with_path(path.clone());
    for (index, account) in accounts.iter().enumerate() {
        store.switch_active_account(account).unwrap();
        store
            .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap();
        assert!(store.private_plaintext_for(realm, strand, "body").is_none());
        assert!(store.load().sync_cursor.is_none());
        assert!(store.load().realm_tree_projections.is_empty());
        store.save_private_plaintext(realm, strand, "body", &format!("\"private-{index}\""));
        store.save_sync_cursor(format!("cursor-{index}"));
        store.save_realm_tree_projection(
            realm,
            serde_json::json!({"summary": format!("realm-{index}")}),
        );
        store
            .persist_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap();
    }
    drop(store);
    let mut reopened = LocalStateStore::with_path(path);
    for (index, account) in accounts.iter().enumerate() {
        reopened.switch_active_account(account).unwrap();
        reopened
            .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap();
        assert_eq!(
            reopened
                .private_plaintext_for(realm, strand, "body")
                .unwrap(),
            format!("\"private-{index}\"")
        );
        assert_eq!(
            reopened.load().sync_cursor.unwrap(),
            format!("cursor-{index}")
        );
        assert_eq!(reopened.load().realm_tree_projections.len(), 1);
        assert_eq!(
            reopened.load().realm_tree_projections[realm]["summary"],
            format!("realm-{index}")
        );
    }
}

#[test]
fn receive_snapshot_and_plaintext_share_one_secure_entry() {
    use garth::mls::checkpoint::encrypt_state;

    use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore};

    let actor = "did:web:alice.example";
    let realm = "ak:realm:AWrezLPcwmM1NuqVqDBC_2CQqLQr-0noHrkMZrKwy_qk";
    let digest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let secure = MemorySecureKeyStore::new();
    let envelope = encrypt_state(realm, "abcd", 4, b"advanced", "profile", b"salt");

    let mut writer = LocalStateStore::with_path(temp_state_path("e2ee-combined-writer"));
    writer.switch_test_account(actor);
    writer.advance_mls_receive_chain(realm, envelope.clone(), digest, b"combined remote secret");
    writer
        .persist_e2ee_plaintext_cache_with_secure_store(&secure)
        .unwrap();

    let namespace = writer.active_authority_namespace_for_test();
    let key = crate::secure_key_store::e2ee_plaintext_cache_store_key(&namespace);
    let raw = secure.get_secret(&key).unwrap().expect("combined entry");
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert!(value["mls_snapshots"].get(realm).is_some());
    assert!(value["decrypted_plaintext"][realm].get(digest).is_some());

    let mut reloaded = LocalStateStore::with_path(temp_state_path("e2ee-combined-reader"));
    reloaded.switch_test_account(actor);
    assert!(reloaded.mls_checkpoint_for(realm).is_none());
    assert!(
        reloaded
            .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap()
    );
    assert_eq!(reloaded.mls_checkpoint_for(realm), Some(envelope));
    assert_eq!(
        reloaded
            .mls_decrypted_plaintext_for(realm, digest)
            .as_deref(),
        Some(&b"combined remote secret"[..])
    );
}

#[test]
fn secure_snapshot_replaces_stale_same_epoch_account_snapshot() {
    use garth::mls::checkpoint::encrypt_state;

    use crate::secure_key_store::MemorySecureKeyStore;

    let actor = "did:web:alice.example";
    let realm = "ak:realm:AUFQ7tDTjjyR4uqCLnpZoeiJVD5Ibv8gxBvWrXaTzl30";
    let secure = MemorySecureKeyStore::new();
    let stale = encrypt_state(realm, "abcd", 5, b"stale", "profile", b"salt");
    let current = encrypt_state(realm, "abcd", 5, b"current", "profile", b"salt");

    let mut secure_writer = LocalStateStore::with_path(temp_state_path("e2ee-current-writer"));
    secure_writer.switch_test_account(actor);
    secure_writer
        .save_mls_checkpoint(realm, current.clone())
        .unwrap();
    secure_writer
        .persist_e2ee_plaintext_cache_with_secure_store(&secure)
        .unwrap();

    let local_path = temp_state_path("e2ee-stale-local");
    let mut reloaded = LocalStateStore::with_path(local_path);
    reloaded.switch_test_account(actor);
    reloaded.save_mls_checkpoint(realm, stale.clone()).unwrap();
    assert_eq!(reloaded.mls_checkpoint_for(realm), Some(stale));
    assert!(
        reloaded
            .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap()
    );
    assert_eq!(reloaded.mls_checkpoint_for(realm), Some(current));
}

#[test]
fn missing_secure_checkpoint_rolls_back_to_pre_decrypt_snapshot() {
    use garth::mls::checkpoint::encrypt_state;

    use crate::secure_key_store::MemorySecureKeyStore;

    let path = temp_state_path("e2ee-interrupted-checkpoint");
    let actor = "did:web:alice.example";
    let realm = "ak:realm:AWAHNzyrBLZcOudyQuSsgg3chDdtouZyFRYAhAnVcPwZ";
    let digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let base = encrypt_state(realm, "abcd", 6, b"base", "profile", b"salt");
    let advanced = encrypt_state(realm, "abcd", 6, b"advanced", "profile", b"salt");

    {
        let mut writer = LocalStateStore::with_path(path.clone());
        writer.switch_test_account(actor);
        writer.save_mls_checkpoint(realm, base.clone()).unwrap();
        writer.advance_mls_receive_chain(realm, advanced.clone(), digest, b"interrupted plaintext");
        assert_eq!(writer.mls_checkpoint_for(realm), Some(advanced.clone()));
        assert_eq!(
            writer.load().mls_receive_recovery_checkpoints.get(realm),
            Some(&base)
        );
    }

    // Simulate a page exit before the combined IndexedDB entry commits: the
    // account file has the advanced encrypted snapshot and recovery checkpoint,
    // while the hardened store is still empty and contains no plaintext.
    let secure = MemorySecureKeyStore::new();
    let mut reloaded = LocalStateStore::with_path(path);
    assert!(!reloaded.switch_test_account(actor));
    assert_eq!(reloaded.mls_checkpoint_for(realm), Some(advanced));
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
    assert_eq!(reloaded.mls_checkpoint_for(realm), Some(base));
    assert!(
        reloaded
            .mls_decrypted_plaintext_for(realm, digest)
            .is_none()
    );

    // Bootstrap now persisted a coherent checkpoint; cleanup can remove the
    // temporary rollback journal without touching that secure entry.
    reloaded.clear_mls_receive_recovery_checkpoints().unwrap();
    assert!(reloaded.load().mls_receive_recovery_checkpoints.is_empty());
}

#[test]
fn stale_background_cache_write_cannot_clear_newer_receive_recovery_checkpoint() {
    use garth::mls::checkpoint::encrypt_state;

    let path = temp_state_path("e2ee-background-checkpoint-guard");
    let actor = "did:web:alice.example";
    let realm = "ak:realm:Af7hHJ0VGmDQ0p9hCnWFJg33V-mOz91iOFhCQ0ZOiB0L";
    let first_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let second_digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let base = encrypt_state(realm, "abcd", 8, b"base", "profile", b"salt");
    let first = encrypt_state(realm, "abcd", 8, b"first", "profile", b"salt");
    let second = encrypt_state(realm, "abcd", 8, b"second", "profile", b"salt");

    let mut state = LocalStateStore::with_path(path);
    state.switch_test_account(actor);
    state.save_mls_checkpoint(realm, base).unwrap();
    state.advance_mls_receive_chain(realm, first, first_digest, b"first plaintext");
    let (old_key, Some(old_json)) = state.e2ee_plaintext_cache_secure_write().unwrap().unwrap()
    else {
        panic!("first receive must produce an E2EE cache write");
    };

    // A second receive lands while the first durable browser write is in flight.
    state.advance_mls_receive_chain(realm, second, second_digest, b"second plaintext");
    assert!(
        !state
            .clear_mls_receive_recovery_checkpoints_if_cache_unchanged(&old_key, &old_json)
            .unwrap(),
        "an older completed write must not clear recovery state for newer cache contents"
    );
    assert!(!state.load().mls_receive_recovery_checkpoints.is_empty());

    let (current_key, Some(current_json)) =
        state.e2ee_plaintext_cache_secure_write().unwrap().unwrap()
    else {
        panic!("second receive must produce an E2EE cache write");
    };
    assert!(
        state
            .clear_mls_receive_recovery_checkpoints_if_cache_unchanged(&current_key, &current_json,)
            .unwrap(),
        "the exact cache write may clear the checkpoints it covers"
    );
    assert!(state.load().mls_receive_recovery_checkpoints.is_empty());
}

#[test]
fn dropping_mls_snapshot_also_drops_receive_recovery_checkpoint() {
    use garth::mls::checkpoint::encrypt_state;

    use crate::secure_key_store::MemorySecureKeyStore;

    let path = temp_state_path("e2ee-drop-recovery-checkpoint");
    let actor = "did:web:alice.example";
    let realm = "ak:realm:AdpPWnG_g2knHq1MwnlFLMRlYtcj2FQQynn1FdVDTYlo";
    let digest = "sha256:abababababababababababababababababababababababababababababababab";
    let secure = MemorySecureKeyStore::new();
    {
        let mut writer = LocalStateStore::with_path(path.clone());
        writer.switch_test_account(actor);
        writer
            .save_mls_checkpoint(
                realm,
                encrypt_state(realm, "abcd", 7, b"base", "profile", b"salt"),
            )
            .unwrap();
        writer.advance_mls_receive_chain(
            realm,
            encrypt_state(realm, "abcd", 7, b"advanced", "profile", b"salt"),
            digest,
            b"cached plaintext",
        );
        writer.absorb_mls_receive_overlay();
        writer.cached.mls_local_checkpoints.remove(realm);
        writer.cached.mls_receive_recovery_checkpoints.remove(realm);
        let _ = writer.flush();
        assert!(writer.mls_checkpoint_for(realm).is_none());
        assert!(writer.load().mls_receive_recovery_checkpoints.is_empty());
        writer
            .persist_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap();
    }

    let mut reloaded = LocalStateStore::with_path(path);
    assert!(!reloaded.switch_test_account(actor));
    reloaded
        .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
        .unwrap();
    assert!(reloaded.mls_checkpoint_for(realm).is_none());
}

#[test]
fn secure_cache_hydration_fills_gaps_without_overwriting_live_values() {
    use garth::mls::checkpoint::encrypt_state;

    use crate::secure_key_store::MemorySecureKeyStore;

    let actor = "did:web:alice.example";
    let realm = "ak:realm:AUuXpUO-yBwwyCNB7AS1IIm5_sgsxyEsG7PBmmkXdFog";
    let strand = "ak:strand:AYdzR-cxE5CaMt7Xeab7lJ6oTMVcXRDFIfPqcXOahgQ4";
    let digest_conflict = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let digest_gap = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let secure = MemorySecureKeyStore::new();

    let mut persisted = LocalStateStore::with_path(temp_state_path("e2ee-secure-cache-old"));
    persisted.switch_test_account(actor);
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
    live.switch_test_account(actor);
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
    let realm = "ak:realm:ASnqpJQi0G5Ljanp7UQXjmcIaFVqDSvBNupH4kpQaTzc";
    let strand = "ak:strand:AaOXNHSDDaM0JligIdzVZIU6um9pht5hNmk_nSGLvEGg";
    let secure = MemorySecureKeyStore::new();
    let mut live = LocalStateStore::with_path(temp_state_path("e2ee-secure-cache-first-frame"));
    live.switch_test_account(actor);
    live.save_private_plaintext(realm, strand, "body", "\"written before init\"");

    let namespace = live.active_authority_namespace_for_test();
    let key = crate::secure_key_store::e2ee_plaintext_cache_store_key(&namespace);
    assert!(secure.get_secret(&key).unwrap().is_none());
    assert!(
        !live
            .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap()
    );
    assert!(secure.get_secret(&key).unwrap().is_some());

    let mut reloaded =
        LocalStateStore::with_path(temp_state_path("e2ee-secure-cache-first-frame-reload"));
    reloaded.switch_test_account(actor);
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
fn mls_plaintext_is_never_written_to_plaintext_state() {
    // The RHRK history-secret family is gone with the protocol, but the
    // invariant it protected is not: decrypted MLS material and the pairwise
    // identity links derived from it live only in the hardened E2EE cache and
    // must never reach the plaintext persistence tier.
    let mut state = ClientLocalState::default();
    state.mls_private_plaintext.insert(
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
        BTreeMap::from([(
            "ak:strand:AXKJvMpMFIFTD9GYNEzOeImU-2ytvLCtsCq3Mrq9-Ci8".to_owned(),
            BTreeMap::from([("body".to_owned(), "\"secret-plaintext-body\"".to_owned())]),
        )])
        .into(),
    );
    state.mls_decrypted_plaintext.insert(
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
        BTreeMap::from([(
            "sha256:6161616161616161616161616161616161616161616161616161616161616161".to_owned(),
            "secret-decrypted-body".to_owned(),
        )])
        .into(),
    );

    let persisted = e2ee_safe_persist_state(&state);
    assert!(
        persisted.mls_private_plaintext.is_empty(),
        "authored MLS plaintext must never enter plaintext persistence"
    );
    assert!(
        persisted.mls_decrypted_plaintext.is_empty(),
        "received MLS plaintext must never enter plaintext persistence"
    );
    let json = serde_json::to_string(&persisted).unwrap();
    assert!(!json.contains("secret-plaintext-body"));
    assert!(!json.contains("secret-decrypted-body"));
}

#[test]
fn e2ee_plaintext_cache_usage_is_grouped_by_realm() {
    use garth::mls::checkpoint::encrypt_state;

    let realm_a = "ak:realm:AXT4J1l4F3ziDJgbW0eaFtcLosoRKMG4tLzy3ImP2xL6";
    let realm_b = "ak:realm:ATI6e10SzOvQlSeBncAyPEeezd2fomt9lrllRopafxxw";
    let strand = "ak:strand:AXKJvMpMFIFTD9GYNEzOeImU-2ytvLCtsCq3Mrq9-Ci8";
    let digest = "sha256:6161616161616161616161616161616161616161616161616161616161616161";
    let mut store = LocalStateStore::with_path(temp_state_path("e2ee-cache-usage"));
    store.save_private_plaintext(realm_a, strand, "body", "alpha");
    store.save_private_plaintext(realm_b, strand, "body", "beta");
    store.advance_mls_receive_chain(
        realm_a,
        encrypt_state(realm_a, "abcd", 1, b"state", "profile", b"salt"),
        digest,
        b"remote",
    );

    let usage = store.e2ee_plaintext_cache_usage();
    assert_eq!(usage.realms.len(), 2);
    assert_eq!(usage.authored_entries, 2);
    assert_eq!(usage.received_entries, 1);
    assert_eq!(usage.entry_count(), 3);
    assert_eq!(usage.plaintext_bytes, 17);
    assert_eq!(usage.realms[realm_a].authored_entries, 1);
    assert_eq!(usage.realms[realm_a].received_entries, 1);
    assert_eq!(usage.realms[realm_a].plaintext_bytes, 13);
    assert_eq!(usage.realms[realm_b].plaintext_bytes, 4);
}

#[tokio::test]
async fn explicit_e2ee_plaintext_cleanup_persists_scope_and_keeps_mls_state() {
    use garth::mls::checkpoint::encrypt_state;

    use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore};

    let actor = "did:web:alice.example";
    let realm_a = "ak:realm:AfbKWLVDgbqfa9qrhI4hl9oGnXQKMQA_OHzH9_0KnTG-";
    let realm_b = "ak:realm:AQxo89D8rwIC6VILfwYma2x_7XCpAlCHZjtD0e1qvH7m";
    let strand = "ak:strand:AXKJvMpMFIFTD9GYNEzOeImU-2ytvLCtsCq3Mrq9-Ci8";
    let digest = "sha256:6363636363636363636363636363636363636363636363636363636363636363";
    let secure = MemorySecureKeyStore::new();
    let mut store = LocalStateStore::with_path(temp_state_path("e2ee-cache-clear"));
    store.switch_test_account(actor);
    store.save_private_plaintext(realm_a, strand, "body", "realm-a-author");
    store.save_private_plaintext(realm_b, strand, "body", "realm-b-author");
    store.advance_mls_receive_chain(
        realm_a,
        encrypt_state(realm_a, "abcd", 3, b"state", "profile", b"salt"),
        digest,
        b"realm-a-remote",
    );
    store
        .persist_e2ee_plaintext_cache_with_secure_store(&secure)
        .unwrap();
    let checkpoint_before_clear = store.mls_checkpoint_for(realm_a).unwrap();

    assert!(
        store
            .clear_e2ee_plaintext_cache_with_secure_store(
                &E2eePlaintextCacheClearScope::Realm(realm_a.to_owned()),
                &secure,
            )
            .await
            .unwrap()
    );
    assert!(
        store
            .private_plaintext_for(realm_a, strand, "body")
            .is_none()
    );
    assert!(store.mls_decrypted_plaintext_for(realm_a, digest).is_none());
    assert_eq!(
        store.mls_checkpoint_for(realm_a),
        Some(checkpoint_before_clear.clone())
    );
    assert_eq!(
        store.private_plaintext_for(realm_b, strand, "body"),
        Some("realm-b-author".to_owned())
    );

    let namespace = store.active_authority_namespace_for_test();
    let key = crate::secure_key_store::e2ee_plaintext_cache_store_key(&namespace);
    let persisted: serde_json::Value =
        serde_json::from_str(&secure.get_secret(&key).unwrap().unwrap()).unwrap();
    assert!(persisted["mls_snapshots"].get(realm_a).is_some());
    assert!(persisted["private_plaintext"].get(realm_a).is_none());
    assert!(persisted["decrypted_plaintext"].get(realm_a).is_none());
    assert!(persisted["private_plaintext"].get(realm_b).is_some());

    let mut reloaded = LocalStateStore::with_path(temp_state_path("e2ee-cache-clear-reload"));
    reloaded.switch_test_account(actor);
    reloaded
        .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
        .unwrap();
    assert!(
        reloaded
            .private_plaintext_for(realm_a, strand, "body")
            .is_none()
    );
    assert_eq!(
        reloaded.mls_checkpoint_for(realm_a),
        Some(checkpoint_before_clear.clone())
    );
    assert_eq!(
        reloaded.private_plaintext_for(realm_b, strand, "body"),
        Some("realm-b-author".to_owned())
    );

    assert!(
        reloaded
            .clear_e2ee_plaintext_cache_with_secure_store(
                &E2eePlaintextCacheClearScope::All,
                &secure,
            )
            .await
            .unwrap()
    );
    assert_eq!(reloaded.e2ee_plaintext_cache_usage().entry_count(), 0);
    assert_eq!(
        reloaded.mls_checkpoint_for(realm_a),
        Some(checkpoint_before_clear)
    );
    assert!(
        !reloaded
            .clear_e2ee_plaintext_cache_with_secure_store(
                &E2eePlaintextCacheClearScope::All,
                &secure,
            )
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn failed_durable_plaintext_cleanup_rolls_back_and_reports_error() {
    use std::sync::atomic::{AtomicBool, Ordering};

    use arkret_sdk::KeyBytes;
    use garth::SecureKeyStoreBackendInfo;

    use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore, SecureKeyStoreError};

    #[derive(Default)]
    struct FailingStore {
        inner: MemorySecureKeyStore,
        fail_writes: AtomicBool,
    }

    impl SecureKeyStore for FailingStore {
        fn store_secret_bytes(&self, key: &str, value: &[u8]) -> Result<(), SecureKeyStoreError> {
            if self.fail_writes.load(Ordering::SeqCst) {
                return Err(SecureKeyStoreError::Backend(
                    "injected durable write failure".to_owned(),
                ));
            }
            self.inner.store_secret_bytes(key, value)
        }

        fn get_secret_bytes(&self, key: &str) -> Result<Option<KeyBytes>, SecureKeyStoreError> {
            self.inner.get_secret_bytes(key)
        }

        fn delete_secret(&self, key: &str) -> Result<(), SecureKeyStoreError> {
            self.inner.delete_secret(key)
        }

        fn list_secret_keys(
            &self,
            prefix: Option<&str>,
        ) -> Result<Vec<String>, SecureKeyStoreError> {
            self.inner.list_secret_keys(prefix)
        }

        fn backend_info(&self) -> SecureKeyStoreBackendInfo {
            self.inner.backend_info()
        }
    }

    let actor = "did:web:alice.example";
    let realm = "ak:realm:AfjofKtO3Dm9g2CU_rgHsVO0g0SrMxfvWw4xdIk3dFWP";
    let strand = "ak:strand:AXKJvMpMFIFTD9GYNEzOeImU-2ytvLCtsCq3Mrq9-Ci8";
    let secure = FailingStore::default();
    let mut store = LocalStateStore::with_path(temp_state_path("e2ee-cache-clear-failure"));
    store.switch_test_account(actor);
    store.save_private_plaintext(realm, strand, "body", "must-survive");
    store
        .persist_e2ee_plaintext_cache_with_secure_store(&secure)
        .unwrap();
    let namespace = store.active_authority_namespace_for_test();
    let key = crate::secure_key_store::e2ee_plaintext_cache_store_key(&namespace);
    let before = secure.get_secret(&key).unwrap().unwrap();

    secure.fail_writes.store(true, Ordering::SeqCst);
    let pending = store
        .prepare_e2ee_plaintext_cache_clear(&E2eePlaintextCacheClearScope::All)
        .unwrap()
        .unwrap();
    store.save_private_plaintext(realm, strand, "new-field", "arrived-during-write");
    let error = pending
        .persist(&secure)
        .await
        .expect_err("durable failure must be visible to the caller");
    store.rollback_e2ee_plaintext_cache_clear(pending);
    assert!(
        format!("{error:#}").contains("injected durable write failure"),
        "full error chain must retain the durable backend failure: {error:#}"
    );
    assert_eq!(
        store.private_plaintext_for(realm, strand, "body"),
        Some("must-survive".to_owned())
    );
    assert_eq!(
        store.private_plaintext_for(realm, strand, "new-field"),
        Some("arrived-during-write".to_owned())
    );
    assert_eq!(
        secure.get_secret(&key).unwrap().as_deref(),
        Some(before.as_str())
    );
}

#[test]
fn browser_storage_warning_starts_at_eighty_percent() {
    let below = BrowserStorageEstimate {
        usage_bytes: 799,
        quota_bytes: 1000,
    };
    let threshold = BrowserStorageEstimate {
        usage_bytes: 800,
        quota_bytes: 1000,
    };
    assert!(!below.is_near_quota());
    assert!(threshold.is_near_quota());
    assert_eq!(
        BrowserStorageEstimate {
            usage_bytes: 0,
            quota_bytes: 0,
        }
        .usage_ratio(),
        None
    );
}

#[test]
fn plain_local_data_persists_in_encrypted_account_records() {
    let path = temp_state_path("private");
    let mut store = LocalStateStore::with_path(path.clone());
    store.save_plain_local_data("theme", "dark");
    store.save_plain_local_data("custom_emoji", "party_parrot");

    assert_eq!(
        store.load_plain_local_data("theme"),
        Some("dark".to_owned())
    );
    assert_eq!(
        store.load_plain_local_data("custom_emoji"),
        Some("party_parrot".to_owned())
    );
    assert!(store.load_plain_local_data("missing").is_none());
    assert_eq!(store.plain_local_data_keys().len(), 2);

    let raw = store.persisted_account_records_for_test(ANONYMOUS_ACCOUNT_NAMESPACE);
    assert!(raw.contains("dark") && raw.contains("party_parrot"));
    let reopened = LocalStateStore::with_path(path);
    assert_eq!(
        reopened.load_plain_local_data("theme").as_deref(),
        Some("dark")
    );
    assert_eq!(
        reopened.load_plain_local_data("custom_emoji").as_deref(),
        Some("party_parrot")
    );
}

#[test]
fn plain_local_data_remove_works() {
    let path = temp_state_path("private-remove");
    let mut store = LocalStateStore::with_path(path);
    store.save_plain_local_data("temp", "value");
    assert!(store.load_plain_local_data("temp").is_some());
    store.remove_plain_local_data("temp");
    assert!(store.load_plain_local_data("temp").is_none());
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn composer_drafts_survive_restart_only_in_exact_account_device_realm_strand_secure_scope() {
    use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore};
    let path = temp_state_path("composer-drafts");
    let secure = MemorySecureKeyStore::new();
    let alice = "did:web:alice.example";
    let bob = "did:web:bob.example";
    let authority = test_authority(alice);
    let device = test_device_id();
    let other_device =
        crate::test_support::device_id("ak:device:01964137-0000-7000-8000-000000000002");
    let mut writer = LocalStateStore::with_path(path.clone());
    writer.switch_test_account(alice);
    let (key, json) = writer
        .prepare_composer_draft_write(
            &authority,
            &device,
            "realm-a",
            "chat-a",
            "private draft A".into(),
        )
        .unwrap();
    let first_json = json.clone();
    LocalStateStore::persist_e2ee_plaintext_cache_write_durable(&secure, &key, json.as_deref())
        .await
        .unwrap();
    for (target_device, realm, strand, text) in [
        (&device, "realm-a", "chat-b", "private draft B"),
        (&device, "realm-b", "chat-a", "private draft other Realm"),
        (
            &other_device,
            "realm-a",
            "chat-a",
            "private draft other device",
        ),
    ] {
        let (key, json) = writer
            .prepare_composer_draft_write(&authority, target_device, realm, strand, text.into())
            .unwrap();
        LocalStateStore::persist_e2ee_plaintext_cache_write_durable(&secure, &key, json.as_deref())
            .await
            .unwrap();
    }
    writer.flush().unwrap();
    let raw =
        writer.persisted_account_records_for_test(&writer.active_authority_namespace_for_test());
    assert!(!raw.contains("composer_drafts"));
    assert!(!raw.contains("private draft"));
    assert!(
        !String::from_utf8(writer.private_plaintext_snapshot_json())
            .unwrap()
            .contains("private draft")
    );
    drop(writer);
    let mut reader = LocalStateStore::with_path(path.clone());
    reader.switch_test_account(alice);
    assert_eq!(reader.composer_draft(&device, "realm-a", "chat-a"), "");
    reader
        .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
        .unwrap();
    assert_eq!(
        reader.composer_draft(&device, "realm-a", "chat-a"),
        "private draft A"
    );
    assert_eq!(
        reader.composer_draft(&device, "realm-a", "chat-b"),
        "private draft B"
    );
    assert_eq!(
        reader.composer_draft(&device, "realm-b", "chat-a"),
        "private draft other Realm"
    );
    assert_eq!(
        reader.composer_draft(&other_device, "realm-a", "chat-a"),
        "private draft other device"
    );
    let (key, cleared) = reader
        .prepare_composer_draft_write(&authority, &device, "realm-a", "chat-a", String::new())
        .unwrap();
    // Hydration of an earlier immutable snapshot cannot undo an explicit clear.
    secure
        .store_secret(&key, first_json.as_deref().unwrap())
        .unwrap();
    reader
        .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
        .unwrap();
    assert_eq!(reader.composer_draft(&device, "realm-a", "chat-a"), "");
    LocalStateStore::persist_e2ee_plaintext_cache_write_durable(&secure, &key, cleared.as_deref())
        .await
        .unwrap();
    reader.switch_test_account(bob);
    assert!(
        reader
            .prepare_composer_draft_write(
                &authority,
                &device,
                "realm-a",
                "chat-a",
                "stale Alice callback".into()
            )
            .is_err()
    );
    reader
        .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
        .unwrap();
    assert_eq!(reader.composer_draft(&device, "realm-a", "chat-b"), "");
    reader.switch_test_account(alice);
    reader
        .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
        .unwrap();
    assert_eq!(reader.composer_draft(&device, "realm-a", "chat-a"), "");
    assert_eq!(
        reader.composer_draft(&device, "realm-a", "chat-b"),
        "private draft B"
    );
    reader.clear_account_scoped();
    assert_eq!(
        reader.composer_draft(&device, "realm-a", "chat-b"),
        "private draft B",
        "same-account projection reset must preserve authored drafts"
    );
    assert_eq!(reader.composer_draft(&device, "realm-a", "chat-a"), "");
    reader.clear_stored_composer_drafts(&secure).unwrap();
    reader.clear_account_scoped();
    drop(reader);
    let mut reset = LocalStateStore::with_path(path);
    reset.switch_test_account(alice);
    reset
        .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
        .unwrap();
    assert_eq!(reset.composer_draft(&device, "realm-a", "chat-b"), "");
    assert_eq!(reset.composer_draft(&other_device, "realm-a", "chat-a"), "");
}
