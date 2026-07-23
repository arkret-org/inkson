use super::*;

/// Serializes the tests that read/write the process-global
/// `ACTIVE_DEVICE_SEED_SCOPE` static. They each carry their own
/// `MemorySecureKeyStore`, but the seed-scope selector is process-wide, so
/// running them concurrently lets one test's `set_active_device_seed_scope`
/// corrupt another's `load_signing_seed` / `active_device_seed_scope()`
/// assertions. Non-scope tests keep running in parallel.
static SCOPE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_scope_tests() -> std::sync::MutexGuard<'static, ()> {
    SCOPE_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct SeedScopeReset;

impl Drop for SeedScopeReset {
    fn drop(&mut self) {
        set_active_device_seed_scope(None);
    }
}

/// T5.2 — store / load signing seed round-trips through a
/// MemorySecureKeyStore. `load_signing_seed` returns None on a
/// fresh store; `store_signing_seed` followed by
/// `load_signing_seed` returns the same 32-byte material plus the
/// derived did:key.
#[test]
fn signing_seed_round_trips_through_memory_store() {
    let _scope_guard = lock_scope_tests();
    let store = MemorySecureKeyStore::new();
    assert!(load_signing_seed(&store).unwrap().is_none());

    let seed = [11u8; 32];
    let saved = store_signing_seed(&store, &seed).expect("store");
    assert_eq!(saved.seed, seed);
    assert!(saved.local_signing_did.starts_with("did:key:z"));

    let loaded = load_signing_seed(&store)
        .expect("load")
        .expect("seed present");
    assert_eq!(loaded.seed, seed);
    assert_eq!(loaded.local_signing_did, saved.local_signing_did);
}

/// `ensure_signing_seed` generates a fresh seed when none exists
/// and is idempotent on subsequent calls.
#[test]
fn ensure_signing_seed_generates_and_is_idempotent() {
    let _scope_guard = lock_scope_tests();
    let store = MemorySecureKeyStore::new();
    let first = ensure_signing_seed(&store).expect("first");
    // Seed must be non-trivial.
    assert!(first.seed.iter().any(|b| *b != 0));
    let second = ensure_signing_seed(&store).expect("second");
    assert_eq!(first.seed, second.seed);
    assert_eq!(first.local_signing_did, second.local_signing_did);
}

#[test]
fn login_adopt_preserves_returning_account_device_identity() {
    let _scope_guard = lock_scope_tests();
    let _reset = SeedScopeReset;
    set_active_device_seed_scope(None);
    let store = MemorySecureKeyStore::new();
    let account = "did:web:alice.example";
    let old_device = "ak:device:01964137-0000-7000-8000-000000000001";
    let bootstrap_device = "ak:device:01964137-0000-7000-8000-000000000002";
    let old_seed = [1u8; 32];
    let bootstrap_seed = [2u8; 32];

    store_signing_seed_scoped(&store, Some(account), &old_seed).expect("old account seed");
    store_device_id_scoped(&store, Some(account), old_device).expect("old account device id");
    store_signing_seed_scoped(&store, None, &bootstrap_seed).expect("bootstrap seed");
    store_device_id_scoped(&store, None, bootstrap_device).expect("bootstrap device id");

    adopt_device_seed_scope_on_login(&store, account).expect("adopt login scope");

    let adopted_seed = load_signing_seed_scoped(&store, Some(account))
        .expect("load account seed")
        .expect("account seed present");
    assert_eq!(adopted_seed.seed, old_seed);
    assert_eq!(
        load_device_id_scoped(&store, Some(account))
            .expect("load account device")
            .as_deref(),
        Some(old_device)
    );
    assert!(
        load_signing_seed_scoped(&store, None)
            .expect("load bootstrap seed")
            .is_none()
    );
    assert!(
        load_device_id_scoped(&store, None)
            .expect("load bootstrap device")
            .is_none()
    );
}

#[test]
fn login_adopt_rehomes_bootstrap_material_for_first_time_account() {
    let _scope_guard = lock_scope_tests();
    let _reset = SeedScopeReset;
    set_active_device_seed_scope(None);
    let store = MemorySecureKeyStore::new();
    let account = "did:web:alice.example";
    let bootstrap_device = "ak:device:01964137-0000-7000-8000-000000000002";
    let bootstrap_seed = [2u8; 32];

    store_signing_seed_scoped(&store, None, &bootstrap_seed).expect("bootstrap seed");
    store_device_id_scoped(&store, None, bootstrap_device).expect("bootstrap device id");

    adopt_device_seed_scope_on_login(&store, account).expect("adopt login scope");

    let adopted_seed = load_signing_seed_scoped(&store, Some(account))
        .expect("load account seed")
        .expect("account seed present");
    assert_eq!(adopted_seed.seed, bootstrap_seed);
    assert_eq!(
        load_device_id_scoped(&store, Some(account))
            .expect("load account device")
            .as_deref(),
        Some(bootstrap_device)
    );
    assert!(
        load_signing_seed_scoped(&store, None)
            .expect("load bootstrap seed")
            .is_none()
    );
    assert!(
        load_device_id_scoped(&store, None)
            .expect("load bootstrap device")
            .is_none()
    );
}

#[test]
fn signin_reset_preserves_account_identity_and_rotates_grant_binding() {
    let _scope_guard = lock_scope_tests();
    let _reset = SeedScopeReset;
    let store = MemorySecureKeyStore::new();
    let account = "did:web:alice.example";
    let account_device = "ak:device:01964137-0000-7000-8000-000000000001";
    let account_seed = [1u8; 32];
    let bootstrap_seed = [2u8; 32];
    let bootstrap_device = "ak:device:01964137-0000-7000-8000-000000000002";
    let old_grant_binding = [3u8; 32];

    set_active_device_seed_scope(Some(account));
    store_signing_seed_scoped(&store, Some(account), &account_seed).expect("account seed");
    store_device_id_scoped(&store, Some(account), account_device).expect("account device");
    store_signing_seed_scoped(&store, None, &bootstrap_seed).expect("bootstrap seed");
    store_device_id_scoped(&store, None, bootstrap_device).expect("bootstrap device");
    store_grant_binding_seed(&store, &old_grant_binding).expect("old grant-binding");

    reset_device_seed_scope_for_signin(&store).expect("reset for signin");

    assert_eq!(active_device_seed_scope(), None);
    assert_eq!(
        load_signing_seed_scoped(&store, Some(account))
            .expect("load account seed")
            .expect("account seed")
            .seed,
        account_seed
    );
    assert_eq!(
        load_device_id_scoped(&store, Some(account))
            .expect("load account device")
            .as_deref(),
        Some(account_device)
    );
    assert!(
        load_signing_seed_scoped(&store, None)
            .expect("load bootstrap seed")
            .is_none()
    );
    assert!(
        load_device_id_scoped(&store, None)
            .expect("load bootstrap device")
            .is_none()
    );
    assert_ne!(
        load_grant_binding_seed(&store)
            .expect("load grant-binding")
            .expect("grant-binding")
            .seed,
        old_grant_binding
    );
}

/// Corrupt entry → backend error so the boot path surfaces a
/// "rotate identity" warning instead of silently regenerating.
#[test]
fn load_signing_seed_rejects_short_entries() {
    let store = MemorySecureKeyStore::new();
    store
        .store_secret(SIGNING_SEED_KEY, &STANDARD_NO_PAD.encode([1u8; 16]))
        .unwrap();
    // Load through the explicit bootstrap scope rather than
    // `load_signing_seed` (which reads the process-global
    // `ACTIVE_DEVICE_SEED_SCOPE`): the seed above is stored under the bare
    // `SIGNING_SEED_KEY`, so a concurrently-running scope test flipping the
    // global must not turn this length-rejection assertion into `Ok(None)`.
    let err = load_signing_seed_scoped(&store, None).unwrap_err();
    assert!(matches!(err, SecureKeyStoreError::Backend(_)));
}

#[test]
fn wasm_indexeddb_required_key_classifier_covers_high_value_secrets() {
    assert!(is_wasm_indexeddb_required_secret_key(SIGNING_SEED_KEY));
    assert!(is_wasm_indexeddb_required_secret_key(
        GRANT_BINDING_SEED_KEY
    ));
    assert!(is_wasm_indexeddb_required_secret_key(
        "identity.local.primary.v1"
    ));
    assert!(is_wasm_indexeddb_required_secret_key(
        "inkson.mls_snapshot.account_secret.v1.did:example:alice"
    ));
    assert!(is_wasm_indexeddb_required_secret_key(
        "inkson_mls_account_secret"
    ));
    assert!(is_wasm_indexeddb_required_secret_key(
        "coauth.session_credential.did:example:alice"
    ));
    assert!(is_wasm_indexeddb_required_secret_key(
        "auth.dpop.device_key.v1.did:example:alice"
    ));
    assert!(is_wasm_indexeddb_required_secret_key(
        "auth.session_grant.v1.did:example:alice"
    ));
    assert!(is_wasm_indexeddb_required_secret_key(
        "inkson.device_hpke_x25519.private.ak:device:01964137-0000-7000-8000-000000000001"
    ));
    // The hard-logout journal embeds a grant-binding seed and is IndexedDB-only.
    assert!(is_wasm_indexeddb_required_secret_key(
        PENDING_LOGOUT_SECRET_KEY
    ));
    assert!(is_wasm_indexeddb_required_secret_key(
        "inkson.e2ee_plaintext_cache.v1.account-digest"
    ));
    // The per-account main state blob moved into the IndexedDB entries store;
    // both a real DID key and the anonymous namespace must be IndexedDB-only.
    assert!(is_wasm_indexeddb_required_secret_key(
        "inkson.local_state.v1.account.did:example:alice"
    ));
    assert!(is_wasm_indexeddb_required_secret_key(
        "inkson.local_state.v1.account.anonymous"
    ));

    assert!(!is_wasm_indexeddb_required_secret_key(
        "push.fcm.registration_token.device-a"
    ));
    assert!(!is_wasm_indexeddb_required_secret_key(
        "oidc.nonce.scaffold"
    ));
}

#[test]
fn wasm_test_downgrade_is_limited_to_device_signing_seed_fixtures() {
    assert!(is_wasm_test_downgrade_fixture_key(SIGNING_SEED_KEY));
    assert!(is_wasm_test_downgrade_fixture_key(
        "device.ed25519.signing_seed.v1.account-digest"
    ));
    assert!(!is_wasm_test_downgrade_fixture_key(
        "inkson.e2ee_plaintext_cache.v1.account-digest"
    ));
    assert!(!is_wasm_test_downgrade_fixture_key(
        "inkson.mls_history_secret.v1.realm-digest"
    ));
    assert!(!is_wasm_test_downgrade_fixture_key(
        "inkson.mls_snapshot.account_secret.v1.did:example:alice"
    ));
    assert!(!is_wasm_test_downgrade_fixture_key(
        "coauth.session_credential.did:example:alice"
    ));
}

/// The AEAD wrap helper MUST be a real ChaCha20-Poly1305 wrap —
/// round-trip recovers the
/// plaintext, identical inputs produce different ciphertexts
/// (random nonce), and decryption with the wrong key fails
/// closed.
#[test]
fn wrap_secret_round_trips_and_is_nonce_unique() {
    let key = [0x42u8; 32];
    let secret = "rt-1234567890";

    let wrapped_a = wrap_secret(secret, &key).expect("wrap a");
    let wrapped_b = wrap_secret(secret, &key).expect("wrap b");
    // Random nonce → identical plaintexts encrypt to distinct
    // ciphertexts.
    assert_ne!(wrapped_a, wrapped_b);

    let recovered = unwrap_secret(&wrapped_a, &key).expect("unwrap a");
    assert_eq!(recovered.as_deref(), Some(secret));

    // Wrong key → MAC fails → None (we collapse decrypt errors
    // into None so callers see "secret missing or corrupt").
    let wrong_key = [0x21u8; 32];
    let recovered_wrong = unwrap_secret(&wrapped_a, &wrong_key).expect("unwrap call ok");
    assert!(recovered_wrong.is_none());

    // Tampered ciphertext → also None.
    let mut tampered = wrapped_a.into_bytes();
    let last_idx = tampered.len() - 1;
    // Flip a single base64 character — close to guaranteed to break
    // the MAC.
    tampered[last_idx] = if tampered[last_idx] == b'A' {
        b'B'
    } else {
        b'A'
    };
    let tampered = String::from_utf8(tampered).unwrap();
    let recovered_tampered = unwrap_secret(&tampered, &key).expect("unwrap call ok");
    assert!(recovered_tampered.is_none());
}

/// Malformed input (non-base64, too short to carry a nonce, etc.)
/// MUST not panic — the helper
/// returns Ok(None) so callers treat it the same as "secret
/// missing".
#[test]
fn unwrap_secret_tolerates_malformed_blobs() {
    let key = [0x10u8; 32];
    assert!(unwrap_secret("not-base64-@@!!", &key).unwrap().is_none());
    assert!(unwrap_secret("", &key).unwrap().is_none());
    // Valid base64 but shorter than 12 bytes (no nonce).
    assert!(
        unwrap_secret(&STANDARD_NO_PAD.encode([0u8; 8]), &key)
            .unwrap()
            .is_none()
    );
}

// F-11: the in-memory backend is now garth's `MemorySecureKeyStore` (garth owns
// its round-trip / overwrite / delete / clone / Debug-redaction / backend-name
// unit tests). inkson keeps only the backend-selection + platform-specific tests
// below.

#[test]
fn default_secure_key_store_returns_a_usable_backend() {
    // We don't hit the OS keychain in unit tests — too easy to
    // pollute the developer's keychain with stale `inkson.test`
    // entries and to flake on locked sessions in CI. We only
    // assert that the constructor returns a value whose
    // `backend_name` matches the platform expectation.
    let store = default_secure_key_store("inkson.test.unit");
    let name = store.backend_name();
    if cfg!(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
    )) {
        assert_eq!(name, "sdk_platform_key_store");
    } else if cfg!(target_os = "android") {
        assert_eq!(name, "android-keystore");
    } else if cfg!(target_os = "ios") {
        assert_eq!(name, "ios-keychain");
    } else {
        assert_eq!(name, "memory");
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows",))]
#[test]
fn keyring_store_exposes_service_name() {
    let store = KeyringSecureKeyStore::new("inkson.test.unit");
    assert_eq!(store.service_name(), "inkson.test.unit");
    assert_eq!(store.backend_name(), "sdk_platform_key_store");
}

/// Android Keystore store constructed against an explicit in-memory
/// bridge round-trips secrets through the bridge. store/get/delete
/// work because the host-bridge pattern moves the FFI out of inkson
/// and into a pluggable trait. A real Android build wires a
/// JNI-backed bridge here;
/// this test wires `MemorySecureKeyStore` behind a thin adapter
/// so the surface compiles + functions on any target.
///
/// Cfg matches the type definition: native Android OR explicit
/// `mobile-android` feature opt-in.
#[cfg(any(feature = "mobile-android", target_os = "android"))]
#[test]
fn android_keystore_via_bridge_round_trips_secrets() {
    let bridge: Arc<dyn HostSecretBridge> = Arc::new(TestHostSecretBridge::new("android-keystore"));
    let store = AndroidKeystoreSecureKeyStore::new_with_bridge("inkson.test.unit", bridge);
    assert_eq!(store.service_name(), "inkson.test.unit");
    assert_eq!(store.backend_name(), "android-keystore");
    store
        .store_secret("session_credential", "credential-123")
        .unwrap();
    assert_eq!(
        store.get_secret("session_credential").unwrap().as_deref(),
        Some("credential-123")
    );
    store.delete_secret("session_credential").unwrap();
    assert_eq!(store.get_secret("session_credential").unwrap(), None);
}

/// Matching iOS test — same rationale as the Android case above.
///
/// Cfg matches the type definition: native iOS OR explicit
/// `mobile-ios` feature opt-in.
#[cfg(any(feature = "mobile-ios", target_os = "ios"))]
#[test]
fn ios_keychain_via_bridge_round_trips_secrets() {
    let bridge: Arc<dyn HostSecretBridge> = Arc::new(TestHostSecretBridge::new("ios-keychain"));
    let store = IosKeychainSecureKeyStore::new_with_bridge("inkson.test.unit", bridge);
    assert_eq!(store.service_name(), "inkson.test.unit");
    assert_eq!(store.backend_name(), "ios-keychain");
    store
        .store_secret("session_credential", "credential-123")
        .unwrap();
    assert_eq!(
        store.get_secret("session_credential").unwrap().as_deref(),
        Some("credential-123")
    );
    store.delete_secret("session_credential").unwrap();
    assert_eq!(store.get_secret("session_credential").unwrap(), None);
}

/// HostBridgeSecureKeyStore wires the right service_name + key
/// tuple through to the bridge.
/// Exercised cross-target because the bridge contract MUST be
/// callable from non-mobile builds too (it's the same trait
/// surface).
#[test]
fn host_bridge_store_namespaces_by_service_name() {
    let bridge: Arc<dyn HostSecretBridge> = Arc::new(TestHostSecretBridge::new("test-bridge"));
    let store_a = HostBridgeSecureKeyStore::new("svc.a", bridge.clone());
    let store_b = HostBridgeSecureKeyStore::new("svc.b", bridge.clone());
    store_a.store_secret("k", "v-a").unwrap();
    store_b.store_secret("k", "v-b").unwrap();
    assert_eq!(store_a.get_secret("k").unwrap().as_deref(), Some("v-a"));
    assert_eq!(store_b.get_secret("k").unwrap().as_deref(), Some("v-b"));
    // Deleting from store_a must not affect store_b — service_name
    // is part of the bridge key tuple.
    store_a.delete_secret("k").unwrap();
    assert_eq!(store_a.get_secret("k").unwrap(), None);
    assert_eq!(store_b.get_secret("k").unwrap().as_deref(), Some("v-b"));
}

/// `backend_name` strands from the bridge's `backend_label` so
/// diagnostic UI can distinguish
/// Android Keystore vs iOS Keychain.
#[test]
fn host_bridge_store_surface_backend_label_from_bridge() {
    let bridge: Arc<dyn HostSecretBridge> = Arc::new(TestHostSecretBridge::new("custom-label"));
    let store = HostBridgeSecureKeyStore::new("svc", bridge);
    assert_eq!(store.backend_name(), "custom-label");
}

/// Biometric challenge gates `store_secret` / `get_secret` on the
/// bridge. With biometric_required = true and the prompt accepting,
/// the round-trip works. With the prompt rejecting, both paths fail
/// with a "biometric" substring so the UI can distinguish "user
/// cancelled" from a real hardware failure. `delete_secret` is
/// intentionally NOT gated — see comment in `delete_secret`.
#[test]
fn host_bridge_biometric_blocks_store_and_get_on_reject() {
    let bridge = Arc::new(TestHostSecretBridge::new("biometric-bridge"));
    bridge.set_biometric_required(true);
    bridge.set_biometric_accept(false);
    let store =
        HostBridgeSecureKeyStore::new("svc.bio", bridge.clone() as Arc<dyn HostSecretBridge>);

    let err = store
        .store_secret("rt", "secret")
        .expect_err("biometric reject must fail store");
    assert!(matches!(err, SecureKeyStoreError::Backend(ref msg) if msg.contains("biometric")));

    // Even if the bridge happens to already hold an entry from a
    // prior accept, a subsequent reject denies the get.
    bridge.set_biometric_accept(true);
    store.store_secret("rt", "secret").expect("store accepted");
    bridge.set_biometric_accept(false);
    let err = store
        .get_secret("rt")
        .expect_err("biometric reject must fail get");
    assert!(matches!(err, SecureKeyStoreError::Backend(ref msg) if msg.contains("biometric")));

    // Delete is NOT biometric-gated by design.
    store.delete_secret("rt").expect("delete is not gated");
}

#[test]
fn host_bridge_biometric_allows_store_and_get_on_accept() {
    let bridge = Arc::new(TestHostSecretBridge::new("biometric-bridge"));
    bridge.set_biometric_required(true);
    bridge.set_biometric_accept(true);
    let store = HostBridgeSecureKeyStore::new("svc.bio", bridge as Arc<dyn HostSecretBridge>);

    store.store_secret("rt", "secret").expect("store accepted");
    assert_eq!(
        store.get_secret("rt").expect("get accepted").as_deref(),
        Some("secret")
    );
}

#[test]
fn host_bridge_biometric_disabled_does_not_prompt() {
    // biometric_challenge_required() defaults to false; the bridge
    // never calls biometric_authenticate, so a bridge that would
    // reject still permits store/get.
    let bridge = Arc::new(TestHostSecretBridge::new("no-bio"));
    bridge.set_biometric_required(false);
    bridge.set_biometric_accept(false);
    let store = HostBridgeSecureKeyStore::new("svc.no-bio", bridge as Arc<dyn HostSecretBridge>);
    store.store_secret("rt", "secret").expect("not gated");
    assert_eq!(
        store.get_secret("rt").expect("not gated").as_deref(),
        Some("secret")
    );
}

/// In-process [`HostSecretBridge`] used by mobile-platform unit
/// tests so the round-trip can run on any target. Stores entries
/// in a `(service_name, key) -> value` map. NOT a real Android /
/// iOS implementation — production hosts wire JNI / Security.framework.
struct TestHostSecretBridge {
    label: &'static str,
    inner: std::sync::Mutex<std::collections::HashMap<(String, String), String>>,
    biometric_required: std::sync::atomic::AtomicBool,
    biometric_accept: std::sync::atomic::AtomicBool,
}

impl TestHostSecretBridge {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            inner: std::sync::Mutex::new(std::collections::HashMap::new()),
            biometric_required: std::sync::atomic::AtomicBool::new(false),
            biometric_accept: std::sync::atomic::AtomicBool::new(true),
        }
    }

    fn set_biometric_required(&self, required: bool) {
        self.biometric_required
            .store(required, std::sync::atomic::Ordering::SeqCst);
    }

    fn set_biometric_accept(&self, accept: bool) {
        self.biometric_accept
            .store(accept, std::sync::atomic::Ordering::SeqCst);
    }
}

impl HostSecretBridge for TestHostSecretBridge {
    fn put(&self, service_name: &str, key: &str, value: &str) -> Result<(), SecureKeyStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|err| SecureKeyStoreError::Backend(format!("lock: {err}")))?;
        guard.insert((service_name.to_owned(), key.to_owned()), value.to_owned());
        Ok(())
    }
    fn get(&self, service_name: &str, key: &str) -> Result<Option<String>, SecureKeyStoreError> {
        let guard = self
            .inner
            .lock()
            .map_err(|err| SecureKeyStoreError::Backend(format!("lock: {err}")))?;
        Ok(guard
            .get(&(service_name.to_owned(), key.to_owned()))
            .cloned())
    }
    fn delete(&self, service_name: &str, key: &str) -> Result<(), SecureKeyStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|err| SecureKeyStoreError::Backend(format!("lock: {err}")))?;
        guard.remove(&(service_name.to_owned(), key.to_owned()));
        Ok(())
    }
    fn backend_label(&self) -> &'static str {
        self.label
    }
    fn biometric_challenge_required(&self) -> bool {
        self.biometric_required
            .load(std::sync::atomic::Ordering::SeqCst)
    }
    fn biometric_authenticate(&self, _reason: &str) -> Result<bool, SecureKeyStoreError> {
        Ok(self
            .biometric_accept
            .load(std::sync::atomic::Ordering::SeqCst))
    }
}

// ── E2EE-at-rest T1 / T6 — MLS history-secret hardening helpers ──────────

/// T6.2 — the per-realm history-secret JSON encodes raw 32-byte secrets as
/// base64url keyed by decimal epoch and round-trips back to identical bytes.
#[test]
fn history_secrets_json_round_trips() {
    use std::collections::BTreeMap;
    let mut by_epoch: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    by_epoch.insert(0, vec![0u8; 32]);
    by_epoch.insert(7, (0u8..32).collect());
    by_epoch.insert(4096, vec![0xABu8; 32]);

    let json = encode_history_secrets_json(&by_epoch);
    let decoded = decode_history_secrets_json(&json);
    assert_eq!(decoded, by_epoch);
}

/// T6.1 (regression guard) — the encoded blob must NOT contain the raw secret
/// bytes in the clear: a distinctive plaintext marker is absent from the JSON.
#[test]
fn history_secrets_json_does_not_leak_raw_bytes() {
    use std::collections::BTreeMap;
    // A secret whose bytes spell an ASCII marker we can search for.
    let marker = b"SUPER-SECRET-EXPORTER-KEY-32BYTE";
    assert_eq!(marker.len(), 32);
    let mut by_epoch: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    by_epoch.insert(3, marker.to_vec());

    let json = encode_history_secrets_json(&by_epoch);
    assert!(
        !json.contains("SUPER-SECRET"),
        "raw secret bytes leaked into stored JSON: {json}"
    );
    // ...but it still round-trips back to the exact bytes.
    assert_eq!(decode_history_secrets_json(&json).get(&3).unwrap(), marker);
}

/// Malformed entries (bad epoch / bad base64) are dropped, not fatal.
#[test]
fn history_secrets_json_drops_malformed_entries() {
    let json = r#"{"5":"AAAA","not-a-number":"AAAA","9":"!!!not-base64!!!"}"#;
    let decoded = decode_history_secrets_json(json);
    assert_eq!(decoded.len(), 1);
    assert!(decoded.contains_key(&5));
}

/// The SecureKeyStore key for a realm is the hardened prefix plus a stable,
/// character-safe base64 encoding of the realm id and is classified as
/// IndexedDB-only key material.
#[test]
fn history_secret_store_key_is_classified_indexeddb_only() {
    let key = mls_history_secret_store_key("ak:realm:abc123");
    assert!(key.starts_with(MLS_HISTORY_SECRET_KEY_PREFIX));
    assert!(is_wasm_indexeddb_required_secret_key(&key));
    // Stable across calls (no nonce / randomness in the key derivation).
    assert_eq!(key, mls_history_secret_store_key("ak:realm:abc123"));
    assert_ne!(key, mls_history_secret_store_key("ak:realm:other"));
}

#[test]
fn e2ee_plaintext_cache_key_is_account_scoped_and_indexeddb_only() {
    let alice = e2ee_plaintext_cache_store_key("did:web:alice.example");
    let bob = e2ee_plaintext_cache_store_key("did:web:bob.example");
    assert!(alice.starts_with(E2EE_PLAINTEXT_CACHE_KEY_PREFIX));
    assert!(is_wasm_indexeddb_required_secret_key(&alice));
    assert_ne!(alice, bob);
    assert_eq!(
        alice,
        e2ee_plaintext_cache_store_key("did:web:alice.example")
    );
}
