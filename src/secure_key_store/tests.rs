use super::*;

/// T5.2 — store / load signing seed round-trips through a
/// MemorySecureKeyStore. `load_signing_seed` returns None on a
/// fresh store; `store_signing_seed` followed by
/// `load_signing_seed` returns the same 32-byte material plus the
/// derived did:key.
#[test]
fn signing_seed_round_trips_through_memory_store() {
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
    let store = MemorySecureKeyStore::new();
    let first = ensure_signing_seed(&store).expect("first");
    // Seed must be non-trivial.
    assert!(first.seed.iter().any(|b| *b != 0));
    let second = ensure_signing_seed(&store).expect("second");
    assert_eq!(first.seed, second.seed);
    assert_eq!(first.local_signing_did, second.local_signing_did);
}

/// Corrupt entry → backend error so the boot path surfaces a
/// "rotate identity" warning instead of silently regenerating.
#[test]
fn load_signing_seed_rejects_short_entries() {
    let store = MemorySecureKeyStore::new();
    store
        .store_secret(SIGNING_SEED_KEY, &STANDARD_NO_PAD.encode([1u8; 16]))
        .unwrap();
    let err = load_signing_seed(&store).unwrap_err();
    assert!(matches!(err, SecureKeyStoreError::Backend(_)));
}

#[test]
fn wasm_indexeddb_required_key_classifier_covers_high_value_secrets() {
    assert!(is_wasm_indexeddb_required_secret_key(SIGNING_SEED_KEY));
    assert!(is_wasm_indexeddb_required_secret_key(
        "identity.local.primary.v1"
    ));
    assert!(is_wasm_indexeddb_required_secret_key(
        "yougen.mls_snapshot.account_secret.v1.did:example:alice"
    ));
    assert!(is_wasm_indexeddb_required_secret_key(
        "yougen_mls_account_secret"
    ));
    assert!(is_wasm_indexeddb_required_secret_key(
        "coauth.session_credential.did:example:alice"
    ));
    // The hard-logout journal embeds a holder seed → seed-grade: both
    // IndexedDB-required and excluded from the localStorage mirror.
    assert!(is_wasm_indexeddb_required_secret_key(
        PENDING_LOGOUT_SECRET_KEY
    ));
    assert!(is_wasm_no_localstorage_mirror_key(
        PENDING_LOGOUT_SECRET_KEY
    ));
    assert!(is_wasm_no_localstorage_mirror_key(SIGNING_SEED_KEY));
    assert!(!is_wasm_no_localstorage_mirror_key(
        "coauth.session_credential.did:example:alice"
    ));

    assert!(!is_wasm_indexeddb_required_secret_key(
        "push.fcm.registration_token.device-a"
    ));
    assert!(!is_wasm_indexeddb_required_secret_key(
        "oidc.nonce.scaffold"
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

#[test]
fn memory_store_round_trips_a_secret() {
    let store = MemorySecureKeyStore::new();
    assert!(store.is_empty());

    store
        .store_secret("test.session_secret", "session-secret-value")
        .expect("store");
    assert_eq!(store.len(), 1);

    let loaded = store
        .get_secret("test.session_secret")
        .expect("get")
        .expect("present");
    assert_eq!(loaded, "session-secret-value");
}

#[test]
fn memory_store_overwrites_existing_entry() {
    let store = MemorySecureKeyStore::new();
    store.store_secret("k", "v1").unwrap();
    store.store_secret("k", "v2").unwrap();
    assert_eq!(store.get_secret("k").unwrap().as_deref(), Some("v2"));
    assert_eq!(store.len(), 1);
}

#[test]
fn memory_store_returns_none_for_missing_key() {
    let store = MemorySecureKeyStore::new();
    assert!(store.get_secret("absent").unwrap().is_none());
}

#[test]
fn memory_store_delete_is_idempotent() {
    let store = MemorySecureKeyStore::new();
    store.delete_secret("never-stored").expect("idempotent");
    store.store_secret("k", "v").unwrap();
    store.delete_secret("k").expect("delete");
    assert!(store.get_secret("k").unwrap().is_none());
    store.delete_secret("k").expect("idempotent second delete");
}

#[test]
fn memory_store_clones_share_state() {
    let a = MemorySecureKeyStore::new();
    let b = a.clone();
    a.store_secret("shared", "value").unwrap();
    assert_eq!(b.get_secret("shared").unwrap().as_deref(), Some("value"));
}

#[test]
fn memory_store_debug_does_not_leak_secret_values() {
    let store = MemorySecureKeyStore::new();
    store
        .store_secret("test.session_secret", "extremely-sensitive-token")
        .unwrap();
    let debug = format!("{store:?}");
    assert!(
        !debug.contains("extremely-sensitive-token"),
        "Debug must NEVER include secret values, got: {debug}"
    );
    assert!(
        !debug.contains("test.session_secret"),
        "Debug should not leak key names either, got: {debug}"
    );
}

#[test]
fn memory_store_advertises_correct_backend_name() {
    assert_eq!(MemorySecureKeyStore::new().backend_name(), "memory");
}

#[test]
fn trait_object_dispatch_works_for_memory_backend() {
    // Sanity: the orchestrator stores `Arc<dyn SecureKeyStore>` —
    // confirm the memory impl is dyn-safe + threads through the
    // trait surface without specialisation.
    fn store_via_trait(store: &dyn SecureKeyStore, key: &str, value: &str) {
        store.store_secret(key, value).expect("store");
    }
    let store = MemorySecureKeyStore::new();
    store_via_trait(&store, "k", "v");
    assert_eq!(store.get_secret("k").unwrap().as_deref(), Some("v"));
}

#[test]
fn default_secure_key_store_returns_a_usable_backend() {
    // We don't hit the OS keychain in unit tests — too easy to
    // pollute the developer's keychain with stale `yougen.test`
    // entries and to flake on locked sessions in CI. We only
    // assert that the constructor returns a value whose
    // `backend_name` matches the platform expectation.
    let store = default_secure_key_store("yougen.test.unit");
    let name = store.backend_name();
    if cfg!(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
    )) {
        assert_eq!(name, "keyring");
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
    let store = KeyringSecureKeyStore::new("yougen.test.unit");
    assert_eq!(store.service_name(), "yougen.test.unit");
    assert_eq!(store.backend_name(), "keyring");
}

/// Android Keystore store constructed against an explicit in-memory
/// bridge round-trips secrets through the bridge. store/get/delete
/// work because the host-bridge pattern moves the FFI out of yougen
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
    let store = AndroidKeystoreSecureKeyStore::new_with_bridge("yougen.test.unit", bridge);
    assert_eq!(store.service_name(), "yougen.test.unit");
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
    let store = IosKeychainSecureKeyStore::new_with_bridge("yougen.test.unit", bridge);
    assert_eq!(store.service_name(), "yougen.test.unit");
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
