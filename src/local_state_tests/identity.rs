//! Local device-identity generation, secure-store persistence, and tamper-detection tests.

use super::*;
// `secure.get_secret(...)` is a `SecureKeyStore` trait method; bring the
// trait into scope so the method calls resolve.
use crate::secure_key_store::SecureKeyStore;

#[test]
fn ensure_local_identity_generates_persists_and_round_trips() {
    let path = temp_state_path("local-identity");
    let id = {
        let mut store = LocalStateStore::with_path(path.clone());
        assert!(store.local_identity_record().is_none());
        assert!(store.local_identity().is_none());
        let id = store.ensure_local_identity().expect("first generate");
        assert!(id.local_signing_did.starts_with("did:key:z"));
        // Idempotent on the same store instance.
        let again = store.ensure_local_identity().expect("idempotent");
        assert_eq!(id, again);
        id
    };
    // Round-trip across store instances.
    let reader = LocalStateStore::with_path(path);
    let loaded = reader.local_identity().expect("persisted identity loads");
    assert_eq!(loaded.local_signing_did, id.local_signing_did);
    assert_eq!(loaded.signing_key.to_bytes(), id.signing_key.to_bytes());
}

#[test]
fn secure_identity_store_keeps_seed_out_of_state_record() {
    let path = temp_state_path("local-identity-secure");
    let secure = crate::secure_key_store::MemorySecureKeyStore::new();
    let id = {
        let mut store = LocalStateStore::with_path(path.clone());
        store
            .ensure_local_identity_with_secure_store(&secure)
            .expect("secure identity")
    };
    assert!(
        LocalStateStore::with_path(path)
            .load()
            .local_identity
            .is_none(),
        "state.json must not keep the identity seed",
    );
    let stored = secure
        .get_secret(LocalStateStore::SECURE_IDENTITY_KEY)
        .expect("secure read")
        .expect("identity secret");
    let record: LocalIdentityRecord = serde_json::from_str(&stored).unwrap();
    assert_eq!(record.did_key, id.local_signing_did);
    assert_eq!(
        LocalIdentity::from_record(&record)
            .unwrap()
            .signing_key
            .to_bytes(),
        id.signing_key.to_bytes(),
    );
}

#[test]
fn local_identity_two_calls_to_generate_diverge() {
    // Sanity: two `generate()` calls produce distinct keys (otherwise
    // the rng plumbing is broken). This guards against an accidental
    // regression to the deterministic [42; 32] seed.
    let one = LocalIdentity::generate().unwrap();
    let two = LocalIdentity::generate().unwrap();
    assert_ne!(one.local_signing_did, two.local_signing_did);
    assert_ne!(one.signing_key.to_bytes(), two.signing_key.to_bytes());
    assert_ne!(one.signing_key.to_bytes(), [42u8; 32]);
    assert_ne!(two.signing_key.to_bytes(), [42u8; 32]);
}

#[test]
fn local_identity_record_tamper_detection_regenerates() {
    let path = temp_state_path("local-identity-tamper");
    let mut store = LocalStateStore::with_path(path.clone());
    let original = store.ensure_local_identity().unwrap();
    // Tamper: scramble the cached did_key while keeping the seed valid.
    // The next `ensure_local_identity` must reject + regenerate.
    store.cached.local_identity = Some(LocalIdentityRecord {
        seed_hex: original.to_record().seed_hex.clone(),
        did_key: "did:key:zTAMPERED".to_owned(),
    });
    let _ = store.flush();
    let regenerated = store.ensure_local_identity().unwrap();
    assert_ne!(regenerated.local_signing_did, "did:key:zTAMPERED");
    assert_ne!(
        regenerated.signing_key.to_bytes(),
        original.signing_key.to_bytes(),
        "regenerated identity is fresh, not the tampered original"
    );
}
