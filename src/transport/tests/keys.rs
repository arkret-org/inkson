use std::collections::BTreeMap;

use serde_json::json;

use super::super::key_backup as keys;

#[test]
fn keys_upload_device_signature_is_raw_signature_tuple() {
    let signer = crate::event_signer::build_ed25519_signer_with_verification_method(
        [42u8; 32],
        "did:web:alice.example",
        "did:web:alice.example#device",
    );
    let mut one_time_keys = BTreeMap::new();
    one_time_keys.insert(
        "signed_curve25519:test-1".to_owned(),
        json!({
            "key_id": "test-1",
            "key": "test-key"
        }),
    );
    let signature = keys::sign_keys_upload_batch_with_signer(
        &signer,
        "ak:device:0196419b-0000-7000-8000-000000000001",
        &one_time_keys,
        &BTreeMap::new(),
    )
    .expect("keys upload signature builds");

    assert_eq!(signature["alg"], "EdDSA");
    assert_eq!(signature["kid"], "did:web:alice.example#device");
    assert!(signature.get("jws").is_none());
    let sig = signature["sig"].as_str().expect("raw signature");
    assert_eq!(sig.len(), 86);
    assert!(!sig.contains('='));
}
