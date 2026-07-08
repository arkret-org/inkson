use serde_json::json;

use crate::mls_api_helpers;

#[test]
fn keypackage_upload_device_signature_is_raw_signature_tuple() {
    let signer = crate::event_signer::build_ed25519_signer_with_verification_method(
        [43u8; 32],
        "did:web:alice.example",
        "did:web:alice.example#device",
    );
    let signature = mls_api_helpers::sign_keypackage_upload_batch_with_signer(
        &signer,
        "ck:device:0196419b-0000-7000-8000-000000000001",
        &[json!({
            "keypackage_id": "ck:mls:kp:0196419b-0000-7000-8000-000000000001",
            "keypackage_ref": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        })],
    )
    .expect("KeyPackage upload signature builds");

    assert_eq!(signature.alg.as_deref(), Some("EdDSA"));
    assert_eq!(signature.kid, "did:web:alice.example#device");
    let sig = signature.sig.as_str();
    assert_eq!(sig.len(), 86);
    assert!(!sig.contains('='));
}

#[test]
fn keypackage_claim_request_carries_required_capabilities() {
    let body = mls_api_helpers::build_mls_keypackage_claim_request(
        "did:web:alice.example",
        "ck:realm:0196419b-0000-7000-8000-000000000000",
        "did:web:bob.example",
        "claim-nonce-1",
        Some("ck:device:0196419b-0000-7000-8000-000000000001"),
        Some("mls-group-1"),
    )
    .expect("claim request builds");

    let expected = mls_api_helpers::mls_keypackage_claim_required_capabilities();
    assert_eq!(body.required_capabilities, expected);

    let wire = serde_json::to_value(&body).expect("claim request serializes");
    assert_eq!(
        wire["required_capabilities"],
        json!(cokret_sdk::COKRET_MLS_KEY_PACKAGE_CAPABILITIES)
    );
}
