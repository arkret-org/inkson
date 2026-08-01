use chrono::{TimeZone as _, Utc};
use serde_json::json;

use crate::mls_api_helpers;

#[test]
fn keypackage_upload_device_signature_is_raw_signature_tuple() {
    let signer = crate::event_signer::build_ed25519_signer_with_verification_method(
        [43u8; 32],
        "did:web:alice.example",
        "did:web:alice.example#device",
    );
    let timestamp = Utc.timestamp_opt(1_774_310_400, 0).single().unwrap();
    let unsigned = arkret_sdk::KeyPackagesUploadUnsignedRequest {
        principal_id: arkret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap(),
        device_id: arkret_sdk::DeviceId::new(
            "ak:device:0196419b-0000-7000-8000-000000000001".to_owned(),
        )
        .unwrap(),
        key_packages: vec![arkret_sdk::KeyPackageUploadEntry {
            keypackage_id: "ak:mls:kp:0196419b-0000-7000-8000-000000000001".to_owned(),
            keypackage_ref:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
            keypackage_digest: arkret_sdk::Hash::new(
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_owned(),
            )
            .unwrap(),
            key_package: arkret_sdk::Base64UrlString::new("AA").unwrap(),
            cipher_suites: vec!["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned()],
            capabilities: vec!["ak.content.v1".to_owned()],
            expires_at: timestamp + chrono::Duration::days(7),
            created_at: timestamp,
            device_signature: None,
            last_resort: None,
        }],
        expires_at: None,
        strand_id: None,
        mls_group_id: None,
    };
    let signature = mls_api_helpers::sign_keypackage_upload_batch_with_signer(&signer, &unsigned)
        .expect("KeyPackage upload signature builds");

    assert_eq!(signature.alg.as_deref(), Some("EdDSA"));
    assert_eq!(signature.kid.as_str(), "did:web:alice.example#device");
    let sig = signature.sig.as_str();
    assert_eq!(sig.len(), 86);
    assert!(!sig.contains('='));
}

#[test]
fn keypackage_claim_request_carries_required_capabilities() {
    let signer = std::sync::Arc::new(
        crate::event_signer::build_ed25519_signer_with_verification_method(
            [44u8; 32],
            "did:web:bob.example",
            "did:web:bob.example#device",
        ),
    );
    let _guard = crate::event_signer::ActiveSignerTestGuard::replace(Some(signer));
    let body = mls_api_helpers::build_mls_keypackage_claim_request(
        "did:web:alice.example",
        "ak:realm:0196419b-0000-7000-8000-000000000000",
        "did:web:bob.example",
        "did:web:arkret.example",
        "AAAAAAAAAAAAAAAAAAAAAA",
        Some("ak:device:0196419b-0000-7000-8000-000000000001"),
        Some("mls-group-1"),
    )
    .expect("claim request builds");

    let expected = mls_api_helpers::mls_keypackage_claim_required_capabilities();
    assert_eq!(body.required_capabilities, expected);

    let wire = serde_json::to_value(&body).expect("claim request serializes");
    assert_eq!(
        wire["required_capabilities"],
        json!(arkret_sdk::ARKRET_MLS_KEY_PACKAGE_CAPABILITIES)
    );
}
