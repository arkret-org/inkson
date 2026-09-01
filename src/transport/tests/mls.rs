use chrono::{TimeZone as _, Utc};
use serde_json::json;

use crate::mls_api_helpers;

#[test]
fn keypackage_upload_endpoint_signature_is_raw_signature_tuple() {
    let signer = crate::event_signer::build_ed25519_signer_with_verification_method(
        [43u8; 32],
        "did:web:alice.example",
        "did:web:alice.example#device",
    );
    let timestamp = Utc.timestamp_opt(1_774_310_400, 0).single().unwrap();
    let unsigned = arkret_sdk::KeyPackagesUploadUnsignedRequest {
        principal_id: crate::mls_api_helpers::principal_core_id("did:web:alice.example").unwrap(),
        device_id: Some(
            arkret_sdk::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001".to_owned())
                .unwrap(),
        ),
        pairwise_verification_method: None,
        intended_realm_id: None,
        agent_verification_method: None,
        agent_key_authorize_event_id: None,
        keypackages: vec![arkret_sdk::KeyPackageUploadEntry {
            keypackage_id: "ak:mls:kp:0196419b-0000-7000-8000-000000000001".to_owned(),
            keypackage_ref:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
            keypackage: arkret_sdk::Base64UrlString::new("AA").unwrap(),
            cipher_suites: vec!["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned()],
            capabilities: vec!["ak.content.v1".to_owned()],
            expires_at: timestamp + chrono::Duration::days(7),
            created_at: timestamp,
            last_resort: None,
        }],
        expires_at: None,
        strand_id: None,
        mls_group_id: None,
    };
    let signature = mls_api_helpers::sign_keypackage_upload_batch_with_signer(&signer, &unsigned)
        .expect("KeyPackage upload signature builds");

    assert_eq!(signature.signature_algorithm.as_deref(), Some("Ed25519"));
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
    let requester_device_id = "ak:device:0196419b-0000-7000-8000-000000000002";
    let requester_device_authorize_event_id =
        arkret_sdk::EventId::new("ak:event:AR4gvLBB1qlq1zRAQHvDYQrKit2SLLNUPBG8C1idlQAc").unwrap();
    let body = mls_api_helpers::build_mls_keypackage_claim_request(
        "did:web:alice.example",
        "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk",
        "ak:did_core:web:bob.example",
        requester_device_id,
        &requester_device_authorize_event_id,
        "ak:did_core:web:source.example",
        "ak:did_core:web:destination.example",
        "AAAAAAAAAAAAAAAAAAAAAA",
        Some("ak:device:0196419b-0000-7000-8000-000000000001"),
        "mls-group-1",
    )
    .expect("claim request builds");

    let expected = mls_api_helpers::mls_keypackage_claim_required_capabilities().unwrap();
    assert_eq!(body.required_capabilities, expected);
    assert_eq!(
        body.requester_account_id
            .as_ref()
            .expect("device requester has an exact account")
            .principal_id
            .as_str(),
        "ak:did_core:web:bob.example"
    );
    assert_eq!(
        body.service_binding.destination_id.as_str(),
        "ak:did_core:web:destination.example"
    );
    match &body.requester_authorization {
        arkret_sdk::PeerKeyPackageRequesterAuthorization::Device {
            requester_device_id: actual_device_id,
            device_authorize_event_id,
            ..
        } => {
            assert_eq!(actual_device_id.as_str(), requester_device_id);
            assert_eq!(
                device_authorize_event_id,
                &requester_device_authorize_event_id
            );
        }
        arkret_sdk::PeerKeyPackageRequesterAuthorization::Agent { .. } => {
            panic!("human caller must author device authorization")
        }
        arkret_sdk::PeerKeyPackageRequesterAuthorization::MinimalMetadataPairwise { .. } => {
            panic!("human caller must not author pairwise authorization")
        }
    }

    let wire = serde_json::to_value(&body).expect("claim request serializes");
    assert_eq!(
        wire["required_capabilities"],
        json!(arkret_sdk::ARKRET_MLS_KEY_PACKAGE_CAPABILITIES)
    );
    assert_eq!(wire["claim_request_id"], json!("AAAAAAAAAAAAAAAAAAAAAA"));
    assert!(wire.get("claim_nonce").is_none());
}

#[test]
fn keypackage_claim_request_rejects_cross_principal_signer() {
    let signer = std::sync::Arc::new(
        crate::event_signer::build_ed25519_signer_with_verification_method(
            [45u8; 32],
            "did:web:bob.example",
            "did:web:bob.example#device",
        ),
    );
    let _guard = crate::event_signer::ActiveSignerTestGuard::replace(Some(signer));
    let requester_device_authorize_event_id =
        arkret_sdk::EventId::new("ak:event:AR4gvLBB1qlq1zRAQHvDYQrKit2SLLNUPBG8C1idlQAc").unwrap();

    let error = mls_api_helpers::build_mls_keypackage_claim_request(
        "ak:did_core:web:alice.example",
        "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk",
        "ak:did_core:web:mallory.example",
        "ak:device:0196419b-0000-7000-8000-000000000002",
        &requester_device_authorize_event_id,
        "ak:did_core:web:source.example",
        "ak:did_core:web:destination.example",
        "AAAAAAAAAAAAAAAAAAAAAA",
        Some("ak:device:0196419b-0000-7000-8000-000000000001"),
        "mls-group-1",
    )
    .expect_err("a signer for another principal must be rejected");

    assert!(
        error
            .to_string()
            .contains("does not project to the KeyPackage claim requester"),
        "unexpected error: {error}"
    );
}
