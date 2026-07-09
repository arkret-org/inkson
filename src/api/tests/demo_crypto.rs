use super::super::*;

// ── Production-path wire guards ─────────────────────────────────
//
// `publish_mls_key_package` produces a real event-signer
// `device_signature` and fails-closed when no signer is installed
// (asserted just below).

#[tokio::test]
async fn publish_mls_key_package_fails_closed_without_active_signer() {
    // Build a syntactically-valid MlsKeyPackageRecord via JSON so
    // we don't need to import every field type. The prod path
    // bails before reading any field, but we still want the
    // argument well-formed so a future refactor that touches the
    // record before bailing surfaces here.
    let record: cokret_sdk::MlsKeyPackageRecord = serde_json::from_value(serde_json::json!({
        "keypackage_id": "ak:mls:kp:01904100-0000-7000-8000-000000000001",
        "principal_id": "did:web:alice.example",
        "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
        "key_package": "AAAA",
        "keypackage_ref": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "cipher_suites": ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
        "created_at": "2026-01-01T00:00:00Z",
    }))
    .expect("MlsKeyPackageRecord fixture must deserialize");

    let api = CokretApi::new("http://127.0.0.1:8787").unwrap();
    let err = api
        .publish_mls_key_package("ak:device:test-prod-guard", &record)
        .await
        .expect_err("MUST refuse to publish without an active event-signer");
    let msg = format!("{err}");
    assert!(
        msg.contains("device_signature") && msg.contains("event-signer"),
        "error must name the missing signer, got: {msg}"
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn mls_key_package_upload_entry_carries_digest_and_ref() {
    let identity = cokret_sdk::CokretMlsIdentity::new_basic(
        cokret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap(),
        cokret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001".to_owned())
            .unwrap(),
    )
    .unwrap();
    let record = identity.key_package_record().unwrap();

    let entry = crate::mls_api_helpers::mls_key_package_record_upload_entry(&record).unwrap();

    assert_eq!(
        entry.keypackage_digest.as_str(),
        record.keypackage_ref.as_str()
    );
    assert_eq!(entry.keypackage_ref, record.keypackage_ref.as_str());
    assert_eq!(
        entry.key_package.as_str(),
        Some(record.key_package.as_str())
    );
}
