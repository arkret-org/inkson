// ── Production-path wire guards ─────────────────────────────────
//
// `publish_mls_key_package` produces a real event-signer
// `device_signature` and fails-closed when no signer is installed
// (asserted just below).

#[tokio::test]
async fn publish_mls_key_package_fails_closed_without_active_signer() {
    let record = arkret_sdk::MlsKeyPackageRecord {
        keypackage_id: "ak:mls:kp:01904100-0000-7000-8000-000000000001".to_owned(),
        principal_id: arkret_sdk::Did::new("did:web:alice.example").unwrap(),
        device_id: arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001")
            .unwrap(),
        key_package: "AAAA".to_owned(),
        keypackage_ref: arkret_sdk::Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
        cipher_suites: vec!["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned()],
        capabilities: Vec::new(),
        state: arkret_sdk::MlsKeyPackageState::Published,
        claim_id: None,
        created_at: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        expires_at: None,
        device_signature: None,
        last_resort: false,
    };

    let transport = crate::transport::TransportClient::new(
        "http://127.0.0.1:8787",
        crate::transport::RequestContext::new(""),
    )
    .unwrap();
    let clients = crate::transport::EndpointClients::new(transport);
    let err = clients
        .mls()
        .publish_key_package("ak:device:test-prod-guard", &record)
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
    let identity = arkret_sdk::ArkretMlsIdentity::new_basic(
        arkret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap(),
        arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001".to_owned())
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
