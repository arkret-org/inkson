use super::super::*;

#[cfg(feature = "demo-crypto")]
#[test]
fn demo_crypto_fallbacks_are_local_only_by_default() {
    let local = CokretApi::new("http://127.0.0.1:8787").unwrap();
    local
        .ensure_demo_crypto_fallback_allowed("test fallback")
        .expect("local dev fallback");
    let remote = CokretApi::new("https://cokret.example").unwrap();
    assert!(
        remote
            .ensure_demo_crypto_fallback_allowed("test fallback")
            .is_err()
    );
}

#[cfg(not(feature = "demo-crypto"))]
#[test]
fn demo_crypto_fallbacks_are_compiled_out() {
    let local = CokretApi::new("http://127.0.0.1:8787").unwrap();
    assert!(
        local
            .ensure_demo_crypto_fallback_allowed("test fallback")
            .is_err(),
        "without the `demo-crypto` feature, even loopback hosts must fail closed"
    );
}

// ── Production-path wire guards ─────────────────────────────────
//
// `publish_mls_key_package` produces a real event-signer
// `device_signature` and fails-closed when no signer is installed
// (asserted just below). `upload_keys` / `send_to_device` are the
// demo-only placeholder entry points (placeholder one-time key
// material / opaque ciphertext) and pin the contract that no dev
// placeholder reaches the wire when the binary is compiled without
// the `demo-crypto` feature. Their prod path `anyhow::bail!`s
// synchronously inside the async fn, so it's safe to call without
// spinning up a network mock — no HTTP byte is sent.
//
// CI gate: see `.github/workflows/ci.yml` (`cargo check
// --workspace --no-default-features`) which compiles this module
// with `not(feature = "demo-crypto")` enabled.

#[tokio::test]
async fn upload_keys_fails_closed_without_demo_crypto() {
    // `upload_keys` ships placeholder one-time key material, so the
    // non-`demo-crypto` build MUST fail-closed before any wire byte
    // leaves the device (never emit a placeholder prekey).
    let api = CokretApi::new("http://127.0.0.1:8787").unwrap();
    let err = api
        .upload_keys("ck:device:test-prod-guard")
        .await
        .expect_err("MUST refuse to upload placeholder prekeys without demo-crypto");
    let msg = format!("{err}");
    assert!(
        msg.contains("demo-crypto") && msg.contains("placeholder"),
        "error must name the demo-crypto gate, got: {msg}"
    );
}

#[tokio::test]
async fn publish_mls_key_package_fails_closed_without_active_signer() {
    // Build a syntactically-valid MlsKeyPackageRecord via JSON so
    // we don't need to import every field type. The prod path
    // bails before reading any field, but we still want the
    // argument well-formed so a future refactor that touches the
    // record before bailing surfaces here.
    let record: cokret_sdk::MlsKeyPackageRecord = serde_json::from_value(serde_json::json!({
        "keypackage_id": "ck:mls:kp:01904100-0000-7000-8000-000000000001",
        "principal_id": "did:web:alice.example",
        "device_id": "ck:device:01904100-0000-7000-8000-000000000001",
        "key_package": "AAAA",
        "keypackage_ref": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "cipher_suites": ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
        "created_at": "2026-01-01T00:00:00Z",
    }))
    .expect("MlsKeyPackageRecord fixture must deserialize");

    let api = CokretApi::new("http://127.0.0.1:8787").unwrap();
    let err = api
        .publish_mls_key_package("ck:device:test-prod-guard", &record)
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
fn mls_key_package_upload_value_includes_digest_alias() {
    let identity = cokret_sdk::CokretMlsIdentity::new_basic(
        cokret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap(),
        cokret_sdk::DeviceId::new("ck:device:01904100-0000-7000-8000-000000000001".to_owned())
            .unwrap(),
    )
    .unwrap();
    let record = identity.key_package_record().unwrap();

    let value = super::super::mls::mls_key_package_record_upload_value(&record).unwrap();

    assert_eq!(
        value["keypackage_digest"].as_str(),
        Some(record.keypackage_ref.as_str())
    );
    assert_eq!(
        value["keypackage_ref"].as_str(),
        Some(record.keypackage_ref.as_str())
    );
}

#[cfg(not(feature = "demo-crypto"))]
#[tokio::test]
async fn send_to_device_refuses_opaque_ciphertext_placeholder_in_prod_build() {
    let api = CokretApi::new("http://127.0.0.1:8787").unwrap();
    let err = api
        .send_to_device("did:web:bob.example", "ck:device:test-prod-guard")
        .await
        .expect_err("prod build MUST refuse to ship opaque ciphertext placeholders");
    let msg = format!("{err}");
    assert!(
        msg.contains("ciphertext") && msg.contains("demo-crypto"),
        "prod-path error must name the placeholder + missing feature gate, got: {msg}"
    );
}

/// Belt-and-braces: even on a loopback host, the prod build of the
/// helper guard must fail closed. We already cover this in
/// `demo_crypto_fallbacks_are_compiled_out` for the public
/// `ensure_demo_crypto_fallback_allowed`; this variant additionally
/// asserts that the error message names the missing build feature
/// so the caller can suggest the right fix in operator-facing logs.
#[cfg(not(feature = "demo-crypto"))]
#[test]
fn demo_crypto_guard_message_names_required_build_feature() {
    let local = CokretApi::new("http://127.0.0.1:8787").unwrap();
    let err = local
        .ensure_demo_crypto_fallback_allowed("upload_keys demo device_signature")
        .expect_err("prod build must fail closed even on loopback");
    let msg = format!("{err}");
    assert!(
        msg.contains("demo-crypto"),
        "guard error must reference the `demo-crypto` build feature for operators, got: {msg}"
    );
}
