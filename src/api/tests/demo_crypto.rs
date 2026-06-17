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
// `upload_keys` / `publish_mls_key_package` now produce real
// event-signer `device_signature`s and fail-closed when no signer is
// installed (asserted just above). `send_to_device` remains the
// demo-only opaque-ciphertext entry point and still pins the contract
// that no dev placeholder reaches the wire when the binary is
// compiled without the `demo-crypto` feature. The prod path
// `anyhow::bail!`s synchronously inside the async fn, so it's
// safe to call without spinning up a network mock — no HTTP byte
// is sent.
//
// CI gate: see `.github/workflows/ci.yml` (`cargo check
// --workspace --no-default-features`) which compiles this module
// with `not(feature = "demo-crypto")` enabled.

#[tokio::test]
async fn upload_keys_fails_closed_without_active_signer() {
    // Device-identity Phase 2: `upload_keys` now produces a REAL
    // `device_signature` via the active event-signer. With no signer
    // installed it MUST fail-closed (never emit a placeholder).
    let api = CokretApi::new("http://127.0.0.1:8787").unwrap();
    let err = api
        .upload_keys("ck:device:test-prod-guard")
        .await
        .expect_err("MUST refuse to upload without an active event-signer");
    let msg = format!("{err}");
    assert!(
        msg.contains("device_signature") && msg.contains("event-signer"),
        "error must name the missing signer, got: {msg}"
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
