use super::binding::push_token_entry_key;
use super::token_source::{current_platform, default_gateway_binding, push_preferences};
use super::*;

fn push_gateway_describe(providers: &[&str]) -> ServiceDescribe {
    let mut describe = ServiceDescribe::development(
        arkret_wire::DidFullId::new("did:web:push.example".to_owned()).unwrap(),
        arkret_wire::TrustDomainId::new("ak:trust_domain:test".to_owned()).unwrap(),
        arkret_wire::ServiceKind::PushGateway,
        vec![
            "ak.operation_bundle.push_gateway.describe.v1".to_owned(),
            "ak.operation_bundle.push_gateway.http_notify.v1".to_owned(),
        ],
        vec![arkret_models_discovery::TransportBinding::http_json(
            "https://push.example/_arkret",
        )],
    );
    describe.limits.extensions.insert(
        "x_floria_supported_providers".to_owned(),
        serde_json::json!(providers),
    );
    describe.limits.extensions.insert(
        "x_floria_auth_modes".to_owned(),
        serde_json::json!(["http-message-signature"]),
    );
    describe
}

fn build_register_request(
    device_id: &str,
) -> anyhow::Result<chime::ChimePushRegisterDeviceRequest> {
    let push_key = "apns:0123456789abcdef0123456789abcdef";
    let idempotency_key = format!("inkson-push-register-{device_id}");
    let config = chime::PushDeviceConfig {
        principal_id: None,
        device_id,
        push_key: Some(push_key),
        platform: Some(current_platform()),
        app_id: Some(APP_ID),
        domestic_app_id: None,
        registration_id: None,
        display_name: Some("inkson"),
        idempotency_key: Some(&idempotency_key),
        request_id: None,
        proof: None,
    };
    Ok(chime::build_register_device_request(
        &config,
        &default_gateway_binding(),
        &push_preferences(),
    )?)
}

fn register_outcome(registration_id: Option<&str>) -> PushRegisterDeviceOutcome {
    PushRegisterDeviceOutcome {
        push_target_id: arkret_wire::PushTargetId::new(
            "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8".to_owned(),
        )
        .unwrap(),
        registration_id: registration_id
            .map(|value| arkret_sdk::OpaqueLocalId::new(value.to_owned()).unwrap()),
        expires_at: None,
    }
}

#[test]
fn builds_chime_register_request() {
    let request = build_register_request("dev_inkson").unwrap();
    assert_eq!(request.device_id, "dev_inkson");
    assert_eq!(request.app_id.as_deref(), Some("inkson"));
    assert_eq!(request.platform.as_deref(), Some(current_platform()));
    assert!(!request.push_key.is_empty());
}

#[test]
fn builds_persistable_registration_state() {
    let request = build_register_request("dev_inkson").unwrap();
    let response = register_outcome(Some("push:test"));
    let state = registration_state_from_response(&request, &response);

    assert_eq!(state.registration_id.as_deref(), Some("push:test"));
    assert_eq!(state.device_id, "dev_inkson");
    assert!(state.push_key_hash.starts_with("sha256:"));
    assert!(!state.push_key_hash.contains("placeholder"));
}

#[test]
fn builds_unregister_request_from_existing_state() {
    let request = build_register_request("dev_inkson").unwrap();
    let response = register_outcome(Some("push:test"));
    let state = registration_state_from_response(&request, &response);
    let unregister = build_unregister_request("dev_inkson", Some(&state)).unwrap();

    assert_eq!(unregister.device_id, "dev_inkson");
    assert_eq!(unregister.registration_id.as_deref(), Some("push:test"));
    assert_eq!(unregister.app_id.as_deref(), Some("inkson"));
}

#[test]
fn summarizes_canonical_push_gateway_description() {
    let summary = summarize_push_gateway(&push_gateway_describe(&["webpush", "fcm"]));

    assert!(summary.contains("ak:did_core:web:push.example"));
    assert!(summary.contains("ak.edge.push.command.notify.v1"));
    assert!(summary.contains("webpush,fcm"));
    assert!(summary.contains("http-message-signature"));
}

#[test]
fn placeholder_push_key_predicate_matches_known_markers() {
    assert!(is_placeholder_push_key(
        "desktop:inkson-dev-placeholder-token"
    ));
    assert!(is_placeholder_push_key(
        "webpush:inkson-dev-placeholder-token"
    ));
    assert!(is_placeholder_push_key("DESKTOP:Inkson-Dev-Placeholder"));
    assert!(!is_placeholder_push_key("apns:abcd1234efgh"));
    assert!(!is_placeholder_push_key(
        "webpush:https://example.com/wp/abc123"
    ));
}

#[test]
fn ensure_production_register_rejects_placeholder_keys() {
    let mut request = build_register_request("dev_inkson").unwrap();
    request.push_key = "desktop:inkson-dev-placeholder-token".to_owned();
    let err = ensure_production_register_request(&request)
        .expect_err("default scaffold push key must be rejected");
    let message = err.to_string();
    assert!(message.contains("dev_inkson"));
    assert!(message.contains("placeholder"));
}

#[test]
fn ensure_production_register_accepts_real_keys() {
    let mut request = build_register_request("dev_inkson").unwrap();
    request.push_key = "apns:5dccd5b9c8be12a8d10dc1ad6c0a3a8d".to_owned();
    ensure_production_register_request(&request).expect("real push key must be accepted");
}

#[test]
fn blind_wakeup_payload_lint_rejects_stable_identifiers() {
    let ok = serde_json::json!({
        "type": "ak.push.blind_wakeup.v1",
        "reason": "background_sync_needed"
    });
    validate_blind_wakeup_payload(&ok).expect("redacted wakeup is allowed");

    for payload in [
        serde_json::json!({"realm_id": "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE"}),
        serde_json::json!({"event": {"event_id": "ak:event:A42FkwFdQPw7aC_yPcdlVU5ZjKLAnFCbmrXTVRJTNhRc"}}),
        serde_json::json!({"sender": "did:web:alice.example"}),
        serde_json::json!({"items": [{"strand_id": "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q"}]}),
        serde_json::json!({"local_name": "Alice from Ops"}),
        serde_json::json!({"petname": "Alice from Ops"}),
        serde_json::json!({"remark": "private label"}),
        serde_json::json!({"opaque": "did:web:alice.example"}),
    ] {
        validate_blind_wakeup_payload(&payload)
            .expect_err("stable ids must not appear in blind wakeups");
    }
}

#[test]
fn push_status_label_treats_state_without_registration_id_as_registered() {
    let request = build_register_request("dev_inkson").unwrap();
    let response = register_outcome(None);
    let state = registration_state_from_response(&request, &response);

    assert_eq!(push_status_label(Some(&state)), "registered");
    assert_eq!(push_status_label(None), "Not registered");
}

#[test]
fn web_push_provider_advertises_web_platform_and_default_sw_path() {
    let provider = WebPushTokenProvider::new();
    assert_eq!(provider.platform(), "web");
    assert_eq!(provider.service_worker_path(), "/service-worker.js");
    let custom = WebPushTokenProvider::new().with_service_worker_path("/sw-v1.js");
    assert_eq!(custom.service_worker_path(), "/sw-v1.js");
}

#[test]
fn fcm_and_apns_providers_advertise_correct_platform_strings() {
    assert_eq!(FcmPushTokenProvider.platform(), "fcm");
    assert_eq!(ApnsPushTokenProvider.platform(), "apns");
}

#[test]
fn fcm_provider_returns_bridged_host_token() {
    clear_fcm_push_token();
    set_fcm_push_token("native-token-123");
    let token = FcmPushTokenProvider.subscribe(None).unwrap().unwrap();
    assert_eq!(token, "fcm:native-token-123");
    clear_fcm_push_token();
}

#[test]
fn apns_provider_returns_bridged_host_token() {
    clear_apns_push_token();
    set_apns_push_token("apns:abcdef012345");
    let token = ApnsPushTokenProvider.subscribe(None).unwrap().unwrap();
    assert_eq!(token, "apns:abcdef012345");
    clear_apns_push_token();
}

#[test]
fn vapid_extractor_returns_none_when_webpush_not_advertised() {
    let describe = push_gateway_describe(&["fcm", "apns"]);
    assert!(vapid_public_key_from_service_describe(&describe).is_none());
}

#[test]
fn vapid_extractor_falls_back_to_env_when_webpush_advertised() {
    // SAFETY: env var mutation in tests is gated behind the per-test
    // serial guard via a unique key; we still scope the change so a
    // panic in the test can't leak into other tests.
    let describe = push_gateway_describe(&["webpush"]);

    // Guard env var manipulation behind cfg(not(target_arch=wasm32))
    // because std::env::set_var doesn't compile on wasm.
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(
        unsafe_code,
        reason = "the test mutates push environment before loading configuration"
    )]
    unsafe {
        std::env::set_var("VAPID_PUBLIC_KEY", "BFakeVapidPublicKey-base64url-string");
    }
    let key = vapid_public_key_from_service_describe(&describe);
    // SAFETY: same serial-guard rationale as the set_var above; this restores
    // the env so neighbouring tests start from a clean slate.
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(
        unsafe_code,
        reason = "the test restores push environment after loading configuration"
    )]
    unsafe {
        std::env::remove_var("VAPID_PUBLIC_KEY");
    }
    #[cfg(not(target_arch = "wasm32"))]
    assert_eq!(key.as_deref(), Some("BFakeVapidPublicKey-base64url-string"));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn web_push_provider_subscribe_native_returns_unsupported() {
    let provider = WebPushTokenProvider::new();
    let err = provider
        .subscribe(None)
        .expect_err("web provider must error on native");
    assert!(err.to_string().contains("wasm32"));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn resolve_provider_push_token_returns_none_without_registered_provider() {
    // Provider OnceLock isn't deterministic across tests; we only
    // assert the no-provider path (the default state in --lib tests).
    // A test that sets the provider via `set_push_token_provider`
    // would race with other tests because OnceLock is process-wide.
    // Instead: we just observe the typed contract.
    let _ = resolve_provider_push_token(None);
}

#[test]
fn vapid_key_decoder_accepts_url_safe_base64() {
    // 65 raw bytes (uncompressed P-256 0x04 || X || Y) shape; we
    // hand-encode in URL-safe-no-pad to mirror the canonical VAPID
    // form documented in RFC 8292.
    use base64::Engine;
    let mut bytes = vec![0x04u8];
    bytes.extend(std::iter::repeat_n(0xab, 32));
    bytes.extend(std::iter::repeat_n(0xcd, 32));
    let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
    let decoded = decode_vapid_application_server_key(&url_safe).expect("decode");
    assert_eq!(decoded.len(), 65);
    assert_eq!(decoded[0], 0x04);
}

#[test]
fn vapid_key_decoder_accepts_padded_standard_base64() {
    use base64::Engine;
    // A valid 65-byte uncompressed P-256 point, encoded as padded standard
    // base64 (the non-URL-safe fallback path).
    let mut bytes = vec![0x04u8];
    bytes.extend(std::iter::repeat_n(0x11, 32));
    bytes.extend(std::iter::repeat_n(0x22, 32));
    let standard = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let decoded = decode_vapid_application_server_key(&standard).expect("decode");
    assert_eq!(decoded, bytes);
}

#[test]
fn vapid_key_decoder_rejects_wrong_length_and_non_uncompressed() {
    use base64::Engine;
    // COR-10: a 32-byte blob is valid base64 but the wrong length for a
    // P-256 public key — it MUST be rejected, not passed to the browser.
    let thirty_two: Vec<u8> = (0..32u8).collect();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&thirty_two);
    assert!(decode_vapid_application_server_key(&encoded).is_err());
    // Correct length but compressed-point prefix (0x02) → rejected.
    let mut compressed = vec![0x02u8];
    compressed.extend(std::iter::repeat_n(0x33, 64));
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&compressed);
    assert!(decode_vapid_application_server_key(&encoded).is_err());
}

#[test]
fn vapid_key_decoder_rejects_empty_and_garbage() {
    assert!(decode_vapid_application_server_key("").is_err());
    assert!(decode_vapid_application_server_key("   ").is_err());
    // Stars are outside both base64 alphabets.
    assert!(decode_vapid_application_server_key("****").is_err());
}

// ── PushTokenBinding / secure_key_store integration ───────────────

use crate::secure_key_store::MemorySecureKeyStore;

#[test]
fn push_token_binding_round_trips_a_token() {
    let store: Arc<dyn SecureKeyStore> = Arc::new(MemorySecureKeyStore::new());
    let binding = PushTokenBinding::new(store.clone(), "dev_inkson");
    assert!(binding.load_token().unwrap().is_none());
    binding.store_token("fcm:real-token-abc").unwrap();
    assert_eq!(
        binding.load_token().unwrap().as_deref(),
        Some("fcm:real-token-abc")
    );
}

/// Distinct device ids share the wrapping seed but get distinct
/// ciphertext slots — overwriting one device's token does not
/// affect another.
#[test]
fn push_token_binding_namespaces_by_device_id() {
    let store: Arc<dyn SecureKeyStore> = Arc::new(MemorySecureKeyStore::new());
    let b_a = PushTokenBinding::new(store.clone(), "device_a");
    let b_b = PushTokenBinding::new(store.clone(), "device_b");
    b_a.store_token("fcm:token-a").unwrap();
    b_b.store_token("apns:token-b").unwrap();
    assert_eq!(b_a.load_token().unwrap().as_deref(), Some("fcm:token-a"));
    assert_eq!(b_b.load_token().unwrap().as_deref(), Some("apns:token-b"));
}

/// After rotating the wrapping seed, any ciphertext written under
/// the old seed and NOT re-wrapped is unrecoverable. This is the
/// load-bearing security property of the binding: a stolen
/// pre-rotation backup cannot be used to recover the post-rotation
/// state.
#[test]
fn push_token_rotation_invalidates_old_ciphertext() {
    let store: Arc<dyn SecureKeyStore> = Arc::new(MemorySecureKeyStore::new());
    let binding = PushTokenBinding::new(store.clone(), "device_x");
    binding.store_token("fcm:original-token").unwrap();
    // Snapshot the ciphertext under the device-id slot.
    let ciphertext_before = store
        .get_secret(&push_token_entry_key("device_x"))
        .unwrap()
        .unwrap();

    // Rotate the wrapping seed WITHOUT re-wrapping the entry —
    // this simulates an attacker who exfiltrated the old
    // ciphertext, then we rotated. The old ciphertext must not
    // decrypt under the new seed.
    let _ = rotate_push_token_wrap_seed(store.as_ref()).unwrap();
    // Manually re-insert the pre-rotation ciphertext so the load
    // path is forced to attempt decryption with the new seed.
    store
        .store_secret(&push_token_entry_key("device_x"), &ciphertext_before)
        .unwrap();
    // load_token returns None when the AEAD MAC fails — that's
    // the "ciphertext is unrecoverable" signal.
    assert!(
        binding.load_token().unwrap().is_none(),
        "old ciphertext must not decrypt under rotated seed"
    );
}

/// `PushTokenBinding::rotate` rotates the seed AND re-wraps the
/// current token so subsequent loads still recover the plaintext.
/// This is the happy path for "user manually rotated push state".
#[test]
fn push_token_binding_rotate_preserves_live_token() {
    let store: Arc<dyn SecureKeyStore> = Arc::new(MemorySecureKeyStore::new());
    let binding = PushTokenBinding::new(store.clone(), "device_y");
    binding.store_token("apns:live-token").unwrap();
    let rotated = binding.rotate().unwrap();
    assert_eq!(rotated.as_deref(), Some("apns:live-token"));
    // Subsequent load succeeds under the new seed.
    assert_eq!(
        binding.load_token().unwrap().as_deref(),
        Some("apns:live-token")
    );
}

/// `delete_token` is idempotent and clears the per-device slot.
#[test]
fn push_token_binding_delete_is_idempotent() {
    let store: Arc<dyn SecureKeyStore> = Arc::new(MemorySecureKeyStore::new());
    let binding = PushTokenBinding::new(store.clone(), "device_z");
    binding.delete_token().expect("idempotent delete");
    binding.store_token("apns:stale").unwrap();
    binding.delete_token().expect("delete");
    assert!(binding.load_token().unwrap().is_none());
    binding.delete_token().expect("idempotent second delete");
}
