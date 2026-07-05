use reqwest::header::{HeaderMap, HeaderValue};

use super::super::*;

#[test]
fn self_request_pop_signature_roundtrips_with_sdk_verifier() {
    use ed25519_dalek::pkcs8::EncodePrivateKey as _;

    let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let pem = signing
        .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .unwrap()
        .to_string();
    let api = CokretApi::new("https://soland.example.com")
        .unwrap()
        .with_bearer("tok")
        .with_session_signing_key(&pem)
        .unwrap();

    let body = serde_json::to_vec(&serde_json::json!({"hello": "world"})).unwrap();
    let request = api
        .http
        .post(api.endpoint("/_cokret/self/events").unwrap())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.clone())
        .build()
        .unwrap();
    let signed = api.sign_request(request).unwrap();

    let headers: Vec<(String, String)> = signed
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.to_str().unwrap().to_owned()))
        .collect();
    let url = signed.url().clone();
    let authority = url.host_str().unwrap().to_owned();

    // The same SDK verifier soland runs MUST accept the yougen signature.
    let verified = cokret_sdk::http_signature::verify_signed_http_message(
        "POST",
        url.as_str(),
        &authority,
        url.path(),
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        &body,
        &signing.verifying_key(),
        &cokret_sdk::http_signature::SignatureVerificationPolicy::service_ingest()
            .require_content_digest(true)
            .max_clock_skew_seconds(30),
        chrono::Utc::now().timestamp(),
    )
    .expect("SDK verifies yougen-produced PoP signature");
    assert_eq!(
        verified.signature_input.key_id,
        crate::dpop::jwk_thumbprint_ed25519(&signing.verifying_key())
    );
    assert!(verified.signature_input.expires - verified.signature_input.created <= 300);
}

#[test]
fn events_batch_response_rejects_partial_acceptance() {
    let accepted: cokret_sdk::EventsSubmitOutcome = serde_json::from_value(json!({
        "status": "accepted",
        "rejected": []
    }))
    .unwrap();
    ensure_events_submit_accepted(&accepted).expect("fully accepted submit should pass");

    let partial: cokret_sdk::EventsSubmitOutcome = serde_json::from_value(json!({
        "status": "partial",
        "rejected": [
            {
                "id": "ck:event:2",
                "reason_code": "capability_denied",
                "detail": "actor is not a member"
            }
        ]
    }))
    .unwrap();
    let err = ensure_events_submit_accepted(&partial).expect_err("partial submit must fail fast");
    assert!(err.to_string().contains("capability_denied"));
    assert!(err.to_string().contains("status=partial"));
}

#[test]
fn retry_policy_defaults_to_bounded_idempotent_retries() {
    let options = CokretApiOptions::default();
    assert_eq!(options.retry.max_retries, 2);
    assert!(options.timeout >= Duration::from_secs(1));
    assert!(is_retryable_method(&Method::GET));
    assert!(is_retryable_method(&Method::PUT));
    assert!(!is_retryable_method(&Method::POST));
    assert!(is_retryable_status(StatusCode::TOO_MANY_REQUESTS));
    assert!(is_retryable_status(StatusCode::BAD_GATEWAY));
    assert!(!is_retryable_status(StatusCode::CONFLICT));
}

#[test]
fn retry_after_prefers_seconds_header() {
    let mut headers = HeaderMap::new();
    headers.insert(RETRY_AFTER, HeaderValue::from_static("3"));
    assert_eq!(parse_retry_after(&headers), Some(Duration::from_secs(3)));
}

#[test]
fn write_requests_include_request_identity_and_wait_for_headers() {
    const WAIT_CURSOR: &str = "ck:cursor:eyJoIjoiMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMiIsInB1cnBvc2UiOiJzdHJlYW0iLCJ0IjoiMjAyNi0wNS0yOVQwMDowMDowMC4wMDBaIiwidiI6IjEiLCJ4IjoxNzgwMDAwMDAwMDAwfQ";
    let api = CokretApi::new("http://127.0.0.1:8787/")
        .unwrap()
        .with_bearer("sx_token")
        .with_wait_for(WAIT_CURSOR);
    let request = api
        .prepare_request(
            api.with_write_request_headers(
                api.http
                    .post(api.endpoint("_cokret/self/events").unwrap())
                    .json(&json!({"body": "hello"})),
                "req-123",
            ),
        )
        .build()
        .unwrap();

    assert_eq!(
        request
            .headers()
            .get("x-cokret-request-id")
            .and_then(|value| value.to_str().ok()),
        Some("req-123")
    );
    assert_eq!(
        request
            .headers()
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok()),
        Some("req-123")
    );
    assert_eq!(
        request
            .headers()
            .get("x-cokret-wait-for")
            .and_then(|value| value.to_str().ok()),
        Some(WAIT_CURSOR)
    );
}

#[test]
fn wait_for_header_rejects_malformed_sync_tokens() {
    let malformed = CokretApi::new("http://127.0.0.1:8787/")
        .unwrap()
        .with_wait_for("ck:cursor:");
    let request = malformed
        .prepare_request(
            malformed.with_write_request_headers(
                malformed
                    .http
                    .post(malformed.endpoint("_cokret/self/events").unwrap())
                    .json(&json!({"body": "hello"})),
                "req-456",
            ),
        )
        .build()
        .unwrap();
    assert!(request.headers().get("x-cokret-wait-for").is_none());
}
