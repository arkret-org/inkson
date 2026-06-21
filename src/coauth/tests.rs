use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use url::Url;

use super::*;

/// Regression: a `gate_account_base` like `…/_cokret/gate/account` has no
/// trailing slash, so a naive `Url::join("session-grants")` would REPLACE the
/// `account` segment and POST to `…/_cokret/gate/session-grants` (404). The
/// `endpoint` helper must instead APPEND, preserving `account`.
#[test]
fn endpoint_appends_relative_path_to_bare_gate_account_base() {
    let api = CoauthApi::new("https://local.host/_cokret/gate/account").unwrap();
    assert_eq!(
        api.endpoint("session-grants").unwrap().as_str(),
        "https://local.host/_cokret/gate/account/session-grants"
    );
    assert_eq!(
        api.endpoint("logout").unwrap().as_str(),
        "https://local.host/_cokret/gate/account/logout"
    );
    assert_eq!(
        api.endpoint("session-grants/refresh").unwrap().as_str(),
        "https://local.host/_cokret/gate/account/session-grants/refresh"
    );
}

/// An origin-rooted base already ends in `/`, so the slash-normalisation is a
/// no-op and full paths resolve from the origin root unchanged.
#[test]
fn endpoint_preserves_full_path_on_origin_base() {
    let api = CoauthApi::new("https://auth.local.host").unwrap();
    assert_eq!(
        api.endpoint("_cokret/gate/account/session-grants/refresh")
            .unwrap()
            .as_str(),
        "https://auth.local.host/_cokret/gate/account/session-grants/refresh"
    );
}

#[test]
fn error_envelope_code_extracts_nested_code() {
    let body = r#"{"ok":false,"error":{"code":"grant_already_consumed","message":"gone"},"request_id":"r1"}"#;
    assert_eq!(
        error_envelope_code(body).as_deref(),
        Some("grant_already_consumed")
    );
}

#[test]
fn error_envelope_code_handles_missing_or_malformed() {
    // Not JSON, empty, missing error.code — all yield None so the caller
    // treats the failure as retryable rather than a known terminal code.
    assert_eq!(error_envelope_code(""), None);
    assert_eq!(error_envelope_code("not json"), None);
    assert_eq!(error_envelope_code(r#"{"ok":false}"#), None);
    assert_eq!(error_envelope_code(r#"{"error":{"message":"x"}}"#), None);
}

/// PKCE verifier MUST be 43 chars for our 32-byte seed (RFC 7636 §4.1
/// allows 43-128). Any drift from 32-byte seeds breaks the S256 fixed
/// challenge size; pin it so a future refactor catches the mismatch.
#[test]
fn pkce_verifier_is_url_safe_43_chars() {
    let verifier = random_url_safe_token(PKCE_VERIFIER_BYTES).unwrap();
    assert_eq!(verifier.len(), 43, "32-byte seed → 43-char URL-safe base64");
    assert!(
        verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "must be URL-safe base64 (no padding, no +/)"
    );
}

/// Two consecutive verifier draws MUST differ. If `random_url_safe_token`
/// ever falls back to a deterministic source this test fires.
#[test]
fn random_tokens_are_unguessable() {
    let a = random_url_safe_token(PKCE_VERIFIER_BYTES).unwrap();
    let b = random_url_safe_token(PKCE_VERIFIER_BYTES).unwrap();
    assert_ne!(a, b, "RNG must not return the same value twice in a row");
}

#[test]
fn login_response_accepts_current_coauth_viewer_shape() {
    let response: CoauthLoginOutcome = serde_json::from_value(json!({
        "status": "success",
        "viewer": {
            "id": "user:01K",
            "handle": "ca",
            "did": "did:web:auth.local.host:u:ca",
            "federated_handle": "ca@auth.local.host",
            "principal_id": "@ca:auth.local.host",
            "display_name": null
        },
        "session_grant": {
            "kind": "principal_session",
            "id": "grant-1",
            "grant_jwt": "eyJ.mock.jwt",
            "session_public_key": "mock-public",
            "session_private_key_pem": "-----BEGIN PRIVATE KEY-----\\nmock\\n-----END PRIVATE KEY-----",
            "expires_at": "2026-05-13T04:00:00Z",
            "audience": "https://local.host/api",
            "scopes": ["urn:cokret:principal-server:session.bind"],
            "principal_server": {
                "name": "local",
                "endpoint": "https://local.host"
            }
        },
        "warnings": []
    }))
    .unwrap();

    let viewer = response.viewer.unwrap();
    assert_eq!(viewer.principal_id.as_deref(), Some("@ca:auth.local.host"));
}

#[test]
fn login_response_accepts_one_shot_session_grant_without_private_key() {
    let response: CoauthLoginOutcome = serde_json::from_value(json!({
        "status": "success",
        "viewer": {
            "id": "user:01K",
            "handle": "ca",
            "did": "did:web:auth.local.host:u:ca",
            "federated_handle": "ca@auth.local.host",
            "principal_id": "@ca:auth.local.host",
            "display_name": null
        },
        "session_grant": {
            "kind": "principal_session",
            "id": "grant-1",
            "grant_jwt": "eyJ.mock.jwt",
            "session_public_key": "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"mock\"}",
            "expires_at": "2026-05-13T04:00:00Z",
            "audience": "https://local.host/api",
            "scopes": ["urn:cokret:principal-server:session.bind"]
        }
    }))
    .unwrap();

    let grant = response.session_grant.expect("session grant");
    assert_eq!(grant.session_private_key_pem, "");
    assert_eq!(grant.audience.as_deref(), Some("https://local.host/api"));
}

/// S256 challenge for a known verifier matches the RFC 7636 Appendix B
/// test vector — confirms we hash the right bytes and base64-encode
/// without padding.
#[test]
fn s256_challenge_matches_rfc7636_test_vector() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = pkce_code_challenge_s256(verifier);
    assert_eq!(
        challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "S256 challenge MUST match RFC 7636 Appendix B"
    );
}

/// The introspection proof MUST be a valid Ed25519 JWS over the
/// canonical claims, MUST embed `ck.session_grant.introspection_proof.v1`
/// as `type`, MUST hash the grant JWT into `grant_jwt_hash`, and MUST
/// round-trip the challenge / audience / grant_id verbatim. coauth's
/// verifier requires every one of those exact strings - drift here
/// would surface as `InvalidProof` at the principal server.
#[test]
fn session_grant_proof_signs_canonical_claims() {
    use ed25519_dalek::{SigningKey, Verifier};
    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let verifying = signing.verifying_key();
    let proof_jwt = build_session_grant_introspection_proof(
        "01HABC123",
        "eyJ.opaque-grant.jwt",
        "did:web:principal.example",
        "challenge-deadbeef",
        &signing,
    )
    .unwrap();
    // Compact JWS: 3 segments separated by `.`.
    let parts: Vec<&str> = proof_jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "proof must be a compact JWS");
    // Decode + verify the signature against the matching pubkey.
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
    verifying
        .verify(signing_input.as_bytes(), &signature)
        .expect("proof JWS must verify under matching pubkey");
    // Decode + assert payload claims.
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let claims: SessionGrantIntrospectionProofClaims =
        serde_json::from_slice(&payload_bytes).unwrap();
    assert_eq!(
        claims.kind, "ck.session_grant.introspection_proof.v1",
        "type claim must match coauth's spec"
    );
    assert_eq!(claims.grant_id, "01HABC123");
    assert_eq!(claims.audience, "did:web:principal.example");
    assert_eq!(claims.challenge, "challenge-deadbeef");
    assert_eq!(
        claims.grant_jwt_hash,
        session_grant_jwt_hash("eyJ.opaque-grant.jwt"),
        "grant_jwt_hash must be sha256(grant_jwt) hex prefixed"
    );
    // Header claim is `EdDSA` + `JWT`.
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
    let header: Value = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(header.get("alg").and_then(|v| v.as_str()), Some("EdDSA"));
    assert_eq!(header.get("typ").and_then(|v| v.as_str()), Some("JWT"));
}

#[test]
fn session_grant_private_key_pem_round_trips_to_signing_key() {
    use ed25519_dalek::pkcs8::EncodePrivateKey as _;

    let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let pem = signing
        .to_pkcs8_pem(Default::default())
        .expect("encode pkcs8 pem");
    let decoded = session_grant_signing_key_from_pem(&pem).expect("decode pkcs8 pem");

    assert_eq!(decoded.to_bytes(), signing.to_bytes());
}

/// Empty inputs MUST be rejected — coauth's verifier treats blank
/// challenge / proof_jwt as `InvalidProof` so client-side validation
/// avoids round-tripping unsignable garbage.
#[test]
fn session_grant_proof_rejects_empty_inputs() {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
    assert!(build_session_grant_introspection_proof("", "j", "a", "c", &signing).is_err());
    assert!(build_session_grant_introspection_proof("g", "", "a", "c", &signing).is_err());
    assert!(build_session_grant_introspection_proof("g", "j", "", "c", &signing).is_err());
    assert!(build_session_grant_introspection_proof("g", "j", "a", "", &signing).is_err());
}

#[test]
fn session_grant_jwt_hash_matches_coauth_format() {
    // `sha256:<lowercase-hex(sha256(bytes))>`. Pin the format so a
    // refactor that switches to base64url doesn't silently desync.
    let hash = session_grant_jwt_hash("hello");
    assert!(hash.starts_with("sha256:"));
    // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    assert_eq!(
        hash,
        "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}

/// `open_oidc_authorize_url` MUST refuse non-http(s) schemes —
/// hand-crafted `javascript:` / `file:` URLs would be a phishing
/// surface on the desktop target.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn open_oidc_authorize_url_rejects_non_http_schemes() {
    let result = open_oidc_authorize_url("javascript:alert(1)");
    assert!(result.is_err(), "javascript: scheme MUST be rejected");
    let result = open_oidc_authorize_url("file:///etc/passwd");
    assert!(result.is_err(), "file: scheme MUST be rejected");
}

#[test]
fn callback_url_uses_current_href_when_query_is_present() {
    let callback = callback_url_with_query(
        "http://127.0.0.1:8080/auth/callback?code=c&state=s",
        Some("http://127.0.0.1:8080/auth/callback?code=old&state=old"),
    )
    .unwrap();
    assert_eq!(
        callback,
        "http://127.0.0.1:8080/auth/callback?code=c&state=s"
    );
}

#[test]
fn callback_url_falls_back_to_initial_navigation_after_router_strips_query() {
    let callback = callback_url_with_query(
        "http://127.0.0.1:8080/auth/callback",
        Some("http://127.0.0.1:8080/auth/callback?code=c&state=s"),
    )
    .unwrap();
    assert_eq!(
        callback,
        "http://127.0.0.1:8080/auth/callback?code=c&state=s"
    );
}

#[test]
fn callback_url_rejects_initial_navigation_from_different_location() {
    let err = callback_url_with_query(
        "http://127.0.0.1:8080/auth/callback",
        Some("http://127.0.0.1:8080/other?code=c&state=s"),
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("does not contain callback query parameters")
    );
}

fn test_discovery() -> OidcDiscoveryDocument {
    OidcDiscoveryDocument {
        issuer: "https://issuer.example".to_owned(),
        authorization_endpoint: "https://issuer.example/auth".to_owned(),
        token_endpoint: Some("https://issuer.example/token".to_owned()),
        userinfo_endpoint: Some("https://issuer.example/userinfo".to_owned()),
        code_challenge_methods_supported: vec!["S256".to_owned()],
        scopes_supported: vec!["openid".to_owned(), "offline_access".to_owned()],
    }
}

fn test_oidc_method() -> cokret_sdk::AuthMethod {
    cokret_sdk::AuthMethod {
        method: cokret_sdk::AuthMethodKind::Oidc,
        issuer: Some("https://issuer.example".to_owned()),
        provider: None,
        openid_configuration: Some(
            "https://issuer.example/.well-known/openid-configuration".to_owned(),
        ),
        client_id: Some("yougen-test".to_owned()),
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        grant_exchange: cokret_sdk::AuthGrantExchange {
            proof_kind: cokret_sdk::SessionGrantProofKind::OidcCodeExchange,
        },
    }
}

/// State and nonce tokens MUST diverge across calls (RFC 6749 §10.12 /
/// RFC 7636 unguessability).
#[test]
fn state_and_nonce_diverge_for_same_caller() {
    let discovery = test_discovery();
    let method = test_oidc_method();
    let bundle_a = build_oidc_authorize_scaffold(
        &discovery,
        &method,
        "https://app.example/auth/callback",
        "",
        "device-aaaa-1111",
        "https://principal.example/api",
    )
    .unwrap();
    let bundle_b = build_oidc_authorize_scaffold(
        &discovery,
        &method,
        "https://app.example/auth/callback",
        "",
        "device-aaaa-1111",
        "https://principal.example/api",
    )
    .unwrap();
    assert_ne!(bundle_a.state, bundle_b.state);
    assert_ne!(bundle_a.nonce, bundle_b.nonce);
    assert_ne!(bundle_a.code_verifier, bundle_b.code_verifier);
    assert_ne!(bundle_a.state, bundle_a.nonce);
}

/// `code_challenge` MUST be S256(code_verifier) when discovery supports S256.
#[test]
fn bundle_challenge_is_s256_of_verifier_when_supported() {
    let bundle = build_oidc_authorize_scaffold(
        &test_discovery(),
        &test_oidc_method(),
        "https://app.example/auth/callback",
        "",
        "device-bbbb-2222",
        "https://principal.example/api",
    )
    .unwrap();
    assert_eq!(
        bundle.code_challenge,
        pkce_code_challenge_s256(&bundle.code_verifier),
        "S256 discovery must produce S256(verifier) challenge"
    );
}

#[test]
fn authorize_scaffold_rejects_plain_only_pkce_discovery() {
    let mut discovery = test_discovery();
    discovery.code_challenge_methods_supported = vec!["plain".to_owned()];
    let error = build_oidc_authorize_scaffold(
        &discovery,
        &test_oidc_method(),
        "https://app.example/auth/callback",
        "",
        "device-plain-only",
        "https://principal.example/api",
    )
    .unwrap_err();
    assert!(error.to_string().contains("PKCE S256"));
}

/// The authorize URL forces re-authentication (prompt=login, max_age=0).
#[test]
fn authorize_url_forces_reauthentication() {
    let bundle = build_oidc_authorize_scaffold(
        &test_discovery(),
        &test_oidc_method(),
        "https://app.example/auth/callback",
        "",
        "device-cccc-3333",
        "https://principal.example/api",
    )
    .unwrap();
    let parsed = Url::parse(&bundle.authorize_url).unwrap();
    assert_eq!(
        parsed
            .query_pairs()
            .find(|(key, _)| key == "prompt")
            .unwrap()
            .1,
        "login"
    );
    assert_eq!(
        parsed
            .query_pairs()
            .find(|(key, _)| key == "max_age")
            .unwrap()
            .1,
        "0"
    );
}

/// The authorize URL MUST request `openid`, the method scopes, and the
/// stable device-binding scope (prevents cursor_integrity_invalid drift).
#[test]
fn authorize_url_requests_standard_and_device_scope() {
    let bundle = build_oidc_authorize_scaffold(
        &test_discovery(),
        &test_oidc_method(),
        "https://app.example/auth/callback",
        "",
        "device-dddd-4444",
        "https://principal.example/api",
    )
    .unwrap();
    let parsed = Url::parse(&bundle.authorize_url).unwrap();
    let requested_scope = parsed
        .query_pairs()
        .find(|(key, _)| key == "scope")
        .unwrap()
        .1
        .into_owned();
    let scopes: Vec<&str> = requested_scope.split_ascii_whitespace().collect();
    assert!(scopes.contains(&"openid"));
    assert!(scopes.contains(&"profile"));
    assert!(
        scopes.contains(&format!("{COKRET_DEVICE_SCOPE_PREFIX}device-dddd-4444").as_str()),
        "authorize URL must request the device-binding scope, got: {requested_scope}"
    );
}

/// `client_id` falls back to the native yougen id when the method omits it.
#[test]
fn authorize_url_falls_back_to_native_client_id() {
    let mut method = test_oidc_method();
    method.client_id = None;
    let bundle = build_oidc_authorize_scaffold(
        &test_discovery(),
        &method,
        "https://app.example/auth/callback",
        "",
        "device-eeee-5555",
        "https://principal.example/api",
    )
    .unwrap();
    assert_eq!(bundle.client_id, YOUGEN_OIDC_CLIENT_ID);
    let parsed = Url::parse(&bundle.authorize_url).unwrap();
    assert_eq!(
        parsed
            .query_pairs()
            .find(|(key, _)| key == "client_id")
            .unwrap()
            .1,
        YOUGEN_OIDC_CLIENT_ID
    );
}

/// `gate_account_base` derivation uses the strong `account_authority`.
#[test]
fn resolve_gate_account_base_prefers_account_authority() {
    let mut metadata = cokret_sdk::AuthMetadata::minimal("production");
    metadata.account_authority = Some(cokret_sdk::AccountAuthority {
        origin: "https://aa.example".to_owned(),
        gate_account_base: "https://aa.example/_cokret/gate/account".to_owned(),
    });
    let base = resolve_gate_account_base("https://principal.example", &metadata).unwrap();
    assert_eq!(base, "https://aa.example/_cokret/gate/account");
}

#[test]
fn resolve_gate_account_base_derives_from_account_authority_origin() {
    let mut metadata = cokret_sdk::AuthMetadata::minimal("production");
    metadata.account_authority = Some(cokret_sdk::AccountAuthority {
        origin: "https://aa.example".to_owned(),
        gate_account_base: String::new(),
    });
    let base = resolve_gate_account_base("https://principal.example", &metadata).unwrap();
    assert_eq!(base, "https://aa.example/_cokret/gate/account");
}

#[test]
fn resolve_gate_account_base_fails_closed_without_account_authority() {
    let metadata = cokret_sdk::AuthMetadata::minimal("production");
    let error = resolve_gate_account_base("https://principal.example", &metadata).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("auth_metadata.account_authority")
    );
}
