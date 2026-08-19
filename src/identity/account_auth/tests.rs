use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use url::Url;

use super::*;

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
/// canonical claims, MUST embed `ak.session_grant.introspection_proof.v1`
/// as `type`, MUST hash the grant JWT into `grant_jwt_digest`, and MUST
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
    let claims: arkret_sdk::SessionGrantIntrospectionProofClaims =
        serde_json::from_slice(&payload_bytes).unwrap();
    assert_eq!(
        claims.kind, "ak.session_grant.introspection_proof.v1",
        "type claim must match coauth's spec"
    );
    assert_eq!(claims.session_grant_id, "01HABC123");
    assert_eq!(
        claims.audience.as_str(),
        "ak:did_core:web:principal.example"
    );
    assert_eq!(claims.challenge, "challenge-deadbeef");
    assert_eq!(
        claims.grant_jwt_digest,
        session_grant_jwt_digest("eyJ.opaque-grant.jwt"),
        "grant_jwt_digest must be sha256(grant_jwt) hex prefixed"
    );
    // Header claim is `Ed25519` + `JWT`.
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
    let header: Value = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(header.get("alg").and_then(|v| v.as_str()), Some("Ed25519"));
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
fn session_grant_jwt_digest_matches_coauth_format() {
    // `sha256:<lowercase-hex(sha256(bytes))>`. Pin the format so a
    // refactor that switches to base64url doesn't silently desync.
    let hash = session_grant_jwt_digest("hello");
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
        code_challenge_methods_supported: vec!["S256".to_owned()],
        scopes_supported: vec!["openid".to_owned(), "offline_access".to_owned()],
    }
}

fn test_oidc_method() -> arkret_sdk::AuthMethod {
    arkret_sdk::AuthMethod {
        method: arkret_sdk::AuthMethodKind::Oidc,
        issuer: Some("https://issuer.example".to_owned()),
        provider: None,
        openid_configuration: Some(
            "https://issuer.example/.well-known/openid-configuration".to_owned(),
        ),
        client_id: Some("inkson-test".to_owned()),
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        grant_exchange: arkret_sdk::AuthGrantExchange {
            proof_kind: arkret_sdk::SessionGrantProofKind::OidcCodeExchange,
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
        "device-aaaa-1111",
        "https://principal.example/api",
        &OidcEntryPoint::SignIn,
        "en",
    )
    .unwrap();
    let bundle_b = build_oidc_authorize_scaffold(
        &discovery,
        &method,
        "https://app.example/auth/callback",
        "device-aaaa-1111",
        "https://principal.example/api",
        &OidcEntryPoint::SignIn,
        "en",
    )
    .unwrap();
    assert_ne!(bundle_a.state, bundle_b.state);
    assert_ne!(bundle_a.nonce, bundle_b.nonce);
    assert_ne!(bundle_a.code_verifier, bundle_b.code_verifier);
    assert_ne!(bundle_a.state, bundle_a.nonce);
}

#[test]
fn persisted_scaffold_carries_returning_principal_assertion() {
    let bundle = build_oidc_authorize_scaffold(
        &test_discovery(),
        &test_oidc_method(),
        "https://app.example/auth/callback",
        "ak:device:01964137-0000-7000-8000-000000000001",
        "ak:did_core:webvh:z6mkfixture",
        &OidcEntryPoint::SignIn,
        "en",
    )
    .unwrap();
    let trust_domain =
        arkret_sdk::TrustDomainId::new("ak:trust_domain:principal.example".to_owned()).unwrap();
    let expected =
        arkret_sdk::DidFullId::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();

    let scaffold = build_persisted_oidc_scaffold(
        &bundle,
        "https://auth.example/_arkret/gate/account",
        "https://principal.example",
        "ak:device:01964137-0000-7000-8000-000000000001",
        "https://issuer.example",
        &trust_domain,
        Some(&expected),
    );

    assert_eq!(
        scaffold.expected_principal_full_id.as_ref(),
        Some(&expected)
    );
    let mut old_payload = serde_json::to_value(scaffold).unwrap();
    old_payload
        .as_object_mut()
        .unwrap()
        .remove("expected_principal_full_id");
    let restored: PersistedOidcScaffold = serde_json::from_value(old_payload).unwrap();
    assert_eq!(restored.expected_principal_full_id, None);
}

/// `code_challenge` MUST be S256(code_verifier) when discovery supports S256.
#[test]
fn bundle_challenge_is_s256_of_verifier_when_supported() {
    let bundle = build_oidc_authorize_scaffold(
        &test_discovery(),
        &test_oidc_method(),
        "https://app.example/auth/callback",
        "device-bbbb-2222",
        "https://principal.example/api",
        &OidcEntryPoint::SignIn,
        "en",
    )
    .unwrap();
    let authorize_url = url::Url::parse(&bundle.authorize_url).unwrap();
    let code_challenge = authorize_url
        .query_pairs()
        .find_map(|(key, value)| (key == "code_challenge").then(|| value.into_owned()))
        .expect("authorize URL code_challenge");
    assert_eq!(
        code_challenge,
        pkce_code_challenge_s256(&bundle.code_verifier)
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
        "device-plain-only",
        "https://principal.example/api",
        &OidcEntryPoint::SignIn,
        "en",
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
        "device-cccc-3333",
        "https://principal.example/api",
        &OidcEntryPoint::SignIn,
        "zh",
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
    assert_eq!(
        parsed
            .query_pairs()
            .find(|(key, _)| key == "ui_locales")
            .unwrap()
            .1,
        "zh"
    );
}

/// A new-identity transaction must enter the issuer's registration strand;
/// treating it as login loses the original creation intent when the user has
/// to create an Account Authority account first.
#[test]
fn create_identity_authorize_url_uses_prompt_create() {
    let bundle = build_oidc_authorize_scaffold(
        &test_discovery(),
        &test_oidc_method(),
        "https://app.example/auth/callback",
        "device-create-3333",
        "https://principal.example/api",
        &OidcEntryPoint::CreateIdentity,
        "zh",
    )
    .unwrap();
    let parsed = Url::parse(&bundle.authorize_url).unwrap();
    assert_eq!(
        parsed
            .query_pairs()
            .find(|(key, _)| key == "prompt")
            .unwrap()
            .1,
        "create"
    );
    assert!(
        parsed.query_pairs().all(|(key, _)| key != "max_age"),
        "prompt=create must not inherit login-only max_age"
    );
}

/// The authorize URL MUST request `openid`, the method scopes, and the
/// pending device-binding scope used throughout this sign-in strand.
#[test]
fn authorize_url_requests_standard_and_device_scope() {
    let bundle = build_oidc_authorize_scaffold(
        &test_discovery(),
        &test_oidc_method(),
        "https://app.example/auth/callback",
        "device-dddd-4444",
        "https://principal.example/api",
        &OidcEntryPoint::SignIn,
        "en",
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
        scopes.contains(&format!("{ARKRET_DEVICE_SCOPE_PREFIX}device-dddd-4444").as_str()),
        "authorize URL must request the device-binding scope, got: {requested_scope}"
    );
}

/// `client_id` falls back to the native inkson id when the method omits it.
#[test]
fn authorize_url_falls_back_to_native_client_id() {
    let mut method = test_oidc_method();
    method.client_id = None;
    let bundle = build_oidc_authorize_scaffold(
        &test_discovery(),
        &method,
        "https://app.example/auth/callback",
        "device-eeee-5555",
        "https://principal.example/api",
        &OidcEntryPoint::SignIn,
        "en",
    )
    .unwrap();
    assert_eq!(bundle.client_id, INKSON_OIDC_CLIENT_ID);
    let parsed = Url::parse(&bundle.authorize_url).unwrap();
    assert_eq!(
        parsed
            .query_pairs()
            .find(|(key, _)| key == "client_id")
            .unwrap()
            .1,
        INKSON_OIDC_CLIENT_ID
    );
}

/// `gate_account_base` derivation uses the strong `account_authority`.
#[test]
fn resolve_gate_account_base_prefers_account_authority() {
    let mut metadata = arkret_sdk::AuthMetadata::minimal("production");
    metadata.account_authority = Some(arkret_sdk::AccountAuthority {
        origin: "https://aa.example".to_owned(),
        gate_account_base: "https://aa.example/_arkret/gate/account".to_owned(),
    });
    let base = resolve_gate_account_base("https://principal.example", &metadata).unwrap();
    assert_eq!(base, "https://aa.example/_arkret/gate/account");
}

#[test]
fn resolve_gate_account_base_derives_from_account_authority_origin() {
    let mut metadata = arkret_sdk::AuthMetadata::minimal("production");
    metadata.account_authority = Some(arkret_sdk::AccountAuthority {
        origin: "https://aa.example".to_owned(),
        gate_account_base: String::new(),
    });
    let base = resolve_gate_account_base("https://principal.example", &metadata).unwrap();
    assert_eq!(base, "https://aa.example/_arkret/gate/account");
}

#[test]
fn resolve_gate_account_base_fails_closed_without_account_authority() {
    let metadata = arkret_sdk::AuthMetadata::minimal("production");
    let error = resolve_gate_account_base("https://principal.example", &metadata).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("auth_metadata.account_authority")
    );
}

fn principal_description() -> arkret_sdk::ServiceDescribe {
    let mut description = arkret_sdk::ServiceDescribe::development(
        arkret_sdk::DidFullId::new("did:webvh:z6mkfixture:principal.example".to_owned()).unwrap(),
        arkret_sdk::TrustDomainId::new("ak:trust_domain:principal.example".to_owned()).unwrap(),
        arkret_sdk::ServiceKind::PrincipalServer,
    );
    description.auth_metadata.account_authority = Some(arkret_sdk::AccountAuthority {
        origin: "https://auth.example".to_owned(),
        gate_account_base: "https://auth.example/_arkret/gate/account".to_owned(),
    });
    description
}

#[test]
fn authority_resolver_carries_principal_trust_domain() {
    let description = principal_description();
    let resolver =
        AuthorityResolver::from_description("https://principal.example", &description).unwrap();
    assert_eq!(
        resolver.principal_trust_domain.as_str(),
        "ak:trust_domain:principal.example"
    );
}
