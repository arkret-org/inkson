//! Round 27 (C32.6): OIDC callback orchestrator.
//!
//! The lower-level pieces of the PKCE authorization-code flow already
//! exist:
//!
//! * [`crate::coauth::build_oidc_scaffold_bundle`] / [`persist_oidc_scaffold`]
//!   mint cryptographic `state` / `nonce` / PKCE verifier and stash them
//!   in `localStorage` (web) before opening the authorize URL.
//! * [`crate::coauth::extract_authorization_code_from_callback`] /
//!   [`extract_state_from_callback`] / [`extract_error_from_callback`] parse
//!   the redirect-URI query string the IdP hands back.
//! * [`crate::coauth::CoauthApi::exchange_pkce_code_for_tokens`] does the
//!   actual `authorization_code` POST against the IdP's token endpoint and
//!   returns a typed [`OidcTokenResponse`].
//! * [`crate::api::ContrixApi::exchange_session_grant_at`] swaps a
//!   coauth-issued audience grant JWT for an authenticated Principal
//!   Server session (a `DevLoginResponse` with access_token + refresh).
//!
//! Until this module landed there was no glue that ran those steps in
//! the right order, validated the CSRF state, persisted the resulting
//! [`OidcTokenBundle`], surfaced errors as typed events the UI can
//! route, and (when an audience grant JWT is available) called the
//! Principal Server `session-grant/exchange` endpoint to mint the
//! audience-scoped session.
//!
//! The split between [`process_callback`] (full async happy path,
//! includes I/O) and the pure helpers [`validate_callback_state`],
//! [`assemble_audience_grant_request`] keeps the unit tests free of a
//! reqwest client. The integration tests in `tests/oidc_callback_*.rs`
//! exercise the network surface against a `wiremock` IdP.

use anyhow::Context;

use crate::{
    api::{ContrixApi, SessionGrantIntrospectionProof},
    coauth::{
        CoauthApi, OidcTokenResponse, PersistedOidcScaffold,
        build_session_grant_introspection_proof_bundle, extract_authorization_code_from_callback,
        extract_error_description_from_callback, extract_error_from_callback,
        extract_state_from_callback,
    },
    local_state::{LocalStateStore, OidcTokenBundle},
    models::DevLoginResponse,
};

/// Inputs required to drive a callback through to a persisted token
/// bundle and (optionally) an audience-grant exchange.
///
/// `audience_grant_jwt` is `None` until the IdP-issued `id_token` /
/// access_token has been presented to coauth's `/contrix/session-grants`
/// endpoint and a per-audience grant JWT has been minted. Callers that
/// already hold an audience grant (e.g. coauth's
/// `CoauthLoginResponse::session_grant`) can pass it straight through;
/// the orchestrator then signs an introspection proof with the device
/// signing key and POSTs the grant to the principal-server.
pub struct CallbackProcessRequest<'a> {
    pub callback_url: &'a str,
    pub scaffold: &'a PersistedOidcScaffold,
    pub coauth_api: &'a CoauthApi,
    /// Token-endpoint URL resolved from OIDC discovery. The scaffold
    /// stores `auth_server_url` (the issuer base) but not the token
    /// endpoint per se, so the caller passes it in explicitly.
    pub token_endpoint: &'a str,
    /// Public client_id registered with the IdP for this redirect URI.
    pub client_id: &'a str,
    /// Optional audience-grant exchange leg. When present, the
    /// orchestrator POSTs the grant to the principal server after the
    /// IdP code-exchange succeeds.
    pub audience_grant: Option<AudienceGrantExchange<'a>>,
}

/// Inputs for the audience-grant exchange leg. The orchestrator signs
/// an introspection proof with `device_signing_key` so the principal
/// server can verify the grant binding without a round-trip to coauth
/// (per `cx.session_grant.introspection_proof.v1`).
pub struct AudienceGrantExchange<'a> {
    pub principal_api: &'a ContrixApi,
    pub session_grant_exchange_path: &'a str,
    pub grant_id: &'a str,
    pub grant_jwt: &'a str,
    pub audience: &'a str,
    pub principal_did: &'a str,
    pub device_id: &'a str,
    pub device_signing_key: &'a ed25519_dalek::SigningKey,
}

/// Outcome of [`process_callback`]. UI callers route on the variant —
/// `Completed` is the happy path, the rest map to typed UI errors.
#[derive(Debug)]
pub enum CallbackOutcome {
    /// Full happy path: token bundle persisted; audience grant exchanged
    /// (if requested).
    Completed {
        token_bundle: OidcTokenBundle,
        audience_session: Option<DevLoginResponse>,
    },
    /// IdP returned `error=…` in the callback URL (user denied consent,
    /// IdP-side policy failure, etc.). `description` carries the human
    /// `error_description` if present.
    IdpError {
        error: String,
        description: Option<String>,
    },
    /// State mismatch — the callback's `state` did not match the
    /// scaffold's `expected_state`. This is a CSRF-protection failure;
    /// the UI must NOT proceed with the exchange.
    StateMismatch {
        expected: String,
        observed: Option<String>,
    },
    /// Code exchange or audience-grant exchange failed downstream.
    Failed {
        stage: &'static str,
        error: anyhow::Error,
    },
}

/// Pure CSRF-state validation. Returns `Ok` only when the callback
/// carries a `state` parameter and it byte-equals the scaffold's
/// `expected_state`. The `Option<String>` in the `Err` payload is the
/// observed value (`None` when the callback URL had no `state` at all).
pub fn validate_callback_state(
    callback_url: &str,
    expected_state: &str,
) -> Result<(), Option<String>> {
    let observed = extract_state_from_callback(callback_url).ok().flatten();
    match observed.as_deref() {
        Some(value) if value == expected_state => Ok(()),
        other => Err(other.map(ToOwned::to_owned)),
    }
}

/// Pure inspection of the callback URL: returns `Some((error, description))`
/// when the IdP redirected with an error response, `None` otherwise.
/// Used by [`process_callback`] before the state check so a user-cancel
/// surfaces as `IdpError` rather than `StateMismatch` (cancellations
/// often omit `state`).
pub fn extract_callback_error(callback_url: &str) -> Option<(String, Option<String>)> {
    let error = extract_error_from_callback(callback_url).ok().flatten()?;
    let description = extract_error_description_from_callback(callback_url)
        .ok()
        .flatten();
    Some((error, description))
}

/// Build the [`SessionGrantIntrospectionProof`] envelope the principal
/// server requires when accepting an audience grant. Pure helper so
/// callers that want to assemble the body themselves (e.g. for a custom
/// HTTP client) can reuse the proof construction without going through
/// [`process_callback`].
pub fn assemble_audience_grant_request(
    grant_id: &str,
    grant_jwt: &str,
    audience: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<SessionGrantIntrospectionProof> {
    build_session_grant_introspection_proof_bundle(grant_id, grant_jwt, audience, signing_key)
}

/// Round 27 (C32.6): full callback → token-bundle → audience-grant
/// pipeline. Mutates `state_store` in place — successful returns mean
/// the persisted [`OidcTokenBundle`] has already been written via
/// [`LocalStateStore::set_oidc_tokens`].
///
/// The audience-grant leg is opt-in (`request.audience_grant`); when
/// `None` the orchestrator stops after persisting the token bundle and
/// returns `Completed { audience_session: None, .. }`.
pub async fn process_callback(
    request: CallbackProcessRequest<'_>,
    state_store: &mut LocalStateStore,
) -> CallbackOutcome {
    // 1. IdP-side errors take precedence — the user may have cancelled
    //    or the IdP may have rejected the request. We don't try to be
    //    clever about partial-state recoveries; just surface the error.
    if let Some((error, description)) = extract_callback_error(request.callback_url) {
        return CallbackOutcome::IdpError { error, description };
    }
    // 2. CSRF state check.
    if let Err(observed) =
        validate_callback_state(request.callback_url, &request.scaffold.expected_state)
    {
        return CallbackOutcome::StateMismatch {
            expected: request.scaffold.expected_state.clone(),
            observed,
        };
    }
    // 3. Pull the authorization code out of the callback.
    let code = match extract_authorization_code_from_callback(request.callback_url)
        .context("extract authorization_code from callback")
    {
        Ok(value) => value,
        Err(error) => {
            return CallbackOutcome::Failed {
                stage: "extract_authorization_code",
                error,
            };
        }
    };
    // 4. Exchange code → tokens at the IdP token endpoint.
    let token_response: OidcTokenResponse = match request
        .coauth_api
        .exchange_pkce_code_for_tokens(
            request.token_endpoint,
            request.client_id,
            &code,
            &request.scaffold.code_verifier,
            &request.scaffold.callback_uri,
        )
        .await
    {
        Ok(value) => value,
        Err(error) => {
            return CallbackOutcome::Failed {
                stage: "exchange_pkce_code_for_tokens",
                error,
            };
        }
    };
    // 5. Persist the token bundle. The `audience_hint` is the
    //    principal-audience the scaffold was minted for — the bundle
    //    records it so the 401-retry path in `oidc_lifecycle` knows
    //    which audience to refresh against.
    let audience_hint = if request.scaffold.principal_audience.is_empty() {
        None
    } else {
        Some(request.scaffold.principal_audience.as_str())
    };
    let token_bundle = token_response.to_persisted_bundle(audience_hint);
    state_store.set_oidc_tokens(Some(token_bundle.clone()));

    // 6. Audience-grant exchange (optional).
    let audience_session = match request.audience_grant {
        Some(audience_grant) => {
            let proof = match assemble_audience_grant_request(
                audience_grant.grant_id,
                audience_grant.grant_jwt,
                audience_grant.audience,
                audience_grant.device_signing_key,
            ) {
                Ok(value) => value,
                Err(error) => {
                    return CallbackOutcome::Failed {
                        stage: "assemble_audience_grant_request",
                        error,
                    };
                }
            };
            match audience_grant
                .principal_api
                .exchange_session_grant_at_with_proof(
                    audience_grant.session_grant_exchange_path,
                    audience_grant.grant_jwt,
                    audience_grant.principal_did,
                    audience_grant.device_id,
                    Some(&proof),
                )
                .await
            {
                Ok(response) => Some(response),
                Err(error) => {
                    return CallbackOutcome::Failed {
                        stage: "exchange_session_grant",
                        error,
                    };
                }
            }
        }
        None => None,
    };

    CallbackOutcome::Completed {
        token_bundle,
        audience_session,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scaffold(expected_state: &str) -> PersistedOidcScaffold {
        PersistedOidcScaffold {
            expected_state: expected_state.to_owned(),
            code_verifier: "verifier-bytes".to_owned(),
            auth_server_url: "https://issuer.example".to_owned(),
            principal_server_url: "https://principal.example".to_owned(),
            principal_actor_did: "did:web:alice.example".to_owned(),
            device_id: "device-1".to_owned(),
            principal_audience: "https://principal.example/api".to_owned(),
            callback_uri: "urn:yougen:oauth:callback".to_owned(),
            authorize_url: "https://issuer.example/auth?...".to_owned(),
        }
    }

    #[test]
    fn validate_callback_state_accepts_matching_state() {
        let url = "urn:yougen:oauth:callback?code=abc&state=expected-1";
        validate_callback_state(url, "expected-1").expect("matching state must pass");
    }

    #[test]
    fn validate_callback_state_rejects_missing_state() {
        let url = "urn:yougen:oauth:callback?code=abc";
        let err = validate_callback_state(url, "expected-1").unwrap_err();
        assert!(err.is_none(), "missing state must surface as None observed");
    }

    #[test]
    fn validate_callback_state_rejects_drifted_state() {
        let url = "urn:yougen:oauth:callback?code=abc&state=other";
        let err = validate_callback_state(url, "expected-1").unwrap_err();
        assert_eq!(err.as_deref(), Some("other"));
    }

    #[test]
    fn validate_callback_state_rejects_unparseable_url() {
        // No scheme — Url::parse fails. Treat as missing state.
        let err = validate_callback_state("not a url", "x").unwrap_err();
        assert!(err.is_none());
    }

    #[test]
    fn extract_callback_error_returns_none_when_clean() {
        let url = "urn:yougen:oauth:callback?code=abc&state=s";
        assert!(extract_callback_error(url).is_none());
    }

    #[test]
    fn extract_callback_error_returns_idp_error_with_description() {
        let url =
            "urn:yougen:oauth:callback?error=access_denied&error_description=user%20cancelled";
        let (error, description) = extract_callback_error(url).expect("error present");
        assert_eq!(error, "access_denied");
        assert_eq!(description.as_deref(), Some("user cancelled"));
    }

    #[test]
    fn extract_callback_error_handles_error_without_description() {
        let url = "urn:yougen:oauth:callback?error=server_error";
        let (error, description) = extract_callback_error(url).expect("error present");
        assert_eq!(error, "server_error");
        assert!(description.is_none());
    }

    #[test]
    fn assemble_audience_grant_request_signs_canonical_proof() {
        // The signing path is the same primitive `coauth.rs` already
        // tests for canonical claims; here we just confirm the wrapper
        // builds a non-empty proof envelope with a syntactically-valid
        // compact JWS (3 segments).
        let signing = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let proof = assemble_audience_grant_request(
            "01HABC456",
            "eyJ.opaque-grant.jwt",
            "https://principal.example/api",
            &signing,
        )
        .unwrap();
        assert!(!proof.challenge.is_empty(), "challenge must be present");
        let parts: Vec<&str> = proof.proof_jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "proof_jwt must be a compact JWS");
    }

    #[test]
    fn callback_outcome_variants_construct_without_panic() {
        // Smoke test for the typed surface — pinning the variant set so
        // a future refactor that drops one fails the build instead of
        // silently regressing the UI router contract.
        let _ = CallbackOutcome::IdpError {
            error: "denied".into(),
            description: None,
        };
        let _ = CallbackOutcome::StateMismatch {
            expected: "a".into(),
            observed: Some("b".into()),
        };
        let _ = CallbackOutcome::Failed {
            stage: "test",
            error: anyhow::anyhow!("boom"),
        };
        let _ = scaffold("x");
    }

    #[test]
    fn scaffold_round_trips_through_serde_json() {
        // Regression: the scaffold is persisted to localStorage as JSON,
        // so any field rename must update the serde shape too. Round-trip
        // through serde_json to pin the wire shape.
        let s = scaffold("expected-2");
        let encoded = serde_json::to_string(&s).unwrap();
        let decoded: PersistedOidcScaffold = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.expected_state, s.expected_state);
        assert_eq!(decoded.code_verifier, s.code_verifier);
        assert_eq!(decoded.principal_audience, s.principal_audience);
        assert_eq!(decoded.callback_uri, s.callback_uri);
    }
}
