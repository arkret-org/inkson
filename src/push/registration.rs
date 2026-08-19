//! Chime-driven push registration orchestrator.
//!
//! `crate::push` has long shipped the building blocks (token source, register
//! request builder, registration-state persistence helper, VAPID describe
//! fetch). What was missing was a *single* end-to-end orchestrator that
//! resolves a real platform token via the active [`PushTokenProvider`],
//! posts the register-device request through the chime [`ArkretPushClient`]
//! pointed at the floria notify gateway, and returns the resulting
//! [`PushRegistrationState`] for the caller to persist through its live store
//! handle.
//!
//! The orchestrator deliberately does **not** silently fall back to a
//! placeholder push key. If the active provider declines (or none is
//! installed), the orchestrator returns
//! [`PushRegistrationError::NoRealToken`]. Tests / dev sandboxes that want
//! placeholder behaviour keep using `crate::push::build_register_request`
//! directly, which is still gated by `ensure_production_register_request`.
//!
//! ## Wiring sketch
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use inkson::push::{set_push_token_provider, FcmPushTokenProvider};
//! use inkson::push_registration::{register_via_chime, RegisterContext};
//!
//! set_push_token_provider(Arc::new(FcmPushTokenProvider));
//! let outcome = register_via_chime(RegisterContext {
//!     principal_server_url: "https://principal.example".into(),
//!     floria_gateway_url: "https://push.example/_arkret/edge/push/notify".into(),
//!     device_id: "dev-inkson".into(),
//!     principal_id: Some("did:web:alice.example".into()),
//!     authorization_credential: Some(api_token),
//!     session_grant: None,
//!     active_circle_id: None,
//! }, &local_state_store).await?;
//! ```

use chime::{
    ArkretPushClient, ChimePushRegisterDeviceOutcome, ChimePushRegisterDeviceRequest,
    ChimePushUnregisterDeviceOutcome, GatewayBinding, PushDeviceConfig, PushGatewayType,
    PushPreferences, PushRegistrationState, build_register_device_request,
};

use crate::identity::account_auth::{
    build_session_grant_introspection_proof_bundle, session_grant_signing_key_from_pem,
};
use crate::identity::session_refresh::grant_matches_principal_server;
use crate::push::{
    ensure_production_register_request, floria_gateway_url, registration_state_from_response,
};
use crate::state::PersistedSessionGrant;

/// Errors the orchestrator surfaces back to the UI / login strand.
#[derive(Debug, thiserror::Error)]
pub enum PushRegistrationError {
    /// No `PushTokenProvider` installed, or the installed one declined
    /// (permission denied, browser closed, FCM token not yet available).
    /// The caller should surface a "notifications disabled" UX rather
    /// than retrying immediately.
    #[error("no real push token available for platform `{platform}`: {reason}")]
    NoRealToken {
        platform: &'static str,
        reason: String,
    },
    /// The provider returned a token that still trips
    /// [`ensure_production_register_request`] (e.g. matches the placeholder
    /// markers). Treated as a hard fail-closed — we never want to ship a
    /// dev marker into a real gateway.
    #[error("rejected placeholder token: {0}")]
    PlaceholderTokenRejected(String),
    /// Building the register-device wire body failed (validation,
    /// gateway URL malformed, etc.).
    #[error("build register request failed: {0}")]
    BuildRequest(anyhow::Error),
    /// chime SDK reported a transport / HTTP failure.
    #[error("chime transport failure: {0}")]
    Transport(String),
    /// No coauth session grant is available to populate
    /// `X-Arkret-Session-Grant`.
    #[error("no coauth session grant available for chime registration")]
    MissingSessionGrant,
    /// The persisted grant is not usable for this registration.
    #[error("coauth session grant cannot be used for chime: {reason}")]
    SessionGrantMismatch { reason: String },
    /// The persisted grant exists but its proof material could not be minted.
    #[error("could not mint chime session-grant proof: {0}")]
    SessionGrantProof(anyhow::Error),
    /// An unexpected internal error.
    #[error("push registration failed: {0}")]
    Other(anyhow::Error),
}

/// Inputs to [`register_via_chime`]. Tracked as a struct (vs a 6-arg
/// fn) so call sites stay readable when `principal_id` /
/// `authorization_credential`
/// flip from `None` to `Some` after coauth lands.
#[derive(Clone, Debug)]
pub struct RegisterContext {
    /// Principal server base URL — the chime client posts the
    /// register-device request here. The push gateway URL itself
    /// (floria) goes in the request body's `push_gateway` field.
    pub principal_server_url: String,
    /// Floria gateway notify URL. Stamped into the register request as
    /// `push_gateway`. Falls back to [`floria_gateway_url`] (which is
    /// env-driven and resolves to an empty no-op in release builds
    /// without `INKSON_FLORIA_URL` set) when empty.
    pub floria_gateway_url: String,
    /// Device id (e.g. `dev_inkson` or `did:web:alice#device-phone`).
    pub device_id: String,
    /// Owning actor DID. `None` for the pre-login boot path; populated
    /// once OIDC / coauth resolves.
    pub principal_id: Option<String>,
    /// API authorization credential (chime client posts it in the standard
    /// `Authorization: Bearer ...` HTTP scheme).
    pub authorization_credential: Option<String>,
    /// X-Arkret-Session-Grant header (coauth-issued grant). `None`
    /// means inkson loads the persisted coauth session grant from
    /// `LocalStateStore`, mints the matching introspection proof headers,
    /// and fails closed if no grant is available.
    pub session_grant: Option<String>,
    /// AKP-0007 P3B.2.9 — active Circle id (when the registration
    /// originates from a Circle-scoped sidebar deep-link or the
    /// current Strand's `scope_circle_id`). `None` falls back to the
    /// historical Realm-wide subscription. Forwarded into the chime
    /// request via [`build_request`].
    pub active_circle_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct UnregisterContext {
    pub principal_server_url: String,
    pub device_id: String,
    pub authorization_credential: Option<String>,
    pub session_grant: Option<String>,
}

/// Outcome of a successful chime-driven registration. The caller owns
/// persistence so Dioxus UI paths can write through the live state handle
/// after the network await.
#[derive(Clone, Debug)]
pub struct RegisterOutcome {
    pub state: PushRegistrationState,
    pub response: ChimePushRegisterDeviceOutcome,
}

#[derive(Clone, Debug)]
struct ChimeSessionGrantHeaders {
    grant_jwt: String,
    challenge: Option<String>,
    proof_jwt: Option<String>,
}

/// Resolve a real token via the installed `PushTokenProvider`, build a
/// chime register-device request, post it through the chime SDK, and
/// return the resulting `PushRegistrationState` for the caller to persist.
///
/// On non-wasm targets the chime client uses reqwest+rustls+tokio. On
/// wasm32 the same client routes through reqwest's fetch-backed wasm32
/// backend (no rustls, no tokio runtime), so the browser build drives a
/// real HTTP POST to the principal server.
pub async fn register_via_chime(
    mut ctx: RegisterContext,
    persisted_grant: Option<PersistedSessionGrant>,
) -> Result<RegisterOutcome, PushRegistrationError> {
    let session_grant = resolve_chime_session_grant(&mut ctx, persisted_grant.as_ref())?;
    let token = resolve_real_token(&ctx).await?;
    let request = build_request(&ctx, &token)?;
    ensure_production_register_request(&request)
        .map_err(|err| PushRegistrationError::PlaceholderTokenRejected(err.to_string()))?;

    let client = chime_client(
        &ctx.principal_server_url,
        ctx.authorization_credential.as_deref(),
        &session_grant,
    )?;

    let response = client
        .register_device_with_request(&request, request.idempotency_key.as_deref(), None)
        .await
        .map_err(|err| PushRegistrationError::Transport(err.to_string()))?;

    let state = registration_state_from_response(&request, &response.body);

    Ok(RegisterOutcome {
        state,
        response: response.body,
    })
}

pub async fn unregister_via_chime(
    ctx: UnregisterContext,
    persisted_grant: Option<PersistedSessionGrant>,
    registration: Option<chime::PushRegistrationState>,
) -> Result<ChimePushUnregisterDeviceOutcome, PushRegistrationError> {
    let mut grant_ctx = RegisterContext {
        principal_server_url: ctx.principal_server_url.clone(),
        floria_gateway_url: String::new(),
        device_id: ctx.device_id.clone(),
        principal_id: None,
        authorization_credential: ctx.authorization_credential.clone(),
        session_grant: ctx.session_grant.clone(),
        active_circle_id: None,
    };
    let session_grant = resolve_chime_session_grant(&mut grant_ctx, persisted_grant.as_ref())?;
    let request = crate::push::build_unregister_request(&ctx.device_id, registration.as_ref())
        .map_err(PushRegistrationError::BuildRequest)?;
    let client = chime_client(
        &ctx.principal_server_url,
        ctx.authorization_credential.as_deref(),
        &session_grant,
    )?;
    let response = client
        .unregister_device_with_request(&request, request.idempotency_key.as_deref(), None)
        .await
        .map_err(|err| PushRegistrationError::Transport(err.to_string()))?;
    Ok(response.body)
}

fn chime_client(
    principal_server_url: &str,
    authorization_credential: Option<&str>,
    session_grant: &ChimeSessionGrantHeaders,
) -> Result<ArkretPushClient, PushRegistrationError> {
    let mut client = ArkretPushClient::new(principal_server_url).with_required_session_grant(true);
    if let Some(token) = authorization_credential {
        client = client.with_bearer_token(token);
    }
    client = client
        .with_session_grant(&session_grant.grant_jwt)
        .map_err(|err| PushRegistrationError::Transport(err.to_string()))?;
    if let (Some(challenge), Some(proof_jwt)) = (
        session_grant.challenge.as_deref(),
        session_grant.proof_jwt.as_deref(),
    ) {
        client = client
            .with_header("X-Arkret-Session-Grant-Challenge", challenge)
            .and_then(|client| client.with_header("X-Arkret-Session-Grant-Proof", proof_jwt))
            .map_err(|err| PushRegistrationError::Transport(err.to_string()))?;
    }
    Ok(client)
}

fn resolve_chime_session_grant(
    ctx: &mut RegisterContext,
    persisted_grant: Option<&PersistedSessionGrant>,
) -> Result<ChimeSessionGrantHeaders, PushRegistrationError> {
    if let Some(grant_jwt) = ctx
        .session_grant
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(ChimeSessionGrantHeaders {
            grant_jwt: grant_jwt.to_owned(),
            challenge: None,
            proof_jwt: None,
        });
    }

    let grant = persisted_grant
        .cloned()
        .ok_or(PushRegistrationError::MissingSessionGrant)?;
    if !grant_matches_principal_server(&grant, &ctx.principal_server_url) {
        return Err(PushRegistrationError::SessionGrantMismatch {
            reason: "persisted grant belongs to a different principal server".to_owned(),
        });
    }
    if grant.device_id != ctx.device_id {
        return Err(PushRegistrationError::SessionGrantMismatch {
            reason: format!(
                "persisted grant device_id {} does not match {}",
                grant.device_id, ctx.device_id
            ),
        });
    }
    if ctx.principal_id.is_none() {
        ctx.principal_id = Some(grant.principal_id.clone());
    }

    let signing_key = session_grant_signing_key_from_pem(&grant.session_private_key_pem)
        .map_err(PushRegistrationError::SessionGrantProof)?;
    let proof = build_session_grant_introspection_proof_bundle(
        &grant.grant_id,
        &grant.grant_jwt,
        &grant.audience,
        &signing_key,
    )
    .map_err(PushRegistrationError::SessionGrantProof)?;

    Ok(ChimeSessionGrantHeaders {
        grant_jwt: grant.grant_jwt,
        challenge: Some(proof.challenge),
        proof_jwt: Some(proof.proof_jwt),
    })
}

#[cfg(not(target_arch = "wasm32"))]
async fn resolve_real_token(_ctx: &RegisterContext) -> Result<String, PushRegistrationError> {
    use crate::push::{push_token_provider, resolve_provider_push_token};

    let Some(provider) = push_token_provider() else {
        return Err(PushRegistrationError::NoRealToken {
            platform: "desktop",
            reason: "no PushTokenProvider installed via set_push_token_provider".to_owned(),
        });
    };
    let platform = provider.platform();

    match resolve_provider_push_token(None) {
        Ok(Some(token)) if !token.is_empty() => Ok(token),
        Ok(_) => Err(PushRegistrationError::NoRealToken {
            platform,
            reason: "provider returned no token (permission denied / not yet ready)".to_owned(),
        }),
        Err(err) => Err(PushRegistrationError::NoRealToken {
            platform,
            reason: err.to_string(),
        }),
    }
}

#[cfg(target_arch = "wasm32")]
async fn resolve_real_token(ctx: &RegisterContext) -> Result<String, PushRegistrationError> {
    use crate::push::{
        fetch_vapid_application_server_key, push_token_provider, resolve_provider_push_token,
    };

    let Some(provider) = push_token_provider() else {
        return Err(PushRegistrationError::NoRealToken {
            platform: "web",
            reason: "no PushTokenProvider installed via set_push_token_provider".to_owned(),
        });
    };
    let platform = provider.platform();

    let vapid = fetch_vapid_application_server_key(&ctx.floria_gateway_url)
        .await
        .ok()
        .flatten();

    match resolve_provider_push_token(vapid.as_deref()).await {
        Ok(Some(token)) if !token.is_empty() => Ok(token),
        Ok(_) => Err(PushRegistrationError::NoRealToken {
            platform,
            reason: "provider returned no token (permission denied / not yet ready)".to_owned(),
        }),
        Err(err) => Err(PushRegistrationError::NoRealToken {
            platform,
            reason: err.to_string(),
        }),
    }
}

fn build_request(
    ctx: &RegisterContext,
    push_key: &str,
) -> Result<ChimePushRegisterDeviceRequest, PushRegistrationError> {
    let push_gateway = if ctx.floria_gateway_url.trim().is_empty() {
        floria_gateway_url()
    } else {
        ctx.floria_gateway_url.clone()
    };
    let binding = GatewayBinding::new(PushGatewayType::Standard, push_gateway);
    // AKP-0007 P3B.2.9 — forward the active Circle id (when present)
    // into the chime subscribe request by stamping it onto the
    // idempotency key, so re-registration after a Circle switch
    // produces a distinct subscription record. When no Circle is
    // active the build falls back to the prior Realm-wide
    // subscription behaviour. (The former `muted_circle_ids`
    // preference field was persisted-only and never consumed by the
    // request builder; chime removed it.)
    let active_circle = ctx
        .active_circle_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let prefs = PushPreferences {
        enabled: true,
        allow_insecure_loopback_push_gateway: true,
        gateways: vec![binding.clone()],
        ..Default::default()
    };
    let idempotency_key = match active_circle {
        Some(circle) => format!("inkson-push-register-{}-{circle}", ctx.device_id),
        None => format!("inkson-push-register-{}", ctx.device_id),
    };
    let platform = current_platform_str();
    let config = PushDeviceConfig {
        principal_id: ctx.principal_id.as_deref(),
        device_id: ctx.device_id.as_str(),
        push_key: Some(push_key),
        platform: Some(platform),
        app_id: Some("inkson"),
        domestic_app_id: None,
        registration_id: None,
        display_name: Some("inkson"),
        idempotency_key: Some(idempotency_key.as_str()),
        request_id: None,
        proof: None,
    };
    build_register_device_request(&config, &binding, &prefs).map_err(|err| {
        PushRegistrationError::BuildRequest(anyhow::anyhow!("build register-device request: {err}"))
    })
}

#[cfg(target_arch = "wasm32")]
fn current_platform_str() -> &'static str {
    "web"
}

#[cfg(not(target_arch = "wasm32"))]
fn current_platform_str() -> &'static str {
    "desktop"
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::{Duration, Utc};
    use ed25519_dalek::pkcs8::EncodePrivateKey as _;

    use super::*;
    use crate::push::{FcmPushTokenProvider, PushTokenProvider};
    use crate::state::PersistedSessionGrant;
    // YOU-05-010: shared hermetic state-store fixture from `local_state`.
    use crate::state::isolated_store_for_tests as isolated_store;

    /// Test-only token source that hands back a fixed real-looking
    /// token. Lets us exercise the full orchestrator without wiring a
    /// real OS keychain or browser pushManager.
    #[derive(Clone, Debug)]
    struct FixedTokenProvider {
        token: String,
        platform: &'static str,
    }

    impl PushTokenProvider for FixedTokenProvider {
        fn platform(&self) -> &'static str {
            self.platform
        }

        #[cfg(not(target_arch = "wasm32"))]
        fn subscribe(&self, _vapid: Option<&str>) -> anyhow::Result<Option<String>> {
            Ok(Some(self.token.clone()))
        }

        #[cfg(target_arch = "wasm32")]
        fn subscribe<'a>(
            &'a self,
            _vapid: Option<&'a str>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Option<String>>> + 'a>>
        {
            let token = self.token.clone();
            Box::pin(async move { Ok(Some(token)) })
        }
    }

    fn ctx(device: &str) -> RegisterContext {
        RegisterContext {
            principal_server_url: "https://principal.example".to_owned(),
            floria_gateway_url: "https://push.example/_arkret/edge/push/notify".to_owned(),
            device_id: device.to_owned(),
            principal_id: Some("did:web:alice.example".to_owned()),
            authorization_credential: Some("session-secret".to_owned()),
            session_grant: None,
            active_circle_id: None,
        }
    }

    fn persisted_grant(device: &str) -> PersistedSessionGrant {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let pem = signing
            .to_pkcs8_pem(Default::default())
            .expect("encode session grant key")
            .to_string();
        PersistedSessionGrant {
            grant_jwt: "header.payload.signature".to_owned(),
            session_private_key_pem: pem,
            grant_id: "ak:grant:push-local".to_owned(),
            audience: "did:web:principal.example".to_owned(),
            principal_id: "did:web:alice.example".to_owned(),
            device_id: device.to_owned(),
            principal_server_url: "https://principal.example/".to_owned(),
            grant_expires_at: Some(Utc::now() + Duration::hours(1)),
            stored_at: Utc::now(),
        }
    }

    #[test]
    fn build_request_uses_floria_url_as_push_gateway() {
        let request = build_request(&ctx("dev_inkson"), "apns:01234567890abcdef").expect("build");
        assert_eq!(request.device_id, "dev_inkson");
        assert_eq!(request.push_key, "apns:01234567890abcdef");
        assert_eq!(
            request.push_gateway,
            "https://push.example/_arkret/edge/push/notify"
        );
        assert_eq!(request.app_id.as_deref(), Some("inkson"));
        assert_eq!(request.platform.as_deref(), Some(current_platform_str()));
    }

    #[test]
    fn build_request_falls_back_to_runtime_floria_gateway_when_empty() {
        let mut c = ctx("dev_inkson");
        c.floria_gateway_url = "   ".to_owned();
        let request = build_request(&c, "apns:01234567890abcdef").expect("build");
        assert_eq!(request.push_gateway, floria_gateway_url());
    }

    #[test]
    fn build_request_stamps_active_circle_into_idempotency_key() {
        let mut c = ctx("dev_inkson");
        c.active_circle_id = Some("ak:circle:opsroom".to_owned());
        let request = build_request(&c, "apns:01234567890abcdef").expect("build");
        let key = request.idempotency_key.as_deref().expect("idempotency_key");
        assert!(key.contains("ak:circle:opsroom"), "idempotency_key={key}");
    }

    #[test]
    fn resolves_persisted_grant_into_chime_headers() {
        let mut store = isolated_store("grant-headers");
        store.set_session_grant(Some(persisted_grant("dev_inkson")));
        let mut context = ctx("dev_inkson");
        context.principal_id = None;

        let headers = resolve_chime_session_grant(&mut context, store.session_grant().as_ref())
            .expect("grant headers");

        assert_eq!(headers.grant_jwt, "header.payload.signature");
        assert!(headers.challenge.as_deref().is_some_and(|v| !v.is_empty()));
        assert!(headers.proof_jwt.as_deref().is_some_and(|v| !v.is_empty()));
        assert_eq!(
            context.principal_id.as_deref(),
            Some("did:web:alice.example")
        );
    }

    #[test]
    fn missing_grant_fails_closed_before_register() {
        let mut context = ctx("dev_inkson");
        let store = isolated_store("missing-grant");
        let err =
            resolve_chime_session_grant(&mut context, store.session_grant().as_ref()).unwrap_err();
        assert!(matches!(err, PushRegistrationError::MissingSessionGrant));
    }

    #[test]
    fn placeholder_resolved_token_is_rejected_by_guard() {
        // Even if a buggy provider hands back a placeholder marker, the
        // production guard MUST reject it before we POST.
        let request =
            build_request(&ctx("dev_inkson"), "desktop:inkson-dev-placeholder-token").unwrap();
        let err = ensure_production_register_request(&request).unwrap_err();
        assert!(err.to_string().contains("placeholder"));
    }

    #[test]
    fn fcm_provider_advertises_correct_platform_via_trait_object() {
        // Sanity: the orchestrator depends on the trait surface, so a
        // concrete provider must satisfy `Send + Sync` and expose its
        // platform without panicking.
        let provider: Arc<dyn PushTokenProvider> = Arc::new(FcmPushTokenProvider);
        assert_eq!(provider.platform(), "fcm");
    }

    #[test]
    fn fixed_provider_subscribe_returns_token_native() {
        // Native test only — the wasm `subscribe` returns an async
        // future that requires a runtime to drive.
        #[cfg(not(target_arch = "wasm32"))]
        {
            let provider = FixedTokenProvider {
                token: "fcm:real-token".to_owned(),
                platform: "fcm",
            };
            let token = provider.subscribe(None).unwrap().unwrap();
            assert_eq!(token, "fcm:real-token");
        }
    }
}
