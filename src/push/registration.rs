//! Chime-driven push registration orchestrator.
//!
//! `crate::push` has long shipped the building blocks (token source, register
//! request builder, registration-state persistence helper, VAPID describe
//! fetch). What was missing was a *single* end-to-end orchestrator that
//! resolves a real platform token via the active [`PushTokenProvider`],
//! posts the register-device request through the chime [`ContrixPushClient`]
//! pointed at the floria notify gateway, and persists the resulting
//! [`PushRegistrationState`] to [`LocalStateStore`].
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
//! use yougen::push::{set_push_token_provider, FcmPushTokenProvider};
//! use yougen::push_registration::{register_via_chime, RegisterContext};
//!
//! set_push_token_provider(Arc::new(FcmPushTokenProvider));
//! let outcome = register_via_chime(RegisterContext {
//!     principal_server_url: "https://principal.example".into(),
//!     floria_gateway_url: "https://push.example/api/v1/push/notify".into(),
//!     device_id: "dev-yougen".into(),
//!     principal_did: Some("did:web:alice.example".into()),
//!     bearer_token: Some(api_token),
//!     session_grant: None,
//!     active_circle_id: None,
//! }, &mut local_state_store).await?;
//! ```

use chime::{
    ContrixPushClient, GatewayBinding, PushDeviceConfig, PushGatewayType, PushPreferences,
    PushRegistrationState, RegisterDeviceRequest, RegisterDeviceResponse,
    build_register_device_request,
};

use crate::coauth::{
    build_session_grant_introspection_proof_bundle, session_grant_signing_key_from_pem,
};
use crate::local_state::LocalStateStore;
use crate::push::{
    ensure_production_register_request, floria_gateway_url, registration_state_from_response,
};
use crate::session_refresh::grant_matches_principal_server;

/// Errors the orchestrator surfaces back to the UI / login flow.
#[derive(Debug)]
pub enum PushRegistrationError {
    /// No `PushTokenProvider` installed, or the installed one declined
    /// (permission denied, browser closed, FCM token not yet available).
    /// The caller should surface a "notifications disabled" UX rather
    /// than retrying immediately.
    NoRealToken {
        platform: &'static str,
        reason: String,
    },
    /// The provider returned a token that still trips
    /// [`ensure_production_register_request`] (e.g. matches the placeholder
    /// markers). Treated as a hard fail-closed — we never want to ship a
    /// dev marker into a real gateway.
    PlaceholderTokenRejected(String),
    /// Building the register-device wire body failed (validation,
    /// gateway URL malformed, etc.).
    BuildRequest(anyhow::Error),
    /// chime SDK reported a transport / HTTP failure.
    Transport(String),
    /// No coauth session grant is available to populate
    /// `X-Contrix-Session-Grant`.
    MissingSessionGrant,
    /// The persisted grant is not usable for this registration.
    SessionGrantMismatch { reason: String },
    /// The persisted grant exists but its proof material could not be minted.
    SessionGrantProof(anyhow::Error),
    /// An unexpected internal error.
    Other(anyhow::Error),
}

impl std::fmt::Display for PushRegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRealToken { platform, reason } => write!(
                f,
                "no real push token available for platform `{platform}`: {reason}"
            ),
            Self::PlaceholderTokenRejected(msg) => {
                write!(f, "rejected placeholder token: {msg}")
            }
            Self::BuildRequest(err) => write!(f, "build register request failed: {err}"),
            Self::Transport(msg) => write!(f, "chime transport failure: {msg}"),
            Self::MissingSessionGrant => {
                write!(
                    f,
                    "no coauth session grant available for chime registration"
                )
            }
            Self::SessionGrantMismatch { reason } => {
                write!(f, "coauth session grant cannot be used for chime: {reason}")
            }
            Self::SessionGrantProof(err) => {
                write!(f, "could not mint chime session-grant proof: {err}")
            }
            Self::Other(err) => write!(f, "push registration failed: {err}"),
        }
    }
}

impl std::error::Error for PushRegistrationError {}

/// Inputs to [`register_via_chime`]. Tracked as a struct (vs a 6-arg
/// fn) so call sites stay readable when `principal_did` / `bearer_token`
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
    /// without `YOUGEN_FLORIA_URL` set) when empty.
    pub floria_gateway_url: String,
    /// Device id (e.g. `dev_yougen` or `did:web:alice#device-phone`).
    pub device_id: String,
    /// Owning actor DID. `None` for the pre-login boot path; populated
    /// once OIDC / coauth resolves.
    pub principal_did: Option<String>,
    /// API access token (chime client posts `Authorization: Bearer …`).
    pub bearer_token: Option<String>,
    /// X-Contrix-Session-Grant header (coauth-issued grant). `None`
    /// means yougen loads the persisted coauth session grant from
    /// `LocalStateStore`, mints the matching introspection proof headers,
    /// and fails closed if no grant is available.
    pub session_grant: Option<String>,
    /// CXP-0007 P3B.2.9 — active Circle id (when the registration
    /// originates from a Circle-scoped sidebar deep-link or the
    /// current Flow's `scope_circle_id`). `None` falls back to the
    /// historical Realm-wide subscription. Forwarded into the chime
    /// request via [`build_request`].
    pub active_circle_id: Option<String>,
}

/// Outcome of a successful chime-driven registration. The persisted
/// `PushRegistrationState` has already been saved to `LocalStateStore`
/// — the value is returned for UI labelling.
#[derive(Clone, Debug)]
pub struct RegisterOutcome {
    pub state: PushRegistrationState,
    pub response: RegisterDeviceResponse,
}

#[derive(Clone, Debug)]
struct ChimeSessionGrantHeaders {
    grant_jwt: String,
    challenge: Option<String>,
    proof_jwt: Option<String>,
}

/// Resolve a real token via the installed `PushTokenProvider`, build a
/// chime register-device request, post it through the chime SDK, and
/// persist the resulting `PushRegistrationState` to `LocalStateStore`.
///
/// On non-wasm targets the chime client uses reqwest+rustls+tokio. On
/// wasm32 the same client routes through reqwest's fetch-backed wasm32
/// backend (no rustls, no tokio runtime), so the browser build drives a
/// real HTTP POST to the principal server.
pub async fn register_via_chime(
    mut ctx: RegisterContext,
    state_store: &mut LocalStateStore,
) -> Result<RegisterOutcome, PushRegistrationError> {
    let session_grant = resolve_chime_session_grant(&mut ctx, state_store)?;
    let token = resolve_real_token(&ctx).await?;
    let request = build_request(&ctx, &token)?;
    ensure_production_register_request(&request)
        .map_err(|err| PushRegistrationError::PlaceholderTokenRejected(err.to_string()))?;

    let mut client =
        ContrixPushClient::new(ctx.principal_server_url.as_str()).with_required_session_grant(true);
    if let Some(token) = ctx.bearer_token.as_deref() {
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
            .with_header("X-Contrix-Session-Grant-Challenge", challenge)
            .and_then(|client| client.with_header("X-Contrix-Session-Grant-Proof", proof_jwt))
            .map_err(|err| PushRegistrationError::Transport(err.to_string()))?;
    }

    let response = client
        .register_device_with_request(&request, request.idempotency_key.as_deref(), None)
        .await
        .map_err(|err| PushRegistrationError::Transport(err.to_string()))?;

    let state = registration_state_from_response(&request, &response.body);
    state_store.save_push_registration(state.clone());

    Ok(RegisterOutcome {
        state,
        response: response.body,
    })
}

fn resolve_chime_session_grant(
    ctx: &mut RegisterContext,
    state_store: &LocalStateStore,
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

    let grant = state_store
        .session_grant()
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
    if ctx.principal_did.is_none() {
        ctx.principal_did = Some(grant.principal_did.clone());
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
) -> Result<RegisterDeviceRequest, PushRegistrationError> {
    let push_gateway = if ctx.floria_gateway_url.trim().is_empty() {
        floria_gateway_url()
    } else {
        ctx.floria_gateway_url.clone()
    };
    let binding = GatewayBinding::new(PushGatewayType::Standard, push_gateway);
    // CXP-0007 P3B.2.9 — forward the active Circle id (when present)
    // into the chime subscribe request. The chime crate carries the
    // value out-of-band by stamping it onto the idempotency key
    // (so re-registration after a Circle switch produces a distinct
    // subscription record) and by registering it as a muted
    // exclusion so the gateway does not re-deliver Realm-only
    // wakeups for that Circle. When no Circle is active the build
    // falls back to the prior Realm-wide subscription behaviour.
    let active_circle = ctx
        .active_circle_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let mut muted_circle_ids = std::collections::BTreeSet::new();
    if let Some(circle) = active_circle {
        // Subscribing to a Circle implicitly opts the device out of
        // Realm-wide duplicate wakeups for the same Circle by adding
        // it to the muted set on the legacy delivery path.
        muted_circle_ids.insert(circle.to_owned());
    }
    let prefs = PushPreferences {
        enabled: true,
        allow_insecure_loopback_push_gateway: true,
        gateways: vec![binding.clone()],
        muted_circle_ids,
        ..Default::default()
    };
    let idempotency_key = match active_circle {
        Some(circle) => format!("yougen-push-register-{}-{circle}", ctx.device_id),
        None => format!("yougen-push-register-{}", ctx.device_id),
    };
    let platform = current_platform_str();
    let config = PushDeviceConfig {
        principal_did: ctx.principal_did.as_deref(),
        device_id: ctx.device_id.as_str(),
        push_key: Some(push_key),
        platform: Some(platform),
        app_id: Some("yougen"),
        domestic_app_id: None,
        registration_id: None,
        display_name: Some("yougen"),
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
    use super::*;
    use chrono::{Duration, Utc};
    use ed25519_dalek::pkcs8::EncodePrivateKey as _;
    use std::sync::Arc;
    #[cfg(not(target_arch = "wasm32"))]
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::local_state::PersistedSessionGrant;
    use crate::push::{FcmPushTokenProvider, PushTokenProvider};

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
            floria_gateway_url: "https://push.example/api/v1/push/notify".to_owned(),
            device_id: device.to_owned(),
            principal_did: Some("did:web:alice.example".to_owned()),
            bearer_token: Some("session-secret".to_owned()),
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
            grant_id: "cx:grant:push-local".to_owned(),
            audience: "https://principal.example/".to_owned(),
            principal_did: "did:web:alice.example".to_owned(),
            device_id: device.to_owned(),
            principal_server_url: "https://principal.example/".to_owned(),
            session_grant_exchange_path: "api/v1/auth/session-grant/exchange".to_owned(),
            grant_expires_at: Some(Utc::now() + Duration::hours(1)),
            session_expires_at: None,
            stored_at: Utc::now(),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn isolated_store(tag: &str) -> LocalStateStore {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("push-registration-{tag}-{stamp}.json"));
        LocalStateStore::with_path(path)
    }

    #[cfg(target_arch = "wasm32")]
    fn isolated_store(_tag: &str) -> LocalStateStore {
        LocalStateStore::default()
    }

    #[test]
    fn build_request_uses_floria_url_as_push_gateway() {
        let request = build_request(&ctx("dev_yougen"), "apns:01234567890abcdef").expect("build");
        assert_eq!(request.device_id, "dev_yougen");
        assert_eq!(request.push_key, "apns:01234567890abcdef");
        assert_eq!(
            request.push_gateway,
            "https://push.example/api/v1/push/notify"
        );
        assert_eq!(request.app_id.as_deref(), Some("yougen"));
        assert_eq!(request.platform.as_deref(), Some(current_platform_str()));
    }

    #[test]
    fn build_request_falls_back_to_runtime_floria_gateway_when_empty() {
        let mut c = ctx("dev_yougen");
        c.floria_gateway_url = "   ".to_owned();
        let request = build_request(&c, "apns:01234567890abcdef").expect("build");
        assert_eq!(request.push_gateway, floria_gateway_url());
    }

    #[test]
    fn build_request_stamps_active_circle_into_idempotency_key() {
        let mut c = ctx("dev_yougen");
        c.active_circle_id = Some("cx:circle:opsroom".to_owned());
        let request = build_request(&c, "apns:01234567890abcdef").expect("build");
        let key = request.idempotency_key.as_deref().expect("idempotency_key");
        assert!(key.contains("cx:circle:opsroom"), "idempotency_key={key}");
    }

    #[test]
    fn resolves_persisted_grant_into_chime_headers() {
        let mut store = isolated_store("grant-headers");
        store.set_session_grant(Some(persisted_grant("dev_yougen")));
        let mut context = ctx("dev_yougen");
        context.principal_did = None;

        let headers = resolve_chime_session_grant(&mut context, &store).expect("grant headers");

        assert_eq!(headers.grant_jwt, "header.payload.signature");
        assert!(headers.challenge.as_deref().is_some_and(|v| !v.is_empty()));
        assert!(headers.proof_jwt.as_deref().is_some_and(|v| !v.is_empty()));
        assert_eq!(
            context.principal_did.as_deref(),
            Some("did:web:alice.example")
        );
    }

    #[test]
    fn missing_grant_fails_closed_before_register() {
        let mut context = ctx("dev_yougen");
        let store = isolated_store("missing-grant");
        let err = resolve_chime_session_grant(&mut context, &store).unwrap_err();
        assert!(matches!(err, PushRegistrationError::MissingSessionGrant));
    }

    #[test]
    fn placeholder_resolved_token_is_rejected_by_guard() {
        // Even if a buggy provider hands back a placeholder marker, the
        // production guard MUST reject it before we POST.
        let request =
            build_request(&ctx("dev_yougen"), "desktop:yougen-dev-placeholder-token").unwrap();
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
