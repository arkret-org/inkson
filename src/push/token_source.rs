//! Platform / preference resolution and the pluggable
//! [`PushTokenSource`] fallback chain.
//!
//! Pure structural split out of `push::mod`; behaviour and visibility
//! are unchanged. Items consumed by sibling modules (`request`) are
//! exposed as `pub(crate)`; the rest stay private to this file.

use std::sync::{Arc, OnceLock};

use chime::{GatewayBinding, PushGatewayType, PushPreferences};

use super::gateway::floria_gateway_url;
#[cfg(not(target_arch = "wasm32"))]
use super::token_provider::resolve_provider_push_token;

pub(crate) fn push_preferences() -> PushPreferences {
    PushPreferences {
        enabled: true,
        allow_insecure_loopback_push_gateway: true,
        gateways: vec![default_gateway_binding()],
        ..Default::default()
    }
}

/// F-BUILD-FIX-1: chime's `build_register_device_request` moved the push
/// gateway URL off `PushPreferences` and onto a per-call `GatewayBinding`.
/// Yougen only registers against a single configured gateway (the floria
/// `/_cokret/edge/push/notify` endpoint by default), so this helper resolves the
/// runtime gateway URL into a freshly-constructed binding for every
/// register / state-rebuild call site.
pub(crate) fn default_gateway_binding() -> GatewayBinding {
    GatewayBinding::new(PushGatewayType::Standard, configured_push_gateway())
}

#[cfg(not(target_arch = "wasm32"))]
fn configured_push_gateway() -> String {
    floria_gateway_url()
}

#[cfg(target_arch = "wasm32")]
fn configured_push_gateway() -> String {
    floria_gateway_url()
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn current_platform() -> &'static str {
    "web"
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn current_platform() -> &'static str {
    "desktop"
}

/// Pluggable source for the platform-specific push token bundled into a
/// register-device request. Production OS / Web Push integrations register
/// their own implementation via [`set_push_token_source`]; until that
/// happens, [`DevPlaceholderTokenSource`] returns the development markers
/// pinned by `tests/dev_token_guard.rs`. Real registrations stay gated by
/// [`ensure_production_register_request`](super::ensure_production_register_request).
pub trait PushTokenSource: Send + Sync {
    fn current_token(&self, platform: &str) -> Option<String>;

    fn rotate_token(&self, _platform: &str) -> Option<String> {
        None
    }
}

/// Default token source; emits the well-known `yougen-dev-placeholder-token`
/// markers per platform. Replaced via [`set_push_token_source`] once a real
/// APNs / FCM / Web Push integration is wired in.
#[derive(Clone, Debug, Default)]
pub struct DevPlaceholderTokenSource;

impl PushTokenSource for DevPlaceholderTokenSource {
    fn current_token(&self, platform: &str) -> Option<String> {
        Some(match platform {
            "web" => "webpush:yougen-dev-placeholder-token".to_owned(),
            _ => "desktop:yougen-dev-placeholder-token".to_owned(),
        })
    }
}

static PUSH_TOKEN_SOURCE: OnceLock<Arc<dyn PushTokenSource>> = OnceLock::new();

/// Install the process-wide push token source. May be called at most once;
/// subsequent calls are silently ignored so test fixtures and a host
/// integration cannot conflict at runtime.
pub fn set_push_token_source(source: Arc<dyn PushTokenSource>) {
    let _ = PUSH_TOKEN_SOURCE.set(source);
}

fn push_token_source() -> Arc<dyn PushTokenSource> {
    PUSH_TOKEN_SOURCE
        .get()
        .cloned()
        .unwrap_or_else(|| Arc::new(DevPlaceholderTokenSource))
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn acquire_platform_push_key() -> String {
    if let Ok(env_key) = std::env::var("CHASK_PUSH_KEY") {
        return env_key;
    }
    if let Ok(Some(token)) = resolve_provider_push_token(None) {
        return token;
    }
    push_token_source()
        .current_token(current_platform())
        .unwrap_or_else(|| "desktop:yougen-dev-placeholder-token".to_owned())
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn acquire_platform_push_key() -> String {
    push_token_source()
        .current_token(current_platform())
        .unwrap_or_else(|| "webpush:yougen-dev-placeholder-token".to_owned())
}
