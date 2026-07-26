//! Platform, preference, and gateway-binding resolution.
//!
//! Pure structural split out of `push::mod`; behaviour and visibility
//! are unchanged. Items consumed by sibling modules (`request`) are
//! exposed as `pub(crate)`; the rest stay private to this file.

use chime::{GatewayBinding, PushGatewayType, PushPreferences};

use super::gateway::floria_gateway_url;

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
/// Inkson only registers against a single configured gateway (the floria
/// `/_arkret/edge/push/notify` endpoint by default), so this helper resolves the
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
