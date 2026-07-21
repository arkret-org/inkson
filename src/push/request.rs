//! Register / unregister request builders and registration-state
//! reconstruction.
//!
//! Pure structural split out of `push::mod`; behaviour and the wire
//! shape of every request are unchanged.

use chime::{
    ChimePushRegisterDeviceOutcome, ChimePushRegisterDeviceRequest,
    ChimePushUnregisterDeviceRequest, GatewayBinding, PushDeviceConfig, PushGatewayType,
    PushRegistrationState, build_register_device_request, build_registration_state,
    build_unregister_device_request,
};
use chrono::Utc;

use super::token_source::{
    acquire_platform_push_key, current_platform, default_gateway_binding, push_preferences,
};
use super::{APP_ID, DISPLAY_NAME};
use crate::models::PushRegisterView;

pub fn build_register_request(device_id: &str) -> anyhow::Result<ChimePushRegisterDeviceRequest> {
    build_register_request_for_actor(device_id, None)
}

pub fn build_register_request_for_actor(
    device_id: &str,
    principal_id: Option<&str>,
) -> anyhow::Result<ChimePushRegisterDeviceRequest> {
    let push_key = acquire_platform_push_key();
    let platform = current_platform();
    let prefs = push_preferences();
    let binding = default_gateway_binding();
    let idempotency_key = format!("inkson-push-register-{device_id}");
    let config = PushDeviceConfig {
        principal_id,
        device_id,
        push_key: Some(&push_key),
        platform: Some(platform),
        app_id: Some(APP_ID),
        domestic_app_id: None,
        registration_id: None,
        display_name: Some(DISPLAY_NAME),
        idempotency_key: Some(&idempotency_key),
        request_id: None,
        proof: None,
    };

    Ok(build_register_device_request(&config, &binding, &prefs)?)
}

pub fn build_unregister_request(
    device_id: &str,
    existing: Option<&PushRegistrationState>,
) -> anyhow::Result<ChimePushUnregisterDeviceRequest> {
    let platform = current_platform();
    let idempotency_key = format!("inkson-push-unregister-{device_id}");
    let registration_id = existing.and_then(|state| state.registration_id.as_deref());
    let app_id = existing
        .and_then(|state| state.app_id.as_deref())
        .unwrap_or(APP_ID);
    let config = PushDeviceConfig {
        principal_id: existing.and_then(|state| state.principal_id.as_deref()),
        device_id,
        push_key: None,
        platform: Some(platform),
        app_id: Some(app_id),
        domestic_app_id: None,
        registration_id,
        display_name: None,
        idempotency_key: Some(&idempotency_key),
        request_id: None,
        proof: None,
    };

    // P4 hygiene: reuse `push_preferences()` (with
    // `allow_insecure_loopback_push_gateway=true`) so the dev /
    // localhost gateway path validates the same way `build_register_request`
    // does. The previous `PushPreferences::default()` had loopback
    // off, which rejected the `http://localhost:…` gateway introduced
    // by `floria_gateway_url`.
    Ok(build_unregister_device_request(
        &config,
        &default_gateway_binding(),
        &push_preferences(),
    )?)
}

pub fn registration_state_from_response(
    request: &ChimePushRegisterDeviceRequest,
    response: &ChimePushRegisterDeviceOutcome,
) -> PushRegistrationState {
    let binding = GatewayBinding::new(PushGatewayType::Standard, request.push_gateway.clone());
    let registered_at = arkret_sdk::canonical::format_timestamp_canonical(Utc::now());

    build_registration_state(&binding, request, response, Some(registered_at.as_str()))
}

pub fn push_register_view_from_chime_response(
    response: ChimePushRegisterDeviceOutcome,
) -> PushRegisterView {
    PushRegisterView {
        ok: response.ok,
        registration_id: response.registration_id,
        expires_at: response
            .expires_at
            .map(arkret_sdk::canonical::format_timestamp_canonical),
    }
}
