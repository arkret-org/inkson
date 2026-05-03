use chime::{
    PushDeviceConfig, PushPreferences, PushRegistrationState, RegisterDeviceRequest,
    RegisterDeviceResponse, UnregisterDeviceRequest, build_register_device_request,
    build_registration_state, build_unregister_device_request,
};
use chrono::Utc;

const APP_ID: &str = "yougen";
const DISPLAY_NAME: &str = "yougen";
const DEFAULT_PUSH_GATEWAY: &str = "https://push.example/api/v1/push/notify";

pub fn push_status_label(state: Option<&PushRegistrationState>) -> String {
    match state {
        Some(state) => state
            .registration_id
            .clone()
            .unwrap_or_else(|| "registered".to_owned()),
        None => "Not registered".to_owned(),
    }
}

pub fn build_register_request(device_id: &str) -> anyhow::Result<RegisterDeviceRequest> {
    let push_key = acquire_platform_push_key();
    let platform = current_platform();
    let prefs = push_preferences();
    let idempotency_key = format!("yougen-push-register-{device_id}");
    let config = PushDeviceConfig {
        principal_did: None,
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

    Ok(build_register_device_request(&config, &prefs)?)
}

pub fn build_unregister_request(
    device_id: &str,
    existing: Option<&PushRegistrationState>,
) -> anyhow::Result<UnregisterDeviceRequest> {
    let platform = current_platform();
    let idempotency_key = format!("yougen-push-unregister-{device_id}");
    let registration_id = existing.and_then(|state| state.registration_id.as_deref());
    let app_id = existing
        .and_then(|state| state.app_id.as_deref())
        .unwrap_or(APP_ID);
    let config = PushDeviceConfig {
        principal_did: existing.and_then(|state| state.principal_did.as_deref()),
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

    Ok(build_unregister_device_request(
        &config,
        &PushPreferences::default(),
    )?)
}

pub fn registration_state_from_response(
    request: &RegisterDeviceRequest,
    response: &RegisterDeviceResponse,
) -> PushRegistrationState {
    let config = PushDeviceConfig {
        principal_did: request.principal_did.as_deref(),
        device_id: &request.device_id,
        push_key: Some(&request.push_key),
        platform: request.platform.as_deref(),
        app_id: request.app_id.as_deref(),
        domestic_app_id: None,
        registration_id: response.registration_id.as_deref(),
        display_name: request.display_name.as_deref(),
        idempotency_key: request.idempotency_key.as_deref(),
        request_id: None,
        proof: request.proof.as_ref(),
    };
    let prefs = PushPreferences {
        enabled: true,
        push_gateway: request.push_gateway.clone(),
        ..Default::default()
    };

    build_registration_state(
        &config,
        &prefs,
        request,
        response,
        Some(&Utc::now().to_rfc3339()),
    )
}

fn push_preferences() -> PushPreferences {
    PushPreferences {
        enabled: true,
        push_gateway: configured_push_gateway(),
        allow_insecure_loopback_push_gateway: true,
        ..Default::default()
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn configured_push_gateway() -> String {
    std::env::var("CHASK_PUSH_GATEWAY").unwrap_or_else(|_| DEFAULT_PUSH_GATEWAY.to_owned())
}

#[cfg(target_arch = "wasm32")]
fn configured_push_gateway() -> String {
    DEFAULT_PUSH_GATEWAY.to_owned()
}

#[cfg(target_arch = "wasm32")]
fn current_platform() -> &'static str {
    "web"
}

#[cfg(not(target_arch = "wasm32"))]
fn current_platform() -> &'static str {
    "desktop"
}

#[cfg(not(target_arch = "wasm32"))]
fn acquire_platform_push_key() -> String {
    std::env::var("CHASK_PUSH_KEY").unwrap_or_else(|_| {
        // TODO(push): replace this development token with OS/Web push token
        // acquisition (APNs, FCM, Web Push, or desktop bridge) before release.
        "desktop:yougen-dev-placeholder-token".to_owned()
    })
}

#[cfg(target_arch = "wasm32")]
fn acquire_platform_push_key() -> String {
    // TODO(push): request Notification permission, create a PushSubscription,
    // and serialize its endpoint/auth/p256dh values as the web push key.
    "webpush:yougen-dev-placeholder-token".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_chime_register_request() {
        let request = build_register_request("dev_yougen").unwrap();
        assert_eq!(request.device_id, "dev_yougen");
        assert_eq!(request.app_id.as_deref(), Some("yougen"));
        assert_eq!(request.platform.as_deref(), Some(current_platform()));
        assert!(!request.push_key.is_empty());
    }

    #[test]
    fn builds_persistable_registration_state() {
        let request = build_register_request("dev_yougen").unwrap();
        let response = RegisterDeviceResponse {
            ok: true,
            registration_id: Some("cx:push:test".to_owned()),
            expires_at: None,
            ..Default::default()
        };
        let state = registration_state_from_response(&request, &response);

        assert_eq!(state.registration_id.as_deref(), Some("cx:push:test"));
        assert_eq!(state.device_id, "dev_yougen");
        assert!(state.push_key_hash.starts_with("sha256:"));
        assert!(!state.push_key_hash.contains("placeholder"));
    }

    #[test]
    fn builds_unregister_request_from_existing_state() {
        let request = build_register_request("dev_yougen").unwrap();
        let response = RegisterDeviceResponse {
            ok: true,
            registration_id: Some("cx:push:test".to_owned()),
            expires_at: None,
            ..Default::default()
        };
        let state = registration_state_from_response(&request, &response);
        let unregister = build_unregister_request("dev_yougen", Some(&state)).unwrap();

        assert_eq!(unregister.device_id, "dev_yougen");
        assert_eq!(unregister.registration_id.as_deref(), Some("cx:push:test"));
        assert_eq!(unregister.app_id.as_deref(), Some("yougen"));
    }

    #[test]
    fn push_status_label_treats_state_without_registration_id_as_registered() {
        let request = build_register_request("dev_yougen").unwrap();
        let response = RegisterDeviceResponse {
            ok: true,
            registration_id: None,
            expires_at: None,
            ..Default::default()
        };
        let state = registration_state_from_response(&request, &response);

        assert_eq!(push_status_label(Some(&state)), "registered");
        assert_eq!(push_status_label(None), "Not registered");
    }
}
