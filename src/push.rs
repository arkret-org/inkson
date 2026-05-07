use chime::{
    PushBridgeDescribeResponse, PushDeviceConfig, PushGatewayIntegrationDescribeResponse,
    PushPreferences, PushRegistrationState,
    RegisterDeviceRequest, RegisterDeviceResponse, UnregisterDeviceRequest,
    build_register_device_request, build_registration_state, build_unregister_device_request,
    push_bridge_describe_url, push_integration_describe_url,
};
use chrono::Utc;

const APP_ID: &str = "yougen";
const DISPLAY_NAME: &str = "yougen";
const DEFAULT_PUSH_GATEWAY: &str = "https://push.example/api/v1/push/notify";

/// Markers embedded in development push tokens. Any push key containing one of
/// these substrings is a build-time placeholder that must NEVER reach a
/// production push gateway — see `tests/dev_token_guard.rs` for the regression
/// suite that holds this invariant.
pub const PLACEHOLDER_PUSH_KEY_MARKERS: &[&str] = &["placeholder", "yougen-dev-"];

/// True when `key` carries one of the development placeholder markers. The
/// login wiring uses this to gate registration against production push
/// gateways; the regression test in `tests/dev_token_guard.rs` keeps the
/// predicate honest as we add more `cfg`-specific defaults.
pub fn is_placeholder_push_key(key: &str) -> bool {
    let lowered = key.to_ascii_lowercase();
    PLACEHOLDER_PUSH_KEY_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
}

/// Returns the request when its push key is real material, otherwise an error
/// describing why the registration must NOT be sent. Callers in the login /
/// settings flow should funnel through this helper before POSTing a register
/// request to a non-loopback push gateway.
pub fn ensure_production_register_request(
    request: &RegisterDeviceRequest,
) -> anyhow::Result<()> {
    if is_placeholder_push_key(&request.push_key) {
        anyhow::bail!(
            "refusing to register device {device_id}: push_key is a development placeholder. \
             Provide a real OS / Web Push token via CHASK_PUSH_KEY or the platform integration \
             before contacting the push gateway.",
            device_id = request.device_id,
        );
    }
    Ok(())
}

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
    build_register_request_for_actor(device_id, None)
}

pub fn build_register_request_for_actor(
    device_id: &str,
    principal_did: Option<&str>,
) -> anyhow::Result<RegisterDeviceRequest> {
    let push_key = acquire_platform_push_key();
    let platform = current_platform();
    let prefs = push_preferences();
    let idempotency_key = format!("yougen-push-register-{device_id}");
    let config = PushDeviceConfig {
        principal_did,
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

pub async fn describe_push_gateway_bridge(
    push_gateway_url: &str,
) -> anyhow::Result<PushBridgeDescribeResponse> {
    let describe_url = push_bridge_describe_url(push_gateway_url)?;
    let response = reqwest::Client::new().get(&describe_url).send().await?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("push gateway bridge describe returned HTTP {status}");
    }
    Ok(response.json().await?)
}

pub async fn describe_push_gateway_integration(
    push_gateway_url: &str,
) -> anyhow::Result<PushGatewayIntegrationDescribeResponse> {
    let describe_url = push_integration_describe_url(push_gateway_url)?;
    let response = reqwest::Client::new().get(&describe_url).send().await?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("push gateway integration describe returned HTTP {status}");
    }
    Ok(response.json().await?)
}

pub fn summarize_push_gateway_bridge(bridge: &PushBridgeDescribeResponse) -> String {
    format!(
        "contract={} version={} notify_path={} providers={} auth_modes={} privacy_mode={} todos={}",
        bridge.contract,
        bridge.version,
        bridge.notify.notify_path,
        if bridge.gateway.supported_providers.is_empty() {
            "none".to_owned()
        } else {
            bridge.gateway.supported_providers.join(",")
        },
        if bridge.gateway.auth_modes.is_empty() {
            "none".to_owned()
        } else {
            bridge.gateway.auth_modes.join(",")
        },
        bridge.privacy.default_mode,
        if bridge.todos.is_empty() {
            "none".to_owned()
        } else {
            bridge.todos.join(" | ")
        },
    )
}

pub fn summarize_push_gateway_integration(
    manifest: &PushGatewayIntegrationDescribeResponse,
) -> String {
    let dependencies = if manifest.dependencies.is_empty() {
        "none".to_owned()
    } else {
        manifest
            .dependencies
            .iter()
            .map(|dependency| {
                format!(
                    "{}:{}@{}",
                    dependency.service, dependency.purpose, dependency.discovery_path
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    let surfaces = if manifest.surfaces.is_empty() {
        "none".to_owned()
    } else {
        manifest
            .surfaces
            .iter()
            .map(|surface| {
                format!(
                    "{} {} {} [{}]",
                    surface.method, surface.path, surface.contract, surface.stability
                )
            })
            .collect::<Vec<_>>()
            .join(" | ")
    };
    format!(
        "contract={} version={} service={} kind={} dependencies={} surfaces={} todos={}",
        manifest.contract,
        manifest.version,
        manifest.service,
        manifest.service_kind,
        dependencies,
        surfaces,
        if manifest.todos.is_empty() {
            "none".to_owned()
        } else {
            manifest.todos.join(" | ")
        },
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
        let mut response = RegisterDeviceResponse::default();
        response.ok = true;
        response.registration_id = Some("cx:push:test".to_owned());
        let state = registration_state_from_response(&request, &response);

        assert_eq!(state.registration_id.as_deref(), Some("cx:push:test"));
        assert_eq!(state.device_id, "dev_yougen");
        assert!(state.push_key_hash.starts_with("sha256:"));
        assert!(!state.push_key_hash.contains("placeholder"));
    }

    #[test]
    fn builds_unregister_request_from_existing_state() {
        let request = build_register_request("dev_yougen").unwrap();
        let mut response = RegisterDeviceResponse::default();
        response.ok = true;
        response.registration_id = Some("cx:push:test".to_owned());
        let state = registration_state_from_response(&request, &response);
        let unregister = build_unregister_request("dev_yougen", Some(&state)).unwrap();

        assert_eq!(unregister.device_id, "dev_yougen");
        assert_eq!(unregister.registration_id.as_deref(), Some("cx:push:test"));
        assert_eq!(unregister.app_id.as_deref(), Some("yougen"));
    }

    #[test]
    fn summarizes_push_bridge_contract() {
        let summary = summarize_push_gateway_bridge(&PushBridgeDescribeResponse {
            contract: "cx.push.bridge.describe".to_owned(),
            version: "2026-05-03".to_owned(),
            api_base_path: "/api/v1/push".to_owned(),
            gateway: Default::default(),
            notify: chime::PushBridgeDescribeNotifyDescriptor {
                notify_path: "/api/v1/push/notify".to_owned(),
                ..Default::default()
            },
            privacy: chime::PushBridgeDescribePrivacyDescriptor {
                default_mode: "e2ee_blind_wakeup".to_owned(),
                ..Default::default()
            },
            examples: Default::default(),
            todos: vec!["TODO(push-bridge)".to_owned()],
        });

        assert!(summary.contains("cx.push.bridge.describe"));
        assert!(summary.contains("/api/v1/push/notify"));
        assert!(summary.contains("e2ee_blind_wakeup"));
    }

    #[test]
    fn placeholder_push_key_predicate_matches_known_markers() {
        assert!(is_placeholder_push_key("desktop:yougen-dev-placeholder-token"));
        assert!(is_placeholder_push_key("webpush:yougen-dev-placeholder-token"));
        assert!(is_placeholder_push_key("DESKTOP:Yougen-Dev-Placeholder"));
        assert!(!is_placeholder_push_key("apns:abcd1234efgh"));
        assert!(!is_placeholder_push_key("webpush:https://example.com/wp/abc123"));
    }

    #[test]
    fn ensure_production_register_rejects_placeholder_keys() {
        let request = build_register_request("dev_yougen").unwrap();
        let err = ensure_production_register_request(&request)
            .expect_err("default scaffold push key must be rejected");
        let message = err.to_string();
        assert!(message.contains("dev_yougen"));
        assert!(message.contains("placeholder"));
    }

    #[test]
    fn ensure_production_register_accepts_real_keys() {
        let mut request = build_register_request("dev_yougen").unwrap();
        request.push_key = "apns:5dccd5b9c8be12a8d10dc1ad6c0a3a8d".to_owned();
        ensure_production_register_request(&request).expect("real push key must be accepted");
    }

    #[test]
    fn push_status_label_treats_state_without_registration_id_as_registered() {
        let request = build_register_request("dev_yougen").unwrap();
        let mut response = RegisterDeviceResponse::default();
        response.ok = true;
        let state = registration_state_from_response(&request, &response);

        assert_eq!(push_status_label(Some(&state)), "registered");
        assert_eq!(push_status_label(None), "Not registered");
    }
}
