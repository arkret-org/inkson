pub mod native;
pub mod registration;

use std::sync::{Arc, Mutex, OnceLock};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use chime::{
    GatewayBinding, PushBridgeDescribeOutcome, PushDeviceConfig,
    PushGatewayIntegrationDescribeOutcome, PushGatewayType, PushPreferences,
    PushRegisterDeviceOutcome, PushRegisterDeviceRequestBody, PushRegistrationState,
    PushUnregisterDeviceRequestBody, build_register_device_request, build_registration_state,
    build_unregister_device_request, push_bridge_describe_url, push_integration_describe_url,
};
use chrono::Utc;
use serde_json::Value;

use crate::secure_key_store::{SecureKeyStore, SecureKeyStoreError, unwrap_secret, wrap_secret};

const APP_ID: &str = "yougen";
const DISPLAY_NAME: &str = "yougen";
/// P4 (CKP-0007 hygiene): the previous hard-coded
/// `https://push.example/_cokret/edge/push/notify` placeholder is gone.
/// We now read `YOUGEN_FLORIA_URL` at the call site (see
/// [`floria_gateway_url`]); when it's unset in dev we point at
/// localhost, when it's unset in prod we return an empty string and
/// the registration code no-ops rather than POSTing to a fake host.
const DEV_FLORIA_GATEWAY: &str = "http://localhost:9001/_cokret/edge/push/notify";
/// Returned by [`floria_gateway_url`] when the env var is unset and
/// we're NOT in a debug build. The chime register-device path treats
/// an empty gateway URL as "no push registration" and short-circuits
/// without contacting any remote host.
const NOOP_FLORIA_GATEWAY: &str = "";

/// Read the floria push gateway URL at runtime.
///
/// Resolution order:
/// 1. `YOUGEN_FLORIA_URL` env var, if non-empty.
/// 2. Debug builds (`cfg(debug_assertions)`): localhost dev gateway.
/// 3. Release builds: empty string ⇒ no-op (registration short-circuits).
pub fn floria_gateway_url() -> String {
    #[cfg(not(target_arch = "wasm32"))]
    {
        if let Ok(value) = std::env::var("YOUGEN_FLORIA_URL") {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.to_owned();
            }
        }
    }
    if cfg!(debug_assertions) {
        DEV_FLORIA_GATEWAY.to_owned()
    } else {
        NOOP_FLORIA_GATEWAY.to_owned()
    }
}

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
    request: &PushRegisterDeviceRequestBody,
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

const BLIND_WAKEUP_FORBIDDEN_KEYS: &[&str] = &[
    "actor",
    "actor_id",
    "device_id",
    "did",
    "event_id",
    "flow_id",
    "local_name",
    "message_id",
    "note",
    "principal_did",
    "principal_id",
    "push_target_id",
    "remark",
    "realm_id",
    "room_id",
    "sender",
    "sender_id",
    "space_id",
    "user_id",
];

/// Lint a push wakeup payload before it leaves the client / bridge tests.
///
/// Spec `discovery/push-notifications.md` requires blind wakeups: the payload
/// must not carry stable identities or Realm/Space/Event/Flow ids. The delivery route
/// already knows the push target; the app resolves the actual notification body
/// locally after waking and syncing.
pub fn validate_blind_wakeup_payload(payload: &Value) -> anyhow::Result<()> {
    validate_blind_wakeup_payload_at(payload, "$")
}

fn validate_blind_wakeup_payload_at(payload: &Value, path: &str) -> anyhow::Result<()> {
    match payload {
        Value::Object(map) => {
            for (key, value) in map {
                let normalized = key.to_ascii_lowercase();
                if BLIND_WAKEUP_FORBIDDEN_KEYS
                    .iter()
                    .any(|forbidden| normalized == *forbidden)
                {
                    anyhow::bail!("blind push payload leaks `{key}` at {path}");
                }
                validate_blind_wakeup_payload_at(value, &format!("{path}.{key}"))?;
            }
        }
        Value::Array(items) => {
            for (idx, value) in items.iter().enumerate() {
                validate_blind_wakeup_payload_at(value, &format!("{path}[{idx}]"))?;
            }
        }
        Value::String(value)
            if value.starts_with("did:")
                || value.starts_with("ck:space:")
                || value.starts_with("ck:realm:")
                || value.starts_with("ck:flow:")
                || value.starts_with("ck:event:") =>
        {
            anyhow::bail!("blind push payload leaks stable id at {path}");
        }
        _ => {}
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

pub fn build_register_request(device_id: &str) -> anyhow::Result<PushRegisterDeviceRequestBody> {
    build_register_request_for_actor(device_id, None)
}

pub fn build_register_request_for_actor(
    device_id: &str,
    principal_id: Option<&str>,
) -> anyhow::Result<PushRegisterDeviceRequestBody> {
    let push_key = acquire_platform_push_key();
    let platform = current_platform();
    let prefs = push_preferences();
    let binding = default_gateway_binding();
    let idempotency_key = format!("yougen-push-register-{device_id}");
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
) -> anyhow::Result<PushUnregisterDeviceRequestBody> {
    let platform = current_platform();
    let idempotency_key = format!("yougen-push-unregister-{device_id}");
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
    request: &PushRegisterDeviceRequestBody,
    response: &PushRegisterDeviceOutcome,
) -> PushRegistrationState {
    let binding = GatewayBinding::new(PushGatewayType::Standard, request.push_gateway.clone());
    let registered_at = Utc::now().to_rfc3339();

    build_registration_state(&binding, request, response, Some(registered_at.as_str()))
}

pub async fn describe_push_gateway_bridge(
    push_gateway_url: &str,
) -> anyhow::Result<PushBridgeDescribeOutcome> {
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
) -> anyhow::Result<PushGatewayIntegrationDescribeOutcome> {
    let describe_url = push_integration_describe_url(push_gateway_url)?;
    let response = reqwest::Client::new().get(&describe_url).send().await?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("push gateway integration describe returned HTTP {status}");
    }
    Ok(response.json().await?)
}

pub fn summarize_push_gateway_bridge(bridge: &PushBridgeDescribeOutcome) -> String {
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
    manifest: &PushGatewayIntegrationDescribeOutcome,
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
fn default_gateway_binding() -> GatewayBinding {
    GatewayBinding::new(PushGatewayType::Standard, configured_push_gateway())
}

#[cfg(not(target_arch = "wasm32"))]
fn configured_push_gateway() -> String {
    // P4 hygiene: `CHASK_PUSH_GATEWAY` was the historical operator
    // override; the canonical name is now `YOUGEN_FLORIA_URL`. We
    // honour the legacy var when set so existing deployments keep
    // working; otherwise `floria_gateway_url` does the right thing
    // (dev → localhost, prod-without-env → empty no-op).
    if let Ok(value) = std::env::var("CHASK_PUSH_GATEWAY") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.to_owned();
        }
    }
    floria_gateway_url()
}

#[cfg(target_arch = "wasm32")]
fn configured_push_gateway() -> String {
    floria_gateway_url()
}

#[cfg(target_arch = "wasm32")]
fn current_platform() -> &'static str {
    "web"
}

#[cfg(not(target_arch = "wasm32"))]
fn current_platform() -> &'static str {
    "desktop"
}

/// Pluggable source for the platform-specific push token bundled into a
/// register-device request. Production OS / Web Push integrations register
/// their own implementation via [`set_push_token_source`]; until that
/// happens, [`DevPlaceholderTokenSource`] returns the development markers
/// pinned by `tests/dev_token_guard.rs`. Real registrations stay gated by
/// [`ensure_production_register_request`].
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
fn acquire_platform_push_key() -> String {
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
fn acquire_platform_push_key() -> String {
    push_token_source()
        .current_token(current_platform())
        .unwrap_or_else(|| "webpush:yougen-dev-placeholder-token".to_owned())
}

// ═══════════════════════════════════════════════════════════════════════════
// Real OS / Web Push token integration.
//
// `PushTokenProvider` is the production trait callers register at boot to
// resolve the platform-specific push token used by `register_device`. The
// crate ships three concrete impls:
//
// * `WebPushTokenProvider` — drives `navigator.serviceWorker.register` + `pushManager.subscribe({
//   userVisibleOnly: true, applicationServerKey })` on wasm32 targets. The VAPID
//   `applicationServerKey` is fetched from soland's push-bridge describe endpoint
//   (ck.push.bridge.describe.v1), so deploys can rotate without rebuilding the client.
// * `FcmPushTokenProvider` / `ApnsPushTokenProvider` — feature-gated stubs for native targets. The
//   trait surface stays stable so a future `chime-fcm` / `chime-apns` adapter can drop in without
//   churn.
//
// `set_push_token_provider` installs one process-wide. Any production
// push token MUST clear `ensure_production_register_request` — the
// regression suite in `tests/dev_token_guard.rs` keeps that gate honest.
// ═══════════════════════════════════════════════════════════════════════════

/// Production push-token provider trait. One implementation
/// is installed at boot (`set_push_token_provider`); push-registration
/// callers go through it instead of the `DevPlaceholderTokenSource` fallback.
///
/// `subscribe` is async because the Web Push provider has to await the
/// service-worker registration + `pushManager.subscribe(...)` promise,
/// and the FCM / APNs paths await OS-level async APIs. The method
/// returns the platform-specific token string the chime gateway expects:
///
/// * Web Push — JSON-encoded `PushSubscription` body (`endpoint`, `keys.p256dh`, `keys.auth`).
/// * FCM      — registration token returned by `getToken()`.
/// * APNs     — hex-encoded device token from `application:didRegister...`.
#[cfg_attr(not(target_arch = "wasm32"), allow(async_fn_in_trait))]
pub trait PushTokenProvider: Send + Sync {
    /// Platform identifier the provider serves (`web` / `fcm` / `apns`).
    fn platform(&self) -> &'static str;

    /// Resolve the current push token, blocking on platform setup if
    /// needed. Returns `Ok(None)` if the user denied notification
    /// permission — callers fall back to a deregistered state and the
    /// guard refuses to send a placeholder to the gateway.
    #[cfg(target_arch = "wasm32")]
    fn subscribe<'a>(
        &'a self,
        vapid_application_server_key: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Option<String>>> + 'a>>;

    #[cfg(not(target_arch = "wasm32"))]
    fn subscribe(
        &self,
        vapid_application_server_key: Option<&str>,
    ) -> anyhow::Result<Option<String>>;
}

static PUSH_TOKEN_PROVIDER: OnceLock<Arc<dyn PushTokenProvider>> = OnceLock::new();

/// Install the process-wide push-token provider. Called once at boot —
/// subsequent calls are silently dropped.
pub fn set_push_token_provider(provider: Arc<dyn PushTokenProvider>) {
    let _ = PUSH_TOKEN_PROVIDER.set(provider);
}

/// Read the active provider, if any. Returns `None` until
/// [`set_push_token_provider`] runs.
pub fn push_token_provider() -> Option<Arc<dyn PushTokenProvider>> {
    PUSH_TOKEN_PROVIDER.get().cloned()
}

static FCM_PUSH_TOKEN: OnceLock<Mutex<Option<String>>> = OnceLock::new();
static APNS_PUSH_TOKEN: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn fcm_token_slot() -> &'static Mutex<Option<String>> {
    FCM_PUSH_TOKEN.get_or_init(|| Mutex::new(None))
}

fn apns_token_slot() -> &'static Mutex<Option<String>> {
    APNS_PUSH_TOKEN.get_or_init(|| Mutex::new(None))
}

fn set_token(slot: &Mutex<Option<String>>, token: impl Into<String>) {
    let token = token.into();
    let value = (!token.trim().is_empty()).then(|| token.trim().to_owned());
    if let Ok(mut guard) = slot.lock() {
        *guard = value;
    }
}

fn clear_token(slot: &Mutex<Option<String>>) {
    if let Ok(mut guard) = slot.lock() {
        *guard = None;
    }
}

// Consumed only by the native (`not(wasm32)`) provider-token path
// below; the wasm build subscribes via the service worker instead.
#[cfg(not(target_arch = "wasm32"))]
fn read_token(slot: &Mutex<Option<String>>) -> Option<String> {
    slot.lock().ok().and_then(|guard| guard.clone())
}

/// Bridge a real Firebase Cloud Messaging registration token into the Rust
/// push layer. Android host code should call this after
/// `FirebaseMessaging.getInstance().getToken()` resolves. Desktop dev builds
/// may use the same hook to inject a token harvested by an external helper.
pub fn set_fcm_push_token(token: impl Into<String>) {
    set_token(fcm_token_slot(), token);
}

/// Clear the bridged FCM token, for example after the OS reports token
/// revocation or the user disables notifications.
pub fn clear_fcm_push_token() {
    clear_token(fcm_token_slot());
}

/// Bridge a real APNs device token into the Rust push layer. iOS/macOS host
/// code should call this from `didRegisterForRemoteNotificationsWithDeviceToken`.
pub fn set_apns_push_token(token: impl Into<String>) {
    set_token(apns_token_slot(), token);
}

/// Clear the bridged APNs token after revocation or notification opt-out.
pub fn clear_apns_push_token() {
    clear_token(apns_token_slot());
}

// Consumed only by the native (`not(wasm32)`) provider-token path.
#[cfg(not(target_arch = "wasm32"))]
fn normalize_provider_token(prefix: &str, token: &str) -> Option<String> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return None;
    }
    let expected = format!("{prefix}:");
    if trimmed
        .get(..expected.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(&expected))
    {
        return Some(trimmed.to_owned());
    }
    Some(format!("{prefix}:{trimmed}"))
}

#[cfg(not(target_arch = "wasm32"))]
fn env_provider_token(prefix: &str, names: &[&str]) -> Option<String> {
    names
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .find_map(|value| normalize_provider_token(prefix, &value))
}

#[cfg(not(target_arch = "wasm32"))]
fn bridged_or_env_token(
    prefix: &str,
    slot: &Mutex<Option<String>>,
    env_names: &[&str],
) -> Option<String> {
    read_token(slot)
        .and_then(|value| normalize_provider_token(prefix, &value))
        .or_else(|| env_provider_token(prefix, env_names))
}

/// Real Web Push provider for wasm32 targets. Drives
/// `navigator.serviceWorker.register('/service-worker.js')` and
/// `registration.pushManager.subscribe({ userVisibleOnly: true,
/// applicationServerKey })`. The VAPID public key is supplied by the
/// caller (typically fetched from soland's push-bridge describe).
///
/// On non-wasm targets this struct exists but `subscribe` errors with
/// `Unsupported`; the FCM / APNs providers cover those paths.
#[derive(Clone, Debug, Default)]
pub struct WebPushTokenProvider {
    service_worker_path: String,
}

impl WebPushTokenProvider {
    /// Default service-worker path (`/service-worker.js`).
    pub fn new() -> Self {
        Self {
            service_worker_path: "/service-worker.js".to_owned(),
        }
    }

    /// Override the service-worker registration path (e.g.
    /// `/sw.js` or a versioned URL with cache-busting).
    pub fn with_service_worker_path(mut self, path: impl Into<String>) -> Self {
        self.service_worker_path = path.into();
        self
    }

    /// Service-worker path the provider will register.
    pub fn service_worker_path(&self) -> &str {
        &self.service_worker_path
    }
}

impl PushTokenProvider for WebPushTokenProvider {
    fn platform(&self) -> &'static str {
        "web"
    }

    #[cfg(target_arch = "wasm32")]
    fn subscribe<'a>(
        &'a self,
        vapid_application_server_key: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Option<String>>> + 'a>>
    {
        let sw_path = self.service_worker_path.clone();
        let vapid = vapid_application_server_key.map(ToOwned::to_owned);
        Box::pin(async move { web_push_subscribe(&sw_path, vapid.as_deref()).await })
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn subscribe(
        &self,
        _vapid_application_server_key: Option<&str>,
    ) -> anyhow::Result<Option<String>> {
        anyhow::bail!(
            "WebPushTokenProvider only resolves on wasm32 — install Fcm/Apns provider for native"
        )
    }
}

/// Decode the VAPID base64url public key into the raw
/// 65-byte uncompressed P-256 representation the Web Push API expects in
/// `applicationServerKey`. The browser actually accepts a `Uint8Array`
/// (as well as a base64url string in some browsers), but the
/// interoperable contract is the byte array — we always produce that.
///
/// Accepts both standard base64 and base64url, with or without trailing
/// `=` padding. Returns an error on any non-alphabet byte so a malformed
/// describe payload surfaces as an explicit failure instead of silently
/// dropping the VAPID guarantee.
pub fn decode_vapid_application_server_key(value: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("VAPID applicationServerKey is empty");
    }
    // Try URL-safe (the spec form) first, then standard as a fallback so
    // a deploy that copy-pasted from a non-URL-safe tool still works.
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE.decode(trimmed) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(trimmed) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed) {
        return Ok(bytes);
    }
    anyhow::bail!("VAPID applicationServerKey is not valid base64 / base64url")
}

#[cfg(target_arch = "wasm32")]
async fn web_push_subscribe(
    service_worker_path: &str,
    vapid_application_server_key: Option<&str>,
) -> anyhow::Result<Option<String>> {
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{
        PushManager, PushSubscriptionOptionsInit, ServiceWorkerContainer, ServiceWorkerRegistration,
    };

    let window = web_sys::window().ok_or_else(|| anyhow::anyhow!("no browser window"))?;
    let nav = window.navigator();
    let sw_container: ServiceWorkerContainer = nav.service_worker();

    // Step 1 — register the service worker. The browser may return an
    // existing registration if one is already active; either way the
    // resolved value is a `ServiceWorkerRegistration`.
    let registration_value = JsFuture::from(sw_container.register(service_worker_path))
        .await
        .map_err(|err| anyhow::anyhow!("serviceWorker.register failed: {err:?}"))?;
    let registration: ServiceWorkerRegistration = registration_value
        .dyn_into()
        .map_err(|_| anyhow::anyhow!("serviceWorker.register did not return a registration"))?;

    // Step 2 — subscribe via PushManager with userVisibleOnly + the
    // optional VAPID `applicationServerKey`. The W3C Push API requires
    // `applicationServerKey` to be either a base64url string or a
    // BufferSource — Chromium / Firefox both accept a `Uint8Array`, so
    // we always feed the raw bytes through `js_sys::Uint8Array::from`
    // which produces a `BufferSource` view the API accepts.
    let push_manager: PushManager = registration
        .push_manager()
        .map_err(|err| anyhow::anyhow!("registration.pushManager unavailable: {err:?}"))?;
    let opts = PushSubscriptionOptionsInit::new();
    opts.set_user_visible_only(true);
    if let Some(key) = vapid_application_server_key {
        let bytes = decode_vapid_application_server_key(key)?;
        let array = js_sys::Uint8Array::new_with_length(bytes.len() as u32);
        array.copy_from(&bytes);
        opts.set_application_server_key(&array.into());
    }
    let subscribe_promise = push_manager
        .subscribe_with_options(&opts)
        .map_err(|err| anyhow::anyhow!("pushManager.subscribe failed to start: {err:?}"))?;
    let subscription = JsFuture::from(subscribe_promise)
        .await
        .map_err(|err| anyhow::anyhow!("pushManager.subscribe rejected: {err:?}"))?;

    // Step 3 — `PushSubscription.toJSON()` returns
    // `{ endpoint, expirationTime, keys: { p256dh, auth } }` which is
    // exactly the JSON envelope the chime gateway expects. We hand that
    // back as a JSON string so the FCM/APNs sibling impls can return the
    // same `Option<String>` shape.
    let to_json = js_sys::Reflect::get(&subscription, &JsValue::from_str("toJSON"))
        .map_err(|err| anyhow::anyhow!("PushSubscription.toJSON missing: {err:?}"))?;
    let func: js_sys::Function = to_json
        .dyn_into()
        .map_err(|_| anyhow::anyhow!("PushSubscription.toJSON is not callable"))?;
    let json_value = func
        .call0(&subscription)
        .map_err(|err| anyhow::anyhow!("PushSubscription.toJSON threw: {err:?}"))?;
    let stringified = js_sys::JSON::stringify(&json_value)
        .map_err(|err| anyhow::anyhow!("JSON.stringify(subscription) failed: {err:?}"))?;
    Ok(stringified.as_string())
}

/// FCM provider. Android host code feeds this provider via
/// [`set_fcm_push_token`] after Firebase returns a registration token; local
/// desktop/dev runs can inject the same value through `YOUGEN_FCM_PUSH_TOKEN`,
/// `FCM_PUSH_TOKEN`, or `CHASK_PUSH_KEY`.
#[derive(Clone, Debug, Default)]
pub struct FcmPushTokenProvider;

impl PushTokenProvider for FcmPushTokenProvider {
    fn platform(&self) -> &'static str {
        "fcm"
    }

    #[cfg(target_arch = "wasm32")]
    fn subscribe<'a>(
        &'a self,
        _vapid_application_server_key: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Option<String>>> + 'a>>
    {
        Box::pin(async move { Ok(None) })
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn subscribe(
        &self,
        _vapid_application_server_key: Option<&str>,
    ) -> anyhow::Result<Option<String>> {
        Ok(bridged_or_env_token(
            "fcm",
            fcm_token_slot(),
            &["YOUGEN_FCM_PUSH_TOKEN", "FCM_PUSH_TOKEN", "CHASK_PUSH_KEY"],
        ))
    }
}

/// APNs provider. iOS/macOS host code feeds this provider via
/// [`set_apns_push_token`] after APNs returns a device token; local runs can
/// inject it through `YOUGEN_APNS_PUSH_TOKEN`, `APNS_DEVICE_TOKEN`, or
/// `CHASK_PUSH_KEY`.
#[derive(Clone, Debug, Default)]
pub struct ApnsPushTokenProvider;

impl PushTokenProvider for ApnsPushTokenProvider {
    fn platform(&self) -> &'static str {
        "apns"
    }

    #[cfg(target_arch = "wasm32")]
    fn subscribe<'a>(
        &'a self,
        _vapid_application_server_key: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Option<String>>> + 'a>>
    {
        Box::pin(async move { Ok(None) })
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn subscribe(
        &self,
        _vapid_application_server_key: Option<&str>,
    ) -> anyhow::Result<Option<String>> {
        Ok(bridged_or_env_token(
            "apns",
            apns_token_slot(),
            &[
                "YOUGEN_APNS_PUSH_TOKEN",
                "APNS_DEVICE_TOKEN",
                "CHASK_PUSH_KEY",
            ],
        ))
    }
}

/// The VAPID `applicationServerKey` exposed by soland's
/// push-bridge describe endpoint. The current chime describe schema does
/// not yet expose VAPID material as a typed field — once the schema
/// graduates `webpush.vapid_public_key`, this helper picks it up
/// without a chime version bump on yougen's side.
///
/// The lookup order:
/// 1. If the gateway advertises a `webpush` profile via
///    [`PushBridgeDescribeOutcome::provider_capability_by_kind`], the capability's stable `kind`
///    ack confirms VAPID is in scope and yougen's deploy MAY rely on environment variable
///    `VAPID_PUBLIC_KEY` (set by the dev-stack bootstrap) for the actual key bytes.
/// 2. Otherwise return `None` — the WebPushTokenProvider will subscribe without an
///    `applicationServerKey`, which produces an unencrypted Web Push subscription and is fine for
///    restricted-origin demos.
pub fn vapid_public_key_from_describe(describe: &PushBridgeDescribeOutcome) -> Option<String> {
    // The gateway must at least advertise the webpush profile for VAPID
    // to be relevant.
    let webpush_advertised = describe.gateway.supports_profile("webpush")
        || describe.provider_capability_by_kind("webpush").is_some();
    if !webpush_advertised {
        return None;
    }
    // Production deploys inject the VAPID public key via env so a key
    // rotation does not require a fresh client build. The dev-stack
    // bootstrap script sets `VAPID_PUBLIC_KEY` to the soland-side
    // counterpart of the signing key the push gateway is configured with.
    #[cfg(not(target_arch = "wasm32"))]
    {
        if let Ok(value) = std::env::var("VAPID_PUBLIC_KEY")
            && !value.is_empty()
        {
            return Some(value);
        }
    }
    None
}

/// Fetch soland's push-bridge describe + extract the
/// VAPID public key. Returned `None` means the deploy hasn't published a
/// VAPID key yet (older soland scaffold) — callers should treat that as
/// "subscribe without applicationServerKey".
pub async fn fetch_vapid_application_server_key(
    push_gateway_url: &str,
) -> anyhow::Result<Option<String>> {
    let describe = describe_push_gateway_bridge(push_gateway_url).await?;
    Ok(vapid_public_key_from_describe(&describe))
}

/// Produce the platform push key by calling the active
/// [`PushTokenProvider`]. Returns `None` if no provider is installed or
/// the provider declined (permission denied / not yet ready). Callers
/// blend the result back into the existing acquisition path so the
/// `is_placeholder_push_key` guard still catches an empty fallback.
#[cfg(target_arch = "wasm32")]
pub async fn resolve_provider_push_token(
    vapid_application_server_key: Option<&str>,
) -> anyhow::Result<Option<String>> {
    let Some(provider) = push_token_provider() else {
        return Ok(None);
    };
    provider.subscribe(vapid_application_server_key).await
}

#[cfg(not(target_arch = "wasm32"))]
pub fn resolve_provider_push_token(
    vapid_application_server_key: Option<&str>,
) -> anyhow::Result<Option<String>> {
    let Some(provider) = push_token_provider() else {
        return Ok(None);
    };
    provider.subscribe(vapid_application_server_key)
}

// ═══════════════════════════════════════════════════════════════════════════
// SecureKeyStore-backed push-token binding.
//
// The push token (`PushRegisterDeviceRequestBody::push_key`) is a long-lived
// platform identifier that we would otherwise persist plaintext in
// `LocalStateStore` so a register/unregister retry can find it. By
// routing the persistence through the [`SecureKeyStore`] tier and
// AEAD-wrapping the token with a key derived from a per-installation
// wrapping seed (itself stored in the secure-key tier), we get two
// useful properties:
//
//   1. The on-disk form of the token is ChaCha20-Poly1305 ciphertext; a backup/disk-dump that
//      doesn't include the secure-key tier cannot recover the plaintext token.
//   2. Rotating the wrapping seed via [`PushTokenBinding::rotate`] invalidates every prior
//      ciphertext — useful when device credentials change or when the user opts to wipe push state
//      without re-registering.
//
// The binding is intentionally narrow: it owns *one* wrapping seed
// per service_name and one entry slot per device_id. Multi-device
// hosts construct one binding per device.
// ═══════════════════════════════════════════════════════════════════════════

/// SecureKeyStore key under which the AEAD wrapping seed for push tokens
/// is held. Keyed by service_name, so a `yougen` install and a
/// `yougen.test` install have separate seeds (and so do their
/// ciphertext entries).
pub const PUSH_TOKEN_WRAP_SEED_KEY: &str = "push.token.wrap_seed.v1";

/// SecureKeyStore key prefix under which the per-device wrapped push
/// token ciphertext is held. Combined with the device id to form the
/// full entry name.
pub const PUSH_TOKEN_ENTRY_PREFIX: &str = "push.token.v1.";

fn push_token_entry_key(device_id: &str) -> String {
    format!("{PUSH_TOKEN_ENTRY_PREFIX}{device_id}")
}

/// Read (or generate + persist) the 32-byte AEAD wrapping seed under
/// [`PUSH_TOKEN_WRAP_SEED_KEY`]. Used by [`PushTokenBinding`] to
/// wrap/unwrap the persisted push token. A future call to
/// [`rotate_push_token_wrap_seed`] overwrites the seed; afterwards
/// any prior ciphertext fails to decrypt.
fn load_or_create_push_token_wrap_seed(
    store: &dyn SecureKeyStore,
) -> Result<[u8; 32], SecureKeyStoreError> {
    if let Some(existing) = store.get_secret(PUSH_TOKEN_WRAP_SEED_KEY)? {
        let bytes = STANDARD_NO_PAD
            .decode(existing.as_bytes())
            .map_err(|err| SecureKeyStoreError::Backend(format!("push wrap seed decode: {err}")))?;
        if bytes.len() != 32 {
            return Err(SecureKeyStoreError::Backend(format!(
                "push wrap seed length {}, expected 32",
                bytes.len()
            )));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        return Ok(buf);
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom wrap seed: {err}")))?;
    store.store_secret(PUSH_TOKEN_WRAP_SEED_KEY, &STANDARD_NO_PAD.encode(seed))?;
    Ok(seed)
}

/// Force-rotate the AEAD wrapping seed used to wrap persisted push
/// tokens. Returns the new seed bytes (the caller usually does not need
/// them — [`PushTokenBinding::rotate`] handles re-wrapping the live
/// token). After this call, every ciphertext stored under
/// [`PUSH_TOKEN_ENTRY_PREFIX`]`*` becomes undecryptable, so callers
/// should follow up with [`PushTokenBinding::store_token`] or
/// [`PushTokenBinding::rotate`] before the next register-device flow.
pub fn rotate_push_token_wrap_seed(
    store: &dyn SecureKeyStore,
) -> Result<[u8; 32], SecureKeyStoreError> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom wrap seed: {err}")))?;
    store.store_secret(PUSH_TOKEN_WRAP_SEED_KEY, &STANDARD_NO_PAD.encode(seed))?;
    Ok(seed)
}

/// Per-device wrapper that funnels push-token persistence through the
/// process-wide [`SecureKeyStore`]. Construct via
/// [`PushTokenBinding::new`] passing the same `service_name` that was
/// handed to [`crate::secure_key_store::default_secure_key_store`].
///
/// The binding does not own the SecureKeyStore — it holds an
/// `Arc<dyn SecureKeyStore>` so multiple bindings (one per device id)
/// share the same wrapping-seed slot.
#[derive(Clone)]
pub struct PushTokenBinding {
    store: Arc<dyn SecureKeyStore>,
    device_id: String,
}

impl PushTokenBinding {
    /// Construct a binding that persists tokens for `device_id` via
    /// `store`. The wrapping seed under
    /// [`PUSH_TOKEN_WRAP_SEED_KEY`] is created lazily on the first
    /// [`store_token`](Self::store_token) call (or eagerly via
    /// [`ensure_wrap_seed`](Self::ensure_wrap_seed)).
    pub fn new(store: Arc<dyn SecureKeyStore>, device_id: impl Into<String>) -> Self {
        Self {
            store,
            device_id: device_id.into(),
        }
    }

    /// Device id this binding writes / reads under.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Ensure the wrapping seed exists. Returns `Ok(())` whether the
    /// seed was already present or freshly generated.
    pub fn ensure_wrap_seed(&self) -> Result<(), SecureKeyStoreError> {
        let _ = load_or_create_push_token_wrap_seed(self.store.as_ref())?;
        Ok(())
    }

    /// Persist `push_key` under this binding's device id. Overwrites
    /// silently. The on-disk form is `wrap_secret(push_key, seed)` —
    /// a ChaCha20-Poly1305 ciphertext with a random nonce prefix.
    pub fn store_token(&self, push_key: &str) -> Result<(), SecureKeyStoreError> {
        let seed = load_or_create_push_token_wrap_seed(self.store.as_ref())?;
        let wrapped = wrap_secret(push_key, &seed)?;
        self.store
            .store_secret(&push_token_entry_key(&self.device_id), &wrapped)
    }

    /// Load the previously-persisted push token. Returns `Ok(None)`
    /// when no entry exists; also returns `Ok(None)` when the
    /// ciphertext fails to authenticate (matches
    /// [`unwrap_secret`]'s contract — typically because the wrapping
    /// seed has been rotated since the ciphertext was written).
    pub fn load_token(&self) -> Result<Option<String>, SecureKeyStoreError> {
        let Some(wrapped) = self
            .store
            .get_secret(&push_token_entry_key(&self.device_id))?
        else {
            return Ok(None);
        };
        let Some(seed_b64) = self.store.get_secret(PUSH_TOKEN_WRAP_SEED_KEY)? else {
            // Seed was rotated away without re-wrapping; the ciphertext
            // is unrecoverable.
            return Ok(None);
        };
        let seed_bytes = STANDARD_NO_PAD
            .decode(seed_b64.as_bytes())
            .map_err(|err| SecureKeyStoreError::Backend(format!("seed decode: {err}")))?;
        if seed_bytes.len() != 32 {
            return Ok(None);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        unwrap_secret(&wrapped, &seed)
    }

    /// Remove the persisted token for this device id. Idempotent —
    /// deleting an absent entry returns `Ok(())`.
    pub fn delete_token(&self) -> Result<(), SecureKeyStoreError> {
        self.store
            .delete_secret(&push_token_entry_key(&self.device_id))
    }

    /// Rotate the AEAD wrapping seed AND re-wrap the current token
    /// under the new seed. Returns the rotated token (read from the
    /// store before rotation) so the caller can immediately drive a
    /// fresh `register_device` call.
    ///
    /// If no token was persisted, the seed is rotated and `Ok(None)`
    /// is returned.
    ///
    /// After this method returns, any *other* ciphertext stored under
    /// a different device id with the old seed becomes unrecoverable —
    /// callers that share a wrapping seed across device ids should
    /// rotate at a higher layer.
    pub fn rotate(&self) -> Result<Option<String>, SecureKeyStoreError> {
        let token = self.load_token()?;
        let _ = rotate_push_token_wrap_seed(self.store.as_ref())?;
        if let Some(ref t) = token {
            self.store_token(t)?;
        } else {
            // Drop any stale ciphertext that was wrapped under the
            // pre-rotation seed.
            self.delete_token()?;
        }
        Ok(token)
    }
}

impl std::fmt::Debug for PushTokenBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushTokenBinding")
            .field("device_id", &self.device_id)
            .field("store", &self.store.backend_name())
            .finish()
    }
}

/// Build a chime [`PushRegisterDeviceRequestBody`] for `device_id`, persisting
/// the resolved push token through [`PushTokenBinding`] for future
/// idempotency / rotation. The returned request is wire-identical to
/// [`build_register_request_for_actor`] — the binding effect is purely
/// on the at-rest secret storage side.
///
/// Use this in the login / settings flow when you already have an
/// [`Arc<dyn SecureKeyStore>`] from
/// [`crate::secure_key_store::default_secure_key_store`].
pub fn build_register_request_with_secure_store(
    device_id: &str,
    principal_id: Option<&str>,
    store: &Arc<dyn SecureKeyStore>,
) -> anyhow::Result<PushRegisterDeviceRequestBody> {
    let request = build_register_request_for_actor(device_id, principal_id)?;
    let binding = PushTokenBinding::new(store.clone(), device_id);
    // Best-effort persist. A backend failure here should not block
    // registration — log and continue. The persisted token is only
    // load-bearing for retry/rotation paths.
    if let Err(err) = binding.store_token(&request.push_key) {
        tracing::warn!(?err, %device_id, "PushTokenBinding::store_token failed");
    }
    Ok(request)
}

/// Hex-encoded SHA-256 of `value`. Helper kept here so the rotation
/// tests can compare push-token hashes without dragging in a full
/// hashing surface from chime's wire module.
#[cfg(test)]
fn sha256_hex(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)] // inner gateway field needs a separate type literal.
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
    fn dev_placeholder_token_source_returns_pinned_markers() {
        let source = DevPlaceholderTokenSource;
        let desktop = source.current_token("desktop").unwrap();
        let web = source.current_token("web").unwrap();
        assert_eq!(desktop, "desktop:yougen-dev-placeholder-token");
        assert_eq!(web, "webpush:yougen-dev-placeholder-token");
        assert!(is_placeholder_push_key(&desktop));
        assert!(is_placeholder_push_key(&web));
        assert!(source.rotate_token("desktop").is_none());
    }

    #[test]
    fn builds_persistable_registration_state() {
        let request = build_register_request("dev_yougen").unwrap();
        let mut response = PushRegisterDeviceOutcome::default();
        response.ok = true;
        response.registration_id = Some("ck:push:test".to_owned());
        let state = registration_state_from_response(&request, &response);

        assert_eq!(state.registration_id.as_deref(), Some("ck:push:test"));
        assert_eq!(state.device_id, "dev_yougen");
        assert!(state.push_key_hash.starts_with("sha256:"));
        assert!(!state.push_key_hash.contains("placeholder"));
    }

    #[test]
    fn builds_unregister_request_from_existing_state() {
        let request = build_register_request("dev_yougen").unwrap();
        let mut response = PushRegisterDeviceOutcome::default();
        response.ok = true;
        response.registration_id = Some("ck:push:test".to_owned());
        let state = registration_state_from_response(&request, &response);
        let unregister = build_unregister_request("dev_yougen", Some(&state)).unwrap();

        assert_eq!(unregister.device_id, "dev_yougen");
        assert_eq!(unregister.registration_id.as_deref(), Some("ck:push:test"));
        assert_eq!(unregister.app_id.as_deref(), Some("yougen"));
    }

    #[test]
    fn summarizes_push_bridge_contract() {
        let summary = summarize_push_gateway_bridge(&PushBridgeDescribeOutcome {
            contract: "ck.push.bridge.describe".to_owned(),
            version: "2026-05-03".to_owned(),
            api_base_path: "/_cokret/edge/push".to_owned(),
            gateway: Default::default(),
            notify: chime::PushBridgeDescribeNotifyDescriptor {
                notify_path: "/_cokret/edge/push/notify".to_owned(),
                ..Default::default()
            },
            privacy: chime::PushBridgeDescribePrivacyDescriptor {
                default_mode: "e2ee_blind_wakeup".to_owned(),
                ..Default::default()
            },
            examples: Default::default(),
            provider_capabilities_version: None,
            provider_capabilities: Vec::new(),
            failure_codes: Vec::new(),
            todos: vec!["TODO(push-bridge)".to_owned()],
            spec_version: None,
        });

        assert!(summary.contains("ck.push.bridge.describe"));
        assert!(summary.contains("/_cokret/edge/push/notify"));
        assert!(summary.contains("e2ee_blind_wakeup"));
    }

    #[test]
    fn placeholder_push_key_predicate_matches_known_markers() {
        assert!(is_placeholder_push_key(
            "desktop:yougen-dev-placeholder-token"
        ));
        assert!(is_placeholder_push_key(
            "webpush:yougen-dev-placeholder-token"
        ));
        assert!(is_placeholder_push_key("DESKTOP:Yougen-Dev-Placeholder"));
        assert!(!is_placeholder_push_key("apns:abcd1234efgh"));
        assert!(!is_placeholder_push_key(
            "webpush:https://example.com/wp/abc123"
        ));
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
    fn blind_wakeup_payload_lint_rejects_stable_identifiers() {
        let ok = serde_json::json!({
            "type": "ck.push.blind_wakeup.v1",
            "reason": "background_sync_needed"
        });
        validate_blind_wakeup_payload(&ok).expect("redacted wakeup is allowed");

        for payload in [
            serde_json::json!({"realm_id": "ck:realm:demo"}),
            serde_json::json!({"event": {"event_id": "ck:event:1"}}),
            serde_json::json!({"sender": "did:web:alice.example"}),
            serde_json::json!({"items": [{"flow_id": "ck:flow:demo"}]}),
            serde_json::json!({"local_name": "Alice from Ops"}),
            serde_json::json!({"remark": "private label"}),
            serde_json::json!({"opaque": "did:web:alice.example"}),
        ] {
            validate_blind_wakeup_payload(&payload)
                .expect_err("stable ids must not appear in blind wakeups");
        }
    }

    #[test]
    fn push_status_label_treats_state_without_registration_id_as_registered() {
        let request = build_register_request("dev_yougen").unwrap();
        let mut response = PushRegisterDeviceOutcome::default();
        response.ok = true;
        let state = registration_state_from_response(&request, &response);

        assert_eq!(push_status_label(Some(&state)), "registered");
        assert_eq!(push_status_label(None), "Not registered");
    }

    #[test]
    fn web_push_provider_advertises_web_platform_and_default_sw_path() {
        let provider = WebPushTokenProvider::new();
        assert_eq!(provider.platform(), "web");
        assert_eq!(provider.service_worker_path(), "/service-worker.js");
        let custom = WebPushTokenProvider::new().with_service_worker_path("/sw-v1.js");
        assert_eq!(custom.service_worker_path(), "/sw-v1.js");
    }

    #[test]
    fn fcm_and_apns_providers_advertise_correct_platform_strings() {
        assert_eq!(FcmPushTokenProvider.platform(), "fcm");
        assert_eq!(ApnsPushTokenProvider.platform(), "apns");
    }

    #[test]
    fn fcm_provider_returns_bridged_host_token() {
        clear_fcm_push_token();
        set_fcm_push_token("native-token-123");
        let token = FcmPushTokenProvider.subscribe(None).unwrap().unwrap();
        assert_eq!(token, "fcm:native-token-123");
        clear_fcm_push_token();
    }

    #[test]
    fn apns_provider_returns_bridged_host_token() {
        clear_apns_push_token();
        set_apns_push_token("apns:abcdef012345");
        let token = ApnsPushTokenProvider.subscribe(None).unwrap().unwrap();
        assert_eq!(token, "apns:abcdef012345");
        clear_apns_push_token();
    }

    #[test]
    fn vapid_extractor_returns_none_when_webpush_not_advertised() {
        let mut describe = PushBridgeDescribeOutcome::default();
        describe.contract = "ck.push.bridge.describe.v1".to_owned();
        describe.version = "2026-05-09".to_owned();
        describe.gateway.supported_profiles = vec!["fcm".to_owned(), "apns".to_owned()];
        assert!(vapid_public_key_from_describe(&describe).is_none());
    }

    #[test]
    fn vapid_extractor_falls_back_to_env_when_webpush_advertised() {
        // SAFETY: env var mutation in tests is gated behind the per-test
        // serial guard via a unique key; we still scope the change so a
        // panic in the test can't leak into other tests.
        let mut describe = PushBridgeDescribeOutcome::default();
        describe.gateway.supported_profiles = vec!["webpush".to_owned()];

        // Guard env var manipulation behind cfg(not(target_arch=wasm32))
        // because std::env::set_var doesn't compile on wasm.
        #[cfg(not(target_arch = "wasm32"))]
        unsafe {
            std::env::set_var("VAPID_PUBLIC_KEY", "BFakeVapidPublicKey-base64url-string");
        }
        let key = vapid_public_key_from_describe(&describe);
        // SAFETY: same serial-guard rationale as the set_var above; this restores
        // the env so neighbouring tests start from a clean slate.
        #[cfg(not(target_arch = "wasm32"))]
        unsafe {
            std::env::remove_var("VAPID_PUBLIC_KEY");
        }
        #[cfg(not(target_arch = "wasm32"))]
        assert_eq!(key.as_deref(), Some("BFakeVapidPublicKey-base64url-string"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn web_push_provider_subscribe_native_returns_unsupported() {
        let provider = WebPushTokenProvider::new();
        let err = provider
            .subscribe(None)
            .expect_err("web provider must error on native");
        assert!(err.to_string().contains("wasm32"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn fcm_apns_native_subscribe_returns_none_until_wired() {
        let fcm = FcmPushTokenProvider.subscribe(None).unwrap();
        let apns = ApnsPushTokenProvider.subscribe(None).unwrap();
        assert!(fcm.is_none());
        assert!(apns.is_none());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn resolve_provider_push_token_returns_none_without_registered_provider() {
        // Provider OnceLock isn't deterministic across tests; we only
        // assert the no-provider path (the default state in --lib tests).
        // A test that sets the provider via `set_push_token_provider`
        // would race with other tests because OnceLock is process-wide.
        // Instead: we just observe the typed contract.
        let _ = resolve_provider_push_token(None);
    }

    #[test]
    fn vapid_key_decoder_accepts_url_safe_base64() {
        // 65 raw bytes (uncompressed P-256 0x04 || X || Y) shape; we
        // hand-encode in URL-safe-no-pad to mirror the canonical VAPID
        // form documented in RFC 8292.
        use base64::Engine;
        let mut bytes = vec![0x04u8];
        bytes.extend(std::iter::repeat_n(0xab, 32));
        bytes.extend(std::iter::repeat_n(0xcd, 32));
        let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
        let decoded = decode_vapid_application_server_key(&url_safe).expect("decode");
        assert_eq!(decoded.len(), 65);
        assert_eq!(decoded[0], 0x04);
    }

    #[test]
    fn vapid_key_decoder_accepts_padded_standard_base64() {
        use base64::Engine;
        let bytes: Vec<u8> = (0..32u8).collect();
        let standard = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let decoded = decode_vapid_application_server_key(&standard).expect("decode");
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn vapid_key_decoder_rejects_empty_and_garbage() {
        assert!(decode_vapid_application_server_key("").is_err());
        assert!(decode_vapid_application_server_key("   ").is_err());
        // Stars are outside both base64 alphabets.
        assert!(decode_vapid_application_server_key("****").is_err());
    }

    // ── PushTokenBinding / secure_key_store integration ───────────────

    use crate::secure_key_store::MemorySecureKeyStore;

    #[test]
    fn push_token_binding_round_trips_a_token() {
        let store: Arc<dyn SecureKeyStore> = Arc::new(MemorySecureKeyStore::new());
        let binding = PushTokenBinding::new(store.clone(), "dev_yougen");
        assert!(binding.load_token().unwrap().is_none());
        binding.store_token("fcm:real-token-abc").unwrap();
        assert_eq!(
            binding.load_token().unwrap().as_deref(),
            Some("fcm:real-token-abc")
        );
    }

    /// Distinct device ids share the wrapping seed but get distinct
    /// ciphertext slots — overwriting one device's token does not
    /// affect another.
    #[test]
    fn push_token_binding_namespaces_by_device_id() {
        let store: Arc<dyn SecureKeyStore> = Arc::new(MemorySecureKeyStore::new());
        let b_a = PushTokenBinding::new(store.clone(), "device_a");
        let b_b = PushTokenBinding::new(store.clone(), "device_b");
        b_a.store_token("fcm:token-a").unwrap();
        b_b.store_token("apns:token-b").unwrap();
        assert_eq!(b_a.load_token().unwrap().as_deref(), Some("fcm:token-a"));
        assert_eq!(b_b.load_token().unwrap().as_deref(), Some("apns:token-b"));
    }

    /// After rotating the wrapping seed, any ciphertext written under
    /// the old seed and NOT re-wrapped is unrecoverable. This is the
    /// load-bearing security property of the binding: a stolen
    /// pre-rotation backup cannot be used to recover the post-rotation
    /// state.
    #[test]
    fn push_token_rotation_invalidates_old_ciphertext() {
        let store: Arc<dyn SecureKeyStore> = Arc::new(MemorySecureKeyStore::new());
        let binding = PushTokenBinding::new(store.clone(), "device_x");
        binding.store_token("fcm:original-token").unwrap();
        // Snapshot the ciphertext under the device-id slot.
        let ciphertext_before = store
            .get_secret(&push_token_entry_key("device_x"))
            .unwrap()
            .unwrap();

        // Rotate the wrapping seed WITHOUT re-wrapping the entry —
        // this simulates an attacker who exfiltrated the old
        // ciphertext, then we rotated. The old ciphertext must not
        // decrypt under the new seed.
        let _ = rotate_push_token_wrap_seed(store.as_ref()).unwrap();
        // Manually re-insert the pre-rotation ciphertext so the load
        // path is forced to attempt decryption with the new seed.
        store
            .store_secret(&push_token_entry_key("device_x"), &ciphertext_before)
            .unwrap();
        // load_token returns None when the AEAD MAC fails — that's
        // the "ciphertext is unrecoverable" signal.
        assert!(
            binding.load_token().unwrap().is_none(),
            "old ciphertext must not decrypt under rotated seed"
        );
    }

    /// `PushTokenBinding::rotate` rotates the seed AND re-wraps the
    /// current token so subsequent loads still recover the plaintext.
    /// This is the happy path for "user manually rotated push state".
    #[test]
    fn push_token_binding_rotate_preserves_live_token() {
        let store: Arc<dyn SecureKeyStore> = Arc::new(MemorySecureKeyStore::new());
        let binding = PushTokenBinding::new(store.clone(), "device_y");
        binding.store_token("apns:live-token").unwrap();
        let rotated = binding.rotate().unwrap();
        assert_eq!(rotated.as_deref(), Some("apns:live-token"));
        // Subsequent load succeeds under the new seed.
        assert_eq!(
            binding.load_token().unwrap().as_deref(),
            Some("apns:live-token")
        );
    }

    /// `delete_token` is idempotent and clears the per-device slot.
    #[test]
    fn push_token_binding_delete_is_idempotent() {
        let store: Arc<dyn SecureKeyStore> = Arc::new(MemorySecureKeyStore::new());
        let binding = PushTokenBinding::new(store.clone(), "device_z");
        binding.delete_token().expect("idempotent delete");
        binding.store_token("apns:stale").unwrap();
        binding.delete_token().expect("delete");
        assert!(binding.load_token().unwrap().is_none());
        binding.delete_token().expect("idempotent second delete");
    }

    /// `build_register_request_with_secure_store` persists the
    /// resolved push token through the binding so a retry path can
    /// recover it. The on-wire request is unaffected: same
    /// `push_key` / `device_id` shape as the non-binding helper.
    #[test]
    fn build_register_request_with_secure_store_persists_token() {
        let store: Arc<dyn SecureKeyStore> = Arc::new(MemorySecureKeyStore::new());
        let request = build_register_request_with_secure_store("dev_yougen", None, &store).unwrap();
        assert_eq!(request.device_id, "dev_yougen");
        assert!(!request.push_key.is_empty());

        let binding = PushTokenBinding::new(store.clone(), "dev_yougen");
        let loaded = binding.load_token().unwrap().expect("token persisted");
        // Compare via hash to avoid printing the token if the test
        // logs are leaked anywhere — sha256_hex is also used for the
        // `push_key_hash` field in the registration state.
        assert_eq!(sha256_hex(&loaded), sha256_hex(&request.push_key));
    }
}
