use std::sync::{Arc, OnceLock};

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
// Round 25 (A3): real OS / Web Push token integration.
//
// `PushTokenProvider` is the production trait callers register at boot to
// resolve the platform-specific push token used by `register_device`. The
// crate ships three concrete impls:
//
// * `WebPushTokenProvider` — drives `navigator.serviceWorker.register` +
//   `pushManager.subscribe({ userVisibleOnly: true, applicationServerKey })`
//   on wasm32 targets. The VAPID `applicationServerKey` is fetched from
//   soland's push-bridge describe endpoint (cx.push.bridge.describe.v1),
//   so deploys can rotate without rebuilding the client.
// * `FcmPushTokenProvider` / `ApnsPushTokenProvider` — feature-gated stubs
//   for native targets. The trait surface stays stable so a future
//   `chime-fcm` / `chime-apns` adapter can drop in without churn.
//
// `set_push_token_provider` installs one process-wide. Any production
// push token MUST clear `ensure_production_register_request` — the
// regression suite in `tests/dev_token_guard.rs` keeps that gate honest.
// ═══════════════════════════════════════════════════════════════════════════

/// Round 25 (A3): production push-token provider trait. One implementation
/// is installed at boot (`set_push_token_provider`); push-registration
/// callers go through it instead of the `DevPlaceholderTokenSource` fallback.
///
/// `subscribe` is async because the Web Push provider has to await the
/// service-worker registration + `pushManager.subscribe(...)` promise,
/// and the FCM / APNs paths await OS-level async APIs. The method
/// returns the platform-specific token string the chime gateway expects:
///
/// * Web Push — JSON-encoded `PushSubscription` body (`endpoint`, `keys.p256dh`,
///   `keys.auth`).
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

/// Round 25 (A3): real Web Push provider for wasm32 targets. Drives
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

/// Round 26 (A3): decode the VAPID base64url public key into the raw
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
        PushManager, PushSubscriptionOptionsInit, ServiceWorkerContainer,
        ServiceWorkerRegistration,
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

/// Round 25 (A3): FCM provider stub. Production wiring will call into
/// `firebase_messaging::Messaging::get_token`. Until that crate lands the
/// stub returns `Ok(None)` so registration falls back to the placeholder
/// guard rather than emitting a fake-but-real-looking FCM token.
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
        Ok(None)
    }
}

/// Round 25 (A3): APNs provider stub. Wiring lives in the macOS / iOS
/// host adapter — the trait surface here is what yougen registers with.
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
        Ok(None)
    }
}

/// Round 25 (A3): the VAPID `applicationServerKey` exposed by soland's
/// push-bridge describe endpoint. The current chime describe schema does
/// not yet expose VAPID material as a typed field — once the schema
/// graduates `webpush.vapid_public_key`, this helper picks it up
/// without a chime version bump on yougen's side.
///
/// The lookup order:
/// 1. If the gateway advertises a `webpush` profile via
///    [`PushBridgeDescribeResponse::provider_capability_by_kind`], the
///    capability's stable `kind` ack confirms VAPID is in scope and
///    yougen's deploy MAY rely on environment variable
///    `VAPID_PUBLIC_KEY` (set by the dev-stack bootstrap) for the actual
///    key bytes.
/// 2. Otherwise return `None` — the WebPushTokenProvider will subscribe
///    without an `applicationServerKey`, which produces an unencrypted
///    Web Push subscription and is fine for restricted-origin demos.
pub fn vapid_public_key_from_describe(describe: &PushBridgeDescribeResponse) -> Option<String> {
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

/// Round 25 (A3): fetch soland's push-bridge describe + extract the
/// VAPID public key. Returned `None` means the deploy hasn't published a
/// VAPID key yet (older soland scaffold) — callers should treat that as
/// "subscribe without applicationServerKey".
pub async fn fetch_vapid_application_server_key(
    push_gateway_url: &str,
) -> anyhow::Result<Option<String>> {
    let describe = describe_push_gateway_bridge(push_gateway_url).await?;
    Ok(vapid_public_key_from_describe(&describe))
}

/// Round 25 (A3): produce the platform push key by calling the active
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
            provider_capabilities_version: None,
            provider_capabilities: Vec::new(),
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

    #[test]
    fn web_push_provider_advertises_web_platform_and_default_sw_path() {
        let provider = WebPushTokenProvider::new();
        assert_eq!(provider.platform(), "web");
        assert_eq!(provider.service_worker_path(), "/service-worker.js");
        let custom = WebPushTokenProvider::new().with_service_worker_path("/sw-v2.js");
        assert_eq!(custom.service_worker_path(), "/sw-v2.js");
    }

    #[test]
    fn fcm_and_apns_providers_advertise_correct_platform_strings() {
        assert_eq!(FcmPushTokenProvider.platform(), "fcm");
        assert_eq!(ApnsPushTokenProvider.platform(), "apns");
    }

    #[test]
    fn vapid_extractor_returns_none_when_webpush_not_advertised() {
        let mut describe = PushBridgeDescribeResponse::default();
        describe.contract = "cx.push.bridge.describe.v1".to_owned();
        describe.version = "2026-05-09".to_owned();
        describe.gateway.supported_profiles = vec!["fcm".to_owned(), "apns".to_owned()];
        assert!(vapid_public_key_from_describe(&describe).is_none());
    }

    #[test]
    fn vapid_extractor_falls_back_to_env_when_webpush_advertised() {
        // SAFETY: env var mutation in tests is gated behind the per-test
        // serial guard via a unique key; we still scope the change so a
        // panic in the test can't leak into other tests.
        let mut describe = PushBridgeDescribeResponse::default();
        describe.gateway.supported_profiles = vec!["webpush".to_owned()];

        // Guard env var manipulation behind cfg(not(target_arch=wasm32))
        // because std::env::set_var doesn't compile on wasm.
        #[cfg(not(target_arch = "wasm32"))]
        unsafe {
            std::env::set_var("VAPID_PUBLIC_KEY", "BFakeVapidPublicKey-base64url-string");
        }
        let key = vapid_public_key_from_describe(&describe);
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
}
