//! Production OS / Web Push token providers.
//!
//! ═══════════════════════════════════════════════════════════════════════════
//! Real OS / Web Push token integration.
//!
//! `PushTokenProvider` is the production trait callers register at boot to
//! resolve the platform-specific push token used by `register_device`. The
//! crate ships three concrete impls:
//!
//! * `WebPushTokenProvider` — drives `navigator.serviceWorker.register` + `pushManager.subscribe({
//!   userVisibleOnly: true, applicationServerKey })` on wasm32 targets. The VAPID
//!   `applicationServerKey` eligibility is discovered from the gateway's canonical
//!   `ServiceDescribe`, so deploys can rotate without rebuilding the client.
//! * `FcmPushTokenProvider` / `ApnsPushTokenProvider` — read tokens bridged by the native host or
//!   supplied through the documented local environment variables.
//!
//! `set_push_token_provider` installs one process-wide. Any production
//! push token MUST clear `ensure_production_register_request` — the
//! regression suite in `tests/dev_token_guard.rs` keeps that gate honest.
//! ═══════════════════════════════════════════════════════════════════════════
//!
//! Pure structural split out of `push::mod`; behaviour and visibility
//! are unchanged.

use std::sync::{Arc, Mutex, OnceLock};

use arkret_sdk::ServiceDescribe;

/// Production push-token provider trait. One implementation
/// is installed at boot (`set_push_token_provider`); push-registration
/// callers go through it instead of manufacturing a token when no provider is
/// available.
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
    // COR-11: recover the inner data on lock poisoning rather than silently
    // no-op'ing. The critical section never panics and never `.await`s, so the
    // guarded `Option` is always consistent; treating a poisoned lock as fatal
    // would silently disable push-token bridging with no log trail.
    *slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = value;
}

#[cfg(test)]
fn clear_token(slot: &Mutex<Option<String>>) {
    *slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
}

// Consumed only by the native (`not(wasm32)`) provider-token path
// below; the wasm build subscribes via the service worker instead.
#[cfg(not(target_arch = "wasm32"))]
fn read_token(slot: &Mutex<Option<String>>) -> Option<String> {
    // COR-11: recover the inner data on poisoning instead of degrading to `None`,
    // which would silently break push-token reads after an unrelated panic.
    slot.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Bridge a real Firebase Cloud Messaging registration token into the Rust
/// push layer. Android host code should call this after
/// `FirebaseMessaging.getInstance().getToken()` resolves. Desktop dev builds
/// may use the same hook to inject a token harvested by an external helper.
pub fn set_fcm_push_token(token: impl Into<String>) {
    set_token(fcm_token_slot(), token);
}

#[cfg(test)]
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

#[cfg(test)]
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

    #[cfg(test)]
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
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
        .map_err(|_| {
            anyhow::anyhow!("VAPID applicationServerKey is not valid base64 / base64url")
        })?;
    // COR-10: a VAPID applicationServerKey is a P-256 public key in uncompressed
    // SEC1 form — 65 bytes (`0x04 || X(32) || Y(32)`). Reject anything else up
    // front so a malformed describe surfaces a clear error here instead of an
    // opaque browser promise rejection (and so `bytes.len() as u32` can never
    // truncate on 32-bit wasm).
    if bytes.len() != 65 {
        anyhow::bail!(
            "VAPID applicationServerKey must be a 65-byte uncompressed P-256 point, got {} bytes",
            bytes.len()
        );
    }
    if bytes[0] != 0x04 {
        anyhow::bail!(
            "VAPID applicationServerKey must start with 0x04 (uncompressed SEC1 point), got 0x{:02x}",
            bytes[0]
        );
    }
    Ok(bytes)
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
/// desktop/dev runs can inject the same value through `INKSON_FCM_PUSH_TOKEN`,
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
            &["INKSON_FCM_PUSH_TOKEN", "FCM_PUSH_TOKEN", "CHASK_PUSH_KEY"],
        ))
    }
}

/// APNs provider. iOS/macOS host code feeds this provider via
/// [`set_apns_push_token`] after APNs returns a device token; local runs can
/// inject it through `INKSON_APNS_PUSH_TOKEN`, `APNS_DEVICE_TOKEN`, or
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
                "INKSON_APNS_PUSH_TOKEN",
                "APNS_DEVICE_TOKEN",
                "CHASK_PUSH_KEY",
            ],
        ))
    }
}

/// Resolve the VAPID `applicationServerKey` only when the canonical gateway
/// description advertises Web Push support.
///
/// The lookup order:
/// 1. If `ServiceDescribe.limits.x_floria_supported_providers` includes `webpush`, the gateway
///    confirms VAPID is in scope and inkson's deploy MAY rely on environment variable
///    `VAPID_PUBLIC_KEY` (set by the dev-stack bootstrap) for the actual key bytes.
/// 2. Otherwise return `None` — the WebPushTokenProvider will subscribe without an
///    `applicationServerKey`, which produces an unencrypted Web Push subscription and is fine for
///    restricted-origin demos.
pub fn vapid_public_key_from_service_describe(describe: &ServiceDescribe) -> Option<String> {
    let webpush_advertised = describe
        .limits
        .extensions
        .get("x_floria_supported_providers")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|providers| {
            providers.iter().any(|provider| {
                provider
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("webpush"))
            })
        });
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
