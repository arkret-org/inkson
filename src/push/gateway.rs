//! Push gateway configuration, describe helpers, and payload validation.
//!
//! This module owns the runtime resolution of the floria push gateway
//! URL, the development placeholder-token guards, the blind-wakeup
//! payload lint, and the bridge / integration describe fetchers and
//! their human-readable summaries. The contents are a pure structural
//! split out of `push::mod`; behaviour, visibility, and serialization
//! are unchanged.

use chime::{
    ChimePushRegisterDeviceRequest, IntegrationDescribeOutcome, PushBridgeDescribeOutcome,
    PushRegistrationState, floria_push_bridge_describe_url, floria_push_integration_describe_url,
};
use serde_json::Value;

use super::token_provider::vapid_public_key_from_describe;

/// P4 (AKP-0007 hygiene): the previous hard-coded
/// `https://push.example/_arkret/edge/push/notify` placeholder is gone.
/// We now read `INKSON_FLORIA_URL` at the call site (see
/// [`floria_gateway_url`]); when it's unset in dev we point at
/// localhost, when it's unset in prod we return an empty string and
/// the registration code no-ops rather than POSTing to a fake host.
const DEV_FLORIA_GATEWAY: &str = "http://localhost:9001/_arkret/edge/push/notify";
/// Returned by [`floria_gateway_url`] when the env var is unset and
/// we're NOT in a debug build. The chime register-device path treats
/// an empty gateway URL as "no push registration" and short-circuits
/// without contacting any remote host.
const NOOP_FLORIA_GATEWAY: &str = "";

/// Read the floria push gateway URL at runtime.
///
/// Resolution order:
/// 1. `INKSON_FLORIA_URL` env var, if non-empty.
/// 2. Debug builds (`cfg(debug_assertions)`): localhost dev gateway.
/// 3. Release builds: empty string ⇒ no-op (registration short-circuits).
pub fn floria_gateway_url() -> String {
    #[cfg(not(target_arch = "wasm32"))]
    {
        if let Ok(value) = std::env::var("INKSON_FLORIA_URL") {
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
pub const PLACEHOLDER_PUSH_KEY_MARKERS: &[&str] = &["placeholder", "inkson-dev-"];

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
/// settings strand should funnel through this helper before POSTing a register
/// request to a non-loopback push gateway.
pub fn ensure_production_register_request(
    request: &ChimePushRegisterDeviceRequest,
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
    "strand_id",
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
/// must not carry stable identities or Realm/Space/Event/Strand ids. The delivery route
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
                || value.starts_with("ak:space:")
                || value.starts_with("ak:realm:")
                || value.starts_with("ak:strand:")
                || value.starts_with("ak:event:") =>
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

/// COR-05: read/connect timeout for the (untrusted) push-gateway describe
/// fetchers. A 10s cap so a slow / half-open / stalled gateway can't hang
/// push registration indefinitely.
#[cfg(not(target_arch = "wasm32"))]
const PUSH_DESCRIBE_TIMEOUT_SECS: u64 = 10;

/// COR-06: hard cap on an untrusted describe response body before
/// deserialization, so a hostile gateway can't trigger OOM (wasm single-page
/// memory is small). 1 MiB is far above any legitimate describe manifest.
const PUSH_DESCRIBE_MAX_BODY_BYTES: usize = 1024 * 1024;

/// Build a reqwest client with the describe read timeout applied. On wasm32
/// `ClientBuilder::timeout` is unavailable (no system clock); the browser fetch
/// layer enforces its own timeouts.
fn push_describe_client() -> anyhow::Result<reqwest::Client> {
    let builder = reqwest::Client::builder();
    #[cfg(not(target_arch = "wasm32"))]
    let builder = builder.timeout(std::time::Duration::from_secs(PUSH_DESCRIBE_TIMEOUT_SECS));
    builder
        .build()
        .map_err(|err| anyhow::anyhow!("push describe client build: {err}"))
}

/// Read the response body with a hard size ceiling, then JSON-decode it.
/// Fails closed (explicit error) when the body exceeds
/// [`PUSH_DESCRIBE_MAX_BODY_BYTES`] instead of buffering unboundedly.
async fn read_capped_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    what: &str,
) -> anyhow::Result<T> {
    let bytes = response.bytes().await?;
    if bytes.len() > PUSH_DESCRIBE_MAX_BODY_BYTES {
        anyhow::bail!(
            "{what} describe body {} bytes exceeds {PUSH_DESCRIBE_MAX_BODY_BYTES} byte limit",
            bytes.len()
        );
    }
    serde_json::from_slice(&bytes)
        .map_err(|err| anyhow::anyhow!("{what} describe decode failed: {err}"))
}

pub async fn describe_push_gateway_bridge(
    push_gateway_url: &str,
) -> anyhow::Result<PushBridgeDescribeOutcome> {
    let describe_url = floria_push_bridge_describe_url(push_gateway_url)?;
    let response = push_describe_client()?.get(&describe_url).send().await?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("push gateway bridge describe returned HTTP {status}");
    }
    read_capped_json(response, "push gateway bridge").await
}

pub async fn describe_push_gateway_integration(
    push_gateway_url: &str,
) -> anyhow::Result<IntegrationDescribeOutcome> {
    let describe_url = floria_push_integration_describe_url(push_gateway_url)?;
    let response = push_describe_client()?.get(&describe_url).send().await?;
    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("push gateway integration describe returned HTTP {status}");
    }
    read_capped_json(response, "push gateway integration").await
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

pub fn summarize_push_gateway_integration(manifest: &IntegrationDescribeOutcome) -> String {
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
