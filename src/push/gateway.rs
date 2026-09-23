//! Push gateway configuration and payload validation.
//!
//! This module owns the runtime resolution of the floria push gateway
//! URL, the development placeholder-token guards, the blind-wakeup
//! payload lint, and the human-readable describe summary used by tests.
//! Network calls belong to the Station-facing registration client; Inkson
//! never connects to the configured gateway directly.

#[cfg(test)]
use arkret_sdk::ServiceDescribe;
use chime::{ChimePushRegisterDeviceRequest, PushRegistrationState};
use serde_json::Value;

/// The previous hard-coded
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
/// settings flow should funnel through this helper before POSTing a register
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
    "petname",
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
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "registered".to_owned()),
        None => "Not registered".to_owned(),
    }
}

#[cfg(test)]
pub fn summarize_push_gateway(describe: &ServiceDescribe) -> String {
    let providers = describe
        .limits
        .extensions
        .get("x_floria_supported_providers")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",")
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "none".to_owned());
    let auth_modes = describe
        .limits
        .extensions
        .get("x_floria_auth_modes")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",")
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "none".to_owned());
    format!(
        "service_id={} kind={} protocol={} notify_operation={} providers={} auth_modes={}",
        describe.service_id,
        describe.service_kind,
        describe.protocol_version,
        arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
        providers,
        auth_modes,
    )
}
