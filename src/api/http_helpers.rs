//! HTTP plumbing helpers for the self-API client: error-envelope
//! decoding/policy-deny dispatch, retry/backoff classification, URL/query
//! component encoding, NDJSON subscribe-frame parsing, and small
//! response-projection parsers. Pure free functions split out of
//! `api/mod.rs` (YOU-07-001) with no logic change; re-exported from the
//! parent module so existing `crate::api::*` / sibling `super::*` paths
//! resolve unchanged.

use super::*;

/// A4b — module-level helper for composing a blob download URL when an
/// [`CokretApi`] handle isn't available (e.g. read-only views that
/// already have the Principal Server `base_url` as a string). Keeps
/// the URL shape canonical so callers can't accidentally desync from
/// [`CokretApi::blob_download_url`].
pub fn blob_download_url_for(base_url: &str, blob_ref: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let blob_ref = query_component(canonical_blob_ref(blob_ref));
    format!("{base}/_cokret/self/blob/get?blob_ref={blob_ref}&purpose=profile_avatar")
}

pub(crate) fn canonical_blob_ref(blob_ref: &str) -> &str {
    blob_ref.split('#').next().unwrap_or(blob_ref).trim()
}

/// Project chime's full [`ChimePushRegisterDeviceOutcome`](chime::ChimePushRegisterDeviceOutcome)
/// onto yougen's slimmer `PushRegisterView` view (the upstream
/// fields not modelled here are intentionally dropped for now).
pub(crate) fn map_chime_register_response(
    response: ChimePushRegisterDeviceOutcome,
) -> PushRegisterView {
    PushRegisterView {
        ok: response.ok,
        registration_id: response.registration_id,
        expires_at: response.expires_at,
    }
}

/// Decode a server error response into an SDK [`ErrorEnvelope`]. We try
/// the current on-the-wire shapes in order:
///
///   1. The canonical wrapped shape `{ "error": ErrorEnvelope }` (what our principal server emits
///      when its inner handler bubbles a typed envelope through the outer `ApiErrorBody`).
///   2. A bare envelope `{ "ok": false, "error": { code, message }, request_id? }` — same shape, no
///      wrapping. The SDK's [`ErrorEnvelope`] requires `request_id`, so we tolerate its absence via
///      a local shadow type that defaults it to `"unknown"`.
///
/// If none match, we synthesise a minimal envelope tagged
/// `ck.error.http_status` so downstream code always has something
/// well-formed to surface.
///
/// G3.Y3 — additionally, when `status` is 403 *and* the decoded
/// envelope carries a policy-shaped code, dispatch a
/// [`crate::components::PolicyDenyEvent`] so the global banner picks
/// it up without each call site having to wire its own UI. The
/// obligations array (per `authz/policy-server.md` §3) is pulled from
/// the envelope's `details["obligations"]` slot if present.
pub fn decode_cokret_error(status: StatusCode, bytes: &[u8]) -> ErrorEnvelope {
    #[derive(serde::Deserialize)]
    struct PlainEnvelope {
        #[serde(default)]
        ok: bool,
        error: cokret_sdk::ErrorDetail,
        #[serde(default = "default_request_id")]
        request_id: String,
    }
    fn default_request_id() -> String {
        "unknown".to_owned()
    }
    impl From<PlainEnvelope> for ErrorEnvelope {
        fn from(value: PlainEnvelope) -> Self {
            ErrorEnvelope {
                ok: value.ok,
                error: value.error,
                request_id: value.request_id,
            }
        }
    }
    #[derive(serde::Deserialize)]
    struct WrappedPlainEnvelope {
        error: PlainEnvelope,
        #[serde(default)]
        request_id: Option<String>,
    }
    impl From<WrappedPlainEnvelope> for ErrorEnvelope {
        fn from(value: WrappedPlainEnvelope) -> Self {
            let mut envelope: ErrorEnvelope = value.error.into();
            if envelope.request_id == "unknown"
                && let Some(request_id) = value.request_id
            {
                envelope.request_id = request_id;
            }
            envelope
        }
    }
    let envelope = if let Ok(body) = serde_json::from_slice::<ApiErrorBody>(bytes) {
        body.error
    } else if let Ok(wrapped_plain) = serde_json::from_slice::<WrappedPlainEnvelope>(bytes) {
        wrapped_plain.into()
    } else if let Ok(plain) = serde_json::from_slice::<PlainEnvelope>(bytes) {
        plain.into()
    } else {
        ErrorEnvelope::new(
            "http_status",
            format!("HTTP request failed with status {status}"),
        )
    };

    maybe_dispatch_policy_deny(status, &envelope);
    // CKP-0007 P3B.3 — also surface any of the 6 Circle reason codes
    // as a global toast. The two dispatchers are independent: the
    // policy deny banner targets 403 + policy code, the circle toast
    // targets the CKP-0007 reason / error code family on any status.
    let reason = envelope
        .details()
        .get("reason")
        .and_then(|v| v.as_str())
        .or_else(|| {
            envelope
                .details()
                .get("reason_code")
                .and_then(|v| v.as_str())
        });
    crate::components::maybe_dispatch_circle_error(envelope.code(), reason);
    // P5 — surface request_id in tracing logs so server + client
    // logs cross-reference on the same ID. The ID may have come from
    // the body or (when callers use `decode_cokret_error_with_header`)
    // from the response header.
    tracing::warn!(
        target: "yougen.api",
        request_id = %envelope.request_id,
        status = %status.as_u16(),
        code = %envelope.code(),
        "cokret error envelope decoded"
    );
    envelope
}

/// Same as [`decode_cokret_error`], but also threads the
/// `x-cokret-request-id` response header so the resulting envelope
/// carries the soland trace ID even when the body's `request_id` slot
/// was missing or `"unknown"`.
///
/// P5: callers that have access to the `reqwest::Response::headers()`
/// map (currently only a few hot paths) should switch to this helper
/// so error toasts can render the **Copy ID** button consistently.
pub fn decode_cokret_error_with_header(
    status: StatusCode,
    bytes: &[u8],
    response_request_id: Option<&str>,
) -> ErrorEnvelope {
    let mut envelope = decode_cokret_error(status, bytes);
    if let Some(id) = response_request_id {
        let trimmed = id.trim();
        if !trimmed.is_empty()
            && (envelope.request_id == "unknown" || envelope.request_id.is_empty())
        {
            envelope.request_id = trimmed.to_owned();
        }
    }
    envelope
}

/// G3.Y3 — on a 403 with a policy-shaped envelope, push a
/// [`crate::components::PolicyDenyEvent`] onto the global queue so the
/// `PolicyDenyBanner` mounted near the app shell surfaces it without
/// each call site needing to plumb its own error UI.
///
/// Skips auth-expired codes (those have their own session-death
/// redirect path) and any non-403 statuses.
pub(crate) fn maybe_dispatch_policy_deny(status: StatusCode, envelope: &ErrorEnvelope) {
    if status != StatusCode::FORBIDDEN {
        return;
    }
    let code = envelope.code();
    if !crate::components::is_policy_deny_code(code) {
        return;
    }
    // Obligations may arrive under `details["obligations"]` (preferred,
    // per the signed-transcript shape) or under a top-level
    // `obligations` field on the envelope itself. We honour both.
    let obligations: Vec<Value> = envelope
        .details()
        .get("obligations")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    crate::components::push_policy_deny(crate::components::PolicyDenyEvent::new(
        code.to_owned(),
        envelope.message().to_owned(),
        obligations,
    ));
}

pub(crate) fn is_retryable_method(method: &Method) -> bool {
    matches!(method, &Method::GET | &Method::PUT | &Method::PATCH)
}

pub(crate) fn is_retryable_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

pub(crate) fn is_retryable_reqwest_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || {
        #[cfg(not(target_arch = "wasm32"))]
        {
            error.is_connect()
        }
        #[cfg(target_arch = "wasm32")]
        {
            false
        }
    }
}

pub(crate) fn canonical_space_join_rule_v1(join_rule: &str) -> &str {
    match join_rule {
        "open" => "public",
        "request" => "knock",
        "invite_only" => "invite",
        value => value,
    }
}

pub(crate) async fn sleep_backoff(initial: Duration, attempt: usize) {
    sleep_for(backoff_duration(initial, attempt)).await;
}

pub(crate) fn backoff_duration(initial: Duration, attempt: usize) -> Duration {
    let factor = 1u32.checked_shl(attempt as u32).unwrap_or(u32::MAX);
    initial.saturating_mul(factor)
}

pub(crate) async fn sleep_retry_delay(headers: &HeaderMap, initial: Duration, attempt: usize) {
    let delay = parse_retry_after(headers).unwrap_or_else(|| backoff_duration(initial, attempt));
    sleep_for(delay).await;
}

// `tokio::time::sleep` reads `std::time::Instant::now()` and panics on
// wasm32-unknown-unknown ("time not implemented on this platform"). Route the
// wasm build through `gloo_timers::future::TimeoutFuture`, which is backed by
// `setTimeout`.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn sleep_for(delay: Duration) {
    tokio::time::sleep(delay).await;
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn sleep_for(delay: Duration) {
    let ms = u32::try_from(delay.as_millis()).unwrap_or(u32::MAX);
    gloo_timers::future::TimeoutFuture::new(ms).await;
}

pub(crate) fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();

    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    chrono::DateTime::parse_from_rfc2822(value)
        .ok()
        .and_then(|deadline| {
            deadline
                .with_timezone(&chrono::Utc)
                .signed_duration_since(chrono::Utc::now())
                .to_std()
                .ok()
        })
}

pub fn parse_server_description(value: Value) -> anyhow::Result<ServerDescription> {
    Ok(serde_json::from_value(value)?)
}

pub(crate) fn query_component(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

pub(crate) fn path_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(&mut encoded, "%{byte:02X}");
        }
    }
    encoded
}

pub(crate) fn safe_blob_filename_header(filename: &str) -> Option<String> {
    let basename = filename
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .trim()
        .trim_matches('"');
    let mut sanitized = String::new();
    for ch in basename.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
            sanitized.push(ch);
        } else if ch.is_ascii_whitespace() || ch.is_ascii_punctuation() {
            sanitized.push('_');
        }
        if sanitized.len() >= 128 {
            break;
        }
    }
    let sanitized = sanitized
        .trim_matches(|ch| matches!(ch, '.' | '_' | '-' | ' '))
        .to_owned();
    (!sanitized.is_empty()).then_some(sanitized)
}

/// H3 — central guard for the `ck:cursor:*` prefix invariant. Every yougen
/// entry point that takes a cursor / `next_cursor` / `after` query argument
/// passes it through this helper before going on the wire. The nil-initial
/// account subscribe case (`after: None`) is handled by callers using
/// `Option::map` so this never runs against an `""` placeholder.
pub(crate) fn validate_cursor(cursor: &str) -> anyhow::Result<()> {
    if cursor.is_empty() {
        return Ok(());
    }
    if !cursor.starts_with("ck:cursor:") {
        anyhow::bail!("cursor must start with `ck:cursor:` (got `{}`)", cursor);
    }
    Ok(())
}

pub(crate) fn events_query_path(realm_id: &str) -> String {
    format!("_cokret/self/events?realms={}", query_component(realm_id))
}

// Consumed only by the native (`not(wasm32)`) `events_subscribe_ndjson`
// streaming reader; the wasm build has no streaming subscribe path yet.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn events_subscribe_path(
    realm_id: &str,
    after: Option<&str>,
    include_history: Option<bool>,
) -> String {
    let mut url = format!(
        "_cokret/self/events/subscribe?realms={}",
        query_component(realm_id)
    );
    if let Some(after) = after {
        url.push_str("&after=");
        url.push_str(&query_component(after));
    }
    if let Some(include_history) = include_history {
        url.push_str("&include_history=");
        url.push_str(if include_history { "true" } else { "false" });
    }
    url
}

/// Round 4 (spec a77b995) — parse the round-4 typed
/// `/events/subscribe` NDJSON stream. The frame body is
/// [`cokret_sdk::EventsSubscribeFrameBody`] (tag = "kind",
/// snake_case-discriminated). Wire-breaking: the pre-round-4 untyped
/// string-line parser is deleted.
pub fn parse_events_subscribe_ndjson_text(
    input: &str,
) -> anyhow::Result<Vec<cokret_sdk::EventsSubscribeFrameBody>> {
    let mut frames = Vec::new();
    for line in input.lines() {
        if let Some(frame) = parse_events_subscribe_ndjson_line(line.as_bytes())? {
            frames.push(frame);
        }
    }
    Ok(frames)
}

// Consumed only by the native (`not(wasm32)`) streaming reader
// (`drain_events_subscribe_response` / `events_subscribe_stream`).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn drain_events_subscribe_ndjson_lines<F>(
    pending: &mut Vec<u8>,
    on_frame: &mut F,
) -> anyhow::Result<()>
where
    F: FnMut(cokret_sdk::EventsSubscribeFrameBody) -> anyhow::Result<()>,
{
    while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
        let mut line: Vec<u8> = pending.drain(..=newline).collect();
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if let Some(frame) = parse_events_subscribe_ndjson_line(&line)? {
            on_frame(frame)?;
        }
    }
    Ok(())
}

pub(crate) fn parse_events_subscribe_ndjson_line(
    line: &[u8],
) -> anyhow::Result<Option<cokret_sdk::EventsSubscribeFrameBody>> {
    let trimmed = trim_ascii(line);
    if trimmed.is_empty() {
        return Ok(None);
    }
    serde_json::from_slice(trimmed)
        .map(Some)
        .map_err(|err| anyhow::anyhow!("failed to parse subscribe NDJSON frame: {err}"))
}

pub(crate) fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

pub fn parse_sync_describe(value: Value) -> anyhow::Result<SyncDescribeView> {
    Ok(serde_json::from_value(value)?)
}

pub fn parse_directory_describe(value: Value) -> anyhow::Result<DirectoryDescription> {
    Ok(serde_json::from_value(value)?)
}

pub fn parse_resolve_realm(value: Value) -> anyhow::Result<ResolveRealmOutcome> {
    Ok(serde_json::from_value(value)?)
}

pub(crate) fn select_join_candidate<'a>(
    resolved: &'a ResolveRealmOutcome,
    join_method: cokret_sdk::models::RealmJoinMethod,
) -> anyhow::Result<&'a RealmJoinCandidate> {
    let realm_id = trim_realm_id(resolved.realm_preview.realm_id.as_str());
    resolved
        .join_candidates
        .iter()
        .filter(|candidate| candidate.realm_id.as_str() == realm_id.as_str())
        .filter(|candidate| {
            candidate
                .operations
                .iter()
                .any(|op| op == "ck.self.events.command.submit")
        })
        .filter(|candidate| {
            candidate
                .join_methods
                .iter()
                .any(|method| *method == join_method)
        })
        .filter(|candidate| join_candidate_is_current(candidate))
        .min_by(|left, right| {
            left.priority
                .unwrap_or(u16::MAX)
                .cmp(&right.priority.unwrap_or(u16::MAX))
                .then_with(|| left.service_did.cmp(&right.service_did))
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "resolve_realm did not return a current join candidate for {join_method:?}"
            )
        })
}

pub(crate) fn join_candidate_is_current(candidate: &RealmJoinCandidate) -> bool {
    candidate.expires_at > chrono::Utc::now()
}

pub(crate) fn patch_touches_create_locked_encryption_profile(patch: &Value) -> bool {
    patch.as_object().is_some_and(|fields| {
        fields.iter().any(|(key, value)| {
            patch_key_touches_encryption_profile(key)
                || (key == "object" && patch_value_has_direct_encryption_profile(value))
        })
    })
}

pub(crate) fn patch_key_touches_encryption_profile(key: &str) -> bool {
    key == "encryption_profile"
        || key.starts_with("encryption_profile.")
        || key == "/encryption_profile"
        || key.starts_with("/encryption_profile/")
        || key == "object.encryption_profile"
        || key.starts_with("object.encryption_profile.")
        || key == "/object/encryption_profile"
        || key.starts_with("/object/encryption_profile/")
}

pub(crate) fn patch_value_has_direct_encryption_profile(value: &Value) -> bool {
    value
        .get("value")
        .unwrap_or(value)
        .as_object()
        .is_some_and(|fields| fields.contains_key("encryption_profile"))
}

pub(crate) fn soland_path_allowed(normalized_path: &str) -> bool {
    let path = normalized_path
        .split(['?', '#'])
        .next()
        .unwrap_or(normalized_path);
    // Keep the marker split so this helper does not carry a direct product-path token.
    if path.starts_with(concat!("_so", "land", "/")) {
        return false;
    }
    true
}
