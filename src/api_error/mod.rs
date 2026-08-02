use arkret_sdk::ErrorEnvelope;
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::Value;

mod classify;

pub use classify::*;

#[derive(Clone, Debug, thiserror::Error)]
#[error("Arkret API returned {status}: {error}")]
pub struct TransportClientError {
    pub status: StatusCode,
    pub error: ErrorEnvelope,
}

pub(crate) fn api_error_status_and_envelope(
    error: &anyhow::Error,
) -> Option<(StatusCode, &ErrorEnvelope)> {
    for cause in error.chain() {
        if let Some(api_error) = cause.downcast_ref::<TransportClientError>() {
            return Some((api_error.status, &api_error.error));
        }
        if let Some(arkret_sdk::Error::Api { status, error }) =
            cause.downcast_ref::<arkret_sdk::Error>()
        {
            return Some((StatusCode::from_u16(*status).ok()?, error.as_ref()));
        }
        if let Some(arkret_sdk::http_client::Error::Api { status, error }) =
            cause.downcast_ref::<arkret_sdk::http_client::Error>()
        {
            return Some((StatusCode::from_u16(*status).ok()?, error.as_ref()));
        }
    }
    None
}

/// Render an API error for user-facing status text, including the server's
/// unstable diagnostic when one was deliberately returned. Soland exposes
/// privacy-sensitive `reason_detail` values only in development mode, so the
/// client does not need to infer deployment posture or loosen production
/// redaction locally.
pub(crate) fn display_with_reason_detail(error: &anyhow::Error) -> String {
    let rendered = error.to_string();
    let Some((_, envelope)) = api_error_status_and_envelope(error) else {
        return rendered;
    };
    let Some(detail) = envelope
        .details()
        .get("reason_detail")
        .and_then(Value::as_str)
        .filter(|detail| !detail.trim().is_empty())
    else {
        return rendered;
    };
    if rendered.contains(detail) {
        rendered
    } else {
        format!("{rendered} (diagnostic: {detail})")
    }
}

#[derive(Debug, Deserialize)]
struct ApiErrorBody {
    error: ErrorEnvelope,
}

/// Decode a server error response into an SDK [`ErrorEnvelope`]. We try
/// the current on-the-wire shapes in order:
///
///   1. The canonical wrapped shape `{ "error": ErrorEnvelope }` (what our principal server emits
///      when its inner handler bubbles a typed envelope through the outer `ApiErrorBody`).
///   2. The canonical bare envelope `{ "ok": false, "error": { code, message }, request_id }`.
///
/// If none match, we synthesise a minimal envelope tagged
/// `ak.error.http_status` so downstream code always has something
/// well-formed to surface.
///
/// G3.Y3 — additionally, when `status` is 403 *and* the decoded
/// envelope carries a policy-shaped code, dispatch a
/// a policy-denial toast so the global feedback host picks
/// it up without each call site needing to wire its own UI. The
/// obligations array (per `authz/policy-server.md` §3) is pulled from
/// the envelope's `details["obligations"]` slot if present.
pub fn decode_arkret_error(status: StatusCode, bytes: &[u8]) -> ErrorEnvelope {
    let envelope = if let Ok(body) = serde_json::from_slice::<ApiErrorBody>(bytes) {
        body.error
    } else if let Ok(plain) = serde_json::from_slice::<ErrorEnvelope>(bytes) {
        plain
    } else {
        ErrorEnvelope::new(
            "http_status",
            format!("HTTP request failed with status {status}"),
        )
    };

    maybe_dispatch_policy_deny(status, &envelope);
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
    tracing::warn!(
        target: "inkson.api",
        request_id = %envelope.request_id,
        status = %status.as_u16(),
        code = %envelope.code(),
        "arkret error envelope decoded"
    );
    envelope
}

/// G3.Y3 — on a 403 with a policy-shaped envelope, push a
/// a warning toast onto the global queue so the `feedback::ToastHost` surfaces it
/// without each call site needing to plumb its own error UI.
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
    crate::components::push_policy_deny_toast(
        code.to_owned(),
        envelope.message().to_owned(),
        obligations,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_http_error_display_includes_returned_reason_detail() {
        let envelope = ErrorEnvelope::new(
            "direct_conversation_unavailable",
            "direct conversation is unavailable",
        )
        .with_detail(
            "reason_detail",
            Value::String("owned Agent controller binding is stale".to_owned()),
        );
        let error = anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status: 412,
            error: Box::new(envelope),
        });

        let displayed = display_with_reason_detail(&error);
        assert!(displayed.contains("direct_conversation_unavailable"));
        assert!(displayed.contains("owned Agent controller binding is stale"));
    }

    #[test]
    fn api_error_display_is_unchanged_without_reason_detail() {
        let error = anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status: 412,
            error: Box::new(ErrorEnvelope::new(
                "direct_conversation_unavailable",
                "direct conversation is unavailable",
            )),
        });

        assert_eq!(display_with_reason_detail(&error), error.to_string());
    }

    #[test]
    fn mls_stale_classifier_accepts_canonical_typed_reason() {
        let envelope = ErrorEnvelope::new(
            arkret_sdk::error::ErrorCode::FAILED_PRECONDITION,
            "security_frontier_digest is stale",
        )
        .with_detail(
            "reason_code",
            Value::String(arkret_sdk::error::ReasonCode::MLS_GOVERNANCE_BINDING_STALE.to_owned()),
        );
        let error = anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status: 409,
            error: Box::new(envelope),
        });

        assert!(is_mls_governance_binding_stale_error(&error));
    }

    #[test]
    fn mls_stale_classifier_rejects_wrong_outer_code() {
        let envelope = ErrorEnvelope::new(
            arkret_sdk::error::ErrorCode::POLICY_VIOLATION,
            arkret_sdk::error::ReasonCode::MLS_GOVERNANCE_BINDING_STALE,
        );
        let error = anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status: 409,
            error: Box::new(envelope),
        });

        assert!(!is_mls_governance_binding_stale_error(&error));
    }

    #[test]
    fn mls_stale_classifier_rejects_unrelated_policy_violation() {
        let envelope = ErrorEnvelope::new(
            arkret_sdk::error::ErrorCode::POLICY_VIOLATION,
            "ordinary policy denial",
        );
        let error = anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status: 409,
            error: Box::new(envelope),
        });

        assert!(!is_mls_governance_binding_stale_error(&error));
    }
}
