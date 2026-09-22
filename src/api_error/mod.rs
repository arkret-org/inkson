use arkret_sdk::Problem;
use reqwest::StatusCode;
use serde_json::Value;

mod classify;

pub use classify::*;

/// Local operation context; preserves the original API error for diagnostics.
#[derive(Debug, thiserror::Error)]
#[error("invite link is unavailable")]
pub(crate) struct InviteLocatorUnavailable;

/// A received response failed decoding or protocol validation, not connectivity.
pub(crate) fn is_response_format_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<arkret_sdk::http_client::Error>(),
            Some(
                arkret_sdk::http_client::Error::Json(_)
                    | arkret_sdk::http_client::Error::Protocol(_)
                    | arkret_sdk::http_client::Error::Wire(_)
            )
        )
    })
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("Arkret API returned {status}: {error}")]
pub struct TransportClientError {
    pub status: StatusCode,
    pub error: Problem,
}

pub(crate) fn api_error_status_and_envelope(
    error: &anyhow::Error,
) -> Option<(StatusCode, &Problem)> {
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

/// Diagnostic rendering for logs and developer surfaces (tracing fields,
/// toast copy-detail affordances, bug reports) — NOT for default UI.
/// Renders the raw error and appends the server's unstable `reason_detail`
/// when one was deliberately returned. Soland exposes privacy-sensitive
/// `reason_detail` values only in development mode, so the client does not
/// need to infer deployment posture or loosen production redaction locally.
///
/// User-facing status text goes through [`display_user_facing`] instead,
/// which maps the envelope to plain-language i18n copy and keeps this raw
/// payload out of the visible message.
pub(crate) fn display_with_reason_detail(error: &anyhow::Error) -> String {
    let rendered = error.to_string();
    let Some((_, envelope)) = api_error_status_and_envelope(error) else {
        return rendered;
    };
    let Some(detail) = envelope
        .extensions
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

/// Plain-language, user-facing rendering of an API error: lead with the
/// localized copy for the well-known code / reason, never with the raw
/// envelope message or `(diagnostic: …)` payload. The raw rendering stays
/// available via [`display_with_reason_detail`] for logs and developer
/// surfaces.
///
/// Fallback tiers:
///
///   1. Envelope with a mapped code / reason code → its `error.*` i18n key.
///   2. Envelope with an unmapped code → `error.generic`.
///   3. No envelope: connection-level reqwest failures map to `error.network_unavailable`; any
///      other local (non-server) error keeps its own message — there is no server payload to hide,
///      and local validation/build errors stay meaningful.
pub fn display_user_facing(error: &anyhow::Error) -> String {
    match user_facing_error_key(error) {
        Some(key) => localized_error_copy(key),
        None => error.to_string(),
    }
}

/// Localize an `error.*` key for the current locale. Falls back to the
/// English dictionary when no Dioxus runtime / i18n context is installed
/// (unit tests, non-view threads — `tr()` panics without a runtime) so the
/// result never surfaces as a raw key.
pub(crate) fn localized_error_copy(key: &str) -> String {
    if dioxus::core::Runtime::try_current().is_some() {
        let translated = crate::i18n::tr(key);
        if translated != key {
            return translated;
        }
    }
    let english = crate::i18n::english_translations();
    english.get(key).unwrap_or(key).to_owned()
}

/// Map an API error to the i18n key of its plain-language copy, or `None`
/// when the error carries no server envelope and is not a connection-level
/// failure (caller keeps the local message).
pub(crate) fn user_facing_error_key(error: &anyhow::Error) -> Option<&'static str> {
    use arkret_sdk::error_codes::{ErrorCode, ReasonCode};

    if error.downcast_ref::<InviteLocatorUnavailable>().is_some() {
        return Some("error.invite_locator_unavailable");
    }
    if is_response_format_error(error) {
        return Some("error.server_format_mismatch");
    }

    let Some((status, envelope)) = api_error_status_and_envelope(error) else {
        // No server envelope: only connection-level failures get mapped;
        // other local errors keep their own message.
        for cause in error.chain() {
            if let Some(reqwest_error) = cause.downcast_ref::<reqwest::Error>() {
                // wasm32 reqwest has no connect/timeout classification; an
                // error without an HTTP status is a transport-level failure.
                #[cfg(not(target_arch = "wasm32"))]
                let network_level = reqwest_error.is_connect() || reqwest_error.is_timeout();
                #[cfg(target_arch = "wasm32")]
                let network_level = reqwest_error.status().is_none();
                if network_level {
                    return Some("error.network_unavailable");
                }
            }
        }
        return None;
    };

    // Typed reason codes are the most specific signal — check them first.
    // api-conventions.md §5 registers `reason_code`; a bare `reason` would be a
    // second dispatch track and is deliberately not read.
    let reason = envelope
        .extensions
        .get("reason_code")
        .and_then(Value::as_str);
    if let Some(reason) = reason {
        if envelope.code() == ErrorCode::FAILED_PRECONDITION
            && reason == "snapshot_capacity_exceeded"
        {
            return Some("error.realm_snapshot_capacity_exceeded");
        }
        if reason == ReasonCode::UNSUPPORTED_PROFILE {
            return Some("error.unsupported_profile");
        }
        if reason == ReasonCode::MLS_GOVERNANCE_BINDING_STALE {
            return Some("error.call.mls_governance_binding_stale");
        }
        if reason == ReasonCode::INVITE_LIVE_TARGET_OCCUPIED {
            return Some("error.invite.live_target_occupied");
        }
        if matches!(
            reason,
            r if r == ReasonCode::PAIRING_REQUEST_EXPIRED
                || r == ReasonCode::PROOF_INVALID
                || r == ReasonCode::AGENT_PAUSED
                || r == ReasonCode::AGENT_DEACTIVATED
                || r == ReasonCode::ACCOUNTABILITY_GRANT_MISSING
                || r == ReasonCode::APPROVAL_ALREADY_CONSUMED
        ) {
            return Some(match reason {
                r if r == ReasonCode::PAIRING_REQUEST_EXPIRED => {
                    "error.agent.pairing_request_expired"
                }
                r if r == ReasonCode::PROOF_INVALID => "error.agent.proof_invalid",
                r if r == ReasonCode::AGENT_PAUSED => "error.agent.paused",
                r if r == ReasonCode::AGENT_DEACTIVATED => "error.agent.deactivated",
                r if r == ReasonCode::ACCOUNTABILITY_GRANT_MISSING => {
                    "error.agent.accountability_grant_missing"
                }
                _ => "error.agent.approval_already_consumed",
            });
        }
        if matches!(
            reason,
            r if r == ReasonCode::RECOVERY_POLICY_MISMATCH
                || r == ReasonCode::CHALLENGE_PROOF_INVALID
        ) {
            return Some(match reason {
                r if r == ReasonCode::RECOVERY_POLICY_MISMATCH => "error.recovery.policy_mismatch",
                _ => "error.recovery.challenge_proof_invalid",
            });
        }
    }

    let code = envelope.code();
    // The media-binding code set already owns its `error.call.*`
    // copy keys; reuse that mapping instead of duplicating it.
    if let Some(rtc) = crate::media::rtc::RtcClientError::from_wire(code) {
        return Some(rtc.i18n_key());
    }
    if matches!(
        code,
        c if c == ErrorCode::AUTH_EXPIRED
            || c == ErrorCode::UNAUTHENTICATED
            || c == ErrorCode::SOFT_LOGGED_OUT
            || c == ErrorCode::SESSION_LOGGED_OUT
            || c == ErrorCode::DEVICE_REVOKED
    ) {
        return Some("error.session_expired");
    }
    // Same two wire codes as `is_device_not_authorized_error`.
    if matches!(
        code,
        c if c == ErrorCode::DEVICE_UNAUTHORIZED
            || c == "recovery_policy_device_unauthorized"
    ) {
        return Some("error.device_not_authorized");
    }
    if code == ErrorCode::RATE_LIMITED {
        return Some("error.rate_limited");
    }
    if code == ErrorCode::NOT_FOUND {
        return Some("error.not_found");
    }
    if code == ErrorCode::CAPABILITY_DENIED {
        return Some("error.permission_denied");
    }
    if code == ErrorCode::UNSUPPORTED_PROFILE {
        return Some("error.unsupported_profile");
    }
    if matches!(
        code,
        // `unsupported_operation_binding` was deleted from the error-code
        // registry as one of the codes no implementation could produce
        // (arkret-spec 0026). `unsupported_operation_version` is the
        // registered code that stayed and belongs in the same bucket.
        c if c == ErrorCode::UNSUPPORTED_EVENT_KIND
            || c == ErrorCode::UNSUPPORTED_FEATURE
            || c == ErrorCode::UNSUPPORTED_OPERATION_VERSION
            || c == ErrorCode::UNSUPPORTED_PROTOCOL_VERSION
    ) {
        return Some("error.unsupported_protocol_data");
    }
    if matches!(
        code,
        c if c == ErrorCode::SCHEMA_VIOLATION || c == ErrorCode::JSON_INVALID
    ) {
        return Some("error.invalid_protocol_data");
    }
    if code == ErrorCode::STATE_MISMATCH {
        return Some("error.realm_state_conflict");
    }
    if code == ErrorCode::SERVICE_UNAVAILABLE {
        return Some("error.server_unavailable");
    }

    // Unmapped code: fall back on the HTTP status class, then generic.
    Some(match status {
        StatusCode::TOO_MANY_REQUESTS => "error.rate_limited",
        StatusCode::NOT_FOUND => "error.not_found",
        StatusCode::SERVICE_UNAVAILABLE | StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT => {
            "error.server_unavailable"
        }
        _ => "error.generic",
    })
}

/// Decode a canonical RFC 9457 Arkret Problem response into an SDK
/// [`Problem`]. If it does not match the single current wire shape, we
/// synthesise a minimal envelope tagged
/// `ak.error.http_status` so downstream code always has something
/// well-formed to surface.
///
/// G3.Y3 — additionally, when `status` is 403 *and* the decoded
/// envelope carries a policy-shaped code, dispatch a
/// a policy-denial toast so the global feedback host picks
/// it up without each call site needing to wire its own UI. The
/// obligations array is pulled from
/// the envelope's `details["obligations"]` slot if present.
pub fn decode_arkret_error(status: StatusCode, bytes: &[u8]) -> Problem {
    let envelope = if let Ok(plain) = serde_json::from_slice::<Problem>(bytes) {
        plain
    } else {
        Problem::from_code(
            "http_status",
            format!("HTTP request failed with status {status}"),
        )
    };

    maybe_dispatch_policy_deny(status, &envelope);
    let reason = envelope
        .extensions
        .get("reason_code")
        .and_then(|v| v.as_str());
    crate::components::maybe_dispatch_circle_error(envelope.code(), reason);
    tracing::warn!(
        target: "inkson.api",
        request_id = envelope.instance.as_deref().unwrap_or("-"),
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
pub(crate) fn maybe_dispatch_policy_deny(status: StatusCode, envelope: &Problem) {
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
        .extensions
        .get("obligations")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    crate::components::push_policy_deny_toast(
        code.to_owned(),
        envelope.detail.to_owned(),
        obligations,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_locator_failure_explains_recovery_without_changing_other_not_found_errors() {
        let error = anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status: 404,
            error: Box::new(Problem::from_code("not_found", "invite locator not found")),
        });
        assert_eq!(user_facing_error_key(&error), Some("error.not_found"));
        let error = error.context(InviteLocatorUnavailable);
        assert_eq!(
            user_facing_error_key(&error),
            Some("error.invite_locator_unavailable")
        );
        assert!(display_user_facing(&error).contains("fresh invite link"));
        assert_eq!(
            api_error_status_and_envelope(&error).unwrap().0,
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn diagnostic_display_includes_returned_reason_detail() {
        let envelope = Problem::from_code(
            "direct_conversation_unavailable",
            "direct conversation is unavailable",
        )
        .with_extension(
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
            error: Box::new(Problem::from_code(
                "direct_conversation_unavailable",
                "direct conversation is unavailable",
            )),
        });

        assert_eq!(display_with_reason_detail(&error), error.to_string());
    }

    /// No i18n context is installed in unit tests, so `display_user_facing`
    /// falls back to the English dictionary — assertions run against it.
    fn english(key: &str) -> String {
        crate::i18n::english_translations()
            .get(key)
            .unwrap_or(key)
            .to_owned()
    }

    #[test]
    fn user_facing_display_hides_raw_envelope_and_reason_detail() {
        let envelope = Problem::from_code(
            "direct_conversation_unavailable",
            "direct conversation is unavailable",
        )
        .with_extension(
            "reason_detail",
            Value::String("owned Agent controller binding is stale".to_owned()),
        );
        let error = anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status: 412,
            error: Box::new(envelope),
        });

        let friendly = display_user_facing(&error);
        assert_eq!(friendly, english("error.generic"));
        assert!(!friendly.contains("direct_conversation_unavailable"));
        assert!(!friendly.contains("direct conversation is unavailable"));
        assert!(!friendly.contains("owned Agent controller binding is stale"));
        assert!(!friendly.contains("diagnostic"));
    }

    #[test]
    fn user_facing_key_maps_known_error_codes() {
        let rate_limited = sdk_api_error(429, arkret_sdk::error_codes::ErrorCode::RATE_LIMITED);
        assert_eq!(
            user_facing_error_key(&rate_limited),
            Some("error.rate_limited")
        );
        assert_eq!(
            display_user_facing(&rate_limited),
            english("error.rate_limited")
        );

        let device = sdk_api_error(403, arkret_sdk::error_codes::ErrorCode::DEVICE_UNAUTHORIZED);
        assert_eq!(
            user_facing_error_key(&device),
            Some("error.device_not_authorized")
        );

        let missing = sdk_api_error(404, arkret_sdk::error_codes::ErrorCode::NOT_FOUND);
        assert_eq!(user_facing_error_key(&missing), Some("error.not_found"));

        let expired = sdk_api_error(401, arkret_sdk::error_codes::ErrorCode::AUTH_EXPIRED);
        assert_eq!(
            user_facing_error_key(&expired),
            Some("error.session_expired")
        );
    }

    #[test]
    fn user_facing_key_maps_typed_reason_codes() {
        let envelope = Problem::from_code(
            arkret_sdk::error_codes::ErrorCode::FAILED_PRECONDITION,
            "security_frontier_digest is stale",
        )
        .with_extension(
            "reason_code",
            Value::String(
                arkret_sdk::error_codes::ReasonCode::MLS_GOVERNANCE_BINDING_STALE.to_owned(),
            ),
        );
        let error = anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status: 409,
            error: Box::new(envelope),
        });

        assert_eq!(
            user_facing_error_key(&error),
            Some("error.call.mls_governance_binding_stale")
        );
        assert_eq!(
            display_user_facing(&error),
            english("error.call.mls_governance_binding_stale")
        );
    }

    #[test]
    fn snapshot_capacity_rejection_has_explicit_non_retry_guidance() {
        let envelope = Problem::from_code(
            arkret_sdk::error_codes::ErrorCode::FAILED_PRECONDITION,
            "candidate RealmCommit would exceed the inline snapshot budget",
        )
        .with_extension(
            "reason_code",
            Value::String("snapshot_capacity_exceeded".to_owned()),
        );
        let error = anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status: 412,
            error: Box::new(envelope),
        });

        assert_eq!(
            user_facing_error_key(&error),
            Some("error.realm_snapshot_capacity_exceeded")
        );
        assert_eq!(
            display_user_facing(&error),
            english("error.realm_snapshot_capacity_exceeded")
        );
    }

    #[test]
    fn user_facing_keys_distinguish_permission_protocol_and_realm_state_failures() {
        use arkret_sdk::error_codes::ErrorCode;

        let permission = sdk_api_error(403, ErrorCode::CAPABILITY_DENIED);
        let profile = sdk_api_error(422, ErrorCode::UNSUPPORTED_PROFILE);
        let unsupported_data = sdk_api_error(422, ErrorCode::UNSUPPORTED_EVENT_KIND);
        let unsupported_version = sdk_api_error(422, ErrorCode::UNSUPPORTED_OPERATION_VERSION);
        let invalid_data = sdk_api_error(422, ErrorCode::SCHEMA_VIOLATION);
        let state_conflict = sdk_api_error(409, ErrorCode::STATE_MISMATCH);

        let cases = [
            (&permission, "error.permission_denied"),
            (&profile, "error.unsupported_profile"),
            (&unsupported_data, "error.unsupported_protocol_data"),
            (&unsupported_version, "error.unsupported_protocol_data"),
            (&invalid_data, "error.invalid_protocol_data"),
            (&state_conflict, "error.realm_state_conflict"),
        ];
        for (error, expected_key) in cases {
            assert_eq!(user_facing_error_key(error), Some(expected_key));
            assert_eq!(display_user_facing(error), english(expected_key));
        }
    }

    #[test]
    fn user_facing_key_maps_media_wire_codes_via_rtc_mapping() {
        let error = sdk_api_error(403, "focus_mismatch");
        assert_eq!(
            user_facing_error_key(&error),
            Some("error.call.focus_mismatch")
        );
    }

    #[test]
    fn user_facing_display_falls_back_to_generic_for_unknown_codes() {
        let error = sdk_api_error(418, "teapot_unmapped_code");
        assert_eq!(user_facing_error_key(&error), Some("error.generic"));
        let friendly = display_user_facing(&error);
        assert_eq!(friendly, english("error.generic"));
        assert!(!friendly.contains("teapot_unmapped_code"));
    }

    #[test]
    fn user_facing_display_keeps_local_message_without_envelope() {
        let error = anyhow::anyhow!("local validation failed: slug is invalid");
        assert_eq!(user_facing_error_key(&error), None);
        assert_eq!(
            display_user_facing(&error),
            "local validation failed: slug is invalid"
        );
    }

    fn sdk_api_error(status: u16, code: &str) -> anyhow::Error {
        anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status,
            error: Box::new(Problem::from_code(code, code)),
        })
    }

    #[test]
    fn revocation_pending_is_typed_and_never_terminal() {
        let error = sdk_api_error(
            409,
            arkret_sdk::error_codes::ErrorCode::DEVICE_REVOCATION_PENDING,
        );

        assert!(is_device_revocation_pending_error(&error));
        assert!(!is_device_revoked_error(&error));
        assert!(!is_auth_expired_error(&error));
        assert!(!is_terminal_session_grant_refresh_error(&error));
    }

    #[test]
    fn sealed_device_revocation_is_terminal_for_session_refresh() {
        let error = sdk_api_error(409, arkret_sdk::error_codes::ErrorCode::DEVICE_REVOKED);

        assert!(is_device_revoked_error(&error));
        assert!(!is_device_revocation_pending_error(&error));
        assert!(is_auth_expired_error(&error));
        assert!(is_terminal_session_grant_refresh_error(&error));
    }

    #[test]
    fn session_refresh_ignores_reserved_and_unregistered_legacy_codes() {
        for code in [
            "authorized_grant_revoked",
            "invalid_grant",
            "grant_expired",
            "grant_revoked",
            "session_grant_revoked",
        ] {
            let error = sdk_api_error(409, code);
            assert!(!is_terminal_session_grant_refresh_error(&error), "{code}");
        }
    }

    #[test]
    fn revocation_classifiers_require_registered_conflict_status() {
        let pending = sdk_api_error(
            503,
            arkret_sdk::error_codes::ErrorCode::DEVICE_REVOCATION_PENDING,
        );
        let revoked = sdk_api_error(403, arkret_sdk::error_codes::ErrorCode::DEVICE_REVOKED);

        assert!(!is_device_revocation_pending_error(&pending));
        assert!(!is_device_revoked_error(&revoked));
    }

    #[test]
    fn account_viewer_projection_missing_requires_structured_not_found() {
        let missing = sdk_api_error(404, arkret_sdk::error_codes::ErrorCode::NOT_FOUND);
        let unavailable = sdk_api_error(503, arkret_sdk::error_codes::ErrorCode::NOT_FOUND);
        let unrelated = sdk_api_error(
            404,
            arkret_sdk::error_codes::ErrorCode::UNSUPPORTED_OPERATION_VERSION,
        );

        assert!(is_account_viewer_projection_missing_error(&missing));
        assert!(!is_account_viewer_projection_missing_error(&unavailable));
        assert!(!is_account_viewer_projection_missing_error(&unrelated));
    }

    #[test]
    fn mls_stale_classifier_accepts_canonical_typed_reason() {
        let envelope = Problem::from_code(
            arkret_sdk::error_codes::ErrorCode::FAILED_PRECONDITION,
            "security_frontier_digest is stale",
        )
        .with_extension(
            "reason_code",
            Value::String(
                arkret_sdk::error_codes::ReasonCode::MLS_GOVERNANCE_BINDING_STALE.to_owned(),
            ),
        );
        let error = anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status: 409,
            error: Box::new(envelope),
        });

        assert!(is_mls_governance_binding_stale_error(&error));
    }

    #[test]
    fn mls_stale_classifier_rejects_wrong_outer_code() {
        let envelope = Problem::from_code(
            arkret_sdk::error_codes::ErrorCode::POLICY_VIOLATION,
            arkret_sdk::error_codes::ReasonCode::MLS_GOVERNANCE_BINDING_STALE,
        );
        let error = anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status: 409,
            error: Box::new(envelope),
        });

        assert!(!is_mls_governance_binding_stale_error(&error));
    }

    #[test]
    fn mls_stale_classifier_rejects_unrelated_policy_violation() {
        let envelope = Problem::from_code(
            arkret_sdk::error_codes::ErrorCode::POLICY_VIOLATION,
            "ordinary policy denial",
        );
        let error = anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status: 409,
            error: Box::new(envelope),
        });

        assert!(!is_mls_governance_binding_stale_error(&error));
    }

    #[test]
    fn identity_creation_expired_classifier_requires_structured_terminal_reason() {
        let error = anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status: 409,
            error: Box::new(
                Problem::from_code(
                    arkret_sdk::error_codes::ErrorCode::FAILED_PRECONDITION,
                    "identity binding challenge expired",
                )
                .with_extension(
                    "reason_code",
                    serde_json::json!(
                        arkret_sdk::error_codes::ReasonCode::IDENTITY_CREATION_CHALLENGE_EXPIRED
                    ),
                ),
            ),
        });

        assert!(is_identity_creation_challenge_expired_error(&error));
        for detail in [
            "lease, fence, reservation, or challenge is stale",
            "reason_code=identity_creation_challenge_expired; expired",
        ] {
            let error = anyhow::Error::new(arkret_sdk::http_client::Error::Api {
                status: 409,
                error: Box::new(Problem::from_code(
                    arkret_sdk::error_codes::ErrorCode::FAILED_PRECONDITION,
                    detail,
                )),
            });
            assert!(!is_identity_creation_challenge_expired_error(&error));
        }
    }
}
