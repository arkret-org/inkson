use reqwest::StatusCode;

use crate::api_error::{
    TransportClientError, decode_arkret_error, is_actor_seq_cas_conflict_error,
    is_auth_expired_error, is_device_not_authorized_error, is_plaintext_visibility_policy_error,
    is_space_membership_denied_error, is_terminal_session_grant_error,
    is_terminal_session_grant_refresh_error, rate_limited_retry_after,
};

fn problem_body(status: StatusCode, code: &str, detail: &str) -> Vec<u8> {
    serde_json::to_vec(
        &arkret_sdk::Problem::new(code, status.as_u16(), detail).with_instance("ak:request:test"),
    )
    .unwrap()
}

fn decode_problem(status: StatusCode, code: &str, detail: &str) -> arkret_sdk::ErrorEnvelope {
    decode_arkret_error(status, &problem_body(status, code, detail))
}

fn sdk_api_error(status: StatusCode, code: &str, detail: &str) -> anyhow::Error {
    arkret_sdk::Error::Api {
        status: status.as_u16(),
        error: Box::new(decode_problem(status, code, detail)),
    }
    .into()
}

#[test]
fn decodes_canonical_problem_details() {
    let body = serde_json::to_vec(
        &arkret_sdk::Problem::new(
            "expected_head_mismatch",
            StatusCode::CONFLICT.as_u16(),
            "expected_head mismatch",
        )
        .with_instance("ak:request:test")
        .with_extension("retry_after_ms", serde_json::json!(250))
        .with_extension("scope", serde_json::json!("repo")),
    )
    .unwrap();
    let decoded = decode_arkret_error(StatusCode::CONFLICT, &body);
    assert_eq!(decoded.code(), "expected_head_mismatch");
    assert_eq!(decoded.message(), "expected_head mismatch");
    assert_eq!(decoded.retry_after_ms(), Some(250));
    assert_eq!(decoded.details()["scope"], "repo");
}

#[test]
fn non_problem_response_falls_back_to_http_status() {
    let fallback = decode_arkret_error(StatusCode::SERVICE_UNAVAILABLE, b"busy");
    assert_eq!(fallback.code(), "http_status");
    assert!(fallback.message().contains("503 Service Unavailable"));
}

#[test]
fn decodes_canonical_error_envelope_with_request_id() {
    let body = serde_json::to_vec(
        &arkret_sdk::Problem::new(
            "capability_denied",
            StatusCode::FORBIDDEN.as_u16(),
            "actor is not a member of the event Space",
        )
        .with_instance("ak:request:01964137-0000-7000-8000-000000000010"),
    )
    .unwrap();
    let decoded = decode_arkret_error(StatusCode::FORBIDDEN, &body);

    assert_eq!(decoded.code(), "capability_denied");
    assert_eq!(
        decoded.message(),
        "actor is not a member of the event Space"
    );
    assert_eq!(
        decoded.request_id,
        "ak:request:01964137-0000-7000-8000-000000000010"
    );
}

#[test]
fn sdk_api_errors_use_same_classifiers() {
    let rate_body = serde_json::to_vec(
        &arkret_sdk::Problem::new(
            "rate_limited",
            StatusCode::TOO_MANY_REQUESTS.as_u16(),
            "slow down",
        )
        .with_instance("ak:request:test")
        .with_extension("retry_after_ms", serde_json::json!(250)),
    )
    .unwrap();
    let rate_limited: anyhow::Error = arkret_sdk::Error::Api {
        status: StatusCode::TOO_MANY_REQUESTS.as_u16(),
        error: Box::new(decode_arkret_error(
            StatusCode::TOO_MANY_REQUESTS,
            &rate_body,
        )),
    }
    .into();
    assert_eq!(rate_limited_retry_after(&rate_limited), Some(250));

    let auth_expired = sdk_api_error(StatusCode::UNAUTHORIZED, "auth_expired", "session expired");
    assert!(is_auth_expired_error(&auth_expired));

    let revoked_session_grant = sdk_api_error(
        StatusCode::FORBIDDEN,
        "capability_denied",
        "session grant is not active: revoked",
    );
    assert!(is_terminal_session_grant_error(&revoked_session_grant));

    let actor_seq_cas = sdk_api_error(
        StatusCode::CONFLICT,
        "cas_conflict",
        "actor_seq is behind the accepted frontier",
    );
    assert!(!is_actor_seq_cas_conflict_error(&actor_seq_cas));

    let consumed_refresh_grant = sdk_api_error(
        StatusCode::BAD_REQUEST,
        "grant_already_consumed",
        "session grant already consumed",
    );
    assert!(is_terminal_session_grant_refresh_error(
        &consumed_refresh_grant
    ));
}

#[test]
fn recognizes_device_not_authorized_errors() {
    // The exact wire shape soland's key-backup gate emits for an
    // unverified / unauthorized session device. Recovery setup keys its
    // fail-closed routing on this, so the classifier must match it and
    // nothing else.
    let device_unauthorized: anyhow::Error = TransportClientError {
        status: StatusCode::FORBIDDEN,
        error: decode_problem(
            StatusCode::FORBIDDEN,
            "device_unauthorized",
            "key backup write requires the authenticated session device to be verified",
        ),
    }
    .into();
    assert!(is_device_not_authorized_error(&device_unauthorized));

    // The recovery-policy genesis path emits its own code when the session
    // device was never enrolled (no projected `device_public_key`). It must
    // route to the same friendly "authorize this device" branch, not the
    // raw long-error fallback that overflows the modal.
    let recovery_policy_denial: anyhow::Error = TransportClientError {
        status: StatusCode::CONFLICT,
        error: decode_problem(
            StatusCode::CONFLICT,
            "recovery_policy_device_unauthorized",
            "recovery policy genesis requires an authorized device for did:webvh:...",
        ),
    }
    .into();
    assert!(is_device_not_authorized_error(&recovery_policy_denial));

    // A different denial (transient / unrelated capability) must NOT be
    // read as "device not authorized" — otherwise a flaky deny would wrongly
    // route the user away from generating their first Recovery Key.
    let other_denial: anyhow::Error = TransportClientError {
        status: StatusCode::FORBIDDEN,
        error: decode_problem(StatusCode::FORBIDDEN, "capability_denied", "not a member"),
    }
    .into();
    assert!(!is_device_not_authorized_error(&other_denial));
}

#[test]
fn recognizes_agent_keypackage_readiness_error() {
    let readiness_error: anyhow::Error = TransportClientError {
        status: StatusCode::CONFLICT,
        error: decode_problem(
            StatusCode::CONFLICT,
            "mls_keypackage_not_found",
            "no claimable KeyPackage",
        ),
    }
    .into();
    assert!(crate::api_error::is_mls_keypackage_not_found_error(
        &readiness_error
    ));

    let unrelated: anyhow::Error = TransportClientError {
        status: StatusCode::CONFLICT,
        error: decode_problem(StatusCode::CONFLICT, "cas_conflict", "membership changed"),
    }
    .into();
    assert!(!crate::api_error::is_mls_keypackage_not_found_error(
        &unrelated
    ));
}

#[test]
fn recognizes_auth_expired_errors() {
    let error: anyhow::Error = TransportClientError {
        status: StatusCode::UNAUTHORIZED,
        error: decode_problem(StatusCode::UNAUTHORIZED, "auth_expired", "session expired"),
    }
    .into();
    assert!(is_auth_expired_error(&error));

    // A bare 401 with no structured envelope (parse failure or a
    // reverse-proxy-injected 401 page) must NOT be treated as session
    // death. Without a body the server has not told us the token is
    // permanently invalid — it may just be a transient deny. The UI
    // surfaces the error and lets the user retry rather than wiping
    // the session and forcing a fresh sign-in.
    let bare: anyhow::Error = TransportClientError {
        status: StatusCode::UNAUTHORIZED,
        error: decode_arkret_error(StatusCode::UNAUTHORIZED, b""),
    }
    .into();
    assert!(!is_auth_expired_error(&bare));

    // Registry session-loss aliases for the same condition should all trigger.
    for code in ["unauthenticated", "soft_logged_out"] {
        let body = problem_body(StatusCode::UNAUTHORIZED, code, "unknown token");
        let aliased: anyhow::Error = TransportClientError {
            status: StatusCode::UNAUTHORIZED,
            error: decode_arkret_error(StatusCode::UNAUTHORIZED, &body),
        }
        .into();
        assert!(is_auth_expired_error(&aliased), "code {code} should match");
    }

    // A 401 carrying an unrelated error code (rate-limit, policy_denied
    // wrapped in 401, etc.) must not be misclassified as session death.
    let unrelated: anyhow::Error = TransportClientError {
        status: StatusCode::UNAUTHORIZED,
        error: decode_problem(StatusCode::UNAUTHORIZED, "rate_limited", "slow down"),
    }
    .into();
    assert!(!is_auth_expired_error(&unrelated));

    let forbidden: anyhow::Error = TransportClientError {
        status: StatusCode::FORBIDDEN,
        error: decode_problem(StatusCode::FORBIDDEN, "auth_expired", "session expired"),
    }
    .into();
    assert!(!is_auth_expired_error(&forbidden));

    let revoked_session_grant: anyhow::Error = TransportClientError {
        status: StatusCode::FORBIDDEN,
        error: decode_problem(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "session grant is not active: revoked",
        ),
    }
    .into();
    assert!(is_terminal_session_grant_error(&revoked_session_grant));
    assert!(is_auth_expired_error(&revoked_session_grant));

    let unrelated_capability_denied: anyhow::Error = TransportClientError {
        status: StatusCode::FORBIDDEN,
        error: decode_problem(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a member of the event Space",
        ),
    }
    .into();
    assert!(!is_terminal_session_grant_error(
        &unrelated_capability_denied
    ));
    assert!(!is_auth_expired_error(&unrelated_capability_denied));
}

/// Regression lock (2026-08-01): when coauth restarts and forgets a session
/// grant, soland answers every request with the exact wording below. This MUST
/// classify as a terminal session-grant loss — the client previously treated
/// it as a transient auth expiry and hammered 1-second retries forever instead
/// of clearing the session and routing to sign-in.
#[test]
fn coauth_rejected_introspection_is_a_terminal_session_grant_loss() {
    let rejected: anyhow::Error = TransportClientError {
        status: StatusCode::UNAUTHORIZED,
        error: decode_problem(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "session grant introspection was rejected by the Auth Server",
        ),
    }
    .into();
    assert!(is_terminal_session_grant_error(&rejected));
    assert!(is_auth_expired_error(&rejected));

    // A rejection that is not about the session grant must stay non-terminal.
    let unrelated: anyhow::Error = TransportClientError {
        status: StatusCode::UNAUTHORIZED,
        error: decode_problem(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "device proof was rejected",
        ),
    }
    .into();
    assert!(!is_terminal_session_grant_error(&unrelated));
}

#[test]
fn recognizes_plaintext_visibility_policy_errors() {
    let error: anyhow::Error = TransportClientError {
        status: StatusCode::FORBIDDEN,
        error: decode_problem(
            StatusCode::FORBIDDEN,
            "policy_denied",
            "private plaintext message operations require this service in plaintext_visible_services",
        ),
    }
    .into();
    assert!(is_plaintext_visibility_policy_error(&error));

    let capability_error: anyhow::Error = TransportClientError {
        status: StatusCode::FORBIDDEN,
        error: decode_problem(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "private plaintext message operations require this service in plaintext_visible_services",
        ),
    }
    .into();
    assert!(is_plaintext_visibility_policy_error(&capability_error));

    let other_policy: anyhow::Error = TransportClientError {
        status: StatusCode::FORBIDDEN,
        error: decode_problem(
            StatusCode::FORBIDDEN,
            "policy_denied",
            "only the space owner can update policy",
        ),
    }
    .into();
    assert!(!is_plaintext_visibility_policy_error(&other_policy));
}

#[test]
fn recognizes_space_membership_denied_errors() {
    let error: anyhow::Error = TransportClientError {
        status: StatusCode::FORBIDDEN,
        error: decode_problem(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "actor is not a member of the event Space",
        ),
    }
    .into();
    assert!(is_space_membership_denied_error(&error));
}
