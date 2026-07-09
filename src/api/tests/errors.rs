use reqwest::StatusCode;

use crate::api_error::{
    CokretApiError, decode_cokret_error, is_actor_frontier_absent_error,
    is_actor_seq_cas_conflict_error, is_auth_expired_error, is_device_not_authorized_error,
    is_invalid_cursor_error, is_plaintext_visibility_policy_error, is_snapshot_unavailable_error,
    is_space_membership_denied_error, is_terminal_session_grant_error,
    is_terminal_session_grant_refresh_error, rate_limited_retry_after, unsupported_endpoint_status,
};

fn sdk_api_error(status: StatusCode, body: &'static [u8]) -> anyhow::Error {
    cokret_sdk::Error::Api {
        status: status.as_u16(),
        error: Box::new(decode_cokret_error(status, body)),
    }
    .into()
}

#[test]
fn decodes_wrapped_cokret_error_envelope() {
    let decoded = decode_cokret_error(
        StatusCode::CONFLICT,
        br#"{"ok":false,"error":{"code":"expected_head_mismatch","message":"expected_head mismatch","retry_after_ms":250,"details":{"scope":"repo"}}}"#,
    );
    assert_eq!(decoded.code(), "expected_head_mismatch");
    assert_eq!(decoded.message(), "expected_head mismatch");
    assert_eq!(decoded.retry_after_ms(), Some(250));
    assert_eq!(decoded.details()["scope"], "repo");
}

#[test]
fn decodes_plain_error_envelope_and_falls_back() {
    let decoded = decode_cokret_error(
        StatusCode::BAD_REQUEST,
        br#"{"ok":false,"error":{"code":"invalid_param","message":"invalid did"}}"#,
    );
    assert_eq!(decoded.code(), "invalid_param");

    // The SDK's ErrorEnvelope::new strips the `ck.error.` prefix in
    // `canonical_error_code` and we depend on that canonicalization so
    // downstream comparisons against the registry shape match.
    let fallback = decode_cokret_error(StatusCode::SERVICE_UNAVAILABLE, b"busy");
    assert_eq!(fallback.code(), "http_status");
    assert!(fallback.message().contains("503 Service Unavailable"));
}

#[test]
fn decodes_canonical_error_envelope_with_request_id() {
    let decoded = decode_cokret_error(
        StatusCode::FORBIDDEN,
        br#"{"ok":false,"error":{"code":"capability_denied","message":"actor is not a member of the event Space"},"request_id":"ak:request:01964137-0000-7000-8000-000000000010"}"#,
    );

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
fn decodes_wrapped_error_envelope_without_inner_request_id() {
    let decoded = decode_cokret_error(
        StatusCode::UNAUTHORIZED,
        br#"{"ok":false,"error":{"ok":false,"error":{"code":"auth_expired","message":"session expired"}},"request_id":"ak:request:01964137-0000-7000-8000-000000000011"}"#,
    );

    assert_eq!(decoded.code(), "auth_expired");
    assert_eq!(decoded.message(), "session expired");
    assert_eq!(
        decoded.request_id,
        "ak:request:01964137-0000-7000-8000-000000000011"
    );
}

#[test]
fn sdk_api_errors_use_same_classifiers() {
    let rate_limited = sdk_api_error(
        StatusCode::TOO_MANY_REQUESTS,
        br#"{"ok":false,"error":{"code":"rate_limited","message":"slow down","retry_after_ms":250}}"#,
    );
    assert_eq!(rate_limited_retry_after(&rate_limited), Some(250));

    let snapshot_missing = sdk_api_error(
        StatusCode::NOT_FOUND,
        br#"{"ok":false,"error":{"code":"unrecognized_endpoint","message":"snapshot head unavailable"}}"#,
    );
    assert!(is_snapshot_unavailable_error(&snapshot_missing));

    let invalid_cursor = sdk_api_error(
        StatusCode::BAD_REQUEST,
        br#"{"ok":false,"error":{"code":"invalid_param","message":"invalid cursor"}}"#,
    );
    assert!(is_invalid_cursor_error(&invalid_cursor));

    let auth_expired = sdk_api_error(
        StatusCode::UNAUTHORIZED,
        br#"{"ok":false,"error":{"code":"auth_expired","message":"session expired"}}"#,
    );
    assert!(is_auth_expired_error(&auth_expired));

    let revoked_session_grant = sdk_api_error(
        StatusCode::FORBIDDEN,
        br#"{"ok":false,"error":{"code":"capability_denied","message":"session grant is not active: revoked"}}"#,
    );
    assert!(is_terminal_session_grant_error(&revoked_session_grant));

    let unsupported_endpoint = sdk_api_error(
        StatusCode::NOT_IMPLEMENTED,
        br#"{"ok":false,"error":{"code":"not_implemented","message":"account_data unavailable"}}"#,
    );
    assert_eq!(
        unsupported_endpoint_status(&unsupported_endpoint),
        Some(StatusCode::NOT_IMPLEMENTED)
    );

    let actor_frontier_absent = sdk_api_error(
        StatusCode::NOT_FOUND,
        br#"{"ok":false,"error":{"code":"not_found","message":"actor frontier not found"}}"#,
    );
    assert!(is_actor_frontier_absent_error(&actor_frontier_absent));

    let actor_seq_cas = sdk_api_error(
        StatusCode::CONFLICT,
        br#"{"ok":false,"error":{"code":"cas_conflict","message":"actor_seq is behind the accepted frontier"}}"#,
    );
    assert!(is_actor_seq_cas_conflict_error(&actor_seq_cas));

    let consumed_refresh_grant = sdk_api_error(
        StatusCode::BAD_REQUEST,
        br#"{"ok":false,"error":{"code":"grant_already_consumed","message":"session grant already consumed"}}"#,
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
    let device_not_authorized: anyhow::Error = CokretApiError {
        status: StatusCode::FORBIDDEN,
        error: decode_cokret_error(
            StatusCode::FORBIDDEN,
            br#"{"ok":false,"error":{"code":"device_not_authorized","message":"key backup write requires the authenticated session device to be verified"}}"#,
        ),
    }
    .into();
    assert!(is_device_not_authorized_error(&device_not_authorized));

    // The recovery-policy genesis path emits its own code when the session
    // device was never enrolled (no projected `device_public_key`). It must
    // route to the same friendly "authorize this device" branch, not the
    // raw long-error fallback that overflows the modal.
    let recovery_policy_denial: anyhow::Error = CokretApiError {
        status: StatusCode::CONFLICT,
        error: decode_cokret_error(
            StatusCode::CONFLICT,
            br#"{"ok":false,"error":{"code":"recovery_policy_device_not_authorized","message":"recovery policy genesis requires an authorized device for did:webvh:..."}}"#,
        ),
    }
    .into();
    assert!(is_device_not_authorized_error(&recovery_policy_denial));

    // The `service_attested` enrollment path's "no authority designated"
    // rejection is likewise a device-authorization problem from the user's
    // point of view.
    let authority_denial: anyhow::Error = CokretApiError {
        status: StatusCode::FORBIDDEN,
        error: decode_cokret_error(
            StatusCode::FORBIDDEN,
            br#"{"ok":false,"error":{"code":"device_enrollment_authority_not_designated","message":"no enrollment authority designated"}}"#,
        ),
    }
    .into();
    assert!(is_device_not_authorized_error(&authority_denial));

    // A different denial (transient / unrelated capability) must NOT be
    // read as "device not authorized" — otherwise a flaky deny would wrongly
    // route the user away from generating their first Recovery Key.
    let other_denial: anyhow::Error = CokretApiError {
        status: StatusCode::FORBIDDEN,
        error: decode_cokret_error(
            StatusCode::FORBIDDEN,
            br#"{"ok":false,"error":{"code":"capability_denied","message":"not a member"}}"#,
        ),
    }
    .into();
    assert!(!is_device_not_authorized_error(&other_denial));
}

#[test]
fn recognizes_auth_expired_errors() {
    let error: anyhow::Error = CokretApiError {
        status: StatusCode::UNAUTHORIZED,
        error: decode_cokret_error(
            StatusCode::UNAUTHORIZED,
            br#"{"ok":false,"error":{"code":"auth_expired","message":"session expired"}}"#,
        ),
    }
    .into();
    assert!(is_auth_expired_error(&error));

    // A bare 401 with no structured envelope (parse failure or a
    // reverse-proxy-injected 401 page) must NOT be treated as session
    // death. Without a body the server has not told us the token is
    // permanently invalid — it may just be a transient deny. The UI
    // surfaces the error and lets the user retry rather than wiping
    // the session and forcing a fresh sign-in.
    let bare: anyhow::Error = CokretApiError {
        status: StatusCode::UNAUTHORIZED,
        error: decode_cokret_error(StatusCode::UNAUTHORIZED, b""),
    }
    .into();
    assert!(!is_auth_expired_error(&bare));

    // Registry session-loss aliases for the same condition should all trigger.
    for code in ["unauthenticated", "soft_logged_out"] {
        let body =
            format!(r#"{{"ok":false,"error":{{"code":"{code}","message":"unknown token"}}}}"#);
        let aliased: anyhow::Error = CokretApiError {
            status: StatusCode::UNAUTHORIZED,
            error: decode_cokret_error(StatusCode::UNAUTHORIZED, body.as_bytes()),
        }
        .into();
        assert!(is_auth_expired_error(&aliased), "code {code} should match");
    }

    // A 401 carrying an unrelated error code (rate-limit, policy_denied
    // wrapped in 401, etc.) must not be misclassified as session death.
    let unrelated: anyhow::Error = CokretApiError {
        status: StatusCode::UNAUTHORIZED,
        error: decode_cokret_error(
            StatusCode::UNAUTHORIZED,
            br#"{"ok":false,"error":{"code":"rate_limited","message":"slow down"}}"#,
        ),
    }
    .into();
    assert!(!is_auth_expired_error(&unrelated));

    let forbidden: anyhow::Error = CokretApiError {
        status: StatusCode::FORBIDDEN,
        error: decode_cokret_error(
            StatusCode::FORBIDDEN,
            br#"{"ok":false,"error":{"code":"auth_expired","message":"session expired"}}"#,
        ),
    }
    .into();
    assert!(!is_auth_expired_error(&forbidden));

    let revoked_session_grant: anyhow::Error = CokretApiError {
        status: StatusCode::FORBIDDEN,
        error: decode_cokret_error(
            StatusCode::FORBIDDEN,
            br#"{"ok":false,"error":{"code":"capability_denied","message":"session grant is not active: revoked"}}"#,
        ),
    }
    .into();
    assert!(is_terminal_session_grant_error(&revoked_session_grant));
    assert!(is_auth_expired_error(&revoked_session_grant));

    let unrelated_capability_denied: anyhow::Error = CokretApiError {
        status: StatusCode::FORBIDDEN,
        error: decode_cokret_error(
            StatusCode::FORBIDDEN,
            br#"{"ok":false,"error":{"code":"capability_denied","message":"actor is not a member of the event Space"}}"#,
        ),
    }
    .into();
    assert!(!is_terminal_session_grant_error(
        &unrelated_capability_denied
    ));
    assert!(!is_auth_expired_error(&unrelated_capability_denied));
}

#[test]
fn recognizes_plaintext_visibility_policy_errors() {
    let error: anyhow::Error = CokretApiError {
        status: StatusCode::FORBIDDEN,
        error: decode_cokret_error(
            StatusCode::FORBIDDEN,
            br#"{"ok":false,"error":{"code":"policy_denied","message":"private plaintext message operations require this service in plaintext_visible_services"}}"#,
        ),
    }
    .into();
    assert!(is_plaintext_visibility_policy_error(&error));

    let capability_error: anyhow::Error = CokretApiError {
        status: StatusCode::FORBIDDEN,
        error: decode_cokret_error(
            StatusCode::FORBIDDEN,
            br#"{"ok":false,"error":{"code":"capability_denied","message":"private plaintext message operations require this service in plaintext_visible_services"}}"#,
        ),
    }
    .into();
    assert!(is_plaintext_visibility_policy_error(&capability_error));

    let other_policy: anyhow::Error = CokretApiError {
        status: StatusCode::FORBIDDEN,
        error: decode_cokret_error(
            StatusCode::FORBIDDEN,
            br#"{"ok":false,"error":{"code":"policy_denied","message":"only the space owner can update policy"}}"#,
        ),
    }
    .into();
    assert!(!is_plaintext_visibility_policy_error(&other_policy));
}

#[test]
fn recognizes_space_membership_denied_errors() {
    let error: anyhow::Error = CokretApiError {
        status: StatusCode::FORBIDDEN,
        error: decode_cokret_error(
            StatusCode::FORBIDDEN,
            br#"{"ok":false,"error":{"code":"capability_denied","message":"actor is not a member of the event Space"},"request_id":"ak:request:01964137-0000-7000-8000-000000000010"}"#,
        ),
    }
    .into();
    assert!(is_space_membership_denied_error(&error));
}
