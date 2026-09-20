//! Server error-envelope classification for the self-API client:
//! session-loss / device-authorization / cursor / frontier / rate-limit /
//! visibility-policy predicates, and the `wait_for` sync-token normalizer.

use arkret_sdk::Problem;
use reqwest::StatusCode;

use super::api_error_status_and_envelope;

/// Realm founding may repeat an exact, already-frozen Event only for the
/// Account Station's closed temporary-unavailability outcome. Other 5xx
/// responses are not silently widened into a creator-bootstrap retry.
pub(crate) fn is_realm_bootstrap_temporarily_unavailable_error(error: &anyhow::Error) -> bool {
    api_error_status_and_envelope(error).is_some_and(|(status, envelope)| {
        status == StatusCode::SERVICE_UNAVAILABLE
            && envelope.code() == arkret_sdk::error_codes::ErrorCode::TEMPORARILY_UNAVAILABLE
    })
}

/// The durable Garth queue stores the rendered transport error rather than
/// the original SDK error. Keep the fallback closed over the one registered
/// code instead of treating every HTTP/server failure as retryable.
pub(crate) fn is_realm_bootstrap_temporarily_unavailable_detail(detail: Option<&str>) -> bool {
    detail.is_some_and(|detail| {
        detail
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .any(|token| token == arkret_sdk::error_codes::ErrorCode::TEMPORARILY_UNAVAILABLE)
    })
}

/// True only while the authoritative Realm Seal frontier is not readable yet.
///
/// The frontier binding uses 404 before any accepted Seal exists and the
/// registered `frontier_unavailable` code while already-accepted Control
/// Events are waiting for durable Seal materialization. Callers may retry this
/// predicate only in a bounded workflow that is already entitled to wait for
/// that Seal; all other errors remain terminal.
pub(crate) fn is_realm_seal_frontier_pending_error(error: &anyhow::Error) -> bool {
    api_error_status_and_envelope(error).is_some_and(|(status, envelope)| {
        status == StatusCode::NOT_FOUND
            || (status == StatusCode::SERVICE_UNAVAILABLE
                && envelope.code() == arkret_sdk::error_codes::ErrorCode::FRONTIER_UNAVAILABLE)
    })
}

/// True only for the retry-safe Recovery Policy publication state where the
/// submitted Event is accepted but its covering Control Seal has not yet
/// materialized. The error registry binds `frontier_unavailable` to HTTP 503;
/// accepting a different status here would hide a server/spec binding drift.
pub(crate) fn is_recovery_policy_frontier_pending_error(error: &anyhow::Error) -> bool {
    api_error_status_and_envelope(error).is_some_and(|(status, envelope)| {
        status == StatusCode::SERVICE_UNAVAILABLE
            && envelope.code() == arkret_sdk::error_codes::ErrorCode::FRONTIER_UNAVAILABLE
    })
}

pub fn is_mls_keypackage_not_found_error(error: &anyhow::Error) -> bool {
    api_error_status_and_envelope(error).is_some_and(|(_, envelope)| {
        envelope.code() == "mls_keypackage_not_found"
            || envelope.detail.contains("mls_keypackage_not_found")
            || envelope
                .extensions
                .get("reason_code")
                .and_then(serde_json::Value::as_str)
                == Some("mls_keypackage_not_found")
    })
}

/// True when the server has *definitively* told us the session is dead.
///
/// We require an explicit error envelope code that names session loss
/// (`auth_expired`, `unauthenticated`, `soft_logged_out`)
/// on HTTP 401, or a session-grant-specific terminal denial such as
/// `capability_denied` / `session grant is not active: revoked`.
///
/// A bare 401 with no structured envelope is treated as a transient denial
/// — the caller should surface it to the user and let them retry rather
/// than wiping their session, persisted config, and bouncing them to the
/// sign-in page. The auto-retry layer in `send_with_retry` has already had
/// its shot before any error reaches the UI, so the residual 401 is most
/// often a reverse-proxy hiccup, a clock skew, or a server-side temp deny
/// — not a permanently dead token.
pub fn is_auth_expired_error(error: &anyhow::Error) -> bool {
    if is_terminal_session_grant_error(error) || is_device_revoked_error(error) {
        return true;
    }
    api_error_status_and_envelope(error).is_some_and(|(status, envelope)| {
        if status != StatusCode::UNAUTHORIZED {
            return false;
        }
        matches!(
            envelope.code(),
            code if code == arkret_sdk::error_codes::ErrorCode::AUTH_EXPIRED
                || code == arkret_sdk::error_codes::ErrorCode::UNAUTHENTICATED
                || code == arkret_sdk::error_codes::ErrorCode::SOFT_LOGGED_OUT
        )
    })
}

/// True when the authenticated account-viewer read proves that the Station has no account
/// projection for the session subject.
///
/// This predicate is intentionally only used at the account-viewer bootstrap
/// call site. A structured 404 there cannot be repaired by continuing with the
/// locally cached actor: a fresh Account Authority sign-in must recreate the
/// Station projection before the authenticated shell is usable.
pub fn is_account_viewer_projection_missing_error(error: &anyhow::Error) -> bool {
    api_error_status_and_envelope(error).is_some_and(|(status, envelope)| {
        status == StatusCode::NOT_FOUND
            && envelope.code() == arkret_sdk::error_codes::ErrorCode::NOT_FOUND
    })
}

#[cfg(test)]
/// True only for the durable accepted-but-not-sealed device revocation gate.
///
/// This state is deliberately non-terminal for local client material: the
/// client must retain recovery, session, KeyPackage and to-device state while
/// the proposal can still receive a rejected command outcome in a Seal.
/// Callers may surface or retry the blocked operation, but must not route this
/// predicate through logout cleanup.
pub fn is_device_revocation_pending_error(error: &anyhow::Error) -> bool {
    api_error_status_and_envelope(error).is_some_and(|(status, envelope)| {
        status == StatusCode::CONFLICT
            && envelope.code() == arkret_sdk::error_codes::ErrorCode::DEVICE_REVOCATION_PENDING
    })
}

/// True only when the server reports the exact device generation as revoked.
///
/// Unlike `device_revocation_pending`, this is terminal for that generation's
/// SessionGrant and authorizes generation-scoped cleanup by callers that own
/// the corresponding binding.
pub fn is_device_revoked_error(error: &anyhow::Error) -> bool {
    api_error_status_and_envelope(error).is_some_and(|(status, envelope)| {
        status == StatusCode::CONFLICT
            && envelope.code() == arkret_sdk::error_codes::ErrorCode::DEVICE_REVOKED
    })
}

/// True when local authenticated-request construction cannot obtain the
/// active session or its Station-scoped session grant.
pub fn is_authenticated_session_unavailable_error(error: &anyhow::Error) -> bool {
    let message = error.to_string();
    message.contains("no session grant is available")
        || message.contains("missing authenticated session")
}

/// True when the server rejected the request because the authenticated
/// session device is not authorized for the operation. Matches three wire
/// codes that reduce to "this device cannot establish a new account
/// Recovery Key root":
///
/// - `device_unauthorized` — soland's `ensure_key_backup_writer_device_authorized` gate (unverified
///   / unpaired device writing the account Recovery Key backup).
/// - `recovery_policy_device_unauthorized` — the recovery-policy genesis path falls back to the
///   projected device row's `device_public_key`; a session device that was never enrolled (no
///   `ak.device.authorize`) has no key there.
///
/// Recovery setup MUST treat both as fail-closed: a device that cannot pass
/// the server's verified-device gate must never establish (or locally persist)
/// a brand-new account Recovery Key root — it has to be authorized from an
/// existing device, or the user must restore with their existing Recovery Key.
pub fn is_device_not_authorized_error(error: &anyhow::Error) -> bool {
    api_error_status_and_envelope(error).is_some_and(|(_, envelope)| {
        matches!(
            envelope.code(),
            "device_unauthorized" | "recovery_policy_device_unauthorized"
        )
    })
}

/// The create-once PCR race has already been won. The client must never
/// author a second genesis; it switches the same Recovery Key and replacement
/// device into the PCR-policy re-anchor continuation.
pub fn is_pcr_genesis_already_accepted_error(error: &anyhow::Error) -> bool {
    api_error_status_and_envelope(error).is_some_and(|(_, envelope)| {
        let reason = envelope
            .extensions
            .get("reason_code")
            .and_then(serde_json::Value::as_str);
        matches!(
            reason,
            Some(
                arkret_sdk::error_codes::ReasonCode::PCR_GENESIS_CONFLICT
                    | arkret_sdk::error_codes::ReasonCode::PCR_GENESIS_NOT_FIRST
            )
        ) || envelope
            .detail
            .contains(arkret_sdk::error_codes::ReasonCode::PCR_GENESIS_CONFLICT)
            || envelope
                .detail
                .contains(arkret_sdk::error_codes::ReasonCode::PCR_GENESIS_NOT_FIRST)
    })
}

/// The identity-binding challenge is short lived and belongs to one lease
/// fence. A prepared register request that carries this terminal reason can
/// never succeed again; the client must discard only that prepared request and
/// obtain a fresh challenge from the same authoritative lease.
pub fn is_identity_creation_challenge_expired_error(error: &anyhow::Error) -> bool {
    api_error_status_and_envelope(error).is_some_and(|(status, envelope)| {
        let reason = envelope
            .extensions
            .get("reason_code")
            .and_then(serde_json::Value::as_str);
        status == StatusCode::CONFLICT
            && envelope.code() == arkret_sdk::error_codes::ErrorCode::FAILED_PRECONDITION
            && reason
                == Some(arkret_sdk::error_codes::ReasonCode::IDENTITY_CREATION_CHALLENGE_EXPIRED)
    })
}

/// The closed `invite_live_target_occupied` details, when this is that error.
///
/// `governance-objects.md` section 5.3: the Realm already holds a live directed
/// invite for the account, so the submitted create was refused with zero writes
/// and never entered canonical history. The client MUST NOT re-sign the same
/// create under a fresh `event_id` — it would hit the same slot again. The
/// returned `create_event_id` is both the occupying invite's stable idempotency
/// key and the exact `head_eq` value a release Move must carry.
pub(crate) fn invite_live_target_occupied_details(
    error: &anyhow::Error,
) -> Option<arkret_sdk::InviteLiveTargetOccupiedProblem> {
    api_error_status_and_envelope(error).and_then(|(_, envelope)| {
        envelope
            .invite_live_target_occupied_details()
            .ok()
            .flatten()
    })
}

/// True when the error envelope says the persisted coauth session grant
/// itself is terminal (revoked, expired, locked, suspended, or otherwise
/// not active). Soland currently maps these through `capability_denied`
/// because the failure happens in the session-grant capability bridge, but
/// the client must treat them as session loss, not as an ordinary Space/
/// Strand capability denial.
pub fn is_terminal_session_grant_error(error: &anyhow::Error) -> bool {
    api_error_status_and_envelope(error)
        .is_some_and(|(status, envelope)| is_terminal_session_grant_api_error(status, envelope))
}

/// True for terminal errors returned by the Account Authority session-grant
/// refresh endpoint. This is intentionally narrower than ordinary auth
/// expiry handling at the call site: only a structured refresh-specific
/// envelope is allowed to clear the persisted grant.
pub fn is_terminal_session_grant_refresh_error(error: &anyhow::Error) -> bool {
    if is_device_revoked_error(error) {
        return true;
    }
    api_error_status_and_envelope(error).is_some_and(|(status, envelope)| {
        terminal_session_grant_refresh_code(envelope.code())
            || is_terminal_session_grant_api_error(status, envelope)
    })
}

fn is_terminal_session_grant_api_error(status: StatusCode, envelope: &Problem) -> bool {
    let code = envelope.code();
    let message = envelope.detail.to_ascii_lowercase();
    (status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED)
        && (code == arkret_sdk::error_codes::ErrorCode::CAPABILITY_DENIED
            || code.ends_with(".capability_denied")
            || code == arkret_sdk::error_codes::ErrorCode::UNAUTHENTICATED
            || code == arkret_sdk::error_codes::ErrorCode::AUTH_EXPIRED)
        && terminal_session_grant_message(&message)
}

fn terminal_session_grant_refresh_code(code: &str) -> bool {
    [
        arkret_sdk::error_codes::ErrorCode::GRANT_ALREADY_CONSUMED,
        arkret_sdk::error_codes::ErrorCode::SESSION_GRANT_NOT_FOUND,
        arkret_sdk::error_codes::ErrorCode::SESSION_LOGGED_OUT,
        arkret_sdk::error_codes::ErrorCode::SIGNATURE_INVALID,
        arkret_sdk::error_codes::ErrorCode::DID_PROOF_REQUIRED,
        arkret_sdk::error_codes::ErrorCode::AUTHORIZED_GRANT_REVOKED,
    ]
    .contains(&code)
        || matches!(
            code,
            "invalid_grant" | "grant_expired" | "grant_revoked" | "session_grant_revoked"
        )
}

fn terminal_session_grant_message(message: &str) -> bool {
    message.contains("session grant")
        && (message.contains("revoked")
            || message.contains("not active")
            || message.contains("expired")
            || message.contains("locked")
            || message.contains("suspended")
            // soland's introspection wording when the private authentication process no longer
            // recognizes the grant at all (e.g. coauth restarted and lost
            // it): "session grant introspection was rejected by the Auth
            // Server". Without this arm the client kept the dead grant and
            // retried every second instead of routing to sign-in.
            || message.contains("rejected"))
}

/// Recognise a `rate_limited` (HTTP 429) error envelope from the
/// server and return its advertised `retry_after_ms` so callers can
/// sleep for the server-suggested duration instead of the generic
/// exponential backoff. Wire constant is pulled from `arkret_sdk`
/// so a spec rename can't silently de-recognise the code.
///
/// Returns `Some(retry_after_ms)` on match (with 0 when the server
/// omitted the hint), `None` otherwise.
pub fn rate_limited_retry_after(error: &anyhow::Error) -> Option<u64> {
    let (status, envelope) = api_error_status_and_envelope(error)?;
    if status != StatusCode::TOO_MANY_REQUESTS
        || envelope.code() != arkret_sdk::error_codes::ErrorCode::RATE_LIMITED
    {
        return None;
    }
    Some(envelope.retry_after_ms().unwrap_or(0))
}

/// `true` for a typed MLS Security Frontier refusal: the submitted binding does
/// not match the frontier projected from accepted control state and active MLS
/// leaves.
///
/// §2.4.1 makes this `epoch_update_required`: the scope MUST stop sending new
/// encrypted application messages until a Commit binds the current frontier.
pub(crate) fn is_mls_governance_binding_stale_error(error: &anyhow::Error) -> bool {
    api_error_status_and_envelope(error).is_some_and(|(status, envelope)| {
        let outer_code = envelope.code() == arkret_sdk::error_codes::ErrorCode::FAILED_PRECONDITION;
        let stable_reason = envelope
            .extensions
            .get("reason_code")
            .and_then(serde_json::Value::as_str)
            == Some(arkret_sdk::error_codes::ReasonCode::MLS_GOVERNANCE_BINDING_STALE)
            || envelope
                .detail
                .contains(arkret_sdk::error_codes::ReasonCode::MLS_GOVERNANCE_BINDING_STALE);
        status == StatusCode::CONFLICT && outer_code && stable_reason
    })
}

pub fn is_space_membership_denied_error(error: &anyhow::Error) -> bool {
    api_error_status_and_envelope(error).is_some_and(|(status, envelope)| {
        let code = envelope.code();
        let message = envelope.detail.to_ascii_lowercase();
        status == StatusCode::FORBIDDEN
            && (code == arkret_sdk::error_codes::ErrorCode::CAPABILITY_DENIED
                || code.ends_with(".capability_denied"))
            && message.contains("not a member")
    })
}

pub fn normalize_wait_for_sync_token(sync_token: &str) -> Option<String> {
    let sync_token = sync_token.trim();
    if sync_token.is_empty() {
        return None;
    }
    let mut tokens = Vec::new();
    for candidate in sync_token.split(',').map(str::trim) {
        if candidate.is_empty() {
            continue;
        }
        let cursor = arkret_sdk::identifiers::Cursor::new(candidate.to_owned()).ok()?;
        tokens.push(cursor.into_string());
    }
    if tokens.is_empty() {
        return None;
    }
    Some(tokens.join(","))
}

#[cfg(test)]
mod tests {
    use super::{
        is_realm_bootstrap_temporarily_unavailable_detail,
        is_realm_bootstrap_temporarily_unavailable_error,
        is_recovery_policy_frontier_pending_error,
    };

    fn api_error(status: u16, code: &str) -> anyhow::Error {
        anyhow::Error::new(arkret_sdk::http_client::Error::Api {
            status,
            error: Box::new(arkret_sdk::Problem::from_code(
                code,
                "recovery policy Seal coverage is pending",
            )),
        })
    }

    #[test]
    fn recovery_policy_frontier_retry_requires_the_registry_status_and_code() {
        assert!(is_recovery_policy_frontier_pending_error(&api_error(
            503,
            arkret_sdk::error_codes::ErrorCode::FRONTIER_UNAVAILABLE,
        )));
        assert!(!is_recovery_policy_frontier_pending_error(&api_error(
            412,
            arkret_sdk::error_codes::ErrorCode::FRONTIER_UNAVAILABLE,
        )));
        assert!(!is_recovery_policy_frontier_pending_error(&api_error(
            503,
            arkret_sdk::error_codes::ErrorCode::FAILED_PRECONDITION,
        )));
    }

    #[test]
    fn realm_bootstrap_retry_is_closed_to_temporary_unavailability() {
        assert!(is_realm_bootstrap_temporarily_unavailable_error(
            &api_error(
                503,
                arkret_sdk::error_codes::ErrorCode::TEMPORARILY_UNAVAILABLE,
            )
        ));
        assert!(!is_realm_bootstrap_temporarily_unavailable_error(
            &api_error(500, "internal_error")
        ));
        assert!(!is_realm_bootstrap_temporarily_unavailable_error(
            &api_error(503, "frontier_unavailable")
        ));
        assert!(is_realm_bootstrap_temporarily_unavailable_detail(Some(
            "Arkret API returned 503: temporarily_unavailable",
        )));
        assert!(!is_realm_bootstrap_temporarily_unavailable_detail(Some(
            "Arkret API returned 503: frontier_unavailable",
        )));
        assert!(!is_realm_bootstrap_temporarily_unavailable_detail(None));
    }
}
