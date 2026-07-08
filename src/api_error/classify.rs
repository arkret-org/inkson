//! Server error-envelope classification for the self-API client:
//! session-loss / device-authorization / cursor / frontier / rate-limit /
//! visibility-policy predicates, the `wait_for` sync-token normalizer, and the
//! blob-presign error class.

use cokret_sdk::ErrorEnvelope;
use reqwest::StatusCode;

use super::api_error_status_and_envelope;

/// True when a discovery probe failed because the endpoint does not exist on
/// this server — i.e. the routing layer returned `404 unrecognized_endpoint`
/// (see `service-http-binding.md` routing rules) rather than a transport,
/// auth, or server error.
#[cfg(test)]
pub(crate) fn is_endpoint_absent(error: &anyhow::Error) -> bool {
    api_error_status_and_envelope(error).is_some_and(|(status, _)| status == StatusCode::NOT_FOUND)
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
    use cokret_sdk::error::{
        ERROR_CODE_AUTH_EXPIRED, ERROR_CODE_SOFT_LOGGED_OUT, ERROR_CODE_UNAUTHENTICATED,
    };

    if is_terminal_session_grant_error(error) {
        return true;
    }
    api_error_status_and_envelope(error).is_some_and(|(status, envelope)| {
        if status != StatusCode::UNAUTHORIZED {
            return false;
        }
        matches!(
            envelope.code(),
            code if code == ERROR_CODE_AUTH_EXPIRED
                || code == ERROR_CODE_UNAUTHENTICATED
                || code == ERROR_CODE_SOFT_LOGGED_OUT
        )
    })
}

/// True when the server rejected the request because the authenticated
/// session device is not authorized for the operation. Matches three wire
/// codes that all reduce to "this device cannot establish a new account
/// Recovery Key root":
///
/// - `device_not_authorized` — soland's `ensure_key_backup_writer_device_authorized` gate
///   (unverified / unpaired device writing the account Recovery Key backup).
/// - `recovery_policy_device_not_authorized` — the recovery-policy genesis path falls back to the
///   projected device row's `device_public_key`; a session device that was never enrolled (no
///   `ck.device.authorize`) has no key there.
/// - `device_enrollment_authority_not_designated` — the `service_attested` enrollment path could
///   not anchor an authority for this device (device-lifecycle.md §5.4).
///
/// Recovery setup MUST treat all three as fail-closed: a device that cannot pass
/// the server's verified-device gate must never establish (or locally persist)
/// a brand-new account Recovery Key root — it has to be authorized from an
/// existing device, or the user must restore with their existing Recovery Key.
pub fn is_device_not_authorized_error(error: &anyhow::Error) -> bool {
    api_error_status_and_envelope(error).is_some_and(|(_, envelope)| {
        matches!(
            envelope.code(),
            "device_not_authorized"
                | "recovery_policy_device_not_authorized"
                | "device_enrollment_authority_not_designated"
        )
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

fn is_terminal_session_grant_api_error(status: StatusCode, envelope: &ErrorEnvelope) -> bool {
    use cokret_sdk::error::{
        ERROR_CODE_AUTH_EXPIRED, ERROR_CODE_CAPABILITY_DENIED, ERROR_CODE_UNAUTHENTICATED,
    };

    let code = envelope.code();
    let message = envelope.message().to_ascii_lowercase();
    (status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED)
        && (code == ERROR_CODE_CAPABILITY_DENIED
            || code.ends_with(".capability_denied")
            || code == ERROR_CODE_UNAUTHENTICATED
            || code == ERROR_CODE_AUTH_EXPIRED)
        && terminal_session_grant_message(&message)
}

fn terminal_session_grant_message(message: &str) -> bool {
    message.contains("session grant")
        && (message.contains("revoked")
            || message.contains("not active")
            || message.contains("expired")
            || message.contains("locked")
            || message.contains("suspended"))
}

/// Recognise a `rate_limited` (HTTP 429) error envelope from the
/// server and return its advertised `retry_after_ms` so callers can
/// sleep for the server-suggested duration instead of the generic
/// exponential backoff. Wire constant is pulled from `cokret_sdk`
/// so a spec rename can't silently de-recognise the code.
///
/// Returns `Some(retry_after_ms)` on match (with 0 when the server
/// omitted the hint), `None` otherwise.
pub fn rate_limited_retry_after(error: &anyhow::Error) -> Option<u64> {
    use cokret_sdk::error::ERROR_CODE_RATE_LIMITED;
    let (_, envelope) = api_error_status_and_envelope(error)?;
    if envelope.code() != ERROR_CODE_RATE_LIMITED {
        return None;
    }
    Some(envelope.retry_after_ms().unwrap_or(0))
}

/// `true` when account subscribe rejected the cursor — expired, invalid,
/// integrity-mismatched, or unrecognized — so the SyncEngine knows to
/// demote to a `after=None` full sync instead of looping on the same
/// broken cursor. Per client-sync.md §2/§12.3, `cursor_expired` /
/// `cursor_integrity_invalid` / `cursor_unrecognized` all recover by
/// clearing the local cursor and redoing initial sync.
pub fn is_invalid_cursor_error(error: &anyhow::Error) -> bool {
    use cokret_sdk::error::{ERROR_CODE_CURSOR_INTEGRITY_INVALID, ERROR_CODE_CURSOR_UNRECOGNIZED};
    use cokret_sdk::{
        ERROR_CODE_CURSOR_EXPIRED, ERROR_CODE_CURSOR_INVALID, ERROR_CODE_INVALID_PARAM,
    };
    api_error_status_and_envelope(error).is_some_and(|(_, envelope)| {
        let code = envelope.code();
        // `invalid_param` only counts when the message mentions the
        // cursor — soland uses it for generic schema rejections too.
        let cursor_message = envelope.message().to_lowercase().contains("cursor");
        matches!(
            code,
            code if code == ERROR_CODE_CURSOR_EXPIRED
                || code == ERROR_CODE_CURSOR_INTEGRITY_INVALID
                || code == ERROR_CODE_CURSOR_UNRECOGNIZED
        ) || (cursor_message
            && matches!(code, code if code == ERROR_CODE_INVALID_PARAM || code == ERROR_CODE_CURSOR_INVALID))
    })
}

/// `true` for `stale_frontier` — the cursor itself is still valid but the
/// service frontier lags the requested causal frontier. Per
/// client-sync.md §4 the client MUST NOT clear the cursor; it should
/// fetch the current frontier via `account/describe` / `snapshot/head`
/// (§12.3 step 2) and retry / backfill with the SAME cursor.
pub fn is_stale_frontier_error(error: &anyhow::Error) -> bool {
    use cokret_sdk::error::ERROR_CODE_STALE_FRONTIER;
    api_error_status_and_envelope(error)
        .is_some_and(|(_, envelope)| envelope.code() == ERROR_CODE_STALE_FRONTIER)
}

pub(crate) fn is_snapshot_unavailable_error(error: &anyhow::Error) -> bool {
    use cokret_sdk::error::{
        ERROR_CODE_NOT_FOUND, ERROR_CODE_NOT_IMPLEMENTED, ERROR_CODE_SNAPSHOT_UNAVAILABLE,
        ERROR_CODE_UNRECOGNIZED_ENDPOINT, ERROR_CODE_UNSUPPORTED_FEATURE,
    };

    api_error_status_and_envelope(error).is_some_and(|(status, envelope)| {
        let code = envelope.code();
        status == StatusCode::NOT_FOUND
            || matches!(
                code,
                code if code == ERROR_CODE_NOT_IMPLEMENTED
                    || code == ERROR_CODE_SNAPSHOT_UNAVAILABLE
                    || code == ERROR_CODE_NOT_FOUND
                    || code == ERROR_CODE_UNRECOGNIZED_ENDPOINT
                    || code == ERROR_CODE_UNSUPPORTED_FEATURE
            )
    })
}

pub fn is_plaintext_visibility_policy_error(error: &anyhow::Error) -> bool {
    use cokret_sdk::error::{ERROR_CODE_CAPABILITY_DENIED, ERROR_CODE_POLICY_DENIED};

    api_error_status_and_envelope(error).is_some_and(|(status, envelope)| {
        let code = envelope.code();
        status == StatusCode::FORBIDDEN
            && (code == ERROR_CODE_POLICY_DENIED
                || code == ERROR_CODE_CAPABILITY_DENIED
                || code.ends_with(".capability_denied"))
            && envelope.message().contains("plaintext_visible_services")
    })
}

pub fn is_space_membership_denied_error(error: &anyhow::Error) -> bool {
    use cokret_sdk::error::ERROR_CODE_CAPABILITY_DENIED;

    api_error_status_and_envelope(error).is_some_and(|(status, envelope)| {
        let code = envelope.code();
        let message = envelope.message().to_ascii_lowercase();
        status == StatusCode::FORBIDDEN
            && (code == ERROR_CODE_CAPABILITY_DENIED || code.ends_with(".capability_denied"))
            && message.contains("not a member")
    })
}

pub fn normalize_wait_for_sync_token(sync_token: &str) -> Option<String> {
    let sync_token = sync_token.trim();
    if sync_token.is_empty() || sync_token == "-" {
        return None;
    }
    let tokens = sync_token
        .split(',')
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        return None;
    }
    tokens
        .iter()
        .all(|candidate| {
            candidate
                .strip_prefix("ck:cursor:")
                .is_some_and(|payload| !payload.is_empty())
        })
        .then(|| tokens.join(","))
}

/// Round R2/R3 (T11) — classify a server error envelope into the four
/// fail-closed presign blob error classes. The UI MUST surface a friendly
/// (translated) message and MUST NOT retry / cache / log the presign URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobPresignError {
    LegalHoldActive,
    BlobRedacted,
    MediaPlaintextServiceNotAuthorised,
    NotAuthorised,
}

impl BlobPresignError {
    pub fn from_error(error: &anyhow::Error) -> Option<Self> {
        let (status, envelope) = api_error_status_and_envelope(error)?;
        let code = envelope.code();
        match code {
            // Round R2/R3 wire codes from cokret_sdk::error.
            "legal_hold_active" => Some(Self::LegalHoldActive),
            "blob_redacted" => Some(Self::BlobRedacted),
            "media_plaintext_service_not_authorised" => {
                Some(Self::MediaPlaintextServiceNotAuthorised)
            }
            _ => {
                if status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED {
                    Some(Self::NotAuthorised)
                } else {
                    None
                }
            }
        }
    }

    /// i18n key for the user-facing error message. Translation values are
    /// owned by [`crate::i18n`].
    pub fn i18n_key(self) -> &'static str {
        match self {
            Self::LegalHoldActive => "blob.error.legal_hold_active",
            Self::BlobRedacted => "blob.error.redacted",
            Self::MediaPlaintextServiceNotAuthorised => "blob.error.plaintext_not_authorised",
            Self::NotAuthorised => "blob.error.not_authorised",
        }
    }
}
