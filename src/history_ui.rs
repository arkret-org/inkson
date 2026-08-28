//! Closed local reason vocabulary for MLS history UI status.
//!
//! Wire `history_not_visible` deliberately merges the two terminal cases.
//! The client retains their typed local distinction and keeps transient,
//! lost-record and quota/retry states out of the terminal bucket.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryUiReason {
    PolicyTerminal,
    ProfileFloorTerminal,
    AwaitingAuthorizedSourceResponse,
    ResponseVerificationPending,
    ServiceRecordLost,
    QuotaOrRetry,
}

impl HistoryUiReason {
    pub const fn code(self) -> &'static str {
        match self {
            Self::PolicyTerminal => "policy_terminal",
            Self::ProfileFloorTerminal => "profile_floor_terminal",
            Self::AwaitingAuthorizedSourceResponse => "awaiting_authorized_source_response",
            Self::ResponseVerificationPending => "response_verification_pending",
            Self::ServiceRecordLost => "service_record_lost",
            Self::QuotaOrRetry => "quota_or_retry",
        }
    }

    pub const fn user_summary(self) -> &'static str {
        match self {
            Self::PolicyTerminal => "History is not visible under the current Realm policy.",
            Self::ProfileFloorTerminal => {
                "This endpoint joined after that history epoch, so its profile floor excludes it."
            }
            Self::AwaitingAuthorizedSourceResponse => {
                "History recovery is waiting for an authorized source response."
            }
            Self::ResponseVerificationPending => {
                "History recovery is waiting for durable verification material."
            }
            Self::ServiceRecordLost => {
                "The recovery service reports that this signed history record was lost."
            }
            Self::QuotaOrRetry => {
                "History recovery is rate-limited or retryable; no terminal visibility decision was made."
            }
        }
    }
}

pub const fn terminal_reason(
    reason: arkret_policy::history_access::HistoryTerminalReason,
) -> HistoryUiReason {
    match reason {
        arkret_policy::history_access::HistoryTerminalReason::DecryptionUnavailableByPolicy => {
            HistoryUiReason::PolicyTerminal
        }
        arkret_policy::history_access::HistoryTerminalReason::DecryptionUnavailableByProfileFloor => {
            HistoryUiReason::ProfileFloorTerminal
        }
    }
}

pub fn classify_runtime_error(error: &str) -> HistoryUiReason {
    let normalized = error.to_ascii_lowercase();
    if normalized.contains("decryption_unavailable_by_policy") {
        HistoryUiReason::PolicyTerminal
    } else if normalized.contains("decryption_unavailable_by_profile_floor") {
        HistoryUiReason::ProfileFloorTerminal
    } else if normalized.contains("awaiting_authorized_source_response") {
        HistoryUiReason::AwaitingAuthorizedSourceResponse
    } else if normalized.contains("service_record_lost") || normalized.contains("lost descriptor") {
        HistoryUiReason::ServiceRecordLost
    } else if normalized.contains("quota")
        || normalized.contains("rate_limit")
        || normalized.contains("rate limit")
        || normalized.contains("retry")
    {
        HistoryUiReason::QuotaOrRetry
    } else {
        HistoryUiReason::ResponseVerificationPending
    }
}

pub fn status_message(reason: HistoryUiReason, detail: &str) -> String {
    let detail = detail.trim();
    if detail.is_empty() {
        format!(
            "History status [{}]: {}",
            reason.code(),
            reason.user_summary()
        )
    } else {
        format!(
            "History status [{}]: {} Details: {detail}",
            reason.code(),
            reason.user_summary()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_reasons_remain_distinct_from_transient_status() {
        assert_eq!(
            terminal_reason(
                arkret_policy::history_access::HistoryTerminalReason::DecryptionUnavailableByPolicy
            ),
            HistoryUiReason::PolicyTerminal
        );
        assert_eq!(
            terminal_reason(
                arkret_policy::history_access::HistoryTerminalReason::DecryptionUnavailableByProfileFloor
            ),
            HistoryUiReason::ProfileFloorTerminal
        );
        assert_eq!(
            classify_runtime_error("dependency_missing"),
            HistoryUiReason::ResponseVerificationPending
        );
        assert_eq!(
            classify_runtime_error("awaiting_authorized_source_response"),
            HistoryUiReason::AwaitingAuthorizedSourceResponse
        );
        assert_eq!(
            classify_runtime_error("history source quota exceeded; retry later"),
            HistoryUiReason::QuotaOrRetry
        );
        assert_eq!(
            classify_runtime_error("signed service_record_lost descriptor"),
            HistoryUiReason::ServiceRecordLost
        );
    }

    #[test]
    fn status_copy_does_not_claim_minimal_privacy_or_remote_revocation() {
        for reason in [
            HistoryUiReason::PolicyTerminal,
            HistoryUiReason::ProfileFloorTerminal,
            HistoryUiReason::AwaitingAuthorizedSourceResponse,
            HistoryUiReason::ResponseVerificationPending,
            HistoryUiReason::ServiceRecordLost,
            HistoryUiReason::QuotaOrRetry,
        ] {
            let copy = status_message(reason, "").to_ascii_lowercase();
            assert!(!copy.contains("anonymous"));
            assert!(!copy.contains("unlinkable"));
            assert!(!copy.contains("remotely revoked"));
            assert!(!copy.contains("remote wipe"));
        }
    }
}
