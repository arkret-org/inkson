//! Global policy-deny event queue.
//!
//! G3.Y3 — when ANY server-side operation returns a 403 with a
//! policy-shaped envelope (`{ error: { code, message, ... }, ... }`),
//! the HTTP layer dispatches a [`PolicyDenyEvent`] here. The unified
//! [`crate::components::feedback::ToastHost`] (mounted once near the
//! app shell) drains this queue each render and surfaces the deny as a
//! Warning toast — the former dedicated `PolicyDenyBanner` component
//! was folded into that host (unified-feedback-system Wave 0).
//!
//! The queue lives in a `std::sync::Mutex` static so the producer side
//! (`crate::api`) does not need to thread a Dioxus `Signal` through
//! every `CokretApi` call. The consumer side (`ToastHost`) drains
//! the queue at the top of each render — Dioxus is single-threaded on
//! the renderer thread, so the lock is uncontended in practice.
//!
//! Spec cross-references:
//! - `authz/policy-server.md` §3 — `POST /_cokret/self/policy/check` deny response carries
//!   `decision/reason/obligations[]`.
//! - `authz/policy-server.md` §4 — obligation kinds (`log_event`, `require_step_up`, `mask_field`,
//!   ...). Soland is responsible for executing them; the UI surfaces them so the user sees what the
//!   server did on their behalf.

use std::sync::Mutex;

use serde_json::Value;

/// One denial event captured from the HTTP layer.
#[derive(Clone, Debug)]
pub struct PolicyDenyEvent {
    /// `error.code` from the envelope (e.g. `policy_denied`,
    /// `capability_denied`, `consent_required`).
    pub code: String,
    /// Human-readable reason from the server.
    pub message: String,
    /// Obligations array if the server emitted one (signed transcript
    /// surface per `authz/policy-server.md` §3). Stored as raw JSON
    /// because the UI only renders a short summary — full structured
    /// decoding lives in the audit panel.
    pub obligations: Vec<Value>,
    /// Wall-clock timestamp (ms since unix epoch) the deny was
    /// captured. Used to drive the auto-dismiss timer.
    pub captured_at_ms: u64,
}

impl PolicyDenyEvent {
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        obligations: Vec<Value>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            obligations,
            captured_at_ms: crate::clock::now_unix_ms(),
        }
    }
}

/// Process-wide event sink. The HTTP layer's 403 decoder calls
/// [`push_policy_deny`]; the toast host polls [`take_policy_deny`]
/// each render to surface the most recent event.
static POLICY_DENY_QUEUE: Mutex<Option<PolicyDenyEvent>> = Mutex::new(None);

/// HTTP-layer entry point: record the latest deny so the toast host can
/// pick it up. Newer denies overwrite older ones — we only surface the
/// most recent because a deny storm should not stack ten toasts.
pub fn push_policy_deny(event: PolicyDenyEvent) {
    if let Ok(mut slot) = POLICY_DENY_QUEUE.lock() {
        *slot = Some(event);
    }
}

/// Consumer entry point: drain (take) the most recent deny if any.
/// Called by the toast host each render tick. Returning by value
/// keeps the lock window minimal.
pub fn take_policy_deny() -> Option<PolicyDenyEvent> {
    POLICY_DENY_QUEUE.lock().ok()?.take()
}

/// Heuristic: classify an error envelope as a policy deny. We accept:
/// - HTTP 403 (FORBIDDEN), and
/// - error code carrying a policy / capability / consent signal.
///
/// Auth-expired (`unauthenticated` / `auth_expired`) is intentionally
/// NOT classified — that path has its own session-death handling in
/// `is_auth_expired_error` and would race the redirect-to-login.
pub fn is_policy_deny_code(code: &str) -> bool {
    use cokret_sdk::error::{ERROR_CODE_CAPABILITY_DENIED, ERROR_CODE_POLICY_DENIED};

    code == ERROR_CODE_POLICY_DENIED
        || code == ERROR_CODE_CAPABILITY_DENIED
        || matches!(
            code,
            "policy_blocked"
                | "policy_timeout"
                | "capability_revoked"
                | "missing_capability"
                | "consent_required"
                | "consent_denied"
                | "delegation_exceeds_grantor_expiry"
                | "capability_not_held"
        )
}

// The former `PolicyDenyBanner` component (and its
// `POLICY_DENY_AUTODISMISS_MS` window) was removed in the
// unified-feedback-system Wave 0: queued events now surface through
// `crate::components::feedback::ToastHost` as Warning toasts with the
// obligations transcript behind the copy-detail affordance.

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn push_and_take_round_trips() {
        // Clear any leftover from a previous test (the static is shared).
        let _ = take_policy_deny();
        push_policy_deny(PolicyDenyEvent::new(
            "policy_denied",
            "external_policy_blocks_user",
            vec![],
        ));
        let event = take_policy_deny().expect("expected a queued deny");
        assert_eq!(event.code, "policy_denied");
        assert_eq!(event.message, "external_policy_blocks_user");
        // Second take is empty — the queue is take-once.
        assert!(take_policy_deny().is_none());
    }

    #[test]
    fn deny_event_captures_timestamp() {
        let event = PolicyDenyEvent::new("capability_denied", "blocked", vec![]);

        assert!(event.captured_at_ms > 0);
    }

    #[test]
    fn newer_event_replaces_older() {
        let _ = take_policy_deny();
        push_policy_deny(PolicyDenyEvent::new("a", "first", vec![]));
        push_policy_deny(PolicyDenyEvent::new("b", "second", vec![]));
        let event = take_policy_deny().expect("expected a queued deny");
        assert_eq!(event.code, "b");
    }

    #[test]
    fn obligations_round_trip_through_event() {
        let _ = take_policy_deny();
        let obligations = vec![
            json!({"kind": "log_event", "target": "audit_log"}),
            json!({"kind": "require_step_up"}),
        ];
        push_policy_deny(PolicyDenyEvent::new(
            "policy_denied",
            "blocked",
            obligations.clone(),
        ));
        let event = take_policy_deny().expect("expected a queued deny");
        assert_eq!(event.obligations.len(), 2);
        assert_eq!(event.obligations[0]["kind"], "log_event");
    }

    #[test]
    fn classifies_policy_codes() {
        assert!(is_policy_deny_code("policy_denied"));
        assert!(is_policy_deny_code("capability_denied"));
        assert!(is_policy_deny_code("consent_required"));
        assert!(is_policy_deny_code("policy_timeout"));
        assert!(is_policy_deny_code("missing_capability"));
        // Auth-expired path stays on its own handler.
        assert!(!is_policy_deny_code("auth_expired"));
        assert!(!is_policy_deny_code("unauthenticated"));
        // Generic IO / cursor errors are not policy denials.
        assert!(!is_policy_deny_code("http_status"));
        assert!(!is_policy_deny_code("cursor_expired"));
    }
}
