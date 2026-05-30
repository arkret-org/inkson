//! Global policy-deny banner.
//!
//! G3.Y3 — when ANY server-side operation returns a 403 with a
//! policy-shaped envelope (`{ error: { code, message, ... }, ... }`),
//! the HTTP layer dispatches a [`PolicyDenyEvent`] here. The
//! `PolicyDenyBanner` component, mounted once near the app shell, polls
//! this in-process queue from a use_effect every tick and renders the
//! most recent deny for ~8 seconds.
//!
//! The queue lives in a `std::sync::Mutex` static so the producer side
//! (`crate::api`) does not need to thread a Dioxus `Signal` through
//! every `ContrixApi` call. The consumer side (this component) drains
//! the queue at the top of each render — Dioxus is single-threaded on
//! the renderer thread, so the lock is uncontended in practice.
//!
//! Spec cross-references:
//! - `authz/policy-server.md` §3 — `POST /api/v1/policy/check` deny response carries
//!   `decision/reason/obligations[]`.
//! - `authz/policy-server.md` §4 — obligation kinds (`log_event`, `require_step_up`, `mask_field`,
//!   ...). Soland is responsible for executing them; the UI surfaces them so the user sees what the
//!   server did on their behalf.

use std::sync::Mutex;

use dioxus::prelude::*;
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
            captured_at_ms: policy_deny_now_ms(),
        }
    }
}

fn policy_deny_now_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now().max(0.0) as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};

        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or_default()
    }
}

/// Process-wide event sink. The HTTP layer's 403 decoder calls
/// [`push_policy_deny`]; the banner component polls [`take_policy_deny`]
/// each render to surface the most recent event.
static POLICY_DENY_QUEUE: Mutex<Option<PolicyDenyEvent>> = Mutex::new(None);

/// HTTP-layer entry point: record the latest deny so the banner can
/// pick it up. Newer denies overwrite older ones — we only show the
/// most recent because a deny storm should not stack ten banners.
pub fn push_policy_deny(event: PolicyDenyEvent) {
    if let Ok(mut slot) = POLICY_DENY_QUEUE.lock() {
        *slot = Some(event);
    }
}

/// Consumer entry point: drain (take) the most recent deny if any.
/// Called by the banner component each render tick. Returning by value
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
    matches!(
        code,
        "policy_denied"
            | "policy_blocked"
            | "policy_timeout"
            | "capability_denied"
            | "capability_revoked"
            | "missing_capability"
            | "consent_required"
            | "consent_denied"
            | "delegation_exceeds_grantor_expiry"
            | "capability_not_held"
    )
}

/// Auto-dismiss window in milliseconds. The banner hides itself after
/// this duration; clicking the close button dismisses earlier.
pub const POLICY_DENY_AUTODISMISS_MS: u64 = 8_000;

/// The visible banner. Mount once near the top of the app shell so it
/// floats above any view. Pulls events from the global queue via a
/// `use_effect` polling loop; renders nothing when no deny is active.
#[component]
pub fn PolicyDenyBanner() -> Element {
    let mut current = use_signal(|| Option::<PolicyDenyEvent>::None);

    // Each render, opportunistically drain the queue. Dioxus reruns
    // the component when other signals tick, so a long-lived deny will
    // still be picked up within milliseconds of the producing call.
    if current.read().is_none()
        && let Some(event) = take_policy_deny()
    {
        current.set(Some(event));
    }

    // Auto-dismiss: spawn a one-shot task that clears the signal after
    // POLICY_DENY_AUTODISMISS_MS. We re-spawn whenever a *new* event
    // lands so consecutive denies each get their own 8s window.
    let captured_at = current.read().as_ref().map(|e| e.captured_at_ms);
    use_effect(move || {
        let Some(captured_at) = captured_at else {
            return;
        };
        #[cfg(not(target_arch = "wasm32"))]
        {
            spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(POLICY_DENY_AUTODISMISS_MS))
                    .await;
                // Only clear if the displayed event is still the one
                // we scheduled the dismissal for; otherwise a newer
                // event has replaced it and owns its own timer.
                let still_same = current
                    .read()
                    .as_ref()
                    .map(|e| e.captured_at_ms == captured_at)
                    .unwrap_or(false);
                if still_same {
                    current.set(None);
                }
            });
        }
        #[cfg(target_arch = "wasm32")]
        {
            let _ = captured_at;
        }
    });

    let Some(event) = current.read().clone() else {
        return rsx! {};
    };

    let obligation_count = event.obligations.len();

    rsx! {
        div {
            class: "policy-deny-banner",
            role: "alert",
            "aria-live": "assertive",
            "data-testid": "policy-deny-banner",
            div { class: "policy-deny-row",
                strong {
                    "data-testid": "policy-deny-code",
                    "{event.code}"
                }
                button {
                    class: "btn icon sm ghost",
                    "data-testid": "policy-deny-dismiss",
                    "aria-label": "Dismiss policy deny notice",
                    onclick: move |_| current.set(None),
                    "×"
                }
            }
            div {
                "data-testid": "policy-deny-message",
                "{event.message}"
            }
            if obligation_count > 0 {
                ul {
                    class: "policy-deny-obligations",
                    "data-testid": "policy-deny-obligations",
                    for (idx, obligation) in event.obligations.iter().enumerate() {
                        li {
                            "data-testid": "policy-deny-obligation",
                            "data-obligation-index": "{idx}",
                            "data-obligation-kind": {
                                obligation
                                    .get("kind")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown")
                            },
                            "{obligation}"
                        }
                    }
                }
            }
        }
    }
}

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
