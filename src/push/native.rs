//! F-OS-NOTIFY-1: thin wrapper around `notify-rust` for OS-level
//! desktop notifications.
//!
//! Spec source: `discovery/push-notifications.md` + the local
//! [`notification_rules`](crate::notification_rules) decision engine.
//! The rule engine decides *whether* to surface a notification; this
//! module decides *how* to actually deliver it to the user's desktop
//! (macOS Notification Center / freedesktop Notifications / Windows
//! Toasts) without forcing every call site to learn a platform-specific
//! API.
//!
//! Design notes:
//! - The struct is intentionally minimal — `title`, `body`, optional
//!   `app_id`. yougen wires it to the chat / kanban / call paths via a
//!   plain `From<&NotificationDecision>` builder rather than burying
//!   the conversion inside the rule engine, so a unit test can build
//!   a fixture decision and exercise the formatting without pulling in
//!   the OS bridge.
//! - The fire path is `cfg(not(target_arch = "wasm32"))`. On wasm we
//!   return `Err(FireError::Unsupported)` — browser apps should hook
//!   the rule engine to the `web-sys` Notification API directly
//!   (`window.Notification`), which has a different permission /
//!   lifecycle model than the OS bridges.
//! - The function returns `Result<(), FireError>` so the caller can
//!   surface the failure into the status bar / telemetry without
//!   crashing the render loop.

use serde::{Deserialize, Serialize};

/// Minimum payload yougen needs to fire a desktop notification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeNotification {
    /// Notification title — typically the source space / sender name.
    pub title: String,
    /// Notification body — the message preview or activity summary.
    /// Already-blinded payloads (E2EE blind wakeup) should pass the
    /// blinded body here so plaintext doesn't leak to the OS bridge.
    pub body: String,
    /// Optional application id used by the freedesktop / Windows
    /// bridges to group notifications. Defaults to `"yougen"`.
    #[serde(default)]
    pub app_id: Option<String>,
}

impl NativeNotification {
    pub fn new(title: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            body: body.into(),
            app_id: None,
        }
    }

    pub fn with_app_id(mut self, app_id: impl Into<String>) -> Self {
        self.app_id = Some(app_id.into());
        self
    }
}

/// Errors surfaced by [`fire_native`].
#[derive(Debug)]
pub enum FireError {
    /// The OS bridge itself rejected the notification (permissions
    /// denied, daemon down, etc.).
    Backend(String),
    /// Native notifications aren't available on this target (wasm32
    /// in particular — browser apps go through `web-sys::Notification`
    /// instead).
    Unsupported,
}

impl std::fmt::Display for FireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend(e) => write!(f, "native notification backend error: {e}"),
            Self::Unsupported => f.write_str("native notifications not supported on this target"),
        }
    }
}

impl std::error::Error for FireError {}

/// F-OS-NOTIFY-1: fire a native desktop notification.
///
/// Native build: routes through `notify-rust`, which talks to the OS
/// notification daemon (macOS Notification Center / freedesktop
/// Notifications / Windows Toasts). Returns `Err(FireError::Backend)`
/// when the daemon rejects the notification.
///
/// Wasm build: returns `Err(FireError::Unsupported)`. The caller
/// should fall back to `web-sys::Notification` for browser
/// deployments — that API has a different permission lifecycle
/// (`Notification.requestPermission()`) and isn't reachable through
/// `notify-rust`.
#[cfg(not(target_arch = "wasm32"))]
pub fn fire_native(notification: &NativeNotification) -> Result<(), FireError> {
    let mut builder = notify_rust::Notification::new();
    builder.summary(&notification.title);
    builder.body(&notification.body);
    if let Some(app_id) = &notification.app_id {
        builder.appname(app_id);
    } else {
        builder.appname("yougen");
    }
    builder
        .show()
        .map(|_| ())
        .map_err(|err| FireError::Backend(err.to_string()))
}

#[cfg(target_arch = "wasm32")]
pub fn fire_native(_notification: &NativeNotification) -> Result<(), FireError> {
    Err(FireError::Unsupported)
}

/// F-OS-NOTIFY-1: convenience builder turning a rule-engine
/// [`crate::notification_rules::NotificationDecision`] +
/// [`crate::notification_rules::NotificationEvalContext`] pair into
/// a [`NativeNotification`].
///
/// Returns `None` when the decision says "don't notify" — callers can
/// `if let Some(n) = build_native_notification(...)` straight into
/// [`fire_native`].
pub fn build_native_notification(
    decision: &crate::notification_rules::NotificationDecision,
    title: impl Into<String>,
    body: impl Into<String>,
) -> Option<NativeNotification> {
    if !decision.should_notify {
        return None;
    }
    Some(NativeNotification::new(title, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notification_rules::NotificationDecision;

    fn notify_decision(should: bool) -> NotificationDecision {
        NotificationDecision {
            should_notify: should,
            highlight: false,
            sound: crate::notification_rules::NotificationSound::None,
            matched_rule_id: None,
            actions: Vec::new(),
            muted_short_circuit: false,
            watch_suppressed: false,
            dnd_suppressed: false,
            unresolved_client_evaluation: false,
            blind_wakeup_required: false,
            reason: String::new(),
        }
    }

    #[test]
    fn build_skips_decisions_that_say_dont_notify() {
        let decision = notify_decision(false);
        assert!(build_native_notification(&decision, "hi", "there").is_none());
    }

    #[test]
    fn build_emits_native_notification_when_decision_says_notify() {
        let decision = notify_decision(true);
        let native = build_native_notification(&decision, "Alice", "ping").expect("should build");
        assert_eq!(native.title, "Alice");
        assert_eq!(native.body, "ping");
        assert!(native.app_id.is_none());
    }

    #[test]
    fn with_app_id_sets_grouping_handle() {
        let native = NativeNotification::new("t", "b").with_app_id("yougen-test");
        assert_eq!(native.app_id.as_deref(), Some("yougen-test"));
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn fire_native_is_unsupported_on_wasm() {
        let native = NativeNotification::new("t", "b");
        match fire_native(&native) {
            Err(FireError::Unsupported) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
}
