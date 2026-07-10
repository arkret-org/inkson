//! Circle-error event queue (AKP-0007 / P3B.3).
//!
//! Surfaces AKP-0007 reason / error codes as user-facing toasts.
//! Uses the same process-wide queue pattern as
//! [`crate::components::policy_deny_banner`]: API call sites push a
//! [`CircleErrorKind`] via [`push_circle_error`]; the unified
//! [`crate::components::feedback::ToastHost`], mounted once near the
//! app shell, drains the queue each render and surfaces the localized
//! message as an Error toast. The former dedicated `CircleErrorToast`
//! component was folded into that host (unified-feedback-system
//! Wave 0), which also upgraded the "newest overwrites" display
//! semantics to normal stacking on the consumer side.

use std::sync::Mutex;

use crate::circle::CircleErrorKind;

/// Process-wide circle-error slot. Newer kinds overwrite older ones —
/// a deny storm should not stack ten toasts.
static CIRCLE_ERROR_QUEUE: Mutex<Option<CircleErrorKind>> = Mutex::new(None);

/// API-layer / sync-engine entry point — record the latest AKP-0007
/// error so the toast can pick it up.
pub fn push_circle_error(kind: CircleErrorKind) {
    if let Ok(mut slot) = CIRCLE_ERROR_QUEUE.lock() {
        *slot = Some(kind);
    }
}

/// Consumer entry point — drain (take) the most recent error if any.
pub fn take_circle_error() -> Option<CircleErrorKind> {
    CIRCLE_ERROR_QUEUE.lock().ok()?.take()
}

/// Helper that classifies a server-side error envelope and pushes a
/// [`CircleErrorKind`] onto the queue if it matches one of the
/// AKP-0007 codes. Returns `true` when a circle error was recognised.
///
/// The HTTP layer can call this opportunistically next to
/// `maybe_dispatch_policy_deny` — the two queues are independent.
pub fn maybe_dispatch_circle_error(code: &str, reason: Option<&str>) -> bool {
    if let Some(kind) = CircleErrorKind::from_error_code(code) {
        push_circle_error(kind);
        return true;
    }
    if let Some(reason) = reason
        && let Some(kind) = CircleErrorKind::from_reason_code(reason)
    {
        push_circle_error(kind);
        return true;
    }
    false
}

// The former `CircleErrorToast` component was removed in the
// unified-feedback-system Wave 0: queued kinds now surface through
// `crate::components::feedback::ToastHost` as Error toasts (i18n key
// from `CircleErrorKind::i18n_key()`, English fallback from
// `CircleErrorKind::english_fallback()`).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realm_mismatch_has_user_facing_fallback() {
        let kind = CircleErrorKind::RealmMismatch;
        let msg = kind.english_fallback();
        assert!(msg.starts_with("This Circle"));
    }

    #[test]
    fn delivery_binding_handed_over_has_user_facing_fallback() {
        let kind = CircleErrorKind::DeliveryBindingHandedOver;
        let msg = kind.english_fallback();
        assert!(msg.contains("delivery binding"));
    }

    #[test]
    fn dispatch_classifies_reason_code() {
        // Drain any prior queue entry so this test is hermetic.
        let _ = take_circle_error();
        assert!(maybe_dispatch_circle_error(
            "failed_precondition",
            Some("circle_not_active")
        ));
        assert_eq!(take_circle_error(), Some(CircleErrorKind::NotActive));
    }

    #[test]
    fn dispatch_classifies_direct_encryption_floor_code() {
        let _ = take_circle_error();
        assert!(maybe_dispatch_circle_error(
            "circle_encryption_below_realm_floor",
            None
        ));
        assert_eq!(
            take_circle_error(),
            Some(CircleErrorKind::EncryptionBelowRealmFloor)
        );
    }

    #[test]
    fn dispatch_ignores_unrelated_codes() {
        let _ = take_circle_error();
        assert!(!maybe_dispatch_circle_error(
            "invalid_param",
            Some("missing_field")
        ));
        assert_eq!(take_circle_error(), None);
    }
}
