//! Circle-error toast (CXP-0007 / P3B.3).
//!
//! Surfaces the 6 CXP-0007 reason / error codes as user-facing toasts.
//! Uses the same process-wide queue pattern as
//! [`crate::components::policy_deny_banner`]: API call sites push a
//! [`CircleErrorKind`] via [`push_circle_error`]; the [`CircleErrorToast`]
//! component, mounted once near the app shell, drains the queue each
//! render and displays a dismissible card with the localized message.

use std::sync::Mutex;

use dioxus::prelude::*;

use crate::circle::CircleErrorKind;
use crate::i18n::{I18nSignal, t};

/// Process-wide circle-error slot. Newer kinds overwrite older ones —
/// a deny storm should not stack ten toasts.
static CIRCLE_ERROR_QUEUE: Mutex<Option<CircleErrorKind>> = Mutex::new(None);

/// API-layer / sync-engine entry point — record the latest CXP-0007
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
/// [`CircleErrorKind`] onto the queue if it matches one of the 6
/// CXP-0007 codes. Returns `true` when a circle error was recognised.
///
/// The HTTP layer can call this opportunistically next to
/// `maybe_dispatch_policy_deny` — the two queues are independent.
pub fn maybe_dispatch_circle_error(code: &str, reason: Option<&str>) -> bool {
    if let Some(kind) = CircleErrorKind::from_error_code(code) {
        push_circle_error(kind);
        return true;
    }
    if let Some(reason) = reason {
        if let Some(kind) = CircleErrorKind::from_reason_code(reason) {
            push_circle_error(kind);
            return true;
        }
    }
    false
}

/// Props for the visible toast surface.
#[derive(Clone, PartialEq, Props)]
pub struct CircleErrorToastProps {
    /// App-wide i18n signal so the toast can pick the localized
    /// `error.circle.*` string.
    pub i18n: I18nSignal,
}

#[component]
pub fn CircleErrorToast(props: CircleErrorToastProps) -> Element {
    let mut current = use_signal(|| Option::<CircleErrorKind>::None);

    if current.read().is_none() {
        if let Some(kind) = take_circle_error() {
            current.set(Some(kind));
        }
    }

    let Some(kind) = *current.read() else {
        return rsx! {};
    };

    let key = kind.i18n_key();
    let translated = t(&props.i18n, key);
    let message = if translated == key {
        kind.english_fallback().to_owned()
    } else {
        translated
    };

    rsx! {
        div {
            class: "toast circle-error-toast",
            "data-testid": "circle-error-toast",
            "data-i18n-key": "{key}",
            div { class: "toast-body",
                strong { "Circle error" }
                p { "{message}" }
            }
            button {
                class: "icon-only",
                "data-testid": "circle-error-toast-dismiss",
                onclick: move |_| current.set(None),
                "×"
            }
        }
    }
}

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
        assert!(maybe_dispatch_circle_error("failed_precondition", Some("circle_not_active")));
        assert_eq!(take_circle_error(), Some(CircleErrorKind::NotActive));
    }

    #[test]
    fn dispatch_ignores_unrelated_codes() {
        let _ = take_circle_error();
        assert!(!maybe_dispatch_circle_error("invalid_param", Some("missing_field")));
        assert_eq!(take_circle_error(), None);
    }
}
