//! Circle-error toast (CXP-0007 / P3B.3.1).
//!
//! Surfaces the 6 CXP-0007 reason / error codes as user-facing toasts.
//! Listens for a [`CircleErrorKind`] pushed onto a shared signal by
//! API call sites (e.g. `api::create_circle`, `sync_engine::decrypt`,
//! the offline-queue drain worker) and renders a dismissible card.

use dioxus::prelude::*;

use crate::circle::CircleErrorKind;
use crate::i18n::{I18nSignal, t};

/// Props for the global circle-error toast surface. Parent should
/// thread a [`Signal<Option<CircleErrorKind>>`] and the i18n signal
/// from the app shell.
#[derive(Clone, PartialEq, Props)]
pub struct CircleErrorToastProps {
    pub current: Signal<Option<CircleErrorKind>>,
    pub i18n: I18nSignal,
}

#[component]
pub fn CircleErrorToast(props: CircleErrorToastProps) -> Element {
    let mut signal = props.current;
    let kind = *signal.read();
    let Some(kind) = kind else {
        return rsx! {};
    };

    let key = kind.i18n_key();
    let translated = t(&props.i18n, key);
    // `t` falls back to returning the key itself when not found — treat
    // that as "no translation" and use the hard-coded English fallback.
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
                onclick: move |_| signal.set(None),
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
}
