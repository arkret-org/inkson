//! P5 — warn the user when running with the browser-storage symmetric-
//! secret fallback.
//!
//! The wasm32 build keeps signing material in `LocalStorageSecureKeyStore`
//! (synchronous boot) and upgrades to `IndexedDbSecureKeyStore` once the
//! async init completes. Either way the browser has no symmetric-secret
//! tier — there is no OS keychain handoff, no hardware-backed key, and
//! cross-tab access is unrestricted.
//!
//! This banner makes that trade-off explicit so users moving from a
//! Tauri desktop install to the web build (or the other way) understand
//! what changed. The component is mounted near the app shell so it
//! follows the user across routes.
//!
//! Wired:
//!   * always rendered on the wasm build (the secure key store can only
//!     be the browser fallback there).
//!   * hidden on native unless the caller explicitly passes `force=true`
//!     (used in tests + the developer panel).

use dioxus::prelude::*;

#[derive(Clone, PartialEq, Props)]
pub struct StorageFallbackBannerProps {
    /// Render the banner regardless of build target. Defaults to
    /// `false`. Used by the developer panel + Playwright tests to
    /// exercise the surface without mocking the build cfg.
    #[props(default)]
    pub force: bool,
    /// Optional callback for the "Dismiss" affordance. Dismissal is
    /// session-scoped — the banner returns on next launch. Pass `None`
    /// to hide the dismiss button.
    #[props(default)]
    pub on_dismiss: Option<EventHandler<MouseEvent>>,
}

#[component]
pub fn StorageFallbackBanner(props: StorageFallbackBannerProps) -> Element {
    let show = props.force || cfg!(target_arch = "wasm32");
    if !show {
        return rsx! {};
    }

    rsx! {
        div {
            class: "banner warning storage-fallback-banner",
            "data-testid": "storage-fallback-banner",
            role: "status",
            "aria-live": "polite",
            span {
                class: "muted",
                "Using browser storage fallback — recommend Tauri desktop for full security."
            }
            if let Some(on_dismiss) = props.on_dismiss {
                button {
                    class: "secondary",
                    "data-testid": "storage-fallback-banner-dismiss",
                    "aria-label": "Dismiss browser storage warning",
                    onclick: move |evt| on_dismiss.call(evt),
                    "Dismiss"
                }
            }
        }
    }
}
