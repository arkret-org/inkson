//! P5 — three-mode theme switcher with localStorage persistence.
//!
//! `app.rs` already tracks a `theme: Signal<String>` carrying one of
//! `"light"` / `"night"` / `"system"`, hydrates it from local state on
//! boot, and exposes the raw mode on the shell's `data-theme`. The
//! *effective* canonical theme (`light`/`dark`) is mirrored onto `<html>`
//! by `app.rs::apply_document_root_theme`, which is what all CSS keys off.
//! The existing topbar / mobile toggles only
//! flip between two states (light ↔ night) via [`next_manual_theme`];
//! this component adds a richer three-mode picker that:
//!
//!   * surfaces all three modes (light / dark / follow system) so users can explicitly delegate to
//!     the OS,
//!   * persists the choice to `localStorage` (browser) or `LocalStateStore` private-data (desktop)
//!     via the same path the existing topbar toggle uses, and
//!   * mirrors ARIA semantics — `role="radiogroup"` + per-mode `aria-checked` so screen-reader
//!     users hear the active mode.
//!
//! The component is intentionally view-agnostic: caller passes the
//! `theme` signal + a persistence callback. Wired into the topbar (new
//! "Theme" group) and the Settings → Appearance card.

use dioxus::prelude::*;

use crate::ui::button::{Button, ButtonVariant};

/// One of the three canonical theme modes. The string round-trip
/// matches what `app.rs` writes into private data (`"theme"` key) so
/// the existing hydration path keeps working unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThemeMode {
    Light,
    Dark,
    System,
}

impl ThemeMode {
    pub fn from_persisted_str(value: &str) -> Self {
        match value {
            "light" => Self::Light,
            "night" | "dark" => Self::Dark,
            _ => Self::System,
        }
    }

    /// The string form persisted in local state. Matches the existing
    /// `"theme"` private-data key written by the topbar toggle so the
    /// two surfaces stay in sync without an explicit migration.
    pub fn as_persisted_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "night",
            Self::System => "system",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Light => "Light",
            Self::Dark => "Dark",
            Self::System => "Follow system",
        }
    }

    pub fn aria_description(self) -> &'static str {
        match self {
            Self::Light => "Use the light color scheme.",
            Self::Dark => "Use the dark color scheme.",
            Self::System => "Match the operating system's color scheme preference.",
        }
    }
}

/// Props for the three-mode theme switcher.
#[derive(Clone, PartialEq, Props)]
pub struct ThemeSwitcherProps {
    /// Live theme signal owned by `app.rs::RouterView`. The component
    /// reads + writes through this signal so the existing rendering
    /// paths (`theme_renders_as_night`, the shell `data-theme` attr,
    /// etc.) re-run automatically.
    pub theme: Signal<String>,
    /// Persist callback. The caller threads the same write path the
    /// existing topbar toggle uses (`LocalStateStore::save_private_data
    /// (&account_did(), "theme", next)` for desktop or the LocalStorage
    /// fallback for wasm). Keeps the component free of any direct
    /// storage coupling.
    pub on_persist: EventHandler<String>,
}

#[component]
pub fn ThemeSwitcher(props: ThemeSwitcherProps) -> Element {
    let mut theme = props.theme;
    let active = ThemeMode::from_persisted_str(&theme.read().clone());

    rsx! {
        div {
            class: "theme-switcher",
            "data-testid": "theme-switcher",
            role: "radiogroup",
            "aria-label": "Theme",

            for mode in [ThemeMode::Light, ThemeMode::Dark, ThemeMode::System] {
                {
                    let is_active = active == mode;
                    let on_persist = props.on_persist;
                    let mode_value = mode;
                    rsx! {
                        Button {
                            variant: if is_active { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                            class: "theme-switcher-option",
                            "data-testid": match mode_value {
                                ThemeMode::Light => "theme-switcher-light",
                                ThemeMode::Dark => "theme-switcher-dark",
                                ThemeMode::System => "theme-switcher-system",
                            },
                            "data-active": if is_active { "true" } else { "false" },
                            role: "radio",
                            "aria-checked": if is_active { "true" } else { "false" },
                            "aria-label": mode_value.label(),
                            title: mode_value.aria_description(),
                            onclick: move |_| {
                                let next = mode_value.as_persisted_str().to_owned();
                                theme.set(next.clone());
                                on_persist.call(next);
                            },
                            "{mode_value.label()}"
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_persisted_string() {
        for mode in [ThemeMode::Light, ThemeMode::Dark, ThemeMode::System] {
            let s = mode.as_persisted_str();
            assert_eq!(ThemeMode::from_persisted_str(s), mode);
        }
    }

    #[test]
    fn dark_alias_normalises_to_dark_mode() {
        assert_eq!(ThemeMode::from_persisted_str("dark"), ThemeMode::Dark);
        assert_eq!(ThemeMode::from_persisted_str("night"), ThemeMode::Dark);
    }

    #[test]
    fn unknown_value_falls_back_to_system() {
        assert_eq!(ThemeMode::from_persisted_str(""), ThemeMode::System);
        assert_eq!(ThemeMode::from_persisted_str("garbage"), ThemeMode::System);
    }

    #[test]
    fn each_mode_has_distinct_label() {
        assert_ne!(ThemeMode::Light.label(), ThemeMode::Dark.label());
        assert_ne!(ThemeMode::Dark.label(), ThemeMode::System.label());
        assert_ne!(ThemeMode::Light.label(), ThemeMode::System.label());
    }
}
