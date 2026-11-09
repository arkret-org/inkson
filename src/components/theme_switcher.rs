//! Live three-mode theme selector.
use std::rc::Rc;

use glory::prelude::*;

use crate::presentation::{InksonContext, View};
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

pub struct ThemeSwitcherProps {
    pub theme: Cage<String>,
    pub on_persist: Rc<dyn Fn(String)>,
}
pub fn theme_switcher(
    scope: &Scope,
    context: Rc<InksonContext>,
    props: ThemeSwitcherProps,
) -> View {
    let theme = props.theme;
    let on_persist = props.on_persist;
    {
        let selected = scope.bond(move || {
            ThemeMode::from_persisted_str(&theme.get())
                .as_persisted_str()
                .to_owned()
        });
        Box::new(
            sapid::radio_group("theme-switcher")
                .unstyled()
                .class("theme-switcher")
                .label(context.translated(scope, "theme.switcher_aria_label"))
                .value(selected)
                .orientation(glory::render::Orientation::Horizontal)
                .items(
                    [ThemeMode::Light, ThemeMode::Dark, ThemeMode::System]
                        .into_iter()
                        .map(|mode| {
                            let class = scope.bond(move || {
                                format!(
                                    "button theme-switcher-option {}",
                                    if ThemeMode::from_persisted_str(&theme.get()) == mode {
                                        "primary"
                                    } else {
                                        "secondary"
                                    }
                                )
                            });
                            sapid::radio(mode.as_persisted_str())
                                .unstyled()
                                .class(class)
                                .name(mode.label())
                                .label(mode.label())
                        }),
                )
                .on_value_change(move |next| {
                    theme.revise(|value| *value = next.clone());
                    on_persist(next);
                }),
        )
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
