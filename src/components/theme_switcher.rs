//! Live three-mode theme selector.
use std::rc::Rc;

use glory::prelude::*;

use crate::presentation::{InksonContext, View};
/// Theme preference stored in the local and account UI settings.
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

    pub fn as_persisted_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "night",
            Self::System => "system",
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
    let selected = scope.bond(move || {
        ThemeMode::from_persisted_str(&theme.get())
            .as_persisted_str()
            .to_owned()
    });
    Box::new(
        sapid::segmented_control("theme-switcher")
            .theme(context.theme_tokens())
            .with_item_borders(false)
            .class("settings-choice-group theme-switcher")
            .label(context.translated(scope, "theme.switcher_aria_label"))
            .value(selected)
            .segments(
                [ThemeMode::Light, ThemeMode::Dark, ThemeMode::System].map(|mode| {
                    let label = context.translated(
                        scope,
                        match mode {
                            ThemeMode::Light => "settings.theme.light",
                            ThemeMode::Dark => "settings.theme.night",
                            ThemeMode::System => "settings.theme.system",
                        },
                    );
                    sapid::segment(mode.as_persisted_str())
                        .class("theme-switcher-option")
                        .name(label)
                        .label(label)
                }),
            )
            .on_value_change(move |next| {
                if next != theme.get_untracked() {
                    theme.revise(|value| *value = next.clone());
                    on_persist(next);
                }
            }),
    )
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
}
