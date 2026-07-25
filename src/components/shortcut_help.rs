//! A6.4 — keyboard-shortcut help overlay.
//!
//! The application shell opens this overlay for `?` or Mod+/ and
//! dismisses it with Escape. The list is limited to bindings that are
//! currently implemented.

use dioxus::prelude::*;

use crate::components::DismissiblePopup;
use crate::i18n::tr;
use crate::ui::button::{Button, ButtonVariant};

/// One entry in the shortcut help list. `keys` is the visible chord
/// rendered as a `<kbd>` group; `description_key` is the i18n key for
/// the human-readable action label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShortcutEntry {
    pub keys: &'static [&'static str],
    pub description_key: &'static str,
}

/// Static list of currently-bound shortcuts surfaced in the help
/// overlay. Keep in sync with `app.rs` global key handlers.
pub fn default_shortcuts() -> Vec<ShortcutEntry> {
    vec![
        ShortcutEntry {
            keys: &["?"],
            description_key: "shortcuts.list.help",
        },
        ShortcutEntry {
            keys: &["Ctrl", "/"],
            description_key: "shortcuts.list.help",
        },
        ShortcutEntry {
            keys: &["Cmd", "/"],
            description_key: "shortcuts.list.help",
        },
        ShortcutEntry {
            keys: &["Esc"],
            description_key: "shortcuts.list.dismiss",
        },
        ShortcutEntry {
            keys: &["Ctrl", "K"],
            description_key: "shortcuts.list.palette",
        },
        ShortcutEntry {
            keys: &["Cmd", "K"],
            description_key: "shortcuts.list.palette_mac",
        },
        ShortcutEntry {
            keys: &["Ctrl", "F"],
            description_key: "shortcuts.list.search",
        },
        ShortcutEntry {
            keys: &["Cmd", "F"],
            description_key: "shortcuts.list.search",
        },
        ShortcutEntry {
            keys: &["Enter"],
            description_key: "shortcuts.list.send",
        },
        ShortcutEntry {
            keys: &["Ctrl", "Enter"],
            description_key: "shortcuts.list.send_alias",
        },
        ShortcutEntry {
            keys: &["Cmd", "Enter"],
            description_key: "shortcuts.list.send_alias",
        },
    ]
}

/// True when a `key` event should be treated as a shortcut-help
/// trigger. Mirrors the spec: Shift+`/` produces `"?"` on most layouts.
///
/// Pure function so the `app.rs` keydown handler can call this without
/// pulling in dioxus state.
pub fn key_event_is_help_trigger(key: &str) -> bool {
    key == "?"
}

/// True when the keydown handler should ignore the event because it
/// originated inside an editable text surface (input, textarea,
/// contenteditable). The shortcut overlay is suppressed in those cases
/// so the user can type a literal `?` into a draft.
pub fn target_is_text_input(tag: Option<&str>, contenteditable: bool) -> bool {
    if contenteditable {
        return true;
    }
    matches!(
        tag.map(str::to_ascii_lowercase).as_deref(),
        Some("input") | Some("textarea")
    )
}

#[component]
pub fn ShortcutHelpOverlay(visible: Signal<bool>) -> Element {
    if !visible() {
        // Render nothing when hidden. A placeholder `div` here becomes an
        // auto-placed grid item inside `.shell.app` and stretches to cover the
        // workspace column, painting on top of live content (it is the last
        // child) and silently intercepting pointer events — which blocked
        // clicks on modal buttons such as the Recovery Key setup dialog.
        return rsx! {};
    }
    let shortcuts = default_shortcuts();
    let title = tr("shortcuts.title");
    rsx! {
        DismissiblePopup {
            overlay_class: "shortcut-help-overlay",
            surface_class: "shortcut-help-card",
            overlay_test_id: Some("shortcut-help-overlay".to_owned()),
            surface_test_id: Some("shortcut-help-card".to_owned()),
            overlay_style: Some("position: fixed; inset: 0; z-index: 60; display: flex; align-items: center; justify-content: center; background: rgba(0,0,0,0.55);".to_owned()),
            surface_style: Some("min-width: 320px; max-width: 480px; padding: 18px; border-radius: 10px; background: var(--bg-elevated, #1a1d22); color: var(--text-strong, #fff); border: 1px solid var(--border-default, #333); box-shadow: 0 12px 36px rgba(0,0,0,0.45);".to_owned()),
            aria_label: title.clone(),
            on_dismiss: move |_| visible.set(false),
            header {
                class: "shortcut-help-card-head",
                style: "display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;",
                h2 {
                    style: "margin: 0; font-size: 1.05rem;",
                    "{title}"
                }
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "shortcut-help-dismiss",
                    onclick: move |_| visible.set(false),
                    "{tr(\"shortcuts.dismiss\")}"
                }
            }
            ul {
                class: "shortcut-help-list",
                style: "list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 8px;",
                for entry in shortcuts.iter() {
                    li {
                        class: "shortcut-help-row",
                        style: "display: flex; align-items: center; justify-content: space-between; gap: 12px;",
                        "data-testid": "shortcut-help-row",
                        span {
                            class: "shortcut-help-keys",
                            style: "display: inline-flex; gap: 4px;",
                            for (idx, key) in entry.keys.iter().enumerate() {
                                if idx > 0 {
                                    span { style: "opacity: 0.6; align-self: center;", "+" }
                                }
                                kbd {
                                    style: "padding: 2px 6px; border: 1px solid var(--border-default, #555); border-radius: 4px; background: var(--bg-default, #11141a); font-family: monospace;",
                                    "{key}"
                                }
                            }
                        }
                        span { class: "shortcut-help-description", "{tr(entry.description_key)}" }
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
    fn question_mark_triggers_help() {
        assert!(key_event_is_help_trigger("?"));
        assert!(!key_event_is_help_trigger("/"));
        assert!(!key_event_is_help_trigger("Slash"));
        assert!(!key_event_is_help_trigger("Escape"));
    }

    #[test]
    fn text_input_targets_suppress_overlay() {
        assert!(target_is_text_input(Some("input"), false));
        assert!(target_is_text_input(Some("TEXTAREA"), false));
        assert!(target_is_text_input(Some("div"), true));
        assert!(!target_is_text_input(Some("div"), false));
        assert!(!target_is_text_input(Some("body"), false));
        assert!(!target_is_text_input(None, false));
    }

    #[test]
    fn default_shortcuts_include_canonical_bindings() {
        let bindings = default_shortcuts();
        // Must surface ?, Esc, and the command-palette chord at minimum.
        assert!(bindings.iter().any(|e| e.keys == ["?"]));
        assert!(
            bindings
                .iter()
                .any(|e| e.keys == ["Ctrl", "/"] || e.keys == ["Cmd", "/"])
        );
        assert!(bindings.iter().any(|e| e.keys == ["Esc"]));
        assert!(bindings.iter().any(|e| e.keys == ["Enter"]));
        assert!(bindings.iter().any(
            |e| e.keys.contains(&"K") && (e.keys.contains(&"Ctrl") || e.keys.contains(&"Cmd"))
        ));
        assert!(bindings.iter().any(
            |e| e.keys.contains(&"F") && (e.keys.contains(&"Ctrl") || e.keys.contains(&"Cmd"))
        ));
    }
}
