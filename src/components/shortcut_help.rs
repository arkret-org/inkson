//! A6.4 — keyboard-shortcut help overlay.
//!
//! The application shell opens this overlay for `?` or Mod+/ and
//! dismisses it with Escape. The list is limited to bindings that are
//! currently implemented.

use std::rc::Rc;

use glory::prelude::*;

use crate::presentation::widgets::{heading, line, paragraph, reactive, stack};
use crate::presentation::{InksonContext, View};

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
/// creating widget state.
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

pub fn shortcut_help_overlay(
    _scope: &Scope,
    context: Rc<InksonContext>,
    visible: Cage<bool>,
) -> View {
    reactive(visible, move |scope, is_visible| {
        if !is_visible {
            return Box::new(widget(|_| Ok(())));
        }
        let dismiss = Box::new(
            sapid::button()
                .unstyled()
                .class("secondary")
                .label(context.translated(scope, "shortcuts.dismiss"))
                .on_press(move || visible.revise(|value| *value = false)),
        ) as View;
        let rows = default_shortcuts()
            .into_iter()
            .map(|entry| {
                line(
                    "shortcut-help-row",
                    vec![
                        paragraph("shortcut-help-keys", entry.keys.join(" + ")),
                        paragraph(
                            "shortcut-help-description",
                            context.translated(scope, entry.description_key),
                        ),
                    ],
                )
            })
            .collect();
        let content = stack(
            "shortcut-help-content",
            vec![
                line(
                    "shortcut-help-card-head",
                    vec![
                        heading(2, "", context.translated(scope, "shortcuts.title")),
                        dismiss,
                    ],
                ),
                stack("shortcut-help-list", rows),
            ],
        );
        let mut content = Some(content);
        Box::new(
            sapid::dialog("shortcut-help")
                .unstyled()
                .class("shortcut-help-card")
                .name(context.translated(scope, "shortcuts.title"))
                .show_trigger(false)
                .show_close(false)
                .open(true)
                .on_dismiss(move |_| visible.revise(|value| *value = false))
                .content(move || {
                    content
                        .take()
                        .unwrap_or_else(|| Box::new(widget(|_| Ok(()))))
                }),
        )
    })
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
