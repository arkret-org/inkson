//! Window keyboard commands remain available when focus returns to the body.
use glory::render::{KeyboardCommand, KeyboardInput};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShortcutAction {
    Search,
    Palette,
    Help,
    DismissHelp,
    DismissNotifications,
}

fn action_for(
    input: KeyboardInput<'_>,
    help_open: bool,
    notifications_open: bool,
) -> Option<ShortcutAction> {
    if input.editable {
        return None;
    }
    match input.command()? {
        KeyboardCommand::Search => Some(ShortcutAction::Search),
        KeyboardCommand::Palette => Some(ShortcutAction::Palette),
        KeyboardCommand::Help => Some(ShortcutAction::Help),
        KeyboardCommand::Dismiss if help_open => Some(ShortcutAction::DismissHelp),
        KeyboardCommand::Dismiss if notifications_open => {
            Some(ShortcutAction::DismissNotifications)
        }
        _ => None,
    }
}

#[cfg(target_arch = "wasm32")]
pub(super) fn install(
    scope: &glory::Scope,
    context: std::rc::Rc<crate::presentation::InksonContext>,
    ui: std::rc::Rc<super::shell_state::ShellState>,
) {
    use wasm_bindgen::JsCast;
    use wasm_bindgen::closure::Closure;

    struct Listener {
        window: web_sys::Window,
        callback: Closure<dyn FnMut(web_sys::KeyboardEvent)>,
    }
    impl Drop for Listener {
        fn drop(&mut self) {
            let _ = self.window.remove_event_listener_with_callback_and_bool(
                "keydown",
                self.callback.as_ref().unchecked_ref(),
                true,
            );
        }
    }

    let Some(window) = web_sys::window() else {
        return;
    };
    let weak = scope.downgrade();
    let callback = Closure::new(move |event: web_sys::KeyboardEvent| {
        if event.default_prevented() || event.repeat() || event.is_composing() || event.alt_key() {
            return;
        }
        let Some(scope) = weak.upgrade() else { return };
        let editable = event
            .target()
            .and_then(|target| target.dyn_into::<web_sys::Element>().ok())
            .is_some_and(|element| {
                matches!(element.tag_name().as_str(), "INPUT" | "TEXTAREA" | "SELECT")
                    || element
                        .dyn_ref::<web_sys::HtmlElement>()
                        .is_some_and(web_sys::HtmlElement::is_content_editable)
                    || element
                        .closest("[contenteditable=\"true\"], [role=\"textbox\"]")
                        .ok()
                        .flatten()
                        .is_some()
            });
        let key = event.key();
        let input = KeyboardInput {
            key: &key,
            control: event.ctrl_key(),
            meta: event.meta_key(),
            alt: event.alt_key(),
            shift: event.shift_key(),
            repeat: event.repeat(),
            composing: event.is_composing(),
            editable,
        };
        let Some(action) = action_for(
            input,
            ui.shortcut_open.get_untracked(),
            ui.notifications_open.get_untracked(),
        ) else {
            return;
        };
        let context = context.clone();
        let ui = ui.clone();
        // The web Host polls owned tasks in a microtask after this DOM event.
        match scope.spawn(async move {
            match action {
                ShortcutAction::Search => context.navigate(crate::routes::Route::Search),
                ShortcutAction::Palette => ui.search_open.revise(|value| *value = true),
                ShortcutAction::Help => ui.shortcut_open.revise(|value| *value = true),
                ShortcutAction::DismissHelp => ui.shortcut_open.revise(|value| *value = false),
                ShortcutAction::DismissNotifications => {
                    ui.notifications_open.revise(|value| *value = false)
                }
            }
        }) {
            Ok(_) => {
                event.prevent_default();
                event.stop_propagation();
            }
            Err(error) => scope.report_error(error),
        }
    });
    if let Err(error) = window.add_event_listener_with_callback_and_bool(
        "keydown",
        callback.as_ref().unchecked_ref(),
        true,
    ) {
        tracing::warn!(?error, "could not install global keyboard commands");
        return;
    }
    let listener = Listener { window, callback };
    if let Err(error) = scope.on_cleanup(move || drop(listener)) {
        scope.report_error(error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_supported_nonediting_global_commands_are_claimed() {
        fn chord(key: &str) -> KeyboardInput<'_> {
            KeyboardInput {
                key,
                control: true,
                ..Default::default()
            }
        }
        assert_eq!(
            action_for(chord("F"), false, false),
            Some(ShortcutAction::Search)
        );
        assert_eq!(
            action_for(chord("k"), false, false),
            Some(ShortcutAction::Palette)
        );
        assert_eq!(
            action_for(chord("/"), false, false),
            Some(ShortcutAction::Help)
        );
        for key in ["F", "k", "/", "Escape", "Enter"] {
            assert_eq!(
                action_for(
                    KeyboardInput {
                        editable: true,
                        ..chord(key)
                    },
                    true,
                    true
                ),
                None
            );
        }
        for input in [
            KeyboardInput {
                repeat: true,
                ..chord("f")
            },
            KeyboardInput {
                composing: true,
                ..chord("f")
            },
            KeyboardInput {
                alt: true,
                ..chord("f")
            },
            KeyboardInput {
                key: "Enter",
                ..Default::default()
            },
        ] {
            assert_eq!(action_for(input, true, true), None);
        }
    }

    #[test]
    fn escape_claims_only_the_original_help_or_notification_dismissal() {
        let escape = KeyboardInput {
            key: "Escape",
            ..Default::default()
        };
        assert_eq!(action_for(escape, false, false), None);
        assert_eq!(
            action_for(escape, true, true),
            Some(ShortcutAction::DismissHelp)
        );
        assert_eq!(
            action_for(escape, false, true),
            Some(ShortcutAction::DismissNotifications)
        );
    }
}
