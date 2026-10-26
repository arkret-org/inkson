use std::rc::Rc;

use glory::prelude::*;
use glory::render::EventKind;

use super::session_shell::{block, icon_action};
use crate::presentation::widgets::*;
use crate::presentation::{InksonContext, View};
use crate::routes::Route;

pub(crate) fn notifications_drawer(
    _scope: &Scope,
    context: Rc<InksonContext>,
    open: Cage<bool>,
) -> View {
    reactive(open, move |scope, visible| {
        if !visible {
            return empty();
        }
        let settings_context = context.clone();
        let settings_route = Route::SettingsSection {
            section: "notifications".into(),
            filter: String::new(),
        };
        let settings = Box::new(
            internal_link()
                .target(settings_route.to_string())
                .class("btn icon sm ghost")
                .name(context.translated(scope, "notifications.tooltip.settings"))
                .fill(crate::components::ui_icon("settings"))
                .on(EventKind::Activate, move |_| {
                    open.revise(|value| *value = false);
                    settings_context.navigate(settings_route.clone());
                }),
        ) as View;
        let header = block(
            "notifications-drawer-header",
            vec![
                block(
                    "notifications-drawer-title",
                    vec![
                        crate::components::ui_icon("bell"),
                        plain(context.translated(scope, "nav.notifications")),
                    ],
                ),
                block(
                    "notifications-drawer-actions",
                    vec![
                        settings,
                        icon_action(
                            "btn icon",
                            context.translated(scope, "common.close"),
                            "x",
                            move || open.revise(|value| *value = false),
                        ),
                    ],
                ),
            ],
        );
        // This is a nonmodal side panel: retain the original CSS containing
        // block below the header and leave the sidebar available for navigation.
        let panel = Box::new(
            view()
                .role(glory::render::Role::Section)
                .class("notifications-drawer-panel")
                .name(context.translated(scope, "nav.notifications"))
                .on(EventKind::Keyboard, move |event| {
                    if matches!(
                        event,
                        glory::render::Event::Keyboard {
                            command: glory::render::KeyboardCommand::Dismiss,
                            ..
                        }
                    ) {
                        open.revise(|value| *value = false);
                    }
                })
                .fill(vec![
                    header,
                    crate::views::notifications::page(scope, context.clone(), Route::Notifications),
                ]),
        ) as View;
        block("notifications-drawer-layer", vec![panel])
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
