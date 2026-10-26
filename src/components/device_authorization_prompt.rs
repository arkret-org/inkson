//! Existing-device approval guidance; dismissing never grants authority.
use std::rc::Rc;

use glory::prelude::*;

use crate::presentation::widgets::{heading, line, paragraph, reactive, stack};
use crate::presentation::{InksonContext, View};
use crate::routes::Route;
pub fn device_authorization_prompt(
    scope: &Scope,
    context: Rc<InksonContext>,
    needs_device_authorization: Cage<bool>,
) -> View {
    let dismissed = scope.cage(false);
    scope.effect(move || {
        if !needs_device_authorization.get() {
            dismissed.revise(|value| *value = false);
        }
    });
    let state = scope.bond(move || (needs_device_authorization.get(), dismissed.get()));
    reactive(state, move |scope, (needed, dismissed_value)| {
        if !needed {
            return Box::new(widget(|_| Ok(())));
        }
        if dismissed_value {
            return Box::new(
                sapid::button()
                    .unstyled()
                    .class("btn mls-unlock-reopen-button primary")
                    .label(context.translated(scope, "device_authorization.reopen"))
                    .on_press(move || dismissed.revise(|value| *value = false)),
            );
        }
        let ctx = context.clone();
        let pairing = Box::new(
            sapid::button()
                .unstyled()
                .class("primary")
                .label(context.translated(scope, "device_authorization.open_pairing"))
                .on_press(move || {
                    dismissed.revise(|value| *value = true);
                    ctx.navigate(Route::SettingsDevicesPair);
                }),
        ) as View;
        let close = Box::new(
            sapid::button()
                .unstyled()
                .class("secondary")
                .label(context.translated(scope, "device_authorization.dismiss"))
                .on_press(move || dismissed.revise(|value| *value = true)),
        ) as View;
        let steps = [
            (
                "device_authorization.approve_step_existing_title",
                "device_authorization.approve_step_existing_body",
            ),
            (
                "device_authorization.approve_step_new_title",
                "device_authorization.approve_step_new_body",
            ),
        ]
        .into_iter()
        .map(|(title, body)| {
            stack(
                "mls-device-authorization-step",
                vec![
                    paragraph("", context.translated(scope, title)),
                    paragraph("", context.translated(scope, body)),
                ],
            )
        })
        .collect();
        let content = stack(
            "modal mls-recovery-modal device-authorization-dialog",
            vec![
                stack(
                    "modal-head event-head",
                    vec![
                        heading(
                            3,
                            "",
                            context.translated(scope, "device_authorization.title"),
                        ),
                        paragraph(
                            "muted",
                            context.translated(scope, "device_authorization.subtitle"),
                        ),
                    ],
                ),
                stack(
                    "modal-body mls-recovery-modal-body",
                    vec![
                        paragraph(
                            "muted",
                            context.translated(scope, "device_authorization.description"),
                        ),
                        stack(
                            "mls-device-authorization-details",
                            vec![stack("mls-device-authorization-path", steps)],
                        ),
                        line(
                            "mls-device-authorization-limitation",
                            vec![
                                super::ui_icon("alert"),
                                paragraph(
                                    "",
                                    context.translated(scope, "device_authorization.limitation"),
                                ),
                            ],
                        ),
                    ],
                ),
                line("modal-foot actions mls-unlock-row", vec![pairing, close]),
            ],
        );
        let mut content = Some(content);
        Box::new(
            sapid::dialog("device-authorization")
                .unstyled()
                .class("device-authorization-modal")
                .name(context.translated(scope, "device_authorization.title"))
                .open(true)
                .show_trigger(false)
                .show_close(false)
                .on_dismiss(move |_| dismissed.revise(|value| *value = true))
                .content(move || {
                    content
                        .take()
                        .unwrap_or_else(|| Box::new(widget(|_| Ok(()))))
                }),
        )
    })
}
