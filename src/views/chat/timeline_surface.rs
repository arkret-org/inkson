use std::cell::RefCell;
use std::collections::BTreeMap;

use super::native::{block, button, field};
use super::*;
use crate::presentation::widgets::{empty, line, paragraph, plain, reactive_distinct};

#[derive(Clone)]
pub(super) struct ChatTimelineContext {
    pub embedded: bool,
    pub visible_messages: Bond<Vec<ChatMessage>>,
    pub strand_scope_lookup: std::collections::BTreeMap<String, StrandScopeCircle>,
    pub private_sidecar_event_ids: std::collections::BTreeSet<String>,
    pub authority: arkret_sdk::AccountId,
    pub principal_id: arkret_sdk::DidCoreId,
    pub account_display_label: String,
    pub participants: Vec<SpaceParticipant>,
    pub selected_realm_id: String,
    pub selected_channel_id: String,
    pub sidecar_active: bool,
    pub direct_mode: bool,
    pub device_id: arkret_sdk::DeviceId,
    pub base_url: String,
    pub focus_message_id: String,
    pub blocked_actor_ids: std::collections::BTreeSet<String>,
    pub selected_channel_security_encrypted: bool,
    pub visible_channels_empty: bool,
    pub visible_message_count: usize,
    pub loading: bool,
    pub token: Cage<String>,
    pub frontier_state: Cage<String>,
}

#[derive(Clone, Copy)]
struct ScrollPosition {
    top: f64,
    follows_latest: bool,
}
impl Default for ScrollPosition {
    fn default() -> Self {
        Self {
            top: 0.0,
            follows_latest: true,
        }
    }
}
thread_local! {
 static POSITIONS:RefCell<BTreeMap<String,ScrollPosition>>=const{RefCell::new(BTreeMap::new())};
}
fn position(key: &str) -> ScrollPosition {
    POSITIONS.with(|values| values.borrow().get(key).copied().unwrap_or_default())
}
fn store_position(key: &str, top: f64, follows_latest: bool) {
    if top.is_finite() {
        POSITIONS.with(|values| {
            values.borrow_mut().insert(
                key.to_owned(),
                ScrollPosition {
                    top: top.max(0.0),
                    follows_latest,
                },
            )
        });
    }
}
pub(super) fn chat_timeline(
    scope: &Scope,
    app: Rc<crate::presentation::InksonContext>,
    controller: ChatController,
    context: Bond<ChatTimelineContext>,
) -> View {
    let target = scope.bond(move || {
        let value = context.get();
        (
            value.authority,
            value.device_id,
            value.selected_realm_id,
            value.selected_channel_id,
        )
    });
    reactive_distinct(target, move |scope, (account, device, realm, strand)| {
        let key = format!("{account:?}\u{1f}{device}\u{1f}{realm}\u{1f}{strand}");
        let saved = position(&key);
        let rows = context.get_untracked().visible_messages;
        let node = scope.cage(None);
        let boundary = MessageMenuBoundary {
            node,
            revision: scope.cage(0),
        };
        #[cfg(target_arch = "wasm32")]
        let saved_key = key.clone();
        #[cfg(target_arch = "wasm32")]
        let saved_context = Rc::downgrade(&app);
        #[cfg(target_arch = "wasm32")]
        let saved_generation = app.session_generation.get_untracked();
        #[cfg(target_arch = "wasm32")]
        let saved_account = app.active_account.get_untracked();
        #[cfg(target_arch = "wasm32")]
        let (feed_id, window) = timeline_window::virtual_timeline(
            scope,
            rows,
            context.get_untracked().focus_message_id,
            saved.follows_latest,
            saved.top,
            Rc::new(move |top, follows| {
                if let Some(context) = saved_context.upgrade()
                    && context.session_generation.try_get().ok() == Some(saved_generation)
                    && context.active_account.try_get().is_ok()
                    && context.session_matches(saved_generation, &saved_account)
                {
                    store_position(&saved_key, top, follows);
                }
            }),
        );
        #[cfg(not(target_arch = "wasm32"))]
        let feed_id = format!("chat-feed-{}", uuid_v7());
        #[cfg(not(target_arch = "wasm32"))]
        let logical = scope.cage(saved.top);
        let stream_app = app.clone();
        let stream = reactive_distinct(
            scope.bond(move || {
                let current = context.get();
                stream_app
                    .message_stream_hub
                    .visible_for(&current.selected_realm_id, &current.selected_channel_id)
            }),
            move |_, cards| {
                if cards.is_empty() {
                    return empty();
                };
                block(
                    "message-stream-previews",
                    cards
                        .into_iter()
                        .map(|card| {
                            let mut body = vec![paragraph(
                                "msg-body",
                                if card.text.is_empty() {
                                    "…".into()
                                } else {
                                    card.text
                                },
                            )];
                            if card.truncated {
                                body.push(paragraph(
                                    "message-stream-truncated",
                                    " Preview truncated; waiting for final message.",
                                ));
                            }
                            if card.stalled {
                                body.push(paragraph(
                                    "message-stream-stalled",
                                    " Generation paused; waiting for an update.",
                                ));
                            }
                            block(
                                if card.stalled {
                                    "chat-message message-stream-preview is-stalled"
                                } else {
                                    "chat-message message-stream-preview"
                                },
                                vec![
                                    line(
                                        "message-meta",
                                        vec![
                                            paragraph("message-sender", card.sender_actor_id),
                                            paragraph("message-stream-badge", "Generating…"),
                                        ],
                                    ),
                                    block("msg-body", body),
                                ],
                            )
                        })
                        .collect(),
                )
            },
        );
        #[cfg(target_arch = "wasm32")]
        let messages: View = {
            let selected = scope.bond(move || {
                let rows = rows.get();
                let window = window.get();
                rows[window.start.min(rows.len())
                    ..window.end.min(rows.len()).max(window.start.min(rows.len()))]
                    .to_vec()
            });
            let row_app = app.clone();
            let items = each(
                selected,
                |row| row.id.clone(),
                move |row, _| {
                    let app = row_app.clone();
                    widget(move |scope| {
                        message_row::message_row(
                            scope,
                            app.clone(),
                            controller,
                            row,
                            context,
                            boundary,
                        )
                        .build(scope)
                    })
                },
            );
            Box::new(
                view()
                    .class("chat-virtual-rows virtual-timeline")
                    .style(scope.bond(move || {
                        glory::style::Style::new()
                            .height(glory::style::Length::Px(window.get().total))
                    }))
                    .fill(
                        view()
                            .class("chat-virtual-slice")
                            .style(scope.bond(move || {
                                glory::style::Style::new()
                                    .position(glory::style::Position::Absolute)
                                    .top(glory::style::Length::Px(window.get().top))
                            }))
                            .fill(items),
                    ),
            )
        };
        #[cfg(not(target_arch = "wasm32"))]
        let messages: View = {
            let count = scope.bond(move || rows.get().len());
            let row_app = app.clone();
            let saved_key = key.clone();
            let inspect_key = key.clone();
            let following = scope.cage(saved.follows_latest);
            let total = scope.cage(0.0);
            let viewport_height = scope.cage(600.0);
            let native = glory::ui::list(
                count,
                move |index| rows.get_untracked()[index].id.clone(),
                move |index, id| {
                    let app = row_app.clone();
                    widget(move |scope| {
                        let row = scope.cage(rows.get_untracked()[index.get_untracked()].clone());
                        let expected = id.clone();
                        scope.effect(move || {
                            let all = rows.get();
                            let index = index.get();
                            if let Some(next) = all.get(index).filter(|row| row.id == expected) {
                                row.revise(|row| *row = next.clone());
                            }
                        });
                        message_row::message_row(
                            scope,
                            app.clone(),
                            controller,
                            row,
                            context,
                            boundary,
                        )
                        .build(scope)
                    })
                },
            )
            .measure(132.0)
            .overscan(12)
            .row_limit(120)
            .position(logical)
            .locate(move |id| rows.get_untracked().iter().position(|row| &row.id == id))
            .on_scroll(move |top| {
                if logical.get_untracked() != top {
                    logical.revise(|value| *value = top);
                    boundary
                        .revision
                        .revise(|value| *value = value.wrapping_add(1));
                }
                store_position(&saved_key, top, following.get_untracked());
            })
            .inspect(move |stats| {
                if total.get_untracked() != stats.total {
                    total.revise(|value| *value = stats.total);
                }
                if stats.viewport.height > 0.0
                    && viewport_height.get_untracked() != stats.viewport.height
                {
                    viewport_height.revise(|value| *value = stats.viewport.height);
                }
                if stats.user_moved {
                    let follow = stats.total - stats.viewport.height - stats.logical <= 32.0;
                    if following.get_untracked() != follow {
                        following.revise(|value| *value = follow);
                    }
                    store_position(&inspect_key, stats.logical, follow);
                }
            });
            let focus = context.get_untracked().focus_message_id;
            scope.effect(move || {
                let current = rows.get();
                if !focus.is_empty() {
                    if let Some(index) = current.iter().position(|row| row.id == focus) {
                        let target = index as f64 * 132.0;
                        if logical.get_untracked() != target {
                            logical.revise(|value| *value = target);
                        }
                    }
                } else if following.get_untracked() {
                    let target = (total.get() - viewport_height.get()).max(0.0);
                    if logical.get_untracked() != target {
                        logical.revise(|value| *value = target);
                    }
                }
            });
            Box::new(native)
        };
        let empty_app = app.clone();
        let empty_state = reactive_distinct(
            scope.bond(move || {
                let value = context.get();
                (
                    value.visible_channels_empty,
                    value.visible_message_count == 0,
                    value.loading,
                    value.embedded,
                )
            }),
            move |scope, (no_channels, no_messages, loading, embedded)| {
                if no_channels {
                    let mut parts = vec![
                        crate::components::ui_icon("plus"),
                        paragraph("t", empty_app.translated(scope, "chat.empty.title")),
                        paragraph("s", empty_app.translated(scope, "chat.empty.description")),
                    ];
                    if !embedded {
                        parts.push(button(
                            empty_app.translated(scope, "chat.empty.create_button"),
                            "primary discussion-empty-create-button",
                            true,
                            move || controller.open_create_dialog(),
                        ));
                    }
                    block(
                        "empty-state discussion-empty-main discussion-main-empty",
                        parts,
                    )
                } else if no_messages {
                    if loading {
                        block(
                            "discussion-empty discussion-loading",
                            vec![
                                Box::new(text().class("discussion-loading-spinner").content("")),
                                Box::new(
                                    text().content(
                                        empty_app.translated(scope, "chat.loading_messages"),
                                    ),
                                ),
                            ],
                        )
                    } else {
                        paragraph(
                            "discussion-empty",
                            empty_app.translated(scope, "chat.empty_messages"),
                        )
                    }
                } else {
                    empty()
                }
            },
        );
        let report = report_dialog(scope, app.clone(), controller, context);
        let Ok(identity) = glory::render::SemanticId::new(feed_id) else {
            return paragraph(
                "message-error",
                "The timeline presentation identity is unavailable.",
            );
        };
        Box::new(
            view()
                .class("discussion-chat-feed message-list")
                .node_ref(node)
                .on(glory::render::EventKind::Scroll, move |_| {
                    boundary
                        .revision
                        .revise(|value| *value = value.wrapping_add(1));
                })
                .on(glory::render::EventKind::Resize, move |_| {
                    boundary
                        .revision
                        .revise(|value| *value = value.wrapping_add(1));
                })
                .semantics(Some(Box::new(glory::render::Semantics {
                    id: Some(identity),
                    ..Default::default()
                })))
                .fill(vec![stream, messages, report, empty_state]),
        )
    })
}

fn report_dialog(
    scope: &Scope,
    app: Rc<crate::presentation::InksonContext>,
    controller: ChatController,
    context: Bond<ChatTimelineContext>,
) -> View {
    let open = scope.bond(move || controller.moderation_report_draft.get().is_some());
    reactive_distinct(open, move |scope, open| {
        if !open {
            return empty();
        };
        let app = app.clone();
        crate::components::dismissible_popup(
            scope,
            app.clone(),
            crate::components::DismissiblePopupProps {
                overlay_class: "discussion-modal-backdrop moderation-report-modal".into(),
                surface_class: "discussion-modal".into(),
                aria_label: app.tr("moderation.report.title"),
                on_dismiss: Rc::new(move |()| controller.cancel_moderation_report()),
                overlay_test_id: None,
                surface_test_id: None,
                overlay_style: None,
                surface_style: None,
                children: Rc::new(move |scope| {
                    let label_app = app.clone();
                    let options = [
                        "spam",
                        "harassment",
                        "hate_speech",
                        "nsfw",
                        "illegal",
                        "misinformation",
                        "other",
                    ]
                    .into_iter()
                    .map(|reason| {
                        #[cfg(target_arch = "wasm32")]
                        {
                            sapid::select_option(
                                reason,
                                label_app.tr(&format!("moderation.report.reason.{reason}")),
                            )
                        }
                        #[cfg(not(target_arch = "wasm32"))]
                        {
                            crate::presentation::native_choice::NativeChoiceOption::new(
                                reason,
                                label_app.tr(&format!("moderation.report.reason.{reason}")),
                            )
                        }
                    })
                    .collect::<Vec<_>>();
                    let reason = scope.bond(move || {
                        controller
                            .moderation_report_draft
                            .get()
                            .map(|draft| draft.reason)
                    });
                    let description = scope.bond(move || {
                        controller
                            .moderation_report_draft
                            .get()
                            .map(|draft| draft.description)
                            .unwrap_or_default()
                    });
                    let enabled = scope.bond(move || !controller.moderation_report_pending.get());
                    let submit = scope.bond(move || {
                        !controller.moderation_report_pending.get()
                            && controller
                                .moderation_report_draft
                                .get()
                                .is_some_and(|draft| {
                                    draft.reason != "other" || !draft.description.trim().is_empty()
                                })
                    });
                    let change_reason = move |value: Option<String>| {
                        if let Some(value) = value {
                            controller.update_moderation_report_reason(value);
                        }
                    };
                    #[cfg(target_arch = "wasm32")]
                    let reason_control: View = Box::new(
                        sapid::native_select("moderation-report-reason")
                            .unstyled()
                            .class("moderation-report-reason")
                            .name(app.translated(scope, "moderation.report.reason"))
                            .enabled(enabled)
                            .value(reason)
                            .options(options)
                            .on_value_change(change_reason),
                    );
                    #[cfg(not(target_arch = "wasm32"))]
                    let reason_control = crate::presentation::native_choice::native_choice(
                        scope,
                        crate::presentation::native_choice::NativeChoiceProps::new(
                            "moderation-report-reason",
                            app.translated(scope, "moderation.report.reason"),
                            reason,
                            options,
                            change_reason,
                        )
                        .enabled(enabled)
                        .class("moderation-report-reason")
                        .close_label(app.translated(scope, "common.close")),
                    );
                    block(
                        "discussion-modal-content",
                        vec![
                            crate::presentation::widgets::heading(
                                2,
                                "discussion-modal-head",
                                app.translated(scope, "moderation.report.title"),
                            ),
                            block(
                                "discussion-modal-body workflow-form",
                                vec![
                                    plain(app.translated(scope, "moderation.report.help")),
                                    line(
                                        "form-row",
                                        vec![
                                            plain(
                                                app.translated(scope, "moderation.report.reason"),
                                            ),
                                            reason_control,
                                        ],
                                    ),
                                    field(
                                        app.translated(scope, "moderation.report.description"),
                                        "moderation-report-description",
                                        description,
                                        true,
                                        move |value| {
                                            controller.update_moderation_report_description(value)
                                        },
                                    ),
                                ],
                            ),
                            line(
                                "discussion-modal-actions",
                                vec![
                                    button(
                                        app.translated(scope, "common.cancel"),
                                        "secondary",
                                        enabled,
                                        move || controller.cancel_moderation_report(),
                                    ),
                                    button(
                                        app.translated(scope, "moderation.report.submit"),
                                        "primary moderation-report-submit",
                                        submit,
                                        move || {
                                            controller.submit_moderation_report(
                                                message_row::command_context(
                                                    &context.get_untracked(),
                                                    false,
                                                ),
                                            )
                                        },
                                    ),
                                ],
                            ),
                        ],
                    )
                }),
            },
        )
    })
}

#[cfg(test)]
mod row_lifetime_tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;
    #[test]
    fn overlapping_virtual_rows_keep_their_component_instances_when_window_slides() {
        let app = glory::ui::App::memory();
        let scope = app.scope();
        let start = scope.cage(0usize);
        let mounts = Rc::new(RefCell::new(BTreeMap::<String, usize>::new()));
        let observed = mounts.clone();
        let rows = scope.bond(move || {
            ["a", "b", "c", "d", "e"]
                .into_iter()
                .skip(start.get())
                .take(3)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        });
        app.mount(each(rows, Clone::clone, move |row, _| {
            let observed = observed.clone();
            widget(move |scope| {
                let id = row.get_untracked();
                *observed.borrow_mut().entry(id.clone()).or_default() += 1;
                text().content(id).build(scope)
            })
        }))
        .unwrap();
        app.flush().unwrap();
        let mut previous = 0;
        for next in [1, 2, 1] {
            let before = mounts.borrow().clone();
            start.revise(|value| *value = next);
            app.flush().unwrap();
            for id in &["a", "b", "c", "d", "e"][next.max(previous)..(next + 3).min(previous + 3)] {
                assert_eq!(mounts.borrow().get(*id), before.get(*id));
            }
            previous = next;
        }
    }
}
