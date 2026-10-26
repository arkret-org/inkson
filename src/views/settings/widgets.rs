//! Native semantic controls shared by the preference editors.
use std::cell::RefCell;
use std::rc::Rc;

use glory::prelude::*;

pub(crate) use crate::presentation::widgets::{empty, heading, paragraph, plain, reactive};
use crate::presentation::{InksonContext, View};

pub(crate) fn field(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: &str,
    label_key: &str,
    value: Cage<String>,
    enabled: impl Into<Lotus<bool>>,
    multiline: bool,
    changed: impl FnMut(String) + 'static,
) -> View {
    let enabled = enabled.into();
    let changed = Rc::new(RefCell::new(changed));
    Box::new(
        sapid::field(key)
            .unstyled()
            .class(format!("field form-field {key}"))
            .label(context.translated(scope, label_key))
            .control(move |field| {
                let changed = changed.clone();
                sapid::text_field()
                    .unstyled()
                    .class("input")
                    .field(field)
                    .value(value)
                    .enabled(enabled.clone())
                    .multiline(multiline)
                    .on_value_change(move |next| changed.borrow_mut()(next))
            }),
    )
}
pub(crate) fn input(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: &str,
    label_key: &str,
    value: Cage<String>,
    enabled: impl Into<Lotus<bool>>,
) -> View {
    field(
        scope,
        context,
        key,
        label_key,
        value,
        enabled,
        false,
        move |next| value.revise(|value| *value = next),
    )
}
pub(crate) fn action(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: &str,
    label_key: &str,
    class: &str,
    enabled: impl Into<Lotus<bool>>,
    handler: impl FnMut() + 'static,
) -> View {
    Box::new(
        sapid::button()
            .unstyled()
            .class(format!("{class} {key}"))
            .label(context.translated(scope, label_key))
            .enabled(enabled)
            .on_press(handler),
    )
}
pub(crate) fn toggle(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: &str,
    label_key: &str,
    checked: impl Into<Lotus<bool>>,
    enabled: impl Into<Lotus<bool>>,
    handler: impl FnMut(bool) + 'static,
) -> View {
    Box::new(
        sapid::checkbox()
            .unstyled()
            .class(format!("settings-toggle {key}"))
            .label(context.translated(scope, label_key))
            .checked(checked)
            .enabled(enabled)
            .on_checked_change(handler),
    )
}
pub(crate) fn switch_toggle(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: &str,
    label_key: &str,
    checked: impl Into<Lotus<bool>>,
    enabled: impl Into<Lotus<bool>>,
    handler: impl FnMut(bool) + 'static,
) -> View {
    Box::new(
        sapid::switch()
            .unstyled()
            .class(format!("settings-toggle settings-switch {key}"))
            .label(context.translated(scope, label_key))
            .checked(checked)
            .enabled(enabled)
            .on_checked_change(handler),
    )
}
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn select_key(options: &[(String, String)], value: &str) -> Option<String> {
    options
        .iter()
        .position(|(candidate, _)| candidate == value)
        .map(|index| format!("opt-{index}"))
}
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn select_value(options: &[(String, String)], key: &str) -> Option<String> {
    let index = key.strip_prefix("opt-")?.parse::<usize>().ok()?;
    if key != format!("opt-{index}") {
        return None;
    }
    options.get(index).map(|(value, _)| value.clone())
}
pub(crate) fn choice(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: &str,
    label_key: &str,
    value: Cage<String>,
    options: Vec<(String, String)>,
    enabled: impl Into<Lotus<bool>>,
    handler: impl FnMut(String) + 'static,
) -> View {
    #[cfg(target_arch = "wasm32")]
    {
        web_choice(
            scope, context, key, label_key, value, options, enabled, handler,
        )
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use crate::presentation::native_choice::{
            NativeChoiceOption, NativeChoiceProps, native_choice,
        };
        let enabled = enabled.into();
        let handler = Rc::new(RefCell::new(handler));
        let select_key = format!("{key}-options");
        let label = context.translated(scope, label_key);
        let close = context.translated(scope, "common.close");
        let selected = scope.bond(move || Some(value.get()));
        Box::new(
            sapid::field(key)
                .unstyled()
                .class(format!("field {key}"))
                .label(label)
                .control(move |field| {
                    let handler = handler.clone();
                    let select_key = select_key.clone();
                    let options = options.clone();
                    let enabled = enabled.clone();
                    widget(move |scope| {
                        let handler = handler.clone();
                        native_choice(
                            scope,
                            NativeChoiceProps::new(
                                select_key.clone(),
                                label,
                                selected,
                                options
                                    .iter()
                                    .map(|(value, label)| {
                                        NativeChoiceOption::new(value.clone(), label.clone())
                                    })
                                    .collect(),
                                move |next| {
                                    if let Some(next) = next {
                                        handler.borrow_mut()(next)
                                    }
                                },
                            )
                            .control_id(field.id.clone())
                            .class("select")
                            .enabled(enabled.clone())
                            .close_label(close),
                        )
                        .build(scope)
                    })
                }),
        )
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn web_choice(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: &str,
    label_key: &str,
    value: Cage<String>,
    options: Vec<(String, String)>,
    enabled: impl Into<Lotus<bool>>,
    handler: impl FnMut(String) + 'static,
) -> View {
    let options = Rc::new(options);
    let selection = options.clone();
    let selected = scope.bond(move || select_key(&selection, &value.get()));
    let enabled = enabled.into();
    let handler = Rc::new(RefCell::new(handler));
    let select_key = format!("{key}-options");
    Box::new(
        sapid::field(key)
            .unstyled()
            .class(format!("field {key}"))
            .label(context.translated(scope, label_key))
            .control(move |field| {
                let handler = handler.clone();
                let callback_options = options.clone();
                sapid::select(select_key.clone())
                    .unstyled()
                    .class("select")
                    .field(field)
                    .value(selected)
                    .enabled(enabled.clone())
                    .options(options.iter().enumerate().map(|(index, (_, label))| {
                        sapid::select_option(format!("opt-{index}"), label.clone())
                    }))
                    .on_value_change(move |next| {
                        if let Some(value) =
                            next.and_then(|key| select_value(&callback_options, &key))
                        {
                            handler.borrow_mut()(value)
                        }
                    })
            }),
    )
}

pub(crate) fn card(
    scope: &Scope,
    context: Rc<InksonContext>,
    title_key: &str,
    children: Vec<View>,
) -> View {
    let mut nodes = vec![line(
        "event-head",
        vec![plain(context.translated(scope, title_key))],
    )];
    nodes.extend(children);
    stack("event", nodes)
}
pub(crate) fn status(value: impl Into<Lotus<String>>) -> View {
    let value = value.into();
    Box::new(widget(move |scope| {
        let mut content = reactive(value.clone(), |_, message| {
            if message.trim().is_empty() {
                empty()
            } else {
                paragraph("muted write-status", message)
            }
        });
        content.build(scope)
    }))
}
pub(crate) fn confirmation(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: &str,
    title: impl Into<Lotus<String>>,
    body: View,
    mut close: impl FnMut() + 'static,
) -> View {
    let mut body = Some(body);
    Box::new(
        sapid::dialog(key)
            .unstyled()
            .class(format!("modal event {key}"))
            .open(true)
            .show_trigger(false)
            .title(title)
            .close_label(context.translated(scope, "common.cancel"))
            .on_open_change(move |open| {
                if !open {
                    close()
                }
            })
            .content(move || body.take().unwrap_or_else(|| empty())),
    )
}
pub(crate) fn spawn(scope: &Scope, future: impl std::future::Future<Output = ()> + 'static) {
    if let Err(error) = scope.owner().spawn(future) {
        scope.report_error(error);
    }
}
pub(crate) fn stack(class: impl Into<String>, children: Vec<View>) -> View {
    crate::presentation::widgets::stack(class, children)
}
pub(crate) fn line(class: impl Into<String>, children: Vec<View>) -> View {
    crate::presentation::widgets::line(class, children)
}

/// Keeps empty-field guidance visible on hosts without a placeholder property.
pub(crate) fn input_prompt(
    scope: &Scope,
    prompt: Lotus<String>,
    value: Cage<String>,
    control: View,
) -> View {
    let visible = scope.bond(move || value.get().is_empty());
    crate::presentation::widgets::stack(
        "input-prompt-host",
        vec![
            control,
            reactive(visible, move |_, visible| {
                if visible {
                    paragraph("input-empty-prompt", prompt.clone())
                } else {
                    empty()
                }
            }),
        ],
    )
}

#[cfg(test)]
mod select_mapping_tests {
    use glory::render::{ChoiceCommand, Event};

    use super::*;
    #[test]
    fn actual_choice_retains_full_account_values_across_keyboard_selection() {
        let app = App::memory();
        let directory = tempfile::tempdir().unwrap();
        let context = InksonContext::new(
            app.scope(),
            crate::presentation::BootState {
                config_store: crate::config::LocalConfigStore::with_path(
                    directory.path().join("config.json"),
                ),
                config: crate::config::ClientConfig::default(),
                state_store: crate::presentation::SharedStateStore::new(
                    crate::state::LocalStateStore::with_path(directory.path().join("state.json")),
                ),
                initial_credential: String::new(),
                realm_tree_nodes: vec![],
            },
            crate::routes::Route::Dashboard,
            |_| {
                Box::pin(async {
                    crate::runtime::session::CurrentSessionRefresh::retry_later("test")
                })
            },
        );
        let account = |principal| {
            arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new(principal).unwrap(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:provider.example").unwrap(),
            )
            .to_string()
        };
        let first = account("ak:did_core:web:account-one.example");
        let second = account("ak:did_core:web:account-two.example");
        assert!(first.len() > 64);
        let selected = app.scope().cage(first.clone());
        app.mount(web_choice(
            app.scope(),
            context.clone(),
            "account-choice",
            "friendly.account",
            selected,
            vec![
                (first.clone(), "First".into()),
                (second.clone(), "Second".into()),
            ],
            true,
            move |next| selected.revise(|value| *value = next),
        ))
        .unwrap();
        assert_eq!(selected.get(), first);
        let mut nodes = app.tree().roots().to_vec();
        let trigger = loop {
            let id = nodes.pop().expect("combobox exists");
            let tree = app.tree();
            let node = tree.node(id).unwrap();
            if node
                .descriptor
                .view()
                .semantics
                .as_ref()
                .is_some_and(|s| s.combobox.is_some())
            {
                break id;
            }
            nodes.extend(node.children.iter().copied());
        };
        app.dispatch(
            trigger,
            Event::Choice {
                from: trigger,
                command: ChoiceCommand::OpenLast,
            },
        )
        .unwrap();
        app.dispatch(
            trigger,
            Event::Choice {
                from: trigger,
                command: ChoiceCommand::Commit,
            },
        )
        .unwrap();
        app.flush().unwrap();
        assert_eq!(selected.get(), second);
        let options = vec![(first.clone(), "First".into()), (second, "Second".into())];
        assert_eq!(select_value(&options, "opt-999"), None);
        assert_eq!(select_value(&options, "opt-01"), None);
        assert_eq!(select_value(&options, &first), None);
        #[cfg(not(target_arch = "wasm32"))]
        {
            app.clear().unwrap();
            app.mount(choice(
                app.scope(),
                context,
                "native-account-choice",
                "friendly.account",
                selected,
                options,
                true,
                move |next| selected.revise(|value| *value = next),
            ))
            .unwrap();
            let find_class = |class: &str| {
                let tree = app.tree();
                let mut pending = tree.roots().to_vec();
                let mut found = Vec::new();
                while let Some(id) = pending.pop() {
                    let node = tree.node(id).unwrap();
                    if node
                        .descriptor
                        .view()
                        .classes
                        .iter()
                        .any(|value| value == class)
                    {
                        found.push(id);
                    }
                    pending.extend(node.children.iter().rev().copied());
                }
                found
            };
            let trigger = find_class("native-choice-trigger")[0];
            assert!(app.dispatch(trigger, Event::Activate).unwrap());
            let choices = find_class("native-choice-option");
            assert_eq!(choices.len(), 2);
            assert!(app.dispatch(choices[0], Event::Activate).unwrap());
            assert_eq!(selected.get(), first);
            assert_eq!(find_class("native-choice-trigger"), vec![trigger]);
            assert!(
                app.tree()
                    .node(trigger)
                    .unwrap()
                    .descriptor
                    .view()
                    .semantics
                    .as_ref()
                    .unwrap()
                    .id
                    .is_some()
            );
        }
    }
    #[test]
    fn empty_status_has_no_text_placeholder_and_keeps_adjacent_nodes_stable() {
        let app = App::memory();
        let message = app.scope().cage(String::new());
        app.mount(view().class("status-regression-layout").fill(vec![
            plain("before"),
            status(message),
            plain("after"),
        ]))
        .unwrap();
        let texts = || {
            let tree = app.tree();
            let mut pending = tree.roots().iter().rev().copied().collect::<Vec<_>>();
            let mut found = Vec::new();
            while let Some(id) = pending.pop() {
                let node = tree.node(id).unwrap();
                let view = node.descriptor.view();
                if let glory::render::Props::Text(text) = view.props {
                    found.push((id, text.content.clone()));
                }
                pending.extend(node.children.iter().rev().copied());
            }
            found
        };
        let initial = texts();
        assert_eq!(
            initial
                .iter()
                .map(|(_, text)| text.as_str())
                .collect::<Vec<_>>(),
            vec!["before", "after"]
        );
        message.revise(|value| *value = "Saving".into());
        app.flush().unwrap();
        let shown = texts();
        assert_eq!(
            shown
                .iter()
                .map(|(_, text)| text.as_str())
                .collect::<Vec<_>>(),
            vec!["before", "Saving", "after"]
        );
        assert_eq!(shown.first().unwrap().0, initial[0].0);
        assert_eq!(shown.last().unwrap().0, initial[1].0);
        message.revise(|value| value.clear());
        app.flush().unwrap();
        assert_eq!(texts(), initial);
    }
}
