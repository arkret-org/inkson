//! Chat presentation uses the shared semantic widget contract directly.
use super::*;

pub(super) fn block(class: impl Into<String>, children: Vec<View>) -> View {
    Box::new(view().class(class.into()).fill(children))
}
pub(super) fn button(
    label: impl Into<Lotus<String>>,
    class: impl Into<String>,
    enabled: impl Into<Lotus<bool>>,
    on_press: impl FnMut() + 'static,
) -> View {
    Box::new(
        sapid::button()
            .unstyled()
            .class(class.into())
            .label(label)
            .enabled(enabled)
            .on_press(on_press),
    )
}
pub(super) fn icon_button(
    icon: &str,
    label: impl Into<Lotus<String>>,
    class: impl Into<String>,
    enabled: impl Into<Lotus<bool>>,
    on_press: impl FnMut() + 'static,
) -> View {
    Box::new(
        sapid::button()
            .unstyled()
            .name(label)
            .class(class.into())
            .enabled(enabled)
            .fill(crate::components::ui_icon(icon))
            .on_press(on_press),
    )
}
pub(super) fn field(
    label: impl Into<Lotus<String>>,
    class: impl Into<String>,
    value: impl Into<Lotus<String>>,
    multiline: bool,
    change: impl FnMut(String) + 'static,
) -> View {
    let label = label.into();
    let value = value.into();
    let class = class.into();
    let change = Rc::new(std::cell::RefCell::new(change));
    Box::new(widget(move |scope| {
        let empty_value = value.clone();
        let empty = scope.bond(move || empty_value.get().is_empty());
        let prompt = label.clone();
        let change = change.clone();
        block(
            "input-prompt-host chat-field-prompt-host",
            vec![
                Box::new(
                    sapid::text_field()
                        .unstyled()
                        .name(label.clone())
                        .class(class.clone())
                        .value(value.clone())
                        .multiline(multiline)
                        .on_value_change(move |next| change.borrow_mut()(next)),
                ),
                crate::presentation::widgets::reactive_distinct(empty, move |_, empty| {
                    if empty {
                        Box::new(text().class("input-empty-prompt").content(prompt.clone()))
                    } else {
                        crate::presentation::widgets::empty()
                    }
                }),
            ],
        )
        .build(scope)
    }))
}

pub(super) fn date_time(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    key: impl Into<String>,
    label: impl Into<Lotus<String>>,
    value: Cage<String>,
) -> View {
    date_time_with_field(scope, context, key, label, value, None)
}

pub(super) fn date_time_with_field(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    key: impl Into<String>,
    label: impl Into<Lotus<String>>,
    value: Cage<String>,
    field: Option<sapid::FieldControl>,
) -> View {
    let key = format!(
        "chat-datetime-{}-{}",
        scope.id().slot(),
        &message_row::presentation_key(&key.into())[..16]
    );
    let Some(today) = crate::clock::canonical_to_local_datetime_input(
        &arkret_sdk::canonical::format_timestamp_canonical(crate::clock::now_utc()),
    )
    .ok()
    .and_then(|value| {
        value
            .get(..10)
            .and_then(|day| sapid::CivilDate::parse_iso(day).ok())
    }) else {
        return crate::presentation::widgets::paragraph(
            "error",
            "The local date could not be determined.",
        );
    };
    let provider = scope.bond(move || {
        sapid::DatesProvider::new(today).today(Some(today)).locale(
            if context.locale.get() == crate::i18n::UiLocale::Zh {
                sapid::DateLocale::ZhCn
            } else {
                sapid::DateLocale::En
            },
        )
    });
    let selected = scope.bond(move || sapid::parse_local_date_time(&value.get()).ok());
    let picker = sapid::date_time_picker(key, provider, sapid::DateTimePolicy::Civil)
        .unstyled()
        .name(label)
        .value(selected)
        .on_value_change(move |next| {
            value.revise(|value| {
                *value = next.map(sapid::format_local_date_time).unwrap_or_default()
            })
        });
    Box::new(if let Some(field) = field {
        picker.field(field)
    } else {
        picker
    })
}

#[cfg(test)]
mod field_tests {
    use glory::render::{Event, NodeId, Props};

    use super::*;

    fn class_node(app: &glory::App, class: &str) -> Option<NodeId> {
        let tree = app.tree();
        let mut pending = tree.roots().to_vec();
        while let Some(id) = pending.pop() {
            let node = tree.node(id).unwrap();
            if node
                .descriptor
                .view()
                .classes
                .iter()
                .any(|value| value == class)
            {
                return Some(id);
            }
            pending.extend(node.children.iter().copied());
        }
        None
    }

    fn edit(app: &glory::App, input: NodeId, value: &str) {
        let revision = match app.tree().node(input).unwrap().descriptor.view().props {
            Props::Input(props) => props.revision,
            _ => panic!("the field must remain a real Input"),
        };
        app.dispatch(
            input,
            Event::ValueChanged {
                value: value.into(),
                composing: false,
                revision,
            },
        )
        .unwrap();
        app.flush().unwrap();
    }

    #[test]
    fn empty_guidance_tracks_locale_without_replacing_the_live_input_or_its_draft() {
        let app = glory::App::memory();
        let value = app.scope().cage(String::new());
        let label = app.scope().cage("Question".to_owned());
        app.mount(field(
            label,
            "poll-question-input",
            value,
            false,
            move |next| {
                value.revise(|value| *value = next);
            },
        ))
        .unwrap();
        app.flush().unwrap();
        let input = class_node(&app, "poll-question-input").unwrap();
        let prompt = class_node(&app, "input-empty-prompt").unwrap();
        assert!(matches!(
            app.tree().node(prompt).unwrap().descriptor.view().props,
            Props::Text(props) if props.content == "Question"
        ));
        edit(&app, input, "literal {number} 原文");
        assert!(class_node(&app, "input-empty-prompt").is_none());
        label.revise(|label| *label = "问题".to_owned());
        app.flush().unwrap();
        assert_eq!(class_node(&app, "poll-question-input"), Some(input));
        assert_eq!(value.get_untracked(), "literal {number} 原文");
        edit(&app, input, "");
        let prompt = class_node(&app, "input-empty-prompt").unwrap();
        assert!(matches!(
            app.tree().node(prompt).unwrap().descriptor.view().props,
            Props::Text(props) if props.content == "问题"
        ));
        assert_eq!(class_node(&app, "poll-question-input"), Some(input));
    }
}
