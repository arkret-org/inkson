//! A native choice uses supported intrinsic buttons and a managed dialog.
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

use glory::prelude::*;
use glory::render::{Action, EventKind, PopupKind, SemanticId, Semantics};

use super::View;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeChoiceOption {
    pub value: String,
    pub label: String,
    pub enabled: bool,
}
impl NativeChoiceOption {
    pub fn new(value: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            label: label.into(),
            enabled: true,
        }
    }
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

pub struct NativeChoiceProps {
    pub key: String,
    pub label: Lotus<String>,
    pub value: Lotus<Option<String>>,
    pub options: Vec<NativeChoiceOption>,
    pub enabled: Lotus<bool>,
    pub class: String,
    pub close_label: Lotus<String>,
    pub control_id: Option<SemanticId>,
    pub on_change: Rc<dyn Fn(Option<String>)>,
}
impl NativeChoiceProps {
    pub fn new(
        key: impl Into<String>,
        label: impl Into<Lotus<String>>,
        value: impl Into<Lotus<Option<String>>>,
        options: Vec<NativeChoiceOption>,
        on_change: impl Fn(Option<String>) + 'static,
    ) -> Self {
        Self {
            key: key.into(),
            label: label.into(),
            value: value.into(),
            options,
            enabled: true.into(),
            class: String::new(),
            close_label: "Close".to_owned().into(),
            control_id: None,
            on_change: Rc::new(on_change),
        }
    }
    pub fn enabled(mut self, enabled: impl Into<Lotus<bool>>) -> Self {
        self.enabled = enabled.into();
        self
    }
    pub fn class(mut self, class: impl Into<String>) -> Self {
        self.class = class.into();
        self
    }
    pub fn close_label(mut self, label: impl Into<Lotus<String>>) -> Self {
        self.close_label = label.into();
        self
    }
    pub fn control_id(mut self, id: SemanticId) -> Self {
        self.control_id = Some(id);
        self
    }
}

pub fn native_choice(scope: &Scope, props: NativeChoiceProps) -> View {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let serial = NEXT.fetch_add(1, Ordering::Relaxed);
    let key = format!("native-choice-{serial:x}");
    let trigger_id = match props.control_id {
        Some(id) => id,
        None => match SemanticId::new(format!("{key}-trigger")) {
            Ok(id) => id,
            Err(error) => {
                scope.report_error(error);
                return super::widgets::empty();
            }
        },
    };
    let options = Rc::new(props.options);
    let value = props.value;
    let enabled = props.enabled;
    let label = props.label;
    let open = scope.cage(false);
    let focused = scope.cage(false);
    let references = Rc::new(options.iter().map(|_| scope.cage(None)).collect::<Vec<_>>());
    let text = scope.bond({
        let value = value.clone();
        let options = options.clone();
        let label = label.clone();
        move || {
            let selected = value.get();
            options
                .iter()
                .find(|option| Some(&option.value) == selected.as_ref())
                .map(|option| option.label.clone())
                .unwrap_or_else(|| label.get())
        }
    });
    let name = scope.bond({
        let label = label.clone();
        move || format!("{}: {}", label.get(), text.get())
    });
    let metadata = scope.bond({
        let trigger_id = trigger_id.clone();
        move || {
            Some(Box::new(Semantics {
                id: Some(trigger_id.clone()),
                expanded: Some(open.get()),
                popup: Some(PopupKind::Dialog),
                ..Default::default()
            }))
        }
    });
    let trigger_enabled = enabled.clone();
    let trigger = glory::ui::button()
        .class(format!(
            "btn secondary native-choice-trigger {} {}",
            props.class, props.key
        ))
        .name(name)
        .label(text)
        .enabled(enabled.clone())
        .semantics(metadata)
        .on(EventKind::Activate, move |_| {
            if glory::core::untracked(|| trigger_enabled.get()) {
                open.revise(|open| *open = !*open);
            }
        });
    let weak = scope.downgrade();
    let focus_options = options.clone();
    let focus_references = references.clone();
    let focus_enabled = enabled.clone();
    let focus_value = value.clone();
    scope.effect(move || {
        if !open.get() {
            if focused.get_untracked() {
                focused.revise(|focused| *focused = false);
            }
            return;
        }
        if !focus_enabled.get() {
            open.revise(|open| *open = false);
            return;
        }
        if focused.get_untracked() {
            return;
        }
        let selected = focus_value.get();
        let index = focus_options
            .iter()
            .position(|option| option.enabled && Some(&option.value) == selected.as_ref())
            .or_else(|| focus_options.iter().position(|option| option.enabled));
        if let Some(index) = index
            && let Some(node) = focus_references[index].get()
            && let Some(scope) = weak.upgrade()
        {
            if !scope
                .capabilities()
                .is_ok_and(|capabilities| capabilities.focus)
            {
                return;
            }
            match scope.action(Action::Focus(node)) {
                Ok(()) => focused.revise(|focused| *focused = true),
                Err(error) => scope.report_error(error),
            }
        }
    });
    let dialog_enabled = enabled.clone();
    let on_change = props.on_change;
    let dialog = sapid::dialog(key)
        .unstyled()
        .class("modal native-choice-panel")
        .name(label.clone())
        .title(label)
        .close_label(props.close_label)
        .content_policy(sapid::ContentPolicy::KeepMounted)
        .open(open)
        .show_trigger(false)
        .return_focus(trigger_id)
        .dismiss_on_escape(true)
        .dismiss_on_outside(true)
        .on_open_change(move |next| {
            open.revise(|open| *open = next && glory::core::untracked(|| dialog_enabled.get()))
        })
        .content(move || {
            let options = options.clone();
            let references = references.clone();
            let value = value.clone();
            let enabled = enabled.clone();
            let on_change = on_change.clone();
            widget(move |scope| {
                let children = options
                    .iter()
                    .enumerate()
                    .map(|(index, option)| {
                        let option = option.clone();
                        let option_value = option.value.clone();
                        let selected = value.clone();
                        let allowed = enabled.clone();
                        let class = scope.bond(move || {
                            format!(
                                "btn native-choice-option {}",
                                if selected.get().as_ref() == Some(&option_value) {
                                    "primary"
                                } else {
                                    "secondary"
                                }
                            )
                        });
                        let selected = value.clone();
                        let option_value = option.value.clone();
                        let pressed = scope.bond(move || {
                            Some(Box::new(Semantics {
                                pressed: Some(selected.get().as_ref() == Some(&option_value)),
                                ..Default::default()
                            }))
                        });
                        let option_enabled = option.enabled;
                        let effective = scope.bond({
                            let allowed = allowed.clone();
                            move || option_enabled && allowed.get()
                        });
                        let on_change = on_change.clone();
                        Box::new(
                            glory::ui::button()
                                .class(class)
                                .label(option.label.clone())
                                .name(option.label)
                                .enabled(effective)
                                .semantics(pressed)
                                .node_ref(references[index])
                                .on(EventKind::Activate, move |_| {
                                    if !option.enabled
                                        || !glory::core::untracked(|| allowed.get())
                                        || !open.get_untracked()
                                    {
                                        return;
                                    }
                                    open.revise(|open| *open = false);
                                    on_change(Some(option.value.clone()));
                                }),
                        ) as View
                    })
                    .collect::<Vec<_>>();
                view()
                    .class("modal-body native-choice-options")
                    .style(
                        Style::new()
                            .display(Display::Flex)
                            .flex_direction(FlexDirection::Column)
                            .gap(6.0),
                    )
                    .fill(children)
                    .build(scope)
            })
        });
    Box::new(view().class("native-choice").fill((trigger, dialog)))
}

#[cfg(test)]
mod tests;
