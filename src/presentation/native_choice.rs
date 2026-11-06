//! Domain values mapped to Sapid's controlled Select keys on native hosts.
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

use glory::prelude::*;

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
    pub label: Vary<String>,
    pub value: Vary<Option<String>>,
    pub options: Vec<NativeChoiceOption>,
    pub enabled: Vary<bool>,
    pub class: String,
    pub field: Option<sapid::FieldControl>,
    pub on_change: Rc<dyn Fn(Option<String>)>,
}
impl NativeChoiceProps {
    pub fn new(
        key: impl Into<String>,
        label: impl Into<Vary<String>>,
        value: impl Into<Vary<Option<String>>>,
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
            field: None,
            on_change: Rc::new(on_change),
        }
    }
    pub fn enabled(mut self, enabled: impl Into<Vary<bool>>) -> Self {
        self.enabled = enabled.into();
        self
    }
    pub fn class(mut self, class: impl Into<String>) -> Self {
        self.class = class.into();
        self
    }
    pub fn field(mut self, field: sapid::FieldControl) -> Self {
        self.field = Some(field);
        self
    }
}
pub fn native_choice(scope: &Scope, props: NativeChoiceProps) -> View {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let serial = NEXT.fetch_add(1, Ordering::Relaxed);
    let options = Rc::new(props.options);
    let values = options.clone();
    let selected = scope.bond(move || {
        let value = props.value.get();
        values
            .iter()
            .position(|option| Some(&option.value) == value.as_ref())
            .map(|index| format!("opt-{index}"))
    });
    let proposals = options.clone();
    let mut control = sapid::select(format!("native-choice-{serial:x}"))
        .unstyled()
        .class(format!(
            "btn secondary native-choice-trigger {} {}",
            props.class, props.key
        ))
        .name(props.label)
        .value(selected)
        .enabled(props.enabled)
        .options(options.iter().enumerate().map(|(index, option)| {
            sapid::select_option(format!("opt-{index}"), option.label.clone())
                .value(option.value.clone())
                .disabled(!option.enabled)
        }))
        .on_value_change(move |key| {
            let next = key
                .and_then(|key| {
                    key.strip_prefix("opt-")
                        .and_then(|index| index.parse::<usize>().ok())
                })
                .and_then(|index| proposals.get(index))
                .map(|option| option.value.clone());
            (props.on_change)(next);
        });
    if let Some(field) = props.field {
        control = control.field(field);
    }
    Box::new(control)
}
#[cfg(test)]
mod tests;
