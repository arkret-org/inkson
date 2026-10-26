//! Stable Realm selection for holder-private preference editors.

use std::rc::Rc;

use glory::{Cage, Scope};

use crate::presentation::{InksonContext, View};
use crate::state::LocalStateStore;

pub(super) fn preference_realm_options(store: &LocalStateStore) -> Vec<(String, String)> {
    let joined = store.sync_joined_realm_ids();
    super::account_data::known_realm_options(store)
        .into_iter()
        .filter(|(id, _)| joined.contains(id) && id.parse::<arkret_sdk::RealmId>().is_ok())
        .map(|(id, label)| {
            let label = format!("{label} · {id}");
            (id, label)
        })
        .collect()
}

pub(super) fn selected_realm_id(
    options: &[(String, String)],
    selected: &str,
) -> Option<arkret_sdk::RealmId> {
    options
        .iter()
        .any(|(id, _)| id == selected)
        .then(|| selected.parse().ok())
        .flatten()
}

pub(super) fn picker(
    scope: &Scope,
    context: Rc<InksonContext>,
    selected: Cage<String>,
    key: &str,
) -> View {
    let read = context.clone();
    let options = scope.bond(move || {
        let _ = read.state_revision.get();
        read.state_store.read(preference_realm_options)
    });
    realm_preference_picker(scope, context, options.into(), selected, key)
}
/// The same controlled picker is used by all preference editors and browser conformance tests.
pub fn realm_preference_picker(
    scope: &Scope,
    context: Rc<InksonContext>,
    options: glory::Lotus<Vec<(String, String)>>,
    selected: Cage<String>,
    key: &str,
) -> View {
    let key = key.to_owned();
    let label = context.translated(scope, "friendly.realm");
    let control = crate::presentation::widgets::reactive(options, move |scope, mut options| {
        let has_options = !options.is_empty();
        let placeholder = context.tr(if has_options {
            "settings.notifications.select_realm"
        } else {
            "settings.notifications.no_realms"
        });
        options.insert(0, (String::new(), placeholder));
        #[cfg(not(target_arch = "wasm32"))]
        {
            use crate::presentation::native_choice::{
                NativeChoiceOption, NativeChoiceProps, native_choice,
            };
            let valid = options.clone();
            let value = scope.bond(move || Some(selected.get()));
            native_choice(
                scope,
                NativeChoiceProps::new(
                    format!("{key}-options"),
                    context.translated(scope, "friendly.realm"),
                    value,
                    options
                        .into_iter()
                        .map(|(value, label)| NativeChoiceOption::new(value, label))
                        .collect(),
                    move |next| {
                        if let Some(next) = next
                            && (next.is_empty() || selected_realm_id(&valid, &next).is_some())
                        {
                            selected.revise(|value| *value = next);
                        }
                    },
                )
                .class(format!("select {key}"))
                .enabled(has_options)
                .close_label(context.translated(scope, "common.close")),
            )
        }
        #[cfg(target_arch = "wasm32")]
        {
            let choices = options.clone();
            let actual = scope.bond(move || super::widgets::select_key(&choices, &selected.get()));
            let valid = options.clone();
            let option_key = format!("{key}-options");
            Box::new(
                sapid::select(option_key)
                    .unstyled()
                    .class(format!("select {key}"))
                    .name(context.translated(scope, "friendly.realm"))
                    .value(actual)
                    .enabled(has_options)
                    .options(options.into_iter().enumerate().map(|(index, (_, label))| {
                        sapid::select_option(format!("opt-{index}"), label)
                    }))
                    .on_value_change(move |next| {
                        if let Some(next) =
                            next.and_then(|key| super::widgets::select_value(&valid, &key))
                            && (next.is_empty() || selected_realm_id(&valid, &next).is_some())
                        {
                            selected.revise(|value| *value = next);
                        }
                    }),
            )
        }
    });
    crate::presentation::widgets::stack(
        "field realm-preference-picker",
        vec![crate::presentation::widgets::plain(label), control],
    )
}
