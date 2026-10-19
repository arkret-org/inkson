//! Stable Realm selection for holder-private preference editors.

use dioxus::prelude::*;

use crate::state::LocalStateStore;
use crate::ui::select::{Select, SelectOption};

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

/// A controlled picker never substitutes another Realm when its options change.
#[component]
pub fn RealmPreferencePicker(
    options: Vec<(String, String)>,
    mut selected: Signal<String>,
    test_id: &'static str,
) -> Element {
    let memo_options = options.clone();
    let value = use_memo(use_reactive!(|(memo_options,)| {
        Some(
            selected_realm_id(&memo_options, &selected())
                .map(|id| id.to_string())
                .unwrap_or_default(),
        )
    }));
    let choices = options.clone();
    let placeholder = crate::i18n::tr(if options.is_empty() {
        "settings.notifications.no_realms"
    } else {
        "settings.notifications.select_realm"
    });
    rsx! {
        label { class: "field",
            span { class: "field-label", {crate::i18n::tr("friendly.realm")} }
            Select::<String> {
                class: "select",
                "data-testid": test_id,
                disabled: options.is_empty(),
                value: Some(value.into()),
                on_value_change: move |value: Option<String>| {
                    selected.set(value.filter(|id| selected_realm_id(&choices, id).is_some()).unwrap_or_default());
                },
                SelectOption::<String> {
                    index: 0usize,
                    value: String::new(),
                    text_value: placeholder.clone(),
                    "{placeholder}"
                }
                for (index, (id, label)) in options.iter().enumerate() {
                    SelectOption::<String> {
                        key: "{id}",
                        index: index + 1,
                        value: id.clone(),
                        "data-realm-id": id.clone(),
                        text_value: label.clone(),
                        "{label}"
                    }
                }
            }
        }
    }
}
