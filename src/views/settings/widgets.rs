//! Small self-contained settings components factored out of the panel: the
//! notification-kind toggle and the per-realm watch-level override row.

use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;

use super::account_data::{push_notification_rules_account_data, watch_level_label};
use crate::local_state::LocalStateStore;
use crate::notification_rules::WatchLevel;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::select::{Select, SelectOption};
use crate::views::helpers::short_protocol_id;

pub(super) fn render_notification_kind_toggle(
    kind: &'static str,
    label: &'static str,
    mut state_store: Signal<LocalStateStore>,
    mut status: Signal<String>,
) -> Element {
    let enabled = state_store.read().notification_kind_enabled(kind);
    rsx! {
        div { class: "metric",
            strong { "{label}" }
            label {
                Checkbox {
                    checked: if enabled { CheckboxState::Checked } else { CheckboxState::Unchecked },
                    on_checked_change: move |state: CheckboxState| {
                        let enabled = bool::from(state);
                        state_store.write().set_notification_kind_enabled(kind, enabled);
                        status.set(format!(
                            "{} {}.",
                            label,
                            if enabled { "enabled" } else { "muted" }
                        ));
                    },
                }
                if enabled { " Enabled" } else { " Muted" }
            }
        }
    }
}

/// One row of the per-realm override list: the realm label, a 4-level watch
/// picker bound to local state, and a remove button. Its own component so the
/// controlled `value` memo can read `state_store` reactively (a free function
/// could not hold a hook).
#[component]
pub(super) fn RealmOverrideRow(
    realm_id: String,
    label: String,
    mut state_store: Signal<LocalStateStore>,
    base_url: Signal<String>,
    token: Signal<String>,
    mut status: Signal<String>,
) -> Element {
    let level = state_store.read().realm_watch_level(&realm_id);
    let selected = use_memo({
        let realm_id = realm_id.clone();
        move || {
            Some(
                state_store
                    .read()
                    .realm_watch_level(&realm_id)
                    .as_wire()
                    .to_owned(),
            )
        }
    });
    // Muted rows expose a stable test id used by notification e2e flows
    // (mute from drawer -> confirm here).
    let row_testid = if level == WatchLevel::Muted {
        "settings-muted-realm-row"
    } else {
        "settings-realm-override-row"
    };
    rsx! {
        div { class: "actions", "data-testid": "{row_testid}", "data-realm-id": "{realm_id}",
            span { class: "mono", title: "{realm_id}", "{label}" }
            Select::<String> {
                class: "select",
                "data-testid": "realm-watch-level-select",
                value: Some(selected.into()),
                on_value_change: {
                    let realm_id = realm_id.clone();
                    move |value: Option<String>| {
                        let Some(value) = value else { return };
                        let next = WatchLevel::from_wire(&value).unwrap_or_default();
                        state_store.write().set_realm_watch_level(realm_id.clone(), next);
                        push_notification_rules_account_data(
                            base_url(),
                            token(),
                            state_store.read().realm_watch_levels(),
                        );
                        status.set(format!(
                            "Set {} to {}.",
                            short_protocol_id(&realm_id),
                            watch_level_label(next)
                        ));
                    }
                },
                SelectOption::<String> { index: 0usize, value: "all".to_string(), text_value: "All messages", "All messages" }
                SelectOption::<String> { index: 1usize, value: "participating".to_string(), text_value: "Participating", "Participating" }
                SelectOption::<String> { index: 2usize, value: "mentions_only".to_string(), text_value: "Mentions only", "Mentions only" }
                SelectOption::<String> { index: 3usize, value: "muted".to_string(), text_value: "Muted", "Muted" }
            }
            Button {
                variant: ButtonVariant::Secondary,
                "data-testid": "settings-realm-override-remove",
                onclick: {
                    let realm_id = realm_id.clone();
                    move |_| {
                        state_store.write().set_realm_watch_level(realm_id.clone(), WatchLevel::default());
                        push_notification_rules_account_data(
                            base_url(),
                            token(),
                            state_store.read().realm_watch_levels(),
                        );
                        status.set(format!(
                            "Removed override for {}.",
                            short_protocol_id(&realm_id)
                        ));
                    }
                },
                "Remove"
            }
        }
    }
}
