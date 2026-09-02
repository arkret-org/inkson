//! CircleScopePicker — dropdown surface for the new-Strand / new-Space /
//! composer-banner family that lets the user pick between Realm scope
//! (default) and any Circle the active account belongs to.
//!
//! Spec: `docs/design/unified-feedback-system.md`.

use dioxus::prelude::*;

use crate::circle::{CircleScope, CircleSummary};
use crate::ui::select::{Select, SelectOption};

/// Dropdown picker. Renders a `<select>` with one option per Circle the
/// caller passed in plus a default everyone-in-realm option (label
/// resolved via `circle.scope.realm_everyone`). Emits the
/// chosen [`CircleScope`] via `onchange`.
///
/// `circles` should already be filtered to the strict subset the active
/// account belongs to (the parent page is responsible for that — the
/// component does no fetching of its own).
#[component]
pub fn CircleScopePicker(
    /// Currently selected scope. Defaults to `CircleScope::Realm` when
    /// the picker first mounts.
    selected: CircleScope,
    /// Eligible Circles. May be empty — the picker renders the
    /// Realm-only option in that case.
    circles: Vec<CircleSummary>,
    /// Test id stamped on the `<select>` so e2e specs can drive it.
    test_id: Option<String>,
    /// Emits the new scope on user change.
    onchange: EventHandler<CircleScope>,
) -> Element {
    let tid = test_id.unwrap_or_else(|| "circle-scope-picker".to_owned());
    // Localized at the render site: `CircleScope::label()` returns
    // &'static str and cannot call tr(), so the picker's descriptive
    // strings resolve here instead.
    let everyone_label = crate::i18n::tr("circle.scope.realm_everyone");
    let scope_help = crate::i18n::tr("circle.scope.help");
    let current_id = match &selected {
        CircleScope::Realm => String::from("__realm__"),
        CircleScope::Circle { circle_id, .. } => circle_id.clone(),
    };
    let current_id_selected = use_memo({
        let current_id = current_id.clone();
        move || Some(current_id.clone())
    });
    let circles_for_handler = circles.clone();

    rsx! {
        label {
            class: "field circle-scope-picker",
            "data-testid": "{tid}-label",
            span { class: "field-label", "Scope" }
            Select::<String> {
                class: "select",
                "data-testid": "{tid}",
                "aria-label": "Circle scope selector",
                value: Some(current_id_selected.into()),
                on_value_change: move |v: Option<String>| {
                    if let Some(value) = v {
                        if value == "__realm__" {
                            onchange.call(CircleScope::Realm);
                            return;
                        }
                        if let Some(summary) =
                            circles_for_handler.iter().find(|c| c.id == value).cloned()
                        {
                            onchange.call(summary.into_scope());
                        }
                    }
                },
                SelectOption::<String> {
                    index: 0usize,
                    value: "__realm__".to_string(),
                    text_value: "{everyone_label}",
                    "{everyone_label}"
                }
                for (i, circle) in circles.iter().enumerate() {
                    SelectOption::<String> {
                        key: "{circle.id}",
                        index: i + 1,
                        value: circle.id.to_string(),
                        text_value: "{circle.title} ({circle.member_count} members)",
                        "{circle.title} ({circle.member_count} members)"
                    }
                }
            }
            p { class: "field-help muted",
                "{scope_help}"
            }
        }
    }
}

/// Coloured banner displayed at the top of a Strand / composer when the
/// active scope is a Circle. Renders nothing for `CircleScope::Realm`
/// (the default scope has no banner — that keeps the UI surface quiet
/// during normal use).
#[component]
pub fn CircleComposerBanner(scope: CircleScope) -> Element {
    match scope {
        CircleScope::Realm => rsx! {},
        CircleScope::Circle {
            circle_id,
            title,
            member_count,
        } => rsx! {
            div {
                class: "banner circle-composer-banner",
                "data-testid": "circle-composer-banner",
                "data-circle-id": "{circle_id}",
                span { class: "banner-icon", "🛡" }
                div { class: "banner-body",
                    strong { "Circle scope · {title}" }
                    span { class: "muted",
                        if member_count == 0 {
                            "This message is visible only to Circle members."
                        } else {
                            "This message is visible only to {member_count} Circle member(s)."
                        }
                    }
                }
            }
        },
    }
}

/// Confidential-discussion-of cross-link panel. Rendered above a Strand
/// when its `Relation::ConfidentialDiscussionOf` points at a parent
/// Strand.
///
/// P3B.2.8 — the link routes through the optional
/// `target_realm_id`. When the relation projection carries the parent
/// Strand's home Realm id the link is built as a Board task deep link; when it
/// doesn't, the seal falls back to a `#strand:<id>` hash.
#[component]
pub fn ConfidentialDiscussionOfBanner(
    target_strand_id: String,
    target_title: String,
    /// Parent Strand's home Realm id. When supplied the link routes to the
    /// Board task URL with the strand id as the task id.
    #[props(default)]
    target_realm_id: Option<String>,
) -> Element {
    let href = match target_realm_id.as_deref() {
        Some(realm_id) if !realm_id.trim().is_empty() => {
            format!("/kanban/{realm_id}/task/{target_strand_id}")
        }
        _ => format!("#strand:{target_strand_id}"),
    };
    rsx! {
        div {
            class: "banner confidential-discussion-of-banner",
            "data-testid": "confidential-discussion-of-banner",
            "data-target-strand-id": "{target_strand_id}",
            span { class: "banner-icon", "💬" }
            div { class: "banner-body",
                strong {
                    "Confidential discussion of "
                    a {
                        href: "{href}",
                        "data-testid": "confidential-discussion-of-link",
                        "data-target-realm-id": "{target_realm_id.clone().unwrap_or_default()}",
                        "{target_title}"
                    }
                }
                span { class: "muted",
                    "This Strand is the confidential side of another Strand. Members of this Circle can see both sides."
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str) -> CircleSummary {
        CircleSummary {
            id: id.to_owned(),
            realm_id: "ak:realm:A28oJpDpEI80mVokdt5Yo0vuv0Z1SXEPt1X593Rirmn8".to_owned(),
            title: format!("Title {id}"),
            short_name: "T".to_owned(),
            color_token: "indigo".to_owned(),
            symbol: "shield".to_owned(),
            member_count: 3,
            state: arkret_sdk::CircleState::Active,
            viewer_is_member: true,
        }
    }

    #[test]
    fn picker_default_selection_is_realm() {
        // Smoke test: constructing the prop struct with defaults yields
        // a Realm-scope selection. The component itself is a Dioxus
        // surface; full render coverage lives in the e2e harness.
        let selected = CircleScope::default();
        assert_eq!(selected.label(), "Realm");
    }

    #[test]
    fn picker_circle_list_round_trips() {
        let one = sample("ak:circle:one");
        let two = sample("ak:circle:two");
        assert_eq!(one.into_scope().circle_id(), Some("ak:circle:one"));
        assert_eq!(two.into_scope().circle_id(), Some("ak:circle:two"));
    }
}
