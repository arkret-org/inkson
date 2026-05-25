//! CircleScopePicker — dropdown surface for the new-Flow / new-Space /
//! composer-banner family that lets the user pick between Realm scope
//! (default) and any Circle the active account belongs to.
//!
//! Spec: CXP-0007 / `_yougen_todos.md` §P3B.2.2-§P3B.2.3.

use dioxus::prelude::*;

use crate::circle::{CircleScope, CircleSummary};

/// Dropdown picker. Renders a `<select>` with one option per Circle the
/// caller passed in plus a default "Realm (everyone)" option. Emits the
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
    let current_id = match &selected {
        CircleScope::Realm => String::from("__realm__"),
        CircleScope::Circle { circle_id, .. } => circle_id.clone(),
    };
    let circles_for_handler = circles.clone();

    rsx! {
        label {
            class: "field circle-scope-picker",
            "data-testid": "{tid}-label",
            span { class: "field-label", "Scope" }
            select {
                class: "select",
                "data-testid": "{tid}",
                value: "{current_id}",
                onchange: move |evt| {
                    let value = evt.value();
                    if value == "__realm__" {
                        onchange.call(CircleScope::Realm);
                        return;
                    }
                    if let Some(summary) =
                        circles_for_handler.iter().find(|c| c.id == value).cloned()
                    {
                        onchange.call(summary.into_scope());
                    }
                },
                option { value: "__realm__", "Realm (everyone)" }
                for circle in circles.iter() {
                    option {
                        key: "{circle.id}",
                        value: "{circle.id}",
                        "{circle.title} ({circle.member_count} members)"
                    }
                }
            }
            p { class: "field-help muted",
                "Choose a Circle to restrict visibility to a strict subset of Realm members."
            }
        }
    }
}

/// Coloured banner displayed at the top of a Flow / composer when the
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

/// Confidential-discussion-of cross-link panel. Rendered above a Flow
/// when its `Relation::ConfidentialDiscussionOf` points at a parent
/// Flow.
///
/// `TODO(circle-rollout-P3B.2.8):` wire the click handler into the
/// dioxus router (`Route::TimelineSpace { space_id }`) once the parent
/// Flow's home Space id is available on the relation projection.
#[component]
pub fn ConfidentialDiscussionOfBanner(target_flow_id: String, target_title: String) -> Element {
    rsx! {
        div {
            class: "banner confidential-discussion-of-banner",
            "data-testid": "confidential-discussion-of-banner",
            "data-target-flow-id": "{target_flow_id}",
            span { class: "banner-icon", "💬" }
            div { class: "banner-body",
                strong { "Confidential discussion of " a { href: "#", "{target_title}" } }
                span { class: "muted",
                    "This Flow is the confidential side of another Flow. Members of this Circle can see both sides."
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
            realm_id: "cx:realm:home".to_owned(),
            title: format!("Title {id}"),
            short_name: "T".to_owned(),
            color_token: "indigo".to_owned(),
            symbol: "shield".to_owned(),
            member_count: 3,
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
        let one = sample("cx:circle:one");
        let two = sample("cx:circle:two");
        assert_eq!(one.into_scope().circle_id(), Some("cx:circle:one"));
        assert_eq!(two.into_scope().circle_id(), Some("cx:circle:two"));
    }
}
