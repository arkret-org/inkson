//! Reusable empty / filtered / error placeholder.
//!
//! Several list views render the same shape when there is nothing to
//! show:
//!
//!     div.event
//!         div.event-head — title + status badge ("empty", "filtered",
//!                          "error")
//!         div.muted      — explanation message
//!
//! Before this module each view hand-rolled the markup with slightly
//! different wording and div nesting. This component is the single
//! source of truth so the empty / filtered / error states stay visually
//! consistent across `directory.rs`, `notifications.rs`, `audit.rs`,
//! `kanban.rs`, etc.
//!
//! It is intentionally **not** a generic data-list — each list view's
//! row markup differs too much to share. What does share is the
//! placeholder shell, which is what this component covers.

use dioxus::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmptyStateKind {
    /// "No data was loaded" — distinguishable from `Filtered` so QA
    /// and users can tell a server fetch returned nothing from a
    /// client-side filter hiding everything.
    Empty,
    /// "Server returned data but the user's filters/mutes hid it all."
    Filtered,
    /// "Tried to load but got an error" — caller surfaces the actual
    /// reason in `message`.
    Error,
    /// "Authenticated session missing." Used when a session is
    /// required to populate the list but the user has not signed in
    /// yet.
    SignedOut,
}

impl EmptyStateKind {
    /// Short label rendered in the event-head right span, matching the
    /// "subtitle" slot the existing card layout already uses.
    pub fn badge(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Filtered => "filtered",
            Self::Error => "error",
            Self::SignedOut => "signed out",
        }
    }

    /// CSS modifier so themes can colour-code the badge. Reuses the
    /// existing badge palette (green / amber / red / muted) so no new
    /// stylesheet rules are needed.
    pub fn badge_class(self) -> &'static str {
        match self {
            Self::Empty => "badge",
            Self::Filtered => "badge amber",
            Self::Error => "badge red",
            Self::SignedOut => "badge",
        }
    }
}

#[component]
pub fn EmptyState(
    /// Title for the event-head left span (e.g. "Notifications",
    /// "Directory"). Usually mirrors the view's section name so the
    /// placeholder reads like a deliberate state rather than a glitch.
    title: String,
    kind: EmptyStateKind,
    /// Optional explanation shown in the muted body. `None` keeps the
    /// muted block out of the DOM entirely so callers can use the
    /// component as a thin "section is empty" hint with no body copy.
    message: Option<String>,
    /// Override the default badge text from `kind.badge()`. Useful when
    /// the caller wants a context-specific subtitle ("no policy",
    /// "awaiting sync") while keeping the colour mapping from `kind`.
    badge_override: Option<String>,
    /// Data-testid for the outer wrapper. Defaults to
    /// `"empty-state"` so e2e tests can target a stable selector.
    test_id: Option<String>,
) -> Element {
    let testid = test_id.unwrap_or_else(|| "empty-state".to_owned());
    let badge_text = badge_override.unwrap_or_else(|| kind.badge().to_owned());
    let badge_class = kind.badge_class();
    rsx! {
        div { class: "event", "data-testid": "{testid}",
            div { class: "event-head",
                span { "{title}" }
                span { class: "{badge_class}", "{badge_text}" }
            }
            if let Some(text) = message {
                div { class: "muted", "{text}" }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn badge_kinds_have_distinct_labels() {
        let labels = [
            EmptyStateKind::Empty.badge(),
            EmptyStateKind::Filtered.badge(),
            EmptyStateKind::Error.badge(),
            EmptyStateKind::SignedOut.badge(),
        ];
        let unique: std::collections::BTreeSet<_> = labels.iter().copied().collect();
        assert_eq!(unique.len(), labels.len());
    }

    #[test]
    fn error_kind_uses_red_badge() {
        assert_eq!(EmptyStateKind::Error.badge_class(), "badge red");
        // The other kinds must not steal the red class — that's
        // reserved for actual failures so theme contrast stays useful.
        for other in [
            EmptyStateKind::Empty,
            EmptyStateKind::Filtered,
            EmptyStateKind::SignedOut,
        ] {
            assert_ne!(other.badge_class(), "badge red");
        }
    }
}
