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
    selected: Signal<CircleScope>,
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
    let current_id_selected = use_memo(move || {
        Some(match selected() {
            CircleScope::Realm => String::from("__realm__"),
            CircleScope::Circle { circle_id, .. } => circle_id,
        })
    });
    let circles_for_handler = circles.clone();
    let selected_identity = circles
        .iter()
        .find(|circle| selected().circle_id() == Some(circle.id.as_str()))
        .cloned();

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
                        CircleIdentityBadge { color: circle.display.color_token, symbol: circle.display.symbol.clone(), short_name: circle.display.short_name.clone() }
                        " {circle.title} ({circle.member_count} members)"
                    }
                }
            }
            if let Some(circle) = selected_identity {
                CircleIdentityBadge { color: circle.display.color_token, symbol: circle.display.symbol, short_name: circle.display.short_name }
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
pub fn CircleComposerBanner(
    scope: CircleScope,
    display: Option<arkret_sdk::CircleDisplay>,
    encrypted: Option<bool>,
) -> Element {
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
                if let Some(display) = display {
                    CircleIdentityBadge { color: display.color_token, symbol: display.symbol, short_name: display.short_name }
                } else {
                    span { class: "banner-icon", "◯" }
                }
                div { class: "banner-body",
                    strong { "Circle scope · {title}" }
                    span { class: "muted", match encrypted { Some(true) => "E2EE active", Some(false) => "Restricted delivery · not E2EE", None => "Waiting for verified encryption state" } }
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

/// Render the protocol's visual identity without turning a colour into authority.
#[component]
pub fn CircleIdentityBadge(
    color: arkret_sdk::CircleColorToken,
    symbol: arkret_sdk::CircleSymbol,
    short_name: Option<String>,
) -> Element {
    use arkret_sdk::{CircleColorToken as Color, CircleGlyph as Glyph, CircleSymbol as Symbol};
    let accent = match color {
        Color::Slate => "#64748b",
        Color::Red => "#ef4444",
        Color::Orange => "#f97316",
        Color::Amber => "#f59e0b",
        Color::Yellow => "#eab308",
        Color::Lime => "#84cc16",
        Color::Green => "#22c55e",
        Color::Emerald => "#10b981",
        Color::Teal => "#14b8a6",
        Color::Cyan => "#06b6d4",
        Color::Sky => "#0ea5e9",
        Color::Blue => "#3b82f6",
        Color::Indigo => "#6366f1",
        Color::Violet => "#8b5cf6",
        Color::Fuchsia => "#d946ef",
        Color::Pink => "#ec4899",
        Color::GrayHighContrast => "var(--text)",
    };
    let symbol_label = match symbol {
        Symbol::Emoji { emoji } => emoji,
        Symbol::Glyph { glyph } => match glyph {
            Glyph::Lock => "🔒",
            Glyph::Shield => "🛡",
            Glyph::Eye => "◉",
            Glyph::EyeOff => "◌",
            Glyph::UserShield => "♙",
            Glyph::Fingerprint => "◎",
            Glyph::Key => "⚿",
            Glyph::Diamond => "◇",
            Glyph::Flame => "♨",
            Glyph::Leaf => "♧",
            Glyph::Stamp => "▣",
            Glyph::Compass => "✥",
            Glyph::Atom => "⚛",
            Glyph::Bolt => "ϟ",
            Glyph::Moon => "☾",
            Glyph::Sun => "☀",
            Glyph::Star => "☆",
            Glyph::Globe => "⊕",
            Glyph::Satellite => "✧",
            Glyph::Ring => "◯",
            Glyph::Chain => "∞",
            Glyph::Tag => "⌑",
            Glyph::Flag => "⚑",
            Glyph::Scroll => "▤",
            Glyph::Scale => "⚖",
            Glyph::Hourglass => "⌛",
            Glyph::Spark => "✦",
        }
        .to_owned(),
    };
    rsx! {
        span { class: "circle-identity-badge", style: "--circle-accent: {accent}", "data-testid": "circle-identity-badge",
            span { class: "circle-identity-symbol", "{symbol_label}" }
            if let Some(short_name) = short_name { strong { "{short_name}" } }
        }
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
            display: crate::operation::ak_ops::circle_display_from_title("T"),
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
