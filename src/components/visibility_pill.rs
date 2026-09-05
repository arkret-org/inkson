//! Visibility pills — three independent dimensions per `discovery/discovery-directory.md`.
//! These are Realm visibility/policy dimensions (NOT authorization /
//! capability "permissions"); the spec keeps them strictly independent:
//!
//! - **Discoverability** decides whether a Space / Org / Actor / Applet can be found.
//! - **Join Rule** decides how a subject can join.
//! - **History Access** decides whether a current member starts at its join or receives all
//!   retained scope history.
//!
//! The spec is explicit that none of the three implies the others:
//! `discoverability=public` does not imply `history_access=all_history_for_current_members`
//! and does not imply `join_rule=public`. Any UI that surfaces a resource's
//! access state must keep the three dimensions visible independently.
//!
//! This component is shared between `views/directory.rs`, `views/realm_admin.rs`,
//! `views/kanban.rs`, and the rest of the UI.

pub use arkret_sdk::{Discoverability, HistoryAccess, JoinRule};
use dioxus::prelude::*;

pub trait DiscoverabilityUi {
    fn label(&self) -> &'static str;
    fn class_name(&self) -> &'static str;
}

impl DiscoverabilityUi for Discoverability {
    fn label(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Listed => "listed",
            Self::Restricted => "restricted",
            Self::Unlisted => "unlisted",
            Self::InviteOnly => "invite_only",
            Self::Secret => "secret",
        }
    }

    fn class_name(&self) -> &'static str {
        match self {
            Self::Public => "badge green",
            Self::Listed => "badge blue",
            Self::Restricted => "badge amber",
            Self::Unlisted | Self::InviteOnly => "badge",
            Self::Secret => "badge red",
        }
    }
}

fn discoverability_from_str_loose(value: &str) -> Discoverability {
    match value {
        "public" => Discoverability::Public,
        "listed" => Discoverability::Listed,
        "restricted" => Discoverability::Restricted,
        "unlisted" => Discoverability::Unlisted,
        "secret" => Discoverability::Secret,
        _ => Discoverability::InviteOnly,
    }
}

pub trait JoinRuleUi {
    fn label(&self) -> &'static str;
    fn class_name(&self) -> &'static str;
}

impl JoinRuleUi for JoinRule {
    fn label(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Knock => "knock",
            Self::KnockRestricted => "knock_restricted",
            Self::Invite => "invite",
            Self::Restricted => "restricted",
            Self::Closed => "closed",
        }
    }

    fn class_name(&self) -> &'static str {
        match self {
            Self::Public => "badge green",
            Self::Knock | Self::KnockRestricted => "badge blue",
            Self::Restricted => "badge amber",
            Self::Invite => "badge",
            Self::Closed => "badge red",
        }
    }
}

fn join_rule_from_str_loose(value: &str) -> JoinRule {
    match value {
        "public" => JoinRule::Public,
        "knock" => JoinRule::Knock,
        "knock_restricted" => JoinRule::KnockRestricted,
        "restricted" => JoinRule::Restricted,
        "closed" => JoinRule::Closed,
        _ => JoinRule::Invite,
    }
}

pub trait HistoryAccessUi {
    fn label(&self) -> &'static str;
    fn class_name(&self) -> &'static str;
}

impl HistoryAccessUi for HistoryAccess {
    fn label(&self) -> &'static str {
        match self {
            Self::AllHistoryForCurrentMembers => "all_history_for_current_members",
            Self::SinceJoin => "since_join",
        }
    }

    fn class_name(&self) -> &'static str {
        match self {
            Self::AllHistoryForCurrentMembers => "badge blue",
            Self::SinceJoin => "badge",
        }
    }
}

fn history_access_from_str_loose(value: &str) -> HistoryAccess {
    match value {
        "all_history_for_current_members" => HistoryAccess::AllHistoryForCurrentMembers,
        _ => HistoryAccess::SinceJoin,
    }
}

/// Single-dimension pill. `prefix` is required so readers can tell which of
/// the three dimensions this pill represents.
#[component]
pub fn VisibilityPill(prefix: String, value: String, kind: String) -> Element {
    let class = match kind.as_str() {
        "discoverability" => discoverability_from_str_loose(&value).class_name(),
        "join_rule" => join_rule_from_str_loose(&value).class_name(),
        "history" | "history_access" => history_access_from_str_loose(&value).class_name(),
        _ => "badge",
    };
    let testid = format!("permission-pill-{kind}");
    rsx! {
        span {
            class: "{class}",
            "data-testid": "{testid}",
            "title": crate::i18n::tr("visibility.pill_title"),
            "{prefix}: {value}"
        }
    }
}

/// Compact component that surfaces all three dimensions at once. Unset
/// dimensions render as `—`.
#[component]
pub fn VisibilityPillRow(
    discoverability: Option<String>,
    join_rule: Option<String>,
    history_access: Option<String>,
) -> Element {
    let disc = discoverability.unwrap_or_else(|| "—".to_owned());
    let join = join_rule.unwrap_or_else(|| "—".to_owned());
    let hist = history_access.unwrap_or_else(|| "—".to_owned());
    rsx! {
        div { class: "actions", "data-testid": "permission-pill-row",
            VisibilityPill { prefix: "disc".to_owned(), value: disc, kind: "discoverability".to_owned() }
            VisibilityPill { prefix: "join".to_owned(), value: join, kind: "join_rule".to_owned() }
            VisibilityPill { prefix: "hist".to_owned(), value: hist, kind: "history".to_owned() }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discoverability_class_names_distinguish_levels() {
        assert_ne!(
            Discoverability::Public.class_name(),
            Discoverability::Secret.class_name()
        );
        assert_eq!(Discoverability::Listed.label(), "listed");
    }

    #[test]
    fn join_rule_loose_parse_falls_back_to_invite() {
        assert_eq!(join_rule_from_str_loose("garbage"), JoinRule::Invite);
        assert_eq!(join_rule_from_str_loose("knock"), JoinRule::Knock);
        assert_eq!(join_rule_from_str_loose("open"), JoinRule::Invite);
    }

    #[test]
    fn history_access_default_is_since_join() {
        assert_eq!(
            history_access_from_str_loose("garbage"),
            HistoryAccess::SinceJoin
        );
        assert_eq!(
            history_access_from_str_loose("all_history_for_current_members"),
            HistoryAccess::AllHistoryForCurrentMembers
        );
    }
}
