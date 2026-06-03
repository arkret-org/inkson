//! Permission pills — three independent dimensions per `discovery/discovery-directory.md`:
//!
//! - **Discoverability** decides whether a Space / Org / Actor / Applet can be found.
//! - **Join Rule** decides how a subject can join.
//! - **History Visibility** decides what history a joined subject can read.
//!
//! The spec is explicit that none of the three implies the others:
//! `discoverability=public` does not imply `history_visibility=world_readable`
//! and does not imply `join_rule=public`. Any UI that surfaces a resource's
//! access state must keep the three dimensions visible independently.
//!
//! This component is shared between `views/directory.rs`, `views/space_admin.rs`,
//! `views/kanban.rs`, and the rest of the UI.

pub use cokret_sdk::{Discoverability, HistoryVisibility, JoinRule};
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
        "public" | "open" => JoinRule::Public,
        "knock" => JoinRule::Knock,
        "request" => JoinRule::Knock,
        "knock_restricted" => JoinRule::KnockRestricted,
        "restricted" => JoinRule::Restricted,
        "closed" => JoinRule::Closed,
        _ => JoinRule::Invite,
    }
}

pub trait HistoryVisibilityUi {
    fn label(&self) -> &'static str;
    fn class_name(&self) -> &'static str;
}

impl HistoryVisibilityUi for HistoryVisibility {
    fn label(&self) -> &'static str {
        match self {
            Self::WorldReadable => "world_readable",
            Self::Shared => "shared",
            Self::Invited => "invited",
            Self::Joined => "joined",
            Self::Restricted => "restricted",
        }
    }

    fn class_name(&self) -> &'static str {
        match self {
            Self::WorldReadable => "badge green",
            Self::Shared => "badge blue",
            Self::Invited => "badge amber",
            Self::Joined => "badge",
            Self::Restricted => "badge red",
        }
    }
}

fn history_visibility_from_str_loose(value: &str) -> HistoryVisibility {
    match value {
        "world_readable" => HistoryVisibility::WorldReadable,
        "shared" | "shared_history" => HistoryVisibility::Shared,
        "invited" => HistoryVisibility::Invited,
        "restricted" => HistoryVisibility::Restricted,
        _ => HistoryVisibility::Joined,
    }
}

/// Single-dimension pill. `prefix` is required so readers can tell which of
/// the three dimensions this pill represents.
#[component]
pub fn PermissionPill(prefix: String, value: String, kind: String) -> Element {
    let class = match kind.as_str() {
        "discoverability" => discoverability_from_str_loose(&value).class_name(),
        "join_rule" => join_rule_from_str_loose(&value).class_name(),
        "history" | "history_visibility" => history_visibility_from_str_loose(&value).class_name(),
        _ => "badge",
    };
    let testid = format!("permission-pill-{kind}");
    rsx! {
        span {
            class: "{class}",
            "data-testid": "{testid}",
            "title": "discovery-directory.md / event-auth-state-resolution §6",
            "{prefix}: {value}"
        }
    }
}

/// Compact component that surfaces all three dimensions at once. Unset
/// dimensions render as `—`.
#[component]
pub fn PermissionPillRow(
    discoverability: Option<String>,
    join_rule: Option<String>,
    history_visibility: Option<String>,
) -> Element {
    let disc = discoverability.unwrap_or_else(|| "—".to_owned());
    let join = join_rule.unwrap_or_else(|| "—".to_owned());
    let hist = history_visibility.unwrap_or_else(|| "—".to_owned());
    rsx! {
        div { class: "actions", "data-testid": "permission-pill-row",
            PermissionPill { prefix: "disc".to_owned(), value: disc, kind: "discoverability".to_owned() }
            PermissionPill { prefix: "join".to_owned(), value: join, kind: "join_rule".to_owned() }
            PermissionPill { prefix: "hist".to_owned(), value: hist, kind: "history".to_owned() }
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
        assert_eq!(join_rule_from_str_loose("open"), JoinRule::Public);
    }

    #[test]
    fn history_visibility_default_is_joined() {
        assert_eq!(
            history_visibility_from_str_loose("garbage"),
            HistoryVisibility::Joined
        );
        assert_eq!(
            history_visibility_from_str_loose("world_readable"),
            HistoryVisibility::WorldReadable
        );
        assert_eq!(
            history_visibility_from_str_loose("shared"),
            HistoryVisibility::Shared
        );
    }
}
