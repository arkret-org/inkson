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

use dioxus::prelude::*;

/// Values for `discoverability` (discovery-directory §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Discoverability {
    Public,
    Listed,
    Restricted,
    Unlisted,
    InviteOnly,
    Secret,
}

impl Discoverability {
    pub fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Listed => "listed",
            Self::Restricted => "restricted",
            Self::Unlisted => "unlisted",
            Self::InviteOnly => "invite_only",
            Self::Secret => "secret",
        }
    }

    pub fn class_name(self) -> &'static str {
        match self {
            Self::Public => "badge green",
            Self::Listed => "badge blue",
            Self::Restricted => "badge amber",
            Self::Unlisted | Self::InviteOnly => "badge",
            Self::Secret => "badge red",
        }
    }

    pub fn from_str_loose(value: &str) -> Self {
        match value {
            "public" => Self::Public,
            "listed" => Self::Listed,
            "restricted" => Self::Restricted,
            "unlisted" => Self::Unlisted,
            "secret" => Self::Secret,
            _ => Self::InviteOnly,
        }
    }
}

/// Values for `join_rule` (authz/event-auth-state-resolution §6 and discovery §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinRule {
    Public,
    Knock,
    KnockRestricted,
    Invite,
    Restricted,
    Closed,
}

impl JoinRule {
    pub fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Knock => "knock",
            Self::KnockRestricted => "knock_restricted",
            Self::Invite => "invite",
            Self::Restricted => "restricted",
            Self::Closed => "closed",
        }
    }

    pub fn class_name(self) -> &'static str {
        match self {
            Self::Public => "badge green",
            Self::Knock | Self::KnockRestricted => "badge blue",
            Self::Restricted => "badge amber",
            Self::Invite => "badge",
            Self::Closed => "badge red",
        }
    }

    pub fn from_str_loose(value: &str) -> Self {
        match value {
            "public" | "open" => Self::Public,
            "knock" => Self::Knock,
            "request" => Self::Knock,
            "knock_restricted" => Self::KnockRestricted,
            "restricted" => Self::Restricted,
            "closed" => Self::Closed,
            _ => Self::Invite,
        }
    }
}

/// Values for `history_visibility` (authz/event-auth-state-resolution §6 is the normative source).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryVisibility {
    WorldReadable,
    Shared,
    Invited,
    Joined,
    Restricted,
}

impl HistoryVisibility {
    pub fn label(self) -> &'static str {
        match self {
            Self::WorldReadable => "world_readable",
            Self::Shared => "shared",
            Self::Invited => "invited",
            Self::Joined => "joined",
            Self::Restricted => "restricted",
        }
    }

    pub fn class_name(self) -> &'static str {
        match self {
            Self::WorldReadable => "badge green",
            Self::Shared => "badge blue",
            Self::Invited => "badge amber",
            Self::Joined => "badge",
            Self::Restricted => "badge red",
        }
    }

    pub fn from_str_loose(value: &str) -> Self {
        match value {
            "world_readable" => Self::WorldReadable,
            "shared" | "shared_history" => Self::Shared,
            "invited" => Self::Invited,
            "restricted" => Self::Restricted,
            _ => Self::Joined,
        }
    }
}

/// Single-dimension pill. `prefix` is required so readers can tell which of
/// the three dimensions this pill represents.
#[component]
pub fn PermissionPill(prefix: String, value: String, kind: String) -> Element {
    let class = match kind.as_str() {
        "discoverability" => Discoverability::from_str_loose(&value).class_name(),
        "join_rule" => JoinRule::from_str_loose(&value).class_name(),
        "history" | "history_visibility" => HistoryVisibility::from_str_loose(&value).class_name(),
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
        assert_eq!(JoinRule::from_str_loose("garbage"), JoinRule::Invite);
        assert_eq!(JoinRule::from_str_loose("knock"), JoinRule::Knock);
        assert_eq!(JoinRule::from_str_loose("open"), JoinRule::Public);
    }

    #[test]
    fn history_visibility_default_is_joined() {
        assert_eq!(
            HistoryVisibility::from_str_loose("garbage"),
            HistoryVisibility::Joined
        );
        assert_eq!(
            HistoryVisibility::from_str_loose("world_readable"),
            HistoryVisibility::WorldReadable
        );
        assert_eq!(
            HistoryVisibility::from_str_loose("shared"),
            HistoryVisibility::Shared
        );
    }
}
