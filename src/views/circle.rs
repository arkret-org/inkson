//! Circle detail view (CKP-0007 / P3B.2.5).
//!
//! Shows the member list (filtered to those the active viewer can see —
//! invisible members stay hidden per CKP-0007 directory_visibility
//! rules) and the leave / archive / scope-rotate controls the viewer
//! has permission to execute.
//!
//! The view is pure projection — writes go out through
//! [`crate::api::CokretApi`] handlers that are wired up by the
//! follow-up P3B.2 commits. The Realm-detail entry point lives in
//! [`crate::views::space_admin`] (see the "create Circle" modal section
//! at the bottom).

use dioxus::prelude::*;

use crate::circle::CircleSummary;

/// Props for the Circle detail page. The parent route (e.g. a
/// `/circles/:circle_id` page added in a follow-up commit) fetches the
/// summary + member list and threads them in.
#[derive(Clone, PartialEq, Props)]
pub struct CirclePanelProps {
    pub summary: CircleSummary,
    /// Members the viewer is allowed to see. Already filtered by the
    /// CKP-0007 directory_visibility rule.
    #[props(default)]
    pub visible_members: Vec<CircleMemberRow>,
    /// `true` when the viewer has the `ck.circle.archive` capability.
    /// Hides the Archive button when `false`.
    #[props(default)]
    pub viewer_can_archive: bool,
    /// `true` when the viewer has the audited `scope_rebind` profile
    /// permission. Hides the Scope-Rotate button when `false`.
    #[props(default)]
    pub viewer_can_scope_rotate: bool,
    /// Optional override of the "Leave" handler so tests can intercept
    /// the action without standing up the full api / move_builder
    /// stack.
    #[props(default)]
    pub on_leave: Option<EventHandler<()>>,
    #[props(default)]
    pub on_archive: Option<EventHandler<()>>,
    #[props(default)]
    pub on_scope_rotate: Option<EventHandler<()>>,
}

/// One row in the member list. Stays a small struct so the parent route
/// can build it from either a synchronous projection or an async
/// `/_cokret/self/circles/:id/members` fetch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleMemberRow {
    pub actor_did: String,
    pub display_handle: String,
    pub role: String,
}

#[component]
pub fn CirclePanel(props: CirclePanelProps) -> Element {
    let CirclePanelProps {
        summary,
        visible_members,
        viewer_can_archive,
        viewer_can_scope_rotate,
        on_leave,
        on_archive,
        on_scope_rotate,
    } = props;

    let circle_id = summary.id.clone();
    let title = summary.title.clone();
    let realm_id = summary.realm_id.clone();
    let short_name = summary.short_name.clone();
    let color = summary.color_token.clone();
    let symbol = summary.symbol.clone();
    let member_count = summary.member_count;

    rsx! {
        section {
            class: "panel circle-detail",
            "data-testid": "circle-detail-panel",
            "data-circle-id": "{circle_id}",
            header { class: "panel-head",
                span { class: "circle-chip color-{color}", "{symbol} {short_name}" }
                h1 { "{title}" }
                p { class: "muted", "Parent Realm · {realm_id} · {member_count} members visible" }
            }

            div { class: "panel-actions",
                button {
                    class: "secondary",
                    "data-testid": "circle-leave-button",
                    onclick: move |_| if let Some(handler) = on_leave.as_ref() { handler.call(()); },
                    "Leave Circle"
                }
                if viewer_can_archive {
                    button {
                        class: "secondary",
                        "data-testid": "circle-archive-button",
                        onclick: move |_| if let Some(handler) = on_archive.as_ref() { handler.call(()); },
                        "Archive Circle"
                    }
                }
                if viewer_can_scope_rotate {
                    button {
                        class: "danger",
                        "data-testid": "circle-scope-rotate-button",
                        onclick: move |_| if let Some(handler) = on_scope_rotate.as_ref() { handler.call(()); },
                        "Rotate scope (audited)"
                    }
                }
            }

            section { class: "members",
                h2 { "Members" }
                if visible_members.is_empty() {
                    p { class: "muted",
                        "No visible members. Directory visibility may be set to members-only — only Circle members see the roster."
                    }
                } else {
                    ul { class: "member-list",
                        for member in visible_members.iter() {
                            li {
                                key: "{member.actor_did}",
                                class: "member-row",
                                "data-testid": "circle-member-row",
                                "data-actor-did": "{member.actor_did}",
                                span { class: "member-handle", "{member.display_handle}" }
                                span { class: "muted", "{member.role}" }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// R3 spec sync (b47ff6ec) — Circle selector grant page stub.
///
/// `resource-selector.schema.json` now accepts the `circle` selector
/// kind with `circle_id` pattern `^ck:circle:[0-9a-f]{8}-...$`. This
/// view lists the grants attached to a Circle and (in R3.1) will let
/// admins attach / detach capability grants scoped by `ck:circle:<uuid>`.
///
/// TODO(R3.1): wire to soland's `/_cokret/self/circles/{id}/grants` once that
/// endpoint lands. For now this is a documented stub that surfaces the
/// selector kind + circle_id for the QA harness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleGrantRow {
    /// Stable grant identifier.
    pub grant_id: String,
    /// Capability action wire form (e.g. `ck.message.send`,
    /// `ck.call.join`, `ck.call.record`).
    pub action: String,
    /// Capability scope expressed as a resource selector. For Circle
    /// grants this is `{"kind":"circle","circle_id":"ck:circle:<uuid>"}`.
    pub scope_summary: String,
    /// `granted_at` timestamp for the audit trail.
    pub granted_at: String,
}

#[component]
pub fn CircleGrantsPanel(summary: CircleSummary, grants: Vec<CircleGrantRow>) -> Element {
    let circle_id = summary.id.clone();
    let title = summary.title.clone();
    rsx! {
        section {
            class: "panel circle-grants",
            "data-testid": "circle-grants-panel",
            "data-circle-id": "{circle_id}",
            "data-selector-kind": "circle",
            header { class: "panel-head",
                h1 { "Grants — {title}" }
                p { class: "muted",
                    "Grants scoped to this Circle use the new `circle` resource selector "
                    "(spec b47ff6ec / `resource-selector.schema.json`). Selector form: "
                    "`ck:circle:<uuid>`."
                }
            }
            if grants.is_empty() {
                p {
                    class: "muted",
                    "data-testid": "circle-grants-empty",
                    "No grants are attached to this Circle yet."
                }
            } else {
                ul { class: "grant-list",
                    for grant in grants.iter() {
                        li {
                            key: "{grant.grant_id}",
                            class: "grant-row",
                            "data-testid": "circle-grant-row",
                            "data-grant-id": "{grant.grant_id}",
                            "data-action": "{grant.action}",
                            span { class: "grant-action mono", "{grant.action}" }
                            span { class: "grant-scope muted", "{grant.scope_summary}" }
                            span { class: "grant-when muted", "{grant.granted_at}" }
                        }
                    }
                }
            }
        }
    }
}

/// Compact Circle-list item used in the Space sidebar (P3B.2.1).
/// Renders a single row that the parent sidebar wraps in a clickable
/// link to `/circles/:circle_id`.
#[component]
pub fn CircleSidebarRow(summary: CircleSummary, onclick: EventHandler<String>) -> Element {
    let circle_id = summary.id.clone();
    let title = summary.title.clone();
    let short_name = summary.short_name.clone();
    let color = summary.color_token.clone();
    let symbol = summary.symbol.clone();
    let member_count = summary.member_count;

    rsx! {
        button {
            class: "sidebar-row circle-sidebar-row",
            "data-testid": "circle-sidebar-row",
            "data-circle-id": "{circle_id}",
            onclick: move |_| onclick.call(circle_id.clone()),
            span { class: "circle-chip color-{color}", "{symbol} {short_name}" }
            span { class: "sidebar-row-label", "{title}" }
            span { class: "muted sidebar-row-count", "{member_count}" }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circle::CircleScope;

    fn sample() -> CircleSummary {
        CircleSummary {
            id: "ck:circle:ops".to_owned(),
            realm_id: "ck:realm:home".to_owned(),
            title: "Ops".to_owned(),
            short_name: "Ops".to_owned(),
            color_token: "indigo".to_owned(),
            symbol: "shield".to_owned(),
            member_count: 4,
            viewer_is_member: true,
        }
    }

    #[test]
    fn summary_round_trips_to_scope() {
        let scope = sample().into_scope();
        assert!(matches!(scope, CircleScope::Circle { .. }));
        assert_eq!(scope.circle_id(), Some("ck:circle:ops"));
    }

    #[test]
    fn member_row_carries_fields() {
        let row = CircleMemberRow {
            actor_did: "did:web:alice.example".to_owned(),
            display_handle: "@alice".to_owned(),
            role: "admin".to_owned(),
        };
        assert_eq!(row.role, "admin");
    }
}
