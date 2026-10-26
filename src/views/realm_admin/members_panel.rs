use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
use arkret_models_collaboration::governance::agent_participation::ParticipationNextReplaceInput;
use arkret_models_collaboration::governance::agent_participation::{
    AgentParticipationView, ParticipationBits, ParticipationScope,
};
use arkret_wire::{CapabilityActionId, event_kind_str};
use glory::ui::Widget;
use glory::{Cage, Scope};
use serde_json::{Value, json};

use super::capabilities::RealmMemberCapabilities;
use crate::operation::ak_ops;
use crate::presentation::{InksonContext, SharedStateStore, View};
use crate::state::{LocalStateStore, MoveSubmissionState, RawOperationRecord};
use crate::transport::auth::{authed_api_with_sync, with_authed_api};
use crate::views::helpers::{actor_display_label, short_protocol_id};
use crate::views::settings::widgets::*;

mod controller;
mod effects;
mod model;
mod owned_authority;

use controller::*;
use model::*;

// These helpers translate presentation only; roster classification and wire values stay in the
// model.
fn member_section_title(section: MemberRosterSection) -> String {
    crate::i18n::tr(match section {
        MemberRosterSection::Members => "realm_admin.members",
        MemberRosterSection::Owners => "realm_admin.roster.owners",
        MemberRosterSection::Admins => "realm_admin.roster.admins",
        MemberRosterSection::MyAgents => "realm_admin.roster.my_agents",
        MemberRosterSection::PendingInvites => "realm_admin.roster.pending_invites",
    })
}
fn member_choice_contents(label: String, count: usize) -> impl glory::ui::Widget {
    glory::ui::group().fill((
        glory::ui::text().content(label),
        glory::ui::text().class("badge").content(count.to_string()),
    ))
}
fn member_section_description(section: MemberRosterSection) -> String {
    crate::i18n::tr(match section {
        MemberRosterSection::Members => "realm_admin.roster.members_description",
        MemberRosterSection::Owners => "realm_admin.roster.owners_description",
        MemberRosterSection::Admins => "realm_admin.roster.admins_description",
        MemberRosterSection::MyAgents => "realm_admin.roster.my_agents_description",
        MemberRosterSection::PendingInvites => "realm_admin.roster.pending_invites_description",
    })
}
fn member_role_label(profile: &MemberProfile) -> String {
    crate::i18n::tr(if profile.is_owner {
        "realm_admin.roster.realm_owner"
    } else if profile.is_admin {
        "realm_admin.roster.realm_admin"
    } else {
        "realm_admin.roster.realm_member"
    })
}
fn member_handles_label(all: &[String], visible: &[String]) -> String {
    crate::i18n::tr(if all.len() == visible.len() {
        "realm_admin.roster.handles"
    } else {
        "realm_admin.roster.other_handles"
    })
}
fn member_identity_title(
    scope: &Scope,
    context: Rc<InksonContext>,
    profile: &MemberProfile,
) -> View {
    let tier = profile.display_tier();
    let mut title = vec![Box::new(
        glory::ui::text()
            .class(format!("member-row-primary {}", tier.css_class()))
            .content(profile.primary_label()),
    ) as View];
    if let Some((badge, detail)) = tier.degraded_badge() {
        title.push(paragraph(
            "badge muted identity-tier-badge member-identity-degraded",
            badge,
        ));
        title.push(crate::components::help_tip(
            scope,
            context,
            crate::components::HelpTipProps { text: detail },
        ));
    }
    line("member-row-title member-identity-title", title)
}
fn member_identity_lines(profile: &MemberProfile) -> Vec<View> {
    member_profile_lines(profile, false)
}
fn member_profile_lines(profile: &MemberProfile, include_role: bool) -> Vec<View> {
    let primary = profile.primary_label();
    let public = profile.public_label();
    let identity = profile
        .handles
        .first()
        .cloned()
        .unwrap_or_else(|| member_identity_fallback_label(&profile.actor_id));
    let mut role = Vec::new();
    if include_role {
        role.push(plain(member_role_label(profile)));
    }
    if member_line_identity_visible(&identity, &primary, &profile.handles) {
        role.push(plain(identity));
    }
    let mut lines = Vec::new();
    if !role.is_empty() {
        lines.push(line("member-profile-line", role));
    }
    if let Some(name) = &profile.remark_name
        && !name.is_empty()
        && *name != public
    {
        lines.push(line(
            "member-profile-line",
            vec![
                paragraph(
                    "member-profile-label",
                    crate::i18n::tr("realm_admin.roster.my_name"),
                ),
                plain(name.clone()),
            ],
        ));
    }
    if let Some(display) = &profile.display_name
        && !display.is_empty()
        && *display != primary
    {
        lines.push(line(
            "member-profile-line",
            vec![
                paragraph(
                    "member-profile-label",
                    crate::i18n::tr("realm_admin.roster.display"),
                ),
                plain(display.clone()),
            ],
        ));
    }
    let visible = member_handles_for_line(&profile.handles, &primary);
    if !visible.is_empty() {
        let mut handles = vec![paragraph(
            "member-profile-label",
            member_handles_label(&profile.handles, &visible),
        )];
        handles.extend(
            visible
                .into_iter()
                .map(|handle| paragraph("member-handle-chip", handle)),
        );
        lines.push(line("member-profile-line member-handle-list", handles));
    }
    if let Some(note) = &profile.remark_note
        && !note.is_empty()
    {
        lines.push(line(
            "member-profile-line",
            vec![
                paragraph(
                    "member-profile-label",
                    crate::i18n::tr("realm_admin.roster.note"),
                ),
                plain(note.clone()),
            ],
        ));
    }
    if let Some(subject) = &profile.subject_id
        && !subject.is_empty()
        && *subject != profile.actor_id
    {
        lines.push(line(
            "member-profile-line",
            vec![
                paragraph(
                    "member-profile-label",
                    crate::i18n::tr("realm_admin.roster.subject"),
                ),
                plain(member_identity_fallback_label(subject)),
            ],
        ));
    }
    lines
}
fn member_mention_label(policy: AgentMentionPolicy) -> String {
    crate::i18n::tr(match policy {
        AgentMentionPolicy::Allowed => "realm_admin.roster.mention_allowed",
        AgentMentionPolicy::OwnerOnly => "realm_admin.roster.mention_owner_only",
        AgentMentionPolicy::Unknown => "realm_admin.roster.mention_unknown",
    })
}
fn member_agent_state_label(state: &str) -> String {
    let key = match state {
        "pending" | "pending_runtime_key" => "realm_admin.roster.agent_awaiting",
        "ready" => "realm_admin.roster.agent_ready",
        "replacing" => "realm_admin.roster.agent_replacing",
        "active" => "realm_admin.roster.agent_active",
        "pairing_expired" => "realm_admin.roster.agent_expired",
        "paused" => "realm_admin.roster.agent_paused",
        "deactivated" => "realm_admin.roster.agent_deactivated",
        other => return other.to_owned(),
    };
    crate::i18n::tr(key)
}

#[derive(Clone)]
struct MembersPage {
    context: Rc<InksonContext>,
    realm: String,
    controller: RealmMembersController,
    section: Cage<MemberRosterSection>,
    query: Cage<String>,
    visible: Cage<usize>,
    block: Cage<Option<String>>,
    agent_pending: Cage<BTreeSet<String>>,
}
impl MembersPage {
    fn new(scope: &Scope, context: Rc<InksonContext>, realm: String) -> Self {
        let controller = RealmMembersController {
            token: context.token,
            status_msg: scope.cage(String::new()),
            sync_cursor: context.sync_cursor,
            frontier_state: context.frontier_state,
            members: scope.cage(Vec::new()),
            invite_target: scope.cage(String::new()),
            invite_modal_open: scope.cage(false),
            agent_add_modal_open: scope.cage(false),
            agent_add_state: scope.cage(AgentAddState::default()),
            selected_contacts: scope.cage(BTreeSet::new()),
            owned_agents: scope.cage(Vec::new()),
            permissions: scope.cage(RealmMemberCapabilities::default()),
            invite_contacts: scope.cage(Vec::new()),
            invite_contacts_loaded: scope.cage(false),
            invite_contacts_status: scope.cage(String::new()),
            state_store: context.state_store.clone(),
            owner: scope.downgrade(),
        };
        Self {
            context,
            realm,
            controller,
            section: scope.cage(MemberRosterSection::Members),
            query: scope.cage(String::new()),
            visible: scope.cage(MEMBER_PAGE_SIZE),
            block: scope.cage(None),
            agent_pending: scope.cage(BTreeSet::new()),
        }
    }
    fn write_context(&self) -> RealmWriteContext {
        RealmWriteContext {
            base_url: self.context.base_url.get(),
            realm_id: self.realm.clone(),
            actor_id: self
                .context
                .principal_id
                .get()
                .map(|value| value.to_string())
                .unwrap_or_default(),
        }
    }
    fn dispatch(&self, command: RealmMembersCommand) {
        self.controller
            .clone()
            .dispatch(self.write_context(), command);
    }
}

fn member_header_icon(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: &str,
    label: &str,
    icon: &str,
    handler: impl FnMut() + 'static,
) -> View {
    Box::new(
        sapid::button()
            .unstyled()
            .class(format!("btn secondary member-head-icon-btn {key}"))
            .name(context.translated(scope, label))
            .label("")
            .fill(crate::components::ui_icon(icon))
            .on_press(handler),
    )
}

pub(super) fn page(scope: &Scope, context: Rc<InksonContext>, realm: String) -> View {
    let state = MembersPage::new(scope, context.clone(), realm.clone());
    effects::mount(scope, context.clone(), state.controller.clone(), realm);
    let members = state.controller.members;
    let agents = state.controller.owned_agents;
    let permissions = state.controller.permissions;
    let section = state.section;
    let query = state.query;
    let visible = state.visible;
    let list_state = state.clone();
    let source = scope.bond(move || {
        (
            members.get(),
            agents.get(),
            permissions.get(),
            section.get(),
            query.get(),
            visible.get(),
        )
    });
    let roster = reactive(
        source,
        move |scope, (members, agents, permissions, selected, filter_value, limit)| {
            let state = list_state.clone();
            let context = state.context.clone();
            let principal = context
                .principal_id
                .get()
                .map(|value| value.to_string())
                .unwrap_or_default();
            let view = build_realm_roster(RealmRosterInput {
                members,
                owned_agents: agents,
                principal_id: &principal,
                section: selected,
                query: &filter_value,
                visible_limit: limit,
            });
            let mut menu = Vec::new();
            for (next, count) in [
                (MemberRosterSection::Members, view.total_regular_members),
                (MemberRosterSection::Owners, view.total_owner_members),
                (MemberRosterSection::Admins, view.total_admin_members),
                (
                    MemberRosterSection::MyAgents,
                    view.self_realm_agent_rows.len(),
                ),
                (
                    MemberRosterSection::PendingInvites,
                    view.total_pending_invites,
                ),
            ] {
                let label = member_section_title(next);
                menu.push(Box::new(
                    sapid::button()
                        .unstyled()
                        .class(next.menu_item_class(selected))
                        .name(label.clone())
                        .label("")
                        .fill(member_choice_contents(label, count))
                        .on_press(move || {
                            section.revise(|value| {
                                *value = next;
                            });
                            visible.revise(|value| {
                                *value = MEMBER_PAGE_SIZE;
                            });
                        }),
                ) as View);
            }
            let mut rows = vec![line(
                "member-section-head",
                vec![
                    stack(
                        "member-section-heading",
                        vec![
                            heading(
                                3,
                                "entity-title members-section-title",
                                member_section_title(selected),
                            ),
                            paragraph("muted", member_section_description(selected)),
                        ],
                    ),
                    paragraph(
                        "badge member-count-badge member-section-visible-count",
                        context
                            .tr("realm_admin.roster.shown")
                            .replace("{total}", &view.selected_section_visible_count.to_string()),
                    ),
                ],
            )];
            if selected == MemberRosterSection::PendingInvites {
                if view.pending_invite_match_count == 0 {
                    rows.push(paragraph(
                        "muted member-pending-invite-empty",
                        context.translated(scope, "realm_admin.roster.pending_no_match"),
                    ));
                }
                for profile in view.visible_pending_invites {
                    rows.push(pending_invite(scope, &state, profile, permissions));
                }
            } else if selected == MemberRosterSection::MyAgents {
                let total = view.self_realm_agent_rows.len();
                let mut section_body = vec![line(
                    "member-self-agent-settings-head",
                    vec![
                        stack(
                            "member-self-agent-heading",
                            vec![
                                heading(
                                    3,
                                    "entity-title",
                                    context.translated(scope, "realm_admin.roster.agents"),
                                ),
                                paragraph(
                                    "muted",
                                    context.translated(scope, "realm_admin.roster.my_agents_hint"),
                                ),
                            ],
                        ),
                        paragraph(
                            "badge",
                            context
                                .tr("realm_admin.roster.total")
                                .replace("{total}", &total.to_string()),
                        ),
                    ],
                )];
                if total == 0 {
                    let open = state.controller.agent_add_modal_open;
                    let adding = state.controller.agent_add_state;
                    section_body.push(stack(
                        "members-empty compact member-self-agent-empty",
                        vec![
                            crate::components::ui_icon("bot"),
                            paragraph(
                                "members-empty-title",
                                context.translated(scope, "realm_admin.roster.no_realm_agents"),
                            ),
                            paragraph(
                                "muted members-empty-hint",
                                context
                                    .translated(scope, "realm_admin.roster.no_realm_agents_hint"),
                            ),
                            action(
                                scope,
                                context.clone(),
                                "member-agent-empty-add",
                                "realm_admin.roster.add_agent_short",
                                "primary",
                                true,
                                move || {
                                    if !adding.get_untracked().is_pending() {
                                        adding.revise(|value| *value = AgentAddState::Idle);
                                    }
                                    open.revise(|value| *value = true);
                                },
                            ),
                        ],
                    ));
                } else {
                    section_body.push(stack(
                        "member-self-agent-list",
                        view.self_realm_agent_rows
                            .into_iter()
                            .map(|agent| owned_agent(scope, &state, agent))
                            .collect(),
                    ));
                }
                rows.push(stack("member-self-agent-settings", section_body));
                rows.push(owned_authority::withdrawal(
                    scope,
                    context.clone(),
                    state.realm.clone(),
                ));
            } else {
                for group in view.visible_groups {
                    let self_row = is_local_account_actor(&group.controller.actor_id, &principal);
                    rows.push(member_row(
                        scope,
                        &state,
                        group,
                        permissions.can_remove,
                        self_row,
                        view.self_leave_disabled_reason.clone(),
                    ));
                }
            }
            if view.selected_section_empty
                && selected != MemberRosterSection::PendingInvites
                && selected != MemberRosterSection::MyAgents
            {
                rows.push(paragraph(
                    "members-empty",
                    context.translated(
                        scope,
                        if view.selected_section_total == 0 && view.filter_query.is_empty() {
                            "realm_admin.no_members_loaded"
                        } else {
                            "realm_admin.members_no_match"
                        },
                    ),
                ));
            }
            if view.has_more {
                rows.push(action(
                    scope,
                    context.clone(),
                    "load-more-members-button",
                    "realm_admin.roster.load_more",
                    "secondary",
                    true,
                    move || visible.revise(|value| *value += MEMBER_PAGE_SIZE),
                ));
            }
            let open_invite = state.controller.invite_modal_open;
            let open_agent = state.controller.agent_add_modal_open;
            let refresh_state = state.clone();
            let mut head_actions = vec![paragraph(
                "badge member-count-badge",
                view.total_members.to_string(),
            )];
            if selected == MemberRosterSection::MyAgents {
                head_actions.push(action(
                    scope,
                    context.clone(),
                    "open-add-realm-agent-modal-button",
                    "realm_admin.roster.add_agent",
                    "secondary member-head-icon-btn-accent",
                    true,
                    move || {
                        open_agent.revise(|value| {
                            *value = true;
                        })
                    },
                ));
            } else if permissions.can_invite {
                head_actions.push(member_header_icon(
                    scope,
                    context.clone(),
                    "open-invite-modal-button",
                    "realm_admin.roster.invite_member",
                    "plus",
                    move || {
                        open_invite.revise(|value| {
                            *value = true;
                        })
                    },
                ));
            }
            head_actions.push(member_header_icon(
                scope,
                context.clone(),
                "refresh-members-button",
                "common.refresh",
                "refresh",
                move || {
                    let next = refresh_state.context.state_store.read(|store| {
                        projected_member_profiles_for_realm(store, &refresh_state.realm)
                    });
                    refresh_state.controller.members.revise(|value| {
                        *value = next;
                    });
                    visible.revise(|value| {
                        *value = MEMBER_PAGE_SIZE;
                    });
                },
            ));
            let search = if view.show_search {
                crate::views::settings::widgets::input_prompt(
                    scope,
                    context
                        .translated(scope, "realm_admin.roster.search")
                        .into(),
                    query,
                    Box::new(
                        sapid::text_field()
                            .unstyled()
                            .class("input member-search-input")
                            .name(context.translated(scope, "realm_admin.roster.search"))
                            .value(query)
                            .on_value_change(move |next| {
                                query.revise(|value| *value = next);
                                visible.revise(|value| *value = MEMBER_PAGE_SIZE);
                            }),
                    ),
                )
            } else {
                empty()
            };
            stack(
                "event member-list-card realm-members-card",
                vec![
                    line(
                        "event-head",
                        vec![
                            plain(context.translated(scope, "realm_admin.members")),
                            line("member-head-actions", head_actions),
                        ],
                    ),
                    search,
                    line(
                        "members-admin-layout",
                        vec![
                            Box::new(
                                glory::ui::view()
                                    .class("members-admin-menu")
                                    .role(glory::render::Role::Navigation)
                                    .name(context.translated(scope, "realm_admin.roster.sections"))
                                    .fill(menu),
                            ) as View,
                            stack("members-admin-content", rows),
                        ],
                    ),
                ],
            )
        },
    );
    stack(
        "timeline realm-members-panel",
        vec![
            status(state.controller.status_msg),
            roster,
            invite_modal(scope, &state),
            add_agent_modal(scope, &state),
            block_modal(scope, &state),
        ],
    )
}
fn member_row(
    scope: &Scope,
    state: &MembersPage,
    group: MemberGroup,
    can_remove: bool,
    is_self: bool,
    leave_reason: Option<String>,
) -> View {
    let context = state.context.clone();
    let profile = group.controller;
    let label = profile.primary_label();
    let id = profile.actor_id.clone();
    let avatar = crate::components::identity_avatar(
        scope,
        context.clone(),
        crate::components::IdentityAvatarProps {
            seed: id.clone(),
            alt_text: label.clone(),
            blob_ref: profile.avatar_blob_ref.as_ref().map(ToString::to_string),
            class: "avatar-img member-avatar-image".into(),
            test_id: None,
        },
    );
    let has_agents = !group.agents.is_empty();
    let mut title = vec![member_identity_title(scope, context.clone(), &profile)];
    if is_self {
        title.push(crate::components::self_attribution_badge(
            scope,
            context.clone(),
            crate::components::SelfAttributionBadgeProps {
                class: Some("member-you-badge".into()),
                test_id: Some("member-self-badge".into()),
            },
        ));
    }
    if profile.is_owner {
        title.push(paragraph(
            "badge amber",
            context.translated(scope, "realm_admin.roster.owner"),
        ));
    } else if profile.is_admin {
        title.push(paragraph(
            "badge blue",
            context.translated(scope, "realm_admin.roster.admin"),
        ));
    }
    if profile.confusable_contact_warning {
        title.push(paragraph(
            "badge amber member-contact-confusable-warning",
            context.translated(scope, "contacts.petname.confusable_warning"),
        ));
    }
    if !is_self && has_agents {
        title.push(paragraph(
            "badge blue member-agent-count",
            context
                .tr("realm_admin.roster.agent_count")
                .replace("{total}", &group.agents.len().to_string()),
        ));
    }
    let details = vec![
        line("member-row-title", title),
        stack(
            "muted member-row-sub member-profile-lines",
            member_profile_lines(&profile, true),
        ),
    ];
    let mut actions = Vec::new();
    if is_self {
        let command = state.clone();
        actions.push(action(
            scope,
            context.clone(),
            "member-row-leave-button",
            "realm_admin.leave_realm",
            "secondary",
            leave_reason.is_none(),
            move || {
                if leave_reason.is_some() {
                    return;
                }
                command.dispatch(RealmMembersCommand::LeaveRealm);
            },
        ));
    } else {
        if can_remove {
            for ban in [false, true] {
                let command = state.clone();
                let id = id.clone();
                let label = label.clone();
                actions.push(action(
                    scope,
                    context.clone(),
                    if ban {
                        "ban-member-button"
                    } else {
                        "kick-member-button"
                    },
                    if ban {
                        "realm_admin.ban_member"
                    } else {
                        "realm_admin.kick_member"
                    },
                    "secondary",
                    true,
                    move || {
                        command.dispatch(if ban {
                            RealmMembersCommand::BanMember {
                                target_id: id.clone(),
                                target_label: label.clone(),
                            }
                        } else {
                            RealmMembersCommand::KickMember {
                                target_id: id.clone(),
                                target_label: label.clone(),
                            }
                        });
                    },
                ));
            }
        }
        let block = state.block;
        let id = id.clone();
        actions.push(action(
            scope,
            context.clone(),
            "member-row-block-button",
            "member.block",
            "secondary",
            true,
            move || {
                block.revise(|value| {
                    *value = Some(id.clone());
                })
            },
        ));
    }
    let chips = group
        .agents
        .into_iter()
        .map(|agent| paragraph("member-agent-chip", agent.display_name))
        .collect();
    let full_identity = serde_json::from_str::<arkret_sdk::ActorId>(&id)
        .ok()
        .and_then(|actor| actor.as_account_id().cloned())
        .map(|account| {
            format!(
                "Principal: {} · Station: {}",
                account.principal_id, account.station_id
            )
        })
        .unwrap_or_else(|| id.clone());
    use sha2::Digest;
    let identity_id = match glory::render::SemanticId::new(format!(
        "member-recipient-{}",
        hex::encode(sha2::Sha256::digest(
            format!("{}:{id}", state.realm).as_bytes()
        ))
    )) {
        Ok(id) => id,
        Err(error) => {
            scope.report_error(error);
            return empty();
        }
    };
    let mut rows = vec![Box::new(
        glory::ui::view()
            .class("event member-row member-controller-row")
            .role(glory::render::Role::Group)
            .semantics(Some(Box::new(glory::render::Semantics {
                described_by: Some(identity_id.clone()),
                ..Default::default()
            })))
            .fill(vec![
                line(
                    "event-head member-row-main",
                    vec![
                        stack("member-avatar", vec![avatar]),
                        stack("member-row-text", details),
                    ],
                ),
                line("actions", actions),
                Box::new(
                    glory::ui::text()
                        .class("sr-only member-row-identity")
                        .content(full_identity)
                        .semantics(Some(Box::new(glory::render::Semantics {
                            id: Some(identity_id),
                            ..Default::default()
                        }))),
                ) as View,
            ]),
    ) as View];
    if has_agents {
        rows.push(line("member-agent-list member-agent-chips", chips));
    }
    stack(
        if has_agents {
            "member-group has-agents"
        } else {
            "member-group"
        },
        rows,
    )
}

fn pending_invite(
    scope: &Scope,
    state: &MembersPage,
    profile: MemberProfile,
    permissions: RealmMemberCapabilities,
) -> View {
    let context = state.context.clone();
    let id = profile.actor_id.clone();
    let label = profile.primary_label();
    let direct = profile
        .invite_is_direct
        .is_some_and(|value| value)
        .then(|| crate::mls_api_helpers::account_id_from_selector(&id))
        .flatten();
    let is_direct = direct.is_some();
    let invite_id = profile.invite_id.clone().unwrap_or_default();
    let allowed = profile.invite_is_direct.is_some()
        && !invite_id.is_empty()
        && if is_direct {
            permissions.can_cancel_invite
        } else {
            permissions.can_revoke_invite
        };
    let command = state.clone();
    let class_known = profile.invite_is_direct.is_some();
    let can_present = class_known
        && if is_direct {
            permissions.can_cancel_invite
        } else {
            permissions.can_revoke_invite
        };
    let membership = profile
        .normalized_membership()
        .unwrap_or("invite")
        .to_owned();
    let state_key = if matches!(membership.as_str(), "pending" | "pending_invite") {
        "realm_admin.roster.pending"
    } else {
        "realm_admin.roster.invitation_sent"
    };
    let mut lines = vec![line(
        "member-row-title",
        vec![
            member_identity_title(scope, context.clone(), &profile),
            paragraph(
                "badge amber",
                context.translated(scope, "realm_admin.roster.pending_badge"),
            ),
        ],
    )];
    let mut profile_lines = vec![
        line(
            "member-profile-line",
            vec![plain(context.translated(scope, state_key))],
        ),
        line(
            "member-profile-line",
            vec![
                paragraph(
                    "member-profile-label",
                    context.translated(scope, "realm_admin.roster.member_state"),
                ),
                plain(membership),
            ],
        ),
    ];
    profile_lines.extend(member_identity_lines(&profile));
    lines.push(stack(
        "muted member-row-sub member-profile-lines",
        profile_lines,
    ));
    let mut actions = Vec::new();
    if can_present {
        actions.push(action(
            scope,
            context.clone(),
            "pending-invite-terminate",
            if is_direct {
                "realm_admin.roster.cancel_invite"
            } else {
                "realm_admin.roster.revoke_invite"
            },
            "secondary",
            allowed,
            move || {
                if !allowed {
                    return;
                }
                command.dispatch(RealmMembersCommand::TerminatePendingInvite {
                    invite_id: invite_id.clone(),
                    member_id: id.clone(),
                    member_label: label.clone(),
                    direct_invitee: direct.clone(),
                });
            },
        ));
        if !allowed {
            actions.push(crate::components::help_tip(
                scope,
                context.clone(),
                crate::components::HelpTipProps {
                    text: context.tr("realm_admin.roster.invite_id_unavailable"),
                },
            ));
        }
    }
    line(
        "event member-row member-pending-invite-row pending-invite-row",
        vec![
            line(
                "event-head member-row-main",
                vec![
                    stack(
                        "member-avatar member-avatar-pending",
                        vec![crate::components::identity_avatar(
                            scope,
                            context.clone(),
                            crate::components::IdentityAvatarProps {
                                seed: profile.actor_id.clone(),
                                alt_text: profile.primary_label(),
                                blob_ref: profile.avatar_blob_ref.as_ref().map(ToString::to_string),
                                class: "avatar-img member-avatar-image".into(),
                                test_id: None,
                            },
                        )],
                    ),
                    stack("member-row-text", lines),
                ],
            ),
            line("actions", actions),
        ],
    )
}

fn owned_agent(scope: &Scope, state: &MembersPage, agent: MemberAgentRow) -> View {
    let context = state.context.clone();
    let id = agent.agent_id.clone();
    let label = agent.display_name.clone();
    let pending = state.agent_pending;
    let check_id = id.clone();
    let enabled = scope.bond(move || !pending.get().contains(&check_id));
    let remove = state.clone();
    let remove_id = owned_agent_actor_key(&id).unwrap_or_default();
    let remove_label = label.clone();
    let mut interaction = Vec::new();
    for (mode, label) in [
        (
            arkret_sdk::AgentInteractionMode::Private,
            "realm_admin.roster.private",
        ),
        (
            arkret_sdk::AgentInteractionMode::Public,
            "realm_admin.roster.public",
        ),
    ] {
        let command = state.clone();
        let id = id.clone();
        interaction.push(action(
            scope,
            context.clone(),
            &format!(
                "member-agent-interaction-{}",
                if matches!(mode, arkret_sdk::AgentInteractionMode::Private) {
                    "private"
                } else {
                    "public"
                }
            ),
            label,
            "secondary",
            enabled,
            move || {
                spawn_set_agent_interaction(
                    command.controller.owner.clone(),
                    command.context.clone(),
                    command.context.base_url.get(),
                    command.context.token.get(),
                    command.realm.clone(),
                    id.clone(),
                    mode,
                    command.controller.status_msg,
                    command.agent_pending,
                );
            },
        ));
    }
    let mut behavior = Vec::new();
    for (index, label) in [
        "realm_admin.roster.reply",
        "realm_admin.roster.mention",
        "realm_admin.roster.acting_on_behalf_allowed",
    ]
    .into_iter()
    .enumerate()
    {
        let checked = match index {
            0 => agent.selection.message_creation_allowed,
            1 => agent.selection.third_party_mention_delivery_allowed,
            _ => agent.selection.acting_on_behalf_allowed,
        };
        let command = state.clone();
        let id = id.clone();
        behavior.push(toggle(
            scope,
            context.clone(),
            &format!("member-agent-behavior-toggle member-agent-behavior-{index}"),
            label,
            checked,
            enabled,
            move |checked| {
                let Some(current) = command
                    .controller
                    .owned_agents
                    .get()
                    .into_iter()
                    .find(|agent| agent.agent_id == id)
                else {
                    return;
                };
                let mut selection = current.selection;
                match index {
                    0 => selection.message_creation_allowed = checked,
                    1 => selection.third_party_mention_delivery_allowed = checked,
                    _ => selection.acting_on_behalf_allowed = checked,
                }
                spawn_set_agent_realm_behavior(
                    command.controller.owner.clone(),
                    command.context.clone(),
                    command.context.base_url.get(),
                    command.context.token.get(),
                    command.realm.clone(),
                    id.clone(),
                    selection,
                    command.controller.owned_agents,
                    command.controller.status_msg,
                    command.agent_pending,
                );
            },
        ));
    }
    let mut title = vec![
        plain(label.clone()),
        paragraph(
            crate::views::agents::agent_state_badge_class(&agent.status),
            member_agent_state_label(&agent.status),
        ),
    ];
    if !agent.slug.is_empty() {
        title.push(paragraph("badge", agent.slug.clone()));
    }
    let mut action_children = vec![
        paragraph(
            "badge green",
            context.translated(scope, "realm_admin.roster.in_realm"),
        ),
        paragraph(
            format!(
                "{} member-agent-mention-policy",
                agent.mention_policy.badge_class()
            ),
            member_mention_label(agent.mention_policy),
        ),
        action(
            scope,
            context.clone(),
            "member-agent-remove-from-realm",
            "realm_admin.roster.remove",
            "secondary",
            true,
            move || {
                remove.dispatch(RealmMembersCommand::RemoveOwnedAgent {
                    target_id: remove_id.clone(),
                    target_label: remove_label.clone(),
                })
            },
        ),
    ];
    interaction.insert(
        0,
        plain(context.translated(scope, "realm_admin.roster.interaction")),
    );
    action_children.push(line("member-agent-interaction-mode", interaction));
    action_children.push(owned_authority::authority(
        scope,
        context.clone(),
        state.realm.clone(),
        id.clone(),
    ));
    line(
        "member-self-agent-row",
        vec![
            line(
                "member-agent-summary",
                vec![
                    stack(
                        "member-avatar member-avatar-agent",
                        vec![crate::components::identity_avatar(
                            scope,
                            context.clone(),
                            crate::components::IdentityAvatarProps {
                                seed: id.clone(),
                                alt_text: label,
                                blob_ref: None,
                                class: "avatar-img member-avatar-image".into(),
                                test_id: None,
                            },
                        )],
                    ),
                    stack(
                        "member-row-text",
                        vec![
                            line("member-row-title", title),
                            paragraph("muted member-row-sub mono", short_protocol_id(&id)),
                        ],
                    ),
                ],
            ),
            line("member-self-agent-actions", action_children),
            line("member-agent-realm-behavior", behavior),
        ],
    )
}

fn invite_modal(_scope: &Scope, state: &MembersPage) -> View {
    let open = state.controller.invite_modal_open;
    let modal_state = state.clone();
    reactive(open, move |scope, open| {
        if !open {
            return empty();
        }
        let state = modal_state.clone();
        let context = state.context.clone();
        let selected = state.controller.selected_contacts;
        let target = state.controller.invite_target;
        let feedback = state.controller.invite_contacts_status;
        let contacts = state.controller.invite_contacts;
        let contacts_context = context.clone();
        let contact_list = reactive(contacts, move |scope, contacts| {
            let context = contacts_context.clone();
            let mut rows = Vec::new();
            for contact in contacts {
                let actor = contact.peer.contact_actor_id();
                let id = actor.to_string();
                let eligible = crate::models::contact_grants_me_invite(&contact)
                    && actor.as_account_id().is_some();
                let checked_id = id.clone();
                let checked = scope.bond(move || selected.get().contains(&checked_id));
                let label = context
                    .state_store
                    .read(|store| actor_display_label(store, &id));
                rows.push(Box::new(
                    sapid::checkbox()
                        .unstyled()
                        .class("invite-contact-row")
                        .label(label)
                        .checked(checked)
                        .enabled(eligible)
                        .on_checked_change(move |checked| {
                            selected.revise(|values| {
                                if checked {
                                    values.insert(id.clone());
                                } else {
                                    values.remove(&id);
                                }
                            })
                        }),
                ) as View);
            }
            stack("invite-contact-list", rows)
        });
        let contact_command = state.clone();
        let direct_command = state.clone();
        let close = state.controller.invite_modal_open;
        let body = stack(
            "modal-body workflow-form",
            vec![
                status(feedback),
                contact_list,
                action(
                    scope,
                    context.clone(),
                    "realm-invite-send",
                    "realm_admin.invite_selected",
                    "primary",
                    scope.bond(move || !selected.get().is_empty()),
                    move || {
                        let selected = selected.get();
                        let targets = contact_command
                            .controller
                            .invite_contacts
                            .get()
                            .into_iter()
                            .filter(|contact| {
                                selected.contains(&contact.peer.contact_actor_id().to_string())
                                    && crate::models::contact_grants_me_invite(contact)
                            })
                            .filter_map(|contact| {
                                contact.peer.contact_actor_id().as_account_id().cloned()
                            })
                            .collect::<Vec<_>>();
                        if targets.is_empty() {
                            return;
                        }
                        contact_command.dispatch(RealmMembersCommand::InviteContacts { targets });
                    },
                ),
                paragraph(
                    "invite-divider muted",
                    context.translated(scope, "realm_admin.invite_divider"),
                ),
                Box::new(
                    sapid::field("invite-target-input")
                        .unstyled()
                        .class("field form-field invite-target-input")
                        .label(context.translated(scope, "realm_admin.invite_target_label"))
                        .control({
                            let prompt = context
                                .translated(scope, "realm_admin.roster.invite_target_placeholder");
                            move |field| {
                                glory::ui::widget(move |scope| {
                                    input_prompt(
                                        scope,
                                        prompt.into(),
                                        target,
                                        Box::new(
                                            sapid::text_field()
                                                .unstyled()
                                                .class("input")
                                                .field(field.clone())
                                                .value(target)
                                                .on_value_change(move |next| {
                                                    target.revise(|value| *value = next)
                                                }),
                                        ),
                                    )
                                    .build(scope)
                                })
                            }
                        }),
                ) as View,
                paragraph(
                    "muted",
                    context.translated(scope, "realm_admin.invite_hint"),
                ),
                action(
                    scope,
                    context.clone(),
                    "send-invite-button",
                    "realm_admin.roster.send_invite",
                    "primary",
                    scope.bond(move || !target.get().trim().is_empty()),
                    move || {
                        let target = target.get().trim().to_owned();
                        if target.is_empty() {
                            return;
                        }
                        direct_command.dispatch(RealmMembersCommand::InviteResolvedTarget {
                            target,
                            wait_for: None,
                        });
                    },
                ),
            ],
        );
        let mut body = Some(Box::new(glory::ui::group().fill(vec![
            line(
                "modal-head",
                vec![
                        heading(
                            3,
                            "",
                            context.translated(scope, "realm_admin.roster.invite_member"),
                        ),
                        Box::new(
                            glory::ui::button()
                                .class("secondary icon-button close invite-modal-close")
                                .name(context.translated(scope, "common.close"))
                                .fill(glory::ui::text().content("✕"))
                                .on(glory::render::EventKind::Activate, move |_| {
                                    close.revise(|value| *value = false)
                                }),
                        ) as View,
                    ],
            ),
            body,
            line(
                "modal-foot",
                vec![action(
                    scope,
                    context.clone(),
                    "invite-modal-cancel",
                    "common.cancel",
                    "secondary",
                    true,
                    move || close.revise(|value| *value = false),
                )],
            ),
        ])) as View);
        Box::new(
            sapid::dialog("invite-modal")
                .unstyled()
                .class("modal event invite-modal invite-member-modal")
                .open(true)
                .show_trigger(false)
                .show_close(false)
                .name(context.translated(scope, "realm_admin.roster.invite_member"))
                .on_open_change(move |open| {
                    if !open {
                        close.revise(|value| *value = false);
                    }
                })
                .content(move || body.take().unwrap_or_else(empty)),
        ) as View
    })
}
fn add_agent_modal(scope: &Scope, state: &MembersPage) -> View {
    let open = state.controller.agent_add_modal_open;
    let agents = state.controller.owned_agents;
    let members = state.controller.members;
    let source = scope.bond(move || (open.get(), agents.get(), members.get()));
    let modal_state = state.clone();
    reactive(source, move |scope, (open, agents, members)| {
        if !open {
            return empty();
        }
        let state = modal_state.clone();
        let context = state.context.clone();
        let principal = context
            .principal_id
            .get()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let roster = build_realm_roster(RealmRosterInput {
            members,
            owned_agents: agents,
            principal_id: &principal,
            section: MemberRosterSection::MyAgents,
            query: "",
            visible_limit: MEMBER_PAGE_SIZE,
        });
        let mut choices = Vec::new();
        for agent in roster.available_self_agent_rows {
            let command = state.clone();
            let target = owned_agent_actor_key(&agent.agent_id).unwrap_or_default();
            let label = agent.display_name.clone();
            choices.push(line(
                "member-self-agent-row",
                vec![
                    plain(agent.display_name),
                    action(
                        scope,
                        context.clone(),
                        "member-agent-add-to-realm",
                        "realm_admin.roster.add_agent_short",
                        "primary",
                        {
                            let pending = state.controller.agent_add_state;
                            scope.bond(move || !pending.get().is_pending())
                        },
                        move || {
                            command.dispatch(RealmMembersCommand::AddOwnedAgent {
                                target_id: target.clone(),
                                target_label: label.clone(),
                            })
                        },
                    ),
                ],
            ));
        }
        if choices.is_empty() {
            choices.push(paragraph(
                "muted",
                context.translated(scope, "realm_admin.roster.no_available_agents"),
            ));
        }
        let add_state = state.controller.agent_add_state;
        choices.push(status(scope.bond(move || match add_state.get() {
            AgentAddState::Failed(message) => message,
            AgentAddState::Pending(_) => "正在加入…".into(),
            AgentAddState::Idle => String::new(),
        })));
        let close = state.controller.agent_add_modal_open;
        confirmation(
            scope,
            context.clone(),
            "add-realm-agent-modal",
            context.translated(scope, "realm_admin.roster.add_agent"),
            stack("modal-body workflow-form", choices),
            move || {
                close.revise(|value| {
                    *value = false;
                })
            },
        )
    })
}
fn block_modal(_scope: &Scope, state: &MembersPage) -> View {
    let target = state.block;
    let modal_state = state.clone();
    reactive(target, move |scope, id| {
        let Some(id) = id else { return empty() };
        let state = modal_state.clone();
        let context = state.context.clone();
        let write_context = context.clone();
        let body = stack(
            "modal-body",
            vec![
                paragraph("mono", id.clone()),
                paragraph(
                    "muted",
                    context.translated(scope, "member.block_confirm.body"),
                ),
                action(
                    scope,
                    context.clone(),
                    "block-user-confirm-button",
                    "member.block_confirm.confirm",
                    "primary",
                    true,
                    move || {
                        let changed = write_context
                            .state_store
                            .write(|store| store.block_user(&id, None));
                        target.revise(|value| {
                            *value = None;
                        });
                        if changed && let Some(account) = write_context.active_account.get() {
                            let entries = write_context
                                .state_store
                                .read(|store| store.client_blocklist());
                            crate::views::settings::push_blocklist_account_data(
                                write_context.clone(),
                                write_context.base_url.get(),
                                write_context.token.get(),
                                account.principal_id().to_string(),
                                write_context.state_store.clone(),
                                entries,
                            );
                        }
                    },
                ),
            ],
        );
        confirmation(
            scope,
            context.clone(),
            "block-user-confirm-modal",
            context.translated(scope, "member.block_confirm.title"),
            body,
            move || {
                target.revise(|value| {
                    *value = None;
                })
            },
        )
    })
}
#[cfg(test)]
#[path = "members_panel/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "members_panel/surface_tests.rs"]
mod surface_tests;

#[cfg(test)]
mod retained_locale_tests {
    use std::cell::Cell;

    use super::*;
    use crate::i18n::{UiLocale, with_locale};
    const ORIGINAL: &str = "realm_admin.roster.realm_owner {member} 原文";
    const QUERY: &str = "member-0:original.example";
    fn rendered(_scope: &Scope, query: Cage<String>, section: Cage<MemberRosterSection>) -> View {
        let raw = query.get_untracked();
        assert_eq!(section.get_untracked(), MemberRosterSection::Members);
        assert_eq!(raw, QUERY);
        assert_eq!(arkret_sdk::Handle::parse(QUERY).unwrap().canonical(), QUERY);
        // Exercise the actual roster projection above the real search threshold,
        // without mounting session effects or inventing membership permissions.
        let profiles = (0..10)
            .map(|index| {
                let principal =
                    arkret_sdk::DidCoreId::new(format!("ak:did_core:web:member-{index}.example"))
                        .unwrap();
                let station =
                    arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap();
                let mut profile = MemberProfile::bare(
                    arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(principal, station))
                        .to_string(),
                );
                profile.membership = Some("join".to_owned());
                profile.display_name = Some(if index == 0 {
                    ORIGINAL.to_owned()
                } else {
                    format!("Original {index}")
                });
                profile.handles = vec![format!("member-{index}:original.example")];
                profile
            })
            .collect();
        let view = build_realm_roster(RealmRosterInput {
            members: profiles,
            owned_agents: Vec::new(),
            principal_id: "ak:did_core:web:local.example",
            section: section.get(),
            query: &raw,
            visible_limit: MEMBER_PAGE_SIZE,
        });
        assert!(view.show_search);
        assert_eq!(view.filtered_count, 1);
        assert_eq!(view.visible_groups.len(), 1);
        let profile = &view.visible_groups[0].controller;
        assert_eq!(profile.display_name.as_deref(), Some(ORIGINAL));
        assert_eq!(profile.handles, ["member-0:original.example"]);
        // The real identity ladder prefers the valid cached handle to display_name.
        // Search the rendered handle and keep the underlying display name verbatim.
        assert_eq!(profile.primary_label(), QUERY);
        let actor = profile.actor_id.clone();
        let display = profile.display_name.clone().unwrap();
        let handle_text = profile.handles[0].clone();
        let mut role_profile = profile.clone();
        role_profile.is_owner = true;
        let owner = member_role_label(&role_profile);
        role_profile.is_owner = false;
        role_profile.is_admin = true;
        let admin = member_role_label(&role_profile);
        role_profile.is_admin = false;
        let member = member_role_label(&role_profile);

        let mut labels = vec![];
        for item in [
            MemberRosterSection::Members,
            MemberRosterSection::Owners,
            MemberRosterSection::Admins,
            MemberRosterSection::MyAgents,
            MemberRosterSection::PendingInvites,
        ] {
            labels.push(member_section_title(item));
            labels.push(member_section_description(item));
        }
        labels.extend([
            owner,
            admin,
            member,
            member_handles_label(&profile.handles, &profile.handles),
            member_handles_label(&profile.handles, &[]),
        ]);
        for policy in [
            AgentMentionPolicy::Allowed,
            AgentMentionPolicy::OwnerOnly,
            AgentMentionPolicy::Unknown,
        ] {
            labels.push(member_mention_label(policy));
        }
        for state in [
            "pending",
            "pending_runtime_key",
            "ready",
            "replacing",
            "active",
            "pairing_expired",
            "paused",
            "deactivated",
            ORIGINAL,
        ] {
            labels.push(member_agent_state_label(state));
        }
        labels.extend([raw, actor.to_string(), display, handle_text]);
        stack(
            "retained-member-presentation",
            labels
                .into_iter()
                .map(|label| paragraph("", label))
                .collect(),
        )
    }
    fn texts(app: &glory::ui::App) -> Vec<String> {
        let tree = app.tree();
        let mut pending = tree.roots().to_vec();
        let mut out = vec![];
        while let Some(id) = pending.pop() {
            let node = tree.node(id).unwrap();
            if let glory::render::Props::Text(props) = node.descriptor.view().props {
                out.push(props.content.clone());
            }
            pending.extend(&node.children);
        }
        out
    }
    #[test]
    fn retained_member_labels_and_real_roster_search_preserve_typed_sections_and_original_values() {
        let app = glory::ui::App::memory();
        let scope = app.scope();
        let initialized = Rc::new(Cell::new(0));
        initialized.set(initialized.get() + 1);
        let query = scope.cage(QUERY.to_owned());
        let section = scope.cage(MemberRosterSection::Members);
        let locale = scope.cage(UiLocale::En);
        app.mount(reactive(locale, move |scope, locale| {
            with_locale(locale, || rendered(scope, query, section))
        }))
        .unwrap();
        let english = texts(&app);
        for expected in [
            "Members",
            "Owners",
            "Admins",
            "My agents",
            "Pending invites",
            "Realm owner",
            "Realm admin",
            "Realm member",
            "Handles",
            "Other handles",
            "Members can @",
            "Controller only",
            "@ policy unknown",
            "Awaiting runtime",
            "Ready",
            "Awaiting replacement runtime",
            "Active",
            "Pairing expired",
            "Paused",
            "Deactivated",
            ORIGINAL,
            QUERY,
        ] {
            assert!(
                english.iter().any(|value| value == expected),
                "missing label: {expected}"
            );
        }
        for language in [UiLocale::Zh, UiLocale::En] {
            locale.revise(|value| *value = language);
            app.flush().unwrap();
            let text = texts(&app);
            assert_eq!(initialized.get(), 1, "raw query Cage remains mounted");
            assert_eq!(query.get_untracked(), QUERY);
            assert!(text.iter().any(|value| value == ORIGINAL));
            assert!(text.iter().any(|value| value == QUERY));
            if language == UiLocale::Zh {
                for expected in [
                    "成员",
                    "所有者",
                    "管理员",
                    "我的 Agent",
                    "待处理邀请",
                    "Realm 所有者",
                    "Realm 管理员",
                    "Realm 成员",
                    "账号标识",
                    "其他账号标识",
                    "成员可以 @提及",
                    "仅控制者",
                    "@提及策略未知",
                    "等待运行时",
                    "就绪",
                    "等待替换运行时",
                    "活跃",
                    "配对已过期",
                    "已暂停",
                    "已停用",
                ] {
                    assert!(
                        text.iter().any(|value| value == expected),
                        "missing label: {expected}"
                    );
                }
            } else {
                assert_eq!(text, english);
            }
        }
    }
}
