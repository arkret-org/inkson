use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
use arkret_models_collaboration::governance::agent_participation::ParticipationNextReplaceInput;
use arkret_models_collaboration::governance::agent_participation::{
    AgentParticipationEntry, ParticipationBits, ParticipationScope,
};
use arkret_wire::{CapabilityActionId, event_kind_str};
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use serde_json::{Value, json};

use super::capabilities::RealmMemberCapabilities;
use crate::components::SelfAttributionBadge;
use crate::operation::ak_ops;
use crate::state::{LocalStateStore, MoveSubmissionState, RawOperationRecord};
use crate::transport::auth::{authed_api_with_sync, with_authed_api};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::views::helpers::{active_sync_token, actor_display_label, short_protocol_id};

pub(super) mod admission;
mod controller;
mod effects;
mod model;

use controller::*;
use effects::use_realm_members_effects;
use model::*;

#[component]
fn MemberRowActions(
    controller: RealmMembersController,
    principal_id: String,
    selected_realm_id: String,
    target_id: String,
    target_label: String,
    can_remove: bool,
    is_self: bool,
    #[props(default)] leave_disabled_reason: Option<String>,
    mut block_confirm_id: Signal<Option<String>>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = crate::app::SessionContext::get().state_store;
    let mut status_msg = controller.status_msg;
    let token = controller.token;
    let write_context = RealmWriteContext {
        base_url: base_url.clone(),
        realm_id: selected_realm_id.clone(),
        actor_id: principal_id.clone(),
    };
    let leave_title = leave_disabled_reason
        .clone()
        .unwrap_or_else(|| crate::i18n::tr("realm_admin.leave_realm"));
    rsx! {
        div { class: "actions",
            if is_self {
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "member-row-leave-button",
                    disabled: leave_disabled_reason.is_some(),
                    title: "{leave_title}",
                    onclick: {
                        let context = write_context.clone();
                        let disabled_reason = leave_disabled_reason.clone();
                        move |_| {
                            if let Some(reason) = disabled_reason.clone() {
                                status_msg.set(reason);
                                return;
                            }
                            let mut context = context.clone();
                            context.actor_id = context.actor_id.trim().to_owned();
                            if context.actor_id.is_empty() {
                                status_msg.set("Leave Realm failed: account is not connected".to_owned());
                                return;
                            }
                            controller.dispatch(context, RealmMembersCommand::LeaveRealm);
                        }
                    },
                    {crate::i18n::tr("realm_admin.leave_realm")}
                }
            } else if can_remove {
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "kick-member-button",
                    onclick: {
                        let context = write_context.clone();
                        let target_id = target_id.clone();
                        let target_label = target_label.clone();
                        move |_| {
                            controller.dispatch(
                                context.clone(),
                                RealmMembersCommand::KickMember {
                                    target_id: target_id.clone(),
                                    target_label: target_label.clone(),
                                },
                            );
                        }
                    },
                    {crate::i18n::tr("realm_admin.kick_member")}
                }
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "ban-member-button",
                    onclick: {
                        let context = write_context.clone();
                        let target_id = target_id.clone();
                        let target_label = target_label.clone();
                        move |_| {
                            controller.dispatch(
                                context.clone(),
                                RealmMembersCommand::BanMember {
                                    target_id: target_id.clone(),
                                    target_label: target_label.clone(),
                                },
                            );
                        }
                    },
                    {crate::i18n::tr("realm_admin.ban_member")}
                }
            }
            if !is_self {
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "member-row-block-button",
                    onclick: {
                        let target = target_id.clone();
                        move |_| block_confirm_id.set(Some(target.clone()))
                    },
                    {crate::i18n::tr("member.block")}
                }
            }
        }
        if !is_self && block_confirm_id().as_deref() == Some(target_id.as_str()) {
            div {
                class: "event member-block-confirm",
                "data-testid": "block-user-confirm-modal",
                div { class: "entity-title", {crate::i18n::tr("member.block_confirm.title")} }
                div { class: "muted", title: "{target_id}", "{target_label}" }
                div { class: "muted", {crate::i18n::tr("member.block_confirm.body")} }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "block-user-confirm-button",
                        onclick: {
                            let target = target_id.clone();
                            let base = base_url.clone();
                            let target_label = target_label.clone();
                            move |_| {
                                let changed = state_store
                                    .write()
                                    .block_user(&target, None);
                                block_confirm_id.set(None);
                                if changed {
                                    status_msg.set(format!("Blocked {target_label}"));
                                    let entries = state_store
                                        .read()
                                        .client_blocklist();
                                    crate::views::settings::push_blocklist_account_data(
                                        base.clone(),
                                        token(),
                                        principal_id.clone(),
                                        state_store,
                                        entries,
                                    );
                                } else {
                                    status_msg.set(format!("{target_label} is already blocked"));
                                }
                            }
                        },
                        {crate::i18n::tr("member.block_confirm.confirm")}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "block-user-cancel-button",
                        onclick: move |_| block_confirm_id.set(None),
                        {crate::i18n::tr("common.cancel")}
                    }
                }
            }
        }
    }
}

#[component]
fn PendingInviteRow(
    profile: MemberProfile,
    controller: RealmMembersController,
    principal_id: String,
    selected_realm_id: String,
    can_cancel_invite: bool,
    can_revoke_invite: bool,
) -> Element {
    // A4 — base_url from session context instead of props.
    let mut status_msg = controller.status_msg;
    let write_context = RealmWriteContext {
        base_url: crate::app::SessionContext::base_url_string(),
        realm_id: selected_realm_id,
        actor_id: principal_id,
    };
    let member = profile.actor_id.clone();
    let member_label = profile.primary_label();
    let member_tier = profile.display_tier();
    let avatar_blob_ref = profile.avatar_blob_ref.as_ref().map(ToString::to_string);
    let invite_id = profile.invite_id.clone().unwrap_or_default();
    let invite_class_known = profile.invite_is_direct.is_some();
    // A direct invite's row is keyed by the invitee's complete ActorId (see
    // `pending_invite_profile`), so the closed account the cancel must name is
    // read back from that key; it is never rebuilt from a principal.
    let direct_invitee = profile
        .invite_is_direct
        .is_some_and(|direct| direct)
        .then(|| crate::mls_api_helpers::account_id_from_selector(&member))
        .flatten();
    let is_direct_invite = direct_invitee.is_some();
    let can_terminate_this_invite = invite_class_known
        && (if is_direct_invite {
            can_cancel_invite
        } else {
            can_revoke_invite
        })
        && !invite_id.trim().is_empty();
    let cancel_title = if can_terminate_this_invite {
        if is_direct_invite {
            "Cancel pending direct invite"
        } else {
            "Revoke pending token or 3PID invite"
        }
    } else {
        "Invite id is not available yet"
    };
    let state = profile
        .normalized_membership()
        .unwrap_or("invite")
        .to_owned();
    let state_label = match state.as_str() {
        "pending" | "pending_invite" => "Pending",
        _ => "Invitation sent",
    };
    let display_name = profile.display_name.clone().unwrap_or_default();
    let subject_id = profile.subject_id.clone().unwrap_or_default();
    let handles = profile.handles.clone();
    let member_identity_label = handles
        .first()
        .cloned()
        .unwrap_or_else(|| member_identity_fallback_label(&member));
    let show_member_identity =
        member_line_identity_visible(&member_identity_label, &member_label, &handles);
    let visible_handles = member_handles_for_line(&handles, &member_label);
    let handles_label = member_handles_line_label(&handles, &visible_handles);
    let subject_label = member_identity_fallback_label(&subject_id);
    rsx! {
        div {
            class: "event member-row member-pending-invite-row",
            "data-testid": "pending-invite-row",
            "data-member-id": "{member}",
            div { class: "event-head member-row-main",
                div {
                    class: "member-avatar member-avatar-pending",
                    title: "{member}",
                    crate::components::IdentityAvatar {
                        seed: member.clone(),
                        alt_text: member_label.clone(),
                        blob_ref: avatar_blob_ref.clone(),
                        class: "avatar-img member-avatar-image".to_owned(),
                    }
                }
                div { class: "member-row-text",
                    div { class: "member-row-title",
                        span {
                            class: "member-row-primary {member_tier.css_class()}",
                            "data-identity-tier": "{member_tier.css_class()}",
                            title: "{member}",
                            "{member_label}"
                        }
                        if let Some((badge, detail)) = member_tier.degraded_badge() {
                            span {
                                class: "badge muted identity-tier-badge",
                                "data-testid": "member-identity-tier",
                                title: "{detail}",
                                "{badge}"
                            }
                        }
                        span { class: "badge amber", "Pending invite" }
                    }
                    div { class: "muted member-row-sub member-profile-lines",
                        div { class: "member-profile-line",
                            span { "{state_label}" }
                            if show_member_identity {
                                span { title: "{member}", "{member_identity_label}" }
                            }
                        }
                        div { class: "member-profile-line",
                            span { class: "member-profile-label", "Member state" }
                            span { "{state}" }
                        }
                        if !display_name.is_empty() && display_name != member_label {
                            div { class: "member-profile-line",
                                span { class: "member-profile-label", "Display" }
                                span { "{display_name}" }
                            }
                        }
                        if !visible_handles.is_empty() {
                            div { class: "member-profile-line member-handle-list",
                                span { class: "member-profile-label", "{handles_label}" }
                                for handle in visible_handles.clone() {
                                    span { class: "member-handle-chip", "{handle}" }
                                }
                            }
                        }
                        if !subject_id.is_empty() && subject_id != member {
                            div { class: "member-profile-line",
                                span { class: "member-profile-label", "Subject" }
                                span { title: "{subject_id}", "{subject_label}" }
                            }
                        }
                    }
                }
            }
            div { class: "actions",
                if invite_class_known
                    && ((is_direct_invite && can_cancel_invite)
                        || (!is_direct_invite && can_revoke_invite))
                {
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "cancel-pending-invite-button",
                        disabled: !can_terminate_this_invite,
                        title: "{cancel_title}",
                        onclick: {
                            let context = write_context.clone();
                            let invite_id = invite_id.clone();
                            let member = member.clone();
                            let member_label = member_label.clone();
                            let direct_invitee = direct_invitee.clone();
                            move |_| {
                                if invite_id.trim().is_empty() {
                                    status_msg.set("invite id is not available yet".to_owned());
                                    return;
                                }
                                controller.dispatch(
                                    context.clone(),
                                    RealmMembersCommand::TerminatePendingInvite {
                                        invite_id: invite_id.clone(),
                                        member_id: member.clone(),
                                        member_label: member_label.clone(),
                                        direct_invitee: direct_invitee.clone(),
                                    },
                                );
                            }
                        },
                        {if is_direct_invite { "Cancel invite" } else { "Revoke invite" }}
                    }
                }
            }
        }
    }
}

#[component]
pub fn RealmMembersPanel(
    principal_id: String,
    token: Signal<String>,
    selected_realm_id: String,
    sync_cursor: Signal<String>,
    frontier_state: Signal<String>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let state_store = crate::app::SessionContext::get().state_store;
    let mut invite_target = use_signal(String::new);
    let mut status_msg = use_signal(String::new);
    let mut members = use_signal(Vec::<MemberProfile>::new);
    let owned_agents = use_signal(Vec::<MemberAgentRow>::new);
    let agent_behavior_pending = use_signal(BTreeSet::<String>::new);
    let block_confirm_id = use_signal(|| Option::<String>::None);
    let permissions = use_signal(RealmMemberCapabilities::default);
    let mut member_roster_section = use_signal(|| MemberRosterSection::Members);
    // Invite is now a modal launched from the list header "+" button.
    let mut invite_modal_open = use_signal(|| false);
    let mut agent_add_modal_open = use_signal(|| false);
    // Client-side member search + incremental paging. `member_filter`
    // narrows the projected roster; `member_visible` caps how many rows we
    // actually mount so a 10k-member Realm doesn't render 10k DOM nodes.
    let mut member_filter = use_signal(String::new);
    let mut member_visible = use_signal(|| MEMBER_PAGE_SIZE);
    // U3 - "Add from contacts" picker state. `invite_contacts` holds the user's
    // accepted contacts (lazily loaded when the modal opens); `selected_contacts`
    // is the multi-select set of DIDs to invite via the consent-grant path.
    let invite_contacts = use_signal(Vec::<crate::models::ContactListRow>::new);
    let invite_contacts_loaded = use_signal(|| false);
    let invite_contacts_status = use_signal(String::new);
    let mut selected_contacts = use_signal(std::collections::BTreeSet::<String>::new);

    // Every membership write goes through this one bundle, so the rsx below
    // only decides which command runs and never how it is submitted.
    let controller = RealmMembersController {
        token,
        status_msg,
        sync_cursor,
        frontier_state,
        members,
        invite_target,
        invite_modal_open,
        agent_add_modal_open,
        selected_contacts,
        owned_agents,
        permissions,
        invite_contacts,
        invite_contacts_loaded,
        invite_contacts_status,
        state_store,
    };
    let write_context = RealmWriteContext {
        base_url: base_url.clone(),
        realm_id: selected_realm_id.clone(),
        actor_id: principal_id.clone(),
    };

    use_realm_members_effects(
        controller,
        base_url.clone(),
        principal_id.clone(),
        selected_realm_id.clone(),
    );

    let member_permissions = permissions();
    let can_invite = member_permissions.can_invite;
    let can_cancel_invite = member_permissions.can_cancel_invite;
    let can_revoke_invite = member_permissions.can_revoke_invite;
    let can_remove = member_permissions.can_remove;

    let selected_section = member_roster_section();
    let RealmRosterView {
        visible_groups,
        visible_pending_invites,
        member_set,
        self_realm_agent_rows,
        available_self_agent_rows,
        total_members,
        total_owner_members,
        total_admin_members,
        total_regular_members,
        total_pending_invites,
        pending_invite_match_count,
        filtered_count,
        visible,
        has_more,
        show_search,
        selected_section_total,
        selected_section_visible_count,
        selected_section_empty,
        self_leave_disabled_reason,
        filter_query,
    } = build_realm_roster(RealmRosterInput {
        members: members(),
        owned_agents: owned_agents(),
        principal_id: &principal_id,
        section: selected_section,
        query: &member_filter(),
        visible_limit: member_visible(),
    });
    let selected_section_title = selected_section.title();
    let selected_section_description = selected_section.description();
    let members_section_class = MemberRosterSection::Members.menu_item_class(selected_section);
    let owners_section_class = MemberRosterSection::Owners.menu_item_class(selected_section);
    let admins_section_class = MemberRosterSection::Admins.menu_item_class(selected_section);
    let my_agents_section_class = MemberRosterSection::MyAgents.menu_item_class(selected_section);
    let pending_section_class =
        MemberRosterSection::PendingInvites.menu_item_class(selected_section);
    // Icon buttons carry their label via title/aria-label instead of text.
    let refresh_label = crate::i18n::tr("realm_admin.refresh_members");

    rsx! {
            div { class: "timeline", "data-testid": "realm-members-panel",
                if selected_section == MemberRosterSection::MyAgents && agent_add_modal_open() {
                    crate::components::DismissiblePopup {
                        overlay_class: "modal-backdrop",
                        surface_class: "modal invite-modal",
                        overlay_test_id: Some("add-realm-agent-modal".to_owned()),
                        aria_label: "Add agent to Realm",
                        on_dismiss: move |_| agent_add_modal_open.set(false),
                        div { class: "modal-head",
                            h3 { "Add agent to Realm" }
                            Button {
                                variant: ButtonVariant::Secondary,
                                class: "icon-button close",
                                "aria-label": "Close",
                                "data-testid": "add-realm-agent-modal-close",
                                onclick: move |_| agent_add_modal_open.set(false),
                                "\u{2715}"
                            }
                        }
                        div { class: "modal-body workflow-form",
                            p { class: "muted",
                                "Choose one of your active agents. It joins immediately under your control and does not receive an invitation."
                            }
                            if available_self_agent_rows.is_empty() {
                                div { class: "members-empty compact", "data-testid": "available-realm-agents-empty",
                                    div { class: "members-empty-icon", crate::components::UiIcon { name: "bot" } }
                                    div { class: "members-empty-title", "No agents available to add." }
                                    div { class: "muted members-empty-hint", "Create or activate an agent in Settings, or remove an existing agent from this Realm first." }
                                }
                            } else {
                                div { class: "member-self-agent-list", "data-testid": "available-realm-agent-list",
                                    for available_agent in available_self_agent_rows.clone() {
                                        {
                                            let agent_id = available_agent.agent_id.clone();
                                            let agent_title = available_agent.display_name.clone();
                                            let status_class = crate::views::agents::agent_state_badge_class(&available_agent.status);
                                            let status_label = crate::views::agents::agent_state_label(&available_agent.status).to_owned();
                                            rsx! {
                                                div { class: "member-self-agent-row", "data-testid": "available-realm-agent-row", "data-agent-id": "{agent_id}",
                                                    div { class: "member-agent-summary",
                                                        div { class: "member-avatar member-avatar-agent",
                                                            crate::components::IdentityAvatar {
                                                                seed: agent_id.clone(),
                                                                alt_text: agent_title.clone(),
                                                                class: "avatar-img member-avatar-image".to_owned(),
                                                            }
                                                        }
                                                        div { class: "member-row-text",
                                                            div { class: "member-row-title",
                                                                span { title: "{agent_id}", "{agent_title}" }
                                                                span { class: "{status_class}", "{status_label}" }
                                                                if !available_agent.slug.is_empty() {
                                                                    span { class: "badge", "{available_agent.slug}" }
                                                                }
                                                            }
                                                            div { class: "muted member-row-sub mono", title: "{agent_id}", "{short_protocol_id(&agent_id)}" }
                                                        }
                                                    }
                                                    Button {
                                                        variant: ButtonVariant::Primary,
                                                        size: ButtonSize::Sm,
                                                        "data-testid": "confirm-add-agent-to-realm",
                                                        onclick: {
                                                            let context = write_context.clone();
                                                            let target_id = owned_agent_actor_key(&agent_id).unwrap_or_default();
                                                            let target_label = agent_title.clone();
                                                            move |_| {
                                                                controller.dispatch(
                                                                    context.clone(),
                                                                    RealmMembersCommand::AddOwnedAgent {
                                                                        target_id: target_id.clone(),
                                                                        target_label: target_label.clone(),
                                                                    },
                                                                );
                                                            }
                                                        },
                                                        "Add"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if can_invite && invite_modal_open() {
                    crate::components::DismissiblePopup {
                        overlay_class: "modal-backdrop",
                        surface_class: "modal invite-modal",
                        overlay_test_id: Some("invite-member-modal".to_owned()),
                        aria_label: "Invite member",
                        on_dismiss: move |_| invite_modal_open.set(false),
                            div { class: "modal-head",
                                h3 { "Invite member" }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    class: "icon-button close",
                                    "aria-label": "Close",
                                    "data-testid": "invite-modal-close",
                                    onclick: move |_| invite_modal_open.set(false),
                                    "\u{2715}"
                                }
                            }
                            div { class: "modal-body workflow-form",
                                // Pull existing contacts into the Realm through the
                                // independent directional Contact invite scope.
                                div { class: "invite-from-contacts", "data-testid": "realm-invite-from-contacts",
                                    div { class: "event-head",
                                        span { {crate::i18n::tr("realm_admin.invite_from_contacts")} }
                                        span { {crate::i18n::tr("realm_admin.invite_recommended")} }
                                    }
                                    if !invite_contacts_status().is_empty() {
                                        div { class: "muted", "data-testid": "realm-invite-contacts-status", "{invite_contacts_status}" }
                                    }
                                    if !invite_contacts.read().is_empty() {
                                        div { class: "settings-list",
                                            for contact in invite_contacts.read().clone() {
                                                {
                                                    let peer_actor = contact.peer.contact_actor_id();
                                                    let did = peer_actor.to_string();
                                                    let did_label = actor_display_label(&state_store.read(), peer_actor.signing_principal_id().as_str());
                                                    let checked = selected_contacts.read().contains(&did);
                                                    let eligible =
                                                        crate::models::contact_grants_me_invite(&contact);
                                                    let usable = eligible && peer_actor.as_account_id().is_some();
                                                    let not_authorized = !usable;
                                                    let did_for_toggle = did.clone();
                                                    rsx! {
                                                        label {
                                                            class: "metric invite-contact-row",
                                                            "data-testid": "realm-invite-contact-{did}",
                                                            "data-eligible": "{usable}",
                                                            Checkbox {
                                                                checked: if checked { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                                                disabled: !usable,
                                                                on_checked_change: move |state: CheckboxState| {
                                                                    let mut next = selected_contacts.read().clone();
                                                                    if bool::from(state) {
                                                                        next.insert(did_for_toggle.clone());
                                                                    } else {
                                                                        next.remove(&did_for_toggle);
                                                                    }
                                                                    selected_contacts.set(next);
                                                                },
                                                            }
                                                            span { title: "{did}", " {did_label}" }
                                                            if not_authorized {
                                                                span {
                                                                    class: "badge",
                                                                    "data-testid": "realm-invite-contact-unauthorized-{did}",
                                                                    {crate::i18n::tr("realm_admin.invite_unauthorized")}
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        div { class: "actions",
                                            Button {
                                                variant: ButtonVariant::Primary,
                                                "data-testid": "realm-invite-send",
                                                disabled: selected_contacts.read().is_empty(),
                                                    onclick: {
                                                        let context = write_context.clone();
                                                        move |_| {
                                                            // Resolve the destination pairs up front so
                                                            // the async task does not borrow the
                                                            // rendered rows.
                                                            let targets: Vec<arkret_sdk::AccountId> = invite_contacts
                                                                .read()
                                                                .iter()
                                                                .filter(|c| selected_contacts.read().contains(&c.peer.contact_actor_id().to_string()))
                                                                .filter(|c| crate::models::contact_grants_me_invite(c))
                                                                .filter_map(|c| c.peer.contact_actor_id().as_account_id().cloned())
                                                                .collect();
                                                            if targets.is_empty() {
                                                                status_msg.set(crate::i18n::tr("realm_admin.invite_none_eligible"));
                                                                return;
                                                            }
                                                            status_msg.set(
                                                                crate::i18n::tr("realm_admin.invite_sending")
                                                                    .replace("{total}", &targets.len().to_string()),
                                                            );
                                                            controller.dispatch(
                                                                context.clone(),
                                                                RealmMembersCommand::InviteContacts { targets },
                                                            );
                                                        }
                                                    },
                                                {crate::i18n::tr("realm_admin.invite_selected")}
                                            }
                                        }
                                    }
                                }

                                div { class: "invite-divider muted", "data-testid": "realm-invite-divider", {crate::i18n::tr("realm_admin.invite_divider")} }

                                div { class: "invite-by-handle", "data-testid": "realm-invite-by-handle",
                                    div { class: "event-head",
                                        span { {crate::i18n::tr("realm_admin.invite_by_handle")} }
                                        span { {crate::i18n::tr("realm_admin.invite_handle_opt_in")} }
                                    }
                                    Label { html_for: "invite-target-input", {crate::i18n::tr("realm_admin.invite_target_label")} }
                                    Input {
                                        id: "invite-target-input",
                                        "data-testid": "invite-target-input",
                                        value: "{invite_target}",
                                        placeholder: "alice:example.com",
                                        oninput: move |event: FormEvent| invite_target.set(event.value()),
                                    }
                                    div { class: "muted members-invite-hint",
                                        {crate::i18n::tr("realm_admin.invite_hint")}
                                    }
                                }
                            }
                            div { class: "modal-foot",
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "invite-modal-cancel",
                                    onclick: move |_| invite_modal_open.set(false),
                                    "Cancel"
                                }
                                Button {
                                    variant: ButtonVariant::Primary,
                                    "data-testid": "send-invite-button",
                                    onclick: {
                                        let context = write_context.clone();
                                        move |_| {
                                            let target = invite_target().trim().to_owned();
                                            if target.is_empty() {
                                                status_msg.set("invite target is required".to_owned());
                                                return;
                                            }
                                            controller.dispatch(
                                                context.clone(),
                                                RealmMembersCommand::InviteResolvedTarget {
                                                    target,
                                                    wait_for: active_sync_token(sync_cursor()),
                                                },
                                            );
                                        }
                                    },
                                    "Send Invite"
                                }
                            }
                    }
                }

                div { class: "event member-list-card", "data-testid": "member-table",
                    div { class: "event-head",
                        span { "Members" }
                        div { class: "member-head-actions",
                            span {
                                class: "badge member-count-badge",
                                "data-testid": "realm-members-count",
                                "{total_members}"
                            }
                            if total_pending_invites > 0 {
                                span {
                                    class: "badge member-pending-count-badge",
                                    "data-testid": "realm-pending-invite-count",
                                    "{total_pending_invites} pending"
                                }
                            }
                            if selected_section == MemberRosterSection::MyAgents {
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    size: ButtonSize::Sm,
                                    class: "member-head-icon-btn-accent",
                                    "data-testid": "open-add-realm-agent-modal-button",
                                    title: "Add one of my agents",
                                    "aria-label": "Add agent to Realm",
                                    onclick: move |_| agent_add_modal_open.set(true),
                                    crate::components::UiIcon { name: "plus" }
                                    "Add agent"
                                }
                            } else if can_invite {
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    size: ButtonSize::IconSm,
                                    class: "member-head-icon-btn member-head-icon-btn-accent",
                                    "data-testid": "open-invite-modal-button",
                                    title: "Invite member",
                                    "aria-label": "Invite member",
                                    onclick: move |_| invite_modal_open.set(true),
                                    crate::components::UiIcon { name: "plus" }
                                }
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                size: ButtonSize::IconSm,
                                class: "member-head-icon-btn",
                                "data-testid": "refresh-members-button",
                                title: "{refresh_label}",
                                "aria-label": "{refresh_label}",
                                onclick: {
                                    let realm = selected_realm_id.clone();
                                    move |_| {
                                        let store = state_store.read();
                                        let next = projected_member_profiles_for_realm(&store, &realm);
                                        let count = next.len();
                                        members.set(next);
                                        member_visible.set(MEMBER_PAGE_SIZE);
                                        status_msg.set(format!(
                                            "members refreshed ({count}) from local sync state"
                                        ));
                                    }
                                },
                                crate::components::UiIcon { name: "refresh" }
                            }
                        }
                    }
                    if !status_msg().is_empty() {
                        div { class: "muted", "data-testid": "realm-members-status", "{status_msg()}" }
                    }
                    if member_permissions.loaded
                        && !can_invite
                        && !can_cancel_invite
                        && !can_revoke_invite
                        && !can_remove
                    {
                        div {
                            class: "muted",
                            "data-testid": "realm-member-actions-hidden",
                            "Member-management actions are not available for this account."
                        }
                    }
                    if show_search {
                        Input {
                            class: "member-search-input",
                            "data-testid": "member-search-input",
                            value: "{member_filter}",
                            placeholder: "Search members…",
                            oninput: move |event: FormEvent| {
                                member_filter.set(event.value());
                                member_visible.set(MEMBER_PAGE_SIZE);
                            },
                        }
                    }
                    div { class: "members-admin-layout",
                        nav { class: "members-admin-menu", "aria-label": "Member sections",
                            button {
                                class: "{members_section_class}",
                                "data-testid": "members-section-members",
                                onclick: move |_| {
                                    member_roster_section.set(MemberRosterSection::Members);
                                    member_visible.set(MEMBER_PAGE_SIZE);
                                },
                                span { "Members" }
                                span { class: "badge", "{total_regular_members}" }
                            }
                            button {
                                class: "{owners_section_class}",
                                "data-testid": "members-section-owners",
                                onclick: move |_| {
                                    member_roster_section.set(MemberRosterSection::Owners);
                                    member_visible.set(MEMBER_PAGE_SIZE);
                                },
                                span { "Owners" }
                                span { class: "badge", "{total_owner_members}" }
                            }
                            button {
                                class: "{admins_section_class}",
                                "data-testid": "members-section-admins",
                                onclick: move |_| {
                                    member_roster_section.set(MemberRosterSection::Admins);
                                    member_visible.set(MEMBER_PAGE_SIZE);
                                },
                                span { "Admins" }
                                span { class: "badge", "{total_admin_members}" }
                            }
                            button {
                                class: "{my_agents_section_class}",
                                "data-testid": "members-section-my-agents",
                                onclick: move |_| {
                                    member_roster_section.set(MemberRosterSection::MyAgents);
                                    member_filter.set(String::new());
                                    member_visible.set(MEMBER_PAGE_SIZE);
                                },
                                span { "My agents" }
                                span { class: "badge", "{self_realm_agent_rows.len()}" }
                            }
                            button {
                                class: "{pending_section_class}",
                                "data-testid": "members-section-pending-invites",
                                onclick: move |_| {
                                    member_roster_section.set(MemberRosterSection::PendingInvites);
                                    member_visible.set(MEMBER_PAGE_SIZE);
                                },
                                span { "Pending invites" }
                                span { class: "badge member-pending-count-badge", "{total_pending_invites}" }
                            }
                        }
                        div { class: "members-admin-content",
                            div { class: "member-section-head",
                                div {
                                    div { class: "entity-title", "{selected_section_title}" }
                                    div { class: "muted", "{selected_section_description}" }
                                }
                                span {
                                    class: "badge member-count-badge",
                                    "data-testid": "member-section-visible-count",
                                    "{selected_section_visible_count} shown"
                                }
                            }
                            if selected_section == MemberRosterSection::PendingInvites {
                                div {
                                    class: "member-pending-invites",
                                    "data-testid": "pending-invites-list",
                                    if pending_invite_match_count == 0 {
                                        div {
                                            class: "muted member-pending-invite-empty",
                                            "data-testid": "pending-invites-no-match",
                                            "No pending invites match your search."
                                        }
                                    }
                                    for invite in visible_pending_invites {
                                        PendingInviteRow {
                                            profile: invite.clone(),
                                            controller,
                                            principal_id: principal_id.clone(),
                                            selected_realm_id: selected_realm_id.clone(),
                                            can_cancel_invite,
                                            can_revoke_invite,
                                        }
                                    }
                                }
                            }
                    for group in visible_groups {
                        {
                            let member_profile = group.controller.clone();
                            let member = member_profile.actor_id.clone();
                            let member_label = member_profile.primary_label();
                            let public_label = member_profile.public_label();
                            let member_tier = member_profile.display_tier();
                            let is_self = is_local_account_actor(&member, &principal_id);
                            let has_agents = !group.agents.is_empty();
                            let group_class = if has_agents {
                                "member-group has-agents"
                            } else {
                                "member-group"
                            };
                            let avatar_blob_ref = member_profile
                                .avatar_blob_ref
                                .as_ref()
                                .map(ToString::to_string);
                            let role_label = member_profile.role_label();
                            let remark_name = member_profile.remark_name.clone().unwrap_or_default();
                            let remark_note = member_profile.remark_note.clone().unwrap_or_default();
                            let display_name = member_profile.display_name.clone().unwrap_or_default();
                            let subject_id = member_profile.subject_id.clone().unwrap_or_default();
                            let handles = member_profile.handles.clone();
                            let member_identity_label = handles
                                .first()
                                .cloned()
                                .unwrap_or_else(|| member_identity_fallback_label(&member));
                            let show_member_identity =
                                member_line_identity_visible(&member_identity_label, &member_label, &handles);
                            let visible_handles = member_handles_for_line(&handles, &member_label);
                            let handles_label = member_handles_line_label(&handles, &visible_handles);
                            let subject_label = member_identity_fallback_label(&subject_id);
                            let self_leave_reason = if is_self {
                                self_leave_disabled_reason.clone()
                            } else {
                                None
                            };
                            rsx! {
                                div {
                                    class: "{group_class}",
                                    "data-testid": "member-group",
                                    "data-controller-principal-id": "{member}",
                                    if selected_section != MemberRosterSection::MyAgents {
                                    div { class: "event member-row member-controller-row", "data-testid": "member-row", "data-member-id": "{member}",
                                        div { class: "event-head member-row-main",
                                            if is_self {
                                                div {
                                                    class: "member-avatar",
                                                    "data-testid": "member-self-avatar",
                                                    title: "{member}",
                                                    crate::components::IdentityAvatar {
                                                        seed: member.clone(),
                                                        alt_text: member_label.clone(),
                                                        blob_ref: avatar_blob_ref.clone(),
                                                        class: "avatar-img member-avatar-image".to_owned(),
                                                    }
                                                }
                                            } else {
                                                div {
                                                    class: "member-avatar",
                                                    "data-testid": "member-avatar",
                                                    title: "{member}",
                                                    crate::components::IdentityAvatar {
                                                        seed: member.clone(),
                                                        alt_text: member_label.clone(),
                                                        blob_ref: avatar_blob_ref.clone(),
                                                        class: "avatar-img member-avatar-image".to_owned(),
                                                    }
                                                }
                                            }
                                            div { class: "member-row-text",
                                                div { class: "member-row-title",
                                                    span {
                                                        class: "member-row-primary {member_tier.css_class()}",
                                                        "data-identity-tier": "{member_tier.css_class()}",
                                                        title: "{member}",
                                                        "{member_label}"
                                                    }
                                                    if let Some((badge, detail)) = member_tier.degraded_badge() {
                                                        span {
                                                            class: "badge muted identity-tier-badge",
                                                            "data-testid": "member-identity-tier",
                                                            title: "{detail}",
                                                            "{badge}"
                                                        }
                                                    }
                                                    if is_self {
                                                        SelfAttributionBadge {
                                                            class: Some("member-you-badge".to_owned()),
                                                            test_id: Some("member-self-badge".to_owned()),
                                                        }
                                                    }
                                                    if member_profile.is_owner {
                                                        span { class: "badge amber", "Owner" }
                                                    } else if member_profile.is_admin {
                                                        span { class: "badge blue", "Admin" }
                                                    }
                                                    if member_profile.confusable_contact_warning {
                                                        span {
                                                            class: "badge amber",
                                                            "data-testid": "member-contact-confusable-warning",
                                                            title: "{crate::i18n::tr(\"contacts.petname.confusable_warning_detail\")}",
                                                            {crate::i18n::tr("contacts.petname.confusable_warning")}
                                                        }
                                                    }
                                                    if !is_self && has_agents {
                                                        span {
                                                            class: "badge blue",
                                                            "data-testid": "member-agent-count",
                                                            "{group.agents.len()} AI"
                                                        }
                                                    }
                                                }
                                                div { class: "muted member-row-sub member-profile-lines",
                                                    div { class: "member-profile-line",
                                                        span { "{role_label}" }
                                                        if show_member_identity {
                                                            span { title: "{member}", "{member_identity_label}" }
                                                        }
                                                    }
                                                    if !remark_name.is_empty() && remark_name != public_label {
                                                        div { class: "member-profile-line",
                                                            span { class: "member-profile-label", "My name" }
                                                            span { "{remark_name}" }
                                                        }
                                                    }
                                                    if !display_name.is_empty() && display_name != member_label {
                                                        div { class: "member-profile-line",
                                                            span { class: "member-profile-label", "Display" }
                                                            span { "{display_name}" }
                                                        }
                                                    }
                                                    if !visible_handles.is_empty() {
                                                        div { class: "member-profile-line member-handle-list",
                                                            span { class: "member-profile-label", "{handles_label}" }
                                                            for handle in visible_handles.clone() {
                                                                span { class: "member-handle-chip", "{handle}" }
                                                            }
                                                        }
                                                    }
                                                    if !remark_note.is_empty() {
                                                        div { class: "member-profile-line",
                                                            span { class: "member-profile-label", "Note" }
                                                            span { "{remark_note}" }
                                                        }
                                                    }
                                                    if !subject_id.is_empty() && subject_id != member {
                                                        div { class: "member-profile-line",
                                                            span { class: "member-profile-label", "Subject" }
                                                            span { title: "{subject_id}", "{subject_label}" }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        MemberRowActions {
                                            controller,
                                            principal_id: principal_id.clone(),
                                            selected_realm_id: selected_realm_id.clone(),
                                            target_id: member.clone(),
                                            target_label: member_label.clone(),
                                            can_remove,
                                            is_self,
                                            leave_disabled_reason: self_leave_reason,
                                            block_confirm_id,
                                        }
                                    }
                                    }
                                    if is_self && selected_section == MemberRosterSection::MyAgents {
                                        div { class: "member-self-agent-settings", "data-testid": "member-self-agent-settings",
                                            div { class: "member-self-agent-settings-head",
                                                div {
                                                    div { class: "entity-title", "AI agents" }
                                                    div { class: "muted", "Your agents that are members of this Realm." }
                                                }
                                                span { class: "badge", "{self_realm_agent_rows.len()} total" }
                                            }
                                            if self_realm_agent_rows.is_empty() {
                                                div { class: "members-empty compact", "data-testid": "member-self-agent-empty",
                                                    div { class: "members-empty-icon", crate::components::UiIcon { name: "bot" } }
                                                    div { class: "members-empty-title", "No agents in this Realm." }
                                                    div { class: "muted members-empty-hint", "Add one of your existing active agents. No invitation or agent approval is required." }
                                                    Button {
                                                        variant: ButtonVariant::Primary,
                                                        size: ButtonSize::Sm,
                                                        "data-testid": "member-agent-empty-add",
                                                        onclick: move |_| agent_add_modal_open.set(true),
                                                        "Add agent"
                                                    }
                                                }
                                            } else {
                                                div { class: "member-self-agent-list",
                                                    for owned_agent in self_realm_agent_rows.clone() {
                                                        {
                                                            let agent_in_realm = owned_agent_actor_key(&owned_agent.agent_id).is_some_and(|key| member_set.contains(&key));
                                                            let policy = owned_agent.mention_policy;
                                                            let policy_class = policy.badge_class();
                                                            let policy_label = policy.label();
                                                            let agent_id = owned_agent.agent_id.clone();
                                                            let agent_title = owned_agent.display_name.clone();
                                                            let status_class = crate::views::agents::agent_state_badge_class(&owned_agent.status);
                                                            let status_label = crate::views::agents::agent_state_label(&owned_agent.status).to_owned();
                                                            let can_enable = agent_in_realm && !agent_behavior_pending.read().contains(&agent_id);
                                                            let can_remove_agent = agent_in_realm;
                                                            rsx! {
                                                                div { class: "member-self-agent-row", "data-testid": "member-self-agent-row", "data-agent-id": "{agent_id}",
                                                                    div { class: "member-agent-summary",
                                                                        div { class: "member-avatar member-avatar-agent",
                                                                            crate::components::IdentityAvatar {
                                                                                seed: agent_id.clone(),
                                                                                alt_text: agent_title.clone(),
                                                                                class: "avatar-img member-avatar-image".to_owned(),
                                                                            }
                                                                        }
                                                                        div { class: "member-row-text",
                                                                            div { class: "member-row-title",
                                                                                span { title: "{agent_id}", "{agent_title}" }
                                                                                span { class: "{status_class}", "{status_label}" }
                                                                                if !owned_agent.slug.is_empty() {
                                                                                    span { class: "badge", "{owned_agent.slug}" }
                                                                                }
                                                                            }
                                                                            div { class: "muted member-row-sub mono", title: "{agent_id}", "{short_protocol_id(&agent_id)}" }
                                                                        }
                                                                    }
                                                                    div { class: "member-self-agent-actions",
                                                                        if agent_in_realm {
                                                                            span { class: "badge green", "in Realm" }
                                                                            span { class: "{policy_class}", "data-testid": "member-agent-mention-policy", "{policy_label}" }
                                                                            if can_remove_agent {
                                                                                Button {
                                                                                    variant: ButtonVariant::Secondary,
                                                                                    size: ButtonSize::Sm,
                                                                                    "data-testid": "member-agent-remove-from-realm",
                                                                                    onclick: {
                                                                                        let context = write_context.clone();
                                                                                        let target_id = owned_agent_actor_key(&agent_id).unwrap_or_default();
                                                                                        let target_label = agent_title.clone();
                                                                                        move |_| {
                                                                                            controller.dispatch(
                                                                                                context.clone(),
                                                                                                RealmMembersCommand::RemoveOwnedAgent {
                                                                                                    target_id: target_id.clone(),
                                                                                                    target_label: target_label.clone(),
                                                                                                },
                                                                                            );
                                                                                        }
                                                                                        },
                                                                                    "Remove"
                                                                                }
                                                                            }
                                                                            div { class: "member-agent-realm-behavior", "data-testid": "member-agent-realm-behavior",
                                                                                label { class: "member-agent-behavior-toggle",
                                                                                    Checkbox {
                                                                                        "data-testid": "member-agent-reply-toggle",
                                                                                        checked: if owned_agent.selection.reply_message { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                                                                        disabled: !can_enable,
                                                                                        on_checked_change: {
                                                                                            let base = base_url.clone();
                                                                                            let realm = selected_realm_id.clone();
                                                                                            let agent_id = agent_id.clone();
                                                                                            let previous = owned_agent.selection;
                                                                                            move |state: CheckboxState| {
                                                                                                spawn_set_agent_realm_behavior(
                                                                                                    base.clone(), token(), realm.clone(), agent_id.clone(),
                                                                                                    ParticipationBits { reply_message: bool::from(state), ..previous },
                                                                                                    owned_agents, status_msg, agent_behavior_pending,
                                                                                                );
                                                                                            }
                                                                                        },
                                                                                    }
                                                                                    span { "Reply as agent" }
                                                                                }
                                                                                label { class: "member-agent-behavior-toggle",
                                                                                    Checkbox {
                                                                                        "data-testid": "member-agent-mention-toggle",
                                                                                        checked: if owned_agent.selection.accept_third_party_mention { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                                                                        disabled: !can_enable,
                                                                                        on_checked_change: {
                                                                                            let base = base_url.clone();
                                                                                            let realm = selected_realm_id.clone();
                                                                                            let agent_id = agent_id.clone();
                                                                                            let previous = owned_agent.selection;
                                                                                            move |state: CheckboxState| {
                                                                                                spawn_set_agent_realm_behavior(
                                                                                                    base.clone(), token(), realm.clone(), agent_id.clone(),
                                                                                                    ParticipationBits { accept_third_party_mention: bool::from(state), ..previous },
                                                                                                    owned_agents, status_msg, agent_behavior_pending,
                                                                                                );
                                                                                            }
                                                                                        },
                                                                                    }
                                                                                    span { "Accept @mentions" }
                                                                                }
                                                                                label { class: "member-agent-behavior-toggle",
                                                                                    Checkbox {
                                                                                        "data-testid": "member-agent-act-on-behalf-toggle",
                                                                                        checked: if owned_agent.selection.act_on_behalf { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                                                                        disabled: !can_enable,
                                                                                        on_checked_change: {
                                                                                            let base = base_url.clone();
                                                                                            let realm = selected_realm_id.clone();
                                                                                            let agent_id = agent_id.clone();
                                                                                            let previous = owned_agent.selection;
                                                                                            move |state: CheckboxState| {
                                                                                                spawn_set_agent_realm_behavior(
                                                                                                    base.clone(), token(), realm.clone(), agent_id.clone(),
                                                                                                    ParticipationBits { act_on_behalf: bool::from(state), ..previous },
                                                                                                    owned_agents, status_msg, agent_behavior_pending,
                                                                                                );
                                                                                            }
                                                                                        },
                                                                                    }
                                                                                    span { "Act on my behalf" }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                }
                                            }
                                        }
                                    }
                                    if !is_self && has_agents {
                                        div { class: "member-agent-list", "data-testid": "member-agent-list",
                                            span { class: "member-profile-label", "AI agents:" }
                                            for agent in group.agents {
                                                {
                                                    let agent_id = agent.agent_id.clone();
                                                    let agent_label = agent.display_name.clone();
                                                    rsx! {
                                                        span {
                                                            class: "member-agent-chip",
                                                            "data-testid": "member-agent-chip",
                                                            title: "{agent_id}",
                                                            "{agent_label}"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if selected_section_empty
                        && selected_section != MemberRosterSection::PendingInvites
                        && selected_section != MemberRosterSection::MyAgents
                    {
                        div { class: "members-empty", "data-testid": "members-empty-state",
                            if selected_section_total == 0 && filter_query.is_empty() {
                                div { class: "members-empty-icon", crate::components::UiIcon { name: "users" } }
                                div { class: "members-empty-title", {crate::i18n::tr("realm_admin.no_members_loaded")} }
                                if can_invite {
                                    div { class: "muted members-empty-hint",
                                        {crate::i18n::tr("realm_admin.members_empty_hint")}
                                    }
                                }
                            } else {
                                div { class: "members-empty-icon", crate::components::UiIcon { name: "search" } }
                                div { class: "members-empty-title", {crate::i18n::tr("realm_admin.members_no_match")} }
                            }
                        }
                    }
                    if has_more {
                        div { class: "member-load-more",
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "load-more-members-button",
                                onclick: move |_| {
                                    let next = member_visible() + MEMBER_PAGE_SIZE;
                                    member_visible.set(next);
                                },
                                "Load more — showing {visible} of {filtered_count} groups"
                            }
                        }
                    }
                        }
                    }
                }

            }
        }
    }
}

#[cfg(test)]
#[path = "members_panel/tests.rs"]
mod tests;
