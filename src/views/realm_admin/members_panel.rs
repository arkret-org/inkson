use std::collections::{BTreeMap, BTreeSet};

use cokret_sdk::models::{AgentParticipation, AgentParticipationEntry, AgentParticipationScope};
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use serde_json::{Value, json};

use super::metadata::projected_members_for_realm;
use super::permissions::{RealmMemberPermissions, authz_json_allowed};
use crate::local_state::{LocalStateStore, MoveSubmissionState};
use crate::operation::ck_ops;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::views::helpers::{active_sync_token, authed_api_with_sync, short_protocol_id};

/// Number of member rows the list renders per page. The member list is
/// hydrated from the full local sync projection (which can hold tens of
/// thousands of entries for a large Realm), so we never mount every row
/// at once — we render this many and reveal more on demand. Keeps the DOM
/// node count bounded regardless of Realm size, mirroring how Telegram
/// pages its participant list rather than materializing the whole roster.
const MEMBER_PAGE_SIZE: usize = 50;

/// Once a Realm has more than this many members the inline search box is
/// shown. Below it, scanning the list by eye is faster than typing.
const MEMBER_SEARCH_THRESHOLD: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgentMentionPolicy {
    Allowed,
    OwnerOnly,
    Unknown,
}

impl AgentMentionPolicy {
    fn label(self) -> &'static str {
        match self {
            Self::Allowed => "普通成员可 @",
            Self::OwnerOnly => "仅主人 @",
            Self::Unknown => "@ 权限未知",
        }
    }

    fn badge_class(self) -> &'static str {
        match self {
            Self::Allowed => "badge green",
            Self::OwnerOnly => "badge amber",
            Self::Unknown => "badge",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct MemberAgentRow {
    agent_principal_id: String,
    controller_did: String,
    display_name: String,
    agent_slug: String,
    status: String,
    mention_policy: AgentMentionPolicy,
    selection: AgentParticipation,
}

#[derive(Clone, Debug, PartialEq)]
struct MemberGroup {
    controller_did: String,
    agents: Vec<MemberAgentRow>,
}

fn agent_projection_value(row: &Value) -> &Value {
    row.get("agent").unwrap_or(row)
}

fn member_agent_row_from_value(
    row: Value,
    fallback_controller_did: &str,
) -> Option<MemberAgentRow> {
    let projection = agent_projection_value(&row);
    let agent_principal_id = projection
        .get("agent_principal_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?
        .to_owned();
    let display_name = projection
        .get("display_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| short_protocol_id(&agent_principal_id));
    let agent_slug = projection
        .get("agent_slug")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    let status = row
        .get("status")
        .or_else(|| projection.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("active")
        .to_owned();
    let controller_did = row
        .get("controller_did")
        .or_else(|| projection.get("controller_did"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| fallback_controller_did.trim().to_owned());
    Some(MemberAgentRow {
        agent_principal_id,
        controller_did,
        display_name,
        agent_slug,
        status,
        mention_policy: AgentMentionPolicy::Unknown,
        selection: AgentParticipation::NONE,
    })
}

fn mention_state_from_entries(
    entries: &[AgentParticipationEntry],
    realm_id: &str,
) -> (AgentMentionPolicy, AgentParticipation) {
    let mut selection = AgentParticipation::NONE;
    let mut matched = false;
    for entry in entries {
        match &entry.scope {
            AgentParticipationScope::Realm {
                realm_id: entry_realm,
            } if entry_realm.as_str() == realm_id => {
                matched = true;
                selection = entry.selection;
                if entry.effective.accept_third_party_mention {
                    return (AgentMentionPolicy::Allowed, selection);
                }
            }
            _ => {}
        }
    }
    if matched {
        (AgentMentionPolicy::OwnerOnly, selection)
    } else {
        (AgentMentionPolicy::OwnerOnly, AgentParticipation::NONE)
    }
}

fn group_members_with_owned_agents(
    members: &[String],
    owned_agents: &[MemberAgentRow],
    fallback_controller_did: &str,
) -> Vec<MemberGroup> {
    let member_set: BTreeSet<&str> = members.iter().map(String::as_str).collect();
    let owned_agent_ids: BTreeSet<&str> = owned_agents
        .iter()
        .map(|agent| agent.agent_principal_id.as_str())
        .collect();
    let mut groups = BTreeMap::<String, MemberGroup>::new();

    for member in members {
        if owned_agent_ids.contains(member.as_str()) {
            continue;
        }
        groups.entry(member.clone()).or_insert_with(|| MemberGroup {
            controller_did: member.clone(),
            agents: Vec::new(),
        });
    }

    let mut in_realm_agents: Vec<MemberAgentRow> = owned_agents
        .iter()
        .filter(|agent| member_set.contains(agent.agent_principal_id.as_str()))
        .cloned()
        .collect();
    in_realm_agents.sort_by(|a, b| {
        a.display_name
            .cmp(&b.display_name)
            .then_with(|| a.agent_principal_id.cmp(&b.agent_principal_id))
    });
    for agent in in_realm_agents {
        let controller = agent.controller_did.trim();
        let controller = if controller.is_empty() {
            fallback_controller_did.trim()
        } else {
            controller
        };
        if !controller.is_empty() {
            groups
                .entry(controller.to_owned())
                .or_insert_with(|| MemberGroup {
                    controller_did: controller.to_owned(),
                    agents: Vec::new(),
                })
                .agents
                .push(agent);
        }
    }

    groups.into_values().collect()
}

fn member_group_matches(group: &MemberGroup, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return true;
    }
    group.controller_did.to_lowercase().contains(&query)
        || short_protocol_id(&group.controller_did)
            .to_lowercase()
            .contains(&query)
        || group.agents.iter().any(|agent| {
            agent.agent_principal_id.to_lowercase().contains(&query)
                || agent.display_name.to_lowercase().contains(&query)
                || agent.agent_slug.to_lowercase().contains(&query)
        })
}

fn agent_invite_target(agent_principal_id: &str, service_did: &str) -> String {
    format!(
        "subject_id={} recipient_service_did={}",
        agent_principal_id.trim(),
        service_did.trim()
    )
}

fn member_avatar_initial(value: &str) -> String {
    value
        .trim_start_matches("did:web:")
        .chars()
        .find(|ch| ch.is_alphanumeric())
        .map(|ch| ch.to_ascii_uppercase().to_string())
        .unwrap_or_else(|| "?".to_owned())
}

#[component]
fn MemberRowActions(
    base_url: String,
    token: Signal<String>,
    account_did: String,
    selected_realm_id: String,
    target_did: String,
    target_label: String,
    can_remove: bool,
    state_store: Signal<LocalStateStore>,
    mut status_msg: Signal<String>,
    mut block_confirm_did: Signal<Option<String>>,
) -> Element {
    rsx! {
        div { class: "actions",
            if can_remove {
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "kick-member-button",
                    onclick: {
                        let base = base_url.clone();
                        let realm = selected_realm_id.clone();
                        let target = target_did.clone();
                        let actor_account_did = account_did.clone();
                        move |_| {
                            let base = base.clone();
                            let realm = realm.clone();
                            let target = target.clone();
                            let api_token = token();
                            let actor_id = actor_account_did.clone();
                            spawn(async move {
                                let target_for_msg = target.clone();
                                let realm_for_api = realm.clone();
                                match crate::views::helpers::with_authed_api(
                                    &base,
                                    api_token,
                                    |api| async move {
                                        api.transition_member_state(
                                            &realm_for_api,
                                            &actor_id,
                                            &target,
                                            Some("join"),
                                            "leave",
                                            "admin_kick",
                                        )
                                        .await
                                    },
                                )
                                .await
                                {
                                    Ok(resp) => {
                                        let mls_encrypted = state_store
                                            .read()
                                            .realm_projection_is_mls_encrypted(&realm);
                                        if mls_encrypted {
                                            state_store.write().record_move_submission_with_event_id(
                                                resp.event_id.clone(),
                                                Some(resp.event_id.clone()),
                                                realm.clone(),
                                                "mls_member_remove",
                                                MoveSubmissionState::PendingMlsBinding,
                                                Some("epoch_update_required: membership frontier changed; MLS Remove commit required".to_owned()),
                                                None,
                                            );
                                        }
                                        let suffix = if mls_encrypted {
                                            "; epoch_update_required"
                                        } else {
                                            ""
                                        };
                                        status_msg.set(format!(
                                            "kicked {}{}",
                                            short_protocol_id(&target_for_msg),
                                            suffix
                                        ));
                                    }
                                    Err(err) => status_msg.set(format!(
                                        "kick failed: {}", err.display()
                                    )),
                                }
                            });
                        }
                    },
                    {crate::i18n::tr("realm_admin.kick_member")}
                }
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "ban-member-button",
                    onclick: {
                        let base = base_url.clone();
                        let realm = selected_realm_id.clone();
                        let target = target_did.clone();
                        let actor_account_did = account_did.clone();
                        move |_| {
                            let base = base.clone();
                            let realm = realm.clone();
                            let target = target.clone();
                            let api_token = token();
                            let actor_id = actor_account_did.clone();
                            spawn(async move {
                                let target_for_msg = target.clone();
                                let realm_for_api = realm.clone();
                                match crate::views::helpers::with_authed_api(
                                    &base,
                                    api_token,
                                    |api| async move {
                                        api.ban_member(&realm_for_api, &actor_id, &target).await
                                    },
                                )
                                .await
                                {
                                    Ok(resp) => {
                                        let mls_encrypted = state_store
                                            .read()
                                            .realm_projection_is_mls_encrypted(&realm);
                                        if mls_encrypted {
                                            state_store.write().record_move_submission_with_event_id(
                                                resp.event_id.clone(),
                                                Some(resp.event_id.clone()),
                                                realm.clone(),
                                                "mls_member_remove",
                                                MoveSubmissionState::PendingMlsBinding,
                                                Some("epoch_update_required: membership frontier changed; MLS Remove commit required".to_owned()),
                                                None,
                                            );
                                        }
                                        let suffix = if mls_encrypted {
                                            "; epoch_update_required"
                                        } else {
                                            ""
                                        };
                                        status_msg.set(format!(
                                            "banned {}{}",
                                            short_protocol_id(&target_for_msg),
                                            suffix
                                        ));
                                    }
                                    Err(err) => status_msg.set(format!(
                                        "ban failed: {}", err.display()
                                    )),
                                }
                            });
                        }
                    },
                    {crate::i18n::tr("realm_admin.ban_member")}
                }
            }
            Button {
                variant: ButtonVariant::Secondary,
                "data-testid": "member-row-block-button",
                onclick: {
                    let target = target_did.clone();
                    move |_| block_confirm_did.set(Some(target.clone()))
                },
                {crate::i18n::tr("member.block")}
            }
        }
        if block_confirm_did().as_deref() == Some(target_did.as_str()) {
            div {
                class: "event member-block-confirm",
                "data-testid": "block-user-confirm-modal",
                div { class: "entity-title", {crate::i18n::tr("member.block_confirm.title")} }
                div { class: "muted", title: "{target_did}", "{target_label}" }
                div { class: "muted", {crate::i18n::tr("member.block_confirm.body")} }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "block-user-confirm-button",
                        onclick: {
                            let target = target_did.clone();
                            let base = base_url.clone();
                            move |_| {
                                let changed = state_store
                                    .write()
                                    .block_user(&target, None);
                                block_confirm_did.set(None);
                                if changed {
                                    status_msg.set(format!(
                                        "Blocked {}",
                                        short_protocol_id(&target)
                                    ));
                                    let entries = state_store
                                        .read()
                                        .client_blocklist();
                                    crate::views::settings::push_blocklist_account_data(
                                        base.clone(),
                                        token(),
                                        entries,
                                    );
                                } else {
                                    status_msg.set(format!(
                                        "{} is already blocked",
                                        short_protocol_id(&target)
                                    ));
                                }
                            }
                        },
                        {crate::i18n::tr("member.block_confirm.confirm")}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "block-user-cancel-button",
                        onclick: move |_| block_confirm_did.set(None),
                        {crate::i18n::tr("common.cancel")}
                    }
                }
            }
        }
    }
}

#[component]
pub fn RealmMembersPanel(
    base_url: String,
    active_service_did: String,
    account_did: String,
    token: Signal<String>,
    selected_realm_id: String,
    sync_cursor: Signal<String>,
    frontier_state: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let mut invite_target = use_signal(String::new);
    let mut status_msg = use_signal(String::new);
    let mut members = use_signal(Vec::<String>::new);
    let mut owned_agents = use_signal(Vec::<MemberAgentRow>::new);
    let mut self_agent_settings_open = use_signal(|| false);
    let block_confirm_did = use_signal(|| Option::<String>::None);
    let mut permissions = use_signal(RealmMemberPermissions::default);
    // Invite is now a modal launched from the list header "+" button.
    let mut invite_modal_open = use_signal(|| false);
    // Client-side member search + incremental paging. `member_filter`
    // narrows the projected roster; `member_visible` caps how many rows we
    // actually mount so a 10k-member Realm doesn't render 10k DOM nodes.
    let mut member_filter = use_signal(String::new);
    let mut member_visible = use_signal(|| MEMBER_PAGE_SIZE);
    // U3 - "Add from contacts" picker state. `invite_contacts` holds the user's
    // accepted contacts (lazily loaded when the modal opens); `selected_contacts`
    // is the multi-select set of DIDs to invite via the consent-grant path.
    let mut invite_contacts = use_signal(Vec::<crate::models::ContactListRow>::new);
    let mut invite_contacts_loaded = use_signal(|| false);
    let mut invite_contacts_status = use_signal(String::new);
    let mut selected_contacts = use_signal(std::collections::BTreeSet::<String>::new);

    // Lazily hydrate the contacts list the first time the invite modal opens.
    {
        let base = base_url.clone();
        use_effect(move || {
            if !invite_modal_open() || invite_contacts_loaded() {
                return;
            }
            invite_contacts_loaded.set(true);
            let api_token = token();
            let base = base.clone();
            invite_contacts_status.set(crate::i18n::tr("realm_admin.invite_loading_contacts"));
            spawn(async move {
                match crate::views::helpers::with_authed_api(&base, api_token, |api| async move {
                    api.contacts().await
                })
                .await
                {
                    Ok(response) => {
                        let accepted: Vec<crate::models::ContactListRow> = response
                            .contacts
                            .into_iter()
                            .filter(|c| c.state == "accepted")
                            .collect();
                        let count = accepted.len();
                        invite_contacts.set(accepted);
                        invite_contacts_status.set(if count == 0 {
                            crate::i18n::tr("realm_admin.invite_no_contacts")
                        } else {
                            String::new()
                        });
                    }
                    Err(err) => invite_contacts_status.set(
                        crate::i18n::tr("realm_admin.invite_contacts_failed")
                            .replace("{error}", &err.display()),
                    ),
                }
            });
        });
    }

    {
        let selected_realm_for_hydration = selected_realm_id.clone();
        use_effect(move || {
            let next =
                projected_members_for_realm(&state_store.read(), &selected_realm_for_hydration);
            if members() != next {
                members.set(next);
            }
        });
    }

    {
        let base = base_url.clone();
        let realm = selected_realm_id.clone();
        let fallback_controller_did = account_did.clone();
        use_effect(move || {
            let api_token = token();
            if api_token.trim().is_empty() {
                owned_agents.set(Vec::new());
                return;
            }
            let base = base.clone();
            let realm = realm.clone();
            let fallback_controller_did = fallback_controller_did.clone();
            spawn(async move {
                let result =
                    crate::views::helpers::with_authed_api(&base, api_token, |api| async move {
                        let list = api.agent_list().await?;
                        let mut rows = Vec::<MemberAgentRow>::new();
                        for value in list.agents {
                            let Some(mut row) =
                                member_agent_row_from_value(value, &fallback_controller_did)
                            else {
                                continue;
                            };
                            match api.agent_participation_get(&row.agent_principal_id).await {
                                Ok(outcome) => {
                                    let (policy, selection) =
                                        mention_state_from_entries(&outcome.entries, &realm);
                                    row.mention_policy = policy;
                                    row.selection = selection;
                                }
                                Err(_) => {
                                    row.mention_policy = AgentMentionPolicy::Unknown;
                                }
                            }
                            rows.push(row);
                        }
                        rows.sort_by(|left, right| {
                            left.display_name.cmp(&right.display_name).then_with(|| {
                                left.agent_principal_id.cmp(&right.agent_principal_id)
                            })
                        });
                        Ok::<Vec<MemberAgentRow>, anyhow::Error>(rows)
                    })
                    .await;
                if let Ok(rows) = result {
                    owned_agents.set(rows);
                }
            });
        });
    }

    {
        let base = base_url.clone();
        let actor = account_did.clone();
        let realm = selected_realm_id.clone();
        use_effect(move || {
            let api_token = token();
            if api_token.trim().is_empty() || actor.trim().is_empty() || realm.trim().is_empty() {
                permissions.set(RealmMemberPermissions {
                    loaded: true,
                    ..RealmMemberPermissions::default()
                });
                return;
            }
            permissions.set(RealmMemberPermissions::default());
            let base = base.clone();
            let actor = actor.clone();
            let realm = realm.clone();
            spawn(async move {
                match authed_api_with_sync(&base, api_token, None) {
                    Ok(api) => {
                        let invite = api
                            .authz_check_raw(&actor, "ck.invite.create", &realm)
                            .await;
                        // Member removal has no standalone capability action in
                        // v1; it is governed by Realm management authority. Probe
                        // the registered `ck.realm.admin` action (management,
                        // high-risk) instead of the unregistered placeholder
                        // `ck.member.remove`, which is not in
                        // capability-action-registry.json and would be treated as
                        // an unknown high-risk action (fail-closed) by a
                        // spec-conformant server.
                        let remove = api.authz_check_raw(&actor, "ck.realm.admin", &realm).await;
                        let can_invite = invite.as_ref().map(authz_json_allowed).unwrap_or(false);
                        let can_remove = remove.as_ref().map(authz_json_allowed).unwrap_or(false);
                        if invite.is_err() && remove.is_err() {
                            status_msg.set(
                                "member action permission check failed; write controls hidden"
                                    .to_owned(),
                            );
                        }
                        permissions.set(RealmMemberPermissions {
                            loaded: true,
                            can_invite,
                            can_remove,
                        });
                    }
                    Err(error) => {
                        permissions.set(RealmMemberPermissions {
                            loaded: true,
                            ..RealmMemberPermissions::default()
                        });
                        status_msg.set(format!("member action permission check failed: {error}"));
                    }
                }
            });
        });
    }

    let member_permissions = permissions();
    let can_invite = member_permissions.can_invite;
    let can_remove = member_permissions.can_remove;

    // Roster → grouped by controller → filtered → paged window. Filtering
    // stays cheap; pagination keeps the mounted row count bounded while
    // keeping each controller's agents visually attached to the owner.
    let all_members = members();
    let owned_agent_rows = owned_agents();
    let member_groups =
        group_members_with_owned_agents(&all_members, &owned_agent_rows, &account_did);
    let total_members = all_members.len();
    let total_groups = member_groups.len();
    let filter_query = member_filter().trim().to_lowercase();
    let filtered_groups: Vec<MemberGroup> = if filter_query.is_empty() {
        member_groups
    } else {
        member_groups
            .into_iter()
            .filter(|group| member_group_matches(group, &filter_query))
            .collect()
    };
    let filtered_count = filtered_groups.len();
    let visible = member_visible().min(filtered_count);
    let visible_groups: Vec<MemberGroup> = filtered_groups[..visible].to_vec();
    let has_more = visible < filtered_count;
    let show_search = total_groups > MEMBER_SEARCH_THRESHOLD;
    let member_set: BTreeSet<String> = all_members.iter().cloned().collect();
    let self_owned_agent_rows: Vec<MemberAgentRow> = owned_agent_rows
        .iter()
        .filter(|agent| {
            let controller = agent.controller_did.trim();
            controller.is_empty() || controller == account_did.trim()
        })
        .cloned()
        .collect();
    // Icon buttons carry their label via title/aria-label instead of text.
    let refresh_label = crate::i18n::tr("realm_admin.refresh_members");

    rsx! {
        div { class: "timeline", "data-testid": "realm-members-panel",
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
                            // U3 — primary, natural path: pull existing contacts
                            // into the Realm directly via their consent grant.
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
                                                let did = contact.peer.clone();
                                                let checked = selected_contacts.read().contains(&did);
                                                let eligible = contact.grants_me_invite();
                                                let has_ref = contact.invite_consent_ref().is_some();
                                                let usable = eligible && has_ref;
                                                // Distinguish "peer never authorised invite" (no real
                                                // consent grant ref) from other not-yet-usable states so
                                                // the badge tells the user why the row is disabled.
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
                                                        span { class: "mono", title: "{did}", " {short_protocol_id(&did)}" }
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
                                                let base = base_url.clone();
                                                let actor = account_did.clone();
                                                let realm = selected_realm_id.clone();
                                                move |_| {
                                                    let base = base.clone();
                                                    let actor = actor.clone();
                                                    let realm = realm.clone();
                                                    let api_token = token();
                                                    // Resolve the (did, consent_ref) pairs up front so the
                                                    // async task doesn't borrow the rendered rows.
                                                    let targets: Vec<(String, String)> = invite_contacts
                                                        .read()
                                                        .iter()
                                                        .filter(|c| selected_contacts.read().contains(&c.peer))
                                                        .filter_map(|c| {
                                                            c.invite_consent_ref().map(|r| (c.peer.clone(), r.to_owned()))
                                                        })
                                                        .collect();
                                                    if targets.is_empty() {
                                                        status_msg.set(crate::i18n::tr("realm_admin.invite_none_eligible"));
                                                        return;
                                                    }
                                                    let total = targets.len();
                                                    status_msg.set(
                                                        crate::i18n::tr("realm_admin.invite_sending")
                                                            .replace("{total}", &total.to_string()),
                                                    );
                                                    spawn(async move {
                                                        let api = match crate::views::helpers::authed_api(&base, api_token) {
                                                            Ok(api) => api,
                                                            Err(err) => {
                                                                status_msg.set(
                                                                    crate::i18n::tr("realm_admin.invite_bad_server")
                                                                        .replace("{error}", &err.to_string()),
                                                                );
                                                                return;
                                                            }
                                                        };
                                                        let mut ok = 0_usize;
                                                        let mut last_err = String::new();
                                                        for (did, consent_ref) in targets {
                                                            match api
                                                                .invite_contact_to_realm(&realm, &actor, &did, &consent_ref)
                                                                .await
                                                            {
                                                                Ok(event_id) => {
                                                                    ok += 1;
                                                                    frontier_state.set(event_id);
                                                                }
                                                                Err(err) => last_err = err.to_string(),
                                                            }
                                                        }
                                                        selected_contacts.set(std::collections::BTreeSet::new());
                                                        if ok == total {
                                                            invite_modal_open.set(false);
                                                            status_msg.set(
                                                                crate::i18n::tr("realm_admin.invite_sent")
                                                                    .replace("{ok}", &ok.to_string()),
                                                            );
                                                        } else {
                                                            status_msg.set(
                                                                crate::i18n::tr("realm_admin.invite_partial")
                                                                    .replace("{ok}", &ok.to_string())
                                                                    .replace("{total}", &total.to_string())
                                                                    .replace("{error}", &last_err),
                                                            );
                                                        }
                                                    });
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
                                    let base = base_url.clone();
                                    let actor = account_did.clone();
                                    let realm = selected_realm_id.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let actor = actor.clone();
                                        let realm = realm.clone();
                                        let api_token = token();
                                        let target = invite_target().trim().to_owned();
                                        if target.is_empty() {
                                            status_msg.set("invite target is required".to_owned());
                                            return;
                                        }
                                        let wait_for = active_sync_token(sync_cursor());
                                        let invite_id = format!(
                                            "ck:invite:{}",
                                            crate::operation::uuid_v7()
                                        );
                                        spawn(async move {
                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                Ok(api) => {
                                                    let invitee = match api
                                                        .resolve_invitee_for_invite(
                                                            &target,
                                                            &realm,
                                                            &actor,
                                                        )
                                                        .await
                                                    {
                                                        Ok(did) => did,
                                                        Err(error) => {
                                                            status_msg.set(format!("invite target resolve failed: {error}"));
                                                            return;
                                                        }
                                                    };
                                                    let invitee_label = invitee
                                                        .handle
                                                        .clone()
                                                        .unwrap_or_else(|| invitee.did.clone());
                                                    let op = match ck_ops::invite_create_structured(
                                                        &realm,
                                                        &actor,
                                                        &invite_id,
                                                        &invitee.did,
                                                        None,
                                                        invitee.invite_delivery_target.clone(),
                                                        &invitee.introduction_evidence_digest,
                                                    ) {
                                                        Ok(builder) => builder
                                                            .build_sdk_event("yougen"),
                                                        Err(err) => {
                                                            status_msg.set(format!("invite failed: {err:#}"));
                                                            return;
                                                        }
                                                    };
                                                    let submit_event = match op {
                                                        Ok(event) => event,
                                                        Err(err) => {
                                                            status_msg.set(format!("invite failed: {err:#}"));
                                                            return;
                                                        }
                                                    };
                                                    let op_id = submit_event
                                                        .unsigned
                                                        .get("local_operation_idempotency_alias")
                                                        .and_then(|value| value.as_str())
                                                        .unwrap_or_else(|| submit_event.event_id.as_str())
                                                        .to_owned();
                                                    status_msg.set(format!(
                                                        "submitting invite for {}",
                                                        invitee_label
                                                    ));
                                                    match api.submit_sdk_event(&submit_event).await {
                                                        Ok(submitted) => {
                                                            frontier_state.set(submitted.event_id.clone());
                                                            {
                                                                let mut store = state_store.write();
                                                                store.append_raw_operation(
                                                                    op_id.clone(),
                                                                    Some(realm.clone()),
                                                                    json!({
                                                                        "kind": "ck.invite.create",
                                                                        "invite_id": invite_id,
                                                                        "invitee": invitee.did,
                                                                        "state": "pending",
                                                                        "event_id": submitted.event_id,
                                                                    }),
                                                                );
                                                            }
                                                            invite_target.set(String::new());
                                                            invite_modal_open.set(false);
                                                            status_msg.set(format!(
                                                                "invited {} (pending) fact {}",
                                                                invitee_label,
                                                                short_protocol_id(&op_id)
                                                            ));
                                                        }
                                                        Err(error) => status_msg.set(format!("invite failed: {error}")),
                                                    }
                                                }
                                                Err(error) => status_msg.set(format!("invalid server URL: {error}")),
                                            }
                                        });
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
                        if can_invite {
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
                                    let next = projected_members_for_realm(&store, &realm);
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
                if member_permissions.loaded && !can_invite && !can_remove {
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
                for group in visible_groups {
                    {
                        let member = group.controller_did.clone();
                        let member_label = short_protocol_id(&member);
                        let is_self = member == account_did;
                        let has_agents = !group.agents.is_empty();
                        let group_class = if has_agents {
                            "member-group has-agents"
                        } else {
                            "member-group"
                        };
                        let avatar_initial = member_avatar_initial(&member);
                        rsx! {
                            div {
                                class: "{group_class}",
                                "data-testid": "member-group",
                                "data-controller-did": "{member}",
                                div { class: "event member-row member-controller-row", "data-testid": "member-row", "data-member-did": "{member}",
                                    div { class: "event-head member-row-main",
                                        if is_self {
                                            button {
                                                class: "member-avatar member-avatar-button",
                                                "data-testid": "member-self-avatar-button",
                                                "aria-label": "Open my AI agent settings",
                                                title: "Open my AI agent settings",
                                                onclick: move |_| self_agent_settings_open.set(!self_agent_settings_open()),
                                                "{avatar_initial}"
                                            }
                                        } else {
                                            div {
                                                class: "member-avatar",
                                                "data-testid": "member-avatar",
                                                "aria-hidden": "true",
                                                "{avatar_initial}"
                                            }
                                        }
                                        div { class: "member-row-text",
                                            div { class: "member-row-title",
                                                span { title: "{member}", "{member_label}" }
                                                if is_self {
                                                    span { class: "badge green", "You" }
                                                }
                                                if has_agents {
                                                    span {
                                                        class: "badge blue",
                                                        "data-testid": "member-agent-count",
                                                        "{group.agents.len()} AI"
                                                    }
                                                }
                                            }
                                            div { class: "muted member-row-sub", "Realm member" }
                                        }
                                    }
                                    MemberRowActions {
                                        base_url: base_url.clone(),
                                        token,
                                        account_did: account_did.clone(),
                                        selected_realm_id: selected_realm_id.clone(),
                                        target_did: member.clone(),
                                        target_label: member_label.clone(),
                                        can_remove,
                                        state_store,
                                        status_msg,
                                        block_confirm_did,
                                    }
                                }
                                if is_self && self_agent_settings_open() {
                                    div { class: "member-self-agent-settings", "data-testid": "member-self-agent-settings",
                                        div { class: "member-self-agent-settings-head",
                                            div {
                                                div { class: "entity-title", "My AI agents in this Realm" }
                                                div { class: "muted", "Set whether ordinary Realm members can @ your agents, or add one of your agents to this Realm." }
                                            }
                                            span { class: "badge", "{self_owned_agent_rows.len()} total" }
                                        }
                                        if self_owned_agent_rows.is_empty() {
                                            div { class: "members-empty compact", "data-testid": "member-self-agent-empty",
                                                div { class: "members-empty-icon", crate::components::UiIcon { name: "bot" } }
                                                div { class: "members-empty-title", "No AI agents yet." }
                                            }
                                        } else {
                                            div { class: "member-self-agent-list",
                                                for owned_agent in self_owned_agent_rows.clone() {
                                                    {
                                                        let agent_in_realm = member_set.contains(&owned_agent.agent_principal_id);
                                                        let policy = owned_agent.mention_policy;
                                                        let policy_class = policy.badge_class();
                                                        let policy_label = policy.label();
                                                        let agent_id = owned_agent.agent_principal_id.clone();
                                                        let agent_title = owned_agent.display_name.clone();
                                                        let status_class = crate::views::agents::agent_state_badge_class(&owned_agent.status);
                                                        let status_label = crate::views::agents::agent_state_label(&owned_agent.status).to_owned();
                                                        let can_enable = agent_in_realm;
                                                        rsx! {
                                                            div { class: "member-self-agent-row", "data-testid": "member-self-agent-row", "data-agent-did": "{agent_id}",
                                                                div { class: "member-agent-summary",
                                                                    div { class: "member-avatar member-avatar-agent", "aria-hidden": "true",
                                                                        crate::components::UiIcon { name: "bot" }
                                                                    }
                                                                    div { class: "member-row-text",
                                                                        div { class: "member-row-title",
                                                                            span { title: "{agent_id}", "{agent_title}" }
                                                                            span { class: "{status_class}", "{status_label}" }
                                                                            if !owned_agent.agent_slug.is_empty() {
                                                                                span { class: "badge", "/{owned_agent.agent_slug}" }
                                                                            }
                                                                        }
                                                                        div { class: "muted member-row-sub mono", title: "{agent_id}", "{short_protocol_id(&agent_id)}" }
                                                                    }
                                                                }
                                                                div { class: "member-self-agent-actions",
                                                                    if agent_in_realm {
                                                                        span { class: "{policy_class}", "data-testid": "member-agent-mention-policy", "{policy_label}" }
                                                                        Button {
                                                                            variant: ButtonVariant::Secondary,
                                                                            "data-testid": "member-agent-mention-toggle",
                                                                            disabled: !can_enable,
                                                                            onclick: {
                                                                                let base = base_url.clone();
                                                                                let realm = selected_realm_id.clone();
                                                                                let agent_id = agent_id.clone();
                                                                                let previous = owned_agent.selection;
                                                                                move |_| {
                                                                                    let base = base.clone();
                                                                                    let realm = realm.clone();
                                                                                    let agent_id = agent_id.clone();
                                                                                    let api_token = token();
                                                                                    let next_mention = !matches!(policy, AgentMentionPolicy::Allowed);
                                                                                    spawn(async move {
                                                                                        let body = cokret_sdk::models::AgentParticipationSetRequestBody {
                                                                                            scope: AgentParticipationScope::Realm {
                                                                                                realm_id: match cokret_sdk::RealmId::new(realm.clone()) {
                                                                                                    Ok(realm_id) => realm_id,
                                                                                                    Err(err) => {
                                                                                                        status_msg.set(format!("invalid realm id: {err:?}"));
                                                                                                        return;
                                                                                                    }
                                                                                                },
                                                                                            },
                                                                                            selection: AgentParticipation {
                                                                                                reply: previous.reply,
                                                                                                accept_third_party_mention: next_mention,
                                                                                                act_on_behalf: previous.act_on_behalf,
                                                                                            },
                                                                                        };
                                                                                        match crate::views::helpers::with_authed_api(&base, api_token, |api| {
                                                                                            let body = body.clone();
                                                                                            let agent_id = agent_id.clone();
                                                                                            async move { api.agent_participation_set(&agent_id, &body).await }
                                                                                        })
                                                                                        .await
                                                                                        {
                                                                                            Ok(outcome) => {
                                                                                                let (mention_policy, selection) =
                                                                                                    mention_state_from_entries(&outcome.entries, &realm);
                                                                                                let mut next_agents = owned_agents.read().clone();
                                                                                                for row in &mut next_agents {
                                                                                                    if row.agent_principal_id == outcome.agent_principal_id {
                                                                                                        row.mention_policy = mention_policy;
                                                                                                        row.selection = selection;
                                                                                                    }
                                                                                                }
                                                                                                owned_agents.set(next_agents);
                                                                                                status_msg.set(format!(
                                                                                                    "agent @ policy updated for {}",
                                                                                                    short_protocol_id(&outcome.agent_principal_id)
                                                                                                ));
                                                                                            }
                                                                                            Err(err) => status_msg.set(format!(
                                                                                                "agent @ policy update failed: {}",
                                                                                                err.display()
                                                                                            )),
                                                                                        }
                                                                                    });
                                                                                }
                                                                            },
                                                                            if matches!(policy, AgentMentionPolicy::Allowed) {
                                                                                "Disable @"
                                                                            } else {
                                                                                "Allow @"
                                                                            }
                                                                        }
                                                                    } else if can_invite {
                                                                        Button {
                                                                            variant: ButtonVariant::Secondary,
                                                                            "data-testid": "member-agent-add-to-realm",
                                                                            disabled: active_service_did.trim().is_empty(),
                                                                            onclick: {
                                                                                let agent_id = agent_id.clone();
                                                                                let service_did = active_service_did.clone();
                                                                                move |_| {
                                                                                    if service_did.trim().is_empty() {
                                                                                        status_msg.set("current service DID is unavailable; cannot prepare agent invite".to_owned());
                                                                                        return;
                                                                                    }
                                                                                    invite_target.set(agent_invite_target(&agent_id, &service_did));
                                                                                    invite_modal_open.set(true);
                                                                                }
                                                                            },
                                                                            "Add to Realm"
                                                                        }
                                                                    } else {
                                                                        span { class: "badge", "not in Realm" }
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
                                if has_agents {
                                    div { class: "member-agent-list", "data-testid": "member-agent-list",
                                        for agent in group.agents {
                                            {
                                                let agent_id = agent.agent_principal_id.clone();
                                                let agent_label = agent.display_name.clone();
                                                let agent_initial = member_avatar_initial(&agent_label);
                                                let policy_class = agent.mention_policy.badge_class();
                                                let policy_label = agent.mention_policy.label();
                                                let status_class = crate::views::agents::agent_state_badge_class(&agent.status);
                                                let status_label = crate::views::agents::agent_state_label(&agent.status).to_owned();
                                                rsx! {
                                                    div { class: "event member-row member-agent-row", "data-testid": "member-agent-row", "data-member-did": "{agent_id}",
                                                        div { class: "event-head member-row-main",
                                                            div { class: "member-avatar member-avatar-agent", "data-testid": "member-agent-avatar", "aria-hidden": "true",
                                                                if agent_initial == "?" {
                                                                    crate::components::UiIcon { name: "bot" }
                                                                } else {
                                                                    "{agent_initial}"
                                                                }
                                                            }
                                                            div { class: "member-row-text",
                                                                div { class: "member-row-title",
                                                                    span { title: "{agent_id}", "{agent_label}" }
                                                                    span { class: "badge member-badge member-badge-agent", "data-testid": "member-badge-agent", "AI agent" }
                                                                    span { class: "{status_class}", "{status_label}" }
                                                                    span { class: "{policy_class}", "{policy_label}" }
                                                                }
                                                                div { class: "muted member-row-sub",
                                                                    "owned by "
                                                                    span { class: "mono", title: "{member}", "{member_label}" }
                                                                    if !agent.agent_slug.is_empty() {
                                                                        span { " · /{agent.agent_slug}" }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        MemberRowActions {
                                                            base_url: base_url.clone(),
                                                            token,
                                                            account_did: account_did.clone(),
                                                            selected_realm_id: selected_realm_id.clone(),
                                                            target_did: agent_id.clone(),
                                                            target_label: agent_label.clone(),
                                                            can_remove,
                                                            state_store,
                                                            status_msg,
                                                            block_confirm_did,
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
                if filtered_count == 0 {
                    div { class: "members-empty", "data-testid": "members-empty-state",
                        if total_members == 0 {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(id: &str, controller: &str, name: &str) -> MemberAgentRow {
        MemberAgentRow {
            agent_principal_id: id.to_owned(),
            controller_did: controller.to_owned(),
            display_name: name.to_owned(),
            agent_slug: "summary".to_owned(),
            status: "active".to_owned(),
            mention_policy: AgentMentionPolicy::Allowed,
            selection: AgentParticipation {
                reply: false,
                accept_third_party_mention: true,
                act_on_behalf: false,
            },
        }
    }

    #[test]
    fn groups_current_account_with_owned_agent_members() {
        let members = vec![
            "did:web:alice.example".to_owned(),
            "did:web:bob.example".to_owned(),
            "did:web:agent.example".to_owned(),
        ];
        let groups = group_members_with_owned_agents(
            &members,
            &[agent(
                "did:web:agent.example",
                "did:web:alice.example",
                "Summary",
            )],
            "did:web:alice.example",
        );

        let alice = groups
            .iter()
            .find(|group| group.controller_did == "did:web:alice.example")
            .expect("alice group exists");
        assert_eq!(alice.agents.len(), 1);
        assert_eq!(alice.agents[0].agent_principal_id, "did:web:agent.example");
        assert!(
            groups
                .iter()
                .all(|group| group.controller_did != "did:web:agent.example")
        );
    }

    #[test]
    fn groups_agent_members_under_reported_controller() {
        let members = vec![
            "did:web:alice.example".to_owned(),
            "did:web:bob.example".to_owned(),
            "did:web:bob-agent.example".to_owned(),
        ];
        let groups = group_members_with_owned_agents(
            &members,
            &[agent(
                "did:web:bob-agent.example",
                "did:web:bob.example",
                "Bob Summary",
            )],
            "did:web:alice.example",
        );

        let bob = groups
            .iter()
            .find(|group| group.controller_did == "did:web:bob.example")
            .expect("bob group exists");
        assert_eq!(bob.agents.len(), 1);
        assert_eq!(
            bob.agents[0].agent_principal_id,
            "did:web:bob-agent.example"
        );
        assert!(
            groups
                .iter()
                .all(|group| group.controller_did != "did:web:bob-agent.example")
        );
    }

    #[test]
    fn mention_policy_reads_realm_effective_bit() {
        let realm_id =
            cokret_sdk::RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001".to_owned())
                .unwrap();
        let entries = vec![AgentParticipationEntry {
            scope: AgentParticipationScope::Realm { realm_id },
            selection: AgentParticipation {
                reply: true,
                accept_third_party_mention: true,
                act_on_behalf: false,
            },
            ceiling: AgentParticipation {
                reply: true,
                accept_third_party_mention: true,
                act_on_behalf: false,
            },
            effective: AgentParticipation {
                reply: true,
                accept_third_party_mention: true,
                act_on_behalf: false,
            },
        }];

        let (policy, selection) =
            mention_state_from_entries(&entries, "ck:realm:01904100-0000-7000-8000-000000000001");
        assert_eq!(policy, AgentMentionPolicy::Allowed);
        assert!(selection.accept_third_party_mention);
    }
}
