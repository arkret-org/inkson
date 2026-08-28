use std::collections::{BTreeMap, BTreeSet};

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
            Self::Allowed => "Members can @",
            Self::OwnerOnly => "Controller only",
            Self::Unknown => "@ policy unknown",
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemberRosterSection {
    Members,
    Owners,
    Admins,
    MyAgents,
    PendingInvites,
}

impl MemberRosterSection {
    fn title(self) -> &'static str {
        match self {
            Self::Members => "Members",
            Self::Owners => "Owners",
            Self::Admins => "Admins",
            Self::MyAgents => "My agents",
            Self::PendingInvites => "Pending invites",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Members => "Active Realm members without owner or admin authority.",
            Self::Owners => "Realm owners with top-level governance authority.",
            Self::Admins => "Realm admins with management authority.",
            Self::MyAgents => "Manage your agents and their behavior in this Realm.",
            Self::PendingInvites => {
                "Invitations sent for this Realm that have not been accepted yet."
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct MemberAgentRow {
    agent_id: String,
    controller_id: String,
    display_name: String,
    slug: String,
    /// Lifecycle intent wire value (active/paused/deactivated).
    status: String,
    /// Derived runtime readiness wire value (key-management.md §3.6.1).
    runtime_state: String,
    mention_policy: AgentMentionPolicy,
    selection: ParticipationBits,
}

#[derive(Clone, Debug, PartialEq)]
struct MemberProfile {
    actor_id: String,
    subject_id: Option<String>,
    invite_id: Option<String>,
    invite_is_direct: Option<bool>,
    display_name: Option<String>,
    avatar_blob_ref: Option<arkret_sdk::BlobRef>,
    handles: Vec<String>,
    remark_name: Option<String>,
    remark_note: Option<String>,
    confusable_contact_warning: bool,
    membership: Option<String>,
    member_display_state_digest: Option<String>,
    is_owner: bool,
    is_admin: bool,
}

impl MemberProfile {
    fn bare(actor_id: impl Into<String>) -> Self {
        Self {
            actor_id: actor_id.into(),
            subject_id: None,
            invite_id: None,
            invite_is_direct: None,
            display_name: None,
            avatar_blob_ref: None,
            handles: Vec::new(),
            remark_name: None,
            remark_note: None,
            confusable_contact_warning: false,
            membership: None,
            member_display_state_digest: None,
            is_owner: false,
            is_admin: false,
        }
    }

    fn primary_label(&self) -> String {
        self.remark_name
            .as_deref()
            .or(self.display_name.as_deref())
            .or_else(|| self.handles.first().map(String::as_str))
            .map(str::to_owned)
            .unwrap_or_else(|| member_identity_fallback_label(&self.actor_id))
    }

    fn public_label(&self) -> String {
        self.display_name
            .as_deref()
            .or_else(|| self.handles.first().map(String::as_str))
            .map(str::to_owned)
            .unwrap_or_else(|| member_identity_fallback_label(&self.actor_id))
    }

    fn role_label(&self) -> &'static str {
        if self.is_owner {
            "Realm owner"
        } else if self.is_admin {
            "Realm admin"
        } else {
            "Realm member"
        }
    }

    fn normalized_membership(&self) -> Option<&str> {
        self.membership
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn is_pending_invite(&self) -> bool {
        matches!(
            self.normalized_membership(),
            Some("invite" | "pending" | "pending_invite")
        )
    }

    fn is_governance_principal(&self) -> bool {
        self.is_owner || self.is_admin
    }
}

fn member_identity_fallback_label(did: &str) -> String {
    short_protocol_id(did)
}

#[derive(Clone, Debug, PartialEq)]
struct MemberGroup {
    controller: MemberProfile,
    agents: Vec<MemberAgentRow>,
}

fn member_agent_row_from_value(
    row: arkret_models_collaboration::agent_operations::AgentProjection,
    fallback_controller_id: &str,
) -> Option<MemberAgentRow> {
    let agent_id = row.agent_id.as_str().trim();
    if agent_id.is_empty() {
        return None;
    }
    let agent_id = agent_id.to_owned();
    let slug = row.slug.trim().to_owned();
    if slug.is_empty() {
        return None;
    }
    let display_name = slug.clone();
    // `agent_projection` carries no controller binding; the list endpoint is
    // already scoped to the caller's owned agents, so use the caller DID.
    let controller_id = fallback_controller_id.trim().to_owned();
    Some(MemberAgentRow {
        agent_id,
        controller_id,
        display_name,
        slug,
        status: crate::views::agents::model::agent_lifecycle_wire(row.lifecycle).to_owned(),
        runtime_state: crate::views::agents::model::agent_runtime_state_wire(
            crate::views::agents::model::agent_projection_runtime_state(&row),
        )
        .to_owned(),
        mention_policy: AgentMentionPolicy::Unknown,
        selection: ParticipationBits::NONE,
    })
}

async fn fetch_owned_agent_rows(
    http: &arkret_sdk::http_client::Client,
    realm: &str,
    fallback_controller_id: &str,
) -> anyhow::Result<Vec<MemberAgentRow>> {
    let list = http.agent_list().await?;
    let mut rows = Vec::<MemberAgentRow>::new();
    for value in list.agents {
        let Some(mut row) = member_agent_row_from_value(value, fallback_controller_id) else {
            continue;
        };
        // Deactivated agents (lifecycle terminal) and never-keyed agents whose
        // bootstrap window lapsed (runtime_state pairing_expired) can never join
        // a Realm. Pending agents stay because Realm membership/grants are
        // independent from key pairing (key-management.md §3.6.1), although the
        // agent cannot act until it has an authorized runtime key.
        if row.status == "deactivated" || row.runtime_state == "pairing_expired" {
            continue;
        }
        match http.agent_participation_get(&row.agent_id).await {
            Ok(outcome) => {
                let (policy, selection) = mention_state_from_entries(&outcome.entries, realm);
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
        left.display_name
            .cmp(&right.display_name)
            .then_with(|| left.agent_id.cmp(&right.agent_id))
    });
    Ok(rows)
}

fn spawn_set_agent_realm_behavior(
    base: String,
    api_token: String,
    realm: String,
    agent_id: String,
    selection: ParticipationBits,
    mut owned_agents: Signal<Vec<MemberAgentRow>>,
    mut status_msg: Signal<String>,
) {
    spawn(async move {
        let realm_id = match arkret_sdk::RealmId::new(realm.clone()) {
            Ok(realm_id) => realm_id,
            Err(err) => {
                status_msg.set(format!("invalid realm id: {err:?}"));
                return;
            }
        };
        let scope = ParticipationScope::Realm { realm_id };
        match crate::transport::auth::with_authed_sdk_client(&base, api_token, |http| {
            let scope = scope.clone();
            let agent_id = agent_id.clone();
            async move {
                crate::transport::account::replace_agent_participation(
                    &http, &agent_id, scope, selection,
                )
                .await
            }
        })
        .await
        {
            Ok(outcome) => {
                let (mention_policy, selection) =
                    mention_state_from_entries(&outcome.entries, &realm);
                owned_agents.with_mut(|rows| {
                    if let Some(row) = rows.iter_mut().find(|row| row.agent_id == outcome.agent_id)
                    {
                        row.mention_policy = mention_policy;
                        row.selection = selection;
                    }
                });
                status_msg.set(format!(
                    "Realm behavior updated for {}",
                    short_protocol_id(&outcome.agent_id)
                ));
            }
            Err(err) => status_msg.set(format!("Realm behavior update failed: {}", err.display())),
        }
    });
}

fn mention_state_from_entries(
    entries: &[AgentParticipationEntry],
    realm_id: &str,
) -> (AgentMentionPolicy, ParticipationBits) {
    let mut selection = ParticipationBits::NONE;
    let mut matched = false;
    for entry in entries {
        match &entry.scope {
            ParticipationScope::Realm {
                realm_id: entry_realm,
            } if entry_realm.as_str() == realm_id => {
                matched = true;
                selection = entry.selection;
                if entry.selection.accept_third_party_mention {
                    return (AgentMentionPolicy::Allowed, selection);
                }
            }
            _ => {}
        }
    }
    if matched {
        (AgentMentionPolicy::OwnerOnly, selection)
    } else {
        (AgentMentionPolicy::OwnerOnly, ParticipationBits::NONE)
    }
}

fn trimmed_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn principal_core_key(value: &str) -> Option<String> {
    let value = value.trim();
    arkret_sdk::DidCoreId::new(value.to_owned())
        .ok()
        .map(|id| id.as_str().to_owned())
        .or_else(|| {
            arkret_sdk::DidFullId::new(value.to_owned())
                .ok()
                .and_then(|id| arkret_sdk::project_full_id_to_core_id(&id).ok())
                .map(|id| id.as_str().to_owned())
        })
}

fn same_principal_core(left: &str, right: &str) -> bool {
    principal_core_key(left)
        .zip(principal_core_key(right))
        .is_some_and(|(left, right)| left == right)
}

fn push_unique(out: &mut Vec<String>, value: impl Into<String>) {
    let value = value.into();
    let value = value.trim();
    if value.is_empty() || out.iter().any(|existing| existing == value) {
        return;
    }
    out.push(value.to_owned());
}

fn normalize_handle_label(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    crate::identity::handle::parse_user_handle(raw)
        .map(|handle| handle.display)
        .or_else(|| Some(raw.to_owned()))
}

fn merge_member_profile(target: &mut MemberProfile, incoming: MemberProfile) {
    if target.subject_id.is_none() {
        target.subject_id = incoming.subject_id;
    }
    if target.invite_id.is_none() {
        target.invite_id = incoming.invite_id;
    }
    if target.invite_is_direct.is_none() {
        target.invite_is_direct = incoming.invite_is_direct;
    }
    if target.display_name.is_none() {
        target.display_name = incoming.display_name;
    }
    if target.avatar_blob_ref.is_none() {
        target.avatar_blob_ref = incoming.avatar_blob_ref;
    }
    for handle in incoming.handles {
        push_unique(&mut target.handles, handle);
    }
    if should_replace_member_membership(
        target.membership.as_deref(),
        incoming.membership.as_deref(),
    ) {
        target.membership = incoming.membership;
    }
    if target.member_display_state_digest.is_none() {
        target.member_display_state_digest = incoming.member_display_state_digest;
    }
    target.is_owner |= incoming.is_owner;
    target.is_admin |= incoming.is_admin;
    target.confusable_contact_warning |= incoming.confusable_contact_warning;
}

fn should_replace_member_membership(current: Option<&str>, incoming: Option<&str>) -> bool {
    let Some(incoming) = normalize_membership_value(incoming) else {
        return false;
    };
    let current = normalize_membership_value(current);
    current.is_none() || membership_precedence(Some(incoming)) > membership_precedence(current)
}

fn normalize_membership_value(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn membership_precedence(value: Option<&str>) -> u8 {
    match normalize_membership_value(value) {
        Some("ban" | "leave") => 5,
        Some("join") => 4,
        Some("invite" | "pending" | "pending_invite") => 2,
        Some("knock") => 1,
        Some(_) => 3,
        None => 0,
    }
}

fn upsert_member_profile(out: &mut BTreeMap<String, MemberProfile>, profile: MemberProfile) {
    match out.entry(profile.actor_id.clone()) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(profile);
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            merge_member_profile(entry.get_mut(), profile);
        }
    }
}

fn projected_member_profiles_for_realm(
    store: &LocalStateStore,
    realm_id: &str,
) -> Vec<MemberProfile> {
    let state = store.load();
    let mut rows = BTreeMap::<String, MemberProfile>::new();
    let contact_anchor_index = crate::views::member_display::contact_petname_binding_index(
        &store.active_contact_remarks(),
    );
    if let Some(projection) = state.realm_tree_projections.get(realm_id) {
        for row in crate::views::member_display::realm_member_roster(Some(projection)) {
            let display =
                crate::views::member_display::resolve_member_display(store, realm_id, &row);
            let mut profile = MemberProfile::bare(row.actor_id);
            profile.confusable_contact_warning =
                crate::views::member_display::public_display_conflicts_with_other_contact(
                    &contact_anchor_index,
                    display.subject_id.as_deref(),
                    &display.collision_public_display,
                );
            profile.subject_id = display.subject_id;
            profile.display_name = display.display_name;
            profile.avatar_blob_ref = display.avatar_blob_ref;
            profile.handles = display.primary_handle.into_iter().collect();
            profile.membership = row.membership;
            profile.member_display_state_digest = row.member_display_state_digest;
            upsert_member_profile(&mut rows, profile);
        }
    }
    // Ownership is not a roster decoration. The only authorization-grade
    // source is the Realm authority-root cell derived from the accepted
    // `ak.realm.create` Event, so classify the owner from that projected Event
    // rather than the discarded `owners` / `admins` presentation mirrors.
    if let Some(owner_id) = crate::security_state::realm_authority_root_controller_for_realm(
        &state.realm_tree_projections,
        realm_id,
    ) {
        let mut owner = MemberProfile::bare(owner_id);
        owner.membership = Some("join".to_owned());
        owner.is_owner = true;
        upsert_member_profile(&mut rows, owner);
    }
    let invitee_by_invite_id =
        local_invitee_by_invite_id_for_realm(&state.raw_operations, realm_id);
    for record in &state.raw_operations {
        if let Some(profile) =
            local_membership_profile_from_raw_operation(record, realm_id, &invitee_by_invite_id)
        {
            upsert_member_profile(&mut rows, profile);
        }
    }
    let locally_terminal_invites =
        local_terminal_invite_ids_for_realm(&state.raw_operations, realm_id);
    for record in &state.raw_operations {
        if let Some(profile) = local_pending_invite_profile_from_raw_operation(record, realm_id) {
            if profile
                .invite_id
                .as_deref()
                .is_some_and(|invite_id| locally_terminal_invites.contains(invite_id))
            {
                continue;
            }
            upsert_member_profile(&mut rows, profile);
        }
    }
    let mut out: Vec<MemberProfile> = rows.into_values().collect();
    for profile in &mut out {
        // Realm actor ids are not Contact identity keys. Join a global
        // petname only through the verified subject projection.
        if let Some(remark) = profile
            .subject_id
            .as_deref()
            .and_then(|principal_id| store.active_contact_remark(principal_id))
        {
            profile.remark_name =
                (!remark.petname.trim().is_empty()).then(|| remark.petname.trim().to_owned());
            profile.remark_note =
                (!remark.note.trim().is_empty()).then(|| remark.note.trim().to_owned());
        }
    }
    out
}

fn local_terminal_invite_ids_for_realm(
    records: &[RawOperationRecord],
    realm_id: &str,
) -> BTreeSet<String> {
    records
        .iter()
        .filter(|record| raw_operation_realm_matches_exact(record, realm_id))
        .filter_map(|record| {
            let payload = &record.payload;
            match raw_operation_payload_kind(payload).as_deref() {
                Some(event_kind_str::INVITE_ACCEPT) if raw_operation_is_accepted_fact(payload) => {
                    raw_operation_invite_ref(payload)
                }
                Some(event_kind_str::INVITE_CANCEL | event_kind_str::INVITE_REVOKE) => {
                    raw_operation_invite_ref(payload)
                }
                _ => None,
            }
        })
        .collect()
}

fn group_members_with_owned_agents(
    members: &[MemberProfile],
    owned_agents: &[MemberAgentRow],
    fallback_controller_id: &str,
) -> Vec<MemberGroup> {
    let member_set: BTreeSet<&str> = members
        .iter()
        .map(|member| member.actor_id.as_str())
        .collect();
    let owned_agent_ids: BTreeSet<&str> = owned_agents
        .iter()
        .map(|agent| agent.agent_id.as_str())
        .collect();
    let mut groups = BTreeMap::<String, MemberGroup>::new();

    for member in members {
        if owned_agent_ids.contains(member.actor_id.as_str()) {
            continue;
        }
        groups
            .entry(member.actor_id.clone())
            .or_insert_with(|| MemberGroup {
                controller: member.clone(),
                agents: Vec::new(),
            });
    }
    let member_by_actor: BTreeMap<&str, &MemberProfile> = members
        .iter()
        .map(|member| (member.actor_id.as_str(), member))
        .collect();

    let mut in_realm_agents: Vec<MemberAgentRow> = owned_agents
        .iter()
        .filter(|agent| member_set.contains(agent.agent_id.as_str()))
        .cloned()
        .collect();
    in_realm_agents.sort_by(|a, b| {
        a.display_name
            .cmp(&b.display_name)
            .then_with(|| a.agent_id.cmp(&b.agent_id))
    });
    for agent in in_realm_agents {
        let controller = agent.controller_id.trim();
        let controller = if controller.is_empty() {
            fallback_controller_id.trim()
        } else {
            controller
        };
        if !controller.is_empty() {
            let controller_profile = member_by_actor
                .get(controller)
                .map(|member| (*member).clone())
                .unwrap_or_else(|| MemberProfile::bare(controller.to_owned()));
            groups
                .entry(controller.to_owned())
                .or_insert_with(|| MemberGroup {
                    controller: controller_profile,
                    agents: Vec::new(),
                })
                .agents
                .push(agent);
        }
    }

    let mut groups = groups.into_values().collect::<Vec<_>>();
    groups.sort_by(|left, right| {
        let left_is_self = same_principal_core(&left.controller.actor_id, fallback_controller_id);
        let right_is_self = same_principal_core(&right.controller.actor_id, fallback_controller_id);
        right_is_self
            .cmp(&left_is_self)
            .then_with(|| {
                left.controller
                    .primary_label()
                    .cmp(&right.controller.primary_label())
            })
            .then_with(|| left.controller.actor_id.cmp(&right.controller.actor_id))
    });
    groups
}

fn split_owned_agents_for_realm(
    owned_agents: &[MemberAgentRow],
    member_set: &BTreeSet<String>,
) -> (Vec<MemberAgentRow>, Vec<MemberAgentRow>) {
    let joined = owned_agents
        .iter()
        .filter(|agent| member_set.contains(&agent.agent_id))
        .cloned()
        .collect();
    let available = owned_agents
        .iter()
        .filter(|agent| !member_set.contains(&agent.agent_id) && agent.status == "active")
        .cloned()
        .collect();
    (joined, available)
}

fn split_member_profiles(members: Vec<MemberProfile>) -> (Vec<MemberProfile>, Vec<MemberProfile>) {
    let mut active_members = Vec::new();
    let mut pending_invites = Vec::new();
    for member in members {
        if member.is_pending_invite() {
            pending_invites.push(member);
        } else {
            active_members.push(member);
        }
    }
    (active_members, pending_invites)
}

fn upsert_pending_invite_profile(
    rows: &mut Vec<MemberProfile>,
    actor_id: &str,
    label: Option<&str>,
    invite_id: Option<&str>,
) {
    let Some(actor_id) = principal_core_key(actor_id) else {
        return;
    };
    let actor_id = actor_id.as_str();
    let apply_label = |profile: &mut MemberProfile| {
        let Some(label) = label.map(str::trim).filter(|value| !value.is_empty()) else {
            return;
        };
        if label == actor_id {
            return;
        }
        if label.starts_with("did:") {
            if profile.display_name.is_none() {
                profile.display_name = Some(short_protocol_id(label));
            }
            return;
        }
        if let Some(handle) = normalize_handle_label(label) {
            push_unique(&mut profile.handles, handle);
        }
    };
    if let Some(existing) = rows
        .iter_mut()
        .find(|profile| profile.actor_id.trim() == actor_id)
    {
        if existing.normalized_membership() != Some("join") {
            existing.membership = Some("invite".to_owned());
        }
        if existing.invite_id.is_none() {
            existing.invite_id = invite_id
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
        }
        if existing.invite_is_direct.is_none() {
            existing.invite_is_direct = Some(true);
        }
        apply_label(existing);
        return;
    }
    let mut profile = MemberProfile::bare(actor_id.to_owned());
    profile.membership = Some("invite".to_owned());
    profile.invite_id = invite_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    profile.invite_is_direct = Some(true);
    apply_label(&mut profile);
    rows.push(profile);
    rows.sort_by(|left, right| left.actor_id.cmp(&right.actor_id));
}

fn local_pending_invite_profile_from_raw_operation(
    record: &RawOperationRecord,
    realm_id: &str,
) -> Option<MemberProfile> {
    if !raw_operation_realm_matches_exact(record, realm_id) {
        return None;
    }
    let payload = &record.payload;
    if raw_operation_payload_kind(payload).as_deref() != Some(event_kind_str::INVITE_CREATE) {
        return None;
    }
    let state = trimmed_string(payload.get("state").or_else(|| payload.get("status")))
        .unwrap_or_else(|| "pending".to_owned());
    if !matches!(state.as_str(), "pending" | "pending_invite" | "invite") {
        return None;
    }
    let direct_invitee = trimmed_string(payload.get("invitee"))
        .and_then(|invitee| arkret_sdk::DidCoreId::new(invitee).ok())
        .map(|invitee| invitee.as_str().to_owned());
    let invite_id = trimmed_string(payload.get("invite_id").or_else(|| payload.get("id")));
    let actor_id = direct_invitee
        .clone()
        .or_else(|| {
            trimmed_string(
                payload
                    .get("invitee_label")
                    .or_else(|| payload.get("threepid"))
                    .or_else(|| payload.get("address"))
                    .or_else(|| payload.get("token_hint")),
            )
        })
        .or_else(|| invite_id.as_ref().map(|id| format!("invite:{id}")))?;
    let mut profile = MemberProfile::bare(actor_id.clone());
    profile.membership = Some("invite".to_owned());
    profile.invite_id = invite_id;
    profile.invite_is_direct = Some(direct_invitee.is_some());
    if let Some(label) = trimmed_string(
        payload
            .get("invitee_label")
            .or_else(|| payload.get("handle"))
            .or_else(|| payload.get("label")),
    ) && label != actor_id
    {
        if label.starts_with("did:") {
            profile.display_name = Some(short_protocol_id(&label));
        } else if let Some(handle) = normalize_handle_label(&label) {
            push_unique(&mut profile.handles, handle);
        }
    }
    Some(profile)
}

/// Realm filter with fail-CLOSED semantics: only records whose `realm_id`
/// exactly matches are included; unknown ownership is excluded. Contrast with
/// `chat::model::agents::raw_operation_realm_matches_or_unscoped`, which
/// fail-opens for unscoped local operations.
fn raw_operation_realm_matches_exact(record: &RawOperationRecord, realm_id: &str) -> bool {
    record.realm_id.as_deref().map(str::trim) == Some(realm_id.trim())
}

fn raw_operation_payload_kind(payload: &Value) -> Option<String> {
    trimmed_string(payload.get("kind").or_else(|| payload.get("wire_kind")))
}

fn raw_operation_path_string(payload: &Value, path: &[&str]) -> Option<String> {
    let mut current = payload;
    for segment in path {
        current = current.get(*segment)?;
    }
    trimmed_string(Some(current))
}

fn raw_operation_is_accepted_fact(payload: &Value) -> bool {
    matches!(
        raw_operation_path_string(payload, &["write_state"]).as_deref(),
        Some("synced" | "accepted")
    ) || raw_operation_path_string(payload, &["event_id"]).is_some()
        || raw_operation_path_string(payload, &["body", "event_id"]).is_some()
        || raw_operation_path_string(payload, &["payload", "event_id"]).is_some()
}

fn raw_operation_invite_ref(payload: &Value) -> Option<String> {
    raw_operation_path_string(payload, &["body", "invite_ref"])
        .or_else(|| raw_operation_path_string(payload, &["body", "invite_id"]))
        .or_else(|| raw_operation_path_string(payload, &["payload", "invite_ref"]))
        .or_else(|| raw_operation_path_string(payload, &["payload", "invite_id"]))
        .or_else(|| {
            trimmed_string(
                payload
                    .get("invite_ref")
                    .or_else(|| payload.get("invite_id")),
            )
        })
        .or_else(|| trimmed_string(payload.get("id")))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AcceptedInviteClaimRoute {
    destination_service_id: String,
    target_device_id: Option<String>,
}

fn accepted_invite_claim_route(
    store: &LocalStateStore,
    realm_id: &str,
    invitee_did: &str,
) -> Option<AcceptedInviteClaimRoute> {
    let state = store.load();
    let accepted = state
        .raw_operations
        .iter()
        .rev()
        .filter(|record| raw_operation_realm_matches_exact(record, realm_id))
        .find_map(|record| {
            let payload = &record.payload;
            if raw_operation_payload_kind(payload).as_deref() != Some(event_kind_str::INVITE_ACCEPT)
                || !raw_operation_is_accepted_fact(payload)
                || raw_operation_path_string(payload, &["actor_id"]).as_deref() != Some(invitee_did)
            {
                return None;
            }
            Some((
                raw_operation_invite_ref(payload)?,
                raw_operation_path_string(payload, &["signing_device_id"]),
            ))
        })?;
    let destination_service_id = state
        .raw_operations
        .iter()
        .rev()
        .filter(|record| raw_operation_realm_matches_exact(record, realm_id))
        .find_map(|record| {
            let payload = &record.payload;
            if raw_operation_payload_kind(payload).as_deref() != Some(event_kind_str::INVITE_CREATE)
                || !raw_operation_is_accepted_fact(payload)
                || raw_invite_create_invitee(payload).as_deref() != Some(invitee_did)
                || raw_operation_invite_ref(payload).as_deref() != Some(accepted.0.as_str())
            {
                return None;
            }
            let service_id = raw_operation_path_string(payload, &["recipient_service_id"])?;
            arkret_sdk::DidCoreId::new(service_id.clone())
                .ok()
                .map(|_| service_id)
        })?;
    let target_device_id = accepted
        .1
        .map(arkret_sdk::DeviceId::new)
        .transpose()
        .ok()?
        .map(|device| device.to_string());
    Some(AcceptedInviteClaimRoute {
        destination_service_id,
        target_device_id,
    })
}

fn claim_target_device_id(
    route: &AcceptedInviteClaimRoute,
    minimal_metadata_pairwise: bool,
) -> anyhow::Result<Option<&str>> {
    if minimal_metadata_pairwise {
        return Ok(None);
    }
    route.target_device_id.as_deref().map(Some).ok_or_else(|| {
        anyhow::anyhow!(
            "accepted human invite has no exact target device from its accepted Event proof"
        )
    })
}

fn raw_member_actor_id(payload: &Value) -> Option<String> {
    raw_operation_path_string(payload, &["body", "actor_id"])
        .or_else(|| raw_operation_path_string(payload, &["body", "member"]))
        .or_else(|| raw_operation_path_string(payload, &["body", "invitee"]))
        .or_else(|| raw_operation_path_string(payload, &["payload", "actor_id"]))
        .or_else(|| raw_operation_path_string(payload, &["payload", "member"]))
        .or_else(|| raw_operation_path_string(payload, &["payload", "invitee"]))
        .or_else(|| trimmed_string(payload.get("member").or_else(|| payload.get("invitee"))))
        .or_else(|| trimmed_string(payload.get("actor_id")))
        .and_then(|actor_id| arkret_sdk::DidCoreId::new(actor_id).ok())
        .map(|actor_id| actor_id.as_str().to_owned())
}

fn raw_member_membership(payload: &Value) -> Option<String> {
    raw_operation_path_string(payload, &["body", "membership"])
        .or_else(|| raw_operation_path_string(payload, &["payload", "membership"]))
        .or_else(|| {
            trimmed_string(
                payload
                    .get("membership")
                    .or_else(|| payload.get("state"))
                    .or_else(|| payload.get("status")),
            )
        })
}

fn raw_invite_create_invitee(payload: &Value) -> Option<String> {
    raw_operation_path_string(payload, &["body", "invitee"])
        .or_else(|| raw_operation_path_string(payload, &["payload", "invitee"]))
        .or_else(|| trimmed_string(payload.get("invitee")))
        .or_else(|| raw_member_actor_id(payload))
}

fn local_invitee_by_invite_id_for_realm(
    records: &[RawOperationRecord],
    realm_id: &str,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for record in records {
        if !raw_operation_realm_matches_exact(record, realm_id) {
            continue;
        }
        let payload = &record.payload;
        if raw_operation_payload_kind(payload).as_deref() != Some(event_kind_str::INVITE_CREATE) {
            continue;
        }
        let Some(invite_id) = raw_operation_invite_ref(payload) else {
            continue;
        };
        let Some(invitee) = raw_invite_create_invitee(payload) else {
            continue;
        };
        out.insert(invite_id, invitee);
    }
    out
}

fn local_membership_profile_from_raw_operation(
    record: &RawOperationRecord,
    realm_id: &str,
    invitee_by_invite_id: &BTreeMap<String, String>,
) -> Option<MemberProfile> {
    if !raw_operation_realm_matches_exact(record, realm_id) {
        return None;
    }
    let payload = &record.payload;
    if !raw_operation_is_accepted_fact(payload) {
        return None;
    }
    match raw_operation_payload_kind(payload).as_deref()? {
        event_kind_str::MEMBER_STATE => {
            let actor_id = raw_member_actor_id(payload)?;
            let membership = raw_member_membership(payload)?;
            let mut profile = MemberProfile::bare(actor_id);
            profile.membership = Some(membership);
            profile.invite_id = raw_operation_invite_ref(payload);
            Some(profile)
        }
        event_kind_str::INVITE_ACCEPT => {
            let invite_id = raw_operation_invite_ref(payload);
            let actor_id = raw_member_actor_id(payload).or_else(|| {
                invite_id
                    .as_ref()
                    .and_then(|invite_id| invitee_by_invite_id.get(invite_id).cloned())
            })?;
            let mut profile = MemberProfile::bare(actor_id);
            profile.membership = Some("join".to_owned());
            profile.invite_id = invite_id;
            Some(profile)
        }
        _ => None,
    }
}

fn member_profile_matches(profile: &MemberProfile, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return true;
    }
    profile.actor_id.to_lowercase().contains(&query)
        || profile.primary_label().to_lowercase().contains(&query)
        || profile.public_label().to_lowercase().contains(&query)
        || profile
            .remark_note
            .as_deref()
            .unwrap_or("")
            .to_lowercase()
            .contains(&query)
        || profile
            .handles
            .iter()
            .any(|handle| handle.to_lowercase().contains(&query))
        || short_protocol_id(&profile.actor_id)
            .to_lowercase()
            .contains(&query)
}

fn member_group_matches(group: &MemberGroup, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return true;
    }
    member_profile_matches(&group.controller, &query)
        || group.agents.iter().any(|agent| {
            agent.agent_id.to_lowercase().contains(&query)
                || agent.display_name.to_lowercase().contains(&query)
                || agent.slug.to_lowercase().contains(&query)
        })
}

fn member_group_in_section(
    group: &MemberGroup,
    section: MemberRosterSection,
    principal_id: &str,
) -> bool {
    match section {
        MemberRosterSection::Members => !group.controller.is_governance_principal(),
        MemberRosterSection::Owners => group.controller.is_owner,
        MemberRosterSection::Admins => group.controller.is_admin && !group.controller.is_owner,
        MemberRosterSection::MyAgents => {
            same_principal_core(&group.controller.actor_id, principal_id)
        }
        MemberRosterSection::PendingInvites => false,
    }
}

fn member_line_identity_visible(
    identity_label: &str,
    primary_label: &str,
    handles: &[String],
) -> bool {
    let identity = identity_label.trim();
    !identity.is_empty()
        && identity != primary_label.trim()
        && !handles.iter().any(|handle| handle.trim() == identity)
}

fn member_handles_for_line(handles: &[String], primary_label: &str) -> Vec<String> {
    let primary = primary_label.trim();
    match handles {
        [] => Vec::new(),
        [handle] if handle.trim() == primary => Vec::new(),
        [_] => handles.to_vec(),
        _ if handles.iter().any(|handle| handle.trim() == primary) => handles
            .iter()
            .filter(|handle| handle.trim() != primary)
            .cloned()
            .collect(),
        _ => handles.to_vec(),
    }
}

fn member_handles_line_label(all_handles: &[String], visible_handles: &[String]) -> &'static str {
    if visible_handles.len() == all_handles.len() {
        "Handles"
    } else {
        "Other handles"
    }
}

#[component]
fn MemberRowActions(
    token: Signal<String>,
    principal_id: String,
    selected_realm_id: String,
    target_did: String,
    target_label: String,
    can_remove: bool,
    is_self: bool,
    #[props(default)] leave_disabled_reason: Option<String>,
    sync_cursor: Signal<String>,
    mut status_msg: Signal<String>,
    mut block_confirm_did: Signal<Option<String>>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = crate::app::SessionContext::get().state_store;
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
                        let base = base_url.clone();
                        let realm = selected_realm_id.clone();
                        let actor_principal_id = principal_id.clone();
                        let disabled_reason = leave_disabled_reason.clone();
                        move |_| {
                            if let Some(reason) = disabled_reason.clone() {
                                status_msg.set(reason);
                                return;
                            }
                            let base = base.clone();
                            let realm = realm.clone();
                            let api_token = token();
                            let actor_id = actor_principal_id.trim().to_owned();
                            if actor_id.is_empty() {
                                status_msg.set("Leave Realm failed: account is not connected".to_owned());
                                return;
                            }
                            spawn(async move {
                                let realm_for_msg = realm.clone();
                                match crate::transport::auth::with_event_submitter(
                                    &base,
                                    api_token,
                                    |sub| async move {
                                        crate::transport::realm_write::leave_realm(&sub, &realm, &actor_id).await
                                    },
                                )
                                .await
                                {
                                    Ok(_) => {
                                        state_store.write().forget_realm_tree_projection(&realm_for_msg);
                                        sync_cursor.set(String::new());
                                        status_msg.set(format!(
                                            "left {realm_for_msg}; local cache cleared"
                                        ));
                                    }
                                    Err(err) => status_msg.set(format!(
                                        "leave failed: {}", err.display()
                                    )),
                                }
                            });
                        }
                    },
                    {crate::i18n::tr("realm_admin.leave_realm")}
                }
            } else if can_remove {
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "kick-member-button",
                    onclick: {
                        let base = base_url.clone();
                        let realm = selected_realm_id.clone();
                        let target = target_did.clone();
                        let target_label = target_label.clone();
                        let actor_principal_id = principal_id.clone();
                        move |_| {
                            let base = base.clone();
                            let realm = realm.clone();
                            let target = target.clone();
                            let target_label = target_label.clone();
                            let api_token = token();
                            let actor_id = actor_principal_id.clone();
                            spawn(async move {
                                let realm_for_api = realm.clone();
                                match crate::transport::auth::with_event_submitter(
                                    &base,
                                    api_token,
                                    |sub| async move {
                                        crate::transport::realm_write::transition_member_state(
                                            &sub,
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
                                            state_store.write().record_move_submission(
                                                format!("mls-binding:{}", resp.event_id),
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
                                            target_label,
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
                        let target_label = target_label.clone();
                        let actor_principal_id = principal_id.clone();
                        move |_| {
                            let base = base.clone();
                            let realm = realm.clone();
                            let target = target.clone();
                            let target_label = target_label.clone();
                            let api_token = token();
                            let actor_id = actor_principal_id.clone();
                            spawn(async move {
                                let realm_for_api = realm.clone();
                                match crate::transport::auth::with_event_submitter(
                                    &base,
                                    api_token,
                                    |sub| async move {
                                        crate::transport::realm_write::ban_member(&sub, &realm_for_api, &actor_id, &target).await
                                    },
                                )
                                .await
                                {
                                    Ok(resp) => {
                                        let mls_encrypted = state_store
                                            .read()
                                            .realm_projection_is_mls_encrypted(&realm);
                                        if mls_encrypted {
                                            state_store.write().record_move_submission(
                                                format!("mls-binding:{}", resp.event_id),
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
                                            target_label,
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
            if !is_self {
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
        }
        if !is_self && block_confirm_did().as_deref() == Some(target_did.as_str()) {
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
                            let target_label = target_label.clone();
                            move |_| {
                                let changed = state_store
                                    .write()
                                    .block_user(&target, None);
                                block_confirm_did.set(None);
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
                        onclick: move |_| block_confirm_did.set(None),
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
    token: Signal<String>,
    principal_id: String,
    selected_realm_id: String,
    can_cancel_invite: bool,
    can_revoke_invite: bool,
    mut members: Signal<Vec<MemberProfile>>,
    mut frontier_state: Signal<String>,
    mut status_msg: Signal<String>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = crate::app::SessionContext::get().state_store;
    let member = profile.actor_id.clone();
    let member_label = profile.primary_label();
    let avatar_blob_ref = profile.avatar_blob_ref.as_ref().map(ToString::to_string);
    let invite_id = profile.invite_id.clone().unwrap_or_default();
    let invite_class_known = profile.invite_is_direct.is_some();
    let direct_invitee = profile
        .invite_is_direct
        .is_some_and(|direct| direct)
        .then(|| arkret_sdk::DidCoreId::new(member.clone()).ok())
        .flatten()
        .map(|invitee| invitee.to_string());
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
            "data-member-did": "{member}",
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
                        span { class: "member-row-primary", title: "{member}", "{member_label}" }
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
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor = principal_id.clone();
                            let invite_id = invite_id.clone();
                            let member = member.clone();
                            let member_label = member_label.clone();
                            let direct_invitee = direct_invitee.clone();
                            move |_| {
                                if invite_id.trim().is_empty() {
                                    status_msg.set("invite id is not available yet".to_owned());
                                    return;
                                }
                                let base = base.clone();
                                let realm = realm.clone();
                                let actor = actor.clone();
                                let invite_id = invite_id.clone();
                                let member = member.clone();
                                let member_label = member_label.clone();
                                let direct_invitee = direct_invitee.clone();
                                let api_token = token();
                                spawn(async move {
                                    let request_realm = realm.clone();
                                    let request_invite_id = invite_id.clone();
                                    let request_invitee = direct_invitee.clone();
                                    let is_direct = request_invitee.is_some();
                                    match crate::transport::auth::with_event_submitter(
                                        &base,
                                        api_token,
                                        |sub| async move {
                                            if let Some(invitee) = request_invitee {
                                                crate::transport::realm_write::cancel_realm_invite(
                                                    &sub,
                                                    &request_realm,
                                                    &actor,
                                                    &request_invite_id,
                                                    &invitee,
                                                    "revoked",
                                                    Some("admin_cancel"),
                                                )
                                                .await
                                            } else {
                                                crate::transport::realm_write::revoke_realm_invite(
                                                    &sub,
                                                    &request_realm,
                                                    &actor,
                                                    &request_invite_id,
                                                    None,
                                                    "revoked",
                                                    "admin_revoke",
                                                )
                                                .await
                                            }
                                        },
                                    )
                                    .await
                                    {
                                        Ok(resp) => {
                                            frontier_state.set(resp.event_id.clone());
                                            state_store.write().append_raw_operation(
                                                format!("ak:operation:{}", crate::operation::uuid_v7()),
                                                Some(realm.clone()),
                                                json!({
                                                    "kind": if is_direct {
                                                        event_kind_str::INVITE_CANCEL
                                                    } else {
                                                        event_kind_str::INVITE_REVOKE
                                                    },
                                                    "invite_id": invite_id.clone(),
                                                    "invitee": direct_invitee.clone(),
                                                    "state": "revoked",
                                                    "event_id": resp.event_id,
                                                }),
                                            );
                                            let mut next_members = members.read().clone();
                                            next_members.retain(|profile| {
                                                profile.invite_id.as_deref() != Some(invite_id.as_str())
                                                    && !(profile.actor_id == member && profile.is_pending_invite())
                                            });
                                            members.set(next_members);
                                            status_msg.set(format!(
                                                "{} invite for {member_label}",
                                                if is_direct { "cancelled" } else { "revoked" }
                                            ));
                                        }
                                        Err(err) => status_msg.set(format!(
                                            "cancel invite failed: {}",
                                            err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        {if is_direct_invite { "Cancel invite" } else { "Revoke invite" }}
                    }
                }
            }
        }
    }
}

async fn retain_current_history_secret_durable(
    mut state_store: SyncSignal<LocalStateStore>,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> anyhow::Result<Option<(u64, zeroize::Zeroizing<Vec<u8>>)>> {
    let account = crate::app::SessionContext::get()
        .active_account()
        .ok_or_else(|| anyhow::anyhow!("active account context is unavailable"))?;
    anyhow::ensure!(
        account.full_id().as_str() == actor_id && account.device_id.as_str() == device_id,
        "MLS history retention identity does not match the active account"
    );
    let derived = {
        let store = state_store.read();
        crate::mls::runtime::derive_and_retain_realm_history_secret(
            &store,
            secure_store,
            realm_id,
            &account.authority,
            &account.device_id,
        )
    }
    .map_err(|error| anyhow::anyhow!(error.user_message()))?;
    let Some((epoch, secret, pending)) = derived else {
        return Ok(None);
    };
    pending.persist(secure_store).await?;
    state_store.write().publish_history_secrets(pending);
    Ok(Some((epoch, secret)))
}

fn mls_admission_authoring_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub(crate) async fn submit_mls_admission_for_invitee(
    api: &crate::transport::TransportClient,
    state_store: SyncSignal<LocalStateStore>,
    realm_id: String,
    actor_id: String,
    device_id: String,
    invitee_did: String,
) -> anyhow::Result<Option<u64>> {
    let _authoring_guard = mls_admission_authoring_lock().lock().await;
    let account = crate::app::SessionContext::get()
        .active_account()
        .ok_or_else(|| anyhow::anyhow!("active account context is unavailable"))?;
    anyhow::ensure!(
        account.full_id().as_str() == actor_id && account.device_id.as_str() == device_id,
        "MLS admission identity does not match the active account"
    );
    let needs_mls_admission = {
        let store = state_store.read();
        store.mls_snapshot_for(&realm_id).is_some()
            || store.realm_projection_is_mls_encrypted(&realm_id)
    };
    if !needs_mls_admission {
        return Ok(None);
    }
    let admission_submitter = api.event_submitter()?;
    if admission_submitter
        .has_pending_mls_admission_for_realm(&realm_id)
        .await?
    {
        let advanced = admission_submitter
            .drain_mls_outbound_with_accepted_store(state_store)
            .await?;
        tracing::warn!(
            target: "mls_admission",
            realm = %short_protocol_id(&realm_id),
            invitee = %short_protocol_id(&invitee_did),
            advanced,
            "admission deferred: drove the exact durable admission unit that already owns this Realm transition"
        );
        anyhow::bail!("an exact durable MLS admission unit is still converging for this Realm");
    }
    let pairwise_requester = {
        let store = state_store.read();
        store
            .realm_projection_is_minimal_metadata(&realm_id)
            .then(|| {
                let realm = arkret_sdk::RealmId::new(realm_id.clone())
                    .map_err(|error| format!("invalid minimal-metadata Realm id: {error}"))?;
                crate::mls::pairwise_identity::derive_pairwise_signing_material(
                    &account.authority,
                    &account.device_id,
                    &realm,
                )
            })
            .transpose()
            .map_err(anyhow::Error::msg)?
    };
    let mls_actor_id = pairwise_requester
        .as_ref()
        .map(|requester| requester.actor_id.to_string())
        .unwrap_or_else(|| actor_id.clone());
    let claim_route = {
        let store = state_store.read();
        accepted_invite_claim_route(&store, &realm_id, &invitee_did)
    }
    .ok_or_else(|| {
        anyhow::anyhow!(
            "accepted invite has no exact destination service and accepting-device route"
        )
    })?;
    let target_device_id = claim_target_device_id(&claim_route, pairwise_requester.is_some())?;
    let group_id = {
        let store = state_store.read();
        store
            .mls_snapshot_for(&realm_id)
            .map(|snapshot| snapshot.group_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "local MLS state is not ready; create or restore this device's MLS state before inviting into an encrypted Realm"
                )
            })?
    };
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    ensure_mls_genesis_frontier_for_invite(
        api,
        state_store,
        secure_store.as_ref(),
        &realm_id,
        &mls_actor_id,
        &device_id,
    )
    .await?;
    // Verify the current governance frontier before consuming a one-time
    // KeyPackage. The roster projection only schedules this attempt; it never
    // authorizes the claim or the resulting Add commit.
    ensure_mls_governance_proof_for_next_commit(
        api,
        state_store,
        &realm_id,
        &mls_actor_id,
        &device_id,
        &[],
    )
    .await?;
    let claim_request_id = crate::mls_api_helpers::generate_mls_claim_request_id()?;
    let mls_clients = crate::transport::EndpointClients::from_http(api.sdk_http_client()?);
    let claim_outcome = if let Some(requester) = pairwise_requester.as_ref() {
        mls_clients
            .mls()
            .claim_pairwise_key_package(
                &invitee_did,
                &realm_id,
                requester,
                Some(&claim_route.destination_service_id),
                &claim_request_id,
                None,
                &group_id,
            )
            .await?
    } else {
        mls_clients
            .mls()
            .claim_key_package(
                &invitee_did,
                &realm_id,
                &actor_id,
                &device_id,
                Some(&claim_route.destination_service_id),
                &claim_request_id,
                target_device_id,
                &group_id,
            )
            .await?
    };
    claim_outcome
        .validate_shape()
        .map_err(|error| anyhow::anyhow!("KeyPackage claim outcome is invalid: {error}"))?;
    let claim_receipt = claim_outcome.claim_receipt;
    let claim = claim_outcome
        .claims
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("KeyPackage claim succeeded without a claim record"))?;
    // Refresh after the claim as well: membership/policy may have advanced
    // while the remote claim request was in flight.
    ensure_mls_governance_proof_for_next_commit(
        api,
        state_store,
        &realm_id,
        &mls_actor_id,
        &device_id,
        &[&claim],
    )
    .await?;
    // History sharing (encryption-and-audit.md): retain the CURRENT (pre-commit)
    // epoch's `history_secret` BEFORE building the admission commit. The commit
    // advances the group epoch (N → N+1) and OpenMLS can only export the epoch
    // the group is currently at, so the only moment to capture epoch N's secret
    // is here, while the local snapshot is still at N. Without this, the invitee
    // joins at epoch N+1 and requests the pre-join window [0, N], but the
    // provider has only ever retained the post-commit epoch (N+1) — its share
    // range is empty and the late joiner can never decrypt pre-join content.
    retain_current_history_secret_durable(
        state_store,
        secure_store.as_ref(),
        &realm_id,
        &mls_actor_id,
        &device_id,
    )
    .await?;
    let requester_device_authorize_event_id = if pairwise_requester.is_none() {
        Some(
            crate::mls::admission::current_requester_device_authorize_event_id(
                &api.sdk_http_client()?,
                &device_id,
            )
            .await
            .map_err(anyhow::Error::msg)?,
        )
    } else {
        None
    };
    let admission = {
        let store = state_store.read();
        crate::mls::admission::build_realm_mls_admission_events_from_claim(
            &store,
            secure_store.as_ref(),
            &realm_id,
            &account.authority,
            &mls_actor_id,
            &account.device_id,
            requester_device_authorize_event_id.as_ref(),
            &claim,
            &claim_request_id,
            &claim_receipt,
        )
        .map_err(|err| anyhow::anyhow!(err))?
    };
    let next_epoch = admission.snapshot.epoch;
    let invitee_device_id = claim.device_id.clone();
    // Persist the entire fail-closed admission saga before the first write.
    // The durable outbound item submits Commit first, then the exact signed
    // Welcome. Only the checkpoint-proven accepted-artifact consumer may publish
    // the snapshot/history secret. A page close between any two steps resumes
    // from the same immutable material on the next sync drain instead of
    // consuming the KeyPackage and losing the Welcome.
    api.event_submitter()?
        .submit_mls_admission_with_snapshot(
            &admission.commit,
            vec![admission.welcome],
            realm_id.clone(),
            mls_actor_id,
            device_id.clone(),
            admission.snapshot,
            state_store,
        )
        .await?;
    tracing::debug!(
        realm = %short_protocol_id(&realm_id),
        invitee_device = %invitee_device_id
            .as_ref()
            .map(|device| short_protocol_id(device.as_str()))
            .unwrap_or_else(|| "agent".to_owned()),
        "retained local-authoritative history_secret for history-key recovery"
    );
    Ok(Some(next_epoch))
}

#[cfg(test)]
pub(crate) fn joined_member_signature_for_realm(store: &LocalStateStore, realm_id: &str) -> String {
    let mut dids: Vec<String> = projected_member_profiles_for_realm(store, realm_id)
        .into_iter()
        .filter(|member| member.normalized_membership() == Some("join"))
        .map(|member| member.actor_id)
        .collect();
    dids.sort();
    dids.dedup();
    dids.join(",")
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum MembershipCompleteness {
    #[default]
    Unavailable,
    Limited,
    Complete,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ProjectedRealmMembershipHint {
    joined: BTreeSet<String>,
    completeness: MembershipCompleteness,
}

/// Account-sync `members[]` is a current roster projection hint. It is more
/// suitable than the bounded raw-operation cache for reconciliation wakeups,
/// but it is not membership authority: the governance proof and server-side
/// Event auth still gate every KeyPackage claim and MLS Commit.
fn projected_realm_membership_hint(
    store: &LocalStateStore,
    realm_id: &str,
) -> ProjectedRealmMembershipHint {
    let state = store.load();
    let Some(projection) = state.realm_tree_projections.get(realm_id) else {
        return ProjectedRealmMembershipHint::default();
    };
    let Some(_) = projection.get("members").and_then(Value::as_array) else {
        return ProjectedRealmMembershipHint::default();
    };
    let joined = crate::views::member_display::realm_member_roster(Some(projection))
        .into_iter()
        .filter(|member| member.membership.as_deref() == Some("join"))
        .map(|member| member.actor_id)
        .filter(|actor_id| !actor_id.trim().is_empty())
        .collect();
    let completeness = if projection.get("members_limited").and_then(Value::as_bool) == Some(false)
    {
        MembershipCompleteness::Complete
    } else {
        MembershipCompleteness::Limited
    };
    ProjectedRealmMembershipHint {
        joined,
        completeness,
    }
}

fn accepted_membership_profiles_for_realm(
    store: &LocalStateStore,
    realm_id: &str,
) -> Vec<MemberProfile> {
    let state = store.load();
    let invitee_by_invite_id =
        local_invitee_by_invite_id_for_realm(&state.raw_operations, realm_id);
    let mut rows =
        BTreeMap::<String, (chrono::DateTime<chrono::Utc>, String, MemberProfile)>::new();
    for record in &state.raw_operations {
        if let Some(profile) =
            local_membership_profile_from_raw_operation(record, realm_id, &invitee_by_invite_id)
        {
            let actor_id = profile.actor_id.clone();
            let event_time = raw_operation_event_time(record);
            let operation_id = record.operation_id.clone();
            match rows.get(&actor_id) {
                Some((current_time, current_operation_id, _))
                    if event_time < *current_time
                        || (event_time == *current_time
                            && operation_id.as_str() <= current_operation_id.as_str()) => {}
                _ => {
                    rows.insert(actor_id, (event_time, operation_id, profile));
                }
            }
        }
    }
    rows.into_values().map(|(_, _, profile)| profile).collect()
}

fn raw_operation_event_time(record: &RawOperationRecord) -> chrono::DateTime<chrono::Utc> {
    raw_operation_path_string(&record.payload, &["created_at"])
        .and_then(|timestamp| chrono::DateTime::parse_from_rfc3339(&timestamp).ok())
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .unwrap_or(record.received_at)
}

/// Admission candidates combine the positive roster hint with locally verified
/// membership state. Accepted state wins on conflict; the hint fills actors for
/// which the bounded local state-event cache has no cell and wakes reconciliation
/// when a membership-only projection arrives.
fn admission_joined_members_for_realm(store: &LocalStateStore, realm_id: &str) -> BTreeSet<String> {
    let hint = projected_realm_membership_hint(store, realm_id);
    let mut joined = hint.joined;
    for member in accepted_membership_profiles_for_realm(store, realm_id) {
        let actor_id = member.actor_id.trim();
        if actor_id.is_empty() {
            continue;
        }
        if member.normalized_membership() == Some("join") {
            joined.insert(actor_id.to_owned());
        } else {
            joined.remove(actor_id);
        }
    }
    joined
}

pub(super) fn realm_mls_roster_matches_complete_membership_hint(
    state_store: &LocalStateStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> bool {
    let Some(account) = crate::app::SessionContext::get().active_account() else {
        return false;
    };
    if account.full_id().as_str() != actor_id || account.device_id.as_str() != device_id {
        return false;
    }
    crate::mls::runtime::realm_mls_roster_matches_complete_membership_hint(
        state_store,
        secure_store,
        realm_id,
        &account.authority,
        &account.device_id,
    )
    .unwrap_or(false)
}

fn admission_joined_member_signature_for_realm(store: &LocalStateStore, realm_id: &str) -> String {
    admission_joined_members_for_realm(store, realm_id)
        .into_iter()
        .collect::<Vec<_>>()
        .join(",")
}

fn realm_projection_is_direct_conversation(store: &LocalStateStore, realm_id: &str) -> bool {
    store.realm_collaboration_role(realm_id)
        == Some(arkret_sdk::CollaborationRealmRole::DirectConversation)
}

pub(crate) fn mls_admission_candidate_realms_for_actor(
    store: &LocalStateStore,
    actor_id: &str,
) -> Vec<(String, String)> {
    let Some(actor_id) = principal_core_key(actor_id) else {
        return Vec::new();
    };
    let state = store.load();
    let mut realm_ids = BTreeSet::<String>::new();
    for realm_id in state.realm_tree_projections.keys() {
        if realm_id.starts_with("ak:realm:") {
            realm_ids.insert(realm_id.clone());
        }
    }
    for realm_id in store.mls_snapshots().keys() {
        if realm_id.starts_with("ak:realm:") {
            realm_ids.insert(realm_id.clone());
        }
    }
    realm_ids
        .into_iter()
        .filter(|realm_id| {
            store.mls_snapshot_for(realm_id).is_some()
                && store.realm_projection_is_mls_encrypted(realm_id)
                // Direct-conversation materialization owns its immutable
                // genesis/Commit/Welcome IDs and admits the peer itself. The
                // generic membership reconciler must never race that flow or
                // it can advance the same local MLS snapshot under unrelated
                // Event IDs before the canonical binding is submitted.
                && !realm_projection_is_direct_conversation(store, realm_id)
        })
        .filter_map(|realm_id| {
            let joined_sig = admission_joined_member_signature_for_realm(store, &realm_id);
            let other_joined = joined_sig
                .split(',')
                .map(str::trim)
                .filter(|did| !did.is_empty())
                .any(|did| did != actor_id);
            other_joined.then_some((realm_id, joined_sig))
        })
        .collect()
}

/// Admin-side admission reconciliation — closes the invite-time race.
///
/// `submit_mls_admission_for_invitee` historically ran the instant an invite
/// was sent, before the invitee had accepted and published an MLS KeyPackage:
/// the claim failed, no `ak.mls.welcome` was produced, and the invitee was
/// stuck "waiting for a Welcome". This pass runs after durable Realm changes
/// and explicit deferred retries — for every Realm member who has actually
/// joined (`membership=join`) but is not yet in this
/// device's MLS group, it (re)attempts admission. Members already in the group
/// are skipped (no commit spam); members who still have not published a
/// KeyPackage are reported as deferred so the caller can apply bounded backoff.
///
/// The outcome separates completed and deferred work. That prevents an opaque
/// account cursor from being abused as a retry clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MlsAdmissionReconcileOutcome {
    pub admitted: usize,
    pub deferred: usize,
}

pub(crate) async fn reconcile_mls_admissions_for_realm(
    api: &crate::transport::TransportClient,
    mut state_store: SyncSignal<LocalStateStore>,
    realm_id: String,
    actor_id: String,
    device_id: String,
) -> anyhow::Result<MlsAdmissionReconcileOutcome> {
    let account = crate::app::SessionContext::get()
        .active_account()
        .ok_or_else(|| anyhow::anyhow!("active account context is unavailable"))?;
    anyhow::ensure!(
        account.full_id().as_str() == actor_id && account.device_id.as_str() == device_id,
        "MLS admission reconcile identity does not match the active account"
    );
    // Only Realms this device can admit into: holding MLS state ⇒ able to build
    // the commit + Welcome. Without a snapshot we are not an admit-capable
    // member and have nothing to reconcile.
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let group_member_dids: BTreeSet<String> = {
        let store = state_store.read();
        match crate::mls::runtime::mls_group_member_principal_ids_for_realm(
            &store,
            secure_store.as_ref(),
            &realm_id,
            &account.authority,
            &account.device_id,
        ) {
            Some(dids) => dids.into_iter().collect(),
            None => {
                // No local group roster: either no snapshot, the device
                // snapshot secret could not be loaded, or the envelope failed
                // to decrypt. Any of these silently aborts admission — surface
                // it at WARN (wasm tracing is capped at WARN). (mls-admission-debug)
                tracing::warn!(
                    target: "mls_admission",
                    realm = %short_protocol_id(&realm_id),
                    actor = %short_protocol_id(&actor_id),
                    device = %short_protocol_id(&device_id),
                    has_snapshot = state_store.read().mls_snapshot_for(&realm_id).is_some(),
                    "admission aborted: cannot read local MLS group roster (snapshot/secret/decrypt) — no member can be admitted"
                );
                return Ok(MlsAdmissionReconcileOutcome::default());
            }
        }
    };
    // Joined Realm members not yet represented in the MLS group, excluding self.
    let pending: Vec<String> = {
        let store = state_store.read();
        admission_joined_members_for_realm(&store, &realm_id)
            .into_iter()
            .filter(|did| {
                let did = did.trim();
                !did.is_empty()
                    && !same_principal_core(did, &actor_id)
                    && !group_member_dids.contains(did)
            })
            .collect()
    };
    if pending.is_empty() {
        return Ok(MlsAdmissionReconcileOutcome::default());
    }
    tracing::warn!(
        target: "mls_admission",
        realm = %short_protocol_id(&realm_id),
        pending = %pending
            .iter()
            .map(short_protocol_id)
            .collect::<Vec<_>>()
            .join(","),
        group_members = group_member_dids.len(),
        "admission reconcile: attempting to admit joined members not yet in MLS group"
    );
    let mut outcome = MlsAdmissionReconcileOutcome::default();
    for invitee_did in pending {
        match submit_mls_admission_for_invitee(
            api,
            state_store,
            realm_id.clone(),
            actor_id.clone(),
            device_id.clone(),
            invitee_did.clone(),
        )
        .await
        {
            Ok(Some(epoch)) => {
                outcome.admitted += 1;
                tracing::warn!(
                    target: "mls_admission",
                    realm = %short_protocol_id(&realm_id),
                    invitee = %short_protocol_id(&invitee_did),
                    epoch,
                    "admission succeeded: Welcome produced for invitee"
                );
            }
            Ok(None) => {
                tracing::warn!(
                    target: "mls_admission",
                    realm = %short_protocol_id(&realm_id),
                    invitee = %short_protocol_id(&invitee_did),
                    "admission no-op: realm not MLS-admittable from this device"
                );
            }
            // A non-fatal failure (most commonly: invitee has not published a
            // KeyPackage yet) is reported to the explicit retry scheduler.
            // Previously logged at DEBUG, which wasm tracing silences — the
            // invisible swallow is why a permanently-stuck invitee produced no
            // observable signal. Surface the actual error at WARN.
            // (mls-admission-debug)
            Err(error) => {
                outcome.deferred += 1;
                tracing::warn!(
                    target: "mls_admission",
                    realm = %short_protocol_id(&realm_id),
                    invitee = %short_protocol_id(&invitee_did),
                    %error,
                    "admission deferred: claim/commit/welcome step failed (bounded retry scheduled)"
                );
            }
        }
    }
    if outcome.admitted > 0 {
        // An accepted Add commit is necessary but not by itself sufficient to
        // release the send gate. Only exact agreement between the current MLS
        // roster and the complete sync hint shows that every currently
        // projected Add obligation is represented in the epoch. This only
        // resolves the locally tracked transition after an accepted Commit;
        // the hint itself is never membership or send authorization.
        let res = {
            let store = state_store.read();
            realm_mls_roster_matches_complete_membership_hint(
                &store,
                secure_store.as_ref(),
                &realm_id,
                &actor_id,
                &device_id,
            )
        };
        if res {
            state_store
                .write()
                .resolve_member_add_mls_bindings(&realm_id);
        }
    }
    Ok(outcome)
}

pub(crate) async fn submit_mls_admission_for_invitees(
    api: &crate::transport::TransportClient,
    state_store: SyncSignal<LocalStateStore>,
    realm_id: String,
    actor_id: String,
    device_id: String,
    invitees: Vec<String>,
) -> anyhow::Result<usize> {
    let _authoring_guard = mls_admission_authoring_lock().lock().await;
    let account = crate::app::SessionContext::get()
        .active_account()
        .ok_or_else(|| anyhow::anyhow!("active account context is unavailable"))?;
    anyhow::ensure!(
        account.full_id().as_str() == actor_id && account.device_id.as_str() == device_id,
        "MLS batch admission identity does not match the active account"
    );
    if invitees.is_empty() {
        return Ok(0);
    }
    let needs_mls_admission = {
        let store = state_store.read();
        store.mls_snapshot_for(&realm_id).is_some()
            || store.realm_projection_is_mls_encrypted(&realm_id)
    };
    if !needs_mls_admission {
        return Ok(0);
    }
    let admission_submitter = api.event_submitter()?;
    if admission_submitter
        .has_pending_mls_admission_for_realm(&realm_id)
        .await?
    {
        let advanced = admission_submitter
            .drain_mls_outbound_with_accepted_store(state_store)
            .await?;
        tracing::warn!(
            target: "mls_admission",
            realm = %short_protocol_id(&realm_id),
            advanced,
            "batch admission deferred: drove the exact durable admission unit that already owns this Realm transition"
        );
        anyhow::bail!("an exact durable MLS admission unit is still converging for this Realm");
    }
    let pairwise_requester = {
        let store = state_store.read();
        store
            .realm_projection_is_minimal_metadata(&realm_id)
            .then(|| {
                let realm = arkret_sdk::RealmId::new(realm_id.clone())
                    .map_err(|error| format!("invalid minimal-metadata Realm id: {error}"))?;
                crate::mls::pairwise_identity::derive_pairwise_signing_material(
                    &account.authority,
                    &account.device_id,
                    &realm,
                )
            })
            .transpose()
            .map_err(anyhow::Error::msg)?
    };
    let mls_actor_id = pairwise_requester
        .as_ref()
        .map(|requester| requester.actor_id.to_string())
        .unwrap_or_else(|| actor_id.clone());
    let group_id = {
        let store = state_store.read();
        store
            .mls_snapshot_for(&realm_id)
            .map(|snapshot| snapshot.group_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "local MLS state is not ready; create or restore this device's MLS state before inviting into an encrypted Realm"
                )
            })?
    };
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    ensure_mls_genesis_frontier_for_invite(
        api,
        state_store,
        secure_store.as_ref(),
        &realm_id,
        &mls_actor_id,
        &device_id,
    )
    .await?;

    // Fail closed before consuming any one-time KeyPackage. Candidate rows are
    // synchronization hints; only a verified governance frontier plus service
    // authorization may advance the MLS group.
    ensure_mls_governance_proof_for_next_commit(
        api,
        state_store,
        &realm_id,
        &mls_actor_id,
        &device_id,
        &[],
    )
    .await?;

    let mut claims = Vec::<(
        arkret_sdk::KeyPackageClaimRecord,
        String,
        arkret_sdk::PeerKeyPackageClaimReceipt,
    )>::new();
    let mls_clients = crate::transport::EndpointClients::from_http(api.sdk_http_client()?);
    for invitee_did in invitees {
        let claim_request_id = crate::mls_api_helpers::generate_mls_claim_request_id()?;
        let claim_route = {
            let store = state_store.read();
            accepted_invite_claim_route(&store, &realm_id, &invitee_did)
        }
        .ok_or_else(|| {
            anyhow::anyhow!(
                "accepted invite has no exact destination service and accepting-device route"
            )
        })?;
        let target_device_id = claim_target_device_id(&claim_route, pairwise_requester.is_some())?;
        let claim_outcome = if let Some(requester) = pairwise_requester.as_ref() {
            mls_clients
                .mls()
                .claim_pairwise_key_package(
                    &invitee_did,
                    &realm_id,
                    requester,
                    Some(&claim_route.destination_service_id),
                    &claim_request_id,
                    None,
                    &group_id,
                )
                .await?
        } else {
            mls_clients
                .mls()
                .claim_key_package(
                    &invitee_did,
                    &realm_id,
                    &actor_id,
                    &device_id,
                    Some(&claim_route.destination_service_id),
                    &claim_request_id,
                    target_device_id,
                    &group_id,
                )
                .await?
        };
        claim_outcome
            .validate_shape()
            .map_err(|error| anyhow::anyhow!("KeyPackage claim outcome is invalid: {error}"))?;
        let claim =
            claim_outcome.claims.into_iter().next().ok_or_else(|| {
                anyhow::anyhow!("KeyPackage claim succeeded without a claim record")
            })?;
        claims.push((claim, claim_request_id, claim_outcome.claim_receipt));
    }
    // Refresh after the batch of claims to bind the Commit to the latest
    // accepted frontier observed after those network round trips.
    let added_claims = claims.iter().map(|(claim, ..)| claim).collect::<Vec<_>>();
    ensure_mls_governance_proof_for_next_commit(
        api,
        state_store,
        &realm_id,
        &mls_actor_id,
        &device_id,
        &added_claims,
    )
    .await?;
    let requester_device_authorize_event_id = if pairwise_requester.is_none() {
        Some(
            crate::mls::admission::current_requester_device_authorize_event_id(
                &api.sdk_http_client()?,
                &device_id,
            )
            .await
            .map_err(anyhow::Error::msg)?,
        )
    } else {
        None
    };
    let admission = {
        let store = state_store.read();
        crate::mls::admission::build_realm_mls_admission_events_from_claims(
            &store,
            secure_store.as_ref(),
            &realm_id,
            &account.authority,
            &mls_actor_id,
            &account.device_id,
            requester_device_authorize_event_id.as_ref(),
            &claims,
        )
        .map_err(|err| anyhow::anyhow!(err))?
    };
    api.event_submitter()?
        .submit_mls_admission_with_snapshot(
            &admission.commit,
            admission.welcomes,
            realm_id,
            mls_actor_id,
            device_id,
            admission.snapshot,
            state_store,
        )
        .await?;
    Ok(claims.len())
}

fn mls_group_state_event_ref_ready(store: &LocalStateStore, realm_id: &str) -> bool {
    let seal_view = store.seal_view_for_realm(realm_id);
    seal_view
        .frontier
        .iter()
        .chain(seal_view.leaves.iter())
        .any(|value| arkret_sdk::EventId::new(value.clone()).is_ok())
}

async fn ensure_mls_genesis_frontier_for_invite(
    api: &crate::transport::TransportClient,
    mut state_store: SyncSignal<LocalStateStore>,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> anyhow::Result<()> {
    let account = crate::app::SessionContext::get()
        .active_account()
        .ok_or_else(|| anyhow::anyhow!("active account context is unavailable"))?;
    anyhow::ensure!(
        account.full_id().as_str() == actor_id && account.device_id.as_str() == device_id,
        "MLS genesis identity does not match the active account"
    );
    {
        let store = state_store.read();
        if mls_group_state_event_ref_ready(&store, realm_id) {
            return Ok(());
        }
    }
    if let Some(event_id) = api
        .event_submitter()?
        .find_mls_genesis_event_id(realm_id)
        .await?
    {
        state_store
            .write()
            .mark_mls_genesis_emitted_with_event(realm_id.to_owned(), &event_id)
            .map_err(anyhow::Error::msg)?;
        return Ok(());
    }
    {
        let store = state_store.read();
        if store.mls_genesis_emitted_for(realm_id) {
            anyhow::bail!(
                "local MLS genesis event id is not available yet; sync this Realm before inviting into its encrypted group"
            );
        }
    }
    let summary = {
        let store = state_store.read();
        crate::mls::runtime::initial_mls_snapshot_summary_from_existing(
            &store,
            secure_store,
            realm_id,
            &account.authority,
            &account.device_id,
        )
        .map_err(|err| anyhow::anyhow!(err.user_message()))?
    }
    .ok_or_else(|| {
        anyhow::anyhow!(
            "local epoch-0 MLS snapshot is not available; create or restore this device's MLS state before inviting into an encrypted Realm"
        )
    })?;
    let leaves =
        crate::mls::governance_proof::singleton_security_frontier_leaf(actor_id, device_id)
            .map_err(anyhow::Error::msg)?;
    let genesis_request = crate::mls::governance_proof::proof_request(
        &state_store.read(),
        realm_id,
        None,
        summary.group_id.clone(),
        0,
        0,
        leaves.clone(),
    )
    .map_err(anyhow::Error::msg)?;
    crate::mls::governance_proof::fetch_verify_and_cache_proof(
        api,
        state_store,
        &genesis_request,
        &leaves,
    )
    .await
    .map_err(anyhow::Error::msg)?;
    let genesis_event = {
        let mut store = state_store.write();
        crate::mls::group_events::build_creator_mls_genesis_event(
            &mut store,
            realm_id,
            actor_id,
            Some(&summary),
        )
        .map_err(|err| anyhow::anyhow!(err))?
    }
    .ok_or_else(|| {
        anyhow::anyhow!(
            "local MLS genesis event is already marked emitted but no group-state event id is available; sync this Realm before inviting"
        )
    })?;
    crate::mls::runtime::upload_mls_genesis_public_material(api, &summary)
        .await
        .map_err(|error| anyhow::anyhow!(error.user_message()))?;
    match api
        .event_submitter()?
        .submit_sdk_event(&genesis_event)
        .await
    {
        Ok(accepted) => {
            // The accepted id is the only one encrypted writes may bind to.
            let event_id = arkret_sdk::EventId::new(accepted.event_id.clone())
                .map_err(|error| anyhow::anyhow!("accepted MLS genesis id invalid: {error}"))?;
            state_store
                .write()
                .mark_mls_genesis_emitted_with_event(realm_id.to_owned(), &event_id)
                .map_err(anyhow::Error::msg)?;
            Ok(())
        }
        Err(err) => {
            if crate::ephemeral::events_submit_rejected_for_reason(
                &err,
                &arkret_sdk::ReasonCode::MlsGenesisAlreadyExists,
            ) {
                if let Some(event_id) = api
                    .event_submitter()?
                    .find_mls_genesis_event_id(realm_id)
                    .await?
                {
                    state_store
                        .write()
                        .mark_mls_genesis_emitted_with_event(realm_id.to_owned(), &event_id)
                        .map_err(anyhow::Error::msg)?;
                    return Ok(());
                }
                anyhow::bail!(
                    "MLS genesis already exists server-side but the local event id is unavailable; sync this Realm before inviting"
                );
            }
            Err(err)
        }
    }
}

async fn ensure_mls_governance_proof_for_next_commit(
    api: &crate::transport::TransportClient,
    state_store: SyncSignal<LocalStateStore>,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    added_claims: &[&arkret_sdk::KeyPackageClaimRecord],
) -> anyhow::Result<()> {
    let account = crate::app::SessionContext::get()
        .active_account()
        .ok_or_else(|| anyhow::anyhow!("active account context is unavailable"))?;
    anyhow::ensure!(
        account.full_id().as_str() == actor_id && account.device_id.as_str() == device_id,
        "MLS governance proof identity does not match the active account"
    );
    refresh_mls_governance_target_basis(api, state_store, realm_id, added_claims).await?;
    let leaves = if added_claims.is_empty() {
        crate::mls::governance_proof::current_security_frontier_leaves(
            &state_store.read(),
            realm_id,
            None,
            &account.authority,
            &account.device_id,
        )
        .map_err(anyhow::Error::msg)?
    } else {
        let realm_id = arkret_sdk::RealmId::new(realm_id.to_owned())
            .map_err(|error| anyhow::anyhow!("invalid MLS Realm id: {error}"))?;
        let effective_scope = arkret_sdk::ScopeRef::Realm { realm_id };
        let key_packages = added_claims
            .iter()
            .map(|claim| {
                crate::mls_api_helpers::keypackage_claim_record_to_mls_record(claim)
                    .map_err(anyhow::Error::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        crate::mls::governance_proof::preview_security_frontier_with_added_keypackages(
            &state_store.read(),
            &effective_scope,
            &account.authority,
            &account.device_id,
            &key_packages,
        )
        .map_err(anyhow::Error::msg)?
    };
    let request = {
        let store = state_store.read();
        let snapshot = store.mls_snapshot_for(realm_id).ok_or_else(|| {
            anyhow::anyhow!("local MLS snapshot is unavailable for governance proof request")
        })?;
        crate::mls::governance_proof::proof_request(
            &store,
            realm_id,
            None,
            snapshot.group_id,
            snapshot.epoch,
            snapshot.epoch.saturating_add(1),
            leaves.clone(),
        )
        .map_err(anyhow::Error::msg)?
    };
    crate::mls::governance_proof::fetch_verify_and_cache_proof(api, state_store, &request, &leaves)
        .await
        .map(|_| ())
        .map_err(anyhow::Error::msg)
}

async fn refresh_mls_governance_target_basis(
    api: &crate::transport::TransportClient,
    mut state_store: SyncSignal<LocalStateStore>,
    realm_id: &str,
    added_claims: &[&arkret_sdk::KeyPackageClaimRecord],
) -> anyhow::Result<()> {
    const ATTEMPTS: usize = 20;
    const DELAY: std::time::Duration = std::time::Duration::from_millis(250);

    let (base_basis, requires_membership_advance) = {
        let store = state_store.read();
        let checkpoint = store
            .trusted_mls_governance_checkpoint(realm_id)
            .ok_or_else(|| anyhow::anyhow!("MLS governance checkpoint is unavailable"))?;
        let requires_membership_advance = added_claims.iter().any(|claim| {
            arkret_sdk::current_authorization_incarnation_from_verified_checkpoint(
                &checkpoint,
                &claim.principal_id,
                None,
            )
            .is_err()
        });
        (checkpoint.basis, requires_membership_advance)
    };
    let submitter = api.event_submitter()?;
    for attempt in 0..ATTEMPTS {
        match submitter.seals_frontier_realm_view(realm_id).await {
            Ok(view) if !requires_membership_advance || view.seal_basis != base_basis => {
                state_store.write().set_realm_seal_view(
                    realm_id.to_owned(),
                    crate::state::LocalSealView {
                        frontier: view
                            .seal_basis
                            .leaves
                            .iter()
                            .map(ToString::to_string)
                            .collect(),
                        ..Default::default()
                    },
                );
                return Ok(());
            }
            Ok(_) if attempt + 1 < ATTEMPTS => {
                crate::runtime_helpers::sleep_for(DELAY).await;
            }
            Ok(_) => {
                anyhow::bail!(
                    "joined MLS Add target was not covered by a newer accepted Realm Seal frontier"
                );
            }
            Err(error)
                if attempt + 1 < ATTEMPTS
                    && crate::api_error::is_realm_seal_frontier_pending_error(&error) =>
            {
                crate::runtime_helpers::sleep_for(DELAY).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("Realm Seal frontier refresh returns on its final attempt")
}

#[component]
pub fn RealmMembersPanel(
    active_service_id: String,
    principal_id: String,
    device_id: String,
    token: Signal<String>,
    selected_realm_id: String,
    sync_cursor: Signal<String>,
    frontier_state: Signal<String>,
) -> Element {
    let _active_service_id = active_service_id;
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = crate::app::SessionContext::get().state_store;
    let mut invite_target = use_signal(String::new);
    let mut status_msg = use_signal(String::new);
    let mut members = use_signal(Vec::<MemberProfile>::new);
    let mut owned_agents = use_signal(Vec::<MemberAgentRow>::new);
    let block_confirm_did = use_signal(|| Option::<String>::None);
    let mut permissions = use_signal(RealmMemberCapabilities::default);
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
                match crate::transport::auth::with_authed_sdk_client(
                    &base,
                    api_token,
                    |http| async move { crate::transport::account::contacts(&http).await },
                )
                .await
                {
                    Ok(response) => {
                        let accepted: Vec<crate::models::ContactListRow> = response
                            .contacts
                            .into_iter()
                            .filter(|c| c.state == arkret_sdk::ContactState::Accepted)
                            .collect();
                        state_store
                            .write()
                            .replace_accepted_human_contacts(&accepted);
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
            let next = projected_member_profiles_for_realm(
                &state_store.read(),
                &selected_realm_for_hydration,
            );
            if members() != next {
                members.set(next);
            }
        });
    }

    {
        let base = base_url.clone();
        let realm = selected_realm_id.clone();
        let fallback_controller_id = principal_id.clone();
        use_effect(move || {
            let api_token = token();
            if api_token.trim().is_empty() {
                owned_agents.set(Vec::new());
                return;
            }
            let base = base.clone();
            let realm = realm.clone();
            let fallback_controller_id = fallback_controller_id.clone();
            spawn(async move {
                let result = crate::transport::auth::with_authed_sdk_client(
                    &base,
                    api_token,
                    |http| async move {
                        fetch_owned_agent_rows(&http, &realm, &fallback_controller_id).await
                    },
                )
                .await;
                if let Ok(rows) = result {
                    owned_agents.set(rows);
                }
            });
        });
    }

    {
        let base = base_url.clone();
        let actor = principal_id.clone();
        let realm = selected_realm_id.clone();
        use_effect(move || {
            let api_token = token();
            if api_token.trim().is_empty() || actor.trim().is_empty() || realm.trim().is_empty() {
                permissions.set(RealmMemberCapabilities {
                    loaded: true,
                    ..RealmMemberCapabilities::default()
                });
                return;
            }
            permissions.set(RealmMemberCapabilities::default());
            let base = base.clone();
            let actor = actor.clone();
            let realm = realm.clone();
            spawn(async move {
                match with_authed_api(&base, api_token, |api| async move {
                    let invite = async {
                        crate::transport::realm_read::authz_check(
                            &api.sdk_http_client()?,
                            &actor,
                            CapabilityActionId::INVITE_CREATE,
                            &realm,
                        )
                        .await
                    }
                    .await;
                    let cancel_invite = async {
                        crate::transport::realm_read::authz_check(
                            &api.sdk_http_client()?,
                            &actor,
                            CapabilityActionId::INVITE_CANCEL,
                            &realm,
                        )
                        .await
                    }
                    .await;
                    let revoke_invite = async {
                        crate::transport::realm_read::authz_check(
                            &api.sdk_http_client()?,
                            &actor,
                            CapabilityActionId::INVITE_REVOKE,
                            &realm,
                        )
                        .await
                    }
                    .await;
                    // Member removal has no standalone capability action in
                    // v1; it is governed by Realm management authority. Probe
                    // the registered `ak.realm.admin` action (management,
                    // high-risk) instead of the unregistered placeholder
                    // `ak.member.remove`, which is not in
                    // capability-action-registry.json and would be treated as
                    // an unknown high-risk action (fail-closed) by a
                    // spec-conformant server.
                    let remove = async {
                        crate::transport::realm_read::authz_check(
                            &api.sdk_http_client()?,
                            &actor,
                            CapabilityActionId::REALM_ADMIN,
                            &realm,
                        )
                        .await
                    }
                    .await;
                    Ok::<_, anyhow::Error>((invite, cancel_invite, revoke_invite, remove))
                })
                .await
                {
                    Ok((invite, cancel_invite, revoke_invite, remove)) => {
                        let can_invite = invite
                            .as_ref()
                            .map(crate::transport::realm_read::authz_allowed)
                            .unwrap_or(false);
                        let can_cancel_invite = cancel_invite
                            .as_ref()
                            .map(crate::transport::realm_read::authz_allowed)
                            .unwrap_or(false);
                        let can_revoke_invite = revoke_invite
                            .as_ref()
                            .map(crate::transport::realm_read::authz_allowed)
                            .unwrap_or(false);
                        let can_remove = remove
                            .as_ref()
                            .map(crate::transport::realm_read::authz_allowed)
                            .unwrap_or(false);
                        if invite.is_err()
                            && cancel_invite.is_err()
                            && revoke_invite.is_err()
                            && remove.is_err()
                        {
                            status_msg.set(
                                "member action permission check failed; write controls hidden"
                                    .to_owned(),
                            );
                        }
                        permissions.set(RealmMemberCapabilities {
                            loaded: true,
                            can_invite,
                            can_cancel_invite,
                            can_revoke_invite,
                            can_remove,
                        });
                    }
                    Err(error) => {
                        permissions.set(RealmMemberCapabilities {
                            loaded: true,
                            ..RealmMemberCapabilities::default()
                        });
                        status_msg.set(format!(
                            "member action permission check failed: {}",
                            error.display()
                        ));
                    }
                }
            });
        });
    }

    let member_permissions = permissions();
    let can_invite = member_permissions.can_invite;
    let can_cancel_invite = member_permissions.can_cancel_invite;
    let can_revoke_invite = member_permissions.can_revoke_invite;
    let can_remove = member_permissions.can_remove;

    // Roster → grouped by controller → filtered → paged window. Filtering
    // stays cheap; pagination keeps the mounted row count bounded while
    // keeping each controller's agents visually attached to the owner.
    let all_members = members();
    let (active_members, pending_invite_rows) = split_member_profiles(all_members);
    let owned_agent_rows = owned_agents();
    let member_groups =
        group_members_with_owned_agents(&active_members, &owned_agent_rows, &principal_id);
    let selected_section = member_roster_section();
    let total_members = active_members.len();
    let total_pending_invites = pending_invite_rows.len();
    let total_groups = member_groups.len();
    let total_owner_members = active_members
        .iter()
        .filter(|member| member.is_owner)
        .count();
    let total_admin_members = active_members
        .iter()
        .filter(|member| member.is_admin && !member.is_owner)
        .count();
    let total_regular_members = active_members
        .iter()
        .filter(|member| !member.is_governance_principal())
        .count();
    let governance_member_count = active_members
        .iter()
        .filter(|member| member.is_governance_principal())
        .count();
    let self_is_known_governance = active_members.iter().any(|member| {
        same_principal_core(&member.actor_id, &principal_id) && member.is_governance_principal()
    });
    // Authority-root controller: `capabilities.md` §10.4 L858 — the root
    // controller's only exit is `ak.realm.owner.transfer`, regardless of how
    // many other admins exist, so this outranks the softer last-admin guard.
    let self_is_root_controller = active_members
        .iter()
        .any(|member| same_principal_core(&member.actor_id, &principal_id) && member.is_owner);
    let self_leave_disabled_reason = if self_is_root_controller {
        Some(
            "Transfer Realm ownership first (ak.realm.owner.transfer, Realm settings → Security \
             → Realm governance) — the root controller has no other exit path."
                .to_owned(),
        )
    } else if self_is_known_governance && governance_member_count <= 1 {
        Some("Transfer or add Realm admin authority before leaving.".to_owned())
    } else {
        None
    };
    let filter_query = member_filter().trim().to_lowercase();
    let section_groups: Vec<MemberGroup> = member_groups
        .into_iter()
        .filter(|group| member_group_in_section(group, selected_section, &principal_id))
        .collect();
    let filtered_groups: Vec<MemberGroup> = if filter_query.is_empty() {
        section_groups
    } else {
        section_groups
            .into_iter()
            .filter(|group| member_group_matches(group, &filter_query))
            .collect()
    };
    let filtered_count = filtered_groups.len();
    let visible = member_visible().min(filtered_count);
    let visible_groups: Vec<MemberGroup> = filtered_groups[..visible].to_vec();
    let has_more =
        selected_section != MemberRosterSection::PendingInvites && visible < filtered_count;
    let show_search = selected_section != MemberRosterSection::MyAgents
        && total_groups + total_pending_invites > MEMBER_SEARCH_THRESHOLD;
    let visible_pending_invites: Vec<MemberProfile> = if filter_query.is_empty() {
        pending_invite_rows.clone()
    } else {
        pending_invite_rows
            .iter()
            .filter(|profile| member_profile_matches(profile, &filter_query))
            .cloned()
            .collect()
    };
    let pending_invite_match_count = visible_pending_invites.len();
    let member_set: BTreeSet<String> = active_members
        .iter()
        .map(|member| member.actor_id.clone())
        .collect();
    let self_owned_agent_rows: Vec<MemberAgentRow> = owned_agent_rows
        .iter()
        .filter(|agent| {
            let controller = agent.controller_id.trim();
            controller.is_empty() || controller == principal_id.trim()
        })
        .cloned()
        .collect();
    let (self_realm_agent_rows, available_self_agent_rows) =
        split_owned_agents_for_realm(&self_owned_agent_rows, &member_set);
    let selected_section_total = match selected_section {
        MemberRosterSection::Members => total_regular_members,
        MemberRosterSection::Owners => total_owner_members,
        MemberRosterSection::Admins => total_admin_members,
        MemberRosterSection::MyAgents => self_realm_agent_rows.len(),
        MemberRosterSection::PendingInvites => total_pending_invites,
    };
    let selected_section_visible_count = match selected_section {
        MemberRosterSection::PendingInvites => pending_invite_match_count,
        MemberRosterSection::MyAgents => self_realm_agent_rows.len(),
        _ => filtered_count,
    };
    let selected_section_empty = selected_section_visible_count == 0;
    let selected_section_title = selected_section.title();
    let selected_section_description = selected_section.description();
    let members_section_class = if selected_section == MemberRosterSection::Members {
        "members-admin-menu-item active"
    } else {
        "members-admin-menu-item"
    };
    let owners_section_class = if selected_section == MemberRosterSection::Owners {
        "members-admin-menu-item active"
    } else {
        "members-admin-menu-item"
    };
    let admins_section_class = if selected_section == MemberRosterSection::Admins {
        "members-admin-menu-item active"
    } else {
        "members-admin-menu-item"
    };
    let my_agents_section_class = if selected_section == MemberRosterSection::MyAgents {
        "members-admin-menu-item active"
    } else {
        "members-admin-menu-item"
    };
    let pending_section_class = if selected_section == MemberRosterSection::PendingInvites {
        "members-admin-menu-item active"
    } else {
        "members-admin-menu-item"
    };
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
                                                div { class: "member-self-agent-row", "data-testid": "available-realm-agent-row", "data-agent-did": "{agent_id}",
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
                                                            let base = base_url.clone();
                                                            let realm = selected_realm_id.clone();
                                                            let target = agent_id.clone();
                                                            let target_label = agent_title.clone();
                                                            let actor_id = principal_id.clone();
                                                            move |_| {
                                                                let base = base.clone();
                                                                let realm = realm.clone();
                                                                let target = target.clone();
                                                                let target_label = target_label.clone();
                                                                let actor_id = actor_id.clone();
                                                                let api_token = token();
                                                                spawn(async move {
                                                                    let realm_for_api = realm.clone();
                                                                    match crate::transport::auth::with_event_submitter(
                                                                        &base,
                                                                        api_token,
                                                                        |sub| async move {
                                                                            crate::transport::realm_write::transition_member_state(
                                                                                &sub,
                                                                                &realm_for_api,
                                                                                &actor_id,
                                                                                &target,
                                                                                None,
                                                                                "join",
                                                                                "controller_add_agent",
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
                                                                                    "mls_member_add",
                                                                                    MoveSubmissionState::PendingMlsBinding,
                                                                                    Some("epoch_update_required: agent membership frontier changed; MLS Add commit required".to_owned()),
                                                                                    None,
                                                                                );
                                                                            }
                                                                            sync_cursor.set(String::new());
                                                                            agent_add_modal_open.set(false);
                                                                            let suffix = if mls_encrypted { "; epoch_update_required" } else { "" };
                                                                            status_msg.set(format!("added agent {} to Realm{}", target_label, suffix));
                                                                        }
                                                                        Err(err) if crate::api_error::is_mls_keypackage_not_found_error(err.inner()) => {
                                                                            status_msg.set("agent add failed: Agent runtime has not completed E2EE KeyPackage publication".to_owned());
                                                                        }
                                                                        Err(err) => status_msg.set(format!("agent add failed: {}", err.display())),
                                                                    }
                                                                });
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
                                                    let did = crate::models::contact_peer_id(&contact).to_string();
                                                    let did_label = actor_display_label(&state_store.read(), &did);
                                                    let checked = selected_contacts.read().contains(&did);
                                                    let eligible =
                                                        crate::models::contact_grants_me_invite(&contact);
                                                    let usable = eligible;
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
                                                        let base = base_url.clone();
                                                        let actor = principal_id.clone();
                                                        let realm = selected_realm_id.clone();
                                                        let state_store = state_store;
                                                        move |_| {
                                                            let base = base.clone();
                                                            let actor = actor.clone();
                                                            let realm = realm.clone();
                                                        let mut state_store = state_store;
                                                        let api_token = token();
                                                        // Resolve the destination pairs up front so the
                                                        // async task doesn't borrow the rendered rows.
                                                        let targets: Vec<(String, Option<String>)> = invite_contacts
                                                            .read()
                                                            .iter()
                                                            .filter(|c| selected_contacts.read().contains(crate::models::contact_peer_id(c).as_str()))
                                                            .filter(|c| crate::models::contact_grants_me_invite(c))
                                                            .map(|c| {
                                                                (
                                                                    crate::models::contact_peer_id(c).to_string(),
                                                                    c.peer_service_id.as_ref().map(ToString::to_string),
                                                                )
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
                                                            let api = match crate::transport::auth::authed_api(&base, api_token) {
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
                                                            let mut ok_invites =
                                                                Vec::<(String, String, String, Option<String>)>::new();
                                                            for (did, recipient_service_id) in targets {
                                                                match api
                                                                    .invite_contact_to_realm(
                                                                        &realm,
                                                                        &actor,
                                                                        &did,
                                                                        recipient_service_id.as_deref(),
                                                                    )
                                                                    .await
                                                                {
                                                                    Ok((event_id, invite_id)) => {
                                                                        ok += 1;
                                                                        ok_invites.push((
                                                                            did,
                                                                            event_id.clone(),
                                                                            invite_id,
                                                                            recipient_service_id,
                                                                        ));
                                                                        frontier_state.set(event_id);
                                                                    }
                                                                    Err(err) => last_err = err.to_string(),
                                                                }
                                                            }
                                                            if !ok_invites.is_empty() {
                                                                let mut next_members = members.read().clone();
                                                                {
                                                                    let mut store = state_store.write();
                                                                    for (did, event_id, invite_id, recipient_service_id) in ok_invites {
                                                                        upsert_pending_invite_profile(&mut next_members, &did, None, Some(&invite_id));
                                                                        store.append_raw_operation(
                                                                            event_id.clone(),
                                                                            Some(realm.clone()),
                                                                            json!({
                                                                                "kind": event_kind_str::INVITE_CREATE,
                                                                                "invite_id": invite_id,
                                                                                "invitee": did,
                                                                                "state": "pending",
                                                                                "event_id": event_id,
                                                                                "recipient_service_id": recipient_service_id,
                                                                            }),
                                                                        );
                                                                    }
                                                                }
                                                                members.set(next_members);
                                                            }
                                                            selected_contacts.set(std::collections::BTreeSet::new());
                                                            if ok == total {
                                                                invite_modal_open.set(false);
                                                                let message = crate::i18n::tr("realm_admin.invite_sent")
                                                                    .replace("{ok}", &ok.to_string());
                                                                status_msg.set(message);
                                                            } else {
                                                                let message = crate::i18n::tr("realm_admin.invite_partial")
                                                                    .replace("{ok}", &ok.to_string())
                                                                    .replace("{total}", &total.to_string())
                                                                    .replace("{error}", &last_err);
                                                                status_msg.set(message);
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
                                        let actor = principal_id.clone();
                                        let realm = selected_realm_id.clone();
                                        let state_store = state_store;
                                        move |_| {
                                            let base = base.clone();
                                            let actor = actor.clone();
                                            let realm = realm.clone();
                                            let mut state_store = state_store;
                                            let api_token = token();
                                            let target = invite_target().trim().to_owned();
                                            if target.is_empty() {
                                                status_msg.set("invite target is required".to_owned());
                                                return;
                                            }
                                            let wait_for = active_sync_token(sync_cursor());
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
                                                                status_msg.set(format!(
                                                                    "invite target resolve failed: {}",
                                                                    crate::api_error::display_user_facing(&error)
                                                                ));
                                                                return;
                                                            }
                                                        };
                                                        let invitee_label = invitee
                                                            .handle
                                                            .clone()
                                                            .unwrap_or_else(|| invitee.did.clone());
                                                        let invitee_did = invitee.did.clone();
                                                        let op = match ak_ops::invite_create_structured(
                                                            &realm,
                                                            &actor,
                                                            &invitee_did,
                                                            None,
                                                            invitee.invite_delivery_target.clone(),
                                                            &invitee.introduction_evidence_digest,
                                                        ) {
                                                            Ok(builder) => builder
                                                                .build_sdk_event("inkson"),
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
                                                        // The Invite is named by its own create Event, so
                                                        // its id arrives with the receipt.
                                                        let op_id = submit_event.local_operation_id().to_string();
                                                        status_msg.set(format!(
                                                            "submitting invite for {}",
                                                            invitee_label
                                                        ));
                                                        match match api.event_submitter() {
                                                            Ok(es) => es.submit_sdk_event(&submit_event).await,
                                                            Err(err) => Err(err),
                                                        } {
                                                            Ok(submitted) => {
                                                                if let Err(error) = api
                                                                    .dispatch_accepted_invite(
                                                                        &submitted.event_id,
                                                                        &invitee,
                                                                    )
                                                                    .await
                                                                {
                                                                    status_msg.set(format!(
                                                                        "invite fact accepted but private delivery failed: {error}"
                                                                    ));
                                                                    return;
                                                                }
                                                                frontier_state.set(submitted.event_id.clone());
                                                                // The Invite is `retype(create.event_id)`, so its
                                                                // id is read from the accepted receipt.
                                                                let invite_id = match arkret_sdk::EventId::new(
                                                                    submitted.event_id.clone(),
                                                                ) {
                                                                    Ok(event_id) => arkret_sdk::InviteId::from_event_id(&event_id)
                                                                        .to_string(),
                                                                    Err(error) => {
                                                                        status_msg.set(format!(
                                                                            "invite accepted but its Event id is invalid: {error}"
                                                                        ));
                                                                        return;
                                                                    }
                                                                };
                                                                {
                                                                    let mut store = state_store.write();
                                                                    store.append_raw_operation(
                                                                        op_id.clone(),
                                                                        Some(realm.clone()),
                                                                        json!({
                                                                            "kind": event_kind_str::INVITE_CREATE,
                                                                            "invite_id": invite_id.clone(),
                                                                            "invitee": invitee_did.clone(),
                                                                            "invitee_label": invitee_label.clone(),
                                                                            "state": "pending",
                                                                            "event_id": submitted.event_id,
                                                                            "recipient_service_id": invitee.invite_delivery_target.recipient_service_id,
                                                                        }),
                                                                    );
                                                                }
                                                                let mut next_members = members.read().clone();
                                                                upsert_pending_invite_profile(
                                                                    &mut next_members,
                                                                    &invitee_did,
                                                                    Some(&invitee_label),
                                                                    Some(&invite_id),
                                                                );
                                                                members.set(next_members);
                                                                invite_target.set(String::new());
                                                                invite_modal_open.set(false);
                                                                status_msg.set(format!(
                                                                    "invited {} (pending) fact {}; MLS admission will reconcile after acceptance",
                                                                    invitee_label,
                                                                    short_protocol_id(&op_id)
                                                                ));
                                                            }
                                                            Err(error) => status_msg.set(format!(
                                                                "invite failed: {}",
                                                                crate::api_error::display_user_facing(&error)
                                                            )),
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
                                            token,
                                            principal_id: principal_id.clone(),
                                            selected_realm_id: selected_realm_id.clone(),
                                            can_cancel_invite,
                                            can_revoke_invite,
                                            members,
                                            frontier_state,
                                            status_msg,
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
                            let is_self = member.trim() == principal_id.trim();
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
                                    "data-controller-id": "{member}",
                                    if selected_section != MemberRosterSection::MyAgents {
                                    div { class: "event member-row member-controller-row", "data-testid": "member-row", "data-member-did": "{member}",
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
                                                    span { class: "member-row-primary", title: "{member}", "{member_label}" }
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
                                            token,
                                            principal_id: principal_id.clone(),
                                            selected_realm_id: selected_realm_id.clone(),
                                            target_did: member.clone(),
                                            target_label: member_label.clone(),
                                            can_remove,
                                            is_self,
                                            leave_disabled_reason: self_leave_reason,
                                            sync_cursor,
                                            status_msg,
                                            block_confirm_did,
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
                                                            let agent_in_realm = member_set.contains(&owned_agent.agent_id);
                                                            let policy = owned_agent.mention_policy;
                                                            let policy_class = policy.badge_class();
                                                            let policy_label = policy.label();
                                                            let agent_id = owned_agent.agent_id.clone();
                                                            let agent_title = owned_agent.display_name.clone();
                                                            let status_class = crate::views::agents::agent_state_badge_class(&owned_agent.status);
                                                            let status_label = crate::views::agents::agent_state_label(&owned_agent.status).to_owned();
                                                            let can_enable = agent_in_realm;
                                                            let can_remove_agent = agent_in_realm;
                                                            rsx! {
                                                                div { class: "member-self-agent-row", "data-testid": "member-self-agent-row", "data-agent-did": "{agent_id}",
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
                                                                                        let base = base_url.clone();
                                                                                        let realm = selected_realm_id.clone();
                                                                                        let target = agent_id.clone();
                                                                                        let target_label = agent_title.clone();
                                                                                        let actor_principal_id = principal_id.clone();
                                                                                        move |_| {
                                                                                            let base = base.clone();
                                                                                            let realm = realm.clone();
                                                                                            let target = target.clone();
                                                                                            let target_label = target_label.clone();
                                                                                            let actor_id = actor_principal_id.clone();
                                                                                            let api_token = token();
                                                                                            spawn(async move {
                                                                                                let realm_for_api = realm.clone();
                                                                                                match crate::transport::auth::with_event_submitter(
                                                                                                    &base,
                                                                                                    api_token,
                                                                                                    |sub| async move {
                                                                                                        crate::transport::realm_write::transition_member_state(
                                                                                                            &sub,
                                                                                                            &realm_for_api,
                                                                                                            &actor_id,
                                                                                                            &target,
                                                                                                            Some("join"),
                                                                                                            "leave",
                                                                                                            "controller_remove_agent",
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
                                                                                                            state_store.write().record_move_submission(
                                                                                                                format!("mls-binding:{}", resp.event_id),
                                                                                                                realm.clone(),
                                                                                                                "mls_member_remove",
                                                                                                                MoveSubmissionState::PendingMlsBinding,
                                                                                                                Some("epoch_update_required: membership frontier changed; MLS Remove commit required".to_owned()),
                                                                                                                None,
                                                                                                            );
                                                                                                        }
                                                                                                        sync_cursor.set(String::new());
                                                                                                        let suffix = if mls_encrypted {
                                                                                                            "; epoch_update_required"
                                                                                                        } else {
                                                                                                            ""
                                                                                                        };
                                                                                                        status_msg.set(format!(
                                                                                                            "removed agent {} from Realm{}",
                                                                                                            target_label,
                                                                                                            suffix
                                                                                                        ));
                                                                                                    }
                                                                                                    Err(err) => status_msg.set(format!(
                                                                                                        "agent remove failed: {}",
                                                                                                        err.display()
                                                                                                    )),
                                                                                                }
                                                                                            });
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
                                                                                                    owned_agents, status_msg,
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
                                                                                                    owned_agents, status_msg,
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
                                                                                                    owned_agents, status_msg,
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
