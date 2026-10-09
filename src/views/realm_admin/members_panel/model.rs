//! Pure roster model for the Realm members panel.
//!
//! Everything here is a data-in / data-out projection over the local sync
//! state: member and agent rows, the invite lifecycle, roster grouping, the
//! section/search/paging derivation and the permission aggregate. None of it
//! reads a Signal or touches the network, so each rule is reachable from a
//! unit test without mounting a component.

use super::*;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) enum AgentAddState {
    #[default]
    Idle,
    Pending(String),
    Failed(String),
}

impl AgentAddState {
    pub(super) fn begin(&mut self, target: String) -> bool {
        if matches!(self, Self::Pending(_)) {
            return false;
        }
        *self = Self::Pending(target);
        true
    }

    pub(super) fn is_pending(&self) -> bool {
        matches!(self, Self::Pending(_))
    }
}

/// Number of member rows the list renders per page. The member list is
/// hydrated from the full local sync projection (which can hold tens of
/// thousands of entries for a large Realm), so we never mount every row
/// at once — we render this many and reveal more on demand. Keeps the DOM
/// node count bounded regardless of Realm size, mirroring how Telegram
/// pages its participant list rather than materializing the whole roster.
pub(super) const MEMBER_PAGE_SIZE: usize = 50;

/// Once a Realm has more than this many members the inline search box is
/// shown. Below it, scanning the list by eye is faster than typing.
pub(super) const MEMBER_SEARCH_THRESHOLD: usize = 8;

pub(super) const MEMBER_PERMISSION_ACTIONS: [&str; 4] = [
    CapabilityActionId::INVITE_CREATE,
    CapabilityActionId::INVITE_CANCEL,
    CapabilityActionId::INVITE_REVOKE,
    CapabilityActionId::REALM_ADMIN,
];

pub(super) struct RealmMemberPermissionChecks {
    pub(super) invite: anyhow::Result<bool>,
    pub(super) cancel_invite: anyhow::Result<bool>,
    pub(super) revoke_invite: anyhow::Result<bool>,
    pub(super) remove: anyhow::Result<bool>,
}

pub(super) struct RealmMemberPermissionLoad {
    pub(super) capabilities: RealmMemberCapabilities,
    pub(super) all_checks_failed: bool,
}

pub(super) fn aggregate_realm_member_permissions(
    checks: &RealmMemberPermissionChecks,
) -> RealmMemberPermissionLoad {
    RealmMemberPermissionLoad {
        capabilities: RealmMemberCapabilities {
            loaded: true,
            can_invite: checks.invite.as_ref().copied().unwrap_or(false),
            can_cancel_invite: checks.cancel_invite.as_ref().copied().unwrap_or(false),
            can_revoke_invite: checks.revoke_invite.as_ref().copied().unwrap_or(false),
            can_remove: checks.remove.as_ref().copied().unwrap_or(false),
        },
        all_checks_failed: checks.invite.is_err()
            && checks.cancel_invite.is_err()
            && checks.revoke_invite.is_err()
            && checks.remove.is_err(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AgentMentionPolicy {
    Allowed,
    OwnerOnly,
    Unknown,
}

impl AgentMentionPolicy {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Allowed => "Members can @",
            Self::OwnerOnly => "Controller only",
            Self::Unknown => "@ policy unknown",
        }
    }

    pub(super) fn badge_class(self) -> &'static str {
        match self {
            Self::Allowed => "badge green",
            Self::OwnerOnly => "badge amber",
            Self::Unknown => "badge",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MemberRosterSection {
    Members,
    Owners,
    Admins,
    MyAgents,
    PendingInvites,
}

impl MemberRosterSection {
    pub(super) fn title(self) -> &'static str {
        match self {
            Self::Members => "Members",
            Self::Owners => "Owners",
            Self::Admins => "Admins",
            Self::MyAgents => "My agents",
            Self::PendingInvites => "Pending invites",
        }
    }

    pub(super) fn description(self) -> &'static str {
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

    /// Class for this section's entry in the panel's left menu, given which
    /// section is currently selected. One place decides what "active" looks
    /// like, instead of five copies of the same conditional in the component.
    pub(super) fn menu_item_class(self, selected: Self) -> &'static str {
        if self == selected {
            "members-admin-menu-item active"
        } else {
            "members-admin-menu-item"
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct MemberAgentRow {
    pub(super) agent_id: String,
    pub(super) controller_principal_id: String,
    pub(super) display_name: String,
    pub(super) slug: String,
    /// Lifecycle intent wire value (active/paused/deactivated).
    pub(super) status: String,
    /// Derived runtime readiness wire value (key-management.md §3.6.1).
    pub(super) runtime_state: String,
    pub(super) mention_policy: AgentMentionPolicy,
    pub(super) selection: ParticipationBits,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct MemberProfile {
    pub(super) actor_id: String,
    pub(super) subject_id: Option<String>,
    pub(super) invite_id: Option<String>,
    pub(super) invite_is_direct: Option<bool>,
    pub(super) display_name: Option<String>,
    pub(super) avatar_blob_ref: Option<arkret_sdk::BlobRef>,
    pub(super) handles: Vec<String>,
    /// §3.8.2 public label already rendered by
    /// `member_display::resolve_member_display` for roster-backed rows.
    /// Rows synthesised from local invite operations have no roster render
    /// and fall back to the same ladder with no exact account id.
    pub(super) resolved_public_label: Option<String>,
    /// §3.8.2 step 5 degradation tier of `resolved_public_label`.
    pub(super) resolved_tier: Option<crate::views::member_display::MemberDisplayTier>,
    pub(super) remark_name: Option<String>,
    pub(super) remark_note: Option<String>,
    pub(super) confusable_contact_warning: bool,
    pub(super) membership: Option<String>,
    pub(super) pending_invite: bool,
    pub(super) member_display_state_digest: Option<String>,
    pub(super) is_owner: bool,
    pub(super) is_admin: bool,
}

impl MemberProfile {
    pub(super) fn bare(actor_id: impl Into<String>) -> Self {
        Self {
            actor_id: actor_id.into(),
            subject_id: None,
            invite_id: None,
            invite_is_direct: None,
            display_name: None,
            avatar_blob_ref: None,
            handles: Vec::new(),
            resolved_public_label: None,
            resolved_tier: None,
            remark_name: None,
            remark_note: None,
            confusable_contact_warning: false,
            membership: None,
            pending_invite: false,
            member_display_state_digest: None,
            is_owner: false,
            is_admin: false,
        }
    }

    /// `client-preferences.md` §3.6 — an accepted Contact's petname is the
    /// overlay on top of the §3.8.2 render, never a replacement ladder.
    pub(super) fn primary_label(&self) -> String {
        self.remark_name
            .clone()
            .unwrap_or_else(|| self.public_label())
    }

    /// §3.8.2 render without the holder-private petname overlay, plus the
    /// degradation tier the row MUST surface.
    pub(super) fn rendered_public(
        &self,
    ) -> (String, crate::views::member_display::MemberDisplayTier) {
        if let (Some(label), Some(tier)) = (&self.resolved_public_label, self.resolved_tier) {
            return (label.clone(), tier);
        }
        // Invite rows never carry roster handle-claim evidence, so §3.2.1
        // Step 0 has no candidate set; the render starts at the step 4
        // fallback ladder with whatever handle the invite disclosed.
        let cached_handle = self
            .handles
            .first()
            .and_then(|handle| arkret_sdk::Handle::parse(handle).ok());
        let rendered = crate::views::member_display::resolve_subject_display(
            None,
            &[],
            &[],
            None,
            cached_handle.as_ref(),
            self.display_name.as_deref(),
            &member_identity_fallback_label(&self.actor_id),
        );
        (rendered.label, rendered.tier)
    }

    pub(super) fn public_label(&self) -> String {
        self.rendered_public().0
    }

    /// The holder-private petname overlay is not a resolution result, so it
    /// never upgrades the tier out of "degraded".
    pub(super) fn display_tier(&self) -> crate::views::member_display::MemberDisplayTier {
        self.rendered_public().1
    }

    pub(super) fn role_label(&self) -> &'static str {
        if self.is_owner {
            "Realm owner"
        } else if self.is_admin {
            "Realm admin"
        } else {
            "Realm member"
        }
    }

    pub(super) fn normalized_membership(&self) -> Option<&str> {
        self.membership
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub(super) fn is_pending_invite(&self) -> bool {
        self.pending_invite
    }

    pub(super) fn is_governance_principal(&self) -> bool {
        self.is_owner || self.is_admin
    }
}

pub(super) fn member_identity_fallback_label(did: &str) -> String {
    serde_json::from_str::<arkret_sdk::ActorId>(did)
        .map(|actor| short_protocol_id(actor.signing_principal_id().as_str()))
        .unwrap_or_else(|_| short_protocol_id(did))
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct MemberGroup {
    pub(super) controller: MemberProfile,
    pub(super) agents: Vec<MemberAgentRow>,
}

pub(super) fn member_agent_row_from_value(
    row: arkret_models_collaboration::agent_operations::AgentProjection,
    fallback_controller_principal_id: &str,
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
    let controller_principal_id = fallback_controller_principal_id.trim().to_owned();
    Some(MemberAgentRow {
        agent_id,
        controller_principal_id,
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

pub(super) fn mention_state_from_entries(
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

pub(super) use crate::state::realm_membership::{
    is_local_account_actor, principal_core_key, trimmed_string,
};

pub(super) fn owned_agent_actor_key(principal: &str) -> Option<String> {
    let station = crate::operation::authoring_station_id().ok()?;
    let principal = crate::mls_api_helpers::principal_core_id(principal).ok()?;
    Some(arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(principal, station)).to_string())
}

pub(super) fn push_unique(out: &mut Vec<String>, value: impl Into<String>) {
    let value = value.into();
    let value = value.trim();
    if value.is_empty() || out.iter().any(|existing| existing == value) {
        return;
    }
    out.push(value.to_owned());
}

pub(super) fn merge_member_profile(target: &mut MemberProfile, incoming: MemberProfile) {
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
    if target.resolved_public_label.is_none() {
        target.resolved_public_label = incoming.resolved_public_label;
        target.resolved_tier = incoming.resolved_tier;
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

pub(super) fn should_replace_member_membership(
    current: Option<&str>,
    incoming: Option<&str>,
) -> bool {
    let Some(incoming) = normalize_membership_value(incoming) else {
        return false;
    };
    let current = normalize_membership_value(current);
    current.is_none() || membership_precedence(Some(incoming)) > membership_precedence(current)
}

pub(super) fn normalize_membership_value(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

pub(super) fn membership_precedence(value: Option<&str>) -> u8 {
    match normalize_membership_value(value) {
        Some("ban" | "leave") => 5,
        Some("join") => 4,
        Some("invite" | "pending" | "pending_invite") => 2,
        Some("knock") => 1,
        Some(_) => 3,
        None => 0,
    }
}

pub(super) fn upsert_member_profile(
    out: &mut BTreeMap<String, MemberProfile>,
    profile: MemberProfile,
) {
    match out.entry(profile.actor_id.clone()) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(profile);
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            merge_member_profile(entry.get_mut(), profile);
        }
    }
}

pub(super) fn projected_member_profiles_for_realm(
    store: &LocalStateStore,
    realm_id: &str,
) -> Vec<MemberProfile> {
    let state = store.load();
    let mut rows = BTreeMap::<String, MemberProfile>::new();
    let contact_anchor_index = crate::views::member_display::contact_petname_binding_index(
        &store.active_contact_remarks(),
    );
    if let Some(projection) = state.realm_tree_projections.get(realm_id) {
        let handle_issuer_policies =
            crate::views::member_display::realm_handle_issuer_policies(store, realm_id);
        for row in crate::views::member_display::realm_member_roster(Some(projection)) {
            let display = crate::views::member_display::resolve_member_display_with_policies(
                store,
                realm_id,
                &row,
                &handle_issuer_policies,
            );
            let mut profile = MemberProfile::bare(row.actor_id.to_string());
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
            profile.resolved_public_label = Some(display.public_label.clone());
            profile.resolved_tier = Some(display.tier);
            profile.membership = row
                .membership
                .map(crate::views::member_display::membership_wire_str)
                .map(ToOwned::to_owned);
            profile.member_display_state_digest = row.member_display_state_digest;
            upsert_member_profile(&mut rows, profile);
        }
    }
    // Do not infer ownership from the retired authority-root Cell embedded in
    // a local Realm tree projection. Ownership is governance authority, not a
    // roster decoration; until the panel receives a verified governing
    // Station typed-current authority root it must leave `is_owner` false.
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

pub(super) fn local_terminal_invite_ids_for_realm(
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
                Some(event_kind_str::INVITE_CANCEL) => raw_operation_invite_ref(payload),
                // `send_failed` is the one `ak.invite.revoke` target that is not
                // terminal: the invite stays inside the live set and keeps the
                // Realm live-target slot claimed
                // (`governance-objects.md` section 5.3). Hiding it here would
                // tell the operator the account is free to re-invite when it
                // still needs a revoke first.
                Some(event_kind_str::INVITE_REVOKE)
                    if raw_operation_invite_target_state(payload).as_deref()
                        != Some(INVITE_STATE_SEND_FAILED) =>
                {
                    raw_operation_invite_ref(payload)
                }
                _ => None,
            }
        })
        .collect()
}

/// The `ak.component.invite.lifecycle.v1` state of one Invite, folded out of
/// the local Realm operation log.
///
/// The live set is `{pending, send_failed}` and the two recover differently
/// from `invite_live_target_occupied`: `pending` only needs its private
/// delivery re-dispatched, while `send_failed` has no edge back to `pending`
/// and must be revoked before a replacement invite can exist
/// (`governance-objects.md` section 5.3).
pub(super) fn local_invite_lifecycle_state(
    records: &[RawOperationRecord],
    realm_id: &str,
    invite_id: &str,
) -> Option<String> {
    let mut state = None;
    for record in records {
        if !raw_operation_realm_matches_exact(record, realm_id) {
            continue;
        }
        let payload = &record.payload;
        match raw_operation_payload_kind(payload).as_deref() {
            Some(event_kind_str::INVITE_CREATE)
                if trimmed_string(payload.get("invite_id").or_else(|| payload.get("id")))
                    .as_deref()
                    == Some(invite_id) =>
            {
                state = Some("pending".to_owned());
            }
            Some(event_kind_str::INVITE_ACCEPT)
                if raw_operation_is_accepted_fact(payload)
                    && raw_operation_invite_ref(payload).as_deref() == Some(invite_id) =>
            {
                state = Some("accepted".to_owned());
            }
            Some(event_kind_str::INVITE_CANCEL | event_kind_str::INVITE_REVOKE)
                if raw_operation_invite_ref(payload).as_deref() == Some(invite_id) =>
            {
                state = raw_operation_invite_target_state(payload);
            }
            _ => {}
        }
    }
    state
}

pub(super) const INVITE_STATE_SEND_FAILED: &str = "send_failed";

pub(super) fn raw_operation_invite_target_state(payload: &Value) -> Option<String> {
    raw_operation_path_string(payload, &["body", "target_state"])
        .or_else(|| raw_operation_path_string(payload, &["payload", "target_state"]))
        .or_else(|| trimmed_string(payload.get("target_state")))
        .or_else(|| trimmed_string(payload.get("state")))
}

pub(super) fn group_members_with_owned_agents(
    members: &[MemberProfile],
    owned_agents: &[MemberAgentRow],
    fallback_controller_principal_id: &str,
) -> Vec<MemberGroup> {
    let member_set: BTreeSet<&str> = members
        .iter()
        .map(|member| member.actor_id.as_str())
        .collect();
    let owned_agent_ids: BTreeSet<String> = owned_agents
        .iter()
        .filter_map(|agent| owned_agent_actor_key(&agent.agent_id))
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
        .filter(|agent| {
            owned_agent_actor_key(&agent.agent_id)
                .is_some_and(|key| member_set.contains(key.as_str()))
        })
        .cloned()
        .collect();
    in_realm_agents.sort_by(|a, b| {
        a.display_name
            .cmp(&b.display_name)
            .then_with(|| a.agent_id.cmp(&b.agent_id))
    });
    for agent in in_realm_agents {
        let controller = agent.controller_principal_id.trim();
        let controller = if controller.is_empty() {
            fallback_controller_principal_id.trim()
        } else {
            controller
        };
        if let Ok(controller) = crate::mls_api_helpers::local_account_actor_id(controller)
            .map(|actor| actor.to_string())
        {
            let controller_profile = member_by_actor
                .get(controller.as_str())
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
        let left_is_self =
            is_local_account_actor(&left.controller.actor_id, fallback_controller_principal_id);
        let right_is_self =
            is_local_account_actor(&right.controller.actor_id, fallback_controller_principal_id);
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

pub(super) fn split_owned_agents_for_realm(
    owned_agents: &[MemberAgentRow],
    member_set: &BTreeSet<String>,
) -> (Vec<MemberAgentRow>, Vec<MemberAgentRow>) {
    let joined = owned_agents
        .iter()
        .filter(|agent| {
            owned_agent_actor_key(&agent.agent_id).is_some_and(|key| member_set.contains(&key))
        })
        .cloned()
        .collect();
    let available = owned_agents
        .iter()
        .filter(|agent| {
            owned_agent_actor_key(&agent.agent_id).is_some_and(|key| !member_set.contains(&key))
                && agent.status == "active"
        })
        .cloned()
        .collect();
    (joined, available)
}

pub(super) fn split_member_profiles(
    members: Vec<MemberProfile>,
) -> (Vec<MemberProfile>, Vec<MemberProfile>) {
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

pub(super) fn upsert_pending_invite_profile(
    rows: &mut Vec<MemberProfile>,
    actor_id: &str,
    label: Option<&str>,
    invite_id: Option<&str>,
) {
    let Some(actor_id) = serde_json::from_str::<arkret_sdk::ActorId>(actor_id)
        .ok()
        .map(|actor| actor.to_string())
    else {
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
        match crate::identity::handle::normalize_user_handle_display(label) {
            Some(handle) => push_unique(&mut profile.handles, handle),
            // A label that is not a canonical handle is a display name, not
            // a handle: §3.8.2 forbids showing an unverified string in the
            // handle rung.
            None => {
                if profile.display_name.is_none() {
                    profile.display_name = Some(label.to_owned());
                }
            }
        }
    };
    if let Some(existing) = rows
        .iter_mut()
        .find(|profile| profile.actor_id.trim() == actor_id)
    {
        existing.pending_invite = existing.normalized_membership() != Some("join");
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
    profile.pending_invite = true;
    profile.invite_id = invite_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    profile.invite_is_direct = Some(true);
    apply_label(&mut profile);
    rows.push(profile);
    rows.sort_by(|left, right| left.actor_id.cmp(&right.actor_id));
}

pub(super) fn local_pending_invite_profile_from_raw_operation(
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
    let direct_invitee = raw_invite_create_account_id(payload)
        .map(|account_id| arkret_sdk::ActorId::account(account_id).to_string());
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
    profile.pending_invite = true;
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
        } else if let Some(handle) = crate::identity::handle::normalize_user_handle_display(&label)
        {
            push_unique(&mut profile.handles, handle);
        } else {
            profile.display_name = Some(label.clone());
        }
    }
    Some(profile)
}

pub(super) use crate::state::realm_membership::{
    AcceptedInviteClaimRoute, accepted_invite_claim_route, claim_target_device_id,
    local_invitee_by_invite_id_for_realm, raw_invite_create_account_id, raw_invite_create_invitee,
    raw_member_actor_id, raw_member_membership, raw_operation_invite_ref,
    raw_operation_is_accepted_fact, raw_operation_path_string, raw_operation_payload_kind,
    raw_operation_realm_matches_exact,
};
pub(super) fn local_membership_profile_from_raw_operation(
    record: &RawOperationRecord,
    realm_id: &str,
    invitee_by_invite_id: &BTreeMap<String, String>,
) -> Option<MemberProfile> {
    let fact = crate::state::realm_membership::local_membership_fact_from_raw_operation(
        record,
        realm_id,
        invitee_by_invite_id,
    )?;
    let mut profile = MemberProfile::bare(fact.actor_id);
    profile.membership = fact.membership;
    profile.invite_id = fact.invite_id;
    Some(profile)
}

pub(super) fn member_profile_matches(profile: &MemberProfile, query: &str) -> bool {
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

pub(super) fn member_group_matches(group: &MemberGroup, query: &str) -> bool {
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

pub(super) fn member_group_in_section(
    group: &MemberGroup,
    section: MemberRosterSection,
    principal_id: &str,
) -> bool {
    match section {
        MemberRosterSection::Members => !group.controller.is_governance_principal(),
        MemberRosterSection::Owners => group.controller.is_owner,
        MemberRosterSection::Admins => group.controller.is_admin && !group.controller.is_owner,
        MemberRosterSection::MyAgents => {
            is_local_account_actor(&group.controller.actor_id, principal_id)
        }
        MemberRosterSection::PendingInvites => false,
    }
}

pub(super) fn member_line_identity_visible(
    identity_label: &str,
    primary_label: &str,
    handles: &[String],
) -> bool {
    let identity = identity_label.trim();
    !identity.is_empty()
        && identity != primary_label.trim()
        && !handles.iter().any(|handle| handle.trim() == identity)
}

pub(super) fn member_handles_for_line(handles: &[String], primary_label: &str) -> Vec<String> {
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

pub(super) fn member_handles_line_label(
    all_handles: &[String],
    visible_handles: &[String],
) -> &'static str {
    if visible_handles.len() == all_handles.len() {
        "Handles"
    } else {
        "Other handles"
    }
}

/// Inputs the members list derives its rendered shape from.
pub(super) struct RealmRosterInput<'a> {
    pub(super) members: Vec<MemberProfile>,
    pub(super) owned_agents: Vec<MemberAgentRow>,
    pub(super) principal_id: &'a str,
    pub(super) section: MemberRosterSection,
    /// Raw search box contents. Normalized here so no caller has to remember
    /// that the roster filter is trimmed and case-folded.
    pub(super) query: &'a str,
    /// How many groups the list is currently willing to mount.
    pub(super) visible_limit: usize,
}

/// Everything the members panel derives from the roster before it renders.
///
/// The panel used to compute this inline between its `use_signal` declarations
/// and its `rsx!`. That block read Signals and wrote none, so it was pure in
/// substance but unreachable from a test in form. Splitting it out leaves the
/// component with one job — read the Signals, hand them over — and makes every
/// rule below assertable on plain data.
pub(super) struct RealmRosterView {
    pub(super) visible_groups: Vec<MemberGroup>,
    pub(super) visible_pending_invites: Vec<MemberProfile>,
    /// Actor keys of every active member, for "is this agent already in the
    /// Realm" checks in the agent list.
    pub(super) member_set: BTreeSet<String>,
    /// The caller's own agents that already joined this Realm.
    pub(super) self_realm_agent_rows: Vec<MemberAgentRow>,
    /// The caller's own agents eligible to be added to it.
    pub(super) available_self_agent_rows: Vec<MemberAgentRow>,
    pub(super) total_members: usize,
    pub(super) total_owner_members: usize,
    pub(super) total_admin_members: usize,
    pub(super) total_regular_members: usize,
    pub(super) total_pending_invites: usize,
    pub(super) pending_invite_match_count: usize,
    /// Groups matching the section and the query, before the paging cap.
    pub(super) filtered_count: usize,
    /// Groups actually mounted: `filtered_count` capped by the paging window.
    pub(super) visible: usize,
    pub(super) has_more: bool,
    pub(super) show_search: bool,
    pub(super) selected_section_total: usize,
    pub(super) selected_section_visible_count: usize,
    pub(super) selected_section_empty: bool,
    /// `None` when the caller may leave the Realm; otherwise the reason the
    /// leave control is disabled.
    pub(super) self_leave_disabled_reason: Option<String>,
    /// Trimmed, case-folded query, so the empty-state copy and the filter
    /// agree on what "no search" means.
    pub(super) filter_query: String,
}

/// Roster to grouped-by-controller to filtered to paged window. Filtering
/// stays cheap; pagination keeps the mounted row count bounded while keeping
/// each controller's agents visually attached to the owner.
pub(super) fn build_realm_roster(input: RealmRosterInput<'_>) -> RealmRosterView {
    let RealmRosterInput {
        members,
        owned_agents,
        principal_id,
        section,
        query,
        visible_limit,
    } = input;
    let (active_members, pending_invite_rows) = split_member_profiles(members);
    let member_groups =
        group_members_with_owned_agents(&active_members, &owned_agents, principal_id);
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
        is_local_account_actor(&member.actor_id, principal_id) && member.is_governance_principal()
    });
    // Authority-root controller: `capabilities.md` §10.4 L858 — the root
    // controller's only exit is `ak.realm.owner.transfer`, regardless of how
    // many other admins exist, so this outranks the softer last-admin guard.
    let self_is_root_controller = active_members
        .iter()
        .any(|member| is_local_account_actor(&member.actor_id, principal_id) && member.is_owner);
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
    let filter_query = query.trim().to_lowercase();
    let section_groups: Vec<MemberGroup> = member_groups
        .into_iter()
        .filter(|group| member_group_in_section(group, section, principal_id))
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
    let visible = visible_limit.min(filtered_count);
    let visible_groups: Vec<MemberGroup> = filtered_groups[..visible].to_vec();
    let has_more = section != MemberRosterSection::PendingInvites && visible < filtered_count;
    let show_search = section != MemberRosterSection::MyAgents
        && total_groups + total_pending_invites > MEMBER_SEARCH_THRESHOLD;
    let visible_pending_invites: Vec<MemberProfile> = if filter_query.is_empty() {
        pending_invite_rows
    } else {
        pending_invite_rows
            .into_iter()
            .filter(|profile| member_profile_matches(profile, &filter_query))
            .collect()
    };
    let pending_invite_match_count = visible_pending_invites.len();
    let member_set: BTreeSet<String> = active_members
        .iter()
        .map(|member| member.actor_id.clone())
        .collect();
    let self_owned_agent_rows: Vec<MemberAgentRow> = owned_agents
        .into_iter()
        .filter(|agent| {
            let controller = agent.controller_principal_id.trim();
            controller.is_empty() || controller == principal_id.trim()
        })
        .collect();
    let (self_realm_agent_rows, available_self_agent_rows) =
        split_owned_agents_for_realm(&self_owned_agent_rows, &member_set);
    let selected_section_total = match section {
        MemberRosterSection::Members => total_regular_members,
        MemberRosterSection::Owners => total_owner_members,
        MemberRosterSection::Admins => total_admin_members,
        MemberRosterSection::MyAgents => self_realm_agent_rows.len(),
        MemberRosterSection::PendingInvites => total_pending_invites,
    };
    let selected_section_visible_count = match section {
        MemberRosterSection::PendingInvites => pending_invite_match_count,
        MemberRosterSection::MyAgents => self_realm_agent_rows.len(),
        _ => filtered_count,
    };
    RealmRosterView {
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
        selected_section_empty: selected_section_visible_count == 0,
        self_leave_disabled_reason,
        filter_query,
    }
}
