use std::collections::{BTreeMap, BTreeSet};

use cokret_sdk::models::{
    AgentKeyScope, AgentParticipation, AgentParticipationEntry, AgentParticipationScope,
    AgentProvisionRequestBody,
};
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use serde_json::{Value, json};

use super::permissions::{RealmMemberPermissions, authz_json_allowed};
use crate::components::SelfAttributionBadge;
use crate::local_state::{LocalStateStore, MoveSubmissionState, RawOperationRecord};
use crate::operation::ck_ops;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::views::helpers::{
    active_sync_token, authed_api_with_sync, display_name_for_did, handle_display_from_did,
    short_protocol_id,
};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MemberRosterSection {
    Members,
    Owners,
    Admins,
    PendingInvites,
}

impl MemberRosterSection {
    fn title(self) -> &'static str {
        match self {
            Self::Members => "Members",
            Self::Owners => "Owners",
            Self::Admins => "Admins",
            Self::PendingInvites => "Pending invites",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Members => "Active Realm members without owner or admin authority.",
            Self::Owners => "Realm owners with top-level governance authority.",
            Self::Admins => "Realm admins with management authority.",
            Self::PendingInvites => {
                "Invitations sent for this Realm that have not been accepted yet."
            }
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
struct MemberProfile {
    actor_id: String,
    subject_id: Option<String>,
    invite_id: Option<String>,
    display_name: Option<String>,
    avatar_blob_ref: Option<String>,
    avatar_url: Option<String>,
    handles: Vec<String>,
    remark_name: Option<String>,
    remark_note: Option<String>,
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
            display_name: None,
            avatar_blob_ref: None,
            avatar_url: None,
            handles: Vec::new(),
            remark_name: None,
            remark_note: None,
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
    handle_display_from_did(did).unwrap_or_else(|| short_protocol_id(did))
}

#[derive(Clone, Debug, PartialEq)]
struct AgentProvisionSummary {
    agent_principal_id: String,
    pairing_request_id: String,
    pairing_code: Option<String>,
    expires_at: String,
}

#[derive(Clone, Debug, PartialEq)]
struct MemberGroup {
    controller: MemberProfile,
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

async fn fetch_owned_agent_rows(
    api: &crate::api::CokretApi,
    realm: &str,
    fallback_controller_did: &str,
) -> anyhow::Result<Vec<MemberAgentRow>> {
    let list = api.agent_list().await?;
    let mut rows = Vec::<MemberAgentRow>::new();
    for value in list.agents {
        let Some(mut row) = member_agent_row_from_value(value, fallback_controller_did) else {
            continue;
        };
        match api.agent_participation_get(&row.agent_principal_id).await {
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
            .then_with(|| left.agent_principal_id.cmp(&right.agent_principal_id))
    });
    Ok(rows)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProjectedMemberRole {
    Member,
    Admin,
    Owner,
}

impl ProjectedMemberRole {
    fn from_projection_key(key: &str) -> Self {
        match key {
            "owner" | "created_by" | "creator" => Self::Owner,
            "admins" | "admin_dids" => Self::Admin,
            _ => Self::Member,
        }
    }
}

fn trimmed_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn projection_path_string(
    map: &serde_json::Map<String, Value>,
    paths: &[&[&str]],
) -> Option<String> {
    for path in paths {
        let Some((first, rest)) = path.split_first() else {
            continue;
        };
        let Some(mut current) = map.get(*first) else {
            continue;
        };
        let mut found = true;
        for segment in rest {
            if let Some(next) = current.get(*segment) {
                current = next;
            } else {
                found = false;
                break;
            }
        }
        if !found {
            continue;
        }
        if let Some(value) = trimmed_string(Some(current)) {
            return Some(value);
        }
    }
    None
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
    crate::identity_handle::parse_user_handle(raw)
        .map(|handle| handle.display)
        .or_else(|| Some(raw.to_owned()))
}

fn collect_string_values(value: Option<&Value>, out: &mut Vec<String>) {
    let Some(value) = value else { return };
    match value {
        Value::String(raw) => {
            if let Some(label) = normalize_handle_label(raw) {
                push_unique(out, label);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_string_values(Some(item), out);
            }
        }
        Value::Object(map) => {
            for key in [
                "handle",
                "primary_handle",
                "verified_handle",
                "value",
                "uri",
            ] {
                if let Some(label) = map
                    .get(key)
                    .and_then(Value::as_str)
                    .and_then(normalize_handle_label)
                {
                    push_unique(out, label);
                }
            }
        }
        _ => {}
    }
}

fn collect_handle_claims(value: Option<&Value>, subject_id: Option<&str>, out: &mut Vec<String>) {
    let Some(value) = value else { return };
    let Some(items) = value.as_array() else {
        return;
    };
    for claim in items {
        let claim_subject = trimmed_string(
            claim
                .get("subject")
                .or_else(|| claim.get("subject_id"))
                .or_else(|| claim.get("holder")),
        );
        if let (Some(expected), Some(actual)) = (subject_id, claim_subject.as_deref())
            && expected.trim() != actual.trim()
        {
            continue;
        }
        let binding_state = claim
            .get("binding_state")
            .and_then(Value::as_str)
            .unwrap_or("verified");
        if !matches!(binding_state, "verified" | "active") {
            continue;
        }
        if let Some(label) = claim
            .get("handle")
            .and_then(Value::as_str)
            .and_then(normalize_handle_label)
        {
            push_unique(out, label);
        }
    }
}

fn collect_member_handles(
    map: &serde_json::Map<String, Value>,
    subject_id: Option<&str>,
) -> Vec<String> {
    let mut handles = Vec::new();
    for key in ["handle", "primary_handle", "verified_handle"] {
        if let Some(label) = map
            .get(key)
            .and_then(Value::as_str)
            .and_then(normalize_handle_label)
        {
            push_unique(&mut handles, label);
        }
    }
    for key in ["handles", "handle_uris"] {
        collect_string_values(map.get(key), &mut handles);
    }
    collect_handle_claims(map.get("handle_claims"), subject_id, &mut handles);
    for container in ["profile", "identity", "display", "metadata"] {
        if let Some(Value::Object(child)) = map.get(container) {
            for key in ["handle", "primary_handle", "verified_handle", "handles"] {
                collect_string_values(child.get(key), &mut handles);
            }
            collect_handle_claims(child.get("handle_claims"), subject_id, &mut handles);
        }
    }
    handles
}

fn profile_from_projected_member_object(
    map: &serde_json::Map<String, Value>,
    role: ProjectedMemberRole,
    fallback_actor_id: Option<&str>,
) -> Option<MemberProfile> {
    let actor_id = trimmed_string(
        map.get("actor_id")
            .or_else(|| map.get("did"))
            .or_else(|| map.get("principal_id")),
    )
    .or_else(|| {
        fallback_actor_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })?;
    let subject_id = trimmed_string(
        map.get("subject_id")
            .or_else(|| map.get("subject"))
            .or_else(|| map.get("holder")),
    );
    let mut profile = MemberProfile::bare(actor_id);
    profile.subject_id = subject_id;
    profile.invite_id = trimmed_string(map.get("invite_id").or_else(|| map.get("id")));
    profile.display_name = projection_path_string(
        map,
        &[
            &["display_name"],
            &["profile", "display_name"],
            &["identity", "display_name"],
            &["display_profile", "display_name"],
            &["member_identity", "display_profile", "display_name"],
        ],
    );
    profile.avatar_blob_ref = projection_path_string(
        map,
        &[
            &["avatar_blob_ref"],
            &["profile", "avatar_blob_ref"],
            &["identity", "avatar_blob_ref"],
            &["display_profile", "avatar_blob_ref"],
            &["member_identity", "display_profile", "avatar_blob_ref"],
        ],
    );
    profile.avatar_url = projection_path_string(
        map,
        &[
            &["avatar_url"],
            &["profile", "avatar_url"],
            &["identity", "avatar_url"],
            &["picture"],
        ],
    );
    profile.handles = collect_member_handles(map, profile.subject_id.as_deref());
    profile.membership = trimmed_string(map.get("membership").or_else(|| map.get("state")));
    profile.member_display_state_digest = trimmed_string(map.get("member_display_state_digest"));
    profile.is_owner = role == ProjectedMemberRole::Owner;
    profile.is_admin = matches!(
        role,
        ProjectedMemberRole::Admin | ProjectedMemberRole::Owner
    );
    Some(profile)
}

fn merge_member_profile(target: &mut MemberProfile, incoming: MemberProfile) {
    if target.subject_id.is_none() {
        target.subject_id = incoming.subject_id;
    }
    if target.invite_id.is_none() {
        target.invite_id = incoming.invite_id;
    }
    if target.display_name.is_none() {
        target.display_name = incoming.display_name;
    }
    if target.avatar_blob_ref.is_none() {
        target.avatar_blob_ref = incoming.avatar_blob_ref;
    }
    if target.avatar_url.is_none() {
        target.avatar_url = incoming.avatar_url;
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

fn collect_projected_member_profiles(
    value: Option<&Value>,
    role: ProjectedMemberRole,
    out: &mut BTreeMap<String, MemberProfile>,
) {
    let Some(value) = value else { return };
    match value {
        Value::String(actor_id) => {
            let mut profile = MemberProfile::bare(actor_id.trim().to_owned());
            profile.is_owner = role == ProjectedMemberRole::Owner;
            profile.is_admin = matches!(
                role,
                ProjectedMemberRole::Admin | ProjectedMemberRole::Owner
            );
            upsert_member_profile(out, profile);
        }
        Value::Array(items) => {
            for item in items {
                collect_projected_member_profiles(Some(item), role, out);
            }
        }
        Value::Object(map) => {
            if let Some(profile) = profile_from_projected_member_object(map, role, None) {
                upsert_member_profile(out, profile);
                return;
            }
            for (key, child) in map {
                if key.starts_with("did:") {
                    let profile = child
                        .as_object()
                        .and_then(|child_map| {
                            profile_from_projected_member_object(child_map, role, Some(key))
                        })
                        .unwrap_or_else(|| {
                            let mut profile = MemberProfile::bare(key.clone());
                            profile.is_owner = role == ProjectedMemberRole::Owner;
                            profile.is_admin = matches!(
                                role,
                                ProjectedMemberRole::Admin | ProjectedMemberRole::Owner
                            );
                            profile
                        });
                    upsert_member_profile(out, profile);
                }
                collect_projected_member_profiles(Some(child), role, out);
            }
        }
        _ => {}
    }
}

fn member_inline_handle_label(profile: &MemberProfile) -> Option<String> {
    profile.handles.first().cloned()
}

fn member_handle_lookup_subject(profile: &MemberProfile) -> Option<String> {
    if let Some(subject) = profile
        .subject_id
        .as_deref()
        .map(str::trim)
        .filter(|value| value.starts_with("did:"))
        .filter(|value| !value.is_empty())
    {
        return Some(subject.to_owned());
    }
    let actor = profile.actor_id.trim();
    actor.starts_with("did:").then(|| actor.to_owned())
}

fn enrich_member_profile_from_store(
    store: &LocalStateStore,
    realm_id: &str,
    profile: &mut MemberProfile,
) {
    if let Some(identity) = store.resolved_member_identity(realm_id, &profile.actor_id) {
        if profile.subject_id.is_none() {
            profile.subject_id = Some(identity.subject_id.as_str().to_owned());
        }
        if profile.display_name.is_none() {
            let display_name = identity.display_profile.display_name.trim();
            if !display_name.is_empty() {
                profile.display_name = Some(display_name.to_owned());
            }
        }
        if profile.avatar_blob_ref.is_none() {
            profile.avatar_blob_ref = identity
                .display_profile
                .avatar_blob_ref
                .as_ref()
                .map(ToString::to_string);
        }
    }
    if let Some(subject_id) = member_handle_lookup_subject(profile)
        && member_inline_handle_label(profile).is_none()
        && let Some(entry) = store.cached_member_handle_lookup(
            &subject_id,
            Some(realm_id),
            profile.member_display_state_digest.as_deref(),
        )
        && let Some(handle) = entry.primary_handle
        && let Some(label) = normalize_handle_label(&handle)
    {
        push_unique(&mut profile.handles, label);
    }
    if member_inline_handle_label(profile).is_none()
        && let Some(handle) = profile
            .subject_id
            .as_deref()
            .and_then(handle_display_from_did)
            .or_else(|| handle_display_from_did(&profile.actor_id))
    {
        push_unique(&mut profile.handles, handle);
    }
    if let Some(remark) = store.contact_remark(&profile.actor_id) {
        let local_name = remark.local_name.trim();
        if !local_name.is_empty() {
            profile.remark_name = Some(local_name.to_owned());
        }
        let note = remark.note.trim();
        if !note.is_empty() {
            profile.remark_note = Some(note.to_owned());
        }
    }
    if profile.display_name.is_none() && profile.handles.is_empty() {
        let fallback = display_name_for_did(store, &profile.actor_id);
        if fallback != short_protocol_id(&profile.actor_id) {
            profile.display_name = Some(fallback);
        }
    }
}

fn projected_member_profiles_for_realm(
    store: &LocalStateStore,
    realm_id: &str,
) -> Vec<MemberProfile> {
    let state = store.load();
    let mut rows = BTreeMap::<String, MemberProfile>::new();
    if let Some(projection) = state.realm_tree_projections.get(realm_id) {
        let sources = [Some(projection), projection.get("summary")];
        for key in [
            "members",
            "participants",
            "owners",
            "admins",
            "admin_dids",
            "owner",
            "created_by",
            "creator",
        ] {
            let role = ProjectedMemberRole::from_projection_key(key);
            for source in sources.into_iter().flatten() {
                collect_projected_member_profiles(source.get(key), role, &mut rows);
            }
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
        enrich_member_profile_from_store(store, realm_id, profile);
    }
    out
}

fn local_terminal_invite_ids_for_realm(
    records: &[RawOperationRecord],
    realm_id: &str,
) -> BTreeSet<String> {
    records
        .iter()
        .filter(|record| record.realm_id.as_deref().map(str::trim) == Some(realm_id.trim()))
        .filter_map(|record| {
            let payload = &record.payload;
            match trimmed_string(payload.get("kind")).as_deref() {
                Some("ck.invite.cancel" | "ck.invite.revoke") => {
                    trimmed_string(payload.get("invite_id").or_else(|| payload.get("id")))
                }
                _ => None,
            }
        })
        .collect()
}

fn group_members_with_owned_agents(
    members: &[MemberProfile],
    owned_agents: &[MemberAgentRow],
    fallback_controller_did: &str,
) -> Vec<MemberGroup> {
    let member_set: BTreeSet<&str> = members
        .iter()
        .map(|member| member.actor_id.as_str())
        .collect();
    let owned_agent_ids: BTreeSet<&str> = owned_agents
        .iter()
        .map(|agent| agent.agent_principal_id.as_str())
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

    groups.into_values().collect()
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
    let actor_id = actor_id.trim();
    if actor_id.is_empty() {
        return;
    }
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
        apply_label(existing);
        return;
    }
    let mut profile = MemberProfile::bare(actor_id.to_owned());
    profile.membership = Some("invite".to_owned());
    profile.invite_id = invite_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    apply_label(&mut profile);
    rows.push(profile);
    rows.sort_by(|left, right| left.actor_id.cmp(&right.actor_id));
}

fn local_pending_invite_profile_from_raw_operation(
    record: &RawOperationRecord,
    realm_id: &str,
) -> Option<MemberProfile> {
    let record_realm = record.realm_id.as_deref().map(str::trim);
    if record_realm != Some(realm_id.trim()) {
        return None;
    }
    let payload = &record.payload;
    if trimmed_string(payload.get("kind")).as_deref() != Some("ck.invite.create") {
        return None;
    }
    let state = trimmed_string(payload.get("state").or_else(|| payload.get("status")))
        .unwrap_or_else(|| "pending".to_owned());
    if !matches!(state.as_str(), "pending" | "pending_invite" | "invite") {
        return None;
    }
    let actor_id = trimmed_string(
        payload
            .get("invitee")
            .or_else(|| payload.get("actor_id"))
            .or_else(|| payload.get("member")),
    )?;
    let mut profile = MemberProfile::bare(actor_id.clone());
    profile.membership = Some("invite".to_owned());
    profile.invite_id = trimmed_string(payload.get("invite_id").or_else(|| payload.get("id")));
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
            agent.agent_principal_id.to_lowercase().contains(&query)
                || agent.display_name.to_lowercase().contains(&query)
                || agent.agent_slug.to_lowercase().contains(&query)
        })
}

fn member_group_in_section(group: &MemberGroup, section: MemberRosterSection) -> bool {
    match section {
        MemberRosterSection::Members => !group.controller.is_governance_principal(),
        MemberRosterSection::Owners => group.controller.is_owner,
        MemberRosterSection::Admins => group.controller.is_admin && !group.controller.is_owner,
        MemberRosterSection::PendingInvites => false,
    }
}

fn agent_invite_target(agent_principal_id: &str, service_did: &str) -> String {
    format!(
        "subject_id={} recipient_service_did={}",
        agent_principal_id.trim(),
        service_did.trim()
    )
}

fn member_avatar_initial_from_value(value: &str) -> String {
    crate::views::helpers::avatar_initial_from_identity_value(value)
        .unwrap_or_else(|| "?".to_owned())
}

fn member_avatar_initial(profile: &MemberProfile) -> String {
    if let Some(initial) = profile
        .remark_name
        .as_deref()
        .or(profile.display_name.as_deref())
        .and_then(crate::views::helpers::avatar_initial_from_identity_value)
    {
        return initial;
    }
    let identity = profile
        .subject_id
        .as_deref()
        .unwrap_or(profile.actor_id.as_str());
    crate::views::helpers::identity_avatar_initial(&profile.handles, identity)
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
    is_self: bool,
    #[props(default)] leave_disabled_reason: Option<String>,
    sync_cursor: Signal<String>,
    state_store: Signal<LocalStateStore>,
    mut status_msg: Signal<String>,
    mut block_confirm_did: Signal<Option<String>>,
) -> Element {
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
                        let actor_account_did = account_did.clone();
                        let disabled_reason = leave_disabled_reason.clone();
                        move |_| {
                            if let Some(reason) = disabled_reason.clone() {
                                status_msg.set(reason);
                                return;
                            }
                            let base = base.clone();
                            let realm = realm.clone();
                            let api_token = token();
                            let actor_id = actor_account_did.trim().to_owned();
                            if actor_id.is_empty() {
                                status_msg.set("Leave Realm failed: account is not connected".to_owned());
                                return;
                            }
                            spawn(async move {
                                let realm_for_msg = realm.clone();
                                match crate::views::helpers::with_authed_api(
                                    &base,
                                    api_token,
                                    |api| async move {
                                        api.leave_realm(&realm, &actor_id).await
                                    },
                                )
                                .await
                                {
                                    Ok(_) => {
                                        state_store.write().forget_realm_tree_projection(&realm_for_msg);
                                        sync_cursor.set("-".to_owned());
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
                        let actor_account_did = account_did.clone();
                        move |_| {
                            let base = base.clone();
                            let realm = realm.clone();
                            let target = target.clone();
                            let target_label = target_label.clone();
                            let api_token = token();
                            let actor_id = actor_account_did.clone();
                            spawn(async move {
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
                        let actor_account_did = account_did.clone();
                        move |_| {
                            let base = base.clone();
                            let realm = realm.clone();
                            let target = target.clone();
                            let target_label = target_label.clone();
                            let api_token = token();
                            let actor_id = actor_account_did.clone();
                            spawn(async move {
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
    base_url: String,
    token: Signal<String>,
    account_did: String,
    selected_realm_id: String,
    can_cancel_invite: bool,
    mut members: Signal<Vec<MemberProfile>>,
    state_store: Signal<LocalStateStore>,
    mut frontier_state: Signal<String>,
    mut status_msg: Signal<String>,
) -> Element {
    let member = profile.actor_id.clone();
    let member_label = profile.primary_label();
    let avatar_initial = member_avatar_initial(&profile);
    let avatar_blob_ref = profile.avatar_blob_ref.clone();
    let avatar_url = profile.avatar_url.clone();
    let invite_id = profile.invite_id.clone().unwrap_or_default();
    let can_cancel_this_invite = can_cancel_invite && !invite_id.trim().is_empty();
    let cancel_title = if can_cancel_this_invite {
        "Cancel pending invite"
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
                    if let Some(blob_ref) = avatar_blob_ref.clone() {
                        div { class: "member-avatar-image",
                            crate::content::renderer::AuthenticatedBlobImage {
                                blob_ref,
                                alt_text: member_label.clone(),
                            }
                        }
                    } else if let Some(url) = avatar_url.clone() {
                        img {
                            class: "member-avatar-img",
                            src: "{url}",
                            alt: "{member_label}",
                            title: "{member}"
                        }
                    } else if avatar_initial == "?" {
                        crate::components::UiIcon { name: "user-plus" }
                    } else {
                        "{avatar_initial}"
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
                            span { title: "{member}", "{member_identity_label}" }
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
                        if !handles.is_empty() {
                            div { class: "member-profile-line member-handle-list",
                                span { class: "member-profile-label", "Handles" }
                                for handle in handles.clone() {
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
                if can_cancel_invite {
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "cancel-pending-invite-button",
                        disabled: !can_cancel_this_invite,
                        title: "{cancel_title}",
                        onclick: {
                            let base = base_url.clone();
                            let realm = selected_realm_id.clone();
                            let actor = account_did.clone();
                            let invite_id = invite_id.clone();
                            let member = member.clone();
                            let member_label = member_label.clone();
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
                                let api_token = token();
                                spawn(async move {
                                    let request_realm = realm.clone();
                                    let request_invite_id = invite_id.clone();
                                    match crate::views::helpers::with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            api.reject_realm_invite(
                                                &request_realm,
                                                &actor,
                                                &request_invite_id,
                                                Some("admin_cancel"),
                                            )
                                            .await
                                        },
                                    )
                                    .await
                                    {
                                        Ok(resp) => {
                                            frontier_state.set(resp.event_id.clone());
                                            state_store.write().append_raw_operation(
                                                format!("ck:operation:{}", crate::operation::uuid_v7()),
                                                Some(realm.clone()),
                                                json!({
                                                    "kind": "ck.invite.cancel",
                                                    "invite_id": invite_id.clone(),
                                                    "invitee": member.clone(),
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
                                            status_msg.set(format!("cancelled invite for {member_label}"));
                                        }
                                        Err(err) => status_msg.set(format!(
                                            "cancel invite failed: {}",
                                            err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        "Cancel invite"
                    }
                }
            }
        }
    }
}

pub(crate) async fn submit_mls_admission_for_invitee(
    api: &crate::api::CokretApi,
    mut state_store: Signal<LocalStateStore>,
    realm_id: String,
    actor_id: String,
    device_id: String,
    invitee_did: String,
) -> anyhow::Result<Option<u64>> {
    let needs_mls_admission = {
        let store = state_store.read();
        store.mls_snapshot_for(&realm_id).is_some()
            || store.realm_projection_is_mls_encrypted(&realm_id)
    };
    if !needs_mls_admission {
        return Ok(None);
    }
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
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    ensure_mls_genesis_frontier_for_invite(
        api,
        state_store,
        secure_store.as_ref(),
        &realm_id,
        &actor_id,
        &device_id,
    )
    .await?;
    let claim_nonce = crate::api::generate_mls_claim_nonce()?;
    let claim_outcome = api
        .claim_mls_key_package(
            &invitee_did,
            &realm_id,
            &actor_id,
            &claim_nonce,
            None,
            Some(&group_id),
        )
        .await?;
    let failures = claim_outcome.failures;
    let claim = claim_outcome.claims.into_iter().next().ok_or_else(|| {
        let reason = failures
            .first()
            .map(|failure| format!("{failure:?}"))
            .unwrap_or_else(|| "no MLS KeyPackage was available for the invitee".to_owned());
        anyhow::anyhow!("{reason}")
    })?;
    let admission = {
        let store = state_store.read();
        crate::mls::admission::build_realm_mls_admission_events_from_claim(
            &store,
            secure_store.as_ref(),
            &realm_id,
            &actor_id,
            &device_id,
            &claim,
            &claim_nonce,
        )
        .map_err(|err| anyhow::anyhow!(err))?
    };
    let next_epoch = admission.snapshot.epoch;
    let invitee_device_id = claim.device_id.clone();
    // Fail-closed ordering: submit the add-member `ck.mls.commit` FIRST and
    // confirm soland accepted it BEFORE delivering the Welcome. The Welcome
    // hands the invitee the post-add (epoch N+1) group state; if it landed while
    // the commit was rejected (e.g. `governance_binding_mismatch`), the invitee
    // would join at epoch N+1 while this admin and the server stayed at epoch N —
    // a permanent fork in which neither side can decrypt the other's messages.
    // Submitting the Welcome only after the commit confirms keeps every member
    // on one epoch chain.
    let commit_event_id = admission.commit.event_id.clone();
    let commit_outcome = api
        .submit_sdk_events_batch(&realm_id, vec![admission.commit], None)
        .await?;
    let commit_accepted = commit_outcome
        .accepted
        .iter()
        .chain(commit_outcome.duplicate.iter())
        .any(|event_id| event_id == &commit_event_id);
    if !commit_accepted {
        return Err(anyhow::anyhow!(
            "MLS admission commit for invitee was not accepted (status={:?}, rejected={:?}); invitee not admitted to avoid an epoch fork",
            commit_outcome.status,
            commit_outcome.rejected
        ));
    }
    api.submit_sdk_events_batch(&realm_id, vec![admission.welcome], None)
        .await?;
    {
        let mut store = state_store.write();
        store.save_mls_snapshot(realm_id.clone(), admission.snapshot);
        // History sharing (encryption-and-audit.md): retain THIS epoch's
        // `history_secret` so a late joiner can later be granted read access to
        // content authored from here on. Best-effort — a failure to retain only
        // means the provider must re-derive on demand from the current epoch.
        let _ = crate::mls::runtime::derive_and_retain_realm_history_secret(
            &mut store,
            secure_store.as_ref(),
            &realm_id,
            &actor_id,
            &device_id,
        );
    }
    // Eager RRK seal (encryption-and-audit.md §2.10.8): if this Realm declares an
    // effective `durability_policy` (mode != none + mls-exporter-aead-v1), seal
    // the retained history_secret(s) to every recovery recipient right after the
    // admission commit advances the epoch and before any (future) GC. yougen
    // never GCs history_secrets, so this only needs to be eager, not blocking.
    if state_store.read().realm_durability_is_rrk_active(&realm_id) {
        if let Err(err) = seal_history_to_recovery_recipients(
            api,
            state_store,
            realm_id.clone(),
            actor_id.clone(),
            device_id.clone(),
        )
        .await
        {
            tracing::warn!(
                realm = %short_protocol_id(&realm_id),
                error = %err,
                "RRK eager seal pass failed after admission commit; history_secret retained for retry"
            );
        }
    }
    // Proactive provider push of `ck.realm_key.share` at admission time would
    // need the invitee device's HPKE public key. The claimed KeyPackage's
    // X25519 init key is not surfaced by the current SDK, and yougen seals to a
    // dedicated per-device HPKE key the invitee advertises in a
    // `ck.realm_key.request`. So the proactive push is deferred to the
    // request-driven path: the invitee sends `ck.realm_key.request` (advertising
    // its HPKE public key), and `share_history_to_requester` answers it.
    // TODO(history-share): seal proactively once the invitee HPKE pubkey is
    // resolvable at admission time.
    tracing::debug!(
        realm = %short_protocol_id(&realm_id),
        invitee_device = %short_protocol_id(&invitee_device_id),
        "retained history_secret for late-joiner sharing; awaiting ck.realm_key.request"
    );
    Ok(Some(next_epoch))
}

/// Provider-side: answer one `ck.realm_key.request` from a late joiner by
/// sealing the retained `history_secret` range to the requester's advertised
/// HPKE public key and submitting a durable `ck.realm_key.share`
/// (`encryption-and-audit.md` history sharing).
///
/// Returns `Ok(true)` when a share was built and submitted, `Ok(false)` when
/// the provider holds no history secret to share (it will be retried once the
/// provider has retained one). `request` is the inbound `ck.realm_key.request`
/// to-device envelope; `realm_id`/`actor_id`/`device_id` are the provider's.
pub(crate) async fn share_history_to_requester(
    api: &crate::api::CokretApi,
    mut state_store: Signal<LocalStateStore>,
    realm_id: String,
    actor_id: String,
    device_id: String,
    request: &cokret_sdk::RealmKeyRequestPayload,
) -> anyhow::Result<bool> {
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    // Ensure the current epoch's key is retained, then gather every retained
    // (epoch, secret) the requester is asking for.
    {
        let mut store = state_store.write();
        let _ = crate::mls::runtime::derive_and_retain_realm_history_secret(
            &mut store,
            secure_store.as_ref(),
            &realm_id,
            &actor_id,
            &device_id,
        );
    }
    let all = state_store.read().history_secrets_for(&realm_id);
    if all.is_empty() {
        return Ok(false);
    }
    let from = request.key_scope.from_epoch;
    let to = request.key_scope.to_epoch;
    let range: Vec<(u64, Vec<u8>)> = all
        .into_iter()
        .filter(|(epoch, _)| *epoch >= from && *epoch <= to)
        .collect();
    if range.is_empty() {
        return Ok(false);
    }
    let recipient_pubkey =
        cokret_sdk::base64url_decode(request.recipient_hpke_public_key.trim().as_bytes())
            .map_err(|err| anyhow::anyhow!("decode requester HPKE public key: {err}"))?;
    let sealed =
        cokret_sdk::secret_share::seal_history_secret_to_device_pubkey(&recipient_pubkey, &range)
            .map_err(|err| anyhow::anyhow!("seal history secrets: {err}"))?;
    let (min_epoch, max_epoch) = range
        .iter()
        .fold((u64::MAX, 0_u64), |(lo, hi), (epoch, _)| {
            (lo.min(*epoch), hi.max(*epoch))
        });
    let share = crate::mls::admission::build_realm_key_share_event(
        &realm_id,
        &actor_id,
        &device_id,
        request.recipient_principal_id.as_str(),
        &request.recipient_device_id,
        min_epoch,
        max_epoch,
        sealed,
    )
    .map_err(|err| anyhow::anyhow!(err))?;
    api.submit_sdk_events_batch(&realm_id, vec![share], None)
        .await?;
    Ok(true)
}

/// Eager RRK seal hook (encryption-and-audit.md §2.10.8): after a commit
/// advances `realm_id`'s epoch and this device has retained the new epoch's
/// `history_secret`, seal every retained `(epoch, history_secret)` to each
/// `durability_policy.recovery_recipients[]` and submit the
/// provider-initiated `ck.realm_key.share` Events.
///
/// MUST run only when the Realm's effective durability is RRK-active
/// (`mode != none` AND `content_scheme == mls-exporter-aead-v1`); the caller
/// gates on [`LocalStateStore::realm_durability_is_rrk_active`].
///
/// **RYW guard (§2.10.8 eager timing)**: yougen never GCs `history_secret`s
/// (`mls_sidecar` is monotonic), so the dangerous "GC before seal accepted"
/// window does not exist structurally — the retained secret survives until the
/// store is wiped. This hook only has to be *eager*: it fires right after the
/// advancing commit, and a recipient whose RRK is unverified or whose share
/// fails to submit leaves the secret retained (never GC'd) so a later pass can
/// re-seal. A `durability_seal_missing_before_gc`-class loss is therefore not
/// reachable from this client.
///
/// Returns `Ok((sealed, unverified))` recipient counts for diagnostics; a
/// non-fatal failure is logged, never surfaced as a hard error (the commit
/// itself already landed).
pub(crate) async fn seal_history_to_recovery_recipients(
    api: &crate::api::CokretApi,
    mut state_store: Signal<LocalStateStore>,
    realm_id: String,
    actor_id: String,
    device_id: String,
) -> anyhow::Result<(usize, usize)> {
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    // Ensure the just-advanced epoch's key is retained before sealing.
    {
        let mut store = state_store.write();
        let _ = crate::mls::runtime::derive_and_retain_realm_history_secret(
            &mut store,
            secure_store.as_ref(),
            &realm_id,
            &actor_id,
            &device_id,
        );
    }
    let (policy, history_secrets, policy_digest) = {
        let store = state_store.read();
        let Some(policy) = store.realm_durability_policy(&realm_id) else {
            return Ok((0, 0));
        };
        if !crate::mls::durability::durability_is_effective(&policy) {
            return Ok((0, 0));
        }
        let history_secrets = store.history_secrets_for(&realm_id);
        // Bind the effective policy at seal time to the realm seal view's
        // state_root (the closest stable governance digest the client holds).
        let policy_digest = store
            .seal_view_for_realm(&realm_id)
            .state_root
            .map(Value::String)
            .unwrap_or(Value::Null);
        (policy, history_secrets, policy_digest)
    };
    if history_secrets.is_empty() {
        return Ok((0, 0));
    }
    // Fetch each recipient principal's raw DID Document (carrying service /
    // keyAgreement) so the SDK authority can verify the active RRK service entry.
    let mut did_documents: BTreeMap<String, Value> = BTreeMap::new();
    for recipient in &policy.recovery_recipients {
        if let Some(document) =
            crate::did_resolver::fetch_raw_did_document_json(&api.http, &recipient.principal_id)
                .await
        {
            did_documents.insert(recipient.recipient_id.clone(), document);
        }
    }
    let outcomes = crate::mls::durability::build_eager_seal_events(
        &realm_id,
        &actor_id,
        &device_id,
        &policy,
        &history_secrets,
        &did_documents,
        policy_digest,
    );
    let mut events = Vec::new();
    let mut unverified = 0_usize;
    for outcome in outcomes {
        match outcome {
            crate::mls::durability::RecipientSealOutcome::Sealed { event, .. } => {
                events.push(event);
            }
            crate::mls::durability::RecipientSealOutcome::Unverified {
                recipient_id,
                reason,
            } => {
                unverified += 1;
                tracing::warn!(
                    realm = %short_protocol_id(&realm_id),
                    recipient = %recipient_id,
                    %reason,
                    "RRK eager seal skipped recipient (fail-closed); history_secret retained for retry"
                );
            }
        }
    }
    let sealed = events.len();
    if !events.is_empty() {
        api.submit_sdk_events_batch(&realm_id, events, None).await?;
        tracing::info!(
            sealed,
            unverified,
            realm = %short_protocol_id(&realm_id),
            "submitted provider-initiated RRK ck.realm_key.share(s)"
        );
    }
    Ok((sealed, unverified))
}

/// History-sharing visibility tiers (realm-and-space.md) under which a
/// late-joining member is *eligible* to pull pre-join history. `world_readable`
/// / `shared` / `invited` admit a reader; `joined` and unknown values do not (a
/// `joined`-visibility Realm grants no pre-join window, so there is nothing to
/// request). The provider-side §13 gate is the authority; this is only the
/// cheap client-side pre-filter so we don't emit a request that will be denied.
fn history_visibility_admits_prejoin_pull(history_visibility: &str) -> bool {
    matches!(
        history_visibility.trim().to_ascii_lowercase().as_str(),
        "world_readable" | "shared" | "invited"
    )
}

/// Read the Realm's projected `history_visibility`, scanning the same nested
/// containers (`summary`/`object`/`realm`/`metadata`) the encryption-state
/// reader walks, since the local projection nests the realm body. Returns the
/// trimmed lowercased value, or `None` when the projection carries no hint.
fn projected_history_visibility_for_realm(
    store: &LocalStateStore,
    realm_id: &str,
) -> Option<String> {
    let state = store.load();
    let body = state.realm_tree_projections.get(realm_id)?;
    let null = Value::Null;
    let containers = [
        body,
        body.get("summary").unwrap_or(&null),
        body.get("object").unwrap_or(&null),
        body.get("realm").unwrap_or(&null),
        body.get("metadata").unwrap_or(&null),
    ];
    containers.into_iter().find_map(|container| {
        crate::realm_tree::string_field(container, &["history_visibility"])
            .map(|value| value.trim().to_ascii_lowercase())
    })
}

/// A planned `ck.realm_key.request`: the provider device to ask and the epoch
/// range whose `history_secret`s are missing locally.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct HistoryKeyRequestPlan {
    pub provider_principal_id: String,
    pub provider_device_ref: String,
    pub from_epoch: u64,
    pub to_epoch: u64,
}

/// Pure planning core for the receiver-initiated history pull. Decides whether
/// to emit a `ck.realm_key.request` and, if so, against which provider and over
/// which epoch range — given only plain inputs so it is unit-testable without a
/// store or network.
///
/// Returns `Some(plan)` iff **all** hold:
/// - `history_visibility` admits a pre-join pull (shared/invited/world_readable);
/// - there is a pre-join epoch (`< join_epoch`) with no installed `history_secret` — i.e. an actual
///   decryptable gap;
/// - at least one provider candidate `(principal, device)` exists that is not this device's own
///   actor.
///
/// The requested range is `[0, join_epoch - 1]` (every pre-join epoch). The
/// provider-side §13 gate trims it to what policy actually allows; asking for
/// the full pre-join window keeps the client honest about "I can't read any of
/// it" without the client having to know the retention floor. When
/// `join_epoch == 0` there is no pre-join window and we return `None`.
pub(crate) fn plan_history_key_request(
    history_visibility: &str,
    join_epoch: u64,
    installed_epochs: &[u64],
    self_actor_id: &str,
    provider_candidates: &[(String, String)],
) -> Option<HistoryKeyRequestPlan> {
    if !history_visibility_admits_prejoin_pull(history_visibility) {
        return None;
    }
    if join_epoch == 0 {
        return None;
    }
    let to_epoch = join_epoch - 1;
    let installed: BTreeSet<u64> = installed_epochs.iter().copied().collect();
    // A gap is any pre-join epoch we have not installed a history_secret for.
    let has_gap = (0..=to_epoch).any(|epoch| !installed.contains(&epoch));
    if !has_gap {
        return None;
    }
    let self_actor = self_actor_id.trim();
    let provider = provider_candidates.iter().find(|(principal, device)| {
        let principal = principal.trim();
        let device = device.trim();
        !principal.is_empty() && !device.is_empty() && principal != self_actor
    })?;
    Some(HistoryKeyRequestPlan {
        provider_principal_id: provider.0.trim().to_owned(),
        provider_device_ref: provider.1.trim().to_owned(),
        from_epoch: 0,
        to_epoch,
    })
}

/// Provider candidates `(sender_principal, sender_device_id)` harvested from the
/// to-device inbox: every `ck.mls.welcome` / `ck.mls.commit` / `ck.realm_key.share`
/// soland relays carries the *sending* (admitting / sharing) device's
/// `(sender, sender_device_id)`. That device is by construction a joined member
/// that holds Realm history, and soland's relay addresses the provider by
/// `(target_principal_id, target_source_ref=ck:device:<id>)`, so this is exactly
/// the addressing tuple `submit_realm_key_request` needs. Self-authored messages
/// are excluded so the requester never names itself as provider.
fn provider_candidates_from_inbox(
    inbox: &[Value],
    realm_id: &str,
    self_actor_id: &str,
) -> Vec<(String, String)> {
    let realm_id = realm_id.trim();
    let self_actor = self_actor_id.trim();
    let mut seen = BTreeSet::<(String, String)>::new();
    let mut out = Vec::new();
    for message in inbox {
        let kind = message
            .get("kind")
            .or_else(|| message.get("type"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let is_history_bearing = matches!(
            kind,
            "ck.mls.welcome" | "ck.mls.commit" | "ck.realm_key.share"
        ) || kind == cokret_sdk::events::kinds::REALM_KEY_SHARE;
        if !is_history_bearing {
            continue;
        }
        // Keep realm-scoped messages and ones that carry no realm hint (a
        // directed to-device delivery already addressed to this device).
        let scope_realm = message.get("realm_id").and_then(Value::as_str).or_else(|| {
            message
                .get("content")
                .and_then(|content| content.get("realm_id"))
                .and_then(Value::as_str)
        });
        if scope_realm.is_some_and(|value| value.trim() != realm_id) {
            continue;
        }
        let principal = message
            .get("sender")
            .or_else(|| message.get("origin"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let device = message
            .get("sender_device_id")
            .or_else(|| {
                message
                    .get("content")
                    .and_then(|content| content.get("sender_device_id"))
            })
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let (Some(principal), Some(device)) = (principal, device) else {
            continue;
        };
        if principal == self_actor {
            continue;
        }
        let entry = (principal.to_owned(), device.to_owned());
        if seen.insert(entry.clone()) {
            out.push(entry);
        }
    }
    out
}

/// Dedup key for the receiver-initiated pull, or `None` when there is nothing to
/// request. The key folds in the requested range and a signature of the
/// currently installed `history_secret` epochs, so it is stable while the gap
/// state is unchanged (suppressing per-sync re-emits) yet changes the instant a
/// share installs a new secret (releasing the dedup guard so a still-open gap can
/// be re-requested). Mirrors `request_history_keys_for_realm`'s eligibility test
/// — encrypted + joined + visibility admits + an actual gap + a provider exists —
/// so the key is `Some` exactly when a request would be emitted.
pub(crate) fn pending_history_request_dedup_key(
    store: &LocalStateStore,
    realm_id: &str,
    actor_id: &str,
) -> Option<String> {
    if !store.realm_projection_is_mls_encrypted(realm_id) {
        return None;
    }
    let snapshot = store.mls_snapshot_for(realm_id)?;
    let join_epoch = snapshot.epoch;
    let mut installed_epochs: Vec<u64> = store
        .history_secrets_for(realm_id)
        .into_iter()
        .map(|(epoch, _)| epoch)
        .collect();
    installed_epochs.sort_unstable();
    let history_visibility =
        projected_history_visibility_for_realm(store, realm_id).unwrap_or_default();
    let inbox = store.to_device_inbox();
    let providers = provider_candidates_from_inbox(&inbox, realm_id, actor_id);
    let plan = plan_history_key_request(
        &history_visibility,
        join_epoch,
        &installed_epochs,
        actor_id,
        &providers,
    )?;
    let installed_signature = installed_epochs
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    Some(format!(
        "{realm_id}|{}|{}|{installed_signature}",
        plan.from_epoch, plan.to_epoch
    ))
}

/// Receiver-initiated history pull (history sharing, last leg): when this device
/// holds an MLS snapshot for an mls-encrypted Realm but cannot read some pre-join
/// epoch's content (no installed `history_secret`) and the Realm's
/// `history_visibility` admits a pre-join window, emit one `ck.realm_key.request`
/// to a joined provider device asking it to seal the missing range back.
///
/// Returns `Some((from_epoch, to_epoch))` of the range actually requested (so the
/// caller can record it for dedup), or `None` when nothing was requested (not
/// encrypted / no snapshot / visibility forbids / no gap / no provider).
pub(crate) async fn request_history_keys_for_realm(
    api: &crate::api::CokretApi,
    state_store: Signal<LocalStateStore>,
    realm_id: String,
    actor_id: String,
    device_id: String,
) -> anyhow::Result<Option<(u64, u64)>> {
    // Gather every plain input under one read borrow, then drop it before the
    // (async) network call.
    let (plan, history_visibility) = {
        let store = state_store.read();
        // Must be an mls-encrypted Realm this device has actually joined.
        if !store.realm_projection_is_mls_encrypted(&realm_id) {
            return Ok(None);
        }
        let Some(snapshot) = store.mls_snapshot_for(&realm_id) else {
            return Ok(None);
        };
        // TODO(history-sharing): use the precise join epoch once the snapshot
        // records it. The current epoch is an over-approximation of the pre-join
        // window (`[0, current_epoch-1]`); the provider-side §13 gate trims the
        // range to what retention + policy actually allow, so over-asking is safe.
        let join_epoch = snapshot.epoch;
        let installed_epochs: Vec<u64> = store
            .history_secrets_for(&realm_id)
            .into_iter()
            .map(|(epoch, _)| epoch)
            .collect();
        // `joined` / unknown visibility ⇒ no pre-join window ⇒ skip cheaply.
        let history_visibility =
            projected_history_visibility_for_realm(&store, &realm_id).unwrap_or_default();
        let inbox = store.to_device_inbox();
        let providers = provider_candidates_from_inbox(&inbox, &realm_id, &actor_id);
        let plan = plan_history_key_request(
            &history_visibility,
            join_epoch,
            &installed_epochs,
            &actor_id,
            &providers,
        );
        (plan, history_visibility)
    };
    let Some(plan) = plan else {
        tracing::debug!(
            realm = %short_protocol_id(&realm_id),
            history_visibility = %history_visibility,
            "history pull skipped: no eligible gap or provider"
        );
        return Ok(None);
    };
    // This device's HPKE public key — the provider seals the reply to it; the
    // matching private half (same keypair) opens it on ingest.
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let (_privkey, pubkey) = crate::mls::runtime::load_or_create_device_hpke_keypair(
        secure_store.as_ref(),
        &actor_id,
        &device_id,
    )
    .map_err(|err| anyhow::anyhow!("load device HPKE keypair for history request: {err}"))?;
    let recipient_hpke_public_key = cokret_sdk::base64url_encode(&pubkey);
    api.submit_realm_key_request(
        &realm_id,
        &actor_id,
        &device_id,
        &plan.provider_device_ref,
        &plan.provider_principal_id,
        &recipient_hpke_public_key,
        plan.from_epoch,
        plan.to_epoch,
    )
    .await?;
    tracing::info!(
        realm = %short_protocol_id(&realm_id),
        provider = %short_protocol_id(&plan.provider_principal_id),
        from_epoch = plan.from_epoch,
        to_epoch = plan.to_epoch,
        "sent ck.realm_key.request for pre-join history"
    );
    Ok(Some((plan.from_epoch, plan.to_epoch)))
}

/// Stable signature of a Realm's joined-member DIDs (sorted, joined-only).
/// Used as a reactive dedup key so admin-side admission reconciliation re-runs
/// when membership changes, but not on every unrelated sync tick.
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

/// Admin-side admission reconciliation — closes the invite-time race.
///
/// `submit_mls_admission_for_invitee` historically ran the instant an invite
/// was sent, before the invitee had accepted and published an MLS KeyPackage:
/// the claim failed, no `ck.mls.welcome` was produced, and the invitee was
/// stuck "waiting for a Welcome". This pass runs on sync — for every Realm
/// member who has actually joined (`membership=join`) but is not yet in this
/// device's MLS group, it (re)attempts admission. Members already in the group
/// are skipped (no commit spam); members who still have not published a
/// KeyPackage just error and are retried on the next sync once they publish.
///
/// Returns the number of members newly admitted on this pass.
pub(crate) async fn reconcile_mls_admissions_for_realm(
    api: &crate::api::CokretApi,
    state_store: Signal<LocalStateStore>,
    realm_id: String,
    actor_id: String,
    device_id: String,
) -> anyhow::Result<usize> {
    // Only Realms this device can admit into: holding MLS state ⇒ able to build
    // the commit + Welcome. Without a snapshot we are not an admit-capable
    // member and have nothing to reconcile.
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let group_member_dids: BTreeSet<String> = {
        let store = state_store.read();
        match crate::mls::runtime::mls_group_member_principal_ids_for_realm(
            &store,
            secure_store.as_ref(),
            &realm_id,
            &actor_id,
            &device_id,
        ) {
            Some(dids) => dids.into_iter().collect(),
            None => return Ok(0),
        }
    };
    // Joined Realm members not yet represented in the MLS group, excluding self.
    let pending: Vec<String> = {
        let store = state_store.read();
        projected_member_profiles_for_realm(&store, &realm_id)
            .into_iter()
            .filter(|member| member.normalized_membership() == Some("join"))
            .map(|member| member.actor_id)
            .filter(|did| {
                let did = did.trim();
                !did.is_empty() && did != actor_id.trim() && !group_member_dids.contains(did)
            })
            .collect()
    };
    if pending.is_empty() {
        return Ok(0);
    }
    let mut admitted = 0_usize;
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
            Ok(Some(_)) => admitted += 1,
            Ok(None) => {}
            // Most commonly the invitee has not published a KeyPackage yet —
            // expected, and retried on the next sync — so stay at debug level.
            Err(error) => {
                tracing::debug!(
                    realm = %short_protocol_id(&realm_id),
                    invitee = %short_protocol_id(&invitee_did),
                    %error,
                    "MLS admission deferred (will retry on next sync)"
                );
            }
        }
    }
    Ok(admitted)
}

pub(crate) async fn submit_mls_admission_for_invitees(
    api: &crate::api::CokretApi,
    mut state_store: Signal<LocalStateStore>,
    realm_id: String,
    actor_id: String,
    device_id: String,
    invitees: Vec<String>,
) -> anyhow::Result<usize> {
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
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    ensure_mls_genesis_frontier_for_invite(
        api,
        state_store,
        secure_store.as_ref(),
        &realm_id,
        &actor_id,
        &device_id,
    )
    .await?;

    let mut claims = Vec::<(cokret_sdk::KeypackageClaimRecord, String)>::new();
    for invitee_did in invitees {
        let claim_nonce = crate::api::generate_mls_claim_nonce()?;
        let claim_outcome = api
            .claim_mls_key_package(
                &invitee_did,
                &realm_id,
                &actor_id,
                &claim_nonce,
                None,
                Some(&group_id),
            )
            .await?;
        let failures = claim_outcome.failures;
        let claim = claim_outcome.claims.into_iter().next().ok_or_else(|| {
            let reason = failures
                .first()
                .map(|failure| format!("{failure:?}"))
                .unwrap_or_else(|| "no MLS KeyPackage was available for the invitee".to_owned());
            anyhow::anyhow!("{reason}")
        })?;
        claims.push((claim, claim_nonce));
    }
    let admission = {
        let store = state_store.read();
        crate::mls::admission::build_realm_mls_admission_events_from_claims(
            &store,
            secure_store.as_ref(),
            &realm_id,
            &actor_id,
            &device_id,
            &claims,
        )
        .map_err(|err| anyhow::anyhow!(err))?
    };
    // Fail-closed ordering (see `submit_mls_admission_for_invitee`): the
    // batched add-member `ck.mls.commit` MUST be accepted before its Welcomes
    // ship, or rejected-commit-but-delivered-Welcome forks the invitees onto an
    // epoch this admin and the server never reach.
    let commit_event_id = admission.commit.event_id.clone();
    let commit_outcome = api
        .submit_sdk_events_batch(&realm_id, vec![admission.commit], None)
        .await?;
    let commit_accepted = commit_outcome
        .accepted
        .iter()
        .chain(commit_outcome.duplicate.iter())
        .any(|event_id| event_id == &commit_event_id);
    if !commit_accepted {
        return Err(anyhow::anyhow!(
            "MLS batch admission commit was not accepted (status={:?}, rejected={:?}); invitees not admitted to avoid an epoch fork",
            commit_outcome.status,
            commit_outcome.rejected
        ));
    }
    api.submit_sdk_events_batch(&realm_id, admission.welcomes, None)
        .await?;
    state_store
        .write()
        .save_mls_snapshot(realm_id, admission.snapshot);
    Ok(claims.len())
}

fn mls_group_state_event_ref_ready(store: &LocalStateStore, realm_id: &str) -> bool {
    let seal_view = store.seal_view_for_realm(realm_id);
    seal_view
        .frontier
        .iter()
        .chain(seal_view.leaves.iter())
        .any(|value| cokret_sdk::EventId::new(value.clone()).is_ok())
}

async fn ensure_mls_genesis_frontier_for_invite(
    api: &crate::api::CokretApi,
    mut state_store: Signal<LocalStateStore>,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
) -> anyhow::Result<()> {
    {
        let store = state_store.read();
        if mls_group_state_event_ref_ready(&store, realm_id) {
            return Ok(());
        }
    }
    if let Some(event_id) = api.find_mls_genesis_event_id(realm_id).await? {
        state_store
            .write()
            .mark_mls_genesis_emitted_with_event(realm_id.to_owned(), &event_id);
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
            actor_id,
            device_id,
        )
        .map_err(|err| anyhow::anyhow!(err.user_message()))?
    }
    .ok_or_else(|| {
        anyhow::anyhow!(
            "local epoch-0 MLS snapshot is not available; create or restore this device's MLS state before inviting into an encrypted Realm"
        )
    })?;
    let genesis_event = {
        let mut store = state_store.write();
        crate::views::kanban::build_creator_mls_genesis_event(
            &mut store,
            realm_id,
            actor_id,
            device_id,
            Some(&summary),
        )
        .map_err(|err| anyhow::anyhow!(err))?
    }
    .ok_or_else(|| {
        anyhow::anyhow!(
            "local MLS genesis event is already marked emitted but no group-state event id is available; sync this Realm before inviting"
        )
    })?;
    match api.submit_sdk_event(&genesis_event).await {
        Ok(_) => {
            state_store
                .write()
                .mark_mls_genesis_emitted_with_event(realm_id.to_owned(), &genesis_event.event_id);
            Ok(())
        }
        Err(err) => {
            let text = err.to_string();
            if text.contains("mls_genesis_already_exists") {
                if let Some(event_id) = api.find_mls_genesis_event_id(realm_id).await? {
                    state_store
                        .write()
                        .mark_mls_genesis_emitted_with_event(realm_id.to_owned(), &event_id);
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

#[component]
pub fn RealmMembersPanel(
    base_url: String,
    active_service_did: String,
    account_did: String,
    device_id: String,
    token: Signal<String>,
    selected_realm_id: String,
    sync_cursor: Signal<String>,
    frontier_state: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let mut invite_target = use_signal(String::new);
    let mut status_msg = use_signal(String::new);
    let mut members = use_signal(Vec::<MemberProfile>::new);
    let mut owned_agents = use_signal(Vec::<MemberAgentRow>::new);
    let mut owned_agents_refresh_nonce = use_signal(|| 0_u64);
    let mut self_agent_settings_open = use_signal(|| false);
    let mut new_agent_display_name = use_signal(|| "my-personal-agent".to_owned());
    let mut new_agent_slug = use_signal(|| "summary".to_owned());
    let mut new_agent_pairing = use_signal(|| Option::<AgentProvisionSummary>::None);
    let block_confirm_did = use_signal(|| Option::<String>::None);
    let mut permissions = use_signal(RealmMemberPermissions::default);
    let mut member_roster_section = use_signal(|| MemberRosterSection::Members);
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
        let fallback_controller_did = account_did.clone();
        use_effect(move || {
            let _refresh_nonce = owned_agents_refresh_nonce();
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
                        fetch_owned_agent_rows(&api, &realm, &fallback_controller_did).await
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
                        let cancel_invite = api
                            .authz_check_raw(&actor, "ck.invite.cancel", &realm)
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
                        let can_cancel_invite = cancel_invite
                            .as_ref()
                            .map(authz_json_allowed)
                            .unwrap_or(false);
                        let can_remove = remove.as_ref().map(authz_json_allowed).unwrap_or(false);
                        if invite.is_err() && cancel_invite.is_err() && remove.is_err() {
                            status_msg.set(
                                "member action permission check failed; write controls hidden"
                                    .to_owned(),
                            );
                        }
                        permissions.set(RealmMemberPermissions {
                            loaded: true,
                            can_invite,
                            can_cancel_invite,
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
    let can_cancel_invite = member_permissions.can_cancel_invite;
    let can_remove = member_permissions.can_remove;

    // Roster → grouped by controller → filtered → paged window. Filtering
    // stays cheap; pagination keeps the mounted row count bounded while
    // keeping each controller's agents visually attached to the owner.
    let all_members = members();
    let (active_members, pending_invite_rows) = split_member_profiles(all_members);
    let owned_agent_rows = owned_agents();
    let member_groups =
        group_members_with_owned_agents(&active_members, &owned_agent_rows, &account_did);
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
        member.actor_id.trim() == account_did.trim() && member.is_governance_principal()
    });
    let self_leave_disabled_reason = if self_is_known_governance && governance_member_count <= 1 {
        Some("Transfer or add Realm admin authority before leaving.".to_owned())
    } else {
        None
    };
    let filter_query = member_filter().trim().to_lowercase();
    let section_groups: Vec<MemberGroup> = member_groups
        .into_iter()
        .filter(|group| member_group_in_section(group, selected_section))
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
    let show_search = total_groups + total_pending_invites > MEMBER_SEARCH_THRESHOLD;
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
    let selected_section_total = match selected_section {
        MemberRosterSection::Members => total_regular_members,
        MemberRosterSection::Owners => total_owner_members,
        MemberRosterSection::Admins => total_admin_members,
        MemberRosterSection::PendingInvites => total_pending_invites,
    };
    let selected_section_visible_count = if selected_section == MemberRosterSection::PendingInvites
    {
        pending_invite_match_count
    } else {
        filtered_count
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
    let pending_section_class = if selected_section == MemberRosterSection::PendingInvites {
        "members-admin-menu-item active"
    } else {
        "members-admin-menu-item"
    };
    let member_set: BTreeSet<String> = active_members
        .iter()
        .map(|member| member.actor_id.clone())
        .collect();
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
                                                let did_label = display_name_for_did(&state_store.read(), &did);
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
                                                let actor = account_did.clone();
                                                let device = device_id.clone();
                                                let realm = selected_realm_id.clone();
                                                let state_store = state_store;
                                                move |_| {
                                                    let base = base.clone();
                                                    let actor = actor.clone();
                                                    let device = device.clone();
                                                    let realm = realm.clone();
                                                    let mut state_store = state_store;
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
                                                        let mut last_mls_err = String::new();
                                                        let mut mls_ok = 0_usize;
                                                        let mut ok_invites =
                                                            Vec::<(String, String, String)>::new();
                                                        for (did, consent_ref) in targets {
                                                            match api
                                                                .invite_contact_to_realm(&realm, &actor, &did, &consent_ref)
                                                                .await
                                                            {
                                                                Ok((event_id, invite_id)) => {
                                                                    ok += 1;
                                                                    match submit_mls_admission_for_invitee(
                                                                        &api,
                                                                        state_store,
                                                                        realm.clone(),
                                                                        actor.clone(),
                                                                        device.clone(),
                                                                        did.clone(),
                                                                    )
                                                                    .await
                                                                    {
                                                                        Ok(Some(_)) => mls_ok += 1,
                                                                        Ok(None) => {}
                                                                        Err(err) => last_mls_err = err.to_string(),
                                                                    }
                                                                    ok_invites.push((
                                                                        did,
                                                                        event_id.clone(),
                                                                        invite_id,
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
                                                                for (did, event_id, invite_id) in ok_invites {
                                                                    upsert_pending_invite_profile(&mut next_members, &did, None, Some(&invite_id));
                                                                    store.append_raw_operation(
                                                                        event_id.clone(),
                                                                        Some(realm.clone()),
                                                                        json!({
                                                                            "kind": "ck.invite.create",
                                                                            "invite_id": invite_id,
                                                                            "invitee": did,
                                                                            "state": "pending",
                                                                            "event_id": event_id,
                                                                        }),
                                                                    );
                                                                }
                                                            }
                                                            members.set(next_members);
                                                        }
                                                        selected_contacts.set(std::collections::BTreeSet::new());
                                                        if ok == total {
                                                            invite_modal_open.set(false);
                                                            let mut message = crate::i18n::tr("realm_admin.invite_sent")
                                                                .replace("{ok}", &ok.to_string());
                                                            if !last_mls_err.is_empty() {
                                                                message.push_str(&format!(
                                                                    "; MLS admission failed for at least one invite: {last_mls_err}"
                                                                ));
                                                            } else if mls_ok > 0 {
                                                                message.push_str(&format!(
                                                                    "; MLS Welcome queued for {mls_ok}"
                                                                ));
                                                            }
                                                            status_msg.set(message);
                                                        } else {
                                                            let mut message = crate::i18n::tr("realm_admin.invite_partial")
                                                                .replace("{ok}", &ok.to_string())
                                                                .replace("{total}", &total.to_string())
                                                                .replace("{error}", &last_err);
                                                            if !last_mls_err.is_empty() {
                                                                message.push_str(&format!(
                                                                    "; MLS admission failed for at least one invite: {last_mls_err}"
                                                                ));
                                                            }
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
                                    let actor = account_did.clone();
                                    let device = device_id.clone();
                                    let realm = selected_realm_id.clone();
                                    let state_store = state_store;
                                    move |_| {
                                        let base = base.clone();
                                        let actor = actor.clone();
                                        let device = device.clone();
                                        let realm = realm.clone();
                                        let mut state_store = state_store;
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
                                                    let invitee_did = invitee.did.clone();
                                                    let op = match ck_ops::invite_create_structured(
                                                        &realm,
                                                        &actor,
                                                        &invite_id,
                                                        &invitee_did,
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
                                                                        "invitee": invitee_did.clone(),
                                                                        "invitee_label": invitee_label.clone(),
                                                                        "state": "pending",
                                                                        "event_id": submitted.event_id,
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
                                                            match submit_mls_admission_for_invitee(
                                                                &api,
                                                                state_store,
                                                                realm.clone(),
                                                                actor.clone(),
                                                                device.clone(),
                                                                invitee_did.clone(),
                                                            )
                                                            .await
                                                            {
                                                                Ok(Some(epoch)) => status_msg.set(format!(
                                                                    "invited {} (pending) fact {}; MLS Welcome queued at epoch {}",
                                                                    invitee_label,
                                                                    short_protocol_id(&op_id),
                                                                    epoch
                                                                )),
                                                                Ok(None) => status_msg.set(format!(
                                                                    "invited {} (pending) fact {}",
                                                                    invitee_label,
                                                                    short_protocol_id(&op_id)
                                                                )),
                                                                Err(error) => status_msg.set(format!(
                                                                    "invited {} (pending) fact {}; MLS admission failed: {error}",
                                                                    invitee_label,
                                                                    short_protocol_id(&op_id)
                                                                )),
                                                            }
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
                        if total_pending_invites > 0 {
                            span {
                                class: "badge member-pending-count-badge",
                                "data-testid": "realm-pending-invite-count",
                                "{total_pending_invites} pending"
                            }
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
                if member_permissions.loaded && !can_invite && !can_cancel_invite && !can_remove {
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
                                        base_url: base_url.clone(),
                                        token,
                                        account_did: account_did.clone(),
                                        selected_realm_id: selected_realm_id.clone(),
                                        can_cancel_invite,
                                        members,
                                        state_store,
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
                        let is_self = member.trim() == account_did.trim();
                        let has_agents = !group.agents.is_empty();
                        let group_class = if has_agents {
                            "member-group has-agents"
                        } else {
                            "member-group"
                        };
                        let avatar_initial = member_avatar_initial(&member_profile);
                        let avatar_blob_ref = member_profile.avatar_blob_ref.clone();
                        let avatar_url = member_profile.avatar_url.clone();
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
                                                if let Some(blob_ref) = avatar_blob_ref.clone() {
                                                    div { class: "member-avatar-image",
                                                        crate::content::renderer::AuthenticatedBlobImage {
                                                            blob_ref,
                                                            alt_text: member_label.clone(),
                                                        }
                                                    }
                                                } else if let Some(url) = avatar_url.clone() {
                                                    img {
                                                        class: "member-avatar-img",
                                                        src: "{url}",
                                                        alt: "{member_label}",
                                                        title: "{member}"
                                                    }
                                                } else {
                                                    "{avatar_initial}"
                                                }
                                            }
                                        } else {
                                            div {
                                                class: "member-avatar",
                                                "data-testid": "member-avatar",
                                                title: "{member}",
                                                if let Some(blob_ref) = avatar_blob_ref.clone() {
                                                    div { class: "member-avatar-image",
                                                        crate::content::renderer::AuthenticatedBlobImage {
                                                            blob_ref,
                                                            alt_text: member_label.clone(),
                                                        }
                                                    }
                                                } else if let Some(url) = avatar_url.clone() {
                                                    img {
                                                        class: "member-avatar-img",
                                                        src: "{url}",
                                                        alt: "{member_label}",
                                                        title: "{member}"
                                                    }
                                                } else {
                                                    "{avatar_initial}"
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
                                                    button {
                                                        class: "badge member-agent-settings-toggle",
                                                        "data-testid": "member-agent-settings-toggle",
                                                        title: "AI agents",
                                                        "aria-label": "AI agents",
                                                        onclick: move |_| self_agent_settings_open.set(!self_agent_settings_open()),
                                                        crate::components::UiIcon { name: "bot" }
                                                        span { "AI agents" }
                                                    }
                                                }
                                                if member_profile.is_owner {
                                                    span { class: "badge amber", "Owner" }
                                                } else if member_profile.is_admin {
                                                    span { class: "badge blue", "Admin" }
                                                }
                                                if has_agents {
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
                                                    span { title: "{member}", "{member_identity_label}" }
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
                                                if !handles.is_empty() {
                                                    div { class: "member-profile-line member-handle-list",
                                                        span { class: "member-profile-label", "Handles" }
                                                        for handle in handles.clone() {
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
                                        base_url: base_url.clone(),
                                        token,
                                        account_did: account_did.clone(),
                                        selected_realm_id: selected_realm_id.clone(),
                                        target_did: member.clone(),
                                        target_label: member_label.clone(),
                                        can_remove,
                                        is_self,
                                        leave_disabled_reason: self_leave_reason,
                                        sync_cursor,
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
                                        div { class: "member-agent-create-card", "data-testid": "member-self-agent-create",
                                            div { class: "member-agent-create-grid",
                                                div {
                                                    Label { html_for: "member-agent-display-name", "Display name" }
                                                    Input {
                                                        id: "member-agent-display-name",
                                                        "data-testid": "member-agent-display-name",
                                                        value: "{new_agent_display_name}",
                                                        placeholder: "my-personal-agent",
                                                        oninput: move |event: FormEvent| new_agent_display_name.set(event.value()),
                                                    }
                                                }
                                                div {
                                                    Label { html_for: "member-agent-slug", "Slug" }
                                                    Input {
                                                        id: "member-agent-slug",
                                                        "data-testid": "member-agent-slug",
                                                        value: "{new_agent_slug}",
                                                        placeholder: "summary",
                                                        oninput: move |event: FormEvent| new_agent_slug.set(event.value()),
                                                    }
                                                }
                                            }
                                            div { class: "actions member-agent-create-actions",
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    "data-testid": "member-agent-create-button",
                                                    onclick: {
                                                        let base = base_url.clone();
                                                        move |_| {
                                                            let display = new_agent_display_name().trim().to_owned();
                                                            if display.is_empty() {
                                                                status_msg.set("agent display name is required".to_owned());
                                                                return;
                                                            }
                                                            let slug = new_agent_slug().trim().to_owned();
                                                            let body = AgentProvisionRequestBody {
                                                                display_name: Some(display.clone()),
                                                                agent_slug: if slug.is_empty() { None } else { Some(slug) },
                                                                requested_scope: Some(AgentKeyScope::Limited),
                                                                accountability: Value::Null,
                                                                pairing_ttl_ms: None,
                                                            };
                                                            let base = base.clone();
                                                            let api_token = token();
                                                            spawn(async move {
                                                                match crate::views::helpers::with_authed_api(
                                                                    &base,
                                                                    api_token,
                                                                    move |api| {
                                                                        let body = body.clone();
                                                                        async move { api.agent_provision(&body).await }
                                                                    },
                                                                )
                                                                .await
                                                                {
                                                                    Ok(outcome) => {
                                                                        let agent_id = outcome.agent_principal_id.to_string();
                                                                        new_agent_pairing.set(Some(AgentProvisionSummary {
                                                                            agent_principal_id: agent_id.clone(),
                                                                            pairing_request_id: outcome.pairing_request_id.clone(),
                                                                            pairing_code: outcome.pairing_code.clone(),
                                                                            expires_at: outcome.expires_at.to_rfc3339(),
                                                                        }));
                                                                        owned_agents_refresh_nonce.set(owned_agents_refresh_nonce() + 1);
                                                                        status_msg.set(format!(
                                                                            "created AI agent {}",
                                                                            short_protocol_id(&agent_id)
                                                                        ));
                                                                    }
                                                                    Err(err) => status_msg.set(format!(
                                                                        "agent create failed: {}",
                                                                        err.display()
                                                                    )),
                                                                }
                                                            });
                                                        }
                                                    },
                                                    "Create AI agent"
                                                }
                                            }
                                            if let Some(pairing) = new_agent_pairing() {
                                                div { class: "member-agent-pairing", "data-testid": "member-agent-pairing",
                                                    div { class: "member-profile-line",
                                                        span { class: "member-profile-label", "Agent" }
                                                        span { class: "mono", title: "{pairing.agent_principal_id}", "{short_protocol_id(&pairing.agent_principal_id)}" }
                                                    }
                                                    div { class: "member-profile-line",
                                                        span { class: "member-profile-label", "Pairing" }
                                                        span { class: "mono", "{pairing.pairing_request_id}" }
                                                    }
                                                    if let Some(code) = pairing.pairing_code.clone() {
                                                        div { class: "member-profile-line",
                                                            span { class: "member-profile-label", "Code" }
                                                            span { class: "mono", "{code}" }
                                                        }
                                                    }
                                                    div { class: "member-profile-line",
                                                        span { class: "member-profile-label", "Expires" }
                                                        span { "{pairing.expires_at}" }
                                                    }
                                                    if can_invite {
                                                        Button {
                                                            variant: ButtonVariant::Secondary,
                                                            "data-testid": "member-agent-created-add-to-realm",
                                                            disabled: active_service_did.trim().is_empty(),
                                                            onclick: {
                                                                let agent_id = pairing.agent_principal_id.clone();
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
                                                    }
                                                }
                                            }
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
                                                let agent_initial = member_avatar_initial_from_value(&agent_label);
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
                                                            is_self: false,
                                                            sync_cursor,
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
                if selected_section_empty && selected_section != MemberRosterSection::PendingInvites {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn member(id: &str) -> MemberProfile {
        MemberProfile::bare(id.to_owned())
    }

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

    fn temp_store(name: &str) -> LocalStateStore {
        let path = std::env::temp_dir().join(format!(
            "yougen-members-panel-{name}-{}.json",
            crate::operation::uuid_v7()
        ));
        LocalStateStore::with_path(path)
    }

    #[test]
    fn splits_pending_invites_out_of_active_members() {
        let mut alice = member("did:web:alice.example");
        alice.membership = Some("join".to_owned());
        let mut bob = member("did:web:bob.example");
        bob.membership = Some("invite".to_owned());

        let (active, pending) = split_member_profiles(vec![alice, bob]);

        assert_eq!(active.len(), 1);
        assert_eq!(active[0].actor_id, "did:web:alice.example");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].actor_id, "did:web:bob.example");
    }

    #[test]
    fn optimistic_pending_invite_does_not_downgrade_joined_member() {
        let mut alice = member("did:web:alice.example");
        alice.membership = Some("join".to_owned());
        let mut rows = vec![alice];

        upsert_pending_invite_profile(&mut rows, "did:web:alice.example", Some("Alice"), None);
        let (active, pending) = split_member_profiles(rows);

        assert_eq!(active.len(), 1);
        assert_eq!(active[0].membership.as_deref(), Some("join"));
        assert!(pending.is_empty());
    }

    #[test]
    fn optimistic_pending_invite_records_display_handle() {
        let mut rows = Vec::new();

        upsert_pending_invite_profile(
            &mut rows,
            "did:web:bob.example",
            Some("bob:example.com"),
            None,
        );

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].membership.as_deref(), Some("invite"));
        assert_eq!(rows[0].handles, vec!["bob:example.com"]);
    }

    #[test]
    fn member_avatar_initial_uses_identity_not_did_prefix() {
        let bob = member("did:web:bob.example");
        let carol = member("did:web:carol.example");

        assert_eq!(member_avatar_initial(&bob), "B");
        assert_eq!(member_avatar_initial(&carol), "C");
    }

    #[test]
    fn member_avatar_initial_prefers_display_and_handle_identity() {
        let mut display = member("did:web:bob.example");
        display.display_name = Some("Robert Example".to_owned());
        assert_eq!(member_avatar_initial(&display), "R");

        let mut handled = member("did:web:acme.example:users:bob");
        handled.handles.push("bob:acme.example".to_owned());
        assert_eq!(member_avatar_initial(&handled), "B");
    }

    #[test]
    fn groups_current_account_with_owned_agent_members() {
        let members = vec![
            member("did:web:alice.example"),
            member("did:web:bob.example"),
            member("did:web:agent.example"),
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
            .find(|group| group.controller.actor_id == "did:web:alice.example")
            .expect("alice group exists");
        assert_eq!(alice.agents.len(), 1);
        assert_eq!(alice.agents[0].agent_principal_id, "did:web:agent.example");
        assert!(
            groups
                .iter()
                .all(|group| group.controller.actor_id != "did:web:agent.example")
        );
    }

    #[test]
    fn groups_agent_members_under_reported_controller() {
        let members = vec![
            member("did:web:alice.example"),
            member("did:web:bob.example"),
            member("did:web:bob-agent.example"),
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
            .find(|group| group.controller.actor_id == "did:web:bob.example")
            .expect("bob group exists");
        assert_eq!(bob.agents.len(), 1);
        assert_eq!(
            bob.agents[0].agent_principal_id,
            "did:web:bob-agent.example"
        );
        assert!(
            groups
                .iter()
                .all(|group| group.controller.actor_id != "did:web:bob-agent.example")
        );
    }

    #[test]
    fn projected_member_profiles_read_display_handles_and_roles() {
        let realm_id = "ck:realm:test";
        let mut store = temp_store("projected-profiles");
        store.save_realm_tree_projection(
            realm_id.to_owned(),
            serde_json::json!({
                "members": [{
                    "actor_id": "did:web:alice.example",
                    "display_name": "Alice",
                    "subject_id": "did:web:acme.example:users:alice",
                    "handle_claims": [{
                        "subject": "did:web:acme.example:users:alice",
                        "binding_state": "verified",
                        "handle": "alice:acme.example"
                    }],
                    "display_profile": {
                        "avatar_blob_ref": "ck:blob:sha256:abc"
                    }
                }],
                "admins": ["did:web:alice.example"]
            }),
        );

        let profiles = projected_member_profiles_for_realm(&store, realm_id);
        let alice = profiles
            .iter()
            .find(|profile| profile.actor_id == "did:web:alice.example")
            .expect("alice profile exists");
        assert_eq!(alice.display_name.as_deref(), Some("Alice"));
        assert_eq!(alice.handles, vec!["alice:acme.example"]);
        assert_eq!(alice.avatar_blob_ref.as_deref(), Some("ck:blob:sha256:abc"));
        assert!(alice.is_admin);
    }

    #[test]
    fn projected_member_profiles_preserve_pending_invite_membership() {
        let realm_id = "ck:realm:test";
        let mut store = temp_store("pending-membership");
        store.save_realm_tree_projection(
            realm_id.to_owned(),
            serde_json::json!({
                "members": [
                    {
                        "actor_id": "did:web:alice.example",
                        "membership": "join"
                    },
                    {
                        "actor_id": "did:web:bob.example",
                        "membership": "invite"
                    }
                ]
            }),
        );

        let profiles = projected_member_profiles_for_realm(&store, realm_id);
        let (active, pending) = split_member_profiles(profiles);

        assert_eq!(active.len(), 1);
        assert_eq!(active[0].actor_id, "did:web:alice.example");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].actor_id, "did:web:bob.example");
        assert_eq!(pending[0].membership.as_deref(), Some("invite"));
    }

    #[test]
    fn joined_member_signature_lists_only_joined_members_sorted() {
        let realm_id = "ck:realm:test";
        let mut store = temp_store("joined-signature");
        store.save_realm_tree_projection(
            realm_id.to_owned(),
            serde_json::json!({
                "members": [
                    { "actor_id": "did:web:carol.example", "membership": "join" },
                    { "actor_id": "did:web:alice.example", "membership": "join" },
                    { "actor_id": "did:web:bob.example", "membership": "invite" }
                ]
            }),
        );

        // Only `join` members, deduped and sorted — `bob` (invite) is excluded
        // so an outstanding invite never triggers an admission attempt, and the
        // signature is stable regardless of projection ordering.
        assert_eq!(
            joined_member_signature_for_realm(&store, realm_id),
            "did:web:alice.example,did:web:carol.example"
        );
    }

    #[test]
    fn projected_join_membership_overrides_earlier_pending_projection() {
        let realm_id = "ck:realm:test";
        let mut store = temp_store("pending-then-joined-membership");
        store.save_realm_tree_projection(
            realm_id.to_owned(),
            serde_json::json!({
                "members": [
                    {
                        "actor_id": "did:web:bob.example",
                        "membership": "invite"
                    },
                    {
                        "actor_id": "did:web:bob.example",
                        "membership": "join"
                    }
                ]
            }),
        );

        let profiles = projected_member_profiles_for_realm(&store, realm_id);
        let (active, pending) = split_member_profiles(profiles);

        assert_eq!(active.len(), 1);
        assert_eq!(active[0].actor_id, "did:web:bob.example");
        assert_eq!(active[0].membership.as_deref(), Some("join"));
        assert!(pending.is_empty());
    }

    #[test]
    fn projected_member_profiles_restore_pending_invites_from_raw_operations() {
        let realm_id = "ck:realm:test";
        let mut store = temp_store("raw-pending-invite");
        store.append_raw_operation(
            "ck:event:invite-local".to_owned(),
            Some(realm_id.to_owned()),
            serde_json::json!({
                "kind": "ck.invite.create",
                "invitee": "did:web:bob.example",
                "invitee_label": "bob:example.com",
                "state": "pending"
            }),
        );

        let profiles = projected_member_profiles_for_realm(&store, realm_id);
        let (active, pending) = split_member_profiles(profiles);

        assert!(active.is_empty());
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].actor_id, "did:web:bob.example");
        assert_eq!(pending[0].handles, vec!["bob:example.com"]);
    }

    #[test]
    fn projected_member_profiles_drop_locally_cancelled_pending_invites() {
        let realm_id = "ck:realm:test";
        let invite_id = "ck:invite:01904100-0000-7000-8000-000000000001";
        let mut store = temp_store("raw-cancelled-pending-invite");
        store.append_raw_operation(
            "ck:event:invite-local".to_owned(),
            Some(realm_id.to_owned()),
            serde_json::json!({
                "kind": "ck.invite.create",
                "invite_id": invite_id,
                "invitee": "did:web:bob.example",
                "invitee_label": "bob:example.com",
                "state": "pending"
            }),
        );
        store.append_raw_operation(
            "ck:event:invite-cancel".to_owned(),
            Some(realm_id.to_owned()),
            serde_json::json!({
                "kind": "ck.invite.cancel",
                "invite_id": invite_id,
                "state": "revoked"
            }),
        );

        let profiles = projected_member_profiles_for_realm(&store, realm_id);
        let (active, pending) = split_member_profiles(profiles);

        assert!(active.is_empty());
        assert!(pending.is_empty());
    }

    #[test]
    fn raw_pending_invite_does_not_override_join_projection() {
        let realm_id = "ck:realm:test";
        let mut store = temp_store("raw-pending-joined");
        store.save_realm_tree_projection(
            realm_id.to_owned(),
            serde_json::json!({
                "members": [{
                    "actor_id": "did:web:bob.example",
                    "membership": "join"
                }]
            }),
        );
        store.append_raw_operation(
            "ck:event:invite-local".to_owned(),
            Some(realm_id.to_owned()),
            serde_json::json!({
                "kind": "ck.invite.create",
                "invitee": "did:web:bob.example",
                "state": "pending"
            }),
        );

        let profiles = projected_member_profiles_for_realm(&store, realm_id);
        let (active, pending) = split_member_profiles(profiles);

        assert_eq!(active.len(), 1);
        assert_eq!(active[0].actor_id, "did:web:bob.example");
        assert_eq!(active[0].membership.as_deref(), Some("join"));
        assert!(pending.is_empty());
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

    // ── Receiver-initiated history pull (ck.realm_key.request) ──────────

    const PROVIDER_DID: &str = "did:web:provider.example";
    const SELF_DID: &str = "did:web:self.example";
    const PROVIDER_DEVICE: &str = "ck:device:01904100-0000-7000-8000-0000000000aa";

    #[test]
    fn plans_request_when_prejoin_gap_and_provider_exist() {
        // Joined at epoch 3, no history_secrets installed, visibility=shared,
        // a non-self provider device is available ⇒ request [0, 2] from it.
        let providers = vec![(PROVIDER_DID.to_owned(), PROVIDER_DEVICE.to_owned())];
        let plan = plan_history_key_request("shared", 3, &[], SELF_DID, &providers)
            .expect("a pre-join gap with a provider yields a plan");
        assert_eq!(plan.from_epoch, 0);
        assert_eq!(plan.to_epoch, 2);
        assert_eq!(plan.provider_principal_id, PROVIDER_DID);
        assert_eq!(plan.provider_device_ref, PROVIDER_DEVICE);
    }

    #[test]
    fn skips_request_when_visibility_forbids_prejoin_pull() {
        let providers = vec![(PROVIDER_DID.to_owned(), PROVIDER_DEVICE.to_owned())];
        // `joined` visibility grants no pre-join window.
        assert!(plan_history_key_request("joined", 3, &[], SELF_DID, &providers).is_none());
        // Unknown / empty visibility is treated as forbidding the pull.
        assert!(plan_history_key_request("", 3, &[], SELF_DID, &providers).is_none());
    }

    #[test]
    fn skips_request_when_no_prejoin_window() {
        // Joined at the genesis epoch ⇒ there is no `< join_epoch` history.
        let providers = vec![(PROVIDER_DID.to_owned(), PROVIDER_DEVICE.to_owned())];
        assert!(plan_history_key_request("shared", 0, &[], SELF_DID, &providers).is_none());
    }

    #[test]
    fn skips_request_when_all_prejoin_epochs_installed() {
        // Joined at epoch 3 and every pre-join epoch (0,1,2) is already installed.
        let providers = vec![(PROVIDER_DID.to_owned(), PROVIDER_DEVICE.to_owned())];
        assert!(plan_history_key_request("shared", 3, &[0, 1, 2], SELF_DID, &providers).is_none());
    }

    #[test]
    fn plans_request_when_partial_gap_remains() {
        // Installed 0 and 2 but 1 is still missing ⇒ still a gap, still request.
        let providers = vec![(PROVIDER_DID.to_owned(), PROVIDER_DEVICE.to_owned())];
        let plan = plan_history_key_request("invited", 3, &[0, 2], SELF_DID, &providers)
            .expect("a remaining gap yields a plan");
        assert_eq!((plan.from_epoch, plan.to_epoch), (0, 2));
    }

    #[test]
    fn skips_request_when_only_self_is_a_provider() {
        // The only candidate is this device's own actor ⇒ no external provider.
        let providers = vec![(SELF_DID.to_owned(), PROVIDER_DEVICE.to_owned())];
        assert!(plan_history_key_request("shared", 3, &[], SELF_DID, &providers).is_none());
        // Empty candidate list ⇒ no provider.
        assert!(plan_history_key_request("shared", 3, &[], SELF_DID, &[]).is_none());
    }

    #[test]
    fn harvests_provider_candidates_from_history_bearing_inbox_messages() {
        let inbox = vec![
            // A Welcome from the admitting (provider) device — top-level sender +
            // sender_device_id, addressed to this realm.
            json!({
                "kind": "ck.mls.welcome",
                "sender": PROVIDER_DID,
                "sender_device_id": PROVIDER_DEVICE,
                "content": { "realm_id": "ck:realm:abc" },
            }),
            // A self-authored message must never name ourselves as provider.
            json!({
                "kind": "ck.mls.commit",
                "sender": SELF_DID,
                "sender_device_id": "ck:device:self",
                "realm_id": "ck:realm:abc",
            }),
            // Unrelated kind is ignored.
            json!({
                "kind": "ck.typing",
                "sender": "did:web:noise.example",
                "sender_device_id": "ck:device:noise",
                "realm_id": "ck:realm:abc",
            }),
            // A message for a different realm is filtered out.
            json!({
                "kind": "ck.mls.welcome",
                "sender": "did:web:other.example",
                "sender_device_id": "ck:device:other",
                "realm_id": "ck:realm:zzz",
            }),
        ];
        let candidates = provider_candidates_from_inbox(&inbox, "ck:realm:abc", SELF_DID);
        assert_eq!(
            candidates,
            vec![(PROVIDER_DID.to_owned(), PROVIDER_DEVICE.to_owned())]
        );
    }

    #[test]
    fn provider_candidates_dedup_repeated_sender() {
        let inbox = vec![
            json!({
                "kind": "ck.mls.welcome",
                "sender": PROVIDER_DID,
                "sender_device_id": PROVIDER_DEVICE,
                "realm_id": "ck:realm:abc",
            }),
            json!({
                "kind": "ck.realm_key.share",
                "sender": PROVIDER_DID,
                "sender_device_id": PROVIDER_DEVICE,
                "realm_id": "ck:realm:abc",
            }),
        ];
        let candidates = provider_candidates_from_inbox(&inbox, "ck:realm:abc", SELF_DID);
        assert_eq!(candidates.len(), 1);
    }
}
