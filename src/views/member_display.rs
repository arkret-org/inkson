use std::collections::BTreeMap;

use serde_json::Value;

use super::helpers::short_protocol_id;
use crate::state::LocalStateStore;

/// Canonical Realm roster row from the root `members[]` projection.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RealmMemberRow {
    pub actor_id: String,
    pub membership: Option<String>,
    pub identity_event_ids: Vec<String>,
    pub member_display_state_digest: Option<String>,
    pub subject_id: Option<String>,
    pub handle_claims: Vec<Value>,
    pub handle_claims_limited: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ResolvedMemberDisplay {
    pub label: String,
    pub primary_handle: Option<String>,
    pub display_name: Option<String>,
    pub avatar_blob_ref: Option<arkret_sdk::BlobRef>,
    pub subject_id: Option<String>,
}

pub(crate) fn realm_member_roster(projection: Option<&Value>) -> Vec<RealmMemberRow> {
    let Some(members) = projection
        .and_then(|root| root.get("members"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    let mut rows = BTreeMap::new();
    for member in members {
        let Some(map) = member.as_object() else {
            continue;
        };
        let Some(actor_id) = map
            .get("actor_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let string_field = |key: &str| {
            map.get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        };
        let row = RealmMemberRow {
            actor_id: actor_id.to_owned(),
            membership: string_field("membership"),
            identity_event_ids: map
                .get("identity_event_ids")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect(),
            member_display_state_digest: string_field("member_display_state_digest"),
            subject_id: string_field("subject_id"),
            handle_claims: map
                .get("handle_claims")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            handle_claims_limited: map
                .get("handle_claims_limited")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        };
        // `actor_id` is the roster key. Retain the first duplicate exactly as
        // required by the sync contract.
        rows.entry(row.actor_id.clone()).or_insert(row);
    }
    rows.into_values().collect()
}

pub(crate) fn verified_inline_handle(row: &RealmMemberRow) -> Option<String> {
    // R3.2 disclosure gates handle evidence on `subject_id`; claims without
    // that disclosed binding are malformed and must not affect display.
    let subject = row.subject_id.as_deref()?;
    row.handle_claims.iter().find_map(|claim| {
        if claim.get("subject").and_then(Value::as_str)?.trim() != subject
            || claim.get("binding_state").and_then(Value::as_str) != Some("verified")
        {
            return None;
        }
        claim
            .get("handle")
            .and_then(Value::as_str)
            .and_then(crate::identity::handle::parse_user_handle)
            .map(|handle| handle.display)
    })
}

pub(crate) fn member_lookup_subject(
    row: &RealmMemberRow,
    identity: Option<&arkret_sdk::MemberIdentity>,
) -> Option<String> {
    row.subject_id
        .as_deref()
        .map(str::trim)
        .filter(|subject| subject.starts_with("did:"))
        .filter(|subject| !subject.is_empty())
        .map(str::to_owned)
        .or_else(|| identity.map(|identity| identity.subject_id.as_str().to_owned()))
}

pub(crate) fn resolve_member_display(
    store: &LocalStateStore,
    realm_id: &str,
    row: &RealmMemberRow,
    preferred_primary_handle: Option<&str>,
) -> ResolvedMemberDisplay {
    let identity = store.resolved_member_identity(realm_id, &row.actor_id);
    let subject_id = member_lookup_subject(row, identity.as_ref());
    let cached_handle = subject_id.as_deref().and_then(|subject| {
        store
            .cached_member_handle_lookup(
                subject,
                Some(realm_id),
                row.member_display_state_digest.as_deref(),
            )
            .and_then(|entry| entry.primary_handle)
    });
    let primary_handle = preferred_primary_handle
        .and_then(crate::identity::handle::parse_user_handle)
        .map(|handle| handle.display)
        .or(cached_handle.and_then(|handle| {
            crate::identity::handle::parse_user_handle(&handle).map(|parsed| parsed.display)
        }))
        .or_else(|| verified_inline_handle(row));
    let display_name = identity.as_ref().and_then(|identity| {
        let name = identity.display_profile.display_name.trim();
        (!name.is_empty()).then(|| name.to_owned())
    });
    let label = member_label(row, identity.as_ref(), primary_handle.as_deref());
    ResolvedMemberDisplay {
        label,
        primary_handle,
        display_name,
        avatar_blob_ref: identity.and_then(|identity| identity.display_profile.avatar_blob_ref),
        subject_id,
    }
}

pub(crate) fn member_label(
    row: &RealmMemberRow,
    identity: Option<&arkret_sdk::MemberIdentity>,
    primary_handle: Option<&str>,
) -> String {
    primary_handle
        .and_then(crate::identity::handle::parse_user_handle)
        .map(|handle| handle.display)
        .or_else(|| verified_inline_handle(row))
        .or_else(|| {
            identity.and_then(|identity| {
                let name = identity.display_profile.display_name.trim();
                (!name.is_empty()).then(|| name.to_owned())
            })
        })
        .unwrap_or_else(|| short_protocol_id(&row.actor_id))
}

pub(crate) fn owned_agent_slug<'a>(
    row: &RealmMemberRow,
    owned_agent_slugs: &'a BTreeMap<String, String>,
) -> Option<&'a str> {
    owned_agent_slugs
        .get(&row.actor_id)
        .or_else(|| {
            row.subject_id
                .as_ref()
                .and_then(|subject| owned_agent_slugs.get(subject))
        })
        .map(String::as_str)
}
