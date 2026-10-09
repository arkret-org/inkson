//! Accepted membership facts and claim selectors, independent of display profiles.

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::event_kind_str;
use serde_json::Value;

use super::{LocalStateStore, RawOperationRecord};

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct MembershipFact {
    pub(crate) actor_id: String,
    pub(crate) membership: Option<String>,
    pub(crate) invite_id: Option<String>,
}
impl MembershipFact {
    fn bare(actor_id: impl Into<String>) -> Self {
        Self {
            actor_id: actor_id.into(),
            membership: None,
            invite_id: None,
        }
    }
    pub(crate) fn normalized_membership(&self) -> Option<&str> {
        self.membership
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }
}
pub(crate) fn trimmed_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

/// Validate canonical roster entries and retain the first duplicate ActorId.
pub(crate) fn validated_realm_roster_entries(
    projection: Option<&Value>,
) -> Vec<arkret_sdk::sync::MemberRosterEntry> {
    let Some(members) = projection
        .and_then(|root| root.get("member_roster_entries"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    let mut rows = BTreeMap::new();
    for member in members {
        let Ok(entry) =
            serde_json::from_value::<arkret_sdk::sync::MemberRosterEntry>(member.clone())
        else {
            continue;
        };
        if entry.validate().is_err() {
            continue;
        }
        rows.entry(entry.actor_id.clone()).or_insert(entry);
    }
    rows.into_values().collect()
}
/// Only records whose Realm matches exactly are included; unknown ownership
/// cannot become an admission or member projection fact.
pub(crate) fn raw_operation_realm_matches_exact(
    record: &RawOperationRecord,
    realm_id: &str,
) -> bool {
    record.realm_id.as_deref().map(str::trim) == Some(realm_id.trim())
}

pub(crate) fn raw_operation_payload_kind(payload: &Value) -> Option<String> {
    trimmed_string(payload.get("kind").or_else(|| payload.get("wire_kind")))
}

pub(crate) fn raw_operation_path_string(payload: &Value, path: &[&str]) -> Option<String> {
    let mut current = payload;
    for segment in path {
        current = current.get(*segment)?;
    }
    trimmed_string(Some(current))
}

pub(crate) fn raw_operation_is_accepted_fact(payload: &Value) -> bool {
    matches!(
        raw_operation_path_string(payload, &["write_state"]).as_deref(),
        Some("synced" | "accepted")
    ) || raw_operation_path_string(payload, &["event_id"]).is_some()
        || raw_operation_path_string(payload, &["body", "event_id"]).is_some()
        || raw_operation_path_string(payload, &["payload", "event_id"]).is_some()
}

pub(crate) fn raw_operation_invite_ref(payload: &Value) -> Option<String> {
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
pub(crate) struct AcceptedInviteClaimRoute {
    pub(crate) destination_id: String,
    pub(crate) target_device_id: Option<String>,
}

pub(crate) fn accepted_invite_claim_route(
    store: &LocalStateStore,
    realm_id: &str,
    invitee_id: &str,
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
                || raw_member_actor_id(payload).as_deref() != Some(invitee_id)
            {
                return None;
            }
            Some((
                raw_operation_invite_ref(payload)?,
                raw_operation_path_string(payload, &["signing_device_id"]),
            ))
        })?;
    let destination_id = state
        .raw_operations
        .iter()
        .rev()
        .filter(|record| raw_operation_realm_matches_exact(record, realm_id))
        .find_map(|record| {
            let payload = &record.payload;
            if raw_operation_payload_kind(payload).as_deref() != Some(event_kind_str::INVITE_CREATE)
                || !raw_operation_is_accepted_fact(payload)
                || raw_invite_create_invitee(payload).as_deref() != Some(invitee_id)
                || raw_operation_invite_ref(payload).as_deref() != Some(accepted.0.as_str())
            {
                return None;
            }
            raw_invite_create_account_id(payload)
                .map(|account_id| account_id.station_id.to_string())
        })?;
    let target_device_id = accepted
        .1
        .map(arkret_sdk::DeviceId::new)
        .transpose()
        .ok()?
        .map(|device| device.to_string());
    Some(AcceptedInviteClaimRoute {
        destination_id,
        target_device_id,
    })
}

pub(crate) fn claim_target_device_id(
    route: &AcceptedInviteClaimRoute,
) -> anyhow::Result<Option<&str>> {
    route.target_device_id.as_deref().map(Some).ok_or_else(|| {
        anyhow::anyhow!(
            "accepted human invite has no exact target device from its accepted Event proof"
        )
    })
}

pub(crate) fn raw_member_actor_id(payload: &Value) -> Option<String> {
    [
        payload.pointer("/body/member_id"),
        payload.pointer("/payload/member_id"),
        payload.get("actor_id"),
    ]
    .into_iter()
    .flatten()
    .find_map(|value| {
        serde_json::from_value::<arkret_sdk::ActorId>(value.clone())
            .ok()
            .map(|actor| actor.to_string())
    })
}

pub(crate) fn raw_member_membership(payload: &Value) -> Option<String> {
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

pub(crate) fn raw_invite_create_invitee(payload: &Value) -> Option<String> {
    raw_invite_create_account_id(payload)
        .map(|account_id| arkret_sdk::ActorId::account(account_id).to_string())
}

pub(crate) fn raw_invite_create_account_id(payload: &Value) -> Option<arkret_sdk::AccountId> {
    [
        payload.pointer("/body/invitee_account_id"),
        payload.pointer("/payload/invitee_account_id"),
        payload.get("invitee_account_id"),
    ]
    .into_iter()
    .flatten()
    .find_map(|value| serde_json::from_value(value.clone()).ok())
}

pub(crate) fn local_invitee_by_invite_id_for_realm(
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

pub(crate) fn local_membership_fact_from_raw_operation(
    record: &RawOperationRecord,
    realm_id: &str,
    invitee_by_invite_id: &BTreeMap<String, String>,
) -> Option<MembershipFact> {
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
            let mut profile = MembershipFact::bare(actor_id);
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
            let mut profile = MembershipFact::bare(actor_id);
            profile.membership = Some("join".to_owned());
            profile.invite_id = invite_id;
            Some(profile)
        }
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum MembershipCompleteness {
    #[default]
    Unavailable,
    Limited,
    Complete,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProjectedRealmMembershipHint {
    pub(crate) joined: BTreeSet<String>,
    pub(crate) completeness: MembershipCompleteness,
}

/// Account-sync `members[]` is a current roster projection hint. It is more
/// suitable than the bounded raw-operation cache for reconciliation wakeups,
/// but it is not membership authority: the governance proof and server-side
/// Event auth still gate every KeyPackage claim and MLS Commit.
pub(crate) fn projected_realm_membership_hint(
    store: &LocalStateStore,
    realm_id: &str,
) -> ProjectedRealmMembershipHint {
    let state = store.load();
    let Some(projection) = state.realm_tree_projections.get(realm_id) else {
        return ProjectedRealmMembershipHint::default();
    };
    let Some(_) = projection
        .get("member_roster_entries")
        .and_then(Value::as_array)
    else {
        return ProjectedRealmMembershipHint::default();
    };
    let joined = validated_realm_roster_entries(Some(projection))
        .into_iter()
        .filter(|member| member.membership == arkret_sdk::sync::MemberRosterMembership::Join)
        .map(|member| member.actor_id.to_string())
        .collect();
    let completeness = if projection
        .get("member_roster_entries_limited")
        .and_then(Value::as_bool)
        == Some(false)
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

pub(crate) fn accepted_membership_facts_for_realm(
    store: &LocalStateStore,
    realm_id: &str,
) -> Vec<MembershipFact> {
    let state = store.load();
    let invitee_by_invite_id =
        local_invitee_by_invite_id_for_realm(&state.raw_operations, realm_id);
    let mut rows =
        BTreeMap::<String, (chrono::DateTime<chrono::Utc>, String, MembershipFact)>::new();
    for record in &state.raw_operations {
        if let Some(profile) =
            local_membership_fact_from_raw_operation(record, realm_id, &invitee_by_invite_id)
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

pub(crate) fn raw_operation_event_time(
    record: &RawOperationRecord,
) -> chrono::DateTime<chrono::Utc> {
    raw_operation_path_string(&record.payload, &["created_at"])
        .and_then(|timestamp| chrono::DateTime::parse_from_rfc3339(&timestamp).ok())
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .unwrap_or(record.received_at)
}

/// Admission candidates combine the positive roster hint with locally verified
/// membership state. Accepted state wins on conflict; the hint fills actors for
/// which the bounded local state-event cache has no cell and wakes reconciliation
/// when a membership-only projection arrives.
pub(crate) fn admission_joined_members_for_realm(
    store: &LocalStateStore,
    realm_id: &str,
) -> BTreeSet<String> {
    let hint = projected_realm_membership_hint(store, realm_id);
    let mut joined = hint.joined;
    for member in accepted_membership_facts_for_realm(store, realm_id) {
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

pub(crate) fn principal_core_key(value: &str) -> Option<String> {
    crate::mls_api_helpers::principal_core_id(value)
        .ok()
        .map(|id| id.as_str().to_owned())
}

pub(crate) fn is_local_account_actor(actor_key: &str, principal: &str) -> bool {
    serde_json::from_str::<arkret_sdk::ActorId>(actor_key)
        .ok()
        .zip(crate::mls_api_helpers::local_account_actor_id(principal).ok())
        .is_some_and(|(actor, local)| actor == local)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn canonical_roster_keeps_first_duplicate_and_rejects_display_only_rows() {
        let actor = json!({"kind":"account", "account_id":{
            "principal_id":"ak:did_core:web:bob.example",
            "station_id":"ak:did_core:web:principal.example"
        }});
        let projection = json!({"member_roster_entries":[
            {"actor_id":actor, "membership":"knock"},
            {"actor_id":actor, "membership":"join"},
            {"actor_id":actor, "membership":"leave"},
            {"actor_id":actor, "membership":"join", "display_name":"untrusted"}
        ]});
        let entries = validated_realm_roster_entries(Some(&projection));
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].membership,
            arkret_sdk::sync::MemberRosterMembership::Knock
        );
    }

    #[test]
    fn roster_disclosure_failure_cannot_become_an_admission_hint() {
        let projection = json!({"member_roster_entries":[{
            "actor_id":{"kind":"account", "account_id":{
                "principal_id":"ak:did_core:web:bob.example",
                "station_id":"ak:did_core:web:principal.example"
            }},
            "membership":"join", "handle_claims_limited":false
        }]});
        assert!(validated_realm_roster_entries(Some(&projection)).is_empty());
    }
}
