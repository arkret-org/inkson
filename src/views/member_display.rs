use std::collections::{BTreeMap, BTreeSet};

use dioxus::prelude::{SyncSignal, WritableExt};
use serde_json::Value;

use super::helpers::short_protocol_id;
use crate::state::LocalStateStore;

/// Canonical Realm roster row from the root `member_roster_entries[]` projection.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RealmMemberRow {
    pub actor_id: arkret_sdk::ActorId,
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
    pub collision_public_display: String,
    pub primary_handle: Option<String>,
    pub display_name: Option<String>,
    pub avatar_blob_ref: Option<arkret_sdk::BlobRef>,
    pub subject_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MemberHandleLookupRequest {
    pub request_key: String,
    pub subject_id: String,
    pub realm_id: String,
    pub member_display_state_digest: Option<String>,
}

pub(crate) fn realm_member_roster(projection: Option<&Value>) -> Vec<RealmMemberRow> {
    let Some(members) = projection
        .and_then(|root| root.get("member_roster_entries"))
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
            .and_then(|value| serde_json::from_value::<arkret_sdk::ActorId>(value.clone()).ok())
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
            actor_id,
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
        if !matches!(row.membership.as_deref(), Some("join" | "knock")) {
            continue;
        }
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
        let core = claim.get("claim")?;
        if core
            .get("subject_account_id")
            .and_then(|account| account.get("principal_id"))
            .and_then(Value::as_str)?
            .trim()
            != subject
            || claim.get("status").and_then(Value::as_str) != Some("verified")
            || claim
                .get("revocation_digest")
                .is_some_and(|value| !value.is_null())
            || claim
                .get("fresh_until")
                .and_then(Value::as_str)
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .is_none_or(|fresh_until| fresh_until <= chrono::Utc::now())
        {
            return None;
        }
        core.get("handle")
            .and_then(Value::as_str)
            .and_then(crate::identity::handle::parse_user_handle)
            .map(|handle| handle.display)
    })
}

#[cfg(test)]
pub(crate) fn test_inline_handle_claim(subject: &str, handle: &str, status: &str) -> Value {
    serde_json::json!({
        "schema": "ak.schema.handle_claim.v1",
        "claim": {
            "handle": handle,
            "subject_account_id": {
                "principal_id": subject,
                "station_id": "ak:did_core:web:fixture-station.example"
            }
        },
        "status": status,
        "revocation_digest": null,
        "fresh_until": "2099-01-01T00:00:00.000Z"
    })
}

fn principal_core_subject(value: &str) -> Option<String> {
    let value = value.trim();
    arkret_sdk::DidCoreId::new(value.to_owned())
        .ok()
        .map(|id| id.as_str().to_owned())
}

pub(crate) fn member_lookup_subject(
    row: &RealmMemberRow,
    identity: Option<&arkret_sdk::MemberIdentity>,
) -> Option<String> {
    row.subject_id
        .as_deref()
        .and_then(principal_core_subject)
        .or_else(|| {
            identity.and_then(|identity| {
                principal_core_subject(identity.subject_actor_id.signing_principal_id().as_str())
            })
        })
}

fn member_handle_lookup_subject(
    row: &RealmMemberRow,
    identity: Option<&arkret_sdk::MemberIdentity>,
) -> Option<String> {
    member_lookup_subject(row, identity)
        // The roster actor is already disclosed to this Realm member. It may
        // also be the account's principal DID (the common non-pairwise case),
        // so it is a valid candidate for the subject -> handle query. The
        // Directory still has to return a verified claim for this exact DID
        // under the Realm context; a pairwise actor simply yields no claim.
        .or_else(|| {
            principal_core_subject(row.actor_id.signing_principal_id().as_str())
        })
}

pub(crate) fn member_handle_fetch_key(
    realm_id: &str,
    subject_id: &str,
    digest: Option<&str>,
) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}",
        realm_id.trim(),
        subject_id.trim(),
        digest.unwrap_or_default().trim()
    )
}

pub(crate) fn missing_member_handle_lookups(
    store: &LocalStateStore,
    realm_id: &str,
    rows: &[RealmMemberRow],
    in_flight: &BTreeSet<String>,
) -> Vec<MemberHandleLookupRequest> {
    let mut requests = Vec::new();
    for row in rows {
        if verified_inline_handle(row).is_some() {
            continue;
        }
        let identity = store.resolved_member_identity(realm_id, &row.actor_id);
        let Some(subject_id) = member_handle_lookup_subject(row, identity.as_ref()) else {
            continue;
        };
        let digest = row.member_display_state_digest.clone();
        if store
            .cached_member_handle_lookup(&subject_id, Some(realm_id), digest.as_deref())
            .is_some()
        {
            continue;
        }
        let request_key = member_handle_fetch_key(realm_id, &subject_id, digest.as_deref());
        if in_flight.contains(&request_key) {
            continue;
        }
        requests.push(MemberHandleLookupRequest {
            request_key,
            subject_id,
            realm_id: realm_id.to_owned(),
            member_display_state_digest: digest,
        });
    }
    requests
}

pub(crate) async fn fetch_and_cache_member_handle(
    base_url: String,
    api_token: String,
    mut state_store: SyncSignal<LocalStateStore>,
    request: MemberHandleLookupRequest,
) {
    let subject_id = request.subject_id.clone();
    let realm_id = request.realm_id.clone();
    let result = crate::transport::auth::with_endpoint_clients(&base_url, api_token, None, {
        let subject_id = subject_id.clone();
        let realm_id = realm_id.clone();
        move |clients| async move {
            clients
                .directory()
                .list_handles_for_subject(
                    &subject_id,
                    Some(&realm_id),
                    Some(arkret_models_discovery::DirectoryIntent::Lookup),
                )
                .await
        }
    })
    .await;
    match result {
        Ok(response) if response.account_id.principal_id.as_str() == request.subject_id => {
            let primary = response
                .primary_handle
                .as_ref()
                .map(|handle| handle.canonical().to_owned());
            let claims_count = response.claims.len();
            let earliest_expiry = response
                .claims
                .iter()
                .filter_map(|claim| claim.claim.expires_at.as_ref().cloned())
                .min();
            state_store.write().save_member_handle_lookup(
                response.account_id.principal_id.as_str().to_owned(),
                Some(request.realm_id),
                request.member_display_state_digest,
                primary,
                claims_count,
                Some(response.as_of),
                earliest_expiry,
            );
        }
        Ok(_) => {
            // A reverse lookup is useful only for the exact already-known
            // subject. Never cache a server response under a different DID.
            state_store.write().save_member_handle_lookup(
                request.subject_id,
                Some(request.realm_id),
                request.member_display_state_digest,
                None,
                0,
                None,
                None,
            );
        }
        Err(error) if !error.is_auth_expired() => {
            state_store.write().save_member_handle_lookup(
                request.subject_id,
                Some(request.realm_id),
                request.member_display_state_digest,
                None,
                0,
                None,
                None,
            );
        }
        Err(_) => {}
    }
}

pub(crate) fn resolve_member_display(
    store: &LocalStateStore,
    realm_id: &str,
    row: &RealmMemberRow,
) -> ResolvedMemberDisplay {
    let identity = store.resolved_member_identity(realm_id, &row.actor_id);
    let subject_id = member_lookup_subject(row, identity.as_ref());
    let handle_lookup_subject = member_handle_lookup_subject(row, identity.as_ref());
    let cached_handle = handle_lookup_subject.as_deref().and_then(|subject| {
        store
            .cached_member_handle_lookup(
                subject,
                Some(realm_id),
                row.member_display_state_digest.as_deref(),
            )
            .and_then(|entry| entry.primary_handle)
    });
    let primary_handle = [
        subject_id.as_deref(),
        Some(row.actor_id.signing_principal_id().as_str()),
    ]
    .into_iter()
    .flatten()
    .find_map(|principal_id| store.primary_handle_for_principal_id(principal_id))
    .and_then(|handle| {
        crate::identity::handle::parse_user_handle(&handle).map(|parsed| parsed.display)
    })
    .or(cached_handle.and_then(|handle| {
        crate::identity::handle::parse_user_handle(&handle).map(|parsed| parsed.display)
    }))
    .or_else(|| verified_inline_handle(row));
    let display_name = identity.as_ref().and_then(|identity| {
        let name = identity.display_profile.display_name.trim();
        (!name.is_empty()).then(|| name.to_owned())
    });
    let public_label = member_label(row, identity.as_ref(), primary_handle.as_deref());
    let collision_public_display = display_name
        .as_ref()
        .cloned()
        .unwrap_or_else(|| public_label.clone());
    let label = member_label_with_contact_petname(store, row, &public_label);
    ResolvedMemberDisplay {
        label,
        collision_public_display,
        primary_handle,
        display_name,
        avatar_blob_ref: identity.and_then(|identity| identity.display_profile.avatar_blob_ref),
        subject_id,
    }
}

/// Canonical actor label for surfaces that only have a stable principal id and no Realm
/// roster row. An accepted human Contact's global petname wins; verified
/// handles remain the secondary fallback and the protocol id is last.
pub(crate) fn actor_display_label(store: &LocalStateStore, principal_id: &str) -> String {
    store
        .active_contact_remark(principal_id)
        .and_then(|remark| {
            let petname = remark.petname.trim();
            (!petname.is_empty()).then(|| petname.to_owned())
        })
        .or_else(|| {
            store
                .primary_handle_for_principal_id(principal_id)
                .and_then(|handle| crate::identity::handle::parse_user_handle(&handle))
                .map(|parsed| parsed.display)
        })
        .or_else(|| {
            store
                .cached_member_handle_lookup(principal_id, None, None)
                .and_then(|entry| entry.primary_handle)
                .and_then(|handle| crate::identity::handle::parse_user_handle(&handle))
                .map(|parsed| parsed.display)
        })
        .unwrap_or_else(|| short_protocol_id(principal_id))
}

/// Realm roster variant. A petname is joined only through a unique verified
/// subject_id projection; actor ids and display strings are never guessed as
/// Contact principals.
pub(crate) fn member_label_with_contact_petname(
    store: &LocalStateStore,
    row: &RealmMemberRow,
    public_label: &str,
) -> String {
    row.subject_id
        .as_deref()
        .and_then(|principal_id| store.active_contact_remark(principal_id))
        .and_then(|remark| {
            let petname = remark.petname.trim();
            (!petname.is_empty()).then(|| petname.to_owned())
        })
        .unwrap_or_else(|| public_label.to_owned())
}

/// Build the bounded local anchor index used to warn when a visible public
/// display string collides with another accepted Contact's saved identity.
pub(crate) fn contact_petname_binding_index(
    remarks: &BTreeMap<String, crate::account_data::ContactRemark>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut index = BTreeMap::<String, BTreeSet<String>>::new();
    for (principal_id, remark) in remarks {
        for anchor in [
            Some(remark.petname.as_str()),
            remark.global_display_name_at_save.as_deref(),
        ]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|anchor| !anchor.is_empty())
        {
            if let Ok(skeleton) = arkret_sdk::display_confusable_skeleton_v1(anchor) {
                index
                    .entry(skeleton)
                    .or_default()
                    .insert(principal_id.clone());
            }
        }
    }
    index
}

pub(crate) fn public_display_conflicts_with_other_contact(
    anchor_index: &BTreeMap<String, BTreeSet<String>>,
    subject_principal_id: Option<&str>,
    public_display: &str,
) -> bool {
    let Ok(skeleton) = arkret_sdk::display_confusable_skeleton_v1(public_display) else {
        return false;
    };
    anchor_index.get(&skeleton).is_some_and(|principals| {
        principals
            .iter()
            .any(|principal| Some(principal.as_str()) != subject_principal_id)
    })
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
        .unwrap_or_else(|| short_protocol_id(row.actor_id.signing_principal_id().as_str()))
}

pub(crate) fn owned_agent_slug<'a>(
    row: &RealmMemberRow,
    owned_agent_slugs: &'a BTreeMap<String, String>,
) -> Option<&'a str> {
    let arkret_sdk::ActorId::Account {
        account_id: arkret_sdk::AccountId { station_id, .. },
    } = &row.actor_id
    else {
        return None;
    };
    if !crate::operation::authoring_station_id().is_ok_and(|local| local == *station_id) {
        return None;
    }
    owned_agent_slugs
        .get(row.actor_id.signing_principal_id().as_str())
        .or_else(|| {
            row.subject_id
                .as_ref()
                .and_then(|subject| owned_agent_slugs.get(subject))
        })
        .map(String::as_str)
}

#[cfg(test)]
mod petname_tests {
    use super::*;

    #[test]
    fn roster_keeps_accounts_at_different_stations_distinct() {
        let principal =
            arkret_sdk::DidCoreId::new("ak:did_core:web:roster-isolation.example").unwrap();
        let actor = |station| {
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                principal.clone(),
                arkret_sdk::DidCoreId::new(station).unwrap(),
            ))
        };
        let first = actor("ak:did_core:web:station-a.example");
        let second = actor("ak:did_core:web:station-b.example");
        let projection = serde_json::json!({"member_roster_entries": [
            {"actor_id": first, "membership": "join"},
            {"actor_id": second, "membership": "knock"},
            {"actor_id": first, "membership": "leave"},
            {"actor_id": principal, "membership": "join"}
        ]});
        let rows = realm_member_roster(Some(&projection));
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows.iter()
                .find(|row| row.actor_id == first)
                .unwrap()
                .membership
                .as_deref(),
            Some("join")
        );
        assert_eq!(
            rows.iter()
                .find(|row| row.actor_id == second)
                .unwrap()
                .membership
                .as_deref(),
            Some("knock")
        );
    }

    fn remark(principal_id: &str, petname: &str) -> crate::account_data::ContactRemark {
        crate::account_data::ContactRemark::new(
            arkret_sdk::DidCoreId::new(principal_id).unwrap(),
            petname,
            chrono::Utc::now(),
        )
    }

    fn accepted_human(principal_id: &str) -> crate::models::ContactListRow {
        crate::models::ContactListRow {
            peer: arkret_sdk::contact_operations::ContactPeer::Human {
                account_id: arkret_sdk::AccountId::new(
                    arkret_sdk::DidCoreId::new(principal_id).unwrap(),
                    arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                ),
            },
            state: arkret_sdk::ContactState::Accepted,
            request_event_ref: None,
            request_receipt: None,
            response_event_ref: None,
            tombstone_event_ref: None,
            next_prepare_input: None,
            granted_to_peer_scopes: Vec::new(),
            granted_by_peer_scopes: Vec::new(),
            bidirectional_scopes: Vec::new(),
            effective_scopes: None,
            peer_host_id: None,
            continuity_evidence: None,
            direct_conversation: None,
            peer_host_resolution: None,
            contact_agent_projections: Vec::new(),
        }
    }

    fn realm_row(actor_id: &str, subject_id: Option<&str>) -> RealmMemberRow {
        RealmMemberRow {
            actor_id: crate::mls_api_helpers::local_account_actor_id(actor_id).unwrap(),
            membership: Some("join".to_owned()),
            identity_event_ids: Vec::new(),
            member_display_state_digest: None,
            subject_id: subject_id.map(ToOwned::to_owned),
            handle_claims: Vec::new(),
            handle_claims_limited: false,
        }
    }

    #[test]
    fn realm_petname_requires_both_accepted_contact_and_verified_subject_join() {
        let principal = "ak:did_core:web:alice.example";
        let mut store = LocalStateStore::default();
        store.set_contact_remark(principal, remark(principal, "Alice from Ops"));
        store.replace_accepted_human_contacts(&[accepted_human(principal)]);

        assert_eq!(
            member_label_with_contact_petname(
                &store,
                &realm_row("ak:did_core:key:realm-actor", None),
                "Public Alice",
            ),
            "Public Alice"
        );
        assert_eq!(
            member_label_with_contact_petname(
                &store,
                &realm_row("ak:did_core:key:realm-actor", Some(principal)),
                "Public Alice",
            ),
            "Alice from Ops"
        );

        store.replace_accepted_human_contacts(&[]);
        assert_eq!(
            member_label_with_contact_petname(
                &store,
                &realm_row("ak:did_core:key:realm-actor", Some(principal)),
                "Public Alice",
            ),
            "Public Alice"
        );
    }

    #[test]
    fn contact_anchor_index_excludes_the_visible_subjects_own_anchor() {
        let alice = "ak:did_core:web:alice.example";
        let bob = "ak:did_core:web:bob.example";
        let remarks = BTreeMap::from([
            (alice.to_owned(), remark(alice, "Alice")),
            (bob.to_owned(), remark(bob, "Bob")),
        ]);
        let index = contact_petname_binding_index(&remarks);

        assert!(!public_display_conflicts_with_other_contact(
            &index,
            Some(alice),
            "Ａlice"
        ));
        assert!(public_display_conflicts_with_other_contact(
            &index,
            Some(bob),
            "Ａlice"
        ));
        assert!(public_display_conflicts_with_other_contact(
            &index, None, "Ａlice"
        ));
    }
}
