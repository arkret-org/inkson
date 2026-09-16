use serde_json::Value;

use crate::models::RealmTreeNodeKind;
use crate::state::LocalStateStore;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MetadataSubject {
    pub(crate) kind: RealmTreeNodeKind,
    pub(crate) home_realm_id: String,
    pub(crate) title: String,
    pub(crate) summary: String,
    pub(crate) avatar_blob_ref: String,
}

fn projection_kind_for_admin(subject_id: &str) -> RealmTreeNodeKind {
    if subject_id.starts_with("ak:space:") {
        RealmTreeNodeKind::Space
    } else {
        RealmTreeNodeKind::Realm
    }
}

fn projection_home_realm_for_admin(
    subject_id: &str,
    kind: RealmTreeNodeKind,
    body: Option<&Value>,
) -> String {
    if kind == RealmTreeNodeKind::Realm {
        return crate::operation::trim_realm_id(subject_id);
    }
    body.and_then(|body| body.get("realm_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|realm_id| !realm_id.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| crate::operation::trim_realm_id(subject_id))
}

fn canonical_realm_profile(body: Option<&Value>) -> Option<arkret_sdk::WindowStartRealmMetadata> {
    let metadata = body?.pointer("/state_at_window_start/realm_metadata")?;
    serde_json::from_value(metadata.clone()).ok()
}

fn local_realm_profile(body: Option<&Value>) -> Option<arkret_sdk::RealmProfile> {
    serde_json::from_value(body?.get("_inkson_realm_profile_payload")?.clone()).ok()
}

pub(crate) fn store_accepted_realm_profile(
    store: &mut LocalStateStore,
    realm_id: &str,
    title: &str,
    summary: Option<&str>,
    avatar_blob_ref: Option<&str>,
) {
    let Some(mut projection) = store.load().realm_tree_projections.get(realm_id).cloned() else {
        return;
    };
    let Ok(mut profile) = arkret_sdk::RealmProfile::new(title) else {
        return;
    };
    profile.summary = summary.map(ToOwned::to_owned);
    profile.avatar_blob_ref = avatar_blob_ref
        .map(|value| arkret_sdk::BlobRef::new(value.to_owned()))
        .transpose()
        .ok()
        .flatten();
    let Ok(payload) = serde_json::to_value(profile) else {
        return;
    };
    let Some(root) = projection.as_object_mut() else {
        return;
    };
    root.insert("_inkson_realm_profile_payload".to_owned(), payload);
    let Some(state) = root
        .entry("state_at_window_start")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
    else {
        return;
    };
    let Some(metadata) = state
        .entry("realm_metadata")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
    else {
        return;
    };
    metadata.insert("title".to_owned(), Value::String(title.to_owned()));
    if let Some(summary) = summary {
        metadata.insert("summary".to_owned(), Value::String(summary.to_owned()));
    } else {
        metadata.remove("summary");
    }
    store.save_realm_tree_projection(realm_id.to_owned(), projection);
}

fn canonical_space_string(body: Option<&Value>, field: &str) -> String {
    body.and_then(|body| body.get(field))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_default()
}

pub(crate) fn reconcile_editor_value(
    current: &str,
    previous_projection: &str,
    current_projection: &str,
) -> String {
    if current == previous_projection {
        current_projection.to_owned()
    } else {
        current.to_owned()
    }
}

pub(crate) fn metadata_subject_for(store: &LocalStateStore, subject_id: &str) -> MetadataSubject {
    let state = store.load();
    let body = state.realm_tree_projections.get(subject_id);
    let kind = projection_kind_for_admin(subject_id);
    let (title, summary, avatar_blob_ref) = match kind {
        RealmTreeNodeKind::Realm => {
            let local_profile = local_realm_profile(body);
            let profile = canonical_realm_profile(body);
            (
                local_profile
                    .as_ref()
                    .map(|profile| profile.title.clone())
                    .or_else(|| profile.as_ref().and_then(|profile| profile.title.clone()))
                    .unwrap_or_default(),
                local_profile
                    .as_ref()
                    .and_then(|profile| profile.summary.clone())
                    .or_else(|| profile.as_ref().and_then(|profile| profile.summary.clone()))
                    .unwrap_or_default(),
                local_profile
                    .and_then(|profile| profile.avatar_blob_ref)
                    .map(|blob_ref| blob_ref.to_string())
                    .unwrap_or_default(),
            )
        }
        RealmTreeNodeKind::Space => (
            canonical_space_string(body, "title"),
            canonical_space_string(body, "summary"),
            canonical_space_string(body, "avatar_blob_ref"),
        ),
    };
    MetadataSubject {
        kind,
        home_realm_id: projection_home_realm_for_admin(subject_id, kind, body),
        title,
        summary,
        avatar_blob_ref,
    }
}

/// Close a typed capability subject into the Realm member it names.
///
/// The admin surfaces take the subject as text. A canonical account selector
/// is taken as is; a bare principal is joined against the locally replayed
/// roster and accepted only when exactly one member account carries it. A
/// principal that is not in the roster, or that appears under two Stations,
/// fails closed: completing it with this client's Station would grant to
/// `(principal, here)`, which for a member hosted elsewhere is an account that
/// is not in the Realm (account-lifecycle.md §156/§158).
pub(crate) fn resolve_realm_member_account(
    store: &LocalStateStore,
    realm_id: &str,
    subject: &str,
) -> anyhow::Result<arkret_sdk::AccountId> {
    let subject = subject.trim();
    if let Some(account) = crate::mls_api_helpers::account_id_from_selector(subject) {
        return Ok(account);
    }
    let principal_id = crate::mls_api_helpers::principal_core_id(subject)
        .map_err(|error| anyhow::anyhow!("subject is not a principal id: {error}"))?;
    let state = store.load();
    let projection = state.realm_tree_projections.get(realm_id);
    let mut candidates = crate::views::member_display::realm_member_roster(projection)
        .into_iter()
        .filter_map(|row| row.actor_id.as_account_id().cloned())
        .filter(|account| account.principal_id == principal_id)
        .collect::<Vec<_>>();
    candidates.dedup();
    match candidates.as_slice() {
        [account] => Ok(account.clone()),
        [] => anyhow::bail!(
            "subject {principal_id} is not a member account of this Realm; paste the full account selector to grant to an account hosted elsewhere"
        ),
        _ => anyhow::bail!(
            "subject {principal_id} is a member of this Realm under more than one Station; paste the full account selector"
        ),
    }
}

pub(crate) fn projected_members_for_realm(store: &LocalStateStore, realm_id: &str) -> Vec<String> {
    let state = store.load();
    let Some(projection) = state.realm_tree_projections.get(realm_id) else {
        return Vec::new();
    };
    crate::views::member_display::realm_member_roster(Some(projection))
        .into_iter()
        .map(|row| row.actor_id.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_subject_reads_window_start_realm_metadata() {
        let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
        let mut store = LocalStateStore::default();
        store.save_realm_tree_projection(
            realm_id.to_owned(),
            serde_json::json!({
                "state_at_window_start": {
                    "actor_profiles": [],
                    "realm_metadata": {
                        "title": "AMAZON",
                        "summary": "Current Realm summary"
                    },
                    "e2ee_epoch": null
                },
                "summary": {"joined_member_count": 1},
                "timeline": {"events": [], "limited": false}
            }),
        );

        let subject = metadata_subject_for(&store, realm_id);

        assert_eq!(subject.title, "AMAZON");
        assert_eq!(subject.summary, "Current Realm summary");
    }

    #[test]
    fn metadata_subject_rejects_retired_realm_metadata_shapes() {
        let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
        let mut store = LocalStateStore::default();
        store.save_realm_tree_projection(
            realm_id.to_owned(),
            serde_json::json!({
                "title": "retired top-level title",
                "description": "retired description",
                "summary": {
                    "title": "retired summary title",
                    "summary": "retired nested summary"
                },
                "object": {
                    "title": "retired object title",
                    "summary": "retired object summary",
                    "avatar_blob_ref": "ak:blob:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            }),
        );

        let subject = metadata_subject_for(&store, realm_id);

        assert!(subject.title.is_empty());
        assert!(subject.summary.is_empty());
        assert!(subject.avatar_blob_ref.is_empty());
    }

    #[test]
    fn projection_refresh_fills_untouched_editor_without_overwriting_user_input() {
        assert_eq!(reconcile_editor_value("", "", "AMAZON"), "AMAZON");
        assert_eq!(
            reconcile_editor_value("Operator draft", "", "AMAZON"),
            "Operator draft"
        );
    }

    #[test]
    fn projected_members_reads_roster_actor_id_entries() {
        let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
        let mut store = LocalStateStore::default();
        store.save_realm_tree_projection(
            realm_id.to_owned(),
            serde_json::json!({
                "member_roster_entries": [
                    {"actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}}, "membership": "join"},
                    {"actor_id": {"kind":"service","service_id":"ak:did_core:web:agent.example"}, "membership": "join"}
                ]
            }),
        );

        assert_eq!(
            projected_members_for_realm(&store, realm_id),
            vec![
                crate::mls_api_helpers::local_account_actor_id("ak:did_core:web:alice.example")
                    .unwrap()
                    .to_string(),
                arkret_sdk::ActorId::service(
                    arkret_sdk::DidCoreId::new("ak:did_core:web:agent.example").unwrap()
                )
                .to_string()
            ]
        );
    }

    #[test]
    fn projected_members_ignores_noncanonical_projection_sources() {
        let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
        let mut store = LocalStateStore::default();
        store.save_realm_tree_projection(
            realm_id.to_owned(),
            serde_json::json!({
                "owner": "did:web:owner.example",
                "admins": [{"actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:admin.example","station_id":"ak:did_core:web:principal.example"}}, "membership": "join"}],
                "summary": {
                    "members": [{"actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:member.example","station_id":"ak:did_core:web:principal.example"}}, "membership": "join"}],
                    "created_by": "did:web:owner.example"
                }
            }),
        );

        assert!(projected_members_for_realm(&store, realm_id).is_empty());
    }
}
