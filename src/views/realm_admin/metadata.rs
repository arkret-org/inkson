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
            let profile = canonical_realm_profile(body);
            (
                profile
                    .as_ref()
                    .and_then(|profile| profile.title.clone())
                    .unwrap_or_default(),
                profile
                    .as_ref()
                    .and_then(|profile| profile.summary.clone())
                    .unwrap_or_default(),
                String::new(),
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
