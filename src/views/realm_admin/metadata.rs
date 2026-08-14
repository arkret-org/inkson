use arkret_wire::SchemaId;
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

fn projection_string(body: &Value, paths: &[&[&str]]) -> Option<String> {
    for path in paths {
        let mut current = body;
        let mut found = true;
        for segment in *path {
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
        if let Some(value) = current.as_str().map(str::trim).filter(|s| !s.is_empty()) {
            return Some(value.to_owned());
        }
    }
    None
}

fn projection_kind_for_admin(subject_id: &str, body: Option<&Value>) -> RealmTreeNodeKind {
    if subject_id.starts_with("ak:realm:") {
        return RealmTreeNodeKind::Realm;
    }
    let Some(body) = body else {
        return RealmTreeNodeKind::Realm;
    };
    match body
        .get("__kind")
        .and_then(Value::as_str)
        .or_else(|| body.get("schema").and_then(Value::as_str))
    {
        Some("space") | Some(SchemaId::SPACE_V1) => RealmTreeNodeKind::Space,
        Some("realm") | Some(SchemaId::REALM_V1) => RealmTreeNodeKind::Realm,
        _ => {
            let has_parent = projection_string(
                body,
                &[&["parent_space_id"], &["summary", "parent_space_id"]],
            )
            .is_some();
            if subject_id.starts_with("ak:realm:") && has_parent {
                RealmTreeNodeKind::Space
            } else {
                RealmTreeNodeKind::Realm
            }
        }
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
    body.and_then(|body| projection_string(body, &[&["realm_id"], &["summary", "realm_id"]]))
        .unwrap_or_else(|| crate::operation::trim_realm_id(subject_id))
}

pub(crate) fn metadata_subject_for(store: &LocalStateStore, subject_id: &str) -> MetadataSubject {
    let state = store.load();
    let body = state.realm_tree_projections.get(subject_id);
    let kind = projection_kind_for_admin(subject_id, body);
    let title = body
        .and_then(|body| {
            projection_string(
                body,
                &[&["summary", "title"], &["title"], &["object", "title"]],
            )
        })
        .unwrap_or_default();
    let summary = body
        .and_then(|body| {
            projection_string(
                body,
                &[
                    &["summary", "summary"],
                    &["summary"],
                    &["description"],
                    &["object", "summary"],
                    &["object", "description"],
                ],
            )
        })
        .unwrap_or_default();
    let avatar_blob_ref = body
        .and_then(|body| {
            projection_string(
                body,
                &[
                    &["summary", "avatar_blob_ref"],
                    &["avatar_blob_ref"],
                    &["object", "avatar_blob_ref"],
                ],
            )
        })
        .unwrap_or_default();
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
        .map(|row| row.actor_id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projected_members_reads_roster_actor_id_entries() {
        let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
        let mut store = LocalStateStore::default();
        store.save_realm_tree_projection(
            realm_id.to_owned(),
            serde_json::json!({
                "members": [
                    {"actor_id": "ak:did_core:web:alice.example", "membership": "join"},
                    {"actor_id": "ak:did_core:web:agent.example", "membership": "join"}
                ]
            }),
        );

        assert_eq!(
            projected_members_for_realm(&store, realm_id),
            vec![
                "ak:did_core:web:agent.example".to_owned(),
                "ak:did_core:web:alice.example".to_owned()
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
                "admins": [{"actor_id": "ak:did_core:web:admin.example", "membership": "join"}],
                "summary": {
                    "members": [{"actor_id": "ak:did_core:web:member.example", "membership": "join"}],
                    "created_by": "did:web:owner.example"
                }
            }),
        );

        assert!(projected_members_for_realm(&store, realm_id).is_empty());
    }
}
