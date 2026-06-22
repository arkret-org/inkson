use serde_json::Value;

use crate::local_state::LocalStateStore;
use crate::models::RealmTreeNodeKind;

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
    if subject_id.starts_with("ck:realm:") {
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
        Some("space") | Some("ck.schema.space.v1") => RealmTreeNodeKind::Space,
        Some("realm") | Some("ck.schema.realm.v1") => RealmTreeNodeKind::Realm,
        _ => {
            let has_parent = projection_string(
                body,
                &[&["parent_space_id"], &["summary", "parent_space_id"]],
            )
            .is_some();
            if subject_id.starts_with("ck:realm:") && has_parent {
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
    store
        .load()
        .realm_tree_projections
        .get(realm_id)
        .and_then(|proj| {
            proj.get("members").or_else(|| {
                proj.get("summary")
                    .and_then(|summary| summary.get("members"))
            })
        })
        .and_then(|members| members.as_array())
        .map(|members| {
            members
                .iter()
                .filter_map(|member| {
                    member.as_str().map(ToOwned::to_owned).or_else(|| {
                        member
                            .get("actor_id")
                            .or_else(|| member.get("did"))
                            .and_then(|did| did.as_str())
                            .map(ToOwned::to_owned)
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projected_members_reads_roster_actor_id_entries() {
        let realm_id = "ck:realm:test";
        let mut store = LocalStateStore::default();
        store.save_realm_tree_projection(
            realm_id.to_owned(),
            serde_json::json!({
                "members": [
                    {"actor_id": "did:web:alice.example", "membership": "join"},
                    {"actor_id": "did:web:agent.example", "membership": "join"}
                ]
            }),
        );

        assert_eq!(
            projected_members_for_realm(&store, realm_id),
            vec![
                "did:web:alice.example".to_owned(),
                "did:web:agent.example".to_owned()
            ]
        );
    }
}
