use std::collections::BTreeSet;

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
        Some("space") | Some("ak.schema.space.v1") => RealmTreeNodeKind::Space,
        Some("realm") | Some("ak.schema.realm.v1") => RealmTreeNodeKind::Realm,
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

fn push_projected_member_id(id: &str, out: &mut Vec<String>, seen: &mut BTreeSet<String>) {
    let id = id.trim();
    if id.is_empty() || !seen.insert(id.to_owned()) {
        return;
    }
    out.push(id.to_owned());
}

fn collect_projected_member_ids(
    value: Option<&Value>,
    out: &mut Vec<String>,
    seen: &mut BTreeSet<String>,
) {
    let Some(value) = value else { return };
    match value {
        Value::String(id) => push_projected_member_id(id, out, seen),
        Value::Array(items) => {
            for item in items {
                collect_projected_member_ids(Some(item), out, seen);
            }
        }
        Value::Object(map) => {
            if let Some(id) = map
                .get("actor_id")
                .or_else(|| map.get("did"))
                .and_then(Value::as_str)
            {
                push_projected_member_id(id, out, seen);
                return;
            }
            for (key, child) in map {
                if key.starts_with("did:") {
                    push_projected_member_id(key, out, seen);
                }
                collect_projected_member_ids(Some(child), out, seen);
            }
        }
        _ => {}
    }
}

pub(crate) fn projected_members_for_realm(store: &LocalStateStore, realm_id: &str) -> Vec<String> {
    let state = store.load();
    let Some(projection) = state.realm_tree_projections.get(realm_id) else {
        return Vec::new();
    };
    let sources = [Some(projection), projection.get("summary")];
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
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
        for source in sources.into_iter().flatten() {
            collect_projected_member_ids(source.get(key), &mut out, &mut seen);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projected_members_reads_roster_actor_id_entries() {
        let realm_id = "ak:realm:test";
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

    #[test]
    fn projected_members_reads_owner_and_admin_projection_sources() {
        let realm_id = "ak:realm:test";
        let mut store = LocalStateStore::default();
        store.save_realm_tree_projection(
            realm_id.to_owned(),
            serde_json::json!({
                "owner": "did:web:owner.example",
                "admins": [{"actor_id": "did:web:admin.example", "membership": "join"}],
                "summary": {
                    "members": [{"actor_id": "did:web:member.example", "membership": "join"}],
                    "created_by": "did:web:owner.example"
                }
            }),
        );

        assert_eq!(
            projected_members_for_realm(&store, realm_id),
            vec![
                "did:web:member.example".to_owned(),
                "did:web:admin.example".to_owned(),
                "did:web:owner.example".to_owned(),
            ]
        );
    }
}
