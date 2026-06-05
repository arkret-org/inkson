//! Pure space-tree / projection / field-extraction helpers.
//!
//! R28-B extracted this cluster out of `crate::app` (which was a single
//! 12k-line module). Everything here is UI-free: no Dioxus signals, no
//! `rsx!`, no component dependencies — just `serde_json::Value` parsing
//! and [`SpacePreview`] hierarchy math. Keeping it in its own module
//! makes the projection/space-tree logic unit-testable in isolation
//! (see the `tests` submodule below).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::models::{SpacePreview, SpacePreviewKind};

/// A flattened, depth-annotated row in the rendered space tree.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SpaceTreeItem {
    pub(crate) space: SpacePreview,
    pub(crate) depth: usize,
    pub(crate) descendant_count: usize,
}

pub(crate) fn non_empty_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| non_empty_string(value.get(*key)))
}

pub(crate) fn string_array_field(value: &Value, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .filter_map(|key| value.get(*key))
        .flat_map(|field| {
            field
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|item| item.as_str())
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

pub(crate) fn bool_field(value: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter().find_map(|key| value.get(*key)?.as_bool())
}

pub(crate) fn encryption_profile_is_encrypted(profile: &str) -> bool {
    let normalized = profile.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    !matches!(
        normalized.as_str(),
        "" | "none" | "plain" | "plaintext" | "unencrypted" | "disabled" | "off" | "false"
    )
}

pub(crate) fn plaintext_visibility_is_encrypted(visibility: &str) -> bool {
    let normalized = visibility
        .trim()
        .to_ascii_lowercase()
        .replace(['-', ' '], "_");
    matches!(
        normalized.as_str(),
        "encrypted" | "e2ee" | "private_encrypted" | "mls" | "mls_rfc9420"
    )
}

pub(crate) fn plaintext_visibility_value(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| string_field(value, &["default", "mode", "visibility"]))
}

pub(crate) fn realm_projection_is_encrypted(body: &Value) -> bool {
    let summary = body.get("summary").unwrap_or(&Value::Null);
    for container in [
        body,
        summary,
        body.get("object").unwrap_or(&Value::Null),
        body.get("realm").unwrap_or(&Value::Null),
        body.get("metadata").unwrap_or(&Value::Null),
    ] {
        if let Some(encrypted) = bool_field(
            container,
            &["encrypted", "is_encrypted", "e2ee", "end_to_end_encrypted"],
        ) {
            return encrypted;
        }
        if let Some(profile) = string_field(
            container,
            &["encryption_profile", "encryptionProfile", "encryption"],
        ) {
            return encryption_profile_is_encrypted(&profile);
        }
        if let Some(visibility) = container
            .get("plaintext_visibility")
            .and_then(plaintext_visibility_value)
        {
            return plaintext_visibility_is_encrypted(&visibility);
        }
    }

    for event in body
        .get("state")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            body.get("state_after")
                .and_then(|state| state.get("events"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
    {
        let kind = event
            .get("kind")
            .or_else(|| event.get("type"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !kind.contains("realm.create") && !kind.contains("encryption") {
            continue;
        }
        for container in [
            event.get("payload").unwrap_or(&Value::Null),
            event
                .get("payload")
                .and_then(|payload| payload.get("object"))
                .unwrap_or(&Value::Null),
            event.get("content").unwrap_or(&Value::Null),
            event
                .get("content")
                .and_then(|content| content.get("object"))
                .unwrap_or(&Value::Null),
            event.get("object").unwrap_or(&Value::Null),
            event,
        ] {
            if let Some(profile) = string_field(
                container,
                &["encryption_profile", "encryptionProfile", "encryption"],
            ) {
                return encryption_profile_is_encrypted(&profile);
            }
        }
    }

    false
}

pub(crate) fn extract_parent_space_id(space_id: &str, body: &Value) -> Option<String> {
    let summary = body.get("summary").unwrap_or(&Value::Null);
    for container in [
        summary,
        body,
        body.get("hierarchy").unwrap_or(&Value::Null),
        body.get("relationships").unwrap_or(&Value::Null),
    ] {
        if let Some(parent) = string_field(
            container,
            &[
                "parent_space_id",
                "parent_id",
                "parent",
                "space_parent_id",
                "root_space_id",
            ],
        )
        .filter(|parent| parent != space_id && parent.starts_with("ck:space:"))
        {
            return Some(parent);
        }
    }

    body.get("state")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find_map(|event| {
            let kind = event
                .get("kind")
                .or_else(|| event.get("type"))
                .and_then(Value::as_str)?;
            if kind != "ck.realm.parent" {
                return None;
            }
            for container in [
                event.get("payload").unwrap_or(&Value::Null),
                event.get("content").unwrap_or(&Value::Null),
                event,
            ] {
                if let Some(parent) = string_field(
                    container,
                    &["parent_space_id", "parent_id", "parent", "target_parent_id"],
                )
                .filter(|parent| parent != space_id && parent.starts_with("ck:space:"))
                {
                    return Some(parent);
                }
            }
            None
        })
}

pub(crate) fn extract_child_space_ids(space_id: &str, body: &Value) -> Vec<String> {
    let summary = body.get("summary").unwrap_or(&Value::Null);
    let mut children = Vec::new();
    for container in [
        summary,
        body,
        body.get("hierarchy").unwrap_or(&Value::Null),
        body.get("relationships").unwrap_or(&Value::Null),
    ] {
        children.extend(string_array_field(
            container,
            &[
                "child_space_ids",
                "children",
                "child_ids",
                "space_child_ids",
            ],
        ));
    }

    for event in body
        .get("state")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let kind = event
            .get("kind")
            .or_else(|| event.get("type"))
            .and_then(Value::as_str);
        if kind != Some("ck.realm.child") {
            continue;
        }
        for container in [
            event.get("payload").unwrap_or(&Value::Null),
            event.get("content").unwrap_or(&Value::Null),
            event,
        ] {
            if let Some(child) = string_field(
                container,
                &["child_space_id", "child_id", "child", "space_id"],
            ) {
                children.push(child);
            }
        }
    }

    children
        .into_iter()
        .filter(|child| child != space_id && child.starts_with("ck:space:"))
        .collect()
}

pub(crate) fn space_tree_parent_id(space: &SpacePreview) -> Option<&str> {
    space
        .parent_space_id
        .as_deref()
        .filter(|parent| !parent.trim().is_empty())
        .or_else(|| {
            (space.kind == SpacePreviewKind::Space)
                .then(|| space.realm_id.trim())
                .filter(|realm_id| !realm_id.is_empty())
        })
}

pub(crate) fn normalize_space_hierarchy(spaces: &mut [SpacePreview]) {
    let known: BTreeSet<String> = spaces.iter().map(|space| space.space_id.clone()).collect();
    let mut child_map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for space in spaces.iter() {
        if let Some(parent) = space_tree_parent_id(space)
            .filter(|parent| known.contains(*parent) && *parent != space.space_id.as_str())
        {
            child_map
                .entry(parent.to_owned())
                .or_default()
                .insert(space.space_id.clone());
        }

        for child in space
            .child_space_ids
            .iter()
            .filter(|child| known.contains(*child) && *child != &space.space_id)
        {
            child_map
                .entry(space.space_id.clone())
                .or_default()
                .insert(child.clone());
        }
    }

    for space in spaces.iter_mut() {
        space.child_space_ids = child_map
            .remove(&space.space_id)
            .map(|children| children.into_iter().collect())
            .unwrap_or_default();
    }
}

pub(crate) fn descendant_space_ids(spaces: &[SpacePreview], root_space_id: &str) -> Vec<String> {
    if root_space_id.trim().is_empty() {
        return Vec::new();
    }

    let known: BTreeSet<&str> = spaces.iter().map(|space| space.space_id.as_str()).collect();
    let mut child_map: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for space in spaces {
        if let Some(parent) = space_tree_parent_id(space)
            .filter(|parent| known.contains(*parent) && *parent != space.space_id.as_str())
        {
            child_map
                .entry(parent)
                .or_default()
                .push(space.space_id.as_str());
        }
        for child in space
            .child_space_ids
            .iter()
            .map(String::as_str)
            .filter(|child| known.contains(*child) && *child != space.space_id.as_str())
        {
            child_map
                .entry(space.space_id.as_str())
                .or_default()
                .push(child);
        }
    }
    for children in child_map.values_mut() {
        children.sort_unstable();
        children.dedup();
    }
    let mut result = Vec::new();
    let mut visited = BTreeSet::new();
    let mut stack = vec![root_space_id];
    while let Some(space_id) = stack.pop() {
        if !visited.insert(space_id.to_owned()) {
            continue;
        }
        result.push(space_id.to_owned());
        if let Some(children) = child_map.get(space_id) {
            for child in children.iter().rev() {
                stack.push(child);
            }
        }
    }
    result
}

pub(crate) fn space_tree_items(spaces: &[SpacePreview]) -> Vec<SpaceTreeItem> {
    let order: BTreeMap<&str, usize> = spaces
        .iter()
        .enumerate()
        .map(|(idx, space)| (space.space_id.as_str(), idx))
        .collect();
    let known: BTreeSet<&str> = spaces.iter().map(|space| space.space_id.as_str()).collect();
    let by_id: BTreeMap<&str, &SpacePreview> = spaces
        .iter()
        .map(|space| (space.space_id.as_str(), space))
        .collect();
    let mut child_map: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for space in spaces {
        if let Some(parent) = space_tree_parent_id(space)
            .filter(|parent| known.contains(*parent) && *parent != space.space_id.as_str())
        {
            child_map
                .entry(parent)
                .or_default()
                .push(space.space_id.as_str());
        }
        for child in space
            .child_space_ids
            .iter()
            .map(String::as_str)
            .filter(|child| known.contains(*child) && *child != space.space_id.as_str())
        {
            child_map
                .entry(space.space_id.as_str())
                .or_default()
                .push(child);
        }
    }
    for children in child_map.values_mut() {
        children.sort_by_key(|child| order.get(child).copied().unwrap_or(usize::MAX));
        children.dedup();
    }
    let mut roots: Vec<&str> = spaces
        .iter()
        .filter(|space| {
            space_tree_parent_id(space)
                .map(|parent| !known.contains(parent))
                .unwrap_or(true)
        })
        .map(|space| space.space_id.as_str())
        .collect();
    roots.sort_by_key(|id| order.get(id).copied().unwrap_or(usize::MAX));

    fn push_item<'a>(
        id: &'a str,
        depth: usize,
        by_id: &BTreeMap<&'a str, &'a SpacePreview>,
        child_map: &BTreeMap<&'a str, Vec<&'a str>>,
        order: &BTreeMap<&'a str, usize>,
        visited: &mut BTreeSet<String>,
        items: &mut Vec<SpaceTreeItem>,
    ) {
        if !visited.insert(id.to_owned()) {
            return;
        }
        let Some(space) = by_id.get(id).copied() else {
            return;
        };
        items.push(SpaceTreeItem {
            space: space.clone(),
            depth,
            descendant_count: descendant_space_ids(
                &by_id.values().copied().cloned().collect::<Vec<_>>(),
                id,
            )
            .len()
            .saturating_sub(1),
        });
        let mut children: Vec<&str> = child_map.get(id).cloned().unwrap_or_default();
        children.sort_by_key(|child| order.get(child).copied().unwrap_or(usize::MAX));
        for child in children {
            push_item(child, depth + 1, by_id, child_map, order, visited, items);
        }
    }

    let mut items = Vec::new();
    let mut visited = BTreeSet::new();
    for root in roots {
        push_item(
            root,
            0,
            &by_id,
            &child_map,
            &order,
            &mut visited,
            &mut items,
        );
    }
    for space in spaces {
        if !visited.contains(&space.space_id) {
            push_item(
                &space.space_id,
                0,
                &by_id,
                &child_map,
                &order,
                &mut visited,
                &mut items,
            );
        }
    }
    items
}

pub fn space_previews_from_sync_realms(realms: &BTreeMap<String, Value>) -> Vec<SpacePreview> {
    let mut previews: Vec<SpacePreview> = realms
        .iter()
        .filter(|(id, body)| {
            is_realm_or_space_projection_id(id) && !projection_looks_like_flow(body)
        })
        .map(|(id, body)| {
            let summary = body.get("summary").unwrap_or(&Value::Null);
            let title = summary
                .get("title")
                .and_then(Value::as_str)
                .or_else(|| {
                    summary
                        .get("flow")
                        .and_then(|flow| flow.get("title"))
                        .and_then(Value::as_str)
                })
                .unwrap_or(id)
                .to_owned();
            let description = summary
                .get("summary")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let tags = summary
                .get("tags")
                .and_then(Value::as_array)
                .map(|tags| {
                    tags.iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect::<BTreeSet<_>>()
                })
                .unwrap_or_default();
            let kind = projection_preview_kind(id, body);
            let realm_id = match kind {
                SpacePreviewKind::Realm => String::new(),
                SpacePreviewKind::Space => projection_home_realm_id(body).unwrap_or_default(),
            };
            let parent_space_id = extract_parent_space_id(id, body);
            SpacePreview {
                space_id: id.clone(),
                title,
                description,
                tags,
                public: true,
                category: summary
                    .get("category")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                parent_space_id,
                child_space_ids: extract_child_space_ids(id, body),
                kind,
                realm_id,
            }
        })
        .collect();
    normalize_space_hierarchy(&mut previews);
    previews
}

pub(crate) fn is_realm_or_space_projection_id(id: &str) -> bool {
    id.starts_with("ck:realm:") || id.starts_with("ck:space:")
}

pub(crate) fn projection_preview_kind(id: &str, body: &Value) -> SpacePreviewKind {
    // Classify Realm vs Space. Wire signals:
    // - `__kind` (yougen-local tag from optimistic save)
    // - `schema` (server projection — ck.schema.realm.v1 vs ck.schema.space.v1)
    // - parent links on legacy nested Space projections
    // Anything else (legacy) defaults to Realm because
    // pre-M-SPACE-CREATE-1 yougen could only create Realms.
    match body
        .get("__kind")
        .and_then(Value::as_str)
        .or_else(|| body.get("schema").and_then(Value::as_str))
    {
        Some("space") | Some("ck.schema.space.v1") => SpacePreviewKind::Space,
        Some("realm") | Some("ck.schema.realm.v1") => SpacePreviewKind::Realm,
        _ if id.starts_with("ck:space:") && extract_parent_space_id(id, body).is_some() => {
            SpacePreviewKind::Space
        }
        _ => SpacePreviewKind::Realm,
    }
}

pub(crate) fn projection_home_realm_id(body: &Value) -> Option<String> {
    body.get("realm_id")
        .and_then(Value::as_str)
        .or_else(|| {
            body.get("summary")
                .and_then(|summary| summary.get("realm_id"))
                .and_then(Value::as_str)
        })
        .map(str::trim)
        .filter(|realm_id| !realm_id.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn server_set_contains_realm_id(server_set: &BTreeSet<String>, realm_id: &str) -> bool {
    server_set.contains(realm_id)
}

pub fn full_sync_projection_keep_set(
    server_set: &BTreeSet<String>,
    cached: &BTreeMap<String, Value>,
) -> BTreeSet<String> {
    let mut keep = server_set.clone();
    for (id, body) in cached {
        if should_retain_projection_after_full_sync(id, body, server_set) {
            keep.insert(id.clone());
        }
    }
    keep
}

pub fn should_retain_projection_after_full_sync(
    id: &str,
    body: &Value,
    server_set: &BTreeSet<String>,
) -> bool {
    if server_set.contains(id) {
        return true;
    }
    if !id.starts_with("ck:space:") || projection_preview_kind(id, body) != SpacePreviewKind::Space
    {
        return false;
    }
    projection_home_realm_id(body)
        .as_deref()
        .is_some_and(|realm_id| server_set_contains_realm_id(server_set, realm_id))
}

pub(crate) fn projection_looks_like_flow(body: &Value) -> bool {
    // Real-Space projections embed their primary flow under
    // `summary.flow` (with `flow_id` etc. inside it) — so peeking into
    // `summary` to spot a flow is a false positive. Only the body's own
    // top-level `flow_id` / `flow` / `tracks` / `kind`, or a
    // `summary.category` that is itself a flow category, identify a
    // flow-as-space projection.
    body.get("flow_id").is_some()
        || body.get("flow").is_some()
        || body.get("tracks").is_some()
        || matches!(
            body.get("kind").and_then(Value::as_str),
            Some("ck.flow.create" | "discussion" | "flow")
        )
        || matches!(
            body.get("summary")
                .and_then(|summary| summary.get("category"))
                .and_then(Value::as_str),
            Some("discussion" | "flow" | "card" | "announce" | "support" | "activity")
        )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn preview(id: &str, name: &str, parent: Option<&str>) -> SpacePreview {
        SpacePreview {
            space_id: id.to_owned(),
            title: name.to_owned(),
            description: None,
            tags: Default::default(),
            public: true,
            category: None,
            parent_space_id: parent.map(ToOwned::to_owned),
            child_space_ids: Vec::new(),
            kind: SpacePreviewKind::Realm,
            realm_id: String::new(),
        }
    }

    #[test]
    fn space_tree_uses_parent_links_for_nested_menu() {
        let spaces = vec![
            preview("ck:space:root", "Root", None),
            preview("ck:space:child", "Child", Some("ck:space:root")),
            preview("ck:space:deep", "Deep", Some("ck:space:child")),
        ];

        let items = space_tree_items(&spaces);

        assert_eq!(items.len(), 3);
        assert_eq!(items[0].space.space_id, "ck:space:root");
        assert_eq!(items[0].depth, 0);
        assert_eq!(items[0].descendant_count, 2);
        assert_eq!(items[1].space.space_id, "ck:space:child");
        assert_eq!(items[1].depth, 1);
        assert_eq!(items[2].space.space_id, "ck:space:deep");
        assert_eq!(items[2].depth, 2);
    }

    #[test]
    fn descendant_space_ids_walks_full_subtree_and_ignores_unknown_root() {
        let spaces = vec![
            preview("ck:space:root", "Root", None),
            preview("ck:space:child", "Child", Some("ck:space:root")),
            preview("ck:space:deep", "Deep", Some("ck:space:child")),
            preview("ck:space:other", "Other", None),
        ];

        assert_eq!(
            descendant_space_ids(&spaces, "ck:space:root"),
            vec![
                "ck:space:root".to_owned(),
                "ck:space:child".to_owned(),
                "ck:space:deep".to_owned(),
            ]
        );
        // An unknown (but non-blank) root has no descendants, so the walk
        // is just the root id itself.
        assert_eq!(
            descendant_space_ids(&spaces, "ck:space:missing"),
            vec!["ck:space:missing".to_owned()]
        );
        // A blank root short-circuits to an empty walk.
        assert!(descendant_space_ids(&spaces, "   ").is_empty());
    }

    #[test]
    fn normalize_space_hierarchy_rebuilds_children_from_parent_links() {
        let mut spaces = vec![
            preview("ck:space:root", "Root", None),
            preview("ck:space:child", "Child", Some("ck:space:root")),
            preview("ck:space:deep", "Deep", Some("ck:space:child")),
            // Parent points at an unknown id — must be dropped, not panic.
            preview("ck:space:orphan", "Orphan", Some("ck:space:ghost")),
        ];

        normalize_space_hierarchy(&mut spaces);

        let root = spaces
            .iter()
            .find(|s| s.space_id == "ck:space:root")
            .expect("root");
        let child = spaces
            .iter()
            .find(|s| s.space_id == "ck:space:child")
            .expect("child");
        let orphan = spaces
            .iter()
            .find(|s| s.space_id == "ck:space:orphan")
            .expect("orphan");

        assert_eq!(root.child_space_ids, vec!["ck:space:child".to_owned()]);
        assert_eq!(child.child_space_ids, vec!["ck:space:deep".to_owned()]);
        assert!(orphan.child_space_ids.is_empty());
    }

    #[test]
    fn extract_parent_space_id_prefers_summary_and_event_signals() {
        // Summary-level parent link.
        assert_eq!(
            extract_parent_space_id(
                "ck:space:child",
                &json!({"summary": {"parent_space_id": "ck:space:root"}})
            ),
            Some("ck:space:root".to_owned())
        );
        // `ck.realm.parent` state event.
        assert_eq!(
            extract_parent_space_id(
                "ck:space:child",
                &json!({
                    "state": [{
                        "kind": "ck.realm.parent",
                        "payload": {"parent_space_id": "ck:space:root"}
                    }]
                })
            ),
            Some("ck:space:root".to_owned())
        );
        // Self-reference and non-space ids are rejected.
        assert_eq!(
            extract_parent_space_id(
                "ck:space:child",
                &json!({"summary": {"parent_space_id": "ck:space:child"}})
            ),
            None
        );
        assert_eq!(
            extract_parent_space_id(
                "ck:space:child",
                &json!({"summary": {"parent_space_id": "ck:realm:root"}})
            ),
            None
        );
    }

    #[test]
    fn realm_projection_encryption_state_uses_profile_and_visibility() {
        assert!(realm_projection_is_encrypted(&json!({
            "summary": {"encryption_profile": "mls_rfc9420"}
        })));
        assert!(realm_projection_is_encrypted(&json!({
            "plaintext_visibility": {"default": "encrypted"}
        })));
        assert!(!realm_projection_is_encrypted(&json!({
            "encryption_profile": "none"
        })));
        assert!(!realm_projection_is_encrypted(&json!({
            "summary": {"title": "Legacy projection without encryption metadata"}
        })));
    }

    #[test]
    fn is_realm_or_space_projection_id_matches_realm_and_space_prefixes() {
        assert!(is_realm_or_space_projection_id("ck:realm:abc"));
        assert!(is_realm_or_space_projection_id("ck:space:abc"));
        assert!(!is_realm_or_space_projection_id("ck:flow:abc"));
        assert!(!is_realm_or_space_projection_id("realm:abc"));
    }

    #[test]
    fn sync_projection_parses_space_hierarchy_fields() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ck:space:root".to_owned(),
            json!({
                "summary": {
                    "title": "Root",
                    "summary": "Root Space",
                    "child_space_ids": ["ck:space:child"]
                }
            }),
        );
        spaces.insert(
            "ck:space:child".to_owned(),
            json!({
                "summary": {
                    "title": "Child",
                    "summary": "Child Space",
                    "parent_space_id": "ck:space:root"
                }
            }),
        );

        let previews = space_previews_from_sync_realms(&spaces);
        let root = previews
            .iter()
            .find(|space| space.space_id == "ck:space:root")
            .expect("root preview");
        let child = previews
            .iter()
            .find(|space| space.space_id == "ck:space:child")
            .expect("child preview");

        assert_eq!(root.child_space_ids, vec!["ck:space:child".to_owned()]);
        assert_eq!(child.parent_space_id.as_deref(), Some("ck:space:root"));
        assert_eq!(root.kind, SpacePreviewKind::Realm);
        assert_eq!(child.kind, SpacePreviewKind::Space);
    }

    #[test]
    fn sync_projection_marks_schema_space_with_home_realm() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ck:realm:root".to_owned(),
            json!({
                "schema": "ck.schema.realm.v1",
                "summary": {"title": "Root"}
            }),
        );
        spaces.insert(
            "ck:space:child".to_owned(),
            json!({
                "schema": "ck.schema.space.v1",
                "realm_id": "ck:realm:root",
                "summary": {"title": "Child"}
            }),
        );

        let previews = space_previews_from_sync_realms(&spaces);
        let child = previews
            .iter()
            .find(|space| space.space_id == "ck:space:child")
            .expect("child preview");

        assert_eq!(child.kind, SpacePreviewKind::Space);
        assert_eq!(child.realm_id, "ck:realm:root");
        assert_eq!(child.parent_space_id, None);

        let items = space_tree_items(&previews);
        let child_item = items
            .iter()
            .find(|item| item.space.space_id == "ck:space:child")
            .expect("child tree item");
        assert_eq!(child_item.depth, 1);
    }

    #[test]
    fn sync_projection_filters_flow_entries_out_of_space_list() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ck:space:root".to_owned(),
            json!({
                "summary": {
                    "title": "Root",
                    "summary": "Root Space"
                }
            }),
        );
        spaces.insert(
            "ck:flow:discussion".to_owned(),
            json!({
                "flow_id": "ck:flow:discussion",
                "summary": {
                    "title": "Should not be a Space"
                }
            }),
        );
        spaces.insert(
            "ck:space:flow-projection".to_owned(),
            json!({
                "flow_id": "ck:flow:nested",
                "summary": {
                    "title": "Flow projection",
                    "category": "discussion"
                }
            }),
        );

        let previews = space_previews_from_sync_realms(&spaces);

        assert_eq!(previews.len(), 1);
        assert_eq!(previews[0].space_id, "ck:space:root");
    }

    /// Regression: soland inlines the primary flow under `summary.flow`
    /// for legitimate Spaces (so the client can render the room title
    /// without joining a separate fanout). A previous filter treated
    /// any `summary.flow` as a flow-as-space projection and dropped the
    /// Space from the sidebar entirely. Only top-level `flow*`/`tracks`
    /// or a flow-shaped `summary.category` should reject a `ck:space:`.
    #[test]
    fn sync_projection_keeps_real_space_with_inlined_primary_flow() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ck:space:0196419b-0000-7000-8000-000000000000".to_owned(),
            json!({
                "ephemeral": [],
                "flows": [{
                    "flow_id": "ck:flow:0196419b-0000-7000-8000-000000000000",
                    "title": "Cokret Demo Space",
                }],
                "summary": {
                    "category": "collaboration",
                    "title": "Cokret Demo Space",
                    "summary": "Shared demo Space served by soland",
                    "tags": ["demo"],
                    "flow": {
                        "flow_id": "ck:flow:0196419b-0000-7000-8000-000000000000",
                        "title": "Cokret Demo Space",
                        "tracks": { "discussion": { "enabled": true } },
                    },
                },
                "timeline": { "events": [], "limited": false },
                "unread": { "highlight_count": 0, "notification_count": 0 },
            }),
        );

        let previews = space_previews_from_sync_realms(&spaces);

        assert_eq!(previews.len(), 1);
        assert_eq!(
            previews[0].space_id,
            "ck:space:0196419b-0000-7000-8000-000000000000"
        );
        assert_eq!(previews[0].title, "Cokret Demo Space");
        assert_eq!(previews[0].category.as_deref(), Some("collaboration"));
    }

    #[test]
    fn sync_projection_keeps_realm_ids_from_account_subscribe() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ck:realm:019e4cdc-b435-7e52-9ada-39d5ec134729".to_owned(),
            json!({
                "bottom_cells": [],
                "ephemeral": [],
                "flows": [{
                    "flow_id": "ck:flow:019e4cdc-b435-7e52-9ada-39d5ec134729",
                    "kind": "discussion",
                    "title": "Test"
                }],
                "state": [],
                "state_after": {
                    "events": [{
                        "flow_id": "ck:flow:019e4cdc-b435-7e52-9ada-39d5ec134729",
                        "kind": "discussion",
                        "title": "Test"
                    }]
                },
                "summary": {
                    "category": null,
                    "flow": {
                        "flow_id": "ck:flow:019e4cdc-b435-7e52-9ada-39d5ec134729",
                        "kind": "discussion",
                        "title": "Test"
                    },
                    "summary": null,
                    "tags": [],
                    "title": "Test"
                },
                "timeline": {"events": [], "limited": false},
                "unread": {"highlight_count": 0, "notification_count": 0}
            }),
        );

        let previews = space_previews_from_sync_realms(&spaces);

        assert_eq!(previews.len(), 1);
        assert_eq!(
            previews[0].space_id,
            "ck:realm:019e4cdc-b435-7e52-9ada-39d5ec134729"
        );
        assert_eq!(previews[0].title, "Test");
        assert_eq!(previews[0].kind, SpacePreviewKind::Realm);
    }

    #[test]
    fn full_sync_keep_set_preserves_local_space_under_joined_realm() {
        let mut server_set = BTreeSet::new();
        server_set.insert("ck:realm:root".to_owned());

        let mut cached = BTreeMap::new();
        cached.insert(
            "ck:realm:root".to_owned(),
            json!({"summary": {"title": "Root"}}),
        );
        cached.insert(
            "ck:space:child".to_owned(),
            json!({
                "__kind": "space",
                "realm_id": "ck:realm:root",
                "summary": {"title": "Child"}
            }),
        );
        cached.insert(
            "ck:space:stale".to_owned(),
            json!({
                "__kind": "space",
                "realm_id": "ck:realm:missing",
                "summary": {"title": "Stale"}
            }),
        );

        let keep = full_sync_projection_keep_set(&server_set, &cached);

        assert!(keep.contains("ck:realm:root"));
        assert!(keep.contains("ck:space:child"));
        assert!(!keep.contains("ck:space:stale"));
    }

    #[test]
    fn space_previews_from_sync_realms_filters_flow_like_projections() {
        // Replacement for the old `merge_space_previews_filters_flow_like_search_results`
        // test. The sync engine relies on `space_previews_from_sync_realms`
        // (rather than the retired client-side merge filter) to keep
        // flow-like projections out of the sidebar — verify that here.
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ck:flow:discussion".to_owned(),
            json!({
                "flow_id": "ck:flow:discussion",
                "summary": {"title": "Discussion", "category": "discussion"}
            }),
        );
        spaces.insert(
            "ck:space:real".to_owned(),
            json!({"summary": {"title": "Real Space"}}),
        );

        let previews = space_previews_from_sync_realms(&spaces);

        assert_eq!(previews.len(), 1);
        assert_eq!(previews[0].space_id, "ck:space:real");
    }
}
