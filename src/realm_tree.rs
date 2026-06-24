//! Pure realm-tree / projection / field-extraction helpers.
//!
//! R28-B extracted this cluster out of `crate::app` (which was a single
//! 12k-line module). Everything here is UI-free: no Dioxus signals, no
//! `rsx!`, no component dependencies — just `serde_json::Value` parsing
//! and [`RealmTreeNode`] hierarchy math. Keeping it in its own module
//! makes the projection/realm-tree logic unit-testable in isolation
//! (see the `tests` submodule below).

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use crate::models::{RealmTreeNode, RealmTreeNodeKind};

/// A flattened, depth-annotated row in the rendered Realm tree.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RealmTreeItem {
    pub(crate) node: RealmTreeNode,
    pub(crate) depth: usize,
    pub(crate) descendant_count: usize,
}

/// Caller-supplied fields for an optimistic Realm projection body.
///
/// A named struct rather than a positional argument list because every
/// field here is a `String`/`Vec<String>`, which made the old constructor
/// trivially easy to call with two arguments swapped.
pub(crate) struct RealmProjectionInput {
    pub owner: String,
    pub admins: Vec<String>,
    pub members: Vec<String>,
    pub title: String,
    pub summary: String,
    pub discoverability: String,
    /// Wire value the user picked from `ENCRYPTION_PROFILE_OPTIONS`
    /// (e.g. `mls_rfc9420`). Written through verbatim — the optimistic
    /// body must match exactly what the user chose.
    pub encryption_profile: String,
    pub plaintext_visible_services: Vec<String>,
    /// Recommended content/metadata floor (e.g. `e2ee_required`), or `None`
    /// to omit the floor keys entirely. The caller decides this via
    /// [`crate::api::encryption_profile_uses_recommended_floor`] so the
    /// "which profile recommends which floor" rule stays single-sourced in
    /// `crate::api` instead of being duplicated here.
    pub encryption_floor: Option<String>,
}

/// Caller-supplied fields for an optimistic Space projection body.
pub(crate) struct SpaceProjectionInput {
    pub realm_id: String,
    pub kind: String,
    pub title: String,
    pub summary: String,
    pub parent_space_id: Option<String>,
    pub default_realm_id: Option<String>,
}

/// Optimistic local Realm/Space projection body written to the sidebar
/// store the instant a create succeeds, before the authoritative sync
/// projection lands.
///
/// Internally tagged on `__kind` (the yougen-local Realm/Space marker read
/// by [`projection_tree_node_kind`]). Each variant flattens its own typed body, so a Realm can
/// never carry Space-only fields and a Space can never carry Realm-only fields —
/// the discriminant and the field set can't disagree. The tag lives at
/// `__kind` rather than `kind` because `kind` is already the Space's own
/// space-kind field.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "__kind", rename_all = "snake_case")]
pub(crate) enum OptimisticRealmTreeProjection {
    Realm(Box<RealmProjectionBody>),
    Space(Box<SpaceProjectionBody>),
}

impl OptimisticRealmTreeProjection {
    pub(crate) fn realm(input: RealmProjectionInput) -> Self {
        let RealmProjectionInput {
            owner,
            admins,
            members,
            title,
            summary,
            discoverability,
            encryption_profile,
            plaintext_visible_services,
            encryption_floor,
        } = input;
        // Realm metadata is mirrored at the body top level *and* under
        // `summary` because downstream readers (e.g.
        // `realm_projection_is_encrypted`) probe both containers.
        Self::Realm(Box::new(RealmProjectionBody {
            owner: owner.clone(),
            admins: admins.clone(),
            members: members.clone(),
            encryption_profile: encryption_profile.clone(),
            plaintext_visible_services: plaintext_visible_services.clone(),
            content_encryption_floor: encryption_floor.clone(),
            metadata_encryption_floor: encryption_floor.clone(),
            summary: RealmProjectionSummary {
                title,
                summary,
                category: "collaboration",
                tags: Vec::new(),
                discoverability,
                encryption_profile,
                plaintext_visible_services,
                owner,
                admins,
                members,
                content_encryption_floor: encryption_floor.clone(),
                metadata_encryption_floor: encryption_floor,
            },
            event_feed: ProjectionEventFeed::default(),
        }))
    }

    pub(crate) fn space(input: SpaceProjectionInput) -> Self {
        let SpaceProjectionInput {
            realm_id,
            kind,
            title,
            summary,
            parent_space_id,
            default_realm_id,
        } = input;
        Self::Space(Box::new(SpaceProjectionBody {
            realm_id,
            space_kind: kind.clone(),
            parent_space_id,
            default_realm_id,
            summary: SpaceProjectionSummary {
                title,
                summary,
                space_kind: kind,
            },
            event_feed: ProjectionEventFeed::default(),
        }))
    }

    pub(crate) fn into_value(self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RealmProjectionBody {
    owner: String,
    admins: Vec<String>,
    members: Vec<String>,
    encryption_profile: String,
    plaintext_visible_services: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_encryption_floor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata_encryption_floor: Option<String>,
    summary: RealmProjectionSummary,
    #[serde(rename = "timeline")]
    event_feed: ProjectionEventFeed,
}

#[derive(Clone, Debug, Serialize)]
struct RealmProjectionSummary {
    title: String,
    summary: String,
    category: &'static str,
    tags: Vec<String>,
    discoverability: String,
    encryption_profile: String,
    plaintext_visible_services: Vec<String>,
    owner: String,
    admins: Vec<String>,
    members: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_encryption_floor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata_encryption_floor: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SpaceProjectionBody {
    realm_id: String,
    #[serde(rename = "kind")]
    space_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_space_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_realm_id: Option<String>,
    summary: SpaceProjectionSummary,
    #[serde(rename = "timeline")]
    event_feed: ProjectionEventFeed,
}

#[derive(Clone, Debug, Serialize)]
struct SpaceProjectionSummary {
    title: String,
    summary: String,
    #[serde(rename = "kind")]
    space_kind: String,
}

#[derive(Clone, Debug, Default, Serialize)]
struct ProjectionEventFeed {
    events: Vec<Value>,
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

fn state_event_values(body: &Value) -> impl Iterator<Item = &Value> {
    body.get("state")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            body.get("state")
                .and_then(|state| state.get("events"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
}

fn nested_string_field(value: &Value, parent: &str, keys: &[&str]) -> Option<String> {
    value
        .get(parent)
        .and_then(|nested| string_field(nested, keys))
}

fn explicit_realm_title(body: &Value) -> Option<String> {
    nested_string_field(
        body,
        "summary",
        &["title", "realm_title", "realm_label", "name"],
    )
    .or_else(|| string_field(body, &["title", "realm_title", "realm_label", "name"]))
    .or_else(|| nested_string_field(body, "realm_preview", &["title", "name"]))
    .or_else(|| nested_string_field(body, "preview", &["title", "name"]))
    .or_else(|| nested_string_field(body, "realm", &["title", "name"]))
}

pub(crate) fn projection_title(id: &str, body: &Value) -> String {
    explicit_realm_title(body)
        .or_else(|| {
            body.get("summary")
                .and_then(|summary| nested_string_field(summary, "strand", &["title", "name"]))
        })
        .unwrap_or_else(|| id.to_owned())
}

pub(crate) fn projection_with_title_hint(
    id: &str,
    body: &Value,
    title_hint: Option<&str>,
) -> Value {
    let Some(title) = title_hint.map(str::trim).filter(|title| !title.is_empty()) else {
        return body.clone();
    };
    if explicit_realm_title(body).is_some() {
        return body.clone();
    }

    let mut next = body.clone();
    if !next.is_object() {
        next = serde_json::json!({});
    }
    let Some(object) = next.as_object_mut() else {
        return serde_json::json!({});
    };
    let summary = object
        .entry("summary".to_owned())
        .or_insert_with(|| serde_json::json!({}));
    if !summary.is_object() {
        *summary = serde_json::json!({});
    }
    let Some(summary_object) = summary.as_object_mut() else {
        return next;
    };
    summary_object.insert("title".to_owned(), Value::String(title.to_owned()));
    object
        .entry("__title_hint_source".to_owned())
        .or_insert_with(|| Value::String(format!("invite:{id}")));
    next
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
    matches!(
        normalized.as_str(),
        "encrypted" | "e2ee" | "mls" | "mls_rfc9420"
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
        if let Some(profile) = string_field(container, &["encryption_profile"]) {
            return encryption_profile_is_encrypted(&profile);
        }
        if let Some(visibility) = container
            .get("plaintext_visibility")
            .and_then(plaintext_visibility_value)
        {
            return plaintext_visibility_is_encrypted(&visibility);
        }
    }

    for event in state_event_values(body).chain(
        body.get("state_after")
            .and_then(|state| state.get("events"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten(),
    ) {
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
            if let Some(profile) = string_field(container, &["encryption_profile"]) {
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

    state_event_values(body).find_map(|event| {
        let kind = event
            .get("kind")
            .or_else(|| event.get("type"))
            .and_then(Value::as_str)?;
        if kind != "ck.space.parent" {
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

    for event in state_event_values(body) {
        let kind = event
            .get("kind")
            .or_else(|| event.get("type"))
            .and_then(Value::as_str);
        if kind != Some("ck.space.child") {
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

pub(crate) fn realm_tree_parent_id(node: &RealmTreeNode) -> Option<&str> {
    node.parent_space_id
        .as_deref()
        .filter(|parent| !parent.trim().is_empty())
        .or_else(|| {
            (node.kind == RealmTreeNodeKind::Space)
                .then(|| node.realm_id.trim())
                .filter(|realm_id| !realm_id.is_empty())
        })
}

pub(crate) fn normalize_realm_tree_hierarchy(nodes: &mut [RealmTreeNode]) {
    let known: BTreeSet<String> = nodes.iter().map(|node| node.id.clone()).collect();
    let mut child_map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for node in nodes.iter() {
        if let Some(parent) = realm_tree_parent_id(node)
            .filter(|parent| known.contains(*parent) && *parent != node.id.as_str())
        {
            child_map
                .entry(parent.to_owned())
                .or_default()
                .insert(node.id.clone());
        }

        for child in node
            .child_space_ids
            .iter()
            .filter(|child| known.contains(*child) && *child != &node.id)
        {
            child_map
                .entry(node.id.clone())
                .or_default()
                .insert(child.clone());
        }
    }

    for node in nodes.iter_mut() {
        node.child_space_ids = child_map
            .remove(&node.id)
            .map(|children| children.into_iter().collect())
            .unwrap_or_default();
    }
}

pub(crate) fn descendant_node_ids(nodes: &[RealmTreeNode], root_node_id: &str) -> Vec<String> {
    if root_node_id.trim().is_empty() {
        return Vec::new();
    }

    let known: BTreeSet<&str> = nodes.iter().map(|node| node.id.as_str()).collect();
    let mut child_map: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in nodes {
        if let Some(parent) = realm_tree_parent_id(node)
            .filter(|parent| known.contains(*parent) && *parent != node.id.as_str())
        {
            child_map.entry(parent).or_default().push(node.id.as_str());
        }
        for child in node
            .child_space_ids
            .iter()
            .map(String::as_str)
            .filter(|child| known.contains(*child) && *child != node.id.as_str())
        {
            child_map.entry(node.id.as_str()).or_default().push(child);
        }
    }
    for children in child_map.values_mut() {
        children.sort_unstable();
        children.dedup();
    }
    let mut result = Vec::new();
    let mut visited = BTreeSet::new();
    let mut stack = vec![root_node_id];
    while let Some(node_id) = stack.pop() {
        if !visited.insert(node_id.to_owned()) {
            continue;
        }
        result.push(node_id.to_owned());
        if let Some(children) = child_map.get(node_id) {
            for child in children.iter().rev() {
                stack.push(child);
            }
        }
    }
    result
}

#[cfg(test)]
pub(crate) fn realm_tree_items(nodes: &[RealmTreeNode]) -> Vec<RealmTreeItem> {
    realm_tree_items_with_pinned_realms(nodes, &BTreeSet::new())
}

pub(crate) fn realm_tree_items_with_pinned_realms(
    nodes: &[RealmTreeNode],
    pinned_realm_ids: &BTreeSet<String>,
) -> Vec<RealmTreeItem> {
    let order: BTreeMap<&str, usize> = nodes
        .iter()
        .enumerate()
        .map(|(idx, node)| (node.id.as_str(), idx))
        .collect();
    let known: BTreeSet<&str> = nodes.iter().map(|node| node.id.as_str()).collect();
    let by_id: BTreeMap<&str, &RealmTreeNode> =
        nodes.iter().map(|node| (node.id.as_str(), node)).collect();
    let mut child_map: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in nodes {
        if let Some(parent) = realm_tree_parent_id(node)
            .filter(|parent| known.contains(*parent) && *parent != node.id.as_str())
        {
            child_map.entry(parent).or_default().push(node.id.as_str());
        }
        for child in node
            .child_space_ids
            .iter()
            .map(String::as_str)
            .filter(|child| known.contains(*child) && *child != node.id.as_str())
        {
            child_map.entry(node.id.as_str()).or_default().push(child);
        }
    }
    for children in child_map.values_mut() {
        children.sort_by_key(|child| order.get(child).copied().unwrap_or(usize::MAX));
        children.dedup();
    }
    let mut roots: Vec<&str> = nodes
        .iter()
        .filter(|node| {
            realm_tree_parent_id(node)
                .map(|parent| !known.contains(parent))
                .unwrap_or(true)
        })
        .map(|node| node.id.as_str())
        .collect();
    roots.sort_by_key(|id| {
        let is_pinned_collaboration_realm = by_id.get(id).copied().is_some_and(|node| {
            realm_tree_node_is_collaboration_pin_candidate(node, pinned_realm_ids)
        });
        (
            usize::from(!is_pinned_collaboration_realm),
            order.get(id).copied().unwrap_or(usize::MAX),
        )
    });

    fn push_item<'a>(
        id: &'a str,
        depth: usize,
        by_id: &BTreeMap<&'a str, &'a RealmTreeNode>,
        child_map: &BTreeMap<&'a str, Vec<&'a str>>,
        order: &BTreeMap<&'a str, usize>,
        visited: &mut BTreeSet<String>,
        items: &mut Vec<RealmTreeItem>,
    ) {
        if !visited.insert(id.to_owned()) {
            return;
        }
        let Some(node) = by_id.get(id).copied() else {
            return;
        };
        items.push(RealmTreeItem {
            node: node.clone(),
            depth,
            descendant_count: descendant_node_ids(
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
    for node in nodes {
        if !visited.contains(&node.id) {
            push_item(
                &node.id,
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

fn realm_tree_node_is_collaboration_pin_candidate(
    node: &RealmTreeNode,
    pinned_realm_ids: &BTreeSet<String>,
) -> bool {
    node.kind == RealmTreeNodeKind::Realm
        && pinned_realm_ids.contains(node.id.as_str())
        && !realm_tree_node_looks_like_direct_conversation(node)
}

pub(crate) fn realm_tree_node_looks_like_direct_conversation(node: &RealmTreeNode) -> bool {
    let category = node.category.as_deref().unwrap_or_default();
    direct_conversation_marker(category)
        || node
            .tags
            .iter()
            .any(|tag| direct_conversation_marker(tag.as_str()))
}

fn direct_conversation_marker(value: &str) -> bool {
    let normalized = value
        .trim()
        .to_ascii_lowercase()
        .replace(['-', ' ', '.'], "_");
    matches!(
        normalized.as_str(),
        "dm" | "direct" | "direct_message" | "direct_conversation"
    )
}

pub fn realm_tree_nodes_from_sync_realms(realms: &BTreeMap<String, Value>) -> Vec<RealmTreeNode> {
    let mut previews: Vec<RealmTreeNode> = realms
        .iter()
        .filter(|(id, body)| {
            is_realm_or_space_projection_id(id) && !projection_looks_like_strand(body)
        })
        .map(|(id, body)| {
            let summary = body.get("summary").unwrap_or(&Value::Null);
            let title = projection_title(id, body);
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
            let kind = projection_tree_node_kind(id, body);
            let realm_id = match kind {
                RealmTreeNodeKind::Realm => id.clone(),
                RealmTreeNodeKind::Space => projection_home_realm_id(body).unwrap_or_default(),
            };
            let parent_space_id = extract_parent_space_id(id, body);
            RealmTreeNode {
                id: id.clone(),
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
    normalize_realm_tree_hierarchy(&mut previews);
    previews
}

pub(crate) fn is_realm_or_space_projection_id(id: &str) -> bool {
    id.starts_with("ck:realm:") || id.starts_with("ck:space:")
}

pub(crate) fn projection_tree_node_kind(id: &str, body: &Value) -> RealmTreeNodeKind {
    // Classify Realm vs Space. Wire signals:
    // - `__kind` (yougen-local tag from optimistic save)
    // - `schema` (server projection — ck.schema.realm.v1 vs ck.schema.space.v1)
    // - id prefix (`ck:realm:*` vs `ck:space:*`)
    match body
        .get("__kind")
        .and_then(Value::as_str)
        .or_else(|| body.get("schema").and_then(Value::as_str))
    {
        Some("space") | Some("ck.schema.space.v1") => RealmTreeNodeKind::Space,
        Some("realm") | Some("ck.schema.realm.v1") => RealmTreeNodeKind::Realm,
        _ if id.starts_with("ck:space:") => RealmTreeNodeKind::Space,
        _ if id.starts_with("ck:realm:") => RealmTreeNodeKind::Realm,
        _ => RealmTreeNodeKind::Realm,
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
    if !id.starts_with("ck:space:")
        || projection_tree_node_kind(id, body) != RealmTreeNodeKind::Space
    {
        return false;
    }
    projection_home_realm_id(body)
        .as_deref()
        .is_some_and(|realm_id| server_set_contains_realm_id(server_set, realm_id))
}

pub(crate) fn projection_looks_like_strand(body: &Value) -> bool {
    // Real Space projections embed their primary strand under
    // `summary.strand` (with `strand_id` etc. inside it) — so peeking into
    // `summary` to spot a strand is a false positive. Only the body's own
    // top-level `strand_id` / `strand` / `tracks` / `kind`, or a
    // `summary.category` that is itself a strand category, identify a
    // strand-as-node projection.
    body.get("strand_id").is_some()
        || body.get("strand").is_some()
        || body.get("tracks").is_some()
        || matches!(
            body.get("kind").and_then(Value::as_str),
            Some("ck.strand.create" | "discussion" | "strand")
        )
        || matches!(
            body.get("summary")
                .and_then(|summary| summary.get("category"))
                .and_then(Value::as_str),
            Some("discussion" | "strand" | "card" | "announce" | "support" | "activity")
        )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn preview(id: &str, name: &str, parent: Option<&str>) -> RealmTreeNode {
        let kind = if id.starts_with("ck:space:") {
            RealmTreeNodeKind::Space
        } else {
            RealmTreeNodeKind::Realm
        };
        RealmTreeNode {
            id: id.to_owned(),
            title: name.to_owned(),
            description: None,
            tags: Default::default(),
            public: true,
            category: None,
            parent_space_id: parent.map(ToOwned::to_owned),
            child_space_ids: Vec::new(),
            kind,
            realm_id: if kind == RealmTreeNodeKind::Realm {
                id.to_owned()
            } else {
                "ck:realm:root".to_owned()
            },
        }
    }

    #[test]
    fn sync_projection_title_accepts_invite_title_aliases() {
        let nodes = realm_tree_nodes_from_sync_realms(&BTreeMap::from([(
            "ck:realm:01904100-0000-7000-8000-000000000002".to_owned(),
            json!({
                "realm_title": "Launch Planning",
                "summary": {}
            }),
        )]));

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].title, "Launch Planning");
    }

    #[test]
    fn projection_title_hint_fills_missing_summary_title() {
        let id = "ck:realm:01904100-0000-7000-8000-000000000003";
        let body = json!({
            "summary": {
                "strand": {"title": "General strand"}
            }
        });

        let patched = projection_with_title_hint(id, &body, Some("Invited Realm"));
        let nodes = realm_tree_nodes_from_sync_realms(&BTreeMap::from([(id.to_owned(), patched)]));

        assert_eq!(nodes[0].title, "Invited Realm");
    }

    #[test]
    fn projection_title_hint_does_not_override_server_title() {
        let id = "ck:realm:01904100-0000-7000-8000-000000000004";
        let body = json!({
            "summary": {"title": "Server Realm"}
        });

        let patched = projection_with_title_hint(id, &body, Some("Invite Label"));
        let nodes = realm_tree_nodes_from_sync_realms(&BTreeMap::from([(id.to_owned(), patched)]));

        assert_eq!(nodes[0].title, "Server Realm");
    }

    #[test]
    fn optimistic_realm_projection_serializes_typed_encryption_floor() {
        let body = OptimisticRealmTreeProjection::realm(RealmProjectionInput {
            owner: "did:web:alice.example".to_owned(),
            admins: vec!["did:web:alice.example".to_owned()],
            members: vec![
                "did:web:alice.example".to_owned(),
                "did:web:bob.example".to_owned(),
            ],
            title: "Launch".to_owned(),
            summary: "Launch planning".to_owned(),
            discoverability: "restricted".to_owned(),
            encryption_profile: "mls_rfc9420".to_owned(),
            plaintext_visible_services: vec!["directory".to_owned()],
            encryption_floor: Some("e2ee_required".to_owned()),
        })
        .into_value();

        assert_eq!(body["__kind"], "realm");
        assert_eq!(body["encryption_profile"], "mls_rfc9420");
        assert_eq!(body["content_encryption_floor"], "e2ee_required");
        assert_eq!(body["metadata_encryption_floor"], "e2ee_required");
        assert_eq!(body["summary"]["content_encryption_floor"], "e2ee_required");
        assert_eq!(
            body["summary"]["metadata_encryption_floor"],
            "e2ee_required"
        );
        assert_eq!(body["timeline"]["events"], json!([]));
    }

    #[test]
    fn optimistic_realm_projection_omits_plaintext_floor() {
        let body = OptimisticRealmTreeProjection::realm(RealmProjectionInput {
            owner: "did:web:alice.example".to_owned(),
            admins: vec!["did:web:alice.example".to_owned()],
            members: vec!["did:web:alice.example".to_owned()],
            title: "Public".to_owned(),
            summary: String::new(),
            discoverability: "public".to_owned(),
            encryption_profile: "none".to_owned(),
            plaintext_visible_services: Vec::new(),
            encryption_floor: None,
        })
        .into_value();

        assert_eq!(body["encryption_profile"], "none");
        assert!(body.get("content_encryption_floor").is_none());
        assert!(body.get("metadata_encryption_floor").is_none());
        assert!(body["summary"].get("content_encryption_floor").is_none());
        assert!(body["summary"].get("metadata_encryption_floor").is_none());
    }

    #[test]
    fn optimistic_space_projection_serializes_optional_parent_links() {
        let body = OptimisticRealmTreeProjection::space(SpaceProjectionInput {
            realm_id: "ck:realm:root".to_owned(),
            kind: "collection".to_owned(),
            title: "Specs".to_owned(),
            summary: "Spec work".to_owned(),
            parent_space_id: Some("ck:space:parent".to_owned()),
            default_realm_id: Some("ck:realm:default".to_owned()),
        })
        .into_value();

        assert_eq!(body["__kind"], "space");
        assert_eq!(body["realm_id"], "ck:realm:root");
        assert_eq!(body["kind"], "collection");
        assert_eq!(body["parent_space_id"], "ck:space:parent");
        assert_eq!(body["default_realm_id"], "ck:realm:default");
        assert_eq!(body["summary"]["kind"], "collection");
        assert_eq!(body["timeline"]["events"], json!([]));
    }

    #[test]
    fn realm_tree_uses_parent_links_for_nested_spaces() {
        let spaces = vec![
            preview("ck:realm:root", "Root", None),
            preview("ck:space:child", "Child", None),
            preview("ck:space:deep", "Deep", Some("ck:space:child")),
        ];

        let items = realm_tree_items(&spaces);

        assert_eq!(items.len(), 3);
        assert_eq!(items[0].node.id, "ck:realm:root");
        assert_eq!(items[0].depth, 0);
        assert_eq!(items[0].descendant_count, 2);
        assert_eq!(items[1].node.id, "ck:space:child");
        assert_eq!(items[1].depth, 1);
        assert_eq!(items[2].node.id, "ck:space:deep");
        assert_eq!(items[2].depth, 2);
    }

    #[test]
    fn pinned_realms_sort_before_unpinned_roots_without_splitting_subtrees() {
        let mut a_child = preview("ck:space:a-child", "A child", None);
        a_child.realm_id = "ck:realm:a".to_owned();
        let mut b_child = preview("ck:space:b-child", "B child", None);
        b_child.realm_id = "ck:realm:b".to_owned();
        let nodes = vec![
            preview("ck:realm:a", "A", None),
            a_child,
            preview("ck:realm:b", "B", None),
            b_child,
        ];
        let pinned = BTreeSet::from(["ck:realm:b".to_owned()]);

        let items = realm_tree_items_with_pinned_realms(&nodes, &pinned);
        let ids: Vec<_> = items
            .iter()
            .map(|item| (item.node.id.as_str(), item.depth))
            .collect();

        assert_eq!(
            ids,
            vec![
                ("ck:realm:b", 0),
                ("ck:space:b-child", 1),
                ("ck:realm:a", 0),
                ("ck:space:a-child", 1),
            ]
        );
    }

    #[test]
    fn pinned_sort_does_not_promote_direct_conversation_realms() {
        let mut dm = preview("ck:realm:dm", "DM", None);
        dm.category = Some("direct_conversation".to_owned());
        let nodes = vec![
            dm,
            preview("ck:realm:work", "Work", None),
            preview("ck:realm:later", "Later", None),
        ];
        let pinned = BTreeSet::from(["ck:realm:dm".to_owned(), "ck:realm:later".to_owned()]);

        let items = realm_tree_items_with_pinned_realms(&nodes, &pinned);
        let ids: Vec<_> = items.iter().map(|item| item.node.id.as_str()).collect();

        assert_eq!(ids, vec!["ck:realm:later", "ck:realm:dm", "ck:realm:work"]);
    }

    #[test]
    fn descendant_node_ids_walks_full_subtree_and_ignores_unknown_root() {
        let spaces = vec![
            preview("ck:realm:root", "Root", None),
            preview("ck:space:child", "Child", None),
            preview("ck:space:deep", "Deep", Some("ck:space:child")),
            RealmTreeNode {
                realm_id: "ck:realm:other".to_owned(),
                ..preview("ck:realm:other", "Other", None)
            },
        ];

        assert_eq!(
            descendant_node_ids(&spaces, "ck:realm:root"),
            vec![
                "ck:realm:root".to_owned(),
                "ck:space:child".to_owned(),
                "ck:space:deep".to_owned(),
            ]
        );
        // An unknown (but non-blank) root has no descendants, so the walk
        // is just the root id itself.
        assert_eq!(
            descendant_node_ids(&spaces, "ck:space:missing"),
            vec!["ck:space:missing".to_owned()]
        );
        // A blank root short-circuits to an empty walk.
        assert!(descendant_node_ids(&spaces, "   ").is_empty());
    }

    #[test]
    fn normalize_realm_tree_hierarchy_rebuilds_children_from_parent_links() {
        let mut spaces = vec![
            preview("ck:realm:root", "Root", None),
            preview("ck:space:child", "Child", None),
            preview("ck:space:deep", "Deep", Some("ck:space:child")),
            // Parent points at an unknown id — must be dropped, not panic.
            preview("ck:space:orphan", "Orphan", Some("ck:space:ghost")),
        ];

        normalize_realm_tree_hierarchy(&mut spaces);

        let root = spaces
            .iter()
            .find(|s| s.id == "ck:realm:root")
            .expect("root");
        let child = spaces
            .iter()
            .find(|s| s.id == "ck:space:child")
            .expect("child");
        let orphan = spaces
            .iter()
            .find(|s| s.id == "ck:space:orphan")
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
        // `ck.space.parent` state event.
        assert_eq!(
            extract_parent_space_id(
                "ck:space:child",
                &json!({
                    "state": [{
                        "kind": "ck.space.parent",
                        "payload": {"parent_space_id": "ck:space:root"}
                    }]
                })
            ),
            Some("ck:space:root".to_owned())
        );
        // Self-reference and non-Space ids are rejected.
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
                &json!({"summary": {"parent_space_id": "ck:strand:root"}})
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
            "summary": {"title": "Projection without encryption metadata"}
        })));
    }

    #[test]
    fn is_realm_or_space_projection_id_matches_realm_and_space_prefixes() {
        assert!(is_realm_or_space_projection_id("ck:realm:abc"));
        assert!(is_realm_or_space_projection_id("ck:space:abc"));
        assert!(!is_realm_or_space_projection_id("ck:strand:abc"));
        assert!(!is_realm_or_space_projection_id("realm:abc"));
    }

    #[test]
    fn sync_projection_parses_realm_and_space_hierarchy_fields() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ck:realm:root".to_owned(),
            json!({
                "schema": "ck.schema.realm.v1",
                "summary": {
                    "title": "Root",
                    "summary": "Root Realm"
                }
            }),
        );
        spaces.insert(
            "ck:space:child".to_owned(),
            json!({
                "schema": "ck.schema.space.v1",
                "realm_id": "ck:realm:root",
                "summary": {
                    "title": "Child",
                    "summary": "Child Space"
                }
            }),
        );

        let previews = realm_tree_nodes_from_sync_realms(&spaces);
        let root = previews
            .iter()
            .find(|node| node.id == "ck:realm:root")
            .expect("root preview");
        let child = previews
            .iter()
            .find(|node| node.id == "ck:space:child")
            .expect("child preview");

        assert_eq!(root.child_space_ids, vec!["ck:space:child".to_owned()]);
        assert_eq!(child.parent_space_id, None);
        assert_eq!(root.kind, RealmTreeNodeKind::Realm);
        assert_eq!(child.kind, RealmTreeNodeKind::Space);
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

        let previews = realm_tree_nodes_from_sync_realms(&spaces);
        let child = previews
            .iter()
            .find(|node| node.id == "ck:space:child")
            .expect("child preview");

        assert_eq!(child.kind, RealmTreeNodeKind::Space);
        assert_eq!(child.realm_id, "ck:realm:root");
        assert_eq!(child.parent_space_id, None);

        let items = realm_tree_items(&previews);
        let child_item = items
            .iter()
            .find(|item| item.node.id == "ck:space:child")
            .expect("child tree item");
        assert_eq!(child_item.depth, 1);
    }

    #[test]
    fn sync_projection_filters_strand_entries_out_of_realm_tree() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ck:realm:root".to_owned(),
            json!({
                "schema": "ck.schema.realm.v1",
                "summary": {
                    "title": "Root",
                    "summary": "Root Realm"
                }
            }),
        );
        spaces.insert(
            "ck:strand:discussion".to_owned(),
            json!({
                "strand_id": "ck:strand:discussion",
                "summary": {
                    "title": "Should not be a node"
                }
            }),
        );
        spaces.insert(
            "ck:space:strand-projection".to_owned(),
            json!({
                "strand_id": "ck:strand:nested",
                "summary": {
                    "title": "Strand projection",
                    "category": "discussion"
                }
            }),
        );

        let previews = realm_tree_nodes_from_sync_realms(&spaces);

        assert_eq!(previews.len(), 1);
        assert_eq!(previews[0].id, "ck:realm:root");
    }

    /// Regression: soland inlines the primary strand under `summary.strand`
    /// for legitimate Spaces (so the client can render the room title
    /// without joining a separate fanout). A previous filter treated
    /// any `summary.strand` as a strand-as-tree-node projection and dropped the
    /// Space from the sidebar entirely. Only top-level `strand*`/`tracks`
    /// or a strand-shaped `summary.category` should reject a `ck:space:`.
    #[test]
    fn sync_projection_keeps_real_space_with_inlined_primary_strand() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ck:space:0196419b-0000-7000-8000-000000000000".to_owned(),
            json!({
                "ephemeral": [],
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000001",
                "strands": [{
                    "strand_id": "ck:strand:0196419b-0000-7000-8000-000000000000",
                    "title": "Cokret Demo Realm",
                }],
                "summary": {
                    "category": "collaboration",
                    "title": "Cokret Demo Realm",
                    "summary": "Shared demo Space served by soland",
                    "tags": ["demo"],
                    "strand": {
                        "strand_id": "ck:strand:0196419b-0000-7000-8000-000000000000",
                        "title": "Cokret Demo Realm",
                        "tracks": { "discussion": { "enabled": true } },
                    },
                },
                "timeline": { "events": [], "limited": false },
                "unread": { "highlight_count": 0, "notification_count": 0 },
            }),
        );

        let previews = realm_tree_nodes_from_sync_realms(&spaces);

        assert_eq!(previews.len(), 1);
        assert_eq!(
            previews[0].id,
            "ck:space:0196419b-0000-7000-8000-000000000000"
        );
        assert_eq!(previews[0].title, "Cokret Demo Realm");
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
                "strands": [{
                    "strand_id": "ck:strand:019e4cdc-b435-7e52-9ada-39d5ec134729",
                    "kind": "discussion",
                    "title": "Test"
                }],
                "state": [],
                "state_after": {
                    "events": [{
                        "strand_id": "ck:strand:019e4cdc-b435-7e52-9ada-39d5ec134729",
                        "kind": "discussion",
                        "title": "Test"
                    }]
                },
                "summary": {
                    "category": null,
                    "strand": {
                        "strand_id": "ck:strand:019e4cdc-b435-7e52-9ada-39d5ec134729",
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

        let previews = realm_tree_nodes_from_sync_realms(&spaces);

        assert_eq!(previews.len(), 1);
        assert_eq!(
            previews[0].id,
            "ck:realm:019e4cdc-b435-7e52-9ada-39d5ec134729"
        );
        assert_eq!(previews[0].title, "Test");
        assert_eq!(previews[0].kind, RealmTreeNodeKind::Realm);
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
    fn realm_tree_nodes_from_sync_realms_filters_strand_like_projections() {
        // The sync engine relies on `realm_tree_nodes_from_sync_realms`
        // (rather than the retired client-side merge filter) to keep
        // strand-like projections out of the sidebar — verify that here.
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ck:strand:discussion".to_owned(),
            json!({
                "strand_id": "ck:strand:discussion",
                "summary": {"title": "Discussion", "category": "discussion"}
            }),
        );
        spaces.insert(
            "ck:space:real".to_owned(),
            json!({
                "schema": "ck.schema.space.v1",
                "realm_id": "ck:realm:root",
                "summary": {"title": "Real Space"}
            }),
        );

        let previews = realm_tree_nodes_from_sync_realms(&spaces);

        assert_eq!(previews.len(), 1);
        assert_eq!(previews[0].id, "ck:space:real");
    }
}
