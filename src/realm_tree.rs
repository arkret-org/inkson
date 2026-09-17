//! Pure realm-tree / projection / field-extraction helpers.
//!
//! R28-B extracted this cluster out of `crate::app` (which was a single
//! 12k-line module). Everything here is UI-free: no Dioxus signals, no
//! `rsx!`, no component dependencies — just `serde_json::Value` parsing
//! and [`RealmTreeNode`] hierarchy math. Keeping it in its own module
//! makes the projection/realm-tree logic unit-testable in isolation
//! (see the `tests` submodule below).

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::{SchemaId, event_kind_str};
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
    /// Effective Realm content capability selected at creation time. The
    /// optimistic projection is authoritative for local writes until account
    /// sync replaces it, so omitting this field would silently downgrade
    /// shared-history content to the `mls_rfc9420` scheme.
    pub content_scheme: String,
    /// Initial history access selected at creation time.
    pub history_access: String,
    pub plaintext_visible_services: Vec<String>,
    pub collaboration_role: Option<arkret_sdk::CollaborationRealmRole>,
    /// Recommended content/metadata floor (e.g. `e2ee_required`), or `None`
    /// to omit the floor keys entirely. The caller decides this via
    /// [`crate::event_builders::encryption_profile_uses_recommended_floor`] so the
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
}

/// Optimistic local Realm/Space projection body written to the sidebar
/// store the instant a create succeeds, before the authoritative sync
/// projection lands.
///
/// Internally tagged on `__kind` (the inkson-local Realm/Space marker read
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
            content_scheme,
            history_access,
            plaintext_visible_services,
            collaboration_role,
            encryption_floor,
        } = input;
        // Realm metadata is mirrored at the body top level *and* under
        // `summary` because the two have different readers, and neither set
        // covers the other:
        //
        //   * top level only — `garth::strand_projection_security_state` walks `[], object, strand,
        //     body, fields, scope, …` and never descends into `summary`, and
        //     `state::realm_tree_snapshot` reads `projection["member_roster_entries"]` flat;
        //   * `summary` first — `explicit_realm_title` and `extract_parent_space_id` /
        //     `extract_child_space_ids` prefer it, because that is where the *server* sync
        //     projection puts these fields. Matching that shape is the point of an optimistic body:
        //     the authoritative projection replaces this value in place, and the same extractors
        //     must keep working across the swap.
        //
        // This is unrelated to the "MUST NOT double-write" rule in
        // `event_builders::assert_realm_candidate_matches_closed_schema`. That
        // one governs the authored `ak.realm.create` `payload.object`, which is
        // validated against the closed `ak.schema.realm_genesis.v1` and rejects
        // unknown members. Nothing here is authored or sent: this body is an
        // inkson-local projection tagged `__kind`, never a wire payload.
        Self::Realm(Box::new(RealmProjectionBody {
            owner: owner.clone(),
            admins: admins.clone(),
            members: members.clone(),
            encryption_profile: encryption_profile.clone(),
            content_scheme: content_scheme.clone(),
            history_access: history_access.clone(),
            plaintext_visible_services: plaintext_visible_services.clone(),
            collaboration_role,
            content_encryption_floor: encryption_floor.clone(),
            metadata_encryption_floor: encryption_floor.clone(),
            summary: RealmProjectionSummary {
                title,
                summary,
                category: "collaboration",
                tags: Vec::new(),
                discoverability,
                encryption_profile,
                content_scheme,
                history_access,
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
        } = input;
        Self::Space(Box::new(SpaceProjectionBody {
            realm_id,
            space_kind: kind.clone(),
            parent_space_id,
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
    content_scheme: String,
    history_access: String,
    plaintext_visible_services: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    collaboration_role: Option<arkret_sdk::CollaborationRealmRole>,
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
    content_scheme: String,
    history_access: String,
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

/// First non-empty string among `keys`, read straight off a projection body.
///
/// The local Realm projection is a heterogeneous JSON view assembled from the
/// account subscription; this is the one accessor every reader goes through so
/// a key spelling cannot drift between call sites.
pub(crate) fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    let object = value.as_object()?;
    keys.iter().find_map(|key| {
        object
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|found| !found.is_empty())
            .map(ToOwned::to_owned)
    })
}

/// The closed `ak.schema.realm_genesis.v1` object carried by the Realm's own
/// `ak.realm.create` Event at position 0 of its Realm stream.
///
/// It is the only authority for the create-locked identity core
/// (`realm-and-space.md` §2.5). The sync layer installs it verbatim under
/// `genesis` when it reads that first commit; nothing here reconstructs it from
/// later Events, because re-deriving a current value from arrival order is
/// exactly what the authority-commit model removed.
pub(crate) fn realm_projection_genesis_value(body: &Value) -> Option<&Value> {
    body.as_object()?.get("genesis").filter(|genesis| {
        genesis
            .get("schema")
            .and_then(Value::as_str)
            .is_some_and(|schema| schema == arkret_wire::SchemaId::REALM_GENESIS_V1)
    })
}

/// Return the create-locked control purpose only when the accepted Realm
/// genesis carries both normative PCR markers. A bare `purpose` string or a
/// profile ref by itself is not enough to classify a Realm as control-plane.
pub(crate) fn realm_projection_control_purpose(body: &Value) -> Option<&str> {
    let genesis = realm_projection_genesis_value(body)?;
    let purpose = genesis.get("purpose").and_then(Value::as_str)?;
    let is_control_purpose = matches!(purpose, "principal_control" | "agent_control");
    let has_control_profile = genesis
        .get("schema_refs")
        .and_then(Value::as_array)
        .is_some_and(|refs| {
            refs.iter().any(|value| {
                value.as_str() == Some(arkret_wire::ProfileId::PRINCIPAL_CONTROL_REALM_V1)
            })
        });
    (is_control_purpose && has_control_profile).then_some(purpose)
}

pub(crate) fn realm_projection_is_principal_control(body: &Value) -> bool {
    realm_projection_control_purpose(body).is_some()
}

/// The local creator's pre-Genesis content-scheme intent, if one was authored
/// on this device.
///
/// This is **not** the accepted binding. `realm-and-space.md` §2.3 and the 1920
/// ruling make `content_scheme` a create-time local intent that only becomes
/// the group's protocol-immutable value at `GenesisAccepted`; the accepted
/// value is published as `ak.component.mls.epoch.v1` and is read through
/// `LocalStateStore::accepted_mls_epoch_binding`. The single legitimate
/// consumer here is the pre-Genesis `proposed_group_genesis_binding` branch,
/// which has to resubmit the exact proposal the interrupted creator
/// transaction carried. Sending, decrypting, Signal and history recovery must
/// never read it.
pub(crate) fn realm_projection_pre_genesis_content_scheme(body: &Value) -> Option<String> {
    let null = Value::Null;
    for container in [
        body,
        body.get("summary").unwrap_or(&null),
        body.get("object").unwrap_or(&null),
        body.get("realm").unwrap_or(&null),
        body.get("metadata").unwrap_or(&null),
    ] {
        if let Some(scheme) = string_field(container, &["content_scheme"]) {
            return Some(scheme);
        }
    }

    None
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
    .or_else(|| {
        body.pointer("/state_at_window_start/realm_metadata")
            .and_then(|metadata| string_field(metadata, &["title", "name"]))
    })
}

fn explicit_realm_summary(body: &Value) -> Option<String> {
    nested_string_field(body, "summary", &["summary", "description"])
        .or_else(|| string_field(body, &["realm_summary", "description"]))
        .or_else(|| {
            body.pointer("/state_at_window_start/realm_metadata")
                .and_then(|metadata| string_field(metadata, &["summary", "description"]))
        })
}

pub(crate) fn projection_title(id: &str, body: &Value) -> String {
    explicit_realm_title(body)
        .or_else(|| {
            body.get("summary")
                .and_then(|summary| nested_string_field(summary, "strand", &["title", "name"]))
        })
        .unwrap_or_else(|| id.to_owned())
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
        .filter(|parent| parent != space_id && parent.starts_with("ak:space:"))
        {
            return Some(parent);
        }
    }

    None
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

    children
        .into_iter()
        .filter(|child| child != space_id && child.starts_with("ak:space:"))
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
    // Direct conversations are addressable only through the contact/direct
    // resolver. Keep this defensive filter at the final navigation projection
    // as well as at sync ingestion so stale local snapshots cannot leak a DM
    // Realm into the ordinary Collaboration sidebar.
    let visible_nodes: Vec<RealmTreeNode> = nodes
        .iter()
        .filter(|node| !realm_tree_node_is_direct_conversation(node))
        .cloned()
        .collect();
    let nodes = visible_nodes.as_slice();
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
        && !realm_tree_node_is_direct_conversation(node)
}

pub(crate) fn realm_tree_node_is_direct_conversation(node: &RealmTreeNode) -> bool {
    node.direct_conversation
}

#[cfg(test)]
pub fn realm_tree_nodes_from_sync_realms(realms: &BTreeMap<String, Value>) -> Vec<RealmTreeNode> {
    realm_tree_nodes_from_sync_realms_with_roles(realms, &BTreeMap::new())
}

pub fn realm_tree_nodes_from_sync_realms_with_roles(
    realms: &BTreeMap<String, Value>,
    collaboration_roles: &BTreeMap<String, arkret_sdk::CollaborationRealmRole>,
) -> Vec<RealmTreeNode> {
    let mut previews: Vec<RealmTreeNode> = realms
        .iter()
        .filter(|(id, body)| {
            is_realm_or_space_projection_id(id)
                && !projection_looks_like_strand(body)
                && !realm_projection_is_principal_control(body)
                && collaboration_roles.get(*id)
                    != Some(&arkret_sdk::CollaborationRealmRole::DirectConversation)
        })
        .map(|(id, body)| {
            let summary = body.get("summary").unwrap_or(&Value::Null);
            let title = projection_title(id, body);
            let description = explicit_realm_summary(body);
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
            let direct_conversation = collaboration_roles.get(id)
                == Some(&arkret_sdk::CollaborationRealmRole::DirectConversation);
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
                direct_conversation,
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
    id.starts_with("ak:realm:") || id.starts_with("ak:space:")
}

pub(crate) fn projection_tree_node_kind(id: &str, body: &Value) -> RealmTreeNodeKind {
    // Classify Realm vs Space. Wire signals:
    // - `__kind` (inkson-local tag from optimistic save)
    // - `schema` (server projection — ak.schema.realm.v1 vs ak.schema.space.v1)
    // - id prefix (`ak:realm:*` vs `ak:space:*`)
    match body
        .get("__kind")
        .and_then(Value::as_str)
        .or_else(|| body.get("schema").and_then(Value::as_str))
    {
        Some("space") | Some(SchemaId::SPACE_V1) => RealmTreeNodeKind::Space,
        Some("realm") | Some(SchemaId::REALM_V1) => RealmTreeNodeKind::Realm,
        _ if id.starts_with("ak:space:") => RealmTreeNodeKind::Space,
        _ if id.starts_with("ak:realm:") => RealmTreeNodeKind::Realm,
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
            Some(event_kind_str::STRAND_CREATE | "discussion" | "strand")
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

    /// One Realm projection carrying exactly the installed current
    /// `ak.component.realm.genesis.v1` value. That single published result is
    /// the whole create-locked identity/security core a client may read.
    fn installed_genesis_projection(realm_id: &str, genesis: Value) -> Value {
        json!({
            "current": {"entries": [{
                "selector": {
                    "scope_ref": {"kind": "realm", "realm_id": realm_id},
                    "cell_id": "ak:cell:ak.component.realm.genesis.v1:null"
                },
                "result": {"status": "value", "value": genesis}
            }]}
        })
    }

    fn preview(id: &str, name: &str, parent: Option<&str>) -> RealmTreeNode {
        let kind = if id.starts_with("ak:space:") {
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
            direct_conversation: false,
            parent_space_id: parent.map(ToOwned::to_owned),
            child_space_ids: Vec::new(),
            kind,
            realm_id: if kind == RealmTreeNodeKind::Realm {
                id.to_owned()
            } else {
                "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY".to_owned()
            },
        }
    }

    #[test]
    fn sync_projection_title_accepts_invite_title_aliases() {
        let nodes = realm_tree_nodes_from_sync_realms(&BTreeMap::from([(
            "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1".to_owned(),
            json!({
                "realm_title": "Launch Planning",
                "summary": {}
            }),
        )]));

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].title, "Launch Planning");
    }

    #[test]
    fn sync_projection_reads_canonical_window_start_realm_metadata() {
        let id = "ak:realm:AVWVGlDqGwJJ7DILnxJ4oq7JGdtoXGIQaK4PoiEf2yBZ";
        let nodes = realm_tree_nodes_from_sync_realms(&BTreeMap::from([(
            id.to_owned(),
            json!({
                "summary": {"joined_member_count": 1},
                "state_at_window_start": {
                    "actor_profiles": [],
                    "realm_metadata": {
                        "title": "Architecture",
                        "summary": "System design"
                    },
                    "e2ee_epoch": null
                }
            }),
        )]));

        assert_eq!(nodes[0].title, "Architecture");
        assert_eq!(nodes[0].description.as_deref(), Some("System design"));
    }

    #[test]
    fn sync_projection_reads_the_title_the_current_profile_value_installed() {
        // `install_bounded_view` writes `summary.title` / `summary.summary`
        // from the current `ak.component.realm.profile.v1` value. The retired
        // `state` / `state_after` Event containers are gone from the wire, so
        // there is no second place a title could come from.
        let id = "ak:realm:AWgGCEbMHnelRQfzqg1C_onV9Ej_FdpdAZyM_JoFgAd3";
        let nodes = realm_tree_nodes_from_sync_realms(&BTreeMap::from([(
            id.to_owned(),
            json!({
                "summary": {
                    "joined_member_count": 1,
                    "title": "Installed title",
                    "summary": "Installed summary"
                }
            }),
        )]));

        assert_eq!(nodes[0].title, "Installed title");
        assert_eq!(nodes[0].description.as_deref(), Some("Installed summary"));
    }

    #[test]
    fn content_scheme_remains_pending_without_an_explicit_authoring_selector() {
        let transient_projection = json!({
            "member_roster_entries_limited": false,
            "member_roster_entries": []
        });

        assert_eq!(
            realm_projection_pre_genesis_content_scheme(&transient_projection),
            None,
            "a roster-only frame may not guess a content wire scheme"
        );
        assert_eq!(
            realm_projection_pre_genesis_content_scheme(&json!({
                "current": {"entries": [{
                    "selector": {
                        "scope_ref": {
                            "kind": "realm",
                            "realm_id": "ak:realm:AWgGCEbMHnelRQfzqg1C_onV9Ej_FdpdAZyM_JoFgAd3"
                        },
                        "cell_id": "ak:cell:ak.component.realm.genesis.v1:null"
                    },
                    "result": {"status": "value", "value": {
                        "encryption_profile": "mls_rfc9420"
                    }}
                }]}
            })),
            None,
            "the Realm genesis profile is not the MLS group content scheme"
        );
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
            content_scheme: "mls_exporter_aead_v1".to_owned(),
            history_access: "all_history_for_current_members".to_owned(),
            plaintext_visible_services: vec!["directory".to_owned()],
            collaboration_role: None,
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
        assert_eq!(body["content_scheme"], "mls_exporter_aead_v1");
        assert_eq!(body["summary"]["content_scheme"], "mls_exporter_aead_v1");
        assert_eq!(body["history_access"], "all_history_for_current_members");
        assert_eq!(
            body["summary"]["history_access"],
            "all_history_for_current_members"
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
            content_scheme: "mls_rfc9420".to_owned(),
            history_access: "since_join".to_owned(),
            plaintext_visible_services: Vec::new(),
            collaboration_role: None,
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
            realm_id: "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY".to_owned(),
            kind: "collection".to_owned(),
            title: "Specs".to_owned(),
            summary: "Spec work".to_owned(),
            parent_space_id: Some("ak:space:parent".to_owned()),
        })
        .into_value();

        assert_eq!(body["__kind"], "space");
        assert_eq!(
            body["realm_id"],
            "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY"
        );
        assert_eq!(body["kind"], "collection");
        assert_eq!(body["parent_space_id"], "ak:space:parent");
        assert!(body.get("default_realm_id").is_none());
        assert_eq!(body["summary"]["kind"], "collection");
        assert_eq!(body["timeline"]["events"], json!([]));
    }

    #[test]
    fn realm_tree_uses_parent_links_for_nested_spaces() {
        let spaces = vec![
            preview(
                "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY",
                "Root",
                None,
            ),
            preview("ak:space:child", "Child", None),
            preview("ak:space:deep", "Deep", Some("ak:space:child")),
        ];

        let items = realm_tree_items(&spaces);

        assert_eq!(items.len(), 3);
        assert_eq!(
            items[0].node.id,
            "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY"
        );
        assert_eq!(items[0].depth, 0);
        assert_eq!(items[0].descendant_count, 2);
        assert_eq!(items[1].node.id, "ak:space:child");
        assert_eq!(items[1].depth, 1);
        assert_eq!(items[2].node.id, "ak:space:deep");
        assert_eq!(items[2].depth, 2);
    }

    #[test]
    fn pinned_realms_sort_before_unpinned_roots_without_splitting_subtrees() {
        let mut a_child = preview("ak:space:a-child", "A child", None);
        a_child.realm_id = "ak:realm:ASN5uMi28AEbWgFm2GmchqhztuhBSoOzWPAht4VgFoXk".to_owned();
        let mut b_child = preview("ak:space:b-child", "B child", None);
        b_child.realm_id = "ak:realm:AF-jk6ju8IdjVa7Gf0eeCnOu9EHYKDaY47I98_7lPyfo".to_owned();
        let nodes = vec![
            preview(
                "ak:realm:ASN5uMi28AEbWgFm2GmchqhztuhBSoOzWPAht4VgFoXk",
                "A",
                None,
            ),
            a_child,
            preview(
                "ak:realm:AF-jk6ju8IdjVa7Gf0eeCnOu9EHYKDaY47I98_7lPyfo",
                "B",
                None,
            ),
            b_child,
        ];
        let pinned =
            BTreeSet::from(["ak:realm:AF-jk6ju8IdjVa7Gf0eeCnOu9EHYKDaY47I98_7lPyfo".to_owned()]);

        let items = realm_tree_items_with_pinned_realms(&nodes, &pinned);
        let ids: Vec<_> = items
            .iter()
            .map(|item| (item.node.id.as_str(), item.depth))
            .collect();

        assert_eq!(
            ids,
            vec![
                ("ak:realm:AF-jk6ju8IdjVa7Gf0eeCnOu9EHYKDaY47I98_7lPyfo", 0),
                ("ak:space:b-child", 1),
                ("ak:realm:ASN5uMi28AEbWgFm2GmchqhztuhBSoOzWPAht4VgFoXk", 0),
                ("ak:space:a-child", 1),
            ]
        );
    }

    #[test]
    fn ordinary_navigation_omits_direct_conversation_realms_even_when_pinned() {
        let mut dm = preview(
            "ak:realm:AXXj-3yEyHv7Kyo7niHWuUuucolddHsvAd2DXS2jtgDA",
            "DM",
            None,
        );
        dm.direct_conversation = true;
        let nodes = vec![
            dm,
            preview(
                "ak:realm:AWG6UBspWdU4JTNRCHibEMTsPmT7o6cbDYSeoEcQkMQw",
                "Work",
                None,
            ),
            preview(
                "ak:realm:Ai5i4v2IpgBcXOnqXG0qYJ4y_Zz5Xs359i6Ubynu-D1s",
                "Later",
                None,
            ),
        ];
        let pinned = BTreeSet::from([
            "ak:realm:AXXj-3yEyHv7Kyo7niHWuUuucolddHsvAd2DXS2jtgDA".to_owned(),
            "ak:realm:Ai5i4v2IpgBcXOnqXG0qYJ4y_Zz5Xs359i6Ubynu-D1s".to_owned(),
        ]);

        let items = realm_tree_items_with_pinned_realms(&nodes, &pinned);
        let ids: Vec<_> = items.iter().map(|item| item.node.id.as_str()).collect();

        assert_eq!(
            ids,
            vec![
                "ak:realm:Ai5i4v2IpgBcXOnqXG0qYJ4y_Zz5Xs359i6Ubynu-D1s",
                "ak:realm:AWG6UBspWdU4JTNRCHibEMTsPmT7o6cbDYSeoEcQkMQw"
            ]
        );
    }

    #[test]
    fn direct_conversation_role_uses_typed_sync_projection_not_category_or_tags() {
        let realm_id = "ak:realm:AXqScWrSVbMRHSSnD37HwS-fgoTGt3HbHkvBV3SttpCU";
        let strong = realm_tree_nodes_from_sync_realms_with_roles(
            &BTreeMap::from([(
                realm_id.to_owned(),
                json!({"summary": {"title": "Conversation"}}),
            )]),
            &BTreeMap::from([(
                realm_id.to_owned(),
                arkret_sdk::CollaborationRealmRole::DirectConversation,
            )]),
        );
        assert!(
            strong.is_empty(),
            "typed direct-conversation Realms must stay out of ordinary navigation"
        );

        let genesis_only = realm_tree_nodes_from_sync_realms(&BTreeMap::from([(
            realm_id.to_owned(),
            installed_genesis_projection(
                realm_id,
                json!({"collaboration_role": "direct_conversation"}),
            ),
        )]));
        assert!(
            !realm_tree_node_is_direct_conversation(&genesis_only[0]),
            "an untyped genesis field probe must not drive MLS classification"
        );

        let heuristic_only = realm_tree_nodes_from_sync_realms(&BTreeMap::from([(
            realm_id.to_owned(),
            json!({"summary": {"category": "direct_conversation", "tags": ["dm"]}}),
        )]));
        assert!(!realm_tree_node_is_direct_conversation(&heuristic_only[0]));
    }

    #[test]
    fn principal_control_realms_are_excluded_from_product_navigation() {
        let pcr_id = "ak:realm:Ac9iLS6pVSDjqFeDeJjvUhbtREpxQ8IWem2mi64wrqDq";
        let collaboration_id = "ak:realm:AXqScWrSVbMRHSSnD37HwS-fgoTGt3HbHkvBV3SttpCU";
        let nodes = realm_tree_nodes_from_sync_realms(&BTreeMap::from([
            (
                pcr_id.to_owned(),
                installed_genesis_projection(
                    pcr_id,
                    json!({
                        "purpose": "principal_control",
                        "schema_refs": ["ak.profile.principal_control_realm.v1"]
                    }),
                ),
            ),
            (
                collaboration_id.to_owned(),
                json!({"summary": {"title": "Product Realm"}}),
            ),
        ]));

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, collaboration_id);
    }

    #[test]
    fn principal_control_classification_requires_purpose_and_profile() {
        let realm_id = "ak:realm:Ac9iLS6pVSDjqFeDeJjvUhbtREpxQ8IWem2mi64wrqDq";
        let purpose_only =
            installed_genesis_projection(realm_id, json!({"purpose": "principal_control"}));
        let profile_only = installed_genesis_projection(
            realm_id,
            json!({
                "purpose": "collaboration",
                "schema_refs": ["ak.profile.principal_control_realm.v1"]
            }),
        );

        assert!(!realm_projection_is_principal_control(&purpose_only));
        assert!(!realm_projection_is_principal_control(&profile_only));
    }

    #[test]
    fn descendant_node_ids_walks_full_subtree_and_ignores_unknown_root() {
        let spaces = vec![
            preview(
                "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY",
                "Root",
                None,
            ),
            preview("ak:space:child", "Child", None),
            preview("ak:space:deep", "Deep", Some("ak:space:child")),
            RealmTreeNode {
                realm_id: "ak:realm:ALxDZio2znRUoLNW5_OmFXNttc8yHs8Jw8_b6vk0QYXo".to_owned(),
                ..preview(
                    "ak:realm:ALxDZio2znRUoLNW5_OmFXNttc8yHs8Jw8_b6vk0QYXo",
                    "Other",
                    None,
                )
            },
        ];

        assert_eq!(
            descendant_node_ids(
                &spaces,
                "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY"
            ),
            vec![
                "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY".to_owned(),
                "ak:space:child".to_owned(),
                "ak:space:deep".to_owned(),
            ]
        );
        // An unknown (but non-blank) root has no descendants, so the walk
        // is just the root id itself.
        assert_eq!(
            descendant_node_ids(&spaces, "ak:space:missing"),
            vec!["ak:space:missing".to_owned()]
        );
        // A blank root short-circuits to an empty walk.
        assert!(descendant_node_ids(&spaces, "   ").is_empty());
    }

    #[test]
    fn normalize_realm_tree_hierarchy_rebuilds_children_from_parent_links() {
        let mut spaces = vec![
            preview(
                "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY",
                "Root",
                None,
            ),
            preview("ak:space:child", "Child", None),
            preview("ak:space:deep", "Deep", Some("ak:space:child")),
            // Parent points at an unknown id — must be dropped, not panic.
            preview("ak:space:orphan", "Orphan", Some("ak:space:ghost")),
        ];

        normalize_realm_tree_hierarchy(&mut spaces);

        let root = spaces
            .iter()
            .find(|s| s.id == "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY")
            .expect("root");
        let child = spaces
            .iter()
            .find(|s| s.id == "ak:space:child")
            .expect("child");
        let orphan = spaces
            .iter()
            .find(|s| s.id == "ak:space:orphan")
            .expect("orphan");

        assert_eq!(root.child_space_ids, vec!["ak:space:child".to_owned()]);
        assert_eq!(child.child_space_ids, vec!["ak:space:deep".to_owned()]);
        assert!(orphan.child_space_ids.is_empty());
    }

    #[test]
    fn extract_parent_space_id_reads_only_projected_hierarchy_fields() {
        // Summary-level parent link.
        assert_eq!(
            extract_parent_space_id(
                "ak:space:child",
                &json!({"summary": {"parent_space_id": "ak:space:root"}})
            ),
            Some("ak:space:root".to_owned())
        );
        // The retired `state` Event container is not a parent-edge source.
        assert_eq!(
            extract_parent_space_id(
                "ak:space:child",
                &json!({
                    "state": [{
                        "kind": "ak.space.parent",
                        "payload": {"parent_space_id": "ak:space:root"}
                    }]
                })
            ),
            None
        );
        // Self-reference and non-Space ids are rejected.
        assert_eq!(
            extract_parent_space_id(
                "ak:space:child",
                &json!({"summary": {"parent_space_id": "ak:space:child"}})
            ),
            None
        );
        assert_eq!(
            extract_parent_space_id(
                "ak:space:child",
                &json!({"summary": {"parent_space_id": "ak:strand:AfgHwnXHiCs7a-wo4z0oefee77xm8izLuvRq5QV231-4"}})
            ),
            None
        );
    }

    // The former `realm_projection_encryption_state_uses_profile_and_visibility`
    // test asserted the create-locked `encryption_profile`, the
    // `plaintext_visibility` default and the `state_at_window_start.e2ee_epoch`
    // window — three wire members that no longer exist. The successor judgement
    // ("the scope has an accepted `ak.mls.genesis`") is
    // `LocalStateStore::realm_projection_is_mls_encrypted`, covered positively
    // and negatively in `src/local_state_tests/projections.rs`.

    #[test]
    fn is_realm_or_space_projection_id_matches_realm_and_space_prefixes() {
        assert!(is_realm_or_space_projection_id(
            "ak:realm:AQ_DYndfRLGXFTmGil1KY2oQW2AKjYbSN9mi4f-HASKg"
        ));
        assert!(is_realm_or_space_projection_id("ak:space:abc"));
        assert!(!is_realm_or_space_projection_id(
            "ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg"
        ));
        assert!(!is_realm_or_space_projection_id("realm:abc"));
    }

    #[test]
    fn sync_projection_parses_realm_and_space_hierarchy_fields() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY".to_owned(),
            json!({
                "schema": "ak.schema.realm.v1",
                "summary": {
                    "title": "Root",
                    "summary": "Root Realm"
                }
            }),
        );
        spaces.insert(
            "ak:space:child".to_owned(),
            json!({
                "schema": "ak.schema.space.v1",
                "realm_id": "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY",
                "summary": {
                    "title": "Child",
                    "summary": "Child Space"
                }
            }),
        );

        let previews = realm_tree_nodes_from_sync_realms(&spaces);
        let root = previews
            .iter()
            .find(|node| node.id == "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY")
            .expect("root preview");
        let child = previews
            .iter()
            .find(|node| node.id == "ak:space:child")
            .expect("child preview");

        assert_eq!(root.child_space_ids, vec!["ak:space:child".to_owned()]);
        assert_eq!(child.parent_space_id, None);
        assert_eq!(root.kind, RealmTreeNodeKind::Realm);
        assert_eq!(child.kind, RealmTreeNodeKind::Space);
    }

    #[test]
    fn sync_projection_marks_schema_space_with_home_realm() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY".to_owned(),
            json!({
                "schema": "ak.schema.realm.v1",
                "summary": {"title": "Root"}
            }),
        );
        spaces.insert(
            "ak:space:child".to_owned(),
            json!({
                "schema": "ak.schema.space.v1",
                "realm_id": "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY",
                "summary": {"title": "Child"}
            }),
        );

        let previews = realm_tree_nodes_from_sync_realms(&spaces);
        let child = previews
            .iter()
            .find(|node| node.id == "ak:space:child")
            .expect("child preview");

        assert_eq!(child.kind, RealmTreeNodeKind::Space);
        assert_eq!(
            child.realm_id,
            "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY"
        );
        assert_eq!(child.parent_space_id, None);

        let items = realm_tree_items(&previews);
        let child_item = items
            .iter()
            .find(|item| item.node.id == "ak:space:child")
            .expect("child tree item");
        assert_eq!(child_item.depth, 1);
    }

    #[test]
    fn sync_projection_filters_strand_entries_out_of_realm_tree() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY".to_owned(),
            json!({
                "schema": "ak.schema.realm.v1",
                "summary": {
                    "title": "Root",
                    "summary": "Root Realm"
                }
            }),
        );
        spaces.insert(
            "ak:strand:AsLgUd73PSI9_dWVG49ZfkmPc0yCUf4zdrfGlSidlNnU".to_owned(),
            json!({
                "strand_id": "ak:strand:AsLgUd73PSI9_dWVG49ZfkmPc0yCUf4zdrfGlSidlNnU",
                "summary": {
                    "title": "Should not be a node"
                }
            }),
        );
        spaces.insert(
            "ak:space:strand-projection".to_owned(),
            json!({
                "strand_id": "ak:strand:AHJT0IVSFPGYRqWgOGcbtadQgIfN5QfHj6vRKazew2F8",
                "summary": {
                    "title": "Strand projection",
                    "category": "discussion"
                }
            }),
        );

        let previews = realm_tree_nodes_from_sync_realms(&spaces);

        assert_eq!(previews.len(), 1);
        assert_eq!(
            previews[0].id,
            "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY"
        );
    }

    /// Regression: soland inlines the primary strand under `summary.strand`
    /// for legitimate Spaces (so the client can render the room title
    /// without joining a separate fanout). A previous filter treated
    /// any `summary.strand` as a strand-as-tree-node projection and dropped the
    /// Space from the sidebar entirely. Only top-level `strand*`/`tracks`
    /// or a strand-shaped `summary.category` should reject a `ak:space:`.
    #[test]
    fn sync_projection_keeps_real_space_with_inlined_primary_strand() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ak:space:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j".to_owned(),
            json!({
                "ephemeral": [],
                "realm_id": "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                "strands": [{
                    "strand_id": "ak:strand:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j",
                    "title": "Arkret Demo Realm",
                }],
                "summary": {
                    "category": "collaboration",
                    "title": "Arkret Demo Realm",
                    "summary": "Shared demo Space served by soland",
                    "tags": ["demo"],
                    "strand": {
                        "strand_id": "ak:strand:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j",
                        "title": "Arkret Demo Realm",
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
            "ak:space:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j"
        );
        assert_eq!(previews[0].title, "Arkret Demo Realm");
        assert_eq!(previews[0].category.as_deref(), Some("collaboration"));
    }

    #[test]
    fn sync_projection_keeps_realm_ids_from_account_subscribe() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ak:realm:ARDR2oN-Bh8J55KxFHM6s_izSsUg0-1gh3XfOjfjJ9HE".to_owned(),
            json!({
                "ephemeral": [],
                "strands": [{
                    "strand_id": "ak:strand:ARDR2oN-Bh8J55KxFHM6s_izSsUg0-1gh3XfOjfjJ9HE",
                    "kind": "discussion",
                    "title": "Test"
                }],
                "summary": {
                    "category": null,
                    "strand": {
                        "strand_id": "ak:strand:ARDR2oN-Bh8J55KxFHM6s_izSsUg0-1gh3XfOjfjJ9HE",
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
            "ak:realm:ARDR2oN-Bh8J55KxFHM6s_izSsUg0-1gh3XfOjfjJ9HE"
        );
        assert_eq!(previews[0].title, "Test");
        assert_eq!(previews[0].kind, RealmTreeNodeKind::Realm);
    }

    #[test]
    fn realm_tree_nodes_from_sync_realms_filters_strand_like_projections() {
        // The sync engine relies on `realm_tree_nodes_from_sync_realms`
        // (rather than the retired client-side merge filter) to keep
        // strand-like projections out of the sidebar — verify that here.
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ak:strand:AsLgUd73PSI9_dWVG49ZfkmPc0yCUf4zdrfGlSidlNnU".to_owned(),
            json!({
                "strand_id": "ak:strand:AsLgUd73PSI9_dWVG49ZfkmPc0yCUf4zdrfGlSidlNnU",
                "summary": {"title": "Discussion", "category": "discussion"}
            }),
        );
        spaces.insert(
            "ak:space:real".to_owned(),
            json!({
                "schema": "ak.schema.space.v1",
                "realm_id": "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY",
                "summary": {"title": "Real Space"}
            }),
        );

        let previews = realm_tree_nodes_from_sync_realms(&spaces);

        assert_eq!(previews.len(), 1);
        assert_eq!(previews[0].id, "ak:space:real");
    }
}
