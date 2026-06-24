//! Projection view models and recommended-encryption constants for the
//! self-API client. UI-facing decode/projection shapes split out of
//! `api/mod.rs` (structural move only). Re-exported from the parent module so
//! existing `crate::api::*` / sibling `super::*` paths resolve unchanged.

use super::*;

pub const RECOMMENDED_REALM_ENCRYPTION_PROFILE: &str = "mls_rfc9420";
pub const RECOMMENDED_REALM_ENCRYPTION_FLOOR: &str = "e2ee_required";

/// Generic wrapper for soland's
/// `/_cokret/self/realms/{realm_id}/{spaces|strands}` lifecycle endpoints. Keeps
/// the query response shape symmetric across the two surfaces so the kanban
/// hydrate path can pluck projection rows with the same code. The decoder
/// normalizes spec `spaces` / `strands` / `morphs` collection keys into `items`.
#[derive(Clone, Debug, Deserialize)]
pub struct LifecycleProjectionView<T> {
    pub realm_id: String,
    #[serde(default)]
    pub total: u32,
    #[serde(
        default = "Vec::new",
        alias = "spaces",
        alias = "strands",
        alias = "morphs"
    )]
    pub items: Vec<T>,
}

/// Server-side Space-container projection row.
///
/// Soland serves these rows from
/// `GET /_cokret/self/realms/{realm_id}/spaces`.
#[derive(Clone, Debug, Deserialize)]
pub struct SpaceContainerProjectionView {
    pub space_id: String,
    pub realm_id: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub title: String,
    /// `active` / `archived` / `tombstoned` per spec
    /// `common-fields.md §5.1`.
    pub state: String,
    #[serde(default)]
    pub rank: Option<String>,
    #[serde(default)]
    pub parent_space_id: Option<String>,
}

/// Server-side Strand row from `GET /_cokret/self/realms/{realm_id}/strands`.
#[derive(Clone, Debug, Deserialize)]
pub struct StrandProjectionView {
    pub strand_id: String,
    pub realm_id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub body: Option<Value>,
    #[serde(default)]
    pub board_space_id: Option<String>,
    #[serde(default)]
    pub list_space_id: Option<String>,
    #[serde(default)]
    pub rank: Option<String>,
    #[serde(default)]
    pub assigned_actor_ids: Vec<String>,
    #[serde(default)]
    pub assigned_to_relations: Vec<AssignedToRelationProjectionView>,
    #[serde(default)]
    pub fields: serde_json::Map<String, serde_json::Value>,
    /// `active` / `archived` / `redacted` per spec
    /// `common-fields.md §5.1`. `redacted` is the only irreversible
    /// terminal state; the reducer no longer accepts `deleted`.
    pub state: String,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_by: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AssignedToRelationProjectionView {
    pub relation_id: String,
    pub actor_id: String,
}

/// UI view model for the SDK `CollectionProjectionView` response.
/// Network decode uses `cokret_sdk::CollectionProjectionView`; this shape
/// keeps the kanban renderer's lenient `Value` accessors local to the UI.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CollectionProjectionView {
    /// Always the literal `"collection"` per the schema const.
    pub projection: String,
    /// Renderer hint (`board` / `list` / `table` / …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renderer: Option<String>,
    pub view_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
    /// Registered `state_frontier` object (NOT a bare event-id list).
    pub frontier: StateFrontierView,
    #[serde(default)]
    pub groups: Vec<CollectionProjectionGroupView>,
    /// Flat item list for group-less renderers (schema `anyOf` requires
    /// `groups` or `items`).
    #[serde(default)]
    pub items: Vec<ProjectionItemView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_estimate: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
}

/// Registered `view.schema.json#/$defs/state_frontier`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StateFrontierView {
    pub state_digest: String,
    #[serde(default)]
    pub event_ids: Vec<String>,
    #[serde(default)]
    pub actor_frontiers: Vec<Value>,
}

/// Registered `view.schema.json#/$defs/collection_projection_group`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CollectionProjectionGroupView {
    /// Stable group key (registered name is `key`, not `group_id`).
    pub key: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    /// Registered `collection_group_source` (oneOf) — kept opaque.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Value>,
    #[serde(default)]
    pub items: Vec<ProjectionItemView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Required by the registered schema: whether this group's item list
    /// was truncated by policy/limit.
    pub limited: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wip_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_estimate: Option<u64>,
}

/// Registered `view.schema.json#/$defs/projection_item`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProjectionItemView {
    /// Registered `projection_object` (`{id, type, morph_type?, facets?,
    /// title?, fields?}`). Kept as a `Value` — readers fall back through
    /// `title`/`fields.*` leniently.
    pub object: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub render: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<Value>,
    /// Registered `collection_position` (oneOf field_value / relation /
    /// time_bucket). Kept opaque; use [`Self::position_rank`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<Value>,
    /// Free-form per-item read-model state (registered as an open object).
    /// Discussion lock metadata, when a server provides it, is read
    /// leniently from `state.discussion`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<Value>,
}

impl ProjectionItemView {
    /// Rank from the registered `collection_position` variants: the
    /// `field_value` / `relation` models carry `rank`; the `time_bucket`
    /// model carries `sort_key`.
    pub fn position_rank(&self) -> Option<String> {
        let position = self.position.as_ref()?;
        position
            .get("rank")
            .or_else(|| position.get("sort_key"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }
}

fn sdk_wire_string<T: Serialize>(value: &T) -> Option<String> {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
}

fn non_null_value(value: Value) -> Option<Value> {
    if value.is_null() { None } else { Some(value) }
}

impl From<cokret_sdk::StateFrontier> for StateFrontierView {
    fn from(frontier: cokret_sdk::StateFrontier) -> Self {
        Self {
            state_digest: frontier.state_digest.as_str().to_owned(),
            event_ids: frontier
                .event_ids
                .into_iter()
                .map(|event_id| event_id.as_str().to_owned())
                .collect(),
            actor_frontiers: frontier
                .actor_frontiers
                .into_iter()
                .filter_map(|frontier| serde_json::to_value(frontier).ok())
                .collect(),
        }
    }
}

impl From<cokret_sdk::ProjectionItem> for ProjectionItemView {
    fn from(item: cokret_sdk::ProjectionItem) -> Self {
        Self {
            object: serde_json::to_value(item.object).unwrap_or(Value::Null),
            render: item.render.as_ref().and_then(sdk_wire_string),
            display: non_null_value(item.display),
            position: non_null_value(item.position),
            state: non_null_value(item.state),
        }
    }
}

impl From<cokret_sdk::CollectionProjectionGroupView> for CollectionProjectionGroupView {
    fn from(group: cokret_sdk::CollectionProjectionGroupView) -> Self {
        Self {
            key: group.key,
            title: group.title,
            rank: group.rank,
            source: group
                .source
                .and_then(|source| serde_json::to_value(source).ok()),
            items: group.items.into_iter().map(Into::into).collect(),
            next_cursor: group.next_cursor.map(|cursor| cursor.as_str().to_owned()),
            limited: group.limited,
            wip_state: group.wip_state.as_ref().and_then(sdk_wire_string),
            total_estimate: group.total_estimate,
        }
    }
}

impl From<cokret_sdk::CollectionProjectionView> for CollectionProjectionView {
    fn from(view: cokret_sdk::CollectionProjectionView) -> Self {
        Self {
            projection: view.projection,
            renderer: view.renderer.as_ref().and_then(sdk_wire_string),
            view_id: view.view_id.as_str().to_owned(),
            realm_id: view.realm_id.map(|realm_id| realm_id.as_str().to_owned()),
            frontier: view.frontier.into(),
            groups: view.groups.into_iter().map(Into::into).collect(),
            items: view.items.into_iter().map(Into::into).collect(),
            next_cursor: view.next_cursor.map(|cursor| cursor.as_str().to_owned()),
            total_estimate: view.total_estimate,
            stale: view.stale,
        }
    }
}

/// Server-side Morph row from
/// `GET /_cokret/self/realms/{realm_id}/morphs`. Same enum as Strand per spec §5.1.
#[derive(Clone, Debug, Deserialize)]
pub struct MorphProjectionView {
    pub morph_id: String,
    pub realm_id: String,
    #[serde(default)]
    pub morph_type: String,
    #[serde(default)]
    pub title: Option<String>,
    pub state: String,
}
