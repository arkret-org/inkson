//! Unified entity/relation/view abstractions per contrix-spec section 4.
//!
//! The object model defines 11 core objects: space, actor, entity, relation,
//! event, view, schema, policy, invite, read_marker, notification.
//!
//! 11 standard entity types: board, task, message, topic, channel, document,
//! file, memory, run, actor_profile, poll.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// Unified entity carrier per contrix-spec section 4.2.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Entity {
    /// Unique entity ID.
    pub entity_id: String,
    /// The space this entity belongs to.
    pub space_id: String,
    /// Entity type (one of the 11 standard types or custom).
    pub entity_type: EntityType,
    /// Capability facets advertised by the server. `entity_type` is a label; facets drive behavior.
    #[serde(default)]
    pub facets: Vec<EntityFacet>,
    /// The actor that created this entity.
    pub creator: String,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    /// ISO 8601 last update timestamp.
    pub updated_at: String,
    /// Entity-specific data fields.
    pub data: BTreeMap<String, Value>,
    /// Tags for categorization.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Whether this entity is archived.
    #[serde(default)]
    pub archived: bool,
    /// Whether this entity is deleted (tombstone).
    #[serde(default)]
    pub deleted: bool,
}

/// Standard entity types per contrix-spec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Board,
    Task,
    Message,
    Topic,
    Channel,
    Document,
    File,
    Memory,
    Run,
    ActorProfile,
    Poll,
    /// Custom entity type with reverse-domain name.
    Custom(String),
}

/// Standard entity capability facets from contrix-spec.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum EntityFacet {
    Container,
    Replyable,
    Schedulable,
    Assignable,
    Stateful,
    Rankable,
    Reviewable,
    Notifiable,
    Documentable,
    Renderable,
    /// Server extension facet. Preserve it for debug/forward compatibility.
    Unknown(String),
}

/// Preferred renderer hint for a view/query result.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ViewRenderer {
    Board,
    Card,
    Row,
    Table,
    Calendar,
    Gantt,
    Timeline,
    Thread,
    Chat,
    Forum,
    Graph,
    Tree,
    Document,
    Dashboard,
    Custom,
    /// Server extension renderer. Preserve it for debug/forward compatibility.
    Unknown(String),
}

/// The compact shape used by generic entity cards.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntityRenderKind {
    Card,
    Row,
    Table,
    Message,
    Node,
}

impl EntityType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Board => "board",
            Self::Task => "task",
            Self::Message => "message",
            Self::Topic => "topic",
            Self::Channel => "channel",
            Self::Document => "document",
            Self::File => "file",
            Self::Memory => "memory",
            Self::Run => "run",
            Self::ActorProfile => "actor_profile",
            Self::Poll => "poll",
            Self::Custom(s) => s,
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "board" => Self::Board,
            "task" => Self::Task,
            "message" => Self::Message,
            "topic" => Self::Topic,
            "channel" => Self::Channel,
            "document" => Self::Document,
            "file" => Self::File,
            "memory" => Self::Memory,
            "run" => Self::Run,
            "actor_profile" => Self::ActorProfile,
            "poll" => Self::Poll,
            other => Self::Custom(other.to_owned()),
        }
    }
}

impl EntityFacet {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Container => "container",
            Self::Replyable => "replyable",
            Self::Schedulable => "schedulable",
            Self::Assignable => "assignable",
            Self::Stateful => "stateful",
            Self::Rankable => "rankable",
            Self::Reviewable => "reviewable",
            Self::Notifiable => "notifiable",
            Self::Documentable => "documentable",
            Self::Renderable => "renderable",
            Self::Unknown(facet) => facet,
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "container" => Self::Container,
            "replyable" => Self::Replyable,
            "schedulable" => Self::Schedulable,
            "assignable" => Self::Assignable,
            "stateful" => Self::Stateful,
            "rankable" => Self::Rankable,
            "reviewable" => Self::Reviewable,
            "notifiable" => Self::Notifiable,
            "documentable" => Self::Documentable,
            "renderable" => Self::Renderable,
            other => Self::Unknown(other.to_owned()),
        }
    }

    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

impl Serialize for EntityFacet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for EntityFacet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self::from_str(&value))
    }
}

impl ViewRenderer {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Board => "board",
            Self::Card => "card",
            Self::Row => "row",
            Self::Table => "table",
            Self::Calendar => "calendar",
            Self::Gantt => "gantt",
            Self::Timeline => "timeline",
            Self::Thread => "thread",
            Self::Chat => "chat",
            Self::Forum => "forum",
            Self::Graph => "graph",
            Self::Tree => "tree",
            Self::Document => "document",
            Self::Dashboard => "dashboard",
            Self::Custom => "custom",
            Self::Unknown(renderer) => renderer,
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "board" => Self::Board,
            "card" => Self::Card,
            "row" => Self::Row,
            "table" => Self::Table,
            "calendar" => Self::Calendar,
            "gantt" => Self::Gantt,
            "timeline" => Self::Timeline,
            "thread" => Self::Thread,
            "chat" => Self::Chat,
            "forum" => Self::Forum,
            "graph" => Self::Graph,
            "tree" => Self::Tree,
            "document" => Self::Document,
            "dashboard" => Self::Dashboard,
            "custom" => Self::Custom,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

impl Serialize for ViewRenderer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ViewRenderer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self::from_str(&value))
    }
}

impl EntityRenderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Card => "card",
            Self::Row => "row",
            Self::Table => "table",
            Self::Message => "message",
            Self::Node => "node",
        }
    }
}

pub fn choose_entity_render_kind(
    facets: &[EntityFacet],
    renderer: Option<&ViewRenderer>,
) -> EntityRenderKind {
    if let Some(renderer) = renderer {
        return match renderer {
            ViewRenderer::Row => EntityRenderKind::Row,
            ViewRenderer::Table => EntityRenderKind::Table,
            ViewRenderer::Timeline
            | ViewRenderer::Thread
            | ViewRenderer::Chat
            | ViewRenderer::Forum => EntityRenderKind::Message,
            ViewRenderer::Graph | ViewRenderer::Tree => EntityRenderKind::Node,
            ViewRenderer::Board
            | ViewRenderer::Card
            | ViewRenderer::Calendar
            | ViewRenderer::Gantt
            | ViewRenderer::Document
            | ViewRenderer::Dashboard => EntityRenderKind::Card,
            ViewRenderer::Custom | ViewRenderer::Unknown(_) => fallback_render_kind(facets),
        };
    }
    fallback_render_kind(facets)
}

pub fn unknown_entity_facets(facets: &[EntityFacet]) -> Vec<String> {
    facets
        .iter()
        .filter_map(|facet| match facet {
            EntityFacet::Unknown(value) => Some(value.clone()),
            _ => None,
        })
        .collect()
}

fn fallback_render_kind(facets: &[EntityFacet]) -> EntityRenderKind {
    if facets.contains(&EntityFacet::Renderable) {
        EntityRenderKind::Card
    } else {
        EntityRenderKind::Row
    }
}

/// A first-class relation between two entities per contrix-spec section 4.3.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Relation {
    /// Unique relation ID.
    pub relation_id: String,
    /// The space this relation belongs to.
    pub space_id: String,
    /// Relation type.
    pub relation_type: RelationType,
    /// Source entity ID.
    pub source: String,
    /// Target entity ID.
    pub target: String,
    /// The actor that created this relation.
    pub creator: String,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    /// Optional relation metadata.
    #[serde(default)]
    pub data: BTreeMap<String, Value>,
    /// Whether this relation is soft-deleted.
    #[serde(default)]
    pub deleted: bool,
}

/// Standard relation types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationType {
    /// Containment (board contains task, space contains channel).
    Contains,
    /// Task dependency.
    DependsOn,
    /// Reply/reference link.
    RepliesTo,
    /// @mention reference.
    Mentions,
    /// Task assignment.
    AssignedTo,
    /// Attachment.
    AttachedTo,
    /// Custom relation type.
    Custom(String),
}

impl RelationType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Contains => "contains",
            Self::DependsOn => "depends_on",
            Self::RepliesTo => "replies_to",
            Self::Mentions => "mentions",
            Self::AssignedTo => "assigned_to",
            Self::AttachedTo => "attached_to",
            Self::Custom(s) => s,
        }
    }
}

/// A view projection definition per contrix-spec section 4.4.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ViewProjection {
    /// Unique view ID.
    pub view_id: String,
    /// The space this view belongs to.
    pub space_id: String,
    /// View kind.
    pub kind: ViewKind,
    /// Human-readable name.
    pub name: String,
    /// View query parameters.
    pub query: ViewQuery,
    /// The actor that created this view.
    pub creator: String,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
}

/// Standard view kinds per contrix-spec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewKind {
    // Work-object views
    Kanban,
    List,
    Table,
    Calendar,
    Timeline,
    Graph,
    Tree,
    Gantt,
    Matrix,
    Document,
    Dashboard,
    // Conversation views
    Chat,
    Forum,
    Thread,
    Activity,
    Inbox,
    Notifications,
    // Review/agent views
    MemoryReview,
    AgentRuns,
    ContextTimeline,
    /// Custom view kind.
    Custom(String),
}

/// Structured view query per contrix-spec.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ViewQuery {
    /// Entity type filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<String>,
    /// Facet filter. All listed facets must match.
    #[serde(default)]
    pub facets: Vec<EntityFacet>,
    /// Preferred server projection renderer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renderer: Option<ViewRenderer>,
    /// Additional filters.
    #[serde(default)]
    pub filters: BTreeMap<String, Value>,
    /// Group-by field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_by: Option<String>,
    /// Order-by field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_by: Option<String>,
    /// Visible fields (projection).
    #[serde(default)]
    pub visible_fields: Vec<String>,
    /// Limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
}

/// A read marker (actor-private read cursor) per contrix-spec section 4.11.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReadMarker {
    /// The actor this marker belongs to.
    pub actor: String,
    /// The space this marker is for.
    pub space_id: String,
    /// The entity/channel being tracked.
    pub target: String,
    /// The read position (HLC or event ID).
    pub position: String,
    /// ISO 8601 timestamp.
    pub updated_at: String,
}

/// A notification (derived projection) per contrix-spec section 4.11.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Notification {
    /// Unique notification ID.
    pub notification_id: String,
    /// Target actor.
    pub actor: String,
    /// The space this notification belongs to.
    pub space_id: String,
    /// Notification type.
    pub kind: String,
    /// Human-readable title.
    pub title: String,
    /// Notification body.
    pub body: String,
    /// Related entity ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    /// Whether this has been read.
    #[serde(default)]
    pub read: bool,
    /// Whether this has been archived.
    #[serde(default)]
    pub archived: bool,
    /// ISO 8601 timestamp.
    pub created_at: String,
    /// Optional action URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_url: Option<String>,
}

/// A schema object per contrix-spec section 4.7.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Schema {
    /// Unique schema ID.
    pub schema_id: String,
    /// The space this schema belongs to.
    pub space_id: String,
    /// Schema name.
    pub name: String,
    /// Schema version.
    pub version: String,
    /// JSON Schema definition.
    pub definition: Value,
    /// The actor that created this schema.
    pub creator: String,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
}

/// A policy object per contrix-spec section 4.8.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// Unique policy ID.
    pub policy_id: String,
    /// The space this policy belongs to.
    pub space_id: String,
    /// Policy name.
    pub name: String,
    /// Policy rules (structured JSON).
    pub rules: Value,
    /// The actor that created this policy.
    pub creator: String,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
}

/// Capability grant per contrix-spec section 5.2.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    /// Unique grant ID.
    pub grant_id: String,
    /// Issuer DID.
    pub issuer: String,
    /// Subject DID or condition selector.
    pub subject: String,
    /// Resource selectors.
    #[serde(default)]
    pub resource_selectors: Vec<String>,
    /// Allowed actions.
    #[serde(default)]
    pub actions: Vec<String>,
    /// Constraints on this grant.
    #[serde(default)]
    pub constraints: Vec<GrantConstraint>,
    /// Proofs supporting this grant.
    #[serde(default)]
    pub proofs: Vec<Value>,
    /// Maximum delegation depth.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_delegation_depth: Option<u32>,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    /// Optional expiration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// A constraint on a capability grant.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GrantConstraint {
    /// Constraint type.
    #[serde(rename = "type")]
    pub constraint_type: String,
    /// Constraint parameters.
    pub params: Value,
}

// ── Builder helpers ──────────────────────────────────────────────

impl Entity {
    pub fn new(
        entity_id: impl Into<String>,
        space_id: impl Into<String>,
        entity_type: EntityType,
        creator: impl Into<String>,
    ) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            entity_id: entity_id.into(),
            space_id: space_id.into(),
            entity_type,
            facets: Vec::new(),
            creator: creator.into(),
            created_at: now.clone(),
            updated_at: now,
            data: BTreeMap::new(),
            tags: Vec::new(),
            archived: false,
            deleted: false,
        }
    }

    /// Set a data field.
    pub fn with_data(mut self, key: impl Into<String>, value: Value) -> Self {
        self.data.insert(key.into(), value);
        self
    }

    /// Add a tag.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Set capability facets advertised for this entity.
    pub fn with_facets(mut self, facets: impl IntoIterator<Item = EntityFacet>) -> Self {
        self.facets = facets.into_iter().collect();
        self
    }
}

impl Relation {
    pub fn new(
        relation_id: impl Into<String>,
        space_id: impl Into<String>,
        relation_type: RelationType,
        source: impl Into<String>,
        target: impl Into<String>,
        creator: impl Into<String>,
    ) -> Self {
        Self {
            relation_id: relation_id.into(),
            space_id: space_id.into(),
            relation_type,
            source: source.into(),
            target: target.into(),
            creator: creator.into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            data: BTreeMap::new(),
            deleted: false,
        }
    }
}

impl ViewQuery {
    pub fn new() -> Self {
        Self {
            entity_type: None,
            facets: Vec::new(),
            renderer: None,
            filters: BTreeMap::new(),
            group_by: None,
            order_by: None,
            visible_fields: Vec::new(),
            limit: None,
        }
    }

    pub fn entity_type(mut self, t: impl Into<String>) -> Self {
        self.entity_type = Some(t.into());
        self
    }

    pub fn facets(mut self, facets: impl IntoIterator<Item = EntityFacet>) -> Self {
        self.facets = facets.into_iter().collect();
        self
    }

    pub fn renderer(mut self, renderer: ViewRenderer) -> Self {
        self.renderer = Some(renderer);
        self
    }

    pub fn filter(mut self, key: impl Into<String>, value: Value) -> Self {
        self.filters.insert(key.into(), value);
        self
    }

    pub fn group_by(mut self, field: impl Into<String>) -> Self {
        self.group_by = Some(field.into());
        self
    }

    pub fn order_by(mut self, field: impl Into<String>) -> Self {
        self.order_by = Some(field.into());
        self
    }

    pub fn limit(mut self, n: u64) -> Self {
        self.limit = Some(n);
        self
    }
}

impl Default for ViewQuery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn entity_round_trip_serde() {
        let entity = Entity::new("e1", "cx:space:s1", EntityType::Task, "did:web:alice")
            .with_data("title", json!("Buy milk"))
            .with_data("priority", json!("high"))
            .with_tag("shopping")
            .with_facets([EntityFacet::Stateful, EntityFacet::Rankable]);

        let json = serde_json::to_string(&entity).unwrap();
        let parsed: Entity = serde_json::from_str(&json).unwrap();
        assert_eq!(entity, parsed);
        assert_eq!(
            parsed.facets,
            vec![EntityFacet::Stateful, EntityFacet::Rankable]
        );
    }

    #[test]
    fn entity_unknown_facets_round_trip() {
        let entity = Entity::new("e1", "cx:space:s1", EntityType::Task, "did:web:alice")
            .with_facets([
                EntityFacet::Renderable,
                EntityFacet::Unknown("com.example.searchable".to_owned()),
            ]);

        let json = serde_json::to_string(&entity).unwrap();
        assert!(json.contains("com.example.searchable"));
        let parsed: Entity = serde_json::from_str(&json).unwrap();
        assert_eq!(entity, parsed);
        assert_eq!(
            unknown_entity_facets(&parsed.facets),
            vec!["com.example.searchable".to_owned()]
        );
    }

    #[test]
    fn relation_round_trip_serde() {
        let rel = Relation::new(
            "r1",
            "cx:space:s1",
            RelationType::DependsOn,
            "e1",
            "e2",
            "did:web:bob",
        );
        let json = serde_json::to_string(&rel).unwrap();
        let parsed: Relation = serde_json::from_str(&json).unwrap();
        assert_eq!(rel, parsed);
    }

    #[test]
    fn entity_type_from_str_standard_types() {
        assert_eq!(EntityType::from_str("task"), EntityType::Task);
        assert_eq!(EntityType::from_str("message"), EntityType::Message);
        assert_eq!(
            EntityType::from_str("custom_thing"),
            EntityType::Custom("custom_thing".into())
        );
    }

    #[test]
    fn entity_type_as_str_round_trip() {
        let types = vec![
            EntityType::Board,
            EntityType::Task,
            EntityType::Message,
            EntityType::Topic,
            EntityType::Channel,
            EntityType::Document,
            EntityType::File,
            EntityType::Memory,
            EntityType::Run,
            EntityType::ActorProfile,
            EntityType::Poll,
            EntityType::Custom("com.example.custom".into()),
        ];
        for t in types {
            assert_eq!(EntityType::from_str(t.as_str()), t);
        }
    }

    #[test]
    fn view_query_builder() {
        let q = ViewQuery::new()
            .entity_type("task")
            .facets([EntityFacet::Stateful, EntityFacet::Rankable])
            .renderer(ViewRenderer::Board)
            .filter("status", json!("open"))
            .order_by("created_at")
            .limit(50);

        assert_eq!(q.entity_type.as_deref(), Some("task"));
        assert_eq!(q.facets, vec![EntityFacet::Stateful, EntityFacet::Rankable]);
        assert_eq!(q.renderer, Some(ViewRenderer::Board));
        assert_eq!(q.filters.get("status").unwrap(), &json!("open"));
        assert_eq!(q.limit, Some(50));
    }

    #[test]
    fn view_renderer_unknown_round_trip() {
        let q = ViewQuery::new().renderer(ViewRenderer::Unknown("swimlane".to_owned()));

        let json = serde_json::to_string(&q).unwrap();
        assert!(json.contains("swimlane"));
        let parsed: ViewQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.renderer,
            Some(ViewRenderer::Unknown("swimlane".to_owned()))
        );
    }

    #[test]
    fn entity_render_kind_prefers_server_renderer_then_renderable_facet() {
        assert_eq!(
            choose_entity_render_kind(&[EntityFacet::Renderable], Some(&ViewRenderer::Thread)),
            EntityRenderKind::Message
        );
        assert_eq!(
            choose_entity_render_kind(&[EntityFacet::Renderable], Some(&ViewRenderer::Graph)),
            EntityRenderKind::Node
        );
        assert_eq!(
            choose_entity_render_kind(&[EntityFacet::Renderable], Some(&ViewRenderer::Table)),
            EntityRenderKind::Table
        );
        assert_eq!(
            choose_entity_render_kind(&[EntityFacet::Renderable], None),
            EntityRenderKind::Card
        );
        assert_eq!(choose_entity_render_kind(&[], None), EntityRenderKind::Row);
    }

    #[test]
    fn notification_round_trip_serde() {
        let n = Notification {
            notification_id: "n1".into(),
            actor: "did:web:alice".into(),
            space_id: "cx:space:s1".into(),
            kind: "mention".into(),
            title: "You were mentioned".into(),
            body: "@alice check this out".into(),
            entity_id: Some("e1".into()),
            read: false,
            archived: false,
            created_at: "2026-01-01T00:00:00Z".into(),
            action_url: None,
        };
        let json = serde_json::to_string(&n).unwrap();
        let parsed: Notification = serde_json::from_str(&json).unwrap();
        assert_eq!(n, parsed);
    }

    #[test]
    fn capability_grant_with_constraints() {
        let grant = CapabilityGrant {
            grant_id: "g1".into(),
            issuer: "did:web:admin".into(),
            subject: "did:web:alice".into(),
            resource_selectors: vec!["cx:space:s1".into()],
            actions: vec!["read".into(), "create_entity".into()],
            constraints: vec![GrantConstraint {
                constraint_type: "temporal".into(),
                params: json!({"expires_at": "2026-12-31T23:59:59Z"}),
            }],
            proofs: vec![],
            max_delegation_depth: Some(2),
            created_at: "2026-01-01T00:00:00Z".into(),
            expires_at: Some("2026-12-31T23:59:59Z".into()),
        };
        let json = serde_json::to_string(&grant).unwrap();
        let parsed: CapabilityGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(grant, parsed);
    }
}
