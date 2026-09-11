//! Projection view models for the self-API client.

use serde::Deserialize;

/// Server-side Space-container projection row.
///
/// Soland serves these rows from
/// `GET /_arkret/self/realms/{realm_id}/spaces`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct SpaceContainerProjectionView {
    pub space_id: String,
    pub realm_id: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub title: String,
    pub state: arkret_sdk::ProjectionSpaceState,
    #[serde(default)]
    pub rank: Option<String>,
    #[serde(default)]
    pub parent_space_id: Option<String>,
}

/// One RSVP cell keyed by occurrence and responder.
#[derive(Clone, Debug, Default, PartialEq, serde::Deserialize)]
pub struct RsvpCellProjectionView {
    /// `null` is the whole series; a string is a canonical instance key.
    #[serde(default)]
    pub occurrence: Option<String>,
    #[serde(default)]
    pub actor_id: String,
    #[serde(default)]
    pub heads: Vec<RsvpHeadProjectionView>,
}

/// One `mv_register` head. `entry` is the complete signed lattice value.
#[derive(Clone, Debug, Default, PartialEq, serde::Deserialize)]
pub struct RsvpHeadProjectionView {
    #[serde(default)]
    pub source_event_id: String,
    #[serde(default)]
    pub source_event_digest: String,
    #[serde(default)]
    pub entry: serde_json::Value,
}

/// Server-side Strand row from `GET /_arkret/self/realms/{realm_id}/strands`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct StrandProjectionView {
    pub strand_id: String,
    pub realm_id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub summary: Option<String>,
    /// Strand Description — the canonical top-level `content` ContentBlock.
    /// Mutual exclusion with
    /// [`Self::encrypted_content`] and the binding to [`Self::state`] are
    /// fixed by that schema and by the SDK `Strand`, so this carries the
    /// authoritative type rather than a raw value paired with a discriminator.
    #[serde(default)]
    pub content: Option<arkret_sdk::ContentBlock>,
    /// E2EE dual of [`Self::content`]: the `encrypted_content` envelope whose
    /// plaintext is a ContentBlock.
    #[serde(default)]
    pub encrypted_content: Option<arkret_sdk::EncryptedEnvelope>,
    /// Canonical Strand track map. Synthesis content lives inside the
    /// `synthesis` entry; Discussion content is represented by Messages.
    #[serde(default)]
    pub tracks: std::collections::BTreeMap<String, arkret_sdk::StrandTrack>,
    #[serde(default)]
    pub board_space_id: Option<String>,
    #[serde(default)]
    pub list_space_id: Option<String>,
    #[serde(default)]
    pub rank: Option<String>,
    #[serde(default)]
    pub assigned_actor_ids: Vec<arkret_sdk::ActorId>,
    #[serde(default)]
    pub assigned_to_relations: Vec<AssignedToRelationProjectionView>,
    #[serde(default)]
    /// Open profile field projection keyed by profile-defined field name.
    /// Lifecycle `state` does not discriminate this map's value shapes.
    pub fields: serde_json::Map<String, serde_json::Value>,
    /// Profile activation axis; its calendar entry and the
    /// `metadata.fields.calendar` subtree co-occur in both directions.
    #[serde(default)]
    pub schema_refs: Vec<String>,
    /// Canonical schedule revision frontier as `event_digest` values. RSVP
    /// authoring signs a subset of this, so an empty frontier is what keeps the
    /// RSVP path fail-closed.
    #[serde(default)]
    pub schedule_revision_heads: Vec<String>,
    /// Live RSVP `mv_register` heads for this Strand. Concurrent responses stay
    /// side by side; the UI shows them as an unresolved conflict rather than
    /// silently choosing one.
    #[serde(default)]
    pub rsvps: Vec<RsvpCellProjectionView>,
    /// Object lifecycle from the authoritative projection contract.
    pub state: arkret_sdk::ProjectionObjectState,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_by: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct AssignedToRelationProjectionView {
    pub relation_id: String,
    pub actor_id: arkret_sdk::ActorId,
}

impl From<arkret_sdk::ProjectionSpaceRow> for SpaceContainerProjectionView {
    fn from(row: arkret_sdk::ProjectionSpaceRow) -> Self {
        Self {
            space_id: row.space_id.as_str().to_owned(),
            realm_id: row.realm_id.as_str().to_owned(),
            kind: row.kind,
            title: row.title,
            state: row.state,
            rank: row.rank,
            parent_space_id: row
                .parent_space_id
                .map(|space_id| space_id.as_str().to_owned()),
        }
    }
}

impl From<arkret_sdk::ProjectionAssignedToRelation> for AssignedToRelationProjectionView {
    fn from(relation: arkret_sdk::ProjectionAssignedToRelation) -> Self {
        Self {
            relation_id: relation.relation_id.as_str().to_owned(),
            actor_id: relation.actor_id,
        }
    }
}

impl From<arkret_sdk::ProjectionStrandRow> for StrandProjectionView {
    fn from(row: arkret_sdk::ProjectionStrandRow) -> Self {
        Self {
            strand_id: row.strand_id.as_str().to_owned(),
            realm_id: row.realm_id.as_str().to_owned(),
            title: row.title.unwrap_or_default(),
            summary: row.summary,
            // The SDK strand projection row carries neither Strand content nor
            // `metadata.fields`; the server never emits them on this endpoint,
            // so they default to empty. The same applies to the calendar
            // activation axis and schedule frontier, so a card built from this
            // row keeps RSVP authoring fail-closed until the richer projection
            // read supplies them.
            content: None,
            encrypted_content: None,
            tracks: std::collections::BTreeMap::new(),
            schema_refs: Vec::new(),
            rsvps: Vec::new(),
            schedule_revision_heads: Vec::new(),
            board_space_id: row
                .board_space_id
                .map(|space_id| space_id.as_str().to_owned()),
            list_space_id: row
                .list_space_id
                .map(|space_id| space_id.as_str().to_owned()),
            rank: row.rank,
            assigned_actor_ids: row.assigned_actor_ids,
            assigned_to_relations: row
                .assigned_to_relations
                .into_iter()
                .map(Into::into)
                .collect(),
            fields: serde_json::Map::new(),
            state: row.state,
            created_by: row
                .created_by
                .map(|actor| actor.signing_principal_id().as_str().to_owned()),
            created_at: row
                .created_at
                .map(arkret_sdk::canonical::format_timestamp_canonical),
            updated_by: row
                .updated_by
                .map(|actor| actor.signing_principal_id().as_str().to_owned()),
            updated_at: row
                .updated_at
                .map(arkret_sdk::canonical::format_timestamp_canonical),
        }
    }
}
