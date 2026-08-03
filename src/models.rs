use std::collections::BTreeMap;

use arkret_sdk::protocol_journey::ContactScope;
pub use arkret_sdk::{
    ClaimedProfileEntry, CompatSurfaceEntry, ContactAgentProjection as ContactAgentRow,
    ContactList as ContactListView, ContactListRow, DirectConversationSummary, ServiceDescribe,
    VerifiedProfileEntry,
};
use arkret_wire::ProfileId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// App-local current-account projection derived from the spec
/// `ak.self.account.query.viewer` response. `handle` is populated only from a
/// signed `primary_handle_claim.handle`; an empty string means the server did
/// not include handle evidence in the viewer response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CurrentAccount {
    pub did: String,
    #[serde(default)]
    pub handle: String,
    pub display_name: Option<String>,
    #[serde(default)]
    pub created_at: String,
}

/// A6.1 — app-local global search projection. The shape is used by the
/// local decrypted client-index path; the Arkret HTTP catalog intentionally
/// has no spec-defined global plaintext search endpoint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IndexSearchView {
    pub query: String,
    #[serde(default)]
    pub results: Vec<Value>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

pub fn contact_state_wire(state: arkret_sdk::ContactState) -> &'static str {
    match state {
        arkret_sdk::ContactState::PendingOutgoing => "pending_outgoing",
        arkret_sdk::ContactState::PendingIncoming => "pending_incoming",
        arkret_sdk::ContactState::Accepted => "accepted",
        arkret_sdk::ContactState::Rejected => "rejected",
        arkret_sdk::ContactState::Tombstoned => "tombstoned",
        arkret_sdk::ContactState::Expired => "expired",
    }
}

pub fn direct_conversation_binding_state_wire(
    state: arkret_sdk::DirectConversationSummaryState,
) -> &'static str {
    match state {
        arkret_sdk::DirectConversationSummaryState::Found => "found",
        arkret_sdk::DirectConversationSummaryState::Suspended => "suspended",
    }
}

pub fn contact_peer_id(contact: &ContactListRow) -> &arkret_sdk::Did {
    contact.peer.subject_id()
}

pub fn contact_scope_wire(scope: ContactScope) -> &'static str {
    match scope {
        ContactScope::Invite => "invite",
        ContactScope::DirectMessage => "direct_message",
        ContactScope::VoiceCall => "voice_call",
        ContactScope::VideoCall => "video_call",
        ContactScope::Presence => "presence",
    }
}

pub fn contact_grants_me_invite(contact: &ContactListRow) -> bool {
    contact
        .granted_by_peer_scopes
        .contains(&ContactScope::Invite)
        || contact.bidirectional_scopes.contains(&ContactScope::Invite)
        || contact
            .effective_scopes
            .as_ref()
            .is_some_and(|scopes| scopes.contains(&ContactScope::Invite))
}

/// U4 - actor `invite_receive_policy` ("who can invite me").
///
/// YOU-01-006: this used to be a bespoke local mirror with all-`String`
/// enum fields and **no** `schema`/`subject_id` — which made the SET body
/// fail closed against the real soland handler (it deserialises
/// `arkret_sdk::InviteReceivePolicy`, `deny_unknown_fields`, with both
/// fields required and `subject_id == session.actor` enforced) and dropped
/// the server-stored `trusted_*` / `denied_principal_services` lists on
/// every round-trip. We now use the SDK authoritative type, which carries
/// the required `schema`/`subject_id`, typed enums, and the trust lists, so
/// a GET→edit→SET cycle preserves fields the U4 form does not touch.
pub use arkret_models_collaboration::governance::invite_addressing::{
    DisclosureLevel, DisclosurePolicy as InviteDisclosurePolicy, InviteReceivePolicy,
};
pub use arkret_wire::{InviteReceiveAction, UnknownInviteAction};

/// R15: result of `ak.realm.create`. Carries a `ak:realm:*` id under the
/// canonical `realm_id` field (was previously squeezed into a shared
/// `space_id` on the old shared lifecycle result). `state` replaces the old
/// `deleted: bool`, matching the spec lifecycle-state enum
/// (`active` / `archived` / `tombstoned`, `common-fields.md §5.1`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RealmCreateResult {
    pub ok: bool,
    pub realm_id: String,
    pub owner: String,
    #[serde(default)]
    pub members: Vec<String>,
    pub state: String,
}

/// R15: result of `ak.space.create`. A Space (`ak:space:*`) lives inside a
/// Realm and inherits its membership / encryption. `state` mirrors the spec
/// lifecycle enum (see [`RealmCreateResult`]).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpaceCreateResult {
    pub ok: bool,
    pub space_id: String,
    pub owner: String,
    #[serde(default)]
    pub members: Vec<String>,
    pub state: String,
}

// (Move/Seal pipeline DTOs deleted; all writes now go through
// ak.self.events.command.submit via SubmitEventResult.)

/// Return whether the canonical service description advertises a profile.
pub fn service_supports_profile(description: &ServiceDescribe, profile: &str) -> bool {
    description
        .supported_profiles
        .iter()
        .any(|value| value == profile)
}

pub fn service_supports_operation(description: &ServiceDescribe, operation_id: &str) -> bool {
    description
        .supported_operations
        .iter()
        .any(|value| value == operation_id)
}

pub fn missing_event_envelope_write_requirements(
    description: &ServiceDescribe,
) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if !service_supports_profile(description, ProfileId::CORE_EVENT_STORE_V1)
        && !service_supports_profile(description, ProfileId::PRINCIPAL_SERVER_EVENTS_API_V1)
    {
        missing.push(ProfileId::CORE_EVENT_STORE_V1);
    }
    if !service_supports_operation(
        description,
        arkret_sdk::ServiceOperationId::SELF_EVENTS_QUERY_DESCRIBE,
    ) {
        missing.push(arkret_sdk::ServiceOperationId::SELF_EVENTS_QUERY_DESCRIBE);
    }
    if !service_supports_operation(
        description,
        arkret_sdk::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT,
    ) {
        missing.push(arkret_sdk::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT);
    }
    missing
}

pub fn service_supports_event_envelope_write_plane(description: &ServiceDescribe) -> bool {
    missing_event_envelope_write_requirements(description).is_empty()
}

pub fn missing_v1_principal_server_requirements(
    description: &ServiceDescribe,
) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if description.service_kind != arkret_sdk::ServiceKind::PrincipalServer {
        missing.push("service_kind=principal_server");
    }
    if description.protocol_version != "1.0" {
        missing.push("protocol_version=1.0");
    }
    missing.extend(missing_event_envelope_write_requirements(description));
    missing
}

pub fn service_is_v1_principal_server_ready(description: &ServiceDescribe) -> bool {
    missing_v1_principal_server_requirements(description).is_empty()
}

// R35: `ak.identity.describe` body. The SDK's canonical type is
// `IdentityDescription` (same fields, with `service_id: Did` validated on
// construction); the SDK's own `IdentityDescribeOutcome` is a transparent
// newtype around it. We re-export the inner struct under the inkson-local
// name so call sites (`registry_mode` read in `views/dashboard.rs`) stay
// unchanged while the field shapes are now SDK-owned.
// `ak.self.account.query.describe` decodes into the SDK's authoritative
// `arkret_sdk::ServiceDescribe`; the former inkson-local describe mirror was
// removed in favor of the wire type.
/// App runtime state derived from validated canonical account-subscribe frames.
/// Wire ownership remains in `AccountSubscribeBatch` and `SyncUpdates`; the
/// JSON map is only the heterogeneous local projection consumed by UI reducers.
#[derive(Clone, Debug)]
pub struct AccountSyncStep {
    pub cursor: String,
    pub updates: arkret_sdk::SyncUpdates,
    /// Canonical SDK Realm entries retained after sync decoding. Product
    /// projections may derive JSON views for heterogeneous reducers, but
    /// security decisions (for example Direct Conversation MLS admission)
    /// must use this typed source.
    pub realm_entries: BTreeMap<arkret_sdk::RealmId, arkret_sdk::RealmSyncEntry>,
    pub realm_projections: BTreeMap<String, Value>,
}

impl AccountSyncStep {
    pub fn from_batch(batch: arkret_sdk::AccountSubscribeBatch) -> arkret_sdk::Result<Self> {
        let cursor = batch.cursor.clone();
        let mut processor = garth::SyncResponseProcessor::new();
        let updates = processor
            .process(batch)
            .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))?;
        Self::from_updates(cursor, updates)
    }

    pub fn from_updates(
        cursor: String,
        updates: arkret_sdk::SyncUpdates,
    ) -> arkret_sdk::Result<Self> {
        let realm_entries = updates
            .realm_updates
            .iter()
            .map(|update| (update.realm_id.clone(), update.entry.clone()))
            .collect();
        let realm_projections = updates
            .realm_updates
            .iter()
            .map(|update| {
                serde_json::to_value(&update.entry)
                    .map(|value| (update.realm_id.as_str().to_owned(), value))
                    .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))
            })
            .collect::<arkret_sdk::Result<BTreeMap<_, _>>>()?;
        Ok(Self {
            cursor,
            updates,
            realm_entries,
            realm_projections,
        })
    }

    pub fn collaboration_role(&self, realm_id: &str) -> Option<arkret_sdk::CollaborationRealmRole> {
        self.realm_entries
            .iter()
            .find(|(id, _)| id.as_str() == realm_id)
            .and_then(|(_, entry)| entry.state_at_window_start.as_ref())
            .and_then(|state| state.realm_metadata.collaboration_role)
    }

    pub fn has_window_start_realm_metadata(&self, realm_id: &str) -> bool {
        self.realm_entries
            .iter()
            .find(|(id, _)| id.as_str() == realm_id)
            .is_some_and(|(_, entry)| entry.state_at_window_start.is_some())
    }
}

// `resolve-realm` decodes into the canonical SDK wire types so the client stays
// byte-compatible with soland's `DirectoryRealmResolutionOutcome` response. A
// inkson-local duplicate previously drifted from the wire (a required
// `public`/`title` on the preview node, a non-optional `join_rule`) and broke
// invite-accept with "error decoding response body" whenever the server omitted
// those fields. The SDK type is the single source of truth.
pub use arkret_models_discovery::{
    DirectoryRealmResolutionOutcome as ResolveRealmOutcome, RealmJoinCandidate,
};
pub use arkret_models_identity::{
    IdentityDescription as IdentityDescribeOutcome, IdentityResolveOutcome,
};

/// Sidebar tag distinguishing a security-boundary Realm from a product
/// Space. Wire signal is either the `ak.schema.{realm,space}.v1` schema
/// field on a projection body, or a inkson-local `__kind` tag used by
/// optimistic post-create state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmTreeNodeKind {
    /// `ak:realm:*` — security / sync / E2EE boundary.
    #[default]
    Realm,
    /// `ak:space:*` — navigation container inside a Realm.
    Space,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RealmTreeNode {
    /// Navigation node id. Realm nodes hold `ak:realm:*`; Space nodes hold
    /// `ak:space:*`. Do not put Realm ids in a `space_id` field.
    pub id: String,
    /// Canonical display name. Spec `realm.schema.json` / `space.schema.json`
    /// both make `title` the required display field; `name` is reserved for
    /// external protocol / algorithm / service labels.
    pub title: String,
    pub description: Option<String>,
    pub tags: std::collections::BTreeSet<String>,
    pub public: bool,
    pub category: Option<String>,
    pub direct_conversation: bool,
    pub parent_space_id: Option<String>,
    pub child_space_ids: Vec<String>,
    /// Realm vs Space classification used by the sidebar to render
    /// the two as separate tiers. Spec realm-and-space.md §1 / §3.
    pub kind: RealmTreeNodeKind,
    /// Home Realm of this entry. For Realm nodes this equals `id`; for Space
    /// nodes this is the containing Realm id.
    pub realm_id: String,
}

impl Serialize for RealmTreeNode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("RealmTreeNode", 11)?;
        match self.kind {
            RealmTreeNodeKind::Realm => state.serialize_field("realm_id", &self.id)?,
            RealmTreeNodeKind::Space => {
                state.serialize_field("space_id", &self.id)?;
                state.serialize_field("realm_id", &self.realm_id)?;
            }
        }
        state.serialize_field("title", &self.title)?;
        state.serialize_field("description", &self.description)?;
        state.serialize_field("tags", &self.tags)?;
        state.serialize_field("public", &self.public)?;
        state.serialize_field("category", &self.category)?;
        state.serialize_field("direct_conversation", &self.direct_conversation)?;
        state.serialize_field("parent_space_id", &self.parent_space_id)?;
        state.serialize_field("child_space_ids", &self.child_space_ids)?;
        state.serialize_field("kind", &self.kind)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for RealmTreeNode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(default)]
            space_id: Option<String>,
            #[serde(default)]
            realm_id: Option<String>,
            title: String,
            description: Option<String>,
            #[serde(default)]
            tags: std::collections::BTreeSet<String>,
            public: bool,
            category: Option<String>,
            #[serde(default)]
            direct_conversation: bool,
            #[serde(default)]
            parent_space_id: Option<String>,
            #[serde(default)]
            child_space_ids: Vec<String>,
            #[serde(default)]
            kind: RealmTreeNodeKind,
        }

        let wire = Wire::deserialize(deserializer)?;
        let id = match wire.kind {
            RealmTreeNodeKind::Realm => wire
                .realm_id
                .clone()
                .ok_or_else(|| serde::de::Error::missing_field("realm_id"))?,
            RealmTreeNodeKind::Space => wire
                .space_id
                .clone()
                .ok_or_else(|| serde::de::Error::missing_field("space_id"))?,
        };
        let realm_id = match wire.kind {
            RealmTreeNodeKind::Realm => id.clone(),
            RealmTreeNodeKind::Space => wire
                .realm_id
                .ok_or_else(|| serde::de::Error::missing_field("realm_id"))?,
        };
        Ok(Self {
            id,
            title: wire.title,
            description: wire.description,
            tags: wire.tags,
            public: wire.public,
            category: wire.category,
            direct_conversation: wire.direct_conversation,
            parent_space_id: wire.parent_space_id,
            child_space_ids: wire.child_space_ids,
            kind: wire.kind,
            realm_id,
        })
    }
}

impl RealmTreeNode {
    pub fn projection_realm_id(&self) -> &str {
        if self.kind == RealmTreeNodeKind::Space && !self.realm_id.trim().is_empty() {
            self.realm_id.trim()
        } else {
            self.id.as_str()
        }
    }
}

pub fn projection_realm_id_for_node(nodes: &[RealmTreeNode], node_id: &str) -> String {
    let requested = node_id.trim();
    projection_realm_id_for_known_node(nodes, requested).unwrap_or_else(|| requested.to_owned())
}

pub fn projection_realm_id_for_known_node(
    nodes: &[RealmTreeNode],
    node_id: &str,
) -> Option<String> {
    let requested = node_id.trim();
    if requested.is_empty() {
        return Some(String::new());
    }
    let by_id: std::collections::BTreeMap<&str, &RealmTreeNode> =
        nodes.iter().map(|node| (node.id.as_str(), node)).collect();
    let mut current = requested;
    let mut visited = std::collections::BTreeSet::new();

    while visited.insert(current.to_owned()) {
        let node = by_id.get(current).copied()?;
        let projection_realm_id = node.projection_realm_id();
        if projection_realm_id != node.id || node.kind == RealmTreeNodeKind::Realm {
            return Some(projection_realm_id.to_owned());
        }
        {
            let parent = node
                .parent_space_id
                .as_deref()
                .map(str::trim)
                .filter(|parent| !parent.is_empty())?;
            current = parent;
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use arkret_sdk::protocol_journey::ContactScope;
    use arkret_wire::SchemaId;

    use super::{
        RealmTreeNode, RealmTreeNodeKind, projection_realm_id_for_known_node,
        projection_realm_id_for_node,
    };

    #[test]
    fn submit_event_outcome_decodes_new_events_submit_wire() {
        // soland head 37ce729: {status, accepted[], cursor} — no top-level
        // event_id / sync_token. This is the shape that previously failed to
        // decode and broke every event submit ("error decoding response body").
        let value = serde_json::json!({
            "status": "accepted",
            "accepted": ["ak:event:0196419b-0000-7000-8000-000000000001"],
            "duplicate": [],
            "rejected": [],
            "realm_actor_frontiers": [],
            "realm_frontiers": [],
            "cursor": "sx:cursor-1",
        });
        let outcome: super::SubmitEventResult = serde_json::from_value(value).unwrap();
        assert_eq!(
            outcome.event_id,
            "ak:event:0196419b-0000-7000-8000-000000000001"
        );
        assert_eq!(outcome.status, "accepted");
        assert_eq!(outcome.cursor, "sx:cursor-1");
    }

    #[test]
    fn contact_list_sidebar_fixture_decodes_direct_chat_targets() {
        let value = serde_json::json!({
            "contacts": [{
                "peer": {"kind": "human", "principal_id": "did:web:bob.example"},
                "state": "accepted",
                "granted_to_peer_scopes": ["direct_message"],
                "granted_by_peer_scopes": ["direct_message"],
                "bidirectional_scopes": ["direct_message"],
                "effective_scopes": ["direct_message"],
                "direct_conversation": {
                    "realm_id": "ak:realm:01964137-0000-7000-8000-00000000d0b1",
                    "main_strand_id": "ak:strand:01964137-0000-7000-8000-00000000d0b2",
                    "binding_event_ref": "ak:event:0196419b-0000-7000-8000-000000000103",
                    "state": "found"
                },
                "agents": [{
                    "agent_id": "did:web:agents.example:bob-helper",
                    "controller_id": "did:web:bob.example",
                    "display_name": "Bob Helper",
                    "agent_slug": "helper",
                    "avatar_blob_ref": "ak:blob:sha256:431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460",
                    "direct_conversation": {
                        "realm_id": "ak:realm:01964137-0000-7000-8000-0000000000b1",
                        "main_strand_id": "ak:strand:01964137-0000-7000-8000-0000000000b2",
                        "binding_event_ref": "ak:event:01964137-0000-7000-8000-0000000000b3",
                        "state": "found"
                    }
                }]
            }],
            "next_cursor": null,
            "has_more": false
        });
        let decoded: arkret_sdk::ContactList = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.contacts.len(), 1);
        assert_eq!(decoded.contacts[0].agents.len(), 1);
    }

    #[test]
    fn submit_event_outcome_rejects_removed_flat_wire() {
        // renames.json rejection policy: the removed flat `{event_id,
        // sync_token, …}` shape MUST NOT decode — canonical-only parser.
        let value = serde_json::json!({
            "event_id": "ak:event:removed",
            "status": "accepted",
            "sync_token": "sx:removed",
        });
        assert!(serde_json::from_value::<super::SubmitEventResult>(value).is_err());
    }

    #[test]
    fn submit_event_outcome_uses_duplicate_id_when_nothing_accepted() {
        let value = serde_json::json!({
            "status": "duplicate",
            "accepted": [],
            "duplicate": ["ak:event:0196419b-0000-7000-8000-000000000002"],
        });
        let outcome: super::SubmitEventResult = serde_json::from_value(value).unwrap();
        assert_eq!(
            outcome.event_id,
            "ak:event:0196419b-0000-7000-8000-000000000002"
        );
        assert_eq!(outcome.status, "duplicate");
        assert_eq!(outcome.cursor, "");
    }

    fn preview(
        id: &str,
        kind: RealmTreeNodeKind,
        realm_id: &str,
        parent: Option<&str>,
    ) -> RealmTreeNode {
        RealmTreeNode {
            id: id.to_owned(),
            title: id.to_owned(),
            description: None,
            tags: Default::default(),
            public: true,
            category: None,
            direct_conversation: false,
            parent_space_id: parent.map(ToOwned::to_owned),
            child_space_ids: Vec::new(),
            kind,
            realm_id: if kind == RealmTreeNodeKind::Realm && realm_id.is_empty() {
                id.to_owned()
            } else {
                realm_id.to_owned()
            },
        }
    }

    #[test]
    fn projection_realm_id_uses_space_home_realm() {
        let spaces = vec![
            preview("ak:realm:root", RealmTreeNodeKind::Realm, "", None),
            preview(
                "ak:space:child",
                RealmTreeNodeKind::Space,
                "ak:realm:root",
                Some("ak:realm:root"),
            ),
        ];

        assert_eq!(
            projection_realm_id_for_node(&spaces, "ak:space:child"),
            "ak:realm:root"
        );
    }

    #[test]
    fn projection_realm_id_climbs_parent_links_to_realm() {
        let spaces = vec![
            preview("ak:realm:root", RealmTreeNodeKind::Realm, "", None),
            preview(
                "ak:space:child",
                RealmTreeNodeKind::Space,
                "",
                Some("ak:realm:root"),
            ),
        ];

        assert_eq!(
            projection_realm_id_for_node(&spaces, "ak:space:child"),
            "ak:realm:root"
        );
    }

    #[test]
    fn known_projection_realm_id_waits_for_unknown_routes() {
        assert_eq!(
            projection_realm_id_for_known_node(&[], "ak:space:child"),
            None
        );
    }

    #[test]
    fn invite_receive_policy_round_trips_sdk_wire_with_trust_lists() {
        // YOU-01-006 — the bare SDK wire body (schema + subject_id required,
        // typed enums, trust lists) must decode and re-encode without losing
        // the `trusted_*` / `denied_principal_services` lists the U4 form
        // never touches.
        let value = serde_json::json!({
            "schema": SchemaId::INVITE_RECEIVE_POLICY_V1,
            "subject_id": "did:web:me.example",
            "holder_allowed_introduction_kinds": ["consent_grant", "locator_ref"],
            "explicit_address_behavior": "drop",
            "unknown_invites": "quarantine",
            "trusted_realm_ids": ["ak:realm:01904100-0000-7000-8000-000000000001"],
            "trusted_principal_services": ["did:web:ps.example"],
            "denied_subjects": ["did:web:spammer.example"],
            "disclosure": {"high_trust": "opaque", "low_trust": "opaque"},
        });
        let policy: super::InviteReceivePolicy =
            serde_json::from_value(value).expect("decode SDK policy wire");
        assert_eq!(
            policy.explicit_address_behavior,
            super::InviteReceiveAction::Drop
        );
        // The trust lists survive a re-encode (no silent wipe on save).
        let re = serde_json::to_value(&policy).expect("re-encode policy");
        assert_eq!(re["trusted_principal_services"][0], "did:web:ps.example");
        assert_eq!(
            re["trusted_realm_ids"][0],
            "ak:realm:01904100-0000-7000-8000-000000000001"
        );
    }

    #[test]
    fn default_invite_receive_policy_carries_schema_and_subject() {
        let subject_id = arkret_sdk::Did::new("did:web:me.example").unwrap();
        let policy = super::InviteReceivePolicy::spec_default(subject_id);
        assert_eq!(policy.schema, SchemaId::INVITE_RECEIVE_POLICY_V1);
        assert_eq!(policy.subject_id.as_str(), "did:web:me.example");
        assert_eq!(
            policy.explicit_address_behavior,
            super::InviteReceiveAction::Quarantine
        );
        assert_eq!(policy.unknown_invites, super::UnknownInviteAction::Drop);
    }

    #[test]
    fn contact_row_invite_gate_uses_directional_contact_scopes() {
        let row = super::ContactListRow {
            peer: arkret_sdk::protocol_journey::ContactPeer::Human {
                principal_id: arkret_sdk::Did::new("did:web:bob.example".to_owned()).unwrap(),
            },
            state: arkret_sdk::ContactState::Accepted,
            request_event_ref: None,
            response_event_ref: Some(
                arkret_sdk::EventId::new(
                    "ak:event:01904100-0000-7000-8000-000000000001".to_owned(),
                )
                .unwrap(),
            ),
            tombstone_event_ref: None,
            granted_to_peer_scopes: Vec::new(),
            granted_by_peer_scopes: vec![ContactScope::Invite],
            bidirectional_scopes: Vec::new(),
            effective_scopes: Some(Vec::new()),
            peer_service_id: None,
            direct_conversation: None,
            agents: Vec::new(),
        };
        assert!(super::contact_grants_me_invite(&row));
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SnapshotBootstrapJson(pub arkret_sdk::SnapshotBootstrap);

impl From<arkret_sdk::SnapshotBootstrap> for SnapshotBootstrapJson {
    fn from(value: arkret_sdk::SnapshotBootstrap) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackfillView {
    #[serde(default)]
    pub events: Vec<arkret_sdk::Event>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_bootstrap: Option<SnapshotBootstrapJson>,
    pub prev_cursor: Option<String>,
    pub next_cursor: Option<String>,
    // Spec `EventsQueryOutcome.has_more` (was the soland-local `limited`).
    #[serde(default)]
    pub has_more: bool,
}

impl BackfillView {
    /// Convert SDK-typed events to JSON for projection reducers.
    pub fn event_values(&self) -> Vec<Value> {
        self.events
            .iter()
            .filter_map(|event| serde_json::to_value(event).ok())
            .collect()
    }
}

impl From<arkret_sdk::EventsQueryOutcome> for BackfillView {
    fn from(outcome: arkret_sdk::EventsQueryOutcome) -> Self {
        Self {
            events: outcome.events,
            snapshot_bootstrap: outcome.snapshot_bootstrap.map(Into::into),
            prev_cursor: outcome.prev_cursor,
            next_cursor: outcome.next_cursor,
            has_more: outcome.has_more,
        }
    }
}

// `ak.self.snapshot.query.manifest_head` returns the full signed
// `ak.schema.snapshot.v1` manifest. See `api::TransportClient::snapshot_head`.

pub use arkret_models_collaboration::governance::authorization::AuthzCheckOutcome;
/// `ak.self.authz.invites` decodes into the SDK's authoritative
/// `AuthzInviteList` (`invites: Vec<Invite>`, `next_cursor`, `has_more`); the
/// former inkson-local `InvitesView` mirror was removed in favor of the wire
/// type.
pub use arkret_models_collaboration::governance::authorization::AuthzInviteList;
/// `ak.self.authz.grants.query.effective` response. soland serialises the SDK
/// `GrantList` (`grants: Vec<CapabilityGrant>`) verbatim, so the client
/// decodes the same authoritative wire contract instead of a weakly-typed
/// local mirror.
pub use arkret_models_collaboration::governance::authorization::GrantList;
/// `POST /_arkret/self/moderation/report` response. soland emits the SDK
/// `ModerationReportOutcome` wire shape verbatim (`status: "submitted"`,
/// `routed_to: Vec<Did>` — scalar DIDs only, no fragments, per
/// `service-operation-dtos.schema.json#/$defs/ModerationReportOutcome`).
pub use arkret_models_collaboration::governance::moderation::ModerationReportOutcome;
pub use arkret_models_collaboration::objects::blob::BlobUploadOutcome;
pub use arkret_models_collaboration::sync_frames::account_sync::{
    DeviceMessageEnvelope, DeviceMessagesAckOutcome, DeviceMessagesAckRequestBody,
    DeviceMessagesGetOutcome, DeviceMessagesSendOutcome,
};
pub use arkret_models_crypto::{KeysClaimOutcome, KeysQueryOutcome, KeysUploadOutcome};
pub use arkret_models_integration::OkOutcome;
pub use arkret_models_integration::models_push::PushRegisterDeviceOutcome;

// ── Directory ───────────────────────────────────────────────────

pub type SearchOrganizationsView = arkret_models_discovery::DirectoryOrganizationSearchOutcome;
pub type SearchActorsView = arkret_models_discovery::DirectoryActorSearchOutcome;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DirectoryDidDocumentJson(pub Value);

impl std::fmt::Display for DirectoryDidDocumentJson {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolveHandleView {
    #[serde(default)]
    pub did: String,
    pub handle: String,
    pub did_document: Option<DirectoryDidDocumentJson>,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub claims: Option<Vec<arkret_models_identity::HandleClaim>>,
    /// Audience the directory bound the response claim to. Spec 0a5ab85:
    /// the client MUST reject claims whose audience doesn't match the
    /// invocation context (e.g. the Space the user is about to join).
    #[serde(default)]
    pub audience: Option<String>,
    /// Membership-builder routing evidence for `intent=member_add|invite`.
    /// Some directory implementations expose this top-level; others carry
    /// the same object inside `handle_claim.member_delivery_binding`.
    #[serde(default)]
    pub member_delivery_binding: Option<arkret_models_identity::DeliveryBindingHint>,
    /// Typed handle claim envelope when the directory issued one.
    #[serde(default)]
    pub handle_claim: Option<arkret_models_identity::HandleClaim>,
    /// §9.1 common resolve metadata.
    #[serde(default)]
    pub as_of: Option<String>,
    #[serde(default)]
    pub source_refs: Vec<String>,
    #[serde(default)]
    pub policy_revision: Option<String>,
    #[serde(default)]
    pub stale: bool,
    #[serde(default)]
    pub divergent: bool,
    #[serde(default)]
    pub via_services: Vec<String>,
}

impl ResolveHandleView {
    pub fn subject_did(&self) -> Option<&str> {
        (!self.did.trim().is_empty())
            .then_some(self.did.as_str())
            .or_else(|| {
                self.handle_claim
                    .as_ref()
                    .and_then(|claim| claim.subject.as_ref())
                    .map(|subject| subject.as_str())
            })
    }

    pub fn claim_audience(&self) -> Option<&str> {
        self.audience.as_deref().or_else(|| {
            self.handle_claim
                .as_ref()
                .and_then(|claim| claim.audience.as_deref())
        })
    }

    pub fn has_member_delivery_binding(&self) -> bool {
        self.member_delivery_binding_ref().is_some()
    }

    pub fn member_delivery_binding_ref(
        &self,
    ) -> Option<&arkret_models_identity::DeliveryBindingHint> {
        self.member_delivery_binding.as_ref().or_else(|| {
            self.handle_claim
                .as_ref()
                .and_then(|claim| claim.member_delivery_binding.as_ref())
        })
    }
}

impl From<arkret_models_discovery::DirectoryHandleResolutionOutcome> for ResolveHandleView {
    fn from(outcome: arkret_models_discovery::DirectoryHandleResolutionOutcome) -> Self {
        // The server-side `DirectoryHandleResolutionOutcome` has no
        // `did_document` field (this resolve endpoint never emits one), so it
        // is always `None` here — behavior-equivalent to the prior wire decode.
        Self {
            did: outcome.did.as_str().to_owned(),
            handle: outcome.handle,
            did_document: None,
            verified: outcome.verified,
            claims: outcome.claims,
            audience: outcome.audience,
            member_delivery_binding: outcome.member_delivery_binding,
            handle_claim: outcome.handle_claim,
            as_of: outcome
                .as_of
                .map(arkret_sdk::canonical::format_timestamp_canonical),
            source_refs: outcome.source_refs,
            policy_revision: outcome.policy_revision,
            stale: outcome.stale,
            divergent: outcome.divergent,
            via_services: outcome.via_services,
        }
    }
}

/// Structured mention node embedded in message body. Spec
/// `models/strand-and-message.md §9.4` + `identity/identity-handles.md §3.8`.
///
/// YOU-05-006: the former hand-rolled weakly-typed mirror (all-`String`
/// fields) duplicated the SDK's authoritative strongly-typed model
/// (`Did` / `Handle` / `DateTime<Utc>`) and had already drifted in field
/// declaration order. Re-export the SDK type; `subject_id` (principal
/// DID) remains the ONLY authoritative field — the `*_at_time` fields
/// are compose-time audit metadata only.
pub use arkret_models_collaboration::events_payloads::mention::Mention;

// ── Realm / Space Management ────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RealmPolicyResult {
    pub ok: bool,
    pub realm_id: String,
    pub join_rule: String,
    pub history_visibility: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TypingResult {
    pub ok: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PresenceResult {
    pub ok: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReceiptResult {
    pub ok: bool,
}

// ── Device & Crypto ─────────────────────────────────────────────

/// `ak.self.events.command.submit` response.
///
/// Decodes **only** the canonical `EventsSubmitOutcome` wire shape —
/// `{status, accepted[], duplicate[], rejected[], actor_frontier,
/// realm_frontier, cursor}` (spec
/// `service-operation-dtos.schema.json#/$defs/EventsSubmitOutcome`,
/// required: `status`, `accepted`). The inkson-facing flat surface is
/// folded from the SDK `EventsSubmitOutcome` on deserialize:
///   * `event_id` ← first `accepted` (else first `duplicate`)
///   * `cursor`   ← `cursor` (read-your-writes barrier)
///   * `status`   ← the `accepted` / `duplicate` / `partial` discriminant
///
/// Per renames.json rejection policy, the removed flat
/// `{event_id, sync_token, …}` shape is NOT tolerated — mocks must emit
/// the canonical shape. Ids stay plain `String`s so synthetic fixture ids
/// do not trip the strict `EventId` validator.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SubmitEventResult {
    pub event_id: String,
    pub status: String,
    #[serde(default)]
    pub cursor: String,
    #[serde(default)]
    pub receipt: Value,
    /// Typed `ingress_receipts[]` from the outcome.
    ///
    /// These are the only evidence that the Event arrived inside its
    /// authorization-lease window, so they are kept as the SDK type rather
    /// than folded into the untyped `receipt` blob: the outbound queue rejects
    /// an acceptance that carries none, and matches each receipt against the
    /// lease the item was bound to.
    #[serde(default)]
    pub ingress_receipts: Vec<arkret_wire::IngressReceipt>,
}

impl From<arkret_sdk::EventsSubmitOutcome> for SubmitEventResult {
    fn from(outcome: arkret_sdk::EventsSubmitOutcome) -> Self {
        let accepted: Vec<String> = outcome
            .accepted
            .into_iter()
            .map(|event_id| event_id.as_str().to_owned())
            .collect();
        let duplicate: Vec<String> = outcome
            .duplicate
            .into_iter()
            .map(|event_id| event_id.as_str().to_owned())
            .collect();
        let event_id = accepted
            .first()
            .cloned()
            .or_else(|| duplicate.first().cloned())
            .unwrap_or_default();
        let status = match outcome.status {
            arkret_sdk::EventsSubmitStatus::Accepted => "accepted",
            arkret_sdk::EventsSubmitStatus::Duplicate => "duplicate",
            arkret_sdk::EventsSubmitStatus::Partial => "partial",
            arkret_sdk::EventsSubmitStatus::HistoricalOnly => "historical_only",
        }
        .to_owned();
        let receipt = serde_json::json!({
            "accepted": accepted,
            "duplicate": duplicate,
            "rejected": outcome.rejected,
            "quarantine": outcome
                .quarantine
                .into_iter()
                .map(|event_id| event_id.as_str().to_owned())
                .collect::<Vec<_>>(),
            "realm_actor_frontiers": outcome.realm_actor_frontiers,
            "realm_frontiers": outcome.realm_frontiers,
        });
        Self {
            event_id,
            status,
            cursor: outcome.cursor.unwrap_or_default(),
            receipt,
            ingress_receipts: outcome.ingress_receipts,
        }
    }
}

impl<'de> Deserialize<'de> for SubmitEventResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        // renames.json rejection policy: the SDK `EventsSubmitOutcome` does
        // not deny unknown fields (and defaults `accepted`), so the removed
        // flat `{event_id, sync_token, …}` legacy shape would otherwise decode
        // as an empty canonical outcome. Reject its marker keys explicitly so
        // the canonical-only guarantee holds.
        if value.get("event_id").is_some() || value.get("sync_token").is_some() {
            return Err(serde::de::Error::custom(
                "removed flat submit-outcome wire shape (event_id/sync_token) is not accepted",
            ));
        }
        let outcome = arkret_sdk::EventsSubmitOutcome::deserialize(value)
            .map_err(serde::de::Error::custom)?;
        Ok(outcome.into())
    }
}

// ── Media ────────────────────────────────────────────────────────

// YOU-05-004: the hand-rolled `IceConfigOutcome` / `IceServer` /
// `IceConfigRequestBody` mirrors drifted from the SDK wire types (missing
// `expires_at` / `turn_required`, `ttl_seconds: u64` vs the authoritative
// `u32`) and bypassed the TURN credential privacy guard. Re-export the
// SDK's authoritative types instead. When the WebRTC surface is wired up,
// each `ice_servers` entry MUST be parsed through `arkret_sdk::IceServer`
// and pass `IceServer::validate_credential_privacy()` (rejects TURN
// usernames embedding cross-Realm stable DIDs, B-14).
pub use arkret_models_collaboration::objects::media::{
    MediaIceConfigOutcome, MediaIceConfigRequestBody,
};

// WebRTC call signaling/recording no longer round-trips through bespoke
// `/_arkret/self/webrtc/*` outcomes: signaling is a `ak.call.signal`
// ephemeral envelope (EphemeralSubmitResult) and recording is a durable
// `ak.call.recording.start` event (SubmitEventResult). See
// `crypto-media/webrtc-signaling.md` §5/§7. The former
// CreateWebrtcSessionOutcome / WebrtcSignalOutcome / CallRecordingStartOutcome
// mirrors were removed (YOU-01-002).

// ─────────────────────────────────────────────────────────────────────
// AKP-0008 / AKP-0009 — Personal Agent HTTP wire types.
//
// YOU-01-005: the former hand-rolled `Agent*ReqBody` / `Agent*ResBody`
// mirrors drifted from `agent-operations.schema.json` (extra required
// fields, non-spec `todos`, wrong outcome shapes) and were removed. The
// agent surface now uses the SDK's authoritative types
// (`arkret_sdk::AgentProvisionOutcome` / `AgentList` / `AgentView` /
// `AgentGrantAttachOutcome` /
// Sidecar SDK DTOs directly in `views::agents`
// (via `with_authed_sdk_client`).
