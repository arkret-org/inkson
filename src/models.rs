use std::collections::BTreeMap;

use arkret_sdk::EventPayloadExt as _;
use arkret_sdk::contact_operations::ContactScope;
pub use arkret_sdk::{
    ClaimedProfileEntry, ContactAgentProjection, ContactList, ContactListRow,
    DirectConversationSummary, InteropSurfaceEntry, ServiceDescribe, VerifiedProfileEntry,
};
use arkret_wire::ProfileId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// App-local current-account projection derived from the spec
/// `ak.self.account.read.viewer.v1` response. `handle` is populated only from a
/// signed `primary_handle_claim.handle`; an empty string means the server did
/// not include handle evidence in the viewer response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CurrentAccount {
    /// Stable principal core id returned by `ak.self.account.read.viewer.v1`.
    ///
    /// This is deliberately typed as a core id: the account viewer does not
    /// return resolution material and callers must not persist this value as a
    /// DID or bind an Event signer to it.
    pub principal_id: arkret_sdk::DidCoreId,
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

pub fn contact_peer_id(contact: &ContactListRow) -> arkret_sdk::DidCoreId {
    contact
        .peer
        .contact_actor_id()
        .signing_principal_id()
        .clone()
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
/// This used to be a bespoke local mirror with all-`String`
/// enum fields and **no** `schema`/`subject_id` — which made the SET body
/// fail closed against the real soland handler (it deserialises
/// `arkret_sdk::InviteReceivePolicy`, `deny_unknown_fields`, with both
/// fields required and account authority equality enforced) and dropped
/// the server-stored `trusted_*` / `denied_source_ids` lists on
/// every round-trip. We now use the SDK authoritative type, which carries
/// the required `schema`/`account_id`, typed enums, and the trust lists, so
/// a GET→edit→SET cycle preserves fields the U4 form does not touch.
pub use arkret_models_collaboration::governance::invite_addressing::{
    DisclosureLevel, DisclosurePolicy, InviteReceivePolicy,
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
// ak.self.events.command.submit.v1 via SubmitEventResult.)

/// Return whether the canonical service description advertises a profile.
pub fn service_supports_profile(description: &ServiceDescribe, profile: &str) -> bool {
    description
        .supported_profiles
        .iter()
        .any(|value| value == profile)
}

pub fn service_supports_operation(description: &ServiceDescribe, operation_id: &str) -> bool {
    let Some(operation_id) = arkret_sdk::ServiceOperationId::from_wire(operation_id) else {
        return false;
    };
    description.supports_operation_binding(operation_id, arkret_sdk::BindingKind::HttpJson)
}

pub fn missing_event_envelope_write_requirements(
    description: &ServiceDescribe,
) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if !service_supports_profile(description, ProfileId::CORE_EVENT_STORE_V1)
        && !service_supports_profile(description, ProfileId::STATION_EVENTS_API_V1)
    {
        missing.push(ProfileId::CORE_EVENT_STORE_V1);
    }
    if !service_supports_operation(
        description,
        arkret_sdk::ServiceOperationId::SELF_EVENTS_READ_DESCRIBE_V1,
    ) {
        missing.push(arkret_sdk::ServiceOperationId::SELF_EVENTS_READ_DESCRIBE_V1);
    }
    if !service_supports_operation(
        description,
        arkret_sdk::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
    ) {
        missing.push(arkret_sdk::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1);
    }
    missing
}

pub fn service_supports_event_envelope_write_plane(description: &ServiceDescribe) -> bool {
    missing_event_envelope_write_requirements(description).is_empty()
}

pub fn missing_v1_station_requirements(description: &ServiceDescribe) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if description.service_kind != arkret_sdk::ServiceKind::Station {
        missing.push("service_kind=station");
    }
    if description.protocol_version.as_str() != arkret_sdk::PROTOCOL_VERSION {
        missing.push("protocol_version=1.0");
    }
    missing.extend(missing_event_envelope_write_requirements(description));
    missing
}

// `ak.self.account.read.describe.v1` decodes into the SDK's authoritative
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
                    .and_then(|mut value| {
                        project_member_roster_from_sdk_entry(&mut value, &update.entry)?;
                        project_default_strand_from_sdk_events(
                            &mut value,
                            update
                                .entry
                                .state
                                .iter()
                                .flat_map(|state| state.events.iter()),
                        );
                        Ok((update.realm_id.as_str().to_owned(), value))
                    })
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

/// Convert the SDK-owned account-sync roster container into Inkson's single
/// local Realm projection shape. Local projection consumers deliberately read
/// only these root fields; retaining the wire `member_roster` container here
/// would create two competing roster representations in durable client state.
fn project_member_roster_from_sdk_entry(
    projection: &mut Value,
    entry: &arkret_sdk::RealmSyncEntry,
) -> serde_json::Result<()> {
    let Some(roster) = entry.member_roster.as_ref() else {
        return Ok(());
    };
    let Some(object) = projection.as_object_mut() else {
        return Ok(());
    };
    object.remove("member_roster");
    object.insert(
        "member_roster_entries".to_owned(),
        serde_json::to_value(&roster.entries)?,
    );
    object.insert(
        "member_roster_entries_limited".to_owned(),
        Value::Bool(roster.limited),
    );
    if let Some(next_cursor) = roster.next_cursor.as_ref() {
        object.insert(
            "member_roster_entries_next_cursor".to_owned(),
            Value::String(next_cursor.clone()),
        );
    } else {
        object.remove("member_roster_entries_next_cursor");
    }
    Ok(())
}

pub(crate) fn project_default_strand_from_sdk_events<'a>(
    projection: &mut Value,
    events: impl IntoIterator<Item = &'a arkret_sdk::Event>,
) -> bool {
    let latest = events.into_iter().filter_map(|event| {
        if event.kind != arkret_sdk::EventKind::RealmSetDefaultStrand {
            return None;
        }
        event
            .typed_payload::<arkret_wire::event_spec::RealmSetDefaultStrand>()
            .ok()
            .map(|payload| payload.strand_id.to_string())
    });
    let Some(strand_id) = latest.last() else {
        return false;
    };
    let Some(object) = projection.as_object_mut() else {
        return false;
    };
    if object.get("default_strand_id").and_then(Value::as_str) == Some(strand_id.as_str()) {
        return false;
    }
    object.insert("default_strand_id".to_owned(), Value::String(strand_id));
    true
}

// `resolve-realm` decodes into the canonical SDK wire types so the client stays
// byte-compatible with soland's `DirectoryRealmResolutionOutcome` response. A
// inkson-local duplicate previously drifted from the wire (a required
// `public`/`title` on the preview node, a non-optional `join_rule`) and broke
// invite-accept with "error decoding response body" whenever the server omitted
// those fields. The SDK type is the single source of truth.
pub use arkret_models_discovery::{DirectoryRealmResolutionOutcome, RealmJoinCandidate};
pub use arkret_models_identity::IdentityResolveOutcome;

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
    use arkret_sdk::contact_operations::ContactScope;
    use arkret_wire::SchemaId;

    use super::{AccountSyncStep, projection_realm_id_for_known_node, service_supports_operation};

    #[test]
    fn since_join_member_roster_uses_authoritative_typed_projection_without_state_event() {
        let realm_id =
            arkret_sdk::RealmId::new("ak:realm:AYlS_mnxn8_f65A0YrWEeLzd0F1vnM347xZzMSQEcrlz")
                .unwrap();
        let alice = "ak:did_core:webvh:QmTwPiXhFdKLBT4AvS2cg4hjiCEdwbmgSTRfhGaEKUVR7P";
        let bob = "ak:did_core:webvh:QmQa9ZRrF8geZSqUMGGzE9M7uLRvuQyJ7wWRSXN9qsEiLU";
        let entry = serde_json::from_value::<arkret_sdk::RealmSyncEntry>(serde_json::json!({
            // A since-join reader may not receive the invite.accept Event that
            // established its own membership. The current typed roster is the
            // authoritative projection input in that case.
            "member_roster": {
                "entries": [
                    {"actor_id": {"kind": "account", "account_id": {
                        "principal_id": alice,
                        "station_id": "ak:did_core:web:station.example"
                    }}, "membership": "join"},
                    {"actor_id": {"kind": "account", "account_id": {
                        "principal_id": bob,
                        "station_id": "ak:did_core:web:station.example"
                    }}, "membership": "join"}
                ],
                "limited": false,
                "next_cursor": "ak:cursor:roster-next"
            }
        }))
        .unwrap();
        let step = AccountSyncStep::from_updates(
            "ak:cursor:account".to_owned(),
            arkret_sdk::SyncUpdates {
                realm_updates: vec![arkret_sdk::RealmUpdate {
                    realm_id: realm_id.clone(),
                    entry,
                }],
                malformed_realm_ids: Vec::new(),
                to_device: Vec::new(),
                to_device_ack_token: None,
                to_device_limited: false,
                to_device_next_cursor: None,
                to_device_lost: false,
                device_lists: arkret_sdk::AccountSubscribeDeviceListChanges {
                    changed_ids: Vec::new(),
                    left_ids: Vec::new(),
                },
                account_data: Vec::new(),
                station_cas_account_data: Vec::new(),
                notifications: Vec::new(),
                agent_signer_evidence: Vec::new(),
                partial: false,
            },
        )
        .unwrap();

        let projection = &step.realm_projections[realm_id.as_str()];
        assert!(
            projection.get("member_roster").is_none(),
            "durable local projection must not retain a competing wire roster shape"
        );
        assert_eq!(projection["member_roster_entries_limited"], false);
        assert_eq!(
            projection["member_roster_entries_next_cursor"],
            "ak:cursor:roster-next"
        );
        let rows = crate::views::member_display::realm_member_roster(Some(projection));
        assert_eq!(
            rows.into_iter().map(|row| row.actor_id).collect::<Vec<_>>(),
            vec![bob, alice]
                .into_iter()
                .map(
                    |principal| arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                        arkret_sdk::DidCoreId::new(principal).unwrap(),
                        arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                    ))
                )
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn operation_support_comes_only_from_registered_bundle_membership() {
        let description = arkret_sdk::ServiceDescribe::development(
            arkret_sdk::Did::new("did:webvh:z6mkfixture:service.example").unwrap(),
            arkret_sdk::TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            arkret_sdk::ServiceKind::Station,
            vec![
                "ak.operation_bundle.station.describe.v1".to_owned(),
                "ak.operation_bundle.station.http_core.v1".to_owned(),
            ],
            vec![arkret_sdk::TransportBinding::HttpJson {
                base_url: "https://service.example/_arkret".to_owned(),
                extension_profile_required: (),
            }],
        );
        assert!(service_supports_operation(
            &description,
            arkret_sdk::ServiceOperationId::SELF_EVENTS_READ_SCAN_V1,
        ));

        let unrelated = arkret_sdk::ServiceDescribe::development(
            arkret_sdk::Did::new("did:webvh:z6mkfixture:service.example").unwrap(),
            arkret_sdk::TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            arkret_sdk::ServiceKind::Station,
            vec![
                "ak.operation_bundle.station.agent_pairing_handoff.v1".to_owned(),
                "ak.operation_bundle.station.describe.v1".to_owned(),
            ],
            vec![arkret_sdk::TransportBinding::HttpJson {
                base_url: "https://service.example/_arkret".to_owned(),
                extension_profile_required: (),
            }],
        );
        assert!(!service_supports_operation(
            &unrelated,
            arkret_sdk::ServiceOperationId::SELF_EVENTS_READ_SCAN_V1,
        ));

        assert!(!service_supports_operation(
            &description,
            "ak.self.events.read.not_registered",
        ));
    }

    #[test]
    fn submit_event_outcome_decodes_new_events_submit_wire() {
        // Soland head 37ce729: {status, accepted[], cursor} — no top-level
        // event_id / sync_token. This is the shape that previously failed to
        // decode and broke every event submit ("error decoding response body").
        let value = serde_json::json!({
            "status": "accepted",
            "pending_delivery_count": 0,
            "accepted": ["ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"],
            "duplicate": [],
            "rejections": [],
            "frontiers": [],
            "cursor": "sx:cursor-1",
        });
        let outcome: super::SubmitEventResult = serde_json::from_value(value).unwrap();
        assert_eq!(
            outcome.event_id,
            "ak:event:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
        );
        assert_eq!(outcome.status, arkret_sdk::EventsSubmitStatus::Accepted);
        assert_eq!(outcome.cursor, "sx:cursor-1");
    }

    #[test]
    fn contact_list_sidebar_fixture_decodes_direct_chat_targets() {
        let value = serde_json::json!({
            "contacts": [{
                "peer": {"kind": "human", "account_id": {
                    "principal_id": "ak:did_core:web:bob.example",
                    "station_id": "ak:did_core:web:station.example"
                }},
                "state": "accepted",
                "next_prepare_input": {
                    "contact_round_id": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "version": 2,
                    "predecessor_event_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
                },
                "granted_to_peer_scopes": ["direct_message"],
                "granted_by_peer_scopes": ["direct_message"],
                "bidirectional_scopes": ["direct_message"],
                "effective_scopes": ["direct_message"],
                "direct_conversation": {
                    "realm_id": "ak:realm:AUEAoXMJeJWBETvkqm7gk4imduk7g-l8bim19OPFQDaO",
                    "main_strand_id": "ak:strand:Ae9PN2rTd0Dojs9yS8iLnfheJtjSEZ3mgDDyONpztHUd",
                    "binding_event_ref": "ak:event:AQmnyvvBmKOWOEOSD2rAYsVBQn6vJ_wdbdUY8CKUGB5c",
                    "state": "found"
                },
                "contact_agents": [{
                    "actor_id": {
                        "kind": "service",
                        "service_id": "ak:did_core:web:agents.example:bob-helper"
                    },
                    "controller_account_id": {
                        "principal_id": "ak:did_core:web:bob.example",
                        "station_id": "ak:did_core:web:station.example"
                    },
                    "display_name": "Bob Helper",
                    "agent_slug": "helper",
                    "avatar_blob_ref": "ak:blob:sha256:431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460",
                    "direct_conversation": {
                        "realm_id": "ak:realm:Ab8b2glgQEo48OSA-g8P4SfHSFLwgN1jG8Jv-AlcdVnI",
                        "main_strand_id": "ak:strand:AQAG6N7vDa1nxssksTCIdqNm-FTDJoKuBrHIclJ7FBy0",
                        "binding_event_ref": "ak:event:ARhOgV4T1qZleEVITbO4iNd_ggoy771-VwFQBRHzRm4x",
                        "state": "found"
                    }
                }]
            }],
            "next_cursor": null,
            "has_more": false
        });
        let decoded: arkret_sdk::ContactList = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.contacts.len(), 1);
        assert_eq!(decoded.contacts[0].contact_agent_projections.len(), 1);
    }

    #[test]
    fn submit_event_outcome_uses_duplicate_id_when_nothing_accepted() {
        let value = serde_json::json!({
            "status": "duplicate",
            "pending_delivery_count": 0,
            "accepted": [],
            "duplicate": ["ak:event:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL"],
        });
        let outcome: super::SubmitEventResult = serde_json::from_value(value).unwrap();
        assert_eq!(
            outcome.event_id,
            "ak:event:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL"
        );
        assert_eq!(outcome.status, arkret_sdk::EventsSubmitStatus::Duplicate);
        assert_eq!(outcome.cursor, "");
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
        // The bare SDK wire body (schema + account_id required,
        // typed enums, trust lists) must decode and re-encode without losing
        // the `trusted_*` / `denied_source_ids` lists the U4 form
        // never touches.
        let value = serde_json::json!({
            "schema": SchemaId::INVITE_RECEIVE_POLICY_V1,
            "account_id": {"principal_id": "ak:did_core:web:me.example", "station_id": "ak:did_core:web:ps.example"},
            "holder_allowed_introduction_kinds": ["consent_grant", "locator_ref"],
            "explicit_address_behavior": "drop",
            "unknown_invites": "quarantine",
            "trusted_realm_ids": ["ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"],
            "trusted_source_ids": ["ak:did_core:web:ps.example"],
            "denied_actor_ids": [{"kind":"account","account_id":{"principal_id":"ak:did_core:web:spammer.example","station_id":"ak:did_core:web:remote.example"}}],
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
        assert_eq!(re["trusted_source_ids"][0], "ak:did_core:web:ps.example");
        assert_eq!(
            re["trusted_realm_ids"][0],
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
        );
    }

    #[test]
    fn default_invite_receive_policy_carries_schema_and_account() {
        let subject_id = crate::mls_api_helpers::principal_core_id("did:web:me.example").unwrap();
        let policy = super::InviteReceivePolicy::spec_default(arkret_sdk::AccountId::new(
            subject_id,
            arkret_sdk::DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
        ));
        assert_eq!(policy.schema, SchemaId::INVITE_RECEIVE_POLICY_V1);
        assert_eq!(
            policy.account_id.principal_id.as_str(),
            "ak:did_core:web:me.example"
        );
        assert_eq!(
            policy.explicit_address_behavior,
            super::InviteReceiveAction::Quarantine
        );
        assert_eq!(policy.unknown_invites, super::UnknownInviteAction::Drop);
    }

    #[test]
    fn contact_row_invite_gate_uses_directional_contact_scopes() {
        let row = super::ContactListRow {
            peer: arkret_sdk::contact_operations::ContactPeer::Human {
                account_id: arkret_sdk::AccountId::new(
                    crate::mls_api_helpers::principal_core_id("did:web:bob.example").unwrap(),
                    arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                ),
            },
            state: arkret_sdk::ContactState::Accepted,
            request_event_ref: None,
            request_receipt: None,
            response_event_ref: Some(
                arkret_sdk::EventId::new(
                    "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
                )
                .unwrap(),
            ),
            tombstone_event_ref: None,
            next_prepare_input: Some(arkret_sdk::contact_operations::ContactNextPrepareInput {
                contact_round_id: arkret_sdk::Hash::new(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
                version: 2,
                predecessor_event_ref: arkret_sdk::EventId::new(
                    "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                )
                .unwrap(),
            }),
            granted_to_peer_scopes: Vec::new(),
            granted_by_peer_scopes: vec![ContactScope::Invite],
            bidirectional_scopes: Vec::new(),
            effective_scopes: Some(Vec::new()),
            peer_host_id: None,
            continuity_evidence: None,
            direct_conversation: None,
            peer_host_resolution: None,
            contact_agent_projections: Vec::new(),
        };
        assert!(super::contact_grants_me_invite(&row));
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BackfillView(pub arkret_sdk::EventsQueryOutcome);

impl BackfillView {
    /// Require a complete accepted Event log for reducers, authority decisions,
    /// completeness verification, and cryptographic operations.
    pub fn complete_events(&self, purpose: &str) -> anyhow::Result<Vec<arkret_sdk::Event>> {
        require_complete_event_rows(&self.0.events, purpose)
    }

    /// Serialize only complete Events for a non-authoritative display
    /// projection. Redacted/reference-locked rows intentionally carry too
    /// little information to rebuild a timeline object, but they must not make
    /// the chat renderer discard other complete rows from the same page (in
    /// particular the server-folded redaction tombstone for a Message).
    ///
    /// Reducers, MLS recovery and authorization continue to use
    /// `complete_events` and therefore fail closed on either incomplete row.
    pub fn display_event_values(&self) -> anyhow::Result<Vec<Value>> {
        self.0
            .events
            .iter()
            .filter_map(|row| match row {
                arkret_sdk::EventReadRow::Event(event) => {
                    Some(serde_json::to_value(event).map_err(Into::into))
                }
                arkret_sdk::EventReadRow::Redacted(_)
                | arkret_sdk::EventReadRow::ReferenceLocked(_) => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod backfill_display_tests {
    use super::*;

    #[test]
    fn display_projection_skips_opaque_rows_without_rejecting_the_page() {
        let redacted = serde_json::from_value(serde_json::json!({
            "view_kind": "redacted_event_view",
            "event_id": "ak:event:AQ-IyBN9yVn52Yqaah8H-_0fuHhf3ImJTExtFDnU3ebQ",
            "kind": "ak.message.redact",
            "realm_id": "ak:realm:AQPaZ0Jo2vyqxYcuCGXtMaCGulqrjFxOxXHsUhcb30Gt",
            "redaction_reason": "redacted",
            "hidden_fields": ["payload", "proofs"],
            "reducer_input": false
        }))
        .expect("valid RedactedEventView row");
        let backfill = BackfillView(arkret_sdk::EventsQueryOutcome {
            events: vec![redacted],
            snapshot_bootstrap: None,
            prev_cursor: None,
            next_cursor: None,
            has_more: false,
        });

        assert!(backfill.display_event_values().unwrap().is_empty());
        assert!(backfill.complete_events("authority replay").is_err());
    }
}

pub(crate) fn require_complete_event_rows(
    rows: &[arkret_sdk::EventReadRow],
    purpose: &str,
) -> anyhow::Result<Vec<arkret_sdk::Event>> {
    rows.iter()
        .enumerate()
        .map(|(index, row)| match row {
            arkret_sdk::EventReadRow::Event(event) => Ok(event.clone()),
            arkret_sdk::EventReadRow::Redacted(view) => anyhow::bail!(
                "{purpose} requires complete Events; row {index} ({}) is redacted ({:?})",
                view.event_id,
                view.redaction_reason
            ),
            arkret_sdk::EventReadRow::ReferenceLocked(stub) => anyhow::bail!(
                "{purpose} requires complete Events; row {index}{} is reference-locked ({:?})",
                stub.event_id
                    .as_ref()
                    .map(|event_id| format!(" ({event_id})"))
                    .unwrap_or_default(),
                stub.reason_code
            ),
        })
        .collect()
}

impl From<arkret_sdk::EventsQueryOutcome> for BackfillView {
    fn from(outcome: arkret_sdk::EventsQueryOutcome) -> Self {
        Self(outcome)
    }
}

// `ak.self.snapshot.read.manifest_head.v1` returns the full signed
// `ak.schema.snapshot.v1` manifest. See `api::TransportClient::snapshot_head`.

/// Structured mention node embedded in message body. Spec
/// `models/strand-and-message.md §9.4` + `identity/identity-handles.md §3.8`.
///
/// The former hand-rolled weakly-typed mirror (all-`String`
/// fields) duplicated the SDK's authoritative strongly-typed model
/// (`Did` / `Handle` / `DateTime<Utc>`) and had already drifted in field
/// declaration order. Re-export the SDK type; `subject_id` (principal
/// DID) remains the ONLY authoritative field — the `*_at_time` fields
/// are compose-time audit metadata only.
pub use arkret_models_collaboration::events_payloads::mention::Mention;
pub use arkret_models_collaboration::governance::authorization::AuthzCheckOutcome;
/// `ak.self.authz.invites` decodes into the SDK's authoritative
/// `AuthzInviteList` (`invites: Vec<Invite>`, `next_cursor`, `has_more`); the
/// former inkson-local `InvitesView` mirror was removed in favor of the wire
/// type.
pub use arkret_models_collaboration::governance::authorization::AuthzInviteList;
/// `ak.self.authz.grants.read.effective.v1` response. soland serialises the SDK
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
// ── Directory ───────────────────────────────────────────────────
pub use arkret_models_discovery::DirectoryHandleResolutionOutcome as ResolveHandleView;
pub use arkret_models_integration::OkOutcome;
pub use arkret_models_integration::models_push::PushRegisterDeviceOutcome;

// ── Realm / Space Management ────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RealmPolicyResult {
    pub ok: bool,
    pub realm_id: String,
    pub join_rule: String,
    pub history_access_tightened: bool,
}

// ── Device & Crypto ─────────────────────────────────────────────

/// `ak.self.events.command.submit.v1` response.
///
/// Decodes the canonical `EventsSubmitOutcome` wire shape and folds it into
/// the inkson-facing result:
///   * `event_id` ← first `accepted` (else first `duplicate`)
///   * `cursor`   ← `cursor` (read-your-writes barrier)
///   * `status`   ← the `accepted` / `duplicate` / `partial` discriminant
///
/// Ids stay plain `String`s so synthetic fixture ids do not trip the strict
/// `EventId` validator.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SubmitEventResult {
    pub event_id: String,
    pub status: arkret_sdk::EventsSubmitStatus,
    #[serde(default)]
    pub cursor: String,
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
        Self {
            event_id,
            status: outcome.status,
            cursor: outcome.cursor.unwrap_or_default(),
            ingress_receipts: outcome.ingress_receipts,
        }
    }
}

impl<'de> Deserialize<'de> for SubmitEventResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let outcome = arkret_sdk::EventsSubmitOutcome::deserialize(deserializer)?;
        Ok(outcome.into())
    }
}

// ── Media ────────────────────────────────────────────────────────

// The hand-rolled `IceConfigOutcome` / `IceServer` /
// `IceConfigRequestBody` mirrors drifted from the SDK wire types (missing
// `turn_required`, `ttl_seconds: u64` vs the authoritative `u32`) and bypassed
// the TURN credential privacy guard. Re-export the
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
// mirrors were removed.

// ─────────────────────────────────────────────────────────────────────
// Agent HTTP wire types.
//
// the former hand-rolled `Agent*ReqBody` / `Agent*ResBody`
// mirrors drifted from `agent-operations.schema.json` (extra required
// fields, non-spec `todos`, wrong outcome shapes) and were removed. The
// agent surface now uses the SDK's authoritative types
// (`arkret_sdk::AgentProvisionOutcome` / `AgentList` / `AgentView` /
// Sidecar SDK DTOs directly in `views::agents`
// (via `with_authed_sdk_client`).
