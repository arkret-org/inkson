use std::collections::BTreeMap;

use arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry;
use arkret_sdk::contact_operations::ContactScope;
pub use arkret_sdk::{
    ContactAgentProjection, ContactList, ContactListRow, ContactState, DirectConversationSummary,
    DirectConversationSummaryState, InteropSurfaceEntry, ServiceDescribe, VerifiedProfileEntry,
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

/// The peer's exact account, for surfaces that address a Contact as a
/// Directory subject. `None` for a `service` actor, which has no account
/// subject at all. Both components stay together: the same principal at
/// another Station is a different subject.
pub fn contact_peer_account_id(contact: &ContactListRow) -> Option<arkret_sdk::AccountId> {
    match contact.peer.contact_actor_id() {
        arkret_sdk::ActorId::Account { account_id } => Some(account_id),
        arkret_sdk::ActorId::Service { .. } => None,
    }
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
    /// The governance Station's first commit for this Realm. UI completion is
    /// gated on this proof, never on a queued/forwarding transport state.
    pub first_commit: arkret_wire::RealmCommit,
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
        arkret_sdk::ServiceOperationId::SERVER_READ_DESCRIBE_V1,
    ) {
        missing.push(arkret_sdk::ServiceOperationId::SERVER_READ_DESCRIBE_V1);
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
/// App runtime state derived from one validated canonical account-subscribe
/// frame.
///
/// Wire ownership stays in `AccountSubscribeFrame`; the JSON map is only the
/// heterogeneous local projection consumed by UI reducers. `cursor` is the
/// account subscription's own opaque resume token — it is never a commit-stream
/// position and never orders Events across Realms.
#[derive(Clone, Debug)]
pub struct AccountSyncStep {
    pub cursor: String,
    /// Canonical SDK Realm entries retained after sync decoding. Product
    /// projections may derive JSON views for heterogeneous reducers, but
    /// security decisions (for example Direct Conversation MLS admission)
    /// must use this typed source.
    pub realm_entries: BTreeMap<arkret_sdk::RealmId, RealmSyncEntry>,
    pub realm_projections: BTreeMap<String, Value>,
}

impl AccountSyncStep {
    pub fn from_frame(
        cursor: String,
        frame: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
    ) -> arkret_sdk::Result<Self> {
        let entries = frame
            .realms
            .as_ref()
            .map(|realms| realms.entries.clone())
            .unwrap_or_default();
        let mut realm_entries = BTreeMap::new();
        let mut realm_projections = BTreeMap::new();
        for (realm, entry) in entries {
            let realm_id = arkret_sdk::RealmId::new(realm)?;
            let mut projection = serde_json::to_value(&entry)
                .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))?;
            project_member_roster_from_sdk_entry(&mut projection, &entry)
                .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))?;
            realm_projections.insert(realm_id.as_str().to_owned(), projection);
            realm_entries.insert(realm_id, entry);
        }
        Ok(Self {
            cursor,
            realm_entries,
            realm_projections,
        })
    }

    /// Every independent commit stream this step delivered items for, with the
    /// last position it carried.
    ///
    /// The key is the exact [`arkret_wire::CommitStreamRef`]; there is
    /// deliberately no Realm-global position, so a caller advances each stream's
    /// own cursor and nothing else.
    pub fn stream_heads(&self) -> BTreeMap<arkret_wire::CommitStreamRef, u64> {
        let mut heads: BTreeMap<arkret_wire::CommitStreamRef, u64> = BTreeMap::new();
        for entry in self.realm_entries.values() {
            let Some(committed_events) = entry.committed_events.as_ref() else {
                continue;
            };
            for item in committed_events {
                let commit = item.commit();
                heads
                    .entry(commit.stream_ref.clone())
                    .and_modify(|position| {
                        *position = (*position).max(commit.stream_position);
                    })
                    .or_insert(commit.stream_position);
            }
        }
        heads
    }

    pub fn collaboration_role(&self, realm_id: &str) -> Option<arkret_sdk::CollaborationRealmRole> {
        self.realm_entries
            .iter()
            .find(|(id, _)| id.as_str() == realm_id)
            .and_then(|(_, entry)| entry.state_at_window_start.as_ref())
            .and_then(|state| state.realm_metadata.collaboration_role)
            .map(|role| match role {
                arkret_models_collaboration::sync_frames::account_sync::WindowStartCollaborationRole::DirectConversation => {
                    arkret_sdk::CollaborationRealmRole::DirectConversation
                }
            })
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
    entry: &RealmSyncEntry,
) -> serde_json::Result<()> {
    let roster = match &entry.member_roster {
        Some(roster) => Some(roster.clone()),
        None => member_roster_from_current(entry)?,
    };
    let Some(roster) = roster.as_ref().and_then(Value::as_object) else {
        return Ok(());
    };
    let Some(object) = projection.as_object_mut() else {
        return Ok(());
    };
    let entries = roster.get("entries").cloned().unwrap_or(Value::Null);
    let limited = roster
        .get("limited")
        .and_then(Value::as_bool)
        .unwrap_or_default();
    let next_cursor = roster
        .get("next_cursor")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    object.remove("member_roster");
    object.insert("member_roster_entries".to_owned(), entries);
    object.insert(
        "member_roster_entries_limited".to_owned(),
        Value::Bool(limited),
    );
    match next_cursor {
        Some(next_cursor) => {
            object.insert(
                "member_roster_entries_next_cursor".to_owned(),
                Value::String(next_cursor),
            );
        }
        None => {
            object.remove("member_roster_entries_next_cursor");
        }
    }
    Ok(())
}

/// A complete account current cut already carries effective member state.
/// Some Stations omit the optional roster convenience projection; use only
/// those authority-committed current rows in that case, never message authors
/// or mention metadata.
fn member_roster_from_current(entry: &RealmSyncEntry) -> serde_json::Result<Option<Value>> {
    use arkret_wire::{CurrentSelector, MemberStateCurrent, MembershipState, TypedCurrentResult};

    let Some(current) = entry.current.as_ref() else {
        return Ok(None);
    };
    let mut entries = Vec::new();
    for row in &current.entries {
        let TypedCurrentResult::Value {
            selector: CurrentSelector::MemberState { actor_id },
            value,
            ..
        } = row
        else {
            continue;
        };
        let state: MemberStateCurrent = serde_json::from_value(value.clone())?;
        match state.membership {
            MembershipState::Join | MembershipState::Knock => entries.push(serde_json::json!({
                    "actor_id": actor_id,
                    "membership": state.membership,
            })),
            MembershipState::Leave | MembershipState::Ban => {}
        }
    }
    Ok(Some(
        serde_json::json!({"entries": entries, "limited": false}),
    ))
}

// `resolve-realm` decodes into the canonical SDK wire types so the client stays
// byte-compatible with soland's `DirectoryRealmResolutionOutcome` response. A
// inkson-local duplicate previously drifted from the wire (a required
// `public`/`title` on the preview node, a non-optional `join_rule`) and broke
// invite-accept with "error decoding response body" whenever the server omitted
// those fields. The SDK type is the single source of truth.
pub use arkret_models_discovery::DirectoryRealmResolutionOutcome;
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

    use super::{
        AccountSyncStep, RealmSyncEntry, project_member_roster_from_sdk_entry,
        projection_realm_id_for_known_node, service_supports_operation,
    };

    #[test]
    fn since_join_member_roster_uses_authoritative_typed_projection_without_state_event() {
        let realm_id =
            arkret_sdk::RealmId::new("ak:realm:AYlS_mnxn8_f65A0YrWEeLzd0F1vnM347xZzMSQEcrlz")
                .unwrap();
        let alice = "ak:did_core:webvh:QmTwPiXhFdKLBT4AvS2cg4hjiCEdwbmgSTRfhGaEKUVR7P";
        let bob = "ak:did_core:webvh:QmQa9ZRrF8geZSqUMGGzE9M7uLRvuQyJ7wWRSXN9qsEiLU";
        let entry = serde_json::from_value::<arkret_sdk::sync::RealmSyncEntry>(serde_json::json!({
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
        let frame = arkret_sdk::sync::AccountSubscribeFrame {
            kind: arkret_sdk::sync::AccountSubscribeFrameKind::Delta,
            cursor: Some("ak:cursor:account".to_owned()),
            realms: Some(arkret_sdk::sync::AccountSubscribeRealms {
                entries: std::collections::BTreeMap::from([(realm_id.as_str().to_owned(), entry)]),
            }),
            to_device: None,
            device_lists: None,
            account_data: None,
            agent_draft_pending_intents: None,
            notifications: None,
            partial: None,
            priority: None,
            reconnect_after_ms: None,
            realm_list: None,
            realm_list_changes: None,
            baseline: None,
            realm_invalidations: None,
        };
        let step = AccountSyncStep::from_frame("ak:cursor:account".to_owned(), &frame).unwrap();

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
    fn missing_wire_roster_uses_only_current_member_state() {
        let actor = serde_json::json!({"kind":"account","account_id":{
            "principal_id":"ak:did_core:web:bob.example",
            "station_id":"ak:did_core:web:station.example"
        }});
        let current_row = |membership: &str| {
            serde_json::json!({
                "selector":{"kind":"member_state","actor_id":actor},
                "source_stream_ref":{"kind":"realm","realm_id":"ak:realm:AYlS_mnxn8_f65A0YrWEeLzd0F1vnM347xZzMSQEcrlz"},
                "revision":{"commit_id":"ak:realm_commit:AT33EWBTXdTx5CjY-ogbIIF2T4vh-v7jCMCQ80Fss2Rq","stream_position":1},
                "value":{"membership":membership}
            })
        };
        let entry: RealmSyncEntry = serde_json::from_value(serde_json::json!({
            "current":{
                "realm_id":"ak:realm:AYlS_mnxn8_f65A0YrWEeLzd0F1vnM347xZzMSQEcrlz",
                "governance_generation":1,
                "stream_heads":[],
                "entries":[current_row("join")]
            }
        }))
        .unwrap();
        let mut projection = serde_json::to_value(&entry).unwrap();
        project_member_roster_from_sdk_entry(&mut projection, &entry).unwrap();
        let rows = crate::views::member_display::realm_member_roster(Some(&projection));
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].actor_id,
            serde_json::from_value(actor.clone()).unwrap()
        );

        let mut left = entry;
        left.current.as_mut().unwrap().entries =
            vec![serde_json::from_value(current_row("leave")).unwrap()];
        let mut projection = serde_json::to_value(&left).unwrap();
        project_member_roster_from_sdk_entry(&mut projection, &left).unwrap();
        assert!(crate::views::member_display::realm_member_roster(Some(&projection)).is_empty());
    }

    #[test]
    fn operation_support_comes_only_from_registered_bundle_membership() {
        let description = arkret_sdk::ServiceDescribe::development(
            arkret_sdk::Did::new("did:webvh:z6mkfixture:service.example").unwrap(),
            arkret_sdk::TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            arkret_sdk::ServiceKind::Station,
            vec![
                "ak.operation_bundle.station.describe.v1".to_owned(),
                "ak.operation_bundle.station.http_core_current.v1".to_owned(),
            ],
            vec![arkret_sdk::TransportBinding::HttpJson {
                base_url: "https://service.example/_arkret".to_owned(),
                extension_profile_required: (),
            }],
        );
        assert!(service_supports_operation(
            &description,
            arkret_sdk::ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
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
            arkret_sdk::ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
        ));

        assert!(!service_supports_operation(
            &description,
            "ak.self.events.read.not_registered",
        ));
    }

    #[test]
    fn submit_event_result_reports_the_station_rejection_reason_code() {
        let outcome: arkret_wire::AuthoritySubmitOutcome = serde_json::from_value(
            serde_json::json!({"status": "rejected", "reason_code": "policy_violation"}),
        )
        .unwrap();
        let result = super::SubmitEventResult::from(outcome);
        assert_eq!(result.status, garth::SendQueueStatus::Rejected);
        assert_eq!(
            result.rejection_reason_code.as_deref(),
            Some("policy_violation")
        );
        assert!(result.commit.is_none());
        assert!(!result.is_committed());
        assert!(result.stream_position().is_none());
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
            request_message: None,
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
            continuity_evidence: None,
            direct_conversation: None,
            contact_agent_projections: Vec::new(),
        };
        assert!(super::contact_grants_me_invite(&row));
    }
}

/// One authorized commit-stream page: the authority-signed `RealmCommit` and
/// the exact Event it covers, in stream order.
///
/// There is deliberately no Realm-global page here. A Realm, each Circle and
/// each Sidecar own independent streams, so a caller names the stream it is
/// catching up and this view never mixes two of them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BackfillView(pub arkret_wire::StreamScanOutcome);

impl BackfillView {
    /// The stream this page belongs to, or `None` for an empty page.
    pub fn stream_ref(&self) -> Option<&arkret_wire::CommitStreamRef> {
        self.0
            .committed_events
            .first()
            .map(|item| &item.commit().stream_ref)
    }

    /// The last position covered by this page, for the caller's per-stream
    /// cursor. `None` means the page was empty and the cursor does not move.
    pub fn last_position(&self) -> Option<u64> {
        self.0
            .committed_events
            .last()
            .map(|item| item.commit().stream_position)
    }

    /// The Station reported more commits after this page.
    pub fn truncated(&self) -> bool {
        self.0.truncated
    }

    /// The accepted Events of this page, in commit order.
    ///
    /// Every item on an authority stream is a complete Event covered by exactly
    /// one commit, so reducers, authorization decisions and cryptographic
    /// operations read this directly.
    pub fn events(&self) -> Vec<arkret_sdk::Event> {
        self.0
            .committed_events
            .iter()
            .filter_map(|item| item.reducer_input().cloned())
            .collect()
    }

    /// Serialize the page's Events for a non-authoritative display projection.
    pub fn display_event_values(&self) -> anyhow::Result<Vec<Value>> {
        self.0
            .committed_events
            .iter()
            .filter_map(arkret_wire::CommittedEventView::reducer_input)
            .map(|event| serde_json::to_value(event).map_err(Into::into))
            .collect()
    }

    /// The exact committed reference of each Event on this page.
    pub fn committed_refs(&self) -> Vec<arkret_wire::CommittedEventRef> {
        self.0
            .committed_events
            .iter()
            .map(|item| arkret_wire::CommittedEventRef {
                event_id: item.commit().event_ref.clone(),
                commit_id: item.commit().commit_id.clone(),
                stream_ref: item.commit().stream_ref.clone(),
                stream_position: item.commit().stream_position,
            })
            .collect()
    }
}

impl From<arkret_wire::StreamScanOutcome> for BackfillView {
    fn from(outcome: arkret_wire::StreamScanOutcome) -> Self {
        Self(outcome)
    }
}

// `ak.self.realm_state_snapshot.read.manifest_head.v1` returns the full signed
// `ak.schema.realm_state_snapshot.v1` manifest. See
// `api::TransportClient::realm_state_snapshot_head`.

pub use arkret_models_collaboration::device_messages::{
    DeviceMessageEnvelope, DeviceMessagesAckOutcome, DeviceMessagesAckRequestBody,
    DeviceMessagesGetOutcome, DeviceMessagesSendOutcome,
};
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
/// `ak.self.authz.grants.read.effective.v1` response. Each SDK row atomically
/// binds an effective grant to the exact current-result revision that may be
/// copied into a subject-signed relinquish; the list digest is never a CAS
/// substitute.
pub use arkret_models_collaboration::governance::authorization::{
    EffectiveCapabilityGrantRow, GrantList,
};
/// `POST /_arkret/self/moderation/report` response. soland emits the SDK
/// `ModerationReportOutcome` wire shape verbatim (`status: "submitted"`,
/// `routed_to: Vec<Did>` — scalar DIDs only, no fragments, per
/// `service-operation-dtos.schema.json#/$defs/ModerationReportOutcome`).
pub use arkret_models_collaboration::governance::moderation::ModerationReportOutcome;
pub use arkret_models_collaboration::objects::blob::BlobUploadOutcome;
pub use arkret_models_crypto::{KeysClaimOutcome, KeysQueryOutcome, KeysUploadOutcome};
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

/// `ak.self.events.command.submit.v1` result, as this client holds it.
///
/// The Station answers one submitted Event with either an authority-signed
/// `RealmCommit` or a rejection reason code; the durable outbound queue adds the
/// pre-answer lifecycle (`Queued` / `Forwarding`) and the local terminal states.
/// `status` is therefore garth's queue vocabulary, and `commit` is the only
/// evidence that the Event is final.
///
/// `event_id` stays a plain `String` so synthetic fixture ids do not trip the
/// strict `EventId` validator.
#[derive(Clone, Debug, PartialEq)]
pub struct SubmitEventResult {
    pub event_id: String,
    pub status: garth::SendQueueStatus,
    /// The authority-signed commit that covers this Event. Present exactly when
    /// `status` is [`garth::SendQueueStatus::Committed`].
    pub commit: Option<arkret_wire::RealmCommit>,
    /// The Station's reason code. Present exactly when `status` is
    /// [`garth::SendQueueStatus::Rejected`].
    pub rejection_reason_code: Option<String>,
}

impl SubmitEventResult {
    pub fn committed(event_id: String, commit: arkret_wire::RealmCommit) -> Self {
        Self {
            event_id,
            status: garth::SendQueueStatus::Committed,
            commit: Some(commit),
            rejection_reason_code: None,
        }
    }

    pub fn rejected(event_id: String, reason_code: String) -> Self {
        Self {
            event_id,
            status: garth::SendQueueStatus::Rejected,
            commit: None,
            rejection_reason_code: Some(reason_code),
        }
    }

    pub fn queued(event_id: String) -> Self {
        Self {
            event_id,
            status: garth::SendQueueStatus::Queued,
            commit: None,
            rejection_reason_code: None,
        }
    }

    pub fn is_committed(&self) -> bool {
        self.status == garth::SendQueueStatus::Committed
    }

    /// The independent stream this Event was committed to.
    pub fn stream_ref(&self) -> Option<&arkret_wire::CommitStreamRef> {
        self.commit.as_ref().map(|commit| &commit.stream_ref)
    }

    /// The position this Event occupies in its own stream. There is no
    /// Realm-global position, so this is only meaningful next to
    /// [`Self::stream_ref`].
    pub fn stream_position(&self) -> Option<u64> {
        self.commit.as_ref().map(|commit| commit.stream_position)
    }
}

impl From<arkret_wire::AuthoritySubmitOutcome> for SubmitEventResult {
    fn from(outcome: arkret_wire::AuthoritySubmitOutcome) -> Self {
        match outcome {
            arkret_wire::AuthoritySubmitOutcome::Accepted { commit, .. } => Self {
                event_id: commit.event_ref.as_str().to_owned(),
                status: garth::SendQueueStatus::Committed,
                commit: Some(commit),
                rejection_reason_code: None,
            },
            arkret_wire::AuthoritySubmitOutcome::Rejected { reason_code, .. } => Self {
                event_id: String::new(),
                status: garth::SendQueueStatus::Rejected,
                commit: None,
                rejection_reason_code: Some(reason_code),
            },
        }
    }
}

impl From<&garth::SendQueueItem> for SubmitEventResult {
    fn from(item: &garth::SendQueueItem) -> Self {
        Self {
            event_id: item.event_id().as_str().to_owned(),
            status: item.status,
            commit: item.commit().cloned(),
            rejection_reason_code: item.rejection_reason_code().map(ToOwned::to_owned),
        }
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
