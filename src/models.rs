pub use cokret_sdk::{
    ClaimedProfileEntry, CompatSurfaceEntry, ServerDescription, VerifiedProfileEntry,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub ok: bool,
    pub service: String,
    pub storage: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DevLoginResponse {
    pub access_token: String,
    pub token_type: String,
    pub actor: String,
    pub device_id: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LogoutResponse {
    pub ok: bool,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccountRegisterOutcome {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub created_at: String,
}

/// A4b — response shape for `POST /_soland/self/account/profile`. Mirrors
/// soland's `AccountUpdateProfileOutcome` wire shape so the settings UI can
/// reconcile its local cache with whatever the server actually stored
/// (the server normalises empty strings to `None`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccountUpdateProfileOutcome {
    pub did: String,
    pub handle: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub bio: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
}

/// A6.1 — response shape for `POST /_soland/self/index/search`. Mirrors
/// soland's index search payload: each result row carries a `kind`
/// (`message` | `space`), an `object_id`, and surface-specific extras
/// (sender / thread_id / content for messages, title / summary for
/// spaces). Unknown fields are ignored so forward additions do not
/// break the client.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IndexSearchResponse {
    pub query: String,
    #[serde(default)]
    pub results: Vec<Value>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContactResponse {
    pub requester: String,
    pub target: String,
    #[serde(default)]
    #[serde(rename = "consent_scope")]
    pub scope: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DirectConversationSummary {
    pub realm_id: String,
    pub main_flow_id: String,
    #[serde(default)]
    pub binding_event_ref: Option<String>,
    pub state: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ContactListRow {
    pub peer: String,
    pub state: String,
    #[serde(default)]
    pub request_event_ref: Option<String>,
    #[serde(default)]
    pub response_event_ref: Option<String>,
    #[serde(default)]
    pub tombstone_event_ref: Option<String>,
    #[serde(default)]
    pub granted_by_me: Vec<String>,
    #[serde(default)]
    pub granted_to_me: Vec<String>,
    #[serde(default)]
    pub bidirectional_scopes: Vec<String>,
    #[serde(default)]
    pub effective_scopes: Vec<String>,
    #[serde(default)]
    pub direct_conversation: Option<DirectConversationSummary>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContactsResponse {
    #[serde(default)]
    pub contacts: Vec<ContactListRow>,
    #[serde(default)]
    pub has_more: bool,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DirectConversationResolveRequestBody {
    pub peer: String,
    #[serde(default)]
    pub create: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct DirectConversationResolveOutcome {
    pub state: String,
    #[serde(default)]
    pub realm_id: Option<String>,
    #[serde(default)]
    pub main_flow_id: Option<String>,
    #[serde(default)]
    pub binding_event_ref: Option<String>,
    #[serde(default)]
    pub created: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ConsentCellResponse {
    pub ok: bool,
    pub cell_id: String,
    pub holder_did: String,
    pub peer_did: String,
    // Spec consent-model.md §3: domain-prefixed `consent_scope` on the wire
    // (soland's consent admin/holder surface emits this name). Rust field
    // kept as `scope` so callers/views are unchanged.
    #[serde(rename = "consent_scope")]
    pub scope: String,
    pub state: String,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub requested_at: Option<String>,
    pub updated_at: String,
    #[serde(default)]
    pub active_grant_dots: Vec<String>,
    #[serde(default)]
    pub grant_dots: Vec<String>,
    #[serde(default)]
    pub revoked_dots: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ConsentCellsResponse {
    pub ok: bool,
    #[serde(default)]
    pub cells: Vec<ConsentCellResponse>,
}

/// R15: result of `ck.realm.create`. Carries a `ck:realm:*` id under the
/// canonical `realm_id` field (was previously squeezed into a shared
/// `space_id` on `SpaceLifecycleResponse`). `state` replaces the old
/// `deleted: bool`, matching the spec lifecycle-state enum
/// (`active` / `archived` / `tombstoned`, `common-fields.md §5.1`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RealmCreateResponse {
    pub ok: bool,
    pub realm_id: String,
    pub owner: String,
    #[serde(default)]
    pub members: Vec<String>,
    pub state: String,
}

/// R15: result of `ck.space.create`. A Space (`ck:space:*`) lives inside a
/// Realm and inherits its membership / encryption. `state` mirrors the spec
/// lifecycle enum (see [`RealmCreateResponse`]).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpaceCreateResponse {
    pub ok: bool,
    pub space_id: String,
    pub owner: String,
    #[serde(default)]
    pub members: Vec<String>,
    pub state: String,
}

// (Move/Anchor pipeline DTOs deleted; all writes now go through
// ck.self.events.submit via SubmitEventResponse.)

/// Outcome of [`crate::api::CokretApi::set_account_data`]. Captures the
/// graceful-degradation contract: 404/501/405 are not treated as errors —
/// soland's principal-control lookup / event ingest may be absent on older
/// deployments and the client must keep working when that path is not wired.
#[derive(Debug, Clone)]
pub enum AccountDataSetOutcome {
    /// Server accepted and stored the value. The caller may inspect the
    /// echoed body for any server-derived metadata, but most callers can
    /// ignore the `Value`.
    Stored { response: serde_json::Value },
    /// Server doesn't yet support the canonical `ck.account_data.set` submit
    /// path needed for this setting; the client logged a `tracing::warn` and
    /// the local state remains the authoritative copy.
    Unsupported { status: reqwest::StatusCode },
}

pub const PROFILE_CORE_EVENT_STORE: &str = "ck.profile.core_event_store.v1";
pub const PROFILE_PRINCIPAL_SERVER_EVENTS_API: &str = "ck.profile.principal_server_events_api.v1";
pub const OP_EVENTS_DESCRIBE: &str = "ck.self.events.describe";
pub const OP_EVENTS_SUBMIT: &str = "ck.self.events.submit";

/// Yougen-side convenience methods over the SDK's [`ServerDescription`].
///
/// Yougen no longer maintains its own `ServerDescription` struct; the SDK
/// type is now the single source of truth, matching the spec at
/// `cokret-spec/spec/v1/artifacts/schemas/service-describe.schema.json`
/// (17 required Round 4 fields, typed `claimed_profiles` / `compat_surfaces`,
/// validated `Did` / `TypedTrustDomainId`). Because yougen cannot add
/// inherent impls on a foreign type, the previous helper methods now live
/// on this extension trait — call sites only need `use
/// crate::models::ServerDescriptionExt;` to get them back.
pub trait ServerDescriptionExt {
    fn supports_profile(&self, profile: &str) -> bool;
    fn supports_operation(&self, operation_id: &str) -> bool;
    fn supports_feature(&self, feature: &str) -> bool;
    fn supports_event_envelope_write_plane(&self) -> bool;
    fn missing_event_envelope_write_requirements(&self) -> Vec<&'static str>;
    fn missing_v1_principal_server_requirements(&self) -> Vec<&'static str>;
    fn is_v1_principal_server_ready(&self) -> bool;
    /// Round 4 — true iff the declared trust domain matches `expected`.
    /// `Did` / `TypedTrustDomainId` enforce non-emptiness on
    /// construction so we don't need a separate "is empty" guard.
    fn trust_domain_matches(&self, expected: &str) -> bool;
    /// Round 4 — treat a missing / null `plaintext_visibility` as
    /// `untrusted` for late-recovery handling.
    fn is_plaintext_visibility_untrusted(&self) -> bool;
}

impl ServerDescriptionExt for ServerDescription {
    fn supports_profile(&self, profile: &str) -> bool {
        self.supported_profiles.iter().any(|value| value == profile)
    }

    fn supports_operation(&self, operation_id: &str) -> bool {
        self.supported_operations
            .iter()
            .any(|value| value == operation_id)
    }

    fn supports_feature(&self, feature: &str) -> bool {
        self.supported_features.iter().any(|value| value == feature)
    }

    fn supports_event_envelope_write_plane(&self) -> bool {
        self.missing_event_envelope_write_requirements().is_empty()
    }

    fn missing_event_envelope_write_requirements(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.supports_profile(PROFILE_CORE_EVENT_STORE)
            && !self.supports_profile(PROFILE_PRINCIPAL_SERVER_EVENTS_API)
        {
            missing.push(PROFILE_CORE_EVENT_STORE);
        }
        if !self.supports_operation(OP_EVENTS_DESCRIBE) {
            missing.push(OP_EVENTS_DESCRIBE);
        }
        if !self.supports_operation(OP_EVENTS_SUBMIT) {
            missing.push(OP_EVENTS_SUBMIT);
        }
        missing
    }

    fn missing_v1_principal_server_requirements(&self) -> Vec<&'static str> {
        // `service_did` is now a `Did` validated on construction, so the
        // legacy `starts_with("did:")` check is redundant — failure to
        // start with "did:" makes the whole response un-deserialisable.
        let mut missing = Vec::new();
        if self.service_type != "principal_server" {
            missing.push("service_type=principal_server");
        }
        if self.protocol_version != "1.0" {
            missing.push("protocol_version=1.0");
        }
        missing.extend(self.missing_event_envelope_write_requirements());
        if self.plaintext_visibility.is_null() {
            missing.push("plaintext_visibility");
        }
        missing
    }

    fn is_v1_principal_server_ready(&self) -> bool {
        self.missing_v1_principal_server_requirements().is_empty()
    }

    fn trust_domain_matches(&self, expected: &str) -> bool {
        self.trust_domain.as_str() == expected.trim()
    }

    fn is_plaintext_visibility_untrusted(&self) -> bool {
        self.plaintext_visibility.is_null()
    }
}

// R35: `ck.identity.describe` body. The SDK's canonical type is
// `IdentityDescription` (same fields, with `service_did: Did` validated on
// construction); the SDK's own `IdentityDescribeOutcome` is a transparent
// newtype around it. We re-export the inner struct under the yougen-local
// name so call sites (`registry_mode` read in `views/dashboard.rs`) stay
// unchanged while the field shapes are now SDK-owned.
pub use cokret_sdk::model::{
    IdentityDescription as IdentityDescribeOutcome, IdentityResolveOutcome,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SyncDescribeResBody {
    pub service_did: String,
    #[serde(default)]
    pub supported_sync_profiles: Vec<String>,
    #[serde(default)]
    pub limits: Value,
    #[serde(default)]
    pub frontier: Value,
}

/// Wire-shape sync response — re-exports the SDK's canonical
/// [`cokret_sdk::model::SyncOutcome`] so client + server can never
/// drift on field names / per-realm body shape. Spec source of truth
/// at `cokret-spec/spec/v1/zh/sync/client-sync.md §2`. Yougen used to
/// own a custom `ClientSyncResponse` with a bucketed-`spaces`
/// deserializer; that was an older Matrix-style transcript that
/// disagreed with what soland actually emits.
pub use cokret_sdk::model::SyncOutcome as ClientSyncResponse;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SearchRealmsResponse {
    pub results: Vec<RealmTreeNode>,
    pub next_cursor: Option<String>,
}

/// soland's directory `describe` wire body. Named distinctly from the SDK
/// core `cokret_sdk::model::DirectoryDescribeOutcome` (which wraps a typed
/// `DirectoryDescription`) because this soland surface has a different,
/// flat shape; sharing the SDK name would mislead readers into expecting
/// the same wire contract.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SolandDirectoryDescribeResBody {
    pub service_did: String,
    pub resource_types: Vec<String>,
    pub discovery_profiles: Vec<String>,
    pub restricted_query_proof: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolveRealmResponse {
    pub realm_preview: RealmTreeNode,
    #[serde(default)]
    pub stripped_state: Vec<Value>,
    pub join_rule: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub join_candidates: Vec<RealmJoinCandidate>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RealmJoinCandidate {
    pub realm_id: String,
    pub service_did: String,
    pub service_type: String,
    pub role: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub join_methods: Vec<String>,
    #[serde(default)]
    pub priority: Option<u16>,
    pub source: String,
    #[serde(default)]
    pub source_refs: Option<Vec<String>>,
    #[serde(default)]
    pub frontier_ref: Option<String>,
    pub as_of: String,
    pub expires_at: String,
    #[serde(default)]
    pub proofs: Vec<Value>,
}

/// Sidebar tag distinguishing a security-boundary Realm from a product
/// Space. Wire signal is either the `ck.schema.{realm,space}.v1` schema
/// field on a projection body, or a yougen-local `__kind` tag used by
/// optimistic post-create state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmTreeNodeKind {
    /// `ck:realm:*` — security / sync / E2EE boundary.
    #[default]
    Realm,
    /// `ck:space:*` — navigation container inside a Realm.
    Space,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RealmTreeNode {
    /// Navigation node id. Realm nodes hold `ck:realm:*`; Space nodes hold
    /// `ck:space:*`. Do not put Realm ids in a `space_id` field.
    pub id: String,
    /// Canonical display name. Spec `realm.schema.json` / `space.schema.json`
    /// both make `title` the required display field; `name` is reserved for
    /// external protocol / algorithm / service labels.
    pub title: String,
    pub description: Option<String>,
    pub tags: std::collections::BTreeSet<String>,
    pub public: bool,
    pub category: Option<String>,
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

        let mut state = serializer.serialize_struct("RealmTreeNode", 10)?;
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
        if let Some(parent) = node
            .parent_space_id
            .as_deref()
            .map(str::trim)
            .filter(|parent| !parent.is_empty())
        {
            current = parent;
        } else {
            return None;
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{
        RealmTreeNode, RealmTreeNodeKind, projection_realm_id_for_known_node,
        projection_realm_id_for_node,
    };

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
            preview("ck:realm:root", RealmTreeNodeKind::Realm, "", None),
            preview(
                "ck:space:child",
                RealmTreeNodeKind::Space,
                "ck:realm:root",
                Some("ck:realm:root"),
            ),
        ];

        assert_eq!(
            projection_realm_id_for_node(&spaces, "ck:space:child"),
            "ck:realm:root"
        );
    }

    #[test]
    fn projection_realm_id_climbs_parent_links_to_realm() {
        let spaces = vec![
            preview("ck:realm:root", RealmTreeNodeKind::Realm, "", None),
            preview(
                "ck:space:child",
                RealmTreeNodeKind::Space,
                "",
                Some("ck:realm:root"),
            ),
        ];

        assert_eq!(
            projection_realm_id_for_node(&spaces, "ck:space:child"),
            "ck:realm:root"
        );
    }

    #[test]
    fn known_projection_realm_id_waits_for_unknown_routes() {
        assert_eq!(
            projection_realm_id_for_known_node(&[], "ck:space:child"),
            None
        );
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BackfillOutcome {
    #[serde(default)]
    pub events: Vec<Value>,
    pub prev_cursor: Option<String>,
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub limited: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SnapshotHeadState {
    pub snapshot_ref: String,
    pub state_digest: String,
    #[serde(default)]
    pub frontier: Value,
    #[serde(default)]
    pub signature: Value,
}

pub use cokret_sdk::model::AuthzCheckOutcome;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GrantList {
    #[serde(default)]
    pub grants: Vec<Value>,
    pub state_digest: Option<String>,
    pub evaluated_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InvitesResponse {
    #[serde(default)]
    pub invites: Vec<Value>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PushRegisterResponse {
    pub ok: bool,
    pub registration_id: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

pub use cokret_sdk::model::{
    DeviceMessagesPutOutcome, KeysClaimOutcome, KeysQueryOutcome, KeysUploadOutcome, OkOutcome,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceMessagesGetOutcome {
    pub events: Vec<Value>,
    #[serde(default)]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub limited: bool,
}

pub use cokret_sdk::model::BlobUploadOutcome;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModerationReportOutcome {
    pub report_id: String,
    pub status: String,
    #[serde(default)]
    pub routed_to: Vec<String>,
}

// ── Directory ───────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SearchOrganizationsResponse {
    pub results: Vec<Value>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SearchActorsResponse {
    pub results: Vec<Value>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolveHandleResponse {
    #[serde(default, alias = "subject")]
    pub did: String,
    pub handle: String,
    pub did_document: Option<Value>,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub claims: Value,
    /// Audience the directory bound the response claim to. Spec 0a5ab85:
    /// the client MUST reject claims whose audience doesn't match the
    /// invocation context (e.g. the Space the user is about to join).
    #[serde(default)]
    pub audience: Option<String>,
    /// Membership-builder routing evidence for `intent=member_add|invite`.
    /// Some directory implementations expose this top-level; others carry
    /// the same object inside `handle_claim.member_delivery_binding`.
    #[serde(default)]
    pub member_delivery_binding: Option<Value>,
    /// Raw handle claim envelope when the directory issued one. Shape
    /// conforms to `handle-claim.schema.json` — typed deserialization is
    /// TODO(spec-sync 0a5ab85) once we depend on the SDK `HandleClaim`.
    #[serde(default)]
    pub handle_claim: Option<Value>,
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

impl ResolveHandleResponse {
    pub fn subject_did(&self) -> Option<&str> {
        (!self.did.trim().is_empty())
            .then_some(self.did.as_str())
            .or_else(|| {
                self.handle_claim
                    .as_ref()
                    .and_then(|claim| claim.get("subject"))
                    .and_then(Value::as_str)
            })
    }

    pub fn claim_audience(&self) -> Option<&str> {
        self.audience.as_deref().or_else(|| {
            self.handle_claim
                .as_ref()
                .and_then(|claim| claim.get("audience"))
                .and_then(Value::as_str)
        })
    }

    pub fn has_member_delivery_binding(&self) -> bool {
        self.member_delivery_binding.is_some()
            || self
                .handle_claim
                .as_ref()
                .and_then(|claim| claim.get("member_delivery_binding"))
                .is_some()
    }
}

/// Structured mention node embedded in message body. Spec b56cab1
/// `models/flow-and-message.md §9.4` + `identity/identity-handles.md §3.8`.
///
/// R3.2 wire-breaking: `subject_id` (principal DID) is the ONLY
/// authoritative field — actor attribution, authorization, resolution
/// and render lookup all key off it. `handle_at_time` /
/// `display_name_at_time` / `mention_text_original` are compose-time
/// audit metadata ONLY and MUST NOT be used as the current display value.
/// The old `subject` / `handle` / `display_snapshot` fields are gone.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Mention {
    /// Principal DID of the mentioned subject (authoritative).
    pub subject_id: String,
    /// Audit-only snapshot of the subject's display name at compose time.
    // R26: canonical field order per spec `models/flow-and-message.md §9.4`
    // places `display_name_at_time` before `handle_at_time`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name_at_time: Option<String>,
    /// Audit-only snapshot of the canonical `<localpart>:<domain>` handle
    /// at compose time. Never the current display value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_at_time: Option<String>,
    /// The original string the user typed (e.g. `@alice:acme.com`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mention_text_original: Option<String>,
    /// When the handle was resolved. Audit metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<String>,
}

/// Per-Realm delivery binding surfaced to the member detail view.
/// Mirrors `member_delivery_binding` from `event-payload.schema.json`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemberDeliveryBindingView {
    pub recipient_service_did: String,
    pub binding_source: String,
    pub delivery_modes: Vec<String>,
    pub resolved_at: String,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub service_endpoint: Option<String>,
}

// ── Realm / Space Management ────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RealmPolicyResponse {
    pub ok: bool,
    pub realm_id: String,
    pub join_rule: String,
    pub history_visibility: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TypingResponse {
    pub ok: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReceiptResponse {
    pub ok: bool,
}

// ── Device & Crypto ─────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RevokeDeviceResponse {
    pub ok: bool,
    pub device_id: String,
    pub revoked: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceTrustResponse {
    pub devices: Vec<DeviceTrustEntry>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceTrustEntry {
    pub device_id: String,
    pub trust_state: String,
    pub verified_at: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifyDeviceResponse {
    pub ok: bool,
    pub device_id: String,
    pub trust_state: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MlsRotateResponse {
    pub ok: bool,
    pub epoch: u64,
    pub mls_group_ref: String,
}

// ── Policy Check ─────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyCheckOutcome {
    pub decision: String,
    #[serde(default)]
    pub obligations: Vec<Value>,
    #[serde(default)]
    pub reason: Option<String>,
    pub signed_decision: Option<Value>,
}

// ── Identity (extended) ──────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DidOperationSubmitOutcome {
    pub ok: bool,
    pub operation_id: String,
    pub status: String,
}

/// soland's events `describe` wire body. Named distinctly from the SDK
/// core `cokret_sdk::model::EventsDescribeOutcome` (which has a different
/// field set: supported_event_schemas/supported_reducer_profiles/...)
/// because this soland surface emits a different shape; sharing the SDK
/// name would mislead readers into expecting the same wire contract.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SolandEventsDescribeResBody {
    pub service_did: String,
    #[serde(default)]
    pub supported_profiles: Vec<String>,
    #[serde(default)]
    pub frontier: Value,
    #[serde(default)]
    pub registry: Value,
    #[serde(default)]
    pub schema_profile: Option<String>,
    #[serde(default)]
    pub reducer_profile: Option<String>,
    #[serde(default)]
    pub capabilities: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubmitEventResponse {
    pub event_id: String,
    pub status: String,
    #[serde(default)]
    pub canonical_digest: Option<String>,
    #[serde(default)]
    pub sync_token: String,
    #[serde(default)]
    pub received_at: Option<String>,
    #[serde(default)]
    pub receipt: Value,
}

/// Round R2/R3 (T02) — server response shape for the
/// `POST /_cokret/self/ephemeral` channel. The endpoint is fire-and-forget — the
/// server's only obligation is to return `accepted: true` (signal entered
/// the broadcast fanout) or surface a structured rejection. No event id is
/// minted because ephemeral signals are never durable.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EphemeralSubmitOutcome {
    #[serde(default)]
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatched_to: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_received_at: Option<String>,
}

// ── Media ────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IceConfigResponse {
    pub realm_id: String,
    pub call_id: String,
    pub actor_id: String,
    pub device_id: String,
    #[serde(default)]
    pub ice_servers: Vec<IceServer>,
    pub ttl_seconds: u64,
    pub refresh_lead_seconds: u64,
    pub issued_at: String,
    pub signature: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub credential: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IceConfigRequest {
    pub realm_id: String,
    pub call_id: String,
    pub actor_id: String,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub context: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CreateWebrtcSessionResponse {
    pub session_id: String,
    pub realm_id: String,
    #[serde(default)]
    pub participants: Vec<String>,
    #[serde(default)]
    pub expires_at: String,
    #[serde(default)]
    pub call_state: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub recording_policy: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WebrtcSignalResponse {
    #[serde(default)]
    pub ok: bool,
    pub session_id: String,
    pub seq: u64,
    #[serde(default)]
    pub call_state: String,
    #[serde(default)]
    pub event: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CallRecordingStartResponse {
    #[serde(default)]
    pub ok: bool,
    pub call_id: String,
    pub realm_id: String,
    #[serde(default)]
    pub recording_policy: String,
    #[serde(default)]
    pub recording_id: String,
    #[serde(default)]
    pub recording_started_by: String,
    #[serde(default)]
    pub recording_blob_ref: String,
}

// ── MIMI Provider Facade ─────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiProviderDirectory {
    pub service_did: Option<String>,
    pub service_type: String,
    #[serde(default)]
    pub supported_profiles: Vec<String>,
    pub mimi: MimiProviderProfile,
    #[serde(default)]
    pub proof: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiProviderProfile {
    pub protocol_draft: String,
    pub content_draft: String,
    pub room_policy_draft: Option<String>,
    pub identifier_draft: Option<String>,
    pub base_url: String,
    pub provider_id: String,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub mls_cipher_suites: Vec<String>,
    #[serde(default)]
    pub content_profiles: Vec<String>,
    #[serde(default)]
    pub room_policy_components: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiKeyMaterialOutcome {
    pub ok: bool,
    #[serde(default)]
    pub key_packages: Vec<Value>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiRoomUpdateOutcome {
    pub ok: bool,
    pub room_id: Option<String>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiNotifyOutcome {
    pub ok: bool,
    #[serde(default)]
    pub accepted: Vec<String>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiSubmitMessageOutcome {
    pub ok: bool,
    pub mimi_message_id: Option<String>,
    pub mapped_operation_id: Option<String>,
    pub cokret_event_id: Option<String>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiGroupInfoOutcome {
    /// R20: wire field name `room_id` is preserved because it comes verbatim
    /// from the MIMI draft (`draft-ietf-mimi-room-policy-03`), which is
    /// interop-exempt from the `Room → Realm` rename
    /// (forbidden-model-terms `allowed_contexts: [interop_module]`). On the
    /// Cokret application side this identifier corresponds to a Flow; the
    /// `Room` term must stay confined to the mls/mimi interop layer. Callers
    /// crossing into the app layer SHOULD bind it to a `flow_id`-named local
    /// to make the boundary explicit (see `views/settings/mod.rs`).
    pub room_id: String,
    pub mimi_room_uri: Option<String>,
    pub group_info: Value,
    #[serde(default)]
    pub participants: Vec<Value>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiRequestConsentOutcome {
    pub ok: bool,
    pub consent_id: Option<String>,
    pub state: Option<String>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiIdentifierQueryOutcome {
    pub query: String,
    pub reachable: bool,
    pub mapped_did: Option<String>,
    pub provider_id: Option<String>,
    #[serde(default)]
    pub proofs: Vec<Value>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiReportAbuseOutcome {
    pub ok: bool,
    pub report_id: Option<String>,
    pub status: Option<String>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiProxyDownloadOutcome {
    pub ok: bool,
    pub blob_ref: String,
    pub media_type: Option<String>,
    /// Spec rename (head 37ce729 / SDK 4d5a1af): `size` → `size_bytes`.
    pub size_bytes: Option<usize>,
    pub proxy_url: Option<String>,
    #[serde(default)]
    pub receipt: Value,
}

// ─────────────────────────────────────────────────────────────────────
// CKP-0008 / CKP-0009 — Personal Agent HTTP wire types (spec head
// 37ce729 / SDK 4d5a1af / soland P2 aa76b91).
//
// These mirror soland's `AgentProvisionReqBody` / `AgentResBody` /
// `AgentListResBody` / `AgentLifecycleReqBody` / `AgentLifecycleResBody`
// / `AgentRotateKeyReqBody` / `AgentRotateKeyResBody` /
// `AgentGrantAttachReqBody` / `AgentGrantResBody` /
// `AgentGrantDetachResBody` / `AgentSidecarThreadEnsureReqBody` /
// `AgentSidecarThreadEnsureResBody` / `AgentKeyPairReqBody` /
// `AgentKeyPairResBody`. Soland's reducer-side semantics are still
// `TODO(P2-impl)` stubs, so yougen treats the response payloads
// permissively (most fields are optional/defaulted) — the wire contract
// for the 11 endpoints is what we want pinned here.
//
// TODO(P3-impl): once soland's reducer stamps `actor_kind` and the
// projection lands, tighten these into typed sub-shapes.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentKeyPairReqBody {
    pub agent_principal_id: String,
    pub verification_method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentKeyPairResBody {
    pub ok: bool,
    pub agent_principal_id: String,
    pub verification_method: String,
    pub authorized_at: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentProvisionReqBody {
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub initial_grants: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentResBody {
    pub agent_principal_id: String,
    pub controller_did: String,
    pub agent_id: String,
    pub display_name: String,
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub grants: Vec<Value>,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentListResBody {
    #[serde(default)]
    pub agents: Vec<AgentResBody>,
    #[serde(default)]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentLifecycleReqBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentLifecycleResBody {
    pub ok: bool,
    pub agent_principal_id: String,
    pub state: String,
    pub status_changed_at: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentRotateKeyReqBody {
    pub new_verification_method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_key_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentRotateKeyResBody {
    pub ok: bool,
    pub agent_principal_id: String,
    pub authorized_verification_method: String,
    #[serde(default)]
    pub revoked_verification_method: Option<String>,
    pub at: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentGrantAttachReqBody {
    pub grant_kind: String,
    #[serde(rename = "agent_key_scope")]
    pub scope: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentGrantResBody {
    pub ok: bool,
    pub agent_principal_id: String,
    pub grant_id: String,
    pub grant_kind: String,
    #[serde(rename = "agent_key_scope")]
    pub scope: Value,
    pub state: String,
    pub created_at: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentGrantDetachResBody {
    pub ok: bool,
    pub agent_principal_id: String,
    pub grant_id: String,
    pub detached_at: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

/// `ck.self.agent.sidecar_thread.ensure` request schema.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentSidecarThreadEnsureReqBody {
    pub realm_id: String,
    pub controller_principal_id: String,
    pub agent_principal_id: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentSidecarThreadEnsureResBody {
    pub ok: bool,
    pub private_circle_id: String,
    pub private_flow_id: String,
    pub private_relation_id: String,
    #[serde(default)]
    pub pending_member_reconciliations: Vec<Value>,
}
