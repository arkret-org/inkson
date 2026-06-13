pub use cokret_sdk::{
    ClaimedProfileEntry, CompatSurfaceEntry, ServerDescription, VerifiedProfileEntry,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HealthOutcome {
    pub ok: bool,
    pub service: String,
    pub storage: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DevLoginOutcome {
    pub access_token: String,
    pub token_type: String,
    pub actor: String,
    pub device_id: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LogoutOutcome {
    pub ok: bool,
    #[serde(default)]
    pub revoked: bool,
}

/// App-local current-account projection derived from the spec
/// `ck.self.account.viewer` response. `handle` is populated only from a
/// signed `primary_handle_claim.handle`; an empty string means the server did
/// not include handle evidence in the viewer response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CurrentAccountOutcome {
    pub did: String,
    #[serde(default)]
    pub handle: String,
    pub display_name: Option<String>,
    #[serde(default)]
    pub created_at: String,
}

/// A6.1 — app-local global search projection. The Cokret HTTP catalog
/// currently has no spec-defined endpoint for this query; the shape is
/// retained for the search UI state model and contract tests.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IndexSearchOutcome {
    pub query: String,
    #[serde(default)]
    pub results: Vec<Value>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContactOutcome {
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
    /// Cross-PS addressing: the peer's originating Principal Server service DID,
    /// used to reverse-deliver an accept/reject when the request came from
    /// another PS. Passed through to `contacts/respond` as
    /// `requester_service_did`.
    ///
    /// `GET /_cokret/self/contacts` now surfaces the peer's originating
    /// Principal Server on cross-PS rows, so this is populated whenever soland
    /// learned it from a cross-PS delivery; it stays `None` for same-PS
    /// contacts, where respond correctly falls back to same-PS behaviour.
    /// Accepts a couple of likely wire spellings for forward compatibility.
    #[serde(default, alias = "requester_service_did", alias = "source_service_did")]
    pub peer_service_did: Option<String>,
    /// U3 — event ref of the `ck.consent.grant` this peer gave me for the
    /// `invite` (or `any`) scope. When present, the realm-invite "from contacts"
    /// path can build `IntroductionEvidence::ConsentGrant { consent_grant_ref }`
    /// instead of requiring a locator URL.
    ///
    /// soland's `GET /_cokret/self/contacts` now surfaces this field directly
    /// (a legal `ck:event` ref when the peer granted me invite/any consent,
    /// otherwise empty/absent). When it is empty the contact has not authorised
    /// me to invite them, so the UI disables the row rather than guessing a ref.
    #[serde(default)]
    pub invite_consent_grant_ref: Option<String>,
}

impl ContactListRow {
    /// U3 — the `consent_grant` event ref for the realm-invite "from contacts"
    /// path. Returns the server-supplied `invite_consent_grant_ref` verbatim
    /// (filtering empty strings); there is no fallback — if the peer never gave
    /// me invite/any consent this is `None` and the row is not invitable.
    pub fn invite_consent_ref(&self) -> Option<&str> {
        self.invite_consent_grant_ref
            .as_deref()
            .filter(|r| !r.trim().is_empty())
    }

    /// Whether this contact has granted me the `invite` scope (i.e. I'm allowed
    /// to pull them into a Realm via the contact path).
    pub fn grants_me_invite(&self) -> bool {
        self.granted_to_me.iter().any(|s| s == "invite")
            || self.bidirectional_scopes.iter().any(|s| s == "invite")
            || self.effective_scopes.iter().any(|s| s == "invite")
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContactsOutcome {
    #[serde(default)]
    pub contacts: Vec<ContactListRow>,
    #[serde(default)]
    pub has_more: bool,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// U4 — actor `invite_receive_policy` ("谁可以邀请我").
///
/// YOU-01-006: this used to be a bespoke local mirror with all-`String`
/// enum fields and **no** `schema`/`subject_id` — which made the SET body
/// fail closed against the real soland handler (it deserialises
/// `cokret_sdk::InviteReceivePolicy`, `deny_unknown_fields`, with both
/// fields required and `subject_id == session.actor` enforced) and dropped
/// the server-stored `trusted_*` / `blocked_principal_services` lists on
/// every round-trip. We now use the SDK authoritative type, which carries
/// the required `schema`/`subject_id`, typed enums, and the trust lists, so
/// a GET→edit→SET cycle preserves fields the U4 form does not touch.
pub use cokret_sdk::model::{
    DisclosureLevel, DisclosurePolicy as InviteDisclosurePolicy, INVITE_RECEIVE_POLICY_SCHEMA,
    InviteReceiveAction, InviteReceivePolicy, UnknownInviteAction,
};

/// Build the recommended default `invite_receive_policy` for `subject_id`,
/// used as the form seed and the graceful-degrade fallback when the server
/// returns 404/501/405. Mirrors soland's
/// `default_invite_receive_policy`: accept contacts (`consent_grant`),
/// invite links (`locator_ref`) and same-group introductions
/// (`shared_realm`); hold everything else for review.
pub fn default_invite_receive_policy(subject_id: &str) -> InviteReceivePolicy {
    InviteReceivePolicy {
        schema: INVITE_RECEIVE_POLICY_SCHEMA.to_owned(),
        subject_id: cokret_sdk::Did::new(subject_id).unwrap_or_else(|_| {
            cokret_sdk::Did::new("did:web:unknown").expect("valid placeholder did")
        }),
        allowed_introduction_kinds: vec![
            "consent_grant".to_owned(),
            "locator_ref".to_owned(),
            "shared_realm".to_owned(),
        ],
        explicit_address_behavior: InviteReceiveAction::Quarantine,
        unknown_invites: UnknownInviteAction::Quarantine,
        trusted_realm_ids: Vec::new(),
        trusted_principal_services: Vec::new(),
        blocked_principal_services: Vec::new(),
        blocked_subjects: Vec::new(),
        disclosure: Some(InviteDisclosurePolicy {
            high_trust: Some(DisclosureLevel::Outcome),
            low_trust: Some(DisclosureLevel::Opaque),
        }),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ConsentCellOutcome {
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
pub struct ConsentCellsOutcome {
    pub ok: bool,
    #[serde(default)]
    pub cells: Vec<ConsentCellOutcome>,
}

/// R15: result of `ck.realm.create`. Carries a `ck:realm:*` id under the
/// canonical `realm_id` field (was previously squeezed into a shared
/// `space_id` on `SpaceLifecycleOutcome`). `state` replaces the old
/// `deleted: bool`, matching the spec lifecycle-state enum
/// (`active` / `archived` / `tombstoned`, `common-fields.md §5.1`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RealmCreateOutcome {
    pub ok: bool,
    pub realm_id: String,
    pub owner: String,
    #[serde(default)]
    pub members: Vec<String>,
    pub state: String,
}

/// R15: result of `ck.space.create`. A Space (`ck:space:*`) lives inside a
/// Realm and inherits its membership / encryption. `state` mirrors the spec
/// lifecycle enum (see [`RealmCreateOutcome`]).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpaceCreateOutcome {
    pub ok: bool,
    pub space_id: String,
    pub owner: String,
    #[serde(default)]
    pub members: Vec<String>,
    pub state: String,
}

// (Move/Seal pipeline DTOs deleted; all writes now go through
// ck.self.events.submit via SubmitEventOutcome.)

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
pub const OP_SNAPSHOT_HEAD: &str = "ck.self.snapshot.head";

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

/// `ck.self.account.describe` response (lenient local read of the spec
/// `ServiceDescribe` body; `frontier` is an authenticated extension field
/// whose shape is deployment-defined, hence `Value`). Follows the local
/// `*Outcome` DTO suffix convention (YOU-04-001).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SyncDescribeOutcome {
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
/// own a custom `ClientSyncOutcome` with a bucketed-`spaces`
/// deserializer; that was an older Matrix-style transcript that
/// disagreed with what soland actually emits.
pub use cokret_sdk::model::SyncOutcome as ClientSyncOutcome;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SearchRealmsOutcome {
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

// `resolve-realm` decodes into the canonical SDK wire types so the client stays
// byte-compatible with soland's `DirectoryRealmResolutionOutcome` response. A
// yougen-local duplicate previously drifted from the wire (a required
// `public`/`title` on the preview node, a non-optional `join_rule`) and broke
// invite-accept with "error decoding response body" whenever the server omitted
// those fields. The SDK type is the single source of truth.
pub use cokret_sdk::model::{
    DirectoryRealmResolutionOutcome as ResolveRealmOutcome, RealmJoinCandidate,
};

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

    #[test]
    fn submit_event_outcome_decodes_new_events_submit_wire() {
        // soland head 37ce729: {status, accepted[], cursor} — no top-level
        // event_id / sync_token. This is the shape that previously failed to
        // decode and broke every event submit ("error decoding response body").
        let value = serde_json::json!({
            "status": "accepted",
            "accepted": ["ck:event:0196419b-0000-7000-8000-000000000001"],
            "duplicate": [],
            "rejected": [],
            "actor_frontier": {"seq": 1},
            "realm_frontier": {},
            "cursor": "sx:cursor-1",
        });
        let outcome: super::SubmitEventOutcome = serde_json::from_value(value).unwrap();
        assert_eq!(
            outcome.event_id,
            "ck:event:0196419b-0000-7000-8000-000000000001"
        );
        assert_eq!(outcome.status, "accepted");
        assert_eq!(outcome.cursor, "sx:cursor-1");
    }

    #[test]
    fn submit_event_outcome_rejects_legacy_flat_wire() {
        // renames.json rejection policy: the legacy flat `{event_id,
        // sync_token, …}` shape MUST NOT decode — canonical-only parser.
        let value = serde_json::json!({
            "event_id": "ck:event:legacy",
            "status": "accepted",
            "sync_token": "sx:legacy",
        });
        assert!(serde_json::from_value::<super::SubmitEventOutcome>(value).is_err());
    }

    #[test]
    fn submit_event_outcome_accepts_synthetic_fixture_ids() {
        // e2e mocks emit ids like `ck:event:e2e` that are not strict UUIDv7
        // EventIds; the lenient mirror must accept them and fall back to the
        // duplicate id + "duplicate" status when nothing was newly accepted.
        let value = serde_json::json!({
            "status": "duplicate",
            "accepted": [],
            "duplicate": ["ck:event:e2e"],
        });
        let outcome: super::SubmitEventOutcome = serde_json::from_value(value).unwrap();
        assert_eq!(outcome.event_id, "ck:event:e2e");
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

    #[test]
    fn invite_receive_policy_round_trips_sdk_wire_with_trust_lists() {
        // YOU-01-006 — the bare SDK wire body (schema + subject_id required,
        // typed enums, trust lists) must decode and re-encode without losing
        // the `trusted_*` / `blocked_principal_services` lists the U4 form
        // never touches.
        let value = serde_json::json!({
            "schema": super::INVITE_RECEIVE_POLICY_SCHEMA,
            "subject_id": "did:web:me.example",
            "allowed_introduction_kinds": ["consent_grant", "locator_ref"],
            "explicit_address_behavior": "drop",
            "unknown_invites": "quarantine",
            "trusted_realm_ids": ["ck:realm:01904100-0000-7000-8000-000000000001"],
            "trusted_principal_services": ["did:web:ps.example"],
            "blocked_subjects": ["did:web:spammer.example"],
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
            "ck:realm:01904100-0000-7000-8000-000000000001"
        );
    }

    #[test]
    fn default_invite_receive_policy_carries_schema_and_subject() {
        let policy = super::default_invite_receive_policy("did:web:me.example");
        assert_eq!(policy.schema, super::INVITE_RECEIVE_POLICY_SCHEMA);
        assert_eq!(policy.subject_id.as_str(), "did:web:me.example");
        assert_eq!(
            policy.explicit_address_behavior,
            super::InviteReceiveAction::Quarantine
        );
    }

    #[test]
    fn contact_row_invite_consent_ref_uses_real_field_no_fallback() {
        let mut row = super::ContactListRow {
            peer: "did:web:bob.example".to_owned(),
            state: "accepted".to_owned(),
            response_event_ref: Some("ck:event:resp".to_owned()),
            granted_to_me: vec!["invite".to_owned()],
            ..Default::default()
        };
        // No fallback: an absent invite_consent_grant_ref yields None even
        // though response_event_ref is present and the peer granted invite.
        assert_eq!(row.invite_consent_ref(), None);
        assert!(row.grants_me_invite());
        // The real server-supplied consent ref is surfaced verbatim.
        row.invite_consent_grant_ref = Some("ck:event:consent".to_owned());
        assert_eq!(row.invite_consent_ref(), Some("ck:event:consent"));
        // Empty strings are treated as absent.
        row.invite_consent_grant_ref = Some("  ".to_owned());
        assert_eq!(row.invite_consent_ref(), None);
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BackfillOutcome {
    #[serde(default)]
    pub events: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_bootstrap: Option<Value>,
    pub prev_cursor: Option<String>,
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub limited: bool,
}

// The yougen-local `SnapshotHeadState` mirror was deleted with the
// 2026-06-11 spec resolution (`renames.json` migration group
// `snapshot_head_returns_manifest`, hard_reject): `ck.self.snapshot.head`
// now returns the full signed `ck.schema.snapshot.v1` manifest, and the
// old head-pointer DTO (`snapshot_ref` / `state_digest` / `frontier` /
// `signature`) MUST NOT appear on current wire. See
// `api::CokretApi::snapshot_head`.

pub use cokret_sdk::model::AuthzCheckOutcome;
/// `ck.self.authz.get_effective_grants` response. soland serialises the SDK
/// `GrantList` (`grants: Vec<CapabilityGrant>`) verbatim, so the client
/// decodes the same authoritative wire contract instead of a weakly-typed
/// local mirror.
pub use cokret_sdk::model::GrantList;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InvitesOutcome {
    #[serde(default)]
    pub invites: Vec<Value>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PushRegisterOutcome {
    pub ok: bool,
    pub registration_id: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// `POST /_cokret/self/moderation/report` response. soland emits the SDK
/// `ModerationReportOutcome` wire shape verbatim (`status: "submitted"`,
/// `routed_to: Vec<Did>` — scalar DIDs only, no fragments, per
/// `service-operation-dtos.schema.json#/$defs/ModerationReportOutcome`).
pub use cokret_sdk::model::ModerationReportOutcome;
pub use cokret_sdk::model::{
    BlobUploadOutcome, DeviceMessageEnvelope, DeviceMessagesAckOutcome,
    DeviceMessagesAckRequestBody, DeviceMessagesGetOutcome, DeviceMessagesPutOutcome,
    KeysClaimOutcome, KeysQueryOutcome, KeysUploadOutcome, OkOutcome,
};

// ── Directory ───────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SearchOrganizationsOutcome {
    pub results: Vec<Value>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SearchActorsOutcome {
    pub results: Vec<Value>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolveHandleOutcome {
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

impl ResolveHandleOutcome {
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

    pub fn member_delivery_binding_value(&self) -> Option<Value> {
        self.member_delivery_binding.clone().or_else(|| {
            self.handle_claim
                .as_ref()
                .and_then(|claim| claim.get("member_delivery_binding"))
                .cloned()
        })
    }
}

/// Structured mention node embedded in message body. Spec
/// `models/flow-and-message.md §9.4` + `identity/identity-handles.md §3.8`.
///
/// YOU-05-006: the former hand-rolled weakly-typed mirror (all-`String`
/// fields) duplicated the SDK's authoritative strongly-typed model
/// (`Did` / `Handle` / `DateTime<Utc>`) and had already drifted in field
/// declaration order. Re-export the SDK type; `subject_id` (principal
/// DID) remains the ONLY authoritative field — the `*_at_time` fields
/// are compose-time audit metadata only.
pub use cokret_sdk::model::Mention;

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
pub struct RealmPolicyOutcome {
    pub ok: bool,
    pub realm_id: String,
    pub join_rule: String,
    pub history_visibility: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TypingOutcome {
    pub ok: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReceiptOutcome {
    pub ok: bool,
}

// ── Device & Crypto ─────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RevokeDeviceOutcome {
    pub ok: bool,
    pub device_id: String,
    pub revoked: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceTrustOutcome {
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
pub struct VerifyDeviceOutcome {
    pub ok: bool,
    pub device_id: String,
    pub trust_state: String,
}

/// `ck.self.events.submit` response.
///
/// Decodes **only** the canonical `EventsSubmitOutcome` wire shape —
/// `{status, accepted[], duplicate[], rejected[], actor_frontier,
/// realm_frontier, cursor}` (spec
/// `service-operation-dtos.schema.json#/$defs/EventsSubmitOutcome`,
/// required: `status`, `accepted`). The yougen-facing flat surface is
/// folded from it on deserialize via [`EventsSubmitWire`]:
///   * `event_id` ← first `accepted` (else first `duplicate`)
///   * `cursor`   ← `cursor` (read-your-writes barrier)
///   * `status`   ← the `accepted` / `duplicate` / `partial` discriminant
///
/// Per renames.json rejection policy, the legacy flat
/// `{event_id, sync_token, …}` shape is NOT tolerated — mocks must emit
/// the canonical shape. Ids stay plain `String`s so synthetic fixture ids
/// do not trip the strict `EventId` validator.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(from = "EventsSubmitWire")]
pub struct SubmitEventOutcome {
    pub event_id: String,
    pub status: String,
    #[serde(default)]
    pub cursor: String,
    #[serde(default)]
    pub receipt: Value,
}

/// Deserialization mirror for the canonical `EventsSubmitOutcome` wire
/// shape. See [`SubmitEventOutcome`]. `status` and `accepted` are required
/// per spec; the rest defaults.
#[derive(Deserialize)]
struct EventsSubmitWire {
    status: String,
    accepted: Vec<String>,
    #[serde(default)]
    duplicate: Vec<String>,
    #[serde(default)]
    rejected: Vec<Value>,
    #[serde(default)]
    actor_frontier: Value,
    #[serde(default)]
    realm_frontier: Value,
    #[serde(default)]
    cursor: Option<String>,
}

impl From<EventsSubmitWire> for SubmitEventOutcome {
    fn from(wire: EventsSubmitWire) -> Self {
        let event_id = wire
            .accepted
            .first()
            .cloned()
            .or_else(|| wire.duplicate.first().cloned())
            .unwrap_or_default();
        let receipt = serde_json::json!({
            "accepted": wire.accepted,
            "duplicate": wire.duplicate,
            "rejected": wire.rejected,
            "actor_frontier": wire.actor_frontier,
            "realm_frontier": wire.realm_frontier,
        });
        Self {
            event_id,
            status: wire.status,
            cursor: wire.cursor.unwrap_or_default(),
            receipt,
        }
    }
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

// YOU-05-004: the hand-rolled `IceConfigOutcome` / `IceServer` /
// `IceConfigRequestBody` mirrors drifted from the SDK wire types (missing
// `expires_at` / `force_turn`, `ttl_seconds: u64` vs the authoritative
// `u32`) and bypassed the TURN credential privacy guard. Re-export the
// SDK's authoritative types instead. When the WebRTC surface is wired up,
// each `ice_servers` entry MUST be parsed through `cokret_sdk::IceServer`
// and pass `IceServer::validate_credential_privacy()` (rejects TURN
// usernames embedding cross-Realm stable DIDs, B-14).
pub use cokret_sdk::model::{MediaIceConfigOutcome, MediaIceConfigRequestBody};

// WebRTC call signaling/recording no longer round-trips through bespoke
// `/_cokret/self/webrtc/*` outcomes: signaling is a `ck.call.signal`
// ephemeral envelope (EphemeralSubmitOutcome) and recording is a durable
// `ck.call.recording.start` event (SubmitEventOutcome). See
// `crypto-media/webrtc-signaling.md` §5/§7. The former
// CreateWebrtcSessionOutcome / WebrtcSignalOutcome / CallRecordingStartOutcome
// mirrors were removed (YOU-01-002).

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
// CKP-0008 / CKP-0009 — Personal Agent HTTP wire types.
//
// YOU-01-005: the former hand-rolled `Agent*ReqBody` / `Agent*ResBody`
// mirrors drifted from `agent-operations.schema.json` (extra required
// fields, non-spec `todos`, wrong outcome shapes) and were removed. The
// agent surface now uses the SDK's authoritative types
// (`cokret_sdk::AgentKeyPairRequestBody` / `AgentProvisionOutcome` /
// `AgentList` / `AgentView` / `AgentRotateKeyOutcome` /
// `AgentGrantAttachOutcome` / `AgentSidecarThreadEnsureOutcome` / ...)
// directly in `api::agent` and `views::agents`.
