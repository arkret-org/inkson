pub use cokret_sdk::{
    ClaimedProfileEntry, CompatSurfaceEntry, ServerDescription, VerifiedProfileEntry,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// App-local current-account projection derived from the spec
/// `ck.self.account.query.viewer` response. `handle` is populated only from a
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

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DirectConversationSummary {
    pub realm_id: String,
    pub main_strand_id: String,
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
pub struct ContactListView {
    #[serde(default)]
    pub contacts: Vec<ContactListRow>,
    #[serde(default)]
    pub has_more: bool,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

impl ContactListView {
    pub fn from_sdk(list: cokret_sdk::ContactList) -> anyhow::Result<Self> {
        Ok(Self {
            contacts: list
                .contacts
                .into_iter()
                .map(ContactListRow::from_sdk)
                .collect(),
            has_more: list.has_more,
            next_cursor: list.next_cursor.map(|cursor| cursor.encode()).transpose()?,
        })
    }
}

impl ContactListRow {
    pub fn from_sdk(row: cokret_sdk::ContactListRow) -> Self {
        Self {
            peer: row.peer.to_string(),
            state: contact_state_wire(row.state).to_owned(),
            request_event_ref: row.request_event_ref.map(|value| value.to_string()),
            response_event_ref: row.response_event_ref.map(|value| value.to_string()),
            tombstone_event_ref: row.tombstone_event_ref.map(|value| value.to_string()),
            granted_by_me: row.granted_by_me,
            granted_to_me: row.granted_to_me,
            bidirectional_scopes: row.bidirectional_scopes,
            effective_scopes: row.effective_scopes,
            direct_conversation: row
                .direct_conversation
                .map(DirectConversationSummary::from_sdk),
            peer_service_did: row.peer_service_did.map(|value| value.to_string()),
            invite_consent_grant_ref: row.invite_consent_grant_ref.map(|value| value.to_string()),
        }
    }
}

impl DirectConversationSummary {
    pub fn from_sdk(summary: cokret_sdk::DirectConversationSummary) -> Self {
        Self {
            realm_id: summary.realm_id.to_string(),
            main_strand_id: summary.main_strand_id.to_string(),
            binding_event_ref: summary.binding_event_ref.map(|value| value.to_string()),
            state: direct_conversation_binding_state_wire(summary.state).to_owned(),
        }
    }
}

fn contact_state_wire(state: cokret_sdk::ContactState) -> &'static str {
    match state {
        cokret_sdk::ContactState::PendingOutgoing => "pending_outgoing",
        cokret_sdk::ContactState::PendingIncoming => "pending_incoming",
        cokret_sdk::ContactState::Accepted => "accepted",
        cokret_sdk::ContactState::Rejected => "rejected",
        cokret_sdk::ContactState::Tombstoned => "tombstoned",
    }
}

fn direct_conversation_binding_state_wire(
    state: cokret_sdk::DirectConversationBindingState,
) -> &'static str {
    match state {
        cokret_sdk::DirectConversationBindingState::Active => "active",
        cokret_sdk::DirectConversationBindingState::Retired => "retired",
        cokret_sdk::DirectConversationBindingState::Duplicate => "duplicate",
        cokret_sdk::DirectConversationBindingState::NonCanonical => "non_canonical",
    }
}

/// U4 - actor `invite_receive_policy` ("who can invite me").
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
pub use cokret_sdk::models::{
    DisclosureLevel, DisclosurePolicy as InviteDisclosurePolicy, INVITE_RECEIVE_POLICY_SCHEMA,
    InviteReceiveAction, InviteReceivePolicy, UnknownInviteAction,
};

/// Build the recommended default `invite_receive_policy` for `subject_id`,
/// used as the form seed and the graceful-degrade fallback when the server
/// returns 404/501/405. Mirrors soland's
/// `default_invite_receive_policy`: accept contacts (`consent_grant`),
/// invite links (`locator_ref`) and same-group introductions
/// (`shared_realm`); hold everything else for review.
#[allow(clippy::expect_used)]
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
        handle_claim_behavior: Some(InviteReceiveAction::Quarantine),
        unknown_invites: UnknownInviteAction::Quarantine,
        allowed_handle_domains: Vec::new(),
        blocked_handle_domains: Vec::new(),
        trusted_handle_issuers: Vec::new(),
        trusted_directory_services: Vec::new(),
        trusted_realm_ids: Vec::new(),
        trusted_principal_services: Vec::new(),
        blocked_principal_services: Vec::new(),
        blocked_subjects: Vec::new(),
        disclosure: Some(InviteDisclosurePolicy {
            high_trust: Some(DisclosureLevel::Outcome),
            discovery_trust: Some(DisclosureLevel::Opaque),
            low_trust: Some(DisclosureLevel::Opaque),
        }),
    }
}

/// R15: result of `ck.realm.create`. Carries a `ck:realm:*` id under the
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

/// R15: result of `ck.space.create`. A Space (`ck:space:*`) lives inside a
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
// ck.self.events.command.submit via SubmitEventResult.)

/// Result of [`crate::api::CokretApi::set_account_data`]. Captures the
/// graceful-degradation contract: 404/501/405 are not treated as errors —
/// soland's principal-control lookup / event ingest may be absent on older
/// deployments and the client must keep working when that path is not wired.
#[derive(Debug, Clone)]
pub enum AccountDataSetResult {
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
pub const OP_EVENTS_DESCRIBE: &str = "ck.self.events.query.describe";
pub const OP_EVENTS_SUBMIT: &str = "ck.self.events.command.submit";
pub const OP_SNAPSHOT_HEAD: &str = "ck.self.snapshot.query.manifest_head";

/// Inkson-side convenience methods over the SDK's [`ServerDescription`].
///
/// Inkson no longer maintains its own `ServerDescription` struct; the SDK
/// type is now the single source of truth, matching the spec at
/// `arkret-spec/spec/v1/artifacts/schemas/service-describe.schema.json`
/// (17 required Round 4 fields, typed `claimed_profiles` / `compat_surfaces`,
/// validated `Did` / `TypedTrustDomainId`). Because inkson cannot add
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
        // `service_did` is a `Did` validated on construction; failure to
        // start with "did:" makes the whole response un-deserialisable.
        let mut missing = Vec::new();
        if self.service_type != "principal_server" {
            missing.push("service_type=principal_server");
        }
        if self.protocol_version != "1.0" {
            missing.push("protocol_version=1.0");
        }
        missing.extend(self.missing_event_envelope_write_requirements());
        // `plaintext_visibility` is a required, strongly-typed field of the v1
        // ServiceDescribe: a describe that omits it fails to deserialize before
        // reaching here, so its presence is structurally guaranteed.
        missing
    }

    fn is_v1_principal_server_ready(&self) -> bool {
        self.missing_v1_principal_server_requirements().is_empty()
    }

    fn trust_domain_matches(&self, expected: &str) -> bool {
        self.trust_domain.as_str() == expected.trim()
    }

    fn is_plaintext_visibility_untrusted(&self) -> bool {
        // Vacuous (all-default) declaration carries no usable plaintext-boundary
        // signal — treat as untrusted / fail-closed, matching the v1 receiver
        // rule for an absent value.
        self.plaintext_visibility == cokret_sdk::PlaintextVisibility::none()
    }
}

// R35: `ck.identity.describe` body. The SDK's canonical type is
// `IdentityDescription` (same fields, with `service_did: Did` validated on
// construction); the SDK's own `IdentityDescribeOutcome` is a transparent
// newtype around it. We re-export the inner struct under the inkson-local
// name so call sites (`registry_mode` read in `views/dashboard.rs`) stay
// unchanged while the field shapes are now SDK-owned.
// `ck.self.account.query.describe` decodes into the SDK's authoritative
// `cokret_sdk::models::SyncDescription`; the former inkson-local
// `SyncDescribeView` mirror was removed in favor of the wire type.
/// Directory `describe` response. The SDK's `DirectoryDescribeOutcome` is a
/// transparent wrapper over this exact wire body, so inkson consumes the SDK
/// authority directly instead of maintaining a flat local mirror.
pub use cokret_sdk::models::DirectoryDescription;
/// Wire-shape sync response — re-exports the SDK's canonical
/// [`cokret_sdk::models::SyncOutcome`] so client + server can never
/// drift on field names / per-realm body shape. Spec source of truth
/// at `arkret-spec/spec/v1/zh/sync/client-sync.md §2`. Inkson used to
/// own a custom `ClientSyncOutcome` with a bucketed-`spaces`
/// deserializer; that was an older Matrix-style transcript that
/// disagreed with what soland actually emits.
pub use cokret_sdk::models::SyncOutcome as ClientSyncOutcome;
// `resolve-realm` decodes into the canonical SDK wire types so the client stays
// byte-compatible with soland's `DirectoryRealmResolutionOutcome` response. A
// inkson-local duplicate previously drifted from the wire (a required
// `public`/`title` on the preview node, a non-optional `join_rule`) and broke
// invite-accept with "error decoding response body" whenever the server omitted
// those fields. The SDK type is the single source of truth.
pub use cokret_sdk::models::{
    DirectoryRealmResolutionOutcome as ResolveRealmOutcome, RealmJoinCandidate,
};
pub use cokret_sdk::models::{
    IdentityDescription as IdentityDescribeOutcome, IdentityResolveOutcome,
};

/// Sidebar tag distinguishing a security-boundary Realm from a product
/// Space. Wire signal is either the `ck.schema.{realm,space}.v1` schema
/// field on a projection body, or a inkson-local `__kind` tag used by
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
            "accepted": ["ak:event:0196419b-0000-7000-8000-000000000001"],
            "duplicate": [],
            "rejected": [],
            "actor_frontier": {"seq": 1},
            "realm_frontier": {},
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
        // the `trusted_*` / `blocked_principal_services` lists the U4 form
        // never touches.
        let value = serde_json::json!({
            "schema": super::INVITE_RECEIVE_POLICY_SCHEMA,
            "subject_id": "did:web:me.example",
            "allowed_introduction_kinds": ["consent_grant", "locator_ref"],
            "explicit_address_behavior": "drop",
            "unknown_invites": "quarantine",
            "trusted_realm_ids": ["ak:realm:01904100-0000-7000-8000-000000000001"],
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
            "ak:realm:01904100-0000-7000-8000-000000000001"
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
            response_event_ref: Some("ak:event:resp".to_owned()),
            granted_to_me: vec!["invite".to_owned()],
            ..Default::default()
        };
        // No fallback: an absent invite_consent_grant_ref yields None even
        // though response_event_ref is present and the peer granted invite.
        assert_eq!(row.invite_consent_ref(), None);
        assert!(row.grants_me_invite());
        // The real server-supplied consent ref is surfaced verbatim.
        row.invite_consent_grant_ref = Some("ak:event:consent".to_owned());
        assert_eq!(row.invite_consent_ref(), Some("ak:event:consent"));
        // Empty strings are treated as absent.
        row.invite_consent_grant_ref = Some("  ".to_owned());
        assert_eq!(row.invite_consent_ref(), None);
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SnapshotBootstrapJson(pub Value);

impl From<Value> for SnapshotBootstrapJson {
    fn from(value: Value) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BackfillView {
    #[serde(default)]
    pub events: Vec<cokret_sdk::Event>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_bootstrap: Option<SnapshotBootstrapJson>,
    pub prev_cursor: Option<String>,
    pub next_cursor: Option<String>,
    // Spec `EventsQueryOutcome.has_more` (was the soland-local `limited`).
    #[serde(default, alias = "limited")]
    pub has_more: bool,
}

impl BackfillView {
    /// UI projection code still has tolerant event walkers for historical
    /// server shapes. Keep that leniency behind an explicit adapter so the
    /// standard backfill response itself remains SDK typed.
    pub fn event_values(&self) -> Vec<Value> {
        self.events
            .iter()
            .filter_map(|event| serde_json::to_value(event).ok())
            .collect()
    }
}

impl From<cokret_sdk::EventsQueryOutcome> for BackfillView {
    fn from(outcome: cokret_sdk::EventsQueryOutcome) -> Self {
        Self {
            events: outcome.events,
            snapshot_bootstrap: outcome.snapshot_bootstrap.map(Into::into),
            prev_cursor: outcome.prev_cursor,
            next_cursor: outcome.next_cursor,
            has_more: outcome.has_more,
        }
    }
}

// `ck.self.snapshot.query.manifest_head` returns the full signed
// `ck.schema.snapshot.v1` manifest. See `api::CokretApi::snapshot_head`.

pub use cokret_sdk::models::AuthzCheckOutcome;
/// `ck.self.authz.invites` decodes into the SDK's authoritative
/// `AuthzInviteList` (`invites: Vec<Invite>`, `next_cursor`, `has_more`); the
/// former inkson-local `InvitesView` mirror was removed in favor of the wire
/// type.
pub use cokret_sdk::models::AuthzInviteList;
/// `ck.self.authz.grants.query.effective` response. soland serialises the SDK
/// `GrantList` (`grants: Vec<CapabilityGrant>`) verbatim, so the client
/// decodes the same authoritative wire contract instead of a weakly-typed
/// local mirror.
pub use cokret_sdk::models::GrantList;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PushRegisterView {
    pub ok: bool,
    pub registration_id: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// `POST /_cokret/self/moderation/report` response. soland emits the SDK
/// `ModerationReportOutcome` wire shape verbatim (`status: "submitted"`,
/// `routed_to: Vec<Did>` — scalar DIDs only, no fragments, per
/// `service-operation-dtos.schema.json#/$defs/ModerationReportOutcome`).
pub use cokret_sdk::models::ModerationReportOutcome;
pub use cokret_sdk::models::{
    BlobUploadOutcome, DeviceMessageEnvelope, DeviceMessagesAckOutcome,
    DeviceMessagesAckRequestBody, DeviceMessagesGetOutcome, DeviceMessagesSendOutcome,
    KeysClaimOutcome, KeysQueryOutcome, KeysUploadOutcome, OkOutcome,
};

// ── Directory ───────────────────────────────────────────────────

pub type SearchOrganizationsView = cokret_sdk::models::DirectoryOrganizationSearchOutcome;
pub type SearchActorsView = cokret_sdk::models::DirectoryActorSearchOutcome;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DirectoryClaimsJson(pub Value);

impl From<Value> for DirectoryClaimsJson {
    fn from(value: Value) -> Self {
        Self(value)
    }
}

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
    #[serde(default, alias = "subject")]
    pub did: String,
    pub handle: String,
    pub did_document: Option<DirectoryDidDocumentJson>,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub claims: DirectoryClaimsJson,
    /// Audience the directory bound the response claim to. Spec 0a5ab85:
    /// the client MUST reject claims whose audience doesn't match the
    /// invocation context (e.g. the Space the user is about to join).
    #[serde(default)]
    pub audience: Option<String>,
    /// Membership-builder routing evidence for `intent=member_add|invite`.
    /// Some directory implementations expose this top-level; others carry
    /// the same object inside `handle_claim.member_delivery_binding`.
    #[serde(default)]
    pub member_delivery_binding: Option<cokret_sdk::models::DeliveryBindingHint>,
    /// Typed handle claim envelope when the directory issued one.
    #[serde(default)]
    pub handle_claim: Option<cokret_sdk::models::HandleClaim>,
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

    pub fn member_delivery_binding_ref(&self) -> Option<&cokret_sdk::models::DeliveryBindingHint> {
        self.member_delivery_binding.as_ref().or_else(|| {
            self.handle_claim
                .as_ref()
                .and_then(|claim| claim.member_delivery_binding.as_ref())
        })
    }
}

impl From<cokret_sdk::models::DirectoryHandleResolutionOutcome> for ResolveHandleView {
    fn from(outcome: cokret_sdk::models::DirectoryHandleResolutionOutcome) -> Self {
        // The server-side `DirectoryHandleResolutionOutcome` has no
        // `did_document` field (this resolve endpoint never emits one), so it
        // is always `None` here — behavior-equivalent to the prior wire decode.
        Self {
            did: outcome.did.as_str().to_owned(),
            handle: outcome.handle,
            did_document: None,
            verified: outcome.verified,
            claims: outcome.claims.into(),
            audience: outcome.audience,
            member_delivery_binding: outcome.member_delivery_binding,
            handle_claim: outcome.handle_claim,
            as_of: outcome
                .as_of
                .map(|as_of| as_of.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
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
pub use cokret_sdk::models::Mention;

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

/// `ck.self.events.command.submit` response.
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
}

impl From<cokret_sdk::EventsSubmitOutcome> for SubmitEventResult {
    fn from(outcome: cokret_sdk::EventsSubmitOutcome) -> Self {
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
            cokret_sdk::EventsSubmitStatus::Accepted => "accepted",
            cokret_sdk::EventsSubmitStatus::Duplicate => "duplicate",
            cokret_sdk::EventsSubmitStatus::Partial => "partial",
            cokret_sdk::EventsSubmitStatus::HistoricalOnly => "historical_only",
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
            "actor_frontier": outcome.actor_frontier,
            "realm_frontier": outcome.realm_frontier,
        });
        Self {
            event_id,
            status,
            cursor: outcome.cursor.unwrap_or_default(),
            receipt,
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
        let outcome = cokret_sdk::EventsSubmitOutcome::deserialize(value)
            .map_err(serde::de::Error::custom)?;
        Ok(outcome.into())
    }
}

/// Round R2/R3 (T02) — server response shape for the
// The `POST /_cokret/self/ephemeral` channel is fire-and-forget; its response
// decodes into the SDK's authoritative `cokret_sdk::EphemeralSubmitOutcome`
// (`accepted`, `dispatched_to`, `server_received_at`). The former inkson-local
// `EphemeralSubmitResult` mirror was removed in favor of the wire type.

// ── Media ────────────────────────────────────────────────────────

// YOU-05-004: the hand-rolled `IceConfigOutcome` / `IceServer` /
// `IceConfigRequestBody` mirrors drifted from the SDK wire types (missing
// `expires_at` / `force_turn`, `ttl_seconds: u64` vs the authoritative
// `u32`) and bypassed the TURN credential privacy guard. Re-export the
// SDK's authoritative types instead. When the WebRTC surface is wired up,
// each `ice_servers` entry MUST be parsed through `cokret_sdk::IceServer`
// and pass `IceServer::validate_credential_privacy()` (rejects TURN
// usernames embedding cross-Realm stable DIDs, B-14).
pub use cokret_sdk::models::{MediaIceConfigOutcome, MediaIceConfigRequestBody};

// WebRTC call signaling/recording no longer round-trips through bespoke
// `/_cokret/self/webrtc/*` outcomes: signaling is a `ck.call.signal`
// ephemeral envelope (EphemeralSubmitResult) and recording is a durable
// `ck.call.recording.start` event (SubmitEventResult). See
// `crypto-media/webrtc-signaling.md` §5/§7. The former
// CreateWebrtcSessionOutcome / WebrtcSignalOutcome / CallRecordingStartOutcome
// mirrors were removed (YOU-01-002).

// ─────────────────────────────────────────────────────────────────────
// CKP-0008 / CKP-0009 — Personal Agent HTTP wire types.
//
// YOU-01-005: the former hand-rolled `Agent*ReqBody` / `Agent*ResBody`
// mirrors drifted from `agent-operations.schema.json` (extra required
// fields, non-spec `todos`, wrong outcome shapes) and were removed. The
// agent surface now uses the SDK's authoritative types
// (`cokret_sdk::AgentProvisionOutcome` / `AgentList` / `AgentView` /
// `AgentRotateKeyOutcome` / `AgentGrantAttachOutcome` /
// `AgentSidecarThreadEnsureOutcome` / ...) directly in `views::agents`
// (via `with_authed_sdk_client`).
