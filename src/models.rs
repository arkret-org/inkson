pub use contrix_sdk::{
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
pub struct AccountResponse {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub created_at: String,
}

/// A4b — response shape for `POST /api/v1/account/profile`. Mirrors
/// soland's `UpdateProfileResponse` wire shape so the settings UI can
/// reconcile its local cache with whatever the server actually stored
/// (the server normalises empty strings to `None`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdateProfileResponse {
    pub did: String,
    pub handle: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub bio: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
}

/// A6.1 — response shape for `POST /api/v1/index/search`. Mirrors
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
    pub scope: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContactsResponse {
    pub contacts: Vec<ContactResponse>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ConsentCellResponse {
    pub ok: bool,
    pub cell_id: String,
    pub holder_did: String,
    pub peer_did: String,
    pub scope: String,
    pub state: String,
    #[serde(default)]
    pub valid_until: Option<String>,
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpaceLifecycleResponse {
    pub ok: bool,
    pub space_id: String,
    pub owner: String,
    #[serde(default)]
    pub members: Vec<String>,
    pub deleted: bool,
}

// (Move/Anchor pipeline DTOs deleted; all writes now go through
// cx.events.submit via SubmitEventResponse.)

/// Outcome of [`crate::api::ContrixApi::set_account_data`]. Captures the
/// graceful-degradation contract: 404/501/405 are not treated as errors —
/// soland's `account_data` PUT is being rolled out incrementally and the
/// client must keep working when the endpoint isn't wired yet.
#[derive(Debug, Clone)]
pub enum AccountDataSetOutcome {
    /// Server accepted and stored the value. The caller may inspect the
    /// echoed body for any server-derived metadata, but most callers can
    /// ignore the `Value`.
    Stored { response: serde_json::Value },
    /// Server doesn't yet support `PUT /api/v1/account_data/{type}` — the
    /// client logged a `tracing::warn` and the local state remains the
    /// authoritative copy.
    Unsupported { status: reqwest::StatusCode },
}

pub const PROFILE_CORE_EVENT_STORE: &str = "cx.profile.core_event_store.v1";
pub const PROFILE_PRINCIPAL_SERVER_EVENTS_API: &str = "cx.profile.principal_server_events_api.v1";
pub const OP_EVENTS_DESCRIBE: &str = "cx.events.describe";
pub const OP_EVENTS_SUBMIT: &str = "cx.events.submit";

/// Yougen-side convenience methods over the SDK's [`ServerDescription`].
///
/// Yougen no longer maintains its own `ServerDescription` struct; the SDK
/// type is now the single source of truth, matching the spec at
/// `contrix-spec/spec/v1/artifacts/schemas/service-describe.schema.json`
/// (17 required v2 fields, typed `claimed_profiles` / `compat_surfaces`,
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IdentityDescribeResBody {
    pub service_did: String,
    pub registry_mode: String,
    #[serde(default)]
    pub supported_receipts: Vec<String>,
    pub protocol_version: String,
    #[serde(default)]
    pub profiles: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IdentityResolveResBody {
    pub did_document: Value,
    pub key_log_head: Option<String>,
    pub seq: u64,
    #[serde(default)]
    pub receipts: Vec<Value>,
    #[serde(default)]
    pub method_evidence: Value,
}

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
/// [`contrix_sdk::model::SyncResBody`] so client + server can never
/// drift on field names / per-realm body shape. Spec source of truth
/// at `contrix-spec/spec/v1/zh/sync/client-sync.md §2`. Yougen used to
/// own a custom `ClientSyncResponse` with a bucketed-`spaces`
/// deserializer; that was an older Matrix-style transcript that
/// disagreed with what soland actually emits.
pub use contrix_sdk::model::SyncResBody as ClientSyncResponse;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SearchSpacesResponse {
    pub results: Vec<SpacePreview>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DirectoryDescribeResBody {
    pub service_did: String,
    pub resource_types: Vec<String>,
    pub discovery_profiles: Vec<String>,
    pub restricted_query_proof: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolveRealmResponse {
    #[serde(alias = "realm_preview")]
    pub space_preview: SpacePreview,
    #[serde(default)]
    pub stripped_state: Vec<Value>,
    pub join_rule: String,
    #[serde(default)]
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

/// Sidebar tag distinguishing a security-boundary Realm from a
/// product-organisation Space. Wire signal is either the
/// `cx.schema.{realm,space}.v1` `schema` field on the projection
/// body, or a yougen-local `__kind` tag used by the optimistic
/// post-create save.
// Default tag is `Realm` because legacy projections (no schema marker) were
// always Realms — yougen had no UI to create real Spaces before
// M-SPACE-CREATE-1. Default tag keeps them visible.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpacePreviewKind {
    /// `cx:realm:*` — security / sync / E2EE boundary.
    #[default]
    Realm,
    /// `cx:space:*` — navigation container inside a Realm.
    Space,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SpacePreview {
    pub space_id: String,
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub tags: std::collections::BTreeSet<String>,
    pub public: bool,
    pub category: Option<String>,
    #[serde(default)]
    pub parent_space_id: Option<String>,
    #[serde(default)]
    pub child_space_ids: Vec<String>,
    /// Realm vs Space classification used by the sidebar to render
    /// the two as separate tiers. Spec realm-and-space.md §1 / §3.
    #[serde(default)]
    pub kind: SpacePreviewKind,
    /// Home Realm of this entry. Empty for Realms (they are their
    /// own home); set to the parent Realm id for Spaces.
    #[serde(default)]
    pub realm_id: String,
}

impl<'de> Deserialize<'de> for SpacePreview {
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
            name: String,
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
            kind: SpacePreviewKind,
        }

        let wire = Wire::deserialize(deserializer)?;
        let space_id = wire
            .space_id
            .or_else(|| wire.realm_id.clone())
            .ok_or_else(|| serde::de::Error::missing_field("space_id"))?;
        Ok(Self {
            space_id,
            name: wire.name,
            description: wire.description,
            tags: wire.tags,
            public: wire.public,
            category: wire.category,
            parent_space_id: wire.parent_space_id,
            child_space_ids: wire.child_space_ids,
            kind: wire.kind,
            realm_id: wire.realm_id.unwrap_or_default(),
        })
    }
}

impl SpacePreview {
    pub fn projection_realm_id(&self) -> &str {
        if self.kind == SpacePreviewKind::Space && !self.realm_id.trim().is_empty() {
            self.realm_id.trim()
        } else {
            self.space_id.as_str()
        }
    }
}

pub fn projection_realm_id_for_space(spaces: &[SpacePreview], space_id: &str) -> String {
    let requested = space_id.trim();
    projection_realm_id_for_known_space(spaces, requested).unwrap_or_else(|| requested.to_owned())
}

pub fn projection_realm_id_for_known_space(
    spaces: &[SpacePreview],
    space_id: &str,
) -> Option<String> {
    let requested = space_id.trim();
    if requested.is_empty() {
        return Some(String::new());
    }
    let by_id: std::collections::BTreeMap<&str, &SpacePreview> = spaces
        .iter()
        .map(|space| (space.space_id.as_str(), space))
        .collect();
    let mut current = requested;
    let mut visited = std::collections::BTreeSet::new();

    while visited.insert(current.to_owned()) {
        let space = by_id.get(current).copied()?;
        let projection_realm_id = space.projection_realm_id();
        if projection_realm_id != space.space_id || space.kind == SpacePreviewKind::Realm {
            return Some(projection_realm_id.to_owned());
        }
        if let Some(parent) = space
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
        SpacePreview, SpacePreviewKind, projection_realm_id_for_known_space,
        projection_realm_id_for_space,
    };

    fn preview(
        id: &str,
        kind: SpacePreviewKind,
        realm_id: &str,
        parent: Option<&str>,
    ) -> SpacePreview {
        SpacePreview {
            space_id: id.to_owned(),
            name: id.to_owned(),
            description: None,
            tags: Default::default(),
            public: true,
            category: None,
            parent_space_id: parent.map(ToOwned::to_owned),
            child_space_ids: Vec::new(),
            kind,
            realm_id: realm_id.to_owned(),
        }
    }

    #[test]
    fn projection_realm_id_uses_space_home_realm() {
        let spaces = vec![
            preview("cx:realm:root", SpacePreviewKind::Realm, "", None),
            preview(
                "cx:space:child",
                SpacePreviewKind::Space,
                "cx:realm:root",
                Some("cx:realm:root"),
            ),
        ];

        assert_eq!(
            projection_realm_id_for_space(&spaces, "cx:space:child"),
            "cx:realm:root"
        );
    }

    #[test]
    fn projection_realm_id_climbs_legacy_parent_links() {
        let spaces = vec![
            preview("cx:space:legacy-root", SpacePreviewKind::Realm, "", None),
            preview(
                "cx:space:legacy-child",
                SpacePreviewKind::Space,
                "",
                Some("cx:space:legacy-root"),
            ),
        ];

        assert_eq!(
            projection_realm_id_for_space(&spaces, "cx:space:legacy-child"),
            "cx:space:legacy-root"
        );
    }

    #[test]
    fn known_projection_realm_id_waits_for_unknown_routes() {
        assert_eq!(
            projection_realm_id_for_known_space(&[], "cx:space:child"),
            None
        );
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BackfillResBody {
    #[serde(default)]
    pub events: Vec<Value>,
    pub prev_cursor: Option<String>,
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub limited: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SnapshotHeadResponse {
    pub snapshot_ref: String,
    pub state_digest: String,
    #[serde(default)]
    pub frontier: Value,
    #[serde(default)]
    pub signature: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthzCheckResBody {
    pub allowed: bool,
    pub reason_code: Option<String>,
    #[serde(default)]
    pub grants: Vec<Value>,
    #[serde(default)]
    pub obligations: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EffectiveGrantsResBody {
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OkResBody {
    pub ok: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeysUploadResBody {
    pub one_time_key_counts: Value,
    pub fallback_keys: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeysQueryResBody {
    pub device_keys: Value,
    pub failures: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeysClaimResBody {
    pub one_time_keys: Value,
    pub failures: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceMessagesSendResBody {
    pub ok: bool,
    pub delivered: Value,
    pub unknown_devices: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceMessagesReceiveResBody {
    pub events: Vec<Value>,
    #[serde(default)]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub limited: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlobUploadResBody {
    pub blob_ref: String,
    /// Spec rename (head 37ce729 / SDK 4d5a1af): `size` → `size_bytes`
    /// on blob/media metadata. No serde alias by design — aggressive
    /// migration mode.
    pub size_bytes: usize,
    pub media_type: String,
    pub content_digest: String,
    #[serde(default)]
    pub thumbnail_ref: Option<String>,
    pub upload_receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModerationReportResBody {
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
    /// Audit-only snapshot of the canonical `<localpart>:<domain>` handle
    /// at compose time. Never the current display value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_at_time: Option<String>,
    /// Audit-only snapshot of the subject's display name at compose time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name_at_time: Option<String>,
    /// The original string the user typed (e.g. `@alice:acme.com`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mention_text_original: Option<String>,
    /// When the handle was resolved. Audit metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<String>,
}

/// Per-Space delivery binding surfaced to the member detail view.
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

// ── Space / Realm Management ────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpacePolicyResponse {
    pub ok: bool,
    pub space_id: String,
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
    pub group_id: String,
}

// ── Policy Check ─────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyCheckResBody {
    pub decision: String,
    #[serde(default)]
    pub obligations: Vec<Value>,
    #[serde(default)]
    pub reason: Option<String>,
    pub signed_decision: Option<Value>,
}

// ── Identity (extended) ──────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubmitDidOperationResBody {
    pub ok: bool,
    pub operation_id: String,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventsDescribeResBody {
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
/// `POST /api/v1/ephemeral` channel. The endpoint is fire-and-forget — the
/// server's only obligation is to return `accepted: true` (signal entered
/// the broadcast fanout) or surface a structured rejection. No event id is
/// minted because ephemeral signals are never durable.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EphemeralSubmitResponse {
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
    pub space_id: String,
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
    pub space_id: String,
    pub call_id: String,
    pub actor_id: String,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub context: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CreateWebrtcSessionResponse {
    pub session_id: String,
    pub space_id: String,
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
    pub space_id: String,
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
pub struct MimiProviderDirectoryResBody {
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
pub struct MimiKeyMaterialResBody {
    pub ok: bool,
    #[serde(default)]
    pub key_packages: Vec<Value>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiRoomUpdateResBody {
    pub ok: bool,
    pub room_id: Option<String>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiNotifyResBody {
    pub ok: bool,
    #[serde(default)]
    pub accepted: Vec<String>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiSubmitMessageResBody {
    pub ok: bool,
    pub mimi_message_id: Option<String>,
    pub mapped_operation_id: Option<String>,
    pub contrix_event_id: Option<String>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiGroupInfoResBody {
    pub room_id: String,
    pub mimi_room_uri: Option<String>,
    pub group_info: Value,
    #[serde(default)]
    pub participants: Vec<Value>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiConsentResBody {
    pub ok: bool,
    pub consent_id: Option<String>,
    pub state: Option<String>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiIdentifierQueryResBody {
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
pub struct MimiReportAbuseResBody {
    pub ok: bool,
    pub report_id: Option<String>,
    pub status: Option<String>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiProxyDownloadResBody {
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
// CXP-0008 / CXP-0009 — Personal Agent HTTP wire types (spec head
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
    pub agent_did: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub initial_grants: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentResBody {
    pub agent_principal_id: String,
    pub controller_did: String,
    pub agent_did: String,
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
    pub at: String,
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

/// CXP-0008 / CXP-0009 §6 + B-F: `cx.agent.sidecar_thread.ensure` MUST
/// default `home_policy = "context_realm_preferred"`. This is encoded
/// in the request body's optional `context_realm_id` plus the
/// `home_policy` discriminator.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentSidecarThreadEnsureReqBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_realm_id: Option<String>,
    /// Default value emitted by yougen: `"context_realm_preferred"`
    /// (B-F / CXP-0009 §3 sidecar home policy).
    #[serde(default)]
    pub home_policy: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentSidecarThreadEnsureResBody {
    pub ok: bool,
    pub agent_principal_id: String,
    pub sidecar_circle_id: String,
    pub realm_id: String,
    pub created: bool,
    #[serde(default)]
    pub todos: Vec<String>,
}
