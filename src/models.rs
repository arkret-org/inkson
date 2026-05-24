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
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContactsResponse {
    pub contacts: Vec<ContactResponse>,
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
    pub space_preview: SpacePreview,
    #[serde(default)]
    pub stripped_state: Vec<Value>,
    pub join_rule: String,
    #[serde(default)]
    pub via_services: Vec<String>,
}

/// Sidebar tag distinguishing a security-boundary Realm from a
/// product-organisation Space. Wire signal is either the
/// `cx.schema.{realm,space}.v1` `schema` field on the projection
/// body, or a yougen-local `__kind` tag used by the optimistic
/// post-create save.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpacePreviewKind {
    /// `cx:realm:*` — security / sync / E2EE boundary.
    Realm,
    /// `cx:space:*` — navigation container inside a Realm.
    Space,
}

impl Default for SpacePreviewKind {
    fn default() -> Self {
        // Legacy projections (no schema marker) were always Realms —
        // yougen had no UI to create real Spaces before
        // M-SPACE-CREATE-1. Default tag keeps them visible.
        Self::Realm
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    pub size: usize,
    pub media_type: String,
    pub sha256: String,
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

// ── Authentication ──────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenRefreshResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_at: String,
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
    pub did: String,
    pub handle: String,
    pub did_document: Option<Value>,
    /// Audience the directory bound the response claim to. Spec 0a5ab85:
    /// the client MUST reject claims whose audience doesn't match the
    /// invocation context (e.g. the Space the user is about to join).
    #[serde(default)]
    pub audience: Option<String>,
    /// Raw handle claim envelope when the directory issued one. Shape
    /// conforms to `handle-claim.schema.json` — typed deserialization is
    /// TODO(spec-sync 0a5ab85) once we depend on the SDK `HandleClaim`.
    #[serde(default)]
    pub handle_claim: Option<Value>,
}

/// Structured mention node embedded in message body. Spec 0a5ab85
/// `models/flow-and-message.md §9.4`. `display_snapshot` is the human
/// label captured at compose time; UI MUST surface a "handle reassigned"
/// badge when current resolution diverges from the snapshot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Mention {
    pub subject: String,
    pub handle_uri: String,
    pub display_snapshot: String,
    pub resolved_at: String,
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
    pub size: Option<usize>,
    pub proxy_url: Option<String>,
    #[serde(default)]
    pub receipt: Value,
}
