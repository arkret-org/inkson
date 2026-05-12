use std::collections::BTreeMap;

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
pub struct AccountResponse {
    pub did: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub created_at: String,
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

// C10.D (2026-05-09 十六轮) Move/Anchor pipeline response shapes — mirror
// soland's `routing::move_anchor::SubmitMoveResponse` /
// `SubmitAnchorResponse` / `SignAnchorResponse`. The DTOs are kept here
// (not in `contrix-sdk`) because they're soland-server-specific surface
// shapes, not protocol primitives.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubmitMoveResponse {
    pub move_id: String,
    /// `pending` (queued for next anchor batch) or `rejected`.
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RejectedMoveEntry {
    pub move_id: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubmitAnchorResponse {
    pub anchor_id: String,
    #[serde(default)]
    pub accepted_move_ids: Vec<String>,
    #[serde(default)]
    pub rejected_moves: Vec<RejectedMoveEntry>,
    pub post_state_root: String,
}

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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignAnchorResponse {
    /// `true` if an Anchor was published; `false` if no pending Moves.
    pub published: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_id: Option<String>,
    #[serde(default)]
    pub accepted_move_ids: Vec<String>,
    #[serde(default)]
    pub rejected_moves: Vec<RejectedMoveEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_state_root: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServerDescription {
    pub service_did: String,
    pub service_type: String,
    pub protocol_version: String,
    #[serde(default)]
    pub supported_profiles: Vec<String>,
    #[serde(default)]
    pub supported_features: Vec<String>,
    #[serde(default)]
    pub supported_operations: Vec<String>,
    #[serde(default)]
    pub supported_bindings: Vec<Value>,
    #[serde(default)]
    pub supported_reducer_profiles: Vec<String>,
    #[serde(default)]
    pub supported_schema_profiles: Vec<String>,
    #[serde(default)]
    pub auth_metadata: Value,
    #[serde(default)]
    pub limits: Value,
}

pub const PROFILE_CORE_EVENT_STORE: &str = "cx.profile.core_event_store.v1";
pub const PROFILE_PRINCIPAL_SERVER_EVENTS_API: &str = "cx.profile.principal_server_events_api.v1";
pub const OP_EVENTS_DESCRIBE: &str = "cx.events.describe";
pub const OP_EVENTS_SUBMIT: &str = "cx.events.submit";

impl ServerDescription {
    pub fn supports_profile(&self, profile: &str) -> bool {
        self.supported_profiles.iter().any(|value| value == profile)
    }

    pub fn supports_operation(&self, operation_id: &str) -> bool {
        self.supported_operations
            .iter()
            .any(|value| value == operation_id)
    }

    pub fn supports_feature(&self, feature: &str) -> bool {
        self.supported_features.iter().any(|value| value == feature)
    }

    pub fn supports_event_envelope_write_plane(&self) -> bool {
        self.missing_event_envelope_write_requirements().is_empty()
    }

    pub fn missing_event_envelope_write_requirements(&self) -> Vec<&'static str> {
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
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IdentityDescribeResponse {
    pub service_did: String,
    pub registry_mode: String,
    #[serde(default)]
    pub supported_receipts: Vec<String>,
    pub protocol_version: String,
    #[serde(default)]
    pub profiles: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IdentityResolveResponse {
    pub did_document: Value,
    pub key_log_head: Option<String>,
    pub seq: u64,
    #[serde(default)]
    pub receipts: Vec<Value>,
    #[serde(default)]
    pub method_evidence: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SyncDescribeResponse {
    pub service_did: String,
    #[serde(default)]
    pub supported_sync_profiles: Vec<String>,
    #[serde(default)]
    pub limits: Value,
    #[serde(default)]
    pub frontier: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClientSyncResponse {
    pub next_batch: String,
    #[serde(default)]
    pub spaces: BTreeMap<String, Value>,
    #[serde(default)]
    pub to_device: Vec<Value>,
    #[serde(default)]
    pub account_data: Vec<Value>,
    #[serde(default)]
    pub device_lists: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SearchSpacesResponse {
    pub results: Vec<SpacePreview>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DirectoryDescribeResponse {
    pub service_did: String,
    pub resource_types: Vec<String>,
    pub discovery_profiles: Vec<String>,
    pub restricted_query_proof: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolveSpaceResponse {
    pub space_preview: SpacePreview,
    #[serde(default)]
    pub stripped_state: Vec<Value>,
    pub join_rule: String,
    #[serde(default)]
    pub via_services: Vec<String>,
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
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BackfillResponse {
    #[serde(default)]
    pub events: Vec<Value>,
    pub prev_cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub limited: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SnapshotHeadResponse {
    pub snapshot_ref: String,
    pub state_hash: String,
    #[serde(default)]
    pub frontier: Value,
    #[serde(default)]
    pub signature: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthzCheckResponse {
    pub allowed: bool,
    pub reason_code: Option<String>,
    #[serde(default)]
    pub grants: Vec<Value>,
    #[serde(default)]
    pub obligations: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EffectiveGrantsResponse {
    #[serde(default)]
    pub grants: Vec<Value>,
    pub state_hash: Option<String>,
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
pub struct OkResponse {
    pub ok: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeysUploadResponse {
    pub one_time_key_counts: Value,
    pub fallback_keys: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeysQueryResponse {
    pub device_keys: Value,
    pub failures: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeysClaimResponse {
    pub one_time_keys: Value,
    pub failures: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceMessagesSendResponse {
    pub ok: bool,
    pub delivered: Value,
    pub unknown_devices: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceMessagesReceiveResponse {
    #[serde(default)]
    pub events: Vec<Value>,
    pub next_batch: Option<String>,
    pub limited: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlobUploadResponse {
    pub blob_ref: String,
    pub size: usize,
    pub media_type: String,
    pub sha256: String,
    #[serde(default)]
    pub thumbnail_ref: Option<String>,
    pub upload_receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModerationReportResponse {
    pub report_id: String,
    pub status: String,
    #[serde(default)]
    pub routed_to: Vec<String>,
}

// ── Authentication ──────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PasskeyChallengeResponse {
    pub challenge: String,
    pub rp_id: String,
    pub user_did: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PasskeyVerifyResponse {
    pub access_token: String,
    pub token_type: String,
    pub actor: String,
    pub device_id: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OidcAuthorizeResponse {
    pub redirect_url: String,
    pub state: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OidcCallbackResponse {
    pub access_token: String,
    pub token_type: String,
    pub actor: String,
    pub device_id: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenRefreshResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccountRecoveryResponse {
    pub ok: bool,
    pub recovery_method: String,
    pub challenge: Option<String>,
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
}

// ── Space Management ────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdateSpaceResponse {
    pub ok: bool,
    pub space_id: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ArchiveSpaceResponse {
    pub ok: bool,
    pub space_id: String,
    pub archived: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpacePolicyResponse {
    pub ok: bool,
    pub space_id: String,
    pub join_rule: String,
    pub history_visibility: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpaceInviteResponse {
    pub ok: bool,
    pub invite_id: String,
    pub space_id: String,
    pub target: String,
    pub state: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpaceLeaveResponse {
    pub ok: bool,
    pub space_id: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BanMemberResponse {
    pub ok: bool,
    pub space_id: String,
    pub member: String,
    pub banned: bool,
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
pub struct RotateKeysResponse {
    pub one_time_key_counts: Value,
    pub fallback_keys: Value,
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
pub struct MlsEpochResponse {
    pub epoch: u64,
    pub group_id: String,
    pub member_count: usize,
    pub last_rotation: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MlsRotateResponse {
    pub ok: bool,
    pub epoch: u64,
    pub group_id: String,
}

// ── Moderation & Policy ─────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModerationReportsResponse {
    pub reports: Vec<Value>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModerationResolveResponse {
    pub ok: bool,
    pub report_id: String,
    pub resolution: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub resource: String,
    pub policy: Value,
}

// ── Federation ───────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationTransactionResponse {
    pub ok: bool,
    pub txn_id: String,
    #[serde(default)]
    pub accepted: Vec<String>,
    #[serde(default)]
    pub rejected: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationOperationsResponse {
    #[serde(default)]
    pub operations: Vec<Value>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationSpaceMembersResponse {
    #[serde(default)]
    pub members: Vec<Value>,
    pub frontier: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationVerifyActorResponse {
    pub verified: bool,
    pub actor: String,
    pub evidence: Value,
}

// ── Policy Check ─────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyCheckResponse {
    pub decision: String,
    #[serde(default)]
    pub obligations: Vec<Value>,
    #[serde(default)]
    pub reason: Option<String>,
    pub signed_decision: Option<Value>,
}

// ── Applet ───────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletPingResponse {
    pub ok: bool,
    pub latency_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletDescribeResponse {
    pub applet_did: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub namespaces: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletTransactionResponse {
    pub ok: bool,
    pub txn_id: String,
    #[serde(default)]
    pub results: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletQueryActorResponse {
    pub actor: Value,
    #[serde(default)]
    pub spaces: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletQuerySpaceResponse {
    pub space: Value,
    #[serde(default)]
    pub members: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletProtocolMetadataResponse {
    pub protocol_version: String,
    #[serde(default)]
    pub supported_operations: Vec<String>,
    #[serde(default)]
    pub supported_schemas: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThirdPartyUsersResponse {
    #[serde(default)]
    pub users: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThirdPartyLocationsResponse {
    #[serde(default)]
    pub locations: Vec<Value>,
}

// ── Identity (extended) ──────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IdentityLogResponse {
    #[serde(default)]
    pub entries: Vec<Value>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubmitDidOperationResponse {
    pub ok: bool,
    pub operation_id: String,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventsDescribeResponse {
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IdentityReceiptsResponse {
    #[serde(default)]
    pub receipts: Vec<Value>,
}

// ── Media ────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IceConfigResponse {
    #[serde(default)]
    pub ice_servers: Vec<IceServer>,
    pub ttl_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IceServer {
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub credential: Option<String>,
}

// ── MIMI Provider Facade ─────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiProviderDirectoryResponse {
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
pub struct MimiKeyMaterialResponse {
    pub ok: bool,
    #[serde(default)]
    pub key_packages: Vec<Value>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiRoomUpdateResponse {
    pub ok: bool,
    pub room_id: Option<String>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiNotifyResponse {
    pub ok: bool,
    #[serde(default)]
    pub accepted: Vec<String>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiSubmitMessageResponse {
    pub ok: bool,
    pub mimi_message_id: Option<String>,
    pub mapped_operation_id: Option<String>,
    pub contrix_event_id: Option<String>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiGroupInfoResponse {
    pub room_id: String,
    pub mimi_room_uri: Option<String>,
    pub group_info: Value,
    #[serde(default)]
    pub participants: Vec<Value>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiConsentResponse {
    pub ok: bool,
    pub consent_id: Option<String>,
    pub state: Option<String>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiIdentifierQueryResponse {
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
pub struct MimiReportAbuseResponse {
    pub ok: bool,
    pub report_id: Option<String>,
    pub status: Option<String>,
    #[serde(default)]
    pub receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MimiProxyDownloadResponse {
    pub ok: bool,
    pub blob_ref: String,
    pub media_type: Option<String>,
    pub size: Option<usize>,
    pub proxy_url: Option<String>,
    #[serde(default)]
    pub receipt: Value,
}
