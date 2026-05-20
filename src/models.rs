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

// Move/Anchor pipeline response shapes — mirror soland's
// `routing::move_anchor::SubmitMoveResponse` / `SubmitAnchorResponse` /
// `SignAnchorResponse`. The DTOs are kept here (not in `contrix-sdk`)
// because they're soland-server-specific surface shapes, not protocol
// primitives.

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
    #[serde(default)]
    pub rate_limit_policy: Value,
    #[serde(default)]
    pub plaintext_visibility: Value,
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

    pub fn missing_v1_principal_server_requirements(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.service_did.starts_with("did:") {
            missing.push("service_did");
        }
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

    pub fn is_v1_principal_server_ready(&self) -> bool {
        self.missing_v1_principal_server_requirements().is_empty()
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

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ClientSyncResponse {
    pub cursor: String,
    pub spaces: BTreeMap<String, Value>,
    /// Spaces the viewer no longer has access to since the last sync —
    /// left rooms, kicks, bans, server-side deletions. The client uses
    /// this to remove the space from `space_projections` and every
    /// per-space cache (drafts, anchor views, read markers, remarks…)
    /// so the sidebar reconciles with the server view on incremental syncs
    /// the same way a `since=None` full sync would.
    pub left_spaces: Vec<String>,
    pub to_device: Vec<Value>,
    pub account_data: Vec<Value>,
    pub device_lists: Value,
    pub notifications: Value,
    pub presence: Value,
}

impl<'de> Deserialize<'de> for ClientSyncResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let cursor = value
            .get("cursor")
            .and_then(Value::as_str)
            .ok_or_else(|| serde::de::Error::custom("sync response missing required cursor"))?
            .to_owned();

        let mut spaces = BTreeMap::new();
        let mut left_spaces = Vec::new();
        if let Some(spaces_value) = value.get("spaces") {
            flatten_sync_spaces(spaces_value, &mut spaces, &mut left_spaces)
                .map_err(serde::de::Error::custom)?;
        }
        left_spaces.sort();
        left_spaces.dedup();

        Ok(Self {
            cursor,
            spaces,
            left_spaces,
            to_device: sync_event_array(value.get("to_device"), "to_device")
                .map_err(serde::de::Error::custom)?,
            account_data: sync_event_array(value.get("account_data"), "account_data")
                .map_err(serde::de::Error::custom)?,
            device_lists: value
                .get("device_lists")
                .cloned()
                .unwrap_or_else(empty_json_object),
            notifications: value
                .get("notifications")
                .cloned()
                .unwrap_or_else(empty_json_object),
            presence: value
                .get("presence")
                .cloned()
                .unwrap_or_else(empty_json_object),
        })
    }
}

fn empty_json_object() -> Value {
    Value::Object(Default::default())
}

fn flatten_sync_spaces(
    value: &Value,
    spaces: &mut BTreeMap<String, Value>,
    left_spaces: &mut Vec<String>,
) -> Result<(), String> {
    let map = value
        .as_object()
        .ok_or_else(|| "sync spaces must be an object".to_owned())?;
    for bucket in map.keys() {
        if !matches!(bucket.as_str(), "join" | "invite" | "knock" | "leave") {
            return Err(format!("unexpected sync spaces bucket `{bucket}`"));
        }
    }

    for bucket in ["join", "invite", "knock"] {
        collect_space_bucket(map.get(bucket), spaces, bucket)?;
    }
    collect_leave_bucket(map.get("leave"), left_spaces)?;
    Ok(())
}

fn collect_space_bucket(
    value: Option<&Value>,
    spaces: &mut BTreeMap<String, Value>,
    bucket: &str,
) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    let map = value
        .as_object()
        .ok_or_else(|| format!("sync spaces.{bucket} must be an object"))?;
    for (space_id, body) in map {
        if !space_id.starts_with("cx:space:") {
            return Err(format!(
                "sync spaces.{bucket} key `{space_id}` is not a Space id"
            ));
        }
        spaces.insert(space_id.clone(), body.clone());
    }
    Ok(())
}

fn collect_leave_bucket(value: Option<&Value>, ids: &mut Vec<String>) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    let map = value
        .as_object()
        .ok_or_else(|| "sync spaces.leave must be an object".to_owned())?;
    for id in map.keys() {
        if !id.starts_with("cx:space:") {
            return Err(format!("sync spaces.leave key `{id}` is not a Space id"));
        }
        ids.push(id.clone());
    }
    Ok(())
}

fn sync_event_array(value: Option<&Value>, field: &str) -> Result<Vec<Value>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| format!("sync {field} must be an event container object"))?;
    match object.get("events") {
        Some(Value::Array(items)) => Ok(items.clone()),
        Some(_) => Err(format!("sync {field}.events must be an array")),
        None => Err(format!("sync {field} missing events array")),
    }
}

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
    #[serde(default)]
    pub parent_space_id: Option<String>,
    #[serde(default)]
    pub child_space_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BackfillResBody {
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
pub struct FederationTransactionResBody {
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
pub struct FederationSpaceMembersResBody {
    #[serde(default)]
    pub members: Vec<Value>,
    pub frontier: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FederationVerifyActorResBody {
    pub verified: bool,
    pub actor: String,
    pub evidence: Value,
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

// ── Applet ───────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletPingResBody {
    pub ok: bool,
    pub latency_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletDescribeResBody {
    pub applet_did: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub namespaces: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletTransactionResBody {
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
pub struct IdentityLogResBody {
    #[serde(default)]
    pub entries: Vec<Value>,
    pub next_cursor: Option<String>,
}

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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IdentityReceiptsResBody {
    #[serde(default)]
    pub receipts: Vec<Value>,
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
