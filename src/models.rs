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
pub struct IndexQueryResponse {
    pub results: Vec<Value>,
    pub next_cursor: Option<String>,
    pub frontier: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IndexDescribeResponse {
    pub service_did: String,
    #[serde(default)]
    pub reducer_profiles: Vec<String>,
    #[serde(default)]
    pub schema_profiles: Vec<String>,
    #[serde(default)]
    pub query_features: Vec<String>,
    #[serde(default)]
    pub frontier: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RepoDescribeResponse {
    pub repo_did: String,
    pub head_commit: Option<String>,
    #[serde(default)]
    pub supported_signatures: Vec<String>,
    pub limits: Value,
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
pub struct ListCommitsResponse {
    #[serde(default)]
    pub commits: Vec<Value>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GetCommitResponse {
    pub commit: Value,
    #[serde(default)]
    pub operations: Vec<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GetOperationsResponse {
    #[serde(default)]
    pub operations: Vec<Value>,
    #[serde(default)]
    pub missing: Vec<String>,
    #[serde(default)]
    pub unauthorized: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RepoSyncResponse {
    #[serde(default)]
    pub operations: Vec<Value>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubmitCommitResponse {
    pub status: String,
    pub commit_id: String,
    pub head_commit: Option<String>,
    pub sync_token: String,
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
    pub upload_receipt: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModerationReportResponse {
    pub report_id: String,
    pub status: String,
    #[serde(default)]
    pub routed_to: Vec<String>,
}
