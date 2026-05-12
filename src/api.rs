use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use chime::{ContrixPushClient, RegisterDeviceRequest, UnregisterDeviceRequest};
use contrix_sdk::ErrorEnvelope;
use reqwest::{
    Client, Method, StatusCode,
    header::{HeaderMap, RETRY_AFTER},
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use url::Url;

/// A token that can be used to cancel in-flight API requests.
#[derive(Clone, Debug)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PrincipalAuthBridgeDescribeResponse {
    pub contract: String,
    pub version: String,
    pub api_base_path: String,
    pub auth: PrincipalAuthBridgeAuthDescriptor,
    pub push: PrincipalAuthBridgePushDescriptor,
    pub examples: PrincipalAuthBridgeExamples,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PrincipalAuthBridgeAuthDescriptor {
    pub dev_login_path: String,
    pub session_grant_exchange_path: String,
    pub bearer_auth_scheme: String,
    pub principal_did_body_field: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PrincipalAuthBridgePushDescriptor {
    pub register_device_path: String,
    pub unregister_device_path: String,
    pub session_grant_header: String,
    pub principal_did_body_field: String,
    pub register_device_mode: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PrincipalAuthBridgeExamples {
    #[serde(default)]
    pub session_grant_exchange_request: Value,
    #[serde(default)]
    pub register_device_request: Value,
    #[serde(default)]
    pub unregister_device_request: Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionGrantIntrospectionProof {
    pub challenge: String,
    pub proof_jwt: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PrincipalIntegrationManifestResponse {
    pub contract: String,
    pub version: String,
    pub service: String,
    pub service_kind: String,
    pub api_base_path: String,
    pub describe_path: String,
    #[serde(default)]
    pub dependencies: Vec<PrincipalIntegrationDependency>,
    #[serde(default)]
    pub surfaces: Vec<PrincipalIntegrationSurface>,
    #[serde(default)]
    pub examples: Value,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PrincipalIntegrationDependency {
    pub service: String,
    pub purpose: String,
    pub required_contract: String,
    pub discovery_path: String,
    pub mode: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PrincipalIntegrationSurface {
    pub name: String,
    pub method: String,
    pub path: String,
    pub contract: String,
    pub stability: String,
    pub todo: String,
}

pub fn summarize_principal_integration_manifest(
    manifest: &PrincipalIntegrationManifestResponse,
) -> String {
    let dependencies = if manifest.dependencies.is_empty() {
        "none".to_owned()
    } else {
        manifest
            .dependencies
            .iter()
            .map(|dependency| {
                format!(
                    "{}:{}@{}",
                    dependency.service, dependency.purpose, dependency.discovery_path
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    let surfaces = if manifest.surfaces.is_empty() {
        "none".to_owned()
    } else {
        manifest
            .surfaces
            .iter()
            .map(|surface| {
                format!(
                    "{} {} {} [{}]",
                    surface.method, surface.path, surface.contract, surface.stability
                )
            })
            .collect::<Vec<_>>()
            .join(" | ")
    };
    format!(
        "contract={} version={} service={} kind={} dependencies={} surfaces={} todos={}",
        manifest.contract,
        manifest.version,
        manifest.service,
        manifest.service_kind,
        dependencies,
        surfaces,
        if manifest.todos.is_empty() {
            "none".to_owned()
        } else {
            manifest.todos.join(" | ")
        },
    )
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Cancel all requests using this token.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Check if cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

use crate::config::validate_server_url;
use crate::models::{
    AccountDataSetOutcome, AccountRecoveryResponse, AccountResponse, AppletDescribeResponse,
    AppletPingResponse, AppletProtocolMetadataResponse, AppletQueryActorResponse,
    AppletQuerySpaceResponse, AppletTransactionResponse, ArchiveSpaceResponse, AuthzCheckResponse,
    BackfillResponse, BanMemberResponse, BlobUploadResponse, ClientSyncResponse, ContactResponse,
    ContactsResponse, DevLoginResponse, DeviceMessagesReceiveResponse, DeviceMessagesSendResponse,
    DeviceTrustResponse, DirectoryDescribeResponse, EffectiveGrantsResponse,
    EventsDescribeResponse, FederationOperationsResponse, FederationSpaceMembersResponse,
    FederationTransactionResponse, FederationVerifyActorResponse, HealthResponse,
    IceConfigResponse, IdentityDescribeResponse, IdentityLogResponse, IdentityReceiptsResponse,
    IdentityResolveResponse, InvitesResponse, KeysClaimResponse, KeysQueryResponse,
    KeysUploadResponse, MimiConsentResponse, MimiGroupInfoResponse, MimiIdentifierQueryResponse,
    MimiKeyMaterialResponse, MimiNotifyResponse, MimiProviderDirectoryResponse,
    MimiProxyDownloadResponse, MimiReportAbuseResponse, MimiRoomUpdateResponse,
    MimiSubmitMessageResponse, MlsEpochResponse, MlsRotateResponse, ModerationReportResponse,
    ModerationReportsResponse, ModerationResolveResponse, OidcAuthorizeResponse,
    OidcCallbackResponse, OkResponse, PasskeyChallengeResponse, PasskeyVerifyResponse,
    PolicyCheckResponse, PolicyResponse, PushRegisterResponse, ReceiptResponse,
    ResolveHandleResponse, ResolveSpaceResponse, RotateKeysResponse, SearchActorsResponse,
    SearchOrganizationsResponse, SearchSpacesResponse, ServerDescription, SignAnchorResponse,
    SnapshotHeadResponse, SpaceInviteResponse, SpaceLeaveResponse, SpaceLifecycleResponse,
    SpacePolicyResponse, SubmitAnchorResponse, SubmitDidOperationResponse, SubmitEventResponse,
    SubmitMoveResponse, SyncDescribeResponse, ThirdPartyLocationsResponse, ThirdPartyUsersResponse,
    TokenRefreshResponse, TypingResponse, UpdateSpaceResponse, VerifyDeviceResponse,
};
use crate::operation::{OperationEnvelope, uuid_v7, uuid_v8};

#[derive(Clone, Debug)]
pub struct ContrixApi {
    base_url: Url,
    pub(crate) http: Client,
    access_token: Option<String>,
    wait_for_sync_token: Option<String>,
    retry: RetryPolicy,
    refresh_token: Option<String>,
    network_state: Arc<RwLock<NetworkState>>,
    cancel_token: Option<CancellationToken>,
}

/// Network connectivity state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkState {
    Online,
    Offline,
    Reconnecting,
}

/// Result of an automatic token refresh attempt.
#[derive(Clone, Debug)]
pub struct TokenRefreshResult {
    pub new_access_token: String,
    pub new_refresh_token: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContrixApiOptions {
    pub timeout: Duration,
    pub retry: RetryPolicy,
}

impl Default for ContrixApiOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            retry: RetryPolicy::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_retries: usize,
    pub initial_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 2,
            initial_backoff: Duration::from_millis(100),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ContrixApiError {
    pub status: StatusCode,
    pub error: ErrorEnvelope,
}

impl fmt::Display for ContrixApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Contrix API returned {}: {}", self.status, self.error)
    }
}

impl std::error::Error for ContrixApiError {}

/// Round 28: typed error class for the `post_audit_user_action`
/// path. Distinguishes "endpoint isn't wired yet" (404 — caller
/// should re-buffer the entry) from "server said no" (every other
/// error — drop and move on). Pulled out so callers can branch
/// without parsing `anyhow::Error` strings.
#[derive(Debug)]
pub enum AuditPostError {
    /// Server responded 404 — the audit ingest endpoint is not yet
    /// wired. Callers re-buffer the entry for a later flush attempt.
    NotWired,
    /// Any other failure (network drop, 5xx, 4xx). Caller drops the
    /// entry — telemetry is best-effort.
    Other(String),
}

impl fmt::Display for AuditPostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditPostError::NotWired => f.write_str("audit endpoint not wired (404)"),
            AuditPostError::Other(msg) => write!(f, "audit post failed: {msg}"),
        }
    }
}

impl std::error::Error for AuditPostError {}

#[derive(Debug, Deserialize)]
struct ApiErrorBody {
    error: ErrorEnvelope,
}

impl ContrixApi {
    pub fn new(base_url: &str) -> anyhow::Result<Self> {
        Self::new_with_options(base_url, ContrixApiOptions::default())
    }

    pub fn new_with_options(base_url: &str, options: ContrixApiOptions) -> anyhow::Result<Self> {
        let base_url = validate_server_url(base_url)?;
        let http = Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let http = http.timeout(options.timeout);

        Ok(Self {
            base_url,
            http: http.build()?,
            access_token: None,
            wait_for_sync_token: None,
            retry: options.retry,
            refresh_token: None,
            network_state: Arc::new(RwLock::new(NetworkState::Online)),
            cancel_token: None,
        })
    }

    pub fn with_bearer(mut self, access_token: impl Into<String>) -> Self {
        self.access_token = Some(access_token.into());
        self
    }

    pub fn with_wait_for(mut self, sync_token: impl Into<String>) -> Self {
        let sync_token = sync_token.into();
        self.wait_for_sync_token = if sync_token.trim().is_empty() || sync_token == "-" {
            None
        } else {
            Some(sync_token)
        };
        self
    }

    /// Set the refresh token for automatic token refresh.
    pub fn with_refresh_token(mut self, refresh_token: impl Into<String>) -> Self {
        self.refresh_token = Some(refresh_token.into());
        self
    }

    /// Set a cancellation token for this API client.
    /// When the token is cancelled, in-flight requests will be aborted.
    pub fn with_cancel(mut self, token: CancellationToken) -> Self {
        self.cancel_token = Some(token);
        self
    }

    /// Get the current network state.
    pub async fn network_state(&self) -> NetworkState {
        self.network_state.read().await.clone()
    }

    /// Set the network state.
    pub async fn set_network_state(&self, state: NetworkState) {
        *self.network_state.write().await = state;
    }

    /// Update the access token (e.g., after a refresh).
    pub fn set_access_token(&mut self, token: impl Into<String>) {
        self.access_token = Some(token.into());
    }

    /// Get the current access token.
    pub fn access_token(&self) -> Option<&str> {
        self.access_token.as_deref()
    }

    /// Attempt to refresh the access token using the stored refresh token.
    /// Returns the new tokens if successful.
    pub async fn try_refresh_token(&self) -> anyhow::Result<TokenRefreshResult> {
        let rt = self
            .refresh_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no refresh token available"))?;
        let response = self
            .http
            .post(self.endpoint("api/v1/auth/token/refresh")?)
            .json(&json!({"refresh_token": rt}))
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            let bytes = response.bytes().await?;
            return Err(ContrixApiError {
                status,
                error: decode_contrix_error(status, &bytes),
            }
            .into());
        }
        let response: TokenRefreshResponse = response.json().await?;
        Ok(TokenRefreshResult {
            new_access_token: response.access_token,
            new_refresh_token: None, // Server may return a new refresh token
            expires_at: Some(response.expires_at),
        })
    }

    /// Check server health and update network state.
    pub async fn check_connectivity(&self) -> bool {
        match self.health().await {
            Ok(resp) => {
                self.set_network_state(NetworkState::Online).await;
                resp.ok
            }
            Err(_) => {
                self.set_network_state(NetworkState::Offline).await;
                false
            }
        }
    }

    pub fn endpoint(&self, path: &str) -> anyhow::Result<Url> {
        Ok(self.base_url.join(path.trim_start_matches('/'))?)
    }

    pub async fn health(&self) -> anyhow::Result<HealthResponse> {
        self.get_json("health").await
    }

    pub async fn describe(&self) -> anyhow::Result<ServerDescription> {
        self.get_json("api/v1/server/describe").await
    }

    pub async fn auth_bridge_describe(
        &self,
    ) -> anyhow::Result<PrincipalAuthBridgeDescribeResponse> {
        self.get_json("api/v1/auth/bridge/describe").await
    }

    pub async fn integration_describe(
        &self,
    ) -> anyhow::Result<PrincipalIntegrationManifestResponse> {
        self.get_json("api/v1/integration/describe").await
    }

    pub async fn authz_describe(&self) -> anyhow::Result<serde_json::Value> {
        self.get_json("api/v1/authz/describe").await
    }

    pub async fn policies_describe(&self) -> anyhow::Result<serde_json::Value> {
        self.get_json("api/v1/policies/describe").await
    }

    pub async fn device_messages_describe(&self) -> anyhow::Result<serde_json::Value> {
        self.get_json("api/v1/device_messages/describe").await
    }

    pub async fn key_backups_describe(&self) -> anyhow::Result<serde_json::Value> {
        self.get_json("api/v1/keys/backups/describe").await
    }

    pub async fn dev_login(
        &self,
        actor: &str,
        device_id: &str,
    ) -> anyhow::Result<DevLoginResponse> {
        self.post_json(
            "api/v1/auth/dev-login",
            json!({"actor": actor, "device_id": device_id, "display_name": "yougen"}),
        )
        .await
    }

    pub async fn exchange_session_grant_at(
        &self,
        path: &str,
        grant_jwt: &str,
        principal_did: &str,
        device_id: &str,
    ) -> anyhow::Result<DevLoginResponse> {
        self.exchange_session_grant_at_with_proof(path, grant_jwt, principal_did, device_id, None)
            .await
    }

    pub async fn exchange_session_grant_at_with_proof(
        &self,
        path: &str,
        grant_jwt: &str,
        principal_did: &str,
        device_id: &str,
        introspection_proof: Option<&SessionGrantIntrospectionProof>,
    ) -> anyhow::Result<DevLoginResponse> {
        let mut body = json!({
            "grant_jwt": grant_jwt,
            "principal_did": principal_did,
            "device_id": device_id,
            "display_name": "yougen session-grant bridge",
        });
        if let Some(introspection_proof) = introspection_proof {
            body["introspection_proof"] = serde_json::to_value(introspection_proof)?;
        }
        self.post_json(path, body).await
    }

    pub async fn exchange_session_grant(
        &self,
        grant_jwt: &str,
        principal_did: &str,
        device_id: &str,
    ) -> anyhow::Result<DevLoginResponse> {
        self.exchange_session_grant_at(
            "api/v1/auth/session-grant/exchange",
            grant_jwt,
            principal_did,
            device_id,
        )
        .await
    }

    pub async fn register_account(
        &self,
        did: &str,
        handle: &str,
        display_name: Option<&str>,
        device_id: Option<&str>,
    ) -> anyhow::Result<AccountResponse> {
        self.post_json(
            "api/v1/account/register",
            json!({
                "did": did,
                "handle": handle,
                "display_name": display_name,
                "device_id": device_id
            }),
        )
        .await
    }

    pub async fn account_me(&self) -> anyhow::Result<AccountResponse> {
        self.get_json("api/v1/account/me").await
    }

    pub async fn request_contact(&self, target: &str) -> anyhow::Result<ContactResponse> {
        self.post_json("api/v1/contacts/request", json!({"target": target}))
            .await
    }

    pub async fn respond_contact(
        &self,
        requester: &str,
        action: &str,
    ) -> anyhow::Result<ContactResponse> {
        self.post_json(
            "api/v1/contacts/respond",
            json!({"requester": requester, "action": action}),
        )
        .await
    }

    pub async fn contacts(&self) -> anyhow::Result<ContactsResponse> {
        self.get_json("api/v1/contacts").await
    }

    pub async fn logout(&self) -> anyhow::Result<OkResponse> {
        self.post_json("api/v1/auth/logout", json!({})).await
    }

    pub async fn create_space(
        &self,
        title: &str,
        summary: Option<&str>,
        public: bool,
        invitees: Vec<String>,
    ) -> anyhow::Result<SpaceLifecycleResponse> {
        self.post_json(
            "api/v1/spaces",
            json!({
                "title": title,
                "summary": summary,
                "public": public,
                "invitees": invitees
            }),
        )
        .await
    }

    pub async fn add_space_member(
        &self,
        space_id: &str,
        member: &str,
    ) -> anyhow::Result<SpaceLifecycleResponse> {
        self.post_json(
            &format!("api/v1/spaces/{space_id}/members"),
            json!({"member": member}),
        )
        .await
    }

    pub async fn remove_space_member(
        &self,
        space_id: &str,
        member: &str,
    ) -> anyhow::Result<SpaceLifecycleResponse> {
        self.delete_json(&format!("api/v1/spaces/{space_id}/members/{member}"))
            .await
    }

    pub async fn delete_space(&self, space_id: &str) -> anyhow::Result<SpaceLifecycleResponse> {
        self.delete_json(&format!("api/v1/spaces/{space_id}")).await
    }

    // C10.D (2026-05-09 十六轮) Move/Anchor pipeline — the protocol-canonical
    // write path for cell-driven state changes (consent, capability, member
    // state, anchorer cell, MLS epoch, etc.). Non-cell writes use
    // `POST /api/v1/events` instead.

    /// Submit a signed [`contrix_sdk::Move`] for the next anchorer batch.
    /// Returns the server's verdict (`pending` if accepted into MoveStore,
    /// `rejected` with reason if structural / signature / replay check
    /// failed). The Move's `id` is content-addressed (`sha256(canonical_bytes)`),
    /// so re-submitting the same Move is idempotent at the server.
    pub async fn submit_move(
        &self,
        move_obj: &contrix_sdk::Move,
    ) -> anyhow::Result<SubmitMoveResponse> {
        let body = serde_json::to_value(move_obj)?;
        self.post_json("api/v1/moves", body).await
    }

    /// Submit a signed [`contrix_sdk::Anchor`]. Most clients should NOT
    /// call this — the server's anchorer signs Anchors locally. Use this
    /// only when implementing a separate anchorer node or replaying
    /// federation-received Anchors.
    pub async fn submit_anchor(
        &self,
        anchor: &contrix_sdk::Anchor,
    ) -> anyhow::Result<SubmitAnchorResponse> {
        let body = serde_json::to_value(anchor)?;
        self.post_json("api/v1/anchors", body).await
    }

    /// Read the current anchorer cell value for a Space (admin-only).
    /// Returns the raw JSON shape the server publishes — typically
    /// `{ "mode": "single_did" | "threshold" | "open_set" | "mixed",
    ///    "principals": [...], ... }`. The endpoint is being implemented
    /// in soland on a separate track (P0 M4); when it 404s the caller's
    /// `Result::Err` arm should surface a clear "endpoint unavailable"
    /// message rather than blocking the page.
    pub async fn admin_anchorer_describe(
        &self,
        space_id: &str,
    ) -> anyhow::Result<serde_json::Value> {
        self.get_json(&format!("api/admin/v1/spaces/{space_id}/anchorer"))
            .await
    }

    /// Trigger one anchorer signing pass for `space_id`. Admin-only.
    /// Useful for tests + ops; production deploys typically rely on the
    /// server-side periodic ticker (when wired) instead.
    pub async fn admin_anchors_sign(
        &self,
        space_id: &str,
        max_moves: Option<usize>,
    ) -> anyhow::Result<SignAnchorResponse> {
        let mut body = json!({ "space_id": space_id });
        if let Some(max) = max_moves {
            body["max_moves"] = json!(max);
        }
        self.post_json("api/v1/admin/anchors/sign", body).await
    }

    /// PUT a per-account `cx.account_data.set` entry. Round 21: thin wrapper
    /// around `PUT /api/v1/account_data/{type}` so settings UIs can push
    /// preferences (e.g. `cx.read_receipt.preferences`) up to soland for
    /// cross-device sync. The endpoint is being implemented in soland on a
    /// separate track — when it returns 404 / 501 / 405 we treat the
    /// outcome as `Unsupported` and let the caller swallow it (local state
    /// stays authoritative). Anything else surfaces as `Err`.
    ///
    /// Structural: the body is `{ "content": <value> }` — soland's existing
    /// `cx.account_data.set` pipeline treats the path's `{type}` segment as
    /// the canonical account-data key.
    pub async fn set_account_data(
        &self,
        type_key: &str,
        content: Value,
    ) -> anyhow::Result<AccountDataSetOutcome> {
        let body = json!({ "content": content });
        let result: anyhow::Result<Value> = self
            .put_json(&format!("api/v1/account_data/{type_key}"), body)
            .await;
        match result {
            Ok(value) => Ok(AccountDataSetOutcome::Stored { response: value }),
            Err(error) => {
                // Detect the "endpoint not yet implemented" shape. We accept
                // 404 (route absent), 501 (NotImplemented), and 405 (route
                // exists for another method but PUT not wired) as graceful
                // degradation — anything else propagates.
                if let Some(api_error) = error.downcast_ref::<ContrixApiError>() {
                    let status = api_error.status;
                    if matches!(
                        status,
                        StatusCode::NOT_FOUND
                            | StatusCode::NOT_IMPLEMENTED
                            | StatusCode::METHOD_NOT_ALLOWED
                    ) {
                        tracing::warn!(
                            "account_data PUT for {type_key} returned {status}; \
                             keeping local state authoritative until soland wires it"
                        );
                        return Ok(AccountDataSetOutcome::Unsupported { status });
                    }
                }
                Err(error)
            }
        }
    }

    pub async fn identity_describe(&self) -> anyhow::Result<IdentityDescribeResponse> {
        self.get_json("api/v1/identity/describe").await
    }

    pub async fn identity_resolve(&self, did: &str) -> anyhow::Result<IdentityResolveResponse> {
        self.post_json(
            "api/v1/identity/resolve",
            json!({"did": did, "include": []}),
        )
        .await
    }

    pub async fn sync_describe(&self) -> anyhow::Result<SyncDescribeResponse> {
        self.get_json("api/v1/sync/describe").await
    }

    pub async fn sync(&self, since: Option<&str>) -> anyhow::Result<ClientSyncResponse> {
        self.post_json(
            "api/v1/sync",
            json!({"since": since, "timeout_ms": 0, "set_presence": "online"}),
        )
        .await
    }

    pub async fn search_spaces(
        &self,
        query: &str,
        next_cursor: Option<&str>,
    ) -> anyhow::Result<SearchSpacesResponse> {
        let mut body = json!({"query": query, "limit": 20});
        if let Some(cursor) = next_cursor {
            body["next_cursor"] = json!(cursor);
        }
        self.post_json("api/v1/directory/search-spaces", body).await
    }

    pub async fn directory_describe(&self) -> anyhow::Result<DirectoryDescribeResponse> {
        self.get_json("api/v1/directory/describe").await
    }

    pub async fn resolve_space(&self, space_id: &str) -> anyhow::Result<ResolveSpaceResponse> {
        self.post_json(
            "api/v1/directory/resolve-space",
            json!({"space_id": space_id}),
        )
        .await
    }

    /// Query durable events through the current `/api/v1/events` surface.
    pub async fn backfill(&self, space_id: &str) -> anyhow::Result<BackfillResponse> {
        self.get_json(&format!(
            "api/v1/events?spaces={space_id}&direction=backward"
        ))
        .await
    }

    /// Subscribe to the live event stream for one or more Spaces.
    pub async fn events_subscribe(
        &self,
        space_id: &str,
        from: Option<&str>,
        include_history: Option<bool>,
    ) -> anyhow::Result<serde_json::Value> {
        let mut url = format!("api/v1/events/subscribe?spaces={space_id}");
        if let Some(from) = from {
            url.push_str(&format!("&from={from}"));
        }
        if let Some(inc) = include_history {
            url.push_str(&format!("&include_history={inc}"));
        }
        self.get_json(&url).await
    }

    /// Typed wrapper around [`Self::events_subscribe`]: parse the unary
    /// response's `frames[]` array into a vector of typed
    /// [`contrix_sdk::EventsSubscribeFrame`] values. Unknown frame kinds are
    /// surfaced as `EventsSubscribeFrame::Unknown` so the caller can log +
    /// continue rather than break the stream on every spec addition.
    pub async fn events_subscribe_typed(
        &self,
        space_id: &str,
        from: Option<&str>,
        include_history: Option<bool>,
    ) -> anyhow::Result<Vec<contrix_sdk::EventsSubscribeFrame>> {
        let response = self
            .events_subscribe(space_id, from, include_history)
            .await?;
        let mut frames = Vec::new();
        if let Some(frames_array) = response.get("frames").and_then(|f| f.as_array()) {
            for frame in frames_array {
                let typed: contrix_sdk::EventsSubscribeFrame =
                    serde_json::from_value(frame.clone())
                        .map_err(|err| anyhow::anyhow!("failed to parse subscribe frame: {err}"))?;
                frames.push(typed);
            }
        }
        Ok(frames)
    }

    pub async fn snapshot_head(&self, space_id: &str) -> anyhow::Result<SnapshotHeadResponse> {
        self.get_json(&format!("api/v1/sync/snapshot-head?space_id={space_id}"))
            .await
    }

    pub async fn authz_check(
        &self,
        actor: &str,
        action: &str,
        space_id: &str,
    ) -> anyhow::Result<AuthzCheckResponse> {
        self.post_json(
            "api/v1/authz/check",
            json!({
                "actor": actor,
                "action": action,
                "resource": {"kind": "space", "space_id": space_id}
            }),
        )
        .await
    }

    pub async fn effective_grants(&self, subject: &str) -> anyhow::Result<EffectiveGrantsResponse> {
        self.get_json(&format!("api/v1/authz/effective-grants?subject={subject}"))
            .await
    }

    pub async fn invites(&self) -> anyhow::Result<InvitesResponse> {
        self.get_json("api/v1/authz/invites").await
    }

    pub async fn profile_presence(&self, did: &str) -> anyhow::Result<Value> {
        self.get_json(&format!("api/v1/profile/presence?did={did}"))
            .await
    }

    pub async fn register_push_device(&self) -> anyhow::Result<PushRegisterResponse> {
        let request = crate::push::build_register_request("dev_yougen")?;
        self.register_push_device_with_request(&request).await
    }

    pub async fn register_push_device_with_request_at(
        &self,
        path: &str,
        request: &RegisterDeviceRequest,
    ) -> anyhow::Result<PushRegisterResponse> {
        let response = self
            .push_client(Some(path), None)
            .register_device_with_request(request, request.idempotency_key.as_deref(), None)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(map_chime_register_response(response.body))
    }

    pub async fn register_push_device_with_request(
        &self,
        request: &RegisterDeviceRequest,
    ) -> anyhow::Result<PushRegisterResponse> {
        // Default register path is hardcoded in chime; pass `None` so it's used.
        let response = self
            .push_client(None, None)
            .register_device_with_request(request, request.idempotency_key.as_deref(), None)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(map_chime_register_response(response.body))
    }

    pub async fn unregister_push_device(&self, device_id: &str) -> anyhow::Result<OkResponse> {
        let request = crate::push::build_unregister_request(device_id, None)?;
        self.unregister_push_device_with_request(&request).await
    }

    pub async fn unregister_push_device_with_request(
        &self,
        request: &UnregisterDeviceRequest,
    ) -> anyhow::Result<OkResponse> {
        let response = self
            .push_client(None, None)
            .unregister_device_with_request(request, request.idempotency_key.as_deref(), None)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(OkResponse {
            ok: response.body.ok,
        })
    }

    /// Build a [`ContrixPushClient`] that mirrors this api client's auth
    /// state. Optional `register_device_path` / `unregister_device_path`
    /// honor a bridge-discovered endpoint.
    fn push_client(
        &self,
        register_device_path: Option<&str>,
        unregister_device_path: Option<&str>,
    ) -> ContrixPushClient {
        // yougen does not currently fail-closed on session grant for push;
        // the access_token is the session's bearer credential.
        let mut client =
            ContrixPushClient::new(self.base_url.as_str()).with_required_session_grant(false);
        if let Some(token) = self.access_token.as_deref() {
            client = client.with_bearer_token(token);
        }
        if let Some(path) = register_device_path {
            client = client.with_register_device_path(path);
        }
        if let Some(path) = unregister_device_path {
            client = client.with_unregister_device_path(path);
        }
        client
    }

    pub async fn upload_keys(&self, device_id: &str) -> anyhow::Result<KeysUploadResponse> {
        self.post_json(
            "api/v1/keys/upload",
            json!({
                "device_id": device_id,
                "one_time_keys": {
                    "signed_curve25519:yougen-otk-1": {
                        "key_id": "yougen-otk-1",
                        "key": "yougen-one-time"
                    }
                },
                "fallback_keys": {},
                "device_signature": {"alg": "EdDSA", "signature": "yougen-dev-signature"}
            }),
        )
        .await
    }

    pub async fn claim_keys(
        &self,
        actor: &str,
        device_id: &str,
        algorithm: &str,
    ) -> anyhow::Result<KeysClaimResponse> {
        self.post_json(
            "api/v1/keys/claim",
            json!({"one_time_keys": {actor: {device_id: algorithm}}}),
        )
        .await
    }

    pub async fn query_keys(
        &self,
        actor: &str,
        device_id: &str,
    ) -> anyhow::Result<KeysQueryResponse> {
        self.post_json(
            "api/v1/keys/query",
            json!({"device_keys": {actor: [device_id]}}),
        )
        .await
    }

    pub async fn send_to_device(
        &self,
        actor: &str,
        device_id: &str,
    ) -> anyhow::Result<DeviceMessagesSendResponse> {
        self.send_device_message_envelope(
            "yougen-txn-1",
            actor,
            device_id,
            "cx.mls.test",
            json!({"ciphertext": "opaque-yougen-test"}),
        )
        .await
    }

    /// POST a typed `cx.schema.device_message.v1` envelope to soland's
    /// `/api/v1/device_messages` endpoint. Used by device
    /// verification flows (R3) and any other flow that needs to deliver a
    /// message to a specific (actor, device_id) pair without going through
    /// Space history. The body shape is the canonical
    /// `messages -> actor -> device_id -> {type, content}` map. Idempotency
    /// is conveyed via the `Idempotency-Key` request header (previously the
    /// trailing `{txn_id}` path segment).
    pub async fn send_device_message_envelope(
        &self,
        txn_id: &str,
        target_actor: &str,
        target_device_id: &str,
        message_type: &str,
        content: serde_json::Value,
    ) -> anyhow::Result<DeviceMessagesSendResponse> {
        let path = "api/v1/device_messages";
        let payload =
            build_device_message_envelope(target_actor, target_device_id, message_type, content);
        let request = self
            .http
            .post(self.endpoint(path)?)
            .header("Idempotency-Key", txn_id)
            .json(&payload);
        self.send_json(self.prepare_request(request), Method::POST)
            .await
    }

    pub async fn receive_device_messages(&self) -> anyhow::Result<DeviceMessagesReceiveResponse> {
        self.get_json("api/v1/device_messages").await
    }

    pub async fn put_key_backup(
        &self,
        backup_id: &str,
        payload: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        self.put_json(&format!("api/v1/keys/backups/{backup_id}"), payload)
            .await
    }

    pub async fn list_key_backups(&self) -> anyhow::Result<serde_json::Value> {
        self.get_json("api/v1/keys/backups").await
    }

    pub async fn get_key_backup(&self, backup_id: &str) -> anyhow::Result<serde_json::Value> {
        self.get_json(&format!("api/v1/keys/backups/{backup_id}"))
            .await
    }

    pub async fn delete_key_backup(&self, backup_id: &str) -> anyhow::Result<serde_json::Value> {
        let request = self
            .http
            .delete(self.endpoint(&format!("api/v1/keys/backups/{backup_id}"))?);
        self.send_json(self.prepare_request(request), Method::DELETE)
            .await
    }

    pub async fn upload_blob(&self, bytes: &'static [u8]) -> anyhow::Result<BlobUploadResponse> {
        let request = self
            .http
            .post(self.endpoint("api/v1/blob/upload")?)
            .header("content-type", "application/octet-stream")
            .body(bytes);
        self.send_json(self.prepare_request(request), Method::POST)
            .await
    }

    pub async fn get_blob_bytes(&self, blob_ref: &str) -> anyhow::Result<Vec<u8>> {
        let request = self
            .http
            .get(self.endpoint(&format!("api/v1/blob/get?blob_ref={blob_ref}"))?);
        self.send_bytes(self.prepare_request(request), Method::GET)
            .await
    }

    pub async fn report_moderation(
        &self,
        space_id: &str,
        target_ref: &str,
        reason: &str,
        reporter: &str,
    ) -> anyhow::Result<ModerationReportResponse> {
        self.post_json(
            "api/v1/moderation/report",
            json!({
                "space_id": space_id,
                "target_ref": target_ref,
                "reason": reason,
                "reporter": reporter,
                "description": null,
                "evidence_refs": []
            }),
        )
        .await
    }

    /// Round 28: ship a single client-side telemetry entry to
    /// soland's audit ingest endpoint (or, if soland routes the path
    /// through coauth, the coauth audit feed — soland's reverse
    /// proxy makes the choice transparent to the client).
    ///
    /// The endpoint shape mirrors sodmin's audit feed: a plain JSON
    /// body keyed by actor/action/outcome/note/recorded_at. The
    /// 404-tolerant return type lets the caller distinguish "not
    /// wired" (re-buffer) from "rejected" (drop) without parsing
    /// error strings.
    pub async fn post_audit_user_action(&self, payload: Value) -> Result<(), AuditPostError> {
        let request = self
            .http
            .post(
                self.endpoint("api/v1/audit/user-action")
                    .map_err(|err| AuditPostError::Other(err.to_string()))?,
            )
            .json(&payload);
        let response = self
            .prepare_request(request)
            .send()
            .await
            .map_err(|err| AuditPostError::Other(err.to_string()))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        if status == StatusCode::NOT_FOUND {
            return Err(AuditPostError::NotWired);
        }
        Err(AuditPostError::Other(format!("HTTP {status}")))
    }

    // ── Authentication ──────────────────────────────────────────────

    pub async fn passkey_challenge(
        &self,
        user_did: &str,
    ) -> anyhow::Result<PasskeyChallengeResponse> {
        self.post_json(
            "api/v1/auth/passkey/challenge",
            json!({"user_did": user_did}),
        )
        .await
    }

    pub async fn passkey_verify(
        &self,
        user_did: &str,
        credential: Value,
    ) -> anyhow::Result<PasskeyVerifyResponse> {
        self.post_json(
            "api/v1/auth/passkey/verify",
            json!({"user_did": user_did, "credential": credential}),
        )
        .await
    }

    pub async fn oidc_authorize(
        &self,
        provider: &str,
        redirect_uri: &str,
    ) -> anyhow::Result<OidcAuthorizeResponse> {
        self.post_json(
            "api/v1/auth/oidc/authorize",
            json!({"provider": provider, "redirect_uri": redirect_uri}),
        )
        .await
    }

    pub async fn oidc_callback(
        &self,
        code: &str,
        state: &str,
    ) -> anyhow::Result<OidcCallbackResponse> {
        self.post_json(
            "api/v1/auth/oidc/callback",
            json!({"code": code, "state": state}),
        )
        .await
    }

    pub async fn token_refresh(&self, refresh_token: &str) -> anyhow::Result<TokenRefreshResponse> {
        self.post_json(
            "api/v1/auth/token/refresh",
            json!({"refresh_token": refresh_token}),
        )
        .await
    }

    pub async fn account_recovery(
        &self,
        did: &str,
        method: &str,
        proof: Value,
    ) -> anyhow::Result<AccountRecoveryResponse> {
        self.post_json(
            "api/v1/account/recovery",
            json!({"did": did, "method": method, "proof": proof}),
        )
        .await
    }

    // ── Identity & Directory ────────────────────────────────────────

    pub async fn search_organizations(
        &self,
        query: &str,
        next_cursor: Option<&str>,
    ) -> anyhow::Result<SearchOrganizationsResponse> {
        let mut body = json!({"query": query, "limit": 20});
        if let Some(cursor) = next_cursor {
            body["next_cursor"] = json!(cursor);
        }
        self.post_json("api/v1/directory/search-organizations", body)
            .await
    }

    pub async fn search_actors(
        &self,
        query: &str,
        next_cursor: Option<&str>,
    ) -> anyhow::Result<SearchActorsResponse> {
        let mut body = json!({"query": query, "limit": 20});
        if let Some(cursor) = next_cursor {
            body["next_cursor"] = json!(cursor);
        }
        self.post_json("api/v1/directory/search-actors", body).await
    }

    pub async fn resolve_handle(&self, handle: &str) -> anyhow::Result<ResolveHandleResponse> {
        self.post_json("api/v1/identity/resolve-handle", json!({"handle": handle}))
            .await
    }

    // ── Space Management ────────────────────────────────────────────

    pub async fn update_space(
        &self,
        space_id: &str,
        updates: Value,
    ) -> anyhow::Result<UpdateSpaceResponse> {
        self.patch_json(&format!("api/v1/spaces/{space_id}"), updates)
            .await
    }

    pub async fn archive_space(&self, space_id: &str) -> anyhow::Result<ArchiveSpaceResponse> {
        self.post_json(&format!("api/v1/spaces/{space_id}/archive"), json!({}))
            .await
    }

    pub async fn set_space_policy(
        &self,
        space_id: &str,
        join_rule: &str,
        history_visibility: &str,
    ) -> anyhow::Result<SpacePolicyResponse> {
        self.put_json(
            &format!("api/v1/spaces/{space_id}/policy"),
            json!({"join_rule": join_rule, "history_visibility": history_visibility}),
        )
        .await
    }

    pub async fn invite_to_space(
        &self,
        space_id: &str,
        target: &str,
        role: Option<&str>,
    ) -> anyhow::Result<SpaceInviteResponse> {
        self.post_json(
            &format!("api/v1/spaces/{space_id}/invite"),
            json!({"target": target, "role": role}),
        )
        .await
    }

    pub async fn accept_space_invite(
        &self,
        space_id: &str,
        invite_id: &str,
    ) -> anyhow::Result<SpaceInviteResponse> {
        self.post_json(
            &format!("api/v1/spaces/{space_id}/invite/accept"),
            json!({"invite_id": invite_id}),
        )
        .await
    }

    pub async fn reject_space_invite(
        &self,
        space_id: &str,
        invite_id: &str,
    ) -> anyhow::Result<SpaceInviteResponse> {
        self.post_json(
            &format!("api/v1/spaces/{space_id}/invite/reject"),
            json!({"invite_id": invite_id}),
        )
        .await
    }

    pub async fn leave_space(&self, space_id: &str) -> anyhow::Result<SpaceLeaveResponse> {
        self.post_json(&format!("api/v1/spaces/{space_id}/leave"), json!({}))
            .await
    }

    pub async fn ban_member(
        &self,
        space_id: &str,
        member: &str,
    ) -> anyhow::Result<BanMemberResponse> {
        self.post_json(
            &format!("api/v1/spaces/{space_id}/members/{member}/ban"),
            json!({}),
        )
        .await
    }

    pub async fn send_typing(
        &self,
        space_id: &str,
        typing: bool,
    ) -> anyhow::Result<TypingResponse> {
        self.post_json(
            "api/v1/typing",
            json!({"space_id": space_id, "typing": typing}),
        )
        .await
    }

    pub async fn send_receipt(
        &self,
        space_id: &str,
        event_id: &str,
        receipt_type: &str,
    ) -> anyhow::Result<ReceiptResponse> {
        self.post_json(
            "api/v1/receipts",
            json!({"space_id": space_id, "event_id": event_id, "receipt_type": receipt_type}),
        )
        .await
    }

    // ── Views — collection projection (T20) ─────────────────────────
    //
    // Pairs with contrix-rust-sdk@9d02761 + soland@1cdab88.
    // POST /api/v1/views/{view_id}/projection returns the typed
    // CollectionProjectionResponse defined in contrix_core::model.
    pub async fn collection_projection(
        &self,
        view_id: &str,
    ) -> anyhow::Result<contrix_sdk::CollectionProjectionResponse> {
        self.post_json(&format!("api/v1/views/{view_id}/projection"), json!({}))
            .await
    }

    // ── Device & Crypto ─────────────────────────────────────────────

    pub async fn revoke_device(&self, device_id: &str) -> anyhow::Result<OkResponse> {
        self.post_json(&format!("api/v1/devices/{device_id}/revoke"), json!({}))
            .await
    }

    pub async fn rotate_keys(&self, device_id: &str) -> anyhow::Result<RotateKeysResponse> {
        self.post_json("api/v1/keys/rotate", json!({"device_id": device_id}))
            .await
    }

    pub async fn get_device_trust(&self) -> anyhow::Result<DeviceTrustResponse> {
        self.get_json("api/v1/devices/trust").await
    }

    pub async fn verify_device(
        &self,
        device_id: &str,
        method: &str,
        proof: Value,
    ) -> anyhow::Result<VerifyDeviceResponse> {
        self.post_json(
            &format!("api/v1/devices/{device_id}/verify"),
            json!({"method": method, "proof": proof}),
        )
        .await
    }

    pub async fn get_mls_epoch(&self, group_id: &str) -> anyhow::Result<MlsEpochResponse> {
        self.get_json(&format!("api/v1/mls/epoch?group_id={group_id}"))
            .await
    }

    pub async fn rotate_mls_epoch(&self, group_id: &str) -> anyhow::Result<MlsRotateResponse> {
        self.post_json("api/v1/mls/rotate", json!({"group_id": group_id}))
            .await
    }

    // ── Moderation & Policy ─────────────────────────────────────────

    pub async fn get_moderation_reports(
        &self,
        space_id: Option<&str>,
    ) -> anyhow::Result<ModerationReportsResponse> {
        match space_id {
            Some(sid) => {
                self.get_json(&format!("api/v1/moderation/reports?space_id={sid}"))
                    .await
            }
            None => self.get_json("api/v1/moderation/reports").await,
        }
    }

    pub async fn resolve_moderation_report(
        &self,
        report_id: &str,
        resolution: &str,
        notes: Option<&str>,
    ) -> anyhow::Result<ModerationResolveResponse> {
        self.post_json(
            &format!("api/v1/moderation/reports/{report_id}/resolve"),
            json!({"resolution": resolution, "notes": notes}),
        )
        .await
    }

    pub async fn get_policy(&self, resource: &str) -> anyhow::Result<PolicyResponse> {
        self.get_json(&format!("api/v1/policy/{resource}")).await
    }

    // ── Federation ──────────────────────────────────────────────────

    pub async fn federation_submit_transaction(
        &self,
        txn_id: &str,
        origin: &str,
        destination: &str,
        operations: Vec<Value>,
    ) -> anyhow::Result<FederationTransactionResponse> {
        self.put_json(
            &format!("api/v1/federation/transactions/{txn_id}"),
            json!({
                "origin": origin,
                "destination": destination,
                "operations": operations
            }),
        )
        .await
    }

    pub async fn federation_push_operations(
        &self,
        space_id: &str,
        operations: Vec<Value>,
    ) -> anyhow::Result<FederationTransactionResponse> {
        self.post_json(
            "api/v1/federation/push-operations",
            json!({"space_id": space_id, "operations": operations}),
        )
        .await
    }

    pub async fn federation_pull_operations(
        &self,
        space_id: &str,
        since: Option<&str>,
        limit: Option<usize>,
    ) -> anyhow::Result<FederationOperationsResponse> {
        self.post_json(
            "api/v1/federation/pull-operations",
            json!({
                "space_id": space_id,
                "since": since,
                "limit": limit.unwrap_or(100)
            }),
        )
        .await
    }

    pub async fn federation_space_members(
        &self,
        space_id: &str,
    ) -> anyhow::Result<FederationSpaceMembersResponse> {
        self.get_json(&format!(
            "api/v1/federation/space-members?space_id={space_id}"
        ))
        .await
    }

    pub async fn federation_verify_actor(
        &self,
        actor: &str,
        space_id: &str,
    ) -> anyhow::Result<FederationVerifyActorResponse> {
        self.post_json(
            "api/v1/federation/verify-actor",
            json!({"actor": actor, "space_id": space_id}),
        )
        .await
    }

    // ── Policy (signed decisions) ───────────────────────────────────

    pub async fn policy_check(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
    ) -> anyhow::Result<PolicyCheckResponse> {
        self.post_json(
            "api/v1/policy/check",
            json!({"actor": actor, "action": action, "resource": resource}),
        )
        .await
    }

    // ── MIMI Provider Facade ─────────────────────────────────────

    pub async fn mimi_provider_directory(&self) -> anyhow::Result<MimiProviderDirectoryResponse> {
        self.get_json("api/v1/mimi/provider-directory").await
    }

    pub async fn mimi_key_material(
        &self,
        request: Value,
    ) -> anyhow::Result<MimiKeyMaterialResponse> {
        self.post_json("api/v1/mimi/key-material", request).await
    }

    pub async fn mimi_room_update(
        &self,
        room_id: &str,
        request: Value,
    ) -> anyhow::Result<MimiRoomUpdateResponse> {
        self.put_json(&format!("api/v1/mimi/rooms/{room_id}/update"), request)
            .await
    }

    pub async fn mimi_notify(
        &self,
        room_id: &str,
        request: Value,
    ) -> anyhow::Result<MimiNotifyResponse> {
        self.post_json(&format!("api/v1/mimi/rooms/{room_id}/notify"), request)
            .await
    }

    pub async fn mimi_submit_message(
        &self,
        room_id: &str,
        request: Value,
    ) -> anyhow::Result<MimiSubmitMessageResponse> {
        self.post_json(&format!("api/v1/mimi/rooms/{room_id}/messages"), request)
            .await
    }

    pub async fn mimi_group_info(&self, room_id: &str) -> anyhow::Result<MimiGroupInfoResponse> {
        self.get_json(&format!("api/v1/mimi/rooms/{room_id}/group-info"))
            .await
    }

    pub async fn mimi_request_consent(
        &self,
        request: Value,
    ) -> anyhow::Result<MimiConsentResponse> {
        self.post_json("api/v1/mimi/consent/request", request).await
    }

    pub async fn mimi_update_consent(&self, request: Value) -> anyhow::Result<MimiConsentResponse> {
        self.post_json("api/v1/mimi/consent/update", request).await
    }

    pub async fn mimi_identifier_query(
        &self,
        request: Value,
    ) -> anyhow::Result<MimiIdentifierQueryResponse> {
        self.post_json("api/v1/mimi/identifiers/query", request)
            .await
    }

    pub async fn mimi_report_abuse(
        &self,
        request: Value,
    ) -> anyhow::Result<MimiReportAbuseResponse> {
        self.post_json("api/v1/mimi/report-abuse", request).await
    }

    pub async fn mimi_proxy_download(
        &self,
        request: Value,
    ) -> anyhow::Result<MimiProxyDownloadResponse> {
        self.post_json("api/v1/mimi/proxy-download", request).await
    }

    // ── Applet ──────────────────────────────────────────────────────

    pub async fn applet_ping(&self, applet_did: &str) -> anyhow::Result<AppletPingResponse> {
        self.post_json("api/v1/applet/ping", json!({"applet_did": applet_did}))
            .await
    }

    pub async fn applet_describe(
        &self,
        applet_did: &str,
    ) -> anyhow::Result<AppletDescribeResponse> {
        self.get_json(&format!("api/v1/applet/describe?applet_did={applet_did}"))
            .await
    }

    pub async fn applet_transaction(
        &self,
        applet_did: &str,
        operations: Vec<Value>,
    ) -> anyhow::Result<AppletTransactionResponse> {
        self.post_json(
            "api/v1/applet/transaction",
            json!({"applet_did": applet_did, "operations": operations}),
        )
        .await
    }

    pub async fn applet_query_actor(
        &self,
        applet_did: &str,
        actor: &str,
    ) -> anyhow::Result<AppletQueryActorResponse> {
        self.post_json(
            "api/v1/applet/query_actor",
            json!({"applet_did": applet_did, "actor": actor}),
        )
        .await
    }

    pub async fn applet_query_space(
        &self,
        applet_did: &str,
        space_id: &str,
    ) -> anyhow::Result<AppletQuerySpaceResponse> {
        self.post_json(
            "api/v1/applet/query_space",
            json!({"applet_did": applet_did, "space_id": space_id}),
        )
        .await
    }

    pub async fn applet_protocol_metadata(
        &self,
        applet_did: &str,
    ) -> anyhow::Result<AppletProtocolMetadataResponse> {
        self.get_json(&format!(
            "api/v1/applet/protocol_metadata?applet_did={applet_did}"
        ))
        .await
    }

    pub async fn applet_third_party_users(
        &self,
        applet_did: &str,
        location: &str,
    ) -> anyhow::Result<ThirdPartyUsersResponse> {
        self.post_json(
            "api/v1/applet/third_party_users",
            json!({"applet_did": applet_did, "location": location}),
        )
        .await
    }

    pub async fn applet_third_party_locations(
        &self,
        applet_did: &str,
        user_id: &str,
    ) -> anyhow::Result<ThirdPartyLocationsResponse> {
        self.post_json(
            "api/v1/applet/third_party_locations",
            json!({"applet_did": applet_did, "user_id": user_id}),
        )
        .await
    }

    // ── Identity (extended) ─────────────────────────────────────────

    pub async fn identity_log(
        &self,
        did: &str,
        limit: Option<usize>,
    ) -> anyhow::Result<IdentityLogResponse> {
        self.post_json(
            "api/v1/identity/log",
            json!({"did": did, "limit": limit.unwrap_or(50)}),
        )
        .await
    }

    pub async fn submit_did_operation(
        &self,
        did: &str,
        operation: Value,
    ) -> anyhow::Result<SubmitDidOperationResponse> {
        self.post_json(
            "api/v1/identity/submit-did-operation",
            json!({"did": did, "operation": operation}),
        )
        .await
    }

    pub async fn events_describe(&self) -> anyhow::Result<EventsDescribeResponse> {
        self.get_json("api/v1/events/describe").await
    }

    async fn submit_event(&self, event: &Value) -> anyhow::Result<SubmitEventResponse> {
        let idempotency_key = event
            .get("unsigned")
            .and_then(|value| value.get("local_operation_idempotency_alias"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(uuid_v8);
        let request = self.http.post(self.endpoint("api/v1/events")?).json(event);
        let request = self.with_write_request_headers(request, &idempotency_key);
        self.send_json_retryable(self.prepare_request(request), Method::POST)
            .await
    }

    pub async fn submit_operation_event(
        &self,
        operation: &OperationEnvelope,
    ) -> anyhow::Result<SubmitEventResponse> {
        let event = operation_event_envelope(operation)?;
        self.submit_event(&event).await
    }

    pub async fn identity_receipts(&self, did: &str) -> anyhow::Result<IdentityReceiptsResponse> {
        self.post_json("api/v1/identity/receipts", json!({"did": did}))
            .await
    }

    // ── Media ───────────────────────────────────────────────────────

    pub async fn ice_config(&self) -> anyhow::Result<IceConfigResponse> {
        self.get_json("api/v1/media/ice-config").await
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let request = self.http.get(self.endpoint(path)?);
        self.send_json(self.prepare_request(request), Method::GET)
            .await
    }

    async fn post_json<T: DeserializeOwned>(&self, path: &str, body: Value) -> anyhow::Result<T> {
        let request = self.http.post(self.endpoint(path)?).json(&body);
        self.send_json(self.prepare_request(request), Method::POST)
            .await
    }

    async fn put_json<T: DeserializeOwned>(&self, path: &str, body: Value) -> anyhow::Result<T> {
        let request = self.http.put(self.endpoint(path)?).json(&body);
        self.send_json(self.prepare_request(request), Method::PUT)
            .await
    }

    async fn patch_json<T: DeserializeOwned>(&self, path: &str, body: Value) -> anyhow::Result<T> {
        let request = self.http.patch(self.endpoint(path)?).json(&body);
        self.send_json(self.prepare_request(request), Method::PATCH)
            .await
    }

    async fn delete_json<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let request = self.http.delete(self.endpoint(path)?);
        self.send_json(self.prepare_request(request), Method::DELETE)
            .await
    }

    async fn send_json<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        method: Method,
    ) -> anyhow::Result<T> {
        self.send_json_internal(request, method.clone(), is_retryable_method(&method))
            .await
    }

    async fn send_json_retryable<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        method: Method,
    ) -> anyhow::Result<T> {
        self.send_json_internal(request, method, true).await
    }

    async fn send_json_internal<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        method: Method,
        retryable: bool,
    ) -> anyhow::Result<T> {
        let response = self.send_with_retry(request, method, retryable).await?;
        let status = response.status();
        if !status.is_success() {
            let bytes = response.bytes().await?;
            return Err(ContrixApiError {
                status,
                error: decode_contrix_error(status, &bytes),
            }
            .into());
        }
        Ok(response.json().await?)
    }

    async fn send_bytes(
        &self,
        request: reqwest::RequestBuilder,
        method: Method,
    ) -> anyhow::Result<Vec<u8>> {
        let response = self
            .send_with_retry(request, method.clone(), is_retryable_method(&method))
            .await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(ContrixApiError {
                status,
                error: decode_contrix_error(status, &bytes),
            }
            .into());
        }
        Ok(bytes.to_vec())
    }

    async fn send_with_retry(
        &self,
        request: reqwest::RequestBuilder,
        _method: Method,
        retryable: bool,
    ) -> anyhow::Result<reqwest::Response> {
        let mut attempt = 0usize;
        let mut did_refresh = false;
        loop {
            // Check if request was cancelled
            if self.cancel_token.as_ref().is_some_and(|t| t.is_cancelled()) {
                return Err(anyhow::anyhow!("request cancelled"));
            }

            let Some(candidate) = request.try_clone() else {
                return Ok(request.send().await?);
            };
            match candidate.send().await {
                Ok(response) => {
                    // Handle 401 with automatic token refresh
                    if response.status() == StatusCode::UNAUTHORIZED
                        && !did_refresh
                        && self.refresh_token.is_some()
                    {
                        if let Ok(result) = self.try_refresh_token().await {
                            // Update token for subsequent requests
                            // Note: we can't mutate self here, but the caller
                            // should handle the TokenRefreshResult
                            let _ = result;
                            did_refresh = true;
                            continue;
                        }
                    }

                    if retryable
                        && attempt < self.retry.max_retries
                        && is_retryable_status(response.status())
                    {
                        self.set_network_state(NetworkState::Reconnecting).await;
                        sleep_retry_delay(response.headers(), self.retry.initial_backoff, attempt)
                            .await;
                        attempt += 1;
                        continue;
                    }

                    // Update network state based on response
                    if response.status().is_server_error()
                        || response.status() == StatusCode::SERVICE_UNAVAILABLE
                    {
                        self.set_network_state(NetworkState::Reconnecting).await;
                    } else if response.status().is_success() {
                        self.set_network_state(NetworkState::Online).await;
                    }

                    return Ok(response);
                }
                Err(error)
                    if retryable
                        && attempt < self.retry.max_retries
                        && is_retryable_reqwest_error(&error) =>
                {
                    self.set_network_state(NetworkState::Reconnecting).await;
                    sleep_backoff(self.retry.initial_backoff, attempt).await;
                    attempt += 1;
                }
                Err(error) => {
                    self.set_network_state(NetworkState::Offline).await;
                    return Err(error.into());
                }
            }
        }
    }

    fn authorize(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.access_token {
            Some(token) => request.bearer_auth(token),
            None => request,
        }
    }

    fn prepare_request(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        self.attach_wait_for(self.authorize(request))
    }

    fn attach_wait_for(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.wait_for_sync_token.as_deref() {
            Some(sync_token) => request.header("x-contrix-wait-for", sync_token),
            None => request,
        }
    }

    fn with_write_request_headers(
        &self,
        request: reqwest::RequestBuilder,
        request_id: &str,
    ) -> reqwest::RequestBuilder {
        request
            .header("x-contrix-request-id", request_id)
            .header("idempotency-key", request_id)
    }
}

fn operation_event_envelope(operation: &OperationEnvelope) -> anyhow::Result<Value> {
    let event_id = format!("cx:event:{}", uuid_v7());
    let payload = operation.body.clone();
    let mut event = json!({
        "event_id": event_id,
        "kind": operation.op_type,
        "actor_id": operation.actor,
        "actor_seq": operation.causal.actor_seq,
        "space_id": operation.space_id,
        "created_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "hlc": operation.causal.hlc,
        "prev_refs": [],
        "refs": [],
        "payload": payload,
        "unsigned": {
            "local_operation_idempotency_alias": operation.operation_id,
        },
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": format!("{}#yougen", operation.actor),
            "payload_hash": "",
            "created_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "jws": "a..b",
        }],
    });
    if let Some(target_ref) = &operation.target_ref {
        event["unsigned"]["local_target_ref"] = Value::String(target_ref.clone());
    }
    refresh_event_proof(&mut event)?;
    Ok(event)
}

fn event_canonical_digest(event: &Value) -> anyhow::Result<String> {
    let mut canonical = event.clone();
    if let Value::Object(object) = &mut canonical {
        object.remove("proofs");
        object.remove("unsigned");
    }
    sha256_json_result(&canonical)
}

fn refresh_event_proof(event: &mut Value) -> anyhow::Result<()> {
    let digest = event_canonical_digest(event)?;
    event["proofs"][0]["payload_hash"] = Value::String(digest);
    Ok(())
}

fn sha256_json_result(value: &Value) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(value)?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

/// Build the canonical `cx.schema.device_message.v1` envelope:
///
/// ```json
/// {
///   "messages": {
///     "<target_actor_did>": {
///       "<target_device_id>": {
///         "type": "<message_type>",
///         "content": <content>
///       }
///     }
///   }
/// }
/// ```
///
/// Pure function so the wire shape is testable without a live HTTP
/// client; used by [`ContrixApi::send_device_message_envelope`] (R3).
pub fn build_device_message_envelope(
    target_actor: &str,
    target_device_id: &str,
    message_type: &str,
    content: serde_json::Value,
) -> serde_json::Value {
    json!({
        "messages": {
            target_actor: {
                target_device_id: {
                    "type": message_type,
                    "content": content,
                }
            }
        }
    })
}

/// Project chime's full [`RegisterDeviceResponse`](chime::RegisterDeviceResponse)
/// onto yougen's slimmer `PushRegisterResponse` view (the upstream
/// fields not modelled here are intentionally dropped for now).
fn map_chime_register_response(response: chime::RegisterDeviceResponse) -> PushRegisterResponse {
    PushRegisterResponse {
        ok: response.ok,
        registration_id: response.registration_id,
        expires_at: response.expires_at,
    }
}

pub fn decode_contrix_error(status: StatusCode, bytes: &[u8]) -> ErrorEnvelope {
    serde_json::from_slice::<ApiErrorBody>(bytes)
        .map(|body| body.error)
        .or_else(|_| serde_json::from_slice::<ErrorEnvelope>(bytes))
        .unwrap_or_else(|_| {
            ErrorEnvelope::new(
                "cx.error.http_status",
                format!("HTTP request failed with status {status}"),
            )
        })
}

fn is_retryable_method(method: &Method) -> bool {
    matches!(method, &Method::GET | &Method::PUT | &Method::PATCH)
}

fn is_retryable_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn is_retryable_reqwest_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || {
        #[cfg(not(target_arch = "wasm32"))]
        {
            error.is_connect()
        }
        #[cfg(target_arch = "wasm32")]
        {
            false
        }
    }
}

async fn sleep_backoff(initial: Duration, attempt: usize) {
    tokio::time::sleep(backoff_duration(initial, attempt)).await;
}

fn backoff_duration(initial: Duration, attempt: usize) -> Duration {
    let factor = 1u32.checked_shl(attempt as u32).unwrap_or(u32::MAX);
    initial.saturating_mul(factor)
}

async fn sleep_retry_delay(headers: &HeaderMap, initial: Duration, attempt: usize) {
    let delay = parse_retry_after(headers).unwrap_or_else(|| backoff_duration(initial, attempt));
    tokio::time::sleep(delay).await;
}

fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();

    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    chrono::DateTime::parse_from_rfc2822(value)
        .ok()
        .and_then(|deadline| {
            deadline
                .with_timezone(&chrono::Utc)
                .signed_duration_since(chrono::Utc::now())
                .to_std()
                .ok()
        })
}

pub fn parse_server_description(value: Value) -> anyhow::Result<ServerDescription> {
    Ok(serde_json::from_value(value)?)
}

pub fn parse_sync(value: Value) -> anyhow::Result<ClientSyncResponse> {
    Ok(serde_json::from_value(value)?)
}

pub fn parse_sync_describe(value: Value) -> anyhow::Result<SyncDescribeResponse> {
    Ok(serde_json::from_value(value)?)
}

pub fn parse_directory_describe(value: Value) -> anyhow::Result<DirectoryDescribeResponse> {
    Ok(serde_json::from_value(value)?)
}

pub fn parse_resolve_space(value: Value) -> anyhow::Result<ResolveSpaceResponse> {
    Ok(serde_json::from_value(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn endpoint_join_keeps_api_paths_under_base_url() {
        let api = ContrixApi::new("http://127.0.0.1:8787/").unwrap();
        assert_eq!(
            api.endpoint("/api/v1/server/describe").unwrap().as_str(),
            "http://127.0.0.1:8787/api/v1/server/describe"
        );
    }

    #[test]
    fn parses_server_and_sync_payloads() {
        let description = parse_server_description(json!({
            "service_did": "did:web:serverx.local",
            "service_type": "principal_server",
            "protocol_version": "1.0",
            "supported_features": ["sync.account"],
            "supported_operations": ["cx.sync.account"],
            "limits": {"storage": "memory"}
        }))
        .unwrap();
        assert_eq!(description.protocol_version, "1.0");

        let sync = parse_sync(json!({
            "next_batch": "sx:1",
            "spaces": {"cx:space:0196419b-0000-7000-8000-000000000000": {"summary": {}}},
            "to_device": [],
            "account_data": [],
            "device_lists": {"changed": [], "left": []}
        }))
        .unwrap();
        assert_eq!(sync.spaces.len(), 1);

        let directory = parse_directory_describe(json!({
            "service_did": "did:web:serverx.local",
            "resource_types": ["space", "organization", "actor"],
            "discovery_profiles": ["cx.profile.directory.v1"],
            "restricted_query_proof": false
        }))
        .unwrap();
        assert!(directory.resource_types.contains(&"space".to_owned()));
    }

    #[test]
    fn decodes_wrapped_contrix_error_envelope() {
        let decoded = decode_contrix_error(
            StatusCode::CONFLICT,
            br#"{"ok":false,"error":{"errcode":"expected_head_mismatch","error":"expected_head mismatch","retry_after_ms":250,"scope":"repo"}}"#,
        );
        assert_eq!(decoded.code(), "expected_head_mismatch");
        assert_eq!(decoded.message(), "expected_head mismatch");
        assert_eq!(decoded.retry_after_ms(), Some(250));
        assert_eq!(decoded.details()["scope"], "repo");
    }

    #[test]
    fn decodes_plain_error_envelope_and_falls_back() {
        let decoded = decode_contrix_error(
            StatusCode::BAD_REQUEST,
            br#"{"errcode":"invalid_param","error":"invalid did"}"#,
        );
        assert_eq!(decoded.code(), "invalid_param");

        let fallback = decode_contrix_error(StatusCode::SERVICE_UNAVAILABLE, b"busy");
        assert_eq!(fallback.code(), "cx.error.http_status");
        assert!(fallback.message().contains("503 Service Unavailable"));
    }

    #[test]
    fn retry_policy_defaults_to_bounded_idempotent_retries() {
        let options = ContrixApiOptions::default();
        assert_eq!(options.retry.max_retries, 2);
        assert!(options.timeout >= Duration::from_secs(1));
        assert!(is_retryable_method(&Method::GET));
        assert!(is_retryable_method(&Method::PUT));
        assert!(!is_retryable_method(&Method::POST));
        assert!(is_retryable_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(is_retryable_status(StatusCode::BAD_GATEWAY));
        assert!(!is_retryable_status(StatusCode::CONFLICT));
    }

    #[test]
    fn retry_after_prefers_seconds_header() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("3"));
        assert_eq!(parse_retry_after(&headers), Some(Duration::from_secs(3)));
    }

    #[test]
    fn write_requests_include_request_identity_and_wait_for_headers() {
        let api = ContrixApi::new("http://127.0.0.1:8787/")
            .unwrap()
            .with_bearer("sx_token")
            .with_wait_for("sx:123");
        let request = api
            .prepare_request(
                api.with_write_request_headers(
                    api.http
                        .post(api.endpoint("api/v1/events").unwrap())
                        .json(&json!({"body": "hello"})),
                    "req-123",
                ),
            )
            .build()
            .unwrap();

        assert_eq!(
            request
                .headers()
                .get("x-contrix-request-id")
                .and_then(|value| value.to_str().ok()),
            Some("req-123")
        );
        assert_eq!(
            request
                .headers()
                .get("idempotency-key")
                .and_then(|value| value.to_str().ok()),
            Some("req-123")
        );
        assert_eq!(
            request
                .headers()
                .get("x-contrix-wait-for")
                .and_then(|value| value.to_str().ok()),
            Some("sx:123")
        );
    }

    #[test]
    fn insecure_remote_http_is_rejected() {
        let error = ContrixApi::new("http://contrix.example").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("HTTPS is required for non-local servers")
        );
    }

    /// R3 — `build_device_message_envelope` MUST emit the canonical
    /// `cx.schema.device_message.v1` shape:
    /// `{messages: {<actor>: {<device_id>: {type, content}}}}`. soland's
    /// reducer keys verification events by this exact path; if the wire
    /// shape drifts (extra wrapping, missing layer, etc.) device verification
    /// silently fails because the message never reaches the target device.
    /// This test pins the bytes so a refactor cannot change them by accident.
    #[test]
    fn device_message_envelope_matches_schema_v1() {
        let envelope = build_device_message_envelope(
            "did:web:alice.example",
            "device-aaaa-1111",
            "cx.key.verification.request",
            json!({
                "method": "sas",
                "transaction_id": "verify-001"
            }),
        );
        assert_eq!(
            envelope,
            json!({
                "messages": {
                    "did:web:alice.example": {
                        "device-aaaa-1111": {
                            "type": "cx.key.verification.request",
                            "content": {
                                "method": "sas",
                                "transaction_id": "verify-001"
                            }
                        }
                    }
                }
            }),
            "wire shape must remain `messages → actor → device_id → {{type, content}}`",
        );
    }

    /// R3 — empty content is still a valid envelope. `cx.key.verification.done`
    /// for example carries only a transaction id; the test ensures we don't
    /// require a populated content map.
    #[test]
    fn device_message_envelope_accepts_minimal_content() {
        let envelope = build_device_message_envelope(
            "did:web:bob.example",
            "device-bbbb-2222",
            "cx.key.verification.done",
            json!({"transaction_id": "verify-done-001"}),
        );
        let inner = &envelope["messages"]["did:web:bob.example"]["device-bbbb-2222"];
        assert_eq!(inner["type"], "cx.key.verification.done");
        assert_eq!(inner["content"]["transaction_id"], "verify-done-001");
    }
}
