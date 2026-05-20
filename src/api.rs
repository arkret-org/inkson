use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chime::{ContrixPushClient, RegisterDeviceRequest, UnregisterDeviceRequest};
use contrix_sdk::ErrorEnvelope;
use ed25519_dalek::Signer;
use reqwest::{
    Client, Method, StatusCode,
    header::{ACCEPT, HeaderMap, RETRY_AFTER},
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use url::Url;

use crate::hlc::{Hlc, next_seq};
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
    AccountDataSetOutcome, AccountRecoveryResponse, AccountResponse, AppletDescribeResBody,
    AppletPingResBody, AppletProtocolMetadataResponse, AppletQueryActorResponse,
    AppletQuerySpaceResponse, AppletTransactionResBody, ArchiveSpaceResponse, AuthzCheckResBody,
    BackfillResBody, BanMemberResponse, BlobUploadResBody, ClientSyncResponse, ContactResponse,
    ContactsResponse, DevLoginResponse, DeviceMessagesReceiveResBody, DeviceMessagesSendResBody,
    DeviceTrustResponse, DirectoryDescribeResBody, EffectiveGrantsResBody, EphemeralSubmitResponse,
    EventsDescribeResBody, FederationOperationsResponse, FederationSpaceMembersResBody,
    FederationTransactionResBody, FederationVerifyActorResBody, HealthResponse, IceConfigRequest,
    IceConfigResponse, IdentityDescribeResBody, IdentityLogResBody, IdentityReceiptsResBody,
    IdentityResolveResBody, IndexSearchResponse, InvitesResponse, KeysClaimResBody,
    KeysQueryResBody, KeysUploadResBody, LogoutResponse, MimiConsentResBody, MimiGroupInfoResBody,
    MimiIdentifierQueryResBody, MimiKeyMaterialResBody, MimiNotifyResBody,
    MimiProviderDirectoryResBody, MimiProxyDownloadResBody, MimiReportAbuseResBody,
    MimiRoomUpdateResBody, MimiSubmitMessageResBody, MlsEpochResponse, MlsRotateResponse,
    ModerationReportResBody, ModerationReportsResponse, ModerationResolveResponse,
    OidcAuthorizeResponse, OidcCallbackResponse, OkResBody, PasskeyChallengeResponse,
    PasskeyVerifyResponse, PolicyCheckResBody, PolicyResponse, PushRegisterResponse,
    ReceiptResponse, ResolveHandleResponse, ResolveSpaceResponse, RotateKeysResponse,
    SearchActorsResponse, SearchOrganizationsResponse, SearchSpacesResponse, ServerDescription,
    SignAnchorResponse, SnapshotHeadResponse, SpaceInviteResponse, SpaceLeaveResponse,
    SpaceLifecycleResponse, SpacePolicyResponse, SubmitAnchorResponse, SubmitDidOperationResBody,
    SubmitEventResponse, SubmitMoveResponse, SyncDescribeResBody, ThirdPartyLocationsResponse,
    ThirdPartyUsersResponse, TokenRefreshResponse, TypingResponse, UpdateProfileResponse,
    UpdateSpaceResponse, VerifyDeviceResponse,
};
use crate::operation::{
    EventEnvelope, OperationEnvelope, PLACEHOLDER_PROOF_JWS, ProofMode, current_proof_mode, uuid_v7,
};

/// T1.3 — pre-submit guard. Returns an error when the active
/// [`ProofMode`] enforces a real signer (Production / RealEd25519 /
/// ExternalSigner) but the envelope still carries the placeholder
/// `jws == "a..b"` (or no proof at all). Mirrors the soland-side
/// `dev_proof_in_production` rejection so the UI can surface a clear
/// local error before the round-trip.
fn guard_event_proof_against_production(event: &EventEnvelope) -> anyhow::Result<()> {
    let mode = current_proof_mode();
    if !mode.enforces_real_signer() {
        return Ok(());
    }
    let Some(proof) = event.proofs.first() else {
        return Err(anyhow::anyhow!(
            "Cannot send: no signer configured for this server (proof mode = {})",
            mode.label_en()
        ));
    };
    if proof.jws == PLACEHOLDER_PROOF_JWS || proof.jws.is_empty() {
        return Err(anyhow::anyhow!(
            "Cannot send: dev-mode placeholder proof rejected by production guard (proof mode = {})",
            mode.label_en()
        ));
    }
    // Production / real-signer modes require a fully signed proof. The
    // wire shape "a..b" is the placeholder used by `attach_placeholder_proof`;
    // a real Ed25519 JWS has three `.`-separated segments and a non-empty
    // signature tail (`<header>..<sig>` with sig length > 0).
    if !proof.jws.contains("..") || proof.jws.split("..").nth(1).is_none_or(str::is_empty) {
        return Err(anyhow::anyhow!(
            "Cannot send: proof jws is missing a real signature (proof mode = {})",
            mode.label_en()
        ));
    }
    let _ = ProofMode::PlaceholderDev; // keep the variant exposed in api.rs for downstream consumers.
    Ok(())
}

/// Generic wrapper for soland's
/// `/api/v1/projection/{places|flows}` lifecycle endpoints. Keeps the
/// query response shape symmetric across the two surfaces so the kanban
/// hydrate path can pluck `.places` / `.flows` with the same code.
#[derive(Clone, Debug, Deserialize)]
pub struct LifecycleProjectionResponse<T> {
    pub space_id: String,
    #[serde(default)]
    pub total: u32,
    #[serde(default = "Vec::new", alias = "places", alias = "flows")]
    pub items: Vec<T>,
}

/// Server-side Place row from `GET /api/v1/projection/places`. Only the
/// fields the kanban hydrate path actually consumes are typed; the rest
/// are tolerated via `#[serde(default)]` so future soland additions
/// don't break deserialization.
#[derive(Clone, Debug, Deserialize)]
pub struct PlaceProjectionView {
    pub place_id: String,
    pub space_id: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub title: String,
    /// `active` / `archived` / `tombstoned` per spec
    /// `common-fields.md §5.1`.
    pub state: String,
    #[serde(default)]
    pub rank: Option<String>,
    #[serde(default)]
    pub parent_ref: Option<String>,
}

/// Server-side Flow row from `GET /api/v1/projection/flows`.
#[derive(Clone, Debug, Deserialize)]
pub struct FlowProjectionView {
    pub flow_id: String,
    pub space_id: String,
    #[serde(default)]
    pub title: String,
    /// `active` / `archived` / `deleted` / `redacted` per spec
    /// `common-fields.md §5.1`. yougen folds the two terminal states
    /// into `FlowLifecycleState::Tombstoned`.
    pub state: String,
}

/// Server-side Morph row from
/// `GET /api/v1/projection/morphs`. Same enum as Flow per spec §5.1.
#[derive(Clone, Debug, Deserialize)]
pub struct MorphProjectionView {
    pub morph_id: String,
    pub space_id: String,
    #[serde(default)]
    pub morph_type: String,
    #[serde(default)]
    pub title: Option<String>,
    pub state: String,
}

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

/// True when the server has *definitively* told us the session is dead.
///
/// We require both:
///   - HTTP 401 Unauthorized, AND
///   - an explicit error envelope code that names session loss
///     (`auth_expired`, `M_UNKNOWN_TOKEN`, `invalid_token`, `token_expired`).
///
/// A bare 401 with no structured envelope is treated as a transient denial
/// — the caller should surface it to the user and let them retry rather
/// than wiping their session, persisted config, and bouncing them to the
/// sign-in page. The auto-retry layer in `send_with_retry` has already had
/// its shot before any error reaches the UI, so the residual 401 is most
/// often a reverse-proxy hiccup, a clock skew, or a server-side temp deny
/// — not a permanently dead token.
pub fn is_auth_expired_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<ContrixApiError>()
        .is_some_and(|api_error| {
            if api_error.status != StatusCode::UNAUTHORIZED {
                return false;
            }
            matches!(
                api_error.error.code(),
                "auth_expired"
                    | "unauthenticated"
                    | "soft_logged_out"
                    | "M_UNKNOWN_TOKEN"
                    | "invalid_token"
                    | "token_expired"
            )
        })
}

/// Recognise a `rate_limited` (HTTP 429) error envelope from the
/// server and return its advertised `retry_after_ms` so callers can
/// sleep for the server-suggested duration instead of the generic
/// exponential backoff. Wire constant is pulled from `contrix_sdk`
/// so a spec rename can't silently de-recognise the code.
///
/// Returns `Some(retry_after_ms)` on match (with 0 when the server
/// omitted the hint), `None` otherwise.
pub fn rate_limited_retry_after(error: &anyhow::Error) -> Option<u64> {
    use contrix_sdk::error::ERROR_CODE_RATE_LIMITED;
    let api_error = error.downcast_ref::<ContrixApiError>()?;
    if api_error.error.code() != ERROR_CODE_RATE_LIMITED {
        return None;
    }
    Some(api_error.error.retry_after_ms().unwrap_or(0))
}

/// `true` when `/sync` rejected the cursor — either expired, invalid,
/// or with an integrity mismatch — so the SyncEngine knows to demote to
/// a `since=None` full sync instead of looping on the same broken cursor.
///
/// Wire constants are pulled from `contrix_sdk` so renames in the spec
/// layer (e.g. round 4's `sync_token_expired` → `cursor_expired`) can't
/// silently de-recognise an error and surface a 410 to the UI.
pub fn is_invalid_cursor_error(error: &anyhow::Error) -> bool {
    use contrix_sdk::{
        ERROR_CODE_CURSOR_EXPIRED, ERROR_CODE_INVALID_PARAM, ERROR_CODE_SYNC_TOKEN_EXPIRED,
    };
    use contrix_sdk::error::ERROR_CODE_CURSOR_INTEGRITY_INVALID;
    error
        .downcast_ref::<ContrixApiError>()
        .is_some_and(|api_error| {
            let code = api_error.error.code();
            // `invalid_param` only counts when the message mentions the
            // cursor — soland uses it for generic schema rejections too.
            let cursor_message = api_error.error.message().to_lowercase().contains("cursor");
            matches!(
                code,
                code if code == ERROR_CODE_CURSOR_EXPIRED
                    || code == ERROR_CODE_SYNC_TOKEN_EXPIRED
                    || code == ERROR_CODE_CURSOR_INTEGRITY_INVALID
            ) || (cursor_message
                && matches!(code, code if code == ERROR_CODE_INVALID_PARAM || code == "invalid_cursor"))
        })
}

pub fn is_plaintext_visibility_policy_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<ContrixApiError>()
        .is_some_and(|api_error| {
            api_error.status == StatusCode::FORBIDDEN
                && api_error.error.code() == "policy_denied"
                && api_error
                    .error
                    .message()
                    .contains("plaintext_visible_services")
        })
}

pub fn normalize_wait_for_sync_token(sync_token: &str) -> Option<String> {
    let sync_token = sync_token.trim();
    if sync_token.is_empty() || sync_token == "-" {
        return None;
    }
    sync_token
        .split(',')
        .all(|candidate| {
            let Some(timestamp_ms) = candidate.trim().strip_prefix("sx:") else {
                return false;
            };
            !timestamp_ms.is_empty() && timestamp_ms.chars().all(|ch| ch.is_ascii_digit())
        })
        .then(|| sync_token.to_owned())
}

/// Typed error class for the `post_audit_user_action` path.
/// Distinguishes "endpoint isn't wired yet" (404 - caller should
/// re-buffer the entry) from "server said no" (every other error -
/// drop and move on). Pulled out so callers can branch without
/// parsing `anyhow::Error` strings.
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
        self.wait_for_sync_token = normalize_wait_for_sync_token(&sync_token);
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
        Ok(self.base_url.join(path.trim().trim_start_matches('/'))?)
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

    /// A4b — update the authenticated principal's public profile
    /// (display_name / bio / avatar_url). Mirrors soland's
    /// `cx.account.update_profile` wire shape: each field is
    /// `Option<String>`; `None` leaves the field untouched server-side,
    /// `Some("")` explicitly clears it. The server normalises empty
    /// strings to `None` on write.
    ///
    /// `avatar_url` MUST be either an `http://` / `https://` URL or
    /// empty — soland rejects other shapes with `invalid_avatar_url`.
    /// To publish a yougen-uploaded blob, the caller constructs the
    /// download URL via [`Self::blob_download_url`] before passing it
    /// here.
    pub async fn update_profile(
        &self,
        display_name: Option<&str>,
        bio: Option<&str>,
        avatar_url: Option<&str>,
    ) -> anyhow::Result<UpdateProfileResponse> {
        self.post_json(
            "api/v1/account/profile",
            json!({
                "display_name": display_name,
                "bio": bio,
                "avatar_url": avatar_url,
            }),
        )
        .await
    }

    /// A4b — resolve a `cx:blob:sha256:<hex>` reference to its
    /// authenticated download URL on this Principal Server. Returns the
    /// `<base>/api/v1/blob/get?blob_ref=<…>` shape that soland's
    /// `/blob/get` handler answers — callers can plug this directly
    /// into `<img src=…>` or `cx.account.update_profile { avatar_url }`.
    pub fn blob_download_url(&self, blob_ref: &str) -> String {
        blob_download_url_for(self.base_url.as_str(), blob_ref)
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

    pub async fn logout(&self) -> anyhow::Result<LogoutResponse> {
        self.post_json("api/v1/auth/logout", json!({})).await
    }

    /// Build + submit the canonical `cx.realm.create` event bundle.
    ///
    /// Per spec `models/realm-and-space.md §2.3`, the create event locks
    /// in `encryption_profile` (`none` / `mls_rfc9420` / `external`),
    /// `security_class` (`standard` / `high_assurance`),
    /// `federation_policy` (`open` / `restricted` / `closed` /
    /// `quarantine`), `anchor_profile` (`single_did` / `threshold` /
    /// `open_set` / `mixed`) and `hash_profile` (`sha256` / `sha512` /
    /// `sha3_256` / `blake3`). The caller MUST surface these as user
    /// choices because none of them can be changed after create.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_realm(
        &self,
        actor_id: &str,
        title: &str,
        summary: Option<&str>,
        discoverability: &str,
        join_rule: &str,
        history_visibility: &str,
        encryption_profile: &str,
        security_class: &str,
        federation_policy: &str,
        anchor_profile: &str,
        hash_profile: &str,
        invitees: Vec<String>,
        plaintext_visible_services: Vec<String>,
    ) -> anyhow::Result<SpaceLifecycleResponse> {
        let actor_id = actor_id.trim();
        if actor_id.is_empty() {
            return Err(anyhow::anyhow!(
                "actor_id is required for canonical cx.realm.create"
            ));
        }
        let title = title.trim();
        if title.is_empty() {
            return Err(anyhow::anyhow!("title is required for cx.realm.create"));
        }

        // R1.7: the security boundary (formerly Space) is now Realm.
        // TODO(realm-rework): switch local prefix to `cx:realm:` once
        // contrix-sdk's SpaceId validator and soland accept the new shape.
        let space_id = format!("cx:space:{}", uuid_v7());
        let join_rule = canonical_space_join_rule_v1(join_rule);
        let events = build_realm_bootstrap_events(
            &space_id,
            actor_id,
            title,
            summary,
            discoverability,
            join_rule,
            history_visibility,
            encryption_profile,
            security_class,
            federation_policy,
            anchor_profile,
            hash_profile,
            &invitees,
            &plaintext_visible_services,
        )?;
        for event in events {
            self.submit_event(&event).await?;
        }

        let mut members = Vec::new();
        if !actor_id.is_empty() {
            members.push(actor_id.to_owned());
        }
        for invitee in invitees {
            let invitee = invitee.trim();
            if !invitee.is_empty() && !members.iter().any(|member| member == invitee) {
                members.push(invitee.to_owned());
            }
        }

        Ok(SpaceLifecycleResponse {
            ok: true,
            space_id,
            owner: actor_id.to_owned(),
            members,
            deleted: false,
        })
    }

    /// Create a Space (product-structure container) inside an existing
    /// Realm. Emits `cx.space.create` per spec realm-and-space.md §3.
    /// Unlike `create_realm`, this does NOT bootstrap MLS / membership
    /// / federation — those live on the Realm and Space inherits them.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_space_under_realm(
        &self,
        realm_id: &str,
        actor_id: &str,
        title: &str,
        summary: Option<&str>,
        kind: &str,
        parent_space_id: Option<&str>,
        default_realm_ref: Option<&str>,
    ) -> anyhow::Result<SpaceLifecycleResponse> {
        let actor_id = actor_id.trim();
        if actor_id.is_empty() {
            return Err(anyhow::anyhow!(
                "actor_id is required for cx.space.create"
            ));
        }
        let title = title.trim();
        if title.is_empty() {
            return Err(anyhow::anyhow!("title is required for cx.space.create"));
        }
        let realm_id = realm_id.trim();
        if realm_id.is_empty() {
            return Err(anyhow::anyhow!(
                "realm_id is required for cx.space.create — Space must live inside a Realm"
            ));
        }
        let space_id = format!("cx:space:{}", uuid_v7());
        let event = build_space_create_event(
            &space_id,
            realm_id,
            actor_id,
            title,
            summary,
            kind,
            parent_space_id,
            default_realm_ref,
        )?;
        self.submit_event(&event).await?;

        Ok(SpaceLifecycleResponse {
            ok: true,
            space_id,
            owner: actor_id.to_owned(),
            members: vec![actor_id.to_owned()],
            deleted: false,
        })
    }

    /// Send a Space lifecycle action (`archive` / `restore` /
    /// `tombstone`) per spec realm-and-space.md §3.4. Caller MUST
    /// pass the home Realm id — the event is authorized + written
    /// inside that Realm. Server validates the state-machine
    /// (active → archived → active, any → tombstoned) and rejects
    /// invalid transitions with `space_not_active` /
    /// `space_not_archived` / `space_already_terminal`.
    pub async fn change_space_lifecycle(
        &self,
        space_id: &str,
        realm_id: &str,
        actor_id: &str,
        kind: &str,
    ) -> anyhow::Result<()> {
        let actor_id = actor_id.trim();
        let space_id = space_id.trim();
        let realm_id = realm_id.trim();
        if actor_id.is_empty() || space_id.is_empty() || realm_id.is_empty() {
            return Err(anyhow::anyhow!(
                "actor_id, space_id and realm_id are all required for {kind}"
            ));
        }
        let event = build_space_lifecycle_event(space_id, realm_id, actor_id, kind)?;
        self.submit_event(&event).await?;
        Ok(())
    }

    pub async fn get_space(&self, space_id: &str) -> anyhow::Result<SpaceLifecycleResponse> {
        self.get_json(&format!("api/v1/spaces/{space_id}")).await
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

    // Move/Anchor pipeline — the protocol-canonical write path for
    // cell-driven state changes (consent, capability, member state,
    // anchorer cell, MLS epoch, etc.). Non-cell writes use
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

    /// PUT a per-account `cx.account_data.set` entry. Thin wrapper around
    /// `PUT /api/v1/account_data/{type}` so settings UIs can push preferences
    /// (e.g. `cx.read_receipt.preferences`) up to soland for cross-device
    /// sync. When the endpoint returns 404 / 501 / 405 we treat the outcome
    /// as `Unsupported` and let the caller swallow it (local state stays
    /// authoritative). Anything else surfaces as `Err`.
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

    /// DELETE an account_data entry. Same graceful-degradation contract as
    /// [`Self::set_account_data`] — 404 means the row was already absent
    /// (treated as success) and is logged at debug level; other errors
    /// propagate.
    pub async fn delete_account_data(&self, type_key: &str) -> anyhow::Result<()> {
        let path = format!("api/v1/account_data/{type_key}");
        let result: anyhow::Result<Value> = self.delete_json(&path).await;
        match result {
            Ok(_) => Ok(()),
            Err(error) => {
                if let Some(api_error) = error.downcast_ref::<ContrixApiError>() {
                    if matches!(
                        api_error.status,
                        StatusCode::NOT_FOUND
                            | StatusCode::NOT_IMPLEMENTED
                            | StatusCode::METHOD_NOT_ALLOWED
                    ) {
                        return Ok(());
                    }
                }
                Err(error)
            }
        }
    }

    pub async fn identity_describe(&self) -> anyhow::Result<IdentityDescribeResBody> {
        self.get_json("api/v1/identity/describe").await
    }

    pub async fn identity_resolve(&self, did: &str) -> anyhow::Result<IdentityResolveResBody> {
        self.post_json(
            "api/v1/identity/resolve",
            json!({"did": did, "include": []}),
        )
        .await
    }

    pub async fn sync_describe(&self) -> anyhow::Result<SyncDescribeResBody> {
        self.get_json("api/v1/sync/describe").await
    }

    pub async fn sync(&self, since: Option<&str>) -> anyhow::Result<ClientSyncResponse> {
        self.sync_with_timeout(since, 0).await
    }

    /// `/sync` with an explicit long-poll timeout. `timeout_ms == 0` makes
    /// soland reply immediately with whatever it has cached for the
    /// cursor; non-zero values are honoured as the upper bound the
    /// server will hold the request open waiting for new events. The
    /// `SyncEngine` background task uses ~30s for the streaming-style
    /// loop and 0 for the boot bootstrap that just wants the current
    /// snapshot.
    pub async fn sync_with_timeout(
        &self,
        since: Option<&str>,
        timeout_ms: u64,
    ) -> anyhow::Result<ClientSyncResponse> {
        self.post_json(
            "api/v1/sync",
            json!({"since": since, "timeout_ms": timeout_ms, "set_presence": "online"}),
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

    pub async fn directory_describe(&self) -> anyhow::Result<DirectoryDescribeResBody> {
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
    pub async fn backfill(&self, space_id: &str) -> anyhow::Result<BackfillResBody> {
        self.get_json(&events_query_path(space_id)).await
    }

    /// Stream the canonical `/api/v1/events/subscribe` NDJSON response and
    /// invoke `on_frame` once per parsed frame.
    ///
    /// Round 4 (spec a77b995) — the parser is now typed against
    /// [`contrix_sdk::EventsSubscribeFrameBody`] (the `tag = "kind"`,
    /// snake_case-discriminated frame body). Callers MUST route on the
    /// canonical variants: `Dropped { cursor }` → resume from `cursor`,
    /// `ResyncRequired` → full resync, `EpochRotation { epoch }` →
    /// refresh session keys. The pre-round-4 untyped string-line
    /// parser is wire-broken.
    ///
    /// Native-only: reqwest's wasm32 backend goes through the browser fetch
    /// API and does not expose `Response::chunk()` / `bytes_stream()`. A wasm
    /// subscription path needs a separate web-sys ReadableStream-based
    /// implementation (not wired up yet — no callers).
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn events_subscribe_ndjson<F>(
        &self,
        space_id: &str,
        after: Option<&str>,
        include_history: Option<bool>,
        mut on_frame: F,
    ) -> anyhow::Result<()>
    where
        F: FnMut(contrix_sdk::EventsSubscribeFrameBody) -> anyhow::Result<()>,
    {
        let request = self
            .http
            .get(self.endpoint(&events_subscribe_path(space_id, after, include_history))?)
            .header(ACCEPT, "application/x-ndjson");
        let mut response = self
            .send_with_retry(self.prepare_request(request), Method::GET, true)
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

        let mut pending = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            pending.extend_from_slice(&chunk);
            drain_events_subscribe_ndjson_lines(&mut pending, &mut on_frame)?;
        }

        if let Some(frame) = parse_events_subscribe_ndjson_line(&pending)? {
            on_frame(frame)?;
        }
        Ok(())
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
    ) -> anyhow::Result<AuthzCheckResBody> {
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

    pub async fn effective_grants(&self, subject: &str) -> anyhow::Result<EffectiveGrantsResBody> {
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

    pub async fn unregister_push_device(&self, device_id: &str) -> anyhow::Result<OkResBody> {
        let request = crate::push::build_unregister_request(device_id, None)?;
        self.unregister_push_device_with_request(&request).await
    }

    pub async fn unregister_push_device_with_request(
        &self,
        request: &UnregisterDeviceRequest,
    ) -> anyhow::Result<OkResBody> {
        let response = self
            .push_client(None, None)
            .unregister_device_with_request(request, request.idempotency_key.as_deref(), None)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(OkResBody {
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

    pub async fn upload_keys(&self, device_id: &str) -> anyhow::Result<KeysUploadResBody> {
        self.ensure_demo_crypto_fallback_allowed("keys/upload demo device_signature")?;
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
    ) -> anyhow::Result<KeysClaimResBody> {
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
    ) -> anyhow::Result<KeysQueryResBody> {
        self.post_json(
            "api/v1/keys/query",
            json!({"device_keys": {actor: [device_id]}}),
        )
        .await
    }

    /// Publish an MLS `MlsKeyPackageRecord` to
    /// soland's `/api/v1/keys/upload` endpoint so peers can fetch it via
    /// `query_keys` and `add_member()` against it. Other key fields
    /// (one_time_keys / fallback_keys / device_signature) carry their
    /// default-test shape; soland tolerates them being placeholder when
    /// the only consumer is the MLS Welcome flow.
    pub async fn publish_mls_key_package(
        &self,
        device_id: &str,
        record: &contrix_sdk::MlsKeyPackageRecord,
    ) -> anyhow::Result<KeysUploadResBody> {
        self.ensure_demo_crypto_fallback_allowed("keys/upload MLS demo device_signature")?;
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
                "device_signature": {"alg": "EdDSA", "signature": "yougen-dev-signature"},
                "mls_key_packages": {
                    record.keypackage_id.clone(): serde_json::to_value(record)?,
                },
            }),
        )
        .await
    }

    /// Fetch a peer's MLS key package via
    /// `query_keys`, decoding the most recent `mls_key_packages` entry
    /// into a typed `MlsKeyPackageRecord`. Returns `Ok(None)` when the
    /// device exists but has no MLS key package on file (in which case
    /// the caller should fall back to a non-MLS path or ask the peer to
    /// publish).
    pub async fn fetch_mls_key_package(
        &self,
        actor: &str,
        device_id: &str,
    ) -> anyhow::Result<Option<contrix_sdk::MlsKeyPackageRecord>> {
        let resp = self.query_keys(actor, device_id).await?;
        let device_keys = &resp.device_keys;
        let packages = device_keys
            .get(actor)
            .and_then(|actor_map| actor_map.get(device_id))
            .and_then(|device_value| device_value.get("mls_key_packages"));
        let Some(packages) = packages else {
            return Ok(None);
        };
        let map = match packages.as_object() {
            Some(m) => m,
            None => return Ok(None),
        };
        let Some((_, value)) = map.iter().next() else {
            return Ok(None);
        };
        let record: contrix_sdk::MlsKeyPackageRecord = serde_json::from_value(value.clone())?;
        Ok(Some(record))
    }

    pub async fn send_to_device(
        &self,
        actor: &str,
        device_id: &str,
    ) -> anyhow::Result<DeviceMessagesSendResBody> {
        self.ensure_demo_crypto_fallback_allowed("device_messages opaque test ciphertext")?;
        self.send_device_message_envelope(
            "yougen-txn-1",
            actor,
            device_id,
            "cx.mls.test",
            json!({"ciphertext": "opaque-yougen-test"}),
        )
        .await
    }

    fn ensure_demo_crypto_fallback_allowed(&self, label: &str) -> anyhow::Result<()> {
        if std::env::var("YOUGEN_ALLOW_DEMO_CRYPTO_FALLBACK")
            .ok()
            .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        {
            return Ok(());
        }
        if matches!(
            self.base_url.host_str().unwrap_or_default(),
            "localhost" | "127.0.0.1" | "::1" | "local.host"
        ) {
            return Ok(());
        }
        anyhow::bail!("{label} is disabled for non-local production servers")
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
    ) -> anyhow::Result<DeviceMessagesSendResBody> {
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

    pub async fn receive_device_messages(&self) -> anyhow::Result<DeviceMessagesReceiveResBody> {
        self.get_json("api/v1/device_messages").await
    }

    pub async fn put_key_backup(
        &self,
        backup_id: &str,
        payload: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        crate::key_backup::validate_key_backup_put_request(backup_id, &payload)
            .map_err(|err| anyhow::anyhow!("invalid key backup envelope: {err}"))?;
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

    /// Round 4 (spec a77b995) — request a presigned blob upload URL
    /// scoped to a Realm. The pre-round-4 omission of `realm_id` is
    /// wire-broken: Realm-owned blobs MUST carry `realm_id` so the
    /// server can bind the resulting blob_ref into the originating
    /// Realm's resource quota / legal-hold scope. Returns the
    /// server-issued envelope verbatim (URL, blob_ref, expires_at,
    /// headers) for the caller to PUT against.
    pub async fn blob_presign(
        &self,
        realm_id: &str,
        content_type: &str,
        content_length: u64,
    ) -> anyhow::Result<Value> {
        let realm = contrix_sdk::RealmId::new(realm_id)
            .map_err(|err| anyhow::anyhow!("invalid realm_id for /blob/presign: {err}"))?;
        self.post_json(
            "api/v1/blob/presign",
            json!({
                "realm_id": realm.as_str(),
                "content_type": content_type,
                "content_length": content_length,
            }),
        )
        .await
    }

    pub async fn upload_blob(&self, bytes: &'static [u8]) -> anyhow::Result<BlobUploadResBody> {
        let request = self
            .http
            .post(self.endpoint("api/v1/blob/upload")?)
            .header("content-type", "application/octet-stream")
            .body(bytes);
        self.send_json(self.prepare_request(request), Method::POST)
            .await
    }

    /// Owned-bytes variant of [`upload_blob`] used by the composer
    /// drag-drop path (A6.2). The drop event yields `Vec<u8>` from
    /// the browser File API which cannot satisfy the `'static`
    /// bound that the original method requires for fixture
    /// attachments.
    pub async fn upload_blob_bytes(
        &self,
        bytes: Vec<u8>,
        content_type: &str,
    ) -> anyhow::Result<BlobUploadResBody> {
        let content_type = if content_type.trim().is_empty() {
            "application/octet-stream"
        } else {
            content_type
        };
        let request = self
            .http
            .post(self.endpoint("api/v1/blob/upload")?)
            .header("content-type", content_type)
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
    ) -> anyhow::Result<ModerationReportResBody> {
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

    /// Ship a single client-side telemetry entry to
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

    /// A6.1 — global cross-space message search backed by soland's
    /// `POST /api/v1/index/search`. The server accepts `space_ids` to
    /// scope the search; pass an empty slice for "search everywhere I
    /// have access to". `object_kinds` defaults to `["message"]` when
    /// `None`, mirroring the panel's primary affordance.
    ///
    /// Note: soland's current index is best-effort substring search
    /// over the in-memory projection; encrypted messages are skipped
    /// server-side. Cross-space coverage will improve as the durable
    /// projection lands (see `_claude_todos.md` D-lane).
    pub async fn index_search(
        &self,
        query: &str,
        space_ids: &[String],
        object_kinds: Option<&[&str]>,
        limit: u32,
    ) -> anyhow::Result<IndexSearchResponse> {
        let kinds: Vec<&str> = object_kinds
            .map(|k| k.to_vec())
            .unwrap_or_else(|| vec!["message"]);
        let body = json!({
            "query": query,
            "limit": limit,
            "object_kinds": kinds,
            "space_ids": space_ids,
        });
        self.post_json("api/v1/index/search", body).await
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

    pub async fn set_space_policy_events(
        &self,
        space_id: &str,
        actor_id: &str,
        join_rule: &str,
        history_visibility: &str,
    ) -> anyhow::Result<SpacePolicyResponse> {
        let actor_id = actor_id.trim();
        if actor_id.is_empty() {
            return Err(anyhow::anyhow!(
                "actor_id is required for canonical Space policy events"
            ));
        }
        let join_rule = canonical_space_join_rule_v1(join_rule);
        for event in [
            build_space_state_event(space_id, actor_id, "cx.realm.join_rule", json!(join_rule))?,
            build_space_state_event(
                space_id,
                actor_id,
                "cx.realm.history_visibility",
                json!(history_visibility),
            )?,
        ] {
            self.submit_event(&event).await?;
        }
        Ok(SpacePolicyResponse {
            ok: true,
            space_id: space_id.to_owned(),
            join_rule: join_rule.to_owned(),
            history_visibility: history_visibility.to_owned(),
        })
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

    /// Round R2/R3 (T02) — typing notifications are wire-scope-ephemeral
    /// (`cx.typing`). They MUST flow through the broadcast ephemeral channel,
    /// NOT through `cx.events.submit`. The REST `POST /api/v1/typing` shim
    /// is retained for transports that don't yet expose the dedicated
    /// ephemeral fanout (TODO(round23-T02): collapse to a single transport
    /// once soland exposes it). The body is shaped as an
    /// `EphemeralEnvelope` so the server can dispatch directly.
    pub async fn send_typing(
        &self,
        space_id: &str,
        actor: &str,
        device_id: Option<&str>,
        typing: bool,
    ) -> anyhow::Result<TypingResponse> {
        let envelope = build_typing_envelope(space_id, actor, device_id, typing)?;
        // Best-effort: route via the broadcast ephemeral channel first.
        // If the server does not yet expose that endpoint, fall through
        // to the typing-specific shim — but never to `cx.events.submit`.
        // TODO(round23-T02): drop the legacy shim once soland exposes the
        // dedicated ephemeral channel on every deployment.
        match self.submit_ephemeral_envelope(&envelope).await {
            Ok(_) => Ok(TypingResponse { ok: true }),
            Err(error) => {
                tracing::debug!(
                    target: "yougen::ephemeral",
                    %error,
                    "broadcast ephemeral channel unavailable for cx.typing; using transport shim"
                );
                self.post_json(
                    "api/v1/typing",
                    json!({"space_id": space_id, "typing": typing}),
                )
                .await
            }
        }
    }

    /// Round R2/R3 (T02) — read receipts (`cx.receipt.read`) are wire-scope-
    /// ephemeral. They MUST flow through the broadcast ephemeral channel.
    /// The REST shim is retained as a transport fallback only; the
    /// `cx.events.submit` durable path MUST NOT be used.
    pub async fn send_receipt(
        &self,
        space_id: &str,
        event_id: &str,
        receipt_type: &str,
    ) -> anyhow::Result<ReceiptResponse> {
        // Only `cx.receipt.read` is an ephemeral receipt; other receipt
        // types (delivered/franking/etc.) stay on their own paths. Guard
        // the kind here so we don't accidentally widen the contract.
        if receipt_type == "cx.receipt.read" {
            let actor_did = event_id.to_owned(); // server fills the actor from the bearer token; payload only needs the event_id reference
            let envelope = build_receipt_read_envelope(space_id, &actor_did, event_id)?;
            if self.submit_ephemeral_envelope(&envelope).await.is_ok() {
                return Ok(ReceiptResponse { ok: true });
            }
            tracing::debug!(
                target: "yougen::ephemeral",
                "broadcast ephemeral channel unavailable for cx.receipt.read; using transport shim"
            );
        }
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
    // CollectionProjectionResBody defined in contrix_core::model.
    pub async fn collection_projection(
        &self,
        view_id: &str,
    ) -> anyhow::Result<contrix_sdk::CollectionProjectionResBody> {
        self.post_json(&format!("api/v1/views/{view_id}/projection"), json!({}))
            .await
    }

    // Pull the canonical Place / Flow lifecycle state for a Space so the
    // kanban view can hydrate `column.state` / `card.lifecycle` after a
    // refresh. Pairs with soland's `routing::events::projection_query`.
    pub async fn list_place_projections(
        &self,
        space_id: &str,
    ) -> anyhow::Result<LifecycleProjectionResponse<PlaceProjectionView>> {
        // `cx:space:<uuid>` is RFC-3986-safe in query string position
        // (colon + hyphen + alpha-digit), so no percent-encoding needed.
        let path = format!("api/v1/projection/places?space_id={space_id}");
        self.get_json(&path).await
    }

    pub async fn list_flow_projections(
        &self,
        space_id: &str,
    ) -> anyhow::Result<LifecycleProjectionResponse<FlowProjectionView>> {
        let path = format!("api/v1/projection/flows?space_id={space_id}");
        self.get_json(&path).await
    }

    /// Parity with `list_place_projections` / `list_flow_projections`
    /// for the morphs read-side endpoint, so future morph-aware views can
    /// hydrate post-refresh state.
    pub async fn list_morph_projections(
        &self,
        space_id: &str,
    ) -> anyhow::Result<LifecycleProjectionResponse<MorphProjectionView>> {
        let path = format!("api/v1/projection/morphs?space_id={space_id}");
        self.get_json(&path).await
    }

    // ── Device & Crypto ─────────────────────────────────────────────

    pub async fn revoke_device(&self, device_id: &str) -> anyhow::Result<OkResBody> {
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
        ensure_device_verification_proof_is_signed(&proof)?;
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
    ) -> anyhow::Result<FederationTransactionResBody> {
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
    ) -> anyhow::Result<FederationTransactionResBody> {
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
    ) -> anyhow::Result<FederationSpaceMembersResBody> {
        self.get_json(&format!(
            "api/v1/federation/space-members?space_id={space_id}"
        ))
        .await
    }

    pub async fn federation_verify_actor(
        &self,
        actor: &str,
        space_id: &str,
    ) -> anyhow::Result<FederationVerifyActorResBody> {
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
    ) -> anyhow::Result<PolicyCheckResBody> {
        self.post_json(
            "api/v1/policy/check",
            json!({"actor": actor, "action": action, "resource": resource}),
        )
        .await
    }

    // ── MIMI Provider Facade ─────────────────────────────────────

    pub async fn mimi_provider_directory(&self) -> anyhow::Result<MimiProviderDirectoryResBody> {
        self.get_json("api/v1/mimi/provider-directory").await
    }

    pub async fn mimi_key_material(
        &self,
        request: Value,
    ) -> anyhow::Result<MimiKeyMaterialResBody> {
        self.post_json("api/v1/mimi/key-material", request).await
    }

    pub async fn mimi_room_update(
        &self,
        room_id: &str,
        request: Value,
    ) -> anyhow::Result<MimiRoomUpdateResBody> {
        self.put_json(&format!("api/v1/mimi/rooms/{room_id}/update"), request)
            .await
    }

    pub async fn mimi_notify(
        &self,
        room_id: &str,
        request: Value,
    ) -> anyhow::Result<MimiNotifyResBody> {
        self.post_json(&format!("api/v1/mimi/rooms/{room_id}/notify"), request)
            .await
    }

    pub async fn mimi_submit_message(
        &self,
        room_id: &str,
        request: Value,
    ) -> anyhow::Result<MimiSubmitMessageResBody> {
        self.post_json(&format!("api/v1/mimi/rooms/{room_id}/messages"), request)
            .await
    }

    pub async fn mimi_group_info(&self, room_id: &str) -> anyhow::Result<MimiGroupInfoResBody> {
        self.get_json(&format!("api/v1/mimi/rooms/{room_id}/group-info"))
            .await
    }

    pub async fn mimi_request_consent(&self, request: Value) -> anyhow::Result<MimiConsentResBody> {
        self.post_json("api/v1/mimi/consent/request", request).await
    }

    pub async fn mimi_update_consent(&self, request: Value) -> anyhow::Result<MimiConsentResBody> {
        self.post_json("api/v1/mimi/consent/update", request).await
    }

    pub async fn mimi_identifier_query(
        &self,
        request: Value,
    ) -> anyhow::Result<MimiIdentifierQueryResBody> {
        self.post_json("api/v1/mimi/identifiers/query", request)
            .await
    }

    pub async fn mimi_report_abuse(
        &self,
        request: Value,
    ) -> anyhow::Result<MimiReportAbuseResBody> {
        self.post_json("api/v1/mimi/report-abuse", request).await
    }

    pub async fn mimi_proxy_download(
        &self,
        request: Value,
    ) -> anyhow::Result<MimiProxyDownloadResBody> {
        self.post_json("api/v1/mimi/proxy-download", request).await
    }

    // ── Applet ──────────────────────────────────────────────────────

    pub async fn applet_ping(&self, applet_did: &str) -> anyhow::Result<AppletPingResBody> {
        self.post_json("api/v1/applet/ping", json!({"applet_did": applet_did}))
            .await
    }

    pub async fn applet_describe(&self, applet_did: &str) -> anyhow::Result<AppletDescribeResBody> {
        self.get_json(&format!("api/v1/applet/describe?applet_did={applet_did}"))
            .await
    }

    pub async fn applet_transaction(
        &self,
        applet_did: &str,
        operations: Vec<Value>,
    ) -> anyhow::Result<AppletTransactionResBody> {
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
    ) -> anyhow::Result<IdentityLogResBody> {
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
    ) -> anyhow::Result<SubmitDidOperationResBody> {
        self.post_json(
            "api/v1/identity/submit-did-operation",
            json!({"did": did, "operation": operation}),
        )
        .await
    }

    /// Round 4 (spec a77b995) — `GET /api/v1/events/frontier` as the
    /// `account_client` variant. Wire-breaking: the round-4
    /// `account_client` variant carries `peer_role`, `frontier`,
    /// `actor_seq_upper_bounds` ONLY — it does NOT include
    /// `frontier_root`, transport signatures, or receipts. Those moved
    /// to the `federation_peer` variant which is S2S-only and clients
    /// MUST NEVER consume.
    ///
    /// The caller MUST pre-confirm that the route is signed-in (the
    /// account-client variant is gated on the principal session token).
    /// Anonymous-health probes go through a separate route.
    pub async fn events_frontier_account_client(
        &self,
    ) -> anyhow::Result<contrix_sdk::EventsFrontierAccountClientResponse> {
        let body: Value = self.get_json("api/v1/events/frontier").await?;
        let frontier: contrix_sdk::EventsFrontierAccountClientResponse =
            serde_json::from_value(body).map_err(|err| {
                anyhow::anyhow!(
                    "events/frontier account_client decode failed (round 4 wire shape): {err}"
                )
            })?;
        if !matches!(
            frontier.peer_role,
            contrix_sdk::FrontierPeerRole::AccountClient
        ) {
            anyhow::bail!(
                "events/frontier peer_role {:?} is not account_client (federation_peer / \
                 anonymous_health are off-limits to clients)",
                frontier.peer_role
            );
        }
        Ok(frontier)
    }

    pub async fn events_describe(&self) -> anyhow::Result<EventsDescribeResBody> {
        self.get_json("api/v1/events/describe").await
    }

    async fn submit_event(&self, event: &Value) -> anyhow::Result<SubmitEventResponse> {
        let idempotency_key = event
            .get("unsigned")
            .and_then(|value| value.get("local_operation_idempotency_alias"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(uuid_v7);
        let request = self.http.post(self.endpoint("api/v1/events")?).json(event);
        let request = self.with_write_request_headers(request, &idempotency_key);
        self.send_json_retryable(self.prepare_request(request), Method::POST)
            .await
    }

    pub async fn submit_event_envelope(
        &self,
        event: &EventEnvelope,
    ) -> anyhow::Result<SubmitEventResponse> {
        // T1.3 — production proof guard. When the runtime
        // [`current_proof_mode`] is anything other than
        // [`ProofMode::PlaceholderDev`], we must not ship envelopes
        // whose proof is the dev placeholder. Soland production rejects
        // them with `dev_proof_in_production` / `invalid_proof`, but
        // failing closed here gives the UI a clear local error instead
        // of a network round-trip that exposes the dev origin.
        //
        // T5.2 — when the active proof mode demands a real signer and
        // the envelope was built unsigned (the
        // `RealEd25519`/`ExternalSigner` branches in
        // `OperationBuilder::build` deliberately skip the placeholder
        // attach), reach into the process-wide `event_signer` registry
        // and sign in place before the guard runs. Callers that prefer
        // explicit signing can call `event_signer::sign_with_active`
        // directly before submit; this path is just the lazy fallback
        // so the dozens of UI call sites that currently
        // `submit_event_envelope(&op)` without an inline sign call keep
        // working.
        let mut signed = event.clone();
        if crate::event_signer::should_auto_sign()
            && signed
                .proofs
                .first()
                .is_none_or(|proof| proof.jws == PLACEHOLDER_PROOF_JWS || proof.jws.is_empty())
        {
            crate::event_signer::sign_with_active(&mut signed)
                .map_err(|err| anyhow::anyhow!("active signer rejected envelope: {err}"))?;
        }
        guard_event_proof_against_production(&signed)?;
        let value = serde_json::to_value(&signed)?;
        self.submit_event(&value).await
    }

    #[deprecated(note = "legacy adapter only; active writes must use submit_event_envelope")]
    pub async fn submit_operation_event(
        &self,
        operation: &OperationEnvelope,
    ) -> anyhow::Result<SubmitEventResponse> {
        let event = EventEnvelope::from_legacy_operation(operation)?;
        self.submit_event_envelope(&event).await
    }

    /// Round 4 (spec a77b995) — `POST /api/v1/events/submit` carrying
    /// the batch shape ([`contrix_sdk::EventsSubmitBatchRequest`]).
    /// Clients pick this when they have multiple ready envelopes (e.g.
    /// composer sends a draft + a read receipt at once); the federation
    /// shape ([`contrix_sdk::EventsSubmitFederationRequest`]) is S2S
    /// only and yougen MUST NEVER serialise it.
    pub async fn submit_events_batch(
        &self,
        envelopes: &[Value],
        idempotency_key: Option<&str>,
    ) -> anyhow::Result<Value> {
        let body = contrix_sdk::EventsSubmitBatchRequest {
            envelopes: envelopes.to_vec(),
            idempotency_key: idempotency_key.map(ToOwned::to_owned),
        };
        let value = serde_json::to_value(&body)?;
        let request = self
            .http
            .post(self.endpoint("api/v1/events/submit")?)
            .json(&value);
        let idem = idempotency_key
            .map(ToOwned::to_owned)
            .unwrap_or_else(uuid_v7);
        let request = self.with_write_request_headers(request, &idem);
        self.send_json_retryable(self.prepare_request(request), Method::POST)
            .await
    }

    /// Round R2/R3 (T02) — POST a broadcast ephemeral signal to the
    /// dedicated ephemeral channel (`POST /api/v1/ephemeral`) instead of the
    /// durable `/api/v1/events` endpoint. The envelope MUST validate against
    /// `cx.schema.ephemeral_envelope.v1` (kind in
    /// {`cx.call.signal`, `cx.presence`, `cx.typing`, `cx.receipt.read`}, and
    /// `expires_at - sent_at <= 300_000` ms). The four broadcast ephemeral
    /// signal kinds MUST NOT travel via `cx.events.submit`; this method is
    /// the single approved network path.
    ///
    /// TODO(round23-T02): once soland exposes a transport-specific ephemeral
    /// channel (sync subscribe live stream / presence fanout), wire this to
    /// that endpoint. For now we POST to `api/v1/ephemeral` and fail fast
    /// rather than fall back to `cx.events.submit`.
    pub async fn submit_ephemeral_envelope(
        &self,
        envelope: &contrix_sdk::EphemeralEnvelope,
    ) -> anyhow::Result<EphemeralSubmitResponse> {
        // Defensive re-validation. The constructor already enforced this,
        // but a caller could mutate a raw envelope in place between build
        // and submit. Fail fast with the canonical error code rather than
        // shipping a non-conformant payload to the wire.
        if !contrix_sdk::events::is_ephemeral_kind(&envelope.kind) {
            anyhow::bail!(
                "ephemeral submit: kind {:?} is not in the broadcast ephemeral allowlist",
                envelope.kind
            );
        }
        let window_ms = envelope
            .expires_at
            .signed_duration_since(envelope.sent_at)
            .num_milliseconds();
        if window_ms <= 0
            || (window_ms as u64) > contrix_sdk::EPHEMERAL_ABSOLUTE_HARD_CEILING_MS as u64
        {
            anyhow::bail!(
                "ephemeral submit: expires_at - sent_at = {window_ms} ms violates 5-minute ceiling"
            );
        }
        // Wire schema id binding — soland's `/api/v1/ephemeral` handler
        // expects an envelope tagged with the v1 schema id so it can
        // dispatch to the right reducer-skipping channel.
        let mut body = serde_json::to_value(envelope)?;
        if let Some(obj) = body.as_object_mut() {
            obj.insert(
                "schema".to_owned(),
                Value::String(contrix_sdk::EphemeralEnvelope::SCHEMA.to_owned()),
            );
        }
        self.post_json("api/v1/ephemeral", body).await
    }

    /// Round R2/R3 (T02) — point-to-point to-device signals (the
    /// `cx.key.verification.*` family) MUST travel on the device-message
    /// channel, NOT through `cx.events.submit` or the broadcast ephemeral
    /// channel. Thin convenience wrapper around
    /// [`Self::send_device_message_envelope`] that asserts the kind belongs
    /// to the to-device ephemeral family.
    pub async fn submit_to_device_ephemeral(
        &self,
        txn_id: &str,
        target_actor: &str,
        target_device_id: &str,
        message_type: &str,
        content: Value,
    ) -> anyhow::Result<DeviceMessagesSendResBody> {
        if !message_type.starts_with("cx.key.verification.") {
            anyhow::bail!(
                "to-device ephemeral submit: message_type {message_type:?} is not in the cx.key.verification.* family"
            );
        }
        self.send_device_message_envelope(
            txn_id,
            target_actor,
            target_device_id,
            message_type,
            content,
        )
        .await
    }

    pub async fn identity_receipts(&self, did: &str) -> anyhow::Result<IdentityReceiptsResBody> {
        self.post_json("api/v1/identity/receipts", json!({"did": did}))
            .await
    }

    // ── Media ───────────────────────────────────────────────────────

    pub async fn ice_config(
        &self,
        request: &IceConfigRequest,
    ) -> anyhow::Result<IceConfigResponse> {
        self.post_json("contrix/v1/ice-config", serde_json::to_value(request)?)
            .await
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
        let mut refreshed_access_token = None::<String>;
        loop {
            // Check if request was cancelled
            if self.cancel_token.as_ref().is_some_and(|t| t.is_cancelled()) {
                return Err(anyhow::anyhow!("request cancelled"));
            }

            let Some(mut candidate) = request.try_clone() else {
                return Ok(request.send().await?);
            };
            if let Some(token) = refreshed_access_token.as_deref() {
                candidate = candidate.bearer_auth(token);
            }
            match candidate.send().await {
                Ok(response) => {
                    // Handle 401 with automatic token refresh
                    if response.status() == StatusCode::UNAUTHORIZED
                        && !did_refresh
                        && self.refresh_token.is_some()
                    {
                        if let Ok(result) = self.try_refresh_token().await {
                            refreshed_access_token = Some(result.new_access_token);
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

/// Round R2/R3 (T02) — default ephemeral TTL for `cx.typing` / `cx.presence`
/// / `cx.receipt.read`. 30 seconds is comfortably below the 5-minute hard
/// ceiling and matches the spec's recommended typing-fade window.
const EPHEMERAL_DEFAULT_TTL_SECS: i64 = 30;

/// Round R2/R3 (T02) — build a `cx.typing` `EphemeralEnvelope`. Enforces
/// the kind allowlist + the 5-minute hard ceiling on `expires_at - sent_at`.
pub fn build_typing_envelope(
    realm_id: &str,
    actor_did: &str,
    device_id: Option<&str>,
    typing: bool,
) -> anyhow::Result<contrix_sdk::EphemeralEnvelope> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(EPHEMERAL_DEFAULT_TTL_SECS);
    let realm = contrix_sdk::RealmId::new(realm_id)
        .map_err(|err| anyhow::anyhow!("invalid realm_id for cx.typing: {err}"))?;
    let actor = contrix_sdk::Did::new(actor_did)
        .map_err(|err| anyhow::anyhow!("invalid actor_did for cx.typing: {err}"))?;
    let device = device_id
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            contrix_sdk::DeviceId::new(s)
                .map_err(|err| anyhow::anyhow!("invalid device_id for cx.typing: {err}"))
        })
        .transpose()?;
    contrix_sdk::EphemeralEnvelope::new(
        "cx.typing",
        realm,
        actor,
        device,
        now,
        expires_at,
        json!({"actor_did": actor_did, "typing": typing}),
        None,
    )
    .map_err(|err| anyhow::anyhow!("typing envelope rejected: {err}"))
}

/// Round R2/R3 (T02) — build a `cx.receipt.read` `EphemeralEnvelope`.
pub fn build_receipt_read_envelope(
    realm_id: &str,
    actor_did: &str,
    event_id: &str,
) -> anyhow::Result<contrix_sdk::EphemeralEnvelope> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(EPHEMERAL_DEFAULT_TTL_SECS);
    let realm = contrix_sdk::RealmId::new(realm_id)
        .map_err(|err| anyhow::anyhow!("invalid realm_id for cx.receipt.read: {err}"))?;
    let actor = contrix_sdk::Did::new(actor_did)
        .map_err(|err| anyhow::anyhow!("invalid actor_did for cx.receipt.read: {err}"))?;
    contrix_sdk::EphemeralEnvelope::new(
        "cx.receipt.read",
        realm,
        actor,
        None,
        now,
        expires_at,
        json!({"event_id": event_id}),
        None,
    )
    .map_err(|err| anyhow::anyhow!("read receipt envelope rejected: {err}"))
}

/// Round R2/R3 (T02) — build a `cx.presence` `EphemeralEnvelope`.
pub fn build_presence_envelope(
    realm_id: &str,
    actor_did: &str,
    status: &str,
    last_active_at: Option<chrono::DateTime<chrono::Utc>>,
) -> anyhow::Result<contrix_sdk::EphemeralEnvelope> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(EPHEMERAL_DEFAULT_TTL_SECS);
    let realm = contrix_sdk::RealmId::new(realm_id)
        .map_err(|err| anyhow::anyhow!("invalid realm_id for cx.presence: {err}"))?;
    let actor = contrix_sdk::Did::new(actor_did)
        .map_err(|err| anyhow::anyhow!("invalid actor_did for cx.presence: {err}"))?;
    let mut payload = serde_json::Map::new();
    payload.insert("actor_did".into(), Value::String(actor_did.to_owned()));
    payload.insert("status".into(), Value::String(status.to_owned()));
    if let Some(ts) = last_active_at {
        payload.insert("last_active_at".into(), Value::String(ts.to_rfc3339()));
    }
    contrix_sdk::EphemeralEnvelope::new(
        "cx.presence",
        realm,
        actor,
        None,
        now,
        expires_at,
        Value::Object(payload),
        None,
    )
    .map_err(|err| anyhow::anyhow!("presence envelope rejected: {err}"))
}

/// Round 4 (spec a77b995) — build a `cx.call.signal` v2 `EphemeralEnvelope`.
///
/// Wire-breaking vs. the round R2/R3 form: the payload shape moved from
/// `{call_id, kind, payload}` to the canonical
/// [`contrix_sdk::CallSignalPayload`] `{call_id, signal_type, seq, data}`
/// where `signal_type` MUST be one of [`contrix_sdk::CALL_SIGNAL_TYPES`]
/// (13 values: `invite`, `answer`, `candidate`, `renegotiate`, `hangup`,
/// `ack`, `reject`, `mute_state`, `media_state`, `speaking`, `focus_join`,
/// `focus_leave`, `error`). `device_id` + `proof` are REQUIRED on the
/// envelope; `seq` is strictly monotonic per
/// `(realm_id, call_id, actor, device)` (callers manage the counter via
/// [`contrix_sdk::CallSignalState`]).
///
/// The caller MUST attach a device-signed proof via the active
/// [`crate::event_signer`] before submit — the bare envelope returned
/// here carries `proof = None` and the submit guard / receiver will
/// reject it. See [`super::ContrixApi::submit_call_signal_v2`] for the
/// signing + submit path.
pub fn build_call_signal_envelope_v2(
    realm_id: &str,
    actor_did: &str,
    device_id: &str,
    call_id: &str,
    signal_type: &str,
    seq: u64,
    data: Value,
) -> anyhow::Result<contrix_sdk::EphemeralEnvelope> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(EPHEMERAL_DEFAULT_TTL_SECS);
    let realm = contrix_sdk::RealmId::new(realm_id)
        .map_err(|err| anyhow::anyhow!("invalid realm_id for cx.call.signal: {err}"))?;
    let actor = contrix_sdk::Did::new(actor_did)
        .map_err(|err| anyhow::anyhow!("invalid actor_did for cx.call.signal: {err}"))?;
    if device_id.trim().is_empty() {
        anyhow::bail!(
            "cx.call.signal v2 requires non-empty device_id (round 4 schema_violation)"
        );
    }
    let device = Some(
        contrix_sdk::DeviceId::new(device_id)
            .map_err(|err| anyhow::anyhow!("invalid device_id for cx.call.signal: {err}"))?,
    );
    if !contrix_sdk::CALL_SIGNAL_TYPES.contains(&signal_type) {
        anyhow::bail!(
            "cx.call.signal signal_type {signal_type:?} not in canonical 13-value enum"
        );
    }
    let call = contrix_sdk::CallId::new(call_id)
        .map_err(|err| anyhow::anyhow!("invalid call_id for cx.call.signal: {err}"))?;
    let payload = contrix_sdk::CallSignalPayload {
        call_id: call,
        signal_type: signal_type.to_owned(),
        seq,
        data,
    };
    payload
        .validate_signal_type()
        .map_err(|err| anyhow::anyhow!("cx.call.signal payload rejected: {err}"))?;
    contrix_sdk::EphemeralEnvelope::new(
        "cx.call.signal",
        realm,
        actor,
        device,
        now,
        expires_at,
        serde_json::to_value(payload)?,
        None,
    )
    .map_err(|err| anyhow::anyhow!("call signal envelope rejected: {err}"))
}

/// Round R2/R3 (T11) — classify a server error envelope into the four
/// fail-closed presign blob error classes. The UI MUST surface a friendly
/// (translated) message and MUST NOT retry / cache / log the presign URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobPresignError {
    LegalHoldActive,
    BlobRedacted,
    MediaPlaintextServiceNotAuthorised,
    NotAuthorised,
}

impl BlobPresignError {
    pub fn from_error(error: &anyhow::Error) -> Option<Self> {
        let api_error = error.downcast_ref::<ContrixApiError>()?;
        let code = api_error.error.code();
        match code {
            // Round R2/R3 wire codes from contrix_sdk::error.
            "legal_hold_active" => Some(Self::LegalHoldActive),
            "blob_redacted" => Some(Self::BlobRedacted),
            "media_plaintext_service_not_authorised" => {
                Some(Self::MediaPlaintextServiceNotAuthorised)
            }
            _ => {
                if api_error.status == StatusCode::FORBIDDEN
                    || api_error.status == StatusCode::UNAUTHORIZED
                {
                    Some(Self::NotAuthorised)
                } else {
                    None
                }
            }
        }
    }

    /// i18n key for the user-facing error message. Translation values are
    /// owned by [`crate::i18n`].
    pub fn i18n_key(self) -> &'static str {
        match self {
            Self::LegalHoldActive => "blob.error.legal_hold_active",
            Self::BlobRedacted => "blob.error.redacted",
            Self::MediaPlaintextServiceNotAuthorised => "blob.error.plaintext_not_authorised",
            Self::NotAuthorised => "blob.error.not_authorised",
        }
    }
}

/// A4b — module-level helper for composing a blob download URL when an
/// [`ContrixApi`] handle isn't available (e.g. read-only views that
/// already have the Principal Server `base_url` as a string). Keeps
/// the URL shape canonical so callers can't accidentally desync from
/// [`ContrixApi::blob_download_url`].
pub fn blob_download_url_for(base_url: &str, blob_ref: &str) -> String {
    let base = base_url.trim_end_matches('/');
    format!("{base}/api/v1/blob/get?blob_ref={blob_ref}")
}

const ZERO_ANCHOR_REF: &str =
    "cx:anchor:sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[allow(clippy::too_many_arguments)]
pub fn build_realm_bootstrap_events(
    space_id: &str,
    actor_id: &str,
    title: &str,
    summary: Option<&str>,
    discoverability: &str,
    join_rule: &str,
    history_visibility: &str,
    encryption_profile: &str,
    security_class: &str,
    federation_policy: &str,
    anchor_profile: &str,
    hash_profile: &str,
    invitees: &[String],
    plaintext_visible_services: &[String],
) -> anyhow::Result<Vec<Value>> {
    let mut events = Vec::new();
    events.push(build_realm_create_event(
        space_id,
        actor_id,
        title,
        summary,
        discoverability,
        join_rule,
        history_visibility,
        encryption_profile,
        security_class,
        federation_policy,
        anchor_profile,
        hash_profile,
    )?);
    events.push(build_space_state_event(
        space_id,
        actor_id,
        "cx.realm.join_rule",
        json!(join_rule),
    )?);
    events.push(build_space_state_event(
        space_id,
        actor_id,
        "cx.realm.history_visibility",
        json!(history_visibility),
    )?);
    events.push(build_space_state_event(
        space_id,
        actor_id,
        "cx.realm.discovery",
        json!(discoverability),
    )?);

    let plaintext_services_event =
        build_plaintext_visible_services_event(space_id, actor_id, plaintext_visible_services)?;
    if let Some(event) = plaintext_services_event {
        events.push(event);
    }

    events.push(build_member_state_event(
        space_id, actor_id, actor_id, "join",
    )?);
    for invitee in invitees {
        let invitee = invitee.trim();
        if !invitee.is_empty() && invitee != actor_id {
            events.push(build_member_state_event(
                space_id, actor_id, invitee, "invite",
            )?);
        }
    }
    Ok(events)
}

#[allow(clippy::too_many_arguments)]
pub fn build_realm_create_event(
    space_id: &str,
    actor_id: &str,
    title: &str,
    summary: Option<&str>,
    discoverability: &str,
    join_rule: &str,
    history_visibility: &str,
    encryption_profile: &str,
    security_class: &str,
    federation_policy: &str,
    anchor_profile: &str,
    hash_profile: &str,
) -> anyhow::Result<Value> {
    let created_at = event_timestamp();
    // Per spec realm-and-space.md §2.3: high_assurance security_class
    // MUST satisfy federation_policy ∈ {closed, restricted, quarantine}.
    // Fall back to "restricted" if the caller passed "open" together
    // with high_assurance — the UI also disables the option but
    // belt-and-suspenders here.
    let effective_federation_policy = if security_class == "high_assurance"
        && federation_policy == "open"
    {
        "restricted"
    } else {
        federation_policy
    };
    let mut object = json!({
        "id": space_id,
        "schema": "cx.schema.realm.v1",
        "title": title,
        "created_by_principal": actor_id,
        "schema_refs": ["cx.schema.realm.v1"],
        "default_discoverability": discoverability,
        "default_join_rule": join_rule,
        "history_visibility": history_visibility,
        "encryption_profile": encryption_profile,
        "security_class": security_class,
        "federation_policy": effective_federation_policy,
        "anchor_profile": anchor_profile,
        "hash_profile": hash_profile,
        "anchorer": {
            "type": "single_did",
            "did": actor_id,
        },
        "created_at": created_at,
    });
    if let Some(summary) = summary
        && !summary.trim().is_empty()
    {
        object["summary"] = Value::String(summary.trim().to_owned());
    }

    build_reducer_event(
        "cx.realm.create",
        space_id,
        actor_id,
        &created_at,
        json!({ "object": object }),
        // TODO(realm-rework): cell family rename to cx.component.realm.create.v1
        // once contrix-spec publishes the renamed registry.
        &space_cell("cx.component.realm.create.v1", space_id),
        "append",
        json!({ "space_id": space_id }),
    )
}

/// Build a `cx.space.create` event per spec realm-and-space.md §3.2.
/// Space is the product-structure container (workspace / project /
/// folder / board / list); it lives inside a Realm (`realm_id`) and
/// has no membership / policy / E2EE of its own — all security
/// semantics inherit from the home Realm.
#[allow(clippy::too_many_arguments)]
pub fn build_space_create_event(
    space_id: &str,
    realm_id: &str,
    actor_id: &str,
    title: &str,
    summary: Option<&str>,
    kind: &str,
    parent_space_id: Option<&str>,
    default_realm_ref: Option<&str>,
) -> anyhow::Result<Value> {
    let created_at = event_timestamp();
    let mut object = json!({
        "id": space_id,
        "schema": "cx.schema.space.v1",
        "realm_id": realm_id,
        "kind": kind,
        "title": title,
        "state": "active",
        "created_by": actor_id,
        "created_at": created_at,
    });
    if let Some(summary) = summary
        && !summary.trim().is_empty()
    {
        object["summary"] = Value::String(summary.trim().to_owned());
    }
    if let Some(parent) = parent_space_id
        && !parent.trim().is_empty()
    {
        object["parent_ref"] = Value::String(parent.trim().to_owned());
    }
    if let Some(default_realm) = default_realm_ref
        && !default_realm.trim().is_empty()
    {
        object["default_realm_ref"] = Value::String(default_realm.trim().to_owned());
    }

    // The Space `create` event is authorized + written to the home
    // Realm — `space_id` on the wire event = the Realm id, per the
    // Realm/Space inversion routing: every container write lands in
    // its `realm_id` for sync / authz. The reducer cell is keyed by
    // the new Space id so the projection stores it correctly.
    build_reducer_event(
        "cx.space.create",
        realm_id,
        actor_id,
        &created_at,
        json!({ "object": object }),
        &space_cell("cx.component.space.create.v1", space_id),
        "append",
        json!({ "space_id": space_id }),
    )
}

/// Build a Space lifecycle event (`cx.space.archive` /
/// `cx.space.restore` / `cx.space.tombstone`) per spec
/// realm-and-space.md §3.4. All three write the new `state` value
/// into the `cx.component.space.state.v1` cell on the home Realm.
/// Server-side cascade rules:
///
/// - `archive` (active → archived): not cascaded to children.
/// - `restore` (archived → active): not cascaded; only valid from
///   `archived`.
/// - `tombstone` (any → tombstoned): irreversible; server MUST
///   `failed_precondition` when the Space still has live child
///   Spaces or live `contains` placement Flows.
pub fn build_space_lifecycle_event(
    space_id: &str,
    realm_id: &str,
    actor_id: &str,
    kind: &str,
) -> anyhow::Result<Value> {
    let next_state = match kind {
        "cx.space.archive" => "archived",
        "cx.space.restore" => "active",
        "cx.space.tombstone" => "tombstoned",
        other => {
            return Err(anyhow::anyhow!(
                "unsupported Space lifecycle event kind {other}"
            ));
        }
    };
    let created_at = event_timestamp();
    build_reducer_event(
        kind,
        realm_id,
        actor_id,
        &created_at,
        json!({
            "space_id": space_id,
            "state": next_state,
            "state_changed_at": created_at,
        }),
        &space_cell("cx.component.space.state.v1", space_id),
        "set",
        json!({ "value": next_state }),
    )
}

pub fn build_space_state_event(
    space_id: &str,
    actor_id: &str,
    kind: &str,
    value: Value,
) -> anyhow::Result<Value> {
    // R1.7: security-boundary state events now live in cx.realm.*; the
    // matching cell families are cx.component.realm.*.v1.
    let cell_family = match kind {
        "cx.realm.join_rule" => "cx.component.realm.join_rule.v1",
        "cx.realm.history_visibility" => "cx.component.realm.history_visibility.v1",
        "cx.realm.discovery" => "cx.component.realm.discovery.v1",
        "cx.realm.schema" => "cx.component.realm.schema.v1",
        "cx.realm.policy_components" => "cx.component.realm.policy_components.v1",
        other => {
            return Err(anyhow::anyhow!(
                "unsupported Realm state event kind {other}"
            ));
        }
    };
    let created_at = event_timestamp();
    let payload_value = value.clone();
    build_reducer_event(
        kind,
        space_id,
        actor_id,
        &created_at,
        json!({ "value": payload_value }),
        &space_cell(cell_family, space_id),
        "set",
        json!({ "value": value }),
    )
}

pub fn build_plaintext_visible_services_event(
    space_id: &str,
    actor_id: &str,
    service_dids: &[String],
) -> anyhow::Result<Option<Value>> {
    let services = service_dids
        .iter()
        .map(|service| service.trim())
        .filter(|service| !service.is_empty())
        .map(|service| {
            json!({
                "service_did": service,
                "service_type": "principal_server",
                "purposes": ["message_index", "notification_fanout"],
                "visibility": "private_plaintext",
            })
        })
        .collect::<Vec<_>>();
    if services.is_empty() {
        return Ok(None);
    }

    let created_at = event_timestamp();
    build_reducer_event(
        "cx.realm.plaintext_visible_services",
        space_id,
        actor_id,
        &created_at,
        json!({ "services": services.clone() }),
        &space_cell("cx.component.realm.plaintext_visible_services.v1", space_id),
        "set",
        json!({ "services": services }),
    )
    .map(Some)
}

fn build_member_state_event(
    space_id: &str,
    actor_id: &str,
    member_actor_id: &str,
    membership: &str,
) -> anyhow::Result<Value> {
    let created_at = event_timestamp();
    build_reducer_event(
        "cx.member.state",
        space_id,
        actor_id,
        &created_at,
        json!({
            "actor_id": member_actor_id,
            "membership": membership,
            "reason": "space_create",
        }),
        &format!(
            "{}:{}",
            space_cell("cx.component.member.state.v1", space_id),
            member_actor_id
        ),
        "transition",
        json!({ "from": null, "to": membership }),
    )
}

fn build_reducer_event(
    kind: &str,
    space_id: &str,
    actor_id: &str,
    created_at: &str,
    payload: Value,
    cell: &str,
    op_kind: &str,
    op_value: Value,
) -> anyhow::Result<Value> {
    let event_id = format!("cx:event:{}", uuid_v7());
    let mut op = json!({ "kind": op_kind });
    match op_value {
        Value::Object(map) => {
            if let Value::Object(op_object) = &mut op {
                for (key, value) in map {
                    op_object.insert(key, value);
                }
            }
        }
        value => {
            op["value"] = value;
        }
    }
    let mut event = json!({
        "event_id": event_id.clone(),
        "kind": kind,
        "actor_id": actor_id,
        "actor_seq": next_seq(),
        "space_id": space_id,
        "created_at": created_at,
        "hlc": Hlc::now("yougen").encode(),
        "prev_refs": [],
        "refs": [],
        "preconditions": [],
        "effects": [{
            "cell": cell,
            "op": op,
        }],
        "anchor_ref": ZERO_ANCHOR_REF,
        "payload": payload,
        "unsigned": {
            "local_operation_idempotency_alias": event_id,
        },
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": format!("{actor_id}#yougen"),
            "payload_hash": "",
            "created_at": created_at,
            "jws": "a..b",
        }],
    });
    refresh_event_proof(&mut event)?;
    Ok(event)
}

/// RFC3339 timestamp in the canonical wire form soland's
/// `canonical::validate_timestamp_canonical` accepts: exactly
/// `YYYY-MM-DDTHH:MM:SSZ` (20 chars, UTC `Z` suffix, NO fractional
/// seconds — spec encoding.md §3.5). Producing `SecondsFormat::Millis`
/// here was a long-standing yougen bug — the trailing `.NNNZ` made
/// every event submission fail with `invalid_param: created_at must
/// use canonical RFC3339 UTC form` once soland's R3 canonical
/// validator landed.
fn event_timestamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn space_cell(cell_family: &str, space_id: &str) -> String {
    format!("cx:cell:{cell_family}:{space_id}")
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

pub fn build_signed_device_verification_proof(
    from_actor: &str,
    from_device: &str,
    target_device: &str,
    method: &str,
    sas_decimal: Option<[u16; 3]>,
    local_public_key: Option<&str>,
    peer_public_key: Option<&str>,
    signing_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<Value> {
    let mut body = json!({
        "type": "cx.device.verification.proof.v1",
        "from_actor": from_actor,
        "from_device": from_device,
        "target_device": target_device,
        "method": method,
        "created_at": event_timestamp(),
    });
    if let Some(sas_decimal) = sas_decimal {
        body["sas_decimal"] = json!(sas_decimal);
    }
    if let Some(local_public_key) = local_public_key {
        body["local_public_key"] = Value::String(local_public_key.to_owned());
    }
    if let Some(peer_public_key) = peer_public_key {
        body["peer_public_key"] = Value::String(peer_public_key.to_owned());
    }
    let canonical = contrix_sdk::canonical::canonical_json_bytes(&body)
        .map_err(|error| anyhow::anyhow!("canonicalize device verification proof: {error}"))?;
    let header = json!({
        "alg": "EdDSA",
        "typ": "JWT",
        "verification_method": format!("{}#yougen-device", from_device),
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&canonical);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes()).to_bytes();
    let jws = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature));
    Ok(json!({
        "device_envelope": body,
        "signature": {
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": format!("{}#yougen-device", from_device),
            "payload_hash": format!("sha256:{:x}", Sha256::digest(&canonical)),
            "jws": jws,
        }
    }))
}

pub fn ensure_device_verification_proof_is_signed(proof: &Value) -> anyhow::Result<()> {
    let Some(signature) = proof.get("signature") else {
        anyhow::bail!("device verification proof must include a signed device envelope")
    };
    let alg = signature
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let jws = signature
        .get("jws")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if alg != "EdDSA" || jws.split('.').count() != 3 {
        anyhow::bail!("device verification proof must carry an EdDSA compact JWS")
    }
    if proof.get("device_envelope").is_none() {
        anyhow::bail!("device verification proof missing device_envelope")
    }
    Ok(())
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

/// Decode a server error response into an SDK [`ErrorEnvelope`]. We try
/// the current on-the-wire shapes in order:
///
///   1. The canonical wrapped shape `{ "error": ErrorEnvelope }` (what
///      our principal server emits when its inner handler bubbles a
///      typed envelope through the outer `ApiErrorBody`).
///   2. A bare envelope `{ "ok": false, "error": { code, message },
///      request_id? }` — same shape, no wrapping. The SDK's
///      [`ErrorEnvelope`] requires `request_id`, so we tolerate its
///      absence via a local shadow type that defaults it to
///      `"unknown"`.
///
/// If none match, we synthesise a minimal envelope tagged
/// `cx.error.http_status` so downstream code always has something
/// well-formed to surface.
pub fn decode_contrix_error(status: StatusCode, bytes: &[u8]) -> ErrorEnvelope {
    #[derive(serde::Deserialize)]
    struct PlainEnvelope {
        #[serde(default)]
        ok: bool,
        error: contrix_sdk::ErrorDetail,
        #[serde(default = "default_request_id")]
        request_id: String,
    }
    fn default_request_id() -> String {
        "unknown".to_owned()
    }
    impl From<PlainEnvelope> for ErrorEnvelope {
        fn from(value: PlainEnvelope) -> Self {
            ErrorEnvelope {
                ok: value.ok,
                error: value.error,
                request_id: value.request_id,
            }
        }
    }

    if let Ok(body) = serde_json::from_slice::<ApiErrorBody>(bytes) {
        return body.error;
    }
    if let Ok(plain) = serde_json::from_slice::<PlainEnvelope>(bytes) {
        return plain.into();
    }
    ErrorEnvelope::new(
        "http_status",
        format!("HTTP request failed with status {status}"),
    )
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

fn canonical_space_join_rule_v1(join_rule: &str) -> &str {
    match join_rule {
        "open" => "public",
        "request" => "knock",
        "invite_only" => "invite",
        value => value,
    }
}

async fn sleep_backoff(initial: Duration, attempt: usize) {
    sleep_for(backoff_duration(initial, attempt)).await;
}

fn backoff_duration(initial: Duration, attempt: usize) -> Duration {
    let factor = 1u32.checked_shl(attempt as u32).unwrap_or(u32::MAX);
    initial.saturating_mul(factor)
}

async fn sleep_retry_delay(headers: &HeaderMap, initial: Duration, attempt: usize) {
    let delay = parse_retry_after(headers).unwrap_or_else(|| backoff_duration(initial, attempt));
    sleep_for(delay).await;
}

// `tokio::time::sleep` reads `std::time::Instant::now()` and panics on
// wasm32-unknown-unknown ("time not implemented on this platform"). Route the
// wasm build through `gloo_timers::future::TimeoutFuture`, which is backed by
// `setTimeout`.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn sleep_for(delay: Duration) {
    tokio::time::sleep(delay).await;
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn sleep_for(delay: Duration) {
    let ms = u32::try_from(delay.as_millis()).unwrap_or(u32::MAX);
    gloo_timers::future::TimeoutFuture::new(ms).await;
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

fn query_component(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn events_query_path(space_id: &str) -> String {
    format!("api/v1/events?spaces={}", query_component(space_id))
}

fn events_subscribe_path(
    space_id: &str,
    after: Option<&str>,
    include_history: Option<bool>,
) -> String {
    let mut url = format!(
        "api/v1/events/subscribe?spaces={}",
        query_component(space_id)
    );
    if let Some(after) = after {
        url.push_str("&after=");
        url.push_str(&query_component(after));
    }
    if let Some(include_history) = include_history {
        url.push_str("&include_history=");
        url.push_str(if include_history { "true" } else { "false" });
    }
    url
}

/// Round 4 (spec a77b995) — parse the round-4 typed
/// `/events/subscribe` NDJSON stream. The frame body is
/// [`contrix_sdk::EventsSubscribeFrameBody`] (tag = "kind",
/// snake_case-discriminated). Wire-breaking: the pre-round-4 untyped
/// string-line parser is deleted.
pub fn parse_events_subscribe_ndjson_text(
    input: &str,
) -> anyhow::Result<Vec<contrix_sdk::EventsSubscribeFrameBody>> {
    let mut frames = Vec::new();
    for line in input.lines() {
        if let Some(frame) = parse_events_subscribe_ndjson_line(line.as_bytes())? {
            frames.push(frame);
        }
    }
    Ok(frames)
}

fn drain_events_subscribe_ndjson_lines<F>(
    pending: &mut Vec<u8>,
    on_frame: &mut F,
) -> anyhow::Result<()>
where
    F: FnMut(contrix_sdk::EventsSubscribeFrameBody) -> anyhow::Result<()>,
{
    while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
        let mut line: Vec<u8> = pending.drain(..=newline).collect();
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if let Some(frame) = parse_events_subscribe_ndjson_line(&line)? {
            on_frame(frame)?;
        }
    }
    Ok(())
}

fn parse_events_subscribe_ndjson_line(
    line: &[u8],
) -> anyhow::Result<Option<contrix_sdk::EventsSubscribeFrameBody>> {
    let trimmed = trim_ascii(line);
    if trimmed.is_empty() {
        return Ok(None);
    }
    serde_json::from_slice(trimmed)
        .map(Some)
        .map_err(|err| anyhow::anyhow!("failed to parse subscribe NDJSON frame: {err}"))
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

pub fn parse_sync(value: Value) -> anyhow::Result<ClientSyncResponse> {
    Ok(serde_json::from_value(value)?)
}

pub fn parse_sync_describe(value: Value) -> anyhow::Result<SyncDescribeResBody> {
    Ok(serde_json::from_value(value)?)
}

pub fn parse_directory_describe(value: Value) -> anyhow::Result<DirectoryDescribeResBody> {
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
            "service_did": "did:web:server.local",
            "trust_domain": "cx:trust_domain:server.local",
            "service_type": "principal_server",
            "protocol_version": "1.0",
            "supported_profiles": [],
            "supported_features": ["sync.account"],
            "supported_operations": ["cx.sync.account"],
            "supported_bindings": [{"kind": "http_json"}],
            "auth_metadata": {},
            "limits": {"storage": "memory"},
            "plaintext_visibility": {"default": "encrypted"},
            "implemented_features": [],
            "claimed_profiles": [],
            "verified_profiles": [],
            "experimental_features": [],
            "compat_surfaces": [],
            "development_mode": true,
        }))
        .unwrap();
        assert_eq!(description.protocol_version, "1.0");

        let sync = parse_sync(json!({
            "cursor": "cx:cursor:test-1",
            "spaces": {
                "cx:space:0196419b-0000-7000-8000-000000000000": {"summary": {}}
            },
            "to_device": [],
            "account_data": [],
            "device_lists": {"changed": [], "left": []}
        }))
        .unwrap();
        assert_eq!(sync.spaces.len(), 1);
        assert_eq!(sync.cursor, "cx:cursor:test-1");

        // Spec-aligned wire shape per `client-sync.md §2`: flat
        // `spaces` keyed by realm id, explicit `left_spaces`,
        // flat arrays for top-level streams. The SDK's
        // `SyncResBody` accepts `next_batch` as a serde alias so
        // pre-spec-rename payloads still decode during the
        // migration window.
        let sync_v1 = parse_sync(json!({
            "cursor": "cx:cursor:v1",
            "spaces": {
                "cx:space:joined": {
                    "summary": {"title": "Joined"}
                }
            },
            "left_spaces": ["cx:space:left"],
            "to_device": [{"type": "cx.mls.welcome"}],
            "account_data": [{"data_type": "client.ui", "content": {"theme": "system"}}],
            "device_lists": {"changed": [], "left": []},
            "notifications": {"events": []},
            "presence": []
        }))
        .unwrap();
        assert_eq!(sync_v1.cursor, "cx:cursor:v1");
        assert!(sync_v1.spaces.contains_key("cx:space:joined"));
        assert_eq!(sync_v1.left_spaces, vec!["cx:space:left".to_owned()]);
        assert_eq!(sync_v1.to_device.len(), 1);
        assert_eq!(sync_v1.account_data.len(), 1);
        assert!(sync_v1.notifications.is_object());
        assert!(sync_v1.presence.is_empty());

        let directory = parse_directory_describe(json!({
            "service_did": "did:web:server.local",
            "resource_types": ["space", "organization", "actor"],
            "discovery_profiles": ["cx.profile.directory.v1"],
            "restricted_query_proof": false
        }))
        .unwrap();
        assert!(directory.resource_types.contains(&"space".to_owned()));
    }

    #[test]
    fn event_paths_use_v1_query_parameters() {
        let backfill = events_query_path("cx:space:demo");
        assert_eq!(backfill, "api/v1/events?spaces=cx%3Aspace%3Ademo");
        assert!(!backfill.contains("direction="));

        let subscribe = events_subscribe_path("cx:space:demo", Some("sx:1"), Some(true));
        assert_eq!(
            subscribe,
            "api/v1/events/subscribe?spaces=cx%3Aspace%3Ademo&after=sx%3A1&include_history=true"
        );
        assert!(!subscribe.contains("&from="));
    }

    #[test]
    fn canonical_space_join_rule_keeps_v1_invite_value() {
        assert_eq!(canonical_space_join_rule_v1("open"), "public");
        assert_eq!(canonical_space_join_rule_v1("request"), "knock");
        assert_eq!(canonical_space_join_rule_v1("invite_only"), "invite");
        assert_eq!(canonical_space_join_rule_v1("invite"), "invite");
    }

    #[test]
    fn space_bootstrap_events_use_canonical_create_and_facet_kinds() {
        let events = build_realm_bootstrap_events(
            // TODO(realm-rework): switch to a `cx:realm:` id once SDK validators accept it.
            "cx:space:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "Engineering",
            Some("Roadmap work"),
            "listed",
            "invite",
            "shared",
            "mls_rfc9420",
            "standard",
            "restricted",
            "single_did",
            "sha256",
            &["did:web:bob.example".to_owned()],
            &["did:web:server.example".to_owned()],
        )
        .unwrap();
        let kinds = events
            .iter()
            .map(|event| event["kind"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![
                "cx.realm.create",
                "cx.realm.join_rule",
                "cx.realm.history_visibility",
                "cx.realm.discovery",
                "cx.realm.plaintext_visible_services",
                "cx.member.state",
                "cx.member.state",
            ]
        );

        let create = &events[0];
        assert_eq!(create["payload"]["object"]["schema"], "cx.schema.realm.v1");
        assert_eq!(
            create["payload"]["object"]["created_by_principal"],
            create["actor_id"]
        );
        assert_eq!(
            create["payload"]["object"]["created_at"], create["created_at"],
            "Realm create cross-field semantic validation requires matching timestamps",
        );
        assert_eq!(create["payload"]["object"]["default_join_rule"], "invite");
        assert_eq!(create["payload"]["object"]["history_visibility"], "shared");
        assert_eq!(
            create["effects"][0]["cell"],
            "cx:cell:cx.component.realm.create.v1:cx:space:0196419b-0000-7000-8000-000000000001"
        );
        assert_eq!(create["effects"][0]["op"]["kind"], "append");
        assert_eq!(create["anchor_ref"], ZERO_ANCHOR_REF);
        assert!(
            create["proofs"][0]["payload_hash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );

        assert_eq!(events[1]["payload"]["value"], "invite");
        assert_eq!(events[2]["payload"]["value"], "shared");
        assert_eq!(events[3]["payload"]["value"], "listed");
        assert_eq!(
            events[4]["payload"]["services"][0]["service_did"],
            "did:web:server.example"
        );
        assert_eq!(events[5]["payload"]["membership"], "join");
        assert_eq!(events[6]["payload"]["membership"], "invite");
    }

    #[test]
    fn parses_events_subscribe_ndjson_frames() {
        // Round 4 typed frames carry the discriminator-required fields:
        // `heartbeat` requires `emitted_at`; `frontier` requires a nested
        // `frontier` value; `catchup_complete` is a unit variant.
        let frames = parse_events_subscribe_ndjson_text(
            r#"
{"kind":"heartbeat","emitted_at":"2026-05-20T00:00:00Z"}
{"kind":"frontier","frontier":{"cx:space:demo":["cx:event:01"]}}
{"kind":"catchup_complete"}
"#,
        )
        .unwrap();

        assert!(matches!(
            frames[0],
            contrix_sdk::EventsSubscribeFrameBody::Heartbeat { .. }
        ));
        assert!(matches!(
            &frames[1],
            contrix_sdk::EventsSubscribeFrameBody::Frontier { .. }
        ));
        assert!(matches!(
            &frames[2],
            contrix_sdk::EventsSubscribeFrameBody::CatchupComplete
        ));
    }

    #[test]
    fn drains_split_events_subscribe_ndjson_chunks() {
        let mut pending = br#"{"kind":"heartbeat","emitted_at":"2026-05-20T00:00:00Z"}
{"kind":"resync_required""#
            .to_vec();
        let mut frames = Vec::new();
        drain_events_subscribe_ndjson_lines(&mut pending, &mut |frame| {
            frames.push(frame);
            Ok(())
        })
        .unwrap();
        assert_eq!(frames.len(), 1);
        assert!(matches!(
            frames[0],
            contrix_sdk::EventsSubscribeFrameBody::Heartbeat { .. }
        ));

        pending.extend_from_slice(
            br#","reason":"server restart"}
"#,
        );
        drain_events_subscribe_ndjson_lines(&mut pending, &mut |frame| {
            frames.push(frame);
            Ok(())
        })
        .unwrap();

        assert!(pending.is_empty());
        assert!(matches!(
            &frames[1],
            contrix_sdk::EventsSubscribeFrameBody::ResyncRequired { reason } if reason == "server restart"
        ));
    }

    #[test]
    fn decodes_wrapped_contrix_error_envelope() {
        let decoded = decode_contrix_error(
            StatusCode::CONFLICT,
            br#"{"ok":false,"error":{"code":"expected_head_mismatch","message":"expected_head mismatch","retry_after_ms":250,"details":{"scope":"repo"}}}"#,
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
            br#"{"ok":false,"error":{"code":"invalid_param","message":"invalid did"}}"#,
        );
        assert_eq!(decoded.code(), "invalid_param");

        // The SDK's ErrorEnvelope::new strips the `cx.error.` prefix in
        // `canonical_error_code` and we depend on that canonicalization so
        // downstream comparisons against the registry shape match.
        let fallback = decode_contrix_error(StatusCode::SERVICE_UNAVAILABLE, b"busy");
        assert_eq!(fallback.code(), "http_status");
        assert!(fallback.message().contains("503 Service Unavailable"));
    }

    #[test]
    fn recognizes_auth_expired_errors() {
        let error: anyhow::Error = ContrixApiError {
            status: StatusCode::UNAUTHORIZED,
            error: decode_contrix_error(
                StatusCode::UNAUTHORIZED,
                br#"{"ok":false,"error":{"code":"auth_expired","message":"session expired"}}"#,
            ),
        }
        .into();
        assert!(is_auth_expired_error(&error));

        // A bare 401 with no structured envelope (parse failure or a
        // reverse-proxy-injected 401 page) must NOT be treated as session
        // death. Without a body the server has not told us the token is
        // permanently invalid — it may just be a transient deny. The UI
        // surfaces the error and lets the user retry rather than wiping
        // the session and forcing a fresh sign-in.
        let bare: anyhow::Error = ContrixApiError {
            status: StatusCode::UNAUTHORIZED,
            error: decode_contrix_error(StatusCode::UNAUTHORIZED, b""),
        }
        .into();
        assert!(!is_auth_expired_error(&bare));

        // Common aliases for the same condition should all trigger.
        for code in [
            "unauthenticated",
            "soft_logged_out",
            "M_UNKNOWN_TOKEN",
            "invalid_token",
            "token_expired",
        ] {
            let body =
                format!(r#"{{"ok":false,"error":{{"code":"{code}","message":"unknown token"}}}}"#);
            let aliased: anyhow::Error = ContrixApiError {
                status: StatusCode::UNAUTHORIZED,
                error: decode_contrix_error(StatusCode::UNAUTHORIZED, body.as_bytes()),
            }
            .into();
            assert!(is_auth_expired_error(&aliased), "code {code} should match");
        }

        // A 401 carrying an unrelated error code (rate-limit, policy_denied
        // wrapped in 401, etc.) must not be misclassified as session death.
        let unrelated: anyhow::Error = ContrixApiError {
            status: StatusCode::UNAUTHORIZED,
            error: decode_contrix_error(
                StatusCode::UNAUTHORIZED,
                br#"{"ok":false,"error":{"code":"rate_limited","message":"slow down"}}"#,
            ),
        }
        .into();
        assert!(!is_auth_expired_error(&unrelated));

        let forbidden: anyhow::Error = ContrixApiError {
            status: StatusCode::FORBIDDEN,
            error: decode_contrix_error(
                StatusCode::FORBIDDEN,
                br#"{"ok":false,"error":{"code":"auth_expired","message":"session expired"}}"#,
            ),
        }
        .into();
        assert!(!is_auth_expired_error(&forbidden));
    }

    #[test]
    fn recognizes_plaintext_visibility_policy_errors() {
        let error: anyhow::Error = ContrixApiError {
            status: StatusCode::FORBIDDEN,
            error: decode_contrix_error(
                StatusCode::FORBIDDEN,
                br#"{"ok":false,"error":{"code":"policy_denied","message":"private plaintext message operations require this service in plaintext_visible_services"}}"#,
            ),
        }
        .into();
        assert!(is_plaintext_visibility_policy_error(&error));

        let other_policy: anyhow::Error = ContrixApiError {
            status: StatusCode::FORBIDDEN,
            error: decode_contrix_error(
                StatusCode::FORBIDDEN,
                br#"{"ok":false,"error":{"code":"policy_denied","message":"only the space owner can update policy"}}"#,
            ),
        }
        .into();
        assert!(!is_plaintext_visibility_policy_error(&other_policy));
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
    fn wait_for_header_rejects_non_timestamp_sync_tokens() {
        let api = ContrixApi::new("http://127.0.0.1:8787/")
            .unwrap()
            .with_wait_for("sx:e2e:2");
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

        assert!(request.headers().get("x-contrix-wait-for").is_none());
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

    #[test]
    fn device_verification_proof_requires_signed_envelope() {
        assert!(ensure_device_verification_proof_is_signed(&json!({})).is_err());
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let proof = build_signed_device_verification_proof(
            "did:web:alice.example",
            "cx:device:alice",
            "cx:device:bob",
            "sas",
            Some([1234, 5678, 9012]),
            Some("alice-x25519"),
            Some("bob-x25519"),
            &signing,
        )
        .unwrap();
        ensure_device_verification_proof_is_signed(&proof).expect("signed proof");
        assert_eq!(
            proof["device_envelope"]["type"].as_str(),
            Some("cx.device.verification.proof.v1")
        );
        assert_eq!(proof["signature"]["alg"].as_str(), Some("EdDSA"));
        assert_eq!(
            proof["signature"]["jws"]
                .as_str()
                .unwrap()
                .split('.')
                .count(),
            3
        );
    }

    #[test]
    fn demo_crypto_fallbacks_are_local_only_by_default() {
        let local = ContrixApi::new("http://127.0.0.1:8787").unwrap();
        local
            .ensure_demo_crypto_fallback_allowed("test fallback")
            .expect("local dev fallback");
        let remote = ContrixApi::new("https://contrix.example").unwrap();
        assert!(
            remote
                .ensure_demo_crypto_fallback_allowed("test fallback")
                .is_err()
        );
    }
}
