use std::fmt::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chime::{CokretPushClient, RegisterDeviceRequest, UnregisterDeviceRequest};
use cokret_sdk::ErrorEnvelope;
use ed25519_dalek::Signer;
use reqwest::header::{ACCEPT, HeaderMap, RETRY_AFTER};
use reqwest::{Client, Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{OnceCell, RwLock};
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
    pub principal_id_body_field: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PrincipalAuthBridgePushDescriptor {
    pub register_device_path: String,
    pub unregister_device_path: String,
    pub session_grant_header: String,
    pub principal_id_body_field: String,
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
use crate::identity_handle::{ParsedUserHandle, parse_user_handle};
use crate::models::{
    AccountDataSetOutcome, AccountResponse, AgentGrantAttachReqBody, AgentGrantDetachResBody,
    AgentGrantResBody, AgentKeyPairReqBody, AgentKeyPairResBody, AgentLifecycleReqBody,
    AgentLifecycleResBody, AgentListResBody, AgentProvisionReqBody, AgentResBody,
    AgentRotateKeyReqBody, AgentRotateKeyResBody, AgentSidecarThreadEnsureReqBody,
    AgentSidecarThreadEnsureResBody, AuthzCheckResBody, BackfillResBody, BlobUploadResBody,
    CallRecordingStartResponse, ClientSyncResponse, ConsentCellResponse, ConsentCellsResponse,
    ContactResponse, ContactsResponse, CreateWebrtcSessionResponse, DevLoginResponse,
    DeviceMessagesReceiveResBody, DeviceMessagesSendResBody, DeviceTrustResponse,
    DirectoryDescribeResBody, EffectiveGrantsResBody, EphemeralSubmitResponse,
    EventsDescribeResBody, HealthResponse, IceConfigRequest, IceConfigResponse,
    IdentityDescribeResBody, IdentityResolveResBody, IndexSearchResponse, InvitesResponse,
    KeysClaimResBody, KeysQueryResBody, KeysUploadResBody, LogoutResponse, MimiConsentResBody,
    MimiGroupInfoResBody, MimiIdentifierQueryResBody, MimiKeyMaterialResBody, MimiNotifyResBody,
    MimiProviderDirectoryResBody, MimiProxyDownloadResBody, MimiReportAbuseResBody,
    MimiRoomUpdateResBody, MimiSubmitMessageResBody, MlsRotateResponse, ModerationReportResBody,
    OkResBody, PolicyCheckResBody, PushRegisterResponse, RealmCreateResponse, RealmJoinCandidate,
    ReceiptResponse, ResolveHandleResponse, ResolveRealmResponse, SearchActorsResponse,
    SearchOrganizationsResponse, SearchSpacesResponse, ServerDescription, SnapshotHeadResponse,
    SpaceCreateResponse, SpacePolicyResponse, SubmitDidOperationResBody, SubmitEventResponse,
    SyncDescribeResBody, TypingResponse, UpdateProfileResponse, VerifyDeviceResponse,
    WebrtcSignalResponse,
};
use crate::operation::{
    Effect, EventEnvelope, EventRequirements, LatticeOp, OperationBuilder, Precondition, Predicate,
    scope_id_as_realm_id, uuid_v7,
};

/// B-F / CXP-0009 §3 — default home-policy discriminator passed on
/// `ck.agent.sidecar_thread.ensure`. The spec rolled the default from
/// "default home realm" to "context realm preferred"; yougen MUST emit
/// this token unless the caller explicitly overrides it.
pub const SIDECAR_HOME_POLICY_CONTEXT_REALM_PREFERRED: &str = "context_realm_preferred";

/// Returns the canonical default home-policy string for the
/// `ck.agent.sidecar_thread.ensure` request body's `home_policy` field.
pub fn sidecar_home_policy_default() -> &'static str {
    SIDECAR_HOME_POLICY_CONTEXT_REALM_PREFERRED
}

/// Generic wrapper for soland's
/// `/_cokret/self/projection/{spaces|flows}` lifecycle endpoints. Keeps
/// the query response shape symmetric across the two surfaces so the kanban
/// hydrate path can pluck projection rows with the same code. The decoder
/// normalizes spec `spaces` / `flows` / `morphs` collection keys plus
/// soland's legacy `space_containers` key into `items`.
#[derive(Clone, Debug, Deserialize)]
pub struct LifecycleProjectionResponse<T> {
    pub realm_id: String,
    #[serde(default)]
    pub total: u32,
    #[serde(
        default = "Vec::new",
        alias = "spaces",
        alias = "space_containers",
        alias = "flows",
        alias = "morphs"
    )]
    pub items: Vec<T>,
}

/// Server-side Space-container projection row.
///
/// Soland serves these rows from
/// `GET /_cokret/self/projection/spaces`.
#[derive(Clone, Debug, Deserialize)]
pub struct SpaceContainerProjectionView {
    #[serde(alias = "space_id")]
    pub container_space_id: String,
    pub realm_id: String,
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
    pub parent_space_id: Option<String>,
}

/// Server-side Flow row from `GET /_cokret/self/projection/flows`.
#[derive(Clone, Debug, Deserialize)]
pub struct FlowProjectionView {
    pub flow_id: String,
    #[serde(alias = "space_id")]
    pub realm_id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub body: Option<Value>,
    #[serde(default)]
    pub board_space_id: Option<String>,
    #[serde(default)]
    pub list_space_id: Option<String>,
    #[serde(default)]
    pub rank: Option<String>,
    #[serde(default)]
    pub fields: serde_json::Map<String, serde_json::Value>,
    /// `active` / `archived` / `redacted` per spec
    /// `common-fields.md §5.1`. `redacted` is the only irreversible
    /// terminal state; the reducer no longer accepts `deleted`.
    pub state: String,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Server-side Morph row from
/// `GET /_cokret/self/projection/morphs`. Same enum as Flow per spec §5.1.
#[derive(Clone, Debug, Deserialize)]
pub struct MorphProjectionView {
    pub morph_id: String,
    #[serde(alias = "space_id")]
    pub realm_id: String,
    #[serde(default)]
    pub morph_type: String,
    #[serde(default)]
    pub title: Option<String>,
    pub state: String,
}

#[derive(Clone)]
pub struct CokretApi {
    base_url: Url,
    pub(crate) http: Client,
    access_token: Option<String>,
    wait_for_sync_token: Option<String>,
    retry: RetryPolicy,
    /// Coauth-issued session grant and optional introspection proof headers
    /// used by chime push register/unregister calls.
    chime_session_grant: Option<String>,
    chime_session_grant_proof: Option<SessionGrantIntrospectionProof>,
    network_state: Arc<RwLock<NetworkState>>,
    cancel_token: Option<CancellationToken>,
    /// H1 — cached `GET /_cokret/self/events/describe` response. Used so callers
    /// like `submit_events_batch` can consult `capabilities.batch_submit`
    /// without re-hitting the network on every batch.
    events_describe_cache: Arc<OnceCell<EventsDescribeResBody>>,
}

impl fmt::Debug for CokretApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CokretApi")
            .field("base_url", &self.base_url)
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<redacted>"),
            )
            .field("wait_for_sync_token", &self.wait_for_sync_token)
            .field("retry", &self.retry)
            .field(
                "chime_session_grant",
                &self.chime_session_grant.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "chime_session_grant_proof",
                &self.chime_session_grant_proof.as_ref().map(|_| "<proof>"),
            )
            .field("cancel_token", &self.cancel_token)
            .field(
                "events_describe_cache",
                &self
                    .events_describe_cache
                    .get()
                    .map(|_| "<cached>")
                    .unwrap_or("<empty>"),
            )
            .finish()
    }
}

/// Network connectivity state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkState {
    Online,
    Offline,
    Reconnecting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CokretApiOptions {
    pub timeout: Duration,
    pub retry: RetryPolicy,
}

impl Default for CokretApiOptions {
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

/// Context for `ck.directory.resolve_handle`.
///
/// Protocol distinction: `lookup` / `mention` are display-safe resolves;
/// `member_add` / `invite` request Realm/audience-bound membership-builder
/// material. Callers that are about to invite or add a member MUST provide
/// `intent`, `requester`, `realm_id`, and `audience`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ResolveHandleContext<'a> {
    pub intent: Option<&'a str>,
    pub requester: Option<&'a str>,
    pub audience: Option<&'a str>,
    pub realm_id: Option<&'a str>,
    pub expected_did: Option<&'a str>,
    pub proof_challenge: Option<&'a str>,
    pub proofs: &'a [&'a str],
}

#[derive(Clone, Debug)]
pub struct CokretApiError {
    pub status: StatusCode,
    pub error: ErrorEnvelope,
}

impl fmt::Display for CokretApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cokret API returned {}: {}", self.status, self.error)
    }
}

impl std::error::Error for CokretApiError {}

const DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS: u64 = 5_000;

#[derive(Clone, Debug)]
pub enum AccountSubscribeSnapshotOutcome {
    Delta(ClientSyncResponse),
    ReconnectAfter {
        reconnect_after_ms: u64,
        reason: Option<String>,
        reset_cursor: bool,
    },
}

#[derive(Clone, Debug)]
pub struct AccountSubscribeReconnectAfter {
    pub reconnect_after_ms: u64,
    pub reason: Option<String>,
    pub reset_cursor: bool,
}

impl fmt::Display for AccountSubscribeReconnectAfter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.reason.as_deref() {
            Some(reason) => write!(
                f,
                "account subscribe requested reconnect after {} ms: {}",
                self.reconnect_after_ms, reason
            ),
            None => write!(
                f,
                "account subscribe requested reconnect after {} ms",
                self.reconnect_after_ms
            ),
        }
    }
}

impl std::error::Error for AccountSubscribeReconnectAfter {}

/// True when the server has *definitively* told us the session is dead.
///
/// We require an explicit error envelope code that names session loss
/// (`auth_expired`, `M_UNKNOWN_TOKEN`, `invalid_token`, `token_expired`)
/// on HTTP 401, or a session-grant-specific terminal denial such as
/// `capability_denied` / `session grant is not active: revoked`.
///
/// A bare 401 with no structured envelope is treated as a transient denial
/// — the caller should surface it to the user and let them retry rather
/// than wiping their session, persisted config, and bouncing them to the
/// sign-in page. The auto-retry layer in `send_with_retry` has already had
/// its shot before any error reaches the UI, so the residual 401 is most
/// often a reverse-proxy hiccup, a clock skew, or a server-side temp deny
/// — not a permanently dead token.
pub fn is_auth_expired_error(error: &anyhow::Error) -> bool {
    if is_terminal_session_grant_error(error) {
        return true;
    }
    error
        .downcast_ref::<CokretApiError>()
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

/// True when the error envelope says the persisted coauth session grant
/// itself is terminal (revoked, expired, locked, suspended, or otherwise
/// not active). Soland currently maps these through `capability_denied`
/// because the failure happens in the session-grant capability bridge, but
/// the client must treat them as session loss, not as an ordinary Space/
/// Flow capability denial.
pub fn is_terminal_session_grant_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<CokretApiError>()
        .is_some_and(is_terminal_session_grant_api_error)
}

fn is_terminal_session_grant_api_error(api_error: &CokretApiError) -> bool {
    let code = api_error.error.code();
    if matches!(
        code,
        "invalid_grant" | "grant_expired" | "grant_revoked" | "session_grant_revoked"
    ) {
        return true;
    }
    let message = api_error.error.message().to_ascii_lowercase();
    (api_error.status == StatusCode::FORBIDDEN || api_error.status == StatusCode::UNAUTHORIZED)
        && (code == "capability_denied"
            || code.ends_with(".capability_denied")
            || code == "unauthenticated"
            || code == "auth_expired")
        && terminal_session_grant_message(&message)
}

fn terminal_session_grant_message(message: &str) -> bool {
    message.contains("session grant")
        && (message.contains("revoked")
            || message.contains("not active")
            || message.contains("expired")
            || message.contains("locked")
            || message.contains("suspended"))
}

/// Recognise a `rate_limited` (HTTP 429) error envelope from the
/// server and return its advertised `retry_after_ms` so callers can
/// sleep for the server-suggested duration instead of the generic
/// exponential backoff. Wire constant is pulled from `cokret_sdk`
/// so a spec rename can't silently de-recognise the code.
///
/// Returns `Some(retry_after_ms)` on match (with 0 when the server
/// omitted the hint), `None` otherwise.
pub fn rate_limited_retry_after(error: &anyhow::Error) -> Option<u64> {
    use cokret_sdk::error::ERROR_CODE_RATE_LIMITED;
    let api_error = error.downcast_ref::<CokretApiError>()?;
    if api_error.error.code() != ERROR_CODE_RATE_LIMITED {
        return None;
    }
    Some(api_error.error.retry_after_ms().unwrap_or(0))
}

/// `true` when account subscribe rejected the cursor — either expired, invalid,
/// or with an integrity mismatch — so the SyncEngine knows to demote to
/// a `after=None` full sync instead of looping on the same broken cursor.
pub fn is_invalid_cursor_error(error: &anyhow::Error) -> bool {
    use cokret_sdk::error::ERROR_CODE_CURSOR_INTEGRITY_INVALID;
    use cokret_sdk::{ERROR_CODE_CURSOR_EXPIRED, ERROR_CODE_INVALID_PARAM};
    error
        .downcast_ref::<CokretApiError>()
        .is_some_and(|api_error| {
            let code = api_error.error.code();
            // `invalid_param` only counts when the message mentions the
            // cursor — soland uses it for generic schema rejections too.
            let cursor_message = api_error.error.message().to_lowercase().contains("cursor");
            matches!(
                code,
                code if code == ERROR_CODE_CURSOR_EXPIRED
                    || code == ERROR_CODE_CURSOR_INTEGRITY_INVALID
            ) || (cursor_message
                && matches!(code, code if code == ERROR_CODE_INVALID_PARAM || code == "invalid_cursor"))
        })
}

pub fn is_plaintext_visibility_policy_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<CokretApiError>()
        .is_some_and(|api_error| {
            let code = api_error.error.code();
            api_error.status == StatusCode::FORBIDDEN
                && (code == "policy_denied"
                    || code == "capability_denied"
                    || code.ends_with(".capability_denied"))
                && api_error
                    .error
                    .message()
                    .contains("plaintext_visible_services")
        })
}

pub fn is_space_membership_denied_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<CokretApiError>()
        .is_some_and(|api_error| {
            let code = api_error.error.code();
            let message = api_error.error.message().to_ascii_lowercase();
            api_error.status == StatusCode::FORBIDDEN
                && (code == "capability_denied" || code.ends_with(".capability_denied"))
                && message.contains("not a member")
        })
}

pub fn normalize_wait_for_sync_token(sync_token: &str) -> Option<String> {
    let sync_token = sync_token.trim();
    if sync_token.is_empty() || sync_token == "-" {
        return None;
    }
    let tokens = sync_token
        .split(',')
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        return None;
    }
    tokens
        .iter()
        .all(|candidate| {
            candidate
                .strip_prefix("ck:cursor:")
                .is_some_and(|payload| !payload.is_empty())
        })
        .then(|| tokens.join(","))
}

fn resolve_handle_request_body(handle: &str, context: ResolveHandleContext<'_>) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("handle".to_owned(), json!(handle));
    if let Some(intent) = context.intent.filter(|value| !value.trim().is_empty()) {
        body.insert("intent".to_owned(), json!(intent));
    }
    if let Some(requester) = context.requester.filter(|value| !value.trim().is_empty()) {
        body.insert("requester".to_owned(), json!(requester));
    }
    if let Some(audience) = context.audience.filter(|value| !value.trim().is_empty()) {
        body.insert("audience".to_owned(), json!(audience));
    }
    if let Some(realm_id) = context.realm_id.filter(|value| !value.trim().is_empty()) {
        body.insert("realm_id".to_owned(), json!(realm_id));
    }
    if let Some(expected_did) = context
        .expected_did
        .filter(|value| !value.trim().is_empty())
    {
        body.insert("expected_did".to_owned(), json!(expected_did));
    }
    if let Some(challenge) = context
        .proof_challenge
        .filter(|value| !value.trim().is_empty())
    {
        body.insert("proof_challenge".to_owned(), json!(challenge));
    }
    let proofs = context
        .proofs
        .iter()
        .map(|proof| proof.trim())
        .filter(|proof| !proof.is_empty())
        .collect::<Vec<_>>();
    if !proofs.is_empty() {
        body.insert("proofs".to_owned(), json!(proofs));
    }
    Value::Object(body)
}

fn canonical_invitee_handle(target: &str) -> anyhow::Result<String> {
    parse_user_handle(target)
        .map(|handle| handle.handle)
        .ok_or_else(|| {
            anyhow::anyhow!("invitee must be a DID or canonical handle `<localpart>:<domain>`")
        })
}

fn validate_invite_handle_resolution(
    resolved: &ResolveHandleResponse,
    expected_audience: &str,
) -> anyhow::Result<()> {
    match resolved.claim_audience() {
        Some(audience) if audience == expected_audience => {}
        Some(audience) => anyhow::bail!(
            "directory handle claim audience mismatch: expected `{expected_audience}`, got `{audience}`"
        ),
        None => anyhow::bail!(
            "directory resolve_handle(intent=invite) response did not include audience"
        ),
    }
    if !resolved.has_member_delivery_binding() {
        anyhow::bail!(
            "directory resolve_handle(intent=invite) response did not include member_delivery_binding"
        );
    }
    Ok(())
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

mod account;
mod agent;
mod blob;
mod directory;
mod events;
mod keys;
mod media;
mod mls;
mod moderation;
mod push;
mod realm;

impl CokretApi {
    pub fn new(base_url: &str) -> anyhow::Result<Self> {
        Self::new_with_options(base_url, CokretApiOptions::default())
    }

    pub fn new_with_options(base_url: &str, options: CokretApiOptions) -> anyhow::Result<Self> {
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
            chime_session_grant: None,
            chime_session_grant_proof: None,
            network_state: Arc::new(RwLock::new(NetworkState::Online)),
            cancel_token: None,
            events_describe_cache: Arc::new(OnceCell::new()),
        })
    }

    /// Attach the coauth session-grant material chime requires for
    /// push registration. `proof` should be present when the Principal
    /// Server validates the grant through coauth introspection.
    pub fn with_chime_session_grant(
        mut self,
        grant_jwt: impl Into<String>,
        proof: Option<SessionGrantIntrospectionProof>,
    ) -> Self {
        self.chime_session_grant = Some(grant_jwt.into());
        self.chime_session_grant_proof = proof;
        self
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

    /// Build a [`CokretPushClient`] that mirrors this api client's auth
    /// state. Optional `register_device_path` / `unregister_device_path`
    /// honor a bridge-discovered endpoint.
    fn push_client(
        &self,
        register_device_path: Option<&str>,
        unregister_device_path: Option<&str>,
    ) -> CokretPushClient {
        let mut client =
            CokretPushClient::new(self.base_url.as_str()).with_required_session_grant(true);
        if let Some(token) = self.access_token.as_deref() {
            client = client.with_bearer_token(token);
        }
        if let Some(grant) = self.chime_session_grant.as_deref()
            && let Ok(next) = client.clone().with_session_grant(grant)
        {
            client = next;
        }
        if let Some(proof) = self.chime_session_grant_proof.as_ref()
            && let Ok(next) = client
                .clone()
                .with_header("X-Cokret-Session-Grant-Challenge", &proof.challenge)
                .and_then(|client| {
                    client.with_header("X-Cokret-Session-Grant-Proof", &proof.proof_jwt)
                })
        {
            client = next;
        }
        if let Some(path) = register_device_path {
            client = client.with_register_device_path(path);
        }
        if let Some(path) = unregister_device_path {
            client = client.with_unregister_device_path(path);
        }
        client
    }

    /// I4 — demo crypto fallback gate. Wired by `#[cfg(feature =
    /// "demo-crypto")]`: when the feature is on, local loopback hosts may
    /// ship the dev-only placeholder ciphertext / device_signature; when
    /// the feature is off (default), the function ALWAYS returns an
    /// error and the dev placeholders never reach the wire. No runtime
    /// env-var override exists by design — production binaries are
    /// compiled `--no-default-features` (or any feature set excluding
    /// `demo-crypto`) and the entire fallback path is unreachable.
    #[cfg(feature = "demo-crypto")]
    fn ensure_demo_crypto_fallback_allowed(&self, label: &str) -> anyhow::Result<()> {
        if matches!(
            self.base_url.host_str().unwrap_or_default(),
            "localhost" | "127.0.0.1" | "::1" | "local.host"
        ) {
            return Ok(());
        }
        anyhow::bail!("{label} is disabled for non-local production servers")
    }

    /// Without the `demo-crypto` feature, the demo fallback is wholly
    /// disabled — even loopback hosts fail closed. This test-only guard
    /// keeps the fail-closed assertion next to the feature-enabled path.
    #[cfg(all(not(feature = "demo-crypto"), test))]
    fn ensure_demo_crypto_fallback_allowed(&self, label: &str) -> anyhow::Result<()> {
        anyhow::bail!(
            "{label} requires the `demo-crypto` build feature (compiled out of this binary)"
        )
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
            return Err(CokretApiError {
                status,
                error: decode_cokret_error(status, &bytes),
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
            return Err(CokretApiError {
                status,
                error: decode_cokret_error(status, &bytes),
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
        loop {
            // Check if request was cancelled
            if self.cancel_token.as_ref().is_some_and(|t| t.is_cancelled()) {
                return Err(anyhow::anyhow!("request cancelled"));
            }

            let Some(candidate) = request.try_clone() else {
                return Ok(request.send().await?);
            };
            // 401 handling lives at the app layer (`crate::session`): a
            // refresh future capturing Dioxus signals + wasm `reqwest` is
            // `!Send`, so the HTTP client can't own it. The client just
            // surfaces the 401; the caller re-mints and retries.
            match candidate.send().await {
                Ok(response) => {
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
            Some(sync_token) => request.header("x-cokret-wait-for", sync_token),
            None => request,
        }
    }

    fn with_write_request_headers(
        &self,
        request: reqwest::RequestBuilder,
        request_id: &str,
    ) -> reqwest::RequestBuilder {
        request
            .header("x-cokret-request-id", request_id)
            .header("idempotency-key", request_id)
    }
}

fn validate_outgoing_registered_payload(event: &EventEnvelope) -> anyhow::Result<()> {
    let catalog = cokret_sdk::schema::event_payload_validator_catalog();
    if !catalog
        .missing_payload_validators_for(std::iter::once(event.kind.as_str()))
        .is_empty()
    {
        return Ok(());
    }

    catalog
        .validate_payload(&event.kind, &event.payload)
        .map_err(|err| {
            anyhow::anyhow!(
                "outgoing event kind '{}' payload violates registered payload schema: {err}",
                event.kind
            )
        })
}

fn ensure_events_submit_batch_accepted(response: &Value) -> anyhow::Result<()> {
    let status = response
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("accepted");
    let rejected = response
        .get("rejected")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if rejected.is_empty() && matches!(status, "accepted" | "duplicate") {
        return Ok(());
    }

    let details = rejected
        .iter()
        .map(|item| {
            let id = item.get("id").and_then(Value::as_str).unwrap_or("unknown");
            let reason = item
                .get("reason_code")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let detail = item.get("detail").and_then(Value::as_str).unwrap_or("");
            if detail.is_empty() {
                format!("{id}:{reason}")
            } else {
                format!("{id}:{reason}:{detail}")
            }
        })
        .collect::<Vec<_>>()
        .join("; ");
    anyhow::bail!(
        "events batch submit was not fully accepted: status={status}, rejected=[{details}]"
    );
}

/// Round R2/R3 (T02) — default ephemeral TTL for long-lived ephemeral
/// fanout such as `ck.presence` / `ck.receipt.read`. 30 seconds is
/// comfortably below the 5-minute hard ceiling.
const EPHEMERAL_DEFAULT_TTL_SECS: i64 = 30;
const TYPING_EPHEMERAL_TTL_SECS: i64 = 5;

/// Round R2/R3 (T02) — build a `ck.typing` `EphemeralEnvelope`. Enforces
/// the kind allowlist + the 5-minute hard ceiling on `expires_at - sent_at`.
pub fn build_typing_envelope(
    realm_id: &str,
    actor_did: &str,
    device_id: Option<&str>,
    typing: bool,
) -> anyhow::Result<cokret_sdk::EphemeralEnvelope> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(TYPING_EPHEMERAL_TTL_SECS);
    let realm_id_wire = scope_id_as_realm_id(realm_id);
    let realm = cokret_sdk::RealmId::new(realm_id_wire.clone())
        .map_err(|err| anyhow::anyhow!("invalid realm_id for ck.typing: {err}"))?;
    let actor = cokret_sdk::Did::new(actor_did)
        .map_err(|err| anyhow::anyhow!("invalid actor_did for ck.typing: {err}"))?;
    let device = device_id
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            cokret_sdk::DeviceId::new(s)
                .map_err(|err| anyhow::anyhow!("invalid device_id for ck.typing: {err}"))
        })
        .transpose()?;
    cokret_sdk::EphemeralEnvelope::new(
        "ck.typing",
        realm,
        actor,
        device,
        now,
        expires_at,
        json!({
            "actor_id": actor_did,
            "realm_id": realm_id_wire,
            "scope_id": realm_id,
            "typing": typing,
            "ttl_ms": TYPING_EPHEMERAL_TTL_SECS * 1000
        }),
        None,
    )
    .map_err(|err| anyhow::anyhow!("typing envelope rejected: {err}"))
}

/// Round R2/R3 (T02) — build a `ck.receipt.read` `EphemeralEnvelope`.
pub fn build_receipt_read_envelope(
    realm_id: &str,
    actor_did: &str,
    event_id: &str,
) -> anyhow::Result<cokret_sdk::EphemeralEnvelope> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(EPHEMERAL_DEFAULT_TTL_SECS);
    let realm_id_wire = scope_id_as_realm_id(realm_id);
    let realm = cokret_sdk::RealmId::new(realm_id_wire.clone())
        .map_err(|err| anyhow::anyhow!("invalid realm_id for ck.receipt.read: {err}"))?;
    let actor = cokret_sdk::Did::new(actor_did)
        .map_err(|err| anyhow::anyhow!("invalid actor_did for ck.receipt.read: {err}"))?;
    cokret_sdk::EphemeralEnvelope::new(
        "ck.receipt.read",
        realm,
        actor,
        None,
        now,
        expires_at,
        json!({
            "receipt_type": "read",
            "schema": "ck.schema.read_receipt.v1",
            "realm_id": realm_id_wire,
            "actor_id": actor_did,
            "event_id": event_id,
            "created_at": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        }),
        None,
    )
    .map_err(|err| anyhow::anyhow!("read receipt envelope rejected: {err}"))
}

/// Round R2/R3 (T02) — build a `ck.presence` `EphemeralEnvelope`.
pub fn build_presence_envelope(
    realm_id: &str,
    actor_did: &str,
    status: &str,
    last_active_at: Option<chrono::DateTime<chrono::Utc>>,
) -> anyhow::Result<cokret_sdk::EphemeralEnvelope> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(EPHEMERAL_DEFAULT_TTL_SECS);
    let realm = cokret_sdk::RealmId::new(realm_id)
        .map_err(|err| anyhow::anyhow!("invalid realm_id for ck.presence: {err}"))?;
    let actor = cokret_sdk::Did::new(actor_did)
        .map_err(|err| anyhow::anyhow!("invalid actor_did for ck.presence: {err}"))?;
    let mut payload = serde_json::Map::new();
    payload.insert("actor_id".into(), Value::String(actor_did.to_owned()));
    payload.insert("status".into(), Value::String(status.to_owned()));
    if let Some(ts) = last_active_at {
        payload.insert("last_active_at".into(), Value::String(ts.to_rfc3339()));
    }
    cokret_sdk::EphemeralEnvelope::new(
        "ck.presence",
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

/// Round 4 (spec a77b995) — build a `ck.call.signal` `EphemeralEnvelope`.
///
/// Wire-breaking vs. the round R2/R3 form: the payload shape moved from
/// `{call_id, kind, payload}` to the canonical
/// [`cokret_sdk::CallSignalPayload`] `{call_id, signal_type, seq, data}`
/// where `signal_type` MUST be one of [`cokret_sdk::CALL_SIGNAL_TYPES`]
/// (13 values: `invite`, `answer`, `candidate`, `renegotiate`, `hangup`,
/// `ack`, `reject`, `mute_state`, `media_state`, `speaking`, `focus_join`,
/// `focus_leave`, `error`). `device_id` + `proof` are REQUIRED on the
/// envelope; `seq` is strictly monotonic per
/// `(realm_id, call_id, actor, device)` (callers manage the counter via
/// [`cokret_sdk::CallSignalState`]).
///
/// The caller MUST attach a device-signed proof via the active
/// [`crate::event_signer`] before submit — the bare envelope returned
/// here carries `proof = None` and the submit guard / receiver will
/// reject it. See [`super::CokretApi::submit_call_signal_v1`] for the
/// signing + submit path.
pub fn build_call_signal_envelope_v1(
    realm_id: &str,
    actor_did: &str,
    device_id: &str,
    call_id: &str,
    signal_type: &str,
    seq: u64,
    data: Value,
) -> anyhow::Result<cokret_sdk::EphemeralEnvelope> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(EPHEMERAL_DEFAULT_TTL_SECS);
    let realm = cokret_sdk::RealmId::new(realm_id)
        .map_err(|err| anyhow::anyhow!("invalid realm_id for ck.call.signal: {err}"))?;
    let actor = cokret_sdk::Did::new(actor_did)
        .map_err(|err| anyhow::anyhow!("invalid actor_did for ck.call.signal: {err}"))?;
    if device_id.trim().is_empty() {
        anyhow::bail!("ck.call.signal requires non-empty device_id (round 4 schema_violation)");
    }
    let device = Some(
        cokret_sdk::DeviceId::new(device_id)
            .map_err(|err| anyhow::anyhow!("invalid device_id for ck.call.signal: {err}"))?,
    );
    if !cokret_sdk::CALL_SIGNAL_TYPES.contains(&signal_type) {
        anyhow::bail!("ck.call.signal signal_type {signal_type:?} not in canonical 13-value enum");
    }
    let call = cokret_sdk::CallId::new(call_id)
        .map_err(|err| anyhow::anyhow!("invalid call_id for ck.call.signal: {err}"))?;
    let payload = cokret_sdk::CallSignalPayload {
        call_id: call,
        signal_type: signal_type.to_owned(),
        seq,
        data,
    };
    payload
        .validate_signal_type()
        .map_err(|err| anyhow::anyhow!("ck.call.signal payload rejected: {err}"))?;
    cokret_sdk::EphemeralEnvelope::new(
        "ck.call.signal",
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
        let api_error = error.downcast_ref::<CokretApiError>()?;
        let code = api_error.error.code();
        match code {
            // Round R2/R3 wire codes from cokret_sdk::error.
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
/// [`CokretApi`] handle isn't available (e.g. read-only views that
/// already have the Principal Server `base_url` as a string). Keeps
/// the URL shape canonical so callers can't accidentally desync from
/// [`CokretApi::blob_download_url`].
pub fn blob_download_url_for(base_url: &str, blob_ref: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let blob_ref = query_component(canonical_blob_ref(blob_ref));
    format!("{base}/_cokret/self/blob/get?blob_ref={blob_ref}&purpose=profile_avatar")
}

fn canonical_blob_ref(blob_ref: &str) -> &str {
    blob_ref.split('#').next().unwrap_or(blob_ref).trim()
}

/// R3.1: `handle` is the canonical `<localpart>:<domain>` wire form
/// (renamed from `handle_uri` @ cokret-spec 7157ee8 — the `cokret://`
/// URI handle form has been retired).
#[derive(Clone, Debug, PartialEq, Eq)]
struct RealmBootstrapMember {
    actor_id: String,
    handle: Option<String>,
    delivery_binding: Option<Value>,
}

impl RealmBootstrapMember {
    fn from_did(did: &str) -> Self {
        Self {
            actor_id: did.trim().to_owned(),
            handle: None,
            delivery_binding: None,
        }
    }

    fn from_handle(handle: ParsedUserHandle) -> Self {
        let resolved_at = event_timestamp();
        Self {
            actor_id: handle.subject_did,
            handle: Some(handle.handle),
            delivery_binding: Some(json!({
                "recipient_service_did": handle.principal_server_did,
                "recipient_service_type": "principal_server",
                "binding_scope": "realm",
                "binding_source": "invite",
                "delivery_modes": ["events", "sync", "to_device", "push", "key_packages"],
                "resolved_at": resolved_at,
                "service_acceptance_ref": format!("ck:event:{}", uuid_v7()),
            })),
        }
    }
}

fn parse_realm_bootstrap_member(input: &str) -> anyhow::Result<RealmBootstrapMember> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow::anyhow!("seed member is empty"));
    }
    if trimmed.starts_with("did:") {
        return Ok(RealmBootstrapMember::from_did(trimmed));
    }
    if let Some(handle) = parse_user_handle(trimmed) {
        return Ok(RealmBootstrapMember::from_handle(handle));
    }
    Err(anyhow::anyhow!(
        "seed member must be a DID or handle like alice:example.com"
    ))
}

fn parse_realm_bootstrap_members(inputs: &[String]) -> anyhow::Result<Vec<RealmBootstrapMember>> {
    let mut members = Vec::new();
    for input in inputs {
        let member = parse_realm_bootstrap_member(input)?;
        if !members
            .iter()
            .any(|existing: &RealmBootstrapMember| existing.actor_id == member.actor_id)
        {
            members.push(member);
        }
    }
    Ok(members)
}

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
    digest_algorithm: &str,
    trust_domain: &str,
    invitees: &[String],
    plaintext_visible_services: &[String],
) -> anyhow::Result<Vec<EventEnvelope>> {
    // Spec realm-and-space.md §2.6: creator membership is auto-derived
    // by the reducer from `ck.realm.create`'s `created_by == actor_id`
    // (renamed from `created_by_principal` at spec head 37ce729).
    // The bootstrap MUST NOT emit an explicit `ck.member.state{join}` for
    // the creator — the reducer writes that cell atomically with the
    // create event.
    let mut events: Vec<EventEnvelope> = Vec::new();
    if history_visibility.trim() == "restricted" {
        return Err(anyhow::anyhow!(
            "restricted history_visibility requires a ck.realm.history_sharing_policy event in the same ordered batch"
        ));
    }
    let invitees = parse_realm_bootstrap_members(invitees)?;
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
        digest_algorithm,
        trust_domain,
        plaintext_visible_services,
    )?);
    events.push(build_space_state_event(
        space_id,
        actor_id,
        "ck.realm.join_rule",
        json!(join_rule),
    )?);
    events.push(build_space_state_event(
        space_id,
        actor_id,
        "ck.realm.history_visibility",
        json!(history_visibility),
    )?);
    events.push(build_space_state_event(
        space_id,
        actor_id,
        "ck.realm.discovery",
        json!(discoverability),
    )?);

    if let Some(event) =
        build_plaintext_visible_services_event(space_id, actor_id, plaintext_visible_services)?
    {
        events.push(event);
    }

    for invitee in invitees.iter() {
        if invitee.actor_id != actor_id {
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
    digest_algorithm: &str,
    trust_domain: &str,
    plaintext_visible_services: &[String],
) -> anyhow::Result<EventEnvelope> {
    // Per spec realm-and-space.md §2.3: high_assurance security_class
    // MUST satisfy federation_policy ∈ {closed, restricted, quarantine}.
    let effective_federation_policy =
        if security_class == "high_assurance" && federation_policy == "open" {
            "restricted"
        } else {
            federation_policy
        };
    let realm_object_id = scope_id_as_realm_id(space_id);
    let envelope_realm_id = scope_id_as_realm_id(space_id);
    let cell = space_cell("ck.component.realm.create.v1", &envelope_realm_id);
    let created_at_for_object = event_timestamp();
    let mut object = json!({
        "id": realm_object_id,
        "schema": "ck.schema.realm.v1",
        "title": title,
        "trust_domain": trust_domain,
        // Spec rename (head 37ce729 / SDK 4d5a1af): realm.schema.json
        // `created_by_principal` → `created_by`. No serde alias —
        // aggressive migration.
        "created_by": actor_id,
        "schema_refs": ["ck.schema.realm.v1"],
        "default_discoverability": discoverability,
        "default_join_rule": join_rule,
        "history_visibility": history_visibility,
        "encryption_profile": encryption_profile,
        "security_class": security_class,
        "federation_policy": effective_federation_policy,
        "anchor_profile": anchor_profile,
        "digest_algorithm": digest_algorithm,
        "anchorer": realm_genesis_anchorer(anchor_profile, actor_id),
        "created_at": created_at_for_object,
    });
    if let Some(summary) = summary
        && !summary.trim().is_empty()
    {
        object["summary"] = Value::String(summary.trim().to_owned());
    }
    let plaintext_services = plaintext_visible_services
        .iter()
        .map(|service| service.trim())
        .filter(|service| !service.is_empty())
        .map(|service| Value::String(service.to_owned()))
        .collect::<Vec<_>>();
    if !plaintext_services.is_empty() {
        object["plaintext_visible_services"] = Value::Array(plaintext_services);
    }

    // ck.component.realm.create.v1 is a cas-register cell; the
    // genesis write asserts head_eq null and sets the realm metadata.
    let preconditions = vec![Precondition {
        cell: cell.clone(),
        predicate: Predicate {
            op: "head_eq".to_owned(),
            value: Some(Value::Null),
            values: None,
            predicate_id: None,
        },
    }];
    let effects = vec![Effect {
        cell,
        op: LatticeOp {
            kind: "set".to_owned(),
            tag: None,
            value: Some(object.clone()),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
            element_id: None,
            predecessor: None,
        },
    }];
    let mut envelope = OperationBuilder::new(space_id, actor_id, "ck.realm.create")
        .target_ref(space_id)
        .body(json!({ "object": object }))
        .preconditions(preconditions)
        .effects(effects)
        .requirements(EventRequirements {
            schema: vec!["ck.schema.realm.v1".to_owned()],
            reducer: None,
            features: Vec::new(),
            critical_extensions: Vec::new(),
        })
        .build("yougen");
    envelope.created_at = created_at_for_object;
    Ok(envelope)
}

fn realm_genesis_anchorer(anchor_profile: &str, actor_id: &str) -> Value {
    match anchor_profile {
        "threshold" => json!({
            "type": "threshold",
            "members": [actor_id],
            "threshold": 1,
        }),
        "open_set" => json!({
            "type": "open_set",
            "members": [actor_id],
        }),
        "mixed" => json!({
            "type": "mixed",
            "did": actor_id,
            "recovery_members": [derived_recovery_member_did(actor_id)],
        }),
        _ => {
            let controller = inferred_controller_organization_did(actor_id);
            json!({
                "type": "single_did",
                "did": actor_id,
                "recovery_members": [derived_recovery_member_did(&controller)],
                "controller_organization": controller,
                "recovery_controller_organizations": [derived_recovery_controller_organization_did(&controller)],
            })
        }
    }
}

fn inferred_controller_organization_did(actor_id: &str) -> String {
    let actor_id = actor_id.trim();
    if let Some(web_specific_id) = actor_id.strip_prefix("did:web:")
        && let Some(host) = web_specific_id.split(':').next()
        && !host.is_empty()
    {
        return format!("did:web:{host}");
    }
    actor_id.to_owned()
}

fn derived_recovery_controller_organization_did(controller: &str) -> String {
    format!("{}:recovery", controller.trim())
}

fn derived_recovery_member_did(controller_or_actor: &str) -> String {
    format!("{}:recovery:anchorer", controller_or_actor.trim())
}

/// Build a `ck.space.create` event per spec realm-and-space.md §3.2.
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
    default_realm_id: Option<&str>,
) -> anyhow::Result<EventEnvelope> {
    let created_at = event_timestamp();
    let mut object = json!({
        "id": space_id,
        "schema": "ck.schema.space.v1",
        "realm_id": scope_id_as_realm_id(realm_id),
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
        object["parent_space_id"] = Value::String(parent.trim().to_owned());
    }
    if let Some(default_realm) = default_realm_id
        && !default_realm.trim().is_empty()
    {
        object["default_realm_id"] = Value::String(scope_id_as_realm_id(default_realm.trim()));
    }

    let cell = space_cell("ck.component.space.create.v1", space_id);
    let preconditions = vec![Precondition {
        cell: cell.clone(),
        predicate: Predicate {
            op: "head_eq".to_owned(),
            value: Some(Value::Null),
            values: None,
            predicate_id: None,
        },
    }];
    let effects = vec![Effect {
        cell,
        op: LatticeOp {
            kind: "set".to_owned(),
            tag: None,
            value: Some(object.clone()),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
            element_id: None,
            predecessor: None,
        },
    }];
    let mut envelope = OperationBuilder::new(realm_id, actor_id, "ck.space.create")
        .target_ref(space_id)
        .body(json!({ "object": object }))
        .preconditions(preconditions)
        .effects(effects)
        .requirements(EventRequirements {
            schema: vec!["ck.schema.space.v1".to_owned()],
            reducer: None,
            features: Vec::new(),
            critical_extensions: Vec::new(),
        })
        .build("yougen");
    envelope.created_at = created_at;
    Ok(envelope)
}

/// Build a Space lifecycle event (`ck.space.archive` /
/// `ck.space.restore` / `ck.space.tombstone`) per spec
/// realm-and-space.md §3.4. All three write the new `state` value
/// into the `ck.component.space.state.v1` cell on the home Realm via
/// an FSM transition.
pub fn build_space_lifecycle_event(
    space_id: &str,
    realm_id: &str,
    actor_id: &str,
    kind: &str,
) -> anyhow::Result<EventEnvelope> {
    let (prior_state, next_state) = match kind {
        "ck.space.archive" => ("active", "archived"),
        "ck.space.restore" => ("archived", "active"),
        // For tombstone, prior state may be either active or archived.
        // We assert via head_in {active, archived}, but the typed
        // helper only knows head_eq — so we model the explicit head_eq
        // against the most common source state (active). Reducer-side
        // FSM logic accepts the transition regardless of head form.
        "ck.space.tombstone" => ("active", "tombstoned"),
        other => {
            return Err(anyhow::anyhow!(
                "unsupported Space lifecycle event kind {other}"
            ));
        }
    };
    let created_at = event_timestamp();
    let cell = space_cell("ck.component.space.state.v1", space_id);
    let preconditions = vec![Precondition {
        cell: cell.clone(),
        predicate: Predicate {
            op: "head_eq".to_owned(),
            value: Some(Value::String(prior_state.to_owned())),
            values: None,
            predicate_id: None,
        },
    }];
    let effects = vec![Effect {
        cell,
        op: LatticeOp {
            kind: "transition".to_owned(),
            tag: None,
            value: None,
            from: Some(Value::String(prior_state.to_owned())),
            to: Some(Value::String(next_state.to_owned())),
            reason: None,
            issuer_seq: None,
            element_id: None,
            predecessor: None,
        },
    }];
    let mut envelope = OperationBuilder::new(realm_id, actor_id, kind)
        .target_ref(space_id)
        .body(json!({ "space_id": space_id }))
        .preconditions(preconditions)
        .effects(effects)
        .build("yougen");
    envelope.created_at = created_at;
    Ok(envelope)
}

/// Build a Realm facet state event (`ck.realm.join_rule`,
/// `ck.realm.history_visibility`, `ck.realm.discovery`, ...).
pub fn build_space_state_event(
    space_id: &str,
    actor_id: &str,
    kind: &str,
    value: Value,
) -> anyhow::Result<EventEnvelope> {
    let cell_family = match kind {
        "ck.realm.join_rule" => "ck.component.realm.join_rule.v1",
        "ck.realm.history_visibility" => "ck.component.realm.history_visibility.v1",
        "ck.realm.history_sharing_policy" => "ck.component.realm.history_sharing_policy.v1",
        "ck.realm.preview_policy" => "ck.component.realm.preview_policy.v1",
        "ck.realm.discovery" => "ck.component.realm.discovery.v1",
        "ck.realm.schema" => "ck.component.realm.schema.v1",
        "ck.realm.policy_components" => "ck.component.realm.policy_components.v1",
        other => {
            return Err(anyhow::anyhow!(
                "unsupported Realm state event kind {other}"
            ));
        }
    };
    let created_at = event_timestamp();
    let realm_id_wire = scope_id_as_realm_id(space_id);
    let cell = space_cell(cell_family, &realm_id_wire);
    let preconditions = vec![Precondition {
        cell: cell.clone(),
        predicate: Predicate {
            op: "head_eq".to_owned(),
            value: Some(Value::Null),
            values: None,
            predicate_id: None,
        },
    }];
    let effects = vec![Effect {
        cell,
        op: LatticeOp {
            kind: "set".to_owned(),
            tag: None,
            value: Some(value.clone()),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
            element_id: None,
            predecessor: None,
        },
    }];
    let mut envelope = OperationBuilder::new(space_id, actor_id, kind)
        .body(json!({ "value": value }))
        .preconditions(preconditions)
        .effects(effects)
        .build("yougen");
    envelope.created_at = created_at;
    Ok(envelope)
}

pub fn build_realm_history_sharing_policy_event(
    space_id: &str,
    actor_id: &str,
    policy: Value,
) -> anyhow::Result<EventEnvelope> {
    build_space_state_event(
        space_id,
        actor_id,
        "ck.realm.history_sharing_policy",
        policy,
    )
}

pub fn build_realm_preview_policy_event(
    space_id: &str,
    actor_id: &str,
    policy: Value,
) -> anyhow::Result<EventEnvelope> {
    build_space_state_event(space_id, actor_id, "ck.realm.preview_policy", policy)
}

/// Build a `ck.realm.plaintext_visible_services` event when the caller
/// supplies at least one service DID. Returns `None` when the input
/// list is empty so the bootstrap chain can skip emission entirely.
pub fn build_plaintext_visible_services_event(
    space_id: &str,
    actor_id: &str,
    service_dids: &[String],
) -> anyhow::Result<Option<EventEnvelope>> {
    let services = service_dids
        .iter()
        .map(|service| service.trim())
        .filter(|service| !service.is_empty())
        .map(|service| {
            json!({
                "service_did": service,
                "service_type": "principal_server",
                // Spec rename (head 37ce729 / SDK 4d5a1af): privacy / service
                // feature enums renamed `flow_body / message_body / body_only`
                // → `flow_content / message_content / content_only`. No serde
                // alias — aggressive migration.
                "data_classes": [
                    "message_content",
                    "full_text_index",
                    "notification_summary",
                    "inbox_preview",
                ],
                "purposes": ["message_index", "notification_fanout"],
                "visibility": "private_plaintext",
            })
        })
        .collect::<Vec<_>>();
    if services.is_empty() {
        return Ok(None);
    }
    let created_at = event_timestamp();
    let realm_id_wire = scope_id_as_realm_id(space_id);
    let cell = space_cell(
        "ck.component.realm.plaintext_visible_services.v1",
        &realm_id_wire,
    );
    let preconditions = vec![Precondition {
        cell: cell.clone(),
        predicate: Predicate {
            op: "head_eq".to_owned(),
            value: Some(Value::Null),
            values: None,
            predicate_id: None,
        },
    }];
    let body_value = json!({ "services": services });
    let effects = vec![Effect {
        cell,
        op: LatticeOp {
            kind: "set".to_owned(),
            tag: None,
            value: Some(body_value.clone()),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
            element_id: None,
            predecessor: None,
        },
    }];
    // Builder takes `Value` by move; reuse the value we already built for
    // the effect rather than cloning `services` a second time.
    let mut envelope =
        OperationBuilder::new(space_id, actor_id, "ck.realm.plaintext_visible_services")
            .body(body_value)
            .preconditions(preconditions)
            .effects(effects)
            .build("yougen");
    envelope.created_at = created_at;
    Ok(Some(envelope))
}

fn build_member_state_event(
    space_id: &str,
    actor_id: &str,
    member: &RealmBootstrapMember,
    membership: &str,
) -> anyhow::Result<EventEnvelope> {
    build_member_state_transition_event_with_binding(
        space_id,
        actor_id,
        &member.actor_id,
        None,
        membership,
        "space_create",
        member.handle.as_deref(),
        member.delivery_binding.clone(),
    )
}

/// Build a generic `ck.member.state` event on `ck.component.member.state.v1`,
/// modeling a single FSM transition (e.g. `join → leave` kick, `join → ban`
/// member ban, `null → join` invite-accept). `reason` shows up in the audit
/// trail.
pub fn build_member_state_transition_event(
    realm_id: &str,
    actor_id: &str,
    member_actor_id: &str,
    from_state: Option<&str>,
    to_state: &str,
    reason: &str,
) -> anyhow::Result<EventEnvelope> {
    build_member_state_transition_event_with_binding(
        realm_id,
        actor_id,
        member_actor_id,
        from_state,
        to_state,
        reason,
        None,
        None,
    )
}

pub fn build_member_state_invite_accept_event(
    realm_id: &str,
    actor_id: &str,
    invite_id: &str,
) -> anyhow::Result<EventEnvelope> {
    let invite_id = invite_id.trim();
    if invite_id.is_empty() {
        return Err(anyhow::anyhow!("invite_id is required for invite accept"));
    }
    let mut envelope = build_member_state_transition_event(
        realm_id,
        actor_id,
        actor_id,
        Some("invite"),
        "join",
        "invite_accept",
    )?;
    envelope.payload["invite_ref"] = json!(invite_id);
    Ok(envelope)
}

fn build_member_state_transition_event_with_binding(
    realm_id: &str,
    actor_id: &str,
    member_actor_id: &str,
    from_state: Option<&str>,
    to_state: &str,
    reason: &str,
    handle: Option<&str>,
    delivery_binding: Option<Value>,
) -> anyhow::Result<EventEnvelope> {
    let created_at = event_timestamp();
    let mut payload = json!({
        "actor_id": member_actor_id,
        "membership": to_state,
        "reason": reason,
    });
    if to_state == "join" {
        payload["delivery_status"] = json!("unroutable");
    }
    // R3.1: spec field is `handle` (`<localpart>:<domain>`); the prior
    // `handle_uri` (`cokret://`) form has been retired @ 7157ee8.
    if let Some(handle) = handle
        && !handle.trim().is_empty()
    {
        payload["handle"] = json!(handle);
    }
    if let Some(delivery_binding) = delivery_binding {
        payload["delivery_binding"] = delivery_binding;
    }
    let realm_id_wire = scope_id_as_realm_id(realm_id);
    let cell = format!(
        "{}:{}",
        space_cell("ck.component.member.state.v1", &realm_id_wire),
        member_actor_id
    );
    let preconditions = if let Some(prior) = from_state {
        vec![Precondition {
            cell: cell.clone(),
            predicate: Predicate {
                op: "head_eq".to_owned(),
                value: Some(Value::String(prior.to_owned())),
                values: None,
                predicate_id: None,
            },
        }]
    } else {
        vec![Precondition {
            cell: cell.clone(),
            predicate: Predicate {
                op: "head_eq".to_owned(),
                value: Some(Value::Null),
                values: None,
                predicate_id: None,
            },
        }]
    };
    let from_value = from_state
        .map(|s| Value::String(s.to_owned()))
        .unwrap_or(Value::Null);
    let effects = vec![Effect {
        cell,
        op: LatticeOp {
            kind: "transition".to_owned(),
            tag: None,
            value: None,
            from: Some(from_value),
            to: Some(Value::String(to_state.to_owned())),
            reason: Some(reason.to_owned()),
            issuer_seq: None,
            element_id: None,
            predecessor: None,
        },
    }];
    let mut envelope = OperationBuilder::new(realm_id, actor_id, "ck.member.state")
        .target_ref(member_actor_id)
        .body(payload)
        .preconditions(preconditions)
        .effects(effects)
        .build("yougen");
    envelope.created_at = created_at;
    Ok(envelope)
}

/// RFC3339 timestamp in the canonical wire form soland's
/// `canonical::validate_timestamp_canonical` accepts: exactly
/// `YYYY-MM-DDTHH:MM:SSZ` (20 chars, UTC `Z` suffix, NO fractional
/// seconds — spec encoding.md §3.5).
fn event_timestamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn space_cell(cell_family: &str, space_id: &str) -> String {
    format!("ck:cell:{cell_family}:{space_id}")
}

/// Build the canonical `ck.schema.device_message.v1` envelope:
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
/// client; used by [`CokretApi::send_device_message_envelope`] (R3).
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
        "type": "ck.device.verification.proof.v1",
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
    let canonical = cokret_sdk::canonical::canonical_json_bytes(&body)
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
            "payload_digest": format!("sha256:{:x}", Sha256::digest(&canonical)),
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
///   1. The canonical wrapped shape `{ "error": ErrorEnvelope }` (what our principal server emits
///      when its inner handler bubbles a typed envelope through the outer `ApiErrorBody`).
///   2. A bare envelope `{ "ok": false, "error": { code, message }, request_id? }` — same shape, no
///      wrapping. The SDK's [`ErrorEnvelope`] requires `request_id`, so we tolerate its absence via
///      a local shadow type that defaults it to `"unknown"`.
///
/// If none match, we synthesise a minimal envelope tagged
/// `ck.error.http_status` so downstream code always has something
/// well-formed to surface.
///
/// G3.Y3 — additionally, when `status` is 403 *and* the decoded
/// envelope carries a policy-shaped code, dispatch a
/// [`crate::components::PolicyDenyEvent`] so the global banner picks
/// it up without each call site having to wire its own UI. The
/// obligations array (per `authz/policy-server.md` §3) is pulled from
/// the envelope's `details["obligations"]` slot if present.
pub fn decode_cokret_error(status: StatusCode, bytes: &[u8]) -> ErrorEnvelope {
    #[derive(serde::Deserialize)]
    struct PlainEnvelope {
        #[serde(default)]
        ok: bool,
        error: cokret_sdk::ErrorDetail,
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
    #[derive(serde::Deserialize)]
    struct WrappedPlainEnvelope {
        error: PlainEnvelope,
        #[serde(default)]
        request_id: Option<String>,
    }
    impl From<WrappedPlainEnvelope> for ErrorEnvelope {
        fn from(value: WrappedPlainEnvelope) -> Self {
            let mut envelope: ErrorEnvelope = value.error.into();
            if envelope.request_id == "unknown"
                && let Some(request_id) = value.request_id
            {
                envelope.request_id = request_id;
            }
            envelope
        }
    }
    let envelope = if let Ok(body) = serde_json::from_slice::<ApiErrorBody>(bytes) {
        body.error
    } else if let Ok(wrapped_plain) = serde_json::from_slice::<WrappedPlainEnvelope>(bytes) {
        wrapped_plain.into()
    } else if let Ok(plain) = serde_json::from_slice::<PlainEnvelope>(bytes) {
        plain.into()
    } else {
        ErrorEnvelope::new(
            "http_status",
            format!("HTTP request failed with status {status}"),
        )
    };

    maybe_dispatch_policy_deny(status, &envelope);
    // CXP-0007 P3B.3 — also surface any of the 6 Circle reason codes
    // as a global toast. The two dispatchers are independent: the
    // policy deny banner targets 403 + policy code, the circle toast
    // targets the CXP-0007 reason / error code family on any status.
    let reason = envelope
        .details()
        .get("reason")
        .and_then(|v| v.as_str())
        .or_else(|| {
            envelope
                .details()
                .get("reason_code")
                .and_then(|v| v.as_str())
        });
    crate::components::maybe_dispatch_circle_error(envelope.code(), reason);
    // P5 — surface request_id in tracing logs so server + client
    // logs cross-reference on the same ID. The ID may have come from
    // the body or (when callers use `decode_cokret_error_with_header`)
    // from the response header.
    tracing::warn!(
        target: "yougen.api",
        request_id = %envelope.request_id,
        status = %status.as_u16(),
        code = %envelope.code(),
        "cokret error envelope decoded"
    );
    envelope
}

/// Same as [`decode_cokret_error`], but also threads the
/// `x-cokret-request-id` response header so the resulting envelope
/// carries the soland trace ID even when the body's `request_id` slot
/// was missing or `"unknown"`.
///
/// P5: callers that have access to the `reqwest::Response::headers()`
/// map (currently only a few hot paths) should switch to this helper
/// so error toasts can render the **Copy ID** button consistently.
pub fn decode_cokret_error_with_header(
    status: StatusCode,
    bytes: &[u8],
    response_request_id: Option<&str>,
) -> ErrorEnvelope {
    let mut envelope = decode_cokret_error(status, bytes);
    if let Some(id) = response_request_id {
        let trimmed = id.trim();
        if !trimmed.is_empty()
            && (envelope.request_id == "unknown" || envelope.request_id.is_empty())
        {
            envelope.request_id = trimmed.to_owned();
        }
    }
    envelope
}

/// G3.Y3 — on a 403 with a policy-shaped envelope, push a
/// [`crate::components::PolicyDenyEvent`] onto the global queue so the
/// `PolicyDenyBanner` mounted near the app shell surfaces it without
/// each call site needing to plumb its own error UI.
///
/// Skips auth-expired codes (those have their own session-death
/// redirect path) and any non-403 statuses.
fn maybe_dispatch_policy_deny(status: StatusCode, envelope: &ErrorEnvelope) {
    if status != StatusCode::FORBIDDEN {
        return;
    }
    let code = envelope.code();
    if !crate::components::is_policy_deny_code(code) {
        return;
    }
    // Obligations may arrive under `details["obligations"]` (preferred,
    // per the signed-transcript shape) or under a top-level
    // `obligations` field on the envelope itself. We honour both.
    let obligations: Vec<Value> = envelope
        .details()
        .get("obligations")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    crate::components::push_policy_deny(crate::components::PolicyDenyEvent::new(
        code.to_owned(),
        envelope.message().to_owned(),
        obligations,
    ));
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

fn path_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(&mut encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn safe_blob_filename_header(filename: &str) -> Option<String> {
    let basename = filename
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .trim()
        .trim_matches('"');
    let mut sanitized = String::new();
    for ch in basename.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
            sanitized.push(ch);
        } else if ch.is_ascii_whitespace() || ch.is_ascii_punctuation() {
            sanitized.push('_');
        }
        if sanitized.len() >= 128 {
            break;
        }
    }
    let sanitized = sanitized
        .trim_matches(|ch| matches!(ch, '.' | '_' | '-' | ' '))
        .to_owned();
    (!sanitized.is_empty()).then_some(sanitized)
}

/// H3 — central guard for the `ck:cursor:*` prefix invariant. Every yougen
/// entry point that takes a cursor / `next_cursor` / `after` query argument
/// passes it through this helper before going on the wire. The nil-initial
/// account subscribe case (`after: None`) is handled by callers using
/// `Option::map` so this never runs against an `""` placeholder.
pub(crate) fn validate_cursor(cursor: &str) -> anyhow::Result<()> {
    if cursor.is_empty() {
        return Ok(());
    }
    if !cursor.starts_with("ck:cursor:") {
        anyhow::bail!("cursor must start with `ck:cursor:` (got `{}`)", cursor);
    }
    Ok(())
}

fn events_query_path(space_id: &str) -> String {
    format!(
        "_cokret/self/events/query?realms={}",
        query_component(space_id)
    )
}

// Consumed only by the native (`not(wasm32)`) `events_subscribe_ndjson`
// streaming reader; the wasm build has no streaming subscribe path yet.
#[cfg(not(target_arch = "wasm32"))]
fn events_subscribe_path(
    space_id: &str,
    after: Option<&str>,
    include_history: Option<bool>,
) -> String {
    let mut url = format!(
        "_cokret/self/events/subscribe?realms={}",
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
/// [`cokret_sdk::EventsSubscribeFrameBody`] (tag = "kind",
/// snake_case-discriminated). Wire-breaking: the pre-round-4 untyped
/// string-line parser is deleted.
pub fn parse_events_subscribe_ndjson_text(
    input: &str,
) -> anyhow::Result<Vec<cokret_sdk::EventsSubscribeFrameBody>> {
    let mut frames = Vec::new();
    for line in input.lines() {
        if let Some(frame) = parse_events_subscribe_ndjson_line(line.as_bytes())? {
            frames.push(frame);
        }
    }
    Ok(frames)
}

// Consumed only by the native (`not(wasm32)`) streaming reader
// (`drain_events_subscribe_response` / `events_subscribe_stream`).
#[cfg(not(target_arch = "wasm32"))]
fn drain_events_subscribe_ndjson_lines<F>(
    pending: &mut Vec<u8>,
    on_frame: &mut F,
) -> anyhow::Result<()>
where
    F: FnMut(cokret_sdk::EventsSubscribeFrameBody) -> anyhow::Result<()>,
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
) -> anyhow::Result<Option<cokret_sdk::EventsSubscribeFrameBody>> {
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

#[cfg(test)]
fn parse_account_subscribe_snapshot(bytes: &[u8]) -> anyhow::Result<ClientSyncResponse> {
    match parse_account_subscribe_snapshot_outcome(bytes)? {
        AccountSubscribeSnapshotOutcome::Delta(response) => Ok(response),
        AccountSubscribeSnapshotOutcome::ReconnectAfter {
            reconnect_after_ms,
            reason,
            reset_cursor,
        } => Err(AccountSubscribeReconnectAfter {
            reconnect_after_ms,
            reason,
            reset_cursor,
        }
        .into()),
    }
}

fn parse_account_subscribe_snapshot_outcome(
    bytes: &[u8],
) -> anyhow::Result<AccountSubscribeSnapshotOutcome> {
    for line in bytes.split(|byte| *byte == b'\n') {
        let trimmed = trim_ascii(line);
        if trimmed.is_empty() {
            continue;
        }
        let frame: cokret_sdk::AccountSubscribeFrame = serde_json::from_slice(trimmed)?;
        if frame.requires_resubscribe() {
            let reset_cursor = frame.kind == cokret_sdk::AccountSubscribeFrameKind::ResyncRequired;
            return Ok(AccountSubscribeSnapshotOutcome::ReconnectAfter {
                reconnect_after_ms: frame
                    .reconnect_after_ms()
                    .unwrap_or(DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS),
                reason: frame.reason,
                reset_cursor,
            });
        }
        if let Some(response) = ClientSyncResponse::from_account_subscribe_frame(frame) {
            return Ok(AccountSubscribeSnapshotOutcome::Delta(response));
        }
    }
    anyhow::bail!("account subscribe stream ended before a delta frame")
}

pub fn parse_sync_describe(value: Value) -> anyhow::Result<SyncDescribeResBody> {
    Ok(serde_json::from_value(value)?)
}

pub fn parse_directory_describe(value: Value) -> anyhow::Result<DirectoryDescribeResBody> {
    Ok(serde_json::from_value(value)?)
}

pub fn parse_resolve_realm(value: Value) -> anyhow::Result<ResolveRealmResponse> {
    Ok(serde_json::from_value(value)?)
}

fn select_join_candidate<'a>(
    resolved: &'a ResolveRealmResponse,
    join_method: &str,
) -> anyhow::Result<&'a RealmJoinCandidate> {
    let realm_id = scope_id_as_realm_id(resolved.realm_preview.projection_realm_id());
    resolved
        .join_candidates
        .iter()
        .filter(|candidate| candidate.realm_id == realm_id)
        .filter(|candidate| {
            candidate
                .operations
                .iter()
                .any(|op| op == "ck.events.submit")
        })
        .filter(|candidate| {
            candidate
                .join_methods
                .iter()
                .any(|method| method == join_method)
        })
        .filter(|candidate| join_candidate_is_current(candidate))
        .min_by(|left, right| {
            left.priority
                .unwrap_or(u16::MAX)
                .cmp(&right.priority.unwrap_or(u16::MAX))
                .then_with(|| left.service_did.cmp(&right.service_did))
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "resolve_realm did not return a current join candidate for {join_method}"
            )
        })
}

fn join_candidate_is_current(candidate: &RealmJoinCandidate) -> bool {
    chrono::DateTime::parse_from_rfc3339(&candidate.expires_at)
        .map(|expires_at| expires_at.with_timezone(&chrono::Utc) > chrono::Utc::now())
        .unwrap_or(false)
}

fn patch_touches_create_locked_encryption_profile(patch: &Value) -> bool {
    patch.as_object().is_some_and(|fields| {
        fields.iter().any(|(key, value)| {
            patch_key_touches_encryption_profile(key)
                || (key == "object" && patch_value_has_direct_encryption_profile(value))
        })
    })
}

fn patch_key_touches_encryption_profile(key: &str) -> bool {
    key == "encryption_profile"
        || key.starts_with("encryption_profile.")
        || key == "/encryption_profile"
        || key.starts_with("/encryption_profile/")
        || key == "object.encryption_profile"
        || key.starts_with("object.encryption_profile.")
        || key == "/object/encryption_profile"
        || key.starts_with("/object/encryption_profile/")
}

fn patch_value_has_direct_encryption_profile(value: &Value) -> bool {
    value
        .get("value")
        .unwrap_or(value)
        .as_object()
        .is_some_and(|fields| fields.contains_key("encryption_profile"))
}

#[cfg(test)]
mod tests {
    use reqwest::header::{HeaderMap, HeaderValue};

    use super::*;

    #[test]
    fn endpoint_join_keeps_api_paths_under_base_url() {
        let api = CokretApi::new("http://127.0.0.1:8787/").unwrap();
        assert_eq!(
            api.endpoint("/_cokret/describe").unwrap().as_str(),
            "http://127.0.0.1:8787/_cokret/describe"
        );
    }

    #[test]
    fn blob_download_url_strips_media_hint_before_query() {
        let url =
            blob_download_url_for("http://127.0.0.1:8787/", "ck:blob:sha256:abcdef#image/png");
        assert_eq!(
            url,
            "http://127.0.0.1:8787/_cokret/self/blob/get?blob_ref=ck%3Ablob%3Asha256%3Aabcdef&purpose=profile_avatar"
        );
    }

    #[test]
    fn path_component_percent_encodes_did_as_path_segment() {
        assert_eq!(
            path_component("did:web:agent.example"),
            "did%3Aweb%3Aagent.example"
        );
        assert_eq!(
            path_component("did:web:example.com:agents/alice"),
            "did%3Aweb%3Aexample.com%3Aagents%2Falice"
        );
    }

    #[test]
    fn blob_upload_filename_header_is_ascii_safe() {
        assert_eq!(
            safe_blob_filename_header("..\\danger<script>.txt").as_deref(),
            Some("danger_script_.txt")
        );
        assert_eq!(
            safe_blob_filename_header("数据库.dump"),
            Some("dump".to_owned())
        );
        assert_eq!(safe_blob_filename_header("🧪").as_deref(), None);
    }

    #[test]
    fn resolve_handle_request_body_carries_invite_context() {
        let body = resolve_handle_request_body(
            "bob:local.host",
            ResolveHandleContext {
                intent: Some("invite"),
                requester: Some("did:web:alice.example"),
                audience: Some("ck:realm:0196419b-0000-7000-8000-000000000001"),
                realm_id: Some("ck:realm:0196419b-0000-7000-8000-000000000001"),
                expected_did: Some("did:web:bob.example"),
                proof_challenge: Some("ck:challenge:test"),
                proofs: &["proof-a", "  ", "proof-b"],
            },
        );

        assert_eq!(body["handle"], "bob:local.host");
        assert_eq!(body["intent"], "invite");
        assert_eq!(body["requester"], "did:web:alice.example");
        assert_eq!(
            body["audience"],
            "ck:realm:0196419b-0000-7000-8000-000000000001"
        );
        assert_eq!(
            body["realm_id"],
            "ck:realm:0196419b-0000-7000-8000-000000000001"
        );
        assert_eq!(body["expected_did"], "did:web:bob.example");
        assert_eq!(body["proof_challenge"], "ck:challenge:test");
        assert_eq!(body["proofs"], json!(["proof-a", "proof-b"]));
    }

    #[test]
    fn canonical_invitee_handle_accepts_display_alias() {
        assert_eq!(
            canonical_invitee_handle("@Bob:Local.Host").unwrap(),
            "bob:local.host"
        );
    }

    #[test]
    fn invite_handle_resolution_requires_bound_candidate_material() {
        let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000001";
        let resolved: ResolveHandleResponse = serde_json::from_value(json!({
            "subject": "did:web:bob.example",
            "handle": "bob:local.host",
            "handle_claim": {
                "subject": "did:web:bob.example",
                "audience": realm_id,
                "member_delivery_binding": {
                    "recipient_service_did": "did:web:local.host",
                    "recipient_service_type": "principal_server",
                    "binding_source": "explicit",
                    "delivery_modes": ["events"]
                }
            }
        }))
        .unwrap();

        assert_eq!(resolved.subject_did(), Some("did:web:bob.example"));
        validate_invite_handle_resolution(&resolved, realm_id).unwrap();

        let missing_binding: ResolveHandleResponse = serde_json::from_value(json!({
            "did": "did:web:bob.example",
            "handle": "bob:local.host",
            "audience": realm_id
        }))
        .unwrap();
        let error = validate_invite_handle_resolution(&missing_binding, realm_id)
            .expect_err("invite resolution must carry delivery binding material");
        assert!(error.to_string().contains("member_delivery_binding"));
    }

    #[test]
    fn realm_metadata_patch_rejects_create_locked_encryption_profile() {
        assert!(patch_touches_create_locked_encryption_profile(&json!({
            "encryption_profile": "none"
        })));
        assert!(patch_touches_create_locked_encryption_profile(&json!({
            "/encryption_profile": { "$op": "replace", "value": "none" }
        })));
        assert!(patch_touches_create_locked_encryption_profile(&json!({
            "object": {
                "value": {
                    "encryption_profile": "none"
                }
            }
        })));
        assert!(!patch_touches_create_locked_encryption_profile(&json!({
            "title": "Renamed Realm",
            "summary": "Still editable"
        })));
    }

    #[test]
    fn lifecycle_projection_response_accepts_soland_legacy_keys() {
        let spaces: LifecycleProjectionResponse<SpaceContainerProjectionView> =
            serde_json::from_value(json!({
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "total": 1,
                "space_containers": [{
                    "container_space_id": "ck:space:01904100-0000-7000-8000-f10dc0000001",
                    "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                    "kind": "board",
                    "title": "Launch board",
                    "state": "active"
                }]
            }))
            .unwrap();
        assert_eq!(spaces.items.len(), 1);
        assert_eq!(spaces.items[0].kind, "board");

        let canonical_spaces: LifecycleProjectionResponse<SpaceContainerProjectionView> =
            serde_json::from_value(json!({
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "total": 1,
                "spaces": [{
                    "space_id": "ck:space:01904100-0000-7000-8000-f10dc0000001",
                    "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                    "kind": "board",
                    "title": "Launch board",
                    "state": "active"
                }]
            }))
            .unwrap();
        assert_eq!(
            canonical_spaces.items[0].container_space_id,
            "ck:space:01904100-0000-7000-8000-f10dc0000001"
        );

        let flows: LifecycleProjectionResponse<FlowProjectionView> =
            serde_json::from_value(json!({
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "flows": [{
                    "flow_id": "ck:flow:01904100-0000-7000-8000-f20dc0000001",
                    "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                    "title": "Card",
                    "summary": "Projection-backed card",
                    "board_space_id": "ck:space:01904100-0000-7000-8000-b0ard0000001",
                    "list_space_id": "ck:space:01904100-0000-7000-8000-l15t00000001",
                    "rank": "U",
                    "fields": { "labels": ["demo"] },
                    "state": "archived"
                }]
            }))
            .unwrap();
        assert_eq!(flows.items[0].realm_id, flows.realm_id);
        assert_eq!(flows.items[0].state, "archived");
        assert_eq!(
            flows.items[0].board_space_id.as_deref(),
            Some("ck:space:01904100-0000-7000-8000-b0ard0000001")
        );
    }

    #[test]
    fn typing_envelope_uses_spec_ephemeral_shape() {
        let envelope = build_typing_envelope(
            "ck:space:0196419b-0000-7000-8000-000000000000",
            "did:web:alice.example",
            Some("ck:device:01904100-0000-7000-8000-a11ce0000001"),
            true,
        )
        .unwrap();

        assert_eq!(envelope.kind, "ck.typing");
        assert_eq!(
            envelope.realm_id.to_string(),
            "ck:realm:0196419b-0000-7000-8000-000000000000"
        );
        assert_eq!(
            envelope.payload["scope_id"],
            "ck:space:0196419b-0000-7000-8000-000000000000"
        );
        assert_eq!(
            envelope.payload["realm_id"],
            "ck:realm:0196419b-0000-7000-8000-000000000000"
        );
        assert_eq!(envelope.payload["actor_id"], "did:web:alice.example");
        assert_eq!(envelope.payload["typing"], true);
        assert!(
            !serde_json::to_value(&envelope)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("schema")
        );
    }

    #[test]
    fn read_receipt_envelope_uses_actor_not_event_as_sender() {
        let envelope = build_receipt_read_envelope(
            "ck:space:0196419b-0000-7000-8000-000000000000",
            "did:web:alice.example",
            "ck:event:01904100-0000-7000-8000-4a4116cba4e8",
        )
        .unwrap();

        assert_eq!(envelope.kind, "ck.receipt.read");
        assert_eq!(envelope.actor_id.to_string(), "did:web:alice.example");
        assert_eq!(
            envelope.realm_id.to_string(),
            "ck:realm:0196419b-0000-7000-8000-000000000000"
        );
        assert_eq!(envelope.payload["actor_id"], "did:web:alice.example");
        assert_eq!(
            envelope.payload["event_id"],
            "ck:event:01904100-0000-7000-8000-4a4116cba4e8"
        );
        assert_eq!(envelope.payload["schema"], "ck.schema.read_receipt.v1");
        assert!(
            !serde_json::to_value(&envelope)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("schema")
        );
    }

    #[test]
    fn parses_server_and_sync_payloads() {
        let description = parse_server_description(json!({
            "service_did": "did:web:server.local",
            "trust_domain": "ck:trust_domain:server.local",
            "service_type": "principal_server",
            "protocol_version": "1.0",
            "supported_profiles": [],
            "supported_features": ["account.subscribe"],
            "supported_operations": ["ck.account.subscribe"],
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
            "cursor": "ck:cursor:test-1",
            "spaces": {
                "ck:space:0196419b-0000-7000-8000-000000000000": {"summary": {}}
            },
            "to_device": [],
            "account_data": [],
            "device_lists": {"changed": [], "left": []}
        }))
        .unwrap();
        assert_eq!(sync.spaces.len(), 1);
        assert_eq!(sync.cursor, "ck:cursor:test-1");

        // Spec-aligned wire shape per `client-sync.md §2`: flat
        // `spaces` keyed by realm id, explicit `left_spaces`,
        // flat arrays for top-level streams. The SDK's
        // Canonical account subscribe snapshot shape.
        let sync_v1 = parse_sync(json!({
            "cursor": "ck:cursor:v1",
            "spaces": {
                "ck:space:joined": {
                    "summary": {"title": "Joined"}
                }
            },
            "left_spaces": ["ck:space:left"],
            "to_device": [{"type": "ck.mls.welcome"}],
            "account_data": [{"data_type": "client.ui", "content": {"theme": "system"}}],
            "device_lists": {"changed": [], "left": []},
            "notifications": {"events": []},
            "presence": []
        }))
        .unwrap();
        assert_eq!(sync_v1.cursor, "ck:cursor:v1");
        assert!(sync_v1.spaces.contains_key("ck:space:joined"));
        assert_eq!(sync_v1.left_spaces, vec!["ck:space:left".to_owned()]);
        assert_eq!(sync_v1.to_device.len(), 1);
        assert_eq!(sync_v1.account_data.len(), 1);
        assert!(sync_v1.notifications.is_object());
        assert!(sync_v1.presence.is_empty());

        let account_frame = parse_account_subscribe_snapshot(
            br#"{"kind":"delta","cursor":"ck:cursor:account-1","realms":{"ck:realm:019e4cdc-b435-7e52-9ada-39d5ec134729":{"summary":{"title":"Test"}}},"to_device":{"messages":[]},"device_lists":{"changed":[],"left":[]},"account_data":{"events":[]},"presence":{"events":[]},"notifications":null,"partial":false}
{"kind":"catchup_complete","cursor":"ck:cursor:account-1"}
"#,
        )
        .unwrap();
        assert_eq!(account_frame.cursor, "ck:cursor:account-1");
        assert!(
            account_frame
                .spaces
                .contains_key("ck:realm:019e4cdc-b435-7e52-9ada-39d5ec134729")
        );
        assert!(account_frame.left_spaces.is_empty());

        let reconnect = parse_account_subscribe_snapshot_outcome(
            br#"{"kind":"resync_required","reason":"compaction","reconnect_after_ms":10000}
"#,
        )
        .unwrap();
        match reconnect {
            AccountSubscribeSnapshotOutcome::ReconnectAfter {
                reconnect_after_ms,
                reason,
                reset_cursor,
            } => {
                assert_eq!(reconnect_after_ms, 10_000);
                assert_eq!(reason.as_deref(), Some("compaction"));
                assert!(reset_cursor);
            }
            other => panic!("expected reconnect outcome, got {other:?}"),
        }

        let directory = parse_directory_describe(json!({
            "service_did": "did:web:server.local",
            "resource_types": ["space", "organization", "actor"],
            "discovery_profiles": ["ck.profile.directory.v1"],
            "restricted_query_proof": false
        }))
        .unwrap();
        assert!(directory.resource_types.contains(&"space".to_owned()));
    }

    #[test]
    fn event_paths_use_v1_query_parameters() {
        let backfill = events_query_path("ck:space:demo");
        assert_eq!(
            backfill,
            "_cokret/self/events/query?realms=ck%3Aspace%3Ademo"
        );
        assert!(!backfill.contains("direction="));

        let subscribe = events_subscribe_path("ck:space:demo", Some("ck:cursor:demo"), Some(true));
        assert_eq!(
            subscribe,
            "_cokret/self/events/subscribe?realms=ck%3Aspace%3Ademo&after=ck%3Acursor%3Ademo&include_history=true"
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
            "ck:realm:0196419b-0000-7000-8000-000000000001",
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
            "ck:trust_domain:server.example",
            &["did:web:bob.example".to_owned()],
            &["did:web:server.example".to_owned()],
        )
        .unwrap();
        let kinds = events
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>();
        // Spec realm-and-space.md §2.6: the creator-join cell is
        // populated atomically by the reducer when it accepts
        // `ck.realm.create`. The bootstrap chain MUST NOT include an
        // explicit `ck.member.state{join}` for the creator.
        assert_eq!(
            kinds,
            vec![
                "ck.realm.create",
                "ck.realm.join_rule",
                "ck.realm.history_visibility",
                "ck.realm.discovery",
                "ck.realm.plaintext_visible_services",
                "ck.member.state",
            ]
        );

        let create = &events[0];
        assert_eq!(create.payload["object"]["schema"], "ck.schema.realm.v1");
        // Spec rename (head 37ce729 / SDK 4d5a1af): realm.schema.json
        // `created_by_principal` → `created_by`.
        assert_eq!(create.payload["object"]["created_by"], create.actor_id);
        assert_eq!(
            create.payload["object"]["created_at"].as_str().unwrap(),
            create.created_at,
            "Realm create cross-field semantic validation requires matching timestamps",
        );
        assert_eq!(create.payload["object"]["default_join_rule"], "invite");
        assert_eq!(create.payload["object"]["history_visibility"], "shared");
        assert_eq!(create.payload["object"]["anchorer"]["type"], "single_did");
        assert_eq!(create.payload["object"]["anchorer"]["did"], create.actor_id);
        assert_eq!(
            create.payload["object"]["anchorer"]["recovery_members"][0],
            "did:web:alice.example:recovery:anchorer",
        );
        assert_eq!(
            create.payload["object"]["anchorer"]["controller_organization"],
            "did:web:alice.example",
        );
        assert_eq!(
            create.payload["object"]["anchorer"]["recovery_controller_organizations"][0],
            "did:web:alice.example:recovery",
        );
        assert_eq!(
            create.effects[0].cell,
            "ck:cell:ck.component.realm.create.v1:ck:realm:0196419b-0000-7000-8000-000000000001"
        );
        assert_eq!(create.effects[0].op.kind, "set");
        // anchor_ref starts unset on the typed envelope. Realm genesis
        // has no snapshot head yet, so the create event relies on its
        // `head_eq null` precondition instead of a prior anchor.
        assert!(create.anchor_ref.is_none());
        // The typed builder leaves the envelope unsigned — the active
        // signer attaches the detached JWS proof at submit time.
        assert!(create.proofs.is_empty());

        // Bootstrap order: create, join_rule, history_visibility,
        // discovery, plaintext_visible, member-invite.
        assert_eq!(events[1].payload["value"], "invite");
        assert_eq!(events[2].payload["value"], "shared");
        assert_eq!(events[3].payload["value"], "listed");
        assert_eq!(
            events[4].payload["services"][0]["service_did"],
            "did:web:server.example"
        );
        assert_eq!(
            events[4].payload["services"][0]["data_classes"],
            json!([
                "message_content",
                "full_text_index",
                "notification_summary",
                "inbox_preview",
            ])
        );
        assert_eq!(events[5].payload["membership"], "invite");
    }

    #[test]
    fn realm_bootstrap_handle_seed_materializes_user_and_principal_server_dids() {
        let events = build_realm_bootstrap_events(
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "Engineering",
            None,
            "listed",
            "invite",
            "shared",
            "mls_rfc9420",
            "standard",
            "restricted",
            "single_did",
            "sha256",
            "ck:trust_domain:server.example",
            &["bob:example.com".to_owned()],
            &[],
        )
        .unwrap();
        let member = events
            .iter()
            .find(|event| event.kind == "ck.member.state")
            .expect("member state invite");

        assert_eq!(member.payload["actor_id"], "did:web:example.com:users:bob");
        assert_eq!(member.payload["handle"], "bob:example.com");
        assert_eq!(
            member.payload["delivery_binding"]["recipient_service_did"],
            "did:web:example.com"
        );
        assert_eq!(
            member.payload["delivery_binding"]["recipient_service_type"],
            "principal_server"
        );
        assert_eq!(member.payload["delivery_binding"]["binding_scope"], "realm");
        assert!(
            member.payload["delivery_binding"]["service_acceptance_ref"]
                .as_str()
                .is_some_and(|value| value.starts_with("ck:event:"))
        );
    }

    #[test]
    fn member_state_invite_accept_event_carries_invite_ref() {
        let event = build_member_state_invite_accept_event(
            "ck:space:0196419b-0000-7000-8000-000000000010",
            "did:web:bob.example",
            "ck:invite:0196419b-0000-7000-8000-000000000020",
        )
        .expect("invite accept event");

        assert_eq!(event.kind, "ck.member.state");
        assert_eq!(
            event.realm_id,
            "ck:realm:0196419b-0000-7000-8000-000000000010"
        );
        assert_eq!(event.actor_id, "did:web:bob.example");
        assert_eq!(event.payload["actor_id"], "did:web:bob.example");
        assert_eq!(event.payload["membership"], "join");
        assert_eq!(event.payload["reason"], "invite_accept");
        assert_eq!(
            event.payload["invite_ref"],
            "ck:invite:0196419b-0000-7000-8000-000000000020"
        );
        assert!(event.payload.get("invite_id").is_none());
        assert_eq!(event.payload["delivery_status"], "unroutable");
        assert_eq!(event.preconditions.len(), 1);
        assert_eq!(
            event.preconditions[0].predicate.value,
            Some(json!("invite"))
        );
        assert_eq!(event.effects.len(), 1);
        assert_eq!(event.effects[0].op.from, Some(json!("invite")));
        assert_eq!(event.effects[0].op.to, Some(json!("join")));
    }

    #[test]
    fn events_batch_response_rejects_partial_acceptance() {
        ensure_events_submit_batch_accepted(&json!({
            "status": "accepted",
            "accepted": ["ck:event:1"],
            "rejected": []
        }))
        .expect("fully accepted batch should pass");

        let err = ensure_events_submit_batch_accepted(&json!({
            "status": "partial",
            "accepted": ["ck:event:1"],
            "rejected": [
                {
                    "id": "ck:event:2",
                    "reason_code": "capability_denied",
                    "detail": "actor is not a member"
                }
            ]
        }))
        .expect_err("partial batch must fail fast");
        assert!(err.to_string().contains("capability_denied"));
    }

    #[test]
    fn outgoing_payload_schema_gate_accepts_sdk_object_patch_payload() {
        let flow_id = "ck:flow:0196419b-0000-7000-8000-000000000002";
        let mut patch = cokret_sdk::Patch::new();
        patch
            .insert_op(
                "fields.document",
                cokret_sdk::PatchOp::set(json!({ "blocks": [] })),
            )
            .unwrap();
        let payload = cokret_sdk::ObjectPatchPayload::for_target(flow_id, patch)
            .unwrap()
            .to_value()
            .unwrap();
        let event = OperationBuilder::new(
            "ck:realm:0196419b-0000-7000-8000-000000000010",
            "did:web:alice.example",
            "ck.flow.update",
        )
        .target_ref(flow_id)
        .body(payload)
        .build("yougen");

        validate_outgoing_registered_payload(&event).unwrap();
    }

    /// Contract test: ck.space.create payload must satisfy spec
    /// space.schema.json — same validator soland runs on the wire.
    #[test]
    fn space_create_payload_matches_spec_schema() {
        // Spec requires payload.object.realm_id to match the
        // `^ck:realm:UUID7` pattern. Caller (yougen UI) holds the home
        // Realm under its legacy ck:space: envelope id; the builder
        // must rewrite for the inner reference.
        let event = build_space_create_event(
            "ck:space:0196419b-0000-7000-8000-000000000010",
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "Roadmap",
            Some("Q3 planning"),
            "board",
            None,
            None,
        )
        .unwrap();
        let catalog = cokret_sdk::schema::event_payload_validator_catalog();
        if catalog
            .missing_payload_validators_for(std::iter::once(event.kind.as_str()))
            .is_empty()
            && let Err(error) = catalog.validate_payload(&event.kind, &event.payload)
        {
            panic!(
                "ck.space.create payload violates spec: {error}\npayload: {}",
                serde_json::to_string_pretty(&event.payload).unwrap_or_default()
            );
        }
    }

    /// Contract test: every event produced by `build_realm_bootstrap_events`
    /// MUST satisfy the spec payload-schema rule for its event kind, using
    /// the same `cokret_sdk::schema::event_payload_validator_catalog` that
    /// soland runs on the wire. Catches schema drift (missing required
    /// fields, wrong patterns) at `cargo test` rather than user runtime.
    #[test]
    fn realm_bootstrap_payloads_match_spec_schema() {
        let events = build_realm_bootstrap_events(
            "ck:realm:0196419b-0000-7000-8000-000000000001",
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
            "ck:trust_domain:server.example",
            &["did:web:bob.example".to_owned()],
            &["did:web:server.example".to_owned()],
        )
        .unwrap();

        let catalog = cokret_sdk::schema::event_payload_validator_catalog();
        for event in &events {
            if catalog
                .missing_payload_validators_for(std::iter::once(event.kind.as_str()))
                .is_empty()
                && let Err(error) = catalog.validate_payload(&event.kind, &event.payload)
            {
                panic!(
                    "event kind `{}` payload violates spec schema: {error}\n\
                     payload was: {}",
                    event.kind,
                    serde_json::to_string_pretty(&event.payload).unwrap_or_default()
                );
            }
        }
    }

    #[test]
    fn parses_events_subscribe_ndjson_frames() {
        // Round 4 typed frames carry the discriminator-required fields:
        // `heartbeat` requires `emitted_at`; `frontier` requires a nested
        // `frontier` value; `catchup_complete` is a unit variant.
        let frames = parse_events_subscribe_ndjson_text(
            r#"
{"kind":"heartbeat","emitted_at":"2026-05-20T00:00:00Z"}
{"kind":"frontier","frontier":{"ck:space:demo":["ck:event:01"]}}
{"kind":"catchup_complete"}
"#,
        )
        .unwrap();

        assert!(matches!(
            frames[0],
            cokret_sdk::EventsSubscribeFrameBody::Heartbeat { .. }
        ));
        assert!(matches!(
            &frames[1],
            cokret_sdk::EventsSubscribeFrameBody::Frontier { .. }
        ));
        assert!(matches!(
            &frames[2],
            cokret_sdk::EventsSubscribeFrameBody::CatchupComplete
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
            cokret_sdk::EventsSubscribeFrameBody::Heartbeat { .. }
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
            cokret_sdk::EventsSubscribeFrameBody::ResyncRequired { reason, .. } if reason == "server restart"
        ));
    }

    #[test]
    fn decodes_wrapped_cokret_error_envelope() {
        let decoded = decode_cokret_error(
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
        let decoded = decode_cokret_error(
            StatusCode::BAD_REQUEST,
            br#"{"ok":false,"error":{"code":"invalid_param","message":"invalid did"}}"#,
        );
        assert_eq!(decoded.code(), "invalid_param");

        // The SDK's ErrorEnvelope::new strips the `ck.error.` prefix in
        // `canonical_error_code` and we depend on that canonicalization so
        // downstream comparisons against the registry shape match.
        let fallback = decode_cokret_error(StatusCode::SERVICE_UNAVAILABLE, b"busy");
        assert_eq!(fallback.code(), "http_status");
        assert!(fallback.message().contains("503 Service Unavailable"));
    }

    #[test]
    fn decodes_canonical_error_envelope_with_request_id() {
        let decoded = decode_cokret_error(
            StatusCode::FORBIDDEN,
            br#"{"ok":false,"error":{"code":"capability_denied","message":"actor is not a member of the event Space"},"request_id":"ck:request:01964137-0000-7000-8000-000000000010"}"#,
        );

        assert_eq!(decoded.code(), "capability_denied");
        assert_eq!(
            decoded.message(),
            "actor is not a member of the event Space"
        );
        assert_eq!(
            decoded.request_id,
            "ck:request:01964137-0000-7000-8000-000000000010"
        );
    }

    #[test]
    fn decodes_wrapped_error_envelope_without_inner_request_id() {
        let decoded = decode_cokret_error(
            StatusCode::UNAUTHORIZED,
            br#"{"ok":false,"error":{"ok":false,"error":{"code":"auth_expired","message":"session expired"}},"request_id":"ck:request:01964137-0000-7000-8000-000000000011"}"#,
        );

        assert_eq!(decoded.code(), "auth_expired");
        assert_eq!(decoded.message(), "session expired");
        assert_eq!(
            decoded.request_id,
            "ck:request:01964137-0000-7000-8000-000000000011"
        );
    }

    #[test]
    fn recognizes_auth_expired_errors() {
        let error: anyhow::Error = CokretApiError {
            status: StatusCode::UNAUTHORIZED,
            error: decode_cokret_error(
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
        let bare: anyhow::Error = CokretApiError {
            status: StatusCode::UNAUTHORIZED,
            error: decode_cokret_error(StatusCode::UNAUTHORIZED, b""),
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
            let aliased: anyhow::Error = CokretApiError {
                status: StatusCode::UNAUTHORIZED,
                error: decode_cokret_error(StatusCode::UNAUTHORIZED, body.as_bytes()),
            }
            .into();
            assert!(is_auth_expired_error(&aliased), "code {code} should match");
        }

        // A 401 carrying an unrelated error code (rate-limit, policy_denied
        // wrapped in 401, etc.) must not be misclassified as session death.
        let unrelated: anyhow::Error = CokretApiError {
            status: StatusCode::UNAUTHORIZED,
            error: decode_cokret_error(
                StatusCode::UNAUTHORIZED,
                br#"{"ok":false,"error":{"code":"rate_limited","message":"slow down"}}"#,
            ),
        }
        .into();
        assert!(!is_auth_expired_error(&unrelated));

        let forbidden: anyhow::Error = CokretApiError {
            status: StatusCode::FORBIDDEN,
            error: decode_cokret_error(
                StatusCode::FORBIDDEN,
                br#"{"ok":false,"error":{"code":"auth_expired","message":"session expired"}}"#,
            ),
        }
        .into();
        assert!(!is_auth_expired_error(&forbidden));

        let revoked_session_grant: anyhow::Error = CokretApiError {
            status: StatusCode::FORBIDDEN,
            error: decode_cokret_error(
                StatusCode::FORBIDDEN,
                br#"{"ok":false,"error":{"code":"capability_denied","message":"session grant is not active: revoked"}}"#,
            ),
        }
        .into();
        assert!(is_terminal_session_grant_error(&revoked_session_grant));
        assert!(is_auth_expired_error(&revoked_session_grant));

        let unrelated_capability_denied: anyhow::Error = CokretApiError {
            status: StatusCode::FORBIDDEN,
            error: decode_cokret_error(
                StatusCode::FORBIDDEN,
                br#"{"ok":false,"error":{"code":"capability_denied","message":"actor is not a member of the event Space"}}"#,
            ),
        }
        .into();
        assert!(!is_terminal_session_grant_error(
            &unrelated_capability_denied
        ));
        assert!(!is_auth_expired_error(&unrelated_capability_denied));
    }

    #[test]
    fn recognizes_plaintext_visibility_policy_errors() {
        let error: anyhow::Error = CokretApiError {
            status: StatusCode::FORBIDDEN,
            error: decode_cokret_error(
                StatusCode::FORBIDDEN,
                br#"{"ok":false,"error":{"code":"policy_denied","message":"private plaintext message operations require this service in plaintext_visible_services"}}"#,
            ),
        }
        .into();
        assert!(is_plaintext_visibility_policy_error(&error));

        let capability_error: anyhow::Error = CokretApiError {
            status: StatusCode::FORBIDDEN,
            error: decode_cokret_error(
                StatusCode::FORBIDDEN,
                br#"{"ok":false,"error":{"code":"capability_denied","message":"private plaintext message operations require this service in plaintext_visible_services"}}"#,
            ),
        }
        .into();
        assert!(is_plaintext_visibility_policy_error(&capability_error));

        let other_policy: anyhow::Error = CokretApiError {
            status: StatusCode::FORBIDDEN,
            error: decode_cokret_error(
                StatusCode::FORBIDDEN,
                br#"{"ok":false,"error":{"code":"policy_denied","message":"only the space owner can update policy"}}"#,
            ),
        }
        .into();
        assert!(!is_plaintext_visibility_policy_error(&other_policy));
    }

    #[test]
    fn recognizes_space_membership_denied_errors() {
        let error: anyhow::Error = CokretApiError {
            status: StatusCode::FORBIDDEN,
            error: decode_cokret_error(
                StatusCode::FORBIDDEN,
                br#"{"ok":false,"error":{"code":"capability_denied","message":"actor is not a member of the event Space"},"request_id":"ck:request:01964137-0000-7000-8000-000000000010"}"#,
            ),
        }
        .into();
        assert!(is_space_membership_denied_error(&error));
    }

    #[test]
    fn retry_policy_defaults_to_bounded_idempotent_retries() {
        let options = CokretApiOptions::default();
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
        const WAIT_CURSOR: &str = "ck:cursor:eyJoIjoiMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMiIsInB1cnBvc2UiOiJzdHJlYW0iLCJ0IjoiMjAyNi0wNS0yOVQwMDowMDowMC4wMDBaIiwidiI6IjEiLCJ4IjoxNzgwMDAwMDAwMDAwfQ";
        let api = CokretApi::new("http://127.0.0.1:8787/")
            .unwrap()
            .with_bearer("sx_token")
            .with_wait_for(WAIT_CURSOR);
        let request = api
            .prepare_request(
                api.with_write_request_headers(
                    api.http
                        .post(api.endpoint("_cokret/self/events").unwrap())
                        .json(&json!({"body": "hello"})),
                    "req-123",
                ),
            )
            .build()
            .unwrap();

        assert_eq!(
            request
                .headers()
                .get("x-cokret-request-id")
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
                .get("x-cokret-wait-for")
                .and_then(|value| value.to_str().ok()),
            Some(WAIT_CURSOR)
        );
    }

    #[test]
    fn wait_for_header_rejects_malformed_sync_tokens() {
        let malformed = CokretApi::new("http://127.0.0.1:8787/")
            .unwrap()
            .with_wait_for("ck:cursor:");
        let request = malformed
            .prepare_request(
                malformed.with_write_request_headers(
                    malformed
                        .http
                        .post(malformed.endpoint("_cokret/self/events").unwrap())
                        .json(&json!({"body": "hello"})),
                    "req-456",
                ),
            )
            .build()
            .unwrap();
        assert!(request.headers().get("x-cokret-wait-for").is_none());
    }

    #[test]
    fn insecure_remote_http_is_rejected() {
        let error = CokretApi::new("http://cokret.example").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("HTTPS is required for non-local servers")
        );
    }

    /// R3 — `build_device_message_envelope` MUST emit the canonical
    /// `ck.schema.device_message.v1` shape:
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
            "ck.key.verification.request",
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
                            "type": "ck.key.verification.request",
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

    /// R3 — empty content is still a valid envelope. `ck.key.verification.done`
    /// for example carries only a transaction id; the test ensures we don't
    /// require a populated content map.
    #[test]
    fn device_message_envelope_accepts_minimal_content() {
        let envelope = build_device_message_envelope(
            "did:web:bob.example",
            "device-bbbb-2222",
            "ck.key.verification.done",
            json!({"transaction_id": "verify-done-001"}),
        );
        let inner = &envelope["messages"]["did:web:bob.example"]["device-bbbb-2222"];
        assert_eq!(inner["type"], "ck.key.verification.done");
        assert_eq!(inner["content"]["transaction_id"], "verify-done-001");
    }

    #[test]
    fn device_verification_proof_requires_signed_envelope() {
        assert!(ensure_device_verification_proof_is_signed(&json!({})).is_err());
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let proof = build_signed_device_verification_proof(
            "did:web:alice.example",
            "ck:device:alice",
            "ck:device:bob",
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
            Some("ck.device.verification.proof.v1")
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

    #[cfg(feature = "demo-crypto")]
    #[test]
    fn demo_crypto_fallbacks_are_local_only_by_default() {
        let local = CokretApi::new("http://127.0.0.1:8787").unwrap();
        local
            .ensure_demo_crypto_fallback_allowed("test fallback")
            .expect("local dev fallback");
        let remote = CokretApi::new("https://cokret.example").unwrap();
        assert!(
            remote
                .ensure_demo_crypto_fallback_allowed("test fallback")
                .is_err()
        );
    }

    #[cfg(not(feature = "demo-crypto"))]
    #[test]
    fn demo_crypto_fallbacks_are_compiled_out() {
        let local = CokretApi::new("http://127.0.0.1:8787").unwrap();
        assert!(
            local
                .ensure_demo_crypto_fallback_allowed("test fallback")
                .is_err(),
            "without the `demo-crypto` feature, even loopback hosts must fail closed"
        );
    }

    // ── Production-path (no `demo-crypto`) wire guards ──────────────
    //
    // These tests pin the contract that the three demo-only entry
    // points (`upload_keys`, `publish_mls_key_package`, `send_to_device`)
    // never let a dev placeholder reach the wire when the binary is
    // compiled without the `demo-crypto` feature. The prod path
    // `anyhow::bail!`s synchronously inside the async fn, so it's
    // safe to call without spinning up a network mock — no HTTP byte
    // is sent.
    //
    // CI gate: see `.github/workflows/ci.yml` (`cargo check
    // --workspace --no-default-features`) which compiles this module
    // with `not(feature = "demo-crypto")` enabled.

    #[cfg(not(feature = "demo-crypto"))]
    #[tokio::test]
    async fn upload_keys_refuses_to_ship_demo_device_signature_in_prod_build() {
        let api = CokretApi::new("http://127.0.0.1:8787").unwrap();
        let err = api
            .upload_keys("ck:device:test-prod-guard")
            .await
            .expect_err("prod build MUST refuse to ship demo device_signature placeholders");
        let msg = format!("{err}");
        assert!(
            msg.contains("device_signature") && msg.contains("demo-crypto"),
            "prod-path error must name the placeholder + missing feature gate, got: {msg}"
        );
    }

    #[cfg(not(feature = "demo-crypto"))]
    #[tokio::test]
    async fn publish_mls_key_package_refuses_demo_signature_in_prod_build() {
        // Build a syntactically-valid MlsKeyPackageRecord via JSON so
        // we don't need to import every field type. The prod path
        // bails before reading any field, but we still want the
        // argument well-formed so a future refactor that touches the
        // record before bailing surfaces here.
        let record: cokret_sdk::MlsKeyPackageRecord = serde_json::from_value(serde_json::json!({
            "keypackage_id": "ck:mls:kp:01904100-0000-7000-8000-000000000001",
            "principal_id": "did:web:alice.example",
            "device_id": "ck:device:01904100-0000-7000-8000-000000000001",
            "key_package": "AAAA",
            "keypackage_ref": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "cipher_suites": ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
            "created_at": "2026-01-01T00:00:00Z",
        }))
        .expect("MlsKeyPackageRecord fixture must deserialize");

        let api = CokretApi::new("http://127.0.0.1:8787").unwrap();
        let err = api
            .publish_mls_key_package("ck:device:test-prod-guard", &record)
            .await
            .expect_err("prod build MUST refuse to publish demo-signed key packages");
        let msg = format!("{err}");
        assert!(
            msg.contains("device_signature") && msg.contains("demo-crypto"),
            "prod-path error must name the placeholder + missing feature gate, got: {msg}"
        );
    }

    #[cfg(not(feature = "demo-crypto"))]
    #[tokio::test]
    async fn send_to_device_refuses_opaque_ciphertext_placeholder_in_prod_build() {
        let api = CokretApi::new("http://127.0.0.1:8787").unwrap();
        let err = api
            .send_to_device("did:web:bob.example", "ck:device:test-prod-guard")
            .await
            .expect_err("prod build MUST refuse to ship opaque ciphertext placeholders");
        let msg = format!("{err}");
        assert!(
            msg.contains("ciphertext") && msg.contains("demo-crypto"),
            "prod-path error must name the placeholder + missing feature gate, got: {msg}"
        );
    }

    /// Belt-and-braces: even on a loopback host, the prod build of the
    /// helper guard must fail closed. We already cover this in
    /// `demo_crypto_fallbacks_are_compiled_out` for the public
    /// `ensure_demo_crypto_fallback_allowed`; this variant additionally
    /// asserts that the error message names the missing build feature
    /// so the caller can suggest the right fix in operator-facing logs.
    #[cfg(not(feature = "demo-crypto"))]
    #[test]
    fn demo_crypto_guard_message_names_required_build_feature() {
        let local = CokretApi::new("http://127.0.0.1:8787").unwrap();
        let err = local
            .ensure_demo_crypto_fallback_allowed("upload_keys demo device_signature")
            .expect_err("prod build must fail closed even on loopback");
        let msg = format!("{err}");
        assert!(
            msg.contains("demo-crypto"),
            "guard error must reference the `demo-crypto` build feature for operators, got: {msg}"
        );
    }
}
