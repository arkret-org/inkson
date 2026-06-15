use std::collections::BTreeMap;
use std::fmt::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use base64::Engine;
use chime::{
    ChimePushRegisterDeviceOutcome, ChimePushRegisterDeviceRequest,
    ChimePushUnregisterDeviceRequest, CokretPushClient,
};
use cokret_sdk::ErrorEnvelope;
use reqwest::header::{ACCEPT, HeaderMap, RETRY_AFTER};
use reqwest::{Client, Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{Mutex, OnceCell, RwLock};
use url::Url;

/// A token that can be used to cancel in-flight API requests.
#[derive(Clone, Debug)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PrincipalAuthBridgeDescribeView {
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

pub use cokret_sdk::SessionGrantIntrospectionProof;

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
use crate::identity_handle::parse_user_handle;
use crate::models::{
    AccountDataSetResult, AuthzCheckOutcome, BackfillView, BlobUploadOutcome, ClientSyncOutcome,
    ContactListView, CurrentAccount, DeviceMessagesAckOutcome, DeviceMessagesAckRequestBody,
    DeviceMessagesGetOutcome, DeviceMessagesSendOutcome, DeviceTrustView, EphemeralSubmitResult,
    GrantList, HealthOutcome, IdentityDescribeOutcome, IdentityResolveOutcome, IndexSearchView,
    InvitesView, KeysClaimOutcome, KeysQueryOutcome, KeysUploadOutcome, MediaIceConfigOutcome,
    MediaIceConfigRequestBody, ModerationReportOutcome, OP_SNAPSHOT_HEAD, OkOutcome,
    PushRegisterView, RealmCreateResult, RealmJoinCandidate, RealmPolicyResult, ReceiptResult,
    ResolveHandleView, ResolveRealmOutcome, SearchActorsView, SearchOrganizationsView,
    ServerDescription, SessionLoginOutcome, SolandDirectoryDescribeResBody, SpaceCreateResult,
    SubmitEventResult, SyncDescribeView, TypingResult, VerifyDeviceResult,
};
use crate::operation::{EventEnvelope, OperationBuilder, trim_realm_id, uuid_v7};

pub const RECOMMENDED_REALM_ENCRYPTION_PROFILE: &str = "mls_rfc9420";
pub const RECOMMENDED_REALM_ENCRYPTION_FLOOR: &str = "e2ee_required";

/// Generic wrapper for soland's
/// `/_cokret/self/projection/{spaces|strands}` lifecycle endpoints. Keeps
/// the query response shape symmetric across the two surfaces so the kanban
/// hydrate path can pluck projection rows with the same code. The decoder
/// normalizes spec `spaces` / `strands` / `morphs` collection keys into `items`.
#[derive(Clone, Debug, Deserialize)]
pub struct LifecycleProjectionView<T> {
    pub realm_id: String,
    #[serde(default)]
    pub total: u32,
    #[serde(
        default = "Vec::new",
        alias = "spaces",
        alias = "strands",
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
    pub space_id: String,
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

/// Server-side Strand row from `GET /_cokret/self/projection/strands`.
#[derive(Clone, Debug, Deserialize)]
pub struct StrandProjectionView {
    pub strand_id: String,
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
    pub assigned_actor_ids: Vec<String>,
    #[serde(default)]
    pub assigned_to_relations: Vec<AssignedToRelationProjectionView>,
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

#[derive(Clone, Debug, Deserialize)]
pub struct AssignedToRelationProjectionView {
    pub relation_id: String,
    pub actor_id: String,
}

/// YOU-01-009 子项 3 — spec-registered collection projection response
/// (`view.schema.json#/$defs/collection_projection_view`, operation
/// `ck.self.views.collection_projection.command.materialize`,
/// `POST /_cokret/self/views/{view_id}/projection`). Defined locally
/// because the SDK still carries its pre-registration draft DTO
/// (`CollectionProjectionOutcome`, with `kind`/`group_id`/`discussion`
/// fields that are not on the registered wire shape).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CollectionProjectionView {
    /// Always the literal `"collection"` per the schema const.
    pub projection: String,
    /// Renderer hint (`board` / `list` / `table` / …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renderer: Option<String>,
    pub view_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
    /// Registered `state_frontier` object (NOT a bare event-id list).
    pub frontier: StateFrontierView,
    #[serde(default)]
    pub groups: Vec<CollectionProjectionGroupView>,
    /// Flat item list for group-less renderers (schema `anyOf` requires
    /// `groups` or `items`).
    #[serde(default)]
    pub items: Vec<ProjectionItemView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_estimate: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
}

/// Registered `view.schema.json#/$defs/state_frontier`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StateFrontierView {
    pub state_digest: String,
    #[serde(default)]
    pub event_ids: Vec<String>,
    #[serde(default)]
    pub actor_frontiers: Vec<Value>,
}

/// Registered `view.schema.json#/$defs/collection_projection_group`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CollectionProjectionGroupView {
    /// Stable group key (registered name is `key`, not `group_id`).
    pub key: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    /// Registered `collection_group_source` (oneOf) — kept opaque.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Value>,
    #[serde(default)]
    pub items: Vec<ProjectionItemView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Required by the registered schema: whether this group's item list
    /// was truncated by policy/limit.
    pub limited: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wip_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_estimate: Option<u64>,
}

/// Registered `view.schema.json#/$defs/projection_item`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProjectionItemView {
    /// Registered `projection_object` (`{id, type, morph_type?, facets?,
    /// title?, fields?}`). Kept as a `Value` — readers fall back through
    /// `title`/`fields.*` leniently.
    pub object: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub render: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<Value>,
    /// Registered `collection_position` (oneOf field_value / relation /
    /// time_bucket). Kept opaque; use [`Self::position_rank`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<Value>,
    /// Free-form per-item read-model state (registered as an open object).
    /// Discussion lock metadata, when a server provides it, is read
    /// leniently from `state.discussion`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<Value>,
}

impl ProjectionItemView {
    /// Rank from the registered `collection_position` variants: the
    /// `field_value` / `relation` models carry `rank`; the `time_bucket`
    /// model carries `sort_key`.
    pub fn position_rank(&self) -> Option<String> {
        let position = self.position.as_ref()?;
        position
            .get("rank")
            .or_else(|| position.get("sort_key"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }
}

/// Server-side Morph row from
/// `GET /_cokret/self/projection/morphs`. Same enum as Strand per spec §5.1.
#[derive(Clone, Debug, Deserialize)]
pub struct MorphProjectionView {
    pub morph_id: String,
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
    /// SPEC-CR-001 — `ck.session.grant` signing key + its `keyid`. When set,
    /// requests to the `/_cokret/self/*` surface carry an RFC 9421 PoP
    /// signature (api-conventions.md §3.2).
    session_signing_key: Option<ed25519_dalek::SigningKey>,
    session_key_id: Option<String>,
    /// Cached `GET /_cokret/self/events/describe` response (spec
    /// `ServiceDescribe` shape) so repeat callers avoid re-hitting the
    /// network.
    events_describe_cache: Arc<OnceCell<cokret_sdk::ServiceDescribe>>,
    /// Cached `GET /_cokret/describe` response used to bind durable
    /// EventProof signatures to this service's trust domain and audience.
    service_describe_cache: Arc<OnceCell<ServerDescription>>,
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
            .field(
                "service_describe_cache",
                &self
                    .service_describe_cache
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

/// Context for `ck.find.directory.query.resolve_handle`.
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

#[derive(Clone, Debug, thiserror::Error)]
#[error("Cokret API returned {status}: {error}")]
pub struct CokretApiError {
    pub status: StatusCode,
    pub error: ErrorEnvelope,
}

const DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS: u64 = 5_000;

/// Browser `fetch` cannot reliably abort the long-poll once reqwest has handed
/// it to the platform. Keep account-subscribe network calls globally serial so
/// duplicate UI tasks cannot leave multiple pending long-polls in DevTools.
static ACCOUNT_SUBSCRIBE_NETWORK_GATE: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// True when a discovery probe failed because the endpoint does not exist on
/// this server — i.e. the routing layer returned `404 unrecognized_endpoint`
/// (see `service-http-binding.md` routing rules) rather than a transport,
/// auth, or server error.
#[cfg(test)]
pub(crate) fn is_endpoint_absent(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<CokretApiError>()
        .is_some_and(|api_error| api_error.status == StatusCode::NOT_FOUND)
}

#[derive(Clone, Debug)]
pub enum AccountSubscribeSnapshotResult {
    Delta(ClientSyncOutcome),
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
/// (`auth_expired`, `unauthenticated`, `invalid_token`, `token_expired`)
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
/// Strand capability denial.
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

/// `true` when account subscribe rejected the cursor — expired, invalid,
/// integrity-mismatched, or unrecognized — so the SyncEngine knows to
/// demote to a `after=None` full sync instead of looping on the same
/// broken cursor. Per client-sync.md §2/§12.3, `cursor_expired` /
/// `cursor_integrity_invalid` / `cursor_unrecognized` all recover by
/// clearing the local cursor and redoing initial sync.
pub fn is_invalid_cursor_error(error: &anyhow::Error) -> bool {
    use cokret_sdk::error::{ERROR_CODE_CURSOR_INTEGRITY_INVALID, ERROR_CODE_CURSOR_UNRECOGNIZED};
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
                    || code == ERROR_CODE_CURSOR_UNRECOGNIZED
            ) || (cursor_message
                && matches!(code, code if code == ERROR_CODE_INVALID_PARAM || code == "invalid_cursor"))
        })
}

/// `true` for `stale_frontier` — the cursor itself is still valid but the
/// service frontier lags the requested causal frontier. Per
/// client-sync.md §4 the client MUST NOT clear the cursor; it should
/// fetch the current frontier via `account/describe` / `snapshot/head`
/// (§12.3 step 2) and retry / backfill with the SAME cursor.
pub fn is_stale_frontier_error(error: &anyhow::Error) -> bool {
    use cokret_sdk::error::ERROR_CODE_STALE_FRONTIER;
    error
        .downcast_ref::<CokretApiError>()
        .is_some_and(|api_error| api_error.error.code() == ERROR_CODE_STALE_FRONTIER)
}

pub(crate) fn is_snapshot_unavailable_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<CokretApiError>()
        .is_some_and(|api_error| {
            let code = api_error.error.code();
            api_error.status == StatusCode::NOT_FOUND
                || matches!(
                    code,
                    "not_implemented"
                        | "snapshot_unavailable"
                        | "not_found"
                        | "unrecognized_endpoint"
                        | "unsupported_feature"
                )
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

fn resolve_handle_request_body(
    handle: &str,
    context: ResolveHandleContext<'_>,
) -> anyhow::Result<cokret_sdk::models::DirectoryResolveHandleRequestBody> {
    let non_empty = |value: Option<&str>| {
        value
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    };
    let realm_id = match non_empty(context.realm_id) {
        Some(realm_id) => Some(
            cokret_sdk::RealmId::new(&realm_id)
                .map_err(|err| anyhow::anyhow!("invalid realm_id `{realm_id}`: {err}"))?,
        ),
        None => None,
    };
    let expected_did = match non_empty(context.expected_did) {
        Some(did) => Some(
            cokret_sdk::Did::new(did.clone())
                .map_err(|err| anyhow::anyhow!("invalid expected_did `{did}`: {err}"))?,
        ),
        None => None,
    };
    let requester = match non_empty(context.requester) {
        Some(did) => Some(
            cokret_sdk::Did::new(did.clone())
                .map_err(|err| anyhow::anyhow!("invalid requester `{did}`: {err}"))?,
        ),
        None => None,
    };
    Ok(cokret_sdk::models::DirectoryResolveHandleRequestBody {
        handle: handle.to_owned(),
        expected_did,
        proof_challenge: non_empty(context.proof_challenge),
        intent: non_empty(context.intent),
        requester,
        audience: non_empty(context.audience),
        realm_id,
        proofs: context
            .proofs
            .iter()
            .map(|proof| proof.trim())
            .filter(|proof| !proof.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
    })
}

fn canonical_invitee_handle(target: &str) -> anyhow::Result<String> {
    parse_user_handle(target)
        .map(|handle| handle.handle)
        .ok_or_else(|| {
            anyhow::anyhow!("invitee must be a DID or canonical handle `<localpart>:<domain>`")
        })
}

/// Typed error class for the `post_audit_user_action` path.
/// Distinguishes "endpoint isn't wired yet" (404 - caller should
/// re-buffer the entry) from "server said no" (every other error -
/// drop and move on). Pulled out so callers can branch without
/// parsing `anyhow::Error` strings.
#[derive(Debug, thiserror::Error)]
pub enum AuditPostError {
    /// Server responded 404 — the audit ingest endpoint is not yet
    /// wired. Callers re-buffer the entry for a later flush attempt.
    #[error("audit endpoint not wired (404)")]
    NotWired,
    /// Any other failure (network drop, 5xx, 4xx). Caller drops the
    /// entry — telemetry is best-effort.
    #[error("audit post failed: {0}")]
    Other(String),
}

#[derive(Debug, Deserialize)]
struct ApiErrorBody {
    error: ErrorEnvelope,
}

mod account;
mod agent;
mod applet;
mod blob;
mod blob_resumable;
// YOU-07-001:领域事件 / 信封构造器从本文件外迁至 `builders`(仅移动)。
// 重导出维持 `crate::api::build_*` 与兄弟子模块 `use super::*` 的解析路径。
mod builders;
mod directory;
mod events;
// YOU-07-001: HTTP plumbing helpers (error decode, retry/backoff classification,
// URL/query encoding, NDJSON subscribe parsing, small response parsers) moved out
// of this file into `http_helpers` (move only). The glob re-export keeps the
// `crate::api::*` public paths and sibling/tests `use super::*` resolution unchanged.
mod http_helpers;
mod keys;
mod media;
mod mls;
mod moderation;
mod push;
mod realm;
// YOU-07-001: sync / account-subscribe parsers moved out of this file into
// `sync_parse` (move only). The glob re-export keeps `crate::api::parse_sync`
// and the sibling/tests `use super::*` resolution paths unchanged.
mod sync_parse;

pub use builders::*;
pub use http_helpers::*;
pub use sync_parse::*;

/// PoP signature validity window (seconds). Kept well under the 300s protocol
/// maximum (api-conventions.md §3.2) while tolerating modest clock skew.
const POP_SIGNATURE_WINDOW_SECONDS: i64 = 120;

/// RFC 7638 JWK thumbprint of an Ed25519 verifying key (the `keyid` soland
/// accepts for the PoP binding check).
fn session_key_thumbprint(verifying_key: &ed25519_dalek::VerifyingKey) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifying_key.to_bytes());
    let canonical = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

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
            session_signing_key: None,
            session_key_id: None,
            events_describe_cache: Arc::new(OnceCell::new()),
            service_describe_cache: Arc::new(OnceCell::new()),
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

    /// SPEC-CR-001 — bind the `ck.session.grant` session key so requests to
    /// `/_cokret/self/*` are RFC 9421 PoP-signed. `session_private_key_pem` is
    /// the PKCS#8 PEM returned by the grant exchange; the keyid is the key's
    /// RFC 7638 thumbprint, which soland accepts for the binding check.
    pub fn with_session_signing_key(
        mut self,
        session_private_key_pem: &str,
    ) -> anyhow::Result<Self> {
        let signing_key =
            crate::coauth::session_grant_signing_key_from_pem(session_private_key_pem)?;
        self.session_key_id = Some(session_key_thumbprint(&signing_key.verifying_key()));
        self.session_signing_key = Some(signing_key);
        Ok(self)
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
        let normalized = path.trim().trim_start_matches('/');
        if !soland_path_allowed(normalized) {
            anyhow::bail!(
                "yougen redline: forbidden soland private path `{normalized}`; use only spec-defined `/_cokret/` endpoints"
            );
        }
        Ok(self.base_url.join(normalized)?)
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

    async fn post_json<T, B>(&self, path: &str, body: &B) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        // Explicit serialized bytes (not `.json()`) so PoP signing can read the
        // exact body for the content-digest on every target (incl. wasm).
        let bytes = serde_json::to_vec(body)?;
        let request = self
            .http
            .post(self.endpoint(path)?)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes);
        self.send_json(self.prepare_request(request), Method::POST)
            .await
    }

    async fn put_json<T, B>(&self, path: &str, body: &B) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let bytes = serde_json::to_vec(body)?;
        let request = self
            .http
            .put(self.endpoint(path)?)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes);
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
                // SPEC-CR-001 — sign the fully-built request (PoP covers
                // @method/@target-uri/@authority/content-digest); re-signed per
                // attempt so created/expires stay fresh after a backoff.
                let built = self.sign_request(request.build()?)?;
                return Ok(self.http.execute(built).await?);
            };
            // 401 handling lives at the app layer (`crate::session`): a
            // refresh future capturing Dioxus signals + wasm `reqwest` is
            // `!Send`, so the HTTP client can't own it. The client just
            // surfaces the 401; the caller re-mints and retries.
            let built = self.sign_request(candidate.build()?)?;
            match self.http.execute(built).await {
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

    /// SPEC-CR-001 — attach an RFC 9421 PoP signature to `/_cokret/self/*`
    /// requests when a session signing key is bound. No-op for other surfaces
    /// or unsigned clients. Covers `@method`/`@target-uri`/`@authority` plus
    /// `content-digest` (over the body) for body-bearing requests; `created` /
    /// `expires` bound the validity window (<=300s, well under the protocol cap).
    fn sign_request(&self, mut request: reqwest::Request) -> anyhow::Result<reqwest::Request> {
        let Some(signing_key) = self.session_signing_key.as_ref() else {
            return Ok(request);
        };
        let path = request.url().path().to_owned();
        if !(path.contains("/_cokret/self/") || path.contains("/_soland/self/")) {
            return Ok(request);
        }
        use cokret_sdk::http_signature::{
            Component, ContentDigest, ContentDigestAlgorithm, SignatureInput, SignedRequestParts,
            canonical_message, sign_message,
        };

        let key_id = self.session_key_id.clone().unwrap_or_default();
        let method = request.method().as_str().to_owned();
        let url = request.url();
        let target_uri = url.as_str().to_owned();
        let authority = match url.port() {
            Some(port) => format!("{}:{}", url.host_str().unwrap_or_default(), port),
            None => url.host_str().unwrap_or_default().to_owned(),
        };
        let path_only = url.path().to_owned();
        let body_bytes: Vec<u8> = request
            .body()
            .and_then(|body| body.as_bytes())
            .map(<[u8]>::to_vec)
            .unwrap_or_default();

        let mut covered = vec![
            Component::Method,
            Component::TargetUri,
            Component::Authority,
        ];
        let mut component_names = vec!["\"@method\"", "\"@target-uri\"", "\"@authority\""];
        let digest = if body_bytes.is_empty() {
            None
        } else {
            let digest = ContentDigest::compute(&body_bytes, ContentDigestAlgorithm::Sha256);
            covered.push(Component::Header("content-digest".to_owned()));
            component_names.push("\"content-digest\"");
            Some(digest.wire_value)
        };

        let created = chrono::Utc::now().timestamp();
        let expires = created + POP_SIGNATURE_WINDOW_SECONDS;
        let params_value = format!(
            "({});created={created};expires={expires};keyid=\"{key_id}\";alg=\"ed25519\"",
            component_names.join(" ")
        );
        let signature_input = SignatureInput {
            label: "sig1".to_owned(),
            covered_components: covered,
            created,
            expires,
            key_id,
            algorithm: "ed25519".to_owned(),
            params_value: params_value.clone(),
        };
        let parts = SignedRequestParts {
            method,
            target_uri,
            authority,
            path: path_only,
            headers: Vec::new(),
            body_digest: digest.clone(),
        };
        let canonical = canonical_message(&parts, &signature_input)
            .map_err(|error| anyhow::anyhow!("build PoP signing string: {error}"))?;
        let signature = sign_message(&canonical, signing_key);

        let headers = request.headers_mut();
        if let Some(ref wire) = digest {
            headers.insert(
                "content-digest",
                reqwest::header::HeaderValue::from_str(wire)?,
            );
        }
        headers.insert(
            "signature-input",
            reqwest::header::HeaderValue::from_str(&format!("sig1={params_value}"))?,
        );
        headers.insert(
            "signature",
            reqwest::header::HeaderValue::from_str(&format!("sig1=:{signature}:"))?,
        );
        Ok(request)
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

pub fn build_read_cursor_advance_event(
    marker: &crate::local_state::ReadMarkerRecord,
) -> EventEnvelope {
    OperationBuilder::new(&marker.body.realm_id, &marker.actor, &marker.marker_type)
        .body(marker.ck_read_cursor_payload())
        .build(&marker.device_id)
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
    actor_id: &str,
    device_id: Option<&str>,
    typing: bool,
) -> anyhow::Result<cokret_sdk::EphemeralEnvelope> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(TYPING_EPHEMERAL_TTL_SECS);
    let realm_id_wire = trim_realm_id(realm_id);
    let realm = cokret_sdk::RealmId::new(realm_id_wire.clone())
        .map_err(|err| anyhow::anyhow!("invalid realm_id for ck.typing: {err}"))?;
    let actor = cokret_sdk::Did::new(actor_id)
        .map_err(|err| anyhow::anyhow!("invalid actor_id for ck.typing: {err}"))?;
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
            "actor_id": actor_id,
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
    actor_id: &str,
    event_id: &str,
) -> anyhow::Result<cokret_sdk::EphemeralEnvelope> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(EPHEMERAL_DEFAULT_TTL_SECS);
    let realm_id_wire = trim_realm_id(realm_id);
    let realm = cokret_sdk::RealmId::new(realm_id_wire.clone())
        .map_err(|err| anyhow::anyhow!("invalid realm_id for ck.receipt.read: {err}"))?;
    let actor = cokret_sdk::Did::new(actor_id)
        .map_err(|err| anyhow::anyhow!("invalid actor_id for ck.receipt.read: {err}"))?;
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
            "actor_id": actor_id,
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
    actor_id: &str,
    status: &str,
    last_active_at: Option<chrono::DateTime<chrono::Utc>>,
) -> anyhow::Result<cokret_sdk::EphemeralEnvelope> {
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::seconds(EPHEMERAL_DEFAULT_TTL_SECS);
    let realm = cokret_sdk::RealmId::new(realm_id)
        .map_err(|err| anyhow::anyhow!("invalid realm_id for ck.presence: {err}"))?;
    let actor = cokret_sdk::Did::new(actor_id)
        .map_err(|err| anyhow::anyhow!("invalid actor_id for ck.presence: {err}"))?;
    let mut payload = serde_json::Map::new();
    payload.insert("actor_id".into(), Value::String(actor_id.to_owned()));
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
    actor_id: &str,
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
    let actor = cokret_sdk::Did::new(actor_id)
        .map_err(|err| anyhow::anyhow!("invalid actor_id for ck.call.signal: {err}"))?;
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
    fn endpoint_enforces_private_path_redline() {
        let api = CokretApi::new("http://127.0.0.1:8787/").unwrap();
        assert!(api.endpoint("_cokret/self/events").is_ok());
        let private_prefix = concat!("_so", "land");
        let private_consent =
            [private_prefix, "self", "consent", "cells", "alice", "grant"].join("/");
        assert!(api.endpoint(&private_consent).is_err());
        let retired_account_me = [private_prefix, "self", "account", "me"].join("/");
        assert!(api.endpoint(&retired_account_me).is_err());
        let unlisted = format!("{private_prefix}/self/spaces/ck:space:1");
        let error = api
            .endpoint(&unlisted)
            .expect_err("soland private paths must be rejected");
        assert!(
            error.to_string().contains("redline"),
            "error should mention the redline: {error}"
        );
    }

    #[test]
    fn self_request_pop_signature_roundtrips_with_sdk_verifier() {
        use ed25519_dalek::pkcs8::EncodePrivateKey as _;

        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let pem = signing
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .unwrap()
            .to_string();
        let api = CokretApi::new("https://soland.example.com")
            .unwrap()
            .with_bearer("tok")
            .with_session_signing_key(&pem)
            .unwrap();

        let body = serde_json::to_vec(&serde_json::json!({"hello": "world"})).unwrap();
        let request = api
            .http
            .post(api.endpoint("/_cokret/self/events").unwrap())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.clone())
            .build()
            .unwrap();
        let signed = api.sign_request(request).unwrap();

        let headers: Vec<(String, String)> = signed
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.to_str().unwrap().to_owned()))
            .collect();
        let url = signed.url().clone();
        let authority = url.host_str().unwrap().to_owned();

        // The same SDK verifier soland runs MUST accept the yougen signature.
        let verified = cokret_sdk::http_signature::verify_signed_http_message(
            "POST",
            url.as_str(),
            &authority,
            url.path(),
            headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
            &body,
            &signing.verifying_key(),
            &cokret_sdk::http_signature::SignatureVerificationPolicy::service_ingest()
                .require_content_digest(true)
                .max_clock_skew_seconds(30),
            chrono::Utc::now().timestamp(),
        )
        .expect("SDK verifies yougen-produced PoP signature");
        assert_eq!(
            verified.signature_input.key_id,
            session_key_thumbprint(&signing.verifying_key())
        );
        assert!(verified.signature_input.expires - verified.signature_input.created <= 300);
    }

    #[test]
    fn endpoint_absent_only_triggers_on_404() {
        // 404 unrecognized_endpoint means the canonical endpoint is absent.
        let not_found: anyhow::Error = CokretApiError {
            status: StatusCode::NOT_FOUND,
            error: decode_cokret_error(StatusCode::NOT_FOUND, b"{}"),
        }
        .into();
        assert!(is_endpoint_absent(&not_found));

        // A 5xx is a real server failure, not an absent endpoint — must propagate.
        let server_error: anyhow::Error = CokretApiError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: decode_cokret_error(StatusCode::INTERNAL_SERVER_ERROR, b"{}"),
        }
        .into();
        assert!(!is_endpoint_absent(&server_error));

        // A non-API transport error must not be mistaken for an absent endpoint.
        let transport: anyhow::Error = anyhow::anyhow!("connection refused");
        assert!(!is_endpoint_absent(&transport));
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
    fn resolve_handle_request_body_carries_lookup_context() {
        let body = resolve_handle_request_body(
            "bob:local.host",
            ResolveHandleContext {
                intent: Some("lookup"),
                requester: Some("did:web:alice.example"),
                audience: Some("ck:realm:0196419b-0000-7000-8000-000000000001"),
                realm_id: Some("ck:realm:0196419b-0000-7000-8000-000000000001"),
                expected_did: Some("did:web:bob.example"),
                proof_challenge: Some("ck:challenge:test"),
                proofs: &["proof-a", "  ", "proof-b"],
            },
        )
        .expect("resolve_handle request body builds");
        let body = serde_json::to_value(body).expect("request body serializes");

        assert_eq!(body["handle"], "bob:local.host");
        assert_eq!(body["intent"], "lookup");
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
    fn handle_resolution_exposes_delivery_binding_without_requiring_it_for_invites() {
        let realm_id = "ck:realm:0196419b-0000-7000-8000-000000000001";
        let resolved: ResolveHandleView = serde_json::from_value(json!({
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
        assert_eq!(
            resolved.member_delivery_binding_value().unwrap()["recipient_service_did"],
            "did:web:local.host"
        );

        let missing_binding: ResolveHandleView = serde_json::from_value(json!({
            "did": "did:web:bob.example",
            "handle": "bob:local.host",
            "audience": realm_id
        }))
        .unwrap();
        assert_eq!(missing_binding.subject_did(), Some("did:web:bob.example"));
        assert!(missing_binding.member_delivery_binding_value().is_none());
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
    fn lifecycle_projection_response_accepts_spec_keys() {
        let canonical_spaces: LifecycleProjectionView<SpaceContainerProjectionView> =
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
            canonical_spaces.items[0].space_id,
            "ck:space:01904100-0000-7000-8000-f10dc0000001"
        );

        let strands: LifecycleProjectionView<StrandProjectionView> =
            serde_json::from_value(json!({
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "strands": [{
                    "strand_id": "ck:strand:01904100-0000-7000-8000-f20dc0000001",
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
        assert_eq!(strands.items[0].realm_id, strands.realm_id);
        assert_eq!(strands.items[0].state, "archived");
        assert_eq!(
            strands.items[0].board_space_id.as_deref(),
            Some("ck:space:01904100-0000-7000-8000-b0ard0000001")
        );
    }

    #[test]
    fn typing_envelope_uses_spec_ephemeral_shape() {
        let envelope = build_typing_envelope(
            "ck:realm:0196419b-0000-7000-8000-000000000000",
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
            "supported_operations": ["ck.self.account.stream.subscribe"],
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
            "realms": {
                "ck:realm:0196419b-0000-7000-8000-000000000000": {"summary": {}}
            },
            "to_device": [],
            "account_data": [],
            "device_lists": {"changed": [], "left": []}
        }))
        .unwrap();
        assert_eq!(sync.realms.len(), 1);
        assert_eq!(sync.cursor, "ck:cursor:test-1");

        // Spec-aligned wire shape per `client-sync.md §2`: flat
        // `realms` keyed by realm id, explicit `left_realms`,
        // flat arrays for top-level streams. The SDK's canonical account
        // subscribe snapshot shape.
        let sync_v1 = parse_sync(json!({
            "cursor": "ck:cursor:v1",
            "realms": {
                "ck:realm:joined": {
                    "summary": {"title": "Joined"}
                }
            },
            "left_realms": ["ck:realm:left"],
            "to_device": [{"type": "ck.mls.welcome"}],
            "account_data": [{"data_type": "client.ui", "content": {"theme": "system"}}],
            "device_lists": {"changed": [], "left": []},
            "notifications": {"events": []},
            "presence": []
        }))
        .unwrap();
        assert_eq!(sync_v1.cursor, "ck:cursor:v1");
        assert!(sync_v1.realms.contains_key("ck:realm:joined"));
        assert_eq!(sync_v1.left_realms, vec!["ck:realm:left".to_owned()]);
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
                .realms
                .contains_key("ck:realm:019e4cdc-b435-7e52-9ada-39d5ec134729")
        );
        assert!(account_frame.left_realms.is_empty());

        let reconnect = parse_account_subscribe_snapshot_outcome(
            br#"{"kind":"resync_required","reason":"compaction","reconnect_after_ms":10000}
"#,
        )
        .unwrap();
        match reconnect {
            AccountSubscribeSnapshotResult::ReconnectAfter {
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
    fn account_subscribe_fold_consumes_every_catchup_frame() {
        // YOU-01-010 — multi-frame catchup: both deltas must be folded
        // (timeline events appended) and the cursor must advance to the
        // LAST cursor-bearing frame (the catchup_complete), not stop at
        // the first delta.
        let folded = parse_account_subscribe_snapshot(
            br#"{"kind":"delta","cursor":"ck:cursor:1","realms":{"ck:realm:a":{"timeline":{"events":[{"event_id":"ck:event:1"}]}}}}
{"kind":"delta","cursor":"ck:cursor:2","realms":{"ck:realm:a":{"timeline":{"events":[{"event_id":"ck:event:2"}]}},"ck:realm:b":{"summary":{"title":"B"}}}}
{"kind":"catchup_complete","cursor":"ck:cursor:3"}
"#,
        )
        .unwrap();
        assert_eq!(folded.cursor, "ck:cursor:3");
        assert!(folded.realms.contains_key("ck:realm:b"));
        let events = folded.realms["ck:realm:a"]["timeline"]["events"]
            .as_array()
            .expect("merged timeline events");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["event_id"], "ck:event:1");
        assert_eq!(events[1]["event_id"], "ck:event:2");
    }

    #[test]
    fn event_paths_use_v1_query_parameters() {
        let backfill = events_query_path("ck:realm:demo");
        assert_eq!(backfill, "_cokret/self/events?realms=ck%3Arealm%3Ademo");
        assert!(!backfill.contains("direction="));

        let subscribe = events_subscribe_path("ck:realm:demo", Some("ck:cursor:demo"), Some(true));
        assert_eq!(
            subscribe,
            "_cokret/self/events/subscribe?realms=ck%3Arealm%3Ademo&after=ck%3Acursor%3Ademo&include_history=true"
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
                "ck.realm.policy_components",
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
        assert!(create.payload["object"]["content_encryption_floor"].is_null());
        assert!(create.payload["object"]["metadata_encryption_floor"].is_null());
        assert_eq!(create.payload["object"]["notary"]["type"], "single_did");
        assert_eq!(create.payload["object"]["notary"]["did"], create.actor_id);
        assert_eq!(
            create.payload["object"]["notary"]["recovery_members"][0],
            "did:web:alice.example:recovery:notary",
        );
        assert_eq!(
            create.payload["object"]["notary"]["controller_organization"],
            "did:web:alice.example",
        );
        assert_eq!(
            create.payload["object"]["notary"]["recovery_controller_organizations"][0],
            "did:web:alice.example:recovery",
        );
        assert_eq!(
            create.effects[0].cell,
            "ck:cell:ck.component.realm.create.v1:ck:realm:0196419b-0000-7000-8000-000000000001"
        );
        assert_eq!(create.effects[0].op.kind, "set");
        // seal_ref starts unset on the typed envelope. Realm genesis
        // has no snapshot head yet, so the create event relies on its
        // `head_eq null` precondition instead of a prior seal.
        assert!(create.seal_ref.is_none());
        // The typed builder leaves the envelope unsigned — the active
        // signer attaches the detached JWS proof at submit time.
        assert!(create.proofs.is_empty());

        // Bootstrap order: create, encryption floor policy,
        // join_rule, history_visibility, discovery, plaintext_visible,
        // member-invite.
        assert_eq!(
            events[1].payload["value"]["content_encryption_floor"],
            RECOMMENDED_REALM_ENCRYPTION_FLOOR
        );
        assert_eq!(
            events[1].payload["value"]["metadata_encryption_floor"],
            RECOMMENDED_REALM_ENCRYPTION_FLOOR
        );
        assert_eq!(events[1].payload["value"]["policy_revision"], 1);
        assert_eq!(events[2].payload["value"], "invite");
        assert_eq!(events[3].payload["value"], "shared");
        assert_eq!(events[4].payload["value"], "listed");
        assert_eq!(
            events[5].payload["services"][0]["service_did"],
            "did:web:server.example"
        );
        assert_eq!(
            events[5].payload["services"][0]["data_classes"],
            json!([
                "message_content",
                "full_text_index",
                "notification_summary",
                "inbox_preview",
            ])
        );
        assert_eq!(events[6].payload["membership"], "invite");
    }

    #[test]
    fn plaintext_realm_create_does_not_claim_e2ee_floors() {
        let envelope = build_realm_create_event(
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "Public updates",
            None,
            "listed",
            "public",
            "world_readable",
            "none",
            "standard",
            "open",
            "single_did",
            "sha256",
            "ck:trust_domain:server.example",
            &[],
        )
        .unwrap();

        assert_eq!(envelope.payload["object"]["encryption_profile"], "none");
        assert!(envelope.payload["object"]["content_encryption_floor"].is_null());
        assert!(envelope.payload["object"]["metadata_encryption_floor"].is_null());
    }

    /// Regression: every genesis bootstrap envelope must produce the SAME
    /// canonical digest whether hashed by yougen's local builder or after a
    /// round-trip through the authoritative `cokret_sdk::Event` wire model.
    ///
    /// The bug this guards: genesis preconditions assert `head_eq null` (an
    /// empty cell) and member transitions move `from: null → join`, both of
    /// which carry an EXPLICIT wire `null`. An earlier `Option<Value>` field on
    /// the SDK `Predicate` / `LatticeOp` collapsed that `null` to `None` on
    /// deserialize and dropped it on re-serialize, so the SDK digest no longer
    /// matched the locally-signed one — `submit_event_envelope` failed closed
    /// with "event digest drift between yougen builder and SDK Event" and the
    /// Realm could never be created.
    #[test]
    fn bootstrap_envelopes_have_no_sdk_digest_drift() {
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
            // an invitee exercises the `ck.member.state` `from: null → invite`
            // transition (LatticeOp.from carries an explicit null).
            &["bob:example.com".to_owned()],
            &["did:web:server.example".to_owned()],
        )
        .unwrap();

        for mut envelope in events {
            let kind = envelope.kind.clone();
            // EventWire requires a non-empty proofs vec to deserialize; attach a
            // dummy proof so to_sdk_event() succeeds. proofs are stripped before
            // the digest, so the dummy does not affect the comparison.
            envelope.proofs.push(crate::operation::EventProof {
                kind: "detached_jws".to_owned(),
                alg: "EdDSA".to_owned(),
                verification_method: "did:web:alice.example#k".to_owned(),
                event_digest:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_owned(),
                created_at: envelope.created_at.clone(),
                domain: None,
                audience: None,
                jws: "a.b.c".to_owned(),
            });

            let local = envelope
                .canonical_digest()
                .unwrap_or_else(|err| panic!("{kind}: local canonical_digest: {err}"));
            let sdk = envelope
                .to_sdk_event()
                .unwrap_or_else(|err| panic!("{kind}: to_sdk_event: {err}"))
                .event_digest()
                .unwrap_or_else(|err| panic!("{kind}: SDK event_digest: {err}"));
            assert_eq!(local, sdk, "{kind}: yougen/SDK digest drift");
        }
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
        // `membership_payload` is additionalProperties:false with NO `handle`
        // property — the member identity is carried by `actor_id`, and handle
        // evidence lives on the signed HandleClaim / roster path. The prior
        // `handle` field was an illegal property soland's schema rejected.
        assert!(member.payload.get("handle").is_none());
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
            "ck:realm:0196419b-0000-7000-8000-000000000010",
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
        // Spec `membership_payload` requires `realm_id` in the body for join.
        assert_eq!(
            event.payload["realm_id"],
            "ck:realm:0196419b-0000-7000-8000-000000000010"
        );
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
        let strand_id = "ck:strand:0196419b-0000-7000-8000-000000000002";
        let mut patch = cokret_sdk::Patch::new();
        patch
            .insert_op(
                "fields.document",
                cokret_sdk::PatchOp::set(json!({ "blocks": [] })),
            )
            .unwrap();
        let payload = cokret_sdk::ObjectPatchPayload::for_target(strand_id, patch)
            .unwrap()
            .to_value()
            .unwrap();
        let event = OperationBuilder::new(
            "ck:realm:0196419b-0000-7000-8000-000000000010",
            "did:web:alice.example",
            "ck.strand.update",
        )
        .target_ref(strand_id)
        .body(payload)
        .build("yougen");

        validate_outgoing_registered_payload(&event).unwrap();
    }

    /// Contract test: ck.space.create payload must satisfy spec
    /// space.schema.json — same validator soland runs on the wire.
    #[test]
    fn space_create_payload_matches_spec_schema() {
        // Spec requires payload.object.realm_id to match the
        // `^ck:realm:UUID7` pattern; the product Space id remains a
        // separate `ck:space:*` object id.
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
{"kind":"frontier","frontier":{"ck:realm:demo":["ck:event:01"]}}
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
    /// `ck.schema.device_message.v1` send shape:
    /// `{messages: {<actor>: {<device_id>: {kind, expires_at, content}}}}`.
    /// This matches the SDK `DeviceMessageTarget` and `device-lifecycle.md`
    /// §7, which both make `kind` and `expires_at` required. If the wire
    /// shape drifts (mislabelled `type`, missing `expires_at`, etc.) soland
    /// has to fall back to defaults. This test pins the bytes so a refactor
    /// cannot change them by accident.
    #[test]
    fn device_message_envelope_matches_schema_v1() {
        let envelope = build_device_message_envelope(
            "did:web:alice.example",
            "device-aaaa-1111",
            "ck.key.verification.request",
            "2026-04-26T00:10:00Z",
            json!({
                "method": "sas",
                "transaction_id": "verify-001"
            }),
        )
        .expect("device message envelope builds");
        let envelope = serde_json::to_value(envelope).expect("device message envelope serializes");
        assert_eq!(
            envelope,
            json!({
                "messages": {
                    "did:web:alice.example": {
                        "device-aaaa-1111": {
                            "kind": "ck.key.verification.request",
                            "expires_at": "2026-04-26T00:10:00Z",
                            "content": {
                                "method": "sas",
                                "transaction_id": "verify-001"
                            }
                        }
                    }
                }
            }),
            "wire shape must remain `messages → actor → device_id → {{kind, expires_at, content}}`",
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
            "2026-04-26T00:10:00Z",
            json!({"transaction_id": "verify-done-001"}),
        )
        .expect("device message envelope builds");
        let envelope = serde_json::to_value(envelope).expect("device message envelope serializes");
        let inner = &envelope["messages"]["did:web:bob.example"]["device-bbbb-2222"];
        assert_eq!(inner["kind"], "ck.key.verification.done");
        assert_eq!(inner["expires_at"], "2026-04-26T00:10:00Z");
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
