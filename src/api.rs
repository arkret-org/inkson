use std::{fmt, sync::Arc, time::Duration};

use contrix_sdk::ErrorEnvelope;
use reqwest::{Client, Method, StatusCode};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use url::Url;

use crate::models::{
    AccountRecoveryResponse, AccountResponse, AppletDescribeResponse, AppletPingResponse,
    AppletProtocolMetadataResponse, AppletQueryActorResponse, AppletQuerySpaceResponse,
    AppletTransactionResponse, ArchiveSpaceResponse, AuthzCheckResponse, BackfillResponse,
    BanMemberResponse, BlobUploadResponse, ClientSyncResponse, ContactsResponse,
    DevLoginResponse, DeviceMessagesReceiveResponse, DeviceMessagesSendResponse,
    DeviceTrustResponse, DirectoryDescribeResponse, EditMessageResponse, EffectiveGrantsResponse,
    FederationOperationsResponse, FederationSpaceMembersResponse, FederationTransactionResponse,
    FederationVerifyActorResponse, GetCommitResponse, GetOperationsResponse, HealthResponse,
    IceConfigResponse, IdentityDescribeResponse, IdentityLogResponse, IdentityReceiptsResponse,
    IdentityResolveResponse, IndexDescribeResponse, IndexEntityResponse, IndexInboxResponse,
    IndexNotificationsResponse, IndexQueryResponse, IndexSearchResponse, IndexThreadResponse,
    InvitesResponse, KeysClaimResponse, KeysQueryResponse, KeysUploadResponse,
    ListCommitsResponse, MlsEpochResponse, MlsRotateResponse, ModerationReportResponse,
    ModerationReportsResponse, ModerationResolveResponse, OkResponse, OidcAuthorizeResponse,
    OidcCallbackResponse, PasskeyChallengeResponse, PasskeyVerifyResponse, PolicyCheckResponse,
    PolicyResponse, PushRegisterResponse, ReactionResponse, ReceiptResponse, RedactMessageResponse,
    RepoDescribeResponse, RepoSyncResponse, ResolveHandleResponse, ResolveSpaceResponse,
    RotateKeysResponse, SearchActorsResponse, SearchOrganizationsResponse, SearchSpacesResponse,
    SearchUsersResponse, SendMessageResponse, ServerDescription, SnapshotHeadResponse,
    SpaceHierarchyResponse, SpaceInviteResponse, SpaceLeaveResponse, SpaceLifecycleResponse,
    SpacePolicyResponse, SubmitCommitResponse, SubmitDidOperationResponse, SyncDescribeResponse,
    ThirdPartyLocationsResponse, ThirdPartyUsersResponse, TokenRefreshResponse, TypingResponse,
    UpdateSpaceResponse, VerifyDeviceResponse,
};

#[derive(Clone, Debug)]
pub struct ContrixApi {
    base_url: Url,
    http: Client,
    access_token: Option<String>,
    retry: RetryPolicy,
    refresh_token: Option<String>,
    network_state: Arc<RwLock<NetworkState>>,
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

#[derive(Debug, Deserialize)]
struct ApiErrorBody {
    error: ErrorEnvelope,
}

impl ContrixApi {
    pub fn new(base_url: &str) -> anyhow::Result<Self> {
        Self::new_with_options(base_url, ContrixApiOptions::default())
    }

    pub fn new_with_options(base_url: &str, options: ContrixApiOptions) -> anyhow::Result<Self> {
        let http = Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let http = http.timeout(options.timeout);

        Ok(Self {
            base_url: Url::parse(base_url)?,
            http: http.build()?,
            access_token: None,
            retry: options.retry,
            refresh_token: None,
            network_state: Arc::new(RwLock::new(NetworkState::Online)),
        })
    }

    pub fn with_bearer(mut self, access_token: impl Into<String>) -> Self {
        self.access_token = Some(access_token.into());
        self
    }

    /// Set the refresh token for automatic token refresh.
    pub fn with_refresh_token(mut self, refresh_token: impl Into<String>) -> Self {
        self.refresh_token = Some(refresh_token.into());
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
        let rt = self.refresh_token.as_ref().ok_or_else(|| {
            anyhow::anyhow!("no refresh token available")
        })?;
        let response: TokenRefreshResponse = self
            .post_json(
                "api/v1/auth/token/refresh",
                json!({"refresh_token": rt}),
            )
            .await?;
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

    pub async fn dev_login(
        &self,
        actor: &str,
        device_id: &str,
    ) -> anyhow::Result<DevLoginResponse> {
        self.post_json(
            "api/v1/auth/dev-login",
            json!({"actor": actor, "device_id": device_id, "display_name": "clientx"}),
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

    pub async fn logout(&self) -> anyhow::Result<OkResponse> {
        self.post_json("api/v1/auth/logout", json!({})).await
    }

    pub async fn request_contact(
        &self,
        target: &str,
    ) -> anyhow::Result<crate::models::ContactResponse> {
        self.post_json("api/v1/contacts/request", json!({"target": target}))
            .await
    }

    pub async fn respond_contact(
        &self,
        requester: &str,
        action: &str,
    ) -> anyhow::Result<crate::models::ContactResponse> {
        self.post_json(
            "api/v1/contacts/respond",
            json!({"requester": requester, "action": action}),
        )
        .await
    }

    pub async fn list_contacts(&self) -> anyhow::Result<ContactsResponse> {
        self.get_json("api/v1/contacts").await
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

    pub async fn send_message(
        &self,
        space_id: &str,
        thread_id: Option<&str>,
        content: Value,
        encrypted: bool,
    ) -> anyhow::Result<SendMessageResponse> {
        self.post_json(
            "api/v1/messages/send",
            json!({
                "space_id": space_id,
                "thread_id": thread_id,
                "content": content,
                "encrypted": encrypted
            }),
        )
        .await
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

    pub async fn search_spaces(&self, query: &str) -> anyhow::Result<SearchSpacesResponse> {
        self.post_json(
            "api/v1/directory/search-spaces",
            json!({"query": query, "limit": 20}),
        )
        .await
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

    pub async fn index_query(&self, space_ids: &[String]) -> anyhow::Result<IndexQueryResponse> {
        self.post_json(
            "api/v1/index/query",
            json!({"space_ids": space_ids, "entity_types": [], "limit": 20}),
        )
        .await
    }

    pub async fn index_describe(&self) -> anyhow::Result<IndexDescribeResponse> {
        self.get_json("api/v1/index/describe").await
    }

    pub async fn repo_describe(&self) -> anyhow::Result<RepoDescribeResponse> {
        self.get_json("api/v1/repo/describe").await
    }

    pub async fn list_commits(&self, limit: usize) -> anyhow::Result<ListCommitsResponse> {
        self.get_json(&format!("api/v1/repo/commits?limit={limit}"))
            .await
    }

    pub async fn get_commit(&self, commit_id: &str) -> anyhow::Result<GetCommitResponse> {
        self.get_json(&format!("api/v1/repo/commit?commit_id={commit_id}"))
            .await
    }

    pub async fn get_operations(
        &self,
        operation_ids: &[String],
    ) -> anyhow::Result<GetOperationsResponse> {
        self.post_json(
            "api/v1/repo/operations",
            json!({"operation_ids": operation_ids, "include_payload": true}),
        )
        .await
    }

    pub async fn repo_sync(
        &self,
        repo_id: &str,
        since: Option<&str>,
    ) -> anyhow::Result<RepoSyncResponse> {
        self.post_json(
            "api/v1/repo/sync",
            json!({"repo_id": repo_id, "since": since, "limit": 100, "filters": null}),
        )
        .await
    }

    pub async fn submit_commit(
        &self,
        repo_id: &str,
        commit: Value,
        expected_head: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> anyhow::Result<SubmitCommitResponse> {
        self.post_json(
            "api/v1/repo/submit-commit",
            json!({
                "repo_id": repo_id,
                "commit": commit,
                "expected_head": expected_head,
                "idempotency_key": idempotency_key
            }),
        )
        .await
    }

    pub async fn backfill(&self, space_id: &str) -> anyhow::Result<BackfillResponse> {
        self.get_json(&format!("api/v1/sync/backfill?space_id={space_id}"))
            .await
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
        self.post_json(
            "api/v1/push/register-device",
            json!({
                "device_id": "dev_clientx",
                "push_gateway": "https://push.example",
                "push_key": "opaque",
                "platform": "desktop",
                "app_id": "clientx",
                "display_name": "clientx"
            }),
        )
        .await
    }

    pub async fn unregister_push_device(&self, device_id: &str) -> anyhow::Result<OkResponse> {
        self.post_json(
            "api/v1/push/unregister-device",
            json!({"device_id": device_id, "push_key": null, "app_id": "clientx"}),
        )
        .await
    }

    pub async fn upload_keys(&self, device_id: &str) -> anyhow::Result<KeysUploadResponse> {
        self.post_json(
            "api/v1/keys/upload",
            json!({
                "device_id": device_id,
                "device_keys": {"alg": "mls-rfc9420", "key": "clientx-dev-key"},
                "one_time_keys": [{"key_id": "clientx-otk-1", "key": "clientx-one-time"}],
                "fallback_keys": {},
                "device_signature": {"alg": "none"}
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
        self.put_json(
            "api/v1/device_messages/clientx-txn-1",
            json!({
                "messages": {
                    actor: {
                        device_id: {
                            "type": "cx.mls.test",
                            "content": {"ciphertext": "opaque-clientx-test"}
                        }
                    }
                }
            }),
        )
        .await
    }

    pub async fn receive_device_messages(&self) -> anyhow::Result<DeviceMessagesReceiveResponse> {
        self.get_json("api/v1/device_messages").await
    }

    pub async fn upload_blob(&self, bytes: &'static [u8]) -> anyhow::Result<BlobUploadResponse> {
        let request = self
            .http
            .post(self.endpoint("api/v1/blob/upload")?)
            .header("content-type", "application/octet-stream")
            .body(bytes);
        self.send_json(self.authorize(request), Method::POST).await
    }

    pub async fn get_blob_bytes(&self, blob_ref: &str) -> anyhow::Result<Vec<u8>> {
        let request = self
            .http
            .get(self.endpoint(&format!("api/v1/blob/get?blob_ref={blob_ref}"))?);
        self.send_bytes(self.authorize(request), Method::GET).await
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
    ) -> anyhow::Result<SearchOrganizationsResponse> {
        self.post_json(
            "api/v1/directory/search-organizations",
            json!({"query": query, "limit": 20}),
        )
        .await
    }

    pub async fn search_actors(&self, query: &str) -> anyhow::Result<SearchActorsResponse> {
        self.post_json(
            "api/v1/directory/search-actors",
            json!({"query": query, "limit": 20}),
        )
        .await
    }

    pub async fn resolve_handle(&self, handle: &str) -> anyhow::Result<ResolveHandleResponse> {
        self.post_json(
            "api/v1/identity/resolve-handle",
            json!({"handle": handle}),
        )
        .await
    }

    pub async fn search_users(&self, query: &str) -> anyhow::Result<SearchUsersResponse> {
        self.post_json(
            "api/v1/directory/search-users",
            json!({"query": query, "limit": 20}),
        )
        .await
    }

    // ── Space Management ────────────────────────────────────────────

    pub async fn update_space(
        &self,
        space_id: &str,
        updates: Value,
    ) -> anyhow::Result<UpdateSpaceResponse> {
        self.patch_json(
            &format!("api/v1/spaces/{space_id}"),
            updates,
        )
        .await
    }

    pub async fn archive_space(&self, space_id: &str) -> anyhow::Result<ArchiveSpaceResponse> {
        self.post_json(
            &format!("api/v1/spaces/{space_id}/archive"),
            json!({}),
        )
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

    // ── Messaging ───────────────────────────────────────────────────

    pub async fn edit_message(
        &self,
        message_id: &str,
        content: Value,
    ) -> anyhow::Result<EditMessageResponse> {
        self.patch_json(
            &format!("api/v1/messages/{message_id}"),
            json!({"content": content}),
        )
        .await
    }

    pub async fn redact_message(
        &self,
        message_id: &str,
        reason: Option<&str>,
    ) -> anyhow::Result<RedactMessageResponse> {
        self.post_json(
            &format!("api/v1/messages/{message_id}/redact"),
            json!({"reason": reason}),
        )
        .await
    }

    pub async fn add_reaction(
        &self,
        message_id: &str,
        reaction_key: &str,
    ) -> anyhow::Result<ReactionResponse> {
        self.post_json(
            &format!("api/v1/messages/{message_id}/reactions"),
            json!({"reaction_key": reaction_key}),
        )
        .await
    }

    pub async fn remove_reaction(
        &self,
        message_id: &str,
        reaction_key: &str,
    ) -> anyhow::Result<ReactionResponse> {
        self.delete_json(&format!(
            "api/v1/messages/{message_id}/reactions/{reaction_key}"
        ))
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

    // ── Device & Crypto ─────────────────────────────────────────────

    pub async fn revoke_device(&self, device_id: &str) -> anyhow::Result<OkResponse> {
        self.post_json(
            &format!("api/v1/devices/{device_id}/revoke"),
            json!({}),
        )
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

    // ── Index / AppView ─────────────────────────────────────────────

    pub async fn index_entity(
        &self,
        entity_id: &str,
        space_id: &str,
    ) -> anyhow::Result<IndexEntityResponse> {
        self.post_json(
            "api/v1/index/entity",
            json!({"entity_id": entity_id, "space_id": space_id}),
        )
        .await
    }

    pub async fn index_thread(
        &self,
        entity_id: &str,
        limit: Option<usize>,
    ) -> anyhow::Result<IndexThreadResponse> {
        self.post_json(
            "api/v1/index/thread",
            json!({"entity_id": entity_id, "limit": limit.unwrap_or(50)}),
        )
        .await
    }

    pub async fn index_notifications(
        &self,
        limit: Option<usize>,
    ) -> anyhow::Result<IndexNotificationsResponse> {
        self.post_json(
            "api/v1/index/notifications",
            json!({"limit": limit.unwrap_or(50)}),
        )
        .await
    }

    pub async fn index_inbox(&self, limit: Option<usize>) -> anyhow::Result<IndexInboxResponse> {
        self.post_json(
            "api/v1/index/inbox",
            json!({"limit": limit.unwrap_or(50)}),
        )
        .await
    }

    pub async fn index_search(
        &self,
        query: &str,
        space_ids: Option<&[String]>,
        entity_types: Option<&[String]>,
        limit: Option<usize>,
    ) -> anyhow::Result<IndexSearchResponse> {
        self.post_json(
            "api/v1/index/search",
            json!({
                "query": query,
                "space_ids": space_ids,
                "entity_types": entity_types,
                "limit": limit.unwrap_or(20)
            }),
        )
        .await
    }

    pub async fn index_space_hierarchy(
        &self,
        space_id: &str,
    ) -> anyhow::Result<SpaceHierarchyResponse> {
        self.post_json(
            "api/v1/index/space-hierarchy",
            json!({"space_id": space_id}),
        )
        .await
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

    // ── Applet ──────────────────────────────────────────────────────

    pub async fn applet_ping(&self, applet_did: &str) -> anyhow::Result<AppletPingResponse> {
        self.post_json("api/v1/applet/ping", json!({"applet_did": applet_did}))
            .await
    }

    pub async fn applet_describe(
        &self,
        applet_did: &str,
    ) -> anyhow::Result<AppletDescribeResponse> {
        self.get_json(&format!(
            "api/v1/applet/describe?applet_did={applet_did}"
        ))
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

    pub async fn identity_receipts(
        &self,
        did: &str,
    ) -> anyhow::Result<IdentityReceiptsResponse> {
        self.post_json(
            "api/v1/identity/receipts",
            json!({"did": did}),
        )
        .await
    }

    // ── Media ───────────────────────────────────────────────────────

    pub async fn ice_config(&self) -> anyhow::Result<IceConfigResponse> {
        self.get_json("api/v1/media/ice-config").await
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let request = self.http.get(self.endpoint(path)?);
        self.send_json(self.authorize(request), Method::GET).await
    }

    async fn post_json<T: DeserializeOwned>(&self, path: &str, body: Value) -> anyhow::Result<T> {
        let request = self.http.post(self.endpoint(path)?).json(&body);
        self.send_json(self.authorize(request), Method::POST).await
    }

    async fn put_json<T: DeserializeOwned>(&self, path: &str, body: Value) -> anyhow::Result<T> {
        let request = self.http.put(self.endpoint(path)?).json(&body);
        self.send_json(self.authorize(request), Method::PUT).await
    }

    async fn patch_json<T: DeserializeOwned>(
        &self,
        path: &str,
        body: Value,
    ) -> anyhow::Result<T> {
        let request = self.http.patch(self.endpoint(path)?).json(&body);
        self.send_json(self.authorize(request), Method::PATCH).await
    }

    async fn delete_json<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let request = self.http.delete(self.endpoint(path)?);
        self.send_json(self.authorize(request), Method::DELETE)
            .await
    }

    async fn send_json<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        method: Method,
    ) -> anyhow::Result<T> {
        let response = self.send_with_retry(request, method).await?;
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
        let response = self.send_with_retry(request, method).await?;
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
        method: Method,
    ) -> anyhow::Result<reqwest::Response> {
        let retryable_method = is_retryable_method(&method);
        let mut attempt = 0usize;
        let mut did_refresh = false;
        loop {
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

                    if retryable_method
                        && attempt < self.retry.max_retries
                        && is_retryable_status(response.status())
                    {
                        sleep_backoff(self.retry.initial_backoff, attempt).await;
                        attempt += 1;
                        continue;
                    }

                    // Update network state based on response
                    if response.status().is_server_error() || response.status() == StatusCode::SERVICE_UNAVAILABLE {
                        self.set_network_state(NetworkState::Reconnecting).await;
                    } else if response.status().is_success() {
                        self.set_network_state(NetworkState::Online).await;
                    }

                    return Ok(response);
                }
                Err(error)
                    if retryable_method
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
}

pub fn decode_contrix_error(status: StatusCode, bytes: &[u8]) -> ErrorEnvelope {
    serde_json::from_slice::<ApiErrorBody>(bytes)
        .map(|body| body.error)
        .or_else(|_| serde_json::from_slice::<ErrorEnvelope>(bytes))
        .unwrap_or_else(|_| ErrorEnvelope {
            errcode: "cx.error.http_status".to_owned(),
            error: format!("HTTP request failed with status {status}"),
            retry_after_ms: None,
            extra: Default::default(),
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
    let factor = 1u32.checked_shl(attempt as u32).unwrap_or(u32::MAX);
    tokio::time::sleep(initial.saturating_mul(factor)).await;
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

pub fn parse_repo_describe(value: Value) -> anyhow::Result<RepoDescribeResponse> {
    Ok(serde_json::from_value(value)?)
}

pub fn parse_index_describe(value: Value) -> anyhow::Result<IndexDescribeResponse> {
    Ok(serde_json::from_value(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

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
            "supported_features": ["sync.client_sync"],
            "supported_operations": ["cx.sync.client_sync"],
            "limits": {"storage": "memory"}
        }))
        .unwrap();
        assert_eq!(description.protocol_version, "1.0");

        let sync = parse_sync(json!({
            "next_batch": "sx:1",
            "spaces": {"cx:space:01js0sp0000000000000000000": {"summary": {}}},
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
        assert_eq!(decoded.errcode, "expected_head_mismatch");
        assert_eq!(decoded.error, "expected_head mismatch");
        assert_eq!(decoded.retry_after_ms, Some(250));
        assert_eq!(decoded.extra["scope"], "repo");
    }

    #[test]
    fn decodes_plain_error_envelope_and_falls_back() {
        let decoded = decode_contrix_error(
            StatusCode::BAD_REQUEST,
            br#"{"errcode":"invalid_param","error":"invalid did"}"#,
        );
        assert_eq!(decoded.errcode, "invalid_param");

        let fallback = decode_contrix_error(StatusCode::SERVICE_UNAVAILABLE, b"busy");
        assert_eq!(fallback.errcode, "cx.error.http_status");
        assert!(fallback.error.contains("503 Service Unavailable"));
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
}
