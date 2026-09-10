use std::future::Future;

use super::*;
use crate::api_error::{
    is_account_viewer_projection_missing_error, is_auth_expired_error,
    is_terminal_session_grant_error,
};

#[cfg(target_arch = "wasm32")]
const BOOTSTRAP_NETWORK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);

async fn bootstrap_request<T, F>(label: &'static str, future: F) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>>,
{
    #[cfg(target_arch = "wasm32")]
    {
        tokio::select! {
            result = future => result,
            _ = crate::runtime_helpers::sleep_for(BOOTSTRAP_NETWORK_TIMEOUT) => {
                Err(anyhow::anyhow!(
                    "{label} timed out after {}s",
                    BOOTSTRAP_NETWORK_TIMEOUT.as_secs()
                ))
            }
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = label;
        future.await
    }
}

async fn bootstrap_session_refresh(
    session: &crate::runtime::session::SessionCoordinator,
) -> crate::runtime::session::CurrentSessionRefresh {
    #[cfg(target_arch = "wasm32")]
    {
        tokio::select! {
            result = session.refresh() => result,
            _ = crate::runtime_helpers::sleep_for(BOOTSTRAP_NETWORK_TIMEOUT) => {
                crate::runtime::session::CurrentSessionRefresh::retry_later(format!(
                    "session refresh timed out after {}s",
                    BOOTSTRAP_NETWORK_TIMEOUT.as_secs()
                ))
            }
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        session.refresh().await
    }
}

async fn session_scoped_bootstrap_request<T, F>(
    label: &'static str,
    session: &crate::runtime::session::SessionCoordinator,
    generation: u64,
    future: F,
) -> Option<anyhow::Result<T>>
where
    F: Future<Output = anyhow::Result<T>>,
{
    if session.generation() != generation {
        return None;
    }
    let result = bootstrap_request(label, future).await;
    (session.generation() == generation).then_some(result)
}

#[derive(Clone)]
struct BootstrapSessionLease {
    session: crate::runtime::session::SessionCoordinator,
    generation: u64,
}

impl BootstrapSessionLease {
    fn new(session: crate::runtime::session::SessionCoordinator, generation: u64) -> Self {
        Self {
            session,
            generation,
        }
    }

    fn invalidate(&self, reason: impl Into<String>) -> bool {
        let reason = reason.into();
        let invalidated = self
            .session
            .invalidate_if_generation(self.generation, reason.clone());
        if !invalidated {
            tracing::debug!(
                target: "session_boot",
                lease_generation = self.generation,
                active_generation = self.session.generation(),
                %reason,
                "ignored stale bootstrap session invalidation"
            );
        }
        invalidated
    }

    fn is_current(&self) -> bool {
        self.session.generation() == self.generation
    }
}

impl std::ops::Deref for BootstrapSessionLease {
    type Target = crate::runtime::session::SessionCoordinator;

    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SessionRefreshWritePlan {
    pub(super) grant: bool,
    pub(super) credential: bool,
    pub(super) config: bool,
}

pub(super) fn session_refresh_write_plan(
    current_grant: Option<&PersistedSessionGrant>,
    current_credential: &str,
    current_config: &ClientConfig,
    next_grant: &PersistedSessionGrant,
    desired_config: &ClientConfig,
) -> SessionRefreshWritePlan {
    SessionRefreshWritePlan {
        grant: current_grant != Some(next_grant),
        credential: current_credential != next_grant.grant_jwt,
        config: !current_config.same_runtime_state(desired_config),
    }
}

async fn accepted_account_context(
    authed: &crate::transport::TransportClient,
    principal_id: arkret_sdk::DidCoreId,
    description: Option<&arkret_sdk::ServiceDescribe>,
    current: Option<&crate::identity::active_account::ActiveAccountContext>,
    device_id: &str,
    server_url: &str,
) -> anyhow::Result<crate::identity::active_account::ActiveAccountContext> {
    let device_id = arkret_sdk::DeviceId::new(device_id.trim().to_owned())?;
    let server_url = url::Url::parse(server_url)?;

    // Login/onboarding only publish ActiveAccountContext after verifying the
    // complete principal + Station resolution histories. Connect must
    // reuse that accepted state instead of making an empty, session-scoped DID
    // cache a second authentication authority. The cache is an optimization for
    // later resolutions and is intentionally cleared across account changes.
    if let Some(current) = current.filter(|account| {
        account.authority.principal_id == principal_id
            && description
                .is_none_or(|description| account.authority.station_id == description.service_id)
            && account.device_id == device_id
            && account.server_url == server_url
    }) {
        return Ok(current.clone());
    }

    let description = description.ok_or_else(|| {
        anyhow::anyhow!(
            "Station describe is temporarily unavailable and no accepted account context can be reused"
        )
    })?;
    let authority = arkret_sdk::AccountId::new(principal_id, description.service_id.clone());
    let profile_id = current
        .filter(|account| account.authority == authority)
        .map(|account| account.profile_id.clone())
        .unwrap_or_else(|| format!("ak:profile:{}", crate::operation::uuid_v7()));

    // A missing/mismatched accepted context is repaired through the canonical
    // authenticated Station current-principal result. A cache miss does not
    // establish that the user's session is invalid.
    crate::transport::account::resolve_active_account_context(
        &authed.sdk_http_client()?,
        profile_id,
        authority,
        device_id,
        server_url,
    )
    .await
}

async fn client_core_events_describe(
    authed: &crate::transport::TransportClient,
    _state_store: SyncSignal<LocalStateStore>,
) -> anyhow::Result<arkret_sdk::ServiceDescribe> {
    let http = authed.sdk_http_client()?;
    http.events_describe().await.map_err(Into::into)
}

/// The single source of truth for restoring or rotating the current session credential.
///
/// Registered once at the app root through `RuntimeServices`. Reads the live
/// base URL and accepted account context (so it always targets the active
/// session), then either adopts the current grant JWT or rotates the grant.
/// On success it writes the current credential into the `token` signal and
/// persisted config and returns it. Missing local refresh material is surfaced
/// as a sign-in requirement; only terminal refresh-endpoint errors clear the
/// app-wide session through the invalidator.
///
/// Concurrency is handled by `crate::runtime::session`: callers coalesce onto one
/// in-flight invocation, so this never runs twice in parallel for a single
/// rollover.
pub(super) async fn refresh_session_credential_for_active_context(
    base_url: Signal<String>,
    mut state_store: SyncSignal<LocalStateStore>,
    mut token: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    session_generation: Signal<u64>,
) -> crate::runtime::session::CurrentSessionRefresh {
    let base = base_url();
    let generation = session_generation();
    let active_account = SessionContext::get().active_account;
    let Some(account) = active_account.peek().clone() else {
        // A newly registered account writes its accepted grant durably before
        // publishing the matching ActiveAccountContext. That short commit
        // window is not an authentication failure and must never drive the
        // app-wide invalidator (which navigates to /login).
        return crate::runtime::session::CurrentSessionRefresh::RetryLater {
            reason: "active account context is unavailable".to_owned(),
        };
    };

    #[cfg(target_arch = "wasm32")]
    if let Err(error) = crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson").await
    {
        return crate::runtime::session::CurrentSessionRefresh::RetryLater {
            reason: format!("secure key store is not ready for session refresh: {error}"),
        };
    }

    // Provider restore owns expiry policy, durable rotation, and client rebuild.
    let restored = crate::identity::session_refresh::provide_authenticated_session(&base).await;
    if active_account.peek().as_ref().is_none_or(|current| {
        !current.same_authority(&account) || current.server_url != account.server_url
    }) || session_generation() != generation
    {
        return crate::runtime::session::CurrentSessionRefresh::retry_later(
            "session changed while refresh was in flight",
        );
    }
    match restored {
        Ok(session) => {
            let session_credential = session.grant.grant_jwt.clone();
            let current_grant = {
                let store = state_store.peek();
                store.session_grant()
            };
            let mut desired_config = config_store.peek().load();
            desired_config.session_credential = session_credential.clone();
            let write_plan = session_refresh_write_plan(
                current_grant.as_ref(),
                token.peek().as_str(),
                &config_store.peek().load(),
                &session.grant,
                &desired_config,
            );
            if session_generation() != generation {
                return crate::runtime::session::CurrentSessionRefresh::retry_later(
                    "session changed while refresh was in flight",
                );
            }
            if write_plan.grant {
                state_store
                    .write()
                    .set_session_grant(Some(session.grant.clone()));
            }
            if write_plan.credential {
                token.set(session_credential.clone());
            }
            if write_plan.config {
                persist_config(
                    config_store,
                    account.server_url.to_string(),
                    Some(account.principal_id().clone()),
                    account.device_id.to_string(),
                    session_credential.clone(),
                );
            }
            crate::runtime::session::CurrentSessionRefresh::Credential(session_credential)
        }
        Err(error) if crate::api_error::is_terminal_session_grant_refresh_error(&error) => {
            state_store.write().set_session_grant(None);
            crate::runtime::session::CurrentSessionRefresh::LoginRequired {
                reason: format!("session grant could not be rotated: {error}"),
            }
        }
        Err(error) if error.to_string().contains("no session grant is available") => {
            crate::runtime::session::CurrentSessionRefresh::SignInRequired {
                reason: error.to_string(),
            }
        }
        Err(error) => crate::runtime::session::CurrentSessionRefresh::RetryLater {
            reason: error.to_string(),
        },
    }
}

fn invalidate_bootstrap_session(
    session: &BootstrapSessionLease,
    reason: impl Into<String>,
    session_boot_state: Signal<SessionBootState>,
    mut sync_bootstrap_complete: Signal<bool>,
) {
    if session.invalidate(reason) {
        transition_session_boot_state(
            session_boot_state,
            SessionBootState::Unauthenticated,
            "bootstrap invalidated the active session",
        );
        sync_bootstrap_complete.set(true);
    }
}

/// Keep an accepted credential alive when bootstrap is temporarily unable to
/// finish. The single bootstrap effect is re-armed after a short delay; only a
/// terminal session result is allowed to call `invalidate_bootstrap_session`.
fn defer_bootstrap_retry(
    session: BootstrapSessionLease,
    reason: String,
    mut connection_status: Signal<String>,
    mut network_state: Signal<String>,
    mut last_error: Signal<Option<String>>,
    mut sync_bootstrap_complete: Signal<bool>,
    mut bootstrap_pending: Signal<bool>,
) {
    let retry_marker = reason.clone();
    connection_status.set(format!(
        "{}: {reason}",
        ConnectionState::Reconnecting.label()
    ));
    network_state.set("reconnecting".to_owned());
    last_error.set(Some(reason));
    sync_bootstrap_complete.set(true);
    spawn(async move {
        crate::runtime_helpers::sleep_for(std::time::Duration::from_secs(2)).await;
        if session.is_current()
            && *sync_bootstrap_complete.peek()
            && last_error.peek().as_deref() == Some(retry_marker.as_str())
        {
            bootstrap_pending.set(true);
        }
    });
}

#[derive(Clone)]
pub(super) struct ConnectContext {
    pub(super) session: crate::runtime::session::SessionCoordinator,
    /// Connection-lifecycle label (offline / loading / online / error).
    pub(super) connection_status: Signal<String>,
    pub(super) sync_cursor: Signal<String>,
    pub(super) token: Signal<String>,
    pub(super) principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    pub(super) selected_realm_id: Signal<String>,
    pub(super) realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    pub(super) projection_events: Signal<Vec<ProjectionEvent>>,
    pub(super) device_queue: Signal<usize>,
    pub(super) crypto_state: Signal<String>,
    pub(super) config_store: Signal<LocalConfigStore>,
    pub(super) state_store: SyncSignal<LocalStateStore>,
    pub(super) network_state: Signal<String>,
    pub(super) last_error: Signal<Option<String>>,
    pub(super) server_description: Signal<Option<ServiceDescribe>>,
    pub(super) server_probe_status: Signal<String>,
    pub(super) account_primary_handle: Signal<String>,
    pub(super) personal_handles: Signal<Vec<String>>,
    pub(super) personal_handles_status: Signal<String>,
    /// SyncEngine generation counter. Bumped when `connect()` detects
    /// the canonical actor has changed since the last persisted run
    /// (account swap on the same device) so any in-flight engine for
    /// the previous account exits before applying its response.
    pub(super) sync_generation: Signal<u64>,
    pub(super) needs_device_authorization: Signal<bool>,
    pub(super) device_authorization_check_complete: Signal<bool>,
    pub(super) account_has_other_devices: Signal<bool>,
    /// Set when the explicit bootstrap/manual connect attempt has completed.
    /// The background SyncEngine waits for this so it does not race the
    /// first full account-subscribe snapshot on the same render.
    pub(super) sync_bootstrap_complete: Signal<bool>,
    pub(super) session_boot_state: Signal<SessionBootState>,
    /// Re-arms the single bootstrap effect after a retryable failure without
    /// converting that failure into a logout.
    pub(super) bootstrap_pending: Signal<bool>,
    /// Session DID-resolution cache handle. Root identity verification uses a
    /// complete retained history instead of depending on this cache. Downstream
    /// resolver back-fills are shared with SyncEngine for reuse.
    /// App-shell DID resolution health banner state. The root identity
    /// describe probe updates this on every connect/manual refresh; authority
    /// resolution availability is reported by the configured Station.
    pub(super) did_resolution_health: Signal<crate::components::DidResolutionHealth>,
}

pub(super) fn redirect_to_login(navigator: Navigator) {
    let _ = navigator.push(Route::Login);
}

fn attach_current_session_material(
    api: TransportClient,
    store: &mut crate::state::LocalStateStore,
) -> anyhow::Result<TransportClient> {
    match crate::identity::account_auth::grant_dpop::load_or_recover_device_key(store) {
        Ok(Some(handle)) => api.with_dpop_device(handle),
        Ok(None) => {
            tracing::warn!(
                target: "session_boot",
                "session DPoP device key unavailable; self-path requests will be rejected until sign-in refreshes the device key"
            );
            Ok(api)
        }
        Err(error) => {
            tracing::warn!(
                target: "session_boot",
                %error,
                "session DPoP device key load/recovery failed"
            );
            Ok(api)
        }
    }
}

fn current_base_api(
    base: &str,
    mut state_store: SyncSignal<LocalStateStore>,
) -> anyhow::Result<TransportClient> {
    let api = TransportClient::unauthenticated(base)?;
    let mut store = state_store.write();
    attach_current_session_material(api, &mut store)
}

fn current_authed_api(
    base: &str,
    session_credential: &str,
    _state_store: SyncSignal<LocalStateStore>,
) -> anyhow::Result<TransportClient> {
    crate::transport::auth::authed_api(base, session_credential.to_owned())
}

/// ②(A+②) — build a `/_arkret/self/*`-ready client: the credential
/// (`ak.session.grant` JWT) in the HTTP Bearer authorization slot plus the
/// grant-binding (DPoP) key so each request carries a per-request `DPoP` proof
/// (api-conventions.md §3.3).
/// Used by standalone (non-`connect`) self-path call sites that build their own
/// `TransportClient`. Best-effort on the DPoP key: if it cannot be loaded the
/// credential is still attached while the request remains server-authenticated
/// by the active session grant.
pub(super) fn self_authed_api(
    base: &str,
    session_credential: impl Into<String>,
) -> anyhow::Result<TransportClient> {
    crate::transport::auth::authed_api(base, session_credential.into())
}

pub(super) fn adopt_live_token_for_api(
    base: &str,
    state_store: SyncSignal<LocalStateStore>,
    live_token: Signal<String>,
    session_credential: &mut String,
    authed: &mut TransportClient,
) {
    let latest = live_token();
    if !latest.trim().is_empty() && latest != *session_credential {
        *session_credential = latest.clone();
        if let Ok(api) = current_authed_api(base, &latest, state_store) {
            *authed = api;
        }
    }
}

fn device_authorization_probe_from_account_viewer(
    viewer: &serde_json::Value,
    device: &str,
    signer_matches_directory: bool,
) -> (bool, bool) {
    let has_other = account_has_other_active_devices_from_account_viewer(viewer, device);
    let needs_authorization = device_authorization_required_from_account_viewer(viewer, device)
        || !signer_matches_directory;
    (needs_authorization, has_other)
}

/// Determine whether the current device is durably authorized. This is a
/// read-only probe: the account-first onboarding flow owns the atomic founding
/// device bootstrap, while every later or key-mismatched device must use the
/// user-approved pairing/recovery flow from key-management.md §5.1.
pub(super) async fn probe_device_authorization(
    account: &crate::config::ActiveAccountContext,
    device: &str,
    principal_api: &TransportClient,
) -> anyhow::Result<(bool, bool)> {
    // The account-viewer helpers read `devices[]` leniently via `Value`
    // accessors; serialize the typed `AccountView` back to its wire JSON.
    let viewer = serde_json::to_value(
        &crate::transport::keys::list_devices(&principal_api.sdk_http_client()?).await?,
    )?;
    let signer_matches_directory =
        current_event_signer_matches_directory(principal_api, account, device).await?;
    Ok(device_authorization_probe_from_account_viewer(
        &viewer,
        device,
        signer_matches_directory,
    ))
}

/// An `active` account-viewer row is not sufficient authorization for
/// persistent Event proofs: the authoritative keys directory must carry the
/// exact Ed25519 key used by this browser's active signer. A mismatch is a
/// subsequent-device or key-loss condition and must never overwrite the
/// accepted device through the founding enrollment endpoint.
async fn current_event_signer_matches_directory(
    principal_api: &TransportClient,
    account: &crate::config::ActiveAccountContext,
    device: &str,
) -> anyhow::Result<bool> {
    let signer = match crate::event_signer::active_signer() {
        Some(signer) => signer,
        None => crate::event_signer::bootstrap_default_signer("inkson")
            .map_err(|error| anyhow::anyhow!("bootstrap device signer: {error}"))?,
    };
    let account_id = &account.authority;
    let actor_id = account.principal_id();
    let signer = crate::event_signer::bind_active_signer_device_id(device)
        .map_err(|error| anyhow::anyhow!("bind event signer device: {error}"))?
        .unwrap_or(signer);
    let signer_did = arkret_sdk::Did::new(signer.signer_did().to_owned())?;
    if &arkret_sdk::project_did_to_core_id(&signer_did)? != actor_id {
        return Ok(false);
    }
    let Some(public_key) = signer.public_key_multibase() else {
        return Ok(false);
    };
    let device_cache_epoch = crate::identity::device_directory::cache_epoch();
    let outcome =
        crate::transport::keys::query_keys(&principal_api.sdk_http_client()?, account_id, device)
            .await?;
    let device_id = arkret_sdk::DeviceId::new(device.to_owned())?;
    let expected_key = format!("did:key:{public_key}");
    let signer_matches = outcome
        .devices_for(account_id)
        .and_then(|devices| devices.get(&device_id))
        .map(|record| {
            record
                .device_projection_attestation
                .attestation
                .device_signing_key_did
                .as_str()
        })
        == Some(expected_key.as_str());
    if !signer_matches {
        return Ok(false);
    }
    let accepted_key =
        crate::identity::device_directory::cache_accepted_device_evidence_from_outcome(
            device_cache_epoch,
            &outcome,
            account_id,
            device,
        );
    if accepted_key.as_ref()
        != crate::identity::device_directory::public_key_from_directory_value(&expected_key)
            .as_ref()
    {
        return Ok(false);
    }
    crate::identity::authoring_generation::cache_principal_authoring_generation_from_keys(
        &outcome, account_id, device,
    )
}

pub(super) fn connect(
    base: String,
    actor: Option<arkret_sdk::DidCoreId>,
    device: String,
    ctx: ConnectContext,
) {
    let device = crate::config::normalize_device_id(&device);
    let mut active_account = SessionContext::get().active_account;
    spawn(async move {
        let session = ctx.session.clone();
        // Capture the owner before the first network await. A login can finish
        // while the unauthenticated describe probes below are still running;
        // that older task must never adopt the replacement credential and
        // continue as though it were the new login's bootstrap.
        let bootstrap_session_generation = session.generation();
        let mut sync_bootstrap_complete = ctx.sync_bootstrap_complete;
        // Connection-lifecycle status only; operation feedback goes through
        // `crate::components::feedback` toasts.
        let mut status = ctx.connection_status;
        let mut sync_cursor = ctx.sync_cursor;
        let token = ctx.token;
        let mut principal_id = ctx.principal_id;
        let mut selected_realm_id = ctx.selected_realm_id;
        let mut realm_tree_nodes = ctx.realm_tree_nodes;
        let mut projection_events = ctx.projection_events;
        let mut device_queue = ctx.device_queue;
        let mut crypto_state = ctx.crypto_state;
        let mut config_store = ctx.config_store;
        let mut state_store = ctx.state_store;
        let mut network_state = ctx.network_state;
        let mut last_error = ctx.last_error;
        let mut server_description = ctx.server_description;
        let mut server_probe_status = ctx.server_probe_status;
        let mut account_primary_handle = ctx.account_primary_handle;
        let mut personal_handles = ctx.personal_handles;
        let mut personal_handles_status = ctx.personal_handles_status;
        let session_boot_state = ctx.session_boot_state;
        let mut needs_device_authorization = ctx.needs_device_authorization;
        let mut device_authorization_check_complete = ctx.device_authorization_check_complete;
        let mut account_has_other_devices = ctx.account_has_other_devices;
        let mut did_resolution_health = ctx.did_resolution_health;
        let bootstrap_pending = ctx.bootstrap_pending;

        // A (re)connect may point at a different / re-provisioned Account
        // Authority, so drop the cached authority resolution and let the first
        // describe below repopulate it. Steady-state session refreshes then
        // reuse that cache instead of re-probing `/_arkret/describe`.
        crate::identity::account_auth::clear_authority_resolver_cache();
        crate::identity::device_directory::reset_session_cache();
        did_resolution_health.set(crate::components::DidResolutionHealth::healthy());
        needs_device_authorization.set(false);
        device_authorization_check_complete.set(false);
        account_has_other_devices.set(false);
        tracing::debug!(target: "session_boot", token_empty = token().trim().is_empty(), "connect: starting bootstrap connect (sets Checking/Restoring; only reaches Authenticated at end)");
        transition_session_boot_state(
            session_boot_state,
            if token().trim().is_empty() {
                SessionBootState::Restoring
            } else {
                SessionBootState::Checking
            },
            "bootstrap connect started",
        );
        status.set(ConnectionState::Loading.label().to_owned());
        network_state.set("reconnecting".to_owned());
        last_error.set(None);
        match current_base_api(&base, state_store) {
            Ok(api) => {
                // Probe `/server/describe` for status text, but treat failure
                // as non-fatal: a transient describe error (CORS preflight,
                // server warming up, brief 5xx) must not block the sync below
                // — otherwise an existing session with cached/server-side
                // the Realm tree silently renders "No Realm tree loaded" until the user
                // manually retries.
                let description = match bootstrap_request("server describe", api.describe()).await {
                    Ok(description) => {
                        let missing = missing_v1_station_requirements(&description);
                        if !missing.is_empty() {
                            let message =
                                format!("server describe rejected: missing {}", missing.join(", "));
                            status.set(format!("{}: {message}", ConnectionState::Error.label()));
                            network_state.set("offline".to_owned());
                            last_error.set(Some(message.clone()));
                            server_probe_status.set(message);
                            crate::operation::set_authoring_station_id(None);
                            server_description.set(None);
                            did_resolution_health
                                .set(crate::components::DidResolutionHealth::unsupported_station());
                            transition_session_boot_state(
                                session_boot_state,
                                if token().trim().is_empty() {
                                    SessionBootState::Unauthenticated
                                } else {
                                    SessionBootState::Authenticated
                                },
                                "server does not satisfy bootstrap requirements",
                            );
                            sync_bootstrap_complete.set(true);
                            return;
                        }
                        status.set(format!(
                            "{}: {} / {}",
                            ConnectionState::Online.label(),
                            description.service_kind,
                            description.protocol_version
                        ));
                        network_state.set("online".to_owned());
                        server_probe_status.set(format!(
                            "server describe loaded: {} / {}",
                            description.service_kind, description.protocol_version
                        ));
                        // Cache the advertised trust_domain so
                        // downstream signing strands and S2S transcripts can pull a canonical
                        // value off local state without an extra round
                        // trip. Cleared when describe fails so a stale
                        // domain can't leak into the next strand.
                        {
                            let mut store = state_store.write();
                            let mut snapshot = store.load();
                            // `TrustDomainId` enforces a non-empty
                            // `ak:trust_domain:<scope>` shape at deserialize
                            // time, so the previous "is_empty" guard is
                            // structurally impossible. Always cache.
                            snapshot.server_trust_domain =
                                Some(description.trust_domain.as_str().to_owned());
                            store.save(snapshot);
                        }
                        crate::operation::set_authoring_station_id(Some(
                            description.service_id.clone(),
                        ));
                        server_description.set(Some(description.clone()));
                        Some(description)
                    }
                    Err(error) => {
                        status.set(format!(
                            "{}: describe failed: {error}; trying sync",
                            ConnectionState::Reconnecting.label()
                        ));
                        network_state.set("reconnecting".to_owned());
                        last_error.set(Some(format!("describe: {error}")));
                        server_probe_status.set(format!("server describe failed: {error}"));
                        crate::operation::set_authoring_station_id(None);
                        server_description.set(None);
                        None
                    }
                };

                let identity_health = match bootstrap_request("identity describe", async {
                    crate::transport::account::identity_describe(&api.sdk_http_client()?).await
                })
                .await
                {
                    Ok(identity) => {
                        crate::components::DidResolutionHealth::from_identity_description(&identity)
                    }
                    Err(error) => {
                        tracing::warn!(?error, "identity describe probe failed");
                        crate::components::DidResolutionHealth::from_probe_error(&error)
                    }
                };
                did_resolution_health.set(identity_health);

                if session.generation() != bootstrap_session_generation {
                    return;
                }
                let session_refresh = bootstrap_session_refresh(&session).await;
                if session.generation() != bootstrap_session_generation {
                    return;
                }
                let mut session_credential;
                match session_refresh {
                    crate::runtime::session::CurrentSessionRefresh::Credential(refreshed) => {
                        session_credential = refreshed;
                        transition_session_boot_state(
                            session_boot_state,
                            SessionBootState::Checking,
                            "session credential restored for bootstrap",
                        );
                    }
                    crate::runtime::session::CurrentSessionRefresh::SignInRequired { reason } => {
                        let probe_label = description
                            .as_ref()
                            .map(|d| format!("{} / {}", d.service_kind, d.protocol_version))
                            .unwrap_or_else(|| "server probe unavailable".to_owned());
                        status.set(format!("Refreshed: {probe_label}; sign-in required"));
                        network_state.set("online".to_owned());
                        crypto_state.set("No authenticated session".to_owned());
                        last_error.set(Some(reason.clone()));
                        needs_device_authorization.set(false);
                        device_authorization_check_complete.set(true);
                        session.invalidate(reason);
                        sync_bootstrap_complete.set(true);
                        return;
                    }
                    // SessionCoordinator invalidates before returning this
                    // variant, so the generation guard above has already
                    // returned. Keep this arm exhaustive and side-effect free.
                    crate::runtime::session::CurrentSessionRefresh::LoginRequired { .. } => {
                        return;
                    }
                    crate::runtime::session::CurrentSessionRefresh::RetryLater { reason } => {
                        let reason = format!("session credential restore deferred: {reason}");
                        defer_bootstrap_retry(
                            BootstrapSessionLease::new(
                                session.clone(),
                                bootstrap_session_generation,
                            ),
                            reason,
                            status,
                            network_state,
                            last_error,
                            sync_bootstrap_complete,
                            bootstrap_pending,
                        );
                        return;
                    }
                }
                let session =
                    BootstrapSessionLease::new(session.clone(), bootstrap_session_generation);

                let Ok(mut authed) = current_authed_api(&base, &session_credential, state_store)
                else {
                    defer_bootstrap_retry(
                        session.clone(),
                        "authenticated session transport is not initialized yet".to_owned(),
                        status,
                        network_state,
                        last_error,
                        sync_bootstrap_complete,
                        bootstrap_pending,
                    );
                    return;
                };
                adopt_live_token_for_api(
                    &base,
                    state_store,
                    token,
                    &mut session_credential,
                    &mut authed,
                );
                // Resolve the canonical stable principal id from the account viewer. Three
                // outcomes:
                //   1. Ok with non-empty id -> use it as the canonical principal id.
                //   2. Err that looks like auth expiry -> try the shared session refresh path. If
                //      the refreshed credential is still rejected, clear the stale session instead
                //      of booting the shell with a bearer token the server will never accept.
                //   3. Anything else (Ok with empty id, transient 5xx, parse error, network
                //      failure) -> fall back to the locally stored actor, log a diagnostic to
                //      last_error so the sidebar/status surface can show it, and keep going so sync
                //      still has a chance to populate realm_tree_nodes.
                let mut account_personal_handle = None::<String>;
                let Some(account_viewer_result) = session_scoped_bootstrap_request(
                    "account viewer",
                    &session,
                    bootstrap_session_generation,
                    async {
                        crate::transport::account::account_me(&authed.sdk_http_client()?).await
                    },
                )
                .await
                else {
                    return;
                };
                let canonical_actor_hint = match account_viewer_result {
                    Ok(account) => {
                        account_personal_handle =
                            personal_handle_from_account_handle(&account.handle);
                        account.principal_id.to_string()
                    }
                    Err(error) if is_account_viewer_projection_missing_error(&error) => {
                        invalidate_bootstrap_session(
                            &session,
                            format!(
                                "Station account projection is missing; sign in again to recreate it: {error}"
                            ),
                            session_boot_state,
                            sync_bootstrap_complete,
                        );
                        return;
                    }
                    Err(error) if is_auth_expired_error(&error) => {
                        match bootstrap_session_refresh(&session).await {
                            crate::runtime::session::CurrentSessionRefresh::Credential(
                                refreshed,
                            ) => {
                                session_credential = refreshed;
                                let Ok(rebound) =
                                    current_authed_api(&base, &session_credential, state_store)
                                else {
                                    defer_bootstrap_retry(
                                        session.clone(),
                                        "refreshed session transport is not initialized yet"
                                            .to_owned(),
                                        status,
                                        network_state,
                                        last_error,
                                        sync_bootstrap_complete,
                                        bootstrap_pending,
                                    );
                                    return;
                                };
                                authed = rebound;
                                let Some(account_viewer_retry_result) =
                                    session_scoped_bootstrap_request(
                                        "account viewer retry",
                                        &session,
                                        bootstrap_session_generation,
                                        async {
                                            crate::transport::account::account_me(
                                                &authed.sdk_http_client()?,
                                            )
                                            .await
                                        },
                                    )
                                    .await
                                else {
                                    return;
                                };
                                match account_viewer_retry_result {
                                    Ok(account) => {
                                        account_personal_handle =
                                            personal_handle_from_account_handle(&account.handle);
                                        account.principal_id.to_string()
                                    }
                                    Err(retry_error)
                                        if is_account_viewer_projection_missing_error(
                                            &retry_error,
                                        ) =>
                                    {
                                        invalidate_bootstrap_session(
                                            &session,
                                            format!(
                                                "Station account projection is missing after session refresh; sign in again to recreate it: {retry_error}"
                                            ),
                                            session_boot_state,
                                            sync_bootstrap_complete,
                                        );
                                        return;
                                    }
                                    Err(retry_error) if !is_auth_expired_error(&retry_error) => {
                                        last_error.set(Some(format!("account_me: {retry_error}")));
                                        crate::app::principal_id_owned(actor.clone())
                                    }
                                    Err(retry_error)
                                        if is_terminal_session_grant_error(&retry_error) =>
                                    {
                                        invalidate_bootstrap_session(
                                            &session,
                                            format!(
                                                "account_me rejected refreshed session: {retry_error}"
                                            ),
                                            session_boot_state,
                                            sync_bootstrap_complete,
                                        );
                                        return;
                                    }
                                    Err(retry_error) if is_auth_expired_error(&retry_error) => {
                                        defer_bootstrap_retry(
                                            session.clone(),
                                            format!(
                                                "account_me temporarily rejected refreshed session: {retry_error}"
                                            ),
                                            status,
                                            network_state,
                                            last_error,
                                            sync_bootstrap_complete,
                                            bootstrap_pending,
                                        );
                                        return;
                                    }
                                    Err(retry_error) => {
                                        last_error.set(Some(format!("account_me: {retry_error}")));
                                        crate::app::principal_id_owned(actor.clone())
                                    }
                                }
                            }
                            crate::runtime::session::CurrentSessionRefresh::SignInRequired {
                                reason,
                            } => {
                                invalidate_bootstrap_session(
                                    &session,
                                    reason,
                                    session_boot_state,
                                    sync_bootstrap_complete,
                                );
                                return;
                            }
                            crate::runtime::session::CurrentSessionRefresh::LoginRequired {
                                ..
                            } => return,
                            crate::runtime::session::CurrentSessionRefresh::RetryLater {
                                reason,
                            } => {
                                defer_bootstrap_retry(
                                    session.clone(),
                                    format!(
                                        "account_me rejected current session and refresh could not complete: {reason}; account_me: {error}"
                                    ),
                                    status,
                                    network_state,
                                    last_error,
                                    sync_bootstrap_complete,
                                    bootstrap_pending,
                                );
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        last_error.set(Some(format!("account_me: {error}")));
                        crate::app::principal_id_owned(actor.clone())
                    }
                };
                let canonical_principal_id =
                    arkret_sdk::DidCoreId::new(canonical_actor_hint.trim().to_owned());
                let Ok(canonical_principal_id) = canonical_principal_id else {
                    invalidate_bootstrap_session(
                        &session,
                        "account viewer did not yield a valid stable principal",
                        session_boot_state,
                        sync_bootstrap_complete,
                    );
                    return;
                };
                let current_account = active_account.peek().clone();
                let mut accepted_account = match accepted_account_context(
                    &authed,
                    canonical_principal_id.clone(),
                    description.as_ref(),
                    current_account.as_ref(),
                    &device,
                    &base,
                )
                .await
                {
                    Ok(account) => account,
                    Err(error) => {
                        defer_bootstrap_retry(
                            session.clone(),
                            format!(
                                "current principal resolution could not be accepted yet: {error}"
                            ),
                            status,
                            network_state,
                            last_error,
                            sync_bootstrap_complete,
                            bootstrap_pending,
                        );
                        return;
                    }
                };
                if !session.is_current() {
                    return;
                }
                if accepted_account.principal_id() != &canonical_principal_id {
                    invalidate_bootstrap_session(
                        &session,
                        "accepted principal resolution does not match the authenticated principal",
                        session_boot_state,
                        sync_bootstrap_complete,
                    );
                    return;
                }
                let canonical_runtime_principal = Some(canonical_principal_id.clone());
                let mut profiles = config_store.read().load_profiles();
                let profile_id =
                    match profiles.upsert_and_activate(crate::config::AccountProfile::new(
                        accepted_account.clone(),
                        session_credential.clone(),
                    )) {
                        Ok(profile_id) => profile_id,
                        Err(error) => {
                            invalidate_bootstrap_session(
                                &session,
                                format!("accepted account profile update rejected: {error}"),
                                session_boot_state,
                                sync_bootstrap_complete,
                            );
                            return;
                        }
                    };
                accepted_account.profile_id = profile_id;
                {
                    let mut store = config_store.write();
                    store.save(ClientConfig::authenticated(
                        accepted_account.clone(),
                        session_credential.clone(),
                    ));
                    if let Some(error) = store.persist_error() {
                        defer_bootstrap_retry(
                            session.clone(),
                            format!("accepted account config persist failed: {error}"),
                            status,
                            network_state,
                            last_error,
                            sync_bootstrap_complete,
                            bootstrap_pending,
                        );
                        return;
                    }
                    if let Err(error) = store.save_profiles(&profiles) {
                        defer_bootstrap_retry(
                            session.clone(),
                            format!("accepted account profile persist failed: {error}"),
                            status,
                            network_state,
                            last_error,
                            sync_bootstrap_complete,
                            bootstrap_pending,
                        );
                        return;
                    }
                }
                let account_changed =
                    match state_store.write().switch_active_account(&accepted_account) {
                        Ok(changed) => changed,
                        Err(error) => {
                            defer_bootstrap_retry(
                                session.clone(),
                                format!("accepted account namespace activation failed: {error}"),
                                status,
                                network_state,
                                last_error,
                                sync_bootstrap_complete,
                                bootstrap_pending,
                            );
                            return;
                        }
                    };
                active_account.set(Some(accepted_account.clone()));
                if account_changed {
                    account_primary_handle.set(String::new());
                    personal_handles.set(Vec::new());
                    personal_handles_status.set("Not published".to_owned());
                    // Account changed since the last persisted run (the
                    // server's account viewer disagrees with our cached
                    // actor). When the previous actor was non-empty this
                    // means a different human is signing in on the same
                    // device — every account-scoped record (projections,
                    // drafts, seal views, read markers, remarks, and the
                    // previous identity's session grant + OIDC bundle) is
                    // someone else's data and must be wiped before the sync
                    // below repopulates the store. Account switching loads the
                    // new owner's isolated entry. Device-level state
                    // (local_identity, push_registration, DPoP key) is
                    // preserved.
                    if actor.is_some() {
                        let store = state_store.write();
                        // Also wipe the in-memory UI signals so the
                        // sidebar can't paint the previous actor's
                        // Realm tree updates between this point and the sync that's
                        // about to run.
                        drop(store);
                        realm_tree_nodes.set(Vec::new());
                        projection_events.set(Vec::new());
                        selected_realm_id.set(String::new());
                        sync_cursor.set(String::new());
                        device_queue.set(0);
                        // Retire the previous-account SyncEngine so its
                        // in-flight long-poll doesn't write back into
                        // the freshly-wiped state.
                        let mut sync_generation = ctx.sync_generation;
                        sync_generation.set(sync_generation() + 1);
                    } else {
                        // No previous identity to displace — just record
                        // who the scope now belongs to (don't wipe: a
                        // just-established grant could be dropped).
                    }
                    principal_id.set(canonical_runtime_principal.clone());
                }
                principal_id.set(canonical_runtime_principal);
                if let Some(personal_handle) = account_personal_handle {
                    account_primary_handle.set(personal_handle.clone());
                    let handles = merge_personal_handles(&personal_handles(), [personal_handle]);
                    personal_handles_status.set(personal_handles_status_for(&handles));
                    personal_handles.set(handles);
                } else if personal_handles().is_empty() {
                    personal_handles_status.set("Not published".to_owned());
                }
                let grant_device = {
                    let canonical_actor_id = Some(accepted_account.principal_id().clone());
                    let store = state_store.read();
                    store
                        .session_grant()
                        .filter(|grant| {
                            canonical_actor_id.as_ref().is_some_and(|principal_id| {
                                crate::identity::session_refresh::grant_matches_principal_id(
                                    grant,
                                    principal_id,
                                )
                            }) && crate::identity::session_refresh::grant_matches_station(
                                grant, &base,
                            ) && crate::config::is_valid_device_id(grant.device_id.as_str())
                        })
                        .map(|grant| grant.device_id)
                };
                if let Some(grant_device) = grant_device
                    && grant_device.as_str() != device
                {
                    invalidate_bootstrap_session(
                        &session,
                        format!(
                            "session grant device {} does not match active account device {}",
                            grant_device, accepted_account.device_id
                        ),
                        session_boot_state,
                        sync_bootstrap_complete,
                    );
                    return;
                }
                {
                    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                    match arkret_sdk::DeviceId::new(device.clone()) {
                        Ok(device_id) => {
                            match crate::secure_key_store::UserLocalStore::new(
                                accepted_account.authority.clone(),
                                device_id.clone(),
                            ) {
                                Ok(user_store) => {
                                    user_store.activate();
                                    if let Err(error) =
                                        user_store.save_device_id(secure_store.as_ref(), &device_id)
                                    {
                                        tracing::warn!(
                                            ?error,
                                            "connect: persist canonical device_id failed"
                                        );
                                    }
                                }
                                Err(error) => tracing::warn!(
                                    ?error,
                                    "connect: canonical secure scope is invalid"
                                ),
                            }
                        }
                        Err(error) => {
                            tracing::warn!(?error, "connect: canonical device_id is invalid")
                        }
                    }
                    if let Err(error) =
                        crate::event_signer::bootstrap_default_signer_for_device("inkson", &device)
                    {
                        tracing::warn!(?error, "connect: device identity signer bootstrap failed");
                    }
                }
                adopt_live_token_for_api(
                    &base,
                    state_store,
                    token,
                    &mut session_credential,
                    &mut authed,
                );
                let Some(device_authorization_result) = session_scoped_bootstrap_request(
                    "device authorization check",
                    &session,
                    bootstrap_session_generation,
                    probe_device_authorization(&accepted_account, &device, &authed),
                )
                .await
                else {
                    return;
                };
                match device_authorization_result {
                    Ok((needs_authorization, has_other)) => {
                        account_has_other_devices.set(has_other);
                        needs_device_authorization.set(needs_authorization);
                        device_authorization_check_complete.set(true);
                    }
                    Err(error) if is_auth_expired_error(&error) => {
                        match bootstrap_session_refresh(&session).await {
                            crate::runtime::session::CurrentSessionRefresh::Credential(
                                refreshed,
                            ) => {
                                session_credential = refreshed;
                                let Ok(rebound) =
                                    current_authed_api(&base, &session_credential, state_store)
                                else {
                                    defer_bootstrap_retry(
                                        session.clone(),
                                        "refreshed session transport is not initialized yet"
                                            .to_owned(),
                                        status,
                                        network_state,
                                        last_error,
                                        sync_bootstrap_complete,
                                        bootstrap_pending,
                                    );
                                    return;
                                };
                                authed = rebound;
                                let Some(device_authorization_retry_result) =
                                    session_scoped_bootstrap_request(
                                        "device authorization retry",
                                        &session,
                                        bootstrap_session_generation,
                                        probe_device_authorization(
                                            &accepted_account,
                                            &device,
                                            &authed,
                                        ),
                                    )
                                    .await
                                else {
                                    return;
                                };
                                match device_authorization_retry_result {
                                    Ok((needs_authorization, has_other)) => {
                                        account_has_other_devices.set(has_other);
                                        needs_device_authorization.set(needs_authorization);
                                    }
                                    Err(retry_error)
                                        if is_terminal_session_grant_error(&retry_error) =>
                                    {
                                        invalidate_bootstrap_session(
                                            &session,
                                            format!(
                                                "device authorization rejected refreshed session: {retry_error}"
                                            ),
                                            session_boot_state,
                                            sync_bootstrap_complete,
                                        );
                                        return;
                                    }
                                    Err(retry_error) if is_auth_expired_error(&retry_error) => {
                                        defer_bootstrap_retry(
                                            session.clone(),
                                            format!(
                                                "device authorization temporarily rejected refreshed session: {retry_error}"
                                            ),
                                            status,
                                            network_state,
                                            last_error,
                                            sync_bootstrap_complete,
                                            bootstrap_pending,
                                        );
                                        return;
                                    }
                                    Err(retry_error) => {
                                        tracing::warn!(
                                            ?retry_error,
                                            "device authorization check failed after refresh"
                                        );
                                        needs_device_authorization.set(true);
                                    }
                                }
                            }
                            crate::runtime::session::CurrentSessionRefresh::SignInRequired {
                                reason,
                            } => {
                                invalidate_bootstrap_session(
                                    &session,
                                    reason,
                                    session_boot_state,
                                    sync_bootstrap_complete,
                                );
                                return;
                            }
                            crate::runtime::session::CurrentSessionRefresh::LoginRequired {
                                ..
                            } => return,
                            crate::runtime::session::CurrentSessionRefresh::RetryLater {
                                reason,
                            } => {
                                defer_bootstrap_retry(
                                    session.clone(),
                                    format!(
                                        "device authorization rejected current session and refresh could not complete: {reason}"
                                    ),
                                    status,
                                    network_state,
                                    last_error,
                                    sync_bootstrap_complete,
                                    bootstrap_pending,
                                );
                                return;
                            }
                        }
                        device_authorization_check_complete.set(true);
                    }
                    Err(error) => {
                        tracing::warn!(?error, "device authorization check failed");
                        needs_device_authorization.set(true);
                        device_authorization_check_complete.set(true);
                    }
                }
                persist_config(
                    config_store,
                    accepted_account.server_url.to_string(),
                    Some(accepted_account.principal_id().clone()),
                    accepted_account.device_id.to_string(),
                    session_credential.clone(),
                );
                crypto_state.set("Session active".to_owned());

                // Session/service bootstrap does not enumerate account Realms.
                // The single account engine durably installs each summary page
                // and demanded Realm detail as soon as its frame arrives.
                sync_bootstrap_complete.set(true);
                tracing::debug!(target: "session_boot", "connect: post-sync, awaiting events_describe");
                let Some(events_describe_result) = session_scoped_bootstrap_request(
                    "events describe",
                    &session,
                    bootstrap_session_generation,
                    client_core_events_describe(&authed, state_store),
                )
                .await
                else {
                    return;
                };
                let events_result = match events_describe_result {
                    Ok(events) => {
                        tracing::debug!(target: "session_boot", "connect: events_describe returned Ok");
                        Ok(events)
                    }
                    Err(error) if is_auth_expired_error(&error) => {
                        match bootstrap_session_refresh(&session).await {
                            crate::runtime::session::CurrentSessionRefresh::Credential(
                                refreshed,
                            ) => {
                                session_credential = refreshed;
                                let Ok(rebound) =
                                    current_authed_api(&base, &session_credential, state_store)
                                else {
                                    defer_bootstrap_retry(
                                        session.clone(),
                                        "refreshed session transport is not initialized yet"
                                            .to_owned(),
                                        status,
                                        network_state,
                                        last_error,
                                        sync_bootstrap_complete,
                                        bootstrap_pending,
                                    );
                                    return;
                                };
                                authed = rebound;
                                let Some(events_retry_result) = session_scoped_bootstrap_request(
                                    "events describe retry",
                                    &session,
                                    bootstrap_session_generation,
                                    client_core_events_describe(&authed, state_store),
                                )
                                .await
                                else {
                                    return;
                                };
                                events_retry_result
                            }
                            crate::runtime::session::CurrentSessionRefresh::SignInRequired {
                                reason,
                            } => {
                                invalidate_bootstrap_session(
                                    &session,
                                    format!(
                                        "session refresh cannot continue locally: {reason}; events_describe: {error}"
                                    ),
                                    session_boot_state,
                                    sync_bootstrap_complete,
                                );
                                return;
                            }
                            crate::runtime::session::CurrentSessionRefresh::LoginRequired {
                                ..
                            } => return,
                            crate::runtime::session::CurrentSessionRefresh::RetryLater {
                                reason,
                            } => {
                                defer_bootstrap_retry(
                                    session.clone(),
                                    format!(
                                        "events_describe rejected current session and refresh could not complete: {reason}; events_describe: {error}"
                                    ),
                                    status,
                                    network_state,
                                    last_error,
                                    sync_bootstrap_complete,
                                    bootstrap_pending,
                                );
                                return;
                            }
                        }
                    }
                    Err(error) => Err(error),
                };
                match events_result {
                    Ok(_events) => {}
                    Err(error) if is_terminal_session_grant_error(&error) => {
                        tracing::warn!(target: "session_boot", ?error, "connect: events_describe returned terminal session-grant error; invalidating current session");
                        invalidate_bootstrap_session(
                            &session,
                            "session grant is no longer active",
                            session_boot_state,
                            sync_bootstrap_complete,
                        );
                        return;
                    }
                    Err(error) if is_auth_expired_error(&error) => {
                        defer_bootstrap_retry(
                            session.clone(),
                            format!(
                                "events_describe temporarily rejected refreshed session: {error}"
                            ),
                            status,
                            network_state,
                            last_error,
                            sync_bootstrap_complete,
                            bootstrap_pending,
                        );
                        return;
                    }
                    Err(error) => {
                        last_error.set(Some(format!("events_describe: {error}")));
                    }
                }
            }
            Err(error) => {
                status.set(format!(
                    "{}: invalid URL: {error}",
                    ConnectionState::Error.label()
                ));
                network_state.set("offline".to_owned());
                last_error.set(Some(format!("invalid URL: {error}")));
                server_probe_status.set(format!("server describe skipped: invalid URL: {error}"));
                crate::operation::set_authoring_station_id(None);
                server_description.set(None);
                did_resolution_health
                    .set(crate::components::DidResolutionHealth::unsupported_station());
            }
        }
        if session.generation() != bootstrap_session_generation {
            return;
        }
        tracing::debug!(target: "session_boot", token_empty = token().trim().is_empty(), "connect: reached END of bootstrap — setting boot_state = Authenticated (token present) / Unauthenticated (empty)");
        transition_session_boot_state(
            session_boot_state,
            if token().trim().is_empty() {
                SessionBootState::Unauthenticated
            } else {
                SessionBootState::Authenticated
            },
            "bootstrap connect completed",
        );
        sync_bootstrap_complete.set(true);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_bootstrap_lease_cannot_invalidate_replacement_session() {
        let coordinator = crate::runtime::session::SessionCoordinator::new(|| {
            Box::pin(async {
                crate::runtime::session::CurrentSessionRefresh::retry_later("unused")
            })
        });
        let invalidated = std::rc::Rc::new(std::cell::RefCell::new(false));
        coordinator.set_invalidator({
            let invalidated = invalidated.clone();
            move |_| *invalidated.borrow_mut() = true
        });
        let lease = BootstrapSessionLease::new(coordinator.clone(), coordinator.generation());

        coordinator.replace("new-login-credential");

        assert!(!lease.invalidate("late connect failure"));
        assert!(!*invalidated.borrow());
        assert_eq!(
            coordinator.credential().as_deref(),
            Some("new-login-credential")
        );
    }

    #[test]
    fn authorized_device_requires_exact_directory_signer_match() {
        let viewer = serde_json::json!({
            "devices": [{
                "device_id": "ak:device:current",
                "status": "active",
                "verification_state": "verified"
            }]
        });

        assert_eq!(
            device_authorization_probe_from_account_viewer(&viewer, "ak:device:current", true),
            (false, false)
        );
        assert_eq!(
            device_authorization_probe_from_account_viewer(&viewer, "ak:device:current", false),
            (true, false)
        );
    }

    #[test]
    fn unauthorized_current_device_detects_existing_pairing_provider() {
        let viewer = serde_json::json!({
            "devices": [
                {
                    "device_id": "ak:device:new",
                    "status": "active",
                    "verification_state": "unresolved"
                },
                {
                    "device_id": "ak:device:existing",
                    "status": "active",
                    "verification_state": "verified"
                }
            ]
        });

        assert_eq!(
            device_authorization_probe_from_account_viewer(&viewer, "ak:device:new", false),
            (true, true)
        );
    }
}
