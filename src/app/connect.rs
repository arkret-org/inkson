use std::future::Future;

use super::*;
use crate::api_error::{is_auth_expired_error, is_terminal_session_grant_error};

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
        config: current_config != desired_config,
    }
}

async fn client_core_events_describe(
    authed: &crate::transport::TransportClient,
    _state_store: SyncSignal<LocalStateStore>,
) -> anyhow::Result<arkret_sdk::ServiceDescribe> {
    let http = authed.sdk_http_client()?;
    http.events_describe().await.map_err(Into::into)
}

async fn client_core_account_subscribe_snapshot(
    authed: &crate::transport::TransportClient,
) -> anyhow::Result<crate::models::AccountSyncStep> {
    let http = authed.sdk_http_client()?;
    crate::client_core::account_subscribe_snapshot(&http, None).await
}

/// The single source of truth for restoring or rotating the current session credential.
///
/// Registered once at the app root through `RuntimeServices`. Reads the live
/// base/actor/device from their signals (so it always targets the active
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
    account_did: Signal<String>,
    device_id: Signal<String>,
    mut state_store: SyncSignal<LocalStateStore>,
    mut token: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    session_generation: Signal<u64>,
) -> crate::runtime::session::CurrentSessionRefresh {
    let base = base_url();
    let actor = account_did();
    let device = device_id();
    let generation = session_generation();

    #[cfg(target_arch = "wasm32")]
    if let Err(error) = crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson").await
    {
        return crate::runtime::session::CurrentSessionRefresh::RetryLater {
            reason: format!("secure key store is not ready for session refresh: {error}"),
        };
    }

    // Provider restore owns expiry policy, durable rotation, and client rebuild.
    let restored = crate::identity::session_refresh::provide_authenticated_session(&base).await;
    if !same_server_url(&base, &base_url()) || session_generation() != generation {
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
            let desired_config = ClientConfig::from_fields(
                base.clone(),
                actor.clone(),
                device.clone(),
                session_credential.clone(),
            );
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
                    base.clone(),
                    actor.clone(),
                    device.clone(),
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
    session: &crate::runtime::session::SessionCoordinator,
    reason: impl Into<String>,
    mut session_boot_state: Signal<SessionBootState>,
    mut sync_bootstrap_complete: Signal<bool>,
) {
    session.invalidate(reason);
    session_boot_state.set(SessionBootState::Unauthenticated);
    sync_bootstrap_complete.set(true);
}

#[derive(Clone)]
pub(super) struct ConnectContext {
    pub(super) session: crate::runtime::session::SessionCoordinator,
    /// Connection-lifecycle label (offline / loading / online / error).
    pub(super) connection_status: Signal<String>,
    pub(super) sync_cursor: Signal<String>,
    pub(super) token: Signal<String>,
    pub(super) account_did: Signal<String>,
    pub(super) device_id: Signal<String>,
    pub(super) selected_realm_id: Signal<String>,
    pub(super) realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    pub(super) projection_events: Signal<Vec<ProjectionEvent>>,
    pub(super) device_queue: Signal<usize>,
    pub(super) frontier_state: Signal<String>,
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
    /// A4a: shared UI theme signal so `/sync` can hydrate the theme
    /// from the remote `ak.client.ui_state` account-data payload right after
    /// session bootstrap. Stub field — wire-up is tracked under A4a.
    pub(super) theme: Signal<String>,
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
    /// Session DID-resolution cache handle. The boot sync's Tier-2 device-key
    /// chain verification (`device-lifecycle.md` §8.3) anchors the published
    /// PSK against the actor's DID document through a resolver backed by a
    /// snapshot of this cache; back-fills are written back. Shared with the
    /// SyncEngine's `did_cache` so both receive paths reuse resolved documents.
    pub(super) did_cache: Signal<arkret_sdk::identity::DidResolutionCache>,
    /// App-shell DID resolution health banner state. The root identity
    /// describe probe updates this on every connect/manual refresh; authority
    /// resolution remains fail-closed in `did_resolver`.
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
    actor: &str,
    device: &str,
    principal_api: &TransportClient,
) -> anyhow::Result<(bool, bool)> {
    // The account-viewer helpers read `devices[]` leniently via `Value`
    // accessors; serialize the typed `AccountView` back to its wire JSON.
    let viewer = serde_json::to_value(
        &crate::transport::keys::list_devices(&principal_api.sdk_http_client()?).await?,
    )?;
    let signer_matches_directory =
        current_event_signer_matches_directory(principal_api, actor, device).await?;
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
    actor: &str,
    device: &str,
) -> anyhow::Result<bool> {
    let signer = match crate::event_signer::active_signer() {
        Some(signer) => signer,
        None => crate::event_signer::bootstrap_default_signer("inkson")
            .map_err(|error| anyhow::anyhow!("bootstrap device signer: {error}"))?,
    };
    let signer = crate::event_signer::bind_active_signer_device_id(device)
        .map_err(|error| anyhow::anyhow!("bind event signer to device: {error}"))?
        .unwrap_or(signer);
    let Some(public_key) = signer.public_key_multibase() else {
        return Ok(false);
    };
    let outcome =
        crate::transport::keys::query_keys(&principal_api.sdk_http_client()?, actor, device)
            .await?;
    let actor_id = arkret_sdk::Did::new(actor.to_owned())?;
    let device_id = arkret_sdk::DeviceId::new(device.to_owned())?;
    let expected_key = format!("did:key:{public_key}");
    let signer_matches = outcome
        .device_keys
        .get(&actor_id)
        .and_then(|devices| devices.get(&device_id))
        .and_then(|record| record.device_signing_key.as_deref())
        == Some(expected_key.as_str());
    if !signer_matches {
        return Ok(false);
    }
    crate::identity::authoring_generation::cache_principal_authoring_generation_from_keys(
        &outcome, actor, device,
    )
}

pub(super) fn connect(base: String, actor: String, device: String, ctx: ConnectContext) {
    let mut device = normalize_device_id(&device);
    spawn(async move {
        let session = ctx.session.clone();
        let mut sync_bootstrap_complete = ctx.sync_bootstrap_complete;
        // Connection-lifecycle status only; operation feedback goes through
        // `crate::components::feedback` toasts.
        let mut status = ctx.connection_status;
        let mut sync_cursor = ctx.sync_cursor;
        let token = ctx.token;
        let mut account_did = ctx.account_did;
        let mut device_id_signal = ctx.device_id;
        let mut selected_realm_id = ctx.selected_realm_id;
        let mut realm_tree_nodes = ctx.realm_tree_nodes;
        let mut projection_events = ctx.projection_events;
        let mut device_queue = ctx.device_queue;
        let mut frontier_state = ctx.frontier_state;
        let mut crypto_state = ctx.crypto_state;
        let config_store = ctx.config_store;
        let mut state_store = ctx.state_store;
        let mut network_state = ctx.network_state;
        let mut last_error = ctx.last_error;
        let mut server_description = ctx.server_description;
        let mut server_probe_status = ctx.server_probe_status;
        let mut account_primary_handle = ctx.account_primary_handle;
        let mut personal_handles = ctx.personal_handles;
        let mut personal_handles_status = ctx.personal_handles_status;
        let mut theme = ctx.theme;
        let mut session_boot_state = ctx.session_boot_state;
        let mut needs_device_authorization = ctx.needs_device_authorization;
        let mut device_authorization_check_complete = ctx.device_authorization_check_complete;
        let mut account_has_other_devices = ctx.account_has_other_devices;
        let mut did_resolution_health = ctx.did_resolution_health;

        // A (re)connect may point at a different / re-provisioned Account
        // Authority, so drop the cached authority resolution and let the first
        // describe below repopulate it. Steady-state session refreshes then
        // reuse that cache instead of re-probing `/_arkret/describe`.
        crate::identity::account_auth::clear_authority_resolver_cache();
        did_resolution_health.set(crate::components::DidResolutionHealth::healthy());
        needs_device_authorization.set(false);
        device_authorization_check_complete.set(false);
        account_has_other_devices.set(false);
        tracing::debug!(target: "session_boot", token_empty = token().trim().is_empty(), "connect: starting bootstrap connect (sets Checking/Restoring; only reaches Authenticated at end)");
        session_boot_state.set(if token().trim().is_empty() {
            SessionBootState::Restoring
        } else {
            SessionBootState::Checking
        });
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
                        let missing = missing_v1_principal_server_requirements(&description);
                        if !missing.is_empty() {
                            let message =
                                format!("server describe rejected: missing {}", missing.join(", "));
                            status.set(format!("{}: {message}", ConnectionState::Error.label()));
                            network_state.set("offline".to_owned());
                            last_error.set(Some(message.clone()));
                            server_probe_status.set(message);
                            server_description.set(None);
                            did_resolution_health.set(
                                crate::components::DidResolutionHealth::unsupported_principal_server(),
                            );
                            session_boot_state.set(if token().trim().is_empty() {
                                SessionBootState::Unauthenticated
                            } else {
                                SessionBootState::Authenticated
                            });
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
                        // Round 4 — cache the advertised trust_domain so
                        // downstream signing strands (cross_signing.publish,
                        // S2S transcripts) can pull a canonical
                        // value off local state without an extra round
                        // trip. Cleared when describe fails so a stale
                        // domain can't leak into the next strand.
                        {
                            let mut store = state_store.write();
                            let mut snapshot = store.load();
                            // `TypedTrustDomainId` enforces a non-empty
                            // `ak:trust_domain:<scope>` shape at deserialize
                            // time, so the previous "is_empty" guard is
                            // structurally impossible. Always cache.
                            snapshot.server_trust_domain =
                                Some(description.trust_domain.as_str().to_owned());
                            store.save(snapshot);
                        }
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
                        let cache = ctx.did_cache.read();
                        crate::components::DidResolutionHealth::from_identity_probe_failure(
                            &cache,
                            chrono::Utc::now(),
                        )
                    }
                };
                did_resolution_health.set(identity_health);

                let mut session_credential;
                match bootstrap_session_refresh(&session).await {
                    crate::runtime::session::CurrentSessionRefresh::Credential(refreshed) => {
                        session_credential = refreshed;
                        session_boot_state.set(SessionBootState::Checking);
                    }
                    crate::runtime::session::CurrentSessionRefresh::SignInRequired { reason }
                    | crate::runtime::session::CurrentSessionRefresh::LoginRequired { reason } => {
                        let probe_label = description
                            .as_ref()
                            .map(|d| format!("{} / {}", d.service_kind, d.protocol_version))
                            .unwrap_or_else(|| "server probe unavailable".to_owned());
                        status.set(format!("Refreshed: {probe_label}; sign-in required"));
                        network_state.set("online".to_owned());
                        crypto_state.set("No authenticated session".to_owned());
                        last_error.set(Some(reason));
                        needs_device_authorization.set(false);
                        device_authorization_check_complete.set(true);
                        session_boot_state.set(SessionBootState::Unauthenticated);
                        sync_bootstrap_complete.set(true);
                        return;
                    }
                    crate::runtime::session::CurrentSessionRefresh::RetryLater { reason } => {
                        status.set("Session could not be restored; sign in again".to_owned());
                        network_state.set("reconnecting".to_owned());
                        last_error
                            .set(Some(format!("session credential restore failed: {reason}")));
                        session_boot_state.set(SessionBootState::Unauthenticated);
                        sync_bootstrap_complete.set(true);
                        return;
                    }
                }
                let bootstrap_session_generation = session.generation();

                let Ok(mut authed) = current_authed_api(&base, &session_credential, state_store)
                else {
                    invalidate_bootstrap_session(
                        &session,
                        "authenticated session provider did not yield a client",
                        session_boot_state,
                        sync_bootstrap_complete,
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
                // Resolve the canonical actor DID from the account viewer. Three
                // outcomes:
                //   1. Ok with non-empty DID -> use it as canonical_actor.
                //   2. Err that looks like auth expiry -> try the shared session refresh path. If
                //      the refreshed credential is still rejected, clear the stale session instead
                //      of booting the shell with a bearer token the server will never accept.
                //   3. Anything else (Ok with empty DID, transient 5xx, parse error, network
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
                let canonical_actor = match account_viewer_result {
                    Ok(account) if !account.did.trim().is_empty() => {
                        account_personal_handle =
                            personal_handle_from_account_handle(&account.handle);
                        account.did
                    }
                    Ok(_) => {
                        last_error.set(Some(
                            "account_me: server returned empty actor DID; reusing local actor"
                                .to_owned(),
                        ));
                        actor.clone()
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
                                    invalidate_bootstrap_session(
                                        &session,
                                        "refreshed session provider did not yield a client",
                                        session_boot_state,
                                        sync_bootstrap_complete,
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
                                    Ok(account) if !account.did.trim().is_empty() => {
                                        account_personal_handle =
                                            personal_handle_from_account_handle(&account.handle);
                                        account.did
                                    }
                                    Ok(_) => {
                                        last_error.set(Some(
                                            "account_me: refreshed session returned empty actor DID; reusing local actor"
                                                .to_owned(),
                                        ));
                                        actor.clone()
                                    }
                                    Err(retry_error) if !is_auth_expired_error(&retry_error) => {
                                        last_error.set(Some(format!("account_me: {retry_error}")));
                                        actor.clone()
                                    }
                                    Err(retry_error) if is_auth_expired_error(&retry_error) => {
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
                                    Err(retry_error) => {
                                        last_error.set(Some(format!("account_me: {retry_error}")));
                                        actor.clone()
                                    }
                                }
                            }
                            crate::runtime::session::CurrentSessionRefresh::SignInRequired {
                                reason,
                            }
                            | crate::runtime::session::CurrentSessionRefresh::LoginRequired {
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
                            crate::runtime::session::CurrentSessionRefresh::RetryLater {
                                reason,
                            } => {
                                invalidate_bootstrap_session(
                                    &session,
                                    format!(
                                        "account_me rejected current session and refresh could not complete: {reason}; account_me: {error}"
                                    ),
                                    session_boot_state,
                                    sync_bootstrap_complete,
                                );
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        last_error.set(Some(format!("account_me: {error}")));
                        actor.clone()
                    }
                };
                if canonical_actor != actor {
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
                    if !actor.trim().is_empty() {
                        let mut store = state_store.write();
                        store.switch_active_account(&canonical_actor);
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
                        // DID-P2-B step 5: the persisted accepted bindings are
                        // scoped structurally (they live in the incoming
                        // account's own entry, which `switch_active_account`
                        // just loaded), but the *in-memory* session cache is
                        // not — it is one signal shared by whoever is signed
                        // in. Clearing it here is what stops the previous
                        // principal's resolved documents from being reused for
                        // the new one.
                        let mut session_did_cache = ctx.did_cache;
                        session_did_cache.write().clear();
                    } else {
                        // No previous identity to displace — just record
                        // who the scope now belongs to (don't wipe: a
                        // just-established grant could be dropped).
                        state_store.write().switch_active_account(&canonical_actor);
                    }
                    account_did.set(canonical_actor.clone());
                } else {
                    // Actor unchanged — record the scope owner so a later
                    // login for a different identity is recognised and the
                    // stale scope is reset.
                    state_store.write().switch_active_account(&canonical_actor);
                }
                // DID-P2-B step 5, trust-domain half: an account entry can be
                // re-pointed at a different Principal Server. A binding accepted
                // against the previous deployment must not authorize anything
                // under the new one, so anything outside the *current* trust
                // domain is dropped now rather than left to expire. Same-domain
                // reconnects are a no-op (nothing to remove ⇒ no flush).
                {
                    // Only the trust-domain half is needed here, and it is
                    // infallible: a resolver-policy digest failure must not be
                    // able to skip this cross-deployment cleanup.
                    let trust_domain =
                        crate::identity::did_binding::DidBindingScope::trust_domain_for(&base);
                    let dropped = state_store
                        .write()
                        .clear_accepted_did_bindings_outside_trust_domain(&trust_domain);
                    if dropped > 0 {
                        tracing::info!(
                            dropped,
                            trust_domain = %trust_domain,
                            "dropped accepted DID bindings from a previous trust domain"
                        );
                        let mut session_did_cache = ctx.did_cache;
                        session_did_cache.write().clear();
                    }
                }
                if let Some(personal_handle) = account_personal_handle {
                    account_primary_handle.set(personal_handle.clone());
                    let handles = merge_personal_handles(&personal_handles(), [personal_handle]);
                    personal_handles_status.set(personal_handles_status_for(&handles));
                    personal_handles.set(handles);
                } else if personal_handles().is_empty() {
                    personal_handles_status.set("Not published".to_owned());
                }
                let grant_device = {
                    let store = state_store.read();
                    store
                        .session_grant()
                        .filter(|grant| {
                            grant.principal_id.trim() == canonical_actor.trim()
                                && crate::identity::session_refresh::grant_matches_principal_server(
                                    grant, &base,
                                )
                                && crate::config::is_valid_device_id(&grant.device_id)
                        })
                        .map(|grant| grant.device_id)
                };
                if let Some(grant_device) = grant_device
                    && grant_device != device
                {
                    tracing::warn!(
                        target: "session_boot",
                        stale = %device,
                        grant_device = %grant_device,
                        "connect: replacing boot device_id with session-grant device_id"
                    );
                    device = grant_device.clone();
                    device_id_signal.set(grant_device);
                }
                {
                    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                    crate::secure_key_store::set_active_device_seed_scope(Some(&canonical_actor));
                    if let Err(error) = crate::secure_key_store::store_device_id_scoped(
                        secure_store.as_ref(),
                        Some(&canonical_actor),
                        &device,
                    ) {
                        tracing::warn!(?error, "connect: persist canonical device_id failed");
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
                    probe_device_authorization(&canonical_actor, &device, &authed),
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
                                    invalidate_bootstrap_session(
                                        &session,
                                        "refreshed session provider did not yield a client",
                                        session_boot_state,
                                        sync_bootstrap_complete,
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
                                            &canonical_actor,
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
                                    Err(retry_error) if is_auth_expired_error(&retry_error) => {
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
                            }
                            | crate::runtime::session::CurrentSessionRefresh::LoginRequired {
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
                            crate::runtime::session::CurrentSessionRefresh::RetryLater {
                                reason,
                            } => {
                                invalidate_bootstrap_session(
                                    &session,
                                    format!(
                                        "device authorization rejected current session and refresh could not complete: {reason}"
                                    ),
                                    session_boot_state,
                                    sync_bootstrap_complete,
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
                    base.clone(),
                    canonical_actor.clone(),
                    device.clone(),
                    session_credential.clone(),
                );
                crypto_state.set("Session active".to_owned());

                // `connect()` always issues a full sync (`since=None`) —
                // it's invoked on app boot, the mobile Refresh button,
                // and server switches, all of which represent
                // "re-establish the world from scratch". The SyncEngine
                // (see crate::sync_engine) owns the long-poll loop that
                // threads the cursor for incremental deltas.
                adopt_live_token_for_api(
                    &base,
                    state_store,
                    token,
                    &mut session_credential,
                    &mut authed,
                );
                let Some(account_subscribe_result) = session_scoped_bootstrap_request(
                    "account subscribe bootstrap",
                    &session,
                    bootstrap_session_generation,
                    client_core_account_subscribe_snapshot(&authed),
                )
                .await
                else {
                    return;
                };
                let sync_result = match account_subscribe_result {
                    Ok(sync) => Ok(sync),
                    Err(error) if is_auth_expired_error(&error) => {
                        match bootstrap_session_refresh(&session).await {
                            crate::runtime::session::CurrentSessionRefresh::Credential(
                                refreshed,
                            ) => {
                                session_credential = refreshed;
                                let Ok(rebound) =
                                    current_authed_api(&base, &session_credential, state_store)
                                else {
                                    invalidate_bootstrap_session(
                                        &session,
                                        "refreshed session provider did not yield a client",
                                        session_boot_state,
                                        sync_bootstrap_complete,
                                    );
                                    return;
                                };
                                authed = rebound;
                                let Some(account_subscribe_retry_result) =
                                    session_scoped_bootstrap_request(
                                        "account subscribe bootstrap retry",
                                        &session,
                                        bootstrap_session_generation,
                                        client_core_account_subscribe_snapshot(&authed),
                                    )
                                    .await
                                else {
                                    return;
                                };
                                account_subscribe_retry_result
                            }
                            crate::runtime::session::CurrentSessionRefresh::SignInRequired {
                                reason,
                            } => {
                                invalidate_bootstrap_session(
                                    &session,
                                    format!(
                                        "session refresh cannot continue locally: {reason}; sync: {error}"
                                    ),
                                    session_boot_state,
                                    sync_bootstrap_complete,
                                );
                                return;
                            }
                            crate::runtime::session::CurrentSessionRefresh::LoginRequired {
                                reason,
                            } => {
                                invalidate_bootstrap_session(
                                    &session,
                                    format!(
                                        "session refresh requires login: {reason}; sync: {error}"
                                    ),
                                    session_boot_state,
                                    sync_bootstrap_complete,
                                );
                                return;
                            }
                            crate::runtime::session::CurrentSessionRefresh::RetryLater {
                                reason,
                            } => {
                                invalidate_bootstrap_session(
                                    &session,
                                    format!(
                                        "sync rejected current session and refresh could not complete: {reason}; sync: {error}"
                                    ),
                                    session_boot_state,
                                    sync_bootstrap_complete,
                                );
                                return;
                            }
                        }
                    }
                    Err(error) => Err(error),
                };
                match sync_result {
                    Ok(sync) => {
                        adopt_live_token_for_api(
                            &base,
                            state_store,
                            token,
                            &mut session_credential,
                            &mut authed,
                        );
                        let Some(invite_notifications_result) = session_scoped_bootstrap_request(
                            "invite notifications",
                            &session,
                            bootstrap_session_generation,
                            async {
                                crate::transport::account::invites(&authed.sdk_http_client()?).await
                            },
                        )
                        .await
                        else {
                            return;
                        };
                        let invite_notifications = match invite_notifications_result {
                                Ok(response) => Some(response.invites),
                                Err(error) if is_auth_expired_error(&error) => {
                                    match bootstrap_session_refresh(&session).await {
                                        crate::runtime::session::CurrentSessionRefresh::Credential(
                                            refreshed,
                                        ) => {
                                            session_credential = refreshed;
                                            let Ok(rebound) = current_authed_api(
                                                &base,
                                                &session_credential,
                                                state_store,
                                            ) else {
                                                invalidate_bootstrap_session(
                                                    &session,
                                                    "refreshed session provider did not yield a client",
                                                    session_boot_state,
                                                    sync_bootstrap_complete,
                                                );
                                                return;
                                            };
                                            authed = rebound;
                                            let Some(invite_retry_result) =
                                                session_scoped_bootstrap_request(
                                                    "invite notifications retry",
                                                    &session,
                                                    bootstrap_session_generation,
                                                    async {
                                                        crate::transport::account::invites(
                                                            &authed.sdk_http_client()?,
                                                        )
                                                        .await
                                                    },
                                                )
                                                .await
                                            else {
                                                return;
                                            };
                                            invite_retry_result.ok().map(|response| response.invites)
                                        }
                                        crate::runtime::session::CurrentSessionRefresh::SignInRequired {
                                            ..
                                        }
                                        | crate::runtime::session::CurrentSessionRefresh::LoginRequired {
                                            ..
                                        }
                                        | crate::runtime::session::CurrentSessionRefresh::RetryLater {
                                            ..
                                        } => None,
                                    }
                                }
                                Err(error) => {
                                    tracing::debug!(
                                        ?error,
                                        "background sync could not refresh invite notifications"
                                    );
                                    None
                                }
                            };
                        {
                            let mut store = state_store.write();
                            store.save_sync_cursor(sync.cursor.clone());
                            // Server-authoritative reconcile for top-level
                            // Realm membership. Keep acknowledged optimistic
                            // Realms until their first account projection and
                            // nested Space containers while their home Realm
                            // is still present.
                            let server_set: BTreeSet<String> =
                                sync.realm_projections.keys().cloned().collect();
                            let keep_set = full_sync_projection_keep_set(
                                &server_set,
                                &store.load().realm_tree_projections,
                            );
                            let pruned =
                                store.retain_realm_tree_projections(|id| keep_set.contains(id));
                            if !pruned.is_empty() {
                                tracing::info!(
                                    pruned_count = pruned.len(),
                                    "full sync pruned stale realm-tree projections",
                                );
                            }
                            // Explicit `left_realms` deltas — soland emits
                            // these on incremental syncs too; for full sync
                            // they're redundant with `retain_realm_tree_projections`
                            // above but cheap to apply when soland evolves
                            // to send them on full sync.
                            let realm_title_hints = invite_notifications
                                .as_deref()
                                .map(
                                    crate::state::projection::notifications::realm_title_hints_from_invites,
                                )
                                .unwrap_or_default();
                            for (id, body) in &sync.realm_projections {
                                let projection = crate::realm_tree::projection_with_title_hint(
                                    id,
                                    body,
                                    realm_title_hints.get(id).map(String::as_str),
                                );
                                store.save_realm_tree_projection(id.clone(), projection);
                                store.save_realm_collaboration_role(
                                    id.clone(),
                                    sync.collaboration_role(id),
                                );
                                // Thread the per-Realm Seal view (frontier /
                                // leaves / state_root / bottom cells) into the
                                // local store so Move builders + UI can read
                                // it. Bodies WITHOUT a `seal_view` field carry
                                // no statement about the frontier at all, so
                                // they may only refresh the projection-only
                                // bottom cells — see
                                // `LocalSealView::merged_from_sync_body`.
                                store.merge_realm_seal_view_from_sync_body(id, body);
                                store.ingest_move_event_states(id, body);
                            }
                            crate::disappearing::shred_expired_message_plaintext_from_sync_realms(
                                &mut store,
                                &sync.realm_projections,
                            );
                            // Keep notification projection current even when
                            // invites live on `authz/invites` rather than the
                            // normal account subscribe notification stream.
                            let mut notification_projection = store.notification_projection();
                            // `server_set` is every Realm the server projected,
                            // which includes discoverable previews and Realms
                            // this actor was only invited or knocked into.
                            // Hiding an invite is a membership question, so it
                            // is answered by the typed roster and nothing else.
                            let joined_realms =
                                crate::state::projection::notifications::JoinedRealmIds::from_realm_entries(
                                    &sync.realm_entries,
                                    &canonical_actor,
                                );
                            crate::state::projection::notifications::apply_notification_projection(
                                &mut notification_projection,
                                &sync.updates.notifications,
                                &sync.updates.account_data,
                                true,
                                invite_notifications,
                                &joined_realms,
                            );
                            store.save_notification_projection(notification_projection);
                            store.ingest_to_device_messages(&sync.updates.to_device);
                            // `/account/subscribe` carries the actor's complete
                            // account_data projection on every successful frame.
                            // Track blocklist presence so a server-side tombstone
                            // (represented by absence from that full projection)
                            // clears the durable local cache as well.
                            let mut blocklist_snapshot_seen = false;
                            for event in &sync.updates.account_data {
                                let entry = &event.payload;
                                let Some(account_data_key) =
                                    entry.get("key").and_then(serde_json::Value::as_str)
                                else {
                                    continue;
                                };
                                match crate::sidecar::ingest_sidecar_view_state_account_data(
                                    &mut store,
                                    &account_did(),
                                    account_data_key,
                                    entry,
                                ) {
                                    Ok(true) => continue,
                                    Ok(false) => {}
                                    Err(error) => {
                                        tracing::warn!(
                                            %error,
                                            "ignoring malformed Sidecar view-state account_data"
                                        );
                                        continue;
                                    }
                                }
                                // A4a — hydrate `ak.client.ui_state` theme from
                                // the remote payload. Cross-device wins:
                                // when remote carries a valid theme that
                                // differs from the local cached value
                                // we update the UI Signal +
                                // LocalConfigStore synchronously.
                                if account_data_key == "ak.client.ui_state" {
                                    match crate::account_data::decrypt_account_data_entry(
                                        &account_did(),
                                        account_data_key,
                                        entry,
                                    ) {
                                        Ok(content) => {
                                            let local_theme = theme();
                                            if let Some(remote_theme) =
                                                crate::account_data::merge_client_ui_theme(
                                                    &local_theme,
                                                    &content,
                                                )
                                            {
                                                theme.set(remote_theme.clone());
                                                store.save_private_data(
                                                    &account_did(),
                                                    "theme",
                                                    remote_theme,
                                                );
                                            }
                                            if let Some(avatar_blob_ref) =
                                            crate::account_data::avatar_blob_ref_from_client_ui(
                                                &content,
                                            )
                                        {
                                            store.save_private_data(
                                                &account_did(),
                                                "avatar_blob_ref",
                                                avatar_blob_ref,
                                            );
                                        } else if crate::account_data::avatar_blob_ref_tombstoned_from_client_ui(&content) {
                                            store.save_private_data(
                                                &account_did(),
                                                "avatar_blob_ref",
                                                "",
                                            );
                                        }
                                        }
                                        Err(error) => tracing::warn!(
                                            "ignoring undecryptable ak.client.ui_state: {error}"
                                        ),
                                    }
                                    continue;
                                }
                                // `client.language` — the actor-private locale
                                // preference. Recording it as this device's
                                // cached choice is what makes the setting
                                // follow the user: the shell observes the
                                // same device preference, so the UI switches
                                // now, and the next cold boot (which runs
                                // before any session exists) starts in the
                                // right language instead of guessing from the
                                // platform.
                                if account_data_key == crate::account_data::CLIENT_LANGUAGE_WIRE_KEY
                                {
                                    match crate::account_data::decrypt_account_data_entry(
                                        &account_did(),
                                        account_data_key,
                                        entry,
                                    ) {
                                        Ok(content) => {
                                            let local = store
                                                .device_pref("locale")
                                                .as_deref()
                                                .and_then(crate::i18n::Locale::from_tag)
                                                .unwrap_or_default();
                                            if let Some(remote) =
                                                crate::account_data::merge_client_language(
                                                    local, &content,
                                                )
                                            {
                                                store.set_device_pref("locale", remote.code());
                                            }
                                        }
                                        Err(error) => tracing::warn!(
                                            "ignoring undecryptable client.language: {error}"
                                        ),
                                    }
                                    continue;
                                }
                                if account_data_key == "ak.presence.visibility" {
                                    let Some(visibility) =
                                        crate::account_data::decrypt_account_data_entry(
                                            &account_did(),
                                            account_data_key,
                                            entry,
                                        )
                                        .ok()
                                        .as_ref()
                                        .and_then(|content| content.get("presence_visibility"))
                                        .and_then(serde_json::Value::as_str)
                                        .and_then(crate::state::PresenceVisibility::try_from_wire)
                                    else {
                                        tracing::warn!(
                                            "ignoring malformed ak.presence.visibility account_data"
                                        );
                                        continue;
                                    };
                                    store.set_presence_visibility(visibility);
                                    continue;
                                }
                                // ak.presence.preference — manual presence
                                // preference (profiles-presence.md §3.6).
                                // Decrypt the standard holder-private envelope
                                // before applying it to local state.
                                if account_data_key == "ak.presence.preference" {
                                    match crate::account_data::decrypt_account_data_entry(
                                        &account_did(),
                                        account_data_key,
                                        entry,
                                    )
                                    .and_then(|content| {
                                        serde_json::from_value(content).map_err(Into::into)
                                    }) {
                                        Ok(preference) => store.set_presence_preference(preference),
                                        Err(error) => tracing::warn!(
                                            "ignoring undecryptable ak.presence.preference: {error}"
                                        ),
                                    }
                                    continue;
                                }
                                if account_data_key == "ak.dnd_schedule" {
                                    match crate::account_data::decrypt_account_data_entry(
                                        &account_did(),
                                        account_data_key,
                                        entry,
                                    ) {
                                        Ok(content) => store.set_notification_dnd_settings(
                                            crate::notification_rules::parse_dnd_settings(&content),
                                        ),
                                        Err(error) => tracing::warn!(
                                            "ignoring undecryptable ak.dnd_schedule: {error}"
                                        ),
                                    }
                                    continue;
                                }
                                if account_data_key == "ak.account.blocklist" {
                                    blocklist_snapshot_seen = true;
                                    match crate::account_data::decrypt_account_data_entry(
                                        &account_did(),
                                        account_data_key,
                                        entry,
                                    )
                                    .and_then(|content| {
                                        crate::account_data::blocklist_entries_from_account_data(
                                            &content,
                                            &account_did(),
                                            entry
                                                .get("revision")
                                                .and_then(serde_json::Value::as_u64)
                                                .ok_or_else(|| {
                                                    anyhow::anyhow!(
                                                        "ak.account.blocklist is missing revision"
                                                    )
                                                })?,
                                        )
                                        .map_err(anyhow::Error::msg)
                                    }) {
                                        Ok(entries) => {
                                            store.set_client_blocklist(entries);
                                        }
                                        Err(error) => {
                                            tracing::warn!(
                                                "ignoring malformed ak.account.blocklist account_data: {error}"
                                            );
                                        }
                                    }
                                    continue;
                                }
                                if crate::account_data::private_account_data_key_prefix(
                                    account_data_key,
                                ) == Some(arkret_sdk::AccountDataKey::SAVED_V1)
                                {
                                    if let Some(content) = entry
                                        .get("content")
                                        .or_else(|| entry.get("encrypted_payload"))
                                        .cloned()
                                    {
                                        store.stage_saved_account_data_entry(
                                            account_data_key,
                                            content,
                                        );
                                    }
                                    continue;
                                }
                                if let Some(actor_id) =
                                    crate::account_data::actor_id_from_contact_remark_key(
                                        account_data_key,
                                    )
                                {
                                    match crate::account_data::decrypt_account_data_entry(
                                        &account_did(),
                                        account_data_key,
                                        entry,
                                    )
                                    .and_then(|content| {
                                        serde_json::from_value(content).map_err(Into::into)
                                    }) {
                                        Ok(remark) => {
                                            store.set_contact_remark(actor_id.to_owned(), remark);
                                        }
                                        Err(error) => {
                                            tracing::warn!(
                                                "ignoring malformed Contact remark for {actor_id}: {error}"
                                            );
                                        }
                                    }
                                    continue;
                                }
                                let Some(realm_id) =
                                    crate::account_data::realm_id_from_realm_remark_key(
                                        account_data_key,
                                    )
                                else {
                                    continue;
                                };
                                match crate::account_data::decrypt_account_data_entry(
                                    &account_did(),
                                    account_data_key,
                                    entry,
                                )
                                .and_then(|content| {
                                    serde_json::from_value(content).map_err(Into::into)
                                }) {
                                    Ok(remark) => {
                                        store.set_realm_remark(realm_id.to_owned(), remark);
                                    }
                                    Err(error) => {
                                        tracing::warn!(
                                            "ignoring malformed Realm remark for {realm_id}: {error}"
                                        );
                                    }
                                }
                            }
                            if !blocklist_snapshot_seen {
                                store.set_client_blocklist(Vec::new());
                            }
                            // Force a synchronous flush so that if the user
                            // refreshes the tab immediately after a successful
                            // sync the next mount's `initial_state_store.load()`
                            // sees the new projections + cursor. Without this
                            // we rely on the per-call `flush()` inside each
                            // setter (which is best-effort on wasm) and on the
                            // WriteGuard's Drop, neither of which is guaranteed
                            // before the browser tears down the page.
                            if let Err(error) = store.flush() {
                                last_error.set(Some(format!("state_store flush failed: {error}")));
                            }
                            // YOU-02-002/003: surface a latched persistence
                            // failure from the fire-and-forget setters (quota
                            // exceeded, atomic write error, corrupt boot read)
                            // so the user learns their changes are not being
                            // saved instead of silently diverging from disk.
                            if let Some(message) = store.persist_error() {
                                last_error.set(Some(format!("local state not saved: {message}")));
                            }
                        }
                        // The receive side of `ak.call.signal` used to live here,
                        // reading each Realm body's `ephemeral.events[]`. v1
                        // deleted that bucket from Realm sync: a call signal is
                        // AEAD plaintext inside a `SignalEnvelope` delivered on
                        // the Signal rail, so nothing about it can be recovered
                        // from a sync body. Routing now belongs to the Signal
                        // subscribe path
                        // (`views::call_signals::route_decrypted_call_signals`),
                        // which this client cannot open until the SDK exposes the
                        // `ak.signal-v1` exporter derivation
                        // (`crate::signal::encrypt_signal_payload`). Leaving a
                        // no-op pass over sync bodies here would only look like
                        // the feature still worked.
                        crate::sync_engine::prefetch_persistent_event_sender_keys(
                            &authed,
                            &sync,
                            super::runtime_adapter::value_cell(ctx.did_cache),
                            state_store,
                            |realm_id| {
                                state_store
                                    .read()
                                    .realm_projection_is_minimal_metadata(realm_id)
                            },
                        )
                        .await;
                        let synced_projection_events = {
                            {
                                let mut store = state_store.write();
                                crate::disappearing::shred_expired_message_plaintext_from_sync_realms(
                                    &mut store,
                                    &sync.realm_projections,
                                );
                            }
                            // Merge encrypted bodies on read (author sidecar →
                            // remote decrypt-on-read). The `store` write guard
                            // above is out of scope here; take a fresh read
                            // guard scoped to this call.
                            let store_guard = state_store.read();
                            crate::state::projection::projection_events_from_sync_realms(
                                &sync.realm_projections,
                                Some(&store_guard),
                                Some((&canonical_actor, &device)),
                            )
                        };
                        // `realm_tree_nodes` is derived from `state_store.realm_tree_projections`
                        // by a use_effect in `RouterView` — we don't set it
                        // here. Read a reconciled snapshot for status text
                        // and selected_realm_id bookkeeping only.
                        let local_state = state_store.read().load();
                        let reconciled = realm_tree_nodes_from_sync_realms_with_roles(
                            &local_state.realm_tree_projections,
                            &local_state.realm_collaboration_roles,
                        );
                        if reconciled.is_empty() {
                            status.set(ConnectionState::Empty.label().to_owned());
                        } else {
                            status.set(format!(
                                "{}: synced {} space(s)",
                                ConnectionState::Online.label(),
                                reconciled.len()
                            ));
                        }
                        let first_realm = reconciled
                            .iter()
                            .find(|node| node.kind == RealmTreeNodeKind::Realm)
                            .map(|node| node.id.clone());
                        let current = selected_realm_id();
                        let trimmed = current.trim();
                        let needs_reset =
                            trimmed.is_empty() || !reconciled.iter().any(|s| s.id == trimmed);
                        if needs_reset {
                            selected_realm_id.set(first_realm.unwrap_or_default());
                        }
                        projection_events.set(synced_projection_events);
                        device_queue.set(state_store.read().load().to_device_inbox.len());
                        sync_cursor.set(sync.cursor);
                    }
                    Err(error) if is_terminal_session_grant_error(&error) => {
                        tracing::warn!(target: "session_boot", ?error, "connect: sync returned terminal session-grant error; invalidating current session");
                        session.invalidate("session grant is no longer active");
                        session_boot_state.set(SessionBootState::Unauthenticated);
                        sync_bootstrap_complete.set(true);
                        return;
                    }
                    Err(error) if is_auth_expired_error(&error) => {
                        invalidate_bootstrap_session(
                            &session,
                            format!("sync rejected refreshed session: {error}"),
                            session_boot_state,
                            sync_bootstrap_complete,
                        );
                        return;
                    }
                    Err(error) => {
                        tracing::warn!(
                            target: "session_boot",
                            ?error,
                            "connect: account subscribe bootstrap failed"
                        );
                        // Sync failed — the `realm_tree_nodes` Signal already
                        // reflects what's in the local store via the
                        // derive effect; just refresh status text and
                        // make sure selected_realm_id points at something
                        // still in scope.
                        let local_state = state_store.read().load();
                        let fallback = realm_tree_nodes_from_sync_realms_with_roles(
                            &local_state.realm_tree_projections,
                            &local_state.realm_collaboration_roles,
                        );
                        if fallback.is_empty() {
                            status.set(format!(
                                "{}: sync failed: {error}",
                                ConnectionState::Reconnecting.label()
                            ));
                        } else {
                            status.set(
                                "Refreshed: sync unavailable, showing cached/local Space list"
                                    .to_owned(),
                            );
                        }
                        let first_realm = fallback
                            .iter()
                            .find(|node| node.kind == RealmTreeNodeKind::Realm)
                            .map(|node| node.id.clone());
                        let current = selected_realm_id();
                        let trimmed = current.trim();
                        let needs_reset =
                            trimmed.is_empty() || !fallback.iter().any(|s| s.id == trimmed);
                        if needs_reset {
                            selected_realm_id.set(first_realm.unwrap_or_default());
                        }
                        last_error.set(Some(format!("sync: {error}")));
                    }
                }
                adopt_live_token_for_api(
                    &base,
                    state_store,
                    token,
                    &mut session_credential,
                    &mut authed,
                );
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
                                    invalidate_bootstrap_session(
                                        &session,
                                        "refreshed session provider did not yield a client",
                                        session_boot_state,
                                        sync_bootstrap_complete,
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
                                reason,
                            } => {
                                invalidate_bootstrap_session(
                                    &session,
                                    format!(
                                        "session refresh requires login: {reason}; events_describe: {error}"
                                    ),
                                    session_boot_state,
                                    sync_bootstrap_complete,
                                );
                                return;
                            }
                            crate::runtime::session::CurrentSessionRefresh::RetryLater {
                                reason,
                            } => {
                                invalidate_bootstrap_session(
                                    &session,
                                    format!(
                                        "events_describe rejected current session and refresh could not complete: {reason}; events_describe: {error}"
                                    ),
                                    session_boot_state,
                                    sync_bootstrap_complete,
                                );
                                return;
                            }
                        }
                    }
                    Err(error) => Err(error),
                };
                match events_result {
                    Ok(events) => {
                        // Spec `ServiceDescribe.frontier` is a typed
                        // EventId list; surface the first head.
                        if let Some(frontier) = events.frontier.first() {
                            frontier_state.set(frontier.to_string());
                        }
                    }
                    Err(error) if is_terminal_session_grant_error(&error) => {
                        tracing::warn!(target: "session_boot", ?error, "connect: events_describe returned terminal session-grant error; invalidating current session");
                        session.invalidate("session grant is no longer active");
                        session_boot_state.set(SessionBootState::Unauthenticated);
                        sync_bootstrap_complete.set(true);
                        return;
                    }
                    Err(error) if is_auth_expired_error(&error) => {
                        invalidate_bootstrap_session(
                            &session,
                            format!("events_describe rejected refreshed session: {error}"),
                            session_boot_state,
                            sync_bootstrap_complete,
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
                server_description.set(None);
                let cache = ctx.did_cache.read();
                did_resolution_health.set(
                    crate::components::DidResolutionHealth::from_identity_probe_failure(
                        &cache,
                        chrono::Utc::now(),
                    ),
                );
            }
        }
        tracing::debug!(target: "session_boot", token_empty = token().trim().is_empty(), "connect: reached END of bootstrap — setting boot_state = Authenticated (token present) / Unauthenticated (empty)");
        session_boot_state.set(if token().trim().is_empty() {
            SessionBootState::Unauthenticated
        } else {
            SessionBootState::Authenticated
        });
        sync_bootstrap_complete.set(true);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorized_device_requires_exact_directory_signer_match() {
        let viewer = serde_json::json!({
            "current_device_id": "ak:device:current",
            "devices": [{
                "device_id": "ak:device:current",
                "verification_state": "verified",
                "is_current_session_device": true
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
            "current_device_id": "ak:device:new",
            "devices": [
                {
                    "device_id": "ak:device:new",
                    "verification_state": "pending",
                    "is_current_session_device": true
                },
                {
                    "device_id": "ak:device:existing",
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
