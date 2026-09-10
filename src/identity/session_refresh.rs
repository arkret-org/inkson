//! Session keep-alive, driven by the persisted `ak.session.grant`.
//!
//! ②(A+②) model (api-conventions.md §3.3): there is **no** second client-visible
//! local session credential minted by soland. After login, the client
//! holds the `ak.session.grant` (issued by the Account Authority) plus the
//! grant-binding (DPoP) key whose thumbprint is the grant's `cnf.jkt`. The grant
//! itself is the live credential for `/_arkret/self/*`: every request presents
//! `Authorization: DPoP <grant>` + a matching per-request `DPoP` proof.
//!
//! The shared `SessionTransportProvider` owns durable restore, due and forced
//! refresh, single-flight coordination, persistence, and authenticated client
//! rebuild. Inkson supplies only its secure grant store, DPoP factory, and UI
//! result mapping.

#[cfg(target_arch = "wasm32")]
use std::rc::Rc;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use anyhow::Context as _;
use arkret_sdk::http_client::{Auth, ClientBuilder};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use garth::session::BoxSessionFuture;
use garth::{
    AuthenticatedTransportFactory, PutSecretOptions, SecretClass, SecretDurability, SecureKeyStore,
    SessionEngine, SessionGrantState, SessionGrantStore, SessionGrantTransport,
    SessionRefreshOptions, SessionTransportProvider, TransportProvider,
};
// The refresh decision layer (constants, `RefreshDecision`, the due/dead
// predicates) is garth's — inkson only maps its persisted grant into
// `garth::SessionGrantRefreshState` and supplies the wall clock. Semantics
// notes that used to live on a local copy: `NoGrant` must not clear a live
// credential; `GrantExpired` still attempts rotation so only the refresh
// endpoint's terminal error decides whether session material is cleared.
pub use garth::{POLL_INTERVAL_SECS, REFRESH_SKEW_SECS};
use url::Url;

use crate::config::normalize_server_url;
use crate::identity::account_auth::grant_dpop::DpopHandle;
use crate::state::{LocalStateStore, PersistedSessionGrant};

#[derive(Clone, Default)]
struct ReplaceableSessionTransport {
    client: Arc<Mutex<Option<arkret_sdk::http_client::Client>>>,
}

impl ReplaceableSessionTransport {
    fn replace(&self, client: arkret_sdk::http_client::Client) {
        *self.client.lock().unwrap_or_else(PoisonError::into_inner) = Some(client);
    }

    fn current(&self) -> garth::Result<arkret_sdk::http_client::Client> {
        self.client
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| garth::Error::Protocol("session transport is not configured".into()))
    }
}

impl SessionGrantTransport for ReplaceableSessionTransport {
    fn issue_session_grant<'a>(
        &'a self,
        request: arkret_sdk::SessionGrantRequestBody,
    ) -> BoxSessionFuture<'a, arkret_sdk::SessionGrantOutcome> {
        let client = self.current();
        Box::pin(async move {
            client?
                .auth_issue_session_grant(&request)
                .await
                .map_err(Into::into)
        })
    }

    fn refresh_session_grant<'a>(
        &'a self,
        request: arkret_sdk::SessionGrantRefreshRequestBody,
    ) -> BoxSessionFuture<'a, arkret_sdk::SessionGrantOutcome> {
        let client = self.current();
        Box::pin(async move {
            client?
                .auth_refresh_session_grant(&request)
                .await
                .map_err(Into::into)
        })
    }
}

#[derive(Clone)]
struct InksonAuthenticatedTransportFactory {
    principal_sdk_base_url: Url,
    account_sdk_base_url: Url,
    station_url: Url,
    device_handle: DpopHandle,
    refresh_transport: ReplaceableSessionTransport,
}

impl InksonAuthenticatedTransportFactory {
    fn build_principal_client(
        &self,
        state: &SessionGrantState,
    ) -> garth::Result<arkret_sdk::http_client::Client> {
        ClientBuilder::new(self.principal_sdk_base_url.clone())
            .allow_insecure_localhost()
            .auth(Auth::Dpop(
                self.device_handle
                    .sdk_dpop_auth_for_access_token(state.grant_jwt.clone()),
            ))
            .build()
            .map_err(Into::into)
    }

    fn build_account_client(
        &self,
        state: &SessionGrantState,
    ) -> garth::Result<arkret_sdk::http_client::Client> {
        ClientBuilder::new(self.account_sdk_base_url.clone())
            .allow_insecure_localhost()
            .auth(Auth::Dpop(
                self.device_handle
                    .sdk_dpop_auth_for_access_token(state.grant_jwt.clone()),
            ))
            .build()
            .map_err(Into::into)
    }

    fn persisted(&self, state: &SessionGrantState) -> anyhow::Result<PersistedSessionGrant> {
        persisted_session_grant_from_state(state, &self.station_url, &self.device_handle)
    }
}

impl AuthenticatedTransportFactory for InksonAuthenticatedTransportFactory {
    type Transport = arkret_sdk::http_client::Client;

    fn build(&self, state: &SessionGrantState) -> garth::Result<Self::Transport> {
        self.build_principal_client(state)
    }

    fn refresh_options(
        &self,
        state: &SessionGrantState,
        _fallback: &SessionRefreshOptions,
    ) -> garth::Result<SessionRefreshOptions> {
        self.refresh_transport
            .replace(self.build_account_client(state)?);
        let persisted = self
            .persisted(state)
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        let proof = mint_session_grant_refresh_proof(&persisted, self.device_handle.jkt())
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        let request = arkret_sdk::auth::session_grant::human_session_grant_refresh_request(
            persisted.grant_jwt.clone(),
            Some(state.audience_id.clone()),
            state
                .device_id
                .clone()
                .ok_or_else(|| garth::Error::Protocol("human refresh device is absent".into()))?,
            proof,
        )
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        Ok(SessionRefreshOptions {
            request: Some(request),
            expected_dpop_jkt: Some(self.device_handle.jkt().to_owned()),
        })
    }
}

#[derive(Clone)]
struct PersistedSessionGrantStore {
    secure_store: Arc<dyn SecureKeyStore + Send + Sync>,
    user_store: crate::secure_key_store::UserLocalStore,
    station_url: Url,
    device_handle: DpopHandle,
}

impl SessionGrantStore for PersistedSessionGrantStore {
    fn load(&self) -> garth::Result<Option<SessionGrantState>> {
        crate::state::load_session_grant_from_user_secure_store(
            &self.user_store,
            self.secure_store.as_ref(),
        )
        .map_err(|error| garth::Error::Protocol(error.to_string()))?
        .map(|grant| session_grant_state_from_persisted(&grant, &self.device_handle, Utc::now()))
        .transpose()
        .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    fn save<'a>(
        &'a self,
        state: &'a SessionGrantState,
    ) -> impl std::future::Future<Output = garth::Result<()>> + garth::MaybeSend + 'a {
        let encoded =
            persisted_session_grant_from_state(state, &self.station_url, &self.device_handle)
                .and_then(|grant| serde_json::to_vec(&grant).map_err(Into::into))
                .map_err(|error: anyhow::Error| garth::Error::Protocol(error.to_string()));
        async move {
            let encoded = encoded?;
            self.secure_store
                .put_secret(
                    &self
                        .user_store
                        .secret_key(LocalStateStore::SECURE_SESSION_GRANT_KEY),
                    &encoded,
                    PutSecretOptions {
                        durability: SecretDurability::DurableBeforeReturn,
                        class: SecretClass::SessionCredential,
                    },
                )
                .await
                .map_err(|error| garth::Error::Protocol(error.to_string()))
        }
    }

    fn clear(&self) -> garth::Result<()> {
        self.secure_store
            .delete_secret(
                &self
                    .user_store
                    .secret_key(LocalStateStore::SECURE_SESSION_GRANT_KEY),
            )
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }
}

type InksonSessionProvider = SessionTransportProvider<
    ReplaceableSessionTransport,
    InksonAuthenticatedTransportFactory,
    PersistedSessionGrantStore,
>;

#[derive(Clone)]
struct ActiveSessionProvider {
    server_key: String,
    device_id: String,
    provider: InksonSessionProvider,
}

#[derive(Default)]
struct SessionGrantRuntime {
    provider: Mutex<Option<ActiveSessionProvider>>,
}

impl SessionGrantRuntime {
    fn get(&self, server_key: &str, device_id: &str) -> Option<InksonSessionProvider> {
        self.provider
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|active| active.server_key == server_key && active.device_id == device_id)
            .map(|active| active.provider.clone())
    }

    fn replace(&self, server_key: String, device_id: String, provider: InksonSessionProvider) {
        *self.provider.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(ActiveSessionProvider {
                server_key,
                device_id,
                provider,
            });
    }

    fn get_for_server(&self, server_key: &str) -> Option<InksonSessionProvider> {
        self.provider
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|active| active.server_key == server_key)
            .map(|active| active.provider.clone())
    }

    fn reset(&self) {
        *self.provider.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

#[cfg(not(target_arch = "wasm32"))]
type SessionGrantRuntimeHandle = Arc<SessionGrantRuntime>;

#[cfg(target_arch = "wasm32")]
type SessionGrantRuntimeHandle = Rc<SessionGrantRuntime>;

#[cfg(not(target_arch = "wasm32"))]
static SESSION_GRANT_RUNTIME: OnceLock<SessionGrantRuntimeHandle> = OnceLock::new();

#[cfg(target_arch = "wasm32")]
thread_local! {
    static SESSION_GRANT_RUNTIME: SessionGrantRuntimeHandle =
        Rc::new(SessionGrantRuntime::default());
}

fn session_grant_runtime() -> SessionGrantRuntimeHandle {
    #[cfg(not(target_arch = "wasm32"))]
    {
        SESSION_GRANT_RUNTIME
            .get_or_init(|| Arc::new(SessionGrantRuntime::default()))
            .clone()
    }
    #[cfg(target_arch = "wasm32")]
    {
        SESSION_GRANT_RUNTIME.with(Clone::clone)
    }
}

pub fn reset_session_grant_runtime() {
    session_grant_runtime().reset();
    crate::authorization_lease::clear_leases();
    crate::event_submit::reset_verified_recovery_gates();
    crate::identity::authoring_generation::reset_verified_authoring_generations();
}

/// Outcome the refresh harness returns to the caller.
fn grant_refresh_state(grant: &PersistedSessionGrant) -> garth::SessionGrantRefreshState {
    garth::SessionGrantRefreshState {
        grant_expires_at: grant.grant_expires_at,
    }
}

/// True when the persisted grant is within `garth::GRANT_ROTATION_SKEW_SECS` of
/// its own expiry and should be rotated (grant-binding DPoP proof → fresh
/// grant). `None` grant expiry is "not due" — the 401 path handles
/// unknown-expiry grants, and we must not rotate blindly without a deadline.
/// True when the grant itself has gone past its `grant_expires_at`.
pub fn grant_is_dead(grant: &PersistedSessionGrant) -> bool {
    garth::grant_is_dead(&grant_refresh_state(grant), Utc::now())
}

/// Inspect the persisted grant and decide what the caller should do.
///
/// ②(A+②): "Due" means the grant itself is near its own expiry and should be
/// rotated (grant-binding DPoP proof → fresh grant). There is no separate
/// minted local session expiry to chase — the grant *is* the credential.
fn normalized_server_key(server_url: &Url) -> String {
    normalize_server_url(server_url.as_str())
        .trim()
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

/// True when a persisted grant is scoped to the active Station.
///
/// The client currently keeps one foreground server session. A grant minted
/// for another server must not be refreshed in the background or persisted as
/// the active server's credential.
pub fn grant_matches_station(grant: &PersistedSessionGrant, station_url: &str) -> bool {
    let grant_server = normalized_server_key(&grant.station_url);
    let Ok(active_server_url) = Url::parse(station_url) else {
        return false;
    };
    let active_server = normalized_server_key(&active_server_url);
    !grant_server.is_empty() && grant_server == active_server
}

/// Restore the shared provider from the durable grant and return its current
/// authenticated SDK client. Due refresh and transport rebuild happen inside
/// `SessionTransportProvider`; callers must not repeat expiry decisions.
pub async fn provide_authenticated_sdk_client(
    station_url: &str,
) -> anyhow::Result<arkret_sdk::http_client::Client> {
    Ok(provide_authenticated_session(station_url).await?.client)
}

pub(crate) struct AuthenticatedSession {
    pub client: arkret_sdk::http_client::Client,
    pub grant: PersistedSessionGrant,
}

fn load_active_session_grant(
    station_url: &str,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<PersistedSessionGrant> {
    let scope = crate::secure_key_store::active_device_seed_scope()
        .context("session grant restore has no active authority/device scope")?;
    let user_store = crate::secure_key_store::UserLocalStore::new(
        scope.authority.clone(),
        scope.device_id.clone(),
    )?;
    let grant = crate::state::load_session_grant_from_user_secure_store(&user_store, secure_store)?
        .filter(|grant| grant_matches_station(grant, station_url))
        .context("no session grant is available for the active Station")?;
    if grant.account_id != scope.authority || grant.device_id != scope.device_id {
        anyhow::bail!("session grant does not match the active authority/device scope");
    }
    Ok(grant)
}

/// Restore the grant for one already-resolved account without relying on the
/// process-wide active scope. This is the only safe read during onboarding:
/// the root still advertises `pending_login`, while the accepted grant has
/// already moved to its authority/device-scoped secure store.
pub(crate) fn load_account_session_grant_with_secure_store(
    account: &crate::config::ActiveAccountContext,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<PersistedSessionGrant> {
    let user_store = crate::secure_key_store::UserLocalStore::new(
        account.authority.clone(),
        account.device_id.clone(),
    )?;
    let grant = crate::state::load_session_grant_from_user_secure_store(&user_store, secure_store)?
        .context("no session grant is available for the accepted account")?;
    if !grant_matches_station(&grant, account.server_url.as_str()) {
        anyhow::bail!("session grant does not match the accepted account server");
    }
    if !grant_matches_principal_did(&grant, account.did()) {
        anyhow::bail!("session grant does not match the accepted account principal");
    }
    if grant.device_id != account.device_id {
        anyhow::bail!("session grant does not match the accepted account device");
    }
    if grant.audience_id != account.authority.station_id {
        anyhow::bail!("session grant does not match the accepted account audience");
    }
    Ok(grant)
}

pub(crate) async fn provide_authenticated_session(
    station_url: &str,
) -> anyhow::Result<AuthenticatedSession> {
    provide_authenticated_session_with_secure_store(
        station_url,
        crate::secure_key_store::default_secure_key_store("inkson"),
    )
    .await
}

async fn provide_authenticated_session_with_secure_store(
    station_url: &str,
    secure_store: Arc<dyn crate::secure_key_store::SecureKeyStore + Send + Sync>,
) -> anyhow::Result<AuthenticatedSession> {
    let mut store = LocalStateStore::default();
    let grant = load_active_session_grant(station_url, secure_store.as_ref())?;
    let device_handle =
        crate::identity::account_auth::grant_dpop::load_or_recover_device_key_with_secure_store(
            &mut store,
            secure_store.as_ref(),
        )?
        .context("session grant has no durable DPoP device key")?;
    let runtime = session_grant_runtime();
    let provider =
        session_transport_provider(runtime.as_ref(), &grant, &device_handle, secure_store).await?;
    let client = provider
        .provide()
        .await
        .map_err(|error| anyhow::anyhow!("provide authenticated session transport: {error}"))?;
    let state = provider
        .session()
        .current_state()
        .context("authenticated session provider has no grant state")?;
    Ok(AuthenticatedSession {
        client,
        grant: persisted_session_grant_from_state(&state, &grant.station_url, &device_handle)?,
    })
}

pub(crate) async fn refresh_authenticated_session_after_unauthorized(
    station_url: &str,
) -> anyhow::Result<AuthenticatedSession> {
    refresh_authenticated_session_after_unauthorized_with_secure_store(
        station_url,
        crate::secure_key_store::default_secure_key_store("inkson"),
    )
    .await
}

async fn refresh_authenticated_session_after_unauthorized_with_secure_store(
    station_url: &str,
    secure_store: Arc<dyn crate::secure_key_store::SecureKeyStore + Send + Sync>,
) -> anyhow::Result<AuthenticatedSession> {
    let mut store = LocalStateStore::default();
    let grant = load_active_session_grant(station_url, secure_store.as_ref())?;
    let device_handle =
        crate::identity::account_auth::grant_dpop::load_or_recover_device_key_with_secure_store(
            &mut store,
            secure_store.as_ref(),
        )?
        .context("session grant has no durable DPoP device key")?;
    let runtime = session_grant_runtime();
    let provider =
        session_transport_provider(runtime.as_ref(), &grant, &device_handle, secure_store).await?;
    if let Err(error) = provider.refresh_after_unauthorized().await {
        let error = anyhow::Error::from(error).context("session grant refresh");
        if crate::api_error::is_terminal_session_grant_refresh_error(&error) {
            provider
                .invalidate()
                .map_err(|invalidate| anyhow::anyhow!("{error}; invalidate grant: {invalidate}"))?;
        }
        return Err(error);
    }
    let client = provider
        .provide()
        .await
        .map_err(|error| anyhow::anyhow!("rebuild authenticated session transport: {error}"))?;
    let state = provider
        .session()
        .current_state()
        .context("refreshed session provider has no grant state")?;
    Ok(AuthenticatedSession {
        client,
        grant: persisted_session_grant_from_state(&state, &grant.station_url, &device_handle)?,
    })
}

pub(crate) fn cached_authenticated_sdk_client(
    station_url: &str,
) -> Option<arkret_sdk::http_client::Client> {
    let station_url = Url::parse(station_url).ok()?;
    session_grant_runtime()
        .get_for_server(&normalized_server_key(&station_url))?
        .cached_transport()
}

async fn session_transport_provider(
    runtime: &SessionGrantRuntime,
    grant: &PersistedSessionGrant,
    device_handle: &DpopHandle,
    secure_store: Arc<dyn crate::secure_key_store::SecureKeyStore + Send + Sync>,
) -> anyhow::Result<InksonSessionProvider> {
    let server_key = normalized_server_key(&grant.station_url);
    if let Some(provider) = runtime.get(&server_key, grant.device_id.as_str()) {
        return Ok(provider);
    }

    // Restoring the provider resolves the Account Authority asynchronously.
    // Several app effects can arrive here together before the first restore
    // reaches `runtime.replace`; serialize that cold path so every caller
    // shares one SessionEngine and therefore one consumable-grant refresh gate.
    let _initialization = session_provider_initialization_lock().lock().await;
    if let Some(provider) = runtime.get(&server_key, grant.device_id.as_str()) {
        return Ok(provider);
    }

    let gate_account_base_url =
        crate::identity::account_auth::resolve_principal_gate_account_base_url(
            grant.station_url.as_str(),
        )
        .await
        .context("resolve Account Authority")?;
    let account_sdk_base_url = sdk_base_url_from_gate_account_base_url(&gate_account_base_url)?;
    let principal_sdk_base_url = grant.station_url.clone();
    let refresh_transport = ReplaceableSessionTransport::default();
    let factory = InksonAuthenticatedTransportFactory {
        principal_sdk_base_url,
        account_sdk_base_url,
        station_url: grant.station_url.clone(),
        device_handle: device_handle.clone(),
        refresh_transport: refresh_transport.clone(),
    };
    let principal_core_id = persisted_grant_principal_id(grant)?;
    let active_scope = crate::secure_key_store::active_device_seed_scope()
        .context("session grant restore has no active authority/device scope")?;
    if active_scope.authority.principal_id != principal_core_id
        || active_scope.device_id != grant.device_id
    {
        anyhow::bail!("session grant does not match the active authority/device scope");
    }
    let state_store = PersistedSessionGrantStore {
        secure_store,
        user_store: crate::secure_key_store::UserLocalStore::new(
            active_scope.authority,
            active_scope.device_id,
        )?,
        station_url: grant.station_url.clone(),
        device_handle: device_handle.clone(),
    };
    let refresh_options = SessionRefreshOptions {
        request: None,
        expected_dpop_jkt: Some(device_handle.jkt().to_owned()),
    };
    let provider = match SessionTransportProvider::restore(
        refresh_transport.clone(),
        factory.clone(),
        refresh_options.clone(),
        state_store.clone(),
    )? {
        restored if restored.session().current_state().is_some() => restored,
        _ => {
            SessionTransportProvider::with_store(
                SessionEngine::with_state(
                    refresh_transport,
                    session_grant_state_from_persisted(grant, device_handle, Utc::now())?,
                ),
                factory,
                refresh_options,
                state_store,
            )
            .await?
        }
    };
    runtime.replace(server_key, grant.device_id.to_string(), provider.clone());
    Ok(provider)
}

fn session_provider_initialization_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn persisted_session_grant_from_state(
    state: &SessionGrantState,
    station_url: &Url,
    device_handle: &DpopHandle,
) -> anyhow::Result<PersistedSessionGrant> {
    let device_id = state
        .device_id
        .as_ref()
        .context("session grant state has no device_id")?;
    let session_private_key_pem = device_handle
        .session_signing_key_pkcs8_pem()
        .map_err(|error| anyhow::anyhow!("export device session key: {error}"))?;
    Ok(PersistedSessionGrant {
        grant_jwt: state.grant_jwt.clone(),
        session_private_key_pem: session_private_key_pem.to_string(),
        grant_id: state.grant_id.as_str().to_owned(),
        audience_id: state.audience_id.clone(),
        granted_scope: state.granted_scope.clone(),
        account_id: state.account_id.clone(),
        device_id: device_id.clone(),
        station_url: station_url.clone(),
        grant_expires_at: Some(state.expires_at),
        stored_at: Utc::now(),
    })
}

fn session_grant_state_from_persisted(
    grant: &PersistedSessionGrant,
    device_handle: &DpopHandle,
    now: chrono::DateTime<Utc>,
) -> anyhow::Result<SessionGrantState> {
    let expires_at = grant
        .grant_expires_at
        .unwrap_or_else(|| now + chrono::Duration::seconds(REFRESH_SKEW_SECS));
    Ok(SessionGrantState {
        account_id: grant.account_id.clone(),
        device_id: Some(grant.device_id.clone()),
        grant_id: arkret_wire::SessionGrantId::new(grant.grant_id.trim().to_owned())
            .map_err(|error| anyhow::anyhow!("invalid refresh grant_id: {error}"))?,
        grant_jwt: grant.grant_jwt.clone(),
        expires_at,
        audience_id: grant.audience_id.clone(),
        granted_scope: grant.granted_scope.clone(),
        // Reconstructed-from-persistence state: the client persistence layer does
        // not retain the session public key, and garth's refresh flow never reads
        // it (only the wire refresh outcome supplies the rotated key). Pass `None`
        // rather than a placeholder string.
        session_public_key: None,
        dpop_jkt: Some(device_handle.jkt().to_owned()),
    })
}

/// Resolve the stable core principal authorized by a persisted session grant.
///
/// Records always store a `DidCoreId`. Anything else is an invalid record: the
/// caller must treat the failure as "no usable session" and re-authenticate,
/// never reconstruct a core id from some other identifier form.
pub(crate) fn persisted_grant_principal_id(
    grant: &PersistedSessionGrant,
) -> anyhow::Result<arkret_sdk::DidCoreId> {
    Ok(grant.account_id.principal_id.clone())
}

pub(crate) fn grant_matches_principal_did(
    grant: &PersistedSessionGrant,
    principal_did: &arkret_sdk::Did,
) -> bool {
    let Ok(expected_core_id) = arkret_sdk::project_did_to_core_id(principal_did) else {
        return false;
    };
    grant_matches_principal_id(grant, &expected_core_id)
}

pub(crate) fn grant_matches_principal_id(
    grant: &PersistedSessionGrant,
    principal_id: &arkret_sdk::DidCoreId,
) -> bool {
    persisted_grant_principal_id(grant).is_ok_and(|grant_core_id| grant_core_id == *principal_id)
}

pub(crate) fn sdk_base_url_from_gate_account_base_url(
    gate_account_base_url: &str,
) -> anyhow::Result<Url> {
    let mut url = Url::parse(gate_account_base_url.trim())
        .with_context(|| format!("invalid Account Authority URL: {gate_account_base_url}"))?;
    url.set_query(None);
    url.set_fragment(None);

    let path = url.path().trim_end_matches('/');
    if let Some(prefix) = path.strip_suffix("/_arkret/gate/account") {
        let root_path = if prefix.is_empty() {
            "/".to_owned()
        } else {
            format!("{}/", prefix.trim_end_matches('/'))
        };
        url.set_path(&root_path);
    } else if !url.path().ends_with('/') {
        let with_slash = format!("{}/", url.path());
        url.set_path(&with_slash);
    }
    Ok(url)
}

fn mint_session_grant_refresh_proof(
    grant: &PersistedSessionGrant,
    holder_jkt: &str,
) -> anyhow::Result<arkret_sdk::AcceptedDeviceRefreshPossessionProof> {
    let principal_core = persisted_grant_principal_id(grant)?;
    let device_id = grant.device_id.clone();
    let audience = grant.audience_id.clone();
    let predecessor_session_grant_id = arkret_wire::SessionGrantId::new(
        required_trimmed(&grant.grant_id, "grant_id")?.to_owned(),
    )?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active device identity signer is not installed"))?;
    let principal_did = arkret_sdk::Did::new(signer.signer_did().to_owned())
        .map_err(|error| anyhow::anyhow!("soft logout restore signer did: {error}"))?;
    if arkret_sdk::project_did_to_core_id(&principal_did)? != principal_core {
        anyhow::bail!("active signer did does not project to the refresh principal_id");
    }
    let verification_method = arkret_sdk::DidUrl::new(format!("{principal_did}#{device_id}"))
        .map_err(|error| anyhow::anyhow!("soft logout restore verification method: {error}"))?;
    let session_intent_digest = arkret_sdk::session_grant_refresh_request_digest(
        &grant.grant_jwt,
        &predecessor_session_grant_id,
        &principal_core,
        &device_id,
        &audience,
        holder_jkt,
    )?;
    let issued_at = Utc::now();
    let expires_at = issued_at + chrono::Duration::seconds(60);
    let unsigned = arkret_wire::UnsignedAcceptedDeviceRefreshPossessionProof {
        context: arkret_wire::AcceptedDevicePossessionProofContext::V1,
        purpose: arkret_wire::AcceptedDeviceRefreshPossessionPurpose::SessionGrantRefresh,
        predecessor_session_grant_id,
        account_id: arkret_wire::AccountId::new(principal_core, audience.clone()),
        device_id,
        audience_id: audience,
        holder_jkt: holder_jkt.to_owned(),
        session_intent_digest,
        issued_at,
        expires_at,
        verification_method,
    };
    let signature = arkret_sdk::Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(signer.sign_raw(&unsigned.canonical_signing_bytes()?)?),
    )
    .map_err(|error| anyhow::anyhow!(error))?;
    unsigned.attach_signature(signature).map_err(Into::into)
}

fn required_trimmed<'a>(value: &'a str, field: &str) -> anyhow::Result<&'a str> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("{field} is required");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_device_handle() -> DpopHandle {
        let seed = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let record =
            crate::identity::account_auth::grant_dpop::dpop_device_key_record_from_seed(&seed)
                .unwrap();
        crate::identity::account_auth::grant_dpop::device_handle_from_seed(&seed, &record.jkt)
            .unwrap()
    }

    fn test_grant_state() -> SessionGrantState {
        let principal_id =
            arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example".to_owned())
                .unwrap();
        let station_id =
            arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkfixture:soland.example".to_owned())
                .unwrap();
        SessionGrantState {
            account_id: arkret_sdk::AccountId::new(principal_id, station_id),
            device_id: Some(
                arkret_sdk::DeviceId::new(
                    "ak:device:01964137-0000-7000-8000-000000000001".to_owned(),
                )
                .unwrap(),
            ),
            grant_id: arkret_wire::SessionGrantId::new(
                "ak:session_grant:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7".to_owned(),
            )
            .unwrap(),
            grant_jwt: "grant.jwt.signature".to_owned(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            audience_id: arkret_sdk::DidCoreId::new(
                "ak:did_core:webvh:z6mkfixture:soland.example".to_owned(),
            )
            .unwrap(),
            granted_scope: Vec::new(),
            session_public_key: None,
            dpop_jkt: None,
        }
    }

    fn test_persisted_grant(principal_id: &str) -> PersistedSessionGrant {
        PersistedSessionGrant {
            grant_jwt: "grant.jwt.signature".to_owned(),
            session_private_key_pem: String::new(),
            grant_id: "ak:session_grant:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7".to_owned(),
            audience_id: arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkfixture:soland.example")
                .unwrap(),
            granted_scope: Vec::new(),
            account_id: arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new(principal_id.to_owned()).unwrap(),
                arkret_sdk::DidCoreId::new(
                    "ak:did_core:webvh:z6mkfixture:soland.example".to_owned(),
                )
                .unwrap(),
            ),
            device_id: arkret_sdk::DeviceId::new(
                "ak:device:01964137-0000-7000-8000-000000000001".to_owned(),
            )
            .unwrap(),
            station_url: url::Url::parse("https://soland.example").unwrap(),
            grant_expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            stored_at: Utc::now(),
        }
    }

    #[test]
    fn persisted_session_retains_the_issued_scope_after_reload() {
        let handle = test_device_handle();
        let mut original = test_grant_state();
        original.granted_scope = vec!["ak:self:read".to_owned(), "ak:self:write".to_owned()];
        let persisted = persisted_session_grant_from_state(
            &original,
            &Url::parse("https://soland.example").unwrap(),
            &handle,
        )
        .unwrap();
        let encoded = serde_json::to_vec(&persisted).unwrap();
        let reloaded: PersistedSessionGrant = serde_json::from_slice(&encoded).unwrap();
        let restored = session_grant_state_from_persisted(&reloaded, &handle, Utc::now()).unwrap();
        assert_eq!(restored.granted_scope, original.granted_scope);
        assert_eq!(restored.account_id, original.account_id);
        assert_eq!(restored.grant_id, original.grant_id);

        let mut incomplete = serde_json::to_value(&persisted).unwrap();
        incomplete.as_object_mut().unwrap().remove("granted_scope");
        assert!(serde_json::from_value::<PersistedSessionGrant>(incomplete).is_err());
    }

    #[test]
    fn authenticated_and_refresh_transports_keep_their_respective_authorities() {
        let factory = InksonAuthenticatedTransportFactory {
            principal_sdk_base_url: Url::parse("https://soland.example/").unwrap(),
            account_sdk_base_url: Url::parse("https://coauth.example/").unwrap(),
            station_url: Url::parse("https://soland.example").unwrap(),
            device_handle: test_device_handle(),
            refresh_transport: ReplaceableSessionTransport::default(),
        };
        let state = test_grant_state();

        let authenticated = factory.build(&state).unwrap();
        let refresh = factory.build_account_client(&state).unwrap();

        assert_eq!(authenticated.base_url().as_str(), "https://soland.example/");
        assert_eq!(refresh.base_url().as_str(), "https://coauth.example/");
    }

    #[test]
    fn session_grant_core_id_matches_its_principal_did_without_string_equality() {
        let did = arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
        let core_id = arkret_sdk::project_did_to_core_id(&did).unwrap();
        let grant = test_persisted_grant(core_id.as_str());

        assert!(grant_matches_principal_did(&grant, &did));
        assert!(grant_matches_principal_id(&grant, &core_id));
        assert_ne!(grant.account_id.principal_id.as_str(), did.as_str());
    }

    /// A persisted grant that stores anything other than a `DidCoreId` is an
    /// invalid record. It MUST NOT be repaired by back-projecting a DID —
    /// the session is simply unusable and the caller re-authenticates.
    #[test]
    fn session_grant_holding_a_did_is_rejected_rather_than_back_projected() {
        let did = arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
        let mut persisted = serde_json::to_value(test_persisted_grant(
            "ak:did_core:webvh:z6mkfixture:alice.example",
        ))
        .unwrap();
        persisted["account_id"]["principal_id"] = serde_json::Value::String(did.to_string());

        assert!(serde_json::from_value::<PersistedSessionGrant>(persisted).is_err());
    }

    #[test]
    fn production_grant_restore_reads_the_active_secure_scope() {
        let grant = test_persisted_grant("ak:did_core:webvh:z6mkfixture:alice.example");
        let authority = arkret_sdk::AccountId::new(
            grant.account_id.principal_id.clone(),
            arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkfixture:soland.example".to_owned())
                .unwrap(),
        );
        let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(Some((
            &authority,
            &grant.device_id,
        )));
        let user_store =
            crate::secure_key_store::UserLocalStore::new(authority, grant.device_id.clone())
                .unwrap();
        let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
        user_store
            .save_secret(
                &secure_store,
                LocalStateStore::SECURE_SESSION_GRANT_KEY,
                &serde_json::to_string(&grant).unwrap(),
            )
            .unwrap();

        let restored = load_active_session_grant("https://soland.example", &secure_store).unwrap();

        assert_eq!(restored.grant_id, grant.grant_id);
        assert_eq!(restored.account_id, grant.account_id);
        assert_eq!(restored.device_id, grant.device_id);
    }

    #[test]
    fn onboarding_grant_restore_uses_the_explicit_account_without_an_active_scope() {
        let did = arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
        let principal_id = arkret_sdk::project_did_to_core_id(&did).unwrap();
        let grant = test_persisted_grant(principal_id.as_str());
        let authority = arkret_sdk::AccountId::new(
            principal_id,
            arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkfixture:soland.example".to_owned())
                .unwrap(),
        );
        let account = crate::config::ActiveAccountContext::new(
            "ak:profile:test".to_owned(),
            authority.clone(),
            arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap(),
            arkret_sdk::PrincipalResolutionProjection {
                did,
                method_history_head: "head-test".to_owned(),
                version_id: "version-test".to_owned(),
                resolution_event_ref: "event-test".to_owned(),
                updated_at: Utc::now(),
            },
            grant.device_id.clone(),
            url::Url::parse("https://soland.example").unwrap(),
        )
        .unwrap();
        let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
        let user_store =
            crate::secure_key_store::UserLocalStore::new(authority, grant.device_id.clone())
                .unwrap();
        let secure_store = crate::secure_key_store::MemorySecureKeyStore::default();
        user_store
            .save_secret(
                &secure_store,
                LocalStateStore::SECURE_SESSION_GRANT_KEY,
                &serde_json::to_string(&grant).unwrap(),
            )
            .unwrap();

        let restored =
            load_account_session_grant_with_secure_store(&account, &secure_store).unwrap();

        assert_eq!(restored.grant_id, grant.grant_id);
        assert!(crate::secure_key_store::active_device_seed_scope().is_none());

        let mut wrong_server = account.clone();
        wrong_server.server_url = url::Url::parse("https://other.example").unwrap();
        let error =
            load_account_session_grant_with_secure_store(&wrong_server, &secure_store).unwrap_err();
        assert!(error.to_string().contains("account server"));

        let mut wrong_audience = grant;
        wrong_audience.audience_id =
            arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkfixture:other.example").unwrap();
        user_store
            .save_secret(
                &secure_store,
                LocalStateStore::SECURE_SESSION_GRANT_KEY,
                &serde_json::to_string(&wrong_audience).unwrap(),
            )
            .unwrap();
        let error =
            load_account_session_grant_with_secure_store(&account, &secure_store).unwrap_err();
        assert!(error.to_string().contains("account audience"));
    }
}
