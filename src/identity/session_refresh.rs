//! Session keep-alive, driven by the persisted `ak.session.grant`.
//!
//! ②(A+②) model (api-conventions.md §3.3): there is **no** second client-visible
//! local session credential minted by soland. After login, the client
//! holds the `ak.session.grant` (issued by the Account Authority) plus the
//! grant-binding (DPoP) key whose thumbprint is the grant's `cnf.jkt`. The grant
//! itself is the live credential for `/_arkret/self/*`: every request presents
//! `Authorization: Bearer <grant>` + a per-request `DPoP` proof.
//!
//! The shared `SessionTransportProvider` owns durable restore, due and forced
//! refresh, single-flight coordination, persistence, and authenticated client
//! rebuild. Inkson supplies only its secure grant store, DPoP factory, and UI
//! result mapping.

#[cfg(target_arch = "wasm32")]
use std::rc::Rc;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::OnceLock;
use std::sync::{Arc, Mutex, PoisonError};

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
use serde::Serialize;
use url::Url;

use crate::config::normalize_server_url;
use crate::identity::account_auth::grant_dpop::DpopHandle;
use crate::state::{LocalStateStore, PersistedSessionGrant};

const SOFT_LOGOUT_RESTORE_OPERATION: &str = "resume_soft_logged_out_session";

// The refresh decision layer (constants, `RefreshDecision`, the due/dead
// predicates) is garth's — inkson only maps its persisted grant into
// `garth::SessionGrantRefreshState` and supplies the wall clock. Semantics
// notes that used to live on a local copy: `NoGrant` must not clear a live
// credential; `GrantExpired` still attempts rotation so only the refresh
// endpoint's terminal error decides whether session material is cleared.
pub use garth::{POLL_INTERVAL_SECS, REFRESH_SKEW_SECS};

#[derive(Clone, Default)]
struct ReplaceableSessionTransport {
    client: Arc<Mutex<Option<arkret_sdk::http_client::Client>>>,
}

impl ReplaceableSessionTransport {
    fn replace(&self, client: arkret_sdk::http_client::Client) {
        *self.client.lock().unwrap_or_else(PoisonError::into_inner) = Some(client);
    }

    fn current(&self) -> arkret_sdk::Result<arkret_sdk::http_client::Client> {
        self.client
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                arkret_sdk::Error::Protocol("session transport is not configured".into())
            })
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
                .map_err(arkret_sdk::Error::from)
        })
    }

    fn refresh_session_grant<'a>(
        &'a self,
        request: arkret_sdk::SessionGrantRefreshRequestBody,
    ) -> BoxSessionFuture<'a, arkret_sdk::SessionGrantRefreshOutcome> {
        let client = self.current();
        Box::pin(async move {
            client?
                .auth_refresh_session_grant(&request)
                .await
                .map_err(arkret_sdk::Error::from)
        })
    }
}

#[derive(Clone)]
struct InksonAuthenticatedTransportFactory {
    principal_sdk_base_url: Url,
    account_sdk_base_url: Url,
    principal_server_url: String,
    device_handle: DpopHandle,
    refresh_transport: ReplaceableSessionTransport,
}

impl InksonAuthenticatedTransportFactory {
    fn build_principal_client(
        &self,
        state: &SessionGrantState,
    ) -> arkret_sdk::Result<arkret_sdk::http_client::Client> {
        ClientBuilder::new(self.principal_sdk_base_url.clone())
            .allow_insecure_localhost()
            .auth(Auth::Dpop(
                self.device_handle
                    .sdk_dpop_auth_for_access_token(state.grant_jwt.clone()),
            ))
            .build()
            .map_err(arkret_sdk::Error::from)
    }

    fn build_account_client(
        &self,
        state: &SessionGrantState,
    ) -> arkret_sdk::Result<arkret_sdk::http_client::Client> {
        ClientBuilder::new(self.account_sdk_base_url.clone())
            .allow_insecure_localhost()
            .auth(Auth::Dpop(
                self.device_handle
                    .sdk_dpop_auth_for_access_token(state.grant_jwt.clone()),
            ))
            .build()
            .map_err(arkret_sdk::Error::from)
    }

    fn persisted(&self, state: &SessionGrantState) -> anyhow::Result<PersistedSessionGrant> {
        persisted_session_grant_from_state(state, &self.principal_server_url, &self.device_handle)
    }
}

impl AuthenticatedTransportFactory for InksonAuthenticatedTransportFactory {
    type Transport = arkret_sdk::http_client::Client;

    fn build(&self, state: &SessionGrantState) -> arkret_sdk::Result<Self::Transport> {
        self.build_principal_client(state)
    }

    fn refresh_options(
        &self,
        state: &SessionGrantState,
        _fallback: &SessionRefreshOptions,
    ) -> arkret_sdk::Result<SessionRefreshOptions> {
        self.refresh_transport
            .replace(self.build_account_client(state)?);
        let persisted = self
            .persisted(state)
            .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))?;
        let proof = mint_session_grant_refresh_proof(&persisted)
            .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))?;
        Ok(SessionRefreshOptions {
            audience: Some(state.audience.clone()),
            device_id: state.device_id.clone(),
            proof: Some(proof),
            expected_dpop_jkt: Some(self.device_handle.jkt().to_owned()),
        })
    }
}

#[derive(Clone)]
struct PersistedSessionGrantStore {
    secure_store: Arc<dyn SecureKeyStore + Send + Sync>,
    principal_server_url: String,
    device_handle: DpopHandle,
}

impl SessionGrantStore for PersistedSessionGrantStore {
    fn load(&self) -> arkret_sdk::Result<Option<SessionGrantState>> {
        crate::state::load_session_grant_from_secure_store(self.secure_store.as_ref())
            .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))?
            .map(|grant| {
                session_grant_state_from_persisted(&grant, &self.device_handle, Utc::now())
            })
            .transpose()
            .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))
    }

    fn save<'a>(
        &'a self,
        state: &'a SessionGrantState,
    ) -> impl std::future::Future<Output = arkret_sdk::Result<()>> + garth::MaybeSend + 'a {
        let encoded = persisted_session_grant_from_state(
            state,
            &self.principal_server_url,
            &self.device_handle,
        )
        .and_then(|grant| serde_json::to_vec(&grant).map_err(Into::into))
        .map_err(|error: anyhow::Error| arkret_sdk::Error::Protocol(error.to_string()));
        async move {
            let encoded = encoded?;
            self.secure_store
                .put_secret(
                    &crate::secure_key_store::account_scoped_device_key(
                        LocalStateStore::SECURE_SESSION_GRANT_KEY,
                    ),
                    &encoded,
                    PutSecretOptions {
                        durability: SecretDurability::DurableBeforeReturn,
                        class: SecretClass::SessionCredential,
                    },
                )
                .await
                .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))
        }
    }

    fn clear(&self) -> arkret_sdk::Result<()> {
        self.secure_store
            .delete_secret(&crate::secure_key_store::account_scoped_device_key(
                LocalStateStore::SECURE_SESSION_GRANT_KEY,
            ))
            .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))
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
fn normalized_server_key(server_url: &str) -> String {
    normalize_server_url(server_url)
        .trim()
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

/// True when a persisted grant is scoped to the active Principal Server.
///
/// The client currently keeps one foreground server session. A grant minted
/// for another server must not be refreshed in the background or persisted as
/// the active server's credential.
pub fn grant_matches_principal_server(
    grant: &PersistedSessionGrant,
    principal_server_url: &str,
) -> bool {
    let grant_server = normalized_server_key(&grant.principal_server_url);
    let active_server = normalized_server_key(principal_server_url);
    !grant_server.is_empty() && grant_server == active_server
}

/// Restore the shared provider from the durable grant and return its current
/// authenticated SDK client. Due refresh and transport rebuild happen inside
/// `SessionTransportProvider`; callers must not repeat expiry decisions.
pub async fn provide_authenticated_sdk_client(
    principal_server_url: &str,
) -> anyhow::Result<arkret_sdk::http_client::Client> {
    Ok(provide_authenticated_session(principal_server_url)
        .await?
        .client)
}

pub(crate) struct AuthenticatedSession {
    pub client: arkret_sdk::http_client::Client,
    pub grant: PersistedSessionGrant,
}

pub(crate) async fn provide_authenticated_session(
    principal_server_url: &str,
) -> anyhow::Result<AuthenticatedSession> {
    let mut store = LocalStateStore::default();
    let grant = store
        .session_grant()
        .filter(|grant| grant_matches_principal_server(grant, principal_server_url))
        .context("no session grant is available for the active principal server")?;
    let device_handle =
        crate::identity::account_auth::grant_dpop::load_or_recover_device_key(&mut store)?
            .context("session grant has no durable DPoP device key")?;
    let runtime = session_grant_runtime();
    let provider = session_transport_provider(runtime.as_ref(), &grant, &device_handle).await?;
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
        grant: persisted_session_grant_from_state(
            &state,
            &grant.principal_server_url,
            &device_handle,
        )?,
    })
}

pub(crate) async fn refresh_authenticated_session_after_unauthorized(
    principal_server_url: &str,
) -> anyhow::Result<AuthenticatedSession> {
    let mut store = LocalStateStore::default();
    let grant = store
        .session_grant()
        .filter(|grant| grant_matches_principal_server(grant, principal_server_url))
        .context("no session grant is available for the active principal server")?;
    let device_handle =
        crate::identity::account_auth::grant_dpop::load_or_recover_device_key(&mut store)?
            .context("session grant has no durable DPoP device key")?;
    let runtime = session_grant_runtime();
    let provider = session_transport_provider(runtime.as_ref(), &grant, &device_handle).await?;
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
        grant: persisted_session_grant_from_state(
            &state,
            &grant.principal_server_url,
            &device_handle,
        )?,
    })
}

pub(crate) fn cached_authenticated_sdk_client(
    principal_server_url: &str,
) -> Option<arkret_sdk::http_client::Client> {
    session_grant_runtime()
        .get_for_server(&normalized_server_key(principal_server_url))?
        .cached_transport()
}

async fn session_transport_provider(
    runtime: &SessionGrantRuntime,
    grant: &PersistedSessionGrant,
    device_handle: &DpopHandle,
) -> anyhow::Result<InksonSessionProvider> {
    let server_key = normalized_server_key(&grant.principal_server_url);
    if let Some(provider) = runtime.get(&server_key, &grant.device_id) {
        return Ok(provider);
    }

    let gate_account_base = crate::identity::account_auth::resolve_principal_gate_account_base(
        &grant.principal_server_url,
    )
    .await
    .map_err(|error| anyhow::anyhow!("resolve Account Authority: {error}"))?;
    let account_sdk_base_url = sdk_base_url_from_gate_account_base(&gate_account_base)?;
    let principal_sdk_base_url = crate::config::validate_server_url(&grant.principal_server_url)?;
    let refresh_transport = ReplaceableSessionTransport::default();
    let factory = InksonAuthenticatedTransportFactory {
        principal_sdk_base_url,
        account_sdk_base_url,
        principal_server_url: grant.principal_server_url.clone(),
        device_handle: device_handle.clone(),
        refresh_transport: refresh_transport.clone(),
    };
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let state_store = PersistedSessionGrantStore {
        secure_store,
        principal_server_url: grant.principal_server_url.clone(),
        device_handle: device_handle.clone(),
    };
    let refresh_options = SessionRefreshOptions {
        audience: Some(session_audience(&grant.audience)?),
        device_id: Some(
            arkret_sdk::DeviceId::new(grant.device_id.trim().to_owned())
                .map_err(|error| anyhow::anyhow!("invalid refresh device_id: {error}"))?,
        ),
        proof: None,
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
    runtime.replace(server_key, grant.device_id.clone(), provider.clone());
    Ok(provider)
}

fn persisted_session_grant_from_state(
    state: &SessionGrantState,
    principal_server_url: &str,
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
        audience: state.audience.to_string(),
        principal_id: state.principal_id.to_string(),
        device_id: device_id.to_string(),
        principal_server_url: principal_server_url.to_owned(),
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
        principal_id: arkret_sdk::Did::new(grant.principal_id.trim().to_owned())
            .map_err(|error| anyhow::anyhow!("invalid refresh principal_id: {error}"))?,
        device_id: Some(
            arkret_sdk::DeviceId::new(grant.device_id.trim().to_owned())
                .map_err(|error| anyhow::anyhow!("invalid refresh device_id: {error}"))?,
        ),
        grant_id: arkret_sdk::GrantId::new(grant.grant_id.trim().to_owned())
            .map_err(|error| anyhow::anyhow!("invalid refresh grant_id: {error}"))?,
        grant_jwt: grant.grant_jwt.clone(),
        expires_at,
        audience: session_audience(&grant.audience)?,
        granted_scope: Vec::new(),
        // Reconstructed-from-persistence state: the client persistence layer does
        // not retain the session public key, and garth's refresh flow never reads
        // it (only the wire refresh outcome supplies the rotated key). Pass `None`
        // rather than a placeholder string.
        session_public_key: None,
        dpop_jkt: Some(device_handle.jkt().to_owned()),
    })
}

pub(crate) fn sdk_base_url_from_gate_account_base(gate_account_base: &str) -> anyhow::Result<Url> {
    let mut url = Url::parse(gate_account_base.trim())
        .with_context(|| format!("invalid Account Authority URL: {gate_account_base}"))?;
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

#[derive(Debug, Serialize)]
struct SoftLogoutDidProofClaims<'a> {
    pub principal_id: &'a str,
    pub device_id: &'a str,
    pub audience: &'a str,
    pub challenge: &'a str,
    pub request_canonical_digest: &'a str,
    pub issued_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct SoftLogoutRestoreRequestDigest<'a> {
    pub operation: &'static str,
    pub grant_jwt_hash: String,
    pub principal_id: &'a str,
    pub device_id: &'a str,
    pub audience: &'a str,
    pub grant_binding_key_id: &'a str,
}

fn mint_session_grant_refresh_proof(
    grant: &PersistedSessionGrant,
) -> anyhow::Result<arkret_sdk::SessionGrantRefreshProof> {
    let principal_id = required_trimmed(&grant.principal_id, "principal_id")?;
    let device_id = required_trimmed(&grant.device_id, "device_id")?;
    let audience = required_trimmed(&grant.audience, "audience")?;
    let verification_method = format!("{principal_id}#{device_id}");
    let request_canonical_digest = soft_logout_restore_request_canonical_digest(
        &grant.grant_jwt,
        principal_id,
        device_id,
        audience,
        &verification_method,
    )?;
    let request_canonical_digest_hash = arkret_sdk::Hash::new(request_canonical_digest.clone())
        .map_err(|error| anyhow::anyhow!("soft logout restore request digest: {error}"))?;
    let challenge = soft_logout_refresh_challenge()?;
    let issued_at = Utc::now();
    let expires_at = issued_at + chrono::Duration::seconds(60);
    let claims = SoftLogoutDidProofClaims {
        principal_id,
        device_id,
        audience,
        challenge: &challenge,
        request_canonical_digest: &request_canonical_digest,
        issued_at,
        expires_at,
    };
    let payload = crate::canonical::canonical_json_bytes(&claims)
        .map_err(|error| anyhow::anyhow!("soft logout restore proof payload: {error}"))?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active device identity signer is not installed"))?;
    let signature = signer
        .detached_jws_over_payload_with_kid(&verification_method, &payload)
        .map_err(|error| anyhow::anyhow!("sign soft logout restore proof: {error}"))?;
    Ok(arkret_sdk::SessionGrantRefreshProof {
        proof_kind: Some(arkret_sdk::SessionGrantProofKind::DidBoundSignature),
        challenge: Some(challenge),
        request_canonical_digest: Some(request_canonical_digest_hash),
        audience: Some(session_audience(audience)?),
        issued_at: Some(issued_at),
        expires_at: Some(expires_at),
        signature: Some(signature),
        verification_method: Some(verification_method),
    })
}

fn required_trimmed<'a>(value: &'a str, field: &str) -> anyhow::Result<&'a str> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("{field} is required");
    }
    Ok(value)
}

fn session_audience(value: &str) -> anyhow::Result<arkret_sdk::Did> {
    let value = required_trimmed(value, "audience")?;
    arkret_sdk::Did::new(value.to_owned())
        .map_err(|error| anyhow::anyhow!("invalid session audience DID: {error}"))
}

fn soft_logout_restore_request_canonical_digest(
    grant_jwt: &str,
    principal_id: &str,
    device_id: &str,
    audience: &str,
    grant_binding_key_id: &str,
) -> anyhow::Result<String> {
    crate::canonical::canonical_sha256(&SoftLogoutRestoreRequestDigest {
        operation: SOFT_LOGOUT_RESTORE_OPERATION,
        grant_jwt_hash: crate::identity::account_auth::session_grant_jwt_hash(grant_jwt),
        principal_id,
        device_id,
        audience,
        grant_binding_key_id,
    })
    .map_err(|error| anyhow::anyhow!("soft logout restore request canonicalization: {error}"))
}

/// Build the soft-logout refresh challenge from a pure 128-bit random nonce +
/// millisecond timestamp. The DPoP jkt is intentionally not mixed in: the
/// grant-binding key id is carried by the signed proof payload and request
/// digest.
fn soft_logout_refresh_challenge() -> anyhow::Result<String> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|err| anyhow::anyhow!("refresh challenge RNG: {err}"))?;
    Ok(format!(
        "sg-refresh-{}-{}",
        Utc::now().timestamp_millis(),
        URL_SAFE_NO_PAD.encode(nonce)
    ))
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
        SessionGrantState {
            principal_id: arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example".to_owned())
                .unwrap(),
            device_id: Some(
                arkret_sdk::DeviceId::new(
                    "ak:device:01964137-0000-7000-8000-000000000001".to_owned(),
                )
                .unwrap(),
            ),
            grant_id: arkret_sdk::GrantId::new(
                "ak:grant:01964137-0000-7000-8000-000000000001".to_owned(),
            )
            .unwrap(),
            grant_jwt: "grant.jwt.signature".to_owned(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            audience: arkret_sdk::Did::new("did:webvh:z6mkfixture:soland.example".to_owned())
                .unwrap(),
            granted_scope: Vec::new(),
            session_public_key: None,
            dpop_jkt: None,
        }
    }

    #[test]
    fn authenticated_and_refresh_transports_keep_their_respective_authorities() {
        let factory = InksonAuthenticatedTransportFactory {
            principal_sdk_base_url: Url::parse("https://soland.example/").unwrap(),
            account_sdk_base_url: Url::parse("https://coauth.example/").unwrap(),
            principal_server_url: "https://soland.example".to_owned(),
            device_handle: test_device_handle(),
            refresh_transport: ReplaceableSessionTransport::default(),
        };
        let state = test_grant_state();

        let authenticated = factory.build(&state).unwrap();
        let refresh = factory.build_account_client(&state).unwrap();

        assert_eq!(authenticated.base_url().as_str(), "https://soland.example/");
        assert_eq!(refresh.base_url().as_str(), "https://coauth.example/");
    }
}
