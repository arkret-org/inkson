//! Authenticated transport construction + the view/engine-facing call
//! wrapper (`with_authed_api*` / [`ApiCallError`]).
//!
//! This is the crate-level HTTP exit for authenticated self-path calls:
//! consumed by sync engines, bootstrap, MLS admission, and UI views.

use crate::api_error::{is_auth_expired_error, is_terminal_session_grant_error};
use crate::transport::TransportClient;

/// Create an authenticated API client from a base URL and optional session credential.
pub fn authed_api(base_url: &str, session_credential: String) -> anyhow::Result<TransportClient> {
    authed_api_with_sync(base_url, session_credential, None)
}

/// Create an authenticated API client that also forwards the latest sync token
/// for read-your-writes consistency on subsequent reads.
///
/// ②(A+②): `session_credential` is the `ak.session.grant` JWT.
/// The client also binds the grant-binding (DPoP) key so every `/_arkret/self/*`
/// request carries a per-request `DPoP` proof bound to the grant
/// (api-conventions.md §3.3). This is the centralized self-path credential
/// builder used across views.
pub fn authed_api_with_sync(
    base_url: &str,
    session_credential: String,
    wait_for_sync_token: Option<String>,
) -> anyhow::Result<TransportClient> {
    authenticated_transport(base_url, session_credential, wait_for_sync_token)
}

/// ②(A+②) — best-effort attach the grant-binding (DPoP) key to a client so its
/// `/_arkret/self/*` requests are sender-constrained (api-conventions.md §3.3).
/// In production the seed is read from the secure key store (independent of the
/// passed state store); in tests no key is present and the client stays
/// without device proof material.
pub fn attach_device_dpop(api: TransportClient) -> TransportClient {
    match try_attach_device_dpop(api.clone()) {
        Ok(api) => api,
        Err(error) => {
            tracing::warn!(?error, "view API DPoP device-key attach skipped");
            api
        }
    }
}

fn try_attach_device_dpop(api: TransportClient) -> anyhow::Result<TransportClient> {
    let mut store = crate::state::LocalStateStore::default();
    let Some(handle) =
        crate::identity::account_auth::grant_dpop::load_or_recover_device_key(&mut store)?
    else {
        return Ok(api);
    };
    Ok(api.with_dpop_device(handle))
}

#[cfg(target_arch = "wasm32")]
fn require_device_dpop(api: TransportClient) -> anyhow::Result<TransportClient> {
    let mut store = crate::state::LocalStateStore::default();
    let Some(handle) =
        crate::identity::account_auth::grant_dpop::load_or_recover_device_key(&mut store)?
    else {
        anyhow::bail!("missing DPoP device key for authenticated self request");
    };
    Ok(api.with_dpop_device(handle))
}

async fn ensure_self_path_auth_material_ready() -> Result<(), ApiCallError> {
    #[cfg(target_arch = "wasm32")]
    {
        crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson")
            .await
            .map(|_| ())
            .map_err(|error| {
                ApiCallError::Unavailable(anyhow::anyhow!(
                    "secure key store is not ready for authenticated self request: {error}"
                ))
            })?;
    }
    Ok(())
}

/// Reason a view-side API call failed. Roughly mirrors `connect()`'s
/// three-way error split:
///
/// * `Unavailable` — `TransportClient::new` rejected the base URL (bad scheme, parse error, etc.).
///   The session is intact; the user should fix the server URL.
/// * `AuthExpired` — the server returned a terminal session-grant code. The app-wide invalidator
///   has already cleared the session; callers should stop the current flow.
/// * `Failed` — every other error. Caller surfaces to status / last_error so the user sees a
///   retriable reason without losing the session.
#[derive(Debug)]
pub enum ApiCallError {
    Unavailable(anyhow::Error),
    AuthExpired(anyhow::Error),
    Failed(anyhow::Error),
}

impl ApiCallError {
    /// `true` when the error carries an explicit session-death signal
    /// from the server; the caller should wipe its session bundle.
    pub fn is_auth_expired(&self) -> bool {
        matches!(self, Self::AuthExpired(_))
    }

    /// The underlying error, regardless of classification, so callers can run
    /// wire-code predicates (e.g. [`crate::api_error::is_device_not_authorized_error`])
    /// against it.
    pub fn inner(&self) -> &anyhow::Error {
        match self {
            Self::Unavailable(err) | Self::AuthExpired(err) | Self::Failed(err) => err,
        }
    }

    /// Human-readable rendering suitable for `status` / `last_error`
    /// signals.
    pub fn display(&self) -> String {
        match self {
            Self::Unavailable(err) => format!("API unavailable: {err}"),
            Self::AuthExpired(err) => format!("Session expired: {err}"),
            Self::Failed(err) => format!("{err}"),
        }
    }
}

/// Build an authenticated [`TransportClient`] and pass it to the closure,
/// folding `TransportClient::new` errors + auth-expired errors + generic
/// API errors into a single [`ApiCallError`] so call sites can write:
///
/// ```ignore
/// match with_authed_api(&base, token, |api| async move {
///     api.list_key_backups().await
/// }).await {
///     Ok(value) => status.set(format!("{value}")),
///     Err(e) if e.is_auth_expired() => { /* stop current flow; invalidator owns cleanup */ }
///     Err(e) => last_error.set(Some(e.display())),
/// }
/// ```
///
/// instead of the three-deep nested `match`. Doesn't perform side
/// side effects of its own except terminal session invalidation through
/// `crate::runtime::session`, because lower-level helpers cannot own app signals.
pub async fn with_authed_api<F, Fut, T>(
    base_url: &str,
    session_credential: String,
    f: F,
) -> Result<T, ApiCallError>
where
    F: FnOnce(TransportClient) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    if session_credential.trim().is_empty() {
        return Err(ApiCallError::AuthExpired(anyhow::anyhow!(
            "missing authenticated session"
        )));
    }
    ensure_self_path_auth_material_ready().await?;
    let api = authed_api(base_url, session_credential).map_err(ApiCallError::Unavailable)?;
    match f(api).await {
        Ok(value) => Ok(value),
        Err(err) => Err(classify_api_call_error(err).await),
    }
}

/// Same as [`with_authed_api`] but also forwards a sync-cursor token to
/// the resulting `TransportClient` so any subsequent read is fenced behind
/// the latest write (read-your-writes consistency). Pass the result of
/// [`active_sync_token`] as `wait_for_sync_token`.
pub async fn with_authed_api_with_sync<F, Fut, T>(
    base_url: &str,
    session_credential: String,
    wait_for_sync_token: Option<String>,
    f: F,
) -> Result<T, ApiCallError>
where
    F: FnOnce(TransportClient) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    if session_credential.trim().is_empty() {
        return Err(ApiCallError::AuthExpired(anyhow::anyhow!(
            "missing authenticated session"
        )));
    }
    ensure_self_path_auth_material_ready().await?;
    let api = authed_api_with_sync(base_url, session_credential, wait_for_sync_token)
        .map_err(ApiCallError::Unavailable)?;
    match f(api).await {
        Ok(value) => Ok(value),
        Err(err) => Err(classify_api_call_error(err).await),
    }
}

/// Same three-way auth/refresh/classification contract as [`with_authed_api`],
/// but hands the closure the shared SDK `http-client::Client` instead of the
/// inkson [`TransportClient`] facade. This is the TransportClient-free transport exit that
/// migrated call sites use: they call the SDK endpoint method directly on the
/// client (`|http| async move { http.some_endpoint(&body).await.map_err(...) }`),
/// keeping the session-refresh + terminal-session-death handling identical to
/// the facade path while dropping the per-domain facade method.
pub async fn with_authed_sdk_client<F, Fut, T>(
    base_url: &str,
    session_credential: String,
    f: F,
) -> Result<T, ApiCallError>
where
    F: FnOnce(arkret_sdk::http_client::Client) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    if session_credential.trim().is_empty() {
        return Err(ApiCallError::AuthExpired(anyhow::anyhow!(
            "missing authenticated session"
        )));
    }
    ensure_self_path_auth_material_ready().await?;
    let transport = authenticated_transport(base_url, session_credential, None)
        .map_err(ApiCallError::Unavailable)?;
    match f(transport.http().clone()).await {
        Ok(value) => Ok(value),
        Err(err) => Err(classify_api_call_error(err).await),
    }
}

/// Authenticated domain endpoint-client exit. New account/directory call
/// sites use this typed boundary; remaining domains migrate here before the
/// `TransportClient` facade is deleted.
pub async fn with_endpoint_clients<F, Fut, T>(
    base_url: &str,
    session_credential: String,
    cursor: Option<String>,
    f: F,
) -> Result<T, ApiCallError>
where
    F: FnOnce(crate::transport::EndpointClients) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    if session_credential.trim().is_empty() {
        return Err(ApiCallError::AuthExpired(anyhow::anyhow!(
            "missing authenticated session"
        )));
    }
    ensure_self_path_auth_material_ready().await?;
    let transport = authenticated_transport(base_url, session_credential, cursor)
        .map_err(ApiCallError::Unavailable)?;
    match f(crate::transport::EndpointClients::new(transport)).await {
        Ok(value) => Ok(value),
        Err(err) => Err(classify_api_call_error(err).await),
    }
}

/// Same auth/refresh/classification contract as [`with_authed_api`], but hands
/// the closure a [`crate::event_submit::EventSubmitter`] built from the shared
/// SDK http-client. This is the TransportClient-free durable/ephemeral event
/// submission exit; migrated call sites call `sub.submit_sdk_event(&event)`
/// etc. directly.
pub async fn with_event_submitter<F, Fut, T>(
    base_url: &str,
    session_credential: String,
    f: F,
) -> Result<T, ApiCallError>
where
    F: FnOnce(crate::event_submit::EventSubmitter) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    with_authed_sdk_client(base_url, session_credential, |http| async move {
        f(crate::event_submit::EventSubmitter::new(http)).await
    })
    .await
}

fn authenticated_transport(
    base_url: &str,
    session_credential: String,
    cursor: Option<String>,
) -> anyhow::Result<crate::transport::TransportClient> {
    let mut context = crate::transport::RequestContext::new(session_credential);
    if let Some(cursor) = cursor {
        context = context.with_cursor(cursor);
    }
    let mut store = crate::state::LocalStateStore::default();
    match crate::identity::account_auth::grant_dpop::load_or_recover_device_key(&mut store)? {
        Some(handle) => context = context.with_dpop(handle),
        None if cfg!(target_arch = "wasm32") => {
            anyhow::bail!("missing DPoP device key for authenticated self request")
        }
        None => {}
    }
    crate::transport::TransportClient::new(base_url, context)
}

async fn classify_api_call_error(err: anyhow::Error) -> ApiCallError {
    if is_terminal_session_grant_error(&err) || is_auth_expired_error(&err) {
        ApiCallError::AuthExpired(err)
    } else {
        ApiCallError::Failed(err)
    }
}
