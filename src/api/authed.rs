//! Authenticated `CokretApi` construction + the view/engine-facing call
//! wrapper (`with_authed_api*` / [`ApiCallError`]).
//!
//! YGN-ARCH-01 step 1 (pure move from `views/helpers.rs`, zero behavior
//! change): this is the whole crate's HTTP exit for authenticated self-path
//! calls — consumed by `sync_engine`, `bootstrap`, `mls` admission and every
//! view — so it lives in the `api` layer, not under `views/`.

use super::{CokretApi, is_auth_expired_error, is_terminal_session_grant_error};

/// Create an authenticated API client from a base URL and optional session credential.
pub fn authed_api(base_url: &str, session_credential: String) -> anyhow::Result<CokretApi> {
    authed_api_with_sync(base_url, session_credential, None)
}

/// Create an authenticated API client that also forwards the latest sync token
/// for read-your-writes consistency on subsequent reads.
///
/// ②(A+②): `session_credential` is the `ck.session.grant` JWT.
/// The client also binds the grant-binding (DPoP) key so every `/_cokret/self/*`
/// request carries a per-request `DPoP` proof bound to the grant
/// (api-conventions.md §3.3). This is the centralized self-path credential
/// builder used across views.
pub fn authed_api_with_sync(
    base_url: &str,
    session_credential: String,
    wait_for_sync_token: Option<String>,
) -> anyhow::Result<CokretApi> {
    let mut api = CokretApi::new(base_url)?;
    if !session_credential.is_empty() {
        api = api.with_bearer(session_credential);
        #[cfg(target_arch = "wasm32")]
        {
            api = require_device_dpop(api)?;
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            api = attach_device_dpop(api);
        }
    } else {
        api = attach_device_dpop(api);
    }
    if let Some(sync_token) = wait_for_sync_token {
        api = api.with_wait_for(sync_token);
    }
    Ok(api)
}

/// ②(A+②) — best-effort attach the grant-binding (DPoP) key to a client so its
/// `/_cokret/self/*` requests are sender-constrained (api-conventions.md §3.3).
/// In production the seed is read from the secure key store (independent of the
/// passed state store); in tests no key is present and the client stays
/// without device proof material.
pub fn attach_device_dpop(api: CokretApi) -> CokretApi {
    match try_attach_device_dpop(api.clone()) {
        Ok(api) => api,
        Err(error) => {
            tracing::warn!(?error, "view API DPoP device-key attach skipped");
            api
        }
    }
}

fn try_attach_device_dpop(api: CokretApi) -> anyhow::Result<CokretApi> {
    let mut store = crate::local_state::LocalStateStore::default();
    let Some(handle) = crate::account_auth::grant_dpop::load_or_recover_device_key(&mut store)?
    else {
        return Ok(api);
    };
    Ok(api.with_dpop_device(handle))
}

#[cfg(target_arch = "wasm32")]
fn require_device_dpop(api: CokretApi) -> anyhow::Result<CokretApi> {
    let mut store = crate::local_state::LocalStateStore::default();
    let Some(handle) = crate::account_auth::grant_dpop::load_or_recover_device_key(&mut store)?
    else {
        anyhow::bail!("missing DPoP device key for authenticated self request");
    };
    Ok(api.with_dpop_device(handle))
}

async fn ensure_self_path_auth_material_ready() -> Result<(), ApiCallError> {
    #[cfg(target_arch = "wasm32")]
    {
        crate::secure_key_store::ensure_wasm_secure_key_store_ready("yougen")
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
/// * `Unavailable` — `CokretApi::new` rejected the base URL (bad scheme, parse error, etc.). The
///   session is intact; the user should fix the server URL.
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
    /// wire-code predicates (e.g. [`crate::api::is_device_not_authorized_error`])
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

/// Build an authenticated [`CokretApi`] and pass it to the closure,
/// folding `CokretApi::new` errors + auth-expired errors + generic
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
/// `crate::session`, because lower-level helpers cannot own app signals.
pub async fn with_authed_api<F, Fut, T>(
    base_url: &str,
    mut session_credential: String,
    f: F,
) -> Result<T, ApiCallError>
where
    F: FnOnce(CokretApi) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    if session_credential.trim().is_empty() {
        return Err(ApiCallError::AuthExpired(anyhow::anyhow!(
            "missing authenticated session"
        )));
    }
    if let Some(refreshed) = crate::session::wait_for_current_session_credential_refresh().await
        && !refreshed.trim().is_empty()
    {
        session_credential = refreshed;
    }
    ensure_self_path_auth_material_ready().await?;
    let api = authed_api(base_url, session_credential).map_err(ApiCallError::Unavailable)?;
    match f(api).await {
        Ok(value) => Ok(value),
        Err(err) => Err(classify_api_call_error(err).await),
    }
}

/// Same as [`with_authed_api`] but also forwards a sync-cursor token to
/// the resulting `CokretApi` so any subsequent read is fenced behind
/// the latest write (read-your-writes consistency). Pass the result of
/// [`active_sync_token`] as `wait_for_sync_token`.
pub async fn with_authed_api_with_sync<F, Fut, T>(
    base_url: &str,
    mut session_credential: String,
    wait_for_sync_token: Option<String>,
    f: F,
) -> Result<T, ApiCallError>
where
    F: FnOnce(CokretApi) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    if session_credential.trim().is_empty() {
        return Err(ApiCallError::AuthExpired(anyhow::anyhow!(
            "missing authenticated session"
        )));
    }
    if let Some(refreshed) = crate::session::wait_for_current_session_credential_refresh().await
        && !refreshed.trim().is_empty()
    {
        session_credential = refreshed;
    }
    ensure_self_path_auth_material_ready().await?;
    let api = authed_api_with_sync(base_url, session_credential, wait_for_sync_token)
        .map_err(ApiCallError::Unavailable)?;
    match f(api).await {
        Ok(value) => Ok(value),
        Err(err) => Err(classify_api_call_error(err).await),
    }
}

async fn classify_api_call_error(err: anyhow::Error) -> ApiCallError {
    if is_terminal_session_grant_error(&err) {
        crate::session::invalidate_current_session("session grant is no longer active");
        return ApiCallError::AuthExpired(err);
    }
    if is_auth_expired_error(&err) {
        // Run the single-flight refresh path so views that ignore the
        // returned error still converge on a fresh token before their next
        // poll. Only the refresh path's terminal result clears the session.
        match crate::session::refresh_current_session().await {
            crate::session::CurrentSessionRefresh::Credential(_) => {
                ApiCallError::Failed(anyhow::anyhow!("session refreshed; retry the operation"))
            }
            crate::session::CurrentSessionRefresh::SignInRequired { reason } => {
                ApiCallError::Failed(anyhow::anyhow!(
                    "session refresh cannot continue locally: {reason}; {err}"
                ))
            }
            crate::session::CurrentSessionRefresh::LoginRequired { reason } => {
                ApiCallError::AuthExpired(anyhow::anyhow!(
                    "session refresh requires login: {reason}; {err}"
                ))
            }
            crate::session::CurrentSessionRefresh::RetryLater { reason } => {
                ApiCallError::Failed(anyhow::anyhow!("session refresh pending: {reason}; {err}"))
            }
        }
    } else {
        ApiCallError::Failed(err)
    }
}
