use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;

mod api;
mod authority;
mod authorize;
mod callback;
mod proof;
mod util;

#[cfg(test)]
mod tests;

pub use api::*;
pub use authority::*;
pub use authorize::*;
pub use callback::*;
pub use proof::*;
pub use util::*;

const YOUGEN_OIDC_REDIRECT_URI_NATIVE: &str = "urn:yougen:oauth:callback";
/// Fallback OIDC `client_id` when `auth_metadata.methods[].oidc.client_id` is
/// absent. Public (PKCE, no secret) client.
const YOUGEN_OIDC_CLIENT_ID: &str = "yougen";
// Device-binding scope prefix (see coauth docs/zh/reference/scopes.md).
// Requesting `urn:cokret:client:device:{device_id}` at authorize time binds
// the OAuth session to our stable, persisted device id so coauth introspection
// returns a stable `org.cokret.device_id`. Without it, soland derives a
// per-OAuth-session device id (hash of session_id), which drifts on every
// re-authentication and invalidates the globally-shared sync cursor
// (`cursor_integrity_invalid` / "cursor device does not match request device").
const COKRET_DEVICE_SCOPE_PREFIX: &str = "urn:cokret:client:device:";

#[derive(Clone, Debug)]
pub struct CoauthApi {
    base_url: Url,
    http: Client,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OidcDiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CoauthLoginOutcome {
    pub status: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub viewer: Option<CoauthViewerInfo>,
    #[serde(default)]
    pub session_grant: Option<CoauthSessionGrantInfo>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CoauthViewerInfo {
    pub id: String,
    pub handle: String,
    pub did: String,
    pub federated_handle: String,
    #[serde(default)]
    pub principal_id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CoauthSessionGrantInfo {
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    pub grant_jwt: String,
    pub session_public_key: String,
    #[serde(default)]
    pub session_private_key_pem: String,
    pub expires_at: String,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub principal_server: Option<CoauthPrincipalServerInfo>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CoauthPrincipalServerInfo {
    pub name: String,
    pub endpoint: String,
}

#[derive(Clone, Debug)]
pub struct OidcScaffoldBundle {
    pub client_id: String,
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub code_challenge: String,
    pub authorize_url: String,
    pub callback_uri: String,
    pub principal_audience: String,
    pub todo: &'static str,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedOidcScaffold {
    pub expected_state: String,
    #[serde(default)]
    pub expected_nonce: String,
    pub code_verifier: String,
    #[serde(default)]
    pub client_id: String,
    pub principal_server_url: String,
    #[serde(default)]
    pub principal_actor_id: String,
    #[serde(default)]
    pub device_id: String,
    pub principal_audience: String,
    pub callback_uri: String,
    pub authorize_url: String,
    /// T1.Y1 — the OIDC issuer the authorization code was obtained from. The
    /// Account Authority redeems the code at this issuer's `token_endpoint`.
    #[serde(default)]
    pub issuer: String,
    /// T1.Y4 — the resolved `gate_account_base` to POST `session-grants` to.
    #[serde(default)]
    pub gate_account_base: String,
}

#[cfg(target_arch = "wasm32")]
pub(crate) const OIDC_SCAFFOLD_STORAGE_KEY: &str = "yougen.oidc_scaffold.v1";

/// Result of running the single client-visible hard logout at the Account
/// Authority. Distinguishes "the server-side logout is terminal" from "the
/// call failed and must be retried" so durable logout never clears its journal
/// on a real error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountLogoutRunOutcome {
    /// The Account Authority reports logout completion, or the target session is already gone.
    Terminated,
}

/// Pull the top-level `error.code` out of a Cokret error envelope body
/// (`{ "ok": false, "error": { "code": ..., "message": ... } }`). Returns
/// `None` when the body is absent / not JSON / lacks the field, so callers
/// treat an undecodable error as a (retryable) failure rather than a known
/// terminal code.
pub(crate) fn error_envelope_code(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    value
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(|code| code.as_str())
        .map(str::to_owned)
}
