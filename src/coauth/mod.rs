use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
    pub oidc_tokens: Option<OidcTokenResponse>,
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

/// Canonical OIDC token endpoint response shape. Used by
/// [`CoauthApi::exchange_pkce_code_for_tokens`] and
/// [`CoauthApi::refresh_oidc_tokens`]. Mirrors RFC 6749 §5.1 +
/// Wire shape of coauth's private session-grant refresh response.
/// OpenID Connect Core §3.1.3.3 - extra provider-specific fields
/// strand through `extras` so tokens minted by Auth0 / Keycloak / etc.
/// don't fail to deserialize on a one-off `provider_session_id` claim.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OidcTokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    /// Catches provider-specific extras (`audience`, `nonce`, …).
    #[serde(flatten)]
    pub extras: serde_json::Map<String, Value>,
}

impl OidcTokenResponse {
    /// Map into the persisted [`crate::local_state::OidcTokenBundle`].
    /// `audience` is sourced from the `audience` extra field if present
    /// or supplied by the caller (the principal-server URL the token is
    /// expected to authenticate against).
    pub fn to_persisted_bundle(
        &self,
        audience_hint: Option<&str>,
    ) -> crate::local_state::OidcTokenBundle {
        let now = chrono::Utc::now();
        let expires_at_unix = self.expires_in.map(|secs| now.timestamp() + secs);
        let audience = self
            .extras
            .get("audience")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .or_else(|| audience_hint.map(ToOwned::to_owned));
        crate::local_state::OidcTokenBundle {
            access_token: self.access_token.clone(),
            refresh_token: self.refresh_token.clone(),
            token_type: self
                .token_type
                .clone()
                .unwrap_or_else(|| "Bearer".to_owned()),
            expires_at_unix,
            id_token: self.id_token.clone(),
            scope: self.scope.clone(),
            audience,
            stored_at: now,
        }
    }
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
    /// Retained field name for back-compat; holds the resolved
    /// `gate_account_base` (the Account Authority origin all `gate/account`
    /// calls are routed to), not a private auth-server bridge base.
    pub auth_server_url: String,
    #[serde(default)]
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

/// Result of a hard-logout session-grant revocation at the Auth Server.
/// Distinguishes "the grant chain is provably gone" from "the call failed and
/// must be retried" so durable logout never clears its journal on a real error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionGrantRevokeOutcome {
    /// The grant was revoked (or was already gone): the rotation chain is dead.
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
