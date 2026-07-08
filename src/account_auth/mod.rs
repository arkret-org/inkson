use serde::{Deserialize, Serialize};

mod api;
mod authority;
mod authorize;
mod callback;
pub mod grant_dpop;
mod proof;
mod util;

#[cfg(test)]
mod tests;

pub use api::fetch_oidc_discovery;
pub use authority::*;
pub use authorize::*;
pub use callback::*;
pub use proof::*;
pub(crate) use util::*;

const INKSON_OIDC_REDIRECT_URI_NATIVE: &str = "urn:inkson:oauth:callback";
/// Fallback OIDC `client_id` when `auth_metadata.methods[].oidc.client_id` is
/// absent. Public (PKCE, no secret) client.
const INKSON_OIDC_CLIENT_ID: &str = "inkson";
// Device-binding scope prefix (see coauth docs/zh/reference/scopes.md).
// Requesting `urn:cokret:client:device:{device_id}` at authorize time binds
// the OAuth session to our stable, persisted device id so coauth introspection
// returns a stable `org.cokret.device_id`. Without it, soland derives a
// per-OAuth-session device id (hash of session_id), which drifts on every
// re-authentication and invalidates the globally-shared sync cursor
// (`cursor_integrity_invalid` / "cursor device does not match request device").
const COKRET_DEVICE_SCOPE_PREFIX: &str = "urn:cokret:client:device:";

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
pub(crate) const OIDC_SCAFFOLD_STORAGE_KEY: &str = "inkson.oidc_scaffold.v1";
