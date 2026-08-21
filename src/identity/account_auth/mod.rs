use serde::{Deserialize, Serialize};

mod api;
mod authority;
mod authorize;
mod callback;
pub mod grant_dpop;
mod handoff;
mod onboarding;
mod proof;
pub mod transition;
mod util;

#[cfg(test)]
mod tests;

pub use api::fetch_oidc_discovery;
pub use authority::*;
pub use authorize::*;
pub use callback::*;
pub use handoff::*;
pub use onboarding::*;
pub use proof::*;
pub(crate) use util::*;

const INKSON_OIDC_REDIRECT_URI_NATIVE: &str = "urn:inkson:oauth:callback";
/// Fallback OIDC `client_id` when `auth_metadata.methods[].oidc.client_id` is
/// absent. Public (PKCE, no secret) client.
const INKSON_OIDC_CLIENT_ID: &str = "inkson";

#[derive(Clone, Debug, Deserialize)]
pub struct OidcDiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub scopes_supported: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct OidcScaffoldBundle {
    pub client_id: String,
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub authorize_url: String,
    pub callback_uri: String,
    pub principal_audience: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedOidcScaffold {
    pub expected_state: String,
    pub expected_nonce: String,
    pub code_verifier: String,
    pub client_id: String,
    pub principal_server_url: String,
    pub device_id: String,
    pub principal_audience: String,
    pub callback_uri: String,
    pub authorize_url: String,
    /// T1.Y1 — the OIDC issuer the authorization code was obtained from. The
    /// Account Authority redeems the code at this issuer's `token_endpoint`.
    pub issuer: String,
    /// T1.Y4 — the resolved `gate_account_base` to POST `session-grants` to.
    pub gate_account_base: String,
    /// Principal Server trust domain, distinct from the Account Authority's
    /// own challenge transcript trust domain.
    pub principal_trust_domain: String,
    /// Optional local returning-account candidate. It never selects the
    /// Account Authority account or the callback endpoint. The callback first
    /// obtains a server-authoritative handoff and compares this candidate only
    /// after that handoff reports `Bound`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_principal_full_id: Option<arkret_sdk::DidFullId>,
    /// Durable device belonging to [`Self::expected_principal_full_id`]. The
    /// OIDC transaction itself always uses [`Self::device_id`], a separate
    /// pending holder namespace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_device_id: Option<arkret_sdk::DeviceId>,
}

/// The Account Authority entry point selected before leaving Inkson.
///
/// This value controls only the OIDC interaction hint. Account-first creation
/// and recovery follow the typed handoff returned by the Account Authority.
/// A returning device may separately carry a local account candidate in
/// [`PersistedOidcScaffold`], but only a server-authored Bound handoff may
/// select the returning-session branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OidcEntryPoint {
    CreateIdentity,
    SignIn,
}

/// Only the wasm32 browser build persists the OIDC scaffold; a native build
/// compiles no reader, so the key namespace carries the same gate rather than
/// an allow that would also hide a real regression.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const OIDC_SCAFFOLD_STORAGE_KEY_PREFIX: &str = "inkson.oidc_scaffold.v1.";
