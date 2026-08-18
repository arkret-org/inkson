use serde::{Deserialize, Serialize};

mod api;
mod authority;
mod authorize;
mod callback;
pub mod grant_dpop;
mod handoff;
mod onboarding;
mod proof;
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
// Device-binding scope prefix (see coauth docs/zh/reference/scopes.md).
// Requesting `urn:arkret:client:device:{device_id}` at authorize time binds
// the OAuth session to our stable, persisted device id so coauth introspection
// returns a stable `org.arkret.device_id`. Without it, soland derives a
// per-OAuth-session device id (hash of session_id), which drifts on every
// re-authentication and invalidates the globally-shared sync cursor
// (`cursor_integrity_invalid` / "cursor device does not match request device").
const ARKRET_DEVICE_SCOPE_PREFIX: &str = "urn:arkret:client:device:";

#[derive(Clone, Debug, Deserialize)]
pub struct OidcDiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
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
    pub authorize_url: String,
    pub callback_uri: String,
    pub principal_audience: String,
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
    /// Principal Server trust domain, distinct from the Account Authority's
    /// own challenge transcript trust domain.
    #[serde(default)]
    pub principal_trust_domain: String,
}

/// The Account Authority entry point selected before leaving Inkson.
///
/// This value controls only the OIDC interaction hint. The authenticated
/// account and its durable binding/identity-creation state come exclusively
/// from the typed account handoff returned by the Account Authority; Inkson
/// must not constrain that result with a principal left in local browser state.
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
