use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::api::ContrixApi;
use crate::config::validate_server_url;

const YOUGEN_OIDC_REDIRECT_URI_NATIVE: &str = "urn:yougen:oauth:callback";
// These three constants are **only**
// referenced by `build_authorize_url_preview` — the diagnostic /
// inspector function that renders an example authorize URL without
// running the real PKCE round trip. The production path
// (`build_authorize_url_with_session`, line ~825) uses
// `random_url_safe_token` for state + nonce and computes the code
// challenge with `pkce_code_challenge_s256(&random_code_verifier)`. The
// `_PREVIEW` suffix is intentional so a future code search for
// `TODO_STATE` / `TODO_NONCE` / `TODO_PKCE_CODE_CHALLENGE` does not
// confuse this with a real authorization gap.
const OIDC_STATE_PREVIEW: &str = "[preview-state]";
const OIDC_NONCE_PREVIEW: &str = "[preview-nonce]";
const OIDC_CODE_CHALLENGE_PREVIEW: &str = "[preview-code-challenge]";

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
pub struct CoauthLoginResponse {
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

#[derive(Clone, Debug, Deserialize)]
pub struct CoauthAuthBridgeDescribe {
    pub contract: String,
    pub version: String,
    pub api_base_path: String,
    pub oauth: CoauthAuthBridgeOAuthDescriptor,
    pub contrix: CoauthAuthBridgeContrixDescriptor,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CoauthAuthBridgeOAuthDescriptor {
    pub discovery_path: String,
    #[serde(default)]
    pub browser_bridge_session_path: String,
    #[serde(default)]
    pub exchange_describe_path: String,
    pub exchange_path: String,
    #[serde(default)]
    pub supported_flows: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CoauthIntegrationManifest {
    pub contract: String,
    pub version: String,
    pub service: String,
    pub service_kind: String,
    pub api_base_path: String,
    pub describe_path: String,
    #[serde(default)]
    pub dependencies: Vec<CoauthIntegrationDependency>,
    #[serde(default)]
    pub surfaces: Vec<CoauthIntegrationSurface>,
    #[serde(default)]
    pub examples: Value,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CoauthIntegrationDependency {
    pub service: String,
    pub purpose: String,
    pub required_contract: String,
    pub discovery_path: String,
    pub mode: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CoauthIntegrationSurface {
    pub name: String,
    pub method: String,
    pub path: String,
    pub contract: String,
    pub stability: String,
    pub todo: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CoauthAuthBridgeContrixDescriptor {
    pub login_path: String,
    pub logout_path: String,
    pub providers_path: String,
    pub session_grants_path: String,
    pub session_grants_introspect_path: String,
    pub session_grant_scope: String,
}

#[derive(Clone, Debug)]
pub struct CoauthTopologySnapshot {
    pub service_did: Option<String>,
    pub service_type: Option<String>,
    pub protocol_version: Option<String>,
    pub identity_service_did: Option<String>,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub oidc_clients: Vec<CoauthOidcClientHint>,
    pub oidc_browser_bridge_session_path: String,
    pub oidc_exchange_describe_path: String,
    pub oidc_exchange_path: String,
    pub auth_bridge_contract: String,
    pub auth_bridge_todos: Vec<String>,
    pub integration_manifest: CoauthIntegrationManifest,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CoauthOidcBrowserBridgeSession {
    pub contract: String,
    pub version: String,
    pub authorize_url: String,
    pub callback_uri: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub client_id: String,
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub principal_audience: String,
    pub todo: String,
}

/// Canonical OIDC token endpoint response shape. Used by
/// [`CoauthApi::exchange_pkce_code_for_tokens`] and
/// [`CoauthApi::refresh_oidc_tokens`]. Mirrors RFC 6749 §5.1 +
/// G3.Y0 — wire shape of `POST /api/v1/session-grants/refresh` (G3.C1).
/// Mirrors `coauth::handlers::contrix::RefreshSessionGrantResponse`. We
/// keep the fields as `String` so the cotest harness can assert
/// equality against the JSON body verbatim.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RefreshSessionGrantResponse {
    pub grant_id: String,
    pub grant_jwt: String,
    pub session_public_key: String,
    pub session_private_key_pem: String,
    pub expires_at: String,
    pub audience: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub dpop_jkt: String,
    pub previous_grant_id: String,
}

/// OpenID Connect Core §3.1.3.3 - extra provider-specific fields
/// flow through `extras` so tokens minted by Auth0 / Keycloak / etc.
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

#[derive(Clone, Debug, Deserialize)]
pub struct CoauthOidcExchangeDescribe {
    pub contract: String,
    pub version: String,
    pub exchange_path: String,
    pub upstream_boundary_mode: String,
    #[serde(default)]
    pub upstream_modes_supported: Vec<String>,
    #[serde(default)]
    pub required_fields: Vec<String>,
    #[serde(default)]
    pub validation_layers: Vec<String>,
    #[serde(default)]
    pub failure_codes: Vec<String>,
    #[serde(default)]
    pub example_request: Value,
    #[serde(default)]
    pub todos: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CoauthOidcClientHint {
    #[serde(default)]
    pub id: String,
    pub client_id: String,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SolandSessionGrantPlan {
    pub principal_server_url: String,
    pub principal_audience: String,
    pub actor_did: String,
    pub device_id: String,
    pub authorize_url_preview: String,
    pub token_endpoint: Option<String>,
    pub integration_manifest_summary: String,
    pub todo: &'static str,
}

#[derive(Clone, Debug)]
pub struct ChimePushGrantPlan {
    pub principal_server_url: String,
    pub principal_audience: String,
    pub device_id: String,
    pub register_request_preview: String,
    pub todo: &'static str,
}

#[derive(Clone, Debug)]
pub struct OidcCodeExchangePlan {
    pub principal_server_url: String,
    pub principal_audience: String,
    pub actor_did: String,
    pub device_id: String,
    pub client_id: String,
    pub authorize_url_preview: String,
    pub token_endpoint: String,
    pub exchange_request_preview: String,
    pub integration_manifest_summary: String,
    pub todo: &'static str,
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
    pub auth_server_url: String,
    #[serde(default)]
    pub principal_server_url: String,
    #[serde(default)]
    pub principal_actor_did: String,
    #[serde(default)]
    pub device_id: String,
    pub principal_audience: String,
    pub callback_uri: String,
    pub authorize_url: String,
}

#[cfg(target_arch = "wasm32")]
const OIDC_SCAFFOLD_STORAGE_KEY: &str = "yougen.oidc_scaffold.v1";

impl CoauthApi {
    pub fn new(base_url: &str) -> anyhow::Result<Self> {
        Ok(Self {
            base_url: validate_server_url(base_url)?,
            http: Client::new(),
        })
    }

    pub async fn inspect_topology(&self) -> anyhow::Result<CoauthTopologySnapshot> {
        let server = self
            .get_json::<Value>("api/v1/server/describe")
            .await
            .context("coauth server describe failed")?;
        let identity = self
            .get_json::<Value>("api/v1/identity/describe")
            .await
            .context("coauth identity describe failed")?;
        let discovery = self
            .get_json::<OidcDiscoveryDocument>(".well-known/openid-configuration")
            .await
            .context("coauth OIDC discovery failed")?;
        let bridge = self
            .get_json::<CoauthAuthBridgeDescribe>("api/v1/auth/bridge/describe")
            .await
            .context("coauth auth bridge describe failed")?;
        let integration_manifest = self
            .get_json::<CoauthIntegrationManifest>("api/v1/integration/describe")
            .await
            .context("coauth integration describe failed")?;

        Ok(CoauthTopologySnapshot {
            service_did: value_string(&server, "service_did"),
            service_type: value_string(&server, "service_type"),
            protocol_version: value_string(&server, "protocol_version"),
            identity_service_did: value_string(&identity, "service_did")
                .or_else(|| value_string(&identity, "issuer_did")),
            issuer: discovery.issuer,
            authorization_endpoint: discovery.authorization_endpoint,
            token_endpoint: discovery.token_endpoint,
            userinfo_endpoint: discovery.userinfo_endpoint,
            code_challenge_methods_supported: discovery.code_challenge_methods_supported,
            scopes_supported: discovery.scopes_supported,
            oidc_clients: server
                .get("auth_metadata")
                .and_then(|value| value.get("oidc_clients"))
                .cloned()
                .map(serde_json::from_value)
                .transpose()?
                .unwrap_or_default(),
            oidc_browser_bridge_session_path: bridge.oauth.browser_bridge_session_path,
            oidc_exchange_describe_path: bridge.oauth.exchange_describe_path,
            oidc_exchange_path: bridge.oauth.exchange_path,
            auth_bridge_contract: bridge.contract,
            auth_bridge_todos: bridge.todos,
            integration_manifest,
        })
    }

    pub async fn auth_bridge_describe(&self) -> anyhow::Result<CoauthAuthBridgeDescribe> {
        self.get_json("api/v1/auth/bridge/describe").await
    }

    pub async fn describe_oidc_exchange(
        &self,
        exchange_describe_path: &str,
    ) -> anyhow::Result<CoauthOidcExchangeDescribe> {
        self.get_json(exchange_describe_path).await
    }

    pub async fn integration_describe(&self) -> anyhow::Result<CoauthIntegrationManifest> {
        self.get_json("api/v1/integration/describe").await
    }

    /// List invite-quarantine entries from coauth's admin endpoint. Admins
    /// receive every quarantined invite in the deployment; non-admin tokens
    /// 403 - the caller surfaces an inline "limited to your own invites"
    /// hint and falls back to [`Self::invite_quarantine_self`].
    pub async fn invite_quarantine_list(&self) -> anyhow::Result<Value> {
        self.get_json("api/admin/v1/invite-quarantine").await
    }

    /// Per-user view of the caller's quarantined invites - surfaced for
    /// non-admin members so they can see what's gated on review without
    /// admin access. Backed by the same coauth admin endpoint via a
    /// self-scope query string.
    pub async fn invite_quarantine_self(&self) -> anyhow::Result<Value> {
        self.get_json("api/v1/invite-quarantine/self").await
    }

    /// Admin decision on a quarantined invite. `decision` is `"approve"`
    /// or `"reject"`; `reason` is required for reject and recommended for
    /// approve so the audit trail captures why the invite was unblocked.
    /// Returns soland's updated quarantine record.
    pub async fn invite_quarantine_resolve(
        &self,
        invite_id: &str,
        decision: &str,
        reason: Option<&str>,
    ) -> anyhow::Result<Value> {
        let mut body = serde_json::json!({"decision": decision});
        if let Some(reason) = reason {
            body["reason"] = serde_json::Value::String(reason.to_owned());
        }
        self.post_json(
            &format!("api/admin/v1/invite-quarantine/{invite_id}/resolve"),
            body,
        )
        .await
    }

    pub async fn exchange_oidc_code(
        &self,
        exchange_path: &str,
        authorization_code: &str,
        code_verifier: &str,
        redirect_uri: &str,
        issuer: &str,
        token_endpoint: &str,
        userinfo_endpoint: &str,
        client_id: &str,
        login_hint: &str,
        device_id: &str,
        principal_audience: Option<&str>,
        state: Option<&str>,
        expected_state: Option<&str>,
        expected_nonce: Option<&str>,
    ) -> anyhow::Result<CoauthLoginResponse> {
        self.post_json(
            exchange_path,
            json!({
                "authorization_code": authorization_code,
                "code_verifier": code_verifier,
                "redirect_uri": redirect_uri,
                "issuer": issuer,
                "token_endpoint": token_endpoint,
                "userinfo_endpoint": userinfo_endpoint,
                "client_id": client_id,
                "login_hint": login_hint,
                "device_id": device_id,
                "principal_audience": principal_audience,
                "state": state,
                "expected_state": expected_state,
                "expected_nonce": expected_nonce,
            }),
        )
        .await
    }

    /// Real OIDC token-endpoint exchange. Drives the PKCE authorization-code
    /// flow directly against the configured OIDC provider's `token_endpoint` -
    /// no coauth bridge in between. Returns the parsed [`OidcTokenResponse`]
    /// with access + refresh tokens + scope + id_token + expires_in.
    ///
    /// Spec refs: RFC 6749 §4.1.3 (token request), RFC 7636 §4.5
    /// (PKCE verifier delivery), OpenID Connect Core §3.1.3 (response
    /// parsing). The caller owns the redirect URI handling — usually
    /// the browser's `/auth/callback` page extracts `?code=` then
    /// invokes this function with the matching PKCE verifier.
    pub async fn exchange_pkce_code_for_tokens(
        &self,
        token_endpoint: &str,
        client_id: &str,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> anyhow::Result<OidcTokenResponse> {
        let endpoint = Url::parse(token_endpoint)
            .with_context(|| format!("invalid token endpoint: {token_endpoint}"))?;
        // Token-endpoint requests use application/x-www-form-urlencoded
        // per RFC 6749 §3.2 — JSON would be silently rejected by some
        // providers (Okta, Azure AD) even when other endpoints accept JSON.
        let form_params: [(&str, &str); 5] = [
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", code_verifier),
        ];
        let response = self
            .http
            .post(endpoint)
            .form(&form_params)
            .send()
            .await
            .context("token endpoint POST failed")?;
        let status = response.status();
        let body = response.text().await.context("read token response body")?;
        if !status.is_success() {
            anyhow::bail!(
                "token endpoint returned {status}: {body}",
                status = status,
                body = body.chars().take(512).collect::<String>(),
            );
        }
        // Parse as OAuth2 / OIDC token response. Tolerate extra fields
        // (Auth0 / Keycloak / etc. add provider-specific keys).
        serde_json::from_str(&body).context("parse OIDC token response")
    }

    /// Refresh-token grant against the upstream OIDC provider. Returns a
    /// fresh [`OidcTokenResponse`]; the new `refresh_token` MAY be present
    /// (rotating refresh tokens) or MAY be absent (the previous one stays
    /// valid).
    pub async fn refresh_oidc_tokens(
        &self,
        token_endpoint: &str,
        client_id: &str,
        refresh_token: &str,
    ) -> anyhow::Result<OidcTokenResponse> {
        let endpoint = Url::parse(token_endpoint)
            .with_context(|| format!("invalid token endpoint: {token_endpoint}"))?;
        let form_params: [(&str, &str); 3] = [
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("refresh_token", refresh_token),
        ];
        let response = self
            .http
            .post(endpoint)
            .form(&form_params)
            .send()
            .await
            .context("refresh token endpoint POST failed")?;
        let status = response.status();
        let body = response
            .text()
            .await
            .context("read refresh response body")?;
        if !status.is_success() {
            anyhow::bail!(
                "refresh endpoint returned {status}: {body}",
                status = status,
                body = body.chars().take(512).collect::<String>(),
            );
        }
        serde_json::from_str(&body).context("parse OIDC refresh response")
    }

    /// G3.Y0 — POST coauth's self-serve `passkey/register/start`
    /// ceremony. Returns the `CreationChallengeResponse` JSON the
    /// browser feeds into `navigator.credentials.create({ publicKey: ... })`.
    pub async fn passkey_register_start(
        &self,
        passkey_register_start_path: &str,
        handle: Option<&str>,
        display_name: Option<&str>,
    ) -> anyhow::Result<serde_json::Value> {
        self.post_json(
            passkey_register_start_path,
            json!({
                "handle": handle,
                "display_name": display_name,
            }),
        )
        .await
    }

    /// G3.Y0 — POST coauth's `passkey/register/finish` ceremony with
    /// the attestation produced by the browser authenticator. Returns
    /// the persisted credential id (base64url) on success.
    ///
    /// The response is typed as JSON because deployments can return
    /// either a credential-only admin result or a self-serve login
    /// result that also includes bearer/session material. The login UI
    /// ships the OIDC browser path locally and leaves passkeys to the
    /// coauth/IdP sign-in page.
    pub async fn passkey_register_finish(
        &self,
        passkey_register_finish_path: &str,
        attestation: serde_json::Value,
        label: Option<&str>,
    ) -> anyhow::Result<serde_json::Value> {
        self.post_json(
            passkey_register_finish_path,
            json!({
                "attestation": attestation,
                "label": label,
            }),
        )
        .await
    }

    /// G3.Y0 — POST coauth's `passkey/auth/start` ceremony. Returns
    /// the `RequestChallengeResponse` JSON the browser feeds into
    /// `navigator.credentials.get({ publicKey: ... })`.
    pub async fn passkey_auth_start(
        &self,
        passkey_auth_start_path: &str,
        login_hint: Option<&str>,
    ) -> anyhow::Result<serde_json::Value> {
        self.post_json(
            passkey_auth_start_path,
            json!({
                "login_hint": login_hint,
            }),
        )
        .await
    }

    /// G3.Y0 — POST coauth's `passkey/auth/finish` ceremony with the
    /// assertion produced by the browser. Returns the credential id
    /// on success.
    ///
    /// The response is typed as JSON for the same reason as
    /// `passkey_register_finish`: some deployments return only the
    /// credential id, while the local shipped sign-in path receives
    /// tokens through the OIDC browser exchange.
    pub async fn passkey_auth_finish(
        &self,
        passkey_auth_finish_path: &str,
        assertion: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        self.post_json(
            passkey_auth_finish_path,
            json!({
                "assertion": assertion,
            }),
        )
        .await
    }

    /// G3.Y0 + G3.C1 — call coauth's `POST /api/v1/session-grants/refresh`
    /// with a DPoP proof and the prior grant JWT. On success returns
    /// the rotated grant (single-use semantics: the old grant is now
    /// revoked).
    ///
    /// The DPoP proof MUST be minted against `htu` = absolute URL of
    /// the refresh endpoint and `htm` = `"POST"`, signed by the same
    /// key whose thumbprint is bound to the prior grant's `cnf.jkt`.
    pub async fn refresh_session_grant(
        &self,
        grant_jwt: &str,
        audience: Option<&str>,
        dpop_proof: &str,
    ) -> anyhow::Result<RefreshSessionGrantResponse> {
        let endpoint = self.endpoint("api/v1/session-grants/refresh")?;
        let body = json!({
            "grant_jwt": grant_jwt,
            "audience": audience,
        });
        let response = self
            .http
            .post(endpoint)
            .header("DPoP", dpop_proof)
            .json(&body)
            .send()
            .await
            .context("session-grant refresh POST failed")?;
        let status = response.status();
        let text = response
            .text()
            .await
            .context("read session-grant refresh body")?;
        if !status.is_success() {
            anyhow::bail!(
                "session-grant refresh returned {status}: {body}",
                status = status,
                body = text.chars().take(512).collect::<String>(),
            );
        }
        serde_json::from_str(&text).context("parse session-grant refresh response")
    }

    pub async fn start_oidc_browser_bridge(
        &self,
        session_path: &str,
        redirect_uri: &str,
        login_hint: &str,
        device_id: &str,
        principal_audience: Option<&str>,
        client_id_hint: Option<&str>,
    ) -> anyhow::Result<CoauthOidcBrowserBridgeSession> {
        self.post_json(
            session_path,
            json!({
                "redirect_uri": redirect_uri,
                "login_hint": login_hint,
                "device_id": device_id,
                "principal_audience": principal_audience,
                "client_id_hint": client_id_hint,
            }),
        )
        .await
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        Ok(self
            .http
            .get(self.endpoint(path)?)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    async fn post_json<T: DeserializeOwned>(&self, path: &str, body: Value) -> anyhow::Result<T> {
        Ok(self
            .http
            .post(self.endpoint(path)?)
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    fn endpoint(&self, path: &str) -> anyhow::Result<Url> {
        Ok(self.base_url.join(path.trim_start_matches('/'))?)
    }
}

/// R3.2 (YG-HC-1) — best-effort deep link to the issuer/coauth handle
/// issuance flow (`/handles/me`). yougen does NOT manage handle lifecycle
/// (per spec §3.2.3 / §3.4): `cx.profile.update` /
/// `cx.member.identity.update` MUST NOT set or override handles. Instead
/// the settings UI surfaces "Handle managed by your organization" with a
/// link out to the issuer flow, where the org-run issuer signs
/// `cx.schema.handle_claim.v1` evidence.
///
/// We derive the link from the principal/auth base URL synchronously
/// (origin + `/handles/me`); deployments that publish a distinct coauth
/// origin via `auth_metadata.auth_server_url` should resolve that first
/// (see [`resolve_principal_auth_server_url`]). Returns `None` for an
/// unparseable base URL.
pub fn issuer_handle_management_url(base_url: &str) -> Option<String> {
    let parsed = Url::parse(base_url.trim()).ok()?;
    let origin = parsed.origin();
    if origin.is_tuple() {
        Some(format!("{}/handles/me", origin.ascii_serialization()))
    } else {
        None
    }
}

pub async fn resolve_principal_auth_server_url(
    principal_server_url: &str,
) -> anyhow::Result<String> {
    Ok(resolve_principal_auth_server(principal_server_url)
        .await?
        .auth_server_url)
}

#[derive(Clone, Debug)]
pub(crate) struct PrincipalAuthServerResolution {
    pub auth_server_url: String,
    pub service_did: String,
}

pub(crate) async fn resolve_principal_auth_server(
    principal_server_url: &str,
) -> anyhow::Result<PrincipalAuthServerResolution> {
    let principal = ContrixApi::new(principal_server_url)?;
    let description = principal.describe().await?;
    let auth_server_url = description
        .auth_metadata
        .get("auth_server_url")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("principal server did not publish auth_metadata.auth_server_url")
        })?;
    Ok(validate_server_url(auth_server_url)?.to_string()).map(|auth_server_url| {
        PrincipalAuthServerResolution {
            auth_server_url,
            service_did: description.service_did.to_string(),
        }
    })
}

pub fn active_oidc_redirect_uri() -> String {
    current_oidc_redirect_uri()
}

pub fn summarize_coauth_integration_manifest(manifest: &CoauthIntegrationManifest) -> String {
    let dependencies = if manifest.dependencies.is_empty() {
        "none".to_owned()
    } else {
        manifest
            .dependencies
            .iter()
            .map(|dependency| {
                format!(
                    "{}:{}@{}",
                    dependency.service, dependency.purpose, dependency.discovery_path
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let surfaces = if manifest.surfaces.is_empty() {
        "none".to_owned()
    } else {
        manifest
            .surfaces
            .iter()
            .map(|surface| {
                format!(
                    "{} {} {} [{}]",
                    surface.method, surface.path, surface.contract, surface.stability
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let todos = if manifest.todos.is_empty() {
        "none".to_owned()
    } else {
        manifest.todos.join(" ")
    };

    format!(
        "service={} kind={} contract={} version={}\ndependencies={}\nsurfaces:\n{}\ntodos={}",
        manifest.service,
        manifest.service_kind,
        manifest.contract,
        manifest.version,
        dependencies,
        surfaces,
        todos,
    )
}

pub fn build_soland_session_grant_plan(
    topology: &CoauthTopologySnapshot,
    principal_server_url: &str,
    actor_did: &str,
    device_id: &str,
) -> anyhow::Result<SolandSessionGrantPlan> {
    let principal_server_url = validate_server_url(principal_server_url)?.to_string();
    let principal_audience = principal_audience(principal_server_url.as_str())?;
    let authorize_url_preview =
        build_authorize_url_preview(topology, actor_did, principal_audience.as_str())?;

    Ok(SolandSessionGrantPlan {
        principal_server_url,
        principal_audience,
        actor_did: actor_did.to_owned(),
        device_id: device_id.to_owned(),
        authorize_url_preview,
        token_endpoint: topology.token_endpoint.clone(),
        integration_manifest_summary: summarize_coauth_integration_manifest(
            &topology.integration_manifest,
        ),
        todo: "Closed: LoginPanel::finish_oidc_callback exchanges the authorization code, validates the principal/device binding, and swaps the resulting OIDC or session-grant bearer into the active principal session.",
    })
}

pub fn build_chime_push_grant_plan(
    principal_server_url: &str,
    device_id: &str,
) -> anyhow::Result<ChimePushGrantPlan> {
    let principal_server_url = validate_server_url(principal_server_url)?.to_string();
    let principal_audience = principal_audience(principal_server_url.as_str())?;
    let register_request = crate::push::build_register_request(device_id)?;

    Ok(ChimePushGrantPlan {
        principal_server_url,
        principal_audience,
        device_id: device_id.to_owned(),
        register_request_preview: serde_json::to_string_pretty(&register_request)?,
        todo: "Closed: push token providers now supply WebPush/FCM/APNs material and register_via_chime attaches the persisted coauth session grant plus introspection proof headers.",
    })
}

pub fn build_oidc_code_exchange_plan(
    topology: &CoauthTopologySnapshot,
    principal_server_url: &str,
    actor_did: &str,
    device_id: &str,
) -> anyhow::Result<OidcCodeExchangePlan> {
    let principal_server_url = validate_server_url(principal_server_url)?.to_string();
    let principal_audience = principal_audience(principal_server_url.as_str())?;
    let redirect_uri = current_oidc_redirect_uri();
    let client_id = resolve_oidc_client_id(topology, redirect_uri.as_str())?;
    let authorize_url_preview =
        build_authorize_url_preview(topology, actor_did, principal_audience.as_str())?;
    let token_endpoint = topology
        .token_endpoint
        .clone()
        .unwrap_or_else(|| "missing".to_owned());
    let userinfo_endpoint = topology
        .userinfo_endpoint
        .clone()
        .unwrap_or_else(|| "missing".to_owned());
    let exchange_request_preview = serde_json::to_string_pretty(&json!({
        "grant_type": "authorization_code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "issuer": topology.issuer,
        "token_endpoint": token_endpoint,
        "userinfo_endpoint": userinfo_endpoint,
        "resource": principal_audience,
        "code": "<authorization_code_from_callback>",
        "code_verifier": "<persisted_pkce_code_verifier>",
        "login_hint": actor_did,
        "device_id": device_id,
    }))?;

    Ok(OidcCodeExchangePlan {
        principal_server_url,
        principal_audience,
        actor_did: actor_did.to_owned(),
        device_id: device_id.to_owned(),
        client_id,
        authorize_url_preview,
        token_endpoint,
        exchange_request_preview,
        integration_manifest_summary: summarize_coauth_integration_manifest(
            &topology.integration_manifest,
        ),
        todo: "Closed: the server sign-in button opens coauth's authorize URL, persists PKCE verifier state, auto-captures the callback URL, exchanges the returned code, and stores the resulting OIDC/session-grant credentials locally.",
    })
}

pub fn build_oidc_scaffold_bundle(
    topology: &CoauthTopologySnapshot,
    principal_server_url: &str,
    actor_did: &str,
    device_id: &str,
) -> anyhow::Result<OidcScaffoldBundle> {
    let principal_server_url = validate_server_url(principal_server_url)?.to_string();
    // Validation only — keep the previous side effect of bailing on a bad
    // principal server URL before we generate PKCE state.
    let _ = principal_server_url;
    let principal_audience = principal_audience(principal_server_url.as_str())?;
    let callback_uri = current_oidc_redirect_uri();
    let client_id = resolve_oidc_client_id(topology, callback_uri.as_str())?;
    // RFC 6749 §10.12 / RFC 7636: state, nonce, and PKCE verifier MUST be
    // unguessable per-flow values. The previous scaffold used deterministic
    // strings derived from (actor_did, device_id), which would let an
    // attacker who learned the DID + device id forge a matching callback
    // payload. Replace with cryptographically random tokens and the spec
    // S256 challenge transformation.
    let state = random_url_safe_token(STATE_NONCE_TOKEN_BYTES)?;
    let nonce = random_url_safe_token(STATE_NONCE_TOKEN_BYTES)?;
    let code_verifier = random_url_safe_token(PKCE_VERIFIER_BYTES)?;
    let _ = (actor_did, device_id); // no longer factored into PKCE state
    let pkce_method = preferred_pkce_method(&topology.code_challenge_methods_supported);
    let code_challenge = match pkce_method {
        Some("plain") => code_verifier.clone(),
        // S256 is the spec-default + only other value we negotiate, so
        // when the topology is silent we still emit an S256 challenge —
        // the authorize URL builder simply omits it for non-PKCE flows.
        _ => pkce_code_challenge_s256(&code_verifier),
    };
    let authorize_url = build_authorize_url(
        topology,
        client_id.as_str(),
        callback_uri.as_str(),
        actor_did,
        principal_audience.as_str(),
        &state,
        &nonce,
        &code_challenge,
    )?;

    Ok(OidcScaffoldBundle {
        client_id,
        state,
        nonce,
        code_verifier,
        code_challenge,
        authorize_url,
        callback_uri,
        principal_audience,
        todo: "Closed: LoginPanel auto-captures the returned authorization code and exchanges it with the persisted PKCE verifier; state, nonce, and S256 challenge are generated from cryptographic RNG.",
    })
}

pub fn oidc_scaffold_bundle_from_bridge_session(
    session: &CoauthOidcBrowserBridgeSession,
) -> OidcScaffoldBundle {
    OidcScaffoldBundle {
        client_id: session.client_id.clone(),
        state: session.state.clone(),
        nonce: session.nonce.clone(),
        code_verifier: session.code_verifier.clone(),
        code_challenge: session.code_challenge.clone(),
        authorize_url: session.authorize_url.clone(),
        callback_uri: session.callback_uri.clone(),
        principal_audience: session.principal_audience.clone(),
        todo: "Closed: browser-bridge sessions supply concrete state/nonce/challenge/verifier material and the login callback path completes the exchange automatically.",
    }
}

pub fn authorize_url_with_forced_reauthentication(authorize_url: &str) -> anyhow::Result<String> {
    let mut url = Url::parse(authorize_url)
        .with_context(|| format!("invalid authorize URL: {authorize_url}"))?;
    let mut query: Vec<(String, String)> = url.query_pairs().into_owned().collect();
    let mut saw_prompt = false;
    let mut saw_max_age = false;

    for (key, value) in &mut query {
        if key == "prompt" {
            saw_prompt = true;
            let mut prompts: Vec<String> = value
                .split_ascii_whitespace()
                .filter(|prompt| *prompt != "none")
                .map(str::to_owned)
                .collect();
            if !prompts.iter().any(|prompt| prompt == "login") {
                prompts.push("login".to_owned());
            }
            *value = prompts.join(" ");
        } else if key == "max_age" {
            saw_max_age = true;
            *value = "0".to_owned();
        }
    }

    if !saw_prompt {
        query.push(("prompt".to_owned(), "login".to_owned()));
    }
    if !saw_max_age {
        query.push(("max_age".to_owned(), "0".to_owned()));
    }

    url.set_query(None);
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in query {
            pairs.append_pair(&key, &value);
        }
    }
    Ok(url.to_string())
}

/// Session-grant introspection proof claims. Mirrors
/// coauth's `SessionGrantIntrospectionProofClaims` (see
/// `coauth/crates/backend/src/handlers/contrix.rs:575`). soland forwards
/// the proof to coauth's `/api/v1/session-grants/introspect` endpoint
/// when calling `validate_session_grant_binding` — the JWS MUST verify
/// against the session_public_key registered with the grant, and the
/// claims MUST match `grant_id` / `grant_jwt_hash` / `audience` /
/// `challenge` / `issued_at` / `expires_at` exactly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionGrantIntrospectionProofClaims {
    /// Always `"cx.session_grant.introspection_proof.v1"`.
    #[serde(rename = "type")]
    pub kind: String,
    pub grant_id: String,
    /// `"sha256:<hex>"` of the grant JWT bytes.
    pub grant_jwt_hash: String,
    /// MUST match `grant.audience` (typically the principal-server URL).
    pub audience: String,
    /// Random per-introspection challenge string supplied by the caller.
    pub challenge: String,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Convenience helper: build the full
/// [`crate::api::SessionGrantIntrospectionProof`] (challenge + proof_jwt
/// bundle) ready to attach to a soland `session-grant/exchange` request.
/// The challenge is freshly minted from `current_time + grant_id`.
pub fn build_session_grant_introspection_proof_bundle(
    grant_id: &str,
    grant_jwt: &str,
    audience: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<crate::api::SessionGrantIntrospectionProof> {
    let challenge = format!(
        "{ts}-{grant_id}",
        ts = chrono::Utc::now().timestamp_millis()
    );
    let proof_jwt = build_session_grant_introspection_proof(
        grant_id,
        grant_jwt,
        audience,
        &challenge,
        signing_key,
    )?;
    Ok(crate::api::SessionGrantIntrospectionProof {
        challenge,
        proof_jwt,
    })
}

/// Decode the ephemeral private key returned with a coauth
/// `principal_session` grant. This key, not the long-lived local device key,
/// signs the one-use introspection proof soland forwards back to coauth.
pub fn session_grant_signing_key_from_pem(pem: &str) -> anyhow::Result<ed25519_dalek::SigningKey> {
    use ed25519_dalek::pkcs8::DecodePrivateKey as _;

    ed25519_dalek::SigningKey::from_pkcs8_pem(pem.trim())
        .context("decode coauth session grant private key")
}

/// Build a session-grant introspection proof JWS. Signs the canonical
/// claims with the ephemeral session-grant private key whose public half
/// is stored by coauth as `session_public_key`.
///
/// The `challenge` is freshly constructed by the caller, typically
/// `format!("{ts}-{grant_id}")` where `ts` is the current Unix time.
/// The `expires_at` window is fixed at 60s - matches coauth's reference
/// implementation (`Duration::try_minutes(1)`).
///
/// Returns the JWS in compact serialization (`<header>.<payload>.<sig>`).
/// Embed the result in a [`SessionGrantIntrospectionProof`] and post it
/// to the soland endpoint that requires session-grant verification.
pub fn build_session_grant_introspection_proof(
    grant_id: &str,
    grant_jwt: &str,
    audience: &str,
    challenge: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<String> {
    if grant_id.trim().is_empty() {
        anyhow::bail!("grant_id is required");
    }
    if grant_jwt.trim().is_empty() {
        anyhow::bail!("grant_jwt is required");
    }
    if audience.trim().is_empty() {
        anyhow::bail!("audience is required");
    }
    if challenge.trim().is_empty() {
        anyhow::bail!("challenge is required");
    }
    let now = chrono::Utc::now();
    let claims = SessionGrantIntrospectionProofClaims {
        kind: "cx.session_grant.introspection_proof.v1".to_owned(),
        grant_id: grant_id.to_owned(),
        grant_jwt_hash: session_grant_jwt_hash(grant_jwt),
        audience: audience.to_owned(),
        challenge: challenge.to_owned(),
        issued_at: now,
        expires_at: now + chrono::Duration::seconds(60),
    };
    sign_compact_jws_eddsa(&claims, signing_key)
}

/// Hash the grant JWT bytes per coauth's `session_grant_jwt_hash`
/// (`"sha256:" + hex(sha256(grant_jwt))`). Public so callers can verify
/// their proof binding before sending.
pub fn session_grant_jwt_hash(grant_jwt: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(grant_jwt.as_bytes()))
}

/// Internal helper: serialize claims to canonical JSON, base64url-encode
/// header + payload, sign with Ed25519, return the compact JWS.
fn sign_compact_jws_eddsa<C: Serialize>(
    claims: &C,
    signing_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<String> {
    use ed25519_dalek::Signer;
    // Compact JWS header (`alg=EdDSA`). The optional `typ=JWT` claim
    // tells generic JWT verifiers this is a JWT proof token; coauth's
    // verifier doesn't require it but adding it improves cross-provider
    // tooling round-trips.
    let header_json = br#"{"alg":"EdDSA","typ":"JWT"}"#;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    let payload_json = serde_json::to_vec(claims)?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes()).to_bytes();
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature);
    Ok(format!("{header_b64}.{payload_b64}.{sig_b64}"))
}

/// Launch the authorize URL in the user's browser / webview. On wasm this
/// navigates the current window - the matching `/auth/callback` handler on
/// the same origin reads `?code=` and invokes
/// [`CoauthApi::exchange_pkce_code_for_tokens`]. On native desktop builds
/// this best-effort opens the system browser via the `cmd /c start`
/// (Windows) / `xdg-open` (Linux) / `open` (macOS) shell out - production
/// deploys SHOULD swap in a webview crate so the callback URL can be
/// intercepted in-process.
pub fn open_oidc_authorize_url(authorize_url: &str) -> anyhow::Result<()> {
    open_authorize_url_impl(authorize_url)
}

#[cfg(target_arch = "wasm32")]
fn open_authorize_url_impl(authorize_url: &str) -> anyhow::Result<()> {
    let window =
        web_sys::window().ok_or_else(|| anyhow::anyhow!("browser window is not available"))?;
    window
        .location()
        .assign(authorize_url)
        .map_err(|err| anyhow::anyhow!("location.assign failed: {err:?}"))?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::needless_return)] // `return` required: target-cfg blocks below are not always present.
fn open_authorize_url_impl(authorize_url: &str) -> anyhow::Result<()> {
    // Validate the URL up front so we never feed an unparsed string to
    // the system shell (defence in depth — the caller should already
    // have validated, but a stray `;` in a hand-edited URL would
    // otherwise compose into a shell injection on Windows `cmd`).
    let parsed = Url::parse(authorize_url)
        .with_context(|| format!("invalid authorize URL: {authorize_url}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        anyhow::bail!("refusing to open non-http(s) authorize URL: {authorize_url}");
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", authorize_url])
            .spawn()
            .with_context(|| "failed to spawn `cmd /C start` for OIDC authorize URL")?;
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(authorize_url)
            .spawn()
            .with_context(|| "failed to spawn `open` for OIDC authorize URL")?;
        return Ok(());
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(authorize_url)
            .spawn()
            .with_context(|| "failed to spawn `xdg-open` for OIDC authorize URL")?;
        return Ok(());
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", unix)))]
    {
        anyhow::bail!("no browser-open implementation for this target");
    }
}

pub fn extract_authorization_code_from_callback(callback_url: &str) -> anyhow::Result<String> {
    let url = Url::parse(callback_url)?;
    url.query_pairs()
        .find_map(|(key, value)| (key == "code").then(|| value.into_owned()))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("callback URL does not contain an authorization code"))
}

pub fn extract_state_from_callback(callback_url: &str) -> anyhow::Result<Option<String>> {
    let url = Url::parse(callback_url)?;
    Ok(url
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned())))
}

pub fn extract_error_from_callback(callback_url: &str) -> anyhow::Result<Option<String>> {
    let url = Url::parse(callback_url)?;
    Ok(url
        .query_pairs()
        .find_map(|(key, value)| (key == "error").then(|| value.into_owned())))
}

pub fn extract_error_description_from_callback(
    callback_url: &str,
) -> anyhow::Result<Option<String>> {
    let url = Url::parse(callback_url)?;
    Ok(url
        .query_pairs()
        .find_map(|(key, value)| (key == "error_description").then(|| value.into_owned())))
}

#[cfg(target_arch = "wasm32")]
pub fn capture_current_browser_callback_url() -> anyhow::Result<String> {
    let window =
        web_sys::window().ok_or_else(|| anyhow::anyhow!("browser window is not available"))?;
    let href = window
        .location()
        .href()
        .map_err(|error| anyhow::anyhow!("failed to read browser location: {error:?}"))?;
    callback_url_with_query(&href, browser_initial_navigation_url(&window).as_deref())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn capture_current_browser_callback_url() -> anyhow::Result<String> {
    anyhow::bail!("current browser callback capture is only available in wasm/web builds")
}

#[cfg(any(target_arch = "wasm32", test))]
fn callback_url_with_query(
    current_href: &str,
    initial_navigation_href: Option<&str>,
) -> anyhow::Result<String> {
    let current = Url::parse(current_href)?;
    if current.query().is_some() {
        return Ok(current_href.to_owned());
    }

    if let Some(initial_navigation_href) = initial_navigation_href {
        let initial = Url::parse(initial_navigation_href)?;
        if initial.query().is_some() && same_callback_location(&current, &initial) {
            return Ok(initial_navigation_href.to_owned());
        }
    }

    anyhow::bail!("current browser location does not contain callback query parameters")
}

#[cfg(any(target_arch = "wasm32", test))]
fn same_callback_location(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
        && left.path() == right.path()
}

#[cfg(target_arch = "wasm32")]
fn browser_initial_navigation_url(window: &web_sys::Window) -> Option<String> {
    use wasm_bindgen::JsCast as _;

    let performance = js_sys::Reflect::get(window, &"performance".into()).ok()?;
    let get_entries = js_sys::Reflect::get(&performance, &"getEntriesByType".into()).ok()?;
    let get_entries = get_entries.dyn_ref::<js_sys::Function>()?;
    let entries = get_entries.call1(&performance, &"navigation".into()).ok()?;
    let first = js_sys::Array::from(&entries).get(0);
    js_sys::Reflect::get(&first, &"name".into())
        .ok()
        .and_then(|value| value.as_string())
}

#[cfg(target_arch = "wasm32")]
pub fn persist_oidc_scaffold(
    bundle: &OidcScaffoldBundle,
    auth_server_url: &str,
    principal_server_url: &str,
    principal_actor_did: &str,
    device_id: &str,
) -> anyhow::Result<()> {
    let window =
        web_sys::window().ok_or_else(|| anyhow::anyhow!("browser window is not available"))?;
    let storage = window
        .local_storage()
        .map_err(|error| anyhow::anyhow!("failed to access localStorage: {error:?}"))?
        .ok_or_else(|| anyhow::anyhow!("localStorage is not available"))?;
    let payload = PersistedOidcScaffold {
        expected_state: bundle.state.clone(),
        expected_nonce: bundle.nonce.clone(),
        code_verifier: bundle.code_verifier.clone(),
        client_id: bundle.client_id.clone(),
        auth_server_url: auth_server_url.to_owned(),
        principal_server_url: principal_server_url.to_owned(),
        principal_actor_did: principal_actor_did.to_owned(),
        device_id: device_id.to_owned(),
        principal_audience: bundle.principal_audience.clone(),
        callback_uri: bundle.callback_uri.clone(),
        authorize_url: bundle.authorize_url.clone(),
    };
    storage
        .set_item(OIDC_SCAFFOLD_STORAGE_KEY, &serde_json::to_string(&payload)?)
        .map_err(|error| anyhow::anyhow!("failed to persist OIDC scaffold: {error:?}"))?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn persist_oidc_scaffold(
    _bundle: &OidcScaffoldBundle,
    _auth_server_url: &str,
    _principal_server_url: &str,
    _principal_actor_did: &str,
    _device_id: &str,
) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(target_arch = "wasm32")]
pub fn restore_oidc_scaffold() -> anyhow::Result<Option<PersistedOidcScaffold>> {
    let window =
        web_sys::window().ok_or_else(|| anyhow::anyhow!("browser window is not available"))?;
    let Some(storage) = window
        .local_storage()
        .map_err(|error| anyhow::anyhow!("failed to access localStorage: {error:?}"))?
    else {
        return Ok(None);
    };
    let Some(payload) = storage
        .get_item(OIDC_SCAFFOLD_STORAGE_KEY)
        .map_err(|error| anyhow::anyhow!("failed to load OIDC scaffold: {error:?}"))?
    else {
        return Ok(None);
    };
    Ok(Some(serde_json::from_str(&payload)?))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn restore_oidc_scaffold() -> anyhow::Result<Option<PersistedOidcScaffold>> {
    Ok(None)
}

#[cfg(target_arch = "wasm32")]
pub fn clear_persisted_oidc_scaffold() -> anyhow::Result<()> {
    let window =
        web_sys::window().ok_or_else(|| anyhow::anyhow!("browser window is not available"))?;
    let Some(storage) = window
        .local_storage()
        .map_err(|error| anyhow::anyhow!("failed to access localStorage: {error:?}"))?
    else {
        return Ok(());
    };
    storage
        .remove_item(OIDC_SCAFFOLD_STORAGE_KEY)
        .map_err(|error| anyhow::anyhow!("failed to clear OIDC scaffold: {error:?}"))?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn clear_persisted_oidc_scaffold() -> anyhow::Result<()> {
    Ok(())
}

/// Diagnostic preview of the OIDC authorize URL using **stable
/// non-secret placeholders** for state / nonce / code_challenge so the
/// preview output is reproducible and obvious in the UI. The real
/// authorize flow runs through [`build_authorize_url_with_session`]
/// (~line 825) which generates the three values via
/// `random_url_safe_token` + `pkce_code_challenge_s256` against fresh
/// per-attempt randomness.
fn build_authorize_url_preview(
    topology: &CoauthTopologySnapshot,
    actor_did: &str,
    principal_audience: &str,
) -> anyhow::Result<String> {
    let redirect_uri = current_oidc_redirect_uri();
    let client_id = resolve_oidc_client_id(topology, redirect_uri.as_str())?;
    build_authorize_url(
        topology,
        client_id.as_str(),
        redirect_uri.as_str(),
        actor_did,
        principal_audience,
        OIDC_STATE_PREVIEW,
        OIDC_NONCE_PREVIEW,
        OIDC_CODE_CHALLENGE_PREVIEW,
    )
}

fn build_authorize_url(
    topology: &CoauthTopologySnapshot,
    client_id: &str,
    redirect_uri: &str,
    actor_did: &str,
    principal_audience: &str,
    state: &str,
    nonce: &str,
    code_challenge: &str,
) -> anyhow::Result<String> {
    let mut url = Url::parse(&topology.authorization_endpoint)?;
    let scope = if topology
        .scopes_supported
        .iter()
        .any(|scope| scope == "offline_access")
    {
        "openid offline_access"
    } else {
        "openid"
    };
    let pkce_method = preferred_pkce_method(&topology.code_challenge_methods_supported);

    {
        let mut query = url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", client_id);
        query.append_pair("redirect_uri", redirect_uri);
        query.append_pair("scope", scope);
        query.append_pair("state", state);
        query.append_pair("nonce", nonce);
        if !actor_did.trim().is_empty() {
            query.append_pair("login_hint", actor_did);
        }
        query.append_pair("resource", principal_audience);
        // OIDC Core §3.1.2.1: `prompt=login` forces the IdP to re-prompt
        // the user for credentials even when an SSO session cookie is
        // present. Without this, an explicit Logout in our app does not
        // kill the IdP cookie, so clicking Continue on the login screen
        // would silently re-authenticate the same user without a
        // password.
        query.append_pair("prompt", "login");
        query.append_pair("max_age", "0");
        if let Some(pkce_method) = pkce_method {
            query.append_pair("code_challenge_method", pkce_method);
            query.append_pair("code_challenge", code_challenge);
        }
    }

    Ok(url.to_string())
}

fn resolve_oidc_client_id(
    topology: &CoauthTopologySnapshot,
    redirect_uri: &str,
) -> anyhow::Result<String> {
    let candidates: Vec<&CoauthOidcClientHint> = topology
        .oidc_clients
        .iter()
        .filter(|client| {
            client
                .grant_types
                .iter()
                .any(|grant_type| grant_type == "authorization_code")
        })
        .filter(|client| {
            client
                .token_endpoint_auth_method
                .as_deref()
                .map(|method| method == "none")
                .unwrap_or(true)
        })
        .collect();

    if let Some(client) = candidates.iter().find(|client| {
        client.redirect_uris.iter().any(|candidate_redirect_uri| {
            redirect_uri_matches_client(candidate_redirect_uri, redirect_uri)
        })
    }) {
        return Ok(client.client_id.clone());
    }

    let available = candidates
        .iter()
        .map(|client| {
            format!(
                "{}({}):[{}]",
                client.client_id,
                client
                    .token_endpoint_auth_method
                    .as_deref()
                    .unwrap_or("none"),
                client.redirect_uris.join(",")
            )
        })
        .collect::<Vec<_>>()
        .join(" | ");

    anyhow::bail!(
        "coauth topology did not expose a usable public authorization_code client whose registered redirect_uris contain redirect_uri={redirect_uri}; available={available}"
    )
}

fn redirect_uri_matches_client(registered_redirect_uri: &str, actual_redirect_uri: &str) -> bool {
    if registered_redirect_uri == actual_redirect_uri {
        return true;
    }

    let Ok(registered) = Url::parse(registered_redirect_uri) else {
        return false;
    };
    let Ok(actual) = Url::parse(actual_redirect_uri) else {
        return false;
    };
    let actual_host = actual.host_str().unwrap_or_default();
    if !matches!(actual_host, "localhost" | "127.0.0.1" | "::1") {
        return false;
    }
    registered.scheme() == actual.scheme()
        && registered.host_str() == actual.host_str()
        && registered.path() == actual.path()
        && registered.query() == actual.query()
        && registered.fragment() == actual.fragment()
        && registered.port().is_none()
}

pub(crate) fn principal_audience(principal_server_url: &str) -> anyhow::Result<String> {
    Ok(validate_server_url(principal_server_url)?
        .join("api")?
        .to_string()
        .trim_end_matches('/')
        .to_owned())
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn current_oidc_redirect_uri() -> String {
    web_sys::window()
        .and_then(|window| window.location().origin().ok())
        .map(|origin| format!("{origin}/auth/callback"))
        .unwrap_or_else(|| YOUGEN_OIDC_REDIRECT_URI_NATIVE.to_owned())
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn current_oidc_redirect_uri() -> String {
    YOUGEN_OIDC_REDIRECT_URI_NATIVE.to_owned()
}

fn preferred_pkce_method(methods: &[String]) -> Option<&'static str> {
    if methods.iter().any(|method| method == "S256") {
        Some("S256")
    } else if methods.iter().any(|method| method == "plain") {
        Some("plain")
    } else {
        None
    }
}

fn value_string(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

/// Random byte length for OIDC `state` and `nonce` parameters. 16 bytes →
/// 22-character URL-safe base64 token, well above the 128-bit unguessability
/// threshold RFC 6749 §10.12 calls for.
const STATE_NONCE_TOKEN_BYTES: usize = 16;

/// Random byte length for the PKCE `code_verifier` (RFC 7636 §4.1). 32 bytes
/// → 43-character URL-safe base64 string, the lower bound the spec allows
/// (43-128 chars). Length is fixed across browser/native to keep S256
/// challenge byte size constant.
const PKCE_VERIFIER_BYTES: usize = 32;

fn random_url_safe_token(byte_len: usize) -> anyhow::Result<String> {
    let mut buf = vec![0u8; byte_len];
    getrandom::fill(&mut buf).map_err(|error| anyhow::anyhow!("getrandom failed: {error}"))?;
    Ok(URL_SAFE_NO_PAD.encode(&buf))
}

fn pkce_code_challenge_s256(code_verifier: &str) -> String {
    let digest = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PKCE verifier MUST be 43 chars for our 32-byte seed (RFC 7636 §4.1
    /// allows 43-128). Any drift from 32-byte seeds breaks the S256 fixed
    /// challenge size; pin it so a future refactor catches the mismatch.
    #[test]
    fn pkce_verifier_is_url_safe_43_chars() {
        let verifier = random_url_safe_token(PKCE_VERIFIER_BYTES).unwrap();
        assert_eq!(verifier.len(), 43, "32-byte seed → 43-char URL-safe base64");
        assert!(
            verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "must be URL-safe base64 (no padding, no +/)"
        );
    }

    /// Two consecutive verifier draws MUST differ. If `random_url_safe_token`
    /// ever falls back to a deterministic source this test fires.
    #[test]
    fn random_tokens_are_unguessable() {
        let a = random_url_safe_token(PKCE_VERIFIER_BYTES).unwrap();
        let b = random_url_safe_token(PKCE_VERIFIER_BYTES).unwrap();
        assert_ne!(a, b, "RNG must not return the same value twice in a row");
    }

    #[test]
    fn login_response_accepts_current_coauth_viewer_shape() {
        let response: CoauthLoginResponse = serde_json::from_value(json!({
            "status": "success",
            "viewer": {
                "id": "user:01K",
                "handle": "ca",
                "did": "did:web:auth.local.host:u:ca",
                "federated_handle": "ca@auth.local.host",
                "principal_id": "@ca:auth.local.host",
                "display_name": null
            },
            "session_grant": {
                "kind": "principal_session",
                "id": "grant-1",
                "grant_jwt": "eyJ.mock.jwt",
                "session_public_key": "mock-public",
                "session_private_key_pem": "-----BEGIN PRIVATE KEY-----\\nmock\\n-----END PRIVATE KEY-----",
                "expires_at": "2026-05-13T04:00:00Z",
                "audience": "https://local.host/api",
                "scopes": ["urn:contrix:principal-server:session.bind"],
                "principal_server": {
                    "name": "local",
                    "endpoint": "https://local.host"
                }
            },
            "warnings": []
        }))
        .unwrap();

        let viewer = response.viewer.unwrap();
        assert_eq!(viewer.principal_id.as_deref(), Some("@ca:auth.local.host"));
    }

    /// S256 challenge for a known verifier matches the RFC 7636 Appendix B
    /// test vector — confirms we hash the right bytes and base64-encode
    /// without padding.
    #[test]
    fn s256_challenge_matches_rfc7636_test_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = pkce_code_challenge_s256(verifier);
        assert_eq!(
            challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "S256 challenge MUST match RFC 7636 Appendix B"
        );
    }

    /// The token-response -> persisted-bundle adapter MUST translate
    /// `expires_in` into an absolute `expires_at_unix` and preserve
    /// refresh_token / id_token / scope verbatim. Production callers persist
    /// the result via `LocalStateStore::set_oidc_tokens`.
    #[test]
    fn oidc_token_response_to_bundle_round_trips_fields() {
        let response = OidcTokenResponse {
            access_token: "at-1234".to_owned(),
            token_type: Some("Bearer".to_owned()),
            expires_in: Some(3600),
            refresh_token: Some("rt-abcd".to_owned()),
            id_token: Some("eyJ...".to_owned()),
            scope: Some("openid offline_access".to_owned()),
            extras: serde_json::Map::new(),
        };
        let bundle = response.to_persisted_bundle(Some("https://principal.example/api"));
        assert_eq!(bundle.access_token, "at-1234");
        assert_eq!(bundle.refresh_token.as_deref(), Some("rt-abcd"));
        assert_eq!(bundle.token_type, "Bearer");
        assert_eq!(bundle.id_token.as_deref(), Some("eyJ..."));
        assert_eq!(bundle.scope.as_deref(), Some("openid offline_access"));
        assert_eq!(
            bundle.audience.as_deref(),
            Some("https://principal.example/api")
        );
        // expires_at_unix should be ~now+3600 (within a few seconds).
        let expected_min = chrono::Utc::now().timestamp() + 3500;
        let expected_max = chrono::Utc::now().timestamp() + 3700;
        let actual = bundle.expires_at_unix.expect("expires_at_unix present");
        assert!(
            actual > expected_min && actual < expected_max,
            "expires_at_unix={actual} out of expected window [{expected_min}, {expected_max}]"
        );
    }

    /// Audience supplied as an `extras` field on the token response
    /// SHOULD win over the caller-supplied hint — providers that mint
    /// audience-scoped tokens (Auth0 RBAC) always emit it on the wire.
    #[test]
    fn oidc_token_response_audience_extras_wins_over_hint() {
        let mut extras = serde_json::Map::new();
        extras.insert(
            "audience".to_owned(),
            Value::String("https://wire.example/api".to_owned()),
        );
        let response = OidcTokenResponse {
            access_token: "at".to_owned(),
            token_type: None,
            expires_in: None,
            refresh_token: None,
            id_token: None,
            scope: None,
            extras,
        };
        let bundle = response.to_persisted_bundle(Some("https://hint.example/api"));
        assert_eq!(bundle.audience.as_deref(), Some("https://wire.example/api"));
    }

    /// The introspection proof MUST be a valid Ed25519 JWS over the
    /// canonical claims, MUST embed `cx.session_grant.introspection_proof.v1`
    /// as `type`, MUST hash the grant JWT into `grant_jwt_hash`, and MUST
    /// round-trip the challenge / audience / grant_id verbatim. coauth's
    /// verifier requires every one of those exact strings - drift here
    /// would surface as `InvalidProof` at the principal server.
    #[test]
    fn session_grant_proof_signs_canonical_claims() {
        use ed25519_dalek::{SigningKey, Verifier};
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let verifying = signing.verifying_key();
        let proof_jwt = build_session_grant_introspection_proof(
            "01HABC123",
            "eyJ.opaque-grant.jwt",
            "did:web:principal.example",
            "challenge-deadbeef",
            &signing,
        )
        .unwrap();
        // Compact JWS: 3 segments separated by `.`.
        let parts: Vec<&str> = proof_jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "proof must be a compact JWS");
        // Decode + verify the signature against the matching pubkey.
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        verifying
            .verify(signing_input.as_bytes(), &signature)
            .expect("proof JWS must verify under matching pubkey");
        // Decode + assert payload claims.
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: SessionGrantIntrospectionProofClaims =
            serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(
            claims.kind, "cx.session_grant.introspection_proof.v1",
            "type claim must match coauth's spec"
        );
        assert_eq!(claims.grant_id, "01HABC123");
        assert_eq!(claims.audience, "did:web:principal.example");
        assert_eq!(claims.challenge, "challenge-deadbeef");
        assert_eq!(
            claims.grant_jwt_hash,
            session_grant_jwt_hash("eyJ.opaque-grant.jwt"),
            "grant_jwt_hash must be sha256(grant_jwt) hex prefixed"
        );
        // Header claim is `EdDSA` + `JWT`.
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header.get("alg").and_then(|v| v.as_str()), Some("EdDSA"));
        assert_eq!(header.get("typ").and_then(|v| v.as_str()), Some("JWT"));
    }

    #[test]
    fn session_grant_private_key_pem_round_trips_to_signing_key() {
        use ed25519_dalek::pkcs8::EncodePrivateKey as _;

        let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let pem = signing
            .to_pkcs8_pem(Default::default())
            .expect("encode pkcs8 pem");
        let decoded = session_grant_signing_key_from_pem(&pem).expect("decode pkcs8 pem");

        assert_eq!(decoded.to_bytes(), signing.to_bytes());
    }

    /// Empty inputs MUST be rejected — coauth's verifier treats blank
    /// challenge / proof_jwt as `InvalidProof` so client-side validation
    /// avoids round-tripping unsignable garbage.
    #[test]
    fn session_grant_proof_rejects_empty_inputs() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        assert!(build_session_grant_introspection_proof("", "j", "a", "c", &signing).is_err());
        assert!(build_session_grant_introspection_proof("g", "", "a", "c", &signing).is_err());
        assert!(build_session_grant_introspection_proof("g", "j", "", "c", &signing).is_err());
        assert!(build_session_grant_introspection_proof("g", "j", "a", "", &signing).is_err());
    }

    #[test]
    fn session_grant_jwt_hash_matches_coauth_format() {
        // `sha256:<lowercase-hex(sha256(bytes))>`. Pin the format so a
        // refactor that switches to base64url doesn't silently desync.
        let hash = session_grant_jwt_hash("hello");
        assert!(hash.starts_with("sha256:"));
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(
            hash,
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    /// `open_oidc_authorize_url` MUST refuse non-http(s) schemes —
    /// hand-crafted `javascript:` / `file:` URLs would be a phishing
    /// surface on the desktop target.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn open_oidc_authorize_url_rejects_non_http_schemes() {
        let result = open_oidc_authorize_url("javascript:alert(1)");
        assert!(result.is_err(), "javascript: scheme MUST be rejected");
        let result = open_oidc_authorize_url("file:///etc/passwd");
        assert!(result.is_err(), "file: scheme MUST be rejected");
    }

    #[test]
    fn callback_url_uses_current_href_when_query_is_present() {
        let callback = callback_url_with_query(
            "http://127.0.0.1:8080/auth/callback?code=c&state=s",
            Some("http://127.0.0.1:8080/auth/callback?code=old&state=old"),
        )
        .unwrap();
        assert_eq!(
            callback,
            "http://127.0.0.1:8080/auth/callback?code=c&state=s"
        );
    }

    #[test]
    fn callback_url_falls_back_to_initial_navigation_after_router_strips_query() {
        let callback = callback_url_with_query(
            "http://127.0.0.1:8080/auth/callback",
            Some("http://127.0.0.1:8080/auth/callback?code=c&state=s"),
        )
        .unwrap();
        assert_eq!(
            callback,
            "http://127.0.0.1:8080/auth/callback?code=c&state=s"
        );
    }

    #[test]
    fn callback_url_rejects_initial_navigation_from_different_location() {
        let err = callback_url_with_query(
            "http://127.0.0.1:8080/auth/callback",
            Some("http://127.0.0.1:8080/other?code=c&state=s"),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not contain callback query parameters")
        );
    }

    /// State and nonce tokens for the same input MUST diverge. The previous
    /// scaffold derived both from `(actor_did, device_id, label)` so they
    /// were predictable; this regression test pins the new behaviour.
    #[test]
    fn state_and_nonce_diverge_for_same_caller() {
        let topology = test_topology();
        let bundle_a = build_oidc_scaffold_bundle(
            &topology,
            "https://principal.example",
            "did:web:alice.example",
            "device-aaaa-1111",
        )
        .unwrap();
        let bundle_b = build_oidc_scaffold_bundle(
            &topology,
            "https://principal.example",
            "did:web:alice.example",
            "device-aaaa-1111",
        )
        .unwrap();
        assert_ne!(
            bundle_a.state, bundle_b.state,
            "same caller MUST get different state across calls"
        );
        assert_ne!(
            bundle_a.nonce, bundle_b.nonce,
            "same caller MUST get different nonce across calls"
        );
        assert_ne!(
            bundle_a.code_verifier, bundle_b.code_verifier,
            "same caller MUST get different verifier across calls"
        );
        assert_ne!(
            bundle_a.state, bundle_a.nonce,
            "state and nonce MUST be independent draws"
        );
    }

    /// The bundle's `code_challenge` MUST be S256(code_verifier) when the
    /// topology supports S256 — anything else means the authorize URL we
    /// hand to the browser cannot complete the PKCE check.
    #[test]
    fn bundle_challenge_is_s256_of_verifier_when_supported() {
        let topology = test_topology();
        let bundle = build_oidc_scaffold_bundle(
            &topology,
            "https://principal.example",
            "did:web:alice.example",
            "device-bbbb-2222",
        )
        .unwrap();
        assert_eq!(
            bundle.code_challenge,
            pkce_code_challenge_s256(&bundle.code_verifier),
            "S256 topology must produce S256(verifier) challenge"
        );
    }

    #[test]
    fn authorize_url_forces_reauthentication() {
        let topology = test_topology();
        let bundle = build_oidc_scaffold_bundle(
            &topology,
            "https://principal.example",
            "did:web:alice.example",
            "device-cccc-3333",
        )
        .unwrap();
        let parsed = Url::parse(&bundle.authorize_url).unwrap();
        assert_eq!(
            parsed
                .query_pairs()
                .find(|(key, _)| key == "prompt")
                .unwrap()
                .1,
            "login"
        );
        assert_eq!(
            parsed
                .query_pairs()
                .find(|(key, _)| key == "max_age")
                .unwrap()
                .1,
            "0"
        );
    }

    #[test]
    fn bridge_authorize_url_gets_reauthentication_params() {
        let updated = authorize_url_with_forced_reauthentication(
            "https://issuer.example/auth?client_id=c&prompt=consent&max_age=3600",
        )
        .unwrap();
        let parsed = Url::parse(&updated).unwrap();
        let prompt = parsed
            .query_pairs()
            .find(|(key, _)| key == "prompt")
            .unwrap()
            .1
            .into_owned();
        assert!(
            prompt
                .split_ascii_whitespace()
                .any(|part| part == "consent")
        );
        assert!(prompt.split_ascii_whitespace().any(|part| part == "login"));
        assert_eq!(
            parsed
                .query_pairs()
                .find(|(key, _)| key == "max_age")
                .unwrap()
                .1,
            "0"
        );
    }

    fn test_topology() -> CoauthTopologySnapshot {
        CoauthTopologySnapshot {
            service_did: None,
            service_type: None,
            protocol_version: None,
            identity_service_did: None,
            issuer: "https://issuer.example".to_owned(),
            authorization_endpoint: "https://issuer.example/auth".to_owned(),
            token_endpoint: Some("https://issuer.example/token".to_owned()),
            userinfo_endpoint: Some("https://issuer.example/userinfo".to_owned()),
            code_challenge_methods_supported: vec!["S256".to_owned()],
            scopes_supported: vec!["openid".to_owned()],
            oidc_clients: vec![CoauthOidcClientHint {
                id: "test-client".to_owned(),
                client_id: "yougen-test".to_owned(),
                client_name: None,
                redirect_uris: vec![current_oidc_redirect_uri()],
                grant_types: vec!["authorization_code".to_owned()],
                token_endpoint_auth_method: Some("none".to_owned()),
            }],
            oidc_browser_bridge_session_path: "api/v1/auth/oidc/browser-bridge/session".to_owned(),
            oidc_exchange_describe_path: "api/v1/auth/oidc/exchange/describe".to_owned(),
            oidc_exchange_path: "api/v1/auth/oidc/exchange".to_owned(),
            auth_bridge_contract: "auth-bridge".to_owned(),
            auth_bridge_todos: Vec::new(),
            integration_manifest: CoauthIntegrationManifest {
                contract: "integration".to_owned(),
                version: "1".to_owned(),
                service: "coauth".to_owned(),
                service_kind: "auth".to_owned(),
                api_base_path: "/api/v1".to_owned(),
                describe_path: "describe".to_owned(),
                dependencies: Vec::new(),
                surfaces: Vec::new(),
                examples: Value::Null,
                todos: Vec::new(),
            },
        }
    }
}
