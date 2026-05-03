use anyhow::Context;
use reqwest::Client;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use url::Url;

use crate::config::validate_server_url;

const YOUGEN_OIDC_CLIENT_ID: &str = "yougen";
const YOUGEN_OIDC_REDIRECT_URI: &str = "urn:yougen:oauth:callback";
const OIDC_STATE_PLACEHOLDER: &str = "TODO_STATE";
const OIDC_NONCE_PLACEHOLDER: &str = "TODO_NONCE";
const OIDC_CODE_CHALLENGE_PLACEHOLDER: &str = "TODO_PKCE_CODE_CHALLENGE";

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
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CoauthViewerInfo {
    pub id: String,
    pub username: String,
    pub did: String,
    pub handle: String,
    pub mxid: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CoauthSessionGrantInfo {
    #[serde(default)]
    pub kind: Option<String>,
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

#[derive(Clone, Debug)]
pub struct CoauthTopologySnapshot {
    pub service_did: Option<String>,
    pub service_type: Option<String>,
    pub protocol_version: Option<String>,
    pub identity_service_did: Option<String>,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: Option<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct SolandSessionGrantPlan {
    pub principal_server_url: String,
    pub principal_audience: String,
    pub actor_did: String,
    pub device_id: String,
    pub authorize_url_preview: String,
    pub token_endpoint: Option<String>,
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
    pub authorize_url_preview: String,
    pub token_endpoint: String,
    pub exchange_request_preview: String,
    pub todo: &'static str,
}

#[derive(Clone, Debug)]
pub struct OidcScaffoldBundle {
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub code_challenge: String,
    pub authorize_url: String,
    pub callback_uri: String,
    pub principal_audience: String,
    pub todo: &'static str,
}

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

        Ok(CoauthTopologySnapshot {
            service_did: value_string(&server, "service_did"),
            service_type: value_string(&server, "service_type"),
            protocol_version: value_string(&server, "protocol_version"),
            identity_service_did: value_string(&identity, "service_did")
                .or_else(|| value_string(&identity, "issuer_did")),
            issuer: discovery.issuer,
            authorization_endpoint: discovery.authorization_endpoint,
            token_endpoint: discovery.token_endpoint,
            code_challenge_methods_supported: discovery.code_challenge_methods_supported,
            scopes_supported: discovery.scopes_supported,
        })
    }

    pub async fn password_login(
        &self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<CoauthLoginResponse> {
        self.post_json(
            "api/v1/auth/login",
            json!({
                "username": username,
                "password": password,
            }),
        )
        .await
    }

    pub async fn exchange_oidc_code(
        &self,
        authorization_code: &str,
        code_verifier: &str,
        login_hint: &str,
        device_id: &str,
        principal_audience: Option<&str>,
    ) -> anyhow::Result<CoauthLoginResponse> {
        self.post_json(
            "api/v1/auth/oidc/exchange",
            json!({
                "authorization_code": authorization_code,
                "code_verifier": code_verifier,
                "login_hint": login_hint,
                "device_id": device_id,
                "principal_audience": principal_audience,
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
        todo: "TODO: after the coauth code exchange, request a short-lived session grant for the soland audience and swap it into yougen's authenticated principal-server session.",
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
        todo: "TODO: replace the scaffold push token/proof with live device material, then attach the coauth-issued soland grant when POSTing the chime register request to /api/v1/push/register-device.",
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
    let authorize_url_preview =
        build_authorize_url_preview(topology, actor_did, principal_audience.as_str())?;
    let token_endpoint = topology
        .token_endpoint
        .clone()
        .unwrap_or_else(|| "missing".to_owned());
    let exchange_request_preview = serde_json::to_string_pretty(&json!({
        "grant_type": "authorization_code",
        "client_id": YOUGEN_OIDC_CLIENT_ID,
        "redirect_uri": YOUGEN_OIDC_REDIRECT_URI,
        "resource": principal_audience,
        "code": "TODO_AUTHORIZATION_CODE",
        "code_verifier": "TODO_PKCE_CODE_VERIFIER",
        "login_hint": actor_did,
        "device_id": device_id,
    }))?;

    Ok(OidcCodeExchangePlan {
        principal_server_url,
        principal_audience,
        actor_did: actor_did.to_owned(),
        device_id: device_id.to_owned(),
        authorize_url_preview,
        token_endpoint,
        exchange_request_preview,
        todo: "TODO: drive the browser/passkey flow through coauth, exchange the returned authorization code at the token endpoint, request a short-lived audience-specific session grant for soland, then swap it at /api/v1/auth/session-grant/exchange.",
    })
}

pub fn build_oidc_scaffold_bundle(
    topology: &CoauthTopologySnapshot,
    principal_server_url: &str,
    actor_did: &str,
    device_id: &str,
) -> anyhow::Result<OidcScaffoldBundle> {
    let principal_server_url = validate_server_url(principal_server_url)?.to_string();
    let principal_audience = principal_audience(principal_server_url.as_str())?;
    let state = format!("cx-state-{}", scaffold_slug(actor_did, device_id, "state"));
    let nonce = format!("cx-nonce-{}", scaffold_slug(actor_did, device_id, "nonce"));
    let code_verifier = format!(
        "cx-pkce-verifier-{}",
        scaffold_slug(actor_did, device_id, "verifier")
    );
    let code_challenge = format!(
        "TODO-S256-{}",
        scaffold_slug(actor_did, device_id, "challenge")
    );
    let authorize_url = build_authorize_url(
        topology,
        actor_did,
        principal_audience.as_str(),
        &state,
        &nonce,
        &code_challenge,
    )?;

    Ok(OidcScaffoldBundle {
        state,
        nonce,
        code_verifier,
        code_challenge,
        authorize_url,
        callback_uri: YOUGEN_OIDC_REDIRECT_URI.to_owned(),
        principal_audience,
        todo: "TODO: replace the deterministic scaffold state/nonce/challenge with real browser-generated PKCE material and a callback handler that captures the returned authorization code automatically.",
    })
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
    Ok(url.query_pairs().find_map(|(key, value)| {
        (key == "error_description").then(|| value.into_owned())
    }))
}

pub fn summarize_password_login_bridge(
    login: &CoauthLoginResponse,
    registration_id: Option<&str>,
    register_request_preview: &str,
) -> String {
    let viewer = login
        .viewer
        .as_ref()
        .map(|viewer| {
            format!(
                "viewer={} did={} handle={} mxid={}",
                viewer.username, viewer.did, viewer.handle, viewer.mxid
            )
        })
        .unwrap_or_else(|| "viewer=unknown".to_owned());
    let grant = login
        .session_grant
        .as_ref()
        .map(|grant| {
            let scopes = if grant.scopes.is_empty() {
                "missing".to_owned()
            } else {
                grant.scopes.join(",")
            };
            let audience = grant.audience.as_deref().unwrap_or("missing");
            let principal_server = grant
                .principal_server
                .as_ref()
                .map(|server| format!("{}@{}", server.name, server.endpoint))
                .unwrap_or_else(|| "missing".to_owned());
            format!(
                "grant_kind={} grant_expires={} audience={} scopes={} principal_server={} session_key_present={} private_key_pem_present={}",
                grant.kind.as_deref().unwrap_or("missing"),
                grant.expires_at,
                audience,
                scopes,
                principal_server,
                !grant.session_public_key.is_empty(),
                !grant.session_private_key_pem.is_empty(),
            )
        })
        .unwrap_or_else(|| "grant=missing".to_owned());
    let registration_id = registration_id.unwrap_or("missing");
    let warnings = if login.warnings.is_empty() {
        "warnings=none".to_owned()
    } else {
        format!("warnings={}", login.warnings.join(" | "))
    };

    format!(
        "{viewer}\n{grant}\n{warnings}\npush_registration_id={registration_id}\nrequest_preview:\n{register_request_preview}\n\nTODO: replace scaffold bridge with real passkey/OIDC code exchange and coauth-issued audience-specific session grant refresh."
    )
}

fn build_authorize_url_preview(
    topology: &CoauthTopologySnapshot,
    actor_did: &str,
    principal_audience: &str,
) -> anyhow::Result<String> {
    build_authorize_url(
        topology,
        actor_did,
        principal_audience,
        OIDC_STATE_PLACEHOLDER,
        OIDC_NONCE_PLACEHOLDER,
        OIDC_CODE_CHALLENGE_PLACEHOLDER,
    )
}

fn build_authorize_url(
    topology: &CoauthTopologySnapshot,
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
        query.append_pair("client_id", YOUGEN_OIDC_CLIENT_ID);
        query.append_pair("redirect_uri", YOUGEN_OIDC_REDIRECT_URI);
        query.append_pair("scope", scope);
        query.append_pair("state", state);
        query.append_pair("nonce", nonce);
        query.append_pair("login_hint", actor_did);
        query.append_pair("resource", principal_audience);
        if let Some(pkce_method) = pkce_method {
            query.append_pair("code_challenge_method", pkce_method);
            query.append_pair("code_challenge", code_challenge);
        }
    }

    Ok(url.to_string())
}

fn principal_audience(principal_server_url: &str) -> anyhow::Result<String> {
    Ok(validate_server_url(principal_server_url)?
        .join("api")?
        .to_string()
        .trim_end_matches('/')
        .to_owned())
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

fn scaffold_slug(actor_did: &str, device_id: &str, label: &str) -> String {
    let mut out = String::new();
    for ch in format!("{label}-{actor_did}-{device_id}").chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_owned()
}
