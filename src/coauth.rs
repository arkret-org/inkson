use anyhow::Context;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use url::Url;

use crate::config::validate_server_url;

const YOUGEN_OIDC_REDIRECT_URI_NATIVE: &str = "urn:yougen:oauth:callback";
const OIDC_STATE_PLACEHOLDER: &str = "TODO_STATE";
const OIDC_NONCE_PLACEHOLDER: &str = "TODO_NONCE";
const OIDC_CODE_CHALLENGE_PLACEHOLDER: &str = "TODO_PKCE_CODE_CHALLENGE";
const OIDC_SCAFFOLD_STORAGE_KEY: &str = "yougen.oidc.scaffold.v1";

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
pub struct CoauthRecoveryDescribe {
    pub contract: String,
    pub version: String,
    pub recovery_start_path: String,
    pub recovery_status_path: String,
    pub recovery_resend_path: String,
    pub recovery_principal_snapshot_path: String,
    pub recovery_principal_cache_status_path: String,
    pub recovery_principal_cache_refresh_path: String,
    pub recovery_principal_cache_queue_path: String,
    pub recovery_principal_cache_complete_path: String,
    pub recovery_principal_cache_fail_path: String,
    pub recovery_principal_cache_policy_path: String,
    pub recovery_principal_cache_retry_path: String,
    pub recovery_principal_cache_invalidate_path: String,
    pub recovery_principal_cache_failures_path: String,
    pub recovery_principal_cache_upstream_path: String,
    pub recovery_principal_cache_upstream_probe_path: String,
    pub recovery_principal_cache_upstream_bind_path: String,
    pub key_backup_rest_base: String,
    pub key_backup_schema: String,
    pub device_message_schema: String,
    pub principal_recovery_contract_stack_path: String,
    pub principal_recovery_stack_bundle_path: String,
    pub principal_recovery_discovery_path: String,
    pub principal_recovery_readiness_path: String,
    pub principal_device_messages_describe_path: String,
    pub principal_key_backups_describe_path: String,
    pub principal_restore_state_describe_path: String,
    pub principal_restore_state_export_path: String,
    pub principal_restore_state_import_path: String,
    pub principal_restore_state_durability_path: String,
    pub principal_restore_state_checkpoint_collection_path: String,
    pub principal_restore_start_path: String,
    pub principal_restore_describe_path: String,
    pub principal_restore_ticket_collection_path: String,
    pub principal_restore_ticket_path: String,
    pub principal_restore_ticket_advance_path: String,
    pub principal_restore_ticket_resume_path: String,
    pub principal_restore_ticket_cancel_path: String,
    pub principal_restore_ticket_retry_path: String,
    pub principal_restore_approval_status_path: String,
    pub principal_restore_approval_submit_path: String,
    pub principal_restore_executor_status_path: String,
    pub principal_restore_executor_enqueue_path: String,
    pub principal_restore_executor_start_path: String,
    pub principal_restore_executor_complete_path: String,
    pub principal_restore_result_path: String,
    pub principal_restore_receipt_path: String,
    pub principal_restore_materialized_device_handoff_path: String,
    pub principal_restore_bundle_path: String,
    pub principal_restore_activity_path: String,
    pub principal_restore_timeline_path: String,
    pub principal_restore_audit_feed_path: String,
    pub principal_recovery_live_snapshot_path: String,
    pub principal_authz_describe_path: String,
    pub principal_authz_check_path: String,
    pub principal_policy_describe_path: String,
    pub principal_policy_collection_path: String,
    pub principal_policy_item_path: String,
    #[serde(default)]
    pub verification_event_kinds: Vec<String>,
    #[serde(default)]
    pub recovery_modes: Vec<String>,
    #[serde(default)]
    pub example_backup_payload: Value,
    #[serde(default)]
    pub recovery_restore_examples: Value,
    #[serde(default)]
    pub recovery_authz_examples: Value,
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
    pub code_verifier: String,
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

    pub async fn recovery_describe(&self) -> anyhow::Result<CoauthRecoveryDescribe> {
        self.get_json("api/v1/auth/recovery/describe").await
    }

    pub async fn principal_recovery_snapshot(&self) -> anyhow::Result<Value> {
        self.get_json("api/v1/auth/recovery/principal-snapshot").await
    }

    pub async fn principal_recovery_cache_status(&self) -> anyhow::Result<Value> {
        self.get_json("api/v1/auth/recovery/principal-cache/status").await
    }

    pub async fn refresh_principal_recovery_cache(&self, payload: Value) -> anyhow::Result<Value> {
        self.post_json("api/v1/auth/recovery/principal-cache/refresh", &payload)
            .await
    }

    pub async fn principal_recovery_cache_queue(&self) -> anyhow::Result<Value> {
        self.get_json("api/v1/auth/recovery/principal-cache/queue").await
    }

    pub async fn complete_principal_recovery_cache(&self, payload: Value) -> anyhow::Result<Value> {
        self.post_json("api/v1/auth/recovery/principal-cache/complete", &payload)
            .await
    }

    pub async fn fail_principal_recovery_cache(&self, payload: Value) -> anyhow::Result<Value> {
        self.post_json("api/v1/auth/recovery/principal-cache/fail", &payload)
            .await
    }

    pub async fn principal_recovery_cache_policy(&self) -> anyhow::Result<Value> {
        self.get_json("api/v1/auth/recovery/principal-cache/policy").await
    }

    pub async fn retry_principal_recovery_cache(&self, payload: Value) -> anyhow::Result<Value> {
        self.post_json("api/v1/auth/recovery/principal-cache/retry", &payload)
            .await
    }

    pub async fn invalidate_principal_recovery_cache(&self, payload: Value) -> anyhow::Result<Value> {
        self.post_json("api/v1/auth/recovery/principal-cache/invalidate", &payload)
            .await
    }

    pub async fn principal_recovery_cache_failures(&self) -> anyhow::Result<Value> {
        self.get_json("api/v1/auth/recovery/principal-cache/failures").await
    }

    pub async fn principal_recovery_cache_upstream(&self) -> anyhow::Result<Value> {
        self.get_json("api/v1/auth/recovery/principal-cache/upstream").await
    }

    pub async fn probe_principal_recovery_cache_upstream(&self, payload: Value) -> anyhow::Result<Value> {
        self.post_json("api/v1/auth/recovery/principal-cache/upstream/probe", &payload)
            .await
    }

    pub async fn bind_principal_recovery_cache_upstream(&self, payload: Value) -> anyhow::Result<Value> {
        self.post_json("api/v1/auth/recovery/principal-cache/upstream/bind", &payload)
            .await
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
            }),
        )
        .await
    }

    pub async fn exchange_oidc_code_legacy(
        &self,
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
    ) -> anyhow::Result<CoauthLoginResponse> {
        self.exchange_oidc_code(
            "api/v1/auth/oidc/exchange",
            authorization_code,
            code_verifier,
            redirect_uri,
            issuer,
            token_endpoint,
            userinfo_endpoint,
            client_id,
            login_hint,
            device_id,
            principal_audience,
            state,
            expected_state,
        ).await
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

pub fn active_oidc_redirect_uri() -> String {
    current_oidc_redirect_uri()
}

pub fn summarize_coauth_integration_manifest(
    manifest: &CoauthIntegrationManifest,
) -> String {
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

pub fn summarize_coauth_recovery_bridge(
    recovery: &CoauthRecoveryDescribe,
) -> anyhow::Result<String> {
    let kinds = if recovery.verification_event_kinds.is_empty() {
        "none".to_owned()
    } else {
        recovery.verification_event_kinds.join(", ")
    };
    let modes = if recovery.recovery_modes.is_empty() {
        "none".to_owned()
    } else {
        recovery.recovery_modes.join(", ")
    };
    let todos = if recovery.todos.is_empty() {
        "none".to_owned()
    } else {
        recovery.todos.join(" ")
    };

    Ok(format!(
        "contract={} version={}\nstart={}\nstatus={}\nresend={}\nkey_backup_base={} schema={}\ndevice_message_schema={}\nprincipal_recovery_contract_stack={}\nprincipal_device_messages_describe={}\nprincipal_key_backups_describe={}\nprincipal_restore_state_describe={}\nprincipal_restore_state_export={}\nprincipal_restore_state_import={}\nprincipal_restore_start={}\nprincipal_restore_describe={}\nprincipal_restore_ticket_collection={}\nprincipal_restore_ticket={}\nprincipal_restore_ticket_advance={}\nprincipal_restore_ticket_resume={}\nprincipal_restore_ticket_cancel={}\nprincipal_restore_ticket_retry={}\nprincipal_restore_approval_status={}\nprincipal_restore_approval_submit={}\nprincipal_restore_executor_status={}\nprincipal_restore_executor_enqueue={}\nprincipal_restore_executor_start={}\nprincipal_restore_executor_complete={}\nprincipal_restore_result={}\nprincipal_restore_receipt={}\nprincipal_restore_materialized_device_handoff={}\nprincipal_restore_bundle={}\nprincipal_authz_describe={}\nprincipal_authz_check={}\nprincipal_policy_describe={}\nprincipal_policy_collection={}\nprincipal_policy_item={}\nverification_kinds={}\nrecovery_modes={}\nexample_backup_payload:\n{}\nrecovery_restore_examples:\n{}\nrecovery_authz_examples:\n{}\ntodos={}",
        recovery.contract,
        recovery.version,
        recovery.recovery_start_path,
        recovery.recovery_status_path,
        recovery.recovery_resend_path,
        recovery.key_backup_rest_base,
        recovery.key_backup_schema,
        recovery.device_message_schema,
        recovery.principal_recovery_contract_stack_path,
        recovery.principal_device_messages_describe_path,
        recovery.principal_key_backups_describe_path,
        recovery.principal_restore_state_describe_path,
        recovery.principal_restore_state_export_path,
        recovery.principal_restore_state_import_path,
        recovery.principal_restore_start_path,
        recovery.principal_restore_describe_path,
        recovery.principal_restore_ticket_collection_path,
        recovery.principal_restore_ticket_path,
        recovery.principal_restore_ticket_advance_path,
        recovery.principal_restore_ticket_resume_path,
        recovery.principal_restore_ticket_cancel_path,
        recovery.principal_restore_ticket_retry_path,
        recovery.principal_restore_approval_status_path,
        recovery.principal_restore_approval_submit_path,
        recovery.principal_restore_executor_status_path,
        recovery.principal_restore_executor_enqueue_path,
        recovery.principal_restore_executor_start_path,
        recovery.principal_restore_executor_complete_path,
        recovery.principal_restore_result_path,
        recovery.principal_restore_receipt_path,
        recovery.principal_restore_materialized_device_handoff_path,
        recovery.principal_restore_bundle_path,
        recovery.principal_authz_describe_path,
        recovery.principal_authz_check_path,
        recovery.principal_policy_describe_path,
        recovery.principal_policy_collection_path,
        recovery.principal_policy_item_path,
        kinds,
        modes,
        serde_json::to_string_pretty(&recovery.example_backup_payload)?,
        serde_json::to_string_pretty(&recovery.recovery_restore_examples)?,
        serde_json::to_string_pretty(&recovery.recovery_authz_examples)?,
        todos,
    ))
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
        client_id,
        authorize_url_preview,
        token_endpoint,
        exchange_request_preview,
        integration_manifest_summary: summarize_coauth_integration_manifest(
            &topology.integration_manifest,
        ),
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
    let callback_uri = current_oidc_redirect_uri();
    let client_id = resolve_oidc_client_id(topology, callback_uri.as_str())?;
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
        todo: "TODO: replace the deterministic scaffold state/nonce/challenge with real browser-generated PKCE material and a callback handler that captures the returned authorization code automatically.",
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
        todo: "TODO: replace scaffold state/nonce/challenge with browser-generated PKCE material and automatic callback handling.",
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
    Ok(url.query_pairs().find_map(|(key, value)| {
        (key == "error_description").then(|| value.into_owned())
    }))
}

#[cfg(target_arch = "wasm32")]
pub fn capture_current_browser_callback_url() -> anyhow::Result<String> {
    let window = web_sys::window()
        .ok_or_else(|| anyhow::anyhow!("browser window is not available"))?;
    let href = window
        .location()
        .href()
        .map_err(|error| anyhow::anyhow!("failed to read browser location: {error:?}"))?;
    let parsed = Url::parse(&href)?;
    if parsed.query().is_none() {
        anyhow::bail!("current browser location does not contain callback query parameters");
    }
    Ok(href)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn capture_current_browser_callback_url() -> anyhow::Result<String> {
    anyhow::bail!("current browser callback capture is only available in wasm/web builds")
}

#[cfg(target_arch = "wasm32")]
pub fn persist_oidc_scaffold(
    bundle: &OidcScaffoldBundle,
    auth_server_url: &str,
    principal_server_url: &str,
    principal_actor_did: &str,
    device_id: &str,
) -> anyhow::Result<()> {
    let window = web_sys::window()
        .ok_or_else(|| anyhow::anyhow!("browser window is not available"))?;
    let storage = window
        .local_storage()
        .map_err(|error| anyhow::anyhow!("failed to access localStorage: {error:?}"))?
        .ok_or_else(|| anyhow::anyhow!("localStorage is not available"))?;
    let payload = PersistedOidcScaffold {
        expected_state: bundle.state.clone(),
        code_verifier: bundle.code_verifier.clone(),
        auth_server_url: auth_server_url.to_owned(),
        principal_server_url: principal_server_url.to_owned(),
        principal_actor_did: principal_actor_did.to_owned(),
        device_id: device_id.to_owned(),
        principal_audience: bundle.principal_audience.clone(),
        callback_uri: bundle.callback_uri.clone(),
        authorize_url: bundle.authorize_url.clone(),
    };
    storage
        .set_item(
            OIDC_SCAFFOLD_STORAGE_KEY,
            &serde_json::to_string(&payload)?,
        )
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
    let window = web_sys::window()
        .ok_or_else(|| anyhow::anyhow!("browser window is not available"))?;
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
    let window = web_sys::window()
        .ok_or_else(|| anyhow::anyhow!("browser window is not available"))?;
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
    let redirect_uri = current_oidc_redirect_uri();
    let client_id = resolve_oidc_client_id(topology, redirect_uri.as_str())?;
    build_authorize_url(
        topology,
        client_id.as_str(),
        redirect_uri.as_str(),
        actor_did,
        principal_audience,
        OIDC_STATE_PLACEHOLDER,
        OIDC_NONCE_PLACEHOLDER,
        OIDC_CODE_CHALLENGE_PLACEHOLDER,
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
        query.append_pair("login_hint", actor_did);
        query.append_pair("resource", principal_audience);
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
        client
            .redirect_uris
            .iter()
            .any(|candidate_redirect_uri| candidate_redirect_uri == redirect_uri)
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

fn principal_audience(principal_server_url: &str) -> anyhow::Result<String> {
    Ok(validate_server_url(principal_server_url)?
        .join("api")?
        .to_string()
        .trim_end_matches('/')
        .to_owned())
}

#[cfg(target_arch = "wasm32")]
fn current_oidc_redirect_uri() -> String {
    web_sys::window()
        .and_then(|window| window.location().origin().ok())
        .map(|origin| format!("{origin}/auth/callback"))
        .unwrap_or_else(|| YOUGEN_OIDC_REDIRECT_URI_NATIVE.to_owned())
}

#[cfg(not(target_arch = "wasm32"))]
fn current_oidc_redirect_uri() -> String {
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
