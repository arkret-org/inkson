use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::api::CokretApi;
use crate::config::validate_server_url;

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
const OIDC_SCAFFOLD_STORAGE_KEY: &str = "yougen.oidc_scaffold.v1";

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
fn error_envelope_code(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    value
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(|code| code.as_str())
        .map(str::to_owned)
}

impl CoauthApi {
    pub fn new(base_url: &str) -> anyhow::Result<Self> {
        Ok(Self {
            base_url: validate_server_url(base_url)?,
            http: Client::new(),
        })
    }

    /// List invite-quarantine entries from coauth's admin endpoint. Admins
    /// receive every quarantined invite in the deployment; non-admin tokens
    /// 403 - the caller surfaces an inline "limited to your own invites"
    /// hint and falls back to [`Self::invite_quarantine_self`].
    pub async fn invite_quarantine_list(&self) -> anyhow::Result<Value> {
        anyhow::bail!(
            "coauth invite quarantine is a private coauth surface; yougen must not call private coauth paths"
        )
    }

    /// Per-user view of the caller's quarantined invites - surfaced for
    /// non-admin members so they can see what's gated on review without
    /// admin access. Backed by the same coauth admin endpoint via a
    /// self-scope query string.
    pub async fn invite_quarantine_self(&self) -> anyhow::Result<Value> {
        anyhow::bail!(
            "coauth invite quarantine is a private coauth surface; yougen must not call private coauth paths"
        )
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
        let _ = (invite_id, decision, reason);
        anyhow::bail!(
            "coauth invite quarantine is a private coauth surface; yougen must not call private coauth paths"
        )
    }

    /// Real OIDC token-endpoint exchange. Drives the PKCE authorization-code
    /// strand directly against the configured OIDC provider's `token_endpoint` -
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

    /// Private coauth session-grant refresh is intentionally unavailable to yougen.
    /// with a DPoP proof and the prior grant JWT. On success returns
    /// the rotated grant (single-use semantics: the old grant is now
    /// revoked).
    ///
    /// The DPoP proof MUST be minted against `htu` = absolute URL of
    /// the refresh endpoint and `htm` = `"POST"`, signed by the same
    /// key whose thumbprint is bound to the prior grant's `cnf.jkt`.
    /// Rotate a near-expiry, DPoP-bound session grant onto a fresh one without
    /// re-running OIDC. This is the `/_cokret` protocol operation
    /// (`gate/account/session-grants/refresh`, service-http-binding session-grants
    /// surface): the caller presents a `DPoP` proof signed by the durable device
    /// key bound into the grant's `cnf.jkt`, and gets back a new grant (same
    /// subject/scope/audience, `cnf.jkt` constant, fresh expiry). The old grant
    /// is single-use revoked server-side. This is what lets a device session
    /// live for days while access bearers stay short.
    pub async fn refresh_session_grant(
        &self,
        grant_jwt: &str,
        audience: Option<&str>,
        dpop_proof: &str,
    ) -> anyhow::Result<cokret_sdk::SessionGrantRefreshOutcome> {
        // Build the POST body from the spec's strong type so the `oneOf` /
        // required-field contract is enforced at compile time, not by hand.
        let body = serde_json::to_value(cokret_sdk::SessionGrantRefreshRequestBody {
            grant_jwt: grant_jwt.to_owned(),
            audience: audience
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned),
        })?;
        self.post_json_with_dpop(
            "_cokret/gate/account/session-grants/refresh",
            body,
            Some(dpop_proof),
        )
        .await
    }

    /// Hard-logout revocation at the Auth Server (account-lifecycle §4.1):
    /// present the device holder proof bound into the grant's `cnf.jkt`, and the
    /// server revokes the grant + finishes the underlying browser session so the
    /// rotation chain cannot be resumed.
    ///
    /// Returns a structured [`SessionGrantRevokeOutcome`] so the durable-logout
    /// retry can distinguish two cases that look alike at the HTTP layer:
    ///
    /// * **terminated** (2xx, or a 404 / `grant_already_consumed` / `session_logged_out` /
    ///   `session_grant_not_found` envelope) — the grant chain is provably gone; the caller MAY
    ///   clear its journal.
    /// * **failure** (any other 4xx — `device_proof_required`, an invalid DPoP proof, a bad body,
    ///   an `audience_mismatch` — or any 5xx / transport error) — the server did NOT terminate
    ///   anything; the caller MUST keep the journal and retry. This is the key fix over
    ///   string-matching the raw error: a 400 caused by a malformed proof is no longer mistaken for
    ///   "already revoked".
    pub async fn revoke_session_grant(
        &self,
        grant_jwt: &str,
        dpop_proof: &str,
    ) -> anyhow::Result<SessionGrantRevokeOutcome> {
        let endpoint = self.endpoint("_cokret/gate/account/session-grants/logout")?;
        let body = cokret_sdk::SessionGrantLogoutRequestBody {
            grant_jwt: grant_jwt.to_owned(),
        };
        let response = self
            .http
            .post(endpoint)
            .header("DPoP", dpop_proof)
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            return Ok(SessionGrantRevokeOutcome::Terminated);
        }

        // A missing grant means there is nothing left to revoke — terminal.
        if status.as_u16() == 404 {
            return Ok(SessionGrantRevokeOutcome::Terminated);
        }

        // Decode the structured error envelope (`{ error: { code } }`) and only
        // treat *grant-already-gone* codes as terminal. Everything else (proof
        // problems, audience mismatch, malformed body, server errors) keeps the
        // journal so the logout is retried.
        let body = response.text().await.unwrap_or_default();
        let code = error_envelope_code(&body);
        if let Some(code) = code.as_deref()
            && matches!(
                code,
                "grant_already_consumed"
                    | "session_logged_out"
                    | "session_grant_not_found"
                    | "authorized_grant_revoked"
            )
        {
            return Ok(SessionGrantRevokeOutcome::Terminated);
        }

        Err(anyhow::anyhow!(
            "coauth session-grant logout failed: status={} code={} body={body}",
            status.as_u16(),
            code.as_deref().unwrap_or("<none>"),
        ))
    }

    /// Standard OIDC discovery (`/.well-known/openid-configuration`) for the
    /// chosen `methods[].oidc`. `openid_configuration` is taken verbatim from
    /// the auth method when present; otherwise it is derived from the issuer.
    /// No Cokret-private OAuth endpoint family is involved — this is plain
    /// OpenID Connect Discovery 1.0.
    pub async fn fetch_oidc_discovery(
        discovery_url: &str,
    ) -> anyhow::Result<OidcDiscoveryDocument> {
        let url = Url::parse(discovery_url)
            .with_context(|| format!("invalid OIDC discovery URL: {discovery_url}"))?;
        Ok(Client::new()
            .get(url)
            .send()
            .await
            .context("OIDC discovery request failed")?
            .error_for_status()
            .context("OIDC discovery returned an error status")?
            .json()
            .await
            .context("parse OIDC discovery document")?)
    }

    /// T1.Y1 — issue a `ck.session.grant` from an OIDC authorization-code
    /// callback. POSTs a SDK-canonical [`cokret_sdk::SessionGrantRequestBody`]
    /// with `proof.proof_kind = oidc_code_exchange` to
    /// `{gate_account_base}/session-grants`; the Account Authority redeems the
    /// `authorization_code` + `code_verifier` at the issuer `token_endpoint`,
    /// validates issuer/state/nonce/redirect/PKCE/principal/audience and the
    /// `DPoP` holder proof (binding the grant to `cnf.jkt`), and returns a
    /// device-bound [`cokret_sdk::SessionGrantOutcome`].
    ///
    /// `self` MUST be rooted at the resolved `gate_account_base`.
    #[allow(clippy::too_many_arguments)]
    pub async fn issue_session_grant_oidc(
        &self,
        principal_id: &str,
        device_id: &str,
        issuer: &str,
        client_id: &str,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        authorization_code: &str,
        code_verifier: &str,
        audience: &str,
        requested_scope: Vec<String>,
        dpop_proof: &str,
    ) -> anyhow::Result<cokret_sdk::SessionGrantOutcome> {
        // First sign-in (② contract D5) omits the principal DID: the client does
        // not yet know it, and the Account Authority derives it from the OIDC
        // subject (returned in `SessionGrantOutcome.principal_id`). A blank hint
        // is therefore sent as `None`; only a non-empty hint is validated and
        // forwarded for the re-auth binding check.
        let principal_id = {
            let trimmed = principal_id.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(
                    cokret_sdk::Did::new(trimmed.to_owned())
                        .map_err(|error| anyhow::anyhow!("invalid principal_id DID: {error}"))?,
                )
            }
        };
        let device_id = cokret_sdk::DeviceId::new(device_id.trim().to_owned())
            .map_err(|error| anyhow::anyhow!("invalid device_id: {error}"))?;
        let proof = cokret_sdk::SessionGrantRequestProof {
            proof_kind: cokret_sdk::SessionGrantProofKind::OidcCodeExchange,
            // The DPoP holder proof (DPoP header) carries the device binding;
            // the authorization-code exchange itself is the authentication
            // material. `challenge` / `signature` are not consulted for the
            // oidc_code_exchange branch, but the wire struct requires them.
            challenge: String::new(),
            request_canonical_digest: oidc_request_canonical_digest(
                issuer,
                client_id,
                authorization_code,
                state,
            )?,
            audience: audience.to_owned(),
            expires_at: None,
            signature: String::new(),
            // Agent-runtime overlay (CKP-0008 §4.6); absent for the
            // human oidc_code_exchange proof kind.
            verification_method: None,
            issuer: Some(issuer.to_owned()),
            client_id: Some(client_id.to_owned()),
            redirect_uri: Some(redirect_uri.to_owned()),
            state: Some(state.to_owned()),
            nonce: Some(nonce.to_owned()),
            authorization_code: Some(authorization_code.to_owned()),
            code_verifier: Some(code_verifier.to_owned()),
        };
        let body = cokret_sdk::SessionGrantRequestBody {
            // ②(A+②) D5: `principal_id` is optional — on true first login the
            // client may not know its DID and the Account Authority derives it
            // (returned in `SessionGrantOutcome.principal_id`). We still forward
            // the resolved/known DID when available (see above: `None` on first
            // sign-in, `Some(did)` on re-auth).
            principal_id,
            device_id: Some(device_id),
            requested_scope,
            agent_key_authorization_ref: None,
            agent_scope_request: Value::Null,
            proof,
        };
        self.post_json_with_dpop(
            "session-grants",
            serde_json::to_value(&body)?,
            Some(dpop_proof),
        )
        .await
    }

    /// T1.Y3 — single client-visible hard logout (account-lifecycle §4.1).
    /// POSTs to `{gate_account_base}/logout` with `Authorization: Bearer
    /// <ck.session.grant>` + a `DPoP` holder proof; the Account Authority
    /// internally terminates BOTH the Auth-side grant rotation chain +
    /// `browser_session` AND the Principal-side account/device session. The
    /// client MUST NOT fan out to two origins.
    ///
    /// `self` MUST be rooted at the resolved `gate_account_base`. Returns a
    /// [`SessionGrantRevokeOutcome`] so the durable journal can distinguish a
    /// provably-terminated chain (clear) from a retryable failure (retain).
    pub async fn account_logout(
        &self,
        grant_jwt: &str,
        dpop_proof: &str,
    ) -> anyhow::Result<SessionGrantRevokeOutcome> {
        let endpoint = self.endpoint("logout")?;
        let response = self
            .http
            .post(endpoint)
            .bearer_auth(grant_jwt)
            .header("DPoP", dpop_proof)
            .json(&cokret_sdk::AccountLogoutRequestBody::default())
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            return Ok(SessionGrantRevokeOutcome::Terminated);
        }
        // A missing grant means there is nothing left to revoke — terminal.
        if status.as_u16() == 404 {
            return Ok(SessionGrantRevokeOutcome::Terminated);
        }
        let body = response.text().await.unwrap_or_default();
        let code = error_envelope_code(&body);
        if let Some(code) = code.as_deref()
            && matches!(
                code,
                "grant_already_consumed"
                    | "session_logged_out"
                    | "session_grant_not_found"
                    | "authorized_grant_revoked"
            )
        {
            return Ok(SessionGrantRevokeOutcome::Terminated);
        }
        Err(anyhow::anyhow!(
            "account authority logout failed: status={} code={} body={body}",
            status.as_u16(),
            code.as_deref().unwrap_or("<none>"),
        ))
    }

    /// Enrollment-authority signing oracle for the current session device
    /// (decision 0002, device-lifecycle.md §5.4). The Account Authority holds
    /// the persistent enrollment signing key; the client cannot produce a
    /// `service_attested` `ck.device.authorize` proof itself. The client sends
    /// the session's `device_id`, the device's `device_public_key`, and the next
    /// `actor_seq` on the principal control stream; coauth verifies the
    /// authenticated session owns that principal, assembles the
    /// `ck.device.authorize` Event for that `device_id` (with `executed_by` /
    /// `authorization_ref` / `enrollment_authority_binding`), signs it with the
    /// enrollment key, and returns the fully-signed Event. The caller submits it
    /// verbatim to the Principal Server's `POST /_cokret/self/events`.
    ///
    /// `self` MUST be rooted at the resolved `gate_account_base`. `grant_jwt` is
    /// the active `ck.session.grant`; `dpop_proof` is the device holder proof
    /// bound to the grant's `cnf.jkt`.
    pub async fn device_authorize_signed_event(
        &self,
        grant_jwt: &str,
        dpop_proof: &str,
        device_id: &str,
        device_public_key: &str,
        actor_seq: u64,
        not_before: Option<&str>,
    ) -> anyhow::Result<Value> {
        let endpoint = self.endpoint("device-authorize")?;
        let mut body = json!({
            "device_id": device_id,
            "device_public_key": device_public_key,
            "actor_seq": actor_seq,
        });
        if let Some(not_before) = not_before.filter(|value| !value.trim().is_empty()) {
            body["not_before"] = Value::String(not_before.to_owned());
        }
        let response = self
            .http
            .post(endpoint)
            .bearer_auth(grant_jwt)
            .header("DPoP", dpop_proof)
            .json(&body)
            .send()
            .await?;
        let status = response.status();
        let text = response.text().await.context("read device-authorize body")?;
        if !status.is_success() {
            let code = error_envelope_code(&text);
            anyhow::bail!(
                "device-authorize failed: status={} code={} body={}",
                status.as_u16(),
                code.as_deref().unwrap_or("<none>"),
                text.chars().take(512).collect::<String>(),
            );
        }
        serde_json::from_str(&text).context("parse device-authorize signed event")
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
        self.post_json_with_dpop(path, body, None).await
    }

    async fn post_json_with_dpop<T: DeserializeOwned>(
        &self,
        path: &str,
        body: Value,
        dpop_proof: Option<&str>,
    ) -> anyhow::Result<T> {
        let mut request = self.http.post(self.endpoint(path)?).json(&body);
        if let Some(proof) = dpop_proof.filter(|proof| !proof.trim().is_empty()) {
            request = request.header("DPoP", proof);
        }
        Ok(request.send().await?.error_for_status()?.json().await?)
    }

    pub fn endpoint_url(&self, path: &str) -> anyhow::Result<String> {
        Ok(self.endpoint(path)?.to_string())
    }

    fn endpoint(&self, path: &str) -> anyhow::Result<Url> {
        // The base may be a bare gate path (e.g. `…/_cokret/gate/account`) with
        // no trailing slash. RFC 3986 `join` would then REPLACE the last segment
        // (`account`) instead of appending — silently producing
        // `…/_cokret/gate/session-grants` and 404-ing. Ensure the base path ends
        // in `/` so a relative segment appends. Origin bases already end in `/`,
        // so this is a no-op for the full-path callers (refresh/revoke).
        let mut base = self.base_url.clone();
        if !base.path().ends_with('/') {
            let with_slash = format!("{}/", base.path());
            base.set_path(&with_slash);
        }
        Ok(base.join(path.trim_start_matches('/'))?)
    }
}

/// R3.2 (YG-HC-1) — best-effort deep link to the issuer/coauth handle
/// issuance strand (`/handles/me`). yougen does NOT manage handle lifecycle
/// (per spec §3.2.3 / §3.4): `ck.profile.update` /
/// `ck.member.identity.update` MUST NOT set or override handles. Instead
/// the settings UI surfaces "Handle managed by your organization" with a
/// link out to the issuer strand, where the org-run issuer signs
/// `ck.schema.handle_claim.v1` evidence.
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
    pub principal_audience: String,
}

/// T1.Y4 — Account Authority resolver. The Principal Server's root
/// `/_cokret/describe` (service-surface §2.5.1) publishes a strongly-typed
/// `auth_metadata.account_authority.gate_account_base`; every Cokret
/// `/_cokret/gate/account/*` request MUST be derived from that single base
/// (a [`CoauthApi`] rooted at it), and the available authentication methods
/// come from `auth_metadata.methods[]`.
///
/// The resolver fails closed: if the describe response carries neither a
/// strong `account_authority` nor the legacy `auth_server_url` / `oauth_issuer`
/// aliases, it errors instead of guessing a per-operation route.
#[derive(Clone, Debug)]
pub struct AuthorityResolver {
    /// Absolute `gate_account_base` — the only origin client `gate/account`
    /// calls are routed to (service-surface §2.5.1).
    pub gate_account_base: String,
    /// Principal Server origin that published the describe response.
    pub principal_server_url: String,
    /// Audience the issued grant / bearer authenticates against.
    pub principal_audience: String,
    /// Authentication methods the Account Authority accepts.
    pub methods: Vec<cokret_sdk::AuthMethod>,
}

impl AuthorityResolver {
    /// Discover the Account Authority from the Principal Server's root
    /// `/_cokret/describe` and its strongly-typed `auth_metadata`.
    pub async fn discover(principal_server_url: &str) -> anyhow::Result<Self> {
        let principal = CokretApi::new(principal_server_url)?;
        let description = principal.describe().await?;
        Self::from_description(principal_server_url, &description)
    }

    pub(crate) fn from_description(
        principal_server_url: &str,
        description: &cokret_sdk::ServerDescription,
    ) -> anyhow::Result<Self> {
        let metadata = &description.auth_metadata;
        let gate_account_base = resolve_gate_account_base(principal_server_url, metadata)?;
        let principal_audience = {
            let service_did = description.service_did.as_str().trim();
            if service_did.is_empty() {
                principal_audience(principal_server_url)?
            } else {
                service_did.to_owned()
            }
        };
        Ok(Self {
            gate_account_base,
            principal_server_url: principal_server_url.to_owned(),
            principal_audience,
            methods: metadata.methods.clone(),
        })
    }

    /// A [`CoauthApi`] rooted at the resolved `gate_account_base`. Every
    /// `gate/account` call (session-grants, refresh, logout) goes through it.
    pub fn gate_account_client(&self) -> anyhow::Result<CoauthApi> {
        CoauthApi::new(&self.gate_account_base)
    }

    /// Pick the first `oidc` method, falling back to a synthesised one when the
    /// server only published the legacy `auth_server_url` / `oauth_issuer`
    /// aliases (older Principal Servers that predate `methods[]`).
    pub fn oidc_method(
        &self,
        metadata: Option<&cokret_sdk::AuthMetadata>,
    ) -> anyhow::Result<cokret_sdk::AuthMethod> {
        if let Some(method) = self
            .methods
            .iter()
            .find(|method| method.method == cokret_sdk::AuthMethodKind::Oidc)
        {
            return Ok(method.clone());
        }
        // Legacy alias fallback.
        if let Some(metadata) = metadata {
            if let Some(method) = synthesize_oidc_method_from_aliases(metadata) {
                return Ok(method);
            }
        }
        anyhow::bail!(
            "principal server describe published no oidc auth method (methods[] empty and no auth_server_url/oauth_issuer alias)"
        )
    }
}

/// Derive the single client-visible `gate_account_base` from `auth_metadata`.
///
/// Order of preference (service-surface §2.5.1 + the legacy aliases the SDK
/// `AuthMetadata` retains for old servers):
///
/// 1. `account_authority.gate_account_base` — canonical.
/// 2. legacy `auth_server_url` alias — older deployments that ran the whole
///    Account Authority on the auth origin; derive `{origin}/_cokret/gate/account`.
/// 3. the Principal Server's own origin — personal deployments where the
///    Account Authority is co-located.
fn resolve_gate_account_base(
    principal_server_url: &str,
    metadata: &cokret_sdk::AuthMetadata,
) -> anyhow::Result<String> {
    if let Some(authority) = metadata.account_authority.as_ref() {
        let base = authority.gate_account_base.trim();
        if !base.is_empty() {
            return Ok(normalize_gate_account_base(base));
        }
        let origin = authority.origin.trim();
        if !origin.is_empty() {
            return Ok(gate_account_base_from_origin(origin)?);
        }
    }
    if let Some(auth_server_url) = metadata
        .auth_server_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return gate_account_base_from_origin(auth_server_url);
    }
    // Personal deployment: Account Authority co-located with the Principal
    // Server. Fail closed only if the URL itself is invalid.
    gate_account_base_from_origin(principal_server_url)
}

fn gate_account_base_from_origin(origin: &str) -> anyhow::Result<String> {
    let url = validate_server_url(origin)?;
    let base = url
        .join("_cokret/gate/account")
        .map_err(|error| anyhow::anyhow!("invalid gate account base from origin {origin}: {error}"))?;
    Ok(normalize_gate_account_base(base.as_str()))
}

fn normalize_gate_account_base(base: &str) -> String {
    base.trim_end_matches('/').to_owned()
}

/// Build an `oidc` [`cokret_sdk::AuthMethod`] from the legacy compatibility
/// aliases (`auth_server_url` / `oauth_issuer` / `openid_configuration`) so
/// pre-`methods[]` servers still drive standard OIDC discovery.
fn synthesize_oidc_method_from_aliases(
    metadata: &cokret_sdk::AuthMetadata,
) -> Option<cokret_sdk::AuthMethod> {
    let issuer = metadata
        .oauth_issuer
        .as_deref()
        .or(metadata.auth_server_url.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)?;
    let openid_configuration = metadata
        .openid_configuration
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| Some(format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'))));
    Some(cokret_sdk::AuthMethod {
        method: cokret_sdk::AuthMethodKind::Oidc,
        issuer: Some(issuer),
        provider: None,
        openid_configuration,
        client_id: None,
        scopes: Vec::new(),
        grant_exchange: cokret_sdk::AuthGrantExchange {
            proof_kind: cokret_sdk::SessionGrantProofKind::OidcCodeExchange,
        },
    })
}

pub(crate) async fn resolve_principal_auth_server(
    principal_server_url: &str,
) -> anyhow::Result<PrincipalAuthServerResolution> {
    let resolver = AuthorityResolver::discover(principal_server_url).await?;
    Ok(PrincipalAuthServerResolution {
        auth_server_url: resolver.gate_account_base.clone(),
        principal_audience: resolver.principal_audience,
    })
}

pub fn active_oidc_redirect_uri() -> String {
    current_oidc_redirect_uri()
}

/// T1.Y1 — build the authorize scaffold (PKCE state/nonce/verifier + the full
/// `authorization_endpoint` URL) directly from standard OIDC discovery and the
/// chosen `methods[].oidc`, without any Cokret-private bridge. `client_id` is
/// taken from the auth method when published, else falls back to the native
/// yougen client id.
pub fn build_oidc_authorize_scaffold(
    discovery: &OidcDiscoveryDocument,
    method: &cokret_sdk::AuthMethod,
    redirect_uri: &str,
    login_hint: &str,
    device_id: &str,
    principal_audience: &str,
) -> anyhow::Result<OidcScaffoldBundle> {
    let client_id = method
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| YOUGEN_OIDC_CLIENT_ID.to_owned());
    let state = random_url_safe_token(STATE_NONCE_TOKEN_BYTES)?;
    let nonce = random_url_safe_token(STATE_NONCE_TOKEN_BYTES)?;
    let code_verifier = random_url_safe_token(PKCE_VERIFIER_BYTES)?;
    let pkce_method = preferred_pkce_method(&discovery.code_challenge_methods_supported);
    let code_challenge = match pkce_method {
        Some("plain") => code_verifier.clone(),
        _ => pkce_code_challenge_s256(&code_verifier),
    };
    let authorize_url = build_standard_authorize_url(
        discovery,
        method,
        &client_id,
        redirect_uri,
        login_hint,
        device_id,
        principal_audience,
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
        callback_uri: redirect_uri.to_owned(),
        principal_audience: principal_audience.to_owned(),
        todo: "Closed: standard OIDC discovery + PKCE authorize; the login callback exchanges the code at the Account Authority session-grants endpoint.",
    })
}

/// Build a standard OpenID Connect authorization-code + PKCE authorize URL
/// from a discovery document and auth method. No Cokret-private scopes are
/// required: `scope` defaults to `openid` plus any `methods[].scopes`, and the
/// stable device binding rides as a `urn:cokret:client:device:{id}` scope.
#[allow(clippy::too_many_arguments)]
fn build_standard_authorize_url(
    discovery: &OidcDiscoveryDocument,
    method: &cokret_sdk::AuthMethod,
    client_id: &str,
    redirect_uri: &str,
    login_hint: &str,
    device_id: &str,
    principal_audience: &str,
    state: &str,
    nonce: &str,
    code_challenge: &str,
) -> anyhow::Result<String> {
    let mut url = Url::parse(&discovery.authorization_endpoint)
        .with_context(|| format!("invalid authorization_endpoint: {}", discovery.authorization_endpoint))?;
    let mut scope_tokens: Vec<String> = vec!["openid".to_owned()];
    for scope in &method.scopes {
        let scope = scope.trim();
        if !scope.is_empty() && !scope_tokens.iter().any(|existing| existing == scope) {
            scope_tokens.push(scope.to_owned());
        }
    }
    // Standard offline_access for refresh tokens when the issuer advertises it.
    if discovery
        .scopes_supported
        .iter()
        .any(|scope| scope == "offline_access")
        && !scope_tokens.iter().any(|scope| scope == "offline_access")
    {
        scope_tokens.push("offline_access".to_owned());
    }
    // Bind this OAuth session to the stable device id so introspection returns
    // a stable `org.cokret.device_id` (avoids per-session device drift →
    // cursor_integrity_invalid). This is a parameterized capability scope,
    // accepted verbatim by the issuer; not gated by discovery scopes_supported.
    let device_id = device_id.trim();
    if !device_id.is_empty() {
        scope_tokens.push(format!("{COKRET_DEVICE_SCOPE_PREFIX}{device_id}"));
    }
    let scope = scope_tokens.join(" ");
    let pkce_method = preferred_pkce_method(&discovery.code_challenge_methods_supported);
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", client_id);
        query.append_pair("redirect_uri", redirect_uri);
        query.append_pair("scope", &scope);
        query.append_pair("state", state);
        query.append_pair("nonce", nonce);
        if !login_hint.trim().is_empty() {
            query.append_pair("login_hint", login_hint);
        }
        query.append_pair("resource", principal_audience);
        // OIDC Core §3.1.2.1: force re-prompt so an app-level logout is not
        // silently undone by a live IdP SSO cookie.
        query.append_pair("prompt", "login");
        query.append_pair("max_age", "0");
        if let Some(pkce_method) = pkce_method {
            query.append_pair("code_challenge_method", pkce_method);
            query.append_pair("code_challenge", code_challenge);
        }
    }
    Ok(url.to_string())
}

/// Session-grant introspection proof claims. Mirrors
/// coauth's `SessionGrantIntrospectionProofClaims` (see
/// `coauth/crates/backend/src/handlers/cokret.rs:575`). soland forwards
/// the proof to coauth's private introspection endpoint when validating
/// a session-grant binding — the JWS MUST verify against
/// the session_public_key registered with the grant, and the
/// claims MUST match `grant_id` / `grant_jwt_hash` / `audience` /
/// `challenge` / `issued_at` / `expires_at` exactly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionGrantIntrospectionProofClaims {
    /// Always `"ck.session_grant.introspection_proof.v1"`.
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
        kind: "ck.session_grant.introspection_proof.v1".to_owned(),
        grant_id: grant_id.to_owned(),
        grant_jwt_hash: session_grant_jwt_hash(grant_jwt),
        audience: audience.to_owned(),
        challenge: challenge.to_owned(),
        issued_at: now,
        expires_at: now + chrono::Duration::seconds(60),
    };
    sign_compact_jws_eddsa(&claims, signing_key)
}

/// Deterministic `sha256:<hex>` digest binding the OIDC code-exchange request
/// fields. The Account Authority does not consult this for the
/// `oidc_code_exchange` branch (it re-validates against the issuer), but the
/// SDK [`cokret_sdk::SessionGrantRequestProof`] requires a valid [`Hash`], so
/// we compute a real content digest of the binding fields rather than ship a
/// placeholder.
fn oidc_request_canonical_digest(
    issuer: &str,
    client_id: &str,
    authorization_code: &str,
    state: &str,
) -> anyhow::Result<cokret_sdk::Hash> {
    let canonical = format!("oidc_code_exchange|{issuer}|{client_id}|{authorization_code}|{state}");
    let digest = format!(
        "sha256:{}",
        crate::canonical::hex_encode(&Sha256::digest(canonical.as_bytes()))
    );
    cokret_sdk::Hash::new(digest)
        .map_err(|error| anyhow::anyhow!("invalid oidc request digest: {error}"))
}

/// Hash the grant JWT bytes per coauth's `session_grant_jwt_hash`
/// (`"sha256:" + hex(sha256(grant_jwt))`). Public so callers can verify
/// their proof binding before sending.
pub fn session_grant_jwt_hash(grant_jwt: &str) -> String {
    format!(
        "sha256:{}",
        crate::canonical::hex_encode(&Sha256::digest(grant_jwt.as_bytes()))
    )
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

/// Assemble the durable scaffold record from a freshly-built authorize bundle
/// plus the resolved Account Authority routing. Persisted across the browser
/// redirect so the callback can restore PKCE verifier / state / nonce and the
/// `gate_account_base` to POST the session-grant to.
#[allow(clippy::too_many_arguments)]
pub fn build_persisted_oidc_scaffold(
    bundle: &OidcScaffoldBundle,
    gate_account_base: &str,
    principal_server_url: &str,
    principal_actor_id: &str,
    device_id: &str,
    issuer: &str,
) -> PersistedOidcScaffold {
    PersistedOidcScaffold {
        expected_state: bundle.state.clone(),
        expected_nonce: bundle.nonce.clone(),
        code_verifier: bundle.code_verifier.clone(),
        client_id: bundle.client_id.clone(),
        auth_server_url: gate_account_base.to_owned(),
        principal_server_url: principal_server_url.to_owned(),
        principal_actor_id: principal_actor_id.to_owned(),
        device_id: device_id.to_owned(),
        principal_audience: bundle.principal_audience.clone(),
        callback_uri: bundle.callback_uri.clone(),
        authorize_url: bundle.authorize_url.clone(),
        issuer: issuer.to_owned(),
        gate_account_base: gate_account_base.to_owned(),
    }
}

#[cfg(target_arch = "wasm32")]
pub fn persist_oidc_scaffold(payload: &PersistedOidcScaffold) -> anyhow::Result<()> {
    let window =
        web_sys::window().ok_or_else(|| anyhow::anyhow!("browser window is not available"))?;
    let storage = window
        .local_storage()
        .map_err(|error| anyhow::anyhow!("failed to access localStorage: {error:?}"))?
        .ok_or_else(|| anyhow::anyhow!("localStorage is not available"))?;
    storage
        .set_item(OIDC_SCAFFOLD_STORAGE_KEY, &serde_json::to_string(payload)?)
        .map_err(|error| anyhow::anyhow!("failed to persist OIDC scaffold: {error:?}"))?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn persist_oidc_scaffold(_payload: &PersistedOidcScaffold) -> anyhow::Result<()> {
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

    /// Regression: a `gate_account_base` like `…/_cokret/gate/account` has no
    /// trailing slash, so a naive `Url::join("session-grants")` would REPLACE the
    /// `account` segment and POST to `…/_cokret/gate/session-grants` (404). The
    /// `endpoint` helper must instead APPEND, preserving `account`.
    #[test]
    fn endpoint_appends_relative_path_to_bare_gate_account_base() {
        let api = CoauthApi::new("https://local.host/_cokret/gate/account").unwrap();
        assert_eq!(
            api.endpoint("session-grants").unwrap().as_str(),
            "https://local.host/_cokret/gate/account/session-grants"
        );
        assert_eq!(
            api.endpoint("logout").unwrap().as_str(),
            "https://local.host/_cokret/gate/account/logout"
        );
    }

    /// An origin-rooted base (used by refresh/revoke with full paths) already
    /// ends in `/`, so the slash-normalisation is a no-op and full paths resolve
    /// from the origin root unchanged.
    #[test]
    fn endpoint_preserves_full_path_on_origin_base() {
        let api = CoauthApi::new("https://auth.local.host").unwrap();
        assert_eq!(
            api.endpoint("_cokret/gate/account/session-grants/refresh")
                .unwrap()
                .as_str(),
            "https://auth.local.host/_cokret/gate/account/session-grants/refresh"
        );
    }

    #[test]
    fn error_envelope_code_extracts_nested_code() {
        let body = r#"{"ok":false,"error":{"code":"grant_already_consumed","message":"gone"},"request_id":"r1"}"#;
        assert_eq!(
            error_envelope_code(body).as_deref(),
            Some("grant_already_consumed")
        );
    }

    #[test]
    fn error_envelope_code_handles_missing_or_malformed() {
        // Not JSON, empty, missing error.code — all yield None so the caller
        // treats the failure as retryable rather than a known terminal code.
        assert_eq!(error_envelope_code(""), None);
        assert_eq!(error_envelope_code("not json"), None);
        assert_eq!(error_envelope_code(r#"{"ok":false}"#), None);
        assert_eq!(error_envelope_code(r#"{"error":{"message":"x"}}"#), None);
    }

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
        let response: CoauthLoginOutcome = serde_json::from_value(json!({
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
                "scopes": ["urn:cokret:principal-server:session.bind"],
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

    #[test]
    fn login_response_accepts_one_shot_session_grant_without_private_key() {
        let response: CoauthLoginOutcome = serde_json::from_value(json!({
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
                "session_public_key": "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"mock\"}",
                "expires_at": "2026-05-13T04:00:00Z",
                "audience": "https://local.host/api",
                "scopes": ["urn:cokret:principal-server:session.bind"]
            }
        }))
        .unwrap();

        let grant = response.session_grant.expect("session grant");
        assert_eq!(grant.session_private_key_pem, "");
        assert_eq!(grant.audience.as_deref(), Some("https://local.host/api"));
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
    /// canonical claims, MUST embed `ck.session_grant.introspection_proof.v1`
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
            claims.kind, "ck.session_grant.introspection_proof.v1",
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

    fn test_discovery() -> OidcDiscoveryDocument {
        OidcDiscoveryDocument {
            issuer: "https://issuer.example".to_owned(),
            authorization_endpoint: "https://issuer.example/auth".to_owned(),
            token_endpoint: Some("https://issuer.example/token".to_owned()),
            userinfo_endpoint: Some("https://issuer.example/userinfo".to_owned()),
            code_challenge_methods_supported: vec!["S256".to_owned()],
            scopes_supported: vec!["openid".to_owned(), "offline_access".to_owned()],
        }
    }

    fn test_oidc_method() -> cokret_sdk::AuthMethod {
        cokret_sdk::AuthMethod {
            method: cokret_sdk::AuthMethodKind::Oidc,
            issuer: Some("https://issuer.example".to_owned()),
            provider: None,
            openid_configuration: Some(
                "https://issuer.example/.well-known/openid-configuration".to_owned(),
            ),
            client_id: Some("yougen-test".to_owned()),
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
            grant_exchange: cokret_sdk::AuthGrantExchange {
                proof_kind: cokret_sdk::SessionGrantProofKind::OidcCodeExchange,
            },
        }
    }

    /// State and nonce tokens MUST diverge across calls (RFC 6749 §10.12 /
    /// RFC 7636 unguessability).
    #[test]
    fn state_and_nonce_diverge_for_same_caller() {
        let discovery = test_discovery();
        let method = test_oidc_method();
        let bundle_a = build_oidc_authorize_scaffold(
            &discovery,
            &method,
            "https://app.example/auth/callback",
            "",
            "device-aaaa-1111",
            "https://principal.example/api",
        )
        .unwrap();
        let bundle_b = build_oidc_authorize_scaffold(
            &discovery,
            &method,
            "https://app.example/auth/callback",
            "",
            "device-aaaa-1111",
            "https://principal.example/api",
        )
        .unwrap();
        assert_ne!(bundle_a.state, bundle_b.state);
        assert_ne!(bundle_a.nonce, bundle_b.nonce);
        assert_ne!(bundle_a.code_verifier, bundle_b.code_verifier);
        assert_ne!(bundle_a.state, bundle_a.nonce);
    }

    /// `code_challenge` MUST be S256(code_verifier) when discovery supports S256.
    #[test]
    fn bundle_challenge_is_s256_of_verifier_when_supported() {
        let bundle = build_oidc_authorize_scaffold(
            &test_discovery(),
            &test_oidc_method(),
            "https://app.example/auth/callback",
            "",
            "device-bbbb-2222",
            "https://principal.example/api",
        )
        .unwrap();
        assert_eq!(
            bundle.code_challenge,
            pkce_code_challenge_s256(&bundle.code_verifier),
            "S256 discovery must produce S256(verifier) challenge"
        );
    }

    /// The authorize URL forces re-authentication (prompt=login, max_age=0).
    #[test]
    fn authorize_url_forces_reauthentication() {
        let bundle = build_oidc_authorize_scaffold(
            &test_discovery(),
            &test_oidc_method(),
            "https://app.example/auth/callback",
            "",
            "device-cccc-3333",
            "https://principal.example/api",
        )
        .unwrap();
        let parsed = Url::parse(&bundle.authorize_url).unwrap();
        assert_eq!(
            parsed.query_pairs().find(|(key, _)| key == "prompt").unwrap().1,
            "login"
        );
        assert_eq!(
            parsed.query_pairs().find(|(key, _)| key == "max_age").unwrap().1,
            "0"
        );
    }

    /// The authorize URL MUST request `openid`, the method scopes, and the
    /// stable device-binding scope (prevents cursor_integrity_invalid drift).
    #[test]
    fn authorize_url_requests_standard_and_device_scope() {
        let bundle = build_oidc_authorize_scaffold(
            &test_discovery(),
            &test_oidc_method(),
            "https://app.example/auth/callback",
            "",
            "device-dddd-4444",
            "https://principal.example/api",
        )
        .unwrap();
        let parsed = Url::parse(&bundle.authorize_url).unwrap();
        let requested_scope = parsed
            .query_pairs()
            .find(|(key, _)| key == "scope")
            .unwrap()
            .1
            .into_owned();
        let scopes: Vec<&str> = requested_scope.split_ascii_whitespace().collect();
        assert!(scopes.contains(&"openid"));
        assert!(scopes.contains(&"profile"));
        assert!(
            scopes.contains(&format!("{COKRET_DEVICE_SCOPE_PREFIX}device-dddd-4444").as_str()),
            "authorize URL must request the device-binding scope, got: {requested_scope}"
        );
    }

    /// `client_id` falls back to the native yougen id when the method omits it.
    #[test]
    fn authorize_url_falls_back_to_native_client_id() {
        let mut method = test_oidc_method();
        method.client_id = None;
        let bundle = build_oidc_authorize_scaffold(
            &test_discovery(),
            &method,
            "https://app.example/auth/callback",
            "",
            "device-eeee-5555",
            "https://principal.example/api",
        )
        .unwrap();
        assert_eq!(bundle.client_id, YOUGEN_OIDC_CLIENT_ID);
        let parsed = Url::parse(&bundle.authorize_url).unwrap();
        assert_eq!(
            parsed.query_pairs().find(|(key, _)| key == "client_id").unwrap().1,
            YOUGEN_OIDC_CLIENT_ID
        );
    }

    /// The legacy alias fallback synthesises an oidc method from
    /// `auth_server_url` / `oauth_issuer` when `methods[]` is empty.
    #[test]
    fn synthesizes_oidc_method_from_legacy_aliases() {
        let mut metadata = cokret_sdk::AuthMetadata::minimal("production");
        metadata.auth_server_url = Some("https://auth.example".to_owned());
        let method = synthesize_oidc_method_from_aliases(&metadata).expect("synthesized method");
        assert_eq!(method.method, cokret_sdk::AuthMethodKind::Oidc);
        assert_eq!(method.issuer.as_deref(), Some("https://auth.example"));
        assert_eq!(
            method.openid_configuration.as_deref(),
            Some("https://auth.example/.well-known/openid-configuration")
        );
    }

    /// `gate_account_base` derivation: prefer the strong account_authority,
    /// then the legacy auth_server_url alias, else the principal origin.
    #[test]
    fn resolve_gate_account_base_prefers_account_authority() {
        let mut metadata = cokret_sdk::AuthMetadata::minimal("production");
        metadata.account_authority = Some(cokret_sdk::AccountAuthority {
            origin: "https://aa.example".to_owned(),
            gate_account_base: "https://aa.example/_cokret/gate/account".to_owned(),
        });
        let base = resolve_gate_account_base("https://principal.example", &metadata).unwrap();
        assert_eq!(base, "https://aa.example/_cokret/gate/account");
    }

    #[test]
    fn resolve_gate_account_base_falls_back_to_auth_server_url() {
        let mut metadata = cokret_sdk::AuthMetadata::minimal("production");
        metadata.auth_server_url = Some("https://auth.example".to_owned());
        let base = resolve_gate_account_base("https://principal.example", &metadata).unwrap();
        assert_eq!(base, "https://auth.example/_cokret/gate/account");
    }

    #[test]
    fn resolve_gate_account_base_falls_back_to_principal_origin() {
        let metadata = cokret_sdk::AuthMetadata::minimal("production");
        let base = resolve_gate_account_base("https://principal.example", &metadata).unwrap();
        assert_eq!(base, "https://principal.example/_cokret/gate/account");
    }
}
