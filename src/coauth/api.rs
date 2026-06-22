use anyhow::Context;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use url::Url;

use super::proof::oidc_request_canonical_digest;
use super::{AccountLogoutRunOutcome, CoauthApi, OidcDiscoveryDocument, error_envelope_code};
use crate::config::validate_server_url;

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
    /// result that also includes session material. The login UI
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

    /// Rotate a near-expiry, DPoP-bound session grant onto a fresh one without
    /// re-running OIDC. This is the `/_cokret` protocol operation
    /// (`gate/account/session-grants/refresh`, service-http-binding session-grants
    /// surface): the caller presents a `DPoP` proof signed by the durable device
    /// key bound into the grant's `cnf.jkt`, and gets back a new grant (same
    /// subject/scope/audience, `cnf.jkt` constant, fresh expiry). The old grant
    /// is single-use revoked server-side. This is what lets a device session
    /// live for days while the grant rotates in place.
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
            device_id: None,
            proof: None,
        })?;
        self.post_json_with_dpop("session-grants/refresh", body, Some(dpop_proof))
            .await
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
    /// [`AccountLogoutRunOutcome`] so the durable journal can distinguish a
    /// provably-terminated chain (clear) from a retryable failure (retain).
    pub async fn account_logout(
        &self,
        grant_jwt: &str,
        dpop_proof: &str,
    ) -> anyhow::Result<AccountLogoutRunOutcome> {
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
            return Ok(AccountLogoutRunOutcome::Terminated);
        }
        // A missing grant means there is nothing left to revoke — terminal.
        if status.as_u16() == 404 {
            return Ok(AccountLogoutRunOutcome::Terminated);
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
            return Ok(AccountLogoutRunOutcome::Terminated);
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
    pub async fn device_enroll_signed_event(
        &self,
        grant_jwt: &str,
        dpop_proof: &str,
        device_id: &str,
        device_public_key: &str,
        actor_seq: u64,
        not_before: Option<&str>,
    ) -> anyhow::Result<Value> {
        let endpoint = self.endpoint("device-enroll")?;
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
        let text = response.text().await.context("read device-enroll body")?;
        if !status.is_success() {
            let code = error_envelope_code(&text);
            anyhow::bail!(
                "device-enroll failed: status={} code={} body={}",
                status.as_u16(),
                code.as_deref().unwrap_or("<none>"),
                text.chars().take(512).collect::<String>(),
            );
        }
        // coauth returns `DeviceAuthorizeOutcome { principal_id, device_id,
        // authority_did, event }`; the signed Event to submit is nested under
        // `event`. Extract it so the caller submits the envelope verbatim (not
        // the outcome wrapper, which has no `kind`/`proofs` and fails the
        // `parse_signed_device_authorize` envelope decode).
        let outcome: Value = serde_json::from_str(&text).context("parse device-enroll response")?;
        outcome
            .get("authorized_event")
            .cloned()
            .context("device-enroll response missing `authorized_event`")
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

    pub(crate) fn endpoint(&self, path: &str) -> anyhow::Result<Url> {
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
