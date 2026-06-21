//! Core HTTP transport for [`CokretApi`]: constructor + builder methods, the
//! request pipeline (authorize / wait-for / PoP signing / per-request DPoP),
//! retry/backoff loop, and the typed JSON/bytes send helpers. Structural move
//! out of `api/mod.rs` with no logic change. Methods invoked by sibling
//! submodules (e.g. `account`, `events`, `keys`) are `pub(crate)` so they
//! remain reachable now that they no longer live in the parent module; the
//! rest stay private to this transport core.

use super::*;

impl CokretApi {
    pub fn new(base_url: &str) -> anyhow::Result<Self> {
        Self::new_with_options(base_url, CokretApiOptions::default())
    }

    pub fn new_with_options(base_url: &str, options: CokretApiOptions) -> anyhow::Result<Self> {
        let base_url = validate_server_url(base_url)?;
        let http = Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let http = http.timeout(options.timeout);

        Ok(Self {
            base_url,
            http: http.build()?,
            access_token: None,
            wait_for_sync_token: None,
            retry: options.retry,
            chime_session_grant: None,
            chime_session_grant_proof: None,
            session_grant_proof: None,
            network_state: Arc::new(RwLock::new(NetworkState::Online)),
            cancel_token: None,
            session_signing_key: None,
            session_key_id: None,
            dpop_device: None,
            events_describe_cache: Arc::new(OnceCell::new()),
            service_describe_cache: Arc::new(OnceCell::new()),
        })
    }

    /// Attach the coauth session-grant material chime requires for
    /// push registration. `proof` should be present when the Principal
    /// Server validates the grant through coauth introspection.
    pub fn with_chime_session_grant(
        mut self,
        grant_jwt: impl Into<String>,
        proof: Option<SessionGrantIntrospectionProof>,
    ) -> Self {
        self.chime_session_grant = Some(grant_jwt.into());
        self.chime_session_grant_proof = proof;
        self
    }

    /// Set the credential presented as `Authorization: Bearer <…>` on
    /// `/_cokret/self/*` requests.
    ///
    /// ②(A+②) model (api-conventions.md §3.3): the Principal Server no longer
    /// mints a local bearer and there is no grant→bearer exchange. The held
    /// credential is the `ck.session.grant` itself, so callers pass the grant
    /// JWT here. Combined with [`Self::with_dpop_device`], each request then
    /// carries `Authorization: Bearer <grant>` plus a per-request `DPoP` proof
    /// bound to that grant (`ath=hash(grant)`).
    ///
    /// The dev-login bare bearer and coauth OAuth access-token introspection
    /// paths remain valid inbound credentials server-side, so passing a raw
    /// bearer here (with no DPoP device) still works for those legacy paths.
    pub fn with_bearer(mut self, access_token: impl Into<String>) -> Self {
        self.access_token = Some(access_token.into());
        self
    }

    /// ②(A+②) — bind the device DPoP holder key so every `/_cokret/self/*`
    /// request mints a fresh per-request `DPoP` proof (RFC 9449) bound to the
    /// grant in `access_token`. Centralized minting happens in the request
    /// pipeline ([`Self::attach_self_path_dpop`]); call sites only attach the
    /// key once. The grant must already be set via [`Self::with_bearer`] for the
    /// `ath` binding to be present.
    /// ②(A+②) — attach the session-grant holder proof presented on every
    /// `/_cokret/self/*` request (headers `X-Cokret-Session-Grant-Challenge` +
    /// `-Proof`). coauth's grant introspection requires it to confirm the caller
    /// holds the grant's session key; soland forwards it verbatim. Mint it from
    /// the same device key as the grant's `cnf.jkt` via
    /// [`crate::auth_dpop::DpopHandle::mint_session_grant_introspection_proof`].
    pub fn with_session_grant_proof(mut self, proof: SessionGrantIntrospectionProof) -> Self {
        self.session_grant_proof = Some(proof);
        self
    }

    pub fn with_dpop_device(mut self, handle: crate::auth_dpop::DpopHandle) -> Self {
        self.dpop_device = Some(handle);
        self
    }

    /// SPEC-CR-001 — bind the `ck.session.grant` session key so requests to
    /// `/_cokret/self/*` are RFC 9421 PoP-signed. `session_private_key_pem` is
    /// the PKCS#8 PEM returned by the grant exchange; the keyid is the key's
    /// RFC 7638 thumbprint, which soland accepts for the binding check.
    pub fn with_session_signing_key(
        mut self,
        session_private_key_pem: &str,
    ) -> anyhow::Result<Self> {
        let signing_key =
            crate::coauth::session_grant_signing_key_from_pem(session_private_key_pem)?;
        self.session_key_id = Some(session_key_thumbprint(&signing_key.verifying_key()));
        self.session_signing_key = Some(signing_key);
        Ok(self)
    }

    pub fn with_wait_for(mut self, sync_token: impl Into<String>) -> Self {
        let sync_token = sync_token.into();
        self.wait_for_sync_token = normalize_wait_for_sync_token(&sync_token);
        self
    }

    /// Set a cancellation token for this API client.
    /// When the token is cancelled, in-flight requests will be aborted.
    pub fn with_cancel(mut self, token: CancellationToken) -> Self {
        self.cancel_token = Some(token);
        self
    }

    /// Get the current network state.
    pub async fn network_state(&self) -> NetworkState {
        self.network_state.read().await.clone()
    }

    /// Set the network state.
    pub async fn set_network_state(&self, state: NetworkState) {
        *self.network_state.write().await = state;
    }

    /// Check server health and update network state.
    pub async fn check_connectivity(&self) -> bool {
        match self.describe().await {
            Ok(_) => {
                self.set_network_state(NetworkState::Online).await;
                true
            }
            Err(_) => {
                self.set_network_state(NetworkState::Offline).await;
                false
            }
        }
    }

    pub fn endpoint(&self, path: &str) -> anyhow::Result<Url> {
        let normalized = path.trim().trim_start_matches('/');
        if !soland_path_allowed(normalized) {
            anyhow::bail!(
                "yougen redline: forbidden soland private path `{normalized}`; use only spec-defined `/_cokret/` endpoints"
            );
        }
        Ok(self.base_url.join(normalized)?)
    }

    /// Build a [`CokretPushClient`] that mirrors this api client's auth
    /// state. Optional `register_device_path` / `unregister_device_path`
    /// honor a bridge-discovered endpoint.
    pub(crate) fn push_client(
        &self,
        register_device_path: Option<&str>,
        unregister_device_path: Option<&str>,
    ) -> CokretPushClient {
        let mut client =
            CokretPushClient::new(self.base_url.as_str()).with_required_session_grant(true);
        if let Some(token) = self.access_token.as_deref() {
            client = client.with_bearer_token(token);
        }
        if let Some(grant) = self.chime_session_grant.as_deref()
            && let Ok(next) = client.clone().with_session_grant(grant)
        {
            client = next;
        }
        if let Some(proof) = self.chime_session_grant_proof.as_ref()
            && let Ok(next) = client
                .clone()
                .with_header("X-Cokret-Session-Grant-Challenge", &proof.challenge)
                .and_then(|client| {
                    client.with_header("X-Cokret-Session-Grant-Proof", &proof.proof_jwt)
                })
        {
            client = next;
        }
        if let Some(path) = register_device_path {
            client = client.with_register_device_path(path);
        }
        if let Some(path) = unregister_device_path {
            client = client.with_unregister_device_path(path);
        }
        client
    }

    /// I4 — demo crypto fallback gate. Wired by `#[cfg(feature =
    /// "demo-crypto")]`: when the feature is on, local loopback hosts may
    /// ship the dev-only placeholder ciphertext / device_signature; when
    /// the feature is off (default), the function ALWAYS returns an
    /// error and the dev placeholders never reach the wire. No runtime
    /// env-var override exists by design — production binaries are
    /// compiled `--no-default-features` (or any feature set excluding
    /// `demo-crypto`) and the entire fallback path is unreachable.
    #[cfg(feature = "demo-crypto")]
    pub(crate) fn ensure_demo_crypto_fallback_allowed(&self, label: &str) -> anyhow::Result<()> {
        if matches!(
            self.base_url.host_str().unwrap_or_default(),
            "localhost" | "127.0.0.1" | "::1" | "local.host"
        ) {
            return Ok(());
        }
        anyhow::bail!("{label} is disabled for non-local production servers")
    }

    /// Without the `demo-crypto` feature, the demo fallback is wholly
    /// disabled — even loopback hosts fail closed. This test-only guard
    /// keeps the fail-closed assertion next to the feature-enabled path.
    #[cfg(all(not(feature = "demo-crypto"), test))]
    pub(crate) fn ensure_demo_crypto_fallback_allowed(&self, label: &str) -> anyhow::Result<()> {
        anyhow::bail!(
            "{label} requires the `demo-crypto` build feature (compiled out of this binary)"
        )
    }

    pub(crate) async fn get_json<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let request = self.http.get(self.endpoint(path)?);
        self.send_json(self.prepare_request(request), Method::GET)
            .await
    }

    pub(crate) async fn post_json<T, B>(&self, path: &str, body: &B) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        // Explicit serialized bytes (not `.json()`) so PoP signing can read the
        // exact body for the content-digest on every target (incl. wasm).
        let bytes = serde_json::to_vec(body)?;
        let request = self
            .http
            .post(self.endpoint(path)?)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes);
        self.send_json(self.prepare_request(request), Method::POST)
            .await
    }

    pub(crate) async fn put_json<T, B>(&self, path: &str, body: &B) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let bytes = serde_json::to_vec(body)?;
        let request = self
            .http
            .put(self.endpoint(path)?)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes);
        self.send_json(self.prepare_request(request), Method::PUT)
            .await
    }

    pub(crate) async fn delete_json<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let request = self.http.delete(self.endpoint(path)?);
        self.send_json(self.prepare_request(request), Method::DELETE)
            .await
    }

    pub(crate) async fn send_json<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        method: Method,
    ) -> anyhow::Result<T> {
        self.send_json_internal(request, method.clone(), is_retryable_method(&method))
            .await
    }

    pub(crate) async fn send_json_retryable<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        method: Method,
    ) -> anyhow::Result<T> {
        self.send_json_internal(request, method, true).await
    }

    async fn send_json_internal<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        method: Method,
        retryable: bool,
    ) -> anyhow::Result<T> {
        let response = self.send_with_retry(request, method, retryable).await?;
        let status = response.status();
        if !status.is_success() {
            let bytes = response.bytes().await?;
            return Err(CokretApiError {
                status,
                error: decode_cokret_error(status, &bytes),
            }
            .into());
        }
        Ok(response.json().await?)
    }

    pub(crate) async fn send_bytes(
        &self,
        request: reqwest::RequestBuilder,
        method: Method,
    ) -> anyhow::Result<Vec<u8>> {
        let response = self
            .send_with_retry(request, method.clone(), is_retryable_method(&method))
            .await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(CokretApiError {
                status,
                error: decode_cokret_error(status, &bytes),
            }
            .into());
        }
        Ok(bytes.to_vec())
    }

    pub(crate) async fn send_with_retry(
        &self,
        request: reqwest::RequestBuilder,
        _method: Method,
        retryable: bool,
    ) -> anyhow::Result<reqwest::Response> {
        let mut attempt = 0usize;
        loop {
            // Check if request was cancelled
            if self.cancel_token.as_ref().is_some_and(|t| t.is_cancelled()) {
                return Err(anyhow::anyhow!("request cancelled"));
            }

            let Some(candidate) = request.try_clone() else {
                // SPEC-CR-001 — sign the fully-built request (PoP covers
                // @method/@target-uri/@authority/content-digest); re-signed per
                // attempt so created/expires stay fresh after a backoff. The
                // ②(A+②) per-request DPoP is attached on the same built request
                // so htu == the final absolute URL.
                let built = self.attach_self_path_dpop(self.sign_request(request.build()?)?)?;
                return Ok(self.http.execute(built).await?);
            };
            // 401 handling lives at the app layer (`crate::session`): a
            // refresh future capturing Dioxus signals + wasm `reqwest` is
            // `!Send`, so the HTTP client can't own it. The client just
            // surfaces the 401; the caller re-mints and retries.
            let built = self.attach_self_path_dpop(self.sign_request(candidate.build()?)?)?;
            match self.http.execute(built).await {
                Ok(response) => {
                    if retryable
                        && attempt < self.retry.max_retries
                        && is_retryable_status(response.status())
                    {
                        self.set_network_state(NetworkState::Reconnecting).await;
                        sleep_retry_delay(response.headers(), self.retry.initial_backoff, attempt)
                            .await;
                        attempt += 1;
                        continue;
                    }

                    // Update network state based on response
                    if response.status().is_server_error()
                        || response.status() == StatusCode::SERVICE_UNAVAILABLE
                    {
                        self.set_network_state(NetworkState::Reconnecting).await;
                    } else if response.status().is_success() {
                        self.set_network_state(NetworkState::Online).await;
                    }

                    return Ok(response);
                }
                Err(error)
                    if retryable
                        && attempt < self.retry.max_retries
                        && is_retryable_reqwest_error(&error) =>
                {
                    self.set_network_state(NetworkState::Reconnecting).await;
                    sleep_backoff(self.retry.initial_backoff, attempt).await;
                    attempt += 1;
                }
                Err(error) => {
                    self.set_network_state(NetworkState::Offline).await;
                    return Err(error.into());
                }
            }
        }
    }

    /// SPEC-CR-001 — attach an RFC 9421 PoP signature to `/_cokret/self/*`
    /// requests when a session signing key is bound. No-op for other surfaces
    /// or unsigned clients. Covers `@method`/`@target-uri`/`@authority` plus
    /// `content-digest` (over the body) for body-bearing requests; `created` /
    /// `expires` bound the validity window (<=300s, well under the protocol cap).
    pub(crate) fn sign_request(
        &self,
        mut request: reqwest::Request,
    ) -> anyhow::Result<reqwest::Request> {
        let Some(signing_key) = self.session_signing_key.as_ref() else {
            return Ok(request);
        };
        let path = request.url().path().to_owned();
        if !is_cokret_signed_surface(&path) {
            return Ok(request);
        }
        use cokret_sdk::http_signature::{
            Component, ContentDigest, ContentDigestAlgorithm, SignatureInput, SignedRequestParts,
            canonical_message, sign_message,
        };

        let key_id = self.session_key_id.clone().unwrap_or_default();
        let method = request.method().as_str().to_owned();
        let url = request.url();
        let target_uri = url.as_str().to_owned();
        let authority = match url.port() {
            Some(port) => format!("{}:{}", url.host_str().unwrap_or_default(), port),
            None => url.host_str().unwrap_or_default().to_owned(),
        };
        let path_only = url.path().to_owned();
        let body_bytes: Vec<u8> = request
            .body()
            .and_then(|body| body.as_bytes())
            .map(<[u8]>::to_vec)
            .unwrap_or_default();

        let mut covered = vec![
            Component::Method,
            Component::TargetUri,
            Component::Authority,
        ];
        let mut component_names = vec!["\"@method\"", "\"@target-uri\"", "\"@authority\""];
        let digest = if body_bytes.is_empty() {
            None
        } else {
            let digest = ContentDigest::compute(&body_bytes, ContentDigestAlgorithm::Sha256);
            covered.push(Component::Header("content-digest".to_owned()));
            component_names.push("\"content-digest\"");
            Some(digest.wire_value)
        };

        let created = chrono::Utc::now().timestamp();
        let expires = created + POP_SIGNATURE_WINDOW_SECONDS;
        let params_value = format!(
            "({});created={created};expires={expires};keyid=\"{key_id}\";alg=\"ed25519\"",
            component_names.join(" ")
        );
        let signature_input = SignatureInput {
            label: "sig1".to_owned(),
            covered_components: covered,
            created,
            expires,
            key_id,
            algorithm: "ed25519".to_owned(),
            params_value: params_value.clone(),
        };
        let parts = SignedRequestParts {
            method,
            target_uri,
            authority,
            path: path_only,
            headers: Vec::new(),
            body_digest: digest.clone(),
        };
        let canonical = canonical_message(&parts, &signature_input)
            .map_err(|error| anyhow::anyhow!("build PoP signing string: {error}"))?;
        let signature = sign_message(&canonical, signing_key);

        let headers = request.headers_mut();
        if let Some(ref wire) = digest {
            headers.insert(
                "content-digest",
                reqwest::header::HeaderValue::from_str(wire)?,
            );
        }
        headers.insert(
            "signature-input",
            reqwest::header::HeaderValue::from_str(&format!("sig1={params_value}"))?,
        );
        headers.insert(
            "signature",
            reqwest::header::HeaderValue::from_str(&format!("sig1=:{signature}:"))?,
        );
        Ok(request)
    }

    /// ②(A+②) — attach the per-request `DPoP` proof for `/_cokret/self/*`
    /// requests (api-conventions.md §3.3). Centralized single mint point: every
    /// request builder funnels through `send_with_retry`, so binding the device
    /// key once via [`Self::with_dpop_device`] is enough to cover every self-path
    /// call. No-op when no DPoP device key is bound (dev-login / OAuth bearer
    /// paths) or for non-self surfaces.
    ///
    /// Binding (RFC 9449): `htm` = request method, `htu` = the absolute request
    /// URL, `ath` = base64url(sha256(grant)) where the grant is the bearer in
    /// `access_token`. Minted on the fully-built request so `htu` is the final
    /// URL and re-minted per attempt so the proof's `iat`/`jti` stay fresh.
    fn attach_self_path_dpop(
        &self,
        mut request: reqwest::Request,
    ) -> anyhow::Result<reqwest::Request> {
        let Some(handle) = self.dpop_device.as_ref() else {
            return Ok(request);
        };
        let path = request.url().path();
        if !is_cokret_signed_surface(path) {
            return Ok(request);
        }
        let htm = request.method().as_str().to_owned();
        let htu = request.url().as_str().to_owned();
        // `ath` binds the proof to the grant being presented as the bearer; the
        // mint helper hashes it (base64url(sha256(grant))) per RFC 9449.
        let ath = self.access_token.as_deref();
        let proof = handle
            .mint_proof(&htm, &htu, ath)
            .map_err(|error| anyhow::anyhow!("mint self-path DPoP proof: {error}"))?;
        request
            .headers_mut()
            .insert("dpop", reqwest::header::HeaderValue::from_str(&proof)?);
        // Present the session-grant holder proof so the Principal Server can
        // forward it to coauth's grant introspection (which requires it to
        // confirm possession of the grant's session key).
        if let Some(grant_proof) = self.session_grant_proof.as_ref() {
            request.headers_mut().insert(
                "x-cokret-session-grant-challenge",
                reqwest::header::HeaderValue::from_str(&grant_proof.challenge)?,
            );
            request.headers_mut().insert(
                "x-cokret-session-grant-proof",
                reqwest::header::HeaderValue::from_str(&grant_proof.proof_jwt)?,
            );
        }
        Ok(request)
    }

    fn authorize(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.access_token {
            Some(token) => request.bearer_auth(token),
            None => request,
        }
    }

    pub(crate) fn prepare_request(
        &self,
        request: reqwest::RequestBuilder,
    ) -> reqwest::RequestBuilder {
        self.attach_wait_for(self.authorize(request))
    }

    fn attach_wait_for(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.wait_for_sync_token.as_deref() {
            Some(sync_token) => request.header("x-cokret-wait-for", sync_token),
            None => request,
        }
    }

    pub(crate) fn with_write_request_headers(
        &self,
        request: reqwest::RequestBuilder,
        request_id: &str,
    ) -> reqwest::RequestBuilder {
        request
            .header("x-cokret-request-id", request_id)
            .header("idempotency-key", request_id)
    }
}

fn is_cokret_signed_surface(path: &str) -> bool {
    path.starts_with("/_cokret/self/") || path.starts_with("/_cokret/root/")
}
