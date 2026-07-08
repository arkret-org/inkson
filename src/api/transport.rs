//! Core transport shell for [`CokretApi`]: constructor + builder methods,
//! SDK http-client construction, network state, and the legacy URL guard.
//! Endpoint traffic is being strangled through `cokret-http-client`; this
//! module now only holds the host-facing state needed to build that client.

use super::*;
use crate::api_error::normalize_wait_for_sync_token;
use crate::wire_helpers::soland_path_allowed;

impl CokretApi {
    pub fn new(base_url: &str) -> anyhow::Result<Self> {
        Self::new_with_options(base_url, CokretApiOptions::default())
    }

    pub fn new_with_options(base_url: &str, options: CokretApiOptions) -> anyhow::Result<Self> {
        let base_url = validate_server_url(base_url)?;
        let http = Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let http = http.timeout(options.timeout);
        #[cfg(target_arch = "wasm32")]
        let _ = options;

        Ok(Self {
            base_url,
            http: http.build()?,
            authorization_credential: None,
            wait_for_sync_token: None,
            chime_session_grant: None,
            chime_session_grant_proof: None,
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
    /// ②(A+②) model (api-conventions.md §3.3): the held credential is the
    /// `ck.session.grant` itself, so callers pass the grant JWT here. Combined
    /// with [`Self::with_dpop_device`], SDK-backed requests carry
    /// `Authorization: Bearer <grant>` plus a per-request `DPoP` proof bound to
    /// that grant (`ath=hash(grant)`).
    ///
    /// Compatibility inbound credentials can still be placed in the HTTP Bearer
    /// slot when no DPoP device is bound.
    pub fn with_bearer(mut self, authorization_credential: impl Into<String>) -> Self {
        self.authorization_credential = Some(authorization_credential.into());
        self
    }

    /// ②(A+②) — bind the grant-binding (DPoP) key used by
    /// [`Self::sdk_http_client`] so SDK-backed requests mint a fresh
    /// per-request `DPoP` proof (RFC 9449) bound to the grant in
    /// `authorization_credential`. The grant must already be set via
    /// [`Self::with_bearer`] for the `ath` binding to be present.
    pub fn with_dpop_device(mut self, handle: crate::account_auth::grant_dpop::DpopHandle) -> Self {
        self.dpop_device = Some(handle);
        self
    }

    pub(crate) fn sdk_http_client(&self) -> anyhow::Result<cokret_sdk::http_client::Client> {
        let mut builder = cokret_sdk::http_client::ClientBuilder::new(self.base_url.clone())
            .http_client(self.http.clone());
        match (
            self.authorization_credential.as_ref(),
            self.dpop_device.as_ref(),
        ) {
            (Some(token), Some(handle)) => {
                builder = builder.auth(cokret_sdk::http_client::Auth::Dpop(
                    handle.sdk_dpop_auth_for_access_token(token.clone()),
                ));
            }
            (Some(token), None) => {
                builder = builder.auth(cokret_sdk::http_client::Auth::Bearer(token.clone()));
            }
            (None, Some(handle)) => {
                builder = builder.auth(cokret_sdk::http_client::Auth::Dpop(
                    handle.sdk_dpop_proof_only_auth(),
                ));
            }
            (None, None) => {}
        }
        if let Some(signing_key) = self.session_signing_key.as_ref() {
            let key_id = match self.session_key_id.clone() {
                Some(key_id) => key_id,
                None => {
                    let jwk = cokret_sdk::dpop::DpopJwk::from_ed25519_verifying_key(
                        &signing_key.verifying_key(),
                    );
                    cokret_sdk::dpop::dpop_jwk_thumbprint(&jwk)
                        .map_err(|error| anyhow::anyhow!("session key thumbprint: {error}"))?
                }
            };
            builder = builder.http_message_signer(
                cokret_sdk::http_client::HttpMessageSigner::new(key_id, signing_key.clone())
                    .with_validity(std::time::Duration::from_secs(
                        POP_SIGNATURE_WINDOW_SECONDS as u64,
                    )),
            );
        }
        builder
            .build()
            .map_err(|error| anyhow::anyhow!("build SDK Cokret HTTP client: {error}"))
    }

    /// SPEC-CR-001 — bind the `ck.session.grant` session key so requests to
    /// `/_cokret/self/*` are RFC 9421 PoP-signed. `session_private_key_pem` is
    /// the PKCS#8 PEM returned by grant issuance; the keyid is the key's
    /// RFC 7638 thumbprint, which soland accepts for the binding check.
    pub fn with_session_signing_key(
        mut self,
        session_private_key_pem: &str,
    ) -> anyhow::Result<Self> {
        let signing_key =
            crate::account_auth::session_grant_signing_key_from_pem(session_private_key_pem)?;
        let jwk =
            cokret_sdk::dpop::DpopJwk::from_ed25519_verifying_key(&signing_key.verifying_key());
        self.session_key_id = Some(
            cokret_sdk::dpop::dpop_jwk_thumbprint(&jwk)
                .map_err(|error| anyhow::anyhow!("session key thumbprint: {error}"))?,
        );
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
        if let Some(token) = self.authorization_credential.as_deref() {
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
}
