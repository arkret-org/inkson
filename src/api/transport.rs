//! Core transport shell for [`CokretApi`]: constructor + builder methods,
//! SDK http-client construction, network state, and the legacy URL guard.
//! Endpoint traffic is being strangled through `arkret-http-client`; this
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
            dpop_device: None,
            service_describe_cache: Arc::new(OnceCell::new()),
        })
    }

    /// Set the credential presented as `Authorization: Bearer <…>` on
    /// `/_arkret/self/*` requests.
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

    pub(crate) fn sdk_http_client(&self) -> anyhow::Result<arkret_sdk::http_client::Client> {
        // Permit `http://` only for loopback hosts (the SDK's guard still
        // rejects insecure remote URLs), matching inkson's own
        // `config::validate_server_url` loopback policy and the garth/login
        // client path (`views::login`). Without this the CokretApi transport
        // could not reach a local dev / joint-e2e soland on `http://127.0.0.1`,
        // while the client-core path could — an inconsistency that broke
        // UI-driven realm create against a loopback stack.
        let mut builder = arkret_sdk::http_client::ClientBuilder::new(self.base_url.clone())
            .http_client(self.http.clone())
            .allow_insecure_localhost();
        match (
            self.authorization_credential.as_ref(),
            self.dpop_device.as_ref(),
        ) {
            (Some(token), Some(handle)) => {
                builder = builder.auth(arkret_sdk::http_client::Auth::Dpop(
                    handle.sdk_dpop_auth_for_access_token(token.clone()),
                ));
            }
            (Some(token), None) => {
                builder = builder.auth(arkret_sdk::http_client::Auth::Bearer(token.clone()));
            }
            (None, Some(handle)) => {
                builder = builder.auth(arkret_sdk::http_client::Auth::Dpop(
                    handle.sdk_dpop_proof_only_auth(),
                ));
            }
            (None, None) => {}
        }
        builder
            .build()
            .map_err(|error| anyhow::anyhow!("build SDK Arkret HTTP client: {error}"))
    }

    /// Build a [`crate::event_submit::EventSubmitter`] from this client's
    /// authenticated SDK transport. Bridge for the sibling `src/api` submodules
    /// whose durable/ephemeral event logic now lives in the extracted engine;
    /// each call gets a fresh submitter (fresh lazy describe cache), matching
    /// the former per-`CokretApi` describe-cache lifetime.
    pub(crate) fn event_submitter(&self) -> anyhow::Result<crate::event_submit::EventSubmitter> {
        Ok(crate::event_submit::EventSubmitter::new(
            self.sdk_http_client()?,
        ))
    }

    pub fn with_wait_for(mut self, sync_token: impl Into<String>) -> Self {
        let sync_token = sync_token.into();
        self.wait_for_sync_token = normalize_wait_for_sync_token(&sync_token);
        self
    }

    pub fn endpoint(&self, path: &str) -> anyhow::Result<Url> {
        let normalized = path.trim().trim_start_matches('/');
        if !soland_path_allowed(normalized) {
            anyhow::bail!(
                "inkson redline: forbidden soland private path `{normalized}`; use only spec-defined `/_arkret/` endpoints"
            );
        }
        Ok(self.base_url.join(normalized)?)
    }
}
