use std::sync::Arc;

use arkret_sdk::http_client::{Auth, ClientBuilder, ClientRequestOptions};
use tokio::sync::OnceCell;
use url::Url;

#[derive(Clone)]
pub struct RequestContext {
    pub(crate) credential: String,
    pub(crate) dpop: Option<crate::identity::account_auth::grant_dpop::DpopHandle>,
    pub(crate) cursor: Option<String>,
    request_id: String,
}

impl RequestContext {
    pub fn new(credential: impl Into<String>) -> Self {
        Self {
            credential: credential.into(),
            dpop: None,
            cursor: None,
            request_id: format!("ak:request:{}", crate::operation::uuid_v7()),
        }
    }

    pub fn with_dpop(
        mut self,
        dpop: crate::identity::account_auth::grant_dpop::DpopHandle,
    ) -> Self {
        self.dpop = Some(dpop);
        self
    }

    pub fn with_cursor(mut self, cursor: impl Into<String>) -> Self {
        let cursor = cursor.into();
        self.cursor = (!cursor.trim().is_empty()).then_some(cursor);
        self
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = request_id.into();
        self
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn request_options(&self) -> ClientRequestOptions {
        let mut options = ClientRequestOptions::new().request_id(self.request_id.clone());
        if let Some(cursor) = self.cursor.as_deref() {
            options = options.wait_for(cursor.to_owned());
        }
        options
    }

    fn auth(&self) -> Option<Auth> {
        match (self.credential.trim(), self.dpop.as_ref()) {
            ("", None) => None,
            ("", Some(dpop)) => Some(Auth::Dpop(dpop.sdk_dpop_proof_only_auth())),
            (credential, Some(dpop)) => Some(Auth::Dpop(
                dpop.sdk_dpop_auth_for_access_token(credential.to_owned()),
            )),
            (credential, None) => Some(Auth::Bearer(credential.to_owned())),
        }
    }
}

#[derive(Clone)]
pub struct TransportClient {
    base_url: Url,
    http: arkret_sdk::http_client::Client,
    context: RequestContext,
    describe_cache: Arc<OnceCell<crate::models::ServiceDescribe>>,
}

impl TransportClient {
    pub fn new(base_url: &str, context: RequestContext) -> anyhow::Result<Self> {
        let base_url = crate::config::validate_server_url(base_url)?;
        let mut builder = ClientBuilder::new(base_url.clone()).allow_insecure_localhost();
        if let Some(auth) = context.auth() {
            builder = builder.auth(auth);
        }
        let http = builder
            .build()
            .map_err(|error| anyhow::anyhow!("build SDK Arkret HTTP client: {error}"))?;
        Ok(Self {
            base_url,
            http,
            context,
            describe_cache: Arc::new(OnceCell::new()),
        })
    }

    pub(crate) fn from_http(
        http: arkret_sdk::http_client::Client,
        context: RequestContext,
    ) -> Self {
        Self {
            base_url: Url::parse("https://transport.invalid/")
                .expect("static transport placeholder URL must parse"),
            http,
            context,
            describe_cache: Arc::new(OnceCell::new()),
        }
    }

    pub fn http(&self) -> &arkret_sdk::http_client::Client {
        &self.http
    }

    pub(crate) fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub fn unauthenticated(base_url: &str) -> anyhow::Result<Self> {
        Self::new(base_url, RequestContext::new(""))
    }

    pub fn with_bearer(mut self, credential: impl Into<String>) -> Self {
        self.context.credential = credential.into();
        Self::new(self.base_url.as_str(), self.context)
            .expect("rebuilding an already validated transport must succeed")
    }

    pub fn with_dpop_device(
        mut self,
        handle: crate::identity::account_auth::grant_dpop::DpopHandle,
    ) -> Self {
        self.context.dpop = Some(handle);
        Self::new(self.base_url.as_str(), self.context)
            .expect("rebuilding an already validated transport must succeed")
    }

    pub fn with_wait_for(mut self, cursor: impl Into<String>) -> Self {
        let cursor = cursor.into();
        self.context.cursor = (!cursor.trim().is_empty()).then_some(cursor);
        Self::new(self.base_url.as_str(), self.context)
            .expect("rebuilding an already validated transport must succeed")
    }

    pub(crate) fn sdk_http_client(&self) -> anyhow::Result<arkret_sdk::http_client::Client> {
        Ok(self.http.clone())
    }

    pub(crate) fn event_submitter(&self) -> anyhow::Result<crate::event_submit::EventSubmitter> {
        Ok(crate::event_submit::EventSubmitter::new(self.http.clone()))
    }

    pub fn endpoint(&self, path: &str) -> anyhow::Result<Url> {
        let normalized = path.trim().trim_start_matches('/');
        if !crate::wire_helpers::soland_path_allowed(normalized) {
            anyhow::bail!(
                "inkson redline: forbidden soland private path `{normalized}`; use only spec-defined `/_arkret/` endpoints"
            );
        }
        Ok(self.base_url.join(normalized)?)
    }

    pub async fn describe(&self) -> anyhow::Result<crate::models::ServiceDescribe> {
        self.http
            .describe()
            .await
            .map_err(|error| anyhow::anyhow!("server describe: {error}"))
    }

    pub fn context(&self) -> &RequestContext {
        &self.context
    }

    pub async fn describe_cached(&self) -> anyhow::Result<&crate::models::ServiceDescribe> {
        self.describe_cache
            .get_or_try_init(|| async {
                self.http
                    .describe()
                    .await
                    .map_err(|error| anyhow::anyhow!("server describe: {error}"))
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_context_carries_cursor_and_request_id() {
        let context = RequestContext::new("grant")
            .with_cursor("ak:cursor:test")
            .with_request_id("ak:request:test");
        let options = context.request_options();
        assert_eq!(options.request_id.as_deref(), Some("ak:request:test"));
        assert_eq!(options.wait_for.as_deref(), Some("ak:cursor:test"));
    }
}
