use arkret_sdk::http_client::{Auth, ClientBuilder, ClientRequestOptions};

#[derive(Clone)]
pub struct RequestContext {
    credential: String,
    dpop: Option<crate::account_auth::grant_dpop::DpopHandle>,
    cursor: Option<String>,
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

    pub fn with_dpop(mut self, dpop: crate::account_auth::grant_dpop::DpopHandle) -> Self {
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
    http: arkret_sdk::http_client::Client,
    context: RequestContext,
}

impl TransportClient {
    pub fn new(base_url: &str, context: RequestContext) -> anyhow::Result<Self> {
        let base_url = crate::config::validate_server_url(base_url)?;
        let mut builder = ClientBuilder::new(base_url).allow_insecure_localhost();
        if let Some(auth) = context.auth() {
            builder = builder.auth(auth);
        }
        let http = builder
            .build()
            .map_err(|error| anyhow::anyhow!("build SDK Arkret HTTP client: {error}"))?;
        Ok(Self { http, context })
    }

    pub(crate) fn from_http(
        http: arkret_sdk::http_client::Client,
        context: RequestContext,
    ) -> Self {
        Self { http, context }
    }

    pub fn http(&self) -> &arkret_sdk::http_client::Client {
        &self.http
    }

    pub fn context(&self) -> &RequestContext {
        &self.context
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
