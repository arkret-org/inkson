//! Client for the soland MIMI provider facade.
//!
//! Spec: `cokret-spec/spec/v1/zh/extensions/mimi-interop.md` §5
//! (Endpoint Surface).
//!
//! The MIMI facade exposes RPC endpoints under
//! `<base_url>/_cokret/open/mimi/*` plus the well-known
//! `/.well-known/mimi-protocol-directory`. This client wraps the
//! read paths (`provider_directory`, `identifier_query`,
//! `request_consent`) and exposes them as typed Rust functions for
//! `views::settings` (or any other consumer) to probe a remote
//! provider's connectivity, draft pinning, and identifier mapping.
//!
//! Write paths (`submit_message`, `room_update`, `notify`,
//! `report_abuse`) are explicitly NOT in this client — those are
//! initiated by Cokret-native authoring surfaces (`chat.rs` etc.)
//! and surfaced through the canonical timeline by soland's facade
//! mapping (see `routing/interop/mimi.rs`). Crossing into MIMI's
//! write side directly from yougen would bypass capability checks
//! and policy gating that the Cokret path enforces.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Errors a [`MimiClient`] call can surface.
#[derive(Debug, thiserror::Error)]
pub enum MimiClientError {
    /// `base_url` was malformed or `reqwest::Client::builder` failed.
    #[error("MIMI client config: {0}")]
    InvalidConfig(String),
    /// Outbound HTTP failed (connection refused, TLS error, timeout).
    #[error("MIMI network: {0}")]
    Network(String),
    /// Upstream returned a non-2xx response.
    #[error("MIMI upstream {status}: {body}")]
    Upstream { status: u16, body: String },
    /// Response body did not parse as the expected JSON shape.
    #[error("MIMI response: {0}")]
    InvalidResponse(String),
}

/// Pinned MIMI draft versions the client speaks. Matches the
/// `ck.profile.mimi_interop.v1` pinning declared in
/// `extensions/mimi-interop.md` §1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MimiDraftPinning {
    pub protocol_draft: String,
    pub content_draft: String,
    pub room_policy_draft: String,
    pub identifier_draft: String,
}

impl Default for MimiDraftPinning {
    fn default() -> Self {
        Self {
            protocol_draft: "draft-ietf-mimi-protocol-06".to_owned(),
            content_draft: "draft-ietf-mimi-content-08".to_owned(),
            room_policy_draft: "draft-ietf-mimi-room-policy-03".to_owned(),
            identifier_draft: "draft-kohbrok-mimi-identifiers-01".to_owned(),
        }
    }
}

/// Parsed `provider_directory` response. The full payload is much
/// richer — this struct projects just the fields the yougen
/// settings UI needs for "is this provider reachable + on a
/// draft-interop diagnostics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MimiProviderDirectorySummary {
    pub service_did: String,
    pub service_type: String,
    pub supported_profiles: Vec<String>,
    pub protocol_draft: String,
    pub content_draft: String,
    pub provider_id: String,
    pub features: Vec<String>,
}

/// Parsed legacy/draft `identifier_query` diagnostic response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MimiIdentifierQuerySummary {
    pub query: String,
    pub reachable: bool,
    pub mapped_did: Option<String>,
    pub provider_id: String,
}

/// Parsed `request_consent` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MimiConsentRequestResult {
    pub consent_id: String,
    pub state: String,
}

#[derive(Clone, Debug)]
pub struct MimiClient {
    base_url: String,
    http: Client,
    drafts: MimiDraftPinning,
}

impl MimiClient {
    /// Build a client against `base_url` (e.g. `https://chat.example`).
    /// The MIMI routes are derived as `{base_url}/_cokret/open/mimi/*` and
    /// `{base_url}/.well-known/mimi-protocol-directory`. Trailing
    /// slashes on `base_url` are tolerated.
    pub fn new(base_url: impl Into<String>) -> Result<Self, MimiClientError> {
        let base = base_url.into().trim_end_matches('/').to_owned();
        if base.is_empty() {
            return Err(MimiClientError::InvalidConfig(
                "base_url is required".to_owned(),
            ));
        }
        if !(base.starts_with("https://") || base.starts_with("http://")) {
            return Err(MimiClientError::InvalidConfig(format!(
                "base_url must use http(s) scheme, got: {base}"
            )));
        }
        // `ClientBuilder::timeout` is unavailable on wasm32 (no
        // system clock); the JS fetch path enforces its own
        // timeouts at the browser layer. Native build gets a 10s cap.
        let builder = Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.timeout(std::time::Duration::from_secs(10));
        let http = builder
            .build()
            .map_err(|err| MimiClientError::InvalidConfig(format!("reqwest build: {err}")))?;
        Ok(Self {
            base_url: base,
            http,
            drafts: MimiDraftPinning::default(),
        })
    }

    /// Replace the pinned MIMI draft versions. Mainly useful for
    /// tests against a server that pins a different draft set.
    pub fn with_drafts(mut self, drafts: MimiDraftPinning) -> Self {
        self.drafts = drafts;
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn drafts(&self) -> &MimiDraftPinning {
        &self.drafts
    }

    /// GET `/.well-known/mimi-protocol-directory`. Surfaces just
    /// enough of the response to verify draft pinning + service
    /// DID interop; returns the parsed summary plus the raw
    /// JSON for surfaces that want richer detail.
    pub async fn fetch_provider_directory(
        &self,
    ) -> Result<(MimiProviderDirectorySummary, Value), MimiClientError> {
        let url = format!("{}/.well-known/mimi-protocol-directory", self.base_url);
        let value = self.get_json(&url).await?;
        let summary = parse_provider_directory_summary(&value)?;
        Ok((summary, value))
    }

    /// POST `/_cokret/open/mimi/identifiers/query`. The `query` must be a
    /// `mimi://` URI or `did:` (the soland-side validator enforces
    /// this). Returns whether the identifier is reachable + the
    /// optional mapped DID.
    pub async fn identifier_query(
        &self,
        query: &str,
    ) -> Result<MimiIdentifierQuerySummary, MimiClientError> {
        let url = format!("{}/_cokret/open/mimi/identifiers/query", self.base_url);
        let body = json!({
            "query": query,
            "privacy_mode": "private_contact_discovery",
            "protocol_draft": self.drafts.protocol_draft,
            "identifier_draft": self.drafts.identifier_draft,
        });
        let value = self.post_json(&url, &body).await?;
        parse_identifier_query(&value)
    }

    /// POST `/_cokret/open/mimi/consent/request`. Body fields (per spec
    /// §10) include the target identifier + Cokret space binding.
    /// Returns the issued `consent_id` and initial state (typically
    /// `"requested"`).
    pub async fn request_consent(
        &self,
        target_identifier: &str,
        realm_id: Option<&str>,
    ) -> Result<MimiConsentRequestResult, MimiClientError> {
        let url = format!("{}/_cokret/open/mimi/consent/request", self.base_url);
        let body = json!({
            "target_identifier": target_identifier,
            "realm_id": realm_id,
            "privacy_mode": "private_contact_discovery",
            "protocol_draft": self.drafts.protocol_draft,
            "identifier_draft": self.drafts.identifier_draft,
        });
        let value = self.post_json(&url, &body).await?;
        parse_consent_request(&value)
    }

    async fn get_json(&self, url: &str) -> Result<Value, MimiClientError> {
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|err| MimiClientError::Network(format!("GET {url}: {err}")))?;
        finalize_response(response, url).await
    }

    async fn post_json(&self, url: &str, body: &Value) -> Result<Value, MimiClientError> {
        let response = self
            .http
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|err| MimiClientError::Network(format!("POST {url}: {err}")))?;
        finalize_response(response, url).await
    }
}

async fn finalize_response(
    response: reqwest::Response,
    url: &str,
) -> Result<Value, MimiClientError> {
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|err| MimiClientError::Network(format!("{url} body: {err}")))?;
    let body = String::from_utf8_lossy(&bytes).into_owned();
    if !status.is_success() {
        return Err(MimiClientError::Upstream {
            status: status.as_u16(),
            body,
        });
    }
    serde_json::from_slice::<Value>(&bytes)
        .map_err(|err| MimiClientError::InvalidResponse(format!("{url} parse: {err}")))
}

/// Pure-function parsers — separated from the async I/O so they
/// can be unit-tested against canned JSON without spinning a
/// reqwest mock server.
pub fn parse_provider_directory_summary(
    value: &Value,
) -> Result<MimiProviderDirectorySummary, MimiClientError> {
    let service_did = value
        .get("service_did")
        .and_then(Value::as_str)
        .ok_or_else(|| MimiClientError::InvalidResponse("missing service_did".to_owned()))?
        .to_owned();
    let service_type = value
        .get("service_type")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let supported_profiles: Vec<String> = value
        .get("supported_profiles")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let mimi = value
        .get("mimi")
        .ok_or_else(|| MimiClientError::InvalidResponse("missing `mimi` block".to_owned()))?;
    let protocol_draft = mimi
        .get("protocol_draft")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let content_draft = mimi
        .get("content_draft")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let provider_id = mimi
        .get("provider_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let features: Vec<String> = mimi
        .get("features")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();
    Ok(MimiProviderDirectorySummary {
        service_did,
        service_type,
        supported_profiles,
        protocol_draft,
        content_draft,
        provider_id,
        features,
    })
}

pub fn parse_identifier_query(
    value: &Value,
) -> Result<MimiIdentifierQuerySummary, MimiClientError> {
    let query = value
        .get("query")
        .and_then(Value::as_str)
        .ok_or_else(|| MimiClientError::InvalidResponse("missing query".to_owned()))?
        .to_owned();
    let reachable = value
        .get("reachable")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mapped_did = value
        .get("mapped_did")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let provider_id = value
        .get("provider_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    Ok(MimiIdentifierQuerySummary {
        query,
        reachable,
        mapped_did,
        provider_id,
    })
}

pub fn parse_consent_request(value: &Value) -> Result<MimiConsentRequestResult, MimiClientError> {
    let consent_id = value
        .get("consent_id")
        .and_then(Value::as_str)
        .ok_or_else(|| MimiClientError::InvalidResponse("missing consent_id".to_owned()))?
        .to_owned();
    let state = value
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    Ok(MimiConsentRequestResult { consent_id, state })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn new_rejects_empty_base_url() {
        let err = MimiClient::new("").expect_err("empty url");
        assert!(matches!(err, MimiClientError::InvalidConfig(_)));
    }

    #[test]
    fn new_rejects_non_http_scheme() {
        let err = MimiClient::new("file:///etc/passwd").expect_err("non-http scheme");
        assert!(matches!(err, MimiClientError::InvalidConfig(_)));
    }

    #[test]
    fn new_strips_trailing_slash() {
        let c = MimiClient::new("https://chat.example/").expect("ok");
        assert_eq!(c.base_url(), "https://chat.example");
    }

    #[test]
    fn parse_provider_directory_pulls_canonical_fields() {
        let v = json!({
            "service_did": "did:web:chat.example",
            "service_type": "mimi_provider_facade",
            "supported_profiles": ["ck.profile.mimi_interop.v1"],
            "mimi": {
                "protocol_draft": "draft-ietf-mimi-protocol-06",
                "content_draft": "draft-ietf-mimi-content-08",
                "provider_id": "mimi://chat.example",
                "features": ["submit_message", "identifier_query", "consent"],
            },
        });
        let summary = parse_provider_directory_summary(&v).expect("ok");
        assert_eq!(summary.service_did, "did:web:chat.example");
        assert_eq!(summary.service_type, "mimi_provider_facade");
        assert!(
            summary
                .supported_profiles
                .iter()
                .any(|p| p == "ck.profile.mimi_interop.v1")
        );
        assert_eq!(summary.protocol_draft, "draft-ietf-mimi-protocol-06");
        assert!(summary.features.iter().any(|f| f == "submit_message"));
    }

    #[test]
    fn parse_provider_directory_missing_service_did_errors() {
        let v = json!({"mimi": {}});
        let err = parse_provider_directory_summary(&v).expect_err("err");
        assert!(matches!(err, MimiClientError::InvalidResponse(_)));
    }

    #[test]
    fn parse_identifier_query_handles_reachable_branch() {
        let v = json!({
            "query": "mimi://chat.example/users/alice",
            "reachable": true,
            "mapped_did": "did:web:alice.example",
            "provider_id": "mimi://chat.example"
        });
        let parsed = parse_identifier_query(&v).expect("ok");
        assert!(parsed.reachable);
        assert_eq!(parsed.mapped_did.as_deref(), Some("did:web:alice.example"));
    }

    #[test]
    fn parse_identifier_query_handles_unreachable_branch() {
        let v = json!({
            "query": "mimi://chat.example/users/bob",
            "reachable": false,
            "provider_id": "mimi://chat.example"
        });
        let parsed = parse_identifier_query(&v).expect("ok");
        assert!(!parsed.reachable);
        assert!(parsed.mapped_did.is_none());
    }

    #[test]
    fn parse_consent_request_extracts_id_and_state() {
        let v = json!({
            "ok": true,
            "consent_id": "mimi_consent-abc",
            "state": "requested",
        });
        let parsed = parse_consent_request(&v).expect("ok");
        assert_eq!(parsed.consent_id, "mimi_consent-abc");
        assert_eq!(parsed.state, "requested");
    }

    #[test]
    fn parse_consent_request_missing_consent_id_errors() {
        let v = json!({"state": "requested"});
        let err = parse_consent_request(&v).expect_err("err");
        assert!(matches!(err, MimiClientError::InvalidResponse(_)));
    }

    #[test]
    fn draft_pinning_default_matches_spec() {
        let drafts = MimiDraftPinning::default();
        assert_eq!(drafts.protocol_draft, "draft-ietf-mimi-protocol-06");
        assert_eq!(drafts.content_draft, "draft-ietf-mimi-content-08");
    }
}
