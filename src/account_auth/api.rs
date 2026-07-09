use anyhow::Context;
use reqwest::Client;
use url::Url;

use super::OidcDiscoveryDocument;

/// Standard OIDC discovery (`/.well-known/openid-configuration`) for the
/// chosen `methods[].oidc`. `openid_configuration` is taken verbatim from
/// the auth method when present; otherwise it is derived from the issuer.
/// No Arkret-private OAuth endpoint family is involved.
pub async fn fetch_oidc_discovery(discovery_url: &str) -> anyhow::Result<OidcDiscoveryDocument> {
    let url = Url::parse(discovery_url)
        .with_context(|| format!("invalid OIDC discovery URL: {discovery_url}"))?;
    Client::new()
        .get(url)
        .send()
        .await
        .context("OIDC discovery request failed")?
        .error_for_status()
        .context("OIDC discovery returned an error status")?
        .json()
        .await
        .context("parse OIDC discovery document")
}
