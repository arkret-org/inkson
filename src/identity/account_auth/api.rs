use std::time::Duration;

use anyhow::Context;
use reqwest::header::{HeaderValue, RETRY_AFTER};
use reqwest::{Client, StatusCode};
use url::Url;

use super::OidcDiscoveryDocument;

const OIDC_DISCOVERY_DEFAULT_RETRY_DELAY: Duration = Duration::from_secs(5);
const OIDC_DISCOVERY_MAX_TOTAL_WAIT: Duration = Duration::from_secs(60);

fn discovery_retry_delay(
    status: StatusCode,
    retry_after: Option<&HeaderValue>,
) -> Option<Duration> {
    if !matches!(
        status,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
    ) {
        return None;
    }
    let seconds = retry_after
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|seconds| seconds.max(1));
    Some(
        seconds
            .map(Duration::from_secs)
            .unwrap_or(OIDC_DISCOVERY_DEFAULT_RETRY_DELAY),
    )
}

/// Standard OIDC discovery (`/.well-known/openid-configuration`) for the
/// chosen `methods[].oidc`. `openid_configuration` is taken verbatim from
/// the auth method when present; otherwise it is derived from the issuer.
/// No Arkret-private OAuth endpoint family is involved.
pub async fn fetch_oidc_discovery(discovery_url: &str) -> anyhow::Result<OidcDiscoveryDocument> {
    let url = Url::parse(discovery_url)
        .with_context(|| format!("invalid OIDC discovery URL: {discovery_url}"))?;
    let client = Client::new();
    let mut total_wait = Duration::ZERO;
    let mut attempt = 0_u32;

    loop {
        attempt += 1;
        let response = client
            .get(url.clone())
            .send()
            .await
            .context("OIDC discovery request failed")?;

        if response.status().is_success() {
            return response
                .json()
                .await
                .context("parse OIDC discovery document");
        }

        let retry_delay =
            discovery_retry_delay(response.status(), response.headers().get(RETRY_AFTER));
        if let Some(delay) = retry_delay
            && total_wait
                .checked_add(delay)
                .is_some_and(|next| next <= OIDC_DISCOVERY_MAX_TOTAL_WAIT)
        {
            total_wait += delay;
            tracing::info!(
                %discovery_url,
                attempt,
                retry_after_seconds = delay.as_secs(),
                total_wait_seconds = total_wait.as_secs(),
                "OIDC discovery is temporarily unavailable; retrying"
            );
            crate::runtime_helpers::sleep_for(delay).await;
            continue;
        }

        let status = response.status();
        return response
            .error_for_status()
            .with_context(|| {
                if total_wait.is_zero() {
                    format!("OIDC discovery returned {status}")
                } else {
                    format!(
                        "OIDC discovery remained unavailable after {} seconds ({attempt} attempts); last status was {status}",
                        total_wait.as_secs()
                    )
                }
            })?
            .json()
            .await
            .context("parse OIDC discovery document");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_gateway_errors_honor_retry_after_seconds() {
        let retry_after = HeaderValue::from_static("7");
        for status in [
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            assert_eq!(
                discovery_retry_delay(status, Some(&retry_after)),
                Some(Duration::from_secs(7))
            );
        }
    }

    #[test]
    fn service_unavailable_uses_bounded_default_for_invalid_retry_after() {
        let retry_after = HeaderValue::from_static("not-a-delay");
        assert_eq!(
            discovery_retry_delay(StatusCode::SERVICE_UNAVAILABLE, Some(&retry_after)),
            Some(OIDC_DISCOVERY_DEFAULT_RETRY_DELAY)
        );
    }

    #[test]
    fn permanent_discovery_errors_are_not_retried() {
        assert_eq!(discovery_retry_delay(StatusCode::BAD_REQUEST, None), None);
        assert_eq!(discovery_retry_delay(StatusCode::NOT_FOUND, None), None);
    }
}
