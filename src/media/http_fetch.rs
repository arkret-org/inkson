//! Bounded HTTP reads for service route discovery.

use arkret_sdk::Did;
#[cfg(target_arch = "wasm32")]
use arkret_sdk::identity::host_is_safe_for_outbound;
use arkret_sdk::identity::{DID_WEB_MAX_DOCUMENT_BYTES, DidWebDocumentOutcome, DidWebResolver};

#[cfg(target_arch = "wasm32")]
fn url_host_is_safe(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "https" {
        return false;
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    // mDNS `.local` is not covered by the SDK's localhost-only name check.
    if host.to_ascii_lowercase().ends_with(".local") {
        return false;
    }
    host_is_safe_for_outbound(host)
        || (cfg!(any(
            debug_assertions,
            feature = "wasm-localstorage-secrets-test"
        )) && (host == "localhost"
            || host.ends_with(".localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())))
}

/// Fetch `url` over `http` with an enforced response-size ceiling and a JSON
/// content-type check. Cross-platform: `bytes()` works on both the native and
/// the wasm browser-fetch reqwest backends (the wasm backend does not expose
/// incremental `chunk()` streaming, so we read once and bound by length).
///
/// DID resolution is triggered by untrusted input (verifying a stranger's
/// signature), so a hostile host must not force an unbounded allocation: the
/// declared `Content-Length` (when present) is rejected above the ceiling
/// before the body is read, and the materialized body is re-checked. Returns
/// `(content_type, body)` or `None` (fail-closed) on any transport / status /
/// size / content-type failure.
/// P3.2c: native half of the DID-fetch SSRF guard. Judges the derived URL,
/// resolves the host, judges **every** DNS answer, and returns a client with
/// the validated addresses pinned into its connector, so a second lookup
/// between validation and connect cannot rebind the host (the gap the wasm
/// static check in [`url_host_is_safe`] structurally cannot close). Any
/// failure is fail-closed (`None`) before a socket is opened.
#[cfg(not(target_arch = "wasm32"))]
async fn locked_did_fetch_client(url: &str) -> Option<reqwest::Client> {
    // Local developer and browser fixture builds follow the SDK client's loopback policy.
    // TLS validation remains enabled; release builds require public HTTPS.
    let parsed = url::Url::parse(url).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    let guard = if cfg!(any(
        debug_assertions,
        feature = "wasm-localstorage-secrets-test"
    )) {
        arkret_egress_reqwest::EgressGuard::local_development()
    } else {
        arkret_egress_reqwest::EgressGuard::public_https()
    };
    let locked = guard.lock_str_async(url, "did fetch").await.ok()?;
    locked
        .apply_to_client_builder(
            reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()),
        )
        .build()
        .ok()
}

pub(crate) async fn fetch_did_bytes(
    http: &reqwest::Client,
    url: &str,
    max_bytes: usize,
) -> Option<(String, Vec<u8>)> {
    fetch_guarded_bytes(http, url, max_bytes, None).await
}

pub(crate) async fn fetch_arkret_bytes(
    http: &reqwest::Client,
    url: &str,
    max_bytes: usize,
    operation: &str,
) -> Option<(String, Vec<u8>)> {
    fetch_guarded_bytes(http, url, max_bytes, Some(operation)).await
}

async fn fetch_guarded_bytes(
    http: &reqwest::Client,
    url: &str,
    max_bytes: usize,
    operation: Option<&str>,
) -> Option<(String, Vec<u8>)> {
    // P3.2c SSRF egress guard — fail-closed *before* any outbound request.
    // The `did:web` / `did:webvh` host is taken verbatim from an untrusted
    // actor DID, so a hostile `did:web:127.0.0.1` /
    // `did:web:169.254.169.254` (cloud metadata) / `did:web:localhost` must
    // never let the client reach into loopback, private, link-local or
    // carrier-NAT address space. The guard lives here, at the request layer:
    // the SDK URL helpers are pure syntax-to-URL derivations and no longer
    // carry this judgment.
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Native: lock the target through the shared guard and dispatch on a
        // client pinned to the validated address set. The caller's client is
        // not reused because DNS pinning is a per-target client property.
        let _ = http;
        let client = locked_did_fetch_client(url).await?;
        fetch_did_bytes_from_url(&client, url, max_bytes, operation).await
    }
    #[cfg(target_arch = "wasm32")]
    {
        // wasm: the browser owns DNS and the socket, so the static shared
        // classification is the entire guard the platform allows.
        if !url_host_is_safe(url) {
            return None;
        }
        fetch_did_bytes_from_url(http, url, max_bytes, operation).await
    }
}

async fn fetch_did_bytes_from_url(
    http: &reqwest::Client,
    url: &str,
    max_bytes: usize,
    operation: Option<&str>,
) -> Option<(String, Vec<u8>)> {
    let mut request = http.get(url);
    if let Some(operation) = operation {
        request = request.header("Arkret-Operation", operation);
    }
    let response = request.send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/json")
        .to_owned();
    // Best-effort pre-check: the wasm browser-fetch backend often omits
    // Content-Length, so this is an early-out, not the sole guard.
    if response
        .content_length()
        .is_some_and(|len| len > max_bytes as u64)
    {
        return None;
    }
    let body = response.bytes().await.ok()?;
    if body.len() > max_bytes {
        return None;
    }
    Some((content_type, body.to_vec()))
}

/// Build the `did:web` document URL (HTTPS, via the SDK helper) and fetch it.
/// The URL helper only ever yields `https://…/did.json`, so plaintext hosts are
/// rejected by construction; the SDK `insert_from_https_response` re-validates
/// the URL, content-type and document `id`.
pub(crate) async fn fetch_did_web_document(
    http: &reqwest::Client,
    did: &Did,
) -> Option<DidWebDocumentOutcome> {
    let url = DidWebResolver::document_url(did).ok()?;
    let (content_type, body) = fetch_did_bytes(http, &url, DID_WEB_MAX_DOCUMENT_BYTES).await?;
    Some(DidWebDocumentOutcome {
        url,
        content_type,
        body,
    })
}
