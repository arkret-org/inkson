use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

#[cfg(not(target_arch = "wasm32"))]
use super::YOUGEN_OIDC_REDIRECT_URI_NATIVE;
use crate::config::validate_server_url;

pub(crate) fn principal_audience(principal_server_url: &str) -> anyhow::Result<String> {
    Ok(validate_server_url(principal_server_url)?
        .join("api")?
        .to_string()
        .trim_end_matches('/')
        .to_owned())
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn current_oidc_redirect_uri() -> String {
    web_sys::window()
        .and_then(|window| window.location().origin().ok())
        .map(|origin| format!("{origin}/auth/callback"))
        .unwrap_or_else(|| super::YOUGEN_OIDC_REDIRECT_URI_NATIVE.to_owned())
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn current_oidc_redirect_uri() -> String {
    YOUGEN_OIDC_REDIRECT_URI_NATIVE.to_owned()
}

pub(crate) fn preferred_pkce_method(methods: &[String]) -> Option<&'static str> {
    if methods.iter().any(|method| method == "S256") {
        Some("S256")
    } else {
        None
    }
}

/// Random byte length for OIDC `state` and `nonce` parameters. 16 bytes →
/// 22-character URL-safe base64 token, well above the 128-bit unguessability
/// threshold RFC 6749 §10.12 calls for.
pub(crate) const STATE_NONCE_TOKEN_BYTES: usize = 16;

/// Random byte length for the PKCE `code_verifier` (RFC 7636 §4.1). 32 bytes
/// → 43-character URL-safe base64 string, the lower bound the spec allows
/// (43-128 chars). Length is fixed across browser/native to keep S256
/// challenge byte size constant.
pub(crate) const PKCE_VERIFIER_BYTES: usize = 32;

pub(crate) fn random_url_safe_token(byte_len: usize) -> anyhow::Result<String> {
    let mut buf = vec![0u8; byte_len];
    getrandom::fill(&mut buf).map_err(|error| anyhow::anyhow!("getrandom failed: {error}"))?;
    Ok(URL_SAFE_NO_PAD.encode(&buf))
}

pub(crate) fn pkce_code_challenge_s256(code_verifier: &str) -> String {
    let digest = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}
