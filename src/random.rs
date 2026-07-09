use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub(crate) fn base64url_token(byte_len: usize, error_context: &str) -> anyhow::Result<String> {
    let mut bytes = vec![0u8; byte_len];
    getrandom::fill(&mut bytes).map_err(|error| anyhow::anyhow!("{error_context}: {error}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
