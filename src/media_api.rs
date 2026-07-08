//! Free-function media/WebRTC READ transport (E2 CokretApi strangler).
//!
//! These are the pure-passthrough media read operations that used to live as
//! thin inherent methods on [`crate::api::CokretApi`]. They call the shared SDK
//! `http-client::Client` directly. Call sites reach them through
//! [`crate::authed_api::with_authed_sdk_client`] (or, for non-`with_authed_api`
//! receivers, `crate::media_api::<name>(&recv.sdk_http_client()?, …)`), which
//! keeps the session-refresh + terminal-session classification identical to the
//! old facade path while dropping the per-domain facade method.
//!
//! The event-authoring media methods (`submit_call_signal_v1`,
//! `submit_call_recording_start`, `submit_call_transcription_start`) build and
//! submit signed events and remain inherent `CokretApi` methods.

use crate::models::{MediaIceConfigOutcome, MediaIceConfigRequestBody};

/// `POST /_cokret/self/rtc/ice-config` using the SDK's authoritative
/// wire types (YOU-05-004). NB: when the WebRTC surface consumes the
/// outcome, each `ice_servers` entry MUST be parsed through
/// `cokret_sdk::IceServer` and pass
/// `IceServer::validate_credential_privacy()` before use.
pub async fn ice_config(
    http: &cokret_sdk::http_client::Client,
    request: &MediaIceConfigRequestBody,
) -> anyhow::Result<MediaIceConfigOutcome> {
    http.media_ice_config(request)
        .await
        .map_err(anyhow::Error::from)
}

/// `POST /_cokret/self/rtc/token` — `ck.self.call.media.exchange.issue_token`.
/// Returns the raw outcome (backend connect URL + token + participant
/// binding). Callers MUST run the response through
/// `cokret_sdk::verify_call_media_token_outcome` against the realm
/// media-service anchors before trusting the backend token.
pub async fn media_token_exchange(
    http: &cokret_sdk::http_client::Client,
    request: &cokret_sdk::CallMediaTokenExchangeRequestBody,
) -> anyhow::Result<cokret_sdk::CallMediaTokenExchangeOutcome> {
    http.media_token_exchange(request)
        .await
        .map_err(anyhow::Error::from)
}
