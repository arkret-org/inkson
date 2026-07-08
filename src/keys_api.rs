//! Free-function keys/device READ transport (E2 CokretApi strangler).
//!
//! These are the pure-passthrough key/device read operations that used to live
//! as thin inherent methods on [`crate::api::CokretApi`]. They build a typed SDK
//! request body (and do input validation) and call the shared SDK
//! `http-client::Client` directly. Call sites reach them through
//! [`crate::authed_api::with_authed_sdk_client`] (or, for non-`with_authed_api`
//! receivers, `crate::keys_api::<name>(&recv.sdk_http_client()?, …)`), which
//! keeps the session-refresh + terminal-session classification identical to the
//! old facade path while dropping the per-domain facade method.
//!
//! The key-backup / recovery / device-message / device-pairing / device-revoke
//! methods carry signing, trust-anchor, or durable event semantics (or are
//! writes) and remain inherent `CokretApi` methods.

use std::collections::BTreeMap;

use crate::models::KeysQueryOutcome;

pub async fn query_keys(
    http: &cokret_sdk::http_client::Client,
    actor: &str,
    device_id: &str,
) -> anyhow::Result<KeysQueryOutcome> {
    let actor = cokret_sdk::Did::new(actor.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid actor DID `{actor}`: {err}"))?;
    let device_id = cokret_sdk::DeviceId::new(device_id.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid device_id `{device_id}`: {err}"))?;
    let mut device_keys = BTreeMap::new();
    device_keys.insert(actor, vec![device_id]);
    let body = cokret_sdk::models::KeysQueryRequestBody {
        device_keys,
        timeout_ms: None,
    };
    http.keys_query(&body).await.map_err(anyhow::Error::from)
}

/// List the principal's active devices from the spec account viewer
/// (`GET /_cokret/self/account/viewer`). Returns the raw JSON response
/// shape with `devices[]`; the settings UI derives "current device" from
/// the first device when the viewer projection has no explicit current
/// marker.
pub async fn list_devices(
    http: &cokret_sdk::http_client::Client,
) -> anyhow::Result<cokret_sdk::AccountView> {
    http.account_viewer()
        .await
        .map_err(|error| anyhow::anyhow!("list devices: {error}"))
}
