//! Typed keys/device transport helpers.
//!
//! These are the pure-passthrough key/device read operations that used to live
//! as thin inherent methods on [`crate::transport::TransportClient`]. They build a typed SDK
//! request body (and do input validation) and call the shared SDK
//! `http-client::Client` directly. Call sites reach them through
//! [`crate::transport::auth::with_authed_sdk_client`] (or, for existing receivers,
//! `crate::transport::keys::<name>(&recv.sdk_http_client()?, …)`), which
//! keeps the session-refresh + terminal-session classification identical to the
//! old facade path while dropping the per-domain facade method.
//!
//! The key-backup / recovery / device-pairing / device-revoke methods and the
//! device-message pull loop (receive / ack / cursor) carry signing,
//! trust-anchor, or durable cursor semantics and remain inherent `TransportClient`
//! methods. Plain one-shot device-message sends remain transport writes; the
//! caller prepares any signed content before dispatch.

use crate::models::{DeviceMessagesSendOutcome, KeysQueryOutcome};

pub async fn query_keys(
    http: &arkret_sdk::http_client::Client,
    account_id: &arkret_sdk::AccountId,
    device_id: &str,
) -> anyhow::Result<KeysQueryOutcome> {
    account_id.validate()?;
    let device_id = arkret_sdk::DeviceId::new(device_id.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid device_id `{device_id}`: {err}"))?;
    let body = arkret_models_crypto::KeysQueryRequestBody {
        device_keys: vec![arkret_models_crypto::QueryAccountDeviceSelector {
            account_id: account_id.clone(),
            device_ids: vec![device_id],
        }],
        timeout_ms: None,
    };
    http.keys_query(&body).await.map_err(anyhow::Error::from)
}

/// List the principal's active devices from the spec account viewer
/// (`GET /_arkret/self/account/viewer`). Returns the raw JSON response
/// shape with `devices[]`; the settings UI derives "current device" from
/// the first device when the viewer projection has no explicit current
/// marker.
pub async fn list_devices(
    http: &arkret_sdk::http_client::Client,
) -> anyhow::Result<arkret_sdk::AccountView> {
    http.account_viewer()
        .await
        .map_err(|error| anyhow::anyhow!("list devices: {error}"))
}

/// Send a one-shot device-message envelope to a target actor/device queue.
/// The caller prepares `content` (which may itself be a signed proof); this
/// wraps it in the typed `DeviceMessagesSendRequestBody` and POSTs it — the
/// envelope carries no additional signing.
pub async fn send_device_message<K: arkret_sdk::DeviceMessageSpec>(
    http: &arkret_sdk::http_client::Client,
    txn_id: &str,
    target_actor: &arkret_sdk::ActorId,
    target_device_id: &str,
    expires_at: &str,
    content: K::Content,
) -> anyhow::Result<DeviceMessagesSendOutcome> {
    let message_id = arkret_sdk::DeviceMessageId::new_v7_at(crate::clock::now_unix_ms());
    send_device_message_with_id::<K>(
        http,
        txn_id,
        message_id,
        target_actor,
        target_device_id,
        expires_at,
        content,
    )
    .await
}

/// Same as [`send_device_message`] but with a caller-pinned
/// `device_message_id`.
///
/// Kinds whose HPKE AAD binds the envelope id (`ak.secret.send`,
/// device-lifecycle.md §10.2) MUST allocate that id **before** sealing and hand
/// the same value here, so the ciphertext, the envelope and the durable queue
/// row all carry one id. Minting a second id at send time would break the AAD.
#[allow(clippy::too_many_arguments)]
pub async fn send_device_message_with_id<K: arkret_sdk::DeviceMessageSpec>(
    http: &arkret_sdk::http_client::Client,
    txn_id: &str,
    message_id: arkret_sdk::DeviceMessageId,
    target_actor: &arkret_sdk::ActorId,
    target_device_id: &str,
    expires_at: &str,
    content: K::Content,
) -> anyhow::Result<DeviceMessagesSendOutcome> {
    target_actor.validate()?;
    let account_id = target_actor
        .as_account_id()
        .ok_or_else(|| anyhow::anyhow!("device messages require an account target"))?;
    let destination = http.describe().await?.service_id;
    if destination != account_id.station_id {
        anyhow::bail!("device message target Station differs from the authenticated destination");
    }
    let target_device_id = arkret_sdk::DeviceId::new(target_device_id.to_owned())?;
    let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at)?.with_timezone(&chrono::Utc);
    let payload = arkret_sdk::TypedDeviceMessageTarget::<K>::new(message_id, expires_at, content)?
        .single_recipient(account_id.principal_id.clone(), target_device_id)?;
    http.send_device_messages(txn_id, &payload)
        .await
        .map_err(anyhow::Error::from)
}
