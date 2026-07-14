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
//! methods. The one-shot device-message send and the `ak.realm_key.request`
//! ephemeral relay below are plain transport writes (the caller prepares any
//! signed `content`; the request itself carries `proof: None`), so they are
//! migrated here.

use std::collections::BTreeMap;

use crate::event_builders::build_device_message_envelope;
use crate::models::{DeviceMessagesSendOutcome, KeysQueryOutcome};

pub async fn query_keys(
    http: &arkret_sdk::http_client::Client,
    actor: &str,
    device_id: &str,
) -> anyhow::Result<KeysQueryOutcome> {
    let actor = arkret_sdk::Did::new(actor.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid actor DID `{actor}`: {err}"))?;
    let device_id = arkret_sdk::DeviceId::new(device_id.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid device_id `{device_id}`: {err}"))?;
    let mut device_keys = BTreeMap::new();
    device_keys.insert(actor, vec![device_id]);
    let body = arkret_sdk::models::KeysQueryRequestBody {
        device_keys,
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
pub async fn send_device_message_envelope(
    http: &arkret_sdk::http_client::Client,
    txn_id: &str,
    target_actor: &str,
    target_device_id: &str,
    kind: &str,
    expires_at: &str,
    content: serde_json::Value,
) -> anyhow::Result<DeviceMessagesSendOutcome> {
    let payload =
        build_device_message_envelope(target_actor, target_device_id, kind, expires_at, content)?;
    http.send_device_messages(txn_id, &payload)
        .await
        .map_err(anyhow::Error::from)
}

/// Submit an ephemeral `ak.realm_key.request` (realm-and-space.md
/// history-sharing): a late-joining device asks the provider device named by
/// `target_source_ref` to seal the retained `history_secret` range to
/// `recipient_hpke_public_key`. soland relays it to the provider's to-device
/// queue (`relay_ephemeral_realm_key_request`); the provider answers with a
/// durable `ak.realm_key.share`.
///
/// Posts directly to `/_arkret/self/ephemeral` rather than via the broadcast
/// ephemeral submitter, whose SDK guard only admits the broadcast ephemeral
/// allowlist (`ak.realm_key.request` is a directed relay, not a broadcast
/// signal).
#[allow(clippy::too_many_arguments)]
pub async fn submit_realm_key_request(
    http: &arkret_sdk::http_client::Client,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    provider_device_ref: &str,
    provider_principal_id: &str,
    recipient_hpke_public_key: &str,
    from_epoch: u64,
    to_epoch: u64,
) -> anyhow::Result<arkret_sdk::EphemeralSubmitOutcome> {
    let realm_id = arkret_sdk::RealmId::new(crate::operation::trim_realm_id(realm_id))?;
    let device_id = arkret_sdk::DeviceId::new(device_id.trim().to_owned())?;
    let payload = arkret_sdk::RealmKeyRequestPayload {
        key_scope: arkret_sdk::RealmKeyRequestScope {
            effective_scope: arkret_sdk::models::EffectiveScope::Realm {
                realm_id: realm_id.clone(),
            },
            policy_digest: None,
            membership_frontier_digest: None,
            from_epoch,
            to_epoch,
            history_visibility: None,
        },
        recipient_principal_id: arkret_sdk::Did::new(actor_id.trim().to_owned())?,
        recipient_device_id: device_id.clone(),
        recipient_hpke_public_key: arkret_sdk::NonEmptyString::new(
            recipient_hpke_public_key.trim(),
        )
        .map_err(anyhow::Error::msg)?,
        requested_source_class: arkret_sdk::HistoryKeySource::VerifiedMemberDevice,
        target_source_ref: arkret_sdk::RealmKeySourceRef::Device(arkret_sdk::DeviceId::new(
            provider_device_ref.trim().to_owned(),
        )?),
        // The principal that owns `target_source_ref` (the provider device the
        // requester picked as its history source). Required by the SDK request
        // schema so the relay can route to the provider's to-device queue.
        target_principal_id: arkret_sdk::Did::new(provider_principal_id.trim().to_owned())?,
        created_at: crate::clock::now_utc(),
    };
    payload
        .validate()
        .map_err(|err| anyhow::anyhow!("ak.realm_key.request invalid: {err}"))?;
    let sent_at = crate::clock::now_utc();
    let envelope = arkret_sdk::EphemeralEnvelope {
        // `ak.realm_key.request` is a directed ephemeral relay, not a broadcast
        // signal, so it has no `events::kinds` constant; the literal is the
        // wire kind soland's `relay_ephemeral_realm_key_request` matches on.
        kind: "ak.realm_key.request".to_owned(),
        realm_id,
        actor_id: arkret_sdk::Did::new(actor_id.trim().to_owned())?,
        device_id: Some(device_id),
        sent_at,
        // Directed relay; soland enforces its own TTL. Stay a full minute
        // under the 5-minute ephemeral ceiling so clock skew / a closed-
        // interval check server-side can't reject a boundary value.
        expires_at: sent_at + chrono::Duration::minutes(4),
        payload: serde_json::to_value(&payload)?,
        proof: None,
    };
    http.post("/_arkret/self/ephemeral", &envelope)
        .await
        .map_err(anyhow::Error::from)
}
