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

fn is_secret_sharing_kind(kind: &arkret_wire::ProtocolKind) -> bool {
    matches!(
        kind.as_str(),
        arkret_wire::SECRET_REQUEST_KIND | arkret_wire::SECRET_SEND_KIND
    )
}

fn has_current_verification_checkpoint(
    devices: &[arkret_sdk::AccountDeviceSummary],
    target_device_id: &arkret_sdk::DeviceId,
) -> bool {
    devices.iter().any(|device| {
        &device.device_id == target_device_id
            && device.status == arkret_sdk::DeviceSummaryStatus::Active
            && device.verification_state == arkret_sdk::DeviceSummaryVerificationState::Verified
            && device.verification_source.is_some()
            && device.authorized_event_ref.is_some()
            && device.signer_resolution_evidence_ref.is_some()
            && device.validate().is_ok()
    })
}

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
///
/// Device messages are not Realm Events and never enter an authority commit
/// stream: the queue carries an opaque `content` map under a protocol `kind`.
/// The caller prepares `content` (which may itself be a signed or sealed
/// object); this wraps it in the typed `DeviceMessagesSendRequestBody` and
/// POSTs it — the envelope adds no signing of its own.
pub async fn send_device_message(
    http: &arkret_sdk::http_client::Client,
    txn_id: &str,
    kind: arkret_wire::ProtocolKind,
    target_actor: &arkret_sdk::ActorId,
    target_device_id: &str,
    expires_at: &str,
    content: std::collections::BTreeMap<String, serde_json::Value>,
) -> anyhow::Result<DeviceMessagesSendOutcome> {
    let message_id = arkret_sdk::DeviceMessageId::new_v7_at(crate::clock::now_unix_ms());
    send_device_message_with_id(
        http,
        txn_id,
        message_id,
        kind,
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
pub async fn send_device_message_with_id(
    http: &arkret_sdk::http_client::Client,
    txn_id: &str,
    message_id: arkret_sdk::DeviceMessageId,
    kind: arkret_wire::ProtocolKind,
    target_actor: &arkret_sdk::ActorId,
    target_device_id: &str,
    expires_at: &str,
    content: std::collections::BTreeMap<String, serde_json::Value>,
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
    if is_secret_sharing_kind(&kind) {
        let viewer = http
            .account_viewer()
            .await
            .map_err(|error| anyhow::anyhow!("verify secret-sharing checkpoint: {error}"))?;
        if viewer.principal_id != account_id.principal_id
            || !has_current_verification_checkpoint(&viewer.devices, &target_device_id)
        {
            anyhow::bail!(
                "secret sharing requires a current verification checkpoint for the exact target device"
            );
        }
    }
    let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at)?.with_timezone(&chrono::Utc);
    let target = arkret_sdk::DeviceMessageTarget {
        device_message_id: message_id,
        kind,
        expires_at,
        content,
    };
    let payload = arkret_sdk::DeviceMessagesSendRequestBody {
        messages: std::collections::BTreeMap::from([(
            account_id.principal_id.clone(),
            std::collections::BTreeMap::from([(target_device_id, target)]),
        )]),
    };
    http.send_device_messages(txn_id, &payload)
        .await
        .map_err(anyhow::Error::from)
}

#[cfg(test)]
mod tests {
    use arkret_sdk::{
        DeviceSummaryStatus, DeviceSummaryVerificationSource, DeviceSummaryVerificationState,
    };

    use super::*;

    fn device(
        status: DeviceSummaryStatus,
        verification_state: DeviceSummaryVerificationState,
        verification_source: Option<DeviceSummaryVerificationSource>,
        with_checkpoint: bool,
    ) -> arkret_sdk::AccountDeviceSummary {
        serde_json::from_value(serde_json::json!({
            "device_id": "ak:device:01964137-0000-7000-8000-0000000000c1",
            "status": status,
            "verification_state": verification_state,
            "verification_source": verification_source,
            "authorized_event_ref": with_checkpoint.then_some("ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e"),
            "signer_resolution_evidence_ref": with_checkpoint.then_some("ak:signer_evidence:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        }))
        .expect("valid device summary fixture")
    }

    fn target_device_id() -> arkret_sdk::DeviceId {
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-0000000000c1".to_owned())
            .expect("device id")
    }

    #[test]
    fn secret_sharing_kinds_are_closed() {
        let request = arkret_wire::ProtocolKind::new(arkret_wire::SECRET_REQUEST_KIND).unwrap();
        let send = arkret_wire::ProtocolKind::new(arkret_wire::SECRET_SEND_KIND).unwrap();
        let other = arkret_wire::ProtocolKind::new("ak.example.notice").unwrap();
        assert!(is_secret_sharing_kind(&request));
        assert!(is_secret_sharing_kind(&send));
        assert!(!is_secret_sharing_kind(&other));
    }

    #[test]
    fn only_an_active_verified_exact_device_has_a_current_checkpoint() {
        let target = target_device_id();
        let active = device(
            DeviceSummaryStatus::Active,
            DeviceSummaryVerificationState::Verified,
            Some(DeviceSummaryVerificationSource::PairingCode),
            true,
        );
        assert!(has_current_verification_checkpoint(&[active], &target));

        let mut missing_signer_evidence = device(
            DeviceSummaryStatus::Active,
            DeviceSummaryVerificationState::Verified,
            Some(DeviceSummaryVerificationSource::PairingCode),
            true,
        );
        missing_signer_evidence.signer_resolution_evidence_ref = None;
        assert!(!has_current_verification_checkpoint(
            &[missing_signer_evidence],
            &target
        ));

        for invalid in [
            device(
                DeviceSummaryStatus::Revoked,
                DeviceSummaryVerificationState::Stale,
                Some(DeviceSummaryVerificationSource::PairingCode),
                true,
            ),
            device(
                DeviceSummaryStatus::GenerationFenced,
                DeviceSummaryVerificationState::Stale,
                Some(DeviceSummaryVerificationSource::Recovery),
                true,
            ),
            device(
                DeviceSummaryStatus::Active,
                DeviceSummaryVerificationState::Unresolved,
                None,
                false,
            ),
        ] {
            assert!(!has_current_verification_checkpoint(&[invalid], &target));
        }
        assert!(!has_current_verification_checkpoint(&[], &target));
    }
}
