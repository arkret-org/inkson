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

/// Default maximum DeviceMessage enqueue TTL (`device-lifecycle.md` §7).
const DEVICE_MESSAGE_MAX_ENQUEUE_TTL_HOURS: i64 = 24;

/// Parse a caller-chosen DeviceMessage `expires_at` and refuse, before any
/// network I/O, a value the queue would reject at enqueue: the Station admits
/// only `sent_at < expires_at <= sent_at + 24h`, with `sent_at` materialized at
/// enqueue. `now` stands in for that `sent_at`; the Station stays authoritative.
fn device_message_expiry(
    now: chrono::DateTime<chrono::Utc>,
    expires_at: &str,
) -> anyhow::Result<chrono::DateTime<chrono::Utc>> {
    let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at)
        .map_err(|error| anyhow::anyhow!("device message expires_at `{expires_at}`: {error}"))?
        .with_timezone(&chrono::Utc);
    if expires_at <= now {
        anyhow::bail!("device message expires_at must be later than the send time");
    }
    if expires_at > now + chrono::Duration::hours(DEVICE_MESSAGE_MAX_ENQUEUE_TTL_HOURS) {
        anyhow::bail!(
            "device message expires_at exceeds the {DEVICE_MESSAGE_MAX_ENQUEUE_TTL_HOURS} hour enqueue TTL"
        );
    }
    Ok(expires_at)
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
    let expires_at = device_message_expiry(crate::clock::now_utc(), expires_at)?;
    let account_id = target_actor
        .as_account_id()
        .ok_or_else(|| anyhow::anyhow!("device messages require an account target"))?;
    let destination = http.describe().await?.service_id;
    if destination != account_id.station_id {
        anyhow::bail!("device message target Station differs from the authenticated destination");
    }
    let target_device_id = arkret_sdk::DeviceId::new(target_device_id.to_owned())?;
    if is_secret_sharing_kind(&kind) {
        anyhow::bail!("ak.secret.request and ak.secret.send are not admitted in v1");
    }
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
    fn device_message_expiry_admits_only_the_enqueue_window() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-24T12:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        for admitted in [
            "2026-09-24T12:00:00.001Z",
            "2026-09-24T12:10:00.000Z",
            "2026-09-25T12:00:00.000Z",
            "2026-09-25T20:00:00.000+08:00",
        ] {
            let parsed = device_message_expiry(now, admitted).unwrap();
            assert!(parsed > now && parsed <= now + chrono::Duration::hours(24));
        }
        for refused in [
            "2026-09-24T12:00:00.000Z",
            "2026-09-24T11:59:59.999Z",
            "2026-09-25T12:00:00.001Z",
            "2026-09-26T12:00:00.000Z",
            "not-a-timestamp",
        ] {
            assert!(
                device_message_expiry(now, refused).is_err(),
                "{refused} must be refused"
            );
        }
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
