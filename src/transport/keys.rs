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

use crate::models::KeysQueryOutcome;

#[cfg(test)]
fn is_secret_sharing_kind(kind: &arkret_wire::ProtocolKind) -> bool {
    matches!(
        kind.as_str(),
        arkret_wire::SECRET_REQUEST_KIND | arkret_wire::SECRET_SEND_KIND
    )
}

/// Default maximum DeviceMessage enqueue TTL (`device-lifecycle.md` §7).
#[cfg(test)]
const DEVICE_MESSAGE_MAX_ENQUEUE_TTL_HOURS: i64 = 24;

/// Parse a caller-chosen DeviceMessage `expires_at` and refuse, before any
/// network I/O, a value the queue would reject at enqueue: the Station admits
/// only `sent_at < expires_at <= sent_at + 24h`, with `sent_at` materialized at
/// enqueue. `now` stands in for that `sent_at`; the Station stays authoritative.
#[cfg(test)]
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

#[cfg(test)]
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
            "authorized_event_ref": with_checkpoint.then_some("ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e")
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

        let mut missing_authorization = device(
            DeviceSummaryStatus::Active,
            DeviceSummaryVerificationState::Verified,
            Some(DeviceSummaryVerificationSource::PairingCode),
            true,
        );
        missing_authorization.authorized_event_ref = None;
        assert!(!has_current_verification_checkpoint(
            &[missing_authorization],
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
