//! Client-authored founding-device enrollment material.
//!
//! Inkson fixes the complete proof-free `ak.device.authorize` Event before it
//! asks the enrollment authority for a proof. The authority may append exactly
//! that proof; it may not assemble or rewrite the Event identity.

use anyhow::Context as _;
use chrono::{DateTime, Utc};

/// Canonical algorithms advertised by an Inkson founding device. The list is
/// UTF-8 bytewise sorted and is part of the Event identity.
pub const INKSON_DEVICE_ALGORITHMS: &[&str] = &["Ed25519", "HPKE-X25519-HKDF-SHA256-AES128GCM"];

pub fn inkson_device_algorithms() -> Vec<String> {
    INKSON_DEVICE_ALGORITHMS
        .iter()
        .map(|value| (*value).to_owned())
        .collect()
}

/// Build the complete client-fixed enrollment request. The returned preimage
/// is safe to persist in the public onboarding checkpoint; it contains public
/// keys and Event identity, but no handoff bearer or holder signature.
#[allow(clippy::too_many_arguments)]
pub fn prepare_device_enrollment_request(
    principal_id: arkret_sdk::Did,
    device_id: arkret_sdk::DeviceId,
    device_public_key: String,
    hpke_key: String,
    bootstrap_create_event_id: arkret_sdk::EventId,
    realm_id: arkret_sdk::RealmId,
    enrollment_authority_did: arkret_sdk::Did,
    created_at: DateTime<Utc>,
    hlc: arkret_sdk::Hlc,
) -> anyhow::Result<arkret_sdk::AccountDeviceEnrollRequestBody> {
    let authorization_ref = arkret_sdk::AuthorizationRef::new(format!(
        "{}#device-enrollment-authority",
        principal_id.as_str()
    ))
    .map_err(|error| anyhow::anyhow!("build device enrollment authority reference: {error}"))?;
    let payload: arkret_sdk::DeviceAuthorizePayload = serde_json::from_value(serde_json::json!({
        "principal_id": principal_id,
        "device_id": device_id,
        "device_public_key": device_public_key,
        "hpke_key": hpke_key,
        "algorithms": inkson_device_algorithms(),
        "authorized_by": principal_id,
        "not_before": arkret_sdk::canonical::format_timestamp_canonical(created_at),
        "enrollment_authority_binding": {
            "kind": "service_attested",
            "authority_did": enrollment_authority_did,
            "authorization_ref": authorization_ref,
        }
    }))
    .context("build canonical device authorize payload")?;
    let mut event = arkret_sdk::Event::new_at(
        "ak.device.authorize",
        arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        principal_id,
        1,
        hlc,
        serde_json::to_value(payload)?,
        created_at,
    )?;
    event.executed_by = Some(enrollment_authority_did);
    event.authorization_ref = Some(authorization_ref);
    event.prev_refs = vec![bootstrap_create_event_id];
    event.refresh_content_bound_identity()?;

    let request = arkret_sdk::AccountDeviceEnrollRequestBody {
        device_id,
        authorize_event_preimage: arkret_sdk::DeviceAuthorizeEventPreimage::try_from(event)?,
    };
    request.validate()?;
    Ok(request)
}

/// Ask the enrollment authority to append its proof, then validate the exact
/// returned Event and canonical outcome digest against the persisted request.
pub async fn request_signed_device_authorize(
    account_client: &arkret_sdk::http_client::Client,
    request: &arkret_sdk::AccountDeviceEnrollRequestBody,
) -> anyhow::Result<arkret_sdk::AccountDeviceEnrollOutcome> {
    let outcome = account_client
        .auth_device_enroll(request)
        .await
        .map_err(|error| anyhow::anyhow!("device-enroll: {error}"))?;
    outcome
        .validate_against(request)
        .context("validate device-enroll exact outcome")?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_request() -> arkret_sdk::AccountDeviceEnrollRequestBody {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../arkret-spec/spec/v1/artifacts/fixtures/device-bootstrap-fixture.json"
        ))
        .unwrap();
        serde_json::from_value(fixture["enroll_request"].clone()).unwrap()
    }

    #[test]
    fn fixture_request_validates_and_keeps_the_canonical_digest() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../arkret-spec/spec/v1/artifacts/fixtures/device-bootstrap-fixture.json"
        ))
        .unwrap();
        let request = fixture_request();
        request.validate().unwrap();
        assert_eq!(
            request.canonical_request_digest().unwrap().as_str(),
            fixture["canonical_request"]["expected_digest"]
                .as_str()
                .unwrap()
        );
    }

    #[test]
    fn tampering_any_client_fixed_event_field_changes_identity() {
        let request = fixture_request();
        let mut event = request.authorize_event_preimage.clone().into_event();
        event.payload.insert(
            "hpke_key".to_owned(),
            serde_json::Value::String(
                "z6LSdifferentHpkeKey111111111111111111111111111111".to_owned(),
            ),
        );
        assert!(event.verify_event_id_matches_content().is_err());
    }

    #[test]
    fn canonical_algorithms_are_protocol_names_and_sorted() {
        let algorithms = inkson_device_algorithms();
        assert!(algorithms.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(algorithms, INKSON_DEVICE_ALGORITHMS);
    }
}
