//! Current-session device enrollment (decision 0002, device-lifecycle.md §5.4).
//!
//! Under the delegated account-authority model the client cannot author the
//! founding `ak.device.authorize` proof itself: the trust root is the enrollment
//! authority (coauth) designated by the principal DID document. Founding-device
//! enrollment is a three-step orchestration:
//!
//! 1. derive this device's `device_public_key` from the persisted signing seed;
//! 2. bind it to actor sequence 1 and the root-signed PCR create Event;
//! 3. ask the enrollment authority to mint a signed `service_attested` `ak.device.authorize` Event,
//!    then submit both Events as one atomic bootstrap unit.
//!
//! Later devices never use this endpoint; they follow the user-approved
//! pairing/recovery flow.

use anyhow::Context as _;

/// Inputs the caller resolves for the atomic founding-device bootstrap. Kept as
/// a struct so the wasm onboarding site stays readable and the assembly is
/// unit testable without a live session.
pub struct DeviceEnrollmentRequest {
    /// This session's `device_id` (`ak:device:<uuid>`). The enrollment authority
    /// signs the `ak.device.authorize` for exactly this device so the projected
    /// `device_public_key` lands under the same id the session (and recovery)
    /// looks up.
    pub device_id: String,
    /// Multibase Ed25519 `device_public_key` (`z6Mk…`) of this session device.
    pub device_public_key: String,
    /// Root-signed `ak.realm.create` Event id for the atomic first-device
    /// bootstrap unit.
    pub bootstrap_create_event_id: String,
    /// Optional `not_before` RFC 3339 timestamp; coauth defaults to now when absent.
    pub not_before: Option<String>,
    /// This device's HPKE sealing public key (multibase, §5.4).
    pub hpke_key: String,
    /// Canonical sorted unique algorithm ids the device supports (§5.2/§5.4).
    pub algorithms: Vec<String>,
}

impl DeviceEnrollmentRequest {
    fn to_sdk_body(&self) -> anyhow::Result<arkret_sdk::AccountDeviceEnrollRequestBody> {
        let not_before = match self
            .not_before
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            Some(value) => Some(
                chrono::DateTime::parse_from_rfc3339(value.trim())
                    .context("parse device-enroll `not_before` as RFC 3339")?
                    .with_timezone(&chrono::Utc),
            ),
            None => None,
        };
        Ok(arkret_sdk::AccountDeviceEnrollRequestBody {
            device_id: arkret_sdk::DeviceId::new(self.device_id.trim().to_owned())
                .context("device-enroll `device_id`")?,
            device_public_key: self.device_public_key.clone(),
            hpke_key: self.hpke_key.clone(),
            algorithms: self.algorithms.clone(),
            actor_seq: 1,
            bootstrap_create_event_id: arkret_sdk::EventId::new(
                self.bootstrap_create_event_id.trim().to_owned(),
            )
            .context("device-enroll `bootstrap_create_event_id`")?,
            not_before,
        })
    }
}

/// Canonical algorithm ids a inkson device advertises in its
/// `ak.device.authorize` record: the default-MUST HPKE suite (secret / key
/// envelope sealing) plus the MLS v1 group algorithm. UTF-8 bytewise sorted.
pub const INKSON_DEVICE_ALGORITHMS: &[&str] =
    &["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"];

pub fn inkson_device_algorithms() -> Vec<String> {
    INKSON_DEVICE_ALGORITHMS
        .iter()
        .map(|value| (*value).to_owned())
        .collect()
}

/// Validate that the enrollment authority returned a usable, self-consistent
/// `ak.device.authorize` Event for *this* device before it is submitted. Returns
/// the parsed envelope on success.
///
/// Checks (fail-closed): the event is a `ak.device.authorize`, it is signed
/// (carries proofs — inkson never submits an unsigned enrollment event), and its
/// `payload.device_id` equals `expected_device_id` (this session's device id, so
/// a server bug cannot enroll a different device under this session).
#[cfg(test)]
pub fn parse_signed_device_authorize(
    signed_event: &serde_json::Value,
    expected_device_id: &str,
    expected_bootstrap_create_event_id: &str,
) -> anyhow::Result<arkret_sdk::Event> {
    let event: arkret_sdk::Event = serde_json::from_value(signed_event.clone())
        .map_err(|err| anyhow::anyhow!("decode signed device.authorize SDK Event: {err}"))?;
    validate_signed_device_authorize(
        event,
        expected_device_id,
        expected_bootstrap_create_event_id,
    )
}

fn validate_signed_device_authorize(
    event: arkret_sdk::Event,
    expected_device_id: &str,
    expected_bootstrap_create_event_id: &str,
) -> anyhow::Result<arkret_sdk::Event> {
    if event.kind.as_str() != "ak.device.authorize" {
        anyhow::bail!(
            "enrollment authority returned unexpected event kind {:?}",
            event.kind.as_str()
        );
    }
    if event.proofs.is_empty() {
        anyhow::bail!("enrollment authority returned an unsigned device.authorize");
    }
    if event.actor_seq != 1 {
        anyhow::bail!(
            "enrollment authority returned founding device.authorize with actor_seq {}, expected 1",
            event.actor_seq
        );
    }
    if event.prev_refs.len() != 1
        || event.prev_refs[0].as_str() != expected_bootstrap_create_event_id
    {
        anyhow::bail!(
            "enrollment authority returned device.authorize with predecessor {:?}, expected sole bootstrap create {:?}",
            event
                .prev_refs
                .iter()
                .map(|event_id| event_id.as_str())
                .collect::<Vec<_>>(),
            expected_bootstrap_create_event_id
        );
    }
    let payload_device_id = event
        .payload
        .get("device_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if payload_device_id != expected_device_id {
        anyhow::bail!(
            "device.authorize device_id {payload_device_id:?} does not match this session device {expected_device_id:?}"
        );
    }
    Ok(event)
}

/// Ask the enrollment authority for the fully-signed authorize Event without
/// submitting it. The first-device caller combines this Event with the
/// root-signed PCR create in one atomic batch.
pub async fn request_signed_device_authorize(
    account_client: &arkret_sdk::http_client::Client,
    request: &DeviceEnrollmentRequest,
    expected_device_id: &str,
) -> anyhow::Result<arkret_sdk::Event> {
    let sdk_request = request.to_sdk_body()?;
    let outcome = account_client
        .auth_device_enroll(&sdk_request)
        .await
        .map_err(|error| anyhow::anyhow!("device-enroll: {error}"))?;
    if outcome.device_id.as_str() != expected_device_id {
        anyhow::bail!(
            "device-enroll outcome device_id {:?} does not match this session device {:?}",
            outcome.device_id.as_str(),
            expected_device_id
        );
    }
    validate_signed_device_authorize(
        outcome.authorized_event,
        expected_device_id,
        request.bootstrap_create_event_id.trim(),
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn signed_device_authorize(device_id: &str) -> serde_json::Value {
        json!({
            "event_id": "ak:event:01964137-0000-7000-8000-000000000000",
            "kind": "ak.device.authorize",
            "realm_id": "ak:realm:01964137-0000-7000-8000-000000000001",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:01964137-0000-7000-8000-000000000001"},
            "actor_id": "did:webvh:example:users:alice",
            "executed_by": "did:webvh:example:auth-server",
            "authorization_ref": "did:webvh:example:users:alice#device-enrollment",
            "actor_seq": 1,
            "created_at": "2026-06-17T00:00:00.000Z",
            "hlc": "019641370000-0000-12345678",
            "prev_refs": ["ak:event:01964137-0000-7000-8000-000000000099"],
            "payload": {
                "principal_id": "did:webvh:example:users:alice",
                "device_id": device_id,
                "device_public_key": "z6MkExamplePublicKey",
                "authorized_by": { "did": "did:webvh:example:auth-server" },
                "not_before": "2026-06-17T00:00:00.000Z",
                "enrollment_authority_binding": {
                    "kind": "service_attested",
                    "authority_did": "did:webvh:example:auth-server",
                    "authorization_ref": "did:webvh:example:users:alice#device-enrollment"
                }
            },
            "proofs": [{
                "kind": "detached_jws",
                "alg": "EdDSA",
                "verification_method": "did:webvh:example:auth-server#enroll-key-1",
                "event_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "created_at": "2026-06-17T00:00:00.000Z",
                "domain": "did:webvh:example:auth-server",
                "audience": "did:webvh:soland.example",
                "jws": "ey.ey.sig"
            }]
        })
    }

    #[test]
    fn accepts_matching_signed_device_authorize() {
        let device_id = "ak:device:01964137-0000-7000-8000-000000000002";
        let event = signed_device_authorize(device_id);
        let parsed = parse_signed_device_authorize(
            &event,
            device_id,
            "ak:event:01964137-0000-7000-8000-000000000099",
        )
        .expect("parse");
        assert_eq!(parsed.kind.as_str(), "ak.device.authorize");
        assert_eq!(parsed.actor_seq, 1);
    }

    #[test]
    fn accepts_e2e_service_attested_device_authorize() {
        let device_id = "ak:device:01964137-0000-7000-8000-0000000000f1";
        let event = json!({
            "event_id": "ak:event:01964137-0000-7000-8000-00000000d0e1",
            "kind": "ak.device.authorize",
            "realm_id": "ak:realm:01964137-0000-7000-8000-00000000c0de",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:01964137-0000-7000-8000-00000000c0de"},
            "actor_id": "did:web:first.example",
            "executed_by": "did:web:auth.local.host",
            "authorization_ref": "did:web:first.example#device-enrollment",
            "actor_seq": 1,
            "created_at": "2026-06-22T00:00:00.000Z",
            "hlc": "019641370000-0000-12345678",
            "prev_refs": ["ak:event:01964137-0000-7000-8000-00000000beef"],
            "refs": [],
            "payload": {
                "principal_id": "did:web:first.example",
                "device_id": device_id,
                "device_public_key": "z6MkExamplePublicKey",
                "authorized_by": "did:web:auth.local.host",
                "not_before": "2026-06-22T00:00:00.000Z",
                "enrollment_authority_binding": {
                    "kind": "service_attested",
                    "authority_did": "did:web:auth.local.host",
                    "authorization_ref": "did:web:first.example#device-enrollment"
                }
            },
            "proofs": [{
                "kind": "detached_jws",
                "alg": "EdDSA",
                "verification_method": "did:web:auth.local.host#enroll-key-1",
                "event_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "created_at": "2026-06-22T00:00:00.000Z",
                "domain": "did:web:auth.local.host",
                "audience": "did:web:server.local",
                "jws": "ey.ey.sig"
            }]
        });
        let parsed = parse_signed_device_authorize(
            &event,
            device_id,
            "ak:event:01964137-0000-7000-8000-00000000beef",
        )
        .expect("parse");
        assert_eq!(parsed.kind.as_str(), "ak.device.authorize");
        assert_eq!(parsed.actor_seq, 1);
    }

    #[test]
    fn rejects_device_id_mismatch() {
        let event = signed_device_authorize("ak:device:01964137-0000-7000-8000-000000000002");
        let err = parse_signed_device_authorize(
            &event,
            "ak:device:01964137-0000-7000-8000-0000000000ff",
            "ak:event:01964137-0000-7000-8000-000000000099",
        )
        .expect_err("mismatch must fail closed");
        assert!(
            err.to_string()
                .contains("does not match this session device")
        );
    }

    #[test]
    fn rejects_unsigned_event() {
        let device_id = "ak:device:01964137-0000-7000-8000-000000000002";
        let mut event = signed_device_authorize(device_id);
        event["proofs"] = json!([]);
        let err = parse_signed_device_authorize(
            &event,
            device_id,
            "ak:event:01964137-0000-7000-8000-000000000099",
        )
        .expect_err("unsigned must fail closed");
        assert!(err.to_string().contains("unsigned"));
    }

    #[test]
    fn rejects_wrong_kind() {
        let device_id = "ak:device:01964137-0000-7000-8000-000000000002";
        let mut event = signed_device_authorize(device_id);
        event["kind"] = json!("ak.device.revoke");
        let err = parse_signed_device_authorize(
            &event,
            device_id,
            "ak:event:01964137-0000-7000-8000-000000000099",
        )
        .expect_err("wrong kind must fail closed");
        assert!(err.to_string().contains("unexpected event kind"));
    }

    #[test]
    fn rejects_non_founding_actor_sequence() {
        let device_id = "ak:device:01964137-0000-7000-8000-000000000002";
        let mut event = signed_device_authorize(device_id);
        event["actor_seq"] = json!(2);
        let err = parse_signed_device_authorize(
            &event,
            device_id,
            "ak:event:01964137-0000-7000-8000-000000000099",
        )
        .expect_err("post-bootstrap sequence must fail closed");
        assert!(err.to_string().contains("expected 1"));
    }

    #[test]
    fn rejects_wrong_bootstrap_predecessor() {
        let device_id = "ak:device:01964137-0000-7000-8000-000000000002";
        let event = signed_device_authorize(device_id);
        let err = parse_signed_device_authorize(
            &event,
            device_id,
            "ak:event:01964137-0000-7000-8000-0000000000ff",
        )
        .expect_err("wrong bootstrap predecessor must fail closed");
        assert!(err.to_string().contains("expected sole bootstrap create"));
    }
}
