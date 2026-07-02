//! Current-session device enrollment (decision 0002, device-lifecycle.md §5.4).
//!
//! Under the delegated account-authority model the client cannot author a
//! `ck.device.authorize` proof itself: the trust root is the enrollment
//! authority (coauth) designated by the principal DID document. Enrollment is a
//! three-step orchestration:
//!
//! 1. derive this device's `device_public_key` from the persisted signing seed;
//! 2. read the next `actor_seq` from the principal control stream's actor frontier on the Principal
//!    Server;
//! 3. ask the enrollment authority to mint a signed `service_attested` `ck.device.authorize` Event,
//!    then submit it verbatim to the Principal Server's `POST /_cokret/self/events`.
//!
//! The flow is idempotent at the caller: it is only invoked when the device
//! is not yet authorized, and a concurrent / already-applied authorization is
//! reported by the server (the submit is a CAS on `actor_seq`).

use crate::api::CokretApi;
use crate::coauth::CoauthApi;
use crate::secure_key_store::SigningSeedMaterial;

/// Inputs the caller resolves before invoking [`enroll_current_device`]. Kept as
/// a struct so the wasm bootstrap site stays readable and the assembly is unit
/// testable without a live session.
pub struct DeviceEnrollmentRequest {
    /// Active `ck.session.grant` JWT used for the enrollment endpoint.
    pub grant_jwt: String,
    /// Device holder DPoP proof bound to the grant `cnf.jkt`, minted for
    /// `POST <gate_account_base>/device-enroll`.
    pub dpop_proof: String,
    /// This session's `device_id` (`ck:device:<uuid>`). The enrollment authority
    /// signs the `ck.device.authorize` for exactly this device so the projected
    /// `device_public_key` lands under the same id the session (and recovery)
    /// looks up.
    pub device_id: String,
    /// Multibase Ed25519 `device_public_key` (`z6Mk…`) of this session device.
    pub device_public_key: String,
    /// Next `actor_seq` on the principal control stream (highest accepted + 1).
    pub actor_seq: u64,
    /// Optional `not_before` RFC 3339 timestamp; coauth defaults to now when absent.
    pub not_before: Option<String>,
    /// This device's HPKE sealing public key (multibase, §5.4).
    pub hpke_key: String,
    /// Canonical sorted unique algorithm ids the device supports (§5.2/§5.4).
    pub algorithms: Vec<String>,
}

/// Canonical algorithm ids a yougen device advertises in its
/// `ck.device.authorize` record: the default-MUST HPKE suite (secret / key
/// envelope sealing) plus the MLS v1 group algorithm. UTF-8 bytewise sorted.
pub const YOUGEN_DEVICE_ALGORITHMS: &[&str] = &[
    "ck.hpke_x25519_aead_xchacha20poly1305.v1",
    "ck.mls.v1",
];

pub fn yougen_device_algorithms() -> Vec<String> {
    YOUGEN_DEVICE_ALGORITHMS
        .iter()
        .map(|value| (*value).to_owned())
        .collect()
}

/// Multibase Ed25519 `device_public_key` for the device described by `material`.
pub fn device_public_key_multibase(material: &SigningSeedMaterial) -> String {
    let verifying = ed25519_dalek::SigningKey::from_bytes(&material.seed).verifying_key();
    crate::did_key::encode_ed25519_did_key_multibase(&verifying)
}

/// Validate that the enrollment authority returned a usable, self-consistent
/// `ck.device.authorize` Event for *this* device before it is submitted. Returns
/// the parsed envelope on success.
///
/// Checks (fail-closed): the event is a `ck.device.authorize`, it is signed
/// (carries proofs — yougen never submits an unsigned enrollment event), and its
/// `payload.device_id` equals `expected_device_id` (this session's device id, so
/// a server bug cannot enroll a different device under this session).
pub fn parse_signed_device_authorize(
    signed_event: &serde_json::Value,
    expected_device_id: &str,
) -> anyhow::Result<cokret_sdk::Event> {
    let event: cokret_sdk::Event = serde_json::from_value(signed_event.clone())
        .map_err(|err| anyhow::anyhow!("decode signed device.authorize SDK Event: {err}"))?;
    if event.kind.as_str() != "ck.device.authorize" {
        anyhow::bail!(
            "enrollment authority returned unexpected event kind {:?}",
            event.kind.as_str()
        );
    }
    if event.proofs.is_empty() {
        anyhow::bail!("enrollment authority returned an unsigned device.authorize");
    }
    let payload_device_id = event
        .content
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

/// Enroll the current session device: ask `coauth` to sign a
/// `ck.device.authorize` for `request`, then submit it through `principal_api`
/// (`POST /_cokret/self/events`). `expected_device_id` is this session's
/// self-certifying id, used to fail closed if the returned event addresses a
/// different device.
pub async fn enroll_current_device(
    coauth: &CoauthApi,
    principal_api: &CokretApi,
    request: &DeviceEnrollmentRequest,
    expected_device_id: &str,
) -> anyhow::Result<()> {
    let signed_event = coauth
        .device_enroll_signed_event(
            &request.grant_jwt,
            &request.dpop_proof,
            &request.device_id,
            &request.device_public_key,
            &request.hpke_key,
            &request.algorithms,
            request.actor_seq,
            request.not_before.as_deref(),
        )
        .await?;
    let event = parse_signed_device_authorize(&signed_event, expected_device_id)?;
    principal_api.submit_signed_sdk_event(&event).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn signed_device_authorize(device_id: &str) -> serde_json::Value {
        json!({
            "event_id": "ck:event:01964137-0000-7000-8000-000000000000",
            "kind": "ck.device.authorize",
            "realm_id": "ck:realm:01964137-0000-7000-8000-000000000001",
            "actor_id": "did:webvh:example:users:alice",
            "executed_by": "did:webvh:example:auth-server",
            "authorization_ref": "did:webvh:example:users:alice#device-enrollment",
            "actor_seq": 3,
            "created_at": "2026-06-17T00:00:00Z",
            "hlc": "019641370000-0000-12345678",
            "prev_refs": [],
            "payload": {
                "principal_id": "did:webvh:example:users:alice",
                "device_id": device_id,
                "device_public_key": "z6MkExamplePublicKey",
                "authorized_by": { "did": "did:webvh:example:auth-server" },
                "not_before": "2026-06-17T00:00:00Z",
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
                "created_at": "2026-06-17T00:00:00Z",
                "domain": "did:webvh:example:auth-server",
                "audience": "did:webvh:soland.example",
                "jws": "ey.ey.sig"
            }]
        })
    }

    #[test]
    fn accepts_matching_signed_device_authorize() {
        let device_id = "ck:device:01964137-0000-7000-8000-000000000002";
        let event = signed_device_authorize(device_id);
        let parsed = parse_signed_device_authorize(&event, device_id).expect("parse");
        assert_eq!(parsed.kind.as_str(), "ck.device.authorize");
        assert_eq!(parsed.actor_seq, 3);
    }

    #[test]
    fn accepts_e2e_service_attested_device_authorize() {
        let device_id = "ck:device:01964137-0000-7000-8000-0000000000f1";
        let event = json!({
            "event_id": "ck:event:01964137-0000-7000-8000-00000000d0e1",
            "kind": "ck.device.authorize",
            "realm_id": "ck:realm:01964137-0000-7000-8000-00000000c0de",
            "actor_id": "did:web:first.example",
            "executed_by": "did:web:auth.local.host",
            "authorization_ref": "did:web:first.example#device-enrollment",
            "actor_seq": 1,
            "created_at": "2026-06-22T00:00:00Z",
            "hlc": "019641370000-0000-12345678",
            "prev_refs": [],
            "refs": [],
            "payload": {
                "principal_id": "did:web:first.example",
                "device_id": device_id,
                "device_public_key": "z6MkExamplePublicKey",
                "authorized_by": "did:web:auth.local.host",
                "not_before": "2026-06-22T00:00:00Z",
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
                "created_at": "2026-06-22T00:00:00Z",
                "domain": "did:web:auth.local.host",
                "audience": "did:web:server.local",
                "jws": "ey.ey.sig"
            }]
        });
        let parsed = parse_signed_device_authorize(&event, device_id).expect("parse");
        assert_eq!(parsed.kind.as_str(), "ck.device.authorize");
        assert_eq!(parsed.actor_seq, 1);
    }

    #[test]
    fn rejects_device_id_mismatch() {
        let event = signed_device_authorize("ck:device:01964137-0000-7000-8000-000000000002");
        let err =
            parse_signed_device_authorize(&event, "ck:device:01964137-0000-7000-8000-0000000000ff")
                .expect_err("mismatch must fail closed");
        assert!(
            err.to_string()
                .contains("does not match this session device")
        );
    }

    #[test]
    fn rejects_unsigned_event() {
        let device_id = "ck:device:01964137-0000-7000-8000-000000000002";
        let mut event = signed_device_authorize(device_id);
        event["proofs"] = json!([]);
        let err = parse_signed_device_authorize(&event, device_id)
            .expect_err("unsigned must fail closed");
        assert!(err.to_string().contains("unsigned"));
    }

    #[test]
    fn rejects_wrong_kind() {
        let device_id = "ck:device:01964137-0000-7000-8000-000000000002";
        let mut event = signed_device_authorize(device_id);
        event["kind"] = json!("ck.device.revoke");
        let err = parse_signed_device_authorize(&event, device_id)
            .expect_err("wrong kind must fail closed");
        assert!(err.to_string().contains("unexpected event kind"));
    }
}
