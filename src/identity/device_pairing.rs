//! Shared same-principal device-pairing approval helpers
//! (`crypto-media/device-lifecycle.md` §2.1 / §7).
//!
//! A new device requests authorization from an already-authorized sibling by
//! sending a `ak.key.verification.request` to-device message whose
//! `content.purpose == "same_principal_device_authorization"`. The receiving
//! device MUST surface the `pairing_code` for user comparison and only finalize
//! through `POST /_arkret/gate/account/device-pair` after explicit approval — it
//! must not trust the new device merely because the request arrived.
//!
//! Both the settings "Requests awaiting this device" card and the global
//! [`crate::components::DevicePairApprovalPrompt`] parse the same to-device
//! inbox and build the same `account_device_pair` body, so that logic lives here
//! once instead of being duplicated per surface.

use serde_json::{Value, json};

/// One pending same-principal pairing request parsed from the to-device inbox.
#[derive(Clone, Debug, PartialEq)]
pub struct PendingPairingRequest {
    /// Stable key for dedup / dismissal — the request `transaction_id` when
    /// present, otherwise `{requesting_device_id}:{pairing_code}`.
    pub request_key: String,
    /// The new device asking to be authorized (`content.from_device`).
    pub requesting_device_id: String,
    /// Short code the user compares on both devices before approving.
    pub pairing_code: String,
    /// Friendly device name from `device_metadata.display_name` (may be empty).
    pub display_name: String,
    /// Platform hint from `device_metadata.platform` (may be empty).
    pub platform: String,
    /// RFC 3339 expiry of the request.
    pub expires_at: String,
    /// When the new device staged its request through the server-mediated
    /// short-link (`ak.open.device_pairing.command.stage`), the staged
    /// `device_pairing_request_id`. Echoed back into `account_device_pair` so the
    /// server flips the staged row to `authorized` for the new device's status
    /// poll. `None` for direct QR/paste pairing.
    pub device_pairing_request_id: Option<String>,
    /// The exact payload handed to [`pairing_request_body`].
    pub request_payload: Value,
}

/// Parse every pending same-principal pairing request out of a to-device inbox.
///
/// Filters to `ak.key.verification.request` messages carrying
/// `purpose == "same_principal_device_authorization"` and the full pairing
/// material (`from_device`, `pairing_code`, `new_device_pubkey`,
/// `challenge_proof`). Incomplete requests are skipped.
pub fn parse_pending_pairing_requests(inbox: &[Value]) -> Vec<PendingPairingRequest> {
    inbox
        .iter()
        .filter_map(|message| {
            if message.get("kind").and_then(Value::as_str) != Some("ak.key.verification.request") {
                return None;
            }
            let content = message.get("content")?;
            if content.get("purpose").and_then(Value::as_str)
                != Some("same_principal_device_authorization")
            {
                return None;
            }
            let requesting_device_id = content.get("from_device").and_then(Value::as_str)?;
            let pairing_code = content.get("pairing_code").and_then(Value::as_str)?;
            let new_device_pubkey = content.get("new_device_pubkey")?.clone();
            let challenge_proof = content.get("challenge_proof")?.clone();
            let hpke_key = content.get("hpke_key")?.clone();
            let device_signature = content.get("device_signature")?.clone();
            let authorize_event = content.get("authorize_event")?.clone();
            let device_metadata = content
                .get("device_metadata")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let display_name = device_metadata
                .get("display_name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_owned();
            let platform = device_metadata
                .get("platform")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_owned();
            let expires_at = content
                .get("expires_at")
                .or_else(|| message.get("expires_at"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let request_key = content
                .get("transaction_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| format!("{requesting_device_id}:{pairing_code}"));
            let device_pairing_request_id = content
                .get("device_pairing_request_id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            let mut request_payload = json!({
                "pairing_code": pairing_code,
                "new_device_pubkey": new_device_pubkey,
                "hpke_key": hpke_key,
                "device_signature": device_signature,
                "challenge_proof": challenge_proof,
                "authorize_event": authorize_event,
                "device_metadata": device_metadata,
            });
            if !display_name.is_empty()
                && let Some(object) = request_payload.as_object_mut()
            {
                object.insert("display_name".to_owned(), json!(display_name));
            }
            if let Some(request_id) = device_pairing_request_id.as_deref()
                && let Some(object) = request_payload.as_object_mut()
            {
                object.insert("device_pairing_request_id".to_owned(), json!(request_id));
            }
            if let Some(challenge_transcript) = content.get("challenge_transcript")
                && let Some(object) = request_payload.as_object_mut()
            {
                object.insert(
                    "challenge_transcript".to_owned(),
                    challenge_transcript.clone(),
                );
            }
            Some(PendingPairingRequest {
                request_key,
                requesting_device_id: requesting_device_id.to_owned(),
                pairing_code: pairing_code.to_owned(),
                display_name,
                platform,
                expires_at,
                device_pairing_request_id,
                request_payload,
            })
        })
        .collect()
}

/// Build the strongly-typed `account_device_pair` body from a parsed request
/// payload (or a pasted QR payload of the same shape). Fails closed when the
/// required pairing material is missing or malformed.
pub fn pairing_request_body(
    payload: &Value,
) -> anyhow::Result<arkret_sdk::AccountDevicePairRequestBody> {
    let pairing_code = arkret_sdk::DevicePairingCode::new(
        payload
            .get("pairing_code")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("pairing payload is missing pairing_code"))?
            .to_owned(),
    )
    .map_err(anyhow::Error::msg)?;
    let new_device_pubkey = match payload.get("new_device_pubkey") {
        Some(value @ Value::Object(_)) => serde_json::from_value(value.clone())?,
        _ => anyhow::bail!("pairing payload is missing new_device_pubkey"),
    };
    let hpke_key = payload
        .get("hpke_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .map(arkret_sdk::NonEmptyString::new)
        .transpose()
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("pairing payload is missing hpke_key"))?;
    let device_signature = payload
        .get("device_signature")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("pairing payload is missing device_signature"))
        .and_then(|value| serde_json::from_value(value).map_err(anyhow::Error::from))?;
    let authorize_event = payload
        .get("authorize_event")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("pairing payload is missing authorize_event"))
        .and_then(|value| serde_json::from_value(value).map_err(anyhow::Error::from))?;
    let challenge_proof = payload
        .get("challenge_proof")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("pairing payload is missing challenge_proof"))
        .and_then(|value| serde_json::from_value(value).map_err(anyhow::Error::from))?;
    let display_name = payload
        .get("display_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(arkret_sdk::NonEmptyString::new)
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let device_metadata = payload
        .get("device_metadata")
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()?;
    let device_pairing_request_id = payload
        .get("device_pairing_request_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .map(arkret_sdk::DevicePairingRequestId::new)
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let challenge_transcript = payload
        .get("challenge_transcript")
        .cloned()
        .map(serde_json::from_value)
        .transpose()?;
    let body = arkret_sdk::AccountDevicePairRequestBody {
        pairing_code,
        new_device_pubkey,
        hpke_key,
        device_signature,
        challenge_proof,
        authorize_event,
        display_name,
        device_metadata,
        device_pairing_request_id,
        challenge_transcript,
    };
    body.validate_authorize_event_binding()?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_message() -> Value {
        json!({
            "kind": "ak.key.verification.request",
            "sender_principal_id": "did:web:alice",
            "sender_device_id": "ak:device:existing",
            "expires_at": "2026-06-17T12:00:00.000Z",
            "content": {
                "transaction_id": "txn-1",
                "from_device": "ak:device:01904100-0000-7000-8000-000000000001",
                "purpose": "same_principal_device_authorization",
                "pairing_code": "7H2K9M4Q",
                "new_device_pubkey": {
                    "kty": "OKP",
                    "kid": "ak:device:01904100-0000-7000-8000-000000000001",
                    "algorithm": "Ed25519",
                    "key": "abc-123"
                },
                "challenge_proof": {
                    "transcript": "ak.device-pairing.challenge.v1",
                    "kid": "ak:device:01904100-0000-7000-8000-000000000001",
                    "signature_algorithm": "Ed25519",
                    "transcript_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "signature": "Y2hhbGxlbmdlLXNpZ25hdHVyZQ"
                },
                "device_pairing_request_id": "device_pairing_request:01904100-0000-7000-8000-000000000001",
                "device_metadata": {
                    "display_name": "New browser",
                    "platform": "browser"
                },
                "expires_at": "2026-06-17T12:00:00.000Z"
            }
        })
    }

    #[test]
    fn parses_same_principal_request_with_metadata() {
        let rows = parse_pending_pairing_requests(&[request_message()]);
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.request_key, "txn-1");
        assert_eq!(
            row.requesting_device_id,
            "ak:device:01904100-0000-7000-8000-000000000001"
        );
        assert_eq!(row.pairing_code, "7H2K9M4Q");
        assert_eq!(row.display_name, "New browser");
        assert_eq!(row.platform, "browser");
        assert_eq!(row.expires_at, "2026-06-17T12:00:00.000Z");
    }

    #[test]
    fn skips_wrong_purpose_and_kind() {
        let mut wrong_purpose = request_message();
        wrong_purpose["content"]["purpose"] = json!("device_key_verification");
        let mut wrong_kind = request_message();
        wrong_kind["kind"] = json!("ak.secret.share");
        assert!(parse_pending_pairing_requests(&[wrong_purpose, wrong_kind]).is_empty());
    }

    #[test]
    fn skips_incomplete_material() {
        let mut missing_challenge = request_message();
        missing_challenge["content"]
            .as_object_mut()
            .unwrap()
            .remove("challenge_proof");
        assert!(parse_pending_pairing_requests(&[missing_challenge]).is_empty());
    }

    #[test]
    fn falls_back_to_device_and_code_request_key() {
        let mut no_txn = request_message();
        no_txn["content"]
            .as_object_mut()
            .unwrap()
            .remove("transaction_id");
        let rows = parse_pending_pairing_requests(&[no_txn]);
        assert_eq!(
            rows[0].request_key,
            "ak:device:01904100-0000-7000-8000-000000000001:7H2K9M4Q"
        );
    }

    #[test]
    fn builds_body_from_request_payload() {
        let row = parse_pending_pairing_requests(&[request_message()])
            .pop()
            .unwrap();
        let body = pairing_request_body(&row.request_payload).expect("body");
        assert_eq!(body.pairing_code.as_str(), "7H2K9M4Q");
        assert_eq!(
            body.challenge_proof.transcript.as_str(),
            "ak.device-pairing.challenge.v1"
        );
        assert_eq!(body.display_name.as_deref(), Some("New browser"));
        assert_eq!(body.new_device_pubkey.kty.as_str(), "OKP");
        assert_eq!(body.new_device_pubkey.key.as_str(), "abc-123");
        assert_eq!(
            body.new_device_pubkey.kid.as_str(),
            "ak:device:01904100-0000-7000-8000-000000000001"
        );
    }

    #[test]
    fn body_accepts_canonical_pubkey_with_kty() {
        let payload = json!({
            "pairing_code": "7H2K9M4Q",
            "challenge_proof": {
                "transcript": "ak.device-pairing.challenge.v1",
                "kid": "ak:device:01904100-0000-7000-8000-000000000001",
                "signature_algorithm": "Ed25519",
                "transcript_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "signature": "Y2hhbGxlbmdlLXNpZ25hdHVyZQ"
            },
            "device_pairing_request_id": "device_pairing_request:01904100-0000-7000-8000-000000000001",
            "new_device_pubkey": {
                "kty": "OKP",
                "kid": "ak:device:01904100-0000-7000-8000-000000000001",
                "algorithm": "Ed25519",
                "key": "abc-123"
            }
        });
        let body = pairing_request_body(&payload).expect("canonical body");
        assert_eq!(body.new_device_pubkey.kty.as_str(), "OKP");
        assert_eq!(body.new_device_pubkey.key.as_str(), "abc-123");
    }

    #[test]
    fn body_rejects_noncanonical_public_key_field() {
        let payload = json!({
            "pairing_code": "7H2K9M4Q",
            "challenge_proof": {
                "transcript": "ak.device-pairing.challenge.v1",
                "kid": "ak:device:01904100-0000-7000-8000-000000000001",
                "signature_algorithm": "Ed25519",
                "transcript_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "signature": "Y2hhbGxlbmdlLXNpZ25hdHVyZQ"
            },
            "device_pairing_request_id": "device_pairing_request:01904100-0000-7000-8000-000000000001",
            "new_device_pubkey": {
                "kty": "OKP",
                "kid": "ak:device:01904100-0000-7000-8000-000000000001",
                "algorithm": "Ed25519",
                "public_key": "abc-123"
            }
        });
        assert!(pairing_request_body(&payload).is_err());
    }

    #[test]
    fn body_fails_closed_on_missing_pubkey() {
        let payload = json!({
            "pairing_code": "7H2K9M4Q",
            "challenge_proof": {
                "transcript": "ak.device-pairing.challenge.v1",
                "kid": "ak:device:01904100-0000-7000-8000-000000000001",
                "signature_algorithm": "Ed25519",
                "transcript_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "signature": "Y2hhbGxlbmdlLXNpZ25hdHVyZQ"
            },
            "device_pairing_request_id": "device_pairing_request:01904100-0000-7000-8000-000000000001"
        });
        assert!(pairing_request_body(&payload).is_err());
    }
}
