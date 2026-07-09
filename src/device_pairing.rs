//! Shared same-principal device-pairing approval helpers
//! (`crypto-media/device-lifecycle.md` §2.1 / §7).
//!
//! A new device requests authorization from an already-authorized sibling by
//! sending a `ck.key.verification.request` to-device message whose
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
    /// The exact payload handed to [`pairing_request_body`].
    pub request_payload: Value,
}

/// Parse every pending same-principal pairing request out of a to-device inbox.
///
/// Filters to `ck.key.verification.request` messages carrying
/// `purpose == "same_principal_device_authorization"` and the full pairing
/// material (`from_device`, `pairing_code`, `new_device_pubkey`,
/// `challenge_signature`). Incomplete requests are skipped.
pub fn parse_pending_pairing_requests(inbox: &[Value]) -> Vec<PendingPairingRequest> {
    inbox
        .iter()
        .filter_map(|message| {
            if message.get("kind").and_then(Value::as_str) != Some("ck.key.verification.request") {
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
            let challenge_signature = content.get("challenge_signature").and_then(Value::as_str)?;
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
            let mut request_payload = json!({
                "pairing_code": pairing_code,
                "new_device_pubkey": new_device_pubkey,
                "challenge_signature": challenge_signature,
                "device_metadata": device_metadata,
            });
            if !display_name.is_empty()
                && let Some(object) = request_payload.as_object_mut()
            {
                object.insert("display_name".to_owned(), json!(display_name));
            }
            Some(PendingPairingRequest {
                request_key,
                requesting_device_id: requesting_device_id.to_owned(),
                pairing_code: pairing_code.to_owned(),
                display_name,
                platform,
                expires_at,
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
    let pairing_code = payload
        .get("pairing_code")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("pairing payload is missing pairing_code"))?
        .to_owned();
    let new_device_pubkey = match payload.get("new_device_pubkey") {
        Some(value @ Value::Object(_)) => value.clone(),
        _ => anyhow::bail!("pairing payload is missing new_device_pubkey"),
    };
    let challenge_signature = payload
        .get("challenge_signature")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("pairing payload is missing challenge_signature"))?
        .to_owned();
    let display_name = payload
        .get("display_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let device_metadata = payload
        .get("device_metadata")
        .cloned()
        .unwrap_or_else(|| json!({}));
    Ok(arkret_sdk::AccountDevicePairRequestBody {
        pairing_code,
        new_device_pubkey,
        challenge_signature,
        display_name,
        device_metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_message() -> Value {
        json!({
            "kind": "ck.key.verification.request",
            "sender_principal_id": "did:web:alice",
            "sender_device_id": "ak:device:existing",
            "expires_at": "2026-06-17T12:00:00Z",
            "content": {
                "transaction_id": "txn-1",
                "from_device": "ak:device:01904100-0000-7000-8000-000000000001",
                "purpose": "same_principal_device_authorization",
                "pairing_code": "384921",
                "new_device_pubkey": {
                    "kid": "ak:device:01904100-0000-7000-8000-000000000001",
                    "alg": "EdDSA",
                    "public_key": "abc-123"
                },
                "challenge_signature": "challenge-signature",
                "device_metadata": {
                    "display_name": "New browser",
                    "platform": "browser"
                },
                "expires_at": "2026-06-17T12:00:00Z"
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
        assert_eq!(row.pairing_code, "384921");
        assert_eq!(row.display_name, "New browser");
        assert_eq!(row.platform, "browser");
        assert_eq!(row.expires_at, "2026-06-17T12:00:00Z");
    }

    #[test]
    fn skips_wrong_purpose_and_kind() {
        let mut wrong_purpose = request_message();
        wrong_purpose["content"]["purpose"] = json!("device_key_verification");
        let mut wrong_kind = request_message();
        wrong_kind["kind"] = json!("ck.secret.share");
        assert!(parse_pending_pairing_requests(&[wrong_purpose, wrong_kind]).is_empty());
    }

    #[test]
    fn skips_incomplete_material() {
        let mut missing_challenge = request_message();
        missing_challenge["content"]
            .as_object_mut()
            .unwrap()
            .remove("challenge_signature");
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
            "ak:device:01904100-0000-7000-8000-000000000001:384921"
        );
    }

    #[test]
    fn builds_body_from_request_payload() {
        let row = parse_pending_pairing_requests(&[request_message()])
            .pop()
            .unwrap();
        let body = pairing_request_body(&row.request_payload).expect("body");
        assert_eq!(body.pairing_code, "384921");
        assert_eq!(body.challenge_signature, "challenge-signature");
        assert_eq!(body.display_name.as_deref(), Some("New browser"));
        assert_eq!(
            body.new_device_pubkey["kid"],
            "ak:device:01904100-0000-7000-8000-000000000001"
        );
    }

    #[test]
    fn body_fails_closed_on_missing_pubkey() {
        let payload = json!({
            "pairing_code": "384921",
            "challenge_signature": "challenge-signature"
        });
        assert!(pairing_request_body(&payload).is_err());
    }
}
