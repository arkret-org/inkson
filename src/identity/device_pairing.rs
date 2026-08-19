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

pub fn sign_target_attestation(
    signer: &crate::event_signer::InksonEventSigner,
    actor_id: &str,
    device_id: &str,
    transcript_digest: arkret_sdk::Hash,
) -> anyhow::Result<arkret_sdk::DevicePairingTargetAttestation> {
    let signer_device = signer
        .device_id()
        .ok_or_else(|| anyhow::anyhow!("device pairing signer is not bound to a device"))?;
    if signer_device != device_id {
        anyhow::bail!("device pairing signer does not match the target device");
    }
    let public_key_multibase = signer
        .public_key_multibase()
        .ok_or_else(|| anyhow::anyhow!("target device signer cannot expose its Ed25519 key"))?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let (_, hpke_public_key) = crate::mls::runtime::load_or_create_device_hpke_keypair(
        secure_store.as_ref(),
        actor_id,
        device_id,
    )?;
    let unsigned = arkret_sdk::UnsignedDevicePairingTargetAttestation::new(
        arkret_sdk::DeviceId::new(device_id.to_owned())?,
        arkret_sdk::DidKey::new(format!("did:key:{public_key_multibase}"))
            .map_err(anyhow::Error::msg)?,
        arkret_sdk::NonEmptyString::new(crate::identity::did_key::encode_x25519_multibase(
            &hpke_public_key,
        ))
        .map_err(anyhow::Error::msg)?,
        vec![
            arkret_sdk::NonEmptyString::new(
                arkret_wire::HPKE_SUITE_X25519_CHACHA20POLY1305_V1.to_owned(),
            )
            .map_err(anyhow::Error::msg)?,
            arkret_sdk::NonEmptyString::new(arkret_sdk::mls::ARKRET_MLS_ALGORITHM.to_owned())
                .map_err(anyhow::Error::msg)?,
        ],
        transcript_digest,
    )?;
    let signature = arkret_sdk::NonEmptyString::new(arkret_sdk::base64url_encode(
        signer.sign_raw(&unsigned.signing_input()?)?,
    ))
    .map_err(anyhow::Error::msg)?;
    let attestation =
        unsigned.attach_signature(arkret_sdk::SignatureMaterial::NonEmptyString(signature));
    arkret_sdk::signatures::device_pairing::verify_device_pairing_target_attestation(&attestation)?;
    Ok(attestation)
}

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
    /// The exact payload handed to [`author_pairing_request_body`].
    pub request_payload: Value,
}

/// Parse every pending same-principal pairing request out of a to-device inbox.
///
/// Filters to `ak.key.verification.request` messages carrying
/// `purpose == "same_principal_device_authorization"` and the full pairing
/// material (`from_device`, `pairing_code`, `new_device_pubkey`,
/// `target_attestation`, `challenge_proof`).
/// Incomplete requests are skipped.
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
            let target_attestation = content.get("target_attestation")?.clone();
            let challenge_proof = content.get("challenge_proof")?.clone();
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
                "target_attestation": target_attestation,
                "challenge_proof": challenge_proof,
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
            if let Some(gate_audience) = content.get("gate_audience")
                && let Some(object) = request_payload.as_object_mut()
            {
                object.insert("gate_audience".to_owned(), gate_audience.clone());
            }
            if let Some(server_challenge) = content.get("server_challenge")
                && let Some(object) = request_payload.as_object_mut()
            {
                object.insert("server_challenge".to_owned(), server_challenge.clone());
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

/// After the approving user confirms the displayed code, verify the target's
/// possession attestation and only then author the exact authorize Event.  The
/// target never authors or supplies this Event.
pub async fn author_pairing_request_body(
    api: &crate::transport::TransportClient,
    payload: &Value,
) -> anyhow::Result<arkret_sdk::AccountDevicePairRequestBody> {
    let attestation: arkret_sdk::DevicePairingTargetAttestation = serde_json::from_value(
        payload
            .get("target_attestation")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("pairing payload is missing target_attestation"))?,
    )?;
    arkret_sdk::signatures::device_pairing::verify_device_pairing_target_attestation(&attestation)?;
    let challenge_proof: arkret_sdk::DevicePairingChallengeProof = serde_json::from_value(
        payload
            .get("challenge_proof")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("pairing payload is missing challenge_proof"))?,
    )?;
    if challenge_proof.transcript_digest != attestation.pairing_challenge_transcript_digest {
        anyhow::bail!(
            "pairing challenge proof and target attestation describe different transcripts"
        );
    }
    let new_device_pubkey: arkret_sdk::PublicKey = serde_json::from_value(
        payload
            .get("new_device_pubkey")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("pairing payload is missing new_device_pubkey"))?,
    )?;
    if new_device_pubkey.kid.as_str() != attestation.device_id.as_str() {
        anyhow::bail!("pairing public key and target attestation name different devices");
    }
    match challenge_proof.transcript {
        arkret_sdk::DevicePairingChallengeTranscriptKind::ServerMediated => {
            let challenge = payload
                .get("server_challenge")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    anyhow::anyhow!("server-mediated pairing omitted its exact challenge")
                })?;
            let server_challenge =
                arkret_sdk::signatures::device_pairing::ServerDevicePairingChallenge {
                    client_nonce: arkret_sdk::DevicePairingNonce::new(required_string(
                        challenge,
                        "client_nonce",
                    )?)
                    .map_err(anyhow::Error::msg)?,
                    device_pairing_request_id: arkret_sdk::DevicePairingRequestId::new(
                        required_string(challenge, "device_pairing_request_id")?,
                    )
                    .map_err(anyhow::Error::msg)?,
                    expires_at: required_string(challenge, "expires_at")?
                        .parse::<chrono::DateTime<chrono::Utc>>()?,
                    gate_audience: required_string(challenge, "gate_audience")?,
                    pairing_code: arkret_sdk::DevicePairingCode::new(required_string(
                        challenge,
                        "pairing_code",
                    )?)
                    .map_err(anyhow::Error::msg)?,
                    server_nonce: arkret_sdk::DevicePairingNonce::new(required_string(
                        challenge,
                        "server_nonce",
                    )?)
                    .map_err(anyhow::Error::msg)?,
                };
            arkret_sdk::signatures::device_pairing::verify_server_device_pairing_challenge(
                &new_device_pubkey,
                &server_challenge,
                &challenge_proof,
                chrono::Utc::now(),
            )?;
        }
        arkret_sdk::DevicePairingChallengeTranscriptKind::ToDevice => {
            let transcript: arkret_sdk::DevicePairingToDeviceChallengeTranscript =
                serde_json::from_value(payload.get("challenge_transcript").cloned().ok_or_else(
                    || anyhow::anyhow!("to-device pairing omitted its exact transcript"),
                )?)?;
            let gate_audience = payload
                .get("gate_audience")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("to-device pairing omitted gate_audience"))?;
            let pairing_code = arkret_sdk::DevicePairingCode::new(
                payload
                    .get("pairing_code")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("pairing payload is missing pairing_code"))?
                    .to_owned(),
            )
            .map_err(anyhow::Error::msg)?;
            arkret_sdk::signatures::device_pairing::verify_to_device_pairing_challenge(
                &new_device_pubkey,
                &pairing_code,
                gate_audience,
                &transcript,
                &challenge_proof,
                chrono::Utc::now(),
            )?;
        }
    }

    let principal = arkret_sdk::DidFullId::new(
        crate::secure_key_store::active_device_seed_scope()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("no active principal can approve device pairing"))?,
    )?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("no active device signer can approve device pairing"))?;
    let authorizing_device = arkret_sdk::DeviceId::new(
        signer
            .device_id()
            .ok_or_else(|| anyhow::anyhow!("active pairing approver is not device-bound"))?
            .to_owned(),
    )?;
    let device_signature = match &attestation.device_signature {
        arkret_sdk::SignatureMaterial::NonEmptyString(value) => {
            arkret_sdk::Base64UrlString::new(value.as_str().to_owned())
                .map_err(anyhow::Error::msg)?
        }
        _ => anyhow::bail!("accepted-device target attestation must use a base64url signature"),
    };
    let created_at = chrono::Utc::now();
    let principal_actor = arkret_sdk::project_full_id_to_core_id(&principal)?;
    let authorize_payload = arkret_sdk::UnsignedDeviceAuthorizePayload::new(
        principal_actor.clone(),
        attestation.device_id.clone(),
        arkret_sdk::NonEmptyString::new(attestation.device_public_key.as_str().to_owned())
            .map_err(anyhow::Error::msg)?,
        attestation.hpke_key.clone(),
        attestation.algorithms.clone(),
        Some(arkret_sdk::NonEmptyString::new("Ed25519".to_owned()).map_err(anyhow::Error::msg)?),
        arkret_sdk::DeviceOrPrincipalRef::DeviceId(authorizing_device),
        None,
        created_at,
        None,
        arkret_sdk::DeviceAuthorizationBindingKind::AcceptedDevice,
        None,
    )?
    .attach_signature(device_signature)?;
    let http = api.sdk_http_client()?;
    let realm_id =
        crate::identity::principal_control::resolve_accepted(&http, &principal_actor).await?;
    let authorize = crate::operation::TypedOperationBuilder::new::<
        arkret_sdk::event_spec::DeviceAuthorize,
    >(realm_id.as_str(), principal.as_str(), authorize_payload)
    .created_at(created_at)
    .build_sdk_event("inkson-device-pairing")?;
    let submitter = api.event_submitter()?;
    let authorized = submitter
        .author_independent_events(vec![authorize.into_intent()])
        .await?;
    let authorize_event = submitter
        .prepare_initial_submissions(&authorized)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("device authorize Event was not prepared"))?;

    let pairing_code = arkret_sdk::DevicePairingCode::new(
        payload
            .get("pairing_code")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("pairing payload is missing pairing_code"))?
            .to_owned(),
    )
    .map_err(anyhow::Error::msg)?;
    let display_name = payload
        .get("display_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| arkret_sdk::NonEmptyString::new(value.to_owned()))
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
        .map(|value| arkret_sdk::DevicePairingRequestId::new(value.to_owned()))
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let challenge_transcript = payload
        .get("challenge_transcript")
        .cloned()
        .map(serde_json::from_value)
        .transpose()?;
    let request = arkret_sdk::AccountDevicePairRequestBody {
        pairing_code,
        new_device_pubkey,
        hpke_key: attestation.hpke_key.clone(),
        device_signature: attestation.device_signature.clone(),
        challenge_proof,
        authorize_event,
        display_name,
        device_metadata,
        device_pairing_request_id,
        challenge_transcript,
    };
    attestation.validate_against_pair_request(&request)?;
    Ok(request)
}

/// Target-device fence before treating an `authorized` status as success.
/// The status row is only an index; trust comes from the exact accepted Event
/// and its target-owned attestation binding.
pub async fn verify_authorized_pairing_event(
    http: &arkret_sdk::http_client::Client,
    principal: &arkret_sdk::DidFullId,
    outcome: &arkret_sdk::DevicePairingStatusOutcome,
    attestation: &arkret_sdk::DevicePairingTargetAttestation,
) -> anyhow::Result<arkret_sdk::Event> {
    arkret_sdk::signatures::device_pairing::verify_device_pairing_target_attestation(attestation)?;
    let device_id = outcome
        .device_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("authorized pairing status omitted device_id"))?;
    let event_ref = outcome
        .authorized_event_ref
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("authorized pairing status omitted authorized_event_ref"))?;
    if device_id != &attestation.device_id {
        anyhow::bail!("authorized pairing status names another target device");
    }
    let resolved = http
        .events_resolve(&arkret_sdk::EventsResolveRequestBody {
            event_ids: vec![event_ref.clone()],
            event_digests: Vec::new(),
            seal_refs: Vec::new(),
            include_payload: Some(true),
        })
        .await?;
    let event = resolved
        .events
        .into_iter()
        .find(|event| &event.event_id == event_ref)
        .ok_or_else(|| anyhow::anyhow!("authorized device Event is not accepted"))?;
    event.verify_event_id_matches_content()?;
    let principal_actor = arkret_sdk::project_full_id_to_core_id(principal)?;
    if event.kind != arkret_sdk::EventKind::DeviceAuthorize || event.actor_id != principal_actor {
        anyhow::bail!(
            "authorized pairing status does not reference this principal's authorize Event"
        );
    }
    let pcr = crate::identity::principal_control::resolve_accepted(http, &principal_actor).await?;
    if event.realm_id != pcr {
        anyhow::bail!("authorized pairing Event is outside the principal control Realm");
    }
    let digest = arkret_sdk::Hash::new(event.event_digest()?)?;
    if !resolved.seals.iter().any(|seal| {
        seal.realm_id == event.realm_id
            && seal.delta.contains(&digest)
            && seal.covered_event_digests.contains(&digest)
    }) {
        anyhow::bail!("authorized pairing Event lacks its exact accepted covering Seal");
    }
    let payload: arkret_sdk::DeviceAuthorizePayload =
        serde_json::from_value(serde_json::to_value(&event.payload)?)?;
    if payload.principal_id != principal_actor
        || payload.device_id != attestation.device_id
        || payload.device_public_key.as_str() != attestation.device_public_key.as_str()
        || payload.hpke_key != attestation.hpke_key
        || payload.algorithms != attestation.algorithms
        || payload.authorization_binding_kind
            != arkret_sdk::DeviceAuthorizationBindingKind::AcceptedDevice
        || payload.device_signature != attestation.device_signature
        || !event
            .proofs
            .iter()
            .filter_map(arkret_sdk::EventProof::as_producer)
            .any(|proof| {
                proof
                    .verification_method
                    .as_str()
                    .strip_prefix(principal.as_str())
                    .is_some_and(|suffix| suffix.starts_with('#'))
                    && !proof
                        .verification_method
                        .as_str()
                        .ends_with(attestation.device_id.as_str())
            })
    {
        anyhow::bail!("authorized pairing Event does not match the target attestation");
    }
    Ok(event)
}

fn required_string(object: &serde_json::Map<String, Value>, field: &str) -> anyhow::Result<String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow::anyhow!("pairing server challenge omitted `{field}`"))
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
                "target_attestation": {
                    "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                    "device_public_key": "did:key:z6MkogKw38hXxUkpMWitoBubBGHZzeGrQJ4oHF36iegUbmpA",
                    "hpke_key": "hpke-abc-123",
                    "algorithms": ["Ed25519"],
                    "device_key_algorithm": "Ed25519",
                    "authorization_binding_kind": "accepted_device",
                    "pairing_challenge_transcript_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "device_signature": "Y2hhbGxlbmdlLXNpZ25hdHVyZQ"
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
}
