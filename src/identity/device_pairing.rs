//! Server-mediated, out-of-band device-pairing helpers
//! (`crypto-media/device-lifecycle.md` §2.1.1).

use serde_json::Value;

pub async fn sign_target_attestation(
    signer: &crate::event_signer::InksonEventSigner,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    transcript_digest: arkret_sdk::Hash,
) -> anyhow::Result<arkret_sdk::DevicePairingTargetAttestation> {
    let signer_device = signer
        .device_id()
        .ok_or_else(|| anyhow::anyhow!("device pairing signer is not bound to a device"))?;
    if signer_device != device_id.as_str() {
        anyhow::bail!("device pairing signer does not match the target device");
    }
    let public_key_multibase = signer
        .public_key_multibase()
        .ok_or_else(|| anyhow::anyhow!("target device signer cannot expose its Ed25519 key"))?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let (_, hpke_public_key) = crate::mls::runtime::load_or_create_device_hpke_keypair_durable(
        secure_store.as_ref(),
        authority,
        device_id,
    )
    .await?;
    let unsigned = arkret_sdk::UnsignedDevicePairingTargetAttestation::new(
        device_id.clone(),
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
    let challenge = payload
        .get("server_challenge")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("server-mediated pairing omitted its exact challenge"))?;
    let server_challenge = arkret_sdk::signatures::device_pairing::ServerDevicePairingChallenge {
        client_nonce: arkret_sdk::DevicePairingNonce::new(required_string(
            challenge,
            "client_nonce",
        )?)
        .map_err(anyhow::Error::msg)?,
        device_pairing_request_id: arkret_sdk::DevicePairingRequestId::new(required_string(
            challenge,
            "device_pairing_request_id",
        )?)
        .map_err(anyhow::Error::msg)?,
        expires_at: required_string(challenge, "expires_at")?
            .parse::<chrono::DateTime<chrono::Utc>>()?,
        gate_audience_uri: required_string(challenge, "gate_audience_uri")?,
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

    let active_scope = crate::secure_key_store::active_device_seed_scope()
        .ok_or_else(|| anyhow::anyhow!("no active authority can approve device pairing"))?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("no active device signer can approve device pairing"))?;
    let principal = arkret_sdk::Did::new(signer.signer_did().to_owned())?;
    if arkret_sdk::project_did_to_core_id(&principal)? != active_scope.authority.principal_id {
        anyhow::bail!("active pairing signer does not match the active authority");
    }
    if signer.device_id() != Some(active_scope.device_id.as_str()) {
        anyhow::bail!("active pairing signer does not match the active device");
    }
    let authorizing_device = active_scope.device_id;
    let device_signature = match &attestation.device_signature {
        arkret_sdk::SignatureMaterial::NonEmptyString(value) => {
            arkret_sdk::Base64UrlString::new(value.as_str().to_owned())
                .map_err(anyhow::Error::msg)?
        }
        _ => anyhow::bail!("accepted-device target attestation must use a base64url signature"),
    };
    let created_at = chrono::Utc::now();
    let principal_actor = arkret_sdk::project_did_to_core_id(&principal)?;
    let authorize_payload = arkret_sdk::UnsignedDeviceAuthorizePayload::new(
        attestation.device_id.clone(),
        arkret_sdk::NonEmptyString::new(attestation.device_public_key_did.as_str().to_owned())
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
    let authorize_digest_suite = authorized
        .first()
        .ok_or_else(|| anyhow::anyhow!("device authorize Event was not authored"))?
        .digest_suite();
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
    let device_pairing_request_id = arkret_sdk::DevicePairingRequestId::new(
        payload
            .get("device_pairing_request_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("pairing payload is missing device_pairing_request_id"))?
            .to_owned(),
    )
    .map_err(anyhow::Error::msg)?;
    let request = arkret_sdk::AccountDevicePairRequestBody {
        pairing_code,
        new_device_pubkey,
        challenge_proof,
        authorize_event,
        display_name,
        device_metadata,
        device_pairing_request_id,
    };
    attestation.validate_against_pair_request(&request, authorize_digest_suite)?;
    Ok(request)
}

/// Target-device fence before treating an `authorized` status as success.
/// The status row is only an index; trust comes from the exact accepted Event
/// and its target-owned attestation binding.
pub async fn verify_authorized_pairing_event(
    http: &arkret_sdk::http_client::Client,
    principal: &arkret_sdk::Did,
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
            include_payload: Some(true),
            history_traversal_access: None,
            max_response_bytes: Some(arkret_sdk::MAX_PEER_RESOLVE_RESPONSE_BYTES),
        })
        .await?;
    let event = resolved
        .events
        .into_iter()
        .find(|event| &event.event_id == event_ref)
        .ok_or_else(|| anyhow::anyhow!("authorized device Event is not accepted"))?;
    let principal_actor = arkret_sdk::project_did_to_core_id(principal)?;
    if event.kind != arkret_sdk::EventKind::DeviceAuthorize
        || event.actor_id.signing_principal_id() != &principal_actor
    {
        anyhow::bail!(
            "authorized pairing status does not reference this principal's authorize Event"
        );
    }
    let pcr = crate::identity::principal_control::resolve_accepted(http, &principal_actor).await?;
    if event.realm_id != pcr {
        anyhow::bail!("authorized pairing Event is outside the principal control Realm");
    }
    crate::event_submit::verify_event_is_covered_by_accepted_seal(http, &event, |_, _, _, _| {
        Err(arkret_sdk::WireError::Protocol(
            "pairing bootstrap cannot trust Agent evidence without a pinned external authority"
                .to_owned(),
        ))
    })
    .await?;
    let payload: arkret_sdk::DeviceAuthorizePayload =
        serde_json::from_value(serde_json::to_value(&event.payload)?)?;
    if payload.device_id != attestation.device_id
        || payload.device_public_key_did.as_str() != attestation.device_public_key_did.as_str()
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
