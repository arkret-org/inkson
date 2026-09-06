//! Pairing a second device into an account that already exists.
//!
//! The staging half mints the handoff token and deep link; the polling half
//! reads the authorized pairing status back. Both are network commands the
//! device-setup screen calls, not view state.

#[derive(Clone, Debug)]
pub(super) struct DeviceSetupPairingRequest {
    pub(super) request_id: arkret_sdk::DevicePairingRequestId,
    pub(super) pairing_code: arkret_sdk::DevicePairingCode,
    pub(super) device_id: arkret_sdk::DeviceId,
    pub(super) deep_link: String,
    pub(super) target_attestation: arkret_sdk::DevicePairingTargetAttestation,
}

pub(super) fn device_pairing_handoff_token(
    request_id: &arkret_sdk::DevicePairingRequestId,
    pairing_code: &arkret_sdk::DevicePairingCode,
) -> anyhow::Result<String> {
    Ok(arkret_sdk::base64url_encode(
        arkret_sdk::canonical::canonical_json_bytes(&serde_json::json!({
            "r": request_id,
            "c": pairing_code,
        }))?,
    ))
}

pub(super) fn device_pairing_deep_link(
    base_url: &str,
    token: &str,
    challenge_proof: &arkret_sdk::DevicePairingChallengeProof,
    target_attestation: &arkret_sdk::DevicePairingTargetAttestation,
) -> anyhow::Result<String> {
    let proof = arkret_sdk::base64url_encode(arkret_sdk::canonical::canonical_json_bytes(
        challenge_proof,
    )?);
    let attestation = arkret_sdk::base64url_encode(arkret_sdk::canonical::canonical_json_bytes(
        target_attestation,
    )?);
    Ok(format!(
        "{}/_arkret/open/device-pairing/resolve#token={token}&proof={proof}&attestation={attestation}",
        base_url.trim_end_matches('/'),
    ))
}

pub(super) async fn stage_device_setup_pairing(
    handoff: &crate::state::PendingAccountHandoff,
) -> anyhow::Result<DeviceSetupPairingRequest> {
    let principal_id = handoff
        .bound_principal_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("bound account principal is missing"))?;
    let station_id = handoff.audience_id.clone();
    let authority = arkret_sdk::AccountId::new(principal_id.clone(), station_id);
    let handoff_device = arkret_sdk::DeviceId::new(handoff.device_id.clone())?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let user_store =
        crate::secure_key_store::UserLocalStore::new(authority.clone(), handoff_device.clone())?;
    let retained = user_store
        .load_device_id(secure_store.as_ref())?
        .zip(user_store.load_signing_seed(secure_store.as_ref())?);
    let (target_device, signing_seed) = if let Some((device, material)) = retained {
        (device, material.seed)
    } else {
        let pending_store = crate::secure_key_store::PendingLocalStore::new(handoff_device.clone());
        pending_store.activate();
        let material = pending_store
            .create_fresh_signing_seed_durable(secure_store.as_ref())
            .await?;
        (handoff_device, material.seed)
    };
    crate::event_signer::activate_device_signer_from_seed_for_device(
        signing_seed,
        Some(secure_store.as_ref()),
        Some(target_device.as_str()),
    )?;
    let signer = crate::event_signer::bind_active_signer_device_id(target_device.as_str())?
        .ok_or_else(|| anyhow::anyhow!("the target device signer is unavailable"))?;
    let public_key = signer
        .public_key_base64url()
        .ok_or_else(|| anyhow::anyhow!("the target device key cannot be exported"))?;
    let mut client_nonce_bytes = [0_u8; 16];
    getrandom::fill(&mut client_nonce_bytes)
        .map_err(|error| anyhow::anyhow!("generate device-pairing nonce: {error}"))?;
    let client_nonce =
        arkret_sdk::DevicePairingNonce::new(arkret_sdk::base64url_encode(client_nonce_bytes))
            .map_err(anyhow::Error::msg)?;
    let stage_body = arkret_sdk::DevicePairingStageRequestBody {
        new_device_pubkey: arkret_sdk::PublicKey {
            kty: arkret_sdk::NonEmptyString::new("OKP".to_owned()).map_err(anyhow::Error::msg)?,
            kid: arkret_sdk::NonEmptyString::new(target_device.to_string())
                .map_err(anyhow::Error::msg)?,
            algorithm: arkret_sdk::NonEmptyString::new("Ed25519".to_owned())
                .map_err(anyhow::Error::msg)?,
            key: arkret_sdk::Base64UrlString::new(public_key.to_owned())
                .map_err(anyhow::Error::msg)?,
            key_digest: None,
        },
        client_nonce: client_nonce.clone(),
        display_name: Some(
            arkret_sdk::NonEmptyString::new("New browser".to_owned())
                .map_err(anyhow::Error::msg)?,
        ),
        device_metadata: Some(arkret_sdk::DeviceMetadata {
            platform: Some(
                arkret_sdk::NonEmptyString::new("browser".to_owned())
                    .map_err(anyhow::Error::msg)?,
            ),
            ..Default::default()
        }),
    };
    let http = crate::transport::TransportClient::unauthenticated(&handoff.station_url)?
        .sdk_http_client()?;
    let stage = http.device_pairing_stage(&stage_body).await?;
    let challenge =
        arkret_sdk::signatures::device_pairing::ServerDevicePairingChallenge::from_stage(
            client_nonce,
            &stage,
        );
    let (challenge_bytes, transcript_digest) =
        arkret_sdk::signatures::device_pairing::server_device_pairing_transcript(
            &stage_body.new_device_pubkey,
            &challenge,
        )?;
    let challenge_proof = arkret_sdk::DevicePairingChallengeProof {
        transcript: arkret_sdk::DevicePairingChallengeTranscriptKind::ServerMediated,
        kid: target_device.clone(),
        signature_algorithm: arkret_sdk::NonEmptyString::new(signer.algorithm().to_owned())
            .map_err(anyhow::Error::msg)?,
        transcript_digest: transcript_digest.clone(),
        signature: arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(
            signer.sign_raw(&challenge_bytes)?,
        ))
        .map_err(anyhow::Error::msg)?,
    };
    let target_attestation = crate::identity::device_pairing::sign_target_attestation(
        &signer,
        &authority,
        &target_device,
        transcript_digest,
    )
    .await?;
    let token =
        device_pairing_handoff_token(&stage.device_pairing_request_id, &stage.pairing_code)?;
    let deep_link = device_pairing_deep_link(
        &handoff.station_url,
        &token,
        &challenge_proof,
        &target_attestation,
    )?;
    let principal_did = handoff
        .bound_principal_did
        .clone()
        .ok_or_else(|| anyhow::anyhow!("bound account principal DID is missing"))?;
    let pending_store = crate::secure_key_store::PendingLocalStore::new(target_device.clone());
    crate::identity::device_pairing::persist_pending_device_pairing_verification(
        &pending_store,
        secure_store.as_ref(),
        &crate::identity::device_pairing::PendingDevicePairingVerification {
            principal_did,
            account_id: authority,
            request_id: stage.device_pairing_request_id.clone(),
            pairing_code: stage.pairing_code.clone(),
            device_id: target_device.clone(),
            target_attestation: target_attestation.clone(),
        },
    )
    .await?;
    Ok(DeviceSetupPairingRequest {
        request_id: stage.device_pairing_request_id,
        pairing_code: stage.pairing_code,
        device_id: target_device,
        deep_link,
        target_attestation,
    })
}

pub(super) async fn check_device_setup_pairing(
    handoff: &crate::state::PendingAccountHandoff,
    request: &DeviceSetupPairingRequest,
) -> anyhow::Result<arkret_sdk::DevicePairingState> {
    let http = crate::transport::TransportClient::unauthenticated(&handoff.station_url)?
        .sdk_http_client()?;
    let outcome = http
        .device_pairing_status(&arkret_sdk::DevicePairingStatusRequestBody {
            device_pairing_request_id: request.request_id.clone(),
            pairing_code: request.pairing_code.clone(),
        })
        .await?;
    if outcome.state != arkret_sdk::DevicePairingState::Authorized {
        return Ok(outcome.state);
    }
    arkret_sdk::signatures::device_pairing::verify_device_pairing_target_attestation(
        &request.target_attestation,
    )?;
    let status_device = outcome
        .device_id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("authorized pairing status omitted device_id"))?;
    if status_device != &request.device_id || status_device != &request.target_attestation.device_id
    {
        anyhow::bail!("authorized pairing status names another target device");
    }
    if outcome.authorized_event_ref.is_none() {
        anyhow::bail!("authorized pairing status omitted authorized_event_ref");
    }
    Ok(outcome.state)
}
