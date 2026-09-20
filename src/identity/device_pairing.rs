//! Server-mediated, out-of-band device-pairing helpers
//! (`crypto-media/device-lifecycle.md` §2.1.1).

use serde::{Deserialize, Serialize};

const PENDING_DEVICE_PAIRING_VERIFICATION_KEY: &str = "pending-device-pairing-verification.v1";

/// App-local out-of-band handoff. Protocol-owned server fields stay inside
/// the SDK bootstrap instead of being copied into another wire-shaped DTO.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolvedPairingApproval {
    pub bootstrap: arkret_sdk::DevicePairingBootstrap,
    pub target_proof: arkret_sdk::DevicePairingTargetProof,
}

/// Target-owned material retained across the OIDC navigation that follows a
/// staged device pairing.  This record is not authority: it only selects the
/// pending signer and the exact accepted Event that must be verified before
/// that signer can be promoted into an account namespace.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingDevicePairingVerification {
    pub principal_did: arkret_sdk::Did,
    pub account_id: arkret_sdk::AccountId,
    pub request_id: arkret_sdk::DevicePairingRequestId,
    pub pairing_code: arkret_sdk::DevicePairingCode,
    pub device_id: arkret_sdk::DeviceId,
    pub target_proof: arkret_sdk::DevicePairingTargetProof,
}

impl PendingDevicePairingVerification {
    pub(crate) fn validate_for_handoff(
        &self,
        handoff: &crate::state::PendingAccountHandoff,
    ) -> anyhow::Result<()> {
        let principal_id = handoff
            .bound_principal_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("pairing handoff is not bound to a principal"))?;
        let principal_did = handoff
            .bound_principal_did
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("pairing handoff omitted the principal DID"))?;
        let expected_account =
            arkret_sdk::AccountId::new(principal_id.clone(), handoff.audience_id.clone());
        if &self.principal_did != principal_did
            || self.account_id != expected_account
            || self.device_id.as_str() != handoff.device_id
            || self.target_proof.device_id != self.device_id
            || self.target_proof.account_id != expected_account
        {
            anyhow::bail!("pending device pairing does not match the bound account handoff");
        }
        arkret_sdk::signatures::device_pairing::verify_device_pairing_target_proof(
            &self.target_proof,
        )?;
        Ok(())
    }
}

pub(crate) async fn persist_pending_device_pairing_verification(
    pending: &crate::secure_key_store::PendingLocalStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    verification: &PendingDevicePairingVerification,
) -> anyhow::Result<()> {
    let encoded = serde_json::to_string(verification)?;
    pending
        .save_secret_durable(
            secure_store,
            PENDING_DEVICE_PAIRING_VERIFICATION_KEY,
            &encoded,
        )
        .await?;
    Ok(())
}

pub(crate) fn load_pending_device_pairing_verification(
    pending: &crate::secure_key_store::PendingLocalStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<Option<PendingDevicePairingVerification>> {
    pending
        .load_secret(secure_store, PENDING_DEVICE_PAIRING_VERIFICATION_KEY)?
        .map(|encoded| serde_json::from_str(&encoded).map_err(anyhow::Error::from))
        .transpose()
}

pub(crate) fn clear_pending_device_pairing_verification(
    pending: &crate::secure_key_store::PendingLocalStore,
    secure_store: &dyn crate::secure_key_store::SecureKeyStore,
) -> anyhow::Result<()> {
    pending.delete_secret(secure_store, PENDING_DEVICE_PAIRING_VERIFICATION_KEY)?;
    Ok(())
}

fn accepted_device_generation_ref(
    authority: &arkret_sdk::AccountId,
    generation: &crate::identity::authoring_generation::AuthoringGeneration,
) -> anyhow::Result<u64> {
    if generation.authority_model
        != crate::identity::authoring_generation::AuthoringAuthorityModel::AcceptedDevice
        || generation.authority_principal_id != authority.principal_id
    {
        anyhow::bail!("pairing requires the approving account's accepted-device generation");
    }
    let generation_ref = generation
        .generation_ref
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("verified PCR generation is not a canonical integer"))?;
    if generation_ref == 0 || generation_ref.to_string() != generation.generation_ref {
        anyhow::bail!("verified PCR generation is not a canonical positive integer");
    }
    Ok(generation_ref)
}

fn verified_current_pairing_generation(
    authority: &arkret_sdk::AccountId,
    approving_device: &arkret_sdk::DeviceId,
) -> anyhow::Result<u64> {
    let generation = crate::identity::authoring_generation::cached_principal_authoring_generation(
        authority,
        approving_device.as_str(),
    )
    .ok_or_else(|| {
        anyhow::anyhow!(
            "pairing requires a Station-verified current PCR generation for the approving device"
        )
    })?;
    accepted_device_generation_ref(authority, &generation)
}

fn validate_pair_request_against_target_proof(
    proof: &arkret_sdk::DevicePairingTargetProof,
    request: &arkret_sdk::AccountDevicePairRequestBody,
) -> anyhow::Result<()> {
    arkret_sdk::signatures::device_pairing::verify_device_pairing_target_proof(proof)?;
    let event = &request.authorize_event.event;
    let payload = arkret_sdk::DeviceAuthorizePayload::try_from(event)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let requested_key = arkret_sdk::base64url_decode(request.new_device_pubkey.key.as_bytes())
        .map_err(|error| anyhow::anyhow!("decode requested pairing key: {error}"))?;
    let proof_key = arkret_sdk::decode_ed25519_multibase(
        proof
            .device_public_key_did
            .as_str()
            .strip_prefix("did:key:")
            .ok_or_else(|| anyhow::anyhow!("pairing proof key is not a did:key"))?,
    )
    .map_err(|error| anyhow::anyhow!("decode pairing proof key: {error}"))?;
    if event.actor_id.as_account_id() != Some(&proof.account_id)
        || request.new_device_pubkey.kid.as_str() != proof.device_id.as_str()
        || requested_key.as_slice() != proof_key.as_slice()
        || payload.device_id != proof.device_id
        || payload.device_public_key_did.as_str() != proof.device_public_key_did.as_str()
        || payload.hpke_key != proof.hpke_key
        || payload.algorithms != proof.algorithms
        || payload.device_key_algorithm.as_str() != "Ed25519"
        || payload.authorization_binding_kind
            != arkret_sdk::DeviceAuthorizationBindingKind::AcceptedDevice
        || payload.device_signature != proof.device_signature
        || payload.pairing_challenge_transcript_digest.as_ref()
            != Some(&proof.pairing_challenge_transcript_digest)
    {
        anyhow::bail!("pairing target proof does not match the exact pair request/Event");
    }
    Ok(())
}

pub async fn sign_target_proof(
    signer: &crate::event_signer::InksonEventSigner,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    transcript_digest: arkret_sdk::Hash,
) -> anyhow::Result<arkret_sdk::DevicePairingTargetProof> {
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
    // device-lifecycle.md 5.4.1 item 5: the account this device is joining is a
    // signed member, so the proof can only be authored once the candidate holds
    // its pending account handoff.
    let unsigned = arkret_sdk::UnsignedDevicePairingTargetProof::new(
        authority.clone(),
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
    arkret_sdk::signatures::device_pairing::verify_device_pairing_target_proof(&attestation)?;
    Ok(attestation)
}

/// After the approving user confirms the displayed code, verify the target's
/// possession attestation and only then author the exact authorize Event.  The
/// target never authors or supplies this Event.
pub async fn author_pairing_request_body(
    api: &crate::transport::TransportClient,
    payload: &ResolvedPairingApproval,
) -> anyhow::Result<arkret_sdk::AccountDevicePairRequestBody> {
    let attestation = payload.target_proof.clone();
    arkret_sdk::signatures::device_pairing::verify_device_pairing_target_proof(&attestation)?;
    let new_device_pubkey = payload.bootstrap.new_device_pubkey.clone();
    if new_device_pubkey.kid.as_str() != attestation.device_id.as_str() {
        anyhow::bail!("pairing public key and target attestation name different devices");
    }
    let server_challenge =
        arkret_sdk::signatures::device_pairing::ServerDevicePairingChallenge::from_bootstrap(
            &payload.bootstrap,
        );
    let active_scope = crate::secure_key_store::active_device_seed_scope()
        .ok_or_else(|| anyhow::anyhow!("no active authority can approve device pairing"))?;
    // Same core, different Station is a different account and MUST be refused:
    // the comparison is over the whole AccountId, not its principal half.
    arkret_sdk::signatures::device_pairing::verify_server_device_pairing_target_proof(
        &new_device_pubkey,
        &server_challenge,
        &active_scope.authority,
        &attestation,
        chrono::Utc::now(),
    )?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("no active device signer can approve device pairing"))?;
    let principal = arkret_sdk::Did::new(signer.signer_did().to_owned())?;
    if arkret_sdk::project_did_to_core_id(&principal)? != active_scope.authority.principal_id {
        anyhow::bail!("active pairing signer does not match the active authority");
    }
    if signer.device_id() != Some(active_scope.device_id.as_str()) {
        anyhow::bail!("active pairing signer does not match the active device");
    }
    let authorized_generation_ref =
        verified_current_pairing_generation(&active_scope.authority, &active_scope.device_id)?;
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
    let authorize_payload = arkret_sdk::DeviceAuthorizePayload {
        device_id: attestation.device_id.clone(),
        device_public_key_did: arkret_sdk::NonEmptyString::new(
            attestation.device_public_key_did.as_str().to_owned(),
        )
        .map_err(anyhow::Error::msg)?,
        hpke_key: attestation.hpke_key.clone(),
        algorithms: attestation.algorithms.clone(),
        device_key_algorithm: arkret_sdk::NonEmptyString::new("Ed25519".to_owned())
            .map_err(anyhow::Error::msg)?,
        authorized_by: arkret_sdk::DeviceOrPrincipalRef::DeviceId(authorizing_device),
        scopes: None,
        not_before: created_at,
        expires_at: None,
        authorization_binding_kind: arkret_sdk::DeviceAuthorizationBindingKind::AcceptedDevice,
        authorized_generation_ref,
        device_signature: arkret_sdk::SignatureMaterial::NonEmptyString(
            arkret_sdk::NonEmptyString::new(device_signature.into_string())
                .map_err(anyhow::Error::msg)?,
        ),
        recovery_session_id: None,
        pairing_challenge_transcript_digest: Some(
            attestation.pairing_challenge_transcript_digest.clone(),
        ),
        applet_id: None,
    };
    authorize_payload
        .validate_wire_constraints()
        .map_err(anyhow::Error::msg)?;
    let http = api.sdk_http_client()?;
    let realm_id =
        crate::identity::principal_control::resolve_accepted(&http, &principal_actor).await?;
    let submitter = api.event_submitter()?;
    let authorize = crate::operation::TypedOperationBuilder::new::<
        arkret_sdk::event_spec::DeviceAuthorize,
    >(realm_id.as_str(), principal.as_str(), authorize_payload)
    .created_at(created_at)
    .build_sdk_event("inkson-device-pairing")?;
    let authorized = submitter
        .author_independent_events(vec![authorize.into_intent()])
        .await?;
    let authorize_event = submitter
        .prepare_initial_submissions(&authorized)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("device authorize Event was not prepared"))?;

    let request = arkret_sdk::AccountDevicePairRequestBody {
        pairing_code: payload.bootstrap.pairing_code.clone(),
        new_device_pubkey,
        authorize_event,
        display_name: payload
            .bootstrap
            .display_name
            .as_ref()
            .map(|value| value.as_str().to_owned()),
        device_metadata: payload.bootstrap.device_metadata.clone(),
        device_pairing_request_id: payload.bootstrap.device_pairing_request_id.clone(),
    };
    validate_pair_request_against_target_proof(&attestation, &request)?;
    Ok(request)
}

/// Submit the target-bound authorize Event and require the gate's exact
/// authority-signed committed coordinate. There is no client-authored Seal or
/// parallel governance frontier.
pub async fn approve_device_pairing(
    api: &crate::transport::TransportClient,
    payload: &ResolvedPairingApproval,
) -> anyhow::Result<arkret_sdk::AccountDevicePairOutcome> {
    let scope = crate::secure_key_store::active_device_seed_scope()
        .ok_or_else(|| anyhow::anyhow!("no active account can approve pairing"))?;
    let store = crate::secure_key_store::default_secure_key_store("inkson");
    let local = crate::secure_key_store::UserLocalStore::new(scope.authority, scope.device_id)?;
    let retry_key = format!(
        "device-pairing-commit.{}",
        payload.bootstrap.device_pairing_request_id
    );
    let body: arkret_sdk::AccountDevicePairRequestBody =
        if let Some(saved) = local.load_secret(store.as_ref(), &retry_key)? {
            let body: arkret_sdk::AccountDevicePairRequestBody = serde_json::from_str(&saved)?;
            let retained: arkret_sdk::DeviceAuthorizePayload =
                serde_json::from_value(serde_json::to_value(&body.authorize_event.event.payload)?)?;
            if retained.device_signature != payload.target_proof.device_signature
                || retained.pairing_challenge_transcript_digest.as_ref()
                    != Some(&payload.target_proof.pairing_challenge_transcript_digest)
                || body.device_pairing_request_id != payload.bootstrap.device_pairing_request_id
            {
                anyhow::bail!("pending pairing retry describes another target proof");
            }
            body
        } else {
            let body = author_pairing_request_body(api, payload).await?;
            local
                .save_secret_durable(store.as_ref(), &retry_key, &serde_json::to_string(&body)?)
                .await?;
            body
        };
    let authorize_event = body.authorize_event.event.clone();
    let http = api.sdk_http_client()?;
    let outcome = http.account_device_pair(&body).await?;
    if outcome.authorized_event_ref.event_id != authorize_event.event_id {
        anyhow::bail!("device-pair gate returned another authorize Event reference");
    }
    let committed = http
        .committed_event_get(&outcome.authorized_event_ref.event_id)
        .await?;
    if !outcome.authorized_event_ref.matches(&committed) {
        anyhow::bail!("device-pair gate returned a mismatched committed authorize Event");
    }
    let committed_event = committed.reducer_input().ok_or_else(|| {
        anyhow::anyhow!("device-pair gate authorize Event is withheld instead of Full")
    })?;
    if committed_event != &authorize_event {
        anyhow::bail!("device-pair gate returned a mismatched committed authorize Event");
    }
    Ok(outcome)
}

/// Target-device fence before treating an `authorized` status as success.
/// The status row is only an index; trust comes from the exact accepted Event
/// and its target-owned attestation binding.
pub async fn verify_authorized_pairing_event_for_authority(
    http: &arkret_sdk::http_client::Client,
    principal: &arkret_sdk::Did,
    authority: &arkret_sdk::AccountId,
    outcome: &arkret_sdk::DevicePairingStatusOutcome,
    attestation: &arkret_sdk::DevicePairingTargetProof,
) -> anyhow::Result<arkret_sdk::Event> {
    outcome.validate()?;
    arkret_sdk::signatures::device_pairing::verify_device_pairing_target_proof(attestation)?;
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
    // device-lifecycle.md 5.4.1 item 5, target side: the account this device
    // signed itself into has to be the exact account it is now being installed
    // under. Comparing the whole AccountId is the point -- the same principal
    // core under a second Station is a different account.
    if attestation.account_id != *authority {
        anyhow::bail!("authorized pairing attestation was signed for another account");
    }
    let resolved = http.committed_event_get(&event_ref.event_id).await?;
    if !event_ref.matches(&resolved) {
        anyhow::bail!("authorized pairing status returned a mismatched committed Event reference");
    }
    let event = resolved
        .reducer_input()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("authorized device Event is withheld"))?;
    let principal_actor = arkret_sdk::project_did_to_core_id(principal)?;
    if authority.principal_id != principal_actor {
        anyhow::bail!("pairing authority does not match the target principal");
    }
    if event.kind != arkret_sdk::EventKind::DeviceAuthorize
        || event.actor_id != arkret_sdk::ActorId::account(authority.clone())
    {
        anyhow::bail!(
            "authorized pairing status does not reference this principal's authorize Event"
        );
    }
    let pcr =
        crate::identity::principal_control::resolve_accepted_for_authority(http, authority).await?;
    if event.realm_id != pcr {
        anyhow::bail!("authorized pairing Event is outside the principal control Realm");
    }
    let payload: arkret_sdk::DeviceAuthorizePayload =
        serde_json::from_value(serde_json::to_value(&event.payload)?)?;
    if payload.device_id != attestation.device_id
        || payload.device_public_key_did.as_str() != attestation.device_public_key_did.as_str()
        || payload.hpke_key != attestation.hpke_key
        || payload.algorithms != attestation.algorithms
        || payload.authorization_binding_kind
            != arkret_sdk::DeviceAuthorizationBindingKind::AcceptedDevice
        || payload.device_signature != attestation.device_signature
        || payload.pairing_challenge_transcript_digest.as_ref() != Some(&attestation.pairing_challenge_transcript_digest)
        || !event
            .producer_proof
            .as_ref()
            .is_some_and(|proof| {
                proof
                    .verification_method
                    .as_str()
                    .strip_prefix(principal.as_str())
                    .is_some_and(|suffix| suffix.starts_with('#'))
                    && matches!(&payload.authorized_by, arkret_sdk::DeviceOrPrincipalRef::DeviceId(device)
                        if proof.verification_method.as_str().split_once('#').map(|(_, fragment)| fragment) == Some(device.as_str()))
            })
    {
        anyhow::bail!("authorized pairing Event does not match the target attestation");
    }
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::authoring_generation::{AuthoringAuthorityModel, AuthoringGeneration};

    fn account(principal: &str) -> arkret_sdk::AccountId {
        arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(principal).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkstation").unwrap(),
        )
    }

    #[test]
    fn pairing_generation_requires_exact_accepted_device_projection() {
        let authority = account("ak:did_core:webvh:z6mkprincipal");
        let current = AuthoringGeneration {
            authority_model: AuthoringAuthorityModel::AcceptedDevice,
            authority_principal_id: authority.principal_id.clone(),
            generation_ref: "7".to_owned(),
        };
        assert_eq!(
            accepted_device_generation_ref(&authority, &current).unwrap(),
            7
        );

        let mut invalid = current.clone();
        invalid.generation_ref = "07".to_owned();
        assert!(accepted_device_generation_ref(&authority, &invalid).is_err());

        invalid = current.clone();
        invalid.authority_model = AuthoringAuthorityModel::Agent;
        assert!(accepted_device_generation_ref(&authority, &invalid).is_err());

        invalid = current;
        invalid.authority_principal_id =
            arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkother").unwrap();
        assert!(accepted_device_generation_ref(&authority, &invalid).is_err());
    }
}
