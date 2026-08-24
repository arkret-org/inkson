//! MLS KeyPackage helper functions shared by API endpoints and admission code.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub(crate) fn principal_core_id(principal_id: &str) -> anyhow::Result<arkret_sdk::DidCoreId> {
    let principal_id = principal_id.trim();
    if let Ok(core_id) = arkret_sdk::DidCoreId::new(principal_id.to_owned()) {
        return Ok(core_id);
    }
    let full_id = arkret_sdk::DidFullId::new(principal_id.to_owned())?;
    arkret_sdk::project_full_id_to_core_id(&full_id).map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod principal_id_tests {
    use super::*;

    #[test]
    fn principal_core_id_accepts_stable_and_resolvable_forms() {
        let core = "ak:did_core:web:alice.example";
        assert_eq!(principal_core_id(core).unwrap().as_str(), core);
        assert_eq!(
            principal_core_id("did:web:alice.example").unwrap().as_str(),
            core
        );
    }
}
pub(crate) fn sign_keypackage_upload_batch_with_signer(
    signer: &crate::event_signer::InksonEventSigner,
    unsigned: &arkret_sdk::KeyPackagesUploadUnsignedRequest,
) -> anyhow::Result<arkret_sdk::KeyOperationSignature> {
    let input = arkret_sdk::keypackages_upload_signing_input(unsigned)?;
    let sig = signer
        .sign_raw(&input)
        .map_err(|err| anyhow::anyhow!("keypackages/upload device_signature sign failed: {err}"))?;
    Ok(arkret_sdk::KeyOperationSignature {
        kid: arkret_sdk::NonEmptyString::new(signer.verification_method())
            .map_err(anyhow::Error::msg)?,
        signature_algorithm: Some(
            arkret_sdk::NonEmptyString::new(signer.algorithm()).map_err(anyhow::Error::msg)?,
        ),
        sig: arkret_sdk::Base64UrlString::new(URL_SAFE_NO_PAD.encode(sig))
            .map_err(anyhow::Error::msg)?,
    })
}

pub(crate) fn sign_keypackage_upload_batch(
    unsigned: &arkret_sdk::KeyPackagesUploadUnsignedRequest,
) -> anyhow::Result<arkret_sdk::KeyOperationSignature> {
    let signer = crate::event_signer::active_signer().ok_or_else(|| {
        anyhow::anyhow!(
            "keypackages/upload device_signature requires an active event-signer (fail-closed)"
        )
    })?;
    sign_keypackage_upload_batch_with_signer(&signer, unsigned)
}

/// Convert a local `MlsKeyPackageRecord` into the typed wire entry for
/// `keypackages/upload`
/// (`keypackage-operations.schema.json#/$defs/keypackage_upload_entry`).
/// `keypackage_ref` (ObjectRef) and `keypackage_digest` (Hash) both carry the
/// canonical KeyPackage hash; a missing `expires_at` falls back to the SDK
/// default KeyPackage lifetime (`created_at` + 7 days).
pub(crate) fn mls_key_package_record_upload_entry(
    record: &arkret_sdk::MlsKeyPackageRecord,
) -> anyhow::Result<arkret_sdk::KeyPackageUploadEntry> {
    arkret_sdk::mls_key_package_record_upload_entry(record).map_err(anyhow::Error::msg)
}

pub(crate) fn generate_mls_claim_nonce() -> anyhow::Result<String> {
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes)
        .map_err(|err| anyhow::anyhow!("generate MLS KeyPackage claim nonce: {err}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn keypackage_claim_record_to_mls_record(
    claim: &arkret_sdk::KeyPackageClaimRecord,
) -> anyhow::Result<arkret_sdk::MlsKeyPackageRecord> {
    let signer_full_id = arkret_sdk::DidFullId::new(
        claim
            .device_signature
            .kid
            .as_str()
            .split_once('#')
            .ok_or_else(|| anyhow::anyhow!("KeyPackage claim signature kid omits DID fragment"))?
            .0
            .to_owned(),
    )?;
    if arkret_sdk::project_full_id_to_core_id(&signer_full_id)? != claim.principal_id {
        anyhow::bail!("KeyPackage claim signer does not project to principal_id");
    }
    if claim.device_id.is_some() && claim.device_authorize_event_id.is_none() {
        anyhow::bail!("device KeyPackage claim is missing its authorization event");
    }
    if claim.agent_id.is_some() && claim.device_authorize_event_id.is_some() {
        anyhow::bail!("Native Agent KeyPackage claim has mixed authorization evidence");
    }
    let endpoint = match (
        &claim.device_id,
        &claim.agent_id,
        &claim.agent_verification_method,
        &claim.agent_key_authorize_event_id,
    ) {
        (Some(device_id), None, None, None) => arkret_sdk::MlsEndpointIdentity::human_device(
            claim.principal_id.clone(),
            device_id.clone(),
        ),
        (None, Some(agent_id), Some(method), Some(authorization_ref)) => {
            if agent_id != &claim.principal_id
                || method.as_str() != claim.device_signature.kid.as_str()
            {
                anyhow::bail!("Native Agent KeyPackage claim endpoint binding mismatch");
            }
            arkret_sdk::MlsEndpointIdentity::native_agent_runtime(
                agent_id.clone(),
                method.clone(),
                authorization_ref.clone(),
            )?
        }
        _ => anyhow::bail!("KeyPackage claim has an incomplete or mixed endpoint identity"),
    };
    Ok(arkret_sdk::MlsKeyPackageRecord {
        keypackage_id: claim.keypackage_ref.as_str().to_owned(),
        endpoint,
        keypackage: claim.keypackage.clone(),
        keypackage_ref: claim.keypackage_digest.clone(),
        cipher_suites: Vec::new(),
        capabilities: claim.capabilities.clone(),
        state: arkret_sdk::MlsKeyPackageState::Published,
        claim_id: Some(claim.claim_id.clone()),
        created_at: crate::clock::now_utc(),
        expires_at: Some(claim.expires_at),
        device_signature: None,
        // Reconstructed claim-side record (admin builds the Welcome from the
        // KeyPackage bytes, which already carry any last_resort extension); the
        // flag is not re-published, so a plain default is correct here.
        last_resort: false,
    })
}

pub(crate) fn mls_keypackage_claim_required_capabilities()
-> anyhow::Result<Vec<arkret_sdk::NonEmptyString>> {
    arkret_sdk::ARKRET_MLS_KEY_PACKAGE_CAPABILITIES
        .iter()
        .map(|capability| arkret_sdk::NonEmptyString::new(*capability).map_err(anyhow::Error::msg))
        .collect()
}

pub(crate) fn build_mls_keypackage_claim_request(
    target_principal_id: &str,
    intended_realm_id: &str,
    requester: &str,
    requester_device_id: &str,
    requester_device_authorize_event_id: &arkret_sdk::EventId,
    source_service_id: &str,
    destination_service_id: &str,
    claim_nonce: &str,
    target_device_id: Option<&str>,
    mls_group_id: &str,
) -> anyhow::Result<arkret_sdk::KeyPackagesClaimRequestBody> {
    let target_device_ids = target_device_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| arkret_sdk::DeviceId::new(value.to_owned()))
        .transpose()?
        .into_iter()
        .collect::<Vec<_>>();
    let requester_full_id = arkret_sdk::DidFullId::new(requester.trim().to_owned())?;
    let requester = arkret_sdk::project_full_id_to_core_id(&requester_full_id)?;
    let requester_device_id = arkret_sdk::DeviceId::new(requester_device_id.trim().to_owned())?;
    let source_service_id = arkret_sdk::DidCoreId::new(source_service_id.trim().to_owned())?;
    let destination_service_id =
        arkret_sdk::DidCoreId::new(destination_service_id.trim().to_owned())?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("KeyPackage claim requires an active device signer"))?;
    let verification_method = signer.verification_method_for_principal(&requester_full_id)?;
    let signed_at = crate::clock::now_utc();
    let unsigned = arkret_sdk::PeerKeyPackagesClaimUnsignedRequest {
        claim_request_id: arkret_sdk::Base64UrlString::new(generate_mls_claim_nonce()?)
            .map_err(anyhow::Error::msg)?,
        target_principal_id: principal_core_id(target_principal_id)?,
        requester,
        intended_realm_id: arkret_sdk::RealmId::new(crate::operation::trim_realm_id(
            intended_realm_id,
        ))?,
        mls_group_id: arkret_sdk::NonEmptyString::new(mls_group_id.trim())
            .map_err(anyhow::Error::msg)?,
        claim_purpose: arkret_sdk::PeerKeyPackageClaimPurpose::RealmMembership,
        required_capabilities: mls_keypackage_claim_required_capabilities()?,
        claim_nonce: arkret_wire::Base64UrlString::new(claim_nonce.trim().to_owned())
            .map_err(|error| anyhow::anyhow!(error))?,
        expires_at: signed_at + chrono::Duration::minutes(5),
        target_device_ids,
        target_keypackage_ref: None,
        target_agent_id: None,
        target_agent_verification_method: None,
        target_agent_key_authorize_event_id: None,
        minimal_metadata_allowed: Some(true),
        timeout_ms: Some(30_000),
        strand_id: None,
        pair_key: None,
        last_resort_allowed: Some(false),
    };
    let service_binding = arkret_sdk::KeyPackagesClaimServiceBinding {
        source_service_id,
        destination_service_id,
    };
    let mut requester_authorization = arkret_sdk::PeerKeyPackageRequesterAuthorization::Device {
        verification_method: verification_method.clone(),
        requester_device_id,
        device_authorize_event_id: requester_device_authorize_event_id.clone(),
        signed_at,
        signature: arkret_sdk::KeyOperationSignature {
            kid: arkret_sdk::NonEmptyString::new(verification_method.as_str())
                .map_err(anyhow::Error::msg)?,
            signature_algorithm: Some(
                arkret_sdk::NonEmptyString::new(signer.algorithm()).map_err(anyhow::Error::msg)?,
            ),
            sig: arkret_sdk::Base64UrlString::new("YQ").map_err(anyhow::Error::msg)?,
        },
    };
    let signing_bytes = arkret_sdk::keypackage_claim_authorization_signing_bytes(
        &unsigned,
        &service_binding,
        &requester_authorization,
    )?;
    let signature = arkret_sdk::Base64UrlString::new(URL_SAFE_NO_PAD.encode(
        signer.sign_raw(&signing_bytes).map_err(|error| {
            anyhow::anyhow!("KeyPackage claim authorization sign failed: {error}")
        })?,
    ))
    .map_err(anyhow::Error::msg)?;
    match &mut requester_authorization {
        arkret_sdk::PeerKeyPackageRequesterAuthorization::Device {
            signature: proof, ..
        }
        | arkret_sdk::PeerKeyPackageRequesterAuthorization::NativeAgent {
            signature: proof, ..
        } => proof.sig = signature,
    }
    let body = arkret_sdk::KeyPackagesClaimRequestBody {
        claim_request_id: unsigned.claim_request_id,
        target_principal_id: unsigned.target_principal_id,
        requester: unsigned.requester,
        intended_realm_id: unsigned.intended_realm_id,
        mls_group_id: unsigned.mls_group_id,
        claim_purpose: unsigned.claim_purpose,
        required_capabilities: unsigned.required_capabilities,
        claim_nonce: unsigned.claim_nonce,
        expires_at: unsigned.expires_at,
        target_device_ids: unsigned.target_device_ids,
        target_keypackage_ref: unsigned.target_keypackage_ref,
        target_agent_id: unsigned.target_agent_id,
        target_agent_verification_method: unsigned.target_agent_verification_method,
        target_agent_key_authorize_event_id: unsigned.target_agent_key_authorize_event_id,
        minimal_metadata_allowed: unsigned.minimal_metadata_allowed,
        timeout_ms: unsigned.timeout_ms,
        strand_id: unsigned.strand_id,
        pair_key: unsigned.pair_key,
        last_resort_allowed: unsigned.last_resort_allowed,
        service_binding,
        requester_authorization,
    };
    body.validate_shape()
        .map_err(|error| anyhow::anyhow!("invalid KeyPackage claim request: {error}"))?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim_for(
        record: &arkret_sdk::MlsKeyPackageRecord,
        kid: &str,
    ) -> arkret_sdk::KeyPackageClaimRecord {
        let (principal_id, device_id) = match &record.endpoint {
            arkret_sdk::MlsEndpointIdentity::HumanDevice {
                principal_id,
                device_id,
            } => (principal_id.clone(), device_id.clone()),
            arkret_sdk::MlsEndpointIdentity::NativeAgentRuntime { .. }
            | arkret_sdk::MlsEndpointIdentity::MinimalMetadataPairwise { .. } => {
                panic!("test fixture requires a human-device record")
            }
        };
        arkret_sdk::KeyPackageClaimRecord {
            claim_id: "claim".to_owned(),
            keypackage_ref: record.keypackage_ref.as_str().to_owned(),
            keypackage_digest: record.keypackage_ref.clone(),
            principal_id,
            device_id: Some(device_id),
            agent_id: None,
            agent_verification_method: None,
            keypackage: record.keypackage.clone(),
            capabilities: record.capabilities.clone(),
            capabilities_digest: record.keypackage_ref.clone(),
            device_authorize_event_id: Some(
                arkret_sdk::EventId::new("ak:event:AR4gvLBB1qlq1zRAQHvDYQrKit2SLLNUPBG8C1idlQAc")
                    .unwrap(),
            ),
            agent_key_authorize_event_id: None,
            expires_at: crate::clock::now_utc() + chrono::Duration::minutes(5),
            device_signature: arkret_sdk::KeyOperationSignature {
                kid: arkret_sdk::NonEmptyString::new(kid).unwrap(),
                signature_algorithm: Some(arkret_sdk::NonEmptyString::new("Ed25519").unwrap()),
                sig: arkret_sdk::Base64UrlString::new("YQ").unwrap(),
            },
            revocation_status: None,
            last_resort: None,
        }
    }

    #[test]
    fn native_agent_claim_is_preserved_as_a_native_agent_endpoint() {
        let principal = principal_core_id("did:web:agent.example").unwrap();
        let device =
            arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000002".to_owned())
                .unwrap();
        let identity = arkret_sdk::ArkretMlsIdentity::new_basic(principal.clone(), device).unwrap();
        let record = identity.key_package_record().unwrap();
        let method = arkret_sdk::DidUrl::new("did:web:agent.example#runtime-key").unwrap();
        let mut claim = claim_for(&record, method.as_str());
        claim.device_id = None;
        claim.device_authorize_event_id = None;
        claim.agent_id = Some(principal.clone());
        claim.agent_verification_method = Some(method.clone());
        let authorization_ref =
            arkret_sdk::EventId::new("ak:event:AR4gvLBB1qlq1zRAQHvDYQrKit2SLLNUPBG8C1idlQAc")
                .unwrap();
        claim.agent_key_authorize_event_id = Some(authorization_ref.clone());

        let converted = keypackage_claim_record_to_mls_record(&claim).unwrap();
        assert_eq!(
            converted.endpoint,
            arkret_sdk::MlsEndpointIdentity::NativeAgentRuntime {
                agent_id: principal,
                verification_method: method,
                agent_key_authorize_event_id: authorization_ref,
            }
        );
    }
}
