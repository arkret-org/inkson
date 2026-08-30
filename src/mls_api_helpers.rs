//! MLS KeyPackage helper functions shared by API endpoints and admission code.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub(crate) fn ordinary_mls_identity(
    principal_id: arkret_sdk::DidCoreId,
    device_id: arkret_sdk::DeviceId,
) -> Result<arkret_sdk::ArkretMlsIdentity, String> {
    #[cfg(test)]
    {
        return arkret_sdk::ArkretMlsIdentity::new_test_human_device(principal_id, device_id)
            .map_err(|error| error.to_string());
    }
    #[cfg(not(test))]
    {
        let Some(signer) = crate::event_signer::active_signer() else {
            return Err("active accepted-device signer is unavailable".to_owned());
        };
        if signer.device_id() != Some(device_id.as_str()) {
            return Err("active signer device differs from MLS endpoint".to_owned());
        }
        let signing_key = signer
            .clone_raw_signing_key()
            .map_err(|error| error.to_string())?;
        arkret_sdk::ArkretMlsIdentity::new_human_device(
            principal_id,
            device_id,
            arkret_sdk::ArkretMlsSigner::from_ed25519_signing_key(signing_key),
        )
        .map_err(|error| error.to_string())
    }
}

pub(crate) fn principal_core_id(principal_id: &str) -> anyhow::Result<arkret_sdk::DidCoreId> {
    let principal_id = principal_id.trim();
    if let Ok(core_id) = arkret_sdk::DidCoreId::new(principal_id.to_owned()) {
        return Ok(core_id);
    }
    let did = arkret_sdk::Did::new(principal_id.to_owned())?;
    arkret_sdk::project_did_to_core_id(&did).map_err(anyhow::Error::msg)
}

/// Complete account actor for a principal authored at the selected Station.
pub(crate) fn local_account_actor_id(value: &str) -> anyhow::Result<arkret_sdk::ActorId> {
    Ok(arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        principal_core_id(value)?,
        crate::operation::authoring_station_id()?,
    )))
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
    let sig = signer.sign_raw(&input).map_err(|err| {
        anyhow::anyhow!("keypackages/upload endpoint_signature sign failed: {err}")
    })?;
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
            "keypackages/upload endpoint_signature requires an active event-signer (fail-closed)"
        )
    })?;
    sign_keypackage_upload_batch_with_signer(&signer, unsigned)
}

pub(crate) fn sign_keypackage_revoke_batch(
    unsigned: &arkret_sdk::KeyPackagesRevokeUnsignedRequest,
) -> anyhow::Result<arkret_sdk::KeyOperationSignature> {
    let signer = crate::event_signer::active_signer().ok_or_else(|| {
        anyhow::anyhow!(
            "keypackages/revoke signature requires an active event-signer (fail-closed)"
        )
    })?;
    let input = arkret_sdk::keypackages_revoke_signing_input(unsigned)?;
    let sig = signer
        .sign_raw(&input)
        .map_err(|error| anyhow::anyhow!("keypackages/revoke signature failed: {error}"))?;
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

/// Convert a local `MlsKeyPackageRecord` into the typed wire entry for
/// `keypackages/upload`
/// (`keypackage-operations.schema.json#/$defs/keypackage_upload_entry`).
/// `keypackage_ref` carries the canonical KeyPackage hash; a missing
/// `expires_at` falls back to the SDK default KeyPackage lifetime
/// (`created_at` + 7 days).
pub(crate) fn mls_key_package_record_upload_entry(
    record: &arkret_sdk::MlsKeyPackageRecord,
) -> anyhow::Result<arkret_sdk::KeyPackageUploadEntry> {
    arkret_sdk::mls_key_package_record_upload_entry(record).map_err(anyhow::Error::msg)
}

pub(crate) fn generate_mls_claim_request_id() -> anyhow::Result<String> {
    crate::random::base64url_token(24, "generate MLS KeyPackage claim request id")
}

pub(crate) fn keypackage_claim_record_to_mls_record(
    claim: &arkret_sdk::KeyPackageClaimRecord,
) -> anyhow::Result<arkret_sdk::MlsKeyPackageRecord> {
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
            if agent_id != &claim.principal_id {
                anyhow::bail!("Native Agent KeyPackage claim endpoint binding mismatch");
            }
            arkret_sdk::MlsEndpointIdentity::native_agent_runtime(
                agent_id.clone(),
                method.clone(),
                authorization_ref.clone(),
            )?
        }
        (None, None, None, None) => arkret_sdk::MlsEndpointIdentity::minimal_metadata_pairwise(
            claim.principal_id.clone(),
            claim
                .pairwise_verification_method
                .clone()
                .ok_or_else(|| anyhow::anyhow!("pairwise KeyPackage claim omits its method"))?,
        )?,
        _ => anyhow::bail!("KeyPackage claim has an incomplete or mixed endpoint identity"),
    };
    let keypackage = arkret_sdk::base64url_decode(claim.keypackage.as_bytes())?;
    let keypackage_ref = arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(&keypackage))?;
    Ok(arkret_sdk::MlsKeyPackageRecord {
        keypackage_id: claim.keypackage_ref.as_str().to_owned(),
        endpoint,
        keypackage: claim.keypackage.clone(),
        keypackage_ref,
        cipher_suites: Vec::new(),
        capabilities: claim.capabilities.clone(),
        state: arkret_sdk::MlsKeyPackageState::Published,
        claim_id: Some(claim.claim_id.clone()),
        created_at: crate::clock::now_utc(),
        expires_at: Some(claim.expires_at),
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
    source_id: &str,
    destination_id: &str,
    claim_request_id: &str,
    target_device_id: Option<&str>,
    mls_group_id: &str,
) -> anyhow::Result<arkret_sdk::KeyPackagesClaimRequestBody> {
    let requester_core_id = principal_core_id(requester)?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("KeyPackage claim requires an active device signer"))?;
    let requester_did = arkret_sdk::Did::new(signer.signer_did().to_owned())?;
    anyhow::ensure!(
        arkret_sdk::project_did_to_core_id(&requester_did)? == requester_core_id,
        "active device signer DID does not project to the KeyPackage claim requester"
    );
    let verification_method = signer.verification_method_for_principal(&requester_did)?;
    build_mls_keypackage_claim_request_with_requester(
        target_principal_id,
        intended_realm_id,
        requester_core_id,
        ClaimRequester::Device {
            requester_device_id: arkret_sdk::DeviceId::new(requester_device_id.trim().to_owned())?,
            device_authorize_event_id: requester_device_authorize_event_id.clone(),
            verification_method,
            signer: signer.as_ref(),
        },
        source_id,
        destination_id,
        claim_request_id,
        target_device_id,
        None,
        mls_group_id,
    )
}

pub(crate) fn build_pairwise_mls_keypackage_claim_request(
    target_principal_id: &str,
    intended_realm_id: &str,
    requester: &crate::mls::pairwise_identity::PairwiseSigningMaterial,
    source_id: &str,
    destination_id: &str,
    claim_request_id: &str,
    target_device_id: Option<&str>,
    mls_group_id: &str,
) -> anyhow::Result<arkret_sdk::KeyPackagesClaimRequestBody> {
    let verification_method =
        arkret_sdk::DidUrl::new(requester.signer.verification_method().to_owned())
            .map_err(anyhow::Error::msg)?;
    let target_actor = principal_core_id(target_principal_id)?;
    let multibase = target_actor
        .as_str()
        .strip_prefix("ak:did_core:key:")
        .ok_or_else(|| {
            anyhow::anyhow!("minimal-metadata KeyPackage target must be a pairwise did:key actor")
        })?;
    let target_pairwise_verification_method =
        arkret_sdk::DidUrl::new(format!("did:key:{multibase}#{multibase}"))
            .map_err(anyhow::Error::msg)?;
    arkret_sdk::MlsEndpointIdentity::minimal_metadata_pairwise(
        target_actor,
        target_pairwise_verification_method.clone(),
    )
    .map_err(anyhow::Error::msg)?;
    build_mls_keypackage_claim_request_with_requester(
        target_principal_id,
        intended_realm_id,
        requester.actor_id.clone(),
        ClaimRequester::MinimalMetadataPairwise {
            verification_method,
            signer: requester.signer.as_ref(),
        },
        source_id,
        destination_id,
        claim_request_id,
        target_device_id,
        Some(target_pairwise_verification_method),
        mls_group_id,
    )
}

enum ClaimRequester<'a> {
    Device {
        requester_device_id: arkret_sdk::DeviceId,
        device_authorize_event_id: arkret_sdk::EventId,
        verification_method: arkret_sdk::DidUrl,
        signer: &'a crate::event_signer::InksonEventSigner,
    },
    MinimalMetadataPairwise {
        verification_method: arkret_sdk::DidUrl,
        signer: &'a crate::event_signer::InksonEventSigner,
    },
}

#[allow(clippy::too_many_arguments)]
fn build_mls_keypackage_claim_request_with_requester(
    target_principal_id: &str,
    intended_realm_id: &str,
    requester: arkret_sdk::DidCoreId,
    requester_authority: ClaimRequester<'_>,
    source_id: &str,
    destination_id: &str,
    claim_request_id: &str,
    target_device_id: Option<&str>,
    target_pairwise_verification_method: Option<arkret_sdk::DidUrl>,
    mls_group_id: &str,
) -> anyhow::Result<arkret_sdk::KeyPackagesClaimRequestBody> {
    let target_device_ids = target_device_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| arkret_sdk::DeviceId::new(value.to_owned()))
        .transpose()?
        .into_iter()
        .collect::<Vec<_>>();
    let source_id = arkret_sdk::DidCoreId::new(source_id.trim().to_owned())?;
    let destination_id = arkret_sdk::DidCoreId::new(destination_id.trim().to_owned())?;
    let signed_at = crate::clock::now_utc();
    let unsigned = arkret_sdk::PeerKeyPackagesClaimUnsignedRequest {
        claim_request_id: arkret_sdk::Base64UrlString::new(claim_request_id.trim().to_owned())
            .map_err(anyhow::Error::msg)?,
        target_principal_id: principal_core_id(target_principal_id)?,
        requester_id: requester,
        intended_realm_id: arkret_sdk::RealmId::new(crate::operation::trim_realm_id(
            intended_realm_id,
        ))?,
        mls_group_id: arkret_sdk::NonEmptyString::new(mls_group_id.trim())
            .map_err(anyhow::Error::msg)?,
        claim_purpose: arkret_sdk::PeerKeyPackageClaimPurpose::RealmMembership,
        required_capabilities: mls_keypackage_claim_required_capabilities()?,
        expires_at: signed_at + chrono::Duration::minutes(5),
        target_device_ids,
        target_keypackage_ref: None,
        target_agent_id: None,
        target_agent_verification_method: None,
        target_agent_key_authorize_event_id: None,
        target_pairwise_verification_method,
        timeout_ms: Some(30_000),
        strand_id: None,
        pair_key: None,
        last_resort_allowed: Some(false),
    };
    let service_binding = arkret_sdk::KeyPackagesClaimServiceBinding {
        source_id,
        destination_id,
    };
    let (mut requester_authorization, signer) = match requester_authority {
        ClaimRequester::Device {
            requester_device_id,
            device_authorize_event_id,
            verification_method,
            signer,
        } => (
            arkret_sdk::PeerKeyPackageRequesterAuthorization::Device {
                signature: placeholder_key_operation_signature(&verification_method, signer)?,
                verification_method,
                requester_device_id,
                device_authorize_event_id,
                signed_at,
            },
            signer,
        ),
        ClaimRequester::MinimalMetadataPairwise {
            verification_method,
            signer,
        } => (
            arkret_sdk::PeerKeyPackageRequesterAuthorization::MinimalMetadataPairwise {
                signature: placeholder_key_operation_signature(&verification_method, signer)?,
                verification_method,
                signed_at,
            },
            signer,
        ),
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
        }
        | arkret_sdk::PeerKeyPackageRequesterAuthorization::MinimalMetadataPairwise {
            signature: proof,
            ..
        } => proof.sig = signature,
    }
    let body = arkret_sdk::KeyPackagesClaimRequestBody {
        claim_request_id: unsigned.claim_request_id,
        target_principal_id: unsigned.target_principal_id,
        requester_id: unsigned.requester_id,
        intended_realm_id: unsigned.intended_realm_id,
        mls_group_id: unsigned.mls_group_id,
        claim_purpose: unsigned.claim_purpose,
        required_capabilities: unsigned.required_capabilities,
        expires_at: unsigned.expires_at,
        target_device_ids: unsigned.target_device_ids,
        target_keypackage_ref: unsigned.target_keypackage_ref,
        target_agent_id: unsigned.target_agent_id,
        target_agent_verification_method: unsigned.target_agent_verification_method,
        target_agent_key_authorize_event_id: unsigned.target_agent_key_authorize_event_id,
        target_pairwise_verification_method: unsigned.target_pairwise_verification_method,
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

fn placeholder_key_operation_signature(
    verification_method: &arkret_sdk::DidUrl,
    signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<arkret_sdk::KeyOperationSignature> {
    Ok(arkret_sdk::KeyOperationSignature {
        kid: arkret_sdk::NonEmptyString::new(verification_method.as_str())
            .map_err(anyhow::Error::msg)?,
        signature_algorithm: Some(
            arkret_sdk::NonEmptyString::new(signer.algorithm()).map_err(anyhow::Error::msg)?,
        ),
        sig: arkret_sdk::Base64UrlString::new("YQ").map_err(anyhow::Error::msg)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairwise_realm() -> arkret_sdk::RealmId {
        arkret_sdk::RealmId::new("ak:realm:Aa8_CTduEn4HY_7QtwQ1Ct3QH2pg-9mfHGxJfGOYYHxx".to_owned())
            .unwrap()
    }

    fn claim_for(
        record: &arkret_sdk::MlsKeyPackageRecord,
        _kid: &str,
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
            principal_id,
            device_id: Some(device_id),
            agent_id: None,
            agent_verification_method: None,
            pairwise_verification_method: None,
            keypackage: record.keypackage.clone(),
            capabilities: record.capabilities.clone(),
            device_authorize_event_id: Some(
                arkret_sdk::EventId::new("ak:event:AR4gvLBB1qlq1zRAQHvDYQrKit2SLLNUPBG8C1idlQAc")
                    .unwrap(),
            ),
            agent_key_authorize_event_id: None,
            expires_at: crate::clock::now_utc() + chrono::Duration::minutes(5),
            revocation_status: None,
            last_resort: None,
        }
    }

    #[test]
    fn pairwise_claim_request_uses_only_the_realm_local_requester_authority() {
        let realm_id = pairwise_realm();
        let requester =
            crate::mls::pairwise_identity::pairwise_signing_material_for_test(&realm_id);
        let body = build_pairwise_mls_keypackage_claim_request(
            requester.actor_id.as_str(),
            realm_id.as_str(),
            &requester,
            "ak:did_core:web:source.example",
            "ak:did_core:web:destination.example",
            "Y2xhaW0tcmVxdWVzdC1wYWlyd2lzZQ",
            None,
            "pairwise-realm-group",
        )
        .unwrap();

        assert_eq!(body.requester_id, requester.actor_id);
        assert_eq!(body.intended_realm_id, realm_id);
        match body.requester_authorization {
            arkret_sdk::PeerKeyPackageRequesterAuthorization::MinimalMetadataPairwise {
                verification_method,
                signature,
                ..
            } => {
                assert_eq!(
                    verification_method.as_str(),
                    requester.signer.verification_method()
                );
                assert_eq!(signature.kid.as_str(), verification_method.as_str());
                assert_ne!(signature.sig.as_str(), "YQ");
            }
            _ => panic!("pairwise requester must not carry device or Agent authority"),
        }
    }

    #[test]
    fn pairwise_upload_signs_the_closed_batch_with_the_exact_method() {
        let realm_id = pairwise_realm();
        let material = crate::mls::pairwise_identity::pairwise_signing_material_for_test(&realm_id);
        let verification_method =
            arkret_sdk::DidUrl::new(material.signer.verification_method().to_owned()).unwrap();
        let identity = arkret_sdk::ArkretMlsIdentity::new_minimal_metadata_pairwise(
            material.actor_id.clone(),
            verification_method.clone(),
            arkret_sdk::ArkretMlsSigner::from_ed25519_signing_key(
                ed25519_dalek::SigningKey::from_bytes(&material.signing_seed()),
            ),
        )
        .unwrap();
        let record = identity.key_package_record().unwrap();
        let entry = mls_key_package_record_upload_entry(&record).unwrap();
        let unsigned = arkret_sdk::KeyPackagesUploadUnsignedRequest {
            principal_id: material.actor_id.clone(),
            device_id: None,
            pairwise_verification_method: Some(verification_method.clone()),
            intended_realm_id: Some(realm_id),
            agent_verification_method: None,
            agent_key_authorize_event_id: None,
            keypackages: vec![entry.clone()],
            expires_at: None,
            strand_id: None,
            mls_group_id: None,
        };

        let batch =
            sign_keypackage_upload_batch_with_signer(material.signer.as_ref(), &unsigned).unwrap();
        assert_eq!(batch.kid.as_str(), verification_method.as_str());
    }

    #[test]
    fn native_agent_claim_is_preserved_as_a_native_agent_endpoint() {
        let principal = principal_core_id("did:web:agent.example").unwrap();
        let device =
            arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000002".to_owned())
                .unwrap();
        let identity =
            arkret_sdk::ArkretMlsIdentity::new_test_human_device(principal.clone(), device)
                .unwrap();
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
