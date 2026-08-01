//! MLS KeyPackage helper functions shared by API endpoints and admission code.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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
        alg: Some(arkret_sdk::NonEmptyString::new(signer.algorithm()).map_err(anyhow::Error::msg)?),
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

pub(crate) fn sign_keypackage_consume(
    unsigned: &arkret_sdk::KeyPackagesConsumeUnsignedRequest,
) -> anyhow::Result<arkret_sdk::KeyOperationSignature> {
    let signer = crate::event_signer::active_signer().ok_or_else(|| {
        anyhow::anyhow!(
            "keypackages/consume signature requires an active event-signer (fail-closed)"
        )
    })?;
    let input = arkret_sdk::keypackages_consume_signing_input(unsigned)?;
    let signature = signer
        .sign_raw(&input)
        .map_err(|error| anyhow::anyhow!("keypackages/consume signature failed: {error}"))?;
    Ok(arkret_sdk::KeyOperationSignature {
        kid: arkret_sdk::NonEmptyString::new(signer.verification_method())
            .map_err(anyhow::Error::msg)?,
        alg: Some(arkret_sdk::NonEmptyString::new(signer.algorithm()).map_err(anyhow::Error::msg)?),
        sig: arkret_sdk::Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature))
            .map_err(anyhow::Error::msg)?,
    })
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
    Ok(arkret_sdk::MlsKeyPackageRecord {
        keypackage_id: claim.keypackage_ref.as_str().to_owned(),
        principal_id: claim.principal_id.clone(),
        device_id: arkret_sdk::DeviceId::new(claim.device_id.clone())?,
        key_package: claim.key_package.clone(),
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

pub(crate) fn mls_keypackage_claim_required_capabilities() -> Vec<String> {
    arkret_sdk::ARKRET_MLS_KEY_PACKAGE_CAPABILITIES
        .iter()
        .map(|capability| (*capability).to_owned())
        .collect()
}

pub(crate) fn build_mls_keypackage_claim_request(
    target_principal_id: &str,
    intended_realm_id: &str,
    requester: &str,
    authority_service_id: &str,
    claim_nonce: &str,
    target_device_id: Option<&str>,
    mls_group_id: Option<&str>,
) -> anyhow::Result<arkret_sdk::KeyPackagesClaimRequestBody> {
    let target_device_ids = target_device_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| arkret_sdk::DeviceId::new(value.to_owned()))
        .transpose()?
        .into_iter()
        .collect::<Vec<_>>();
    let requester = arkret_sdk::Did::new(requester.trim().to_owned())?;
    let authority_service_id = arkret_sdk::Did::new(authority_service_id.trim().to_owned())?;
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("KeyPackage self-claim requires an active device signer"))?;
    let verification_method = signer.verification_method_for_principal(&requester)?;
    let created_at = crate::clock::now_utc();
    let expires_at = created_at + chrono::Duration::minutes(5);
    let mut body = arkret_sdk::KeyPackagesClaimRequestBody {
        target_principal_id: arkret_sdk::Did::new(target_principal_id.trim().to_owned())?,
        intended_realm_id: arkret_sdk::RealmId::new(crate::operation::trim_realm_id(
            intended_realm_id,
        ))?,
        requester,
        required_capabilities: mls_keypackage_claim_required_capabilities(),
        claim_nonce: arkret_wire::Base64UrlString::new(claim_nonce.trim().to_owned())
            .map_err(|error| anyhow::anyhow!(error))?,
        expires_at,
        target_device_ids,
        minimal_metadata_allowed: Some(true),
        timeout_ms: Some(30_000),
        strand_id: None,
        mls_group_id: mls_group_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        proofs: [arkret_models_crypto::http_bodies::KeyPackageClaimProof {
            kind: arkret_models_crypto::http_bodies::KeyPackageClaimProofKind::DetachedJws,
            verification_method,
            alg: arkret_models_crypto::http_bodies::KeyPackageClaimProofAlgorithm::EdDsa,
            payload_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            created_at,
            audience: authority_service_id,
            proof_purpose:
                arkret_models_crypto::http_bodies::KeyPackageClaimProofPurpose::HolderAcceptance,
            jws: "eyJhbGciOiJFZERTQSJ9..AA".to_owned(),
        }],
    };
    body.proofs[0].payload_digest = body.payload_digest()?;
    let binding = body.proof_binding_bytes()?;
    body.proofs[0].jws = signer.sign_detached_jws_bytes(&binding)?;
    Ok(body)
}
