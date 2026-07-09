//! MLS KeyPackage helper functions shared by API endpoints and admission code.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

/// Canonical signing-input prefix for the MLS `keypackages/upload`
/// `device_signature`. Distinct domain string from the prekey `keys/upload`
/// (`ck-keys-upload-v1`, spec §8.1) so a signature over one batch can never be
/// replayed as the other; binds the device + the published KeyPackage batch.
const KEYPACKAGE_UPLOAD_SIGNATURE_PREFIX: &str = "ck-keypackage-upload-v1\n";

/// Sign the MLS KeyPackage upload batch with the local event-signer (device
/// identity Ed25519 `did:key`), binding `device_id` + the published
/// `key_packages`. Fail-closed (`bail!`) when no signer is installed.
pub(crate) fn keypackage_upload_signing_input(
    device_id: &str,
    key_packages: &[Value],
) -> anyhow::Result<Vec<u8>> {
    let body = json!({
        "device_id": device_id,
        "key_packages": key_packages,
    });
    let canonical = crate::canonical::canonical_json_bytes(&body)?;
    let mut input = Vec::with_capacity(KEYPACKAGE_UPLOAD_SIGNATURE_PREFIX.len() + canonical.len());
    input.extend_from_slice(KEYPACKAGE_UPLOAD_SIGNATURE_PREFIX.as_bytes());
    input.extend_from_slice(&canonical);
    Ok(input)
}

pub(crate) fn sign_keypackage_upload_batch_with_signer(
    signer: &crate::event_signer::InksonEventSigner,
    device_id: &str,
    key_packages: &[Value],
) -> anyhow::Result<arkret_sdk::KeyOperationSignature> {
    let input = keypackage_upload_signing_input(device_id, key_packages)?;
    let sig = signer
        .sign_raw(&input)
        .map_err(|err| anyhow::anyhow!("keypackages/upload device_signature sign failed: {err}"))?;
    Ok(arkret_sdk::KeyOperationSignature {
        kid: signer.verification_method().to_owned(),
        alg: Some(signer.algorithm().to_owned()),
        sig: URL_SAFE_NO_PAD.encode(sig),
    })
}

pub(crate) fn sign_keypackage_upload_batch(
    device_id: &str,
    key_packages: &[Value],
) -> anyhow::Result<arkret_sdk::KeyOperationSignature> {
    let signer = crate::event_signer::active_signer().ok_or_else(|| {
        anyhow::anyhow!(
            "keypackages/upload device_signature requires an active event-signer (fail-closed)"
        )
    })?;
    sign_keypackage_upload_batch_with_signer(&signer, device_id, key_packages)
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
    Ok(arkret_sdk::KeyPackageUploadEntry {
        keypackage_id: record.keypackage_id.clone(),
        keypackage_ref: record.keypackage_ref.as_str().to_owned(),
        keypackage_digest: record.keypackage_ref.clone(),
        key_package: Value::String(record.key_package.clone()),
        cipher_suites: record.cipher_suites.clone(),
        capabilities: record.capabilities.clone(),
        expires_at: record
            .expires_at
            .unwrap_or(record.created_at + chrono::Duration::days(7)),
        created_at: record.created_at,
        device_signature: None,
        last_resort: record.last_resort.then_some(true),
    })
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
    Ok(arkret_sdk::KeyPackagesClaimRequestBody {
        target_principal_id: arkret_sdk::Did::new(target_principal_id.trim().to_owned())?,
        intended_realm_id: arkret_sdk::RealmId::new(crate::operation::trim_realm_id(
            intended_realm_id,
        ))?,
        requester: arkret_sdk::Did::new(requester.trim().to_owned())?,
        required_capabilities: mls_keypackage_claim_required_capabilities(),
        claim_nonce: claim_nonce.trim().to_owned(),
        expires_at: crate::clock::now_utc() + chrono::Duration::minutes(10),
        target_device_ids,
        minimal_metadata_allowed: Some(true),
        timeout_ms: Some(30_000),
        strand_id: None,
        mls_group_id: mls_group_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        proofs: Vec::new(),
    })
}
