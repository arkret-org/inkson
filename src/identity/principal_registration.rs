//! Durable, client-authored identity creation with atomic PCR genesis.

use anyhow::{Context as _, anyhow};
use arkret_sdk::EventPayloadExt as _;
use chrono::{Timelike as _, Utc};
use dioxus::prelude::WritableExt as _;
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::state::{
    PendingAccountHandoff, PendingPrincipalRegistration, PendingPrincipalRegistrationStage,
};

pub fn prepare_registration_checkpoint(
    handoff: &PendingAccountHandoff,
    device_id: &str,
    recovery_key: &str,
) -> anyhow::Result<PendingPrincipalRegistration> {
    let key_material = arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
        recovery_key,
        "",
        0,
    )?;
    let endpoint = Url::parse(&handoff.principal_server_url)
        .context("Principal Server URL cannot drive did:webvh inception")?;
    let created_at = Utc::now().with_nanosecond(0).unwrap_or_else(Utc::now);
    let local_id = handoff
        .request_id
        .trim()
        .strip_prefix("ak:request:")
        .unwrap_or(handoff.request_id.trim())
        .to_ascii_lowercase();
    let lease_id = handoff
        .lease_id
        .clone()
        .ok_or_else(|| anyhow!("account handoff has no active identity-creation lease"))?;
    let lease_fence = handoff
        .lease_fence
        .ok_or_else(|| anyhow!("account handoff has no lease fence"))?;
    let draft = arkret_sdk::webvh::prepare_principal_inception(
        &arkret_sdk::webvh::PrincipalInceptionInput {
            principal_endpoint: &endpoint,
            local_id: &local_id,
            also_known_as: &[],
            version_time: created_at,
            root_seed: &key_material.root_seed,
            next_root_public_key_multibase: &key_material.next_root_public_key_multikey,
        },
    )?;
    let genesis_hlc = crate::signing_stamp::issue_realm_genesis_hlc_with_secret(
        &draft.did,
        device_id.trim(),
        &key_material.root_seed,
    )?
    .to_string();
    Ok(PendingPrincipalRegistration {
        principal_server_url: handoff.principal_server_url.clone(),
        gate_account_base: handoff.gate_account_base.clone(),
        handoff_request_id: handoff.request_id.clone(),
        account_handle: handoff.account_handle.clone(),
        account_subject: handoff.account_subject.clone(),
        lease_id,
        lease_fence,
        device_id: device_id.trim().to_owned(),
        trust_domain: handoff.trust_domain.clone(),
        did: draft.did,
        version_id: draft.version_id,
        identity_abandonment: None,
        root_public_key_multibase: draft.root_public_key_multibase,
        root_verification_method: draft.root_verification_method,
        next_root_public_key_multibase: draft.next_root_public_key_multibase,
        next_root_key_hash: draft.next_root_key_hash,
        recovery_proof_public_key_multibase: key_material
            .recovery_proof_public_key_multikey
            .clone(),
        backup_hpke_public_key_multibase: key_material.backup_hpke_public_key_multikey.clone(),
        recovery_key_fingerprint: crate::recovery_crypto::fingerprint_recovery_key(recovery_key),
        did_entry0_canonical_base64url: arkret_sdk::base64url_encode(
            &arkret_sdk::canonical::canonical_json_bytes(&draft.log_entry)?,
        ),
        did_operation: draft.submit_body,
        pcr_genesis_unit: None,
        initial_session: None,
        pcr_genesis_receipt: None,
        pcr_bootstrap_seal: None,
        genesis_created_at: arkret_sdk::canonical::format_timestamp_canonical(created_at),
        genesis_hlc,
        genesis_salt: arkret_sdk::GenesisSalt::generate()?.into_string(),
        binding_receipt: None,
        principal_service_binding: None,
        stage: PendingPrincipalRegistrationStage::CustodyConfirmed,
    })
}

/// Rebuild the public onboarding checkpoint on a replacement device after an
/// identity-creation lease has been fenced. The DID operation is inherited
/// byte-for-byte from the Account Authority reservation; only device, HPKE,
/// DPoP and PCR-genesis material will be regenerated for the new holder.
pub fn recover_registration_checkpoint_from_reservation(
    handoff: &PendingAccountHandoff,
    recovery_key: &str,
) -> anyhow::Result<PendingPrincipalRegistration> {
    let reserved: arkret_sdk::ReservedIdentityCreation = serde_json::from_value(
        handoff
            .reserved_identity
            .clone()
            .context("renewed identity-creation lease omits the reserved DID operation")?,
    )?;
    let lease_id = handoff
        .lease_id
        .clone()
        .context("renewed identity-creation lease has no lease id")?;
    let lease_fence = handoff
        .lease_fence
        .context("renewed identity-creation lease has no fence")?;
    if lease_fence == 0 {
        anyhow::bail!("renewed identity-creation lease fence must be positive");
    }
    let validated = arkret_sdk::signatures::webvh::validate_principal_inception_operation(
        &reserved.did_operation,
    )
    .map_err(|error| anyhow!("reserved DID inception operation is invalid: {error}"))?;
    if validated.principal_id != reserved.principal_id
        || validated.operation_digest != reserved.operation_digest
    {
        anyhow::bail!("reserved DID operation digest or principal does not match its checkpoint");
    }
    let key_material = arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
        recovery_key,
        "",
        0,
    )?;
    if validated.root_public_key_multibase != key_material.root_public_key_multikey {
        anyhow::bail!("Recovery Key does not control the reserved identity root");
    }
    let operation = serde_json::Value::Object(
        reserved
            .did_operation
            .operation
            .clone()
            .into_iter()
            .collect(),
    );
    let version_id = operation
        .get("versionId")
        .and_then(serde_json::Value::as_str)
        .context("reserved DID inception omits versionId")?
        .to_owned();
    let created_at = operation
        .get("versionTime")
        .and_then(serde_json::Value::as_str)
        .context("reserved DID inception omits versionTime")?;
    let created_at = chrono::DateTime::parse_from_rfc3339(created_at)
        .context("reserved DID inception versionTime is invalid")?
        .with_timezone(&Utc);
    let next_root_key_hash = operation
        .pointer("/parameters/nextKeyHashes/0")
        .and_then(serde_json::Value::as_str)
        .context("reserved DID inception omits nextKeyHashes[0]")?;
    if next_root_key_hash != key_material.next_root_key_hash {
        anyhow::bail!("Recovery Key does not match the reserved root pre-rotation chain");
    }
    let root_verification_method = operation
        .pointer("/proof/0/verificationMethod")
        .and_then(serde_json::Value::as_str)
        .context("reserved DID inception omits its root verification method")?
        .to_owned();
    let genesis_hlc = crate::signing_stamp::issue_realm_genesis_hlc_with_secret(
        reserved.full_id.as_str(),
        handoff.device_id.trim(),
        &key_material.root_seed,
    )?
    .to_string();
    Ok(PendingPrincipalRegistration {
        principal_server_url: handoff.principal_server_url.clone(),
        gate_account_base: handoff.gate_account_base.clone(),
        handoff_request_id: handoff.request_id.clone(),
        account_handle: handoff.account_handle.clone(),
        account_subject: handoff.account_subject.clone(),
        lease_id,
        lease_fence,
        device_id: handoff.device_id.trim().to_owned(),
        trust_domain: handoff.trust_domain.clone(),
        did: reserved.full_id.to_string(),
        version_id,
        identity_abandonment: None,
        root_public_key_multibase: key_material.root_public_key_multikey.clone(),
        root_verification_method,
        next_root_public_key_multibase: key_material.next_root_public_key_multikey.clone(),
        next_root_key_hash: key_material.next_root_key_hash.clone(),
        recovery_proof_public_key_multibase: key_material
            .recovery_proof_public_key_multikey
            .clone(),
        backup_hpke_public_key_multibase: key_material.backup_hpke_public_key_multikey.clone(),
        recovery_key_fingerprint: crate::recovery_crypto::fingerprint_recovery_key(recovery_key),
        did_entry0_canonical_base64url: arkret_sdk::base64url_encode(
            &arkret_sdk::canonical::canonical_json_bytes(&operation)?,
        ),
        did_operation: reserved.did_operation,
        pcr_genesis_unit: None,
        initial_session: None,
        pcr_genesis_receipt: None,
        pcr_bootstrap_seal: None,
        genesis_created_at: arkret_sdk::canonical::format_timestamp_canonical(created_at),
        genesis_hlc,
        genesis_salt: arkret_sdk::GenesisSalt::generate()?.into_string(),
        binding_receipt: None,
        principal_service_binding: None,
        stage: PendingPrincipalRegistrationStage::CustodyConfirmed,
    })
}

pub fn validate_checkpoint_recovery_key(
    checkpoint: &PendingPrincipalRegistration,
    recovery_key: &str,
) -> anyhow::Result<arkret_sdk::identity_root::IdentityRecoveryKeyMaterial> {
    let key_material = arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
        recovery_key,
        "",
        0,
    )?;
    let fingerprint = crate::recovery_crypto::fingerprint_recovery_key(recovery_key);
    if checkpoint.recovery_key_fingerprint != fingerprint
        || checkpoint.root_public_key_multibase != key_material.root_public_key_multikey
        || checkpoint.next_root_public_key_multibase != key_material.next_root_public_key_multikey
        || checkpoint.next_root_key_hash != key_material.next_root_key_hash
        || checkpoint.recovery_proof_public_key_multibase
            != key_material.recovery_proof_public_key_multikey
        || checkpoint.backup_hpke_public_key_multibase
            != key_material.backup_hpke_public_key_multikey
    {
        anyhow::bail!("Recovery Key does not match the persisted identity draft");
    }
    Ok(key_material)
}

pub fn checkpoint_belongs_to_handoff(
    checkpoint: &PendingPrincipalRegistration,
    handoff: &PendingAccountHandoff,
) -> bool {
    let same_context = checkpoint.principal_server_url == handoff.principal_server_url
        && checkpoint.gate_account_base == handoff.gate_account_base
        && checkpoint.trust_domain == handoff.trust_domain
        && checkpoint.account_subject.is_some()
        && checkpoint.account_subject == handoff.account_subject;
    if !same_context {
        return false;
    }
    if checkpoint.handoff_request_id == handoff.request_id {
        return true;
    }
    let Some(reserved_identity) = handoff.reserved_identity.as_ref() else {
        return false;
    };
    let Ok(reserved_identity) =
        serde_json::from_value::<arkret_sdk::ReservedIdentityCreation>(reserved_identity.clone())
    else {
        return false;
    };
    arkret_sdk::ReservedIdentityCreation::from_operation(checkpoint.did_operation.clone())
        .is_ok_and(|expected| expected == reserved_identity)
}

/// Finish all local key generation and signatures before the first identity
/// challenge or register network side effect. Re-entry validates and reuses the
/// byte-identical unit.
#[allow(clippy::too_many_arguments)]
pub fn prepare_genesis_draft(
    checkpoint: &PendingPrincipalRegistration,
    recovery_key: &str,
    device_public_key: String,
    hpke_key: String,
    device_signer: &crate::event_signer::InksonEventSigner,
    dpop: &crate::identity::account_auth::grant_dpop::DpopHandle,
    audience: arkret_sdk::DidCoreId,
) -> anyhow::Result<PendingPrincipalRegistration> {
    let key_material = validate_checkpoint_recovery_key(checkpoint, recovery_key)?;
    if checkpoint.stage != PendingPrincipalRegistrationStage::CustodyConfirmed {
        let unit = checkpoint
            .pcr_genesis_unit
            .clone()
            .context("checkpoint omits PCR genesis unit")?;
        let initial = checkpoint
            .initial_session
            .clone()
            .context("checkpoint omits initial session request")?;
        unit.validate_ordered_envelopes()?;
        initial.validate()?;
        let create_payload = unit
            .create()
            .typed_payload::<arkret_sdk::event_spec::RealmCreate>()?;
        let descriptor = create_payload
            .object
            .founding_device_descriptor
            .context("persisted PCR genesis omits founding device descriptor")?;
        if initial.session_public_key.thumbprint_sha256()? != dpop.jkt()
            || initial.device_id.as_str() != checkpoint.device_id
            || descriptor.device_public_key.as_str() != device_public_key
            || descriptor.hpke_key.as_str() != hpke_key
        {
            anyhow::bail!(
                "persisted genesis draft belongs to different DPoP or device key material"
            );
        }
        return Ok(checkpoint.clone());
    }

    let principal_id = arkret_sdk::DidFullId::new(checkpoint.did.clone())?;
    let created_at = chrono::DateTime::parse_from_rfc3339(&checkpoint.genesis_created_at)
        .context("persisted genesis creation time is invalid")?
        .with_timezone(&Utc);
    let unit = crate::identity::principal_genesis::build_genesis_unit(
        principal_id,
        arkret_sdk::GenesisSalt::new(checkpoint.genesis_salt.clone())?,
        arkret_sdk::TypedTrustDomainId::new(checkpoint.trust_domain.clone())?,
        checkpoint.version_id.clone(),
        created_at,
        arkret_sdk::Hlc::new(checkpoint.genesis_hlc.clone())?,
        &key_material.root_seed,
        &checkpoint.root_public_key_multibase,
        arkret_sdk::DeviceId::new(checkpoint.device_id.clone())?,
        device_public_key,
        hpke_key,
        device_signer,
    )?;
    let initial = arkret_sdk::InitialSessionGrantRequest {
        device_id: arkret_sdk::DeviceId::new(checkpoint.device_id.clone())?,
        session_public_key: dpop.canonical_session_public_jwk()?,
        audience,
        requested_scope: vec!["ak.self.account.read.viewer".to_owned()],
    };
    initial.validate()?;
    let mut prepared = checkpoint.clone();
    prepared.pcr_genesis_unit = Some(unit);
    prepared.initial_session = Some(initial);
    prepared
        .advance_registration_stage(PendingPrincipalRegistrationStage::GenesisDraftPrepared)
        .map_err(anyhow::Error::msg)?;
    Ok(prepared)
}

pub struct IdentityBindingCompletion {
    pub binding_receipt: arkret_sdk::AccountBindingReceipt,
    pub pcr_genesis_receipt: arkret_sdk::EventBatchReceipt,
    pub session_grant: garth::SessionGrantState,
    pub session_private_key_pem: String,
    pub dpop_device_key: crate::state::DpopDeviceKeyRecord,
}

/// Install the immutable principal-to-Principal-Server binding immediately
/// after registration.  The request id is deterministic for this principal
/// and service, so prepare/commit response loss reuses the frozen challenge and
/// the byte-identical Ed25519 signature instead of creating another history
/// generation.
pub async fn ensure_principal_service_binding(
    http: &arkret_sdk::http_client::Client,
    principal_id: &arkret_sdk::DidFullId,
    signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<arkret_sdk::AcceptedAtServiceBinding> {
    let request_seed = format!(
        "arkret.principal-service-binding.v1\0{}\0{}",
        principal_id,
        http.base_url()
    );
    let request_id = arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(
        Sha256::digest(request_seed.as_bytes()),
    ))
    .map_err(anyhow::Error::msg)?;
    let principal_core =
        arkret_sdk::DidCoreId::from(arkret_sdk::project_full_id_to_core_id(principal_id)?);
    let prepare_request = arkret_sdk::PrincipalServiceBindingPrepareRequestBody {
        request_id: request_id.clone(),
        expected_current_binding_digest: None,
    };
    let prepared = http
        .principal_service_binding_prepare(&prepare_request)
        .await?;
    prepared.validate_shape()?;
    if prepared.request_id != request_id || prepared.binding_draft.principal_id != principal_core {
        anyhow::bail!("principal service binding prepare returned foreign authoring material");
    }
    let verification_method = signer.verification_method_for_principal(principal_id)?;
    let signing_input = prepared.binding_draft.proof_signing_input_bytes(
        arkret_sdk::PrincipalServiceBindingProofPurpose::PrincipalAuthorization,
        &verification_method,
    )?;
    let signature = arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(
        signer.sign_raw(&signing_input)?,
    ))
    .map_err(anyhow::Error::msg)?;
    let commit = arkret_sdk::PrincipalServiceBindingCommitRequestBody {
        request_id,
        challenge_id: prepared.challenge_id,
        binding_digest: prepared.binding_draft.binding_digest.clone(),
        principal_authorization_proof: arkret_sdk::ProtocolSignature {
            verification_method,
            created_at: prepared.binding_draft.accepted_at,
            jws: signature,
        },
    };
    let outcome = http.principal_service_binding_commit(&commit).await?;
    outcome.binding.validate_shape()?;
    if outcome.binding.core() != prepared.binding_draft {
        anyhow::bail!("principal service binding commit changed the frozen binding core");
    }
    Ok(outcome.binding)
}

pub async fn complete_account_handoff_binding(
    handoff: &PendingAccountHandoff,
    checkpoint: &PendingPrincipalRegistration,
    recovery_key: &str,
    dpop: &crate::identity::account_auth::grant_dpop::DpopHandle,
    mut state_store: dioxus::prelude::SyncSignal<crate::state::LocalStateStore>,
) -> anyhow::Result<IdentityBindingCompletion> {
    let expected_account_subject = handoff
        .account_subject
        .as_ref()
        .context("account handoff subject is unavailable; authenticate again")?;
    if checkpoint.account_subject.as_ref() != Some(expected_account_subject) {
        anyhow::bail!("account handoff subject does not match the frozen registration draft");
    }
    if handoff.expires_at <= Utc::now() {
        anyhow::bail!("account handoff expired; authenticate the account again");
    }
    if handoff.holder_jkt != dpop.jkt() {
        anyhow::bail!("account handoff holder key does not match the current DPoP key");
    }
    let account_handoff_grant = crate::identity::account_auth::load_account_handoff_grant()?
        .ok_or_else(|| anyhow!("account handoff credential is unavailable; authenticate again"))?;
    let key_material = validate_checkpoint_recovery_key(checkpoint, recovery_key)?;
    let did_operation = checkpoint.did_operation.clone();
    let unit = checkpoint
        .pcr_genesis_unit
        .clone()
        .context("checkpoint omits PCR genesis unit")?;
    let initial = checkpoint
        .initial_session
        .clone()
        .context("checkpoint omits initial session request")?;
    let lease = arkret_sdk::IdentityCreationLease {
        identity_creation_lease_id: checkpoint.lease_id.clone(),
        fence: checkpoint.lease_fence,
        expires_at: handoff
            .lease_expires_at
            .ok_or_else(|| anyhow!("identity-creation lease expiry is unavailable"))?,
        reserved_identity: handoff
            .reserved_identity
            .clone()
            .map(serde_json::from_value)
            .transpose()
            .context("persisted identity reservation is invalid")?,
    };
    let challenge_request = garth::identity_binding_challenge_request(
        arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms()),
        &lease,
        did_operation.clone(),
        &unit,
        &initial,
    )?;
    let account_base = crate::identity::session_refresh::sdk_base_url_from_gate_account_base(
        &handoff.gate_account_base,
    )?;
    let account_client = arkret_sdk::http_client::ClientBuilder::new(account_base)
        .allow_insecure_localhost()
        .auth(arkret_sdk::http_client::Auth::Dpop(
            dpop.sdk_account_handoff_auth(account_handoff_grant),
        ))
        .build()?;

    let register_request = if let Some(prepared) =
        crate::identity::account_auth::load_prepared_identity_creation_request()?
    {
        prepared.validate()?;
        let registration = prepared
            .identity_creation
            .as_ref()
            .context("prepared registration omits identity creation")?;
        if prepared.principal_id.as_str() != checkpoint.did
            || registration.identity_creation_lease_id != checkpoint.lease_id
            || registration.lease_fence != checkpoint.lease_fence
            || registration.pcr_genesis_unit != unit
            || registration.initial_session != initial
        {
            anyhow::bail!("prepared identity creation request belongs to another lease or draft");
        }
        prepared
    } else {
        let challenge = account_client
            .auth_issue_identity_binding_challenge(&challenge_request)
            .await?;
        let request = garth::identity_creation_register_request(
            &challenge,
            expected_account_subject,
            did_operation,
            unit,
            initial.clone(),
            &key_material.root_seed,
            None,
        )?;
        crate::identity::account_auth::persist_prepared_identity_creation_request(&request).await?;
        request
    };
    let register_outcome = account_client.account_register(&register_request).await?;
    garth::validate_identity_creation_outcome(&register_outcome, &register_request)?;
    let binding_receipt = register_outcome.binding_receipt.clone();
    let checkpoint_full_id = arkret_sdk::DidFullId::new(checkpoint.did.clone())?;
    if &binding_receipt.account_subject != expected_account_subject
        || binding_receipt.principal_id
            != arkret_sdk::project_full_id_to_core_id(&checkpoint_full_id)?
    {
        anyhow::bail!("Account Authority binding receipt does not match the frozen account or DID");
    }
    let pcr_genesis_receipt = register_outcome
        .pcr_genesis_receipt
        .clone()
        .context("Account Authority omitted PCR genesis receipt")?;

    // Preserve the exact typed response before any follow-up resolution. A
    // transient authority-history failure can be retried without discarding
    // the signed proof or substituting a later response.
    {
        let mut durable = checkpoint.clone();
        durable.binding_receipt = Some(serde_json::to_value(&binding_receipt)?);
        durable.pcr_genesis_receipt = Some(serde_json::to_value(&pcr_genesis_receipt)?);
        let barrier = {
            let mut store = state_store.write();
            store.set_pending_principal_registration(Some(durable))?;
            store.begin_durable_flush()?
        };
        barrier.wait().await?;
    }

    verify_registration_terminal_evidence(
        checkpoint,
        &register_request,
        &binding_receipt,
        &account_client,
    )
    .await?;
    let grant = register_outcome
        .session_grant_outcome
        .context("Account Authority omitted initial Standard grant")?;
    let session_grant =
        garth::SessionGrantState::from_initial_registration_outcome(&initial, grant, Utc::now())?;
    let session_private_key_pem = dpop.session_signing_key_pkcs8_pem()?.to_string();
    let dpop_device_key =
        crate::identity::account_auth::grant_dpop::dpop_device_key_record_from_seed(
            dpop.seed_b64().as_str(),
        )?;
    Ok(IdentityBindingCompletion {
        binding_receipt,
        pcr_genesis_receipt,
        session_grant,
        session_private_key_pem,
        dpop_device_key,
    })
}

async fn verify_registration_terminal_evidence(
    checkpoint: &PendingPrincipalRegistration,
    request: &arkret_sdk::AccountRegisterRequestBody,
    receipt: &arkret_sdk::AccountBindingReceipt,
    account_client: &arkret_sdk::http_client::Client,
) -> anyhow::Result<()> {
    let authority_full_id = arkret_sdk::DidFullId::new(
        receipt
            .proof
            .verification_method
            .as_str()
            .split_once('#')
            .map(|(controller, _)| controller.to_owned())
            .context("Account Authority receipt proof omits DID fragment")?,
    )?;
    if arkret_sdk::project_full_id_to_core_id(&authority_full_id)? != receipt.account_authority_id {
        anyhow::bail!("Account Authority receipt proof controller mismatch");
    }
    let authority_history = crate::identity::history::fetch_complete_identity_history(
        account_client,
        &authority_full_id,
    )
    .await
    .context("fetch complete Account Authority DID history")?;
    let authority_resolver =
        crate::identity::history::FrozenAuthorityHistoryResolver::new(&authority_history)?;
    garth::verify_binding_receipt_at_issuance(receipt, &authority_resolver)
        .map_err(|error| anyhow!("verify Account Authority receipt at issuance: {error}"))?;

    let principal_id = arkret_sdk::DidFullId::new(checkpoint.did.clone())?;
    let principal_client =
        arkret_sdk::http_client::ClientBuilder::new(Url::parse(&checkpoint.principal_server_url)?)
            .allow_insecure_localhost()
            .build()?;
    let history =
        crate::identity::history::fetch_complete_identity_history(&principal_client, &principal_id)
            .await
            .context("fetch complete principal did.jsonl history")?;
    if history.method != "did:webvh" || history.native_history != Some(true) {
        anyhow::bail!("principal history is not a native did:webvh history");
    }
    let entry0 = history
        .entries
        .first()
        .context("principal did.jsonl is empty after accepted registration")?;
    let observed_entry0 =
        arkret_sdk::base64url_encode(&arkret_sdk::canonical::canonical_json_bytes(entry0)?);
    if observed_entry0 != checkpoint.did_entry0_canonical_base64url {
        anyhow::bail!("principal did.jsonl entry 0 differs from the frozen inception bytes");
    }

    let did_operation = checkpoint.did_operation.clone();
    let frozen_entry =
        serde_json::Value::Object(did_operation.operation.clone().into_iter().collect());
    if entry0 != &frozen_entry {
        anyhow::bail!("principal did.jsonl entry 0 differs from the frozen operation");
    }
    let validated =
        arkret_sdk::signatures::webvh::validate_principal_inception_operation(&did_operation)
            .map_err(|error| anyhow!("revalidate accepted principal inception: {error}"))?;
    let registration = request
        .identity_creation
        .as_ref()
        .context("identity-creation request lost its frozen registration")?;
    if validated.principal_id != receipt.principal_id
        || validated.operation_digest != receipt.operation_digest
        || validated.log_head_digest != receipt.head_event_digest
        || validated.did_version_id != registration.control_proof.did_version_id
        || validated.log_head_digest != registration.control_proof.log_head_digest
        || validated.control_key_digest != registration.control_proof.control_key_digest
    {
        anyhow::bail!("accepted DID history does not reproduce the signed registration pins");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handoff(device_id: &str, fence: u64) -> PendingAccountHandoff {
        PendingAccountHandoff {
            principal_server_url: "https://principal.example".to_owned(),
            gate_account_base: "https://account.example/_arkret/gate/account".to_owned(),
            request_id: "ak:request:019f0000-0000-7000-8000-000000000001".to_owned(),
            account_handle: "alice:example.com".to_owned(),
            account_subject: Some(
                arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            ),
            holder_jkt: "holder-jkt".to_owned(),
            audience: "did:webvh:z6mkfixture:principal.example".to_owned(),
            expires_at: Utc::now() + chrono::Duration::minutes(15),
            lease_id: Some("lease-1".to_owned()),
            lease_fence: Some(fence),
            lease_expires_at: Some(Utc::now() + chrono::Duration::minutes(15)),
            reserved_identity: None,
            retry_after_ms: None,
            device_id: device_id.to_owned(),
            trust_domain: "ak:trust_domain:principal.example".to_owned(),
            bound_principal_id: None,
        }
    }

    #[test]
    fn replacement_device_reuses_reserved_did_and_new_fence() {
        let key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let first = prepare_registration_checkpoint(
            &handoff("ak:device:019f0000-0000-7000-8000-000000000001", 1),
            "ak:device:019f0000-0000-7000-8000-000000000001",
            &key,
        )
        .unwrap();
        let operation = first.did_operation.clone();
        let mut renewed = handoff("ak:device:019f0000-0000-7000-8000-000000000002", 2);
        renewed.reserved_identity = Some(
            serde_json::to_value(
                arkret_sdk::ReservedIdentityCreation::from_operation(operation).unwrap(),
            )
            .unwrap(),
        );

        let recovered = recover_registration_checkpoint_from_reservation(&renewed, &key).unwrap();

        assert_eq!(recovered.did, first.did);
        assert_eq!(recovered.did_operation, first.did_operation);
        assert_eq!(recovered.lease_fence, 2);
        assert_eq!(recovered.device_id, renewed.device_id);
        assert!(recovered.pcr_genesis_unit.is_none());
    }

    #[test]
    fn replacement_device_rejects_wrong_recovery_key() {
        let key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let first = prepare_registration_checkpoint(
            &handoff("ak:device:019f0000-0000-7000-8000-000000000001", 1),
            "ak:device:019f0000-0000-7000-8000-000000000001",
            &key,
        )
        .unwrap();
        let operation = first.did_operation;
        let mut renewed = handoff("ak:device:019f0000-0000-7000-8000-000000000002", 2);
        renewed.reserved_identity = Some(
            serde_json::to_value(
                arkret_sdk::ReservedIdentityCreation::from_operation(operation).unwrap(),
            )
            .unwrap(),
        );
        let wrong = crate::recovery_crypto::generate_recovery_key().unwrap();

        assert!(recover_registration_checkpoint_from_reservation(&renewed, &wrong).is_err());
    }
}
