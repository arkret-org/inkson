//! Durable, client-authored identity creation with atomic PCR genesis.

use std::time::Duration;

use anyhow::{Context as _, anyhow};
use arkret_sdk::EventPayloadExt as _;
use chrono::{DateTime, Timelike as _, Utc};
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
    let endpoint =
        Url::parse(&handoff.station_url).context("Station URL cannot drive did:webvh inception")?;
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
            provider_endpoint: &endpoint,
            principal_endpoint: &endpoint,
            local_id: &local_id,
            also_known_as: &[],
            version_time: created_at,
            root_seed: &key_material.root_seed,
            next_root_public_key_multibase: &key_material.next_root_public_key_multikey,
            witness_policy: None,
        },
    )?;
    let genesis_hlc = crate::signing_stamp::issue_realm_genesis_hlc_with_secret(
        &draft.did,
        device_id.trim(),
        &key_material.root_seed,
    )?
    .to_string();
    Ok(PendingPrincipalRegistration {
        station_url: handoff.station_url.clone(),
        gate_account_base_url: handoff.gate_account_base_url.clone(),
        handoff_request_id: handoff.request_id.clone(),
        account_handle: handoff.account_handle.clone(),
        account_subject: handoff.account_subject.clone(),
        lease_id,
        lease_fence,
        device_id: device_id.trim().to_owned(),
        trust_domain: handoff.trust_domain.clone(),
        did: arkret_sdk::Did::new(draft.did)?,
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
        did_operation: draft.submit_body,
        pcr_genesis_unit: None,
        initial_session: None,
        pcr_genesis_receipt: None,
        pcr_bootstrap_seal: None,
        genesis_created_at: arkret_sdk::canonical::format_timestamp_canonical(created_at),
        genesis_hlc,
        genesis_salt: arkret_sdk::GenesisSalt::generate()?.into_string(),
        binding_receipt: None,
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
    let reserved = handoff
        .reserved_identity
        .clone()
        .context("renewed identity-creation lease omits the reserved DID operation")?;
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
    if validated.next_root_key_hash != key_material.next_root_key_hash {
        anyhow::bail!("Recovery Key does not match the reserved root pre-rotation chain");
    }
    let genesis_hlc = crate::signing_stamp::issue_realm_genesis_hlc_with_secret(
        reserved.did.as_str(),
        handoff.device_id.trim(),
        &key_material.root_seed,
    )?
    .to_string();
    Ok(PendingPrincipalRegistration {
        station_url: handoff.station_url.clone(),
        gate_account_base_url: handoff.gate_account_base_url.clone(),
        handoff_request_id: handoff.request_id.clone(),
        account_handle: handoff.account_handle.clone(),
        account_subject: handoff.account_subject.clone(),
        lease_id,
        lease_fence,
        device_id: handoff.device_id.trim().to_owned(),
        trust_domain: handoff.trust_domain.clone(),
        did: reserved.did,
        version_id: validated.did_version_id,
        identity_abandonment: None,
        root_public_key_multibase: key_material.root_public_key_multikey.clone(),
        root_verification_method: validated.root_verification_method.to_string(),
        next_root_public_key_multibase: key_material.next_root_public_key_multikey.clone(),
        next_root_key_hash: validated.next_root_key_hash,
        recovery_proof_public_key_multibase: key_material
            .recovery_proof_public_key_multikey
            .clone(),
        backup_hpke_public_key_multibase: key_material.backup_hpke_public_key_multikey.clone(),
        recovery_key_fingerprint: crate::recovery_crypto::fingerprint_recovery_key(recovery_key),
        did_operation: reserved.did_operation,
        pcr_genesis_unit: None,
        initial_session: None,
        pcr_genesis_receipt: None,
        pcr_bootstrap_seal: None,
        genesis_created_at: arkret_sdk::canonical::format_timestamp_canonical(
            validated.did_version_time,
        ),
        genesis_hlc,
        genesis_salt: arkret_sdk::GenesisSalt::generate()?.into_string(),
        binding_receipt: None,
        stage: PendingPrincipalRegistrationStage::CustodyConfirmed,
    })
}

/// Prove that a supplied Recovery Key controls the exact DID operation kept in
/// the Account Authority reservation. This performs no mutation and is safe to
/// use while reconstructing the UI after a reload.
pub fn validate_reserved_identity_recovery_key(
    handoff: &PendingAccountHandoff,
    recovery_key: &str,
) -> anyhow::Result<()> {
    let reserved = handoff
        .reserved_identity
        .as_ref()
        .context("account handoff omits its reserved DID operation")?;
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
    if validated.root_public_key_multibase != key_material.root_public_key_multikey
        || validated.next_root_key_hash != key_material.next_root_key_hash
    {
        anyhow::bail!("Recovery Key does not control the reserved identity root");
    }
    Ok(())
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
    let same_context = checkpoint.station_url == handoff.station_url
        && checkpoint.gate_account_base_url == handoff.gate_account_base_url
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
    arkret_sdk::ReservedIdentityCreation::from_operation(checkpoint.did_operation.clone())
        .is_ok_and(|expected| expected == *reserved_identity)
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
            || descriptor.device_public_key_did.as_str() != device_public_key
            || descriptor.hpke_key.as_str() != hpke_key
        {
            anyhow::bail!(
                "persisted genesis draft belongs to different DPoP or device key material"
            );
        }
        return Ok(checkpoint.clone());
    }

    let principal_did = checkpoint.did.clone();
    let created_at = chrono::DateTime::parse_from_rfc3339(&checkpoint.genesis_created_at)
        .context("persisted genesis creation time is invalid")?
        .with_timezone(&Utc);
    let validated_inception =
        arkret_sdk::signatures::webvh::validate_principal_inception_operation(
            &checkpoint.did_operation,
        )
        .map_err(|error| anyhow!("persisted DID inception operation is invalid: {error}"))?;
    if validated_inception.did_version_id != checkpoint.version_id {
        anyhow::bail!("persisted DID inception version does not match its checkpoint");
    }
    let unit = crate::identity::principal_genesis::build_genesis_unit(
        principal_did,
        audience.clone(),
        arkret_sdk::GenesisSalt::new(checkpoint.genesis_salt.clone())?,
        arkret_sdk::TrustDomainId::new(checkpoint.trust_domain.clone())?,
        checkpoint.version_id.clone(),
        validated_inception.log_head_digest.to_string(),
        created_at,
        arkret_sdk::Hlc::new(checkpoint.genesis_hlc.clone())?,
        &key_material.root_seed,
        &checkpoint.root_public_key_multibase,
        arkret_sdk::DeviceId::new(checkpoint.device_id.clone())?,
        device_public_key,
        hpke_key,
        device_signer,
    )?;
    let initial = arkret_sdk::InitialSessionGrantIntent {
        device_id: arkret_sdk::DeviceId::new(checkpoint.device_id.clone())?,
        session_public_key: dpop.canonical_session_public_jwk()?,
        audience_id: audience,
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

pub async fn complete_account_handoff_binding(
    handoff: &PendingAccountHandoff,
    checkpoint: &PendingPrincipalRegistration,
    recovery_key: &str,
    dpop: &crate::identity::account_auth::grant_dpop::DpopHandle,
    state_store: &crate::runtime::input::StateStoreHandle,
    mut on_challenge_rate_limit: impl FnMut(Duration),
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
    if let Some(bound) = handoff.bound_principal_id.as_ref()
        && arkret_sdk::project_did_to_core_id(&checkpoint.did)
            .ok()
            .as_ref()
            != Some(bound)
    {
        anyhow::bail!("bound account principal does not match the frozen registration draft");
    }
    let account_handoff_grant = crate::identity::account_auth::load_account_handoff_grant(handoff)?
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
    let account_base = crate::identity::session_refresh::sdk_base_url_from_gate_account_base_url(
        &handoff.gate_account_base_url,
    )?;
    let account_client = arkret_sdk::http_client::ClientBuilder::new(account_base)
        .allow_insecure_localhost()
        .auth(arkret_sdk::http_client::Auth::Dpop(
            dpop.sdk_account_handoff_auth(account_handoff_grant),
        ))
        .build()?;
    let expected_principal_id = arkret_sdk::project_did_to_core_id(&checkpoint.did)?;
    let prepared =
        crate::identity::account_auth::load_prepared_identity_creation_request(handoff, checkpoint)
            .await?;
    #[cfg(debug_assertions)]
    tracing::warn!(
        prepared_request_found = prepared.is_some(),
        checkpoint_stage = ?checkpoint.stage,
        server_account_bound = handoff.bound_principal_id.is_some(),
        lease_fence = checkpoint.lease_fence,
        checkpoint_did = %checkpoint.did,
        storage_principal_id = %expected_principal_id,
        "identity registration continuation state classified"
    );
    let mut replaying_prepared_request = false;
    let mut lease = None::<arkret_sdk::IdentityCreationLease>;
    let mut challenge_retry_deadline = None::<DateTime<Utc>>;

    let register_request = if let Some(prepared) = prepared {
        prepared.validate()?;
        let registration = prepared
            .identity_creation
            .as_ref()
            .context("prepared registration omits identity creation")?;
        if prepared.principal_id != expected_principal_id
            || registration.identity_creation_lease_id != checkpoint.lease_id
            || registration.lease_fence != checkpoint.lease_fence
            || registration.pcr_genesis_unit != unit
            || registration.initial_session != initial
        {
            anyhow::bail!("prepared identity creation request belongs to another lease or draft");
        }
        persist_register_request_prepared_checkpoint(checkpoint, state_store).await?;
        replaying_prepared_request = true;
        if handoff.bound_principal_id.is_none() {
            let current_lease = arkret_sdk::IdentityCreationLease {
                identity_creation_lease_id: checkpoint.lease_id.clone(),
                fence: checkpoint.lease_fence,
                state: handoff
                    .identity_creation_state
                    .context("account handoff omits the server identity-creation state")?,
                expires_at: handoff
                    .lease_expires_at
                    .ok_or_else(|| anyhow!("identity-creation lease expiry is unavailable"))?,
                reserved_identity: handoff.reserved_identity.clone(),
            };
            challenge_retry_deadline =
                Some(std::cmp::min(handoff.expires_at, current_lease.expires_at));
            lease = Some(current_lease);
        }
        prepared
    } else {
        let current_lease = arkret_sdk::IdentityCreationLease {
            identity_creation_lease_id: checkpoint.lease_id.clone(),
            fence: checkpoint.lease_fence,
            state: handoff
                .identity_creation_state
                .context("account handoff omits the server identity-creation state")?,
            expires_at: handoff
                .lease_expires_at
                .ok_or_else(|| anyhow!("identity-creation lease expiry is unavailable"))?,
            reserved_identity: handoff.reserved_identity.clone(),
        };
        let retry_deadline = std::cmp::min(handoff.expires_at, current_lease.expires_at);
        let challenge_request = garth::identity_binding_challenge_request(
            arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms()),
            &current_lease,
            did_operation.clone(),
            &unit,
            &initial,
        )?;
        let challenge = issue_identity_binding_challenge_with_retry(
            &account_client,
            &challenge_request,
            retry_deadline,
            &mut on_challenge_rate_limit,
        )
        .await?;
        let request = garth::identity_creation_register_request(
            &challenge,
            expected_account_subject,
            did_operation,
            unit.clone(),
            initial.clone(),
            &key_material.root_seed,
            None,
        )?;
        crate::identity::account_auth::persist_prepared_identity_creation_request(
            handoff, &request,
        )
        .await?;
        persist_register_request_prepared_checkpoint(checkpoint, state_store).await?;
        challenge_retry_deadline = Some(retry_deadline);
        lease = Some(current_lease);
        request
    };
    let (register_request, register_outcome) = match account_client
        .account_register(&register_request)
        .await
    {
        Ok(outcome) => (register_request, outcome),
        Err(error) => {
            let error = anyhow::Error::new(error);
            if !crate::api_error::is_identity_creation_challenge_expired_error(&error) {
                return Err(error);
            }
            if replaying_prepared_request && handoff.bound_principal_id.is_some() {
                return Err(error.context(
                    "Account Authority did not replay the already-bound canonical registration outcome",
                ));
            }
            // A challenge is the sole ephemeral field in the prepared
            // request. Keep the lease, DID operation, genesis unit and
            // user-confirmed Recovery Key; replace only this terminal
            // server-authored challenge, and retry once.
            crate::identity::account_auth::clear_prepared_identity_creation_request_for_checkpoint(
                checkpoint,
            )?;
            let lease = lease
                .as_ref()
                .context("identity-creation lease is unavailable for challenge renewal")?;
            let challenge_retry_deadline = challenge_retry_deadline
                .context("identity-creation retry deadline is unavailable")?;
            let renewed_challenge_request = garth::identity_binding_challenge_request(
                arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms()),
                lease,
                checkpoint.did_operation.clone(),
                &unit,
                &initial,
            )?;
            let challenge = issue_identity_binding_challenge_with_retry(
                &account_client,
                &renewed_challenge_request,
                challenge_retry_deadline,
                &mut on_challenge_rate_limit,
            )
            .await?;
            let request = garth::identity_creation_register_request(
                &challenge,
                expected_account_subject,
                checkpoint.did_operation.clone(),
                unit.clone(),
                initial.clone(),
                &key_material.root_seed,
                None,
            )?;
            crate::identity::account_auth::persist_prepared_identity_creation_request(
                handoff, &request,
            )
            .await?;
            persist_register_request_prepared_checkpoint(checkpoint, state_store).await?;
            let outcome = account_client.account_register(&request).await?;
            (request, outcome)
        }
    };
    garth::validate_identity_creation_outcome(&register_outcome, &register_request)?;
    let binding_receipt = register_outcome.binding_receipt.clone();
    if &binding_receipt.account_subject != expected_account_subject
        || binding_receipt.principal_id != expected_principal_id
    {
        anyhow::bail!("Account Authority binding receipt does not match the frozen account or DID");
    }
    let pcr_genesis_receipt = register_outcome
        .pcr_genesis_receipt
        .clone()
        .context("Account Authority omitted PCR genesis receipt")?;

    // Preserve the exact response with the frozen request before installing
    // the session, so a restart resumes the same registration terminal.
    {
        let mut durable = register_request_prepared_checkpoint(checkpoint)?;
        durable.binding_receipt = Some(binding_receipt.clone());
        durable.pcr_genesis_receipt = Some(pcr_genesis_receipt.clone());
        let barrier = state_store.write(|store| {
            store.set_pending_principal_registration(Some(durable))?;
            store.begin_durable_flush()
        })?;
        barrier.wait().await?;
    }

    check_registration_result_binding(checkpoint, &register_request, &binding_receipt)?;
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

fn register_request_prepared_checkpoint(
    checkpoint: &PendingPrincipalRegistration,
) -> anyhow::Result<PendingPrincipalRegistration> {
    let mut prepared = checkpoint.clone();
    match prepared.stage {
        PendingPrincipalRegistrationStage::GenesisDraftPrepared => prepared
            .advance_registration_stage(PendingPrincipalRegistrationStage::RegisterRequestPrepared)
            .map_err(anyhow::Error::msg)?,
        PendingPrincipalRegistrationStage::RegisterRequestPrepared => {}
        _ => anyhow::bail!(
            "identity registration checkpoint is not ready to persist a register request"
        ),
    }
    Ok(prepared)
}

async fn persist_register_request_prepared_checkpoint(
    checkpoint: &PendingPrincipalRegistration,
    state_store: &crate::runtime::input::StateStoreHandle,
) -> anyhow::Result<()> {
    let prepared = register_request_prepared_checkpoint(checkpoint)?;
    let barrier = state_store.write(|store| {
        store.set_pending_principal_registration(Some(prepared))?;
        store.begin_durable_flush()
    })?;
    barrier.wait().await
}

const IDENTITY_BINDING_CHALLENGE_RETRY_GUARD: Duration = Duration::from_millis(250);
const IDENTITY_BINDING_CHALLENGE_DEADLINE_GUARD: Duration = Duration::from_secs(1);

async fn issue_identity_binding_challenge_with_retry(
    account_client: &arkret_sdk::http_client::Client,
    request: &arkret_sdk::IdentityBindingChallengeRequestBody,
    retry_deadline: DateTime<Utc>,
    on_rate_limit: &mut impl FnMut(Duration),
) -> anyhow::Result<arkret_sdk::IdentityBindingChallengeOutcome> {
    let started_at = Utc::now();
    let retry_window_deadline = started_at
        + chrono::Duration::from_std(arkret_retry::SPEC_RETRY_WINDOW)
            .unwrap_or_else(|_| chrono::Duration::minutes(5));
    let retry_deadline = std::cmp::min(retry_deadline, retry_window_deadline);
    let mut schedule = arkret_retry::RetrySchedule::arkret_default().with_jitter(
        arkret_retry::SPEC_JITTER_RATIO,
        retry_jitter_seed(&request.request_id),
    );

    loop {
        match account_client
            .auth_issue_identity_binding_challenge(request)
            .await
        {
            Ok(challenge) => return Ok(challenge),
            Err(error) => {
                let error = anyhow::Error::new(error);
                if schedule.exhausted() {
                    return Err(error);
                }
                let Some(retry_after_ms) = crate::api_error::rate_limited_retry_after(&error)
                else {
                    return Err(error);
                };
                let advertised_delay =
                    (retry_after_ms > 0).then(|| Duration::from_millis(retry_after_ms));
                let delay = schedule
                    .next_delay_with_hint(advertised_delay)
                    .saturating_add(IDENTITY_BINDING_CHALLENGE_RETRY_GUARD);
                let Some(delay) = bounded_identity_binding_challenge_retry_delay(
                    delay,
                    Utc::now(),
                    retry_deadline,
                ) else {
                    return Err(error);
                };
                tracing::info!(
                    retry_after_ms = delay.as_millis(),
                    retry = schedule.retries(),
                    request_id = %request.request_id,
                    "identity-binding challenge was rate limited; waiting before exact retry"
                );
                on_rate_limit(delay);
                crate::runtime_helpers::sleep_for(delay).await;
            }
        }
    }
}

fn retry_jitter_seed(request_id: &arkret_sdk::RequestId) -> u64 {
    request_id
        .to_string()
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            hash.wrapping_mul(0x0000_0100_0000_01b3) ^ u64::from(byte)
        })
}

fn bounded_identity_binding_challenge_retry_delay(
    delay: Duration,
    now: DateTime<Utc>,
    retry_deadline: DateTime<Utc>,
) -> Option<Duration> {
    let usable_for = (retry_deadline - now).to_std().ok()?;
    (delay.saturating_add(IDENTITY_BINDING_CHALLENGE_DEADLINE_GUARD) < usable_for).then_some(delay)
}

fn check_registration_result_binding(
    checkpoint: &PendingPrincipalRegistration,
    request: &arkret_sdk::AccountRegisterRequestBody,
    receipt: &arkret_sdk::AccountBindingReceipt,
) -> anyhow::Result<()> {
    receipt.validate_shape()?;
    let did_operation = &checkpoint.did_operation;
    let validated =
        arkret_sdk::signatures::webvh::validate_principal_inception_operation(did_operation)
            .map_err(|error| anyhow!("validate frozen principal inception: {error}"))?;
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
        anyhow::bail!("registration result does not match the frozen inception pins");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_binding_challenge_retry_obeys_server_window_and_deadline_guards() {
        let now = DateTime::parse_from_rfc3339("2026-08-17T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let deadline = now + chrono::Duration::minutes(15);

        assert_eq!(
            bounded_identity_binding_challenge_retry_delay(
                Duration::from_millis(59_978),
                now,
                deadline,
            ),
            Some(Duration::from_millis(59_978))
        );
    }

    #[test]
    fn identity_binding_challenge_retry_does_not_outlive_lease_or_handoff() {
        let now = DateTime::parse_from_rfc3339("2026-08-17T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        assert_eq!(
            bounded_identity_binding_challenge_retry_delay(
                Duration::from_millis(59_978),
                now,
                now + chrono::Duration::seconds(60),
            ),
            None
        );
    }

    #[test]
    fn identity_binding_challenge_retry_uses_the_shared_bounded_schedule() {
        let mut schedule = arkret_retry::RetrySchedule::arkret_default()
            .with_jitter(0.0, retry_jitter_seed(&arkret_sdk::RequestId::new_v7_at(0)));

        assert_eq!(schedule.next_delay(), Duration::from_secs(1));
        assert_eq!(schedule.next_delay(), Duration::from_secs(2));
        assert_eq!(
            schedule.next_delay_with_hint(Some(Duration::from_secs(60))),
            Duration::from_secs(60)
        );
        assert!(!schedule.exhausted());
        schedule.next_delay();
        schedule.next_delay();
        assert!(schedule.exhausted());
    }

    #[test]
    fn prepared_register_request_advances_checkpoint_before_submission() {
        let key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let handoff = handoff("ak:device:019f0000-0000-7000-8000-000000000001", 1);
        let mut checkpoint = prepare_registration_checkpoint(
            &handoff,
            "ak:device:019f0000-0000-7000-8000-000000000001",
            &key,
        )
        .unwrap();
        checkpoint
            .advance_registration_stage(PendingPrincipalRegistrationStage::GenesisDraftPrepared)
            .unwrap();

        let prepared = register_request_prepared_checkpoint(&checkpoint).unwrap();

        assert_eq!(
            prepared.stage,
            PendingPrincipalRegistrationStage::RegisterRequestPrepared
        );
        assert_eq!(
            register_request_prepared_checkpoint(&prepared)
                .unwrap()
                .stage,
            PendingPrincipalRegistrationStage::RegisterRequestPrepared
        );
    }

    fn handoff(device_id: &str, fence: u64) -> PendingAccountHandoff {
        PendingAccountHandoff {
            station_url: "https://principal.example".to_owned(),
            gate_account_base_url: "https://account.example/_arkret/gate/account".to_owned(),
            request_id: "ak:request:019f0000-0000-7000-8000-000000000001".to_owned(),
            oidc_state: None,
            account_handle: "alice:example.com".to_owned(),
            account_subject: Some(
                arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            ),
            holder_jkt: "holder-jkt".to_owned(),
            audience_id: arkret_sdk::DidCoreId::new(
                "ak:did_core:webvh:z6mkfixture:principal.example",
            )
            .unwrap(),
            expires_at: Utc::now() + chrono::Duration::minutes(15),
            lease_id: Some("lease-1".to_owned()),
            lease_fence: Some(fence),
            lease_expires_at: Some(Utc::now() + chrono::Duration::minutes(15)),
            identity_creation_state: Some(arkret_sdk::IdentityCreationLeaseState::Active),
            reserved_identity: None,
            identity_abandonment: None,
            retry_after_ms: None,
            device_id: device_id.to_owned(),
            trust_domain: "ak:trust_domain:principal.example".to_owned(),
            bound_principal_id: None,
            bound_principal_did: None,
            bound_device_entry_state: None,
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
        renewed.reserved_identity =
            Some(arkret_sdk::ReservedIdentityCreation::from_operation(operation).unwrap());

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
        renewed.reserved_identity =
            Some(arkret_sdk::ReservedIdentityCreation::from_operation(operation).unwrap());
        let wrong = crate::recovery_crypto::generate_recovery_key().unwrap();

        assert!(recover_registration_checkpoint_from_reservation(&renewed, &wrong).is_err());
    }
}
