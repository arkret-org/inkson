//! Client-authored principal registration and resumable bootstrap checkpoint.

use anyhow::{Context as _, anyhow};
use chrono::{Timelike as _, Utc};
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
            enrollment: arkret_sdk::webvh::PrincipalEnrollmentDelegation::ExternalAuthority {
                authority_did: &handoff.enrollment_authority_did,
            },
        },
    )?;
    let draft_actor = arkret_sdk::Did::new(draft.did.clone())?;
    let draft_realm = arkret_sdk::principal_control_realm_id(&draft_actor);
    let bootstrap_hlc = crate::signing_stamp::issue_protocol_hlc_with_secret(
        draft_actor.as_str(),
        device_id.trim(),
        &draft_realm,
        &key_material.root_seed,
    )?
    .to_string();
    let mut checkpoint = PendingPrincipalRegistration {
        principal_server_url: handoff.principal_server_url.clone(),
        gate_account_base: handoff.gate_account_base.clone(),
        handoff_request_id: handoff.request_id.clone(),
        account_handle: handoff.account_handle.clone(),
        lease_id,
        lease_fence,
        device_id: device_id.trim().to_owned(),
        enrollment_authority_did: handoff.enrollment_authority_did.clone(),
        trust_domain: handoff.trust_domain.clone(),
        did: draft.did,
        version_id: draft.version_id,
        root_public_key_multibase: draft.root_public_key_multibase,
        root_verification_method: draft.root_verification_method,
        next_root_public_key_multibase: draft.next_root_public_key_multibase,
        next_root_key_hash: draft.next_root_key_hash,
        recovery_proof_public_key_multibase: key_material
            .recovery_proof_public_key_multikey
            .clone(),
        backup_hpke_public_key_multibase: key_material.backup_hpke_public_key_multikey.clone(),
        recovery_key_fingerprint: crate::recovery_crypto::fingerprint_recovery_key(recovery_key),
        did_operation: serde_json::to_value(draft.submit_body)?,
        bootstrap_create_event: None,
        bootstrap_authorize_event_preimage: None,
        founding_event_ids: Vec::new(),
        founding_batch_digest: None,
        device_enroll_outcome: None,
        bootstrap_created_at: arkret_sdk::canonical::format_timestamp_canonical(created_at),
        bootstrap_hlc,
        binding_receipt: None,
        stage: PendingPrincipalRegistrationStage::CustodyConfirmed,
    };
    let create = build_bootstrap_create_event(&checkpoint, &key_material)?;
    checkpoint.bootstrap_create_event = Some(serde_json::to_value(create)?);
    Ok(checkpoint)
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

/// Whether a persisted identity draft can safely follow this Account
/// Authority handoff. A request-id match is exact continuity. A renewed
/// request must carry the exact server-side identity reservation.
///
/// An account handle is deliberately NOT accepted as continuity on its own.
/// A handle is re-registrable: delete the account, or reset the Account
/// Authority's store, and the same handle comes back as a different identity.
/// Treating it as proof handed the *next* registration of a familiar handle the
/// previous one's abandoned draft — the user was asked for 24 words belonging to
/// a DID the server no longer has, with no way forward. The server's own
/// reservation is the only thing that can say "this draft is still the identity
/// I am holding for you".
pub fn checkpoint_belongs_to_handoff(
    checkpoint: &PendingPrincipalRegistration,
    handoff: &PendingAccountHandoff,
) -> bool {
    let same_context = checkpoint.principal_server_url == handoff.principal_server_url
        && checkpoint.gate_account_base == handoff.gate_account_base
        && checkpoint.device_id == handoff.device_id
        && checkpoint.enrollment_authority_did == handoff.enrollment_authority_did
        && checkpoint.trust_domain == handoff.trust_domain;
    if !same_context {
        return false;
    }
    if checkpoint.handoff_request_id == handoff.request_id {
        return true;
    }
    // A renewed lease carries forward whatever identity the server reserved. No
    // reservation means the server is holding nothing for this account, so any
    // local draft under a different request id is an orphan from an earlier
    // attempt, whatever handle it was created under.
    let Some(reserved_identity) = handoff.reserved_identity.as_ref() else {
        return false;
    };
    // The handle still has to agree when it is known: the reservation proves
    // *which identity*, the handle proves *whose account* it was reserved for.
    if !checkpoint.account_handle.trim().is_empty()
        && checkpoint.account_handle != handoff.account_handle
    {
        return false;
    }
    let Ok(reserved_identity) =
        serde_json::from_value::<arkret_sdk::ReservedIdentityCreation>(reserved_identity.clone())
    else {
        return false;
    };
    let Ok(did_operation) = serde_json::from_value::<arkret_sdk::DidOperationSubmitRequestBody>(
        checkpoint.did_operation.clone(),
    ) else {
        return false;
    };
    arkret_sdk::ReservedIdentityCreation::from_operation(did_operation)
        .is_ok_and(|expected| expected == reserved_identity)
}

pub struct IdentityBindingCompletion {
    pub binding_receipt: arkret_sdk::AccountBindingReceipt,
    pub session_grant: garth::SessionGrantState,
    pub session_private_key_pem: String,
    pub dpop_device_key: crate::state::DpopDeviceKeyRecord,
}

async fn prepare_exact_bootstrap_session_request(
    handoff: &PendingAccountHandoff,
    checkpoint: &PendingPrincipalRegistration,
    account_handoff_grant: &str,
    dpop: &crate::identity::account_auth::grant_dpop::DpopHandle,
) -> anyhow::Result<arkret_sdk::SessionGrantRequestBody> {
    let principal_id = arkret_sdk::Did::new(checkpoint.did.clone())?;
    let device_id = arkret_sdk::DeviceId::new(checkpoint.device_id.clone())?;
    let audience = arkret_sdk::Did::new(handoff.audience.clone())?;
    let bootstrap = device_bootstrap_request_from_checkpoint(checkpoint)?;
    if let Some(prepared) =
        crate::identity::account_auth::load_prepared_bootstrap_session_request()?
    {
        prepared.validate()?;
        if prepared.principal_id != principal_id
            || prepared.device_id.as_ref() != Some(&device_id)
            || prepared.proof.audience != audience
            || prepared.proof.challenge != account_handoff_grant
            || prepared.device_bootstrap_request.as_ref() != Some(&bootstrap)
        {
            anyhow::bail!("secure prepared bootstrap request does not match public checkpoint");
        }
        return Ok(prepared);
    }
    let request = garth::pre_registration_session_grant_request(
        principal_id,
        device_id,
        Vec::new(),
        bootstrap,
        account_handoff_grant,
        audience,
        Utc::now() + chrono::Duration::minutes(5),
        |bytes| {
            dpop.sign_protocol_bytes(bytes)
                .map_err(|error| garth::Error::Protocol(error.to_string()))
        },
    )?;
    crate::identity::account_auth::persist_prepared_bootstrap_session_request(&request).await?;
    Ok(request)
}

pub async fn complete_account_handoff_binding(
    handoff: &PendingAccountHandoff,
    checkpoint: &PendingPrincipalRegistration,
    recovery_key: &str,
    dpop: &crate::identity::account_auth::grant_dpop::DpopHandle,
) -> anyhow::Result<IdentityBindingCompletion> {
    if handoff.expires_at <= Utc::now() {
        anyhow::bail!("account handoff expired; authenticate the account again");
    }
    if handoff.holder_jkt != dpop.jkt() {
        anyhow::bail!("account handoff holder key does not match the current DPoP key");
    }
    let account_handoff_grant = crate::identity::account_auth::load_account_handoff_grant()?
        .ok_or_else(|| anyhow!("account handoff credential is unavailable; authenticate again"))?;
    let session_request =
        prepare_exact_bootstrap_session_request(handoff, checkpoint, &account_handoff_grant, dpop)
            .await?;
    let key_material = validate_checkpoint_recovery_key(checkpoint, recovery_key)?;
    let did_operation: arkret_sdk::DidOperationSubmitRequestBody =
        serde_json::from_value(checkpoint.did_operation.clone())
            .context("persisted DID operation is invalid")?;
    let lease = arkret_sdk::IdentityCreationLease {
        lease_id: checkpoint.lease_id.clone(),
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
    )?;
    let account_base = crate::identity::session_refresh::sdk_base_url_from_gate_account_base(
        &handoff.gate_account_base,
    )?;
    let account_client = arkret_sdk::http_client::ClientBuilder::new(account_base)
        .allow_insecure_localhost()
        .auth(arkret_sdk::http_client::Auth::Dpop(
            dpop.sdk_account_handoff_auth(account_handoff_grant.clone()),
        ))
        .build()?;
    let challenge = account_client
        .auth_issue_identity_binding_challenge(&challenge_request)
        .await?;
    let register_request = garth::identity_creation_register_request(
        &challenge,
        did_operation,
        &key_material.root_seed,
        None,
    )?;
    let register_outcome = account_client.account_register(&register_request).await?;
    let binding_receipt = register_outcome
        .binding_receipt
        .ok_or_else(|| anyhow!("Account Authority omitted identity-creation binding receipt"))?;
    garth::validate_binding_receipt(&binding_receipt, &challenge)?;
    if register_outcome.principal_id != session_request.principal_id {
        anyhow::bail!("identity registration outcome changed the prepared principal identity");
    }
    let session_engine = garth::SessionEngine::new(account_client);
    session_engine
        .login(
            garth::LoginKind::PreRegistrationHandoff(Box::new(
                garth::PreRegistrationHandoffLogin {
                    request: session_request,
                },
            )),
            Utc::now(),
        )
        .await?;
    let session_grant = session_engine
        .current_state()
        .ok_or_else(|| anyhow!("Account Authority did not return session state"))?;
    let session_private_key_pem = dpop.session_signing_key_pkcs8_pem()?.to_string();
    let dpop_device_key =
        crate::identity::account_auth::grant_dpop::dpop_device_key_record_from_seed(
            dpop.seed_b64().as_str(),
        )?;
    Ok(IdentityBindingCompletion {
        binding_receipt,
        session_grant,
        session_private_key_pem,
        dpop_device_key,
    })
}

fn build_bootstrap_create_event_with_registry(
    checkpoint: &PendingPrincipalRegistration,
    key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
    capability_action_registry_digest: arkret_sdk::Hash,
) -> anyhow::Result<arkret_sdk::Event> {
    let principal_id = arkret_sdk::Did::new(checkpoint.did.clone())?;
    let realm_id = arkret_sdk::RealmId::new(arkret_sdk::principal_control_realm_id(&principal_id))?;
    let created_at = chrono::DateTime::parse_from_rfc3339(&checkpoint.bootstrap_created_at)
        .context("persisted bootstrap_created_at is invalid")?
        .with_timezone(&Utc);
    let mut create = arkret_bootstrap::build_self_principal_pcr_create(
        arkret_bootstrap::SelfPrincipalPcrCreateInput {
            principal_id,
            realm_id,
            trust_domain: arkret_sdk::TypedTrustDomainId::new(checkpoint.trust_domain.clone())?,
            did_inception_ref: arkret_sdk::EventRef::new(
                checkpoint.version_id.clone(),
                arkret_bootstrap::DID_INCEPTION_REF_ROLE,
            ),
            capability_action_registry_digest,
            created_at,
            hlc: arkret_sdk::Hlc::new(checkpoint.bootstrap_hlc.clone())?,
        },
        &crate::operation::cell_write_projector,
    )?;
    let root_did =
        arkret_sdk::Did::new(format!("did:key:{}", checkpoint.root_public_key_multibase))?;
    let root_verification_method =
        arkret_sdk::DidUrl::new(checkpoint.root_verification_method.clone())
            .map_err(anyhow::Error::msg)?;
    let root_signer = arkret_sdk::Ed25519PayloadSigner::from_did_key_seed(
        key_material.root_seed,
        root_did,
        root_verification_method.clone(),
    );
    let digest_suite = serde_json::from_value::<arkret_sdk::RealmCreatePayload>(
        serde_json::to_value(&create.payload)?,
    )
    .context("decode Principal Control Realm genesis digest suite")?
    .object
    .digest_algorithm;
    arkret_sdk::signatures::sign_event_with_digest_suite(
        &mut create,
        &root_signer,
        &root_verification_method,
        digest_suite,
        arkret_sdk::signatures::SignEventOptions::new().with_created_at(created_at),
    )?;
    Ok(create)
}

fn build_bootstrap_create_event(
    checkpoint: &PendingPrincipalRegistration,
    key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
) -> anyhow::Result<arkret_sdk::Event> {
    let registry_digest = arkret_sdk::current_capability_action_registry_digest()
        .map_err(|error| anyhow::anyhow!("load capability action registry digest: {error}"))?;
    build_bootstrap_create_event_with_registry(checkpoint, key_material, registry_digest)
}

fn validate_persisted_bootstrap_create_event(
    checkpoint: &PendingPrincipalRegistration,
    key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
    create: &arkret_sdk::Event,
) -> anyhow::Result<()> {
    let create_value = serde_json::to_value(create)?;
    let registry_digest = create_value
        .pointer("/payload/object/capability_action_registry_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("persisted bootstrap create Event has no registry basis"))?;
    let expected = build_bootstrap_create_event_with_registry(
        checkpoint,
        key_material,
        arkret_sdk::Hash::new(registry_digest.to_owned())?,
    )?;
    if crate::canonical::canonical_json_bytes(&expected)?
        != crate::canonical::canonical_json_bytes(create)?
    {
        anyhow::bail!("persisted bootstrap create Event does not match the saved identity draft");
    }
    Ok(())
}

fn load_bootstrap_create_event(
    checkpoint: &PendingPrincipalRegistration,
    key_material: &arkret_sdk::identity_root::IdentityRecoveryKeyMaterial,
) -> anyhow::Result<arkret_sdk::Event> {
    let value = checkpoint
        .bootstrap_create_event
        .as_ref()
        .context("checkpoint is missing its bootstrap create Event")?;
    let create: arkret_sdk::Event = serde_json::from_value(value.clone())
        .context("persisted bootstrap create Event is invalid")?;
    validate_persisted_bootstrap_create_event(checkpoint, key_material, &create)?;
    Ok(create)
}

/// Fix the founding device Event identity before any bootstrap credential is
/// requested. Re-entry returns the already-persisted material after verifying
/// that it still names the same public device keys.
pub fn prepare_device_bootstrap_checkpoint(
    checkpoint: &PendingPrincipalRegistration,
    recovery_key: &str,
    device_public_key: String,
    hpke_key: String,
) -> anyhow::Result<PendingPrincipalRegistration> {
    let key_material = validate_checkpoint_recovery_key(checkpoint, recovery_key)?;
    let create = load_bootstrap_create_event(checkpoint, &key_material)?;
    if checkpoint.bootstrap_authorize_event_preimage.is_some() {
        let request = device_bootstrap_request_from_checkpoint(checkpoint)?;
        let payload = &request.authorize_event_preimage.payload;
        if payload
            .get("device_public_key")
            .and_then(serde_json::Value::as_str)
            != Some(device_public_key.trim())
            || payload.get("hpke_key").and_then(serde_json::Value::as_str) != Some(hpke_key.trim())
        {
            anyhow::bail!("persisted bootstrap Event belongs to different device key material");
        }
        return Ok(checkpoint.clone());
    }

    let principal_id = arkret_sdk::Did::new(checkpoint.did.clone())?;
    let realm_id = arkret_sdk::RealmId::new(arkret_sdk::principal_control_realm_id(&principal_id))?;
    let created_at = chrono::DateTime::parse_from_rfc3339(&checkpoint.bootstrap_created_at)
        .context("persisted bootstrap_created_at is invalid")?
        .with_timezone(&Utc);
    let authorize_hlc = crate::signing_stamp::issue_protocol_hlc_with_secret(
        principal_id.as_str(),
        &checkpoint.device_id,
        realm_id.as_str(),
        &key_material.root_seed,
    )?;
    let enroll_request = crate::identity::device_enrollment::prepare_device_enrollment_request(
        principal_id,
        arkret_sdk::DeviceId::new(checkpoint.device_id.clone())?,
        device_public_key,
        hpke_key,
        create.event_id.clone(),
        realm_id,
        arkret_sdk::Did::new(checkpoint.enrollment_authority_did.clone())?,
        created_at,
        authorize_hlc,
    )?;
    let founding_event_ids = vec![
        create.event_id,
        enroll_request.authorize_event_preimage.event_id.clone(),
    ];
    let founding_batch_digest = arkret_sdk::founding_batch_digest(&founding_event_ids)?;
    let mut prepared = checkpoint.clone();
    prepared.bootstrap_authorize_event_preimage = Some(serde_json::to_value(
        &enroll_request.authorize_event_preimage,
    )?);
    prepared.founding_event_ids = founding_event_ids.iter().map(ToString::to_string).collect();
    prepared.founding_batch_digest = Some(founding_batch_digest.to_string());
    prepared
        .advance_bootstrap_stage(PendingPrincipalRegistrationStage::BootstrapPrepared)
        .map_err(anyhow::Error::msg)?;
    device_bootstrap_request_from_checkpoint(&prepared)?;
    Ok(prepared)
}

pub fn device_bootstrap_request_from_checkpoint(
    checkpoint: &PendingPrincipalRegistration,
) -> anyhow::Result<arkret_sdk::SessionGrantDeviceBootstrapRequest> {
    let authorize_event_preimage = serde_json::from_value(
        checkpoint
            .bootstrap_authorize_event_preimage
            .clone()
            .context("checkpoint is missing device authorize Event preimage")?,
    )
    .context("persisted device authorize Event preimage is invalid")?;
    let founding_event_ids = checkpoint
        .founding_event_ids
        .iter()
        .map(|value| arkret_sdk::EventId::new(value.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let request = arkret_sdk::SessionGrantDeviceBootstrapRequest {
        mode: arkret_sdk::SessionGrantDeviceBootstrapMode::Founding,
        authorize_event_preimage,
        founding_event_ids,
        founding_batch_digest: arkret_sdk::Hash::new(
            checkpoint
                .founding_batch_digest
                .clone()
                .context("checkpoint is missing founding batch digest")?,
        )?,
    };
    request.validate()?;
    Ok(request)
}

/// Execute only the enrollment-authority step and persist its strictly
/// validated public response before attempting the founding batch.
pub async fn enroll_prepared_device(
    checkpoint: &PendingPrincipalRegistration,
    account_client: &arkret_sdk::http_client::Client,
) -> anyhow::Result<PendingPrincipalRegistration> {
    let request = arkret_sdk::AccountDeviceEnrollRequestBody {
        device_id: arkret_sdk::DeviceId::new(checkpoint.device_id.clone())?,
        authorize_event_preimage: device_bootstrap_request_from_checkpoint(checkpoint)?
            .authorize_event_preimage,
    };
    let outcome = crate::identity::device_enrollment::request_signed_device_authorize(
        account_client,
        &request,
    )
    .await?;
    let mut enrolled = checkpoint.clone();
    enrolled.device_enroll_outcome = Some(serde_json::to_value(outcome)?);
    enrolled
        .advance_bootstrap_stage(PendingPrincipalRegistrationStage::DeviceEnrolled)
        .map_err(anyhow::Error::msg)?;
    Ok(enrolled)
}

/// Submit the exact create/authorize pair and its bootstrap seal. The authority
/// response is revalidated against the persisted preimage before every retry.
pub async fn submit_prepared_founding_batch(
    checkpoint: &PendingPrincipalRegistration,
    recovery_key: &str,
    device_signer: &crate::event_signer::InksonEventSigner,
    principal_client: &arkret_sdk::http_client::Client,
) -> anyhow::Result<()> {
    let key_material = validate_checkpoint_recovery_key(checkpoint, recovery_key)?;
    let principal_id = arkret_sdk::Did::new(checkpoint.did.clone())?;
    let realm_id = arkret_sdk::RealmId::new(arkret_sdk::principal_control_realm_id(&principal_id))?;
    let create = load_bootstrap_create_event(checkpoint, &key_material)?;
    let request = arkret_sdk::AccountDeviceEnrollRequestBody {
        device_id: arkret_sdk::DeviceId::new(checkpoint.device_id.clone())?,
        authorize_event_preimage: device_bootstrap_request_from_checkpoint(checkpoint)?
            .authorize_event_preimage,
    };
    let outcome: arkret_sdk::AccountDeviceEnrollOutcome = serde_json::from_value(
        checkpoint
            .device_enroll_outcome
            .clone()
            .context("checkpoint is missing validated device enrollment outcome")?,
    )
    .context("persisted device enrollment outcome is invalid")?;
    outcome.validate_against(&request)?;
    let authorize = outcome.authorized_event;
    let seal_hlc = crate::signing_stamp::issue_protocol_hlc_with_secret(
        principal_id.as_str(),
        &checkpoint.device_id,
        realm_id.as_str(),
        &key_material.root_seed,
    )?;
    let seal = device_signer
        .sign_self_principal_bootstrap_seal(&create, &authorize, seal_hlc)
        .map_err(|error| anyhow!(error.to_string()))?;
    // `EventSealSubmitOutcome.accepted_event_digests` is a set in `Seal.delta`'s
    // normalization (byte-wise ascending, unique), so `seal.delta` is directly
    // comparable. It is *not* reducer apply order, which is causal then
    // digest-descending: comparing against that sequence made this check pass or
    // fail on whether the causal order of the bootstrap pair happened to match
    // ascending digest order.
    let expected_digests = seal.delta.clone();
    // A self-principal genesis has no accepted notary yet. The Principal
    // Server therefore pre-admits the complete ordered pair, issues one
    // anchor-unit authorization lease per Event, and mints the proposal
    // receipts atomically during submit. Sending the pair as plain online
    // submissions skips that pre-admission and is rejected by the server.
    let submissions = principal_client
        .prepare_initial_submissions(&[create, authorize])
        .await?;
    let [create_submission, authorize_submission]: [arkret_wire::EventInitialSubmission; 2] =
        submissions.try_into().map_err(|submissions: Vec<_>| {
            anyhow!(
                "self principal bootstrap preparation returned {} submissions, expected 2",
                submissions.len()
            )
        })?;
    let batch = arkret_bootstrap::self_principal_bootstrap_submit_request(
        create_submission,
        authorize_submission,
        &crate::operation::cell_write_projector,
    )?;
    let arkret_sdk::EventsSubmitRequestBody::Batch(batch) = batch else {
        anyhow::bail!("self principal bootstrap must submit as a batch");
    };
    let response = principal_client.events_submit_batch(&batch.events).await?;
    crate::ephemeral::ensure_events_submit_accepted(&response)?;
    let seal_outcome = principal_client.events_submit_seal(&seal).await?;
    if seal_outcome.seal_id != seal.id
        || seal_outcome.accepted_event_digests != expected_digests
        || seal_outcome.post_state_root != seal.state_root
    {
        anyhow::bail!("Principal Server returned a mismatched bootstrap Seal outcome");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn continuity_handoff(request_id: &str, handle: &str) -> PendingAccountHandoff {
        PendingAccountHandoff {
            principal_server_url: "https://principal.example".to_owned(),
            gate_account_base: "https://auth.example/_arkret/gate/account".to_owned(),
            request_id: request_id.to_owned(),
            account_handle: handle.to_owned(),
            holder_jkt: "holder-jkt".to_owned(),
            audience: "did:webvh:z6mkfixture:principal.example".to_owned(),
            expires_at: Utc::now() + chrono::Duration::minutes(10),
            lease_id: Some("lease-1".to_owned()),
            lease_fence: Some(1),
            lease_expires_at: Some(Utc::now() + chrono::Duration::minutes(15)),
            reserved_identity: None,
            retry_after_ms: None,
            device_id: "ak:device:019f0000-0000-7000-8000-000000000001".to_owned(),
            enrollment_authority_did: "did:key:z6MkrJVnaZkeFzdQyKjzgRHjhBfE6ZscXDFHq8T7TYNy9v1t"
                .to_owned(),
            trust_domain: "ak:trust_domain:test".to_owned(),
        }
    }

    /// A handle is re-registrable. Delete the account or reset the Account
    /// Authority's store and the same handle comes back as a different
    /// identity, so it cannot stand in for the server's reservation.
    #[test]
    fn a_reused_account_handle_is_not_continuity() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let first = continuity_handoff("ak:request:019f0000-0000-7000-8000-000000000010", "alice");
        let abandoned_draft =
            prepare_registration_checkpoint(&first, &first.device_id, &recovery_key).unwrap();

        // Same handle, same device, same deployment — but a brand-new
        // registration: the server reserved nothing, so it is not holding the
        // abandoned draft's identity for anyone.
        let re_registration =
            continuity_handoff("ak:request:019f0000-0000-7000-8000-000000000011", "alice");
        assert!(!re_registration.reserved_identity.is_some());

        assert!(
            !checkpoint_belongs_to_handoff(&abandoned_draft, &re_registration),
            "a re-registered handle must not inherit the previous registration's draft"
        );
    }

    #[test]
    fn a_renewed_lease_keeps_its_own_reserved_draft() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let first = continuity_handoff("ak:request:019f0000-0000-7000-8000-000000000010", "alice");
        let draft =
            prepare_registration_checkpoint(&first, &first.device_id, &recovery_key).unwrap();
        let did_operation: arkret_sdk::DidOperationSubmitRequestBody =
            serde_json::from_value(draft.did_operation.clone()).unwrap();
        let reserved = arkret_sdk::ReservedIdentityCreation::from_operation(did_operation).unwrap();

        let mut renewed =
            continuity_handoff("ak:request:019f0000-0000-7000-8000-000000000011", "alice");
        renewed.reserved_identity = Some(serde_json::to_value(&reserved).unwrap());
        assert!(checkpoint_belongs_to_handoff(&draft, &renewed));

        // The reservation says which identity; the handle says whose account it
        // was reserved for. A different account cannot claim it.
        let mut other_account =
            continuity_handoff("ak:request:019f0000-0000-7000-8000-000000000012", "bob");
        other_account.reserved_identity = Some(serde_json::to_value(&reserved).unwrap());
        assert!(!checkpoint_belongs_to_handoff(&draft, &other_account));
    }

    #[test]
    fn fresh_recovery_custody_produces_a_distinct_principal_did() {
        let handoff = PendingAccountHandoff {
            principal_server_url: "https://principal.example".to_owned(),
            gate_account_base: "https://auth.example/_arkret/gate/account".to_owned(),
            request_id: "ak:request:019f0000-0000-7000-8000-000000000001".to_owned(),
            account_handle: "alice:auth.example".to_owned(),
            holder_jkt: "holder-jkt".to_owned(),
            audience: "did:webvh:z6mkfixture:principal.example".to_owned(),
            expires_at: Utc::now() + chrono::Duration::minutes(10),
            lease_id: Some("lease-1".to_owned()),
            lease_fence: Some(1),
            lease_expires_at: Some(Utc::now() + chrono::Duration::minutes(15)),
            reserved_identity: None,
            retry_after_ms: None,
            device_id: "ak:device:019f0000-0000-7000-8000-000000000001".to_owned(),
            enrollment_authority_did: "did:key:z6MkrJVnaZkeFzdQyKjzgRHjhBfE6ZscXDFHq8T7TYNy9v1t"
                .to_owned(),
            trust_domain: "ak:trust_domain:test".to_owned(),
        };
        let first_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let second_key = crate::recovery_crypto::generate_recovery_key().unwrap();

        let first =
            prepare_registration_checkpoint(&handoff, &handoff.device_id, &first_key).unwrap();
        let second =
            prepare_registration_checkpoint(&handoff, &handoff.device_id, &second_key).unwrap();

        assert_ne!(
            first.recovery_key_fingerprint,
            second.recovery_key_fingerprint
        );
        assert_ne!(
            first.root_public_key_multibase,
            second.root_public_key_multibase
        );
        assert_ne!(first.did, second.did);
    }

    #[test]
    fn persisted_checkpoint_contains_no_recovery_secret_and_requires_the_same_key() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let handoff = PendingAccountHandoff {
            principal_server_url: "https://principal.example".to_owned(),
            gate_account_base: "https://auth.example/_arkret/gate/account".to_owned(),
            request_id: "ak:request:019f0000-0000-7000-8000-000000000000".to_owned(),
            account_handle: "alice:auth.example".to_owned(),
            holder_jkt: "holder-jkt".to_owned(),
            audience: "did:webvh:z6mkfixture:principal.example".to_owned(),
            expires_at: Utc::now() + chrono::Duration::minutes(10),
            lease_id: Some("lease-1".to_owned()),
            lease_fence: Some(1),
            lease_expires_at: Some(Utc::now() + chrono::Duration::minutes(15)),
            reserved_identity: None,
            retry_after_ms: None,
            device_id: "ak:device:019f0000-0000-7000-8000-000000000001".to_owned(),
            enrollment_authority_did: "did:key:z6MkrJVnaZkeFzdQyKjzgRHjhBfE6ZscXDFHq8T7TYNy9v1t"
                .to_owned(),
            trust_domain: "ak:trust_domain:test".to_owned(),
        };
        let checkpoint = prepare_registration_checkpoint(
            &handoff,
            "ak:device:019f0000-0000-7000-8000-000000000001",
            &recovery_key,
        )
        .unwrap();

        let persisted = serde_json::to_string(&checkpoint).unwrap();
        let encoded_recovery_key = serde_json::to_string(&recovery_key).unwrap();
        assert!(!persisted.contains(&encoded_recovery_key));
        assert!(!persisted.contains("root_seed"));
        assert!(!persisted.contains("recovery_proof_seed"));
        assert!(!persisted.contains("backup_hpke_private"));
        arkret_sdk::canonical::validate_timestamp_canonical(&checkpoint.bootstrap_created_at)
            .unwrap();
        validate_checkpoint_recovery_key(&checkpoint, &recovery_key).unwrap();
        let persisted_create: arkret_sdk::Event = serde_json::from_value(
            checkpoint
                .bootstrap_create_event
                .clone()
                .expect("new checkpoints persist the signed create Event"),
        )
        .unwrap();
        validate_persisted_bootstrap_create_event(
            &checkpoint,
            &validate_checkpoint_recovery_key(&checkpoint, &recovery_key).unwrap(),
            &persisted_create,
        )
        .unwrap();

        let mut legacy_value = serde_json::to_value(&checkpoint).unwrap();
        let legacy_object = legacy_value.as_object_mut().unwrap();
        legacy_object.remove("account_handle");
        legacy_object.remove("bootstrap_create_event");
        let legacy: PendingPrincipalRegistration = serde_json::from_value(legacy_value).unwrap();
        assert!(legacy.account_handle.is_empty());
        assert!(legacy.bootstrap_create_event.is_none());

        let another_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        assert!(validate_checkpoint_recovery_key(&checkpoint, &another_key).is_err());
    }

    #[test]
    fn bootstrap_checkpoint_fixes_ordered_event_identity_before_handoff_issue() {
        let recovery_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        let handoff =
            continuity_handoff("ak:request:019f0000-0000-7000-8000-000000000020", "alice");
        let checkpoint =
            prepare_registration_checkpoint(&handoff, &handoff.device_id, &recovery_key).unwrap();
        let prepared = prepare_device_bootstrap_checkpoint(
            &checkpoint,
            &recovery_key,
            "z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw".to_owned(),
            "z6LSfixtureHpkeKey11111111111111111111111111111111".to_owned(),
        )
        .unwrap();

        assert_eq!(
            prepared.stage,
            PendingPrincipalRegistrationStage::BootstrapPrepared
        );
        let bootstrap = device_bootstrap_request_from_checkpoint(&prepared).unwrap();
        assert_eq!(bootstrap.founding_event_ids.len(), 2);
        assert_eq!(
            bootstrap.authorize_event_preimage.prev_refs,
            vec![bootstrap.founding_event_ids[0].clone()]
        );
        assert_eq!(
            bootstrap.authorize_event_preimage.event_id,
            bootstrap.founding_event_ids[1]
        );

        let replayed = prepare_device_bootstrap_checkpoint(
            &prepared,
            &recovery_key,
            "z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw".to_owned(),
            "z6LSfixtureHpkeKey11111111111111111111111111111111".to_owned(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(replayed).unwrap(),
            serde_json::to_value(&prepared).unwrap()
        );

        let mut reordered = bootstrap;
        reordered.founding_event_ids.swap(0, 1);
        assert!(reordered.validate().is_err());

        let mut stages = checkpoint;
        assert!(
            stages
                .advance_bootstrap_stage(PendingPrincipalRegistrationStage::BatchAccepted)
                .is_err()
        );
        for next in [
            PendingPrincipalRegistrationStage::BootstrapPrepared,
            PendingPrincipalRegistrationStage::BootstrapGrantIssued,
            PendingPrincipalRegistrationStage::DeviceEnrolled,
            PendingPrincipalRegistrationStage::BatchAccepted,
            PendingPrincipalRegistrationStage::StandardPromoted,
        ] {
            stages.advance_bootstrap_stage(next).unwrap();
        }
        assert!(
            stages
                .advance_bootstrap_stage(PendingPrincipalRegistrationStage::BatchAccepted)
                .is_err()
        );
    }
}
