//! Client-authored principal registration and resumable bootstrap checkpoint.

use anyhow::{Context as _, anyhow};
use chrono::{SecondsFormat, Timelike as _, Utc};
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
    let bootstrap_create_event_id = arkret_sdk::identifiers::new_prefixed_uuid7("ak:event:");
    arkret_sdk::EventId::new(bootstrap_create_event_id.clone())?;
    let draft_actor = arkret_sdk::Did::new(draft.did.clone())?;
    let draft_realm = arkret_sdk::principal_control_realm_id(&draft_actor);
    let bootstrap_hlc = crate::signing_stamp::issue_protocol_hlc_with_secret(
        draft_actor.as_str(),
        device_id.trim(),
        &draft_realm,
        &key_material.root_seed,
    )?
    .to_string();
    Ok(PendingPrincipalRegistration {
        principal_server_url: handoff.principal_server_url.clone(),
        gate_account_base: handoff.gate_account_base.clone(),
        handoff_request_id: handoff.request_id.clone(),
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
        bootstrap_create_event_id,
        bootstrap_created_at: created_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        bootstrap_hlc,
        binding_receipt: None,
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

pub struct IdentityBindingCompletion {
    pub binding_receipt: arkret_sdk::AccountBindingReceipt,
    pub session_grant: garth::SessionGrantState,
    pub session_private_key_pem: String,
    pub dpop_device_key: crate::state::DpopDeviceKeyRecord,
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
        reserved_identity: None,
    };
    let challenge_request = garth::identity_binding_challenge_request(
        arkret_sdk::RequestId::new(arkret_sdk::identifiers::new_prefixed_uuid7("ak:request:"))?,
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
    let session_request = garth::pre_registration_session_grant_request(
        register_outcome.principal_id,
        Some(arkret_sdk::DeviceId::new(checkpoint.device_id.clone())?),
        Vec::new(),
        &account_handoff_grant,
        arkret_sdk::Did::new(handoff.audience.clone())?,
        Utc::now() + chrono::Duration::minutes(5),
        |bytes| dpop.sign_protocol_bytes(bytes),
    )?;
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

pub async fn bootstrap_principal(
    checkpoint: &PendingPrincipalRegistration,
    recovery_key: &str,
    device_public_key: String,
    hpke_key: String,
    device_signer: &crate::event_signer::InksonEventSigner,
    account_client: &arkret_sdk::http_client::Client,
    principal_client: &arkret_sdk::http_client::Client,
) -> anyhow::Result<()> {
    let key_material = validate_checkpoint_recovery_key(checkpoint, recovery_key)?;
    let principal_id = arkret_sdk::Did::new(checkpoint.did.clone())?;
    let realm_id = arkret_sdk::RealmId::new(arkret_sdk::principal_control_realm_id(&principal_id))?;
    let created_at = chrono::DateTime::parse_from_rfc3339(&checkpoint.bootstrap_created_at)
        .context("persisted bootstrap_created_at is invalid")?
        .with_timezone(&Utc);
    let mut create = arkret_sdk::identity::build_self_principal_pcr_create(
        arkret_sdk::identity::SelfPrincipalPcrCreateInput {
            principal_id: principal_id.clone(),
            realm_id: realm_id.clone(),
            trust_domain: arkret_sdk::TypedTrustDomainId::new(checkpoint.trust_domain.clone())?,
            did_inception_ref: arkret_sdk::EventRef::new(
                checkpoint.version_id.clone(),
                arkret_sdk::identity::DID_INCEPTION_REF_ROLE,
            ),
            event_id: arkret_sdk::EventId::new(checkpoint.bootstrap_create_event_id.clone())?,
            created_at,
            hlc: arkret_sdk::Hlc::new(checkpoint.bootstrap_hlc.clone())?,
        },
    )?;
    let root_did =
        arkret_sdk::Did::new(format!("did:key:{}", checkpoint.root_public_key_multibase))?;
    let root_signer = arkret_sdk::Ed25519MoveSigner::from_did_key_seed(
        key_material.root_seed,
        root_did,
        checkpoint.root_verification_method.clone(),
    );
    arkret_sdk::signatures::sign_event(
        &mut create,
        &root_signer,
        &checkpoint.root_verification_method,
        arkret_sdk::signatures::SignEventOptions::new().with_created_at(created_at),
    )?;

    let request = crate::identity::device_enrollment::DeviceEnrollmentRequest {
        device_id: checkpoint.device_id.clone(),
        device_public_key,
        actor_seq: 1,
        bootstrap_create_event_id: Some(create.event_id.to_string()),
        not_before: None,
        hpke_key,
        algorithms: crate::identity::device_enrollment::inkson_device_algorithms(),
    };
    let authorize = crate::identity::device_enrollment::request_signed_device_authorize(
        account_client,
        &request,
        &checkpoint.device_id,
    )
    .await?;
    let seal_hlc = crate::signing_stamp::issue_protocol_hlc_with_secret(
        principal_id.as_str(),
        &checkpoint.device_id,
        realm_id.as_str(),
        &key_material.root_seed,
    )?;
    let seal = device_signer
        .sign_self_principal_bootstrap_seal(&create, &authorize, seal_hlc)
        .map_err(|error| anyhow!(error.to_string()))?;
    let expected_digests = seal.delta.clone();
    let batch = arkret_sdk::identity::self_principal_bootstrap_submit_request(create, authorize)?;
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
            retry_after_ms: None,
            device_id: "ak:device:019f0000-0000-7000-8000-000000000001".to_owned(),
            enrollment_authority_did: "did:key:z6MkrJVnaZkeFzdQyKjzgRHjhBfE6ZscXDFHq8T7TYNy9v1t"
                .to_owned(),
            trust_domain: "ak:trust-domain:test".to_owned(),
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
        validate_checkpoint_recovery_key(&checkpoint, &recovery_key).unwrap();

        let another_key = crate::recovery_crypto::generate_recovery_key().unwrap();
        assert!(validate_checkpoint_recovery_key(&checkpoint, &another_key).is_err());
    }
}
