//! PCR-policy fresh-device recovery.
//!
//! Recovery is deliberately a closed two-event unit. The accepted recovery
//! policy authorizes the unit, while the replacement device signs both
//! `ak.device.reanchor` and `ak.device.authorize` with its identity key.

use anyhow::Context;
use arkret_models_collaboration::events_payloads::SignatureMaterial;
use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
    DeviceReanchorPayload, device_authorize_payload_digest,
};
use arkret_models_crypto::{
    RecoveryAuthorityKind, RecoveryCommitIntent, RecoveryProofKind,
    SecurityTransactionTerminalOutcome,
};
use arkret_sdk::{
    PcrPolicyRecoveryIntent, PreparedEventUnit, RecoveryTransactionCreateRequestBody,
    SecurityTransaction, SecurityTransactionCreateRequestBody,
};
use arkret_wire::{CommitStreamRef, Hash, NonEmptyString, ReceiptId, TransactionId};

fn non_empty(value: String) -> anyhow::Result<NonEmptyString> {
    NonEmptyString::new(value).map_err(anyhow::Error::msg)
}

pub(crate) struct PreparedPcrPolicyRecovery {
    pub security_transaction_create_request_body: RecoveryTransactionCreateRequestBody,
    pub publication_context: arkret_sdk::ProducerVerificationContext,
    pub proof_summary: arkret_models_crypto::RecoverySessionProofSummary,
    pub verified_session: arkret_sdk::RecoverySession,
}

pub(crate) struct CompletedFreshDeviceRecovery {
    pub transaction_id: TransactionId,
    pub readiness: crate::fresh_device_recovery::RecoveryReadinessEvidence,
    pub standard_grant_installed: bool,
    pub pending: crate::security_transaction::PendingFreshDeviceRecovery,
}

fn completed_recovery(
    transaction: &SecurityTransaction,
) -> anyhow::Result<CompletedFreshDeviceRecovery> {
    transaction.validate_structural()?;
    anyhow::ensure!(
        crate::fresh_device_recovery::transaction_is_completed(transaction),
        "recovery transaction is not completed"
    );
    let binding = &transaction
        .recovery_plan()
        .ok_or_else(|| anyhow::anyhow!("completed recovery has no PCR-policy binding"))?
        .binding;
    Ok(CompletedFreshDeviceRecovery {
        transaction_id: transaction.transaction_id.clone(),
        readiness: crate::fresh_device_recovery::RecoveryReadinessEvidence {
            transaction_id: transaction.transaction_id.clone(),
            terminal_receipt_id: binding.terminal_receipt_id.clone(),
            authorization_event_id: binding.authorize_event_id.clone(),
        },
        standard_grant_installed: false,
        pending: crate::security_transaction::PendingFreshDeviceRecovery::capture(
            &transaction.transaction_id,
        )?,
    })
}

/// A durable completed transaction proves the identity replacement only.
/// Resume grant issuance directly; its consumed recovery session is not a
/// credential for the replacement Device's separate content recovery.
pub(crate) fn load_completed_pending_pcr_policy_recovery(
    account_id: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
) -> anyhow::Result<Option<CompletedFreshDeviceRecovery>> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let Some(transaction_id) =
        crate::security_transaction::pending_fresh_device_recovery(secure_store.as_ref())?
    else {
        return Ok(None);
    };
    let store = crate::security_transaction::InksonSecurityTransactionStore::new(secure_store);
    let Some(local) = garth::SecurityTransactionStore::load(&store, &transaction_id)? else {
        return Ok(None);
    };
    let Some(resource) = &local.last_observed_resource else {
        return Ok(None);
    };
    anyhow::ensure!(
        resource.account_id == *account_id
            && resource.transaction_id == transaction_id
            && resource.request_digest
                == Hash::new(arkret_sdk::canonical::sha256_digest(
                    &local.canonical_create_request
                ))?
            && resource
                .recovery_plan()
                .is_some_and(|plan| { plan.binding.replacement_device_id == *device_id }),
        "pending recovery belongs to another account or replacement device"
    );
    if !crate::fresh_device_recovery::transaction_is_completed(resource) {
        return Ok(None);
    }
    let receipt = local
        .completed_recovery_receipt()?
        .ok_or_else(|| anyhow::anyhow!("completed recovery has no durable terminal receipt"))?;
    let Some(SecurityTransactionTerminalOutcome::Completed {
        completion_attestation: Some(attestation),
        ..
    }) = &resource.terminal_outcome
    else {
        anyhow::bail!("completed recovery has no completion attestation");
    };
    anyhow::ensure!(
        Hash::new(arkret_sdk::canonical::sha256_digest(
            &arkret_sdk::canonical::canonical_json_bytes(&receipt)?
        ))? == attestation.terminal_receipt_digest,
        "completed recovery changed its durable terminal receipt"
    );
    completed_recovery(resource).map(Some)
}

fn next_recovery_device_generation(current: u64) -> anyhow::Result<u64> {
    if current == 0 {
        anyhow::bail!("verified recovery session carries generation zero");
    }
    current
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("device generation exhausted"))
}

pub(crate) async fn prepare_pcr_policy_recovery(
    api: &crate::transport::TransportClient,
    principal_did: &arkret_sdk::Did,
    session: &arkret_sdk::RecoverySession,
    proof_outcome: &arkret_sdk::RecoverySessionProofSubmitResponseBody,
) -> anyhow::Result<PreparedPcrPolicyRecovery> {
    // A 2xx submit reply already means the proof verified and the session
    // entered `verified`; the outcome echoes neither `state` nor
    // `verification`. The authoritative state is re-read below.
    if proof_outcome.recovery_session_id != session.recovery_session_id {
        anyhow::bail!("recovery proof outcome did not verify the requested session");
    }
    let verified_session = api
        .recovery_session(session.recovery_session_id.as_str())
        .await?;
    let device_signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("replacement device signer is unavailable"))?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    prepare_verified_pcr_policy_recovery(
        principal_did,
        session,
        proof_outcome,
        verified_session,
        device_signer.as_ref(),
        secure_store.as_ref(),
    )
    .await
}

async fn prepare_verified_pcr_policy_recovery(
    principal_did: &arkret_sdk::Did,
    session: &arkret_sdk::RecoverySession,
    proof_outcome: &arkret_sdk::RecoverySessionProofSubmitResponseBody,
    verified_session: arkret_sdk::RecoverySession,
    device_signer: &crate::event_signer::InksonEventSigner,
    secure_store: &(dyn crate::secure_key_store::SecureKeyStore + Send + Sync),
) -> anyhow::Result<PreparedPcrPolicyRecovery> {
    verified_session.validate_shape()?;
    if arkret_sdk::project_did_to_core_id(principal_did)?
        != verified_session.account_id.principal_id
    {
        anyhow::bail!("selected recovery principal did does not match the verified session");
    }
    if verified_session.state != arkret_sdk::RecoverySessionState::Verified
        || verified_session.identity_model != arkret_sdk::RecoveryIdentityModel::PcrPolicy
        || proof_outcome.recovery_session_id != session.recovery_session_id
        || verified_session.recovery_session_id != session.recovery_session_id
        || verified_session.account_id != session.account_id
        || verified_session.requesting_device_id != session.requesting_device_id
        || verified_session.requesting_device_public_key_did
            != session.requesting_device_public_key_did
        || verified_session.proof_summary != proof_outcome.proof_summary
    {
        anyhow::bail!("recovery session is not the verified PCR-policy snapshot");
    }

    let previous_device_generation = verified_session.current_device_generation_ref;
    let result_device_generation = next_recovery_device_generation(previous_device_generation)?;

    let scope_ref = verified_session
        .publication_authority_context
        .scope_ref
        .clone();
    let created_at = crate::clock::now_utc_millis();
    let device_public_key_multibase = device_signer
        .public_key_multibase()
        .ok_or_else(|| anyhow::anyhow!("replacement device signer has no Ed25519 public key"))?;
    let device_public_key = format!("did:key:{device_public_key_multibase}");
    anyhow::ensure!(
        device_signer.device_id() == Some(verified_session.requesting_device_id.as_str())
            && verified_session.requesting_device_public_key_did.as_str() == device_public_key
            && crate::clock::now_utc() < verified_session.expires_at,
        "recovery session does not bind the current replacement key or is expired"
    );
    let (_, hpke_public_key) = crate::mls::runtime::load_or_create_device_hpke_keypair_durable(
        secure_store,
        &verified_session.account_id,
        &verified_session.requesting_device_id,
    )
    .await?;
    let hpke_key = crate::identity::did_key::encode_x25519_multibase(&hpke_public_key);
    let algorithms = crate::identity::principal_genesis::INKSON_DEVICE_ALGORITHMS
        .iter()
        .map(|value| non_empty((*value).to_owned()))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut authorize_payload = DeviceAuthorizePayload {
        device_id: verified_session.requesting_device_id.clone(),
        device_public_key_did: non_empty(device_public_key)?,
        hpke_key: non_empty(hpke_key)?,
        algorithms,
        device_key_algorithm: non_empty("Ed25519".to_owned())?,
        authorized_by: DeviceOrPrincipalRef::Principal(
            verified_session.account_id.principal_id.clone(),
        ),
        scopes: None,
        not_before: created_at,
        expires_at: None,
        authorization_binding_kind: DeviceAuthorizationBindingKind::PcrRecovery,
        authorized_generation_ref: result_device_generation,
        device_signature: SignatureMaterial::NonEmptyString(non_empty("AA".to_owned())?),
        recovery_session_id: Some(verified_session.recovery_session_id.clone()),
        pairing_challenge_transcript_digest: None,
        applet_id: None,
        expected_control_revision: None,
        expected_device_revision: None,
    };
    authorize_payload
        .validate_wire_constraints()
        .map_err(anyhow::Error::msg)?;
    authorize_payload.device_signature = SignatureMaterial::NonEmptyString(non_empty(
        arkret_sdk::base64url_encode(device_signer.sign_raw(
            &authorize_payload.device_possession_signature_input(&verified_session.account_id)?,
        )?),
    )?);
    let digest_suite = arkret_sdk::canonical::DigestSuite::Sha256;
    let reanchor_payload = exact_device_reanchor_payload(
        &verified_session,
        previous_device_generation,
        result_device_generation,
        device_authorize_payload_digest(&serde_json::to_value(&authorize_payload)?, digest_suite)?,
    )?;

    let mut reanchor = arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::DeviceReanchor>::new(
        scope_ref.clone(),
        arkret_sdk::ActorId::account(verified_session.account_id.clone()),
        reanchor_payload,
    )?
    .author_with_digest_suite(created_at, digest_suite)?;
    device_signer.sign_sdk_event_with_context_at(
        &mut reanchor,
        crate::event_signer::ProducerProofContext::for_native_unit(digest_suite),
        created_at,
    )?;
    let mut authorize =
        arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::DeviceAuthorize>::new(
            scope_ref.clone(),
            arkret_sdk::ActorId::account(verified_session.account_id.clone()),
            authorize_payload,
        )?
        .author_with_digest_suite(created_at, digest_suite)?;
    device_signer.sign_sdk_event_with_context_at(
        &mut authorize,
        crate::event_signer::ProducerProofContext::for_native_unit(digest_suite),
        created_at,
    )?;
    let reanchor = reanchor.into_event();
    let authorize = authorize.into_event();
    let proof_summary = verified_session
        .proof_summary
        .clone()
        .ok_or_else(|| anyhow::anyhow!("verified recovery session omitted proof summary"))?;
    if proof_summary.kind != RecoveryProofKind::RecoveryUnlock {
        anyhow::bail!("recovery-word flow requires a recovery_unlock proof");
    }
    let recovery_verification_method = proof_summary
        .verification_method
        .clone()
        .ok_or_else(|| anyhow::anyhow!("recovery_unlock proof omitted verification method"))?;
    let recovery_rule = verified_session
        .publication_authority_context
        .authority_set_policy
        .authorization_rules
        .iter()
        .find(|rule| rule.rule_id == "recovery_unlock")
        .ok_or_else(|| anyhow::anyhow!("verified recovery method has no publication authority"))?;
    if recovery_rule.threshold != 1
        || recovery_rule.issuers.len() != 1
        || recovery_rule.issuers[0].verification_method != recovery_verification_method
    {
        anyhow::bail!("recovery_unlock publication authority does not match the verified proof");
    }
    let unit_event_digests = [
        Hash::new(reanchor.event_digest_with_digest_suite(digest_suite)?)?,
        Hash::new(authorize.event_digest_with_digest_suite(digest_suite)?)?,
    ];
    let reanchor_submission = arkret_wire::EventsSubmitBatchRequestBody {
        events: (vec![reanchor, authorize])
            .into_iter()
            .map(arkret_wire::EventAdmissionSubmission::new)
            .collect(),
    };

    let expected_stream_ref = CommitStreamRef::Realm {
        realm_id: scope_ref.realm_id().clone(),
    };
    if verified_session.realm_stream_head.stream_ref != expected_stream_ref {
        anyhow::bail!("PCR recovery Realm stream head does not match publication scope");
    }
    let reanchor_commit_intent = RecoveryCommitIntent {
        realm_id: scope_ref.realm_id().clone(),
        predecessor_ref: verified_session.realm_stream_head.commit_id.clone(),
        unit_event_digests,
    };
    reanchor_commit_intent.validate()?;
    // The client freezes the two signed Events and the predecessor it observed.
    // Only the governance Station may assign their two consecutive RealmCommits.
    let recovery_intent = PcrPolicyRecoveryIntent {
        recovery_session_id: verified_session.recovery_session_id.clone(),
        replacement_device_id: verified_session.requesting_device_id.clone(),
        previous_model_generation_ref: previous_device_generation,
        new_model_generation_ref: result_device_generation,
        terminal_receipt_id: ReceiptId::new(format!("ak:receipt:{}", crate::operation::uuid_v7()))?,
        reanchor_unit: PreparedEventUnit::new(digest_suite, reanchor_submission)?,
        reanchor_commit_intent,
    };
    let security_transaction_create_request_body = RecoveryTransactionCreateRequestBody::new(
        TransactionId::new(format!("ak:transaction:{}", crate::operation::uuid_v7()))?,
        verified_session.account_id.clone(),
        std::cmp::min(
            verified_session.expires_at,
            crate::clock::now_utc() + chrono::Duration::hours(1),
        ),
        recovery_intent,
    )?;
    Ok(PreparedPcrPolicyRecovery {
        publication_context: device_signer.publication_context(&arkret_sdk::ActorId::account(
            verified_session.account_id.clone(),
        ))?,
        security_transaction_create_request_body,
        proof_summary,
        verified_session,
    })
}

fn exact_device_reanchor_payload(
    session: &arkret_sdk::RecoverySession,
    previous_device_generation: u64,
    new_device_generation: u64,
    replacement_authorize_payload_digest: Hash,
) -> anyhow::Result<DeviceReanchorPayload> {
    let payload = DeviceReanchorPayload {
        account_id: session.account_id.clone(),
        recovery_authority_kind: RecoveryAuthorityKind::PcrPolicy,
        recovery_policy_id: session.policy_id.clone(),
        recovery_policy_version: session.policy_version,
        recovery_session_id: session.recovery_session_id.clone(),
        previous_device_generation,
        new_device_generation,
        did_root_evidence_digest: None,
        replacement_authorize_payload_digest,
    };
    payload.validate()?;
    Ok(payload)
}

fn identity_recovery_terminal_observation(
    session: &arkret_sdk::RecoverySession,
    proof: &arkret_models_crypto::RecoverySessionProofSummary,
) -> crate::fresh_device_recovery::RecoveryTerminalObservation {
    crate::fresh_device_recovery::RecoveryTerminalObservation {
        policy_id: session.policy_id.clone(),
        policy_version: session.policy_version,
        trust_domain: session.trust_domain.clone(),
        proof_summary: arkret_models_crypto::RecoveryProofSummary {
            kind: proof.kind,
            proof_digest: proof.proof_digest.clone(),
            quorum_participant_count: None,
        },
        // No historical object has been opened by the identity coordinator.
        backup_classes_unlocked: vec![],
        welcome_count: 0,
        welcome_realm_summary: None,
        started_at: session.created_at,
        completed_at: crate::clock::now_utc(),
    }
}

fn reject_terminal_recovery_transaction(
    transaction: &SecurityTransaction,
    secure_store: &(dyn garth::SecureKeyStore + Send + Sync),
) -> anyhow::Result<()> {
    match transaction.terminal_outcome.as_ref() {
        Some(SecurityTransactionTerminalOutcome::Aborted { .. })
        | Some(SecurityTransactionTerminalOutcome::Expired { .. }) => {
            crate::security_transaction::clear_pending_fresh_device_recovery(secure_store)?;
            anyhow::bail!("recovery transaction ended without completion");
        }
        None | Some(SecurityTransactionTerminalOutcome::Completed { .. }) => {}
    }
    Ok(())
}

pub(crate) async fn execute_pcr_policy_recovery(
    api: &crate::transport::TransportClient,
    principal_did: &arkret_sdk::Did,
    session: &arkret_sdk::RecoverySession,
    proof_outcome: &arkret_sdk::RecoverySessionProofSubmitResponseBody,
) -> anyhow::Result<CompletedFreshDeviceRecovery> {
    let prepared = prepare_pcr_policy_recovery(api, principal_did, session, proof_outcome).await?;
    let session = &prepared.verified_session;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    // The verified identity proof authorizes only the replacement unit. Old
    // checkpoint secrets are neither needed nor imported before the fence;
    // history uses the new Device's separately authorized per-object lane.

    let transaction_id = prepared
        .security_transaction_create_request_body
        .transaction_id
        .clone();
    crate::security_transaction::store_pending_fresh_device_recovery(
        secure_store.as_ref(),
        &transaction_id,
    )
    .await?;
    let engine = crate::security_transaction::security_transaction_engine(
        api.sdk_http_client()?,
        secure_store.clone(),
    );
    let workflow = crate::fresh_device_recovery::FreshDeviceRecovery::new(engine);
    let mut transaction = workflow
        .create_or_resume(
            prepared.security_transaction_create_request_body,
            None,
            &prepared.publication_context,
        )
        .await?;
    if let Some(retried) = workflow
        .retry_byte_identical_pending(&transaction_id)
        .await?
    {
        transaction = retried;
    }
    reject_terminal_recovery_transaction(&transaction, secure_store.as_ref())?;
    if !crate::fresh_device_recovery::transaction_is_completed(&transaction) {
        let signer = crate::event_signer::active_signer()
            .ok_or_else(|| anyhow::anyhow!("replacement device signer is unavailable"))?;
        let terminal = crate::fresh_device_recovery::sign_recovery_terminal_commit_continue(
            &transaction,
            identity_recovery_terminal_observation(session, &prepared.proof_summary),
            signer.as_ref(),
        )?;
        transaction = workflow
            .continue_with_signed_artifact(&transaction_id, &terminal)
            .await?;
    }
    reject_terminal_recovery_transaction(&transaction, secure_store.as_ref())?;
    if !crate::fresh_device_recovery::transaction_is_completed(&transaction) {
        anyhow::bail!("recovery transaction did not reach completed state");
    }
    completed_recovery(&transaction)
}

/// Resume the byte-identical durable request after reload or response loss.
/// Its already verified proof and exact replacement key remain binding; no
/// historical private material is imported while completing the identity unit.
pub(crate) async fn resume_pending_pcr_policy_recovery(
    api: &crate::transport::TransportClient,
    expected_account: &arkret_sdk::AccountId,
    expected_device: &arkret_sdk::DeviceId,
) -> anyhow::Result<Option<CompletedFreshDeviceRecovery>> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let Some(transaction_id) =
        crate::security_transaction::pending_fresh_device_recovery(secure_store.as_ref())?
    else {
        return Ok(None);
    };
    let transaction_store =
        crate::security_transaction::InksonSecurityTransactionStore::new(secure_store.clone());
    let Some(local) = garth::SecurityTransactionStore::load(&transaction_store, &transaction_id)?
    else {
        // The process may have stopped after the small pending index was
        // flushed but before Garth durably staged the canonical create. No
        // remote side effect was possible in that window, so discard only the
        // orphan index and safely prepare a new transaction.
        crate::security_transaction::clear_pending_fresh_device_recovery(secure_store.as_ref())?;
        return Ok(None);
    };
    let create: SecurityTransactionCreateRequestBody =
        serde_json::from_slice(&local.canonical_create_request)?;
    let SecurityTransactionCreateRequestBody::Recovery(create) = create else {
        anyhow::bail!("pending fresh-device recovery is not a recovery transaction");
    };
    anyhow::ensure!(
        create.account_id == *expected_account
            && create.transaction_id == transaction_id
            && create.recovery_intent.replacement_device_id == *expected_device,
        "pending recovery create belongs to another account or device"
    );
    let engine = crate::security_transaction::security_transaction_engine(
        api.sdk_http_client()?,
        secure_store.clone(),
    );
    let workflow = crate::fresh_device_recovery::FreshDeviceRecovery::new(engine);
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("replacement device signer is unavailable"))?;
    anyhow::ensure!(
        signer.device_id() == Some(expected_device.as_str()),
        "pending recovery signer belongs to another device"
    );
    let context =
        signer.publication_context(&arkret_sdk::ActorId::account(expected_account.clone()))?;
    let mut transaction = workflow
        .create_or_resume(create, local.staged_secret_ref, &context)
        .await?;
    if let Some(retried) = workflow
        .retry_byte_identical_pending(&transaction_id)
        .await?
    {
        transaction = retried;
    }
    reject_terminal_recovery_transaction(&transaction, secure_store.as_ref())?;
    if crate::fresh_device_recovery::transaction_is_completed(&transaction) {
        return completed_recovery(&transaction).map(Some);
    }
    let binding = transaction
        .recovery_plan()
        .map(|plan| &plan.binding)
        .ok_or_else(|| anyhow::anyhow!("pending recovery lost its PCR-policy binding"))?
        .clone();
    let session = api
        .recovery_session(binding.recovery_session_id.as_str())
        .await?;
    session.validate_shape()?;
    let plan = transaction
        .recovery_plan()
        .context("pending recovery has no plan")?;
    anyhow::ensure!(
        session.state == arkret_sdk::RecoverySessionState::Verified
            && session.identity_model == arkret_sdk::RecoveryIdentityModel::PcrPolicy
            && session.account_id == *expected_account
            && session.requesting_device_id == *expected_device
            && session.recovery_session_id == binding.recovery_session_id
            && session.current_device_generation_ref == plan.previous_model_generation_ref
            && session.proof_summary.as_ref().is_some_and(|proof| {
                proof.kind == RecoveryProofKind::RecoveryUnlock
                    && proof.proof_digest == plan.proof_digest
            })
            && crate::clock::now_utc() < session.expires_at,
        "pending recovery session changed its frozen account, device, generation or proof"
    );
    let proof_summary = session
        .proof_summary
        .clone()
        .ok_or_else(|| anyhow::anyhow!("verified recovery session omitted proof summary"))?;
    if !crate::fresh_device_recovery::transaction_is_completed(&transaction) {
        let signer = crate::event_signer::active_signer()
            .ok_or_else(|| anyhow::anyhow!("replacement device signer is unavailable"))?;
        let terminal = crate::fresh_device_recovery::sign_recovery_terminal_commit_continue(
            &transaction,
            identity_recovery_terminal_observation(&session, &proof_summary),
            signer.as_ref(),
        )?;
        transaction = workflow
            .continue_with_signed_artifact(&transaction_id, &terminal)
            .await?;
    }
    reject_terminal_recovery_transaction(&transaction, secure_store.as_ref())?;
    if !crate::fresh_device_recovery::transaction_is_completed(&transaction) {
        anyhow::bail!("pending recovery did not reach completed state");
    }
    completed_recovery(&transaction).map(Some)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Verifier as _;

    use super::*;

    fn hash(value: &impl serde::Serialize) -> Hash {
        Hash::new(arkret_sdk::canonical::sha256_digest(
            arkret_sdk::canonical::canonical_json_bytes(value).unwrap(),
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn identity_unit_and_terminal_sign_without_any_old_checkpoint_secret() {
        let (words, _, policy, session) =
            crate::recovery_flow::recovery_unlock_fixture_for_principal(
                "did:webvh:zRecoveryUnit:principal.example",
            );
        let proof =
            crate::recovery_flow::build_recovery_unlock_proof_from_words(&session, &policy, &words)
                .unwrap();
        let arkret_sdk::RecoverySessionProof::RecoveryUnlock(unlock) = &proof else {
            panic!("expected the mnemonic proof");
        };
        // This unit test models the already verified source snapshot. Native
        // policy admission and server fencing require their separate live test.
        let summary = arkret_models_crypto::RecoverySessionProofSummary {
            kind: RecoveryProofKind::RecoveryUnlock,
            proof_digest: hash(&proof),
            verification_method: Some(unlock.verification_method.clone()),
        };
        let outcome = arkret_sdk::RecoverySessionProofSubmitResponseBody {
            recovery_session_id: session.recovery_session_id.clone(),
            proof_summary: Some(summary.clone()),
        };
        let mut verified = session.clone();
        verified.state = arkret_sdk::RecoverySessionState::Verified;
        verified.proof_summary = Some(summary);
        let principal =
            arkret_sdk::Did::new("did:webvh:zRecoveryUnit:principal.example".to_owned()).unwrap();
        let signer = crate::event_signer::build_ed25519_device_signer(
            [41; 32],
            principal.as_str(),
            session.requesting_device_id.as_str(),
        );
        let store = crate::secure_key_store::MemorySecureKeyStore::default();
        assert!(
            crate::mls::runtime::load_account_mls_secret(&store, &session.account_id)
                .unwrap()
                .is_none()
        );
        let prepared = prepare_verified_pcr_policy_recovery(
            &principal,
            &session,
            &outcome,
            verified.clone(),
            &signer,
            &store,
        )
        .await
        .unwrap();
        let create = prepared.security_transaction_create_request_body;
        arkret_sdk::VerifiedSubmission::verify(
            SecurityTransactionCreateRequestBody::Recovery(create.clone()),
            |_| Ok(prepared.publication_context.clone()),
        )
        .unwrap();
        let intent = &create.recovery_intent;
        let plan = arkret_models_crypto::PcrPolicyRecoveryPlan {
            binding: arkret_models_crypto::PcrPolicyRecoveryBinding {
                identity_model: arkret_sdk::RecoveryIdentityModel::PcrPolicy,
                recovery_session_id: intent.recovery_session_id.clone(),
                replacement_device_id: intent.replacement_device_id.clone(),
                reanchor_event_id: intent.reanchor_unit.request.events[0]
                    .event
                    .event_id
                    .clone(),
                authorize_event_id: intent.reanchor_unit.request.events[1]
                    .event
                    .event_id
                    .clone(),
                terminal_receipt_id: intent.terminal_receipt_id.clone(),
            },
            recovery_session_snapshot_digest: hash(&verified),
            proof_digest: prepared.proof_summary.proof_digest.clone(),
            previous_model_generation_ref: intent.previous_model_generation_ref,
            new_model_generation_ref: intent.new_model_generation_ref,
            reanchor_unit: intent.reanchor_unit.clone(),
            reanchor_commit_intent: intent.reanchor_commit_intent.clone(),
        };
        let plan = arkret_models_crypto::SecurityTransactionPreparedPlan::Recovery(plan);
        let transaction = SecurityTransaction {
            transaction_id: create.transaction_id.clone(),
            kind: create.kind,
            account_id: create.account_id.clone(),
            authorizing_device_id: None,
            expires_at: create.expires_at,
            created_at: crate::clock::now_utc(),
            request_digest: hash(&SecurityTransactionCreateRequestBody::Recovery(
                create.clone(),
            )),
            prepared_plan_digest: hash(&plan),
            prepared_plan: plan,
            accepted_steps: vec![],
            revoke_proposal: None,
            revoke_command_outcome: None,
            terminal_outcome: None,
        };
        transaction.validate_structural().unwrap();
        let terminal = crate::fresh_device_recovery::sign_recovery_terminal_commit_continue(
            &transaction,
            identity_recovery_terminal_observation(&verified, &prepared.proof_summary),
            &signer,
        )
        .unwrap();
        terminal.validate_for_transaction(&transaction).unwrap();
        let arkret_models_crypto::ClientStepAttestationArtifact::Recovery(commit) =
            &terminal.client_attestation.artifact
        else {
            panic!("expected the identity terminal artifact");
        };
        let receipt = &commit.recovery_receipt;
        assert!(receipt.unlocked_backups.is_empty());
        assert_eq!(receipt.welcome_count, 0);
        assert_eq!(receipt.previous_model_generation_ref, 3);
        assert_eq!(receipt.new_model_generation_ref, 4);
        assert_eq!(receipt.account_id, session.account_id);
        assert_eq!(receipt.new_device_id, session.requesting_device_id);
        let key = ed25519_dalek::SigningKey::from_bytes(&[41; 32]).verifying_key();
        for (bytes, signature) in [
            (
                receipt.signature_transcript_bytes().unwrap(),
                &receipt.signature_proof.signature,
            ),
            (
                terminal.client_attestation.signing_bytes().unwrap(),
                &terminal.client_attestation.signature_proof.signature,
            ),
        ] {
            let signature = ed25519_dalek::Signature::from_slice(
                &arkret_sdk::base64url_decode(signature.as_str()).unwrap(),
            )
            .unwrap();
            key.verify_strict(&bytes, &signature).unwrap();
        }
        let mut rebound = receipt.clone();
        rebound.new_model_generation_ref += 1;
        let signature = ed25519_dalek::Signature::from_slice(
            &arkret_sdk::base64url_decode(receipt.signature_proof.signature.as_str()).unwrap(),
        )
        .unwrap();
        assert!(
            key.verify(&rebound.signature_transcript_bytes().unwrap(), &signature)
                .is_err()
        );
        assert!(
            crate::mls::runtime::load_account_mls_secret(&store, &session.account_id)
                .unwrap()
                .is_none()
        );
        assert!(
            crate::mls::runtime::load_device_hpke_keypair(
                &store,
                &session.account_id,
                &session.requesting_device_id,
            )
            .unwrap()
            .is_some()
        );
        for mismatch in ["key", "station", "proof", "pending"] {
            let mut changed = verified.clone();
            let signer = crate::event_signer::build_ed25519_device_signer(
                if mismatch == "key" {
                    [42; 32]
                } else {
                    [41; 32]
                },
                principal.as_str(),
                session.requesting_device_id.as_str(),
            );
            match mismatch {
                "station" => {
                    changed.account_id.station_id = arkret_sdk::DidCoreId::new(
                        "ak:did_core:webvh:zOther:other-station.example".to_owned(),
                    )
                    .unwrap()
                }
                "proof" => {
                    changed.proof_summary.as_mut().unwrap().proof_digest = hash(&"other proof")
                }
                "pending" => changed.state = arkret_sdk::RecoverySessionState::Pending,
                _ => {}
            }
            let empty = crate::secure_key_store::MemorySecureKeyStore::default();
            assert!(
                prepare_verified_pcr_policy_recovery(
                    &principal, &session, &outcome, changed, &signer, &empty,
                )
                .await
                .is_err(),
                "{mismatch}"
            );
        }
    }

    #[test]
    fn recovery_generation_is_the_single_checked_successor() {
        assert_eq!(next_recovery_device_generation(7).unwrap(), 8);
        assert!(next_recovery_device_generation(0).is_err());
        assert!(next_recovery_device_generation(u64::MAX).is_err());
    }
}
