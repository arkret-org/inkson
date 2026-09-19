//! PCR-policy fresh-device recovery.
//!
//! Recovery is deliberately a closed two-event unit. The accepted recovery
//! policy authorizes the unit, while the replacement device signs both
//! `ak.device.reanchor` and `ak.device.authorize` with its identity key.

use arkret_models_collaboration::events_payloads::SignatureMaterial;
use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
    DeviceReanchorPayload, device_authorize_payload_digest,
};
use arkret_models_crypto::{
    PreparedEventBatchRequest, RecoveryAuthorityKind, RecoveryCommitIntent, RecoveryProofKind,
    SecurityTransactionTerminalOutcome,
};
use arkret_sdk::{
    PcrPolicyRecoveryIntent, PreparedEventUnit, RecoveryTransactionCreateRequest,
    SecurityTransaction, SecurityTransactionCreateRequest,
};
use arkret_wire::{CommitStreamRef, Hash, NonEmptyString, ReceiptId, TransactionId};
use zeroize::Zeroizing;

fn non_empty(value: String) -> anyhow::Result<NonEmptyString> {
    NonEmptyString::new(value).map_err(anyhow::Error::msg)
}

pub(crate) struct PreparedPcrPolicyRecovery {
    pub create_request: RecoveryTransactionCreateRequest,
    pub proof_summary: arkret_models_crypto::RecoverySessionProofSummary,
    pub recovery_private_key: Zeroizing<[u8; 32]>,
    pub verified_session: arkret_sdk::RecoverySession,
}

pub(crate) struct CompletedFreshDeviceRecovery {
    pub transaction_id: TransactionId,
    pub readiness: crate::fresh_device_recovery::RecoveryReadinessEvidence,
    pub standard_grant_installed: bool,
}

pub(crate) async fn prepare_pcr_policy_recovery(
    api: &crate::transport::TransportClient,
    principal_did: &arkret_sdk::Did,
    session: &arkret_sdk::RecoverySession,
    proof_outcome: &arkret_sdk::RecoverySessionProofSubmitOutcome,
    recovery_words: &str,
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
    verified_session.validate_shape()?;
    if arkret_sdk::project_did_to_core_id(principal_did)?
        != verified_session.account_id.principal_id
    {
        anyhow::bail!("selected recovery principal did does not match the verified session");
    }
    if verified_session.state != arkret_sdk::RecoverySessionState::Verified
        || verified_session.identity_model != arkret_sdk::RecoveryIdentityModel::PcrPolicy
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
    let result_device_generation = previous_device_generation
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("device generation exhausted"))?;
    let backup_material =
        arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
            recovery_words,
            "",
            0,
        )?;

    let scope_ref = verified_session
        .publication_authority_context
        .scope_ref
        .clone();
    let created_at = crate::clock::now_utc_millis();
    let device_signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("replacement device signer is unavailable"))?;
    let device_public_key_multibase = device_signer
        .public_key_multibase()
        .ok_or_else(|| anyhow::anyhow!("replacement device signer has no Ed25519 public key"))?;
    let device_public_key = format!("did:key:{device_public_key_multibase}");
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let (_, hpke_public_key) = crate::mls::runtime::load_or_create_device_hpke_keypair_durable(
        secure_store.as_ref(),
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
        device_signature: SignatureMaterial::NonEmptyString(non_empty("AA".to_owned())?),
        recovery_session_id: Some(verified_session.recovery_session_id.clone()),
        pairing_challenge_transcript_digest: None,
        applet_id: None,
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
    let reanchor_submission = PreparedEventBatchRequest {
        events: vec![reanchor, authorize],
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
        result_model_generation_ref: result_device_generation,
        terminal_receipt_id: ReceiptId::new(format!("ak:receipt:{}", crate::operation::uuid_v7()))?,
        reanchor_unit: PreparedEventUnit::new(digest_suite, reanchor_submission)?,
        reanchor_commit_intent,
    };
    let create_request = RecoveryTransactionCreateRequest::new(
        TransactionId::new(format!("ak:transaction:{}", crate::operation::uuid_v7()))?,
        verified_session.account_id.clone(),
        std::cmp::min(
            verified_session.expires_at,
            crate::clock::now_utc() + chrono::Duration::hours(1),
        ),
        recovery_intent,
    )?;
    Ok(PreparedPcrPolicyRecovery {
        create_request,
        proof_summary,
        recovery_private_key: Zeroizing::new(backup_material.backup_hpke_serialized_private_key),
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

fn recovery_backup_classes_unlocked(
    restore_payload: &serde_json::Value,
) -> anyhow::Result<Vec<arkret_models_crypto::RecoveryBackupUnlocked>> {
    let mut classes = crate::mls::runtime::iter_backup_bodies(restore_payload)
        .filter(|backup| {
            backup
                .get("ciphertext")
                .and_then(serde_json::Value::as_str)
                .is_some()
        })
        .map(|backup| {
            Ok(arkret_models_crypto::RecoveryBackupUnlocked {
                backup_kind: serde_json::from_value(
                    backup
                        .get("backup_kind")
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("backup omits kind"))?,
                )?,
                backup_id: arkret_sdk::BackupId::new(
                    backup
                        .get("backup_id")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| anyhow::anyhow!("backup omits id"))?
                        .to_owned(),
                )?,
                series_id: arkret_sdk::BackupSeriesId::new(
                    backup
                        .get("series_id")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| anyhow::anyhow!("backup omits series"))?
                        .to_owned(),
                )?,
                ciphertext_digest: Hash::new(
                    backup
                        .get("ciphertext_digest")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| anyhow::anyhow!("backup omits ciphertext digest"))?
                        .to_owned(),
                )?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    classes.sort_by(|left, right| left.backup_id.as_str().cmp(right.backup_id.as_str()));
    classes.dedup_by(|left, right| left.backup_id == right.backup_id);
    Ok(classes)
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
    state_store: &crate::runtime::input::StateStoreHandle,
    principal_did: &arkret_sdk::Did,
    session: &arkret_sdk::RecoverySession,
    proof_outcome: &arkret_sdk::RecoverySessionProofSubmitOutcome,
    recovery_words: &str,
) -> anyhow::Result<CompletedFreshDeviceRecovery> {
    let prepared =
        prepare_pcr_policy_recovery(api, principal_did, session, proof_outcome, recovery_words)
            .await?;
    let session = &prepared.verified_session;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let restore_payload = super::fetch_mls_restore_payload_with_recovery_session_unlock_proof(
        api,
        session.account_id.principal_id.as_str(),
        session.requesting_device_id.as_str(),
        session,
    )
    .await?;
    // The restore report is intentionally not bound: the returned summary was
    // only ever stored in a transaction field that was retired as never-read;
    // the restore side effects inside the write guard are what matters here.
    super::restore_mls_history_with_recovery_key_from_payload(
        &restore_payload,
        state_store,
        secure_store.as_ref(),
        &session.account_id,
        session.account_id.principal_id.as_str(),
        session.requesting_device_id.as_str(),
        prepared.recovery_private_key.as_slice(),
        (session.policy_id.as_str(), session.policy_version),
    )
    .await?;
    state_store
        .read(crate::state::LocalStateStore::begin_durable_flush)?
        .wait()
        .await?;

    let transaction_id = prepared.create_request.transaction_id.clone();
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
        .create_or_resume(prepared.create_request, None)
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
            crate::fresh_device_recovery::RecoveryTerminalObservation {
                policy_id: session.policy_id.clone(),
                policy_version: session.policy_version,
                trust_domain: session.trust_domain.clone(),
                proof_summary: arkret_models_crypto::RecoveryProofSummary {
                    kind: prepared.proof_summary.kind,
                    proof_digest: prepared.proof_summary.proof_digest,
                    quorum_participant_count: None,
                },
                backup_classes_unlocked: recovery_backup_classes_unlocked(&restore_payload)?,
                welcome_count: 0,
                welcome_realm_summary: None,
                started_at: session.created_at,
                completed_at: crate::clock::now_utc(),
            },
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
    let binding = transaction
        .recovery_plan()
        .map(|plan| &plan.binding)
        .ok_or_else(|| anyhow::anyhow!("completed transaction lost its PCR-policy binding"))?
        .clone();
    crate::security_transaction::clear_pending_fresh_device_recovery(secure_store.as_ref())?;
    Ok(CompletedFreshDeviceRecovery {
        transaction_id,
        readiness: crate::fresh_device_recovery::RecoveryReadinessEvidence {
            transaction_id: transaction.transaction_id,
            terminal_receipt_id: binding.terminal_receipt_id,
            authorization_event_id: binding.authorize_event_id,
        },
        standard_grant_installed: false,
    })
}

/// Resume the byte-identical durable request after reload or response loss.
/// Recovery words are re-entered; they are never part of the persisted plan.
pub(crate) async fn resume_pending_pcr_policy_recovery(
    api: &crate::transport::TransportClient,
    state_store: &crate::runtime::input::StateStoreHandle,
    recovery_words: &str,
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
    let create: SecurityTransactionCreateRequest =
        serde_json::from_slice(&local.canonical_create_request)?;
    let SecurityTransactionCreateRequest::Recovery(create) = create else {
        anyhow::bail!("pending fresh-device recovery is not a recovery transaction");
    };
    let engine = crate::security_transaction::security_transaction_engine(
        api.sdk_http_client()?,
        secure_store.clone(),
    );
    let workflow = crate::fresh_device_recovery::FreshDeviceRecovery::new(engine);
    let mut transaction = workflow
        .create_or_resume(create, local.staged_secret_ref)
        .await?;
    if let Some(retried) = workflow
        .retry_byte_identical_pending(&transaction_id)
        .await?
    {
        transaction = retried;
    }
    reject_terminal_recovery_transaction(&transaction, secure_store.as_ref())?;
    let binding = transaction
        .recovery_plan()
        .map(|plan| &plan.binding)
        .ok_or_else(|| anyhow::anyhow!("pending recovery lost its PCR-policy binding"))?
        .clone();
    let session = api
        .recovery_session(binding.recovery_session_id.as_str())
        .await?;
    session.validate_shape()?;
    let proof_summary = session
        .proof_summary
        .clone()
        .ok_or_else(|| anyhow::anyhow!("verified recovery session omitted proof summary"))?;
    let recovery_material =
        arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
            recovery_words,
            "",
            0,
        )?;
    let restore_payload = super::fetch_mls_restore_payload_with_recovery_session_unlock_proof(
        api,
        session.account_id.principal_id.as_str(),
        session.requesting_device_id.as_str(),
        &session,
    )
    .await?;
    super::restore_mls_history_with_recovery_key_from_payload(
        &restore_payload,
        state_store,
        secure_store.as_ref(),
        &session.account_id,
        session.account_id.principal_id.as_str(),
        session.requesting_device_id.as_str(),
        &recovery_material.backup_hpke_serialized_private_key,
        (session.policy_id.as_str(), session.policy_version),
    )
    .await?;
    state_store
        .read(crate::state::LocalStateStore::begin_durable_flush)?
        .wait()
        .await?;
    if !crate::fresh_device_recovery::transaction_is_completed(&transaction) {
        let signer = crate::event_signer::active_signer()
            .ok_or_else(|| anyhow::anyhow!("replacement device signer is unavailable"))?;
        let terminal = crate::fresh_device_recovery::sign_recovery_terminal_commit_continue(
            &transaction,
            crate::fresh_device_recovery::RecoveryTerminalObservation {
                policy_id: session.policy_id.clone(),
                policy_version: session.policy_version,
                trust_domain: session.trust_domain.clone(),
                proof_summary: arkret_models_crypto::RecoveryProofSummary {
                    kind: proof_summary.kind,
                    proof_digest: proof_summary.proof_digest,
                    quorum_participant_count: None,
                },
                backup_classes_unlocked: recovery_backup_classes_unlocked(&restore_payload)?,
                welcome_count: 0,
                welcome_realm_summary: None,
                started_at: session.created_at,
                completed_at: crate::clock::now_utc(),
            },
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
    let binding = transaction
        .recovery_plan()
        .map(|plan| &plan.binding)
        .ok_or_else(|| anyhow::anyhow!("completed recovery transaction has no terminal binding"))?;
    let readiness = crate::fresh_device_recovery::RecoveryReadinessEvidence {
        transaction_id: transaction.transaction_id.clone(),
        terminal_receipt_id: binding.terminal_receipt_id.clone(),
        authorization_event_id: binding.authorize_event_id.clone(),
    };
    crate::security_transaction::clear_pending_fresh_device_recovery(secure_store.as_ref())?;
    Ok(Some(CompletedFreshDeviceRecovery {
        transaction_id,
        readiness,
        standard_grant_installed: false,
    }))
}
