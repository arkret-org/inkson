//! PCR-policy fresh-device recovery.
//!
//! Recovery is deliberately a closed two-event unit. The Recovery Key derives
//! the current DID root and signs `ak.device.reanchor`; the replacement device
//! signs its own `ak.device.authorize`. No service or second person is an
//! identity authority in this path.

use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizationBindingKind, DeviceOrPrincipalRef, DeviceReanchorPayload,
    UnsignedDeviceAuthorizePayload, device_authorize_payload_digest,
};
use arkret_models_crypto::RecoveryAuthorityKind;
use arkret_wire::{
    EventInitialSubmission, EventRef, EventsSubmitBatchRequestBody, Hash, NonEmptyString,
    PcrPolicyRecoveryBinding, PcrPolicyRecoveryPlan, PreparedEventUnit, ReceiptId,
    RecoveryIdentityModel, RecoveryPreparedPlan, RecoveryTransactionCreateRequest,
    SecurityTransaction, SecurityTransactionCreateRequest, SecurityTransactionResultKind,
    SecurityTransactionStep, TransactionId,
};
use dioxus::prelude::WritableExt as _;
use zeroize::Zeroizing;

fn non_empty(value: String) -> anyhow::Result<NonEmptyString> {
    NonEmptyString::new(value).map_err(anyhow::Error::msg)
}

pub(crate) struct PreparedPcrPolicyRecovery {
    pub create_request: RecoveryTransactionCreateRequest,
    pub proof_summary: arkret_sdk::ProofSummary,
    pub recovery_private_key: Zeroizing<[u8; 32]>,
    pub verified_session: arkret_sdk::RecoverySessionState,
}

pub(crate) struct CompletedFreshDeviceRecovery {
    pub transaction_id: TransactionId,
    pub readiness: crate::fresh_device_recovery::RecoveryReadinessEvidence,
    pub standard_grant_installed: bool,
}

pub(crate) async fn prepare_pcr_policy_recovery(
    api: &crate::transport::TransportClient,
    principal_did: &arkret_sdk::Did,
    session: &arkret_sdk::RecoverySessionState,
    proof_outcome: &arkret_sdk::RecoverySessionProofSubmitOutcome,
    recovery_words: &str,
) -> anyhow::Result<PreparedPcrPolicyRecovery> {
    if proof_outcome.recovery_session_id != session.recovery_session_id
        || proof_outcome.state != arkret_sdk::SessionState::Verified
    {
        anyhow::bail!("recovery proof outcome did not verify the requested session");
    }
    let verified_session = api
        .recovery_session(session.recovery_session_id.as_str())
        .await?;
    verified_session.validate()?;
    if arkret_sdk::project_did_to_core_id(principal_did)?
        != verified_session.account_id.principal_id
    {
        anyhow::bail!("selected recovery principal did does not match the verified session");
    }
    if verified_session.state != arkret_sdk::SessionState::Verified
        || verified_session.identity_model != arkret_sdk::RecoveryIdentityModel::PcrPolicy
        || verified_session.recovery_session_id != session.recovery_session_id
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

    let http = api.sdk_http_client()?;
    let history =
        crate::identity::history::fetch_complete_identity_history(&http, principal_did).await?;
    if history.method != arkret_sdk::DidMethodUri::Webvh || history.native_history != Some(true) {
        anyhow::bail!("principal DID does not expose native did:webvh history");
    }
    let previous_entry = history
        .entries
        .last()
        .ok_or_else(|| anyhow::anyhow!("principal DID history is empty"))?;
    let previous_did_version = previous_entry
        .get("versionId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("DID history head omits versionId"))?;
    let current_root_generation = did_webvh_version_sequence(previous_did_version)?;
    let root_material =
        arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
            recovery_words,
            "",
            current_root_generation,
        )?;
    if previous_entry
        .get("versionId")
        .and_then(serde_json::Value::as_str)
        != Some(previous_did_version)
        || verified_session.registry_head
            != Hash::new(arkret_sdk::canonical::canonical_sha256(previous_entry)?)?
    {
        anyhow::bail!("DID history head changed after the recovery snapshot");
    }
    let active_update_keys = previous_entry
        .pointer("/parameters/updateKeys")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("DID history head omits active update keys"))?;
    if active_update_keys.as_slice()
        != [serde_json::Value::String(
            root_material.root_public_key_multikey.clone(),
        )]
    {
        anyhow::bail!("recovery secret does not control the accepted DID history head");
    }
    let root_verification_method = format!(
        "did:key:{key}#{key}",
        key = root_material.root_public_key_multikey.as_str()
    );

    let submitter = api.event_submitter()?;
    let scope_ref = verified_session
        .publication_authority_context
        .scope_ref
        .clone();
    let frontier = submitter
        .events_frontier_actor(
            verified_session.account_id.principal_id.as_str(),
            scope_ref.realm_id().as_str(),
        )
        .await?;
    frontier.validate()?;
    let authorize_actor_seq = frontier
        .next_actor_seq
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("recovery actor sequence exhausted"))?;
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
    let authorize_payload = UnsignedDeviceAuthorizePayload::new(
        verified_session.requesting_device_id.clone(),
        non_empty(device_public_key)?,
        non_empty(hpke_key)?,
        algorithms,
        Some(non_empty("Ed25519".to_owned())?),
        DeviceOrPrincipalRef::Principal(verified_session.account_id.principal_id.clone()),
        None,
        created_at,
        None,
        DeviceAuthorizationBindingKind::PcrRecovery,
        Some(verified_session.recovery_session_id.clone()),
    )?;
    let authorize_signature =
        arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(device_signer.sign_raw(
            &authorize_payload.device_possession_signature_input(&verified_session.account_id)?,
        )?))
        .map_err(anyhow::Error::msg)?;
    let authorize_payload = authorize_payload.attach_signature(authorize_signature)?;
    let digest_suite = arkret_sdk::canonical::DigestSuite::Sha256;
    let reanchor_payload = exact_device_reanchor_payload(
        &verified_session,
        previous_device_generation,
        result_device_generation,
        device_authorize_payload_digest(&serde_json::to_value(&authorize_payload)?, digest_suite)?,
    )?;

    let reexpiry_start_hlc = crate::signing_stamp::issue_protocol_hlc_for_active_device(
        verified_session.account_id.principal_id.as_str(),
        scope_ref.realm_id().as_str(),
    )?;
    let authorize_hlc = crate::signing_stamp::issue_protocol_hlc_for_active_device(
        verified_session.account_id.principal_id.as_str(),
        scope_ref.realm_id().as_str(),
    )?;
    let station_id = crate::operation::authoring_station_id()?;
    if station_id != verified_session.account_id.station_id {
        anyhow::bail!("verified recovery session belongs to a different AccountId");
    }
    let mut reanchor = arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::DeviceReanchor>::new(
        scope_ref.clone(),
        arkret_sdk::ActorId::account(verified_session.account_id.clone()),
        reanchor_payload,
    )?
    .with_prev_refs(frontier.frontier_event_ids)
    .with_ref(EventRef::new(
        previous_did_version.to_owned(),
        "did_recovery_anchor",
    ))
    .author_with_digest_suite(
        frontier.next_actor_seq,
        reexpiry_start_hlc,
        created_at,
        digest_suite,
    )?;
    let root_did = arkret_sdk::Did::new(
        root_verification_method
            .split_once('#')
            .map_or(root_verification_method.as_str(), |(did, _)| did)
            .to_owned(),
    )?;
    let root_method =
        arkret_sdk::DidUrl::new(root_verification_method).map_err(anyhow::Error::msg)?;
    let root_signer = arkret_sdk::Ed25519PayloadSigner::from_did_key_seed(
        root_material.root_seed,
        root_did,
        root_method.clone(),
    );
    arkret_sdk::signatures::sign_event(
        &mut reanchor,
        &root_signer,
        &root_method,
        arkret_sdk::signatures::SignEventOptions::new().with_created_at(created_at),
    )?;
    let reanchor_event_id = reanchor.event_id().clone();

    let mut authorize =
        arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::DeviceAuthorize>::new(
            scope_ref,
            arkret_sdk::ActorId::account(verified_session.account_id.clone()),
            authorize_payload,
        )?
        .with_prev_refs(vec![reanchor_event_id.clone()])
        .author_with_digest_suite(
            authorize_actor_seq,
            authorize_hlc,
            created_at,
            digest_suite,
        )?;
    device_signer.sign_sdk_event_with_context(
        &mut authorize,
        crate::event_signer::EventProofContext::default().with_digest_suite(digest_suite),
    )?;
    let authorize_event_id = authorize.event_id().clone();
    let reanchor_submission = EventsSubmitBatchRequestBody {
        events: vec![
            EventInitialSubmission::online(reanchor.into_event()),
            EventInitialSubmission::online(authorize.into_event()),
        ],
    };

    let proof_summary = verified_session
        .proof_summary
        .clone()
        .ok_or_else(|| anyhow::anyhow!("verified recovery session omitted proof summary"))?;
    let plan = PcrPolicyRecoveryPlan {
        binding: PcrPolicyRecoveryBinding {
            identity_model: RecoveryIdentityModel::PcrPolicy,
            recovery_session_id: verified_session.recovery_session_id.clone(),
            replacement_device_id: verified_session.requesting_device_id.clone(),
            reanchor_event_id,
            authorize_event_id,
            terminal_receipt_id: ReceiptId::new(format!(
                "ak:receipt:{}",
                crate::operation::uuid_v7()
            ))?,
        },
        recovery_session_snapshot_digest: Hash::new(arkret_sdk::canonical::canonical_sha256(
            &verified_session,
        )?)?,
        proof_digest: proof_summary.proof_digest.clone(),
        previous_model_generation_ref: previous_device_generation,
        result_model_generation_ref: result_device_generation,
        reanchor_unit: PreparedEventUnit::new(digest_suite, reanchor_submission)?,
    };
    let create_request = RecoveryTransactionCreateRequest::new(
        TransactionId::new(format!("ak:transaction:{}", crate::operation::uuid_v7()))?,
        verified_session.account_id.clone(),
        std::cmp::min(
            verified_session.expires_at,
            crate::clock::now_utc() + chrono::Duration::hours(1),
        ),
        RecoveryPreparedPlan::PcrPolicy(plan),
    )?;
    Ok(PreparedPcrPolicyRecovery {
        create_request,
        proof_summary,
        recovery_private_key: Zeroizing::new(backup_material.backup_hpke_serialized_private_key),
        verified_session,
    })
}

fn exact_device_reanchor_payload(
    session: &arkret_sdk::RecoverySessionState,
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
        pre_fence_seal_frontier: Some(session.accepted_seal_frontier.clone()),
        replacement_authorize_payload_digest,
    };
    payload.validate().map_err(anyhow::Error::msg)?;
    Ok(payload)
}

fn did_webvh_version_sequence(version_id: &str) -> anyhow::Result<u64> {
    version_id
        .split_once('-')
        .and_then(|(sequence, _)| sequence.parse::<u64>().ok())
        .filter(|sequence| *sequence > 0)
        .ok_or_else(|| anyhow::anyhow!("DID generation is not a canonical did:webvh versionId"))
}

fn recovery_backup_classes_unlocked(
    restore_payload: &serde_json::Value,
) -> anyhow::Result<Vec<arkret_models_crypto::RecoveryBackupClassUnlocked>> {
    let mut classes = garth::mls::backup_selection::iter_backup_bodies(restore_payload)
        .filter(|backup| {
            backup
                .get("ciphertext")
                .and_then(serde_json::Value::as_str)
                .is_some()
        })
        .map(|backup| {
            Ok(arkret_models_crypto::RecoveryBackupClassUnlocked {
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
    if let Some(result) = transaction.terminal_kind()
        && result != SecurityTransactionResultKind::Completed
    {
        crate::security_transaction::clear_pending_fresh_device_recovery(secure_store)?;
        anyhow::bail!("recovery transaction ended in {result:?}");
    }
    Ok(())
}

pub(crate) async fn execute_pcr_policy_recovery(
    api: &crate::transport::TransportClient,
    mut state_store: dioxus::prelude::SyncSignal<crate::state::LocalStateStore>,
    principal_did: &arkret_sdk::Did,
    session: &arkret_sdk::RecoverySessionState,
    proof_outcome: &arkret_sdk::RecoverySessionProofSubmitOutcome,
    recovery_words: &str,
) -> anyhow::Result<CompletedFreshDeviceRecovery> {
    let prepared =
        prepare_pcr_policy_recovery(api, principal_did, session, proof_outcome, recovery_words)
            .await?;
    let session = &prepared.verified_session;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
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
        session,
        &recovery_material,
    )
    .await?;
    // The restore report is intentionally not bound: the returned summary was
    // only ever stored in a transaction field that was retired as never-read;
    // the restore side effects inside the write guard are what matters here.
    {
        let mut store = state_store.write();
        super::restore_mls_history_with_recovery_key_from_payload(
            &restore_payload,
            &mut store,
            secure_store.as_ref(),
            &session.account_id,
            session.account_id.principal_id.as_str(),
            session.requesting_device_id.as_str(),
            prepared.recovery_private_key.as_slice(),
            (session.policy_id.as_str(), session.policy_version),
        )
        .await?;
    }
    {
        let store = state_store.write();
        let barrier = store.begin_durable_flush()?;
        drop(store);
        barrier.wait().await?;
    }

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
    while transaction.next_required_step()? == Some(SecurityTransactionStep::SubmitReanchorUnit) {
        transaction = workflow.continue_server_step(&transaction).await?;
    }
    if !transaction.is_completed() {
        let signer = crate::event_signer::active_signer()
            .ok_or_else(|| anyhow::anyhow!("replacement device signer is unavailable"))?;
        let terminal = crate::fresh_device_recovery::sign_terminal_receipt_continue(
            &transaction,
            crate::fresh_device_recovery::RecoveryTerminalObservation {
                policy_id: session.policy_id.clone(),
                policy_version: session.policy_version,
                trust_domain: session.trust_domain.clone(),
                proof_summary: arkret_models_crypto::RecoveryProofSummary {
                    kind: prepared.proof_summary.kind,
                    proof_digest: prepared.proof_summary.proof_digest,
                    quorum_participant_count: None,
                    share_ids: None,
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
    if !transaction.is_completed() {
        anyhow::bail!("recovery transaction did not reach completed state");
    }
    let binding = transaction
        .recovery_binding()
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
    mut state_store: dioxus::prelude::SyncSignal<crate::state::LocalStateStore>,
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
        .recovery_binding()
        .ok_or_else(|| anyhow::anyhow!("pending recovery lost its PCR-policy binding"))?
        .clone();
    let session = api
        .recovery_session(binding.recovery_session_id.as_str())
        .await?;
    session.validate()?;
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
        &recovery_material,
    )
    .await?;
    {
        let mut store = state_store.write();
        super::restore_mls_history_with_recovery_key_from_payload(
            &restore_payload,
            &mut store,
            secure_store.as_ref(),
            &session.account_id,
            session.account_id.principal_id.as_str(),
            session.requesting_device_id.as_str(),
            &recovery_material.backup_hpke_serialized_private_key,
            (session.policy_id.as_str(), session.policy_version),
        )
        .await?;
    }
    {
        let store = state_store.write();
        let barrier = store.begin_durable_flush()?;
        drop(store);
        barrier.wait().await?;
    }
    while transaction.next_required_step()? == Some(SecurityTransactionStep::SubmitReanchorUnit) {
        transaction = workflow.continue_server_step(&transaction).await?;
    }
    if !transaction.is_completed() {
        let signer = crate::event_signer::active_signer()
            .ok_or_else(|| anyhow::anyhow!("replacement device signer is unavailable"))?;
        let terminal = crate::fresh_device_recovery::sign_terminal_receipt_continue(
            &transaction,
            crate::fresh_device_recovery::RecoveryTerminalObservation {
                policy_id: session.policy_id.clone(),
                policy_version: session.policy_version,
                trust_domain: session.trust_domain.clone(),
                proof_summary: arkret_models_crypto::RecoveryProofSummary {
                    kind: proof_summary.kind,
                    proof_digest: proof_summary.proof_digest,
                    quorum_participant_count: None,
                    share_ids: None,
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
    if !transaction.is_completed() {
        anyhow::bail!("pending recovery did not reach completed state");
    }
    let binding = transaction
        .recovery_binding()
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
