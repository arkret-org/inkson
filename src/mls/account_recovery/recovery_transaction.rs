//! Root-anchored fresh-device recovery.
//!
//! Recovery is deliberately a closed two-event unit. The Recovery Key derives
//! the current DID root and signs `ak.device.reanchor`; the replacement device
//! signs its own `ak.device.authorize`. No service or second person is an
//! identity authority in this path.

use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizationBindingKind, DeviceOrPrincipalRef, DeviceReanchorPayload,
    UnsignedDeviceAuthorizePayload, device_authorize_payload_digest,
};
use arkret_wire::{
    CanonicalPublicMaterial, Event, EventInitialSubmission, EventRef, EventsSubmitBatchRequestBody,
    Hash, NonEmptyString, PreparedDidPublication, PreparedEventUnit, ReceiptId, RecoveryBinding,
    RecoveryIdentityModel, RecoveryPreparedPlan, RecoveryTransactionCreateRequest,
    RootAnchoredRecoveryBinding, RootAnchoredRecoveryPlan, SecurityTransaction,
    SecurityTransactionBinding, SecurityTransactionCreateRequest, SecurityTransactionState,
    SecurityTransactionStep, TransactionId,
};
use dioxus::prelude::WritableExt as _;
use zeroize::Zeroizing;

fn non_empty(value: String) -> anyhow::Result<NonEmptyString> {
    NonEmptyString::new(value).map_err(anyhow::Error::msg)
}

pub(crate) struct PreparedRootAnchoredRecovery {
    pub create_request: RecoveryTransactionCreateRequest,
    pub proof_summary: arkret_sdk::ProofSummary,
    pub recovery_private_key: Zeroizing<[u8; 32]>,
    pub verified_session: arkret_sdk::RecoverySessionState,
}

pub(crate) struct CompletedFreshDeviceRecovery {
    pub transaction_id: TransactionId,
    pub readiness: crate::fresh_device_recovery::RecoveryReadinessEvidence,
    pub restore_report: super::RestoreReport,
    pub standard_grant_installed: bool,
}

pub(crate) async fn prepare_root_anchored_recovery(
    api: &crate::transport::TransportClient,
    session: &arkret_sdk::RecoverySessionState,
    proof_outcome: &arkret_sdk::RecoverySessionProofSubmitOutcome,
    recovery_words: &str,
) -> anyhow::Result<PreparedRootAnchoredRecovery> {
    if proof_outcome.recovery_session_id != session.recovery_session_id
        || proof_outcome.state != arkret_sdk::SessionState::Verified
    {
        anyhow::bail!("recovery proof outcome did not verify the requested session");
    }
    let verified_session = api
        .recovery_session(session.recovery_session_id.as_str())
        .await?;
    verified_session.validate()?;
    if verified_session.state != arkret_sdk::SessionState::Verified
        || verified_session.identity_model != arkret_sdk::RecoveryIdentityModel::RootAnchored
        || verified_session.recovery_session_id != session.recovery_session_id
        || verified_session.proof_summary != proof_outcome.proof_summary
    {
        anyhow::bail!("recovery session is not the verified root-anchored snapshot");
    }

    let previous_generation = verified_session
        .current_device_generation_ref
        .as_str()
        .to_owned();
    let current_root_generation = did_webvh_version_sequence(&previous_generation)?;
    let root_material =
        arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
            recovery_words,
            "",
            current_root_generation,
        )?;
    let backup_material =
        arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
            recovery_words,
            "",
            0,
        )?;

    let http = api.sdk_http_client()?;
    let history = crate::identity::history::fetch_complete_identity_history(
        &http,
        &verified_session.principal_id,
    )
    .await?;
    if history.method != "did:webvh" || history.native_history != Some(true) {
        anyhow::bail!("principal DID does not expose native did:webvh history");
    }
    let previous_entry = history
        .entries
        .last()
        .ok_or_else(|| anyhow::anyhow!("principal DID history is empty"))?;
    if previous_entry
        .get("versionId")
        .and_then(serde_json::Value::as_str)
        != Some(previous_generation.as_str())
        || verified_session.registry_head
            != Hash::new(arkret_sdk::canonical::canonical_sha256(previous_entry)?)?
    {
        anyhow::bail!("DID history head changed after the recovery snapshot");
    }
    let document = http
        .identity_document(verified_session.principal_id.as_str(), None)
        .await?;
    if document.head_event_digest.as_ref() != Some(&verified_session.registry_head) {
        anyhow::bail!("DID document head changed after the recovery snapshot");
    }
    let document_state = serde_json::Value::Object(
        document
            .did_document
            .clone()
            .into_iter()
            .collect::<serde_json::Map<_, _>>(),
    );
    let local_id = verified_session
        .principal_id
        .as_str()
        .rsplit(':')
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("principal did:webvh has no local id"))?;
    let rotation = arkret_sdk::webvh::prepare_principal_rotation(
        &arkret_sdk::webvh::PrincipalRotationInput {
            did: verified_session.principal_id.as_str(),
            local_id,
            previous_entries: &history.entries,
            version_time: crate::clock::now_utc(),
            current_root_seed: &root_material.root_seed,
            next_root_public_key_multibase: &root_material.next_root_public_key_multikey,
            state: &document_state,
        },
    )?;
    if rotation.previous_version_id != previous_generation {
        anyhow::bail!("prepared DID rotation does not immediately follow the recovery snapshot");
    }

    let submitter = api.event_submitter()?;
    let scope_ref = verified_session
        .publication_authority_context
        .scope_ref
        .clone();
    let frontier = submitter
        .events_frontier_actor(
            verified_session.principal_id.as_str(),
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
    let device_public_key = device_signer
        .public_key_multibase()
        .ok_or_else(|| anyhow::anyhow!("replacement device signer has no Ed25519 public key"))?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let (_, hpke_public_key) = crate::mls::runtime::load_or_create_device_hpke_keypair(
        secure_store.as_ref(),
        verified_session.principal_id.as_str(),
        verified_session.requesting_device_id.as_str(),
    )?;
    let hpke_key = crate::identity::did_key::encode_x25519_multibase(&hpke_public_key);
    let algorithms = crate::identity::principal_genesis::INKSON_DEVICE_ALGORITHMS
        .iter()
        .map(|value| non_empty((*value).to_owned()))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let authorize_payload = UnsignedDeviceAuthorizePayload::new(
        verified_session.principal_id.clone(),
        verified_session.requesting_device_id.clone(),
        non_empty(device_public_key)?,
        non_empty(hpke_key)?,
        algorithms,
        Some(non_empty("Ed25519".to_owned())?),
        DeviceOrPrincipalRef::Did(verified_session.principal_id.clone()),
        None,
        created_at,
        None,
        DeviceAuthorizationBindingKind::RootAnchored,
        Some(verified_session.recovery_session_id.clone()),
    )?;
    let authorize_signature = arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(
        device_signer.sign_raw(&authorize_payload.device_possession_signature_input()?)?,
    ))
    .map_err(anyhow::Error::msg)?;
    let authorize_payload = authorize_payload.attach_signature(authorize_signature)?;
    let authorize_payload_wire = serde_json::to_value(&authorize_payload)?;
    let digest_suite = arkret_sdk::canonical::DigestSuite::Sha256;
    let reanchor_payload = DeviceReanchorPayload {
        principal_id: verified_session.principal_id.clone(),
        did_version_id: non_empty(rotation.version_id.clone())?,
        previous_device_generation: non_empty(previous_generation.clone())?,
        new_device_generation: non_empty(rotation.version_id.clone())?,
        pre_fence_basis: verified_session.accepted_seal_frontier.clone(),
        replacement_authorize_payload_digest: device_authorize_payload_digest(
            &authorize_payload_wire,
            digest_suite,
        )?,
    };

    let reanchor_hlc = crate::signing_stamp::issue_protocol_hlc_for_active_device(
        verified_session.principal_id.as_str(),
        scope_ref.realm_id().as_str(),
    )?;
    let authorize_hlc = crate::signing_stamp::issue_protocol_hlc_for_active_device(
        verified_session.principal_id.as_str(),
        scope_ref.realm_id().as_str(),
    )?;
    let mut reanchor = arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::DeviceReanchor>::new(
        scope_ref.clone(),
        verified_session.principal_id.clone(),
        reanchor_payload,
    )?
    .with_prev_refs(frontier.frontier_event_ids)
    .with_ref(EventRef::new(
        rotation.version_id.clone(),
        "did_recovery_anchor",
    ))
    .author(frontier.next_actor_seq, reanchor_hlc, created_at)?;
    let root_did = arkret_sdk::Did::new(
        rotation
            .current_root_verification_method
            .split_once('#')
            .map_or(
                rotation.current_root_verification_method.as_str(),
                |(did, _)| did,
            )
            .to_owned(),
    )?;
    let root_method = arkret_sdk::DidUrl::new(rotation.current_root_verification_method.clone())
        .map_err(anyhow::Error::msg)?;
    let root_signer = arkret_sdk::Ed25519PayloadSigner::from_did_key_seed(
        root_material.root_seed,
        root_did,
        root_method.clone(),
    );
    arkret_sdk::signatures::sign_event_with_digest_suite(
        &mut reanchor,
        &root_signer,
        &root_method,
        digest_suite,
        arkret_sdk::signatures::SignEventOptions::new().with_created_at(created_at),
    )?;
    let reanchor_event_id = reanchor.event_id.clone();

    let mut authorize =
        arkret_sdk::TypedEventDraft::<arkret_sdk::event_spec::DeviceAuthorize>::new(
            scope_ref,
            verified_session.principal_id.clone(),
            authorize_payload,
        )?
        .with_prev_refs(vec![reanchor_event_id.clone()])
        .author(authorize_actor_seq, authorize_hlc, created_at)?;
    device_signer.sign_sdk_event_with_context(
        &mut authorize,
        crate::event_signer::EventProofContext::default().with_digest_suite(digest_suite),
    )?;
    let authorize_event_id = authorize.event_id.clone();
    let reanchor_submission = EventsSubmitBatchRequestBody {
        events: vec![
            EventInitialSubmission::online(reanchor),
            EventInitialSubmission::online(authorize),
        ],
    };

    let previous_entry_ref = format!(
        "{}?versionId={}",
        verified_session.principal_id, rotation.previous_version_id
    );
    let expected_entry_ref = format!(
        "{}?versionId={}",
        verified_session.principal_id, rotation.version_id
    );
    let did_entry = CanonicalPublicMaterial::canonical_json(rotation.log_entry)?;
    let coordinator_service_id = arkret_sdk::Did::new(submitter.service_id().await?)?;
    let did_publication = PreparedDidPublication {
        registry_service_id: coordinator_service_id.clone(),
        registry_endpoint: http
            .base_url()
            .join("/_arkret/root/identity/submit-did-operation")?
            .to_string(),
        previous_entry_ref,
        expected_entry_ref: expected_entry_ref.clone(),
        canonical_entry_base64url: did_entry.canonical_bytes_base64url,
        entry_digest: did_entry.digest,
    };
    let proof_summary = verified_session
        .proof_summary
        .clone()
        .ok_or_else(|| anyhow::anyhow!("verified recovery session omitted proof summary"))?;
    let plan = RootAnchoredRecoveryPlan {
        identity_model: RecoveryIdentityModel::RootAnchored,
        recovery_session_snapshot_digest: Hash::new(arkret_sdk::canonical::canonical_sha256(
            &verified_session,
        )?)?,
        proof_digest: proof_summary.proof_digest.clone(),
        previous_model_generation_ref: previous_generation,
        result_model_generation_ref: rotation.version_id,
        did_publication,
        reanchor_unit: PreparedEventUnit::new(
            coordinator_service_id,
            serde_json::to_value(reanchor_submission)?,
        )?,
    };
    let create_request = RecoveryTransactionCreateRequest::new(
        TransactionId::new(format!("ak:transaction:{}", crate::operation::uuid_v7()))?,
        verified_session.principal_id.clone(),
        std::cmp::min(
            verified_session.expires_at,
            crate::clock::now_utc() + chrono::Duration::hours(1),
        ),
        RecoveryBinding::RootAnchored(RootAnchoredRecoveryBinding {
            identity_model: RecoveryIdentityModel::RootAnchored,
            recovery_session_id: verified_session.recovery_session_id.clone(),
            replacement_device_id: verified_session.requesting_device_id.clone(),
            did_entry_ref: expected_entry_ref,
            reanchor_event_id,
            authorize_event_id,
            terminal_receipt_id: ReceiptId::new(format!(
                "ak:receipt:{}",
                crate::operation::uuid_v7()
            ))?,
        }),
        RecoveryPreparedPlan::RootAnchored(plan),
    )?;
    Ok(PreparedRootAnchoredRecovery {
        create_request,
        proof_summary,
        recovery_private_key: Zeroizing::new(backup_material.backup_hpke_serialized_private_key),
        verified_session,
    })
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
    let mut classes = super::selection::iter_backup_bodies(restore_payload)
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
    if transaction.state.is_terminal() && transaction.state != SecurityTransactionState::Completed {
        crate::security_transaction::clear_pending_fresh_device_recovery(secure_store)?;
        anyhow::bail!("recovery transaction ended in {:?}", transaction.state);
    }
    Ok(())
}

pub(crate) async fn execute_root_anchored_recovery(
    api: &crate::transport::TransportClient,
    mut state_store: dioxus::prelude::SyncSignal<crate::state::LocalStateStore>,
    session: &arkret_sdk::RecoverySessionState,
    proof_outcome: &arkret_sdk::RecoverySessionProofSubmitOutcome,
    recovery_words: &str,
) -> anyhow::Result<CompletedFreshDeviceRecovery> {
    let prepared =
        prepare_root_anchored_recovery(api, session, proof_outcome, recovery_words).await?;
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
        session.principal_id.as_str(),
        session.requesting_device_id.as_str(),
        session,
        &recovery_material,
    )
    .await?;
    let restore_report = {
        let mut store = state_store.write();
        super::restore_mls_history_with_recovery_key_from_payload(
            &restore_payload,
            &mut store,
            secure_store.as_ref(),
            session.principal_id.as_str(),
            session.requesting_device_id.as_str(),
            prepared.recovery_private_key.as_slice(),
            (session.policy_id.as_str(), session.policy_version),
        )?
    };
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
    while matches!(
        transaction.next_required_step,
        Some(
            SecurityTransactionStep::PublishDidEntry | SecurityTransactionStep::SubmitReanchorUnit
        )
    ) {
        transaction = workflow.continue_server_step(&transaction).await?;
    }
    if transaction.state != SecurityTransactionState::Completed {
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
    if transaction.state != SecurityTransactionState::Completed {
        anyhow::bail!("recovery transaction did not reach completed state");
    }
    let SecurityTransactionBinding::Recovery(RecoveryBinding::RootAnchored(binding)) =
        &transaction.binding
    else {
        anyhow::bail!("completed transaction lost its root-anchored binding");
    };
    crate::security_transaction::clear_pending_fresh_device_recovery(secure_store.as_ref())?;
    Ok(CompletedFreshDeviceRecovery {
        transaction_id,
        readiness: crate::fresh_device_recovery::RecoveryReadinessEvidence {
            transaction_id: transaction.transaction_id,
            terminal_receipt_id: binding.terminal_receipt_id.clone(),
            authorization_event_id: binding.authorize_event_id.clone(),
            did_entry_ref: binding.did_entry_ref.clone(),
        },
        restore_report,
        standard_grant_installed: false,
    })
}

/// Resume the byte-identical durable request after reload or response loss.
/// Recovery words are re-entered; they are never part of the persisted plan.
pub(crate) async fn resume_pending_root_anchored_recovery(
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
    let SecurityTransactionBinding::Recovery(RecoveryBinding::RootAnchored(binding)) =
        &transaction.binding
    else {
        anyhow::bail!("pending recovery lost its root-anchored binding");
    };
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
        session.principal_id.as_str(),
        session.requesting_device_id.as_str(),
        &session,
        &recovery_material,
    )
    .await?;
    let restore_report = {
        let mut store = state_store.write();
        super::restore_mls_history_with_recovery_key_from_payload(
            &restore_payload,
            &mut store,
            secure_store.as_ref(),
            session.principal_id.as_str(),
            session.requesting_device_id.as_str(),
            &recovery_material.backup_hpke_serialized_private_key,
            (session.policy_id.as_str(), session.policy_version),
        )?
    };
    {
        let store = state_store.write();
        let barrier = store.begin_durable_flush()?;
        drop(store);
        barrier.wait().await?;
    }
    while matches!(
        transaction.next_required_step,
        Some(
            SecurityTransactionStep::PublishDidEntry | SecurityTransactionStep::SubmitReanchorUnit
        )
    ) {
        transaction = workflow.continue_server_step(&transaction).await?;
    }
    if transaction.state != SecurityTransactionState::Completed {
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
    if transaction.state != SecurityTransactionState::Completed {
        anyhow::bail!("pending recovery did not reach completed state");
    }
    let SecurityTransactionBinding::Recovery(RecoveryBinding::RootAnchored(binding)) =
        &transaction.binding
    else {
        unreachable!("binding was checked above")
    };
    let readiness = crate::fresh_device_recovery::RecoveryReadinessEvidence {
        transaction_id: transaction.transaction_id.clone(),
        terminal_receipt_id: binding.terminal_receipt_id.clone(),
        authorization_event_id: binding.authorize_event_id.clone(),
        did_entry_ref: binding.did_entry_ref.clone(),
    };
    crate::security_transaction::clear_pending_fresh_device_recovery(secure_store.as_ref())?;
    Ok(Some(CompletedFreshDeviceRecovery {
        transaction_id,
        readiness,
        restore_report,
        standard_grant_installed: false,
    }))
}
