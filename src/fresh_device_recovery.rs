//! Durable device-revocation security-rotation helpers.
//!
//! Fresh-device account recovery is authorized by the accepted PCR policy;
//! the replacement device proves possession of its key in the closed unit.

use arkret_models_crypto::{
    ClientStepAttestationArtifact, RecoveryBackupClassUnlocked, RecoveryProofSummary,
    RecoveryReceiptOutcome, RecoveryWelcomeRealmSummary, SecurityTransactionContinueRequest,
    UnsignedRecoveryReceipt, UnsignedRecoveryReceiptBody,
};
use arkret_wire::{
    BackupObjectRef, BackupRotationBinding, BackupRotationKind, BackupRotationPlan, BackupSeriesId,
    CanonicalPublicMaterial, DidCoreId, DidFullId, EventId, EventsSubmitBatchRequestBody, Hash,
    IssueRecoveryCompletionGrantOutcome, IssueRecoveryCompletionGrantRequest, PreparedEventUnit,
    RecoveryPreparedPlan, RecoveryTransactionCreateRequest,
    SecurityRotationTransactionCreateRequest, SecurityTransaction,
    SecurityTransactionCreateRequest, SecurityTransactionPreparedPlan, SecurityTransactionState,
    SecurityTransactionStep, TransactionId, UnsignedClientStepAttestation,
};
use garth::{SecurityTransactionEngine, SecurityTransactionStore, SecurityTransactionTransport};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Default)]
pub struct RecoveryWordsInput {
    words: Zeroizing<String>,
}

impl RecoveryWordsInput {
    pub fn as_str(&self) -> &str {
        self.words.as_str()
    }

    pub fn replace(&mut self, value: impl Into<String>) {
        self.words.zeroize();
        self.words = Zeroizing::new(value.into());
    }

    pub fn normalized(&self) -> Option<Zeroizing<String>> {
        crate::recovery_crypto::normalize_recovery_key_input(self.words.as_str())
            .map(Zeroizing::new)
    }

    pub fn clear(&mut self) {
        self.words.zeroize();
        self.words.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }
}

impl Drop for RecoveryWordsInput {
    fn drop(&mut self) {
        self.words.zeroize();
    }
}

/// Evidence the client requires before presenting a recovered device as
/// usable. The security transaction receipt is authoritative; a local event
/// submission success by itself is deliberately insufficient.
#[derive(Clone, Debug)]
pub struct RecoveryReadinessEvidence {
    pub transaction_id: TransactionId,
    pub terminal_receipt_id: arkret_sdk::ReceiptId,
    pub authorization_event_id: EventId,
}

pub struct RecoveryTerminalObservation {
    pub policy_id: arkret_sdk::PolicyId,
    pub policy_version: u64,
    pub trust_domain: arkret_sdk::TrustDomainId,
    pub proof_summary: RecoveryProofSummary,
    pub backup_classes_unlocked: Vec<RecoveryBackupClassUnlocked>,
    pub welcome_count: u64,
    pub welcome_realm_summary: Option<Vec<RecoveryWelcomeRealmSummary>>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: chrono::DateTime<chrono::Utc>,
}

/// Sign the one client-authored terminal artifact for a PCR-policy
/// recovery. All earlier steps are server continuations over a byte-identical
/// durable plan.
pub fn sign_terminal_receipt_continue(
    resource: &SecurityTransaction,
    observation: RecoveryTerminalObservation,
    signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<SecurityTransactionContinueRequest> {
    resource.validate_structural()?;
    if !resource.requires_device_attestation()? {
        anyhow::bail!("terminal receipt requires canonical device-attestation readiness");
    }
    let SecurityTransactionPreparedPlan::Recovery(RecoveryPreparedPlan::PcrPolicy(plan)) =
        &resource.prepared_plan
    else {
        anyhow::bail!("terminal receipt requires a PCR-policy recovery transaction");
    };
    let binding = &plan.binding;
    if observation.policy_version == 0
        || observation.proof_summary.proof_digest != plan.proof_digest
    {
        anyhow::bail!("terminal observation does not match the verified recovery proof");
    }
    let batch_receipt = resource
        .accepted_steps
        .first()
        .ok_or_else(|| anyhow::anyhow!("accepted re-anchor unit is missing"))?;
    let signer_full_id = DidFullId::new(signer.signer_did().to_owned())?;
    if arkret_sdk::project_full_id_to_core_id(&signer_full_id)? != resource.principal_id {
        anyhow::bail!("recovery receipt signer does not control the recovered principal");
    }
    let verification_method = signer.verification_method_for_principal(&signer_full_id)?;
    let receipt = UnsignedRecoveryReceipt::new(
        UnsignedRecoveryReceiptBody {
            receipt_id: binding.terminal_receipt_id.clone(),
            transaction_id: resource.transaction_id.clone(),
            transaction_request_digest: resource.request_digest.clone(),
            prepared_plan_digest: resource.prepared_plan_digest.clone(),
            principal_id: resource.principal_id.clone(),
            recovery_session_id: binding.recovery_session_id.clone(),
            policy_id: observation.policy_id,
            policy_version: observation.policy_version,
            trust_domain: observation.trust_domain,
            new_device_id: binding.replacement_device_id.clone(),
            identity_model: arkret_sdk::RecoveryIdentityModel::PcrPolicy,
            previous_model_generation_ref: plan.previous_model_generation_ref,
            result_model_generation_ref: plan.result_model_generation_ref,
            authorization_event_id: binding.authorize_event_id.clone(),
            device_list_update_event_id: None,
            reanchor_event_id: Some(binding.reanchor_event_id.clone()),
            reanchor_batch_receipt_id: Some(arkret_sdk::ReceiptId::new(
                batch_receipt.output_ref.clone(),
            )?),
            proof_summary: observation.proof_summary,
            backup_classes_unlocked: observation.backup_classes_unlocked,
            welcome_count: observation.welcome_count,
            welcome_realm_summary: observation.welcome_realm_summary,
            outcome: RecoveryReceiptOutcome::Completed,
            outcome_reason_code: None,
            started_at: observation.started_at,
            completed_at: observation.completed_at,
            extra: Default::default(),
        },
        verification_method.clone(),
    )?;
    let receipt_signature = arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(
        signer.sign_raw(&receipt.signing_payload_bytes()?)?,
    ))
    .map_err(anyhow::Error::msg)?;
    let receipt = receipt.attach_signature(receipt_signature)?;
    receipt.validate()?;

    let artifact = ClientStepAttestationArtifact::RecoveryReceipt(receipt);
    let attestation = UnsignedClientStepAttestation::new(
        SecurityTransactionStep::IssueTerminalReceipt,
        binding.terminal_receipt_id.as_str().to_owned(),
        resource.transaction_id.clone(),
        resource.request_digest.clone(),
        resource.prepared_plan_digest.clone(),
        Hash::new(arkret_sdk::canonical::canonical_sha256(&artifact)?)?,
        artifact,
        verification_method,
    )?;
    let attestation_signature = arkret_sdk::NonEmptyString::new(arkret_sdk::base64url_encode(
        signer.sign_raw(&attestation.signing_bytes()?)?,
    ))
    .map_err(anyhow::Error::msg)?;
    let attestation = attestation.attach_signature(attestation_signature)?;
    attestation.validate_structural()?;
    Ok(SecurityTransactionContinueRequest {
        request_digest: resource.request_digest.clone(),
        prepared_plan_digest: resource.prepared_plan_digest.clone(),
        expected_accepted_step_count: resource.accepted_steps.len().try_into()?,
        client_attestation: Some(attestation),
    })
}

/// Thin UI-facing facade over Garth's byte-identical durable coordinator.
pub struct FreshDeviceRecovery<T, S> {
    engine: SecurityTransactionEngine<T, S>,
}

impl<T, S> FreshDeviceRecovery<T, S>
where
    T: SecurityTransactionTransport,
    S: SecurityTransactionStore,
{
    pub fn new(engine: SecurityTransactionEngine<T, S>) -> Self {
        Self { engine }
    }

    pub async fn create_or_resume(
        &self,
        request: RecoveryTransactionCreateRequest,
        encrypted_staged_material_ref: Option<String>,
    ) -> garth::Result<SecurityTransaction> {
        self.engine
            .create_or_resume(
                &SecurityTransactionCreateRequest::Recovery(request),
                encrypted_staged_material_ref,
            )
            .await
    }

    pub async fn refresh(
        &self,
        transaction_id: &TransactionId,
    ) -> garth::Result<SecurityTransaction> {
        self.engine.refresh(transaction_id).await
    }

    pub async fn continue_server_step(
        &self,
        transaction: &SecurityTransaction,
    ) -> garth::Result<SecurityTransaction> {
        let step = transaction.next_required_step()?.ok_or_else(|| {
            garth::Error::Protocol("recovery transaction has no next step".to_owned())
        })?;
        if step == SecurityTransactionStep::IssueTerminalReceipt {
            return Err(garth::Error::Protocol(
                "terminal receipt requires a signed client attestation".to_owned(),
            ));
        }
        self.engine
            .continue_transaction(
                &transaction.transaction_id,
                &SecurityTransactionContinueRequest {
                    request_digest: transaction.request_digest.clone(),
                    prepared_plan_digest: transaction.prepared_plan_digest.clone(),
                    expected_accepted_step_count: transaction
                        .accepted_steps
                        .len()
                        .try_into()
                        .map_err(|_| {
                            garth::Error::Protocol(
                                "recovery transaction progress exceeds wire limit".to_owned(),
                            )
                        })?,
                    client_attestation: None,
                },
            )
            .await
    }

    pub async fn continue_with_signed_artifact(
        &self,
        transaction_id: &TransactionId,
        request: &SecurityTransactionContinueRequest,
    ) -> garth::Result<SecurityTransaction> {
        self.engine
            .continue_transaction(transaction_id, request)
            .await
    }

    pub async fn retry_byte_identical_pending(
        &self,
        transaction_id: &TransactionId,
    ) -> garth::Result<Option<SecurityTransaction>> {
        self.engine.retry_pending(transaction_id).await
    }

    pub async fn issue_completion_grant(
        &self,
        transaction_id: &TransactionId,
        request: &IssueRecoveryCompletionGrantRequest,
    ) -> garth::Result<IssueRecoveryCompletionGrantOutcome> {
        self.engine
            .issue_recovery_completion_grant(transaction_id, request)
            .await
    }

    pub fn build_completion_grant_issuance(
        &self,
        transaction_id: &TransactionId,
        initial_session: arkret_sdk::InitialSessionGrantIntent,
    ) -> anyhow::Result<IssueRecoveryCompletionGrantRequest> {
        let local = self
            .engine
            .local_state(transaction_id)?
            .ok_or_else(|| anyhow::anyhow!("recovery transaction has no durable local state"))?;
        let resource = local
            .last_observed_resource
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("recovery transaction has no authoritative resource"))?;
        if resource.state != SecurityTransactionState::Completed {
            anyhow::bail!("recovery completion grant requires a completed transaction");
        }
        let completion_attestation = resource
            .terminal_result
            .as_ref()
            .and_then(|result| result.completion_attestation.clone())
            .ok_or_else(|| anyhow::anyhow!("completed recovery omitted its attestation"))?;
        let terminal_continue = local.accepted_terminal_continue.as_ref().ok_or_else(|| {
            anyhow::anyhow!("completed recovery omitted its durable terminal receipt")
        })?;
        let terminal_request: SecurityTransactionContinueRequest = serde_json::from_value(
            arkret_sdk::canonical::parse_canonical_json(terminal_continue)?,
        )?;
        let receipt = match terminal_request
            .client_attestation
            .ok_or_else(|| anyhow::anyhow!("terminal continuation omitted attestation"))?
            .artifact
        {
            ClientStepAttestationArtifact::RecoveryReceipt(receipt) => receipt,
            ClientStepAttestationArtifact::SecurityRotationLocalCommit(_) => {
                anyhow::bail!("recovery completion grant cannot use a rotation local commit")
            }
        };
        let mut request = IssueRecoveryCompletionGrantRequest {
            transaction_id: transaction_id.clone(),
            transaction_request_digest: resource.request_digest.clone(),
            terminal_receipt: serde_json::to_value(receipt)?,
            completion_attestation: completion_attestation.clone(),
            device_authorization_event_id: completion_attestation
                .device_authorization_event_id
                .clone(),
            result_model_generation_ref: completion_attestation.result_model_generation_ref,
            initial_session: serde_json::to_value(initial_session)?,
            canonical_request_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
        };
        request.canonical_request_digest = request.expected_canonical_request_digest()?;
        request.validate_structural()?;
        Ok(request)
    }

    pub async fn retry_byte_identical_completion_grant(
        &self,
        transaction_id: &TransactionId,
    ) -> garth::Result<Option<IssueRecoveryCompletionGrantOutcome>> {
        self.engine
            .retry_durable_completion_grant(transaction_id)
            .await
    }

    pub fn local_state(
        &self,
        transaction_id: &TransactionId,
    ) -> garth::Result<Option<garth::DurableSecurityTransaction>> {
        self.engine.local_state(transaction_id)
    }
}

#[derive(Clone, Debug)]
pub struct SecurityRotationBackupDraft {
    pub backup_kind: BackupRotationKind,
    pub previous_series_id: BackupSeriesId,
    pub new_series_id: BackupSeriesId,
    pub new_backup_bodies: Vec<arkret_sdk::KeyBackup>,
    pub active_series_submission: EventsSubmitBatchRequestBody,
    pub old_backups: Vec<BackupObjectRef>,
}

#[derive(Clone, Debug)]
pub struct SecurityRotationDraft {
    pub transaction_id: TransactionId,
    pub principal_id: DidCoreId,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub revoke_submission: EventsSubmitBatchRequestBody,
    pub new_secret_commitment: Hash,
    pub backup_rotations: Vec<SecurityRotationBackupDraft>,
}

impl SecurityRotationDraft {
    pub fn into_create_request(
        self,
        coordinator_service_id: DidCoreId,
    ) -> anyhow::Result<SecurityRotationTransactionCreateRequest> {
        let revoke_unit = PreparedEventUnit::new(
            coordinator_service_id.clone(),
            serde_json::to_value(&self.revoke_submission)?,
        )?;
        let mut prepared = Vec::with_capacity(self.backup_rotations.len());
        for draft in self.backup_rotations {
            let active_series_event_id =
                exactly_one_event_id(&draft.active_series_submission, "active-series")?;
            let mut new_backups = draft
                .new_backup_bodies
                .iter()
                .map(backup_object_ref)
                .collect::<anyhow::Result<Vec<_>>>()?;
            new_backups
                .sort_by(|left, right| left.backup_id.as_str().cmp(right.backup_id.as_str()));
            let mut old_backups = draft.old_backups;
            old_backups
                .sort_by(|left, right| left.backup_id.as_str().cmp(right.backup_id.as_str()));
            prepared.push(BackupRotationPlan {
                binding: BackupRotationBinding {
                    backup_kind: draft.backup_kind,
                    previous_series_id: draft.previous_series_id,
                    new_series_id: draft.new_series_id,
                    new_backups,
                    active_series_event_id,
                    old_backups,
                },
                encrypted_backup_material: CanonicalPublicMaterial::canonical_json(
                    serde_json::to_value(draft.new_backup_bodies)?,
                )?,
                active_series_unit: PreparedEventUnit::new(
                    coordinator_service_id.clone(),
                    serde_json::to_value(draft.active_series_submission)?,
                )?,
            });
        }
        SecurityRotationTransactionCreateRequest::from_prepared_rotations(
            self.transaction_id,
            self.principal_id,
            self.expires_at,
            revoke_unit,
            self.new_secret_commitment,
            prepared,
        )
        .map_err(anyhow::Error::from)
    }
}

fn exactly_one_event_id(
    submission: &EventsSubmitBatchRequestBody,
    label: &str,
) -> anyhow::Result<EventId> {
    let [event] = submission.events.as_slice() else {
        anyhow::bail!("{label} prepared unit must contain exactly one Event");
    };
    Ok(event.event.event_id.clone())
}

fn backup_object_ref(value: &arkret_sdk::KeyBackup) -> anyhow::Result<BackupObjectRef> {
    Ok(BackupObjectRef {
        backup_id: value.backup_id.clone(),
        ciphertext_digest: Hash::new(value.ciphertext_digest.clone())?,
    })
}

pub struct DeviceRevokeSecurityRotation<T, S> {
    engine: SecurityTransactionEngine<T, S>,
}

impl<T, S> DeviceRevokeSecurityRotation<T, S>
where
    T: SecurityTransactionTransport,
    S: SecurityTransactionStore,
{
    pub fn new(engine: SecurityTransactionEngine<T, S>) -> Self {
        Self { engine }
    }

    pub async fn create_or_resume(
        &self,
        request: SecurityRotationTransactionCreateRequest,
        encrypted_staged_material_ref: String,
    ) -> garth::Result<SecurityTransaction> {
        self.engine
            .create_or_resume(
                &SecurityTransactionCreateRequest::SecurityRotation(request),
                Some(encrypted_staged_material_ref),
            )
            .await
    }

    pub async fn refresh(
        &self,
        transaction_id: &TransactionId,
    ) -> garth::Result<SecurityTransaction> {
        self.engine.refresh(transaction_id).await
    }

    pub async fn continue_server_step(
        &self,
        transaction: &SecurityTransaction,
    ) -> garth::Result<SecurityTransaction> {
        let step = transaction.next_required_step()?.ok_or_else(|| {
            garth::Error::Protocol("security rotation has no next server step".to_owned())
        })?;
        if matches!(
            step,
            arkret_wire::SecurityTransactionStep::EraseOldMaterial
                | arkret_wire::SecurityTransactionStep::LocalCommit
        ) {
            return Err(garth::Error::Protocol(
                "erase and local commit require their typed dedicated operations".to_owned(),
            ));
        }
        self.engine
            .continue_transaction(
                &transaction.transaction_id,
                &SecurityTransactionContinueRequest {
                    request_digest: transaction.request_digest.clone(),
                    prepared_plan_digest: transaction.prepared_plan_digest.clone(),
                    expected_accepted_step_count: transaction
                        .accepted_steps
                        .len()
                        .try_into()
                        .map_err(|_| {
                            garth::Error::Protocol(
                                "security rotation progress exceeds wire limit".to_owned(),
                            )
                        })?,
                    client_attestation: None,
                },
            )
            .await
    }

    pub async fn continue_with_signed_local_commit(
        &self,
        transaction_id: &TransactionId,
        request: &SecurityTransactionContinueRequest,
    ) -> garth::Result<SecurityTransaction> {
        self.engine
            .continue_transaction(transaction_id, request)
            .await
    }

    pub async fn erase_old_series(
        &self,
        transaction_id: &TransactionId,
        request: &arkret_models_crypto::BackupSeriesEraseRequestBody,
    ) -> garth::Result<arkret_models_crypto::BackupSeriesEraseOutcome> {
        self.engine
            .erase_backup_series(transaction_id, request)
            .await
    }

    pub async fn retry_pending_erase(
        &self,
        transaction_id: &TransactionId,
    ) -> garth::Result<Option<arkret_models_crypto::BackupSeriesEraseOutcome>> {
        self.engine.retry_pending_erase(transaction_id).await
    }

    pub async fn retry_byte_identical_pending(
        &self,
        transaction_id: &TransactionId,
    ) -> garth::Result<Option<SecurityTransaction>> {
        self.engine.retry_pending(transaction_id).await
    }
}
