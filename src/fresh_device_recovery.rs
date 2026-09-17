//! Durable device-revocation security-rotation helpers.
//!
//! Fresh-device account recovery is authorized by the accepted PCR policy;
//! the replacement device proves possession of its key in the closed unit.

use arkret_models_crypto::{
    ClientStepAttestationArtifact, RecoveryBackupClassUnlocked, RecoveryProofSummary,
    RecoveryReceiptOutcome, RecoveryTerminalCommit, RecoveryWelcomeRealmSummary,
    SecurityTransactionContinueRequest, UnsignedRecoveryReceipt, UnsignedRecoveryReceiptBody,
};
use arkret_wire::{
    BackupObjectRef, BackupRotationBinding, BackupRotationKind, BackupRotationPlan, BackupSeriesId,
    CanonicalPublicMaterial, Did, EventId, EventsSubmitBatchRequestBody, Hash,
    IssueRecoveryCompletionGrantOutcome, IssueRecoveryCompletionGrantRequest, PreparedEventUnit,
    RecoveryPreparedPlan, RecoveryTransactionCreateRequest, SealId,
    SecurityRotationTransactionCreateRequest, SecurityTransaction,
    SecurityTransactionCreateRequest, SecurityTransactionPreparedPlan, SecurityTransactionStep,
    TransactionId, UnsignedClientStepAttestation,
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

/// The Realm digest suite a recovery prepare already committed to.
///
/// `first_generation_seal_id` is the content-derived identity of the frozen
/// unsigned body, so its digest prefix is the only wire-visible statement of
/// the suite the Station used; signing under any other suite would derive a
/// different id and the commit would not close.
fn reserved_seal_digest_suite(
    reserved_id: &SealId,
) -> anyhow::Result<arkret_sdk::canonical::DigestSuite> {
    let digest = reserved_id
        .as_str()
        .strip_prefix("ak:seal:")
        .ok_or_else(|| anyhow::anyhow!("reserved first-generation Seal id is malformed"))?;
    Ok(Hash::new(digest)?.digest_suite()?)
}

/// Sign the one client-authored terminal artifact for a PCR-policy recovery.
///
/// A RecoveryTransaction has exactly one client-attested step. The replacement
/// device signs the exact first new-generation Seal the Station froze in its
/// prepare, then the receipt that names that Seal, then the outer attestation
/// over both, and delivers all three as one `commit_recovery_unit`. There is no
/// earlier server continuation to wait for: before this request the transaction
/// has produced no recovery effect at all.
pub fn sign_recovery_terminal_commit_continue(
    resource: &SecurityTransaction,
    observation: RecoveryTerminalObservation,
    signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<SecurityTransactionContinueRequest> {
    resource.validate_structural()?;
    if !resource.requires_device_attestation()? {
        anyhow::bail!("recovery terminal commit requires canonical device-attestation readiness");
    }
    let SecurityTransactionPreparedPlan::Recovery(RecoveryPreparedPlan::PcrPolicy(plan)) =
        &resource.prepared_plan
    else {
        anyhow::bail!("recovery terminal commit requires a PCR-policy recovery transaction");
    };
    let binding = &plan.binding;
    if observation.policy_version == 0
        || observation.proof_summary.proof_digest != plan.proof_digest
    {
        anyhow::bail!("terminal observation does not match the verified recovery proof");
    }
    if !resource.accepted_steps.is_empty() {
        anyhow::bail!("recovery terminal commit is the only accepted step of its transaction");
    }
    let signer_did = Did::new(signer.signer_did().to_owned())?;
    if arkret_sdk::project_did_to_core_id(&signer_did)? != resource.account_id.principal_id {
        anyhow::bail!("recovery receipt signer does not control the recovered principal");
    }
    let verification_method = signer.verification_method_for_principal(&signer_did)?;

    // `validate_structural` above already proved the frozen body derives the
    // reserved id, so signing it is the only remaining degree of freedom.
    let first_generation_seal = signer.sign_recovery_first_generation_seal(
        &signer_did,
        plan.first_generation_seal_body.clone(),
        reserved_seal_digest_suite(&binding.first_generation_seal_id)?,
    )?;
    if first_generation_seal.id != binding.first_generation_seal_id {
        anyhow::bail!("signed first-generation Seal does not carry the reserved plan identity");
    }

    let receipt = UnsignedRecoveryReceipt::new(
        UnsignedRecoveryReceiptBody {
            receipt_id: binding.terminal_receipt_id.clone(),
            transaction_id: resource.transaction_id.clone(),
            transaction_request_digest: resource.request_digest.clone(),
            prepared_plan_digest: resource.prepared_plan_digest.clone(),
            account_id: resource.account_id.clone(),
            recovery_session_id: binding.recovery_session_id.clone(),
            policy_id: observation.policy_id,
            policy_version: observation.policy_version,
            trust_domain: observation.trust_domain,
            new_device_id: binding.replacement_device_id.clone(),
            identity_model: arkret_sdk::RecoveryIdentityModel::PcrPolicy,
            recovery_authority_kind: arkret_sdk::RecoveryAuthorityKind::PcrPolicy,
            previous_model_generation_ref: plan.previous_model_generation_ref,
            result_model_generation_ref: plan.result_model_generation_ref,
            authorization_event_id: binding.authorize_event_id.clone(),
            reanchor_event_id: Some(binding.reanchor_event_id.clone()),
            // Reserved by the prepare, not observed from an accepted step: the
            // two Events are still unaccepted at signing time.
            reanchor_batch_receipt_id: Some(binding.reanchor_batch_receipt_id.clone()),
            first_generation_seal_id: binding.first_generation_seal_id.clone(),
            proof_summary: observation.proof_summary,
            unlocked_backups: observation.backup_classes_unlocked,
            welcome_count: observation.welcome_count,
            welcome_realm_summaries: observation.welcome_realm_summary,
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

    let commit = RecoveryTerminalCommit {
        first_generation_seal,
        recovery_receipt: receipt,
    };
    commit.validate()?;
    let artifact = ClientStepAttestationArtifact::RecoveryTerminalCommit(commit);
    let attestation = UnsignedClientStepAttestation::new(
        SecurityTransactionStep::CommitRecoveryUnit,
        binding.terminal_receipt_id.as_str().to_owned(),
        resource.transaction_id.clone(),
        resource.request_digest.clone(),
        resource.prepared_plan_digest.clone(),
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
        expected_accepted_step_count: 0,
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
            .issue_recovery_completion_grant(transaction_id, request, crate::clock::now_utc())
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
        if !resource.is_completed() {
            anyhow::bail!("recovery completion grant requires a completed transaction");
        }
        let completion_attestation = resource
            .terminal_outcome
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
            ClientStepAttestationArtifact::RecoveryTerminalCommit(commit) => {
                commit.recovery_receipt
            }
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
            .retry_durable_completion_grant(transaction_id, crate::clock::now_utc())
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
    /// The closed account whose devices and backups rotate. Carried whole so
    /// the create request never reassembles it from a principal plus the
    /// ambient Station (account-lifecycle.md §156).
    pub account_id: arkret_sdk::AccountId,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub revoke_submission: EventsSubmitBatchRequestBody,
    pub new_secret_commitment: Hash,
    pub backup_rotations: Vec<SecurityRotationBackupDraft>,
}

impl SecurityRotationDraft {
    pub fn into_create_request(self) -> anyhow::Result<SecurityRotationTransactionCreateRequest> {
        let revoke_unit = PreparedEventUnit::new(
            arkret_sdk::canonical::DigestSuite::Sha256,
            self.revoke_submission,
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
                    arkret_sdk::canonical::DigestSuite::Sha256,
                    draft.active_series_submission,
                )?,
            });
        }
        SecurityRotationTransactionCreateRequest::from_prepared_rotations(
            self.transaction_id,
            self.account_id,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The recovery prepare states its digest suite only through the reserved
    /// Seal id. Signing under a different suite derives a different id, and the
    /// only symptom would be a commit the Station cannot verify, so the
    /// derivation is pinned here rather than left to a live run to discover.
    #[test]
    fn the_reserved_seal_id_is_the_only_statement_of_the_realm_digest_suite() {
        let sha256 = SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap();
        assert_eq!(
            reserved_seal_digest_suite(&sha256).unwrap(),
            arkret_sdk::canonical::DigestSuite::Sha256
        );
        let blake3 = SealId::new(format!("ak:seal:blake3:{}", "b".repeat(64))).unwrap();
        assert_eq!(
            reserved_seal_digest_suite(&blake3).unwrap(),
            arkret_sdk::canonical::DigestSuite::Blake3
        );
    }
}
