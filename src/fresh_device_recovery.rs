//! Durable device-revocation security-rotation helpers.
//!
//! Fresh-device account recovery is authorized by the accepted PCR policy;
//! the replacement device proves possession of its key in the closed unit.

// The security-transaction DTO family lives in `arkret-models-crypto`, not in
// `arkret-wire`: `arkret-wire` keeps the transport envelopes and the generated
// identifier newtypes, while the recovery/rotation plan shapes are model types.
use arkret_models_crypto::{
    BackupObjectRef, BackupRotationBinding, BackupRotationKind, BackupRotationPlan,
    PreparedEventUnit, RecoveryBackupUnlocked, RecoveryProofSummary, RecoveryReceipt,
    RecoveryReceiptOutcome, RecoveryReceiptSignatureProof, RecoveryTransactionCreateRequestBody,
    RecoveryUnit, RecoveryWelcomeRealmSummary, SecurityRotationTransactionCreateRequestBody,
    SecurityTransaction, SecurityTransactionContinueRequestBody,
    SecurityTransactionCreateRequestBody, SecurityTransactionStep,
    SecurityTransactionTerminalOutcome,
};
use arkret_models_identity::RecoveryCompletionGrantRequestBody;
use arkret_wire::{
    BackupSeriesId, Base64UrlString, Did, EventId, EventsSubmitBatchRequestBody, Hash, SchemaId,
    TransactionId,
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
    pub backup_classes_unlocked: Vec<RecoveryBackupUnlocked>,
    pub welcome_count: u64,
    pub welcome_realm_summary: Option<Vec<RecoveryWelcomeRealmSummary>>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: chrono::DateTime<chrono::Utc>,
}

/// Sign the one self-free R after local work and both producer Events are frozen.
/// Its native predecessor is already accepted; future Commit IDs never enter R.
pub fn sign_recovery_create(
    session: &arkret_sdk::RecoverySession,
    transaction_id: TransactionId,
    receipt_id: arkret_sdk::ReceiptId,
    recovery_unit: RecoveryUnit,
    observation: RecoveryTerminalObservation,
    signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<RecoveryTransactionCreateRequestBody> {
    session.validate_shape()?;
    let public_key = signer
        .public_key_multibase()
        .ok_or_else(|| anyhow::anyhow!("replacement signer has no Ed25519 key"))?;
    anyhow::ensure!(
        signer.device_id() == Some(session.requesting_device_id.as_str())
            && session.requesting_device_public_key_did.as_str() == format!("did:key:{public_key}"),
        "Recovery signer differs from the verified Session candidate"
    );
    let signer_did = Did::new(signer.signer_did().to_owned())?;
    anyhow::ensure!(
        arkret_sdk::project_did_to_core_id(&signer_did)? == session.account_id.principal_id,
        "Recovery signer controls another Account"
    );
    let mut receipt = RecoveryReceipt {
        schema: SchemaId::RECOVERY_RECEIPT_V1.to_owned(),
        receipt_id,
        transaction_id,
        account_id: session.account_id.clone(),
        expires_at: session.expires_at,
        recovery_session_id: session.recovery_session_id.clone(),
        session_grant_ref: session.session_grant_ref.clone(),
        session_grant_cnf_jkt: session.session_grant_cnf_jkt.clone(),
        policy_id: observation.policy_id,
        policy_version: observation.policy_version,
        trust_domain: observation.trust_domain,
        new_device_id: session.requesting_device_id.clone(),
        identity_model: session.identity_model,
        recovery_authority_kind: arkret_sdk::RecoveryAuthorityKind::PcrPolicy,
        previous_model_generation_ref: session.current_device_generation_ref,
        new_model_generation_ref: session
            .current_device_generation_ref
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Recovery generation overflow"))?,
        proof_summary: observation.proof_summary,
        recovery_unit,
        unlocked_backups: observation.backup_classes_unlocked,
        welcome_count: observation.welcome_count,
        welcome_realm_summaries: observation.welcome_realm_summary,
        outcome: RecoveryReceiptOutcome::Completed,
        outcome_reason_code: None,
        started_at: observation.started_at,
        completed_at: observation.completed_at,
        signature_proof: RecoveryReceiptSignatureProof {
            verification_method: signer.verification_method_for_principal(&signer_did)?,
            signature_algorithm: "Ed25519".into(),
            signature: Base64UrlString::new(arkret_sdk::base64url_encode([0; 64]))
                .map_err(anyhow::Error::msg)?,
        },
    };
    receipt.validate_for_session(session, receipt.completed_at)?;
    receipt.signature_proof.signature = Base64UrlString::new(arkret_sdk::base64url_encode(
        signer.sign_raw(&receipt.signature_transcript_bytes()?)?,
    ))
    .map_err(anyhow::Error::msg)?;
    RecoveryTransactionCreateRequestBody::new(receipt).map_err(Into::into)
}

pub(crate) fn transaction_is_completed(resource: &SecurityTransaction) -> bool {
    match resource {
        SecurityTransaction::Recovery(_) => true,
        SecurityTransaction::SecurityRotation(rotation) => matches!(
            rotation.terminal_outcome,
            Some(SecurityTransactionTerminalOutcome::Completed { .. })
        ),
    }
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

    pub async fn freeze_create(
        &self,
        request: RecoveryTransactionCreateRequestBody,
        staged: Option<String>,
        context: &arkret_sdk::ProducerVerificationContext,
    ) -> garth::Result<()> {
        let verified = arkret_sdk::VerifiedSubmission::verify(
            SecurityTransactionCreateRequestBody::Recovery(request),
            |_| Ok(context.clone()),
        )
        .map_err(|e| garth::Error::Protocol(e.to_string()))?;
        self.engine
            .freeze_create(&verified, staged)
            .await
            .map(|_| ())
    }

    pub async fn create_or_resume(
        &self,
        request: RecoveryTransactionCreateRequestBody,
        encrypted_staged_material_ref: Option<String>,
        context: &arkret_sdk::ProducerVerificationContext,
    ) -> garth::Result<SecurityTransaction> {
        let request = arkret_sdk::VerifiedSubmission::verify(
            SecurityTransactionCreateRequestBody::Recovery(request),
            |_| Ok(context.clone()),
        )
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        self.engine
            .create_or_resume(&request, encrypted_staged_material_ref)
            .await
    }

    pub async fn refresh(
        &self,
        transaction_id: &TransactionId,
    ) -> garth::Result<SecurityTransaction> {
        self.engine.refresh(transaction_id).await
    }

    pub async fn retry_byte_identical_pending(
        &self,
        transaction_id: &TransactionId,
    ) -> garth::Result<Option<SecurityTransaction>> {
        self.engine.retry_pending(transaction_id).await
    }

    /// The AA fetches C itself. The client supplies its exact persisted R even
    /// when the original successful Station response was lost.
    pub fn receipt_for_completion(
        &self,
        transaction_id: &TransactionId,
    ) -> anyhow::Result<RecoveryReceipt> {
        let local = self
            .engine
            .local_state(transaction_id)?
            .ok_or_else(|| anyhow::anyhow!("Recovery has no durable signed request"))?;
        let request: SecurityTransactionCreateRequestBody =
            serde_json::from_slice(&local.canonical_create_request)?;
        anyhow::ensure!(
            arkret_sdk::canonical::canonical_json_bytes(&request)?
                == local.canonical_create_request,
            "stored Recovery request is not canonical"
        );
        let SecurityTransactionCreateRequestBody::Recovery(request) = request else {
            anyhow::bail!("stored request is not Recovery")
        };
        request.validate()?;
        anyhow::ensure!(
            request.recovery_receipt.transaction_id == *transaction_id,
            "stored Recovery changed transaction identity"
        );
        if let Some(observed) = local.last_observed_resource.as_ref() {
            let SecurityTransaction::Recovery(completed) = observed else {
                anyhow::bail!("Recovery changed its closed branch")
            };
            completed.validate_for_request(&request)?;
        }
        Ok(request.recovery_receipt)
    }

    pub async fn build_completion_grant_issuance(
        &self,
        transaction_id: &TransactionId,
        initial_session: arkret_sdk::InitialSessionGrantIntent,
        accepted_device_possession_proof: arkret_wire::AcceptedDeviceIssuePossessionProof,
    ) -> anyhow::Result<RecoveryCompletionGrantRequestBody> {
        let request = RecoveryCompletionGrantRequestBody::new(
            self.receipt_for_completion(transaction_id)?,
            initial_session,
            accepted_device_possession_proof,
        )?;
        self.engine
            .freeze_recovery_completion_request(&request)
            .await
            .map_err(Into::into)
    }

    pub async fn renew_completion_after_issuer_expiry(
        &self,
        rejected: &RecoveryCompletionGrantRequestBody,
        fresh: &RecoveryCompletionGrantRequestBody,
        status: u16,
        problem: &arkret_wire::Problem,
    ) -> anyhow::Result<RecoveryCompletionGrantRequestBody> {
        self.engine
            .renew_recovery_completion_request(rejected, fresh, status, problem)
            .await
            .map_err(Into::into)
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
    /// The active device whose high-risk authorization created this rotation.
    /// Coland rechecks this exact device before erasing the old series.
    pub authorizing_device_id: arkret_sdk::DeviceId,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub revoke_submission: EventsSubmitBatchRequestBody,
    pub new_secret_commitment: Hash,
    pub backup_rotations: Vec<SecurityRotationBackupDraft>,
}

impl SecurityRotationDraft {
    pub fn into_create_request(
        self,
    ) -> anyhow::Result<SecurityRotationTransactionCreateRequestBody> {
        let revoke_unit = PreparedEventUnit::new(
            arkret_sdk::canonical::DigestSuite::Sha256,
            self.revoke_submission,
        )?;
        let mut prepared = Vec::with_capacity(self.backup_rotations.len());
        for mut draft in self.backup_rotations {
            let active_series_event_id =
                exactly_one_event_id(&draft.active_series_submission, "active-series")?;
            draft
                .new_backup_bodies
                .sort_by(|left, right| left.backup_id.as_str().cmp(right.backup_id.as_str()));
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
                new_backup_envelopes: draft.new_backup_bodies,
                active_series_unit: PreparedEventUnit::new(
                    arkret_sdk::canonical::DigestSuite::Sha256,
                    draft.active_series_submission,
                )?,
            });
        }
        SecurityRotationTransactionCreateRequestBody::from_prepared_rotations(
            self.transaction_id,
            self.account_id,
            self.authorizing_device_id,
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
        ciphertext_digest: value.ciphertext_digest.clone(),
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
        request: SecurityRotationTransactionCreateRequestBody,
        encrypted_staged_material_ref: String,
        context: &arkret_sdk::ProducerVerificationContext,
    ) -> garth::Result<SecurityTransaction> {
        let request = arkret_sdk::VerifiedSubmission::verify(
            SecurityTransactionCreateRequestBody::SecurityRotation(request),
            |_| Ok(context.clone()),
        )
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        self.engine
            .create_or_resume(&request, Some(encrypted_staged_material_ref))
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
        let SecurityTransaction::SecurityRotation(rotation) = transaction else {
            return Err(garth::Error::Protocol(
                "Recovery has no Rotation continuation".into(),
            ));
        };
        let step = rotation.next_required_step()?.ok_or_else(|| {
            garth::Error::Protocol("security rotation has no next server step".to_owned())
        })?;
        if step == SecurityTransactionStep::LocalCommit {
            return Err(garth::Error::Protocol(
                "local commit requires its signed client attestation".to_owned(),
            ));
        }
        self.engine.refresh(transaction.transaction_id()).await
    }

    pub async fn continue_with_signed_local_commit(
        &self,
        transaction_id: &TransactionId,
        request: &SecurityTransactionContinueRequestBody,
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
}
