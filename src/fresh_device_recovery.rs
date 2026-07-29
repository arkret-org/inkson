//! Fresh-device recovery UI safety boundaries.
//!
//! Network coordination is owned by Garth's durable transaction engine. This
//! module owns only secret lifetime and the evidence required before the UI may
//! call a recovered device ready.

use arkret_models_crypto::{
    ClientStepAttestationArtifact, RecoveryBackupClassUnlocked,
    RecoveryIdentityModel as ReceiptIdentityModel,
    RecoveryModelGenerationRef as ReceiptModelGenerationRef, RecoveryProofSummary, RecoveryReceipt,
    RecoveryReceiptAuthData, RecoveryReceiptOutcome, RecoveryWelcomeRealmSummary,
    TypedClientStepAttestation, TypedSecurityTransactionContinueRequest,
};
use arkret_wire::{
    BackupObjectRef, BackupRotationBinding, BackupRotationKind, BackupRotationPlan, BackupSeriesId,
    CLIENT_STEP_ATTESTATION_SIGNED_FIELDS, CanonicalPublicMaterial, ClientStepAttestationAuthData,
    Did, EventId, EventsSubmitBatchRequestBody, GrantId, Hash, NonEmptyString, PolicyId,
    PreparedEventUnit, PromoteRecoverySessionGrantOutcome, PromoteRecoverySessionGrantRequest,
    ReceiptId, RecoveryAuthorityHolderProof, RecoveryBinding, RecoveryPreparedPlan,
    RecoveryTransactionCreateRequest, SecurityRotationTransactionCreateRequest,
    SecurityTransaction, SecurityTransactionBinding, SecurityTransactionCreateRequest,
    SecurityTransactionPreparedPlan, SecurityTransactionState, SecurityTransactionStep,
    TransactionId, TypedTrustDomainId,
};
use chrono::{DateTime, Utc};
use garth::{SecurityTransactionEngine, SecurityTransactionStore, SecurityTransactionTransport};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Default)]
pub struct RecoveryWordsInput {
    words: Zeroizing<String>,
}

impl RecoveryWordsInput {
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

    pub fn as_str(&self) -> &str {
        self.words.as_str()
    }
}

impl Drop for RecoveryWordsInput {
    fn drop(&mut self) {
        self.words.zeroize();
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveryReadinessEvidence {
    pub transaction_completed_with_attestation: bool,
    pub holder_bound_grant_refreshed: bool,
    pub durable_device_authorized: bool,
    pub durable_control_generation_matches: bool,
    pub restore_report_committed: bool,
}

impl RecoveryReadinessEvidence {
    pub fn is_ready(&self) -> bool {
        self.transaction_completed_with_attestation
            && self.holder_bound_grant_refreshed
            && self.durable_device_authorized
            && self.durable_control_generation_matches
            && self.restore_report_committed
    }
}

#[derive(Clone, Debug)]
pub struct SecurityRotationBackupDraft {
    pub backup_kind: BackupRotationKind,
    pub previous_series_id: BackupSeriesId,
    pub new_series_id: BackupSeriesId,
    pub new_backup_bodies: Vec<serde_json::Value>,
    pub active_series_submission: EventsSubmitBatchRequestBody,
    pub old_backups: Vec<BackupObjectRef>,
}

#[derive(Clone, Debug)]
pub struct SecurityRotationDraft {
    pub transaction_id: TransactionId,
    pub principal_id: Did,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub revoke_submission: EventsSubmitBatchRequestBody,
    pub new_secret_commitment: Hash,
    pub backup_rotations: Vec<SecurityRotationBackupDraft>,
}

impl SecurityRotationDraft {
    /// Close all public rotation material into the protocol's exact
    /// secret_storage + mls_history plan. Secret bytes are deliberately not
    /// accepted by this API.
    pub fn into_create_request(
        self,
        coordinator_service_id: Did,
    ) -> anyhow::Result<SecurityRotationTransactionCreateRequest> {
        let revoke_event_id = exactly_one_event_id(&self.revoke_submission, "revoke")?;
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
            let binding = BackupRotationBinding {
                backup_kind: draft.backup_kind,
                previous_series_id: draft.previous_series_id,
                new_series_id: draft.new_series_id,
                new_backups,
                active_series_event_id,
                old_backups,
            };
            prepared.push(BackupRotationPlan {
                binding,
                encrypted_backup_material: CanonicalPublicMaterial::canonical_json(
                    serde_json::Value::Array(draft.new_backup_bodies),
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
            revoke_event_id,
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

fn backup_object_ref(value: &serde_json::Value) -> anyhow::Result<BackupObjectRef> {
    let backup_id = value
        .get("backup_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("prepared backup body omits backup_id"))?;
    let ciphertext_digest = value
        .get("ciphertext_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("prepared backup body omits ciphertext_digest"))?;
    Ok(BackupObjectRef {
        backup_id: arkret_sdk::BackupId::new(backup_id.to_owned())?,
        ciphertext_digest: Hash::new(ciphertext_digest.to_owned())?,
    })
}

pub struct RecoveryTerminalObservation {
    pub policy_id: PolicyId,
    pub policy_version: u64,
    pub trust_domain: TypedTrustDomainId,
    pub proof_summary: RecoveryProofSummary,
    pub backup_classes_unlocked: Vec<RecoveryBackupClassUnlocked>,
    pub welcome_count: u64,
    pub welcome_realm_summary: Option<Vec<RecoveryWelcomeRealmSummary>>,
    pub completed_at: DateTime<Utc>,
}

pub fn sign_terminal_receipt_continue(
    resource: &SecurityTransaction,
    observation: RecoveryTerminalObservation,
    signer: &crate::event_signer::InksonEventSigner,
) -> anyhow::Result<TypedSecurityTransactionContinueRequest> {
    resource.validate_structural()?;
    if resource.state != SecurityTransactionState::AwaitingDeviceAttestation
        || resource.next_required_step != Some(SecurityTransactionStep::IssueTerminalReceipt)
    {
        anyhow::bail!(
            "terminal receipt may only be signed from authoritative awaiting_device_attestation state"
        );
    }
    let (binding, plan) = match (&resource.binding, &resource.prepared_plan) {
        (
            SecurityTransactionBinding::Recovery(binding),
            SecurityTransactionPreparedPlan::Recovery(plan),
        ) => (binding, plan),
        _ => anyhow::bail!("terminal receipt requires a recovery transaction"),
    };
    if observation.policy_version == 0
        || observation.proof_summary.proof_digest != *plan_proof_digest(plan)
    {
        anyhow::bail!("terminal observation does not match the accepted recovery proof");
    }

    let (
        new_device_id,
        authorization_event_id,
        device_list_update_event_id,
        reanchor_event_id,
        reanchor_batch_receipt_id,
        authority_ticket_id,
        did_entry_ref,
        previous_model_generation_ref,
        result_model_generation_ref,
    ) = match (binding, plan) {
        (RecoveryBinding::CrossSigning(binding), RecoveryPreparedPlan::CrossSigning(plan)) => (
            binding.replacement_device_id.clone(),
            binding.authorize_event_id.clone(),
            Some(binding.device_list_update_event_id.clone()),
            None,
            None,
            None,
            None,
            ReceiptModelGenerationRef::CrossSigning(
                std::num::NonZeroU64::new(plan.previous_model_generation_ref)
                    .ok_or_else(|| anyhow::anyhow!("previous SSK generation must be positive"))?,
            ),
            ReceiptModelGenerationRef::CrossSigning(
                std::num::NonZeroU64::new(plan.result_model_generation_ref)
                    .ok_or_else(|| anyhow::anyhow!("result SSK generation must be positive"))?,
            ),
        ),
        (
            RecoveryBinding::EnrollmentAuthority(binding),
            RecoveryPreparedPlan::EnrollmentAuthority(plan),
        ) => {
            let preimage = &plan.authorization_preimage;
            if observation.policy_id != preimage.policy_id
                || observation.policy_version != preimage.policy_version
                || observation.trust_domain != preimage.trust_domain
            {
                anyhow::bail!(
                    "terminal observation changed the enrollment-authority policy binding"
                );
            }
            let batch_receipt = resource
                .accepted_steps
                .iter()
                .find(|step| step.step == SecurityTransactionStep::SubmitReanchorUnit)
                .ok_or_else(|| anyhow::anyhow!("accepted re-anchor unit is missing"))?;
            (
                binding.replacement_device_id.clone(),
                binding.authorize_event_id.clone(),
                None,
                Some(binding.reanchor_event_id.clone()),
                Some(ReceiptId::new(batch_receipt.output_ref.clone())?),
                Some(binding.authority_ticket_id.clone()),
                Some(binding.did_entry_ref.clone()),
                ReceiptModelGenerationRef::EnrollmentAuthority(
                    NonEmptyString::new(plan.previous_model_generation_ref.clone())
                        .map_err(anyhow::Error::msg)?,
                ),
                ReceiptModelGenerationRef::EnrollmentAuthority(
                    NonEmptyString::new(plan.result_model_generation_ref.clone())
                        .map_err(anyhow::Error::msg)?,
                ),
            )
        }
        _ => anyhow::bail!("recovery binding and prepared plan models disagree"),
    };

    let mut signed_fields = vec![
        "schema",
        "receipt_id",
        "transaction_id",
        "transaction_request_digest",
        "prepared_plan_digest",
        "principal_id",
        "recovery_session_id",
        "policy_id",
        "policy_version",
        "trust_domain",
        "new_device_id",
        "identity_model",
        "previous_model_generation_ref",
        "result_model_generation_ref",
        "authorization_event_id",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    match binding {
        RecoveryBinding::CrossSigning(_) => {
            signed_fields.push("device_list_update_event_id".into())
        }
        RecoveryBinding::EnrollmentAuthority(_) => signed_fields.extend(
            [
                "reanchor_event_id",
                "reanchor_batch_receipt_id",
                "authority_ticket_id",
                "did_entry_ref",
            ]
            .into_iter()
            .map(str::to_owned),
        ),
    }
    signed_fields.extend(
        ["proof_summary", "backup_classes_unlocked", "welcome_count"]
            .into_iter()
            .map(str::to_owned),
    );
    if observation.welcome_realm_summary.is_some() {
        signed_fields.push("welcome_realm_summary".into());
    }
    signed_fields.extend(
        ["outcome", "started_at", "completed_at"]
            .into_iter()
            .map(str::to_owned),
    );

    let mut receipt = RecoveryReceipt {
        schema: "ak.schema.recovery_receipt.v1".to_owned(),
        receipt_id: binding.terminal_receipt_id().clone(),
        transaction_id: resource.transaction_id.clone(),
        transaction_request_digest: resource.request_digest.clone(),
        prepared_plan_digest: resource.prepared_plan_digest.clone(),
        principal_id: resource.principal_id.clone(),
        recovery_session_id: binding.recovery_session_id().clone(),
        policy_id: observation.policy_id,
        policy_version: observation.policy_version,
        trust_domain: observation.trust_domain,
        new_device_id,
        identity_model: match binding {
            RecoveryBinding::CrossSigning(_) => ReceiptIdentityModel::CrossSigning,
            RecoveryBinding::EnrollmentAuthority(_) => ReceiptIdentityModel::EnrollmentAuthority,
        },
        previous_model_generation_ref,
        result_model_generation_ref,
        authorization_event_id,
        device_list_update_event_id,
        reanchor_event_id,
        reanchor_batch_receipt_id,
        authority_ticket_id,
        did_entry_ref,
        proof_summary: observation.proof_summary,
        backup_classes_unlocked: observation.backup_classes_unlocked,
        welcome_count: observation.welcome_count,
        welcome_realm_summary: observation.welcome_realm_summary,
        outcome: RecoveryReceiptOutcome::Completed,
        outcome_reason_code: None,
        started_at: resource.created_at,
        completed_at: observation.completed_at,
        auth_data: RecoveryReceiptAuthData {
            verification_method: signer.verification_method().to_owned(),
            signature_algorithm: "Ed25519".to_owned(),
            signature: String::new(),
            signed_fields,
        },
        extra: Default::default(),
    };
    let receipt_signature = signer.sign_raw(&receipt.signature_transcript_bytes()?)?;
    receipt.auth_data.signature = arkret_sdk::base64url_encode(receipt_signature);
    receipt.validate()?;

    let artifact = ClientStepAttestationArtifact::RecoveryReceipt(receipt);
    let artifact_bytes = arkret_sdk::canonical::canonical_json_bytes(&artifact)?;
    let mut attestation = TypedClientStepAttestation {
        step: SecurityTransactionStep::IssueTerminalReceipt,
        output_ref: binding.terminal_receipt_id().as_str().to_owned(),
        transaction_id: resource.transaction_id.clone(),
        transaction_request_digest: resource.request_digest.clone(),
        prepared_plan_digest: resource.prepared_plan_digest.clone(),
        attestation_digest: Hash::new(arkret_sdk::canonical::sha256_digest(&artifact_bytes))?,
        artifact,
        auth_data: ClientStepAttestationAuthData {
            verification_method: signer.verification_method().to_owned(),
            alg: "EdDSA".to_owned(),
            signature: String::new(),
            signed_fields: CLIENT_STEP_ATTESTATION_SIGNED_FIELDS
                .into_iter()
                .map(str::to_owned)
                .collect(),
        },
    };
    let outer_signature = signer.sign_raw(&attestation.signing_bytes()?)?;
    attestation.auth_data.signature = arkret_sdk::base64url_encode(outer_signature);
    attestation.validate_structural()?;

    Ok(TypedSecurityTransactionContinueRequest {
        request_digest: resource.request_digest.clone(),
        prepared_plan_digest: resource.prepared_plan_digest.clone(),
        expected_next_step: SecurityTransactionStep::IssueTerminalReceipt,
        client_attestation: Some(attestation),
        participant_request: None,
    })
}

fn plan_proof_digest(plan: &RecoveryPreparedPlan) -> &Hash {
    match plan {
        RecoveryPreparedPlan::CrossSigning(plan) => &plan.proof_digest,
        RecoveryPreparedPlan::EnrollmentAuthority(plan) => &plan.proof_digest,
    }
}

/// Thin UI-facing facade over Garth's durable coordinator.
///
/// Callers author and sign protocol artifacts outside this type. Every
/// continuation, including the terminal receipt, is handed to Garth before
/// transport so a response-loss retry reuses the exact canonical bytes.
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

    /// GET is authoritative; the UI must render this result rather than
    /// advancing a local success flag.
    pub async fn refresh(
        &self,
        transaction_id: &TransactionId,
    ) -> garth::Result<SecurityTransaction> {
        self.engine.refresh(transaction_id).await
    }

    pub async fn continue_with_signed_artifact(
        &self,
        transaction_id: &TransactionId,
        request: &TypedSecurityTransactionContinueRequest,
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

    pub async fn promote_holder_bound_grant(
        &self,
        transaction_id: &TransactionId,
        request: &PromoteRecoverySessionGrantRequest,
    ) -> garth::Result<PromoteRecoverySessionGrantOutcome> {
        self.engine
            .promote_recovery_session_grant(transaction_id, request)
            .await
    }

    pub fn build_holder_bound_promotion(
        &self,
        transaction_id: &TransactionId,
        old_grant_id: GrantId,
        account_authority_endpoint: &str,
        holder: &crate::identity::account_auth::grant_dpop::DpopHandle,
    ) -> anyhow::Result<PromoteRecoverySessionGrantRequest> {
        let endpoint = url::Url::parse(account_authority_endpoint)?;
        if endpoint.scheme() != "https"
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/_arkret/gate/account/recovery-session-grants/promote"
        {
            anyhow::bail!("recovery grant promotion requires the exact standard HTTPS endpoint");
        }
        let local = self
            .engine
            .local_state(transaction_id)?
            .ok_or_else(|| anyhow::anyhow!("recovery transaction has no durable local state"))?;
        let resource = local
            .last_observed_resource
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("recovery transaction has no authoritative resource"))?;
        if resource.state != SecurityTransactionState::Completed {
            anyhow::bail!("recovery grant promotion requires a completed transaction");
        }
        let terminal_result = resource
            .terminal_result
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("completed recovery transaction omitted result"))?;
        let completion_attestation = terminal_result
            .completion_attestation
            .clone()
            .ok_or_else(|| anyhow::anyhow!("completed recovery transaction omitted attestation"))?;
        let terminal_continue = local.accepted_terminal_continue.as_ref().ok_or_else(|| {
            anyhow::anyhow!("completed recovery transaction omitted its durable terminal receipt")
        })?;
        let terminal_request: TypedSecurityTransactionContinueRequest = serde_json::from_value(
            arkret_sdk::canonical::parse_canonical_json(terminal_continue)?,
        )?;
        let receipt = match terminal_request
            .client_attestation
            .ok_or_else(|| anyhow::anyhow!("terminal continuation omitted client attestation"))?
            .artifact
        {
            ClientStepAttestationArtifact::RecoveryReceipt(receipt) => receipt,
            ClientStepAttestationArtifact::SecurityRotationLocalCommit(_) => {
                anyhow::bail!("recovery promotion cannot use a rotation local commit")
            }
        };
        let terminal_receipt = serde_json::to_value(receipt)?;
        let mut request = PromoteRecoverySessionGrantRequest {
            old_grant_id,
            transaction_id: transaction_id.clone(),
            transaction_request_digest: resource.request_digest.clone(),
            terminal_receipt,
            completion_attestation: completion_attestation.clone(),
            device_authorization_event_id: completion_attestation
                .device_authorization_event_id
                .clone(),
            result_model_generation_ref: completion_attestation.result_model_generation_ref.clone(),
            canonical_request_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            holder_proof: RecoveryAuthorityHolderProof {
                dpop_jkt: holder.jkt().to_owned(),
                proof_jwt: String::new(),
            },
        };
        request.canonical_request_digest = request.expected_canonical_request_digest()?;
        let jti = format!("urn:uuid:{}", crate::operation::uuid_v7());
        request.holder_proof.proof_jwt = holder.mint_recovery_authority_proof(
            endpoint.as_str(),
            request.canonical_request_digest.as_str(),
            &jti,
        )?;
        request.validate_structural()?;
        Ok(request)
    }

    pub async fn retry_byte_identical_promotion(
        &self,
        transaction_id: &TransactionId,
    ) -> garth::Result<Option<PromoteRecoverySessionGrantOutcome>> {
        self.engine.retry_pending_promotion(transaction_id).await
    }

    pub fn install_promoted_holder_bound_grant(
        &self,
        store: &mut crate::state::LocalStateStore,
        outcome: &PromoteRecoverySessionGrantOutcome,
        principal_server_url: &str,
        holder: &crate::identity::account_auth::grant_dpop::DpopHandle,
    ) -> anyhow::Result<crate::state::PersistedSessionGrant> {
        crate::identity::session_refresh::persist_promoted_recovery_grant(
            store,
            outcome,
            principal_server_url,
            holder,
        )
    }
}

/// Device-revoke UI entrypoint for the fixed two-kind rotation transaction.
/// It intentionally accepts only the closed SDK request, so the former
/// single-secret upload/delete saga cannot be represented.
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
        let step = transaction.next_required_step.ok_or_else(|| {
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
                &TypedSecurityTransactionContinueRequest {
                    request_digest: transaction.request_digest.clone(),
                    prepared_plan_digest: transaction.prepared_plan_digest.clone(),
                    expected_next_step: step,
                    client_attestation: None,
                    participant_request: None,
                },
            )
            .await
    }

    pub async fn continue_with_signed_local_commit(
        &self,
        transaction_id: &TransactionId,
        request: &TypedSecurityTransactionContinueRequest,
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

    #[test]
    fn ready_requires_every_durable_evidence_source() {
        let complete = RecoveryReadinessEvidence {
            transaction_completed_with_attestation: true,
            holder_bound_grant_refreshed: true,
            durable_device_authorized: true,
            durable_control_generation_matches: true,
            restore_report_committed: true,
        };
        assert!(complete.is_ready());
        for missing in 0..5 {
            let mut evidence = complete.clone();
            match missing {
                0 => evidence.transaction_completed_with_attestation = false,
                1 => evidence.holder_bound_grant_refreshed = false,
                2 => evidence.durable_device_authorized = false,
                3 => evidence.durable_control_generation_matches = false,
                4 => evidence.restore_report_committed = false,
                _ => unreachable!(),
            }
            assert!(!evidence.is_ready());
        }
    }

    #[test]
    fn recovery_words_are_normalized_only_into_zeroizing_memory() {
        let phrase = crate::recovery_crypto::format_recovery_key(&[7u8; 32]);
        let mut input = RecoveryWordsInput::default();
        input.replace(format!("  {}  ", phrase.replace(' ', " \n ")));
        assert_eq!(
            input.normalized().as_deref().map(String::as_str),
            Some(phrase.as_str())
        );
        input.clear();
        assert!(input.is_empty());
    }
}
