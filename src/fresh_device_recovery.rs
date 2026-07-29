//! Fresh-device recovery UI safety boundaries.
//!
//! Network coordination is owned by Garth's durable transaction engine. This
//! module owns only secret lifetime and the evidence required before the UI may
//! call a recovered device ready.

use arkret_models_crypto::TypedSecurityTransactionContinueRequest;
use arkret_wire::{
    BackupObjectRef, BackupRotationBinding, BackupRotationKind, BackupRotationPlan, BackupSeriesId,
    CanonicalPublicMaterial, Did, EventId, EventsSubmitBatchRequestBody, Hash, PreparedEventUnit,
    RecoveryTransactionCreateRequest, SecurityRotationTransactionCreateRequest,
    SecurityTransaction, SecurityTransactionCreateRequest, TransactionId,
};
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
