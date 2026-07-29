//! Fresh-device recovery UI safety boundaries.
//!
//! Network coordination is owned by Garth's durable transaction engine. This
//! module owns only secret lifetime and the evidence required before the UI may
//! call a recovered device ready.

use arkret_models_crypto::TypedSecurityTransactionContinueRequest;
use arkret_wire::{
    RecoveryTransactionCreateRequest, SecurityRotationTransactionCreateRequest,
    SecurityTransaction, SecurityTransactionCreateRequest, TransactionId,
};
use garth::{SecurityTransactionEngine, SecurityTransactionStore, SecurityTransactionTransport};
use zeroize::{Zeroize, Zeroizing};

#[derive(Default)]
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
