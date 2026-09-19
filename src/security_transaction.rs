//! Inkson persistence adapter for Garth security-transaction coordination.
//!
//! The serialized value contains only canonical public requests, the last
//! server projection, and an opaque reference to separately encrypted staged
//! material. Recovery words and derived key material are never stored here.

use std::sync::Arc;

use garth::{
    DurableSecurityTransaction, PutSecretOptions, SecretClass, SecretDurability, SecureKeyStore,
    SecureKeyStoreError, SecurityTransactionStore,
};
use serde_json::Value;
use zeroize::Zeroizing;

const SECURITY_TRANSACTION_RECORD_KEY: &str = "security_transaction.record.v1";
const SECURITY_TRANSACTION_STAGED_SECRET_KEY: &str = "security_transaction.staged_secret.v1";
const PENDING_FRESH_DEVICE_RECOVERY_KEY: &str = "fresh_device_recovery.pending.v1";
const SECURITY_TRANSACTION_STAGED_SECRET_REF_PREFIX: &str = "secure-store://security-transaction/";

#[derive(Clone)]
pub struct InksonSecurityTransactionStore {
    secure_store: Arc<dyn SecureKeyStore + Send + Sync>,
}

impl InksonSecurityTransactionStore {
    pub fn new(secure_store: Arc<dyn SecureKeyStore + Send + Sync>) -> Self {
        Self { secure_store }
    }

    fn storage_key(transaction_id: &arkret_sdk::TransactionId) -> garth::Result<String> {
        crate::secure_key_store::account_scoped_device_key(&format!(
            "{SECURITY_TRANSACTION_RECORD_KEY}.{}",
            transaction_id.as_str()
        ))
        .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    fn staged_secret_key(transaction_id: &arkret_sdk::TransactionId) -> garth::Result<String> {
        crate::secure_key_store::account_scoped_device_key(&format!(
            "{SECURITY_TRANSACTION_STAGED_SECRET_KEY}.{}",
            transaction_id.as_str()
        ))
        .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    fn staged_secret_reference(transaction_id: &arkret_sdk::TransactionId) -> String {
        format!(
            "{SECURITY_TRANSACTION_STAGED_SECRET_REF_PREFIX}{}",
            transaction_id.as_str()
        )
    }

    fn transaction_id_from_staged_secret_reference(
        reference: &str,
    ) -> garth::Result<arkret_sdk::TransactionId> {
        let transaction_id = reference
            .strip_prefix(SECURITY_TRANSACTION_STAGED_SECRET_REF_PREFIX)
            .ok_or_else(|| {
                garth::Error::Protocol(
                    "security transaction staged secret reference is not host-owned".to_owned(),
                )
            })?;
        arkret_sdk::TransactionId::new(transaction_id).map_err(|error| {
            garth::Error::Protocol(format!(
                "security transaction staged secret reference is invalid: {error}"
            ))
        })
    }

    pub async fn stage_secret(
        &self,
        transaction_id: &arkret_sdk::TransactionId,
        material: Zeroizing<Vec<u8>>,
    ) -> garth::Result<String> {
        if material.is_empty() {
            return Err(garth::Error::Protocol(
                "security transaction staged secret material is empty".to_owned(),
            ));
        }
        self.secure_store
            .put_secret(
                &Self::staged_secret_key(transaction_id)?,
                material.as_slice(),
                PutSecretOptions {
                    durability: SecretDurability::DurableBeforeReturn,
                    class: SecretClass::Seed,
                },
            )
            .await
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        Ok(Self::staged_secret_reference(transaction_id))
    }

    pub fn load_staged_secret(
        &self,
        transaction_id: &arkret_sdk::TransactionId,
    ) -> garth::Result<Option<arkret_sdk::KeyBytes>> {
        self.secure_store
            .get_secret_bytes(&Self::staged_secret_key(transaction_id)?)
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }
}

fn pending_fresh_device_recovery_storage_key() -> garth::Result<String> {
    crate::secure_key_store::account_scoped_device_key(PENDING_FRESH_DEVICE_RECOVERY_KEY)
        .map_err(|error| garth::Error::Protocol(error.to_string()))
}

pub(crate) async fn store_pending_fresh_device_recovery(
    secure_store: &(dyn SecureKeyStore + Send + Sync),
    transaction_id: &arkret_sdk::TransactionId,
) -> garth::Result<()> {
    let bytes = arkret_sdk::canonical::canonical_json_bytes(&serde_json::json!({
        "transaction_id": transaction_id,
    }))
    .map_err(|error| garth::Error::Protocol(error.to_string()))?;
    secure_store
        .put_secret(
            &pending_fresh_device_recovery_storage_key()?,
            &bytes,
            PutSecretOptions {
                durability: SecretDurability::DurableBeforeReturn,
                class: SecretClass::General,
            },
        )
        .await
        .map_err(|error| garth::Error::Protocol(error.to_string()))
}

pub(crate) fn pending_fresh_device_recovery(
    secure_store: &(dyn SecureKeyStore + Send + Sync),
) -> garth::Result<Option<arkret_sdk::TransactionId>> {
    let Some(bytes) = secure_store
        .get_secret_bytes(&pending_fresh_device_recovery_storage_key()?)
        .map_err(|error| garth::Error::Protocol(error.to_string()))?
    else {
        return Ok(None);
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| garth::Error::Protocol(error.to_string()))?;
    let transaction_id = value
        .get("transaction_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            garth::Error::Protocol(
                "pending fresh-device recovery omitted transaction_id".to_owned(),
            )
        })?;
    arkret_sdk::TransactionId::new(transaction_id.to_owned())
        .map(Some)
        .map_err(|error| garth::Error::Protocol(error.to_string()))
}

pub(crate) fn clear_pending_fresh_device_recovery(
    secure_store: &(dyn SecureKeyStore + Send + Sync),
) -> garth::Result<()> {
    match secure_store.delete_secret(&pending_fresh_device_recovery_storage_key()?) {
        Ok(()) | Err(SecureKeyStoreError::NotFound) => Ok(()),
        Err(error) => Err(garth::Error::Protocol(error.to_string())),
    }
}

fn audit_public_transaction_state(state: &DurableSecurityTransaction) -> garth::Result<()> {
    audit_canonical_public_json("canonical_create_request", &state.canonical_create_request)?;
    if let Some(pending) = &state.pending_continue {
        audit_canonical_public_json(
            "pending_continue.canonical_request",
            &pending.canonical_request,
        )?;
    }
    if let Some(receipt) = state.completed_recovery_receipt()? {
        let canonical = arkret_sdk::canonical::canonical_json_bytes(&receipt).map_err(|error| {
            garth::Error::Protocol(format!(
                "encode completed recovery receipt for secret audit: {error}"
            ))
        })?;
        audit_canonical_public_json("completed_recovery_receipt", &canonical)?;
    }
    if let Some(resource) = &state.last_observed_resource {
        let value = serde_json::to_value(resource).map_err(|error| {
            garth::Error::Protocol(format!(
                "encode security transaction resource for secret audit: {error}"
            ))
        })?;
        audit_public_json_value("last_observed_resource", &value)?;
    }
    Ok(())
}

fn audit_canonical_public_json(label: &str, bytes: &[u8]) -> garth::Result<()> {
    let value = arkret_sdk::canonical::parse_canonical_json(bytes).map_err(|error| {
        garth::Error::Protocol(format!(
            "security transaction {label} is not canonical public JSON: {error}"
        ))
    })?;
    audit_public_json_value(label, &value)
}

fn audit_public_json_value(path: &str, value: &Value) -> garth::Result<()> {
    let Some(violation) = crate::secret_surface::find_json_violation(path, value) else {
        return Ok(());
    };
    let message = match &violation {
        crate::secret_surface::SecretSurfaceViolation::ForbiddenField(_) => {
            "contains forbidden secret field"
        }
        crate::secret_surface::SecretSurfaceViolation::PrivateKeyBlock(_) => {
            "contains a private-key block"
        }
        crate::secret_surface::SecretSurfaceViolation::RecoveryMnemonic(_) => {
            "contains a recovery mnemonic"
        }
        crate::secret_surface::SecretSurfaceViolation::TextAssignment(_) => {
            "contains a secret-bearing text assignment"
        }
    };
    Err(garth::Error::Protocol(format!(
        "security transaction public state {message} at {}",
        violation.path()
    )))
}

impl SecurityTransactionStore for InksonSecurityTransactionStore {
    fn load(
        &self,
        transaction_id: &arkret_sdk::TransactionId,
    ) -> garth::Result<Option<DurableSecurityTransaction>> {
        self.secure_store
            .get_secret_bytes(&Self::storage_key(transaction_id)?)
            .map_err(|error| garth::Error::Protocol(error.to_string()))?
            .map(|bytes| {
                serde_json::from_slice(&bytes).map_err(|error| {
                    garth::Error::Protocol(format!(
                        "decode durable security transaction state: {error}"
                    ))
                })
            })
            .transpose()
    }

    fn save<'a>(
        &'a self,
        state: &'a DurableSecurityTransaction,
    ) -> impl std::future::Future<Output = garth::Result<()>> + garth::MaybeSend + 'a {
        let encoded = audit_public_transaction_state(state).and_then(|()| {
            serde_json::to_vec(state).map_err(|error| {
                garth::Error::Protocol(format!(
                    "encode durable security transaction state: {error}"
                ))
            })
        });
        async move {
            self.secure_store
                .put_secret(
                    &Self::storage_key(&state.transaction_id)?,
                    &encoded?,
                    PutSecretOptions {
                        durability: SecretDurability::DurableBeforeReturn,
                        class: SecretClass::General,
                    },
                )
                .await
                .map_err(|error| garth::Error::Protocol(error.to_string()))
        }
    }

    fn clear_staged_secret(&self, reference: &str) -> garth::Result<()> {
        let transaction_id = Self::transaction_id_from_staged_secret_reference(reference)?;
        match self
            .secure_store
            .delete_secret(&Self::staged_secret_key(&transaction_id)?)
        {
            Ok(()) | Err(SecureKeyStoreError::NotFound) => Ok(()),
            Err(error) => Err(garth::Error::Protocol(error.to_string())),
        }
    }

    fn remove(&self, transaction_id: &arkret_sdk::TransactionId) -> garth::Result<()> {
        let state_result = match self
            .secure_store
            .delete_secret(&Self::storage_key(transaction_id)?)
        {
            Ok(()) | Err(SecureKeyStoreError::NotFound) => Ok(()),
            Err(error) => Err(garth::Error::Protocol(error.to_string())),
        };
        let staged_result = match self
            .secure_store
            .delete_secret(&Self::staged_secret_key(transaction_id)?)
        {
            Ok(()) | Err(SecureKeyStoreError::NotFound) => Ok(()),
            Err(error) => Err(garth::Error::Protocol(error.to_string())),
        };
        state_result.and(staged_result)
    }
}

#[derive(Clone)]
pub struct InksonSecurityTransactionTransport {
    client: arkret_sdk::http_client::Client,
}

impl InksonSecurityTransactionTransport {
    fn new(client: arkret_sdk::http_client::Client) -> Self {
        Self { client }
    }
}

impl garth::SecurityTransactionTransport for InksonSecurityTransactionTransport {
    async fn create(
        &self,
        request: &arkret_models_crypto::SecurityTransactionCreateRequest,
    ) -> garth::Result<arkret_models_crypto::SecurityTransaction> {
        self.client
            .create_security_transaction(request)
            .await
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    async fn get(
        &self,
        transaction_id: &arkret_sdk::TransactionId,
    ) -> garth::Result<arkret_models_crypto::SecurityTransaction> {
        self.client
            .get_security_transaction(transaction_id)
            .await
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    async fn continue_transaction(
        &self,
        transaction_id: &arkret_sdk::TransactionId,
        request: &arkret_models_crypto::SecurityTransactionContinueRequest,
    ) -> garth::Result<arkret_models_crypto::SecurityTransaction> {
        self.client
            .continue_security_transaction(transaction_id, request)
            .await
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }
}

pub type InksonSecurityTransactionEngine = garth::SecurityTransactionEngine<
    InksonSecurityTransactionTransport,
    InksonSecurityTransactionStore,
>;

pub fn security_transaction_engine(
    client: arkret_sdk::http_client::Client,
    secure_store: Arc<dyn SecureKeyStore + Send + Sync>,
) -> InksonSecurityTransactionEngine {
    garth::SecurityTransactionEngine::new(
        InksonSecurityTransactionTransport::new(client),
        InksonSecurityTransactionStore::new(secure_store),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every storage key in this module resolves through the process-global
    // device-seed scope (`account_scoped_device_key`), so each test installs
    // its own scope instead of depending on whatever a neighbouring test
    // happens to leave behind.
    fn activate_test_scope() -> crate::secure_key_store::DeviceSeedScopeTestGuard {
        let authority = arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example".to_owned()).unwrap(),
        );
        let device_id =
            arkret_sdk::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000042".to_owned())
                .unwrap();
        crate::secure_key_store::DeviceSeedScopeTestGuard::replace(Some((&authority, &device_id)))
    }

    #[tokio::test]
    async fn pending_fresh_device_recovery_pointer_round_trips_and_clears() {
        let _scope = activate_test_scope();
        let secure_store = garth::MemorySecureKeyStore::new();
        let transaction_id =
            arkret_sdk::TransactionId::new("ak:transaction:01904100-0000-7000-8000-abcdefabcda0")
                .unwrap();

        store_pending_fresh_device_recovery(&secure_store, &transaction_id)
            .await
            .unwrap();
        assert_eq!(
            pending_fresh_device_recovery(&secure_store)
                .unwrap()
                .as_ref(),
            Some(&transaction_id)
        );
        clear_pending_fresh_device_recovery(&secure_store).unwrap();
        clear_pending_fresh_device_recovery(&secure_store).unwrap();
        assert!(
            pending_fresh_device_recovery(&secure_store)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn adapter_round_trips_public_plan_without_plaintext_secret() {
        let _scope = activate_test_scope();
        let secure_store: Arc<dyn SecureKeyStore + Send + Sync> =
            Arc::new(garth::MemorySecureKeyStore::new());
        let store = InksonSecurityTransactionStore::new(secure_store);
        let transaction_id =
            arkret_sdk::TransactionId::new("ak:transaction:01904100-0000-7000-8000-abcdefabcdef")
                .unwrap();
        let state = DurableSecurityTransaction {
            transaction_id: transaction_id.clone(),
            canonical_create_request: br#"{"prepared_plan":"public"}"#.to_vec(),
            staged_secret_ref: Some("secure-store://recovery/staged-1".to_owned()),
            pending_continue: None,
            completed_recovery_receipt: None,
            last_observed_resource: None,
        };
        store.save(&state).await.unwrap();
        let loaded = store.load(&transaction_id).unwrap().unwrap();
        assert_eq!(
            loaded.canonical_create_request,
            state.canonical_create_request
        );
        assert_eq!(loaded.staged_secret_ref, state.staged_secret_ref);
        store.remove(&transaction_id).unwrap();
        assert!(store.load(&transaction_id).unwrap().is_none());
    }

    #[tokio::test]
    async fn adapter_round_trips_completed_recovery_receipt_exactly() {
        let _scope = activate_test_scope();
        let secure_store: Arc<dyn SecureKeyStore + Send + Sync> =
            Arc::new(garth::MemorySecureKeyStore::new());
        let store = InksonSecurityTransactionStore::new(secure_store);
        let transaction_id =
            arkret_sdk::TransactionId::new("ak:transaction:01904100-0000-7000-8000-abcdefabcda1")
                .unwrap();
        let receipt = serde_json::json!({
            "schema": "ak.schema.recovery_receipt.v1",
            "receipt_id": "ak:receipt:01904100-0000-7000-8000-abcdefabcda2",
            "transaction_id": transaction_id,
            "transaction_request_digest": format!("sha256:{}", "1".repeat(64)),
            "prepared_plan_digest": format!("sha256:{}", "2".repeat(64)),
            "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixtureprincipalexample",
                "station_id": "ak:did_core:webvh:z6mkfixtureserviceexample"
            },
            "recovery_session_id": "ak:recovery_session:01904100-0000-7000-8000-abcdefabcda3",
            "policy_id": "ak:policy:01904100-0000-7000-8000-abcdefabcda4",
            "policy_version": 1,
            "trust_domain": "ak:trust_domain:fixture.example",
            "new_device_id": "ak:device:01904100-0000-7000-8000-abcdefabcda5",
            "identity_model": "pcr_policy",
            "recovery_authority_kind": "pcr_policy",
            "previous_model_generation_ref": 7,
            "result_model_generation_ref": 8,
            "authorization_event_id": "ak:event:AWKDhmQTc5zyfilaLwPF3xnhoZAjxSha7Z-6grioN9aW",
            "reanchor_event_id": "ak:event:AR8bu-n-kOOB3nRUvYuIEglCX5B-JpFaNTex9gxs_cWY",
            "proof_summary": {
                "kind": "recovery_unlock",
                "proof_digest": format!("sha256:{}", "3".repeat(64))
            },
            "unlocked_backups": [],
            "welcome_count": 0,
            "outcome": "completed",
            "started_at": "2026-09-19T10:00:00.000Z",
            "completed_at": "2026-09-19T10:00:01.000Z",
            "auth_data": {
                "verification_method": "did:web:alice.example#device-1",
                "signature_algorithm": "Ed25519",
                "signature": "AA"
            }
        });
        let canonical_receipt = arkret_sdk::canonical::canonical_json_bytes(&receipt).unwrap();
        let state: DurableSecurityTransaction = serde_json::from_value(serde_json::json!({
            "transaction_id": transaction_id,
            "canonical_create_request": arkret_sdk::canonical::canonical_json_bytes(
                &serde_json::json!({"kind": "recovery"}),
            ).unwrap(),
            "staged_secret_ref": null,
            "pending_continue": null,
            "completed_recovery_receipt": {
                "canonical_receipt": canonical_receipt,
            },
            "last_observed_resource": null,
        }))
        .unwrap();

        store.save(&state).await.unwrap();
        let restored = store.load(&transaction_id).unwrap().unwrap();

        assert_eq!(
            serde_json::to_value(restored.completed_recovery_receipt().unwrap().unwrap()).unwrap(),
            receipt
        );
    }

    #[tokio::test]
    async fn adapter_stages_and_idempotently_clears_terminal_secret_material() {
        let _scope = activate_test_scope();
        let secure_store = Arc::new(garth::MemorySecureKeyStore::new());
        let store = InksonSecurityTransactionStore::new(secure_store.clone());
        let transaction_id =
            arkret_sdk::TransactionId::new("ak:transaction:01904100-0000-7000-8000-abcdefabcded")
                .unwrap();

        let reference = store
            .stage_secret(
                &transaction_id,
                Zeroizing::new(b"staged key material".to_vec()),
            )
            .await
            .unwrap();
        assert_eq!(
            reference,
            format!("{SECURITY_TRANSACTION_STAGED_SECRET_REF_PREFIX}{transaction_id}")
        );
        assert!(
            secure_store
                .get_secret_bytes(
                    &InksonSecurityTransactionStore::staged_secret_key(&transaction_id).unwrap(),
                )
                .unwrap()
                .is_some()
        );
        assert_eq!(
            store
                .load_staged_secret(&transaction_id)
                .unwrap()
                .unwrap()
                .as_slice(),
            b"staged key material"
        );

        store.clear_staged_secret(&reference).unwrap();
        store.clear_staged_secret(&reference).unwrap();
        assert!(
            secure_store
                .get_secret_bytes(
                    &InksonSecurityTransactionStore::staged_secret_key(&transaction_id).unwrap(),
                )
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn adapter_rejects_forbidden_secret_fields_before_persistence() {
        let _scope = activate_test_scope();
        let secure_store: Arc<dyn SecureKeyStore + Send + Sync> =
            Arc::new(garth::MemorySecureKeyStore::new());
        let store = InksonSecurityTransactionStore::new(secure_store);
        let transaction_id =
            arkret_sdk::TransactionId::new("ak:transaction:01904100-0000-7000-8000-abcdefabcdea")
                .unwrap();
        let state = DurableSecurityTransaction {
            transaction_id: transaction_id.clone(),
            canonical_create_request:
                br#"{"binding":{"plaintext_keybag":"synthetic-sensitive-material"}}"#.to_vec(),
            staged_secret_ref: Some("secure-store://recovery/staged-2".to_owned()),
            pending_continue: None,
            completed_recovery_receipt: None,
            last_observed_resource: None,
        };

        let error = store.save(&state).await.unwrap_err().to_string();

        assert!(error.contains("forbidden secret field"), "{error}");
        assert!(error.contains("plaintext_keybag"), "{error}");
        assert!(!error.contains("synthetic-sensitive-material"), "{error}");
        assert!(store.load(&transaction_id).unwrap().is_none());
    }

    #[tokio::test]
    async fn adapter_rejects_recovery_mnemonic_hidden_in_public_text() {
        let _scope = activate_test_scope();
        let secure_store: Arc<dyn SecureKeyStore + Send + Sync> =
            Arc::new(garth::MemorySecureKeyStore::new());
        let store = InksonSecurityTransactionStore::new(secure_store);
        let transaction_id =
            arkret_sdk::TransactionId::new("ak:transaction:01904100-0000-7000-8000-abcdefabcdeb")
                .unwrap();
        let mnemonic = crate::recovery_crypto::format_recovery_key(&[0_u8; 32]);
        let state = DurableSecurityTransaction {
            transaction_id: transaction_id.clone(),
            canonical_create_request: arkret_sdk::canonical::canonical_json_bytes(
                &serde_json::json!({"note": format!("do not persist {mnemonic} here")}),
            )
            .unwrap(),
            staged_secret_ref: Some("secure-store://recovery/staged-3".to_owned()),
            pending_continue: None,
            completed_recovery_receipt: None,
            last_observed_resource: None,
        };

        let error = store.save(&state).await.unwrap_err().to_string();

        assert!(error.contains("recovery mnemonic"), "{error}");
        assert!(!error.contains(&mnemonic), "{error}");
        assert!(store.load(&transaction_id).unwrap().is_none());
    }

    #[tokio::test]
    async fn adapter_allows_public_digests_ciphertext_and_opaque_secret_reference() {
        let _scope = activate_test_scope();
        let secure_store: Arc<dyn SecureKeyStore + Send + Sync> =
            Arc::new(garth::MemorySecureKeyStore::new());
        let store = InksonSecurityTransactionStore::new(secure_store);
        let transaction_id =
            arkret_sdk::TransactionId::new("ak:transaction:01904100-0000-7000-8000-abcdefabcdec")
                .unwrap();
        let state = DurableSecurityTransaction {
            transaction_id: transaction_id.clone(),
            canonical_create_request: arkret_sdk::canonical::canonical_json_bytes(
                &serde_json::json!({
                    "encrypted_backup_material": "ciphertext-only",
                    "prepared_plan_digest": format!("sha256:{}", "a".repeat(64)),
                }),
            )
            .unwrap(),
            staged_secret_ref: Some("secure-store://recovery/staged-4".to_owned()),
            pending_continue: None,
            completed_recovery_receipt: None,
            last_observed_resource: None,
        };

        store.save(&state).await.unwrap();

        assert!(store.load(&transaction_id).unwrap().is_some());
    }
}
