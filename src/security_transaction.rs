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

const SECURITY_TRANSACTION_STATE_KEY: &str = "security_transaction.state.v1";
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

    fn storage_key(transaction_id: &arkret_sdk::TransactionId) -> String {
        crate::secure_key_store::account_scoped_device_key(&format!(
            "{SECURITY_TRANSACTION_STATE_KEY}.{}",
            transaction_id.as_str()
        ))
    }

    fn staged_secret_key(transaction_id: &arkret_sdk::TransactionId) -> String {
        crate::secure_key_store::account_scoped_device_key(&format!(
            "{SECURITY_TRANSACTION_STAGED_SECRET_KEY}.{}",
            transaction_id.as_str()
        ))
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
                &Self::staged_secret_key(transaction_id),
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
    ) -> garth::Result<Option<Zeroizing<Vec<u8>>>> {
        self.secure_store
            .get_secret_bytes(&Self::staged_secret_key(transaction_id))
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }
}

fn pending_fresh_device_recovery_storage_key() -> String {
    crate::secure_key_store::account_scoped_device_key(PENDING_FRESH_DEVICE_RECOVERY_KEY)
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
            &pending_fresh_device_recovery_storage_key(),
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
        .get_secret_bytes(&pending_fresh_device_recovery_storage_key())
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
    match secure_store.delete_secret(&pending_fresh_device_recovery_storage_key()) {
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
    if let Some(accepted) = &state.accepted_terminal_continue {
        audit_canonical_public_json("accepted_terminal_continue", accepted)?;
    }
    if let Some(pending) = &state.pending_erase_request {
        audit_canonical_public_json("pending_erase_request", pending)?;
    }
    if let Some(pending) = &state.pending_completion_grant_request {
        audit_canonical_public_json("pending_completion_grant_request", pending)?;
    }
    if let Some(accepted) = &state.accepted_completion_grant_request {
        audit_canonical_public_json("accepted_completion_grant_request", accepted)?;
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
            .get_secret_bytes(&Self::storage_key(transaction_id))
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
                    &Self::storage_key(&state.transaction_id),
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
            .delete_secret(&Self::staged_secret_key(&transaction_id))
        {
            Ok(()) | Err(SecureKeyStoreError::NotFound) => Ok(()),
            Err(error) => Err(garth::Error::Protocol(error.to_string())),
        }
    }

    fn remove(&self, transaction_id: &arkret_sdk::TransactionId) -> garth::Result<()> {
        let state_result = match self
            .secure_store
            .delete_secret(&Self::storage_key(transaction_id))
        {
            Ok(()) | Err(SecureKeyStoreError::NotFound) => Ok(()),
            Err(error) => Err(garth::Error::Protocol(error.to_string())),
        };
        let staged_result = match self
            .secure_store
            .delete_secret(&Self::staged_secret_key(transaction_id))
        {
            Ok(()) | Err(SecureKeyStoreError::NotFound) => Ok(()),
            Err(error) => Err(garth::Error::Protocol(error.to_string())),
        };
        state_result.and(staged_result)
    }
}

pub type InksonSecurityTransactionEngine = garth::SecurityTransactionEngine<
    arkret_sdk::http_client::Client,
    InksonSecurityTransactionStore,
>;

pub fn security_transaction_engine(
    client: arkret_sdk::http_client::Client,
    secure_store: Arc<dyn SecureKeyStore + Send + Sync>,
) -> InksonSecurityTransactionEngine {
    garth::SecurityTransactionEngine::new(client, InksonSecurityTransactionStore::new(secure_store))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every storage key in this module resolves through the process-global
    // device-seed scope (`account_scoped_device_key`), so each test installs
    // its own scope instead of depending on whatever a neighbouring test
    // happens to leave behind.
    fn activate_test_scope() -> crate::secure_key_store::DeviceSeedScopeTestGuard {
        let authority = arkret_sdk::PrincipalAuthorityKey::new(
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
            accepted_terminal_continue: None,
            pending_erase_request: None,
            pending_completion_grant_request: None,
            accepted_completion_grant_request: None,
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
                .get_secret_bytes(&InksonSecurityTransactionStore::staged_secret_key(
                    &transaction_id
                ))
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
                .get_secret_bytes(&InksonSecurityTransactionStore::staged_secret_key(
                    &transaction_id
                ))
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
            accepted_terminal_continue: None,
            pending_erase_request: None,
            pending_completion_grant_request: None,
            accepted_completion_grant_request: None,
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
            accepted_terminal_continue: None,
            pending_erase_request: None,
            pending_completion_grant_request: None,
            accepted_completion_grant_request: None,
            last_observed_resource: None,
        };

        let error = store.save(&state).await.unwrap_err().to_string();

        assert!(error.contains("recovery mnemonic"), "{error}");
        assert!(!error.contains(&mnemonic), "{error}");
        assert!(store.load(&transaction_id).unwrap().is_none());
    }

    #[tokio::test]
    async fn adapter_audits_pending_erase_request_before_persistence() {
        let _scope = activate_test_scope();
        let secure_store: Arc<dyn SecureKeyStore + Send + Sync> =
            Arc::new(garth::MemorySecureKeyStore::new());
        let store = InksonSecurityTransactionStore::new(secure_store);
        let transaction_id =
            arkret_sdk::TransactionId::new("ak:transaction:01904100-0000-7000-8000-abcdefabcdee")
                .unwrap();
        let state = DurableSecurityTransaction {
            transaction_id: transaction_id.clone(),
            canonical_create_request: br#"{"prepared_plan":"public"}"#.to_vec(),
            staged_secret_ref: None,
            pending_continue: None,
            accepted_terminal_continue: None,
            pending_erase_request: Some(
                arkret_sdk::canonical::canonical_json_bytes(
                    &serde_json::json!({"mls_secret": "must-not-persist"}),
                )
                .unwrap(),
            ),
            pending_completion_grant_request: None,
            accepted_completion_grant_request: None,
            last_observed_resource: None,
        };

        let error = store.save(&state).await.unwrap_err().to_string();

        assert!(error.contains("forbidden secret field"), "{error}");
        assert!(
            error.contains("pending_erase_request.mls_secret"),
            "{error}"
        );
        assert!(!error.contains("must-not-persist"), "{error}");
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
            accepted_terminal_continue: None,
            pending_erase_request: None,
            pending_completion_grant_request: None,
            accepted_completion_grant_request: None,
            last_observed_resource: None,
        };

        store.save(&state).await.unwrap();

        assert!(store.load(&transaction_id).unwrap().is_some());
    }
}
