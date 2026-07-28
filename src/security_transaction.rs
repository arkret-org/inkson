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

const SECURITY_TRANSACTION_STATE_KEY: &str = "security_transaction.state.v1";

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
        let encoded = serde_json::to_vec(state).map_err(|error| {
            garth::Error::Protocol(format!(
                "encode durable security transaction state: {error}"
            ))
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

    fn remove(&self, transaction_id: &arkret_sdk::TransactionId) -> garth::Result<()> {
        match self
            .secure_store
            .delete_secret(&Self::storage_key(transaction_id))
        {
            Ok(()) | Err(SecureKeyStoreError::NotFound) => Ok(()),
            Err(error) => Err(garth::Error::Protocol(error.to_string())),
        }
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

    #[tokio::test]
    async fn adapter_round_trips_public_plan_without_plaintext_secret() {
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
}
