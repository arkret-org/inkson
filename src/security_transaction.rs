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

const SECURITY_TRANSACTION_STATE_KEY: &str = "security_transaction.state.v1";
const FORBIDDEN_SECRET_FIELD_NAMES: &[&str] = &[
    "account_mls_secret",
    "device_private_key",
    "device_seed",
    "hkdf_prk",
    "mls_secret",
    "mnemonic",
    "plaintext_keybag",
    "prk",
    "private_key",
    "recovery_key",
    "recovery_phrase",
    "recovery_secret",
    "root_private_key",
    "root_seed",
    "secret_b64u",
    "seed",
];

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

fn audit_public_transaction_state(state: &DurableSecurityTransaction) -> garth::Result<()> {
    audit_canonical_public_json(
        "canonical_create_request",
        &state.canonical_create_request,
    )?;
    if let Some(pending) = &state.pending_continue {
        audit_canonical_public_json("pending_continue.canonical_request", &pending.canonical_request)?;
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
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let next_path = format!("{path}.{key}");
                if FORBIDDEN_SECRET_FIELD_NAMES
                    .iter()
                    .any(|forbidden| key.eq_ignore_ascii_case(forbidden))
                {
                    return Err(garth::Error::Protocol(format!(
                        "security transaction public state contains forbidden secret field at {next_path}"
                    )));
                }
                audit_public_json_value(&next_path, value)?;
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                audit_public_json_value(&format!("{path}[{index}]"), item)?;
            }
        }
        Value::String(text) => {
            if text.contains("-----BEGIN PRIVATE KEY-----")
                || text.contains("-----BEGIN RSA PRIVATE KEY-----")
                || text.contains("-----BEGIN EC PRIVATE KEY-----")
                || text.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
                || text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
            {
                return Err(garth::Error::Protocol(format!(
                    "security transaction public state contains a private-key block at {path}"
                )));
            }
            if contains_recovery_mnemonic(text) {
                return Err(garth::Error::Protocol(format!(
                    "security transaction public state contains a recovery mnemonic at {path}"
                )));
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn contains_recovery_mnemonic(text: &str) -> bool {
    let words = text
        .split(|character: char| !character.is_ascii_alphabetic())
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    words.windows(24).any(|window| {
        crate::recovery_crypto::normalize_recovery_key_input(&window.join(" ")).is_some()
    })
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

    #[tokio::test]
    async fn adapter_rejects_forbidden_secret_fields_before_persistence() {
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
            last_observed_resource: None,
        };

        let error = store.save(&state).await.unwrap_err().to_string();

        assert!(error.contains("recovery mnemonic"), "{error}");
        assert!(!error.contains(&mnemonic), "{error}");
        assert!(store.load(&transaction_id).unwrap().is_none());
    }

    #[tokio::test]
    async fn adapter_allows_public_digests_ciphertext_and_opaque_secret_reference() {
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
            last_observed_resource: None,
        };

        store.save(&state).await.unwrap();

        assert!(store.load(&transaction_id).unwrap().is_some());
    }
}
