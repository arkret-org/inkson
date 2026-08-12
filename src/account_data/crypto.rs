use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;

const ACCOUNT_DATA_NAMESPACE_INFO: &[u8] = b"secret_storage/account_data_namespace/v1";

/// Derive the account-data namespace subkey shared by the holder's devices.
/// The subkey is domain-separated from value-encryption use of the account
/// secret and is never sent to the server.
pub fn account_data_namespace_key_from_secret(account_secret: &str) -> anyhow::Result<[u8; 32]> {
    let secret = URL_SAFE_NO_PAD
        .decode(account_secret.trim())
        .map_err(|error| anyhow::anyhow!("account secret base64url: {error}"))?;
    if secret.len() != 32 {
        anyhow::bail!("account secret must be 32 bytes");
    }
    let hk = Hkdf::<Sha256>::new(None, &secret);
    let mut namespace_key = [0u8; 32];
    hk.expand(ACCOUNT_DATA_NAMESPACE_INFO, &mut namespace_key)
        .map_err(|_| anyhow::anyhow!("account-data namespace HKDF expand failed"))?;
    Ok(namespace_key)
}

pub fn account_data_namespace_key(actor_id: &str) -> anyhow::Result<[u8; 32]> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let secret = crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), actor_id)?
        .ok_or_else(|| anyhow::anyhow!("account secret is unavailable"))?;
    account_data_namespace_key_from_secret(&secret.secret)
}

/// Seal `plaintext` for `account_data_key` under `actor_id`'s account secret.
///
/// The envelope AAD binds both `actor_id` and `account_data_key`, so a value
/// cannot be replayed under another key or another account.
pub fn encrypt_account_data_value(
    actor_id: &str,
    account_data_key: &str,
    plaintext: &Value,
) -> anyhow::Result<Value> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let account_secret =
        crate::mls::runtime::load_or_create_account_mls_secret(secure_store.as_ref(), actor_id)?;
    let secret = URL_SAFE_NO_PAD
        .decode(account_secret)
        .map_err(|error| anyhow::anyhow!("account secret base64url: {error}"))?;
    let secret: [u8; 32] = secret
        .try_into()
        .map_err(|_| anyhow::anyhow!("account secret must be 32 bytes"))?;
    let actor_core_id = crate::mls_api_helpers::principal_core_id(actor_id)?;
    let envelope = arkret_sdk::account_data_crypto::seal_account_data_value(
        &secret,
        &actor_core_id,
        account_data_key,
        plaintext,
    )?;
    serde_json::to_value(envelope)
        .map_err(|error| anyhow::anyhow!("account-data encrypted value: {error}"))
}

pub fn decrypt_account_data_value(
    actor_id: &str,
    account_data_key: &str,
    value: &Value,
) -> anyhow::Result<Value> {
    let envelope: arkret_sdk::account_data_crypto::AccountDataEncryptedValue =
        serde_json::from_value(value.clone())?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let account_secret =
        crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), actor_id)?
            .ok_or_else(|| anyhow::anyhow!("account secret is unavailable"))?;
    let secret = URL_SAFE_NO_PAD
        .decode(account_secret.secret)
        .map_err(|error| anyhow::anyhow!("account secret base64url: {error}"))?;
    let secret: [u8; 32] = secret
        .try_into()
        .map_err(|_| anyhow::anyhow!("account secret must be 32 bytes"))?;
    let actor_core_id = crate::mls_api_helpers::principal_core_id(actor_id)?;
    arkret_sdk::account_data_crypto::open_account_data_value(
        &secret,
        &actor_core_id,
        account_data_key,
        &envelope,
    )
    .map_err(Into::into)
}

pub fn decrypt_account_data_entry<T: Serialize>(
    actor_id: &str,
    account_data_key: &str,
    entry: &T,
) -> anyhow::Result<Value> {
    let entry = serde_json::to_value(entry)?;
    let value = entry
        .get("content")
        .or_else(|| entry.get("body"))
        .or_else(|| entry.get("encrypted_payload"))
        .or_else(|| entry.get("encrypted_content"))
        .ok_or_else(|| anyhow::anyhow!("account_data entry has no encrypted value"))?;
    decrypt_account_data_value(actor_id, account_data_key, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_encrypted_value_fails_closed() {
        assert!(
            decrypt_account_data_entry(
                "did:web:alice.example",
                "ak.dnd_schedule",
                &serde_json::json!({"content": {"dnd": {"enabled": true}}}),
            )
            .is_err()
        );
    }
}
