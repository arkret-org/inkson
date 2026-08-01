use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use serde_json::Value;

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
    let account_secret = crate::mls::runtime::load_or_create_account_mls_secret(
        secure_store.as_ref(),
        actor_id,
        "",
    )?;
    let secret = URL_SAFE_NO_PAD
        .decode(account_secret)
        .map_err(|error| anyhow::anyhow!("account secret base64url: {error}"))?;
    let secret: [u8; 32] = secret
        .try_into()
        .map_err(|_| anyhow::anyhow!("account secret must be 32 bytes"))?;
    let envelope = arkret_sdk::account_data_crypto::seal_account_data_value(
        &secret,
        actor_id,
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
    arkret_sdk::account_data_crypto::open_account_data_value(
        &secret,
        actor_id,
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
