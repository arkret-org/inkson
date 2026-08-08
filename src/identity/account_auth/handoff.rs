//! Secure storage for the short-lived account-handoff credential.

use crate::secure_key_store::default_secure_key_store;

pub(crate) const ACCOUNT_HANDOFF_GRANT_SECRET_KEY: &str = "inkson.account_handoff_grant.v1";
pub(crate) const PREPARED_IDENTITY_CREATION_REQUEST_SECRET_KEY: &str =
    "inkson.prepared_identity_creation_request.v1";

pub async fn persist_account_handoff_grant(grant: &str) -> anyhow::Result<()> {
    let grant = grant.trim();
    if grant.is_empty() {
        anyhow::bail!("account handoff grant is empty");
    }
    default_secure_key_store("inkson")
        .store_secret_durable(ACCOUNT_HANDOFF_GRANT_SECRET_KEY, grant)
        .await?;
    Ok(())
}

pub fn load_account_handoff_grant() -> anyhow::Result<Option<String>> {
    Ok(default_secure_key_store("inkson").get_secret(ACCOUNT_HANDOFF_GRANT_SECRET_KEY)?)
}

pub fn clear_account_handoff_grant() -> anyhow::Result<()> {
    default_secure_key_store("inkson").delete_secret(ACCOUNT_HANDOFF_GRANT_SECRET_KEY)?;
    Ok(())
}

/// Persist the complete root-signed registration before its first submission.
pub async fn persist_prepared_identity_creation_request(
    request: &arkret_sdk::AccountRegisterRequestBody,
) -> anyhow::Result<()> {
    request.validate()?;
    let canonical = String::from_utf8(arkret_sdk::canonical::canonical_json_bytes(request)?)?;
    default_secure_key_store("inkson")
        .store_secret_durable(PREPARED_IDENTITY_CREATION_REQUEST_SECRET_KEY, &canonical)
        .await?;
    Ok(())
}

pub fn load_prepared_identity_creation_request()
-> anyhow::Result<Option<arkret_sdk::AccountRegisterRequestBody>> {
    default_secure_key_store("inkson")
        .get_secret(PREPARED_IDENTITY_CREATION_REQUEST_SECRET_KEY)?
        .map(|canonical| {
            let request = arkret_sdk::canonical::from_canonical_json_slice(canonical.as_bytes())?;
            Ok::<_, anyhow::Error>(request)
        })
        .transpose()
}

pub fn clear_prepared_identity_creation_request() -> anyhow::Result<()> {
    default_secure_key_store("inkson")
        .delete_secret(PREPARED_IDENTITY_CREATION_REQUEST_SECRET_KEY)?;
    Ok(())
}
