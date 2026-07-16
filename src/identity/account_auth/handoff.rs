//! Secure storage for the short-lived account-handoff credential.

use crate::secure_key_store::default_secure_key_store;

pub(crate) const ACCOUNT_HANDOFF_GRANT_SECRET_KEY: &str = "inkson.account_handoff_grant.v1";

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
