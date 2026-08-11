//! Secure storage for the short-lived account-handoff credential.

use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::secure_key_store::default_secure_key_store;

pub(crate) const ACCOUNT_HANDOFF_GRANT_SECRET_KEY: &str = "inkson.account_handoff_grant.v1";
pub(crate) const ACCOUNT_HANDOFF_GRANT_SECRET_KEY_PREFIX: &str = "inkson.account_handoff_grant.v2.";
pub(crate) const PREPARED_IDENTITY_CREATION_REQUEST_SECRET_KEY: &str =
    "inkson.prepared_identity_creation_request.v1";
pub(crate) const PREPARED_IDENTITY_CREATION_REQUEST_SECRET_KEY_PREFIX: &str =
    "inkson.prepared_identity_creation_request.v2.";
pub(crate) const PENDING_IDENTITY_CREATION_RECOVERY_KEY_PREFIX: &str =
    "inkson.pending_identity_creation_recovery_key.v1.";

fn pending_identity_creation_recovery_key(
    handoff: &crate::state::PendingAccountHandoff,
) -> anyhow::Result<String> {
    let account_subject = handoff
        .account_subject
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("account handoff omits account subject"))?;
    let mut digest = Sha256::new();
    digest.update(b"inkson.pending-identity-creation-recovery-key-scope-v1\0");
    digest.update(account_subject.as_str().as_bytes());
    digest.update(b"\0");
    digest.update(handoff.audience.as_bytes());
    digest.update(b"\0");
    digest.update(handoff.device_id.as_bytes());
    Ok(format!(
        "{PENDING_IDENTITY_CREATION_RECOVERY_KEY_PREFIX}{}",
        arkret_sdk::base64url_encode(digest.finalize())
    ))
}

/// Durably retain the user-confirmed key before the first remote mutation.
///
/// The phrase lives only in the platform SecureKeyStore. Public onboarding
/// checkpoints retain fingerprints and public keys, never the phrase itself.
pub async fn persist_pending_identity_creation_recovery_key(
    handoff: &crate::state::PendingAccountHandoff,
    recovery_key: &str,
) -> anyhow::Result<()> {
    let recovery_key = recovery_key.trim();
    arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
        recovery_key,
        "",
        0,
    )?;
    default_secure_key_store("inkson")
        .store_secret_durable(
            &pending_identity_creation_recovery_key(handoff)?,
            recovery_key,
        )
        .await?;
    Ok(())
}

pub fn load_pending_identity_creation_recovery_key(
    handoff: &crate::state::PendingAccountHandoff,
) -> anyhow::Result<Option<Zeroizing<String>>> {
    Ok(default_secure_key_store("inkson")
        .get_secret(&pending_identity_creation_recovery_key(handoff)?)?
        .map(Zeroizing::new))
}

pub fn clear_pending_identity_creation_recovery_key(
    handoff: &crate::state::PendingAccountHandoff,
) -> anyhow::Result<()> {
    default_secure_key_store("inkson")
        .delete_secret(&pending_identity_creation_recovery_key(handoff)?)?;
    Ok(())
}

fn prepared_identity_creation_request_secret_key(
    account_subject: &arkret_sdk::Hash,
    principal_id: &str,
    lease_id: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"inkson.prepared-identity-creation-request-scope-v2\0");
    digest.update(account_subject.as_str().as_bytes());
    digest.update(b"\0");
    digest.update(principal_id.as_bytes());
    digest.update(b"\0");
    digest.update(lease_id.as_bytes());
    format!(
        "{PREPARED_IDENTITY_CREATION_REQUEST_SECRET_KEY_PREFIX}{}",
        arkret_sdk::base64url_encode(digest.finalize())
    )
}

fn account_handoff_grant_secret_key(
    handoff: &crate::state::PendingAccountHandoff,
) -> anyhow::Result<String> {
    let account_subject = handoff
        .account_subject
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("account handoff omits account subject"))?;
    let mut digest = Sha256::new();
    digest.update(b"inkson.account-handoff-grant-scope-v2\0");
    digest.update(account_subject.as_str().as_bytes());
    digest.update(b"\0");
    digest.update(handoff.request_id.as_bytes());
    digest.update(b"\0");
    digest.update(handoff.holder_jkt.as_bytes());
    Ok(format!(
        "{ACCOUNT_HANDOFF_GRANT_SECRET_KEY_PREFIX}{}",
        arkret_sdk::base64url_encode(digest.finalize())
    ))
}

fn prepared_request_matches_scope(
    request: &arkret_sdk::AccountRegisterRequestBody,
    account_subject: &arkret_sdk::Hash,
    principal_id: &str,
    lease_id: &str,
) -> bool {
    request.principal_id.as_str() == principal_id
        && request
            .identity_creation
            .as_ref()
            .is_some_and(|registration| {
                &registration.control_proof.account_subject == account_subject
                    && registration.identity_creation_lease_id == lease_id
            })
}

fn parse_prepared_request(
    canonical: &str,
) -> anyhow::Result<arkret_sdk::AccountRegisterRequestBody> {
    Ok(arkret_sdk::canonical::from_canonical_json_slice(
        canonical.as_bytes(),
    )?)
}

pub async fn persist_account_handoff_grant(
    handoff: &crate::state::PendingAccountHandoff,
    grant: &str,
) -> anyhow::Result<()> {
    let grant = grant.trim();
    if grant.is_empty() {
        anyhow::bail!("account handoff grant is empty");
    }
    let store = default_secure_key_store("inkson");
    store
        .store_secret_durable(&account_handoff_grant_secret_key(handoff)?, grant)
        .await?;
    // v1 was one browser-global slot and cannot be authenticated against an
    // account/request context locally. Never migrate or expose it to a v2
    // flow; remove it once a context-bound grant is durable.
    store.delete_secret(ACCOUNT_HANDOFF_GRANT_SECRET_KEY)?;
    Ok(())
}

pub fn load_account_handoff_grant(
    handoff: &crate::state::PendingAccountHandoff,
) -> anyhow::Result<Option<String>> {
    Ok(default_secure_key_store("inkson")
        .get_secret(&account_handoff_grant_secret_key(handoff)?)?)
}

pub fn clear_account_handoff_grant(
    handoff: &crate::state::PendingAccountHandoff,
) -> anyhow::Result<()> {
    default_secure_key_store("inkson")
        .delete_secret(&account_handoff_grant_secret_key(handoff)?)?;
    Ok(())
}

/// Persist the complete root-signed registration before its first submission.
pub async fn persist_prepared_identity_creation_request(
    request: &arkret_sdk::AccountRegisterRequestBody,
) -> anyhow::Result<()> {
    request.validate()?;
    let registration = request
        .identity_creation
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("prepared request omits identity creation"))?;
    let key = prepared_identity_creation_request_secret_key(
        &registration.control_proof.account_subject,
        request.principal_id.as_str(),
        &registration.identity_creation_lease_id,
    );
    let canonical = String::from_utf8(arkret_sdk::canonical::canonical_json_bytes(request)?)?;
    default_secure_key_store("inkson")
        .store_secret_durable(&key, &canonical)
        .await?;
    Ok(())
}

pub async fn load_prepared_identity_creation_request(
    account_subject: &arkret_sdk::Hash,
    principal_id: &str,
    lease_id: &str,
) -> anyhow::Result<Option<arkret_sdk::AccountRegisterRequestBody>> {
    let store = default_secure_key_store("inkson");
    let key =
        prepared_identity_creation_request_secret_key(account_subject, principal_id, lease_id);
    if let Some(canonical) = store.get_secret(&key)? {
        return Ok(Some(parse_prepared_request(&canonical)?));
    }

    // v1 used one browser-global slot. Migrate it only when all three scope
    // coordinates match the active flow. A record owned by another account,
    // principal or lease is invisible here and remains untouched.
    let Some(legacy_canonical) = store.get_secret(PREPARED_IDENTITY_CREATION_REQUEST_SECRET_KEY)?
    else {
        return Ok(None);
    };
    let legacy = parse_prepared_request(&legacy_canonical)?;
    if !prepared_request_matches_scope(&legacy, account_subject, principal_id, lease_id) {
        return Ok(None);
    }
    store.store_secret_durable(&key, &legacy_canonical).await?;
    store.delete_secret(PREPARED_IDENTITY_CREATION_REQUEST_SECRET_KEY)?;
    Ok(Some(legacy))
}

pub fn clear_prepared_identity_creation_request(
    account_subject: &arkret_sdk::Hash,
    principal_id: &str,
    lease_id: &str,
) -> anyhow::Result<()> {
    let store = default_secure_key_store("inkson");
    let key =
        prepared_identity_creation_request_secret_key(account_subject, principal_id, lease_id);
    store.delete_secret(&key)?;
    if let Some(legacy_canonical) =
        store.get_secret(PREPARED_IDENTITY_CREATION_REQUEST_SECRET_KEY)?
    {
        let legacy = parse_prepared_request(&legacy_canonical)?;
        if prepared_request_matches_scope(&legacy, account_subject, principal_id, lease_id) {
            store.delete_secret(PREPARED_IDENTITY_CREATION_REQUEST_SECRET_KEY)?;
        }
    }
    Ok(())
}

pub fn clear_prepared_identity_creation_request_for_checkpoint(
    checkpoint: &crate::state::PendingPrincipalRegistration,
) -> anyhow::Result<()> {
    let Some(account_subject) = checkpoint.account_subject.as_ref() else {
        // A legacy unscoped request cannot be authenticated against the
        // current server flow. It is never reusable and must not survive local
        // reconciliation merely because it lacks the coordinates needed for a
        // v2 key.
        default_secure_key_store("inkson")
            .delete_secret(PREPARED_IDENTITY_CREATION_REQUEST_SECRET_KEY)?;
        return Ok(());
    };
    clear_prepared_identity_creation_request(account_subject, &checkpoint.did, &checkpoint.lease_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_request_keys_are_isolated_by_account_principal_and_lease() {
        let account_a = arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let account_b = arkret_sdk::Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        let baseline = prepared_identity_creation_request_secret_key(
            &account_a,
            "did:webvh:alice.example",
            "lease-a",
        );

        assert_ne!(
            baseline,
            prepared_identity_creation_request_secret_key(
                &account_b,
                "did:webvh:alice.example",
                "lease-a"
            )
        );
        assert_ne!(
            baseline,
            prepared_identity_creation_request_secret_key(
                &account_a,
                "did:webvh:bob.example",
                "lease-a"
            )
        );
        assert_ne!(
            baseline,
            prepared_identity_creation_request_secret_key(
                &account_a,
                "did:webvh:alice.example",
                "lease-b"
            )
        );
    }

    fn handoff(
        account: &str,
        request_id: &str,
        holder_jkt: &str,
    ) -> crate::state::PendingAccountHandoff {
        crate::state::PendingAccountHandoff {
            principal_server_url: "https://principal.example".to_owned(),
            gate_account_base: "https://account.example/_arkret/gate/account".to_owned(),
            request_id: request_id.to_owned(),
            account_handle: "user@example".to_owned(),
            account_subject: Some(arkret_sdk::Hash::new(format!("sha256:{account}")).unwrap()),
            holder_jkt: holder_jkt.to_owned(),
            audience: "did:web:principal.example".to_owned(),
            expires_at: chrono::Utc::now(),
            lease_id: None,
            lease_fence: None,
            lease_expires_at: None,
            identity_creation_state: None,
            reserved_identity: None,
            identity_abandonment: None,
            retry_after_ms: None,
            device_id: "ak:device:01900000-0000-7000-8000-000000000000".to_owned(),
            trust_domain: "arkret:trust-domain:principal.example".to_owned(),
            bound_principal_id: None,
        }
    }

    #[test]
    fn handoff_grant_keys_are_isolated_by_account_request_and_holder() {
        let account_a = "a".repeat(64);
        let account_b = "b".repeat(64);
        let baseline =
            account_handoff_grant_secret_key(&handoff(&account_a, "req-a", "jkt-a")).unwrap();

        assert_ne!(
            baseline,
            account_handoff_grant_secret_key(&handoff(&account_b, "req-a", "jkt-a")).unwrap()
        );
        assert_ne!(
            baseline,
            account_handoff_grant_secret_key(&handoff(&account_a, "req-b", "jkt-a")).unwrap()
        );
        assert_ne!(
            baseline,
            account_handoff_grant_secret_key(&handoff(&account_a, "req-a", "jkt-b")).unwrap()
        );
    }

    #[test]
    fn pending_recovery_key_survives_reauthentication_but_isolates_identity_context() {
        let account_a = "a".repeat(64);
        let account_b = "b".repeat(64);
        let baseline_handoff = handoff(&account_a, "req-a", "jkt-a");
        let baseline = pending_identity_creation_recovery_key(&baseline_handoff).unwrap();

        let reauthenticated = handoff(&account_a, "req-b", "jkt-b");
        assert_eq!(
            baseline,
            pending_identity_creation_recovery_key(&reauthenticated).unwrap(),
            "request and holder rotation must not hide a retained key for the same flow"
        );

        assert_ne!(
            baseline,
            pending_identity_creation_recovery_key(&handoff(&account_b, "req-b", "jkt-b")).unwrap()
        );

        let mut other_audience = reauthenticated.clone();
        other_audience.audience = "did:web:other-principal.example".to_owned();
        assert_ne!(
            baseline,
            pending_identity_creation_recovery_key(&other_audience).unwrap()
        );

        let mut other_device = reauthenticated;
        other_device.device_id = "ak:device:01900000-0000-7000-8000-000000000001".to_owned();
        assert_ne!(
            baseline,
            pending_identity_creation_recovery_key(&other_device).unwrap()
        );
    }
}
