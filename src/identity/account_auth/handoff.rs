//! Secure storage for the short-lived account-handoff credential.

use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::secure_key_store::{PendingLocalStore, default_secure_key_store};

pub(crate) const ACCOUNT_HANDOFF_GRANT_SECRET_KEY_PREFIX: &str = "account_handoff_grant.v1.";
pub(crate) const PREPARED_IDENTITY_CREATION_REQUEST_SECRET_KEY_PREFIX: &str =
    "prepared_identity_creation_request.v1.";
pub(crate) const PREPARED_RETURNING_SESSION_REQUEST_SECRET_KEY_PREFIX: &str =
    "prepared_returning_session_request.v1.";
pub(crate) const PENDING_IDENTITY_CREATION_RECOVERY_KEY_PREFIX: &str =
    "pending_identity_creation_recovery_key.v1.";

fn pending_store(
    handoff: &crate::state::PendingAccountHandoff,
) -> anyhow::Result<PendingLocalStore> {
    Ok(PendingLocalStore::new(arkret_sdk::DeviceId::new(
        handoff.device_id.clone(),
    )?))
}

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
    digest.update(handoff.audience_id.as_str().as_bytes());
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
    let secure_store = default_secure_key_store("inkson");
    pending_store(handoff)?
        .save_secret_durable(
            secure_store.as_ref(),
            &pending_identity_creation_recovery_key(handoff)?,
            recovery_key,
        )
        .await?;
    Ok(())
}

pub fn load_pending_identity_creation_recovery_key(
    handoff: &crate::state::PendingAccountHandoff,
) -> anyhow::Result<Option<Zeroizing<String>>> {
    let secure_store = default_secure_key_store("inkson");
    Ok(pending_store(handoff)?
        .load_secret(
            secure_store.as_ref(),
            &pending_identity_creation_recovery_key(handoff)?,
        )?
        .map(Zeroizing::new))
}

pub fn clear_pending_identity_creation_recovery_key(
    handoff: &crate::state::PendingAccountHandoff,
) -> anyhow::Result<()> {
    let secure_store = default_secure_key_store("inkson");
    pending_store(handoff)?.delete_secret(
        secure_store.as_ref(),
        &pending_identity_creation_recovery_key(handoff)?,
    )?;
    Ok(())
}

// These are Inkson local-storage key domains, not Arkret protocol or operation
// versions. This storage layout is v1; changing either byte string changes the
// physical key and must not be used as an implicit migration mechanism.
const PREPARED_IDENTITY_CREATION_REQUEST_KEY_DOMAIN: &[u8] =
    b"inkson.prepared-identity-creation-request-scope-v1\0";
const ACCOUNT_HANDOFF_GRANT_KEY_DOMAIN: &[u8] = b"inkson.account-handoff-grant-scope-v1\0";

fn prepared_identity_creation_request_secret_key(
    account_subject: &arkret_sdk::Hash,
    principal_id: &arkret_sdk::DidCoreId,
    lease_id: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(PREPARED_IDENTITY_CREATION_REQUEST_KEY_DOMAIN);
    digest.update(account_subject.as_str().as_bytes());
    digest.update(b"\0");
    digest.update(principal_id.as_str().as_bytes());
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
    digest.update(ACCOUNT_HANDOFF_GRANT_KEY_DOMAIN);
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

fn prepared_returning_session_request_secret_key(
    handoff: &crate::state::PendingAccountHandoff,
) -> anyhow::Result<String> {
    let account_subject = handoff
        .account_subject
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("account handoff omits account subject"))?;
    let mut digest = Sha256::new();
    digest.update(b"inkson.prepared-returning-session-request-scope-v1\0");
    digest.update(account_subject.as_str().as_bytes());
    digest.update(b"\0");
    digest.update(handoff.request_id.as_bytes());
    digest.update(b"\0");
    digest.update(handoff.holder_jkt.as_bytes());
    Ok(format!(
        "{PREPARED_RETURNING_SESSION_REQUEST_SECRET_KEY_PREFIX}{}",
        arkret_sdk::base64url_encode(digest.finalize())
    ))
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
    let secure_store = default_secure_key_store("inkson");
    pending_store(handoff)?
        .save_secret_durable(
            secure_store.as_ref(),
            &account_handoff_grant_secret_key(handoff)?,
            grant,
        )
        .await?;
    Ok(())
}

pub fn load_account_handoff_grant(
    handoff: &crate::state::PendingAccountHandoff,
) -> anyhow::Result<Option<String>> {
    let secure_store = default_secure_key_store("inkson");
    Ok(pending_store(handoff)?.load_secret(
        secure_store.as_ref(),
        &account_handoff_grant_secret_key(handoff)?,
    )?)
}

pub fn clear_account_handoff_grant(
    handoff: &crate::state::PendingAccountHandoff,
) -> anyhow::Result<()> {
    let secure_store = default_secure_key_store("inkson");
    pending_store(handoff)?.delete_secret(
        secure_store.as_ref(),
        &account_handoff_grant_secret_key(handoff)?,
    )?;
    Ok(())
}

/// Persist the fully signed returning-session request before its first send.
/// A browser reload or response-loss retry must replay these exact canonical
/// bytes rather than authoring a new request identity.
pub async fn persist_prepared_returning_session_request(
    handoff: &crate::state::PendingAccountHandoff,
    request: &arkret_sdk::SessionGrantRequestBody,
) -> anyhow::Result<()> {
    let canonical = String::from_utf8(arkret_sdk::canonical::canonical_json_bytes(request)?)?;
    let secure_store = default_secure_key_store("inkson");
    pending_store(handoff)?
        .save_secret_durable(
            secure_store.as_ref(),
            &prepared_returning_session_request_secret_key(handoff)?,
            &canonical,
        )
        .await?;
    Ok(())
}

pub fn load_prepared_returning_session_request(
    handoff: &crate::state::PendingAccountHandoff,
) -> anyhow::Result<Option<arkret_sdk::SessionGrantRequestBody>> {
    let secure_store = default_secure_key_store("inkson");
    pending_store(handoff)?
        .load_secret(
            secure_store.as_ref(),
            &prepared_returning_session_request_secret_key(handoff)?,
        )?
        .map(|canonical| {
            arkret_sdk::canonical::from_canonical_json_slice(canonical.as_bytes())
                .map_err(anyhow::Error::from)
        })
        .transpose()
}

pub fn clear_prepared_returning_session_request(
    handoff: &crate::state::PendingAccountHandoff,
) -> anyhow::Result<()> {
    let secure_store = default_secure_key_store("inkson");
    pending_store(handoff)?.delete_secret(
        secure_store.as_ref(),
        &prepared_returning_session_request_secret_key(handoff)?,
    )?;
    Ok(())
}

/// Persist the complete root-signed registration before its first submission.
pub async fn persist_prepared_identity_creation_request(
    handoff: &crate::state::PendingAccountHandoff,
    request: &arkret_sdk::AccountRegisterRequestBody,
) -> anyhow::Result<()> {
    request.validate()?;
    let registration = request
        .identity_creation
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("prepared request omits identity creation"))?;
    let key = prepared_identity_creation_request_secret_key(
        &registration.control_proof.account_subject,
        &request.principal_id,
        &registration.identity_creation_lease_id,
    );
    let canonical = String::from_utf8(arkret_sdk::canonical::canonical_json_bytes(request)?)?;
    let secure_store = default_secure_key_store("inkson");
    pending_store(handoff)?
        .save_secret_durable(secure_store.as_ref(), &key, &canonical)
        .await?;
    Ok(())
}

pub async fn load_prepared_identity_creation_request(
    handoff: &crate::state::PendingAccountHandoff,
    checkpoint: &crate::state::PendingPrincipalRegistration,
) -> anyhow::Result<Option<arkret_sdk::AccountRegisterRequestBody>> {
    let account_subject = checkpoint
        .account_subject
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("registration checkpoint omits account subject"))?;
    // AccountRegisterRequestBody carries the protocol/core DID. The checkpoint
    // carries the project/DID, so deriving the storage coordinate here is
    // essential: using did makes every persisted request look absent.
    let principal_id = arkret_sdk::project_did_to_core_id(&checkpoint.did)?;
    let secure_store = default_secure_key_store("inkson");
    let key = prepared_identity_creation_request_secret_key(
        account_subject,
        &principal_id,
        &checkpoint.lease_id,
    );
    pending_store(handoff)?
        .load_secret(secure_store.as_ref(), &key)?
        .map(|canonical| parse_prepared_request(&canonical))
        .transpose()
}

pub fn clear_prepared_identity_creation_request(
    device_id: &arkret_sdk::DeviceId,
    account_subject: &arkret_sdk::Hash,
    principal_id: &arkret_sdk::DidCoreId,
    lease_id: &str,
) -> anyhow::Result<()> {
    let secure_store = default_secure_key_store("inkson");
    let key =
        prepared_identity_creation_request_secret_key(account_subject, principal_id, lease_id);
    PendingLocalStore::new(device_id.clone()).delete_secret(secure_store.as_ref(), &key)?;
    Ok(())
}

pub fn clear_prepared_identity_creation_request_for_checkpoint(
    checkpoint: &crate::state::PendingPrincipalRegistration,
) -> anyhow::Result<()> {
    let Some(account_subject) = checkpoint.account_subject.as_ref() else {
        return Ok(());
    };
    let device_id = arkret_sdk::DeviceId::new(checkpoint.device_id.clone())?;
    let principal_id = arkret_sdk::project_did_to_core_id(&checkpoint.did)?;
    clear_prepared_identity_creation_request(
        &device_id,
        account_subject,
        &principal_id,
        &checkpoint.lease_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_request_keys_are_isolated_by_account_principal_and_lease() {
        let account_a = arkret_sdk::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let account_b = arkret_sdk::Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        let alice = arkret_sdk::project_did_to_core_id(
            &arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap(),
        )
        .unwrap();
        let bob = arkret_sdk::project_did_to_core_id(
            &arkret_sdk::Did::new("did:webvh:z6mkfixturebob:bob.example".to_owned()).unwrap(),
        )
        .unwrap();
        let baseline = prepared_identity_creation_request_secret_key(&account_a, &alice, "lease-a");
        assert_eq!(
            baseline,
            "prepared_identity_creation_request.v1.gzxa1uBq99sAqhOwl0vEZEmOxAXNZNHnpl423PlXAdE",
            "the v1 storage key is stable; changing it requires an explicit storage decision"
        );

        assert_ne!(
            baseline,
            prepared_identity_creation_request_secret_key(&account_b, &alice, "lease-a")
        );
        assert_ne!(
            baseline,
            prepared_identity_creation_request_secret_key(&account_a, &bob, "lease-a")
        );
        assert_ne!(
            baseline,
            prepared_identity_creation_request_secret_key(&account_a, &alice, "lease-b")
        );
    }

    fn handoff(
        account: &str,
        request_id: &str,
        holder_jkt: &str,
    ) -> crate::state::PendingAccountHandoff {
        crate::state::PendingAccountHandoff {
            station_url: "https://principal.example".to_owned(),
            gate_account_base_url: "https://account.example/_arkret/gate/account".to_owned(),
            request_id: request_id.to_owned(),
            oidc_state: None,
            account_handle: "user@example".to_owned(),
            account_subject: Some(arkret_sdk::Hash::new(format!("sha256:{account}")).unwrap()),
            holder_jkt: holder_jkt.to_owned(),
            audience_id: arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
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
            bound_principal_did: None,
        }
    }

    #[test]
    fn handoff_grant_keys_are_isolated_by_account_request_and_holder() {
        let account_a = "a".repeat(64);
        let account_b = "b".repeat(64);
        let baseline =
            account_handoff_grant_secret_key(&handoff(&account_a, "req-a", "jkt-a")).unwrap();
        assert_eq!(
            baseline, "account_handoff_grant.v1.VE2834qbxrl65E2xOTMToRJsJTG1m2NTn-ks5RIHdro",
            "the v1 storage key is stable; changing it requires an explicit storage decision"
        );

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
    fn returning_session_replay_requests_are_isolated_by_exact_handoff() {
        let account_a = "a".repeat(64);
        let account_b = "b".repeat(64);
        let baseline =
            prepared_returning_session_request_secret_key(&handoff(&account_a, "req-a", "jkt-a"))
                .unwrap();

        assert_ne!(
            baseline,
            prepared_returning_session_request_secret_key(&handoff(&account_b, "req-a", "jkt-a"))
                .unwrap()
        );
        assert_ne!(
            baseline,
            prepared_returning_session_request_secret_key(&handoff(&account_a, "req-b", "jkt-a"))
                .unwrap()
        );
        assert_ne!(
            baseline,
            prepared_returning_session_request_secret_key(&handoff(&account_a, "req-a", "jkt-b"))
                .unwrap()
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

        assert!(!baseline.starts_with("inkson."));

        let mut other_audience = reauthenticated.clone();
        other_audience.audience_id =
            arkret_sdk::DidCoreId::new("ak:did_core:web:other-principal.example").unwrap();
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
