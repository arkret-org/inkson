//! Fresh HPKE root blocks use the existing native policy and active series.

use arkret_models_crypto::{ContentRootBackupEntry, RecoveryMethod};
use arkret_sdk::{AccountId, BackupId, MlsWelcomeRecipientEndpoint};
use garth::mls::content_roots::ContentRootVault;

pub(crate) async fn ensure_content_root_backup(
    api: &crate::transport::TransportClient,
    secure: &dyn crate::secure_key_store::SecureKeyStore,
    account: &AccountId,
    device: &arkret_sdk::DeviceId,
    root: &ContentRootBackupEntry,
) -> anyhow::Result<Vec<BackupId>> {
    let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
    let actor = arkret_sdk::ActorId::account(account.clone());
    let endpoint = MlsWelcomeRecipientEndpoint::Device {
        device_id: device.clone(),
    };
    let vault = ContentRootVault::new(secure, &actor, &endpoint);
    vault.retain_root(root).await?;
    let policy = crate::recovery_flow::fetch_active_recovery_policy(api)
        .await?
        .ok_or_else(|| anyhow::anyhow!("content root requires an accepted recovery policy"))?;
    policy.validate_shape()?;
    anyhow::ensure!(
        policy.account_id == *account,
        "content backup policy belongs to another Account"
    );
    let body = policy
        .policy
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("recovery policy omitted its key configuration"))?;
    body.validate_shape()?;
    let now = crate::clock::now_utc();
    let mut recipients = std::collections::BTreeMap::new();
    for method in &body.methods {
        let RecoveryMethod::RecoveryUnlock { keys } = method else {
            continue;
        };
        for entry in keys {
            let key = &entry.backup_hpke;
            if entry.not_before > now
                || entry.expires_at <= now
                || entry.revoked_at.is_some_and(|at| at <= now)
                || key.not_before > now
                || key.expires_at <= now
                || key.revoked_at.is_some_and(|at| at <= now)
                || !key
                    .hpke_suites
                    .contains(&arkret_sdk::RecoveryBackupHpkeSuite::X25519AeadChacha20Poly1305V1)
            {
                continue;
            }
            let bytes = arkret_sdk::decode_multibase_base58btc(&key.public_key_multibase)?;
            let (codec, prefix) = arkret_sdk::decode_multicodec_varint(&bytes)
                .ok_or_else(|| anyhow::anyhow!("backup HPKE key has no multicodec"))?;
            anyhow::ensure!(
                codec == 0xec && bytes.len() == prefix + 32,
                "backup recipient is not an X25519 public key"
            );
            let public = bytes[prefix..].to_vec();
            let (reference, ..) = super::upload::active_recovery_backup_recipient(
                &policy,
                account,
                account.principal_id.as_str(),
                &public,
            )?;
            recipients.insert(reference, public);
        }
    }
    anyhow::ensure!(
        !recipients.is_empty(),
        "accepted policy has no currently usable root backup recipient"
    );
    let mut backups = Vec::new();
    for (recipient, public) in recipients {
        fence.check()?;
        let operation = format!(
            "root:{}",
            arkret_sdk::canonical::canonical_sha256(&(
                &root.root_ref,
                &policy.policy_id,
                policy.version,
                &recipient,
            ))?
        );
        let frozen = if let Some(frozen) = vault.frozen_backup(&operation).await? {
            frozen
        } else {
            let list =
                super::restore::fetch_mls_restore_payload(api, account.principal_id.as_str())
                    .await?;
            let state = super::current_basis::state_from_payload(&list)?;
            let previous = super::upload::fetch_active_series_tail(
                api,
                &list,
                account.principal_id.as_str(),
                device.as_str(),
                arkret_sdk::BackupRotationKind::SecretStorage,
            )
            .await?
            .map(serde_json::from_value::<arkret_sdk::KeyBackup>)
            .transpose()?;
            let basis = super::current_basis::ConfirmedBackupBasis::read(
                api,
                account,
                &state.control_realm_id,
                device.as_str(),
                Some(&state),
            )
            .await?;
            let signer = crate::event_signer::active_signer()
                .ok_or_else(|| anyhow::anyhow!("root backup signer is unavailable"))?;
            let auth = api.key_backup_auth_binding(account, &signer).await?;
            basis.check_auth(&auth)?;
            let (series_id, sequence, supersedes) = if let Some(previous) = previous {
                let digest = garth::mls::backup_series::series_supersedes_digest(&previous)?;
                (
                    previous.series_id,
                    previous
                        .series_sequence
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("backup series overflow"))?,
                    Some((previous.backup_id, digest)),
                )
            } else {
                anyhow::ensure!(
                    basis.state()?.secret_storage.series_id().is_none(),
                    "root backup active series has no verified predecessor"
                );
                (
                    arkret_sdk::BackupSeriesId::new(arkret_wire::new_prefixed_uuid7(
                        "ak:backup_series:",
                    ))?,
                    0,
                    None,
                )
            };
            let draft = arkret_crypto::content_history::ContentRootBackupDraft {
                backup_id: garth::mls::backup_series::fresh_backup_id()?,
                actor_id: actor.clone(),
                created_at: now,
                expires_at: None,
                author: arkret_crypto::content_history::ContentRootBackupAuthor::Device {
                    binding: auth,
                    source: basis.source_commit_ref()?,
                },
                recipient_key_ref: recipient,
                recovery_policy_ref: arkret_models_crypto::RecoveryPolicyRef {
                    policy_id: policy.policy_id.clone(),
                    policy_version: policy.version,
                },
                domain_separation: arkret_sdk::KeyBackupDomainSeparation {
                    subdomain: "content_epoch_root".into(),
                    aead_aad_extensions: Default::default(),
                },
                series_id,
                series_sequence: sequence,
                supersedes,
                custody: None,
            };
            let sealed = draft.seal(vec![root.clone()], &public, |bytes| {
                signer
                    .sign_raw(bytes)
                    .map_err(|error| arkret_crypto::Error::Crypto(error.to_string()))
            })?;
            basis.check()?;
            vault.freeze_backup(&operation, &sealed).await?
        };
        fence.check()?;
        api.put_key_backup(frozen.backup_id.as_str(), frozen.clone())
            .await?;
        fence.check()?;
        let list = api.list_key_backups().await?;
        super::upload::ensure_initial_active_series(
            api,
            &list.active_series.control_realm_id,
            account,
            account.principal_id.as_str(),
            device.as_str(),
            arkret_sdk::BackupRotationKind::SecretStorage,
            frozen.series_id.as_str(),
        )
        .await?;
        backups.push(frozen.backup_id);
    }
    backups.sort();
    backups.dedup();
    Ok(backups)
}
