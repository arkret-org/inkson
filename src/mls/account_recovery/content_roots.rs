//! Fresh HPKE root blocks use the existing native policy and active series.

use arkret_models_crypto::{ContentRootBackupEntry, RecoveryMethod};
use arkret_sdk::{AccountId, BackupId, MlsWelcomeRecipientEndpoint};
use garth::mls::content_roots::ContentRootVault;

/// Import history keys from this holder's complete current backup series.
/// Membership, authorized original reads and fresh MLS state remain separate.
pub(crate) async fn restore_content_root_backups(
    api: &crate::transport::TransportClient,
    secure: &dyn crate::secure_key_store::SecureKeyStore,
    account: &AccountId,
    device: &arkret_sdk::DeviceId,
    material: &serde_json::Value,
    recovery_private_key: &[u8],
    policy: &arkret_sdk::RecoveryPolicySummary,
) -> anyhow::Result<usize> {
    super::restore::validate_backup_account(material, account, account.principal_id.as_str())?;
    super::restore::verify_active_backup_series(material, "secret_storage")?;
    anyhow::ensure!(
        policy.account_id == *account,
        "root recovery policy belongs to another Account"
    );
    policy.validate_shape()?;
    let policy = policy.policy.as_ref().ok_or_else(|| {
        anyhow::anyhow!("root recovery policy omitted its recipient configuration")
    })?;
    policy.validate_shape()?;
    let state = super::current_basis::state_from_payload(material)?;
    let basis = super::current_basis::ConfirmedBackupBasis::read(
        api,
        account,
        &state.control_realm_id,
        device.as_str(),
        Some(&state),
    )
    .await?;
    let http = api.sdk_http_client()?;
    let source = crate::transport::own_station_results::client_for_http(&http).await?;
    let actor = arkret_sdk::ActorId::account(account.clone());
    let endpoint = MlsWelcomeRecipientEndpoint::Device {
        device_id: device.clone(),
    };
    let vault = ContentRootVault::new(secure, &actor, &endpoint);
    let policy_ref = arkret_models_crypto::RecoveryPolicyRef {
        policy_id: policy.policy_id.clone(),
        policy_version: policy.version,
    };
    let mut required = std::collections::BTreeSet::new();
    let mut restored = std::collections::BTreeSet::new();
    for body in crate::mls::runtime::all_secret_storage_backups(material) {
        let backup: arkret_sdk::KeyBackup = serde_json::from_value(body)?;
        backup.validate()?;
        let roots = backup
            .contents
            .iter()
            .filter_map(|item| item.root_ref.clone())
            .collect::<std::collections::BTreeSet<_>>();
        if roots.is_empty() {
            continue;
        }
        required.extend(roots);
        if backup.encryption.recipient_method
            != arkret_sdk::KeyBackupRecipientMethod::RecoveryPublicKey
            || backup.recovery_policy_ref.as_ref() != Some(&policy_ref)
        {
            continue;
        }
        backup.validate_recovery_recipient(policy, backup.created_at)?;
        let key = super::current_basis::verify_envelope_source(
            &http,
            &source,
            account,
            &state.control_realm_id,
            &backup,
        )
        .await?;
        basis.check()?;
        let signature = ed25519_dalek::Signature::from_slice(&arkret_sdk::base64url_decode(
            backup.signature_proof.signature.as_str(),
        )?)?;
        let plaintext = arkret_crypto::content_history::open_content_root_backup(
            &backup,
            recovery_private_key,
            |bytes, _proof| {
                key.verify_strict(bytes, &signature)
                    .map_err(|error| arkret_crypto::Error::Protocol(error.to_string()))
            },
        )?;
        for item in plaintext.items {
            if let arkret_models_crypto::SecretStorageEntry::ContentRoot(root) = item {
                basis.check()?;
                source.check_session()?;
                vault.retain_root(&root).await?;
                basis.check()?;
                restored.insert(root.root_ref);
            }
        }
    }
    anyhow::ensure!(
        required.is_subset(&restored),
        "current recovery recipients do not cover every retained content root"
    );
    basis.check()?;
    source.check_session()?;
    Ok(restored.len())
}

fn root_backup_operation(
    root: &arkret_sdk::Hash,
    policy: &arkret_models_crypto::RecoveryPolicyRef,
    recipient: &str,
    series: Option<&arkret_sdk::BackupSeriesId>,
) -> anyhow::Result<String> {
    Ok(format!(
        "root:{}",
        arkret_sdk::canonical::canonical_sha256(&(root, policy, recipient, series))?
    ))
}

pub(crate) async fn ensure_content_root_backup(
    api: &crate::transport::TransportClient,
    secure: &dyn crate::secure_key_store::SecureKeyStore,
    account: &AccountId,
    device: &arkret_sdk::DeviceId,
    root: &ContentRootBackupEntry,
) -> anyhow::Result<Vec<BackupId>> {
    let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
    anyhow::ensure!(
        fence.belongs_to_account(account) && fence.signer.device_id() == Some(device.as_str()),
        "root publication belongs to another active Account or Device"
    );
    let actor = arkret_sdk::ActorId::account(account.clone());
    let endpoint = MlsWelcomeRecipientEndpoint::Device {
        device_id: device.clone(),
    };
    let vault = ContentRootVault::new(secure, &actor, &endpoint);
    vault.retain_root(root).await?;
    if let Some(backups) = vault.published_backup_refs(root).await? {
        fence.check()?;
        return Ok(backups);
    }
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
    let policy_ref = arkret_models_crypto::RecoveryPolicyRef {
        policy_id: policy.policy_id.clone(),
        policy_version: policy.version,
    };
    for (recipient, public) in recipients {
        fence.check()?;
        let metadata = api.list_key_backups().await?;
        let current_basis = super::current_basis::ConfirmedBackupBasis::read(
            api,
            account,
            &metadata.active_series.control_realm_id,
            device.as_str(),
            None,
        )
        .await?;
        let series = current_basis.state()?.secret_storage.series_id().cloned();
        current_basis.check()?;
        let operation =
            root_backup_operation(&root.root_ref, &policy_ref, &recipient, series.as_ref())?;
        let mut existing = vault.frozen_backup(&operation).await?;
        if existing.is_none()
            && let Some(series) = &series
        {
            let initial = root_backup_operation(&root.root_ref, &policy_ref, &recipient, None)?;
            existing = vault
                .frozen_backup(&initial)
                .await?
                .filter(|backup| &backup.series_id == series);
        }
        let frozen = if let Some(frozen) = existing {
            anyhow::ensure!(
                series
                    .as_ref()
                    .is_none_or(|series| series == &frozen.series_id),
                "frozen root backup belongs to another active series"
            );
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
            anyhow::ensure!(
                basis.state()?.secret_storage.series_id() == series.as_ref(),
                "root backup series changed while preparing its immutable package"
            );
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
                recipient_key_ref: recipient.clone(),
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
        frozen.validate()?;
        anyhow::ensure!(
            frozen.actor_id == actor
                && frozen.device_id.as_ref() == Some(device)
                && frozen.recovery_policy_ref.as_ref() == Some(&policy_ref)
                && frozen.encryption.recipient_key_ref.as_deref() == Some(recipient.as_str())
                && frozen.contents.len() == 1
                && frozen.contents[0].root_ref.as_ref() == Some(&root.root_ref)
                && frozen.contents[0].root_context.as_ref() == Some(&root.root_context),
            "frozen backup differs from its complete root publication intent"
        );
        fence.check()?;
        let accepted = api
            .put_key_backup(frozen.backup_id.as_str(), frozen.clone())
            .await?;
        anyhow::ensure!(
            accepted.backup_id == frozen.backup_id
                && accepted.ciphertext_digest == frozen.ciphertext_digest,
            "native root PUT acknowledgement differs from its exact envelope"
        );
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
        backups.push((frozen, accepted));
    }
    fence.check()?;
    vault
        .retain_backup_publication(root, &backups)
        .await
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use arkret_crypto::content_history::{
        ContentRootBackupAuthor, ContentRootBackupDraft, open_content_root_backup,
    };
    use arkret_models_crypto::{KeyBackup, KeyBackupPlaintext, SecretStorageEntry};
    use ed25519_dalek::{Signer as _, Verifier as _};

    #[test]
    fn mnemonic_opens_fresh_root_blocks_but_retained_daily_secret_cannot() {
        // Construction-only regression: the fixture does not establish Native
        // authority, an accepted recovery policy or complete PCR coverage.
        let fixture =
            arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
                .unwrap();
        let original: KeyBackup =
            serde_json::from_value(fixture["root_backup"]["envelope"].clone()).unwrap();
        let bag: KeyBackupPlaintext =
            serde_json::from_value(fixture["root_backup"]["plaintext"].clone()).unwrap();
        let roots = bag
            .items
            .iter()
            .map(|entry| match entry {
                SecretStorageEntry::ContentRoot(root) => root.clone(),
                _ => panic!("root-only fixture"),
            })
            .collect::<Vec<_>>();
        let mnemonic = fixture["hpke_grant"]["mnemonic"].as_str().unwrap();
        let (recovered_private, public) =
            crate::hpke_backup::derive_recovery_keypair_from_recovery_key(mnemonic).unwrap();
        let (wrong_private, _) = crate::hpke_backup::derive_recovery_keypair_from_recovery_key(
            &crate::recovery_crypto::format_recovery_key(&[19; 32]),
        )
        .unwrap();
        let retained_daily_secret =
            crate::recovery_crypto::derive_vault_kek(b"former-device-account-checkpoint-secret")
                .unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&[41; 32]);
        let draft = ContentRootBackupDraft {
            backup_id: original.backup_id,
            actor_id: original.actor_id,
            created_at: original.created_at,
            expires_at: original.expires_at.flatten(),
            author: ContentRootBackupAuthor::Device {
                binding: arkret_crypto::backup::KeyBackupAuthBinding {
                    device_id: original.signature_proof.device_id.unwrap(),
                    verification_method: original.signature_proof.verification_method,
                    signature_algorithm: original.signature_proof.signature_algorithm,
                    device_authorize_event_id: original
                        .signature_proof
                        .device_authorize_event_id
                        .unwrap(),
                },
                source: original.source_commit_ref.unwrap(),
            },
            recipient_key_ref: original.encryption.recipient_key_ref.unwrap(),
            recovery_policy_ref: original.recovery_policy_ref.unwrap(),
            domain_separation: original.domain_separation,
            series_id: original.series_id,
            series_sequence: original.series_sequence,
            supersedes: original.supersedes_id.zip(original.supersedes_digest),
            custody: None,
        };
        let seal = || {
            draft
                .clone()
                .seal(roots.clone(), &public, |bytes| {
                    Ok(signing.sign(bytes).to_bytes().to_vec())
                })
                .unwrap()
        };
        let first = seal();
        let mut successor = draft.clone();
        successor.backup_id = garth::mls::backup_series::fresh_backup_id().unwrap();
        successor.series_id =
            arkret_sdk::BackupSeriesId::new(arkret_wire::new_prefixed_uuid7("ak:backup_series:"))
                .unwrap();
        successor.series_sequence = 0;
        successor.supersedes = None;
        let second = successor
            .clone()
            .seal(roots.clone(), &public, |bytes| {
                Ok(signing.sign(bytes).to_bytes().to_vec())
            })
            .unwrap();
        let operation = |series| {
            super::root_backup_operation(
                &roots[0].root_ref,
                &draft.recovery_policy_ref,
                &draft.recipient_key_ref,
                series,
            )
            .unwrap()
        };
        assert_eq!(
            operation(Some(&draft.series_id)),
            operation(Some(&draft.series_id))
        );
        assert_ne!(operation(None), operation(Some(&draft.series_id)));
        assert_ne!(
            operation(Some(&draft.series_id)),
            operation(Some(&successor.series_id))
        );
        assert_ne!(first.encryption.aead.enc, second.encryption.aead.enc);
        assert_ne!(first.ciphertext, second.ciphertext);
        for backup in [first, second] {
            let verify = |bytes: &[u8], proof: &arkret_models_crypto::KeyBackupSignatureProof| {
                let signature = ed25519_dalek::Signature::from_slice(
                    &arkret_sdk::canonical::base64url_decode(proof.signature.as_str())?,
                )
                .map_err(|error| arkret_crypto::Error::Crypto(error.to_string()))?;
                signing
                    .verifying_key()
                    .verify(bytes, &signature)
                    .map_err(|error| arkret_crypto::Error::Crypto(error.to_string()))
            };
            let recovered = open_content_root_backup(&backup, &recovered_private, verify).unwrap();
            assert_eq!(
                serde_json::to_value(&recovered.items).unwrap(),
                serde_json::to_value(&bag.items).unwrap()
            );
            assert!(open_content_root_backup(&backup, &wrong_private, verify).is_err());
            assert!(open_content_root_backup(&backup, &retained_daily_secret.key, verify).is_err());
        }
    }
}
