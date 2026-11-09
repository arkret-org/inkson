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
        let second = seal();
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
