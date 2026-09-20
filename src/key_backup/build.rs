use arkret_models_crypto::{KeyBackup, SecretStorageContentIndex, SecretStorageSecret};
use arkret_wire::{Base64UrlString, HPKE_SUITE_X25519_CHACHA20POLY1305_V1};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};

use super::BackupKind;
use crate::recovery_crypto::VaultKek;

fn plaintext_item(
    item: &SecretStorageContentIndex,
    secret: &[u8],
) -> anyhow::Result<SecretStorageSecret> {
    let secret_id = item
        .secret_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("key backup content item requires secret_id"))?;
    Ok(SecretStorageSecret {
        item_kind: item.item_kind,
        secret_id,
        secret_b64u: Base64UrlString::new(B64.encode(secret)).map_err(anyhow::Error::msg)?,
        secret_generation: item.secret_version.map(u64::from),
        extra: Default::default(),
    })
}

fn public_content_item(item: &SecretStorageSecret) -> anyhow::Result<SecretStorageContentIndex> {
    Ok(SecretStorageContentIndex {
        item_kind: item.item_kind,
        secret_id: Some(item.secret_id.clone()),
        secret_version: item.secret_version()?,
    })
}

/// Spec §7.5 builder: assemble a `passphrase_kdf` backup envelope and seal
/// `plaintext` into it with the deterministic-nonce / domain-isolated-HKDF /
/// `key_commitment` / AAD-bound construction.
///
/// The metadata (backup_id, created_at, contents, domain separation) is built
/// FIRST so the SDK-derived AEAD AAD and nonce transcript can be bound before
/// encryption — the inverse of the old "encrypt then wrap"
/// strand. `root` is the Argon2id root key (its salt/params travel on the wire).
pub fn build_passphrase_kdf_backup_body(
    backup_id: &str,
    // The closed account actor the envelope belongs to. Every production
    // caller holds the account's `AccountId`; rebuilding it from a principal
    // plus the ambient Station would pass a loose identity
    // (account-lifecycle.md §156).
    actor_id: &arkret_sdk::ActorId,
    device_id: &str,
    root: &VaultKek,
    secret: &[u8],
    class: BackupKind,
    subdomain: &str,
    item: &SecretStorageContentIndex,
    auth: &arkret_crypto::backup::KeyBackupAuthBinding,
    sign: arkret_crypto::backup::KeyBackupSignFn<'_>,
    source_commit_ref: Option<arkret_sdk::KeyBackupSourceCommitRef>,
) -> anyhow::Result<KeyBackup> {
    let backup_id = arkret_sdk::BackupId::new(backup_id.to_owned())
        .map_err(|error| anyhow::anyhow!("backup_id: {error}"))?;
    let actor_id = actor_id.clone();
    let device_id_typed = arkret_sdk::DeviceId::new(device_id.to_owned()).ok();
    let envelope = arkret_crypto::backup::build_key_backup_envelope_with_extensions(
        backup_id,
        actor_id,
        device_id_typed,
        class,
        "kb_1",
        subdomain,
        Default::default(),
        root,
        vec![plaintext_item(item, secret)?],
        auth,
        sign,
        source_commit_ref,
    )
    .map_err(|error| anyhow::anyhow!("build key backup: {error}"))?;
    envelope
        .validate()
        .map_err(|error| anyhow::anyhow!("validate key backup: {error}"))?;
    Ok(envelope)
}

/// Build a `passphrase_kdf` successor after its complete series/frontier
/// identity has been resolved. The SDK seals the plaintext keybag only after
/// inheriting the predecessor series and attaching the supersedes link, so no
/// caller can mutate ciphertext-bound identity metadata afterward.
#[allow(clippy::too_many_arguments)]
pub fn build_passphrase_kdf_backup_successor_body(
    backup_id: &str,
    predecessor: &KeyBackup,
    device_id: &str,
    root: &VaultKek,
    secret: &[u8],
    item: &SecretStorageContentIndex,
    auth: &arkret_crypto::backup::KeyBackupAuthBinding,
    sign: arkret_crypto::backup::KeyBackupSignFn<'_>,
    source_commit_ref: Option<arkret_sdk::KeyBackupSourceCommitRef>,
) -> anyhow::Result<KeyBackup> {
    let envelope = arkret_crypto::backup::build_key_backup_successor_envelope(
        arkret_sdk::BackupId::new(backup_id.to_owned())?,
        predecessor,
        Some(arkret_sdk::DeviceId::new(device_id.to_owned())?),
        "kb_1",
        root,
        vec![plaintext_item(item, secret)?],
        auth,
        sign,
        source_commit_ref,
    )
    .map_err(|error| anyhow::anyhow!("build key backup successor: {error}"))?;
    envelope
        .validate()
        .map_err(|error| anyhow::anyhow!("validate key backup successor: {error}"))?;
    Ok(envelope)
}

/// Spec §7.5 reader: re-derive the AAD + nonce transcript from a stored
/// `passphrase_kdf` envelope and `open_vault` it with `passphrase`. Verifies the
/// `key_commitment` and recomputes the deterministic nonce.
pub fn open_passphrase_kdf_backup_body(
    passphrase: &[u8],
    body: &Value,
) -> anyhow::Result<arkret_sdk::KeyBackupPlaintext> {
    let envelope: arkret_models_crypto::KeyBackup = serde_json::from_value(body.clone())
        .map_err(|error| anyhow::anyhow!("parse key backup: {error}"))?;
    arkret_crypto::backup::decrypt_key_backup_envelope(passphrase, &envelope)
        .map_err(|error| anyhow::anyhow!("decrypt key backup: {error}"))
}

/// AEAD identifiers for HPKE backups. This surface pins the v1 default-MUST
/// application-layer HPKE suite `ak.hpke_x25519_aead_chacha20poly1305.v1`
/// (see [`HPKE_SUITE_X25519_CHACHA20POLY1305_V1`]), whose AEAD is RFC 9180
/// ChaCha20-Poly1305 (96-bit nonce). The `encryption.hpke_suite` selector is
/// written explicitly so `aead.name` is unambiguously consistent with the
/// selected suite per `hpke-suite-registry.json` registry rules.
pub const HPKE_AEAD_PROFILE: &str = arkret_wire::AeadProfileId::CHACHA20_POLY1305_V1;

/// `info` transcript bound into the HPKE context (key-management.md §7.5.2):
/// canonical_json of the envelope identity tuple. Both sealer and opener
/// reconstruct this byte-identically from the envelope fields.
fn recovery_public_key_info(body: &KeyBackup) -> anyhow::Result<Vec<u8>> {
    // key-management.md §7.5.2 closes this exact seven-field HPKE info object.
    // Recipient interpretation remains bound by the complete envelope AEAD AAD.
    let info = json!({
        "backup_id": body.backup_id,
        "series_id": body.series_id,
        "series_seq": body.series_seq,
        "actor_id": body.actor_id,
        "backup_kind": body.backup_kind,
        "backup_version": body.backup_version,
        "created_at": body.created_at,
    });
    crate::canonical::canonical_json_bytes(&info)
}

/// HPKE `recovery_public_key` envelope whose genesis `series_id` the caller
/// may preselect. This is required when the encrypted plaintext keybag itself
/// commits to the same series identity.
#[allow(clippy::too_many_arguments)]
pub fn build_recovery_public_key_backup_body_in_series(
    backup_id: &str,
    actor_id: &arkret_sdk::ActorId,
    device_id: &str,
    recovery_public_key: &[u8],
    recovery_key_ref: &str,
    class: BackupKind,
    subdomain: &str,
    item: &SecretStorageContentIndex,
    plaintext: &[u8],
    recovery_policy_ref: (&str, u64),
    series_id: Option<&str>,
    previous_series_tail: Option<&Value>,
    auth: &arkret_crypto::backup::KeyBackupAuthBinding,
    sign: arkret_crypto::backup::KeyBackupSignFn<'_>,
    source_commit_ref: Option<arkret_sdk::KeyBackupSourceCommitRef>,
) -> anyhow::Result<KeyBackup> {
    build_recovery_public_key_backup_body_for_items_in_series(
        backup_id,
        actor_id,
        device_id,
        recovery_public_key,
        recovery_key_ref,
        class,
        subdomain,
        vec![plaintext_item(item, plaintext)?],
        recovery_policy_ref,
        series_id,
        previous_series_tail,
        auth,
        sign,
        source_commit_ref,
    )
}

/// Multi-item HPKE envelope variant used by a controller-owned active series
/// whose tail folds every currently Agent PCR binding.
#[allow(clippy::too_many_arguments)]
pub fn build_recovery_public_key_backup_body_for_items_in_series(
    backup_id: &str,
    actor_id: &arkret_sdk::ActorId,
    device_id: &str,
    recovery_public_key: &[u8],
    recovery_key_ref: &str,
    class: BackupKind,
    subdomain: &str,
    plaintext_items: Vec<SecretStorageSecret>,
    recovery_policy_ref: (&str, u64),
    series_id: Option<&str>,
    previous_series_tail: Option<&Value>,
    auth: &arkret_crypto::backup::KeyBackupAuthBinding,
    sign: arkret_crypto::backup::KeyBackupSignFn<'_>,
    source_commit_ref: Option<arkret_sdk::KeyBackupSourceCommitRef>,
) -> anyhow::Result<KeyBackup> {
    if plaintext_items.is_empty() {
        anyhow::bail!("recovery_public_key backup requires at least one content item");
    }
    let items = plaintext_items
        .iter()
        .map(public_content_item)
        .collect::<anyhow::Result<Vec<_>>>()?;
    build_recovery_public_key_backup_body_for_items_and_index_in_series(
        backup_id,
        actor_id,
        device_id,
        recovery_public_key,
        recovery_key_ref,
        class,
        subdomain,
        plaintext_items,
        items,
        recovery_policy_ref,
        series_id,
        previous_series_tail,
        auth,
        sign,
        source_commit_ref,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_recovery_public_key_backup_body_for_items_and_index_in_series(
    backup_id: &str,
    actor_id: &arkret_sdk::ActorId,
    device_id: &str,
    recovery_public_key: &[u8],
    recovery_key_ref: &str,
    class: BackupKind,
    subdomain: &str,
    plaintext_items: Vec<SecretStorageSecret>,
    items: Vec<SecretStorageContentIndex>,
    recovery_policy_ref: (&str, u64),
    series_id: Option<&str>,
    previous_series_tail: Option<&Value>,
    auth: &arkret_crypto::backup::KeyBackupAuthBinding,
    sign: arkret_crypto::backup::KeyBackupSignFn<'_>,
    source_commit_ref: Option<arkret_sdk::KeyBackupSourceCommitRef>,
) -> anyhow::Result<KeyBackup> {
    if plaintext_items.is_empty() {
        anyhow::bail!("key backup plaintext must contain at least one item");
    }
    let device_id = arkret_sdk::DeviceId::new(device_id.to_owned()).ok();
    let created_at = crate::clock::now_utc_canonical();
    let mut body = KeyBackup {
        backup_id: arkret_sdk::BackupId::new(backup_id.to_owned())?,
        actor_id: actor_id.clone(),
        device_id: device_id.clone(),
        backup_kind: class,
        mixed_secret_storage: false,
        backup_version: "kb_1".to_owned(),
        created_at,
        updated_at: None,
        expires_at: None,
        encryption: arkret_sdk::KeyBackupEncryption {
            recipient_method: arkret_sdk::KeyBackupRecipientMethod::RecoveryPublicKey,
            recipient_key_ref: Some(recovery_key_ref.to_owned()),
            kdf: None,
            aead: arkret_sdk::KeyBackupAead {
                name: arkret_sdk::KeyBackupAeadName::Chacha20Poly1305,
                aead_profile: Some(HPKE_AEAD_PROFILE.to_owned()),
                nonce_salt: None,
                nonce: None,
                enc: None,
                extra: Default::default(),
            },
            key_commitment: None,
            hpke_suite: Some(HPKE_SUITE_X25519_CHACHA20POLY1305_V1.to_owned()),
            extra: Default::default(),
        },
        domain_separation: arkret_sdk::KeyBackupDomainSeparation {
            subdomain: subdomain.to_owned(),
            aead_aad_extensions: Default::default(),
        },
        contents: items,
        ciphertext: Base64UrlString::new("AA".to_owned()).map_err(anyhow::Error::msg)?,
        ciphertext_digest: arkret_sdk::Hash::new(format!("sha256:{}", "0".repeat(64)))?,
        plaintext_commitment: None,
        auth_data: arkret_sdk::KeyBackupAuthData {
            device_id: auth.device_id.clone(),
            verification_method: auth.verification_method.clone(),
            signature_algorithm: auth.signature_algorithm,
            signature: Base64UrlString::new("AA".to_owned()).map_err(anyhow::Error::msg)?,
            device_authorize_event_id: auth.device_authorize_event_id.clone(),
        },
        retention: None,
        series_id: arkret_sdk::BackupSeriesId::new(
            series_id
                .map(str::to_owned)
                .unwrap_or_else(|| format!("ak:backup_series:{}", crate::operation::uuid_v7())),
        )?,
        series_seq: 0,
        supersedes_id: None,
        supersedes_digest: None,
        source_commit_ref,
        recovery_policy_ref: Some(arkret_sdk::RecoveryPolicyRef {
            policy_id: arkret_sdk::PolicyId::new(recovery_policy_ref.0.to_owned())?,
            policy_version: recovery_policy_ref.1,
        }),
        extra: Default::default(),
    };
    if let Some(previous) = previous_series_tail {
        let predecessor = serde_json::from_value::<KeyBackup>(previous.clone())
            .map_err(|error| anyhow::anyhow!("typed key backup predecessor: {error}"))?;
        let supersedes_digest =
            crate::mls::account_recovery::series_supersedes_digest(&predecessor)?;
        body.series_id = predecessor.series_id;
        body.series_seq = predecessor
            .series_seq
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("key backup successor series_seq overflow"))?;
        body.supersedes_id = Some(predecessor.backup_id);
        body.supersedes_digest = Some(supersedes_digest);
    }
    let plaintext = arkret_sdk::KeyBackupPlaintext {
        backup_kind: class,
        items: plaintext_items,
    };
    let plaintext_bytes = crate::canonical::canonical_json_bytes(&plaintext)?;
    let aad = arkret_crypto::backup::key_backup_aead_aad(&body)
        .map_err(|error| anyhow::anyhow!("derive key backup AAD: {error}"))?;
    let info = recovery_public_key_info(&body)?;
    let sealed = crate::hpke_backup::hpke_seal(recovery_public_key, &info, &aad, &plaintext_bytes)?;

    body.encryption.aead.enc = Some(
        arkret_sdk::Base64UrlString::new(B64.encode(&sealed.enc)).map_err(anyhow::Error::msg)?,
    );
    body.ciphertext =
        Base64UrlString::new(B64.encode(&sealed.ciphertext)).map_err(anyhow::Error::msg)?;
    body.ciphertext_digest = arkret_sdk::Hash::new(format!(
        "sha256:{}",
        crate::canonical::sha256_digest(&sealed.ciphertext)
            .strip_prefix("sha256:")
            .unwrap_or_default()
    ))?;
    body.auth_data.signature = Base64UrlString::new(
        B64.encode(
            sign(&body.signing_payload_bytes()?)
                .map_err(|error| anyhow::anyhow!("sign key backup: {error}"))?,
        ),
    )
    .map_err(anyhow::Error::msg)?;
    body.validate()
        .map_err(|error| anyhow::anyhow!("validate built key backup: {error}"))?;
    plaintext.validate_against(&body.contents)?;
    Ok(body)
}

/// Spec §7.5.2 reader: rebuild the HPKE `info` + `aad` from a stored
/// `recovery_public_key` envelope and HPKE-open it with `recovery_private_key`.
pub fn open_recovery_public_key_backup_body(
    recovery_private_key: &[u8],
    body: &Value,
) -> anyhow::Result<arkret_sdk::KeyBackupPlaintext> {
    let body = serde_json::from_value::<KeyBackup>(body.clone())
        .map_err(|error| anyhow::anyhow!("typed recovery_public_key backup: {error}"))?;
    body.validate()?;
    let enc_b64 = body.encryption.aead.enc.as_ref().ok_or_else(|| {
        anyhow::anyhow!("recovery_public_key envelope missing encryption.aead.enc")
    })?;
    let aad = arkret_crypto::backup::key_backup_aead_aad(&body)
        .map_err(|error| anyhow::anyhow!("derive key backup AAD: {error}"))?;
    let info = recovery_public_key_info(&body)?;
    let enc = B64
        .decode(enc_b64.as_str())
        .map_err(|e| anyhow::anyhow!("enc base64url: {e}"))?;
    let ciphertext = B64
        .decode(body.ciphertext.as_str())
        .map_err(|e| anyhow::anyhow!("ciphertext base64url: {e}"))?;
    let plaintext =
        crate::hpke_backup::hpke_open(recovery_private_key, &enc, &info, &aad, &ciphertext)?;
    let plaintext = serde_json::from_slice::<arkret_sdk::KeyBackupPlaintext>(&plaintext)
        .map_err(|error| anyhow::anyhow!("decode key backup plaintext: {error}"))?;
    plaintext.validate_against(&body.contents)?;
    Ok(plaintext)
}
