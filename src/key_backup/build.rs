use arkret_models_crypto::{KeyBackup, KeyBackupContentItem};
use arkret_wire::HPKE_SUITE_X25519_CHACHA20POLY1305_V1;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};

use super::BackupKind;
use crate::recovery_crypto::VaultKek;

fn plaintext_item(
    item: &KeyBackupContentItem,
    secret: &[u8],
) -> anyhow::Result<arkret_sdk::PlaintextItem> {
    let secret_id = item
        .secret_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("key backup content item requires secret_id"))?;
    Ok(arkret_sdk::PlaintextItem {
        item_kind: item.item_kind.clone(),
        secret_id,
        secret_b64u: B64.encode(secret),
        secret_generation: item.secret_version.map(u64::from),
        realm_id: item.realm_id.clone(),
        managed_principal_binding: item.managed_principal_binding.clone(),
        mls_group_id: item.mls_group_id.clone(),
        epoch: item.epoch,
        first_event_id: item.first_event_id.clone(),
        last_event_id: item.last_event_id.clone(),
        extra: Default::default(),
    })
}

fn public_content_item(item: &arkret_sdk::PlaintextItem) -> anyhow::Result<KeyBackupContentItem> {
    Ok(KeyBackupContentItem {
        item_kind: item.item_kind.clone(),
        realm_id: item.realm_id.clone(),
        managed_principal_binding: item.managed_principal_binding.clone(),
        mls_group_id: item.mls_group_id.clone(),
        epoch: item.epoch,
        first_event_id: item.first_event_id.clone(),
        last_event_id: item.last_event_id.clone(),
        secret_id: Some(item.secret_id.clone()),
        secret_version: item.secret_version()?,
        extra: Default::default(),
    })
}

/// Spec §7.5 builder: assemble a `passphrase_kdf` backup envelope and seal
/// `plaintext` into it with the deterministic-nonce / domain-isolated-HKDF /
/// `key_commitment` / AAD-bound construction.
///
/// The metadata (backup_id, created_at, contents, domain separation) is built
/// FIRST so the AEAD AAD (`domain_separation.aead_aad`) and the nonce transcript
/// can be bound BEFORE encryption — the inverse of the old "encrypt then wrap"
/// strand. `root` is the Argon2id root key (its salt/params travel on the wire).
pub fn build_passphrase_kdf_backup_body(
    backup_id: &str,
    actor_id: &str,
    device_id: &str,
    root: &VaultKek,
    secret: &[u8],
    class: BackupKind,
    subdomain: &str,
    item: &KeyBackupContentItem,
) -> anyhow::Result<KeyBackup> {
    let backup_id = arkret_sdk::BackupId::new(backup_id.to_owned())
        .map_err(|error| anyhow::anyhow!("backup_id: {error}"))?;
    let actor_id = crate::mls_api_helpers::principal_core_id(actor_id)
        .map_err(|error| anyhow::anyhow!("actor_id: {error}"))?;
    let device_id_typed = arkret_sdk::DeviceId::new(device_id.to_owned()).ok();
    let envelope = arkret_crypto::backup::build_key_backup_envelope(
        backup_id,
        actor_id,
        device_id_typed,
        class,
        "kb_1",
        subdomain,
        root,
        vec![plaintext_item(item, secret)?],
    )
    .map_err(|error| anyhow::anyhow!("build key backup: {error}"))?;
    envelope
        .validate_envelope_fields()
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
    root: &VaultKek,
    secret: &[u8],
    item: &KeyBackupContentItem,
    frontier_digest: &arkret_sdk::Hash,
    device_generation_ref: arkret_sdk::NonEmptyString,
) -> anyhow::Result<KeyBackup> {
    let envelope = arkret_crypto::backup::build_key_backup_successor_envelope(
        arkret_sdk::BackupId::new(backup_id.to_owned())?,
        predecessor,
        "kb_1",
        root,
        vec![plaintext_item(item, secret)?],
        frontier_digest.as_str(),
        device_generation_ref,
    )
    .map_err(|error| anyhow::anyhow!("build key backup successor: {error}"))?;
    envelope
        .validate_envelope_fields()
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
pub const HPKE_AEAD_PROFILE: &str = "ak.aead.chacha20_poly1305.v1";

/// `info` transcript bound into the HPKE context (key-management.md §7.5.2):
/// canonical_json of the envelope identity tuple. Both sealer and opener
/// reconstruct this byte-identically from the envelope fields.
fn recovery_public_key_info(body: &KeyBackup) -> anyhow::Result<Vec<u8>> {
    // SEC-04: anchor the HPKE `info` to the envelope's `recipient_method` and the
    // recipient key it is sealed to (`recipient_key_ref`), so the HPKE context is
    // bound to the recipient interpretation as well as the AEAD AAD. Both sealer
    // and opener reconstruct this byte-identically from the stored envelope.
    let info = json!({
        "backup_id": body.backup_id,
        "series_id": body.series_id,
        "series_seq": body.series_seq,
        "actor_id": body.actor_id,
        "backup_kind": body.backup_kind,
        "backup_version": body.backup_version,
        "created_at": body.created_at,
        "recipient_method": body.encryption.recipient_method,
        "recipient_key_ref": body.encryption.recipient_key_ref,
    });
    crate::canonical::canonical_json_bytes(&info)
}

fn canonical_managed_principal_bindings(
    items: &[KeyBackupContentItem],
) -> anyhow::Result<Vec<arkret_sdk::ManagedPrincipalBinding>> {
    items
        .iter()
        .filter_map(|item| item.managed_principal_binding.clone())
        .map(|binding| {
            crate::canonical::canonical_json_bytes(&binding).map(|bytes| (bytes, binding))
        })
        .collect::<anyhow::Result<std::collections::BTreeMap<_, _>>>()
        .map(|bindings| bindings.into_values().collect())
}

/// Spec §7.5.2 builder: assemble a `recovery_public_key` backup envelope and
/// HPKE-seal `plaintext` to `recovery_public_key`. ANY device (holding only the
/// public key) can build this; only the recovery private key opens it — the
/// fresh-device restore path. `recovery_key_ref` names the recovery policy
/// verification method / DID `recoveryKeyAgreement` the public key belongs to.
#[allow(clippy::too_many_arguments)]
pub fn build_recovery_public_key_backup_body(
    backup_id: &str,
    actor_id: &str,
    device_id: &str,
    recovery_public_key: &[u8],
    recovery_key_ref: &str,
    class: BackupKind,
    subdomain: &str,
    item: &KeyBackupContentItem,
    plaintext: &[u8],
    // Active recovery policy this recovery-public-key envelope binds. The
    // server cross-checks it against the actor's accepted policy.
    recovery_policy_ref: Option<(&str, u64)>,
) -> anyhow::Result<KeyBackup> {
    build_recovery_public_key_backup_body_in_series(
        backup_id,
        actor_id,
        device_id,
        recovery_public_key,
        recovery_key_ref,
        class,
        subdomain,
        item,
        plaintext,
        recovery_policy_ref,
        None,
        None,
        None,
    )
}

/// Variant of [`build_recovery_public_key_backup_body`] that lets a caller
/// preselect the genesis `series_id`. This is required when the encrypted
/// plaintext keybag itself commits to the same series identity.
#[allow(clippy::too_many_arguments)]
pub fn build_recovery_public_key_backup_body_in_series(
    backup_id: &str,
    actor_id: &str,
    device_id: &str,
    recovery_public_key: &[u8],
    recovery_key_ref: &str,
    class: BackupKind,
    subdomain: &str,
    item: &KeyBackupContentItem,
    plaintext: &[u8],
    recovery_policy_ref: Option<(&str, u64)>,
    series_id: Option<&str>,
    previous_series_tail: Option<&Value>,
    frontier_ref: Option<arkret_sdk::KeyBackupFrontierRef>,
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
        frontier_ref,
    )
}

/// Multi-item HPKE envelope variant used by a controller-owned active series
/// whose tail folds every currently managed Agent PCR binding.
#[allow(clippy::too_many_arguments)]
pub fn build_recovery_public_key_backup_body_for_items_in_series(
    backup_id: &str,
    actor_id: &str,
    device_id: &str,
    recovery_public_key: &[u8],
    recovery_key_ref: &str,
    class: BackupKind,
    subdomain: &str,
    plaintext_items: Vec<arkret_sdk::PlaintextItem>,
    recovery_policy_ref: Option<(&str, u64)>,
    series_id: Option<&str>,
    previous_series_tail: Option<&Value>,
    frontier_ref: Option<arkret_sdk::KeyBackupFrontierRef>,
) -> anyhow::Result<KeyBackup> {
    if plaintext_items.is_empty() {
        anyhow::bail!("recovery_public_key backup requires at least one content item");
    }
    let items = plaintext_items
        .iter()
        .map(public_content_item)
        .collect::<anyhow::Result<Vec<_>>>()?;
    let actor_id = crate::mls_api_helpers::principal_core_id(actor_id)?;
    let device_id = arkret_sdk::DeviceId::new(device_id.to_owned()).ok();
    let created_at = crate::clock::now_utc_canonical();
    let mut body = KeyBackup {
        backup_id: arkret_sdk::BackupId::new(backup_id.to_owned())?,
        actor_id: actor_id.clone(),
        device_id: device_id.clone(),
        backup_kind: class,
        mixed_secret_storage: false,
        backup_version: "kb_1".to_owned(),
        created_at: created_at.clone(),
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
            hkdf_info: class.hkdf_info(subdomain),
            subdomain: subdomain.to_owned(),
            aead_aad: arkret_sdk::KeyBackupDomainSeparationAad {
                schema: arkret_sdk::SchemaId::KEY_BACKUP_V1.to_owned(),
                actor_id,
                device_id: device_id.as_ref().map(ToString::to_string),
                backup_kind: class,
                backup_version: "kb_1".to_owned(),
                created_at,
                item_kinds: items.iter().map(|item| item.item_kind.clone()).collect(),
                managed_principal_bindings: canonical_managed_principal_bindings(&items)?,
                recipient_method: Some(arkret_sdk::KeyBackupRecipientMethod::RecoveryPublicKey),
                recipient_key_ref: Some(recovery_key_ref.to_owned()),
                extra: Default::default(),
            },
            extra: Default::default(),
        },
        contents: items,
        ciphertext: String::new(),
        ciphertext_digest: String::new(),
        plaintext_commitment: None,
        auth_data: None,
        retention: None,
        series_id: arkret_sdk::BackupSeriesId::new(
            series_id
                .map(str::to_owned)
                .unwrap_or_else(|| format!("ak:backup_series:{}", crate::operation::uuid_v7())),
        )?,
        series_seq: 0,
        supersedes: None,
        supersedes_digest: None,
        frontier_ref,
        recovery_policy_ref: recovery_policy_ref
            .map(|(policy_id, policy_version)| {
                arkret_sdk::PolicyId::new(policy_id.to_owned()).map(|policy_id| {
                    arkret_sdk::RecoveryPolicyRef {
                        policy_id,
                        policy_version,
                    }
                })
            })
            .transpose()?,
        extra: Default::default(),
    };
    if let Some(previous) = previous_series_tail {
        if body.frontier_ref.is_none() {
            anyhow::bail!("key backup successor requires frontier_ref before encryption");
        }
        let predecessor = serde_json::from_value::<KeyBackup>(previous.clone())
            .map_err(|error| anyhow::anyhow!("typed key backup predecessor: {error}"))?;
        body.series_id = predecessor.series_id;
        body.series_seq = predecessor
            .series_seq
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("key backup successor series_seq overflow"))?;
        body.supersedes = Some(predecessor.backup_id);
        body.supersedes_digest = Some(crate::mls::account_recovery::series_supersedes_digest(
            previous,
        )?);
    }
    let plaintext = arkret_sdk::KeyBackupPlaintext {
        schema: arkret_sdk::KeyBackupPlaintext::SCHEMA.to_owned(),
        backup_id: body.backup_id.clone(),
        backup_kind: body.backup_kind,
        series_id: body.series_id.clone(),
        series_seq: body.series_seq,
        items: plaintext_items,
        extra: Default::default(),
    };
    let plaintext_bytes = crate::canonical::canonical_json_bytes(&plaintext)?;
    let aad = crate::canonical::canonical_json_bytes(&body.domain_separation.aead_aad)?;
    let info = recovery_public_key_info(&body)?;
    let sealed = crate::hpke_backup::hpke_seal(recovery_public_key, &info, &aad, &plaintext_bytes)?;

    body.encryption.aead.enc = Some(
        arkret_sdk::Base64UrlString::new(B64.encode(&sealed.enc)).map_err(anyhow::Error::msg)?,
    );
    body.ciphertext = B64.encode(&sealed.ciphertext);
    body.ciphertext_digest = format!(
        "sha256:{}",
        crate::canonical::sha256_digest(&sealed.ciphertext)
            .strip_prefix("sha256:")
            .unwrap_or_default()
    );
    body.validate_envelope_fields()
        .map_err(|error| anyhow::anyhow!("validate built key backup: {error}"))?;
    plaintext.validate_for_envelope(&body)?;
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
    body.validate_envelope_fields()?;
    let enc_b64 = body.encryption.aead.enc.as_ref().ok_or_else(|| {
        anyhow::anyhow!("recovery_public_key envelope missing encryption.aead.enc")
    })?;
    let aad = crate::canonical::canonical_json_bytes(&body.domain_separation.aead_aad)?;
    let info = recovery_public_key_info(&body)?;
    let enc = B64
        .decode(enc_b64.as_str())
        .map_err(|e| anyhow::anyhow!("enc base64url: {e}"))?;
    let ciphertext = B64
        .decode(&body.ciphertext)
        .map_err(|e| anyhow::anyhow!("ciphertext base64url: {e}"))?;
    let plaintext =
        crate::hpke_backup::hpke_open(recovery_private_key, &enc, &info, &aad, &ciphertext)?;
    let plaintext = serde_json::from_slice::<arkret_sdk::KeyBackupPlaintext>(&plaintext)
        .map_err(|error| anyhow::anyhow!("decode key backup plaintext: {error}"))?;
    plaintext.validate_for_envelope(&body)?;
    Ok(plaintext)
}
