use arkret_models_crypto::KeyBackupContentItem;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};

use super::{
    BackupClass, attach_key_backup_domain_separation, attach_key_backup_genesis_series,
    is_protocol_device_id, sign_key_backup_with_active_device,
};
use crate::recovery_crypto::VaultKek;

/// Serialize a SDK `KeyBackupContentItem` into the on-wire `contents[]` object.
/// The content item is the spec-defined type (`ak.schema.key_backup.v1`); the
/// authoritative shape lives in `arkret_models_crypto::KeyBackupContentItem`, so
/// neither inkson nor soland redefines it. `skip_serializing_if` keeps absent
/// optionals (e.g. `secret_version` on share items) out of the canonical bytes.
fn backup_content_object(item: &KeyBackupContentItem) -> anyhow::Result<Value> {
    serde_json::to_value(item).map_err(|error| anyhow::anyhow!("key backup content item: {error}"))
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
    plaintext: &[u8],
    class: BackupClass,
    subdomain: &str,
    item: &KeyBackupContentItem,
) -> anyhow::Result<Value> {
    let backup_id = arkret_sdk::BackupId::new(backup_id.to_owned())
        .map_err(|error| anyhow::anyhow!("backup_id: {error}"))?;
    let actor_id = arkret_sdk::Did::new(actor_id.to_owned())
        .map_err(|error| anyhow::anyhow!("actor_id: {error}"))?;
    let device_id_typed = is_protocol_device_id(device_id)
        .then(|| arkret_sdk::DeviceId::new(device_id.to_owned()))
        .transpose()
        .map_err(|error| anyhow::anyhow!("device_id: {error}"))?;
    let mut envelope = arkret_crypto::backup::build_key_backup_envelope(
        backup_id,
        actor_id,
        device_id_typed,
        class,
        "kb_1",
        subdomain,
        root,
        plaintext,
        &[(item.item_type.as_str(), item.secret_id.as_deref())],
    )
    .map_err(|error| anyhow::anyhow!("build key backup: {error}"))?;
    envelope.contents = vec![item.clone()];
    let mut body = serde_json::to_value(envelope)
        .map_err(|error| anyhow::anyhow!("serialize key backup: {error}"))?;
    sign_key_backup_with_active_device(&mut body, device_id)?;
    Ok(body)
}

/// Spec §7.5 reader: re-derive the AAD + nonce transcript from a stored
/// `passphrase_kdf` envelope and `open_vault` it with `passphrase`. Verifies the
/// `key_commitment` and recomputes the deterministic nonce.
pub fn open_passphrase_kdf_backup_body(passphrase: &[u8], body: &Value) -> anyhow::Result<Vec<u8>> {
    let envelope: arkret_models_crypto::KeyBackup = serde_json::from_value(body.clone())
        .map_err(|error| anyhow::anyhow!("parse key backup: {error}"))?;
    arkret_crypto::backup::decrypt_key_backup_envelope(passphrase, &envelope)
        .map(|plaintext| plaintext.to_vec())
        .map_err(|error| anyhow::anyhow!("decrypt key backup: {error}"))
}

/// Build a `did_recovery` backup, HPKE-sealed to the actor's recovery public
/// key. Spec §5.0.1 first-backup gate forbids passphrase_kdf-only did_recovery,
/// so this uses `recovery_public_key` (a single passphrase must never control
/// DID recovery). `recovery_key_ref` names the recovery policy verification
/// method / DID `recoveryKeyAgreement`.
#[allow(clippy::too_many_arguments)]
pub fn build_did_recovery_backup_body(
    backup_id: &str,
    actor_id: &str,
    device_id: &str,
    recovery_public_key: &[u8],
    recovery_key_ref: &str,
    plaintext: &[u8],
    // did_recovery backups MUST bind the active recovery policy.
    policy_id: &str,
    policy_version: u64,
) -> anyhow::Result<Value> {
    build_recovery_public_key_backup_body(
        backup_id,
        actor_id,
        device_id,
        recovery_public_key,
        recovery_key_ref,
        BackupClass::DidRecovery,
        "recovery_policy",
        &KeyBackupContentItem {
            item_type: "recovery_key_share".to_owned(),
            secret_id: Some("inkson_did_recovery_share".to_owned()),
            ..Default::default()
        },
        plaintext,
        Some((policy_id, policy_version)),
    )
}

/// AEAD identifiers for HPKE backups. This surface pins the v1 default-MUST
/// application-layer HPKE suite `ak.hpke_x25519_aead_chacha20poly1305.v1`
/// (see [`crate::hpke_backup::HPKE_SUITE`]), whose AEAD is RFC 9180
/// ChaCha20-Poly1305 (96-bit nonce). The `encryption.hpke_suite` selector is
/// written explicitly so `aead.name` is unambiguously consistent with the
/// selected suite per `hpke-suite-registry.json` registry rules.
pub const HPKE_AEAD_NAME: &str = "chacha20_poly1305";
pub const HPKE_AEAD_PROFILE: &str = "ak.aead.chacha20_poly1305.v1";

/// `info` transcript bound into the HPKE context (key-management.md §7.5.2):
/// canonical_json of the envelope identity tuple. Both sealer and opener
/// reconstruct this byte-identically from the envelope fields.
fn recovery_public_key_info(body: &Value) -> anyhow::Result<Vec<u8>> {
    // SEC-04: anchor the HPKE `info` to the envelope's `recipient_method` and the
    // recipient key it is sealed to (`recipient_key_ref`), so the HPKE context is
    // bound to the recipient interpretation as well as the AEAD AAD. Both sealer
    // and opener reconstruct this byte-identically from the stored envelope.
    let encryption = body.get("encryption");
    let info = json!({
        "backup_id": body.get("backup_id").cloned().unwrap_or(Value::Null),
        "series_id": body.get("series_id").cloned().unwrap_or(Value::Null),
        "series_seq": body.get("series_seq").cloned().unwrap_or(Value::Null),
        "actor_id": body.get("actor_id").cloned().unwrap_or(Value::Null),
        "backup_class": body.get("backup_class").cloned().unwrap_or(Value::Null),
        "backup_version": body.get("backup_version").cloned().unwrap_or(Value::Null),
        "created_at": body.get("created_at").cloned().unwrap_or(Value::Null),
        "recipient_method": encryption
            .and_then(|encryption| encryption.get("recipient_method"))
            .cloned()
            .unwrap_or(Value::Null),
        "recipient_key_ref": encryption
            .and_then(|encryption| encryption.get("recipient_key_ref"))
            .cloned()
            .unwrap_or(Value::Null),
    });
    crate::canonical::canonical_json_bytes(&info)
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
    class: BackupClass,
    subdomain: &str,
    item: &KeyBackupContentItem,
    plaintext: &[u8],
    // Active recovery policy this backup binds (key-backup.schema.json
    // `recovery_policy_ref`). REQUIRED for `did_recovery`; an optional signed
    // hint for other classes. The server cross-checks it against the actor's
    // currently accepted recovery policy and rejects on mismatch.
    recovery_policy_ref: Option<(&str, u64)>,
) -> anyhow::Result<Value> {
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
    class: BackupClass,
    subdomain: &str,
    item: &KeyBackupContentItem,
    plaintext: &[u8],
    recovery_policy_ref: Option<(&str, u64)>,
    series_id: Option<&str>,
    previous_series_tail: Option<&Value>,
) -> anyhow::Result<Value> {
    build_recovery_public_key_backup_body_for_items_in_series(
        backup_id,
        actor_id,
        device_id,
        recovery_public_key,
        recovery_key_ref,
        class,
        subdomain,
        std::slice::from_ref(item),
        plaintext,
        recovery_policy_ref,
        series_id,
        previous_series_tail,
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
    class: BackupClass,
    subdomain: &str,
    items: &[KeyBackupContentItem],
    plaintext: &[u8],
    recovery_policy_ref: Option<(&str, u64)>,
    series_id: Option<&str>,
    previous_series_tail: Option<&Value>,
) -> anyhow::Result<Value> {
    if items.is_empty() {
        anyhow::bail!("recovery_public_key backup requires at least one content item");
    }
    let contents = items
        .iter()
        .map(backup_content_object)
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut body = json!({
        "backup_id": backup_id,
        "actor_id": actor_id,
        "backup_class": class.as_str(),
        "backup_version": "kb_1",
        "created_at": arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now()),
        "encryption": {
            "recipient_method": "recovery_public_key",
            "recipient_key_ref": recovery_key_ref,
            "hpke_suite": crate::hpke_backup::HPKE_SUITE,
            "aead": {
                "name": HPKE_AEAD_NAME,
                "aead_profile": HPKE_AEAD_PROFILE,
                "enc": "",
            }
        },
        "contents": contents,
        "ciphertext": "",
        "ciphertext_digest": "",
    });
    if is_protocol_device_id(device_id)
        && let Some(object) = body.as_object_mut()
    {
        object.insert("device_id".to_owned(), Value::String(device_id.to_owned()));
    }
    if let Some((policy_id, policy_version)) = recovery_policy_ref
        && let Some(object) = body.as_object_mut()
    {
        object.insert(
            "recovery_policy_ref".to_owned(),
            json!({ "policy_id": policy_id, "policy_version": policy_version }),
        );
    }
    attach_key_backup_genesis_series(&mut body);
    if let Some(series_id) = series_id {
        body["series_id"] = Value::String(series_id.to_owned());
    }
    if previous_series_tail.is_some() {
        crate::mls::account_recovery::apply_next_series(previous_series_tail, &mut body)?;
    }
    attach_key_backup_domain_separation(&mut body, class, subdomain);

    let aad_aad = body
        .get("domain_separation")
        .and_then(|d| d.get("aead_aad"))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("domain_separation.aead_aad missing"))?;
    let aad = crate::canonical::canonical_json_bytes(&aad_aad)?;
    let info = recovery_public_key_info(&body)?;
    let sealed = crate::hpke_backup::hpke_seal(recovery_public_key, &info, &aad, plaintext)?;

    body["encryption"]["aead"]["enc"] = Value::String(B64.encode(&sealed.enc));
    body["ciphertext"] = Value::String(B64.encode(&sealed.ciphertext));
    body["ciphertext_digest"] = Value::String(format!(
        "sha256:{}",
        crate::canonical::sha256_digest(&sealed.ciphertext)
            .strip_prefix("sha256:")
            .unwrap_or_default()
    ));
    sign_key_backup_with_active_device(&mut body, device_id)?;
    Ok(body)
}

/// Spec §7.5.2 reader: rebuild the HPKE `info` + `aad` from a stored
/// `recovery_public_key` envelope and HPKE-open it with `recovery_private_key`.
pub fn open_recovery_public_key_backup_body(
    recovery_private_key: &[u8],
    body: &Value,
) -> anyhow::Result<Vec<u8>> {
    let enc_b64 = body
        .pointer("/encryption/aead/enc")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            anyhow::anyhow!("recovery_public_key envelope missing encryption.aead.enc")
        })?;
    let ciphertext_b64 = body
        .get("ciphertext")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("backup body missing ciphertext"))?;
    let aad_aad = body
        .get("domain_separation")
        .and_then(|d| d.get("aead_aad"))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("domain_separation.aead_aad missing"))?;
    let aad = crate::canonical::canonical_json_bytes(&aad_aad)?;
    let info = recovery_public_key_info(body)?;
    let enc = B64
        .decode(enc_b64)
        .map_err(|e| anyhow::anyhow!("enc base64url: {e}"))?;
    let ciphertext = B64
        .decode(ciphertext_b64)
        .map_err(|e| anyhow::anyhow!("ciphertext base64url: {e}"))?;
    crate::hpke_backup::hpke_open(recovery_private_key, &enc, &info, &aad, &ciphertext)
}
