use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use chrono::SecondsFormat;
use cokret_sdk::models::KeyBackupContentItem;
use serde_json::{Value, json};

use super::{
    KeyBackupClass, attach_key_backup_domain_separation, attach_key_backup_genesis_series,
    is_protocol_device_id, sign_key_backup_with_active_device,
};
use crate::recovery_crypto::{
    VAULT_AEAD_NAME, VAULT_AEAD_PROFILE, VaultKek, VaultSealContext, open_vault, seal_vault,
};

/// Serialize a SDK `KeyBackupContentItem` into the on-wire `contents[]` object.
/// The content item is the spec-defined type (`ck.schema.key_backup.v1`); the
/// authoritative shape lives in `cokret_sdk::models::KeyBackupContentItem`, so
/// neither yougen nor soland redefines it. `skip_serializing_if` keeps absent
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
    class: KeyBackupClass,
    subdomain: &str,
    item: &KeyBackupContentItem,
) -> anyhow::Result<Value> {
    let content = backup_content_object(item)?;
    let mut body = json!({
        "backup_id": backup_id,
        "actor_id": actor_id,
        "backup_class": class.as_str(),
        "backup_version": "kb_1",
        "created_at": chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "encryption": {
            "recipient_method": "passphrase_kdf",
            "recipient_key_ref": device_id,
            "kdf": {
                "name": "argon2id",
                "salt": "",
                "params": {
                    "memory_kib": root.m_kib,
                    "iterations": root.t,
                    "parallelism": root.p
                }
            },
            "aead": {
                "name": VAULT_AEAD_NAME,
                "aead_profile": VAULT_AEAD_PROFILE,
                "nonce": "",
                "nonce_salt": "",
            }
        },
        "contents": [content],
        "ciphertext": "",
        "ciphertext_digest": "",
    });
    if is_protocol_device_id(device_id)
        && let Some(object) = body.as_object_mut()
    {
        object.insert("device_id".to_owned(), Value::String(device_id.to_owned()));
    }
    attach_key_backup_genesis_series(&mut body);
    attach_key_backup_domain_separation(&mut body, class, subdomain);

    // AEAD AAD = canonical bytes of the envelope's `domain_separation.aead_aad`
    // (single source of truth, so encrypt and decrypt bind identical bytes).
    let aad_aad = body
        .get("domain_separation")
        .and_then(|d| d.get("aead_aad"))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("domain_separation.aead_aad missing"))?;
    let aad_canonical = crate::canonical::canonical_json_bytes(&aad_aad)?;
    let created_at = body
        .get("created_at")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let backup_version = body
        .get("backup_version")
        .and_then(Value::as_str)
        .unwrap_or("kb_1")
        .to_owned();

    let ctx = VaultSealContext {
        backup_id,
        actor_id,
        device_id,
        backup_class: class.as_str(),
        subdomain,
        backup_version: &backup_version,
        created_at: &created_at,
        aad_canonical: &aad_canonical,
    };
    let sealed = seal_vault(root, &ctx, plaintext)?;

    body["encryption"]["kdf"]["salt"] = Value::String(sealed.salt_b64);
    body["encryption"]["aead"]["nonce"] = Value::String(sealed.nonce_b64);
    body["encryption"]["aead"]["nonce_salt"] = Value::String(sealed.nonce_salt_b64);
    body["encryption"]["key_commitment"] = Value::String(sealed.key_commitment);
    body["ciphertext"] = Value::String(sealed.ciphertext_b64);
    body["ciphertext_digest"] = Value::String(sealed.ciphertext_digest);
    // Phase 2: sign the completed envelope with the active device signer. Errors
    // propagate (a present signer that fails MUST NOT ship an unsigned backup);
    // unsigned is only allowed when NO signer is installed (Ok(false), e.g. tests).
    sign_key_backup_with_active_device(&mut body, device_id)?;
    Ok(body)
}

/// Spec §7.5 reader: re-derive the AAD + nonce transcript from a stored
/// `passphrase_kdf` envelope and `open_vault` it with `passphrase`. Verifies the
/// `key_commitment` and recomputes the deterministic nonce.
pub fn open_passphrase_kdf_backup_body(passphrase: &[u8], body: &Value) -> anyhow::Result<Vec<u8>> {
    let str_at = |path: &[&str]| -> anyhow::Result<String> {
        let mut cur = body;
        for key in path {
            cur = cur
                .get(*key)
                .ok_or_else(|| anyhow::anyhow!("backup body missing {}", path.join(".")))?;
        }
        cur.as_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| anyhow::anyhow!("backup body field {} is not a string", path.join(".")))
    };
    let backup_id = str_at(&["backup_id"])?;
    let actor_id = str_at(&["actor_id"])?;
    let backup_class = str_at(&["backup_class"])?;
    let backup_version = str_at(&["backup_version"])?;
    let created_at = str_at(&["created_at"])?;
    let subdomain = str_at(&["domain_separation", "subdomain"])?;
    let device_id = body
        .get("device_id")
        .and_then(Value::as_str)
        .or_else(|| {
            body.get("encryption")
                .and_then(|e| e.get("recipient_key_ref"))
                .and_then(Value::as_str)
        })
        .unwrap_or_default()
        .to_owned();
    let salt_b64 = str_at(&["encryption", "kdf", "salt"])?;
    let nonce_b64 = str_at(&["encryption", "aead", "nonce"])?;
    let nonce_salt_b64 = str_at(&["encryption", "aead", "nonce_salt"])?;
    let key_commitment = str_at(&["encryption", "key_commitment"])?;
    let ciphertext_b64 = str_at(&["ciphertext"])?;
    // key-management.md §7.2: `ciphertext_digest` covers the ciphertext bytes
    // and is a local integrity check. When present, recompute SHA-256 over the
    // decoded ciphertext and refuse to decrypt on mismatch — this catches a
    // tampered / substituted ciphertext before any KDF/AEAD work, without
    // contacting the server (no decryption oracle).
    if let Some(expected_digest) = body
        .get("ciphertext_digest")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let ciphertext_bytes = B64
            .decode(ciphertext_b64.trim_end_matches('='))
            .map_err(|err| anyhow::anyhow!("ciphertext base64: {err}"))?;
        let actual_digest = crate::canonical::sha256_digest(&ciphertext_bytes);
        if actual_digest != expected_digest {
            anyhow::bail!(
                "backup decrypt refused: ciphertext_digest mismatch (tampered ciphertext)"
            );
        }
    }
    let aad_aad = body
        .get("domain_separation")
        .and_then(|d| d.get("aead_aad"))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("domain_separation.aead_aad missing"))?;
    let aad_canonical = crate::canonical::canonical_json_bytes(&aad_aad)?;

    let ctx = VaultSealContext {
        backup_id: &backup_id,
        actor_id: &actor_id,
        device_id: &device_id,
        backup_class: &backup_class,
        subdomain: &subdomain,
        backup_version: &backup_version,
        created_at: &created_at,
        aad_canonical: &aad_canonical,
    };
    open_vault(
        passphrase,
        &ctx,
        &salt_b64,
        &nonce_b64,
        &nonce_salt_b64,
        &key_commitment,
        &ciphertext_b64,
    )
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
        KeyBackupClass::DidRecovery,
        "recovery_policy",
        &KeyBackupContentItem {
            item_type: "recovery_key_share".to_owned(),
            secret_id: Some("yougen_did_recovery_share".to_owned()),
            ..Default::default()
        },
        plaintext,
        Some((policy_id, policy_version)),
    )
}

/// AEAD identifiers for HPKE backups. This surface pins the v1 default-MUST
/// application-layer HPKE suite `ck.hpke_x25519_aead_xchacha20poly1305.v1`
/// (see [`crate::hpke_backup::HPKE_SUITE`]), whose AEAD is XChaCha20-Poly1305
/// (extended 192-bit nonce). The `encryption.hpke_suite` selector is written
/// explicitly so `aead.name` is unambiguously consistent with the selected
/// suite per `hpke-suite-registry.json` registry rules.
pub const HPKE_AEAD_NAME: &str = "xchacha20_poly1305";
pub const HPKE_AEAD_PROFILE: &str = "ck.aead.xchacha20_poly1305.v1";

/// `info` transcript bound into the HPKE context (key-management.md §7.5.2):
/// canonical_json of the envelope identity tuple. Both sealer and opener
/// reconstruct this byte-identically from the envelope fields.
fn recovery_public_key_info(body: &Value) -> anyhow::Result<Vec<u8>> {
    let info = json!({
        "backup_id": body.get("backup_id").cloned().unwrap_or(Value::Null),
        "series_id": body.get("series_id").cloned().unwrap_or(Value::Null),
        "series_seq": body.get("series_seq").cloned().unwrap_or(Value::Null),
        "actor_id": body.get("actor_id").cloned().unwrap_or(Value::Null),
        "backup_class": body.get("backup_class").cloned().unwrap_or(Value::Null),
        "backup_version": body.get("backup_version").cloned().unwrap_or(Value::Null),
        "created_at": body.get("created_at").cloned().unwrap_or(Value::Null),
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
    class: KeyBackupClass,
    subdomain: &str,
    item: &KeyBackupContentItem,
    plaintext: &[u8],
    // Active recovery policy this backup binds (key-backup.schema.json
    // `recovery_policy_ref`). REQUIRED for `did_recovery`; an optional signed
    // hint for other classes. The server cross-checks it against the actor's
    // currently accepted recovery policy and rejects on mismatch.
    recovery_policy_ref: Option<(&str, u64)>,
) -> anyhow::Result<Value> {
    let content = backup_content_object(item)?;
    let mut body = json!({
        "backup_id": backup_id,
        "actor_id": actor_id,
        "backup_class": class.as_str(),
        "backup_version": "kb_1",
        "created_at": chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
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
        "contents": [content],
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
