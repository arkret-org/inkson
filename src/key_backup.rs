use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use chrono::SecondsFormat;
use cokret_sdk::models::KeyBackupContentItem;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{Value, json};

use crate::recovery_crypto::{
    VAULT_AEAD_NAME, VAULT_AEAD_PROFILE, VaultKek, VaultSealContext, open_vault, seal_vault,
};

const KEY_BACKUP_SCHEMA: &str = "ck.schema.key_backup.v1";
const KEY_BACKUP_RAW_SIGNATURE_ALGORITHM: &str = "Ed25519";
pub const KEY_BACKUP_UNLOCK_PROOF_HEADER: &str = "x-cokret-key-backup-unlock-proof";
pub const KEY_BACKUP_UNLOCK_PROOF_SCHEMA: &str = "ck.schema.key_backup_unlock_proof.v1";
pub const KEY_BACKUP_PLAINTEXT_SCHEMA: &str = "ck.schema.key_backup_plaintext.v1";
pub const KEY_BACKUP_ACTIVE_SERIES_SCHEMA: &str = "ck.schema.key_backup_active_series.v1";
pub const DEFAULT_SSK_GENERATION: u64 = 1;

/// Envelope fields the backup `auth_data.signature` MUST cover (key-management.md
/// §7.4.1 / §7.6 + the `ck.schema.key_backup.v1` `signed_fields.allOf`). Optional
/// fields (`supersedes`, `supersedes_digest`, `frontier_ref`) are only listed
/// when present on the envelope.
pub const KEY_BACKUP_SIGNED_FIELDS: &[&str] = &[
    "backup_id",
    "actor_id",
    "backup_class",
    "backup_version",
    "series_id",
    "series_seq",
    "supersedes",
    "supersedes_digest",
    "encryption",
    "domain_separation",
    "contents",
    "ciphertext_digest",
    "frontier_ref",
    // did_recovery backups MUST carry + sign this (key-backup.schema.json);
    // other classes MAY carry it as a hint. Listed here so the signer covers it
    // whenever present (the filter drops it when absent).
    "recovery_policy_ref",
];

/// The mandatory subset of [`KEY_BACKUP_SIGNED_FIELDS`] that MUST always be
/// covered (genesis envelopes omit `supersedes*`/`frontier_ref`).
const KEY_BACKUP_SIGNED_FIELDS_MANDATORY: &[&str] = &[
    "backup_id",
    "actor_id",
    "backup_class",
    "backup_version",
    "series_id",
    "series_seq",
    "encryption",
    "domain_separation",
    "contents",
    "ciphertext_digest",
];

/// Phase 2 (key-management.md §7.4.1, CKP-0013): sign a key-backup envelope with
/// the device Ed25519 key. The signature covers
/// `canonical_json(envelope without auth_data.signature)` — i.e. the rest of
/// `auth_data` (verification_method / signed_fields / ssk_generation) is bound
/// too, so it cannot be tampered. `ssk_generation`, when given, seals the
/// envelope to the published cross-signing self-signing key generation.
pub fn sign_key_backup_auth_data(
    body: &mut Value,
    signing_key: &SigningKey,
    device_id: &str,
    verification_method: &str,
    ssk_generation: Option<u64>,
) -> anyhow::Result<()> {
    if let Some(object) = body.as_object_mut() {
        object.remove("auth_data");
    }
    let signed_fields: Vec<Value> = KEY_BACKUP_SIGNED_FIELDS
        .iter()
        .filter(|field| body.get(**field).is_some())
        .map(|field| Value::String((*field).to_owned()))
        .collect();
    let mut auth = json!({
        "device_id": device_id,
        "verification_method": verification_method,
        "signature_algorithm": KEY_BACKUP_RAW_SIGNATURE_ALGORITHM,
        "signed_fields": signed_fields,
    });
    if let Some(generation) = ssk_generation {
        auth["ssk_generation"] = Value::Number(serde_json::Number::from(generation));
    }
    body["auth_data"] = auth;
    // Sign over the envelope WITH auth_data present but WITHOUT the signature.
    let payload = crate::canonical::canonical_json_bytes(body)?;
    let signature = signing_key.sign(&payload);
    body["auth_data"]["signature"] = Value::String(B64.encode(signature.to_bytes()));
    Ok(())
}

/// Sign `body`'s `auth_data` with the active device signer. This requires a
/// signer that can produce raw Ed25519 signatures over canonical JSON bytes.
///
/// Returns `Ok(true)` when signed, `Ok(false)` when NO signer is installed (the
/// legitimate unsigned case — e.g. tests, or pre-bootstrap), and `Err` when a
/// signer IS present but signing failed. Crucially this no longer silently
/// downgrades a present-but-unsuitable signer to unsigned: a present signer
/// always signs or errors, so callers never ship an unsigned backup by accident.
pub fn sign_key_backup_with_active_device(
    body: &mut Value,
    device_id: &str,
) -> anyhow::Result<bool> {
    let Some(signer) = crate::event_signer::active_signer() else {
        return Ok(false);
    };
    // Build auth_data WITHOUT the signature, then sign canonical(body) over it.
    if let Some(object) = body.as_object_mut() {
        object.remove("auth_data");
    }
    let signed_fields: Vec<Value> = KEY_BACKUP_SIGNED_FIELDS
        .iter()
        .filter(|field| body.get(**field).is_some())
        .map(|field| Value::String((*field).to_owned()))
        .collect();
    body["auth_data"] = json!({
        "device_id": device_id,
        "verification_method": signer.verification_method(),
        "signature_algorithm": KEY_BACKUP_RAW_SIGNATURE_ALGORITHM,
        "ssk_generation": DEFAULT_SSK_GENERATION,
        "signed_fields": signed_fields,
    });
    let payload = crate::canonical::canonical_json_bytes(body)?;
    let signature = signer
        .sign_raw(&payload)
        .map_err(|err| anyhow::anyhow!("key backup auth_data sign: {err:?}"))?;
    body["auth_data"]["signature"] = Value::String(B64.encode(signature));
    Ok(true)
}

/// Phase 2 verify: check a key-backup envelope's `auth_data.signature` against
/// `verifying_key`, recomputing `canonical_json(envelope without
/// auth_data.signature)`, and confirm `signed_fields` covers the mandatory set.
/// Returns `Err` (caller maps to `untrusted_backup_signature`) on any mismatch.
pub fn verify_key_backup_auth_data(
    body: &Value,
    verifying_key: &VerifyingKey,
) -> Result<(), String> {
    let auth = body
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(|| "auth_data is required".to_owned())?;
    if auth.get("signature_algorithm").and_then(Value::as_str)
        != Some(KEY_BACKUP_RAW_SIGNATURE_ALGORITHM)
    {
        return Err("auth_data.signature_algorithm must be Ed25519".to_owned());
    }
    if !auth
        .get("ssk_generation")
        .and_then(Value::as_u64)
        .is_some_and(|generation| generation >= 1)
    {
        return Err("auth_data.ssk_generation must be >= 1".to_owned());
    }
    let sig_b64 = auth
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| "auth_data.signature is required".to_owned())?;
    let sig_bytes: [u8; 64] = B64
        .decode(sig_b64)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "auth_data.signature must be 64-byte base64url".to_owned())?;
    let signature = Signature::from_bytes(&sig_bytes);

    let signed_fields: Vec<&str> = auth
        .get("signed_fields")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    for field in KEY_BACKUP_SIGNED_FIELDS_MANDATORY {
        if !signed_fields.contains(field) {
            return Err(format!("auth_data.signed_fields must cover `{field}`"));
        }
    }

    let mut unsigned = body.clone();
    if let Some(object) = unsigned.get_mut("auth_data").and_then(Value::as_object_mut) {
        object.remove("signature");
    }
    let payload =
        crate::canonical::canonical_json_bytes(&unsigned).map_err(|err| err.to_string())?;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| "untrusted_backup_signature: signature does not verify".to_owned())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyBackupClass {
    DidRecovery,
    SecretStorage,
    MlsHistory,
}

impl KeyBackupClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DidRecovery => "did_recovery",
            Self::SecretStorage => "secret_storage",
            Self::MlsHistory => "mls_history",
        }
    }
}

impl TryFrom<&str> for KeyBackupClass {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "did_recovery" => Ok(Self::DidRecovery),
            "secret_storage" => Ok(Self::SecretStorage),
            "mls_history" => Ok(Self::MlsHistory),
            other => Err(format!("unsupported backup_class {other}")),
        }
    }
}

pub fn key_backup_hkdf_info(class: KeyBackupClass, subdomain: &str) -> String {
    format!("cokret-key-backup/{}/{subdomain}/v1", class.as_str())
}

pub fn key_backup_delete_ownership_proof(actor_id: &str, backup_id: &str) -> String {
    format!("dev-ssk-delete:v1:{actor_id}:{backup_id}")
}

pub fn build_key_backup_unlock_proof_active(
    backup: &Value,
    principal_id: &str,
    requesting_device_id: &str,
    recovery_session: Option<&Value>,
) -> anyhow::Result<Value> {
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active signer is required for key backup unlock proof"))?;
    let backup_id = required_str_anyhow(backup, "backup_id")?;
    let backup_class = required_str_anyhow(backup, "backup_class")?;
    let series_id = required_str_anyhow(backup, "series_id")?;
    let ciphertext_digest = required_str_anyhow(backup, "ciphertext_digest")?;
    let issued_at = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let (recovery_session_id, proof_kind, proof_digest) = if let Some(session) = recovery_session {
        let session_id = required_str_anyhow(session, "recovery_session_id")?.to_owned();
        let summary = session
            .get("proof_summary")
            .ok_or_else(|| anyhow::anyhow!("verified recovery session missing proof_summary"))?;
        let kind = required_str_anyhow(summary, "kind")?.to_owned();
        let digest = required_str_anyhow(summary, "proof_digest")?.to_owned();
        (session_id, kind, digest)
    } else {
        let session_id = format!("ck:recovery_session:{}", crate::operation::uuid_v7());
        let local_digest = crate::canonical::canonical_sha256(&json!({
            "type": "ck.key_backup.local_unlock_proof.v1",
            "principal_id": principal_id,
            "requesting_device_id": requesting_device_id,
            "backup_id": backup_id,
            "backup_class": backup_class,
            "series_id": series_id,
            "ciphertext_digest": ciphertext_digest,
            "issued_at": issued_at,
        }))?;
        (session_id, "recovery_unlock".to_owned(), local_digest)
    };
    let signed_fields = vec![
        "schema",
        "recovery_session_id",
        "principal_id",
        "requesting_device_id",
        "backup_id",
        "backup_class",
        "series_id",
        "ciphertext_digest",
        "proof_kind",
        "proof_digest",
        "issued_at",
    ];
    let mut proof = json!({
        "schema": KEY_BACKUP_UNLOCK_PROOF_SCHEMA,
        "recovery_session_id": recovery_session_id,
        "principal_id": principal_id,
        "requesting_device_id": requesting_device_id,
        "backup_id": backup_id,
        "backup_class": backup_class,
        "series_id": series_id,
        "ciphertext_digest": ciphertext_digest,
        "proof_kind": proof_kind,
        "proof_digest": proof_digest,
        "issued_at": issued_at,
        "auth_data": {
            "device_id": requesting_device_id,
            "verification_method": signer.verification_method(),
            "signature_algorithm": KEY_BACKUP_RAW_SIGNATURE_ALGORITHM,
            "signed_fields": signed_fields,
        }
    });
    let payload = crate::canonical::canonical_json_bytes(&proof)?;
    let signature = signer
        .sign_raw(&payload)
        .map_err(|err| anyhow::anyhow!("key backup unlock proof sign: {err:?}"))?;
    proof["auth_data"]["signature"] = Value::String(B64.encode(signature));
    Ok(proof)
}

pub async fn fetch_key_backup_with_active_unlock_proof(
    api: &crate::api::CokretApi,
    backup_metadata: &Value,
    principal_id: &str,
    requesting_device_id: &str,
) -> anyhow::Result<Value> {
    let backup_id = required_str_anyhow(backup_metadata, "backup_id")?.to_owned();
    let proof = build_key_backup_unlock_proof_active(
        backup_metadata,
        principal_id,
        requesting_device_id,
        None,
    )?;
    api.get_key_backup_with_unlock_proof(&backup_id, &proof)
        .await
}

pub fn attach_key_backup_domain_separation(
    body: &mut Value,
    class: KeyBackupClass,
    subdomain: &str,
) {
    let item_types = body
        .get("contents")
        .and_then(Value::as_array)
        .map(|contents| {
            contents
                .iter()
                .filter_map(|item| item.get("item_type").and_then(Value::as_str))
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let device_id = body
        .get("device_id")
        .or_else(|| {
            body.get("encryption")
                .and_then(|encryption| encryption.get("recipient_key_ref"))
        })
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    body["domain_separation"] = json!({
        "hkdf_info": key_backup_hkdf_info(class, subdomain),
        "subdomain": subdomain,
        "aead_aad": {
            "schema": KEY_BACKUP_SCHEMA,
            "actor_id": body.get("actor_id").cloned().unwrap_or(Value::Null),
            "device_id": device_id,
            "backup_class": class.as_str(),
            "backup_version": body.get("backup_version").cloned().unwrap_or(Value::Null),
            "created_at": body.get("created_at").cloned().unwrap_or(Value::Null),
            "item_types": item_types,
        }
    });
}

pub fn attach_key_backup_genesis_series(body: &mut Value) {
    if let Some(object) = body.as_object_mut() {
        object
            .entry("series_id")
            .or_insert_with(|| json!(format!("ck:backup_series:{}", crate::operation::uuid_v7())));
        object.entry("series_seq").or_insert_with(|| json!(0));
        // Genesis carries `supersedes: null` explicitly so it is present in the
        // envelope and covered by `auth_data.signed_fields` (the schema requires
        // signed_fields to contain `supersedes` on every envelope, and the
        // fixture genesis case uses `null`). `apply_next_series` overwrites this
        // with the predecessor backup_id for successors. soland treats a null
        // `supersedes` as "no predecessor" (its `as_str()` read yields None), so
        // the genesis chain check still passes.
        object.entry("supersedes").or_insert(Value::Null);
    }
}

pub fn validate_key_backup_put_request(backup_id: &str, body: &Value) -> Result<(), String> {
    validate_key_backup_envelope(body, None)?;
    let body_backup_id = required_str(body, "backup_id")?;
    if body_backup_id != backup_id {
        return Err(format!(
            "backup_id path/body mismatch: path={backup_id} body={body_backup_id}"
        ));
    }
    Ok(())
}

pub fn validate_key_backup_envelope(
    body: &Value,
    expected_class: Option<KeyBackupClass>,
) -> Result<(), String> {
    let backup_id = required_str(body, "backup_id")?;
    if !is_protocol_backup_id(backup_id) {
        return Err("backup_id must be ck:backup:<uuidv7>".to_owned());
    }
    let series_id = required_str(body, "series_id")?;
    if !is_protocol_backup_series_id(series_id) {
        return Err("series_id must be ck:backup_series:<uuidv7>".to_owned());
    }
    if body.get("series_seq").and_then(Value::as_u64).is_none() {
        return Err("series_seq must be a non-negative integer".to_owned());
    }
    let actor_id = required_str(body, "actor_id")?;
    if !actor_id.starts_with("did:") {
        return Err("actor_id must be a DID".to_owned());
    }
    let class = KeyBackupClass::try_from(required_str(body, "backup_class")?)?;
    if let Some(expected) = expected_class
        && expected != class
    {
        return Err(format!(
            "backup_class mismatch: expected {} got {}",
            expected.as_str(),
            class.as_str()
        ));
    }
    let backup_version = required_str(body, "backup_version")?;
    if !backup_version.starts_with("kb_") {
        return Err("backup_version must start with kb_".to_owned());
    }
    let created_at = required_str(body, "created_at")?;
    if !created_at.ends_with('Z') {
        return Err("created_at must be UTC RFC3339 ending in Z".to_owned());
    }
    if let Some(device_id) = body.get("device_id").and_then(Value::as_str)
        && !is_protocol_device_id(device_id)
    {
        return Err("device_id must be ck:device:<uuidv7> when present".to_owned());
    }

    validate_contents(body, class)?;
    validate_encryption(body, class)?;
    if class == KeyBackupClass::MlsHistory {
        validate_mls_history_opaque_only(body)?;
    }
    validate_domain_separation(body, class)?;

    let ciphertext = required_str(body, "ciphertext")?;
    if !is_base64url_token(ciphertext) {
        return Err("ciphertext must be base64url".to_owned());
    }
    let ciphertext_digest = required_str(body, "ciphertext_digest")?;
    if !is_sha_digest(ciphertext_digest) {
        return Err("ciphertext_digest must be a sha digest".to_owned());
    }
    Ok(())
}

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

/// AEAD identifiers for HPKE backups (HPKE uses ChaCha20Poly1305 internally,
/// 12-byte nonce derived by the HPKE key schedule — no wire nonce).
pub const HPKE_AEAD_NAME: &str = "chacha20_poly1305";
pub const HPKE_AEAD_PROFILE: &str = "ck.aead.chacha20_poly1305.v1";

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

fn validate_contents(body: &Value, class: KeyBackupClass) -> Result<(), String> {
    let contents = body
        .get("contents")
        .and_then(Value::as_array)
        .ok_or_else(|| "contents must be a non-empty array".to_owned())?;
    if contents.is_empty() {
        return Err("contents must be a non-empty array".to_owned());
    }
    for item in contents {
        let item_type = required_str(item, "item_type")?;
        if !item_type_allowed_for_class(class, item_type) {
            return Err(format!(
                "item_type {item_type} is not allowed in backup_class {}",
                class.as_str()
            ));
        }
    }
    Ok(())
}

fn validate_encryption(body: &Value, class: KeyBackupClass) -> Result<(), String> {
    let encryption = body
        .get("encryption")
        .ok_or_else(|| "encryption is required".to_owned())?;
    let method = required_str(encryption, "recipient_method")?;
    let aead = encryption
        .get("aead")
        .ok_or_else(|| "encryption.aead is required".to_owned())?;
    let aead_name = required_str(aead, "name")?;
    if !matches!(
        aead_name,
        "xchacha20_poly1305" | "aes_256_gcm" | "chacha20_poly1305"
    ) {
        return Err("encryption.aead.name is unsupported".to_owned());
    }
    // The wire AEAD `nonce` is required for the symmetric methods
    // (passphrase_kdf / secret_storage_key); HPKE (`recovery_public_key`)
    // derives its nonce internally and carries `enc` instead, so it is checked
    // in its own branch below.
    if method != "recovery_public_key" {
        let nonce = required_str(aead, "nonce")?;
        if !is_base64url_token(nonce) || nonce.contains("placeholder") || nonce.contains("demo") {
            return Err("encryption.aead.nonce must be real base64url metadata".to_owned());
        }
    }
    match method {
        "passphrase_kdf" => {
            // Spec §5.0.1 first-backup gate: a did_recovery envelope MUST encrypt
            // to recovery_public_key, while threshold / hardware factors live
            // in the recovery policy proof layer. passphrase_kdf alone is
            // forbidden because a single passphrase must not control DID
            // recovery.
            if class == KeyBackupClass::DidRecovery {
                return Err(
                    "did_recovery backups must not use passphrase_kdf alone; use recovery_public_key or satisfy threshold/hardware factors in the recovery policy proof layer"
                        .to_owned(),
                );
            }
            if class == KeyBackupClass::MlsHistory {
                return Err(
                    "mls_history backups must use secret_storage_key or recovery_public_key"
                        .to_owned(),
                );
            }
            let kdf = encryption
                .get("kdf")
                .ok_or_else(|| "passphrase_kdf requires encryption.kdf".to_owned())?;
            validate_kdf(
                kdf,
                body.get("mixed_secret_storage").and_then(Value::as_bool) == Some(true),
            )?;
            // Spec §7.5: passphrase_kdf MUST carry a producer-generated
            // `nonce_salt` (deterministic nonce transcript) and
            // `encryption.key_commitment` (wrong-passphrase fail-fast).
            let nonce_salt = aead
                .get("nonce_salt")
                .and_then(Value::as_str)
                .ok_or_else(|| "passphrase_kdf requires encryption.aead.nonce_salt".to_owned())?;
            if !is_base64url_token(nonce_salt) {
                return Err("encryption.aead.nonce_salt must be base64url".to_owned());
            }
            let key_commitment = required_str(encryption, "key_commitment")?;
            if !is_sha_digest(key_commitment) {
                return Err("key_commitment must be a sha digest".to_owned());
            }
        }
        "secret_storage_key" => {
            // mls_history (and secret_storage caches) are wrapped under a named
            // secret_storage key; recovered after the secret_storage root is
            // unlocked. recipient_key_ref names that key id (NOT a device id),
            // and no passphrase KDF travels on the wire.
            if !matches!(
                class,
                KeyBackupClass::MlsHistory | KeyBackupClass::SecretStorage
            ) {
                return Err(
                    "secret_storage_key is only valid for mls_history or secret_storage backups"
                        .to_owned(),
                );
            }
            let key_ref = required_str(encryption, "recipient_key_ref")?;
            if key_ref.trim().is_empty() {
                return Err("secret_storage_key requires a non-empty recipient_key_ref".to_owned());
            }
            if encryption.get("kdf").is_some() {
                return Err("secret_storage_key backups must not carry encryption.kdf".to_owned());
            }
        }
        "recovery_public_key" => {
            // Spec §7.5.2: HPKE base-mode to the recovery public key. The KEM
            // encapsulation rides in `encryption.aead.enc`; no passphrase KDF,
            // no wire nonce, no nonce_salt/key_commitment (HPKE binds them).
            let key_ref = required_str(encryption, "recipient_key_ref")?;
            if key_ref.trim().is_empty() {
                return Err("recovery_public_key requires a non-empty recipient_key_ref".to_owned());
            }
            let enc = required_str(aead, "enc")?;
            if !is_base64url_token(enc) {
                return Err("recovery_public_key encryption.aead.enc must be base64url".to_owned());
            }
            if encryption.get("kdf").is_some() {
                return Err("recovery_public_key backups must not carry encryption.kdf".to_owned());
            }
        }
        other => return Err(format!("unsupported recipient_method {other}")),
    }
    Ok(())
}

fn validate_kdf(kdf: &Value, mixed_secret_storage: bool) -> Result<(), String> {
    let name = required_str(kdf, "name")?;
    let salt = required_str(kdf, "salt")?;
    if !is_base64url_token(salt) || salt.contains("demo") {
        return Err("kdf.salt must be real base64url metadata".to_owned());
    }
    let params = kdf
        .get("params")
        .ok_or_else(|| "kdf.params is required".to_owned())?;
    match name {
        "argon2id" => {
            let memory = required_u64(params, "memory_kib")?;
            let iterations = required_u64(params, "iterations")?;
            let parallelism = required_u64(params, "parallelism")?;
            let min_memory = if mixed_secret_storage {
                262_144
            } else {
                65_536
            };
            let min_iterations = if mixed_secret_storage { 4 } else { 3 };
            if memory < min_memory || iterations < min_iterations || parallelism < 1 {
                return Err("argon2id parameters below key backup profile floor".to_owned());
            }
        }
        "pbkdf2" => {
            let iterations = required_u64(params, "iterations")?;
            if params.get("hash").is_some() {
                return Err("pbkdf2 params.hash is forbidden; use digest_algorithm".to_owned());
            }
            let digest_algorithm = required_str(params, "digest_algorithm")?;
            if iterations < 600_000 || !matches!(digest_algorithm, "sha256" | "sha384" | "sha512") {
                return Err("pbkdf2 parameters below degraded profile floor".to_owned());
            }
            if kdf
                .get("degraded_profile_reason")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err("pbkdf2 key backup requires degraded_profile_reason".to_owned());
            }
        }
        _ => return Err("unsupported kdf.name".to_owned()),
    }
    Ok(())
}

fn validate_domain_separation(body: &Value, class: KeyBackupClass) -> Result<(), String> {
    let domain = body
        .get("domain_separation")
        .ok_or_else(|| "domain_separation metadata is required".to_owned())?;
    let subdomain = required_str(domain, "subdomain")?;
    let expected_info = key_backup_hkdf_info(class, subdomain);
    if required_str(domain, "hkdf_info")? != expected_info {
        return Err("domain_separation.hkdf_info does not match backup_class".to_owned());
    }
    let aad = domain
        .get("aead_aad")
        .ok_or_else(|| "domain_separation.aead_aad is required".to_owned())?;
    for key in ["actor_id", "backup_class", "backup_version", "created_at"] {
        if aad.get(key) != body.get(key) {
            return Err(format!("domain_separation.aead_aad.{key} mismatch"));
        }
    }
    if aad.get("schema").and_then(Value::as_str) != Some(KEY_BACKUP_SCHEMA) {
        return Err("domain_separation.aead_aad.schema mismatch".to_owned());
    }
    let expected_device = body
        .get("device_id")
        .or_else(|| {
            body.get("encryption")
                .and_then(|encryption| encryption.get("recipient_key_ref"))
        })
        .and_then(Value::as_str)
        .unwrap_or_default();
    if aad.get("device_id").and_then(Value::as_str) != Some(expected_device) {
        return Err("domain_separation.aead_aad.device_id mismatch".to_owned());
    }
    let expected_item_types = body
        .get("contents")
        .and_then(Value::as_array)
        .map(|contents| {
            contents
                .iter()
                .filter_map(|item| item.get("item_type").and_then(Value::as_str))
                .map(|item| Value::String(item.to_owned()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if aad.get("item_types").and_then(Value::as_array) != Some(&expected_item_types) {
        return Err("domain_separation.aead_aad.item_types mismatch".to_owned());
    }
    Ok(())
}

fn validate_mls_history_opaque_only(body: &Value) -> Result<(), String> {
    fn scan(value: &Value, path: &str) -> Result<(), String> {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    let key_lower = key.to_ascii_lowercase();
                    if matches!(
                        key_lower.as_str(),
                        "plaintext"
                            | "plain_text"
                            | "serialized_state"
                            | "state_bytes"
                            | "group_state"
                            | "passphrase"
                            | "mls_passphrase"
                            | "snapshot_secret"
                    ) {
                        return Err(format!(
                            "mls_history backups must not carry plaintext field {path}/{key}"
                        ));
                    }
                    let child_path = if path.is_empty() {
                        format!("/{key}")
                    } else {
                        format!("{path}/{key}")
                    };
                    scan(child, &child_path)?;
                }
                Ok(())
            }
            Value::Array(items) => {
                for (idx, child) in items.iter().enumerate() {
                    scan(child, &format!("{path}/{idx}"))?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    scan(body, "")
}

fn item_type_allowed_for_class(class: KeyBackupClass, item_type: &str) -> bool {
    match class {
        KeyBackupClass::DidRecovery => matches!(item_type, "recovery_key_share"),
        KeyBackupClass::SecretStorage => matches!(
            item_type,
            "self_signing_key"
                | "user_signing_key"
                | "recovery_secret"
                | "mls_account_secret"
                | "mls_private_plaintext"
                | "mls_group_secrets_backup_key"
                | "private_account_state"
        ),
        KeyBackupClass::MlsHistory => matches!(
            item_type,
            "mls_group_state" | "mls_epoch_secret" | "pending_welcome"
        ),
    }
}

fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} is required"))
}

fn required_str_anyhow<'a>(value: &'a Value, key: &str) -> anyhow::Result<&'a str> {
    required_str(value, key).map_err(|err| anyhow::anyhow!(err))
}

fn required_u64(value: &Value, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{key} is required"))
}

fn is_protocol_device_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("ck:device:") else {
        return false;
    };
    rest.len() == 36
        && rest.chars().enumerate().all(|(idx, ch)| match idx {
            8 | 13 | 18 | 23 => ch == '-',
            14 => ch == '7',
            19 => matches!(ch, '8' | '9' | 'a' | 'b'),
            _ => ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase(),
        })
}

fn is_protocol_backup_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("ck:backup:") else {
        return false;
    };
    rest.len() == 36
        && rest.chars().enumerate().all(|(idx, ch)| match idx {
            8 | 13 | 18 | 23 => ch == '-',
            14 => ch == '7',
            19 => matches!(ch, '8' | '9' | 'a' | 'b'),
            _ => ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase(),
        })
}

fn is_protocol_backup_series_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("ck:backup_series:") else {
        return false;
    };
    rest.len() == 36
        && rest.chars().enumerate().all(|(idx, ch)| match idx {
            8 | 13 | 18 | 23 => ch == '-',
            14 => ch == '7',
            19 => matches!(ch, '8' | '9' | 'a' | 'b'),
            _ => ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase(),
        })
}

fn is_base64url_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

fn is_sha_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit()))
        || value
            .strip_prefix("sha3_256:")
            .is_some_and(|hex| hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit()))
        || value
            .strip_prefix("blake3:")
            .is_some_and(|hex| hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit()))
        || value
            .strip_prefix("sha512:")
            .is_some_and(|hex| hex.len() == 128 && hex.chars().all(|ch| ch.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery_crypto::{VAULT_SALT_LEN, derive_vault_kek_with_salt};

    const BACKUP_ID: &str = "ck:backup:01964137-0000-7000-8000-00000000beef";
    const ACTOR: &str = "did:web:alice.example";
    const DEVICE: &str = "ck:device:01964137-0000-7000-8000-000000000001";

    fn test_root() -> VaultKek {
        derive_vault_kek_with_salt(b"correct horse battery staple", &[7u8; VAULT_SALT_LEN]).unwrap()
    }

    /// Test-only `secret_storage`/`recovery_vault` passphrase_kdf envelope —
    /// the former UI-facing recovery-vault builder. Kept here as a fixture so
    /// the shared seal / open / sign machinery in
    /// [`build_passphrase_kdf_backup_body`] / [`open_passphrase_kdf_backup_body`]
    /// stays covered.
    fn build_recovery_vault_backup_body(
        backup_id: &str,
        actor_id: &str,
        device_id: &str,
        root: &VaultKek,
        plaintext: &[u8],
    ) -> anyhow::Result<Value> {
        build_passphrase_kdf_backup_body(
            backup_id,
            actor_id,
            device_id,
            root,
            plaintext,
            KeyBackupClass::SecretStorage,
            "recovery_vault",
            &KeyBackupContentItem {
                item_type: "recovery_secret".to_owned(),
                secret_id: Some("yougen_recovery_vault_payload".to_owned()),
                ..Default::default()
            },
        )
    }

    #[test]
    fn build_recovery_vault_backup_body_seals_per_spec() {
        let root = test_root();
        let body =
            build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"vault payload")
                .unwrap();
        assert_eq!(body["backup_class"], "secret_storage");
        assert!(
            body["series_id"]
                .as_str()
                .is_some_and(is_protocol_backup_series_id)
        );
        assert_eq!(body["series_seq"], 0);
        assert_eq!(body["encryption"]["recipient_method"], "passphrase_kdf");
        assert_eq!(body["encryption"]["kdf"]["name"], "argon2id");
        // Argon2id params come from the root KEK; salt/nonce/nonce_salt are real.
        assert_eq!(
            body["encryption"]["kdf"]["params"]["memory_kib"],
            root.m_kib
        );
        assert!(is_base64url_token(
            body["encryption"]["kdf"]["salt"].as_str().unwrap()
        ));
        assert_eq!(body["encryption"]["aead"]["name"], "xchacha20_poly1305");
        assert_eq!(
            body["encryption"]["aead"]["aead_profile"],
            "ck.aead.xchacha20_poly1305.v1"
        );
        assert!(is_base64url_token(
            body["encryption"]["aead"]["nonce"].as_str().unwrap()
        ));
        // Spec §7.5 additions: nonce_salt + key_commitment present.
        assert!(is_base64url_token(
            body["encryption"]["aead"]["nonce_salt"].as_str().unwrap()
        ));
        assert!(is_sha_digest(
            body["encryption"]["key_commitment"].as_str().unwrap()
        ));
        assert_eq!(body["contents"][0]["item_type"], "recovery_secret");
        assert!(is_base64url_token(body["ciphertext"].as_str().unwrap()));
        assert_eq!(body["device_id"], DEVICE);
        assert_eq!(
            body["domain_separation"]["hkdf_info"],
            "cokret-key-backup/secret_storage/recovery_vault/v1"
        );
        validate_key_backup_put_request(BACKUP_ID, &body)
            .expect("secret_storage recovery vault envelope should validate");
    }

    #[test]
    fn key_backup_auth_data_sign_verify_round_trip() {
        let root = test_root();
        let mut body =
            build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"payload").unwrap();
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let vm = format!("{ACTOR}#cx_device_01964137");
        sign_key_backup_auth_data(&mut body, &signing_key, DEVICE, &vm, Some(7)).unwrap();

        assert_eq!(body["auth_data"]["verification_method"], vm);
        assert_eq!(body["auth_data"]["signature_algorithm"], "Ed25519");
        assert_eq!(body["auth_data"]["ssk_generation"], 7);
        // signed_fields must cover the mandatory set (+ series fields present).
        let signed: Vec<String> = body["auth_data"]["signed_fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        for f in KEY_BACKUP_SIGNED_FIELDS_MANDATORY {
            assert!(signed.contains(&f.to_string()), "missing signed field {f}");
        }

        verify_key_backup_auth_data(&body, &signing_key.verifying_key())
            .expect("freshly signed backup must verify");
    }

    #[test]
    fn recovery_policy_ref_is_covered_by_signed_fields_when_present() {
        // 6.2 — when recovery_policy_ref is on the envelope, the signer MUST
        // cover it (so the policy binding can't be stripped/tampered).
        let root = test_root();
        let mut body =
            build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"payload").unwrap();
        body["recovery_policy_ref"] = json!({
            "policy_id": "ck:policy:01964137-0000-7000-8000-0000000000aa",
            "policy_version": 3,
        });
        let signing_key = SigningKey::from_bytes(&[43u8; 32]);
        sign_key_backup_auth_data(&mut body, &signing_key, DEVICE, "did:web:a#device", Some(7))
            .unwrap();
        let signed: Vec<String> = body["auth_data"]["signed_fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        assert!(
            signed.contains(&"recovery_policy_ref".to_string()),
            "recovery_policy_ref must be signed: {signed:?}"
        );
        verify_key_backup_auth_data(&body, &signing_key.verifying_key())
            .expect("signed backup with recovery_policy_ref must verify");
    }

    #[test]
    fn sign_key_backup_with_active_device_is_noop_helper_signs_directly() {
        // The build-path integration uses the process-wide signer slot, which
        // races with other tests; the signing CORRECTNESS is covered by the
        // round-trip/tamper tests. Here we just confirm the direct signing
        // helper produces a self-verifying envelope (deterministic, no globals).
        let root = test_root();
        let mut body =
            build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"payload").unwrap();
        let signing_key = SigningKey::from_bytes(&[55u8; 32]);
        sign_key_backup_auth_data(
            &mut body,
            &signing_key,
            DEVICE,
            "did:web:alice.example#device",
            Some(1),
        )
        .unwrap();
        verify_key_backup_auth_data(&body, &signing_key.verifying_key())
            .expect("built+signed backup must self-verify");
    }

    #[test]
    fn key_backup_auth_data_rejects_tamper_and_wrong_key() {
        let root = test_root();
        let mut body =
            build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"payload").unwrap();
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        sign_key_backup_auth_data(&mut body, &signing_key, DEVICE, "did:web:a#device", Some(1))
            .unwrap();

        // Tamper a signed field (ciphertext is covered via ciphertext_digest, but
        // mutate backup_class which is in signed_fields) → verify fails.
        let mut tampered = body.clone();
        tampered["backup_class"] = json!("did_recovery");
        assert!(verify_key_backup_auth_data(&tampered, &signing_key.verifying_key()).is_err());

        // Wrong verifying key → fails.
        let other = SigningKey::from_bytes(&[10u8; 32]);
        let err = verify_key_backup_auth_data(&body, &other.verifying_key()).unwrap_err();
        assert!(err.contains("untrusted_backup_signature"));
    }

    #[test]
    fn recovery_vault_round_trips_through_open() {
        let root = test_root();
        let body =
            build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"secret payload")
                .unwrap();
        let recovered =
            open_passphrase_kdf_backup_body(b"correct horse battery staple", &body).unwrap();
        assert_eq!(recovered, b"secret payload");
        // Wrong passphrase fails fast via key_commitment.
        let err = open_passphrase_kdf_backup_body(b"wrong", &body).unwrap_err();
        assert!(err.to_string().contains("key_commitment mismatch"));
    }

    #[test]
    fn did_recovery_backup_uses_separate_domain_and_hpke() {
        let (sk, pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
        let body = build_did_recovery_backup_body(
            "ck:backup:01964137-0000-7000-8000-00000000d1d0",
            ACTOR,
            DEVICE,
            &pk,
            "did:web:alice.example#recovery",
            b"recovery share",
            "ck:policy:01964137-0000-7000-8000-0000000000aa",
            1,
        )
        .unwrap();

        assert_eq!(body["backup_class"], "did_recovery");
        assert_eq!(
            body["encryption"]["recipient_method"],
            "recovery_public_key"
        );
        // 6.2 — did_recovery MUST carry recovery_policy_ref (top-level).
        assert_eq!(
            body["recovery_policy_ref"]["policy_id"],
            "ck:policy:01964137-0000-7000-8000-0000000000aa"
        );
        assert_eq!(body["recovery_policy_ref"]["policy_version"], 1);
        assert!(
            body["series_id"]
                .as_str()
                .is_some_and(is_protocol_backup_series_id)
        );
        assert_eq!(body["series_seq"], 0);
        assert_eq!(body["contents"][0]["item_type"], "recovery_key_share");
        assert_eq!(
            body["domain_separation"]["hkdf_info"],
            "cokret-key-backup/did_recovery/recovery_policy/v1"
        );
        validate_key_backup_envelope(&body, Some(KeyBackupClass::DidRecovery))
            .expect("did_recovery HPKE envelope should validate");
        // Round-trips with the recovery private key.
        assert_eq!(
            open_recovery_public_key_backup_body(&sk, &body).unwrap(),
            b"recovery share"
        );
    }

    #[test]
    fn did_recovery_passphrase_kdf_is_rejected() {
        // Spec §5.0.1 first-backup gate: passphrase_kdf-only did_recovery forbidden.
        let root = test_root();
        let mut body =
            build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
        body["backup_class"] = json!("did_recovery");
        body["contents"][0]["item_type"] = json!("recovery_key_share");
        attach_key_backup_domain_separation(
            &mut body,
            KeyBackupClass::DidRecovery,
            "recovery_policy",
        );
        let err = validate_key_backup_envelope(&body, Some(KeyBackupClass::DidRecovery))
            .expect_err("passphrase_kdf did_recovery must be rejected");
        assert!(err.contains("did_recovery"), "{err}");
    }

    #[test]
    fn key_backup_validator_rejects_cross_domain_item_mix() {
        let root = test_root();
        let mut body =
            build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
        body["contents"][0]["item_type"] = json!("mls_group_state");
        attach_key_backup_domain_separation(
            &mut body,
            KeyBackupClass::SecretStorage,
            "recovery_vault",
        );

        let err = validate_key_backup_envelope(&body, Some(KeyBackupClass::SecretStorage))
            .expect_err("secret_storage must not carry MLS history items");
        assert!(err.contains("not allowed"));
    }

    #[test]
    fn key_backup_validator_rejects_missing_domain_separation() {
        let root = test_root();
        let mut body =
            build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
        body.as_object_mut().unwrap().remove("domain_separation");

        let err = validate_key_backup_envelope(&body, Some(KeyBackupClass::SecretStorage))
            .expect_err("domain separation metadata is required");
        assert!(err.contains("domain_separation"));
    }

    #[test]
    fn key_backup_validator_rejects_missing_series_fields() {
        let root = test_root();
        let mut body =
            build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
        body.as_object_mut().unwrap().remove("series_id");

        let err = validate_key_backup_envelope(&body, Some(KeyBackupClass::SecretStorage))
            .expect_err("series_id is mandatory");
        assert!(err.contains("series_id"));
    }

    #[test]
    fn mls_history_rejects_passphrase_kdf() {
        let root = test_root();
        let mut body =
            build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
        body["backup_class"] = json!("mls_history");
        body["contents"][0]["item_type"] = json!("mls_group_state");
        attach_key_backup_domain_separation(&mut body, KeyBackupClass::MlsHistory, "mls_snapshot");

        let err = validate_key_backup_envelope(&body, Some(KeyBackupClass::MlsHistory))
            .expect_err("MLS history passphrase KDF backup must be rejected");
        assert!(err.contains("secret_storage_key"));
    }

    #[test]
    fn mls_history_accepts_secret_storage_key() {
        let envelope = crate::mls::persistence::encrypt_state(
            "ck:realm:demo",
            "group-a",
            3,
            b"opaque sdk state",
            "device-secret",
            b"salt",
        );
        let body = envelope.to_key_backup_body(
            "ck:backup:01964137-0000-7000-8000-00000000feed",
            ACTOR,
            DEVICE,
        );
        assert_eq!(body["encryption"]["recipient_method"], "secret_storage_key");
        assert_eq!(
            body["encryption"]["recipient_key_ref"],
            "mls_group_secrets_backup_key"
        );
        validate_key_backup_envelope(&body, Some(KeyBackupClass::MlsHistory))
            .expect("mls_history secret_storage_key envelope should validate");
    }

    #[test]
    fn recovery_public_key_backup_round_trips_and_validates() {
        let (sk, pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
        let body = build_recovery_public_key_backup_body(
            BACKUP_ID,
            ACTOR,
            DEVICE,
            &pk,
            "did:web:alice.example#recovery",
            KeyBackupClass::MlsHistory,
            "mls_snapshot",
            &KeyBackupContentItem {
                item_type: "mls_group_state".to_owned(),
                secret_id: Some("yougen_mls_snapshot".to_owned()),
                ..Default::default()
            },
            b"opaque mls snapshot bytes",
            None,
        )
        .unwrap();

        assert_eq!(
            body["encryption"]["recipient_method"],
            "recovery_public_key"
        );
        assert_eq!(
            body["encryption"]["recipient_key_ref"],
            "did:web:alice.example#recovery"
        );
        assert!(is_base64url_token(
            body["encryption"]["aead"]["enc"].as_str().unwrap()
        ));
        assert!(body["encryption"]["aead"].get("nonce").is_none());
        validate_key_backup_envelope(&body, Some(KeyBackupClass::MlsHistory))
            .expect("recovery_public_key mls_history envelope should validate");

        // The recovery private key opens it (the fresh-device restore path);
        // a different recovery key cannot.
        let opened = open_recovery_public_key_backup_body(&sk, &body).unwrap();
        assert_eq!(opened, b"opaque mls snapshot bytes");
        let (other_sk, _other_pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
        assert!(open_recovery_public_key_backup_body(&other_sk, &body).is_err());
    }

    #[test]
    fn mls_history_rejects_obvious_plaintext_fields() {
        let envelope = crate::mls::persistence::encrypt_state(
            "ck:realm:demo",
            "group-a",
            3,
            b"not real sdk state",
            "device-secret",
            b"salt",
        );
        let mut body = envelope.to_key_backup_body(
            "ck:backup:01964137-0000-7000-8000-00000000beef",
            "did:web:alice.example",
            "ck:device:01964137-0000-7000-8000-000000000001",
        );
        body["serialized_state"] = json!("plaintext sdk bytes");

        let err = validate_key_backup_envelope(&body, Some(KeyBackupClass::MlsHistory))
            .expect_err("MLS history backups must stay opaque");
        assert!(err.contains("plaintext field"));
    }

    #[test]
    fn key_backup_validator_rejects_weak_argon2id() {
        let root = test_root();
        let mut body =
            build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();
        // Force the wire params below the profile floor (the builder always uses
        // the strong root params, so weaken them post-build to exercise the
        // validator).
        body["encryption"]["kdf"]["params"]["memory_kib"] = json!(1);
        body["encryption"]["kdf"]["params"]["iterations"] = json!(1);

        let err = validate_key_backup_envelope(&body, Some(KeyBackupClass::SecretStorage))
            .expect_err("weak KDF parameters must be rejected");
        assert!(err.contains("argon2id"));
    }

    #[test]
    fn key_backup_put_request_rejects_path_body_mismatch() {
        let root = test_root();
        let body = build_recovery_vault_backup_body(BACKUP_ID, ACTOR, DEVICE, &root, b"x").unwrap();

        let err = validate_key_backup_put_request(
            "ck:backup:01964137-0000-7000-8000-00000000badd",
            &body,
        )
        .expect_err("path/body backup id mismatch must be rejected");
        assert!(err.contains("mismatch"));
    }

    #[test]
    fn delete_ownership_proof_binds_actor_and_backup() {
        assert_eq!(
            key_backup_delete_ownership_proof(
                "did:web:alice.example",
                "ck:backup:01964137-0000-7000-8000-00000000beef"
            ),
            "dev-ssk-delete:v1:did:web:alice.example:ck:backup:01964137-0000-7000-8000-00000000beef"
        );
    }
}
