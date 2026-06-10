//! Principal-private file transfer support (`ck.profile.file_transfer.v1`).
//!
//! The feature is intentionally account-scoped: encrypted blob bytes live in
//! the blob service, while the transfer record is sealed before being written
//! as private account-data under `ck.file_transfer.v1:<transfer_key>`.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::api::CokretApi;
use crate::models::AccountDataSetOutcome;

pub const FILE_TRANSFER_PURPOSE: &str = "file_transfer";
pub const FILE_TRANSFER_RECORD_KIND: &str = "file_transfer";
pub const FILE_TRANSFER_RECORD_ENVELOPE_SCHEME: &str = "ck.file_transfer.account_data_envelope.v1";
pub const FILE_TRANSFER_BLOB_SCHEME: &str = "ck.file_transfer.encrypted_blob.v1";
pub const FILE_TRANSFER_SCHEMA: &str = "ck.schema.file_transfer.v1";
pub const FILE_TRANSFER_AEAD_PROFILE: &str = "ck.aead.xchacha20_poly1305.v1";
pub const FILE_TRANSFER_RETENTION_DAYS: i64 = 7;

const CONTENT_KEY_LEN: usize = 32;
const XCHACHA_NONCE_LEN: usize = 24;
const NAMESPACE_KEY_INFO: &[u8] = b"cokret-file-transfer-account-data-key-v1";
const RECORD_WRAP_KEY_INFO: &[u8] = b"cokret-file-transfer-record-wrap-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileTransferCryptoContext {
    namespace_key: [u8; CONTENT_KEY_LEN],
    record_wrap_key: [u8; CONTENT_KEY_LEN],
}

impl FileTransferCryptoContext {
    pub fn from_account_secret(account_secret: &str) -> anyhow::Result<Self> {
        Ok(Self {
            namespace_key: derive_account_subkey(account_secret, NAMESPACE_KEY_INFO)?,
            record_wrap_key: derive_account_subkey(account_secret, RECORD_WRAP_KEY_INFO)?,
        })
    }

    pub fn namespace_key(&self) -> &[u8; CONTENT_KEY_LEN] {
        &self.namespace_key
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileTransferRecord {
    pub kind: String,
    pub transfer_id: String,
    pub blob_ref: String,
    pub content_digest: String,
    pub blob_size_bytes: u64,
    pub media_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    pub plaintext_size_bytes: u64,
    pub access: FileTransferAccess,
    pub encryption: FileTransferEncryption,
    pub origin_device_id: String,
    pub created_at: String,
    pub updated_hlc: String,
    pub retention_expires_at: String,
    pub state: FileTransferState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileTransferAccess {
    pub visibility: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipient_device_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileTransferEncryption {
    pub scheme: String,
    pub aead_profile: String,
    pub nonce: String,
    pub aad: FileTransferAad,
    pub key_delivery: FileTransferKeyDelivery,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileTransferAad {
    pub schema: String,
    pub purpose: String,
    pub transfer_id: String,
    pub origin_device_id: String,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileTransferKeyDelivery {
    pub method: String,
    pub content_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileTransferState {
    Available,
    Downloaded,
    Dismissed,
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileTransferItem {
    pub account_data_key: String,
    pub record: FileTransferRecord,
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileTransferUploadResult {
    pub item: FileTransferItem,
    pub server_response: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedFileTransfer {
    account_data_key: String,
    transfer_id: String,
    ciphertext: Vec<u8>,
    content_digest: String,
    plaintext_size_bytes: u64,
    media_type: String,
    filename: Option<String>,
    content_key: [u8; CONTENT_KEY_LEN],
    nonce: [u8; XCHACHA_NONCE_LEN],
    aad: FileTransferAad,
    origin_device_id: String,
    created_at: String,
    updated_hlc: String,
    retention_expires_at: String,
}

pub fn load_or_create_file_transfer_crypto_context(
    actor_id: &str,
    device_id: &str,
) -> anyhow::Result<FileTransferCryptoContext> {
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let account_secret = crate::mls::runtime::load_or_create_account_mls_secret(
        secure_store.as_ref(),
        actor_id,
        device_id,
    )
    .map_err(|error| anyhow::anyhow!("account MLS secret unavailable: {error}"))?;
    FileTransferCryptoContext::from_account_secret(&account_secret)
}

pub fn load_file_transfer_crypto_context(
    actor_id: &str,
) -> anyhow::Result<Option<FileTransferCryptoContext>> {
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let Some(account_secret) =
        crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), actor_id)
            .map_err(|error| anyhow::anyhow!("account MLS secret unavailable: {error}"))?
    else {
        return Ok(None);
    };
    FileTransferCryptoContext::from_account_secret(&account_secret.secret).map(Some)
}

pub async fn upload_actor_private_file(
    api: &CokretApi,
    crypto: &FileTransferCryptoContext,
    actor_id: &str,
    device_id: &str,
    filename: Option<&str>,
    media_type: &str,
    plaintext: Vec<u8>,
) -> anyhow::Result<FileTransferUploadResult> {
    let prepared = prepare_actor_private_file(
        crypto, actor_id, device_id, filename, media_type, plaintext,
    )?;
    let account_data_key = prepared.account_data_key.clone();
    // Auto-dispatch: large ciphertexts take the resumable (tus) binding
    // when the server advertises it in /_cokret/describe, with automatic
    // fallback to the canonical single-shot upload. Outcome shape and
    // blob_ref are identical either way (media-and-blob.md §2.1).
    let upload = api
        .upload_file_transfer_ciphertext_auto(prepared.ciphertext.clone(), &prepared.content_digest)
        .await?;
    let uploaded_digest = upload.content_digest.to_string();
    if uploaded_digest != prepared.content_digest {
        anyhow::bail!("file-transfer blob upload digest mismatch");
    }
    let blob_ref = upload.blob_ref.to_string();
    verify_content_addressed_blob_ref(&blob_ref, &prepared.content_digest)?;

    let record = prepared.into_record(blob_ref, upload.size_bytes)?;
    let derived_account_data_key = record_account_key(&record, crypto)?;
    if derived_account_data_key != account_data_key {
        anyhow::bail!("file-transfer account_data key derivation drift");
    }
    let envelope = seal_record_envelope(&record, crypto, &account_data_key, actor_id)?;
    let outcome = api.set_account_data(&account_data_key, envelope).await?;
    let server_response = match outcome {
        AccountDataSetOutcome::Stored { response } => response,
        AccountDataSetOutcome::Unsupported { status } => {
            anyhow::bail!("ck.account_data.set unsupported for file transfer: {status}");
        }
    };
    Ok(FileTransferUploadResult {
        item: FileTransferItem {
            account_data_key,
            record,
            updated_at: None,
        },
        server_response,
    })
}

pub async fn decrypt_file_transfer_item(
    api: &CokretApi,
    item: &FileTransferItem,
) -> anyhow::Result<Vec<u8>> {
    let ciphertext = api
        .get_file_transfer_blob_bytes(&item.record.blob_ref)
        .await?;
    decrypt_file_transfer_ciphertext(&item.record, &ciphertext)
}

pub fn decrypt_file_transfer_ciphertext(
    record: &FileTransferRecord,
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    validate_ciphertext_binding(record, ciphertext)?;
    let content_key = decode_fixed::<CONTENT_KEY_LEN>(&record.encryption.key_delivery.content_key)?;
    let nonce = decode_fixed::<XCHACHA_NONCE_LEN>(&record.encryption.nonce)?;
    let aad_bytes = crate::canonical::canonical_json_bytes(&record.encryption.aad)?;
    let cipher = XChaCha20Poly1305::new((&content_key).into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad_bytes,
            },
        )
        .map_err(|error| anyhow::anyhow!("file-transfer decrypt failed: {error}"))?;
    if plaintext.len() as u64 != record.plaintext_size_bytes {
        anyhow::bail!("file-transfer plaintext size mismatch");
    }
    Ok(plaintext)
}

pub fn file_transfer_items_from_account_data(
    entries: &[Value],
    crypto: &FileTransferCryptoContext,
) -> Vec<FileTransferItem> {
    let mut items = entries
        .iter()
        .filter_map(|entry| file_transfer_item_from_account_data(entry, crypto).ok())
        .filter(|item| item.record.state != FileTransferState::Deleted)
        .collect::<Vec<_>>();
    items.sort_by(|left, right| {
        right
            .record
            .created_at
            .cmp(&left.record.created_at)
            .then_with(|| right.account_data_key.cmp(&left.account_data_key))
    });
    items
}

pub fn data_url_for_download(bytes: &[u8], media_type: &str) -> String {
    let media_type = normalize_media_type(media_type);
    format!("data:{media_type};base64,{}", BASE64_STANDARD.encode(bytes))
}

pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else if value >= 10.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn display_filename(record: &FileTransferRecord) -> String {
    record
        .filename
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("Untitled file")
        .to_owned()
}

fn prepare_actor_private_file(
    crypto: &FileTransferCryptoContext,
    actor_id: &str,
    device_id: &str,
    filename: Option<&str>,
    media_type: &str,
    plaintext: Vec<u8>,
) -> anyhow::Result<PreparedFileTransfer> {
    if actor_id.trim().is_empty() {
        anyhow::bail!("actor_id is required for file transfer");
    }
    if device_id.trim().is_empty() {
        anyhow::bail!("device_id is required for file transfer");
    }
    let transfer_id = random_base64url(24)?;
    let account_data_key =
        crate::account_data::file_transfer_account_data_key(crypto.namespace_key(), &transfer_id)?;
    let mut content_key = [0u8; CONTENT_KEY_LEN];
    getrandom::fill(&mut content_key)
        .map_err(|error| anyhow::anyhow!("file-transfer content-key rng: {error}"))?;
    let mut nonce = [0u8; XCHACHA_NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|error| anyhow::anyhow!("file-transfer nonce rng: {error}"))?;

    let created_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let retention_expires_at = (chrono::Utc::now()
        + chrono::Duration::days(FILE_TRANSFER_RETENTION_DAYS))
    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let aad = FileTransferAad {
        schema: FILE_TRANSFER_SCHEMA.to_owned(),
        purpose: FILE_TRANSFER_PURPOSE.to_owned(),
        transfer_id: transfer_id.clone(),
        origin_device_id: device_id.trim().to_owned(),
        created_at: created_at.clone(),
    };
    let aad_bytes = crate::canonical::canonical_json_bytes(&aad)?;
    let cipher = XChaCha20Poly1305::new((&content_key).into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad_bytes,
            },
        )
        .map_err(|error| anyhow::anyhow!("file-transfer encrypt failed: {error}"))?;
    let content_digest = sha256_digest(&ciphertext);
    Ok(PreparedFileTransfer {
        account_data_key,
        transfer_id,
        ciphertext,
        content_digest,
        plaintext_size_bytes: plaintext.len() as u64,
        media_type: normalize_media_type(media_type),
        filename: filename.and_then(sanitize_filename),
        content_key,
        nonce,
        aad,
        origin_device_id: device_id.trim().to_owned(),
        created_at,
        updated_hlc: crate::hlc::Hlc::now(device_id).encode(),
        retention_expires_at,
    })
}

impl PreparedFileTransfer {
    fn into_record(
        self,
        blob_ref: String,
        blob_size_bytes: u64,
    ) -> anyhow::Result<FileTransferRecord> {
        Ok(FileTransferRecord {
            kind: FILE_TRANSFER_RECORD_KIND.to_owned(),
            transfer_id: self.transfer_id,
            blob_ref,
            content_digest: self.content_digest,
            blob_size_bytes,
            media_type: self.media_type,
            filename: self.filename,
            plaintext_size_bytes: self.plaintext_size_bytes,
            access: FileTransferAccess {
                visibility: "actor_private".to_owned(),
                recipient_device_ids: Vec::new(),
            },
            encryption: FileTransferEncryption {
                scheme: FILE_TRANSFER_BLOB_SCHEME.to_owned(),
                aead_profile: FILE_TRANSFER_AEAD_PROFILE.to_owned(),
                nonce: URL_SAFE_NO_PAD.encode(self.nonce),
                aad: self.aad,
                key_delivery: FileTransferKeyDelivery {
                    method: "account_data_wrapped_key".to_owned(),
                    content_key: URL_SAFE_NO_PAD.encode(self.content_key),
                },
            },
            origin_device_id: self.origin_device_id,
            created_at: self.created_at,
            updated_hlc: self.updated_hlc,
            retention_expires_at: self.retention_expires_at,
            state: FileTransferState::Available,
        })
    }
}

fn file_transfer_item_from_account_data(
    entry: &Value,
    crypto: &FileTransferCryptoContext,
) -> anyhow::Result<FileTransferItem> {
    let data_type = entry
        .get("data_type")
        .or_else(|| entry.get("type"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("account_data entry missing data_type"))?;
    if !data_type
        .strip_prefix(cokret_sdk::ACCOUNT_DATA_TYPE_FILE_TRANSFER)
        .is_some_and(|rest| rest.starts_with(':'))
    {
        anyhow::bail!("not a file-transfer account_data entry");
    }
    crate::account_data::validate_private_account_data_key(data_type)?;
    let content = entry
        .get("content")
        .or_else(|| entry.get("encrypted_payload"))
        .ok_or_else(|| anyhow::anyhow!("file-transfer account_data content missing"))?;
    let record = open_record_envelope(content, crypto, data_type)?;
    if record.kind != FILE_TRANSFER_RECORD_KIND {
        anyhow::bail!("file-transfer record kind mismatch");
    }
    let derived_key = record_account_key(&record, crypto)?;
    if derived_key != data_type {
        anyhow::bail!("file-transfer account_data key mismatch");
    }
    Ok(FileTransferItem {
        account_data_key: data_type.to_owned(),
        record,
        updated_at: entry
            .get("updated_at")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    })
}

fn seal_record_envelope(
    record: &FileTransferRecord,
    crypto: &FileTransferCryptoContext,
    account_data_key: &str,
    actor_id: &str,
) -> anyhow::Result<Value> {
    let mut nonce = [0u8; XCHACHA_NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|error| anyhow::anyhow!("file-transfer record nonce rng: {error}"))?;
    let aad = json!({
        "schema": FILE_TRANSFER_SCHEMA,
        "purpose": "file_transfer_record",
        "transfer_key": account_data_key,
        "actor_id": actor_id,
    });
    let aad_bytes = crate::canonical::canonical_json_bytes(&aad)?;
    let plaintext = crate::canonical::canonical_json_bytes(record)?;
    let cipher = XChaCha20Poly1305::new((&crypto.record_wrap_key).into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad_bytes,
            },
        )
        .map_err(|error| anyhow::anyhow!("file-transfer record seal failed: {error}"))?;
    Ok(json!({
        "scheme": FILE_TRANSFER_RECORD_ENVELOPE_SCHEME,
        "aead_profile": FILE_TRANSFER_AEAD_PROFILE,
        "nonce": URL_SAFE_NO_PAD.encode(nonce),
        "aad": aad,
        "ciphertext": URL_SAFE_NO_PAD.encode(ciphertext),
    }))
}

fn open_record_envelope(
    envelope: &Value,
    crypto: &FileTransferCryptoContext,
    account_data_key: &str,
) -> anyhow::Result<FileTransferRecord> {
    if envelope.get("scheme").and_then(Value::as_str) != Some(FILE_TRANSFER_RECORD_ENVELOPE_SCHEME)
    {
        anyhow::bail!("file-transfer account-data envelope scheme mismatch");
    }
    if envelope.get("aead_profile").and_then(Value::as_str) != Some(FILE_TRANSFER_AEAD_PROFILE) {
        anyhow::bail!("file-transfer account-data envelope AEAD mismatch");
    }
    let nonce = decode_fixed::<XCHACHA_NONCE_LEN>(required_str(envelope, "nonce")?)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(required_str(envelope, "ciphertext")?)
        .map_err(|error| anyhow::anyhow!("file-transfer record ciphertext base64: {error}"))?;
    let aad = envelope
        .get("aad")
        .ok_or_else(|| anyhow::anyhow!("file-transfer record envelope aad missing"))?;
    validate_record_envelope_aad(aad, account_data_key)?;
    let aad_bytes = crate::canonical::canonical_json_bytes(aad)?;
    let cipher = XChaCha20Poly1305::new((&crypto.record_wrap_key).into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext.as_slice(),
                aad: &aad_bytes,
            },
        )
        .map_err(|error| anyhow::anyhow!("file-transfer record open failed: {error}"))?;
    serde_json::from_slice(&plaintext)
        .map_err(|error| anyhow::anyhow!("file-transfer record JSON decode failed: {error}"))
}

fn validate_record_envelope_aad(aad: &Value, account_data_key: &str) -> anyhow::Result<()> {
    if aad.get("schema").and_then(Value::as_str) != Some(FILE_TRANSFER_SCHEMA) {
        anyhow::bail!("file-transfer record envelope AAD schema mismatch");
    }
    if aad.get("purpose").and_then(Value::as_str) != Some("file_transfer_record") {
        anyhow::bail!("file-transfer record envelope AAD purpose mismatch");
    }
    if aad.get("transfer_key").and_then(Value::as_str) != Some(account_data_key) {
        anyhow::bail!("file-transfer record envelope AAD transfer key mismatch");
    }
    if aad
        .get("actor_id")
        .and_then(Value::as_str)
        .is_none_or(|actor| actor.trim().is_empty())
    {
        anyhow::bail!("file-transfer record envelope AAD actor_id missing");
    }
    Ok(())
}

fn record_account_key(
    record: &FileTransferRecord,
    crypto: &FileTransferCryptoContext,
) -> anyhow::Result<String> {
    crate::account_data::file_transfer_account_data_key(crypto.namespace_key(), &record.transfer_id)
}

fn validate_ciphertext_binding(
    record: &FileTransferRecord,
    ciphertext: &[u8],
) -> anyhow::Result<()> {
    let digest = sha256_digest(ciphertext);
    if record.content_digest != digest {
        anyhow::bail!("file-transfer ciphertext digest mismatch");
    }
    verify_content_addressed_blob_ref(&record.blob_ref, &digest)?;
    if record.blob_size_bytes != ciphertext.len() as u64 {
        anyhow::bail!("file-transfer blob size mismatch");
    }
    if record.encryption.scheme != FILE_TRANSFER_BLOB_SCHEME {
        anyhow::bail!("file-transfer encryption scheme mismatch");
    }
    if record.encryption.aead_profile != FILE_TRANSFER_AEAD_PROFILE {
        anyhow::bail!("file-transfer AEAD profile mismatch");
    }
    if record.encryption.key_delivery.method != "account_data_wrapped_key" {
        anyhow::bail!("file-transfer key delivery method unsupported");
    }
    if record.access.visibility != "actor_private" {
        anyhow::bail!("file-transfer access visibility unsupported");
    }
    validate_content_aad(record)?;
    Ok(())
}

fn validate_content_aad(record: &FileTransferRecord) -> anyhow::Result<()> {
    let aad = &record.encryption.aad;
    if aad.schema != FILE_TRANSFER_SCHEMA {
        anyhow::bail!("file-transfer content AAD schema mismatch");
    }
    if aad.purpose != FILE_TRANSFER_PURPOSE {
        anyhow::bail!("file-transfer content AAD purpose mismatch");
    }
    if aad.transfer_id != record.transfer_id {
        anyhow::bail!("file-transfer content AAD transfer_id mismatch");
    }
    if aad.origin_device_id != record.origin_device_id {
        anyhow::bail!("file-transfer content AAD origin_device_id mismatch");
    }
    if aad.created_at != record.created_at {
        anyhow::bail!("file-transfer content AAD created_at mismatch");
    }
    Ok(())
}

fn verify_content_addressed_blob_ref(blob_ref: &str, digest: &str) -> anyhow::Result<()> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        anyhow::bail!("file-transfer content_digest must be sha256");
    };
    let expected = format!("ck:blob:sha256:{hex}");
    if blob_ref != expected {
        anyhow::bail!("file-transfer blob_ref does not match ciphertext digest");
    }
    Ok(())
}

fn derive_account_subkey(
    account_secret: &str,
    info: &[u8],
) -> anyhow::Result<[u8; CONTENT_KEY_LEN]> {
    let ikm = match URL_SAFE_NO_PAD.decode(account_secret.trim()) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        _ => account_secret.as_bytes().to_vec(),
    };
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = [0u8; CONTENT_KEY_LEN];
    hk.expand(info, &mut out)
        .map_err(|_| anyhow::anyhow!("file-transfer HKDF expand failed"))?;
    Ok(out)
}

fn random_base64url(bytes_len: usize) -> anyhow::Result<String> {
    let mut bytes = vec![0u8; bytes_len];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("file-transfer transfer-id rng: {error}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn decode_fixed<const N: usize>(value: &str) -> anyhow::Result<[u8; N]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| anyhow::anyhow!("base64url decode failed: {error}"))?;
    if bytes.len() != N {
        anyhow::bail!("decoded value has length {}, expected {N}", bytes.len());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn required_str<'a>(value: &'a Value, field: &str) -> anyhow::Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("{field} is required"))
}

fn sanitize_filename(value: &str) -> Option<String> {
    let name = value
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .trim()
        .trim_matches('"');
    if name.is_empty() {
        return None;
    }
    let mut sanitized = String::new();
    for ch in name.chars() {
        if ch.is_control() {
            continue;
        }
        if matches!(ch, '/' | '\\' | ':') {
            sanitized.push('_');
        } else {
            sanitized.push(ch);
        }
        if sanitized.len() >= 255 {
            break;
        }
    }
    let sanitized = sanitized
        .trim_matches(|ch: char| ch.is_whitespace() || matches!(ch, '.' | '_' | '-'))
        .to_owned();
    (!sanitized.is_empty()).then_some(sanitized)
}

fn normalize_media_type(value: &str) -> String {
    let media_type = value
        .split(';')
        .next()
        .unwrap_or("application/octet-stream")
        .trim()
        .to_ascii_lowercase();
    let Some((top, sub)) = media_type.split_once('/') else {
        return "application/octet-stream".to_owned();
    };
    if valid_mime_token(top) && valid_mime_token(sub) {
        media_type
    } else {
        "application/octet-stream".to_owned()
    }
}

fn valid_mime_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '+' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACTOR: &str = "did:web:alice.example";
    const DEVICE: &str = "ck:device:01904100-0000-7000-8000-000000000001";

    #[test]
    fn prepared_file_round_trips_through_record_envelope_and_content_aead() {
        let crypto = FileTransferCryptoContext::from_account_secret("test-account-secret").unwrap();
        let prepared = prepare_actor_private_file(
            &crypto,
            ACTOR,
            DEVICE,
            Some("report.pdf"),
            "Application/Pdf; charset=utf-8",
            b"hello file".to_vec(),
        )
        .unwrap();
        let blob_ref = format!(
            "ck:blob:sha256:{}",
            prepared.content_digest.trim_start_matches("sha256:")
        );
        let ciphertext = prepared.ciphertext.clone();
        let record = prepared
            .into_record(blob_ref, ciphertext.len() as u64)
            .unwrap();
        let key = record_account_key(&record, &crypto).unwrap();
        let envelope = seal_record_envelope(&record, &crypto, &key, ACTOR).unwrap();
        let entry = json!({
            "data_type": key,
            "content": envelope,
            "updated_at": "2026-06-07T00:00:00Z",
        });
        let items = file_transfer_items_from_account_data(&[entry], &crypto);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].record.filename.as_deref(), Some("report.pdf"));
        assert_eq!(items[0].record.media_type, "application/pdf");

        let plaintext = decrypt_file_transfer_ciphertext(&items[0].record, &ciphertext).unwrap();
        assert_eq!(plaintext, b"hello file");
    }

    #[test]
    fn record_envelope_must_match_account_data_key() {
        let crypto = FileTransferCryptoContext::from_account_secret("test-account-secret").unwrap();
        let prepared = prepare_actor_private_file(
            &crypto,
            ACTOR,
            DEVICE,
            Some("report.pdf"),
            "application/pdf",
            b"hello file".to_vec(),
        )
        .unwrap();
        let blob_ref = format!(
            "ck:blob:sha256:{}",
            prepared.content_digest.trim_start_matches("sha256:")
        );
        let blob_size_bytes = prepared.ciphertext.len() as u64;
        let record = prepared.into_record(blob_ref, blob_size_bytes).unwrap();
        let key = record_account_key(&record, &crypto).unwrap();
        let envelope = seal_record_envelope(&record, &crypto, &key, ACTOR).unwrap();
        let wrong_key = crate::account_data::file_transfer_account_data_key(
            crypto.namespace_key(),
            "0123456789abcdef012345",
        )
        .unwrap();
        let entry = json!({
            "data_type": wrong_key,
            "content": envelope,
        });

        let items = file_transfer_items_from_account_data(&[entry], &crypto);
        assert!(items.is_empty());
    }

    #[test]
    fn digest_or_blob_ref_drift_fails_closed() {
        let crypto = FileTransferCryptoContext::from_account_secret("test-account-secret").unwrap();
        let prepared = prepare_actor_private_file(
            &crypto,
            ACTOR,
            DEVICE,
            Some("a.txt"),
            "text/plain",
            b"hello".to_vec(),
        )
        .unwrap();
        let ciphertext = prepared.ciphertext.clone();
        let record = prepared
            .into_record(
                "ck:blob:sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_owned(),
                ciphertext.len() as u64,
            )
            .unwrap();
        assert!(decrypt_file_transfer_ciphertext(&record, &ciphertext).is_err());
    }

    #[test]
    fn top_level_and_content_aad_must_match() {
        let crypto = FileTransferCryptoContext::from_account_secret("test-account-secret").unwrap();
        let prepared = prepare_actor_private_file(
            &crypto,
            ACTOR,
            DEVICE,
            Some("a.txt"),
            "text/plain",
            b"hello".to_vec(),
        )
        .unwrap();
        let ciphertext = prepared.ciphertext.clone();
        let blob_ref = format!(
            "ck:blob:sha256:{}",
            prepared.content_digest.trim_start_matches("sha256:")
        );
        let mut record = prepared
            .into_record(blob_ref, ciphertext.len() as u64)
            .unwrap();
        record.transfer_id = "0123456789abcdef012345".to_owned();

        assert!(decrypt_file_transfer_ciphertext(&record, &ciphertext).is_err());
    }
}
