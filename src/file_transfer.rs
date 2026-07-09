//! Principal-private file transfer support (`ck.profile.file_transfer.v1`).
//!
//! The feature is intentionally account-scoped: encrypted blob bytes live in
//! the blob service, while the transfer record is sealed before being written
//! as private account-data under `ck.file_transfer.v1:<transfer_key>`.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
pub use cokret_sdk::{
    FileTransferAad, FileTransferAccess, FileTransferAccessVisibility, FileTransferEncryption,
    FileTransferKeyDelivery, FileTransferKeyEnvelope, FileTransferKeyMessage, FileTransferRecord,
    FileTransferState,
};
use hkdf::Hkdf;
use serde_json::{Value, json};
use sha2::Sha256;

use crate::api::CokretApi;
use crate::models::AccountDataSetResult;

pub const FILE_TRANSFER_PURPOSE: &str = "file_transfer";
pub const FILE_TRANSFER_RECORD_KIND: &str = "file_transfer";
pub const FILE_TRANSFER_RECORD_ENVELOPE_SCHEME: &str = "ck.file_transfer.account_data_envelope.v1";
pub const FILE_TRANSFER_BLOB_SCHEME: &str = "ck.file_transfer.encrypted_blob.v1";
pub const FILE_TRANSFER_SCHEMA: &str = "ck.schema.file_transfer.v1";
pub const FILE_TRANSFER_AEAD_PROFILE: &str = "ck.aead.xchacha20_poly1305.v1";
pub const FILE_TRANSFER_RETENTION_DAYS: i64 = 7;
pub const FILE_TRANSFER_KEY_HPKE_INFO: &[u8] = b"arkret-file-transfer-key-hpke-x25519-v1";

const CONTENT_KEY_LEN: usize = 32;
const XCHACHA_NONCE_LEN: usize = 24;
const NAMESPACE_KEY_INFO: &[u8] = b"arkret-file-transfer-account-data-key-v1";
const RECORD_WRAP_KEY_INFO: &[u8] = b"arkret-file-transfer-record-wrap-v1";

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
pub struct FileTransferRecipientDevice {
    pub actor_id: String,
    pub device_id: String,
    pub hpke_public_key: String,
}

#[derive(Clone, Debug)]
pub struct FileTransferDeviceBoundUploadResult {
    pub item: FileTransferItem,
    pub server_response: Value,
    pub device_message_responses: Vec<cokret_sdk::DeviceMessagesSendOutcome>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileTransferDeviceKeyDispatch {
    pub target_actor_id: String,
    pub target_device_id: String,
    pub txn_id: String,
    pub kind: String,
    pub expires_at: String,
    pub content: Value,
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
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
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
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
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
    let prepared =
        prepare_actor_private_file(crypto, actor_id, device_id, filename, media_type, plaintext)?;
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
    let outcome =
        crate::account_api::set_account_data(&api.event_submitter()?, &account_data_key, envelope)
            .await?;
    let server_response = match outcome {
        AccountDataSetResult::Stored { response } => response,
        AccountDataSetResult::Unsupported { status } => {
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

pub async fn upload_device_bound_file(
    api: &CokretApi,
    crypto: &FileTransferCryptoContext,
    actor_id: &str,
    device_id: &str,
    filename: Option<&str>,
    media_type: &str,
    recipient_devices: Vec<FileTransferRecipientDevice>,
    plaintext: Vec<u8>,
) -> anyhow::Result<FileTransferDeviceBoundUploadResult> {
    let prepared =
        prepare_actor_private_file(crypto, actor_id, device_id, filename, media_type, plaintext)?;
    let account_data_key = prepared.account_data_key.clone();
    let upload = api
        .upload_file_transfer_ciphertext_auto(prepared.ciphertext.clone(), &prepared.content_digest)
        .await?;
    let uploaded_digest = upload.content_digest.to_string();
    if uploaded_digest != prepared.content_digest {
        anyhow::bail!("file-transfer blob upload digest mismatch");
    }
    let blob_ref = upload.blob_ref.to_string();
    verify_content_addressed_blob_ref(&blob_ref, &prepared.content_digest)?;

    let (record, dispatches) = prepared.into_device_bound_record_and_messages(
        blob_ref,
        upload.size_bytes,
        recipient_devices,
    )?;
    let derived_account_data_key = record_account_key(&record, crypto)?;
    if derived_account_data_key != account_data_key {
        anyhow::bail!("file-transfer account_data key derivation drift");
    }
    let envelope = seal_record_envelope(&record, crypto, &account_data_key, actor_id)?;
    let outcome =
        crate::account_api::set_account_data(&api.event_submitter()?, &account_data_key, envelope)
            .await?;
    let server_response = match outcome {
        AccountDataSetResult::Stored { response } => response,
        AccountDataSetResult::Unsupported { status } => {
            anyhow::bail!("ck.account_data.set unsupported for file transfer: {status}");
        }
    };

    let mut device_message_responses = Vec::with_capacity(dispatches.len());
    let http = api.sdk_http_client()?;
    for dispatch in dispatches {
        let response = crate::keys_api::send_device_message_envelope(
            &http,
            &dispatch.txn_id,
            &dispatch.target_actor_id,
            &dispatch.target_device_id,
            &dispatch.kind,
            &dispatch.expires_at,
            dispatch.content,
        )
        .await?;
        device_message_responses.push(response);
    }

    Ok(FileTransferDeviceBoundUploadResult {
        item: FileTransferItem {
            account_data_key,
            record,
            updated_at: None,
        },
        server_response,
        device_message_responses,
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
    let content_key_value = match &record.encryption.key_delivery {
        FileTransferKeyDelivery::AccountDataWrappedKey { content_key } => content_key,
        FileTransferKeyDelivery::ToDeviceWrappedKey { .. } => {
            anyhow::bail!("file-transfer device_bound requires a to-device key message");
        }
    };
    let content_key = decode_fixed::<CONTENT_KEY_LEN>(content_key_value)?;
    decrypt_file_transfer_ciphertext_with_key(record, ciphertext, &content_key)
}

pub fn decrypt_file_transfer_ciphertext_with_device_key_message(
    record: &FileTransferRecord,
    ciphertext: &[u8],
    key_message: &Value,
    recipient_private_key: &[u8],
    recipient_actor_id: &str,
    recipient_device_id: &str,
) -> anyhow::Result<Vec<u8>> {
    validate_ciphertext_blob_binding(record, ciphertext)?;
    let content_key = open_file_transfer_device_key_message(
        record,
        key_message,
        recipient_private_key,
        recipient_actor_id,
        recipient_device_id,
    )?;
    decrypt_file_transfer_ciphertext_with_key(record, ciphertext, &content_key)
}

pub fn try_decrypt_file_transfer_from_device_message(
    record: &FileTransferRecord,
    ciphertext: &[u8],
    envelope: &Value,
    recipient_private_key: &[u8],
    recipient_actor_id: &str,
    recipient_device_id: &str,
) -> anyhow::Result<Option<Vec<u8>>> {
    if envelope.get("kind").and_then(Value::as_str)
        != Some(cokret_sdk::FILE_TRANSFER_KEY_MESSAGE_KIND)
    {
        return Ok(None);
    }
    if envelope
        .get("recipient_device_id")
        .and_then(Value::as_str)
        .is_some_and(|value| value != recipient_device_id)
    {
        anyhow::bail!("file-transfer key envelope recipient_device_id mismatch");
    }
    let content = envelope
        .get("content")
        .ok_or_else(|| anyhow::anyhow!("file-transfer key envelope missing content"))?;
    decrypt_file_transfer_ciphertext_with_device_key_message(
        record,
        ciphertext,
        content,
        recipient_private_key,
        recipient_actor_id,
        recipient_device_id,
    )
    .map(Some)
}

fn decrypt_file_transfer_ciphertext_with_key(
    record: &FileTransferRecord,
    ciphertext: &[u8],
    content_key: &[u8; CONTENT_KEY_LEN],
) -> anyhow::Result<Vec<u8>> {
    let nonce = decode_fixed::<XCHACHA_NONCE_LEN>(&record.encryption.nonce)?;
    let aad_bytes = crate::canonical::canonical_json_bytes(&record.encryption.aad)?;
    let cipher = XChaCha20Poly1305::new(content_key.into());
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
    // Dedup: delegate to the shared yoface implementation, keeping the local
    // wrapper name so call sites stay unchanged.
    yoface::utils::format::format_bytes(bytes)
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
    let transfer_id = crate::random::base64url_token(24, "file-transfer transfer-id rng")?;
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
    let content_digest = crate::canonical::sha256_digest(&ciphertext);
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
        let record = FileTransferRecord {
            kind: FILE_TRANSFER_RECORD_KIND.to_owned(),
            transfer_id: self.transfer_id,
            blob_ref,
            content_digest: self.content_digest,
            blob_size_bytes,
            media_type: self.media_type,
            filename: self.filename,
            plaintext_size_bytes: self.plaintext_size_bytes,
            access: FileTransferAccess {
                visibility: FileTransferAccessVisibility::ActorPrivate,
                recipient_device_ids: Vec::new(),
            },
            encryption: FileTransferEncryption {
                scheme: FILE_TRANSFER_BLOB_SCHEME.to_owned(),
                aead_profile: FILE_TRANSFER_AEAD_PROFILE.to_owned(),
                nonce: URL_SAFE_NO_PAD.encode(self.nonce),
                aad: self.aad,
                key_delivery: FileTransferKeyDelivery::AccountDataWrappedKey {
                    content_key: URL_SAFE_NO_PAD.encode(self.content_key),
                },
            },
            origin_device_id: self.origin_device_id,
            created_at: self.created_at,
            updated_hlc: self.updated_hlc,
            retention_expires_at: self.retention_expires_at,
            state: FileTransferState::Available,
        };
        record
            .validate()
            .map_err(|error| anyhow::anyhow!("file-transfer record invalid: {error}"))?;
        Ok(record)
    }

    fn into_device_bound_record_and_messages(
        self,
        blob_ref: String,
        blob_size_bytes: u64,
        recipient_devices: Vec<FileTransferRecipientDevice>,
    ) -> anyhow::Result<(FileTransferRecord, Vec<FileTransferDeviceKeyDispatch>)> {
        if recipient_devices.is_empty() {
            anyhow::bail!("device_bound file-transfer requires recipient devices");
        }
        let mut seen_devices = std::collections::BTreeSet::new();
        let mut recipients = Vec::with_capacity(recipient_devices.len());
        for recipient in recipient_devices {
            let actor_id = recipient.actor_id.trim().to_owned();
            let device_id = recipient.device_id.trim().to_owned();
            cokret_sdk::Did::new(actor_id.clone()).map_err(|error| {
                anyhow::anyhow!("invalid file-transfer recipient actor: {error}")
            })?;
            cokret_sdk::DeviceId::new(device_id.clone()).map_err(|error| {
                anyhow::anyhow!("invalid file-transfer recipient device_id: {error}")
            })?;
            if !seen_devices.insert(device_id.clone()) {
                anyhow::bail!("device_bound file-transfer recipient_device_ids must be unique");
            }
            let hpke_public_key = recipient.hpke_public_key.trim().to_owned();
            if hpke_public_key.is_empty() {
                anyhow::bail!("device_bound file-transfer recipient HPKE key is required");
            }
            recipients.push(FileTransferRecipientDevice {
                actor_id,
                device_id,
                hpke_public_key,
            });
        }

        let nonce = URL_SAFE_NO_PAD.encode(self.nonce);
        let content_key = self.content_key;
        let record = FileTransferRecord {
            kind: FILE_TRANSFER_RECORD_KIND.to_owned(),
            transfer_id: self.transfer_id,
            blob_ref,
            content_digest: self.content_digest,
            blob_size_bytes,
            media_type: self.media_type,
            filename: self.filename,
            plaintext_size_bytes: self.plaintext_size_bytes,
            access: FileTransferAccess {
                visibility: FileTransferAccessVisibility::DeviceBound,
                recipient_device_ids: recipients
                    .iter()
                    .map(|recipient| recipient.device_id.clone())
                    .collect(),
            },
            encryption: FileTransferEncryption {
                scheme: FILE_TRANSFER_BLOB_SCHEME.to_owned(),
                aead_profile: FILE_TRANSFER_AEAD_PROFILE.to_owned(),
                nonce,
                aad: self.aad,
                key_delivery: FileTransferKeyDelivery::ToDeviceWrappedKey {
                    key_message_kind: cokret_sdk::FILE_TRANSFER_KEY_MESSAGE_KIND.to_owned(),
                },
            },
            origin_device_id: self.origin_device_id,
            created_at: self.created_at,
            updated_hlc: self.updated_hlc,
            retention_expires_at: self.retention_expires_at,
            state: FileTransferState::Available,
        };
        record
            .validate()
            .map_err(|error| anyhow::anyhow!("file-transfer record invalid: {error}"))?;

        let expires_at = (chrono::Utc::now() + chrono::Duration::hours(24))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let mut dispatches = Vec::with_capacity(recipients.len());
        for recipient in &recipients {
            dispatches.push(build_file_transfer_device_key_dispatch(
                &record,
                &content_key,
                recipient,
                &expires_at,
            )?);
        }
        Ok((record, dispatches))
    }
}

fn build_file_transfer_device_key_dispatch(
    record: &FileTransferRecord,
    content_key: &[u8; CONTENT_KEY_LEN],
    recipient: &FileTransferRecipientDevice,
    expires_at: &str,
) -> anyhow::Result<FileTransferDeviceKeyDispatch> {
    if !record
        .access
        .recipient_device_ids
        .iter()
        .any(|device_id| device_id == &recipient.device_id)
    {
        anyhow::bail!("file-transfer recipient device is not in recipient_device_ids");
    }
    let recipient_public_key = URL_SAFE_NO_PAD
        .decode(recipient.hpke_public_key.as_bytes())
        .map_err(|error| anyhow::anyhow!("file-transfer recipient HPKE public key: {error}"))?;
    let aad = file_transfer_key_message_aad(
        record,
        recipient.actor_id.as_str(),
        recipient.device_id.as_str(),
        expires_at,
    )?;
    let sealed = crate::hpke_backup::hpke_seal(
        &recipient_public_key,
        FILE_TRANSFER_KEY_HPKE_INFO,
        &aad,
        content_key,
    )?;
    let key_message = FileTransferKeyMessage {
        transfer_id: record.transfer_id.clone(),
        blob_ref: record.blob_ref.clone(),
        aead_profile: record.encryption.aead_profile.clone(),
        nonce: record.encryption.nonce.clone(),
        content_digest: record.content_digest.clone(),
        key_envelope: FileTransferKeyEnvelope {
            scheme: cokret_sdk::FILE_TRANSFER_KEY_ENVELOPE_SCHEME.to_owned(),
            enc: URL_SAFE_NO_PAD.encode(sealed.enc),
            ciphertext: URL_SAFE_NO_PAD.encode(sealed.ciphertext),
            aad_digest: crate::canonical::sha256_digest(&aad),
        },
        expires_at: expires_at.to_owned(),
    };
    key_message
        .validate_record_binding(record)
        .map_err(|error| anyhow::anyhow!("file-transfer key message invalid: {error}"))?;
    let content = serde_json::to_value(key_message)
        .map_err(|error| anyhow::anyhow!("file-transfer key message JSON: {error}"))?;
    Ok(FileTransferDeviceKeyDispatch {
        target_actor_id: recipient.actor_id.clone(),
        target_device_id: recipient.device_id.clone(),
        txn_id: file_transfer_device_key_txn_id(
            &record.transfer_id,
            &recipient.actor_id,
            &recipient.device_id,
        ),
        kind: cokret_sdk::FILE_TRANSFER_KEY_MESSAGE_KIND.to_owned(),
        expires_at: expires_at.to_owned(),
        content,
    })
}

fn open_file_transfer_device_key_message(
    record: &FileTransferRecord,
    key_message: &Value,
    recipient_private_key: &[u8],
    recipient_actor_id: &str,
    recipient_device_id: &str,
) -> anyhow::Result<[u8; CONTENT_KEY_LEN]> {
    let key_message: FileTransferKeyMessage = serde_json::from_value(key_message.clone())
        .map_err(|error| anyhow::anyhow!("file-transfer key message decode failed: {error}"))?;
    key_message
        .validate_record_binding(record)
        .map_err(|error| anyhow::anyhow!("file-transfer key message binding failed: {error}"))?;
    let recipient_actor_id = recipient_actor_id.trim();
    let recipient_device_id = recipient_device_id.trim();
    cokret_sdk::Did::new(recipient_actor_id.to_owned())
        .map_err(|error| anyhow::anyhow!("invalid file-transfer recipient actor: {error}"))?;
    cokret_sdk::DeviceId::new(recipient_device_id.to_owned())
        .map_err(|error| anyhow::anyhow!("invalid file-transfer recipient device_id: {error}"))?;
    if !record
        .access
        .recipient_device_ids
        .iter()
        .any(|device_id| device_id == recipient_device_id)
    {
        anyhow::bail!("file-transfer key message recipient device is not authorized");
    }

    let aad = file_transfer_key_message_aad(
        record,
        recipient_actor_id,
        recipient_device_id,
        key_message.expires_at.as_str(),
    )?;
    if key_message.key_envelope.aad_digest != crate::canonical::sha256_digest(&aad) {
        anyhow::bail!("file-transfer key envelope aad_digest mismatch");
    }
    let enc = URL_SAFE_NO_PAD
        .decode(key_message.key_envelope.enc.as_bytes())
        .map_err(|error| anyhow::anyhow!("file-transfer key envelope enc: {error}"))?;
    let sealed_key = URL_SAFE_NO_PAD
        .decode(key_message.key_envelope.ciphertext.as_bytes())
        .map_err(|error| anyhow::anyhow!("file-transfer key envelope ciphertext: {error}"))?;
    let opened = crate::hpke_backup::hpke_open(
        recipient_private_key,
        &enc,
        FILE_TRANSFER_KEY_HPKE_INFO,
        &aad,
        &sealed_key,
    )?;
    if opened.len() != CONTENT_KEY_LEN {
        anyhow::bail!("file-transfer opened content key length mismatch");
    }
    let mut content_key = [0u8; CONTENT_KEY_LEN];
    content_key.copy_from_slice(&opened);
    Ok(content_key)
}

fn file_transfer_key_message_aad(
    record: &FileTransferRecord,
    recipient_actor_id: &str,
    recipient_device_id: &str,
    expires_at: &str,
) -> anyhow::Result<Vec<u8>> {
    let aad = json!({
        "kind": cokret_sdk::FILE_TRANSFER_KEY_MESSAGE_KIND,
        "transfer_id": record.transfer_id.as_str(),
        "blob_ref": record.blob_ref.as_str(),
        "aead_profile": record.encryption.aead_profile.as_str(),
        "nonce": record.encryption.nonce.as_str(),
        "content_digest": record.content_digest.as_str(),
        "recipient_actor_id": recipient_actor_id,
        "recipient_device_id": recipient_device_id,
        "expires_at": expires_at,
    });
    crate::canonical::canonical_json_bytes(&aad)
}

fn file_transfer_device_key_txn_id(
    transfer_id: &str,
    recipient_actor_id: &str,
    recipient_device_id: &str,
) -> String {
    let digest_hex = cokret_sdk::canonical::sha256_hex(
        format!("{transfer_id}\n{recipient_actor_id}\n{recipient_device_id}").as_bytes(),
    );
    format!("file-transfer-key-{transfer_id}-{}", &digest_hex[..16])
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
    let record: FileTransferRecord = serde_json::from_slice(&plaintext)
        .map_err(|error| anyhow::anyhow!("file-transfer record JSON decode failed: {error}"))?;
    record
        .validate()
        .map_err(|error| anyhow::anyhow!("file-transfer record validation failed: {error}"))?;
    Ok(record)
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
    validate_ciphertext_blob_binding(record, ciphertext)?;
    if !matches!(
        &record.encryption.key_delivery,
        FileTransferKeyDelivery::AccountDataWrappedKey { .. }
    ) {
        anyhow::bail!("file-transfer key delivery method unsupported");
    }
    if record.access.visibility != FileTransferAccessVisibility::ActorPrivate {
        anyhow::bail!("file-transfer access visibility unsupported");
    }
    Ok(())
}

fn validate_ciphertext_blob_binding(
    record: &FileTransferRecord,
    ciphertext: &[u8],
) -> anyhow::Result<()> {
    record
        .validate()
        .map_err(|error| anyhow::anyhow!("file-transfer record invalid: {error}"))?;
    let digest = crate::canonical::sha256_digest(ciphertext);
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
    let expected = format!("ak:blob:sha256:{hex}");
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
    const DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000001";
    const RECIPIENT_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000002";
    const OTHER_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000003";

    fn device_bound_fixture() -> (FileTransferRecord, Vec<u8>, Vec<u8>, Value) {
        let crypto = FileTransferCryptoContext::from_account_secret("test-account-secret").unwrap();
        let prepared = prepare_actor_private_file(
            &crypto,
            ACTOR,
            DEVICE,
            Some("vault.txt"),
            "text/plain",
            b"device-only".to_vec(),
        )
        .unwrap();
        let ciphertext = prepared.ciphertext.clone();
        let blob_ref = format!(
            "ak:blob:sha256:{}",
            prepared.content_digest.trim_start_matches("sha256:")
        );
        let (recipient_sk, recipient_pk) = crate::hpke_backup::generate_recovery_keypair().unwrap();
        let (record, dispatches) = prepared
            .into_device_bound_record_and_messages(
                blob_ref,
                ciphertext.len() as u64,
                vec![FileTransferRecipientDevice {
                    actor_id: ACTOR.to_owned(),
                    device_id: RECIPIENT_DEVICE.to_owned(),
                    hpke_public_key: URL_SAFE_NO_PAD.encode(recipient_pk),
                }],
            )
            .unwrap();
        assert_eq!(dispatches.len(), 1);
        assert_eq!(
            dispatches[0].kind,
            cokret_sdk::FILE_TRANSFER_KEY_MESSAGE_KIND
        );
        (
            record,
            ciphertext,
            recipient_sk,
            dispatches[0].content.clone(),
        )
    }

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
            "ak:blob:sha256:{}",
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
    fn device_bound_file_round_trips_through_to_device_key_message() {
        let (record, ciphertext, recipient_sk, key_message) = device_bound_fixture();

        assert_eq!(
            record.access.visibility,
            FileTransferAccessVisibility::DeviceBound
        );
        assert_eq!(
            record.access.recipient_device_ids,
            vec![RECIPIENT_DEVICE.to_owned()]
        );
        assert!(decrypt_file_transfer_ciphertext(&record, &ciphertext).is_err());

        let plaintext = decrypt_file_transfer_ciphertext_with_device_key_message(
            &record,
            &ciphertext,
            &key_message,
            &recipient_sk,
            ACTOR,
            RECIPIENT_DEVICE,
        )
        .unwrap();
        assert_eq!(plaintext, b"device-only");
    }

    #[test]
    fn device_bound_file_opens_from_to_device_inbox_envelope() {
        let (record, ciphertext, recipient_sk, key_message) = device_bound_fixture();
        let envelope = json!({
            "kind": cokret_sdk::FILE_TRANSFER_KEY_MESSAGE_KIND,
            "recipient_device_id": RECIPIENT_DEVICE,
            "content": key_message,
        });

        let plaintext = try_decrypt_file_transfer_from_device_message(
            &record,
            &ciphertext,
            &envelope,
            &recipient_sk,
            ACTOR,
            RECIPIENT_DEVICE,
        )
        .unwrap()
        .unwrap();
        assert_eq!(plaintext, b"device-only");

        assert!(
            try_decrypt_file_transfer_from_device_message(
                &record,
                &ciphertext,
                &json!({"kind": "ck.key.verification.request"}),
                &recipient_sk,
                ACTOR,
                RECIPIENT_DEVICE,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn device_bound_key_message_drift_fails_closed() {
        let (record, ciphertext, recipient_sk, mut key_message) = device_bound_fixture();
        key_message["nonce"] = Value::String("different_nonce".to_owned());

        assert!(
            decrypt_file_transfer_ciphertext_with_device_key_message(
                &record,
                &ciphertext,
                &key_message,
                &recipient_sk,
                ACTOR,
                RECIPIENT_DEVICE,
            )
            .is_err()
        );
    }

    #[test]
    fn device_bound_unlisted_device_fails_closed() {
        let (record, ciphertext, recipient_sk, key_message) = device_bound_fixture();

        assert!(
            decrypt_file_transfer_ciphertext_with_device_key_message(
                &record,
                &ciphertext,
                &key_message,
                &recipient_sk,
                ACTOR,
                OTHER_DEVICE,
            )
            .is_err()
        );
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
            "ak:blob:sha256:{}",
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
        assert!(
            prepared
                .into_record(
                    "ak:blob:sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_owned(),
                    ciphertext.len() as u64,
                )
                .is_err()
        );
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
            "ak:blob:sha256:{}",
            prepared.content_digest.trim_start_matches("sha256:")
        );
        let mut record = prepared
            .into_record(blob_ref, ciphertext.len() as u64)
            .unwrap();
        record.transfer_id = "0123456789abcdef012345".to_owned();

        assert!(decrypt_file_transfer_ciphertext(&record, &ciphertext).is_err());
    }
}
