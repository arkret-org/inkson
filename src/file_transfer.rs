//! Principal-private file transfer support (`ak.profile.file_transfer.v1`).
//!
//! The feature is intentionally account-scoped: encrypted blob bytes live in
//! the blob service, while the transfer record is sealed before being written
//! as private account-data under `ak.file_transfer.v1:<transfer_key>`.

pub use arkret_sdk::{
    FileTransferAad, FileTransferAccess, FileTransferAccessVisibility, FileTransferEncryption,
    FileTransferKeyDelivery, FileTransferKeyEnvelope, FileTransferKeyMessage, FileTransferRecord,
    FileTransferStatus,
};
use arkret_wire::{AEAD_PROFILE_XCHACHA20_POLY1305_V1, SchemaId};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::Serialize;
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use sha2::Sha256;

use crate::transport::TransportClient;

pub const FILE_TRANSFER_PURPOSE: &str = "file_transfer";
pub const FILE_TRANSFER_RECORD_KIND: &str = "file_transfer";
pub const FILE_TRANSFER_RECORD_ENVELOPE_SCHEME: &str =
    "org.arkret.inkson.file_transfer.account_data_envelope.v1";
pub const FILE_TRANSFER_BLOB_SCHEME: &str = arkret_sdk::BLOB_SCHEME_WHOLE_FILE_AEAD_V1;
pub const FILE_TRANSFER_RETENTION_DAYS: i64 = 7;
pub const FILE_TRANSFER_KEY_HPKE_INFO: &[u8] = b"arkret-file-transfer-key-hpke-x25519-v1";

const CONTENT_KEY_LEN: usize = 32;
const XCHACHA_NONCE_LEN: usize = 24;
const NAMESPACE_KEY_INFO: &[u8] = b"arkret-file-transfer-account-data-key-v1";
const RECORD_WRAP_KEY_INFO: &[u8] = b"arkret-file-transfer-record-wrap-v1";

#[derive(Serialize)]
struct FileTransferRecordAad<'a> {
    schema: &'static str,
    purpose: &'static str,
    transfer_key: &'a str,
    actor_id: &'a str,
}

#[derive(Serialize)]
struct FileTransferRecordEnvelope<'a> {
    scheme: &'static str,
    aead_profile: &'static str,
    nonce: String,
    aad: FileTransferRecordAad<'a>,
    ciphertext: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileTransferCryptoContext {
    account_data_secret: [u8; CONTENT_KEY_LEN],
    namespace_key: [u8; CONTENT_KEY_LEN],
    record_wrap_key: [u8; CONTENT_KEY_LEN],
}

impl FileTransferCryptoContext {
    pub fn from_account_secret(account_secret: &str) -> anyhow::Result<Self> {
        let account_data_secret = decode_fixed::<CONTENT_KEY_LEN>(account_secret.trim())
            .map_err(|error| anyhow::anyhow!("account secret: {error}"))?;
        Ok(Self {
            account_data_secret,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileTransferDeviceKeyDispatch {
    pub target_actor_id: String,
    pub target_device_id: String,
    pub txn_id: String,
    pub expires_at: String,
    pub content: FileTransferKeyMessage,
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
    authority: &arkret_sdk::PrincipalAuthorityKey,
) -> anyhow::Result<FileTransferCryptoContext> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let account_secret =
        crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), authority)
            .map_err(|error| anyhow::anyhow!("account MLS secret unavailable: {error}"))?
            .ok_or_else(|| anyhow::anyhow!("account MLS secret recovery is required"))?;
    FileTransferCryptoContext::from_account_secret(&account_secret.secret)
}

pub fn load_file_transfer_crypto_context(
    authority: &arkret_sdk::PrincipalAuthorityKey,
) -> anyhow::Result<Option<FileTransferCryptoContext>> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let Some(account_secret) =
        crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), authority)
            .map_err(|error| anyhow::anyhow!("account MLS secret unavailable: {error}"))?
    else {
        return Ok(None);
    };
    FileTransferCryptoContext::from_account_secret(&account_secret.secret).map(Some)
}

pub async fn upload_actor_private_file(
    api: &TransportClient,
    crypto: &FileTransferCryptoContext,
    actor_id: &str,
    device_id: &str,
    filename: Option<&str>,
    media_type: &str,
    plaintext: Vec<u8>,
) -> anyhow::Result<FileTransferUploadResult> {
    let http = api.sdk_http_client()?;
    let actor = arkret_sdk::DidFullId::new(actor_id.trim().to_owned())?;
    let principal_control_realm_id =
        crate::identity::principal_control::resolve_accepted(&http, &actor).await?;
    let prepared = prepare_actor_private_file(
        crypto,
        &principal_control_realm_id,
        actor_id,
        device_id,
        filename,
        media_type,
        plaintext,
    )?;
    let account_data_key = prepared.account_data_key.clone();
    // Auto-dispatch: large ciphertexts take the resumable (tus) binding
    // when the server advertises it in /_arkret/describe, with automatic
    // fallback to the canonical single-shot upload. Outcome shape and
    // blob_ref are identical either way (media-and-blob.md §2.1).
    let clients = crate::transport::EndpointClients::from_http(api.sdk_http_client()?);
    let upload = clients
        .blob()
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
    let (item, server_response) = store_file_transfer_record(
        &api.event_submitter()?,
        &account_data_key,
        &record,
        crypto,
        actor_id,
    )
    .await?;
    Ok(FileTransferUploadResult {
        item,
        server_response,
    })
}

async fn store_file_transfer_record(
    submitter: &crate::event_submit::EventSubmitter,
    account_data_key: &str,
    candidate: &FileTransferRecord,
    crypto: &FileTransferCryptoContext,
    actor_id: &str,
) -> anyhow::Result<(FileTransferItem, Value)> {
    let candidate_envelope = seal_record_envelope(candidate, crypto, account_data_key, actor_id)?;
    let response = crate::transport::account::update_account_data_with_merge(
        submitter,
        account_data_key,
        |snapshot| {
            merge_file_transfer_account_data(
                snapshot.entry.as_ref(),
                candidate,
                &candidate_envelope,
                crypto,
            )
        },
    )
    .await?;
    let item = file_transfer_item_from_account_data(&response, crypto)?;
    Ok((item, response))
}

fn merge_file_transfer_account_data(
    current: Option<&arkret_sdk::AccountDataRow>,
    candidate: &FileTransferRecord,
    candidate_envelope: &Value,
    crypto: &FileTransferCryptoContext,
) -> anyhow::Result<Value> {
    let Some(current) = current else {
        return Ok(candidate_envelope.clone());
    };
    let current_value = serde_json::to_value(current)?;
    let current_item = file_transfer_item_from_account_data(&current_value, crypto)?;
    if current_item.record.status == FileTransferStatus::Deleted {
        anyhow::bail!("file-transfer transfer_key is terminal deleted; create a new transfer_id");
    }
    if current_item.record.updated_hlc >= candidate.updated_hlc {
        Ok(current.content.clone())
    } else {
        Ok(candidate_envelope.clone())
    }
}

pub async fn decrypt_file_transfer_item(
    api: &TransportClient,
    item: &FileTransferItem,
) -> anyhow::Result<Vec<u8>> {
    let clients = crate::transport::EndpointClients::from_http(api.sdk_http_client()?);
    let ciphertext = clients
        .blob()
        .get_file_transfer_bytes(&item.record.blob_ref)
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
        .filter(|item| item.record.status != FileTransferStatus::Deleted)
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
    principal_control_realm_id: &arkret_sdk::RealmId,
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
    let actor = arkret_sdk::DidFullId::new(actor_id.trim().to_owned())?;
    let updated_hlc = crate::signing_stamp::issue_protocol_hlc(
        actor.as_str(),
        device_id.trim(),
        principal_control_realm_id.as_str(),
    )?;
    let transfer_id = crate::random::base64url_token(24, "file-transfer transfer-id rng")?;
    let account_data_key =
        crate::account_data::file_transfer_account_data_key(crypto.namespace_key(), &transfer_id)?;
    let mut content_key = [0u8; CONTENT_KEY_LEN];
    getrandom::fill(&mut content_key)
        .map_err(|error| anyhow::anyhow!("file-transfer content-key rng: {error}"))?;
    let mut nonce = [0u8; XCHACHA_NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|error| anyhow::anyhow!("file-transfer nonce rng: {error}"))?;

    let created_at = arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now());
    let retention_expires_at = arkret_sdk::canonical::format_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::days(FILE_TRANSFER_RETENTION_DAYS),
    );
    let aad = FileTransferAad {
        schema: SchemaId::FILE_TRANSFER_V1.to_owned(),
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
        updated_hlc: updated_hlc.to_string(),
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
                aead_profile: AEAD_PROFILE_XCHACHA20_POLY1305_V1.to_owned(),
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
            status: FileTransferStatus::Available,
        };
        record
            .validate()
            .map_err(|error| anyhow::anyhow!("file-transfer record invalid: {error}"))?;
        Ok(record)
    }
}

fn file_transfer_item_from_account_data(
    entry: &Value,
    crypto: &FileTransferCryptoContext,
) -> anyhow::Result<FileTransferItem> {
    let account_data_key = entry
        .get("account_data_key")
        .or_else(|| entry.get("type"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("account_data entry missing account_data_key"))?;
    if !account_data_key
        .strip_prefix(arkret_sdk::AccountDataKey::FILE_TRANSFER_V1)
        .is_some_and(|rest| rest.starts_with(':'))
    {
        anyhow::bail!("not a file-transfer account_data entry");
    }
    crate::account_data::validate_private_account_data_key(account_data_key)?;
    let content = entry
        .get("content")
        .or_else(|| entry.get("encrypted_payload"))
        .ok_or_else(|| anyhow::anyhow!("file-transfer account_data content missing"))?;
    let record = open_record_envelope(content, crypto, account_data_key)?;
    if record.kind != FILE_TRANSFER_RECORD_KIND {
        anyhow::bail!("file-transfer record kind mismatch");
    }
    let derived_key = record_account_key(&record, crypto)?;
    if derived_key != account_data_key {
        anyhow::bail!("file-transfer account_data key mismatch");
    }
    Ok(FileTransferItem {
        account_data_key: account_data_key.to_owned(),
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
    let aad = FileTransferRecordAad {
        schema: SchemaId::FILE_TRANSFER_V1,
        purpose: "file_transfer_record",
        transfer_key: account_data_key,
        actor_id,
    };
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
    let inner_envelope = serde_json::to_value(FileTransferRecordEnvelope {
        scheme: FILE_TRANSFER_RECORD_ENVELOPE_SCHEME,
        aead_profile: AEAD_PROFILE_XCHACHA20_POLY1305_V1,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        aad,
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })?;
    let actor_core_id = crate::mls_api_helpers::principal_core_id(actor_id)?;
    let envelope = arkret_sdk::account_data_crypto::seal_account_data_value(
        &crypto.account_data_secret,
        &actor_core_id,
        account_data_key,
        &inner_envelope,
    )?;
    serde_json::to_value(envelope)
        .map_err(|error| anyhow::anyhow!("file-transfer account-data envelope JSON: {error}"))
}

fn open_record_envelope(
    envelope: &Value,
    crypto: &FileTransferCryptoContext,
    account_data_key: &str,
) -> anyhow::Result<FileTransferRecord> {
    let outer: arkret_sdk::account_data_crypto::AccountDataEncryptedValue =
        serde_json::from_value(envelope.clone()).map_err(|error| {
            anyhow::anyhow!("file-transfer account-data outer envelope: {error}")
        })?;
    let actor_id = outer.aad.actor_id.clone();
    let envelope = arkret_sdk::account_data_crypto::open_account_data_value(
        &crypto.account_data_secret,
        &actor_id,
        account_data_key,
        &outer,
    )?;
    if envelope.get("scheme").and_then(Value::as_str) != Some(FILE_TRANSFER_RECORD_ENVELOPE_SCHEME)
    {
        anyhow::bail!("file-transfer account-data envelope scheme mismatch");
    }
    if envelope.get("aead_profile").and_then(Value::as_str)
        != Some(AEAD_PROFILE_XCHACHA20_POLY1305_V1)
    {
        anyhow::bail!("file-transfer account-data envelope AEAD mismatch");
    }
    let nonce = decode_fixed::<XCHACHA_NONCE_LEN>(required_str(&envelope, "nonce")?)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(required_str(&envelope, "ciphertext")?)
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
    if aad.get("schema").and_then(Value::as_str) != Some(SchemaId::FILE_TRANSFER_V1) {
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
    if record.encryption.aead_profile != AEAD_PROFILE_XCHACHA20_POLY1305_V1 {
        anyhow::bail!("file-transfer AEAD profile mismatch");
    }
    validate_content_aad(record)?;
    Ok(())
}

fn validate_content_aad(record: &FileTransferRecord) -> anyhow::Result<()> {
    let aad = &record.encryption.aad;
    if aad.schema != SchemaId::FILE_TRANSFER_V1 {
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

    fn test_pcr() -> arkret_sdk::RealmId {
        arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned())
            .unwrap()
    }

    fn test_account_secret() -> String {
        URL_SAFE_NO_PAD.encode([7u8; 32])
    }

    #[test]
    fn file_transfer_cas_merge_uses_hlc_and_preserves_terminal_delete() {
        let crypto =
            FileTransferCryptoContext::from_account_secret(&test_account_secret()).unwrap();
        let prepared = prepare_actor_private_file(
            &crypto,
            &test_pcr(),
            ACTOR,
            DEVICE,
            Some("merge.txt"),
            "text/plain",
            b"merge".to_vec(),
        )
        .unwrap();
        let blob_ref = format!(
            "ak:blob:sha256:{}",
            prepared.content_digest.trim_start_matches("sha256:")
        );
        let mut candidate = prepared
            .into_record(blob_ref, b"merge".len() as u64)
            .unwrap();
        candidate.updated_hlc = "019041000000-0002-deadbeef".to_owned();
        let account_data_key = record_account_key(&candidate, &crypto).unwrap();
        let candidate_envelope =
            seal_record_envelope(&candidate, &crypto, &account_data_key, ACTOR).unwrap();

        let mut current = candidate.clone();
        current.updated_hlc = "019041000000-0001-deadbeef".to_owned();
        let current_envelope =
            seal_record_envelope(&current, &crypto, &account_data_key, ACTOR).unwrap();
        let mut current_row = arkret_sdk::AccountDataRow {
            account_data_key: account_data_key.clone(),
            revision: 3,
            content: current_envelope,
            updated_at: chrono::Utc::now(),
        };
        assert_eq!(
            merge_file_transfer_account_data(
                Some(&current_row),
                &candidate,
                &candidate_envelope,
                &crypto,
            )
            .unwrap(),
            candidate_envelope
        );

        current.status = FileTransferStatus::Deleted;
        current_row.content =
            seal_record_envelope(&current, &crypto, &account_data_key, ACTOR).unwrap();
        assert!(
            merge_file_transfer_account_data(
                Some(&current_row),
                &candidate,
                &candidate_envelope,
                &crypto,
            )
            .is_err()
        );
    }

    #[test]
    fn prepared_file_round_trips_through_record_envelope_and_content_aead() {
        let crypto =
            FileTransferCryptoContext::from_account_secret(&test_account_secret()).unwrap();
        let prepared = prepare_actor_private_file(
            &crypto,
            &test_pcr(),
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
            "account_data_key": key,
            "content": envelope,
            "updated_at": "2026-06-07T00:00:00.000Z",
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
        let crypto =
            FileTransferCryptoContext::from_account_secret(&test_account_secret()).unwrap();
        let prepared = prepare_actor_private_file(
            &crypto,
            &test_pcr(),
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
            "account_data_key": wrong_key,
            "content": envelope,
        });

        let items = file_transfer_items_from_account_data(&[entry], &crypto);
        assert!(items.is_empty());
    }

    #[test]
    fn digest_or_blob_ref_drift_fails_closed() {
        let crypto =
            FileTransferCryptoContext::from_account_secret(&test_account_secret()).unwrap();
        let prepared = prepare_actor_private_file(
            &crypto,
            &test_pcr(),
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
        let crypto =
            FileTransferCryptoContext::from_account_secret(&test_account_secret()).unwrap();
        let prepared = prepare_actor_private_file(
            &crypto,
            &test_pcr(),
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
