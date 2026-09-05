//! Principal-private file transfer support (`ak.profile.file_transfer.v1`).
//!
//! The feature is intentionally account-scoped: encrypted blob bytes live in
//! the blob service, while the transfer record is sealed before being written
//! as private account-data under `ak.file_transfer.v1:<transfer_key>`.

use anyhow::Context as _;
pub use arkret_sdk::{
    FileTransferAad, FileTransferAccess, FileTransferAccessVisibility, FileTransferEncryption,
    FileTransferKeyDelivery, FileTransferKeyEnvelope, FileTransferRecord, FileTransferStatus,
};
use arkret_wire::{AEAD_PROFILE_XCHACHA20_POLY1305_V1, SchemaId};
use base64::Engine as _;
#[cfg(target_arch = "wasm32")]
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::StreamExt as _;
use hkdf::Hkdf;
#[cfg(target_arch = "wasm32")]
use serde::Deserialize;
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::transport::TransportClient;

pub const FILE_TRANSFER_PURPOSE: &str = "file_transfer";
pub const FILE_TRANSFER_RECORD_KIND: &str = "file_transfer";
pub const FILE_TRANSFER_BLOB_SCHEME: &str = arkret_sdk::BLOB_SCHEME_WHOLE_FILE_AEAD_V1;
pub const FILE_TRANSFER_RETENTION_DAYS: i64 = 7;

const CONTENT_KEY_LEN: usize = 32;
const XCHACHA_NONCE_LEN: usize = 24;
const NAMESPACE_KEY_INFO: &[u8] = b"arkret-file-transfer-account-data-key-v1";
const MAX_WHOLE_FILE_DOWNLOAD_BYTES: u64 = 262_144 + 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileTransferCryptoContext {
    actor_id: arkret_sdk::ActorId,
    account_data_secret: [u8; CONTENT_KEY_LEN],
    namespace_key: [u8; CONTENT_KEY_LEN],
}

impl FileTransferCryptoContext {
    pub fn from_account_secret(
        authority: &arkret_sdk::AccountId,
        account_secret: &str,
    ) -> anyhow::Result<Self> {
        let account_data_secret = decode_fixed::<CONTENT_KEY_LEN>(account_secret.trim())
            .map_err(|error| anyhow::anyhow!("account secret: {error}"))?;
        Ok(Self {
            actor_id: arkret_sdk::ActorId::account(authority.clone()),
            account_data_secret,
            namespace_key: derive_account_subkey(account_secret, NAMESPACE_KEY_INFO)?,
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

/// User-selected transactional output for one file-transfer download.
///
/// Browser callers must create this directly in the click handler so the File
/// System Access picker retains transient user activation. No network request
/// or plaintext write occurs until [`save_file_transfer_item`] consumes it.
pub struct FileTransferSaveRequest {
    #[cfg(not(target_arch = "wasm32"))]
    filename: String,
    #[cfg(target_arch = "wasm32")]
    eval: Option<dioxus::document::Eval>,
}

#[cfg(target_arch = "wasm32")]
impl Drop for FileTransferSaveRequest {
    fn drop(&mut self) {
        if let Some(eval) = self.eval.take() {
            let _ = eval.send(serde_json::json!({"kind": "abort"}));
        }
    }
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
    encryption: FileTransferEncryption,
    origin_device_id: String,
    created_at: String,
    updated_hlc: String,
    retention_expires_at: String,
}

pub fn load_or_create_file_transfer_crypto_context(
    authority: &arkret_sdk::AccountId,
) -> anyhow::Result<FileTransferCryptoContext> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let account_secret =
        crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), authority)
            .map_err(|error| anyhow::anyhow!("account MLS secret unavailable: {error}"))?
            .ok_or_else(|| anyhow::anyhow!("account MLS secret recovery is required"))?;
    FileTransferCryptoContext::from_account_secret(authority, &account_secret.secret)
}

pub fn load_file_transfer_crypto_context(
    authority: &arkret_sdk::AccountId,
) -> anyhow::Result<Option<FileTransferCryptoContext>> {
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let Some(account_secret) =
        crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), authority)
            .map_err(|error| anyhow::anyhow!("account MLS secret unavailable: {error}"))?
    else {
        return Ok(None);
    };
    FileTransferCryptoContext::from_account_secret(authority, &account_secret.secret).map(Some)
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
    let actor = crate::mls_api_helpers::principal_core_id(actor_id)?;
    let principal_control_realm_id =
        crate::identity::principal_control::resolve_accepted(&http, &actor).await?;
    let mut prepared = prepare_actor_private_file(
        crypto,
        &principal_control_realm_id,
        actor_id,
        device_id,
        filename,
        media_type,
        plaintext,
    )?;
    let account_data_key = prepared.account_data_key.clone();
    let ciphertext_len = prepared.ciphertext.len();
    let content_digest = prepared.content_digest.clone();
    let ciphertext = std::mem::take(&mut prepared.ciphertext);
    // Auto-dispatch: large ciphertexts take the resumable (tus) binding
    // when the server advertises it in /_arkret/describe, with automatic
    // fallback to the canonical single-shot upload. Outcome shape and
    // blob_ref are identical either way (media-and-blob.md §2.1).
    let clients = crate::transport::EndpointClients::from_http(api.sdk_http_client()?);
    let upload = clients
        .blob()
        .upload_file_transfer_ciphertext_auto(
            ciphertext,
            &content_digest,
            principal_control_realm_id.as_str(),
        )
        .await?;
    if upload.size_bytes != ciphertext_len as u64 {
        anyhow::bail!("file-transfer blob upload size mismatch");
    }
    // `into_record` re-derives the content-addressed binding, so the upload
    // outcome only has to agree on the byte count here.
    let record = prepared.into_record(upload.blob_ref.to_string(), upload.size_bytes)?;
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

pub fn begin_file_transfer_save(
    item: &FileTransferItem,
) -> anyhow::Result<FileTransferSaveRequest> {
    let filename = display_filename(&item.record);
    #[cfg(not(target_arch = "wasm32"))]
    {
        Ok(FileTransferSaveRequest { filename })
    }
    #[cfg(target_arch = "wasm32")]
    {
        let filename = serde_json::to_string(&filename)?;
        let script = format!(
            r#"
            let writable = null;
            try {{
                if (typeof window.showSaveFilePicker !== "function") {{
                    dioxus.send({{ kind: "error", error: "streaming save is unavailable in this browser" }});
                    return;
                }}
                const handle = await window.showSaveFilePicker({{
                    suggestedName: {filename}
                }});
                writable = await handle.createWritable();
                dioxus.send({{ kind: "ready" }});
                while (true) {{
                    const message = await dioxus.recv();
                    if (message.kind === "chunk") {{
                        const raw = atob(message.bytes_b64);
                        const bytes = new Uint8Array(raw.length);
                        for (let index = 0; index < raw.length; index += 1) {{
                            bytes[index] = raw.charCodeAt(index);
                        }}
                        await writable.write(bytes);
                        dioxus.send({{ kind: "written" }});
                    }} else if (message.kind === "commit") {{
                        await writable.close();
                        dioxus.send({{ kind: "committed" }});
                        return;
                    }} else if (message.kind === "abort") {{
                        await writable.abort();
                        dioxus.send({{ kind: "aborted" }});
                        return;
                    }} else {{
                        await writable.abort();
                        dioxus.send({{ kind: "error", error: "invalid streaming save command" }});
                        return;
                    }}
                }}
            }} catch (error) {{
                if (writable !== null) {{
                    try {{ await writable.abort(); }} catch (_) {{}}
                }}
                dioxus.send({{ kind: "error", error: String(error) }});
            }}
            "#,
        );
        Ok(FileTransferSaveRequest {
            eval: Some(dioxus::document::eval(&script)),
        })
    }
}

pub async fn save_file_transfer_item(
    api: &TransportClient,
    item: &FileTransferItem,
    request: FileTransferSaveRequest,
) -> anyhow::Result<()> {
    let mut sink = TransactionalDownloadSink::from_request(request).await?;
    match decrypt_file_transfer_item_to_sink(api, item, &mut sink).await {
        Ok(()) => sink.commit().await,
        Err(error) => {
            if let Err(abort_error) = sink.abort().await {
                tracing::warn!(%abort_error, "failed to abort file-transfer download sink");
            }
            Err(error)
        }
    }
}

pub async fn abort_file_transfer_save(request: FileTransferSaveRequest) -> anyhow::Result<()> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = request;
        Ok(())
    }
    #[cfg(target_arch = "wasm32")]
    {
        let mut sink = TransactionalDownloadSink::from_request(request).await?;
        sink.abort().await
    }
}

async fn decrypt_file_transfer_item_to_sink<S: FileTransferPlaintextSink>(
    api: &TransportClient,
    item: &FileTransferItem,
    sink: &mut S,
) -> anyhow::Result<()> {
    let record = &item.record;
    let content_key = validate_download_record(record)?;
    let count = arkret_sdk::crypto::file_transfer_aead::segment_count(record)?;
    if record.encryption.segment_bytes.is_none()
        && record.blob_size_bytes > MAX_WHOLE_FILE_DOWNLOAD_BYTES
    {
        anyhow::bail!("whole-file file transfer exceeds Inkson's bounded-memory download limit");
    }

    let blob_ref = arkret_sdk::BlobRef::new(
        crate::wire_helpers::canonical_blob_ref(&record.blob_ref).to_owned(),
    )?;
    let http = api.sdk_http_client()?;
    let request_options = api.context().request_options();
    let mut ciphertext_digest = Sha256::new();
    let mut plaintext_bytes = 0u64;

    for index in 0..count {
        let plan = arkret_sdk::crypto::file_transfer_aead::segment(record, index)?;
        let range = format!("bytes={}-{}", plan.ciphertext_start, plan.ciphertext_end);
        let options = arkret_sdk::http_client::BlobDownloadOptions::new()
            .purpose(FILE_TRANSFER_PURPOSE)
            .range(range)
            .max_bytes(plan.ciphertext_len);
        let response = http
            .blob_download_response_with_options(&blob_ref, &options, &request_options)
            .await?;
        let ciphertext =
            read_exact_segment_response(response, &plan, record.blob_size_bytes).await?;
        ciphertext_digest.update(&ciphertext);
        let plaintext = arkret_sdk::crypto::file_transfer_aead::decrypt_segment(
            record,
            index,
            &ciphertext,
            &content_key,
        )?;
        plaintext_bytes = plaintext_bytes
            .checked_add(plaintext.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("file-transfer plaintext length overflow"))?;
        sink.write_segment(&plaintext).await?;
    }

    if plaintext_bytes != record.plaintext_size_bytes {
        anyhow::bail!("file-transfer plaintext size mismatch");
    }
    let actual_digest = format!("sha256:{}", hex::encode(ciphertext_digest.finalize()));
    verify_content_addressed_blob_ref(&record.blob_ref, &actual_digest)?;
    Ok(())
}

fn validate_download_record(record: &FileTransferRecord) -> anyhow::Result<[u8; CONTENT_KEY_LEN]> {
    record
        .validate()
        .map_err(|error| anyhow::anyhow!("file-transfer record invalid: {error}"))?;
    if record.encryption.aead_profile != AEAD_PROFILE_XCHACHA20_POLY1305_V1 {
        anyhow::bail!("file-transfer AEAD profile mismatch");
    }
    validate_content_aad(record)?;
    if record.access.visibility != FileTransferAccessVisibility::ActorPrivate {
        anyhow::bail!("file-transfer access visibility unsupported");
    }
    let content_key = match &record.encryption.key_delivery {
        FileTransferKeyDelivery::AccountDataWrappedKey { content_key } => content_key,
        FileTransferKeyDelivery::ToDeviceWrappedKey { .. } => {
            anyhow::bail!("file-transfer device_bound requires a to-device key message");
        }
    };
    decode_fixed::<CONTENT_KEY_LEN>(content_key)
}

async fn read_exact_segment_response(
    response: reqwest::Response,
    plan: &arkret_sdk::crypto::file_transfer_aead::FileTransferSegment,
    blob_size_bytes: u64,
) -> anyhow::Result<Vec<u8>> {
    if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
        anyhow::bail!("file-transfer Range request did not return HTTP 206");
    }
    if response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .is_some_and(|value| {
            value
                .to_str()
                .map_or(true, |value| !value.eq_ignore_ascii_case("identity"))
        })
    {
        anyhow::bail!("file-transfer Range response must not use content encoding");
    }
    let content_range = response
        .headers()
        .get(reqwest::header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("file-transfer Range response missing Content-Range"))?;
    validate_content_range(content_range, plan, blob_size_bytes)?;
    if let Some(content_length) = response.content_length()
        && content_length != plan.ciphertext_len as u64
    {
        anyhow::bail!("file-transfer Range response Content-Length mismatch");
    }

    let mut body = Vec::with_capacity(plan.ciphertext_len);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len().saturating_add(chunk.len()) > plan.ciphertext_len {
            anyhow::bail!("file-transfer Range response exceeded the requested segment");
        }
        body.extend_from_slice(&chunk);
    }
    if body.len() != plan.ciphertext_len {
        anyhow::bail!("file-transfer Range response was truncated");
    }
    Ok(body)
}

fn validate_content_range(
    value: &str,
    plan: &arkret_sdk::crypto::file_transfer_aead::FileTransferSegment,
    blob_size_bytes: u64,
) -> anyhow::Result<()> {
    let value = value
        .strip_prefix("bytes ")
        .ok_or_else(|| anyhow::anyhow!("file-transfer Content-Range unit mismatch"))?;
    let (range, total) = value
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("file-transfer Content-Range is malformed"))?;
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| anyhow::anyhow!("file-transfer Content-Range is malformed"))?;
    let start = start.parse::<u64>()?;
    let end = end.parse::<u64>()?;
    let total = total.parse::<u64>()?;
    if start != plan.ciphertext_start || end != plan.ciphertext_end || total != blob_size_bytes {
        anyhow::bail!("file-transfer Content-Range does not match the authenticated record");
    }
    Ok(())
}

trait FileTransferPlaintextSink {
    async fn write_segment(&mut self, plaintext: &[u8]) -> anyhow::Result<()>;
    async fn commit(&mut self) -> anyhow::Result<()>;
    async fn abort(&mut self) -> anyhow::Result<()>;
}

#[cfg(not(target_arch = "wasm32"))]
struct TransactionalDownloadSink {
    destination: std::path::PathBuf,
    temporary: Option<tempfile::NamedTempFile>,
}

#[cfg(not(target_arch = "wasm32"))]
impl TransactionalDownloadSink {
    async fn from_request(request: FileTransferSaveRequest) -> anyhow::Result<Self> {
        let handle = rfd::AsyncFileDialog::new()
            .set_file_name(request.filename)
            .save_file()
            .await
            .ok_or_else(|| anyhow::anyhow!("file-transfer download cancelled"))?;
        let destination = handle.path().to_owned();
        let parent = destination
            .parent()
            .ok_or_else(|| anyhow::anyhow!("file-transfer destination has no parent directory"))?;
        let temporary = tempfile::Builder::new()
            .prefix(".inkson-file-transfer-")
            .tempfile_in(parent)?;
        Ok(Self {
            destination,
            temporary: Some(temporary),
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl FileTransferPlaintextSink for TransactionalDownloadSink {
    async fn write_segment(&mut self, plaintext: &[u8]) -> anyhow::Result<()> {
        use std::io::Write as _;

        self.temporary
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("file-transfer sink is closed"))?
            .write_all(plaintext)?;
        Ok(())
    }

    async fn commit(&mut self) -> anyhow::Result<()> {
        use std::io::Write as _;

        let mut temporary = self
            .temporary
            .take()
            .ok_or_else(|| anyhow::anyhow!("file-transfer sink is closed"))?;
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(&self.destination)
            .map_err(|error| anyhow::anyhow!("persist file-transfer download: {}", error.error))?;
        Ok(())
    }

    async fn abort(&mut self) -> anyhow::Result<()> {
        self.temporary.take();
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
struct TransactionalDownloadSink {
    eval: dioxus::document::Eval,
    open: bool,
}

#[cfg(target_arch = "wasm32")]
impl Drop for TransactionalDownloadSink {
    fn drop(&mut self) {
        if self.open {
            let _ = self.eval.send(serde_json::json!({"kind": "abort"}));
        }
    }
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
struct BrowserSinkEvent {
    kind: String,
    #[serde(default)]
    error: String,
}

#[cfg(target_arch = "wasm32")]
impl TransactionalDownloadSink {
    async fn from_request(mut request: FileTransferSaveRequest) -> anyhow::Result<Self> {
        let mut eval = request
            .eval
            .take()
            .ok_or_else(|| anyhow::anyhow!("file-transfer save target is closed"))?;
        expect_browser_sink_event(&mut eval, "ready").await?;
        Ok(Self { eval, open: true })
    }

    async fn command(&mut self, value: Value, expected: &str) -> anyhow::Result<()> {
        self.eval.send(value)?;
        expect_browser_sink_event(&mut self.eval, expected).await
    }
}

#[cfg(target_arch = "wasm32")]
async fn expect_browser_sink_event(
    eval: &mut dioxus::document::Eval,
    expected: &str,
) -> anyhow::Result<()> {
    let event: BrowserSinkEvent = eval.recv().await?;
    if event.kind == expected {
        return Ok(());
    }
    if event.kind == "error" {
        anyhow::bail!("file-transfer streaming save failed: {}", event.error);
    }
    anyhow::bail!(
        "file-transfer streaming save returned unexpected state `{}`",
        event.kind
    )
}

#[cfg(target_arch = "wasm32")]
impl FileTransferPlaintextSink for TransactionalDownloadSink {
    async fn write_segment(&mut self, plaintext: &[u8]) -> anyhow::Result<()> {
        self.command(
            serde_json::json!({
                "kind": "chunk",
                "bytes_b64": BASE64_STANDARD.encode(plaintext),
            }),
            "written",
        )
        .await
    }

    async fn commit(&mut self) -> anyhow::Result<()> {
        let result = self
            .command(serde_json::json!({"kind": "commit"}), "committed")
            .await;
        self.open = false;
        result
    }

    async fn abort(&mut self) -> anyhow::Result<()> {
        let result = self
            .command(serde_json::json!({"kind": "abort"}), "aborted")
            .await;
        self.open = false;
        result
    }
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
    Ok(arkret_sdk::crypto::file_transfer_aead::decrypt(
        record,
        ciphertext,
        content_key,
    )?)
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
    let actor = crate::mls_api_helpers::principal_core_id(actor_id)
        .context("file-transfer principal identity")?;
    let updated_hlc = crate::signing_stamp::issue_protocol_hlc(
        actor.as_str(),
        device_id.trim(),
        principal_control_realm_id.as_str(),
    )
    .context("file-transfer signing stamp")?;
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
    let streaming = plaintext.len() > 262_144;
    let encryption = FileTransferEncryption {
        scheme: if streaming {
            arkret_sdk::BLOB_SCHEME_STREAM_AEAD_V1
        } else {
            FILE_TRANSFER_BLOB_SCHEME
        }
        .to_owned(),
        aead_profile: AEAD_PROFILE_XCHACHA20_POLY1305_V1.to_owned(),
        nonce: (!streaming).then(|| URL_SAFE_NO_PAD.encode(nonce)),
        nonce_prefix: streaming.then(|| URL_SAFE_NO_PAD.encode(&nonce[..19])),
        segment_bytes: streaming.then_some(262_144),
        aad,
        key_delivery: FileTransferKeyDelivery::AccountDataWrappedKey {
            content_key: URL_SAFE_NO_PAD.encode(content_key),
        },
    };
    let media_type = normalize_media_type(media_type);
    let ciphertext = arkret_sdk::crypto::file_transfer_aead::encrypt(
        &encryption,
        &media_type,
        &plaintext,
        &content_key,
    )?;
    let content_digest = crate::canonical::sha256_digest(&ciphertext);
    Ok(PreparedFileTransfer {
        account_data_key,
        transfer_id,
        ciphertext,
        content_digest,
        plaintext_size_bytes: plaintext.len() as u64,
        media_type,
        filename: filename.and_then(sanitize_filename),
        encryption,
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
        // `blob_ref` is the only wire carrier of the ciphertext digest
        // (file-transfer.md §4), and the record deliberately keeps no second
        // copy of it. Binding it to the exact ciphertext this transfer
        // produced therefore has to happen where the record is constructed,
        // not only on the upload path, or a drifting digest reaches
        // account-data unchecked.
        verify_content_addressed_blob_ref(&blob_ref, &self.content_digest)?;
        let record = FileTransferRecord {
            kind: FILE_TRANSFER_RECORD_KIND.to_owned(),
            transfer_id: self.transfer_id,
            blob_ref,
            blob_size_bytes,
            media_type: self.media_type,
            filename: self.filename,
            plaintext_size_bytes: self.plaintext_size_bytes,
            access: FileTransferAccess {
                visibility: FileTransferAccessVisibility::ActorPrivate,
                recipient_device_ids: Vec::new(),
            },
            encryption: self.encryption,
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
        .or_else(|| entry.get("key"))
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
    if crate::mls_api_helpers::principal_core_id(actor_id)?
        != *crypto.actor_id.signing_principal_id()
    {
        anyhow::bail!("file-transfer author differs from the crypto context account");
    }
    let plaintext = serde_json::to_value(record)?;
    let envelope = arkret_sdk::account_data_crypto::seal_account_data_value(
        &crypto.account_data_secret,
        &crypto.actor_id,
        account_data_key,
        &plaintext,
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
    let plaintext = arkret_sdk::account_data_crypto::open_account_data_value(
        &crypto.account_data_secret,
        &crypto.actor_id,
        account_data_key,
        &outer,
    )?;
    let record: FileTransferRecord = serde_json::from_value(plaintext)
        .map_err(|error| anyhow::anyhow!("file-transfer record JSON decode failed: {error}"))?;
    record
        .validate()
        .map_err(|error| anyhow::anyhow!("file-transfer record validation failed: {error}"))?;
    Ok(record)
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
    verify_content_addressed_blob_ref(&record.blob_ref, &digest)?;
    if record.blob_size_bytes != ciphertext.len() as u64 {
        anyhow::bail!("file-transfer blob size mismatch");
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

    #[cfg(not(target_arch = "wasm32"))]
    struct DigestSink {
        digest: Sha256,
        total: usize,
        max_segment: usize,
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl FileTransferPlaintextSink for DigestSink {
        async fn write_segment(&mut self, plaintext: &[u8]) -> anyhow::Result<()> {
            self.digest.update(plaintext);
            self.total += plaintext.len();
            self.max_segment = self.max_segment.max(plaintext.len());
            Ok(())
        }

        async fn commit(&mut self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn abort(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn test_authority() -> arkret_sdk::AccountId {
        crate::test_support::authority(ACTOR)
    }

    const ACTOR: &str = "did:web:alice.example";
    const DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000000001";

    fn test_pcr() -> arkret_sdk::RealmId {
        crate::test_support::realm_id("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
    }

    fn test_account_secret() -> String {
        URL_SAFE_NO_PAD.encode([7u8; 32])
    }

    #[test]
    fn file_transfer_cas_merge_uses_hlc_and_preserves_terminal_delete() {
        let crypto = FileTransferCryptoContext::from_account_secret(
            &test_authority(),
            &test_account_secret(),
        )
        .unwrap();
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
        let authority = test_authority();
        let crypto =
            FileTransferCryptoContext::from_account_secret(&authority, &test_account_secret())
                .unwrap();
        let prepared = prepare_actor_private_file(
            &crypto,
            &test_pcr(),
            authority.principal_id.as_str(),
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
        let other_account = arkret_sdk::AccountId::new(
            test_authority().principal_id,
            arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        );
        let other_crypto =
            FileTransferCryptoContext::from_account_secret(&other_account, &test_account_secret())
                .unwrap();
        assert!(
            open_record_envelope(&envelope, &other_crypto, &key).is_err(),
            "same principal and secret must not admit a different Station account"
        );
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
    fn account_subscribe_event_payload_restores_file_transfer_record() {
        let authority = test_authority();
        let crypto =
            FileTransferCryptoContext::from_account_secret(&authority, &test_account_secret())
                .unwrap();
        let prepared = prepare_actor_private_file(
            &crypto,
            &test_pcr(),
            authority.principal_id.as_str(),
            DEVICE,
            Some("restored.txt"),
            "text/plain",
            b"restored".to_vec(),
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
        let event_payload = json!({
            "key": key,
            "expected_revision": 0,
            "encrypted_payload": envelope,
            "updated_at": "2026-06-07T00:00:00.000Z",
        });

        let items = file_transfer_items_from_account_data(&[event_payload], &crypto);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].record.filename.as_deref(), Some("restored.txt"));
    }

    #[test]
    fn record_envelope_must_match_account_data_key() {
        let crypto = FileTransferCryptoContext::from_account_secret(
            &test_authority(),
            &test_account_secret(),
        )
        .unwrap();
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
        let crypto = FileTransferCryptoContext::from_account_secret(
            &test_authority(),
            &test_account_secret(),
        )
        .unwrap();
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
        let crypto = FileTransferCryptoContext::from_account_secret(
            &test_authority(),
            &test_account_secret(),
        )
        .unwrap();
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

    #[test]
    fn content_range_must_match_authenticated_segment_geometry() {
        let crypto = FileTransferCryptoContext::from_account_secret(
            &test_authority(),
            &test_account_secret(),
        )
        .unwrap();
        let prepared = prepare_actor_private_file(
            &crypto,
            &test_pcr(),
            ACTOR,
            DEVICE,
            Some("range.bin"),
            "application/octet-stream",
            vec![9; 262_145],
        )
        .unwrap();
        let ciphertext = prepared.ciphertext.clone();
        let blob_ref = format!(
            "ak:blob:sha256:{}",
            prepared.content_digest.trim_start_matches("sha256:")
        );
        let record = prepared
            .into_record(blob_ref, ciphertext.len() as u64)
            .unwrap();
        let first = arkret_sdk::crypto::file_transfer_aead::segment(&record, 0).unwrap();
        let exact = format!(
            "bytes {}-{}/{}",
            first.ciphertext_start, first.ciphertext_end, record.blob_size_bytes
        );
        assert!(validate_content_range(&exact, &first, record.blob_size_bytes).is_ok());
        assert!(
            validate_content_range(
                &format!(
                    "bytes {}-{}/{}",
                    first.ciphertext_start,
                    first.ciphertext_end + 1,
                    record.blob_size_bytes
                ),
                &first,
                record.blob_size_bytes,
            )
            .is_err()
        );
        assert!(validate_content_range(&exact, &first, record.blob_size_bytes + 1).is_err());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn production_range_pipeline_decrypts_into_a_bounded_sink() {
        use std::io::{BufRead as _, BufReader, Write as _};
        use std::net::TcpListener;
        use std::sync::Arc;

        let crypto = FileTransferCryptoContext::from_account_secret(
            &test_authority(),
            &test_account_secret(),
        )
        .unwrap();
        let plaintext = (0..(262_144 * 2 + 17))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let prepared = prepare_actor_private_file(
            &crypto,
            &test_pcr(),
            ACTOR,
            DEVICE,
            Some("range.bin"),
            "application/octet-stream",
            plaintext.clone(),
        )
        .unwrap();
        let ciphertext = Arc::new(prepared.ciphertext.clone());
        let blob_ref = format!(
            "ak:blob:sha256:{}",
            prepared.content_digest.trim_start_matches("sha256:")
        );
        let record = prepared
            .into_record(blob_ref, ciphertext.len() as u64)
            .unwrap();
        let segment_count = arkret_sdk::crypto::file_transfer_aead::segment_count(&record).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_ciphertext = Arc::clone(&ciphertext);
        let server = std::thread::spawn(move || {
            for _ in 0..segment_count {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                assert!(request_line.starts_with("GET /_arkret/self/blob/get?"));
                let mut requested_range = None;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some(value) = line
                        .strip_prefix("range:")
                        .or_else(|| line.strip_prefix("Range:"))
                    {
                        requested_range = Some(value.trim().to_owned());
                    }
                }
                let requested_range = requested_range.unwrap();
                let (start, end) = requested_range
                    .strip_prefix("bytes=")
                    .unwrap()
                    .split_once('-')
                    .unwrap();
                let start = start.parse::<usize>().unwrap();
                let end = end.parse::<usize>().unwrap();
                let body = &server_ciphertext[start..=end];
                write!(
                    stream,
                    "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nCache-Control: private, no-store\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment\r\nConnection: close\r\n\r\n",
                    body.len(),
                    start,
                    end,
                    server_ciphertext.len()
                )
                .unwrap();
                stream.write_all(body).unwrap();
            }
        });

        let api = TransportClient::new(
            &format!("http://{address}/"),
            crate::transport::RequestContext::new("test-grant"),
        )
        .unwrap();
        let item = FileTransferItem {
            account_data_key: "ak.file_transfer.v1:test".to_owned(),
            record,
            updated_at: None,
        };
        let mut sink = DigestSink {
            digest: Sha256::new(),
            total: 0,
            max_segment: 0,
        };
        decrypt_file_transfer_item_to_sink(&api, &item, &mut sink)
            .await
            .unwrap();
        server.join().unwrap();

        assert_eq!(sink.total, plaintext.len());
        assert!(sink.max_segment <= 262_144);
        assert_eq!(
            hex::encode(sink.digest.finalize()),
            crate::canonical::sha256_hex(&plaintext)
        );
    }
}
