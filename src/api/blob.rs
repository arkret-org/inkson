use super::*;

const DEFAULT_BLOB_DOWNLOAD_MAX_BYTES: usize = 64 * 1024 * 1024;

impl CokretApi {
    /// A4b — resolve a `ck:blob:sha256:<hex>` reference to its
    /// authenticated download URL on this Principal Server. Returns the
    /// `<base>/_cokret/self/blob/get?blob_ref=<…>&purpose=profile_avatar`
    /// shape answered by the spec blob handler; callers can plug this
    /// directly into `<img src=…>`.
    pub fn blob_download_url(&self, blob_ref: &str) -> String {
        blob_download_url_for(self.base_url.as_str(), blob_ref)
    }

    /// Round 4 (spec a77b995) — request a presigned blob upload URL
    /// scoped to a Realm. The pre-round-4 omission of `realm_id` is
    /// wire-broken: Realm-owned blobs MUST carry `realm_id` so the
    /// server can bind the resulting blob_ref into the originating
    /// Realm's resource quota / legal-hold scope. Returns the
    /// server-issued envelope verbatim (URL, blob_ref, expires_at,
    /// headers) for the caller to PUT against.
    pub async fn blob_presign(
        &self,
        blob_ref: &str,
        realm_id: Option<&str>,
        purpose: Option<&str>,
    ) -> anyhow::Result<cokret_sdk::BlobPresignOutcome> {
        let realm = realm_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                cokret_sdk::RealmId::new(value.to_owned()).map_err(|err| {
                    anyhow::anyhow!("invalid realm_id for /blob/presign `{value}`: {err}")
                })
            })
            .transpose()?;
        let body = cokret_sdk::models::BlobPresignRequestBody {
            blob_ref: cokret_sdk::BlobRef::new(canonical_blob_ref(blob_ref).to_owned())
                .map_err(|err| anyhow::anyhow!("invalid blob_ref for /blob/presign: {err}"))?,
            realm_id: realm,
            max_age_seconds: None,
            purpose: purpose
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        };
        self.sdk_http_client()?
            .blob_presign(&body)
            .await
            .map_err(anyhow::Error::from)
    }

    fn blob_upload_metadata(
        size_bytes: usize,
        media_type: &str,
        realm_id: Option<&str>,
        content_digest: Option<&str>,
        filename: Option<&str>,
        purpose: Option<&str>,
    ) -> anyhow::Result<cokret_sdk::models::BlobUploadMetadata> {
        let realm_id = realm_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                cokret_sdk::RealmId::new(value.to_owned()).map_err(|err| {
                    anyhow::anyhow!("invalid realm_id for /blob/upload `{value}`: {err}")
                })
            })
            .transpose()?;
        let content_digest = content_digest
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                cokret_sdk::Hash::new(value.to_owned()).map_err(|err| {
                    anyhow::anyhow!("invalid content_digest for /blob/upload `{value}`: {err}")
                })
            })
            .transpose()?;
        let media_type = if media_type.trim().is_empty() {
            None
        } else {
            Some(media_type.trim().to_owned())
        };
        Ok(cokret_sdk::models::BlobUploadMetadata {
            realm_id,
            content_digest,
            size_bytes: size_bytes as u64,
            media_type,
            filename: filename.map(ToOwned::to_owned),
            purpose: purpose.map(ToOwned::to_owned),
        })
    }

    pub async fn upload_blob(&self, bytes: &'static [u8]) -> anyhow::Result<BlobUploadOutcome> {
        let metadata = Self::blob_upload_metadata(
            bytes.len(),
            "application/octet-stream",
            None,
            None,
            None,
            None,
        )?;
        self.sdk_http_client()?
            .blob_upload_bytes(&metadata, bytes.to_vec())
            .await
            .map_err(anyhow::Error::from)
    }

    /// Owned-bytes variant of [`upload_blob`] used by the composer
    /// drag-drop path (A6.2). The drop event yields `Vec<u8>` from
    /// the browser File API which cannot satisfy the `'static`
    /// bound that the original method requires for fixture
    /// attachments.
    pub async fn upload_blob_bytes(
        &self,
        bytes: Vec<u8>,
        content_type: &str,
    ) -> anyhow::Result<BlobUploadOutcome> {
        self.upload_blob_bytes_scoped(bytes, content_type, None, None)
            .await
    }

    /// Upload owned bytes with optional Realm and filename metadata.
    ///
    /// Message / task attachments should pass the current `realm_id` so
    /// soland can enforce membership, plaintext-visibility policy and
    /// per-Realm quota on the authoritative blob record. Avatar and other
    /// actor-private uploads intentionally leave it unset.
    pub async fn upload_blob_bytes_scoped(
        &self,
        bytes: Vec<u8>,
        content_type: &str,
        realm_id: Option<&str>,
        filename: Option<&str>,
    ) -> anyhow::Result<BlobUploadOutcome> {
        let filename = filename.and_then(safe_blob_filename_header);
        let metadata = Self::blob_upload_metadata(
            bytes.len(),
            content_type,
            realm_id,
            None,
            filename.as_deref(),
            None,
        )?;
        self.sdk_http_client()?
            .blob_upload_bytes(&metadata, bytes)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn upload_encrypted_mls_attachment_asset(
        &self,
        realm_id: &str,
        asset: &crate::blob::EncryptedClientAsset,
    ) -> anyhow::Result<BlobUploadOutcome> {
        // The ciphertext travels as the opaque multipart `content` part.
        // The SDK's canonical `EncryptedAttachmentEnvelope` does NOT ride
        // on the upload (the spec form has no field for it); it travels
        // alongside the blob_ref in the referencing message payload.
        let metadata = Self::blob_upload_metadata(
            asset.ciphertext.len(),
            crate::blob::CIPHERTEXT_MEDIA_TYPE,
            Some(realm_id),
            Some(asset.ciphertext_digest()),
            None,
            None,
        )?;
        self.sdk_http_client()?
            .blob_upload_bytes(&metadata, asset.ciphertext.clone())
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn upload_file_transfer_ciphertext(
        &self,
        ciphertext: Vec<u8>,
        content_digest: &str,
    ) -> anyhow::Result<BlobUploadOutcome> {
        let metadata = Self::blob_upload_metadata(
            ciphertext.len(),
            crate::blob::CIPHERTEXT_MEDIA_TYPE,
            None,
            Some(content_digest),
            None,
            Some("file_transfer"),
        )?;
        self.sdk_http_client()?
            .blob_upload_bytes(&metadata, ciphertext)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn get_blob_bytes(&self, blob_ref: &str) -> anyhow::Result<Vec<u8>> {
        self.download_blob_bytes_sdk(
            blob_ref,
            "message_attachment",
            DEFAULT_BLOB_DOWNLOAD_MAX_BYTES,
        )
        .await
    }

    pub async fn download_blob_verified(
        &self,
        descriptor: &cokret_sdk::SnapshotChunkDescriptor,
    ) -> anyhow::Result<Vec<u8>> {
        let max_bytes = blob_download_max_bytes_for_declared_size(descriptor.size_bytes)?;
        let bytes = self
            .download_blob_bytes_sdk(descriptor.chunk_ref.as_str(), "download", max_bytes)
            .await?;
        if bytes.len() as u64 > descriptor.size_bytes {
            anyhow::bail!(
                "{}: snapshot chunk response exceeded declared size",
                cokret_sdk::SnapshotValidationCode::DigestMismatch.as_str()
            );
        }
        cokret_sdk::verify_snapshot_chunk_bytes(descriptor, &bytes)
            .map_err(snapshot_validation_error)?;
        Ok(bytes)
    }

    pub async fn download_snapshot_chunk_verified(
        &self,
        descriptor: &cokret_sdk::SnapshotChunkDescriptor,
    ) -> anyhow::Result<cokret_sdk::SnapshotChunkPayload> {
        let bytes = self.download_blob_verified(descriptor).await?;
        cokret_sdk::parse_verified_snapshot_chunk_bytes(descriptor, &bytes)
            .map_err(snapshot_validation_error)
    }

    pub async fn get_file_transfer_blob_bytes(&self, blob_ref: &str) -> anyhow::Result<Vec<u8>> {
        self.download_blob_bytes_sdk(blob_ref, "file_transfer", DEFAULT_BLOB_DOWNLOAD_MAX_BYTES)
            .await
    }

    /// Download an encrypted MLS attachment and recover its plaintext using the
    /// SDK's canonical decoder, dispatched on the envelope `scheme`.
    ///
    /// `content_key` is the 32-byte MLS-exporter secret (the same value passed
    /// as `content_key` at encrypt time). The envelope is the canonical
    /// [`cokret_sdk::blob_aead::EncryptedAttachmentEnvelope`] that travelled
    /// alongside the blob_ref in the message payload.
    ///
    /// Scheme dispatch:
    /// - `ck.blob.whole_file_aead.v1` → [`decrypt_whole_file`].
    /// - `ck.blob.stream_aead.v1` → incremental [`StreamDecryptor`] fed the segments of the
    ///   downloaded ciphertext, so every §3.3.6 sequencing / integrity check runs before plaintext
    ///   is released.
    /// - any other scheme → fail closed.
    ///
    /// Minimal implementation: the ciphertext is fetched with a single whole
    /// GET, then driven segment-by-segment through the decryptor.
    /// TODO(perf): for `ck.blob.stream_aead.v1` issue HTTP Range requests at
    /// `segment_size` (+16-byte tag) integer offsets so Range / progressive
    /// playback can decrypt segments as they arrive instead of buffering the
    /// whole object — the `StreamDecryptor` already supports incremental push.
    pub async fn get_encrypted_attachment_plaintext(
        &self,
        envelope: &cokret_sdk::blob_aead::EncryptedAttachmentEnvelope,
        content_key: &[u8; 32],
    ) -> anyhow::Result<Vec<u8>> {
        use cokret_sdk::blob_aead::{
            SCHEME_STREAM, SCHEME_WHOLE_FILE, StreamDecryptor, decrypt_whole_file,
        };

        let ciphertext = self.get_blob_bytes(&envelope.blob_ref).await?;

        match envelope.scheme.as_str() {
            SCHEME_WHOLE_FILE => decrypt_whole_file(&ciphertext, envelope, content_key)
                .map_err(|err| anyhow::anyhow!("whole-file attachment decrypt: {err}")),
            SCHEME_STREAM => {
                let segment_size = envelope
                    .segment_size
                    .ok_or_else(|| anyhow::anyhow!("stream envelope missing segment_size"))?
                    as usize;
                let segment_count = envelope
                    .segment_count
                    .ok_or_else(|| anyhow::anyhow!("stream envelope missing segment_count"))?;
                const TAG_LEN: usize = 16;

                let mut decryptor = StreamDecryptor::new(envelope, content_key)
                    .map_err(|err| anyhow::anyhow!("stream attachment decrypt: {err}"))?;
                // All three length fields (`size_bytes`, `segment_size`,
                // `segment_count`) come from the server-supplied envelope and
                // are not cross-checked by `StreamDecryptor::new`. Validate the
                // declared geometry up front with checked arithmetic so a
                // malformed envelope returns an error instead of wrapping (in
                // release the overflow-checks are off) and panicking on the
                // wasm32 `usize` slice below.
                let last_index = (segment_count - 1) as u64;
                // Bytes covered by all-but-last full segments must not exceed
                // the declared total plaintext size; the last segment carries
                // the (>=0) remainder.
                let leading_bytes = (segment_size as u64)
                    .checked_mul(last_index)
                    .ok_or_else(|| anyhow::anyhow!("stream envelope segment geometry overflow"))?;
                if leading_bytes > envelope.size_bytes {
                    return Err(anyhow::anyhow!(
                        "stream envelope segment_size * (segment_count - 1) exceeds size_bytes"
                    ));
                }
                let last_pt_len = (envelope.size_bytes - leading_bytes) as usize;
                let mut plaintext = Vec::with_capacity(envelope.size_bytes as usize);
                let mut offset = 0usize;
                for index in 0..segment_count {
                    // Per §3.3.1: every segment but the last carries exactly
                    // `segment_size` plaintext bytes; the last carries the
                    // remainder. Each ciphertext segment adds a 16-byte tag.
                    let pt_len = if (index as u64) < last_index {
                        segment_size
                    } else {
                        last_pt_len
                    };
                    let seg_len = pt_len
                        .checked_add(TAG_LEN)
                        .ok_or_else(|| anyhow::anyhow!("stream segment length overflow"))?;
                    let seg_end = offset
                        .checked_add(seg_len)
                        .ok_or_else(|| anyhow::anyhow!("stream ciphertext offset overflow"))?;
                    if seg_end > ciphertext.len() {
                        return Err(anyhow::anyhow!(
                            "stream ciphertext shorter than declared segments"
                        ));
                    }
                    let segment = &ciphertext[offset..seg_end];
                    offset = seg_end;
                    let seg_plaintext = decryptor
                        .push_segment(index, segment)
                        .map_err(|err| anyhow::anyhow!("stream segment decrypt: {err}"))?;
                    plaintext.extend_from_slice(&seg_plaintext);
                }
                decryptor
                    .finish()
                    .map_err(|err| anyhow::anyhow!("stream attachment finalize: {err}"))?;
                Ok(plaintext)
            }
            // Unknown / unsupported scheme: fail closed, never attempt a decrypt.
            other => Err(anyhow::anyhow!("unsupported_attachment_scheme: {other}")),
        }
    }

    async fn download_blob_bytes_sdk(
        &self,
        blob_ref: &str,
        purpose: &str,
        max_bytes: usize,
    ) -> anyhow::Result<Vec<u8>> {
        let blob_ref = cokret_sdk::BlobRef::new(canonical_blob_ref(blob_ref).to_owned())
            .map_err(|err| anyhow::anyhow!("invalid blob_ref for /blob/get: {err}"))?;
        let options = cokret_sdk::http_client::BlobDownloadOptions::new()
            .purpose(purpose.to_owned())
            .max_bytes(max_bytes);
        let request_options = self.blob_download_request_options();
        self.sdk_http_client()?
            .blob_download_bytes_with_options(&blob_ref, &options, &request_options)
            .await
            .map_err(anyhow::Error::from)
    }

    fn blob_download_request_options(&self) -> cokret_sdk::http_client::ClientRequestOptions {
        match self.wait_for_sync_token.as_deref() {
            Some(sync_token) => {
                cokret_sdk::http_client::ClientRequestOptions::new().wait_for(sync_token.to_owned())
            }
            None => cokret_sdk::http_client::ClientRequestOptions::new(),
        }
    }
}

fn snapshot_validation_error(error: cokret_sdk::SnapshotValidationError) -> anyhow::Error {
    anyhow::anyhow!("{}: {}", error.code.as_str(), error.message)
}

fn blob_download_max_bytes_for_declared_size(size_bytes: u64) -> anyhow::Result<usize> {
    let size_bytes = usize::try_from(size_bytes)
        .map_err(|_| anyhow::anyhow!("snapshot chunk size_bytes exceeds this platform"))?;
    size_bytes
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("snapshot chunk size_bytes exceeds this platform"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_chunk_download_limit_allows_one_extra_byte_for_mismatch_check() {
        assert_eq!(blob_download_max_bytes_for_declared_size(5).unwrap(), 6);
    }

    #[test]
    fn snapshot_chunk_download_limit_rejects_usize_overflow() {
        let oversized = usize::MAX as u64;
        if usize::try_from(oversized).is_ok() {
            let error = blob_download_max_bytes_for_declared_size(oversized).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("snapshot chunk size_bytes exceeds this platform")
            );
        }
    }
}
