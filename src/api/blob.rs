use super::*;

impl CokretApi {
    /// A4b — resolve a `ck:blob:sha256:<hex>` reference to its
    /// authenticated download URL on this Principal Server. Returns the
    /// `<base>/_cokret/self/blob/get?blob_ref=<…>&purpose=profile_avatar`
    /// shape that soland's
    /// `/blob/get` handler answers — callers can plug this directly
    /// into `<img src=…>` or `ck.self.account.update_profile { avatar_url }`.
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
        realm_id: &str,
        content_type: &str,
        content_length: u64,
    ) -> anyhow::Result<Value> {
        let realm = cokret_sdk::RealmId::new(realm_id)
            .map_err(|err| anyhow::anyhow!("invalid realm_id for /blob/presign: {err}"))?;
        self.post_json(
            "_cokret/self/blob/presign",
            json!({
                "realm_id": realm.as_str(),
                "content_type": content_type,
                "content_length": content_length,
            }),
        )
        .await
    }

    pub async fn upload_blob(&self, bytes: &'static [u8]) -> anyhow::Result<BlobUploadOutcome> {
        let request = self
            .http
            .post(self.endpoint("_cokret/self/blob/upload")?)
            .header("content-type", "application/octet-stream")
            .body(bytes);
        self.send_json(self.prepare_request(request), Method::POST)
            .await
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
        let content_type = if content_type.trim().is_empty() {
            "application/octet-stream"
        } else {
            content_type
        };
        let mut request = self
            .http
            .post(self.endpoint("_cokret/self/blob/upload")?)
            .header("content-type", content_type)
            .body(bytes);
        if let Some(realm_id) = realm_id.filter(|value| !value.trim().is_empty()) {
            request = request.header("x-cokret-realm-id", realm_id.trim());
        }
        if let Some(filename) = filename.and_then(safe_blob_filename_header) {
            request = request.header("x-cokret-filename", filename);
        }
        self.send_json(self.prepare_request(request), Method::POST)
            .await
    }

    pub async fn upload_encrypted_mls_attachment_asset(
        &self,
        realm_id: &str,
        asset: &crate::blob::EncryptedClientAsset,
    ) -> anyhow::Result<BlobUploadOutcome> {
        // The envelope is now the SDK's canonical `EncryptedAttachmentEnvelope`
        // (spec `blob.schema.json#/$defs/encrypted_attachment` wire shape), not
        // the old private `cokret.encrypted_attachment.v1` JSON.
        let envelope = serde_json::to_string(&asset.envelope)?;
        let request = self
            .http
            .post(self.endpoint("_cokret/self/blob/upload")?)
            .header("content-type", crate::blob::CIPHERTEXT_MEDIA_TYPE)
            .header("x-cokret-realm-id", realm_id)
            .header("x-cokret-blob-encrypted", "true")
            .header("x-cokret-attachment-envelope", envelope)
            .header("x-cokret-content-digest", asset.ciphertext_digest())
            .body(asset.ciphertext.clone());
        self.send_json(self.prepare_request(request), Method::POST)
            .await
    }

    pub async fn upload_file_transfer_ciphertext(
        &self,
        ciphertext: Vec<u8>,
        content_digest: &str,
    ) -> anyhow::Result<BlobUploadOutcome> {
        let request = self
            .http
            .post(self.endpoint("_cokret/self/blob/upload")?)
            .header("content-type", crate::blob::CIPHERTEXT_MEDIA_TYPE)
            .header("x-cokret-blob-encrypted", "true")
            .header("x-cokret-blob-purpose", "file_transfer")
            .header("x-cokret-content-digest", content_digest)
            .body(ciphertext);
        self.send_json(self.prepare_request(request), Method::POST)
            .await
    }

    pub async fn get_blob_bytes(&self, blob_ref: &str) -> anyhow::Result<Vec<u8>> {
        let blob_ref = query_component(canonical_blob_ref(blob_ref));
        let request = self.http.get(self.endpoint(&format!(
            "_cokret/self/blob/get?blob_ref={blob_ref}&purpose=message_attachment"
        ))?);
        self.send_bytes(self.prepare_request(request), Method::GET)
            .await
    }

    pub async fn get_file_transfer_blob_bytes(&self, blob_ref: &str) -> anyhow::Result<Vec<u8>> {
        let blob_ref = query_component(canonical_blob_ref(blob_ref));
        let request = self.http.get(self.endpoint(&format!(
            "_cokret/self/blob/get?blob_ref={blob_ref}&purpose=file_transfer"
        ))?);
        self.send_bytes(self.prepare_request(request), Method::GET)
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
    /// - `ck.blob.stream_aead.v1` → incremental [`StreamDecryptor`] fed the
    ///   segments of the downloaded ciphertext, so every §3.3.6 sequencing /
    ///   integrity check runs before plaintext is released.
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
                let mut plaintext = Vec::with_capacity(envelope.size_bytes as usize);
                let mut offset = 0usize;
                for index in 0..segment_count {
                    // Per §3.3.1: every segment but the last carries exactly
                    // `segment_size` plaintext bytes; the last carries the
                    // remainder. Each ciphertext segment adds a 16-byte tag.
                    let last_index = segment_count - 1;
                    let pt_len = if index < last_index {
                        segment_size
                    } else {
                        (envelope.size_bytes - (segment_size as u64) * (last_index as u64)) as usize
                    };
                    let seg_len = pt_len + TAG_LEN;
                    if offset + seg_len > ciphertext.len() {
                        return Err(anyhow::anyhow!(
                            "stream ciphertext shorter than declared segments"
                        ));
                    }
                    let segment = &ciphertext[offset..offset + seg_len];
                    offset += seg_len;
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
            other => Err(anyhow::anyhow!(
                "unsupported_attachment_scheme: {other}"
            )),
        }
    }
}
