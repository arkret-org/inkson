use super::*;

impl CokretApi {
    /// A4b — resolve a `ck:blob:sha256:<hex>` reference to its
    /// authenticated download URL on this Principal Server. Returns the
    /// `<base>/_cokret/self/blob/get?blob_ref=<…>&purpose=profile_avatar`
    /// shape that soland's
    /// `/blob/get` handler answers — callers can plug this directly
    /// into `<img src=…>` or `ck.account.update_profile { avatar_url }`.
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

    pub async fn upload_blob(&self, bytes: &'static [u8]) -> anyhow::Result<BlobUploadResBody> {
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
    ) -> anyhow::Result<BlobUploadResBody> {
        self.upload_blob_bytes_scoped(bytes, content_type, None, None)
            .await
    }

    /// Upload owned bytes with optional Space and filename metadata.
    ///
    /// Message / task attachments should pass the current `space_id` so
    /// soland can enforce membership, plaintext-visibility policy and
    /// per-Space quota on the authoritative blob record. Avatar and other
    /// actor-private uploads intentionally leave it unset.
    pub async fn upload_blob_bytes_scoped(
        &self,
        bytes: Vec<u8>,
        content_type: &str,
        space_id: Option<&str>,
        filename: Option<&str>,
    ) -> anyhow::Result<BlobUploadResBody> {
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
        if let Some(space_id) = space_id.filter(|value| !value.trim().is_empty()) {
            request = request.header("x-cokret-space-id", space_id.trim());
        }
        if let Some(filename) = filename.and_then(safe_blob_filename_header) {
            request = request.header("x-cokret-filename", filename);
        }
        self.send_json(self.prepare_request(request), Method::POST)
            .await
    }

    pub async fn upload_encrypted_mls_attachment_asset(
        &self,
        space_id: &str,
        asset: &crate::blob::EncryptedClientAsset,
    ) -> anyhow::Result<BlobUploadResBody> {
        let envelope = serde_json::to_string(&asset.envelope)?;
        let request = self
            .http
            .post(self.endpoint("_cokret/self/blob/upload")?)
            .header("content-type", crate::blob::CIPHERTEXT_MEDIA_TYPE)
            .header("x-cokret-space-id", space_id)
            .header("x-cokret-blob-encrypted", "true")
            .header("x-cokret-attachment-envelope", envelope)
            .header("x-cokret-content-digest", &asset.ciphertext_digest)
            .body(asset.ciphertext.clone());
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
}
