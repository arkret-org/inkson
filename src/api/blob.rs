use super::*;

const DEFAULT_BLOB_DOWNLOAD_MAX_BYTES: usize = 64 * 1024 * 1024;

impl ArkretApi {
    pub(crate) fn blob_upload_metadata(
        size_bytes: usize,
        media_type: &str,
        realm_id: Option<&str>,
        content_digest: Option<&str>,
        filename: Option<&str>,
        purpose: Option<&str>,
    ) -> anyhow::Result<arkret_sdk::models::BlobUploadMetadata> {
        let realm_id = realm_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                arkret_sdk::RealmId::new(value.to_owned()).map_err(|err| {
                    anyhow::anyhow!("invalid realm_id for /blob/upload `{value}`: {err}")
                })
            })
            .transpose()?;
        let content_digest = content_digest
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                arkret_sdk::Hash::new(value.to_owned()).map_err(|err| {
                    anyhow::anyhow!("invalid content_digest for /blob/upload `{value}`: {err}")
                })
            })
            .transpose()?;
        let media_type = if media_type.trim().is_empty() {
            None
        } else {
            Some(media_type.trim().to_owned())
        };
        Ok(arkret_sdk::models::BlobUploadMetadata {
            realm_id,
            content_digest,
            size_bytes: size_bytes as u64,
            media_type,
            filename: filename.map(ToOwned::to_owned),
            purpose: purpose.map(ToOwned::to_owned),
        })
    }

    /// Owned-bytes upload used by the composer drag-drop path.
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

    pub async fn get_blob_bytes(&self, blob_ref: &str) -> anyhow::Result<Vec<u8>> {
        self.download_blob_bytes_sdk(
            blob_ref,
            "message_attachment",
            DEFAULT_BLOB_DOWNLOAD_MAX_BYTES,
        )
        .await
    }

    async fn download_blob_verified(
        &self,
        descriptor: &arkret_sdk::SnapshotChunkDescriptor,
    ) -> anyhow::Result<Vec<u8>> {
        let max_bytes = blob_download_max_bytes_for_declared_size(descriptor.size_bytes)?;
        let bytes = self
            .download_blob_bytes_sdk(descriptor.chunk_ref.as_str(), "download", max_bytes)
            .await?;
        if bytes.len() as u64 > descriptor.size_bytes {
            anyhow::bail!(
                "{}: snapshot chunk response exceeded declared size",
                arkret_sdk::SnapshotValidationCode::DigestMismatch.as_str()
            );
        }
        arkret_sdk::verify_snapshot_chunk_bytes(descriptor, &bytes)
            .map_err(snapshot_validation_error)?;
        Ok(bytes)
    }

    pub async fn download_snapshot_chunk_verified(
        &self,
        descriptor: &arkret_sdk::SnapshotChunkDescriptor,
    ) -> anyhow::Result<arkret_sdk::SnapshotChunkPayload> {
        let bytes = self.download_blob_verified(descriptor).await?;
        arkret_sdk::parse_verified_snapshot_chunk_bytes(descriptor, &bytes)
            .map_err(snapshot_validation_error)
    }

    pub async fn get_file_transfer_blob_bytes(&self, blob_ref: &str) -> anyhow::Result<Vec<u8>> {
        self.download_blob_bytes_sdk(blob_ref, "file_transfer", DEFAULT_BLOB_DOWNLOAD_MAX_BYTES)
            .await
    }

    async fn download_blob_bytes_sdk(
        &self,
        blob_ref: &str,
        purpose: &str,
        max_bytes: usize,
    ) -> anyhow::Result<Vec<u8>> {
        let blob_ref = arkret_sdk::BlobRef::new(canonical_blob_ref(blob_ref).to_owned())
            .map_err(|err| anyhow::anyhow!("invalid blob_ref for /blob/get: {err}"))?;
        let options = arkret_sdk::http_client::BlobDownloadOptions::new()
            .purpose(purpose.to_owned())
            .max_bytes(max_bytes);
        let request_options = self.blob_download_request_options();
        self.sdk_http_client()?
            .blob_download_bytes_with_options(&blob_ref, &options, &request_options)
            .await
            .map_err(anyhow::Error::from)
    }

    fn blob_download_request_options(&self) -> arkret_sdk::http_client::ClientRequestOptions {
        match self.wait_for_sync_token.as_deref() {
            Some(sync_token) => {
                arkret_sdk::http_client::ClientRequestOptions::new().wait_for(sync_token.to_owned())
            }
            None => arkret_sdk::http_client::ClientRequestOptions::new(),
        }
    }
}

fn snapshot_validation_error(error: arkret_sdk::SnapshotValidationError) -> anyhow::Error {
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
