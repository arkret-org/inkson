const DEFAULT_BLOB_DOWNLOAD_MAX_BYTES: usize = 64 * 1024 * 1024;

pub const RESUMABLE_UPLOAD_THRESHOLD_BYTES: usize =
    arkret_sdk::http_client::RESUMABLE_UPLOAD_THRESHOLD_BYTES;

pub struct BlobEndpoints<'a> {
    transport: &'a super::TransportClient,
}

impl<'a> BlobEndpoints<'a> {
    pub(crate) fn new(transport: &'a super::TransportClient) -> Self {
        Self { transport }
    }

    pub(crate) fn upload_metadata(
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
        let media_type = (!media_type.trim().is_empty()).then(|| media_type.trim().to_owned());
        Ok(arkret_sdk::models::BlobUploadMetadata {
            realm_id,
            content_digest,
            size_bytes: size_bytes as u64,
            media_type,
            filename: filename.map(ToOwned::to_owned),
            purpose: purpose.map(ToOwned::to_owned),
        })
    }

    pub async fn upload_bytes(
        &self,
        bytes: Vec<u8>,
        content_type: &str,
    ) -> anyhow::Result<crate::models::BlobUploadOutcome> {
        self.upload_bytes_scoped(bytes, content_type, None, None)
            .await
    }

    pub async fn upload_bytes_scoped(
        &self,
        bytes: Vec<u8>,
        content_type: &str,
        realm_id: Option<&str>,
        filename: Option<&str>,
    ) -> anyhow::Result<crate::models::BlobUploadOutcome> {
        let filename = filename.and_then(crate::wire_helpers::safe_blob_filename_header);
        let metadata = Self::upload_metadata(
            bytes.len(),
            content_type,
            realm_id,
            None,
            filename.as_deref(),
            None,
        )?;
        self.transport
            .http()
            .blob_upload_bytes(&metadata, bytes)
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn get_bytes(&self, blob_ref: &str) -> anyhow::Result<Vec<u8>> {
        self.download_bytes(
            blob_ref,
            "message_attachment",
            DEFAULT_BLOB_DOWNLOAD_MAX_BYTES,
        )
        .await
    }

    pub async fn download_snapshot_chunk_verified(
        &self,
        descriptor: &arkret_sdk::SnapshotChunkDescriptor,
    ) -> anyhow::Result<arkret_sdk::SnapshotChunkPayload> {
        let max_bytes = download_max_bytes_for_declared_size(descriptor.size_bytes)?;
        let bytes = self
            .download_bytes(descriptor.chunk_ref.as_str(), "download", max_bytes)
            .await?;
        if bytes.len() as u64 > descriptor.size_bytes {
            anyhow::bail!(
                "{}: snapshot chunk response exceeded declared size",
                arkret_sdk::SnapshotValidationCode::DigestMismatch.as_str()
            );
        }
        arkret_sdk::verify_snapshot_chunk_bytes(descriptor, &bytes)
            .map_err(snapshot_validation_error)?;
        arkret_sdk::parse_verified_snapshot_chunk_bytes(descriptor, &bytes)
            .map_err(snapshot_validation_error)
    }

    pub async fn get_file_transfer_bytes(&self, blob_ref: &str) -> anyhow::Result<Vec<u8>> {
        self.download_bytes(blob_ref, "file_transfer", DEFAULT_BLOB_DOWNLOAD_MAX_BYTES)
            .await
    }

    async fn download_bytes(
        &self,
        blob_ref: &str,
        purpose: &str,
        max_bytes: usize,
    ) -> anyhow::Result<Vec<u8>> {
        let blob_ref =
            arkret_sdk::BlobRef::new(crate::wire_helpers::canonical_blob_ref(blob_ref).to_owned())
                .map_err(|err| anyhow::anyhow!("invalid blob_ref for /blob/get: {err}"))?;
        let options = arkret_sdk::http_client::BlobDownloadOptions::new()
            .purpose(purpose.to_owned())
            .max_bytes(max_bytes);
        self.transport
            .http()
            .blob_download_bytes_with_options(
                &blob_ref,
                &options,
                &self.transport.context().request_options(),
            )
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn resumable_upload_base_url(&self) -> Option<url::Url> {
        let describe = self.transport.describe_cached().await.ok()?;
        arkret_sdk::http_client::blob_resumable_upload_base_url(describe)
    }

    pub async fn upload_file_transfer_ciphertext_auto(
        &self,
        ciphertext: Vec<u8>,
        content_digest: &str,
    ) -> anyhow::Result<crate::models::BlobUploadOutcome> {
        if ciphertext.len() >= RESUMABLE_UPLOAD_THRESHOLD_BYTES
            && let Some(base_url) = self.resumable_upload_base_url().await
        {
            let options = arkret_sdk::http_client::BlobResumableUploadOptions::new()
                .metadata("purpose", "file_transfer")
                .metadata("encrypted", "true")
                .metadata("content_digest", content_digest);
            match self
                .transport
                .http()
                .blob_upload_resumable(base_url, &ciphertext, &options)
                .await
            {
                Ok(outcome) => return Ok(outcome),
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "resumable upload failed; falling back to canonical blob upload"
                    );
                }
            }
        }
        let metadata = Self::upload_metadata(
            ciphertext.len(),
            crate::blob::CIPHERTEXT_MEDIA_TYPE,
            None,
            Some(content_digest),
            None,
            Some("file_transfer"),
        )?;
        self.transport
            .http()
            .blob_upload_bytes(&metadata, ciphertext)
            .await
            .map_err(anyhow::Error::from)
    }
}

fn snapshot_validation_error(error: arkret_sdk::SnapshotValidationError) -> anyhow::Error {
    anyhow::anyhow!("{}: {}", error.code.as_str(), error.message)
}

fn download_max_bytes_for_declared_size(size_bytes: u64) -> anyhow::Result<usize> {
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
        assert_eq!(download_max_bytes_for_declared_size(5).unwrap(), 6);
    }

    #[test]
    fn snapshot_chunk_download_limit_rejects_usize_overflow() {
        let oversized = usize::MAX as u64;
        if usize::try_from(oversized).is_ok() {
            let error = download_max_bytes_for_declared_size(oversized).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("snapshot chunk size_bytes exceeds this platform")
            );
        }
    }
}
