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
        encryption: Option<arkret_models_collaboration::objects::blob::BlobStorageEncryption>,
    ) -> anyhow::Result<arkret_models_collaboration::objects::blob::BlobUploadMetadata> {
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
        Ok(
            arkret_models_collaboration::objects::blob::BlobUploadMetadata {
                realm_id,
                content_digest,
                size_bytes: size_bytes as u64,
                media_type,
                filename: filename.map(ToOwned::to_owned),
                encryption,
            },
        )
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

    /// Normalize and upload a plaintext long-text body, then build the
    /// hash-addressed `ak.content.long_text` descriptor for a message Event.
    pub async fn upload_plaintext_long_text(
        &self,
        body: &str,
        media_type: arkret_sdk::LongTextMediaType,
        realm_id: &str,
    ) -> anyhow::Result<arkret_sdk::ContentBlock> {
        let normalized = arkret_sdk::normalize_long_text(body)
            .map_err(|error| anyhow::anyhow!("normalize long text: {error}"))?;
        let digest = format!(
            "sha256:{}",
            crate::canonical::sha256_hex(normalized.as_bytes())
        );
        let expected_blob_ref = format!("ak:blob:{digest}");
        let metadata = Self::upload_metadata(
            normalized.len(),
            media_type.as_str(),
            Some(realm_id),
            Some(&digest),
            None,
            None,
        )?;
        let outcome = self
            .transport
            .http()
            .blob_upload_bytes(&metadata, normalized.as_bytes().to_vec())
            .await
            .map_err(anyhow::Error::from)?;
        if outcome.size_bytes != normalized.len() as u64
            || outcome.blob_ref.as_str() != expected_blob_ref
        {
            anyhow::bail!(
                "long-text Blob upload outcome does not match the normalized content commitment"
            );
        }
        arkret_sdk::ContentBlock::plaintext_long_text(
            &normalized,
            media_type,
            expected_blob_ref,
            arkret_sdk::LongTextBodyKind::Prefix,
            None,
        )
        .map_err(|error| anyhow::anyhow!("build long-text content block: {error}"))
    }

    pub async fn get_bytes(&self, blob_ref: &str) -> anyhow::Result<Vec<u8>> {
        self.download_bytes(
            blob_ref,
            "message_attachment",
            DEFAULT_BLOB_DOWNLOAD_MAX_BYTES,
        )
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
        let bytes = self
            .transport
            .http()
            .blob_download_bytes_with_options(
                &blob_ref,
                &options,
                &self.transport.context().request_options(),
            )
            .await
            .map_err(anyhow::Error::from)?;
        verify_content_addressed_blob_bytes(blob_ref.as_str(), &bytes)?;
        Ok(bytes)
    }

    pub async fn resumable_upload_base_url(&self) -> Option<url::Url> {
        let describe = self.transport.describe_cached().await.ok()?;
        arkret_sdk::http_client::blob_resumable_upload_base_url(describe)
    }

    pub async fn upload_file_transfer_ciphertext_auto(
        &self,
        ciphertext: Vec<u8>,
        content_digest: &str,
        principal_control_realm_id: &str,
        encryption: arkret_models_collaboration::objects::blob::BlobStorageEncryption,
    ) -> anyhow::Result<crate::models::BlobUploadOutcome> {
        if ciphertext.len() >= RESUMABLE_UPLOAD_THRESHOLD_BYTES
            && let Some(base_url) = self.resumable_upload_base_url().await
        {
            // Only the storage classification is disclosed for private ciphertext.
            let options =
                arkret_sdk::http_client::BlobResumableUploadOptions::new(Some(encryption));
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
            Some(principal_control_realm_id),
            Some(content_digest),
            None,
            Some(encryption),
        )?;
        self.transport
            .http()
            .blob_upload_bytes(&metadata, ciphertext)
            .await
            .map_err(anyhow::Error::from)
    }
}

fn verify_content_addressed_blob_bytes(blob_ref: &str, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(expected_sha256) = blob_ref.strip_prefix("ak:blob:sha256:")
        && !crate::media::hash_matches(expected_sha256, bytes)
    {
        anyhow::bail!("blob content digest does not match content-addressed blob_ref");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_addressed_download_rejects_digest_mismatch() {
        let bytes = b"authenticated attachment";
        let blob_ref = format!("ak:blob:sha256:{}", crate::canonical::sha256_hex(bytes));
        assert!(verify_content_addressed_blob_bytes(&blob_ref, bytes).is_ok());
        assert!(verify_content_addressed_blob_bytes(&blob_ref, b"tampered").is_err());
    }
}
