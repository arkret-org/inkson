const DEFAULT_BLOB_DOWNLOAD_MAX_BYTES: usize = 64 * 1024 * 1024;

#[cfg(not(target_arch = "wasm32"))]
struct UploadCancellation(std::sync::Arc<std::sync::atomic::AtomicBool>);
#[cfg(not(target_arch = "wasm32"))]
impl Drop for UploadCancellation {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}

pub struct BlobEndpoints<'a> {
    transport: &'a super::TransportClient,
}

impl<'a> BlobEndpoints<'a> {
    /// Canonical multipart consumes only durable, immutable ciphertext parts.
    pub(crate) async fn upload_attachment_object(
        &self,
        object: &crate::attachments::AttachmentObject,
        chunks: crate::state::current_index::AttachmentChunkStore,
    ) -> anyhow::Result<()> {
        use arkret_models_collaboration::objects::blob::{
            BlobStorageEncryption, BlobStorageEncryptionScheme,
        };
        object.validate()?;
        let prepared = object
            .prepared
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("attachment is not durably prepared"))?;
        let encrypted = prepared.descriptor.is_some();
        let digest = prepared
            .blob_ref
            .as_str()
            .strip_prefix("ak:blob:")
            .ok_or_else(|| anyhow::anyhow!("attachment must be content addressed"))?;
        let mut hasher = arkret_sdk::canonical::ContentHasher::new(object.digest_suite);
        let mut size = 0_u64;
        for index in 0..prepared.part_count {
            let part = chunks.read_part("ciphertext", index).await?;
            hasher.update(&part);
            size += part.len() as u64;
        }
        anyhow::ensure!(
            size == prepared.ciphertext_size && hasher.finish() == digest,
            "durable attachment ciphertext commitment differs"
        );
        let mime = if encrypted {
            "application/octet-stream"
        } else {
            &object.media_type
        };
        let filename = if encrypted {
            None
        } else {
            Some(object.filename.as_str())
        };
        let metadata = Self::upload_metadata(
            usize::try_from(size)?,
            mime,
            object.scope.realm_id_opt().map(|r| r.as_str()),
            Some(digest),
            filename,
            if encrypted {
                Some(BlobStorageEncryption {
                    scheme: BlobStorageEncryptionScheme::StreamV1,
                })
            } else {
                None
            },
        )?;
        #[cfg(not(target_arch = "wasm32"))]
        let outcome = {
            let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let _cancel = UploadCancellation(cancelled.clone());
            let stream = futures_util::stream::unfold(
                (chunks, 0_u32, prepared.part_count),
                move |(chunks, index, count)| {
                    let cancelled = cancelled.clone();
                    async move {
                        if index >= count {
                            return None;
                        }
                        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                            return Some((
                                Err(std::io::Error::new(
                                    std::io::ErrorKind::Interrupted,
                                    "attachment upload cancelled",
                                )),
                                (chunks, count, count),
                            ));
                        }
                        let part = chunks
                            .read_part("ciphertext", index)
                            .await
                            .map(|mut part| std::mem::take(&mut *part))
                            .map_err(std::io::Error::other);
                        Some((part, (chunks, index + 1, count)))
                    }
                },
            );
            self.transport
                .http()
                .blob_upload_stream(&metadata, stream)
                .await?
        };
        #[cfg(target_arch = "wasm32")]
        let outcome = {
            let properties = web_sys::BlobPropertyBag::new();
            properties.set_type(mime);
            let mut blob =
                web_sys::Blob::new().map_err(|e| anyhow::anyhow!("browser Blob: {e:?}"))?;
            for index in 0..prepared.part_count {
                let part = chunks.read_part("ciphertext", index).await?;
                let pieces = js_sys::Array::new();
                pieces.push(blob.as_ref());
                pieces.push(js_sys::Uint8Array::from(part.as_slice()).as_ref());
                blob = web_sys::Blob::new_with_blob_sequence_and_options(&pieces, &properties)
                    .map_err(|e| anyhow::anyhow!("browser Blob part: {e:?}"))?;
            }
            self.transport
                .http()
                .blob_upload_browser_blob(&metadata, &blob)
                .await?
        };
        anyhow::ensure!(
            outcome.blob_ref == prepared.blob_ref && outcome.size_bytes == size,
            "attachment upload outcome differs from the frozen commitment"
        );
        Ok(())
    }

    pub(crate) async fn download_attachment_segment(
        &self,
        blob_ref: &arkret_sdk::BlobRef,
        offset: u64,
        length: usize,
    ) -> anyhow::Result<Vec<u8>> {
        let end = offset
            .checked_add(length as u64)
            .and_then(|n| n.checked_sub(1))
            .ok_or_else(|| anyhow::anyhow!("invalid attachment range"))?;
        let options = arkret_sdk::http_client::BlobDownloadOptions::new()
            .purpose("message_attachment")
            .range(format!("bytes={offset}-{end}"))
            .max_bytes(length);
        let response = self
            .transport
            .http()
            .blob_download_response_with_options(
                blob_ref,
                &options,
                &self.transport.context().request_options(),
            )
            .await?;
        anyhow::ensure!(
            response.status() == reqwest::StatusCode::PARTIAL_CONTENT,
            "attachment range was not honored"
        );
        let expected_range = format!("bytes {offset}-{end}/");
        anyhow::ensure!(
            response
                .headers()
                .get(reqwest::header::CONTENT_RANGE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.starts_with(&expected_range)),
            "attachment response range differs"
        );
        use futures_util::StreamExt;
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::with_capacity(length);
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            anyhow::ensure!(
                bytes.len().saturating_add(chunk.len()) <= length,
                "attachment segment is oversized"
            );
            bytes.extend_from_slice(&chunk);
        }
        anyhow::ensure!(bytes.len() == length, "attachment segment is truncated");
        Ok(bytes)
    }
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
        arkret_sdk::RealmId::new(realm_id.to_owned())?;
        let suite = arkret_sdk::DigestSuite::Sha256;
        let digest = arkret_sdk::canonical::digest(suite, normalized.as_bytes());
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
}

fn verify_content_addressed_blob_bytes(blob_ref: &str, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(expected) = blob_ref.strip_prefix("ak:blob:")
        && let Some((suite, _)) = expected.split_once(':')
    {
        anyhow::ensure!(
            arkret_sdk::canonical::digest(arkret_sdk::canonical::digest_suite(suite)?, bytes)
                == expected,
            "blob content digest does not match content-addressed blob_ref"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_addressed_download_rejects_digest_mismatch() {
        let bytes = b"authenticated attachment";
        for suite in [
            arkret_sdk::DigestSuite::Sha256,
            arkret_sdk::DigestSuite::Blake3,
        ] {
            let blob_ref = format!("ak:blob:{}", arkret_sdk::canonical::digest(suite, bytes));
            assert!(verify_content_addressed_blob_bytes(&blob_ref, bytes).is_ok());
            assert!(verify_content_addressed_blob_bytes(&blob_ref, b"tampered").is_err());
        }
        assert!(verify_content_addressed_blob_bytes("ak:blob:unknown:abcd", bytes).is_err());
    }
}
