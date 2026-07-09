//! Resumable (tus 1.0.0) blob upload client.
//!
//! Spec: crypto-media/media-and-blob.md §2.1. Discovery is describe-first:
//! the server advertises `ck.feature.blob.resumable_upload.tus.v1` in
//! `supported_features` plus a `kind="tus"` entry in `supported_bindings`;
//! only then does the client speak tus against that binding's `base_url`.
//! No blind endpoint probing.
//!
//! Strand: `POST` create (Upload-Length + Upload-Metadata) → chunked `PATCH`
//! at `Upload-Offset` (resyncing via `HEAD` after a failed chunk) →
//! `POST {upload_url}/finalize`, which returns the same
//! `BlobUploadOutcome` the canonical single-shot upload produces.
//! Any resumable-path failure falls back to the canonical upload — the
//! binding is an optional transport, never a semantic change.

use super::*;

/// Ciphertext payloads at or above this size prefer the resumable binding
/// when the server advertises it. Below it the single-shot POST wins on
/// round-trips.
pub const RESUMABLE_UPLOAD_THRESHOLD_BYTES: usize =
    arkret_sdk::http_client::RESUMABLE_UPLOAD_THRESHOLD_BYTES;

impl CokretApi {
    /// Describe-gated tus endpoint discovery. Returns the binding
    /// `base_url` only when the server advertises both the protocol
    /// feature id and a `kind="tus"` binding that covers
    /// `ck.self.blob.upload.create`.
    pub async fn resumable_upload_base_url(&self) -> Option<Url> {
        let describe = self.describe_cached().await.ok()?;
        arkret_sdk::http_client::blob_resumable_upload_base_url(describe)
    }

    /// File-transfer ciphertext upload with automatic resumable/canonical
    /// dispatch: large payloads take the tus binding when the server
    /// advertises it, and any resumable failure falls back to the
    /// canonical single-shot POST. The returned outcome is shape-identical
    /// either way (content-addressing invariant, spec §2.1).
    pub async fn upload_file_transfer_ciphertext_auto(
        &self,
        ciphertext: Vec<u8>,
        content_digest: &str,
    ) -> anyhow::Result<BlobUploadOutcome> {
        if ciphertext.len() >= RESUMABLE_UPLOAD_THRESHOLD_BYTES
            && let Some(base_url) = self.resumable_upload_base_url().await
        {
            let options = arkret_sdk::http_client::BlobResumableUploadOptions::new()
                .metadata("purpose", "file_transfer")
                .metadata("encrypted", "true")
                .metadata("content_digest", content_digest);
            match self
                .sdk_http_client()?
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
}
