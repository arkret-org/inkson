//! Resumable (tus 1.0.0) blob upload client.
//!
//! Spec: crypto-media/media-and-blob.md §2.1. Discovery is describe-first:
//! the server advertises `ck.feature.blob.resumable_upload.tus.v1` in
//! `supported_features` plus a `kind="tus"` entry in `supported_bindings`;
//! only then does the client speak tus against that binding's `base_url`.
//! No blind endpoint probing.
//!
//! Flow: `POST` create (Upload-Length + Upload-Metadata) → chunked `PATCH`
//! at `Upload-Offset` (resyncing via `HEAD` after a failed chunk) →
//! `POST {upload_url}/finalize`, which returns the same
//! `BlobUploadOutcome` the canonical single-shot upload produces.
//! Any resumable-path failure falls back to the canonical upload — the
//! binding is an optional transport, never a semantic change.

use super::*;

/// Protocol-level feature id the server must advertise (spec §2.1).
pub const RESUMABLE_UPLOAD_FEATURE: &str = "ck.feature.blob.resumable_upload.tus.v1";
/// Ciphertext payloads at or above this size prefer the resumable binding
/// when the server advertises it. Below it the single-shot POST wins on
/// round-trips.
pub const RESUMABLE_UPLOAD_THRESHOLD_BYTES: usize = 2 * 1024 * 1024;
/// PATCH chunk size. One chunk per request keeps memory bounded and makes
/// the resume window small without flooding the server with tiny bodies.
const RESUMABLE_CHUNK_BYTES: usize = 1024 * 1024;
const TUS_VERSION: &str = "1.0.0";
/// Offset-conflict / transport retries per upload before giving up and
/// falling back to the canonical path.
const MAX_CHUNK_RETRIES: usize = 3;

fn b64_metadata_value(value: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
}

impl CokretApi {
    /// Describe-gated tus endpoint discovery. Returns the binding
    /// `base_url` only when the server advertises both the protocol
    /// feature id and a `kind="tus"` binding that covers
    /// `ck.self.blob.upload`.
    pub async fn resumable_upload_base_url(&self) -> Option<Url> {
        let describe = self.describe_cached().await.ok()?;
        if !describe
            .supported_features
            .iter()
            .any(|feature| feature == RESUMABLE_UPLOAD_FEATURE)
        {
            return None;
        }
        let binding = describe
            .supported_bindings
            .iter()
            .find(|binding| binding.get("kind").and_then(Value::as_str) == Some("tus"))?;
        if let Some(operations) = binding.get("operations").and_then(Value::as_array)
            && !operations
                .iter()
                .any(|op| op.as_str() == Some("ck.self.blob.upload"))
        {
            return None;
        }
        let base_url = binding.get("base_url").and_then(Value::as_str)?;
        Url::parse(base_url).ok()
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
            match self
                .upload_resumable(
                    base_url,
                    &ciphertext,
                    &[
                        ("purpose", "file_transfer"),
                        ("encrypted", "true"),
                        ("content_digest", content_digest),
                    ],
                )
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
        self.upload_file_transfer_ciphertext(ciphertext, content_digest)
            .await
    }

    /// Drive one payload through the tus binding: create → PATCH loop →
    /// finalize. `metadata` pairs become `Upload-Metadata` (values base64
    /// per tus); per spec §2.1 they must never include plaintext
    /// filenames/MIME of private or E2EE blobs.
    async fn upload_resumable(
        &self,
        base_url: Url,
        payload: &[u8],
        metadata: &[(&str, &str)],
    ) -> anyhow::Result<BlobUploadOutcome> {
        let upload_metadata = metadata
            .iter()
            .map(|(key, value)| format!("{key} {}", b64_metadata_value(value)))
            .collect::<Vec<_>>()
            .join(",");
        let create = self
            .prepare_request(
                self.http
                    .post(base_url.clone())
                    .header("tus-resumable", TUS_VERSION)
                    .header("upload-length", payload.len().to_string())
                    .header("upload-metadata", upload_metadata),
            )
            .send()
            .await?;
        if create.status() != StatusCode::CREATED {
            anyhow::bail!(
                "resumable upload create failed with status {}",
                create.status()
            );
        }
        let location = create
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| anyhow::anyhow!("resumable upload create returned no Location"))?;
        // Location may be relative (resolved against the binding URL) or
        // absolute.
        let upload_url = base_url
            .join(location)
            .map_err(|err| anyhow::anyhow!("unresolvable upload Location: {err}"))?;

        let mut offset: usize = 0;
        let mut retries = 0usize;
        while offset < payload.len() {
            let end = (offset + RESUMABLE_CHUNK_BYTES).min(payload.len());
            let chunk = payload[offset..end].to_vec();
            let patch = self
                .prepare_request(
                    self.http
                        .patch(upload_url.clone())
                        .header("tus-resumable", TUS_VERSION)
                        .header("content-type", "application/offset+octet-stream")
                        .header("upload-offset", offset.to_string())
                        .body(chunk),
                )
                .send()
                .await;
            let committed = match patch {
                Ok(response) if response.status() == StatusCode::NO_CONTENT => response
                    .headers()
                    .get("upload-offset")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<usize>().ok()),
                Ok(response)
                    if response.status() == StatusCode::CONFLICT
                        || response.status() == StatusCode::NOT_FOUND =>
                {
                    None
                }
                Ok(response) => {
                    anyhow::bail!("resumable chunk failed with status {}", response.status())
                }
                Err(_) => None,
            };
            match committed {
                Some(new_offset) => {
                    offset = new_offset;
                    retries = 0;
                }
                None => {
                    // Offset desync or transport drop — resync via HEAD,
                    // the tus resume primitive.
                    retries += 1;
                    if retries > MAX_CHUNK_RETRIES {
                        anyhow::bail!("resumable upload exceeded chunk retry budget");
                    }
                    offset = self.resumable_committed_offset(&upload_url).await?;
                }
            }
        }

        let finalize_url = Url::parse(&format!("{upload_url}/finalize"))
            .map_err(|err| anyhow::anyhow!("unresolvable finalize URL: {err}"))?;
        let request = self.http.post(finalize_url);
        self.send_json(self.prepare_request(request), Method::POST)
            .await
    }

    /// `HEAD {upload_url}` → committed `Upload-Offset` (tus resume probe).
    async fn resumable_committed_offset(&self, upload_url: &Url) -> anyhow::Result<usize> {
        let response = self
            .prepare_request(
                self.http
                    .head(upload_url.clone())
                    .header("tus-resumable", TUS_VERSION),
            )
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!(
                "resumable upload resume probe failed with status {}",
                response.status()
            );
        }
        response
            .headers()
            .get("upload-offset")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| anyhow::anyhow!("resume probe returned no Upload-Offset"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_values_are_standard_base64() {
        assert_eq!(b64_metadata_value("file_transfer"), "ZmlsZV90cmFuc2Zlcg==");
        assert_eq!(b64_metadata_value("true"), "dHJ1ZQ==");
    }
}
