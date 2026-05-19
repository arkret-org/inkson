//! Media blob upload / download helpers (`crypto-media/media-and-blob.md`).
//!
//! Yougen ships a Media classifier already (`media.rs`); this module adds the
//! protocol-level send paths so blob references survive in event payloads
//! with the spec's content-hash typed-id (`cx:blob:sha256:<hex>`).
//!
//! Re-exports the SDK's [`Attachment`] / [`MediaMetadata`] / [`Thumbnail`]
//! structures and provides operation builders for blob register / revoke
//! events. The actual upload bytes go to the Principal Server's
//! `cx.blob.upload` endpoint; this module covers the durable event side.

pub use contrix_sdk::{
    Attachment, AuthenticatedDownloadGrant, DownloadGrantScope, EncryptedAttachment, MediaMetadata,
    Thumbnail, safe_content_disposition, safe_content_type,
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::operation::OperationBuilder;

/// Content-address a blob payload as `cx:blob:sha256:<hex>`.
pub fn blob_typed_id(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("cx:blob:sha256:{digest:x}")
}

/// Build a `cx.blob.register` event body describing an authenticated media
/// upload. Pairs with a server-side `cx.blob.upload` to make the blob
/// retrievable through the durable event chain.
pub fn build_blob_register(
    space_id: &str,
    actor: &str,
    blob_id: &str,
    metadata: &MediaMetadata,
) -> anyhow::Result<OperationBuilder> {
    let metadata_value = serde_json::to_value(metadata)?;
    Ok(OperationBuilder::new(space_id, actor, "cx.blob.register")
        .target_ref(blob_id)
        .body(json!({
            "blob_id": blob_id,
            "metadata": metadata_value,
        })))
}

/// Build a `cx.blob.revoke` event — revokes prior download grants for the
/// referenced blob without deleting the underlying bytes.
pub fn build_blob_revoke(
    space_id: &str,
    actor: &str,
    blob_id: &str,
    reason: Option<&str>,
) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "cx.blob.revoke")
        .target_ref(blob_id)
        .body(json!({
            "blob_id": blob_id,
            "reason": reason,
        }))
}

/// Build a `cx.blob.grant` event — authenticated download grant for a blob.
/// `scope` indicates whether the grant is space-wide, flow-scoped, or
/// per-actor (matches the SDK's [`DownloadGrantScope`]).
pub fn build_blob_grant(
    space_id: &str,
    actor: &str,
    blob_id: &str,
    grant: &AuthenticatedDownloadGrant,
) -> anyhow::Result<OperationBuilder> {
    let grant_value = serde_json::to_value(grant)?;
    Ok(OperationBuilder::new(space_id, actor, "cx.blob.grant")
        .target_ref(blob_id)
        .body(json!({
            "blob_id": blob_id,
            "grant": grant_value,
        })))
}

/// Wrap a [`MediaMetadata`] reference in the canonical event payload shape
/// used by `cx.message.create` attachments. Useful for building chat /
/// timeline event bodies that carry a single attached blob.
pub fn attachment_payload(metadata: &MediaMetadata) -> anyhow::Result<Value> {
    Ok(json!({
        "kind": "cx.content.attachment",
        "metadata": serde_json::to_value(metadata)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_typed_id_is_content_addressed() {
        let a = blob_typed_id(b"hello");
        let b = blob_typed_id(b"hello");
        let c = blob_typed_id(b"world");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("cx:blob:sha256:"));
        // sha256 hex length is 64.
        assert_eq!(a.len(), "cx:blob:sha256:".len() + 64);
    }

    #[test]
    fn blob_revoke_emits_canonical_kind() {
        let op = build_blob_revoke(
            "cx:space:s1",
            "did:web:alice",
            "cx:blob:sha256:dead",
            Some("uploaded in error"),
        )
        .build("node");
        assert_eq!(op.kind, "cx.blob.revoke");
        assert_eq!(op.payload["reason"], "uploaded in error");
    }
}
