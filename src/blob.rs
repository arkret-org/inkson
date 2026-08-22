//! Media blob upload / download helpers (`crypto-media/media-and-blob.md`).
//!
//! Inkson ships a Media classifier already (`media.rs`); this module adds the
//! protocol-level send paths so blob references survive in event payloads
//! with the spec's content-hash typed-id (`ak:blob:sha256:<hex>`).
//!
//! The actual upload bytes go to the Principal Server's
//! `ak.self.blob.upload.create` endpoint; this module covers client-side
//! encryption and content addressing.
//!
//! # Attachment AEAD is the SDK's canonical codec
//!
//! All client-side attachment encryption is delegated to
//! [`arkret_crypto::blob_aead`], the canonical implementation of
//! `ak.blob.stream_aead.v1` (chunked streaming AEAD) and
//! `ak.blob.whole_file_aead.v1` (whole-file AEAD). Inkson no longer ships a
//! private XChaCha envelope or its own nonce derivation; the
//! `mls_exported_secret` (32 bytes from the MLS exporter) is passed straight
//! through as the SDK `content_key`. The envelope carried on the wire is the
//! SDK's [`arkret_models_crypto::EncryptedAttachment`], whose serde shape is exactly
//! `blob.schema.json#/$defs/encrypted_attachment`.

use arkret_crypto::blob_aead::{self, DEFAULT_SEGMENT_SIZE, StreamEncryptParams};
use arkret_models_crypto::EncryptedAttachment;
pub use arkret_sdk::EncryptedAttachmentKeyRef;
use sha2::{Digest, Sha256};

/// MLS exporter content-key length (XChaCha20-Poly1305 key).
pub const MLS_ATTACHMENT_KEY_LEN: usize = 32;
/// Ciphertext is opaque octet-stream on the wire; the plaintext media type is
/// recorded inside the (encrypted-AAD-bound) envelope, never in the blob's
/// transport `content-type`.
pub const CIPHERTEXT_MEDIA_TYPE: &str = "application/octet-stream";

/// Plaintext sizes at or below this go whole-file; larger attachments use the
/// chunked streaming scheme so a multi-MiB upload/download can be processed
/// segment-by-segment (Range / progressive playback) instead of buffered
/// whole. Equal to the SDK's `DEFAULT_SEGMENT_SIZE` (256 KiB): a payload that
/// fits in a single stream segment gains nothing from the streaming framing,
/// so it stays whole-file.
pub const STREAM_ATTACHMENT_THRESHOLD: usize = DEFAULT_SEGMENT_SIZE as usize;

/// A single encrypted asset ready for upload: the ciphertext bytes plus the
/// canonical [`EncryptedAttachment`] (SDK / spec wire shape) with its
/// `blob_ref` already content-addressed over the ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedClientAsset {
    pub ciphertext: Vec<u8>,
    pub envelope: EncryptedAttachment,
}

impl EncryptedClientAsset {
    /// `<algo>:<hex>` digest the SDK already recorded over the ciphertext.
    pub fn ciphertext_digest(&self) -> &str {
        match &self.envelope {
            EncryptedAttachment::WholeFile(envelope) => envelope.ciphertext_digest.as_str(),
            EncryptedAttachment::Stream(envelope) => envelope.ciphertext_digest.as_str(),
        }
    }

    /// Content-addressed blob reference (`ak:blob:sha256:<hex>`).
    pub fn blob_ref(&self) -> &str {
        match &self.envelope {
            EncryptedAttachment::WholeFile(envelope) => envelope.blob_ref.as_str(),
            EncryptedAttachment::Stream(envelope) => envelope.blob_ref.as_str(),
        }
    }

    #[cfg(test)]
    fn scheme(&self) -> &'static str {
        match self.envelope {
            EncryptedAttachment::WholeFile(_) => arkret_wire::BLOB_SCHEME_WHOLE_FILE_AEAD_V1,
            EncryptedAttachment::Stream(_) => arkret_wire::BLOB_SCHEME_STREAM_AEAD_V1,
        }
    }

    #[cfg(test)]
    fn segment_bytes(&self) -> Option<u64> {
        match &self.envelope {
            EncryptedAttachment::WholeFile(_) => None,
            EncryptedAttachment::Stream(envelope) => Some(envelope.segment_bytes),
        }
    }

    #[cfg(test)]
    fn segment_count(&self) -> Option<u64> {
        match &self.envelope {
            EncryptedAttachment::WholeFile(_) => None,
            EncryptedAttachment::Stream(envelope) => Some(envelope.segment_count),
        }
    }

    #[cfg(test)]
    fn media_type(&self) -> &str {
        match &self.envelope {
            EncryptedAttachment::WholeFile(envelope) => &envelope.media_type,
            EncryptedAttachment::Stream(envelope) => &envelope.media_type,
        }
    }
}

/// A full-resolution attachment plus its optional independently-keyed
/// thumbnail. Per spec §3.3.4 the thumbnail always uses the whole-file scheme.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedAttachmentBundle {
    pub attachment: EncryptedClientAsset,
    pub thumbnail: Option<EncryptedClientAsset>,
}

/// Content-address a blob payload as `ak:blob:sha256:<hex>`.
pub fn blob_typed_id(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("ak:blob:sha256:{}", crate::canonical::hex_encode(&digest))
}

/// Finish an SDK encrypt: content-address the ciphertext and stamp the
/// resulting `ak:blob:sha256:<hex>` into the envelope's `blob_ref`.
fn finish_asset(ciphertext: Vec<u8>, envelope: EncryptedAttachment) -> EncryptedClientAsset {
    debug_assert_eq!(
        match &envelope {
            EncryptedAttachment::WholeFile(value) => value.blob_ref.as_str(),
            EncryptedAttachment::Stream(value) => value.blob_ref.as_str(),
        },
        blob_typed_id(&ciphertext)
    );
    EncryptedClientAsset {
        ciphertext,
        envelope,
    }
}

/// Encrypt one attachment asset, choosing the scheme by size.
///
/// `force_whole_file` pins the whole-file scheme regardless of size — used for
/// thumbnails, which spec §3.3.4 always carries whole-file. The plaintext
/// `media_type` is recorded inside the envelope only (AAD-bound), never on the
/// transport.
fn encrypt_asset(
    plaintext: &[u8],
    content_key: &[u8; MLS_ATTACHMENT_KEY_LEN],
    epoch: u64,
    key_ref: &EncryptedAttachmentKeyRef,
    media_type: &str,
    force_whole_file: bool,
) -> anyhow::Result<EncryptedClientAsset> {
    let (ciphertext, envelope) =
        if !force_whole_file && plaintext.len() > STREAM_ATTACHMENT_THRESHOLD {
            let params = StreamEncryptParams {
                key_ref: key_ref.clone(),
                epoch,
                media_type: media_type.to_owned(),
                segment_bytes: DEFAULT_SEGMENT_SIZE,
            };
            blob_aead::encrypt_stream(plaintext, content_key, &params)
                .map_err(|err| anyhow::anyhow!("stream attachment encrypt: {err}"))?
        } else {
            blob_aead::encrypt_whole_file(
                plaintext,
                content_key,
                key_ref.clone(),
                epoch,
                media_type.to_owned(),
            )
            .map_err(|err| anyhow::anyhow!("whole-file attachment encrypt: {err}"))?
        };
    Ok(finish_asset(ciphertext, envelope))
}

fn derive_thumbnail_content_key(
    mls_exported_secret: &[u8; MLS_ATTACHMENT_KEY_LEN],
    source_blob_ref: &str,
    epoch: u64,
    thumbnail_media_type: &str,
) -> [u8; MLS_ATTACHMENT_KEY_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(b"arkret-thumbnail-content-key-v1\0");
    hasher.update(mls_exported_secret);
    hasher.update(b"\0source_blob_ref\0");
    hasher.update(source_blob_ref.as_bytes());
    hasher.update(b"\0epoch\0");
    hasher.update(epoch.to_be_bytes());
    hasher.update(b"\0media_type\0");
    hasher.update(thumbnail_media_type.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; MLS_ATTACHMENT_KEY_LEN];
    key.copy_from_slice(&digest);
    key
}

// YOU-01-011: the former `ak.blob.register` / `ak.blob.revoke` /
// `ak.blob.grant` event builders were removed — none of those kinds is in
// the spec event-kind-registry, and unregistered wire kinds must not be
// mintable from client code. Re-add once the kinds are registered via AKP.

#[cfg(test)]
mod tests {
    use arkret_crypto::blob_aead::{decrypt_stream, decrypt_whole_file};
    use arkret_wire::{BLOB_SCHEME_STREAM_AEAD_V1, BLOB_SCHEME_WHOLE_FILE_AEAD_V1};

    use super::*;

    #[test]
    fn blob_typed_id_is_content_addressed() {
        let a = blob_typed_id(b"hello");
        let b = blob_typed_id(b"hello");
        let c = blob_typed_id(b"world");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("ak:blob:sha256:"));
        // sha256 hex length is 64.
        assert_eq!(a.len(), "ak:blob:sha256:".len() + 64);
    }

    fn test_key_ref() -> EncryptedAttachmentKeyRef {
        EncryptedAttachmentKeyRef {
            algorithm: arkret_sdk::EncryptedAttachmentKeyAlgorithm::Mls,
            group_state_ref: arkret_sdk::EncryptedAttachmentGroupStateRef::Event(
                arkret_sdk::EventId::new(
                    "ak:event:AQNy1zG98lAoTz0YOf-2Yp2-GXeJioPlyg8nW6qxW-OB".to_owned(),
                )
                .unwrap(),
            ),
        }
    }
}
