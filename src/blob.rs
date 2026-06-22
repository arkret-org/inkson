//! Media blob upload / download helpers (`crypto-media/media-and-blob.md`).
//!
//! Yougen ships a Media classifier already (`media.rs`); this module adds the
//! protocol-level send paths so blob references survive in event payloads
//! with the spec's content-hash typed-id (`ck:blob:sha256:<hex>`).
//!
//! Re-exports the SDK's [`Attachment`] / [`MediaMetadata`] / [`Thumbnail`]
//! structures and provides operation builders for blob register / revoke
//! events. The actual upload bytes go to the Principal Server's
//! `ck.self.blob.upload.create` endpoint; this module covers the durable event side.
//!
//! # Attachment AEAD is the SDK's canonical codec
//!
//! All client-side attachment encryption is delegated to
//! [`cokret_sdk::blob_aead`], the canonical implementation of
//! `ck.blob.stream_aead.v1` (chunked streaming AEAD) and
//! `ck.blob.whole_file_aead.v1` (whole-file AEAD). Yougen no longer ships a
//! private XChaCha envelope or its own nonce derivation; the
//! `mls_exported_secret` (32 bytes from the MLS exporter) is passed straight
//! through as the SDK `content_key`. The envelope carried on the wire is the
//! SDK's [`EncryptedAttachmentEnvelope`], whose serde shape is exactly
//! `blob.schema.json#/$defs/encrypted_attachment`.

use cokret_sdk::blob_aead::{
    self, DEFAULT_SEGMENT_SIZE, EncryptedAttachmentEnvelope, StreamEncryptParams,
};
pub use cokret_sdk::{
    Attachment, AuthenticatedDownloadGrant, DownloadGrantScope, EncryptedAttachment, KeyRefObject,
    MediaMetadata, Thumbnail, safe_content_disposition, safe_content_type,
};
use serde_json::{Value, json};
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
/// canonical [`EncryptedAttachmentEnvelope`] (SDK / spec wire shape) with its
/// `blob_ref` already content-addressed over the ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedClientAsset {
    pub ciphertext: Vec<u8>,
    pub envelope: EncryptedAttachmentEnvelope,
}

impl EncryptedClientAsset {
    /// `<algo>:<hex>` digest the SDK already recorded over the ciphertext.
    pub fn ciphertext_digest(&self) -> &str {
        &self.envelope.ciphertext_digest
    }

    /// Content-addressed blob reference (`ck:blob:sha256:<hex>`).
    pub fn blob_ref(&self) -> &str {
        &self.envelope.blob_ref
    }
}

/// A full-resolution attachment plus its optional independently-keyed
/// thumbnail. Per spec §3.3.4 the thumbnail always uses the whole-file scheme.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedAttachmentBundle {
    pub attachment: EncryptedClientAsset,
    pub thumbnail: Option<EncryptedClientAsset>,
}

/// Content-address a blob payload as `ck:blob:sha256:<hex>`.
pub fn blob_typed_id(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("ck:blob:sha256:{}", crate::canonical::hex_encode(&digest))
}

/// Finish an SDK encrypt: content-address the ciphertext and stamp the
/// resulting `ck:blob:sha256:<hex>` into the envelope's `blob_ref`.
fn finish_asset(
    ciphertext: Vec<u8>,
    mut envelope: EncryptedAttachmentEnvelope,
) -> EncryptedClientAsset {
    envelope.blob_ref = blob_typed_id(&ciphertext);
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
    key_ref: &KeyRefObject,
    media_type: &str,
    force_whole_file: bool,
) -> anyhow::Result<EncryptedClientAsset> {
    let (ciphertext, envelope) =
        if !force_whole_file && plaintext.len() > STREAM_ATTACHMENT_THRESHOLD {
            let params = StreamEncryptParams {
                key_ref: key_ref.clone(),
                epoch,
                media_type: media_type.to_owned(),
                segment_size: DEFAULT_SEGMENT_SIZE,
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
    hasher.update(b"cokret-thumbnail-content-key-v1\0");
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

/// Encrypt a full-resolution attachment (plus an optional thumbnail) against
/// the SDK's canonical AEAD codec.
///
/// `mls_exported_secret` is the 32-byte MLS-exporter content key. The body
/// attachment uses it as the SDK `content_key`; the thumbnail derives a
/// separate content key bound to the source ciphertext blob ref. The body
/// attachment picks stream vs whole-file by size
/// ([`STREAM_ATTACHMENT_THRESHOLD`]); the thumbnail is always whole-file (spec
/// §3.3.4). `media_type` is the *plaintext* media type recorded in the
/// AAD-bound envelope; `thumbnail_media_type` defaults to `image/jpeg` when
/// `None`.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_mls_attachment_bundle(
    attachment_plaintext: &[u8],
    thumbnail_plaintext: Option<&[u8]>,
    mls_exported_secret: &[u8; MLS_ATTACHMENT_KEY_LEN],
    epoch: u64,
    key_ref: KeyRefObject,
    media_type: &str,
    thumbnail_media_type: Option<&str>,
) -> anyhow::Result<EncryptedAttachmentBundle> {
    let attachment = encrypt_asset(
        attachment_plaintext,
        mls_exported_secret,
        epoch,
        &key_ref,
        media_type,
        false,
    )?;
    let thumbnail_media_type = thumbnail_media_type.unwrap_or("image/jpeg");
    let thumbnail_key = derive_thumbnail_content_key(
        mls_exported_secret,
        attachment.blob_ref(),
        epoch,
        thumbnail_media_type,
    );
    let thumbnail = thumbnail_plaintext
        .map(|bytes| {
            encrypt_asset(
                bytes,
                &thumbnail_key,
                epoch,
                &key_ref,
                thumbnail_media_type,
                // Thumbnails are always whole-file (spec §3.3.4).
                true,
            )
        })
        .transpose()?;
    Ok(EncryptedAttachmentBundle {
        attachment,
        thumbnail,
    })
}

/// Encrypt a single MLS attachment asset (body media), choosing stream vs
/// whole-file by size. Thin wrapper over the SDK codec for callers that do not
/// also produce a thumbnail.
pub fn encrypt_mls_asset(
    plaintext: &[u8],
    mls_exported_secret: &[u8; MLS_ATTACHMENT_KEY_LEN],
    epoch: u64,
    key_ref: KeyRefObject,
    media_type: &str,
) -> anyhow::Result<EncryptedClientAsset> {
    encrypt_asset(
        plaintext,
        mls_exported_secret,
        epoch,
        &key_ref,
        media_type,
        false,
    )
}

// YOU-01-011: the former `ck.blob.register` / `ck.blob.revoke` /
// `ck.blob.grant` event builders were removed — none of those kinds is in
// the spec event-kind-registry, and unregistered wire kinds must not be
// mintable from client code. Re-add once the kinds are registered via CKP.

/// Wrap a [`MediaMetadata`] reference in the canonical event payload shape
/// used by `ck.message.create` attachments. Useful for building chat /
/// message event bodies that carry a single attached blob.
pub fn attachment_payload(metadata: &MediaMetadata) -> anyhow::Result<Value> {
    Ok(json!({
        "kind": "ck.content.attachment",
        "metadata": serde_json::to_value(metadata)?,
    }))
}

#[cfg(test)]
mod tests {
    use cokret_sdk::blob_aead::{
        SCHEME_STREAM, SCHEME_WHOLE_FILE, decrypt_stream, decrypt_whole_file,
    };

    use super::*;

    #[test]
    fn blob_typed_id_is_content_addressed() {
        let a = blob_typed_id(b"hello");
        let b = blob_typed_id(b"hello");
        let c = blob_typed_id(b"world");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("ck:blob:sha256:"));
        // sha256 hex length is 64.
        assert_eq!(a.len(), "ck:blob:sha256:".len() + 64);
    }

    fn test_key_ref() -> KeyRefObject {
        KeyRefObject {
            algorithm: "MLS".to_owned(),
            group_state_ref: "ck:event:01964148-0000-7000-8000-000000000000".to_owned(),
        }
    }

    #[test]
    fn small_attachment_uses_whole_file_and_roundtrips() {
        let key = [7u8; MLS_ATTACHMENT_KEY_LEN];
        let plaintext = b"plain cat png bytes";
        let asset = encrypt_mls_asset(plaintext, &key, 42, test_key_ref(), "image/png").unwrap();

        assert_ne!(asset.ciphertext.as_slice(), plaintext.as_slice());
        assert_eq!(asset.envelope.scheme, SCHEME_WHOLE_FILE);
        assert_eq!(asset.blob_ref(), blob_typed_id(&asset.ciphertext));
        assert_eq!(
            asset.ciphertext_digest(),
            format!(
                "sha256:{}",
                crate::canonical::hex_encode(&Sha256::digest(&asset.ciphertext))
            )
        );
        // ciphertext-only metadata: no plaintext filename / media type leaks
        // into the wire envelope.
        let wire = serde_json::to_string(&asset.envelope).unwrap();
        assert!(!wire.contains("cat.png"));

        let recovered = decrypt_whole_file(&asset.ciphertext, &asset.envelope, &key).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn large_attachment_uses_stream_and_roundtrips() {
        let key = [5u8; MLS_ATTACHMENT_KEY_LEN];
        // Strictly larger than one segment so the streaming scheme kicks in.
        let plaintext: Vec<u8> = (0..(STREAM_ATTACHMENT_THRESHOLD + 1024))
            .map(|i| (i % 251) as u8)
            .collect();
        let asset = encrypt_mls_asset(&plaintext, &key, 9, test_key_ref(), "video/mp4").unwrap();

        assert_eq!(asset.envelope.scheme, SCHEME_STREAM);
        assert_eq!(asset.envelope.segment_size, Some(DEFAULT_SEGMENT_SIZE));
        assert!(asset.envelope.segment_count.unwrap() >= 2);
        assert_eq!(asset.blob_ref(), blob_typed_id(&asset.ciphertext));

        let recovered = decrypt_stream(&asset.ciphertext, &asset.envelope, &key).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn thumbnail_is_always_whole_file_and_independent() {
        let key = [9u8; MLS_ATTACHMENT_KEY_LEN];
        // Make the body large enough to be a stream, while the thumbnail must
        // still be whole-file even if it were also large.
        let body: Vec<u8> = vec![1u8; STREAM_ATTACHMENT_THRESHOLD + 4096];
        let thumb: Vec<u8> = vec![2u8; STREAM_ATTACHMENT_THRESHOLD + 4096];
        let bundle = encrypt_mls_attachment_bundle(
            &body,
            Some(&thumb),
            &key,
            7,
            test_key_ref(),
            "video/mp4",
            Some("image/jpeg"),
        )
        .unwrap();
        let thumbnail = bundle.thumbnail.as_ref().expect("thumbnail encrypted");

        assert_eq!(bundle.attachment.envelope.scheme, SCHEME_STREAM);
        // §3.3.4: thumbnail always whole-file regardless of size.
        assert_eq!(thumbnail.envelope.scheme, SCHEME_WHOLE_FILE);
        // Independent ciphertexts / blob refs.
        assert_ne!(bundle.attachment.ciphertext, thumbnail.ciphertext);
        assert_ne!(bundle.attachment.blob_ref(), thumbnail.blob_ref());
        assert_ne!(
            bundle.attachment.ciphertext_digest(),
            thumbnail.ciphertext_digest()
        );

        // ciphertext-only metadata: the wire transport media type is opaque,
        // but the envelope records the plaintext media type for the receiver.
        assert_eq!(thumbnail.envelope.media_type, "image/jpeg");
        assert!(decrypt_whole_file(&thumbnail.ciphertext, &thumbnail.envelope, &key).is_err());
        let thumbnail_key =
            derive_thumbnail_content_key(&key, bundle.attachment.blob_ref(), 7, "image/jpeg");
        assert_ne!(thumbnail_key, key);
        let recovered = decrypt_whole_file(
            &thumbnail.ciphertext,
            &thumbnail.envelope,
            &thumbnail_key,
        )
        .unwrap();
        assert_eq!(recovered, thumb);
    }

    #[test]
    fn bundle_without_thumbnail_leaves_it_unset() {
        let key = [3u8; MLS_ATTACHMENT_KEY_LEN];
        let bundle = encrypt_mls_attachment_bundle(
            b"small body",
            None,
            &key,
            1,
            test_key_ref(),
            "text/plain",
            None,
        )
        .unwrap();
        assert!(bundle.thumbnail.is_none());
        assert_eq!(bundle.attachment.envelope.scheme, SCHEME_WHOLE_FILE);
        assert_eq!(bundle.attachment.envelope.key_ref, test_key_ref());
    }
}
