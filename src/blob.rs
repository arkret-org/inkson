//! Media blob upload / download helpers (`crypto-media/media-and-blob.md`).
//!
//! Yougen ships a Media classifier already (`media.rs`); this module adds the
//! protocol-level send paths so blob references survive in event payloads
//! with the spec's content-hash typed-id (`ck:blob:sha256:<hex>`).
//!
//! Re-exports the SDK's [`Attachment`] / [`MediaMetadata`] / [`Thumbnail`]
//! structures and provides operation builders for blob register / revoke
//! events. The actual upload bytes go to the Principal Server's
//! `ck.blob.upload` endpoint; this module covers the durable event side.

use anyhow::anyhow;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
pub use cokret_sdk::{
    Attachment, AuthenticatedDownloadGrant, DownloadGrantScope, EncryptedAttachment, MediaMetadata,
    Thumbnail, safe_content_disposition, safe_content_type,
};
use getrandom::fill;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::operation::OperationBuilder;

pub const MLS_ATTACHMENT_AEAD_ALGORITHM: &str = "mls-rfc9420+xchacha20poly1305";
pub const MLS_ATTACHMENT_NONCE_LEN: usize = 24;
pub const MLS_ATTACHMENT_KEY_LEN: usize = 32;
pub const CIPHERTEXT_MEDIA_TYPE: &str = "application/octet-stream";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedClientAsset {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; MLS_ATTACHMENT_NONCE_LEN],
    pub ciphertext_digest: String,
    pub aad: String,
    pub envelope: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedAttachmentBundle {
    pub attachment: EncryptedClientAsset,
    pub thumbnail: Option<EncryptedClientAsset>,
}

/// Content-address a blob payload as `ck:blob:sha256:<hex>`.
pub fn blob_typed_id(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("ck:blob:sha256:{digest:x}")
}

/// Build a `ck.blob.register` event body describing an authenticated media
/// upload. Pairs with a server-side `ck.blob.upload` to make the blob
/// retrievable through the durable event chain.
pub fn build_blob_register(
    space_id: &str,
    actor: &str,
    blob_id: &str,
    metadata: &MediaMetadata,
) -> anyhow::Result<OperationBuilder> {
    let metadata_value = serde_json::to_value(metadata)?;
    Ok(OperationBuilder::new(space_id, actor, "ck.blob.register")
        .target_ref(blob_id)
        .body(json!({
            "blob_id": blob_id,
            "metadata": metadata_value,
        })))
}

/// Build a `ck.blob.revoke` event — revokes prior download grants for the
/// referenced blob without deleting the underlying bytes.
pub fn build_blob_revoke(
    space_id: &str,
    actor: &str,
    blob_id: &str,
    reason: Option<&str>,
) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "ck.blob.revoke")
        .target_ref(blob_id)
        .body(json!({
            "blob_id": blob_id,
            "reason": reason,
        }))
}

/// Build a `ck.blob.grant` event — authenticated download grant for a blob.
/// `scope` indicates whether the grant is space-wide, flow-scoped, or
/// per-actor (matches the SDK's [`DownloadGrantScope`]).
pub fn build_blob_grant(
    space_id: &str,
    actor: &str,
    blob_id: &str,
    grant: &AuthenticatedDownloadGrant,
) -> anyhow::Result<OperationBuilder> {
    let grant_value = serde_json::to_value(grant)?;
    Ok(OperationBuilder::new(space_id, actor, "ck.blob.grant")
        .target_ref(blob_id)
        .body(json!({
            "blob_id": blob_id,
            "grant": grant_value,
        })))
}

/// Wrap a [`MediaMetadata`] reference in the canonical event payload shape
/// used by `ck.message.create` attachments. Useful for building chat /
/// timeline event bodies that carry a single attached blob.
pub fn attachment_payload(metadata: &MediaMetadata) -> anyhow::Result<Value> {
    Ok(json!({
        "kind": "ck.content.attachment",
        "metadata": serde_json::to_value(metadata)?,
    }))
}

pub fn encrypt_mls_attachment_bundle(
    attachment_plaintext: &[u8],
    thumbnail_plaintext: Option<&[u8]>,
    mls_exported_secret: &[u8; MLS_ATTACHMENT_KEY_LEN],
    realm_id: &str,
    epoch: u64,
    key_ref: Value,
) -> anyhow::Result<EncryptedAttachmentBundle> {
    let attachment = encrypt_mls_asset(
        attachment_plaintext,
        "attachment",
        mls_exported_secret,
        realm_id,
        epoch,
        key_ref.clone(),
    )?;
    let thumbnail = thumbnail_plaintext
        .map(|bytes| {
            encrypt_mls_asset(
                bytes,
                "thumbnail",
                mls_exported_secret,
                realm_id,
                epoch,
                key_ref.clone(),
            )
        })
        .transpose()?;
    Ok(EncryptedAttachmentBundle {
        attachment,
        thumbnail,
    })
}

pub fn encrypt_mls_asset(
    plaintext: &[u8],
    asset_kind: &str,
    mls_exported_secret: &[u8; MLS_ATTACHMENT_KEY_LEN],
    realm_id: &str,
    epoch: u64,
    key_ref: Value,
) -> anyhow::Result<EncryptedClientAsset> {
    let mut nonce = [0u8; MLS_ATTACHMENT_NONCE_LEN];
    fill(&mut nonce).map_err(|err| anyhow!("attachment nonce rng: {err}"))?;
    encrypt_mls_asset_with_nonce(
        plaintext,
        asset_kind,
        mls_exported_secret,
        realm_id,
        epoch,
        key_ref,
        nonce,
    )
}

fn encrypt_mls_asset_with_nonce(
    plaintext: &[u8],
    asset_kind: &str,
    mls_exported_secret: &[u8; MLS_ATTACHMENT_KEY_LEN],
    realm_id: &str,
    epoch: u64,
    key_ref: Value,
    nonce: [u8; MLS_ATTACHMENT_NONCE_LEN],
) -> anyhow::Result<EncryptedClientAsset> {
    if realm_id.trim().is_empty() {
        anyhow::bail!("realm_id is required for encrypted attachment AAD");
    }
    if !key_ref.is_object() && !key_ref.is_string() {
        anyhow::bail!("key_ref must be an MLS key reference object or string");
    }
    let asset_kind = match asset_kind {
        "attachment" | "thumbnail" => asset_kind,
        _ => anyhow::bail!("asset_kind must be attachment or thumbnail"),
    };
    let aad = format!("cokret:media:v1:{realm_id}:{epoch}:{asset_kind}");
    let cipher = XChaCha20Poly1305::new(mls_exported_secret.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|err| anyhow!("xchacha20poly1305 attachment encrypt: {err}"))?;
    let ciphertext_digest = format!("sha256:{:x}", Sha256::digest(&ciphertext));
    let envelope = json!({
        "version": "cokret.encrypted_attachment.v1",
        "algorithm": MLS_ATTACHMENT_AEAD_ALGORITHM,
        "nonce": URL_SAFE_NO_PAD.encode(nonce),
        "key_ref": key_ref,
        "ciphertext_digest": ciphertext_digest,
        "media_type": CIPHERTEXT_MEDIA_TYPE,
        "realm_id": realm_id,
        "epoch": epoch,
    });
    Ok(EncryptedClientAsset {
        ciphertext,
        nonce,
        ciphertext_digest,
        aad,
        envelope,
    })
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
        assert!(a.starts_with("ck:blob:sha256:"));
        // sha256 hex length is 64.
        assert_eq!(a.len(), "ck:blob:sha256:".len() + 64);
    }

    #[test]
    fn blob_revoke_emits_canonical_kind() {
        let op = build_blob_revoke(
            "ck:space:s1",
            "did:web:alice",
            "ck:blob:sha256:dead",
            Some("uploaded in error"),
        )
        .build("node");
        assert_eq!(op.kind, "ck.blob.revoke");
        assert_eq!(op.payload["reason"], "uploaded in error");
    }

    #[test]
    fn encrypt_mls_attachment_asset_uses_ciphertext_only_metadata() {
        let key = [7u8; MLS_ATTACHMENT_KEY_LEN];
        let nonce = [3u8; MLS_ATTACHMENT_NONCE_LEN];
        let asset = encrypt_mls_asset_with_nonce(
            b"plain cat png bytes",
            "attachment",
            &key,
            "ck:realm:encrypted",
            42,
            json!({"group_id": "ck:mls:group", "epoch": 42}),
            nonce,
        )
        .unwrap();

        assert_ne!(asset.ciphertext, b"plain cat png bytes");
        assert_eq!(
            asset.ciphertext_digest,
            format!("sha256:{:x}", Sha256::digest(&asset.ciphertext))
        );
        assert_eq!(asset.envelope["algorithm"], MLS_ATTACHMENT_AEAD_ALGORITHM);
        assert_eq!(asset.envelope["media_type"], CIPHERTEXT_MEDIA_TYPE);
        assert_eq!(asset.envelope["ciphertext_digest"], asset.ciphertext_digest);
        let envelope = asset.envelope.to_string();
        assert!(!envelope.contains("cat.png"));
        assert!(!envelope.contains("image/png"));

        let cipher = XChaCha20Poly1305::new((&key).into());
        let decrypted = cipher
            .decrypt(
                XNonce::from_slice(&asset.nonce),
                Payload {
                    msg: &asset.ciphertext,
                    aad: asset.aad.as_bytes(),
                },
            )
            .unwrap();
        assert_eq!(decrypted, b"plain cat png bytes");
    }

    #[test]
    fn encrypt_mls_attachment_bundle_encrypts_thumbnail_as_separate_asset() {
        let key = [9u8; MLS_ATTACHMENT_KEY_LEN];
        let bundle = encrypt_mls_attachment_bundle(
            b"full-resolution plaintext",
            Some(b"thumbnail plaintext"),
            &key,
            "ck:realm:encrypted",
            7,
            json!({"group_id": "ck:mls:group", "epoch": 7}),
        )
        .unwrap();
        let thumbnail = bundle.thumbnail.as_ref().expect("thumbnail encrypted");

        assert_ne!(bundle.attachment.ciphertext, b"full-resolution plaintext");
        assert_ne!(thumbnail.ciphertext, b"thumbnail plaintext");
        assert_ne!(bundle.attachment.nonce, thumbnail.nonce);
        assert_ne!(
            bundle.attachment.ciphertext_digest,
            thumbnail.ciphertext_digest
        );
        assert_eq!(thumbnail.envelope["media_type"], CIPHERTEXT_MEDIA_TYPE);
        assert_eq!(
            thumbnail.ciphertext_digest,
            format!("sha256:{:x}", Sha256::digest(&thumbnail.ciphertext))
        );
    }
}
