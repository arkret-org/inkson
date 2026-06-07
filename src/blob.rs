//! Media blob upload / download helpers (`crypto-media/media-and-blob.md`).
//!
//! Yougen ships a Media classifier already (`media.rs`); this module adds the
//! protocol-level send paths so blob references survive in event payloads
//! with the spec's content-hash typed-id (`ck:blob:sha256:<hex>`).
//!
//! Re-exports the SDK's [`Attachment`] / [`MediaMetadata`] / [`Thumbnail`]
//! structures and provides operation builders for blob register / revoke
//! events. The actual upload bytes go to the Principal Server's
//! `ck.self.blob.upload` endpoint; this module covers the durable event side.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
pub use cokret_sdk::{
    Attachment, AuthenticatedDownloadGrant, DownloadGrantScope, EncryptedAttachment, MediaMetadata,
    Thumbnail, safe_content_disposition, safe_content_type,
};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::canonical::canonical_json_bytes;
use crate::operation::OperationBuilder;

pub const MLS_ATTACHMENT_AEAD_ALGORITHM: &str = "mls-rfc9420+xchacha20poly1305";
pub const MLS_ATTACHMENT_AEAD_PROFILE: &str = "ck.aead.xchacha20_poly1305.v1";
pub const MLS_ATTACHMENT_NONCE_LEN: usize = 24;
pub const MLS_ATTACHMENT_NONCE_COUNTER_LEN: usize = 8;
pub const MLS_ATTACHMENT_NONCE_PREFIX_LEN: usize =
    MLS_ATTACHMENT_NONCE_LEN - MLS_ATTACHMENT_NONCE_COUNTER_LEN;
pub const MLS_ATTACHMENT_KEY_LEN: usize = 32;
pub const CIPHERTEXT_MEDIA_TYPE: &str = "application/octet-stream";
const MLS_ATTACHMENT_NONCE_LABEL: &str = "cokret-aead-sender-nonce-prefix-v1";
const MLS_ATTACHMENT_NONCE_PURPOSE: &str = "blob-attachment";

type HmacSha256 = Hmac<Sha256>;

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

/// Caller-owned per-device counter for MLS attachment AEAD nonces.
///
/// The spec requires the counter to be persisted per `(device_id, key_ref,
/// epoch, purpose)` so restarts never reuse a value. Yougen keeps this type
/// at the API boundary: encryption callers must provide the monotonic state
/// explicitly instead of falling back to a random nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsAttachmentNonceState {
    sender_device_id: String,
    next_counter: u64,
}

impl MlsAttachmentNonceState {
    pub fn new(sender_device_id: impl Into<String>, next_counter: u64) -> anyhow::Result<Self> {
        let sender_device_id = sender_device_id.into();
        if sender_device_id.trim().is_empty() {
            anyhow::bail!("sender_device_id is required for attachment nonce derivation");
        }
        Ok(Self {
            sender_device_id,
            next_counter,
        })
    }

    pub fn sender_device_id(&self) -> &str {
        &self.sender_device_id
    }

    pub fn next_counter(&self) -> u64 {
        self.next_counter
    }

    fn next_nonce(
        &mut self,
        mls_exported_secret: &[u8; MLS_ATTACHMENT_KEY_LEN],
        epoch: u64,
        key_ref: &Value,
    ) -> anyhow::Result<DerivedMlsAttachmentNonce> {
        let counter = self.next_counter;
        let next_counter = counter
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("attachment nonce counter exhausted"))?;
        let bytes = derive_mls_attachment_nonce(
            mls_exported_secret,
            epoch,
            key_ref,
            &self.sender_device_id,
            counter,
        )?;
        self.next_counter = next_counter;
        Ok(DerivedMlsAttachmentNonce { bytes, counter })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DerivedMlsAttachmentNonce {
    bytes: [u8; MLS_ATTACHMENT_NONCE_LEN],
    counter: u64,
}

fn derive_mls_attachment_nonce(
    mls_exported_secret: &[u8; MLS_ATTACHMENT_KEY_LEN],
    epoch: u64,
    key_ref: &Value,
    sender_device_id: &str,
    counter: u64,
) -> anyhow::Result<[u8; MLS_ATTACHMENT_NONCE_LEN]> {
    if sender_device_id.trim().is_empty() {
        anyhow::bail!("sender_device_id is required for attachment nonce derivation");
    }
    if !key_ref.is_object() && !key_ref.is_string() {
        anyhow::bail!("key_ref must be an MLS key reference object or string");
    }
    let context = json!({
        "key_ref": key_ref,
        "epoch": epoch,
        "device_id": sender_device_id,
        "purpose": MLS_ATTACHMENT_NONCE_PURPOSE,
        "aead_profile": MLS_ATTACHMENT_AEAD_PROFILE,
    });
    let context = canonical_json_bytes(&context)?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(mls_exported_secret)
        .map_err(|err| anyhow::anyhow!("attachment nonce hmac key: {err}"))?;
    mac.update(MLS_ATTACHMENT_NONCE_LABEL.as_bytes());
    mac.update(&[0]);
    mac.update(&context);
    let digest = mac.finalize().into_bytes();

    let mut nonce = [0u8; MLS_ATTACHMENT_NONCE_LEN];
    nonce[..MLS_ATTACHMENT_NONCE_PREFIX_LEN]
        .copy_from_slice(&digest[..MLS_ATTACHMENT_NONCE_PREFIX_LEN]);
    nonce[MLS_ATTACHMENT_NONCE_PREFIX_LEN..].copy_from_slice(&counter.to_be_bytes());
    Ok(nonce)
}

/// Content-address a blob payload as `ck:blob:sha256:<hex>`.
pub fn blob_typed_id(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("ck:blob:sha256:{digest:x}")
}

/// Build a `ck.blob.register` event body describing an authenticated media
/// upload. Pairs with a server-side `ck.self.blob.upload` to make the blob
/// retrievable through the durable event chain.
pub fn build_blob_register(
    realm_id: &str,
    actor: &str,
    blob_id: &str,
    metadata: &MediaMetadata,
) -> anyhow::Result<OperationBuilder> {
    let metadata_value = serde_json::to_value(metadata)?;
    Ok(OperationBuilder::new(realm_id, actor, "ck.blob.register")
        .target_ref(blob_id)
        .body(json!({
            "blob_id": blob_id,
            "metadata": metadata_value,
        })))
}

/// Build a `ck.blob.revoke` event — revokes prior download grants for the
/// referenced blob without deleting the underlying bytes.
pub fn build_blob_revoke(
    realm_id: &str,
    actor: &str,
    blob_id: &str,
    reason: Option<&str>,
) -> OperationBuilder {
    OperationBuilder::new(realm_id, actor, "ck.blob.revoke")
        .target_ref(blob_id)
        .body(json!({
            "blob_id": blob_id,
            "reason": reason,
        }))
}

/// Build a `ck.blob.grant` event — authenticated download grant for a blob.
/// `scope` indicates whether the grant covers the blob object or an
/// attachment reference (matches the SDK's [`DownloadGrantScope`]).
pub fn build_blob_grant(
    realm_id: &str,
    actor: &str,
    blob_id: &str,
    grant: &AuthenticatedDownloadGrant,
) -> anyhow::Result<OperationBuilder> {
    let grant_value = serde_json::to_value(grant)?;
    Ok(OperationBuilder::new(realm_id, actor, "ck.blob.grant")
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
    nonce_state: &mut MlsAttachmentNonceState,
) -> anyhow::Result<EncryptedAttachmentBundle> {
    let attachment = encrypt_mls_asset(
        attachment_plaintext,
        "attachment",
        mls_exported_secret,
        realm_id,
        epoch,
        key_ref.clone(),
        nonce_state,
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
                nonce_state,
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
    nonce_state: &mut MlsAttachmentNonceState,
) -> anyhow::Result<EncryptedClientAsset> {
    let nonce = nonce_state.next_nonce(mls_exported_secret, epoch, &key_ref)?;
    encrypt_mls_asset_with_nonce(
        plaintext,
        asset_kind,
        mls_exported_secret,
        realm_id,
        epoch,
        key_ref,
        nonce.bytes,
        nonce_state.sender_device_id(),
        nonce.counter,
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
    sender_device_id: &str,
    nonce_counter: u64,
) -> anyhow::Result<EncryptedClientAsset> {
    if realm_id.trim().is_empty() {
        anyhow::bail!("realm_id is required for encrypted attachment AAD");
    }
    if !key_ref.is_object() && !key_ref.is_string() {
        anyhow::bail!("key_ref must be an MLS key reference object or string");
    }
    if sender_device_id.trim().is_empty() {
        anyhow::bail!("sender_device_id is required for encrypted attachment metadata");
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
        .map_err(|err| anyhow::anyhow!("xchacha20poly1305 attachment encrypt: {err}"))?;
    let ciphertext_digest = format!("sha256:{:x}", Sha256::digest(&ciphertext));
    let envelope = json!({
        "version": "cokret.encrypted_attachment.v1",
        "algorithm": MLS_ATTACHMENT_AEAD_ALGORITHM,
        "aead_profile": MLS_ATTACHMENT_AEAD_PROFILE,
        "nonce": URL_SAFE_NO_PAD.encode(nonce),
        "nonce_counter": nonce_counter,
        "sender_device_id": sender_device_id,
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
            "ck:realm:s1",
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
            "ck:device:alice",
            3,
        )
        .unwrap();

        assert_ne!(asset.ciphertext, b"plain cat png bytes");
        assert_eq!(
            asset.ciphertext_digest,
            format!("sha256:{:x}", Sha256::digest(&asset.ciphertext))
        );
        assert_eq!(asset.envelope["algorithm"], MLS_ATTACHMENT_AEAD_ALGORITHM);
        assert_eq!(asset.envelope["aead_profile"], MLS_ATTACHMENT_AEAD_PROFILE);
        assert_eq!(asset.envelope["sender_device_id"], "ck:device:alice");
        assert_eq!(asset.envelope["nonce_counter"], 3);
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
        let mut nonce_state = MlsAttachmentNonceState::new("ck:device:alice", 0).unwrap();
        let bundle = encrypt_mls_attachment_bundle(
            b"full-resolution plaintext",
            Some(b"thumbnail plaintext"),
            &key,
            "ck:realm:encrypted",
            7,
            json!({"group_id": "ck:mls:group", "epoch": 7}),
            &mut nonce_state,
        )
        .unwrap();
        let thumbnail = bundle.thumbnail.as_ref().expect("thumbnail encrypted");

        assert_ne!(bundle.attachment.ciphertext, b"full-resolution plaintext");
        assert_ne!(thumbnail.ciphertext, b"thumbnail plaintext");
        assert_ne!(bundle.attachment.nonce, thumbnail.nonce);
        assert_eq!(nonce_counter(&bundle.attachment.nonce), 0);
        assert_eq!(nonce_counter(&thumbnail.nonce), 1);
        assert_eq!(nonce_state.next_counter(), 2);
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

    #[test]
    fn mls_attachment_nonce_state_derives_monotonic_nonce_suffixes() {
        let key = [11u8; MLS_ATTACHMENT_KEY_LEN];
        let key_ref = json!({"group_id": "ck:mls:group", "epoch": 7});
        let mut state = MlsAttachmentNonceState::new("ck:device:alice", 41).unwrap();

        let first = state.next_nonce(&key, 7, &key_ref).unwrap();
        let second = state.next_nonce(&key, 7, &key_ref).unwrap();

        assert_eq!(nonce_counter(&first.bytes), 41);
        assert_eq!(nonce_counter(&second.bytes), 42);
        assert_eq!(state.next_counter(), 43);
        assert_ne!(first.bytes, second.bytes);
        assert_eq!(
            &first.bytes[..MLS_ATTACHMENT_NONCE_PREFIX_LEN],
            &second.bytes[..MLS_ATTACHMENT_NONCE_PREFIX_LEN],
            "same sender/key_ref/epoch keeps a stable sender nonce prefix"
        );
    }

    #[test]
    fn mls_attachment_nonce_prefix_binds_sender_device_and_key_ref() {
        let key = [13u8; MLS_ATTACHMENT_KEY_LEN];
        let key_ref = json!({"group_id": "ck:mls:group", "epoch": 7});
        let other_key_ref = json!({"group_id": "ck:mls:other", "epoch": 7});
        let alice = derive_mls_attachment_nonce(&key, 7, &key_ref, "ck:device:alice", 0).unwrap();
        let bob = derive_mls_attachment_nonce(&key, 7, &key_ref, "ck:device:bob", 0).unwrap();
        let other_key =
            derive_mls_attachment_nonce(&key, 7, &other_key_ref, "ck:device:alice", 0).unwrap();

        assert_eq!(nonce_counter(&alice), 0);
        assert_eq!(nonce_counter(&bob), 0);
        assert_ne!(
            &alice[..MLS_ATTACHMENT_NONCE_PREFIX_LEN],
            &bob[..MLS_ATTACHMENT_NONCE_PREFIX_LEN]
        );
        assert_ne!(
            &alice[..MLS_ATTACHMENT_NONCE_PREFIX_LEN],
            &other_key[..MLS_ATTACHMENT_NONCE_PREFIX_LEN]
        );
    }

    #[test]
    fn mls_attachment_nonce_state_rejects_empty_sender_device() {
        assert!(MlsAttachmentNonceState::new("  ", 0).is_err());
    }

    fn nonce_counter(nonce: &[u8; MLS_ATTACHMENT_NONCE_LEN]) -> u64 {
        u64::from_be_bytes(nonce[MLS_ATTACHMENT_NONCE_PREFIX_LEN..].try_into().unwrap())
    }
}
