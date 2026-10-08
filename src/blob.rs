//! Media blob upload / download helpers (`crypto-media/media-and-blob.md`).
//!
//! Inkson ships a Media classifier already (`media.rs`); this module adds the
//! protocol-level send paths so blob references survive in event payloads
//! with the spec's content-hash typed-id (`ak:blob:sha256:<hex>`).
//!
//! The actual upload bytes go to the Station's
//! `ak.self.blob.upload.create.v1` endpoint; this module covers client-side
//! encryption and content addressing.
//!
//! # Attachment AEAD is the SDK's canonical codec
//!
//! All client-side attachment encryption is delegated to
//! [`arkret_crypto::blob_aead`], the canonical implementation of
//! `ak.blob.stream_aead.v1` (XChaCha20-Poly1305 streaming AEAD).
//! The encrypted composer path is not yet connected. Its caller must freeze
//! a fresh SDK `AttachmentContentKeySalt`, resolve one authorized winning
//! MLS checkpoint, and derive through the registered `ak.blob-content-key-v1`
//! Context before passing the key to the codec. Retrying the same object must
//! preserve its salt, descriptor and ciphertext. The wire envelope is the
//! SDK's [`arkret_models_crypto::EncryptedAttachment`], whose serde shape is exactly
//! `blob.schema.json#/$defs/encrypted_attachment`.

/// Ciphertext is opaque octet-stream on the wire; the plaintext media type is
/// recorded inside the (encrypted-AAD-bound) envelope, never in the blob's
/// transport `content-type`.
pub const CIPHERTEXT_MEDIA_TYPE: &str = "application/octet-stream";

// The former `ak.blob.register` / `ak.blob.revoke` /
// `ak.blob.grant` event builders were removed — none of those kinds is in
// the spec event-kind-registry, and unregistered wire kinds must not be
// mintable from client code. Re-add once the kinds are registered via AKP.
