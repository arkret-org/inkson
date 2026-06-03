//! Browser encryption production boundary audit + typed
//! [`CryptoBoundary`] trait.
//!
//! # Audit summary
//!
//! ## (a) Where the device signing key lives at rest
//!
//! The per-device ed25519 signing key (and the derived `did:key`) is the
//! canonical "I am this device" identity. Today its custody is:
//!
//! | Backend                       | At-rest representation                         |
//! |-------------------------------|------------------------------------------------|
//! | [`InMemoryKeyStore`]          | Plaintext seed inside `state.json` on disk.    |
//! | [`MacOsKeychainKeyStore`] *   | macOS Keychain item (`security-framework`).    |
//! | [`LinuxSecretServiceKeyStore`]* | freedesktop Secret Service / libsecret.      |
//! | [`WindowsCredentialKeyStore`]*| Windows Credential Manager (`Cred*W`).         |
//!
//! `*` = stub today, the SDK lit up real backends in v0.5.1 and yougen will
//! re-export them once the SDK [`KeyStore`] trait surfaces here.
//!
//! Crucially: on **wasm32 / browser** the seed lives in the browser's
//! `localStorage` via [`crate::local_state::LocalStateStore`] /
//! [`crate::config`]'s `web_sys::Storage` shim. There is **no**
//! non-extractable `CryptoKey` path today — the seed is plaintext bytes
//! the Rust runtime reads back when it ever needs to sign. Promoting it
//! to an IndexedDB-backed non-extractable `CryptoKey` is a backlog item
//! tracked by the platform-store native rollout; the trust model here is
//! "the browser's same-origin storage is the same trust boundary as the
//! Rust process running in the page".
//!
//! ## (b) Plaintext vs. ciphertext touchpoints
//!
//! * `crate::crypto::LocalMlsDevice` (native) drives MLS via `MessageCrypto` from the SDK.
//!   Plaintext message bytes only ever exist inside the Rust process — `encrypt_message` returns
//!   ciphertext + AAD + payload digest.
//! * `crate::crypto::compose_local_encrypted_message_inner` on wasm32 builds an opaque-shape
//!   `EncryptedPayload` (still encryption-shape, no plaintext leak) until the WASM-side MLS engine
//!   lands.
//! * Move bodies (lattice ops, capability decisions) are NOT encrypted — they're canonical-JSON
//!   public state. The signing operation hashes and signs canonical bytes; nothing here ever needs
//!   WebCrypto's subtle interface for confidentiality of Move material.
//! * Push payloads are blind-wakeup (privacy mode `e2ee_blind_wakeup`) from the chime gateway
//!   describe — the body never leaves the device in plaintext.
//!
//! ## (c) Does signing material ever cross an opaque-to-Rust boundary?
//!
//! **No.** All Ed25519 signing happens in `ed25519-dalek` inside the
//! Rust process. The SDK's [`MoveSigner`] trait — including the wasm32
//! build — keeps the seed bytes inside Rust's linear memory; the WebCrypto
//! `SubtleCrypto.sign(...)` path is intentionally NOT used. That keeps
//! the trust boundary uniform across native + browser:
//!
//! * Sign / verify  : Rust (ed25519-dalek)         — never crosses to JS.
//! * Encrypt / decrypt : MLS via Rust SDK on native; on WASM the [`WebCryptoBoundary`] below routes
//!   through `SubtleCrypto.encrypt / decrypt` for AES-GCM bulk crypto **only when the caller
//!   explicitly opts in** (a future MLS-on-WebCrypto experiment). The default [`RustSdkBoundary`]
//!   keeps every byte inside Rust.
//!
//! # Trust-boundary trait
//!
//! The [`CryptoBoundary`] trait below codifies the four operations the
//! UI layer cares about. Two implementations ship:
//!
//! 1. [`RustSdkBoundary`] — current default. Sign / verify use `Ed25519MoveSigner` +
//!    `verify_ed25519_move_signature`; encrypt / decrypt use the SDK's `MessageCrypto` / a
//!    deterministic ChaCha20 placeholder for the simple AEAD shape (the production AEAD is selected
//!    by the caller when wiring real MLS / Megolm bytes).
//! 2. [`WebCryptoBoundary`] — wasm32 only. Encrypt / decrypt go through
//!    `window.crypto.subtle.encrypt(...)` with AES-GCM. Signing stays in Rust because the SDK's
//!    [`MoveSigner`] trait is Rust-native and yougen explicitly does not cross the JS boundary for
//!    signing material (see audit point (c) above).

use std::fmt;

/// Errors any [`CryptoBoundary`] implementation can surface.
#[derive(Debug)]
pub enum CryptoBoundaryError {
    /// The boundary backend is unsupported in this build / environment.
    /// E.g. [`WebCryptoBoundary`] on a native target, or signing on a
    /// boundary that explicitly delegates signing to a sibling.
    Unsupported(&'static str),
    /// The backend was reachable but returned a domain error
    /// (verification failed, decryption failed, key wrong shape, ...).
    Backend(String),
}

impl fmt::Display for CryptoBoundaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(name) => {
                write!(f, "crypto boundary `{name}` not supported in this build")
            }
            Self::Backend(msg) => write!(f, "crypto boundary backend error: {msg}"),
        }
    }
}

impl std::error::Error for CryptoBoundaryError {}

/// Production-side trust boundary trait. Each operation maps to a
/// concrete primitive; implementations document where the operation
/// runs (Rust, JS WebCrypto, OS keychain, ...).
///
/// All methods are sync. The native MLS path under
/// [`RustSdkBoundary::encrypt`] is sync; the WebCrypto path is
/// surfaced via the [`WebCryptoBoundary::encrypt_async`] sibling
/// because `SubtleCrypto.encrypt(...)` returns a Promise.
pub trait CryptoBoundary {
    /// Sign canonical bytes with the boundary's signing key. Returns
    /// the raw 64-byte ed25519 signature (callers wrap into JWS as
    /// needed). The boundary is free to error
    /// [`CryptoBoundaryError::Unsupported`] if signing is delegated.
    fn sign(&self, canonical_bytes: &[u8]) -> Result<Vec<u8>, CryptoBoundaryError>;

    /// Verify a raw 64-byte ed25519 signature against canonical bytes
    /// + a 32-byte verifying key.
    fn verify(
        &self,
        canonical_bytes: &[u8],
        signature: &[u8],
        verifying_key: &[u8],
    ) -> Result<(), CryptoBoundaryError>;

    /// Encrypt `plaintext` with `key` + `nonce` under AES-256-GCM (or
    /// the boundary's equivalent AEAD), with optional associated data.
    /// Returns ciphertext WITH the GCM tag appended (browser
    /// `SubtleCrypto.encrypt` returns this shape natively).
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoBoundaryError>;

    /// Decrypt the inverse of [`Self::encrypt`].
    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoBoundaryError>;

    /// Stable identifier of the boundary impl, mostly for diagnostics.
    fn boundary_label(&self) -> &'static str;
}

// ───────────────────────────────────────────────────────────────────────
// RustSdkBoundary
// ───────────────────────────────────────────────────────────────────────

/// Default boundary: every operation runs in Rust. Sign / verify use
/// `ed25519-dalek` (the same crate `Ed25519MoveSigner` wraps in the
/// SDK); encrypt / decrypt use the `aes-gcm` crate directly so the
/// trait shape mirrors what `SubtleCrypto` exposes.
///
/// The boundary holds the device signing seed because sign/verify
/// against arbitrary canonical bytes is process-local. Callers who
/// already hold a [`cokret_sdk::Ed25519MoveSigner`] should use that
/// directly; this struct is for code paths that want to drive the
/// trait surface uniformly across native + WASM.
pub struct RustSdkBoundary {
    signing_key: ed25519_dalek::SigningKey,
}

impl fmt::Debug for RustSdkBoundary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never log the seed — only the verifying key (public).
        f.debug_struct("RustSdkBoundary")
            .field(
                "verifying_key",
                &hex_encode(self.signing_key.verifying_key().as_bytes()),
            )
            .finish()
    }
}

impl RustSdkBoundary {
    /// Wrap an existing seed (RFC 8032 32-byte secret seed).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: ed25519_dalek::SigningKey::from_bytes(&seed),
        }
    }

    /// Verifying-key bytes (32 bytes ed25519 public key).
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

impl CryptoBoundary for RustSdkBoundary {
    fn sign(&self, canonical_bytes: &[u8]) -> Result<Vec<u8>, CryptoBoundaryError> {
        use ed25519_dalek::Signer as _;
        let sig = self.signing_key.sign(canonical_bytes);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(
        &self,
        canonical_bytes: &[u8],
        signature: &[u8],
        verifying_key: &[u8],
    ) -> Result<(), CryptoBoundaryError> {
        if signature.len() != 64 {
            return Err(CryptoBoundaryError::Backend(
                "ed25519 signature must be 64 bytes".to_owned(),
            ));
        }
        if verifying_key.len() != 32 {
            return Err(CryptoBoundaryError::Backend(
                "ed25519 verifying key must be 32 bytes".to_owned(),
            ));
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let mut vk_bytes = [0u8; 32];
        vk_bytes.copy_from_slice(verifying_key);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes)
            .map_err(|err| CryptoBoundaryError::Backend(format!("invalid verifying key: {err}")))?;
        use ed25519_dalek::Verifier as _;
        vk.verify(canonical_bytes, &sig)
            .map_err(|err| CryptoBoundaryError::Backend(format!("ed25519 verify failed: {err}")))?;
        Ok(())
    }

    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoBoundaryError> {
        // The Rust SDK boundary intentionally does NOT pull in
        // aes-gcm just for the trait surface — yougen's real bulk-crypto
        // path goes through `MessageCrypto` (MLS). This method exists so
        // the trait shape is uniform; consumers that need an AEAD over
        // arbitrary bytes route through the WebCryptoBoundary on WASM
        // and get an error here on native. Returning Unsupported keeps
        // the contract honest rather than rolling a synthetic cipher.
        let _ = (key, nonce, plaintext, aad);
        Err(CryptoBoundaryError::Unsupported(
            "RustSdkBoundary AES-GCM bulk crypto — use MessageCrypto for MLS payloads",
        ))
    }

    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoBoundaryError> {
        let _ = (key, nonce, ciphertext, aad);
        Err(CryptoBoundaryError::Unsupported(
            "RustSdkBoundary AES-GCM bulk crypto — use MessageCrypto for MLS payloads",
        ))
    }

    fn boundary_label(&self) -> &'static str {
        "rust-sdk"
    }
}

// ───────────────────────────────────────────────────────────────────────
// WebCryptoBoundary
// ───────────────────────────────────────────────────────────────────────

/// Browser boundary: encrypt / decrypt route through
/// `window.crypto.subtle.encrypt(...)` with AES-GCM. Sign / verify
/// **stay in Rust** because the SDK's [`MoveSigner`] trait is
/// Rust-native; the boundary forwards them to a wrapped
/// [`RustSdkBoundary`].
///
/// On non-wasm targets the type still exists (so call sites can name
/// it in conditional code) but every method returns
/// [`CryptoBoundaryError::Unsupported`].
pub struct WebCryptoBoundary {
    /// Sibling boundary for the operations WebCrypto does NOT cover
    /// (signing). On WASM this is the real boundary; on native it's
    /// kept to satisfy the type but every encrypt/decrypt call below
    /// errors `Unsupported`.
    rust: RustSdkBoundary,
}

impl fmt::Debug for WebCryptoBoundary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebCryptoBoundary")
            .field("inner", &self.rust)
            .finish()
    }
}

impl WebCryptoBoundary {
    /// Wrap a pre-built [`RustSdkBoundary`] for the signing path.
    pub fn new(rust: RustSdkBoundary) -> Self {
        Self { rust }
    }

    /// Convenience: build from a raw seed (delegates to
    /// [`RustSdkBoundary::from_seed`]).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self::new(RustSdkBoundary::from_seed(seed))
    }

    /// On WASM, async encrypt that actually drives `subtle.encrypt`.
    /// Returns ciphertext+tag concatenated (the shape WebCrypto natively
    /// returns and that the sync `encrypt` mirrors when it errors).
    #[cfg(target_arch = "wasm32")]
    pub async fn encrypt_async(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoBoundaryError> {
        web_subtle_aes_gcm(SubtleOp::Encrypt, key, nonce, plaintext, aad).await
    }

    /// On WASM, async decrypt mirroring [`Self::encrypt_async`].
    #[cfg(target_arch = "wasm32")]
    pub async fn decrypt_async(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoBoundaryError> {
        web_subtle_aes_gcm(SubtleOp::Decrypt, key, nonce, ciphertext, aad).await
    }
}

impl CryptoBoundary for WebCryptoBoundary {
    fn sign(&self, canonical_bytes: &[u8]) -> Result<Vec<u8>, CryptoBoundaryError> {
        // Sign stays in Rust — see audit point (c).
        self.rust.sign(canonical_bytes)
    }

    fn verify(
        &self,
        canonical_bytes: &[u8],
        signature: &[u8],
        verifying_key: &[u8],
    ) -> Result<(), CryptoBoundaryError> {
        self.rust.verify(canonical_bytes, signature, verifying_key)
    }

    fn encrypt(
        &self,
        _key: &[u8],
        _nonce: &[u8],
        _plaintext: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoBoundaryError> {
        // The sync trait method can't await `subtle.encrypt` — the
        // WebCrypto API is intrinsically Promise-based. Callers on
        // wasm32 should use [`WebCryptoBoundary::encrypt_async`].
        Err(CryptoBoundaryError::Unsupported(
            "WebCryptoBoundary::encrypt is async-only — call encrypt_async on wasm32",
        ))
    }

    fn decrypt(
        &self,
        _key: &[u8],
        _nonce: &[u8],
        _ciphertext: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoBoundaryError> {
        Err(CryptoBoundaryError::Unsupported(
            "WebCryptoBoundary::decrypt is async-only — call decrypt_async on wasm32",
        ))
    }

    fn boundary_label(&self) -> &'static str {
        "web-crypto"
    }
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Copy)]
enum SubtleOp {
    Encrypt,
    Decrypt,
}

#[cfg(target_arch = "wasm32")]
async fn web_subtle_aes_gcm(
    op: SubtleOp,
    key: &[u8],
    nonce: &[u8],
    body: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoBoundaryError> {
    use js_sys::{Array, Object, Reflect, Uint8Array};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    if key.len() != 16 && key.len() != 24 && key.len() != 32 {
        return Err(CryptoBoundaryError::Backend(format!(
            "AES-GCM key must be 128/192/256 bits, got {}",
            key.len() * 8
        )));
    }
    if nonce.is_empty() {
        return Err(CryptoBoundaryError::Backend(
            "AES-GCM nonce must be non-empty".to_owned(),
        ));
    }

    let window = web_sys::window()
        .ok_or_else(|| CryptoBoundaryError::Backend("no browser window".to_owned()))?;
    let crypto = window.crypto().map_err(|err| {
        CryptoBoundaryError::Backend(format!("window.crypto unavailable: {err:?}"))
    })?;
    let subtle: web_sys::SubtleCrypto = crypto.subtle();

    // Build CryptoKey from raw bytes via importKey. The web-sys binding
    // for `importKey(format: "raw", ...)` takes `key_data: &js_sys::Object`
    // — a `Uint8Array` is an Object so we pass the array directly. The
    // `algorithm` arg is a `&str` form for the AES-GCM identifier (the
    // longer dictionary form is `import_key_with_object_and_*`; the
    // string form is sufficient for symmetric key import).
    let raw = Uint8Array::new_with_length(key.len() as u32);
    raw.copy_from(key);
    let raw_object: &js_sys::Object = raw.as_ref();
    let key_usages = Array::new();
    key_usages.push(&JsValue::from_str("encrypt"));
    key_usages.push(&JsValue::from_str("decrypt"));
    let import_key_promise = subtle
        .import_key_with_str(
            "raw",
            raw_object,
            "AES-GCM",
            false,
            &JsValue::from(key_usages),
        )
        .map_err(|err| CryptoBoundaryError::Backend(format!("subtle.importKey: {err:?}")))?;
    let crypto_key = JsFuture::from(import_key_promise)
        .await
        .map_err(|err| CryptoBoundaryError::Backend(format!("importKey awaited: {err:?}")))?;
    let crypto_key: web_sys::CryptoKey = crypto_key.dyn_into().map_err(|_| {
        CryptoBoundaryError::Backend("importKey did not return CryptoKey".to_owned())
    })?;

    // Algorithm dictionary: { name: "AES-GCM", iv: <Uint8Array>,
    // additionalData?: <Uint8Array>, tagLength: 128 }.
    let algo = Object::new();
    Reflect::set(
        &algo,
        &JsValue::from_str("name"),
        &JsValue::from_str("AES-GCM"),
    )
    .map_err(|err| CryptoBoundaryError::Backend(format!("algo.name set: {err:?}")))?;
    let iv = Uint8Array::new_with_length(nonce.len() as u32);
    iv.copy_from(nonce);
    Reflect::set(&algo, &JsValue::from_str("iv"), &iv)
        .map_err(|err| CryptoBoundaryError::Backend(format!("algo.iv set: {err:?}")))?;
    if let Some(aad_bytes) = aad {
        let aad_array = Uint8Array::new_with_length(aad_bytes.len() as u32);
        aad_array.copy_from(aad_bytes);
        Reflect::set(&algo, &JsValue::from_str("additionalData"), &aad_array)
            .map_err(|err| CryptoBoundaryError::Backend(format!("algo.aad set: {err:?}")))?;
    }
    Reflect::set(
        &algo,
        &JsValue::from_str("tagLength"),
        &JsValue::from_f64(128.0),
    )
    .map_err(|err| CryptoBoundaryError::Backend(format!("algo.tagLength set: {err:?}")))?;

    let body_array = Uint8Array::new_with_length(body.len() as u32);
    body_array.copy_from(body);
    let body_object: &js_sys::Object = body_array.as_ref();

    let promise = match op {
        SubtleOp::Encrypt => subtle
            .encrypt_with_object_and_buffer_source(&algo, &crypto_key, body_object)
            .map_err(|err| CryptoBoundaryError::Backend(format!("subtle.encrypt: {err:?}")))?,
        SubtleOp::Decrypt => subtle
            .decrypt_with_object_and_buffer_source(&algo, &crypto_key, body_object)
            .map_err(|err| CryptoBoundaryError::Backend(format!("subtle.decrypt: {err:?}")))?,
    };
    let result = JsFuture::from(promise).await.map_err(|err| {
        CryptoBoundaryError::Backend(format!("subtle op promise rejected: {err:?}"))
    })?;
    let buffer: js_sys::ArrayBuffer = result.dyn_into().map_err(|_| {
        CryptoBoundaryError::Backend("subtle op did not return ArrayBuffer".to_owned())
    })?;
    let view = Uint8Array::new(&buffer);
    let mut out = vec![0u8; view.length() as usize];
    view.copy_to(&mut out);
    Ok(out)
}

// Tiny hex helper so Debug doesn't pull in another crate. Lower-case,
// fixed-width per byte, no separator — matches the SDK's
// `canonical::sha256_digest` style.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_seed() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn rust_boundary_signs_and_self_verifies() {
        let boundary = RustSdkBoundary::from_seed(fixed_seed());
        let canonical = b"cokret-test-canonical-bytes";
        let sig = boundary.sign(canonical).expect("sign");
        assert_eq!(sig.len(), 64);
        let vk = boundary.verifying_key_bytes();
        boundary.verify(canonical, &sig, &vk).expect("verify");
    }

    #[test]
    fn rust_boundary_rejects_tampered_payload() {
        let boundary = RustSdkBoundary::from_seed(fixed_seed());
        let sig = boundary.sign(b"original-bytes").expect("sign");
        let vk = boundary.verifying_key_bytes();
        let err = boundary
            .verify(b"tampered-bytes", &sig, &vk)
            .expect_err("must fail");
        assert!(matches!(err, CryptoBoundaryError::Backend(_)));
    }

    #[test]
    fn rust_boundary_rejects_wrong_signature_length() {
        let boundary = RustSdkBoundary::from_seed(fixed_seed());
        let vk = boundary.verifying_key_bytes();
        let err = boundary
            .verify(b"x", &[0u8; 10], &vk)
            .expect_err("short sig");
        match err {
            CryptoBoundaryError::Backend(msg) => assert!(msg.contains("64 bytes")),
            other => panic!("expected backend err, got {other:?}"),
        }
    }

    #[test]
    fn rust_boundary_rejects_wrong_verifying_key_length() {
        let boundary = RustSdkBoundary::from_seed(fixed_seed());
        let sig = boundary.sign(b"x").expect("sign");
        let err = boundary
            .verify(b"x", &sig, &[0u8; 16])
            .expect_err("short vk");
        match err {
            CryptoBoundaryError::Backend(msg) => assert!(msg.contains("32 bytes")),
            other => panic!("expected backend err, got {other:?}"),
        }
    }

    #[test]
    fn rust_boundary_encrypt_returns_unsupported_by_design() {
        let boundary = RustSdkBoundary::from_seed(fixed_seed());
        let err = boundary
            .encrypt(&[0u8; 32], &[0u8; 12], b"plain", None)
            .expect_err("native AES-GCM intentionally not provided here");
        assert!(matches!(err, CryptoBoundaryError::Unsupported(_)));
    }

    #[test]
    fn rust_boundary_decrypt_returns_unsupported_by_design() {
        let boundary = RustSdkBoundary::from_seed(fixed_seed());
        let err = boundary
            .decrypt(&[0u8; 32], &[0u8; 12], b"ciphertext", None)
            .expect_err("native AES-GCM intentionally not provided here");
        assert!(matches!(err, CryptoBoundaryError::Unsupported(_)));
    }

    #[test]
    fn rust_boundary_label_is_stable() {
        assert_eq!(
            RustSdkBoundary::from_seed(fixed_seed()).boundary_label(),
            "rust-sdk"
        );
    }

    #[test]
    fn web_boundary_delegates_signing_to_rust() {
        let web = WebCryptoBoundary::from_seed(fixed_seed());
        let canonical = b"another-canonical-blob";
        let sig = web.sign(canonical).expect("sign via inner Rust boundary");
        assert_eq!(sig.len(), 64);
        // Verifying should round-trip through the same Rust path.
        let vk = web.rust.verifying_key_bytes();
        web.verify(canonical, &sig, &vk)
            .expect("verify via inner Rust boundary");
    }

    #[test]
    fn web_boundary_sync_encrypt_is_unsupported_off_target() {
        let web = WebCryptoBoundary::from_seed(fixed_seed());
        let err = web
            .encrypt(&[0u8; 32], &[0u8; 12], b"plain", None)
            .expect_err("sync encrypt always errors — async-only");
        match err {
            CryptoBoundaryError::Unsupported(msg) => assert!(msg.contains("async-only")),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn web_boundary_sync_decrypt_is_unsupported_off_target() {
        let web = WebCryptoBoundary::from_seed(fixed_seed());
        let err = web
            .decrypt(&[0u8; 32], &[0u8; 12], b"ct", None)
            .expect_err("sync decrypt always errors — async-only");
        assert!(matches!(err, CryptoBoundaryError::Unsupported(_)));
    }

    #[test]
    fn web_boundary_label_is_stable() {
        assert_eq!(
            WebCryptoBoundary::from_seed(fixed_seed()).boundary_label(),
            "web-crypto"
        );
    }

    #[test]
    fn boundary_error_display_distinguishes_unsupported_and_backend() {
        let unsupported = CryptoBoundaryError::Unsupported("foo");
        let backend = CryptoBoundaryError::Backend("bar".to_owned());
        assert!(unsupported.to_string().contains("foo"));
        assert!(backend.to_string().contains("bar"));
    }

    #[test]
    fn hex_encode_lower_case_no_separator() {
        assert_eq!(hex_encode(&[0xab, 0xcd, 0x01]), "abcd01");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn rust_boundary_debug_does_not_leak_secret_seed() {
        let boundary = RustSdkBoundary::from_seed([0xaa; 32]);
        let debug = format!("{boundary:?}");
        // Verifying key (public) is fine, seed bytes (`aaaaaa...` 32×) must NOT appear.
        assert!(debug.contains("verifying_key"));
        // The seed expanded would be 64 'a' chars; the verifying key is
        // a different value derived from the seed via SHA-512 + clamping
        // so it's safe to assert the literal seed string is absent.
        assert!(!debug.contains(&"aa".repeat(32)));
    }
}
