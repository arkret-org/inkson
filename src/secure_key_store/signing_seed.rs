//! T5.2: signing-seed convenience layer over the [`SecureKeyStore`] KV.
//!
//! The `SecureKeyStore` trait is a generic string → string KV
//! (used by OIDC refresh tokens, push grants, etc.). T5.2 piggybacks on
//! the same backend for the per-device Ed25519 signing seed so the seed
//! lands in the OS keychain alongside the rest of the secrets instead of
//! in `state.json` plaintext.
//!
//! ## wasm32 signing-seed storage
//!
//! Ed25519 signing remains in the Rust/SDK path. We do not rely on a
//! browser-native non-extractable Ed25519 `CryptoKey` because that is not
//! portable enough across the target browsers this client supports. The
//! at-rest seed boundary is therefore:
//!
//!   * [`super::LocalStorageSecureKeyStore`] refuses Ed25519 seed keys.
//!   * [`load_signing_seed`] / [`store_signing_seed`] require [`super::IndexedDbSecureKeyStore`] on
//!     wasm32.
//!   * `migrate_localstorage_entries_to_indexeddb` deletes historical localStorage Ed25519 seed
//!     entries instead of decrypting or migrating them.
//!
//! Before the async IndexedDB/SubtleCrypto upgrade completes, browser
//! signer bootstrap fails closed and ProofMode remains Production.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;

use super::{SecureKeyStore, SecureKeyStoreError, require_wasm_indexeddb_ed25519_seed_store};

/// Canonical key name for the active-device Ed25519 signing seed in the
/// secure-key store. Scoped by `service_name` (`"yougen"` in production)
/// so dev and prod builds never collide.
pub const SIGNING_SEED_KEY: &str = "device.ed25519.signing_seed.v1";

/// Decoded signing seed (32 bytes) plus the `did:key` the seed encodes.
/// Returned by [`load_signing_seed`] / [`ensure_signing_seed`] so callers
/// can stand up an `Ed25519DetachedJwsSigner` without re-deriving the DID.
#[derive(Clone)]
pub struct SigningSeedMaterial {
    pub seed: [u8; 32],
    /// `did:key:z<multibase>` encoded local signing public key. This is
    /// the device signing key's self-describing encoding, not a device DID
    /// or actor identity. Devices are not independent DID principals; event
    /// `actor_id` uses the account/principal DID. See spec models/actor.md §2.
    pub local_signing_did: String,
}

impl std::fmt::Debug for SigningSeedMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningSeedMaterial")
            .field("seed", &"<redacted>")
            .field("local_signing_did", &self.local_signing_did)
            .finish()
    }
}

impl SigningSeedMaterial {
    /// Raw 32-byte Ed25519 public key for this device signing seed. This is the
    /// `device_public_key` submitted to the enrollment authority.
    pub fn device_public_key(&self) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&self.seed)
            .verifying_key()
            .to_bytes()
    }
}

/// Read a previously-stashed signing seed from `store`. Returns `Ok(None)`
/// when the entry is absent (vs `Err(...)` for backend failures).
///
/// The seed is encoded as base64-no-pad. Any decode failure (corrupt
/// entry, length mismatch) is reported as `SecureKeyStoreError::Backend`
/// so the boot path can surface a clear "rotate device identity" warning
/// instead of silently regenerating.
pub fn load_signing_seed(
    store: &dyn SecureKeyStore,
) -> Result<Option<SigningSeedMaterial>, SecureKeyStoreError> {
    require_wasm_indexeddb_ed25519_seed_store(store)?;
    let Some(raw) = store.get_secret(SIGNING_SEED_KEY)? else {
        return Ok(None);
    };
    let bytes = STANDARD_NO_PAD.decode(raw.as_bytes()).map_err(|err| {
        SecureKeyStoreError::Backend(format!("signing seed base64 decode: {err}"))
    })?;
    if bytes.len() != 32 {
        return Err(SecureKeyStoreError::Backend(format!(
            "signing seed length {}, expected 32",
            bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    let did = ed25519_seed_to_did_key(&seed);
    Ok(Some(SigningSeedMaterial {
        seed,
        local_signing_did: did,
    }))
}

/// Persist `seed` into the secure-key store under [`SIGNING_SEED_KEY`].
/// Overwrites silently. The DID is recomputed from the seed by the
/// loader, so it is not stored separately.
pub fn store_signing_seed(
    store: &dyn SecureKeyStore,
    seed: &[u8; 32],
) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
    require_wasm_indexeddb_ed25519_seed_store(store)?;
    let encoded = STANDARD_NO_PAD.encode(seed);
    store.store_secret(SIGNING_SEED_KEY, &encoded)?;
    Ok(SigningSeedMaterial {
        seed: *seed,
        local_signing_did: ed25519_seed_to_did_key(seed),
    })
}

/// Load the existing signing seed, or generate + persist a fresh one if
/// none exists. The generated seed is a 32-byte `getrandom` draw.
pub fn ensure_signing_seed(
    store: &dyn SecureKeyStore,
) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
    if let Some(material) = load_signing_seed(store)? {
        return Ok(material);
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom signing seed: {err}")))?;
    store_signing_seed(store, &seed)
}

/// Encode an Ed25519 seed into a `did:key:z…` (multibase `0xed01 ||
/// pubkey32`). Kept in this module so callers don't have to depend on
/// `crate::local_state::encode_did_key` for the seed-only path.
fn ed25519_seed_to_did_key(seed: &[u8; 32]) -> String {
    let signing = ed25519_dalek::SigningKey::from_bytes(seed);
    let verifying = signing.verifying_key();
    let mut prefixed = Vec::with_capacity(34);
    prefixed.push(0xed);
    prefixed.push(0x01);
    prefixed.extend_from_slice(&verifying.to_bytes());
    format!("did:key:z{}", bs58::encode(prefixed).into_string())
}
