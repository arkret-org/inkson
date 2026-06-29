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

use std::sync::RwLock;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};

use super::{SecureKeyStore, SecureKeyStoreError, require_wasm_indexeddb_ed25519_seed_store};

/// Canonical key name for the active-device Ed25519 signing seed in the
/// secure-key store. Scoped by `service_name` (`"yougen"` in production)
/// so dev and prod builds never collide.
///
/// The seed is additionally scoped *per account* (see
/// [`signing_seed_key_for`]): two accounts signed in on the same browser MUST
/// hold completely separate device signing keys, never one shared key. The
/// bare `SIGNING_SEED_KEY` is the **bootstrap** scope, used only during the
/// pre-account phase of an interactive sign-in (the device key is needed to
/// mint the session grant before the Account Authority resolves which principal
/// the OIDC subject maps to); it is migrated into the account scope by
/// [`adopt_device_seed_scope_on_login`] once the principal is known.
pub const SIGNING_SEED_KEY: &str = "device.ed25519.signing_seed.v1";

/// Process-global active device-seed scope: the signed-in account DID whose
/// per-account seed the bare [`load_signing_seed`] / [`ensure_signing_seed`]
/// helpers resolve. `None` selects the bootstrap scope. Set on login
/// completion ([`adopt_device_seed_scope_on_login`]), on app boot / session
/// restore for the persisted account, and reset for a fresh interactive
/// sign-in ([`reset_device_seed_scope_for_signin`]). The seed is read at a few
/// controlled points (signer activation at boot/login, recovery); per-event
/// signing uses the already-activated in-memory signer, so this is not a hot
/// path.
static ACTIVE_DEVICE_SEED_SCOPE: RwLock<Option<String>> = RwLock::new(None);

/// Set the active per-account device-seed scope (the account DID), or `None`
/// for the bootstrap scope.
pub fn set_active_device_seed_scope(scope: Option<&str>) {
    let normalized = scope
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    if let Ok(mut guard) = ACTIVE_DEVICE_SEED_SCOPE.write() {
        *guard = normalized;
    }
}

/// The current active per-account device-seed scope, if any.
pub fn active_device_seed_scope() -> Option<String> {
    ACTIVE_DEVICE_SEED_SCOPE
        .read()
        .ok()
        .and_then(|guard| guard.clone())
}

/// Process-global pending-login device id. During the pre-DID phase of an
/// interactive sign-in the wrap_seed (and any pending secrets) live under the
/// `pending.<device_id>` namespace; once the principal DID resolves, that
/// material is adopted/migrated under the DID namespace. `None` outside an
/// in-flight pending sign-in.
static PENDING_LOGIN_DEVICE_ID: RwLock<Option<String>> = RwLock::new(None);

/// Set (or clear with `None`) the pending-login device id used to namespace the
/// pre-DID wrap_seed and pending secrets.
pub fn set_pending_login_device_id(device_id: Option<&str>) {
    let normalized = device_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    if let Ok(mut guard) = PENDING_LOGIN_DEVICE_ID.write() {
        *guard = normalized;
    }
}

/// The current pending-login device id, if a pre-DID sign-in is in flight.
pub fn pending_login_device_id() -> Option<String> {
    PENDING_LOGIN_DEVICE_ID
        .read()
        .ok()
        .and_then(|guard| guard.clone())
}

/// Wrap_seed namespace for the AEAD secure store — intentionally GLOBAL (the
/// bare `service_name`), NOT per-account.
///
/// Per-account device-key isolation is provided by the ENTRY keys
/// (`signing_seed_key_for(scope)` / [`account_scoped_device_key`]): account A's
/// device-key material lives under a different localStorage entry than account
/// B's, so they never read each other's. The wrap_seed is only the at-rest
/// wrapping key for the store on this one browser; sharing it across the
/// browser's own accounts leaks nothing the user can't already read.
///
/// It MUST stay constant across a sign-in: [`adopt_device_seed_scope_on_login`]
/// re-homes the bootstrap signing seed to the account scope and only THEN flips
/// `ACTIVE_DEVICE_SEED_SCOPE`. If the wrap_seed namespace tracked that scope, the
/// account-scope seed would be wrapped under the pre-flip namespace but read back
/// under the post-flip one — an undecryptable mismatch that silently drops the
/// device key (regenerating it with a fresh `jkt` that no longer matches the
/// just-issued grant). Keeping it global avoids that write/read skew entirely.
pub fn wrap_seed_namespace(service_name: &str) -> String {
    service_name.to_owned()
}

/// Append the active per-account scope to a secure-store key `base`, for
/// device-key material that must be isolated per account alongside the signing
/// seed — notably the cached DPoP device-key record (which embeds the same seed
/// bytes and is what `ensure_device_key` consults first). Returns `base`
/// unchanged in the bootstrap scope. The account segment uses the same
/// URL-safe-base64 sanitisation as [`signing_seed_key_for`].
pub fn account_scoped_device_key(base: &str) -> String {
    match active_device_seed_scope() {
        Some(account) => format!("{base}.{}", URL_SAFE_NO_PAD.encode(account.as_bytes())),
        None => base.to_owned(),
    }
}

/// Secure-store key for the signing seed under `scope` (the account DID), or
/// the bootstrap key when `scope` is `None`/empty. The account segment is
/// URL-safe-base64 encoded (the same sanitisation the MLS marker keys use) so
/// DID characters are safe across every backend.
fn signing_seed_key_for(scope: Option<&str>) -> String {
    match scope.map(str::trim).filter(|value| !value.is_empty()) {
        Some(account) => format!(
            "{SIGNING_SEED_KEY}.{}",
            URL_SAFE_NO_PAD.encode(account.as_bytes())
        ),
        None => SIGNING_SEED_KEY.to_owned(),
    }
}

/// Decoded signing seed (32 bytes) plus the `did:key` the seed encodes.
/// Returned by [`load_signing_seed`] / [`ensure_signing_seed`] so callers
/// can stand up an `Ed25519DetachedJwsSigner` without re-deriving the DID.
///
/// SEC-06: `ZeroizeOnDrop` wipes the in-memory 32-byte seed when a loaded
/// material value is dropped, so the high-value "one-key-many-uses" device
/// signing seed does not linger in freed heap / stack after a load. Callers that
/// copy `seed` out by value (`[u8;32]` is `Copy`) still leave their own copies —
/// this is defense-in-depth on the canonical container, not a guarantee over
/// every derived copy.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
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
    load_signing_seed_scoped(store, active_device_seed_scope().as_deref())
}

/// [`load_signing_seed`] for an explicit account scope (`None` = bootstrap).
pub fn load_signing_seed_scoped(
    store: &dyn SecureKeyStore,
    scope: Option<&str>,
) -> Result<Option<SigningSeedMaterial>, SecureKeyStoreError> {
    require_wasm_indexeddb_ed25519_seed_store(store)?;
    let Some(raw) = store.get_secret(&signing_seed_key_for(scope))? else {
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
    store_signing_seed_scoped(store, active_device_seed_scope().as_deref(), seed)
}

/// [`store_signing_seed`] for an explicit account scope (`None` = bootstrap).
pub fn store_signing_seed_scoped(
    store: &dyn SecureKeyStore,
    scope: Option<&str>,
    seed: &[u8; 32],
) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
    require_wasm_indexeddb_ed25519_seed_store(store)?;
    let encoded = STANDARD_NO_PAD.encode(seed);
    store.store_secret(&signing_seed_key_for(scope), &encoded)?;
    Ok(SigningSeedMaterial {
        seed: *seed,
        local_signing_did: ed25519_seed_to_did_key(seed),
    })
}

/// Delete the signing seed for `scope` (`None` = bootstrap). Best-effort; a
/// missing entry is not an error at the backend level.
pub fn delete_signing_seed_scoped(
    store: &dyn SecureKeyStore,
    scope: Option<&str>,
) -> Result<(), SecureKeyStoreError> {
    store.delete_secret(&signing_seed_key_for(scope))
}

/// On login completion (the resolved principal DID is now known), re-home the
/// bootstrap-scope seed — the one bound to the just-issued session grant
/// (`cnf.jkt`) — under the account scope, then clear the bootstrap entry so the
/// next account signed in on this browser cannot inherit it. Idempotent: if the
/// account already holds a seed, the bootstrap one is simply cleared. Sets the
/// active scope to `account`.
pub fn adopt_device_seed_scope_on_login(
    store: &dyn SecureKeyStore,
    account: &str,
) -> Result<(), SecureKeyStoreError> {
    let account = account.trim();
    if account.is_empty() {
        return Ok(());
    }
    // A present bootstrap seed is the freshly-minted device bound to the
    // session grant just issued during this sign-in; it becomes this account's
    // device key, OVERWRITING any prior one (the prior key is not bound to the
    // live grant, so a sign-in that resolves back to the same principal must
    // adopt the new key, not the stale one).
    if let Some(material) = load_signing_seed_scoped(store, None)? {
        store_signing_seed_scoped(store, Some(account), &material.seed)?;
        delete_signing_seed_scoped(store, None)?;
        // Re-home the paired bootstrap `device_id` under the account scope in
        // lockstep with the seed it was minted with, so the account keeps one
        // stable device identity (the MLS KeyPackage published during this
        // sign-in is bound to it). Only adopt the bootstrap `device_id` when the
        // account does not already hold one — a returning account keeps its
        // existing stable id rather than inheriting this sign-in's fresh one.
        if let Some(bootstrap_device_id) = load_device_id_scoped(store, None)? {
            if load_device_id_scoped(store, Some(account))?.is_none() {
                store_device_id_scoped(store, Some(account), &bootstrap_device_id)?;
            }
            delete_device_id_scoped(store, None)?;
        }
    }
    set_active_device_seed_scope(Some(account));
    Ok(())
}

/// Reset to the bootstrap scope for a fresh interactive sign-in and clear any
/// leftover bootstrap seed, so the device key minted for whatever principal the
/// OIDC flow resolves to is brand-new and never the previous account's key.
pub fn reset_device_seed_scope_for_signin(
    store: &dyn SecureKeyStore,
) -> Result<(), SecureKeyStoreError> {
    set_active_device_seed_scope(None);
    let _ = delete_device_id_scoped(store, None);
    delete_signing_seed_scoped(store, None)
}

/// Load the existing signing seed, or generate + persist a fresh one if
/// none exists. The generated seed is a 32-byte `getrandom` draw.
pub fn ensure_signing_seed(
    store: &dyn SecureKeyStore,
) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
    ensure_signing_seed_scoped(store, active_device_seed_scope().as_deref())
}

/// [`ensure_signing_seed`] for an explicit account scope (`None` = bootstrap).
pub fn ensure_signing_seed_scoped(
    store: &dyn SecureKeyStore,
    scope: Option<&str>,
) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
    if let Some(material) = load_signing_seed_scoped(store, scope)? {
        return Ok(material);
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom signing seed: {err}")))?;
    store_signing_seed_scoped(store, scope, &seed)
}

/// Canonical storage key for the stable protocol `device_id`
/// (`ck:device:<uuidv7>`), scoped per account.
///
/// The `device_id` is NOT a secret — it is a PUBLIC identifier that already
/// appears in events, KeyPackages and DIDs — so on wasm it lives in PLAIN
/// `localStorage` (`DEVICE_ID_LOCALSTORAGE_KEY`), deliberately OUTSIDE the
/// encrypted IndexedDB secure store. That decoupling is load-bearing: the secure
/// store's AES-GCM wrapping key can transiently mismatch (a second store
/// deriving a fresh random-salt key), making encrypted entries fail to decrypt
/// and silently vanish. If `device_id` lived there, such a miss would mint a NEW
/// device on the next reload — stranding the MLS KeyPackage (and its retained
/// init key) published under the prior device, so the Welcome can never be
/// decrypted ("no local KeyPackage identity state"). Plain `localStorage` is
/// always readable regardless of the wrapping-key state, so the `device_id`
/// stays stable. Native keeps it in the OS keychain, which has no such
/// instability.
#[cfg(not(target_arch = "wasm32"))]
const DEVICE_ID_KEY: &str = "device.id.v1";

#[cfg(target_arch = "wasm32")]
const DEVICE_ID_LOCALSTORAGE_KEY: &str = "yougen.device_id.v1";

/// Storage key for the `device_id` under `scope` (account DID), or the bootstrap
/// key when `scope` is `None`/empty. The account segment is URL-safe-base64
/// encoded, matching [`signing_seed_key_for`].
fn device_id_key_for(scope: Option<&str>) -> String {
    #[cfg(target_arch = "wasm32")]
    let base = DEVICE_ID_LOCALSTORAGE_KEY;
    #[cfg(not(target_arch = "wasm32"))]
    let base = DEVICE_ID_KEY;
    match scope.map(str::trim).filter(|value| !value.is_empty()) {
        Some(account) => format!("{base}.{}", URL_SAFE_NO_PAD.encode(account.as_bytes())),
        None => base.to_owned(),
    }
}

#[cfg(target_arch = "wasm32")]
fn device_id_local_storage() -> Option<web_sys::Storage> {
    web_sys::window().and_then(|window| window.local_storage().ok().flatten())
}

/// Read the persisted stable `device_id` for the active account scope.
pub fn load_device_id(store: &dyn SecureKeyStore) -> Result<Option<String>, SecureKeyStoreError> {
    load_device_id_scoped(store, active_device_seed_scope().as_deref())
}

/// [`load_device_id`] for an explicit account scope (`None` = bootstrap).
pub fn load_device_id_scoped(
    store: &dyn SecureKeyStore,
    scope: Option<&str>,
) -> Result<Option<String>, SecureKeyStoreError> {
    let key = device_id_key_for(scope);
    #[cfg(target_arch = "wasm32")]
    {
        let _ = store;
        Ok(device_id_local_storage()
            .and_then(|storage| storage.get_item(&key).ok().flatten())
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty()))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Ok(store
            .get_secret(&key)?
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty()))
    }
}

/// Persist `device_id` for the active account scope. Overwrites silently.
pub fn store_device_id(
    store: &dyn SecureKeyStore,
    device_id: &str,
) -> Result<(), SecureKeyStoreError> {
    store_device_id_scoped(store, active_device_seed_scope().as_deref(), device_id)
}

/// [`store_device_id`] for an explicit account scope (`None` = bootstrap).
pub fn store_device_id_scoped(
    store: &dyn SecureKeyStore,
    scope: Option<&str>,
    device_id: &str,
) -> Result<(), SecureKeyStoreError> {
    let key = device_id_key_for(scope);
    #[cfg(target_arch = "wasm32")]
    {
        let _ = store;
        if let Some(storage) = device_id_local_storage() {
            storage.set_item(&key, device_id.trim()).map_err(|err| {
                SecureKeyStoreError::Backend(format!("localStorage device_id set: {err:?}"))
            })?;
        }
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        store.store_secret(&key, device_id.trim())
    }
}

/// Delete the `device_id` for `scope` (`None` = bootstrap). Best-effort.
fn delete_device_id_scoped(
    store: &dyn SecureKeyStore,
    scope: Option<&str>,
) -> Result<(), SecureKeyStoreError> {
    let key = device_id_key_for(scope);
    #[cfg(target_arch = "wasm32")]
    {
        let _ = store;
        if let Some(storage) = device_id_local_storage() {
            let _ = storage.remove_item(&key);
        }
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        store.delete_secret(&key)
    }
}

/// Encode an Ed25519 seed into a `did:key:z…`.
fn ed25519_seed_to_did_key(seed: &[u8; 32]) -> String {
    let signing = ed25519_dalek::SigningKey::from_bytes(seed);
    let verifying = signing.verifying_key();
    crate::did_key::did_key_from_verifying_key(&verifying)
}
