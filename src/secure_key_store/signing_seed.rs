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
//!     wasm32. Before the async IndexedDB/SubtleCrypto upgrade completes, browser signer bootstrap
//!     fails closed and ProofMode remains Production.

use std::sync::RwLock;

use arkret_sdk::{AccountId, DeviceId};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};

use super::{SecureKeyStore, SecureKeyStoreError, require_wasm_indexeddb_ed25519_seed_store};

/// Canonical key name for the active-device Ed25519 signing seed in the
/// secure-key store. Scoped by `service_name` (`"inkson"` in production)
/// so dev and prod builds never collide.
///
/// The seed is additionally scoped *per account* (see
/// [`signing_seed_key_for`]): two accounts signed in on the same browser MUST
/// hold completely separate device signing keys, never one shared key. The
/// bare `SIGNING_SEED_KEY` is a bootstrap scope used only before an
/// account scope is known. Interactive session grants are bound by the separate
/// grant-binding key below, so a returning account's signing seed must not be
/// overwritten by a fresh login.
pub const SIGNING_SEED_KEY: &str = "device.ed25519.signing_seed.v1";

/// Process-global active device-seed scope: the signed-in authority/device whose
/// per-account seed the bare [`load_signing_seed`] / [`ensure_signing_seed`]
/// helpers resolve. `None` selects the bootstrap scope. Set on login
/// completion, on app boot / session restore for the persisted account, and temporarily reset for a
/// fresh interactive sign-in ([`reset_device_seed_scope_for_signin`]). The seed
/// is read at a few controlled points (signer activation at boot/login,
/// recovery); per-event signing uses the already-activated in-memory signer, so
/// this is not a hot path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveDeviceSeedScope {
    pub authority: AccountId,
    pub device_id: DeviceId,
}

struct ActiveDeviceSeedScopeState {
    scope: Option<ActiveDeviceSeedScope>,
    epoch: u64,
}
static ACTIVE_DEVICE_SEED_SCOPE: RwLock<ActiveDeviceSeedScopeState> =
    RwLock::new(ActiveDeviceSeedScopeState {
        scope: None,
        epoch: 0,
    });

#[cfg(test)]
static ACTIVE_DEVICE_SEED_SCOPE_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes unit tests that read or write the process-global
/// [`ACTIVE_DEVICE_SEED_SCOPE`] / [`PENDING_LOGIN_DEVICE_ID`] pair — directly
/// or through `UserLocalStore::activate` / `PendingLocalStore::activate` /
/// `promote_to` / `LocalStateStore::begin_pending_login` — and restores both
/// globals on drop. Every such test MUST hold this guard; a single unguarded
/// test reintroduces cross-test races under the parallel runner. In tests
/// that also hold [`crate::event_signer::ActiveSignerTestGuard`], acquire
/// this guard first so all tests agree on one lock order. Production code
/// never takes this lock.
#[cfg(test)]
pub(crate) struct DeviceSeedScopeTestGuard {
    previous_scope: Option<ActiveDeviceSeedScope>,
    previous_pending: Option<DeviceId>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl DeviceSeedScopeTestGuard {
    /// Take the scope lock, clear any pending-login device id, and install
    /// `scope` as the active device-seed scope (`None` selects the neutral
    /// bootstrap state). The guarded test may freely mutate both globals;
    /// drop restores the pre-guard values.
    pub(crate) fn replace(scope: Option<(&AccountId, &DeviceId)>) -> Self {
        let lock = ACTIVE_DEVICE_SEED_SCOPE_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous_scope = active_device_seed_scope();
        let previous_pending = pending_login_device_id();
        set_pending_login_device_id(None);
        set_active_device_seed_scope(scope);
        Self {
            previous_scope,
            previous_pending,
            _lock: lock,
        }
    }
}

#[cfg(test)]
impl Drop for DeviceSeedScopeTestGuard {
    fn drop(&mut self) {
        set_active_device_seed_scope(
            self.previous_scope
                .as_ref()
                .map(|scope| (&scope.authority, &scope.device_id)),
        );
        set_pending_login_device_id(self.previous_pending.as_ref());
    }
}

/// Set the active authority/device seed scope, or `None`
/// for the bootstrap scope.
pub fn set_active_device_seed_scope(scope: Option<(&AccountId, &DeviceId)>) {
    let normalized = scope.map(|(authority, device_id)| ActiveDeviceSeedScope {
        authority: authority.clone(),
        device_id: device_id.clone(),
    });
    if let Ok(mut guard) = ACTIVE_DEVICE_SEED_SCOPE.write() {
        if guard.scope != normalized {
            match guard.epoch.checked_add(1) {
                Some(epoch) => {
                    guard.epoch = epoch;
                    guard.scope = normalized;
                }
                None => {
                    guard.scope = None;
                }
            }
        }
    }
}

/// The current active per-account device-seed scope, if any.
pub fn active_device_seed_scope() -> Option<ActiveDeviceSeedScope> {
    ACTIVE_DEVICE_SEED_SCOPE
        .read()
        .ok()
        .and_then(|guard| guard.scope.clone())
}

/// Capture scope and its ABA fence under the same lock.
pub(crate) fn active_device_seed_scope_snapshot() -> Option<(ActiveDeviceSeedScope, u64)> {
    let guard = ACTIVE_DEVICE_SEED_SCOPE.read().ok()?;
    guard.scope.clone().map(|scope| (scope, guard.epoch))
}

/// Process-global pending-login device id. During the pre-DID phase of an
/// interactive sign-in the wrap_seed (and any pending secrets) live under the
/// `pending.<device_id>` namespace; once the principal DID resolves, that
/// material is transferred under the accepted authority/device namespace. `None` outside an
/// in-flight pending sign-in.
static PENDING_LOGIN_DEVICE_ID: RwLock<Option<DeviceId>> = RwLock::new(None);

/// Set (or clear with `None`) the pending-login device id used to namespace the
/// pre-DID wrap_seed and pending secrets.
pub fn set_pending_login_device_id(device_id: Option<&DeviceId>) {
    let normalized = device_id.cloned();
    if let Ok(mut guard) = PENDING_LOGIN_DEVICE_ID.write() {
        *guard = normalized;
    }
}

/// The current pending-login device id, if a pre-DID sign-in is in flight.
pub fn pending_login_device_id() -> Option<DeviceId> {
    PENDING_LOGIN_DEVICE_ID
        .read()
        .ok()
        .and_then(|guard| guard.clone())
}

#[derive(Clone, Debug)]
enum DeviceSeedScope {
    Account(ActiveDeviceSeedScope),
    Pending(DeviceId),
}

fn effective_device_seed_scope() -> Option<DeviceSeedScope> {
    active_device_seed_scope()
        .map(DeviceSeedScope::Account)
        .or_else(|| pending_login_device_id().map(DeviceSeedScope::Pending))
}

/// Append the active per-account scope to a secure-store key `base`, for
/// device-key material that must be isolated per account alongside the signing
/// seed — notably the cached DPoP device-key record (which embeds the same seed
/// bytes and is what `ensure_device_key` consults first). Returns `base`
/// unchanged in the bootstrap scope. The account segment uses the same
/// URL-safe-base64 sanitisation as [`signing_seed_key_for`].
pub fn account_scoped_device_key(base: &str) -> Result<String, SecureKeyStoreError> {
    let scope = effective_device_seed_scope().ok_or_else(missing_identity_scope_error)?;
    identity_storage_key(&scope, base)
}

/// Resolve an identity-owned device key for fallible runtime paths.
///
/// Startup and account-switch effects can legitimately observe a short window
/// with neither an active user nor a pending login. That state means there is
/// no credential to load; it must become a handled error, never a wasm panic.
fn try_account_scoped_device_key(base: &str) -> Result<String, SecureKeyStoreError> {
    account_scoped_device_key(base)
}

fn missing_identity_scope_error() -> SecureKeyStoreError {
    SecureKeyStoreError::Backend(
        "identity-owned key is unavailable before an account authority/device or pending device scope is active"
            .to_owned(),
    )
}

fn identity_storage_key(
    scope: &DeviceSeedScope,
    logical_key: &str,
) -> Result<String, SecureKeyStoreError> {
    match scope {
        DeviceSeedScope::Account(scope) => Ok(format!(
            "inkson.authority.{}.device.{}.{logical_key}",
            super::account_id_storage_digest(&scope.authority)?,
            super::device_storage_digest(&scope.device_id)
        )),
        DeviceSeedScope::Pending(device_id) => Ok(format!(
            "inkson.pending.{}.{logical_key}",
            super::device_storage_digest(device_id)
        )),
    }
}

/// Secure-store key for the signing seed under the active typed scope.
// The `expect` below asserts the scope invariant named in its message; this
// helper returns a key string, not a Result, so the invariant cannot be
// propagated.
#[allow(clippy::expect_used)]
fn signing_seed_key() -> Result<String, SecureKeyStoreError> {
    account_scoped_device_key(SIGNING_SEED_KEY)
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
    load_signing_seed_at(store, &signing_seed_key()?)
}

/// Read the original device seed by explicit Account/Device coordinates.
/// Never falls back to the mutable active scope or creates replacement material.
pub(crate) fn load_signing_seed_for(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<Option<SigningSeedMaterial>, SecureKeyStoreError> {
    load_signing_seed_at(
        store,
        &identity_storage_key(
            &DeviceSeedScope::Account(ActiveDeviceSeedScope {
                authority: authority.clone(),
                device_id: device_id.clone(),
            }),
            SIGNING_SEED_KEY,
        )?,
    )
}

pub(super) fn load_signing_seed_at(
    store: &dyn SecureKeyStore,
    key: &str,
) -> Result<Option<SigningSeedMaterial>, SecureKeyStoreError> {
    require_wasm_indexeddb_ed25519_seed_store(store)?;
    let Some(raw) = store.get_secret(key)? else {
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
    store_signing_seed_at(store, &signing_seed_key()?, seed)
}

pub(super) fn store_signing_seed_at(
    store: &dyn SecureKeyStore,
    key: &str,
    seed: &[u8; 32],
) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
    require_wasm_indexeddb_ed25519_seed_store(store)?;
    let encoded = STANDARD_NO_PAD.encode(seed);
    store.store_secret(key, &encoded)?;
    Ok(SigningSeedMaterial {
        seed: *seed,
        local_signing_did: ed25519_seed_to_did_key(seed),
    })
}

/// Crash-durable counterpart used before a protocol transition starts
/// depending on a newly-created device key. On wasm this awaits the IndexedDB
/// transaction instead of returning after the in-memory cache update.
pub(super) async fn store_signing_seed_at_durable(
    store: &dyn SecureKeyStore,
    key: &str,
    seed: &[u8; 32],
) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
    require_wasm_indexeddb_ed25519_seed_store(store)?;
    let encoded = STANDARD_NO_PAD.encode(seed);
    store.store_secret_durable(key, &encoded).await?;
    Ok(SigningSeedMaterial {
        seed: *seed,
        local_signing_did: ed25519_seed_to_did_key(seed),
    })
}

/// Delete the signing seed for `scope` (`None` = bootstrap). Best-effort; a
/// missing entry is not an error at the backend level.
pub(super) fn delete_signing_seed(store: &dyn SecureKeyStore) -> Result<(), SecureKeyStoreError> {
    store.delete_secret(&signing_seed_key()?)
}

/// Reset to the bootstrap scope for a fresh interactive sign-in, clear only
/// bootstrap leftovers, and rotate the session grant-binding key. Account-scoped
/// device identity seeds/device ids are deliberately preserved so a hard
/// re-login can prove a fresh `cnf.jkt` without rotating the E2EE device.
pub fn reset_device_seed_scope_for_signin(
    store: &dyn SecureKeyStore,
    pending_device_id: &DeviceId,
) -> Result<(), SecureKeyStoreError> {
    set_active_device_seed_scope(None);
    set_pending_login_device_id(Some(pending_device_id));
    let _ = delete_device_id(store);
    let _ = delete_signing_seed(store);
    rotate_grant_binding_seed(store).map(|_| ())
}

/// Load the existing signing seed, or generate + persist a fresh one if
/// none exists. The generated seed is a 32-byte `getrandom` draw.
pub fn ensure_signing_seed(
    store: &dyn SecureKeyStore,
) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
    ensure_signing_seed_at(store, &signing_seed_key()?)
}

pub(super) fn ensure_signing_seed_at(
    store: &dyn SecureKeyStore,
    key: &str,
) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
    if let Some(material) = load_signing_seed_at(store, key)? {
        return Ok(material);
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom signing seed: {err}")))?;
    store_signing_seed_at(store, key, &seed)
}

pub(super) async fn ensure_signing_seed_at_durable(
    store: &dyn SecureKeyStore,
    key: &str,
) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
    if let Some(material) = load_signing_seed_at(store, key)? {
        return Ok(material);
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom signing seed: {err}")))?;
    store_signing_seed_at_durable(store, key, &seed).await
}

// ---------------------------------------------------------------------------
// Grant-binding (DPoP) key — decision 0004 / spec device-lifecycle §3.3.
//
// The grant-binding key is a SESSION-auth credential, distinct from the
// per-account device identity signing seed ([`SIGNING_SEED_KEY`] above): its
// RFC 7638 JWK thumbprint is the grant's `cnf.jkt`, it signs DPoP proofs and the
// grant-rotation / logout-revoke DPoP proofs, and it MUST NOT feed the event
// signer — rotating or clearing it must never change the device identity key
// that signs events / KeyPackages / MLS. It is minted fresh on interactive
// sign-in, cleared on hard logout, and preserved across grant rotation and soft
// recovery. It is isolated by pending transaction before the principal is
// known and by authority/device after adoption, so concurrent or sequential
// account flows cannot overwrite one another's holder key.
// ---------------------------------------------------------------------------

/// Canonical key name for the browser-session grant-binding (DPoP) key in the
/// secure-key store, resolved through the current pending/account scope.
pub const GRANT_BINDING_SEED_KEY: &str = "device.ed25519.grant_binding.v1";

/// Read the browser-session grant-binding seed. `Ok(None)` when absent (vs
/// `Err(...)` for backend / decode failures). Mirrors [`load_signing_seed`] but
/// resolves the single session-scoped entry rather than a per-account one.
pub fn load_grant_binding_seed(
    store: &dyn SecureKeyStore,
) -> Result<Option<SigningSeedMaterial>, SecureKeyStoreError> {
    require_wasm_indexeddb_ed25519_seed_store(store)?;
    let key = try_account_scoped_device_key(GRANT_BINDING_SEED_KEY)?;
    let Some(raw) = store.get_secret(&key)? else {
        return Ok(None);
    };
    let bytes = STANDARD_NO_PAD.decode(raw.as_bytes()).map_err(|err| {
        SecureKeyStoreError::Backend(format!("grant-binding seed base64 decode: {err}"))
    })?;
    if bytes.len() != 32 {
        return Err(SecureKeyStoreError::Backend(format!(
            "grant-binding seed length {}, expected 32",
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

/// Persist `seed` as the browser-session grant-binding key. Overwrites silently.
pub fn store_grant_binding_seed(
    store: &dyn SecureKeyStore,
    seed: &[u8; 32],
) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
    require_wasm_indexeddb_ed25519_seed_store(store)?;
    let encoded = STANDARD_NO_PAD.encode(seed);
    let key = try_account_scoped_device_key(GRANT_BINDING_SEED_KEY)?;
    store.store_secret(&key, &encoded)?;
    Ok(SigningSeedMaterial {
        seed: *seed,
        local_signing_did: ed25519_seed_to_did_key(seed),
    })
}

/// Persist a `URL_SAFE_NO_PAD` base64 seed as the browser-session grant-binding
/// key. Used by the injected-grant test seam, whose `dpop_seed_b64url` IS the
/// key the issued grant's `cnf.jkt` binds to, so it must become the
/// grant-binding key (not the device identity seed).
pub fn store_grant_binding_seed_b64url(
    store: &dyn SecureKeyStore,
    seed_b64url: &str,
) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(seed_b64url.as_bytes())
        .map_err(|err| {
            SecureKeyStoreError::Backend(format!("grant-binding seed b64url decode: {err}"))
        })?;
    if bytes.len() != 32 {
        return Err(SecureKeyStoreError::Backend(format!(
            "grant-binding seed length {}, expected 32",
            bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    store_grant_binding_seed(store, &seed)
}

/// Load the existing grant-binding seed, or generate + persist a fresh one if
/// none exists (soft recovery / grant rotation reuse the same key).
pub fn ensure_grant_binding_seed(
    store: &dyn SecureKeyStore,
) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
    if let Some(material) = load_grant_binding_seed(store)? {
        return Ok(material);
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|err| {
        SecureKeyStoreError::Backend(format!("getrandom grant-binding seed: {err}"))
    })?;
    store_grant_binding_seed(store, &seed)
}

/// Mint a fresh grant-binding seed, replacing any existing one. Used at the
/// start of an interactive sign-in so the grant issued this session binds to a
/// brand-new `cnf.jkt` (spec device-lifecycle §4.1: hard logout / re-login
/// rotates the grant-binding key), independent of the device identity key.
pub fn rotate_grant_binding_seed(
    store: &dyn SecureKeyStore,
) -> Result<SigningSeedMaterial, SecureKeyStoreError> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|err| {
        SecureKeyStoreError::Backend(format!("getrandom grant-binding seed: {err}"))
    })?;
    store_grant_binding_seed(store, &seed)
}

/// Delete the grant-binding seed (hard logout). Best-effort; a missing entry is
/// not an error at the backend level. Soft recovery MUST NOT call this.
pub fn delete_grant_binding_seed(store: &dyn SecureKeyStore) -> Result<(), SecureKeyStoreError> {
    let key = try_account_scoped_device_key(GRANT_BINDING_SEED_KEY)?;
    store.delete_secret(&key)
}

/// Canonical storage key for the stable protocol `device_id`
/// (`ak:device:<uuidv7>`), scoped per account.
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
const DEVICE_ID_LOCALSTORAGE_KEY: &str = "device_id.v1";

/// Storage key for the `device_id` under the active typed scope.
// The `expect` below asserts the scope invariant named in its message; this
// helper returns a key string, not a Result, so the invariant cannot be
// propagated.
#[allow(clippy::expect_used)]
fn device_id_key() -> Result<String, SecureKeyStoreError> {
    #[cfg(target_arch = "wasm32")]
    let base = DEVICE_ID_LOCALSTORAGE_KEY;
    #[cfg(not(target_arch = "wasm32"))]
    let base = DEVICE_ID_KEY;
    account_scoped_device_key(base)
}

/// Read the persisted stable `device_id` for the active account scope.
pub fn load_device_id(store: &dyn SecureKeyStore) -> Result<Option<DeviceId>, SecureKeyStoreError> {
    let key = device_id_key()?;
    #[cfg(target_arch = "wasm32")]
    {
        let _ = store;
        crate::browser_storage::browser_storage()
            .and_then(|storage| storage.get_item(&key).ok().flatten())
            .map(|value| DeviceId::new(value.trim().to_owned()))
            .transpose()
            .map_err(|error| {
                SecureKeyStoreError::Backend(format!("stored device_id is invalid: {error}"))
            })
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        store
            .get_secret(&key)?
            .map(|value| DeviceId::new(value.trim().to_owned()))
            .transpose()
            .map_err(|error| {
                SecureKeyStoreError::Backend(format!("stored device_id is invalid: {error}"))
            })
    }
}

/// Persist `device_id` for the active account scope. Overwrites silently.
pub fn store_device_id(
    store: &dyn SecureKeyStore,
    device_id: &DeviceId,
) -> Result<(), SecureKeyStoreError> {
    let key = device_id_key()?;
    #[cfg(target_arch = "wasm32")]
    {
        let _ = store;
        if let Some(storage) = crate::browser_storage::browser_storage() {
            storage.set_item(&key, device_id.as_str()).map_err(|err| {
                SecureKeyStoreError::Backend(format!("localStorage device_id set: {err:?}"))
            })?;
        }
        Ok(())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        store.store_secret(&key, device_id.as_str())
    }
}

/// Delete the `device_id` for `scope` (`None` = bootstrap). Best-effort.
pub(super) fn delete_device_id(store: &dyn SecureKeyStore) -> Result<(), SecureKeyStoreError> {
    let key = device_id_key()?;
    #[cfg(target_arch = "wasm32")]
    {
        let _ = store;
        if let Some(storage) = crate::browser_storage::browser_storage() {
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
    crate::identity::did_key::did_key_from_verifying_key(&verifying)
}

#[cfg(test)]
mod grant_binding_tests {
    use super::*;
    use crate::secure_key_store::MemorySecureKeyStore;

    fn activate_test_user() -> DeviceSeedScopeTestGuard {
        let authority = AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:server.example".to_owned()).unwrap(),
        );
        let device_id =
            DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001".to_owned()).unwrap();
        DeviceSeedScopeTestGuard::replace(Some((&authority, &device_id)))
    }

    #[test]
    fn ensure_is_idempotent_and_load_round_trips() {
        let _scope = activate_test_user();
        let store = MemorySecureKeyStore::default();
        let first = ensure_grant_binding_seed(&store).unwrap();
        let second = ensure_grant_binding_seed(&store).unwrap();
        assert_eq!(first.seed, second.seed);
        let loaded = load_grant_binding_seed(&store).unwrap().expect("loaded");
        assert_eq!(loaded.seed, first.seed);
        assert_eq!(loaded.local_signing_did, first.local_signing_did);
    }

    #[test]
    fn rotate_replaces_with_a_fresh_seed() {
        let _scope = activate_test_user();
        let store = MemorySecureKeyStore::default();
        let original = ensure_grant_binding_seed(&store).unwrap();
        let rotated = rotate_grant_binding_seed(&store).unwrap();
        assert_ne!(original.seed, rotated.seed);
        let loaded = load_grant_binding_seed(&store).unwrap().expect("loaded");
        assert_eq!(loaded.seed, rotated.seed);
    }

    #[test]
    fn delete_clears_the_entry() {
        let _scope = activate_test_user();
        let store = MemorySecureKeyStore::default();
        ensure_grant_binding_seed(&store).unwrap();
        delete_grant_binding_seed(&store).unwrap();
        assert!(load_grant_binding_seed(&store).unwrap().is_none());
    }

    #[test]
    fn missing_identity_scope_returns_an_error_instead_of_panicking() {
        let _scope = DeviceSeedScopeTestGuard::replace(None);
        let store = MemorySecureKeyStore::default();

        let error = load_grant_binding_seed(&store).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("before an account authority/device or pending device scope is active")
        );
    }

    #[test]
    fn grant_binding_key_is_independent_of_the_account_signing_seed() {
        let _scope = activate_test_user();
        // The two subjects use different store keys, so writing one never
        // perturbs the other — the core invariant of decision 0004.
        let store = MemorySecureKeyStore::default();
        let device_identity = ensure_signing_seed(&store).unwrap();
        let grant_binding = ensure_grant_binding_seed(&store).unwrap();
        assert_ne!(device_identity.seed, grant_binding.seed);
        // Rotating the grant-binding key leaves the device identity seed intact.
        rotate_grant_binding_seed(&store).unwrap();
        let identity_after = load_signing_seed(&store)
            .unwrap()
            .expect("device identity seed survives grant-binding rotation");
        assert_eq!(identity_after.seed, device_identity.seed);
    }

    #[test]
    fn pending_accounts_use_distinct_device_and_grant_key_namespaces() {
        let _scope = DeviceSeedScopeTestGuard::replace(None);
        let first_id =
            DeviceId::new("ak:device:01964137-0000-7000-8000-000000000001".to_owned()).unwrap();
        set_pending_login_device_id(Some(&first_id));
        let first_device = device_id_key().unwrap();
        let first_grant = account_scoped_device_key(GRANT_BINDING_SEED_KEY).unwrap();

        let second_id =
            DeviceId::new("ak:device:01964137-0000-7000-8000-000000000002".to_owned()).unwrap();
        set_pending_login_device_id(Some(&second_id));
        let second_device = device_id_key().unwrap();
        let second_grant = account_scoped_device_key(GRANT_BINDING_SEED_KEY).unwrap();

        assert_ne!(first_device, second_device);
        assert_ne!(first_grant, second_grant);
        assert_ne!(first_device, "device_id.v1");
        assert_ne!(first_grant, GRANT_BINDING_SEED_KEY);
    }
}
